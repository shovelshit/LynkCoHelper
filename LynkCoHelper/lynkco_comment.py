# -*- coding: utf-8 -*-
"""Local-first, fail-closed coordinator for independent AI comments."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows keeps the previous behavior.
    fcntl = None

from lynkco_ai import CommentGenerationError, generate_comment, load_ai_config
from lynkco_common import env_value
from lynkco_comment_client import CommentClient, CommentPostError, CommentPostUncertain
from lynkco_comment_feed import eligible_posts, fetch_article_detail, fetch_recent_posts
from lynkco_notify import send_bark_notification
from lynkco_share import article_share_url


DEFAULT_STATE = Path(__file__).resolve().with_name(".comment_state.json")
UTC = timezone.utc
_BARK_URL_PATTERN = re.compile(r"(https?://api\.day\.app/)[^\s/'\"]+", re.IGNORECASE)
_BEARER_PATTERN = re.compile(r"\bbearer[A-Za-z0-9._-]+", re.IGNORECASE)


def _redact_log_text(value):
    text = str(value)
    for name in (
        "LYNKCO_BARK_KEY", "CHATANYWHERE_API_KEY", "GLM_API_KEY",
        "ZHIPU_API_KEY", "LYNKCO_TOKEN", "LYNKCO_REFRESH_TOKEN",
        "LYNKCO_DEVICE_ID",
    ):
        secret = env_value(name)
        if secret:
            text = text.replace(secret, "<redacted>")
    text = _BARK_URL_PATTERN.sub(r"\1<redacted>", text)
    return _BEARER_PATTERN.sub("bearer<redacted>", text)


def _log(message):
    print(f"[评论] {_redact_log_text(message)}", flush=True)


class _TaskLock:
    """Best-effort cross-process lock for local runs sharing one state file."""

    def __init__(self, state_path: Path):
        self.path = state_path.with_name(f"{state_path.name}.lock")
        self.handle = None
        self.locked = False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+", encoding="utf-8")
        if fcntl is not None:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
                self.locked = True
            except OSError:
                # Some filesystems do not implement advisory locks; preserve the
                # prior single-process behavior instead of failing the task.
                self.locked = False
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.handle is not None:
            if fcntl is not None and self.locked:
                try:
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            self.handle.close()


def _detail_failure_status(error):
    message = str(error)
    if "identity or availability changed" in message or "article changed before publication" in message or \
            "includes video" in message:
        return "detail_changed", "未发布｜动态已变化"
    return "detail_unavailable", "未发布｜详情暂不可用"


def _validate_entries(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"state.{name} must be an object")
    timestamp_key = "confirmed_at" if name == "successes" else "recorded_at"
    for identifier, record in value.items():
        if not isinstance(identifier, str) or not identifier.strip() or not isinstance(record, dict) or \
                set(record) != {timestamp_key}:
            raise ValueError(f"state.{name} contains an invalid entry")
        timestamp = record.get(timestamp_key)
        if not isinstance(timestamp, str):
            raise ValueError(f"state.{name} contains an invalid timestamp")
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"state.{name} contains an invalid timestamp") from None
        if parsed.tzinfo is None:
            raise ValueError(f"state.{name} contains an invalid timestamp")


def validate_state(value):
    """Validate artifact state before any feed or posting operation."""
    if not isinstance(value, dict) or type(value.get("version")) is not int or \
            value["version"] != 1 or set(value) != {"version", "successes", "uncertain"}:
        raise ValueError("comment state version is invalid")
    _validate_entries(value.get("successes"), "successes")
    _validate_entries(value.get("uncertain"), "uncertain")
    if set(value["successes"]) & set(value["uncertain"]):
        raise ValueError("comment state has conflicting IDs")
    return value


def load_state(path: Path):
    if not path.exists():
        return {"version": 1, "successes": {}, "uncertain": {}}
    try:
        with path.open("r", encoding="utf-8") as source:
            return validate_state(json.load(source))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("comment state cannot be read; inspect it before retrying") from exc


def save_state_atomic(path: Path, state: dict):
    validate_state(state)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as output:
            temp_name = output.name
            os.chmod(temp_name, 0o600)
            json.dump(state, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def _summary(result):
    mode = "演练" if result["dry_run"] else "发布"
    lines = [f"### 评论{mode}：本轮未生成评论"]
    for key, label in (("skipped", "跳过"), ("pending", "本轮未处理"),
                       ("failed", "失败"), ("uncertain", "结果待核对")):
        if result[key]:
            lines.append(f"- {label}：{result[key]}")
    for item in result["items"]:
        if item.get("reason"):
            lines.append(f"- 动态：{item.get('title') or item['id']}")
            lines.append(f"- 原因：{item['reason']}")
            if item.get("share_url"):
                lines.append(f"- 详情：{item['share_url']}")
    if result["error"]:
        lines.append(f"- 错误类别：{result['error']}")
    if result["uncertain"]:
        lines.append("- 不确定的动态已隔离，核对服务端评论后再人工处理状态文件")
    return "\n".join(lines)


def _bark_icon():
    return env_value("LYNKCO_BARK_ICON") or None


def _article_url(post):
    # Never forward a feed-provided jump URL to Bark.
    identifier = post.get("id")
    if post.get("kind") == "article" and isinstance(identifier, str) and re.fullmatch(r"[0-9]+", identifier):
        return article_share_url(identifier)
    return None


def _failure_item(post, status, reason):
    item = {"id": post["id"], "status": status, "reason": reason,
            "title": (post.get("title") or "领克动态").replace("\n", " ").replace("\r", " ")}
    url = _article_url(post)
    if url:
        item["share_url"] = url
    return item


def _notify_generated(post, comment, status, result):
    # UGC links are not trusted or published; article links are generated locally.
    # 链接只出现一次：open_url 让整条通知可点击打开 H5 页，正文不再重复
    # 同一链接（Bark 会把 url 参数单独渲染成链接行，正文再写会推送两条）。
    url = _article_url(post)
    article_title = post.get("title") or "领克动态"
    try:
        send_bark_notification(
            title=f"领克动态评论｜{status}",
            markdown_body=(f"**动态**：{article_title}\n\n"
                           f"**评论**：{comment}\n\n"
                           f"**结果**：{status}"),
            group="LynkCo评论", icon=_bark_icon(), open_url=url,
        )
    except Exception as exc:
        result["bark_failed"] = True
        _log(f"Bark 推送失败 id={post.get('id')} error={type(exc).__name__}: {exc}")


def _run_comment_task_unlocked(max_comments: int, dry_run: bool, state_path: Path,
                     *, share_client=None, comment_client=None,
                     api_key="", model="gpt-4o-mini", max_age_hours=48,
                     feed_pages=1):
    """Process at most max_comments candidates, persisting each confirmed or uncertain POST."""
    if isinstance(max_comments, bool) or not isinstance(max_comments, int) or not 1 <= max_comments <= 10:
        raise ValueError("LYNKCO_COMMENT_MAX_PER_RUN must be an integer between 1 and 10")
    if isinstance(max_age_hours, bool) or not isinstance(max_age_hours, int) or not 1 <= max_age_hours <= 168:
        raise ValueError("LYNKCO_COMMENT_MAX_AGE_HOURS must be an integer between 1 and 168")
    if isinstance(feed_pages, bool) or not isinstance(feed_pages, int) or not 1 <= feed_pages <= 20:
        raise ValueError("LYNKCO_COMMENT_FEED_PAGES must be an integer between 1 and 20")
    if not dry_run and comment_client is None:
        raise ValueError("publishing requires a configured comment client")
    state = load_state(Path(state_path))
    now = datetime.now(UTC)
    result = {"dry_run": dry_run, "confirmed": 0, "generated": 0,
              "skipped": 0, "pending": 0, "failed": 0, "uncertain": 0,
              "items": [], "error": ""}
    candidates = None
    attempted = 0
    generated_candidates = 0
    try:
        feed = fetch_recent_posts(share_client, pages=feed_pages)
        excluded = set(state["successes"]) | set(state["uncertain"])
        candidates = eligible_posts(feed, excluded, now, max_age_hours=max_age_hours)
        result["skipped"] += len(feed) - len(candidates)
        _log(
            f"开始{'演练' if dry_run else '发布'}：feed={len(feed)} candidates={len(candidates)} "
            f"excluded={len(feed) - len(candidates)} max_comments={max_comments} model={model}"
        )
        for post in candidates:
            if attempted >= max_comments:
                break
            attempted += 1
            post_id = post["id"]
            _log(
                f"处理第 {attempted}/{max_comments} 条：id={post_id} "
                f"kind={post.get('kind')} title={(post.get('title') or '')[:80]!r}"
            )
            if not dry_run and (post.get("kind") != "article" or not share_client or
                                not isinstance(post.get("author_id"), str) or not post["author_id"].strip()):
                result["skipped"] += 1
                result["items"].append(_failure_item(post, "metadata_skipped", "发布元数据不完整"))
                _log(f"跳过 id={post_id} reason=发布元数据不完整")
                continue
            if post.get("kind") == "article" and share_client is not None:
                _log(f"复查详情 id={post_id}")
                try:
                    post = fetch_article_detail(share_client, post)
                except (ValueError, RuntimeError, OSError) as detail_error:
                    detail_status, detail_reason = _detail_failure_status(detail_error)
                    result["skipped"] += 1
                    result["items"].append(_failure_item(post, detail_status, detail_reason))
                    _log(f"详情跳过 id={post_id} status={detail_status} error={detail_error}")
                    continue
            try:
                comment = generate_comment(post, api_key, model=model)
            except CommentGenerationError as generation_error:
                result["skipped"] += 1
                result["items"].append(_failure_item(
                    post, "generation_skipped", str(generation_error) or "模型评论生成失败"))
                _log(f"模型跳过 id={post_id} reason={generation_error}"
                     + (f" share_url={_article_url(post)}" if _article_url(post) else ""))
                continue
            generated_candidates += 1
            _log(f"模型生成 id={post_id} comment={comment}")
            if dry_run:
                result["generated"] += 1
                result["items"].append({"id": post_id, "status": "dry_run", "preview": comment})
                _notify_generated(post, comment, "演练｜未发布", result)
                continue
            status = "未发布｜执行中断"
            try:
                try:
                    latest = fetch_article_detail(share_client, post)
                    if any(latest[key] != post[key] for key in ("title", "text", "images", "cover_image")):
                        raise ValueError("article changed before publication")
                except (ValueError, RuntimeError, OSError) as detail_error:
                    detail_status, status = _detail_failure_status(detail_error)
                    result["skipped"] += 1
                    result["items"].append(_failure_item(post, detail_status, status))
                    continue
                # Quarantine before the POST so a process crash cannot silently retry it.
                state["uncertain"][post_id] = {"recorded_at": datetime.now(UTC).isoformat()}
                save_state_atomic(Path(state_path), state)
                status = "待核对｜执行中断"
                try:
                    confirmation = comment_client.publish(post, comment)
                except CommentPostUncertain:
                    result["uncertain"] += 1
                    result["items"].append({"id": post_id, "status": "uncertain"})
                    status = "待核对｜勿重复提交"
                    break
                except CommentPostError:
                    del state["uncertain"][post_id]
                    try:
                        save_state_atomic(Path(state_path), state)
                    except OSError:
                        result["uncertain"] += 1
                        result["error"] = "state_persistence_after_post"
                        result["items"].append({"id": post_id, "status": "uncertain"})
                        status = "待核对｜状态保存失败"
                        break
                    result["failed"] += 1
                    result["items"].append({"id": post_id, "status": "rejected"})
                    status = "失败｜服务端拒绝"
                    break
                if not isinstance(confirmation, dict) or not confirmation.get("commentId"):
                    result["uncertain"] += 1
                    result["items"].append({"id": post_id, "status": "uncertain"})
                    status = "待核对｜勿重复提交"
                    break
                del state["uncertain"][post_id]
                state["successes"][post_id] = {"confirmed_at": datetime.now(UTC).isoformat()}
                try:
                    save_state_atomic(Path(state_path), state)
                except OSError:
                    result["uncertain"] += 1
                    result["error"] = "state_persistence_after_post"
                    result["items"].append({"id": post_id, "status": "uncertain"})
                    status = "待核对｜状态保存失败"
                    break
                result["confirmed"] += 1
                result["items"].append({"id": post_id, "status": "confirmed"})
                status = "发布成功"
            finally:
                _notify_generated(post, comment, status, result)
    except (OSError, ValueError, RuntimeError) as exc:
        result["failed"] += 1
        if isinstance(exc, OSError):
            result["error"] = "state_persistence_or_feed_io"
        elif isinstance(exc, ValueError) and ("square feed" in str(exc) or
                                              "v3 feed contains no usable posts" in str(exc)):
            result["error"] = "feed_metadata_missing_or_unusable"
        else:
            result["error"] = type(exc).__name__
    finally:
        if candidates is not None:
            result["pending"] = len(candidates) - attempted
    if not generated_candidates:
        try:
            # 各条目的详情链接只在正文里出现一次，不再传 open_url
            #（首条链接会与正文里的 - 详情行重复）
            send_bark_notification(title="本轮未生成评论", markdown_body=_summary(result),
                                    group="LynkCo评论", icon=_bark_icon())
        except Exception as exc:
            result["bark_failed"] = True
            _log(f"本轮汇总 Bark 推送失败 error={type(exc).__name__}: {exc}")
    _log(
        f"任务结束：attempted={attempted} generated={result['generated']} "
        f"confirmed={result['confirmed']} skipped={result['skipped']} "
        f"pending={result['pending']} failed={result['failed']} uncertain={result['uncertain']}"
    )
    return result


def run_comment_task(max_comments: int, dry_run: bool, state_path: Path,
                     *, share_client=None, comment_client=None,
                     api_key="", model="gpt-4o-mini", max_age_hours=48,
                     feed_pages=1):
    """Run the complete stateful operation under one local process lock."""
    with _TaskLock(Path(state_path)):
        return _run_comment_task_unlocked(
            max_comments, dry_run, state_path, share_client=share_client,
            comment_client=comment_client, api_key=api_key, model=model,
            max_age_hours=max_age_hours, feed_pages=feed_pages,
        )


def _int_environment(name, default):
    value = env_value(name, str(default))
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None


def _ai_runtime_config():
    """Resolve the selected provider without changing the generation call site."""
    config = load_ai_config()
    if not isinstance(config, dict):
        raise ValueError("AI provider configuration is invalid")
    provider = str(config.get("provider") or "").strip().lower()
    api_key = str(config.get("api_key") or "").strip()
    model = str(config.get("model") or "").strip()
    if not provider:
        raise ValueError("AI provider is not configured")
    if not api_key:
        raise ValueError(f"{provider} API key unavailable")
    if not model:
        raise ValueError(f"{provider} model is not configured")
    _log(f"AI 配置：provider={provider} model={model} api_key={'已配置' if api_key else '缺失'}")
    return api_key, model


def _valid_comment_account_id(value):
    """Return a numeric comment identity, or an empty string for invalid input."""
    if value is None:
        return ""
    value = str(value).strip()
    return value if value.isdigit() else ""


def _resolve_comment_account_id(token, device_id):
    """Resolve the publisher identity without confusing it with the article author."""
    from lynkco_login import get_user_info

    info = get_user_info(token, device_id)
    account_id = _valid_comment_account_id((info or {}).get("id"))
    if not account_id:
        raise ValueError("current user info did not contain a numeric id")
    _log("评论账号 ID 已通过当前 token/device 动态获取")
    return account_id


def main(argv=None):
    parser = argparse.ArgumentParser(description="领克社区图文动态评论，默认仅演练")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="仅读取动态并生成评论，不提交")
    mode.add_argument("--publish", action="store_true", help="明确允许发布评论")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE, help="本地状态 JSON 路径")
    parser.add_argument("--max-comments", type=int, help="本次最多处理数量，1 到 10")
    args = parser.parse_args(argv)
    error_category = "configuration_invalid"
    try:
        maximum = args.max_comments if args.max_comments is not None else _int_environment("LYNKCO_COMMENT_MAX_PER_RUN", 1)
        age = _int_environment("LYNKCO_COMMENT_MAX_AGE_HOURS", 48)
        feed_pages = _int_environment("LYNKCO_COMMENT_FEED_PAGES", 1)
        if not 1 <= maximum <= 10 or not 1 <= age <= 168 or not 1 <= feed_pages <= 20:
            raise ValueError("comment cap must be 1..10, age must be 1..168 hours, and feed pages must be 1..20")
        from lynkco_login import load_token
        from lynkco_share import LynkCoShareClient

        error_category = "model_configuration_invalid"
        api_key, model = _ai_runtime_config()
        error_category = "login_unavailable"
        token = load_token()
        client = None
        share_client = LynkCoShareClient(token)
        if args.publish:
            error_category = "comment_identity_missing"
            from lynkco_common import load_env_data
            user = load_env_data().get("user", {})
            device_id = env_value("LYNKCO_DEVICE_ID") or user.get("deviceId")
            if not device_id:
                raise ValueError("publishing requires LYNKCO_DEVICE_ID or env.json.user.deviceId")
            account_id = _resolve_comment_account_id(token, device_id)
            client = CommentClient(token, account_id, device_id)
        error_category = "state_or_runtime_invalid"
        result = run_comment_task(maximum, not args.publish, args.state,
                                  share_client=share_client, comment_client=client,
                                  api_key=api_key, model=model,
                                  max_age_hours=age, feed_pages=feed_pages)
    except (OSError, ValueError, RuntimeError) as exc:
        if error_category == "model_configuration_invalid":
            # Surface the selected provider's missing/invalid setting without
            # exposing any credential value in the preflight diagnostic.
            error_category = str(exc) or error_category
        try:
            send_bark_notification(
                title="领克动态评论", group="LynkCo评论",
                markdown_body=f"### 评论任务 · {'发布' if args.publish else '演练'}\n- 预检失败：{error_category}\n- 未执行评论发布",
                icon=_bark_icon(),
            )
        except Exception as bark_error:
            _log(f"预检失败后的 Bark 推送失败 error={type(bark_error).__name__}: {bark_error}")
        _log(f"任务预检失败 category={error_category} detail={exc}")
        parser.exit(2, f"评论任务预检失败：{error_category}；请核查状态后重试\n")
    print(json.dumps(result, ensure_ascii=False))
    return 1 if result["failed"] or result["uncertain"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
