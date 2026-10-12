# -*- coding: utf-8 -*-
"""
通知工具模块，提供任务报告格式化和多渠道推送能力（不含业务逻辑，供
lynkco_daily_tasks.py、lynkco_comment.py 按需调用）：
    - build_markdown_report(result)：把任务结果字典组装成 Markdown 文案；
    - send_bark_notification(...)：把一段 Markdown 文案推送到 Bark；
    - send_notifications(...)：按配置推送到 Bark、飞书、钉钉、企业微信。

配置方式：环境变量 LYNKCO_BARK_KEY，或 env.json 的 notify.barkKey 字段
（Bark App「我的」页面可查看），未配置时跳过推送并打印提示，不抛异常。
"""
import requests

from lynkco_common import env_value, load_env_data

BARK_DEFAULT_BASE = "https://api.day.app"
BARK_CONNECT_TIMEOUT = 5
BARK_READ_TIMEOUT = 15


def _notify_value(env_names, config_key):
    """Read a notification value with environment variables taking precedence."""
    for env_name in env_names:
        value = env_value(env_name)
        if value:
            return value
    value = load_env_data().get("notify", {}).get(config_key, "")
    return value.strip() if isinstance(value, str) else ""


def _post_json(url, payload):
    """POST a JSON notification without inheriting a desktop proxy."""
    session = requests.Session()
    session.trust_env = False
    response = session.post(
        url,
        json=payload,
        headers={"Content-Type": "application/json; charset=utf-8"},
        timeout=(BARK_CONNECT_TIMEOUT, BARK_READ_TIMEOUT),
    )
    response.raise_for_status()
    try:
        return response.json()
    except ValueError:
        return {"status_code": response.status_code}


def _extract_point(energy_resp: dict) -> str:
    """从 myEnergy 响应中安全地取出 point 字段，取不到时返回 '?'。"""
    return str((energy_resp.get("data") or {}).get("point", "?"))


def _extract_growth(growth_resp: dict) -> tuple[str, str]:
    data = growth_resp.get("data") or {}
    level = data.get("accountLevelVo") or data
    return str(level.get("name", "?")), str(level.get("growth", "?"))


def _extract_tasks(tasks_resp: dict) -> list[dict]:
    raw_tasks = tasks_resp.get("data") or []
    if not isinstance(raw_tasks, list):
        return []
    tasks = []
    for task in raw_tasks:
        if not isinstance(task, dict):
            continue
        rewards = task.get("rewardContent") or []
        reward = ", ".join(str(item) for item in rewards) if isinstance(rewards, list) else str(rewards)
        tasks.append({
            "name": str(task.get("taskName") or "?"),
            "process": str(task.get("taskProcess") or "?"),
            "reward": reward or "无奖励字段",
        })
    return tasks


def build_markdown_report(result: dict) -> str:
    """
    把 lynkco_daily_tasks.run_daily_tasks() 返回的结果字典组装成一段
    Markdown 推送内容，各渠道共享同一份正文。
    """
    lines = []

    # --- 签到 ---
    if result.get("already_signed"):
        lines.append("### ℹ️ 签到")
        lines.append("- 今日已签到，无需重复签到")
    else:
        sign_result = result.get("sign_result") or {}
        sign_ok = bool(sign_result.get("success"))
        sign_data = sign_result.get("data") or {}
        if sign_ok:
            lines.append("### ✅ 签到成功")
            reward = sign_data.get("rewardEnergyNumber")
            if reward is not None:
                lines.append(f"- 本次奖励能量体：**+{reward}**")
        else:
            lines.append("### ❌ 签到失败")
            lines.append(f"- {sign_result.get('message', '未知错误')}")

    continue_data = (result.get("continue_info") or {}).get("data") or {}
    continue_days = continue_data.get("continueDays")
    sign_card = continue_data.get("signCardNumber")
    if continue_days is not None:
        lines.append(f"- 连续签到：**{continue_days} 天**")
    if sign_card is not None:
        lines.append(f"- 签到卡剩余：**{sign_card} 张**")

    # --- 分享 ---
    share_result = result.get("share_result")
    if share_result is not None:
        lines.append("\n### 🔗 分享任务")
        if share_result.get("ok"):
            lines.append("- 状态：**上报成功**")
            article_title = share_result.get("articleTitle")
            if article_title:
                lines.append(f"- 分享文章：{article_title}")
        else:
            detail = share_result.get("detail") or {}
            lines.append(f"- 状态：**失败**（{detail.get('message', '详情见日志')}）")

    # --- 成长等级 ---
    growth_before = _extract_growth(result.get("growth_before") or {})
    growth_after = _extract_growth(result.get("growth_after") or {})
    lines.append("\n### 📈 成长等级")
    lines.append(f"- {growth_before[0]} / {growth_before[1]} → **{growth_after[0]} / {growth_after[1]}**")

    # --- 任务进度 ---
    tasks = _extract_tasks(result.get("tasks_after") or result.get("tasks_before") or {})
    if tasks:
        lines.append("\n### 📋 任务进度")
        for task in tasks:
            lines.append(f"- {task['name']}：`{task['process']}`（{task['reward']}）")

    # --- 积分变化 ---
    point_before = _extract_point(result.get("energy_before") or {})
    point_after = _extract_point(result.get("energy_after") or {})
    lines.append("\n### 💰 积分变化")
    try:
        delta = int(point_after) - int(point_before)
        delta_str = f"（+{delta}）" if delta > 0 else (f"（{delta}）" if delta < 0 else "（无变化）")
    except (ValueError, TypeError):
        delta_str = ""
    lines.append(f"- {point_before} → **{point_after}** {delta_str}".rstrip())

    return "\n".join(lines)


def send_bark_notification(title: str, markdown_body: str, group: str = "LynkCo签到",
                            icon: str = None, level: str = "active",
                            bark_key: str = None, open_url: str = None) -> dict:
    """
    通过 Bark 发送一条 Markdown 格式的推送通知。level 可选
    "critical"/"active"/"timeSensitive"/"passive"。bark_key 不传则读取
    环境变量 LYNKCO_BARK_KEY，未配置时返回 {"skipped": True} 且不抛异常。
    """
    bark_key = bark_key or _notify_value(("LYNKCO_BARK_KEY",), "barkKey")
    if not bark_key:
        print("[提示] 未配置 LYNKCO_BARK_KEY，跳过 Bark 推送。")
        return {"skipped": True}

    url = f"{BARK_DEFAULT_BASE}/{bark_key}"

    payload = {
        "title": title,
        "markdown": markdown_body,
        "group": group,
        "level": level,
    }
    if icon:
        payload["icon"] = icon
    if open_url:
        payload["url"] = open_url

    # requests may inherit a desktop-wide proxy that can connect but never
    # return Bark's response. Bark is directly reachable, so use a clean
    # session and separate short connect/read timeouts for this notification.
    session = requests.Session()
    session.trust_env = False
    resp = session.post(
        url, json=payload,
        headers={"Content-Type": "application/json; charset=utf-8"},
        timeout=(BARK_CONNECT_TIMEOUT, BARK_READ_TIMEOUT),
    )
    resp.raise_for_status()
    return resp.json()


def send_wecom_notification(title: str, markdown_body: str, webhook: str = None,
                            open_url: str = None) -> dict:
    """Send Markdown to an enterprise WeChat robot."""
    webhook = webhook or _notify_value(
        ("LYNKCO_WECOM_WEBHOOK", "PUSH_WE_COM_WEBHOOK"), "weComWebhook"
    )
    if not webhook:
        return {"skipped": True}
    body = f"# {title}\n\n{markdown_body}"
    if open_url:
        body += f"\n\n[打开详情]({open_url})"
    return _post_json(webhook, {"msgtype": "markdown", "markdown": {"content": body}})


def send_dingtalk_notification(title: str, markdown_body: str, webhook: str = None,
                               open_url: str = None) -> dict:
    """Send Markdown to a DingTalk robot."""
    webhook = webhook or _notify_value(
        ("LYNKCO_DINGTALK_WEBHOOK", "PUSH_DING_TALK_WEBHOOK"), "dingTalkWebhook"
    )
    if not webhook:
        return {"skipped": True}
    body = f"# {title}\n\n{markdown_body}"
    if open_url:
        body += f"\n\n[打开详情]({open_url})"
    return _post_json(webhook, {"msgtype": "markdown", "markdown": {"title": title, "text": body}})


def send_feishu_notification(title: str, markdown_body: str, webhook: str = None,
                             open_url: str = None) -> dict:
    """Send a post message to a Feishu custom bot."""
    webhook = webhook or _notify_value(
        ("LYNKCO_FEISHU_WEBHOOK", "PUSH_FEI_SHU_WEBHOOK"), "feiShuWebhook"
    )
    if not webhook:
        return {"skipped": True}
    body = markdown_body
    if open_url:
        body += f"\n\n打开详情：{open_url}"
    payload = {"msg_type": "post", "content": {"post": {"zh_cn": {
        "title": title,
        "content": [[{"tag": "text", "text": body}]],
    }}}}
    return _post_json(webhook, payload)


def send_notifications(title: str, markdown_body: str, *, group: str = "LynkCo签到",
                       icon: str = None, open_url: str = None) -> dict:
    """Send to every configured channel and return one result per channel."""
    senders = {
        "bark": lambda: send_bark_notification(
            title, markdown_body, group=group, icon=icon, open_url=open_url
        ),
        "feishu": lambda: send_feishu_notification(title, markdown_body, open_url=open_url),
        "dingtalk": lambda: send_dingtalk_notification(title, markdown_body, open_url=open_url),
        "wecom": lambda: send_wecom_notification(title, markdown_body, open_url=open_url),
    }
    results = {}
    for channel, sender in senders.items():
        try:
            results[channel] = sender()
        except Exception as exc:
            print(f"[警告] {channel} 推送失败（不影响任务结果）: {exc}")
            results[channel] = {"skipped": True, "error": str(exc)}
    if all(item.get("skipped") for item in results.values()):
        print("[提示] 未配置通知渠道，跳过推送。")
    return results
