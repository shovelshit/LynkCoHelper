# -*- coding: utf-8 -*-
"""
Bark 推送通知工具模块，提供两个通用能力（不含任何业务逻辑，供
lynkco_daily_tasks.py 按需调用）：
    - build_markdown_report(result)：把任务结果字典组装成 Bark Markdown 文案；
    - send_bark_notification(...)：把一段 Markdown 文案推送到 Bark。

配置方式：环境变量 LYNKCO_BARK_KEY，或 env.json 的 notify.barkKey 字段
（Bark App「我的」页面可查看），未配置时跳过推送并打印提示，不抛异常。
"""
import os

import requests

from lynkco_common import load_env_data

BARK_DEFAULT_BASE = "https://api.day.app"


def _extract_point(energy_resp: dict) -> str:
    """从 myEnergy 响应中安全地取出 point 字段，取不到时返回 '?'。"""
    return str((energy_resp.get("data") or {}).get("point", "?"))


def build_markdown_report(result: dict) -> str:
    """
    把 lynkco_daily_tasks.run_daily_tasks() 返回的结果字典组装成一段
    Bark markdown 推送内容。
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
                            bark_key: str = None) -> dict:
    """
    通过 Bark 发送一条 Markdown 格式的推送通知。level 可选
    "critical"/"active"/"timeSensitive"/"passive"。bark_key 不传则读取
    环境变量 LYNKCO_BARK_KEY，未配置时返回 {"skipped": True} 且不抛异常。
    """
    bark_key = bark_key or os.environ.get("LYNKCO_BARK_KEY", "").strip() or load_env_data().get("notify", {}).get("barkKey", "").strip()
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

    resp = requests.post(
        url, json=payload,
        headers={"Content-Type": "application/json; charset=utf-8"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()
