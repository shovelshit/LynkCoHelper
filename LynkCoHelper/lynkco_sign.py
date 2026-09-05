# -*- coding: utf-8 -*-
"""
领克App 每日签到脚本。签名算法详见 lynkco_common.py / docs/AppSecret_逆向分析记录.md。

使用前提：需要有效 token，由 lynkco_login.py 的 load_token() 统一提供
（自动续期或人工获取），本脚本无需关心 token 具体来源。

2026-07 抓包更新：真正"执行签到"的接口路径已从 /up/api/v1/user/sign 变为
/up/api/v1/user/sign/upgrade，且改走原生 SDK 签名体系（build_native_signature，
NATIVE_APP_KEY/SECRET，签名头顺序 x-ca-nonce,x-ca-key,x-ca-timestamp，POST body
即使是空对象 "{}" 也要计算 Content-MD5）。经实测验证，sweet_security_info/imei/
gl_user_id/gl_dev_id 等设备风控头并非必需（不带也能 200 成功），故未携带，仅保留
ca_version/x-requiretoken/User-Agent 等基础头。查询类接口（day/info、
getContinueDaysAndSignCard）经抓包验证仍是原来的 H5 签名体系（build_signature），
未受影响。
"""
import json
import sys

import requests

from lynkco_common import (
    BASE_URL,
    DEFAULT_USER_AGENT,
    NATIVE_ANDROID_UA,
    build_native_signature,
    build_signature,
    mask_sensitive,
    request_with_retry,
)
from lynkco_login import load_token

EP_SIGN_DAY_INFO = "/up/api/v1/user/sign/day/info"
EP_SIGN_UPGRADE = "/up/api/v1/user/sign/upgrade"  # 真正执行签到的接口（抓包确认，非 /up/api/v1/user/sign）
EP_CONTINUE_DAYS = "/up/api/v1/userReward/getContinueDaysAndSignCard"


class LynkCoSignClient:
    def __init__(self, token: str):
        if not token:
            raise ValueError("token 不能为空")
        # 领克接口的 token 头需要 "bearer" 前缀且中间无空格，若外部传入时已带前缀则不重复添加
        self.token = token if token.startswith("bearer") else f"bearer{token}"
        self.session = requests.Session()

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """走 H5 签名体系（build_signature），用于查询类接口。"""
        # 注意：若请求带 query 参数（GET 的 params），必须一并传给 build_signature
        # 参与签名计算，否则服务端会返回 400 Invalid Signature。
        extra_headers = kwargs.pop("extra_headers", {})
        url = BASE_URL + path
        resp = request_with_retry(
            self.session, method, url,
            build_headers=lambda: {
                **build_signature(method, path, query=kwargs.get("params")),
                "token": self.token,
                "Origin": "https://h5.lynkco.cn",
                "Referer": "https://h5.lynkco.cn/",
                "User-Agent": DEFAULT_USER_AGENT,
                "content-type": "application/json",
                "Accept": "*/*",
                **extra_headers,
            },
            **kwargs,
        )
        try:
            resp.json()
        except ValueError:
            raise RuntimeError(
                f"[{method} {path}] 接口未返回有效 JSON（可能被网关拦截，如境外 IP 访问限制"
                f"或 AppKey 未授权），HTTP {resp.status_code}，"
                f"响应体前200字符: {resp.text[:200]!r}"
            )
        return resp

    def _native_request(self, method: str, path: str, body: bytes = None, **kwargs) -> requests.Response:
        """走 App 原生 SDK 签名体系（build_native_signature），用于 sign/upgrade 等写操作接口。"""
        extra_headers = kwargs.pop("extra_headers", {})
        url = BASE_URL + path
        resp = request_with_retry(
            self.session, method, url,
            build_headers=lambda: {
                **build_native_signature(
                    method, path,
                    accept="application/json; charset=utf-8",
                    content_type="application/json; charset=utf-8",
                    signature_headers_order="x-ca-nonce,x-ca-key,x-ca-timestamp",
                    body=body,
                ),
                "token": self.token,
                "ca_version": "1",
                "x-requiretoken": "false",
                "User-Agent": NATIVE_ANDROID_UA,
                **extra_headers,
            },
            data=body,
            **kwargs,
        )
        try:
            resp.json()
        except ValueError:
            raise RuntimeError(
                f"[Native {method} {path}] 接口未返回有效 JSON，HTTP {resp.status_code}，"
                f"响应体前200字符: {resp.text[:200]!r}"
            )
        return resp

    def get_sign_day_info(self) -> dict:
        """查询今日签到状态"""
        resp = self._request("GET", EP_SIGN_DAY_INFO)
        return resp.json()

    def do_sign(self) -> dict:
        """执行签到（POST /up/api/v1/user/sign/upgrade，原生签名，body 固定为空对象 "{}"）"""
        resp = self._native_request("POST", EP_SIGN_UPGRADE, body=b"{}")
        return resp.json()

    def get_continue_days(self) -> dict:
        """查询连续签到天数和签到卡数量"""
        resp = self._request("GET", EP_CONTINUE_DAYS)
        return resp.json()


def main():
    try:
        token = load_token()
    except RuntimeError as e:
        print(f"[错误] {e}")
        sys.exit(1)

    client = LynkCoSignClient(token)

    print("=== 查询签到状态 ===")
    try:
        day_info = client.get_sign_day_info()
        print(json.dumps(mask_sensitive(day_info), ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"[错误] 查询签到状态失败: {e}")
        sys.exit(1)

    if not day_info.get("success"):
        print("[错误] token 可能已失效，请重新登录获取新 token。")
        sys.exit(1)

    already_signed = day_info.get("data", {}).get("signStatus") == 1
    if already_signed:
        print("\n今日已签到，无需重复签到。")
    else:
        print("\n=== 执行签到 ===")
        try:
            sign_result = client.do_sign()
            print(json.dumps(mask_sensitive(sign_result), ensure_ascii=False, indent=2))
            if sign_result.get("success"):
                print("\n签到成功！")
            else:
                print(f"\n签到失败: {sign_result.get('message')}")
        except Exception as e:
            print(f"[错误] 签到请求失败: {e}")
            sys.exit(1)

    print("\n=== 连续签到信息 ===")
    try:
        continue_info = client.get_continue_days()
        print(json.dumps(mask_sensitive(continue_info), ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"[警告] 查询连续签到信息失败: {e}")

    # 分享任务已独立到 lynkco_share.py，每次运行本脚本都会执行一次（接口
    # 每日有加分次数上限，重复调用不会重复加分，详见 docs/分享任务接口说明.md）。
    from lynkco_share import run_auto_share
    run_auto_share(token)


if __name__ == "__main__":
    main()
