# -*- coding: utf-8 -*-
"""
领克App 分享任务脚本。

分享流程横跨"原生签名"和"H5签名"两套认证体系，接口协议细节、已知限制见
docs/分享任务接口说明.md。重要提醒：接口返回 success 不代表真正加分（每日
有次数上限，重复调用不会重复加分），需自行对比 myEnergy 的 point 字段判断。

do_share() 已封装好"优先简化两步法，失败/无 content_id 时可选回退完整三步法"的
逻辑。通过 lynkco_sign.py / lynkco_daily_tasks.py 运行时会自动执行一次分享；
也可直接运行本文件单独触发一次分享。
"""
import json
import sys
import time

import requests

from lynkco_common import (
    BASE_URL,
    NATIVE_ANDROID_UA,
    NATIVE_DEVICE_HEADERS,
    NATIVE_RISK_IMEI,
    build_native_signature,
    build_signature,
    mask_sensitive,
    request_with_retry,
)
from lynkco_login import load_token

# ------------------------- 分享任务相关端点，完整协议见 docs/分享任务接口说明.md -------------------------
EP_GET_SHARE_CODE = "/app/v1/task/getShareCode"          # 获取本次分享的一次性 shareCode（原生签名）
EP_SHARE_LOOKUP = "/app/v1/task/shareCodeToUserId"        # 通过 shareCode 反查分享人 userId（H5签名）
EP_SHARE_CHECK = "/app/v1/task/shareContentContectCheck"  # 分享前置校验，可选步骤（H5签名）
EP_SHARE_REPORT = "/app/v1/task/shareContentContectReporting"  # 完整版上报，另一账号点开链接后走的三步流程（H5签名）
# 简化版上报：拿到 getShareCode 返回的 shareCode 后，POST 到该接口即可让服务端
# 记为"已完成一次分享"，比 lookup+check+report 三步法更直接，单账号即可自己
# 触发（H5签名，Origin 需为 https://h5.lynkco.com）。
EP_SHARE_REPORTING_SIMPLE = "/app/v1/task/shareReporting"
# 探索广场首页文章流（H5签名），用于动态取最新文章 id，避免固定文章失效。body 需带
# dynamicSort/uniqueId/refreshType/pageNo 分页参数（抓包自原生请求，H5签名不覆盖
# body 故可直接复用），否则只返回首屏、命中"文章"类型的概率很低。
EP_EXPLORE_SQUARE_INDEX = "/app/explore/home-page/square/index2"
# get_latest_article() 命中第一篇文章前最多尝试翻的页数。
EXPLORE_SQUARE_PAGE_COUNT = 5

# 分享落地页 H5 域名（与签到用的 h5.lynkco.cn 是两个不同域名/Origin，
# shareReporting 接口的签名 AppKey 虽然相同，但网关会校验 Origin/Referer）。
H5_SHARE_ORIGIN = "https://h5.lynkco.com"

# 典型文章 id（真实抓包样本），作为 get_latest_article() 获取失败时的兜底。
DEFAULT_SHARE_ARTICLE_ID = "2075054309774663680"


def _find_article(value) -> dict:
    """递归查找广场文章流中第一个“文章”类型内容，返回 {"articleId", "title"}，未找到则返回空 dict。"""
    if isinstance(value, dict):
        article_id = value.get("articleId")
        content_type = value.get("contentType") or value.get("contentTypeCode")
        if article_id and (not content_type or content_type in ("文章", "article")):
            return {"articleId": str(article_id), "title": str(value.get("title") or "")}
        for child in value.values():
            found = _find_article(child)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_article(item)
            if found:
                return found
    return {}


class LynkCoShareClient:
    def __init__(self, token: str):
        if not token:
            raise ValueError("token 不能为空")
        self.token = token if token.startswith("bearer") else f"bearer{token}"
        self.session = requests.Session()

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """走 H5 签名体系（build_signature）请求 app-api-gw-toc.lynkco.com 网关。"""
        extra_headers = kwargs.pop("extra_headers", {})
        url = BASE_URL + path
        resp = request_with_retry(
            self.session, method, url,
            build_headers=lambda: {
                **build_signature(method, path, query=kwargs.get("params")),
                "token": self.token,
                "Origin": "https://h5.lynkco.cn",
                "Referer": "https://h5.lynkco.cn/",
                "content-type": "application/json",
                "Accept": "*/*",
                **extra_headers,
            },
            **kwargs,
        )
        try:
            resp.json()
        except ValueError:
            print(
                f"[警告][H5 {method} {path}] 接口未返回有效 JSON，HTTP {resp.status_code}，"
                f"响应体前200字符: {resp.text[:200]!r}"
            )
        return resp

    def _native_request(self, method: str, path: str, extra_headers: dict = None, **kwargs) -> requests.Response:
        """
        走 App 原生 SDK 签名体系（build_native_signature）请求
        app-api-gw-toc.lynkco.com 网关的部分端点（如 getShareCode）。
        """
        extra = extra_headers or {}
        url = BASE_URL + path
        resp = request_with_retry(
            self.session, method, url,
            build_headers=lambda: {
                **build_native_signature(
                    method, path, query=kwargs.get("params"),
                    signature_headers_order="x-ca-nonce,x-ca-key,x-ca-timestamp",
                ),
                "token": self.token,
                "svcsid": self.token,
                "ca_version": "1",
                "appversion": "4.2.3",
                "appVersionCode": "4.2.3",
                "appVersionName": "402030320",
                "publicPlatform": "android",
                "User-Agent": NATIVE_ANDROID_UA,
                **NATIVE_DEVICE_HEADERS,
                **extra,
            },
            **kwargs,
        )
        try:
            resp.json()
        except ValueError:
            print(
                f"[警告][Native {method} {path}] 接口未返回有效 JSON，HTTP {resp.status_code}，"
                f"响应体前200字符: {resp.text[:200]!r}"
            )
        return resp

    def get_latest_article(self) -> dict:
        """翻页查找探索广场文章流，命中第一篇"文章"即返回 {"articleId", "title"}，失败/未找到时返回空 dict 并打印警告日志。"""
        for page_no in range(1, EXPLORE_SQUARE_PAGE_COUNT + 1):
            try:
                body = {"dynamicSort": "new", "uniqueId": "", "refreshType": "MORE", "pageNo": page_no}
                resp = self._request("POST", EP_EXPLORE_SQUARE_INDEX, json=body)
                resp_json = resp.json()
                found = _find_article(resp_json)
                if found:
                    return found
                print(
                    f"[警告] get_latest_article: 第 {page_no} 页未命中\"文章\"类型内容，"
                    f"接口返回 code={resp_json.get('code')!r}"
                )
            except Exception as e:
                print(f"[警告] get_latest_article: 第 {page_no} 页请求异常: {e}")
                continue
        print(f"[警告] get_latest_article: 翻完 {EXPLORE_SQUARE_PAGE_COUNT} 页仍未找到文章，将回退到 DEFAULT_SHARE_ARTICLE_ID")
        return {}

    def get_share_code(self, article_id: str = None, account_id: str = None) -> dict:
        """
        获取本次分享专属的一次性 shareCode（GET /app/v1/task/getShareCode，走原生
        AppKey 签名）。请求头 risk_request_info 里携带了被分享文章的 id，之后必须原样
        作为 businessNo 传给 share_reporting()，网关会校验两者一致，否则虽返回 success
        但不会真正加分。

        参数:
            article_id: 被分享文章/内容的 id，不传则用 DEFAULT_SHARE_ARTICLE_ID 兜底（推荐
                通过 do_share() 调用，会自动取最新文章）。
            account_id: 当前账号 accountId，用于填充 gl_user_id 风控头，不传则留空。
        """
        article_id = article_id or DEFAULT_SHARE_ARTICLE_ID
        share_content_url = (
            "https://h5.lynkco.com/app-h5/dist/web/pages/exploration/article/index.html"
            f"?id={article_id}&isShare=lynkco%3A%2F%2Fwx%2F%3FrouteUrl%3D%2Fpages%2Fexploration%2Farticle%2Findex.js%3Fid%3D{article_id}"
        )
        risk_request_info = json.dumps(
            {
                "openTimeStamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "shareContentType": 1,
                "shareContentURL": share_content_url,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        sweet_security_info = json.dumps(
            {
                "appVersion": "4.2.3", "platform": "android", "battery": "100",
                "isCharging": "4", "isSetProxy": "true", "isUsbDebug": "false",
                "isMockLocation": "false", "isRoot": "false",
                "appSignature": "4F8393A255313DE42799571ABDF33A60",
                # channel 为 URL-encoded 后的值（"%E5%90%89%E5%88%A9" = 吉利），
                # HTTP 头只能是 ASCII 字符，直接放中文会被 requests 库报编码错。
                "channel": "%E5%90%89%E5%88%A9", "screenResolution": "2400*1080", "brand": "google",
                "model": "sdk_gphone64_arm64", "imsi": NATIVE_RISK_IMEI,
                "geelyDeviceId": "0de2480e07cefcd852cf3a8dadc822cc", "os": "android",
                "osVersion": "13", "androidVersion": "33", "networkType": "WIFI",
                "ip": "10.0.2.16", "wifiName": "AndroidWifi", "wifiSignalLevel": "-50",
                "isLbsEnabled": "true", "lbsLatitude": "", "lbsLongitude": "",
                "deviceToken": "",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        extra_headers = {
            "risk_type": "1",
            "risk_request_info": risk_request_info,
            "sweet_security_info": sweet_security_info,
            "imei": NATIVE_RISK_IMEI,
            "os": "13",
        }
        if account_id:
            extra_headers["gl_user_id"] = account_id
        resp = self._native_request("GET", EP_GET_SHARE_CODE, extra_headers=extra_headers)
        return resp.json()

    def share_reporting(self, share_code: str, business_no: str = None,
                         first_classification: str = "文章", second_classification: str = "") -> dict:
        """
        分享上报（POST /app/v1/task/shareReporting?shareCode=<shareCode>，Origin 需为
        https://h5.lynkco.com）。网关会校验 businessNo 与 getShareCode 时的文章 id 是否
        一致。返回 success 不代表真正加分成功，需自行对比 myEnergy 的 point 字段确认。
        """
        business_no = business_no or DEFAULT_SHARE_ARTICLE_ID
        body = {
            "businessNo": business_no,
            "eventData": {
                "firstClassification": first_classification,
                "secondClassification": second_classification,
            },
        }
        resp = self._request(
            "POST", EP_SHARE_REPORTING_SIMPLE,
            params={"shareCode": share_code},
            json=body,
            extra_headers={"Origin": H5_SHARE_ORIGIN, "Referer": H5_SHARE_ORIGIN + "/"},
        )
        return resp.json()

    def share_lookup(self, share_code: str) -> dict:
        """（完整三步法-第1步）通过 shareCode 反查分享人 userId"""
        resp = self._request("POST", EP_SHARE_LOOKUP, json={"shareCode": share_code})
        return resp.json()

    def share_check(self, content_id: str, share_code: str) -> dict:
        """（完整三步法-第2步）分享前置校验"""
        resp = self._request("POST", EP_SHARE_CHECK, json={"contentId": content_id, "shareCode": share_code})
        return resp.json()

    def share_report(self, content_id: str, share_code: str) -> dict:
        """（完整三步法-第3步）真正上报分享、加能量体"""
        resp = self._request("POST", EP_SHARE_REPORT, json={"contentId": content_id, "shareCode": share_code})
        return resp.json()

    def do_share(self, article_id: str = None, account_id: str = None,
                 content_id: str = None, use_simple: bool = True) -> dict:
        """
        执行一次完整的分享任务，自动编排 get_share_code -> share_reporting 两步法，
        use_simple=False 或两步法失败且提供了 content_id 时回退到 lookup->check->report
        完整三步法。返回 {"ok": bool, "via": "simple"|"full", "detail": {...}}。

        未显式传入 article_id 时自动调用 get_latest_article() 取最新文章，失败则回退到
        DEFAULT_SHARE_ARTICLE_ID（无标题），分享成功时返回值会带上 "articleId"/"articleTitle"。
        """
        article_title = ""
        if not article_id:
            latest = self.get_latest_article()
            article_id = latest.get("articleId") or DEFAULT_SHARE_ARTICLE_ID
            article_title = latest.get("title", "")
            if latest and not article_title:
                print(f"[警告] do_share: 动态获取到文章 articleId={article_id}，但该内容节点的 title 字段为空")
            elif not latest:
                print(f"[警告] do_share: 未获取到动态文章，回退使用 DEFAULT_SHARE_ARTICLE_ID={article_id}")

        if use_simple:
            try:
                code_info = self.get_share_code(article_id=article_id, account_id=account_id)
                share_code = code_info.get("data") or ""
                if not share_code:
                    raise RuntimeError(f"getShareCode 未返回有效 shareCode: {code_info}")

                result = self.share_reporting(share_code, business_no=article_id)
                if str(result.get("code")) in ("200", "success"):
                    return {
                        "ok": True, "via": "simple",
                        "articleId": article_id, "articleTitle": article_title,
                        "detail": {"getShareCode": code_info, "shareReporting": result},
                    }
                # 后端明确返回"已分享过"之类信息也视为成功（幂等）
                msg = result.get("message", "")
                if any(k in msg for k in ("已分享", "已领取", "今日已", "已结束")):
                    return {
                        "ok": True, "via": "simple",
                        "articleId": article_id, "articleTitle": article_title,
                        "detail": {"getShareCode": code_info, "shareReporting": result},
                    }
            except Exception as e:
                if not content_id:
                    return {"ok": False, "via": "simple", "detail": {"message": f"简化两步法失败: {e}"}}
                # 简化接口异常且提供了 content_id 时继续尝试完整三步法

        share_code_for_full = None
        try:
            share_code_for_full = (self.get_share_code(article_id=article_id, account_id=account_id).get("data") or "")
        except Exception:
            pass

        if not content_id:
            return {"ok": False, "via": "simple", "detail": {"message": "简化两步法未成功，且未提供 content_id 无法回退到完整三步法"}}

        lookup_result = self.share_lookup(share_code_for_full or "")
        check_result = self.share_check(content_id, share_code_for_full or "")
        report_result = self.share_report(content_id, share_code_for_full or "")
        ok = str(report_result.get("code")) in ("200", "success")
        msg = report_result.get("message", "")
        if not ok and any(k in msg for k in ("已分享", "已领取", "今日已", "已结束")):
            ok = True
        return {
            "ok": ok,
            "via": "full",
            "articleId": article_id, "articleTitle": article_title,
            "detail": {"lookup": lookup_result, "check": check_result, "report": report_result},
        }


def run_auto_share(token: str) -> dict:
    """供 lynkco_sign.py / lynkco_daily_tasks.py 调用的便捷封装：执行一次分享，打印结果。"""
    print("\n=== 执行分享任务 ===")
    client = LynkCoShareClient(token)
    try:
        share_result = client.do_share()
        print(json.dumps(mask_sensitive(share_result), ensure_ascii=False, indent=2))
        if share_result.get("ok"):
            print("\n分享任务成功！")
        else:
            print(f"\n分享任务失败: {share_result.get('detail')}")
        return share_result
    except Exception as e:
        print(f"[警告] 分享任务执行失败: {e}")
        return {"ok": False, "detail": {"message": str(e)}}


def main():
    """独立运行本文件即可单独触发一次分享任务（无需通过 lynkco_sign.py）。"""
    try:
        token = load_token()
    except RuntimeError as e:
        print(f"[错误] {e}")
        sys.exit(1)
    run_auto_share(token)


if __name__ == "__main__":
    main()
