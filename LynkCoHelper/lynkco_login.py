# -*- coding: utf-8 -*-
"""
领克App 登录 / Token 获取与续期模块。

两套获取 token 的方式：
    1. refreshToken 自动续期（推荐）：refresh_token()，内部依次尝试 AppCode
       静态认证、AppKey/AppSecret HMAC 签名认证两套方案。
    2. 账号密码/短信验证码全流程登录：get_security_config -> 用户完成极验
       滑块 -> validate_geetest -> send_login_sms -> login_by_mobile_code。

接口协议细节（请求路径、body 结构、签名要求等）见
docs/登录接口协议说明.md；签名密钥来源见 docs/AppSecret_逆向分析记录.md。

统一入口 load_token()：按优先级自动选择上述方式，供 lynkco_sign.py /
lynkco_share.py 等业务脚本直接调用。
"""
import json
import os
import sys
import time
import uuid

import requests

from lynkco_common import (
    LOGIN_APP_CODE,
    NATIVE_ANDROID_UA,
    NATIVE_APP_CODE,
    NATIVE_APP_KEY,
    NATIVE_BASE_URL,
    NATIVE_DEVICE_HEADERS,
    build_native_signature,
    load_env_data,
    save_env_fields,
)

# ------------------------- refreshToken 续期 -------------------------


def _parse_refresh_response(data: dict, refresh_token_value: str) -> dict:
    """解析 /auth/login/refresh 接口的响应体，两种认证方案返回结构一致，共用此解析逻辑。"""
    if data.get("code") != "success":
        raise RuntimeError(
            f"refreshToken 续期失败，接口返回: {data}。"
            "可能是 refreshToken 已过期(有效期约30天)，需要重新抓包获取。"
        )

    token_dto = (data.get("data") or {}).get("centerTokenDto") or {}
    token = token_dto.get("token")
    if not token:
        raise RuntimeError(f"refreshToken 续期响应异常，未找到 token 字段: {data}")

    return {
        "token": token,
        "refreshToken": token_dto.get("refreshToken", refresh_token_value),
        "expireAt": token_dto.get("expireAt"),
        "refreshExpireAt": token_dto.get("refreshExpireAt"),
    }


def refresh_token_by_appcode(refresh_token_value: str, device_id: str) -> dict:
    """
    方案一（优先，已验证）：使用 AppCode 静态认证换取新 token（无需任何签名运算）。

    只需固定的 `Authorization: APPCODE <NATIVE_APP_CODE>` 请求头即可通过
    阿里云网关校验，若未来失效上层会自动回退到方案二(HMAC 签名)。
    """
    path = "/auth/login/refresh"
    query = {
        "refreshToken": refresh_token_value,
        "deviceId": device_id,
        "deviceType": "IOS",
        "appVersion": "4.2.0",
    }
    headers = {
        "Authorization": f"APPCODE {NATIVE_APP_CODE}",
        "accept": "application/json",
        "content-type": "application/json; charset=UTF-8",
        "publicplatform": "iOS",
        "user-agent": "CA_iOS_SDK_2.0",
        "token": "",
        "gl_dev_id": device_id,
        "appversioncode": "4.2.0",
        "appversionname": "40200106",
        "gl_app_version": "4.2.0",
        "gl_app_build": "40200106",
        "x-ca-version": "1",
    }

    url = NATIVE_BASE_URL + path
    resp = requests.get(url, params=query, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return _parse_refresh_response(data, refresh_token_value)


def refresh_token_by_signature(refresh_token_value: str, device_id: str) -> dict:
    """方案二（兜底）：使用 AppKey/AppSecret HMAC 签名认证换取新 token。"""
    path = "/auth/login/refresh"
    query = {"deviceId": device_id, "refreshToken": refresh_token_value}

    # Accept / Content-Type 已参与签名运算，不要在下面覆盖它们，否则会与签名时的值不一致导致校验失败。
    headers = build_native_signature("GET", path, query)
    headers["ca_version"] = "1"
    headers["x-requiretoken"] = "false"
    headers["oauth"] = "false"
    headers["User-Agent"] = NATIVE_ANDROID_UA
    headers.update(NATIVE_DEVICE_HEADERS)

    url = NATIVE_BASE_URL + path
    resp = requests.get(url, params=query, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return _parse_refresh_response(data, refresh_token_value)


def refresh_token(refresh_token_value: str, device_id: str) -> dict:
    """依次尝试 AppCode 静态认证、HMAC 签名认证换取新 token，两者均失败时抛出异常。"""
    try:
        return refresh_token_by_appcode(refresh_token_value, device_id)
    except Exception as e_appcode:
        try:
            return refresh_token_by_signature(refresh_token_value, device_id)
        except Exception as e_sig:
            raise RuntimeError(
                f"refreshToken 续期失败，两套认证方案均未成功。\n"
                f"  方案一(AppCode)报错: {e_appcode}\n"
                f"  方案二(HMAC签名)报错: {e_sig}"
            ) from e_sig


def _save_refreshed_token(refreshed: dict) -> None:
    """续期成功后，把最新的 token/refreshToken/expireAt 回写 env.json，便于排查、留档及本地缓存判断。"""
    fields = {"token": refreshed["token"]}
    if refreshed.get("refreshToken"):
        fields["refreshToken"] = refreshed["refreshToken"]
    if refreshed.get("expireAt"):
        fields["tokenExpireAt"] = refreshed["expireAt"]
    save_env_fields(fields)


# ------------------------- 账号密码/短信验证码全流程登录，完整链路见 docs/登录接口协议说明.md -------------------------

EP_SECURITY_CONFIG = "/auth/v1/security/config"
EP_GEETEST_VALIDATE = "/auth/v1/security/geeTestV4/validate"
EP_SEND_SMS = "/auth/login/sliding/sendSms"
EP_MOBILE_CODE_LOGIN = "/auth/login/mobileCodeLogin"
EP_PASSWORD_LOGIN = "/auth/login/sliding/login"

# App 版本相关信息，需与签名头里的 gl_app_version/appVersionCode 等保持一致，
# 抓包样本版本号，实测网关未强校验必须最新版本。
APP_VERSION = "4.2.3"


def get_security_config(device_id: str) -> dict:
    """第1步：获取极验(Geetest v4)配置（GET /auth/v1/security/config?type=GEE_TEST_V4）。"""
    path = EP_SECURITY_CONFIG
    query = {"type": "GEE_TEST_V4"}
    ca_headers = {"x-ca-appcode": LOGIN_APP_CODE}
    headers = build_native_signature(
        "GET", path, query=query,
        accept="application/json; charset=utf-8",
        content_type="application/x-www-form-urlencoded; charset=utf-8",
        signature_headers_order="x-ca-appcode,x-ca-nonce,x-ca-key,x-ca-timestamp",
        extra_ca_headers=ca_headers,
    )
    headers["ca_version"] = "1"
    headers["tenantid"] = "569001643002"
    headers["x-refresh-token"] = "true"
    headers["User-Agent"] = NATIVE_ANDROID_UA
    headers["appVersionCode"] = APP_VERSION
    headers["appVersionName"] = "402030320"
    headers["publicPlatform"] = "android"
    headers.update(NATIVE_DEVICE_HEADERS)
    headers["gl_dev_id"] = device_id  # 覆盖 NATIVE_DEVICE_HEADERS 里的默认设备id

    url = NATIVE_BASE_URL + path
    resp = requests.get(url, params=query, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def validate_geetest(device_id: str, lot_number: str, captcha_output: str,
                      pass_token: str, gen_time: str, scene: str) -> dict:
    """
    第3步：校验极验滑块结果，成功后返回 certifyId（=lot_number）。
    scene 取值："passwordLogin"（密码登录）/ "mobileLoginSendsms"（短信登录）。
    """
    path = EP_GEETEST_VALIDATE
    body_dict = {
        "passToken": pass_token,
        "lotNumber": lot_number,
        "genTime": gen_time,
        "captchaOutput": captcha_output,
        "scene": scene,
    }
    body_bytes = json.dumps(body_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    ca_headers = {"x-ca-appcode": LOGIN_APP_CODE}
    headers = build_native_signature(
        "POST", path,
        accept="application/json; charset=utf-8",
        content_type="application/json; charset=utf-8",
        signature_headers_order="x-ca-appcode,x-ca-nonce,x-ca-key,x-ca-timestamp",
        body=body_bytes,
        extra_ca_headers=ca_headers,
    )
    headers["ca_version"] = "1"
    headers["tenantid"] = "569001643002"
    headers["x-refresh-token"] = "true"
    headers["User-Agent"] = NATIVE_ANDROID_UA
    headers["appVersionCode"] = APP_VERSION
    headers["appVersionName"] = "402030320"
    headers["publicPlatform"] = "android"
    headers.update(NATIVE_DEVICE_HEADERS)
    headers["gl_dev_id"] = device_id  # 覆盖 NATIVE_DEVICE_HEADERS 里的默认设备id

    url = NATIVE_BASE_URL + path
    resp = requests.post(url, data=body_bytes, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def send_login_sms(device_id: str, mobile: str, certify_id: str) -> dict:
    """第4步：凭 certifyId（=lot_number）给手机号发送登录短信验证码。"""
    path = EP_SEND_SMS
    body_dict = {"mobile": mobile, "challenge": certify_id}
    body_bytes = json.dumps(body_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    headers = build_native_signature(
        "POST", path,
        accept="application/json; charset=utf-8",
        content_type="application/json; charset=utf-8",
        signature_headers_order="x-ca-nonce,x-ca-timestamp,x-ca-key",
        body=body_bytes,
    )
    headers["ca_version"] = "1"
    headers["User-Agent"] = NATIVE_ANDROID_UA
    headers["appVersionCode"] = APP_VERSION
    headers["appVersionName"] = "402030320"
    headers["publicPlatform"] = "android"
    headers.update(NATIVE_DEVICE_HEADERS)
    headers["gl_dev_id"] = device_id  # 覆盖 NATIVE_DEVICE_HEADERS 里的默认设备id

    url = NATIVE_BASE_URL + path
    resp = requests.post(url, data=body_bytes, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def login_by_mobile_code(device_id: str, mobile: str, verification_code: str) -> dict:
    """
    第5步：手机号 + 短信验证码完成最终登录，返回值经
    _parse_refresh_response 同款结构解析后含 token/refreshToken。

    注意：该接口所有业务参数均通过 query string 传递，而非 JSON body；
    body 固定为空 JSON 对象 "{}"，但仍需据此计算 Content-MD5 参与签名。
    """
    path = EP_MOBILE_CODE_LOGIN
    query = {
        "deviceType": "ANDROID",
        "appVersion": APP_VERSION,
        "hardwareDeviceId": device_id,
        "mobile": mobile,
        "deviceModel": NATIVE_DEVICE_HEADERS.get("gl_dev_model", "sdk_gphone64_arm64"),
        "verificationCode": verification_code,
    }
    body_bytes = b"{}"

    headers = build_native_signature(
        "POST", path, query=query,
        accept="application/json; charset=utf-8",
        content_type="application/json; charset=utf-8",
        signature_headers_order="x-ca-nonce,x-ca-timestamp,x-ca-key",
        body=body_bytes,
    )
    headers["certifyid"] = ""
    headers["ca_version"] = "1"
    headers["User-Agent"] = NATIVE_ANDROID_UA
    headers["appVersionCode"] = APP_VERSION
    headers["appVersionName"] = "402030320"
    headers["publicPlatform"] = "android"
    headers.update(NATIVE_DEVICE_HEADERS)
    headers["gl_dev_id"] = device_id  # 覆盖 NATIVE_DEVICE_HEADERS 里的默认设备id

    url = NATIVE_BASE_URL + path
    resp = requests.post(url, params=query, data=body_bytes, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    result = _parse_refresh_response(data, refresh_token_value="")
    result["deviceId"] = device_id
    return result


def login_by_password(device_id: str, username: str, password_md5: str, certify_id: str,
                       hardware_device_id: str = None, device_type: str = "ANDROID") -> dict:
    """
    【参考实现，不建议依赖】账号密码登录（sliding/login）。陌生设备会被风控拦截为
    untrusted.device，需改走 send_login_sms + login_by_mobile_code 兜底；password_md5
    加密算法未完全逆向确认。device_type="IOS" 时使用不同的签名 header 顺序/大小写规则
    （详见 docs/登录接口协议说明.md）。
    """
    path = EP_PASSWORD_LOGIN
    is_ios = device_type.upper() == "IOS"
    query = {
        "deviceType": device_type.upper(),
        "appVersion": APP_VERSION,
        "password": password_md5,
        "hardwareDeviceId": hardware_device_id or device_id,
        "challenge": certify_id,
        "deviceModel": NATIVE_DEVICE_HEADERS.get("gl_dev_model", "sdk_gphone64_arm64"),
        "username": username,
    }
    body_bytes = b"{}"

    if is_ios:
        nonce = str(uuid.uuid4())
        timestamp = str(int(time.time() * 1000))
        signature_header_items = [
            ("X-Ca-Key", NATIVE_APP_KEY),
            ("X-Ca-Nonce", nonce),
            ("X-Ca-Signature-Method", "HmacSHA256"),
            ("X-Ca-Timestamp", timestamp),
            ("X-Ca-Version", "1"),
            ("token", ""),
        ]
        headers = build_native_signature(
            "POST", path, query=query,
            accept="application/json",
            content_type="application/json; charset=UTF-8",
            signature_headers_order="X-Ca-Key,X-Ca-Nonce,X-Ca-Signature-Method,X-Ca-Timestamp,X-Ca-Version,token",
            body=body_bytes,
            signature_header_items=signature_header_items,
        )
        headers.pop("_nonce", None)
        headers.pop("_timestamp", None)
        headers["certifyid"] = ""
        headers["User-Agent"] = "CA_iOS_SDK_2.0"
        headers["appVersionCode"] = APP_VERSION
        headers["appVersionName"] = "40203073"
        headers["publicPlatform"] = "iOS"
        headers["gl_dev_brand"] = "Apple"
        headers["gl_app_build"] = "40203073"
        headers["gl_dev_platform"] = "iOS"
        headers["gl_dev_name"] = "iPhone"
        headers["gl_os_version"] = "27.0"
        headers["gl_dev_model"] = "iPhone 15 Pro"
        headers["gl_dev_id"] = hardware_device_id or device_id
        headers["gl_app_version"] = APP_VERSION
        headers["gl_user_id"] = ""
    else:
        headers = build_native_signature(
            "POST", path, query=query,
            accept="application/json; charset=utf-8",
            content_type="application/json; charset=utf-8",
            signature_headers_order="x-ca-nonce,x-ca-timestamp,x-ca-key",
            body=body_bytes,
        )
        headers["certifyid"] = ""
        headers["ca_version"] = "1"
        headers["User-Agent"] = NATIVE_ANDROID_UA
        headers["appVersionCode"] = APP_VERSION
        headers["appVersionName"] = "402030320"
        headers["publicPlatform"] = "android"
        headers.update(NATIVE_DEVICE_HEADERS)
        headers["gl_dev_id"] = device_id  # 覆盖 NATIVE_DEVICE_HEADERS 里的默认设备id

    url = NATIVE_BASE_URL + path
    resp = requests.post(url, params=query, data=body_bytes, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if data.get("code") != "success":
        # 未信任设备/密码错误/极验校验错误等预期内的业务分支，直接返回给调用方自行判断。
        return {"code": data.get("code"), "message": data.get("message"), "raw": data}
    result = _parse_refresh_response(data, refresh_token_value="")
    result["deviceId"] = device_id
    return result


def login_with_geetest_and_sms(mobile: str, verification_code: str,
                                device_id: str = None) -> dict:
    """
    完整登录流程的最后一步封装：给定手机号和用户收到的短信验证码，直接调用
    login_by_mobile_code 完成登录，并把结果（含 token/refreshToken/
    deviceId）写入 env.json。

    device_id 不传则自动生成一个随机值，只要求本次登录流程从获取极验配置到最终登录
    全程使用同一个值。
    """
    device_id = device_id or uuid.uuid4().hex[:16]
    result = login_by_mobile_code(device_id, mobile, verification_code)
    save_env_fields({
        "token": result["token"],
        "refreshToken": result.get("refreshToken", ""),
        "deviceId": device_id,
    })
    return result


# ------------------------- 统一 token 获取入口 -------------------------

# 本地缓存的 token 距过期时间小于该阈值(秒)时视为已失效，提前触发续期，避免请求发出后 token 恰好过期。
TOKEN_CACHE_SAFETY_MARGIN_SEC = 60


def _cached_token_valid(user_data: dict) -> str:
    """若 env.json 中缓存的 token 距 tokenExpireAt 仍有余量，返回该 token；已过期/缺失时返回空字符串。"""
    token = user_data.get("token")
    expire_at = user_data.get("tokenExpireAt")
    if not token or not expire_at:
        return ""
    try:
        remain_sec = (float(expire_at) - time.time() * 1000) / 1000
    except (TypeError, ValueError):
        return ""
    if remain_sec > TOKEN_CACHE_SAFETY_MARGIN_SEC:
        print(f"[信息] 命中本地缓存 token，距过期还剩约 {int(remain_sec)} 秒，跳过 refreshToken 续期请求。")
        return token.strip()
    return ""


def load_token() -> str:
    """
    token 获取优先级：
        1. env.json 中缓存的 token 若未过期（留 60 秒安全余量），直接复用，调试时避免
           频繁调用续期接口；
        2. 环境变量 LYNKCO_REFRESH_TOKEN + LYNKCO_DEVICE_ID，或 env.json
           user.refreshToken + user.deviceId —— 自动向网关换取最新 token（成功后
           会把 token/expireAt 写回 env.json 供下次复用）；
        3. 环境变量 LYNKCO_TOKEN 或 env.json 的 user.token（静态兜底）。
    """
    user_data = load_env_data().get("user", {})

    cached = _cached_token_valid(user_data)
    if cached:
        return cached

    refresh_token_value = os.environ.get("LYNKCO_REFRESH_TOKEN") or user_data.get("refreshToken")
    device_id = os.environ.get("LYNKCO_DEVICE_ID") or user_data.get("deviceId")

    if refresh_token_value and device_id:
        try:
            refreshed = refresh_token(refresh_token_value.strip(), device_id.strip())
            print("[信息] 已使用 refreshToken 自动续期获取最新 token。")
            _save_refreshed_token(refreshed)
            return refreshed["token"]
        except Exception as e:
            print(f"[警告] refreshToken 自动续期失败: {e}，将退回使用静态 token。")

    env_token = os.environ.get("LYNKCO_TOKEN")
    if env_token:
        return env_token.strip()

    token = user_data.get("token")
    if token:
        return token.strip()

    raise RuntimeError(
        "未找到有效的 token。请设置环境变量 LYNKCO_TOKEN，或在 env.json 的 "
        "user.token 中添加（参考 readme.md / env.json.example）。"
    )


# ------------------------- 极验 GT4 本地滑块辅助页面 -------------------------
#
# 极验人机挑战无法自动化，本地生成一个 HTML 页面加载极验官方 GT4 Web SDK，
# 用户完成滑动后页面会把 lot_number/captcha_output/pass_token/gen_time
# 拼装成一行 JSON 供复制粘贴回终端，无需手动抄写 4 个字段。

_GEETEST_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>LynkCo 极验滑块辅助验证</title>
<script src="{api_server}/www/gt4.js"></script>
<style>
  body {{ font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
         background: #0f172a; color: #e2e8f0; display: flex; flex-direction: column;
         align-items: center; padding: 40px 16px; }}
  h2 {{ margin-bottom: 4px; }}
  .hint {{ color: #94a3b8; margin-bottom: 24px; text-align: center; }}
  #captcha-box {{ margin: 16px 0; }}
  #result-box {{ width: 100%; max-width: 640px; margin-top: 24px; display: none; }}
  textarea {{ width: 100%; height: 120px; box-sizing: border-box; background: #1e293b;
             color: #4ade80; border: 1px solid #334155; border-radius: 8px; padding: 12px;
             font-family: Menlo, Consolas, monospace; font-size: 13px; }}
  button {{ margin-top: 12px; padding: 10px 20px; border: none; border-radius: 6px;
           background: #3b82f6; color: white; font-size: 14px; cursor: pointer; }}
  button:hover {{ background: #2563eb; }}
  #copied-tip {{ color: #4ade80; margin-left: 12px; display: none; }}
  #scene-label {{ color: #facc15; font-weight: bold; }}
  #error-box {{ color: #f87171; margin-top: 16px; display: none; max-width: 640px; text-align: center; }}
</style>
</head>
<body>
  <h2>LynkCo 领克 App 登录 · 极验滑块验证</h2>
  <p class="hint">
    场景：<span id="scene-label">{scene}</span> ｜ 请完成下方滑块拖动，
    成功后会自动生成结果 JSON，点击"复制"后粘贴回终端即可。
  </p>
  <div id="captcha-box"></div>
  <div id="result-box">
    <textarea id="result-text" readonly></textarea>
    <br />
    <button onclick="copyResult()">复制结果 JSON</button>
    <span id="copied-tip">已复制 ✓</span>
  </div>
  <div id="error-box">
    加载极验SDK失败，可能是浏览器拦截了本地文件跨域请求，
    请尝试更换浏览器（推荐 Chrome）重新打开本页面，或直接在领克 App 内触发一次
    登录流程走真实滑块。
  </div>

<script>
  // captcha4.geely.com/www/gt4.js 提供的是极验旧版(GT3 风格) SDK，入口函数为
  // window.initGeetest(config, callback)，config 结构为 {{captchaId, apiServers, protocol}}。
  // SDK 默认使用 "bind" 模式挂到 document.body 下的浮层且默认隐藏，需显式调用 showBox() 弹出。
  var geetestConfig = {{
    captchaId: "{captcha_id}",
    apiServers: ["{api_server_host}"],
    protocol: "https://",
  }};

  function onGeetestSuccess(captchaObj) {{
    captchaObj.onSuccess(function () {{
      var result = captchaObj.getValidate();
      // result: {{lot_number, captcha_output, pass_token, gen_time}}
      var payload = {{
        lotNumber: result.lot_number,
        captchaOutput: result.captcha_output,
        passToken: result.pass_token,
        genTime: result.gen_time,
        scene: "{scene}",
      }};
      var text = JSON.stringify(payload);
      document.getElementById("result-text").value = text;
      document.getElementById("result-box").style.display = "block";
    }});
    captchaObj.onError(function () {{
      document.getElementById("error-box").style.display = "block";
    }});
    captchaObj.onClose(function () {{
      // 面板被用户关闭后，提供一个入口可以重新打开，避免用户卡住。
      document.getElementById("captcha-box").innerHTML =
        '<button onclick="window.__captchaObj.showBox()">重新打开滑块验证</button>';
    }});
    window.__captchaObj = captchaObj;
    captchaObj.appendTo("#captcha-box");
    captchaObj.showBox();
  }}

  function copyResult() {{
    var textarea = document.getElementById("result-text");
    textarea.select();
    document.execCommand("copy");
    var tip = document.getElementById("copied-tip");
    tip.style.display = "inline";
    setTimeout(function () {{ tip.style.display = "none"; }}, 1500);
  }}

  if (typeof initGeetest === "function") {{
    initGeetest(geetestConfig, onGeetestSuccess);
  }} else {{
    document.getElementById("error-box").style.display = "block";
  }}
</script>
</body>
</html>
"""


def generate_geetest_html(scene: str, config: dict = None, device_id: str = None) -> str:
    """
    生成本地极验 GT4 滑块辅助页面，返回写入的 HTML 文件绝对路径。

    scene: "passwordLogin" 或 "mobileLoginSendsms"，会写入页面标题和最终生成
        的 JSON 结果中，方便直接传给 validate_geetest()。
    config: get_security_config() 的返回值；不传则内部自动请求一次
        （需要 device_id）。
    """
    if config is None:
        if not device_id:
            device_id = uuid.uuid4().hex[:16]
        config = get_security_config(device_id)

    data = config.get("data") or {}
    captcha_id = data.get("captchaId")
    # gt4.js 固定挂在 apiServer 域名下的 /www/gt4.js，不能用 staticServer 拼接
    # （那是 gt4.js 加载后再去请求其他资源用的基础路径，会得到 404）。
    api_server = data.get("apiServer") or "https://captcha4.geely.com"
    # apiServers 传给 initGeetest() 时必须是纯域名，带 "https://" 协议头会导致请求地址拼接错误。
    api_server_host = api_server.split("://", 1)[-1].rstrip("/")
    if not captcha_id:
        raise RuntimeError(f"极验配置响应中未找到 captchaId: {config}")

    html = _GEETEST_HTML_TEMPLATE.format(
        api_server=api_server,
        api_server_host=api_server_host,
        captcha_id=captcha_id,
        scene=scene,
    )

    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geetest_helper.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    return html_path


def _parse_geetest_result_json(raw: str) -> dict:
    """解析用户从辅助页面复制粘贴回来的一行 JSON，容错处理首尾多余字符。"""
    raw = raw.strip()
    result = json.loads(raw)
    required = ("lotNumber", "captchaOutput", "passToken", "genTime", "scene")
    missing = [k for k in required if not result.get(k)]
    if missing:
        raise ValueError(f"粘贴的 JSON 缺少必要字段: {missing}，原始输入: {raw}")
    return result


def serve_geetest_html(html_path: str):
    """
    启动本机临时 HTTP 服务（仅监听 127.0.0.1）以 http:// 形式提供页面，避免
    file:// 协议被浏览器安全策略拦截极验 SDK 的跨域脚本请求。
    返回 (httpd, thread, url)，调用方结束后应调用 httpd.shutdown()。
    """
    import http.server
    import socketserver
    import threading

    directory = os.path.dirname(html_path)
    filename = os.path.basename(html_path)

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

        def log_message(self, format, *args):  # noqa: A002 - 屏蔽默认访问日志刷屏
            pass

    # port=0 由系统自动分配一个空闲端口，避免和其他本地服务冲突。
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}/{filename}"
    return httpd, thread, url


def main():
    """
    命令行辅助入口：交互式完成一次「极验滑块 + 短信验证码」登录。

    用法：python3 lynkco_login.py <手机号>，运行后会依次：生成本地极验滑块
    辅助页面并自动打开 -> 用户完成滑块后粘贴结果 JSON 回终端 -> 调用
    validate_geetest 换取 certifyId -> 发送短信验证码 -> 输入验证码完成登录并写入 env.json。
    """
    if len(sys.argv) < 2:
        print("用法: python3 lynkco_login.py <手机号>")
        sys.exit(1)

    mobile = sys.argv[1].strip()
    device_id = uuid.uuid4().hex[:16]

    print("=== 第1步：获取极验配置 ===")
    try:
        config = get_security_config(device_id)
        print(config)
    except Exception as e:
        print(f"[错误] 获取极验配置失败: {e}")
        sys.exit(1)

    print("\n=== 第2步：生成本地极验滑块辅助页面 ===")
    html_path = None
    httpd = None
    try:
        html_path = generate_geetest_html("mobileLoginSendsms", config=config)
        # file:// 直接打开会被部分浏览器拦截跨域脚本请求，改用本地 HTTP 服务器提供页面。
        httpd, _thread, url = serve_geetest_html(html_path)
        print(f"辅助页面已生成: {html_path}")
        print(f"本地服务已启动: {url}")
        import webbrowser
        webbrowser.open(url)
        print("已尝试用默认浏览器打开，若未自动打开请手动复制上面的地址在浏览器中打开。")
    except Exception as e:
        print(f"[警告] 自动生成/打开辅助页面失败（可退回手动输入模式）: {e}")

    try:
        print("\n请在打开的页面里完成滑块拖动，成功后点击「复制结果 JSON」，")
        print("然后粘贴到下方（一行 JSON，形如")
        print('  {"lotNumber":"...","captchaOutput":"...","passToken":"...","genTime":"...","scene":"mobileLoginSendsms"}')
        print("）：")
        raw_json = input("> ").strip()

        try:
            geetest_result = _parse_geetest_result_json(raw_json)
        except Exception as e:
            print(f"[错误] 解析粘贴内容失败: {e}")
            sys.exit(1)

        print("\n=== 第3步：校验极验结果 ===")
        try:
            validate_result = validate_geetest(
                device_id,
                geetest_result["lotNumber"],
                geetest_result["captchaOutput"],
                geetest_result["passToken"],
                geetest_result["genTime"],
                geetest_result["scene"],
            )
            print(validate_result)
            certify_id = (validate_result.get("data") or {}).get("certifyId")
            if not certify_id:
                print(f"[错误] 极验校验响应中未找到 certifyId: {validate_result}")
                sys.exit(1)
        except Exception as e:
            print(f"[错误] 极验校验失败: {e}")
            sys.exit(1)

        print("\n=== 第4步：发送登录短信验证码 ===")
        try:
            sms_result = send_login_sms(device_id, mobile, certify_id)
            print(sms_result)
        except Exception as e:
            print(f"[错误] 发送短信验证码失败: {e}")
            sys.exit(1)

        verification_code = input("\n请输入收到的短信验证码: ").strip()

        print("\n=== 第5步：登录 ===")
        try:
            result = login_with_geetest_and_sms(mobile, verification_code, device_id=device_id)
            safe_result = {k: v for k, v in result.items() if k != "token"}
            safe_result["token"] = "***"
            print("登录成功，已写入 env.json：")
            print(safe_result)
        except Exception as e:
            print(f"[错误] 登录失败: {e}")
            sys.exit(1)
    finally:
        _cleanup_geetest_resources(httpd, html_path)


def _cleanup_geetest_resources(httpd, html_path):
    """统一清理本地 HTTP 服务器和生成的辅助 HTML 文件，任何异常均静默忽略。"""
    if httpd is not None:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
    if html_path and os.path.exists(html_path):
        try:
            os.remove(html_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
