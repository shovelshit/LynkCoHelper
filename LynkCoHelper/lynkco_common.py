# -*- coding: utf-8 -*-
"""
领克 App 相关脚本的公共基础模块：App 原生阿里云 API 网关签名算法
（build_native_signature），以及 env.json 读写辅助函数
（load_env_data / save_env_fields）。

env.json 结构（四个子对象）：
    {
      "user": {"username": "", "password": "", "token": "", "refreshToken": "", "deviceId": "",
                "tokenExpireAt": ""},
      "secrets": {"nativeAppKey": "", "nativeAppSecret": "", "nativeAppCode": "",
                  "loginAppCode": ""},
      "notify": {"barkKey": "", "feiShuWebhook": "", "dingTalkWebhook": "", "weComWebhook": ""},
      "ai": {"provider": "chatanywhere", "model": "gpt-4o-mini", "apiKey": ""}
    }

密钥读取优先级：单独环境变量 > 整合环境变量 LYNKCO_APP_SECRETS（JSON 字符串，
结构同 env.json["secrets"]） > env.json["secrets"] 对应字段，均未配置时报错。
签名算法与密钥来源详见 docs/AppSecret_逆向分析记录.md。
"""
import base64
import hashlib
import hmac
import json
import os
import time
import uuid

import requests.exceptions

ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "env.json")


def env_value(name: str, default: str = "") -> str:
    """Read one string environment value with consistent whitespace handling."""
    value = os.environ.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else default

# 网络请求默认超时（秒），GitHub Actions runner 到领克服务器延迟较高，
# 15 秒不够。可通过环境变量覆盖。
DEFAULT_TIMEOUT = int(env_value("LYNKCO_TIMEOUT", "30"))
AI_TIMEOUT = int(env_value("LYNKCO_AI_TIMEOUT", "60"))
# 超时/断连后自动重试次数（每次间隔 3 秒），重试时会重新生成签名。
DEFAULT_RETRIES = int(env_value("LYNKCO_RETRIES", "2"))

# 密钥字段名 -> (环境变量名, env.json["secrets"] 字段名)
_SECRET_SPECS = {
    "NATIVE_APP_KEY": ("LYNKCO_NATIVE_APP_KEY", "nativeAppKey"),
    "NATIVE_APP_SECRET": ("LYNKCO_NATIVE_APP_SECRET", "nativeAppSecret"),
    "NATIVE_APP_CODE": ("LYNKCO_NATIVE_APP_CODE", "nativeAppCode"),
    "LOGIN_APP_CODE": ("LYNKCO_LOGIN_APP_CODE", "loginAppCode"),
}


def _load_bundled_secrets() -> dict:
    """解析整合环境变量 LYNKCO_APP_SECRETS，未配置或解析失败时返回空 dict。"""
    raw = env_value("LYNKCO_APP_SECRETS")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _get_secret(name: str) -> str:
    """按“单独环境变量 > LYNKCO_APP_SECRETS > env.json[secrets] 字段”优先级取值。"""
    env_var, json_key = _SECRET_SPECS[name]
    value = (
        env_value(env_var)
        or _load_bundled_secrets().get(json_key)
        or load_env_data().get("secrets", {}).get(json_key)
    )
    if not value:
        raise RuntimeError(
            f"缺少必需的签名密钥 {name}，请通过环境变量 {env_var}、整合环境变量 "
            f"LYNKCO_APP_SECRETS（JSON 字符串中的 {json_key} 字段）或 env.json 的 "
            f"secrets.{json_key} 字段配置（参考 env.json.example）。"
        )
    return value


BASE_URL = "https://app-api-gw-toc.lynkco.com"
NATIVE_BASE_URL = "https://app-services.lynkco.com.cn"

NATIVE_APP_UA = "CA_iOS_SDK_2.0"

APP_VERSION = "4.2.8"
APP_BUILD = "40208072"
IOS_DEVICE_NAME = "iPhone"
IOS_DEVICE_MODEL = "iPhone 15 Pro"
IOS_OS_VERSION = "27.0.1"
MAX_COMMENT_CHARS = 500
AI_PROMPT_MAX_CHARS = 50
IOS_SIGNATURE_HEADERS = "X-Ca-Key,X-Ca-Nonce,X-Ca-Signature-Method,X-Ca-Timestamp,X-Ca-Version,token"


def _build_native_device_headers() -> dict:
    """Build the fixed iOS device headers from the latest captured request."""
    return {
        "gl_dev_name": IOS_DEVICE_NAME,
        "gl_dev_model": IOS_DEVICE_MODEL,
        "gl_dev_brand": "Apple",
        "gl_dev_platform": "iOS",
        "gl_os_version": IOS_OS_VERSION,
        "gl_app_version": APP_VERSION,
        "gl_app_build": APP_BUILD,
        "gl_dev_id": env_value("LYNKCO_DEVICE_ID") or
                     str((load_env_data().get("user") or {}).get("deviceId") or "").strip(),
    }


def build_native_app_headers(device_id: str = None, token: str = None,
                             account_id: str = None, extra: dict = None) -> dict:
    """Build the single iOS header set captured from the latest HAR."""
    headers = {
        "User-Agent": NATIVE_APP_UA,
        "appVersionCode": APP_VERSION,
        "appVersionName": APP_BUILD,
        "publicPlatform": "iOS",
        **_build_native_device_headers(),
    }
    if device_id:
        headers["gl_dev_id"] = device_id
    if token:
        headers["svcsid"] = token
    if account_id:
        headers["gl_user_id"] = account_id
    if extra:
        headers.update(extra)
    return headers


def build_ios_security_info() -> str:
    """Build the non-secret iOS risk metadata used by the share endpoint."""
    device_id = _build_native_device_headers()["gl_dev_id"]
    return json.dumps({
        "osVersion": IOS_OS_VERSION,
        "platform": "ios",
        "os": "iOS",
        "brand": "Apple",
        "model": IOS_DEVICE_MODEL,
        "appVersion": APP_VERSION,
        "isUsingVpn": "true",
        "isSetProxy": "true",
        "isJailbreak": "false",
        "isCharging": "4",
        "battery": "95",
        "networkType": "NETWORK_5G",
        "screenResolution": "1179 * 2556",
        "channel": "ios%E5%AE%98%E6%96%B9",
        "geelyDeviceId": device_id,
        "deviceUUID": device_id,
        "deviceToken": "",
    }, ensure_ascii=False, separators=(",", ":"))




# 以下模块级“常量”通过 __getattr__（PEP 562）惰性求值，取值时才读取配置。
_LAZY_ATTRS = {
    "NATIVE_APP_KEY": lambda: _get_secret("NATIVE_APP_KEY"),
    "NATIVE_APP_SECRET": lambda: _get_secret("NATIVE_APP_SECRET"),
    "NATIVE_APP_CODE": lambda: _get_secret("NATIVE_APP_CODE"),
    "LOGIN_APP_CODE": lambda: _get_secret("LOGIN_APP_CODE"),
}


def __getattr__(name: str):
    if name in _LAZY_ATTRS:
        return _LAZY_ATTRS[name]()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def request_with_retry(session, method: str, url: str, *, build_headers, retries: int = DEFAULT_RETRIES, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> requests.Response:
    """带超时重试的请求封装。build_headers 是一个无参回调，每次尝试（含重试）
    时调用以重新生成签名头（刷新 nonce/timestamp），保证签名时效性。
    遇到 ReadTimeout / ConnectionError 时等待 3 秒后重试，最多 retries 次。"""
    last_exc = None
    for attempt in range(retries + 1):
        headers = build_headers()
        try:
            return session.request(method, url, headers=headers, timeout=timeout, **kwargs)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
            last_exc = e
            if attempt < retries:
                print(f"[警告] 请求超时/断连，3秒后重试（第 {attempt + 1}/{retries} 次）: {e}")
                time.sleep(3)
            else:
                print(f"[警告] 请求重试 {retries} 次后仍失败: {e}")
    raise last_exc


def _format_gmt_date() -> str:
    """生成 HTTP 标准 GMT 时间格式，如 'Wed, 08 Jul 2026 09:49:57 GMT'。"""
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())


def build_native_signature(method: str, path: str, query: dict = None,
                            accept: str = "application/json; charset=utf-8",
                            content_type: str = "application/x-www-form-urlencoded; charset=utf-8",
                            signature_headers_order: str = "x-ca-nonce,x-ca-timestamp,x-ca-key",
                            body: bytes = None,
                            extra_ca_headers: dict = None,
                            signature_header_items=None) -> dict:
    """
    复刻领克 App 原生 SDK 访问 app-services.lynkco.com.cn 网关的签名逻辑，
    对照阿里云官方 SDK `SignUtil.buildStringToSign` 实现：

        METHOD\\n Accept\\n Content-MD5\\n Content-Type\\n Date\\n
        (参与签名的 header，每行 "name:value\\n") path(?排序后的query)

    参数说明：
        extra_ca_headers: 额外的 x-ca- 前缀头，与默认的 x-ca-key/nonce/timestamp
            一起按字典序排序参与签名。
        signature_header_items: 传入 [(name, value), ...] 或接收 (nonce, timestamp)
            并返回该列表的函数，可自定义参与签名的 header 集合/顺序/大小写。
        body: 传入则计算 Content-MD5 = Base64(MD5(body))，部分登录接口会校验，
            默认接口（refresh/getShareCode）无需传。

    签名 = Base64(HMAC-SHA256(待签名字符串, appSecret))
    """
    nonce = str(uuid.uuid4())
    timestamp = str(int(time.time() * 1000))
    date_str = _format_gmt_date()

    content_md5 = ""
    if body:
        content_md5 = base64.b64encode(hashlib.md5(body).digest()).decode()

    parts = [method.upper(), "\n", accept, "\n", content_md5, "\n", content_type, "\n", date_str, "\n"]

    if signature_header_items is not None:
        header_items = (signature_header_items(nonce, timestamp)
                        if callable(signature_header_items) else signature_header_items)
        result_headers = {}
        for name, value in header_items:
            parts.append(f"{name}:{value}")
            parts.append("\n")
            result_headers[name] = value
    else:
        ca_headers = {
            "x-ca-key": _get_secret("NATIVE_APP_KEY"),
            "x-ca-nonce": nonce,
            "x-ca-timestamp": timestamp,
        }
        if extra_ca_headers:
            ca_headers.update(extra_ca_headers)
        for k in sorted(ca_headers.keys()):
            parts.append(f"{k}:{ca_headers[k]}")
            parts.append("\n")
        result_headers = dict(ca_headers)

    parts.append(path)
    if query:
        sorted_query = "&".join(f"{k}={v}" for k, v in sorted(query.items()) if v is not None and v != "")
        if sorted_query:
            parts.append("?")
            parts.append(sorted_query)

    string_to_sign = "".join(parts)
    digest = hmac.new(_get_secret("NATIVE_APP_SECRET").encode(), string_to_sign.encode(), hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode()

    result = dict(result_headers)
    result["x-ca-signature-headers"] = signature_headers_order
    result["x-ca-signature"] = signature
    result["date"] = date_str
    result["accept"] = accept
    result["content-type"] = content_type
    if content_md5:
        result["content-md5"] = content_md5
    result["_nonce"] = nonce
    result["_timestamp"] = timestamp
    return result


def build_ios_signature(method: str, path: str, token: str = "", query: dict = None,
                        body: bytes = None,
                        accept: str = "application/json",
                        content_type: str = "application/json; charset=UTF-8") -> dict:
    """Build the exact iOS signature header set captured in the latest HAR."""
    normalized_token = token or ""

    def signature_items(nonce, timestamp):
        return [
            ("X-Ca-Key", _get_secret("NATIVE_APP_KEY")),
            ("X-Ca-Nonce", nonce),
            ("X-Ca-Signature-Method", "HmacSHA256"),
            ("X-Ca-Timestamp", timestamp),
            ("X-Ca-Version", "1"),
            ("token", normalized_token),
        ]

    headers = build_native_signature(
        method, path, query=query, accept=accept, content_type=content_type,
        body=body, signature_headers_order=IOS_SIGNATURE_HEADERS,
        signature_header_items=signature_items,
    )
    headers.pop("_nonce", None)
    headers.pop("_timestamp", None)
    return headers


def load_env_data() -> dict:
    """读取 env.json，返回标准配置节；缺失节使用空 dict。"""
    if not os.path.exists(ENV_FILE):
        return {"user": {}, "secrets": {}, "notify": {}, "ai": {}}
    with open(ENV_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {"user": {}, "secrets": {}, "notify": {}, "ai": {}}
    return {
        "user": data.get("user") or {},
        "secrets": data.get("secrets") or {},
        "notify": data.get("notify") or {},
        "ai": data.get("ai") or {},
    }


def save_env_fields(fields: dict, section: str = "user") -> None:
    """把 fields 写入/更新到 env.json 的指定子对象（默认 "user"），文件或子对象不存在时自动创建。"""
    try:
        raw = load_env_data() if not os.path.exists(ENV_FILE) else json.load(open(ENV_FILE, "r", encoding="utf-8"))
        if not isinstance(raw, dict):
            raw = {}
        raw.setdefault(section, {})
        if not isinstance(raw[section], dict):
            raw[section] = {}
        raw[section].update(fields)
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# 打印接口响应到控制台/CI日志前需要脱敏的字段名（不区分大小写，同时匹配
# userId/user_id/accountId/account_id 等驼峰、下划线两种命名风格）。
_SENSITIVE_LOG_KEYS = {"userid", "user_id", "accountid", "account_id"}


def mask_sensitive(data):
    """
    递归遍历 dict/list，把键名命中 _SENSITIVE_LOG_KEYS 的值替换为掩码字符串，
    用于打印接口响应到控制台/CI日志前脱敏，避免泄露 userId/accountId。
    不修改原始数据，返回一份新的结构。
    """
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if isinstance(k, str) and k.replace("-", "_").lower() in _SENSITIVE_LOG_KEYS and v is not None:
                result[k] = "***"
            else:
                result[k] = mask_sensitive(v)
        return result
    if isinstance(data, list):
        return [mask_sensitive(item) for item in data]
    return data
