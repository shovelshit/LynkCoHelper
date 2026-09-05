# -*- coding: utf-8 -*-
"""
领克 App 相关脚本的公共基础模块：H5 / App 原生两套阿里云 API 网关签名算法
（build_signature / build_native_signature），以及 env.json 读写辅助函数
（load_env_data / save_env_fields）。

env.json 结构（三个子对象）：
    {
      "user": {"username": "", "password": "", "token": "", "refreshToken": "", "deviceId": "",
                "tokenExpireAt": ""},
      "secrets": {"h5AppKey": "", "h5AppSecret": "", "nativeAppKey": "", "nativeAppSecret": "",
                  "nativeAppCode": "", "loginAppCode": "", "deviceImei": "", "glDevId": ""},
      "notify": {"barkKey": ""}
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

# 网络请求默认超时（秒），GitHub Actions runner 到领克服务器延迟较高，
# 15 秒不够。可通过环境变量覆盖。
DEFAULT_TIMEOUT = int(os.environ.get("LYNKCO_TIMEOUT", "30"))
# 超时/断连后自动重试次数（每次间隔 3 秒），重试时会重新生成签名。
DEFAULT_RETRIES = 2

# 密钥字段名 -> (环境变量名, env.json["secrets"] 字段名)
_SECRET_SPECS = {
    "H5_APP_KEY": ("LYNKCO_H5_APP_KEY", "h5AppKey"),
    "H5_APP_SECRET": ("LYNKCO_H5_APP_SECRET", "h5AppSecret"),
    "NATIVE_APP_KEY": ("LYNKCO_NATIVE_APP_KEY", "nativeAppKey"),
    "NATIVE_APP_SECRET": ("LYNKCO_NATIVE_APP_SECRET", "nativeAppSecret"),
    "NATIVE_APP_CODE": ("LYNKCO_NATIVE_APP_CODE", "nativeAppCode"),
    "LOGIN_APP_CODE": ("LYNKCO_LOGIN_APP_CODE", "loginAppCode"),
    "NATIVE_RISK_IMEI": ("LYNKCO_DEVICE_IMEI", "deviceImei"),
    "NATIVE_GL_DEV_ID": ("LYNKCO_NATIVE_GL_DEV_ID", "glDevId"),
}


def _load_bundled_secrets() -> dict:
    """解析整合环境变量 LYNKCO_APP_SECRETS，未配置或解析失败时返回空 dict。"""
    raw = os.environ.get("LYNKCO_APP_SECRETS", "").strip()
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
        os.environ.get(env_var)
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

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 13; sdk_gphone64_arm64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/109.0.5414.123 "
    "Mobile Safari/537.36"
)

NATIVE_ANDROID_UA = "ALIYUN-ANDROID-UA"


def _build_native_device_headers() -> dict:
    """设备指纹请求头，仅 gl_dev_id 来自配置，其余为固定机型字段。"""
    return {
        "gl_dev_name": "sdk_gphone64_arm64",
        "gl_dev_model": "sdk_gphone64_arm64",
        "gl_dev_brand": "Google",
        "gl_dev_platform": "android",
        "gl_os_version": "33",
        "gl_app_version": "4.2.3",
        "gl_app_build": "402030320",
        "gl_dev_id": _get_secret("NATIVE_GL_DEV_ID"),
    }


# 以下模块级“常量”通过 __getattr__（PEP 562）惰性求值，取值时才读取配置。
_LAZY_ATTRS = {
    "H5_APP_KEY": lambda: _get_secret("H5_APP_KEY"),
    "H5_APP_SECRET": lambda: _get_secret("H5_APP_SECRET"),
    "NATIVE_APP_KEY": lambda: _get_secret("NATIVE_APP_KEY"),
    "NATIVE_APP_SECRET": lambda: _get_secret("NATIVE_APP_SECRET"),
    "NATIVE_APP_CODE": lambda: _get_secret("NATIVE_APP_CODE"),
    "LOGIN_APP_CODE": lambda: _get_secret("LOGIN_APP_CODE"),
    "NATIVE_RISK_IMEI": lambda: _get_secret("NATIVE_RISK_IMEI"),
    "NATIVE_DEVICE_HEADERS": _build_native_device_headers,
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


def build_signature(method: str, path: str, accept: str = "*/*",
                     content_type: str = "application/json", query: dict = None) -> dict:
    """
    复刻领克 H5 页面 buildApiSigature() 的签名逻辑。

    待签名字符串(用 \n 连接): METHOD / Accept / "" / Content-Type / "" /
    X-Ca-Key:.. / X-Ca-Nonce:.. / X-Ca-Signature-Method:.. / X-Ca-Timestamp:.. /
    path(可带排序后的 query)，签名 = Base64(HMAC-SHA256(待签名字符串, appSecret))。
    """
    nonce = str(uuid.uuid4())
    timestamp = str(int(time.time() * 1000))

    ca_headers = {
        "X-Ca-Key": _get_secret("H5_APP_KEY"),
        "X-Ca-Nonce": nonce,
        "X-Ca-Signature-Method": "HmacSHA256",
        "X-Ca-Timestamp": timestamp,
    }

    signed_path = path
    if query:
        sorted_query = "&".join(f"{k}={v}" for k, v in sorted(query.items()) if v is not None and v != "")
        if sorted_query:
            signed_path = f"{path}?{sorted_query}"

    parts = [method.upper(), accept, "", content_type, ""]
    for k, v in ca_headers.items():
        parts.append(f"{k}:{v}")
    parts.append(signed_path)

    string_to_sign = "\n".join(parts)
    digest = hmac.new(_get_secret("H5_APP_SECRET").encode(), string_to_sign.encode(), hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode()

    result = dict(ca_headers)
    result["X-Ca-Signature-Headers"] = "X-Ca-Key,X-Ca-Timestamp,X-Ca-Nonce,X-Ca-Signature-Method"
    result["X-Ca-Signature"] = signature
    return result


def _format_gmt_date() -> str:
    """生成 HTTP 标准 GMT 时间格式，如 'Wed, 08 Jul 2026 09:49:57 GMT'。"""
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())


def build_native_signature(method: str, path: str, query: dict = None,
                            accept: str = "application/json; charset=utf-8",
                            content_type: str = "application/x-www-form-urlencoded; charset=utf-8",
                            signature_headers_order: str = "x-ca-nonce,x-ca-timestamp,x-ca-key",
                            body: bytes = None,
                            extra_ca_headers: dict = None,
                            signature_header_items: list = None) -> dict:
    """
    复刻领克 App 原生 SDK 访问 app-services.lynkco.com.cn 网关的签名逻辑，
    对照阿里云官方 SDK `SignUtil.buildStringToSign` 实现：

        METHOD\\n Accept\\n Content-MD5\\n Content-Type\\n Date\\n
        (参与签名的 header，每行 "name:value\\n") path(?排序后的query)

    参数说明：
        extra_ca_headers: 额外的 x-ca- 前缀头，与默认的 x-ca-key/nonce/timestamp
            一起按字典序排序参与签名。
        signature_header_items: 传入 [(name, value), ...] 可完全自定义参与签名
            的 header 集合/顺序/大小写（部分接口如 iOS 端登录需要），不传则用默认模式。
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
        header_items = signature_header_items
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


def load_env_data() -> dict:
    """读取 env.json，返回 {"user": {...}, "secrets": {...}, "notify": {...}} 结构；文件不存在或字段缺失时对应子对象为空 dict。"""
    if not os.path.exists(ENV_FILE):
        return {"user": {}, "secrets": {}, "notify": {}}
    with open(ENV_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {"user": {}, "secrets": {}, "notify": {}}
    return {
        "user": data.get("user") or {},
        "secrets": data.get("secrets") or {},
        "notify": data.get("notify") or {},
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
