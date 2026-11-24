---
# 郑重告知：本程序源码仅供学习研究使用，使用该程序造成的一切后果与程序作者无关
---

## 简介

领克 App「我的-签到」自动化脚本，支持每日签到、签到状态、成长等级、任务进度、分享任务、积分查询，并可通过 Bark、飞书、钉钉、企业微信推送结果。

模块划分：

| 文件 | 作用 |
| --- | --- |
| `lynkco_common.py` | 签名算法 + 公共常量 + `env.json` 读写 |
| `lynkco_login.py` | token 获取统一入口 `load_token()`，含账号密码/短信验证码全流程登录 |
| `lynkco_sign.py` | 每日签到逻辑 |
| `lynkco_share.py` | 分享任务逻辑（可选功能） |
| `lynkco_notify.py` | Bark、飞书、钉钉、企业微信推送工具 |
| `lynkco_daily_tasks.py` | 顶层入口：编排签到 + 分享 + 积分查询并推送结果 |

## AppSecret 自动提取

提取 API 密钥（`nativeAppKey` / `nativeAppSecret`），写入 `env.json` 的 `secrets` 段。统一入口支持直接从已验证的 4.3.0 / 4.3.1 APK 离线提取 KeyVault 固定槽位，无需 Android 环境；不含 KeyVault 的 4.2.9 保留模拟器 + jdb 流程。未知 KeyVault 库会明确报错，避免错误套用偏移。

### 提取入口（`tools/`）

| 脚本 | 平台 | 说明 |
| --- | --- | --- |
| `tools/extract_appsecret_github_action.py` | Python / GitHub Actions | 唯一入口：4.3.x 离线提取；4.2.9 才准备 Android 环境 |

本地 4.3.x 示例（在仓库根目录执行）：

```bash
python3 LynkCoHelper/tools/extract_appsecret_github_action.py --apk /path/to/lynkco.apk
```

也支持 `--apk-version 4.3.1` 从上游 Release 下载。成功后确认写入配置；设置 `LYNKCO_AUTO_WRITE=1` 可免确认。

### CI workflows（`.github/workflows/`）

| Workflow | 触发 | 作用 |
| --- | --- | --- |
| `extract-appsecret` | 手动 | `apk_version` 默认 `4.3.1`，可填 `X.Y.Z` 或 `latest`；提取后输出**一次性取件链接**（仅可打开 1 次、10 分钟失效），需手动填入 `LYNKCO_APP_SECRETS` 供 daily-tasks 使用 |
| `fetch-lynkco-apk` | 每日 + 手动 | 拉取最新版领克 APK 上传 Release（`apk-vX.Y.Z` 留历史 + `apk-latest` 稳定资产） |

### 安全说明

- 新增静态路径隐藏完整凭据；旧版调试流程在 CI 中脱敏，本地可能显示明文。生成的 `env.json` 已被 gitignore；CI 沿用一次性链接送达明文的既有行为。
- Action 的 `apk_version` 默认 `4.3.1`；指定 `X.Y.Z` 使用对应版本 Release，`latest` 读取 `apk-latest/lynkco-latest.apk`（当前为 4.3.1，后续随 Release 更新）。离线静态路径不依赖模拟器；只有 4.2.9 兼容流程使用固定的 x86_64 模拟器镜像。

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置账号与密钥

复制 `env.json.example` 为 `env.json`，按需填写：

```json
{
  "user": {
    "username": "",
    "password": "",
    "token": "bearerXXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "refreshToken": "",
    "deviceId": ""
  },
  "secrets": {
    "nativeAppKey": "",
    "nativeAppSecret": "",
    "nativeAppCode": "",
    "loginAppCode": ""
  },
  "notify": {
    "barkKey": "",
    "feiShuWebhook": "",
    "dingTalkWebhook": "",
    "weComWebhook": ""
  }
}
```

- `user`：账号相关凭据（token 至少需要一个，见下）。
- `secrets`：领克 App 的应用级签名密钥（非个人凭证，但代码中不内置，必须自行配置），获取方式：运行 `tools/extract_appsecret_*.py` 自动提取，或抓包分析。每个字段都支持用同名大写环境变量覆盖（如 `LYNKCO_NATIVE_APP_KEY`）；也可用一个整合环境变量 `LYNKCO_APP_SECRETS`（值为与 `secrets` 结构相同的 JSON 字符串）一次性提供全部 4 个字段，适合 CI 只想配置一个 Secret 的场景（优先级：单独字段环境变量 > `LYNKCO_APP_SECRETS` > `env.json`）。均未配置时程序会直接报错退出。
- `notify`：推送相关配置。支持 `barkKey`、`feiShuWebhook`、`dingTalkWebhook`、`weComWebhook`，也可使用环境变量 `LYNKCO_BARK_KEY`、`LYNKCO_FEISHU_WEBHOOK`、`LYNKCO_DINGTALK_WEBHOOK`、`LYNKCO_WECOM_WEBHOOK` 覆盖。未配置的渠道会跳过。

### 3. 获取 token

登录环节含极验滑块验证，无法完全自动化，需人工/半自动获取一次：

- **token**（约 30 分钟有效）：写入 `user.token`，或设置环境变量 `LYNKCO_TOKEN`。
- **refreshToken + deviceId**（约 30 天有效，推荐）：写入 `user.refreshToken` / `user.deviceId`，或设置环境变量 `LYNKCO_REFRESH_TOKEN` / `LYNKCO_DEVICE_ID`。配置后脚本每次运行会自动续期 token 并回写 `env.json`，无需频繁手动登录。

获取方式：抓包登录一次领克 App，或运行 `python3 lynkco_login.py <手机号>` 交互式完成滑块 + 短信登录（会自动写入 `env.json`）。

### 4. 执行

```bash
python3 lynkco_helper.py         # 签到 + 分享
python3 lynkco_daily_tasks.py    # 签到 + 分享 + 状态查询 + 按配置推送
```

分享任务（`lynkco_share.py`）每日有加分次数上限，接口返回成功不代表真正加分，重复调用不会重复加分。

可选环境变量：

| 变量 | 说明 |
| --- | --- |
| `LYNKCO_BARK_KEY` | Bark 推送的 Key，未配置则跳过推送（也可写入 `env.json` 的 `notify.barkKey`） |
| `LYNKCO_FEISHU_WEBHOOK` | 飞书自定义机器人 Webhook，可选 |
| `LYNKCO_DINGTALK_WEBHOOK` | 钉钉自定义机器人 Webhook，可选 |
| `LYNKCO_WECOM_WEBHOOK` | 企业微信机器人 Webhook，可选 |
| `LYNKCO_ENERGY_DELAY` | 签到/分享后查询积分前的等待秒数，默认 5 |
| `LYNKCO_BARK_ICON` | Bark 推送使用的自定义图标 URL，可选 |
| `LYNKCO_TIMEOUT` | 领克接口统一请求超时秒数，默认 30 |
| `LYNKCO_RETRIES` | 领克接口超时/断连重试次数，默认 2 |
| `LYNKCO_AI_TIMEOUT` | AI 请求超时秒数，默认 60 |

每日通知包含今日签到状态、连续签到/签到卡、成长等级与成长值、积分变化和任务进度。配置了哪些渠道就发送哪些渠道，单个渠道失败不会影响任务结果。

### GRIC 车辆接口（独立配置）

`geely_gric.py` 使用独立的 GRIC 签名及 `geely_env.json`，不替代上面的签到配置。先复制 `geely_env.json.example` 为 `geely_env.json`；模板是可解析的 JSON，敏感字段留空，不能直接用于联网。填写 `gricSecret`（GRIC HMAC 密钥）和 `lynkcoAppsecret`（领克 access-code 请求头的 appsecret），并按上文配置 `env.json` 中的领克登录态及原生签名密钥。不要提交这两个本地配置文件。

```bash
python3 geely_gric.py auth          # 领克登录态 -> access-code -> GRIC JWT，写回配置
python3 geely_gric.py vehicle-init  # 获取默认车辆并生成 identifier/series，写回配置
python3 geely_gric.py hb            # 验证 GRIC 请求；需要有效凭据和车辆配置
```

`GrwbClient()` 在没有显式 JWT 和 `GEELY_GRIC_JWT` 时使用 `load_jwt()`：先读取尚未过期的 `geely_env.json` 缓存，否则重新执行认证并回写。手动传入的 JWT 优先于环境变量；设置 `GEELY_GRIC_JWT` 后直接使用该值，不会替它自动续期。设备 ID 与车辆头的环境变量优先于文件中的值。

| 环境变量 | `geely_env.json` 字段 | 用途 |
| --- | --- | --- |
| `GEELY_GRIC_SECRET` | `gricSecret` | GRIC 请求签名密钥 |
| `GEELY_LYNKCO_APPSECRET` | `lynkcoAppsecret` | access-code 请求头 |
| `GEELY_GRIC_JWT` | `authorization` | GRIC JWT；显式设置时跳过缓存/续期 |
| `GEELY_DEVICE_ID` | `device.id` | 设备 ID |
| `GEELY_VEHICLE_IDENTIFIER` / `GEELY_VEHICLE_SERIES` | `vehicle.identifier` / `vehicle.series` | 已加密 VIN / Base64 车型代码 |
| `GEELY_VEH_AES_KEY` / `GEELY_VEH_AES_IV` | `vehicle.aesKey` / `vehicle.aesIv` | 可选的车辆加密算法覆盖值，`vehicle-init` 不会清除它们 |
| `GEELY_TIMEOUT` / `GEELY_RETRIES` | 无 | GRIC 请求超时秒数（默认 30）/ 超时重试次数（默认 2） |

`geely_env.json.example` 中的空值只是占位，不能充当密钥、JWT 或车辆 ID。

## 部署到 GitHub Actions 定时执行

项目内置 `.github/workflows/daily-tasks.yml`，默认每天北京时间 8:00（UTC 0:00，GitHub 调度可能有延迟）自动运行。

1. Fork 本仓库。
2. 进入 `Settings → Secrets and variables → Actions`，新增 Secret：
   - 必需：`LYNKCO_TOKEN`（或 `LYNKCO_REFRESH_TOKEN` + `LYNKCO_DEVICE_ID`，推荐后者，可自动续期）。
   - 必需：`LYNKCO_APP_SECRETS`，一个 JSON 字符串，整合了 `env.json` 中 `secrets` 段的全部 4 个字段，形如：
     ```json
     {"nativeAppKey":"...","nativeAppSecret":"...","nativeAppCode":"...","loginAppCode":"..."}
     ```
     （如果不想合并配置，也可改用 4 个独立的 `LYNKCO_NATIVE_APP_KEY` 等 Secret，同时修改 workflow 中的 `env` 字段）。
   - 可选：`LYNKCO_BARK_KEY`、`LYNKCO_FEISHU_WEBHOOK`、`LYNKCO_DINGTALK_WEBHOOK`、`LYNKCO_WECOM_WEBHOOK`（daily-tasks 的通知渠道）。
3. 可在 `Actions` 页面手动触发一次 workflow 验证。
4. 仅配置 `LYNKCO_TOKEN` 时，token 失效后需要手动更新；配置 `refreshToken` 后可自动续期，仅需在其过期（约 30 天）时才需人工干预。

## 已知限制

- 登录环节（滑块验证码、可能的短信验证）无法完全自动化。
- 已确认的 iPhone 使用场景可在安装并完全信任代理证书后抓包；桌面助手按此流程设计。不同 App/系统版本仍需真机验收，不能仅因系统是 iOS 就判定无法抓包。
- `token`/`refreshToken`/`secrets` 均为敏感信息，请勿提交到公开仓库（`env.json` 已在 `.gitignore` 中忽略），应通过 GitHub Secrets 或本地 `env.json` 传递。
