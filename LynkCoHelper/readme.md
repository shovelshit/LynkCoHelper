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
| `lynkco_comment.py` | 独立的图文动态评论任务；默认 dry-run，不属于签到/分享任务 |

原理、签名算法、接口协议等技术细节见 `docs/` 目录，此处只介绍如何使用。

## AppSecret 自动提取

从模拟器内运行的领克 App 中自动提取 API 密钥（`nativeAppKey` / `nativeAppSecret`），写入 `env.json` 的 `secrets` 段。原理：x86_64 系统镜像（自带 libndk，可翻译执行 arm64 原生库）+ KVM 加速冷启动 + jdb 在加固壳常量类 `<clinit>` 设断点读取字段。

### 按平台入口（`tools/`）

| 脚本 | 平台 | 说明 |
| --- | --- | --- |
| `tools/extract_appsecret_mac.py` | macOS（HVF） | 原版交互式流程 |
| `tools/extract_appsecret_ubuntu.py` | WSL2 Ubuntu（KVM） | 一键式，环境缺失自动下载 |
| `tools/extract_appsecret_windows.py` | Windows 原生编排 | 模拟器跑在 WSL2，Windows 侧驱动 |
| `tools/extract_appsecret_github_action.py` | GitHub Actions | 全自动无人值守 |

### CI workflows（`.github/workflows/`）

| Workflow | 触发 | 作用 |
| --- | --- | --- |
| `extract-appsecret` | 手动 | 全自动提取密钥 → 运行日志输出**一次性取件链接**（仅可打开 1 次、10 分钟失效），需手动填入 `LYNKCO_APP_SECRETS` 供 daily-tasks 使用 |
| `fetch-lynkco-apk` | 每日 + 手动 | 拉取最新版领克 APK 上传 Release（`apk-v VERSION` 留历史 + `apk-latest` 稳定资产），提取 CI 优先使用 |

### 安全说明

- 所有日志输出均脱敏（密钥值仅显示前 3 后 2 位），明文只写入本地 `env.json`（gitignore）；CI 提取时通过一次性链接送达明文（仅可打开 1 次，10 分钟失效）
- CI 使用的 x86_64 模拟器镜像与 APK 均托管在仓库 Release（`sysimg-x86_64-33-r09` / `apk-latest`），版本经实测钉死，不随上游变动漂移

详细排障（镜像版本坑、IPv6 坑、forward 生命周期坑等）见 `docs/本地一键提取指南.md`。

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
- `secrets`：领克 App 的应用级签名密钥（非个人凭证，但代码中不内置，必须自行配置），获取方式见 `docs/AppSecret_逆向分析记录.md`。每个字段都支持用同名大写环境变量覆盖（如 `LYNKCO_NATIVE_APP_KEY`）；也可用一个整合环境变量 `LYNKCO_APP_SECRETS`（值为与 `secrets` 结构相同的 JSON 字符串）一次性提供全部 4 个字段，适合 CI 只想配置一个 Secret 的场景（优先级：单独字段环境变量 > `LYNKCO_APP_SECRETS` > `env.json`）。均未配置时程序会直接报错退出。
- `notify`：推送相关配置。支持 `barkKey`、`feiShuWebhook`、`dingTalkWebhook`、`weComWebhook`，也可使用环境变量 `LYNKCO_BARK_KEY`、`LYNKCO_FEISHU_WEBHOOK`、`LYNKCO_DINGTALK_WEBHOOK`、`LYNKCO_WECOM_WEBHOOK` 覆盖。未配置的渠道会跳过。

### 3. 获取 token

登录环节含极验滑块验证，无法完全自动化，需人工/半自动获取一次：

- **token**（约 30 分钟有效）：写入 `user.token`，或设置环境变量 `LYNKCO_TOKEN`。
- **refreshToken + deviceId**（约 30 天有效，推荐）：写入 `user.refreshToken` / `user.deviceId`，或设置环境变量 `LYNKCO_REFRESH_TOKEN` / `LYNKCO_DEVICE_ID`。配置后脚本每次运行会自动续期 token 并回写 `env.json`，无需频繁手动登录。

获取方式：抓包登录一次领克 App，或运行 `python3 lynkco_login.py <手机号>` 交互式完成滑块 + 短信登录（会自动写入 `env.json`）。详见 `docs/登录接口协议说明.md`。

### 4. 执行

```bash
python3 lynkco_helper.py         # 签到 + 分享
python3 lynkco_daily_tasks.py    # 签到 + 分享 + 状态查询 + 按配置推送
```

分享任务（`lynkco_share.py`）每日有加分次数上限，接口返回成功不代表真正加分，重复调用不会重复加分，详见 `docs/分享任务接口说明.md`。

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

每日通知包含今日签到状态、连续签到/签到卡、成长等级与成长值、积分变化和任务进度。评论任务同样使用这些通知配置，配置了哪些渠道就发送哪些渠道；单个渠道失败不会影响任务结果。

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

## 图文动态评论（独立任务）

`lynkco_comment.py` 从 `/home-page/v3/list` 读取新内容，默认读取 1 页（最多 20 条），发布前复查文章详情，再通过统一 AI 门面调用 ChatAnywhere 或 GLM 分析文字与图片，生成不超过 500 字的评论。**目前仅对文章自动发布**：文章评论已在本地得到服务端 `commentId`，并通过评论列表确认可见。普通 UGC 图文可在演练中分析，但其评论关系未验证，`--publish` 会跳过；视频不处理。评论任务与签到/分享相互独立。

在 `LynkCoHelper` 目录执行：

```bash
python3 lynkco_comment.py --dry-run                 # 真实列表、详情和模型，不提交评论
python3 lynkco_comment.py --publish --max-comments 1 # 真实发布，最多尝试 1 条
```

真实演练会调用第三方模型，可能产生费用，但不会发送评论 POST。AI 配置优先级为独立环境变量 > `env.json` 的 `ai` 段 > 默认值：默认使用 ChatAnywhere，设置 `ai.provider` 为 `glm` 可切换到 GLM。ChatAnywhere 使用 `CHATANYWHERE_API_KEY` / `CHATANYWHERE_MODEL`，GLM 使用 `GLM_API_KEY`（兼容 `ZHIPU_API_KEY`）/ `GLM_MODEL`；本地也可以直接在 `env.json` 的 `ai.apiKey` 和 `ai.model` 中填写。GLM 图文动态默认使用 `glm-4v-flash`。AI 提示词要求评论最多 50 字，但评论接口和发布校验仍保留 500 字上限。除此之外还需要有效的领克 token（或 refreshToken）及 App 原生签名密钥。所有领克原生请求统一使用最新 HAR 中的 iOS 头：`CA_iOS_SDK_2.0`、`4.2.8`、`40208072`、`iPhone 15 Pro`、`27.0.1`；这些版本和设备头不再按设备差异化配置。发布前通过 `GET /auth/user/info` 的 iOS 原生签名请求，从当前 token 获取 `data.id` 作为评论请求的 `gl_user_id`；userinfo 获取失败会直接终止发布，不使用本地写死账号 ID。`deviceId` 仅从 `LYNKCO_DEVICE_ID` 或 `env.json.user.deviceId` 读取。`LYNKCO_COMMENT_MAX_PER_RUN` 控制每轮最多尝试 1～10 条（默认 1），即使模型失败也不会继续尝试更多动态；`LYNKCO_COMMENT_MAX_AGE_HOURS` 控制发布时间窗口 1～168 小时（默认 48）；`LYNKCO_COMMENT_FEED_PAGES` 控制列表拉取页数 1～20（默认 1，每页 20 条）；命令行 `--max-comments` 优先于环境变量；网络超时统一使用 `LYNKCO_TIMEOUT`。

配置任一通知渠道后，每条生成评论各推送一条，文案固定包含动态标题、评论正文和**演练/发布/失败/待核对**状态；文章通知可点击打开对应 H5 分享页。没有生成评论时发送本轮计数汇总。通知推送失败不会改变评论确认结果。成功或结果不明的文章 ID 保存在已忽略的 `.comment_state.json` 中，结果不明时不会自动重发；请核实评论列表后再处理状态。一次受控的 UGC 发布曾返回业务拒绝，不能当成 UGC 可用的证据。

评论任务相关环境变量：`LYNKCO_COMMENT_MAX_PER_RUN`（每轮尝试 1～10 条，默认 1）、`LYNKCO_COMMENT_MAX_AGE_HOURS`（时间窗口 1～168 小时，默认 48）、`LYNKCO_COMMENT_FEED_PAGES`（列表页数 1～20，默认 1，每页 20 条）、`LYNKCO_AI_TIMEOUT`（模型请求超时，默认 60 秒）。领克原生请求统一使用最新 HAR 的 iOS 请求头，版本和设备字段由公共模块固定管理。

独立的 `.github/workflows/comment-task.yml` 每天北京时间 09:17、15:17、21:17 计划运行，每轮最多尝试 1 篇文章（GitHub 调度可能延迟）；定时运行使用发布模式，手动触发默认演练，勾选 `publish` 才发布。定时配置需位于 GitHub 默认分支才能生效。它使用与本地相同的脚本，运行前只从当前分支最新的 `lynkco-comment-state` artifact 恢复去重状态，首次无 artifact 时从 `LYNKCO_COMMENT_BOOTSTRAP_STATE` Secret 导入；发布时两者都没有会中止。运行后上传状态 artifact，评论部分成功而后续失败也会保留已记录的 ID。若 Runner 在评论已被服务端接受、但最终 artifact 上传前中断，下一轮前必须先核对评论列表，再处理状态，不能盲目重发。既有的 `daily-tasks.yml` 不会执行评论。

评论工作流的 Actions Secrets：`LYNKCO_REFRESH_TOKEN`、`LYNKCO_DEVICE_ID`、`LYNKCO_APP_SECRETS`、`CHATANYWHERE_API_KEY`、`GLM_API_KEY`；`LYNKCO_BARK_KEY`、`LYNKCO_FEISHU_WEBHOOK`、`LYNKCO_DINGTALK_WEBHOOK`、`LYNKCO_WECOM_WEBHOOK` 和 `LYNKCO_BARK_ICON` 可选。默认通过 userinfo 接口实时获取当前账号，不需要配置账号 ID。通过 Actions Variable `LYNKCO_AI_PROVIDER=glm` 切换到 GLM，模型可用 `GLM_MODEL` 覆盖。已在本地发布过评论时，用当前 `.comment_state.json` 的内容初始化 `LYNKCO_COMMENT_BOOTSTRAP_STATE` Secret，避免首次 CI 运行重复评论；之后以同一分支的最新 artifact 为准。Actions Variables 可设置 `LYNKCO_COMMENT_MAX_PER_RUN`、`LYNKCO_COMMENT_MAX_AGE_HOURS`、`LYNKCO_COMMENT_FEED_PAGES`、`LYNKCO_TIMEOUT`、`LYNKCO_AI_TIMEOUT` 和 `LYNKCO_RETRIES`。密钥不要写入仓库、命令行参数或工作流文件。

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

## 更多文档

- `docs/本地一键提取指南.md`：AppSecret 自动提取的完整流程、各平台坑位与排障速查。
- `docs/AppSecret_逆向分析记录.md`：签名密钥的逆向分析过程与获取方式。
- `docs/登录接口协议说明.md`：登录/续期相关接口协议细节。
- `docs/分享任务接口说明.md`：分享任务接口协议与限制说明。
