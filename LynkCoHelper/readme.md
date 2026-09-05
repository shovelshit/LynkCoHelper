---
# 郑重告知：本程序源码仅供学习研究使用，使用该程序造成的一切后果与程序作者无关
---

## 简介

领克 App「我的-签到」自动化脚本，支持每日签到、分享任务、积分查询，并可通过 Bark 推送结果。

模块划分：

| 文件 | 作用 |
| --- | --- |
| `lynkco_common.py` | 签名算法 + 公共常量 + `env.json` 读写 |
| `lynkco_login.py` | token 获取统一入口 `load_token()`，含账号密码/短信验证码全流程登录 |
| `lynkco_sign.py` | 每日签到逻辑 |
| `lynkco_share.py` | 分享任务逻辑（可选功能） |
| `lynkco_notify.py` | Bark 推送工具 |
| `lynkco_daily_tasks.py` | 顶层入口：编排签到 + 分享 + 积分查询并推送结果 |

原理、签名算法、接口协议等技术细节见 `docs/` 目录，此处只介绍如何使用。

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
    "h5AppKey": "",
    "h5AppSecret": "",
    "nativeAppKey": "",
    "nativeAppSecret": "",
    "nativeAppCode": "",
    "loginAppCode": "",
    "deviceImei": "",
    "glDevId": ""
  },
  "notify": {
    "barkKey": ""
  }
}
```

- `user`：账号相关凭据（token 至少需要一个，见下）。
- `secrets`：领克 App 的应用级签名密钥（非个人凭证，但代码中不内置，必须自行配置），获取方式见 `docs/AppSecret_逆向分析记录.md`。每个字段都支持用同名大写环境变量覆盖（如 `LYNKCO_H5_APP_KEY`）；也可用一个整合环境变量 `LYNKCO_APP_SECRETS`（值为与 `secrets` 结构相同的 JSON 字符串）一次性提供全部 8 个字段，适合 CI 只想配置一个 Secret 的场景（优先级：单独字段环境变量 > `LYNKCO_APP_SECRETS` > `env.json`）。均未配置时程序会直接报错退出。
- `notify`：推送相关配置，`barkKey` 为 Bark 推送 Key（可选，也可用环境变量 `LYNKCO_BARK_KEY` 覆盖）。

### 3. 获取 token

登录环节含极验滑块验证，无法完全自动化，需人工/半自动获取一次：

- **token**（约 30 分钟有效）：写入 `user.token`，或设置环境变量 `LYNKCO_TOKEN`。
- **refreshToken + deviceId**（约 30 天有效，推荐）：写入 `user.refreshToken` / `user.deviceId`，或设置环境变量 `LYNKCO_REFRESH_TOKEN` / `LYNKCO_DEVICE_ID`。配置后脚本每次运行会自动续期 token 并回写 `env.json`，无需频繁手动登录。

获取方式：抓包登录一次领克 App，或运行 `python3 lynkco_login.py <手机号>` 交互式完成滑块 + 短信登录（会自动写入 `env.json`）。详见 `docs/登录接口协议说明.md`。

### 4. 执行

```bash
python3 lynkco_helper.py         # 签到 + 分享
python3 lynkco_daily_tasks.py    # 签到 + 分享 + 积分查询 + Bark 推送
```

分享任务（`lynkco_share.py`）每日有加分次数上限，接口返回成功不代表真正加分，重复调用不会重复加分，详见 `docs/分享任务接口说明.md`。

可选环境变量：

| 变量 | 说明 |
| --- | --- |
| `LYNKCO_BARK_KEY` | Bark 推送的 Key，未配置则跳过推送（也可写入 `env.json` 的 `notify.barkKey`） |
| `LYNKCO_ENERGY_DELAY` | 签到/分享后查询积分前的等待秒数，默认 5 |
| `LYNKCO_BARK_ICON` | Bark 推送使用的图标 URL，默认使用领克官方图标 |

## 部署到 GitHub Actions 定时执行

项目内置 `.github/workflows/daily-tasks.yml`，默认每天北京时间 8:00（UTC 0:00，GitHub 调度可能有延迟）自动运行。

1. Fork 本仓库。
2. 进入 `Settings → Secrets and variables → Actions`，新增 Secret：
   - 必需：`LYNKCO_TOKEN`（或 `LYNKCO_REFRESH_TOKEN` + `LYNKCO_DEVICE_ID`，推荐后者，可自动续期）。
   - 必需：`LYNKCO_APP_SECRETS`，一个 JSON 字符串，整合了 `env.json` 中 `secrets` 段的全部 8 个字段，形如：
     ```json
     {"h5AppKey":"...","h5AppSecret":"...","nativeAppKey":"...","nativeAppSecret":"...","nativeAppCode":"...","loginAppCode":"...","deviceImei":"...","glDevId":"..."}
     ```
     （如果不想合并配置，也可仍改用 8 个独立的 `LYNKCO_H5_APP_KEY` 等 Secret，同时修改 workflow 中的 `env` 字段）。
   - 可选：`LYNKCO_BARK_KEY`。
3. 可在 `Actions` 页面手动触发一次 workflow 测试。
4. 仅配置 `LYNKCO_TOKEN` 时，token 失效后需要手动更新；配置 `refreshToken` 后可自动续期，仅需在其过期（约 30 天）时才需人工干预。

## 已知限制

- 登录环节（滑块验证码、可能的短信验证）无法完全自动化。
- iOS 设备因 App 存在 SSL Pinning，无法直接抓包获取 token，建议使用 Android 模拟器/真机。
- `token`/`refreshToken`/`secrets` 均为敏感信息，请勿提交到公开仓库（`env.json` 已在 `.gitignore` 中忽略），应通过 GitHub Secrets 或本地 `env.json` 传递。

## 更多文档

- `docs/AppSecret_逆向分析记录.md`：签名密钥的逆向分析过程与获取方式。
- `docs/登录接口协议说明.md`：登录/续期相关接口协议细节。
- `docs/分享任务接口说明.md`：分享任务接口协议与限制说明。
