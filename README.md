---
# 郑重告知：本程序源码仅供学习研究使用，使用该程序造成的一切后果与程序作者无关。本项目并非拿来即用，有技术门槛！！！
---

领克 App 自动签到助手，支持每日签到、分享任务、积分查询与 Bark 推送，可通过 GitHub Actions 定时自动运行。

## 功能状态

### 已完成

- [x] 每日签到、积分（能量体）查询与前后对比
- [x] 分享任务（简化两步法 + 完整三步法回退），随机抽取探索广场最新文章分享，避免固定文章下架失效
- [x] Bark 推送每日任务结果（含分享文章标题展示）
- [x] token 自动续期（refreshToken 双方案兜底）+ 本地过期时间缓存，避免调试时频繁续期
- [x] 短信验证码登录全流程（含本地极验滑块辅助页面）
- [x] GitHub Actions 定时执行，环境变量 / `env.json` 双配置方式，密钥零硬编码
- [x] `nativeAppKey` / `nativeAppSecret` 全自动提取：x86_64 镜像（libndk 翻译）+ jdb 断点，本地三平台与 CI 均可用，日志全程脱敏

### 暂未完成 / 已知限制

- [ ] 账号密码登录（`login_by_password`）：仅为参考实现，密码加密算法未完全逆向确认，且陌生设备会被风控拦截，不建议依赖
- [ ] 分享任务仅支持"文章"类型内容，"动态"类型的正确分享链接格式尚未验证
- [ ] 登录滑块验证码全自动化：极验人机验证无法自动完成，仍需人工操作一次

## AppSecret 自动提取

从模拟器内运行的领克 App 中自动提取 API 密钥（`nativeAppKey` / `nativeAppSecret`），写入 `env.json` 的 `secrets` 段。原理：x86_64 系统镜像（自带 libndk，可翻译执行 arm64 原生库）+ KVM 加速冷启动 + jdb 在加固壳常量类 `<clinit>` 设断点读取字段。

### 按平台入口（`LynkCoHelper/tools/`）

| 脚本 | 平台 | 说明 |
| --- | --- | --- |
| `extract_appsecret_mac.py` | macOS（HVF） | 原版交互式流程 |
| `extract_appsecret_ubuntu.py` | WSL2 Ubuntu（KVM） | 一键式，环境缺失自动下载 |
| `extract_appsecret_windows.py` | Windows 原生编排 | 模拟器跑在 WSL2，Windows 侧驱动 |
| `extract_appsecret_github_action.py` | GitHub Actions | 全自动无人值守 |

### CI workflows（`.github/workflows/`）

| Workflow | 触发 | 作用 |
| --- | --- | --- |
| `extract-appsecret` | 手动 | 全自动提取密钥 → 写 `env.json` → 同步仓库 Secret `LYNKCO_APP_SECRETS` → Bark 推送（值脱敏） |
| `fetch-lynkco-apk` | 每日 + 手动 | 拉取最新版领克 APK 上传 Release（`apk-v VERSION` 留历史 + `apk-latest` 稳定资产），提取 CI 优先使用 |

### 安全说明

- 所有日志输出均脱敏（密钥值仅显示前 3 后 2 位），明文只写入本地 `env.json`（gitignore）与仓库 Secret
- CI 使用的 x86_64 模拟器镜像与 APK 均托管在仓库 Release（`sysimg-x86_64-33-r09` / `apk-latest`），版本经实测钉死，不随上游变动漂移

详细排障（镜像版本坑、IPv6 坑、forward 生命周期坑等）见 [`LynkCoHelper/docs/本地一键提取指南.md`](LynkCoHelper/docs/本地一键提取指南.md)。

详细说明（配置方式、token 获取、部署步骤等）见 [`LynkCoHelper/readme.md`](LynkCoHelper/readme.md)。
