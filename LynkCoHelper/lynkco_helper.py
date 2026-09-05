#!/usr/bin/python3
"""
项目主入口：领克App每日签到。

模块划分：
    - lynkco_common.py       签名算法 + 公共常量 + env.json 读写（基础模块）
    - lynkco_login.py        token 获取统一入口 load_token()，另含账号密码/短信验证码全流程登录
    - lynkco_sign.py         每日签到逻辑
    - lynkco_share.py        分享任务逻辑（可选功能）
    - lynkco_notify.py       Bark 推送工具
    - lynkco_daily_tasks.py  每日任务顶层入口：编排签到+分享+积分查询并推送结果

使用前提：
    需要一个有效的登录 token（登录环节含极验滑块，无法在 CI 中完全自动化，需人工/半自动获取一次）：
        - 本地运行：写入 env.json 的 user.token 字段
        - CI/GitHub Actions：写入仓库 Secrets 的 LYNKCO_TOKEN
    详见 readme.md。

用法：
    python3 lynkco_helper.py     # 查询并执行今日签到
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from lynkco_sign import main as sign_main


if __name__ == "__main__":
    sign_main()
