#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_gric_auto.py —— GRIC X-SIGNATURE 密钥全自动提取（CI / 无本地 Android 环境）。

与 extract_appsecret_github_action.py 共用模拟器 / APK 自动安装基础设施，
但提取链路完全不同：**不走 JDWP**（GRIC 提取无反调试对抗），纯堆内存取证：

    冷启动模拟器 -> 装最新 APK -> 正常启动 App（无 -D）->
    自动点隐私协议 -> 等 SDK 初始化（无需登录：密钥启动时即解密进
    配置对象）-> extract_gric_key.py scan（dump 堆 -> 三级候选 ->
    HAR 离线复算 -> 写 geely_env.json）

验证 HAR 来源（二选一；都没有则只产出未验证候选清单 gric_candidates.json）：
  1. 环境变量 GRIC_HAR_B64 —— 任一次抓包 HAR 文件的 base64（CI 用
     GitHub Secret 传入；含 x-signature 请求即可，无需脱敏）。
     生成：macOS `base64 -i capture.har | pbcopy`，
           Linux `base64 -w0 capture.har`；
  2. 命令行 --har <capture.har>（本地使用）。

镜像 ABI（环境变量 LYNKCO_IMAGE_ABI，默认 x86_64）：
  - x86_64：KVM 加速冷启动约 45 秒；镜像优先取仓库 Release 托管的
    sysimg-x86_64-33-r09（x86_64-33-r09-local.zip，保留 arm64 libndk
    翻译；官方 r10+ 已移除），emulator 钉 31.3.10；App 的 arm64 库经
    libndk 翻译执行。
  - arm64-v8a：Linux TCG 全系统模拟，App 跑真 ARM64 指令，冷启动
    20~50 分钟，CI timeout 需 180 分钟。注意：当前 CI 环境不可用——
    新版 emulator 37.x 的 QEMU2 直接拒绝 arm64 guest，旧 31.3.10 在
    2026 ubuntu runner 内核上 segfault（run 33374210610 实证）。

CI 实证结论（2026-10-13）：x86_64 路线已闭环（run 38369132429 成功，
密钥 HAR 复算 100% 命中）。链路要点：App 的加固壳在 libndk 翻译下会
周期性 SIGSEGV 并由系统自动重启（每轮存活 ~1-2 分钟）；首次启动的进程
SDK init 不完整，需**跨重启跟踪主进程**（cmdline 精确匹配包名）并对
每轮存活窗口做高地址优先全堆快照——重启后的进程会完成 SDK init、
密钥解密进配置对象（deviceModel ±2KB 锚点命中），进程崩溃后用快照
离线扫描提取。GRIC_HAR_B64 存精简版验证 HAR（仅 x-signature 请求，
约 6KB；完整 HAR 超 Secret 48KB 上限，需裁剪到仅含签名请求）。

用法（在仓库根目录执行）：
  python3 LynkCoHelper/tools/extract_gric_auto.py                # 全自动
  python3 LynkCoHelper/tools/extract_gric_auto.py --har <capture.har>
  python3 LynkCoHelper/tools/extract_gric_auto.py <AVD名字>      # 指定本地 AVD

环境变量：GRIC_HAR_B64 / GRIC_WAIT_SEC（SDK 初始化等待秒数，默认 TCG 300 /
KVM 120）/ EMU_HEADLESS=1 / LYNKCO_IMAGE_ABI。GitHub Actions 工作流见
.github/workflows/extract-gric-key.yml。

密钥只写入 geely_env.json（gitignore，runner 销毁即丢），经一次性链接送达。
"""
import argparse
import base64
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import appsecret_core as core                    # noqa: E402
import extract_appsecret_github_action as auto   # noqa: E402
import extract_gric_key as gk                    # noqa: E402

# 隐私协议/引导页可点击文案（前缀匹配；"不同意"不会误命中：正则要求
# 引号后紧跟文案首字）。首次启动 SDK 初始化通常被隐私协议阻塞，必须点掉。
CONSENT_TEXTS = ("同意", "允许", "确定", "继续", "立即体验", "我知道了", "跳过", "进入应用")
CANDIDATES_FILE = os.path.join(os.getcwd(), "gric_candidates.json")


def _wait_sec():
    v = os.environ.get("GRIC_WAIT_SEC")
    if v:
        return int(v)
    # SLOW_VM：Linux 宿主跑 arm64 镜像（TCG 全系统模拟）时为 True；
    # x86_64 镜像 KVM 路线 auto 模块已把它改回 False
    return 300 if core.SLOW_VM else 120


def _platform_guard():
    machine = platform.machine()
    if sys.platform == "darwin" and machine != "arm64":
        sys.exit("[!] Intel mac 无 qemu-system-aarch64，跑不了 arm64 镜像。"
                 "请改用 ubuntu（TCG 模拟）、Apple Silicon Mac 或 arm64 真机。")
    if sys.platform.startswith("linux") and machine != "x86_64":
        sys.exit("[!] Linux ARM64 无官方 emulator 包。请改用 x86_64 Linux、"
                 "Apple Silicon Mac 或 arm64 真机（本地版 tools/extract_gric_key.py scan）。")


def tap_consent():
    """uiautomator 找隐私协议/引导页按钮并点击（best-effort，失败静默）。"""
    try:
        core.adb("shell", "uiautomator", "dump", "/sdcard/ui.xml")
        xml = core.adb("shell", "cat", "/sdcard/ui.xml")
        for text in CONSENT_TEXTS:
            # text 属性在 bounds 前 / 后两种节点顺序都匹配
            for pat in (r'text="' + text + r'[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
                        r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"[^>]*text="' + text + r'[^"]*"'):
                m = re.search(pat, xml)
                if m:
                    x = (int(m.group(1)) + int(m.group(3))) // 2
                    y = (int(m.group(2)) + int(m.group(4))) // 2
                    core.adb("shell", "input", "tap", str(x), str(y))
                    print(f"    [>] 已点击「{text}…」@ ({x},{y})")
                    return True
    except Exception as e:
        print(f"    [!] uiautomator 点击失败（忽略）：{e}")
    return False


def ensure_root():
    """GRIC 堆取证要求 adbd 以 root 运行（google_apis 模拟器镜像支持）。"""
    out = core.adb("root")
    print(f"[*] adb root: {out.strip() or '(已是 root)'}")
    time.sleep(2)
    core.adb("wait-for-device")


def app_main_pid():
    """返回 App 主进程 PID（cmdline 恰为包名；子进程形如 pkg:web）。
    主进程不存在但子进程存活时返回 None（壳守护进程骗不过 pidof 检查）。"""
    out = core.adb("shell", "pidof", core.APP).strip()
    if not out:
        return None
    pids = out.split()
    for pid in pids:
        try:
            cmd = core.adb("shell", "cat", f"/proc/{pid}/cmdline").strip("\r\n\x00")
        except Exception:
            continue
        if core.APP in cmd and ":" not in cmd:
            return pid
    return None


def snapshot_heap(pid, snap_dir, seq, block_mb=32):
    """dump 目标进程 dalvik 主堆到分块文件，高地址块优先。

    壳在 SDK init 后不久即 SIGSEGV（libndk 翻译），存活窗口只有几秒；
    新分配的对象（解密后的密钥/配置对象）偏向堆高地址端，因此从堆尾
    向堆头分块 dump：进程崩溃前的 partial 快照最可能覆盖到密钥。
    返回本轮写入的文件路径列表（可能为空）。"""
    try:
        regions = gk.find_heap_regions(None, pid, 400)
    except SystemExit:
        return []
    files = []
    bs = block_mb * 1048576
    for start, end, _name in regions:
        # 从高到低切块：[(max(start, end-bs), end), ..., (start, start+bs)]
        blocks = []
        hi = end
        while hi > start:
            lo = max(start, hi - bs)
            blocks.append((lo, hi))
            hi = lo
        for lo, hi in blocks:
            path = os.path.join(snap_dir, f"heap_{seq:03d}_{lo:x}.bin")
            try:
                blob = gk.dump_region(None, pid, lo, hi)
            except Exception:
                break   # 进程崩溃：已落盘的分块仍有价值
            if not blob:
                continue
            with open(path, "wb") as f:
                f.write(blob)
            files.append(path)
    return files


def launch_app_and_wait():
    """启动 App -> 点隐私协议 -> 跨崩溃重启跟踪主进程抓堆快照。

    实证（run 38369132429）：壳在 libndk 翻译下周期性 SIGSEGV，系统自动
    重启 App；重启后的进程会完成 SDK init、密钥解密进配置对象。因此：
      1. 紧凑循环点「同意」（SDK init 被隐私协议阻塞，点不中则密钥不解密）；
      2. 对每轮存活窗口抓高地址优先全堆快照（新对象偏向堆尾）；
      3. 进程崩溃即停，用快照离线扫。
    返回 [快照文件路径]（可为空；快照已覆盖活进程全堆，无需另做活扫）。"""
    print(f"[*] 启动 App: {core.ACTIVITY}")
    core.adb("shell", "am", "start", "-n", core.ACTIVITY)

    # 1. 等主进程出现（TCG 下 am start 拉起进程可能要几分钟）
    deadline = time.time() + (240 if core.SLOW_VM else 60)
    pid = None
    while time.time() < deadline:
        pid = app_main_pid()
        if pid:
            break
        time.sleep(5)
    if not pid:
        print("[警告] 未等到 App 主进程（启动失败或被反调试拦截？）")
        return []
    print(f"[*] App 主进程 PID = {pid}")

    wait_sec = _wait_sec()
    snap_dir = tempfile.mkdtemp(prefix="gric_snap_")
    snaps, seq = [], 0
    t0 = time.time()

    # 2. 紧凑循环点隐私协议/引导页（uiautomator 单次 ~6s，循环到点中/崩溃/超时）
    print("[*] 尝试点掉隐私协议/引导页（SDK 初始化的前置）...")
    while time.time() - t0 < wait_sec:
        if app_main_pid() is None:
            print("[警告] App 主进程已消失（未点中同意即崩溃）")
            return snaps
        if tap_consent():
            break

    # 3. 高地址优先分块快照：每轮覆盖当前主进程全堆，崩溃重启自动跟随；
    #    周期性补点引导页后续页；主进程消失即停
    print("[*] SDK 初始化中，高地址优先抓主进程堆快照...")
    seen_pid = app_main_pid()
    next_tap = time.time() + 20
    while time.time() - t0 < wait_sec + 60:
        pid = app_main_pid()
        if pid is None:
            print(f"[警告] 主进程已消失（libndk 崩溃常见），"
                  f"用已抓到的 {len(snaps)} 个堆快照块离线扫描")
            return snaps
        if pid != seen_pid:
            print(f"[*] 主进程 PID 变化 {seen_pid} -> {pid}（崩溃后重启），跟随新进程")
            seen_pid = pid
        if time.time() > next_tap:
            next_tap += 20
            tap_consent()
        files = snapshot_heap(pid, snap_dir, seq)
        if files:
            snaps.extend(files)
            seq += 1
            print(f"    ... {int(time.time() - t0)}s，第 {seq} 轮 +{len(files)} 块")
        time.sleep(2)
    return snaps


def resolve_har(cli_path):
    """验证 HAR：--har 指定 > GRIC_HAR_B64 环境变量（base64 解码到临时文件）。"""
    if cli_path:
        if not os.path.exists(cli_path):
            sys.exit(f"[!] HAR 文件不存在: {cli_path}")
        return cli_path
    b64 = os.environ.get("GRIC_HAR_B64", "").strip()
    if not b64:
        return None
    try:
        data = base64.b64decode(b64)
        json.loads(data.decode("utf-8"))
    except Exception as e:
        sys.exit(f"[!] GRIC_HAR_B64 解码/解析失败（应为 HAR 文件的 base64）: {e}")
    path = os.path.join(tempfile.gettempdir(), "gric_verify.har")
    with open(path, "wb") as f:
        f.write(data)
    print(f"[*] 已从 GRIC_HAR_B64 解出验证 HAR（{len(data) // 1024}KB）: {path}")
    return path


def run_scan(har_path, heap_files=None):
    cmd = [sys.executable, os.path.join(HERE, "extract_gric_key.py"),
           "scan", "--write", "--candidates", CANDIDATES_FILE]
    for hf in (heap_files or []):
        cmd += ["--heap-file", hf]
    if har_path:
        cmd += ["--har", har_path]
    print("[*] " + " ".join(cmd))
    return subprocess.call(cmd)


def main():
    ap = argparse.ArgumentParser(description="GRIC 密钥全自动提取（模拟器 + 堆取证）")
    ap.add_argument("avd", nargs="?", default=None, help="指定 AVD 名（默认自动）")
    ap.add_argument("--har", default=None, help="验证用 HAR 文件（默认读 GRIC_HAR_B64）")
    args = ap.parse_args()

    _platform_guard()
    adb_path = auto.ensure_adb()
    core.setup(adb_path, adb_path)   # jdb 不需要，占位注入（GRIC 不走 JDWP）
    # extract_gric_key.py 直接调 PATH 上的 adb，注入其所在目录
    os.environ["PATH"] = (os.path.dirname(os.path.abspath(adb_path)) + os.pathsep
                          + os.environ.get("PATH", ""))
    print(f"[*] adb: {adb_path}")

    auto.ensure_device(args.avd)
    auto.ensure_apk()
    ensure_root()
    snaps = launch_app_and_wait()

    # 诊断：SDK init/崩溃行为看 logcat（artifact 由 workflow 上传）
    try:
        logcat = core.adb("shell", "logcat", "-d", "-t", "8000")
        with open("/tmp/gric_logcat.txt", "w", encoding="utf-8", errors="replace") as f:
            f.write(logcat)
        print("[*] logcat 已存 /tmp/gric_logcat.txt")
    except Exception as e:
        print(f"[!] logcat 采集失败：{e}")

    har_path = resolve_har(args.har)
    if not har_path:
        print("[!] 未提供验证 HAR（--har / GRIC_HAR_B64）。仍会提取候选清单到")
        print(f"    {CANDIDATES_FILE}，但无法复算验证——请下载候选清单后用")
        print("    tools/extract_gric_key.py har <capture.har> --secret <候选> 本地复算。")

    # 快照离线扫（快照已覆盖各存活窗口的全堆）；无快照时退化为活进程扫
    rc = run_scan(har_path, heap_files=snaps) if snaps else run_scan(har_path)
    if rc == 0:
        # 候选清单含明文密钥，命中后删除防泄漏（密钥仅经 geely_env.json/
        # 一次性链接送达；workflow 仅在失败时才上传候选清单）
        try:
            os.remove(CANDIDATES_FILE)
        except OSError:
            pass
        print("[+] 提取完成，密钥已写入 LynkCoHelper/geely_env.json（gitignore），"
              "经一次性链接送达")
    sys.exit(rc)


if __name__ == "__main__":
    main()
