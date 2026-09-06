#!/usr/bin/env python3
"""
appsecret_core.py —— AppSecret 提取的平台无关共享核心（非入口，勿直接运行）。

包含两个平台入口（macOS 本地: extract_appsecret.py / CI·全自动:
extract_appsecret_auto.py）共用的全部逻辑：
  - 常量与目标信息（App/Activity/断点类/端口/env.json 路径）
  - 工具探测（find_adb / find_jdb / find_emulator，平台感知）
  - 下载工具（_download / _try_download / _confirm_download）
  - 领克 App 自动下载安装（ensure_apk，官方 CDN）
  - 冷启动 AVD 并等待 boot_completed（按平台自动选窗口/无头模式）
  - 本地 TCP 代理（抢先完成 JDWP 握手后双向转发，原理见文档 4.5 节）
  - jdb 交互（send_cmd 回显锚点 + 静默等待同步策略）
  - 字段解析与格式校验、env.json 写入（LYNKCO_AUTO_WRITE=1 免确认）
  - 提取主循环（最多 3 次重试）
拆分动机：此前 mac/win 两个脚本复制粘贴导致逻辑漂移（jdb 版本硬编码等），
故核心收敛于此，平台差异只留在各自入口文件。
"""
import glob
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import zipfile

# CI/管道环境下 stdout 是块缓冲（非 tty），长时间不刷新会显得"卡死"，
# 强制行缓冲，保证每行进度实时上屏（GitHub Actions 按行切分日志）。
try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

try:
    import pexpect
except ImportError:
    pexpect = None

APP = "com.lynkco.customer"
ACTIVITY = "com.lynkco.customer/com.geely.lynkco.main.activity.LynkCoEntranceActivity"
CLASS = "com.safe.cons.LynkCoConstants$g"

PROXY_PORT = 8700      # jdb -> 代理
UPSTREAM_PORT = 8701   # 代理 -> adb forward -> jdwp:<pid>

BREAKPOINT_PATTERNS = ["Breakpoint hit", "断点命中"]
EMPTY_VALUES = {"null", '""', "", "= null", "空值"}
# jdb 提示符两种形态：主提示符 "> "、断点命中后的线程提示符 "main[1] "。
# 只匹配 "> " 会在断点命中后失同步，导致命令输出错位（上一条命令的残留
# 被当成下一条的结果）。
PROMPTS = ["> ", r"main\[\d+\] "]
# 提取值应为纯字母数字串（实测 key 为 9 位数字、secret 为 32 位小写字母数字）
VALUE_RE = re.compile(r"[0-9A-Za-z]{6,64}")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 脚本位于 tools/ 子目录，env.json 在上一级业务目录
ENV_JSON = os.path.join(SCRIPT_DIR, "..", "env.json")
ENV_EXAMPLE = os.path.join(SCRIPT_DIR, "..", "env.json.example")

# 自动下载的前置工具安装位置（不污染项目目录；二次运行可直接复用）
TOOLS_DIR = os.path.expanduser("~/.lynkco-helper-tools")

MAX_ATTEMPTS = 3

# 全系统 TCG 环境（Linux x86_64 宿主跑 arm64-v8a 镜像，见
# extract_appsecret_auto.py）：qemu 逐条翻译 ARM 指令，VM 每步执行慢一两个
# 数量级，所有与设备/VM 交互的等待窗口按平台放大
SLOW_VM = sys.platform == "linux"


def _vt(base):
    """按平台放大超时：TCG 全系统模拟 10 倍，macOS HVF 原生 1 倍。"""
    return base * 10 if SLOW_VM else base

# 领克官方最新版本号查询接口（App 自动下载安装用，见 ensure_apk）
LYNKCO_VER_API = "https://app-api-gw-toc.lynkco.com/app/newest/info"

# 各入口探测完成后调用 setup() 注入，core 内的 adb()/run_once() 使用
ADB = None
JDB = None


def setup(adb_path, jdb_path):
    """入口脚本在探测/下载完成后调用，注入 adb / jdb 路径。"""
    global ADB, JDB
    ADB = adb_path
    JDB = jdb_path


def ensure_pexpect():
    """pexpect 缺失时自动 pip 安装（仅本脚本进程内生效）。"""
    global pexpect
    if pexpect is not None:
        return
    print("[*] 缺少依赖 pexpect，自动安装中（pip install pexpect）...")
    r = subprocess.run([sys.executable, "-m", "pip", "install", "pexpect"])
    if r.returncode != 0:
        # Ubuntu 23.04+/Debian 12+ 启用 PEP 668，pip 拒绝装到系统 Python，需附加参数
        r = subprocess.run([sys.executable, "-m", "pip", "install",
                            "--break-system-packages", "pexpect"])
    if r.returncode != 0:
        sys.exit("[!] pexpect 自动安装失败，请手动执行: "
                 f"{sys.executable} -m pip install pexpect"
                 "（Ubuntu/Debian 亦可用: sudo apt install python3-pexpect）")
    import importlib
    pexpect = importlib.import_module("pexpect")


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def adb(*args):
    return subprocess.run([ADB, *args], capture_output=True, text=True).stdout.strip()


# ---------------------------------------------------------------------------
# 工具探测（adb / jdb / emulator，全平台共用；各入口的 ensure_* 在此基础上
# 补自动下载。jdb 任意版本 JDK 均可：走 JDWP 协议，与目标 JVM 版本无关）
# ---------------------------------------------------------------------------

def find_adb():
    """探测 adb：PATH -> ANDROID_HOME/SDK_ROOT -> 平台默认 SDK 位置 -> 工具目录。"""
    p = shutil.which("adb")
    if p:
        return p
    bases = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             "~/Library/Android/sdk" if sys.platform == "darwin" else "~/Android/Sdk"]
    for base in bases:
        if not base:
            continue
        cand = os.path.join(os.path.expanduser(base), "platform-tools", "adb")
        if os.path.exists(cand):
            return cand
    cand = os.path.join(TOOLS_DIR, "platform-tools", "adb")
    return cand if os.path.exists(cand) else None


def find_jdb():
    """探测 jdb。
    macOS: java_home(-v 1.8) -> 已安装 JVM 目录 -> PATH（排除无 JDK 时的桩）
    Linux: JAVA_HOME -> PATH（/usr/bin/jdb 是 alternatives 真实链接）
    -> /usr/lib/jvm 等常见位置 -> 工具目录（自动下载的 Corretto 8）。"""
    if sys.platform == "darwin":
        try:
            home = subprocess.run(["/usr/libexec/java_home", "-v", "1.8"],
                                  capture_output=True, text=True).stdout.strip()
            if home and os.path.exists(os.path.join(home, "bin", "jdb")):
                return os.path.join(home, "bin", "jdb")
        except Exception:
            pass
        for base in ("~/Library/Java/JavaVirtualMachines",   # macOS 用户级
                     "/Library/Java/JavaVirtualMachines"):    # macOS 系统级
            hits = sorted(glob.glob(os.path.expanduser(base) + "/*/Contents/Home/bin/jdb"))
            if hits:
                return hits[0]
        p = shutil.which("jdb")
        if p and p != "/usr/bin/jdb":   # macOS 的 /usr/bin/jdb 是无 JDK 时的桩
            return p
    else:
        jh = os.environ.get("JAVA_HOME")
        if jh and os.path.exists(os.path.join(jh, "bin", "jdb")):
            return os.path.join(jh, "bin", "jdb")
        p = shutil.which("jdb")
        if p:
            return p
        for pat in ("/usr/lib/jvm/*/bin/jdb",                      # Debian/Ubuntu/Fedora
                    os.path.expanduser("~/.jdks/*/bin/jdb"),        # IntelliJ IDEA
                    os.path.expanduser("~/.sdkman/candidates/java/*/bin/jdb")):
            hits = sorted(glob.glob(pat))
            if hits:
                return hits[0]
    hits = sorted(glob.glob(os.path.join(TOOLS_DIR, "jdk8", "**", "bin", "jdb"),
                            recursive=True))
    return hits[0] if hits else None


def find_emulator():
    """探测 emulator：PATH -> ANDROID_HOME/SDK_ROOT -> 平台默认 SDK 位置
    -> 工具目录（自动版下载的 sdk/emulator）。"""
    p = shutil.which("emulator")
    if p:
        return p
    bases = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             "~/Library/Android/sdk" if sys.platform == "darwin" else "~/Android/Sdk"]
    for base in bases:
        if not base:
            continue
        cand = os.path.join(os.path.expanduser(base), "emulator", "emulator")
        if os.path.exists(cand):
            return cand
    cand = os.path.join(TOOLS_DIR, "sdk", "emulator", "emulator")
    return cand if os.path.exists(cand) else None


# ---------------------------------------------------------------------------
# 下载工具（两个平台入口共用）
# ---------------------------------------------------------------------------

def _fmt_dur(seconds):
    """秒数 -> "3分12秒 / 45秒" 可读时长。"""
    s = int(seconds)
    return f"{s // 60}分{s % 60}秒" if s >= 60 else f"{s}秒"


def _download_to(url, dest_file, interval=10):
    """流式下载并按时间间隔输出换行结尾的进度行。

    进度行包含 百分比/MB/瞬时速度/预计剩余，每 interval 秒最多一行：
    CI 日志按行刷新（\r 单行刷新在 Actions 里不可见，大文件会全程静默），
    本地终端也不会被刷屏。连接与读均有 60 秒超时，避免 stall 挂死。
    下载前先建父目录：runner 上 adb/jdb/emulator 常全预装，所有 ensure_*
    提前返回时 TOOLS_DIR 可能从未被创建过（mac runner 实测踩坑：
    首个系统镜像下载即 [Errno 2] ENOENT）。"""
    req = urllib.request.Request(url, headers={"User-Agent": "lynkco-helper"})
    os.makedirs(os.path.dirname(dest_file) or ".", exist_ok=True)
    # 大文件（1.2GB 镜像）在 CDN 偶发 stall 下 60s 读超时不够，放宽到 180s
    with urllib.request.urlopen(req, timeout=180) as resp, \
            open(dest_file, "wb") as f:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        t0 = last_t = time.time()
        last_done = 0
        while True:
            chunk = resp.read(262144)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            now = time.time()
            if now - last_t >= interval:
                speed = (done - last_done) / (now - last_t) / 1048576
                if total:
                    eta = (total - done) / max(speed, 0.01) / 1048576
                    print(f"    进度 {done * 100 // total}%"
                          f"（{done // 1048576}/{total // 1048576}MB）"
                          f"  {speed:.1f}MB/s  剩余 ~{_fmt_dur(eta)}")
                else:
                    print(f"    已下载 {done // 1048576}MB  {speed:.1f}MB/s")
                last_t, last_done = now, done
        dt = time.time() - t0
        avg = done / 1048576 / max(dt, 0.01)
        print(f"    下载完成：{done // 1048576}MB  平均 {avg:.1f}MB/s  耗时 {_fmt_dur(dt)}")


def _download(url, dest_file, size_mb):
    """下载文件（中断自动重试，共 3 次机会），进度每 10 秒一行。"""
    print(f"[*] 下载 {url}（约 {size_mb}MB，视网络可能需数分钟）")
    for attempt in range(1, 4):
        try:
            _download_to(url, dest_file)
            return
        except Exception as e:
            if os.path.exists(dest_file):
                os.remove(dest_file)
            if attempt == 3:
                sys.exit(f"[!] 下载失败（已重试 3 次）：{e}\n"
                         f"    可手动下载 {url} 解压到 {TOOLS_DIR} 后重跑")
            print(f"    [重试 {attempt}/2] 下载中断：{e}，10 秒后重来 ...")
            time.sleep(10)


def _try_download(url, dest_file, size_mb):
    """尝试下载（软失败返回 False，供多镜像回退），进度每 10 秒一行。"""
    print(f"[*] 尝试 {url}（约 {size_mb}MB）")
    try:
        _download_to(url, dest_file)
    except Exception as e:
        if os.path.exists(dest_file):
            os.remove(dest_file)
        print(f"    [失败] {e}")
        return False
    return True


def _confirm_download(kind, size_mb, dest):
    """交互确认下载；非交互环境（CI/管道，stdin 非 tty 或 EOF）自动同意。"""
    try:
        if not sys.stdin.isatty():
            print(f"[*] 未找到 {kind}（非交互环境，自动下载约 {size_mb}MB -> {dest}）")
            return True
        ans = input(f"[*] 未找到 {kind}，是否自动下载（约 {size_mb}MB -> {dest}）？[Y/n]: ")
    except EOFError:
        ans = "y"
    return ans.strip().lower() != "n"


def _extract_jdk_and_find_jdb(arc, dest):
    """解压 JDK 压缩包并返回 jdb 路径（mac/linux ensure_jdb 共用）。"""
    os.makedirs(dest, exist_ok=True)
    if zipfile.is_zipfile(arc):
        with zipfile.ZipFile(arc) as z:
            z.extractall(dest)
        os.remove(arc)
    else:
        with tarfile.open(arc) as t:
            t.extractall(dest)
        os.remove(arc)
    hits = sorted(glob.glob(os.path.join(dest, "**", "bin", "jdb"), recursive=True))
    if not hits:
        sys.exit(f"[!] 解压后未找到 jdb，请检查 {dest}")
    return hits[0]


def _app_installed(tries=6, wait=5):
    """确认设备上领克 App 的安装状态，返回 True/False；持续查询失败则退出。

    pm path 的“未安装”与 adb 传输故障（设备闪断/多设备/adbd 未就绪）
    退出码与 stdout 完全一致（exit=1、stdout 空），仅 stderr 可区分；
    冷启动后 adbd 有一小段不稳窗口，若不加区分，传输抖动会被误判为
    “未安装”而白下 285MB APK（2026-08-31 macOS 冷启动实测踩坑）。"""
    for attempt in range(tries):
        r = subprocess.run([ADB, "shell", "pm", "path", APP],
                           capture_output=True, text=True)
        if r.stdout.strip():
            return True                    # 已安装
        if not r.stderr.strip():
            return False                   # pm 正常执行且未找到
        print(f"    [.] 设备查询不稳（{attempt + 1}/{tries}）："
              f"{r.stderr.strip().splitlines()[-1]}")
        time.sleep(wait)
    sys.exit("[!] adb 持续无法查询设备（见上方错误），请检查 adb devices 后重试")


def ensure_apk():
    """设备未装领克 App 时自动安装（平台无关）：查询官方接口拿最新
    版本号，从领克官方 CDN 下载（约 285MB，已下载则复用）后 adb install。"""
    if _app_installed():
        return
    try:
        data = json.loads(urllib.request.urlopen(LYNKCO_VER_API, timeout=15).read())
        ver = (data.get("data") or {}).get("androidNewestVersion", "").lstrip("V")
    except Exception:
        ver = ""
    if not ver:
        sys.exit(f"[!] 设备上未安装 {APP} 且无法查询最新版本号，请手动安装后重试")
    apk = os.path.join(TOOLS_DIR, f"lynkco-v{ver}.apk")
    if not os.path.exists(apk):
        if not _confirm_download(f"领克 App v{ver} APK", 285, apk):
            sys.exit("[!] 未安装 App 且跳过下载，退出。")
        os.makedirs(TOOLS_DIR, exist_ok=True)
        _download(f"https://app-cdn.lynkco.com/android/lynkco-64-v{ver}.apk",
                  apk, 285)
    print(f"[*] 安装 APK: {apk}")
    r = subprocess.run([ADB, "install", "-r", apk], capture_output=True, text=True)
    out = "\n".join(p for p in (r.stdout.strip(), r.stderr.strip()) if p)
    if out:
        print("    " + out.replace("\n", "\n    "))
    if not _app_installed():
        # 安装失败诊断：adb 把安装失败原因（如 Failure
        # [INSTALL_FAILED_NO_MATCHING_ABIS]）打到 stderr，且 x86_64 镜像
        # 是否带 ARM 翻译层直接决定 arm64-only APK 能否装上
        print(f"[!] 设备 CPU ABI 列表: "
              f"{adb('shell', 'getprop', 'ro.product.cpu.abilist')}")
        # 镜像侧诊断：比对运行时 abilist 与镜像 build.prop 是否一致
        #（排除镜像内容/下载差异），并输出 system.img 指纹供跨环境比对
        import glob as _glob
        import hashlib as _hashlib
        for bp in _glob.glob(os.path.join(TOOLS_DIR, "sdk", "system-images",
                                          "android-*", "google_apis", "*",
                                          "build.prop")):
            try:
                for ln in open(bp, encoding="utf-8", errors="replace"):
                    if "abilist" in ln:
                        print(f"[diag] {bp}: {ln.strip()}")
            except OSError:
                pass
        for simg in _glob.glob(os.path.join(TOOLS_DIR, "sdk", "system-images",
                                            "android-*", "google_apis", "*",
                                            "system.img")):
            try:
                h = _hashlib.sha256()
                with open(simg, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                print(f"[diag] {simg} sha256: {h.hexdigest()}")
            except OSError as e:
                print(f"[diag] {simg}: {e}")
        sys.exit(f"[!] APK 安装后仍未检测到 {APP}，请人工检查")


# ---------------------------------------------------------------------------
# 冷启动 AVD（按平台自动选窗口 / 无头模式）
# ---------------------------------------------------------------------------

def cold_start_and_wait(emu, avd):
    """冷启动 AVD 并等 boot_completed。设 EMU_HEADLESS=1 或无 DISPLAY 的
    Linux 自动切无头模式（CI/服务器场景）；macOS 保持窗口模式。
    Linux x86_64 宿主跑 arm64 镜像走 qemu 全系统 TCG 模拟，冷启动慢
    （20~50 分钟），boot 超时已按平台放宽，心跳每 30 秒一行。"""
    headless = os.environ.get("EMU_HEADLESS") or \
        (sys.platform != "darwin" and not os.environ.get("DISPLAY"))
    # -no-snapshot-save：提取工具无需快照，退出更快更干净；也规避关机
    # 保存快照被杀（run 33373332280：qemu 启动即走保存流程，20 秒不够
    # 被 SIGKILL）。SLOW_VM 加 -verbose：CI 排障需要完整设备初始化日志
    cmd = [emu, "-avd", avd, "-no-snapshot-load", "-no-snapshot-save"]
    if headless:
        cmd += ["-no-window", "-gpu", "swiftshader_indirect",
                "-no-audio", "-no-boot-anim"]
        if SLOW_VM:
            cmd += ["-verbose"]
            print(f"[*] 冷启动模拟器 {avd}（无头，全系统 TCG 模拟 arm64 镜像，"
                  "冷启动 20~50 分钟属预期）...")
        else:
            print(f"[*] 冷启动模拟器 {avd}（无头模式，约需 2~5 分钟）...")
    else:
        print(f"[*] 冷启动模拟器 {avd}（-no-snapshot-load，约需 1~2 分钟）...")
    env = os.environ.copy()
    sdk_root = os.path.dirname(os.path.dirname(emu))
    # 必须覆盖而非 setdefault：CI runner（如 GitHub ubuntu-latest）预设了
    # ANDROID_HOME=/usr/local/lib/android/sdk，而 AVD 的 image.sysdir.1 是
    # 相对路径，模拟器按该变量解析系统镜像位置——指向别的 SDK 会启动即失败
    # （adb wait-for-device 干等 5 分钟超时，2026-08-31 CI 实测踩坑）。
    env["ANDROID_HOME"] = sdk_root
    env["ANDROID_SDK_ROOT"] = sdk_root
    log_file = os.path.join(TOOLS_DIR, "emulator.log")
    log_monitored = False   # 无头路径才有落盘日志可监听
    if sys.platform == "darwin" and not headless:
        # macOS 窗口模式：界面即状态，输出丢弃；清掉上次运行的残留日志，
        # 避免 _fail() 打印陈旧的 PANIC 误导排查
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
            except OSError:
                pass
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=env)
    else:
        # 无头模式（含全部 Linux/CI、macOS EMU_HEADLESS=1）：输出落盘，
        # 失败时由 _fail() 把末尾打到 stdout，等待期由 _emulator_died() 监听
        os.makedirs(TOOLS_DIR, exist_ok=True)
        with open(log_file, "wb") as lf:
            proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT,
                                    env=env)
        log_monitored = True

    def _fail(reason):
        """失败时带上 emulator.log 末尾再退出：CI runner 用后即焚，
        只留一句"日志见某路径"等于没有日志；顺带终止残留的模拟器进程。"""
        proc.terminate()
        log_file = os.path.join(TOOLS_DIR, "emulator.log")
        if os.path.exists(log_file):
            try:
                with open(log_file, "rb") as f:
                    lines = f.read()[-16000:].decode("utf-8", "replace").splitlines()
                lines = [ln for ln in lines[-60:] if ln.strip()]
                if lines:
                    print(f"[!] {reason}，emulator.log 末尾 {len(lines)} 行：")
                    for ln in lines:
                        print(f"    | {ln}")
            except Exception:
                pass
        sys.exit(f"[!] {reason}")

    def _emulator_died():
        """模拟器进程退出或日志报 PANIC/FATAL 即刻判死，返回原因字符串；
        活着返回 None。run 33368243194 踩坑：模拟器启动 1 秒即 PANIC
        "Broken AVD system path"，等待逻辑却干等 adb 满 10 分钟才超时
        发现——秒级失败要秒级退出，别把时间浪费在必死等待上。"""
        if proc.poll() is not None:
            return f"模拟器进程已退出（exit={proc.returncode}）"
        if not log_monitored:
            return None
        try:
            with open(log_file, "rb") as f:
                tail = f.read()[-4000:].decode("utf-8", "replace")
        except OSError:
            return None
        for ln in tail.splitlines():
            if re.search(r"(?i)^\s*(panic|fatal)\b", ln):
                return f"模拟器启动失败：{ln.strip()[:160]}"
        return None

    # 连接等待：不用 adb wait-for-device 一次性干等——它对“模拟器已死”
    # 毫无感知（TCG 下要白等满超时窗口）。改为 5 秒一轮：get-state 变
    # device 即连接成功；进程退出 / 日志 PANIC/FATAL 立刻带日志退出。
    print("[*] 等待 adb 连接模拟器（进程崩溃/日志报错即刻失败）...")
    connect_timeout = 600 if SLOW_VM else 300
    waited = 0
    connected = False
    while waited <= connect_timeout:
        died = _emulator_died()
        if died:
            _fail(died)
        if subprocess.run([ADB, "get-state"], capture_output=True,
                          text=True).stdout.strip() == "device":
            connected = True
            break
        time.sleep(5)
        waited += 5
        if waited % 60 == 0:
            print(f"[*] 仍在等待 adb 连接模拟器（已 {waited // 60} 分钟，"
                  "TCG 冷启动慢属预期）...")
    if not connected:
        _fail("adb 连接模拟器超时（%d 分钟）" % (connect_timeout // 60))
    # TCG 全系统模拟（Linux x86_64 宿主跑 arm64 镜像）冷启动慢得多，
    # boot 超时 8 -> 50 分钟；macOS HVF 原生路径维持 8 分钟
    boot_polls = 1500 if SLOW_VM else 240
    for i in range(boot_polls):
        died = _emulator_died()   # 启动中崩溃/报错也要即刻退出，别傻等满超时
        if died:
            _fail(died)
        if adb("shell", "getprop", "sys.boot_completed").strip() == "1":
            print("[+] 模拟器启动完成")
            # 等 adbd / am 就绪，避免首轮 am start 拿不到 PID（TCG 下更保守）
            time.sleep(30 if SLOW_VM else 5)
            return
        time.sleep(2)
        if i and i % 15 == 0:   # 每 30 秒一行心跳，CI 日志不静默
            print(f"[*] 仍在等待系统启动（已 {i * 2} 秒，"
                  f"模拟器日志 {TOOLS_DIR}/emulator.log）...")
    _fail(f"模拟器启动超时（{boot_polls * 2 // 60} 分钟）")


# ---------------------------------------------------------------------------
# JDWP 代理 + jdb 交互 + 字段解析（平台无关）
# ---------------------------------------------------------------------------

class Proxy:
    """jdb 先连上并挂起在握手阶段；等上游就绪后抢先握手并双向转发。"""

    def __init__(self):
        self.upstream_ready = threading.Event()
        self.handshake_done = threading.Event()
        self.upstream_failed = threading.Event()   # 上游连接/握手失败（进程已死等）
        self.status = "init"
        self.aborted = False

    def start_and_serve(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", PROXY_PORT))
        srv.listen(1)
        # 1. 接受 jdb 连接，读取其握手请求并挂起
        self.jdb_sock, _ = srv.accept()
        self.jdb_sock.settimeout(None)
        hs = b""
        while len(hs) < 14:
            chunk = self.jdb_sock.recv(14 - len(hs))
            if not chunk:
                raise RuntimeError("jdb 在握手前断开")
            hs += chunk
        assert hs == b"JDWP-Handshake", hs
        self.status = "jdb_connected"
        srv.close()

        # 2. 等主流程通知上游就绪（无限等：TCG 全系统模拟下 am start ->
        #    pidof 链路可能要几分钟；主流程退出时 close() 会 set 本事件
        #    并置 aborted，不会挂死）
        self.upstream_ready.wait()
        if self.aborted:
            return
        print("[*] [proxy] upstream_ready 已收到，开始连接上游 ...", flush=True)
        # 3. 抢先连接上游（命中早期窗口）并完成握手。
        # libndk 翻译环境（x86_64 镜像跑 arm64 库）下，am start 后 ART 运行时
        # 初始化 + JDWP 注册要几十秒，而 adb forward 建好后立即 connect 会
        # 因 jdwp 端点未注册而 EOF——在窗口内小步重试，默认窗口 10s 不变
        echo = None
        up = None
        _uw = _vt(int(os.environ.get("LYNKCO_UPSTREAM_TIMEOUT", "10")))
        _deadline = time.time() + _uw
        while True:
            try:
                # forward 若在 jdwp 注册前建立，会被 adb 绑在空端点上且不会
                # 重解析，之后 connect 永远 EOF——每次尝试前刷新 forward
                _rf = getattr(self, "refresh_upstream", None)
                if _rf:
                    _rf()
                print("[*] [proxy] 刷新完成，尝试 connect ...", flush=True)
                if up is None:
                    up = socket.socket()
                    # 单次尝试短超时，窗口内反复重试（jdwp 注册晚于 forward
                    # 建立时，adb 可能对 connect 静默挂起，长超时会吃满窗口）
                    up.settimeout(5.0)
                up.connect(("127.0.0.1", UPSTREAM_PORT))
                up.sendall(b"JDWP-Handshake")
                echo = b""
                while len(echo) < 14:
                    c = up.recv(14 - len(echo))
                    if not c:
                        raise RuntimeError("上游握手被关闭")
                    echo += c
                assert echo == b"JDWP-Handshake"
                break
            except (OSError, RuntimeError, AssertionError) as _e:
                # 上游异常（jdwp 未注册/进程退出等）：窗口内重试，窗口耗尽
                # 才标记失败，由主流程终止本次尝试
                print(f"[*] 上游尝试失败: {_e}", flush=True)
                if up is not None:
                    try:
                        up.close()
                    except OSError:
                        pass
                    up = None
                    echo = None
                if time.time() >= _deadline:
                    self.upstream_failed.set()
                    return
                time.sleep(1.5)
        up.settimeout(None)
        self.up_sock = up
        self.jdb_sock.sendall(echo)  # 把握手回显交给 jdb
        self.handshake_done.set()
        self.status = "relaying"

        # 4. 双向转发
        def pump(a, b):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            try:
                b.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        t1 = threading.Thread(target=pump, args=(self.jdb_sock, up), daemon=True)
        t2 = threading.Thread(target=pump, args=(up, self.jdb_sock), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        self.status = "closed"

    def close(self):
        """中止代理线程并释放套接字（重试前清理旧代理）。"""
        self.aborted = True
        self.upstream_ready.set()
        for s in (getattr(self, "jdb_sock", None), getattr(self, "up_sock", None)):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        self.status = "closed"


class Disconnected(Exception):
    """jdb 与目标 VM 的连接中断（App 反调试自杀或平台连接不稳），可重试。"""


def send_cmd(child, cmd, timeout=15):
    """向 jdb 发送命令并收集本条命令的输出。

    同步策略（修复命令输出错位）：
    1. 回显锚点——先等到本条命令的回显出现，天然跳过缓冲区里上一条
       命令的残留输出；
    2. 静默等待——jdb 会异步输出事件（典型：next 的"已完成的步骤"出现在
       早期 "> " 提示符之后），只等第一个提示符会提前返回、把事件文本
       留给下一条命令误捕获，造成整体错位一条。故持续消费到 1 秒无新
       输出为止。
    连接中断时抛 Disconnected，由主循环统一重试。
    """
    try:
        child.sendline(cmd)
        child.expect(re.escape(cmd), timeout=timeout)   # 锚点：本条回显
    except pexpect.EOF:
        raise Disconnected("jdb 已退出（EOF）")
    except (pexpect.TIMEOUT, OSError) as e:
        raise Disconnected(f"等待命令回显失败（{cmd!r}）：{e}")

    parts = []
    first = True
    while True:
        try:
            idx = child.expect(PROMPTS + [pexpect.EOF, pexpect.TIMEOUT],
                               timeout=timeout if first else 1)
        except OSError as e:
            raise Disconnected(f"读取 jdb 输出失败（{e}）")
        if idx == len(PROMPTS):            # EOF：jdb 退出
            raise Disconnected("jdb 已退出（EOF）")
        if idx == len(PROMPTS) + 1:        # 静默：本条命令输出结束
            break
        parts.append(child.before or "")
        first = False
    out = "\n".join(p for p in parts if p.strip())
    if "已断开连接" in out or "disconnected" in out.lower():
        raise Disconnected("目标 VM 断开（App 反调试自杀或平台连接中断）")
    return out


def parse_field(out):
    """从 jdb print 输出中解析字段值；未赋值/失败返回 None。

    只接受行尾 `= "..."` 形式的带引号字符串值：jdb 未赋值时打印 `空值`/
    `null`（无引号）；`next` 的"已完成的步骤: \"线程=main\", ..."等行
    虽含 "=" 但值不带引号，均会被正确排除。
    """
    for line in out.splitlines():
        m = re.search(r'=\s*"([^"]+)"\s*$', line.strip())
        if m and m.group(1) not in EMPTY_VALUES:
            return m.group(1)
    return None


def looks_valid(v):
    """提取值格式校验：纯字母数字串（key=9 位数字，secret=32 位字母数字）。"""
    return bool(v) and VALUE_RE.fullmatch(v) is not None


def mask_secret(v):
    """脱敏显示：前 3 后 2 可见，中间以 *** 代替（过短则全遮）。
    公开 CI 日志任何人可读，密钥值绝不能明文出现。"""
    if not v:
        return v
    if len(v) <= 8:
        return "***"
    return v[:3] + "***" + v[-2:]


def scrub_jdb(out):
    """抹掉 jdb 原始输出中的字段值（= "..." 形式），防日志泄漏。"""
    return re.sub(r'=\s*"[^"]+"', '= "******"', out or "")


class ScrubStream:
    """pexpect logfile 包装：实时抹掉 jdb 输出中的字段值。
    jdb 对 print 命令的应答含密钥明文，直接落 CI 日志即泄漏。"""

    def write(self, s):
        sys.stdout.write(scrub_jdb(s))

    def flush(self):
        sys.stdout.flush()


def maybe_write_env(key, secret):
    """交互确认后，把提取结果写入 env.json 的 secrets 段。
    设 LYNKCO_AUTO_WRITE=1（CI 场景）免确认，且 env.json 不存在时自动创建。"""
    auto = os.environ.get("LYNKCO_AUTO_WRITE") == "1"
    if not auto:
        try:
            ans = input("\n是否把上述两个值自动写入 env.json？[y/N]: ").strip().lower()
        except EOFError:
            ans = ""
        if ans != "y":
            print("[*] 未写入，请自行保存。")
            return
    if os.path.exists(ENV_JSON):
        with open(ENV_JSON, encoding="utf-8") as f:
            env = json.load(f)
    elif auto:
        env = {}   # CI：env.json 未入库（gitignore），直接创建仅含 secrets 的文件
    else:
        hint = (f"请先复制 {ENV_EXAMPLE} 为 env.json 并填入账号后重跑"
                if os.path.exists(ENV_EXAMPLE) else "请手动创建该文件")
        print(f"[!] {ENV_JSON} 不存在：{hint}，或手动填入上述值。")
        return
    env.setdefault("secrets", {})
    env["secrets"]["nativeAppKey"] = key
    env["secrets"]["nativeAppSecret"] = secret
    with open(ENV_JSON, "w", encoding="utf-8") as f:
        json.dump(env, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[+] 已写入 {ENV_JSON}（该文件已被 gitignore，不会入库）")


# ---------------------------------------------------------------------------
# 单次提取 + 主循环（平台无关）
# ---------------------------------------------------------------------------

def _dump_device_diagnostics(tag):
    """提取失败时采集设备侧证据（进程存活/ABI 支持/logcat 崩溃缓冲）。
    CI runner 用后即焚，不现场抓证据就只能事后猜：2026-08-31 CI 实测三次
    握手超时却无任何设备侧信息，根因（如 APK 仅 arm64-v8a 与 x86_64 模拟器
    不兼容导致进程启动即死）完全无法定位。"""
    print(f"[*] 设备侧诊断（{tag}）：")
    try:
        alive = adb("shell", "pidof", APP).strip()
        print(f"    App 进程: {alive or '已退出（启动即崩溃的典型特征）'}")
    except Exception:
        pass
    try:
        print(f"    设备 ABI: {adb('shell', 'getprop', 'ro.product.cpu.abilist').strip()}")
    except Exception:
        pass
    try:
        crash = adb("shell", "logcat", "-d", "-b", "crash", "-t", "60")
        if crash.strip():
            print("    logcat 崩溃缓冲尾部：")
            for ln in crash.splitlines()[-25:]:
                print(f"    | {ln}")
        else:
            print("    logcat 崩溃缓冲为空（进程非崩溃退出，或未被拉起）")
    except Exception:
        pass

def run_once():
    """单次完整提取；连接类故障抛 Disconnected 交由主循环重试。返回 (key, secret)。"""
    proxy = Proxy()
    threading.Thread(target=proxy.start_and_serve, daemon=True).start()
    time.sleep(0.3)  # 等代理开始监听
    child = None
    try:
        print(f"[*] Using jdb: {JDB}")
        child = pexpect.spawn(f"{shlex.quote(JDB)} -attach 127.0.0.1:{PROXY_PORT}",
                              timeout=60, encoding="utf-8")
        child.logfile = ScrubStream()

        # 等 jdb 完成与代理的 TCP 连接（握手暂时挂起）
        for _ in range(50):
            if proxy.status in ("jdb_connected", "upstream_ready", "relaying"):
                break
            time.sleep(0.1)
        print("\n[*] jdb 已连上代理（阻塞在握手），现在启动 App ...")

        # 启动 App（等待调试器状态），进程一出现立刻建立 forward 并放行代理
        adb("shell", "am", "force-stop", APP)
        time.sleep(_vt(0.5))
        started = adb("shell", "am", "start", "-D", "-n", ACTIVITY)
        for ln in started.splitlines():
            if ln.strip():
                print(f"    am start: {ln.strip()}")
        t0 = time.time()
        pid = None
        # 按 deadline 而非次数等：TCG 全系统模拟下 am start 拉起进程慢
        # （分钟级），且每次 adb 往返耗时不可控；出现即返回，等久不亏
        pid_deadline = time.time() + _vt(45)
        while time.time() < pid_deadline:
            out = adb("shell", f"pidof {APP}")
            out = out.strip()
            if out and out.split()[0].isdigit():
                pid = out.split()[0]
                break
            time.sleep(0.03)
        if not pid:
            _dump_device_diagnostics("未取到 App PID")
            raise Disconnected("未取到 App PID：请确认模拟器已安装领克 App"
                               "（adb shell pm list packages | grep lynkco）")
        print(f"[*] PID={pid} (t={time.time()-t0:.2f}s)，立即建立转发 ...")
        adb("forward", f"tcp:{UPSTREAM_PORT}", f"jdwp:{pid}")

        _jdwp_kick = {"p": None}

        def _refresh(p=pid):
            # 踢醒并保持 adbd 的 jdwp 扫描器：挂起 VM（am start -D）的 JDWP
            # 注册依赖 adbd tracker 扫描 /proc，且 tracker 只在有活跃
            # `adb jdwp` 客户端时工作——短连即断再立刻 connect 反而踩上
            # tracker 刚停的空窗。故后台常驻一个客户端，让扫描持续进行，
            # 再刷新 forward 让 adb 重新解析端点
            try:
                if _jdwp_kick["p"] is None or _jdwp_kick["p"].poll() is not None:
                    _jdwp_kick["p"] = subprocess.Popen(
                        [ADB, "jdwp"], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                    import atexit
                    atexit.register(lambda q=_jdwp_kick["p"]:
                                    q.kill() if q.poll() is None else None)
            except Exception:
                pass
            adb("forward", f"tcp:{UPSTREAM_PORT}", f"jdwp:{p}")

        proxy.refresh_upstream = _refresh
        proxy.upstream_ready.set()

        # 新装 285MB App 首启需 dex 校验，模拟器负载高时（TCG 全系统模拟
        # 尤甚）VM 达到等待调试器状态可能较慢，窗口按平台放大；但若上游
        # 连接失败（进程秒退，如加固壳异常退出），立即失败进入重试，
        # 不浪费整个超时窗口
        deadline = time.time() + _vt(int(os.environ.get(
            "LYNKCO_UPSTREAM_TIMEOUT", "60")))
        while not proxy.handshake_done.is_set():
            if proxy.upstream_failed.is_set():
                _dump_device_diagnostics("上游连接失败（App 进程大概率已退出）")
                raise Disconnected("上游连接失败：App 进程已退出或 jdwp 未就绪。"
                                   "若 CI 上反复出现，多为 APK 仅含 arm64-v8a"
                                   "原生库，其加固壳在 x86_64 模拟器的 ARM"
                                   "翻译层（libndk）下必崩，需改用 arm64 设备")
            if time.time() > deadline:
                _dump_device_diagnostics("上游握手超时")
                raise Disconnected("上游握手失败（可能错过早期窗口）。"
                                   "若模拟器非冷启动，请按文档 4.5 节坑 1 冷启动后重试")
            time.sleep(0.2)
        print("[+] JDWP 握手完成（命中早期窗口）！\n")

        # 等 jdb 初始化完成出现提示符（两种形态："> " / "main[1] "）
        try:
            child.expect(PROMPTS + [pexpect.EOF, pexpect.TIMEOUT],
                         timeout=_vt(30))
        except Exception:
            pass

        # 尽快冻结 VM，最大限度赢得与 clinit 的竞速
        print("\n[*] suspend")
        send_cmd(child, "suspend", timeout=_vt(10))

        print("\n[*] Setting breakpoint ...")
        send_cmd(child, f"stop in {CLASS}.<clinit>", timeout=_vt(15))

        print("\n[*] resume")
        try:
            child.sendline("resume")
        except OSError as e:
            raise Disconnected(f"jdb 进程已退出（{e}）")
        # resume 后断点事件（"设置延迟的断点/断点命中"）会异步到达，这里
        # 不能用 send_cmd（其静默等待可能提前吞掉断点事件），直接等断点文本。
        idx = child.expect(BREAKPOINT_PATTERNS + [pexpect.EOF, pexpect.TIMEOUT],
                           timeout=_vt(90))
        if idx == len(BREAKPOINT_PATTERNS):
            raise Disconnected("等待断点期间 jdb 已退出（EOF）")
        if idx < len(BREAKPOINT_PATTERNS):
            print("\n[+] Breakpoint hit!")
            time.sleep(0.2)
            try:
                child.expect(PROMPTS + [pexpect.TIMEOUT], timeout=5)
            except Exception:
                pass
            for i in range(15):
                print(f"\n[*] next (step {i + 1})")
                send_cmd(child, "next", timeout=_vt(15))
                out = send_cmd(child, f"print {CLASS}.c", timeout=_vt(10))
                val = parse_field(out)
                print(f"    -> c probe: "
                      f"{'有值（' + str(len(val)) + ' 位）' if val else 'None'}")
                if val:
                    break
        else:
            print("\n[!] 未命中断点（clinit 可能已提前执行），直接尝试打印字段 ...")

        print("\n[*] Dumping fields b/c/d/e ...")
        results = {}
        for field in ["b", "c", "d", "e"]:
            results[field] = send_cmd(child, f"print {CLASS}.{field}",
                                      timeout=_vt(10))

        print("\n" + "=" * 60)
        print("[RESULT]（值已脱敏，明文仅写入 env.json）")
        for field, out in results.items():
            print(f"--- {field} raw output ---")
            print(scrub_jdb(out))
        print("=" * 60)

        return parse_field(results.get("b", "")), parse_field(results.get("c", ""))
    finally:
        print("\n[*] Killing local jdb with SIGKILL (NOT quit) ...")
        if child is not None:
            try:
                child.kill(9)
            except Exception:
                pass
        proxy.close()
        try:
            adb("forward", "--remove", f"tcp:{UPSTREAM_PORT}")
        except Exception:
            pass


def extract_main_loop():
    """提取主循环：调用前需已 setup(adb, jdb) 且设备就绪。"""
    key = secret = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            print(f"\n========== 第 {attempt}/{MAX_ATTEMPTS} 次尝试 ==========")
            key, secret = run_once()
            if looks_valid(key) and looks_valid(secret):
                break
            # 解析出了值但格式异常（含空格/中文/引号等）——多为 jdb 输出错位
            print(f"\n[!] 第 {attempt} 次提取的值格式异常（疑似 jdb 输出不同步）：")
            print(f"    nativeAppKey    = {mask_secret(key)!r}")
            print(f"    nativeAppSecret = {mask_secret(secret)!r}")
            key = secret = None
            if attempt < MAX_ATTEMPTS:
                print("[*] 3 秒后自动重试（将重新 force-stop 并启动 App）...")
                time.sleep(3)
        except Disconnected as e:
            print(f"\n[!] 第 {attempt} 次尝试失败：{e}")
            if attempt < MAX_ATTEMPTS:
                print("[*] 3 秒后自动重试（将重新 force-stop 并启动 App）...")
                time.sleep(3)

    if key and secret:
        print(f"\n[+] 提取成功！nativeAppKey    = {mask_secret(key)}")
        print(f"           nativeAppSecret = {mask_secret(secret)}")
        maybe_write_env(key, secret)
    else:
        print("\n[!] 多次尝试均未提取到 b/c 字段值。排查建议：")
        print("    1. 反复在 suspend/断点阶段断开 → 多为模拟器非冷启动或平台连接"
              "不稳，请冷启动模拟器（文档 4.5 坑 1/坑 2）后重跑")
        print("    2. 反复未命中断点/字段为空 → App 可能更新了混淆类名，"
              "需按文档第 1 节思路重新静态分析")
        print("    3. 逐段排查可参考文档 4.3 节的 jdb 命令序列；速查表见 7.4 节")
        sys.exit(1)
