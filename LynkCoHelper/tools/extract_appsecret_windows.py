#!/usr/bin/env python3
"""Windows 编排版一键提取 nativeAppKey / nativeAppSecret。

与 tools/extract_appsecret_x86_local.py（WSL 版）的分工：
  - 模拟器仍跑在 WSL2 里（复用 WSL 侧已下载的 SDK / x86_64 镜像 / AVD，
    Windows 原生跑 Android 模拟器需另装整套 SDK + 镜像，不划算）；
  - 本脚本在 Windows 原生 Python 下运行，用 Windows 的 adb.exe 通过
    `adb connect 127.0.0.1:5555` 连接 WSL 模拟器（WSL2 默认开启
    localhost 端口转发），并驱动 Windows 侧 jdb 完成提取。

Windows 侧前置（脚本自动处理，无需手动装）：
  - Python 3 + pexpect（`pip install pexpect`；仅用其 PopenSpawn）；
  - jdb：首次运行自动下载 Amazon Corretto 8（x64 windows jdk，约
    110MB）解压到 ~/.lynkco-helper-tools-win/，之后离线复用；
  - adb.exe：默认取 PATH 里的，找不到时按本文件 ADB_FALLBACK 找。

三个坑与 WSL 版同源，处理方式已内置（详见 docs/本地一键提取指南.md）：
  1. IPv6 坑：jdb -attach 一律显式 127.0.0.1:端口；
  2. forward 生命周期坑：每轮重试换新端口；
  3. 探测握手坑：jdb attach 成功后走完全程，绝不提前 kill。

中文 Windows 专属坑：jdb 输出跟随系统 locale 是 GBK，通过管道读出
再按 utf-8 解码会乱码，导致"Breakpoint hit"匹配不到。故给 jdb 注入
JAVA_TOOL_OPTIONS=-Duser.language=en 强制英文输出。

用法（Windows 命令行，仓库根目录下）：
  python LynkCoHelper\\tools\\extract_appsecret_x86_local_win.py
后台跑：
  start /b python LynkCoHelper\\tools\\extract_appsecret_x86_local_win.py
"""
import glob
import os
import re
import subprocess
import sys
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import appsecret_core as core   # 复用常量/parse_field/looks_valid/send_cmd

os.environ.setdefault("LYNKCO_AUTO_WRITE", "1")
os.environ.setdefault("LYNKCO_UPSTREAM_TIMEOUT", "420")


def _ensure_pexpect():
    """新机器自举：缺 pexpect 则自动 pip 安装（PopenSpawn 所在）。"""
    try:
        import pexpect  # noqa: F401
    except ImportError:
        print("[*] 缺少 pexpect，自动安装（pip install --user pexpect）...")
        r = subprocess.run([sys.executable, "-m", "pip", "install", "--user",
                            "pexpect"])
        if r.returncode != 0:
            sys.exit("[!] pexpect 安装失败，请手动执行：pip install pexpect")


_ensure_pexpect()
import pexpect
from pexpect.popen_spawn import PopenSpawn

# ---------- 可按需修改的配置 ----------
WSL_DISTRO = "Ubuntu"                    # 模拟器所在发行版
WSL_USER = "root"                        # WSL 用户（emulator/AVD 装在其家目录）
AVD = "lynkco_helper_avd_x64"            # x86_64 镜像 AVD
DEVICE = "127.0.0.1:5555"                # Windows adb 视角下的 WSL 模拟器
WIN_TOOLS = os.path.join(os.path.expanduser("~"), ".lynkco-helper-tools-win")
ADB_FALLBACK = r"D:\Android-data\platform-tools\adb.exe"
CORRETTO_URL = ("https://corretto.aws/downloads/latest/"
                "amazon-corretto-8-x64-windows-jdk.zip")
PLATFORM_TOOLS_URL = ("https://dl.google.com/android/repository/"
                      "platform-tools-latest-windows.zip")
_FWD_BASE = 18800                        # forward 端口池起点
# -------------------------------------


def _wait_line(child, pattern, timeout):
    """等 jdb 输出匹配 pattern 的一行（行尾有换行必然 flush）；返回是否命中。
    Windows 管道下 jdb 的 "> " 提示符不带换行不 flush，不能用提示符同步，
    行级同步是可靠路径。"""
    idx = child.expect([pattern, pexpect.EOF, pexpect.TIMEOUT],
                       timeout=timeout)
    return idx == 0


def main():
    # 中文 Windows 的 stdout 默认 GBK：jdb 输出经 utf-8 解码后可能含
    # U+FFFD，print 直接崩。强制 utf-8 + replace 一劳永逸
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    adb_bin = _find_adb()
    jdb = _ensure_jdb()

    def adb(*a, t=30):
        return subprocess.run([adb_bin, *a], capture_output=True, text=True,
                              timeout=t).stdout

    _ensure_device(adb)
    _ensure_apk(adb)

    PKG, ACT, CLASS = core.APP, core.ACTIVITY, core.CLASS
    for attempt in range(1, core.MAX_ATTEMPTS + 1):
        print(f"\n========== 第 {attempt}/{core.MAX_ATTEMPTS} 次尝试 ==========",
              flush=True)
        adb("-s", DEVICE, "shell", "am", "force-stop", PKG)
        time.sleep(1)
        print(adb("-s", DEVICE, "shell", "am", "start", "-D", "-n",
                  ACT).strip(), flush=True)

        pid = None
        t0 = time.time()
        while time.time() - t0 < 60:
            out = adb("-s", DEVICE, "shell", "pidof", PKG).strip()
            if out and out.split()[0].isdigit():
                pid = out.split()[0]
                break
            time.sleep(0.5)
        print("pid:", pid, flush=True)
        if not pid:
            print("[!] 未取到 App PID，重试 ...")
            continue

        # forward + jdb attach 重试（同 WSL 版：新端口 / 显式 IPv4 /
        # 成功后绝不中断）
        child = None
        t0 = time.time()
        port_i = 0
        deadline = t0 + int(os.environ["LYNKCO_UPSTREAM_TIMEOUT"])
        while time.time() < deadline:
            fwd = _FWD_BASE + (port_i % 40)
            port_i += 1
            try:
                adb("-s", DEVICE, "forward", f"tcp:{fwd}", f"jdwp:{pid}",
                    t=10)
            except subprocess.TimeoutExpired:
                print("forward 卡死，重试", flush=True)
                time.sleep(5)
                continue
            child = _spawn_jdb(jdb, fwd)
            try:
                idx = child.expect(
                    core.PROMPTS + [pexpect.EOF, pexpect.TIMEOUT], timeout=25)
            except Exception as e:
                print("attach 异常:", repr(e), flush=True)
                child = None
                time.sleep(8)
                continue
            if idx < len(core.PROMPTS):
                print(f"jdb 已附着（t={time.time() - t0:.1f}s）", flush=True)
                break
            print("attach 未果，输出头部:",
                  repr((child.before or "")[:200]), flush=True)
            try:
                child.kill(9)
            except Exception:
                pass
            child = None
            time.sleep(12)
        if child is None:
            print("[!] 窗口内 jdb 未能附着（JDWP 一直未注册？）")
            continue

        try:
            # Windows 管道下 jdb 的 "> " 提示符无换行不 flush，不能用提示符
            # 同步；jdb 所有响应行都带换行会 flush，用行级同步
            # banner 已在 attach 的 expect 中被消费，直接发 suspend
            child.sendline("suspend")
            _wait_line(child, r"All threads suspended", 60)
            child.sendline(f"stop in {CLASS}.<clinit>")
            _wait_line(child, r"eferring breakpoint|et .*breakpoint", 60)
            child.sendline("resume")
            idx = child.expect(core.BREAKPOINT_PATTERNS +
                               [pexpect.EOF, pexpect.TIMEOUT], timeout=300)
            if idx < len(core.BREAKPOINT_PATTERNS):
                print("[+] Breakpoint hit!", flush=True)
                v = None
                for i in range(15):
                    child.sendline("next")
                    _wait_line(child, r"Step completed", 120)
                    child.sendline(f"print {CLASS}.c")
                    if _wait_line(child,
                                  re.escape(CLASS) + r"\.c\s*=\s*.*", 60):
                        v = core.parse_field(child.after)
                    print(f"probe c: "
                          f"{'有值（' + str(len(v)) + ' 位）' if v else 'None'}",
                          flush=True)
                    if v:
                        break
            else:
                print("[!] 未命中断点（clinit 可能已提前执行），直接 dump")
            results = {}
            for f in ["b", "c", "d", "e"]:
                child.sendline(f"print {CLASS}.{f}")
                out = ""
                if _wait_line(child,
                              re.escape(f"{CLASS}.{f}") + r"\s*=\s*.*", 60):
                    out = child.after
                results[f] = out
                print(f"--- {f} raw: {core.scrub_jdb(out)!r}", flush=True)
            key = core.parse_field(results.get("b", ""))
            secret = core.parse_field(results.get("c", ""))
            print("\n[RESULT]（值已脱敏，明文仅写入 env.json）")
            print(f"    nativeAppKey    = {core.mask_secret(key)}")
            print(f"    nativeAppSecret = {core.mask_secret(secret)}")
            if core.looks_valid(key) and core.looks_valid(secret):
                core.maybe_write_env(key, secret)
                print("[+] 提取完成")
                return
            print("[!] 提取值格式异常，重试 ...")
        finally:
            try:
                child.kill(9)
            except Exception:
                pass
            try:
                adb("-s", DEVICE, "forward", "--remove",
                    f"tcp:{_FWD_BASE}", t=10)
            except Exception:
                pass

    sys.exit(f"[!] {core.MAX_ATTEMPTS} 次尝试全部失败，"
             "请参照 docs/本地一键提取指南.md 排障")


# ---------------------------------------------------------------- helpers

def _find_adb():
    """PATH → 本地兜底路径 → 自动下载 platform-tools（约 10MB）。"""
    import shutil
    cand = shutil.which("adb")
    if cand:
        return cand
    if os.path.exists(ADB_FALLBACK):
        return ADB_FALLBACK
    print("[*] 未找到 adb.exe，自动下载 platform-tools ...")
    os.makedirs(WIN_TOOLS, exist_ok=True)
    zpath = os.path.join(WIN_TOOLS, "platform-tools.zip")
    urllib.request.urlretrieve(PLATFORM_TOOLS_URL, zpath)
    with zipfile.ZipFile(zpath) as z:
        z.extractall(WIN_TOOLS)
    cand = os.path.join(WIN_TOOLS, "platform-tools", "adb.exe")
    if not os.path.exists(cand):
        sys.exit(f"[!] platform-tools 解压异常，请检查 {WIN_TOOLS}")
    return cand


def _ensure_jdb():
    """Windows 侧 jdb：已有则用，没有则自动下载 Corretto 8 并解压。"""
    cand = sorted(glob.glob(os.path.join(WIN_TOOLS, "*", "bin", "jdb.exe")))
    if cand:
        return cand[-1]
    print("[*] 首次运行：下载 Amazon Corretto 8（约 110MB，一次性）...")
    os.makedirs(WIN_TOOLS, exist_ok=True)
    zpath = os.path.join(WIN_TOOLS, "corretto8.zip")
    urllib.request.urlretrieve(CORRETTO_URL, zpath)
    print("[*] 解压中 ...")
    with zipfile.ZipFile(zpath) as z:
        z.extractall(WIN_TOOLS)
    cand = sorted(glob.glob(os.path.join(WIN_TOOLS, "*", "bin", "jdb.exe")))
    if not cand:
        sys.exit(f"[!] 解压后未找到 jdb.exe，请检查 {WIN_TOOLS}")
    return cand[-1]


def _wsl(cmd, t=30):
    return subprocess.run(
        ["wsl", "-d", WSL_DISTRO, "-u", WSL_USER, "-e", "bash", "-c", cmd],
        capture_output=True, text=True, timeout=t)


def _ensure_wsl_ready():
    """新机器检查：WSL 发行版、WSL 侧工具链（模拟器/镜像/AVD）。
    工具链缺失时引导一次 extract_appsecret_auto.py 完成下载与 AVD 创建。"""
    r = _wsl("true", t=20)
    if r.returncode != 0:
        sys.exit("[!] WSL 未就绪：请以管理员身份执行 "
                 "`wsl --install -d Ubuntu` 并重启后再跑本脚本")
    r = _wsl("test -x ~/.lynkco-helper-tools/sdk/emulator/emulator && "
             f"test -d ~/.android/avd/{AVD}.avd && echo Y || echo N")
    if (r.stdout or "").strip() == "Y":
        return
    print("[*] WSL 侧工具链未就绪（首次一次性引导：下载 emulator + x86_64 "
          "系统镜像 + JDK8 + platform-tools + 领克 APK，约 1.5GB，"
          "视网速 10~40 分钟）...")
    # 把 Windows 侧仓库复制进 WSL（auto 脚本在仓库内运行）
    repo_win = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    repo_mnt = ("/mnt/" + repo_win[0].lower() +
                repo_win[2:].replace("\\", "/"))
    r = _wsl(f"mkdir -p ~/lynkco-helper && cp -r '{repo_mnt}/.' "
             "~/lynkco-helper/", t=1200)
    if r.returncode != 0:
        sys.exit(f"[!] 仓库复制进 WSL 失败：{r.stderr}")
    print("[*] 下载并初始化 WSL 工具链（输出较多，完成后自动继续）...")
    subprocess.run(
        ["wsl", "-d", WSL_DISTRO, "-u", WSL_USER, "-e", "bash", "-c",
         "cd ~/lynkco-helper && LYNKCO_IMAGE_ABI=x86_64 EMU_HEADLESS=1 "
         "python3 LynkCoHelper/tools/extract_appsecret_auto.py "
         f"{AVD}; echo BOOTSTRAP-EXITED"])
    print("[*] WSL 工具链引导流程结束，继续提取 ...")


def _ensure_device(adb):
    """Windows adb 连上 WSL 模拟器；模拟器没跑则在 WSL 里冷启动并等 boot。"""
    _ensure_wsl_ready()
    out = adb("devices")
    for ln in out.splitlines()[1:]:
        parts = ln.split()
        if parts and parts[0] == DEVICE and len(parts) > 1 and \
                parts[1] == "device":
            print(f"[*] 已连接 {DEVICE}，直接复用")
            return
    print("[*] Windows adb 未见 WSL 模拟器，检查/启动 ...")
    r = _wsl("pgrep -f 'emulator.*avd' | wc -l")
    if (r.stdout or "").strip() == "0":
        _wsl("setsid nohup ~/.lynkco-helper-tools/sdk/emulator/emulator "
             f"-avd {AVD} -no-snapshot-load -no-window "
             "-gpu swiftshader_indirect -no-audio -no-boot-anim "
             "> ~/.lynkco-helper-tools/emulator.log 2>&1 < /dev/null &",
             t=15)
        print("[*] 已在 WSL 冷启动模拟器（约 2~5 分钟）...")
    # connect + 等 boot（端口转发就绪前 connect 会失败，循环重试）
    for i in range(90):
        adb("connect", DEVICE, t=10)
        out = adb("devices")
        ok = any(ln.split()[:2] == [DEVICE, "device"]
                 for ln in out.splitlines()[1:] if ln.split())
        if ok:
            boot = adb("-s", DEVICE, "shell", "getprop",
                       "sys.boot_completed").strip()
            if boot == "1":
                print(f"[*] {DEVICE} 在线且 boot 完成")
                return
        time.sleep(5)
    sys.exit("[!] 等待 WSL 模拟器上线超时；排查：wsl 内 tail -40 "
             "~/.lynkco-helper-tools/emulator.log，并确认 WSL2 的 "
             "localhostForwarding 未关闭")


def _ensure_apk(adb):
    """App 未安装时：优先用 WSL 里已下载的 APK（经 UNC 路径安装）。"""
    PKG = core.APP
    if PKG in adb("-s", DEVICE, "shell", "pm", "list", "packages"):
        return
    print("[*] 领克 App 未安装，从 WSL 侧 APK 安装 ...")
    r = _wsl("ls ~/.lynkco-helper-tools/lynkco-v*.apk | tail -1")
    apk_wsl = (r.stdout or "").strip()
    if not apk_wsl:
        sys.exit("[!] WSL 内无本地 APK，请先在 WSL 跑一次 "
                 "extract_appsecret_auto.py 下载")
    apk_win = "\\\\wsl.localhost\\" + WSL_DISTRO + "\\" + \
        apk_wsl.replace("~", "/home/" + WSL_USER).lstrip("/").replace("/", "\\")
    print("[*] 安装:", apk_win)
    print(adb("-s", DEVICE, "install", "-r", "-g", apk_win, t=600).strip())


def _spawn_jdb(jdb, port):
    """PopenSpawn 驱动 jdb（管道下 Java System.out 自动按行 flush）；
    强制英文 locale，避免中文 Windows 下 GBK 输出导致断点模式失配。"""
    env = dict(os.environ)
    env["JAVA_TOOL_OPTIONS"] = "-Duser.language=en -Duser.country=US"
    # Windows 上 jdb -attach <addr> 默认走 dt_shmem（共享内存）而非
    # dt_socket，必须用 -connect 显式指定 SocketAttach
    child = PopenSpawn([jdb, "-connect",
                        f"com.sun.jdi.SocketAttach:hostname=127.0.0.1,"
                        f"port={port}"],
                       timeout=60, encoding="utf-8",
                       codec_errors="replace", env=env)
    child.logfile = sys.stdout     # jdb 全量流量可见，便于排障
    child.logfile_send = sys.stdout
    return child


if __name__ == "__main__":
    main()
