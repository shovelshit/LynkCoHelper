#!/usr/bin/env python3
"""
extract_appsecret_auto.py —— 全自动版（CI / 无本地 Android 环境的机器）：
从零自动提取领克 App 的 nativeAppKey / nativeAppSecret。

支持平台（默认镜像 ABI 为 arm64-v8a——领克 APK 仅含 arm64 原生库）：
  - macOS Apple Silicon：Hypervisor.framework 原生虚拟化，快；本地
    全自动首选。
  - Linux x86_64（含 GitHub Actions ubuntu runner）：qemu 全系统 TCG
    模拟——x64 emulator 包自带 qemu-system-aarch64，逐条翻译 ARM
    指令，整个 guest 就是 arm64 Android，App 的加固壳跑真 ARM64 代码，
    无 libndk 翻译层、不会崩溃；代价是慢（冷启动 20~50 分钟）。

已排除的路线（2026-08-31 实测，勿再踩）：
  - ubuntu + x86_64 镜像：App 的 arm64 库经 libndk 翻译执行，加固壳必崩
  - macOS runner（VM 内）：无 Hypervisor.framework，而 Android emulator
    的 arm64 guest 在 macOS 上死绑 HVF（-accel off 无效、-qemu 直通
    -accel tcg 即 fatal），且预装 darwin-x86_64 包不含 qemu-system-aarch64

用法（在仓库根目录执行，详见文档第 7 节；脚本已置可执行位，两种调用等价）：
  ./LynkCoHelper/tools/extract_appsecret_auto.py            # 全自动
  python3 LynkCoHelper/tools/extract_appsecret_auto.py <AVD名字>  # 指定 AVD

全自动内容（核心流程与 macOS 版共用 appsecret_core.py）：
  1. 前置环境自动探测与下载（存 ~/.lynkco-helper-tools/，二次运行复用）：
     - pexpect 缺失 -> 自动 pip 安装
     - adb / jdb 缺失 -> 多镜像源自动下载官方公开源包
     - emulator：本地已有的（带 qemu-system-aarch64）直接用；否则自下载
       （macos runner 预装的 darwin-x86_64 包不含 arm64 qemu，不能用）
     - arm64-v8a API34 Google APIs 系统镜像缺失 -> 下载（约 1.2GB）、
       手工创建 AVD（无需 cmdline-tools）
     - 硬件加速预检：macOS 查 Hypervisor.framework（缺失直接失败并指路
       Linux 路线——mac 上 arm64 guest 无法降级 TCG）；Linux 无需 KVM
       （arm64 镜像走 qemu TCG 全系统模拟）
  2. 无在线设备时自动冷启动 AVD（-no-snapshot-load，规避快照导致的握手
     挂死；设 EMU_HEADLESS=1 或无 DISPLAY 时自动切无头模式，适配 CI）
  3. 设备未装领克 App 时 -> 从领克官方 CDN 下载最新版 APK（约 285MB）
     自动安装（与 macOS 版共用 core.ensure_apk）
  4. 代理抢握手 -> jdb 断点单步 -> 提取 b/c 字段
  5. 提取成功后交互确认，可自动写入 env.json 的 secrets 段
     （CI 场景设 LYNKCO_AUTO_WRITE=1 免确认，env.json 缺失时自动创建）
  6. 连接中断（App 反调试自杀/平台不稳）或提取值格式异常时自动重试，
     最多 3 次；失败时 dump 设备侧诊断（进程/ABI/logcat 崩溃缓冲）

注意：密钥不应写入代码仓库（env.json 已被 gitignore）。
本地 macOS 已有 Android Studio 环境时，交互友好的入口是
tools/extract_appsecret.py。
"""
import glob
import os
import platform
import re
import sys
import zipfile
import urllib.request

import appsecret_core as core

# 下载镜像源：官方源优先（海外快），腾讯云镜像回退（国内快，包同步自 Google）
_PKG_MIRRORS = [
    "https://dl.google.com/android/repository/",
    "https://mirrors.cloud.tencent.com/AndroidSDK/",
]

_IS_MAC = sys.platform == "darwin"

# 镜像参数：默认 ABI 为 arm64-v8a（App 仅含 arm64 库，壳跑真 ARM64 指令，
# 2026-08-31 实测稳定）；API 用 33（本地 Mac 实测验证过的版本，提取流程
# 与 API 级别无关，文档 7.1 节亦确认 31~34 均可）。
#
# 实验：LYNKCO_IMAGE_ABI=x86_64（仅 Linux x86_64 宿主）——x86_64 镜像 +
# KVM 硬件加速，冷启动从 TCG 的 20~50 分钟降到约 45 秒；领克的 arm64
# 库由镜像自带的 libndk 翻译执行。镜像版本是成败关键（2026-09-06 定案）：
#   - 必须用 API33 的 x86_64-33_r09（abilist 含 arm64-v8a，自带 libndk；
#     本地 WSL2+KVM 实测连续 7+ 次提取成功）
#   - x86_64-33_r12 起 Google 移除了 arm64 翻译（abilist 仅 x86_64），
#     APK 安装直接 INSTALL_FAILED_NO_MATCHING_ABIS（run 33766293821）
#   - API34 的 x86_64 镜像虽可安装，但加固壳 libndk 翻译下启动约 3 秒
#     即 SIGSEGV（run 33768167646，3 次重试同型失败）
# 故本脚本对 x86_64 镜像钉死 r09 版本，不走"取最新"逻辑。
_ABI = os.environ.get("LYNKCO_IMAGE_ABI", "arm64-v8a")
if _ABI not in ("arm64-v8a", "x86_64"):
    sys.exit(f"[!] 不支持的 LYNKCO_IMAGE_ABI={_ABI}（可选 arm64-v8a / x86_64）")
_IS_X86_IMAGE = _ABI == "x86_64"
# 镜像 API：arm64/x86_64 均用 33。x86_64 用 API33 的 r09 修订版
# （r10+ 已移除 arm64 翻译；API34 可装但壳 3 秒 SIGSEGV，见上）
_API = "33"
_SYSIMG_PKG_RE = rf"({_ABI}-{_API}_r\d+\.zip)"
# x86_64 钉死 r09：r10+ 的镜像不再含 arm64 翻译（见上）
_SYSIMG_FALLBACK = f"sys-img/google_apis/{_ABI}-{_API}_r09.zip" \
    if _IS_X86_IMAGE else "sys-img/google_apis/arm64-v8a-33_r17.zip"
_SYSIMG_MB = 1700 if not _IS_X86_IMAGE else 1200
# AVD 名带 ABI 后缀：避免与（可能已存在的）arm64 AVD 配置互相覆盖
_AVD_NAME = "lynkco_helper_avd" if not _IS_X86_IMAGE else "lynkco_helper_avd_x64"
if _IS_X86_IMAGE:
    # x86_64 镜像在 x86_64 宿主上是同架构 KVM 硬件加速虚拟化，不是 TCG，
    # core 的超时/心跳按 SLOW_VM（linux 即 TCG）放大 10 倍，这里改回常态
    core.SLOW_VM = False
if _IS_MAC:
    _EMU_PKG_RE = r"(emulator-darwin_aarch64-\d+\.zip)"
    _EMU_MB = 350
    _PT_ZIP = "platform-tools-latest-darwin.zip"
    _CORRETTO_PKG = "amazon-corretto-8-aarch64-macos-jdk.tar.gz"
else:
    # Linux 也用最新 linux_x64 包：跨架构拒绝靠 AVD 谎报 target 绕过
    # （对 31.x~当前 master 的启动器均有效，见 _create_avd_manual），
    # 无需钉老版本；反而老二进制在新内核/glibc 上会段错误（31.3.10
    # qemu 在 2026 ubuntu runner 上 segfault at 0，run 33374210610
    # dmesg 实证）。qemu 全系统 TCG 模拟 arm64 guest，冷启动 20~50
    # 分钟属预期
    _EMU_PKG_RE = r"(emulator-linux_x64-\d+\.zip)"
    _EMU_MB = 350
    _PT_ZIP = "platform-tools-latest-linux.zip"
    _CORRETTO_PKG = "amazon-corretto-8-x64-linux-jdk.tar.gz"


def ensure_adb():
    """探测 adb；缺失时自动下载 Android platform-tools（官方公开源，
    ~10MB，解压即用，无需许可协议）。CI runner 已预装，直接复用。"""
    p = core.find_adb()
    if p:
        return p
    dest = os.path.join(core.TOOLS_DIR, "platform-tools")
    if not core._confirm_download("adb (Android platform-tools)", 10, dest):
        sys.exit("[!] 未找到 adb 且跳过下载。请安装 Android Studio（文档 7.1 节）"
                 "或系统包管理器（macOS: brew install android-platform-tools；"
                 "Linux: sudo apt install adb）后重试。")
    os.makedirs(core.TOOLS_DIR, exist_ok=True)
    arc = os.path.join(core.TOOLS_DIR, _PT_ZIP)
    core._download("https://dl.google.com/android/repository/" + _PT_ZIP, arc, 10)
    with zipfile.ZipFile(arc) as z:
        z.extractall(core.TOOLS_DIR)
    os.remove(arc)
    cand = os.path.join(core.TOOLS_DIR, "platform-tools", "adb")
    if not os.path.exists(cand):
        sys.exit(f"[!] 解压后未找到 adb，请检查 {core.TOOLS_DIR}")
    os.chmod(cand, 0o755)   # zipfile 解压不保留可执行位
    return cand


def ensure_jdb():
    """探测 jdb（任意版本 JDK 均可）；缺失时经确认自动下载 Amazon Corretto 8
    （官方公开源，~110MB，解压即用，无需许可协议）。"""
    p = core.find_jdb()
    if p:
        return p
    dest = os.path.join(core.TOOLS_DIR, "jdk8")
    if not core._confirm_download("jdb (Amazon Corretto 8 / JDK 8)", 110, dest):
        sys.exit("[!] 未找到 jdb 且跳过下载。请安装任意版本 JDK 后重试"
                 "（jdb 走 JDWP 协议，任意版本均可）。")
    os.makedirs(core.TOOLS_DIR, exist_ok=True)
    arc = os.path.join(core.TOOLS_DIR, _CORRETTO_PKG)
    core._download("https://corretto.aws/downloads/latest/" + _CORRETTO_PKG,
                   arc, 110)
    return core._extract_jdk_and_find_jdb(arc, dest)


# ---------------------------------------------------------------------------
# 模拟器 / 系统镜像 / AVD / APK 自动安装
# ---------------------------------------------------------------------------

def _fetch_latest_pkg_names():
    """从 Google repository XML 获取最新的 emulator 与 google_apis 系统镜像
    包名，返回 (emulator_pkg, sysimg_pkg)。两者分属不同 XML：emulator 在
    repository2-3.xml，系统镜像在 sys-img/google_apis/sys-img2-3.xml
    （只在主 XML 里找镜像永远找不到）。单项失败不影响另一项。
    同一包在 XML 中有多个通道（stable/beta/canary）各一块，只取 stable
    （channel-0）——beta 包捆绑 android-sdk-preview-license，行为不可预期。"""
    def _grep(url, pattern):
        try:
            text = urllib.request.urlopen(url, timeout=30).read().decode("utf-8", "replace")
        except Exception:
            return None
        for block in re.findall(r"<remotePackage[^>]*>.*?</remotePackage>", text, re.S):
            if 'ref="channel-0"' not in block:
                continue
            hits = re.findall(pattern, block)
            if hits:
                return hits[-1]
        hits = re.findall(pattern, text)   # 无 stable 块时回退全文匹配
        return hits[-1] if hits else None

    emu_pkg = _grep("https://dl.google.com/android/repository/repository2-3.xml",
                    _EMU_PKG_RE)
    sysimg = _grep("https://dl.google.com/android/repository/"
                   "sys-img/google_apis/sys-img2-3.xml",
                   _SYSIMG_PKG_RE)
    return emu_pkg, (f"sys-img/google_apis/{sysimg}" if sysimg else None)


def _download_and_extract(pkg_name, dest_dir, size_mb):
    """多镜像源下载 zip 并解压到指定目录，成功返回 True。"""
    arc = os.path.join(core.TOOLS_DIR, os.path.basename(pkg_name))
    for base in _PKG_MIRRORS:
        if core._try_download(base + pkg_name, arc, size_mb):
            print(f"[*] 解压 {os.path.basename(pkg_name)} 到 {dest_dir}"
                  f"（约 {size_mb}MB，可能需 1~3 分钟）...")
            os.makedirs(dest_dir, exist_ok=True)
            with zipfile.ZipFile(arc) as z:
                z.extractall(dest_dir)
            os.remove(arc)
            return True
    return False


def _make_executable(bin_dir):
    """zipfile 解压不保留可执行位，对无后缀二进制补 chmod +x。"""
    for root, _dirs, files in os.walk(bin_dir):
        for f in files:
            if os.path.splitext(f)[1] == "" or f.startswith("qemu-"):
                try:
                    os.chmod(os.path.join(root, f), 0o755)
                except OSError:
                    pass


def _create_avd_manual(avd_name):
    """手工创建 AVD 配置（无需 cmdline-tools/avdmanager）。
    AVD 本质就是 ~/.android/avd/<name>.ini + <name>.avd/config.ini。
    Linux 上根 ini 的 target 谎报 android-27（实际镜像仍是 API33）：启动器
    的跨架构检查是 "arm64 且 apiLevel>=28 才拒"（emulator/emulator/
    main-emulator.cpp，31.x~当前 master 同款），apiLevel 只从根 ini 的
    target= 解析（avd/avd-info.c，与镜像 build.prop 无交叉校验），
    而 CPU arch 从镜像 build.prop 读（真 arm64）。本地用 CI 同版 31.3.10
    实测：target=android-27 + API33 arm64 镜像正常 boot、guest 实为
    Android 13。顺带 hw.sdCard=no 规避 arm 镜像附加 sdcard 的老 bug
    （b/174481551：api>=30 时启动器本会跳过 sdcard，谎报 27 会重新踩上）。"""
    avd_home = os.environ.get("ANDROID_AVD_HOME",
                              os.path.join(os.path.expanduser("~"), ".android", "avd"))
    os.makedirs(avd_home, exist_ok=True)
    avd_dir = os.path.join(avd_home, f"{avd_name}.avd")
    os.makedirs(avd_dir, exist_ok=True)
    # Linux + arm64 镜像才需要谎报 target（跨架构检查）；x86_64 镜像是
    # 同架构，保持真实 target
    _fake_target = (not _IS_MAC) and (not _IS_X86_IMAGE)
    target_api = "27" if _fake_target else _API
    with open(os.path.join(avd_home, f"{avd_name}.ini"), "w", encoding="utf-8") as f:
        f.write("avd.ini.encoding=UTF-8\n")
        f.write(f"path={avd_dir}\n")
        f.write(f"path.rel=avd/{avd_name}.avd\n")
        f.write(f"target=android-{target_api}\n")
    with open(os.path.join(avd_dir, "config.ini"), "w", encoding="utf-8") as f:
        f.write("avd.ini.encoding=UTF-8\n")
        f.write(f"image.sysdir.1=system-images/android-{_API}/google_apis/{_ABI}/\n")
        f.write("tag.id=google_apis\n")
        f.write("tag.display=Google APIs\n")
        f.write(f"abi.type={_ABI}\n")
        f.write(f"hw.cpu.arch={'x86_64' if _IS_X86_IMAGE else 'arm64'}\n")
        f.write("hw.cpu.ncore=4\n")
        f.write("hw.ramSize=2048\n")
        f.write("hw.lcd.width=1080\n")
        f.write("hw.lcd.height=1920\n")
        f.write("hw.lcd.density=440\n")
        f.write("hw.keyboard=yes\n")
        f.write("hw.gpu.enabled=yes\n")
        f.write("hw.gpu.mode=auto\n")
        # hw.sdCard=no 仅 arm 镜像需要（规避 b/174481551：谎报 target=27
        # 后启动器重新踩 arm 镜像 sdcard 老 bug）；x86_64 镜像无此问题
        if not _IS_MAC and not _IS_X86_IMAGE:
            f.write("hw.sdCard=no\n")
        # Linux/CI：userdata 2GB 足够（App 285MB 装后 <1GB）；runner 磁盘
        # 紧张，6GB 分区 + 镜像 + 快照有爆盘风险。macOS 本地磁盘宽裕
        # 维持 6GB（多留 App 数据余量）
        f.write(f"disk.dataPartition.size={'2147483648' if not _IS_MAC else '6442450944'}\n")
    print(f"[+] 已创建 AVD: {avd_name}")


def _ensure_acceleration():
    """硬件加速预检（下载镜像前做，避免白下 ~1.2GB 后才发现起不来）：
    - macOS：arm64 guest 死绑 Hypervisor.framework（37.1.11 实测：
      -accel off 传给 qemu 后仍走 HVF；-qemu 直通 -accel tcg 即
      fatal "HVF error: HV_NO_DEVICE"），无 HVF 直接失败并指路 Linux
      路线。GitHub macos runner 是 VM，guest 内无 HVF（官方确认短期
      无解，actions/runner-images#13505）——mac runner 不可行。
    - Linux x86_64：arm64 镜像走 qemu 全系统 TCG 模拟，无需 KVM。"""
    if not _IS_MAC:
        return
    try:
        out = core.sh(["sysctl", "-n", "kern.hv_support"]).strip()
    except Exception:
        out = ""
    if out != "1":
        sys.exit("[!] 此 macOS 无 Hypervisor.framework（VM 内？）。Android "
                 "emulator 的 arm64 guest 在 macOS 上死绑 HVF，无法降级 "
                 "TCG（2026-08-31 实测），本环境跑不了 arm64 镜像。\n"
                 "    CI 请用 ubuntu-latest：x86_64 宿主 + arm64-v8a 镜像，"
                 "qemu 全系统 TCG 模拟，App 的 arm64 代码原生执行。")


def _emu_supports_arm64_guests(emu):
    """检查 emulator 是否带 qemu-system-aarch64（承载 arm64 guest 的前提）。
    darwin-aarch64 / linux-x86_64 官方包都带；GitHub macos runner 预装的
    darwin-x86_64 包不带（启动 arm64 AVD 即 "Could not launch .../qemu/
    darwin-x86_64/qemu-system-aarch64"，run 33359423830 实测）。"""
    hits = glob.glob(os.path.join(os.path.dirname(emu), "qemu", "*",
                                  "qemu-system-aarch64*"))
    return bool(hits)


def ensure_emulator(existing_emu=None):
    """自动下载 emulator + 系统镜像并创建 AVD（镜像约 1.2GB）。
    返回 (emulator_path, avd_name)。下载前先做硬件加速预检。
    现有 emulator 不带 qemu-system-aarch64 时（如 macos runner 预装的
    darwin-x86_64 包）不用它，改自下载对应平台的官方包（linux_x64 包
    自带 qemu-system-aarch64）。"""
    sdk_root = os.path.join(core.TOOLS_DIR, "sdk")
    emu = os.path.join(sdk_root, "emulator", "emulator")
    # 复用条件仅一条：带 qemu-system-aarch64（跨架构拒绝靠 AVD 谎报
    # target 绕过，31.x~master 启动器均适用，无需版本门禁）
    if existing_emu and _emu_supports_arm64_guests(existing_emu):
        emu = existing_emu
        sdk_root = os.path.dirname(os.path.dirname(emu))
    elif existing_emu:
        print("[*] 现有 emulator 不带 qemu-system-aarch64（无法承载 arm64 "
              "guest），改用自下载的官方 emulator 包 ...")
    else:
        print("[*] 未找到 emulator，开始自动安装 ...")
    os.makedirs(sdk_root, exist_ok=True)

    _ensure_acceleration()

    sysimg_dir = os.path.join(sdk_root, "system-images", f"android-{_API}",
                              "google_apis", _ABI)
    emu_pkg, sysimg_pkg = None, None
    if not os.path.exists(emu) or not os.path.exists(sysimg_dir):
        emu_pkg, sysimg_pkg = _fetch_latest_pkg_names()
        if _IS_X86_IMAGE:
            # x86_64 镜像钉死 r09：XML 里"最新"是 r12，已移除 arm64 翻译，
            # 装 APK 会 INSTALL_FAILED_NO_MATCHING_ABIS，必须用钉住的包名
            sysimg_pkg = _SYSIMG_FALLBACK

    # 1. emulator（最新官方包，约 350MB）
    if not os.path.exists(emu):
        if not emu_pkg:
            sys.exit("[!] 无法获取 emulator 包名（repository XML 不可达），"
                     "请手动安装 Android SDK 后重试。")
        print(f"[*] 下载 emulator ({emu_pkg}, 约 {_EMU_MB}MB)...")
        if not _download_and_extract(emu_pkg, sdk_root, _EMU_MB):
            sys.exit(f"[!] emulator 下载失败，可手动下载解压到 {sdk_root}/")
        _make_executable(os.path.join(sdk_root, "emulator"))
    if not os.path.exists(emu):
        sys.exit(f"[!] 安装后未找到 emulator：{emu}")

    # 2. sdk_root 下必须有 platform-tools 子目录，否则 emulator 启动即
    #    FATAL "Broken AVD system path"
    pt_dir = os.path.join(sdk_root, "platform-tools")
    if not os.path.exists(pt_dir):
        print("[*] 下载 platform-tools 到 SDK 目录 (~10MB)...")
        arc = os.path.join(core.TOOLS_DIR, "platform-tools-sdk.zip")
        core._download("https://dl.google.com/android/repository/" + _PT_ZIP, arc, 10)
        with zipfile.ZipFile(arc) as z:
            z.extractall(sdk_root)
        os.remove(arc)

    # 2b. 旧版 emulator（如 31.3.10）的 SDK 根校验要求 platforms/ 子目录
    #     存在（新版已不查），缺失即 WARN "invalid sdk root" -> PANIC
    #     "Broken AVD system path"（run 33368243194 实测）。空目录即可
    #     通过校验：模拟器启动只用 system-images，platforms 里的
    #     android.jar 是编译期产物，启动不读。
    plat_dir = os.path.join(sdk_root, "platforms", f"android-{_API}")
    os.makedirs(plat_dir, exist_ok=True)

    # 3. 系统镜像（API 33 Google APIs，ABI 恒为 arm64-v8a）
    if not os.path.exists(sysimg_dir):
        # 上次运行可能解压到错误位置（sdk_root/<ABI>），先归位
        wrong_dir = os.path.join(sdk_root, _ABI)
        if os.path.isdir(wrong_dir):
            os.makedirs(os.path.dirname(sysimg_dir), exist_ok=True)
            os.rename(wrong_dir, sysimg_dir)
            print(f"[+] 系统镜像已移到正确位置: {sysimg_dir}")
        else:
            if not sysimg_pkg:
                sysimg_pkg = _SYSIMG_FALLBACK
                print(f"[*] 未从 XML 取到镜像包名，使用已验证版本: {sysimg_pkg}")
            print(f"[*] 下载系统镜像 ({sysimg_pkg}, 约 {_SYSIMG_MB}MB)...")
            # zip 内顶层是 <ABI>/，解压到 google_apis/ 即得 google_apis/<ABI>/
            if not _download_and_extract(sysimg_pkg, os.path.dirname(sysimg_dir),
                                         _SYSIMG_MB):
                sys.exit("[!] 系统镜像下载失败，可手动下载解压到 "
                         f"{os.path.dirname(sysimg_dir)}/")

    _create_avd_manual(_AVD_NAME)
    return emu, _AVD_NAME


def ensure_apk():
    """已收敛至共享核心（appsecret_core.ensure_apk），两平台行为一致。"""
    core.ensure_apk()


def ensure_device(wanted_avd=None):
    """有在线设备直接用；否则冷启动 AVD（-no-snapshot-load 是硬性前提，见 4.5 坑 1）。"""
    out = core.adb("devices")
    online = [ln.split()[0] for ln in out.splitlines()
              if ln.strip().endswith("\tdevice")]
    if online:
        print(f"[*] 检测到在线设备：{online[0]}"
              "（若此前是快照方式启动且稍后握手挂死，请改用冷启动后重试，见文档 4.5 坑 1）")
        return
    emu = core.find_emulator()
    if not emu:
        # 硬件加速预检 + 自动下载 emulator/镜像 + 建 AVD
        emu, avd = ensure_emulator()
        core.cold_start_and_wait(emu, avd)
        return
    _ensure_acceleration()   # 有 emulator 也先预检：mac 无 HVF 直接失败，别白下镜像白等超时
    avds = core.sh([emu, "-list-avds"]).split()
    if not avds:
        # 复用/自备 emulator，补齐镜像并创建 AVD。
        # 必须用返回值：现有 emulator 不带 arm64 qemu 时 ensure_emulator 会
        # 切换为自下载的官方包（run 33361068931 踩坑：丢弃返回值导致仍用
        # 预装 emulator + 镜像在另一 sdk 根，启动即 PANIC "Broken AVD system path"）
        emu, avd = ensure_emulator(emu)
        core.cold_start_and_wait(emu, avd)
        return
    if wanted_avd:
        if wanted_avd not in avds:
            sys.exit(f"[!] 未找到 AVD \"{wanted_avd}\"，可用：{', '.join(avds)}")
        avd = wanted_avd
    elif len(avds) == 1:
        avd = avds[0]
    else:
        print("[*] 检测到多个 AVD：")
        for i, name in enumerate(avds, 1):
            print(f"    {i}. {name}")
        try:
            idx = int(input("选择要启动的编号 [1]: ").strip() or "1") - 1
            avd = avds[idx]
        except (ValueError, IndexError, EOFError):
            avd = avds[0]
    core.cold_start_and_wait(emu, avd)


def main():
    if _IS_MAC and platform.machine() != "arm64":
        sys.exit("[!] Intel mac 不支持：emulator 的 darwin-x86_64 包不含 "
                 "qemu-system-aarch64，跑不了 arm64 镜像。请改用 x86_64 Linux"
                 "（qemu 全系统 TCG 模拟）或 arm64 真机（adb 连接后跑本地版 "
                 "tools/extract_appsecret.py）。")
    if not _IS_MAC and platform.machine() != "x86_64":
        sys.exit("[!] Linux ARM64 无官方 emulator/platform-tools 包。请改用 "
                 "x86_64 Linux（ubuntu runner，qemu 全系统 TCG 模拟）、"
                 "Apple Silicon Mac（HVF 原生）或 arm64 真机（本地版 "
                 "tools/extract_appsecret.py）。")
    if _IS_X86_IMAGE and (_IS_MAC or platform.machine() != "x86_64"):
        sys.exit("[!] LYNKCO_IMAGE_ABI=x86_64 实验仅支持 x86_64 Linux 宿主"
                 "（x86_64 镜像 + KVM + libndk 翻译 arm64 库）。")
    if _IS_X86_IMAGE:
        print("[*] 实验模式：x86_64 镜像 + KVM，领克 arm64 库经 libndk 翻译执行。")
        print("    已实证：壳翻译执行约 3 秒即 SIGSEGV（run 33768167646），"
              "本路线预期失败，仅作复现验证。")
    core.ensure_pexpect()
    core.setup(ensure_adb(), ensure_jdb())
    print(f"[*] adb: {core.ADB}")
    print(f"[*] jdb: {core.JDB}")
    ensure_device(sys.argv[1].strip() if len(sys.argv) > 1 else None)
    ensure_apk()
    core.extract_main_loop()


if __name__ == "__main__":
    main()
