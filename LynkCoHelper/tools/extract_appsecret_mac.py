#!/usr/bin/env python3
"""
extract_appsecret.py —— macOS 版：一键自动提取领克 App 的 nativeAppKey /
nativeAppSecret（平台共享核心见 appsecret_core.py）。

原理（详见 docs/AppSecret_逆向分析记录.md 4.5 节）：
  App 进入 waitForDebugger 阻塞态后，adbd 的 jdwp 转发握手会永久挂死；
  只有在进程 fork 后约 0.5s 的早期窗口内完成 JDWP 握手才能成功，而 jdb
  （JVM）冷启动需 1-3s 赶不上。故由本地 TCP 代理抢先完成握手，再把字节流
  双向转发给 jdb 下断点提取。

用法（在仓库根目录执行，详见文档第 7 节；脚本已置可执行位，两种调用等价）：
  ./LynkCoHelper/tools/extract_appsecret.py             # 无设备时自动冷启动 AVD
  python3 LynkCoHelper/tools/extract_appsecret.py <AVD名字>  # 指定要冷启动的 AVD

macOS 自动化内容（核心流程与全自动版共用 appsecret_core.py）：
  1. pexpect 缺失 -> 自动 pip 安装
  2. adb (platform-tools ~10MB) / jdb (Corretto 8 ~110MB) 缺失 ->
     确认后自动下载官方公开源包到 ~/.lynkco-helper-tools/（无需许可协议）
  3. 无在线设备时自动冷启动 AVD（-no-snapshot-load，规避快照导致的握手挂死）
  4. 设备未装领克 App 时自动从领克官方 CDN 下载最新版 APK（约 285MB）并安装
  5. 代理抢握手 -> jdb 断点单步 -> 提取 b/c 字段
  6. 提取成功后交互确认，可自动写入 env.json 的 secrets 段
  7. 连接中断（App 反调试自杀/平台不稳）或提取值格式异常时自动重试，最多 3 次

注意：密钥不应写入代码仓库（env.json 已被 gitignore）。
平台限制：仅模拟器/AVD 在 macOS 上需一次性手动创建（Android Studio 图形
界面三步更可靠，见文档 7.1 节）；CI/无本地环境的全自动版（含模拟器
镜像下载）见 tools/extract_appsecret_auto.py。
"""
import os
import platform
import sys
import zipfile

import appsecret_core as core


def ensure_adb():
    """探测 adb（core.find_adb）；缺失时经确认自动下载 Android platform-tools
    （官方公开源，~10MB，解压即用，无需许可协议）。"""
    p = core.find_adb()
    if p:
        return p
    dest = os.path.join(core.TOOLS_DIR, "platform-tools")
    if not core._confirm_download("adb (Android platform-tools)", 10, dest):
        sys.exit("[!] 未找到 adb 且跳过下载。请安装 Android Studio（文档 7.1 节）"
                 "或设置 ANDROID_HOME 后重试。")
    os.makedirs(core.TOOLS_DIR, exist_ok=True)
    zip_name = "platform-tools-latest-darwin.zip"
    arc = os.path.join(core.TOOLS_DIR, zip_name)
    core._download("https://dl.google.com/android/repository/" + zip_name, arc, 10)
    with zipfile.ZipFile(arc) as z:
        z.extractall(core.TOOLS_DIR)
    os.remove(arc)
    cand = os.path.join(core.TOOLS_DIR, "platform-tools", "adb")
    if not os.path.exists(cand):
        sys.exit(f"[!] 解压后未找到 adb，请检查 {core.TOOLS_DIR}")
    return cand


def ensure_jdb():
    """探测 jdb（core.find_jdb）；缺失时经确认自动下载 Amazon Corretto 8 /
    JDK 8（官方公开源，~110MB，解压即用，无需许可协议）。"""
    p = core.find_jdb()
    if p:
        return p
    dest = os.path.join(core.TOOLS_DIR, "jdk8")
    if not core._confirm_download("jdb (Amazon Corretto 8 / JDK 8)", 110, dest):
        sys.exit("[!] 未找到 jdb 且跳过下载。请安装 JDK 8"
                 "（macOS: brew install --cask corretto8）后重试。")
    os.makedirs(core.TOOLS_DIR, exist_ok=True)
    arch = "aarch64" if platform.machine() == "arm64" else "x64"
    pkg_name = f"amazon-corretto-8-{arch}-macos-jdk.tar.gz"
    arc = os.path.join(core.TOOLS_DIR, pkg_name)
    core._download("https://corretto.aws/downloads/latest/" + pkg_name, arc, 110)
    return core._extract_jdk_and_find_jdb(arc, dest)


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
        sys.exit("[!] 无在线设备且未找到 emulator。模拟器/AVD 需一次性手动安装："
                 "Android Studio -> Device Manager 创建（系统镜像选 Google APIs，"
                 "勿选 Google Play），步骤见文档 7.1 节。本脚本不自动下载它"
                 "（emulator + 系统镜像约 1.5GB 且需接受许可协议，手动装一次"
                 "更可靠）。CI/无本地环境的全自动版本见 extract_appsecret_auto.py。")
    avds = core.sh([emu, "-list-avds"]).split()
    if not avds:
        sys.exit("[!] 无在线设备，也未找到任何 AVD。请先在 Android Studio 创建模拟器"
                 "（系统镜像必须选 Google APIs，不要选 Google Play）。")
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
    if sys.platform != "darwin":
        sys.exit(f"[!] 本脚本是 macOS 本地版（当前平台: {sys.platform}）。\n"
                 "    CI/无本地环境请用: LynkCoHelper/tools/extract_appsecret_auto.py")
    core.ensure_pexpect()
    core.setup(ensure_adb(), ensure_jdb())
    print(f"[*] adb: {core.ADB}")
    print(f"[*] jdb: {core.JDB}")
    ensure_device(sys.argv[1].strip() if len(sys.argv) > 1 else None)
    core.ensure_apk()
    core.extract_main_loop()


if __name__ == "__main__":
    main()
