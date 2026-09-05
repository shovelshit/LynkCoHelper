#!/usr/bin/env python3
"""一键本地提取 nativeAppKey / nativeAppSecret（x86_64 镜像 + KVM 路线）。

与 extract_appsecret_auto.py 的区别：
  - auto 版是为 CI（GitHub Actions runner）设计的全自动下载+提取；
  - 本版面向"本地已配好 WSL2/Ubuntu 环境的一键复跑"：
      1) 已有在线模拟器直接复用，否则冷启动 x86_64 AVD（约 2~5 分钟）；
      2) App 未安装时优先用 TOOLS_DIR 里已下载的本地 APK，缺失才走官方
         接口下载；
      3) 提取主流程不走 auto 版的多线程代理（其在本地环境有竞态问题），
         而是 jdb 直连：am start -D 挂起启动 → 等 JDWP 注册 → 新端口
         forward → jdb attach（显式 127.0.0.1，见下"IPv6 坑"）→ 设
         延迟断点 → resume → 命中 <clinit> 断点 → next 探针 → dump 字段。

为什么必须 x86_64 镜像（arm64 路线本地不可行的根因，详见 docs）：
  arm64 ranchu 虚拟机没有 PCI 总线，而 31.3.10 / 36.2.12 的 emulator
  qemu fork 会无条件初始化 virtio-snd-pci 音频设备，"PCI bus not
  available" 直接致命，且无任何参数可绕（二进制手术是唯一出路）。
  x86_64 镜像走 KVM 原生加速，冷启动秒级~分钟级，加固壳经 libndk
  翻译执行可存活到 <clinit>。

三个本地环境专属大坑（macOS/CI 不复现）：
  1. IPv6 坑：`jdb -attach 端口` 连 localhost 会解析成 ::1，而 adb
     forward 的监听只绑 127.0.0.1（IPv4）→ Connection refused 死循环。
     必须显式 `jdb -attach 127.0.0.1:端口`（core 已同步修复）。
  2. forward 生命周期坑：JDWP 注册出现之前建立的 forward 被 adbd 绑在
     空端点上，之后重复下发同名 forward 是 no-op，连接永远 refused。
     所以每轮用全新端口建 forward（18800 起循环复用）。
  3. 探测握手坑：App 处于 -D 等待调试器状态时，任何"连上就断开"的
     探测（python 握手/超时被杀的 jdb）都会导致 VM 自杀。jdb 一旦
     attach 成功就要走完提取流程，绝不提前 kill。

后台运行注意（wsl.exe 特有）：wsl 会话结束会 SIGTERM 整个进程组，
nohup 只挡 SIGHUP 挡不住它，后台跑必须 `setsid nohup ... &`。

用法：
  python3 LynkCoHelper/tools/extract_appsecret_x86_local.py            # 默认 AVD
  python3 LynkCoHelper/tools/extract_appsecret_x86_local.py <AVD名>    # 指定 AVD
  LYNKCO_AUTO_WRITE=0 ...   # 提取成功后交互确认再写 env.json
"""
import argparse
import glob
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import appsecret_core as core

# 本地一键场景的默认值（都可用环境变量覆盖）：
# - EMU_HEADLESS=1：无头跑，不弹窗口
# - LYNKCO_AUTO_WRITE=1：成功后免确认直接写 env.json
# - LYNKCO_UPSTREAM_TIMEOUT=420：等 JDWP 注册/附着的主窗口（秒）
os.environ.setdefault("EMU_HEADLESS", "1")
os.environ.setdefault("LYNKCO_AUTO_WRITE", "1")
os.environ.setdefault("LYNKCO_UPSTREAM_TIMEOUT", "420")

# forward 端口池起点：注册前建立的 forward 会绑死空端点（见文件头坑 2），
# 每轮重试换新端口，40 个循环复用
_FWD_BASE = 18800

# 模拟器重启重试标记：只自动重启一次，避免无限循环
_RESTARTED = False


def main():
    ap = argparse.ArgumentParser(
        description="一键本地提取领克 App nativeAppKey/nativeAppSecret")
    ap.add_argument("avd", nargs="?", default="lynkco_helper_avd_x64",
                    help="AVD 名（默认 lynkco_helper_avd_x64，x86_64 镜像）")
    args = ap.parse_args()

    core.ensure_pexpect()
    # 环境自举：adb/jdb 缺失时自动下载（复用 auto 脚本的 ensure 系列）
    os.environ.setdefault("LYNKCO_IMAGE_ABI", "x86_64")
    import extract_appsecret_auto as boot
    adb_path = boot.ensure_adb() or core.find_adb()
    jdb_path = boot.ensure_jdb() or core.find_jdb()
    if not adb_path or not jdb_path:
        sys.exit("[!] adb/jdb 自动下载失败，请检查网络后重试")
    core.setup(adb_path, jdb_path)
    import pexpect

    ADB, JDB = core.ADB, core.JDB
    PKG, ACT, CLASS = core.APP, core.ACTIVITY, core.CLASS

    def adb(*a, t=25):
        # Windows 版脚本 connect 过 127.0.0.1:5555 后，本机 adb 可能同时
        # 看到 emulator-5554 和 127.0.0.1:5555 两台设备，所有调用必须
        # 带 -s 指定序列号，否则报 more than one device
        args = [ADB] + (["-s", serial[0]] if serial[0] else []) + list(a)
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=t).stdout

    # ---------- 1. 在线模拟器？没有则冷启动 ----------
    serial = [None]
    online = False
    for ln in adb("devices").splitlines()[1:]:
        parts = ln.split()
        if len(parts) >= 2 and parts[1] == "device" and \
                parts[0].startswith("emulator-"):
            print(f"[*] 已有在线模拟器 {parts[0]}，直接复用")
            serial[0] = parts[0]
            online = True
            break
    if not online:
        emu = core.find_emulator()
        if not emu:
            # 模拟器缺失：自动下载 emulator（~350MB）+ x86_64 系统镜像
            # （~1.2GB）并创建 AVD，仅首次
            emu, args.avd = boot.ensure_emulator()
        else:
            avd_dir = os.path.expanduser(f"~/.android/avd/{args.avd}.avd")
            if not os.path.isdir(avd_dir):
                boot.ensure_emulator(emu)   # 复用现有 emulator，补建 AVD
        core.cold_start_and_wait(emu, args.avd)
        for ln in adb("devices").splitlines()[1:]:
            parts = ln.split()
            if len(parts) >= 2 and parts[1] == "device" and \
                    parts[0].startswith("emulator-"):
                serial[0] = parts[0]
                break

    # ---------- 2. 领克 App 已安装？没有则装 ----------
    if PKG not in adb("shell", "pm", "list", "packages"):
        print("[*] 领克 App 未安装，尝试本地 APK ...")
        apks = sorted(glob.glob(os.path.join(core.TOOLS_DIR,
                                             "lynkco-v*.apk")))
        apk = apks[-1] if apks else None
        if apk:
            print(f"[*] 使用本地包 {os.path.basename(apk)}")
        else:
            apk = core.ensure_apk()   # 本地没有则走官方接口下载最新版
        print(adb("install", "-r", "-g", apk, t=600).strip())

    # ---------- 3. 提取主循环 ----------
    for attempt in range(1, core.MAX_ATTEMPTS + 1):
        print(f"\n========== 第 {attempt}/{core.MAX_ATTEMPTS} 次尝试 ==========",
              flush=True)
        adb("shell", "am", "force-stop", PKG)
        time.sleep(1)
        # -D：等调试器再跑，为断点抢在 <clinit> 之前赢得窗口
        print(adb("shell", "am", "start", "-D", "-n", ACT).strip(), flush=True)

        pid = None
        t0 = time.time()
        while time.time() - t0 < 60:
            out = adb("shell", "pidof", PKG).strip()
            if out and out.split()[0].isdigit():
                pid = out.split()[0]
                break
            time.sleep(0.5)
        print("pid:", pid, flush=True)
        if not pid:
            print("[!] 未取到 App PID（启动即崩？检查镜像 ABI 与 libndk）")
            continue

        # forward + jdb attach 重试：连接被拒 = JDWP 尚未注册（libndk 下
        # 运行时初始化要几分钟），无副作用，循环等到注册完成即一发命中。
        # 见文件头坑 2（每轮新端口）与坑 3（成功后绝不中断）
        child = None
        t0 = time.time()
        port_i = 0
        deadline = t0 + int(os.environ["LYNKCO_UPSTREAM_TIMEOUT"])
        while time.time() < deadline:
            fwd = _FWD_BASE + (port_i % 40)
            port_i += 1
            try:
                subprocess.run([ADB, "forward", f"tcp:{fwd}", f"jdwp:{pid}"],
                               capture_output=True, text=True, timeout=10)
            except subprocess.TimeoutExpired:
                print("forward 卡死，重试", flush=True)
                time.sleep(5)
                continue
            child = pexpect.spawn(f"{JDB} -attach 127.0.0.1:{fwd}",
                                  timeout=60, encoding="utf-8")
            idx = child.expect(core.PROMPTS + [pexpect.EOF, pexpect.TIMEOUT],
                               timeout=60)
            if idx < len(core.PROMPTS):
                print(f"jdb 已附着（t={time.time() - t0:.1f}s）", flush=True)
                break
            try:
                child.kill(9)
            except Exception:
                pass
            child = None
            time.sleep(12)
        if child is None:
            print("[!] 整个窗口内 jdb 都没附着上（JDWP 一直未注册？）")
            continue

        try:
            # App 在 -D 挂起点：先全挂起，对壳的常量类设延迟断点，再
            # resume 放行，等 <clinit> 命中
            core.send_cmd(child, "suspend", timeout=60)
            core.send_cmd(child, f"stop in {CLASS}.<clinit>", timeout=60)
            child.sendline("resume")
            idx = child.expect(core.BREAKPOINT_PATTERNS +
                               [pexpect.EOF, pexpect.TIMEOUT], timeout=300)
            if idx < len(core.BREAKPOINT_PATTERNS):
                print("[+] Breakpoint hit!", flush=True)
                time.sleep(0.2)
                try:
                    child.expect(core.PROMPTS + [pexpect.TIMEOUT], timeout=5)
                except Exception:
                    pass
                # 壳可能在断点行之后才给字段赋值，next 逐步探到 c 有值为止
                for i in range(15):
                    core.send_cmd(child, "next", timeout=60)
                    out = core.send_cmd(child, f"print {CLASS}.c", timeout=30)
                    v = core.parse_field(out)
                    print(f"probe c: {v!r}", flush=True)
                    if v:
                        break
            else:
                print("[!] 未命中断点（clinit 可能已提前执行），直接 dump")
            results = {}
            for f in ["b", "c", "d", "e"]:
                results[f] = core.send_cmd(child, f"print {CLASS}.{f}",
                                           timeout=30)
                print(f"--- {f} raw: {results[f]!r}", flush=True)
            key = core.parse_field(results.get("b", ""))
            secret = core.parse_field(results.get("c", ""))
            print("\n[RESULT]")
            print(f"    nativeAppKey    = {key}")
            print(f"    nativeAppSecret = {secret}")
            if core.looks_valid(key) and core.looks_valid(secret):
                core.maybe_write_env(key, secret)
                print("[+] 提取完成")
                return
            print("[!] 提取值格式异常（疑似 jdb 输出不同步），重试 ...")
        finally:
            # 见文件头坑 3：jdb 一旦附着成功就绝不在提取流程中提前 kill；
            # 这里是流程走完（成功/失败）后的兜底清理
            try:
                child.kill(9)
            except Exception:
                pass
            try:
                adb("forward", "--remove", f"tcp:{_FWD_BASE}")
            except Exception:
                pass

    # 全部失败：模拟器长时间连跑后会出现状态劣化（JDWP 注册越来越慢、
    # 渲染帧时间暴涨），重启冷启动一次往往即恢复
    global _RESTARTED
    if not _RESTARTED:
        _RESTARTED = True
        print("[*] 所有尝试失败：疑似模拟器长时间运行状态劣化，"
              "重启冷启动一次后自动重试 ...")
        adb("emu", "kill", t=15)
        time.sleep(8)
        # 清掉残留 TCP 传输（如 Windows 版 connect 过的 127.0.0.1:5555），
        # 否则 wait-for-device 在多设备歧义下报超时
        adb("disconnect", t=10)
        emu = core.find_emulator()
        core.cold_start_and_wait(emu, args.avd)
        return main()
    sys.exit(f"[!] {core.MAX_ATTEMPTS} 次尝试全部失败；若反复失败请参考文件头"
             "的坑位说明与 docs/本地一键提取指南.md 的排障章节")


if __name__ == "__main__":
    main()
