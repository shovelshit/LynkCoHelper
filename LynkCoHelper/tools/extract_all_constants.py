#!/usr/bin/env python3
"""
extract_all_constants.py —— 全量常量提取（v3：专攻 HttpSecretKey/GRIC 密钥）。

背景：
  v2 已提取 com.safe.cons.b 的 20 个常量（落盘 extracted_constants.json），
  但穷举验证证明 GRIC 网关 X-SIGNATURE 的 HMAC key 不在其中——该密钥由
  libHttpSecretKey.so 保管（JNI: com.haohan.module.http.encrypt.
  HttpSecretKey.getSecretKey/setSecretKey），运行时动态设置。

v3 流程（最小化调试暴露面，无单步）：
  1. 代理抢 JDWP 早期窗口握手（同 core.run_once）
  2. suspend 冻结 -> 设两个断点：
     - 密钥常量类（core 自动定位，如 LynkCoConstants$f）.<clinit>
       （早期必命中，确认调试链路活着）
     - com.haohan.module.http.encrypt.HttpSecretKey.<clinit>（延迟断点：
       类首次初始化时命中，即 App 首个 GRIC 请求签名前）
  3. 哨兵断点命中后 clear 该断点 -> cont 放行
  4. 等 HttpSecretKey.<clinit> 命中（App 启动后数秒内发心跳即触发）
  5. 命中后：dump 该类 fields/methods，探测 getSecretKey 的调用形式
     （静态/实例/Companion），取返回值；再 cont 数秒 -> suspend -> 复取
     （密钥可能在 clinit 之后才 setSecretKey）
  6. kill -9 jdb 收尾

用法（macOS）：
  python3 LynkCoHelper/tools/extract_all_constants.py [AVD名字]

结果实时打印并持续落盘 ~/.lynkco-helper-tools/extracted_constants.json
（v2 的 20 个 com.safe.cons.b 常量已在其中，本脚本追加 HttpSecretKey 结果）。
"""
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import appsecret_core as core
import extract_appsecret_mac as mac_entry

try:
    import pexpect
except ImportError:
    pexpect = None

OUT_FILE = os.path.join(core.TOOLS_DIR, "extracted_constants.json")

# 目标：GRIC 网关签名密钥所在类（libHttpSecretKey.so 的 Java 侧）
TARGET_CLASS = "com.haohan.module.http.encrypt.HttpSecretKey"
# 顺带探测的其他 haohan 安全类
EXTRA_CLASSES = ["com.haohan.common.security.HHSecurity",
                 "com.haohan.common.security.HHSecurity$Companion"]

# 等 HttpSecretKey.<clinit> 命中的超时（App 启动到首个 GRIC 心跳的耗时）
TARGET_BP_TIMEOUT = int(os.environ.get("EXTRACT_TARGET_BP_TIMEOUT", "120"))
# clinit 命中后再 cont 的秒数（等 setSecretKey 被调用）
POST_CLINIT_WAIT = int(os.environ.get("EXTRACT_POST_CLINIT_WAIT", "6"))


def _load_existing_results():
    try:
        with open(OUT_FILE, "r", encoding="utf-8") as stream:
            existing = json.load(stream)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid existing constants JSON in {OUT_FILE}: {error}") from error
    if not isinstance(existing, dict):
        raise ValueError(f"Existing constants JSON in {OUT_FILE} must be a dict")
    return existing


def _save(results):
    merged = _load_existing_results()
    merged.update(results)
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=os.path.dirname(OUT_FILE),
                                         delete=False, encoding="utf-8") as stream:
            temporary = stream.name
            json.dump(merged, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, OUT_FILE)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def safe_cmd(child, cmd, timeout=15):
    try:
        return core.send_cmd(child, cmd, timeout=timeout)
    except core.Disconnected:
        raise
    except Exception as e:
        print(f"    [!] 命令 {cmd!r} 失败：{e}")
        return ""


def record(results, key, val):
    if val and key not in results:
        results[key] = val
        print(f"    [+] {key} = {val!r}")
        _save(results)
        return True
    return False


def parse_fields(out):
    names = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith(">") or ln.startswith("main[") or ln.startswith("**"):
            continue
        toks = ln.split()
        if len(toks) >= 2 and re.fullmatch(r"[A-Za-z_$][\w$]*", toks[-1]):
            if toks[-1] not in ("shadow$_klass_", "shadow$_monitor_") and toks[-1] not in names:
                names.append(toks[-1])
    return names


def parse_methods(out, cls):
    ms = []
    for ln in out.splitlines():
        m = re.match(rf"^{re.escape(cls)}\s+([\w$<>]+)\(([^)]*)\)", ln.strip())
        if m:
            ms.append((m.group(1), m.group(2)))
    return ms


def dump_class(child, cls, results):
    """dump 一个类的字段值 + 无参方法返回值（静态/实例两种形式都试）。"""
    out = safe_cmd(child, f"fields {cls}", timeout=10)
    flds = parse_fields(out)
    if flds:
        print(f"[*] {cls} 字段: {flds}")
        for f in flds:
            o = safe_cmd(child, f"print {cls}.{f}", timeout=10)
            record(results, f"{cls}.{f}", core.parse_field(o))

    out = safe_cmd(child, f"methods {cls}", timeout=10)
    ms = parse_methods(out, cls)
    noarg = [n for n, a in ms if not a.strip() and not n.startswith("<")]
    if noarg:
        print(f"[*] {cls} 无参方法: {noarg}")
    # 找实例工厂：静态方法返回本类实例的（如 o()/getInstance()）
    factories = []
    for n, a in ms:
        if n in ("<init>", "<clinit>") or a.strip():
            continue
        o = safe_cmd(child, f"print {cls}.{n}()", timeout=10)
        val = core.parse_field(o)
        if val and val.startswith(cls + "@"):
            factories.append(n)
            print(f"[*] {cls}.{n}() 是实例工厂 -> {val}")
    for n in noarg:
        exprs = [f"{cls}.{n}()"] + [f"{cls}.{f}.{n}()" for f in factories]
        for expr in exprs:
            o = safe_cmd(child, f"print {expr}", timeout=10)
            val = core.parse_field(o)
            if val and not val.startswith(cls + "@"):
                record(results, f"invoke:{expr}", val)
                break


def run_dump_once(results):
    """单次提取：延迟断点等 HttpSecretKey 初始化，命中后 dump。"""
    proxy = core.Proxy()
    threading.Thread(target=proxy.start_and_serve, daemon=True).start()
    time.sleep(0.3)
    child = None
    try:
        print(f"[*] Using jdb: {core.JDB}")
        child = pexpect.spawn(
            f"{shlex.quote(core.JDB)} -attach 127.0.0.1:{core.PROXY_PORT}",
            timeout=60, encoding="utf-8")
        child.logfile = core.ScrubStream()

        for _ in range(50):
            if proxy.status in ("jdb_connected", "upstream_ready", "relaying"):
                break
            time.sleep(0.1)
        print("\n[*] jdb 已连上代理（阻塞在握手），现在启动 App ...")

        core.adb("shell", "am", "force-stop", core.APP)
        time.sleep(core._vt(0.5))
        started = core.adb("shell", "am", "start", "-D", "-n", core.ACTIVITY)
        for ln in started.splitlines():
            if ln.strip():
                print(f"    am start: {ln.strip()}")
        t0 = time.time()
        pid = None
        pid_deadline = time.time() + core._vt(45)
        while time.time() < pid_deadline:
            out = core.adb("shell", f"pidof {core.APP}").strip()
            if out and out.split()[0].isdigit():
                pid = out.split()[0]
                break
            time.sleep(0.03)
        if not pid:
            core._dump_device_diagnostics("未取到 App PID")
            raise core.Disconnected("未取到 App PID")
        print(f"[*] PID={pid} (t={time.time()-t0:.2f}s)，立即建立转发 ...")
        core.adb("forward", f"tcp:{core.UPSTREAM_PORT}", f"jdwp:{pid}")

        _jdwp_kick = {"p": None}

        def _refresh(p=pid):
            try:
                if _jdwp_kick["p"] is None or _jdwp_kick["p"].poll() is not None:
                    _jdwp_kick["p"] = subprocess.Popen(
                        [core.ADB, "jdwp"], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
            except Exception:
                pass
            core.adb("forward", f"tcp:{core.UPSTREAM_PORT}", f"jdwp:{p}")

        proxy.refresh_upstream = _refresh
        proxy.upstream_ready.set()

        deadline = time.time() + core._vt(int(os.environ.get(
            "LYNKCO_UPSTREAM_TIMEOUT", "60")))
        while not proxy.handshake_done.is_set():
            if proxy.upstream_failed.is_set():
                raise core.Disconnected("上游连接失败：App 进程已退出或 jdwp 未就绪")
            if time.time() > deadline:
                raise core.Disconnected("上游握手失败（可能错过早期窗口）")
            time.sleep(0.2)
        print("[+] JDWP 握手完成（命中早期窗口）！\n")

        try:
            child.expect(core.PROMPTS + [pexpect.EOF, pexpect.TIMEOUT],
                         timeout=core._vt(30))
        except Exception:
            pass

        print("\n[*] suspend")
        core.send_cmd(child, "suspend", timeout=core._vt(10))

        # 设延迟断点：HttpSecretKey 类加载初始化时命中
        print(f"\n[*] 设延迟断点: {TARGET_CLASS}.<clinit>")
        core.send_cmd(child, f"stop in {TARGET_CLASS}.<clinit>", timeout=core._vt(15))
        # 早期哨兵断点：密钥常量类 clinit 必先命中，证明断点链路可用
        key_cls = core.get_single_candidate()
        print(f"[*] 设哨兵断点: {key_cls}.<clinit>")
        core.send_cmd(child, f"stop in {key_cls}.<clinit>", timeout=core._vt(15))

        print("\n[*] resume")
        try:
            child.sendline("resume")
        except OSError as e:
            raise core.Disconnected(f"jdb 进程已退出（{e}）")

        # 第一阶段：等哨兵断点（密钥常量类 clinit，秒级）
        idx = child.expect(core.BREAKPOINT_PATTERNS + [pexpect.EOF, pexpect.TIMEOUT],
                           timeout=core._vt(90))
        if idx == len(core.BREAKPOINT_PATTERNS):
            raise core.Disconnected("等待哨兵断点期间 jdb 已退出（EOF）")
        if idx < len(core.BREAKPOINT_PATTERNS):
            print(f"\n[+] 哨兵断点命中（{key_cls} clinit），清除并放行 ...")
            time.sleep(0.2)
            try:
                child.expect(core.PROMPTS + [pexpect.TIMEOUT], timeout=5)
            except Exception:
                pass
            safe_cmd(child, f"clear {key_cls}.<clinit>", timeout=10)

        # 第二阶段：cont 放行，等 HttpSecretKey.<clinit> 命中
        print(f"\n[*] cont -> 等待 {TARGET_CLASS}.<clinit> 命中（超时 {TARGET_BP_TIMEOUT}s）...")
        child.sendline("cont")
        idx = child.expect(core.BREAKPOINT_PATTERNS + [pexpect.EOF, pexpect.TIMEOUT],
                           timeout=core._vt(TARGET_BP_TIMEOUT))
        if idx == len(core.BREAKPOINT_PATTERNS):
            raise core.Disconnected("等待目标断点期间 jdb 已退出（EOF）")
        if idx == len(core.BREAKPOINT_PATTERNS) + 1:
            # 超时未命中：类未加载（无网络请求？）——直接挂起碰运气
            print("\n[!] 目标断点超时未命中，suspend 后直接探测 ...")
            core.send_cmd(child, "suspend", timeout=core._vt(10))
        else:
            print(f"\n[+] 目标断点命中：{TARGET_CLASS}.<clinit>！")
            time.sleep(0.2)
            try:
                child.expect(core.PROMPTS + [pexpect.TIMEOUT], timeout=5)
            except Exception:
                pass
            # 单步几次让 clinit 里的赋值完成
            for i in range(8):
                print(f"[*] next (step {i + 1})")
                core.send_cmd(child, "next", timeout=core._vt(15))

        print(f"\n[*] ===== dump {TARGET_CLASS} =====")
        dump_class(child, TARGET_CLASS, results)

        print(f"\n[*] cont {POST_CLINIT_WAIT}s -> suspend -> 复取（密钥可能 clinit 后才 set）")
        child.sendline("cont")
        time.sleep(POST_CLINIT_WAIT)
        try:
            core.send_cmd(child, "suspend", timeout=core._vt(10))
            dump_class(child, TARGET_CLASS, results)
        except (core.Disconnected, Exception) as e:
            print(f"[!] 复取失败（{e}），保留已有结果")

        # 顺带探测其他 haohan 安全类（类此时应已加载）
        for cls in EXTRA_CLASSES:
            print(f"\n[*] ===== 探测 {cls} =====")
            dump_class(child, cls, results)

        return results
    finally:
        print("\n[*] Killing local jdb with SIGKILL (NOT quit) ...")
        if child is not None:
            try:
                child.kill(9)
            except Exception:
                pass
        proxy.close()
        try:
            core.adb("forward", "--remove", f"tcp:{core.UPSTREAM_PORT}")
        except Exception:
            pass


def main():
    if sys.platform != "darwin":
        sys.exit("[!] 本脚本为 macOS 本地版（复用 extract_appsecret_mac 入口逻辑）")
    results = _load_existing_results()
    core.ensure_pexpect()
    global pexpect
    import importlib
    pexpect = importlib.import_module("pexpect") if pexpect is None else pexpect

    core.setup(mac_entry.ensure_adb(), mac_entry.ensure_jdb())
    print(f"[*] adb: {core.ADB}")
    print(f"[*] jdb: {core.JDB}")
    mac_entry.ensure_device(sys.argv[1].strip() if len(sys.argv) > 1 else None)
    core.ensure_apk()

    for attempt in range(1, core.MAX_ATTEMPTS + 1):
        try:
            print(f"\n========== 第 {attempt}/{core.MAX_ATTEMPTS} 次尝试 ==========")
            run_dump_once(results)
            break
        except core.Disconnected as e:
            print(f"\n[!] 第 {attempt} 次尝试失败：{e}")
            if results:
                _save(results)
                print(f"[*] 已保留部分结果（{len(results)} 项），见 {OUT_FILE}")
            if attempt < core.MAX_ATTEMPTS:
                print("[*] 3 秒后自动重试 ...")
                time.sleep(3)

    _save(results)
    print("\n" + "=" * 60)
    print(f"[RESULT] 共提取 {len(results)} 个常量，已保存 {OUT_FILE}")
    for k, v in sorted(results.items()):
        print(f"  {k} = {v!r}")
    print("=" * 60)


if __name__ == "__main__":
    main()
