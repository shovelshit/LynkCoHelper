#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_gric_key.py —— GRIC X-SIGNATURE 密钥提取与回归验证（脱敏版）。

实现 GRIC X-SIGNATURE 密钥提取与回归校验流程，
两个子命令（均不硬编码任何密钥）：

  scan  在线提取：dump 设备 Java 堆 -> 三级降级找密钥 -> 复算验证（全部内置）
        python3 tools/extract_gric_key.py scan [--serial <SN>] [--pid <PID>]
                    [--max-mb 1200] [--har <capture.har>] [--write] [--show]

        验证优先级（复算逻辑写死在脚本内，无需外部步骤）：
          1. STS 现场自验证：密钥候选与签名同现场，HMAC 配对即实锤
             （需 App 已登录，心跳持续重签产生现场）；
          2. HAR 离线复算：按算法规格重建 STS 逐候选复算抓包签名
             （--har 未指定时自动发现仓库内最新 *.har；App 未登录也可用，
             密钥在 SDK 启动时即解密进配置对象，不依赖 STS 现场）。

        候选来源（按命中成本排序，逐级降级）：
          a. STS 现场后 4KB 窗口（32 可打印字符）
          b. 配置对象锚点：deviceModel ±2KB 窗口内的 32-hex
             （密钥与设备字段并列在同一配置对象，锚点与 App 版本无关）
          c. 全堆 32-hex 形态扫描（兜底，候选多但复算仍是本地零成本）

        --write   验证命中后自动写入 ../geely_env.json 的 gricSecret 字段
        --show    输出明文密钥（默认打码，防 CI 日志泄漏）

  har   离线回归：用已知密钥复算 HAR 里的全部签名请求，要求 100% 一致
        python3 tools/extract_gric_key.py har <capture.har> [--secret <KEY>]

        密钥来源优先级：--secret > 环境变量 GEELY_GRIC_SECRET > geely_env.json

  vehicle  在线/离线提取车辆头：dump 堆 -> 扫 x-vehicle-identifier/series 现场
        python3 tools/extract_gric_key.py vehicle [--serial <SN>] [--pid <PID>]
                    [--max-mb 1200] [--write] [--show]
        python3 tools/extract_gric_key.py vehicle --dump <heap.bin>   # 离线分析已有 dump

        --write  命中后写入 ../geely_env.json 的 vehicle 字段

        背景：x-vehicle-identifier 是 AES 加密的 VIN（密文 32 字节/44 字符 Base64，
        服务端会解密校验，传 VIN 明文会被拒），x-vehicle-series 是 Base64(车型代码)
        如 Base64("DCY11-A2")。二者均为登录/绑定后由 App 生成、长期稳定的值，
        在签名瞬间随 STS 一起以明文出现在堆中，可直接扫描提取。
        VIN/车型代码明文也可经 favorite-vehicles 接口（无需车辆头）获取，
        但明文无法在本地反推密文（AES key 为 App 内另一常量）。

前置条件（scan）：
  * root 且可直读 /proc/<pid>/mem 的环境（userdebug 模拟器）
  * App 已登录并挂前台（心跳 app/hb 持续重签，现场必然存在）
  * adb 在 PATH 或用 --serial 指定设备

原理：
  签名计算瞬间，(完整 STS, HMAC 密钥, 签名结果) 同时以明文存在于堆中。
  以 STS 第一行 accept-language: 为锚点提取，锚点后依次为
  签名 raw digest(byte[32]) -> 签名 Base64 -> 密钥(32 可打印字符)。
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, "..", "geely_env.json")

STS_ANCHOR = b"accept-language:"
# STS 内必须出现的行（自检锚点截取完整性）
STS_MUST_HAVE = (b"\nauthorization:", b"\nx-api-signature-nonce:", b"\nx-app-id:")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{43}=")
# 密钥候选：32 个可打印字符（经验上为十六进制小写）
KEY_RE = re.compile(rb"[!-~]{32}")
SCAN_WINDOW_AFTER_STS = 4096  # STS 结束后向后扫描多远找密钥/签名

# 密钥形态（实测口径）：32 个小写十六进制字符，前后不紧邻 hex 字符/连字符
HEX32_RE = re.compile(rb"(?<![0-9a-fA-F-])[0-9a-f]{32}(?![0-9a-fA-F-])")
# 配置对象锚点：密钥与 deviceModel/osVersion 等设备字段并列在同一配置对象里
# （锚点是模拟器镜像属性，与 App 版本无关，不受混淆更新影响）
CFG_ANCHORS = (b"sdk_gphone64_arm64", b"sdk_gphone64_x86_64", b"Android 13 (API 33)")
CFG_ANCHOR_WINDOW = 2048       # 锚点 ±2KB 窗口
HAR_ACCEPT_RATE = 0.9          # HAR 复算通过率阈值（≥90% 即采用）

# 车辆头提取：STS/header 现场中的 "x-vehicle-identifier:<value>" 行。
# 密文形态 = 32 字节 AES 密文的 Base64（43 字符 + '='）；
# series = Base64(车型代码)（如 DCY11-A2 -> RENZMTEtQTI=，长度不固定）。
VEH_IDENTIFIER_RE = re.compile(rb"x-vehicle-identifier:([A-Za-z0-9+/]{43}=)")
VEH_SERIES_RE = re.compile(rb"x-vehicle-series:([A-Za-z0-9+/]{8,42}={1,2})")
# 顺带收集 VIN 明文（17 位车架号，排除 I/O/Q）用于对照展示；
# 排除已知 17 字符静态常量（如 appId GEELYCNCH001M0001）免得误报
VIN_RE = re.compile(rb"\b[A-HJ-NPR-Z0-9]{17}\b")
VIN_EXCLUDE = {b"GEELYCNCH001M0001"}

PKG = os.environ.get("GEELY_PKG", "com.lynkco.customer")


def adb(*args, serial=None, binary=False, timeout=600):
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    out = subprocess.run(cmd, capture_output=True, timeout=timeout)
    data = out.stdout if binary else out.stdout.decode("utf-8", "replace")
    if out.returncode != 0 and not binary:
        print(f"[错误] {' '.join(cmd)} 失败: {out.stderr.decode('utf-8', 'replace')[:300]}")
    return data


# ---------------------------------------------------------------- scan ----

def _cmdline(serial, pid):
    try:
        return adb("shell", "cat", f"/proc/{pid}/cmdline", serial=serial)
    except Exception:
        return ""


def get_pid(serial):
    pids = adb("shell", "pidof", PKG, serial=serial).strip().split()
    if not pids:
        print(f"[错误] 未找到进程 {PKG}，请确认 App 已在前台运行")
        sys.exit(1)
    # 多进程 App（壳守护/沙盒子进程）：主进程 cmdline 恰为包名，
    # 子进程形如 pkg:web —— SDK 配置对象在主进程，优先返回主进程
    for pid in pids:
        cmd = _cmdline(serial, pid)
        if PKG in cmd and ":" not in cmd:
            return pid
    return pids[0]


def find_heap_regions(serial, pid, max_mb):
    """从 /proc/<pid>/maps 找 dalvik 主堆 RW 区域。"""
    maps = adb("shell", "cat", f"/proc/{pid}/maps", serial=serial)
    regions = []
    for line in maps.splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (rw\S*) \S+ \S+ \S+\s*(.*)", line)
        if not m:
            continue
        start, end, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4).strip()
        if "dalvik-main space" in name and perms.startswith("rw"):
            regions.append((start, end, name))
    if not regions:
        print("[错误] maps 中未找到 dalvik-main space RW 区域")
        sys.exit(1)
    total = sum(e - s for s, e, _ in regions)
    print(f"[*] 找到 {len(regions)} 个堆区域，共 {total / 1048576:.0f} MB：")
    for s, e, n in regions:
        print(f"    {s:#x}-{e:#x} ({(e - s) / 1048576:.0f} MB) {n}")
    if total / 1048576 > max_mb:
        print(f"[警告] 超过 --max-mb {max_mb}，按区域倒序只取前若干个（大区域优先）")
        kept, acc = [], 0
        for s, e, n in sorted(regions, key=lambda r: r[1] - r[0], reverse=True):
            if acc / 1048576 >= max_mb:
                break
            kept.append((s, e, n))
            acc += e - s
        regions = kept
    return regions


def dump_region(serial, pid, start, end):
    """流式拉取一段内存（exec-out 避免 shell tty 污染二进制）。"""
    size = end - start
    skip, cnt = start // 4096, size // 4096
    data = adb("exec-out",
               f"dd if=/proc/{pid}/mem bs=4096 skip={skip} count={cnt}",
               serial=serial, binary=True, timeout=1800)
    return data[:cnt * 4096]


def printable_run(data, off):
    """从 off 读连续可打印+\n 的段，返回 (bytes, end)。"""
    end = off
    n = len(data)
    while end < n and (32 <= data[end] < 127 or data[end] == 10):
        end += 1
    return data[off:end], end


def extract_sts_candidates(blob):
    """返回 [(sts_bytes, blob_offset)]。锚点=accept-language:，含完整性自检。"""
    out = []
    pos = 0
    while True:
        off = blob.find(STS_ANCHOR, pos)
        if off < 0:
            break
        pos = off + 1
        run, end = printable_run(blob, off)
        # 自检：必须是完整 STS（含 JWT 行、nonce、method、path）
        if all(must in run for must in STS_MUST_HAVE):
            lines = run.split(b"\n")
            if len(lines) >= 6 and lines[-2] in (b"POST", b"GET", b"PUT", b"DELETE"):
                out.append((run, off))
    return out


def find_candidates_after(blob, end):
    """STS 结束位置之后的小窗口内找 (b64 签名候选, 32 字符密钥候选)。"""
    window = blob[end:end + SCAN_WINDOW_AFTER_STS]
    sigs = [m.group(0) for m in B64_RE.finditer(window)]
    keys = []
    for m in KEY_RE.finditer(window):
        cand = m.group(0)
        # 排除误命中：纯 hex / 含 x- 头 / base64 段本身由调用方验证
        if cand.startswith(b"x-") or b":" in cand:
            continue
        keys.append(cand)
    return sigs, keys


def try_verify(sts, sig_b64, key):
    digest = hmac.new(key, sts, hashlib.sha256).digest()
    return base64.b64encode(digest) == sig_b64


def collect_cfg_anchor_candidates(blobs):
    """配置对象锚点扫描：锚点 ±2KB 窗口内的 32-hex 候选（带出现次数）。

    实测密钥在堆中与 deviceModel/deviceBrand/osVersion 并列在同一配置对象，
    以设备字段为锚可把全堆候选压缩约 50 倍（200 -> 个位数）。
    """
    counter = {}
    for blob in blobs:
        for anchor in CFG_ANCHORS:
            pos = 0
            while True:
                off = blob.find(anchor, pos)
                if off < 0:
                    break
                pos = off + 1
                lo = max(0, off - CFG_ANCHOR_WINDOW)
                hi = min(len(blob), off + CFG_ANCHOR_WINDOW)
                for m in HEX32_RE.finditer(blob, lo, hi):
                    counter[m.group(0)] = counter.get(m.group(0), 0) + 1
    return counter


def collect_hex_candidates(blobs):
    """全堆形态扫描（兜底）：全部唯一 32-hex 值。"""
    seen = set()
    for blob in blobs:
        for m in HEX32_RE.finditer(blob):
            seen.add(m.group(0))
    return seen


def discover_har(explicit):
    """定位离线复算用的 HAR：--har 指定 > 仓库内最新 *.har 自动发现。"""
    if explicit:
        if not os.path.exists(explicit):
            print(f"[错误] HAR 文件不存在: {explicit}")
            sys.exit(1)
        return explicit
    # 仓库两层根目录（LynkCoHelper/ 与 LynkCoHelper-master/）找最新的 .har
    roots = (os.path.dirname(HERE), os.path.dirname(os.path.dirname(HERE)))
    best = None
    for root in roots:
        if not os.path.isdir(root):
            continue
        for name in os.listdir(root):
            if name.lower().endswith(".har"):
                p = os.path.join(root, name)
                if best is None or os.path.getmtime(p) > os.path.getmtime(best):
                    best = p
    return best


def verify_candidates_with_har(candidates, har_path):
    """逐候选对 HAR 全部签名请求复算（STS 重建 + HMAC 内置，零线上请求）。

    返回 [(key, ok, total)] 按 ok 降序；采用阈值见 HAR_ACCEPT_RATE。
    """
    with open(har_path, "r", encoding="utf-8") as f:
        har = json.load(f)
    signed = []
    for entry in har.get("log", {}).get("entries", []):
        built = build_sts_from_har(entry)
        if built:
            signed.append(built)
    if not signed:
        print(f"[错误] {har_path} 中没有带 x-signature 的请求，无法离线复算")
        sys.exit(2)
    results = []
    for cand in candidates:
        key = cand.decode()
        ok = 0
        for sts, expect, _, _ in signed:
            digest = hmac.new(key.encode(), sts.encode(), hashlib.sha256).digest()
            if base64.b64encode(digest).decode() == expect:
                ok += 1
        results.append((cand, ok, len(signed)))
    results.sort(key=lambda r: -r[1])
    return results


def _report_and_write(key, note, args):
    shown = key.decode() if not args.mask else \
        f"{key[:6].decode()}******{key[-4:].decode()}"
    print(f"\n[★] 密钥命中：{shown}")
    print(f"    验证方式：{note}")
    if args.write:
        write_env_secret(key.decode())


def cmd_scan(args):
    blobs = []
    if getattr(args, "heap_file", None):
        # 离线模式：分析已 dump 的堆快照文件（App 崩溃后仍可扫，
        # 快照由 extract_gric_auto.py 在等待期间持续抓取）
        for path in args.heap_file:
            with open(path, "rb") as f:
                blob = f.read()
            blobs.append(blob)
            print(f"[*] 堆快照 {path}: {len(blob) / 1048576:.0f} MB")
        sts_hits = []
        for blob in blobs:
            for sts, off in extract_sts_candidates(blob):
                sts_hits.append((sts, off, blob, off + len(sts)))
        print(f"[*] 离线模式：{len(blobs)} 个快照，累计 STS 现场 {len(sts_hits)} 处")
    else:
        pid = args.pid or get_pid(args.serial)
        print(f"[*] PID = {pid}（{PKG}），App 保持前台")
        regions = find_heap_regions(args.serial, pid, args.max_mb)

        sts_hits = []
        for start, end, name in regions:
            print(f"[*] dump {start:#x}-{end:#x} ...")
            try:
                blob = dump_region(args.serial, pid, start, end)
            except subprocess.TimeoutExpired:
                print("[警告] 该区域 dump 超时，跳过")
                continue
            if not blob:
                print("[警告] 该区域读取为空（可能已被回收/反保护），跳过")
                continue
            blobs.append(blob)
            for sts, off in extract_sts_candidates(blob):
                sts_hits.append((sts, start + off, blob, off + len(sts)))
            print(f"    {len(blob) / 1048576:.0f} MB，累计 STS 现场 {len(sts_hits)} 处")

    # ---- 验证优先级 1：STS 现场自验证（密钥与签名同现场，HMAC 配对即实锤） ----
    if sts_hits:
        verified = set()
        for sts, addr, blob, end in sts_hits:
            sigs, keys = find_candidates_after(blob, end)
            for sig in sigs:
                for key in keys:
                    if try_verify(sts, sig, key):
                        verified.add(key)
        if verified:
            # 跨现场交叉验证（同一候选能对上多个现场的签名，防巧合）
            cross = {key: 0 for key in verified}
            for sts, addr, blob, end in sts_hits:
                sigs, keys = find_candidates_after(blob, end)
                for sig in sigs:
                    for key in verified:
                        if try_verify(sts, sig, key):
                            cross[key] += 1
            best = max(cross.items(), key=lambda kv: kv[1])
            _report_and_write(best[0],
                              f"STS 现场配对（跨 {best[1]}/{len(sts_hits)} 个签名现场）",
                              args)
            return
        print(f"[*] {len(sts_hits)} 个 STS 现场自验证未命中，转入候选复算 ...")
    else:
        print("[*] 无 STS 现场（App 未登录也可提取：密钥在 SDK 启动时已解密进配置对象）")

    # ---- 验证优先级 2：候选密钥 × HAR 离线复算（STS 重建 + HMAC 内置） ----
    # 候选来源按成本升序逐级降级，任一级复算达标即采用
    sts_window_keys = set()
    for sts, addr, blob, end in sts_hits:
        _, keys = find_candidates_after(blob, end)
        sts_window_keys.update(keys)
    tier_sources = [
        ("STS 现场后 4KB 窗口", {k: 1 for k in sts_window_keys}),
        ("配置对象锚点（deviceModel ±2KB 窗口）", collect_cfg_anchor_candidates(blobs)),
        ("全堆 32-hex 形态扫描", {k: 1 for k in collect_hex_candidates(blobs)}),
    ]
    # 候选清单落盘（无 HAR/未命中时仍产出，供本地 har 子命令事后复算）
    if args.candidates:
        payload = {
            "stsHits": len(sts_hits),
            "tiers": [
                {"name": name,
                 "count": len(counter),
                 "candidates": {k.decode(): c for k, c in counter.items()}}
                for name, counter in tier_sources
            ],
        }
        with open(args.candidates, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[*] 候选清单已写入 {args.candidates}")

    har_path = discover_har(args.har)
    if not har_path:
        print("[错误] 现场自验证未命中且未找到 HAR。两种解法：")
        print("  1) 加 --har <capture.har>（任一次抓包，含 x-signature 请求即可）离线复算候选；")
        print("  2) App 登录后挂前台 30s（心跳重签产生 STS 现场）再重跑。")
        sys.exit(3)
    print(f"[*] 离线复算 HAR：{har_path}")

    for tier_name, counter in tier_sources:
        if not counter:
            continue
        cands = list(counter)
        print(f"[*] 候选来源「{tier_name}」：{len(cands)} 个，逐候选复算 ...")
        results = verify_candidates_with_har(cands, har_path)
        key, ok, total = results[0]
        if ok >= total * HAR_ACCEPT_RATE:
            _report_and_write(key, f"HAR 离线复算 {ok}/{total}"
                                   f"（{ok * 100 // total}%，{har_path}）", args)
            return
        for k, o, t in results[:3]:
            shown = k.decode() if not args.mask else \
                f"{k[:6].decode()}******{k[-4:].decode()}"
            print(f"    最佳候选 {shown}: {o}/{t}")

    print(f"\n[未命中] 全部候选复算未达 {int(HAR_ACCEPT_RATE * 100)}%。可能原因：")
    print("  1) HAR 是密钥轮换前的旧抓包（新密钥验不过旧签名）——用当前版本 App 重新抓一份；")
    print("  2) 密钥形态不再是 32-hex（v2.2+ 算法升级）——人工检查 STS 现场/配置对象邻域；")
    print("  3) 堆 dump 不含密钥（SDK 未初始化）——确认 App 进程已跑完启动流程。")
    sys.exit(3)


def write_env_secret(secret):
    data = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    data["gricSecret"] = secret
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[*] 已写入 {ENV_FILE} 的 gricSecret 字段（该文件在 .gitignore 中，不会提交）")


# ------------------------------------------------------------- vehicle ----

def _decode_series(series_b64: bytes) -> str:
    """series 是 Base64(车型代码)，解码失败返回 '?'。"""
    try:
        raw = base64.b64decode(series_b64, validate=True)
        return raw.decode("ascii")
    except Exception:
        return "?"


def cmd_vehicle(args):
    """dump 堆（或读 --dump 离线文件）扫描车辆头现场。"""
    ident_count, series_count, vin_count = {}, {}, {}

    def scan_blob(blob):
        for m in VEH_IDENTIFIER_RE.finditer(blob):
            ident_count[m.group(1)] = ident_count.get(m.group(1), 0) + 1
        for m in VEH_SERIES_RE.finditer(blob):
            series_count[m.group(1)] = series_count.get(m.group(1), 0) + 1
        for m in VIN_RE.finditer(blob):
            if m.group(0) not in VIN_EXCLUDE:
                vin_count[m.group(0)] = vin_count.get(m.group(0), 0) + 1

    if args.dump:
        print(f"[*] 离线模式：读取 {args.dump} ...")
        with open(args.dump, "rb") as f:
            scan_blob(f.read())
    else:
        pid = args.pid or get_pid(args.serial)
        print(f"[*] PID = {pid}（{PKG}），App 保持前台（心跳持续重签，现场必然存在）")
        regions = find_heap_regions(args.serial, pid, args.max_mb)
        for start, end, name in regions:
            print(f"[*] dump {start:#x}-{end:#x} ...")
            try:
                blob = dump_region(args.serial, pid, start, end)
            except subprocess.TimeoutExpired:
                print("[警告] 该区域 dump 超时，跳过")
                continue
            if not blob:
                print("[警告] 该区域读取为空（可能已被回收/反保护），跳过")
                continue
            scan_blob(blob)
            print(f"    {len(blob) / 1048576:.0f} MB 扫描完成")

    if not ident_count:
        print("[错误] 未找到 x-vehicle-identifier 密文现场。排查：1) App 是否前台且已登录；"
              "2) 心跳/车辆接口是否在跑（等 30s 重试）；3) 堆区域是否被 --max-mb 截掉")
        sys.exit(2)

    best_ident = max(ident_count.items(), key=lambda kv: kv[1])
    best_series = max(series_count.items(), key=lambda kv: kv[1]) if series_count else (None, 0)

    def mask(s):
        return f"{s[:6]}******{s[-4:]}" if args.mask else s

    print(f"\n[★] x-vehicle-identifier（AES 密文，出现 {best_ident[1]} 次）：")
    print(f"    {mask(best_ident[0].decode())}")
    if best_series[0]:
        decoded = _decode_series(best_series[0])
        print(f"[★] x-vehicle-series（Base64(车型代码)，出现 {best_series[1]} 次）：")
        print(f"    {mask(best_series[0].decode())}  ->  车型代码 {decoded}")
    if vin_count:
        top_vin = max(vin_count.items(), key=lambda kv: kv[1])
        print(f"[i] 堆中 VIN 明文（对照用，出现 {top_vin[1]} 次）：{top_vin[0].decode()}")
    if len(ident_count) > 1:
        print(f"[警告] identifier 候选有 {len(ident_count)} 个（多车账号？），按频次取最高，")
        print("       其余候选：")
        for cand, n in sorted(ident_count.items(), key=lambda kv: -kv[1])[1:]:
            print(f"         {mask(cand.decode())} ({n} 次)")

    if args.write:
        data = {}
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        veh = data.get("vehicle", {})
        veh["identifier"] = best_ident[0].decode()
        if best_series[0]:
            veh["series"] = best_series[0].decode()
        veh.setdefault("brand", "LYNKCO")
        data["vehicle"] = veh
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[*] 已写入 {ENV_FILE} 的 vehicle 字段（该文件在 .gitignore 中，不会提交）")


# ----------------------------------------------------------------- har ----

def load_secret(cli_secret):
    if cli_secret:
        return cli_secret
    if os.environ.get("GEELY_GRIC_SECRET"):
        return os.environ["GEELY_GRIC_SECRET"]
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            v = json.load(f).get("gricSecret")
            if v:
                return v
    print("[错误] 未提供密钥：用 --secret、环境变量 GEELY_GRIC_SECRET 或 geely_env.json")
    sys.exit(1)


def build_sts_from_har(entry):
    """按算法规格从 HAR 条目重建 STS；返回 (sts, method, path) 或 None。"""
    req = entry.get("request", {})
    headers = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
    if "x-signature" not in headers:
        return None
    url = req.get("url", "")
    after_scheme = url.partition("://")[2]
    path_and_q = after_scheme.split("/", 1)[1] if "/" in after_scheme else ""
    path = "/" + path_and_q
    path, _, query = path.partition("?")
    method = req.get("method", "GET").upper()

    lines = []
    for name in ("accept-language", "authorization"):
        if headers.get(name):
            lines.append(f"{name}:{headers[name]}")
    for k in sorted(k for k in headers if k.startswith("x-") and k != "x-signature"):
        lines.append(f"{k}:{headers[k]}")
    body = (req.get("postData") or {}).get("text", "")
    if body:
        lines.append(base64.b64encode(hashlib.md5(body.encode()).digest()).decode())
    if query:
        lines.append(query)
    lines.append(method)
    lines.append(path)
    return "\n".join(lines), headers["x-signature"], method, path


def cmd_har(args):
    secret = load_secret(args.secret)
    with open(args.har, "r", encoding="utf-8") as f:
        har = json.load(f)
    entries = har.get("log", {}).get("entries", [])
    total = ok = 0
    fails = []
    for i, entry in enumerate(entries):
        built = build_sts_from_har(entry)
        if not built:
            continue
        sts, expect, method, path = built
        total += 1
        got = base64.b64encode(hmac.new(secret.encode(), sts.encode(), hashlib.sha256).digest()).decode()
        if got == expect:
            ok += 1
        else:
            fails.append((i, method, path))
    print(f"[*] 签名请求共 {total} 个，复算一致 {ok} 个")
    for i, m, p in fails:
        print(f"    ✗ entry#{i} {m} {p}")
    if total == 0:
        print("[错误] HAR 中没有带 x-signature 的请求")
        sys.exit(2)
    if ok == total:
        print("[✓] 100% 一致，密钥与 STS 规则确认")
        return
    print(f"[✗] {total - ok} 个不一致：密钥错误或 STS 规则已变化（不可采用该候选）")
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="GRIC X-SIGNATURE 密钥提取与回归验证（脱敏）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="在线提取：dump 堆 -> 扫 STS -> 验证密钥")
    p_scan.add_argument("--serial", default=None, help="adb 设备序列号（默认取唯一设备）")
    p_scan.add_argument("--pid", type=int, default=None, help="目标进程 PID（默认 pidof 自动获取）")
    p_scan.add_argument("--max-mb", type=int, default=1200, help="最多 dump 多少 MB 堆")
    p_scan.add_argument("--heap-file", action="append", default=None, metavar="FILE",
                        help="离线模式：分析已有的堆快照文件（可重复，跳过活进程 dump；"
                             "App 崩溃后用快照扫）")
    p_scan.add_argument("--har", default=None,
                        help="离线复算用的 HAR 文件（默认自动发现仓库内最新 *.har）")
    p_scan.add_argument("--candidates", default=None, metavar="JSON",
                        help="把各层级候选密钥写入 JSON 文件（CI 产物/本地事后复算用）")
    p_scan.add_argument("--write", action="store_true", help="命中后写入 geely_env.json")
    p_scan.add_argument("--show", dest="mask", action="store_false",
                        help="输出明文密钥（默认打码）")
    p_scan.set_defaults(func=cmd_scan)

    p_har = sub.add_parser("har", help="离线回归：复算 HAR 全部签名（要求 100%%）")
    p_har.add_argument("har", help="HAR 文件路径")
    p_har.add_argument("--secret", default=None, help="HMAC 密钥（默认读环境变量/geely_env.json）")
    p_har.set_defaults(func=cmd_har)

    p_veh = sub.add_parser("vehicle", help="提取车辆头 identifier/series（在线 dump 或离线 dump 文件）")
    p_veh.add_argument("--serial", default=None, help="adb 设备序列号（默认取唯一设备）")
    p_veh.add_argument("--pid", type=int, default=None, help="目标进程 PID（默认 pidof 自动获取）")
    p_veh.add_argument("--max-mb", type=int, default=1200, help="最多 dump 多少 MB 堆")
    p_veh.add_argument("--dump", default=None, help="离线模式：分析已有的堆 dump 文件")
    p_veh.add_argument("--write", action="store_true", help="命中后写入 geely_env.json 的 vehicle 字段")
    p_veh.add_argument("--show", dest="mask", action="store_false",
                       help="输出明文（默认打码）")
    p_veh.set_defaults(func=cmd_vehicle)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
