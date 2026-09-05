# 领克 App 原生签名密钥（AppKey / AppSecret）逆向提取记录

本文档记录 `lynkco_common.py` 中 `NATIVE_APP_KEY` / `NATIVE_APP_SECRET`
两个常量的来源、提取方法与验证过程，供密钥失效后重新提取时参考。

> 密钥明文不在本文档展示（用 `<REDACTED_APP_KEY>` / `<REDACTED_APP_SECRET>`
> 占位），实际值在 `lynkco_common.py` 的默认常量中（支持环境变量
> `LYNKCO_NATIVE_APP_KEY` / `LYNKCO_NATIVE_APP_SECRET` 覆盖，详见该文件顶部
> 注释与 `readme.md`）。

用途：为 App 原生 SDK 访问 `app-services.lynkco.com.cn` 网关（阿里云 API 网关）
的 `/auth/login/refresh`（refreshToken 换取新 token）接口生成
`x-ca-signature` 签名，实现自动续期，见 `lynkco_common.py` 的
`build_native_signature()` 和 `lynkco_login.py` 的 `refresh_token()`。

> **速查入口**：密钥失效后只想重新提取、不想读原理分析的，直接跳到
> **第 7 节**——一条命令完成提取（仅需一次性创建模拟器并装入 App）。

---

## 1. 背景：为什么不能靠静态反编译直接拿到明文

App 包名 `com.lynkco.customer`，代码中密钥调用链如下：

```
LynkCoModuleInitializer.initInProcess()
  -> SWXKitCore.setAliCloudAppKey(str2, str3)      // str2 = g.b, str3 = g.c
  -> SWFramworkKitCore.setAliCloudGateWay(str2, str3)

com.safe.cons.LynkCoConstants$g   (静态初始化块)
  static { b = v(); c = w(); d = H(); e = I(); ... }
  v() -> release 分支: com.safe.cons.b.w().l()   // -> b 字段 = APP_KEY  (x-ca-key)
  w() -> release 分支: com.safe.cons.b.w().p()   // -> c 字段 = APP_SECRET

com.safe.cons.b（com/safe/cons/b.java）全部方法均标注 @LDPProtect、均为
native 方法，无 Java 实现：
  public native String l();   // APP_KEY
  public native String p();   // APP_SECRET
```

`@LDPProtect` 由白盒加密/VMP 壳 SDK 在运行时动态实现，**密钥明文只在这些
native 方法被调用执行的运行时瞬间存在于内存中**，无法通过反编译 dex、扫描
字符串常量池等静态手段获取，必须走动态调试路线截获返回值。

## 2. 尝试过但失败/放弃的路线

| 方案 | 结果 |
|---|---|
| Frida hook `com.safe.cons.b.l()/p()` | App 检测到 frida-server 进程存在（即使未 attach）就会自杀退出 |
| IDA Pro `android_server` native attach 直接下断点 | 连接稳定建立后几秒内即被反调试逻辑发现并自杀；精细控制挂起时机仍未能抢在检测窗口之前 |
| 对 native 方法本体直接下断点（JDWP / jdb） | JDI 报错 `"Cannot set breakpoints on native methods"`——ART/JVM 硬限制，非权限问题 |

关键教训：**只要 App 有机会跑完自己的反调试/自杀检测逻辑，进程就会被杀掉**，
必须在检测逻辑执行之前完成挂起/拦截。

## 3. 前置条件：系统镜像必须是 `userdebug`/`eng`（与 root、App 自身 debuggable 无关）

```bash
adb shell dumpsys package com.lynkco.customer | grep -i pkgFlags
# 没有 DEBUGGABLE 标志，说明 App 本身不是 debuggable 构建

adb shell run-as com.lynkco.customer id
# run-as: package not debuggable      <- 进一步印证 App 级 debuggable=false

adb shell getprop ro.debuggable   # 1
adb shell getprop ro.build.type   # userdebug
```

- App 级 `android:debuggable`：领克 App 官方正式包是 `false`（Release 构建），
  `run-as` 直接拒绝，这条路走不通。
- 系统级 `ro.debuggable` 才是关键：只要系统固件是 `userdebug`/`eng`（AVD 模拟器、
  部分厂商工程机默认如此），`adbd` 就能无视 App 自身 debuggable 标志，允许
  `am start -D` 强制让任意 App 进程挂起等待调试器、并开放 JDWP 端口。
- 零售版真机（`ro.build.type=user`）：**无论是否 root 都无法使用**本方案（`am
  start -D` 后 JDWP 端口不会开放）。若确需重新提取密钥，可选 AVD 模拟器（本文档
  采用的方式）或 `userdebug`/`eng` 固件的工程机。

### 3.1 本文档实测使用的具体环境版本

以下版本组合已验证可稳定复现（并非唯一可行版本，仅供参考对齐；核心要求
仍是第 3 节所述的 `userdebug`/`eng` 固件）：

| 组件 | 版本 |
|---|---|
| 宿主机 OS | macOS 26.5.1（arm64） |
| Android Emulator | 36.6.11.0 |
| AVD 镜像 | `android-33`（Android 13 / API 33），`google_apis`，`arm64-v8a` |
| 领克 App 安装包 | `com.lynkco.customer`（Release 正式包，`debuggable=false`） |
| Python | 3.9.6 |
| pexpect | 4.9.0（`pip install pexpect`） |
| JDK（提供 `jdb`） | OpenJDK 1.8.0（Corretto 8），`jdb` 协议版本 1.8 |
| Android SDK 位置 | `$HOME/Library/Android/sdk`（`platform-tools`/`emulator` 需在 `PATH` 中） |

> **2026-08-25 二次复现补充**：Android Emulator 升级到 37.1.11.0、宿主机 macOS
> 26.6 同样可复现；Corretto 8 若因 Homebrew Cask 需要 sudo 装不上，可
> `brew fetch --cask corretto@8` 下载 pkg 后用 `xar -xf` + `cat Payload |
> gunzip -dc | cpio -idmu` 手动解包到用户级目录
> `~/Library/Java/JavaVirtualMachines/amazon-corretto-8.jdk`（免 sudo，jdb
> 1.8 验证可用）。此外本次复现发现三个与版本无关的平台级新坑，见第 4.5 节——
> **其中坑 2/3 会导致 4.3 节的直连流程跑不通，实际操作请优先走 4.5 节的代理方案**。

## 4. 最终成功路线：`am start -D` + `jdb`（JDWP）在 Java 层断点静态初始化块

### 4.1 思路

1. 用 `adb shell am start -D -n <component>` 以"等待调试器"状态启动 App，此时
   进程会阻塞在等待 JDWP 客户端连接这一步，App 自身代码（包括反调试检测逻辑）
   尚未开始执行，是一个天然的早期挂起点。
2. 用 JDK 自带的 `jdb` 通过 `adb forward tcp:8700 jdwp:<pid>` 建立端口转发后
   连接。JDWP 是 Java 标准协议，可直接对 Java 方法下断点、查看局部变量/静态
   字段，无需涉及 native 层的 ArtMethod 内存结构。
3. 因 native 方法本体不能下断点，改为在**调用方**——
   `com.safe.cons.LynkCoConstants$g` 类的静态初始化块 `<clinit>`——下断点
   （`stop in com.safe.cons.LynkCoConstants$g.<clinit>`），命中后单步执行完
   `static { b = v(); c = w(); ... }`，再 `print` 打印静态字段 `b`/`c`/`d`/`e`。

### 4.2 关键坑与规避方式

- `adb jdwp` 命令会一直阻塞，需后台短暂运行再杀掉获取一次输出（`(adb jdwp
  &) ; sleep 1.5; pkill -f "adb jdwp"`），不能直接阻塞式调用。
- **jdb 必须交互式驱动**：非交互模式（`jdb -attach 8700 < commands.txt`）stdin
  关闭会导致 jdb 直接退出、等不到断点命中，必须用 `expect`/Python `pexpect`
  逐条发送命令并等待响应后再发下一条（一次性批量 `send()` 多条命令也不可靠，
  目标线程还未恢复到挂起态时发送的命令会被丢弃并回显"未挂起任何对象"）。
- `<clinit>` 断点只能命中一次：静态初始化块只执行一次，若连接晚了（类已
  初始化完）只能重启 App（`am force-stop` + `am start -D`）重新来过。
- **不能发送 `quit` 让 jdb 正常断开**：jdb 走正常 "VM Dispose" 流程会让 App 检测到
  调试器连接状态变化并触发自杀重启。**正确做法：直接 `kill -9` 强杀本地 jdb
  客户端进程**，让 TCP 连接异常中断，App 端无感知，进程可继续存活。
- **单步次数越多耗时越长，越容易触发自杀重启**：实测 30 次 `next` 逐条发送（每步
  `sleep 0.2s`）执行到第 14 步左右即触发自杀断开重连。**规避方式：每单步一次即立
  `print` 探测目标字段是否已赋值，命中立即停止**，无需固定次数跑完整个初始化
  块。实测仅需 2 次 `next` 即可命中，大幅压缩暴露在调试状态下的时间窗口。
- jdb 的断点命中提示可能是中文"断点命中"也可能是英文 `"Breakpoint hit"`，驱动
  脚本的匹配逻辑需同时兼容两种输出。

### 4.3 实际操作步骤（可复现）

```bash
# 0. 环境准备（若无现成设备，先启动 AVD 模拟器，天然 userdebug）
export ANDROID_HOME="$HOME/Library/Android/sdk"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
emulator -avd <avd_name> -no-snapshot-load &
adb wait-for-device

# 1. 以等待调试器状态启动 App
adb shell "am force-stop com.lynkco.customer"
adb shell "am start -D -n com.lynkco.customer/com.geely.lynkco.main.activity.LynkCoEntranceActivity"
NEWPID=$(adb shell "pidof com.lynkco.customer")

# 2. 建立 JDWP 端口转发
adb forward tcp:8700 jdwp:$NEWPID

# 3. 用 pexpect 驱动 jdb：连接 -> 下断点 -> run -> 命中后逐步 next
#    （每步探测字段是否已赋值，命中即停）-> 打印 b/c/d/e -> kill -9 本地 jdb
python3 drive_jdb.py
adb forward --remove tcp:8700
```

> ⚠️ **注意**：以上"先 `am start -D` 挂起、再手动跑脚本"的直连流程依赖
> "App 阻塞在 waitForDebugger 时 JDWP 仍可握手"这一前提。2026-08-25 复现实测
> 该前提**不再成立**（App 一旦进入 waitForDebugger 阻塞态，JDWP 握手即挂死），
> 直连流程会一直卡在 "Waiting For Debugger" 弹窗。**实际操作请直接使用
> 4.5 节的本地 TCP 代理方案**（`tools/extract_appsecret.py`），保留本节仅作原理说明。

对应的 `jdb` 交互命令序列（注意每条命令都要等上一条的提示符返回后再发送）：

```
jdb -attach 8700
stop in com.safe.cons.LynkCoConstants$g.<clinit>
run
# ... 等待 "Breakpoint hit" / "断点命中" ...
next                                          # 单步一次
print com.safe.cons.LynkCoConstants$g.c       # 探测 c 是否已赋值，仍为空值则继续 next
# ... 重复 next + print 探测，直到 c 不再是"空值" ...
print com.safe.cons.LynkCoConstants$g.b
print com.safe.cons.LynkCoConstants$g.c
print com.safe.cons.LynkCoConstants$g.d
print com.safe.cons.LynkCoConstants$g.e
# 不发 quit！直接在本地 kill -9 这个 jdb 进程
```

`drive_jdb.py`（`pexpect`）实现思路：连接后下断点并 `run`，匹配中英文两种
断点提示；循环执行 `next` + `print com...c` 探测，一旦返回值不再是空值就
`break` 跳出循环；最后依次打印 b/c/d/e 四个字段，并用 `child.kill(9)`（而非
发送 `quit`）结束本地 jdb 进程。

完整可复现代码如下（**注意**：`EMPTY_VALUES` 必须包含中文 `"空值"`——jdb 在
字段尚未赋值时会打印 `= 空值` 而非英文 `null`，漏判会导致探测循环提前误判
为"已赋值"而过早退出，实测因这个坑多走了一轮完整流程才定位到）：

```python
#!/usr/bin/env python3
"""
按照 docs/AppSecret_逆向分析记录.md 第4节流程，
通过 jdb (JDWP) 在 com.safe.cons.LynkCoConstants$g.<clinit> 下断点，
单步执行后提取 b/c/d/e 四个静态字段明文值。

用法: python3 drive_jdb.py [jdb端口，默认8700]

注意：
- 本脚本仅在本地临时使用，提取完成后应删除，密钥不应写入代码仓库。
- 结束时必须 kill -9 本地 jdb 进程，不能发送 quit（会触发 App 自杀重启）。
"""
import sys
import time

import pexpect

PORT = sys.argv[1] if len(sys.argv) > 1 else "8700"
CLASS = "com.safe.cons.LynkCoConstants$g"

BREAKPOINT_PATTERNS = [
    "Breakpoint hit",
    "断点命中",
]

# jdb 在字段未赋值时可能打印中文"空值"或英文 null，两者都要识别为"未就绪"
EMPTY_VALUES = {"null", '""', "", "= null", "空值"}


def send_cmd(child, cmd, timeout=15):
    child.sendline(cmd)
    time.sleep(0.3)
    try:
        child.expect(["> ", pexpect.TIMEOUT], timeout=timeout)
    except Exception:
        pass
    return child.before


def main():
    print(f"[*] Connecting jdb -attach {PORT} ...")
    child = pexpect.spawn(f"jdb -attach {PORT}", timeout=30, encoding="utf-8")
    child.logfile = sys.stdout  # 实时打印交互过程，便于观察

    child.expect(["> ", pexpect.EOF, pexpect.TIMEOUT], timeout=30)

    print(f"\n[*] Setting breakpoint at {CLASS}.<clinit> ...")
    send_cmd(child, f"stop in {CLASS}.<clinit>")

    print("\n[*] run")
    child.sendline("run")

    idx = child.expect(BREAKPOINT_PATTERNS + [pexpect.EOF, pexpect.TIMEOUT], timeout=60)
    if idx >= len(BREAKPOINT_PATTERNS):
        print("[!] 未命中断点（超时/EOF），退出")
        child.kill(9)
        return
    print("\n[+] Breakpoint hit!")
    time.sleep(0.2)
    try:
        child.expect(["> ", pexpect.TIMEOUT], timeout=5)
    except Exception:
        pass

    max_steps = 15
    hit = False
    for i in range(max_steps):
        print(f"\n[*] next (step {i + 1})")
        send_cmd(child, "next", timeout=15)

        out = send_cmd(child, f"print {CLASS}.c", timeout=10)
        val_line = [l for l in out.splitlines() if "=" in l]
        val = val_line[-1].split("=", 1)[-1].strip() if val_line else ""
        print(f"    -> c probe: {val!r}")
        if val and val not in EMPTY_VALUES:
            hit = True
            break

    if not hit:
        print("[!] 单步次数用尽仍未探测到 c 字段赋值，可能命中太晚或结构变化")

    print("\n[*] Dumping fields b/c/d/e ...")
    results = {}
    for field in ["b", "c", "d", "e"]:
        out = send_cmd(child, f"print {CLASS}.{field}", timeout=10)
        results[field] = out

    print("\n" + "=" * 60)
    print("[RESULT]")
    for field, out in results.items():
        print(f"--- {field} raw output ---")
        print(out)
    print("=" * 60)

    print("\n[*] Done. Killing local jdb process with SIGKILL (NOT quit) ...")
    child.kill(9)


if __name__ == "__main__":
    main()
```

运行方式（承接 4.3 节第 2 步已建立的端口转发）：

```bash
pip install pexpect   # 若未安装
python3 drive_jdb.py 8700
```

实测：仅 2 次 `next` 即探测到 `c` 字段非空，`b`/`c` 两个字段打印结果与
`env.json` 中已保存的 `nativeAppKey`/`nativeAppSecret` **完全一致**，全程未
触发反调试自杀，再次验证了方法与脚本的可复现性。

### 4.4 捕获结果

单步执行 `<clinit>` 过程中完整捕获到四个静态字段的明文值：

```
b = "<REDACTED_APP_KEY>"      <- v() 结果 = APP_KEY (x-ca-key)
c = "<REDACTED_APP_SECRET>"   <- w() 结果 = APP_SECRET
d/e                          <- 另一套日志上报用的 APP_KEY/APP_SECRET，非本次目标
```

`b` 字段的值与此前长时间真实抓包记录中观察到的 `x-ca-key` 请求头值**完全一致**，
从未变化过，证明断点位置正确，`c` 字段就是目标 `appSecret` 明文。

> **多次复现验证**：按上述流程在同一台 AVD 上重新跑过多遍，仅需 2 次
> `next` 即命中 `b`/`c` 赋值，全程未触发自杀。每次提取到的值均与当时 `env.json`
> 中已保存的 `nativeAppKey`/`nativeAppSecret` **完全一致**，交叉验证了本文档方法
> 的可复现性与准确性。

### 4.5 2026-08-25 二次复现发现的三个新坑与本地 TCP 代理方案

在另一台 mac（macOS 26.6 / Emulator 37.1.11.0 / 同款 android-33 arm64-v8a 镜像）
上复现时，4.3 节的直连流程**完全跑不通**——App 一直卡在 "Waiting For Debugger"
弹窗，jdb 连上后无任何输出直至挂死。逐层排查（原始 socket 探测 JDWP 握手、
系统应用对照实验、`adb root`、重启 adb server）后定位到三个此前未记载的坑：

**坑 1：模拟器从快照恢复（snapshot-load）会让 adbd 的 jdwp 转发永久挂死。**
表现为：所有进程（包括 Settings 等系统应用）的 `adb forward tcp:N jdwp:<pid>`
都能建立 TCP 连接，但发送 `JDWP-Handshake` 后永远收不到回显；`adb kill-server`
/ `adb root` 重启 adbd 均无效。**唯一解法：`-no-snapshot-load -no-snapshot-save`
冷启动模拟器**（本文档 4.3 节第 0 步其实一直带着该参数，但之前没意识到它是
硬性前提，不是可选项）。

**坑 2：即使冷启动，App 一旦真正进入 waitForDebugger 阻塞态，JDWP 握手也会挂死。**
这是最反直觉的一条：通过竞速实验实测——从 `am start -D` 后轮询到 PID 出现，
**在进程 fork 后约 0.5 秒内（尚未执行到 `waitForDebugger` 的早期窗口）立即发起
JDWP 握手可以成功**；超过这个窗口、App 挂起等待调试器之后，握手永久超时。
对照实验证实连 Settings（毫无反调试的系统应用）也如此，说明这是平台级行为
（adbd jdwp 服务 + `am start -D` 挂起态的交互问题），**不是领克 App 的对抗**。
这正是 4.3 节直连流程跑不通的根因：人工敲命令的速度永远赶不上 0.5 秒窗口。

**坑 3：jdb 是 JVM，冷启动需 1-3 秒，来不及在窗口期内发起握手。**
即使把 `am start -D` 与 `jdb -attach` 写进同一个脚本无脑抢跑，jdb 也赶不上。

**解法：本地 TCP 代理抢跑方案（`tools/extract_appsecret.py`，本次实际成功路线）。**

```
代理监听 8700 -> jdb 先连代理并阻塞在握手阶段（jdb 启动慢不再是问题）
  -> am start -D 启动 App -> 高频轮询 pidof（30ms 间隔）
  -> PID 出现瞬间 adb forward tcp:8701 jdwp:<pid>
  -> 代理立刻连上游 8701，抢先完成 JDWP 握手（命中 0.5s 早期窗口）
  -> 把握手回显转交给 jdb，此后双向字节转发
  -> jdb 侧：suspend（先冻结 VM 赢得与 clinit 的竞速）-> stop in <clinit>
     -> resume -> 断点命中 -> next + print 探测（同 4.3 节）-> kill -9 jdb
```

关键设计点：

- **握手由代理在 Python 进程内完成**（socket 级 14 字节 `JDWP-Handshake`
  交换），Python 轮询 + 连接的总延迟可以控制在几十毫秒内，稳定命中早期窗口；
- jdb 只与本地代理通信，其慢启动被"提前连上、挂起等握手"完全吸收；
- 握手完成后 jdb 侧先 `suspend` 冻结整个 VM 再下断点、然后 `resume`——比
  直连流程的 `run` 更稳，最大限度赢得与 `<clinit>` 执行的竞速；
- 结束时同样 `kill -9` 本地 jdb（不发 `quit`），并 `adb forward --remove`
  清理上游转发。

完整实现已作为仓库文件 `LynkCoHelper/tools/extract_appsecret.py` 提供（原名
drive_jdb_proxy.py，初版的内嵌
代码已移除，以仓库文件为准），并在初版基础上做了多处增强，把提取流程压缩成一条命令（用法详见第 7 节）：

1. 前置环境自动探测与下载：`pexpect` 缺失自动 pip 安装；`adb`（platform-tools
   ~10MB）/ `jdb`（Amazon Corretto 8 ~110MB）缺失时确认后自动下载官方公开源
   包到 `~/.lynkco-helper-tools/`；模拟器/AVD 仍需一次性手动安装（约 1.5GB
   且需接受许可协议，见 7.1 节）；
2. 无在线设备时自动列出并**冷启动** AVD（`-no-snapshot-load`，规避坑 1），
   多个 AVD 时交互选择，也可通过命令行参数指定；
3. 提取过程全自动（代理抢握手 -> suspend -> 断点 -> 单步探测 -> `kill -9`
   收尾 -> 清理转发），中英文 jdb 输出均兼容；
4. 提取成功后交互确认，可自动写入 `env.json` 的 `secrets` 段（该文件已被
   gitignore，不会入库）；
5. 命令同步采用"回显锚点 + 静默等待"：先等本条命令的回显出现（天然跳过
   残留输出），再持续消费到 1 秒无新输出（兼容 jdb 异步事件——`next` 的
   "已完成的步骤"会出现在早期 `> ` 提示符之后，只等第一个提示符会导致命令
   输出整体错位一条），彻底避免输出错位；提取值格式校验（仅接受行尾
   `= "..."` 的纯字母数字值，排除 `next` 步骤行等干扰），异常/断连自动
   重试（最多 3 次）。

用法（依赖 `pexpect`）：

```bash
python3 LynkCoHelper/tools/extract_appsecret.py            # 无设备时自动冷启动 AVD
python3 LynkCoHelper/tools/extract_appsecret.py <AVD名字>  # 指定要冷启动的 AVD
```

2026-08-25 实测：代理方案一次成功——PID 出现后 0.04s 内完成上游握手，
`suspend` -> 断点 -> `resume` 后命中 `LynkCoConstants$g.<clinit>`，同样仅
2 次 `next` 即探测到 `c` 赋值，提取结果与原文档记录一致，App 进程全程存活。


## 5. 验证：确认 AppSecret 与签名算法均正确

拿到候选 `appSecret` 后，用真实抓包样本反向验证签名算法。

### 5.1 第一轮验证：失败

最初按猜测的签名格式（分隔符 `#`、无 `Date` 头参与）构造 `string-to-sign`
计算签名，与真实抓包的 `x-ca-signature` 逐一比对，所有组合均不匹配，
说明问题在于签名格式而非密钥本身。

### 5.2 定位官方签名算法

参考阿里云 API 网关官方 SDK（`SignUtil`/`SdkConstant`）的公开实现，确认：

- 分隔符为换行符 `"\n"`，而非之前猜测的 `"#"`；
- `Date` 请求头需要参与签名运算；
- 参与签名的头仅限 `x-ca-` 前缀，按 key 字典序排序，格式为每行 `"key:value\n"`；
- 待签名字符串结构（`buildStringToSign`）为：

  ```
  METHOD\n
  Accept\n
  Content-MD5(固定为空)\n
  Content-Type\n
  Date\n
  (排序后的 x-ca- 头，每行 "key:value\n")
  path(?按 key 排序的 query，格式 "k1=v1&k2=v2")
  ```

- 签名 = `Base64(HMAC-SHA256(string-to-sign, appSecret))`。

### 5.3 第二轮验证：完全匹配

严格按上述算法重建 `string-to-sign`（使用真实抓包的 `nonce`/`timestamp`/
`date`/`path`/`query`），用候选 secret 计算签名，与两组独立的真实抓包样本中的
`x-ca-signature` 逐字节完全一致。至此，`NATIVE_APP_KEY` / `NATIVE_APP_SECRET`
与签名算法均得到验证，`lynkco_common.py` 据此完成 `build_native_signature()`
的实现。

## 6. 结论 & 后续维护提示

- `NATIVE_APP_KEY` / `NATIVE_APP_SECRET` 是领克 App **应用级别**共用的密钥（不区分
  用户、不随登录状态变化），可在脚本里长期复用。
- 若未来领克升级 App 并更换密钥（常见于大版本更新或更换加固方案时），签名会
  重新返回 403，需重新提取密钥（直接按第 7 节运行提取脚本），并按第 5 节验证。重新提取前请先
  确认第 3 节的前置条件（设备系统固件为 `userdebug`/`eng`）仍满足，否则需先
  换用模拟器或工程机。**注意 4.5 节的三个坑**：模拟器必须 `-no-snapshot-load`
  冷启动（快照恢复会让 jdwp 转发挂死），且应优先使用 `tools/extract_appsecret.py`
  代理方案而非 4.3 节的直连流程（后者在 waitForDebugger 挂起态下握手不通）。
- 若某个 App 版本调整了密钥调用链（类名/方法名/字段名混淆变化），需先重新做静态
  分析定位新的调用路径（参考第 1 节的分析思路）。
- **环境要求小结**：本方法不依赖 root，也不依赖 App 自身的
  `android:debuggable`，真正的前提是设备/模拟器系统固件为 `userdebug`/`eng`
  （详见第 3 节）。零售版真机（`user` 固件）无论是否 root 均无法直接使用本文档
  的方法，需改用 AVD 模拟器或对应固件的工程机。

## 7. 一键提取（推荐）

> 本节写给"密钥失效了，我只想重新提出密钥"的读者。提取脚本按平台分两个入口
> （共享核心 `tools/appsecret_core.py`：代理/jdb 交互/提取主循环）：
>
> | 入口 | 平台 | 特点 |
> |---|---|---|
> | `tools/extract_appsecret.py` | macOS（本地） | 常规本地使用，**仅一件事手动做（一次）**：创建模拟器；领克 App 自动下载安装 |
> | `tools/extract_appsecret_auto.py` | macOS Apple Silicon / Linux x86_64（含 CI） | 一切全自动（含模拟器镜像、APK），适合无人值守；GitHub Actions 手动触发见 `.github/workflows/extract-appsecret.yml`（ubuntu-latest） |
>
> 架构硬约束：领克 APK 仅含 arm64-v8a 原生库，**镜像 ABI 恒为 arm64-v8a**。
> 可行路线只有两条（2026-08-31 实测定案）：
> 1. **macOS Apple Silicon（本地）**：Hypervisor.framework 原生虚拟化，快。
> 2. **Linux x86_64（CI/ubuntu runner）**：x64 emulator 包自带
>    qemu-system-aarch64，对 arm64 镜像做全系统 TCG 模拟——整个 guest
>    就是 arm64 Android，App 的加固壳跑真 ARM64 指令（逐条翻译），
>    无 libndk 翻译层、不会崩溃；代价是慢（冷启动 20~50 分钟），
>    boot 超时已放宽到 50 分钟，工作流 timeout 180 分钟。
>    ⚠️ Linux 上 emulator 钉住 31.3.10（build 8807927，与 API33 镜像
>    同代，脚本固定包名不经 XML 解析）。37.x 与 31.x 启动器均有跨架构
>    硬检查（run 33365171562 / 33370599438 实测 FATAL "Avd's CPU
>    Architecture 'arm64' is not supported by the QEMU2 emulator on
>    x86_64 host"），但检查条件是「arm64 且 apiLevel≥28」：apiLevel
>    只从 AVD 根 ini 的 target= 字段解析（avd/avd-info.c，与镜像
>    build.prop 无交叉校验；CPU arch 则从镜像 build.prop 读，真
>    arm64）——Linux 上把根 ini 的 target 谎报为 android-27（镜像仍
>    是 API33）检查即不触发。本地用 CI 同版 31.3.10 实测：谎报
>    target + API33 arm64 镜像正常 boot，guest 实为 Android 13。
>    顺带 hw.sdCard=no 规避 arm 镜像 sdcard 老 bug（b/174481551）。
>    镜像统一用 API 33 google_apis（arm64-v8a-33_r17.zip，
>    1.7GB，双镜像源均有）。31.3.10 的 SDK 根校验还要求 platforms/
>    子目录存在（37.x 已不查，本地最小 SDK 实测复现/解除），脚本自建
>    空目录 platforms/android-33/ 即可通过——启动只用 system-images，
>    不读 platforms 内容。等待逻辑也已改为 5 秒一轮探测（进程存活 +
>    日志 PANIC/FATAL + adb get-state），秒级失败秒级退出，不再干等超时
>    （run 33368243194 踩坑：启动 1 秒即 PANIC 却白等 adb 满 10 分钟）。
> 已排除的路线（勿再踩）：ubuntu+x86_64 镜像（libndk 下加固壳必崩）；
> macos runner——VM 内无 Hypervisor.framework（actions/runner-images#13505），
> 且 Android emulator 的 arm64 guest 在 macOS 上死绑 HVF（37.1.11 实测：
> -accel off 传给 qemu 后仍走 HVF，-qemu 直通 -accel tcg 即 fatal
> "HVF error: HV_NO_DEVICE"），无法降级 TCG；预装 darwin-x86_64 包
> 也不含 qemu-system-aarch64。Intel mac / Linux ARM64 同理不可行。
>
> 两者均自动完成：依赖下载、冷启动模拟器、代理抢握手、断点提取、写入
> env.json、失败重试。原理与踩坑细节见第 4 / 4.5 节；脚本失败先查 7.4 常见问题表。

### 7.1 一次性手动准备（仅 1 步，仅 macOS 入口需要）

1. **创建模拟器（AVD）**：安装 Android Studio（自带 SDK 管理器与模拟器）
→ Device Manager → Create Virtual Device → 任选一款手机 → 系统镜像
**必须选 "Google APIs" 版本，不要选带 "Google Play" 的版本**（Play 版是
零售固件 `user`，不允许 JDWP 调试，是新手最常踩的坑）。API 31~34 的
Google APIs 镜像均可（userdebug 固件），实测 API 33。

以下均**无需手动准备**，脚本自动处理：

| 依赖 | 脚本行为 |
|---|---|
| `pexpect` | 缺失时自动 `pip install` |
| `adb`（platform-tools ~10MB） | 缺失时询问并自动下载官方公开源到 `~/.lynkco-helper-tools/`（二次运行复用） |
| `jdb`（JDK 8 ~110MB） | 同上（macOS: Corretto 8 aarch64 / Linux: Corretto 8 x64；本机已装任意 JDK 时直接复用其 jdb） |
| 模拟器启动 | 无在线设备时自动 `-no-snapshot-load` **冷启动**（规避 4.5 节坑 1） |
| 领克 App APK（约 285MB） | 设备未装时自动从领克官方 CDN 下载最新版并 `adb install`（已下载则复用） |
| 提取结果 | 成功后询问 `[y/N]`，确认则自动写入 `env.json`（已被 gitignore） |

### 7.2 运行

```bash
# macOS（仓库根目录执行；无在线设备时自动列出并冷启动 AVD，多个则交互选择）
python3 LynkCoHelper/tools/extract_appsecret.py
python3 LynkCoHelper/tools/extract_appsecret.py <AVD名字>

# 全自动版（CI / 无本地 Android 环境：加速预检 -> 自动下载镜像+APK -> 无头冷启动）
python3 LynkCoHelper/tools/extract_appsecret_auto.py
```

环境变量（两个入口均生效）：`EMU_HEADLESS=1` 强制无头启动模拟器（CI 必设；
本地默认窗口模式，无 DISPLAY 的 Linux 自动无头）；`LYNKCO_AUTO_WRITE=1`
免交互确认，直接写入 env.json。Linux（TCG 全系统模拟）下所有等待窗口
自动放宽 10 倍，无需手工干预。

CI 工作流另支持可选 Secret `LYNKCO_PAT`（具备本仓库 Secret 写权限的 PAT）：
配置后提取结果会自动合并更新 `LYNKCO_APP_SECRETS` Secret，未配置时从
运行日志取值手动更新。

预计耗时：首次（含下载依赖）约 5~10 分钟，之后每次约 1~2 分钟。脚本自动
完成 4.5 节的全流程：代理抢握手 → suspend 冻结 → 断点 → 单步探测 →
`kill -9` 收尾（不发 `quit`，避免触发 App 自杀）→ 清理端口转发；连接中断
或提取值格式异常时自动重试，最多 3 次。

### 7.3 验证结果

成功后脚本会打印提取到的 `nativeAppKey` / `nativeAppSecret` 并询问是否写入
`env.json` 的 `secrets` 段。之后跑一次任意任务（如
`python3 lynkco_daily_tasks.py`）：

- 不再返回 403 → 提取成功；
- 仍 403 → 写入的值不对，或 App 已更换密钥调用链（类名变了），回到 7.4 排查；
  需要离线严格验证可按第 5 节用历史抓包样本比对签名。

### 7.4 常见问题速查

| 脚本提示/现象 | 原因 | 处理 |
|---|---|---|
| `Activity class ... does not exist` | App 更新换了入口 Activity | `adb shell cmd package resolve-activity --brief com.lynkco.customer` 查输出最后一行的新 Activity 名，修改脚本头部 `ACTIVITY` 常量 |
| `未取到 App PID` | App 没装上 | `adb shell pm list packages \| grep lynkco` 确认已安装，必要时重装 APK（见 7.1 第 2 步） |
| `上游握手失败`（重试 3 次仍失败） | AVD 用了 Google Play 镜像，或模拟器以快照方式启动（4.5 节坑 1/坑 2） | 换 **Google APIs** 镜像重建 AVD（见 7.1 第 1 步）；若自己手动开过模拟器请关掉，让脚本自动冷启动（脚本自启的 AVD 必为冷启动） |
| `未命中断点` / 提取值一直为空 | App 大版本更新、混淆类名变了 | 按第 1 节思路用新版 APK 重新静态分析，修改脚本头部 `CLASS` 常量；手动逐段定位可参考 4.3 节的 jdb 命令序列 |
| `目标 VM 断开`（App 反调试自杀） | 调试暴露过久或平台连接不稳 | 脚本会自动重试；3 次均失败多为连接不稳，冷启动模拟器后重跑 |
| `PANIC: Broken AVD system path` | SDK 根缺 `platforms/` 子目录（31.3.10 校验，37.x 不查） | 脚本已自建空 `platforms/android-<API>/`；自备 SDK 时确保该目录存在 |
| FATAL/PANIC "Avd's CPU Architecture 'arm64' is not supported ... on x86_64 host" | x86_64 宿主跑 arm64 镜像且 AVD 根 ini 的 target≥android-28 | 脚本已把 Linux 的 AVD target 谎报为 android-27 绕过检查（镜像仍是 API33）；自建 AVD 时同理 |
| 模拟器启动失败（带 PANIC/FATAL 日志末尾） | 模拟器秒挂，等待逻辑 5 秒一轮探测即刻发现并带日志退出 | 看日志末尾的具体报错，对照本表或第 4.5 节踩坑记录排查 |

> 曾有的"手动 10 步教程"已随脚本完善而移除：手动直连依赖在进程 fork 后
> 0.5s 内完成 JDWP 握手（4.5 节坑 2），多数环境人工根本赶不上，作为兜底
> 反不如脚本可靠；需要理解每步在做什么，看 4.3 / 4.5 节的原理与命令序列。
