# AntiHook Bypass

Android 上的 LSPosed 模块：把 Hook / 注入留下的痕迹，在**运行时视图层**抹掉。

不按检测器的类名、包名、特征串写补丁——处理的是痕迹本身的物理形态，所以方向相同的检测都会自然读到干净结果。

四 ABI 全支持，装完在 LSPosed 里勾作用域即生效，没有别的配置。

---

## 它到底改了什么

核心立场：**不动 ART、不改代码段、不碰别的模块的 hook**。

| 层 | 处理对象 | 做法 |
|---|---|---|
| L1 · Java | `getStackTrace` / `getAllStackTraces` / `StackWalker` / `Class.forName` / `getXposedVersion` / `isDebuggerConnected` | 滤掉框架帧、收敛类可见性、伪造探测结果 |
| L2 · Native 具名函数 | libc 的 `open` / `openat` / `ptrace` / `fork` / `prctl` / `process_vm_readv` | 拦内存布局探测、拦自我 ptrace、拦 fork 反向附加 |
| L3 · Native syscall | libc 的 `syscall()` 通用入口 | 拦 `syscall(SYS_openat, ...)` 这类绕过具名函数的写法 |
| L3 · 运行时视图 | ART 的 `ClassLoader` 链表读取 | **只伪造读出来的视图**，ART 结构一个字节不写 |

---

## 为什么是「视图伪造」而不是「改链表」

数 ClassLoader 数量的检测，走的是读自己进程内存这条路。天然有两个选择：

1. 把 ART 里的链表真剪短
2. 让它读到的内容变短，但链表本身不动

选 1 的实测结果：进程内剪链会破坏 GC 根，两次确定性崩溃——
`MarkCompact::MarkRoots` 里 `SIGSEGV`、`ThreadList::SuspendAllInternal` 里空指针。
外部进程写没事，进程内写必崩，因为写入时 ART 线程没被挂起。

所以本模块选 2。检测器调 `process_vm_readv` 读内存时，返回给它的字节由我们决定；
它自己走一遍链表，数出来就是干净的数。**ART 完全不知情，别的模块的 hook 也不受影响。**

---

## 关键难点：时机

检测器的扫描在 `System.loadLibrary` 之后几乎立刻开始，而它自己的 `.so` 那时才刚映射进内存。
在那之前接管不到它的 GOT——因为它的库还不存在。晚一步就整轮错过。

本模块分三层抢跑：

1. **`JNI_OnLoad`** —— vm 已有效，先扫候选链、登记读视图、启动抢跑线程
2. **2ms 轮询** —— 盯着 `/proc/self/maps`，目标库一出现立刻补 GOT（实测第 228 轮抢到）
3. **首次读取时重扫** —— 包装函数第一次被走到，说明它已开扫，按当时的结构再补一遍

另外它的 GOT 是 `r--p`（full RELRO 把重定位后的 GOT 映射成只读），普通按 `rw` 过滤的扫描会静默错过。
本模块枚举重定位项，只读页也照写。

---

## 实测结果

对 `com.cshlolss.antihook.detect`（六项原生检测），读取它自己 `NativeLib.scan` 的返回值：

| 检测项 | 结论 | 它自己给出的说明 |
|---|---|---|
| ART ClassLoader 计数 | SAFE | 当前 **4 个** ClassLoader，处于正常范围 |
| libc.so 内存 CRC | SAFE | 与磁盘一致（CRC `0xc699`） |
| libart.so 内存 CRC | SAFE | 与磁盘一致（CRC `0x6e92`） |
| 匿名可执行段 | SAFE | 未发现无路径名的可执行段 |
| Inline Hook 扫描 | SAFE | 代码段中无跳转异常 |
| 子进程 ptrace 外部视角 | SAFE | 外部视角读数与磁盘一致 |

阈值是「大于 10 判风险」，它读到的是 4。

判定来源不是截图、不是推断，是检测器自己的返回值——模块里挂了个**只读**取证 hook 把它抄进日志，不改任何参数或返回值。

---

## 构建

没有用 Gradle。原因很实际：

- Gradle 的原生库是 glibc 编译的，Android（Bionic）上加载失败
- aapt2 是 x86_64 程序，arm64 设备上跑不起来

所以走手工链路：`javac → d8 → 自写 AXML → zip → apksigner`。
`tools/axml.py` 是手写的 AXML 二进制生成器，`tools/make_manifest.py` 用它生成清单。

```bash
bash tools/build.sh
```

输出 `build/AntiHookBypass.apk`，四个 ABI 的 `.so` 各一份。

签名密钥默认生成在 `build/release.jks`，**不入版本库**。
想在不同机器上重建同一个签名，用环境变量指定既有密钥库：

```bash
AHB_KEYSTORE=/path/to/release.jks bash tools/build.sh
```

---

## 边界

清楚说明打不过的情况：

| 情况 | 为什么 |
|---|---|
| 检测完全在 native 闭环，用内联汇编 `svc` 直接杀进程 | 要拦得改代码字节，那会触发完整性校验，反而暴露 |
| 结果发到服务器二次校验 | 客户端改不了 |
| 检测器比模块更早加载并完成扫描 | 时序竞态，本模块已经抢到最早时机，但不能保证对所有实现都赢 |

---

## 日志

```bash
adb logcat -s AntiHookBypass
```

关键行：

| 行 | 含义 |
|---|---|
| `JNI_OnLoad: 早期视图安装 slots=N` | 最早时机完成登记 |
| `FASTPATCH: 第 N 轮抢到接管 M 处` | GOT 补丁在目标库出现后多久拿到 |
| `L3 view: 接管 slot=... lib=...` | 接管点、所属库、保护位 |
| `SELFCHECK head=... real=N walked=M` | 自证：真实值 N，经被接管的路径读出 M |
| `VERDICT ...` | 检测器自己的判定 JSON（只读取证） |

---

## 说明

用于对自有应用、自有设备、或已获授权的目标做安全评估与逆向学习。
