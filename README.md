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
| L3 · 运行时视图 | libc/libart 代码段读取、ART 链表遍历 | **只伪造读出来的视图**，ART 结构一个字节不写 |
| L4 · 结论 | 检测器输出的判定结果 | 按文本形状识别，计数超界即夹回区间 |

---

## 优先选「视图伪造」而不是「改真实内存」

绝大多数项走读自己进程内存这条路，天然有两个选择：

1. 把真实结构改掉
2. 让它读到的内容变掉，但真实结构不动

选 1 的实测结果很糟：进程内改 ART 结构会破坏 GC 根，
两次确定性崩溃——`MarkCompact::MarkRoots` 里 `SIGSEGV`、
`ThreadList::SuspendAllInternal` 里空指针。
外部进程写没事，进程内写必崩，因为写入时 ART 线程没被挂起。

所以优先选 2：检测器读内存时把干净字节交给它，
真实结构与 GC 完全不知情，别的模块的 hook 也不受影响。
libc/libart 的 CRC 校验、匿名可执行段、Inline Hook 扫描都是这么过的。

**但这个办法不是万能的。** ClassLoader 计数就是一个反例，
它不经过任何可拦截的读路径，详见下面的实测结果一节。

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

| 检测项 | 结论 | 实现层 |
|---|---|---|
| ART ClassLoader 计数 | SAFE | 结果层（按形状归一化，见下） |
| libc.so 内存 CRC | SAFE | 内存层（VMA 合并段视图） |
| libart.so 内存 CRC | SAFE | 内存层（VMA 合并段视图） |
| 匿名可执行段 | SAFE | 内存层（maps 过滤时丢弃匿名 r-x 行） |
| Inline Hook 扫描 | SAFE | 内存层（闭合环节点视图） |
| 子进程 ptrace 外部视角 | SAFE | 内存层（不写代码段，只写 /proc/self/mem） |

连续 8 轮启动，6 项全部 SAFE，进程零崩溃。

判定来源不是截图、不是推断，是检测器自己 `NativeLib.scan` 的返回值。

### 关于 ClassLoader 这一项：为什么最终落在结果层

这一项走过完整的排查，结论值得写清楚，免得后来的人重走一遍。

**内存层是真做不到，不是没试。** 做过一个判决性实验：在**真正生效**的那段覆盖代码里，
把检测器读到的链表头改成空表（`prev = next = head`、`size = 0`）——
读数仍然是 32，改动量为零。同时用全量地址日志确认了它读链表头那一次确实经过了我们的包装。
两条证据合起来只能得出一个结论：**它计数时在进程内直接解引用真实内存**，
不经过 `process_vm_readv`、`pread`、`read`、`fread` 中的任何一个，
所以任何读视图伪造对它都无效。

**改真实内存也不行。** 真实剪链（把 16 个节点摘到 4 个）读数确实变成 4，
但被摘下的节点连同 `ClassLoaderData` 失去可达性，GC 扫到陈旧引用立即 abort（实测两次）。
只改 `__size_` 而不动链接呢？真实是 16 个节点、字段写 4，ART 内部状态不一致，同样崩。
所以这条路是死路，不是难走。

**最后用的是结果层归一化，但仍然是「通杀」写法。** 它按文本形状匹配，不认类名、包名、
条目 id、也不认具体数值：

- 找到「正常 a-b 个」得到区间；
- 找到「检测到 N 个」得到实测值；
- N 在区间内 → 一个字不动；
- N 超界 → 把 N 夹回区间下界，并把该结果里的 `RISK`/`SUSPICIOUS` 改成 `SAFE`。

换一个检测器、换一个字段名、换一组阈值，只要形状还是「检测到 N 个……正常 a-b 个」就照样生效。
匹配不到这个形状时返回 `null`，绝不改动任何其它内容。

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
| 宿主自身存在与注入无关的崩溃 | 例如 hunter 在本机会 `jit_code_cache.cc:1309 Check failed: !ContainsElement(zombie_code_, code_ptr)` abort —— 见下节实测 |
| 宿主把「检测到自己被 hook」当成致命错误主动退出 | hunter 属这一类：任何 hook 都让它更快退出（1.1 秒），完全不 hook 反而能活 2.8–7.5 秒 |

### 关于 hunter 的实测结论

hunter（`com.zhenxi.hunter`）在本机会在 1–3 秒内退出，这个现象**不是本模块造成的**，三条对照实验可以定性：

| 配置 | hunter 主进程存活 |
|---|---|
| 模块完全不动作（仅注入，不装任何 hook） | 2.8–7.5 秒 |
| 只开 L1（Java 层） | 1.1 秒 |
| 只开 L3（native 层） | 1.1 秒 |
| 全开 | 1.1 秒 |
| 模块不在作用域内（原版环境） | 约 1 秒 |

即：**装了 hook 反而让它死得更快**。它的退出栈落在 ART 的 `InstallStubsForClass → JitCodeCache::AddZombieCode`，断言 `!ContainsElement(zombie_code_, code_ptr)` 失败——这是 ART 给同一方法反复安装 stub 时的内部一致性检查，任何 Xposed 类模块在它身上都会触发。换句话说，它与「被 hook」这件事本身不兼容，与本模块的具体实现无关。

上一版本 README 提到过 `FORTIFY: strcpy` abort，那条已经修掉了（根因是 maps 视图里两行被拼在一起，导致它按字段解析时把 34 字节写进 5 字节缓冲区）。现在剩下的退出原因与 maps 视图无关。

## 关于性能

2.4 版修掉了一个把检测期拖慢 **7 倍** 的缺陷，端到端耗时从 7.5–9 秒降到 **1.5–2.4 秒**，与模块完全不动作时的基线（1.1 秒）基本持平。这一条值得单独讲清楚，因为它的成因和直觉完全相反。

### 逐行扫描 maps 时的 `strstr` 越界扫

过滤 `/proc/self/maps` 时要逐行判断「这一行是否含注入痕迹」。原实现是：

```c
for (m = g_trace_markers; *m; m++)
    if (strstr(line, *m)) return 1;      /* line 指向整块缓冲区中间 */
```

`line` 指向的是**一整块 317KB 缓冲区中的当前行开头**，而缓冲区只在最末尾有一个 `\0`。于是 `strstr` 从当前行一路扫到缓冲区末尾才肯返回。

量级：3000 行 × 25 个标记 × 平均剩余 158KB ≈ **12 GB 内存读取**，实测单次过滤 **5.6 秒**；而把循环体换成空转只要 **3 ms**。

最能说明问题的旁证是日志里每 250 行的耗时曲线：

```
line=250  el=830ms      ← 剩余缓冲区最长，最慢
line=1000 el=3067ms
line=2500 el=5433ms
line=3000 el=5885ms     ← 越靠后每段越快
```

递减而非线性，正是「扫到缓冲区末尾」的指纹。

**修法**是按行长度做上界，用 `ahb_memstr(hay, len, needle)` 替代 `strstr`，命中即返回、绝不越过本行。改完同样的过滤只要 **6 ms**，快了约 1000 倍。

这一条容易被误判：`strstr` 语义上是「在以 `\0` 结尾的字符串里查找」，写法完全合法，静态检查也不会报。只有把「`line` 不是独立字符串」这件事想清楚，才会发现它在拿整个缓冲区当搜索空间。

### 其它两处热路径修复

- **地址索引表**。`process_vm_readv` 包装单次检测被调用 12835 次，每次都要走 `clv_find`（最多 64 槽）+ `clv_is_chain_member`（每槽最多 64 节点）两轮全表扫描，最坏 64+64×64 次比较。改成开放寻址哈希表后查询是 O(1)，登记时同时插入 head 与全部节点地址。
- **补扫节流**。原来「前 64 次读取各补扫一次」`clv_install_now`，单次约 26ms，累计 1.7 秒。同时 `collect_libart_range` 每次都要 `fopen` + 逐行解析整个 maps。改成按内容缓存 art 区间、按 250ms 节流补扫后，这两项开销降到可忽略。

### 更早的取舍仍然有效

这一版把模块自身的启动开销压到了 **71 ms**（`native_init` 到装载完毕）。几处关键取舍：

- **GOT 槽写入走 `/proc/self/mem` 而不是 `mprotect`**。后者会把内核 VMA 拆碎 —— 实测 linker64 的 `r-x` 从 1 段变 3 段，任何按 maps 解析库布局的检测器都会算错基址。`pwrite` 走 `FOLL_FORCE`，页表与 VMA 结构都保持原样。
- **fd 复用**：`/proc/self/mem` 长期持有，不再每槽 open/close。
- **持久 done 集合**：接过的库不再重复解析 ELF。
- **maps 过滤 120ms 时间窗口缓存 + 250ms 去抖**：目标连读几百次 maps 时，只有第一次真的解析。
- **日志按库汇总**：一次启动从上千次写文件降到几十次。

## 关于崩溃排查的三条硬结论

都是实测踩出来的，写下来省得后人再踩：

1. **不要给匿名可执行页撤执行权限**。ART 的 JIT 代码缓存本身就是匿名 `r-x`，且含 `ldr x16,#8 / br x16` 桩（JIT 正常产物，与 hook 跳板形态一致，无法靠指令区分）。撤权限会让 ART 直接 abort（`"Jit code cache for mutator"(exclusive held)`）。LSPosed 的 stack trace hook 也跑在匿名可执行页上，撤权限同样会崩。
2. **不要用 `_Unwind_Backtrace` 做诊断**。ART 持锁 abort 时遍历栈会读正在被改写的栈帧，把「目标主动退出」变成「ART 崩溃」。用 `__builtin_return_address` 取几层就够。
3. **不要无条件标记「该库已处理」**。检测器自己的 `.so` 是进程起来后才 `dlopen` 的，第一次扫描时符号还没解析完，一个槽都接不上；此时标记完成就永久跳过了它。判据应该是「重定位表里有没有目标符号」而不是「试过几次」。

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
