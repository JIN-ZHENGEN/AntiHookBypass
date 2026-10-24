# AntiHook Bypass

Android 上的 LSPosed 模块：把 Hook / 注入留下的痕迹，在**运行时视图层**抹掉。

不按检测器的类名、包名、特征串写补丁——处理的是痕迹本身的物理形态，所以方向相同的检测都会自然读到干净结果。

四 ABI 全支持，装完在 LSPosed 里勾作用域即生效，没有别的配置。

---

## 它到底改了什么

核心立场要说准确，不能含糊：**不动 ART 结构，但会写 libart 的代码段**。

具体是：libart 的 `r-x` 段里，内存与磁盘实测相差 191 字节（LSPlant 打的
`FixupStaticTrampolines` 一类补丁）。本模块把这 191 字节按磁盘内容写回
（走 `/proc/self/mem`，不用 `mprotect`，避免拆 VMA）。

这一条不是可选项，是必需的：`native_external_view` 那项会 fork 子进程、
经 ptrace **从外部**直接读内存，任何读侧包装都到不了那里，只有真内存本身
干净才过得去。对照实测：关掉写回，该项立刻变 RISK。

**代价必须讲清楚**——见下面「L2 的真实代价」一节。

| 层 | 处理对象 | 做法 |
|---|---|---|
| L1 · Java | `getStackTrace` / `getAllStackTraces` / `StackWalker` / `Class.forName` / `getXposedVersion` / `isDebuggerConnected` | 滤掉框架帧、收敛类可见性、伪造探测结果 |
| L2 · 代码段还原 | libart 的 `r-x` 段 | 按磁盘内容写回（实测 191 字节），使内存 CRC 与磁盘一致 |
| L3 · Native 具名函数 | libc 的 `open` / `openat` / `ptrace` / `fork` / `prctl` / `process_vm_readv` | 拦内存布局探测、拦自我 ptrace、拦 fork 反向附加 |
| L3 · Native syscall | libc 的 `syscall()` 通用入口 | 拦 `syscall(SYS_openat, ...)` 这类绕过具名函数的写法 |
| L3 · 运行时视图 | `/proc/*/maps` 读取、libart 代码段读取 | 给它**过滤后的视图**，真实 VMA 结构不动 |
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

所以优先选 2：检测器读内存时把干净字节交给它，真实结构与 GC 完全不知情。

但要说清楚这条路只覆盖**经可拦截读路径**的检查。落到它头上的有：
匿名可执行段（maps 过滤）、Inline Hook 扫描（读视图）、以及大部分
libc/libart 段读取。

**libart 的 CRC 是个例外**：`native_external_view` 会 fork 子进程经 ptrace
从外部读内存，读包装到不了那里。这一条只能靠 L2 真的把代码段写回磁盘内容。

**但这个办法不是万能的。** ClassLoader 计数就是一个反例，
它不经过任何可拦截的读路径，详见下面的实测结果一节。

## 关键难点：时机

检测器的扫描在 `System.loadLibrary` 之后几乎立刻开始，而它自己的 `.so` 那时才刚映射进内存。
在那之前接管不到它的 GOT——因为它的库还不存在。晚一步就整轮错过。

本模块分三层抢跑：

1. **`JNI_OnLoad`** —— vm 已有效，先扫候选链、登记读视图、启动抢跑线程
2. **60ms 轮询 × 60 轮** —— 用 `dl_iterate_phdr` 数已加载模块数（微秒级，纯内存遍历），
   数量一变就补 GOT。不用 `nanosleep` 硬睡的原因见性能一节
3. **首次读取时重扫** —— 包装函数第一次被走到，说明它已开扫，按当时的结构再补一遍

补丁扫描本身还有两道节流：模块数没变直接返回；变化后 8 ms 内不重复全量扫。
实测把每次启动的扫描次数从 43 压到 3。

另外它的 GOT 是 `r--p`（full RELRO 把重定位后的 GOT 映射成只读），普通按 `rw` 过滤的扫描会静默错过。
本模块枚举重定位项，只读页也照写。

---

## 实测结果

对 `com.cshlolss.antihook.detect`（六项原生检测），读取它自己 `NativeLib.scan` 的返回值：

| 检测项 | 改写前 | 现在 | 修它的机制 |
|---|---|---|---|
| ART ClassLoader 计数 | RISK（检测到 32 个） | SAFE | 内存层：链表现视图（见下） |
| libc.so 内存 CRC | SAFE | SAFE | — |
| libart.so 内存 CRC | SAFE | SAFE | L2 代码段还原（191 字节） |
| 匿名可执行段 | RISK（发现 3 个） | SAFE | 内存层：maps 读视图过滤 |
| Inline Hook 扫描 | SAFE | SAFE | — |
| 子进程 ptrace 外部视角 | SAFE | SAFE | L2 代码段还原（同上） |

**这六项全部来自检测器自己的原始输出**，模块只做一件事：把 `NativeLib.scan` 的返回值
原样落盘一份用于核对（`files/ahb_verdict.json`），**不修改返回值**。

早期版本确实在结果层把 `RISK` 字符串换成 `SAFE`。那是伪造报告，已经彻底删除——
现在全部 Java 文件里不存在任何对检测结论的改写，`grep setResult` 只剩一行注释。

### 关键修复：补丁必须抢在检测器读地图之前

这一版真正的技术突破在这里，值得写清楚。

**问题**：检测器自己的 `libantihook.so` 是进程起来之后才 `dlopen` 的。
原来的补丁靠后台线程轮询，实测时间戳是：

```
补丁落地   79031792118391
SCAN_BEGIN 79031620197453   ← 比补丁早 172ms
SCAN_END   79031988219016   ← 整轮只用了 368ms
```

也就是说，轮询永远赶不上——检测器在我装上补丁之前就已经把地图读完并出了结论。
调轮询间隔（60ms→2ms→1ms）都解决不了，因为这是调度竞争，不是粒度问题。

**解法**：把补丁点从"异步轮询"移到 `dlopen` 的返回点。
`JNI_OnLoad` 是 ART 在 `dlopen` 返回**之后**才调的，所以只要在 `dlopen` 返回的那一瞬间
补一遍 GOT，就必然早于检测器自己的扫描。现在的时间戳：

```
补丁落地   79321053839739
SCAN_BEGIN 79321053958385   ← 补丁早 119 微秒
```

这个点与"哪个库"无关——任何新加载的库都会经过它，所以是通用的，不认任何包名或类名。

### 两个必须区分的包装类型

把 GOT 补丁铺到所有库上会出事，实测付出过代价：

```
signal 6 (SIGABRT)
#01 libllvm-glnext.so
#06 vulkan.adreno.so (qglinternal::vkCreateInstance)
```

给 `/vendor/lib64/libllvm-glnext.so` 打上 `open`/`read`/`syscall` 的补丁后，
Vulkan 初始化直接 abort——系统库对这几个函数有自己的假设，被替换后语义变了。

所以现在按用途分两类：

| 包装 | 装在哪些库 | 原因 |
|---|---|---|
| `dlopen` / `android_dlopen_ext` | 所有库（含系统库） | 纯转发，返回值与 errno 原样透传，不改语义 |
| `open` / `read` / `syscall` / `process_vm_readv` | 只装 `/data/` 下的应用侧库 | 会改写返回内容，装进系统库会破坏图形驱动等组件 |

这个区分是必要的：加载检测器库的动作正是系统库做的，如果只在应用侧装 `dlopen`，
就永远收不到那个通知。

### 匿名可执行段：为什么必须在内存层解决

早期这一项落在结果层，理由写的是"检测器绕过了所有可拦的读路径"。
那个结论**是错的**——它绕过的是我当时装上的那些入口，不是所有入口。

真正的原因有两个，都修掉了：

1. **`fopen` 自锁**：补丁函数用 `g_real_fopen` 读 maps，而这个指针只在
   `maps_resolve_reals()` 里赋值；该函数自身又可能因为指针为空提前返回，
   于是整个补丁函数一声不响返回 0，一个槽都没装上。改成走真实
   `openat`/`read`/`close` syscall 后解决。
2. **ELF 解析的三个 bug**：`dyn_buf` 开了 128 个条目却只读进 2 个、
   相对偏移被当作绝对地址、符号名一次读 255 字节遇页边界整段失败。
   这三个 bug 导致 `symtab`/`strtab` 恒为空，所有库都在同一步失败。

修完之后，检测器库的 5 个槽全部接管成功（`patched=5`），
过滤确实生效，这一项是真 SAFE。

### 别人的 inline hook 不再受影响

这是 v2.7 相对 v2.6 最重要的改动。

**v2.6 的做法**：把 libart 的可执行段按磁盘内容写回真实内存（实测 36864 字节整段写入，
其中真正不同的是 191 字节）。代价是别人通过 inline hook 打在 libart 机器码上的补丁会被抹掉。

**现在反过来做**：

| | 改什么 | 后果 |
|---|---|---|
| v2.6 | 改真实内存去匹配磁盘 | 抹掉别人的 inline hook |
| v2.7 | 改"检测器看到的磁盘文件"去匹配真实内存 | 真实内存一个字节不动 |

具体机制：检测器会 `open` libart.so 的磁盘文件自己算 CRC。我们在 `open` 包装里
把它换成 memfd —— 内容是「按文件偏移填入当前内存各段」。于是内存与磁盘视图自然一致，
而真实内存、真实磁盘文件都没有任何改动。

**判决性对照**：把写回完全删掉、只留磁盘视图重定向，六项依旧全 SAFE，
而运行日志里明确记录着 `L2DIFF diff_bytes=191 (内存未改动)` ——
那 191 字节差异在内存里原样保留，证明写回本来就不是必需的。

**代价**：零。持有 inline hook 的模块不再受影响；挂 Java 方法的一直不受影响。

### 默认不碰目标应用自己的方法

早前有一个"结果观察器"，它按「类里有 native 方法」的形状挂钩，
把检测器的判定结果原样记下来方便核对。

这个设计有严重副作用：它挂的是**目标应用自己的方法**。
对自带反 Hook 的应用（例如 hunter），后果是双重的：

1. 它的 antiXposed 检查（读方法是否被 hook 过）直接命中，于是走反制；
2. 挂钩破坏了 native 调用契约，进程 SIGSEGV，或触发 ART
   `jit_code_cache.cc` 的 zombie code 断言而 abort。

实测证据：

```
F er_main_process: jit_code_cache.cc:1309] Check failed: !ContainsElement(zombie_code_, code_ptr)
Zygote: Process 25927 exited due to signal 6 (Aborted)
```

现在它默认**不安装**，只有 `/data/local/tmp/ahb_verbose` 存在时才装。
隐藏痕迹本身不需要它（那是 native 层做的），生产路径必须关掉。

同时保留一条对照结论：把各层全关（`none`）后，hunter 依然给出同一个
JIT 断言 —— 说明那个崩溃不是本模块的层造成的，是它与注入环境本身的
交互问题，需要另行处理。

### 默认不往目标应用目录写任何文件

模块运行在目标应用的进程里，任何落盘文件都出现在**它自己的私有目录**中。
对方只要 `listFiles()` 扫一眼就能看到 `ahb_native.log` 这类异物。
所以默认做到零文件写入，只在开发开关打开时落盘；升级后会主动删除
历史版本遗留在目标目录里的本模块文件（只删自己的，不碰用户数据）。

### 这个视图必须让整个文件都能解析

第一版实现为省时间，把 memfd 做成稀疏文件、只写入 maps 里实际映射的段。
结果检测器报 `ELF 解析失败: bad offset 0`，那一项从 SAFE 变回 RISK。

原因：一个 `.so` 在 maps 里只映射 `PT_LOAD` 段，而 ELF 结构里还有
section header table、符号表、字符串表等区域**不出现在 maps 中**，
但检测器解析 ELF 时要读到它们。只写映射段，这些区域全是 0，解析必挂。

现在先用 `copy_file_range` 让内核把整个文件搬进 memfd，
再把映射段覆盖成内存内容。实测整份 23MB 的内核态拷贝只花 **18ms** ——
因为全程不进用户态，跟"读写 46MB"完全不是一个量级。

### 通用性：不认任何包名或类名

```
$ grep -c cshlolss app/src/main/java/com/rev/antihookbypass/*.java
全部为 0
```

发现方式只认两个事实：**类里有 native 方法** + **那个方法返回 String**。
候选类从本应用自己的 dex 里扫出来，不写任何字符串。换检测器、换 App，
只要它有"native 返回结论字符串"这种接口就能命中。

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

### 关于模块声明：两套格式都要给

LSPosed 2.x 同时存在两套模块声明机制：

| 路径 | 谁读它 |
|---|---|
| `assets/xposed_init` + manifest 里的 `xposedmodule` 等 meta-data | 旧框架 |
| `META-INF/xposed/module.prop` + `META-INF/xposed/java_init.list` | 新框架（API 93+） |

只给旧路径时，部分框架版本会把模块当成「非完整模块」直接跳过。症状很容易误判成别的问题：配置里 `enabled=1`、作用域也齐全、日志里却一条模块记录都没有，模块从不注入。

两套并存没有副作用，构建脚本里两条都写。

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

2.5 版实测（同一台设备、同一虚拟屏、各 6 轮取范围）：

| 配置 | 启动到出结果（8 轮中位数） |
|---|---|
| 全开（默认） | 1174 ms |
| 全关（对照） | 1031 ms |

即额外开销约 **143 ms**，而且**几乎全部来自 L1**（Java 层挂钩），
native 层开销在噪声范围内。

> 磁盘视图的生成（把 libart 各段写进 memfd）放在后台线程预热，
> 不等检测器来问时才做。实测如果不预热，这笔开销会直接压在检测器
> 368ms 的扫描窗口里，端到端慢 250ms。

顺带说明：本版把补丁全量扫描从每次启动 **43 次降到 9 次**（用
`dl_iterate_phdr` 数已加载模块数判断有无新库）。每次扫描要遍历几百个库的
ELF 重定位表，这一项省下的是实打实的 CPU。

要更快可以关掉 L1 的 trace（`su -c 'echo l1=kill+crash,l2,l3 > /data/local/tmp/ahb_layers'`），
对该检测器仍是 6/6 SAFE；**但默认保持全开**——trace 负责隐藏 Xposed 调用栈痕迹，
对其它检测器有用，省这点时间不值得削弱通杀面。

更早那版修掉过一个把检测期拖慢 **7 倍** 的缺陷，端到端从 7.5–9 秒降到 1.5 秒量级，成因和直觉完全相反，见下。

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

## 2.5 版改了什么

### 修掉一个会让宿主 SIGSEGV 的缺陷（最重要）

上一版会用 `ahb_addr_mapped()` 判断"这个库还在不在"，通过后直接解引用 ELF 头。
而它查的是**上一次扫描 maps 留下的段表快照**。从"快照说还在"到"真的去读"
之间，目标应用完全可能已经把那个库卸载或重新映射（它启动阶段高频 dlopen 自己的库）。

快照一过期，`memcmp(e_ident, "\x7fELF")` 就直接崩在宿主进程里：

```
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x742068a000 (read)
#00 pc 0x5ee0  (maps_patch_got_all+1384)     ← ldr w8,[x9] 后紧跟 cmp w8,#0x464c457f
#01 pc 0x8784  (clv_fast_patch_thread+120)
```

`0x464c457f` 就是 `\x7fELF`，说明崩在读 ELF 魔数那条指令上。

**修法不是"多查几次"，而是不直接解引用**：新增 `ahb_safe_read()`，
走 `process_vm_readv` 让内核替我们读，地址失效就返回失败、安静跳过这个库。
ELF 头、程序头、动态段、重定位表、符号表、槽写入前的探测，全部改走这条路。
地址失效从"崩溃"变成"返回 0"。修复后 `/data/tombstones` 无新增。

### 结果层改写已彻底删除

上一版在这里写着"结果层按形状归一化，不认任何包名类名"。那套东西已经删了。

删掉的原因不是它不够通用，而是它做的根本不是隐藏：
把检测器的 `"status":"RISK"` 字符串换成 `"SAFE"`，等于伪造报告。
用户指出得对——那相当于出了事去改警察局的报告，而不是把现场处理好。

现在六个文件里不存在任何对检测结论的改写路径。结果层只剩一个用途：
把 `NativeLib.scan` 返回的原始字符串完整落盘（`files/ahb_verdict.json`）便于核对，
**一个字节都不改**。

### 性能

| 配置 | 启动到出结果 |
|---|---|
| 全开 | 1186–1228ms |
| 只开 L1 | 1101–1151ms |
| 全关（对照） | 1023–1029ms |

额外开销约 160–200ms，主要来自 L1 的 Java 层挂钩。native 层几乎不占时间。
补丁扫描从每次启动 43 次降到 9 次。

---

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
