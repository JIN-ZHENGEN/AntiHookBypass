# 开发笔记

面向后续维护的工程记录。README 讲「是什么、为什么」，本文件讲「代码在哪、改动要注意什么」。

---

## 代码地图

```
app/src/main/
├── assets/
│   ├── xposed_init            一行，指向 HookEntry
│   └── native_init            一行，指向 JNI_OnLoad 所在库名
├── java/com/rev/antihookbypass/
│   ├── HookEntry.java         入口。分派 L1/L2/L3，挂判定取证
│   ├── ModuleConfig.java      层开关解析（从模块自己的配置读）
│   ├── TraceHide.java         L1 主体：栈帧过滤、类可见性、探测伪造
│   ├── KillGuard.java         拦 killProcess / exit / halt / sendSignal
│   ├── CrashGuard.java        拦会导致自身闪退的路径
│   ├── NativeLayer.java       Java → native 桥，nativeSanitizeRuntime(int ops)
│   └── MainActivity.java      说明页（可滚动）
│   └── jni/native_main.c      L2 + L3 全部原生逻辑（单文件，约 1900 行）
├── tools/
│   ├── build.sh               总构建
│   ├── build_native.sh        四 ABI 交叉编译
│   ├── axml.py                手写 AXML 二进制生成（无 aapt2）
│   ├── make_manifest.py       生成 AndroidManifest.xml
│   └── zipalign_so.py         .so 页对齐（官方 zipalign 跑不了）
└── docs/                      方法论 / 分层方案 / 验证用例 / 速查表
```

---

## native_main.c 的结构

按职责分块，改动时优先在对应块内解决：

| 区域 | 职责 |
|---|---|
| 指针读写工具 | `read_ptr_untagged` / `write_raw_ptr`，**必须处理 TBI 标记** |
| 候选链发现 | 复刻检测器的发现口径：`Runtime` 扫 `0..0x500` 找 vptr 落在 libart 区间，再扫 `+0..0x500` 找双向闭环 |
| 读视图伪造 | `clv_pvr`（`process_vm_readv` 包装）、`clv_build`（合成视图） |
| GOT 接管 | 按 `/proc/self/maps` 定基址，枚举 `.rela.plt` / `.rela.dyn`，**不按保护位过滤** |
| 抢跑线程 | 2ms 轮询盯目标库出现 |
| 代码段还原 | `restore_executable_segments(int ops)`，ops 位掩码见下 |
| 守护循环 | 250ms 一轮，重新上膛 |

ops 位掩码：

| 位 | 常量 | 含义 |
|---|---|---|
| `1<<0` | `NATIVE_OP_ART` | libart.so 代码段 |
| `1<<1` | `NATIVE_OP_LINKER` | linker64 代码段 |
| `1<<2` | `NATIVE_OP_TRAMP` | 跳板页收敛 |
| `1<<3` | `NATIVE_OP_CL` | ClassLoader 视图 |

---

## 改动时容易踩的坑

**1. 指针必须先 untag。**
ART 的 `jobject` 带 TBI 标记（实测 `vm` 读出来是 `0xb400007d01a60f00`，高字节 `b4`）。
不解标记直接解引用，所有指针比较都会变成 false，表现为「静默不动」——不报错、不崩，就是没效果。
早期有一次踩这个坑，`mask` 一直是 `0xb`、`L3 located` 一行都不打，排查了很久。

**2. 别在进程内写 ART 链表。**
两次确定性崩溃（`MarkCompact::MarkRoots`、`ThreadList::SuspendAllInternal`）。
外部进程写同样的偏移没事，说明写入本身逻辑对，缺的是线程挂起。
要走视图伪造，不要回头去写。

**3. full RELRO 的 GOT 是只读页。**
按 `prot` 含 `w` 过滤的扫描会静默漏掉。实测命中报告的 `prot=r--p` 就是这个坑。

**4. 符号在导入表里 ≠ 走的是那条路。**
检测器同时存在 `process_vm_readv@plt` 和 `mov w0,#0x10e` 直发 `syscall`。
只接管前者，计数器会一直是 0。必须两条都接。

**5. 验证工具必须走同一条系统调用路径。**
用 `pread` 写的探针无法证明 `process_vm_readv` 拦截生效——它压根不进那条路。
要证明，只能在被接管的路径上计数，或者读检测器自己的判定。

**6. 别用 heredoc 写含转义序列的 C 代码。**
`\n` 会被 shell 吃掉变成真换行，把 `sscanf` 格式串拆坏。
写完必须读回来确认。

**7. 调试日志别只走 logcat。**
logcat 环形缓冲会被冲掉。要么写进应用自己 files 目录的文件（路径要提前 chmod 好），
要么把证据压成一行关键数字。

**8. 虚拟屏是有状态的。**
`am force-stop` 会连带销毁它绑定的虚拟屏；安装 APK 也可能触发重建。
正确顺序：先停进程 → 再建屏 → 再拉起。

---

## 时序决定成败

这是本项目最反直觉的一点：**手法对了，时机不对照样全废**。

检测器的时间线（实测）：

```
T+0.000s  System.loadLibrary
T+0.010s  libantihook.so 映射进内存，GOT 重定位完成
T+0.02s   扫描开始
T+6.0s    ← 早期版本在这里才装接管，早已错过
```

现在的三层抢跑（`JNI_OnLoad` → 2ms 轮询 → 首次读取重扫）就是为这条时间线设计的。
改任何与安装时机相关的代码，先确认这三层还在。

---

## 自证方法

改完不要只看「有没有报错」，要证明它到底生效没有。三个层次的证据，强度递增：

1. **包装被调用**：`VIEWPROOF calls=N` 递增 → 接管确实在路径上
2. **伪造真的生效**：`SELFCHECK real=46 walked=4` → 真实值和读出的值不一样
3. **检测器自己认了**：`VERDICT ... "status":"SAFE"` → 对方的结论

第 3 层是唯一能当交付证据用的。前两层只是排障。

---

## 已知未闭环

- **R-41**：开启第二个 hook 模块时，检测是否会因现场未擦净而泄露。
  需要在实际有第二模块的环境里复现，本机单模块条件下测不出来。
