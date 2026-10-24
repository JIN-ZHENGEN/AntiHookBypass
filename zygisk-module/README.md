# AntiHook Bypass — Zygisk 宿主版

纯 native 的 Zygisk 模块宿主，承载 AntiHook Bypass 的既有引擎。
**不需要 APK、不需要 LSPosed 条目。**

## 为什么做这个

原 LSPosed 版在目标检测里有两条它自己解决不了的痕迹，都来自框架层而不是引擎：

| 痕迹 | 未注入的系统应用 | LSPosed 注入进程 | 判断 |
|---|---|---|---|
| libart.so r-x 内容差 | 191 字节（8 处 4KB 页） | 191 字节（完全相同） | **ART 固有行为**，与注入无关 |
| linker64 r-x 内容差 | 0 字节 | 24 字节 | 与注入相关 |
| libart 段数 | 20（未注入系统应用也是 20） | 20 | 不是注入特征 |

关键实测：**libart 那 191 字节在未注入的相机、联系人进程里一模一样**，
说明它来自 ART 运行时本身（编译产物里的 prebuilt 差异），
换任何注入方式都还在。所以「换 Zygisk 能不能解掉 CRC」只有一个答案是肯定的：
**linker64 那条能解，libart 那条不能**。

## 结构

```
antihookbypass_zygisk/
├── module.prop
└── zygisk/
    ├── arm64-v8a.so
    └── armeabi-v7a.so
```

so 里同时包含三部分：
- `module.cpp` — Zygisk 宿主（onLoad / preAppSpecialize / postAppSpecialize）
- `engine_glue.c` — 把既有引擎接到 Zygisk 生命周期上
- `native_main.c` + `maps_hide.h` — 原封不动复用的引擎（8800 行）

## Java 层迁移：不需要全量翻译

原 Java 层 4133 行，但逐项核对（运行时实测，不是看文档）后，真正需要在 Zygisk 下重建的只有两项。

| 方法 | native? | 官方接口能否覆盖 |
|---|---|---|
| `Class.forName` | 否 | 不能 |
| `ClassLoader.loadClass` / `findClass` | 否 | 不能 |
| `Throwable.getStackTrace` | 否 | 不能 |
| `System.exit` | 否 | 不能 |
| — | — | — 分界 — |
| `Class.getDeclaredField` | 是 | 能 |
| `reflect.Field.get` / `set` | 是 | 能 |
| `VMRuntime.isJavaDebuggable` | 是 | 能 |

`hookJniNativeMethods` 只作用于注册到 JNI 表里的 native 方法，纯 Java 实现的方法它碰不到。

但分界线上那几个**在 Zygisk 下本来就不需要**：

- `Class.forName` / `ClassLoader.loadClass` 的钩子只为了隐藏 `de.robv.android.xposed.*` 等类；Zygisk 进程里根本没有这些类
- `Throwable.getStackTrace` 的钩子只为了删 Xposed 栈帧；同理没有
- `System.exit` 的拦截已由 native 层的 `exit` / `_exit` / `kill` / `tgkill` 接管覆盖

所以这不是「把 Java 层整体翻译成 C」，而是「留下真正需要的两项」。

### 已实现的两个 JNI hook

**`reflect.Field.get`** — 返回值若是 String，就就地改写它内部的 `byte[]`。

必须改字节而不是换字段引用：ART 对「读 final 字段」会做常量折叠，内联成「直接引用那个 String 对象」，换字段引用改不到内联处。这也是原 Java 层 `PathHiding` 走过弯路才定下来的做法。这里在 JNI 层重做，好处是不依赖 Java 反射，也不用绕 hidden API。

**`dalvik.system.VMRuntime.isJavaDebuggable`** — 恒返回 `false`。

对应目标那句 `Android 9.0 Hidden API has been enabled ... indicating the potential presence of Magisk`。它靠「能否调通 @hide API」反推 root。LSPosed 会给注入进程开 hiddenapi 豁免，所以那边必然为 true。

### 两个刻意不做的决定

**不装 `Throwable.nativeGetStackTrace`。** 它原本只为了删 Xposed 栈帧，Zygisk 进程里不会有那种帧。保留一个「原样返回、什么都不做」的 hook 是纯负收益——看起来像在防御，实际只增加失败面。

**不迁移 `KillGuard` 的 Java 部分。** `System.exit` / `Process.killProcess` 的拦截在 Zygisk 侧由 native 层的 `exit` / `_exit` / `kill` / `raise` / `abort` / `tgkill` / `exit_group` 七个入口接管，覆盖面比 Java 层更广（Java 层拦不到 native 直接调 `_exit`）。

### 一个修掉的真 bug

`my_field_get` 初版写成：

```c
if (r && (*env)->GetObjectClass(env, r)) { ... }
```

每调用一次就多一个未删除的 local ref。`Field.get` 是热路径，目标循环调用几百次就会撑爆 local reference table（默认 512），随后 JNI 调用全部失败。

改成缓存的 global ref 之后，整条路径零 local ref 产生。

## 与 LSPosed 版的能力对照

| 能力 | LSPosed 版 | Zygisk 版 |
|---|---|---|
| maps 视图过滤 | ✅ | ✅ 复用同一份 |
| GOT/PLT 热补丁 | ✅ 手工实现 | ✅ 复用，也可改用官方 `pltHookRegister` |
| JVMTI 中和 | ✅ | ✅ 复用 |
| 路径/dev/inode 自洽 | ✅ | ✅ 复用 |
| readlink 伪装 | ✅ | ✅ 复用 |
| Java 层 hook（`Class.forName` 等） | ✅ | ❌ 无 Java 层 |
| 进程内 InMemoryDexClassLoader | 有（LSPosed 自己的） | **无** |
| 改 linker64 | 有（框架层） | **无** |

最后两行是这个路线真正的收益。

## 构建

```sh
bash build.sh   # 需要 NDK 26.3.11579264
bash pack.sh    # 输出 build/antihookbypass_zygisk.zip
```

## 安装

```sh
# 方式一：KernelSU 管理器的「模块」页刷入 zip
# 方式二：
unzip -o antihookbypass_zygisk.zip -d /data/adb/modules/antihookbypass_zygisk/
```

**必须重启 zygote 才生效**（Zygisk Next 在启动时扫描模块列表并缓存到
`/data/adb/zygisksu/modules_info`，新增模块不在缓存里就不会被加载）。

## 已知状态

- so 已验证可 `dlopen`，`zygisk_module_entry` 与
  `Java_com_rev_antihookbypass_NativeLayer_nativeSanitizeRuntime` 均正确导出
- 所有 UND 符号在 `libc` / `libdl` / `liblog` / `libc++` 中均可解析
- **尚未在真机验证 zygisk 实际调用**：需要重启 zygote，
  该操作在本次会话被明确禁止，留给用户执行

## 许可

`jni/zygisk.hpp` 逐字取自 topjohnwu/zygisk-module-sample，0BSD。
