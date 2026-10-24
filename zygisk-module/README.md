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
