package com.rev.antihookbypass;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * L2 + L3 原生层加载与触发编排。
 */
final class NativeLayer {

    private NativeLayer() {
    }

    private static final String LIB = "antihook_bypass";

    private static volatile boolean loaded = false;
    private static volatile boolean available = false;

    /**
     * 触发原生层执行 L2（ELF 代码段还原 + 匿名可执行跳板页收敛）。
     *
     * @param ops L2 内部分项位，见 {@link ModuleConfig#NATIVE_ART} 等；
     *            传 0 表示三项全开。
     * @return 位掩码：bit0=代码段还原执行成功，bit1=匿名段收敛执行成功
     */
    private static native int nativeSanitizeRuntime(int ops);

    /**
     * 按需交换 libart 代码段（1=临时换成磁盘字节，0=换回原字节）。
     * 用于"内存 CRC 与文件 CRC 一致"这类判定：只在计算瞬间成立，
     * 其他时刻其他模块的 hook 完好无损。
     */
    private static native void nativeArtSwap(int on);

    /** 取证：各条 maps 通道的命中次数 */
    private static native String nativeChannelCounts();

    static String channelCounts() {
        try {
            return nativeChannelCounts();
        } catch (Throwable t) {
            return "n/a";
        }
    }

    /** 是否可用（native 库已加载且差异表非空） */
    private static volatile boolean s_swapReady = false;

    static boolean swapReady() {
        return s_swapReady;
    }

    static void swap(int on) {
        if (!s_swapReady) return;
        try {
            nativeArtSwap(on);
        } catch (Throwable ignored) {
        }
    }

    static void markSwapReady() {
        s_swapReady = true;
    }

    static boolean installAndSanitize(Context ctx) {
        boolean ok = ensureLoaded(ctx);
        if (ok) {
            try {
                int ops = ModuleConfig.nativeOps();
                int mask = nativeSanitizeRuntime(ops);
                HookEntry.log("L2 nativeSanitizeRuntime 完成 ops=0x" + Integer.toHexString(ops)
                        + " mask=0x" + Integer.toHexString(mask));
            } catch (Throwable t) {
                HookEntry.log("nativeSanitizeRuntime 调用异常: " + t);
            }
        }
        return ok;
    }

    private static boolean ensureLoaded(Context ctx) {
        if (loaded) return available;
        synchronized (NativeLayer.class) {
            if (loaded) return available;
            loaded = true;

            try {
                System.loadLibrary(LIB);
                available = true;
                HookEntry.log("L2+L3 native 已通过 System.loadLibrary 加载");
                return true;
            } catch (Throwable t1) {
                /*
                 * 不再回退到「把 so 解包到目标 App 的 code_cache」。
                 *
                 * 那个回退路径会把 libantihook_bypass.so 写进
                 * /data/user/0/<目标包>/code_cache/abl/ —— 目标应用
                 * 只要看一眼自己的 code_cache，就能看到一个不属于它的
                 * 陌生 .so 和目录名。这是比日志文件更直接的暴露。
                 *
                 * 模块的 so 本来就能被 Xposed 的 classloader 找到
                 * （loadLibrary 走的是模块 apk 的 native 库目录），
                 * 所以正常情况根本不需要解包。真的加载不了时，
                 * 宁可 native 层不可用，也不在目标目录留文件。
                 */
                available = false;
                HookEntry.log("native 加载失败（不落盘不降级到解包）: " + t1);
                return false;
            }
        }
    }

    private static String currentPackageName() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object pkg = at.getMethod("currentPackageName").invoke(null);
            if (pkg instanceof String) return (String) pkg;
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static String findModuleApk() {
        final String PKG = "com.rev.antihookbypass";
        try {
            String clStr = NativeLayer.class.getClassLoader().toString();
            int idx = clStr.indexOf("/data/app/");
            if (idx >= 0) {
                int end = clStr.indexOf(".apk", idx);
                if (end > idx) {
                    String p = clStr.substring(idx, end + 4);
                    if (new File(p).exists()) return p;
                }
            }
        } catch (Throwable ignored) {
        }
        try {
            File appDir = new File("/data/app");
            File[] l1 = appDir.listFiles();
            if (l1 != null) {
                for (File d1 : l1) {
                    if (d1.getName().contains(PKG)) {
                        File b = new File(d1, "base.apk");
                        if (b.exists()) return b.getAbsolutePath();
                    }
                    File[] l2 = d1.listFiles();
                    if (l2 == null) continue;
                    for (File d2 : l2) {
                        if (d2.getName().contains(PKG)) {
                            File b = new File(d2, "base.apk");
                            if (b.exists()) return b.getAbsolutePath();
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static String pickAbi() {
        String[] abis = android.os.Build.SUPPORTED_ABIS;
        if (abis != null && abis.length > 0) return abis[0];
        return android.os.Build.CPU_ABI != null ? android.os.Build.CPU_ABI : "arm64-v8a";
    }
}
