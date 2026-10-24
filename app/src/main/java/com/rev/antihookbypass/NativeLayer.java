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
    private static final String LIB_FILE = "libantihook_bypass.so";

    private static volatile boolean loaded = false;
    private static volatile boolean available = false;
    private static volatile String cachedSoPath = null;

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
                HookEntry.log("loadLibrary 回退解包路径: " + t1.getMessage());
            }

            try {
                String path = extractSo(ctx);
                if (path == null) throw new RuntimeException("extractSo 返回 null");
                System.load(path);
                available = true;
                HookEntry.log("L2+L3 native 已通过解包路径加载: " + path);
                return true;
            } catch (Throwable t2) {
                available = false;
                HookEntry.log("native 加载失败: " + t2);
                return false;
            }
        }
    }

    private static String extractSo(Context hostCtx) {
        if (cachedSoPath != null && new File(cachedSoPath).exists()) {
            return cachedSoPath;
        }
        String apkPath = findModuleApk();
        if (apkPath == null) return null;

        File outDir = null;
        if (hostCtx != null) {
            try {
                File d = new File(hostCtx.getCodeCacheDir(), "abl");
                if (d.exists() || d.mkdirs()) outDir = d;
            } catch (Throwable ignored) {
            }
        }
        if (outDir == null) {
            String selfPkg = currentPackageName();
            if (selfPkg != null) {
                for (String base : new String[]{"/data/user/0/", "/data/data/"}) {
                    try {
                        File d = new File(base + selfPkg + "/code_cache/abl");
                        if (d.exists() || d.mkdirs()) {
                            outDir = d;
                            break;
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
        if (outDir == null) return null;

        File out = new File(outDir, LIB_FILE);
        String abi = pickAbi();

        ZipFile zip = null;
        InputStream in = null;
        FileOutputStream fos = null;
        try {
            zip = new ZipFile(apkPath);
            ZipEntry e = zip.getEntry("lib/" + abi + "/" + LIB_FILE);
            if (e == null) {
                java.util.Enumeration<? extends ZipEntry> en = zip.entries();
                while (en.hasMoreElements()) {
                    ZipEntry z = en.nextElement();
                    String n = z.getName();
                    if (n.startsWith("lib/") && n.endsWith("/" + LIB_FILE)) {
                        e = z;
                        break;
                    }
                }
            }
            if (e == null) return null;

            File tmp = new File(outDir, LIB_FILE + ".tmp");
            if (tmp.exists()) tmp.delete();
            in = zip.getInputStream(e);
            fos = new FileOutputStream(tmp);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
            fos.flush();
            fos.close();
            fos = null;
            in.close();
            in = null;

            if (out.exists()) out.delete();
            if (!tmp.renameTo(out)) {
                tmp.delete();
                return null;
            }
            cachedSoPath = out.getAbsolutePath();
            return cachedSoPath;
        } catch (Throwable ignored) {
            return null;
        } finally {
            try { if (fos != null) fos.close(); } catch (Throwable ignored) {}
            try { if (in != null) in.close(); } catch (Throwable ignored) {}
            try { if (zip != null) zip.close(); } catch (Throwable ignored) {}
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
