package com.rev.antihookbypass;

import android.content.Context;
import android.content.pm.ApplicationInfo;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import de.robv.android.xposed.XposedHelpers;

/**
 * Native 层（L2 + L3）加载与编排。
 *
 * <h2>这一层做什么</h2>
 * 处理 Java 层打不到的部分：检测在 native 里直接读 {@code /proc/self/maps}、
 * 做内存 CRC、fork 子进程 ptrace 回读自己。分两个子层：
 *
 * <ul>
 *   <li><b>L2 具名函数</b>：替换 libc 的 open/openat/ptrace/fork/prctl/
 *       process_vm_readv。</li>
 *   <li><b>L3 syscall 入口</b>：替换 libc 的 {@code syscall()} 通用入口，
 *       拦住 {@code syscall(SYS_openat, ...)} 这种绕法。</li>
 * </ul>
 *
 * <h2>为什么不能直接 System.loadLibrary</h2>
 * LSPosed 把模块 dex 放在内存里（{@code InMemoryDexFile}），
 * 模块的 nativeLibraryDirectories 虽然指向
 * {@code base.apk!/lib/arm64-v8a}，但那是个**不存在的伪路径** ——
 * 系统不会去 APK 里解压。
 *
 * <p>实测直接 {@code System.loadLibrary("antihook_bypass")} 会报：
 * <pre>
 *   UnsatisfiedLinkError: couldn't find "libantihook_bypass.so"
 * </pre>
 *
 * <p>所以必须自己去 APK 里把 so 解出来，落到模块自己的数据目录，
 * 再用绝对路径 {@code System.load()}。
 *
 * <h2>失败处理</h2>
 * native 层加载失败不影响 L1 —— L1 本身就能覆盖绝大多数检测。
 * 只记日志，不抛异常。
 */
final class NativeLayer {

    private NativeLayer() {
    }

    private static final String LIB = "antihook_bypass";
    private static final String LIB_FILE = "libantihook_bypass.so";

    private static volatile boolean loaded = false;
    private static volatile boolean available = false;

    /** 已解压出来的 so 路径缓存（同一进程只解一次） */
    private static volatile String cachedSoPath = null;

    static boolean install(Context ctx) {
        HookEntry.log("NativeLayer.install 进入 ctx=" + (ctx != null ? ctx.getPackageName() : "null")
                + " loaded=" + loaded + " available=" + available);
        if (loaded) return available;
        synchronized (NativeLayer.class) {
            if (loaded) return available;
            loaded = true;

            // 路线 1：常规 loadLibrary（模块被正常安装解压时可走这条）
            try {
                System.loadLibrary(LIB);
                available = true;
                HookEntry.log("L2+L3 native 已加载（loadLibrary）");
                return true;
            } catch (Throwable t1) {
                HookEntry.log("loadLibrary 失败: " + t1.getMessage());
            }

            // 路线 2：从 APK 里解出 so，再按绝对路径加载
            try {
                String path = extractSo(ctx);
                if (path == null) throw new RuntimeException("解包 so 失败");
                System.load(path);
                available = true;
                HookEntry.log("L2+L3 native 已加载（解包路径）: " + path);
                return true;
            } catch (Throwable t) {
                available = false;
                HookEntry.log("native 加载失败，降级为仅 L1（功能仍可用）: " + t);
                return false;
            }
        }
    }

    /**
     * 从模块自己的 APK 里解出 so。
     *
     * <p>路径优先级：
     * <ol>
     *   <li>模块 APK 的 sourceDir（最可靠）</li>
     *   <li>模块自己 dataDir 里已解压过的副本（二次启动直接复用）</li>
     * </ol>
     *
     * <p>用模块自身的 Context 拿路径，而不是宿主的 —— 否则会解错包。
     */
    private static String extractSo(Context hostCtx) {
        if (cachedSoPath != null && new File(cachedSoPath).exists()) {
            return cachedSoPath;
        }

        /*
         * 关键：找出"模块自己"的 APK 路径。
         *
         * 难点：
         *   - hostCtx.getApplicationInfo().sourceDir 是**宿主**的 APK，不是模块的；
         *   - createPackageContext("com.rev.antihookbypass", ...) 在部分 ROM 上
         *     会抛 NameNotFoundException（跨包访问受限）；
         *   - LSPosed 用 InMemoryDexFile 加载模块 dex，
         *     所以模块并没有一个"已加载的路径"可直接读。
         *
         * 解法：从 Xposed 框架自己的数据结构里拿。
         * LSPosed 会把模块 APK 路径放在 LoadedApk 的 modulePath 字段里，
         * 而 LoadedApk 挂在 ActivityThread 的 mPackages 表中。
         * 三条路依次尝试，任一成功即可。
         */
        String apkPath = findModuleApk(hostCtx);
        if (apkPath == null) {
            HookEntry.log("extractSo: 找不到模块 APK 路径");
            return null;
        }
        HookEntry.log("extractSo: 模块 APK = " + apkPath);

        /*
         * 找可写目录。不能只依赖 hostCtx ——
         * handleLoadPackage 阶段 currentApplication() 还是 null。
         * 按可用性依次尝试：
         *   1. 宿主 codeCacheDir
         *   2. 宿主 dataDir
         *   3. /data/local/tmp（多数设备本应用可读写）
         */
        File outDir = null;
        if (hostCtx != null) {
            try {
                File d = new File(hostCtx.getCodeCacheDir(), "abl");
                if (d.exists() || d.mkdirs()) outDir = d;
            } catch (Throwable ignored) {
            }
            if (outDir == null) {
                try {
                    File d = new File(hostCtx.getFilesDir(), "abl");
                    if (d.exists() || d.mkdirs()) outDir = d;
                } catch (Throwable ignored) {
                }
            }
        }
        // 路线 3：用 ActivityThread 的 mInitialApplication（在 handleLoadPackage 之后可用）
        if (outDir == null) {
            try {
                Class<?> at = Class.forName("android.app.ActivityThread");
                Object th = at.getMethod("currentActivityThread").invoke(null);
                java.lang.reflect.Field f = at.getDeclaredField("mInitialApplication");
                f.setAccessible(true);
                Object app = f.get(th);
                if (app instanceof Context) {
                    Context cx = (Context) app;
                    File d = new File(cx.getCodeCacheDir(), "abl");
                    if (d.exists() || d.mkdirs()) outDir = d;
                    if (outDir == null) {
                        File d2 = new File(cx.getFilesDir(), "abl");
                        if (d2.exists() || d2.mkdirs()) outDir = d2;
                    }
                }
            } catch (Throwable ignored) {
            }
        }

        // 路线 4：直接拼进程私有目录。
        //   为什么可行：当前进程就是这个 uid，/data/data/<自己包名> 必然可写，
        //   不需要任何 Context 对象，也不需要查询包管理器。
        //   包名从 ActivityThread.mBoundApplication.appInfo.packageName 拿。
        if (outDir == null) {
            String selfPkg = null;
            try {
                Class<?> at = Class.forName("android.app.ActivityThread");
                Object th = at.getMethod("currentActivityThread").invoke(null);
                java.lang.reflect.Field bf = at.getDeclaredField("mBoundApplication");
                bf.setAccessible(true);
                Object ba = bf.get(th);
                if (ba != null) {
                    java.lang.reflect.Field af = ba.getClass().getDeclaredField("appInfo");
                    af.setAccessible(true);
                    Object ai = af.get(ba);
                    if (ai != null) {
                        java.lang.reflect.Field pf = ai.getClass().getField("packageName");
                        Object pn = pf.get(ai);
                        if (pn instanceof String) selfPkg = (String) pn;
                    }
                }
            } catch (Throwable ignored) {
            }
            if (selfPkg != null) {
                for (String base : new String[]{"/data/data/", "/data/user/0/"}) {
                    try {
                        File d = new File(base + selfPkg + "/code_cache/abl");
                        if (d.exists() || d.mkdirs()) { outDir = d; break; }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }

        // 路线 5：/data/local/tmp
        if (outDir == null) {
            try {
                File d = new File("/data/local/tmp");
                if (d.exists() && d.canWrite()) {
                    File sub = new File(d, "abl_" + android.os.Process.myPid());
                    if (sub.exists() || sub.mkdirs()) outDir = sub;
                }
            } catch (Throwable ignored) {
            }
        }
        if (outDir == null) {
            HookEntry.log("extractSo: 没有可写目录");
            return null;
        }

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
                    if (n.startsWith("lib/") && n.endsWith("/" + LIB_FILE)) { e = z; break; }
                }
            }
            if (e == null) {
                HookEntry.log("extractSo: APK 里没有 " + LIB_FILE);
                return null;
            }
            File tmp = new File(outDir, LIB_FILE + ".tmp");
            if (tmp.exists()) tmp.delete();
            in = zip.getInputStream(e);
            fos = new FileOutputStream(tmp);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
            fos.flush(); fos.close(); fos = null;
            in.close(); in = null;

            if (out.exists()) out.delete();
            if (!tmp.renameTo(out)) {
                HookEntry.log("extractSo: rename 失败");
                tmp.delete();
                return null;
            }
            cachedSoPath = out.getAbsolutePath();
            HookEntry.log("extractSo: 成功 " + cachedSoPath + " (" + out.length() + "B)");
            return cachedSoPath;
        } catch (Throwable t) {
            HookEntry.log("extractSo 异常: " + t);
            return null;
        } finally {
            try { if (fos != null) fos.close(); } catch (Throwable ignored) {}
            try { if (in != null) in.close(); } catch (Throwable ignored) {}
            try { if (zip != null) zip.close(); } catch (Throwable ignored) {}
        }
    }

    /**
     * 找出模块自己的 APK 路径。
     *
     * <p>按可靠性排序尝试：
     * <ol>
     *   <li>LSPosed 的 LoadedApk.modulePath（最准确）；</li>
     *   <li>从 ActivityThread.mPackages 里按包名找；</li>
     *   <li>createPackageContext（部分 ROM 可用）；</li>
     *   <li>扫描 /data/app 下本模块的 base.apk（最后兜底）。</li>
     * </ol>
     */
    private static String findModuleApk(Context hostCtx) {
        final String PKG = "com.rev.antihookbypass";

        // 路线 1 & 2：ActivityThread.mPackages -> LoadedApk.modulePath / getResDir
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object thread = at.getMethod("currentActivityThread").invoke(null);
            java.lang.reflect.Field f = at.getDeclaredField("mPackages");
            f.setAccessible(true);
            Map<?, ?> pkgs = (Map<?, ?>) f.get(thread);
            if (pkgs != null) {
                Object apk = pkgs.get(PKG);
                if (apk != null) {
                    // LoadedApk 里可能的字段名
                    for (String fn : new String[]{"modulePath", "mModulePath"}) {
                        try {
                            java.lang.reflect.Field mf = apk.getClass().getDeclaredField(fn);
                            mf.setAccessible(true);
                            Object v = mf.get(apk);
                            if (v instanceof String && new File((String) v).exists()) {
                                return (String) v;
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                    // 退而用 getResDir / getAppDir
                    try {
                        Object rd = apk.getClass().getMethod("getResDir").invoke(apk);
                        if (rd instanceof String && new File((String) rd).exists()) return (String) rd;
                    } catch (Throwable ignored) {
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        // 路线 3：createPackageContext
        try {
            Context c = hostCtx.createPackageContext(PKG, Context.CONTEXT_IGNORE_SECURITY);
            if (c != null && c.getApplicationInfo() != null
                    && c.getApplicationInfo().sourceDir != null) {
                return c.getApplicationInfo().sourceDir;
            }
        } catch (Throwable ignored) {
        }

        // 路线 4：扫 /data/app 找本模块。
        //   注意 /data/app 下是两级结构：/data/app/~~hash==/pkg-hash==/base.apk，
        //   所以要递归一层。
        try {
            File appRoot = new File("/data/app");
            File[] lvl1 = appRoot.listFiles();
            if (lvl1 != null) {
                for (File d1 : lvl1) {
                    String n1 = d1.getName();
                    if (n1.startsWith(PKG)) {
                        File base = new File(d1, "base.apk");
                        if (base.exists()) return base.getAbsolutePath();
                    }
                    File[] lvl2 = d1.listFiles();
                    if (lvl2 == null) continue;
                    for (File d2 : lvl2) {
                        if (!d2.getName().startsWith(PKG)) continue;
                        File base = new File(d2, "base.apk");
                        if (base.exists()) return base.getAbsolutePath();
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        // 路线 4.5：从模块自己的 ClassLoader 反查。
        //   LSPosed 用 LspModuleClassLoader，它的 toString() 里带 APK 路径，
        //   形如 LspModuleClassLoader[module=/data/app/.../base.apk, ...]
        try {
            ClassLoader cl = NativeLayer.class.getClassLoader();
            if (cl != null) {
                String s = cl.toString();
                int i = s.indexOf("module=");
                if (i >= 0) {
                    int b = s.indexOf('=', i) + 1;
                    int e = s.indexOf(',', b);
                    if (e < 0) e = s.indexOf(']', b);
                    if (e > b) {
                        String path = s.substring(b, e).trim();
                        if (path.endsWith(".apk") && new File(path).exists()) {
                            HookEntry.log("从 ClassLoader 拿到模块 APK: " + path);
                            return path;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        // 路线 5：从已加载的模块类反查其 CodeSource
        try {
            java.security.CodeSource cs =
                    NativeLayer.class.getProtectionDomain().getCodeSource();
            if (cs != null && cs.getLocation() != null) {
                String p = cs.getLocation().getPath();
                if (p != null && p.endsWith(".apk") && new File(p).exists()) return p;
            }
        } catch (Throwable ignored) {
        }

        return null;
    }

    /** 当前进程的 ABI */
    private static String pickAbi() {
        String[] abis = android.os.Build.SUPPORTED_ABIS;
        if (abis != null && abis.length > 0) return abis[0];
        return android.os.Build.CPU_ABI != null ? android.os.Build.CPU_ABI : "arm64-v8a";
    }

    /**
     * 取模块自己的 Context。
     *
     * <p>{@code AndroidAppHelper.currentApplication()} 拿到的是<b>宿主</b>的，
     * 不能用来定位模块 APK。正确做法是通过 Xposed 的
     * {@code AndroidAppHelper} 取模块资源，或直接用反射读
     * {@code ActivityThread} 里模块的 LoadedApk。
     *
     * <p>这里用最稳的一条：{@code XposedHelpers} 拿不到模块 Context 时，
     * 退化为反射构造。失败返回 null，由调用方降级。
     */

    static boolean isActive() {
        return available;
    }
}
