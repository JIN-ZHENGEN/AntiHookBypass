package com.rev.antihookbypass;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * L1 框架痕迹压制层 —— 面向 Java 层类探测、调用栈与调试状态检测。
 *
 * 性能修复（anti-cpu-hotfix）：
 *   Throwable.getStackTrace / Thread.getAllStackTraces / StackWalker.walk
 *   在宿主（尤其 QQ 这类超大进程）启动与运行期被高频调用。原实现每次调用
 *   都对整条调用栈逐帧做 getClassName()+字符串匹配并重建数组，在数百线程、
 *   栈深数百帧的进程里被放大成 CPU 黑洞，表现为主线程常驻 Runnable、高占用、ANR。
 *
 *   修复：对"未含框架帧"的栈（绝大多数业务调用都属于这一类）做带 TTL 的结果缓存，
 *   同线程在窗口期内直接返回上次的原始/过滤结果，不再逐帧重建。
 *   只有真正出现框架帧（需要剥离）时才走完整 filter，且结果同样被缓存。
 *   这样高频业务调用基本零成本，隐藏能力对检测器的取栈仍然生效。
 */
final class TraceHide {

    private TraceHide() {
    }

    /** 判定框架痕迹的关键词 */
    private static final String[] MARKS = {
            "de.robv.android.xposed",
            "org.lsposed",
            "io.github.lsposed",
            "io.github.libxposed",
            "XposedBridge",
            "XposedHelpers",
            "XposedInit",
            "XposedModule",
            "EdXposed",
            "org.meowcat",
            "com.elderdrivers.riru",
            "LSPosed",
            "LspModuleClassLoader",
            "com.rev.antihookbypass",
    };

    /**
     * getStackTrace 结果缓存（anti-cpu-hotfix v2）。
     *
     * 原做法以 StackTraceElement[] 数组身份为 key，但 getStackTrace 每次都
     * new 一个全新数组，key 永不相同 → 缓存 100% miss，等于没缓存。
     *
     * 正确做法：以「线程 + 栈指纹」为 key。
     *   指纹 = 最近 FINGERPRINT_DEPTH 帧的 className.hashCode() 混合。
     *   同一线程反复取栈（业务代码在热点循环里取栈、检测器轮询）指纹稳定 → 命中。
     *   指纹不同（换调用点）才走一次完整 filter。
     * 用 ThreadLocal 持有本线程上一份结果，避免全局 map 的锁竞争与 GC 压力。
     */
    private static final int FINGERPRINT_DEPTH = 8;
    private static final long TRACE_TTL_MS = 200L;

    private static final class TraceCache {
        long fp;
        long ts;
        StackTraceElement[] value;
    }

    private static final ThreadLocal<TraceCache> TL_TRACE_CACHE = new ThreadLocal<TraceCache>();

    /** 计算栈指纹：取前 depth 帧的类名 + 方法名哈希混合。 */
    private static long fingerprint(StackTraceElement[] frames) {
        int n = frames.length < FINGERPRINT_DEPTH ? frames.length : FINGERPRINT_DEPTH;
        long h = 1125899906842597L;
        for (int i = 0; i < n; i++) {
            StackTraceElement e = frames[i];
            if (e == null) {
                h = h * 31 + 7;
                continue;
            }
            String cn = e.getClassName();
            String mn = e.getMethodName();
            h = h * 31 + (cn == null ? 0 : cn.hashCode());
            h = h * 31 + (mn == null ? 0 : mn.hashCode());
        }
        /* 长度也纳入指纹：同前缀不同深度视为不同栈 */
        h = h * 31 + (long) frames.length;
        return h;
    }

    static void install(ClassLoader cl) {
        hookClassLoaderLoadClass();
        hookStackTrace();
        hookStackTraceDeep();
        hookAllStackTraces();
        hookStackWalker();
        hookXposedVersion();
        hookDebugger();
        hookStackTraceElementToString();

        hookInstalledPackages();
        hookSystemProperties();
        hookRuntimeProbes();
        hookClassLoaderVisibility();
    }

    /* ================= 应用层检测面加固 ================= */

    private static void hookInstalledPackages() {
        try {
            Class<?> apm = Class.forName("android.app.ApplicationPackageManager");
            XposedHelpers.findAndHookMethod(
                    apm,
                    "getInstalledPackages", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof java.util.List) {
                                param.setResult(filterPackages((java.util.List<?>) r));
                            }
                        }
                    });
            XposedHelpers.findAndHookMethod(
                    apm,
                    "getInstalledApplications", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof java.util.List) {
                                param.setResult(filterPackages((java.util.List<?>) r));
                            }
                        }
                    });
            HookEntry.log("安装包枚举过滤已挂");
        } catch (Throwable t) {
            HookEntry.log("安装包枚举过滤失败: " + t);
        }
    }

    private static java.util.List<?> filterPackages(java.util.List<?> in) {
        java.util.ArrayList<Object> out = new java.util.ArrayList<>(in.size());
        for (Object o : in) {
            String pkg = null;
            try {
                if (o instanceof android.content.pm.PackageInfo) {
                    pkg = ((android.content.pm.PackageInfo) o).packageName;
                } else if (o instanceof android.content.pm.ApplicationInfo) {
                    pkg = ((android.content.pm.ApplicationInfo) o).packageName;
                }
            } catch (Throwable ignored) {
            }
            if (pkg != null && isFrameworkPackage(pkg)) continue;
            out.add(o);
        }
        return out;
    }

    private static boolean isFrameworkPackage(String pkg) {
        if (pkg == null) return false;
        if (pkg.equals("com.rev.antihookbypass")) return true;
        if (pkg.equals("org.lsposed.manager")) return true;
        if (pkg.startsWith("org.lsposed.")) return true;
        if (pkg.startsWith("io.github.lsposed")) return true;
        if (pkg.startsWith("io.github.libxposed")) return true;
        if (pkg.startsWith("de.robv.android.xposed")) return true;
        return false;
    }

    private static void hookSystemProperties() {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            XposedBridge.hookAllMethods(sp, "get", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Object a0 = param.args.length > 0 ? param.args[0] : null;
                    if (a0 instanceof String && isFrameworkProp((String) a0)) {
                        param.setResult("");
                    }
                }
            });
            HookEntry.log("系统属性屏蔽已挂");
        } catch (Throwable t) {
            HookEntry.log("系统属性屏蔽失败: " + t);
        }
    }

    private static boolean isFrameworkProp(String key) {
        if (key == null) return false;
        String k = key.toLowerCase(java.util.Locale.ROOT);
        if (k.contains("lsposed")) return true;
        if (k.contains("xposed")) return true;
        if (k.contains("edxposed")) return true;
        if (k.equals("ro.debuggable")) return false;
        return false;
    }

    private static void hookRuntimeProbes() {
        try {
            XposedHelpers.findAndHookMethod(
                    java.lang.Runtime.class, "exec",
                    String[].class, String[].class, java.io.File.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object cmd = param.args.length > 0 ? param.args[0] : null;
                            if (cmd instanceof String[] && isFrameProbe((String[]) cmd)) {
                                param.setResult(null);
                            }
                        }
                    });
            HookEntry.log("运行时命令探测拦截已挂");
        } catch (Throwable t) {
            HookEntry.log("运行时命令探测拦截失败: " + t);
        }
    }

    private static boolean isFrameProbe(String[] cmd) {
        if (cmd.length == 0 || cmd[0] == null) return false;
        String c = cmd[0].toLowerCase(java.util.Locale.ROOT);
        if (c.contains("lspd") || c.contains("lsposed") || c.contains("xposed")) return true;
        return false;
    }

    private static void hookClassLoaderVisibility() {
        try {
            XposedHelpers.findAndHookMethod(
                    ClassLoader.class, "getParent", new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof ClassLoader && isFrameworkLoader((ClassLoader) r)) {
                                param.setResult(null);
                            }
                        }
                    });
            HookEntry.log("类加载器可见性收敛已挂");
        } catch (Throwable t) {
            HookEntry.log("类加载器可见性收敛失败: " + t);
        }
    }

    private static boolean isFrameworkLoader(ClassLoader cl) {
        if (cl == null) return false;
        String n = cl.getClass().getName();
        for (String m : MARKS) {
            if (n.contains(m)) return true;
        }
        return false;
    }

    static void installOnly(int which) {
        switch (which) {
            case 1: hookForName(); break;
            case 2: hookStackTrace(); break;
            case 3: hookStackTraceDeep(); break;
            case 4: hookAllStackTraces(); break;
            case 5: hookStackWalker(); break;
            case 6: hookXposedVersion(); break;
            case 7: hookDebugger(); break;
            case 8: hookStackTraceElementToString(); break;
            case 11: hookClassForName(); break;
            case 12: hookClassLoaderLoadClass(); break;
            case 21: hookForName1(); break;
            case 22: hookForName3(); break;
            default: break;
        }
    }

    private static void hookForName1() {
        try {
            XposedHelpers.findAndHookMethod(Class.class, "forName", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String name = firstStringArg(param.args);
                            if (!isFrameworkName(name)) return;
                            if (fromSelfOrFramework()) return;
                            HookEntry.log("拦截 forName1: " + name + " caller=" + firstRealFrame());
                            param.setThrowable(new ClassNotFoundException(name));
                        }
                    });
        } catch (Throwable t) {
            HookEntry.log("挂 forName1 失败: " + t);
        }
    }

    private static void hookForName3() {
        try {
            XposedHelpers.findAndHookMethod(Class.class, "forName",
                    String.class, boolean.class, ClassLoader.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String name = firstStringArg(param.args);
                            if (!isFrameworkName(name)) return;
                            if (fromSelfOrFramework()) return;
                            HookEntry.log("拦截 forName3: " + name + " caller=" + firstRealFrame());
                            param.setThrowable(new ClassNotFoundException(name));
                        }
                    });
        } catch (Throwable t) {
            HookEntry.log("挂 forName3 失败: " + t);
        }
    }

    private static void hookForName() {
        hookClassForName();
        hookClassLoaderLoadClass();
    }

    private static void hookClassForName() {
        try {
            XposedBridge.hookAllMethods(Class.class, "forName", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String name = firstStringArg(param.args);
                    if (!isFrameworkName(name)) return;
                    if (fromSelfOrFramework()) return;
                    HookEntry.log("拦截 forName: " + name + " caller=" + firstRealFrame());
                    param.setThrowable(new ClassNotFoundException(name));
                }
            });
        } catch (Throwable t) {
            HookEntry.log("挂 forName 失败: " + t);
        }
    }

    private static void hookClassLoaderLoadClass() {
        try {
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String name = firstStringArg(param.args);
                    if (!isFrameworkName(name)) return;
                    if (fromSelfOrFramework()) return;
                    HookEntry.log("拦截 loadClass: " + name + " caller=" + firstRealFrame());
                    param.setThrowable(new ClassNotFoundException(name));
                }
            });
        } catch (Throwable t) {
            HookEntry.log("挂 loadClass 失败: " + t);
        }
    }

    private static String firstRealFrame() {
        try {
            StackTraceElement[] st = Thread.currentThread().getStackTrace();
            int end = Math.min(st.length, 24);
            for (int i = 0; i < end; i++) {
                StackTraceElement e = st[i];
                if (e == null) continue;
                String cn = e.getClassName();
                if (cn == null) continue;
                if (cn.equals("java.lang.Thread") || cn.equals("dalvik.system.VMStack")) continue;
                if (cn.startsWith("com.rev.antihookbypass.TraceHide")) continue;
                if (cn.startsWith("java.lang.reflect.")) continue;
                if (cn.startsWith("de.robv.android.xposed.XposedBridge")) continue;
                return cn + "." + e.getMethodName();
            }
        } catch (Throwable ignored) {
        }
        return "?";
    }

    private static String firstStringArg(Object[] args) {
        if (args == null) return null;
        for (Object a : args) {
            if (a instanceof String) return (String) a;
        }
        return null;
    }

    static boolean isFrameworkName(String name) {
        if (name == null) return false;
        for (String m : MARKS) {
            if (name.contains(m)) return true;
        }
        return false;
    }

    private static boolean fromSelfOrFramework() {
        try {
            StackTraceElement[] st = Thread.currentThread().getStackTrace();
            int end = Math.min(st.length, 32);
            for (int i = 0; i < end; i++) {
                StackTraceElement e = st[i];
                if (e == null) continue;
                String cn = e.getClassName();
                String mn = e.getMethodName();
                if (cn == null) continue;
                if (cn.equals("java.lang.Thread") || cn.equals("dalvik.system.VMStack")) continue;
                if (cn.startsWith("com.rev.antihookbypass.TraceHide$")) continue;
                if (cn.equals("com.rev.antihookbypass.TraceHide") && "fromSelfOrFramework".equals(mn)) continue;
                if (cn.startsWith("java.lang.reflect.") || cn.startsWith("J.")) continue;
                if (cn.equals("java.lang.Class") && "forName".equals(mn)) continue;
                if (cn.endsWith("ClassLoader") && ("loadClass".equals(mn) || "findClass".equals(mn))) continue;
                if (cn.startsWith("de.robv.android.xposed.XposedBridge")) continue;

                return cn.startsWith("com.rev.antihookbypass")
                        || cn.startsWith("de.robv.android.xposed")
                        || cn.startsWith("org.lsposed")
                        || cn.startsWith("io.github.libxposed");
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static void hookStackTrace() {
        try {
            XposedHelpers.findAndHookMethod(Throwable.class, "getStackTrace", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Object r = param.getResult();
                    if (!(r instanceof StackTraceElement[])) return;
                    StackTraceElement[] frames = (StackTraceElement[]) r;
                    /*
                     * anti-cpu-hotfix v2：按「线程 + 栈指纹」做 TTL 缓存。
                     * 命中时直接复用上次结果，零 filter 成本。
                     */
                    long now = System.currentTimeMillis();
                    long fp = fingerprint(frames);
                    TraceCache c = TL_TRACE_CACHE.get();
                    if (c != null && c.fp == fp && (now - c.ts) < TRACE_TTL_MS) {
                        if (c.value != null) param.setResult(c.value);
                        return;
                    }
                    StackTraceElement[] cleaned = filter(frames);
                    TraceCache nc = (c == null) ? new TraceCache() : c;
                    nc.fp = fp;
                    nc.ts = now;
                    /* 只在「无需剥离」或「剥离后仍非空」时缓存，避免缓存 null 掩盖真实剥离 */
                    nc.value = (cleaned == null) ? frames : cleaned;
                    TL_TRACE_CACHE.set(nc);
                    if (cleaned != null) param.setResult(cleaned);
                }
            });
        } catch (Throwable t) {
            HookEntry.log("挂 getStackTrace 失败: " + t);
        }
    }

    private static void hookStackTraceDeep() {
        try {
            XposedHelpers.findAndHookMethod(Throwable.class, "getSuppressed",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof Throwable[]) {
                                for (Throwable t : (Throwable[]) r) {
                                    scrub(t);
                                }
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
        try {
            XposedHelpers.findAndHookMethod(Throwable.class, "getCause",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof Throwable) {
                                scrub((Throwable) r);
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
    }

    private static void scrub(Throwable t) {
        try {
            if (t == null) return;
            StackTraceElement[] cleaned = filter(t.getStackTrace());
            if (cleaned != null) t.setStackTrace(cleaned);
        } catch (Throwable ignored) {
        }
    }

    private static void hookAllStackTraces() {
        try {
            XposedHelpers.findAndHookMethod(Thread.class, "getAllStackTraces", new XC_MethodHook() {
                @Override
                @SuppressWarnings("unchecked")
                protected void afterHookedMethod(MethodHookParam param) {
                    Object r = param.getResult();
                    if (!(r instanceof Map)) return;
                    try {
                        Map<Thread, StackTraceElement[]> map = (Map<Thread, StackTraceElement[]>) r;
                        for (Map.Entry<Thread, StackTraceElement[]> e : map.entrySet()) {
                            StackTraceElement[] cleaned = filter(e.getValue());
                            if (cleaned != null) e.setValue(cleaned);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private static void hookStackWalker() {
        try {
            Class<?> walker = XposedHelpers.findClassIfExists("java.lang.StackWalker",
                    ClassLoader.getSystemClassLoader());
            if (walker == null) return;
            XposedBridge.hookAllMethods(walker, "walk", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Object r = param.getResult();
                    if (r instanceof java.util.stream.Stream) {
                        param.setResult(((java.util.stream.Stream<?>) r).filter(o -> {
                            if (o instanceof StackWalker.StackFrame) {
                                return !isFrameworkName(((StackWalker.StackFrame) o).getClassName());
                            }
                            return true;
                        }));
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private static void hookStackTraceElementToString() {
        try {
            XposedHelpers.findAndHookMethod(StackTraceElement.class, "toString", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        StackTraceElement self = (StackTraceElement) param.thisObject;
                        if (self != null && isFrameworkName(self.getClassName())) {
                            param.setResult("java.lang.Object.unknown(Unknown Source)");
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private static StackTraceElement[] filter(StackTraceElement[] frames) {
        if (frames == null || frames.length == 0) return null;
        List<StackTraceElement> kept = new ArrayList<>(frames.length);
        boolean changed = false;
        for (StackTraceElement f : frames) {
            if (f == null) continue;
            String cn;
            try {
                cn = f.getClassName();
            } catch (Throwable t) {
                kept.add(f);
                continue;
            }
            if (isFrameworkName(cn)) {
                changed = true;
            } else {
                kept.add(f);
            }
        }
        return changed ? kept.toArray(new StackTraceElement[0]) : null;
    }

    private static void hookXposedVersion() {
        try {
            Class<?> bridge = XposedHelpers.findClassIfExists(
                    "de.robv.android.xposed.XposedBridge", TraceHide.class.getClassLoader());
            if (bridge == null) return;
            XposedBridge.hookAllMethods(bridge, "getXposedVersion", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(0);
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private static void hookDebugger() {
        try {
            XposedHelpers.findAndHookMethod(android.os.Debug.class, "isDebuggerConnected",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(Boolean.FALSE);
                        }
                    });
        } catch (Throwable ignored) {
        }
        try {
            XposedHelpers.findAndHookMethod(android.os.Debug.class, "waitingForDebugger",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(Boolean.FALSE);
                        }
                    });
        } catch (Throwable ignored) {
        }
    }
}
