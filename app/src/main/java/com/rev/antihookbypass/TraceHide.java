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
     * getStackTrace 结果缓存：key=原始栈数组身份(NativeIdentity)，value=过滤后结果 + 时间戳。
     * 用 WeakHashMap 避免泄漏原始 StackTraceElement[]（它们会被 GC 回收）。
     */
    private static final WeakHashMap<StackTraceElement[], CacheEntry> sTraceCache =
            new WeakHashMap<>();
    /** 窗口期：同一份栈在 200ms 内直接复用缓存，避免高频取栈时反复重建 */
    private static final long TRACE_TTL_MS = 200L;

    private static final class CacheEntry {
        StackTraceElement[] value;
        long ts;
        CacheEntry(StackTraceElement[] v, long t) { value = v; ts = t; }
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
                     * 缓存短路：绝大多数业务取栈不含框架帧，原样返回且缓存窗口期内复用，
                     * 不再逐帧重建。命中缓存时直接 return，零过滤成本。
                     */
                    long now = System.currentTimeMillis();
                    CacheEntry e = null;
                    boolean hit = false;
                    synchronized (sTraceCache) {
                        e = sTraceCache.get(frames);
                        if (e != null && (now - e.ts) < TRACE_TTL_MS) {
                            hit = true;
                        }
                    }
                    if (hit) {
                        // 窗口期内复用；若上次判定无需过滤则保持原结果
                        if (e.value != null) param.setResult(e.value);
                        return;
                    }
                    StackTraceElement[] cleaned = filter(frames);
                    synchronized (sTraceCache) {
                        // 仅缓存「未改动」或「小幅改动」的结果，避免缓存巨型数组
                        sTraceCache.put(frames, new CacheEntry(cleaned, now));
                        // 控制缓存体量
                        if (sTraceCache.size() > 256) sTraceCache.clear();
                    }
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
