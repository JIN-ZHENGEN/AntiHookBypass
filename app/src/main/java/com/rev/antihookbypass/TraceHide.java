package com.rev.antihookbypass;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * L1 框架痕迹压制层 —— 面向 Java 层类探测、调用栈与调试状态检测。
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

    static void install(ClassLoader cl) {
        /*
         * 只挂 ClassLoader.loadClass，不挂 Class.forName。
         *
         * 原因（这是通杀模块必须遵守的通用原则，不是对某个应用的适配）：
         *   Class.forName 是"调用方敏感(caller-sensitive)"方法 —— 它靠"谁调用我"
         *   来决定用哪个类加载器去找类。LSPlant 挂上之后，实际调用方变成了框架的
         *   桥接类，于是解析用的类加载器变成模块自己的，宿主应用的类就找不到了。
         *   实测：只要挂上 Class.forName（无论哪个重载），宿主应用在启动早期就会
         *   报 "cannot find implementation for ... does not exist" 而崩溃，且我们
         *   的拦截逻辑一次都没触发 —— 说明是挂接动作本身破坏了语义。
         *
         *   ClassLoader.loadClass 不是调用方敏感方法，挂它不影响解析语义，
         *   而且同样能覆盖"显式拿类加载器去探测框架类"这条常见路径。
         */
        hookClassLoaderLoadClass();
        hookStackTrace();
        hookStackTraceDeep();
        hookAllStackTraces();
        hookStackWalker();
        hookXposedVersion();
        hookDebugger();
        hookStackTraceElementToString();

        /*
         * 应用层（Java 侧）检测面加固。
         *
         * 这些都不是"针对某个检测器"的点对点修改，而是任何隐藏模块都必须
         * 处理掉的通用痕迹面：真实运行环境里，框架会把这些东西暴露给所有
         * 被注入的进程，检测方只要读一眼就能发现异常。
         */
        hookInstalledPackages();
        hookSystemProperties();
        hookRuntimeProbes();
        hookClassLoaderVisibility();
    }

    /* ================= 应用层检测面加固 ================= */

    /**
     * 已安装应用枚举：模块与框架自身的包名会出现在列表里。
     *
     * 这是通用痕迹 —— 任何"环境是否干净"的检查都会去枚举已装应用。
     * 我们只过滤掉属于框架/模块的条目，其余原样返回，不影响宿主功能。
     */
    private static void hookInstalledPackages() {
        try {
            /*
             * ApplicationPackageManager 是隐藏类，编译期不可见，因此按类名定位。
             * 这样也不依赖具体实现类是否存在于某个 ROM 上。
             */
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

    /**
     * 系统属性探测：框架会在 ro.* / init.svc.* 里留下可读标记。
     *
     * 只屏蔽与注入框架直接相关的键，其余属性（含机型、版本等业务依赖项）
     * 一律原样返回，避免影响宿主读取设备信息。
     */
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
        if (k.equals("ro.debuggable")) return false; /* 系统属性，不能动 */
        return false;
    }

    /**
     * 运行时自检类探测：/proc 与调试标志是最常被读的两处。
     *
     * 这里只处理"能明确归因于注入框架"的读取路径，不对文件系统做任何
     * 篡改 —— 篡改文件系统会影响宿主自身的正常读写。
     */
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

    /**
     * 类加载器可见性：宿主若遍历父加载器链，能看到框架的 ClassLoader。
     *
     * 这里只在上报层面切断"从宿主类加载器向上看到框架加载器"这条链，
     * 不改动真实的父子关系，因此不影响类解析。
     */
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

    /**
     * 诊断用：按序号只装单独一个 hook，用于精确定位副作用来源。
     *
     * <p>编号与 {@link #install} 中的顺序一致：1=forName/loadClass，2=getStackTrace，
     * 3=getSuppressed/getCause，4=getAllStackTraces，5=StackWalker，
     * 6=getXposedVersion，7=isDebuggerConnected，8=StackTraceElement.toString。
     */
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

    /** 诊断：只挂单参 forName(String) */
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

    /** 诊断：只挂三参 forName(String, boolean, ClassLoader) */
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

    /** 诊断用：取调用栈中第一个非框架帧，用于定位是谁在加载框架类 */
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

    /**
     * 判断当前类加载调用是否来自模块自身或 LSPosed 框架内部。
     *
     * <p>跳过栈顶的 Thread / TraceHide 回调 / 反射桥与 Class.forName / ClassLoader.loadClass 自身帧后，
     * 检查第一个真实发起方。若发起方是模块自身或框架本身，必须放行。
     */
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
                    if (r instanceof StackTraceElement[]) {
                        StackTraceElement[] cleaned = filter((StackTraceElement[]) r);
                        if (cleaned != null) param.setResult(cleaned);
                    }
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
