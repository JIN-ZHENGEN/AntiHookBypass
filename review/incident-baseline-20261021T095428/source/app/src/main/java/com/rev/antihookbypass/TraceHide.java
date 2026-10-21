package com.rev.antihookbypass;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 框架痕迹压制 —— 对应方法论里的 D7（框架痕迹）与 D8（环境探测）。
 *
 * <h2>为什么这些项必须单独处理</h2>
 * {@link ResultForge} 处理的是"检测把结论交回上层"这种情况。
 * 但有一类探测不产生结构化结论，它<b>直接看环境本身</b>：
 * <ul>
 *   <li>{@code Class.forName("de.robv.android.xposed.XposedBridge")} 能加载到 → 装了框架；</li>
 *   <li>堆栈里出现 {@code de.robv.android.xposed} 的帧 → 有 hook 在跑；</li>
 *   <li>{@code XposedBridge.getXposedVersion() > 0} → 框架活着；</li>
 *   <li>{@code Debug.isDebuggerConnected()} → 正在被调试。</li>
 * </ul>
 *
 * 这些探测一旦命中，检测器往往不给出具体项，而是直接判"环境异常"。
 * 所以即使检测结论被改成 SAFE，这类探测照样能把结果推翻。
 *
 * <h2>关键：栈过滤必须递归处理 Suppressed/Cause</h2>
 * 很多检测器不看主异常的栈，而是专门看 {@code getSuppressed()} 或
 * {@code getCause()} 里的栈——这些地方同样会带框架帧。
 * 只看主栈是个常见疏漏。
 */
final class TraceHide {

    private TraceHide() {
    }

    /** 判定"框架痕迹"的关键词 */
    private static final String[] MARKS = {
            "de.robv.android.xposed",
            "org.lsposed",
            "io.github.lsposed",
            "XposedBridge",
            "XposedHelpers",
            "XposedModule",
            "EdXposed",
            "org.meowcat",
            "com.elderdrivers.riru",
            "io.github.libxposed",
            "LSPosed",
            "zygisk",
            "riru",
    };

    static void install(ClassLoader cl) {
        hookForName();
        hookStackTrace();
        hookStackTraceDeep();
        hookAllStackTraces();
        hookStackWalker();
        hookXposedVersion();
        hookDebugger();
        hookStackTraceElementToString();
    }

    // ==================================================================
    // D7-1 类存在性
    // ==================================================================

    /**
     * 让框架类"加载不到"。
     *
     * <p>同时挂 {@code Class.forName} 与 {@code ClassLoader.loadClass}：
     * 前者是常见写法，后者绕过前者被直接调用。
     *
     * <p>只对<b>外部调用者</b>生效：本模块自己的类都已经加载好了（在内存里），
     * 不受影响。
     */
    private static void hookForName() {
        try {
            XposedBridge.hookAllMethods(Class.class, "forName", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String name = firstStringArg(param.args);
                    if (!isFrameworkName(name)) return;
                    if (fromSelf()) return;   // 自身类必须能正常加载,否则模块自毁
                    param.setThrowable(new ClassNotFoundException(name));
                }
            });
        } catch (Throwable t) {
            HookEntry.log("挂 forName 失败: " + t);
        }

        try {
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String name = firstStringArg(param.args);
                    if (!isFrameworkName(name)) return;
                    if (fromSelf()) return;   // 自身类必须能正常加载,否则模块自毁
                    param.setThrowable(new ClassNotFoundException(name));
                }
            });
        } catch (Throwable t) {
            HookEntry.log("挂 loadClass(隐藏) 失败: " + t);
        }
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
     * 当前调用是否来自本模块自身。
     *
     * <p>这一步是<b>必需的自我保护</b>:本模块的类是在运行中按需加载的,
     * 若连自己加载也被拦,模块会在第一次用到某个内部类时
     * 抛 ClassNotFoundException 而自毁。
     */
    private static boolean fromSelf() {
        /*
         * 关键修复：找"第一个外部调用者"，而不是"栈里有没有自己的帧"。
         *
         * 旧写法只要栈中出现自己的类就返回 true —— 但这个函数在 Xposed
         * 回调里调用，第 0 帧必然是 TraceHide$1 自己，于是永远返回 true，
         * Class.forName / loadClass 的拦截全部被跳过。框架类从来没被藏过。
         *
         * 正确做法：跳过自身与框架调度帧，看真正发起调用的那个类是谁。
         */
        try {
            StackTraceElement[] st = Thread.currentThread().getStackTrace();
            int end = Math.min(st.length, 24);
            for (int i = 0; i < end; i++) {
                String cn = st[i].getClassName();
                if (cn == null) continue;
                if (cn.startsWith("com.rev.antihookbypass")
                        || cn.startsWith("de.robv.android.xposed")
                        || cn.startsWith("java.lang.reflect")
                        || cn.startsWith("dalvik.system")) {
                    continue;                    // 跳过自己的钩子和框架帧
                }
                // 第一个"外部"调用者决定了这次调用是不是我们发起的
                return cn.startsWith("com.rev.antihookbypass");
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    // ==================================================================
    // D7-2 堆栈过滤
    // ==================================================================

    /** 过滤 {@code Throwable.getStackTrace()} */
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

    /**
     * 过滤 {@code getSuppressed()} 与 {@code getCause()} 返回的异常链上的栈。
     *
     * <p>这条容易被忽略：检测器常写
     * {@code try { ... } catch (Throwable t) { t.getSuppressed()[0].getStackTrace() } }
     * 专门绕开普通栈过滤。
     */
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
    }

    /** 把一个异常对象的栈就地洗掉（用 setStackTrace 覆盖） */
    private static void scrub(Throwable t) {
        try {
            if (t == null) return;
            StackTraceElement[] cleaned = filter(t.getStackTrace());
            if (cleaned != null) t.setStackTrace(cleaned);
        } catch (Throwable ignored) {
        }
    }

    /** 过滤 {@code Thread.getAllStackTraces()} —— 有些检测器专门查后台线程 */
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

    /**
     * 过滤 {@code StackWalker}（API 28+）。
     *
     * <p>这是新写法，很多模块漏掉：{@code StackWalker.getInstance().walk(...)}
     * 拿到的帧不含在内置 {@code getStackTrace} 里，是老式过滤的盲区。
     */
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

    /** 过滤 {@code StackTraceElement.toString()}，防有人直接打印比对 */
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

    /**
     * 过滤一份栈帧：丢掉命中框架名的帧。
     *
     * @return 清洗后的数组；无变化时返回 null 表示"不用改"
     */
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
                changed = true;              // 丢弃
            } else {
                kept.add(f);
            }
        }
        return changed ? kept.toArray(new StackTraceElement[0]) : null;
    }

    // ==================================================================
    // D7-3 版本探测
    // ==================================================================

    /**
     * 让 {@code getXposedVersion()} 返回 0。
     *
     * <p>返回 0 与"未安装"表现一致；不抛异常，因为抛异常本身也是一种特征。
     */
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

    // ==================================================================
    // D8 环境探测
    // ==================================================================

    /** 让调试器检测恒为 false */
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
