package com.rev.antihookbypass;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 模块主入口 —— 通用 Hook 检测对抗。
 *
 * <h2>这套东西解决什么问题</h2>
 * 安卓上各种"检测你是否装了 Hook 框架/在 hook 我"的实现,本质上都会落到
 * 有限的几个<b>观测面</b>上。本模块不针对某一款检测器,而是按观测面分层压制,
 * 所以换一套自研检测体系、换一个 App,照样有效。
 *
 * <p>完整的分析框架见 {@code docs/01-方法论.md}。这里只做编排。
 *
 * <h2>三层职责划分</h2>
 * <table>
 *   <tr><th>层</th><th>类</th><th>对应方向</th></tr>
 *   <tr><td>结果伪造</td><td>{@link ResultForge}</td><td>D6 检测结论出口</td></tr>
 *   <tr><td>痕迹压制</td><td>{@link TraceHide}</td><td>D7 框架痕迹 / D8 环境探测</td></tr>
 *   <tr><td>处置拦截</td><td>{@link KillGuard}</td><td>D9 自杀与不可逆动作</td></tr>
 * </table>
 *
 * <p>D1~D5(结构计数、代码 CRC、匿名段、inline hook 特征、外部 ptrace)
 * 全部发生在 native 层,<b>Java hook 无法直接影响</b>。
 * 它们由 {@link NativeLayer}(L2)与文档里的 L3/L4 处理。
 * 但在实战中,D6 往往能间接把它们一起解决 —— 因为它们算完也要交回上层。
 *
 * <p>L2 默认关闭:它会让自己出现在 maps 里、扩大暴露面,
 * 且大多数检测最终都经过 Java 层,不需要下沉。
 *
 * <h2>安装时机</h2>
 * 在 {@code handleLoadPackage} 里立刻安装,不等 Application 启动完成。
 * 原因:检测常在 {@code attachBaseContext} / {@code onCreate} 极早阶段执行,
 * 晚一步就来不及。
 */
public class HookEntry implements IXposedHookLoadPackage {

    /** true=正常运行；false=完全静默（对照用） */
    private static final boolean CONTROL_PROBE = true;

    static final String TAG = "AntiHookBypass";

    /** 安装标记,防止同一进程重复安装 */
    private static volatile boolean installed = false;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) return;
        synchronized (HookEntry.class) {
            if (installed) return;
            installed = true;      // 先占位,避免并发重复安装
        }

        /*
         * 每一层独立 try/catch:任何一层失败都不影响其余层。
         * 这是刻意的 —— 在加固/魔改 ROM 上,某一层的 API 可能被禁
         * (例如 TraceHide 依赖的 forName 挂钩被拒),
         * 但其余层仍然能起作用。整体失败才真的没救。
         */
        /*
         * 最先装：主动把 NativeLib 拉起来并立刻挂钩。
         *
         * 顺序很重要 —— 如果等 Application.onCreate 再挂，
         * 目标可能已经跑完一轮检测（Compose 的 LaunchedEffect 很早）。
         * 这里在 handleLoadPackage 一开始就 findClass + 挂方法，
         * 相当于抢在目标使用之前接管。
         */
        probeLSPosed();
        probeClassLoader();

        // [R-26 已移除] 接管/改写类逻辑不得启用

        boolean l1a = safeInstall("TraceHide", () -> TraceHide.install(lpparam.classLoader));
        // [R-26 已移除] 接管/改写类逻辑不得启用
        boolean l1c = safeInstall("KillGuard", KillGuard::install);
        boolean l1d = safeInstall("CrashGuard", () -> CrashGuard.install(lpparam.classLoader));

        // 精准挂：直接短路检测出口（含 native 方法）
        // 精准挂：在 Application 初始化后再执行，确保宿主的类已真正加载
        // [R-26 已移除] 接管/改写类逻辑不得启用

        // 终极兜底：全局挂"返回 String 的 native 方法"
        // [R-26 已移除] 接管/改写类逻辑不得启用

        // 直接接管 native 出口（最可靠）
        // [R-26 已移除] native 出口接管

        // 通用出口接管：按结论形状改写，不认任何类名
        // [R-26 已移除] 接管/改写类逻辑不得启用

        // Frida 痕迹隐藏：端口/文件/进程探测全部按掉
        boolean l1h = safeInstall("FridaHide", () -> FridaHide.install(lpparam.classLoader));
        boolean l2 = NativeLayer.install(hostContext(lpparam));
        if (!l2) {
            /*
             * 此刻 Application 还没创建，拿不到 Context。
             *
             * 最早能拿到 Context 的时机是 Application.attachBaseContext ——
             * 它比 onCreate 更早，参数就是 base Context 本身。
             * 在这里加载 native，能赶在大部分检测逻辑之前。
             *
             * 为什么不用 onCreate：Compose 类应用会在 onCreate 里就启动检测，
             * 那时再装就晚了。
             */
            try {
                de.robv.android.xposed.XposedHelpers.findAndHookMethod(
                        android.app.Application.class, "attachBaseContext",
                        android.content.Context.class,
                        new de.robv.android.xposed.XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                try {
                                    Object base = param.args[0];
                                    if (base instanceof android.content.Context) {
                                        NativeLayer.install((android.content.Context) base);
                                    }
                                } catch (Throwable ignored) {
                                }
                            }
                        });
            } catch (Throwable ignored) {
            }
        }

        /* 只报告真实挂载的层。已移除的接管/改写层不再出现在这里，
           避免日志继续暗示"全部启用"（旧版恒 true 的自评问题）。 */
        log("已装载: " + lpparam.packageName
                + " (trace=" + l1a + " kill=" + l1c
                + " crash=" + l1d + " frida=" + l1h
                + " native=" + l2 + ")");
    }

    /** 取宿主 Application 作为 Context（native 解包 so 需要 dataDir） */
    private static android.content.Context hostContext(XC_LoadPackage.LoadPackageParam lp) {
        try {
            Object app = de.robv.android.xposed.XposedHelpers.callStaticMethod(
                    de.robv.android.xposed.XposedHelpers.findClass(
                            "android.app.ActivityThread", lp.classLoader),
                    "currentApplication");
            if (app instanceof android.content.Context) return (android.content.Context) app;
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** 同时写文件，避免 logcat 缓冲区滚动丢失（调试期用） */
    private static volatile java.io.File logFile = null;

    /**
     * 同时写文件 —— logcat 缓冲区滚动很快，调试时经常丢日志。
     *
     * <p>落点：优先写宿主自己的 code_cache（该进程必然可写），
     * 失败就放弃，绝不影响主流程。
     */
    private static void writeFileLog(String msg) {
        try {
            if (logFile == null) {
                // 从 ActivityThread 拿当前包名，拼私有目录
                String pkg = null;
                try {
                    Class<?> at = Class.forName("android.app.ActivityThread");
                    Object th = at.getMethod("currentActivityThread").invoke(null);
                    java.lang.reflect.Field bf = at.getDeclaredField("mBoundApplication");
                    bf.setAccessible(true);
                    Object ba = bf.get(th);
                    if (ba != null) {
                        java.lang.reflect.Field af =
                                ba.getClass().getDeclaredField("appInfo");
                        af.setAccessible(true);
                        Object ai = af.get(ba);
                        Object pn = ai.getClass().getField("packageName").get(ai);
                        if (pn instanceof String) pkg = (String) pn;
                    }
                } catch (Throwable ignored) {
                }
                if (pkg == null) return;
                java.io.File dir = new java.io.File("/data/data/" + pkg + "/code_cache");
                if (!dir.exists()) dir.mkdirs();
                logFile = new java.io.File(dir, "ahb.log");
            }
            java.io.FileWriter w = new java.io.FileWriter(logFile, true);
            w.write(new java.text.SimpleDateFormat("HH:mm:ss.SSS")
                    .format(new java.util.Date()) + " " + msg + "\n");
            w.close();
        } catch (Throwable ignored) {
        }
    }

    /**
     * 探测：LSPosed 是否把 native hook 能力暴露成可反射的 Java 接口。
     *
     * <p>这个探测只跑一次，结果写日志，用来决定 native 层怎么接入。
     */
    private static void probeLSPosed() {
        String[] candidates = {
                "org.lsposed.lspd.nativebridge.HookBridge",
                "org.lsposed.lspd.core.nativebridge.HookBridge",
                "org.lsposed.lspd.impl.LSPosedContext",
                "de.robv.android.xposed.XposedBridge",
        };
        for (String cn : candidates) {
            try {
                Class<?> c = Class.forName(cn);
                StringBuilder sb = new StringBuilder("找到 " + cn + " 方法: ");
                for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                    if (m.getName().toLowerCase().contains("hook")) {
                        sb.append(m.getName()).append(' ');
                    }
                }
                log(sb.toString());
            } catch (Throwable t) {
                log("未找到 " + cn);
            }
        }
    }

    /**
     * 直接挂检测器的 native 出口。
     *
     * <h2>为什么必须"硬挂"</h2>
     * 前面试过的形态发现方法在这个目标上全部落空，原因很实在：
     * 检测器的 {@code NativeLib} 是在 {@code attachBaseContext} 里同步调用的，
     * 而我们的 loadClass 钩子装得比它晚；等钩子就绪，第一轮检测早跑完了。
     *
     * <p>所以这里做一件不优雅但有效的事：<b>主动把那个类加载起来并挂上</b>。
     * {@code findClass} 会触发类初始化，此时我们的钩子已经在位。
     *
     * <h2>这不是特征方案</h2>
     * 类名取自"通用的检测出口形态"：返回 String 的 native 方法。
     * 具体类名通过遍历当前 ClassLoader 的所有类 + 检查是否有 native String 方法
     * 来发现，而不是写死。
     */
    private static int hookScanDirectly(ClassLoader cl) {
        int n = 0;
        try {
            java.util.List<Class<?>> all = new java.util.ArrayList<>();
            java.lang.reflect.Field f = ClassLoader.class.getDeclaredField("classes");
            f.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Vector<Class<?>> v = (java.util.Vector<Class<?>>) f.get(cl);
            if (v != null) synchronized (v) { all.addAll(v); }

            for (Class<?> c : all) {
                if (c == null) continue;
                String nm = c.getName();
                if (nm.startsWith("java.") || nm.startsWith("android.")
                        || nm.startsWith("androidx.") || nm.startsWith("kotlin.")
                        || nm.startsWith("dalvik.") || nm.startsWith("com.rev.antihookbypass")) {
                    continue;
                }
                for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                    int mod = m.getModifiers();
                    if ((mod & 0x0100) == 0) continue;              // 只处理 native
                    if (m.getReturnType() != String.class) continue;
                    try {
                        de.robv.android.xposed.XposedBridge.hookMethod(m,
                                new de.robv.android.xposed.XC_MethodHook() {
                                    @Override
                                    protected void beforeHookedMethod(MethodHookParam p) {
                                        // 交给 ExitHook 的统一改写逻辑：
                                        // 不凭空造 JSON，而是让真实检测跑完后改写。
                                        // 但 native 方法很慢（fork+ptrace），
                                        // 这里直接给安全结果更稳。
                                        p.setResult(ShapeDetector.buildSafeFor(
                                                (String) null));
                                        log("挂住 native 出口: " + m.getName());
                                    }
                                });
                        n++;
                        log("native 出口已接管: " + nm + "." + m.getName());
                    } catch (Throwable ignored) {
                    }
                }
            }
        } catch (Throwable t) {
            log("hookScanDirectly 失败: " + t);
        }
        return n;
    }

    /** 探测：我们的 ClassLoader 是什么类型，它怎么解析 native 库 */
    private static void probeClassLoader() {
        try {
            ClassLoader cl = HookEntry.class.getClassLoader();
            log("模块 ClassLoader: " + cl.getClass().getName());
            log("  toString: " + cl);
            // 试探它有没有 findLibrary
            for (java.lang.reflect.Method m : cl.getClass().getDeclaredMethods()) {
                String n = m.getName();
                if (n.contains("findLibrary") || n.contains("Library")) {
                    log("  方法: " + n + " 参数=" + m.getParameterCount());
                }
            }
        } catch (Throwable t) {
            log("探测 ClassLoader 失败: " + t);
        }
    }

    /** 装一层,失败只记日志,不中断其他层 */
    private static boolean safeInstall(String name, Runnable action) {
        try {
            action.run();
            return true;
        } catch (Throwable t) {
            log(name + " 装载失败(其余层继续): " + t);
            return false;
        }
    }

    static void log(String msg) {
        try {
            XposedBridge.log("[" + TAG + "] " + msg);
        } catch (Throwable ignored) {
        }
        writeFileLog(msg);
    }
}
