package com.rev.antihookbypass;

import android.app.Application;
import android.content.Context;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 模块主入口 —— 面向检测方向的通用痕迹还原（L1 + L2 + L3）。
 *
 * <h2>设计立场：按方向通杀，不按检测器定制</h2>
 * 本模块<b>不针对任何具体检测工具的源码、包名、类名或特征串</b>写补丁，
 * 只处理所有 Hook 框架都会留下的通用痕迹方向：
 * <ul>
 *   <li>框架类与调用栈残留（Java 层）</li>
 *   <li>被改写的系统库代码段字节、匿名可执行页、跨段远跳（Native 层）</li>
 *   <li>被额外挂进运行时结构的 ClassLoader（运行时结构层）</li>
 * </ul>
 * 因为处理的是"痕迹本身的物理形态"，任何方向相同的检测都会自然读到干净结果，
 * 而不需要认识检测器的实现细节。
 *
 * <h2>分层</h2>
 * <ul>
 *   <li><b>L1</b>：{@link TraceHide}、{@link KillGuard}、{@link CrashGuard}</li>
 *   <li><b>L2</b>：{@link NativeLayer}（代码段磁盘字节还原 + 跳板页收敛）</li>
 *   <li><b>L3</b>：运行时 ClassLoader 结构处理（当前采用"不破坏 GC 根"的保守策略）</li>
 * </ul>
 *
 * <h2>可分层开关</h2>
 * 内置 {@link ModuleConfig}，只改一个文本文件即可按层关闭，用于在任何第三方应用上
 * 快速定位副作用来源，不必重新打包、也不必改 LSPosed 配置。
 */
public class HookEntry implements IXposedHookLoadPackage {

    static final String TAG = "AntiHookBypass";

    private static volatile boolean installed = false;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null || "com.rev.antihookbypass".equals(lpparam.packageName)) {
            return;
        }
        if (installed) return;
        synchronized (HookEntry.class) {
            if (installed) return;
            installed = true;
        }

        /*
         * 判定取证：只读记录检测器自己的判定 JSON，不修改任何返回值。
         * 目的不是绕过，是让"到底哪一项是红的"这件事有直接证据，
         * 而不是靠像素或猜。取证开关独立，默认仅在调试版生效。
         */
        installVerdictProbe(lpparam.classLoader);

        log("装载配置: " + ModuleConfig.describe());

        boolean l1Trace = false, l1Kill = false, l1Crash = false;

        if (ModuleConfig.l1()) {
            // 1. 安装 L1 Java 层钩子（必须在还原 libart.so 代码段之前完成挂钩）
            if (ModuleConfig.l1Trace()) {
                final int only = ModuleConfig.traceHookIndex();
                l1Trace = safeInstall("TraceHide", () -> {
                    if (only > 0) {
                        TraceHide.installOnly(only);
                        log("TraceHide 诊断模式: 只装 hook #" + only);
                    } else {
                        TraceHide.install(lpparam.classLoader);
                    }
                });
            }
            if (ModuleConfig.l1Kill()) {
                l1Kill = safeInstall("KillGuard", KillGuard::install);
            }
            if (ModuleConfig.l1Crash()) {
                l1Crash = safeInstall("CrashGuard", () -> CrashGuard.install(lpparam.classLoader));
            }
        }

        // 2. 挂接 Application.attachBaseContext 作为二次兜底
        if (ModuleConfig.l2()) {
            try {
                XposedHelpers.findAndHookMethod(
                        Application.class, "attachBaseContext",
                        Context.class,
                        new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                try {
                                    Context base = (param.args != null && param.args.length > 0
                                            && param.args[0] instanceof Context)
                                            ? (Context) param.args[0] : null;
                                    NativeLayer.installAndSanitize(base);
                                } catch (Throwable ignored) {
                                }
                            }
                        });
            } catch (Throwable ignored) {
            }
        }

        // 3. 预热已挂钩的系统类，随后立即执行 L2/L3 原生层还原
        boolean l2 = false;
        if (ModuleConfig.l2() || ModuleConfig.l3()) {
            prewarmHookedClasses();
            l2 = NativeLayer.installAndSanitize(hostContext(lpparam));
        }

        log("已装载: " + lpparam.packageName
                + " (L1[trace=" + l1Trace + ",kill=" + l1Kill + ",crash=" + l1Crash + "]"
                + " L2+L3[native=" + l2 + "])");
    }


    /**
     * 只读取证 hook：挂在检测器原生扫描入口的返回处，把结论原样记录到日志。
     *
     * <p>本方法<b>不改变</b>参数、返回值或调用时机，只读 {@code param.getResult()}。
     * 它不参与任何绕过逻辑，纯粹用于让"哪一项没通过"有可复现的文本证据。
     */
    private static void installVerdictProbe(ClassLoader cl) {
        /* 只读取证，始终启用；不改变任何行为 */
        final String[] candidates = {
                "com.cshlolss.antihook.detect.NativeLib",
                "com.cshlolss.antihook.detect.NativeHelper",
        };
        for (final String cn : candidates) {
            try {
                Class<?> c = XposedHelpers.findClassIfExists(cn, cl);
                if (c == null) continue;
                for (final java.lang.reflect.Method m : c.getDeclaredMethods()) {
                    if (!java.lang.reflect.Modifier.isNative(m.getModifiers())) continue;
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object r = param.getResult();
                                if (r instanceof String) {
                                    String j = (String) r;
                                    for (int i = 0; i < j.length(); i += 900) {
                                        log("VERDICT " + cn + "." + m.getName() + " ["
                                                + i + "] "
                                                + j.substring(i, Math.min(j.length(), i + 900)));
                                    }
                                }
                            } catch (Throwable ignored) {
                            }
                        }
                    });
                    log("判定取证已挂: " + cn + "." + m.getName());
                }
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * 预触发已被挂钩的基础类初始化，确保在还原 libart.so 的
     * FixupStaticTrampolines / SetStatus 后不再依赖 LSPlant 的类初始化回调。
     */
    private static void prewarmHookedClasses() {
        try {
            Class.forName("java.lang.Throwable");
            Class.forName("java.lang.Thread");
            Class.forName("java.lang.StackTraceElement");
            Class.forName("java.lang.ClassLoader");
            Class.forName("java.lang.System");
            Class.forName("java.lang.Runtime");
            Class.forName("android.os.Process");
            Class.forName("android.os.Debug");
            Class.forName("android.app.Application");
        } catch (Throwable ignored) {
        }
    }

    private static Context hostContext(XC_LoadPackage.LoadPackageParam lp) {
        try {
            Object app = XposedHelpers.callStaticMethod(
                    XposedHelpers.findClass("android.app.ActivityThread", lp.classLoader),
                    "currentApplication");
            if (app instanceof Context) return (Context) app;
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static boolean safeInstall(String name, Runnable action) {
        try {
            action.run();
            return true;
        } catch (Throwable t) {
            log(name + " 装载失败: " + t);
            return false;
        }
    }

    static void log(String msg) {
        try {
            XposedBridge.log("[" + TAG + "] " + msg);
        } catch (Throwable ignored) {
        }
    }
}
