package com.rev.antihookbypass;

import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 直接掐断 native 扫描的调用。
 *
 * <h2>与前几版的差别</h2>
 * 前面试过两条路都失败：
 * <ol>
 *   <li>形态识别（类加载扫描）—— 检测类加载得比钩子早；</li>
 *   <li>按类名精准挂 —— R8 把 Detector 内联进 MainActivity，
 *       而 NativeLib.scan 的真实调用点用的是被内联后的副本。</li>
 * </ol>
 *
 * <p>现在改成最直接的办法：<b>不等特定类，直接在所有已加载类里找
 * "返回 String 且方法名叫 scan/check" 的方法并挂钩</b>，
 * 同时挂 {@code libcore} 的 native 加载路径做兜底。
 *
 * <h2>为什么这样能覆盖</h2>
 * 不管 R8 怎么内联，<b>最终一定会有一次真实的 JNI 调用</b>
 * （native 方法只能通过 JNI 进入）。只要把那个 native 方法本身挂住，
 * 无论谁调用都会命中。
 */
final class ScanBreaker {

    private ScanBreaker() {
    }

    /**
     * 在给定类上挂钩所有 native 方法中"返回值像结论"的那些。
     *
     * <p>重点是 {@code native} 方法 —— 它们是 JNI 边界，无法被内联，
     * 所以挂上去一定有效。目标的 {@code scan} 正是 native 方法。
     */
    static int hookNativeMethods(Class<?> c) {
        int n = 0;
        try {
            for (Method m : c.getDeclaredMethods()) {
                int mod = m.getModifiers();
                if ((mod & 0x0100) == 0) continue;      // 只处理 native
                Class<?> r = m.getReturnType();
                if (r != String.class) continue;
                if (hook(m)) n++;
            }
        } catch (Throwable ignored) {
        }
        return n;
    }

    /** 挂任意方法，before 直接返回全 SAFE JSON */
    static boolean hook(final Method m) {
        try {
            XposedBridge.hookMethod(m, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(ResultForge.safeJson());
                    HookEntry.log("掐断 native 扫描: "
                            + m.getDeclaringClass().getName() + "." + m.getName());
                }
            });
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * 全局兜底：挂 ClassLoader.loadClass，任何类加载完成后
     * 立刻检查它有没有"返回 String 的 native 方法"，有就挂。
     *
     * <p>这是覆盖面最广的一招：不认类名、不认包名，
     * 只要有 native 方法返回字符串（检测结果的典型形态）就处理。
     */
    static void hookAllNativeScans() {
        try {
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (!(r instanceof Class)) return;
                            Class<?> c = (Class<?>) r;
                            try {
                                String name = c.getName();
                                // 只处理应用自己的类，跳过系统与模块自身
                                if (name.startsWith("java.") || name.startsWith("android.")
                                        || name.startsWith("androidx.")
                                        || name.startsWith("kotlin.")
                                        || name.startsWith("com.rev.antihookbypass")) {
                                    return;
                                }
                                hookNativeMethods(c);
                            } catch (Throwable ignored) {
                            }
                        }
                    });
        } catch (Throwable t) {
            HookEntry.log("挂全局 native 扫描失败: " + t);
        }
    }
}
