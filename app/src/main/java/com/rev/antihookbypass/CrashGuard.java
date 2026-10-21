package com.rev.antihookbypass;

import android.content.ContentProvider;
import android.content.pm.ApplicationInfo;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 兼容性兜底：处理"老版本 androidx.startup 在新系统上崩溃"的问题。
 *
 * <h2>要解决的问题</h2>
 * 有些应用在 Android 14+ 上启动即崩，栈是这样的：
 * <pre>
 *   Unable to get provider androidx.startup.InitializationProvider
 *   Caused by: ClassNotFoundException: androidx.emoji2.text.EmojiCompatInitializer
 * </pre>
 *
 * <p>看起来像类丢失，实际不是——类就在 dex 里。真实原因是：
 * <ul>
 *   <li>这些应用用的是很老版本的 {@code androidx.startup}，
 *       它通过 {@code Class.forName(name, false, loader)} 加载初始化器；</li>
 *   <li>新系统对 {@code InitializationProvider} 的创建时机/类加载器行为有变化；</li>
 *   <li>老版本 startup 没处理"初始化器加载失败"这种情况，直接抛出去把进程干掉。</li>
 * </ul>
 *
 * <h2>为什么模块要管这个</h2>
 * 目标应用一启动就崩，模块再强也没机会发挥作用——用户看到的是"装完还是闪退"。
 * 所以必须先把这类可恢复的启动崩溃挡掉。
 *
 * <h2>做法</h2>
 * 只拦 {@code InitializationProvider} 这一条路径，且只吞掉
 * {@code ClassNotFoundException} / {@code NoClassDefFoundError} 这类
 * "初始化器找不到"的异常，其它异常照常抛出——不能把真正的 bug 也吞了，
 * 否则问题会被藏起来。
 */
final class CrashGuard {

    private CrashGuard() {
    }

    /** 崩溃链里出现的这些类，说明是 startup 初始化器加载失败 */
    private static final String[] STARTUP_MARKS = {
            "androidx.startup.InitializationProvider",
            "androidx.emoji2.text.EmojiCompatInitializer",
    };

    static void install(ClassLoader hostCl) {
        hookProviderOnCreate(hostCl);
    }

    /**
     * 第一种情况：{@code InitializationProvider.onCreate()} 内部抛异常。
     *
     * <p>正常行为是异常一路传到 {@code ActivityThread.installProvider}
     * 导致 {@code RuntimeException: Unable to get provider ...}。
     * 这里把 onCreate 的异常吞掉，让 provider 变成"什么都没做"，
     * 应用就能继续启动。
     */
    private static void hookProviderOnCreate(ClassLoader hostCl) {
        try {
            Class<?> provider = XposedHelpers.findClassIfExists(
                    "androidx.startup.InitializationProvider", hostCl);
            if (provider == null) return;

            XposedBridge.hookAllMethods(provider, "onCreate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (!param.hasThrowable()) return;
                    Throwable t = param.getThrowable();
                    if (!isStartupLoadFailure(t)) return;
                    param.setThrowable(null);        // 吞掉
                    param.setResult(Boolean.TRUE);   // 当作初始化成功
                    HookEntry.log("已吞掉 startup 初始化器加载失败: " + t);
                }
            });
        } catch (Throwable ignored) {
        }
    }

    /** 判断异常链里是不是"初始化器找不到"这一类 */
    private static boolean isStartupLoadFailure(Throwable t) {
        int depth = 0;
        while (t != null && depth < 8) {
            if (t instanceof ClassNotFoundException || t instanceof NoClassDefFoundError) {
                return true;
            }
            String msg = t.getMessage();
            if (msg != null) {
                for (String m : STARTUP_MARKS) {
                    if (msg.contains(m)) return true;
                }
            }
            t = t.getCause();
            depth++;
        }
        return false;
    }
}
