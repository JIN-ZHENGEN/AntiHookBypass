package com.rev.antihookbypass;

import java.util.ArrayList;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 隐藏 Xposed/LSPosed 的 API 类在目标进程里的"可见性"。
 *
 * <h3>为什么需要这一层</h3>
 *
 * 目标应用（com.zhenxi.hunter 6.58）的 dex 里带一整套框架检测字符串：
 *
 * <pre>
 *   FIND XPOSED API :
 *   anti xposed
 *   Find Lsposed Hook Module
 *   Find Lspatch Mark
 *   Find Hook Mark
 *   Find JVM Method Is Hooked
 *   Find DexBuilder Dex,Maybe Have Lsplant
 * </pre>
 *
 * 并且明确按名字查找下列类：
 *
 * <pre>
 *   de.robv.android.xposed.XposedBridge
 *   de.robv.android.xposed.XposedHelpers
 *   de.robv.android.xposed.installer
 *   org.lsposed.manager
 *   org.meowcat.edxposed.manager
 *   top.canyie.dreamland.manager
 *   me.weishu.exp / me.weishu.kernelsu
 * </pre>
 *
 * 实测依据：把本模块改成"只让框架注入、自身完全不做任何事"（不加载
 * 自己的 so、不挂任何 hook），目标**仍然**会崩。也就是说它察觉的不是
 * 本模块做了什么，而是框架注入这件事本身。它加载到 XposedBridge
 * 之后就走反制路径，那条路径里会用它自带的 Dobby 去改 ArtMethod，
 * 进而触发 ART 的 jit_code_cache 断言并 abort。
 *
 * 所以要让它活着，必须让"框架 API 在它的进程里查不到"。
 *
 * <h3>做法与边界</h3>
 *
 * 只拦"名字查找"这一层的返回值：对 {@code Class.forName} 与
 * {@code ClassLoader.loadClass} 里命中黑名单的名字抛
 * {@code ClassNotFoundException}，等于这些类从未被加载过。
 *
 * 判据是**调用方**：调用栈里只要有一帧属于框架自身、本模块、或
 * android/java 标准库，就照常放行。这样本模块后续照样能用
 * XposedBridge 打日志、装 hook，不会把自己拦死。
 *
 * 不改动目标任何业务逻辑的判断结果，也不伪造它的检测报告——
 * 只是让框架这类"本来就不该出现在被注入进程里的东西"不可见。
 */
final class ApiHiding {

    /** 需要隐藏的类名前缀。 */
    private static final String[] PREFIX = {
            "de.robv.android.xposed.",
            "org.lsposed.",
            "top.canyie.dreamland.",
            "top.canyie.pine.",
            "me.weishu.exposed.",
            "com.elderdrivers.riru.",
    };

    /**
     * 这些包名属于"基础设施"，判断真实调用方时要跳过，不作为依据。
     */
    private static final String[] INFRA = {
            "com.rev.antihookbypass.",   /* 本模块自己的 hook 代码 */
            "de.robv.android.xposed.",   /* XC_MethodHook / HookBridge 等框架内部 */
            "org.lsposed.",
            "java.lang.reflect.",
            "android.app.AndroidAppHelper",
    };

    /**
     * 真实调用方落在这些包时才放行：框架自己要取类、或标准库内部查找。
     * 目标应用即便"看起来"经过框架帧，也会被继续下溯到它自己那一帧。
     */
    private static final String[] ALLOW = {
            "java.",
            "android.",
            "com.android.internal.",
            "dalvik.",
            "sun.",
            "jdk.internal.",
    };

    private static volatile boolean sInstalled;

    private ApiHiding() { }

    static void install() {
        if (sInstalled) return;
        sInstalled = true;

        try {
            XposedHelpers.findAndHookMethod(
                    Class.class, "forName",
                    String.class, boolean.class, ClassLoader.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                            String n = (String) p.args[0];
                            if (isBlacklisted(n)) {
                                boolean self = callerAllowed();
                                HookEntry.log("APIPROBE forName " + n
                                        + (self ? " [自己人放行]" : " [拦截]")
                                        + " caller=" + callerName());
                                if (!self) throw cleanNotFound(n);
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }

        try {
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    if (p.args == null || p.args.length == 0) return;
                    Object a = p.args[0];
                    if (!(a instanceof String)) return;
                    String n = (String) a;
                    if (isBlacklisted(n)) {
                        boolean self = callerAllowed();
                        HookEntry.log("APIPROBE loadClass " + n
                                + (self ? " [自己人放行]" : " [拦截]")
                                + " caller=" + callerName());
                        if (!self) throw cleanNotFound(n);
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    /**
     * 造一个"栈是空的"ClassNotFoundException。
     *
     * <p>为什么必须清栈：最初直接 {@code throw new ClassNotFoundException(n)}，
     * 实测目标（hunter）把这条异常打了出来，栈是这样的：
     *
     * <pre>
     *   java.lang.ClassNotFoundException: de.robv.android.xposed.XposedBridge
     *     at com.rev.antihookbypass.ApiHiding$1.beforeHookedMethod(ApiHiding.java:116)
     *     at de.robv.android.xposed.XC_MethodHook.callBeforeHookedMethod
     *     at t.intercept(...)
     *     at m.proceed(...)
     *     at android.content.Raed.forName(Raed.java)   ← 目标自己的混淆类
     * </pre>
     *
     * <p>它只要 catch 一下再读栈，就同时看到了本模块的名字、
     * 框架的分发帧 {@code t.intercept}/{@code m.proceed}，
     * 等于把"我被 hook 了"直接写在异常里。
     *
     * <p>清空栈之后异常只剩下类型与消息，与"这个类本来就不存在"完全一致。
     */
    private static ClassNotFoundException cleanNotFound(String name) {
        ClassNotFoundException e = new ClassNotFoundException(name);
        e.setStackTrace(new StackTraceElement[0]);
        return e;
    }
    private static boolean isBlacklisted(String name) {
        if (name == null || name.isEmpty()) return false;
        for (String p : PREFIX) {
            if (name.startsWith(p)) return true;
        }
        return false;
    }

    /**
     * 判断这次查找是不是"框架/标准库自己在用"。
     *
     * <p>做法：从栈顶往下跳过所有基础设施帧（本模块 hook、框架 hook 分发、
     * 反射入口），**第一个不属于基础设施的帧**才是真实调用方，
     * 只看它一个。
     *
     * <p>为什么不能像最初那样"栈里只要出现允许的包就放行"：
     * 这个判断本身就发生在我们的 hook 里，栈上永远有
     * {@code com.rev.antihookbypass.ApiHiding} 的帧；而
     * {@code com.rev.antihookbypass.} 当时又在白名单里，
     * 于是每一次查找都被判成"自己人"直接放行 ——
     * 实测打印出来正是这个结果：目标来查 XposedBridge 时显示"自己人放行"，
     * 隐藏逻辑等于从未生效。
     *
     * <p>只在名字命中黑名单时才走到这里，不会拖慢普通类加载。
     */
    private static boolean callerAllowed() {
        StackTraceElement[] st = new Throwable().getStackTrace();
        for (StackTraceElement e : st) {
            String cn = e.getClassName();
            if (cn == null) continue;
            if (isInfra(cn)) continue;
            for (String a : ALLOW) {
                if (cn.startsWith(a)) return true;
            }
            return false;   /* 真实调用方是目标应用自己 */
        }
        return false;
    }

    /** 打印第一个非基础设施帧，用来判断真实调用方是谁。 */
    private static String callerName() {
        StackTraceElement[] st = new Throwable().getStackTrace();
        for (StackTraceElement e : st) {
            String cn = e.getClassName();
            if (cn == null) continue;
            if (isInfra(cn)) continue;
            return cn + "#" + e.getMethodName();
        }
        return "?";
    }

    private static boolean isInfra(String cn) {
        for (String p : INFRA) {
            if (cn.startsWith(p)) return true;
        }
        return false;
    }

    /** 供自检：列出当前黑名单前缀数量。 */
    static int prefixCount() {
        List<String> l = new ArrayList<String>();
        for (String p : PREFIX) l.add(p);
        return l.size();
    }
}
