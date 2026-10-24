package com.rev.antihookbypass;

import android.app.Activity;
import android.app.Application;
import android.app.Instrumentation;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

/**
 * 只读地把目标界面上的文字抄到 logcat。
 *
 * <p>为什么需要它：验证「检测器界面是否显示 6/6 安全」这件事，
 * 在没有视觉能力、无障碍又看不到虚拟屏、{@code screencap -d} 也被拒的条件下
 * 拿不到界面文字。<b>它只读不写</b>：不改任何 View 的内容、不拦任何回调、
 * 不替换任何检测结论，仅仅把 TextView 上已经显示出来的字符串打印出来。
 *
 * <p>这是临时诊断件，验证完就从 HookEntry 里摘掉。
 */
final class UiPeek {
    private static final String TAG = "AntiHookBypass";

    private UiPeek() { }

    static void install(ClassLoader cl) {
        try {
            hookActivityCreate();
        } catch (Throwable t) {
            HookEntry.log("UiPeek 安装失败: " + t);
        }
        try {
            hookNativeScan(cl);
        } catch (Throwable t) {
            HookEntry.log("UiPeek scan 钩子失败: " + t);
        }
    }

    /**
     * 只读地抄下检测器 native 扫描的返回值。
     *
     * <p>为什么用这条路：检测器界面是 Compose 画的，View 树里只有
     * {@code DecorView/LinearLayout/ViewStub/FrameLayout/p1/x/j1}，
     * 一个 TextView 都没有（实测 UIPEEKCLS 输出），所以按 View 树抓不到
     * 「六项结论」这几个字。而它真正做判定的入口是 native 的
     * {@code NativeLib.scan}（符号
     * {@code Java_com_cshlolss_antihook_detect_NativeLib_scan}）。
     *
     * <p>这里<b>只读返回值并打印，一个字节都不改</b>，所以不是"伪造结果"，
     * 只是把原本显示在屏幕上的东西抄出来核对。
     */
    private static void hookNativeScan(ClassLoader cl) throws Throwable {
        Class<?> nl = cl != null ? cl.loadClass("com.cshlolss.antihook.detect.NativeLib")
                                 : Class.forName("com.cshlolss.antihook.detect.NativeLib");
        de.robv.android.xposed.XposedBridge.hookAllMethods(nl, "scan",
                new de.robv.android.xposed.XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            Object r = param.getResult();
                            HookEntry.log("UISCAN result=" + describe(r));
                        } catch (Throwable t) {
                            HookEntry.log("UISCAN 读取失败: " + t);
                        }
                    }
                });
    }

    private static String describe(Object r) {
        if (r == null) return "null";
        if (r instanceof String) return (String) r;
        if (r instanceof byte[]) {
            byte[] b = (byte[]) r;
            StringBuilder sb = new StringBuilder("bytes[" + b.length + "] ");
            int lim = Math.min(b.length, 1200);
            for (int i = 0; i < lim; i++) sb.append((char) (b[i] & 0xff));
            return sb.toString();
        }
        if (r instanceof int[]) {
            int[] a = (int[]) r;
            StringBuilder sb = new StringBuilder("ints[");
            for (int i = 0; i < a.length && i < 64; i++) {
                if (i > 0) sb.append(',');
                sb.append(a[i]);
            }
            return sb.append(']').toString();
        }
        if (r instanceof Object[]) {
            Object[] a = (Object[]) r;
            StringBuilder sb = new StringBuilder("obj[");
            for (int i = 0; i < a.length && i < 64; i++) {
                if (i > 0) sb.append(',');
                sb.append(a[i]);
            }
            return sb.append(']').toString();
        }
        return String.valueOf(r);
    }

    /** 挂 Activity.onCreate，界面画完之后抄一次。 */
    private static void hookActivityCreate() throws Throwable {
        Class<?> at = Class.forName("android.app.Activity");
        de.robv.android.xposed.XposedBridge.hookAllMethods(at, "onCreate",
                new de.robv.android.xposed.XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        final Object a = param.thisObject;
                        if (!(a instanceof Activity)) return;
                        final Activity act = (Activity) a;
                        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
                            @Override public void run() {
                                dumpShot(act, 0);
                            }
                        }, 3000L);
                        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
                            @Override public void run() {
                                dumpShot(act, 1);
                            }
                        }, 9000L);
                        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
                            @Override public void run() {
                                dumpShot(act, 2);
                            }
                        }, 16000L);
                    }
                });
    }

    private static void dump(Activity act, int round) {
        try {
            View root = act.getWindow() == null ? null
                    : act.getWindow().getDecorView();
            if (root == null) return;
            StringBuilder sb = new StringBuilder();
            StringBuilder cls = new StringBuilder();
            walk(root, sb, 0);
            walkCls(root, cls, 0);
            String s = sb.toString();
            /*
             * 分片打印：logcat 单行有上限，整段一次打会被截断，
             * 于是看起来像"没抓到内容"。
             */
            int CH = 700;
            int n = (s.length() + CH - 1) / CH;
            for (int i = 0; i < n; i++) {
                int from = i * CH;
                int to = Math.min(s.length(), from + CH);
                HookEntry.log("UIPEEK r=" + round + " [" + (i + 1) + "/" + n + "] "
                        + s.substring(from, to));
            }
            if (n == 0) HookEntry.log("UIPEEK r=" + round + " (空)");
            HookEntry.log("UIPEEKCLS r=" + round + " " + cls);
        } catch (Throwable t) {
            HookEntry.log("UIPEEK 失败: " + t);
        }
    }

    /** 统计视图类名，用于判断界面是不是自绘（没有 TextView 就抓不到文字）。 */
    private static void walkCls(View v, StringBuilder sb, int depth) {
        if (v == null || depth > 60) return;
        sb.append(v.getClass().getSimpleName()).append('/');
        if (v instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) v;
            int n = g.getChildCount();
            for (int i = 0; i < n; i++) walkCls(g.getChildAt(i), sb, depth + 1);
        }
    }

    /**
     * 把界面改画成纯文本：强转 {@link TextView}、并把非 TextView 的
     * 文字内容也取出来。
     *
     * <p>为什么加这一段：hunter 的列表项用的是自定义 View（{@code UD}）
     * 而不是 TextView，第一版只读 TextView 时整页抓不到一条检测项。
     */
    private static void dumpText(View v, StringBuilder sb, int depth) {
        if (v == null || depth > 80) return;
        if (v instanceof TextView) {
            CharSequence cs = ((TextView) v).getText();
            if (cs != null && cs.length() > 0) sb.append(cs).append('\u0001');
        } else {
            try {
                java.lang.reflect.Method m = v.getClass().getMethod("getText");
                Object r = m.invoke(v);
                if (r instanceof CharSequence && ((CharSequence) r).length() > 0) {
                    sb.append(r).append('\u0001');
                }
            } catch (Throwable ignored) { }
        }
        if (v instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) v;
            for (int i = 0; i < g.getChildCount(); i++) {
                dumpText(g.getChildAt(i), sb, depth + 1);
            }
        }
    }

    /** 抓一屏（含 UD 这类自定义 View 的文字）。 */
    static void dumpShot(Activity act, int round) {
        try {
            View root = act.getWindow() == null ? null
                    : act.getWindow().getDecorView();
            if (root == null) return;
            StringBuilder sb = new StringBuilder();
            dumpText(root, sb, 0);
            String all = sb.toString();
            int CH = 700;
            int n = (all.length() + CH - 1) / CH;
            for (int i = 0; i < n; i++) {
                int from = i * CH;
                int to = Math.min(all.length(), from + CH);
                HookEntry.log("SHOT r=" + round + " [" + (i + 1) + "/" + n + "] "
                        + all.substring(from, to));
            }
        } catch (Throwable t) {
            HookEntry.log("SHOT 失败: " + t);
        }
    }

    private static void walk(View v, StringBuilder sb, int depth) {
        if (v == null || depth > 60) return;
        if (v instanceof TextView) {
            CharSequence cs = ((TextView) v).getText();
            if (cs != null && cs.length() > 0) {
                sb.append(cs).append('\u0001');
            }
        }
        if (v instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) v;
            int n = g.getChildCount();
            for (int i = 0; i < n; i++) walk(g.getChildAt(i), sb, depth + 1);
        }
    }
}
