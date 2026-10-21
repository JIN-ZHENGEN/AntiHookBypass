package com.rev.antihookbypass;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 处置拦截：挡住检测逻辑发起的"自我了断"。
 *
 * <h2>为什么必须拦</h2>
 * 绝大多数 Hook 检测工具发现异常后的动作不是弹窗，而是<b>直接杀进程</b>。
 * 具体做法通常是：
 * <pre>
 *   Toast.makeText(ctx, "检测到异常环境", LENGTH_LONG).show();
 *   Thread.sleep(4000);            // 让用户看到提示
 *   Process.killProcess(myPid());
 *   System.exit(0);
 * </pre>
 * 只要把最后两步拦住，用户就能继续用应用。
 *
 * <h2>怎么判断"这次退出是检测发起的"</h2>
 * 这是本实现的关键，也是<b>通用性</b>所在。
 *
 * <p>不认包名、不认类名 —— 那样换个 App 就失效。改用两层结构判据：
 *
 * <ol>
 *   <li><b>调用方是不是"当前应用自己"</b>：如果 kill 的 pid 不是自己，
 *       那是正常的内存清理/多进程管理，不该拦；</li>
 *   <li><b>调用栈里有没有"检测语义"的帧</b>：扫栈顶若干帧，
 *       只要有一帧的类名/方法名含 detect/check/scan/hook/tamper/root 等词，
 *       就认定是检测逻辑在自杀。</li>
 * </ol>
 *
 * <p>两条同时满足才拦。这样既不误伤正常退出，也不依赖任何具体名字。
 *
 * <h2>为什么不无条件拦</h2>
 * 直接拦掉所有 exit 会让应用无法正常退出，用户会以为卡死。
 * 而且一些系统流程（如 crash 处理）依赖 exit 真正生效。
 */
final class KillGuard {

    private KillGuard() {
    }

    /**
     * 栈里出现这些词，说明当前调用链在做"检测/判定"。
     *
     * <p>这些是<b>领域词</b>而不是某个 App 的专名 —— 任何检测工具
     * 都会用其中至少一个来命名自己的判定方法。
     */
    private static final String[] DETECT_WORDS = {
            "detect", "check", "scan", "verify", "inspect", "probe",
            "audit", "validate", "tamper", "hook", "root", "frida",
            "emulator", "debug", "integrity", "risk", "threat", "malware",
            "antihook", "antisys", "protect", "guard", "shield",
    };

    /** 本模块自己的包名，永远不拦（否则会把自己搞崩） */
    private static final String SELF = "com.rev.antihookbypass";

    static void install() {
        hookKillProcess();
        hookExit();
        hookHalt();
        hookSendSignal();
    }

    // ------------------------------------------------------------------
    // 四个处置入口
    // ------------------------------------------------------------------

    private static void hookKillProcess() {
        try {
            XposedHelpers.findAndHookMethod(
                    android.os.Process.class, "killProcess", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            int pid = (Integer) param.args[0];
                            if (shouldBlock(pid)) {
                                param.setResult(null);
                                HookEntry.log("拦截 killProcess(" + pid + ")");
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
    }

    private static void hookExit() {
        try {
            XposedHelpers.findAndHookMethod(
                    java.lang.System.class, "exit", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            if (fromDetector()) {
                                param.setResult(null);
                                HookEntry.log("拦截 System.exit(" + param.args[0] + ")");
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
    }

    private static void hookHalt() {
        try {
            XposedHelpers.findAndHookMethod(
                    java.lang.Runtime.class, "halt", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            if (fromDetector()) {
                                param.setResult(null);
                                HookEntry.log("拦截 Runtime.halt(" + param.args[0] + ")");
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
    }

    private static void hookSendSignal() {
        try {
            XposedHelpers.findAndHookMethod(
                    android.os.Process.class, "sendSignal", int.class, int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            int pid = (Integer) param.args[0];
                            int sig = (Integer) param.args[1];
                            // 只拦"给自己发致命信号"，其它（如给别的进程发）放行
                            boolean fatal = sig == 9 || sig == 6 || sig == 15;
                            if (fatal && shouldBlock(pid)) {
                                param.setResult(null);
                                HookEntry.log("拦截 sendSignal(pid=" + pid + ", sig=" + sig + ")");
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
    }

    // ------------------------------------------------------------------
    // 判定
    // ------------------------------------------------------------------

    /** 是对"自己这个进程"下手，且调用方带检测语义 → 拦 */
    private static boolean shouldBlock(int pid) {
        return pid == android.os.Process.myPid() && fromDetector();
    }

    /**
     * 扫调用栈，判断是不是检测逻辑在发起这次处置。
     *
     * <p>只看前 24 帧：检测逻辑通常在业务方法里直接调 kill，
     * 栈不会很深；看太深反而容易误判到无关的框架帧。
     */
    private static boolean fromDetector() {
        StackTraceElement[] st;
        try {
            st = new Throwable().getStackTrace();
        } catch (Throwable t) {
            return false;
        }
        /*
         * 关键修复：跳过自己的帧，而不是"看到自己的帧就判定不是检测器"。
         *
         * 旧写法 `if (cn.startsWith(SELF)) return false;` 是致命 bug：
         * 这个函数是在 Xposed 回调里被调用的，栈的第 0 帧永远是我们自己的
         * KillGuard$1，于是一进来就 return false —— 四个拦截全部失效，
         * 一个都没拦住过。
         *
         * 正确做法：跳过框架帧和自身帧，继续往上看真正的调用者。
         */
        int limit = Math.min(st.length, 24);
        for (int i = 0; i < limit; i++) {
            StackTraceElement e = st[i];
            String cn = e.getClassName();
            if (cn == null) continue;
            if (cn.startsWith(SELF)
                    || cn.startsWith("de.robv.android.xposed")
                    || cn.startsWith("android.app.ActivityThread")
                    || cn.startsWith("java.lang.reflect")) {
                continue;                                 // 跳过，继续找
            }
            String s = (cn + "." + e.getMethodName()).toLowerCase();
            for (String w : DETECT_WORDS) {
                if (s.contains(w)) return true;
            }
        }
        return false;
    }
}
