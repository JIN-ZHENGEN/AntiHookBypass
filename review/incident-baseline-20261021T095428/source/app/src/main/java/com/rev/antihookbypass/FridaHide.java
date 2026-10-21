package com.rev.antihookbypass;

import java.io.File;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Map;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * Frida 痕迹隐藏。
 *
 * <h2>要解决什么</h2>
 * 检测 App 判断"有没有人在用 Frida 调试我"，靠的是一组固定信号。
 * 这份代码把它们逐一按掉，使宿主上即使 frida-server 在跑，
 * 检测方也看不出异常。
 *
 * <h2>覆盖的信号（按检测难度从易到难）</h2>
 * <ol>
 *   <li><b>端口探测</b>：连 127.0.0.1:27042/27043 看是否响应；</li>
 *   <li><b>进程/线程名</b>：读 /proc/self/task/{tid}/comm 找 gum-js-loop、gmain、pool-frida；</li>
 *   <li><b>内存映射</b>：读 /proc/self/maps 找 frida-agent、gum、linjector；</li>
 *   <li><b>命名管道</b>：列 /data/local/tmp 下的 frida-* 文件；</li>
 *   <li><b>so 名</b>：遍历已加载库找 frida-gadget.so。</li>
 * </ol>
 *
 * <h2>分层</h2>
 * <ul>
 *   <li><b>Java 层（本文件）</b>：端口探测、文件列举、Socket 连接。
 *       这类检测通常用 Java 的 Socket / File API，在这里拦最省事。</li>
 *   <li><b>native 层（observe_mask.c）</b>：/proc 内容的过滤。
 *       因为很多检测直接 open+read /proc，Java 层拦不到。</li>
 * </ul>
 */
final class FridaHide {

    private FridaHide() {
    }

    /** Frida 默认端口 */
    private static final int[] FRIDA_PORTS = {27042, 27043};

    /** 文件名里的 frida 特征 */
    private static final String[] FILE_MARKS = {
            "frida", "gum-js-loop", "gmain", "linjector", "frida-server",
    };

    static void install(ClassLoader cl) {
        hookSocketConnect();
        hookFileListing();
        hookProcessListing();
    }

    // ------------------------------------------------------------------
    // 1. 端口探测：连 27042 看是否通
    // ------------------------------------------------------------------

    /**
     * 拦 Socket.connect。
     *
     * <p>检测逻辑通常是：
     * <pre>
     *   new Socket().connect(new InetSocketAddress("127.0.0.1", 27042), 100);
     *   // 连上 → 有 frida
     * </pre>
     * 我们让这个 connect 对 frida 端口抛超时/拒绝，
     * 对方就认为"没有 frida 在跑"。
     */
    private static void hookSocketConnect() {
        try {
            XposedHelpers.findAndHookMethod(
                    Socket.class, "connect", java.net.SocketAddress.class, int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object addr = param.args[0];
                            if (isFridaEndpoint(addr)) {
                                // 抛"连接被拒绝"，这是最自然的结果 ——
                                // 没装 frida 的机器上本来就是这样
                                param.setThrowable(
                                        new java.net.ConnectException("Connection refused"));
                                HookEntry.log("屏蔽 Frida 端口探测: " + addr);
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
        try {
            XposedHelpers.findAndHookMethod(
                    Socket.class, "connect", java.net.SocketAddress.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Object addr = param.args[0];
                            if (isFridaEndpoint(addr)) {
                                param.setThrowable(
                                        new java.net.ConnectException("Connection refused"));
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
    }

    /** 判断目标地址是不是 frida 的默认端口 */
    private static boolean isFridaEndpoint(Object addr) {
        if (!(addr instanceof InetSocketAddress)) return false;
        InetSocketAddress sa = (InetSocketAddress) addr;
        int port = sa.getPort();
        for (int p : FRIDA_PORTS) {
            if (port == p) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 2. 文件列举：/data/local/tmp 下的 frida-* 文件
    // ------------------------------------------------------------------

    /**
     * 拦 File.list / File.listFiles。
     *
     * <p>检测逻辑常这样找痕迹：
     * <pre>
     *   for (String f : new File("/data/local/tmp").list())
     *       if (f.contains("frida")) return "有 frida";
     * </pre>
     * 我们把结果里带 frida 特征的条目剔掉。
     */
    private static void hookFileListing() {
        try {
            XposedBridge.hookAllMethods(File.class, "list", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    /*
                     * 只在"可能暴露 frida 的目录"里过滤，不做全局过滤。
                     * 全局过滤会把任意目录下名字含 gmain/frida 的正常文件也藏掉，
                     * 那是可观测的异常行为（用户会发现文件莫名消失）。
                     */
                    Object self = param.thisObject;
                    if (!(self instanceof File)) return;
                    String dir = ((File) self).getAbsolutePath();
                    if (!(dir.equals("/data/local/tmp") || dir.startsWith("/proc/"))) return;
                    Object r = param.getResult();
                    if (r instanceof String[]) {
                        String[] arr = (String[]) r;
                        java.util.List<String> keep = new java.util.ArrayList<>();
                        boolean changed = false;
                        for (String s : arr) {
                            if (hitMark(s)) { changed = true; continue; }
                            keep.add(s);
                        }
                        if (changed) param.setResult(keep.toArray(new String[0]));
                    }
                }
            });
            XposedBridge.hookAllMethods(File.class, "listFiles", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Object r = param.getResult();
                    if (r instanceof File[]) {
                        File[] arr = (File[]) r;
                        java.util.List<File> keep = new java.util.ArrayList<>();
                        boolean changed = false;
                        for (File f : arr) {
                            if (f != null && hitMark(f.getName())) { changed = true; continue; }
                            keep.add(f);
                        }
                        if (changed) param.setResult(keep.toArray(new File[0]));
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    // ------------------------------------------------------------------
    // 3. 进程/线程列举：/proc 下的 cmdline、comm
    // ------------------------------------------------------------------

    /**
     * 拦 java.lang.ProcessBuilder / Runtime.exec 执行 ps、cat /proc 的情况。
     *
     * <p>不少检测会直接跑 shell 命令：
     * <pre>
     *   Runtime.getRuntime().exec("ps -A | grep frida");
     *   Runtime.getRuntime().exec("cat /proc/self/maps | grep frida");
     * </pre>
     * 我们让这类命令返回空 —— 相当于"没有任何匹配"。
     */
    private static void hookProcessListing() {
        try {
            XposedHelpers.findAndHookMethod(
                    Runtime.class, "exec", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String cmd = (String) param.args[0];
                            if (isFridaProbeCommand(cmd)) {
                                /*
                                 * 不能返回 null —— 调用方通常直接 .getInputStream()，
                                 * 返回 null 会抛 NPE，比"检测到 frida"更像异常特征。
                                 * 改成返回一个真实进程：执行一个必定成功、无输出的命令。
                                 */
                                try {
                                    param.setResult(Runtime.getRuntime().exec(new String[]{"/system/bin/true"}));
                                } catch (Throwable t) {
                                    param.setThrowable(new java.io.IOException("Cannot run program"));
                                }
                                HookEntry.log("拦截 Frida 探测命令: " + cmd);
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
        try {
            XposedBridge.hookAllMethods(ProcessBuilder.class, "start", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Object pb = param.thisObject;
                    if (pb == null) return;
                    try {
                        java.util.List<String> cmd = (java.util.List<String>)
                                XposedHelpers.callMethod(pb, "command");
                        StringBuilder sb = new StringBuilder();
                        for (String s : cmd) sb.append(s).append(' ');
                        if (isFridaProbeCommand(sb.toString())) {
                            try {
                                param.setResult(Runtime.getRuntime().exec(new String[]{"/system/bin/true"}));
                            } catch (Throwable t) {
                                param.setThrowable(new java.io.IOException("Cannot run program"));
                            }
                            HookEntry.log("拦截 Frida 探测进程: " + sb);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    /** 命令里同时出现"进程/文件列举"和"frida 特征" → 判定为探测 */
    private static boolean isFridaProbeCommand(String cmd) {
        if (cmd == null) return false;
        String s = cmd.toLowerCase();
        boolean probe = s.contains("/proc") || s.contains("ps ")
                || s.contains("grep") || s.contains("ls ")
                || s.contains("cat ") || s.contains("find ");
        if (!probe) return false;
        for (String m : FILE_MARKS) {
            if (s.contains(m)) return true;
        }
        return false;
    }

    private static boolean hitMark(String s) {
        if (s == null) return false;
        String l = s.toLowerCase();
        for (String m : FILE_MARKS) {
            if (l.contains(m)) return true;
        }
        return false;
    }
}
