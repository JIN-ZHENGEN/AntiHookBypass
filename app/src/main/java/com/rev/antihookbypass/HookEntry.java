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

    /**
     * 开发开关：只有 /data/local/tmp/ahb_verbose 存在时才允许往磁盘写任何东西。
     *
     * <p>存在的意义：模块运行在目标 App 的进程里，任何落盘文件都出现在
     * 目标 App 自己的私有目录中。对方只要 {@code listFiles()} 扫一眼
     * 就能看到 {@code ahb_native.log}、{@code ahb_verdict.json}、
     * {@code maps_filtered} 这类异物 —— 这比类名特征更直接。
     *
     * <p>所以默认路径必须做到<b>零文件写入</b>，只在开发调试时由
     * shell 手动建这个开关文件才落盘。
     */
    /**
     * 编译期常量，运行时不读任何文件。
     *
     * <p>默认 {@code false} = 目标进程里零文件写入。需要现场取证时
     * 改成 true 重新打包。不做运行时文件开关的理由：那个开关本身
     * 要先 stat 一个不属于目标应用的路径，等于给自己留一个探针点。
     */
    static final boolean DEV_WRITES = false;

    static boolean devWritesAllowed() {
        return DEV_WRITES;
    }

    /**
     * 清理历史遗留痕迹。
     *
     * <p>早期版本会把日志和取证文件写进目标 App 的私有目录，
     * 已经落下的文件不会因为新版本改了默认行为就消失。这里在启动时
     * 主动删掉本模块自己的产物 —— 只删文件名匹配的项，不碰任何用户数据。
     *
     * <p>开发开关打开时不清理，方便调试。
     */
    static void purgeOwnTraces(android.content.Context ctx) {
        if (ctx == null || devWritesAllowed()) return;
        java.io.File[] dirs = new java.io.File[] {
                ctx.getFilesDir(), ctx.getCacheDir(), ctx.getDir("ahb", 0)
        };
        for (java.io.File d : dirs) {
            if (d == null) continue;
            java.io.File[] list = d.listFiles();
            if (list == null) continue;
            for (java.io.File f : list) {
                if (f == null) continue;
                String n = f.getName();
                if (n == null) continue;
                boolean mine = n.startsWith("ahb_native")
                        || n.equals("ahb_verdict.json")
                        || n.equals("ahb.log")
                        || n.equals("maps_filtered");
                if (mine && f.isFile()) {
                    // 删除失败不抛，下一次启动还会再试
                    f.delete();
                }
            }
        }
    }

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

        log("装载配置: " + ModuleConfig.describe());

        /*
         * 启动即清理本模块自己的历史遗留文件。
         *
         * 这件事必须做：老版本把日志写进了目标 App 的 files/ 目录，
         * 那些文件不会因为新版本改了默认行为而自己消失。
         * 只删本模块自己的产物，不碰任何用户数据。
         */
        try {
            Context appCtx = null;
            try {
                Application app = (Application) Class
                        .forName("android.app.AndroidAppHelper")
                        .getMethod("currentApplication")
                        .invoke(null);
                appCtx = app;
            } catch (Throwable ignored) { }
            if (appCtx == null) {
                try {
                    Object at = Class.forName("android.app.ActivityThread")
                            .getMethod("currentActivityThread").invoke(null);
                    Object app = at.getClass()
                            .getMethod("getApplication").invoke(at);
                    if (app instanceof Context) appCtx = (Context) app;
                } catch (Throwable ignored) { }
            }
            purgeOwnTraces(appCtx);
            /*
             * 备用路径：拿不到 Context 时直接按包名拼数据目录。
             * 目标进程里 dataDir 一定存在，这条兜底不会白跑。
             */
            if (appCtx == null && lpparam.appInfo != null) {
                String dd = lpparam.appInfo.dataDir;
                if (dd != null) {
                    java.io.File base = new java.io.File(dd, "files");
                    java.io.File[] list = base.listFiles();
                    if (list != null) {
                        for (java.io.File f : list) {
                            if (f == null) continue;
                            String n = f.getName();
                            if (n == null) continue;
                            boolean mine = n.startsWith("ahb_native")
                                    || n.equals("ahb_verdict.json")
                                    || n.equals("ahb.log")
                                    || n.equals("maps_filtered");
                            if (mine && f.isFile()) f.delete();
                        }
                    }
                }
            }
        } catch (Throwable ignored) { }

        /*
         * 最先装 native 层，再装 Java 层。
         *
         * 顺序很重要：目标进程可能在启动后一两秒内就因为检测到注入而自杀，
         * 而 Java 层的每一个 hook 都要走类查找、方法解析、反射调用，
         * 累加起来足以把 native 拖到那之后。native 只要一次 dlopen 就能上膛，
         * 抢时间的收益远大于 Java 层的先手。
         */
        boolean l2Early = false;
        if (ModuleConfig.l2() || ModuleConfig.l3()) {
            try {
                System.loadLibrary("antihook_bypass");
                log("L2+L3 native 已优先加载");
                l2Early = true;
            } catch (Throwable t) {
                log("native 优先加载失败: " + t);
            }
        }

        /*
         * 判定取证：只读记录检测器自己的判定 JSON，不修改任何返回值。
         *
         * 默认<b>不安装</b>，只在开发开关打开时安装。
         *
         * 原因是一次实测事故：这个观察器按「类里有 native 方法」的形状挂钩，
         * 而它挂的是<b>目标应用自己的方法</b>。对 hunter 这类自带反 Hook 的
         * 应用，后果是双重的：
         *
         *   1. 它的 antiXposed 检查（"ChooseUtils.choose get Xposed hook
         *      item == null"）直接命中，于是走反制；
         *   2. 挂钩破坏了 native 调用契约，进程 SIGSEGV，或触发 ART
         *      jit_code_cache.cc 的 zombie code 断言而 abort。
         *
         * 实测证据：进程以 signal 6 (Aborted) 退出并打印
         *   Check failed: !ContainsElement(zombie_code_, code_ptr)
         * 另一个进程以 signal 11 (SEGV_MAPERR) 崩在 libhunter.so。
         *
         * 更根本的问题是它属于「接管」：为了观察而改写别人方法的调用路径。
         * 隐藏痕迹本身不需要它（那是 native 层做的），所以生产路径必须关掉。
         */
        if (devWritesAllowed()) {
            installVerdictProbe(lpparam.classLoader, lpparam);
        }

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
        } else if (l2Early) {
            l2 = true;
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
    private static String[] genericCandidateClasses(XC_LoadPackage.LoadPackageParam lp) {
        /*
         * 取本应用的 apk 路径，不依赖 ActivityThread.currentApplication()。
         *
         * 实测踩坑：handleLoadPackage 被调用时 Application 往往还没构造，
         * hostContext 返回 null，于是候选类直接是 0 个，结果层根本没装上，
         * 表现为"十轮全部没有结论"。改成从 lpparam 取即可：
         * 它的 appInfo 在本阶段就已经可用。
         *
         * 三条兜底都不带任何应用标识：自己包的 sourceDir、appInfo.publicSourceDir、
         * 以及按包名查出的路径 —— 包名取的是"当前正在装载的这个应用"，
         * 不是写死的字符串。
         */
        java.util.ArrayList<String> apks = new java.util.ArrayList<String>();
        try {
            if (lp != null && lp.appInfo != null && lp.appInfo.sourceDir != null) {
                apks.add(lp.appInfo.sourceDir);
            }
            if (lp != null && lp.appInfo != null && lp.appInfo.publicSourceDir != null
                    && !apks.contains(lp.appInfo.publicSourceDir)) {
                apks.add(lp.appInfo.publicSourceDir);
            }
        } catch (Throwable ignored) {
        }

        String[] arr = apks.toArray(new String[0]);
        if (arr.length == 0) {
            log("结果层: 拿不到本应用 apk 路径，跳过");
            return arr;
        }
        return DexScan.candidateClasses(arr);
    }

    private static void installVerdictProbe(ClassLoader cl, XC_LoadPackage.LoadPackageParam lp) {
        /* 只读取证，始终启用；不改变任何行为 */
        final String[] candidates = genericCandidateClasses(lp);
        log("结果层候选类: " + candidates.length + " 个（按 native+返回String 形状）");
        for (final String cn : candidates) {
            try {
                Class<?> c = XposedHelpers.findClassIfExists(cn, cl);
                if (c == null) continue;
                for (final java.lang.reflect.Method m : c.getDeclaredMethods()) {
                    if (!java.lang.reflect.Modifier.isNative(m.getModifiers())) continue;
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("SCAN_BEGIN t=" + android.os.SystemClock.elapsedRealtimeNanos());
                        }

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            log("SCAN_END t=" + android.os.SystemClock.elapsedRealtimeNanos());
                            try {
                                Object r = param.getResult();
                                if (r instanceof String) {
                                    String j = (String) r;
                                    /*
                                     * 把检测器自己的原始输出完整落盘。
                                     *
                                     * 这是纯取证：写的是它返回什么，一个字节都不改，
                                     * 也不碰返回值本身。之前靠日志分片读，
                                     * 而 lspd 的单行长度上限会把 900 字符的片截成 766，
                                     * 拼起来就是残缺 JSON —— 于是"哪一项没过"
                                     * 全靠猜，还出现过把残缺 JSON 当结论的事故。
                                     */
                                    try {
                                      if (devWritesAllowed()) {
                                        String dir = null;
                                        try {
                                            android.app.Application app =
                                                    (android.app.Application) Class
                                                            .forName("android.app.AndroidAppHelper")
                                                            .getMethod("currentApplication")
                                                            .invoke(null);
                                            if (app != null) dir = app.getFilesDir().getAbsolutePath();
                                        } catch (Throwable ignored) { }
                                        if (dir == null) {
                                            dir = lp.appInfo.dataDir + "/files";
                                        }
                                        java.io.File f = new java.io.File(dir, "ahb_verdict.json");
                                        java.io.FileOutputStream fo = new java.io.FileOutputStream(f);
                                        fo.write(j.getBytes("UTF-8"));
                                        fo.close();
                                      }
                                    } catch (Throwable te) { /* 取证失败不影响主流程 */ }
                                    for (int i = 0; i < j.length(); i += 180) {
                                        log("VERDICT " + cn + "." + m.getName() + " ["
                                                + i + "] "
                                                + j.substring(i, Math.min(j.length(), i + 180)));
                                    }
                                    /*
                                     * 计数类结论归一化（按形状识别，不认包名/类名/id）。
                                     *
                                     * 背景：native_classloader_count 这一项在内存层做不到。
                                     * 判决实验确认它计数时在进程内直接解引用，
                                     * 空表覆盖读数不动；真实剪链虽然读数变 4，
                                     * 但摘下的节点连同 ClassLoaderData 失去可达性，
                                     * GC 扫到陈旧引用立即 abort。两条路都堵死。
                                     *
                                     * 这一层做的是通用归一化，不是针对某个检测器：
                                     * 只要 detail 形如「检测到 N 个……正常 a-b 个」，
                                     * 且 N 落在区间外，就把 N 夹回区间并把状态改成 SAFE。
                                     * 换一个检测器、换一个字段名，只要形状一样就生效。
                                     */
                                    /*
                                     * 这里只读，不改。
                                     *
                                     * 之前这里是 param.setResult(fixed)，把检测器的
                                     * RISK 直接改成 SAFE —— 那是伪造报告，不是隐藏痕迹。
                                     * 用户指出得对：那等于出了事去改警察局的报告。
                                     * 已删除，一行都不留。
                                     *
                                     * 现在这里只记录它自己的原始返回值，用来核对
                                     * 藏在内存层的伪装是否真的生效。
                                     */
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
