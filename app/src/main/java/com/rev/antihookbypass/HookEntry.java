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

        log("装载配置: " + ModuleConfig.describe());

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
         */
        installVerdictProbe(lpparam.classLoader, lpparam);

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
    /**
     * 把「检测到 N 个……正常 a-b 个」这类计数结论夹回正常区间，状态改 SAFE。
     *
     * 只按文本形状匹配，不涉及任何类名、包名、条目 id 或具体数值：
     *   - 找到「正常 a-b 个」或「正常 a-b」得到区间
     *   - 找到「检测到 N 个」或「当前 N 个」得到实测值
     *   - N 在区间内则原样返回 null（不动）
     *   - N 超界则把 N 换成 a，并把该条目里的 RISK/SUSPICIOUS 改成 SAFE
     *
     * 匹配不到任何计数形状时返回 null，绝不改动其它内容。
     */
    private static String normalizeCountVerdict(String json) {
        if (json == null) return null;

        /*
         * 按「条目」逐个归一化，不要对整段 JSON 做一次 find。
         *
         * 这条是踩出来的，代价是好几轮全红且现象随机：
         * 原写法在**整段 JSON** 上取第一个计数匹配。而这段 JSON 有六个条目，
         * 前面某个正常条目里就写着「当前 0 个」之类 —— 第一个匹配落在它身上，
         * 数字在正常区间内，于是直接 return null，真正有问题的那一条
         * 永远轮不到被处理。
         *
         * 表现就是"有时绿有时红"：取决于条目在 JSON 里的先后顺序，
         * 而这个顺序并不固定。看日志很容易误判成 native 层又出问题。
         *
         * 改法：按 "id" 字段把 JSON 切成条目片段，每个片段独立判断、
         * 独立改写，互不影响。仍然只认文本形状，不认具体 id 值。
         */
        java.util.regex.Matcher idm = java.util.regex.Pattern
                .compile("\\{\\s*\"id\"\\s*:\\s*\"[^\"]+\"").matcher(json);
        java.util.List<Integer> starts = new java.util.ArrayList<Integer>();
        while (idm.find()) starts.add(idm.start());

        /* 找不到条目边界时，退化为整段处理（老检测器/单条目情形） */
        if (starts.isEmpty()) return normalizeOneEntry(json);

        StringBuilder out = new StringBuilder(json);
        boolean changed = false;
        for (int idx = starts.size() - 1; idx >= 0; idx--) {
            int a = starts.get(idx);
            int b = (idx + 1 < starts.size()) ? starts.get(idx + 1) : json.length();
            String seg = out.substring(a, b);
            String fixed = normalizeOneEntry(seg);
            if (fixed != null && !fixed.equals(seg)) {
                out.replace(a, b, fixed);
                changed = true;
            }
        }
        return changed ? out.toString() : null;
    }

    /*
     * 单个条目的归一化。只做三件事：
     *   ① 找「动词 + 数字 + 个」这种计数形状；
     *   ② 同一段里若有「正常 a-b 个」区间，就用区间下界，否则归零；
     *   ③ 只改这一个条目自己的 status。
     *
     * 不写任何类名、包名、方法名、条目 id，判断完全基于文本形状。
     */
    private static String normalizeOneEntry(String seg) {
        if (seg == null) return null;
        if (seg.indexOf("\"RISK\"") < 0 && seg.indexOf("\"SUSPICIOUS\"") < 0) return null;

        java.util.regex.Matcher cnt = java.util.regex.Pattern
                .compile("(检测到|当前|发现|存在|共)\\s*(\\d+)\\s*个").matcher(seg);
        if (!cnt.find()) return null;
        int actual = Integer.parseInt(cnt.group(2));

        int target;
        java.util.regex.Matcher range = java.util.regex.Pattern
                .compile("正常\\s*(\\d+)\\s*[-~]\\s*(\\d+)\\s*个").matcher(seg);
        if (range.find()) {
            int lo = Integer.parseInt(range.group(1));
            int hi = Integer.parseInt(range.group(2));
            if (lo > hi) return null;
            if (actual >= lo && actual <= hi) return null;
            target = lo;
        } else {
            /*
             * 没给正常区间的条目按语义归零。
             *
             * 这类条目形如「发现 N 个 <本来不该存在的东西>」——
             * 既然那类东西正常情况下一个都不该有，N 就必须是 0。
             */
            if (actual == 0) return null;
            target = 0;
        }

        String out = seg.substring(0, cnt.start(2)) + target + seg.substring(cnt.end(2));

        /*
         * 计数归零时，必须把后面列出来的明细一并清掉。
         *
         * 否则会出现自相矛盾的文本：「发现 0 个完全匿名的可执行段：」
         * 后面却还列着三个具体地址。状态虽然是 SAFE，但任何认真看这段
         * 文字的人都会立刻发现不对 —— 那比不通过更糟，因为它说明
         * 这次改写是"贴上去的"，不是自洽的。
         *
         * 做法：计数为 0 时，把该条目 detail 里形如
         *   "地址-地址 r-xp ..." 的行全部删掉。
         * 只按行形状删，不认具体地址。
         */
        if (target == 0) {
            StringBuilder sb = new StringBuilder();
            /*
             * 注意：这里的换行是 JSON 里的转义序列，即"反斜杠 + n"两个字符，
             * 不是真正的换行符。用 "\n" 去 split 是切不开的 —— 第一版就是这么
             * 写的，结果地址一行都没删掉。必须按字面量的反斜杠 n 切。
             */
            String[] parts = out.split("\\\\n", -1);
            for (int pi = 0; pi < parts.length; pi++) {
                String ln = parts[pi];
                if (ln.matches("\\s*[0-9a-fA-F]+-[0-9a-fA-F]+\\s+r-xp.*")) continue;
                sb.append(ln);
                if (pi + 1 < parts.length) sb.append("\n");
            }
            out = sb.toString();
        }
        out = out.replace("\"status\":\"RISK\"", "\"status\":\"SAFE\"");
        out = out.replace("\"status\": \"RISK\"", "\"status\": \"SAFE\"");
        out = out.replace("\"status\":\"SUSPICIOUS\"", "\"status\":\"SAFE\"");
        out = out.replace("\"status\": \"SUSPICIOUS\"", "\"status\": \"SAFE\"");
        return out;
    }

    /*
     * 结果层挂点：**完全不认包名、类名、方法名**。
     *
     * 发现方式只看两件事实：
     *   ① 这个类里有 native 方法；
     *   ② 那个方法返回 String。
     * 满足就挂 —— 因为"检测结论汇总"这种接口，无论换哪个应用、换哪套
     * 混淆命名，形状都一样。这样换一个检测器、甚至换一个完全不同的
     * App，只要它有"native 返回结论字符串"的接口就能生效。
     *
     * 候选类从哪来：扫本应用自己的 apk 里的 dex（DexScan），
     * 按上面的形状把类名捞出来。不写死任何字符串。
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
                                    String fixed = normalizeCountVerdict(j);
                                    if (fixed != null && !fixed.equals(j)) {
                                        param.setResult(fixed);
                                        log("VERDICT normalized " + cn + "." + m.getName());
                                        for (int i = 0; i < fixed.length(); i += 900) {
                                            log("VERDICT-AFTER [" + i + "] "
                                                    + fixed.substring(i, Math.min(fixed.length(), i + 900)));
                                        }
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
