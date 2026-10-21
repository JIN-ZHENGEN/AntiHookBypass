package com.rev.antihookbypass;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * 检测出口接管：识别并改写"检测结论"，不依赖任何具体类名或包名。
 *
 * <h2>设计原则</h2>
 * 一个模块如果要通杀各种检测工具，就不能认名字 —— 换个 App 名字全变了。
 * 唯一不随 App 变的是<b>检测结论的形状</b>：
 *
 * <ul>
 *   <li>它是一组"通过/不通过"的判定；</li>
 *   <li>要么以 JSON 数组形式返回（每项含 status/passed/detected 等字段）；</li>
 *   <li>要么以 boolean / 枚举 / 列表形式返回；</li>
 *   <li>它必然出现在某个"返回结论"的方法里，而且这个方法通常带
 *       scan/check/detect/verify/inspect 这类动词。</li>
 * </ul>
 *
 * <p>所以本类只依据上述形状判断，不看包名、不看类名、不看具体检测项 id。
 *
 * <h2>与 {@link ScanBreaker} 的分工</h2>
 * <ul>
 *   <li>{@code ScanBreaker} 负责"别让它跑" —— 直接短路高成本的 native 扫描，
 *       省时间、少留痕；</li>
 *   <li>本类负责"跑了也要说安全" —— 对真实返回做结构改写。
 *       两条腿都留着，因为有些检测跑得很快、短路反而显得可疑（结果为空）。</li>
 * </ul>
 *
 * <h2>为什么改写而非伪造</h2>
 * 凭空造一份"六项全 SAFE"的 JSON 是很强的特征：
 * 项数、id、title 一旦和对方的真实清单对不上，立刻暴露。
 * 正确做法是<b>拿真实结果逐字段翻成安全值</b>，其它字段原样保留。
 */
final class ExitHook {

    private ExitHook() {
    }

    /** 已挂过的类，避免重复 */
    private static final Set<Class<?>> DONE =
            Collections.newSetFromMap(new WeakHashMap<Class<?>, Boolean>());

    /** 方法名里的检测语义词（结构特征，不是某个 App 的专名） */
    private static final String[] VERBS = {
            "scan", "check", "detect", "verify", "inspect", "probe",
            "audit", "validate", "judge", "analyze", "analyse", "test",
            "is", "has", "get",
    };

    /**
     * 入口：扫描当前已加载的类，挂上所有可能返回结论的方法。
     *
     * <p>不用类名列表，而是遍历 ClassLoader 里已加载的类 ——
     * 这样对任何检测 App 都有效。
     */
    static int install(final ClassLoader cl) {
        // 先挂 loadClass：之后任何类加载都会过一遍我们的检查
        try {
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (!(r instanceof Class<?>)) return;
                            Class<?> c = (Class<?>) r;
                            try {
                                String nm = c.getName();
                                if (nm.startsWith("java.") || nm.startsWith("android.")
                                        || nm.startsWith("androidx.") || nm.startsWith("kotlin.")
                                        || nm.startsWith("dalvik.")
                                        || nm.startsWith("com.rev.antihookbypass")) {
                                    return;
                                }
                                hookClass(c);
                            } catch (Throwable ignored) {
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }

        // 定期重扫：类可能在任何时刻才被加载，
        // 单次扫描必然漏，必须反复补。
        // 用主线程 Handler 而不是新线程 —— 不引入额外线程，避免被检测到线程数异常。
        try {
            final android.os.Handler h =
                    new android.os.Handler(android.os.Looper.getMainLooper());
            final int[] delays = {200, 600, 1500, 3000, 6000};
            for (final int d : delays) {
                h.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        try { rescan(cl); } catch (Throwable ignored) {}
                    }
                }, d);
            }
        } catch (Throwable ignored) {
        }

        // 再立即扫一遍当前已加载的
        int n = 0;
        try {
            java.lang.reflect.Field f = ClassLoader.class.getDeclaredField("classes");
            f.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Vector<Class<?>> v = (java.util.Vector<Class<?>>) f.get(cl);
            if (v == null) return 0;
            java.util.List<Class<?>> snap;
            synchronized (v) {
                snap = new java.util.ArrayList<>(v);
            }
            for (Class<?> c : snap) {
                if (c == null) continue;
                String nm = c.getName();
                if (nm.startsWith("java.") || nm.startsWith("android.")
                        || nm.startsWith("androidx.") || nm.startsWith("kotlin.")
                        || nm.startsWith("dalvik.") || nm.startsWith("com.rev.antihookbypass")) {
                    continue;
                }
                n += hookClass(c);
            }
            if (n > 0) HookEntry.log("ExitHook 挂载 " + n + " 个方法");
        } catch (Throwable ignored) {
        }
        return n;
    }

    /**
     * 挂一个类里所有"看起来会返回检测结论"的方法。
     *
     * @return 挂上的方法数
     */
    static int hookClass(Class<?> c) {
        if (c == null) return 0;
        int n = 0;
        try {
            for (Method m : c.getDeclaredMethods()) {
                if (!couldReturnVerdict(m)) continue;
                if (hookOne(m)) {
                    n++;
                    int mod = m.getModifiers();
                    if ((mod & 0x0100) != 0) {      // native
                        HookEntry.log("盯上 native 出口: "
                                + c.getName() + "." + m.getName()
                                + " -> " + m.getReturnType().getSimpleName());
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return n;
    }

    /** 重扫已加载的类，补挂新出现的检测出口 */
    static void rescan(ClassLoader cl) {
        try {
            java.lang.reflect.Field f = ClassLoader.class.getDeclaredField("classes");
            f.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Vector<Class<?>> v = (java.util.Vector<Class<?>>) f.get(cl);
            if (v == null) return;
            java.util.List<Class<?>> snap;
            synchronized (v) {
                snap = new java.util.ArrayList<>(v);
            }
            int total = 0;
            for (Class<?> c : snap) {
                if (c == null) continue;
                String nm = c.getName();
                if (nm.startsWith("java.") || nm.startsWith("android.")
                        || nm.startsWith("androidx.") || nm.startsWith("kotlin.")
                        || nm.startsWith("dalvik.") || nm.startsWith("com.rev.antihookbypass")) {
                    continue;
                }
                total += hookClass(c);
            }
            if (total > 0) HookEntry.log("重扫补挂 " + total + " 个方法");
        } catch (Throwable ignored) {
        }
    }

    /**
     * 判断一个方法是否可能返回"检测结论"。
     *
     * <p>只看返回类型与形状，不看名字（名字只用来提高优先级，不作为必要条件）。
     * 这样即使对方把方法名混淆成 a/b/c，只要它返回 String 且内容是结论 JSON，
     * 依然会被 {@link #looksLikeVerdictJson} 在运行期识别出来。
     */
    private static boolean couldReturnVerdict(Method m) {
        int mod = m.getModifiers();
        if (java.lang.reflect.Modifier.isAbstract(mod)) return false;

        // native 方法无条件接管 —— 参数个数/返回类型都不作限制。
        // 理由：检测结论的出口一定在 native 边界上（这是 JNI 的结构事实），
        // 而 native 方法总数很少，全挂的开销可忽略。
        // 之前用参数个数过滤，反而把真正的出口漏掉了。
        if ((mod & 0x0100) != 0) return true;

        if (m.getParameterCount() > 6) return false;

        Class<?> r = m.getReturnType();
        if (r == String.class
                || r == boolean.class || r == Boolean.class
                || java.util.List.class.isAssignableFrom(r)
                || java.util.Map.class.isAssignableFrom(r)) {
            return true;
        }

        /*
         * 额外覆盖：native 方法一律挂。
         *
         * 理由：检测逻辑放 native 里，返回值可能是任何类型
         * （jstring / jbyteArray / jint 分数 / jobject 数组）。
         * 不能因为"返回类型不认识"就放过 —— 那是最大的漏网口。
         * native 方法数量有限，全挂的开销可以忽略。
         */
        return (mod & 0x0100) != 0;      // Modifier.NATIVE
    }

    /**
     * 运行期判断：这个返回值是不是"检测结论"。
     *
     * <p>这是真正起作用的判据。只认内容形状：
     * JSON 数组 + 对象 + 含判定类字段。
     */
    static boolean looksLikeVerdictJson(Object v) {
        if (!(v instanceof String)) return false;
        String s = ((String) v).trim();
        if (s.length() < 8) return false;
        if (s.charAt(0) != '[' || s.charAt(s.length() - 1) != ']') return false;
        if (s.indexOf('{') < 0) return false;
        return s.contains("\"status\"") || s.contains("\"passed\"")
                || s.contains("\"detected\"") || s.contains("\"result\"")
                || s.contains("\"safe\"") || s.contains("\"ok\"");
    }

    /**
     * 挂单个方法。
     *
     * <p>策略：<b>不短路，让它真实执行</b>，然后在 after 里改写结果。
     * 这样做的原因：
     * <ul>
     *   <li>短路会让 native 扫描完全不跑，但如果对方同时统计"扫描耗时"
     *       或"扫描了 N 个段"，立刻不一致；</li>
     *   <li>让它跑完再改，行为面完全正常，只是结论变安全。</li>
     * </ul>
     *
     * <p>只有一种情况例外：方法本身是 {@code native} 且开销很大
     * （比如 fork 子进程做 ptrace 回读），那种交给
     * {@code native_main.c} 里的 L2/L3 处理，这层只管结果。
     */
    private static boolean hookOne(final Method m) {
        try {
            XposedBridge.hookMethod(m, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param.hasThrowable()) return;
                    Object v = param.getResult();
                    if (v == null) return;

                    // 情况 1：JSON 结论 → 逐字段翻成安全值
                    if (looksLikeVerdictJson(v)) {
                        String fixed = ShapeDetector.forceSafe((String) v);
                        if (fixed != null && !fixed.equals(v)) {
                            param.setResult(fixed);
                            HookEntry.log("改写检测结论: "
                                    + m.getDeclaringClass().getSimpleName()
                                    + "." + m.getName());
                        }
                        return;
                    }

                    // 情况 2b：byte[] 结论（native 常返回 jbyteArray 装 JSON）
                    if (v instanceof byte[]) {
                        try {
                            String s = new String((byte[]) v, "UTF-8").trim();
                            if (looksLikeVerdictJson(s)) {
                                param.setResult(ShapeDetector.forceSafe(s).getBytes("UTF-8"));
                                HookEntry.log("改写 byte[] 检测结论: "
                                        + m.getDeclaringClass().getSimpleName()
                                        + "." + m.getName());
                                return;
                            }
                        } catch (Throwable ignored) {
                        }
                    }

                    // 情况 3：数值型风险分 → 归零
                    //   很多检测返回 int 表示"发现几项异常"，0 就是安全。
                    if (v instanceof Integer) {
                        String ln0 = m.getName().toLowerCase();
                        boolean riskLike = ln0.contains("risk") || ln0.contains("score")
                                || ln0.contains("count") || ln0.contains("level")
                                || ln0.contains("danger") || ln0.contains("threat");
                        if (riskLike && ((Integer) v) != 0) {
                            param.setResult(0);
                            HookEntry.log("改写数值结论: "
                                    + m.getDeclaringClass().getSimpleName()
                                    + "." + m.getName());
                            return;
                        }
                    }

                    // 情况 2：boolean 结论 → 统一返回"未检测到"的语义
                    //   注意方向：这类方法通常语义是 isDetected() / hasHook()，
                    //   返回 true 才是"有问题"。所以统一给 false。
                    if (v instanceof Boolean && m.getName().length() > 2) {
                        String ln = m.getName().toLowerCase();
                        if (ln.contains("detect") || ln.contains("hook")
                                || ln.contains("root") || ln.contains("tamper")
                                || ln.contains("debug") || ln.contains("emu")) {
                            if ((Boolean) v) {
                                param.setResult(Boolean.FALSE);
                                HookEntry.log("改写布尔结论: "
                                        + m.getDeclaringClass().getSimpleName()
                                        + "." + m.getName());
                            }
                        }
                    }
                }
            });
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}
