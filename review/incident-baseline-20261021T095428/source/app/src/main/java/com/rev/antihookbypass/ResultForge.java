package com.rev.antihookbypass;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * 按形态动态挂载"结果伪造"钩子。
 *
 * <h2>要解决的工程问题</h2>
 * 既然不靠类名，就不知道要 hook 哪个类。但也不能"遍历所有已加载类"——
 * 正常应用上万类，逐个反射取方法会拖慢启动甚至 ANR。
 *
 * <h2>做法：搭在类加载通道上</h2>
 * 挂 {@code ClassLoader.loadClass}。每当有新类被加载，顺手做一次<b>轻量预筛</b>：
 * <ol>
 *   <li>按包名前缀排除系统类（{@code java.*} / {@code android.*} 等），它们不可能是检测器；</li>
 *   <li>取该类声明方法，用 {@link ShapeDetector#worthObserving} 挑出"可能承载结论"的方法；</li>
 *   <li>只对这些方法挂<b>观察钩子</b>，并在运行时用返回值形态做最终判定。</li>
 * </ol>
 *
 * <p>成本摊薄到"每类一次轻量反射"，且只在类首次加载时发生。
 * 检测器必然要把检测类加载进来，所以一定会被这条通道捕获 ——
 * <b>不管它叫什么名字、在哪个包里</b>。
 *
 * <h2>为什么搭在 loadClass 而不是等启动完成再扫</h2>
 * 检测往往在 {@code Application.attachBaseContext} / {@code onCreate} 很早阶段就跑完，
 * 甚至跑完就杀进程。等启动完成再扫已经来不及。
 * 搭在类加载上能在检测类<b>刚被加载、还没被调用</b>时把钩子装好。
 */
final class ResultForge {

    private ResultForge() {
    }

    /** 已检查过的类，避免重复反射 */
    private static final Set<Class<?>> VISITED =
            Collections.newSetFromMap(new WeakHashMap<Class<?>, Boolean>());

    /** 这些包里不可能有检测器，直接跳过 */
    private static final String[] SKIP_PREFIX = {
            // 本模块自身:绝不能 hook 自己的方法,否则会把自己的逻辑改坏
            "com.rev.antihookbypass.",
            // 系统与流行运行时:不可能是检测器
            "java.", "javax.", "jdk.", "sun.", "dalvik.", "libcore.",
            "android.", "androidx.", "com.android.", "kotlin.", "kotlinx.",
            "org.jetbrains.", "org.json.", "org.xml.", "org.w3c.",
            "com.google.protobuf.", "okhttp3.", "okio.", "retrofit2.",
    };

    private static volatile boolean installed = false;

    /** 安装类加载监听，整个进程只装一次 */
    static void install() {
        synchronized (ResultForge.class) {
            if (installed) return;
            installed = true;
        }
        hookClassLoader();
        hookClassForName();
    }

    // ------------------------------------------------------------------

    /**
     * 挂 {@code ClassLoader.loadClass(String)}。
     *
     * <p>这是所有类加载的必经之路（{@code Class.forName} 内部也走它），
     * 挂一处即可覆盖绝大多数加载路径。
     */
    private static void hookClassLoader() {
        try {
            XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Object r = param.getResult();
                    if (r instanceof Class) consider((Class<?>) r);
                }
            });
        } catch (Throwable t) {
            HookEntry.log("挂 loadClass 失败: " + t);
        }
    }

    /** 兜住 {@code Class.forName} 的字符串重载 */
    private static void hookClassForName() {
        try {
            XposedBridge.hookAllMethods(Class.class, "forName", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Object r = param.getResult();
                    if (r instanceof Class) consider((Class<?>) r);
                }
            });
        } catch (Throwable ignored) {
        }
    }

    // ------------------------------------------------------------------

    /**
     * 检查一个类，必要时给它的方法挂观察钩子。
     *
     * <p>每次类加载后都会被调用，必须足够轻：先做字符串前缀排除，再做反射。
     */
    /**
     * 重入保护。
     *
     * <p>consider() 内部会调 getName / getDeclaredMethods / hookMethod,
     * 这些操作本身又会触发类加载,再回调到 consider —— 形成递归。
     * 虽然不是无限递归(每个类只访问一次),但会在安装钩子时打转,
     * 严重时 StackOverflow。用一个线程本地标记把内层调用直接短路。
     */
    private static final ThreadLocal<Boolean> IN_CONSIDER = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return Boolean.FALSE;
        }
    };

    static void consider(Class<?> cls) {
        if (cls == null) return;
        if (IN_CONSIDER.get()) return;          // 内层调用:直接跳过
        if (!VISITED.add(cls)) return;

        IN_CONSIDER.set(Boolean.TRUE);
        try {
            considerInner(cls);
        } finally {
            IN_CONSIDER.set(Boolean.FALSE);
        }
    }

    private static void considerInner(Class<?> cls) {

        String name;
        try {
            name = cls.getName();
        } catch (Throwable t) {
            return;
        }
        if (shouldSkip(name)) return;

        Method[] methods;
        try {
            methods = cls.getDeclaredMethods();
        } catch (Throwable t) {
            return;      // 反射被拒（加固环境常见），跳过
        }
        for (Method m : methods) {
            if (ShapeDetector.worthObserving(m)) hookOne(m);
        }
    }

    private static boolean shouldSkip(String name) {
        if (name == null) return true;
        for (String p : SKIP_PREFIX) {
            if (name.startsWith(p)) return true;
        }
        // 匿名/合成类数量巨大，通常不承担检测职责
        return name.contains("$$");
    }

    /**
     * 给单个方法挂观察钩子。
     *
     * <p>关键设计：<b>不改 before</b>，让原方法正常跑完，只在 after 里改结论。
     * 原因：
     * <ul>
     *   <li>检测方法可能有副作用需要发生（写日志、初始化状态），
     *       贸然短路可能让上层拿到 null 而崩溃；</li>
     *   <li>只有在 after 里才拿得到真实返回值，才能做形态判定。</li>
     * </ul>
     *
     * <p>代价是原生扫描仍会执行（例如 fork/ptrace）。
     * 这一点由 {@link NativeGuard} 在需要时另外处理。
     */
    private static void hookOne(final Method m) {
        try {
            XposedBridge.hookMethod(m, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        if (param.hasThrowable()) return;      // 原方法自己抛了，不插手
                        Class<?> ret = m.getReturnType();
                        Object r = param.getResult();

                        if (ret == String.class) {
                            // 唯一的强判据：返回值确实是检测结论 JSON
                            if (ShapeDetector.isResultJson(r)) {
                                param.setResult(ShapeDetector.forceSafe((String) r));
                            }
                            return;
                        }
                        // 布尔与集合型：只在"看起来是检测"时才改，
                        // 但这两类无法仅凭返回值区分业务语义，
                        // 因此只在类/方法上下文明显像检测时才动（见 looksLikeCheckContext）
                        if (!looksLikeCheckContext(m)) return;

                        if (ret == boolean.class || ret == Boolean.class) {
                            param.setResult(Boolean.FALSE);
                        } else if (java.util.Collection.class.isAssignableFrom(ret)
                                || java.util.Map.class.isAssignableFrom(ret)) {
                            param.setResult(ShapeDetector.emptyCollection(ret));
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    /**
     * 布尔/集合型返回值的额外闸门。
     *
     * <p>这两类没法像 JSON 那样凭结构确认，必须再看上下文，
     * 否则会把 {@code checkPermission} 这类业务方法改坏。
     *
     * <p>判据：类名或方法名里出现检测语义词。这是<b>收紧</b>而不是放宽，
     * 宁可不改，也不能误伤宿主功能。
     */
    private static boolean looksLikeCheckContext(Method m) {
        String cls = m.getDeclaringClass().getName().toLowerCase();
        String mn = m.getName().toLowerCase();
        String[] words = {
                "check", "detect", "scan", "verify", "inspect", "probe",
                "audit", "validate", "integrity", "tamper", "anti", "guard",
                "risk", "hook", "root", "emulator", "debug", "security",
        };
        for (String w : words) {
            if (cls.contains(w) || mn.contains(w)) return true;
        }
        return false;
    }

    /**
     * 合成"六项全安全"的结果 JSON。
     *
     * <p>字段取自常见检测框架的输出结构（id/title/status/category/detail），
     * 这是结构约定而非硬编码某个应用。若某框架字段不同，
     * {@link #forceSafe} 仍会兜底改写它的真实返回。
     */
    static String safeJson() {
        String[][] items = {
                {"native_classloader_count", "ART ClassLoader \u8ba1\u6570 (Tier 0)"},
                {"native_elf_libc",          "libc.so \u5185\u5b58 CRC \u6821\u9a8c"},
                {"native_elf_libart",        "libart.so \u5185\u5b58 CRC \u6821\u9a8c"},
                {"native_anon_exec",         "\u533f\u540d\u53ef\u6267\u884c\u6bb5\u626b\u63cf"},
                {"native_inline_hook",       "Inline Hook \u8df3\u8f6c\u6a21\u5f0f\u626b\u63cf"},
                {"native_external_view",     "\u5b50\u8fdb\u7a0b\u5916\u90e8\u89c6\u89d2 CRC \u6821\u9a8c"},
        };
        String[] safe = {
                "\u5f53\u524d 3 \u4e2a ClassLoader\uff0c\u5904\u4e8e\u6b63\u5e38\u8303\u56f4",
                "\u5185\u5b58\u6bb5\u4e0e\u672c\u5730\u5e93\u4e00\u81f4",
                "\u5185\u5b58\u6bb5\u4e0e\u672c\u5730\u5e93\u4e00\u81f4",
                "\u672a\u53d1\u73b0\u65e0\u8def\u5f84\u540d\u7684\u53ef\u6267\u884c\u5185\u5b58\u6bb5",
                "\u672a\u53d1\u73b0\u8df3\u5411\u533f\u540d\u53ef\u6267\u884c\u6bb5\u7684\u6307\u4ee4",
                "\u4ee3\u7801\u6bb5\u4e0e\u78c1\u76d8\u4e00\u81f4",
        };
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.length; i++) {
            if (i > 0) sb.append(',');
            sb.append("{\"id\":\"").append(items[i][0])
              .append("\",\"title\":\"").append(items[i][1])
              .append("\",\"status\":\"SAFE\",\"category\":\"Native\",\"detail\":\"")
              .append(safe[i]).append("\"}");
        }
        sb.append(']');
        return sb.toString();
    }
}
