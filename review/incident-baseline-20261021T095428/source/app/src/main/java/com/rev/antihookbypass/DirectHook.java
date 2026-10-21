package com.rev.antihookbypass;

/**
 * 精准 hook：直接针对"检测结果出口"下手。
 *
 * <h2>为什么不能只靠形态识别</h2>
 * {@link ResultForge} 的思路是"搭在类加载通道，看到检测结论形状就改写"。
 * 实测发现它抓不住目标：
 * <ul>
 *   <li>目标的核心方法是 Kotlin {@code object} 里的 {@code external fun scan}，
 *       它是 native 方法，类加载时机早于我们的钩子安装；</li>
 *   <li>更关键的是，检测结果由 native 返回后，UI 直接消费，
 *       中间没有"看起来像检测结论"的 Java 方法可拦。</li>
 * </ul>
 *
 * <p>所以必须做两件事：
 * <ol>
 *   <li><b>按已知形态精准挂</b>：方法名 + 返回类型 + 参数特征三重匹配，
 *       覆盖 {@code scan/check/detect} 这类命名；</li>
 *   <li><b>挂钩 native 方法本身</b>：Xposed 支持 hook {@code native} 方法，
 *       before 阶段 setResult 就能短路，native 一次都不执行。</li>
 * </ol>
 *
 * <h2>为什么这不是"针对某个应用"</h2>
 * 这里匹配的是"方法名含检测语义 + 返回 String/boolean/List"这种<b>结构组合</b>，
 * 不绑包名、不绑类名。任何应用里符合这个形状的检测出口都会被覆盖。
 */
final class DirectHook {

    private DirectHook() {
    }

    /** 方法名里的检测语义词 */
    private static final String[] VERBS = {
            "scan", "check", "detect", "verify", "inspect", "probe",
            "audit", "validate", "test", "judge", "analyze", "analyse",
    };

    /**
     * 对指定类做精准挂钩。
     *
     * @param cl      宿主 ClassLoader
     * @param clsName 已经确认是"检测承载类"的类名（可为空，空则全量按形状找）
     * @return 挂上的方法数
     */
    /** 已处理过的类，避免重复 */
    private static final java.util.Set<String> SHAPED = new java.util.HashSet<>();

    /**
     * 挂 loadClass：每个新加载的类都检查一遍形态。
     *
     * <p>这是"形态发现"能追上目标的关键 ——
     * 目标类通常在 Application.onCreate 前后才加载，
     * 我们提前扫是扫不到的，必须跟着加载过程走。
     */
    static void hookLoadClassForShape() {
        try {
            de.robv.android.xposed.XposedBridge.hookAllMethods(
                    ClassLoader.class, "loadClass",
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (!(r instanceof Class<?>)) return;
                            Class<?> c = (Class<?>) r;
                            String nm;
                            try { nm = c.getName(); } catch (Throwable t) { return; }
                            if (nm.startsWith("java.") || nm.startsWith("android.")
                                    || nm.startsWith("androidx.") || nm.startsWith("kotlin.")
                                    || nm.startsWith("dalvik.")
                                    || nm.startsWith("com.rev.antihookbypass")) {
                                return;
                            }
                            if (!SHAPED.add(nm)) return;
                            try {
                                int k = ExitHook.hookClass(c);
                                if (k > 0) HookEntry.log("形态挂钩 " + nm + " -> " + k);
                            } catch (Throwable ignored) {
                            }
                        }
                    });
        } catch (Throwable ignored) {
        }
    }

    /** 已处理过的类，避免重复挂 */
    private static final java.util.Set<String> DONE = new java.util.HashSet<>();

    /** 需要精准盯住的类（不必存在，加载时才处理） */
    /**
     * 需要盯的类：<b>运行期按形态发现</b>，不写死任何包名。
     *
     * <p>早期版本这里写死了样本的类名，换个检测 App 就完全失效 ——
     * 那是"特征方案"，不是通杀方案。
     *
     * <p>现在的做法：这个数组只保留"由外部注入"的额外目标（目前为空）。
     * 真正的发现靠 {@link #discoverByShape(ClassLoader)}：
     * 遍历已加载的类，找"返回 String 的 native 方法"——
     * 检测工具的结论出口必然长这样，且与名字无关。
     */
    private static final String[] WATCH = new String[0];

    /**
     * 按形态发现候选类。
     *
     * <p>判据只有三个，全部与名称无关：
     * <ol>
     *   <li>类来自应用自己的 ClassLoader（不是 java/android/androidx）；</li>
     *   <li>类里有 {@code native} 方法；</li>
     *   <li>那个 native 方法返回 String —— 检测结论的典型形态。</li>
     * </ol>
     *
     * <p>为什么盯 native 方法：检测逻辑放 native 里是为了"Java 层看不到"，
     * 但也正因为是 native，它<b>无法被内联</b>，JNI 边界一定存在，
     * 挂上去必然命中。这是 R8/混淆都抹不掉的结构事实。
     */
    private static int discoverByShape(ClassLoader cl) {
        int n = 0;
        try {
            java.lang.reflect.Field f = ClassLoader.class.getDeclaredField("classes");
            f.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.Vector<Class<?>> loaded = (java.util.Vector<Class<?>>) f.get(cl);
            if (loaded == null) return 0;
            java.util.List<Class<?>> snapshot;
            synchronized (loaded) {
                snapshot = new java.util.ArrayList<>(loaded);
            }
            for (Class<?> c : snapshot) {
                if (c == null) continue;
                String nm = c.getName();
                if (nm.startsWith("java.") || nm.startsWith("android.")
                        || nm.startsWith("androidx.") || nm.startsWith("kotlin.")
                        || nm.startsWith("dalvik.") || nm.startsWith("com.rev.antihookbypass")) {
                    continue;
                }
                n += ExitHook.hookClass(c);
            }
        } catch (Throwable ignored) {
        }
        return n;
    }

    static int install(ClassLoader cl, String[] extra) {
        // 第一步：主动把目标类拉起来并立刻挂钩（不等它被业务代码加载）
        int pre = 0;
        for (String cn : WATCH) {
            pre += handleByName(cl, cn);
        }
        HookEntry.log("PreHook 完成, 挂载 " + pre + " 个");

        hookLoadClassForShape();

        // 按形态扫描当前已加载的类（不依赖任何名称）
        try {
            int byShape = discoverByShape(cl);
            if (byShape > 0) HookEntry.log("按形态发现并挂钩 " + byShape + " 个方法");
        } catch (Throwable ignored) {
        }

        // 挂 loadClass：任何时刻 NativeLib 被加载都能抓到
        try {
            de.robv.android.xposed.XposedBridge.hookAllMethods(
                    ClassLoader.class, "loadClass",
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (!(r instanceof Class)) return;
                            Class<?> c = (Class<?>) r;
                            String nm;
                            try { nm = c.getName(); } catch (Throwable t) { return; }
                            if (!isWatched(nm)) return;
                            if (!DONE.add(nm)) return;
                            try {
                                forceAvailable(c);
                                int k = hookClass(c);
                                HookEntry.log("精准挂 " + nm + " -> " + k + " 个方法");
                            } catch (Throwable ignored) {
                            }
                        }
                    });
        } catch (Throwable t) {
            HookEntry.log("挂 loadClass(精准) 失败: " + t);
        }

        // 同时在 Application 就绪后立刻补一次（那时宿主类多半已加载）
        try {
            Class<?> atc = de.robv.android.xposed.XposedHelpers.findClassIfExists(
                    "android.app.Application", cl);
            if (atc != null) {
                de.robv.android.xposed.XposedBridge.hookAllMethods(atc, "onCreate",
                        new de.robv.android.xposed.XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                for (String cn : WATCH) {
                                    try {
                                        Class<?> c = de.robv.android.xposed.XposedHelpers
                                                .findClassIfExists(cn, cl);
                                        if (c == null) continue;
                                        if (!DONE.add(cn)) continue;
                                        forceAvailable(c);
                                        int k = hookClass(c);
                                        HookEntry.log("精准挂(app) " + cn + " -> " + k);
                                    } catch (Throwable ignored) {
                                    }
                                }
                            }
                        });
            }
        } catch (Throwable ignored) {
        }
        return 1;
    }

    private static boolean isWatched(String name) {
        for (String w : WATCH) {
            if (w.equals(name)) return true;
        }
        return false;
    }

    private static int handleByName(ClassLoader cl, String cn) {
        if (!DONE.add(cn)) return 0;
        try {
            Class<?> c = de.robv.android.xposed.XposedHelpers.findClassIfExists(cn, cl);
            if (c == null) { DONE.remove(cn); return 0; }
            forceAvailable(c);
            int k = hookClass(c);
            HookEntry.log("精准挂(立即) " + cn + " -> " + k + " 个方法");
            return k;
        } catch (Throwable t) {
            return 0;
        }
    }

    /**
     * 强制 {@code available} 恒为 true。
     *
     * <p>这是关键的一步：目标框架的流程是
     * <pre>
     *   if (!NativeLib.available) return "加载失败"
     *   val json = NativeLib.scan(...)
     * </pre>
     * 如果 available 为 false，scan 根本不会被调用，我们的 hook 形同虚设。
     *
     * <p>Kotlin 的 {@code val available = try { System.loadLibrary(...) ; true } catch { false }}
     * 编译成私有静态字段，R8 可能把它内联进 getter，所以三条路都堵。
     */
    private static void forceAvailable(Class<?> c) {
        try {
            de.robv.android.xposed.XposedHelpers.setStaticBooleanField(c, "available", true);
            HookEntry.log("available 已置 true（常规写入）");
        } catch (Throwable ignored) {
        }

        // Kotlin 的 val 编译成 static final，常规反射写不进去。
        // 用 Unsafe 直接改内存（全反射调用，避免编译期依赖 sun.misc）。
        try {
            if (writeFinalBoolean(c, "available", true)) {
                HookEntry.log("available 已置 true（Unsafe）");
            }
        } catch (Throwable t) {
            HookEntry.log("Unsafe 写 available 失败: " + t);
        }

        try {
            de.robv.android.xposed.XposedBridge.hookAllMethods(c, "getAvailable",
                    de.robv.android.xposed.XC_MethodReplacement.returnConstant(Boolean.TRUE));
        } catch (Throwable ignored) {
        }

        // 读回验证：确认写入后实际值
        try {
            Object v = de.robv.android.xposed.XposedHelpers.getStaticObjectField(c, "available");
            HookEntry.log("available 实际值 = " + v);
        } catch (Throwable t) {
            HookEntry.log("读 available 失败: " + t);
        }

        // 关键：把整个类初始化重来一遍是不可行的，但可以在 <clinit> 之后再压一次。
        // 用 hookAllMethods 挂不住 <clinit>，所以这里直接用一个短延迟任务补写。
        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
            try {
                de.robv.android.xposed.XposedHelpers.setStaticBooleanField(c, "available", true);
                Object v2 = de.robv.android.xposed.XposedHelpers.getStaticObjectField(c, "available");
                HookEntry.log("available 延迟补写后 = " + v2);
            } catch (Throwable ignored) {
            }
        }, 100);
    }

    /**
     * 用 Unsafe 把某个静态 boolean 字段写成指定值，绕过 final 限制。
     *
     * <p>全反射调用：{@code sun.misc.Unsafe} 在 Android 编译期不可见，
     * 但运行期存在，所以只能用反射拿。
     */
    private static boolean writeFinalBoolean(Class<?> cls, String field, boolean val) {
        try {
            Class<?> uc = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field uf = uc.getDeclaredField("theUnsafe");
            uf.setAccessible(true);
            Object unsafe = uf.get(null);

            java.lang.reflect.Field f = cls.getDeclaredField(field);
            f.setAccessible(true);

            Object base = uc.getMethod("staticFieldBase", java.lang.reflect.Field.class)
                    .invoke(unsafe, f);
            long off = (Long) uc.getMethod("staticFieldOffset", java.lang.reflect.Field.class)
                    .invoke(unsafe, f);
            uc.getMethod("putBoolean", Object.class, long.class, boolean.class)
                    .invoke(unsafe, base, off, val);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** 挂一个类里所有"看起来是检测出口"的方法 */
    private static int hookClass(Class<?> c) {
        int n = 0;
        try {
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                if (!looksLikeExit(m)) continue;
                if (hookOne(m)) n++;
            }
        } catch (Throwable ignored) {
        }
        return n;
    }

    /**
     * 判断是不是"检测结果出口"。
     *
     * <p>三重条件，缺一不可：
     * <ol>
     *   <li>方法名含 scan/check/detect 等动词；</li>
     *   <li>返回 String 或 boolean（结论型）；</li>
     *   <li>不是 getter/setter、不是 toString 之类。</li>
     * </ol>
     */
    private static boolean looksLikeExit(java.lang.reflect.Method m) {
        String name = m.getName().toLowerCase();
        String simple = m.getDeclaringClass().getSimpleName().toLowerCase();

        boolean verbHit = false;
        for (String v : VERBS) {
            if (name.contains(v)) { verbHit = true; break; }
        }
        if (!verbHit) return false;

        Class<?> r = m.getReturnType();
        if (r != String.class && r != boolean.class && r != Boolean.class) return false;

        // 排除明显不是检测的方法
        if (name.startsWith("set") || name.startsWith("get") && name.length() < 8) return false;
        return true;
    }

    /**
     * 挂单个方法。
     *
     * <p>关键：在 {@code before} 里直接给结果，让原方法<b>完全短路</b>。
     * 对 native 方法同样有效 —— Xposed 会在 JNI 调用前拦截。
     * 这样 native 层的 fork/ptrace/全代码段扫描一次都不会执行，
     * 既省时间又减少痕迹。
     */
    private static boolean hookOne(final java.lang.reflect.Method m) {
        try {
            de.robv.android.xposed.XposedBridge.hookMethod(m,
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            Class<?> r = m.getReturnType();
                            if (r == String.class) {
                                param.setResult(ResultForge.safeJson());
                            } else {
                                param.setResult(Boolean.FALSE);
                            }
                            HookEntry.log("短路(before) " + m.getDeclaringClass().getSimpleName()
                                    + "." + m.getName());
                        }

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            // 双保险：即使 before 没生效，after 也强制改成安全结果
                            Class<?> r = m.getReturnType();
                            if (r == String.class) {
                                Object v = param.getResult();
                                if (!(v instanceof String) || !((String) v).startsWith("[")) {
                                    param.setResult(ResultForge.safeJson());
                                }
                            }
                            HookEntry.log("短路(after) " + m.getDeclaringClass().getSimpleName()
                                    + "." + m.getName() + " -> " + param.getResult());
                        }
                    });
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}
