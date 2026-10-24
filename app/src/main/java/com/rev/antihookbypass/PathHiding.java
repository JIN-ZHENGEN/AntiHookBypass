package com.rev.antihookbypass;

import java.lang.reflect.Method;
import java.util.regex.Pattern;

/**
 * 隐藏本模块自身在 ClassLoader 文本描述里的路径。
 *
 * <h2>要挡的是什么</h2>
 * hunter 6.58 会打印这样一段（实测原文）：
 *
 * <pre>
 * Find Lsposed Hook Module
 * [module=/data/app/~~xxx==/com.rev.antihookbypass-yyy==/base.apk,
 *  o1[DexPathList[[dex file "InMemoryDexFile[...]"],
 *     nativeLibraryDirectories=[/data/app/~~xxx==/com.rev.antihookbypass-yyy==
 *                               /base.apk!/lib/arm64-v8a, /system/lib64]]]]
 * </pre>
 *
 * 中间那个 {@code o1[DexPathList[...]]} 是
 * {@code dalvik.system.DexPathList.toString()} 的输出格式，
 * 里面直接带出了本模块 APK 的路径。目标据此就能指名道姓
 * 「装了 AntiHookBypass 这个模块」。
 *
 * <h2>为什么在 Java 层改</h2>
 * 这段文字是 Java 层拼出来交给调用方的。不管 hunter 是直接调
 * {@code toString()}，还是反射读 {@code nativeLibraryDirectories} 再自己拼，
 * 只要把「路径文本」这一层管住，就都挡住了。
 *
 * <h2>边界</h2>
 * 只替换**本模块自己的包名路径**，替换目标是系统本来就存在的
 * {@code /system/framework/framework.jar}。其它任何路径、
 * 任何检测结论都不动 —— 不碰它的判定，只把自己的名字从文本里抹掉。
 */
final class PathHiding {

    /** 本模块包名，路径里出现它就说明是我们。 */
    private static final String SELF = "com.rev.antihookbypass";

    /** 命中本模块 apk 路径（含 /data/app/~~xxx==/ 前缀与 !/lib 后缀）。 */
    private static final Pattern SELF_PATH =
            Pattern.compile("/data/app/[^\\s,\\]]*" + SELF + "[^\\s,\\]]*");

    /** 命中 lib 目录形式的路径。 */
    private static final Pattern SELF_LIB =
            Pattern.compile("/data/app/[^\\s,\\]]*" + SELF + "[^\\s,\\]]*/lib/[^\\s,\\]]*");

    private static final String REPLACE = "/system/framework/framework.jar";

    private PathHiding() { }

    static void install() {
        /*
         * getLdLibraryPath 是 BaseDexClassLoader 的公开方法，
         * 返回 ".../base.apk!/lib/arm64-v8a"。
         *
         * 实测（SRC 扫描）：本模块 ClassLoader 上唯一直接返回
         * 本模块路径的公开方法就是它。而 LspModuleClassLoader 的
         * toString 是匿名类实现，lsplant 直接拒绝挂载
         * （IllegalArgumentException: Do not allow hooking inner methods），
         * 所以能拦的正路就是这里。
         */
        /*
         * 顺序很重要：先原地改写，再装钩子。
         *
         * 钩子（尤其 Field.get）会改写反射读到的值。
         * 如果先装钩子，scrub 自己读字段时拿到的是被钩子换过的干净值，
         * 就会认为"这个字段不含本模块路径"，一条都不改 ——
         * 实测症状就是"原地改写零条日志，toString 仍带路径"。
         */
        scrubAllLoaders();
        detachFromThreads();

        hookLdLibraryPath();
        hookToString("dalvik.system.DexPathList");
        hookToString("dalvik.system.BaseDexClassLoader");
        hookToString("java.lang.ClassLoader");
        hookFieldGet();
        hookActualClassToString();
        hookStringConcat();
        /*
         * 这里曾经试图给 BaseDexClassLoader / ClassLoader 的**所有方法**
         * 挂返回值 scrub，想一网打尽。实测不可行，已撤：
         *
         * 日志打印本身就要做 String 操作，而这些类的方法被大量调用，
         * 钩子内部再触发钩子 -> 递归 -> 模块初始化在打第一条日志前就中断，
         * 表现成"模块日志一条都没有"。
         *
         * 结论：整类拦截代价不可控，只能针对具体方法。
         */
        if (com.rev.antihookbypass.ExpFlags.UIPEEK) {
            selfCheckAll();
        }
    }

    /** 拦 getLdLibraryPath：把模块 so 目录换回系统路径。 */
    private static void hookLdLibraryPath() {
        try {
            Class<?> c = Class.forName("dalvik.system.BaseDexClassLoader");
            Method m = c.getDeclaredMethod("getLdLibraryPath");
            de.robv.android.xposed.XposedBridge.hookMethod(m,
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof String && ((String) r).contains(SELF)) {
                                param.setResult(REPLACE);
                            }
                        }
                    });
            HookEntry.log("PathHiding getLdLibraryPath 已挂");
        } catch (Throwable t) {
            HookEntry.log("PathHiding getLdLibraryPath 跳过: " + t);
        }
    }

    /** 把类里所有 toString() 的返回值过滤一遍。 */
    private static void hookToString(String className) {
        try {
            Class<?> c = Class.forName(className);
            Method m = c.getDeclaredMethod("toString");
            de.robv.android.xposed.XposedBridge.hookMethod(m,
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof String) {
                                String s = (String) r;
                                if (s.contains(SELF)) {
                                    param.setResult(scrub(s));
                                }
                            }
                        }
                    });
        } catch (Throwable t) {
            HookEntry.log("PathHiding " + className + " 跳过: " + t);
        }
    }

    /**
     * 字段读取路径：hunter 可能反射取 {@code nativeLibraryDirectories}。
     *
     * <p>拦的是 {@code Field.get} / {@code Field.getXxx} 这一族，
     * 只在返回值里出现本模块路径时才改写，其它一律原样返回。
     */
    private static void hookFieldGet() {
        try {
            Class<?> f = Class.forName("java.lang.reflect.Field");
            de.robv.android.xposed.XposedBridge.hookAllMethods(f, "get",
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            /*
                             * 必须放行自己人。
                             *
                             * 踩过的坑：scrub 自己要用反射读字段，
                             * 而这里把 Field.get 的返回值换成了 framework.jar，
                             * 于是 scrub 读到的永远是"已经干净"的值，
                             * 永远不会进"含本模块路径"的分支 ——
                             * 表现成"原地改写一条日志都没有"。
                             *
                             * 判定：调用栈里出现本类，就说明是自己发起
                             * 的反射读，直接放行原值。
                             */
                            if (selfCalling()) return;
                            scrubResult(param);
                        }
                    });
        } catch (Throwable t) {
            HookEntry.log("PathHiding Field.get 跳过: " + t);
        }
    }

    /** 当前调用栈里是否有本类自己的帧。 */
    private static boolean selfCalling() {
        StackTraceElement[] st = new Throwable().getStackTrace();
        for (StackTraceElement e : st) {
            String cn = e.getClassName();
            if (cn != null && cn.startsWith("com.rev.antihookbypass.")) return true;
        }
        return false;
    }

    private static void scrubResult(de.robv.android.xposed.XC_MethodHook.MethodHookParam param) {
        Object r = param.getResult();
        if (r instanceof String) {
            String s = (String) r;
            if (s.contains(SELF)) param.setResult(scrub(s));
            return;
        }
        if (r instanceof String[]) {
            String[] a = (String[]) r;
            boolean dirty = false;
            for (String s : a) if (s != null && s.contains(SELF)) { dirty = true; break; }
            if (!dirty) return;
            String[] b = new String[a.length];
            for (int i = 0; i < a.length; i++) {
                b[i] = (a[i] != null && a[i].contains(SELF)) ? scrub(a[i]) : a[i];
            }
            param.setResult(b);
            return;
        }
        if (r instanceof java.io.File[]) {
            java.io.File[] a = (java.io.File[]) r;
            boolean dirty = false;
            for (java.io.File f : a) {
                if (f != null && f.getPath().contains(SELF)) { dirty = true; break; }
            }
            if (!dirty) return;
            java.io.File[] b = new java.io.File[a.length];
            for (int i = 0; i < a.length; i++) {
                String p = a[i] == null ? null : a[i].getPath();
                b[i] = (p != null && p.contains(SELF)) ? new java.io.File(scrub(p)) : a[i];
            }
            param.setResult(b);
        }
    }


    /**
     * 把 toString 直接挂到「本模块 ClassLoader 的实际类」上。
     *
     * <h2>为什么挂在父类上不管用</h2>
     * 实测本模块的 ClassLoader 是 {@code LspModuleClassLoader}，
     * 它<b>重写了自己的 toString</b>。而 Java 的方法分派是
     * 「子类覆写后，调父类的钩子不再执行」，
     * 所以前面挂在 {@code ClassLoader} / {@code BaseDexClassLoader}
     * 上的 toString 钩子，对它的覆写版本完全无效 ——
     * 自证日志里"已抹除 1 个字段"却"仍有痕迹"就是这个原因。
     *
     * <p>做法：拿到实例的真实类，反射出它的 toString 再挂。
     * 这样不管框架把这个类叫什么名字（不同 LSPosed 版本不一样），
     * 都能挂到正确的方法上。
     */
    private static void hookActualClassToString() {
        try {
            ClassLoader cl = PathHiding.class.getClassLoader();
            if (cl == null) return;
            final Class<?> c = cl.getClass();
            Method m = c.getMethod("toString");
            de.robv.android.xposed.XposedBridge.hookMethod(m,
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof String && ((String) r).contains(SELF)) {
                                param.setResult(scrub((String) r));
                            }
                        }
                    });
            HookEntry.log("SELFCL 已挂 " + c.getName() + "#toString");
        } catch (Throwable t) {
            HookEntry.log("SELFCL 挂 toString 失败: " + t);
        }
    }

    /**
     * 把本模块 ClassLoader 实例上所有「含本模块路径的字符串字段」就地抹掉。
     *
     * <h2>为什么必须改字段，不能只改 toString</h2>
     * 实测本模块的 ClassLoader 是 {@code LspModuleClassLoader}，
     * 它自己的 toString 是这么拼的：
     *
     * <pre>
     * LspModuleClassLoader[module=/data/app/~~xxx==/com.rev.antihookbypass-yyy==/base.apk,
     *   o1[DexPathList[...nativeLibraryDirectories=[...]]]]
     * </pre>
     *
     * 前面 {@code DexPathList} 那一段已经被 toString 钩子改掉了，
     * 但 {@code module=} 后面的路径是它<b>自己字段</b>拼进去的，
     * 钩子管不到 —— 自证日志里 "仍有痕迹" 就是这么来的。
     *
     * <h2>为什么改字段能挡住 ptrace</h2>
     * 目标有子进程用 ptrace 从外部读主进程内存（它自己的字符串里就有
     * "checkPtraceIsStart main pid"）。这种读法完全绕过我们所有的
     * open/read/process_vm_readv 钩子。唯一能让它读不到的办法，
     * 就是让这个字符串在内存里<b>真的不存在</b>。
     *
     * <h2>边界</h2>
     * 只碰「值是字符串、且值里含本模块路径」的字段，其余一律不动。
     * pathList、parent、parentClassLoader 这些功能字段显式跳过，
     * 保证模块本身照常工作。
     */
    private static void scrubFields(ClassLoader cl) {
        if (cl == null) return;
        int changed = 0;
        for (Class<?> c = cl.getClass(); c != null && c != Object.class;
             c = c.getSuperclass()) {
            java.lang.reflect.Field[] fs;
            try {
                fs = c.getDeclaredFields();
            } catch (Throwable t) {
                continue;
            }
            for (java.lang.reflect.Field f : fs) {
                String nm = f.getName();
                if ("pathList".equals(nm) || "parent".equals(nm)
                        || "parentClassLoader".equals(nm)) {
                    continue;   /* 功能字段，动它会破坏模块加载 */
                }
                Class<?> ty = f.getType();
                boolean isStr = ty == String.class;
                boolean isFile = ty == java.io.File.class;
                if (!isStr && !isFile) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(cl);
                    if (isStr) {
                        if (v instanceof String && ((String) v).contains(SELF)) {
                            /*
                             * 原地改写，不 set 字段。
                             *
                             * 换引用没用：ART 把读这个 final 字段内联成了
                             * 直接引用那个 String 对象，换引用改不到内联处。
                             * 改对象内容才两边一致。
                             */
                            if (rewriteStringInPlace((String) v)) {
                                HookEntry.log("SELFCL 原地改写字段 " + nm
                                        + " @" + c.getSimpleName());
                                changed++;
                            }
                        }
                    } else if (v instanceof java.io.File) {
                        if (((java.io.File) v).getPath().contains(SELF)) {
                            f.set(cl, new java.io.File(REPLACE));
                            HookEntry.log("SELFCL 抹除字段 " + nm + " @" + c.getSimpleName());
                            changed++;
                        }
                    }
                } catch (Throwable ignored) {
                    /* final 字段或访问受限，跳过；不影响其它字段 */
                }
            }
        }
        if (changed > 0) {
            HookEntry.log("SELFCL 已抹除 " + changed + " 个字段");
        }
    }


    /**
     * 把集合 / 数组里含本模块路径的元素就地替换掉。
     *
     * <h2>为什么连容器内容也要改</h2>
     * 实测 {@code LspModuleClassLoader} 上有两个 ArrayList 字段，
     * 里面存的就是模块的 dex 路径与 so 目录。而它的 toString 会把这些
     * 内容拼出来：
     *
     * <pre>
     * LspModuleClassLoader[module=/data/app/~~xxx==/com.rev.antihookbypass-yyy==/base.apk,
     *   o1[DexPathList[...]]]
     * </pre>
     *
     * 前面只改字段本身（String/File）时，路径照样出现 —— 因为真正带着
     * 路径的是容器里的元素。
     *
     * <h2>为什么必须让字符串真的消失</h2>
     * 目标有子进程用 ptrace 从外部读主进程内存，完全绕过我们所有的
     * open/read/process_vm_readv 钩子。只有内存里真的没有这个字符串，
     * 它才读不到。
     *
     * <h2>边界</h2>
     * 只替换「值里含本模块包名」的元素，替换成系统自带的
     * framework.jar；其余元素原样保留，容器本身不动。
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static int scrubContainers(ClassLoader cl) {
        int changed = 0;
        for (Class<?> c = cl.getClass(); c != null && c != Object.class;
             c = c.getSuperclass()) {
            java.lang.reflect.Field[] fs;
            try {
                fs = c.getDeclaredFields();
            } catch (Throwable t) {
                continue;
            }
            for (java.lang.reflect.Field f : fs) {
                try {
                    f.setAccessible(true);
                    Object v = f.get(cl);
                    if (v instanceof java.util.List) {
                        java.util.List lst = (java.util.List) v;
                        int n = lst.size();
                        for (int i = 0; i < n; i++) {
                            Object e = lst.get(i);
                            if (e instanceof String && ((String) e).contains(SELF)) {
                                lst.set(i, REPLACE);
                                changed++;
                            } else if (e instanceof java.io.File
                                    && ((java.io.File) e).getPath().contains(SELF)) {
                                lst.set(i, new java.io.File(REPLACE));
                                changed++;
                            }
                        }
                    } else if (v instanceof Object[]) {
                        Object[] arr = (Object[]) v;
                        for (int i = 0; i < arr.length; i++) {
                            Object e = arr[i];
                            if (e instanceof String && ((String) e).contains(SELF)) {
                                arr[i] = REPLACE;
                                changed++;
                            } else if (e instanceof java.io.File
                                    && ((java.io.File) e).getPath().contains(SELF)) {
                                arr[i] = new java.io.File(REPLACE);
                                changed++;
                            }
                        }
                    }
                } catch (Throwable ignored) { }
            }
        }
        return changed;
    }


    /**
     * 递归清理：把对象图里所有含本模块路径的字符串换成系统路径。
     *
     * <h2>为什么必须递归</h2>
     * 决定性实验：把 o1 上两个 String 字段都改成 framework.jar 之后，
     * toString 输出的 module= 后面仍然是完整的 base.apk 路径。
     *
     *   NOW o1.a = /system/framework/framework.jar
     *   NOW o1.e = /system/framework/framework.jar
     *   SELFCL 仍有痕迹 :: LspModuleClassLoader[module=/data/app/~~xxx==
     *       /com.rev.antihookbypass-yyy==/base.apk, ...]
     *
     * 结论：那个路径根本不在这两个字段里，而是藏在两个 ArrayList 字段
     * 所指的对象图里（元素是框架自己的对象，路径是它内部的字段）。
     * 所以只洗一层不够，得顺着对象图往里走。
     *
     * <h2>为什么必须让字符串真的消失</h2>
     * 目标有子进程用 ptrace 从外部读主进程内存，绕过我们全部
     * open/read/process_vm_readv 钩子。只有内存里真的没有这个字符串，
     * 它才读不到。
     *
     * <h2>边界</h2>
     * 只替换「值里含本模块包名」的字符串；不新增、不删除字段，
     * 不改任何非字符串值；跳过 parent/pathList 这些功能字段；
     * 深度限 4 层、节点数限 400，避免走得太远。
     */
    private static int scrubDeep(Object root) {
        if (root == null) return 0;
        java.util.IdentityHashMap<Object, Boolean> seen =
                new java.util.IdentityHashMap<Object, Boolean>();
        int[] budget = {400};
        int[] changed = {0};
        try {
            scrubDeep0(root, seen, budget, changed, 0);
        } catch (Throwable t) {
            HookEntry.log("SELFCL 递归清理中断: " + t);
        }
        return changed[0];
    }

    private static void scrubDeep0(Object o, java.util.IdentityHashMap<Object, Boolean> seen,
                                   int[] budget, int[] changed, int depth) {
        if (o == null || depth > 4 || budget[0] <= 0) return;
        if (seen.put(o, Boolean.TRUE) != null) return;
        budget[0]--;

        if (o instanceof String) return;      /* 字符串本身不可变，改由持有者替换 */
        if (o instanceof Number || o instanceof Boolean
                || o instanceof Character) return;

        /* 容器：逐个元素递归 */
        if (o instanceof java.util.List) {
            java.util.List<?> lst = (java.util.List<?>) o;
            int n;
            try { n = lst.size(); } catch (Throwable t) { return; }
            for (int i = 0; i < n && budget[0] > 0; i++) {
                Object e;
                try { e = lst.get(i); } catch (Throwable t) { break; }
                /*
                 * 元素可能是 String，也可能是 java.io.File。
                 *
                 * 实测漏的正是后者：probeModule 打出来的是
                 *   o1.b (ArrayList) 元素: [0]java.io.File =
                 *       /data/app/~~xxx==/com.rev.antihookbypass-yyy==/base.apk!/lib/arm64-v8a
                 * 第一版只判 String，File 元素被当成"普通对象"继续往下递归，
                 * 而 File 内部的 path 字段属于 java.io 包，被包名规则跳过，
                 * 于是这条路径一直留着。
                 */
                if (e instanceof String && ((String) e).contains(SELF)) {
                    if (rewriteStringInPlace((String) e)) changed[0]++;
                } else if (e instanceof java.io.File
                        && ((java.io.File) e).getPath().contains(SELF)) {
                    try {
                        ((java.util.List) lst).set(i, new java.io.File(REPLACE));
                        changed[0]++;
                    } catch (Throwable ignored) { }
                } else if (e != null) {
                    scrubDeep0(e, seen, budget, changed, depth + 1);
                }
            }
            return;
        }
        if (o.getClass().isArray()) {
            if (o instanceof Object[]) {
                Object[] arr = (Object[]) o;
                for (int i = 0; i < arr.length && budget[0] > 0; i++) {
                    Object e = arr[i];
                    if (e instanceof String && ((String) e).contains(SELF)) {
                        if (rewriteStringInPlace((String) e)) changed[0]++;
                    } else if (e instanceof java.io.File
                            && ((java.io.File) e).getPath().contains(SELF)) {
                        arr[i] = new java.io.File(REPLACE);
                        changed[0]++;
                    } else if (e != null) {
                        scrubDeep0(e, seen, budget, changed, depth + 1);
                    }
                }
            }
            return;
        }
        if (o instanceof java.util.Map) {
            java.util.Map<?, ?> m = (java.util.Map<?, ?>) o;
            java.util.ArrayList<Object> ks;
            try { ks = new java.util.ArrayList<Object>(m.keySet()); }
            catch (Throwable t) { return; }
            for (Object k : ks) {
                if (budget[0] <= 0) break;
                Object v;
                try { v = m.get(k); } catch (Throwable t) { continue; }
                if (v instanceof String && ((String) v).contains(SELF)) {
                    if (rewriteStringInPlace((String) v)) changed[0]++;
                } else if (v != null) {
                    scrubDeep0(v, seen, budget, changed, depth + 1);
                }
            }
            return;
        }

        /*
         * 普通对象：只走"看起来像框架/应用自己的类"，
         * 跳过 JDK 核心类。JDK 内部结构深且不该动，
         * 走过去只会白耗预算还可能踩到并发修改。
         */
        /*
         * 跳过 JDK/Android 核心类的内部结构 —— 但**不能因此跳过容器**。
         *
         * 踩过的坑：这里原本对所有 java./javax./android. 开头的类直接返回。
         * 而实测那个带路径的容器是个 ArrayList，它是 java.util.ArrayList，
         * 于是被这条规则挡在门外，一个元素都没洗到。
         *
         * 证据（probeModule 打出来的）：
         *   o1.b (ArrayList) = [/data/app/~~xxx==/com.rev.antihookbypass-yyy==
         *                       /base.apk!/lib/arm64-v8a]
         *
         * 正确做法：容器类（List/Map/数组）无论属于哪个包都要递归，
         * 只有真正的"普通对象"才按包名跳过。
         */
        String cn = o.getClass().getName();
        if (cn.startsWith("java.") || cn.startsWith("javax.")
                || cn.startsWith("sun.") || cn.startsWith("android.")) {
            return;
        }
        for (Class<?> c = o.getClass(); c != null && c != Object.class;
             c = c.getSuperclass()) {
            java.lang.reflect.Field[] fs;
            try { fs = c.getDeclaredFields(); } catch (Throwable t) { break; }
            for (java.lang.reflect.Field f : fs) {
                if (budget[0] <= 0) return;
                String nm = f.getName();
                if ("pathList".equals(nm) || "parent".equals(nm)
                        || "parentClassLoader".equals(nm)) continue;
                Class<?> ty = f.getType();
                if (ty.isPrimitive()) continue;
                try {
                    f.setAccessible(true);
                    Object v = f.get(o);
                    if (v instanceof String) {
                        if (((String) v).contains(SELF)) {
                            if (rewriteStringInPlace((String) v)) changed[0]++;
                        }
                    } else if (v instanceof java.io.File) {
                        if (((java.io.File) v).getPath().contains(SELF)) {
                            f.set(o, new java.io.File(REPLACE));
                            changed[0]++;
                        }
                    } else if (v != null) {
                        scrubDeep0(v, seen, budget, changed, depth + 1);
                    }
                } catch (Throwable ignored) { }
            }
        }
    }

    /**
     * 自证：打印本模块 ClassLoader 的 toString，确认路径已被抹掉。
     *
     * <p>为什么必须自证：这条改动最容易「看起来装上了但没命中」——
     * 如果 hook 的类名不对、或 hunter 走的是别的取值路径，
     * 日志一切正常而痕迹照样在。直接把实际字符串打出来才算数。
     */
    static void selfCheck() {
        try {
            ClassLoader cl = PathHiding.class.getClassLoader();
            scrubFields(cl);
            int nc = scrubContainers(cl);
            int nd = scrubDeep(cl);
            HookEntry.log("SELFCL 容器=" + nc + " 递归=" + nd);
            /*
             * 定位 module= 的真实来源：把 o1 上所有无参方法都调一遍，
             * 看哪个返回的字符串里带本模块路径。
             *
             * 为什么用这个办法：字段全部改净、对象图递归也搜不到，
             * 说明那个路径是某个方法现算/现取的，不是躺在字段里。
             * 一次性把所有无参方法的结果打出来，就能直接看到是哪个。
             */
            try {
                for (java.lang.reflect.Method mm : cl.getClass().getMethods()) {
                    if (mm.getParameterTypes().length != 0) continue;
                    Class<?> rt = mm.getReturnType();
                    if (rt != String.class && rt != java.io.File.class
                            && rt != ClassLoader.class) continue;
                    try {
                        Object r = mm.invoke(cl);
                        String rs = (r instanceof java.io.File)
                                ? ((java.io.File) r).getPath() : String.valueOf(r);
                        if (rs != null && rs.contains(SELF)) {
                            HookEntry.log("SRC " + mm.getName() + " -> " + rs);
                        }
                    } catch (Throwable ignored) { }
                }
            } catch (Throwable t) {
                HookEntry.log("SRC 扫描失败: " + t);
            }

            /* 决定性对比：字段实时值 vs toString 输出 */
            for (Class<?> c = cl.getClass(); c != null && c != Object.class;
                 c = c.getSuperclass()) {
                for (java.lang.reflect.Field f : c.getDeclaredFields()) {
                    try {
                        f.setAccessible(true);
                        Object v = f.get(cl);
                        if (v instanceof String || v instanceof java.io.File) {
                            HookEntry.log("NOW " + c.getSimpleName() + "." + f.getName()
                                    + " = " + v);
                        }
                    } catch (Throwable ignored) { }
                }
            }
            String raw = String.valueOf(cl);
            HookEntry.log("SELFCL " + (raw.contains(SELF) ? "仍有痕迹" : "已隐藏")
                    + " :: " + raw.substring(0, Math.min(raw.length(), 300)));
        } catch (Throwable t) {
            HookEntry.log("SELFCL 失败: " + t);
        }
    }



    /**
     * 把所有「可能返回路径」的类加载器方法统统一层返回值 scrub。
     *
     * <h2>为什么必须挂整类</h2>
     * 已经查明：本模块 ClassLoader 的 toString 输出里带
     * {@code module=/data/app/~~xxx==/com.rev.antihookbypass-yyy==/base.apk}，
     * 但那个路径
     * <ul>
     *   <li>不在字段里（String/File 字段已改成 framework.jar）</li>
     *   <li>不在容器里（ArrayList 元素已改）</li>
     *   <li>对象图递归也搜不到</li>
     * </ul>
     * 说明它是 toString 内部<b>调某个 getter</b> 现取的。
     *
     * 所以不去猜是哪个 getter，直接给这些类的所有方法挂上 after 钩子，
     * 返回 String 的一律过一遍 scrub。这样无论它走哪条路都绕不过去。
     *
     * <h2>为什么挂在父类上就够</h2>
     * toString 是 inner 方法（lsplant 拒绝挂载），但它内部取路径
     * 只能通过继承来的公开方法。父类方法被钩住后，
     * 子类覆写版本之外的调用都会被拦。
     */
    private static void hookAllReturns(String className) {
        try {
            Class<?> c = Class.forName(className);
            de.robv.android.xposed.XposedBridge.hookAllMethods(c, null,
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object r = param.getResult();
                            if (r instanceof String && ((String) r).contains(SELF)) {
                                param.setResult(REPLACE);
                            } else if (r instanceof java.io.File
                                    && ((java.io.File) r).getPath().contains(SELF)) {
                                param.setResult(new java.io.File(REPLACE));
                            }
                        }
                    });
            HookEntry.log("PathHiding 已挂 " + className + " 全部方法");
        } catch (Throwable t) {
            HookEntry.log("PathHiding " + className + " 挂载失败: " + t);
        }
    }

    /**
     * 把进程里所有能枚举到的 ClassLoader 都洗一遍。
     *
     * <h2>为什么不能只洗自己那一个</h2>
     * 前面只处理 {@code PathHiding.class.getClassLoader()}，实测 hunter 照样
     * 报出 {@code module=/data/app/~~xxx==/com.rev.antihookbypass-yyy==/base.apk}。
     * 说明它拿到的不是这个实例 —— LSPosed 给模块建的 ClassLoader 可能有多个，
     * 或者它从别的线程/别的入口取到的是另一份。
     *
     * <h2>枚举哪些</h2>
     * 不依赖任何框架私有结构，只用标准的公开入口：
     * <ol>
     *   <li>当前线程的 contextClassLoader</li>
     *   <li>系统 ClassLoader</li>
     *   <li>所有线程的 contextClassLoader（进程里其它线程可能挂着不同的）</li>
     * </ol>
     * 每个都顺着 {@code parent} 链往上走一遍。
     *
     * <h2>为什么还要顺着别的线程找</h2>
     * 目标的检测跑在它自己的工作线程里，那个线程的 contextClassLoader
     * 与主线程不是一个。只查主线程会漏。
     */
    static void scrubAllLoaders() {
        java.util.IdentityHashMap<ClassLoader, Boolean> seen =
                new java.util.IdentityHashMap<ClassLoader, Boolean>();
        java.util.ArrayList<ClassLoader> all = new java.util.ArrayList<ClassLoader>();

        try {
            all.add(PathHiding.class.getClassLoader());
            all.add(Thread.currentThread().getContextClassLoader());
            all.add(ClassLoader.getSystemClassLoader());
        } catch (Throwable ignored) { }

        /* 所有线程的 contextClassLoader */
        try {
            Thread[] ts = new Thread[Thread.activeCount() * 2 + 16];
            int n = Thread.enumerate(ts);
            for (int i = 0; i < n; i++) {
                if (ts[i] == null) continue;
                try {
                    all.add(ts[i].getContextClassLoader());
                } catch (Throwable ignored) { }
            }
        } catch (Throwable t) {
            HookEntry.log("SELFCL 枚举线程失败: " + t);
        }

        int total = 0;
        for (ClassLoader cl : all) {
            while (cl != null && seen.put(cl, Boolean.TRUE) == null) {
                total += scrubDeep(cl);
                try {
                    cl = cl.getParent();
                } catch (Throwable t) {
                    break;
                }
            }
        }
        HookEntry.log("SELFCL 全量清洗 实例=" + seen.size() + " 元素=" + total);
    }

    /** 自证：把每个能枚举到的 ClassLoader 的 toString 都打出来，看还剩几个带路径。 */
    static void selfCheckAll() {
        java.util.IdentityHashMap<ClassLoader, Boolean> seen =
                new java.util.IdentityHashMap<ClassLoader, Boolean>();
        java.util.ArrayList<ClassLoader> all = new java.util.ArrayList<ClassLoader>();
        try {
            all.add(PathHiding.class.getClassLoader());
            all.add(Thread.currentThread().getContextClassLoader());
            all.add(ClassLoader.getSystemClassLoader());
            Thread[] ts = new Thread[Thread.activeCount() * 2 + 16];
            int n = Thread.enumerate(ts);
            for (int i = 0; i < n; i++) {
                if (ts[i] != null) all.add(ts[i].getContextClassLoader());
            }
        } catch (Throwable ignored) { }
        int bad = 0, total = 0;
        for (ClassLoader cl : all) {
            while (cl != null && seen.put(cl, Boolean.TRUE) == null) {
                total++;
                String str;
                try {
                    str = String.valueOf(cl);
                } catch (Throwable t) {
                    str = "";
                }
                if (str.contains(SELF)) {
                    bad++;
                    HookEntry.log("SELFCLBAD " + str.substring(0, Math.min(str.length(), 200)));
                }
                try {
                    cl = cl.getParent();
                } catch (Throwable t) {
                    break;
                }
            }
        }
        HookEntry.log("SELFCL 实例总数=" + total + " 仍带路径=" + bad);
        /* 把本模块那个 ClassLoader 的 toString 全文打出来，确认实际内容 */
        try {
            ClassLoader mine = PathHiding.class.getClassLoader();
            String t = String.valueOf(mine);
            HookEntry.log("SELFCL 全文 " + (t.length() > 260
                    ? t.substring(0, 260) : t));
        } catch (Throwable ignored) { }
        /* 把带路径那个实例的 module 字段逐层扒开，看清路径真正存在哪 */
        for (ClassLoader cl : all) {
            if (cl != null && String.valueOf(cl).contains(SELF)) {
                probeModule(cl);
                break;
            }
        }
    }




    /*
     * ---------------------------------------------------------------
     * 就地改写 String 内部字节
     * ---------------------------------------------------------------
     *
     * 这是本轮最关键的发现，绕过了 JIT 常量内联。
     *
     * 前面查明：o1.a / o1.e 两个 final String 字段 set 成功了，
     * get 出来确实是 framework.jar，但 toString 仍输出原 base.apk 路径。
     * 原因是 ART 把「读这个 final 字段」内联成了「直接引用那个 String 对象」——
     * 注意它内联的是<b>对象引用</b>，不是字面量。
     *
     * 由此得出正确解法：**不换引用，只换那个对象的内部字节**。
     * 字段仍指向原对象，内联处也指向同一对象，
     * 但对象的内容已经是新字符串 —— 两边读出来一致，都是干净的。
     *
     * 长度必须严格相等，所以替换词都选等长的：
     *     antihookbypass      (14) -> androidruntime       (14)
     *     libantihook_bypass.so (21) -> libandroid_runtime.so (21)
     *
     * java.lang.String 在 Android 9+ 用 compact string：
     * 内部是 byte[] value + byte coder（0=LATIN1，1=UTF16）。
     * 纯 ASCII 路径 coder=0，改 byte[] 即可。老系统是 char[]，也一并处理。
     *
     * 改完要把缓存的 hash 清零，否则后续 hashCode()/HashMap 查找会不一致。
     */
    private static final String SELF_SHORT = "antihookbypass";
    private static final String REPL_SHORT = "androidruntime";
    private static final String SELF_SO = "libantihook_bypass.so";
    private static final String REPL_SO = "libandroid_runtime.so";

    static boolean rewriteStringInPlace(String s) {
        if (s == null || !s.contains(SELF_SHORT)) return false;
        /*
         * 走 JNI。
         *
         * Java 反射在这里完全走不通：String.value 是 hidden API，
         * getDeclaredField("value") 直接抛
         *     NoSuchFieldException: No field value in class Ljava/lang/String;
         * 而 JNI 的 GetFieldID 不受 hiddenapi 政策拦截。
         */
        try {
            return NativeLayer.nativeRewriteString(s);
        } catch (Throwable t) {
            HookEntry.log("SELFCL 原地改写失败: " + t);
            return false;
        }
    }

    /** 清掉缓存的 hash，避免改写后 hashCode 与内容不一致。 */
    private static void resetStringHash(String s) {
        try {
            java.lang.reflect.Field hf = String.class.getDeclaredField("hash");
            hf.setAccessible(true);
            hf.setInt(s, 0);
        } catch (Throwable ignored) { }
    }


    /**
     * 拦截字符串拼接的出口。
     *
     * <h2>为什么盯这里</h2>
     * 决定性事实链：
     * <ol>
     *   <li>{@code o1.a} / {@code o1.e} 两个 String 字段读出来已干净</li>
     *   <li>{@code o1.b} 容器里的 File 元素已换成 framework.jar</li>
     *   <li>全字段扫描（PRBHIT）找不到任何含本模块路径的 String 字段</li>
     *   <li>但 {@code toString()} 仍输出原 base.apk 路径</li>
     * </ol>
     * 说明那段路径是<b>拼接时现造</b>的，不在任何字段里。
     *
     * 既然它是拼出来的，拦拼接的出口即可 —— 不管上层怎么拼、
     * 拼在哪个类里，最终都要经过 StringBuilder.toString 或 String.concat。
     *
     * <h2>为什么必须放行自己</h2>
     * 这些方法被全进程高频调用，钩子内部若再触发改名会递归。
     * {@link #selfCalling()} 保证只有外部调用被处理。
     */
    private static void hookStringConcat() {
        try {
            de.robv.android.xposed.XposedBridge.hookAllMethods(
                    StringBuilder.class, "toString",
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (selfCalling()) return;
                            Object r = param.getResult();
                            if (r instanceof String && ((String) r).contains(SELF_SHORT)) {
                                String fixed = String.valueOf(r)
                                        .replace(SELF_SO, REPL_SO)
                                        .replace(SELF_SHORT, REPL_SHORT);
                                param.setResult(fixed);
                            }
                        }
                    });
            HookEntry.log("PathHiding 已挂 StringBuilder.toString");
        } catch (Throwable t) {
            HookEntry.log("PathHiding StringBuilder 跳过: " + t);
        }

        try {
            de.robv.android.xposed.XposedBridge.hookAllMethods(
                    String.class, "concat",
                    new de.robv.android.xposed.XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (selfCalling()) return;
                            Object r = param.getResult();
                            if (r instanceof String && ((String) r).contains(SELF_SHORT)) {
                                String fixed = String.valueOf(r)
                                        .replace(SELF_SO, REPL_SO)
                                        .replace(SELF_SHORT, REPL_SHORT);
                                param.setResult(fixed);
                            }
                        }
                    });
            HookEntry.log("PathHiding 已挂 String.concat");
        } catch (Throwable t) {
            HookEntry.log("PathHiding String.concat 跳过: " + t);
        }
    }

    /**
     * 把所有线程的 contextClassLoader 里指向本模块的那个摘掉。
     *
     * <h2>为什么改字段没用</h2>
     * 已经查明：{@code o1.a} / {@code o1.e} 两个 final String 字段
     * 读出来确实是 {@code /system/framework/framework.jar}（set 成功了），
     * 但 {@code toString()} 依然输出原来的 base.apk 路径。
     *
     * 原因是 ART 把 final 字段的值**常量折叠**进了编译后的方法体：
     * toString 里那句拼接实际已变成字面量，不再回读字段。
     * 这也解释了为什么 nativeLibraryDirectories 那一段能改成功
     * —— 它是运行时读容器，没有折叠。
     *
     * <h2>所以改思路</h2>
     * 不再动那个实例内部，而是让目标**枚举不到它**。
     * 目标要在 Java 层拿到某个 ClassLoader，最常用的入口就是
     * 遍历线程的 contextClassLoader。把这些入口里指向我们的引用摘掉。
     *
     * <h2>为什么不破坏模块</h2>
     * 我们的类此时已经加载完成，模块自身执行不依赖
     * contextClassLoader 再去找自己。摘的只是外部可见的入口。
     */
    static void detachFromThreads() {
        int cleared = 0;
        try {
            Thread[] ts = new Thread[Thread.activeCount() * 2 + 32];
            int n = Thread.enumerate(ts);
            for (int i = 0; i < n; i++) {
                Thread th = ts[i];
                if (th == null) continue;
                try {
                    ClassLoader cl = th.getContextClassLoader();
                    if (cl != null && isOurs(cl)) {
                        th.setContextClassLoader(ClassLoader.getSystemClassLoader());
                        cleared++;
                    }
                } catch (Throwable ignored) { }
            }
        } catch (Throwable t) {
            HookEntry.log("SELFCL 摘除失败: " + t);
        }
        if (cleared > 0) {
            HookEntry.log("SELFCL 已摘除 contextClassLoader x" + cleared);
        }
    }

    /** 这个 ClassLoader 是不是本模块那个（按 toString 里是否带本模块包名判断）。 */
    private static boolean isOurs(ClassLoader cl) {
        try {
            String str = String.valueOf(cl);
            return str != null && str.contains(SELF);
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * 逐层扒开带路径的那个对象，打印每一层的全部字段。
     *
     * <p>为什么要这么做：字段、容器、对象图都洗过之后
     * {@code toString} 仍输出 {@code module=/data/app/~~xxx==/.../base.apk}，
     * 说明那个路径藏在某个我们没走到的位置。
     * 与其继续猜，不如把这个对象逐层展开，直接看是哪一层的哪个字段带着它。
     */
    private static void probeModule(ClassLoader cl) {
        Object cur = cl;
        for (int d = 0; d < 6 && cur != null; d++) {
            HookEntry.log("PRB[" + d + "] type=" + cur.getClass().getName());
            /* 这一层自身的 toString，看路径是不是在这里就出来了 */
            try {
                String ts = String.valueOf(cur);
                HookEntry.log("PRBSTR[" + d + "] " + (ts.length() > 220
                        ? ts.substring(0, 220) + "..." : ts));
            } catch (Throwable ignored) { }
            /*
             * 扫描**所有**无参方法（含 private）的返回值。
             *
             * 前面只扫了 public（getMethods），没找到。而字段里一个都命不中，
             * 说明 module= 那个值是某个方法现算的，很可能在 private 里。
             */
            for (Class<?> c4 = cur.getClass(); c4 != null && c4 != Object.class;
                 c4 = c4.getSuperclass()) {
                for (java.lang.reflect.Method m4 : c4.getDeclaredMethods()) {
                    if (m4.getParameterTypes().length != 0) continue;
                    Class<?> rt4 = m4.getReturnType();
                    if (rt4 != String.class && rt4 != java.io.File.class
                            && rt4 != Object.class) continue;
                    if (!m4.isAccessible()) {
                        try { m4.setAccessible(true); } catch (Throwable t) { continue; }
                    }
                    try {
                        Object r4 = m4.invoke(cur);
                        String rs4 = (r4 instanceof java.io.File)
                                ? ((java.io.File) r4).getPath() : String.valueOf(r4);
                        if (rs4 != null && rs4.contains(SELF)) {
                            HookEntry.log("PRBM " + c4.getSimpleName() + "."
                                    + m4.getName() + " -> "
                                    + (rs4.length() > 130
                                       ? rs4.substring(0, 130) + "..." : rs4));
                        }
                    } catch (Throwable ignored) { }
                }
            }
            /* 扫描所有 String 字段，看哪个还带着路径 */
            for (Class<?> c3 = cur.getClass(); c3 != null && c3 != Object.class;
                 c3 = c3.getSuperclass()) {
                for (java.lang.reflect.Field f3 : c3.getDeclaredFields()) {
                    try {
                        f3.setAccessible(true);
                        Object v3 = f3.get(cur);
                        if (v3 instanceof String && ((String) v3).contains(SELF)) {
                            HookEntry.log("PRBHIT " + c3.getSimpleName() + "."
                                    + f3.getName() + " = " + v3);
                        }
                        if (v3 instanceof java.io.File
                                && ((java.io.File) v3).getPath().contains(SELF)) {
                            HookEntry.log("PRBHIT " + c3.getSimpleName() + "."
                                    + f3.getName() + " (File) = " + v3);
                        }
                    } catch (Throwable ignored) { }
                }
            }
            /* 容器类字段：把每个元素的运行时类型也打出来 */
            for (Class<?> c2 = cur.getClass(); c2 != null && c2 != Object.class;
                 c2 = c2.getSuperclass()) {
                for (java.lang.reflect.Field f2 : c2.getDeclaredFields()) {
                    try {
                        f2.setAccessible(true);
                        Object v2 = f2.get(cur);
                        if (v2 instanceof java.util.List) {
                            java.util.List<?> l2 = (java.util.List<?>) v2;
                            StringBuilder eb = new StringBuilder();
                            for (int i2 = 0; i2 < l2.size() && i2 < 4; i2++) {
                                Object e2 = l2.get(i2);
                                eb.append('[').append(i2).append(']')
                                  .append(e2 == null ? "null"
                                        : e2.getClass().getName())
                                  .append(" = ")
                                  .append(String.valueOf(e2).length() > 70
                                        ? String.valueOf(e2).substring(0, 70) + "..."
                                        : String.valueOf(e2))
                                  .append(" ; ");
                            }
                            HookEntry.log("PRBEL " + c2.getSimpleName() + "."
                                    + f2.getName() + " ("
                                    + v2.getClass().getName() + ") 元素: " + eb);
                        }
                    } catch (Throwable ignored) { }
                }
            }
            Object next = null;
            for (Class<?> c = cur.getClass(); c != null && c != Object.class;
                 c = c.getSuperclass()) {
                java.lang.reflect.Field[] fs;
                try {
                    fs = c.getDeclaredFields();
                } catch (Throwable t) {
                    continue;
                }
                for (java.lang.reflect.Field f : fs) {
                    try {
                        f.setAccessible(true);
                        Object v = f.get(cur);
                        String sv = (v instanceof String) ? ("\"" + v + "\"")
                                : String.valueOf(v);
                        if (sv != null && sv.length() > 110) {
                            sv = sv.substring(0, 110) + "...";
                        }
                        HookEntry.log("PRB[" + d + "]   " + c.getSimpleName() + "."
                                + f.getName() + " (" + f.getType().getSimpleName()
                                + ") = " + sv);
                        if (next == null && v != null
                                && f.getName().toLowerCase().contains("module")) {
                            next = v;
                        }
                    } catch (Throwable ignored) { }
                }
            }
            if (next == null || next == cur) break;
            cur = next;
        }
    }

    /**
     * 把 ClassLoader 实例及其父类的全部字段（名字/类型/值）打出来。
     *
     * <p>为什么需要：已经抹掉一个含路径的字段，可 toString 里路径照旧，
     * 说明真正被 toString 拼进去的是另一个字段。靠猜字段名会一直猜错，
     * 直接把整张表打出来，一眼就能看到哪个字段带着路径。
     */
    private static void dumpFields(ClassLoader cl) {
        for (Class<?> c = cl.getClass(); c != null && c != Object.class;
             c = c.getSuperclass()) {
            java.lang.reflect.Field[] fs;
            try {
                fs = c.getDeclaredFields();
            } catch (Throwable t) {
                continue;
            }
            for (java.lang.reflect.Field f : fs) {
                try {
                    f.setAccessible(true);
                    Object v = f.get(cl);
                    String sv;
                    if (v == null) sv = "null";
                    else if (v instanceof String) sv = "\"" + v + "\"";
                    else if (v instanceof java.io.File) sv = "F:" + v;
                    else if (v instanceof ClassLoader) sv = "CL:" + v.getClass().getName();
                    else sv = v.getClass().getSimpleName();
                    if (sv.length() > 160) sv = sv.substring(0, 160) + "...";
                    HookEntry.log("FLDD " + c.getSimpleName() + "." + f.getName()
                            + " (" + f.getType().getSimpleName() + ") = " + sv);
                } catch (Throwable ignored) { }
            }
        }
    }

    /** 把一段文本里所有本模块路径换成系统自带路径。 */
    static String scrub(String s) {
        if (s == null || !s.contains(SELF)) return s;
        s = SELF_LIB.matcher(s).replaceAll(REPLACE);
        s = SELF_PATH.matcher(s).replaceAll(REPLACE);
        return s;
    }
}
