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
        hookLdLibraryPath();
        hookToString("dalvik.system.DexPathList");
        hookToString("dalvik.system.BaseDexClassLoader");
        hookToString("java.lang.ClassLoader");
        hookFieldGet();
        hookActualClassToString();
        selfCheck();
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
                            scrubResult(param);
                        }
                    });
        } catch (Throwable t) {
            HookEntry.log("PathHiding Field.get 跳过: " + t);
        }
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
                            f.set(cl, REPLACE);
                            HookEntry.log("SELFCL 抹除字段 " + nm + " @" + c.getSimpleName());
                            changed++;
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
                if (e instanceof String && ((String) e).contains(SELF)) {
                    try {
                        ((java.util.List) lst).set(i, REPLACE);
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
                        arr[i] = REPLACE;
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
                    try { ((java.util.Map) m).put(k, REPLACE); changed[0]++; }
                    catch (Throwable ignored) { }
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
                            f.set(o, REPLACE);
                            changed[0]++;
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
