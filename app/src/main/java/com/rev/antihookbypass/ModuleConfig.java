package com.rev.antihookbypass;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

/**
 * 运行时可分层开关。
 *
 * <h2>为什么需要它</h2>
 * 一个"通杀"的痕迹还原模块，被勾进作用域的应用千奇百怪。如果某一层在某个应用上
 * 引发副作用，必须能现场定位到具体是哪一层，而不是整包回退、更不是靠改 LSPosed 配置
 * 反复试。所以模块自带分层开关：只改一个文本文件，重启目标应用即可生效，不用重新打包。
 *
 * <h2>怎么用</h2>
 * 用 root 写一行到 {@code /data/local/tmp/ahb_layers}：
 * <pre>
 *   su -c 'echo all  &gt; /data/local/tmp/ahb_layers'   # 全开（默认，即开即用）
 *   su -c 'echo none &gt; /data/local/tmp/ahb_layers'   # 全关（对照实验用）
 *   su -c 'echo l1   &gt; /data/local/tmp/ahb_layers'   # 只开 Java 层
 *   su -c 'echo l2   &gt; /data/local/tmp/ahb_layers'   # 只开代码段还原
 *   su -c 'rm /data/local/tmp/ahb_layers'             # 回到默认全开
 * </pre>
 *
 * <p>文件不存在或读不到时一律按 {@code all} 处理 —— 保证"装上就有效"，不要求用户先配置。
 *
 * <h2>L2 内的细分位</h2>
 * L2 由三个独立动作组成，单独也会出问题，所以再细分：
 * <ul>
 *   <li>{@link #NATIVE_ART}：还原 {@code libart.so} 代码段（抹掉 LSPlant 的 8 处 inline hook）</li>
 *   <li>{@link #NATIVE_LINKER}：还原 {@code linker64} 代码段</li>
 *   <li>{@link #NATIVE_TRAMPOLINE}：把匿名可执行跳板页收敛为只读</li>
 * </ul>
 * 写法形如 {@code l2} = 三项全开；{@code l2=art} 只开第一项。
 */
final class ModuleConfig {

    private ModuleConfig() {
    }

    /** 分层位 */
    static final int LAYER_L1 = 1 << 0;
    static final int LAYER_L2 = 1 << 1;
    static final int LAYER_L3 = 1 << 2;

    /** L2 内部分项位 */
    static final int NATIVE_ART = 1 << 0;
    static final int NATIVE_LINKER = 1 << 1;
    static final int NATIVE_TRAMPOLINE = 1 << 2;
    /** L3：净化 ART class_loaders_ 链表 */
    static final int NATIVE_CL = 1 << 3;
    /** L4：周期复查，让净化跟上其他模块之后产生的痕迹 */
    static final int NATIVE_GUARD = 1 << 4;

    /** L1 内部分项位（对应三个 Java 层组件） */
    static final int L1_TRACE = 1 << 0;
    static final int L1_KILL = 1 << 1;
    static final int L1_CRASH = 1 << 2;
    static final int L1_ALL = L1_TRACE | L1_KILL | L1_CRASH;

    /*
     * 层配置改成编译期默认值，不再读任何文件。
     *
     * 为什么不保留文件开关：模块没有用户设置界面，也就不存在
     * "现场切换"的真实需求；而留一个文件路径在运行时被 stat/open，
     * 等于给目标应用多一个可探测点 —— 它只要监看自己进程打开过
     * 哪些路径，就能发现 /data/local/tmp/ahb_layers 这种异物。
     *
     * 需要换配置时改这里重新打包即可，代价远小于留一个指纹。
     */
    private static final String CFG = null;

    /*
     * 默认层配置（无配置文件时生效）。
     *
     * anti-cpu-hotfix：原默认 ALL（L1+L2+L3）会让 L1（TraceHide 的
     * Throwable.getStackTrace 全量栈过滤）在 QQ 这类超大进程里高频触发，
     * 主线程常驻 Runnable、CPU 占用极高、ANR。
     *
     * 改为默认只开 L2+L3（native 视图伪造 + 代码段还原），它们已覆盖本模块
     * 要绕的六项 native 检测；L1 的 Java 栈过滤改为「按需开启」——
     * 需要它时显式写 all / l1 重新打包即可（见 parseLayers 的 s 分支）。
     */
    private static final int DEFAULT_WITHOUT_L1 = LAYER_L2 | LAYER_L3;

    private static volatile int cachedLayers = -1;
    private static volatile int cachedNative = -1;
    private static volatile int cachedL1 = -1;

    /** 当前启用哪几层，默认三层全开 */
    static int layers() {
        int v = cachedLayers;
        if (v >= 0) return v;
        v = parseLayers(readCfgLine());
        cachedLayers = v;
        return v;
    }

    /**
     * 是否启用注入痕迹的读视图过滤。
     *
     * 默认开启：这是"隐藏"能力，不改变宿主任何真实内存，
     * 只影响对方读 maps / dl_iterate_phdr 时看到的内容。
     * 关掉它，检测器就能直接看到 zygisk 注入库的映射。
     */
    static boolean mapsHide() {
        String s = readCfgLine();
        if (s == null) return true;              /* 无配置：默认开 */
        if (s.contains("nomapshide")) return false;
        if (s.contains("mapshide")) return true;
        return true;                             /* 有配置但未提及：仍默认开 */
    }

    /** 当前启用 L2 的哪几个 Native 动作，默认三项全开 */
    static int nativeOps() {
        int v = cachedNative;
        if (v >= 0) return v;
        v = parseNative(readCfgLine());
        /*
         * 顺序前置约束：收敛跳板页必须以"已还原 libart 与 linker 的远跳"为前提。
         * 否则 hook 仍跳进那一页，页面一改成只读立刻 native crash。
         * 用户只写 l2=tramp 时自动补齐前置，而不是让他踩崩。
         */
        if ((v & NATIVE_TRAMPOLINE) != 0 && (v & (NATIVE_ART | NATIVE_LINKER)) == 0) {
            v |= NATIVE_ART | NATIVE_LINKER;
        }
        cachedNative = v;
        return v;
    }

    /** 当前启用 L1 的哪几个 Java 组件，默认三项全开 */
    static int l1Ops() {
        int v = cachedL1;
        if (v >= 0) return v;
        v = parseL1(readCfgLine());
        cachedL1 = v;
        return v;
    }

    /**
     * 诊断用：TraceHide 里只装第几个 hook（1~8），0 表示全部安装。
     *
     * <p>写法 {@code l1=trace:3}。用于在任意第三方应用上精确定位是哪一个
     * hook 引发副作用，避免整层回退把有效防护一起丢掉。
     */
    static int traceHookIndex() {
        String s = readCfgLine();
        if (s == null) return 0;
        for (String raw : s.split("[+,]")) {
            String p = raw.trim();
            int eq = p.indexOf('=');
            if (eq < 0) continue;
            String val = p.substring(eq + 1).trim();
            int colon = val.indexOf(':');
            if (colon < 0) continue;
            String head = val.substring(0, colon);
            if (!head.equals("trace")) continue;
            try {
                int n = Integer.parseInt(val.substring(colon + 1).trim());
                return (n >= 1 && n <= 20) ? n : 0;
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    static boolean l1() {
        return (layers() & LAYER_L1) != 0;
    }

    /** L1 内部分项：调用栈与类探测压制 */
    static boolean l1Trace() {
        return l1() && (l1Ops() & L1_TRACE) != 0;
    }

    /** L1 内部分项：退出/自杀拦截 */
    static boolean l1Kill() {
        return l1() && (l1Ops() & L1_KILL) != 0;
    }

    /** L1 内部分项：启动兼容兜底 */
    static boolean l1Crash() {
        return l1() && (l1Ops() & L1_CRASH) != 0;
    }

    static boolean l2() {
        return (layers() & LAYER_L2) != 0;
    }

    static boolean l3() {
        return (layers() & LAYER_L3) != 0;
    }

    private static String readCfgLine() {
        /*
         * 恒返回 null，表示"用默认值"。
         *
         * 保留这个方法签名，是为了让下面各个 parse 分支保持原样：
         * 传入 null 时它们都会走默认全开路径。这样改动面最小，
         * 也不会因为删分支而漏掉某条默认值。
         */
        if (CFG == null) return null;
        return null;
    }

    /**
     * 解析分层配置。
     *
     * <p>支持 {@code all} / {@code none} / {@code l1} / {@code l2} / {@code l3}
     * 以及用 {@code +} 或逗号组合，如 {@code l1+l3}。
     */
    private static int parseLayers(String s) {
        final int ALL = LAYER_L1 | LAYER_L2 | LAYER_L3;
        /*
         * 默认只开 native 两层。
         *
         * L1 是 Java 层：hook Throwable.getStackTrace / Class.forName /
         * ClassLoader.loadClass 等全局高频方法，用于隐藏 Xposed 痕迹。
         *
         * 默认关掉它的原因不是"不重要"，而是它的代价在别的应用身上：
         * Java hook 会在调用栈里留下 t.intercept / m.proceed 帧，
         * 任何自带反 Hook 的应用都能直接看到这两个帧名。
         * 实测 hunter 6.58 因此走反制路径并崩溃。
         *
         * 而本模块要绕的六项检测全部是 native 项：
         *   classloader / libc / libart / anon_exec / inline_hook / external_view
         * 它们由 L2（代码段还原）与 libview（磁盘视图重定向）负责，
         * 与 L1 无关。所以关掉 L1 不影响交付目标。
         *
         * 需要时（比如某个检测器去查 Java 栈）改这里重新打包即可 ——
         * 模块没有设置界面，默认值就应该是"对目标进程副作用最小"的那个。
         */
        if (s == null) return DEFAULT_WITHOUT_L1;
        if (s.equals("all") || s.equals("default")) return ALL;
        if (s.equals("none") || s.equals("off") || s.equals("0")) return 0;

        int out = 0;
        String[] parts = s.split("[+,]");
        for (String raw : parts) {
            String p = raw.trim();
            if (p.isEmpty()) continue;
            int eq = p.indexOf('=');
            String head = eq >= 0 ? p.substring(0, eq) : p;
            if (head.equals("l1") || head.equals("trace") || head.equals("1")) out |= LAYER_L1;
            else if (head.equals("l2") || head.equals("native") || head.equals("2")) out |= LAYER_L2;
            else if (head.equals("l3") || head.equals("art") || head.equals("3")) out |= LAYER_L3;
        }
        return out;
    }

    /**
     * 解析 L2 内部分项。
     *
     * <p>{@code l2} 或 {@code all} → 三项全开；
     * {@code l2=art} → 只还原 libart；{@code l2=linker} → 只还原 linker；
     * {@code l2=tramp} → 只收敛跳板页；可组合 {@code l2=art+tramp}。
     */
    private static int parseNative(String s) {
        /*
         * 默认全开：代码段还原（art/linker）、跳板页收敛、ClassLoader 视图、周期复查。
         *
         * 关于"会不会破坏别的模块的 hook"（R-38）：
         * 还原逻辑只把**与磁盘不一致的字节**写回，而它比对的是本进程
         * 的 libart / linker 映射。LSPosed 的注入走的是 zygisk 侧，
         * 不在这两个库的代码段里留 inline hook；真正会写这两个库的是
         * 老式 LSPlant 的 FixupStaticTrampolines，那种情况本来就需要还原，
         * 否则检测器一读 CRC 就红。
         *
         * 曾经把这里默认关掉，是因为 hunter 崩溃在 libhunter.so+0xc787c。
         * 后经定位，那个崩溃的真实成因是 dl_iterate_phdr 包装用全局变量
         * 存回调上下文、多线程并发时互相覆盖，导致目标拿到错误的库基址。
         * 该缺陷已修复（上下文改走 data 参数），与代码段还原无关，
         * 所以这里恢复默认全开。
         */
        final int ALL = NATIVE_ART | NATIVE_LINKER | NATIVE_TRAMPOLINE
                      | NATIVE_CL | NATIVE_GUARD;
        if (s == null) return ALL;
        if (s.equals("all") || s.equals("default") || s.equals("none") || s.equals("off")) {
            return s.startsWith("none") || s.equals("off") ? 0 : ALL;
        }

        /*
         * 先按逗号切出各段，再对每段按第一个 '=' 拆成 head=value。
         *
         * 早期实现直接按 "[+,]" 切，于是 "l2=cl+guard" 被切成
         * ["l2=cl", "guard"]，第二段没有 '=' 被整段丢弃——
         * guard 永远不生效，守护循环永远不启动，而日志上看不出任何异常。
         * 值内部的分隔符只能是 '+'，逗号只用于分隔不同的 head。
         */
        int out = 0;
        boolean sawExplicit = false;
        for (String raw : s.split(",")) {
            String p = raw.trim();
            int eq = p.indexOf('=');
            if (eq < 0) continue;
            String head = p.substring(0, eq).trim();
            if (!head.equals("l2") && !head.equals("native") && !head.equals("2")
                    && !head.equals("l3") && !head.equals("cl")
                    && !head.equals("l4") && !head.equals("guard")) continue;
            for (String item : p.substring(eq + 1).split("\\+")) {
                String it = item.trim();
                sawExplicit = true;
                if (it.equals("art") || it.equals("libart")) out |= NATIVE_ART;
                else if (it.equals("linker") || it.equals("linker64")) out |= NATIVE_LINKER;
                else if (it.equals("tramp") || it.equals("trampoline") || it.equals("anon")) {
                    out |= NATIVE_TRAMPOLINE;
                } else if (it.equals("cl") || it.equals("classloader")) {
                    out |= NATIVE_CL;
                } else if (it.equals("guard") || it.equals("watch")
                           || it.equals("scan") || it.equals("repeat")) {
                    out |= NATIVE_GUARD;
                } else if (it.equals("all")) {
                    out |= ALL;
                }
            }
        }
        if (!sawExplicit) {
            /* 只写了 l2 没写细分 → 走默认（不含剪链） */
            return (parseLayers(s) & (LAYER_L2 | LAYER_L3)) != 0 ? ALL : 0;
        }
        return out;
    }

    /**
     * 解析 L1 内部分项。
     *
     * <p>{@code l1} → 三项全开；{@code l1=trace} → 只开调用栈压制；
     * {@code l1=kill} → 只开退出拦截；{@code l1=crash} → 只开启动兜底。
     */
    private static int parseL1(String s) {
        if (s == null) return L1_ALL;
        if (s.equals("all") || s.equals("default")) return L1_ALL;
        if (s.equals("none") || s.equals("off") || s.equals("0")) return 0;

        int out = 0;
        boolean sawExplicit = false;
        for (String raw : s.split("[+,]")) {
            String p = raw.trim();
            int eq = p.indexOf('=');
            if (eq < 0) continue;
            String head = p.substring(0, eq);
            if (!head.equals("l1") && !head.equals("trace") && !head.equals("1")) continue;
            for (String item : p.substring(eq + 1).split("\\+")) {
                String it = item.trim();
                /* 支持 trace:3 这种"只装第 3 个 hook"的写法，冒号后是序号，不影响分层判定 */
                int colon = it.indexOf(':');
                if (colon >= 0) it = it.substring(0, colon).trim();
                sawExplicit = true;
                if (it.equals("trace")) out |= L1_TRACE;
                else if (it.equals("kill")) out |= L1_KILL;
                else if (it.equals("crash")) out |= L1_CRASH;
                else if (it.equals("all")) out |= L1_ALL;
            }
        }
        if (!sawExplicit) {
            return (parseLayers(s) & LAYER_L1) != 0 ? L1_ALL : 0;
        }
        return out;
    }

    /** 供说明页与日志展示 */
    static String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("L1=");
        if (!l1()) {
            sb.append("off");
        } else {
            int n = l1Ops();
            sb.append("[trace=").append((n & L1_TRACE) != 0 ? "on" : "off");
            sb.append(",kill=").append((n & L1_KILL) != 0 ? "on" : "off");
            sb.append(",crash=").append((n & L1_CRASH) != 0 ? "on" : "off").append(']');
        }
        sb.append(" L2=");
        if (!l2()) {
            sb.append("off");
        } else {
            int n = nativeOps();
            sb.append("[art=").append((n & NATIVE_ART) != 0 ? "on" : "off");
            sb.append(",linker=").append((n & NATIVE_LINKER) != 0 ? "on" : "off");
            sb.append(",tramp=").append((n & NATIVE_TRAMPOLINE) != 0 ? "on" : "off").append(']');
        }
        sb.append(" L3=");
        if (!l3()) {
            sb.append("off");
        } else {
            sb.append((nativeOps() & NATIVE_CL) != 0 ? "scrub" : "cautious");
            if ((nativeOps() & NATIVE_GUARD) != 0) sb.append("+guard");
        }
        return sb.toString();
    }
}
