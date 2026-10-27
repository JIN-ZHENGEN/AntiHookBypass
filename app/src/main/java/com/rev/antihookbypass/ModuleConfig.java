package com.rev.antihookbypass;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

final class ModuleConfig {

    private ModuleConfig() {
    }

    static final int LAYER_L1 = 1 << 0;
    static final int LAYER_L2 = 1 << 1;
    static final int LAYER_L3 = 1 << 2;

    static final int NATIVE_ART = 1 << 0;
    static final int NATIVE_LINKER = 1 << 1;
    static final int NATIVE_TRAMPOLINE = 1 << 2;
    static final int NATIVE_CL = 1 << 3;
    static final int NATIVE_GUARD = 1 << 4;

    static final int L1_TRACE = 1 << 0;
    static final int L1_KILL = 1 << 1;
    static final int L1_CRASH = 1 << 2;
    static final int L1_ALL = L1_TRACE | L1_KILL | L1_CRASH;

    /*
     * 层配置编译期常量。CFG 恒为 null，readCfgLine() 永远返回 null，
     * 因此 parseLayers(null) 直接走默认值。
     *
     * l1-default-on 分支：默认 ALL（L1+L2+L3 全开），
     * 保留 L1（TraceHide 的 getStackTrace 缓存修复），与 anti-cpu-hotfix 版
     * 唯一差别就是默认层选择——让用户实测 L1 完整能力下的 CPU 表现。
     */
    private static final String CFG = null;

    private static final int DEFAULT_ALL = LAYER_L1 | LAYER_L2 | LAYER_L3;

    private static volatile int cachedLayers = -1;
    private static volatile int cachedNative = -1;
    private static volatile int cachedL1 = -1;

    static int layers() {
        int v = cachedLayers;
        if (v >= 0) return v;
        v = parseLayers(readCfgLine());
        cachedLayers = v;
        return v;
    }

    static boolean mapsHide() {
        String s = readCfgLine();
        if (s == null) return true;
        if (s.contains("nomapshide")) return false;
        if (s.contains("mapshide")) return true;
        return true;
    }

    static int nativeOps() {
        int v = cachedNative;
        if (v >= 0) return v;
        v = parseNative(readCfgLine());
        if ((v & NATIVE_TRAMPOLINE) != 0 && (v & (NATIVE_ART | NATIVE_LINKER)) == 0) {
            v |= NATIVE_ART | NATIVE_LINKER;
        }
        cachedNative = v;
        return v;
    }

    static int l1Ops() {
        int v = cachedL1;
        if (v >= 0) return v;
        v = parseL1(readCfgLine());
        cachedL1 = v;
        return v;
    }

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

    static boolean l1Trace() {
        return l1() && (l1Ops() & L1_TRACE) != 0;
    }

    static boolean l1Kill() {
        return l1() && (l1Ops() & L1_KILL) != 0;
    }

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
        if (CFG == null) return null;
        return null;
    }

    private static int parseLayers(String s) {
        final int ALL = LAYER_L1 | LAYER_L2 | LAYER_L3;
        /*
         * l1-default-on：默认全开（含 L1 TraceHide 缓存修复版）。
         * L1 是调用栈/类探测压制，属于"隐藏 Xposed 痕迹"的 Java 层能力；
         * 缓存修复（WeakHashMap 200ms TTL）已把高频 getStackTrace 的 CPU 黑洞压下去，
         * 故该分支保留 L1 默认开，供用户对比"完整能力 vs 默认关 L1"的 CPU 与检测差异。
         */
        if (s == null) return DEFAULT_ALL;
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

    private static int parseNative(String s) {
        final int ALL = NATIVE_ART | NATIVE_LINKER | NATIVE_TRAMPOLINE
                      | NATIVE_CL | NATIVE_GUARD;
        if (s == null) return ALL;
        if (s.equals("all") || s.equals("default") || s.equals("none") || s.equals("off")) {
            return s.startsWith("none") || s.equals("off") ? 0 : ALL;
        }
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
            return (parseLayers(s) & (LAYER_L2 | LAYER_L3)) != 0 ? ALL : 0;
        }
        return out;
    }

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
