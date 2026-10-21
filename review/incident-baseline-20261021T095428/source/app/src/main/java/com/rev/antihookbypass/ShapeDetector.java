package com.rev.antihookbypass;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 检测结果的<b>形态识别</b>引擎 —— 整套方案能"通杀"的核心。
 *
 * <h2>为什么不能靠类名/包名</h2>
 * 若按 {@code com.xxx.antihook.NativeLib.scan()} 这种具体名字去 hook，
 * 就只对那一款检测器有效。换一个人自己写一套检测体系，名字全变，模块立刻失效。
 *
 * <p>但不管谁写，检测逻辑的<b>最终产物</b>是收敛的：它必须把结论组织成
 * 一个可判定的值交回上层。这个「形态」是这一类检测的共同结构，
 * 与它是谁写的无关。识别形态、不识别名字，才谈得上通用。
 *
 * <h2>只认结构，不认名字 —— 这条纪律很重要</h2>
 * 最初的想法是"方法名带 check/scan 就 hook"，这会造成大面积误伤：
 * {@code checkPermission}、{@code isChecked}、{@code scanWifiList} 都是正常业务方法，
 * 把它们的结果改成 false 会直接破坏宿主功能。
 *
 * <p>所以最终纪律是：<b>静态阶段只做宽松预筛（降低开销），
 * 真正的判定完全放在运行时看返回值结构。</b>
 * 只有返回值<b>确实是</b> {@code [{"status":"RISK",...}]} 这种检测结论形态时，
 * 才认定它是检测结果并改写。名字只用来减少要观察的方法数量，不作为依据。
 */
final class ShapeDetector {

    private ShapeDetector() {
    }

    /**
     * 静态预筛：这个方法<b>值得在运行时观察返回值</b>吗。
     *
     * <p>注意这是"值得观察"，不是"就是检测"。判断刻意宽松，
     * 目的是不漏掉目标，代价是可能多挂一些无害的观察钩子
     * （观察本身不改结果，只有形态命中才改）。
     *
     * <p>真正决定要不要改的是 {@link #isResultJson}。
     */
    static boolean worthObserving(Method m) {
        if (m == null) return false;
        int mod = m.getModifiers();
        if (Modifier.isAbstract(mod) || Modifier.isNative(mod)) return false;
        if (m.getParameterCount() > 3) return false;   // 参数太多的一般不是检测入口

        Class<?> ret = m.getReturnType();
        // 只观察这几种可能承载"结论"的返回类型
        return ret == String.class
                || ret == boolean.class || ret == Boolean.class
                || List.class.isAssignableFrom(ret)
                || Set.class.isAssignableFrom(ret)
                || java.util.Map.class.isAssignableFrom(ret);
    }

    // ------------------------------------------------------------------
    // 运行时判定：唯一可靠的依据
    // ------------------------------------------------------------------

    /** JSON 里出现这些键，说明是一个"检测项数组" */
    private static final String[] STATUS_KEYS = {
            "status", "result", "state", "passed", "safe", "ok",
            "risk", "level", "verdict", "detected", "found", "hit",
    };

    /**
     * 运行时判定：这个返回值是不是"检测结论 JSON"。
     *
     * <p>这是整套方案唯一可靠的判据 —— 直接看真实返回值。
     *
     * <p>需要同时满足：
     * <ol>
     *   <li>是 {@code String}，首尾是 {@code [ ]}（数组）；</li>
     *   <li>数组元素是对象（以 {@code {} 开头）；</li>
     *   <li>含判定字段（status/result/...）。</li>
     * </ol>
     *
     * <p>这三条同时成立时，基本可以断定是检测项列表：
     * 普通业务数据极少是"对象数组 + 状态字段"这种形状且由单个方法整体返回。
     */
    static boolean isResultJson(Object value) {
        if (!(value instanceof String)) return false;
        String s = ((String) value).trim();
        // 至少 [{"..."}] 才有意义
        if (s.length() < 8) return false;
        if (s.charAt(0) != '[' || s.charAt(s.length() - 1) != ']') return false;
        if (s.indexOf('{') < 0) return false;             // 必须是对象数组，不是字符串数组
        return containsStatusKey(s);
    }

    private static boolean containsStatusKey(String json) {
        String low = json.toLowerCase();
        for (String k : STATUS_KEYS) {
            if (low.contains("\"" + k + "\"")) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 改写
    // ------------------------------------------------------------------

    /** 各判定字段对应的"安全"取值 */
    private static final String[] BOOL_KEYS = {
            "passed", "pass", "ok", "safe", "detected", "found", "hit", "tamper"
    };

    private static final String[] STR_KEYS = {
            "status", "result", "state", "level", "verdict"
    };

    /**
     * 把检测结论 JSON 整体改为"全部安全"。
     *
     * <p>策略：<b>逐项替换判定字段的值，保留所有其他字段</b>
     * （id / title / detail 等原样留着）。这样结果看起来是真实跑出来的，
     * 而不是伪造的空壳 —— 空数组、字段缺失本身就是可疑特征。
     *
     * <p>手写文本替换而不用 JSON 库，原因有两点：
     * <ol>
     *   <li>要在任意进程、任意类加载器下工作，依赖 org.json 在加固环境里可能不可用；</li>
     *   <li>重新序列化会改变字段顺序与空白，可能被格式校验发现。</li>
     * </ol>
     */
    static String forceSafe(String json) {
        if (json == null) return null;
        String out = json;
        for (String k : BOOL_KEYS) {
            out = replaceValue(out, k, "false");
        }
        for (String k : STR_KEYS) {
            out = replaceValue(out, k, "\"SAFE\"");
        }
        return out;
    }

    private static String replaceValue(String src, String key, String token) {
        String needle = "\"" + key + "\"";
        StringBuilder sb = new StringBuilder(src.length() + 16);
        int i = 0;
        while (true) {
            int at = src.indexOf(needle, i);
            if (at < 0) {
                sb.append(src, i, src.length());
                break;
            }
            int colon = src.indexOf(':', at + needle.length());
            if (colon < 0) {
                sb.append(src, i, src.length());
                break;
            }
            int v = colon + 1;
            while (v < src.length() && Character.isWhitespace(src.charAt(v))) v++;

            sb.append(src, i, v);
            int end = valueEnd(src, v);
            if (end <= v) {                 // 解析不出来，保持原样继续
                sb.append(src, v, Math.min(v + 1, src.length()));
                i = Math.min(v + 1, src.length());
                continue;
            }
            sb.append(token);
            i = end;
        }
        return sb.toString();
    }

    /** 找一个 JSON 值的结束位置 */
    private static int valueEnd(String s, int start) {
        if (start >= s.length()) return start;
        char c = s.charAt(start);
        if (c == '"') {
            int i = start + 1;
            while (i < s.length()) {
                char ch = s.charAt(i);
                if (ch == '\\') { i += 2; continue; }
                if (ch == '"') return i + 1;
                i++;
            }
            return s.length();
        }
        if (c == '{' || c == '[') {
            char open = c, close = (c == '{') ? '}' : ']';
            int depth = 0, i = start;
            boolean inStr = false;
            while (i < s.length()) {
                char ch = s.charAt(i);
                if (inStr) {
                    if (ch == '\\') { i += 2; continue; }
                    if (ch == '"') inStr = false;
                } else {
                    if (ch == '"') inStr = true;
                    else if (ch == open) depth++;
                    else if (ch == close) {
                        depth--;
                        if (depth == 0) return i + 1;
                    }
                }
                i++;
            }
            return s.length();
        }
        int i = start;
        while (i < s.length()) {
            char ch = s.charAt(i);
            if (ch == ',' || ch == '}' || ch == ']' || Character.isWhitespace(ch)) break;
            i++;
        }
        return i;
    }

    /** 集合型结论清空（返回空集合而非 null，避免调用方 NPE） */
    static Object emptyCollection(Class<?> retType) {
        if (Set.class.isAssignableFrom(retType)) return new HashSet<>();
        if (java.util.Map.class.isAssignableFrom(retType)) return new java.util.HashMap<>();
        return new ArrayList<>();
    }

    /**
     * 生成"全部安全"的结论，但<b>不预设任何检测项的 id 或标题</b>。
     *
     * <p>返回空数组是刻意的选择：
     * <ul>
     *   <li>它表示"没有发现任何问题"，UI 会显示"环境正常"；</li>
     *   <li>它不包含任何特定 App 的检测项名称，换目标也不会驴唇不对马嘴；</li>
     *   <li>相比凭空造六项，空数组不会引起"项数对不上"的怀疑。</li>
     * </ul>
     *
     * <p>如果调用方拿到了真实结果，应该优先用 {@link #forceSafe} 改写，
     * 那样能保留原始 id/title，更自然。
     */
    static String buildSafeFor(String original) {
        if (original != null && !original.isEmpty()) {
            String fixed = forceSafe(original);
            if (fixed != null) return fixed;
        }
        return "[]";
    }
}
