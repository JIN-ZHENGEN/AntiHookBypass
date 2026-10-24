package com.rev.antihookbypass;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 直接解析 APK 里的 dex，找出「native 且返回 String」的方法所属的类。
 *
 * <h2>为什么不靠 ClassLoader.loadClass 发现</h2>
 * 实测（Android 17 / ART）：{@code Class.forName} 与 JNI 的 {@code FindClass}
 * 都由 ART 的 ClassLinker 原生解析，**不经过 Java 层的 ClassLoader.loadClass**。
 * 挂在 loadClass 上只能看到显式调用 loadClass 的那一小部分类，目标类照样漏。
 * 实测症状很直接：日志里 "结果层已挂 2/2"，但整轮没有任何一条 VERDICT。
 *
 * <h2>为什么不用 Class.forName 枚举所有类</h2>
 * 那要先把每个类名都解析一遍。几千个类就是几百毫秒到几秒，大应用上不可接受，
 * 而且会提前加载大量无关类。
 *
 * <h2>这里的做法</h2>
 * 直接读 dex 的 method_ids / proto_ids / class_data 三段结构：
 * <ol>
 *   <li>{@code class_data} 里的 encoded_method 带 access_flags，ACC_NATIVE=0x100，
 *       原生方法的 code_off 必为 0；</li>
 *   <li>method_idx 指向 method_ids，取 proto_idx；</li>
 *   <li>proto_ids 的 return_type_idx 指向 type_ids，看返回类型描述符是不是
 *       {@code Ljava/lang/String;}。</li>
 * </ol>
 * 全过程只读字节，不加载任何类。一个 dex 解析完是线性时间，几毫秒量级；
 * 只有真正命中的类才做一次 {@code Class.forName(name, false, cl)}。
 *
 * <p>判据只有「是 native」+「返回 String」两条，不含任何包名、类名、方法名、
 * 字段名或具体数值，换任何应用、任何库都同样适用。
 */
final class DexScan {

    private DexScan() {
    }

    /** 单个 dex 最多读出多少字节，防止畸形 dex 把内存吃光 */
    private static final int MAX_DEX_BYTES = 64 * 1024 * 1024;
    /** 候选类上限，防止极端应用把 hook 数量拖爆 */
    private static final int MAX_CANDIDATES = 4096;
    /** 整个 APK 最多读多少个 dex（classes.dex ~ classes32.dex 的量级） */
    private static final int MAX_DEX_FILES = 64;

    private static final int ACC_NATIVE = 0x0100;

    /**
     * 扫描给定 APK 列表，返回「含 native 且返回 String 的方法」的类名列表。
     *
     * @return 二进制类名（点分）数组，可能为空，绝不为 null
     */
    static String[] candidateClasses(String[] apks) {
        if (apks == null || apks.length == 0) return new String[0];
        ArrayList<String> out = new ArrayList<String>();
        int files = 0;
        for (String apk : apks) {
            if (apk == null || apk.length() == 0) continue;
            ZipFile zf = null;
            try {
                zf = new ZipFile(apk);
                java.util.Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    if (files >= MAX_DEX_FILES) break;
                    ZipEntry e = en.nextElement();
                    String n = e.getName();
                    if (n == null) continue;
                    if (!n.startsWith("classes") || !n.endsWith(".dex")) continue;
                    files++;
                    byte[] data = readEntry(zf, e);
                    if (data == null) continue;
                    try {
                        collectFromDex(data, out);
                    } catch (Throwable ignored) {
                    }
                    if (out.size() >= MAX_CANDIDATES) break;
                }
            } catch (Throwable ignored) {
            } finally {
                if (zf != null) {
                    try {
                        zf.close();
                    } catch (Throwable ignored) {
                    }
                }
            }
            if (out.size() >= MAX_CANDIDATES) break;
        }
        return out.toArray(new String[0]);
    }

    private static byte[] readEntry(ZipFile zf, ZipEntry e) {
        InputStream in = null;
        try {
            long size = e.getSize();
            if (size <= 0 || size > MAX_DEX_BYTES) return null;
            in = zf.getInputStream(e);
            byte[] buf = new byte[(int) size];
            int off = 0;
            while (off < buf.length) {
                int r = in.read(buf, off, buf.length - off);
                if (r <= 0) break;
                off += r;
            }
            return off == buf.length ? buf : null;
        } catch (Throwable t) {
            return null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* dex 结构解析                                                       */
    /* ------------------------------------------------------------------ */

    private static void collectFromDex(byte[] d, ArrayList<String> out) {
        if (d.length < 0x70) return;
        /* magic: "dex\n0xx\0" */
        if (d[0] != 'd' || d[1] != 'e' || d[2] != 'x' || d[3] != '\n') return;

        ByteBuffer b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
        int stringIdsOff = b.getInt(0x3C);
        int typeIdsOff = b.getInt(0x44);
        int protoIdsOff = b.getInt(0x4C);
        int methodIdsOff = b.getInt(0x5C);
        int classDefsSize = b.getInt(0x60);
        int classDefsOff = b.getInt(0x64);
        if (classDefsSize <= 0 || classDefsSize > 200000) return;

        java.util.HashMap<Integer, String> retMap = new java.util.HashMap<Integer, String>();

        for (int i = 0; i < classDefsSize; i++) {
            int cd = classDefsOff + i * 32;
            if (cd < 0 || cd + 32 > d.length) return;
            int classIdx = b.getInt(cd);
            int classDataOff = b.getInt(cd + 24);
            if (classDataOff <= 0 || classDataOff >= d.length) continue;

            String cls = typeDesc(b, typeIdsOff, stringIdsOff, classIdx);
            if (cls == null) continue;

            /* class_data_item: 四个 uleb128 计数，然后是字段表、方法表 */
            int p = classDataOff;
            int[] sizes = new int[4];
            for (int k = 0; k < 4; k++) {
                int[] r = uleb(b, p);
                if (r == null) { p = -1; break; }
                sizes[k] = r[0];
                p = r[1];
            }
            if (p < 0) continue;
            /* 跳过 encoded_field（idx_diff, access_flags） */
            int fieldCount = sizes[0] + sizes[1];
            for (int k = 0; k < fieldCount; k++) {
                int[] r = uleb(b, p);
                if (r == null) { p = -1; break; }
                r = uleb(b, r[1]);
                if (r == null) { p = -1; break; }
                p = r[1];
            }
            if (p < 0) continue;

            /*
             * 方法表：direct 与 virtual 是两张独立的表，各自的 method_idx_diff
             * 都从 0 开始累加。合并成一个累加器会把 virtual 表的方法索引整体算偏
             * —— 实测后果是候选类数为 0，日志上看不出任何异常。
             */
            boolean hit = false;
            for (int t = 0; t < 2 && !hit; t++) {
                int count = (t == 0) ? sizes[2] : sizes[3];
                int methodIdx = 0;
                for (int k = 0; k < count; k++) {
                    int[] r = uleb(b, p);
                    if (r == null) { p = -1; break; }
                    methodIdx += r[0];
                    p = r[1];
                    int[] acc = uleb(b, p);
                    if (acc == null) { p = -1; break; }
                    p = acc[1];
                    int[] code = uleb(b, p);
                    if (code == null) { p = -1; break; }
                    p = code[1];

                    if ((acc[0] & ACC_NATIVE) == 0) continue;
                    if (code[0] != 0) continue;         /* 原生方法没有 code_item */

                    int mi = methodIdsOff + methodIdx * 8;
                    if (mi < 0 || mi + 8 > d.length) continue;
                    int protoIdx = b.getShort(mi + 2) & 0xFFFF;

                    String ret = retMap.get(protoIdx);
                    if (ret == null) {
                        int po = protoIdsOff + protoIdx * 12;
                        if (po < 0 || po + 12 > d.length) continue;
                        int retTypeIdx = b.getInt(po + 4);
                        ret = typeDesc(b, typeIdsOff, stringIdsOff, retTypeIdx);
                        if (ret == null) ret = "?";
                        retMap.put(protoIdx, ret);
                    }
                    if ("Ljava/lang/String;".equals(ret)) {
                        hit = true;
                        break;
                    }
                }
            }
            if (p < 0) continue;
            if (hit) {
                String bin = descToBinary(cls);
                if (bin != null) out.add(bin);
            }
        }
    }

    private static String typeDesc(ByteBuffer b, int typeIdsOff, int stringIdsOff, int typeIdx) {
        int p = typeIdsOff + typeIdx * 4;
        if (p < 0 || p + 4 > b.capacity()) return null;
        int stringIdx = b.getInt(p);
        return string(b, stringIdsOff, stringIdx);
    }

    private static String string(ByteBuffer b, int stringIdsOff, int idx) {
        if (idx < 0) return null;
        int p = stringIdsOff + idx * 4;
        if (p < 0 || p + 4 > b.capacity()) return null;
        int dataOff = b.getInt(p);
        if (dataOff < 0 || dataOff >= b.capacity()) return null;
        int q = dataOff;
        int[] r = uleb(b, q);                            /* 跳过 utf16 长度 */
        if (r == null) return null;
        q = r[1];
        StringBuilder sb = new StringBuilder(64);
        while (q < b.capacity()) {
            int c = b.get(q) & 0xFF;
            if (c == 0) break;
            if (c < 0x80) {
                sb.append((char) c);
                q++;
            } else if ((c & 0xE0) == 0xC0) {
                if (q + 1 >= b.capacity()) break;
                sb.append((char) (((c & 0x1F) << 6) | (b.get(q + 1) & 0x3F)));
                q += 2;
            } else if ((c & 0xF0) == 0xE0) {
                if (q + 2 >= b.capacity()) break;
                sb.append((char) (((c & 0x0F) << 12)
                        | ((b.get(q + 1) & 0x3F) << 6)
                        | (b.get(q + 2) & 0x3F)));
                q += 3;
            } else {
                q++;
            }
        }
        return sb.toString();
    }

    /** uleb128 解码，返回 {值, 下一位置}；越界返回 null */
    private static int[] uleb(ByteBuffer b, int p) {
        if (p < 0 || p >= b.capacity()) return null;
        int result = 0;
        int shift = 0;
        while (p < b.capacity() && shift < 35) {
            int c = b.get(p) & 0xFF;
            p++;
            result |= (c & 0x7F) << shift;
            if ((c & 0x80) == 0) return new int[]{result, p};
            shift += 7;
        }
        return null;
    }

    /** "Lcom/a/B;" -> "com.a.B"；数组/基本类型返回 null */
    private static String descToBinary(String desc) {
        if (desc == null || desc.length() < 3) return null;
        if (desc.charAt(0) != 'L' || desc.charAt(desc.length() - 1) != ';') return null;
        return desc.substring(1, desc.length() - 1).replace('/', '.');
    }
}
