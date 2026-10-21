#!/usr/bin/env python3
"""
AXML 生成器：把 AndroidManifest.xml 编译成 Android 二进制 XML。

== 为什么自己写 ==
标准做法是 aapt2，但 aapt2 是 x86_64 原生程序，在 arm64 Android 上跑不起来。
所以直接按 AXML 二进制格式生成，绕开整个 aapt2。

== 结构（按真实 APK 逆向确认）==
文件级 chunk 序列：
  0x0003  文件头（8 字节）
  0x0001  字符串池
  0x0180  资源映射表（属性名 -> 框架资源 ID）
  0x0100  命名空间开始  ← 必须有，否则 apksigner/系统解析失败
  0x0102  元素开始
  0x0103  元素结束
  0x0101  命名空间结束
"""

import struct

RES_STRING_POOL    = 0x0001
RES_XML            = 0x0003
RES_XML_START_NS   = 0x0100
RES_XML_END_NS     = 0x0101
RES_XML_START_EL   = 0x0102
RES_XML_END_EL     = 0x0103
RES_XML_RES_MAP    = 0x0180

TYPE_NULL        = 0x00
TYPE_REFERENCE   = 0x01
TYPE_STRING      = 0x03
TYPE_INT_DEC     = 0x10
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 0x100

# Android 框架属性资源 ID（固定值，从 android.R.attr 来）
ATTR_IDS = {
    # 这些 ID 取自 android.R.attr，是系统固定值。
    # 只有在这张表里的属性才会被写进 resource map，
    # 也只有进了 map 的属性，系统才能识别成 "android:xxx"。
    # 缺一个，就会报 "requires an android:xxx attribute" —— 即使字节都在。
    'theme':            0x01010000,
    'label':            0x01010001,
    'icon':             0x01010002,
    'name':             0x01010003,
    'permission':       0x01010006,
    'exported':         0x01010010,
    'enabled':          0x0101000e,
    'value':            0x01010024,   # 关键：<meta-data android:value>
    'resource':         0x01010025,
    'debuggable':       0x0101000f,
    'minSdkVersion':    0x0101020c,
    'versionCode':      0x0101021b,
    'versionName':      0x0101021c,
    'targetSdkVersion': 0x01010270,
    'allowBackup':      0x01010280,
    'largeHeap':        0x0101035a,
    'supportsRtl':      0x010103af,
    'extractNativeLibs':0x010104ea,
    'roundIcon':        0x0101052c,
    'multiArch':        0x010104f7,
    'hasCode':          0x0101000c,
    'process':          0x01010011,
}

ANDROID_NS = 'http://schemas.android.com/apk/res/android'


class StringPool:
    def __init__(self):
        self.strings = []
        self.index = {}

    def add(self, s):
        if s is None:
            s = ''
        if s not in self.index:
            self.index[s] = len(self.strings)
            self.strings.append(s)
        return self.index[s]

    @staticmethod
    def _enc_len(n):
        """AXML UTF-8 长度编码：<=0x7F 单字节，否则双字节"""
        if n <= 0x7F:
            return bytes([n])
        return bytes([0x80 | ((n >> 8) & 0x7F), n & 0xFF])

    def build(self):
        offsets = []
        data = bytearray()
        for s in self.strings:
            offsets.append(len(data))
            b = s.encode('utf-8')
            data.extend(self._enc_len(len(s)))
            data.extend(self._enc_len(len(b)))
            data.extend(b)
            data.append(0)

        header_size = 28
        data_start = header_size + 4 * len(offsets)
        total = data_start + len(data)
        # 补齐到 4 字节
        pad = (4 - total % 4) % 4
        total += pad

        out = bytearray()
        out += struct.pack('<HHI', RES_STRING_POOL, header_size, total)
        out += struct.pack('<I', len(self.strings))
        out += struct.pack('<I', 0)
        out += struct.pack('<I', UTF8_FLAG)
        out += struct.pack('<I', data_start)
        out += struct.pack('<I', 0)
        for o in offsets:
            out += struct.pack('<I', o)
        out += data
        out += b'\x00' * pad
        return bytes(out)


class XmlWriter:
    """
    两遍构建：先登记所有字符串得到稳定索引，再序列化。
    一边登记一边序列化会让后加入的字符串改变池大小，
    但已写入 chunk 的索引不跟着变，导致错位。
    """

    def __init__(self, line=1):
        self.pool = StringPool()
        self.ops = []
        self.attr_names = []
        self.line = line

    def _reg(self, tag, attrs):
        self.pool.add(tag)
        for (aname, aval, atype) in attrs:
            self.pool.add(aname)
            if atype == 'str':
                self.pool.add(str(aval))
            if aname in ATTR_IDS and aname not in self.attr_names:
                self.attr_names.append(aname)

    def start_ns(self, prefix, uri):
        self.pool.add(prefix)
        self.pool.add(uri)
        self.ops.append(('start_ns', (prefix, uri), None))
        return self

    def end_ns(self, prefix, uri):
        self.pool.add(prefix)
        self.pool.add(uri)
        self.ops.append(('end_ns', (prefix, uri), None))
        return self

    def start(self, tag, attrs=None, ns=None):
        attrs = attrs or []
        self._reg(tag, attrs)
        if ns:
            self.pool.add(ns)
        self.ops.append(('start', tag, (attrs, ns)))
        return self

    def end(self, tag, ns=None):
        self.pool.add(tag)
        if ns:
            self.pool.add(ns)
        self.ops.append(('end', tag, ns))
        return self

    # ---- 序列化 ----

    def _ns_chunk(self, ctype, prefix, uri):
        body = struct.pack('<II', self.line, 0xFFFFFFFF)   # line, comment
        body += struct.pack('<II', self.pool.add(prefix), self.pool.add(uri))
        total = 8 + len(body)
        return struct.pack('<HHI', ctype, 16, total) + body

    def _start_chunk(self, tag, attrs, ns):
        name_idx = self.pool.add(tag)
        # 元素自身的 ns 一律 0xFFFFFFFF。
        # 实测真实 APK 里 <manifest>/<application>/<meta-data> 的 ns 全是无命名空间，
        # 元素名本身不带前缀；只有"属性"才需要区分 android: 命名空间。
        # 给元素塞 ns 会让系统解析器认不出属性归属，报
        # "<meta-data> requires an android:name attribute"。
        ns_idx = 0xFFFFFFFF

        # 属性用的 android 命名空间索引（与元素自身的 ns 无关）
        attr_ns_idx = self.pool.add(ns) if ns else 0xFFFFFFFF

        attr_data = bytearray()
        for (aname, aval, atype) in attrs:
            ans = self.pool.add(aname)
            rid = ATTR_IDS.get(aname, 0)
            # 属于 android: 命名空间的属性（ATTR_IDS 里有资源 ID 的）才带 ns，
            # 自定义属性（如 package、xposedmodule）不带。
            use_ns = attr_ns_idx if rid else 0xFFFFFFFF

            if atype == 'str':
                raw = self.pool.add(str(aval))
                vtype, vdata = TYPE_STRING, raw
            elif atype == 'int':
                raw = 0xFFFFFFFF
                vtype, vdata = TYPE_INT_DEC, int(aval)
            elif atype == 'bool':
                raw = 0xFFFFFFFF
                vtype, vdata = TYPE_INT_BOOLEAN, (0xFFFFFFFF if aval else 0)
            elif atype == 'ref':
                raw = 0xFFFFFFFF
                vtype, vdata = TYPE_REFERENCE, int(aval)
            else:
                raise ValueError(atype)

            attr_data += struct.pack('<III', use_ns, ans, raw)
            # Res_value: size(2) res0(1) dataType(1) data(4) = 8 字节
            attr_data += struct.pack('<HBBI', 8, 0, vtype, vdata)

        # ResXMLTree_node: line(4) comment(4)
        # ResXMLTree_attrExt: ns(4) name(4) attributeStart(2) attributeSize(2)
        #                     attributeCount(2) idIndex(2) classIndex(2) styleIndex(2)
        #
        # 关键：attributeStart 是"从 attrExt 起点算起"的偏移，
        # attrExt 起点 = chunk 头(8) + line/comment(8) = 16；
        # 属性区紧跟在 attrExt 之后，而 attrExt 本身是 20 字节，
        # 所以 attributeStart = 20 + ... 实际标准写法就是 20。
        # attributeSize 是单个属性的结构大小：ns(4)+name(4)+rawValue(4)
        #   + typedValue(8) = 20。
        ext = struct.pack('<II', self.line, 0xFFFFFFFF)          # line, comment
        ext += struct.pack('<II', ns_idx, name_idx)              # ns, name
        ext += struct.pack('<HHHHHH', 20, 20, len(attrs), 0, 0, 0)
        body = ext + bytes(attr_data)
        total = 8 + len(body)
        return struct.pack('<HHI', RES_XML_START_EL, 16, total) + body

    def _end_chunk(self, tag, ns):
        name_idx = self.pool.add(tag)
        ns_idx = 0xFFFFFFFF      # 与 start 保持一致
        body = struct.pack('<II', self.line, 0xFFFFFFFF)
        body += struct.pack('<II', ns_idx, name_idx)
        total = 8 + len(body)
        return struct.pack('<HHI', RES_XML_END_EL, 16, total) + body

    def build(self):
        # ============================================================
        # 关键：重建字符串池，让"属性名"排在最前面。
        #
        # AXML 的 resource map 是"按下标对应"的：第 i 项资源 ID 对应
        # 字符串池第 i 个字符串。系统靠它把属性名映射到 android.R.attr，
        # 从而认出"这是 android:name 属性"。
        #
        # 如果属性名不在池的前 N 项（N = resource map 项数），
        # 映射就对不上，系统会报
        #   "<meta-data> requires an android:name attribute"
        # 即使字节层面属性确实存在、也带了正确的命名空间。
        #
        # 所以这里做一次重排：属性名按 attr_names 顺序放最前，
        # 其余字符串按原有相对顺序跟在后。
        # ============================================================
        if self.attr_names:
            ordered = list(self.attr_names)
            seen = set(ordered)
            for s in self.pool.strings:
                if s not in seen:
                    ordered.append(s)
                    seen.add(s)
            self.pool.strings = ordered
            self.pool.index = {s: i for i, s in enumerate(ordered)}

        pool_bytes = self.pool.build()

        body = bytearray()
        body += pool_bytes

        if self.attr_names:
            ids = [ATTR_IDS[n] for n in self.attr_names]
            body += struct.pack('<HHI', RES_XML_RES_MAP, 8, 8 + 4 * len(ids))
            for i in ids:
                body += struct.pack('<I', i)

        for kind, a, b in self.ops:
            if kind == 'start_ns':
                body += self._ns_chunk(RES_XML_START_NS, a[0], a[1])
            elif kind == 'end_ns':
                body += self._ns_chunk(RES_XML_END_NS, a[0], a[1])
            elif kind == 'start':
                body += self._start_chunk(a, b[0], b[1])
            else:
                body += self._end_chunk(a, b)

        return struct.pack('<HHI', RES_XML, 8, 8 + len(body)) + bytes(body)
