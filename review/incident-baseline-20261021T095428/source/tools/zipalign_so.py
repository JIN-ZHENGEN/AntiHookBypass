#!/usr/bin/env python3
"""
让 APK 里的 .so 按页对齐存放。

================================ 为什么需要 ================================

Android 从 Android 6 起支持"不把 so 解压到磁盘、直接从 APK 里 mmap 加载"。
但有个硬性前提：**so 在 zip 里的数据起始位置必须按页对齐**。

原因是 linker 直接用 mmap 把 so 映射进内存，而 mmap 的 offset 必须是页大小
的整数倍。如果数据从 offset=65 开始，这次 mmap 直接失败，dlopen 报：

    dlopen failed: library ".../base.apk!/lib/arm64-v8a/libxxx.so" not found

这个报错极具误导性 —— 文件明明在 APK 里，却报"找不到"。

官方工具是 zipalign（`zipalign -P 16 -f in.apk out.apk`），
但它在本机跑不起来（x86 二进制）。所以这里自己实现。

================================= 做法 =====================================

1. 逐个读出原 APK 的所有条目
2. 重新写入新 zip，但 .so 条目：
   - 用 STORED（不压缩）
   - 在条目文件头前插入 padding，使"数据区起点"落在 16K 边界
   - padding 通过 extra field 实现（zip 规范允许，且不改变文件内容）
3. 非 .so 条目正常压缩
"""
import struct
import sys
import zipfile

# zip 规范里用于对齐的 extra field id（"对齐填充"，Android 认这个）
ALIGN_EXTRA_ID = 0xd935
PAGE = 16384          # 16K，覆盖 4K 设备（16K 对齐天然满足 4K）


def build(src, dst):
    zin = zipfile.ZipFile(src, "r")
    zout = zipfile.ZipFile(dst, "w")

    for item in zin.infolist():
        data = zin.read(item.filename)
        name = item.filename

        if name.endswith(".so"):
            # so 用 STORED，并做页对齐
            _add_aligned_stored(zout, name, data, item)
        else:
            # 其它文件正常压缩
            zi = zipfile.ZipInfo(name, item.date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = item.external_attr
            zout.writestr(zi, data)

    zout.close()
    zin.close()


def _add_aligned_stored(zout, name, data, orig):
    """把一个 STORED 文件写进 zip，并保证其数据区起点页对齐"""
    zi = zipfile.ZipInfo(name, orig.date_time)
    zi.compress_type = zipfile.ZIP_STORED
    zi.external_attr = orig.external_attr

    name_b = name.encode("utf-8")

    # 先算：如果不加 padding，数据区会在哪个 offset
    # 结构：local header(30) + name + extra + data
    hl = zout.fp.tell()
    base = hl + 30 + len(name_b)
    # 当前 extra 为空时 data 的 offset
    pad = (PAGE - (base % PAGE)) % PAGE

    if pad < 4:
        # extra field 至少 4 字节（id 2 + size 2），不够就再加一页
        pad += PAGE

    # 构造 extra：id(2) size(2) payload
    payload_len = pad - 4
    extra = struct.pack("<HH", ALIGN_EXTRA_ID, payload_len) + b"\x00" * payload_len
    zi.extra = extra

    # 校验对齐结果
    actual = hl + 30 + len(name_b) + len(extra)
    if actual % PAGE != 0:
        # 兜底：直接扩 extra 到对齐
        need = (PAGE - (actual % PAGE)) % PAGE
        if need < 4:
            need += PAGE
        payload_len = len(extra) - 4 + need
        extra = struct.pack("<HH", ALIGN_EXTRA_ID, payload_len) + b"\x00" * payload_len
        zi.extra = extra

    zout.writestr(zi, data)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: zipalign_so.py <in.apk> <out.apk>")
        sys.exit(1)
    build(sys.argv[1], sys.argv[2])
    print("aligned ->", sys.argv[2])
