#!/usr/bin/env bash
#
# 编译四种 ABI 的 native 库（L2 + L3）。
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(cd "$ROOT/.." && pwd)"
NDK="$W/android-sdk/ndk/26.3.11579264"
SYS="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
SRC="$ROOT/app/src/main/jni/native_main.c"
OUT="$ROOT/build/lib"

export PATH="$PATH"

mkdir -p "$OUT"

# 探测 sysroot 中真实存在 crtbegin_so.o 的 API 级目录。
# NDK r26(r26b) 的 unified sysroot 布局与旧版不同：aarch64-linux-android/ 下
# 可能没有数字子目录，crt 直接放在该 triple 目录根；也可能按 24/27 分目录。
# 这里直接找"含 crtbegin_so.o 的目录"，兼容两种布局。
detect_crtdir() {
    local libroot="$SYS/usr/lib/aarch64-linux-android"
    local found=""
    # 优先在 数字子目录 中找
    for d in "$libroot"/*/crtbegin_so.o; do
        [ -f "$d" ] || continue
        found="$(dirname "$d")"
        break
    done
    # 若没有数字子目录，回退到 triple 根目录（unified sysroot）
    if [ -z "$found" ] && [ -f "$libroot/crtbegin_so.o" ]; then
        found="$libroot"
    fi
    echo "$found"
}

CRTDIR="$(detect_crtdir)"
if [ -z "$CRTDIR" ]; then
    echo "    FAIL: 在 $SYS/usr/lib 下找不到 crtbegin_so.o"
    exit 1
fi
echo "==> 使用 crt 目录: $CRTDIR"

build() {
    local abi="$1" target="$2" libdir="$3"; shift 3
    local extra="$*"
    local d="$OUT/$abi"
    mkdir -p "$d"

    # shellcheck disable=SC2086
    clang --target="$target" --sysroot="$SYS" $extra \
        -shared -fPIC -O2 -fvisibility=hidden -nostdlib \
        "$CRTDIR/crtbegin_so.o" \
        "$CRTDIR/crtend_so.o" \
        -L"$CRTDIR" \
        -o "$d/libantihook_bypass.so" $SRC -lc -ldl -llog

    if readelf --dyn-syms "$d/libantihook_bypass.so" | grep -q native_init && \
       readelf --dyn-syms "$d/libantihook_bypass.so" | grep -q Java_com_rev_antihookbypass_NativeLayer_nativeSanitizeRuntime; then
        echo "    $abi  OK  $(stat -c%s "$d/libantihook_bypass.so") B"
    else
        echo "    $abi  FAIL: 关键符号未导出"
        return 1
    fi
}

echo "==> 编译 native（4 个 ABI）"

build arm64-v8a    aarch64-linux-android24    aarch64-linux-android    ""
build armeabi-v7a  armv7a-linux-androideabi24 arm-linux-androideabi    "-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16"
build x86          i686-linux-android24       i686-linux-android       ""
build x86_64       x86_64-linux-android24     x86_64-linux-android     ""

echo "==> native 编译完成"