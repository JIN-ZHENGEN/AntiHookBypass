#!/data/data/com.dsharnessmobile.shell/files/usr/bin/bash
#
# 编译四种 ABI 的 native 库（L2 + L3）。
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(cd "$ROOT/.." && pwd)"
NDK="$W/android-sdk/ndk/26.3.11579264"
SYS="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
SRC="$ROOT/app/src/main/jni/native_main.c"
OUT="$ROOT/build/lib"

export PATH=/data/data/com.dsharnessmobile.shell/files/usr/bin:$PATH

mkdir -p "$OUT"

build() {
    local abi="$1" target="$2" libdir="$3"; shift 3
    local extra="$*"
    local d="$OUT/$abi"
    mkdir -p "$d"

    # shellcheck disable=SC2086
    clang --target="$target" --sysroot="$SYS" $extra \
        -shared -fPIC -O2 -fvisibility=hidden -nostdlib \
        "$SYS/usr/lib/$libdir/21/crtbegin_so.o" \
        "$SYS/usr/lib/$libdir/21/crtend_so.o" \
        -L"$SYS/usr/lib/$libdir/21" \
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
build arm64-v8a   aarch64-linux-android21        aarch64-linux-android            ""
build armeabi-v7a armv7a-linux-androideabi21    arm-linux-androideabi            "-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16"
build x86         i686-linux-android21          i686-linux-android               "-march=i686"
build x86_64      x86_64-linux-android21        x86_64-linux-android             ""

echo "==> native 全部完成"
