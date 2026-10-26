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

# 探测 NDK sysroot 实际存在的 API level（r26b 仅有 24+，无 21）。
# 取 aarch64-linux-android 目录下数值最小的那个，作为 crt/link 路径的 API 级。
detect_api() {
    local libroot="$SYS/usr/lib/aarch64-linux-android"
    local best=""
    for d in "$libroot"/*; do
        local n
        n="$(basename "$d")"
        case "$n" in
            (*[!0-9]*) continue ;;
        esac
        if [ -z "$best" ] || [ "$n" -lt "$best" ]; then
            best="$n"
        fi
    done
    echo "${best:-24}"
}

API="$(detect_api)"

build() {
    local abi="$1" target="$2" libdir="$3"; shift 3
    local extra="$*"
    local d="$OUT/$abi"
    mkdir -p "$d"

    # shellcheck disable=SC2086
    clang --target="$target" --sysroot="$SYS" $extra \
        -shared -fPIC -O2 -fvisibility=hidden -nostdlib \
        "$SYS/usr/lib/$libdir/$API/crtbegin_so.o" \
        "$SYS/usr/lib/$libdir/$API/crtend_so.o" \
        -L"$SYS/usr/lib/$libdir/$API" \
        -o "$d/libantihook_bypass.so" $SRC -lc -ldl -llog

    if readelf --dyn-syms "$d/libantihook_bypass.so" | grep -q native_init && \
       readelf --dyn-syms "$d/libantihook_bypass.so" | grep -q Java_com_rev_antihookbypass_NativeLayer_nativeSanitizeRuntime; then
        echo "    $abi  OK  $(stat -c%s "$d/libantihook_bypass.so") B"
    else
        echo "    $abi  FAIL: 关键符号未导出"
        return 1
    fi
}

echo "==> 编译 native（4 个 ABI），NDK sysroot API=$API"

build arm64-v8a    aarch64-linux-android$API    aarch64-linux-android    ""
build armeabi-v7a  armv7a-linux-androideabi$API arm-linux-androideabi    "-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16"
build x86          i686-linux-android$API       i686-linux-android       ""
build x86_64       x86_64-linux-android$API     x86_64-linux-android     ""

echo "==> native 编译完成"