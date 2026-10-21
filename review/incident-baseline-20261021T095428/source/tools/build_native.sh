#!/data/data/com.dsharnessmobile.shell/files/usr/bin/bash
#
# 编译四种 ABI 的 native 库（L2 + L3）。
#
# 为什么这么麻烦：
#   termux 的 clang 是 arm64 原生的，交叉编译到别的架构时，
#   它会去链自己目录下的 crtbegin_so.o / libc.so —— 那些都是 arm64 的，
#   直接报 "incompatible with elf_i386" 之类。
#
#   解法：显式用 NDK sysroot 里对应架构的 crt 对象和 libc，
#   完全绕开 termux 自带的那套。
#
# 四种 ABI 都要，因为用户设备不一定是 arm64：
#   arm64-v8a    主流手机
#   armeabi-v7a  老设备/低端机
#   x86 / x86_64 模拟器（很多检测工具自己也跑在模拟器上）
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="$(cd "$ROOT/.." && pwd)"
NDK="$W/android-sdk/ndk/26.3.11579264"
SYS="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
SRC="$ROOT/app/src/main/jni/native_main.c $ROOT/app/src/main/jni/observe_mask.c $ROOT/app/src/main/jni/manual_hook.c"
OUT="$ROOT/build/lib"
MAP="$ROOT/build/export.map"

export PATH=/data/data/com.dsharnessmobile.shell/files/usr/bin:$PATH

mkdir -p "$OUT"

# 只导出 native_init，其余符号全部隐藏。
# 注意 version script 在 32 位下有匹配差异，所以配合 __attribute__((visibility)) 一起用。
cat > "$MAP" <<'EOF'
{
  global:
    native_init;
  local:
    *;
};
EOF

# build <abi目录名> <target> <lib目录> <额外参数...>
build() {
    local abi="$1" target="$2" libdir="$3"; shift 3
    local extra="$*"
    local d="$OUT/$abi"
    mkdir -p "$d"

    # shellcheck disable=SC2086
    clang --target="$target" --sysroot="$SYS" $extra \
        -shared -fPIC -O2 -nostdlib \
        "$SYS/usr/lib/$libdir/21/crtbegin_so.o" \
        "$SYS/usr/lib/$libdir/21/crtend_so.o" \
        -L"$SYS/usr/lib/$libdir/21" \
        -o "$d/libantihook_bypass.so" $SRC -lc -ldl -llog

    # 校验导出符号，缺了就等于 L2/L3 在該架构上失效
    if readelf --dyn-syms "$d/libantihook_bypass.so" | grep -q native_init; then
        echo "    $abi  OK  $(stat -c%s "$d/libantihook_bypass.so") B"
    else
        echo "    $abi  FAIL: native_init 未导出"
        return 1
    fi
}

echo "==> 编译 native（4 个 ABI）"
build arm64-v8a   aarch64-linux-android21        aarch64-linux-android            ""
build armeabi-v7a armv7a-linux-androideabi21    arm-linux-androideabi            "-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16"
build x86         i686-linux-android21          i686-linux-android               "-march=i686"
build x86_64      x86_64-linux-android21        x86_64-linux-android             ""

echo "==> native 全部完成"
