#!/data/data/com.dsharnessmobile.shell/files/usr/bin/bash
# 编译 Zygisk 版模块（纯 native，不含 APK）
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
# android-sdk 在 workspaces/incoming/ 下，比本仓库高两级
W="$(cd "$ROOT/../.." && pwd)"
NDK="$W/android-sdk/ndk/26.3.11579264"
SYS="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
ENGINE="$(cd "$ROOT/.." && pwd)/app/src/main/jni"
OUT="$ROOT/out"
export PATH=/data/data/com.dsharnessmobile.shell/files/usr/bin:$PATH

[ -d "$SYS" ] || { echo "找不到 NDK sysroot: $SYS"; exit 1; }
mkdir -p "$OUT" "$ROOT/module/zygisk" "$ROOT/module/engine"

build_abi() {
    local abi="$1" target="$2" libdir="$3"
    local d="$OUT/$abi"
    mkdir -p "$d"
    echo "==> $abi ($target)"

    clang --target="$target" --sysroot="$SYS" \
        -O2 -fPIC -fvisibility=hidden -nostdlib \
        -I"$ENGINE" -I"$SYS/usr/include" -I"$SYS/usr/include/$libdir" \
        -c "$ENGINE/native_main.c" -o "$d/native_main.o"

    clang --target="$target" --sysroot="$SYS" \
        -O2 -fPIC -nostdlib \
        -I"$SYS/usr/include" -I"$SYS/usr/include/$libdir" \
        -c "$ROOT/module/jni/engine_glue.c" -o "$d/engine_glue.o"

    clang --target="$target" --sysroot="$SYS" \
        -O2 -fPIC -nostdlib \
        -I"$SYS/usr/include" -I"$SYS/usr/include/$libdir" \
        -c "$ROOT/module/jni/jnihooks.c" -o "$d/jnihooks.o"

    clang++ --target="$target" --sysroot="$SYS" \
        -O2 -fPIC -nostdlib -fno-exceptions -fno-rtti \
        -I"$ROOT/module/jni" -I"$SYS/usr/include" -I"$SYS/usr/include/$libdir" \
        -c "$ROOT/module/jni/module.cpp" -o "$d/module.o"

    # ---- 引擎 .so：业务代码全在这里，可热替换 ----
    mkdir -p "$ROOT/module/engine"
    clang++ --target="$target" --sysroot="$SYS" -shared -fPIC -nostdlib \
        "$SYS/usr/lib/$libdir/21/crtbegin_so.o" \
        "$SYS/usr/lib/$libdir/21/crtend_so.o" \
        -L"$SYS/usr/lib/$libdir/21" \
        -o "$ROOT/module/engine/$abi.so" \
        "$d/module.o" "$d/engine_glue.o" "$d/jnihooks.o" "$d/native_main.o" \
        -lc -ldl -llog

    # ---- 加载器 .so：zygisk 注册 + 把引擎拉起来，逻辑极少 ----
    clang++ --target="$target" --sysroot="$SYS" -shared -fPIC -nostdlib \
        -fno-exceptions -fno-rtti \
        -I"$ROOT/module/jni" -I"$SYS/usr/include" -I"$SYS/usr/include/$libdir" \
        "$SYS/usr/lib/$libdir/21/crtbegin_so.o" \
        "$SYS/usr/lib/$libdir/21/crtend_so.o" \
        -L"$SYS/usr/lib/$libdir/21" \
        -o "$ROOT/module/zygisk/$abi.so" \
        "$ROOT/module/jni/loader.cpp" \
        -lc -ldl -llog

    echo "    引擎 $(stat -c%s "$ROOT/module/engine/$abi.so") B / 加载器 $(stat -c%s "$ROOT/module/zygisk/$abi.so") B"
}

build_abi arm64-v8a   aarch64-linux-android21    aarch64-linux-android
build_abi armeabi-v7a armv7a-linux-androideabi21 arm-linux-androideabi
echo "==> 完成"
ls -la "$ROOT/module/zygisk/"
