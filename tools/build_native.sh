#!/usr/bin/env bash
#
# 编译四种 ABI 的 native 库（L2 + L3）。
# CI（SDK 在仓库根 android-sdk）与手机（SDK 在仓库父目录）双兼容。
#
# 关键：不再手工指定 crtbegin/crtend 路径（旧 NDK 布局与 r26b unified sysroot
# 差异大，且不同 triple 的 crt 目录不同，极易写错导致 "no such file"）。
# 改为交给 clang 用 --target=<triple><api> + --sysroot 自动定位 crt，
# 显式链接 -lc -ldl -llog 即可。-nostdlib 也去掉，避免阻止 clang 放 crt。
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 定位 android-sdk：CI 装在仓库根，手机可能装在仓库父目录，做回退探测。
SDK_ROOT=""
for c in "$ROOT/android-sdk" "$ROOT/../android-sdk" "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}"; do
  [ -n "$c" ] && [ -d "$c/ndk/26.3.11579264" ] && SDK_ROOT="$c" && break
done
[ -z "$SDK_ROOT" ] && SDK_ROOT="$ROOT/android-sdk"

NDK="$SDK_ROOT/ndk/26.3.11579264"
SYS="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
SRC="$ROOT/app/src/main/jni/native_main.c"
OUT="$ROOT/build/lib"
CLANG_BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"

# 将 NDK 工具链加入 PATH（clang / readelf 等）
export PATH="$CLANG_BIN:$PATH"

mkdir -p "$OUT"

build() {
  local abi="$1" target="$2"; shift 2
  local extra="$*"
  local d="$OUT/$abi"
  mkdir -p "$d"

  # shellcheck disable=SC2086
  clang --target="$target" --sysroot="$SYS" $extra \
      -shared -fPIC -O2 -fvisibility=hidden \
      -o "$d/libantihook_bypass.so" "$SRC" -lc -ldl -llog

  if readelf --dyn-syms "$d/libantihook_bypass.so" | grep -q native_init && \
     readelf --dyn-syms "$d/libantihook_bypass.so" | grep -q Java_com_rev_antihookbypass_NativeLayer_nativeSanitizeRuntime; then
    echo "    $abi  OK  $(stat -c%s "$d/libantihook_bypass.so") B"
  else
    echo "    $abi  FAIL: 关键符号未导出"
    return 1
  fi
}

echo "==> SDK_ROOT=$SDK_ROOT  NDK=$NDK"
echo "==> clang: $(command -v clang)"

echo "==> 编译 native（4 个 ABI）"
build arm64-v8a    aarch64-linux-android24    ""
build armeabi-v7a  armv7a-linux-androideabi24 "-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16"
build x86          i686-linux-android24       ""
build x86_64       x86_64-linux-android24     ""

echo "==> native 编译完成"