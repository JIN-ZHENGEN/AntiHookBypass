#!/data/data/com.dsharnessmobile.shell/files/usr/bin/bash
#
# 一键构建 AntiHook Bypass 模块 APK。
#
# 为什么不用 Gradle：
#   Gradle 的原生库是为 glibc Linux 编译的，在 Android(Bionic) 上加载失败
#   （报 libnative-platform.so 加载不了）。所以这里走手工链路：
#     javac → d8 → 自写 AXML → zip → apksigner
#
# 需要：JDK 17、Android SDK（build-tools 里的 d8/apksigner）、clang。
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/data/data/com.dsharnessmobile.shell/files/usr
W="$(cd "$ROOT/.." && pwd)"
SDK="$W/android-sdk"
BT="$SDK/build-tools/34.0.0"
AJ="$SDK/platforms/android-34/android.jar"
XAPI="$W/.libs/xposed-api.jar"

export JAVA_HOME="$PREFIX/lib/jvm/java-17-openjdk"
export PATH="$JAVA_HOME/bin:$PREFIX/bin:$PATH"

OUT="$ROOT/build"
CLS="$OUT/classes"
DEX="$OUT/dex"
STAGE="$OUT/stage"

rm -rf "$OUT"
mkdir -p "$CLS" "$DEX" "$STAGE"

echo "==> [1/6] 编译 Java"
javac --release 8 -nowarn -classpath "$AJ:$XAPI" -d "$CLS" \
    "$ROOT"/app/src/main/java/com/rev/antihookbypass/*.java

echo "==> [2/6] 转 dex"
# 注意：xposed-api 用 --lib 传入（不是打进 dex）。
# LSPosed 运行时自己提供这些类，模块只需要编译期可见。
# 不打进 dex 的好处是包更小，也避免与框架的类冲突（duplicate class）。
"$BT/d8" --release --min-api 21 --lib "$AJ" --lib "$XAPI" \
    --output "$DEX" $(find "$CLS" -name '*.class')

echo "==> [3/6] 编译 native（L2+L3，四种 ABI）"
bash "$ROOT/tools/build_native.sh"
cp -r "$ROOT/build/lib" "$STAGE/lib"

echo "==> [4/6] 生成 AndroidManifest.xml（自写 AXML，绕开 aapt2）"
python3 "$ROOT/tools/make_manifest.py" "$STAGE/AndroidManifest.xml"

echo "==> [5/6] 打包"
cp "$DEX/classes.dex" "$STAGE/classes.dex"
cp -r "$ROOT/app/src/main/assets" "$STAGE/assets"
# native_init 已在 assets/ 里（由上面 cp -r assets 带入）

UNSIGNED="$OUT/unsigned.apk"
rm -f "$UNSIGNED"

# 关键：.so 必须用"不压缩"方式打包。
#   Android 的 System.loadLibrary 只愿意从 APK 里加载 STORED（未压缩）的 so；
#   压缩过的 so 必须先解压到磁盘，而 LSPosed 的模块加载器不做这一步。
#   这也是之前 loadLibrary 一直失败、只能退化到 System.load 绝对路径的原因 ——
#   而走 System.load 就绕开了框架的 native_init 回调，native hook 全废。
(cd "$STAGE" && find . -name "*.so" -print0 | xargs -0 zip -q -X -0 "$UNSIGNED")
# 其余文件正常压缩
(cd "$STAGE" && find . -type f ! -name "*.so" -print0 | xargs -0 zip -q -X "$UNSIGNED")

# 关键：.so 必须页对齐，否则 dlopen 报 "not found"（实际是 mmap offset 不对齐）。
# 官方 zipalign 是 x86 二进制跑不了，用自写脚本代替。
echo "    so 页对齐"
python3 "$ROOT/tools/zipalign_so.py" "$UNSIGNED" "$OUT/aligned.apk" || exit 1
mv "$OUT/aligned.apk" "$UNSIGNED"

echo "==> [6/6] 签名"
# 签名密钥：优先用环境变量里指定的既有密钥库（便于在别的机器上复现同一签名），
# 没有才生成。密钥库一律落在 build/ 下，不进版本库。
if [ -n "${AHB_KEYSTORE:-}" ] && [ -f "$AHB_KEYSTORE" ]; then
    KS="$AHB_KEYSTORE"
    echo "    使用既有密钥库: $KS"
else
    KS="$OUT/release.jks"
    if [ ! -f "$KS" ]; then
        "$JAVA_HOME/bin/keytool" -genkeypair -keystore "$KS" \
            -storepass android -keypass android -alias antihook \
            -keyalg RSA -keysize 2048 -validity 10000 \
            -dname "CN=AntiHook Bypass" >/dev/null 2>&1
    fi
    echo "    使用本地生成密钥库: $KS"
fi

APK="$OUT/AntiHookBypass.apk"
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android \
    --key-pass pass:android --min-sdk-version 21 \
    --out "$APK" "$UNSIGNED"

"$BT/apksigner" verify --min-sdk-version 21 "$APK"

echo ""
echo "==> 完成: $APK"
ls -la "$APK"
