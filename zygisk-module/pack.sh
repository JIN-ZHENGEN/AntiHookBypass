#!/data/data/com.dsharnessmobile.shell/files/usr/bin/bash
# 打成可直接刷入的 Zygisk 模块 zip
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
NAME=antihookbypass_zygisk
OUT="$ROOT/build/$NAME.zip"
mkdir -p "$ROOT/build"
cd "$ROOT/module"
rm -f "$OUT"
export PATH=/data/data/com.dsharnessmobile.shell/files/usr/bin:$PATH
# 先把权限摆正再打包。
#
# 这步不能省：这些文件是从 shell 用户目录（umask 077）来的，
# 直接 zip 会带上 600 权限。KernelSU 安装后 WebUI 由 WebView 以
# 非 root 身份读取，600 会让它读不到，页面直接白屏。
# .so 需要可执行位，其余 644。
find . -type f -name '*.so' -exec chmod 755 {} +
find . -type f ! -name '*.so' -exec chmod 644 {} +
find . -type d -exec chmod 755 {} +

# 排除中间产物与测试页：.preview.html 是带假 KSU 桥的预览页，
# 只用于本地验证渲染，绝不能进交付包
zip -q -r -X "$OUT" . -x '*.o' -x '.preview.html' -x '*.tmp' -x '.DS_Store'
echo "==> $OUT"
unzip -l "$OUT"
