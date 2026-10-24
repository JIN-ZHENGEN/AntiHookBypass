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
zip -q -r -X "$OUT" . -x '*.o'
echo "==> $OUT"
unzip -l "$OUT"
