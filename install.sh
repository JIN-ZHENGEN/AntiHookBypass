#!/data/data/com.dsharnessmobile.shell/files/usr/bin/bash
# 安装 + 修 LSPosed 路径 + 校验 so 版本，一步到位。
#
# 三个坑都在这里堵住：
#  1) pm install -r 每次新建 /data/app/~~XXX== 目录，LSPosed 记录的
#     apk_path 不跟着变 -> 模块静默不加载。
#     修法：在记录路径上建**目录软链**指向新安装目录（不是文件软链，
#     文件软链会导致 lib/ 下的 so 找不到）。
#  2) 直接覆盖 base.apk 不会重新解包 lib/arm64/*.so，
#     系统加载的是旧 so —— 这会让人误以为改了代码没生效。
#     所以必须走 pm install。
#  3) 装完必须核对"APK 内 so" == "解包 so" == "本地构建 so"。
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
APK="$ROOT/build/AntiHookBypass.apk"
PKG=com.rev.antihookbypass
FAKEROOT="/data/app/~~VbK28CCSlaL1URUjSjtFng=="
FAKEPKG="$FAKEROOT/$PKG-ktdPgz65opOuXMvZN_Mbdw=="

su -c "pm install -r '$APK'" | tail -1
sleep 2
ACT=$(su -c "pm path $PKG" | tr -d '\r' | sed 's/package://' | head -1)
REALPKG=$(dirname "$ACT")

su -c "rm -rf '$FAKEPKG'"
su -c "mkdir -p '$FAKEROOT'"
su -c "ln -sfn '$REALPKG' '$FAKEPKG'"

L1=$(sha256sum "$ROOT/build/lib/arm64-v8a/libantihook_bypass.so" | awk '{print $1}')
L2=$(su -c "sha256sum '$FAKEPKG/lib/arm64/libantihook_bypass.so'" 2>/dev/null | awk '{print $1}')
echo "本地 so : $L1"
echo "解包 so : $L2"
if [ "$L1" != "$L2" ]; then echo ">>> so 不一致，改的 native 代码没生效"; exit 1; fi
echo ">>> 就绪"
