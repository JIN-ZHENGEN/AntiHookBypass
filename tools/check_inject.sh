#!/data/data/com.dsharnessmobile.shell/files/usr/bin/bash
# 判定模块是否真的注入到目标进程。
#
# 为什么不能只看 logcat：LSPosed 把模块日志写在自己的
# /data/adb/lspd/log/modules_*.log 里，转发到 logcat 受等级配置影响，
# 默认可能一行都看不到。用 logcat 行数判断注入会得出错误的"没注入"。
#
# 本脚本按可信度从高到低用三个独立证据：
#   1. /proc/<pid>/maps 里有我们的 so（最硬，进程级）
#   2. LSPosed 的 modules 日志里有 (包名)[com.rev.antihookbypass...] 行
#   3. logcat 里的模块 tag（最弱，仅参考）
set -u
echo "判定以 LSPosed 自己的 modules 日志为准；logcat 与 maps 都会被遮蔽或漏采，只能作参考。"
TARGET="${1:-com.zhenxi.hunter}"

echo "=== 0) 先确认这轮有没有真的起过进程 ==="
echo "  当前 $TARGET 进程: $(su -c "pidof $TARGET" 2>/dev/null | tr -d '\r' | tr ' ' ',')"

echo "=== 1) 进程级证据（maps，注意会被自过滤遮蔽） ==="
FOUND=0
for P in $(su -c "pidof $TARGET" 2>/dev/null | tr -d '\r'); do
  N=$(su -c "grep -c antihookbypass /proc/$P/maps 2>/dev/null" | tr -d '\r')
  CMD=$(su -c "cat /proc/$P/cmdline 2>/dev/null" | tr -d '\0')
  echo "  pid=$P so=$N  $CMD"
  L=$(su -c "grep -cE 'liblspd|lsplant|lsposed' /proc/$P/maps 2>/dev/null" | tr -d '\r')
  echo "     lspd/lsplant 映射数=${L:-0}（这一项其实也受我们的过滤影响，仅参考）"
  [ "${N:-0}" -gt 0 ] && FOUND=1
done
if [ "$FOUND" -eq 0 ]; then
  echo "  （maps 里没看到我们的 so —— 但不要据此判定未注入）"
fi

echo "=== 2) LSPosed 模块日志（最近 6 分钟） ==="
LATEST=$(su -c "ls -t /data/adb/lspd/log/modules_*.log 2>/dev/null" | tr -d '\r' | head -1)
if [ -n "$LATEST" ]; then
  su -c "grep -a '$TARGET' '$LATEST' 2>/dev/null" | grep -a antihookbypass | tail -3 | cut -c1-155
  N=$(su -c "grep -a '$TARGET' '$LATEST' 2>/dev/null" | grep -ac antihookbypass)
  echo "  命中行数 = ${N:-0}"
else
  echo "  （找不到 LSPosed 日志）"
fi

echo "=== 3) logcat（最弱证据） ==="
echo "  AntiHookBypass 行数 = $(su -c "logcat -d 2>/dev/null" | grep -ac AntiHookBypass)"
