#!/data/data/com.dsharnessmobile.shell/files/usr/bin/bash
# 安装模块 + 核对 LSPosed 记录的 apk_path 与实际是否一致。
#
# 背景：pm install -r 每次都会新建 /data/app/~~XXX== 目录，而 LSPosed
# 在 modules_config.db 里记的 apk_path 不会跟着变。路径一旦失配，
# LSPosed 静默不加载，日志一行都没有 —— 很容易把"没注入"误判成"修好了"。
#
# 历史做法是往记录路径上建 symlink 或塞一份实体 APK 顶住，**已废弃**：
#   * 重启后 /data/app 下的伪造目录会被系统回收，顶不住；
#   * 它绕过了 LSPosed 自己的状态，属于改系统行为，不是正确做法。
#
# 现在的正确做法是让 LSPosed 自己更新记录，两条路：
#   1. 用户在 LSPosed 界面里把模块开关关掉再打开（最稳）；
#   2. 重启设备（系统会重新扫描所有模块路径）。
# 本脚本只负责核对并把结论说清楚，不替用户做决定。
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG=com.rev.antihookbypass
APK="$ROOT/build/AntiHookBypass.apk"
TARGET="${1:-}"

ACT=$(su -c "pm path $PKG" 2>/dev/null | tr -d '\r' | sed 's/package://' | head -1)
echo "实装路径: $ACT"
echo "本地 sha256: $(sha256sum "$APK" | awk '{print $1}')"

su -c "cp /data/adb/lspd/config/modules_config.db /data/local/tmp/_mc.db" 2>/dev/null
su -c "cat /data/local/tmp/_mc.db" > "$ROOT/_mc.db" 2>/dev/null
REC=$(python3 - "$ROOT/_mc.db" <<'PY'
import sqlite3,sys
try:
    c=sqlite3.connect(sys.argv[1])
    r=c.execute("select apk_path from modules where module_pkg_name like '%antihookbypass%'").fetchone()
    print(r[0] if r else '')
except Exception: pass
PY
)
rm -f "$ROOT/_mc.db"
echo "LSPosed 记录: ${REC:-<未找到>}"

if [ "$ACT" = "$REC" ]; then
  echo ">>> 路径一致，模块可被正常加载"
else
  echo ">>> 路径失配，LSPosed 不会加载本模块"
  echo "    需要你在 LSPosed 界面把模块开关关掉再打开一次（或重启设备）"
  echo "    在此之前所有'没崩'的结论都不成立"
  exit 2
fi

if [ -n "$TARGET" ]; then
  su -c "logcat -c"
  su -c "am force-stop $TARGET"
  sleep 1
  su -c "am start --user 0 --display ${AHB_DISPLAY:?需要设置 AHB_DISPLAY=虚拟屏id} -n $TARGET/.MainActivity" >/dev/null 2>&1
  sleep 6
  N=$(su -c "logcat -d 2>/dev/null" | grep -ac AntiHookBypass)
  echo "注入日志行数 = $N"
  if [ "$N" -eq 0 ]; then echo ">>> 警告：未被注入，此时任何结论都无效"; exit 1; fi
  echo ">>> 注入确认"
fi
