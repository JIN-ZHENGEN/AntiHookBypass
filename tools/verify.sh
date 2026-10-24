#!/system/bin/sh
# 单轮验证：必须确认进程真的起来了，否则不出结论。
# 关键改动：用「行号偏移」过滤本轮新增日志，绝不读到上一轮的旧 VERDICT。
PKG=com.cshlolss.antihook.detect
DISP="$1"
NLOG=$(su -c "ls -t /data/adb/lspd/log/modules_*.log|head -1"|tr -d '\r')

su -c "am force-stop $PKG" 2>/dev/null
sleep 1
BEFORE=$(su -c "wc -l < $NLOG"|tr -d '\r ')
su -c "am start --display $DISP -n $PKG/.MainActivity" >/dev/null 2>&1
sleep 15
PID=$(su -c "pidof $PKG"|tr -d '\r')
if [ -z "$PID" ]; then
  echo "FAIL_START pid 为空，display=$DISP 可能已失效"
  exit 1
fi
AFTER=$(su -c "wc -l < $NLOG"|tr -d '\r ')
echo "pid=$PID  本轮新增日志行=$((AFTER - BEFORE))"
su -c "tail -n +$((BEFORE+1)) $NLOG > /data/local/tmp/cur.log" 2>/dev/null
FRESH=$(su -c "grep -ac 'VERDICT' /data/local/tmp/cur.log"|tr -d '\r')
echo "本轮 VERDICT 行数=$FRESH（0 表示结果层没命中）"
su -c "grep -a 'VERDICT' /data/local/tmp/cur.log | tail -2" \
  | grep -oE '检测到 [0-9]+ 个|当前 [0-9]+ 个|链表结构校验失败' | tail -1
su -c "grep -a 'VERDICT' /data/local/tmp/cur.log | tail -2" \
  | grep -oE '"id":"native_[a-z_]+","[^}]*"status":"[A-Z]+"' | sed 's/,"title.*"status"/ => /' | tail -6
su -c "grep -aE '结果层|归一化' /data/local/tmp/cur.log | tail -3" | sed 's/.*AntiHookBypass\] //'
