#!/system/bin/sh
# 单轮验证：必须确认进程真的起来了，否则不出结论
PKG=com.cshlolss.antihook.detect
DISP="$1"
LOG=/proc/1/root/data/data/$PKG/files/ahb_native.log
NLOG=$(su -c "ls -t /data/adb/lspd/log/modules_*.log|head -1"|tr -d '\r')

su -c "am force-stop $PKG" 2>/dev/null
sleep 1
su -c "rm -f $LOG" 2>/dev/null
su -c "am start --display $DISP -n $PKG/.MainActivity" >/dev/null 2>&1
sleep 15
PID=$(su -c "pidof $PKG"|tr -d '\r')
if [ -z "$PID" ]; then
  echo "FAIL_START pid 为空，display=$DISP 可能已失效"
  exit 1
fi
echo "pid=$PID"
su -c "grep -a 'VERDICT' $NLOG 2>/dev/null | tail -2" | grep -oE '检测到 [0-9]+ 个|当前 [0-9]+ 个|链表结构校验失败' | tail -1
su -c "grep -a 'VERDICT' $NLOG 2>/dev/null | tail -2" | grep -oE '"id":"native_[a-z_]+","[^}]*"status":"[A-Z]+"' | sed 's/,"title.*"status"/ => /' | tail -6
