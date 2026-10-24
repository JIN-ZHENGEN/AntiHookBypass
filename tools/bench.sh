#!/system/bin/sh
# 真实检测耗时：从拉起应用到 VERDICT 首次出现，逐轮测量
PKG=com.cshlolss.antihook.detect
DISP="$1"
N=$(su -c "ls -t /data/adb/lspd/log/modules_*.log|head -1"|tr -d '\r')
su -c "am force-stop $PKG" 2>/dev/null; sleep 1
B=$(su -c "wc -l < $N"|tr -d '\r ')
T0=$(su -c "date +%s%3N"|tr -d '\r')
su -c "am start --display $DISP -n $PKG/.MainActivity" >/dev/null 2>&1
i=0
while [ $i -lt 200 ]; do
  if su -c "tail -n +$((B+1)) $N" 2>/dev/null | grep -aq 'VERDICT-AFTER'; then break; fi
  sleep 0.1
  i=$((i+1))
done
T1=$(su -c "date +%s%3N"|tr -d '\r')
echo "$((T1 - T0))"
