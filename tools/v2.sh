#!/system/bin/sh
# 单轮验证：读检测器自己的原始输出（ahb_verdict.json），不做任何改写
PKG=com.cshlolss.antihook.detect
DISP="$1"
P=/proc/1/root/data/data/$PKG/files
su -c "rm -f $P/ahb_verdict.json"
su -c "am force-stop $PKG" 2>/dev/null
sleep 1
su -c "am start --display $DISP -n $PKG/.MainActivity" >/dev/null 2>&1
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do
  sleep 1
  if su -c "test -s $P/ahb_verdict.json" 2>/dev/null; then break; fi
done
su -c "cat $P/ahb_verdict.json" 2>/dev/null
