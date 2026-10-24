#!/system/bin/sh
# 对比目标进程内 libart r-x 段与磁盘文件，统计不同字节数
PKG=com.cshlolss.antihook.detect
PID=$(su -c "pidof $PKG"|tr -d '\r')
[ -z "$PID" ] && { echo "NO_PID"; exit 1; }
LINE=$(su -c "grep 'libart.so' /proc/$PID/maps | grep 'r-xp' | head -1"|tr -d '\r')
[ -z "$LINE" ] && { echo "NO_SEG"; exit 1; }
S=$(echo "$LINE"|cut -d- -f1); REST=$(echo "$LINE"|cut -d- -f2)
E=$(echo "$REST"|cut -d' ' -f1); OFF=$(echo "$REST"|awk '{print $3}')
PATHF=$(echo "$LINE"|awk '{print $NF}')
START=$((0x$S)); END=$((0x$E)); LEN=$((END-START)); OFFD=$((0x$OFF))
su -c "dd if=/proc/$PID/mem of=/data/local/tmp/memseg bs=1 skip=$START count=$LEN 2>/dev/null"
su -c "dd if=$PATHF of=/data/local/tmp/disseg bs=1 skip=$OFFD count=$LEN 2>/dev/null"
echo "段长=$LEN"
cmp -l /data/local/tmp/memseg /data/local/tmp/disseg 2>/dev/null | wc -l
