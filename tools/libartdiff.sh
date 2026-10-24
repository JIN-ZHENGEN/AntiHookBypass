#!/system/bin/sh
# /proc/<pid>/mem 必须按字节读（bs=4096 会读成全零）
PID="$1"
L=$(grep '/libart.so' /proc/$PID/maps | grep ' r-xp ' | head -1)
[ -z "$L" ] && { echo NO_SEG; exit 1; }
S=$(echo "$L" | cut -d- -f1)
E=$(echo "$L" | cut -d- -f2 | cut -d' ' -f1)
OFF=$(echo "$L" | awk '{print $3}')
P=$(echo "$L" | awk '{print $6}')
ST=$((16#$S)); EN=$((16#$E)); LN=$((EN-ST)); OD=$((16#$OFF))
echo "seg=$S-$E off=$OFF len=$LN"
dd if=/proc/$PID/mem of=/data/local/tmp/m.bin bs=1 skip=$ST count=$LN 2>/dev/null
dd if="$P" of=/data/local/tmp/d.bin bs=1 skip=$OD count=$LN 2>/dev/null
echo -n "memsize="; wc -c < /data/local/tmp/m.bin
echo -n "diff_bytes="
cmp -l /data/local/tmp/m.bin /data/local/tmp/d.bin 2>/dev/null | wc -l
