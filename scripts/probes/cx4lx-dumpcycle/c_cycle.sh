#!/bin/bash
# R-A3/R-A4 Task 3: C-cycle = arm -> seed -> readback -> trigger -> drain -> parse
# (order pinned by plan Task 3 Step 4; arm EVERY cycle - drain disarms).
set -u
ADDR=$1
TAG=$2
BDF=0000:04:00.0
cd /root/ra3 || exit 1
TL=cycle-$TAG.log
: > $TL
ts() { date +%s.%N; }
log() { echo "$1 $(ts)" | tee -a $TL; }

nohup /root/mlxscope trace arm -d $BDF --no-flr --mask 0x4000000 -l 1 \
  --out /root/ra3/ev-$TAG.log --raw-out /root/ra3/ring-$TAG.bin \
  --image /root/cx4lx-dump-ra3c.bin > /root/ra3/arm-$TAG.log 2>&1 < /dev/null &
ARM_PID=$!
log "ARM_SPAWN pid=$ARM_PID addr=$ADDR"
i=0
until grep -q "SET_ITRACE done" /root/ra3/arm-$TAG.log 2>/dev/null; do
  i=$((i+1)); [ $i -gt 40 ] && { log ARM_TIMEOUT; kill -9 $ARM_PID; exit 1; }
  sleep 0.25
done
log "ARM_DONE"
sleep 5
/root/mlxscope dump seed --addr $ADDR 2>&1 | tee -a $TL
log "SEEDED"
/root/mlxscope dump read 2>&1 | tee -a $TL
log "READBACK"
/root/mlxscope dump trigger 2>&1 | tee -a $TL
log "TRIGGERED"
sleep 2
kill -INT $ARM_PID
wait $ARM_PID 2>/dev/null
log "DRAINED"
echo "--- our events (ev-$TAG.log):" | tee -a $TL
grep -E "var6=0x|rt=0x00aeb83b" /root/ra3/ev-$TAG.log | tee -a $TL
log "CYCLE_END"
