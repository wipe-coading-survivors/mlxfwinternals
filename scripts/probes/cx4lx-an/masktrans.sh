#!/bin/bash
set -u
D=/tmp/cx4lxan
TFS=/sys/kernel/debug/tracing
run_phase(){
  local MASK=$1
  local LVL=$2
  local N=$3
  local NAME=$4
  local LOG=$D/mt-$NAME.log
  nohup timeout $((N*4+30)) mstfwtrace -d 41:00.0 -m $MASK -l $LVL --ignore_old_events > $LOG 2>&1 &
  MP=$!
  sleep 2
  for i in $(seq 1 $N); do
    T0=$(date +%s.%N); mstreg -d 41:00.1 --reg_name MTRC_CAP --get --yes </dev/null >/dev/null 2>&1; T1=$(date +%s.%N)
    echo "$T0 $T1 mt-$NAME-$i" >> $D/mt-markers.txt
    sleep 3
  done
  sleep 4
  echo "mt-$NAME icmd=$(grep -c icmd_generic_reg_access $LOG || true) lines=$(wc -l < $LOG) lost=$(grep -c "Events were lost" $LOG || true)" >> $D/mt-markers.txt
  kill $MP 2>/dev/null; wait $MP 2>/dev/null
  sleep 2
}
echo 1 > $TFS/events/mlx5/mlx5_fw/enable
run_phase 0x4000000 1 10 A-4000000-l1
run_phase 0x4000C40 0 6  B-4000c40-l0
run_phase 0x4400C40 0 6  C-4400c40-l0
timeout 12 mstfwtrace -d 41:00.0 -m 0 -l 0 > $D/mt-restore.log 2>&1
echo 0 > $TFS/events/mlx5/mlx5_fw/enable
echo "MT-DONE $(date +%s.%N)" >> $D/mt-markers.txt
