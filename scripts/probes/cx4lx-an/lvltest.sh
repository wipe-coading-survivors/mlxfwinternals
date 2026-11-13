#!/bin/bash
set -u
D=/tmp/cx4lxan; TFS=/sys/kernel/debug/tracing
lvl_phase(){
  local LVL=$1 NAME=$2
  local LOG=$D/lvl-$NAME.log
  nohup timeout 55 mstfwtrace -d 41:00.0 -m 0x4400C40 -l $LVL --ignore_old_events > $LOG 2>&1 &
  local MP=$!
  sleep 2
  local T0=$(date +%s.%N); mstreg -d 41:00.1 --reg_name MTRC_CAP --get --yes </dev/null >/dev/null 2>&1; echo "$T0 $(date +%s.%N) lvl-$NAME-marker" >> $D/lvl-markers.txt
  sleep 3
  mstlink -d 41:00.1 > $D/lvl-$NAME-kick.txt 2>&1
  sleep 8
  echo "lvl-$NAME mtrc9040=$(grep -c 0x9040 $LOG || true) pddr5031=$(grep -c 0x5031 $LOG || true) nego=$(grep -c ib_speed_nego $LOG || true) lines=$(wc -l < $LOG)" >> $D/lvl-markers.txt
  kill $MP 2>/dev/null; wait $MP 2>/dev/null; sleep 2
}
echo 1 > $TFS/events/mlx5/mlx5_fw/enable
lvl_phase 1 L1
lvl_phase 0 L0
timeout 12 mstfwtrace -d 41:00.0 -m 0 -l 0 > $D/lvl-restore.log 2>&1
echo 0 > $TFS/events/mlx5/mlx5_fw/enable
echo "LVL-DONE $(date +%s.%N)" >> $D/lvl-markers.txt
