#!/bin/bash
# H1 stage 2: VFIO-окно БЕЗ re-apply — репродукция тишины ПОСЛЕ FLR
# usage: h1-stage2.sh [LOG]   (default /tmp/fwtrace-h1-pre.log)
set -u
DEV0=0000:81:00.0
DEV1=0000:81:00.1
IFACE=enp129s0f0np0
PROBE=/tmp/mlxscope/mlxscope
HEX=093200000000000000000000000400000001533200600001258c53326c04638afd001825
LOG=${1:-/tmp/fwtrace-h1-pre.log}
PROBELOG=$LOG.probe.log
FTRACE=/sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable
TRACEBUF=/sys/kernel/debug/tracing/trace

ts() { date -u +"%H:%M:%S.%3N"; }
log() { echo "[$(ts)] $*"; }
marker() {
  log "marker $1: mstreg GET MTRC_CAP ($DEV0)"
  mstreg -d $DEV0 --get --reg_name MTRC_CAP > $LOG.marker-$1.log 2>&1
  log "marker $1 rc=$?"
}
close_window() {
  log "close: unbind vfio-pci $DEV0"
  echo $DEV0 > /sys/bus/pci/drivers/vfio-pci/unbind 2>&1; log "  rc=$?"
  log "close: bind mlx5_core $DEV0"
  echo $DEV0 > /sys/bus/pci/drivers/mlx5_core/bind 2>&1; log "  rc=$?"
  log "close: remove_id 15b3 1019"
  echo "15b3 1019" > /sys/bus/pci/drivers/vfio-pci/remove_id 2>&1; log "  rc=$?"
  log "close: ip link set $IFACE up"
  ip link set $IFACE up 2>&1; log "  rc=$?"
}
IN_WINDOW=0
on_exit() {
  if [ "$IN_WINDOW" = "1" ]; then
    log "TRAP: window open at exit — rebinding"
    close_window
    IN_WINDOW=0
  fi
  wait 2>/dev/null
  log "on_exit: children done"
}
trap on_exit EXIT

log "=== stage2 start (log=$LOG) ==="
log "ftrace enable=1"
echo 1 > $FTRACE; log "  rc=$? (now=$(cat $FTRACE))"

timeout 120 mstfwtrace -d $DEV1 -m ICMD -l 1 --ignore_old_events > $LOG 2>&1 &
TPID=$!
log "mstfwtrace started pid=$TPID (timeout 120, ICMD, l1, owner $DEV1)"
sleep 5
log "liveness head($LOG):"
head -5 $LOG
if ! head -20 $LOG | grep -q "Read new events"; then
  log "LIVENESS GATE FAILED — trace dead, aborting BEFORE window"
  exit 1
fi
log "liveness OK"

marker before

log "=== VFIO window open ==="
log "ip link set $IFACE down"
ip link set $IFACE down 2>&1; log "  rc=$?"
log "modprobe vfio-pci"
modprobe vfio-pci 2>&1; log "  rc=$?"
log "new_id 15b3 1019"
echo "15b3 1019" > /sys/bus/pci/drivers/vfio-pci/new_id 2>&1; log "  rc=$?"
log "unbind mlx5_core $DEV0"
echo $DEV0 > /sys/bus/pci/drivers/mlx5_core/unbind 2>&1; log "  rc=$?"
log "bind vfio-pci $DEV0"
echo $DEV0 > /sys/bus/pci/drivers/vfio-pci/bind 2>&1; log "  rc=$?"
IN_WINDOW=1

log "=== probe (mlxscope mode B, B_F40) ==="
$PROBE --device /sys/bus/pci/devices/$DEV0 --detour-mode B --input-hex $HEX > $PROBELOG 2>&1
log "probe rc=$?"
cat $PROBELOG

log "=== VFIO window close ==="
close_window
IN_WINDOW=0

marker after1
sleep 2
marker after2

log "waiting for trace pid=$TPID ..."
wait $TPID
log "trace rc=$?"

log "=== stage2 results ==="
log "icmd_generic_reg_access: $(grep -c icmd_generic_reg_access $LOG)"
log "total events: $(grep -cE '^\[0x' $LOG)"
grep -E '^\[0x' $LOG | head -40

log "=== stage2 restore-intermediate: mask 0, ftrace off, clear ==="
timeout 12 mstfwtrace -d $DEV1 -m 0 -l 0 > $LOG.restore.log 2>&1
log "mask0 rc=$?"
echo 0 > $FTRACE; log "ftrace off rc=$? (now=$(cat $FTRACE))"
: > $TRACEBUF; log "buffer clear rc=$?"
log "=== stage2 done ==="
