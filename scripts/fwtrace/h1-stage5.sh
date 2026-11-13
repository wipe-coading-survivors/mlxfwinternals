#!/bin/bash
# H1 stage 5: финальный restore (рецепт task-03 C.6) + carrier-проверка + DO-state
set -u
DEV0=0000:81:00.0
DEV1=0000:81:00.1
FTRACE=/sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable
TRACEBUF=/sys/kernel/debug/tracing/trace
TSDB=/sys/kernel/debug/tracing/stats

ts() { date -u +"%H:%M:%S.%3N"; }
log() { echo "[$(ts)] $*"; }

log "=== stage5 start ==="

log "mask 0 (идемпотентно): timeout 12 mstfwtrace -m 0 -l 0"
timeout 12 mstfwtrace -d $DEV1 -m 0 -l 0 > /tmp/fwtrace-h1-final-restore.log 2>&1
log "mask0 rc=$?"

log "carrier-check: ftrace on"
echo 1 > $FTRACE; log "  rc=$? (now=$(cat $FTRACE))"
: > $TRACEBUF; log "buffer clear rc=$?"

log "carrier-check: mstreg GET #1"
mstreg -d $DEV0 --get --reg_name MTRC_CAP > /tmp/h1-final-marker1.log 2>&1
log "  rc=$?"
sleep 2
log "carrier-check: mstreg GET #2"
mstreg -d $DEV0 --get --reg_name MTRC_CAP > /tmp/h1-final-marker2.log 2>&1
log "  rc=$?"
log "carrier-check: sleep 15"
sleep 15
CNT=$(grep -c "mlx5_fw:" $TRACEBUF 2>/dev/null || true)
log "carrier-check: mlx5_fw-событий в буфере = $CNT (ожидание 0)"

log "ftrace off"
echo 0 > $FTRACE; log "  rc=$? (now=$(cat $FTRACE))"
: > $TRACEBUF; log "buffer clear rc=$?"
log "buffer entries: $(grep -E 'entries-(in-buffer|written)' $TSDB 2>/dev/null | head -2 | tr '\n' ' ')"

log "=== final DO-state (read-only) ==="
log "lspci:"; lspci -nns 81:00
for f in 0000:81:00.0 0000:81:00.1; do printf "driver %s: " $f; readlink /sys/bus/pci/devices/$f/driver 2>/dev/null || echo NO-DRIVER; done
ip -br li | grep enp129
ibstat 2>&1 | grep -A6 "CA .mlx5_2." | grep -E "Node GUID|State|Physical|Link layer"
ibstat 2>&1 | grep -A6 "CA .mlx5_3." | grep -E "Node GUID|State|Physical|Link layer"
mstflint -d $DEV0 q 2>&1 | grep -E "FW Version|PSID|Base GUID|Base MAC"
mstfwtrace -v
md5sum /tmp/mlxscope/mlxscope
ls -d /sys/bus/pci/drivers/vfio-pci/0* 2>/dev/null || echo "vfio: none bound"
pgrep -a mstfwtrace || echo "no stray mstfwtrace"
pgrep -a mstflint || echo "no stray mstflint"
log "dmesg tail (mlx5/81:00):"
dmesg | grep -E "mlx5|81:00" | tail -15
log "=== stage5 done ==="
