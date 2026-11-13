#!/bin/bash
# H1 stage 3 part 1: sanity — re-apply маски БЕЗ VFIO-окна, маркеры ×3
# usage: h1-stage3-sanity.sh [LOG]   (default /tmp/fwtrace-h1-post.log)
set -u
DEV0=0000:81:00.0
DEV1=0000:81:00.1
LOG=${1:-/tmp/fwtrace-h1-post.log}
FTRACE=/sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable
TRACEBUF=/sys/kernel/debug/tracing/trace

ts() { date -u +"%H:%M:%S.%3N"; }
log() { echo "[$(ts)] $*"; }
marker() {
  log "marker $1: mstreg GET MTRC_CAP ($DEV0)"
  mstreg -d $DEV0 --get --reg_name MTRC_CAP > $LOG.marker-$1.log 2>&1
  log "marker $1 rc=$?"
}
on_exit() { wait 2>/dev/null; }
trap on_exit EXIT

log "=== stage3-sanity start (log=$LOG) ==="
echo 1 > $FTRACE; log "ftrace on rc=$? (now=$(cat $FTRACE))"

timeout 60 mstfwtrace -d $DEV1 -m ICMD -l 1 --ignore_old_events > $LOG 2>&1 &
TPID=$!
log "mstfwtrace started pid=$TPID (timeout 60)"
sleep 5
log "liveness head($LOG):"
head -5 $LOG
if ! head -20 $LOG | grep -q "Read new events"; then
  log "LIVENESS GATE FAILED — aborting"
  exit 1
fi
log "liveness OK"

marker p1
sleep 2
marker p2
sleep 2
marker p3

log "waiting for trace pid=$TPID ..."
wait $TPID
log "trace rc=$?"

log "=== stage3-sanity results ==="
log "icmd_generic_reg_access: $(grep -c icmd_generic_reg_access $LOG)"
log "total events: $(grep -cE '^\[0x' $LOG)"
grep -E '^\[0x' $LOG | head -40

log "=== restore: mask 0, ftrace off, clear ==="
timeout 12 mstfwtrace -d $DEV1 -m 0 -l 0 > $LOG.restore.log 2>&1
log "mask0 rc=$?"
echo 0 > $FTRACE; log "ftrace off rc=$? (now=$(cat $FTRACE))"
: > $TRACEBUF; log "buffer clear rc=$?"
log "=== stage3-sanity done ==="
