#!/bin/bash
# T1-A run3: driver-bound ip-link admin flap with the stock trace pipeline
# (mstfwtrace mask + driver ftrace drain; B1 precedent). This is the brief's
# original trigger (port admin down/up on the netdev) — impossible in the
# driverless mlxscope window (no netdev), so it runs as a separate window.
set -u
BDF=${BDF:-0000:04:00.0}
NETDEV=${NETDEV:-ibs5}
CA=${CA:-mlx5_2}
DIR=${DIR:-/var/roothome/t1a}
MASK=${MASK:-0x4404c60}
LEVEL=${LEVEL:-0}
DWELL=${DWELL:-10}
SETTLE=${SETTLE:-30}
cd "$DIR" || exit 1
TL=timeline-run3.log
: > $TL
ts() { date +%s.%N; }
log() { echo "$1 $(ts)" | tee -a $TL; }
TR=/sys/kernel/debug/tracing

paos_get_field() {
    timeout 20 mstreg -d $BDF --reg_name PAOS --index "local_port=1" --get 2>/dev/null \
        | awk -v f="$1" '$1==f{print $3}'
}

log "SCRIPT3_START driver=$(readlink /sys/bus/pci/devices/$BDF/driver | xargs basename)"
log "BASELINE admin=$(paos_get_field admin_status) oper=$(paos_get_field oper_status)"
ibstat $CA | sed -n 8,11p | tr '\n' ' ' | sed 's/^/IBSTAT_BASELINE /' | tee -a $TL; echo

# ftrace prepare
mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug
ls $TR/events/ | grep -i mlx5 > ftrace-events.txt 2>&1
FW_EV=$(ls $TR/events/ | grep -iE '^mlx5' | head -1)
echo "$FW_EV" > ftrace-ev-name.txt
log "FTRACE_EVENT_DIR=$FW_EV"
echo 0 > $TR/events/$FW_EV/fw/enable 2>/dev/null
echo > $TR/trace
echo 1 > $TR/events/$FW_EV/fw/enable && log "FTRACE_ENABLED"

# mstfwtrace arm (stock pipeline: driver owns ring)
nohup mstfwtrace -d $BDF -m $MASK -l $LEVEL --ignore_old_events > mft-run3.log 2>&1 &
MFT_PID=$!
log "MFT_SPAWN pid=$MFT_PID"
sleep 6
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER1"

# flap via netdev admin (the brief's trigger)
ip link set $NETDEV down && log "IPLINK_DOWN_SET" || log "IPLINK_DOWN_FAIL"
i=0
while [ "$(paos_get_field oper_status)" != "0x00000002" ] && [ $i -lt 20 ]; do
    i=$((i+1)); sleep 1
done
if [ "$(paos_get_field oper_status)" = "0x00000002" ]; then log "OPER_DOWN after ${i}s"; else log "OPER_STAYED_UP_20s"; fi
sleep $DWELL
ip link set $NETDEV up && log "IPLINK_UP_SET" || log "IPLINK_UP_FAIL"

# link return watch
i=0
while ! ibstat $CA 2>/dev/null | grep -q "State: *Active"; do
    i=$((i+1)); [ $i -gt 90 ] && { log "ACTIVE_TIMEOUT_90s"; break; }
    sleep 1
done
[ $i -le 90 ] && log "ACTIVE_BACK after ${i}s"
sleep $SETTLE

timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER2"
MG=$(timeout 20 mstreg -d $BDF --reg_name MGIR --get 2>/dev/null | grep -i uptime)
log "MGIR $MG"

# collect + restore
cat $TR/trace > ftrace-run3.log
log "FTRACE_LINES=$(wc -l < ftrace-run3.log)"
kill $MFT_PID 2>/dev/null; sleep 2; kill -9 $MFT_PID 2>/dev/null
log "MFT_STOPPED"
timeout 30 mstfwtrace -d $BDF -m 0 -l 0 --ignore_old_events >/dev/null 2>&1
log "MASK_RESTORE_DONE rc=$?"
echo 0 > $TR/events/$FW_EV/fw/enable
echo > $TR/trace
# silence check
sleep 3
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
sleep 12
SIL=$(dmesg | wc -l)
log "SILENCE_FTRACE_LINES=$(cat $TR/trace | wc -l)"
log "FINAL admin=$(paos_get_field admin_status) oper=$(paos_get_field oper_status)"
ibstat $CA | sed -n 8,11p | tr '\n' ' ' | sed 's/^/IBSTAT_FINAL /' | tee -a $TL; echo
md5sum mft-run3.log ftrace-run3.log $TL | tee -a md5.txt
log "SCRIPT3_END"
