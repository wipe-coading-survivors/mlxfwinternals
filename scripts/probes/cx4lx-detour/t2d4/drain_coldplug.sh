#!/bin/bash
# T2d-4b drain (cable-path, Eth branch, "three cold plugs" protocol):
# IMMEDIATE drain per coordinator priority (stop the ring first, all checks
# after). Owner timeline ends 21:07:27 UTC (+333 s from the post-arm anchor)
# with 100G optics plugged; if that link did not come up, the pre-arm AN
# storm (~360 evt/s) may have kept running -> 512KB ring wrap risk. So:
# verbatim date -u FIRST, window anchors from ev-cable.log (file greps only,
# NO card access, NO mstlink/PTYS pre-drain), then SIGINT the live arm
# (pid from T2d-4a) -> disarm + SET_ITRACE 0 + raw ring dump -> md5.
# Link checks / vfio->mlx5 rebind / ibstat / mstlink deferred to the
# post-drain recovery step (T2d-4b step 5).
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t2d4}
ARM_PID=${ARM_PID:-$(pgrep -f "mlxscope trace arm" | head -1)}
cd "$DIR" || exit 1
TL=timeline.log
ts() { date +%s.%N; }
log() { echo "$1 $(ts)" | tee -a $TL; }

date -u | tee date-u-drain.txt | sed 's/^/DATE_U_DRAIN_START /' | tee -a $TL
log "DRAIN_SCRIPT_START arm_pid=$ARM_PID"
[ -n "$ARM_PID" ] || { log "NO_ARM_PROCESS"; exit 1; }

# 1) window anchors straight from the live ev-log file (no card access)
W0=$(head -1 ev-cable.log | grep -oE "^[0-9]+")
W1=$(tail -1 ev-cable.log | grep -oE "^[0-9]+")
log "EVLOG_WINDOW first=$W0 last=$W1 span_ms=$((W1-W0))"
EV0=$(grep -cE '^[0-9]+ \[0x[0-9a-f?]+\] 0 \[0x' ev-cable.log 2>/dev/null)
MM0=$(grep -cE "module_management|cable_module_read_write" ev-cable.log 2>/dev/null)
HD0=$(grep -c "bw should be less than network speed" ev-cable.log 2>/dev/null)
HA0=$(grep -c "ib_force_edr_fsm: config_tx_sd_set" ev-cable.log 2>/dev/null)
log "PRE_DRAIN evlog_events=$EV0 mm=$MM0 hook_an=$HA0 hook_dec=$HD0"

# 2) drain: SIGINT -> disarm + SET_ITRACE 0 + raw ring dump
kill -INT "$ARM_PID"
i=0
until grep -q "raw ring dump" arm.log 2>/dev/null; do
    i=$((i+1)); [ $i -gt 120 ] && { log "ARM_TEARDOWN_TIMEOUT"; break; }
    sleep 1
done
log "ARM_STOPPED after ${i}s"
grep -aE "SIGINT|disarm readback|SET_ITRACE 0|raw ring dump|done: total_events|drop" arm.log \
    | tail -8 | tr "\r" "\n" | tee -a $TL
pgrep -af "mlxscope trace arm" >/dev/null && log "ARM_STILL_RUNNING" || log "ARM_EXITED"
date -u | sed 's/^/DATE_U_DRAIN_END /' | tee -a $TL
stat -c "%n %s" ring-cable.bin ev-cable.log arm.log $TL date-u-drain.txt 2>/dev/null | tee -a $TL
md5sum ev-cable.log ring-cable.bin arm.log $TL date-u-drain.txt 2>/dev/null | tee md5-run1.txt
log "DRAIN_SCRIPT_END"
