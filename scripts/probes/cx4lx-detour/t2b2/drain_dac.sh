#!/bin/bash
# T2b-2b drain: read-only link snapshot BEFORE any teardown, final marker +
# MGIR, then SIGINT the live arm process (pid from T2b-2a) -> disarm +
# mask 0 + raw ring dump. Physical setup: QDR AOC our-card <->
# InfiniScale-IV switch, link expected LinkUp QDR (phase-A topology, owner
# replugged DAC->AOC while armed). Hook counters recorded pre-drain
# (H-AN marker 0x00ae58cd string / H-DEC marker 0x00ad7547 string).
# Ring 512KB, arm polls every 100 ms into ev-dac.log: overflow check =
# ev-log event count vs raw ring records at drain time.
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t2b2}
ARM_PID=${ARM_PID:-$(pgrep -f "mlxscope trace arm" | head -1)}
cd "$DIR" || exit 1
TL=timeline.log
ts() { date +%s.%N; }
log() { echo "$1 $(ts)" | tee -a $TL; }

log "DRAIN_SCRIPT_START arm_pid=$ARM_PID"
[ -n "$ARM_PID" ] || { log "NO_ARM_PROCESS"; exit 1; }

# 1) phase anchors: wall of first AN / first hook line in the ev log
FIRST_AN=$(grep -m1 -oE "^[0-9]+" <(grep -m1 -E "ib_speed_nego" ev-dac.log) 2>/dev/null)
log "FIRST_AN_WALL=$FIRST_AN"
FIRST_HA=$(grep -m1 -oE "^[0-9]+" <(grep -m1 "ib_force_edr_fsm: config_tx_sd_set" ev-dac.log) 2>/dev/null)
log "FIRST_HOOK_AN_WALL=$FIRST_HA"
FIRST_HD=$(grep -m1 -oE "^[0-9]+" <(grep -m1 "bw should be less than network speed" ev-dac.log) 2>/dev/null)
log "FIRST_HOOK_DEC_WALL=$FIRST_HD"
FIRST_CNF=$(grep -m1 -oE "^[0-9]+" <(grep -m1 "cnf_test" ev-dac.log) 2>/dev/null)
log "FIRST_CNF_TEST_WALL=$FIRST_CNF"

# 2) link state BEFORE any change (read-only; the mstlink burst will show up
# in the trace as a tool-triggered MM/pddr burst — same as T1/T2b-1, mark it)
log "LINK_SNAPSHOT_LOCAL_BEGIN"
timeout 30 mstlink -d $BDF > link-local-before-drain.txt 2>&1
grep -aE "State|Physical state|Speed|Width|Enabled Link|Supported Cable|Status Opcode|Recommendation" \
    link-local-before-drain.txt | tee -a $TL
timeout 20 mstreg -d $BDF --reg_name PTYS --index "local_port=1,proto_mask=0x1" --get 2>/dev/null \
    | grep -E "ib_proto_(capab|admin|oper)|data_rate_oper" | tee -a $TL
timeout 20 mstreg -d $BDF --reg_name PAOS --index "local_port=1" --get 2>/dev/null \
    | grep -E "admin_status|oper_status" | tee -a $TL
log "LINK_SNAPSHOT_LOCAL_END"

# 3) final marker + MGIR, then drain (SIGINT: disarm + SET_ITRACE 0 + raw dump)
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER_FINAL"
MG=$(timeout 20 mstreg -d $BDF --reg_name MGIR --get 2>/dev/null | grep -i uptime)
log "MGIR_END $MG"
EV0=$(grep -cE '^[0-9]+ \[0x[0-9a-f?]+\] 0 \[0x' ev-dac.log)
AN0=$(grep -cE "ib_speed_nego_fsm|init_ib_an_fsm" ev-dac.log)
HA0=$(grep -c "ib_force_edr_fsm: config_tx_sd_set" ev-dac.log)
HD0=$(grep -c "bw should be less than network speed" ev-dac.log)
log "PRE_DRAIN events=$EV0 an=$AN0 hook_an=$HA0 hook_dec=$HD0"
kill -INT "$ARM_PID"
i=0
until grep -q "raw ring dump" arm.log 2>/dev/null; do
    i=$((i+1)); [ $i -gt 60 ] && { log "ARM_TEARDOWN_TIMEOUT"; break; }
    sleep 1
done
log "ARM_STOPPED after ${i}s"
grep -aE "SIGINT|disarm readback|SET_ITRACE 0|raw ring dump|done: total_events|drop" arm.log \
    | tail -6 | tr "\r" "\n" | tee -a $TL
pgrep -af "mlxscope trace arm" >/dev/null && log "ARM_STILL_RUNNING" || log "ARM_EXITED"
stat -c "%n %s" ring-dac.bin ev-dac.log arm.log $TL 2>/dev/null | tee -a $TL
md5sum ev-dac.log ring-dac.bin arm.log $TL 2>/dev/null | tee md5-run1.txt
log "DRAIN_SCRIPT_END"
