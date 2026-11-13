#!/bin/bash
# T2d-2 drain (cable-path, Eth branch): read-only Eth link snapshot BEFORE
# any teardown (mstlink driverless: did the link come up vs the multi-rate
# Eth switch? 40G?), final liveness marker + MGIR, then SIGINT the live arm
# process (pid from T2d-1) -> disarm + SET_ITRACE 0 + raw ring dump.
# Physical setup (done by the owner while armed): AOC re-plugged THREE times
# on our side (out of the card and back), far end moved from the
# InfiniScale-IV IB switch into the multi-rate Eth switch. Storm background
# ~224 evt/s (Eth-AN retry vs IB switch earlier); ev-log starts at t0_arm
# (window check = first vs last wall ms), ring-loss check = arm.log
# total_events vs ev-log event lines.
# Hook strings (stock table ids): H-AN marker 0x00ae58cd =
# "ib_force_edr_fsm: config_tx_sd_set", H-DEC marker 0x00ad7547 =
# "bw should be less than network speed".
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t2d}
ARM_PID=${ARM_PID:-$(pgrep -f "mlxscope trace arm" | head -1)}
cd "$DIR" || exit 1
TL=timeline.log
ts() { date +%s.%N; }
log() { echo "$1 $(ts)" | tee -a $TL; }

ev_count() { grep -cE '^[0-9]+ \[0x[0-9a-f?]+\] 0 \[0x' ev-dac.log 2>/dev/null; }
an_eth_count()  { grep -c "eth_speed_nego" ev-dac.log 2>/dev/null; }
mm_count()      { grep -cE "module_management|cable_module_read_write|TEMPERATURE|isr_mng2core|scl|sda" ev-dac.log 2>/dev/null; }
icmd_count()    { grep -cE "isr_icmd|icmd_generic" ev-dac.log 2>/dev/null; }
kr_count()      { grep -c "kr_startup" ev-dac.log 2>/dev/null; }
conn_count()    { grep -c "get_connector_type" ev-dac.log 2>/dev/null; }
pdet_count()    { grep -c "parallel_detect" ev-dac.log 2>/dev/null; }
hook_an_count() { grep -c "ib_force_edr_fsm: config_tx_sd_set" ev-dac.log 2>/dev/null; }
hook_dec_count() { grep -c "bw should be less than network speed" ev-dac.log 2>/dev/null; }

log "DRAIN_SCRIPT_START arm_pid=$ARM_PID"
[ -n "$ARM_PID" ] || { log "NO_ARM_PROCESS"; exit 1; }

# 1) window anchors: first/last event wall ms (ring-wrap check) + phase
# anchors: first MM detect / connector / kr / hook lines
W0=$(head -1 ev-dac.log | grep -oE "^[0-9]+")
W1=$(tail -1 ev-dac.log | grep -oE "^[0-9]+")
log "EVLOG_WINDOW first=$W0 last=$W1 span_ms=$((W1-W0))"
FIRST_MM=$(grep -m1 -oE "^[0-9]+" <(grep -m1 -E "module_management" ev-dac.log) 2>/dev/null)
log "FIRST_MM_WALL=$FIRST_MM"
FIRST_CN=$(grep -m1 -oE "^[0-9]+" <(grep -m1 "get_connector_type" ev-dac.log) 2>/dev/null)
log "FIRST_CONNECTOR_WALL=$FIRST_CN"
FIRST_KR=$(grep -m1 -oE "^[0-9]+" <(grep -m1 "kr_startup" ev-dac.log) 2>/dev/null)
log "FIRST_KR_WALL=$FIRST_KR"
FIRST_HD=$(grep -m1 -oE "^[0-9]+" <(grep -m1 "bw should be less than network speed" ev-dac.log) 2>/dev/null)
log "FIRST_HOOK_DEC_WALL=$FIRST_HD"

# 2) Eth link state BEFORE any change (read-only, driverless via VSEC)
log "LINK_SNAPSHOT_LOCAL_BEGIN"
timeout 30 mstlink -d $BDF > link-local-before-drain.txt 2>&1
grep -aE "State|Physical state|Speed|Width|Auto Negotiation|Enabled Link|Supported Cable|Status Opcode|Recommendation" \
    link-local-before-drain.txt | tee -a $TL
timeout 20 mstreg -d $BDF --reg_name PTYS --index "local_port=1,proto_mask=0x2" --get 2>/dev/null \
    | grep -E "eth_proto_(capab|admin|oper)|data_rate_oper|link_speed" | tee -a $TL
timeout 20 mstreg -d $BDF --reg_name PAOS --index "local_port=1" --get 2>/dev/null \
    | grep -E "admin_status|oper_status" | tee -a $TL
log "LINK_SNAPSHOT_LOCAL_END"

# 3) final marker + MGIR, then drain (SIGINT: disarm + SET_ITRACE 0 + raw dump)
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER_FINAL"
MG=$(timeout 20 mstreg -d $BDF --reg_name MGIR --get 2>/dev/null | grep -i uptime)
log "MGIR_END $MG"
EV0=$(ev_count); ET0=$(an_eth_count); MM0=$(mm_count); IC0=$(icmd_count)
KR0=$(kr_count); CN0=$(conn_count); PD0=$(pdet_count); HA0=$(hook_an_count); HD0=$(hook_dec_count)
log "PRE_DRAIN events=$EV0 an_eth=$ET0 mm=$MM0 icmd=$IC0 kr=$KR0 connector=$CN0 pdetect=$PD0 hook_an=$HA0 hook_dec=$HD0"
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
