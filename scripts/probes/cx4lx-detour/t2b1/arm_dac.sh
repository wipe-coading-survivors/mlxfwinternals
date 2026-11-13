#!/bin/bash
# T2b-1 arm: driverless iTrace ARM with the T2a an5 hook image now ACTIVE
# (bank A; burn + activation reboot done). Physical setup unchanged since
# T1-B3: FDR DAC our-card <-> InfiniScale-IV QDR switch, link down, eternal
# AN retry — the storm is expected to run continuously through the capture.
# Config = phase A run2 / T1-B1 / T1-B3 EXACTLY: mask 0x4404c60, level 0,
# ring 512KB (4KB<<7), poll 100ms, stock image for decode strings (hook
# markers 0x00ae58cd / 0x00ad7547 are stock string-table ids), --no-flr.
# NEW vs T1: the running FW carries hooks H-AN emit5 @dc 0x1b9da4 (marker
# 0x00ae58cd, 5 ctx words [0x58/0x5c/0x68/0xa0/0xa4]) and H-DEC emit2
# @dc 0x233094 (marker 0x00ad7547, module + verdict). Expect H-AN lines in
# every AN round; H-DEC may stay 0 (module detected before arm — expected).
# Window: mlx5 unbind -> vfio bind (FW restart) -> FW_READY -> arm -> mask
# guard -> liveness marker -> fixed storm observation (~120 s). NO teardown
# after arm (canon docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md); the drain script takes over.
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t2b1}
MASK=${MASK:-0x4404c60}
LEVEL=${LEVEL:-0}
SIZE=${SIZE:-7}
POLL=${POLL:-100}
OBSERVE=${OBSERVE:-120}
SYS=/sys/bus/pci/devices/$BDF
cd "$DIR" || exit 1
TL=timeline.log
: > $TL
ts() { date +%s.%N; }
log() { echo "$1 $(ts)" | tee -a $TL; }

paos_get_field() { # $1 field name
    timeout 20 mstreg -d $BDF --reg_name PAOS --index "local_port=1" --get 2>/dev/null \
        | awk -v f="$1" '$1==f{print $3}'
}
# live ev-log line format: "<wall_ms> [0x<fw-ts>] 0 [0x<id>] <string>"
ev_count() { grep -cE '^[0-9]+ \[0x[0-9a-f?]+\] 0 \[0x' ev-dac.log 2>/dev/null; }
an_count() { grep -cE "ib_speed_nego_fsm|init_ib_an_fsm" ev-dac.log 2>/dev/null; }
hook_an_count() { grep -c "ib_force_edr_fsm: config_tx_sd_set" ev-dac.log 2>/dev/null; }
hook_dec_count() { grep -c "bw should be less than network speed" ev-dac.log 2>/dev/null; }

log "SCRIPT_START driver=$(readlink $SYS/driver | xargs basename 2>/dev/null)"
log "PAOS_BASELINE admin=$(paos_get_field admin_status) oper=$(paos_get_field oper_status)"

# 1) driverless window: mlx5 unbind -> vfio bind (FW restarts here)
DR=$(readlink $SYS/driver 2>/dev/null | xargs basename 2>/dev/null)
if [ "$DR" = "mlx5_core" ]; then
    echo $BDF > /sys/bus/pci/drivers/mlx5_core/unbind && log "MLX5_UNBOUND" || { log "MLX5_UNBIND_FAIL"; exit 1; }
fi
echo vfio-pci > $SYS/driver_override
echo $BDF > /sys/bus/pci/drivers/vfio-pci/bind && log "VFIO_BOUND" || { log "VFIO_BIND_FAIL"; exit 1; }

# 2) FW ready (MTRC_CAP readable via VSEC)
i=0
until timeout 10 /root/mlxscope trace status -d $BDF 2>/dev/null | grep -q 'trace_to_memory'; do
    i=$((i+1)); [ $i -gt 60 ] && { log "FW_READY_TIMEOUT"; exit 1; }
    sleep 0.5
done
log "FW_READY"

# 3) arm, config = phase A run2 / B1 / B3 (no FLR: device just came up fresh)
nohup /root/mlxscope trace arm -d $BDF --no-flr --mask $MASK -l $LEVEL -s $SIZE \
    --poll-ms $POLL --out ev-dac.log --raw-out ring-dac.bin --image fw-stock.bin \
    > arm.log 2>&1 &
ARM_PID=$!
log "ARM_SPAWN pid=$ARM_PID"
i=0
until grep -q "SET_ITRACE done" arm.log 2>/dev/null; do
    i=$((i+1)); [ $i -gt 40 ] && { log "ARM_TIMEOUT"; kill -9 $ARM_PID 2>/dev/null; exit 1; }
    sleep 0.25
done
log "ARM_DONE"

# 4) arm self-check: tracer status snapshot (armed state)
sleep 5   # mask-apply guard (Lx: 1.8-4.1 s)
timeout 10 /root/mlxscope trace status -d $BDF > status-armed.txt 2>&1
log "STATUS_ARMED captured"

# 5) liveness marker: mstreg GET -> ICMD-class events (0x4000000 in mask)
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER_MTRC_CAP_GET"
sleep 2
log "MARKER_ICMD_EVENTS=$(grep -cE 'isr_icmd|icmd_generic' ev-dac.log 2>/dev/null || echo 0)"

# 6) fixed storm observation (~120 s target window; hook events expected in
# every AN round — H-AN emit5, and possibly H-DEC emit2 if MM SM re-runs)
EV0=$(ev_count); AN0=$(an_count); HA0=$(hook_an_count); HD0=$(hook_dec_count)
log "OBS_START events=$EV0 an=$AN0 hook_an=$HA0 hook_dec=$HD0"
sleep $OBSERVE
EV1=$(ev_count); AN1=$(an_count); HA1=$(hook_an_count); HD1=$(hook_dec_count)
log "OBS_END events=$EV1 an=$AN1 hook_an=$HA1 hook_dec=$HD1 delta=$((EV1-EV0)) an_delta=$((AN1-AN0)) hook_an_delta=$((HA1-HA0)) hook_dec_delta=$((HD1-HD0)) over=${OBSERVE}s"
MG=$(timeout 20 mstreg -d $BDF --reg_name MGIR --get 2>/dev/null | grep -i uptime)
log "MGIR_END $MG"

# 7) STOP — arm stays live; NO teardown, NO rebind; drain script takes over
log "SCRIPT_END armed pid=$ARM_PID (left running for the T2b-1 drain step)"
