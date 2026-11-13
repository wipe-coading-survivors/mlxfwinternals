#!/bin/bash
# T1-B3 arm: driverless iTrace ARM with the FDR DAC now terminated on the
# InfiniScale-IV QDR switch (link down, Polling both ends; partner CX-5
# disconnected). Config = phase A run2 / phase B step 1 EXACTLY: mask
# 0x4404c60, level 0, ring 512KB (4KB<<7), poll 100ms, stock image for decode
# strings, --no-flr. Window: mlx5 unbind -> vfio bind (FW restart) ->
# FW_READY -> arm -> mask guard -> liveness marker -> fixed storm observation
# (~150-180 s; AN storm expected immediately after FW restart — the switch is
# a responding partner, unlike the dangling-DAC arm of step B1).
# NO teardown / drain / disarm / rebind after arm: the mask must survive
# until the drain script (canon docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md — mask dies on mlx5 rebind and
# FW restart). The arm process keeps running (nohup) and drains events from
# the ring into the ev log, keeping the ring free.
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t1b3}
MASK=${MASK:-0x4404c60}
LEVEL=${LEVEL:-0}
SIZE=${SIZE:-7}
POLL=${POLL:-100}
OBSERVE=${OBSERVE:-170}
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

# 3) arm, config = phase A run2 / B1 (no FLR: device just came up fresh)
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

# 6) fixed storm observation (switch partner: AN retry storm expected right
# after FW restart; ~150-180 s target window for the B3 capture)
EV0=$(ev_count); AN0=$(an_count)
log "OBS_START events=$EV0 an=$AN0"
sleep $OBSERVE
EV1=$(ev_count); AN1=$(an_count)
log "OBS_END events=$EV1 an=$AN1 delta=$((EV1-EV0)) an_delta=$((AN1-AN0)) over=${OBSERVE}s"
MG=$(timeout 20 mstreg -d $BDF --reg_name MGIR --get 2>/dev/null | grep -i uptime)
log "MGIR_END $MG"

# 7) STOP — arm stays live; NO teardown, NO rebind; drain script takes over
log "SCRIPT_END armed pid=$ARM_PID (left running for the B3 drain step)"
