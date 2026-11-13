#!/bin/bash
# T1-A capture: driverless iTrace of the AOC link path on CX-4 Lx (bank B,
# no image change). Window: vfio bind (FW restart, natural AOC link-up) ->
# arm (mask 0x4404c60) -> marker -> PAOS admin down/up (soft AN-restart
# trigger; no netdev driverless, so no `ip link`) -> settle -> optional PTYS
# speed cycle (only if no AN strings seen) -> SIGINT teardown -> driver back.
# NO bind/unbind/reboot between arm and teardown (SET_ITRACE mask dies).
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t1a}
MASK=${MASK:-0x4404c60}
LEVEL=${LEVEL:-0}
SIZE=${SIZE:-7}
POLL=${POLL:-100}
DOWN_DWELL=${DOWN_DWELL:-10}
SETTLE=${SETTLE:-60}
PTYS_FALLBACK=${PTYS_FALLBACK:-auto}   # auto|force|off
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
paos_set() { # $1 admin_status value (1 up / 2 down); verify by readback
    local out rc got
    out=$(timeout 20 mstreg -d $BDF --reg_name PAOS --yes \
        --index "local_port=1" --set admin_status=$1 2>&1)
    rc=$?
    got=$(paos_get_field admin_status)
    if echo "$got" | grep -qi "0x0000000$1\$"; then
        return 0
    fi
    echo "paos_set($1) diag: rc=$rc sent_ok=$(echo "$out" | grep -c 'Sending access register') readback=$got" >&2
    return 1
}

log "SCRIPT_START driver=$(readlink $SYS/driver | xargs basename 2>/dev/null)"
oper=$(paos_get_field oper_status); log "PAOS_BASELINE admin=$(paos_get_field admin_status) oper=$oper"

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

# 3) arm (no FLR: device just came up fresh; ring 4KB<<SIZE)
nohup /root/mlxscope trace arm -d $BDF --no-flr --mask $MASK -l $LEVEL -s $SIZE \
    --poll-ms $POLL --out ev-aoc.log --raw-out ring-aoc.bin --image fw-stock.bin \
    > arm.log 2>&1 &
ARM_PID=$!
log "ARM_SPAWN pid=$ARM_PID"
i=0
until grep -q "SET_ITRACE done" arm.log 2>/dev/null; do
    i=$((i+1)); [ $i -gt 40 ] && { log "ARM_TIMEOUT"; kill -9 $ARM_PID 2>/dev/null; exit 1; }
    sleep 0.25
done
log "ARM_DONE"
sleep 5   # mask-apply guard (Lx: 1.8-4.1 s)

# 4) marker: mstreg GET -> ICMD-class events (0x4000000 in mask) = ring liveness
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER_MTRC_CAP_GET"

# 5) wait for natural AOC link-up (driverless)
i=0
while [ "$(paos_get_field oper_status)" != "0x00000001" ]; do
    i=$((i+1)); [ $i -gt 120 ] && { log "LINK_UP_TIMEOUT_DRIVERLESS"; break; }
    sleep 1
done
[ $i -le 120 ] && log "LINK_UP_DRIVERLESS after ${i}s"
sleep 10   # settle after link-up

# 6) flap: PAOS admin down -> dwell -> up (soft AN-restart on our side only)
if paos_set 2; then log "FLAP_ADMIN_DOWN_SET"; else log "FLAP_ADMIN_DOWN_FAIL"; fi
i=0
while [ "$(paos_get_field oper_status)" != "0x00000002" ] && [ $i -lt 30 ]; do
    i=$((i+1)); sleep 1
done
if [ "$(paos_get_field oper_status)" = "0x00000002" ]; then log "OPER_DOWN_CONFIRMED after ${i}s"; else log "OPER_STAYED_UP_30s"; fi
sleep $DOWN_DWELL
if paos_set 1; then log "FLAP_ADMIN_UP_SET"; else log "FLAP_ADMIN_UP_FAIL"; fi

# 7) settle; watch link return
i=0
while [ "$(paos_get_field oper_status)" != "0x00000001" ] && [ $i -lt $SETTLE ]; do
    i=$((i+1)); sleep 1
done
log "OPER_BACK_UP after ${i}s (or timeout ${SETTLE}s)"

# 8) optional second soft trigger: PTYS speed cycle (only if no AN strings)
AN_SEEN=$(grep -cE "ib_speed_nego_fsm|init_ib_an_fsm" ev-aoc.log 2>/dev/null || echo 0)
log "AN_STRING_COUNT_AFTER_FLAP=$AN_SEEN"
DO_PTYS=0
if [ "$PTYS_FALLBACK" = "force" ]; then DO_PTYS=1; fi
if [ "$PTYS_FALLBACK" = "auto" ] && [ "$AN_SEEN" = "0" ]; then DO_PTYS=1; fi
if [ "$DO_PTYS" = "1" ]; then
    log "PTYS_CYCLE_START"
    timeout 20 mstreg -d $BDF --reg_name PTYS --yes --index "local_port=1,proto_mask=0x1" \
        --set ib_proto_admin=0x2 >/dev/null 2>&1 && log "PTYS_DDR_ONLY_SET" || log "PTYS_DDR_ONLY_FAIL"
    i=0
    while [ "$(paos_get_field oper_status)" != "0x00000002" ] && [ $i -lt 30 ]; do
        i=$((i+1)); sleep 1
    done
    if [ "$(paos_get_field oper_status)" = "0x00000002" ]; then log "OPER_DROPPED_AFTER_PTYS after ${i}s"; else log "OPER_STILL_UP_AFTER_PTYS_30s"; fi
    sleep 15
    timeout 20 mstreg -d $BDF --reg_name PTYS --yes --index "local_port=1,proto_mask=0x1" \
        --set ib_proto_admin=0x3f >/dev/null 2>&1 && log "PTYS_RESTORE_SET" || log "PTYS_RESTORE_FAIL"
    sleep 5
    PTYS_NOW=$(timeout 20 mstreg -d $BDF --reg_name PTYS --index "local_port=1,proto_mask=0x1" --get 2>/dev/null | awk '$1=="ib_proto_admin"{print $3}')
    log "PTYS_ADMIN_AFTER=$PTYS_NOW"
    i=0
    while [ "$(paos_get_field oper_status)" != "0x00000001" ] && [ $i -lt 60 ]; do
        i=$((i+1)); sleep 1
    done
    if [ "$(paos_get_field oper_status)" = "0x00000001" ]; then log "OPER_UP_AFTER_PTYS after ${i}s"; else log "OPER_STILL_DOWN_AFTER_PTYS_60s"; fi
    sleep 20
fi

# 9) final marker + teardown (SIGINT: disarm + mask 0 + raw dump)
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER_FINAL"
MG=$(timeout 20 mstreg -d $BDF --reg_name MGIR --get 2>/dev/null | grep -i uptime)
log "MGIR_END $MG"
kill -INT $ARM_PID
i=0
until grep -q "raw ring dump" arm.log 2>/dev/null; do
    i=$((i+1)); [ $i -gt 40 ] && { kill -9 $ARM_PID 2>/dev/null; break; }
    sleep 0.5
done
log "ARM_STOPPED"

# 10) driver back; link/state verify
echo $BDF > /sys/bus/pci/drivers/vfio-pci/unbind 2>/dev/null && log "VFIO_UNBOUND"
echo "" > $SYS/driver_override
echo $BDF > /sys/bus/pci/drivers/mlx5_core/bind 2>/dev/null && log "MLX5_REBOUND" || log "MLX5_REBIND_FAIL"
sleep 8
log "DRIVER_END=$(readlink $SYS/driver | xargs basename 2>/dev/null)"
log "NETDEV_IBS5=$(ip link show ibs5 >/dev/null 2>&1 && echo present || echo absent)"
ibstat 2>/dev/null | sed -n "/mlx5_2/,/Link layer/p" > ibstat-after.txt
log "IBSTAT_AFTER_TAIL"; tail -5 ibstat-after.txt
timeout 20 mstreg -d $BDF --reg_name PAOS --index "local_port=1" --get > paos-after.txt 2>&1
grep -E "admin_status|oper_status" paos-after.txt | sed "s/^/PAOS_AFTER /" | tee -a $TL
md5sum ev-aoc.log ring-aoc.bin arm.log $TL 2>/dev/null | tee md5.txt
log "SCRIPT_END"
