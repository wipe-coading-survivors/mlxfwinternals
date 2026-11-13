#!/bin/bash
# T2d-4a arm (cable-path, Eth branch, "three cold plugs" protocol): driverless
# iTrace ARM before the owner's cold-plug sequence. Image an5 stays ACTIVE
# (bank A, build-ID cx4lx-cable-t2-an5, hooks H-AN emit5 @dc 0x1b9da4 marker
# 0x00ae58cd / H-DEC emit2 @dc 0x233094 marker 0x00ad7547). Port is in
# ETHERNET, 100G optics in the cage, link 50G up vs SN2700 (owner state).
# Protocol AFTER arm (coordinator commands the owner): optics out -> AOC
# plug/link/unplug -> FDR DAC plug/link@40/unplug -> optics plug/link@50/keep,
# wall-clock times recorded by the owner. Expected background while linked
# (this window): near-silence + smbus ticks.
# Config = t2d1 EXCEPT: OBSERVE=30 (linked-quiet window, not the AN storm),
# UTC anchors around the arm procedure (owner wall-clock binding), ev-log
# names ev-cable/ring-cable (cable-plug protocol). MASK 0x24404efc, level 0,
# ring 512KB (4KB<<7), poll 100ms, --no-flr, stock image for decode.
# Window: mlx5 unbind -> vfio bind (FW restart) -> FW_READY -> arm -> mask
# guard -> status -> MTRC_CAP GET marker -> self-check 1:1 -> UTC anchor ->
# fixed background observation (30 s) -> STOP (arm stays live).
# NO ICMD access to the card after the self-check marker (clean window);
# NO mstlink/ibstat at all (noise injection into the window); NO teardown;
# IOMMU kargs PERMANENT (docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md): no kargs revert, no reboot.
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t2d4}
MASK=${MASK:-0x24404efc}
LEVEL=${LEVEL:-0}
SIZE=${SIZE:-7}
POLL=${POLL:-100}
OBSERVE=${OBSERVE:-30}
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
ev_count() { grep -cE '^[0-9]+ \[0x[0-9a-f?]+\] 0 \[0x' ev-cable.log 2>/dev/null; }
# per-class counters (stock string fragments; classes of mask 0x24404efc)
an_ib_count()   { grep -cE "ib_speed_nego_fsm|init_ib_an_fsm" ev-cable.log 2>/dev/null; }
an_eth_count()  { grep -c "eth_speed_nego" ev-cable.log 2>/dev/null; }
ptys_count()    { grep -cE "hal_set_ib_speed|PTYS|an_disable_admin" ev-cable.log 2>/dev/null; }
phy_count()     { grep -cE "phy_manager|phy test mode|change_port_state" ev-cable.log 2>/dev/null; }
pll_count()     { grep -c "speed_2_pll" ev-cable.log 2>/dev/null; }
mm_count()      { grep -cE "module_management|cable_module_read_write|TEMPERATURE|isr_mng2core|scl|sda" ev-cable.log 2>/dev/null; }
icmd_count()    { grep -cE "isr_icmd|icmd_generic" ev-cable.log 2>/dev/null; }
kr_count()      { grep -c "kr_startup" ev-cable.log 2>/dev/null; }
hook_an_count() { grep -c "ib_force_edr_fsm: config_tx_sd_set" ev-cable.log 2>/dev/null; }
hook_dec_count() { grep -c "bw should be less than network speed" ev-cable.log 2>/dev/null; }
snapshot() { # $1 label
    echo "$1 events=$(ev_count) an_ib=$(an_ib_count) an_eth=$(an_eth_count) ptys=$(ptys_count) phy=$(phy_count) pll=$(pll_count) mm=$(mm_count) icmd=$(icmd_count) kr=$(kr_count) hook_an=$(hook_an_count) hook_dec=$(hook_dec_count)"
}

log "SCRIPT_START driver=$(readlink $SYS/driver | xargs basename 2>/dev/null) mask=$MASK observe=${OBSERVE}s"
log "PAOS_BASELINE admin=$(paos_get_field admin_status) oper=$(paos_get_field oper_status)"

# UTC anchor PRE-arm (owner wall-clock binding): verbatim date -u on its own
# line, also frozen into date-u-pre.txt
date -u | tee date-u-pre.txt | sed 's/^/DATE_U_PRE_ARM /' | tee -a $TL

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

# 3) arm: t2d1 config, extended mask (actual mask fixed by SET_ITRACE line)
nohup /root/mlxscope trace arm -d $BDF --no-flr --mask $MASK -l $LEVEL -s $SIZE \
    --poll-ms $POLL --out ev-cable.log --raw-out ring-cable.bin --image fw-stock.bin \
    > arm.log 2>&1 &
ARM_PID=$!
log "ARM_SPAWN pid=$ARM_PID"
i=0
until grep -q "SET_ITRACE done" arm.log 2>/dev/null; do
    i=$((i+1)); [ $i -gt 40 ] && { log "ARM_TIMEOUT"; kill -9 $ARM_PID 2>/dev/null; exit 1; }
    sleep 0.25
done
log "ARM_DONE $(grep -m1 'SET_ITRACE done' arm.log)"

# 4) arm self-check: tracer status snapshot (armed state)
sleep 5   # mask-apply guard (Lx: 1.8-4.1 s)
timeout 10 /root/mlxscope trace status -d $BDF > status-armed.txt 2>&1
log "STATUS_ARMED captured"

# 5) liveness marker: mstreg GET -> ICMD-class events (0x4000000 in mask),
#    then self-check isr_icmd : icmd_generic == 1:1
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER_MTRC_CAP_GET"
sleep 2
log "MARKER_ICMD_EVENTS=$(icmd_count) (isr_icmd $(grep -c 'isr_icmd' ev-cable.log 2>/dev/null) : icmd_generic $(grep -c 'icmd_generic' ev-cable.log 2>/dev/null))"

# UTC anchor POST-arm: arm procedure complete (self-check done), clean window
# from here; verbatim date -u also frozen into date-u-post.txt
date -u | tee date-u-post.txt | sed 's/^/DATE_U_POST_ARM /' | tee -a $TL

# 6) fixed background observation (30 s), per-class counters.
# Optics in the cage, 50G link up: expect near-silence + smbus ticks (MM).
E0=$(ev_count); IB0=$(an_ib_count); ET0=$(an_eth_count); PT0=$(ptys_count)
PH0=$(phy_count); PL0=$(pll_count); MM0=$(mm_count); IC0=$(icmd_count)
KR0=$(kr_count); HA0=$(hook_an_count); HD0=$(hook_dec_count)
log "OBS_START events=$E0 an_ib=$IB0 an_eth=$ET0 ptys=$PT0 phy=$PH0 pll=$PL0 mm=$MM0 icmd=$IC0 kr=$KR0 hook_an=$HA0 hook_dec=$HD0"
sleep $OBSERVE
E1=$(ev_count); IB1=$(an_ib_count); ET1=$(an_eth_count); PT1=$(ptys_count)
PH1=$(phy_count); PL1=$(pll_count); MM1=$(mm_count); IC1=$(icmd_count)
KR1=$(kr_count); HA1=$(hook_an_count); HD1=$(hook_dec_count)
log "OBS_END events=$E1 an_ib=$IB1 an_eth=$ET1 ptys=$PT1 phy=$PH1 pll=$PL1 mm=$MM1 icmd=$IC1 kr=$KR1 hook_an=$HA1 hook_dec=$HD1 delta=$((E1-E0)) an_ib_delta=$((IB1-IB0)) an_eth_delta=$((ET1-ET0)) ptys_delta=$((PT1-PT0)) phy_delta=$((PH1-PH0)) pll_delta=$((PL1-PL0)) mm_delta=$((MM1-MM0)) icmd_delta=$((IC1-IC0)) kr_delta=$((KR1-KR0)) hook_an_delta=$((HA1-HA0)) hook_dec_delta=$((HD1-HD0)) over=${OBSERVE}s"

# 7) STOP — arm stays live; NO teardown, NO rebind, NO further card access;
# owner runs the three-cold-plug protocol on coordinator command, the drain
# is a separate step.
log "SCRIPT_END armed pid=$ARM_PID (left running: owner cold-plug protocol on coordinator command, coordinator drains separately)"
