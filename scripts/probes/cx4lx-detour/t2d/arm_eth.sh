#!/bin/bash
# T2d-1 arm (cable-path, Eth branch): driverless iTrace ARM to prepare the
# Eth handshake capture. Image an5 stays ACTIVE (bank A, build-ID
# cx4lx-cable-t2-an5, hooks H-AN emit5 @dc 0x1b9da4 marker 0x00ae58cd /
# H-DEC emit2 @dc 0x233094 marker 0x00ad7547). Port is in ETHERNET now
# (owner switch: ibstat mlx5_2 Link layer Ethernet, Rate 40, Physical
# Disabled; mstlink: Polling / ETH_AN_FSM_ABILITY_DETECT / AN ON, Enabled
# 0xf801f0d3 (50G,40G,25G,10G,1G), opcode 2 PHY FW). AOC still in the
# cage, far end in the old InfiniScale-IV IB switch — Eth AN cannot
# succeed against it, an ability-detect retry loop is expected.
# H-AN (IB AN FSM marker 0x00ae58cd) is expected to stay 0 on the Eth
# path; H-DEC (0x00ad7547) is the prime candidate: the Eth detect may run
# the is_sfp branch @0x233094 which the IB path never executed — if it
# already ticks at idle/detected, that is a FINDING. Module present →
# MM polling may tick; all classes counted separately.
# Config = phase A run2 / t2b2a EXCEPT the mask — EXTENDED 0x24404efc
# (T0 s.3.2 Eth/KR context: core 0x4404c60 + eth_speed_nego 0x80 +
# kr_startup 0x20000000 + SerDes 0x200 + bits 0x8/0x4). Tool takes the
# mask as u32 — no width limit, actual mask fixed from arm.log
# (SET_ITRACE done mask=...). level 0, ring 512KB (4KB<<7), poll 100ms,
# stock image for decode strings (hook markers are stock string-table
# ids), --no-flr. Window: mlx5 unbind -> vfio bind (FW restart) ->
# FW_READY -> arm -> mask guard -> liveness marker -> fixed background
# observation (90 s) -> STOP.
# IOMMU kargs PERMANENT (docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md): no kargs revert, no reboot.
# NO teardown after arm: trace stays live until the separate drain step;
# NO MGIR after the observation window (canon t2b2a).
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t2d}
MASK=${MASK:-0x24404efc}
LEVEL=${LEVEL:-0}
SIZE=${SIZE:-7}
POLL=${POLL:-100}
OBSERVE=${OBSERVE:-90}
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
# per-class counters (stock string fragments; classes of mask 0x24404efc)
an_ib_count()   { grep -cE "ib_speed_nego_fsm|init_ib_an_fsm" ev-dac.log 2>/dev/null; }
an_eth_count()  { grep -c "eth_speed_nego" ev-dac.log 2>/dev/null; }
ptys_count()    { grep -cE "hal_set_ib_speed|PTYS|an_disable_admin" ev-dac.log 2>/dev/null; }
phy_count()     { grep -cE "phy_manager|phy test mode|change_port_state" ev-dac.log 2>/dev/null; }
pll_count()     { grep -c "speed_2_pll" ev-dac.log 2>/dev/null; }
mm_count()      { grep -cE "module_management|cable_module_read_write|TEMPERATURE|isr_mng2core|scl|sda" ev-dac.log 2>/dev/null; }
icmd_count()    { grep -cE "isr_icmd|icmd_generic" ev-dac.log 2>/dev/null; }
kr_count()      { grep -c "kr_startup" ev-dac.log 2>/dev/null; }
hook_an_count() { grep -c "ib_force_edr_fsm: config_tx_sd_set" ev-dac.log 2>/dev/null; }
hook_dec_count() { grep -c "bw should be less than network speed" ev-dac.log 2>/dev/null; }
snapshot() { # $1 label
    echo "$1 events=$(ev_count) an_ib=$(an_ib_count) an_eth=$(an_eth_count) ptys=$(ptys_count) phy=$(phy_count) pll=$(pll_count) mm=$(mm_count) icmd=$(icmd_count) kr=$(kr_count) hook_an=$(hook_an_count) hook_dec=$(hook_dec_count)"
}

log "SCRIPT_START driver=$(readlink $SYS/driver | xargs basename 2>/dev/null) mask=$MASK observe=${OBSERVE}s"
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

# 3) arm: run2 config, EXTENDED mask (actual mask fixed by SET_ITRACE line in arm.log)
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
log "ARM_DONE $(grep -m1 'SET_ITRACE done' arm.log)"

# 4) arm self-check: tracer status snapshot (armed state)
sleep 5   # mask-apply guard (Lx: 1.8-4.1 s)
timeout 10 /root/mlxscope trace status -d $BDF > status-armed.txt 2>&1
log "STATUS_ARMED captured"

# 5) liveness marker: mstreg GET -> ICMD-class events (0x4000000 in mask)
timeout 20 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
log "MARKER_MTRC_CAP_GET"
sleep 2
log "MARKER_ICMD_EVENTS=$(icmd_count) (isr_icmd $(grep -c 'isr_icmd' ev-dac.log 2>/dev/null) : icmd_generic $(grep -c 'icmd_generic' ev-dac.log 2>/dev/null))"

# 6) fixed background observation (90 s), per-class counters.
# Eth AN ability-detect loop expected vs the IB switch (no peer); H-AN
# expected 0 (IB AN FSM); H-DEC is the open question — any tick is a
# finding; MM polling may tick (module in the cage).
E0=$(ev_count); IB0=$(an_ib_count); ET0=$(an_eth_count); PT0=$(ptys_count)
PH0=$(phy_count); PL0=$(pll_count); MM0=$(mm_count); IC0=$(icmd_count)
KR0=$(kr_count); HA0=$(hook_an_count); HD0=$(hook_dec_count)
log "OBS_START events=$E0 an_ib=$IB0 an_eth=$ET0 ptys=$PT0 phy=$PH0 pll=$PL0 mm=$MM0 icmd=$IC0 kr=$KR0 hook_an=$HA0 hook_dec=$HD0"
sleep $OBSERVE
E1=$(ev_count); IB1=$(an_ib_count); ET1=$(an_eth_count); PT1=$(ptys_count)
PH1=$(phy_count); PL1=$(pll_count); MM1=$(mm_count); IC1=$(icmd_count)
KR1=$(kr_count); HA1=$(hook_an_count); HD1=$(hook_dec_count)
log "OBS_END events=$E1 an_ib=$IB1 an_eth=$ET1 ptys=$PT1 phy=$PH1 pll=$PL1 mm=$MM1 icmd=$IC1 kr=$KR1 hook_an=$HA1 hook_dec=$HD1 delta=$((E1-E0)) an_ib_delta=$((IB1-IB0)) an_eth_delta=$((ET1-ET0)) ptys_delta=$((PT1-PT0)) phy_delta=$((PH1-PH0)) pll_delta=$((PL1-PL0)) mm_delta=$((MM1-MM0)) icmd_delta=$((IC1-IC0)) kr_delta=$((KR1-KR0)) hook_an_delta=$((HA1-HA0)) hook_dec_delta=$((HD1-HD0)) over=${OBSERVE}s"

# 7) STOP — arm stays live; NO teardown, NO rebind, NO further card access
# (canon t2b2a); owner re-plugs the AOC into the multi-rate Eth switch on
# coordinator command, the drain is a separate step.
log "SCRIPT_END armed pid=$ARM_PID (left running: owner re-plugs AOC to Eth switch, coordinator drains separately)"
