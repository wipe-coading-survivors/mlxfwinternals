#!/bin/bash
# T2d-4b recovery (after the immediate drain): vfio-pci -> mlx5_core rebind
# (IOMMU kargs PERMANENT per docs/250-re/120-irisc/045-cx4lx-boot-window-cablepath.md - no kargs revert, no reboot), then
# link/card state checks that were deferred past the drain per coordinator
# priority: ibstat mlx5_2 + mstlink (did the re-plugged 100G optic come back
# at 50G?), PTYS oper, mstflint q (rc=0 gate), dc build-ID (an5 image active:
# cx4lx-cable-t2-an5).
set -u
BDF=${BDF:-0000:04:00.0}
DIR=${DIR:-/var/roothome/t2d4}
SYS=/sys/bus/pci/devices/$BDF
cd "$DIR" || exit 1
TL=timeline.log
ts() { date +%s.%N; }
log() { echo "$1 $(ts)" | tee -a $TL; }

log "RECOVERY_START driver=$(readlink $SYS/driver 2>/dev/null | xargs basename 2>/dev/null)"
DR=$(readlink $SYS/driver 2>/dev/null | xargs basename 2>/dev/null)
if [ "$DR" = "vfio-pci" ]; then
    echo $BDF > /sys/bus/pci/drivers/vfio-pci/unbind && log "VFIO_UNBOUND" || { log "VFIO_UNBIND_FAIL"; exit 1; }
fi
echo "" > $SYS/driver_override
echo $BDF > /sys/bus/pci/drivers/mlx5_core/bind && log "MLX5_BOUND" || { log "MLX5_BIND_FAIL"; exit 1; }

i=0
until ibstat 2>/dev/null | grep -q "mlx5_2"; do
    i=$((i+1)); [ $i -gt 40 ] && { log "IBSTAT_TIMEOUT"; break; }
    sleep 0.5
done
log "IBSTAT_PORT_UP after ~$((i/2))s"
date -u | sed 's/^/DATE_U_RECOVERY /' | tee -a $TL

ibstat mlx5_2 > ibstat-recovery.log 2>&1
grep -E "State:|Rate:|Port 1:" ibstat-recovery.log | head -6 | tee -a $TL

timeout 30 mstlink -d $BDF > mstlink-recovery.txt 2>&1
grep -aE "State|Physical state|Speed|Width|Auto Negotiation|Enabled Link" mstlink-recovery.txt | head -12 | tee -a $TL

timeout 30 mstreg -d $BDF --reg_name PTYS --index "local_port=1,proto_mask=0x2" --get > ptys-recovery.txt 2>&1
grep -E "eth_proto_(capab|admin|oper)|data_rate_oper" ptys-recovery.txt | tee -a $TL

timeout 30 mstflint -d $BDF q > q-recovery.log 2>&1
log "Q_RC=$?"
grep -E "PSID|FW Version|Board ID" q-recovery.log | head -4 | tee -a $TL

timeout 30 mstflint -d $BDF dc > dc-recovery.ini 2>/dev/null
log "DC_RC=$?"
grep -m2 -iE "build" dc-recovery.ini | tee -a $TL
log "RECOVERY_END"
