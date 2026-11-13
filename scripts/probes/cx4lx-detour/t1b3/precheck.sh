#!/bin/bash
# T1-B3 precheck (read-only): card/link state with FDR DAC now going to the
# InfiniScale-IV QDR switch (partner CX-5 disconnected by the owner; link is
# down, Polling on both ends). The B3 pre point for the diff vs B (CX-5) and
# A (AOC->switch, QDR LinkUp). Driver stays bound (mlx5), no unbind/rebind.
set -u
BDF=${BDF:-0000:04:00.0}
CA=${CA:-mlx5_2}
OUT=${OUT:-precheck.log}

run() { echo "=== $* ==="; timeout 30 "$@" 2>&1; echo "[rc=$?]"; }

{
echo "### T1-B3 precheck $(date -u +%Y-%m-%dT%H:%M:%SZ) BDF=$BDF (FDR DAC -> InfiniScale-IV QDR switch)"
echo "=== lspci ==="; lspci -s $BDF; echo "[rc=$?]"
echo "=== driver/netdev ==="
readlink /sys/bus/pci/devices/$BDF/driver
ls /sys/class/net/
echo "=== ibstat (our CA) ==="
ibstat $CA 2>&1; echo "[rc=$?]"
run mstlink -d $BDF
run mstreg -d $BDF --reg_name PTYS --index "local_port=1,proto_mask=0x1" --get
run mstreg -d $BDF --reg_name PAOS --index "local_port=1" --get
run mstreg -d $BDF --reg_name MGIR --get
echo "=== mstflint q (identity) ==="
mstflint -d $BDF q 2>&1 | sed -n '1,14p'; echo "[rc=$?]"
echo "=== dmesg our card ==="
dmesg | grep -E "$BDF" | tail -5
dmesg | grep -cE "$BDF.*(assert|Assert)" || true
} | tee "$OUT"
