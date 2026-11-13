#!/bin/bash
# T1-B1 precheck (read-only): card/link state with FDR DAC inserted (far end
# disconnected) — the R_B pre point for the diff vs phase A (AOC: Enabled
# 0x07 / Supported 0x0f). Driver stays bound (mlx5), no unbind/rebind.
set -u
BDF=${BDF:-0000:04:00.0}
CA=${CA:-mlx5_2}
OUT=${OUT:-precheck.log}

run() { echo "=== $* ==="; timeout 30 "$@" 2>&1; echo "[rc=$?]"; }

{
echo "### T1-B1 precheck $(date -u +%Y-%m-%dT%H:%M:%SZ) BDF=$BDF"
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
run /root/mlxscope trace status -d $BDF --cr 0x23f0
echo "=== mstflint q (identity) ==="
mstflint -d $BDF q 2>&1 | sed -n '1,14p'; echo "[rc=$?]"
echo "=== dmesg our card ==="
dmesg | grep -E "$BDF" | tail -5
dmesg | grep -cE "$BDF.*(assert|Assert)" || true
} | tee "$OUT"
