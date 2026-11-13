#!/bin/sh
# usage: t17r-run.sh NAME   (one probe per invocation; R12 protocol)
NAME=$1
HEX=$(python3 - "$NAME" <<'PYEOF'
import sys
SPECS = {
 "p0a": {}, "p2": {0x12:0x5A}, "p3": {0x13:0x5A}, "p4": {0x14:0x5A},
 "p5": {0x18:0x5A}, "p6": {0x20:0x5A},
 "p7": {0x12:0x11,0x13:0x22,0x14:0x44,0x18:0x66,0x20:0x88},
 "p0b": {},
}
INV = {6,7,9,0xC,0xD,0xE,0xF,0x11,0x12,0x13,0x14,0x18,0x20}
name = sys.argv[1]
assert name in SPECS, name
b = bytearray(36)
b[0:4] = bytes.fromhex("09320000")
b[8] = 0
for k, v in SPECS[name].items():
    b[k] = v
h = b.hex()
assert len(h) == 72
nz = [i for i in range(4,36) if b[i]]
assert all(k in INV for k in nz), nz
assert all(k not in (0xA, 0xB, 8) for k in nz), nz
assert not any(4 <= k < 6 for k in nz), nz
print(h)
PYEOF
) || { echo "HEX-BUILD-FAIL"; exit 1; }
echo "[$NAME] hex=$HEX"
nohup /root/mlxscope --input-hex "$HEX" > /root/t17r-$NAME.log 2>&1 &
PID=$!
DONE=0
for i in $(seq 1 30); do
  sleep 1
  kill -0 $PID 2>/dev/null || { DONE=1; break; }
done
if [ $DONE -eq 0 ]; then echo "HANG: pid $PID alive >30s"; exit 2; fi
sleep 0.3
echo "--- trigger log (t17r-$NAME.log) ---"
cat /root/t17r-$NAME.log
echo "--- setpci CR reads ---"
setpci -s 81:00.0 0xc4.l=20000002
sleep 0.2
for SLOT in 2380 2384 2388 238c; do
  setpci -s 81:00.0 0xd0.l=0000$SLOT
  sleep 0.2
  A=$(setpci -s 81:00.0 0xd0.l)
  sleep 0.2
  D=$(setpci -s 81:00.0 0xd4.l)
  sleep 0.2
  echo "CR $SLOT: addr_echo=$A data=$D"
done
echo "[$NAME] complete"
