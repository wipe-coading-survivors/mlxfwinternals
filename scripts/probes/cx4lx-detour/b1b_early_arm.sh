#!/bin/bash
# B1b early-arm v2: unbind vfio-pci -> mstfwreset L3 -> re-arm on device/FW ready.
set -u
cd /root/b1b
BDF=0000:04:00.0
SYS=/sys/bus/pci/devices/$BDF
mkdir -p early2
rm -f early2/* ev-post2.log ring-post2.bin

ts() { date +%s.%N; }
echo "SCRIPT_START $(ts)" | tee early2/timeline.log

# 0) ensure driverless-clean: unbind vfio-pci (override stays -> auto rebind on reappearance)
DR=$(readlink $SYS/driver 2>/dev/null || true)
echo "DRIVER_BEFORE ${DR##*/} $(ts)" | tee -a early2/timeline.log
if [ "${DR##*/}" = "vfio-pci" ]; then
    echo $BDF > /sys/bus/pci/drivers/vfio-pci/unbind
    echo "VFIO_UNBOUND $(ts)" | tee -a early2/timeline.log
fi

# 1) mstfwreset level 3 (no driver bound)
echo "MSTFWRESET_CMD $(ts)" | tee -a early2/timeline.log
nohup mstfwreset -d $BDF -l 3 -y reset > early2/fwreset.log 2>&1 &
FR_PID=$!

# 2) poller: track link-down (config reads -> 0xffff) then UP, 20 ms,
# started BEFORE the reset lands
python3 - "$BDF" <<'PYEOF' | tee -a early2/timeline.log &
import sys, time
bdf = sys.argv[1]
cfg = "/sys/bus/pci/devices/%s/config" % bdf
t0 = time.time()
down_at = None
up_at = None
def devid():
    try:
        with open(cfg, "rb") as f:
            v = f.read(4)
        return (v[2] << 8) | v[3]
    except Exception:
        return None
while time.time() - t0 < 120:
    d = devid()
    if down_at is None:
        if d is None or d == 0xffff or d == 0:
            down_at = time.time()
            print("DEV_DOWN %.6f" % down_at, flush=True)
    elif up_at is None:
        if d in (0x1015, 0x1510):
            up_at = time.time()
            print("DEV_UP %.6f devid=%04x" % (up_at, d), flush=True)
            break
    time.sleep(0.02)
print("POLLER_EXIT %.6f down=%s up=%s" % (time.time(), down_at, up_at), flush=True)
PYEOF
POLL_PID=$!

wait $FR_PID; FR_RC=$?
echo "MSTFWRESET_DONE rc=$FR_RC $(ts)" | tee -a early2/timeline.log
wait $POLL_PID

# bind vfio-pci right after DEV_UP (no auto-probe for a persistent device)
echo $BDF > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null \
    && echo "VFIO_BIND $(ts)" | tee -a early2/timeline.log \
    || echo "VFIO_BIND_FAIL $(ts)" | tee -a early2/timeline.log

# 3) FW-ready: MTRC_CAP GET via our status tool
i=0
until timeout 10 /root/mlxscope trace status -d $BDF 2>/dev/null | grep -q 'MTRC_CAP:.*trace_to_memory'; do
    i=$((i+1)); [ $i -gt 100 ] && { echo "FW_READY_TIMEOUT $(ts)" | tee -a early2/timeline.log; exit 1; }
    sleep 0.1
done
echo "FW_READY (MTRC_CAP GET ok) $(ts)" | tee -a early2/timeline.log

# 4) RE-ARM + drain (no FLR: timing run)
echo "REARM_SPAWN $(ts)" | tee -a early2/timeline.log
nohup /root/mlxscope trace arm -d $BDF --no-flr --mask 0x04000000 --level 1 \
    --out ev-post2.log --raw-out ring-post2.bin --image fw-stock.bin --poll-ms 50 \
    > early2/arm-post.log 2>&1 &
POST_PID=$!

# 5) markers ×3
sleep 2
for i in 1 2 3; do
    echo "MARKER_$i $(ts)" | tee -a early2/timeline.log
    timeout 15 mstreg -d $BDF --reg_name MTRC_CAP --get >/dev/null 2>&1
    sleep 1
done

# 6) teardown + MGIR
sleep 3
kill -INT $POST_PID; sleep 2; kill -9 $POST_PID 2>/dev/null
echo "POST_ARM_STOP $(ts)" | tee -a early2/timeline.log
MG=$(timeout 15 mstreg -d $BDF --reg_name MGIR --get 2>/dev/null | grep -i uptime)
echo "MGIR $MG $(ts)" | tee -a early2/timeline.log
echo "SCRIPT_END $(ts)" | tee -a early2/timeline.log
