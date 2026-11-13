#!/bin/bash
# B1 rearm probe: baseline window -> MTRC readback -> mstfwreset L3 ->
# survival readback -> rearm timing. Mirrors the 2026-10-11 live run
# (logs of the run: build/b1/). Run on the card host as root.
# Usage: b1_rearm_probe.sh <logdir>   (e.g. /root/b1)
set -euo pipefail
D=${1:?logdir}
B=0000:04:00.0
T=/sys/kernel/debug/tracing
mkdir -p "$D"
HERE=$(cd "$(dirname "$0")" && pwd)

marker() { timeout 25 mstreg -d $B --reg_name MTRC_CAP --get > /dev/null 2>&1; }

echo "1 baseline window"
echo 1 > $T/events/mlx5/mlx5_fw/enable
: > $T/trace
stdbuf -oL timeout 150 mstfwtrace -d $B -m 0x4000000 -l 0 --ignore_old_events 2>&1 \
  | stdbuf -oL python3 "$HERE/b1_helpers.py" ts > "$D/p1-baseline.log" &
sleep 3
for i in 1 2 3 4 5; do echo "MARK $i $(date +%s.%N)" >> "$D/p1-markers.log"; marker; sleep 5; done
timeout 30 mstreg -d $B --reg_name MTRC_CAP --get > "$D/p1-mtrc-cap-get.txt" 2>&1 || true
timeout 30 mstreg -d $B --reg_name MTRC_CONF --get > "$D/p1-mtrc-conf-get.txt" 2>&1 || true
timeout 30 mstreg -d $B --reg_name MTRC_CTRL --get > "$D/p1-mtrc-ctrl-get.txt" 2>&1 || true
timeout 30 mstreg -d $B --reg_name MGIR --get 2>&1 | grep uptime > "$D/p1-mgir.txt" || true

echo "2 reset (mstfwreset level 3) with phase poller"
nohup python3 "$HERE/b1_helpers.py" poll "$D/p2-poll.log" > /dev/null 2>&1 &
echo "POLLER $!"
echo "T0 $(date +%s.%N)"
stdbuf -oL mstfwreset -d $B -y reset 2>&1 \
  | stdbuf -oL python3 "$HERE/b1_helpers.py" ts > "$D/p2-fwreset.log"

echo "3 survival readback"
timeout 30 mstreg -d $B --reg_name MGIR --get 2>&1 | grep uptime > "$D/p3-mgir.txt" || true
timeout 30 mstreg -d $B --reg_name MTRC_CAP --get > "$D/p3-mtrc-cap-get.txt" 2>&1 || true
python3 /root/vsec_cr.py $B 0x23f0 0x223f0 > "$D/p3-vsec.txt" 2>&1 || true
: > $T/trace
for i in 1 2 3; do marker; sleep 4; done
sleep 4
grep -c mlx5_fw $T/trace > "$D/p3-mask-survival-count.txt" || true

echo "4 rearm timing"
: > $T/trace
stdbuf -oL timeout 90 mstfwtrace -d $B -m 0x4000000 -l 0 --ignore_old_events 2>&1 \
  | stdbuf -oL python3 "$HERE/b1_helpers.py" ts > "$D/p4-rearm.log" &
for i in $(seq 1 20); do echo "mark$i $(date +%s.%N)" >> "$D/p4-markers.log"; marker; sleep 2; done
sleep 6

echo "5 restore"
timeout 15 mstfwtrace -d $B -m 0 -l 0 > "$D/restore.log" 2>&1 || true
: > $T/trace
marker; marker; sleep 12
grep -c mlx5_fw $T/trace > "$D/restore-silence-count.txt" || true
echo 0 > $T/events/mlx5/mlx5_fw/enable
pkill -f "b1_helpers[.]py poll" || true
echo done
