#!/bin/bash
# Stage B: control trace on v5r, NO VFIO window.
# ftrace-event enable -> mstfwtrace (owner f1, -m ICMD -l 1) -> mstreg
# MTRC_CAP GET x5 (81:00.0) -> wait -> restore (mask 0, ftrace off).
ts() { date -u +%FT%T.%3N; }

ts
pgrep -a mstfwtrace || echo "no-mstfwtrace-before"
echo "ftrace_enable_before=$(cat /sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable)"
# 1) ftrace-event enable (owner function f1 = 81:00.1, stays on mlx5_core)
echo 1 > /sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable
echo "rc_ftrace_enable=$?"
ts
# 2) trace (owner = f1!)
timeout 60 mstfwtrace -d 0000:81:00.1 -m ICMD -l 1 --ignore_old_events \
    > /tmp/fwtrace-v5r-control.log 2>&1 &
TRACE_PID=$!
echo "trace_pid=$TRACE_PID"
ts
# 3) settle
sleep 5
ts
if ! kill -0 $TRACE_PID 2>/dev/null; then
    echo "ABORT: mstfwtrace died before markers; log head:"
    head -20 /tmp/fwtrace-v5r-control.log
    exit 1
fi
echo "--- trace log head (after sleep 5):"
head -5 /tmp/fwtrace-v5r-control.log
# 4) markers: mstreg GET MTRC_CAP x5 on 81:00.0 (config space, no driver)
for i in 1 2 3 4 5; do
    mstreg -d 0000:81:00.0 --get --reg_name MTRC_CAP >/dev/null 2>&1
    echo "marker_$i rc=$? ts=$(ts)"
    sleep 2
done
ts
# 5) wait for trace to finish (timeout 60 inside)
wait $TRACE_PID
echo "rc_trace=$?"
ts
# 6) restore: mask 0
timeout 12 mstfwtrace -d 0000:81:00.1 -m 0 -l 0 > /tmp/fwtrace-v5r-control-restore.log 2>&1
echo "rc_mask0=$? (124=timeout-expected)"
# 6b) mask-0 carrier check: clear buffer, mstreg x2, wait ~15s, count mlx5_fw
: > /sys/kernel/debug/tracing/trace
echo "cleared ts=$(ts)"
mstreg -d 0000:81:00.0 --get --reg_name MTRC_CAP >/dev/null 2>&1
echo "carrier_1 rc=$?"
mstreg -d 0000:81:00.0 --get --reg_name MTRC_CAP >/dev/null 2>&1
echo "carrier_2 rc=$?"
sleep 15
echo "mlx5_fw_events_after_mask0=$(grep -c 'mlx5_fw:' /sys/kernel/debug/tracing/trace)"
grep 'mlx5_fw:' /sys/kernel/debug/tracing/trace | tail -5
# 7) ftrace off + final buffer state
echo 0 > /sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable
echo "rc_ftrace_disable=$?"
: > /sys/kernel/debug/tracing/trace
echo "final_trace_lines=$(wc -l < /sys/kernel/debug/tracing/trace)"
echo "ftrace_enable_after=$(cat /sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable)"
ts
echo "STAGE-B-DONE"
