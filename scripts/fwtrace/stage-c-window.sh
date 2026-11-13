#!/bin/bash
# Stage C: 0x0932 probe (v5q, mode B, frame B_F40) under mstfwtrace
# (owner f1 = 81:00.1). Single window: ftrace-event enable -> trace ->
# mstreg marker DO -> VFIO window 81:00.0 (S3 bind-dance, trap-protected
# rebind) -> probe -> close window -> mstreg marker POSLE -> wait for trace.
ts() { date -u +%FT%T.%3N; }

ts
# 0) sanity
pgrep -a mstfwtrace || echo "no-mstfwtrace-before"
echo "ftrace_enable_before=$(cat /sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable)"
echo "driver_before=$(readlink -f /sys/bus/pci/devices/0000:81:00.0/driver)"
# 1) ftrace-event enable (owner function f1 = 81:00.1, stays on mlx5_core)
echo 1 > /sys/kernel/debug/tracing/events/mlx5/mlx5_fw/enable
echo "rc_ftrace_enable=$?"
ts
# 2) trace (owner = f1!; mask = ICMD — worked in Stage B)
timeout 120 mstfwtrace -d 0000:81:00.1 -m ICMD -l 1 --ignore_old_events \
    > /tmp/fwtrace-0932-v5q.log 2>&1 &
TRACE_PID=$!
echo "trace_pid=$TRACE_PID"
ts
# 3) settle
sleep 5
ts
# liveness gate: trace must be alive before the probe
if ! kill -0 $TRACE_PID 2>/dev/null; then
    echo "ABORT: mstfwtrace died before probe; log head:"
    head -20 /tmp/fwtrace-0932-v5q.log
    exit 1
fi
echo "--- trace log head (after sleep 5):"
head -5 /tmp/fwtrace-0932-v5q.log
# 4) marker DO (config space, no driver required)
mstreg -d 0000:81:00.0 --get --reg_name MTRC_CAP >/dev/null 2>&1
echo "rc_marker_do=$?"
ts
# 5) VFIO window 81:00.0 (S3 bind-dance; plan order: new_id -> unbind -> bind)
ip link set enp129s0f0np0 down
echo "rc_ip_down=$?"
modprobe vfio-pci
echo "rc_modprobe=$?"
echo "15b3 1019" > /sys/bus/pci/drivers/vfio-pci/new_id
echo "rc_new_id=$?"
echo 0000:81:00.0 > /sys/bus/pci/drivers/mlx5_core/unbind
rc_unbind=$?
echo "rc_unbind=$rc_unbind"
# trap-protected rebind on EXIT (safety net for any failure below)
trap 'echo 0000:81:00.0 > /sys/bus/pci/drivers/vfio-pci/unbind 2>&1; \
      echo 0000:81:00.0 > /sys/bus/pci/drivers/mlx5_core/bind 2>&1' EXIT
if [ $rc_unbind -ne 0 ]; then
    echo "ABORT: unbind from mlx5_core failed rc=$rc_unbind (not forcing)"
    exit 2
fi
drv=$(readlink -f /sys/bus/pci/devices/0000:81:00.0/driver)
echo "driver_after_unbind=$drv"
rc_bind=0
if [ "$drv" != "/sys/bus/pci/drivers/vfio-pci" ]; then
    echo 0000:81:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
    rc_bind=$?
    echo "rc_bind=$rc_bind"
fi
echo "driver_now=$(readlink -f /sys/bus/pci/devices/0000:81:00.0/driver)"
if [ $rc_bind -ne 0 ] || [ "$(readlink -f /sys/bus/pci/devices/0000:81:00.0/driver)" != "/sys/bus/pci/drivers/vfio-pci" ]; then
    echo "ABORT: device not bound to vfio-pci (not forcing)"
    exit 2
fi
ts
# 6) probe 0x0932 (mode B, frame B_F40) on 0000:81:00.0
#    (mlxscope does FLR+InitHCA on open: VfioCmdIf::open_from_sysfs(reset=true, init=true))
/tmp/mlxscope/mlxscope --device /sys/bus/pci/devices/0000:81:00.0 \
  --detour-mode B \
  --input-hex 093200000000000000000000000400000001533200600001258c53326c04638afd001825 \
  > /tmp/mlxscope/probe-0932-v5q.log 2>&1
rc_probe=$?
echo "rc_probe=$rc_probe"
cat /tmp/mlxscope/probe-0932-v5q.log | grep -vE "buf (cqe_page|in_mb0|out_mb0) len=.*hex=0{40,}"
ts
# 7) close the window
echo 0000:81:00.0 > /sys/bus/pci/drivers/vfio-pci/unbind
echo "rc_window_unbind=$?"
echo 0000:81:00.0 > /sys/bus/pci/drivers/mlx5_core/bind
echo "rc_window_bind=$?"
echo "15b3 1019" > /sys/bus/pci/drivers/vfio-pci/remove_id
echo "rc_remove_id=$?"
ip link set enp129s0f0np0 up
echo "rc_ip_up=$?"
sleep 3
echo "driver_final=$(readlink -f /sys/bus/pci/devices/0000:81:00.0/driver)"
trap - EXIT
ts
# 8) marker POSLE
mstreg -d 0000:81:00.0 --get --reg_name MTRC_CAP >/dev/null 2>&1
echo "rc_marker_posle=$?"
ts
# 9) wait for trace to finish (timeout 120 inside)
wait $TRACE_PID
echo "rc_trace=$?"
ts
echo "WINDOW-DONE"
