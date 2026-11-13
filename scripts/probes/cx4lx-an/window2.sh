#!/bin/bash
# cx4lx-an-fsm task-01 RETRY window (v2): server-side fixes = mstlink kick (outside
# window), mask 0x4000C40 -l 0 (drop MANAGEMENT spin), marker heartbeat ~3 s
# (keeps tracer drain path alive), arm-verification gate.
# usage: window2.sh <bazzite|server>
set -u
ROLE=${1:?role}
case $ROLE in
  bazzite) TRDEV=04:00.0; MARKDEV=04:00.0; CA=mlx5_2;  MASK=0x4400C40; KICK=0 ;;
  server)  TRDEV=41:00.0; MARKDEV=41:00.1; CA=mlx5_5;  MASK=0x4000C40; KICK=1 ;;
  *) echo bad-role; exit 2 ;;
esac
D=/tmp/cx4lxan/${ROLE}2
mkdir -p "$D"
TFS=/sys/kernel/debug/tracing
NOW(){ date +%s.%N; }
mark(){
  local T0 T1 LBL=$1
  T0=$(NOW)
  mstreg -d $MARKDEV --reg_name MTRC_CAP --get --yes </dev/null >/dev/null 2>&1
  T1=$(NOW)
  echo "$T0 $T1 $LBL" >> "$D/markers.txt"
}

{ NOW; ibstat "$CA"; } > "$D/pre-ibstat.txt" 2>&1
echo "$(NOW) ftrace-entry=$(cat $TFS/events/mlx5/mlx5_fw/enable)" >> "$D/narrative.txt"

if [ "$KICK" = 1 ]; then
  mstlink -d 41:00.1 -m > "$D/kick-mstlink.txt" 2>&1
  echo "$(NOW) mstlink-kick-done" >> "$D/narrative.txt"
fi

journalctl -k -f --no-pager > "$D/dmesg.log" 2>&1 &
DPID=$!
echo "$DPID" > "$D/dmesg.pid"

echo 1 > $TFS/events/mlx5/mlx5_fw/enable
nohup timeout 460 mstfwtrace -d $TRDEV -m $MASK -l 0 --ignore_old_events > "$D/window.log" 2>&1 &
MPID=$!
echo "$MPID" > "$D/mstfwtrace.pid"
echo "$(NOW) mstfwtrace-pid=$MPID mask=$MASK l=0 dev=$TRDEV markdev=$MARKDEV" >> "$D/narrative.txt"

sleep 2
for i in 1 2 3 4 5 6 7 8 9 10; do mark "arm-$i"; sleep 3; done

ARMOK=$(grep -c icmd_generic_reg_access "$D/window.log" || true)
echo "$(NOW) arm-verify icmd=$ARMOK" >> "$D/narrative.txt"
if [ "$ARMOK" -lt 6 ]; then
  echo "$(NOW) ABORT-arm-failed" >> "$D/narrative.txt"
  kill "$MPID" 2>/dev/null; wait "$MPID" 2>/dev/null
  timeout 12 mstfwtrace -d $TRDEV -m 0 -l 0 > "$D/restore.log" 2>&1
  echo 0 > $TFS/events/mlx5/mlx5_fw/enable
  kill "$DPID" 2>/dev/null
  exit 3
fi

echo "$(NOW) WINDOW-START" >> "$D/markers.txt"
for p in 1 2 3 4 5 6 7 8 9 10; do
  { echo "poll-$p $(NOW)"; ibstat "$CA" | grep -E "State:|Physical state:|Rate:"; } >> "$D/polls.txt" 2>&1
  for m in 1 2 3 4 5 6 7 8 9 10; do
    mark "a$p$m"
    sleep 3
  done
done
echo "$(NOW) WINDOW-END" >> "$D/markers.txt"

mark "end"
sleep 2
kill "$MPID" 2>/dev/null
wait "$MPID" 2>/dev/null
echo "$(NOW) window-mstfwtrace-killed" >> "$D/narrative.txt"

timeout 12 mstfwtrace -d $TRDEV -m 0 -l 0 > "$D/restore.log" 2>&1
echo "restore-rc=$?" >> "$D/restore.log"

nohup timeout 30 mstfwtrace -d $TRDEV -m 0 -l 0 --ignore_old_events > "$D/silence.log" 2>&1 &
SPID=$!
sleep 3
mark "silence-1"
sleep 5
mark "silence-2"
wait "$SPID" 2>/dev/null

echo 0 > $TFS/events/mlx5/mlx5_fw/enable
kill "$DPID" 2>/dev/null
{ NOW; ibstat "$CA"; } > "$D/post-ibstat.txt" 2>&1
{
  echo "$(NOW) DONE"
  echo "window-log-lines: $(wc -l < "$D/window.log")"
  echo "icmd-in-window: $(grep -c icmd_generic_reg_access "$D/window.log" || true)"
  echo "nego-lines: $(grep -c "ib_speed_nego" "$D/window.log" || true)"
  echo "lost: $(grep -c "Events were lost" "$D/window.log" || true)"
} >> "$D/narrative.txt"
