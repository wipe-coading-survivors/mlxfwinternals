#!/bin/bash
# cx4lx-an-fsm task-01 window v3: server = capture-into-ring + post-window
# mstlink flush (drain path unreliable post-wedge); bazzite = live tail (proven);
# arm gate = PDDR(0x5031) markers (0x9040 emission dead post-wedge) + flush-kick
# on server before the check; abort if markers missing.
set -u
ROLE=${1:?role}
case $ROLE in
  bazzite) TRDEV=04:00.0; MARKDEV=04:00.0; CA=mlx5_2; MASK=0x4400C40; FLUSH=0 ;;
  server)  TRDEV=41:00.0; MARKDEV=41:00.1; CA=mlx5_5; MASK=0x4400C40; FLUSH=1 ;;
  *) echo bad-role; exit 2 ;;
esac
D=/tmp/cx4lxan/${ROLE}4
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
pmark(){
  local T0 T1 LBL=$1
  T0=$(NOW)
  mstreg -d $MARKDEV --reg_name PDDR --get --yes </dev/null >/dev/null 2>&1
  T1=$(NOW)
  echo "$T0 $T1 $LBL" >> "$D/markers.txt"
}

{ NOW; ibstat "$CA"; } > "$D/pre-ibstat.txt" 2>&1
echo "$(NOW) ftrace-entry=$(cat $TFS/events/mlx5/mlx5_fw/enable)" >> "$D/narrative.txt"

journalctl -k -f --no-pager > "$D/dmesg.log" 2>&1 &
DPID=$!
echo "$DPID" > "$D/dmesg.pid"

echo 1 > $TFS/events/mlx5/mlx5_fw/enable
nohup timeout 900 mstfwtrace -d $TRDEV -m $MASK -l 0 --ignore_old_events > "$D/window.log" 2>&1 &
MPID=$!
echo "$MPID" > "$D/mstfwtrace.pid"
echo "$(NOW) mstfwtrace-pid=$MPID mask=$MASK l=0 dev=$TRDEV markdev=$MARKDEV FLUSH=$FLUSH" >> "$D/narrative.txt"

sleep 2
for i in $(seq 1 15); do pmark "arm-$i"; sleep 3; done
if [ "$FLUSH" = 1 ]; then
  mstlink -d 41:00.1 -m > "$D/gate-kick.txt" 2>&1
  echo "$(NOW) gate-kick-done" >> "$D/narrative.txt"
  sleep 8
fi
ARMOK=$(grep -c 0x5031 "$D/window.log" || true)
echo "$(NOW) arm-verify pddr=$ARMOK" >> "$D/narrative.txt"
if [ "$ARMOK" -lt 6 ]; then
  echo "$(NOW) ABORT-arm-failed" >> "$D/narrative.txt"
  kill "$MPID" 2>/dev/null; wait "$MPID" 2>/dev/null
  timeout 12 mstfwtrace -d $TRDEV -m 0 -l 0 > "$D/restore.log" 2>&1
  echo 0 > $TFS/events/mlx5/mlx5_fw/enable
  kill "$DPID" 2>/dev/null
  exit 3
fi

echo "$(NOW) WINDOW-START" >> "$D/markers.txt"
for p in $(seq 1 20); do
  { echo "poll-$p $(NOW)"; ibstat "$CA" | grep -E "State:|Physical state:|Rate:"; } >> "$D/polls.txt" 2>&1
  for m in 1 2 3 4 5 6 7 8 9 10; do
    mark "a$p$m"
    sleep 3
  done
done
echo "$(NOW) WINDOW-END" >> "$D/markers.txt"
mark "end"

if [ "$FLUSH" = 1 ]; then
  mstlink -d 41:00.1 -m > "$D/flush-mstlink.txt" 2>&1
  echo "$(NOW) flush-kick-1-done" >> "$D/narrative.txt"
  sleep 8
  mstlink -d 41:00.1 > "$D/flush-mstlink2.txt" 2>&1
  echo "$(NOW) flush-kick-2-done" >> "$D/narrative.txt"
  sleep 8
else
  sleep 2
fi

kill "$MPID" 2>/dev/null
wait "$MPID" 2>/dev/null
echo "$(NOW) window-mstfwtrace-killed lines=$(wc -l < "$D/window.log")" >> "$D/narrative.txt"

timeout 12 mstfwtrace -d $TRDEV -m 0 -l 0 > "$D/restore.log" 2>&1
echo "restore-rc=$?" >> "$D/restore.log"

if [ "$FLUSH" = 1 ]; then
  nohup timeout 40 mstfwtrace -d $TRDEV -m 0 -l 0 --ignore_old_events > "$D/silence.log" 2>&1 &
  SPID=$!
  sleep 2
  mstlink -d 41:00.1 > "$D/silence-kick.txt" 2>&1
  mark "silence-1"
  sleep 5
  mark "silence-2"
  sleep 10
  wait "$SPID" 2>/dev/null
else
  nohup timeout 30 mstfwtrace -d $TRDEV -m 0 -l 0 --ignore_old_events > "$D/silence.log" 2>&1 &
  SPID=$!
  sleep 3
  mark "silence-1"
  sleep 5
  mark "silence-2"
  wait "$SPID" 2>/dev/null
fi

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
