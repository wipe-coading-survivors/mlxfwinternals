#!/bin/bash
# cx4lx-an-fsm task-01: two-sided AN-loop trace window (NO burns, read-only + mask)
# usage: window.sh <bazzite|server>
set -u
ROLE=${1:?role}
case $ROLE in
  bazzite) TRDEV=04:00.0; MARKDEV=04:00.0; CA=mlx5_2 ;;
  server)  TRDEV=41:00.0; MARKDEV=41:00.1; CA=mlx5_5 ;;
  *) echo bad-role; exit 2 ;;
esac
D=/tmp/cx4lxan/$ROLE
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

journalctl -k -f --no-pager > "$D/dmesg.log" 2>&1 &
DPID=$!
echo "$DPID" > "$D/dmesg.pid"

echo 1 > $TFS/events/mlx5/mlx5_fw/enable
nohup timeout 400 mstfwtrace -d $TRDEV -m 0x4400C40 -l 0 --ignore_old_events > "$D/window.log" 2>&1 &
MPID=$!
echo "$MPID" > "$D/mstfwtrace.pid"
echo "$(NOW) mstfwtrace-pid=$MPID mask=0x4400C40 l=0 dev=$TRDEV markdev=$MARKDEV" >> "$D/narrative.txt"

sleep 2
for i in 1 2 3 4 5 6; do mark "arm-$i"; sleep 3; done

echo "$(NOW) WINDOW-START" >> "$D/markers.txt"
for p in 1 2 3 4 5 6 7 8 9 10; do
  sleep 30
  { echo "poll-$p $(NOW)"; ibstat "$CA" | grep -E "State:|Physical state:|Rate:"; } >> "$D/polls.txt" 2>&1
  case $p in 1|3|5|7|9) mark "anchor-$p" ;; esac
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
  echo "stray-procs:"
  pgrep -af "mstfwtrace|journalctl" || echo none
  echo "window-log-lines: $(wc -l < "$D/window.log")"
  echo "icmd-in-window: $(grep -c icmd_generic_reg_access "$D/window.log" || true)"
} >> "$D/narrative.txt"
