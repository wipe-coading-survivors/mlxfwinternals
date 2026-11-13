#!/bin/bash
# cx4lx-an-fsm task-05 stage-2 closeout: bonus window on the WORKING QDR-AOC
# link (Lx bazzite 04:00.0 <-> CX-5 server 41:00.1). Purpose: working-case
# reference — in-window PDDR pg0/pg2 sampling (hw_link_phy_state expected
# 0x50 linkup, contrast to failing-case 0x30-0x43 loop) + any re-negotiation
# lines (enable/cl/clp) if the link recovers in-window. Recipe: docs/850-howto/150-fw-trace.md
# (server: capture-into-ring + gate-kick/flush-kick outside window, PDDR
# 0x5031 markers; bazzite: live tail). No mstlink inside the window.
set -u
ROLE=${1:?role}
WIN=${2:-150}
case $ROLE in
  bazzite) TRDEV=04:00.0; MARKDEV=04:00.0; CA=mlx5_2; MASK=0x4400C40; FLUSH=0; LP=1 ;;
  server)  TRDEV=41:00.0; MARKDEV=41:00.1; CA=mlx5_5; MASK=0x4400C40; FLUSH=1; LP=1 ;;
  *) echo bad-role; exit 2 ;;
esac
D=/tmp/cx4lxan/w6/$ROLE
mkdir -p "$D"
TFS=/sys/kernel/debug/tracing
NOW(){ date +%s.%N; }
pmark(){
  local T0 T1 LBL=$1
  T0=$(NOW)
  mstreg -d $MARKDEV --reg_name PDDR --get --yes </dev/null >/dev/null 2>&1
  T1=$(NOW)
  echo "$T0 $T1 $LBL" >> "$D/markers.txt"
}
p2f() {
  awk -F'|' '
    $1 ~ /num_of_negotiation_attempts/ {printf "na=%s;",$2}
    $1 ~ /hw_link_phy_state/ {printf "hw=%s;",$2}
    $1 ~ /ib_phy_fsm_state_trace/ {printf "tr=%s;",$2}
    END{print ""}'
}
p0f() {
  awk -F'|' '
    $1 ~ /ib_phy_fsm_state/ {printf "ib=%s;",$2}
    $1 ~ /phy_mngr_fsm_state/ {printf "pm=%s;",$2}
    END{print ""}'
}

{ NOW; ibstat "$CA"; } > "$D/pre-ibstat.txt" 2>&1
echo "$(NOW) ftrace-entry=$(cat $TFS/events/mlx5/mlx5_fw/enable)" > "$D/narrative.txt"

journalctl -k -f --no-pager > "$D/dmesg.log" 2>&1 &
DPID=$!
echo "$DPID" > "$D/dmesg.pid"

echo 1 > $TFS/events/mlx5/mlx5_fw/enable
nohup timeout $((WIN+400)) mstfwtrace -d $TRDEV -m $MASK -l 0 --ignore_old_events > "$D/window.log" 2>&1 &
MPID=$!
echo "$MPID" > "$D/mstfwtrace.pid"
echo "$(NOW) mstfwtrace-pid=$MPID mask=$MASK l=0 dev=$TRDEV markdev=$MARKDEV FLUSH=$FLUSH win=$WIN" >> "$D/narrative.txt"

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
T0=$(NOW)
N=0
while :; do
  EL=$(awk -v a="$(NOW)" -v b="$T0" 'BEGIN{print a-b}')
  if awk -v e="$EL" -v w="$WIN" 'BEGIN{exit !(e>=w)}'; then break; fi
  N=$((N+1))
  TS=$(NOW)
  RAW=$(timeout 15 mstreg -d $MARKDEV --reg_name PDDR --get -i page_select=2,local_port=$LP --yes </dev/null 2>/dev/null)
  F=$(printf '%s\n' "$RAW" | p2f)
  echo "$TS pg2 $F" >> "$D/poll.csv"
  if [ $((N % 3)) -eq 0 ]; then
    TS=$(NOW)
    RAW=$(timeout 15 mstreg -d $MARKDEV --reg_name PDDR --get -i page_select=0,local_port=$LP --yes </dev/null 2>/dev/null)
    F=$(printf '%s\n' "$RAW" | p0f)
    echo "$TS pg0 $F" >> "$D/poll.csv"
  fi
  if [ $((N % 30)) -eq 0 ]; then
    { echo "poll-$N $(NOW)"; ibstat "$CA" | grep -E "State:|Physical state:|Rate:"; } >> "$D/polls.txt" 2>&1
  fi
  sleep 10
done
echo "$(NOW) WINDOW-END" >> "$D/markers.txt"
pmark "end"

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
  pmark "silence-1"
  sleep 5
  pmark "silence-2"
  sleep 10
  wait "$SPID" 2>/dev/null
else
  nohup timeout 30 mstfwtrace -d $TRDEV -m 0 -l 0 --ignore_old_events > "$D/silence.log" 2>&1 &
  SPID=$!
  sleep 3
  pmark "silence-1"
  sleep 5
  pmark "silence-2"
  wait "$SPID" 2>/dev/null
fi

echo 0 > $TFS/events/mlx5/mlx5_fw/enable
kill "$DPID" 2>/dev/null
{ NOW; ibstat "$CA"; } > "$D/post-ibstat.txt" 2>&1
{
  echo "$(NOW) DONE"
  echo "window-log-lines: $(wc -l < "$D/window.log")"
  echo "pddr-in-window: $(grep -c 0x5031 "$D/window.log" || true)"
  echo "nego-lines: $(grep -c "ib_speed_nego" "$D/window.log" || true)"
  echo "clp-lines: $(grep -c "clp" "$D/window.log" || true)"
  echo "lost: $(grep -c "Events were lost" "$D/window.log" || true)"
  echo "polls: $(wc -l < "$D/poll.csv")"
} >> "$D/narrative.txt"
