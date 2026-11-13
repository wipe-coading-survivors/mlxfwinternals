#!/bin/bash
# cx4lx-an task-05 attack#1, phase B: iTrace window (bazzite Lx) with
# integrated PDDR pg2 fast-poll. Polls double as 0x5031 markers (alignment).
# Recipe: docs/850-howto/150-fw-trace.md + window4.sh bazzite role. No mstlink anywhere.
set -u
D=/tmp/cx4lxan/t5/phaseB
mkdir -p "$D"
DEV=04:00.0; CA=mlx5_2; MASK=0x4400C40
TFS=/sys/kernel/debug/tracing
WIN=${1:-150}
NOW(){ date +%s.%N; }
pmark(){
  local T0 T1 LBL=$1
  T0=$(NOW)
  mstreg -d $DEV --reg_name PDDR --get --yes </dev/null >/dev/null 2>&1
  T1=$(NOW)
  echo "$T0 $T1 $LBL" >> "$D/markers.txt"
}
p2f() {
  awk -F'|' '
    $1 ~ /num_of_negotiation_attempts/ {printf "na=%s;",$2}
    $1 ~ /hw_link_phy_state/ {printf "hw=%s;",$2}
    $1 ~ /ib_phy_fsm_state_trace/ {printf "tr=%s;",$2}
    $1 ~ /signal_detected/ {printf "sd=%s;",$2}
    END{print ""}'
}
p0f() {
  awk -F'|' '
    $1 ~ /ib_phy_fsm_state/ {printf "ib=%s;",$2}
    END{print ""}'
}

{ NOW; ibstat "$CA"; } > "$D/pre-ibstat.txt" 2>&1
echo "$(NOW) ftrace-entry=$(cat $TFS/events/mlx5/mlx5_fw/enable)" > "$D/narrative.txt"

journalctl -k -f --no-pager > "$D/dmesg.log" 2>&1 &
DPID=$!

echo 1 > $TFS/events/mlx5/mlx5_fw/enable
nohup timeout $((WIN+400)) mstfwtrace -d $DEV -m $MASK -l 0 --ignore_old_events > "$D/window.log" 2>&1 &
MPID=$!
echo "$(NOW) mstfwtrace-pid=$MPID mask=$MASK l=0 dev=$DEV win=$WIN" >> "$D/narrative.txt"

sleep 2
for i in $(seq 1 15); do pmark "arm-$i"; sleep 3; done
ARMOK=$(grep -c 0x5031 "$D/window.log" || true)
echo "$(NOW) arm-verify pddr=$ARMOK" >> "$D/narrative.txt"
if [ "$ARMOK" -lt 6 ]; then
  echo "$(NOW) ABORT-arm-failed" >> "$D/narrative.txt"
  kill "$MPID" 2>/dev/null; wait "$MPID" 2>/dev/null
  timeout 12 mstfwtrace -d $DEV -m 0 -l 0 > "$D/restore.log" 2>&1
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
  RAW=$(timeout 15 mstreg -d $DEV --reg_name PDDR --get -i page_select=2,local_port=1 --yes </dev/null 2>/dev/null)
  F=$(printf '%s\n' "$RAW" | p2f)
  echo "$TS pg2 $F" >> "$D/poll.csv"
  if [ $((N % 5)) -eq 0 ]; then
    TS=$(NOW)
    RAW=$(timeout 15 mstreg -d $DEV --reg_name PDDR --get -i page_select=0,local_port=1 --yes </dev/null 2>/dev/null)
    F=$(printf '%s\n' "$RAW" | p0f)
    echo "$TS pg0 $F" >> "$D/poll.csv"
  fi
done
echo "$(NOW) WINDOW-END" >> "$D/markers.txt"
mark_end(){ pmark "end"; }
mark_end

kill "$MPID" 2>/dev/null
wait "$MPID" 2>/dev/null
echo "$(NOW) window-mstfwtrace-killed lines=$(wc -l < "$D/window.log")" >> "$D/narrative.txt"

timeout 12 mstfwtrace -d $DEV -m 0 -l 0 > "$D/restore.log" 2>&1
echo "restore-rc=$?" >> "$D/restore.log"

nohup timeout 30 mstfwtrace -d $DEV -m 0 -l 0 --ignore_old_events > "$D/silence.log" 2>&1 &
SPID=$!
sleep 3
pmark "silence-1"
sleep 5
pmark "silence-2"
wait "$SPID" 2>/dev/null

echo 0 > $TFS/events/mlx5/mlx5_fw/enable
kill "$DPID" 2>/dev/null
{ NOW; ibstat "$CA"; } > "$D/post-ibstat.txt" 2>&1
{
  echo "$(NOW) DONE"
  echo "window-log-lines: $(wc -l < "$D/window.log")"
  echo "pddr-in-window: $(grep -c 0x5031 "$D/window.log" || true)"
  echo "nego-lines: $(grep -c "ib_speed_nego" "$D/window.log" || true)"
  echo "lost: $(grep -c "Events were lost" "$D/window.log" || true)"
  echo "polls: $(wc -l < "$D/poll.csv")"
} >> "$D/narrative.txt"
