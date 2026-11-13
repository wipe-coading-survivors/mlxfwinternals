#!/bin/bash
# cx4lx-an task-05 attack#1, phase C (server side): CX-5 41:00.1 PDDR snapshots.
# Modes: dormant | era <dur_s>   (era = sampling loop after kick; kick done by caller)
set -u
MODE=${1:?dormant|era}
DUR=${2:-90}
OUT=/tmp/cx4lxan/t5/cx5-$MODE
mkdir -p "$OUT"
f0() { awk -F'|' '$1 ~ /ib_phy_fsm_state/{printf "ib=%s;",$2} $1 ~ /phy_mngr_fsm_state/{printf "pm=%s;",$2} $1 ~ /link_speed_active/ && !x{printf "lsa=%s;",$2; x=1} END{print ""}'; }
f2() { awk -F'|' '$1 ~ /num_of_negotiation_attempts/{printf "na=%s;",$2} $1 ~ /hw_link_phy_state/{printf "hw=%s;",$2} $1 ~ /ib_phy_fsm_state_trace/{printf "tr=%s;",$2} $1 ~ /sd_valid/{printf "sdv=%s;",$2} $1 ~ /signal_detected/{printf "sd=%s;",$2} END{print ""}'; }
snap() {
  local LP=$1 TAG=$2
  for PG in 0 2; do
    TS=$(date +%s.%N)
    RAW=$(timeout 15 mstreg -d 41:00.1 --reg_name PDDR --get -i page_select=$PG,local_port=$LP --yes </dev/null 2>/dev/null)
    if [ "$PG" = 0 ]; then F=$(printf '%s\n' "$RAW" | f0); else F=$(printf '%s\n' "$RAW" | f2); fi
    echo "$TS lp$LP pg$PG $TAG $F" >> "$OUT/poll.csv"
    printf '%s\n' "$RAW" >> "$OUT/raw.txt"; printf '@%s %s pg%s\n' "$TS" "$TAG" "$PG" >> "$OUT/raw.txt"
  done
}
if [ "$MODE" = dormant ]; then
  for LP in 1 2; do snap $LP dorm; sleep 4; done
  snap 2 dorm2
else
  T0=$(date +%s.%N)
  while :; do
    E=$(awk -v a="$(date +%s.%N)" -v b="$T0" 'BEGIN{print a-b}')
    awk -v e="$E" -v d="$DUR" 'BEGIN{exit !(e>=d)}' && break
    snap 1 era
    sleep 0.4
  done
fi
echo DONE >> "$OUT/poll.csv"
