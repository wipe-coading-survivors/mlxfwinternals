#!/bin/bash
# cx4lx-an task-05 attack#1: PDDR page poller (read-only).
# Usage: pddr-poll.sh <outdir> <duration_s> [pages: "0 2"] [interval_s=0.12]
# Each sample: epoch_ns, page, then selected fields as key=val CSV.
set -u
OUT=${1:?outdir}; DUR=${2:?duration_s}
PAGES=${3:-"0 2"}
INTV=${4:-0.12}
mkdir -p "$OUT"
DEV=04:00.0

fields0() { # from page 0 output
  awk -F'|' '
    $1 ~ /ib_phy_fsm_state/ && !p0ib {printf "ib=%s;",$2; p0ib=1}
    $1 ~ /phy_mngr_fsm_state/ {printf "pm=%s;",$2}
    $1 ~ /eth_an_fsm_state/ {printf "ea=%s;",$2}
    $1 ~ /link_speed_active/ && !p0ls {printf "lsa=%s;",$2; p0ls=1}
    END{print ""}'
}
fields2() { # from page 2 output
  awk -F'|' '
    $1 ~ /num_of_negotiation_attempts/ {printf "na=%s;",$2}
    $1 ~ /hw_link_phy_state/ {printf "hw=%s;",$2}
    $1 ~ /num_of_presets_tested_lane3/ {printf "p3=%s;",$2}
    $1 ~ /num_of_presets_tested_lane2/ {printf "p2=%s;",$2}
    $1 ~ /num_of_presets_tested_lane1/ {printf "p1=%s;",$2}
    $1 ~ /num_of_presets_tested_lane0/ && !pp0 {printf "p0=%s;",$2; pp0=1}
    $1 ~ /ib_phy_fsm_state_trace/ {printf "tr=%s;",$2}
    $1 ~ /sd_valid/ {printf "sdv=%s;",$2}
    $1 ~ /plu_tx_speed/ {printf "txt=%s;",$2}
    $1 ~ /plu_rx_speed/ {printf "rxs=%s;",$2}
    $1 ~ /signal_detected/ {printf "sd=%s;",$2}
    $1 ~ /ib_revision/ {printf "ibr=%s;",$2}
    END{print ""}'
}

T0=$(date +%s.%N)
while :; do
  NOW=$(date +%s.%N)
  ELAPSED=$(awk -v a="$NOW" -v b="$T0" 'BEGIN{print a-b}')
  if awk -v e="$ELAPSED" -v d="$DUR" 'BEGIN{exit !(e>=d)}'; then break; fi
  for PG in $PAGES; do
    TS=$(date +%s.%N)
    RAW=$(timeout 15 mstreg -d $DEV --reg_name PDDR --get \
            -i page_select=$PG,local_port=1 --yes </dev/null 2>/dev/null)
    if [ "$PG" = 0 ]; then F=$(printf '%s\n' "$RAW" | fields0)
    else F=$(printf '%s\n' "$RAW" | fields2); fi
    echo "$TS pg$PG $F" >> "$OUT/poll.csv"
    printf '%s\n' "$RAW" >> "$OUT/raw_pg$PG.txt"
    printf '@%s\n' "$TS" >> "$OUT/raw_pg$PG.txt"
  done
  sleep "$INTV"
done
echo "DONE $(date +%s.%N) samples=$(wc -l < "$OUT/poll.csv")" >> "$OUT/poll.csv"
