#!/bin/bash
# T2d-2 analyze: decode-free ev-log phase analysis of the Eth-branch armed
# window (cable re-plugs + Eth-AN handshake vs the multi-rate Eth switch).
# Input: ev-dac.log (drained, no losses: total_events == ev-log event lines).
# Phases are marked by module_management_init_sm transitions, phy_manager
# events, eth_speed_nego (Eth AN FSM) state walk and kr_startup bursts.
# Hook strings: H-AN 0x00ae58cd = "ib_force_edr_fsm: config_tx_sd_set",
# H-DEC 0x00ad7547 = "bw should be less than network speed".
# Usage: analyze_run1.sh [ev-log] (default: alongside this script's raw dir)
set -u
EV=${1:-$(cd "$(dirname "$0")/../../../../build/raw/t2d/run1" && pwd)/ev-dac.log}
T0=$(head -1 "$EV" | grep -oE "^[0-9]+")
out() { awk -F'[][]' -v t0="$T0" '{split($1,a," "); printf "%+9.2fs %s\n", (a[1]-t0)/1000, $0}' ; }

echo "== window =="
W1=$(tail -1 "$EV" | grep -oE "^[0-9]+")
echo "first=$T0 last=$W1 span_ms=$((W1-T0))"
echo "event lines: $(grep -cE '^[0-9]+ \[0x[0-9a-f?]+\] 0 \[0x' "$EV") (must equal drain total_events)"

echo; echo "== hooks (whole window) =="
echo "H-AN (ib_force_edr_fsm: config_tx_sd_set): $(grep -c 'ib_force_edr_fsm: config_tx_sd_set' "$EV")"
echo "H-DEC (bw should be less than network speed): $(grep -c 'bw should be less than network speed' "$EV")"

echo; echo "== MM init_sm transitions (self-loops removed) =="
grep -E "module_management_init_sm: curr_state" "$EV" \
  | awk -F'[][]' -v t0="$T0" '{split($1,a," "); t=(a[1]-t0)/1000; match($0,/curr_state = [0-9]+, next_state = [0-9]+/);
      s=substr($0,RSTART,RLENGTH); gsub(/curr_state = |, next_state = /," ",s); gsub(/ +/," ",s);
      if (s !~ /^( 2 2|13 13|1 1|9 9|5 5|20 20|19 19)$/) printf "+%8.2fs %s\n", t, s}'
grep -E "MM_INIT_PARSE_PAGE" "$EV" | out | sed 's/^/  /' | cut -c1-110

echo; echo "== phy_manager events / state walk (AN-state self-loops removed) =="
grep -E "phy_manager_set_next_state" "$EV" \
  | awk -F'[][]' -v t0="$T0" '{split($1,a," "); t=(a[1]-t0)/1000; match($0,/curr_state: [0-9]+ next_state: [0-9]+\. new_next_state: [0-9]+|event: [0-9]+/);
      s=substr($0,RSTART,RLENGTH); if (s !~ /^curr_state: 3 next_state: 3/) printf "+%8.2fs %s\n", t, s}'

echo; echo "== Eth AN FSM (eth_speed_nego) non-storm transitions =="
grep -E "eth_speed_nego local" "$EV" | out \
  | grep -vE "0x3->0x4|0x4->0x7|0x7->0x3" | cut -c1-110
grep -E "starting KR port" "$EV" | out | sed 's/^/  /'

echo; echo "== speed_2_pll_mask ETH =="
grep -E "in speed_2_pll_mask.*ETH|enabled_active_" "$EV" | out | cut -c1-110 | grep -B1 "ETH"

echo; echo "== pcs_link_status =="
grep "get_pcs_link_status_hal" "$EV" | out | cut -c1-120

echo; echo "== kr_startup by 10s bucket =="
grep "kr_startup" "$EV" | awk -v t0="$T0" '{printf "%d\n", int(($1-t0)/10000)}' | sort -n | uniq -c \
  | awk '{printf "+%d0..+%d0s %s\n", $2, $2+1, $1}'

echo; echo "== get_connector_type by type and bucket =="
for ty in 4 1; do
  echo "type=$ty total $(grep -cE "type=$ty(\$| )" "$EV")"
  grep -E "^[0-9]+ \[0x" "$EV" | grep -E "type=$ty(\$| )" \
    | awk -v t0="$T0" '{printf "%d\n", int(($1-t0)/10000)}' | sort -n | uniq -c \
    | awk -v ty="$ty" '{printf "  +%d0..+%d0s %s\n", $2, $2+1, $1}'
done

echo; echo "== intensity by 10s bucket (event lines) =="
grep -E "^[0-9]+ \[0x" "$EV" | awk -v t0="$T0" '{printf "%d\n", int(($1-t0)/10000)}' | sort -n | uniq -c \
  | awk '{printf "+%d0..+%d0s %s\n", $2, $2+1, $1}'

echo; echo "== external ICMD query bursts (PDDR/MCAM/PAOS reads, not ours) =="
grep -E "register_id=0x(5031|907f|504c)|reg_access_paos" "$EV" | out | cut -c1-110 | head -12
