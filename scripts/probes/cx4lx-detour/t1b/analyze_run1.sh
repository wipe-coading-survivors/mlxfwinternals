#!/bin/bash
# T1-B2 offline analysis: decode the phase-B FDR ev-log with the phase-A
# pipeline (t1/parse_trace.py) + targeted QDR-vs-FDR diff extracts
# (speed words, AN round intervals, MM/dump-family presence, ICMD markers).
# Usage: analyze_run1.sh <ev-log>  (run from the raw dir; writes *.log)
set -u
EV=${1:?usage: analyze_run1.sh <ev-log>}
HERE=$(cd "$(dirname "$0")" && pwd)
PARSE=$HERE/../t1/parse_trace.py
TICKS_PER_MS=1073   # calibrated in phase A (both windows + PAOS cadence)

echo "== parse_trace ($EV) =="
python3 "$PARSE" "$EV" | tee parse-run1.log

echo; echo "== diff extracts =="
{
echo "-- outcome words --"
echo "cnf_test lines:        $(grep -c 'cnf_test' "$EV" || true)"
echo "set timers in cfg_test: $(grep -c 'set timers in cfg_test' "$EV" || true)"
grep -oE "default_ts3_speed=0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/default_ts3: /'
grep -oE "chosen_mask=0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/preset_mask: /'
echo "-- init_ib_an_fsm full samples + count --"
grep -c "init_ib_an_fsm" "$EV"
grep -m2 "init_ib_an_fsm" "$EV"
echo "-- dispatcher input_event histogram --"
grep -oE "ib_speed_nego: generic, pport 1, prev_state_or_event 0x[0-9a-f]+, input_event 0x[0-9a-f]+, verifier returned [0-9]+" "$EV" \
    | sed -E 's/pport 1, //' | sort | uniq -c | sort -rn | head -12
echo "-- families present/absent (vs phase A) --"
for k in "cable_module_read_write" "module_management_init_sm" "Port 0" "phy2module_handler" \
         "speed_2_pll_mask" "reg_access_pddr" "reg_access_paos" "hal_get_ib_speed_and_width" \
         "isr_icmd" "icmd_generic" "smbus_get_teans_status" "pmaos" "link_maintenance"; do
    printf '%-28s %s\n' "$k:" "$(grep -ci "$k" "$EV" || true)"
done
echo "-- MM burst wall span (tool-triggered check) --"
grep "cable_module_read_write" "$EV" | sed -n '1p;$p'
echo "-- AN window --"
grep -E "ib_speed_nego" "$EV" | sed -n '1p;$p'
echo "-- init_ib_an_fsm fw-ts (for interval med from parse-run1.log) --"
awk '/init_ib_an_fsm/ {print $2}' "$EV" | head -3
} | tee diff-extracts.log

echo; echo "== init round cadence (ms, fw-ts deltas / $TICKS_PER_MS) =="
awk '/init_ib_an_fsm/ {match($0, /\[0x([0-9a-f]+)\]/, a); if (a[1] != "") print strtonum("0x" a[1])}' "$EV" \
  | awk -v T=$TICKS_PER_MS 'NR>1 {d=$1-p; if (d>0) print d/T} {p=$1}' \
  | sort -n | awk '{v[NR]=$1} END {if (NR) printf "n=%d min=%.0f med=%.0f max=%.0f ms\n", NR, v[1], v[int(NR/2)+1], v[NR]}'
