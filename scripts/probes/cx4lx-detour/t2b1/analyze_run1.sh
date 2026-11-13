#!/bin/bash
# T2b-1 offline analysis: decode the T2b-1 ev-log (FDR DAC ->
# InfiniScale-IV, eternal AN retry, hook image an5 ACTIVE) with the
# phase-A pipeline + targeted extracts for the T2b-1 questions:
#  (1) hook liveness: H-AN marker 0x00ae58cd string (emit5: cl,clp,lane,
#      type,index = ctx[0x58/0x5c/0x68/0xa0/0xa4]) and H-DEC marker
#      0x00ad7547 string (emit2: bw=module, network_speed=verdict);
#  (2) ctx-word dynamics across the retry storm (per-field histograms);
#  (3) storm baseline vs T1-B3 (dispatcher histogram, AN cadence, families,
#      ICMD marker coverage).
# Usage: analyze_run1.sh <ev-log>  (run from the raw dir; writes *.log)
set -u
EV=${1:?usage: analyze_run1.sh <ev-log>}
HERE=$(cd "$(dirname "$0")" && pwd)
PARSE=$HERE/../t1/parse_trace.py
TICKS_PER_MS=1073   # calibrated in phase A (both windows + PAOS cadence)

echo "== parse_trace ($EV) =="
python3 "$PARSE" "$EV" | tee parse-run1.log

echo; echo "== hook extracts (T2b-1 core) =="
{
echo "-- H-AN emit5 (marker 0x00ae58cd string) count --"
grep -c "ib_force_edr_fsm: config_tx_sd_set" "$EV" || true
echo "-- H-AN samples (first 3 / last 3) --"
grep "ib_force_edr_fsm: config_tx_sd_set" "$EV" | sed -n '1,3p'
grep "ib_force_edr_fsm: config_tx_sd_set" "$EV" | tail -3
echo "-- H-DEC emit2 (marker 0x00ad7547 string) count --"
grep -c "bw should be less than network speed" "$EV" || true
echo "-- H-DEC samples --"
grep -m3 "bw should be less than network speed" "$EV"
} | tee hook-extracts.log

echo; echo "== H-AN ctx-word dynamics (per-field histograms) =="
python3 - "$EV" <<'EOF' | tee hook-ctx-dynamics.log
import re, sys
from collections import Counter
line_re = re.compile(r"^(\d+) \[0x([0-9a-f?]+)\] \d+ \[0x[0-9a-f?]+\]\s+(.*)$")
fields = ("cl", "clp", "lane", "type", "index")
vals = {f: Counter() for f in fields}
walls = []
for raw in open(sys.argv[1], errors="replace"):
    if "ib_force_edr_fsm: config_tx_sd_set" not in raw:
        continue
    m = line_re.match(raw.strip())
    if not m:
        continue
    walls.append(int(m.group(1)))
    for f in fields:
        fm = re.search(rf"\b{f}=(-?\w+)", m.group(3))
        if fm:
            vals[f][fm.group(1)] += 1
print(f"hook_an_events={len(walls)}")
if walls:
    print(f"first_wall={walls[0]} last_wall={walls[-1]} span_s={(walls[-1]-walls[0])/1000:.1f}")
    import statistics
    if len(walls) > 1:
        d = [b - a for a, b in zip(walls, walls[1:]) if b > a]
        if d:
            print(f"interval_ms n={len(d)} min={min(d)} med={int(statistics.median(d))} max={max(d)}")
for f in fields:
    top = ", ".join(f"{k}x{v}" for k, v in vals[f].most_common(8))
    print(f"ctx[{f}]: {top or '(no data)'}")
EOF

echo; echo "== storm baseline extracts (vs T1-B3) =="
{
echo "-- outcome words --"
echo "cnf_test lines:        $(grep -c 'cnf_test' "$EV" || true)"
echo "set timers in cfg_test: $(grep -c 'set timers in cfg_test' "$EV" || true)"
grep -oE "default_ts3_speed=0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/default_ts3: /'
grep -oE "chosen_mask=0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/preset_mask: /'
grep -oE "speed_enable: 0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/speed_enable: /'
echo "-- init_ib_an_fsm count --"
grep -c "init_ib_an_fsm" "$EV" || true
echo "-- dispatcher input_event histogram --"
grep -oE "ib_speed_nego: generic, pport 1, prev_state_or_event 0x[0-9a-f]+, input_event 0x[0-9a-f]+, verifier returned [0-9]+" "$EV" \
    | sed -E 's/pport 1, //' | sort | uniq -c | sort -rn | head -12
echo "-- families present/absent --"
for k in "cable_module_read_write" "module_management_init_sm" "Port 0" "phy2module_handler" \
         "speed_2_pll_mask" "reg_access_pddr" "hal_get_ib_speed_and_width" \
         "isr_icmd" "icmd_generic" "pmaos" "link_maintenance" \
         "sync_tx_clk_phase" "phy_manager_set_next_state"; do
    printf '%-28s %s\n' "$k:" "$(grep -ci "$k" "$EV" || true)"
done
echo "-- AN window --"
grep -E "ib_speed_nego" "$EV" | sed -n '1p;$p'
} | tee diff-extracts.log

echo; echo "== init round cadence (ms, fw-ts deltas / $TICKS_PER_MS) =="
awk '/init_ib_an_fsm/ {match($0, /\[0x([0-9a-f]+)\]/, a); if (a[1] != "") print strtonum("0x" a[1])}' "$EV" \
  | awk -v T=$TICKS_PER_MS 'NR>1 {d=$1-p; if (d>0) print d/T} {p=$1}' \
  | sort -n | awk '{v[NR]=$1} END {if (NR) printf "n=%d min=%.0f med=%.0f max=%.0f ms\n", NR, v[1], v[int(NR/2)+1], v[NR]}'

echo "== dispatcher cadence (ms, consecutive dispatcher-line deltas) =="
grep -E "ib_speed_nego: generic" "$EV" \
  | awk '{match($0, /\[0x([0-9a-f]+)\]/, a); if (a[1] != "") print strtonum("0x" a[1])}' \
  | awk -v T=$TICKS_PER_MS 'NR>1 {d=$1-p; if (d>0) print d/T} {p=$1}' \
  | sort -n | awk '{v[NR]=$1; s+=$1} END {if (NR) printf "n=%d min=%.1f med=%.1f mean=%.1f max=%.1f ms\n", NR, v[1], v[int(NR/2)+1], s/NR, v[NR]}'

echo "== H-AN vs stock init correlation (H-AN lines per init round) =="
INIT=$(grep -c "init_ib_an_fsm" "$EV" || true)
HA=$(grep -c "ib_force_edr_fsm: config_tx_sd_set" "$EV" || true)
echo "init=$INIT hook_an=$HA ratio=$(awk -v a="$HA" -v b="$INIT" 'BEGIN{if(b>0)printf "%.2f", a/b; else print "n/a"}')"
