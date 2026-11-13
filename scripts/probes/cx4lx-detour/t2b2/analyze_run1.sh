#!/bin/bash
# T2b-2b offline analysis: decode the T2b-2 ev-log (DAC-retry storm -> owner
# replug -> QDR AOC -> LinkUp, hook image an5 ACTIVE) with the phase-A
# pipeline + phase markup + the C-T2 final-diff extracts:
#  (1) phase reconstruction (wall-based): PH1 DAC-retry / swap gap / PH2 AOC
#      detect (MM) / PH3 QDR-AN / PH4 post-LinkUp;
#  (2) hooks: H-AN marker 0x00ae58cd (emit5 ctx[58/5c/68/a0/a4]) ctx-word
#      dynamics retry-vs-success (THE diff axis vs T2b-1 constants);
#      H-DEC marker 0x00ad7547 (emit2 module+is_sfp verdict) count;
#  (3) outcome words per phase (default_ts3/chosen_mask/speed_enable,
#      agreed_ts3 speed), dispatcher histogram per phase, family counts,
#      cadences (init round, cnf_test), MM detect structure, LinkUp markers.
# Usage: analyze_run1.sh <raw-dir>  (expects ev-dac.log + arm.log inside;
#       writes parse/phases/hook-extracts/hook-ctx-dynamics/diff-extracts .log)
set -u
DIR=${1:?usage: analyze_run1.sh <raw-dir>}
DIR=$(cd "$DIR" && pwd) || exit 1
EV=$DIR/ev-dac.log
AL=$DIR/arm.log
HERE=$(cd "$(dirname "$0")" && pwd)
PARSE=$HERE/../t1/parse_trace.py
cd "$DIR" || exit 1

echo "== parse_trace (ev-dac.log) =="
python3 "$PARSE" "$EV" | tee parse-run1.log

python3 - "$EV" "$AL" <<'EOF' | tee phases.log
import re, sys, statistics
from collections import Counter

ev_path, arm_path = sys.argv[1], sys.argv[2]
line_re = re.compile(r"^(\d+) \[0x([0-9a-f?]+)\] \d+ \[0x[0-9a-f?]+\]\s+(.*)$")
han_re = re.compile(r"ib_force_edr_fsm: config_tx_sd_set: cl=(-?\d+), clp=(-?\d+), lane=(-?\d+), type=(-?\d+), index=(-?\d+)")

events = []
for raw in open(ev_path, errors="replace"):
    m = line_re.match(raw.strip())
    if m:
        events.append((int(m.group(1)), m.group(2), m.group(3)))

# t0 from arm.log: last "t=+X s wall=Y ms" pair (SIGINT teardown line)
t0 = None
for raw in open(arm_path, errors="replace"):
    m = re.search(r"t=\+([0-9.]+)s wall=(\d+)", raw)
    if m:
        t0 = int(m.group(2)) - int(float(m.group(1)) * 1000)
print(f"t0_arm={t0} total_events={len(events)}")

def first_wall(pred):
    for w, ts, tx in events:
        if pred(tx):
            return w
    return None

def last_wall(pred):
    r = None
    for w, ts, tx in events:
        if pred(tx):
            r = w
    return r

def walls(pred):
    return [w for w, ts, tx in events if pred(tx)]

def rel(w, base=t0):
    return (w - base) / 1000.0

han = [(w, tuple(int(x) for x in han_re.search(tx).groups()))
       for w, ts, tx in events if han_re.search(tx)]
retry_ctx = (256, 17167, 16, 16777232, 30936385)

first_an   = first_wall(lambda t: "ib_speed_nego" in t)
last_retry = max((w for w, c in han if c[:2] == (256, 17167)), default=None)
mm1        = first_wall(lambda t: "module_management_init_sm" in t)
mm255      = first_wall(lambda t: "module_management_init_sm" in t and "module = 255" in t)
crw1       = first_wall(lambda t: "cable_module_read_write" in t)
qdr1       = min((w for w, c in han if c[0] == 1024), default=None)
cnf1       = first_wall(lambda t: "cnf_test" in t)
linkup     = first_wall(lambda t: "speed_active.ib in SPEC speed is 0x4" in t)
end        = events[-1][0] if events else None
port0      = first_wall(lambda t: "Port 0" in t)

print(f"first_event=+{rel(events[0][0]):.1f}s first_an=+{rel(first_an):.1f}s")
print(f"PH1_DAC_RETRY  [{first_an} .. {last_retry}]  +{rel(first_an):.1f} .. +{rel(last_retry):.1f}s")
print(f"SWAP_GAP       ({last_retry} .. {mm1})  {(mm1-last_retry)/1000:.1f}s")
print(f"PH2_AOC_DETECT [{mm1} .. {qdr1})  +{rel(mm1):.1f} .. +{rel(qdr1):.1f}s")
print(f"  mm_module255=+{rel(mm255):.1f}s crw_first=+{rel(crw1):.1f}s")
print(f"PH3_QDR_AN     [{qdr1} .. {linkup})  +{rel(qdr1):.1f} .. +{rel(linkup):.1f}s  ({(linkup-qdr1)/1000:.1f}s)")
print(f"  first_cnf_test=+{rel(cnf1):.1f}s")
print(f"LINKUP         {linkup}  +{rel(linkup):.1f}s (speed_active.ib=0x4/QDR)")
print(f"PH4_POST_LINKUP [{linkup} .. {end}]  +{rel(linkup):.1f} .. +{rel(end):.1f}s")
print(f"  first_Port0_MAD=+{rel(port0):.1f}s")

# per-phase counts
bounds = [("PH1_DAC_RETRY", first_an, last_retry), ("PH2_AOC_DETECT", mm1, qdr1),
          ("PH3_QDR_AN", qdr1, linkup), ("PH4_POST_LINKUP", linkup, end)]
keys = {"AN-dispatcher": "ib_speed_nego: generic", "AN-fsm": "ib_speed_nego_fsm",
        "H-AN-hook": "ib_force_edr_fsm: config_tx_sd_set",
        "H-DEC-hook": "bw should be less than network speed",
        "MM-init-sm": "module_management_init_sm", "MM-crw": "cable_module_read_write",
        "agreed_ts3": "agreed_ts3", "set-timers-cfg_test": "set timers in cfg_test",
        "phy2module": "phy2module_handler", "speed_2_pll": "speed_2_pll_mask",
        "Port0-dump": "Port 0", "TEMPERATURE": "TEMPERATURE",
        "isr_icmd": "isr_icmd", "PTYS-hal": "hal_get_ib_speed"}
print("\nper-phase counts:")
hdr = "family".ljust(18) + "".join(n.split("_")[0].ljust(9) for n, _, _ in bounds)
print(hdr)
for k, s in keys.items():
    row = k.ljust(18)
    for name, lo, hi in bounds:
        n = sum(1 for w, ts, tx in events if s in tx and lo <= w < hi)
        row += str(n).ljust(9)
    print(row)

# dispatcher input_event histogram per phase (PH1 vs PH3)
print("\ndispatcher in_ev histogram (PH1 vs PH3):")
for name, lo, hi in (bounds[0], bounds[2]):
    c = Counter()
    for w, ts, tx in events:
        if "ib_speed_nego: generic" in tx and lo <= w < hi:
            m = re.search(r"input_event 0x([0-9a-f]+), verifier returned (\d+)", tx)
            if m:
                c[f"in 0x{m.group(1)} / ver {m.group(2)}"] += 1
    tot = sum(c.values())
    print(f"  {name}: total={tot}")
    for k, v in c.most_common(6):
        print(f"    {k}: {v} ({100*v/tot:.1f}%)")

# speed words per phase
print("\nspeed words per phase:")
for name, lo, hi in (bounds[0], bounds[2]):
    wd = Counter(); se = Counter(); dt = Counter(); cm = Counter(); ag = Counter()
    for w, ts, tx in events:
        if not (lo <= w < hi):
            continue
        for rx, cnt in ((r"default_ts3_speed=0x([0-9a-f]+)", dt),
                        (r"speed_enable: 0x([0-9a-f]+)", se),
                        (r"chosen_mask=0x([0-9a-f]+)", cm),
                        (r"agreed_ts3 speed=0x([0-9a-f]+)", ag)):
            m = re.search(rx, tx)
            if m:
                cnt[m.group(1)] += 1
    print(f"  {name}: default_ts3={dict(dt)} speed_enable={dict(se)} chosen_mask={dict(cm)} agreed={dict(ag)}")

# cadences: init round (H-AN), cnf_test, PH1 vs PH3
def cad(ws, label):
    if len(ws) > 1:
        d = [b - a for a, b in zip(ws, ws[1:]) if b > a]
        if d:
            print(f"  {label}: n={len(ws)} span={(ws[-1]-ws[0])/1000:.1f}s "
                  f"int_ms n={len(d)} min={min(d)} med={int(statistics.median(d))} max={max(d)}")

print("\ncadences (wall ms):")
cad([w for w, ts, tx in events if "init_ib_an_fsm" in tx], "init_round_all")
cad([w for w, ts, tx in events if "init_ib_an_fsm" in tx and w <= last_retry], "init_round_PH1")
cad([w for w, ts, tx in events if "init_ib_an_fsm" in tx and qdr1 <= w < linkup], "init_round_PH3")
cad([w for w, ts, tx in events if "cnf_test" in tx and w < linkup], "cnf_test")
cad([w for w, ts, tx in events if "TEMPERATURE" in tx], "smbus_temp")
cad([w for w, ts, tx in events if "cable_module_read_write" in tx and w > linkup], "MM-crw_postlink_poll")

# MM detect structure in PH2
print("\nPH2 MM-init-sm transitions:")
for w, ts, tx in events:
    if "module_management_init_sm" in tx and w < qdr1:
        print(f"  +{rel(w):.1f}s {tx.strip()}")
EOF

echo; echo "== hook extracts (T2b-2b core) =="
{
echo "-- H-AN emit5 (marker 0x00ae58cd string) count --"
grep -c "ib_force_edr_fsm: config_tx_sd_set" "$EV" || true
echo "-- H-AN first 2 (retry ctx) / round 1 post-plug / last 2 (QDR ctx) --"
grep "ib_force_edr_fsm: config_tx_sd_set" "$EV" | sed -n '1,2p;88,89p'
grep "ib_force_edr_fsm: config_tx_sd_set" "$EV" | tail -2
echo "-- H-DEC emit2 (marker 0x00ad7547 string) count --"
grep -c "bw should be less than network speed" "$EV" || echo 0
echo "-- H-DEC substitute evidence: MM activity walls (hot-plug detect) --"
grep -m2 "module_management_init_sm" "$EV"
grep -m1 "module = 255" "$EV"
} | tee hook-extracts.log

echo; echo "== H-AN ctx-word dynamics retry vs success (hex) =="
python3 - "$EV" <<'EOF' | tee hook-ctx-dynamics.log
import re, sys, statistics
line_re = re.compile(r"^(\d+) \[0x[0-9a-f?]+\] \d+ \[0x[0-9a-f?]+\]\s+ib_force_edr_fsm: config_tx_sd_set: cl=(-?\d+), clp=(-?\d+), lane=(-?\d+), type=(-?\d+), index=(-?\d+)")
rows = []
for raw in open(sys.argv[1], errors="replace"):
    m = line_re.match(raw.strip())
    if m:
        rows.append(tuple(int(x) for x in m.groups()))
names = ("cl", "clp", "lane", "type", "index")
retry = [r for r in rows if r[1] == 256]
qdr = [r for r in rows if r[1] == 1024]
print(f"total={len(rows)} retry_ctx={len(retry)} qdr_ctx={len(qdr)}")
for label, seg in (("RETRY (DAC storm)", retry), ("SUCCESS (QDR AN)", qdr)):
    print(f"-- {label}: n={len(seg)}")
    for i, n in enumerate(names):
        vals = [r[i + 1] for r in seg]
        uniq = sorted(set(vals))
        hx = ", ".join(f"0x{v:x}" for v in uniq[:4])
        print(f"   ctx[{n}]: uniq={len(uniq)} vals(dec/hex): {hx}"
              + (f"{' ...' if len(uniq) > 4 else ''}" if len(uniq) > 4 else ""))
if len(qdr) > 1:
    d = [b[2] - a[2] for a, b in zip(qdr, qdr[1:])]
    dd = [b[0] - a[0] for a, b in zip(qdr, qdr[1:]) if b[0] > a[0]]
    print(f"-- SUCCESS clp per-event delta: const={len(set(d)) == 1} "
          f"value={d[0]} (0x{d[0]:x}) over med {int(statistics.median(dd))} ms")
    base = qdr[0][2]
    # linear fit clp vs wall (least squares through first point)
    num = sum((r[0] - qdr[0][0]) * (r[2] - base) for r in qdr)
    den = sum((r[0] - qdr[0][0]) ** 2 for r in qdr)
    slope = num / den if den else 0
    print(f"   clp_0={base} (0x{base:x}); wall->clp slope = {slope:.0f} units/ms "
          f"(rate {slope * 1000 / 1e6:.2f}M units/s)")
EOF

echo; echo "== final-diff extracts (vs T2b-1 FDR retry / T1-A QDR) =="
{
echo "-- outcome words (whole window; per-phase in phases.log) --"
grep -oE "default_ts3_speed=0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/default_ts3: /'
grep -oE "chosen_mask=0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/preset_mask: /'
grep -oE "speed_enable: 0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/speed_enable: /'
grep -oE "agreed_ts3 speed=0x[0-9a-f]+" "$EV" | sort | uniq -c | sed 's/^/agreed: /'
grep -oE "is_peer_legacy_device = [0-9]" "$EV" | sort | uniq -c
echo "-- families --"
for k in "cable_module_read_write" "module_management_init_sm" "Port 0" "phy2module_handler" \
         "speed_2_pll_mask" "reg_access_pddr" "hal_get_ib_speed_and_width" \
         "isr_icmd" "icmd_generic" "TEMPERATURE" "pmaos" "link_maintenance" \
         "phy_manager_set_next_state" "send_packet"; do
    printf '%-28s %s\n' "$k:" "$(grep -ci "$k" "$EV" || true)"
done
echo "-- LinkUp markers --"
grep -m2 "speed_2_pll_mask" "$EV" | head -1
grep "speed_active.ib in SPEC" "$EV"
grep -m1 "Port 0" "$EV"
echo "-- ring loss check --"
grep -E "total_events|drop" arm.log | tail -2
echo "ev-log events: $(grep -cE '^[0-9]+ \[0x[0-9a-f?]+\] 0 \[0x' "$EV")"
} | tee diff-extracts.log
