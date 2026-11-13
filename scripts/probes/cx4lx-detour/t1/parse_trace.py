#!/usr/bin/env python3
"""T1-A: parse `mlxscope trace drain` output into a class/string table.

Line format (ring.rs render):
  [trace-drain] [0x<fw-ts>] 0 [0x<event_id>] [<anchor> ]<rendered string ...>

Class map from T0 report §3.1 (string family -> SET_ITRACE class bit).
Output: per-class per-string counts, first/last fw-ts, interval stats
(min/median/max between consecutive events, same string), plus a flat
timeline of AN-class (0x40) events for the ~0.4 s [H] calibration.
"""
import re
import sys
import statistics

LINE = re.compile(
    r"^(?:\d+\s+)?(?:\[trace-drain\]\s+)?\[0x([0-9a-f?]{8})\]\s+\d+\s+\[0x[0-9a-f]{2}\]\s+(.*)$"
)

# (class, [substrings]) — first match wins; keep most specific first.
FAMILIES = [
    ("0x40", ["ib_speed_nego_fsm", "init_ib_an_fsm", "ib_force_edr_fsm",
              "link_maintenance", "lm_input_event_handler"]),
    ("0x400000", ["module_management_init_sm", "cable_module_read_write",
                  "isr_mng2core", "TEMPERATURE", "scl stuck", "sda stuck"]),
    ("0x4000", ["connector is not SFP or QSFP", "cableinfo",
                "PPCNT fpga i2c"]),
    ("0x800", ["speed_2_pll_mask"]),
    ("0x400", ["phy_manager_open_pport", "phy test mode",
               "change_port_state"]),
    ("0x20", ["hal_set_ib_speed_and_width", "PTYS", "an_disable_admin"]),
    ("0x4000000", ["isr_icmd", "icmd_generic_reg_access",
                   "MMINIT invalid module"]),
    ("other-ts", ["TRACER: timestamp update"]),
]


def classify(text):
    for cls, keys in FAMILIES:
        for k in keys:
            if k in text:
                return cls
    return "?"


def main(path):
    events = []  # (ts or None, text)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LINE.match(line.rstrip("\n"))
            if not m:
                continue
            ts_raw, text = m.groups()
            ts = int(ts_raw, 16) if "?" not in ts_raw else None
            events.append((ts, text))
    if not events:
        print("no events parsed")
        return 1

    buckets = {}  # (class, short) -> [ts...]
    for ts, text in events:
        cls = classify(text)
        short = text.split(",")[0][:64]
        buckets.setdefault((cls, short), []).append(ts)

    print(f"total events: {len(events)}")
    tss = [t for t, _ in events if t is not None]
    if tss:
        print(f"fw-ts range: 0x{min(tss):08x} .. 0x{max(tss):08x} "
              f"(span {max(tss)-min(tss)} ticks)")
    print()
    hdr = f"{'class':<10}{'count':>6}  {'first':>10} {'last':>10}  string"
    print(hdr)
    print("-" * len(hdr))
    order = {"0x40": 0, "0x400000": 1, "0x4000000": 2, "0x20": 3,
             "0x800": 4, "0x400": 5, "0x4000": 6, "other-ts": 8, "?": 9}
    for (cls, short), tsts in sorted(buckets.items(),
                                     key=lambda kv: (order.get(kv[0][0], 9),
                                                     -len(kv[1]))):
        present = [t for t in tsts if t is not None]
        f = f"0x{present[0]:08x}" if present else "-"
        l = f"0x{present[-1]:08x}" if present else "-"
        print(f"{cls:<10}{len(tsts):>6}  {f:>10} {l:>10}  {short}")

    # interval stats per (class, string) where >=3 timestamped events
    print("\ninterval stats (fw-ticks, consecutive same-string events):")
    for (cls, short), tsts in sorted(buckets.items(),
                                     key=lambda kv: order.get(kv[0][0], 9)):
        present = [t for t in tsts if t is not None]
        if len(present) < 3:
            continue
        d = [b - a for a, b in zip(present, present[1:]) if b > a]
        if not d:
            continue
        med = statistics.median(d)
        print(f"  {cls} n={len(tsts)} d={len(d)} "
              f"min={min(d)} med={med} max={max(d)}  {short[:48]}")

    # AN-class flat timeline (0.4 s [H] calibration)
    print("\nAN-class (0x40) timeline:")
    prev = None
    for ts, text in events:
        if ts is None or classify(text) != "0x40":
            continue
        delta = f" +{ts - prev}" if prev is not None and ts > prev else ""
        print(f"  0x{ts:08x}{delta:<12} {text[:70]}")
        prev = ts
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
