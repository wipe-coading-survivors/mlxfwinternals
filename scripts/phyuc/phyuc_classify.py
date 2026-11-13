#!/usr/bin/env python3
"""PHY-UC 0x0C record classification across CX-4/CX-5/CX-6/CX-6Dx families.

Reuses load_slots from phyuc_diff (slot format: [6x0][op,a,b,c,d BE16];
records are (op, a, b, c, d) BE16 tuples). Classes each CX-5 record
against the CX-4 skeleton and the Gen5-era families (key = (op, b, c)):

  skeleton      byte-equal multiset match with a CX-4 record
  resched       CX-4 key, differs only in field a (read/delay reschedule)
  skeleton-add  CX-4 key, extra operand instance (additive d/a value)
  gen4          key absent in CX-4, present in both CX-6 and CX-6Dx
  cx5-only      key absent in CX-4, missing from CX-6 or CX-6Dx

op2000 (0x2000 cond) records get a "-cond" class suffix.

Usage: phyuc_classify.py CX4 CX5 CX6 CX6DX [--markup FILE] [--ops]
  --markup FILE  write per-record markup, one line: <idx> <hex-slot> <class>
  --ops          print full per-family op histograms

Verified on 0x0c dumps (journal 2026-10-24-pcie-phy-rate-knob-task-01).
Offline/static tool: no hardware access.
"""
import argparse
import collections
import struct
import sys

from phyuc_diff import load_slots


def slot_bytes(rec):
    return b"\x00" * 6 + struct.pack(">5H", *rec)


def key(rec):
    return (rec[0], rec[2], rec[3])


def keyset(words):
    return {key(w) for w in words}


def classify(cx4, cx5, cx6, cx6dx):
    """cx4/cx5/cx6/cx6dx: record lists as returned by phyuc_diff.load_slots.

    Returns (markup, summary): markup is a list of (idx, slot, class) for
    every CX-5 record (slot = 16-byte hex source); summary is a dict of
    family-table numbers.
    """
    w4, w5, w6, wdx = cx4, cx5, cx6, cx6dx

    classes: list = [None] * len(w5)
    left = collections.Counter(w4)
    for i, rec in enumerate(w5):
        if left[rec] > 0:
            left[rec] -= 1
            classes[i] = "skeleton"

    k4, k5, k6, kdx = keyset(w4), keyset(w5), keyset(w6), keyset(wdx)
    for i, rec in enumerate(w5):
        if classes[i] is not None:
            continue
        k = key(rec)
        match = next((w for w in left.elements()
                      if key(w) == k
                      and [f for f in range(5) if w[f] != rec[f]] == [1]),
                     None)
        if match is not None:
            left[match] -= 1
            classes[i] = "resched"
        elif k in k4:
            classes[i] = "skeleton-add"
        elif k in k6 and k in kdx:
            classes[i] = "gen4"
        else:
            classes[i] = "cx5-only"
        if rec[0] == 0x2000:
            classes[i] += "-cond"

    markup = [(i, slot_bytes(s), c)
              for i, (s, c) in enumerate(zip(w5, classes))]

    o4 = {r[0] for r in w4}
    o5 = {r[0] for r in w5}
    o6 = {r[0] for r in w6}
    odx = {r[0] for r in wdx}
    summary = {
        "records": {"cx4": len(w4), "cx5": len(w5),
                    "cx6": len(w6), "cx6dx": len(wdx)},
        "classes": collections.Counter(classes),
        "skeleton_keys": {"cx4": len(k4),
                          "cx5": len(k4 & k5),
                          "cx6": len(k4 & k6),
                          "cx6dx": len(k4 & kdx)},
        "gen4_keys": len((k5 & k6 & kdx) - k4),
        "gen4_ops": sorted((o5 & o6 & odx) - o4),
        "ops_all_four": sorted(o4 & o5 & o6 & odx),
        "serdes_delta": {"cx6_only_keys": len(k6 - kdx),
                         "cx6dx_only_keys": len(kdx - k6)},
        "cx6_growth": {"raw_diff": len(w6) - len(w5),
                       "new_key_instances": sum(1 for r in w6
                                                 if key(r) not in k5)},
        "op_hist": {name: collections.Counter(w[0] for w in ws)
                    for name, ws in (("cx4", w4), ("cx5", w5),
                                     ("cx6", w6), ("cx6dx", wdx))},
    }
    return markup, summary


def format_markup(markup):
    return "\n".join(f"{i} {s.hex()} {c}" for i, s, c in markup)


def load_markup(path):
    """Parse a markup file written by --markup: one record per line,
    `<idx> <hex-slot> <class>`."""
    markup = []
    with open(path) as f:
        for line in f:
            parts = line.split()
            if not parts:
                continue
            idx, hx, cls = parts
            markup.append((int(idx), bytes.fromhex(hx), cls))
    return markup


def cond_context(markup, window=4):
    """Interleave evidence for op2000 cond records: per-cond nearest
    frozen-skeleton record distance and share of non-skeleton neighbors
    in a +-window (conds embedded in inserted material stay far from
    byte-equal skeleton records)."""
    classes = [c for _, _, c in markup]
    skeleton = [i for i, c in enumerate(classes) if c == "skeleton"]
    conds = [i for i, c in enumerate(classes) if c.endswith("-cond")]
    nearest = {}
    share = {}
    for i in conds:
        if skeleton:
            nearest[i] = min(abs(i - j) for j in skeleton)
        neighbors = [classes[j] for j in
                     range(max(0, i - window), min(len(classes), i + window + 1))
                     if j != i]
        share[i] = (sum(1 for c in neighbors if c != "skeleton") /
                    len(neighbors)) if neighbors else 0.0
    return {"conds": conds, "nearest_skeleton": nearest,
            "insert_share": share}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cx4")
    ap.add_argument("cx5")
    ap.add_argument("cx6")
    ap.add_argument("cx6dx")
    ap.add_argument("--markup", metavar="FILE")
    ap.add_argument("--ops", action="store_true")
    args = ap.parse_args()
    markup, s = classify(*(load_slots(p) for p in
                           (args.cx4, args.cx5, args.cx6, args.cx6dx)))
    print(f"records: {s['records']}")
    print(f"cx5 classes: {dict(s['classes'])}")
    print(f"skeleton keys by family: {s['skeleton_keys']}")
    print(f"gen4 keys (5&6&6dx, not cx4): {s['gen4_keys']}")
    print(f"gen4 ops (5&6&6dx, not cx4): "
          f"{' '.join(f'{o:04x}' for o in s['gen4_ops'])}")
    print(f"ops in all four families: "
          f"{' '.join(f'{o:04x}' for o in s['ops_all_four'])}")
    print(f"serdes delta: {s['serdes_delta']}")
    print(f"cx6 growth: {s['cx6_growth']}")
    if args.ops:
        for name in ("cx4", "cx5", "cx6", "cx6dx"):
            hist = " ".join(f"{o:04x}x{n}" for o, n in
                            sorted(s["op_hist"][name].items()))
            print(f"op hist {name} ({len(s['op_hist'][name])} ops): {hist}")
    if args.markup:
        with open(args.markup, "w") as f:
            f.write(format_markup(markup) + "\n")
        print(f"markup: {args.markup} ({len(markup)} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
