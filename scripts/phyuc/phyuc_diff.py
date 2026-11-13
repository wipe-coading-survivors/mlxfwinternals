#!/usr/bin/env python3
"""PHY-UC slot-table differential (ITOC 0x0a/0x0c), record-level.

Compares two slot tables (see phyuc_dis.py for the slot format):
  - byte-exact multiset intersection, positional common prefix
  - strict key pairing on (op, b, c): byte-equal / operand-only classes
  - key-level (a, d)-multiset comparison incl. additivity (dB superset of dA)
  - structural alignment summary (difflib): equal/insert/replace map
  - per-op-family census diff (ops only in B), read invariant d == c >> 4
  - per-op-family monotonicity of field a (read/delay schedule check)
  - 0x08 schedule-table analysis: parse the BE16 table (+0xf0 legacy /
    16.35, +0x110 @16.19) and the (0x64, N) record-count pair, envelope /
    first-slot / op2000-handler cross-checks against a 0x0c table
  - GC-3 rate scan: 25/50/80/160 (& co) numeric hits tagged by operand
    domain (rate-knob task-02)

Usage: phyuc_diff.py TABLE_A TABLE_B [--blocks] [--rate-scan]
                          [--sched08 FILE] [--sched08-b FILE]
  --blocks          print alignment block map (non-equal blocks, listings)
  --rate-scan       GC-3 rate-candidate hits for both tables
  --sched08 FILE    parse FILE (raw 0x08 section) and cross-check vs A
  --sched08-b FILE  same for B

Verified on 0x0c CX-4/Lx 14.32/12.28 vs CX-5 16.35/16.19 (journals
2026-10-24-pcie-phy-uc-format-re, 2026-10-24-pcie-phy-rate-knob-task-02).
Offline/static tool: no hardware access.
"""
import argparse
import collections
import difflib
import struct
import sys

SCHED_MIN = 0x600
SCHED_MAX = 0x8FF
RATE_SET = (2, 4, 8, 16, 25, 50, 80, 100, 125, 160,
            2500, 5000, 8000, 16000)


def load_slots(path):
    data = open(path, "rb").read()
    if len(data) % 16:
        raise ValueError(f"{path}: size {len(data):#x} not multiple of 16")
    slots = []
    for off in range(0, len(data), 16):
        if data[off:off + 6] != b"\x00" * 6:
            raise ValueError(f"{path}: slot at {off:#x} breaks 6-zero-byte invariant")
        slots.append(struct.unpack_from(">5H", data, off + 6))
    return slots


def fmt(rec):
    return " ".join(f"{x:04x}" for x in rec)


def is_read(op):
    return 0x50 <= (op >> 8) <= 0x5F


def is_delay(op):
    return op == 0x4000


def is_write(op):
    return 0x60 <= (op >> 8) <= 0x7F


def sched_values(slots):
    return [r[1] for r in slots if is_read(r[0]) or is_delay(r[0])]


def parse_schedule(data):
    """Parse the 0x08 HW_BOOT_CFG schedule table (BE16, domain
    SCHED_MIN..SCHED_MAX) and the trailing (0x64, record_count) pair.

    Returns {"off", "entries", "pair_off", "pair"} or None if no table
    (a run of >= 2 in-domain BE16 words at an even offset in
    0xe0..0x120) is found.
    """
    def word(off):
        return struct.unpack_from(">H", data, off)[0]

    for off in range(0xE0, min(0x122, len(data) - 1), 2):
        if not SCHED_MIN <= word(off) <= SCHED_MAX:
            continue
        end = off
        while end + 2 <= len(data) and SCHED_MIN <= word(end) <= SCHED_MAX:
            end += 2
        if (end - off) // 2 < 2:
            continue
        entries = [word(p) for p in range(off, end, 2)]
        sched = {"off": off, "entries": entries, "pair": None,
                 "pair_off": None}
        for p in range(end, min(end + 0x40, len(data) - 3), 2):
            if word(p) == 0x64 and word(p + 2):
                sched["pair"] = (0x64, word(p + 2))
                sched["pair_off"] = p
                break
        return sched
    return None


def schedule_report(slots, sched):
    """Cross-check a 0x0c slot table against its 0x08 schedule table:
    envelope (max read/delay a == max entry), first scheduled slot ==
    entry[0], domain intersection, and op2000 cond handlers (d low-12
    bits against the schedule domain)."""
    avals = sched_values(slots)
    aset = set(avals)
    tset = set(sched["entries"])
    conds = []
    for i, r in enumerate(slots):
        if r[0] != 0x2000:
            continue
        lo = r[4] & 0xFFF
        conds.append({"idx": i, "c": r[3], "d": r[4], "tag": r[4] >> 12,
                      "lo12": lo, "in_table": lo in tset,
                      "in_aset": lo in aset})
    return {
        "max_a": max(avals) if avals else None,
        "table_max": max(sched["entries"]),
        "envelope_match": bool(avals) and max(avals) == max(sched["entries"]),
        "first_sched_a": avals[0] if avals else None,
        "table0": sched["entries"][0],
        "first_is_table0": bool(avals) and avals[0] == sched["entries"][0],
        "domain_inter": sorted(aset & tset),
        "conds": conds,
    }


def rate_hits(slots):
    """GC-3 scan: every operand equal to a rate-like number (RATE_SET),
    tagged by field/domain so matches are not over-read as lane-rate
    arithmetic."""
    hits = []
    for i, r in enumerate(slots):
        op, a, b, c, d = r
        fields = []
        if is_write(op):
            fields = ((a, "wr-a"), (b, "wr-b"), (c, "wr-c"), (d, "wr-d"))
        elif is_read(op):
            fields = ((a, "rd-a"), (b, "rd-b"))
        elif is_delay(op):
            fields = ((a, "delay-a"),)
        elif op == 0x2000:
            fields = ((c, "cond-c"), (d, "cond-d"), (d & 0xFFF, "cond-d.lo12"))
        for v, tag in fields:
            if v in RATE_SET:
                hits.append((i, op, tag, v))
    return hits


def print_schedule_report(name, slots, path):
    data = open(path, "rb").read()
    sched = parse_schedule(data)
    if sched is None:
        print(f"{name}: no schedule table found in {path}")
        return
    r = schedule_report(slots, sched)
    print(f"{name}: schedule @+{sched['off']:#x} ({len(sched['entries'])} entries, "
          f"max {r['table_max']:#x}), pair {sched['pair']} @+{sched['pair_off']:#x}")
    print(f"{name}: envelope max_a={r['max_a']:#x} match={r['envelope_match']}, "
          f"first_sched_a={r['first_sched_a']:#x} == entry0 "
          f"{r['first_is_table0']}, domain inter {len(r['domain_inter'])}: "
          f"{' '.join(f'{v:04x}' for v in r['domain_inter'])}")
    for cnd in r["conds"]:
        print(f"{name}: cond idx={cnd['idx']} c={cnd['c']:#04x} d={cnd['d']:#06x} "
              f"tag={cnd['tag']:x} lo12={cnd['lo12']:#05x} "
              f"in_table={cnd['in_table']} in_aset={cnd['in_aset']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("table_a")
    ap.add_argument("table_b")
    ap.add_argument("--blocks", action="store_true")
    ap.add_argument("--rate-scan", action="store_true")
    ap.add_argument("--sched08")
    ap.add_argument("--sched08-b")
    args = ap.parse_args()
    A = load_slots(args.table_a)
    B = load_slots(args.table_b)
    print(f"A: {args.table_a}: {len(A)} slots")
    print(f"B: {args.table_b}: {len(B)} slots")

    ma, mb = collections.Counter(A), collections.Counter(B)
    print(f"byte-exact multiset intersection: {sum((ma & mb).values())} "
          f"(A-only {sum((ma - mb).values())}, B-only {sum((mb - ma).values())})")
    p = 0
    while p < min(len(A), len(B)) and A[p] == B[p]:
        p += 1
    print(f"positional common prefix: {p} slots ({p * 16:#x} bytes)")

    ka = collections.Counter((r[0], r[2], r[3]) for r in A)
    kb = collections.Counter((r[0], r[2], r[3]) for r in B)
    print(f"key (op,b,c) intersection: {sum((ka & kb).values())}/{sum(ka.values())} of A keys")

    bidx = collections.defaultdict(list)
    for j, r in enumerate(B):
        bidx[(r[0], r[2], r[3])].append(j)
    used = set()
    cls = collections.Counter()
    a_diffs, d_diffs = [], []
    for i, r in enumerate(A):
        for j in bidx.get((r[0], r[2], r[3]), []):
            if j in used:
                continue
            used.add(j)
            if r == B[j]:
                cls["byte_equal"] += 1
            else:
                fields = [f for f in range(5) if r[f] != B[j][f]]
                if fields == [1]:
                    cls["a_only"] += 1
                    a_diffs.append((i, j, r[0], r[1], B[j][1]))
                elif fields == [4]:
                    cls["d_only"] += 1
                    d_diffs.append((i, j, r, B[j]))
                else:
                    cls["other:" + ",".join("opabcd"[f] for f in fields)] += 1
            break
    print(f"strict pairing classes: {dict(cls)}")
    if a_diffs:
        w = [x for x in a_diffs if is_read(x[2]) or is_delay(x[2])]
        print(f"  a-only diffs: {len(a_diffs)}, of which read/delay ops: {len(w)}")
    kdiff = 0
    for k in sorted(set(ka) | set(kb)):
        if k not in ka or k not in kb:
            continue
        va = collections.Counter((r[1], r[4]) for r in A if (r[0], r[2], r[3]) == k)
        vb = collections.Counter((r[1], r[4]) for r in B if (r[0], r[2], r[3]) == k)
        if va == vb:
            continue
        da = {x[1] for x in va}
        db = {x[1] for x in vb}
        if da != db:
            kdiff += 1
            rel = "additive" if da <= db else ("subset" if db <= da else "disjoint-mix")
            print(f"  key op={k[0]:04x} b={k[1]:04x} c={k[2]:04x}: "
                  f"dA={sorted(hex(x) for x in da)} dB={sorted(hex(x) for x in db)} [{rel}]")
    print(f"keys with differing d-value sets: {kdiff}")

    ops_a = collections.Counter(r[0] for r in A)
    ops_b = collections.Counter(r[0] for r in B)
    only_b = sorted(set(ops_b) - set(ops_a))
    only_a = sorted(set(ops_a) - set(ops_b))
    print(f"ops only in B ({len(only_b)}): {' '.join(f'{o:04x}x{ops_b[o]}' for o in only_b)}")
    print(f"ops only in A ({len(only_a)}): {' '.join(f'{o:04x}x{ops_a[o]}' for o in only_a)}")

    for name, S in (("A", A), ("B", B)):
        bad = [r for r in S if is_read(r[0]) and r[4] != (r[3] >> 4)]
        print(f"{name}: read-invariant d==c>>4 violations: {len(bad)}")
        byop = collections.defaultdict(list)
        for r in S:
            if is_read(r[0]) or is_delay(r[0]):
                byop[r[0]].append(r[1])
        nonmono = {f"{op:04x}": v for op, v in
                   ((op, sum(1 for x, y in zip(vals, vals[1:]) if x > y))
                    for op, vals in byop.items()) if v}
        print(f"{name}: op families with non-monotone a: {nonmono or 'none'}")

    if args.rate_scan:
        for name, S in (("A", A), ("B", B)):
            hits = rate_hits(S)
            print(f"{name}: rate-set hits ({len(hits)}):")
            for i, op, tag, v in hits:
                print(f"    idx={i:4d} op={op:04x} {tag}={v}")

    if args.sched08:
        print_schedule_report("A", A, args.sched08)
    if args.sched08_b:
        print_schedule_report("B", B, args.sched08_b)

    if args.blocks:
        matcher = difflib.SequenceMatcher(a=A, b=B, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue
            print(f"--- {tag}: A[{i1}:{i2}] B[{j1}:{j2}]")
            for k in range(i1, i2):
                print(f"    A[{k:4d}] {fmt(A[k])}")
            for k in range(j1, j2):
                print(f"    B[{k:4d}] {fmt(B[k])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
