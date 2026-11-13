#!/usr/bin/env python3
"""PHY-UC register-address space overlap (ITOC 0x0a vs 0x0c), serdes-c4 task.

Slot format and op families per phyuc_dis.py (task-4b): 16-byte slots
[6x0][op,a,b,c,d BE16]. Address-space model (methodology fixed before
counting overlaps; journal 2026-11-11-serdes-c4-bank-overlap.md section 2):

  write domain   hi(op) 0x60..0x7f: address = (b, c); b = bank
                 (blk<<12 | reg-select), c = offset. NOT addresses: a
                 (flavor/schedule), d (value).
  read domain    hi(op) 0x50..0x5f: address = (b, c); d is derived
                 (d == c >> 4 invariant, phyuc_diff), a = schedule.
  lane-status    CX-6-gen ops with hi-byte 0x48..0x4d (incl. 0x4c40) share
                 the read (b, c) domain (b = lane ids, c = 0x30..0x280,
                 d = status codes); counted separately as "read+lane"
                 so it never mixes into the write domain.
  excluded       op2000 (c = cond/doorbell, d = engine target / mask),
                 0x4000 delay, 0x3000 (CX-6 constant mask op), 0x8520
                 (CX-4-gen sync constant), nop. Their field domains are
                 printed for transparency but never intersected as
                 register banks.

Pairwise report: per-table class census, write/read (b, c) pair sets with
b/c projections, intersection sizes for same-domain pairs, plus two
controls against false overlap: cross-domain (A.write vs B.read) and the
excluded-op domains listed separately.

--consts FILE: structural scan of a 0x0b PHY_UC_CONSTS dump (BE32 word
classes, BE16 stream) cross-checked against both tables' bank sets.

Usage: phyuc_overlap.py TABLE_A TABLE_B [--consts FILE] [--verbose]
Offline/static tool: no hardware access.
"""
import argparse
import collections
import struct
import sys

from phyuc_diff import load_slots


def is_lane_op(op):
    """CX-6-gen lane/status family: hi-byte 0x48..0x4d (incl. 0x4c40).
    Shares the read (b, c) domain: b = lane ids (0x26..0x3527), c =
    0x30..0x280 (read-c range), d = small/status codes."""
    return 0x48 <= (op >> 8) <= 0x4D


def excluded_domains(slots):
    """Field domains of ops excluded from the address model."""
    dom = collections.defaultdict(lambda: collections.defaultdict(set))
    for op, a, b, c, d in slots:
        if op == 0x2000:
            dom["op2000"]["c"] |= {c}
            dom["op2000"]["d"] |= {d}
        elif op == 0x4000:
            dom["delay"]["a"] |= {a}
        elif op == 0x3000:
            dom["op3000"]["d"] |= {d}
        elif op == 0x8520:
            dom["op8520"]["b"] |= {b}
            dom["op8520"]["c"] |= {c}
        elif op == 0:
            dom["nop"]["a"] |= {a}
    return dom


def addr_sets(slots):
    """Write/read register-address projections of a slot table.

    Returns {"write": {"pairs", "b", "c"}, "read": ..., "lane": ...}
    where lane merges 0x4c40 into the read domain ("read+lane" keys).
    """
    out = {}
    for name, want in (("write", lambda op: 0x60 <= (op >> 8) <= 0x7F),
                       ("read", lambda op: 0x50 <= (op >> 8) <= 0x5F),
                       ("lane", is_lane_op)):
        pairs = {(b, c) for op, a, b, c, d in slots if want(op)}
        out[name] = {"pairs": pairs, "b": {p[0] for p in pairs},
                     "c": {p[1] for p in pairs}}
    out["read+lane"] = {
        "pairs": out["read"]["pairs"] | out["lane"]["pairs"],
        "b": out["read"]["b"] | out["lane"]["b"],
        "c": out["read"]["c"] | out["lane"]["c"],
    }
    return out


def fmt_rng(vals):
    if not vals:
        return "(none)"
    s = sorted(vals)
    if isinstance(s[0], tuple):
        lo, hi = min(s), max(s)
        return f"{len(s)} distinct, ({lo[0]:#06x},{lo[1]:#06x})..({hi[0]:#06x},{hi[1]:#06x})"
    return f"{len(s)} distinct, {s[0]:#06x}..{s[-1]:#06x}"


def report_set(name, s, top=None):
    print(f"  {name}: {fmt_rng(s)}")
    if top and s:
        cnt = collections.Counter(s)
        print(f"    top: {' '.join(f'{v:#06x}x{n}' for v, n in cnt.most_common(top))}")


def fmt_val(v):
    if isinstance(v, tuple):
        return f"({v[0]:#06x},{v[1]:#06x})"
    return f"{v:#06x}"


def intersect(tag, sa, sb, top=8):
    inter = sa & sb
    j = len(inter) / len(sa | sb) if (sa | sb) else 0.0
    print(f"  {tag}: |A&B|={len(inter)} of |A|={len(sa)} |B|={len(sb)} "
          f"jaccard={j:.3f}")
    if inter:
        print(f"    shared: {' '.join(fmt_val(v) for v in sorted(inter)[:top])}"
              f"{' ...' if len(inter) > top else ''}")
    return inter


def census(name, slots):
    cen = collections.Counter()
    for op, a, b, c, d in slots:
        if op == 0:
            cen["nop"] += 1
        elif op == 0x2000:
            cen["op2000"] += 1
        elif op == 0x3000:
            cen["op3000"] += 1
        elif op == 0x4000:
            cen["delay"] += 1
        elif op == 0x4C40:
            cen["lane"] += 1
        elif is_lane_op(op):
            cen["lane"] += 1
        elif op == 0x8520:
            cen["op8520"] += 1
        elif 0x50 <= (op >> 8) <= 0x5F:
            cen["read"] += 1
        elif 0x60 <= (op >> 8) <= 0x7F:
            cen["write"] += 1
        else:
            cen[f"other:{op:04x}"] += 1
    print(f"{name}: {len(slots)} slots, census {dict(cen)}")
    return cen


def consts_scan(path, banks_a, banks_b):
    """0x0b PHY_UC_CONSTS structural scan: BE32 word classes, BE16 stream
    hits against both bank (write-b) sets."""
    data = open(path, "rb").read()
    words = struct.unpack(f">{len(data) // 4}I", data[:len(data) // 4 * 4])
    print(f"\nconsts {path}: {len(data)} B = {len(words)} BE32 words")
    cls = collections.Counter()
    for w in words:
        if w == 0:
            cls["zero"] += 1
        elif w < 0x100:
            cls["u8"] += 1
        elif w < 0x10000:
            cls["u16"] += 1
        elif w < 0x1000000:
            cls["u24"] += 1
        else:
            cls["big"] += 1
    print(f"  word classes: {dict(cls)}")
    top = collections.Counter(words).most_common(10)
    print(f"  top values: {' '.join(f'{v:#010x}x{n}' for v, n in top)}")
    be16 = struct.unpack(f">{len(data) // 2}H", data[:len(data) // 2 * 2])
    for tag, banks in (("A", banks_a), ("B", banks_b)):
        hits = [v for v in be16 if v in banks]
        if hits:
            print(f"  BE16 stream hits vs {tag} write-banks: "
                  f"{collections.Counter(f'{v:#06x}' for v in hits)}")
        else:
            print(f"  BE16 stream hits vs {tag} write-banks: none")
    return words


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("table_a")
    ap.add_argument("table_b")
    ap.add_argument("--consts")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    A = load_slots(args.table_a)
    B = load_slots(args.table_b)

    census(f"A: {args.table_a}", A)
    census(f"B: {args.table_b}", B)

    sa = addr_sets(A)
    sb = addr_sets(B)
    for dom in ("write", "read", "read+lane"):
        print(f"\n[{dom} domain]")
        for tag, s in (("A", sa[dom]), ("B", sb[dom])):
            print(f" {tag}: pairs {fmt_rng(s['pairs'])}")
            if args.verbose:
                report_set(f"{tag} b", s["b"], top=10)
                report_set(f"{tag} c", s["c"], top=10)
        inter = intersect(f"{dom} pairs A&B", sa[dom]["pairs"], sb[dom]["pairs"])
        intersect(f"{dom} b A&B", sa[dom]["b"], sb[dom]["b"])
        intersect(f"{dom} c A&B", sa[dom]["c"], sb[dom]["c"])
        if args.verbose and inter:
            if dom == "write":
                cnta = collections.Counter((b, c) for op, x, b, c, d in A
                                           if 0x60 <= (op >> 8) <= 0x7F)
                print(f"    (A instances of shared write pairs: "
                      f"{sum(cnta[p] for p in inter)})")

    print("\n[cross-domain control A.write vs B.read / A.read vs B.write]")
    intersect("ctrl pairs A.wr x B.rd", sa["write"]["pairs"], sb["read"]["pairs"])
    intersect("ctrl pairs A.rd x B.wr", sa["read"]["pairs"], sb["write"]["pairs"])

    print("\n[excluded-op domains (not register addresses)]")
    for tag, slots in (("A", A), ("B", B)):
        for fam, fields in sorted(excluded_domains(slots).items()):
            print(f" {tag} {fam}: "
                  + ", ".join(f"{f} {fmt_rng(v)}"
                              for f, v in sorted(fields.items())))

    if args.consts:
        consts_scan(args.consts, sa["write"]["b"], sb["write"]["b"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
