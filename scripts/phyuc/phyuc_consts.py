#!/usr/bin/env python3
"""PHY-UC constants section (ITOC 0x0b) layout parser (serdes arc C, T3).

Section format (verified on CX-4 12.28/14.32, CX-5 16.35/16.19; journal
2026-11-11-serdes-c4-bank-overlap.md section 6 plus this task's recon):
  - CX-4/CX-4Lx/CX-5 gen: 11392 B = 2848 BE32 words = 32-word header +
    16 tables x 176 words (autocorrelation peak at word lag 176; t7..t13
    near-identical coefficient tables, t15 all-zero). Word classes per
    c4: u24/u16/zero/u8, analog/timing tables, NOT address-like, no
    structural reference to 0x0a/0x0c banks.
  - CX-6 gen: 1280 B all-zero placeholder (constants relocated; see
    journal task-03).

parse_consts(payload) -> ConstsLayout:
  1. zero fast-path (>= 90% zero words -> single zero table);
  2. uniform grid hypothesis: header h <= 64 words + k >= 6 tables of
     L >= 4 words; accepted when >= 45% of consecutive table pairs match
     at >= 75% of words (strong pairs) and mean pair rate >= 0.25; best
     grid = max payload coverage, then strong fraction;
  3. fallback: segmentation into periodic zones (value with >= 3
     occurrences at a constant word lag claims its zone, zone length
     >= 3 x lag; zero words carry no stride evidence); leftovers become
     stride-None flat tables;
  4. per-table entropy class: zero > counter-like (stride-1 monotone
     run of >= 6 same-direction transitions with steps <= 0x40) >
     timing-looking (monotone stepwise run of >= 3 transitions in a
     stride-2 column with plateau factor >= 1.5, >= 8 distinct values)
     > analog-looking (distinct ratio < 0.6 and top value >= 10%) >
     mixed. Class names carry no semantic proof - heuristics grounded
     in c4 section 6 observations, unvalidated beyond structure.

index_alignment(consts, scripts): does 0x0a reference 0x0b by row index?
scripts records are 5-tuples (op, a, b, c, d) from phyuc_diff.load_slots
or 6-tuples (slot_idx, op, a, b, c, d) from phyuc_dis.slots - anything
else raises ValueError. Candidate index fields are the non-address
fields of the c4 address
model (write/read flavor a, op2000/8520 c, op3000 c/d, lane c; b is an
address carrier and is never tested). A (family, field) -> table link
is accepted only when ALL of the family's field values fit the table
row space, start at 0, cover >= 50% of the rows and are >= 50% dense.
Each contributing slot then yields Match(table, idx).

Usage: phyuc_consts.py PAYLOAD [--slots 0A_RAW] [--json OUT]
Offline/static tool: no hardware access.
"""
import argparse
import collections
import json
import struct
import sys
from dataclasses import dataclass

from phyuc_diff import load_slots
from phyuc_dis import op_class
from phyuc_overlap import is_lane_op

ZERO_TABLE_FRAC = 0.9
ANALOG_DISTINCT_MAX = 0.6
ANALOG_TOP_MIN = 0.10
TIMING_MIN_STEPS = 3
TIMING_COL_STRIDES = (2,)
TIMING_MIN_DISTINCT = 8
TIMING_MIN_PLATEAU = 1.5
COUNTER_MIN_STEPS = 6
COUNTER_MAX_STEP = 0x40
PERIODIC_MIN_OCCUR = 3
GRID_MIN_STRIDE = 4
GRID_MIN_TABLES = 6
GRID_MAX_HEADER = 64
GRID_STRONG_PAIRS = 0.45
GRID_PAIR_RATE = 0.75
GRID_MIN_MEAN = 0.25
SEG_MIN_STRIDE = 2
SEG_MIN_ROWS = 3
FLAT_MIN_WORDS = 2

INDEX_FIELDS = {
    "write": ("a",),
    "read": ("a",),
    "op2000": ("c",),
    "op8520": ("c",),
    "op3000": ("c", "d"),
    "lane": ("c",),
}
SLOT_FIELDS = {"a": 1, "b": 2, "c": 3, "d": 4}
INDEX_MIN_COVERAGE = 0.5
INDEX_MIN_DENSITY = 0.5


@dataclass(frozen=True)
class ConstsTable:
    tid: int
    offset: int
    length: int
    stride: int | None
    row_count: int
    sub_stride: int | None
    entropy_class: str


@dataclass(frozen=True)
class GridInfo:
    stride: int
    header_words: int
    count: int


@dataclass(frozen=True)
class ConstsLayout:
    n_words: int
    strides: tuple
    grid: GridInfo | None
    tables: tuple


@dataclass(frozen=True)
class Match:
    table: int
    idx: int
    slot: int | None = None
    field: str | None = None


def be32_words(payload):
    if not payload or len(payload) % 4:
        raise ValueError(f"payload size {len(payload)} not a non-zero multiple of 4")
    return struct.unpack(f">{len(payload) // 4}I", payload)


def stride_census(words):
    """Lag votes: values with >= PERIODIC_MIN_OCCUR occurrences at a
    constant word lag (zero words carry no stride evidence)."""
    pos = collections.defaultdict(list)
    for i, v in enumerate(words):
        if v:
            pos[v].append(i)
    votes = collections.Counter()
    for v, ps in pos.items():
        if len(ps) < PERIODIC_MIN_OCCUR:
            continue
        run, lag = 1, ps[1] - ps[0]
        for j in range(2, len(ps)):
            d = ps[j] - ps[j - 1]
            if d == lag:
                run += 1
            else:
                if run >= PERIODIC_MIN_OCCUR - 1:
                    votes[lag] += 1
                run, lag = 1, d
        if run >= PERIODIC_MIN_OCCUR - 1:
            votes[lag] += 1
    return votes


def _grid_scan(words, cands):
    n = len(words)
    best = None
    for L in sorted(cands):
        if L < GRID_MIN_STRIDE:
            continue
        for h in range(0, min(GRID_MAX_HEADER, n // 2) + 1):
            if (n - h) % L or (n - h) // L < GRID_MIN_TABLES:
                continue
            k = (n - h) // L
            rates = []
            for r in range(k - 1):
                a = words[h + L * r:h + L * (r + 1)]
                b = words[h + L * (r + 1):h + L * (r + 2)]
                if not any(a) or not any(b):
                    continue
                rates.append(sum(1 for x, y in zip(a, b) if x == y) / L)
            if not rates:
                continue
            strong = sum(1 for x in rates if x >= GRID_PAIR_RATE) / len(rates)
            mean = sum(rates) / len(rates)
            if strong < GRID_STRONG_PAIRS or mean < GRID_MIN_MEAN:
                continue
            cand = ((n - h) / n, strong, mean, GridInfo(L, h, k))
            if best is None or cand[:3] > best[:3]:
                best = cand
    return best[3] if best else None


def _segments(words, cands):
    n = len(words)
    label = [None] * n
    for L in sorted((c for c in cands if c >= SEG_MIN_STRIDE), reverse=True):
        for i in range(n):
            if label[i] is not None or words[i] == 0:
                continue
            if (i + L < n and words[i + L] == words[i]) or \
               (i - L >= 0 and words[i - L] == words[i]):
                label[i] = L
    zones = []
    i = 0
    while i < n:
        L = label[i]
        j = i
        while j < n and label[j] == L:
            j += 1
        zones.append((i, j, L))
        i = j
    return zones


def _mono_run(seq):
    best = cur = 0
    sign = 0
    for a, b in zip(seq, seq[1:]):
        if a == b:
            continue
        s = 1 if b > a else -1
        if s == sign:
            cur += 1
        else:
            cur, sign = 1, s
        best = max(best, cur)
    return best


def _collapsed(col):
    return [col[0]] + [col[i] for i in range(1, len(col)) if col[i] != col[i - 1]]


def _counter_run(words):
    best = cur = 0
    sign = 0
    prev = None
    for x in words:
        if prev is None or x == prev:
            prev = x
            continue
        d = x - prev
        if 0 < d <= COUNTER_MAX_STEP:
            s = 1
        elif -COUNTER_MAX_STEP <= d < 0:
            s = -1
        else:
            s = 0
        if s and s == sign:
            cur += 1
        else:
            cur, sign = (1, s) if s else (0, 0)
        best = max(best, cur)
        prev = x
    return best


def _classify(words):
    n = len(words)
    if not n:
        return "zero"
    if sum(1 for x in words if not x) / n >= ZERO_TABLE_FRAC:
        return "zero"
    if _counter_run(words) >= COUNTER_MIN_STEPS:
        return "counter-like"
    if len(set(words)) >= TIMING_MIN_DISTINCT:
        for s in TIMING_COL_STRIDES:
            for c in range(min(s, n)):
                col = words[c::s]
                cc = _collapsed(col)
                if len(col) / len(cc) >= TIMING_MIN_PLATEAU and \
                        _mono_run(cc) >= TIMING_MIN_STEPS:
                    return "timing-looking"
    cnt = collections.Counter(words)
    if len(cnt) / n < ANALOG_DISTINCT_MAX and \
            cnt.most_common(1)[0][1] / n >= ANALOG_TOP_MIN:
        return "analog-looking"
    return "mixed"


def _sub_stride(words):
    n = len(words)
    if n < 8:
        return None
    votes = stride_census(words)
    cand = [L for L, v in sorted(votes.items())
            if v >= PERIODIC_MIN_OCCUR and SEG_MIN_STRIDE <= L < n // 2]
    return cand[0] if cand else None


def _mk_tables(zones, words):
    tables = []
    for off, end, L in zones:
        chunk = words[off:end]
        if L is None:
            if end - off < FLAT_MIN_WORDS:
                continue
            row_count = end - off
        else:
            if end - off < SEG_MIN_ROWS * L:
                continue
            row_count = (end - off) // L
        tables.append(ConstsTable(
            tid=0, offset=off * 4, length=(end - off) * 4, stride=L,
            row_count=row_count, sub_stride=_sub_stride(chunk),
            entropy_class=_classify(chunk)))
    return tables


def parse_consts(payload):
    """Layout of a 0x0b PHY_UC_CONSTS payload (see module docstring)."""
    words = be32_words(payload)
    n = len(words)
    if sum(1 for x in words if not x) / n >= ZERO_TABLE_FRAC:
        table = ConstsTable(tid=0, offset=0, length=n * 4, stride=None,
                            row_count=n, sub_stride=None,
                            entropy_class="zero")
        return ConstsLayout(n_words=n, strides=(), grid=None, tables=(table,))
    cands = stride_census(words)
    grid = _grid_scan(words, cands)
    if grid is not None:
        h = grid.header_words
        zones = []
        if h:
            zones.append((0, h, None))
        for r in range(grid.count):
            off = h + grid.stride * r
            zones.append((off, off + grid.stride, None))
        tables = _mk_tables(zones, words)
        strides = (grid.stride,)
    else:
        tables = _mk_tables(_segments(words, cands), words)
        strides = tuple(sorted({t.stride for t in tables
                                if t.stride is not None}))
    for tid, t in enumerate(tables):
        tables[tid] = ConstsTable(**{**t.__dict__, "tid": tid})
    return ConstsLayout(n_words=n, strides=strides, grid=grid,
                        tables=tuple(tables))


def _family(op):
    if op == 0x3000:
        return "op3000"
    fam = op_class(op)
    if is_lane_op(op):
        return "lane"
    return fam


def _norm_scripts(scripts):
    """Yield (slot, op, a, b, c, d) from either accepted record shape.

    Accepted records: 5-tuples (op, a, b, c, d) as produced by
    phyuc_diff.load_slots, and 6-tuples (slot_idx, op, a, b, c, d) as
    produced by phyuc_dis.slots. Anything else - wrong arity, non-int
    fields, negative slot index, values outside BE16 - raises
    ValueError (no silent empty results).
    """
    for pos, rec in enumerate(scripts):
        if not isinstance(rec, (tuple, list)) or len(rec) not in (5, 6):
            raise ValueError(f"bad slot record shape: {rec!r}")
        fields = tuple(rec)
        if len(fields) == 6:
            slot, fields = fields[0], fields[1:]
            if not isinstance(slot, int) or isinstance(slot, bool) or slot < 0:
                raise ValueError(f"bad slot index: {rec!r}")
            pos = slot
        if not all(isinstance(x, int) and not isinstance(x, bool)
                   for x in fields):
            raise ValueError(f"non-integer slot fields: {rec!r}")
        op, a, b, c, d = fields
        if not 0 <= op <= 0xFFFF or \
                any(not 0 <= x <= 0xFFFF for x in (a, b, c, d)):
            raise ValueError(f"slot field outside BE16 range: {rec!r}")
        yield pos, op, a, b, c, d


def index_alignment(consts, scripts):
    """Row-index references from 0x0a slot scripts into consts tables.

    scripts records: 5-tuples (op, a, b, c, d) from phyuc_diff.load_slots
    or 6-tuples (slot_idx, op, a, b, c, d) from phyuc_dis.slots (see
    _norm_scripts; malformed records raise ValueError). Match.slot carries
    the record's slot index for phyuc_dis shapes, the list position
    otherwise.
    """
    groups = collections.defaultdict(list)
    for i, op, a, b, c, d in _norm_scripts(scripts):
        if not op:
            continue
        fam = _family(op)
        rec = (op, a, b, c, d)
        for f in INDEX_FIELDS.get(fam, ()):
            groups[(fam, f)].append((i, rec[SLOT_FIELDS[f]]))
    out = []
    for (fam, f), items in sorted(groups.items()):
        uniq = sorted({v for _, v in items})
        for t in consts.tables:
            if len(uniq) < 2 or uniq[0] != 0 or uniq[-1] >= t.row_count:
                continue
            if len(uniq) / t.row_count < INDEX_MIN_COVERAGE:
                continue
            if len(uniq) / (uniq[-1] + 1) < INDEX_MIN_DENSITY:
                continue
            for i, v in items:
                out.append(Match(table=t.tid, idx=v, slot=i, field=f))
    return out


def layout_json(layout, matches):
    return {
        "payload_bytes": layout.n_words * 4,
        "n_words": layout.n_words,
        "grid": layout.grid.__dict__ if layout.grid else None,
        "strides": list(layout.strides),
        "tables": [t.__dict__ for t in layout.tables],
        "matches": [m.__dict__ for m in matches],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("payload")
    ap.add_argument("--slots")
    ap.add_argument("--json")
    args = ap.parse_args()
    payload = open(args.payload, "rb").read()
    layout = parse_consts(payload)
    print(f"{args.payload}: {len(payload)} B = {layout.n_words} BE32 words")
    if layout.grid:
        g = layout.grid
        print(f"  grid: stride={g.stride} words ({g.stride * 4:#x} B), "
              f"header={g.header_words}, tables={g.count}")
    else:
        print("  grid: none")
    for t in layout.tables:
        print(f"  t{t.tid:02d} +{t.offset:#06x}..{t.offset + t.length:#06x} "
              f"stride={t.stride} rows={t.row_count} sub={t.sub_stride} "
              f"class={t.entropy_class}")
    matches = []
    if args.slots:
        matches = index_alignment(layout, load_slots(args.slots))
        print(f"  index alignment vs {args.slots}: {len(matches)} matches")
        for m in matches[:16]:
            print(f"    {m}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(layout_json(layout, matches), fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
