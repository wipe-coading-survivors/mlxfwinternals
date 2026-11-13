#!/usr/bin/env python3
"""isa-max-a Task 3: normalize the fuzz-5 captured live layer into
fuzz5_live.json (pinned artifact consumed as-is by grind tasks T4-T8).

Inputs (md5-pinned via fuzz5_live_manifest.md5; drift => RC!=0):
- docs/superpowers/journal/2026-10-26-irisc-fuzz5-task-04.md  PRIMARY
  (per-group verdict tables: fuzz4rem, map36-has, map33 prose+examples,
  map34 rogue Fix round 1 + non-rogue, c2rare, zero-sites, disc round)
- scripts/probes/cx5-fuzz5/fuzz5_vectors.json (battery: expectations,
  census_rows join keys, seeds/words -> operands)
- scripts/probes/cx5-fuzz5/fuzz5_disc_vectors.json (disc round; vectors
  carry no census_rows -- keys restored by decoding the lo11 of the
  target word, selector model of census_map.py:13)
- scripts/probes/cx5-fuzz5/select_merges.json (derived verdicts used as
  build cross-gates: live_covered, live_only per-op counts, confirms)
- scripts/probes/cx5-fuzz5/census_map.json (row universe; NEVER rewritten)

Live verdict per census row follows select_merges.py:130-169 (alive-set
intersection over covering vectors, PRIOR_DEAD narrowing, DISC_RESOLVE
override, div/rogue/unique/multi tags).  Journal tables are PARSED; the
prose-only verdicts (map33 all-depR, zero-sites, disc outcomes, c2rare)
are transcribed with line refs (select_merges.py DISC_RESOLVE precedent).

Observations are a LIST: the battery observation plus disc/OPDEP points
on the same key stay separate entries (task-04 precedents:
op34_f5=04_idx=00_flag=0: 0xc + 0x7ffc (OPDEP-A); op34_f5=08_idx=0a_flag=1:
0x3634 + 0x37ff (OPDEP-B)).  `observed` priority: journal-stated value >
surviving-model expectation (a live 'alive' verdict means the expectation
matched the captured outcome) > null.  The div row carries the three
captured run values as a list.

cmp38-self is a separate record referencing BOTH live supports (fuzz-4
ltV/cmp38-self + fuzz-5 V-F5R-38SELF), per the C-A.5 double-live ruling.
"""
import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
F5 = REPO / "scripts" / "probes" / "cx5-fuzz5"

JOURNAL_REL = "docs/superpowers/journal/2026-10-26-irisc-fuzz5-task-04.md"
JOURNAL_F4_REL = ("docs/superpowers/journal/"
                  "2026-10-25-irisc-fuzz4-task-07.md")
SRC = "journal:2026-10-26-irisc-fuzz5-task-04.md"

TARGET_OPS = (0x33, 0x34, 0x36)  # scan set for disc key restoration


# ---------------------------------------------------------------- selector
def word_key(w):
    """word -> census row id (selector model census_map.py:13), or None
    when the word is not a 0x33/0x34/0x36 selector word."""
    op = w >> 26
    if op not in TARGET_OPS:
        return None
    lo11 = w & 0x7FF
    if op in (0x33, 0x34):
        flag, idx, f5 = ((lo11 >> 10) & 1, (lo11 >> 5) & 0x1F, lo11 & 0x1F)
        return "op%02x_f5=%02x_idx=%02x_flag=%d" % (op, f5, idx, flag)
    f5, i6 = lo11 & 0x1F, (lo11 >> 5) & 0x3F
    return "op36_f5=%02x_i6=%02x" % (f5, i6)


def word_selector(w):
    op = w >> 26
    lo11 = w & 0x7FF
    if op in (0x33, 0x34):
        return {"f5": lo11 & 0x1F, "idx": (lo11 >> 5) & 0x1F,
                "flag": (lo11 >> 10) & 1, "lo11": lo11}
    return {"f5": lo11 & 0x1F, "i6": (lo11 >> 5) & 0x3F, "lo11": lo11}


def target_word(v):
    """last 0x33/0x34/0x36 word of the vector (op38 cmp predecessors and
    prologue loads never match the scan set)."""
    words = [int(w, 16) for w in v.get("words", [])]
    for w in reversed(words):
        if (w >> 26) in TARGET_OPS:
            return w
    return None


def disc_vector_key(v):
    w = target_word(v)
    return word_key(w) if w is not None else None


# --------------------------------------------------------- journal parsing
H_PREFIX = lambda tok: tok if tok.startswith("H-") else "H-" + tok


def _alive_set(cell):
    m = re.search(r"\{([^}]*)\}", cell)
    if not m:
        return None
    toks = [t.strip() for t in m.group(1).split(",") if t.strip()]
    return sorted(H_PREFIX(t) for t in toks)


def _norm_row_id(cell):
    cell = cell.strip()
    m = re.match(r"^op38_sel=(\d+)$", cell)
    if m:
        return "op38_sel=%02x" % int(m.group(1), 10)
    return cell


def _i6(tok):
    return int(tok, 16) if tok.lower().startswith("0x") else int(tok, 16)


def parse_fuzz4rem(lines):
    out = []
    for i, ln in enumerate(lines, 1):
        if not ln.startswith("| V-F5R-"):
            continue
        c = [x.strip() for x in ln.strip().strip("|").split("|")]
        if len(c) < 3 or "op" not in c[1]:
            continue
        alive = _alive_set(c[2])
        if alive is None:
            continue
        out.append({"vector_id": c[0], "row": _norm_row_id(c[1]),
                    "alive": alive, "line": i})
    return out


def parse_map36_groups(lines):
    out = []
    for i, ln in enumerate(lines, 1):
        if not ln.startswith("|"):
            continue
        c = [x.strip() for x in ln.strip().strip("|").split("|")]
        if len(c) < 2 or not re.match(r"^[0-9a-f/ ]+(\(|i6=)", c[0]):
            continue
        alive = _alive_set(c[1])
        if alive is None:
            continue
        # pattern B: comma items "04 i6=0x1c/0x20, 02 i6=0x20"
        if "i6=" in c[0] and "(" not in c[0]:
            for item in c[0].split(","):
                m = re.match(r"^([0-9a-f]+)\s+i6=([0-9a-fx/]+)$",
                             item.strip())
                if not m:
                    continue
                f5 = int(m.group(1), 16)
                for i6tok in m.group(2).split("/"):
                    out.append({"f5": f5, "i6": _i6(i6tok), "alive": alive,
                                "line": i})
            continue
        # pattern A: "03/05/06 (0)" single i6 in parens
        m = re.match(r"^([0-9a-f/]+)\s+\(([0-9a-fx]+)\)$", c[0])
        if not m:
            continue
        i6 = _i6(m.group(2))
        for f5tok in m.group(1).split("/"):
            out.append({"f5": int(f5tok, 16), "i6": i6, "alive": alive,
                        "line": i})
    return out


def parse_rogue34(lines):
    """Fix round 1 corrected table `| (idx,f) | obs | f5 (hex) |`: rows
    are taken only after the 'Fix round 1' heading, so the superseded
    Step-2 table (cells 'f5∈{...}', decimal tokens, f5 >= 0x20) never
    matches.  Radix (Fix round 1): f5 tokens hex; (idx,flag) tokens
    decimal -- cross-checked against covering vector census rows."""
    start = 0
    for i, ln in enumerate(lines):
        if "Fix round 1" in ln:
            start = i + 1
    out = []
    for i, ln in enumerate(lines, 1):
        if i <= start or not ln.lstrip().startswith("| ("):
            continue
        c = [x.strip() for x in ln.strip().strip("|").split("|")]
        if len(c) < 3:
            continue
        m = re.match(r"^\((\d+),([01])\)$", c[0])
        if not m or not re.match(r"^0x[0-9a-f]+$", c[1]):
            continue
        # leading pure hex-pair list; trailing prose ignored (the 0x4 row
        # carries an em-dash note in its f5 cell)
        fm = re.match(r"^([0-9a-f]{2}(,[0-9a-f]{2})*)", c[2])
        if not m or not fm:
            continue
        f5s = [int(t, 16) for t in fm.group(1).split(",")]
        if any(f > 0x1F for f in f5s):
            continue
        out.append({"idx": int(m.group(1), 10), "flag": int(m.group(2), 10),
                    "obs": "0x%08x" % int(c[1], 16), "f5s": f5s, "line": i})
    return out


def parse_nonrogue34(lines):
    """`| вектор | строка | obs | жива |` with строка = '(f5,idx,flag)':
    f5 hex, idx/flag decimal (journal radix, see parse_rogue34)."""
    out = []
    for i, ln in enumerate(lines, 1):
        if not ln.startswith("| V-M34-"):
            continue
        c = [x.strip() for x in ln.strip().strip("|").split("|")]
        if len(c) < 4:
            continue
        m = re.match(r"^\(([0-9a-f]+),(\d+),([01])\)$", c[1])
        if not m or not re.match(r"^0x[0-9a-f]+$", c[2]):
            continue
        model = c[3].split()[0]
        if not re.match(r"^[a-zA-Z0-9-]+$", model):
            continue
        out.append({"vector_id": c[0],
                    "f5": int(m.group(1), 16),
                    "idx": int(m.group(2), 10),
                    "flag": int(m.group(3), 10),
                    "obs": "0x%08x" % int(c[2], 16),
                    "model": H_PREFIX(model), "line": i})
    return out


def parse_map33_examples(lines):
    out = []
    for i, ln in enumerate(lines, 1):
        if not ln.startswith("| V-M33-"):
            continue
        c = [x.strip() for x in ln.strip().strip("|").split("|")]
        if len(c) < 4:
            continue
        m = re.match(r"^op33 f5=([0-9a-f]+)(?: idx=([0-9a-f]+))?"
                     r"(?: flag=([01]))?$", c[1])
        if not m or not re.match(r"^0x[0-9a-f]+$", c[2]):
            continue
        f5, idx, flag = m.group(1), m.group(2) or "00", m.group(3) or "0"
        model = None
        for cand_m in ("depR", "pass", "min", "max"):
            if re.search(r"\b%s\b" % cand_m, c[3]):
                model = H_PREFIX(cand_m)
                break
        out.append({"vector_id": c[0],
                    "row": "op33_f5=%s_idx=%s_flag=%s" % (f5, idx, flag),
                    "obs": "0x%08x" % int(c[2], 16),
                    "model": model,
                    "line": i})
    return out


def parse_journal(text):
    lines = text.splitlines()
    return {"fuzz4rem": parse_fuzz4rem(lines),
            "map36_groups": parse_map36_groups(lines),
            "rogue34": parse_rogue34(lines),
            "nonrogue34": parse_nonrogue34(lines),
            "map33_examples": parse_map33_examples(lines)}


# --------------------------------------------- transcribed journal outcomes
# PRIOR_DEAD: fuzz-4 live deaths (same table as select_merges.py:47-50 /
# consolidate_battery.py) -- live-layer narrowing, keyed per
# select_merges.py:123-127 row_prior_key.
PRIOR_DEAD = {"op36:f5=04": ["H-uge32", "H-ule32"]}

# DISC_RESOLVE (select_merges.py:52-62; task-04 Step 3 + Fix round 1):
# final row outcome after the discriminator round; None => rogue.
DISC_RESOLVE = {
    "op36_f5=0a_i6=00": ("H-V", SRC + ":L197-203"),
    "op33_f5=00_idx=00_flag=1": ("H-pass", SRC + ":L204-206"),
    "op34_f5=0b_idx=10_flag=1": (None, SRC + ":L344 + select_merges.py:60-62"),
}

# disc-round observations (task-04 Step 3): vector -> (restored key,
# observed, source).  Keys restored by lo11 decode (word_key).
DISC_OBSERVED = {
    "V-D34-OPDEP-A": ("op34_f5=04_idx=00_flag=0", "0x00007ffc",
                      SRC + ":L207-208"),
    "V-D34-OPDEP-B": ("op34_f5=08_idx=0a_flag=1", "0x000037ff",
                      SRC + ":L209"),
    "V-D34-F0B": ("op34_f5=0b_idx=00_flag=0", "0x0000100c",
                  SRC + ":L210"),
    "V-D34-F2F1": ("op34_f5=02_idx=00_flag=1", "0x00000005",
                   SRC + ":L211-212"),
    "V-D34-IDX1": ("op34_f5=04_idx=01_flag=0", "0x00000019",
                   SRC + ":L213-214"),
    "V-D34-IDX2": ("op34_f5=04_idx=02_flag=0", "0x00000031",
                   SRC + ":L213-214"),
    "V-D34-IDX3": ("op34_f5=04_idx=03_flag=0", "0x00000061",
                   SRC + ":L213-214"),
    "V-D34-IDX1F": ("op34_f5=04_idx=01_flag=1", "0x0000001b",
                    SRC + ":L213-214"),
    "V-D36-F0A-EQ16": ("op36_f5=0a_i6=00", "0x00000005", SRC + ":L198"),
    "V-D36-F0A-EQ": ("op36_f5=0a_i6=00", "0x00000007", SRC + ":L199"),
    "V-D33-F0F1": ("op33_f5=00_idx=00_flag=1", "0x00000005",
                   SRC + ":L204-205"),
}

# c2rare + fuzz4rem row verdicts (task-04 c2rare table L159-167 and
# fuzz4rem table L62-67; final row outcomes incl. static refutations
# noted there are NOT applied -- live layer only).
C2RARE_VERDICTS = {
    "op16_lo11=028": ("unique", ["H-16-shr32u"], SRC + ":L161"),
    "op16_lo11=03c": ("unique", ["H-16-shr32u"], SRC + ":L161"),
    "op16_lo11=07d": ("unique", ["H-16-shr32u"], SRC + ":L161"),
    "op16_lo11=000": ("unique", ["H-16-zero"], SRC + ":L162"),
    "op39_lo11=000": ("unique", ["H-39-lo"], SRC + ":L163"),
    "op39_lo11=7ff": ("unique", ["H-39-lo"], SRC + ":L163"),
    "op3c_lo11=000": ("multi", ["H-3c-and-lo11", "H-3c-zero"],
                      SRC + ":L164"),
    "op3c_lo11=7ff": ("unique", ["H-3c-zero"], SRC + ":L165"),
    "op0c_imm=0000": ("multi", ["H-0c-hiand", "H-0c-loonly"],
                      SRC + ":L166"),
    "op0c_imm=01ff": ("unique", ["H-0c-hiand"], SRC + ":L167"),
    "op0c_imm=00ff": ("multi", ["H-0c-bswap", "H-0c-hiand"],
                      SRC + ":L67"),
    "op38_sel=00": ("unique", ["H-38self-false"], SRC + ":L66"),
}

# zero-sites explicit rows (task-04 L171-183); map36 i6=0 fill rows use
# FILL_ALIVE (L171-172), the five i6!=0 rows are listed explicitly.
FILL_ALIVE = ["H-eq32", "H-eq16", "H-uge32", "H-ugt32", "H-V"]
ZERO_VERDICTS = {
    "op36_f5=0d_i6=30": ("multi", ["H-eq32i", "H-uge32i", "H-V"],
                         None, SRC + ":L172-173"),
    "op36_f5=11_i6=36": ("multi", ["H-eq32i", "H-uge32i", "H-V"],
                         None, SRC + ":L172-173"),
    "op36_f5=12_i6=2e": ("multi", ["H-eq32i", "H-uge32i", "H-V"],
                         None, SRC + ":L172-173"),
    "op36_f5=18_i6=14": ("multi", ["H-ne32i", "H-lt32i"],
                         None, SRC + ":L173"),
    "op36_f5=1c_i6=16": ("multi", ["H-ne32i", "H-lt32i"],
                         None, SRC + ":L173"),
    "op33_f5=13_idx=14_flag=1": ("unique", ["H-depR"], "0x021f0f0f",
                                 SRC + ":L175-176"),
    "op34_f5=01_idx=00_flag=0": ("unique", ["H-depR"], "0x00000006",
                                 SRC + ":L177"),
    "op38_sel=04": ("div", [], ["0x01016000", "0x01036000", "0x01066000"],
                    SRC + ":L179-183"),
}
MAP33_PROSE = (SRC + ":L89-100")   # all map33 has-rows -> H-depR
MAP33_MODEL = "H-depR"

CMP38_SELF = {
    "unique_model": "H-38self-false",
    "supports": [
        {"cycle": "fuzz-4", "vector_id": "V-op38-self",
         "ref": JOURNAL_F4_REL + ":32",
         "fact": "cmp38-self 7==7 -> cc=F (1-method live fact)"},
        {"cycle": "fuzz-5", "vector_id": "V-F5R-38SELF",
         "ref": JOURNAL_REL + ":66",
         "fact": "self -> cc=F repeat with separating operand 0x1234 "
                 "+ known-T predecessor (double-live)"},
    ],
}


# ------------------------------------------------------------- operands
def operands_seed(v):
    """{rs, rt, seeds} decoded from the vector prologue: addi/addi.hi
    immediates into r5/r6 (r7 fallback), seeds pair (CR 0x8c6 lo /
    0x8c7 hi) for r5 when no immediate feeds it."""
    regs = {}
    tgt = target_word(v)
    words = [int(w, 16) for w in v.get("words", [])]
    for w in words:
        if tgt is not None and w == tgt and (w >> 26) in TARGET_OPS:
            break
        op, rd = w >> 26, (w >> 16) & 0x1F
        if op in (0x00, 0x01) and rd in (5, 6, 7):
            regs[rd] = (regs.get(rd, 0) & 0xFFFF0000) | (w & 0xFFFF)
        elif op in (0x02, 0x03) and rd in (5, 6, 7):
            regs[rd] = ((w & 0xFFFF) << 16) | (regs.get(rd, 0) & 0xFFFF)
    seeds = v.get("seeds")
    out = {}
    if seeds:
        lo = int(seeds.get("0x8c6", "0"), 16)
        hi = int(seeds.get("0x8c7", "0"), 16)
        seed64 = (hi << 32) | lo
        out["seeds"] = dict(seeds)
    else:
        seed64 = None
    rs = regs.get(5, seed64 if seeds else None)
    rt = regs.get(6, regs.get(7))
    if rs is not None:
        out["rs"] = "0x%016x" % rs if seeds and 5 not in regs \
            else "0x%08x" % rs
    if rt is not None:
        out["rt"] = "0x%08x" % rt
    return out or None


def concrete_value(exp):
    """first concrete hex value of an expectation dict ('echo' first,
    then '0x8c8'); 'stock' (no write) is not a value."""
    if not isinstance(exp, dict):
        return None
    for k in ("echo", "0x8c8"):
        v = exp.get(k)
        if isinstance(v, str) and re.match(r"^0x[0-9a-f]+$", v):
            return "0x%08x" % (int(v, 16) & 0xFFFFFFFF)
    return None


# ------------------------------------------------------------------ build
def build(parsed, census, vectors, disc, merges, input_sources):
    rows = census["rows"]
    by_id = {r["id"]: r for r in rows}
    vec_by_id = {v["id"]: v for v in vectors + disc}

    out = {}
    for r in rows:
        out[r["id"]] = {
            "section": "MAIN", "op": r["op"], "selector": r["selector"],
            "live_verdict": "unobserved", "alive_set": [],
            "unique_model": None, "observations": [],
            "source": "census_map.json (no live coverage)",
            "static": (r.get("static") or {}).get("verdict_id"),
            "in_census": True, "coverage": "none",
        }

    # -- battery observations (order: battery before disc) --
    battery_rows = defaultdict(list)
    for v in vectors:
        if v["id"] == "V-F4-MARKER":
            continue
        ops = operands_seed(v)
        for rid in v.get("census_rows", []):
            if rid not in out:
                raise SystemExit("battery vector %s -> unknown row %s"
                                 % (v["id"], rid))
            battery_rows[rid].append(v["id"])
            out[rid]["observations"].append({
                "vector_id": v["id"], "observed": None,
                "operands_seed": ops,
                "source": "fuzz5_vectors.json:" + v["id"]})
            out[rid]["coverage"] = "battery"

    # -- verdict candidates per row --
    cand = defaultdict(list)    # rid -> [(alive_set, source)]
    stated = {}                 # rid -> (observed_or_list, source)

    for rec in parsed["fuzz4rem"]:
        cand[rec["row"]].append(
            (rec["alive"], "%s:L%d" % (SRC, rec["line"])))
    for g in parsed["map36_groups"]:
        rid = "op36_f5=%02x_i6=%02x" % (g["f5"], g["i6"])
        cand[rid].append((g["alive"], "%s:L%d" % (SRC, g["line"])))
    for ex in parsed["map33_examples"]:
        stated.setdefault(ex["row"], (ex["obs"], "%s:L%d"
                                      % (SRC, ex["line"])))
    for r in parsed["rogue34"]:
        for f5 in r["f5s"]:
            rid = "op34_f5=%02x_idx=%02x_flag=%d" % (f5, r["idx"],
                                                     r["flag"])
            cand[rid].append(([], "%s:L%d (rogue)" % (SRC, r["line"])))
            stated.setdefault(rid, (r["obs"], "%s:L%d" % (SRC, r["line"])))
    for r in parsed["nonrogue34"]:
        rid = "op34_f5=%02x_idx=%02x_flag=%d" % (r["f5"], r["idx"],
                                                 r["flag"])
        cand[rid].append(([r["model"]], "%s:L%d" % (SRC, r["line"])))
        stated.setdefault(rid, (r["obs"], "%s:L%d" % (SRC, r["line"])))
    for rid, (tag, alive, src) in C2RARE_VERDICTS.items():
        cand[rid].append((alive, src))
    for rid, (tag, alive, obs, src) in ZERO_VERDICTS.items():
        cand[rid].append((alive, src))
        if obs is not None:
            stated.setdefault(rid, (obs, src))

    # map33 prose rule: every battery-covered map33-group row -> H-depR
    for v in vectors:
        if v.get("group") != "map33" or v["id"] == "V-F4-MARKER":
            continue
        for rid in v.get("census_rows", []):
            cand[rid].append(([MAP33_MODEL], MAP33_PROSE))
    # map36 zero fill: live_only-covered rows with native i6=0
    for v in vectors:
        if not v.get("live_only") or v.get("group") != "map36":
            continue
        for rid in v.get("census_rows", []):
            sel = by_id[rid]["selector"]
            if sel.get("i6", 0) == 0:
                cand[rid].append((FILL_ALIVE, SRC + ":L171-172"))

    # -- finalize verdicts (intersection, PRIOR_DEAD, DISC_RESOLVE) --
    verdicts = {}
    for rid, cands in cand.items():
        if rid not in out:
            continue  # journal rule about a row outside this universe
        alive = set(cands[0][0])
        for a, _s in cands[1:]:
            alive &= set(a)
        row = by_id.get(rid)
        if row and row["op"] == "0x36" and "f5" in row["selector"]:
            pk = "op36:f5=%02x" % row["selector"]["f5"]
            alive -= set(PRIOR_DEAD.get(pk, []))
        src = cands[0][1]
        div = rid in ZERO_VERDICTS and ZERO_VERDICTS[rid][0] == "div"
        if div:
            verdicts[rid] = ("div", [], src)
            continue
        if rid in DISC_RESOLVE:
            res, rsrc = DISC_RESOLVE[rid]
            alive = {res} if res else set()
            src = rsrc
        if not alive:
            verdicts[rid] = ("rogue", [], src)
        elif len(alive) == 1:
            verdicts[rid] = ("unique", sorted(alive), src)
        else:
            verdicts[rid] = ("multi", sorted(alive), src)

    # -- disc observations / extras --
    extras = {}
    for v in disc:
        if v["id"] == "V-F4-MARKER" or v["id"] not in DISC_OBSERVED:
            continue
        key, obs, src = DISC_OBSERVED[v["id"]]
        if key not in out:
            w = target_word(v)
            if w is None:
                raise SystemExit("disc vector %s has no target word"
                                 % v["id"])
            sel = word_selector(w)
            op = "0x%02x" % (w >> 26)
            extras[key] = {
                "section": "MAIN", "op": op, "selector": sel,
                "live_verdict": "rogue", "alive_set": [],
                "unique_model": None, "observations": [],
                "source": src, "static": None, "in_census": False,
                "coverage": "disc",
            }
            target = extras[key]
        else:
            target = out[key]
            if target["coverage"] == "none":
                target["coverage"] = "disc"
            if target["live_verdict"] == "unobserved":
                target["live_verdict"] = "rogue"
                target["source"] = src
        target["observations"].append({
            "vector_id": v["id"], "observed": obs,
            "operands_seed": operands_seed(v),
            "source": src})

    # -- write verdicts + observed into records --
    for rid, (tag, alive, src) in verdicts.items():
        rec = out[rid]
        rec["live_verdict"] = tag
        rec["alive_set"] = alive
        rec["unique_model"] = alive[0] if len(alive) == 1 else None
        rec["source"] = src

    for rid, rec in out.items():
        if rid in stated:
            obs, src = stated[rid]
            for o in rec["observations"]:
                if o["observed"] is None and o["vector_id"].startswith(
                        ("V-M", "V-C2R", "V-F5R")):
                    o["observed"] = obs
                    o["source"] += " + " + src
            continue
        if rec["live_verdict"] in ("unique", "multi") and rec["alive_set"]:
            for o in rec["observations"]:
                if o["observed"] is not None:
                    continue
                v = vec_by_id.get(o["vector_id"])
                if not v:
                    continue
                for m in rec["alive_set"]:
                    val = concrete_value(v.get("expectations", {}).get(m))
                    if val is not None:
                        o["observed"] = val
                        break

    result = {"rows": {}, "cmp38_self": CMP38_SELF, "meta": {}}
    for rid in sorted(set(out) | set(extras)):
        result["rows"][rid] = out.get(rid) or extras[rid]

    # -- cross-gates vs select_merges.json --
    census_verdicted = [rid for rid, r in result["rows"].items()
                        if r["in_census"] and r["live_verdict"] !=
                        "unobserved"]
    battery_covered = sorted(battery_rows)
    got_covered = sorted(rid for rid in census_verdicted
                         if result["rows"][rid]["coverage"] == "battery")
    if got_covered != battery_covered:
        raise SystemExit("gate: battery-covered rows not all verdicted: "
                         "%s" % sorted(set(battery_covered) -
                                       set(got_covered))[:5])
    if merges and len(got_covered) != merges["live_covered"]:
        raise SystemExit("gate: covered %d != select_merges live_covered %d"
                         % (len(got_covered), merges["live_covered"]))
    if merges:
        for op, ref in merges.get("live_only_rows", {}).items():
            got = [rid for rid in got_covered
                   if result["rows"][rid]["op"] == op
                   and not result["rows"][rid]["static"]]
            if len(got) != ref["rows"]:
                raise SystemExit(
                    "gate: op %s live_only rows %d != %d"
                    % (op, len(got), ref["rows"]))
            nrogue = sum(1 for rid in got if result["rows"][rid]
                         ["live_verdict"] == "rogue")
            if nrogue != ref["rogue_rows"]:
                raise SystemExit(
                    "gate: op %s rogue %d != %d"
                    % (op, nrogue, ref["rogue_rows"]))
        for mrec in merges.get("merges", []):
            for rid, tag, _vids in mrec.get("confirms", []):
                r = result["rows"].get(rid)
                if not r or r["live_verdict"] != "unique" \
                        or r["unique_model"] != tag:
                    raise SystemExit("gate: merge confirm %s/%s mismatch"
                                     % (rid, tag))
    for key, vals in (("op34_f5=04_idx=00_flag=0",
                       ["0x0000000c", "0x00007ffc"]),
                      ("op34_f5=08_idx=0a_flag=1",
                       ["0x00003634", "0x000037ff"])):
        got = [o["observed"] for o in result["rows"][key]["observations"]]
        if got != vals:
            raise SystemExit("gate: OPDEP precedent %s: %s" % (key, got))

    # -- meta --
    by_op = defaultdict(lambda: {"rows": 0, "observed": 0,
                                 "unobserved": 0, "with_values": 0})
    for rid, r in result["rows"].items():
        if not r["in_census"]:
            continue
        d = by_op[r["op"]]
        d["rows"] += 1
        if r["live_verdict"] == "unobserved":
            d["unobserved"] += 1
        else:
            d["observed"] += 1
            if any(o["observed"] is not None for o in r["observations"]):
                d["with_values"] += 1
    hist = defaultdict(int)
    for r in result["rows"].values():
        hist[r["live_verdict"]] += 1
    result["meta"] = {
        "census_rows": len(rows),
        "covered_rows": len(got_covered),
        "records": len(result["rows"]),
        "extra_keys": sorted(k for k, r in result["rows"].items()
                             if not r["in_census"]),
        "verdict_counts": dict(sorted(hist.items())),
        "coverage_by_op": {op: dict(d) for op, d in sorted(by_op.items())},
        "inputs": input_sources,
    }
    return result


# ----------------------------------------------------------------- CLI
def md5_of(p):
    return hashlib.md5(Path(p).read_bytes()).hexdigest()


def rel_of(p):
    """repo-relative display path when possible (deterministic artifact
    and manifest), absolute otherwise."""
    p = Path(p).resolve()
    try:
        return str(p.relative_to(REPO.resolve()))
    except ValueError:
        return str(p)


def manifest_lines(inputs):
    return ["%s  %s" % (md5_of(p), rel_of(p)) for p in inputs]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="isa-max-a T3: build normalized fuzz5 live table")
    ap.add_argument("--journal", default=JOURNAL_REL)
    ap.add_argument("--census", default="scripts/probes/cx5-fuzz5/"
                    "census_map.json")
    ap.add_argument("--vectors", default="scripts/probes/cx5-fuzz5/"
                    "fuzz5_vectors.json")
    ap.add_argument("--disc", default="scripts/probes/cx5-fuzz5/"
                    "fuzz5_disc_vectors.json")
    ap.add_argument("--merges", default="scripts/probes/cx5-fuzz5/"
                    "select_merges.json")
    ap.add_argument("--out", default="scripts/probes/cx5-isa-max/"
                    "fuzz5_live.json")
    ap.add_argument("--manifest", default="scripts/probes/cx5-isa-max/"
                    "fuzz5_live_manifest.md5")
    ap.add_argument("--force", action="store_true",
                    help="rewrite the manifest after intentional input "
                         "changes (drift gate is bypassed once)")
    ap.add_argument("--check", action="store_true",
                    help="verify manifest + rebuild determinism against "
                         "the committed artifact; no writes")
    args = ap.parse_args(argv)

    def resolve(p):
        q = Path(p)
        return q if q.is_absolute() or q.exists() else REPO / q

    inputs = [resolve(args.journal), resolve(args.census),
              resolve(args.vectors), resolve(args.disc),
              resolve(args.merges)]
    out_p, manifest = resolve(args.out), resolve(args.manifest)
    if manifest.exists() and not args.force:
        have = {}
        for ln in manifest.read_text().splitlines():
            if ln.strip():
                _md5, _, rel = ln.partition("  ")
                have[rel.strip()] = _md5.strip()
        for p in inputs:
            ref = have.get(rel_of(p))
            if ref is None:
                print("manifest: no entry for %s" % rel_of(p),
                      file=sys.stderr)
                return 2
            if ref != md5_of(p):
                print("manifest drift: %s (%s != %s)"
                      % (rel_of(p), md5_of(p), ref), file=sys.stderr)
                return 2

    parsed = parse_journal(inputs[0].read_text())
    census = json.loads(inputs[1].read_text())
    vectors = json.loads(inputs[2].read_text())
    disc = json.loads(inputs[3].read_text())
    merges = json.loads(inputs[4].read_text())
    src = [{"path": rel_of(p), "md5": md5_of(p)} for p in inputs]
    result = build(parsed, census, vectors, disc, merges, src)
    text = json.dumps(result, indent=1, sort_keys=True) + "\n"

    if args.check:
        if not manifest.exists():
            print("check: manifest missing", file=sys.stderr)
            return 2
        if out_p.read_text() != text:
            print("check: artifact not reproducible", file=sys.stderr)
            return 3
        print("check OK: manifest + determinism (%d records)"
              % len(result["rows"]))
        return 0

    out_p.write_text(text)
    if not manifest.exists() or args.force:
        manifest.write_text("\n".join(manifest_lines(inputs)) + "\n")
    cov = result["meta"]["coverage_by_op"]
    print("fuzz5_live.json: %d records (census %d, covered %d, extras %d)"
          % (result["meta"]["records"], result["meta"]["census_rows"],
             result["meta"]["covered_rows"],
             len(result["meta"]["extra_keys"])))
    for op, d in sorted(cov.items()):
        print("  op %-5s observed %4d/%4d (values %4d)"
              % (op, d["observed"], d["rows"], d["with_values"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
