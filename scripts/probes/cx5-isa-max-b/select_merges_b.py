#!/usr/bin/env python3
"""isa-max cycle B task 3: verdicts B + programmatic merge selection
(C-B.1 tail -> C-B.3 prep).

Row universe: the axes of the B battery matrix (matrix_b_vectors.json,
battery_meta in the marker record) x the observed outcomes
(battery_b_results.json), adjudicated by the T1 adjudicator.  Per axis ->
audit row {key, category, reason}.  Categories (task brief, verbatim
semantics):

  merge                  map36: separated axis, single alive model inside
                         the eq family AND the h36 static leg
                         (H-36-eq-usage, family-grade ruling A) on the
                         selector; c3c: per-literal :zero merge (direct
                         separation on a literal with a rare_verdicts
                         static leg, or the whitelisted lo11=000
                         literal-uniformity transfer that holds);
  merge.rt_invariant     rtfed34: the p34 predicted (P-formula, recomputed
                         here from the selector -- not the matrix
                         self-report) agrees with EVERY observation of the
                         axis AND the rt=X/rt=Y pair discriminates (the
                         rt-fed alternative killed live) -- the A '49
                         rt-fed contradict' residual closes in favor of
                         the rt-invariant P-formula;
  excluded.conflict      two methods disagree: a live-unique model outside
                         the eq family vs the H-36-eq-usage static leg
                         (usage-vs-semantics tension, the f5=2/f5=0a
                         precedent), or a P-formula disagreement with an
                         observation (ruling 2026-11-02: such rows stay
                         residual map rows);
  excluded.single_method vacuous merge of unobserved rows is forbidden
                         (2-confirmation rule);
  excluded.ruling        programmatic exclusion list (0x34 f5=2 idx=5,
                         both flags -- inherited A ruling) and cmp38-self
                         (formalizable=FALSE stays; the B observation
                         goes to the map);
  residual.parked        'could not, parking': live-only rows (no static
                         leg), unseparated axes (tried pairs + reason),
                         non-discriminating X/Y pairs, the inv33 live-only
                         corroborating probe, and the inv38v sel=4 axis
                         (no model in the space survives; the correlation
                         verdict and the observation array are recorded);
  residual.untestable    axes whose observations cannot exist by design
                         (e.g. 0x38 sel in {1,20}: the value form does
                         not write the cc-latch, the killer documented in
                         the A map); for THIS battery the category fires
                         on fixtures only.

merge_ready / dep_merge_unblocked_rows and other advisory flags in the A
artifacts are ignored: the decision above is derived from the contract
fields only (merge = live x static, without weakening).

Sections beyond the per-axis audit:
  inv38v_sel4   correlation statistics over the raw battery.log run lines
                (counter / time / per-op-step discrimination over
                timestamps; non-convergence -> residual with the
                observation array);
  cmp38_self    the B observation -> map; formalization stays blocked
                (formalizable=FALSE);
  c3c_000       the separator outcome -> per-literal merge decision by
                the :zero precedent, with the literal-uniformity
                assumption recorded explicitly (violation -> residual).

Inputs (read-only): battery_b_results.json, matrix_b_vectors.json,
inv38v_runs_raw.log (beside this script: the verbatim
'grep -E "V-B38v-R[0-9]+ run[123]:" battery.log' extraction; provenance
md5 in meta) and the cycle-A static legs h36_verdicts.json,
p34_table.json, rare_verdicts.json, fuzz5_live.json (../cx5-isa-max/).
Output: --out json (default select_merges_b.json beside this script).
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from adjudicate_b import adjudicate, _norm

M32 = 0xffffffff
RTFED_RS = 0x1234
RTFED_X = 0xffffffff
RTFED_Y = 0x00000000

CATEGORIES = (
    "merge",
    "merge.rt_invariant",
    "excluded.conflict",
    "excluded.single_method",
    "excluded.ruling",
    "residual.parked",
    "residual.untestable",
)

EQ_FAMILY = ("H-eq16", "H-eq32", "H-eq32i")

RULING_EXCLUSIONS = [
    {
        "id": "OPEN-34-f5=2-idx=5",
        "op": "0x34",
        "section": "MAIN",
        "selector_fields": {"f5": 2, "idx": 5},
        "reason": (
            "OPEN-34-f5=2-idx=5 ruling (fuzz-5 owner: the f5=2 idx=5 axis "
            "stays OPEN; fuzz-4 V-34-2 rs=0xff/rt=1 -> 0x000400ff is "
            "outside the P-formula and outside fuzz5_live.json; the single "
            "fuzz-5 battery point is non-discriminating) -- inherited by "
            "isa-max B; both flag variants excluded programmatically"
        ),
    },
]

RULE_TEXT = (
    "merge = separated axis & single alive model inside the eq family "
    "{H-eq16,H-eq32,H-eq32i} & h36 static leg H-36-eq-usage on the "
    "selector (family-grade ruling A, :cmp36.eq32 precedent); "
    "merge.rt_invariant = rtfed34 axis: p34 predicted recomputed from the "
    "selector agrees with ALL observations & the rt=X/rt=Y pair "
    "discriminates (rt-fed alternative killed live); live-unique model "
    "outside the eq family vs H-36-eq-usage -> excluded.conflict "
    "(usage-vs-semantics); P-formula disagreement with an observation -> "
    "excluded.conflict (ruling 2026-11-02: residual map rows); no "
    "observations -> excluded.single_method; ruling list + cmp38-self "
    "formalizable=FALSE -> excluded.ruling; live-only / unseparated / "
    "non-discriminating pair / no surviving model -> residual.parked; "
    "advisory flags in the A artifacts are ignored"
)


# --------------------------------------------------------------- helpers ---

def parse_axis(axis):
    """'0x34|MAIN|f5=04,flag=0,idx=00,lo11=004' -> key dict."""
    op, section, fields = axis.split("|")
    selector = {}
    for part in fields.split(","):
        name, _, value = part.partition("=")
        selector[name] = int(value, 16)
    return {"op": op, "section": section, "selector": selector}


def exp_value(exp):
    for chan in ("0x8c8", "echo"):
        if chan in exp:
            return _norm(exp[chan])
    return None


def matches_ruling(key, excl):
    if key.get("op") != excl["op"] or key.get("section") != excl["section"]:
        return False
    sel = key.get("selector") or {}
    return all(sel.get(f) == v for f, v in excl["selector_fields"].items())


def ruling_for(key):
    for excl in RULING_EXCLUSIONS:
        if matches_ruling(key, excl):
            return excl
    return None


def axis_records(records, axis):
    return [r for r in records if r.get("axis") == axis]


# ------------------------------------------------------ static leg index ---

def h36_static_lookup(h36, key):
    for row in h36["phases"]["B"]["rows"]:
        rk = row["key"]
        if rk["op"] == key["op"] and rk["section"] == key["section"] \
                and rk["selector"] == key["selector"]:
            return row.get("static_verdict")
    return None


def p34_rt_lookup(p34, key):
    for row in p34["phases"]["B"]["rows"]:
        rk = row["key"]
        if rk["op"] == key["op"] and rk["section"] == key["section"] \
                and rk["selector"] == key["selector"] \
                and row.get("static_verdict") == "H-34-rt-fed":
            return row
    return None


def rare_lookup(rare, key):
    for row in rare["phases"]["B"]["rows"]:
        rk = row["key"]
        if rk["op"] == key["op"] and rk["section"] == key["section"] \
                and rk["selector"] == key["selector"]:
            return row
    return None


def p_formula(mask, deposit, rs):
    return ((rs & ~int(mask, 16)) & M32) | (int(deposit, 16) & M32)


def p_recompute(sel):
    f5, idx, flag = sel["f5"], sel["idx"], sel["flag"]
    mask32 = M32 if f5 == 0 else (1 << f5) - 1
    return ((mask32 << idx) & M32,
            (((0xc | flag) & mask32) << idx) & M32)


# ------------------------------------------------------------- selectors ---

def channel_killer(records, observed):
    """True when every observation of the axis is 'stock' while no model
    expectation on the axis is 'stock': the probe channel never moved
    (the A-documented killer class, e.g. 0x38 sel!=0 value forms do not
    write the cc-latch) -- the axis is untestable by design, its models
    are not contradicted, they are invisible."""
    obs_vals, stock_expected = [], False
    for rec in records:
        if rec["id"] in observed:
            obs_vals.append(_norm(observed[rec["id"]]))
        for exp in (rec.get("expectations") or {}).values():
            if exp_value(exp) == "stock":
                stock_expected = True
    return (bool(obs_vals)
            and all(v == "stock" for v in obs_vals)
            and not stock_expected)


def select_map36_axis(axis, records, info, static_verdict, observed=None):
    key = parse_axis(axis)
    tried = info.get("tried", 0)
    if tried == 0:
        return {"key": key, "axis": axis, "group": "map36",
                "category": "excluded.single_method",
                "reason": "no observations: vacuous merge of unobserved "
                          "rows forbidden (2-confirmation rule)",
                "tried": 0}
    alive = info.get("alive_models", [])
    dead = info.get("dead_models", [])
    if info.get("separated") and len(alive) == 1:
        model = alive[0]
        if static_verdict is None:
            return {"key": key, "axis": axis, "group": "map36",
                    "category": "residual.parked",
                    "reason": "live-only: unique live model %s (separated, "
                              "%d vector(s)) but no h36 static leg on the "
                              "selector -- single-method row, parked "
                              "(2-confirmation rule)" % (model, tried),
                    "alive_models": alive, "dead_models": dead,
                    "tried": tried}
        if static_verdict == "H-36-eq-usage":
            if model in EQ_FAMILY:
                return {"key": key, "axis": axis, "group": "map36",
                        "category": "merge",
                        "reason": "live unique model %s inside the eq "
                                  "family x h36 static leg H-36-eq-usage "
                                  "(family-grade ruling A, :cmp36.eq32 "
                                  "precedent)" % model,
                        "alive_models": alive, "dead_models": dead,
                        "tried": tried}
            return {"key": key, "axis": axis, "group": "map36",
                    "category": "excluded.conflict",
                    "reason": "live unique model %s is outside the eq "
                              "family while the h36 static leg says "
                              "H-36-eq-usage (usage-vs-semantics tension, "
                              "the f5=2/f5=0a precedent: dead code, "
                              "stale-cc or an incomplete live model) -- "
                              "two methods disagree, no merge" % model,
                    "alive_models": alive, "dead_models": dead,
                    "tried": tried}
        return {"key": key, "axis": axis, "group": "map36",
                "category": "excluded.conflict",
                "reason": "unknown static verdict %r on the selector"
                          % static_verdict,
                "alive_models": alive, "dead_models": dead,
                "tried": tried}
    if info.get("separated") and len(alive) == 0:
        if observed is not None and channel_killer(records, observed):
            return {"key": key, "axis": axis, "group": "map36",
                    "category": "residual.untestable",
                    "reason": "channel killer: every observation is "
                              "'stock' while no model expects 'stock' -- "
                              "the probe channel never moved (the "
                              "A-documented killer class, e.g. 0x38 "
                              "sel!=0 value forms) -- untestable by "
                              "design",
                    "alive_models": [], "dead_models": dead,
                    "tried": tried}
        return {"key": key, "axis": axis, "group": "map36",
                "category": "residual.parked",
                "reason": "every model of the axis contradicted by the "
                          "observations (%d vector(s)); no live model to "
                          "merge, parked with the tried pairs"
                          % tried,
                "alive_models": [], "dead_models": dead, "tried": tried}
    return {"key": key, "axis": axis, "group": "map36",
            "category": "residual.parked",
            "reason": "axis not separated (%d vector(s) tried, alive %s, "
                      "dead %s) -- parking with the tried pairs"
                      % (tried, alive, dead),
            "alive_models": alive, "dead_models": dead, "tried": tried}


def select_rtfed_axis(axis, records, info, p34, observed):
    key = parse_axis(axis)
    recs = [r for r in records if r.get("axis") == axis]
    excl = ruling_for(key)
    if excl is not None:
        return {"key": key, "axis": axis, "group": "rtfed34",
                "category": "excluded.ruling", "reason": excl["reason"],
                "tried": info.get("tried", 0)}
    row = p34_rt_lookup(p34, key)
    sel = key["selector"]
    if row is None:
        return {"key": key, "axis": axis, "group": "rtfed34",
                "category": "excluded.single_method",
                "reason": "no p34 rt-fed static row on the selector: "
                          "single-method row"}
    mask, deposit = p_recompute(sel)
    predicted = row["predicted"]
    if (mask != int(predicted["mask"], 16)
            or deposit != int(predicted["deposit"], 16)):
        return {"key": key, "axis": axis, "group": "rtfed34",
                "category": "excluded.conflict",
                "reason": "p34 predicted does not match the P-formula "
                          "recompute from the selector (%08x/%08x vs "
                          "%s/%s) -- artifact drift, no merge"
                          % (mask, deposit, predicted["mask"],
                             predicted["deposit"]),
                "tried": info.get("tried", 0)}
    rd_p = p_formula(predicted["mask"], predicted["deposit"], RTFED_RS)
    wmask = M32 if sel["f5"] == 0 else (1 << sel["f5"]) - 1
    n_val = n_agree = discriminating = 0
    for rec in recs:
        if rec["id"] not in observed:
            continue
        n_val += 1
        got = _norm(observed[rec["id"]])
        if got == rd_p & M32:
            n_agree += 1
        exps = rec.get("expectations", {})
        rt_alt = exps.get("H-34-rt-fed")
        p_alt = exps.get("H-34-p-formula")
        if rt_alt is not None and p_alt is not None \
                and exp_value(rt_alt) != exp_value(p_alt) \
                and got == exp_value(p_alt):
            discriminating += 1
    if n_val == 0:
        return {"key": key, "axis": axis, "group": "rtfed34",
                "category": "excluded.single_method",
                "reason": "P-row without observations: vacuous merge of "
                          "unobserved rows forbidden (2-confirmation rule)",
                "tried": 0}
    if channel_killer(recs, observed):
        return {"key": key, "axis": axis, "group": "rtfed34",
                "category": "residual.untestable",
                "reason": "channel killer: every observation is 'stock' "
                          "while no model expects 'stock' -- the probe "
                          "channel never moved, untestable by design",
                "n_observations": n_val, "tried": info.get("tried", 0)}
    if n_agree != n_val:
        return {"key": key, "axis": axis, "group": "rtfed34",
                "category": "excluded.conflict",
                "reason": "P-formula disagrees with %d/%d observation(s) "
                          "-- residual map row (ruling 2026-11-02)"
                          % (n_val - n_agree, n_val),
                "n_observations": n_val, "n_agree": n_agree,
                "tried": info.get("tried", 0)}
    if discriminating == 0:
        return {"key": key, "axis": axis, "group": "rtfed34",
                "category": "residual.parked",
                "reason": "predicted agrees with all %d observation(s) "
                          "but the X/Y pair does not discriminate (the "
                          "rt-fed alternative coincides everywhere) -- "
                          "rt-invariance not confirmed, parked" % n_val,
                "n_observations": n_val, "n_agree": n_agree,
                "pair_discriminating": False,
                "tried": info.get("tried", 0)}
    return {"key": key, "axis": axis, "group": "rtfed34",
            "category": "merge.rt_invariant",
            "reason": "p34 predicted (recomputed P-formula) agrees with "
                      "all %d observation(s) and the X/Y pair "
                      "discriminates (%d vector(s)): the deposit is "
                      "rt-invariant, the rt-fed alternative is dead -- "
                      "the A '49 rt-fed contradict' residual closes in "
                      "favor of the P-formula" % (n_val, discriminating),
            "n_observations": n_val, "n_agree": n_agree,
            "pair_discriminating": True,
            "predicted": dict(predicted),
            "tried": info.get("tried", 0)}


def select_inv33_axis(axis, records, info):
    key = parse_axis(axis)
    alive = info.get("alive_models", [])
    if info.get("separated") and alive == ["H-depR"]:
        return {"key": key, "axis": axis, "group": "inv33",
                "category": "residual.parked",
                "reason": "corroborating dep-class probe PASSED: H-depR "
                          "unique at a second idx of f5=0x0f (depM dead) "
                          "-- the dep-class invariant (spec section 3, "
                          "deposit-replace like the merged :dep.c) is "
                          "corroborated; but no static leg for 0x33 "
                          "exists in the A artifacts: live-only row, "
                          "parked (2-confirmation rule)",
                "alive_models": alive,
                "dead_models": info.get("dead_models", []),
                "tried": info.get("tried", 0)}
    if info.get("tried", 0) == 0:
        return {"key": key, "axis": axis, "group": "inv33",
                "category": "excluded.single_method",
                "reason": "corroborating probe unobserved",
                "tried": 0}
    return {"key": key, "axis": axis, "group": "inv33",
            "category": "residual.parked",
            "reason": "corroborating dep-class probe did not confirm "
                      "H-depR (alive %s, dead %s) -- the dep-class "
                      "invariant needs an owner look before any merge "
                      "wave touches the 0x34 dep literals"
                      % (alive, info.get("dead_models", [])),
            "alive_models": alive,
            "dead_models": info.get("dead_models", []),
            "tried": info.get("tried", 0)}


def select_cmp38_self(axis, records, info, rare, fuzz5):
    key = parse_axis(axis)
    canon = fuzz5.get("cmp38_self") or {}
    if canon.get("unique_model") != "H-38self-false":
        raise ValueError("cmp38_self canon drift: %r"
                         % canon.get("unique_model"))
    block = ((rare.get("phases") or {}).get("B") or {}).get("cmp38_self")
    agg = (block or {}).get("aggregate") or {}
    observations = []
    for rec in records:
        exp = (rec.get("expectations") or {}).get("H-38self-false") or {}
        observations.append({"vector_id": rec["id"], "expects": exp})
    alive = info.get("alive_models", [])
    formalizable = bool(agg.get("formalizable"))
    live_model = alive[0] if len(alive) == 1 else None
    section = {
        "live_model": live_model,
        "formalizable": formalizable,
        "observations": observations,
        "note": "the B battery repeats the double-live canon a third time "
                "(fuzz-4, fuzz-5, B); the observation goes to the map as "
                "a live fact (cmp38 rs==rt -> cc=F); formalization stays "
                "blocked: formalizable=FALSE (strict consumer-sensitive "
                "sites, rare_verdicts aggregate)",
    }
    if not info.get("separated") or live_model != "H-38self-false":
        reason = ("cmp38-self: B adjudication did not confirm "
                  "H-38self-false (alive %s) -- unexpected, parked" % alive)
        category = "residual.parked"
    else:
        category = "excluded.ruling"
        reason = ("cmp38-self: H-38self-false confirmed live (B REP/VAR, "
                  "double-live canon x3) but formalizable=FALSE stays "
                  "(strict_sites=%d, strict_insensitive=%d): a self->F "
                  "carve-out would alter FW control flow -- no merge, the "
                  "observation is recorded to the map"
                  % (agg.get("strict_sites", 0),
                     agg.get("strict_insensitive", 0)))
    row = {"key": key, "axis": axis, "group": "cmpself",
           "category": category, "reason": reason,
           "alive_models": alive,
           "dead_models": info.get("dead_models", []),
           "tried": info.get("tried", 0)}
    return row, section


def select_c3c_section(records, axes_info, observed, rare):
    """Per-literal decisions for the c3csep axes: the whitelisted
    inseparable literal (battery_meta.separator_whitelist) receives the
    verdict transferred from the intermediate separation points under the
    literal-uniformity assumption (recorded; violation -> residual)."""
    by_axis = {}
    for rec in records:
        if rec.get("group") == "c3csep":
            by_axis.setdefault(rec["axis"], []).append(rec)
    out = {"literals": [], "assumption_source": "separator_whitelist"}
    literal_rows = {}
    for axis in sorted(by_axis):
        literal = parse_axis(axis)["selector"]["lo11"]
        recs = by_axis[axis]
        info = axes_info[axis]
        static_row = rare_lookup(rare, parse_axis(axis))
        alive = info.get("alive_models", [])
        if info.get("separated") and len(alive) == 1:
            model = alive[0]
            if static_row is not None:
                row = {"literal": literal, "axis": axis, "group": "c3csep",
                       "category": "merge", "basis": "direct",
                       "reason": "separator outcome: live unique %s "
                                 "directly at lo11=0x%03x x static leg %s "
                                 "-- per-literal merge by the :zero "
                                 "precedent"
                                 % (model, literal,
                                    static_row.get("static_verdict")),
                       "alive_models": alive,
                       "tried": info.get("tried", 0)}
            else:
                row = {"literal": literal, "axis": axis, "group": "c3csep",
                       "category": "residual.parked", "basis": "direct",
                       "reason": "live-only literal: separator confirmed "
                                 "%s at lo11=0x%03x but no rare_verdicts "
                                 "static row on the literal -- parked "
                                 "(2-confirmation rule)" % (model, literal),
                       "alive_models": alive,
                       "tried": info.get("tried", 0)}
            literal_rows[literal] = row
            continue
        rec = recs[0]
        obs = _norm(observed[rec["id"]]) if rec["id"] in observed else None
        literal_rows[literal] = {"literal": literal, "axis": axis,
                                 "group": "c3csep", "observed": obs,
                                 "record": rec, "info": info}
    out["_staging"] = literal_rows
    intermediates = sorted(lit for lit, r in literal_rows.items()
                           if r.get("category") is not None)
    winners = None
    for lit in intermediates:
        alive = set(literal_rows[lit].get("alive_models") or [])
        winners = alive if winners is None else (winners & alive)
    candidates = sorted(winners) if winners is not None else []
    for literal, staged in sorted(literal_rows.items()):
        if staged.get("category") is not None:
            row = dict(staged)
            row["key"] = parse_axis(staged["axis"])
            out["literals"].append(row)
            continue
        axis = staged["axis"]
        key = parse_axis(axis)
        rec, info = staged["record"], staged["info"]
        obs = staged["observed"]
        static_row = rare_lookup(rare, key)
        uni = {
            "assumption": "verdict transfer from the intermediate "
                          "separation points relies on the "
                          "literal-uniformity assumption (both models "
                          "predict rd=0 at lo11=000; battery_meta "
                          "separator_whitelist entry)",
            "intermediate_points": intermediates,
            "winner_candidates": candidates,
            "violation": False,
        }
        if len(candidates) != 1:
            row = {"literal": literal, "key": key, "axis": axis,
                   "group": "c3csep", "category": "residual.parked",
                   "basis": "transfer",
                   "reason": "no unique winner across the intermediate "
                             "points (candidates %s): the transfer to "
                             "lo11=0x%03x is not justified -- residual"
                             % (candidates, literal),
                   "literal_uniformity": uni, "tried": info.get("tried", 0)}
            out["literals"].append(row)
            continue
        winner = candidates[0]
        winner_pred = exp_value(
            (rec.get("expectations") or {}).get(winner) or {})
        if obs is None or obs != winner_pred:
            uni["violation"] = True
            row = {"literal": literal, "key": key, "axis": axis,
                   "group": "c3csep", "category": "residual.parked",
                   "basis": "transfer",
                   "reason": "literal-uniformity VIOLATION: observed %s "
                             "at lo11=0x%03x is not the prediction of the "
                             "intermediate winner %s (%s) -- third "
                             "behavior at the literal, residual with the "
                             "observation" % (obs, literal, winner,
                                              winner_pred),
                   "literal_uniformity": uni,
                   "observed": ("0x%08x" % obs) if obs is not None else None,
                   "tried": info.get("tried", 0)}
            out["literals"].append(row)
            continue
        if static_row is None:
            row = {"literal": literal, "key": key, "axis": axis,
                   "group": "c3csep", "category": "residual.parked",
                   "basis": "transfer",
                   "reason": "transfer holds (%s predicted and observed "
                             "at lo11=0x%03x) but no static leg on the "
                             "literal -- live-only, parked" % (winner,
                                                              literal),
                   "literal_uniformity": uni, "tried": info.get("tried", 0)}
            out["literals"].append(row)
            continue
        row = {"literal": literal, "key": key, "axis": axis,
               "group": "c3csep", "category": "merge", "basis": "transfer",
               "reason": "separator outcome: %s wins at the intermediate "
                         "points and its prediction matches the "
                         "observation at lo11=0x%03x (uniformity holds) x "
                         "static leg %s -- per-literal merge by the "
                         ":zero precedent, transfer assumption recorded"
                         % (winner, literal,
                            static_row.get("static_verdict")),
               "literal_uniformity": uni, "alive_models": [winner],
               "tried": info.get("tried", 0)}
        out["literals"].append(row)
    out.pop("_staging")
    return out


# ---------------------------------------------------------- separator x ---

def crosscheck_separation(records, observed, axes_info, whitelist):
    """Programmatic check against the T1 separator DESIGN (the matrix
    records), not the adjudicator self-report: every axis reported
    'separated' must have, for each (dead, alive) model pair, at least one
    OBSERVED vector whose expectations for the two models differ; an
    all-dead separated axis must have every dead model directly
    contradicted by an observed vector."""
    by_axis = {}
    for rec in records:
        ax = rec.get("axis")
        if ax:
            by_axis.setdefault(ax, []).append(rec)
    report = {}
    for axis, info in axes_info.items():
        recs = by_axis.get(axis, [])
        models = sorted({m for r in recs
                         for m in (r.get("expectations") or {})})
        alive = set(info.get("alive_models") or [])
        dead = set(info.get("dead_models") or [])
        if axis in whitelist:
            report[axis] = {"status": "whitelisted", "ok": True,
                            "missing_pairs": []}
            continue
        missing = []
        for m in sorted(dead):
            if alive:
                witnesses = [
                    r for r in recs if r["id"] in observed
                    and m in (r.get("expectations") or {})
                    and any(a in (r.get("expectations") or {})
                            and exp_value(r["expectations"][m])
                            != exp_value(r["expectations"][a])
                            for a in alive)]
            else:
                witnesses = [
                    r for r in recs if r["id"] in observed
                    and m in (r.get("expectations") or {})
                    and exp_value(r["expectations"][m])
                    != _norm(observed[r["id"]])]
            if not witnesses:
                missing.append(m)
        report[axis] = {
            "status": "ok" if not missing else "missing_separator",
            "ok": not missing,
            "missing_pairs": missing,
            "models": models,
        }
    return report


# ------------------------------------------------------------- inv38v -----

RUN_RE = re.compile(
    r"^(\d\d):(\d\d):(\d\d) \| V-B38v-R(\d+) run(\d): rc=(\d+) "
    r"cr0x8c8=0x([0-9a-f]{8}) ")


def parse_inv38v_runs(text):
    runs = []
    for line in text.splitlines():
        m = RUN_RE.match(line)
        if not m:
            raise ValueError("unparseable inv38v run line: %r" % line)
        hh, mm, ss, rep, n, rc, cr = m.groups()
        if rc != "0":
            raise ValueError("non-zero rc in inv38v run line: %r" % line)
        t = int(hh) * 3600 + int(mm) * 60 + int(ss)
        crv = int(cr, 16)
        runs.append({"repeat": int(rep), "run": int(n), "t": t, "cr": crv,
                     "byte": (crv >> 16) & 0xff})
    return runs


def op_positions(records, third_run_ids):
    """Temporal positions of every tool op (marker or run) in the session,
    file order: per vector -- pre-marker, run1, run2, run3 (iff the
    battery reports divergence for it), post-marker."""
    ops = []
    for rec in records:
        if rec["id"] == "V-F4-MARKER":
            continue
        ops.append(("marker", rec["id"]))
        ops.append(("run", rec["id"]))
        ops.append(("run", rec["id"]))
        if rec["id"] in third_run_ids:
            ops.append(("run", rec["id"]))
        ops.append(("marker", rec["id"]))
    return ops


def _fit_step(deltas, units, mod=8):
    """The steps s in 1..mod-1 with delta == s*unit (mod mod) for every
    transition; returns the fitting steps."""
    fits = []
    for s in range(1, mod):
        if all(d == (s * u) % mod for d, u in zip(deltas, units)):
            fits.append(s)
    return fits


def inv38v_statistics(records, runs, third_run_ids=None):
    """Counter / time discrimination for the volatile byte [23:16]:
    hypotheses -- a session counter advanced by every tool op (markers +
    runs), a counter advanced by vector runs only, and wall-clock time
    (seconds).  Converged iff one hypothesis explains EVERY transition."""
    third_run_ids = third_run_ids if third_run_ids is not None else {
        r["id"] for r in records if r.get("group") == "inv38v"}
    ops = op_positions(records, third_run_ids)
    inv_pos = [i for i, (k, v) in enumerate(ops)
               if k == "run" and v.startswith("V-B38v")]
    if len(inv_pos) != len(runs):
        raise ValueError("op sequence covers %d inv38v runs, raw data has "
                         "%d" % (len(inv_pos), len(runs)))
    pos_of = {idx: p for p, idx in enumerate(inv_pos)}
    value_counts = {}
    for r in runs:
        value_counts[str(r["byte"])] = value_counts.get(str(r["byte"]),
                                                        0) + 1
    within_steps = {}
    deltas, op_units, run_units, time_units = [], [], [], []
    for p in range(len(runs) - 1):
        a, b = runs[p], runs[p + 1]
        pa, pb = inv_pos[p], inv_pos[p + 1]
        deltas.append((b["byte"] - a["byte"]) % 8)
        op_units.append(pb - pa)
        run_units.append(sum(1 for i in range(pa, pb)
                             if ops[i][0] == "run"))
        time_units.append(max(0, b["t"] - a["t"]))
        if a["repeat"] == b["repeat"]:
            d = deltas[-1]
            within_steps[str(d)] = within_steps.get(str(d), 0) + 1
    per_op = _fit_step(deltas, op_units)
    per_run = _fit_step(deltas, run_units)
    per_time = _fit_step(deltas, time_units)
    total = len(deltas)

    def best_fit(units):
        step, matches = max(
            ((s, sum(1 for d, u in zip(deltas, units)
                     if d == (s * u) % 8)) for s in range(1, 8)),
            key=lambda x: x[1])
        return {"best_step": step, "best_matches": matches}

    fit_report = {
        "counter_per_tool_op": best_fit(op_units),
        "counter_per_vector_run": best_fit(run_units),
        "time": dict(
            best_fit(time_units),
            naive_step1_matches=sum(1 for d, u in zip(deltas, time_units)
                                    if d == u % 8),
            note="the best single-step time fit aliases the 1-second "
                 "within-repeat gaps (step 3 there matches the per-op "
                 "counter); the naive +1/s step is step-1 matches"),
    }
    if per_op:
        verdict, hypothesis = "converged_counter", {
            "kind": "counter_per_tool_op", "step": per_op[0],
            "steps_fitting": per_op, "matches": total, "total": total}
    elif per_run:
        verdict, hypothesis = "converged_counter", {
            "kind": "counter_per_vector_run", "step": per_run[0],
            "steps_fitting": per_run, "matches": total, "total": total}
    elif per_time:
        verdict, hypothesis = "converged_time", {
            "step": per_time[0], "steps_fitting": per_time,
            "matches": total, "total": total}
    else:
        kind, matches = max(
            ((name, fit_report[name]["best_matches"])
             for name in ("counter_per_tool_op",
                          "counter_per_vector_run", "time")),
            key=lambda x: x[1])
        verdict, hypothesis = "non_convergence", {
            "kind": kind, "matches": matches, "total": total,
            "note": "no hypothesis explains every transition; the "
                    "free-running internal state (DIV-remainder class) "
                    "remains the fallback explanation"}
    return {
        "n_runs": len(runs),
        "value_counts": dict(sorted(value_counts.items())),
        "within_repeat_steps": dict(sorted(within_steps.items())),
        "verdict": verdict,
        "hypothesis": hypothesis,
        "fit_report": fit_report,
        "transitions": [
            {"from": "R%02d/%d" % (a["repeat"], a["run"]),
             "to": "R%02d/%d" % (b["repeat"], b["run"]),
             "delta": d, "ops_between": o, "run_ops_between": rr,
             "gap_s": t}
            for (a, b), d, o, rr, t in zip(zip(runs, runs[1:]), deltas,
                                           op_units, run_units,
                                           time_units)],
    }


def select_inv38v_axis(axis, stats):
    key = parse_axis(axis)
    if stats["verdict"] == "non_convergence":
        reason = ("correlation statistics do not converge (%s: %d/%d "
                  "transitions): the volatile byte stays unexplained -- "
                  "residual with the observation array"
                  % (stats["hypothesis"]["kind"],
                     stats["hypothesis"]["matches"],
                     stats["hypothesis"]["total"]))
    else:
        reason = ("correlation statistics CONVERGED (%s, step +%d, "
                  "%d/%d transitions): the byte is a deterministic "
                  "session counter readout, not operand noise -- but no "
                  "model of the axis space survives and there is no "
                  "static leg; the semantics stays a residual map row "
                  "with the observation array"
                  % (stats["hypothesis"]["kind"],
                     stats["hypothesis"]["step"],
                     stats["hypothesis"]["matches"],
                     stats["hypothesis"]["total"]))
    return {"key": key, "axis": axis, "group": "inv38v",
            "category": "residual.parked", "reason": reason,
            "alive_models": [], "dead_models": [
                "H-38v-bool-eq", "H-38v-bool-ne", "H-38v-rs", "H-38v-rt"],
            "tried": stats["n_runs"]}


# ------------------------------------------------------------- pipeline ---

def run_selection(records, battery, raw_runs_text, h36, p34, rare, fuzz5):
    observed = battery["observed"]
    meta = battery.get("meta") or {}
    health = battery.get("health") or {}
    adj = adjudicate(records, observed)
    axes_info = adj["axes"]
    counts = {c: 0 for c in CATEGORIES}
    audit = []
    merges = {"map36": [], "rtfed34": [], "c3c": []}
    axis_table = []
    sections = {}
    whitelist = {}
    marker = [r for r in records if r["id"] == "V-F4-MARKER"]
    if marker:
        whitelist = (marker[0].get("battery_meta") or {}).get(
            "separator_whitelist") or {}

    def emit(row):
        counts[row["category"]] += 1
        audit.append(row)
        status = ("separated"
                  if row["category"] in ("merge", "merge.rt_invariant",
                                         "excluded.conflict",
                                         "excluded.ruling")
                  else "parked")
        axis_table.append({
            "axis": row.get("axis"), "group": row.get("group"),
            "status": status, "category": row["category"],
            "alive_models": row.get("alive_models", []),
            "dead_models": row.get("dead_models", []),
            "tried": row.get("tried", 0), "reason": row["reason"]})
        return row

    third_run_ids = set()
    inv38v_health = health.get("inv38v") or {}
    if inv38v_health.get("divergence_runs3"):
        third_run_ids = {r["id"] for r in records
                         if r.get("group") == "inv38v"}

    for axis in sorted(axes_info):
        info = axes_info[axis]
        group = None
        for rec in records:
            if rec.get("axis") == axis:
                group = rec.get("group")
                break
        recs = axis_records(records, axis)
        if group == "map36":
            static = h36_static_lookup(h36, parse_axis(axis))
            row = emit(select_map36_axis(axis, recs, info, static,
                                         observed))
            if row["category"] == "merge":
                merges["map36"].append(
                    {"key": row["key"], "model": row["alive_models"][0],
                     "static": static})
        elif group == "rtfed34":
            row = emit(select_rtfed_axis(axis, recs, info, p34, observed))
            if row["category"] == "merge.rt_invariant":
                merges["rtfed34"].append(
                    {"key": row["key"], "predicted": row["predicted"],
                     "n_observations": row["n_observations"],
                     "n_agree": row["n_agree"],
                     "pair_discriminating": row["pair_discriminating"]})
        elif group == "inv33":
            emit(select_inv33_axis(axis, recs, info))
        elif group == "cmpself":
            row, section = select_cmp38_self(axis, recs, info, rare, fuzz5)
            emit(row)
            sections["cmp38_self"] = section
        elif group == "c3csep":
            continue
        elif group == "inv38v":
            runs = parse_inv38v_runs(raw_runs_text)
            stats = inv38v_statistics(records, runs, third_run_ids)
            row = select_inv38v_axis(axis, stats)
            emit(row)
            sections["inv38v_sel4"] = {
                "axis": axis,
                "dataset": "raw battery.log run lines (36 runs, 12 repeats"
                           " x 3; md5 provenance in meta.inv38v_dataset)",
                "statistics": stats,
                "observations": [
                    {"repeat": r["repeat"], "run": r["run"],
                     "t": "%02d:%02d:%02d" % (r["t"] // 3600,
                                              (r["t"] // 60) % 60,
                                              r["t"] % 60),
                     "cr0x8c8": "0x%08x" % r["cr"],
                     "volatile_byte": r["byte"]}
                    for r in runs],
                "category": row["category"],
            }
        else:
            raise ValueError("axis %s: unknown group %r" % (axis, group))

    c3c_records_flat = [r for r in records if r.get("group") == "c3csep"]
    c3c_info = {a: axes_info[a] for a in axes_info
                if a in {r.get("axis") for r in c3c_records_flat}}
    c3c = select_c3c_section(c3c_records_flat, c3c_info, observed, rare)
    sections["c3c_000"] = c3c
    for lit_row in c3c["literals"]:
        counts[lit_row["category"]] += 1
        audit.append(lit_row)
        axis_table.append({
            "axis": lit_row["axis"], "group": "c3csep",
            "status": ("separated"
                       if lit_row["category"] == "merge" else "parked"),
            "category": lit_row["category"],
            "alive_models": lit_row.get("alive_models", []),
            "tried": lit_row.get("tried", 0),
            "reason": lit_row["reason"]})
        if lit_row["category"] == "merge":
            merges["c3c"].append({
                "literal": lit_row["literal"], "key": lit_row["key"],
                "model": "H-3c-zero",
                "basis": lit_row["basis"],
                "literal_uniformity": lit_row.get("literal_uniformity")})

    crosscheck = crosscheck_separation(records, observed, axes_info,
                                       whitelist)
    return {"counts": counts, "audit": audit, "merges": merges,
            "axis_table": axis_table, "sections": sections,
            "separator_crosscheck": crosscheck,
            "meta_battery": meta}


def _md5(path):
    return hashlib.md5(Path(path).read_bytes()).hexdigest()


def load_real(battery, matrix, raw_runs, h36, p34, rare, fuzz5):
    return {
        "records": json.loads(Path(matrix).read_text()),
        "battery": json.loads(Path(battery).read_text()),
        "raw_runs_text": Path(raw_runs).read_text(),
        "h36": json.loads(Path(h36).read_text()),
        "p34": json.loads(Path(p34).read_text()),
        "rare": json.loads(Path(rare).read_text()),
        "fuzz5": json.loads(Path(fuzz5).read_text()),
        "paths": {"battery": battery, "matrix": matrix,
                  "raw_runs": raw_runs, "h36": h36, "p34": p34,
                  "rare": rare, "fuzz5": fuzz5},
    }


def run_real(battery, matrix, raw_runs, h36, p34, rare, fuzz5):
    d = load_real(battery, matrix, raw_runs, h36, p34, rare, fuzz5)
    rep = run_selection(d["records"], d["battery"], d["raw_runs_text"],
                        d["h36"], d["p34"], d["rare"], d["fuzz5"])
    pins = {}
    for name, p in d["paths"].items():
        pins[Path(p).name] = _md5(p)
    rep["meta"] = {
        "cycle": "isa-max-b task-3 (C-B.1 tail -> C-B.3 prep)",
        "generated_by": "scripts/probes/cx5-isa-max-b/select_merges_b.py",
        "rule": RULE_TEXT,
        "eq_family": list(EQ_FAMILY),
        "ruling_exclusions": RULING_EXCLUSIONS,
        "pins": pins,
        "inv38v_dataset": {
            "source": "root-mellanox:/root/isa-max-b-battery/battery.log, "
                      "grep -E 'V-B38v-R[0-9]+ run[123]:' (read-only "
                      "ssh, 2026-11-02)",
            "battery_log_md5": "60aedb7aa534ad961d522c5bf93bebd0",
            "battery_log_md5_manifest": "battery_b_results_manifest.md5",
            "extraction": "inv38v_runs_raw.log (36 lines, verbatim)",
            "note": "the consolidated battery observed carries the run1 "
                    "value of each repeat only; the full 0..7 range lives "
                    "in this raw dataset",
        },
        "battery_meta": rep.pop("meta_battery"),
    }
    return rep


def main(argv=None):
    here = Path(__file__).resolve().parent
    a_dir = here.parent / "cx5-isa-max"
    ap = argparse.ArgumentParser(
        description="isa-max cycle B task-3 merge selection "
                    "(see module docstring)")
    ap.add_argument("--out", default=str(here / "select_merges_b.json"))
    ap.add_argument("--battery", default=str(here / "battery_b_results.json"))
    ap.add_argument("--matrix", default=str(here / "matrix_b_vectors.json"))
    ap.add_argument("--raw-runs", default=str(here / "inv38v_runs_raw.log"))
    ap.add_argument("--h36", default=str(a_dir / "h36_verdicts.json"))
    ap.add_argument("--p34", default=str(a_dir / "p34_table.json"))
    ap.add_argument("--rare", default=str(a_dir / "rare_verdicts.json"))
    ap.add_argument("--fuzz5", default=str(a_dir / "fuzz5_live.json"))
    args = ap.parse_args(argv)
    rep = run_real(args.battery, args.matrix, args.raw_runs, args.h36,
                   args.p34, args.rare, args.fuzz5)
    Path(args.out).write_text(
        json.dumps(rep, indent=1, sort_keys=True) + "\n")
    print("=== isa-max B merge selection ===")
    total = sum(rep["counts"].values())
    for cat in CATEGORIES:
        print("  %-26s %d" % (cat, rep["counts"][cat]))
    print("  %-26s %d" % ("total audited rows", total))
    bad = {a: e for a, e in rep["separator_crosscheck"].items()
           if e.get("status") not in ("ok", "whitelisted")}
    print("separator cross-check: %s"
          % ("ALL OK" if not bad else "MISSING: %s" % sorted(bad)))
    sec = rep["sections"]["inv38v_sel4"]["statistics"]
    print("inv38v sel=4: %s (%s)" % (sec["verdict"], sec["hypothesis"]))
    for name, m in (("map36", rep["merges"]["map36"]),
                    ("rtfed34", rep["merges"]["rtfed34"]),
                    ("c3c", rep["merges"]["c3c"])):
        print("  merges %-7s %d" % (name, len(m)))
    print("written: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
