#!/usr/bin/env python3
"""isa-max A task 8: merge wave A selection over the T4-T7 verdict artifacts.

Unified per-row contract (T4-T7, phase B = join phase):
    {key: {section, op, selector}, static_verdict|null, unique: bool,
     basis, conflict: bool, live_join}  (+ predicted for 0x34 P-rows)

Selection rules (task brief, verbatim semantics):
  merge                    static_verdict != None AND unique AND live unique
                           model matched (live_join.status == "match") AND
                           conflict == false -- for rows whose live leg is a
                           resolved unique model (h36 / h16 / rare axes);
  merge.p_model_full_obs   op 0x34 P-rows: static_verdict != None (raw
                           def-use leg) AND value-bearing observations[]
                           NON-empty AND predicted agrees with ALL of them
                           (live leg = re-evaluation of every captured
                           fuzz5_live observation, rogue rows included;
                            unique_model is not required) AND conflict == false
                            -- this is how the P-table result itself merges;
                           a raw rt_live signal below RT_FED_MIN on such a
                           row is adjudicated noise per-row in p34_table.json
                           (rt_live_adjudication, owner ruling 2026-11-01);
  excluded.single_method   live silence (no observations): a vacuous merge of
                           unobserved rows is forbidden (2-confirmation rule);
  excluded.live_only       live observations present but static_verdict is
                           None (no second method);
  excluded.conflict        row.conflict or live_join.status in
                           {"conflict", "contradiction"} or a P-model
                           disagreement with a captured observation;
  excluded.ruling          the script exclusion list below (fuzz-5 owner
                           rulings, programmatic, not a comment) and the
                           documented cmp38-self exclusion when its category
                           does not fire;
  merge.double_live_formalizable  cmp38-self only: double_live AND
                           aggregate.formalizable (spec sanction).

merge_ready / dep_merge_unblocked_rows in the sources are ADVISORY and are
ignored: the decision above is derived from the contract fields only.

Inputs (read-only): h36_verdicts.json, p34_table.json, h16_verdicts.json,
rare_verdicts.json, fuzz5_live.json (all beside this script).
Output: --out json (default select_merges_a.json beside this script).
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

CATEGORIES = (
    "merge",
    "merge.p_model_full_obs",
    "merge.double_live_formalizable",
    "excluded.live_only",
    "excluded.single_method",
    "excluded.conflict",
    "excluded.ruling",
)

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
            "fuzz-5 battery point is non-discriminating) -- no slaspec "
            "semantics for this axis, both flag variants"
        ),
    },
]

CMP38_SELF_KEY = {"section": "MAIN", "op": "0x38",
                  "selector": {"rs_eq_rt": True}}


def matches_exclusion(key, excl):
    if key.get("op") != excl["op"] or key.get("section") != excl["section"]:
        return False
    sel = key.get("selector") or {}
    return all(sel.get(f) == v for f, v in excl["selector_fields"].items())


def p_value_check(predicted, observations):
    """(n_value, n_agree) of value-bearing observations vs the P-formula
    rd = (rs & ~mask) | deposit (32-bit, rs from operands_seed)."""
    mask = int(predicted["mask"], 16) & 0xFFFFFFFF
    deposit = int(predicted["deposit"], 16) & 0xFFFFFFFF
    n_val = n_agree = 0
    for o in observations:
        if o.get("observed") is None:
            continue
        n_val += 1
        rs = int(o["operands_seed"]["rs"], 16) & 0xFFFFFFFF
        want = ((rs & ~mask) | deposit) & 0xFFFFFFFF
        if want == int(o["observed"], 16):
            n_agree += 1
    return n_val, n_agree


def _has_live_observations(row, live_obs):
    lj = row.get("live_join") or {}
    if lj.get("status") == "match":
        return True
    return bool(live_obs) and any(
        o.get("observed") is not None for o in live_obs)


def categorize_row(row, live_obs, exclusions=RULING_EXCLUSIONS):
    """(category, reason) for one phase-B row; live_obs is the fuzz5_live
    observations list for op 0x34 P-rows (None when there is no live row)."""
    key = row["key"]
    for excl in exclusions:
        if matches_exclusion(key, excl):
            return "excluded.ruling", excl["reason"]
    lj = row.get("live_join") or {}
    if row.get("conflict") or lj.get("status") in ("conflict",
                                                   "contradiction"):
        why = ("row conflict flag" if row.get("conflict")
               else "live_join status %s (live model outside the static "
                    "family / usage-vs-semantics tension)" % lj["status"])
        return ("excluded.conflict",
                "%s -- two methods disagree, no merge" % why)
    static = row.get("static_verdict")
    if static is None:
        if _has_live_observations(row, live_obs):
            return ("excluded.live_only",
                    "live observations present but no static verdict "
                    "(single-method row)")
        return ("excluded.single_method",
                "no static verdict and no live observations")
    if key["op"] == "0x34":
        n_val, n_agree = p_value_check(row["predicted"], live_obs or [])
        if n_val == 0:
            return ("excluded.single_method",
                    "live_join silence: observations[] empty -- vacuous "
                    "merge of an unobserved P-row forbidden")
        if n_agree != n_val:
            return ("excluded.conflict",
                    "P-formula disagrees with %d/%d captured "
                    "observation(s)" % (n_val - n_agree, n_val))
        adj = row.get("rt_live_adjudication") or {}
        reason = ("static %s (raw def-use leg) + predicted agrees with all "
                  "%d captured observation(s) (fuzz5_live re-evaluation)"
                  % (static, n_val))
        if adj.get("verdict") == "noise":
            reason += ("; raw rt_live signal (%d site(s)) adjudicated "
                       "noise per-row (owner ruling 2026-11-01)"
                       % len(adj.get("sites") or []))
        return ("merge.p_model_full_obs", reason)
    if lj.get("status") == "match" and lj.get("live_verdict") == "unique":
        if not row.get("unique"):
            return ("excluded.single_method",
                    "live unique model matched but the static leg is "
                    "non-unique (no model-grade verdict)")
        return ("merge",
                "static %s + live unique model %s matched (live_join "
                "match)" % (static, lj.get("unique_model")))
    if lj.get("status") == "silence" or lj.get("status") is None:
        return ("excluded.single_method",
                "live_join silence: single-method row (static %s only, "
                "vacuous merge of unobserved rows forbidden)" % static)
    return ("excluded.single_method",
            "live_join status %s with live_verdict %s: no unique live "
            "model confirmed" % (lj.get("status"), lj.get("live_verdict")))


def categorize_cmp38_self(block):
    """cmp38-self pre-sweep outcome: the spec-sanctioned category
    double_live AND formalizable; anything less lands excluded."""
    live = block.get("live_join") or {}
    agg = block.get("aggregate") or {}
    if not live.get("double_live"):
        return ("excluded.single_method",
                "cmp38-self: single live support only (no double-live)")
    if agg.get("formalizable"):
        return ("merge.double_live_formalizable",
                "cmp38-self: double-live (%d supports) + formalizable "
                "sweep (insensitive consumers)" % len(
                    live.get("supports") or []))
    return ("excluded.ruling",
            "CMP38-SELF documented exclusion: double-live holds (both "
            "supports cited) but the T7 aggregate says formalizable=FALSE "
            "(strict_sites=%d, strict_insensitive=%d -- consumer-sensitive "
            "strict code); a self->F carve-out would alter FW behavior, "
            "the axis stays residual"
            % (agg.get("strict_sites", 0), agg.get("strict_insensitive", 0)))


def _live34_index(fuzz5_live):
    idx = {}
    for row in (fuzz5_live.get("rows") or {}).values():
        if row.get("op") != "0x34":
            continue
        key = {"section": row["section"], "op": "0x34",
               "selector": row["selector"]}
        idx[json.dumps(key, sort_keys=True)] = row.get("observations") or []
    return idx


def run_selection(docs):
    """docs: {h36, p34, h16, rare, fuzz5_live} parsed artifact dicts."""
    live34 = _live34_index(docs.get("fuzz5_live") or {})
    audit = []
    counts = {c: 0 for c in CATEGORIES}
    merges = {"h36": [], "p34": [], "h16": [], "rare": []}

    for source, name in (("h36", "h36"), ("p34", "p34"),
                         ("h16", "h16"), ("rare", "rare")):
        rows = (docs.get(source) or {}).get("phases", {}).get("B", {}).get(
            "rows") or []
        for row in rows:
            key = row["key"]
            live_obs = live34.get(json.dumps(key, sort_keys=True)) \
                if key["op"] == "0x34" else None
            cat, reason = categorize_row(row, live_obs)
            counts[cat] += 1
            audit.append({"key": key, "source": name,
                          "category": cat, "reason": reason})
            if cat.startswith("merge"):
                entry = {"key": key,
                         "live_join": row.get("live_join")}
                if key["op"] == "0x34":
                    entry["predicted"] = row["predicted"]
                    entry["n_observations"], entry["n_agree"] = \
                        p_value_check(row["predicted"], live_obs or [])
                    adj = row.get("rt_live_adjudication") or {}
                    if adj.get("verdict") == "noise":
                        entry["rt_live_adjudication"] = {
                            "verdict": "noise",
                            "n_sites": len(adj.get("sites") or []),
                        }
                merges[name].append(entry)

    cmp38 = None
    block = (docs.get("rare") or {}).get("phases", {}).get("B", {}).get(
        "cmp38_self")
    if block is not None:
        cat, reason = categorize_cmp38_self(block)
        counts[cat] += 1
        audit.append({"key": dict(CMP38_SELF_KEY), "source": "cmp38_self",
                      "category": cat, "reason": reason})
        cmp38 = {"key": dict(CMP38_SELF_KEY), "category": cat,
                 "reason": reason,
                 "aggregate": block.get("aggregate"),
                 "double_live": (block.get("live_join") or {}).get(
                     "double_live")}

    return {"counts": counts, "audit": audit, "merges": merges,
            "cmp38_self": cmp38}


def md5_of(path):
    return hashlib.md5(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(
        description="isa-max A task 8: merge wave A selection (T4-T7)")
    ap.add_argument("--out", default=str(HERE / "select_merges_a.json"))
    args = ap.parse_args()

    docs = {}
    pins = {}
    for source, fname in (("h36", "h36_verdicts.json"),
                          ("p34", "p34_table.json"),
                          ("h16", "h16_verdicts.json"),
                          ("rare", "rare_verdicts.json"),
                          ("fuzz5_live", "fuzz5_live.json")):
        p = HERE / fname
        docs[source] = json.loads(p.read_text())
        pins[fname] = md5_of(p)

    rep = run_selection(docs)
    out = {
        "meta": {
            "cycle": "isa-max-a task-8 (C-A.5 merge wave A selection)",
            "rule": (
                "merge = static_verdict!=null & unique & live unique_model "
                "matched & !conflict; merge.p_model_full_obs = 0x34 P-rows: "
                "static_verdict!=null & observations[] non-empty & "
                "predicted agrees with ALL fuzz5_live observations & "
                "!conflict (a raw rt_live signal below RT_FED_MIN on a "
                "merged row is adjudicated noise per-row in p34_table.json, "
                "owner ruling 2026-11-01); live silence -> "
                "excluded.single_method; merge_ready/dep_merge_unblocked_rows"
                " in sources are advisory and ignored"
            ),
            "ruling_exclusions": RULING_EXCLUSIONS,
            "pins": pins,
        },
        "counts": rep["counts"],
        "audit": rep["audit"],
        "merges": rep["merges"],
        "cmp38_self": rep["cmp38_self"],
    }
    Path(args.out).write_text(
        json.dumps(out, indent=1, sort_keys=True) + "\n")

    print("=== isa-max A merge wave A selection ===")
    total = sum(rep["counts"].values())
    for cat in CATEGORIES:
        print("  %-30s %d" % (cat, rep["counts"][cat]))
    print("  %-30s %d" % ("total audited rows", total))
    for name in ("h36", "p34", "h16", "rare"):
        for m in rep["merges"][name]:
            extra = ""
            if "predicted" in m:
                extra = " predicted=%s n_obs=%d" % (
                    m["predicted"], m["n_observations"])
            print("  MERGE %s %s%s" % (
                name, json.dumps(m["key"], sort_keys=True), extra))
    if rep["cmp38_self"]:
        print("  cmp38_self: %s" % rep["cmp38_self"]["category"])
    print("written: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
