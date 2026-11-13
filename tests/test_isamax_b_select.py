"""isa-max B Task 3 tests: programmatic merge selection over the B battery
adjudication (fixtures for every category), the hardened adjudicator value
normalization, the inv38v sel=4 correlation statistics, the c3c/000
literal-uniformity transfer, cmp38-self handling, and the separator-design
cross-check.  Real-artifact runs (91 axes, committed-file regeneration) are
slow-marked."""
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

pytest_mark_slow = pytest.mark.slow

REPO = Path(__file__).resolve().parent.parent
DIR = REPO / "scripts" / "probes" / "cx5-isa-max-b"
A_DIR = REPO / "scripts" / "probes" / "cx5-isa-max"

_CACHE = {}


def load(name, path=None):
    if name in _CACHE:
        return _CACHE[name]
    p = path or (DIR / (name + ".py"))
    spec = importlib.util.spec_from_file_location(name, p)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(str(p))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    _CACHE[name] = m
    return m


# ---------------------------------------------------------------- fixtures --

def vec(vid, axis, expectations, group="map36", **kw):
    v = {"id": vid, "group": group, "axis": axis,
         "expectations": expectations}
    v.update(kw)
    return v


def exp32(v):
    return {"0x8c8": "0x%08x" % (v & 0xffffffff)}


MAP36_AXIS = "0x36|MAIN|f5=03,i6=00,lo11=003"
MAP36_MODELS = ["H-V", "H-eq16", "H-eq32", "H-uge32", "H-ugt32"]


def map36_records(axis=MAP36_AXIS):
    return [
        vec("V-a", axis, {"H-V": exp32(0), "H-eq16": exp32(1),
                          "H-eq32": exp32(0), "H-uge32": exp32(1),
                          "H-ugt32": exp32(1)}),
        vec("V-b", axis, {"H-V": exp32(0), "H-eq16": exp32(0),
                          "H-eq32": exp32(3), "H-uge32": exp32(3),
                          "H-ugt32": exp32(4)}),
    ]


def h36_doc(selector_verdicts):
    rows = []
    for sel, verdict in selector_verdicts:
        rows.append({
            "key": {"op": "0x36", "section": "MAIN", "selector": sel},
            "static_verdict": verdict,
            "unique": verdict is not None,
            "conflict": False,
            "live_join": {"status": "silence"},
        })
    return {"phases": {"B": {"rows": rows}}}


def sel_36(f5=3, i6=0, lo11=3):
    return {"f5": f5, "i6": i6, "lo11": lo11}


RTFED_AXIS = "0x34|MAIN|f5=04,flag=0,idx=00,lo11=004"


def rtfed_docs(f5=4, idx=0, flag=0, rt_x=0xffffffff, rt_y=0,
               p_deposit=0xc, p_mask=None, rt_expect=None, lo11=None):
    lo11 = lo11 if lo11 is not None else (flag << 10) | (idx << 5) | f5
    wmask = 0xffffffff if f5 == 0 else (1 << f5) - 1
    mask = p_mask if p_mask is not None else (wmask << idx) & 0xffffffff
    rs = 0x1234
    rd_p = ((rs & ~mask) | p_deposit) & 0xffffffff
    rd_rt_x = ((rs & ~mask) | ((rt_x & wmask) << idx)) & 0xffffffff
    rd_rt_y = ((rs & ~mask) | ((rt_y & wmask) << idx)) & 0xffffffff
    axis = "0x34|MAIN|f5=%02x,flag=%d,idx=%02x,lo11=%03x" % (
        f5, flag, idx, lo11)
    records = [
        vec("V-x", axis,
            {"H-34-p-formula": exp32(rd_p), "H-34-rt-fed": exp32(rd_rt_x)},
            group="rtfed34"),
        vec("V-y", axis,
            {"H-34-p-formula": exp32(rd_p), "H-34-rt-fed": exp32(rd_rt_y)},
            group="rtfed34"),
    ]
    p34 = {"phases": {"B": {"rows": [{
        "key": {"op": "0x34", "section": "MAIN",
                "selector": {"f5": f5, "flag": flag, "idx": idx,
                             "lo11": lo11}},
        "static_verdict": "H-34-rt-fed", "unique": True, "conflict": False,
        "predicted": {"mask": "0x%08x" % mask,
                      "deposit": "0x%08x" % p_deposit},
    }]}}}
    return records, p34

C3C_AXES = {
    0x000: "0x3c|MAIN|lo11=000",
    0x001: "0x3c|MAIN|lo11=001",
    0x400: "0x3c|MAIN|lo11=400",
}


def c3c_records():
    out = []
    for lo11, axis in C3C_AXES.items():
        zero = {"0x8c8": "0x00000000"}
        andv = {"0x8c8": "0x%08x" % (0xffffffff & lo11)}
        out.append(vec("V-c%03x" % lo11, axis,
                       {"H-3c-zero": zero, "H-3c-and-lo11": andv},
                       group="c3csep"))
    return out


def rare_doc(literals):
    rows = []
    for lo11 in literals:
        rows.append({
            "key": {"op": "0x3c", "section": "MAIN",
                    "selector": {"lo11": lo11}},
            "static_verdict": "H-3c-zero-consistent", "unique": True,
            "conflict": False, "live_join": {"status": "silence"},
        })
    return {"phases": {"B": {
        "rows": rows,
        "cmp38_self": {
            "aggregate": {"formalizable": False, "strict_sites": 2,
                          "strict_insensitive": 0},
            "live_join": {"double_live": True, "supports": []},
        }}}}


def fuzz5_doc():
    return {"rows": {}, "cmp38_self": {"unique_model": "H-38self-false"}}


# ------------------------------------------------------- adjudicator norm --

class TestAdjudicatorHardening(unittest.TestCase):
    def test_norm_accepts_stock_and_hex(self):
        adj = load("adjudicate_b")
        self.assertEqual(adj._norm("stock"), "stock")
        self.assertEqual(adj._norm("  STOCK "), "stock")
        self.assertEqual(adj._norm("0x1234"), 0x1234)
        self.assertEqual(adj._norm("0x0000000000001234"), 0x1234)
        self.assertEqual(adj._norm("0xdeadbeef"), 0xdeadbeef)

    def test_norm_strict_raises_on_unparseable(self):
        adj = load("adjudicate_b")
        for bad in ("zzz", "1234", "", "0x", "0x1g", "-0x5", None):
            with self.assertRaises(ValueError):
                adj._norm(bad)

    def test_adjudicate_raises_on_unparseable_observed(self):
        adj = load("adjudicate_b")
        vectors = [vec("V1", "0xZZ|MAIN|k=00",
                       {"H-a": exp32(1)})]
        with self.assertRaises(ValueError):
            adj.adjudicate(vectors, {"V1": "garbage"})


# ------------------------------------------------------------- map36 ------

class TestSelectMap36(unittest.TestCase):
    def run_axis(self, observed, static_verdicts):
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        records = map36_records()
        res = adj.adjudicate(records, observed)
        row = smb.select_map36_axis(
            MAP36_AXIS, records, res["axes"][MAP36_AXIS],
            smb.h36_static_lookup(h36_doc(static_verdicts),
                                  {"op": "0x36", "section": "MAIN",
                                   "selector": sel_36()}))
        return row

    def test_merge_eq_family_survivor(self):
        # eq32 survives both vectors (observed == eq32 expectations)
        observed = {"V-a": "0x0", "V-b": "0x3"}
        row = self.run_axis(observed, [(sel_36(), "H-36-eq-usage")])
        self.assertEqual(row["category"], "merge")
        self.assertIn("family-grade", row["reason"])
        self.assertEqual(row["alive_models"], ["H-eq32"])

    def test_conflict_non_eq_survivor(self):
        observed = {"V-a": "0x1", "V-b": "0x3"}  # uge32 alone survives
        row = self.run_axis(observed, [(sel_36(), "H-36-eq-usage")])
        self.assertEqual(row["category"], "excluded.conflict")
        self.assertEqual(row["alive_models"], ["H-uge32"])

    def test_parked_live_only_without_static_leg(self):
        observed = {"V-a": "0x0", "V-b": "0x3"}
        row = self.run_axis(observed, {})
        self.assertEqual(row["category"], "residual.parked")
        self.assertIn("live-only", row["reason"])

    def test_single_method_unobserved(self):
        row = self.run_axis({}, {})
        self.assertEqual(row["category"], "excluded.single_method")

    def test_parked_unseparated_with_observations(self):
        # H-V alive on V-a only, H-eq32 alive on V-b only -> unseparated
        observed = {"V-a": "0x0"}
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        records = map36_records()
        res = adj.adjudicate(records, observed)
        info = res["axes"][MAP36_AXIS]
        info = dict(info, separated=False,
                    alive_models=["H-V", "H-eq32"],
                    dead_models=["H-eq16", "H-uge32", "H-ugt32"])
        row = smb.select_map36_axis(
            MAP36_AXIS, records, info,
            smb.h36_static_lookup(h36_doc({}),
                                  {"op": "0x36", "section": "MAIN",
                                   "selector": sel_36()}),
            observed)
        self.assertEqual(row["category"], "residual.parked")
        self.assertEqual(row["tried"], 1)

    def test_untestable_channel_killer(self):
        # every observation 'stock' while no model expects 'stock':
        # the probe channel never moved -> untestable by design
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        records = map36_records()
        observed = {"V-a": "stock", "V-b": "stock"}
        res = adj.adjudicate(records, observed)
        info = res["axes"][MAP36_AXIS]
        row = smb.select_map36_axis(
            MAP36_AXIS, records, info,
            smb.h36_static_lookup(h36_doc({}),
                                  {"op": "0x36", "section": "MAIN",
                                   "selector": sel_36()}),
            observed)
        self.assertEqual(row["category"], "residual.untestable")
        self.assertEqual(row["dead_models"],
                         sorted(["H-V", "H-eq16", "H-eq32",
                                 "H-uge32", "H-ugt32"]))


# ------------------------------------------------------------- rtfed34 ----

class TestSelectRtfed34(unittest.TestCase):
    def run_axis(self, observed, **kw):
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        records, p34 = rtfed_docs(**kw)
        axis = records[0]["axis"]
        res = adj.adjudicate(records, observed)
        return smb.select_rtfed_axis(
            axis, records, res["axes"][axis], p34,
            observed), res["axes"][axis]

    def test_rt_invariant_merge_all_obs_agree(self):
        records, p34 = rtfed_docs()
        observed = {"V-x": records[0]["expectations"]["H-34-p-formula"]
                    ["0x8c8"],
                    "V-y": records[1]["expectations"]["H-34-p-formula"]
                    ["0x8c8"]}
        row, info = self.run_axis(observed)
        self.assertEqual(row["category"], "merge.rt_invariant")
        self.assertEqual((row["n_observations"], row["n_agree"]), (2, 2))
        self.assertTrue(row["pair_discriminating"])

    def test_rt_invariant_contradiction_is_conflict(self):
        records, p34 = rtfed_docs()
        observed = {"V-x": records[0]["expectations"]["H-34-p-formula"]
                    ["0x8c8"],
                    "V-y": "0x%08x"
                    % (int(records[1]["expectations"]["H-34-rt-fed"]
                           ["0x8c8"], 16))}
        row, info = self.run_axis(observed)
        self.assertEqual(row["category"], "excluded.conflict")
        self.assertEqual(row["n_agree"], 1)

    def test_single_method_without_observations(self):
        row, info = self.run_axis({})
        self.assertEqual(row["category"], "excluded.single_method")

    def test_ruling_axis_excluded_programmatically(self):
        records, p34 = rtfed_docs(f5=2, idx=5, flag=0, lo11=0x0a2)
        observed = {"V-x": records[0]["expectations"]["H-34-p-formula"]
                    ["0x8c8"],
                    "V-y": records[1]["expectations"]["H-34-p-formula"]
                    ["0x8c8"]}
        row, info = self.run_axis(observed, f5=2, idx=5, flag=0, lo11=0x0a2)
        self.assertEqual(row["category"], "excluded.ruling")
        self.assertIn("OPEN-34-f5=2-idx=5", row["reason"])

    def test_parked_nondiscriminating_pair(self):
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        records, p34 = rtfed_docs(f5=1, flag=0, p_deposit=0)
        axis = records[0]["axis"]
        # both vectors observe the shared prediction; rt-fed alternative
        # coincides on y (deposit 0) and is killed only on x -- make a
        # degenerate design where BOTH expectations coincide by forcing
        # deposit equal to the rt-fed value on both legs
        records[0]["expectations"]["H-34-rt-fed"] = dict(
            records[0]["expectations"]["H-34-p-formula"])
        records[1]["expectations"]["H-34-rt-fed"] = dict(
            records[1]["expectations"]["H-34-p-formula"])
        observed = {
            r["id"]: r["expectations"]["H-34-p-formula"]["0x8c8"]
            for r in records}
        res = adj.adjudicate(records, observed)
        row = smb.select_rtfed_axis(axis, records, res["axes"][axis], p34,
                                    observed)
        self.assertEqual(row["category"], "residual.parked")
        self.assertFalse(row["pair_discriminating"])


# --------------------------------------------------------------- c3c ------

class TestSelectC3c(unittest.TestCase):
    def run_section(self, observed_overrides=None):
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        records = c3c_records()
        observed = {"V-c000": "0x0", "V-c001": "0x0", "V-c400": "0x0"}
        observed.update(observed_overrides or {})
        res = adj.adjudicate(records, observed)
        return smb.select_c3c_section(records, res["axes"], observed,
                                      rare_doc([0x000, 0x400]))

    def test_per_literal_merge_direct_and_transfer(self):
        out = self.run_section()
        by_lit = {r["literal"]: r for r in out["literals"]}
        self.assertEqual(by_lit[0x400]["category"], "merge")
        self.assertEqual(by_lit[0x400]["basis"], "direct")
        self.assertEqual(by_lit[0x000]["category"], "merge")
        self.assertEqual(by_lit[0x000]["basis"], "transfer")
        uni = by_lit[0x000]["literal_uniformity"]
        self.assertFalse(uni["violation"])
        self.assertEqual(uni["intermediate_points"], [1, 0x400])
        self.assertEqual(by_lit[0x001]["category"], "residual.parked")

    def test_transfer_violation_is_residual(self):
        out = self.run_section({"V-c000": "0x5"})
        by_lit = {r["literal"]: r for r in out["literals"]}
        self.assertEqual(by_lit[0x000]["category"], "residual.parked")
        self.assertTrue(by_lit[0x000]["literal_uniformity"]["violation"])

    def test_intermediate_disagreement_is_residual(self):
        # and-lo11 wins at 0x400 (observed its prediction) -> the
        # intermediate winners disagree -> no transfer
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        records = c3c_records()
        observed = {"V-c000": "0x0", "V-c001": "0x0",
                    "V-c400": records[2]["expectations"]
                    ["H-3c-and-lo11"]["0x8c8"]}
        res = adj.adjudicate(records, observed)
        out = smb.select_c3c_section(records, res["axes"], observed,
                                     rare_doc([0x000, 0x400]))
        by_lit = {r["literal"]: r for r in out["literals"]}
        self.assertEqual(by_lit[0x000]["category"], "residual.parked")


# ------------------------------------------------------- inv33 / cmpself --

class TestInv33AndCmpSelf(unittest.TestCase):
    def test_inv33_corroborated_probe_is_live_only_parked(self):
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        axis = "0x33|MAIN|f5=0f,flag=0,idx=0a,lo11=14f"
        records = [vec("V-33", axis,
                       {"H-depR": exp32(0x1400),
                        "H-depM": exp32(0x1410)}, group="inv33")]
        res = adj.adjudicate(records, {"V-33": "0x1400"})
        row = smb.select_inv33_axis(axis, records, res["axes"][axis])
        self.assertEqual(row["category"], "residual.parked")
        self.assertIn("corroborat", row["reason"])
        self.assertEqual(row["alive_models"], ["H-depR"])

    def test_cmp38_self_ruling_with_observation(self):
        smb = load("select_merges_b")
        adj = load("adjudicate_b")
        axis = "0x38|MAIN|sel=00"
        records = [
            vec("V-38S-REP", axis,
                {"H-38self-false": {"echo": "0x0000000000001234"},
                 "H-38self-keepT": {"echo": "stock"}}, group="cmpself"),
            vec("V-38S-VAR", axis,
                {"H-38self-false": {"echo": "0x0000000000004321"},
                 "H-38self-keepT": {"echo": "stock"}}, group="cmpself")]
        observed = {"V-38S-REP": "0x1234", "V-38S-VAR": "0x4321"}
        res = adj.adjudicate(records, observed)
        row, section = smb.select_cmp38_self(
            axis, records, res["axes"][axis], rare_doc([]), fuzz5_doc())
        self.assertEqual(row["category"], "excluded.ruling")
        self.assertIn("formalizable=FALSE", row["reason"])
        self.assertEqual(section["live_model"], "H-38self-false")
        self.assertFalse(section["formalizable"])
        self.assertEqual(len(section["observations"]), 2)


# --------------------------------------------------------------- inv38v ---

def inv38v_matrix_small():
    return [
        vec("V-A", "0x34|MAIN|f5=04,flag=0,idx=00,lo11=004",
            {"H-34-p-formula": exp32(1), "H-34-rt-fed": exp32(2)},
            group="rtfed34"),
        vec("V-B38v-R01", "0x38|MAIN|sel=04",
            {"H-38v-rs": exp32(0x01076000)}, group="inv38v"),
        vec("V-B", "0x34|MAIN|f5=05,flag=0,idx=00,lo11=005",
            {"H-34-p-formula": exp32(1), "H-34-rt-fed": exp32(2)},
            group="rtfed34"),
        vec("V-B38v-R02", "0x38|MAIN|sel=04",
            {"H-38v-rs": exp32(0x01076000)}, group="inv38v"),
    ]


def inv38v_raw_text(bytes_):
    lines = []
    ts = 0
    for rep, runs in enumerate(bytes_, start=1):
        for n, b in enumerate(runs, start=1):
            h, m, s = 11, 52 + ts // 60, ts % 60
            lines.append(
                "%02d:%02d:%02d | V-B38v-R%02d run%d: rc=0 "
                "cr0x8c8=0x010%01d6000 echo16=010%01d600000000000"
                % (h, m, s, rep, n, b, b))
            ts += 1
        ts += 2
    return "\n".join(lines) + "\n"


class TestInv38vStatistics(unittest.TestCase):
    def test_counter_converged_step_three(self):
        smb = load("select_merges_b")
        records = inv38v_matrix_small()
        runs = smb.parse_inv38v_runs(inv38v_raw_text([[7, 2, 5], [2, 5, 0]]))
        stats = smb.inv38v_statistics(records, runs)
        self.assertEqual(stats["verdict"], "converged_counter")
        self.assertEqual(stats["hypothesis"]["step"], 3)
        self.assertEqual(stats["hypothesis"]["matches"],
                         stats["hypothesis"]["total"])
        self.assertEqual(stats["within_repeat_steps"], {"3": 4})
        fit = stats["fit_report"]
        self.assertEqual(fit["counter_per_tool_op"],
                         {"best_step": 3, "best_matches": 5})
        # time: gaps 1,1,3,1,1 -- step 3 matches the 1s gaps only (4/5)
        self.assertEqual(fit["time"]["best_step"], 3)
        self.assertEqual(fit["time"]["best_matches"], 4)
        self.assertEqual(fit["time"]["naive_step1_matches"], 0)

    def test_non_convergence(self):
        smb = load("select_merges_b")
        records = inv38v_matrix_small()
        runs = smb.parse_inv38v_runs(inv38v_raw_text([[7, 2, 5], [4, 4, 4]]))
        stats = smb.inv38v_statistics(records, runs)
        self.assertEqual(stats["verdict"], "non_convergence")

    def test_parse_inv38v_runs(self):
        smb = load("select_merges_b")
        text = ("11:52:32 | V-B38v-R01 run1: rc=0 cr0x8c8=0x01076000 "
                "echo16=0107600000000000\n")
        runs = smb.parse_inv38v_runs(text)
        self.assertEqual(len(runs), 1)
        r = runs[0]
        self.assertEqual((r["repeat"], r["run"], r["byte"]), (1, 1, 7))
        self.assertEqual(r["cr"], 0x01076000)


# ------------------------------------------------------------ crosscheck --

class TestSeparatorCrosscheck(unittest.TestCase):
    def test_separated_axis_has_observed_separating_vector(self):
        smb = load("select_merges_b")
        records = map36_records()
        observed = {"V-a": "0x0", "V-b": "0x0"}
        forged = {"axis": MAP36_AXIS, "alive_models": ["H-eq32"],
                  "dead_models": ["H-V", "H-eq16", "H-uge32", "H-ugt32"],
                  "separated": True, "tried": 2}
        rep = smb.crosscheck_separation(records, observed,
                                        {MAP36_AXIS: forged}, whitelist={})
        self.assertTrue(rep[MAP36_AXIS]["ok"])
        self.assertEqual(rep[MAP36_AXIS]["missing_pairs"], [])

    def test_forged_separation_flagged(self):
        smb = load("select_merges_b")
        records = map36_records()
        observed = {"V-a": "0x0"}
        forged = {"axis": MAP36_AXIS, "alive_models": ["H-eq32"],
                  "dead_models": ["H-V", "H-eq16", "H-uge32", "H-ugt32"],
                  "separated": True, "tried": 1}
        rep = smb.crosscheck_separation(records, observed,
                                        {MAP36_AXIS: forged}, whitelist={})
        self.assertFalse(rep[MAP36_AXIS]["ok"])
        self.assertTrue(rep[MAP36_AXIS]["missing_pairs"])

    def test_whitelisted_axis_marked(self):
        smb = load("select_merges_b")
        records = c3c_records()
        observed = {"V-c000": "0x0", "V-c001": "0x0", "V-c400": "0x0"}
        forged = {"axis": C3C_AXES[0], "alive_models": ["H-3c-and-lo11",
                                                        "H-3c-zero"],
                  "dead_models": [], "separated": False, "tried": 1}
        rep = smb.crosscheck_separation(
            records, observed, {C3C_AXES[0]: forged},
            whitelist={C3C_AXES[0]: "by-design"})
        self.assertEqual(rep[C3C_AXES[0]]["status"], "whitelisted")


# ----------------------------------------------------------- real run -----

def real_paths():
    return {
        "battery": DIR / "battery_b_results.json",
        "matrix": DIR / "matrix_b_vectors.json",
        "raw_runs": DIR / "inv38v_runs_raw.log",
        "h36": A_DIR / "h36_verdicts.json",
        "p34": A_DIR / "p34_table.json",
        "rare": A_DIR / "rare_verdicts.json",
        "fuzz5": A_DIR / "fuzz5_live.json",
    }


@pytest_mark_slow
class TestRealSelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smb = load("select_merges_b")
        cls.out = cls.smb.run_real(**real_paths())

    def test_category_counters(self):
        counts = self.out["counts"]
        self.assertEqual(sum(counts.values()), 91)
        self.assertEqual(counts["merge"], 2)
        self.assertEqual(counts["merge.rt_invariant"], 49)
        self.assertEqual(counts["excluded.conflict"], 14)
        self.assertEqual(counts["excluded.single_method"], 0)
        self.assertEqual(counts["excluded.ruling"], 1)
        self.assertEqual(counts["residual.parked"], 25)
        self.assertEqual(counts["residual.untestable"], 0)

    def test_rtfed_all_agree_and_discriminate(self):
        for m in self.out["merges"]["rtfed34"]:
            self.assertEqual((m["n_observations"], m["n_agree"]), (2, 2))
            self.assertTrue(m["pair_discriminating"])

    def test_crosscheck_all_ok(self):
        rep = self.out["separator_crosscheck"]
        bad = {a: e for a, e in rep.items()
               if e.get("status") not in ("ok", "whitelisted")}
        self.assertEqual(bad, {})

    def test_inv38v_counter_converged(self):
        sec = self.out["sections"]["inv38v_sel4"]
        self.assertEqual(sec["statistics"]["verdict"], "converged_counter")
        self.assertEqual(sec["statistics"]["hypothesis"]["step"], 3)
        self.assertEqual(sec["statistics"]["hypothesis"]["matches"], 35)
        self.assertEqual(sec["statistics"]["value_counts"],
                         {"0": 3, "1": 3, "2": 7, "3": 2,
                          "4": 6, "5": 6, "6": 2, "7": 7})
        fit = sec["statistics"]["fit_report"]
        self.assertEqual(fit["counter_per_tool_op"],
                         {"best_step": 3, "best_matches": 35})
        self.assertEqual(fit["counter_per_vector_run"],
                         {"best_step": 3, "best_matches": 27})
        # time: best single-step fit 20/35 at step 3 -- aliasing the
        # 1-second within-repeat gaps; the naive +1/s step gives 2/35
        self.assertEqual(fit["time"]["best_step"], 3)
        self.assertEqual(fit["time"]["best_matches"], 20)
        self.assertEqual(fit["time"]["naive_step1_matches"], 2)

    def test_c3c_merges_and_parked_literal(self):
        lits = {r["literal"]: r for r in
                self.out["sections"]["c3c_000"]["literals"]}
        self.assertEqual(lits[0]["category"], "merge")
        self.assertEqual(lits[0x400]["category"], "merge")
        self.assertEqual(lits[1]["category"], "residual.parked")

    def test_pins_match_current_artifacts(self):
        for name, md5 in self.out["meta"]["pins"].items():
            data = (DIR / name if name in
                    ("battery_b_results.json", "matrix_b_vectors.json",
                     "inv38v_runs_raw.log")
                    else A_DIR / name).read_bytes()
            self.assertEqual(hashlib.md5(data).hexdigest(), md5)

    def test_committed_json_regenerates(self):
        committed = (DIR / "select_merges_b.json").read_text()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "select.json"
            argv = ["--out", str(out)]
            for flag, p in real_paths().items():
                argv += ["--" + flag.replace("_", "-"), str(p)]
            rc = self.smb.main(argv)
            self.assertEqual(rc, 0)
            self.assertEqual(out.read_text(), committed)


if __name__ == "__main__":
    unittest.main()
