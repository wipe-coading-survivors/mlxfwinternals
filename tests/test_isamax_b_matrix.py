"""isa-max B Task 1 tests: matrix-B derivation from cycle-A artifacts
(fixtures), vector construction per model class, separator gate, battery
format/order gates, adjudicator.  Fast tests run the generator on small
deterministic fixture slices; the real-artifact run (36 axes, 49 rt-fed,
committed-file regeneration) is slow-marked."""
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
FIX = Path(__file__).resolve().parent / "fixtures" / "isamax_b"
A_DIR = REPO / "scripts" / "probes" / "cx5-isa-max"
RUNNER = REPO / "scripts" / "probes" / "cx5-fuzz4" / "run_battery.py"

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


def fixture_inputs():
    return {
        "fuzz5_live": FIX / "fuzz5_live_fixture.json",
        "select_merges_a": FIX / "select_merges_a_fixture.json",
        "p34_table": FIX / "p34_table_fixture.json",
        "rare_verdicts": FIX / "rare_verdicts_fixture.json",
    }


def real_inputs():
    return {
        "fuzz5_live": A_DIR / "fuzz5_live.json",
        "select_merges_a": A_DIR / "select_merges_a.json",
        "p34_table": A_DIR / "p34_table.json",
        "rare_verdicts": A_DIR / "rare_verdicts.json",
    }


def build_fixture_matrix():
    gmb = load("gen_matrix_b")
    return gmb.build_all(fixture_inputs())


class TestDeriveAxes36(unittest.TestCase):
    def test_multi_rows_become_axes_with_class(self):
        gmb = load("gen_matrix_b")
        inputs = gmb.load_inputs(fixture_inputs())
        axes = gmb.derive_axes_36(inputs)
        by_axis = {a["axis"]: a for a in axes}
        # 5 multi 0x36 rows + 2 conflict axes
        self.assertEqual(len(axes), 7)
        a = by_axis["0x36|MAIN|f5=00,i6=00,lo11=000"]
        self.assertEqual(a["kind"], "reg")
        self.assertEqual(
            sorted(a["models"]),
            ["H-V", "H-eq16", "H-eq32", "H-uge32", "H-ugt32"])
        self.assertEqual(a["row_id"], "op36_f5=00_i6=00")
        # imm6 split by selector i6
        imm = [a for a in axes if a["kind"] == "imm6"]
        self.assertEqual(len(imm), 2)
        self.assertEqual(
            sorted(imm[0]["models"]) if imm[0]["selector"]["i6"] == 0x3f
            else sorted(imm[1]["models"]),
            ["H-V", "H-eq32i", "H-uge32i"])
        # live_verdict != multi rows are excluded (fixture f5=04 unique)
        self.assertNotIn("0x36|MAIN|f5=04,i6=00,lo11=004", by_axis)
        # reg/imm split consistent: reg rows have i6 == 0
        for a in axes:
            if a["kind"] in ("reg", "conflict"):
                self.assertEqual(a["selector"]["i6"], 0)

    def test_conflict_axes_appended_with_eq_family_class(self):
        gmb = load("gen_matrix_b")
        inputs = gmb.load_inputs(fixture_inputs())
        axes = gmb.derive_axes_36(inputs)
        conf = [a for a in axes if a["kind"] == "conflict"]
        self.assertEqual(len(conf), 2)
        got = {a["axis"]: sorted(a["models"]) for a in conf}
        self.assertEqual(got["0x36|MAIN|f5=02,i6=00,lo11=002"],
                         ["H-V", "H-eq16", "H-eq32"])
        self.assertEqual(got["0x36|MAIN|f5=0a,i6=00,lo11=00a"],
                         ["H-V", "H-eq16", "H-eq32"])
        # decoy non-conflict audit entry must not become an axis
        self.assertNotIn("0x36|MAIN|f5=07,i6=00,lo11=007",
                         {a["axis"] for a in axes})


class TestDeriveRtFed(unittest.TestCase):
    def test_rt_fed_rows_selected_by_static_verdict(self):
        gmb = load("gen_matrix_b")
        inputs = gmb.load_inputs(fixture_inputs())
        rows = gmb.derive_rt_fed(inputs)
        self.assertEqual(len(rows), 3)
        keys = [r["axis"] for r in rows]
        self.assertIn("0x34|MAIN|f5=0c,flag=0,idx=00,lo11=00c", keys)
        self.assertIn("0x34|IRON_PREP|f5=10,flag=0,idx=00,lo11=010", keys)
        # field-consistent row excluded
        self.assertNotIn("0x34|MAIN|f5=04,flag=0,idx=00,lo11=004", keys)
        for r in rows:
            self.assertIn("mask", r["predicted"])
            self.assertIn("deposit", r["predicted"])

    def test_p_formula_selfcheck_recomputes_predicted(self):
        gmb = load("gen_matrix_b")
        inputs = gmb.load_inputs(fixture_inputs())
        for r in gmb.derive_rt_fed(inputs):
            m, d = gmb.p_formula_recompute(r["key"]["selector"])
            self.assertEqual("0x%08x" % m, r["predicted"]["mask"])
            self.assertEqual("0x%08x" % d, r["predicted"]["deposit"])


class TestDeriveInv33(unittest.TestCase):
    def test_idx_outside_covered_point(self):
        gmb = load("gen_matrix_b")
        inputs = gmb.load_inputs(fixture_inputs())
        sel = gmb.derive_inv33(inputs)
        self.assertEqual(sel["f5"], 15)
        self.assertNotIn(sel["idx"], sel["covered_idx"])
        self.assertEqual(sel["covered_idx"], [0])


class TestDeriveC3csep(unittest.TestCase):
    def test_premise_gate_requires_live_multi_000(self):
        gmb = load("gen_matrix_b")
        inputs = gmb.load_inputs(fixture_inputs())
        self.assertTrue(gmb.derive_c3csep_premise(inputs))
        broken = json.loads(json.dumps(inputs["raw"]["rare_verdicts"]))
        for r in broken["phases"]["B"]["rows"]:
            if r["key"]["op"] == "0x3c":
                r["live_join"]["live_verdict"] = "unobserved"
        inputs2 = gmb.load_inputs(fixture_inputs())
        inputs2["raw"]["rare_verdicts"] = broken
        with self.assertRaises(Exception):
            gmb.derive_c3csep_premise(inputs2)


class TestMatrixStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = build_fixture_matrix()

    def test_marker_first_with_battery_meta_pins(self):
        recs = self.records
        self.assertEqual(recs[0]["id"], "V-F4-MARKER")
        self.assertEqual(recs[0]["group"], "marker")
        meta = recs[0]["battery_meta"]
        self.assertEqual(meta["cycle"], "isa-max-b task-1 (C-B.1)")
        self.assertEqual(sorted(meta["pins"]),
                         ["fuzz5_live.json", "p34_table.json",
                          "rare_verdicts.json", "select_merges_a.json"])
        for name, md5 in meta["pins"].items():
            self.assertRegex(md5, r"^[0-9a-f]{32}$")
        self.assertIn("rt_fed_rule", meta)
        self.assertIn("inv38v_schedule", meta)

    def test_group_priority_contiguous_blocks(self):
        gmb = load("gen_matrix_b")
        recs = [r for r in self.records if r["group"] != "marker"]
        main_groups = [r["group"] for r in recs if r["group"] != "inv38v"]
        want = ["map36", "inv33", "c3csep", "cmpself", "rtfed34"]
        # contiguous blocks in priority order (inv38v distributed by design)
        blocks = [g for i, g in enumerate(main_groups) if i == 0 or main_groups[i - 1] != g]
        self.assertEqual(blocks, want)
        self.assertEqual(gmb.GROUP_ORDER,
                         ["map36", "inv33", "inv38v", "c3csep", "cmpself",
                          "rtfed34"])

    def test_inv38v_repeats_distributed_with_positions(self):
        recs = self.records
        reps = [r for r in recs if r["group"] == "inv38v"]
        self.assertGreaterEqual(len(reps), 10)
        words = {tuple(r["words"]) for r in reps}
        self.assertEqual(len(words), 1, "all repeats must be one vector")
        self.assertEqual(reps[0]["axis"], "0x38|MAIN|sel=04")
        # distributed: not one contiguous run
        groups = [r["group"] for r in recs]
        first = groups.index("inv38v")
        last = len(groups) - 1 - groups[::-1].index("inv38v")
        self.assertGreater(last - first + 1, len(reps))
        for r in reps:
            self.assertIn("insert", r["notes"])
            self.assertIn("repeat", r["notes"])

    def test_inv38v_placed_count_tied_to_total(self):
        gmb = load("gen_matrix_b")
        recs = self.records
        reps = [r for r in recs if r["group"] == "inv38v"]
        meta = recs[0]["battery_meta"]
        # placed repeats == INV38V_TOTAL == schedule length, and the
        # "repeat N/<total>" notes cover N = 1..INV38V_TOTAL exactly once
        # (the fixture path truncates silently without the placement
        # assert — fix round 1)
        self.assertEqual(len(reps), gmb.INV38V_TOTAL)
        self.assertEqual(len(meta["inv38v_schedule"]), gmb.INV38V_TOTAL)
        import re
        nums = []
        for r in reps:
            m = re.search(r'repeat (\d+)/(\d+)', r['notes'])
            self.assertIsNotNone(m, r['notes'])
            self.assertEqual(int(m.group(2)), gmb.INV38V_TOTAL)
            nums.append(int(m.group(1)))
        self.assertEqual(sorted(nums), list(range(1, gmb.INV38V_TOTAL + 1)))

    def test_assemble_order_places_all_repeats_small_rtfed(self):
        gmb = load("gen_matrix_b")
        inv = [{'id': 'R%02d' % n, 'group': 'inv38v', 'notes': 'x'}
               for n in range(1, gmb.INV38V_TOTAL + 1)]
        rtfed = [{'id': 'V%d' % i, 'group': 'rtfed34', 'notes': 'x'}
                 for i in range(6)]
        blocks = {g: [{'id': g, 'group': g, 'notes': 'x'}]
                  for g in ('map36', 'inv33', 'c3csep', 'cmpself')}
        order, schedule = gmb.assemble_order(blocks, inv, rtfed)
        placed = [r for r in order if r['group'] == 'inv38v']
        self.assertEqual(len(placed), gmb.INV38V_TOTAL)
        self.assertEqual(len(placed), len(inv))
        self.assertEqual(len(schedule), gmb.INV38V_TOTAL)
        self.assertEqual(sorted(e['repeat'] for e in schedule),
                         list(range(1, gmb.INV38V_TOTAL + 1)))
        self.assertEqual(len(order), 4 + len(rtfed) + len(placed))

    def test_every_record_format(self):
        for r in self.records:
            self.assertIn(r["group"], {"marker", "map36", "inv33", "inv38v",
                                       "c3csep", "cmpself", "rtfed34"})
            self.assertTrue(r["id"].startswith("V-B") or r["id"] == "V-F4-MARKER")
            if r["id"] == "V-F4-MARKER":
                continue
            self.assertEqual(len(r["words"]), 10)
            for w in r["words"]:
                self.assertRegex(w, r"^[0-9a-f]{8}$")
            self.assertIn("axis", r)
            self.assertIn("expectations", r)
            self.assertTrue(r["notes"])
        ids = [r["id"] for r in self.records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate ids")

    def test_map36_volumes(self):
        map36 = [r for r in self.records if r["group"] == "map36"]
        axes = {r["axis"] for r in map36}
        self.assertEqual(len(axes), 7)  # fixture: 5 multi + 2 conflict
        # class recipe vector counts
        per_axis = {}
        for r in map36:
            per_axis[r["axis"]] = per_axis.get(r["axis"], 0) + 1
        self.assertEqual(per_axis["0x36|MAIN|f5=00,i6=00,lo11=000"], 3)  # 5-model class
        self.assertEqual(per_axis["0x36|MAIN|f5=01,i6=00,lo11=001"], 3)  # f5=1 class
        self.assertEqual(per_axis["0x36|MAIN|f5=01,i6=3f,lo11=7e1"], 2)  # imm {eq32i,uge32i,V}
        self.assertEqual(per_axis["0x36|MAIN|f5=02,i6=20,lo11=402"], 1)  # imm {lt32i,ne32i}
        self.assertEqual(per_axis["0x36|MAIN|f5=02,i6=00,lo11=002"], 2)  # conflict class

    def test_rt_fed_vectors_two_per_axis_fixed_rs(self):
        rtf = [r for r in self.records if r["group"] == "rtfed34"]
        per_axis = {}
        for r in rtf:
            per_axis.setdefault(r["axis"], []).append(r)
        self.assertEqual(len(per_axis), 3)
        for axis, vecs in per_axis.items():
            self.assertEqual(len(vecs), 2)
            tags = sorted(v["id"].rsplit("-", 1)[-1] for v in vecs)
            self.assertEqual(tags, ["x", "y"])
            by_model = {}
            for v in vecs:
                for m, exp in v["expectations"].items():
                    by_model.setdefault(m, {})[v["id"]] = exp["0x8c8"]
            # P-formula expectation identical on both (rt-invariant)
            self.assertEqual(
                by_model["H-34-p-formula"][vecs[0]["id"]],
                by_model["H-34-p-formula"][vecs[1]["id"]])
            # rt-fed alternative moves with rt (X != Y)
            self.assertNotEqual(
                by_model["H-34-rt-fed"][vecs[0]["id"]],
                by_model["H-34-rt-fed"][vecs[1]["id"]])
            # separation on the X vector: P != rt-fed
            x = [v for v in vecs if v["id"].endswith("-x")][0]
            self.assertNotEqual(
                x["expectations"]["H-34-p-formula"]["0x8c8"],
                x["expectations"]["H-34-rt-fed"]["0x8c8"])

    def test_c3csep_design(self):
        c3 = {r["id"]: r for r in self.records if r["group"] == "c3csep"}
        self.assertEqual(len(c3), 3)
        v000 = c3["V-B3C-i000"]
        self.assertEqual(v000["axis"], "0x3c|MAIN|lo11=000")
        exps = {m: e["0x8c8"] for m, e in v000["expectations"].items()}
        self.assertEqual(exps["H-3c-zero"], exps["H-3c-and-lo11"])
        for vid, want_and in (("V-B3C-i001", "0x00000001"),
                              ("V-B3C-i400", "0x00000400")):
            v = c3[vid]
            self.assertEqual(
                v["expectations"]["H-3c-zero"]["0x8c8"], "0x00000000")
            self.assertEqual(
                v["expectations"]["H-3c-and-lo11"]["0x8c8"], want_and)

    def test_cmpself_two_vectors_from_canon(self):
        cs = [r for r in self.records if r["group"] == "cmpself"]
        self.assertEqual(len(cs), 2)
        for v in cs:
            self.assertEqual(v["axis"], "0x38|MAIN|sel=00")
            self.assertEqual(
                sorted(v["expectations"]), ["H-38self-false", "H-38self-keepT"])

    def test_inv33_vector(self):
        v = [r for r in self.records if r["group"] == "inv33"]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["axis"], "0x33|MAIN|f5=0f,flag=0,idx=0a,lo11=14f")
        exps = v[0]["expectations"]
        self.assertEqual(sorted(exps), ["H-depM", "H-depR"])
        self.assertNotEqual(exps["H-depR"]["0x8c8"], exps["H-depM"]["0x8c8"])


class TestSeparatorGate(unittest.TestCase):
    def test_synthetic_inseparable_pair_flagged_and_allowed(self):
        gmb = load("gen_matrix_b")
        vecs = [{
            "id": "V-X", "group": "g", "axis": "0xZZ|MAIN|k=00",
            "expectations": {"H-a": {"0x8c8": "0x00000000"},
                             "H-b": {"0x8c8": "0x00000000"}}}]
        # unlisted inseparable pair -> gate fails
        with self.assertRaises(gmb.SepError):
            gmb.separator_gate(vecs, whitelist={})
        # whitelisted -> recorded as inseparable_by_design with reason
        wl = {"0xZZ|MAIN|k=00": "by-design: both models predict rd=0 here"}
        report = gmb.separator_gate(vecs, whitelist=wl)
        entry = report["0xZZ|MAIN|k=00"]
        self.assertEqual(entry["inseparable"],
                         [{"pair": ["H-a", "H-b"],
                           "status": "inseparable_by_design",
                           "reason": "by-design: both models predict rd=0 here"}])
        self.assertEqual(entry["pairs_total"], 1)
        self.assertEqual(entry["pairs_separated"], 0)

    def test_synthetic_separated_pair(self):
        gmb = load("gen_matrix_b")
        vecs = [{
            "id": "V-X", "group": "g", "axis": "0xZZ|MAIN|k=00",
            "expectations": {"H-a": {"0x8c8": "0x00000001"},
                             "H-b": {"0x8c8": "0x00000002"}}}]
        report = gmb.separator_gate(vecs, whitelist={})
        entry = report["0xZZ|MAIN|k=00"]
        self.assertEqual(entry["pairs_total"], 1)
        self.assertEqual(entry["pairs_separated"], 1)
        self.assertEqual(entry["inseparable"], [])

    def test_matrix_gate_only_c3csep_000_inseparable(self):
        gmb = load("gen_matrix_b")
        records = build_fixture_matrix()
        report = gmb.separator_gate(records, whitelist=gmb.SEP_WHITELIST)
        bad = {a: e for a, e in report.items() if e["inseparable"]}
        self.assertEqual(list(bad), ["0x3c|MAIN|lo11=000"])
        # every other axis: all pairs separated
        for axis, entry in report.items():
            if axis == "0x3c|MAIN|lo11=000":
                continue
            self.assertEqual(entry["pairs_separated"], entry["pairs_total"])


class TestAdjudicator(unittest.TestCase):
    def test_synthetic_alive_dead_separated(self):
        adj = load("adjudicate_b")
        vectors = [
            {"id": "V1", "group": "g", "axis": "0xZZ|MAIN|k=00",
             "expectations": {"H-a": {"0x8c8": "0x00000001"},
                              "H-b": {"0x8c8": "0x00000002"}}},
            {"id": "V2", "group": "g", "axis": "0xZZ|MAIN|k=00",
             "expectations": {"H-a": {"0x8c8": "0x00000003"},
                              "H-b": {"0x8c8": "0x00000003"}}}]
        res = adj.adjudicate(vectors, {"V1": "0x1", "V2": "0x3"})
        e = res["axes"]["0xZZ|MAIN|k=00"]
        self.assertEqual(e["alive_models"], ["H-a"])
        self.assertEqual(e["dead_models"], ["H-b"])
        self.assertTrue(e["separated"])
        self.assertEqual(e["tried"], 2)

    def test_synthetic_untested_model_in_neither_list(self):
        adj = load("adjudicate_b")
        vectors = [
            {"id": "V1", "group": "g", "axis": "0xZZ|MAIN|k=00",
             "expectations": {"H-a": {"0x8c8": "0x00000001"},
                              "H-c": {"0x8c8": "0x00000009"}}}]
        res = adj.adjudicate(vectors, {})
        e = res["axes"]["0xZZ|MAIN|k=00"]
        self.assertEqual(e["alive_models"], [])
        self.assertEqual(e["dead_models"], [])
        self.assertFalse(e["separated"])
        self.assertEqual(e["tried"], 0)

    def test_synthetic_all_dead_not_separated_unique(self):
        adj = load("adjudicate_b")
        vectors = [
            {"id": "V1", "group": "g", "axis": "0xZZ|MAIN|k=00",
             "expectations": {"H-a": {"0x8c8": "0x00000001"},
                              "H-b": {"0x8c8": "0x00000002"}}}]
        res = adj.adjudicate(vectors, {"V1": "0xdeadbeef"})
        e = res["axes"]["0xZZ|MAIN|k=00"]
        self.assertEqual(sorted(e["dead_models"]), ["H-a", "H-b"])
        self.assertTrue(e["separated"])

    def test_stock_marker_and_low32(self):
        adj = load("adjudicate_b")
        vectors = [
            {"id": "V1", "group": "g", "axis": "0xZZ|MAIN|k=00",
             "expectations": {"H-a": {"echo": "stock"},
                              "H-b": {"echo": "0x0000000000001234"}}}]
        res = adj.adjudicate(vectors, {"V1": "stock"})
        e = res["axes"]["0xZZ|MAIN|k=00"]
        self.assertEqual(e["alive_models"], ["H-a"])
        self.assertEqual(e["dead_models"], ["H-b"])
        # 16-digit observed value compares on low32
        res2 = adj.adjudicate(vectors, {"V1": "0x0000000000001234"})
        e2 = res2["axes"]["0xZZ|MAIN|k=00"]
        self.assertEqual(e2["alive_models"], ["H-b"])

    def test_fixture_matrix_adjudication(self):
        adj = load("adjudicate_b")
        records = build_fixture_matrix()
        observed = {}
        # simulate a live session where the eq32 model wins on f5=00
        for r in records:
            if r.get("axis") == "0x36|MAIN|f5=00,i6=00,lo11=000":
                exp = r["expectations"]["H-eq32"]
                observed[r["id"]] = (exp.get("0x8c8") or exp["echo"])
        res = adj.adjudicate(records, observed)
        e = res["axes"]["0x36|MAIN|f5=00,i6=00,lo11=000"]
        self.assertEqual(e["alive_models"], ["H-eq32"])
        self.assertEqual(sorted(e["dead_models"]),
                         ["H-V", "H-eq16", "H-uge32", "H-ugt32"])
        self.assertTrue(e["separated"])
        self.assertEqual(e["tried"], 3)


class TestDeterminismAndRunner(unittest.TestCase):
    def test_build_deterministic_same_bytes(self):
        gmb = load("gen_matrix_b")
        a = gmb.build_all(fixture_inputs())
        b = gmb.build_all(fixture_inputs())
        ta = json.dumps(a, indent=1, sort_keys=True)
        tb = json.dumps(b, indent=1, sort_keys=True)
        self.assertEqual(hashlib.md5(ta.encode()).hexdigest(),
                         hashlib.md5(tb.encode()).hexdigest())

    def test_runner_dry_run_consumes_file(self):
        gmb = load("gen_matrix_b")
        records = gmb.build_all(fixture_inputs())
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "matrix_b_vectors.json"
            p.write_text(json.dumps(records, indent=1) + "\n")
            r = subprocess.run(
                [sys.executable, str(RUNNER), "dry-run", "--vectors", str(p)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("fuzzvec", r.stdout)


@pytest_mark_slow
class TestRealArtifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gmb = load("gen_matrix_b")
        cls.records = cls.gmb.build_all(real_inputs())

    def test_real_derivation_counts(self):
        inputs = self.gmb.load_inputs(real_inputs())
        axes = self.gmb.derive_axes_36(inputs)
        multi = [a for a in axes if a["kind"] != "conflict"]
        reg = [a for a in multi if a["kind"] == "reg"]
        imm = [a for a in multi if a["kind"] == "imm6"]
        self.assertEqual(len(multi), 34)
        self.assertEqual((len(reg), len(imm)), (24, 10))
        self.assertEqual(len([a for a in axes if a["kind"] == "conflict"]), 2)
        self.assertEqual(len(self.gmb.derive_rt_fed(inputs)), 49)

    def test_real_group_counts_and_marker(self):
        recs = self.records
        self.assertEqual(recs[0]["id"], "V-F4-MARKER")
        counts = {}
        for r in recs:
            counts[r["group"]] = counts.get(r["group"], 0) + 1
        self.assertEqual(counts["map36"], 90)
        self.assertEqual(counts["inv33"], 1)
        self.assertEqual(counts["inv38v"], 12)
        self.assertEqual(counts["c3csep"], 3)
        self.assertEqual(counts["cmpself"], 2)
        self.assertEqual(counts["rtfed34"], 98)
        meta = recs[0]["battery_meta"]
        self.assertEqual(meta["group_counts"], counts)

    def test_committed_file_regenerates(self):
        gmb = self.gmb
        committed = (DIR / "matrix_b_vectors.json").read_text()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "m.json"
            gmb.main(["--out", str(out)] + sum(
                [["--" + k, str(v)] for k, v in real_inputs().items()], []))
            self.assertEqual(out.read_text(), committed)

    def test_pins_match_current_artifacts(self):
        meta = self.records[0]["battery_meta"]
        for name, md5 in meta["pins"].items():
            data = (A_DIR / name).read_bytes()
            self.assertEqual(hashlib.md5(data).hexdigest(), md5)


if __name__ == "__main__":
    unittest.main()
