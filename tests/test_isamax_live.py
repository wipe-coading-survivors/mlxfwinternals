"""isa-max A Task 3 live-table tests: journal-table normalization on
fixtures (mini-markdown), disc lo11 key restoration, OPDEP multi-
observation merge, manifest drift gate, and committed artifact gates."""
import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIR = REPO / "scripts" / "probes" / "cx5-isa-max"
F5 = REPO / "scripts" / "probes" / "cx5-fuzz5"
SCRIPT = DIR / "build_live_table.py"
ARTIFACT = DIR / "fuzz5_live.json"
MANIFEST = DIR / "fuzz5_live_manifest.md5"
JOURNAL = REPO / "docs/superpowers/journal/2026-10-26-irisc-fuzz5-task-04.md"

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


# --- mini-markdown journal-table excerpt (formats of the real journal) ---
MINI_MD = """\
### Сессия A: fuzz4rem (idx 0-4)

| вектор | census-строка | вердикт-сет жива | заметки |
|---|---|---|---|
| V-F5R-EQ | op36_f5=04_i6=00 | {eq32, ule32} формально (F-путь, write 5) | ule32 мертва по fuzz-4-приору -> eq32 жива |
| V-F5R-LTV | op36_f5=02_i6=00 | {uge32, ugt32, V} (write) | == известному live-факту f5=2 |

| f5 (i6) | жива-сет | комментарий |
|---|---|---|
| 02 (0) | {V} | uge/ugt модели умерли |
| 03/05/06 (0) | {eq32, eq16, uge32, ugt32, V} | одинаковый профиль |
| 04 i6=0x1c/0x20, 08 i6=0x18 | {ne32i, lt32i} | imm6-форма |
| 01 i6=0x3f | {eq32i, uge32i, V} | граница i6=63 |

| (idx,f) | obs | f5 (hex) |
|---|---|---|
| (0,0) | 0x0000000c | 00,04,05,06 |
| (10,1) | 0x00003634 | 08,0c,16 |

| вектор | строка | obs | жива |
|---|---|---|---|
| V-M34-f502-i00 | (2,0,0) | 0x0 | bclr |
| V-M34-f515-i16 | (0f,16,0) | 0xc0005 | depR |

| вектор | строка | obs | вывод |
|---|---|---|---|
| V-M33-f516-i14 | op33 f5=10 idx=0e | 0x0000bffe | clamp16 мертва, depR жива |
"""


def blt():
    return load("build_live_table")


class TestJournalParsers(unittest.TestCase):
    """mini-markdown journal-table excerpt -> per-row records."""

    @classmethod
    def setUpClass(cls):
        cls.m = blt()
        cls.parsed = cls.m.parse_journal(MINI_MD)

    def test_fuzz4rem_rows(self):
        rows = self.parsed["fuzz4rem"]
        by_vec = {r["vector_id"]: r for r in rows}
        self.assertEqual(by_vec["V-F5R-EQ"]["row"], "op36_f5=04_i6=00")
        self.assertEqual(by_vec["V-F5R-EQ"]["alive"], ["H-eq32", "H-ule32"])
        self.assertEqual(by_vec["V-F5R-LTV"]["alive"],
                         ["H-V", "H-uge32", "H-ugt32"])

    def test_map36_groups_expand(self):
        groups = self.parsed["map36_groups"]
        got = {(g["f5"], g["i6"]): g["alive"] for g in groups}
        self.assertEqual(got[(0x02, 0x00)], ["H-V"])
        for f5 in (0x03, 0x05, 0x06):
            self.assertEqual(got[(f5, 0x00)],
                             ["H-V", "H-eq16", "H-eq32", "H-uge32",
                              "H-ugt32"])
        self.assertEqual(got[(0x04, 0x1c)], ["H-lt32i", "H-ne32i"])
        self.assertEqual(got[(0x04, 0x20)], ["H-lt32i", "H-ne32i"])
        self.assertEqual(got[(0x08, 0x18)], ["H-lt32i", "H-ne32i"])
        self.assertEqual(got[(0x01, 0x3f)], ["H-V", "H-eq32i", "H-uge32i"])

    def test_map34_rogue_table(self):
        rog = self.parsed["rogue34"]
        got = {(r["idx"], r["flag"]): r for r in rog}
        self.assertEqual(got[(0x0, 0x0)]["obs"], "0x0000000c")
        self.assertEqual(got[(0x0, 0x0)]["f5s"], [0x00, 0x04, 0x05, 0x06])
        self.assertEqual(got[(0x0a, 0x1)]["obs"], "0x00003634")
        self.assertEqual(got[(0x0a, 0x1)]["f5s"], [0x08, 0x0c, 0x16])

    def test_map34_nonrogue_table(self):
        nr = self.parsed["nonrogue34"]
        by_vec = {r["vector_id"]: r for r in nr}
        r = by_vec["V-M34-f502-i00"]
        self.assertEqual((r["f5"], r["idx"], r["flag"]), (0x02, 0x00, 0x00))
        self.assertEqual(r["obs"], "0x00000000")
        self.assertEqual(r["model"], "H-bclr")
        r2 = by_vec["V-M34-f515-i16"]
        self.assertEqual((r2["f5"], r2["idx"], r2["flag"]),
                         (0x0F, 0x10, 0x00))
        self.assertEqual(r2["model"], "H-depR")

    def test_map33_examples(self):
        ex = self.parsed["map33_examples"]
        r = ex[0]
        self.assertEqual(r["vector_id"], "V-M33-f516-i14")
        self.assertEqual(r["row"], "op33_f5=10_idx=0e_flag=0")
        self.assertEqual(r["obs"], "0x0000bffe")
        self.assertEqual(r["model"], "H-depR")


class TestLo11KeyRestore(unittest.TestCase):
    """disc vectors without census_rows: key restored by decoding the lo11
    of the vector's target word (pinned: OPDEP-A/B, F0B)."""

    @classmethod
    def setUpClass(cls):
        cls.m = blt()
        cls.disc = json.loads((F5 / "fuzz5_disc_vectors.json").read_text())

    def _key_of(self, vector_id):
        v = next(x for x in self.disc if x["id"] == vector_id)
        return self.m.disc_vector_key(v)

    def test_pinned_opdep_a(self):
        self.assertEqual(self._key_of("V-D34-OPDEP-A"),
                         "op34_f5=04_idx=00_flag=0")

    def test_pinned_opdep_b(self):
        self.assertEqual(self._key_of("V-D34-OPDEP-B"),
                         "op34_f5=08_idx=0a_flag=1")

    def test_pinned_f0b(self):
        self.assertEqual(self._key_of("V-D34-F0B"),
                         "op34_f5=0b_idx=00_flag=0")

    def test_word_decode_rule(self):
        # lo11 = flag[10]|idx[9:5]|f5[4:0] (census_map.py:13 selector model)
        self.assertEqual(self.m.word_key(0xD0A43548),
                         "op34_f5=08_idx=0a_flag=1")
        self.assertEqual(self.m.word_key(0xD0A43402),
                         "op34_f5=02_idx=00_flag=1")
        self.assertEqual(self.m.word_key(0xD8A0300A), "op36_f5=0a_i6=00")

    def test_op38_predecessor_not_target(self):
        # cmp38 predecessor words (op 0x38) never feed the scan set
        self.assertIsNone(self.m.word_key(0xE0A03002))


MINI_CENSUS = {
    "rows": [
        {"id": "op34_f5=04_idx=00_flag=0", "op": "0x34",
         "selector": {"f5": 4, "idx": 0, "flag": 0, "lo11": 4},
         "class": "has-sites", "static": None},
        {"id": "op34_f5=08_idx=0a_flag=1", "op": "0x34",
         "selector": {"f5": 8, "idx": 10, "flag": 1, "lo11": 0x548},
         "class": "has-sites", "static": None},
        {"id": "op36_f5=04_i6=00", "op": "0x36",
         "selector": {"f5": 4, "i6": 0, "lo11": 4},
         "class": "has-sites", "static": None},
        {"id": "op34_f5=0f_idx=10_flag=0", "op": "0x34",
         "selector": {"f5": 15, "idx": 16, "flag": 0, "lo11": 0x20f},
         "class": "has-sites", "static": None},
        {"id": "op34_f5=1f_idx=00_flag=0", "op": "0x34",
         "selector": {"f5": 31, "idx": 0, "flag": 0, "lo11": 31},
         "class": "has-sites", "static": None},
    ]
}

# battery vector + OPDEP-A/B disc vector: real words from the repo artifacts
MINI_VECTORS = [
    {"id": "V-M34-f504-i00", "group": "map34",
     "words": ["00050001", "00060000", "d0a43004", "00032320", "6c602002",
               "6e402012", "00000000", "000443c8", "0884008e", "fc002025"],
     "expectations": {"H-depR": {"0x8c8": "0x00000000"},
                      "H-depM": {"0x8c8": "0x00000001"}},
     "census_rows": ["op34_f5=04_idx=00_flag=0"]},
    {"id": "V-M34-f508-i10-f1", "group": "map34",
     "words": ["00051234", "00060000", "d0a43548", "00032320", "6c602002",
               "6e402012", "00000000", "000443c8", "0884008e", "fc002025"],
     "expectations": {"H-depR": {"0x8c8": "0x00000234"},
                      "H-depM": {"0x8c8": "0x00001234"}},
     "census_rows": ["op34_f5=08_idx=0a_flag=1"]},
    {"id": "V-M34-f515-i16", "group": "map34",
     "words": ["00050001", "00060005", "d0a4300f", "00032320", "6c602002",
               "6e402012", "00000000", "000443c8", "0884008e", "fc002025"],
     "expectations": {"H-depR": {"0x8c8": "0x000c0005"},
                      "H-depM": {"0x8c8": "0x000d0005"}},
     "census_rows": ["op34_f5=0f_idx=10_flag=0"]},
]

MINI_DISC = [
    {"id": "V-D34-OPDEP-A", "group": "disc",
     "words": ["00057fff", "00060321", "d0a43004", "00032320", "6c602002",
               "6e402012", "00000000", "000443c8", "0884008e", "fc002025"],
     "expectations": {"H-depR": {"0x8c8": "0x00007ff1"},
                      "H-depM": {"0x8c8": "0x00007fff"},
                      "H-rogue": {"0x8c8": "0x0000000c"}},
     "notes": "rogue operand-independence: (4,0,0)"},
    {"id": "V-D34-OPDEP-B", "group": "disc",
     "words": ["00057fff", "00060321", "d0a43548", "00032320", "6c602002",
               "6e402012", "00000000", "000443c8", "0884008e", "fc002025"],
     "expectations": {"H-depR": {"0x8c8": "0x000087ff"},
                      "H-depM": {"0x8c8": "0x0000ffff"},
                      "H-rogue": {"0x8c8": "0x00003634"}},
     "notes": "rogue operand-independence: (8,10,1)"},
]

class TestMiniBuild(unittest.TestCase):
    """end-to-end build on fixtures: base + OPDEP observation on one key,
    verdicts from parsed tables, manifest drift gate."""

    @classmethod
    def setUpClass(cls):
        cls.m = blt()
        import tempfile
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        (t / "journal.md").write_text(MINI_MD)
        (t / "census.json").write_text(json.dumps(MINI_CENSUS))
        (t / "vectors.json").write_text(json.dumps(MINI_VECTORS))
        (t / "disc.json").write_text(json.dumps(MINI_DISC))
        (t / "merges.json").write_text(json.dumps(
            {"live_covered": 3, "live_only_rows": {
                "0x34": {"rows": 3, "rogue_rows": 2}}, "merges": []}))
        cls.dir = t
        cls.out = t / "fuzz5_live.json"
        cls.manifest = t / "manifest.md5"
        rc = cls.m.main([
            "--journal", str(t / "journal.md"),
            "--census", str(t / "census.json"),
            "--vectors", str(t / "vectors.json"),
            "--disc", str(t / "disc.json"),
            "--merges", str(t / "merges.json"),
            "--out", str(cls.out), "--manifest", str(cls.manifest)])
        cls.rc = rc
        cls.live = json.loads(cls.out.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_build_rc0_and_manifest_written(self):
        self.assertEqual(self.rc, 0)
        self.assertTrue(self.manifest.exists())

    def test_base_and_opdep_both_in_observations(self):
        rows = self.live["rows"]
        obs = rows["op34_f5=04_idx=00_flag=0"]["observations"]
        self.assertEqual([o["vector_id"] for o in obs],
                         ["V-M34-f504-i00", "V-D34-OPDEP-A"])
        self.assertEqual([o["observed"] for o in obs],
                         ["0x0000000c", "0x00007ffc"])
        obs_b = rows["op34_f5=08_idx=0a_flag=1"]["observations"]
        self.assertEqual([o["observed"] for o in obs_b],
                         ["0x00003634", "0x000037ff"])

    def test_rogue_and_unique_verdicts(self):
        rows = self.live["rows"]
        self.assertEqual(
            rows["op34_f5=04_idx=00_flag=0"]["live_verdict"], "rogue")
        self.assertEqual(
            rows["op34_f5=0f_idx=10_flag=0"]["live_verdict"], "unique")
        self.assertEqual(
            rows["op34_f5=0f_idx=10_flag=0"]["unique_model"], "H-depR")
        self.assertEqual(
            rows["op34_f5=0f_idx=10_flag=0"]["observations"][0]["observed"],
            "0x000c0005")

    def test_unobserved_default(self):
        row = self.live["rows"]["op34_f5=1f_idx=00_flag=0"]
        self.assertEqual(row["live_verdict"], "unobserved")
        self.assertEqual(row["observations"], [])
        self.assertIsNone(row["unique_model"])

    def test_operands_seed_captured(self):
        obs = self.live["rows"]["op34_f5=04_idx=00_flag=0"]["observations"]
        self.assertEqual(obs[0]["operands_seed"]["rs"], "0x00000001")
        self.assertEqual(obs[0]["operands_seed"]["rt"], "0x00000000")
        self.assertEqual(obs[1]["operands_seed"]["rs"], "0x00007fff")
        self.assertEqual(obs[1]["operands_seed"]["rt"], "0x00000321")

    def test_manifest_drift_rc_nonzero(self):
        j = self.dir / "journal.md"
        orig = j.read_text()
        try:
            j.write_text(orig.replace("0x0000000c", "0x0000000d"))
            rc = self.m.main([
                "--journal", str(j),
                "--census", str(self.dir / "census.json"),
                "--vectors", str(self.dir / "vectors.json"),
                "--disc", str(self.dir / "disc.json"),
                "--merges", str(self.dir / "merges.json"),
                "--out", str(self.out), "--manifest", str(self.manifest)])
            self.assertNotEqual(rc, 0)
        finally:
            j.write_text(orig)


class TestRealArtifact(unittest.TestCase):
    """committed fuzz5_live.json gates (pinned artifact for T4-T8)."""

    @classmethod
    def setUpClass(cls):
        if not ARTIFACT.exists():
            raise FileNotFoundError(
                "fuzz5_live.json not built (red: run build_live_table.py)")
        cls.live = json.loads(ARTIFACT.read_text())
        cls.merges = json.loads((F5 / "select_merges.json").read_text())
        cls.census = json.loads((F5 / "census_map.json").read_text())

    def test_universe_all_census_rows_plus_extras(self):
        rows = self.live["rows"]
        for r in self.census["rows"]:
            self.assertIn(r["id"], rows)
        extras = [k for k, v in rows.items() if not v["in_census"]]
        self.assertEqual(
            sorted(extras),
            ["op34_f5=04_idx=01_flag=0", "op34_f5=04_idx=01_flag=1",
             "op34_f5=04_idx=02_flag=0", "op34_f5=04_idx=03_flag=0",
             "op34_f5=0b_idx=00_flag=0"])
        for v in rows.values():
            self.assertEqual(v["section"], "MAIN")

    def test_covered_rows_match_select_merges(self):
        rows = self.live["rows"]
        battery_covered = sum(
            1 for v in rows.values()
            if v["in_census"] and v["coverage"] == "battery"
            and v["live_verdict"] != "unobserved")
        verdicted = sum(1 for v in rows.values()
                        if v["live_verdict"] != "unobserved")
        self.assertEqual(battery_covered, self.merges["live_covered"])
        self.assertEqual(self.live["meta"]["covered_rows"], 141)
        # 141 battery + 1 disc-only census row (V-D34-F2F1) + 5 extras
        self.assertEqual(verdicted, 147)
        f2f1 = rows["op34_f5=02_idx=00_flag=1"]
        self.assertEqual(f2f1["live_verdict"], "rogue")
        self.assertEqual(f2f1["coverage"], "disc")
        self.assertEqual(f2f1["observations"][0]["observed"],
                         "0x00000005")

    def test_live_only_counts_match_select_merges(self):
        per_op = {}
        for k, v in self.live["rows"].items():
            if not v["in_census"] or v["coverage"] != "battery":
                continue
            if v["live_verdict"] == "unobserved" or v["static"]:
                continue
            d = per_op.setdefault(v["op"], {"rows": 0, "rogue": 0})
            d["rows"] += 1
            if v["live_verdict"] == "rogue":
                d["rogue"] += 1
        for op, ref in self.merges["live_only_rows"].items():
            self.assertEqual(per_op[op]["rows"], ref["rows"])
            self.assertEqual(per_op[op]["rogue"], ref["rogue_rows"])

    def test_merge_confirms_are_unique_verdicts(self):
        rows = self.live["rows"]
        for mrec in self.merges["merges"]:
            for rid, tag, _vids in mrec.get("confirms", []):
                self.assertEqual(rows[rid]["live_verdict"], "unique", rid)
                self.assertEqual(rows[rid]["unique_model"], tag, rid)

    def test_spot_verdicts(self):
        rows = self.live["rows"]
        # fuzz4rem + narrowing
        self.assertEqual(rows["op36_f5=04_i6=00"]["live_verdict"], "unique")
        self.assertEqual(rows["op36_f5=04_i6=00"]["unique_model"], "H-eq32")
        self.assertEqual(
            rows["op36_f5=04_i6=00"]["observations"][0]["observed"],
            "0x00000005")
        # f5=2: unique V, two battery observations (V-F5R-LTV + V-M36-f502)
        r02 = rows["op36_f5=02_i6=00"]
        self.assertEqual(r02["live_verdict"], "unique")
        self.assertEqual(r02["unique_model"], "H-V")
        self.assertEqual(len(r02["observations"]), 2)
        # disc-resolved axes
        self.assertEqual(rows["op36_f5=0a_i6=00"]["unique_model"], "H-V")
        self.assertEqual(rows["op33_f5=00_idx=00_flag=1"]["unique_model"],
                         "H-pass")
        obs = rows["op33_f5=00_idx=00_flag=1"]["observations"]
        self.assertEqual([o["observed"] for o in obs],
                         ["0x00000003", "0x00000005"])
        # rogue-collision (DISC_RESOLVE select_merges.py)
        self.assertEqual(
            rows["op34_f5=0b_idx=10_flag=1"]["live_verdict"], "rogue")
        # div row
        self.assertEqual(rows["op38_sel=04"]["live_verdict"], "div")
        self.assertEqual(len(rows["op38_sel=04"]["observations"][0]
                             ["observed"]), 3)
        # multi (5-model class) preserved
        self.assertEqual(rows["op36_f5=03_i6=00"]["live_verdict"], "multi")
        self.assertEqual(rows["op36_f5=03_i6=00"]["alive_set"],
                         ["H-V", "H-eq16", "H-eq32", "H-uge32", "H-ugt32"])

    def test_opdep_precedent_keys(self):
        rows = self.live["rows"]
        obs = rows["op34_f5=04_idx=00_flag=0"]["observations"]
        self.assertEqual([o["observed"] for o in obs],
                         ["0x0000000c", "0x00007ffc"])
        obs_b = rows["op34_f5=08_idx=0a_flag=1"]["observations"]
        self.assertEqual([o["observed"] for o in obs_b],
                         ["0x00003634", "0x000037ff"])

    def test_cmp38_self_record_both_live_supports(self):
        rec = self.live["cmp38_self"]
        self.assertEqual(rec["unique_model"], "H-38self-false")
        sup = rec["supports"]
        self.assertEqual(len(sup), 2)
        self.assertEqual({s["cycle"] for s in sup}, {"fuzz-4", "fuzz-5"})
        fuzz4 = next(s for s in sup if s["cycle"] == "fuzz-4")
        self.assertIn("V-op38-self", fuzz4["vector_id"])
        self.assertTrue(fuzz4["ref"].endswith(
            "2026-10-25-irisc-fuzz4-task-07.md:32"))
        fuzz5 = next(s for s in sup if s["cycle"] == "fuzz-5")
        self.assertEqual(fuzz5["vector_id"], "V-F5R-38SELF")
        # the census row itself stays a normal record
        self.assertEqual(self.live["rows"]["op38_sel=00"]["live_verdict"],
                         "unique")

    def test_sources_present_on_every_record(self):
        for k, v in self.live["rows"].items():
            if v["live_verdict"] != "unobserved":
                self.assertTrue(v["source"], k)
            for o in v["observations"]:
                self.assertTrue(o["vector_id"], k)
                self.assertTrue(o["source"], k)

    def test_check_mode_determinism_and_manifest(self):
        if not JOURNAL.exists():
            self.skipTest("journal not present (public clone)")
        manifest = MANIFEST.read_text()
        self.assertEqual(len(manifest.strip().splitlines()), 5)
        res = subprocess.run(
            [sys.executable, str(SCRIPT), "--check"],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(res.returncode, 0, res.stderr)


if __name__ == "__main__":
    unittest.main()
