"""isa-max A Task 2 corpus tests: per-section classifier (synthetic) +
committed corpus/census artifact shape gates."""
import importlib.util
import json
import struct
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIR = REPO / "scripts" / "probes" / "cx5-isa-max"
F5 = REPO / "scripts" / "probes" / "cx5-fuzz5"

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


def load_census_map():
    return load("census_map", F5 / "census_map.py")


def words_of(payload):
    n = len(payload) // 4
    return struct.unpack_from(">%dI" % n, payload, 0)


ALU_OPS = (0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
BR_OP = 0x25


def known_stream(n, target_idx=None, target_word=None, ptr_span=None,
                 base=0x20710000):
    """Synthetic code stream: rotating known ALU ops + branches at
    i%16 in (0, 7) (>=2 anchors per 64-word window -> no mono-table vote,
    and every +-8 window keeps a branch when a ptr span swallows some);
    optional target word and a span of self-pointers (base + k*4)."""
    words = []
    for i in range(n):
        if target_idx is not None and i == target_idx:
            words.append(target_word)
        elif ptr_span and ptr_span[0] <= i <= ptr_span[1]:
            words.append(base + (i - ptr_span[0]) * 4)
        elif i % 16 in (0, 7):
            words.append((BR_OP << 26) | 0x11)
        else:
            words.append((ALU_OPS[i % len(ALU_OPS)] << 26) | (0x11 + i % 7))
    return words


class TestStrictMaskParam0(unittest.TestCase):
    """strict criterion uses the per-section param0 ptr window
    (the census_map.py:146 0x800000 hardcode must not be inherited)."""

    @classmethod
    def setUpClass(cls):
        cls.cc = load("census_corpus")
        cls.rc = cls.cc.RC

    def _code(self, words):
        n = len(words)
        feat, ops, code, cover, votes, wstats = self.rc.classify(words, n)
        return code

    def test_known_answer_strict_site(self):
        cc = self.cc
        target = (0x33 << 26) | (8 << 5) | 4  # f5=4 idx=8 flag=0
        words = known_stream(80, target_idx=40, target_word=target)
        code = self._code(words)
        self.assertTrue(code[40])
        strict = cc.strict_mask(words, len(words), code, 0x20710000)
        self.assertTrue(strict[40])
        # strict site must also satisfy the census selector model
        sel = load_census_map().selector_of(0x33, target)
        self.assertEqual((sel["f5"], sel["idx"], sel["flag"]), (4, 8, 0))

    def test_ptr_dense_rejected_with_correct_base(self):
        cc = self.cc
        words = known_stream(96, ptr_span=(40, 52))
        code = self._code(words)
        self.assertTrue(all(code))
        strict = cc.strict_mask(words, len(words), code, 0x20710000)
        # words inside/adjacent to the IRON_PREP-domain pointer table are
        # ptr-dense in +-8 -> never strict
        for i in (44, 46, 48):
            self.assertFalse(strict[i])
        # far from the ptr table and next to a branch -> strict holds
        self.assertTrue(strict[17])

    def test_ptr_dense_missed_by_hardcoded_base_documents_defect(self):
        cc = self.cc
        words = known_stream(96, ptr_span=(40, 52))
        code = self._code(words)
        wrong = cc.strict_mask(words, len(words), code, 0x800000)
        right = cc.strict_mask(words, len(words), code, 0x20710000)
        # with the census_map.py:146 hardcode the same window passes strict
        self.assertTrue(wrong[48])
        self.assertFalse(right[48])

    def test_param0_zero_disables_ptr_window(self):
        cc = self.cc
        words = known_stream(96, ptr_span=(40, 52), base=0x00001000)
        code = self._code(words)
        strict = cc.strict_mask(words, len(words), code, 0)
        # small-valued words must not be treated as pointers when base==0
        self.assertTrue(strict[48])


class TestClassifySectionSynthetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cs = load("corpus_sections")

    def _payload(self, words):
        return struct.pack(">%dI" % len(words), *words)

    def test_code_section_classified_irisc(self):
        words = known_stream(80, target_idx=40,
                             target_word=(0x33 << 26) | 0x104)
        cls, stats = self.cs.classify_section(0x05, self._payload(words))
        self.assertEqual(cls, "irisc")
        self.assertGreaterEqual(stats["code_frac"], 0.5)
        self.assertEqual(stats["words"], 80)

    def test_phu_like_stride16_is_data(self):
        # PHY-like 16B-stride table: half unknown-op words, no anchors,
        # known_frac 0.5 < TH_KNOWN -> data
        words = []
        for blk in range(64):
            words.append((0x33 << 26) | 0x201 | (blk % 8))
            words.append((0x35 << 26) | 0x102 | (blk % 4))
            words += [0x0000000F, 0x0000001E]
        cls, stats = self.cs.classify_section(0x20, self._payload(words))
        self.assertEqual(cls, "data")
        self.assertLess(stats["code_frac"], 0.5)

    def test_prior_disagreement_raises(self):
        words = [(0x33 << 26) | 0x201] * 256
        with self.assertRaises(self.cs.PriorDisagreement):
            self.cs.classify_section(0x03, self._payload(words))

    def test_phy_recorded_with_prior_not_decoded(self):
        words = [(0x33 << 26) | 0x201] * 256
        cls, stats = self.cs.classify_section(0x0a, self._payload(words))
        self.assertEqual(cls, "data")
        self.assertIsNone(stats)

    def test_domain_prior_table(self):
        dp = self.cs.DOMAIN_PRIOR
        for t in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0d, 0x0e, 0x15):
            self.assertEqual(dp.get(t), "irisc", hex(t))
        for t in (0x0a, 0x0b, 0x0c):
            self.assertEqual(dp.get(t), "data", hex(t))
        self.assertEqual(dp.get(0x18), "x86")
        self.assertIsNone(dp.get(0x01))
        self.assertIsNone(dp.get(0x20))


class TestCensusSectionCounting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = load("census_corpus")
        cls.cm = load_census_map()

    def test_census_section_cells_and_sites(self):
        w33a = (0x33 << 26) | (8 << 5) | 4        # f5=4 idx=8 flag=0
        w33b = (0x33 << 26) | 1                   # f5=1 idx=0 flag=0
        w36 = (0x36 << 26) | 4                    # f5=4 i6=0
        w0c = (0x0c << 26) | 0x00FF               # imm16=0x00ff
        w34 = (0x34 << 26) | 0x022                # dep.c lo11=0x022 selector
        words = [(0x01 << 26) | i for i in range(1, 33)]
        words[4] = w33a
        words[8] = w33a
        words[12] = w33b
        words[16] = w36
        words[20] = w0c
        words[24] = w34
        code = [True] * len(words)
        strict = [False] * len(words)
        strict[4] = True
        strict[24] = True
        cells = {}
        op_counts = {}
        sites = []
        self.cc.census_section(cells, op_counts, sites, "4030", "IRON_PREP",
                               words, code, strict)
        key = ("IRON_PREP", 0x33, (4, 8, 0))
        self.assertEqual(cells[key]["sites"]["4030"], 2)
        self.assertEqual(cells[key]["sites_strict"]["4030"], 1)
        key1 = ("IRON_PREP", 0x33, (1, 0, 0))
        self.assertEqual(cells[key1]["sites"]["4030"], 1)
        self.assertEqual(op_counts["IRON_PREP"][0x0c], 1)
        self.assertEqual(op_counts["IRON_PREP"][0x36], 1)
        self.assertEqual(len(sites), 6)  # 0x33 x3, 0x36, 0x0c, 0x34
        by_off = {int(s["dc_offset"], 16): s for s in sites}
        s = by_off[4 * 4]
        self.assertEqual(s["word"], "0x%08x" % w33a)
        self.assertTrue(s["strict"])
        self.assertEqual(s["fw"], "4030")
        self.assertEqual(s["section"], "IRON_PREP")
        self.assertFalse(by_off[8 * 4]["strict"])
        self.assertTrue(by_off[24 * 4]["strict"])
        self.assertEqual(by_off[20 * 4]["word"], "0x%08x" % w0c)


class TestCorpusSectionsArtifact(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads((DIR / "corpus_sections.json").read_text())

    def rows(self, **flt):
        out = [r for r in self.doc["sections"]
               if all(r.get(k) == v for k, v in flt.items())]
        self.assertTrue(out, str(flt))
        return out

    def test_all_five_versions_present_with_pinned_md5(self):
        imgs = self.doc["meta"]["images"]
        self.assertEqual(set(imgs), {"4030", "8008", "1619", "LX1900",
                                     "CX6DX"})
        for v, spec_ in imgs.items():
            self.assertIn("md5", spec_)
            self.assertRegex(spec_["md5"], r"^[0-9a-f]{32}$")

    def test_main_sections_cl1_irisc_every_version(self):
        for r in self.rows(type="0x03"):
            self.assertEqual(r["cl"], 1)
            self.assertEqual(r["classification"], "irisc")
            self.assertEqual(r["domain_prior"], "irisc")
            self.assertNotEqual(r["param0"], 0)
            self.assertGreater(r["decode_stats"]["code_frac"], 0.5)

    def test_reset_info_classified_data_zero_code_words(self):
        rows = self.rows(type="0x20")
        self.assertEqual(len(rows), 5)
        for r in rows:
            self.assertEqual(r["classification"], "data")
            self.assertEqual(r["decode_stats"]["code_words"], 0)

    def test_phy_and_rom_not_decoded(self):
        for r in self.rows(type="0x0a") + self.rows(type="0x0b") + \
                self.rows(type="0x0c"):
            self.assertEqual(r["classification"], "data")
            self.assertIsNone(r["decode_stats"])
        for r in self.rows(type="0x18"):
            self.assertEqual(r["classification"], "x86")
            self.assertIsNone(r["decode_stats"])

    def test_cx6dx_expanded_sections(self):
        for t in ("0x0d", "0x0e", "0x15"):
            rows = [r for r in self.rows(fw="CX6DX") if r["type"] == t]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["classification"], "irisc")
            self.assertEqual(rows[0]["domain_prior"], "irisc")


class TestCensusCorpusArtifact(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads((DIR / "census_corpus.json").read_text())
        cls.cm = load_census_map()
        cls.lines = (DIR / "corpus_sites.jsonl").read_text().splitlines()

    def test_row_contract(self):
        self.assertTrue(self.doc["rows"])
        for r in self.doc["rows"][:50]:
            self.assertIn("section", r["key"])
            self.assertIn("op", r["key"])
            self.assertIn("selector", r["key"])
            self.assertIn("sites", r)
            self.assertIn("class", r)
            self.assertIn(r["class"], ("has-sites", "zero-sites"))

    def test_main_baseline_matches_op_level_expected(self):
        base = self.doc["meta"]["linear_baseline"]["MAIN"]
        for ver in ("4030", "8008", "1619", "CX6DX"):
            for op, cnt in self.cm.OP_LEVEL_EXPECTED[ver].items():
                self.assertEqual(base[ver]["0x%02x" % op], cnt,
                                 "%s op 0x%02x" % (ver, op))

    def test_lx1900_baseline_matches_profile_census(self):
        base = self.doc["meta"]["linear_baseline"]["MAIN"]["LX1900"]
        for op, cnt in self.cm.PROFILE_CX4LX.items():
            self.assertEqual(base["0x%02x" % op], cnt, "0x%02x" % op)

    def test_sites_jsonl_counter_matches_census_sites(self):
        per = {}
        for line in self.lines:
            r = json.loads(line)
            k = (r["fw"], r["section"])
            per[k] = per.get(k, 0) + 1
        total = sum(per.values())
        self.assertEqual(total, len(self.lines))
        census_total = 0
        targets = {int(t, 16) for t in self.doc["meta"]["target_ops"]}
        for r in self.doc["rows"]:
            if int(r["key"]["op"], 16) not in targets:
                continue
            for ver, cnt in r["sites"].items():
                census_total += cnt
        self.assertEqual(total, census_total)

    def test_jsonl_site_shape(self):
        r = json.loads(self.lines[0])
        self.assertEqual(sorted(r.keys()),
                         ["dc_offset", "fw", "section", "strict", "word"])
        self.assertRegex(r["dc_offset"], r"^0x[0-9a-f]+$")
        self.assertRegex(r["word"], r"^0x[0-9a-f]{8}$")


if __name__ == "__main__":
    unittest.main()
