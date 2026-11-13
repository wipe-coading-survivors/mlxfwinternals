"""isa-max A Task 4 tests: 0x36 def-use framework (synthetic word stream) +
Rosetta idiom classifier + per-row verdict assignment + committed artifact
schema (unified T4-T7 contract; anti-circularity gates)."""
import collections
import importlib.util
import json
import struct
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIR = REPO / "scripts" / "probes" / "cx5-isa-max"

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


def op36(rs, rd, rt, lo11):
    return (0x36 << 26) | (rs << 21) | (rd << 16) | (rt << 11) | lo11


def bt(cc, off_words, rs=0):
    return (0x28 << 26) | (rs << 21) | (cc << 16) | (off_words & 0xffff)


def bf(cc, off_words, rs=0):
    return (0x29 << 26) | (rs << 21) | (cc << 16) | (off_words & 0xffff)


def set0(rd, imm):
    return (0x06 << 26) | (rd << 16) | (imm & 0xffff)


def addi(rd, rs, imm):
    return (0x00 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def ands(rd, rs, imm):
    return (0x0B << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def subsi(rd, rs, imm):
    return (0x05 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def subs(rd, rs, rt):
    return (0x3F << 26) | (rs << 21) | (rd << 16) | (rt << 11) | 5


def subi(rd, rs, imm):
    return (0x04 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def jump(delta_words):
    return (0x25 << 26) | (delta_words & 0x3ffffff)


def cmpw(rs, rt):
    return (0x38 << 26) | (rs << 21) | (0 << 16) | (rt << 11)


FILLER = addi(4, 0, 1)


class TestDefUseWindow(unittest.TestCase):
    """producer -> b.t/b.f cc0a consumer + operand provenance on a
    synthetic word stream (deterministic framework part)."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("h36_grind")

    def test_consumer_bt_at_distance_one(self):
        words = [op36(5, 0, 0, 0x004), bt(0x0A, 2), FILLER, FILLER]
        ctx = self.h.defuse_context(words, 0)
        self.assertEqual(ctx["state"], "consumer")
        self.assertEqual(ctx["polarity"], "t")
        self.assertEqual(ctx["dist"], 1)

    def test_consumer_bf_polarity(self):
        words = [op36(5, 0, 0, 0x004), FILLER, bf(0x0A, 2)]
        ctx = self.h.defuse_context(words, 0)
        self.assertEqual(ctx["state"], "consumer")
        self.assertEqual(ctx["polarity"], "f")
        self.assertEqual(ctx["dist"], 2)

    def test_killed_by_producer_0x36(self):
        words = [op36(5, 0, 0, 0x004), op36(6, 0, 0, 0x002), bt(0x0A, 2)]
        ctx = self.h.defuse_context(words, 0)
        self.assertEqual(ctx["state"], "killed")
        self.assertEqual(ctx["killed_by"], "0x36")

    def test_killed_by_cmpw_sel0(self):
        words = [op36(5, 0, 0, 0x004), cmpw(7, 8), bt(0x0A, 2)]
        ctx = self.h.defuse_context(words, 0)
        self.assertEqual(ctx["state"], "killed")
        self.assertEqual(ctx["killed_by"], "cmp.w")

    def test_other_cc_branch_is_not_consumer(self):
        words = [op36(5, 0, 0, 0x004), bt(0x00, 2), bt(0x0A, 2)]
        ctx = self.h.defuse_context(words, 0)
        self.assertEqual(ctx["state"], "consumer")
        self.assertEqual(ctx["dist"], 2)

    def test_no_consumer(self):
        words = [op36(5, 0, 0, 0x004)] + [FILLER] * 10
        ctx = self.h.defuse_context(words, 0)
        self.assertEqual(ctx["state"], "no-consumer")

    def test_operand_shapes(self):
        h = self.h
        self.assertEqual(
            h.defuse_context([op36(5, 0, 0, 0x004), bt(0x0A, 2)], 0)["shape"],
            "rs-vs-zero")
        self.assertEqual(
            h.defuse_context([op36(5, 0, 7, 0x004), bt(0x0A, 2)], 0)["shape"],
            "rs-vs-rt")
        self.assertEqual(
            h.defuse_context([op36(5, 0, 5, 0x004), bt(0x0A, 2)], 0)["shape"],
            "self")
        self.assertEqual(
            h.defuse_context([op36(5, 0, 0, 0x104), bt(0x0A, 2)], 0)["shape"],
            "imm")

    def test_provenance_imm_def(self):
        words = [set0(5, 0x1234), op36(5, 0, 0, 0x004), bt(0x0A, 2)]
        prov = self.h.provenance(words, 1, 5)
        self.assertEqual(prov[0], "imm")
        self.assertEqual(prov[1], -1)

    def test_provenance_none(self):
        words = [op36(5, 0, 0, 0x004), bt(0x0A, 2)]
        prov = self.h.provenance(words, 0, 5)
        self.assertEqual(prov[0], "none")

    def test_const_both_operands(self):
        words = [set0(5, 7), addi(6, 0, 9), op36(5, 0, 6, 0x004),
                 bt(0x0A, 2)]
        ctx = self.h.defuse_context(words, 2)
        self.assertTrue(ctx["const_both"])
        self.assertEqual(ctx["prov_rs"][0], "imm")
        self.assertEqual(ctx["prov_rt"][0], "imm")

    def test_dead_branch_noop(self):
        # b.t.0xa target == fall-through (branch to next instruction)
        words = [op36(5, 0, 0, 0x004), bt(0x0A, 1), FILLER, FILLER]
        ctx = self.h.defuse_context(words, 0)
        self.assertEqual(ctx["state"], "consumer")
        self.assertTrue(ctx["dead_branch"])

    def test_dead_branch_skip_noop(self):
        # b.t.0xa to a word that jumps right to the instruction after
        # the branch
        words = [op36(5, 0, 0, 0x004), bt(0x0A, 1), jump(1), FILLER]
        ctx = self.h.defuse_context(words, 0)
        self.assertTrue(ctx["dead_branch"])

    def test_live_branch_not_dead(self):
        words = [op36(5, 0, 0, 0x004), bt(0x0A, 3), FILLER, jump(-3)]
        ctx = self.h.defuse_context(words, 0)
        self.assertFalse(ctx["dead_branch"])


class TestRosettaClassify(unittest.TestCase):
    """position-strict known-op idiom classification at the aligned
    position of the old-compiler binary."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("h36_grind")

    def test_ztest_ands(self):
        words = [ands(3, 3, 0xF), subsi(3, 3, 0), bf(0x00, 2)]
        cands = self.h.classify_at(words, 0)
        self.assertTrue(cands)
        fam, detail, j = cands[0]
        self.assertEqual(fam, "eq")
        self.assertIn("0xf", detail)

    def test_cmp_const(self):
        words = [subsi(3, 4, 0x123), bt(0x00, 2)]
        cands = self.h.classify_at(words, 0)
        fam, detail, j = cands[0]
        self.assertEqual(fam, "eq")
        self.assertIn("0x123", detail)

    def test_reg_eq_subs(self):
        words = [subs(3, 4, 5), bf(0x00, 2)]
        cands = self.h.classify_at(words, 0)
        fam, detail, j = cands[0]
        self.assertEqual(fam, "eq")

    def test_ord_subi(self):
        words = [subi(3, 4, 5), bt(0x04, 2)]
        cands = self.h.classify_at(words, 0)
        fams = {c[0] for c in cands}
        self.assertIn("ord", fams)

    def test_nothing(self):
        words = [FILLER, FILLER, bt(0x0A, 5)]
        self.assertEqual(self.h.classify_at(words, 0), [])


class TestVerdictAssignment(unittest.TestCase):
    """axis verdict from aligned-pair cluster stats (programmatic per-row
    hypothesis assignment; thresholds documented in the artifact meta)."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("h36_grind")

    def _pair(self, fam):
        return {"fam": fam}

    def test_eq_dominant_axis_gets_hypothesis(self):
        pairs = [self._pair("eq")] * 20 + [self._pair("ord")] * 1
        v = self.h.assign_axis_verdict(pairs)
        self.assertEqual(v["static_verdict"], "H-36-eq-usage")
        self.assertTrue(v["unique"])
        self.assertFalse(v["conflict"])

    def test_ord_noise_above_threshold_blocks(self):
        pairs = [self._pair("eq")] * 20 + [self._pair("ord")] * 4
        v = self.h.assign_axis_verdict(pairs)
        self.assertIsNone(v["static_verdict"])
        self.assertFalse(v["unique"])
        self.assertTrue(v["conflict"])

    def test_too_few_pairs(self):
        v = self.h.assign_axis_verdict([self._pair("eq")] * 3)
        self.assertIsNone(v["static_verdict"])
        self.assertFalse(v["unique"])
        self.assertFalse(v["conflict"])


class TestArtifactSchema(unittest.TestCase):
    """committed h36_verdicts.json: unified per-row contract, two phases,
    lossless MAIN join surface, anti-circularity (Phase A has no live
    fields)."""

    @classmethod
    def setUpClass(cls):
        p = DIR / "h36_verdicts.json"
        cls.doc = json.loads(p.read_text())
        cls.live = json.loads((DIR / "fuzz5_live.json").read_text())

    def test_phases_present(self):
        self.assertIn("A", self.doc["phases"])
        self.assertIn("B", self.doc["phases"])

    def test_phase_a_row_contract(self):
        rows = self.doc["phases"]["A"]["rows"]
        self.assertTrue(rows)
        for r in rows[:50] + rows[-50:]:
            key = r["key"]
            self.assertEqual(key["op"], "0x36")
            self.assertEqual(set(key), {"section", "op", "selector"})
            sel = key["selector"]
            self.assertEqual(set(sel), {"f5", "i6", "lo11"})
            self.assertEqual(sel["lo11"], sel["f5"] | (sel["i6"] << 5))
            self.assertIn(r["form"], ("reg", "imm6"))
            self.assertIn("static_verdict", r)
            self.assertIsInstance(r["unique"], bool)
            self.assertIsInstance(r["conflict"], bool)
            self.assertIsInstance(r["basis"], list)
            self.assertIn(r["constructor_scope"], ("reg", "imm6"))
            self.assertIn(r["v_support"], (None, dict))
            # unified T4-T7 contract: the field exists in phase A too,
            # unjoined (null) -- no live data may leak into phase A
            self.assertIsNone(r["live_join"])
            if r["static_verdict"] is None:
                self.assertIn("reason", r)

    def test_phase_a_no_live_fields(self):
        text = json.dumps(self.doc["phases"]["A"])
        self.assertNotIn("unique_model", text)
        self.assertNotIn("live_verdict", text)
        self.assertNotIn("alive_set", text)

    def test_join_lossless_with_fuzz5_live(self):
        akeys = {json.dumps(r["key"], sort_keys=True)
                 for r in self.doc["phases"]["A"]["rows"]
                 if r["key"]["section"] == "MAIN"}
        lkeys = set()
        for k, v in self.live["rows"].items():
            if v["op"] != "0x36":
                continue
            lkeys.add(json.dumps(
                {"section": "MAIN", "op": "0x36", "selector": v["selector"]},
                sort_keys=True))
        self.assertTrue(lkeys)
        self.assertEqual(akeys & lkeys, lkeys)

    def test_phase_b_row_contract(self):
        """unified T4-T7 contract: every phase-B row carries ALL fields
        (static four + live_join) -- a T8 consumer reads one array."""
        rows = self.doc["phases"]["B"]["rows"]
        self.assertTrue(rows)
        for r in rows[:50]:
            for field in ("form", "static_verdict", "unique", "basis",
                          "conflict", "constructor_scope", "v_support",
                          "live_join"):
                self.assertIn(field, r)
            self.assertIn(r["live_join"]["status"],
                          ("match", "conflict", "silence"))
        self.assertIn("merge_ready", self.doc["phases"]["B"])

    def test_ceiling_inputs_computed(self):
        """ceiling items 1-2 are computed from the pinned corpus, not
        hardcoded strings (regenerable by --check)."""
        meta = self.doc["meta"]
        ci = meta["ceiling_inputs"]
        self.assertEqual(ci["rosetta_1619_strict_sites"], 0)
        self.assertEqual(ci["rosetta_1619_mask_only_sites"], 2)
        self.assertEqual(ci["dual_encoding_sites"], 0)
        self.assertIn("strict-sites of 0x36 in 1619: 0",
                      meta["ceiling"][0])
        self.assertIn("dual encoding", meta["ceiling"][1])
        self.assertIn("0 sites", meta["ceiling"][1])

    def test_drift_cap_documented(self):
        a = self.doc["phases"]["A"]
        self.assertLessEqual(len(a["drift_pairs"]), 200)
        self.assertEqual(a["drift_pairs_total"],
                         self.doc["meta"]["coverage"]["drift_pairs"])

    def test_basis_contexts_have_coordinates(self):
        for r in self.doc["phases"]["A"]["rows"]:
            if r["static_verdict"]:
                self.assertTrue(r["basis"])
                for ctx in r["basis"]:
                    if ctx["type"] == "rosetta":
                        self.assertIn("dc_offset", ctx["src"])
                        self.assertIn("dc_offset", ctx["tgt"])
                    elif ctx["type"] == "site":
                        self.assertIn("dc_offset", ctx["site"])
                        self.assertIn("fw", ctx["site"])

    def test_meta_thresholds_documented(self):
        meta = self.doc["meta"]
        self.assertIn("verdict_rule", meta)
        self.assertIn("v_axes_search", meta)
        self.assertIn("ceiling", meta)


class TestDualEncoding(unittest.TestCase):
    """in-corpus dual-encoding check: cmp.w with the same operand pair
    near a reg-form producer (ceiling item, computed in phase A)."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("h36_grind")

    def _run(self, words, producer_word):
        site = {"fw": "X", "section": "Y", "dc_offset": "0x8",
                "_word": producer_word, "_idx": 2}
        sections = {("X", "Y"): words}
        return self.h.dual_encoding_count(sections, [site])

    def test_same_pair_hit(self):
        words = [cmpw(5, 7), FILLER, op36(5, 0, 7, 0x004), bt(0x0A, 2),
                 FILLER]
        self.assertEqual(self._run(words, words[2]), 1)

    def test_swapped_pair_hit(self):
        words = [FILLER, cmpw(7, 5), op36(5, 0, 7, 0x004), bt(0x0A, 2)]
        self.assertEqual(self._run(words, words[2]), 1)

    def test_different_pair_miss(self):
        words = [cmpw(5, 9), FILLER, op36(5, 0, 7, 0x004), bt(0x0A, 2)]
        self.assertEqual(self._run(words, words[2]), 0)

    def test_out_of_range_miss(self):
        # cmp.w 13 words away: outside the +-12-word window
        words = [FILLER] * 15 + [cmpw(5, 7)] + [FILLER]
        words[2] = op36(5, 0, 7, 0x004)
        words[3] = bt(0x0A, 2)
        self.assertEqual(self._run(words, words[2]), 0)

    def test_imm_form_not_counted(self):
        # imm form compares rs vs i6, rt field is not the comparand
        words = [cmpw(5, 0), FILLER, op36(5, 0, 0, 0x104), bt(0x0A, 2)]
        self.assertEqual(self._run(words, words[2]), 0)


class TestAligner(unittest.TestCase):
    """const fingerprint + shifted-window alignment (Rosetta leg)."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("h36_grind")

    def test_const_fingerprint_anchors(self):
        words = [set0(4, 0x1234), addi(5, 0, 0x42), FILLER,
                 op36(5, 0, 0, 0x004), bt(0x0A, 2)]
        vals = [v for _, v in self.h.const_fingerprint(words, 0, 5)]
        self.assertIn(0x1234, vals)
        self.assertNotIn(0x42, vals)          # <= 0xff filtered

    def test_align_shifted_target(self):
        src = [set0(4, 0x1234), set0(5, 0x4321), addi(6, 0, 0x3456),
               op36(5, 0, 0, 0x004), bt(0x0A, 2)]
        tgt = [FILLER, FILLER, FILLER] + src + [FILLER] * 10
        idx = collections.defaultdict(list)
        for j, v in self.h.const_fingerprint(tgt, 0, len(tgt)):
            idx[v].append(j)
        al = self.h.align(src, 3, tgt, idx)
        self.assertIsNotNone(al)
        pi, score = al
        self.assertEqual(pi, 6)               # 3-word shift
        self.assertGreaterEqual(score, 3)


def op34(rs, rd, rt, lo11):
    return (0x34 << 26) | (rs << 21) | (rd << 16) | (rt << 11) | (lo11 & 0x7ff)


def op16(rs, rd, lo11):
    return (0x16 << 26) | (rs << 21) | (rd << 16) | (lo11 & 0x7ff)


def set3z(rd, imm):
    return (0x08 << 26) | (0 << 21) | (rd << 16) | (imm & 0xffff)


def set1z(rd, imm):
    return (0x07 << 26) | (0 << 21) | (rd << 16) | (imm & 0xffff)


def set3or(rd, imm):
    return (0x08 << 26) | (rd << 21) | (rd << 16) | (imm & 0xffff)


def addiz(rd, imm):
    return (0x00 << 26) | (0 << 21) | (rd << 16) | (imm & 0xffff)


def std(base, src):
    return (0x1E << 26) | (base << 21) | (src << 11)


LIVE_SEED_RS = 0x80000000A5A5F0F0


class TestH16FormulaCore(unittest.TestCase):
    """reformulated H-16 formula (width 32 + imm=0 carve-out) on synthetic
    selector/operand values -- the recompute path, no live access."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("h16_reform")

    def test_imm0_carveout_writes_zero(self):
        self.assertEqual(self.h.predict(0, LIVE_SEED_RS), 0)
        self.assertEqual(self.h.predict(0, 0xDEADBEEF), 0)

    def test_width32_saturate_at_32plus(self):
        # the three live-unique selector points all predict 0
        for lo11 in (0x028, 0x03C, 0x07D):
            self.assertEqual(self.h.predict(lo11, LIVE_SEED_RS), 0)

    def test_shift_1_31_uses_low32_only(self):
        self.assertEqual(self.h.predict(4, LIVE_SEED_RS), 0x0A5A5F0F)
        self.assertEqual(self.h.predict(1, 0xFFFFFFFFFFFFFFFF), 0x7FFFFFFF)
        self.assertEqual(self.h.predict(31, LIVE_SEED_RS), 1)

    def test_pass32_when_shift_mask_zero_but_imm_nonzero(self):
        self.assertEqual(self.h.predict(0x40, LIVE_SEED_RS), 0xA5A5F0F0)

    def test_predicted_class(self):
        p = self.h.predicted_class
        self.assertEqual(p(0), "imm0-carveout")
        self.assertEqual(p(3), "shr32")
        self.assertEqual(p(0x28), "width32-zero")
        self.assertEqual(p(0x7FF), "width32-zero")
        self.assertEqual(p(0x40), "pass32")

    def test_old_64bit_formula_diverges_at_the_conflict_points(self):
        # documented divergence: old H-16-shr (64-bit) vs reformulated
        self.assertEqual(self.h.predict_old(0, LIVE_SEED_RS), LIVE_SEED_RS)
        self.assertEqual(self.h.predict_old(0x28, LIVE_SEED_RS), 0x800000)
        self.assertEqual(self.h.predict(0, LIVE_SEED_RS), 0)
        self.assertEqual(self.h.predict(0x28, LIVE_SEED_RS), 0)


class TestH16DefUseSynthetic(unittest.TestCase):
    """raw def-use framework on synthetic word streams: rd consumer
    classification, rs provenance consts, and the value-check path."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("h16_reform")

    def test_consumer_pred0(self):
        words = [op16(5, 4, 0), op36(4, 0, 0, 0x002), bt(0x0A, 2)]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "pred0")
        self.assertEqual(f["consumer_class"], "const-test")

    def test_consumer_cmp0(self):
        words = [op16(5, 4, 0x28), subsi(4, 4, 0), bf(0x00, 2)]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "cmp0")
        self.assertEqual(f["consumer_class"], "const-test")

    def test_consumer_cmpC(self):
        words = [op16(5, 4, 0), subsi(4, 4, 1), bf(0x00, 2)]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "cmpC")
        self.assertEqual(f["cmp_const"], 1)
        self.assertEqual(f["consumer_class"], "const-test")

    def test_consumer_ztest_ands(self):
        ands_rd = (0x0B << 26) | (4 << 21) | (6 << 16) | 0xF
        words = [op16(5, 4, 3), ands_rd, bf(0x00, 2)]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "ztest")
        self.assertEqual(f["consumer_class"], "const-test")

    def test_consumer_bittest_branch(self):
        # b.bset/b.bclr (0x2a/0x2b) read rs: a fixed-bit test of rd
        bbset = (0x2A << 26) | (4 << 21) | (5 << 16) | 3
        words = [op16(5, 4, 0), bbset]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "bittest")
        self.assertEqual(f["consumer_class"], "const-test")

    def test_consumer_store_is_carry(self):
        words = [op16(5, 4, 0), std(1, 4)]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "store")
        self.assertEqual(f["consumer_class"], "carry")

    def test_consumer_read_is_carry(self):
        and_rd = (0x0A << 26) | (4 << 21) | (6 << 16) | 0xFFFF
        words = [op16(5, 4, 0), and_rd]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "read")
        self.assertEqual(f["consumer_class"], "carry")

    def test_consumer_clobber_is_dead(self):
        words = [op16(5, 4, 0), set0(4, 7), bf(0x00, 2)]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "clobber")
        self.assertEqual(f["consumer_class"], "dead")

    def test_consumer_none_is_dead(self):
        words = [op16(5, 6, 0)] + [FILLER] * 12
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "none")
        self.assertEqual(f["consumer_class"], "dead")

    def test_rd_zero_result_discarded(self):
        words = [op16(5, 0, 0), subsi(4, 4, 0)]
        f = self.h.site_facts(words, 0)
        self.assertEqual(f["consumer"], "rd-zero")
        self.assertEqual(f["consumer_class"], "rd-zero")

    def test_prov_set3_from_zero(self):
        words = [set3z(5, 0x1234), op16(5, 4, 3)]
        f = self.h.site_facts(words, 1)
        self.assertEqual(f["rs_prov"], "imm")
        self.assertEqual(f["rs_value"], 0x1234)

    def test_prov_set1_from_zero_chunk32(self):
        words = [set1z(5, 0x61E5), op16(5, 4, 3)]
        f = self.h.site_facts(words, 1)
        self.assertEqual(f["rs_value"], 0x61E5 << 32)

    def test_prov_addi_from_zero_sign_extended(self):
        words = [addiz(5, 0x8000), op16(5, 4, 3)]
        f = self.h.site_facts(words, 1)
        self.assertEqual(f["rs_value"], 0xFFFFFFFFFFFF8000)

    def test_prov_set_or_form_is_other(self):
        # set3 with rs==rd ORs into the register: not a pure constant
        words = [set3or(4, 0x61E5), op16(4, 8, 0x3C)]
        f = self.h.site_facts(words, 1)
        self.assertEqual(f["rs_prov"], "other")
        self.assertIsNone(f["rs_value"])

    def test_prov_none_and_zero_reg(self):
        f = self.h.site_facts([op16(9, 4, 3)], 0)
        self.assertEqual(f["rs_prov"], "none")
        f = self.h.site_facts([op16(0, 4, 3)], 0)
        self.assertEqual(f["rs_prov"], "zero-reg")
        self.assertEqual(f["rs_value"], 0)

    def test_value_check_match_shift(self):
        # 0x2468 >> 3 == 0x48D: the consumer tests exactly the predicted
        # constant -> raw-context value corroboration of the formula
        words = [set3z(5, 0x2468), op16(5, 4, 3), subsi(9, 4, 0x48D)]
        f = self.h.site_facts(words, 1)
        self.assertEqual(f["value_check"], "match")

    def test_value_check_mismatch_is_conflict(self):
        words = [set3z(5, 0x2468), op16(5, 4, 3), subsi(9, 4, 0x111)]
        f = self.h.site_facts(words, 1)
        self.assertEqual(f["value_check"], "mismatch")

    def test_value_check_imm0_carveout(self):
        # imm=0 with a proven nonzero rs: consumers must see 0, not rs
        words = [set3z(5, 5), op16(5, 4, 0), subsi(9, 4, 0)]
        self.assertEqual(self.h.site_facts(words, 1)["value_check"],
                         "match")
        words = [set3z(5, 5), op16(5, 4, 0), subsi(9, 4, 5)]
        self.assertEqual(self.h.site_facts(words, 1)["value_check"],
                         "mismatch")

    def test_value_check_width32_saturate(self):
        # rs = 1<<63 (set0 chunk 48), shift 40: width-32 -> 0, the
        # consumer tests 0; the old 64-bit reading would give 1<<23
        set0z63 = (0x06 << 26) | (0 << 21) | (5 << 16) | 0x8000
        words = [set0z63, op16(5, 4, 0x28), subsi(9, 4, 0)]
        self.assertEqual(self.h.site_facts(words, 1)["value_check"],
                         "match")

    def test_value_check_absent_without_const(self):
        words = [op16(5, 4, 3), subsi(9, 4, 0x48D)]
        self.assertIsNone(self.h.site_facts(words, 0)["value_check"])


class TestH16RowVerdict(unittest.TestCase):
    """per-row verdict recomputed from raw site facts (no live access)."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("h16_reform")

    def _fact(self, **kw):
        base = {"value_check": None, "consumer_class": "const-test"}
        base.update(kw)
        return base

    def test_no_sites_silent(self):
        v = self.h.row_verdict(0, [])
        self.assertIsNone(v["static_verdict"])
        self.assertFalse(v["conflict"])
        self.assertFalse(v["unique"])
        self.assertIn("reason", v)

    def test_sites_consistent(self):
        v = self.h.row_verdict(0, [self._fact(), self._fact()])
        self.assertEqual(v["static_verdict"], "H-16-shr32u0-consistent")
        self.assertFalse(v["conflict"])
        self.assertTrue(v["unique"])

    def test_value_mismatch_is_conflict(self):
        v = self.h.row_verdict(3, [self._fact(),
                                   self._fact(value_check="mismatch")])
        self.assertIsNone(v["static_verdict"])
        self.assertTrue(v["conflict"])
        self.assertIn("reason", v)


class TestH16ArtifactSchema(unittest.TestCase):
    """committed h16_verdicts.json: unified per-row contract, anti-circular
    phase separation, imm=0 dossier with coordinates, conflict-resolution
    join with fuzz5_live."""

    @classmethod
    def setUpClass(cls):
        p = DIR / "h16_verdicts.json"
        cls.doc = json.loads(p.read_text())
        cls.live = json.loads((DIR / "fuzz5_live.json").read_text())

    def test_phases_present(self):
        self.assertIn("A", self.doc["phases"])
        self.assertIn("B", self.doc["phases"])

    def test_phase_a_row_contract(self):
        rows = self.doc["phases"]["A"]["rows"]
        self.assertEqual(len(rows), 421)
        for r in rows[:60] + rows[-60:]:
            key = r["key"]
            self.assertEqual(key["op"], "0x16")
            self.assertEqual(set(key), {"section", "op", "selector"})
            self.assertEqual(set(key["selector"]), {"lo11"})
            f = r["formula"]
            self.assertEqual(f["width"], 32)
            self.assertIsInstance(f["imm0_carveout"], str)
            self.assertIn(r["predicted_class"],
                          ("imm0-carveout", "shr32", "width32-zero",
                           "pass32"))
            self.assertIsInstance(r["unique"], bool)
            self.assertIsInstance(r["conflict"], bool)
            self.assertIsInstance(r["basis"], list)
            # verdict provenance: raw def-use only
            if r["static_verdict"] is not None:
                self.assertEqual(r["static_verdict"],
                                 "H-16-shr32u0-consistent")
                self.assertEqual(r["static_source"], "raw-def-use")
            else:
                self.assertNotIn("static_source", r)
                self.assertIn("reason", r)
            # anti-circularity: phase A never carries live fields
            self.assertIsNone(r["live_join"])
            self.assertFalse(r["merge_ready"])

    def test_predicted_class_consistent_with_lo11(self):
        for r in self.doc["phases"]["A"]["rows"]:
            lo11 = r["key"]["selector"]["lo11"]
            self.assertEqual(r["predicted_class"],
                             self.h16().predicted_class(lo11))

    def test_imm0_dossier_five_4030_sites_with_coordinates(self):
        d = self.doc["meta"]["imm0_dossier"]
        sites_4030 = [s for s in d["sites"] if s["fw"] == "4030"]
        self.assertEqual(len(sites_4030), 5)
        offs = {s["dc_offset"] for s in sites_4030}
        self.assertEqual(offs, {"0x218858", "0x218c74", "0x3936d0",
                                "0x3936d8", "0x393700"})
        by_off = {s["dc_offset"]: s for s in sites_4030}
        # the two strict code sites: consumers see a fixed constant
        # (const-test), never a flowing rs
        for off in ("0x218858", "0x218c74"):
            self.assertTrue(by_off[off]["strict"])
            self.assertEqual(by_off[off]["def_use"]["consumer_class"],
                             "const-test")
        # the three data-region words: mask-only, never proof
        for off in ("0x3936d0", "0x3936d8", "0x393700"):
            self.assertFalse(by_off[off]["strict"])
            self.assertEqual(by_off[off]["def_use"]["consumer_class"],
                             "data-region")

    def test_imm0_dossier_covers_all_strict_sites(self):
        d = self.doc["meta"]["imm0_dossier"]
        n_strict = sum(1 for s in d["sites"] if s["strict"])
        self.assertGreaterEqual(n_strict, 15)
        self.assertEqual(d["note_sites_4030"], 5)

    def test_phase_a_no_live_fields(self):
        text = json.dumps(self.doc["phases"]["A"])
        for banned in ("observed", "vector_id", "live_verdict",
                       "alive_set", "unique_model", "operands"):
            self.assertNotIn(banned, text)

    def test_join_lossless_with_fuzz5_live(self):
        akeys = {json.dumps(r["key"], sort_keys=True)
                 for r in self.doc["phases"]["A"]["rows"]}
        lkeys = set()
        for k, v in self.live["rows"].items():
            if v["op"] != "0x16":
                continue
            lkeys.add(json.dumps(
                {"section": "MAIN", "op": "0x16",
                 "selector": {"lo11": v["selector"]["lo11"]}},
                sort_keys=True))
        self.assertEqual(len(lkeys), 39)
        self.assertTrue(lkeys <= akeys)

    def test_phase_b_row_contract(self):
        rows = self.doc["phases"]["B"]["rows"]
        self.assertEqual(len(rows), len(self.doc["phases"]["A"]["rows"]))
        for r in rows:
            for field in ("formula", "static_verdict", "unique", "basis",
                          "conflict", "live_join", "merge_ready"):
                self.assertIn(field, r)
            self.assertIsInstance(r["merge_ready"], bool)

    def test_live_join_agrees_with_every_observation(self):
        h = self.h16()
        by_key = {json.dumps(r["key"], sort_keys=True): r
                  for r in self.doc["phases"]["B"]["rows"]}
        checked = 0
        for lk, v in self.live["rows"].items():
            if v["op"] != "0x16":
                continue
            jkey = json.dumps({"section": "MAIN", "op": "0x16",
                               "selector": {"lo11": v["selector"]["lo11"]}},
                              sort_keys=True)
            r = by_key[jkey]
            pts = [(int(o["operands_seed"]["rs"], 16), int(o["observed"], 16))
                   for o in v["observations"] if o.get("observed") is not None]
            if pts:
                checked += 1
                for rs, obs in pts:
                    self.assertEqual(
                        h.predict(v["selector"]["lo11"], rs), obs, lk)
                self.assertEqual(r["live_join"]["status"], "match", lk)
        self.assertEqual(checked, 4)

    def test_conflict_resolved_and_merge_ready_rows(self):
        meta = self.doc["meta"]["h16_conflict_resolution"]
        self.assertEqual(meta["outcome"], "resolved")
        rows = self.doc["phases"]["B"]["rows"]
        ready = [r for r in rows if r["merge_ready"]]
        self.assertEqual({r["key"]["selector"]["lo11"] for r in ready},
                         {0x0, 0x28, 0x3C, 0x7D})
        for r in ready:
            self.assertEqual(r["key"]["section"], "MAIN")
            self.assertIsNotNone(r["static_verdict"])
            self.assertEqual(r["live_join"]["status"], "match")
            self.assertFalse(r["conflict"])

    def test_no_merge_ready_without_static_and_live(self):
        for r in self.doc["phases"]["B"]["rows"]:
            if r["merge_ready"]:
                self.assertIsNotNone(r["static_verdict"])
                self.assertEqual(r["live_join"]["status"], "match")
            else:
                self.assertTrue(r["static_verdict"] is None
                                or r["live_join"]["status"] != "match"
                                or r["conflict"])

    def test_basis_contexts_have_coordinates(self):
        for r in self.doc["phases"]["A"]["rows"]:
            if r["static_verdict"] is not None:
                self.assertTrue(r["basis"])
                for b in r["basis"]:
                    self.assertIn("dc_offset", b["site"])
                    self.assertIn("fw", b["site"])
                    self.assertIn("consumer_class", b["def_use"])

    def test_ceiling_adjudicable_pairs_computed(self):
        # const-value adjudication pairs found in the corpus (computed,
        # not hardcoded): documented as zero in this production run
        self.assertEqual(
            self.doc["meta"]["coverage"]["value_adjudicable_sites"], 0)

    def test_pins_present(self):
        pins = self.doc["meta"]["pins"]
        for name in ("corpus_sites.jsonl", "census_corpus.json",
                     "census_map.json", "fuzz5_live.json"):
            self.assertRegex(pins[name], r"^[0-9a-f]{32}$")

    def test_verdict_rule_documented(self):
        meta = self.doc["meta"]
        self.assertIn("verdict_rule", meta)
        self.assertIn("static_rule_note", meta)
        self.assertIn("coverage", meta)

    @classmethod
    def h16(cls):
        return load("h16_reform")


class TestP34ModelCore(unittest.TestCase):
    """rogue P-model core on a synthetic observed set: mask from f5
    (incl. the f5=0 width-32 wrap), idx-dependence, flag OR into the
    deposit base, and the residual rule (contradiction -> residual)."""

    @classmethod
    def setUpClass(cls):
        cls.m = load("p34_model")

    def test_mask32(self):
        self.assertEqual(self.m.mask32(0), 0xFFFFFFFF)
        self.assertEqual(self.m.mask32(1), 0x1)
        self.assertEqual(self.m.mask32(2), 0x3)
        self.assertEqual(self.m.mask32(4), 0xF)
        self.assertEqual(self.m.mask32(0x1F), 0x7FFFFFFF)

    def test_deposit_base_masked_to_field_width(self):
        # P0 = (0xc | flag) & mask32(f5): the fuzz-5 "outside simple
        # formula" f5=3 point P=0x4 is the width-masked deposit base
        self.assertEqual(self.m.p0(4, 0), 0xC)
        self.assertEqual(self.m.p0(4, 1), 0xD)
        self.assertEqual(self.m.p0(3, 0), 0x4)
        self.assertEqual(self.m.p0(3, 1), 0x5)
        self.assertEqual(self.m.p0(2, 0), 0x0)
        self.assertEqual(self.m.p0(2, 1), 0x1)
        self.assertEqual(self.m.p0(0, 0), 0xC)

    def test_field_mask_and_deposit_shift_by_idx(self):
        self.assertEqual(self.m.field_mask(4, 0), 0xF)
        self.assertEqual(self.m.field_mask(4, 16), 0x000F0000)
        self.assertEqual(self.m.field_mask(2, 26), 0x0C000000)
        self.assertEqual(self.m.field_mask(0, 5), 0xFFFFFFE0)
        self.assertEqual(self.m.deposit(0xC, 8), 0xC00)

    def test_predict_synthetic_observed_set(self):
        # every captured discriminating shape, as synthetic points
        p = self.m.predict
        self.assertEqual(p(4, 0, 0, 0x1), 0xC)             # battery
        self.assertEqual(p(4, 0, 0, 0x7FFF), 0x7FFC)       # OPDEP-A
        self.assertEqual(p(4, 1, 1, 0x1), 0x1B)            # IDX1F
        self.assertEqual(p(4, 3, 0, 0x1), 0x61)            # IDX3
        self.assertEqual(p(3, 0, 0, 0x3), 0x4)             # P0 width-mask
        self.assertEqual(p(0, 0, 0, 0x3), 0xC)             # f5=0 width 32
        self.assertEqual(p(0, 5, 0, 0x1234), 0x194)        # keeps low idx
        self.assertEqual(p(2, 0, 1, 0x5), 0x5)
        self.assertEqual(p(2, 26, 1, 0x0F0F0F0F), 0x070F0F0F)
        self.assertEqual(p(2, 14, 1, 0x7FFE), 0x7FFE)
        self.assertEqual(p(8, 10, 1, 0x1234), 0x3634)
        self.assertEqual(p(8, 10, 1, 0x7FFF), 0x37FF)      # OPDEP-B
        self.assertEqual(p(8, 24, 1, 0x0F0F0F0F), 0x0D0F0F0F)
        self.assertEqual(p(0xB, 0, 0, 0x1234), 0x100C)     # F0B
        self.assertEqual(p(0xB, 16, 1, 0x10005), 0xD0005)
        self.assertEqual(p(0x14, 12, 1, 0x1234), 0xD234)
        self.assertEqual(p(0x1A, 6, 1, 0x55), 0x355)
        self.assertEqual(p(0x1D, 3, 0, 0xA), 0x62)
        self.assertEqual(p(0x1F, 1, 0, 0x3), 0x19)

    def test_fit_all_observations(self):
        # the full captured observed set fits the formula with no
        # residuals (synthetic mirror of the artifact gate)
        pts = [(4, 0, 0, 0x1, 0xC), (4, 0, 0, 0x7FFF, 0x7FFC),
               (8, 10, 1, 0x1234, 0x3634), (8, 10, 1, 0x7FFF, 0x37FF),
               (0xB, 0, 0, 0x1234, 0x100C), (3, 0, 0, 0x3, 0x4),
               (0, 0, 0, 0x3, 0xC)]
        for f5, idx, flag, rs, obs in pts:
            self.assertEqual(self.m.predict(f5, idx, flag, rs), obs)

    def test_contradiction_marks_residual(self):
        # a synthetic observation the model misses -> the row verdict
        # must be residual, not a forced formula fit
        v = self.m.row_model_form(
            4, 0, 0, [(0x1, 0xC), (0x7FFF, 0x7FFC), (0x5, 0xDEAD)])
        self.assertEqual(v, "residual")
        self.assertEqual(
            self.m.row_model_form(4, 0, 0,
                                  [(0x1, 0xC), (0x7FFF, 0x7FFC)]),
            "formula")

    def test_row_model_form_checks_all_observations(self):
        # first observation matching is not enough: a mismatching second
        # observation still flips the row to residual
        v = self.m.row_model_form(4, 0, 0, [(0x1, 0xC), (0x7FFF, 0xBEEF)])
        self.assertEqual(v, "residual")


class TestP34StaticLeg(unittest.TestCase):
    """def-use facts of a 0x34 site on a synthetic word stream: rt
    provenance (the const-deposit contradiction signal) and rd next-use.
    """

    @classmethod
    def setUpClass(cls):
        cls.m = load("p34_model")

    def test_rt_live_def_detected(self):
        # rt freshly written from a non-imm source just before the site
        # (ld.w r8, [r1+off]: a live value, not an imm chain)
        ldw = (0x19 << 26) | (1 << 21) | (8 << 16)
        words = [ldw, op34(2, 4, 8, 0x009), bt(0x0A, 2)]
        self.assertEqual(self.m.prov_class(words, 1, 8), ("other", -1))

    def test_rt_zero_reg(self):
        words = [op34(2, 4, 0, 0x009)]
        self.assertEqual(self.m.prov_class(words, 0, 0)[0], "zero-reg")

    def test_rt_imm_chain_not_live(self):
        words = [set0(8, 0x42), op34(2, 4, 8, 0x009)]
        self.assertEqual(self.m.prov_class(words, 1, 8), ("imm", -1))

    def test_rd_next_use_store(self):
        words = [op34(2, 4, 8, 0x009), bt(0x0A, 5),
                 (0x1B << 26) | (1 << 21) | (4 << 11)]
        self.assertEqual(self.m.next_use(words, 0, 4), ("store", 2))

    def test_rd_clobber_before_use(self):
        words = [op34(2, 4, 8, 0x009), set0(4, 5), bt(0x0A, 2)]
        self.assertEqual(self.m.next_use(words, 0, 4), ("clobber", 1))

    def test_row_static_verdict_thresholds(self):
        fact_rt_live = {"rt_live": True}
        fact_plain = {"rt_live": False}
        self.assertEqual(
            self.m.row_static_verdict([fact_rt_live] * 3 + [fact_plain] * 5),
            "H-34-rt-fed")
        self.assertEqual(
            self.m.row_static_verdict([fact_rt_live] * 2 + [fact_plain] * 5),
            "H-34-field-consistent")
        self.assertIsNone(self.m.row_static_verdict([]))


class TestP34ArtifactSchema(unittest.TestCase):
    """committed p34_table.json: unified per-row contract, two phases,
    anti-circularity, lossless live join, dual-validation meta."""

    @classmethod
    def setUpClass(cls):
        p = DIR / "p34_table.json"
        cls.doc = json.loads(p.read_text())
        cls.live = json.loads((DIR / "fuzz5_live.json").read_text())

    def test_phases_present(self):
        self.assertIn("A", self.doc["phases"])
        self.assertIn("B", self.doc["phases"])

    def test_phase_a_row_contract(self):
        rows = self.doc["phases"]["A"]["rows"]
        self.assertTrue(rows)
        for r in rows:
            key = r["key"]
            self.assertEqual(key["op"], "0x34")
            self.assertEqual(set(key), {"section", "op", "selector"})
            sel = key["selector"]
            self.assertEqual(set(sel), {"f5", "idx", "flag", "lo11"})
            self.assertEqual(sel["lo11"],
                             sel["f5"] | (sel["idx"] << 5)
                             | (sel["flag"] << 10))
            self.assertIn(r["static_verdict"],
                          (None, "H-34-rt-fed", "H-34-field-consistent"))
            self.assertIsInstance(r["predicted"], dict)
            self.assertIn("mask", r["predicted"])
            self.assertIn("deposit", r["predicted"])
            self.assertIsInstance(r["unique"], bool)
            self.assertIsInstance(r["basis"], list)
            self.assertIsInstance(r["conflict"], bool)
            self.assertIsNone(r["live_join"])
            if r["static_verdict"] is None:
                self.assertIn("reason", r)

    def test_phase_a_no_live_fields(self):
        text = json.dumps(self.doc["phases"]["A"])
        for banned in ("observed", "vector_id", "live_verdict",
                       "alive_set", "operands"):
            self.assertNotIn(banned, text)

    def test_predicted_serializes_the_p_table(self):
        m = load("p34_model")
        for r in self.doc["phases"]["A"]["rows"]:
            sel = r["key"]["selector"]
            self.assertEqual(int(r["predicted"]["mask"], 16),
                             m.field_mask(sel["f5"], sel["idx"]))
            self.assertEqual(int(r["predicted"]["deposit"], 16),
                             m.deposit(sel["f5"], sel["idx"],
                                       sel["flag"]))

    def test_join_lossless_with_fuzz5_live(self):
        bkeys = {json.dumps(r["key"], sort_keys=True)
                 for r in self.doc["phases"]["B"]["rows"]}
        lkeys = set()
        for k, v in self.live["rows"].items():
            if v["op"] != "0x34":
                continue
            lkeys.add(json.dumps(
                {"section": v["section"], "op": "0x34",
                 "selector": v["selector"]}, sort_keys=True))
        self.assertTrue(lkeys)
        self.assertTrue(lkeys <= bkeys)

    def test_phase_b_row_contract(self):
        rows = self.doc["phases"]["B"]["rows"]
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["key"]["op"], "0x34")
            for field in ("static_verdict", "predicted", "unique",
                          "basis", "conflict", "live_join",
                          "model_form"):
                self.assertIn(field, r)
            self.assertIn(r["live_join"]["status"],
                          ("match", "contradiction", "silence"))
            self.assertIn(r["model_form"], ("formula", "residual"))

    def test_live_join_agrees_with_all_observations(self):
        m = load("p34_model")
        by_key = {json.dumps(r["key"], sort_keys=True): r
                  for r in self.doc["phases"]["B"]["rows"]}
        checked = 0
        for lk, v in self.live["rows"].items():
            if v["op"] != "0x34":
                continue
            r = by_key[json.dumps({"section": v["section"], "op": "0x34",
                                   "selector": v["selector"]},
                                  sort_keys=True)]
            n_val = sum(1 for o in v["observations"]
                        if o.get("observed") is not None)
            if n_val:
                checked += 1
                self.assertEqual(r["live_join"]["status"], "match",
                                 lk)
                sel = v["selector"]
                for o in v["observations"]:
                    if o.get("observed") is None:
                        continue
                    rs = int((o.get("operands_seed") or {})
                             .get("rs", "0"), 16) & 0xFFFFFFFF
                    self.assertEqual(
                        m.predict(sel["f5"], sel["idx"], sel["flag"], rs),
                        int(o["observed"], 16), "%s/%s" % (
                            lk, o["vector_id"]))
        self.assertGreater(checked, 40)

    def test_meta_dual_validation(self):
        meta = self.doc["meta"]
        self.assertEqual(meta["model_form"], "formula")
        vl = meta["validation_live"]
        vs = meta["validation_static"]
        self.assertGreater(vl["observed_total"], 40)
        self.assertEqual(vl["match"], vl["observed_total"])
        self.assertEqual(vs["checked"] + vs["unobserved"],
                         len(self.doc["phases"]["B"]["rows"]))
        self.assertGreater(vs["checked"], 0)
        self.assertEqual(vs["match"] + vs["contradict"], vs["checked"])
        self.assertGreater(vs["contradict"], 0)   # rt-fed tension is real
        self.assertIsInstance(meta["dep_merge_unblocked_rows"], list)
        self.assertTrue(meta["dep_merge_unblocked_rows"])

    def test_dep_merge_unblocked_rows_clean(self):
        by_key = {json.dumps(r["key"], sort_keys=True): r
                  for r in self.doc["phases"]["B"]["rows"]}
        for k in self.doc["meta"]["dep_merge_unblocked_rows"]:
            r = by_key[k]
            self.assertEqual(r["live_join"]["status"], "match")
            self.assertFalse(r["conflict"])

    def test_residual_rule_enforced(self):
        """any-leg contradiction -> row model_form residual and out of
        dep_merge_unblocked_rows."""
        unblocked = set(self.doc["meta"]["dep_merge_unblocked_rows"])
        for r in self.doc["phases"]["B"]["rows"]:
            contrad = (r["live_join"]["status"] == "contradiction"
                       or r["static_verdict"] == "H-34-rt-fed")
            self.assertEqual(r["model_form"] == "residual", contrad)
            if contrad:
                self.assertNotIn(json.dumps(r["key"], sort_keys=True),
                                 unblocked)

    def test_pins_present(self):
        pins = self.doc["meta"]["pins"]
        for name in ("corpus_sites.jsonl", "census_corpus.json",
                     "census_map.json", "fuzz5_live.json"):
            self.assertRegex(pins[name], r"^[0-9a-f]{32}$")

    def test_open_axis_f5_2_idx_5_ruling_excluded(self):
        """fuzz-5 ruling «ось f5=2 idx=5 не трогать»: the OPEN axis key
        never enters dep_merge_unblocked_rows; the row itself is
        ruling-excluded and carries the V-34-2 history (the fuzz-4
        observation 0x000400ff that the formula does not reproduce and
        that is absent from fuzz5_live.json)."""
        open_key = json.dumps(
            {"section": "MAIN", "op": "0x34",
             "selector": {"f5": 2, "idx": 5, "flag": 0, "lo11": 162}},
            sort_keys=True)
        unblocked = self.doc["meta"]["dep_merge_unblocked_rows"]
        self.assertNotIn(open_key, unblocked)
        self.assertIn(open_key, self.doc["meta"]["ruling_excluded_rows"])
        by_key = {json.dumps(r["key"], sort_keys=True): r
                  for r in self.doc["phases"]["B"]["rows"]}
        r = by_key[open_key]
        self.assertTrue(r["ruling_excluded"])
        self.assertIn("V-34-2", r["ruling_note"])
        self.assertIn("0x000400ff", r["ruling_note"])
        # the exclusion is a ruling, not a contradiction: the row keeps
        # its model fields but is never merge-ready
        self.assertIn(r["live_join"]["status"], ("match", "silence"))
        # guard the guard: no f5=2/idx=5/flag=0 key of ANY section may
        # appear in the unblocked list
        for k in unblocked:
            sel = json.loads(k)["selector"]
            self.assertFalse(sel["f5"] == 2 and sel["idx"] == 5
                             and sel["flag"] == 0)

    def test_no_ruling_excluded_row_is_unblocked(self):
        excluded = set(self.doc["meta"]["ruling_excluded_rows"])
        self.assertTrue(excluded)
        self.assertFalse(excluded & set(
            self.doc["meta"]["dep_merge_unblocked_rows"]))

    def test_basis_contexts_have_coordinates(self):
        for r in self.doc["phases"]["A"]["rows"]:
            if r["static_verdict"] is not None:
                self.assertTrue(r["basis"])
                for ctx in r["basis"]:
                    self.assertIn("dc_offset", ctx["site"])
                    self.assertIn("fw", ctx["site"])

    def test_rt_live_signal_adjudicated_on_merged_rows(self):
        """2026-11-01 owner ruling: a merge-candidate P-row (live match,
        no conflict) carrying a raw rt_live counter-signal below
        RT_FED_MIN must carry a complete per-row offline adjudication
        (every rt-live site classified with a reason); verdict noise
        keeps the row mergeable, anything else fails closed out of
        dep_merge_unblocked_rows."""
        unblocked = set(self.doc["meta"]["dep_merge_unblocked_rows"])
        adjudicated = set()
        for r in self.doc["phases"]["B"]["rows"]:
            rt_live = (r.get("def_use") or {}).get("rt_live", 0)
            jkey = json.dumps(r["key"], sort_keys=True)
            adj = r.get("rt_live_adjudication")
            if jkey in unblocked and rt_live:
                self.assertIsNotNone(adj, jkey)
                self.assertEqual(adj["verdict"], "noise", jkey)
                self.assertEqual(len(adj["sites"]), rt_live, jkey)
                for s in adj["sites"]:
                    self.assertEqual(s["verdict"], "noise", jkey)
                    self.assertIn("fw", s)
                    self.assertIn("dc_offset", s)
                    self.assertIn("word", s)
                    self.assertTrue(s["reason"])
                adjudicated.add(jkey)
            elif rt_live and (adj is None or adj["verdict"] != "noise"):
                self.assertNotIn(jkey, unblocked)
        self.assertEqual(len(adjudicated), 4)

    def test_rt_live_adjudication_site_evidence(self):
        """the four merged rows with a raw rt_live signal: exact site
        coordinates + a reason naming the decoded evidence.  0x4bb pins
        the corrected reasoning: rt=r3 is dead at the site (sole
        consumer before it, no post-site consumers until the re-def);
        fd4b1883 @+13 is shr r11,r10,0x3 (shamt immediate, reads only
        r10), never an r3 consumer -- the round-2 'ALU operand @+13'
        reading was false and must not return."""
        expect = {
            0x4bb: {("LX1900", "0x153c04"): (
                "dead at the site", "no post-site consumers", "csr.w")},
            0x01c: {("CX6DX", "0x666a4"): ("ret.r",)},
            0x604: {("CX6DX", "0x14abb8"): ("rt==rs",)},
            0x708: {("CX6DX", "0x28e6e0"): ("andmsk",),
                    ("CX6DX", "0xe5aac"): ("stack",)},
        }
        by_key = {r["key"]["selector"]["lo11"]: r
                  for r in self.doc["phases"]["B"]["rows"]
                  if r["key"]["section"] == "MAIN"}
        for lo11, sites in expect.items():
            r = by_key[lo11]
            adj = r["rt_live_adjudication"]
            self.assertEqual(adj["verdict"], "noise")
            got = {(s["fw"], s["dc_offset"]) for s in adj["sites"]}
            self.assertEqual(got, set(sites), hex(lo11))
            for s in adj["sites"]:
                for marker in sites[(s["fw"], s["dc_offset"])]:
                    self.assertIn(marker, s["reason"], hex(lo11))
            self.assertEqual(r["def_use"]["rt_live"], len(sites))
            if lo11 == 0x4bb:
                reason = adj["sites"][0]["reason"]
                self.assertNotIn("ALU operand", reason)
                self.assertNotIn("rs=r10/rt=r3", reason)


class TestP34RtLiveAdjudication(unittest.TestCase):
    """adjudication_for: per-row classification of the raw rt_live
    counter-signal (owner ruling 2026-11-01); fail-closed semantics."""

    @classmethod
    def setUpClass(cls):
        cls.m = load("p34_model")

    @staticmethod
    def jkey(lo11):
        sel = {"f5": lo11 & 0x1f, "idx": (lo11 >> 5) & 0x1f,
               "flag": (lo11 >> 10) & 1, "lo11": lo11}
        return json.dumps({"section": "MAIN", "op": "0x34",
                           "selector": sel}, sort_keys=True)

    def test_known_rows_are_noise(self):
        for lo11, n in ((0x4bb, 1), (0x01c, 1), (0x604, 1), (0x708, 2)):
            adj = self.m.adjudication_for(self.jkey(lo11), n)
            self.assertEqual(adj["verdict"], "noise", hex(lo11))
            self.assertEqual(len(adj["sites"]), n, hex(lo11))
            self.assertTrue(adj["note"])

    def test_unknown_row_fails_closed(self):
        adj = self.m.adjudication_for(self.jkey(0x5a5), 1)
        self.assertEqual(adj["verdict"], "unadjudicated")
        self.assertEqual(adj["sites"], [])

    def test_site_count_mismatch_is_table_drift(self):
        with self.assertRaises(SystemExit):
            self.m.adjudication_for(self.jkey(0x708), 1)


def op39(rs, rd, rt, lo11):
    return (0x39 << 26) | (rs << 21) | (rd << 16) | (rt << 11) | (lo11 & 0x7ff)


def op3c(rs, rd, rt, lo11):
    return (0x3C << 26) | (rs << 21) | (rd << 16) | (rt << 11) | (lo11 & 0x7ff)


class TestRareFormulaCore(unittest.TestCase):
    """task-7 candidate formulas on synthetic selector/operand values
    (recompute path, no live access): 0x39 lo-passthrough, 0x3c zero."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("rare_formal")

    def test_39_lo_passthrough(self):
        self.assertEqual(self.h.predict(0x39, 0x000, LIVE_SEED_RS),
                         0xA5A5F0F0)
        self.assertEqual(self.h.predict(0x39, 0x7FF, LIVE_SEED_RS),
                         0xA5A5F0F0)
        self.assertEqual(self.h.predict(0x39, 0x123, 0x89abcdef12345678),
                         0x12345678)

    def test_39_discards_hi32(self):
        self.assertEqual(self.h.predict(0x39, 0, 0xFFFFFFFF00001234),
                         0x1234)

    def test_3c_zero_any_selector_any_rs(self):
        for lo11 in (0x000, 0x100, 0x7FF):
            for rs in (0, 0x5A5A5A5AA5A5F0F0, 0xFFFFFFFFFFFFFFFF):
                self.assertEqual(self.h.predict(0x3c, lo11, rs), 0)

    def test_verdict_ids_per_op(self):
        self.assertEqual(self.h.verdict_id(0x39), "H-39-lo-consistent")
        self.assertEqual(self.h.verdict_id(0x3c), "H-3c-zero-consistent")


class TestRareDefUseSynthetic(unittest.TestCase):
    """task-7 raw def-use framework on synthetic word streams: rs
    provenance consts, rd consumer classification, and the per-op
    value-check path against the candidate formula."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("rare_formal")

    def test_39_consumer_cmpC_match(self):
        # rd gets rs_lo = 0x2468 and the FW tests rd == 0x2468
        words = [set3z(5, 0x2468), op39(5, 4, 0, 0), subsi(9, 4, 0x2468)]
        f = self.h.site_facts(0x39, words, 1)
        self.assertEqual(f["rs_prov"], "imm")
        self.assertEqual(f["consumer"], "cmpC")
        self.assertEqual(f["value_check"], "match")

    def test_39_consumer_cmpC_mismatch(self):
        words = [set3z(5, 0x2468), op39(5, 4, 0, 0), subsi(9, 4, 0x111)]
        f = self.h.site_facts(0x39, words, 1)
        self.assertEqual(f["value_check"], "mismatch")

    def test_39_consumer_ztest_adjudicates(self):
        # ands rd,0x2000: passthrough of 0x2468 has bit 13 set -> the
        # zero-test would read nonzero: contradiction of lo-passthrough
        ands_2k = (0x0B << 26) | (4 << 21) | (9 << 16) | 0x2000
        words = [set3z(5, 0x2468), op39(5, 4, 0, 0), ands_2k]
        self.assertEqual(self.h.site_facts(0x39, words, 1)["value_check"],
                         "mismatch")
        ands_8k = (0x0B << 26) | (4 << 21) | (9 << 16) | 0x8000
        words = [set3z(5, 0x2468), op39(5, 4, 0, 0), ands_8k]
        self.assertEqual(self.h.site_facts(0x39, words, 1)["value_check"],
                         "match")

    def test_39_consumer_pred0_bits(self):
        # 0x36 f5=2 predicate: passthrough of 0x2468 has low 2 bits clear
        words = [set3z(5, 0x2468), op39(5, 4, 0, 0), op36(4, 0, 0, 0x002)]
        self.assertEqual(self.h.site_facts(0x39, words, 1)["value_check"],
                         "match")
        words = [set3z(5, 0x2467), op39(5, 4, 0, 0), op36(4, 0, 0, 0x002)]
        self.assertEqual(self.h.site_facts(0x39, words, 1)["value_check"],
                         "mismatch")

    def test_3c_cmp0_on_proven_nonzero_rs_is_positive_match(self):
        # the FW zeroes a register with a known nonzero value inside and
        # tests rd == 0: positive corroboration of the zero formula
        words = [set3z(5, 0x2468), op3c(5, 4, 6, 0x100), subsi(9, 4, 0)]
        f = self.h.site_facts(0x3c, words, 1)
        self.assertEqual(f["consumer"], "cmp0")
        self.assertEqual(f["value_check"], "match")

    def test_3c_cmpC_nonzero_is_mismatch(self):
        # rd = 0 can never equal a nonzero folded constant
        words = [set3z(5, 0x2468), op3c(5, 4, 6, 0x100),
                 subsi(9, 4, 0x2468)]
        self.assertEqual(self.h.site_facts(0x3c, words, 1)["value_check"],
                         "mismatch")

    def test_3c_ztest_always_consistent(self):
        ands_rd = (0x0B << 26) | (4 << 21) | (9 << 16) | 0xFFFF
        words = [set3z(5, 0x2468), op3c(5, 4, 6, 0x7FF), ands_rd]
        f = self.h.site_facts(0x3c, words, 1)
        self.assertEqual(f["value_check"], "match")

    def test_value_check_absent_without_const_prov(self):
        words = [op39(5, 4, 0, 0), subsi(9, 4, 0x2468)]
        self.assertIsNone(self.h.site_facts(0x39, words, 0)["value_check"])
        words = [op3c(5, 4, 6, 0), subsi(9, 4, 0)]
        self.assertIsNone(self.h.site_facts(0x3c, words, 0)["value_check"])

    def test_rd_eq_rs_form_recorded(self):
        words = [op39(4, 4, 0, 0)] + [FILLER] * 12
        f = self.h.site_facts(0x39, words, 0)
        self.assertTrue(f["rd_eq_rs"])
        words = [op3c(4, 5, 6, 0x100)] + [FILLER] * 12
        f = self.h.site_facts(0x3c, words, 0)
        self.assertFalse(f["rd_eq_rs"])

    def test_consumer_read_is_carry(self):
        and_rd = (0x0A << 26) | (4 << 21) | (6 << 16) | 0xFFFF
        words = [op39(5, 4, 0, 0), and_rd]
        f = self.h.site_facts(0x39, words, 0)
        self.assertEqual(f["consumer_class"], "carry")

    def test_consumer_rd_zero_discarded(self):
        words = [op39(5, 0, 0, 0), subsi(4, 4, 0)]
        f = self.h.site_facts(0x39, words, 0)
        self.assertEqual(f["consumer"], "rd-zero")


class TestRareRowVerdict(unittest.TestCase):
    """task-7 per-row verdict from raw site facts (no live access)."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("rare_formal")

    def _fact(self, **kw):
        base = {"value_check": None, "consumer_class": "carry"}
        base.update(kw)
        return base

    def test_no_sites_silent(self):
        for op in (0x39, 0x3c):
            v = self.h.row_verdict(op, 0, [])
            self.assertIsNone(v["static_verdict"])
            self.assertFalse(v["conflict"])
            self.assertFalse(v["unique"])
            self.assertIn("reason", v)

    def test_sites_consistent(self):
        v = self.h.row_verdict(0x39, 0, [self._fact(), self._fact()])
        self.assertEqual(v["static_verdict"], "H-39-lo-consistent")
        self.assertTrue(v["unique"])
        self.assertFalse(v["conflict"])
        v = self.h.row_verdict(0x3c, 0x7FF, [self._fact()])
        self.assertEqual(v["static_verdict"], "H-3c-zero-consistent")

    def test_value_mismatch_is_conflict(self):
        v = self.h.row_verdict(0x39, 0,
                               [self._fact(), self._fact(value_check="mismatch")])
        self.assertIsNone(v["static_verdict"])
        self.assertTrue(v["conflict"])
        self.assertIn("reason", v)


class TestCmp38SelfSweepSynthetic(unittest.TestCase):
    """cmp38-self pre-sweep: linear cc0a consumer scan after an rs==rt
    cmp.w (0x38 sel=0) site; sensitivity classification + aggregate."""

    @classmethod
    def setUpClass(cls):
        cls.h = load("rare_formal")

    def test_live_branch_consumer_is_sensitive(self):
        words = [cmpw(6, 6), FILLER, bt(0x0A, 3), FILLER, FILLER, FILLER]
        st = self.h.cc0a_scan(words, 0)
        self.assertEqual(st["state"], "consumer")
        self.assertFalse(st["dead_branch"])
        rec = self.h.site_sensitivity(words, 0)
        self.assertFalse(rec["consumer_insensitive"])

    def test_noop_branch_consumer_is_insensitive(self):
        words = [cmpw(6, 6), bt(0x0A, 1), FILLER, FILLER]
        rec = self.h.site_sensitivity(words, 0)
        self.assertEqual(rec["state"], "consumer")
        self.assertTrue(rec["dead_branch"])
        self.assertTrue(rec["consumer_insensitive"])

    def test_skip_noop_consumer_is_insensitive(self):
        # b.t -> a jump back to the fall-through word
        words = [cmpw(6, 6), bt(0x0A, 2), FILLER, jump(-1), FILLER]
        rec = self.h.site_sensitivity(words, 0)
        self.assertEqual(rec["state"], "consumer")
        self.assertTrue(rec["dead_branch"])
        self.assertTrue(rec["consumer_insensitive"])

    def test_killed_by_0x36_is_insensitive(self):
        words = [cmpw(6, 6), op36(5, 0, 0, 0x002), bt(0x0A, 2), FILLER]
        rec = self.h.site_sensitivity(words, 0)
        self.assertEqual(rec["state"], "killed")
        self.assertEqual(rec["killer"], "0x36")
        self.assertTrue(rec["consumer_insensitive"])

    def test_killed_by_cmpw_sel0_is_insensitive(self):
        words = [cmpw(6, 6), cmpw(7, 8), bt(0x0A, 2), FILLER]
        rec = self.h.site_sensitivity(words, 0)
        self.assertEqual(rec["state"], "killed")
        self.assertEqual(rec["killer"], "cmp.w")
        self.assertTrue(rec["consumer_insensitive"])

    def test_038_selne0_is_not_a_cc0a_writer(self):
        # value-form op38 (rd != 0) does not touch the cc latch: the
        # scan must run past it to the real consumer
        val38 = (0x38 << 26) | (5 << 21) | (4 << 16) | (2 << 11)
        words = [cmpw(6, 6), val38, bt(0x0A, 2), FILLER, FILLER]
        rec = self.h.site_sensitivity(words, 0)
        self.assertEqual(rec["state"], "consumer")
        self.assertFalse(rec["consumer_insensitive"])

    def test_other_cc_branch_is_not_a_consumer(self):
        words = [cmpw(6, 6), bt(0x00, 2), bf(0x0A, 2), FILLER, FILLER]
        rec = self.h.site_sensitivity(words, 0)
        self.assertEqual(rec["state"], "consumer")
        self.assertEqual(rec["polarity"], "f")
        self.assertFalse(rec["consumer_insensitive"])

    def test_no_consumer_is_insensitive(self):
        words = [cmpw(6, 6), FILLER, FILLER]
        rec = self.h.site_sensitivity(words, 0)
        self.assertEqual(rec["state"], "no-consumer")
        self.assertTrue(rec["consumer_insensitive"])

    def test_aggregate_formalizable_rule(self):
        ins = {"fw": "A", "section": "MAIN", "dc_offset": "0x0",
               "consumer_insensitive": True}
        sens = {"fw": "B", "section": "MAIN", "dc_offset": "0x4",
                "consumer_insensitive": False}
        agg = self.h.sweep_aggregate([ins, ins])
        self.assertEqual(agg["rs_eq_rt_sites"], 2)
        self.assertEqual(agg["insensitive"], 2)
        self.assertTrue(agg["formalizable"])
        agg = self.h.sweep_aggregate([ins, sens])
        self.assertEqual(agg["insensitive"], 1)
        self.assertFalse(agg["formalizable"])


class TestRareArtifactSchema(unittest.TestCase):
    """committed rare_verdicts.json: unified per-row contract (0x39/0x3c),
    anti-circular phase separation, cmp38-self sweep records + aggregate,
    live join with fuzz5_live (incl. the double-live cmp38-self record)."""

    @classmethod
    def setUpClass(cls):
        p = DIR / "rare_verdicts.json"
        cls.doc = json.loads(p.read_text())
        cls.live = json.loads((DIR / "fuzz5_live.json").read_text())

    def test_phases_present(self):
        self.assertIn("A", self.doc["phases"])
        self.assertIn("B", self.doc["phases"])

    def test_phase_a_row_contract(self):
        rows = self.doc["phases"]["A"]["rows"]
        self.assertEqual(len(rows), 592)
        for r in rows[:60] + rows[-60:]:
            key = r["key"]
            self.assertIn(key["op"], ("0x39", "0x3c"))
            self.assertEqual(set(key), {"section", "op", "selector"})
            self.assertEqual(set(key["selector"]), {"lo11"})
            self.assertIsInstance(r["unique"], bool)
            self.assertIsInstance(r["conflict"], bool)
            self.assertIsInstance(r["basis"], list)
            if r["static_verdict"] is not None:
                self.assertEqual(r["static_verdict"],
                                 self.load_h().verdict_id(int(key["op"], 16)))
                self.assertEqual(r["static_source"], "raw-def-use")
            else:
                self.assertNotIn("static_source", r)
                self.assertIn("reason", r)
            self.assertIsNone(r["live_join"])
            self.assertFalse(r["merge_ready"])

    @classmethod
    def load_h(cls):
        return load("rare_formal")

    def test_universe_lossless_both_maps(self):
        rows = self.doc["phases"]["A"]["rows"]
        per_op = collections.Counter(
            (r["key"]["op"]) for r in rows)
        self.assertEqual(per_op["0x39"], 343)
        self.assertEqual(per_op["0x3c"], 249)
        self.assertEqual(self.doc["meta"]["coverage"]["census_map_only_rows"],
                         0)

    def test_phase_a_no_live_fields(self):
        text = json.dumps(self.doc["phases"]["A"]["rows"])
        for banned in ("observed", "vector_id", "live_verdict",
                       "alive_set", "unique_model", "operands"):
            self.assertNotIn(banned, text)

    def test_join_lossless_with_fuzz5_live(self):
        akeys = {json.dumps(r["key"], sort_keys=True)
                 for r in self.doc["phases"]["A"]["rows"]}
        lkeys = set()
        for k, v in self.live["rows"].items():
            if v["op"] not in ("0x39", "0x3c"):
                continue
            lkeys.add(json.dumps(
                {"section": "MAIN", "op": v["op"],
                 "selector": {"lo11": v["selector"]["lo11"]}},
                sort_keys=True))
        self.assertEqual(len(lkeys), 20)
        self.assertTrue(lkeys <= akeys)

    def test_phase_b_row_contract(self):
        rows = self.doc["phases"]["B"]["rows"]
        self.assertEqual(len(rows), len(self.doc["phases"]["A"]["rows"]))
        for r in rows:
            for field in ("static_verdict", "unique", "basis", "conflict",
                          "live_join", "merge_ready"):
                self.assertIn(field, r)
            self.assertIsInstance(r["merge_ready"], bool)
            self.assertIn(r["live_join"]["status"],
                          ("match", "contradiction", "silence"))

    def test_live_join_agrees_with_every_observation(self):
        h = self.load_h()
        by_key = {json.dumps(r["key"], sort_keys=True): r
                  for r in self.doc["phases"]["B"]["rows"]}
        checked = 0
        matched = 0
        for lk, v in self.live["rows"].items():
            if v["op"] not in ("0x39", "0x3c"):
                continue
            jkey = json.dumps({"section": "MAIN", "op": v["op"],
                               "selector": {"lo11": v["selector"]["lo11"]}},
                              sort_keys=True)
            r = by_key[jkey]
            pts = [(int(o["operands_seed"]["rs"], 16), int(o["observed"], 16))
                   for o in v["observations"]
                   if o.get("observed") is not None]
            if pts:
                checked += 1
                for rs, obs in pts:
                    self.assertEqual(
                        h.predict(int(v["op"], 16), v["selector"]["lo11"],
                                  rs), obs, lk)
                # values agree everywhere; 'match' additionally needs the
                # unique-model leg (op3c lo11=000 is live-multi -> silence)
                self.assertIn(r["live_join"]["status"],
                              ("match", "silence"), lk)
                if v.get("unique_model") == h.FORMULAS[v["op"]]["id"]:
                    self.assertEqual(r["live_join"]["status"], "match", lk)
                    matched += 1
                else:
                    self.assertEqual(r["live_join"]["status"], "silence", lk)
                    self.assertIn("no unique model", r["live_join"]["note"])
        self.assertEqual(checked, 4)
        self.assertEqual(matched, 3)

    def test_merge_ready_rows_and_advisory(self):
        rows = self.doc["phases"]["B"]["rows"]
        ready = [r for r in rows if r["merge_ready"]]
        got = {(r["key"]["op"], r["key"]["selector"]["lo11"])
               for r in ready}
        self.assertEqual(got, {("0x39", 0x0), ("0x39", 0x7FF),
                               ("0x3c", 0x7FF)})
        for r in ready:
            self.assertEqual(r["key"]["section"], "MAIN")
            self.assertIsNotNone(r["static_verdict"])
            self.assertEqual(r["live_join"]["status"], "match")
            self.assertFalse(r["conflict"])
        for r in rows:
            if r["merge_ready"]:
                self.assertIsNotNone(r["static_verdict"])
                self.assertEqual(r["live_join"]["status"], "match")
            else:
                self.assertTrue(r["static_verdict"] is None
                                or r["live_join"]["status"] != "match"
                                or r["conflict"])

    def test_no_value_mismatch_in_production_run(self):
        cov = self.doc["meta"]["coverage"]
        self.assertEqual(cov["value_mismatches"], 0)
        self.assertGreaterEqual(cov["strict_sites"], 500)
        self.assertGreaterEqual(cov["rows_with_strict_sites"], 200)

    def test_cmp38_self_sweep_records(self):
        sweep = self.doc["phases"]["A"]["cmp38_self"]
        sites = sweep["sites"]
        self.assertEqual(len(sites), 8)
        for s in sites:
            self.assertIn("fw", s)
            self.assertIn("section", s)
            self.assertIn("dc_offset", s)
            self.assertIsInstance(s["consumer_insensitive"], bool)
            self.assertIn(s["state"], ("consumer", "killed", "no-consumer"))
        strict = [s for s in sites if s["strict"]]
        self.assertEqual(len(strict), 2)
        # both strict sites are the live-branch consumer sites
        for s in strict:
            self.assertEqual(s["state"], "consumer")
            self.assertFalse(s["consumer_insensitive"])

    def test_cmp38_self_aggregate(self):
        agg = self.doc["phases"]["A"]["cmp38_self"]["aggregate"]
        self.assertEqual(agg["rs_eq_rt_sites"], 8)
        self.assertEqual(agg["insensitive"], 5)
        self.assertFalse(agg["formalizable"])
        self.assertEqual(
            agg["insensitive"] + sum(
                1 for s in self.doc["phases"]["A"]["cmp38_self"]["sites"]
                if not s["consumer_insensitive"]),
            agg["rs_eq_rt_sites"])

    def test_cmp38_self_phase_b_join_double_live(self):
        cj = self.doc["phases"]["B"]["cmp38_self"]
        self.assertTrue(cj["live_join"]["double_live"])
        self.assertEqual(len(cj["live_join"]["supports"]), 2)
        self.assertEqual(cj["live_join"]["unique_model"], "H-38self-false")
        # double-live holds but the sweep blocks: aggregate carried over
        self.assertFalse(cj["aggregate"]["formalizable"])
        self.assertFalse(cj["merge"])          # input for the T8 rule
        self.assertTrue(cj["sensitive_sites"])

    def test_pins_present(self):
        pins = self.doc["meta"]["pins"]
        for name in ("corpus_sites.jsonl", "census_corpus.json",
                     "census_map.json", "fuzz5_live.json"):
            self.assertRegex(pins[name], r"^[0-9a-f]{32}$")

    def test_verdict_rule_documented(self):
        meta = self.doc["meta"]
        self.assertIn("verdict_rule", meta)
        self.assertIn("static_rule_note", meta)
        self.assertIn("coverage", meta)
        self.assertIn("formulas", meta)


# ------------------------------------------------- task 8: merge wave A select

_DEFAULT = object()


def h36_row(f5, status, static=_DEFAULT, unique=True, conflict=False,
            unique_model="H-eq32", live_verdict="unique"):
    if static is _DEFAULT:
        static = "H-36-eq-usage"
    return {
        "key": {"section": "MAIN", "op": "0x36",
                "selector": {"f5": f5, "i6": 0, "lo11": f5}},
        "form": "reg", "static_verdict": static, "unique": unique,
        "basis": [], "conflict": conflict,
        "live_join": None if status is None else {
            "status": status, "live_verdict": live_verdict,
            "unique_model": unique_model, "n_observations": 1},
    }


def h16_row(lo11, status, merge_ready=False):
    return {
        "key": {"section": "MAIN", "op": "0x16", "selector": {"lo11": lo11}},
        "static_verdict": "H-16-shr32u0-consistent", "unique": True,
        "basis": [], "conflict": False, "merge_ready": merge_ready,
        "predicted_class": "width32-zero", "static_source": "raw-def-use",
        "live_join": None if status is None else {
            "status": status, "live_verdict": "unique",
            "unique_model": "H-16-shr32u", "n_observations": 1},
    }


def p34_row(f5, idx, flag, static=_DEFAULT, conflict=False,
            predicted=None, rt_live_adj=None):
    if static is _DEFAULT:
        static = "H-34-field-consistent"
    if predicted is None:
        predicted = {"mask": "0x00000003", "deposit": "0x00000001"}
    row = {
        "key": {"section": "MAIN", "op": "0x34",
                "selector": {"f5": f5, "idx": idx, "flag": flag,
                             "lo11": (flag << 10) | (idx << 5) | f5}},
        "static_verdict": static, "predicted": predicted, "unique": True,
        "basis": [], "conflict": conflict, "model_form": "formula",
        "live_join": None,
    }
    if rt_live_adj is not None:
        row["rt_live_adjudication"] = rt_live_adj
    return row


def live34_row(f5, idx, flag, observations):
    return {"op": "0x34", "section": "MAIN",
            "selector": {"f5": f5, "idx": idx, "flag": flag,
                         "lo11": (flag << 10) | (idx << 5) | f5},
            "observations": observations}


def obs(observed, rs):
    return {"observed": observed, "operands_seed": {"rs": rs, "rt": "0x0"},
            "source": "fixture", "vector_id": "V-FIX"}


class TestSelectMergesARules(unittest.TestCase):
    """wave A selection rules on fixtures of the actual T4-T7 row schemas."""

    @classmethod
    def setUpClass(cls):
        cls.sel = load("select_merges_a")

    def categorize(self, row, live_obs=None):
        return self.sel.categorize_row(row, live_obs)

    def test_merge_unique_live_match(self):
        cat, reason = self.categorize(h36_row(4, "match"))
        self.assertEqual(cat, "merge")
        self.assertIn("H-eq32", reason)

    def test_live_join_conflict_excluded(self):
        cat, _ = self.categorize(
            h36_row(2, "conflict", unique_model="H-V"))
        self.assertEqual(cat, "excluded.conflict")

    def test_row_conflict_flag_excluded(self):
        cat, _ = self.categorize(h36_row(6, "match", conflict=True))
        self.assertEqual(cat, "excluded.conflict")

    def test_silence_single_method(self):
        cat, _ = self.categorize(h36_row(0, "silence"))
        self.assertEqual(cat, "excluded.single_method")

    def test_null_static_with_live_is_live_only(self):
        cat, _ = self.categorize(h36_row(4, "match", static=None))
        self.assertEqual(cat, "excluded.live_only")

    def test_merge_ready_advisory_ignored(self):
        # merge_ready=True cannot force a silent row in ...
        cat, _ = self.categorize(h16_row(0x28, "silence", merge_ready=True))
        self.assertEqual(cat, "excluded.single_method")
        # ... and merge_ready=False cannot keep a qualifying row out
        cat, _ = self.categorize(h16_row(0x28, "match", merge_ready=False))
        self.assertEqual(cat, "merge")

    def test_p_model_full_obs_multi_observation(self):
        row = p34_row(8, 0x0a, 1,
                      predicted={"mask": "0x0003fc00", "deposit": "0x00003400"})
        live = live34_row(8, 0x0a, 1, [
            obs("0x00003401", "0x00000001"),
            obs("0x000037ff", "0x00000fff"),
        ])
        cat, reason = self.categorize(row, live["observations"])
        self.assertEqual(cat, "merge.p_model_full_obs")
        self.assertIn("2", reason)

    def test_p_row_empty_observations_single_method(self):
        # brief: static_verdict/predicted non-empty but observations[] EMPTY
        row = p34_row(3, 0, 0)
        cat, _ = self.categorize(row, [])
        self.assertEqual(cat, "excluded.single_method")

    def test_p_row_no_live_row_single_method(self):
        cat, _ = self.categorize(p34_row(3, 0, 0), None)
        self.assertEqual(cat, "excluded.single_method")

    def test_p_row_only_silent_observations_single_method(self):
        row = p34_row(3, 0, 0)
        cat, _ = self.categorize(row, [obs(None, "0x1")])
        self.assertEqual(cat, "excluded.single_method")

    def test_p_row_disagreeing_observation_conflict(self):
        row = p34_row(3, 0, 0,
                      predicted={"mask": "0x00000007", "deposit": "0x4"})
        live = live34_row(3, 0, 0, [
            obs("0x00000004", "0x00000000"),
            obs("0x00000009", "0x00000000"),   # disagrees with deposit 0x4
        ])
        cat, _ = self.categorize(row, live["observations"])
        self.assertEqual(cat, "excluded.conflict")

    def test_p_row_rt_fed_conflict_flag_wins(self):
        row = p34_row(4, 0, 0, static="H-34-rt-fed", conflict=True,
                      predicted={"mask": "0x0000000f", "deposit": "0xc"})
        live = live34_row(4, 0, 0, [obs("0x0000000c", "0x1")])
        cat, _ = self.categorize(row, live["observations"])
        self.assertEqual(cat, "excluded.conflict")

    def test_p_row_null_static_live_only(self):
        row = p34_row(9, 9, 9, static=None)
        live = live34_row(9, 9, 9, [obs("0x0000000c", "0x0")])
        cat, _ = self.categorize(row, live["observations"])
        self.assertEqual(cat, "excluded.live_only")

    def test_p_row_noise_adjudication_noted_in_merge_reason(self):
        # 2026-11-01 owner ruling: a merged P-row with a raw rt_live
        # counter-signal carries the per-row adjudication in its reason
        adj = {"verdict": "noise",
               "sites": [{"fw": "CX6DX", "dc_offset": "0x1", "word": "0x1",
                          "verdict": "noise", "reason": "other consumer"}],
               "note": "fixture"}
        row = p34_row(7, 3, 1, rt_live_adj=adj)
        live = live34_row(7, 3, 1, [obs("0x00000001", "0x1")])
        cat, reason = self.categorize(row, live["observations"])
        self.assertEqual(cat, "merge.p_model_full_obs")
        self.assertIn("adjudicated noise", reason)
        self.assertIn("1 site", reason)
        # ... and a plain row without the signal is untouched
        cat2, reason2 = self.categorize(p34_row(7, 3, 1),
                                        live["observations"])
        self.assertEqual(cat2, "merge.p_model_full_obs")
        self.assertNotIn("adjudicated", reason2)

    def test_exclusion_list_fires_on_open_axis(self):
        # MAIN 0x34 f5=2 idx=5 qualifies by every contract rule -- the
        # ruling must still keep it out, programmatically
        row = p34_row(2, 5, 0,
                      predicted={"mask": "0x00000060", "deposit": "0x0"})
        live = live34_row(2, 5, 0, [obs("0x00000001", "0x00000021")])
        cat, reason = self.categorize(row, live["observations"])
        self.assertEqual(cat, "excluded.ruling")
        self.assertIn("OPEN-34-f5=2-idx=5", reason)
        # the axis ruling covers both flag variants
        cat2, _ = self.categorize(p34_row(2, 5, 1), [])
        self.assertEqual(cat2, "excluded.ruling")
        # and is scoped: a different idx on f5=2 is untouched by the list
        cat3, _ = self.categorize(p34_row(2, 1, 0), [])
        self.assertEqual(cat3, "excluded.single_method")

    def test_cmp38_self_not_formalizable_is_excluded(self):
        block = {"aggregate": {"formalizable": False, "strict_sites": 2,
                               "strict_insensitive": 0},
                 "live_join": {"double_live": True}}
        cat, reason = self.sel.categorize_cmp38_self(block)
        self.assertEqual(cat, "excluded.ruling")
        self.assertIn("formalizable", reason)

    def test_cmp38_self_formalizable_fires_category(self):
        block = {"aggregate": {"formalizable": True},
                 "live_join": {"double_live": True}}
        cat, _ = self.sel.categorize_cmp38_self(block)
        self.assertEqual(cat, "merge.double_live_formalizable")

    def test_cmp38_self_single_live_not_merged(self):
        block = {"aggregate": {"formalizable": True},
                 "live_join": {"double_live": False}}
        cat, _ = self.sel.categorize_cmp38_self(block)
        self.assertEqual(cat, "excluded.single_method")


class TestSelectMergesAFixturesRun(unittest.TestCase):
    """run_selection joins fixture docs shaped like the committed artifacts."""

    @classmethod
    def setUpClass(cls):
        cls.sel = load("select_merges_a")

    @staticmethod
    def docs():
        return {
            "h36": {"phases": {"B": {"rows": [
                h36_row(4, "match"),
                h36_row(2, "conflict", unique_model="H-V"),
                h36_row(0, "silence", static=None),
            ]}}},
            "p34": {"phases": {"B": {"rows": [
                p34_row(8, 0x0a, 1, predicted={"mask": "0x0003fc00",
                                               "deposit": "0x00003400"}),
                p34_row(3, 0, 0),
                p34_row(2, 5, 0, predicted={"mask": "0x00000060",
                                           "deposit": "0x0"}),
                p34_row(9, 9, 9, static=None),
            ]}}},
            "h16": {"phases": {"B": {"rows": [
                h16_row(0x000, "match", merge_ready=True),
                h16_row(0x028, "match", merge_ready=True),
                h16_row(0x005, "silence"),
            ]}}},
            "rare": {"phases": {"B": {
                "rows": [
                    {"key": {"section": "MAIN", "op": "0x39",
                             "selector": {"lo11": 0}},
                     "static_verdict": "H-39-lo-consistent", "unique": True,
                     "basis": [], "conflict": False,
                     "live_join": {"status": "match", "live_verdict": "unique",
                                   "unique_model": "H-39-lo"}},
                    {"key": {"section": "PCI", "op": "0x39",
                             "selector": {"lo11": 1}},
                     "static_verdict": "H-39-lo-consistent", "unique": True,
                     "basis": [], "conflict": False,
                     "live_join": {"status": "silence"}},
                ],
                "cmp38_self": {"aggregate": {"formalizable": False},
                               "live_join": {"double_live": True}}}}},
            "fuzz5_live": {"rows": {
                "op34_a": live34_row(8, 0x0a, 1, [
                    obs("0x00003401", "0x00000001"),
                    obs("0x000037ff", "0x00000fff")]),
                "op34_b": live34_row(3, 0, 0, []),
                "op34_c": live34_row(2, 5, 0, [obs("0x00000001",
                                                   "0x00000021")]),
                "op34_d": live34_row(9, 9, 9, [obs("0x0000000c", "0x0")]),
            }},
        }

    def test_fixture_run_categories(self):
        rep = self.sel.run_selection(self.docs())
        by_key = {json.dumps(a["key"], sort_keys=True): a["category"]
                  for a in rep["audit"]}
        self.assertEqual(
            by_key[json.dumps({"section": "MAIN", "op": "0x36",
                               "selector": {"f5": 4, "i6": 0, "lo11": 4}},
                              sort_keys=True)], "merge")
        self.assertEqual(
            by_key[json.dumps({"section": "MAIN", "op": "0x34",
                               "selector": {"f5": 2, "idx": 5, "flag": 0,
                                            "lo11": 162}},
                              sort_keys=True)], "excluded.ruling")
        self.assertEqual(
            by_key[json.dumps({"section": "MAIN", "op": "0x38",
                               "selector": {"rs_eq_rt": True}},
                              sort_keys=True)], "excluded.ruling")
        self.assertEqual(rep["counts"]["merge.p_model_full_obs"], 1)
        self.assertEqual(rep["counts"]["excluded.ruling"], 2)
        self.assertEqual(rep["counts"]["excluded.single_method"], 4)
        self.assertEqual(rep["counts"]["excluded.live_only"], 1)
        self.assertEqual(rep["counts"]["excluded.conflict"], 1)
        self.assertEqual(rep["counts"]["merge.double_live_formalizable"], 0)
        self.assertEqual(rep["counts"]["merge"], 4)
        self.assertEqual(len(rep["audit"]), 3 + 4 + 3 + 2 + 1)


class TestSelectMergesARealArtifacts(unittest.TestCase):
    """selection over the committed T4-T7 artifacts: exact wave A outcome."""

    @classmethod
    def setUpClass(cls):
        sel = load("select_merges_a")
        docs = {
            short: json.loads((DIR / (fname + ".json")).read_text())
            for short, fname in (("h36", "h36_verdicts"),
                                 ("p34", "p34_table"),
                                 ("h16", "h16_verdicts"),
                                 ("rare", "rare_verdicts"))
        }
        docs["fuzz5_live"] = json.loads(
            (DIR / "fuzz5_live.json").read_text())
        cls.report = sel.run_selection(docs)

    def test_every_row_audited_with_valid_category(self):
        n_rows = sum(len(json.loads((DIR / f).read_text())["phases"]["B"]["rows"])
                     for f in ("h36_verdicts.json", "p34_table.json",
                               "h16_verdicts.json", "rare_verdicts.json"))
        self.assertEqual(len(self.report["audit"]), n_rows + 1)
        for a in self.report["audit"]:
            self.assertEqual(set(a), {"key", "source", "category", "reason"})
            self.assertIn(a["category"], load("select_merges_a").CATEGORIES)
            self.assertEqual(
                set(a["key"]), {"section", "op", "selector"})

    def test_exact_category_counts(self):
        self.assertEqual(self.report["counts"], {
            "merge": 8,
            "merge.p_model_full_obs": 26,
            "merge.double_live_formalizable": 0,
            "excluded.live_only": 10,
            "excluded.single_method": 1848,
            "excluded.conflict": 51,
            "excluded.ruling": 3,
        })

    def test_merged_membership(self):
        merged = {json.dumps(a["key"], sort_keys=True)
                  for a in self.report["audit"]
                  if a["category"].startswith("merge")}
        self.assertIn(json.dumps(
            {"section": "MAIN", "op": "0x36",
             "selector": {"f5": 4, "i6": 0, "lo11": 4}}, sort_keys=True),
            merged)
        for lo11 in (0x000, 0x028, 0x03c, 0x7d):
            self.assertIn(json.dumps(
                {"section": "MAIN", "op": "0x16",
                 "selector": {"lo11": lo11}}, sort_keys=True), merged)
        for op, lo11 in (("0x39", 0x000), ("0x39", 0x7ff), ("0x3c", 0x7ff)):
            self.assertIn(json.dumps(
                {"section": "MAIN", "op": op,
                 "selector": {"lo11": lo11}}, sort_keys=True), merged)
        p34 = [json.loads(k) for k in merged
               if json.loads(k)["op"] == "0x34"]
        self.assertEqual(len(p34), 26)
        for k in p34:
            self.assertNotEqual(
                (k["selector"]["f5"], k["selector"]["idx"]), (2, 5))
            self.assertNotEqual(k["selector"]["lo11"], 0x022)

    def test_multi_observation_row_merged(self):
        detail = self.report["merges"]["p34"]
        multi = [m for m in detail if m["key"]["selector"]["f5"] == 8
                 and m["key"]["selector"]["idx"] == 0x0a
                 and m["key"]["selector"]["flag"] == 1]
        self.assertEqual(len(multi), 1)
        self.assertEqual(multi[0]["n_observations"], 2)
        self.assertEqual(multi[0]["predicted"],
                         {"mask": "0x0003fc00", "deposit": "0x00003400"})

    def test_h36_conflict_axes_excluded(self):
        by_key = {json.dumps(a["key"], sort_keys=True): a
                  for a in self.report["audit"]}
        for f5 in (2, 0x0a):
            k = json.dumps({"section": "MAIN", "op": "0x36",
                            "selector": {"f5": f5, "i6": 0, "lo11": f5}},
                           sort_keys=True)
            self.assertEqual(by_key[k]["category"], "excluded.conflict")

    def test_cmp38_self_lands_excluded(self):
        ent = [a for a in self.report["audit"] if a["source"] == "cmp38_self"]
        self.assertEqual(len(ent), 1)
        self.assertEqual(ent[0]["category"], "excluded.ruling")

    def test_p34_merged_rt_live_rows_note_adjudication(self):
        """the four merged P-rows that carry a raw rt_live signal stay
        merged (adjudicated noise, 2026-11-01 owner ruling) and the
        audit reason + merges entry say so."""
        lo11s = {0x4bb, 0x01c, 0x604, 0x708}
        hits = 0
        for a in self.report["audit"]:
            sel = (a["key"].get("selector") or {})
            if a["key"]["op"] == "0x34" and a["key"]["section"] == "MAIN" \
                    and sel.get("lo11") in lo11s:
                hits += 1
                self.assertEqual(a["category"], "merge.p_model_full_obs")
                self.assertIn("adjudicated noise", a["reason"])
        self.assertEqual(hits, 4)
        merged = [m for m in self.report["merges"]["p34"]
                  if m["key"]["selector"]["lo11"] in lo11s]
        self.assertEqual(len(merged), 4)
        for m in merged:
            self.assertEqual(m["rt_live_adjudication"]["verdict"], "noise")
            self.assertEqual(m["rt_live_adjudication"]["n_sites"],
                             {0x4bb: 1, 0x01c: 1, 0x604: 1, 0x708: 2}[
                                 m["key"]["selector"]["lo11"]])

    def test_dep_merge_unblocked_is_advisory(self):
        # rows with a null static leg never merge, even when T5 listed them
        # in dep_merge_unblocked_rows
        doc = json.loads((DIR / "p34_table.json").read_text())
        unblocked = {json.dumps(json.loads(s), sort_keys=True)
                     for s in doc["meta"]["dep_merge_unblocked_rows"]}
        merged = {json.dumps(a["key"], sort_keys=True)
                  for a in self.report["audit"]
                  if a["category"] == "merge.p_model_full_obs"}
        for u in unblocked:
            row = [r for r in doc["phases"]["B"]["rows"]
                   if json.dumps(r["key"], sort_keys=True) == u][0]
            if row["static_verdict"] is None:
                self.assertNotIn(u, merged)


if __name__ == "__main__":
    unittest.main()
