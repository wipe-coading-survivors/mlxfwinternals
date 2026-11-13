import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-prov"))

import lane_scan  # noqa: E402


# Verbatim from build/corpus/cx5/16_35_1012/MCX516A-CDA/sections/04/
# disasm.txt dc 0x7862ec..0x786320 (doc 130 §10 Gen4-EQ per-lane idiom).
GOLDEN_CX5_IDIOM = [
    "007862ec  62e40000  ld.b r4,r23,0x0",
    "007862f0  fc846881  shl64.i r4,r4,0xd",
    "007862f4  2405009d  set2 r5,zero,0x9d",
    "007862f8  20a68ec0  set3 r6,r5,0x8ec0",
    "007862fc  fc863000  add r6,r4,r6",
    "00786300  20a58edb  set3 r5,r5,0x8edb",
    "00786304  fc842800  add r4,r4,r5",
    "00786308  0005ffff  addi r5,zero,0x-1",
    "0078630c  fc84280e  xor r4,r4,r5",
    "00786310  2c84001f  ands r4,r4,0x1f",
    "00786314  00160001  addi r22,zero,0x1",
    "00786318  fec42080  shl64.r r4,r22,r4",
    "0078631c  fcc51883  shr r5,r6,0x3",
    "00786320  6ca02002  st.d r4,r5,0x0",
]

# LX homolog, minimal reconstruction of the dc 0x781330..0x7813a8 idiom
# (cx4lx/14_32_1900 0x04): lane-shifted SerDes addr on base 0x8c0000.
GOLDEN_LX_IDIOM = [
    "00790000  fd071881  shl64.i r7,r5,0xf",
    "00790004  2416008c  set2 r22,zero,0x8c",
    "00790008  21560000  set3 r22,r22,0x0",
    "0079000c  fd079000  add r7,r7,r22",
    "00790010  fce81883  shr r8,r7,0x3",
    "00790014  6d002802  st.d r5,r8,0x0",
]

# Verbatim from cx4lx/14_32_1900 0x04 dc 0x781304..0x78130c: count-up
# loop with lane-count bound 8 and backward branch.
GOLDEN_LOOP = [
    "00781304  00840001  addi r4,r4,0x1",
    "00781308  14870008  subsi r7,r4,0x8",
    "0078130c  a400fff4  b.f.0x0 zero,0x7812dc",
]

# Verbatim from cx4lx/14_32_1900 0x04 dc 0x7813d0..0x7813dc: per-lane
# table read via lw.r (group index <<4, word offset <<2).
GOLDEN_ROLE_TABLE = [
    "007813d0  fcc62081  shl64.i r6,r6,0x4",
    "007813d4  fe663000  add r6,r19,r6",
    "007813d8  fca51081  shl64.i r5,r5,0x2",
    "007813dc  fcc52a19  lw.r r5,r6,r5",
]

NOISE_LINES = [
    "00786400  deadbeef  raw 0xdeadbeef",
    "garbage shl64.i r4,r4,0xd",
    "",
]

# Re-materialization idiom (slaspec set2/set3 replace the target half:
# set2 = (RS & 0x0000ffff) | imm<<16, set3 = (RS & 0xffff0000) | imm).
# Buggy OR tracking would yield 0x12345678 | 0x9ab00000 = 0x9ab45678,
# outside the exact-point range below -> no regfile_cluster hit.
GOLDEN_REMAT = [
    "00710000  24051234  set2 r5,zero,0x1234",
    "00710004  20a55678  set3 r5,r5,0x5678",
    "00710008  24059ab0  set2 r5,r5,0x9ab0",
    "0071000c  6c402802  st.d r4,r5,0x0",
]

HIT_KEYS = {"kind", "line_no", "addr", "stride", "lineage"}


def by_kind(hits, kind):
    return [h for h in hits if h["kind"] == kind]


class TestGoldenIdioms(unittest.TestCase):
    def test_cx5_idiom_shl_stride_and_regfile_cluster(self):
        hits = lane_scan.scan_lane_patterns(GOLDEN_CX5_IDIOM)
        shl = by_kind(hits, "shl_stride")
        self.assertEqual(len(shl), 1)
        self.assertEqual(shl[0]["stride"], 13)
        self.assertEqual(shl[0]["addr"], 0x7862f0)
        self.assertEqual(shl[0]["line_no"], 2)
        rfc = by_kind(hits, "regfile_cluster")
        self.assertEqual(len(rfc), 1)
        self.assertEqual(rfc[0]["addr"], 0x9d8ec0)
        self.assertEqual(rfc[0]["stride"], 13)
        self.assertEqual(rfc[0]["line_no"], 14)

    def test_lx_homolog_base_0x8c0000(self):
        hits = lane_scan.scan_lane_patterns(GOLDEN_LX_IDIOM)
        rfc = by_kind(hits, "regfile_cluster")
        self.assertEqual(len(rfc), 1)
        self.assertEqual(rfc[0]["addr"], 0x8c0000)
        self.assertEqual(rfc[0]["stride"], 15)
        self.assertEqual(len(by_kind(hits, "shl_stride")), 1)

    def test_bit_select_base_0x9d8edb_is_not_a_store_cluster(self):
        hits = lane_scan.scan_lane_patterns(GOLDEN_CX5_IDIOM)
        addrs = {h["addr"] for h in by_kind(hits, "regfile_cluster")}
        self.assertNotIn(0x9d8edb, addrs)

    def test_every_hit_has_exact_schema_and_lineage_key(self):
        for lines in (GOLDEN_CX5_IDIOM, GOLDEN_LX_IDIOM,
                      GOLDEN_LOOP, GOLDEN_ROLE_TABLE):
            for hit in lane_scan.scan_lane_patterns(lines):
                self.assertEqual(set(hit), HIT_KEYS)
                self.assertIn(hit["kind"], lane_scan.KINDS)

    def test_lineage_default_none_and_stamped(self):
        hits = lane_scan.scan_lane_patterns(GOLDEN_CX5_IDIOM)
        self.assertTrue(all(h["lineage"] is None for h in hits))
        stamped = lane_scan.scan_lane_patterns(
            GOLDEN_CX5_IDIOM, lineage="witness")
        self.assertTrue(stamped)
        self.assertTrue(all(h["lineage"] == "witness" for h in stamped))

    def test_set_rematerialization_replaces_half(self):
        hits = lane_scan.scan_lane_patterns(
            GOLDEN_REMAT, serdes_ranges=[(0x9ab05678, 0x9ab05678)])
        rfc = by_kind(hits, "regfile_cluster")
        self.assertEqual([h["addr"] for h in rfc], [0x9ab05678])
        self.assertEqual(rfc[0]["line_no"], 4)
        self.assertIsNone(rfc[0]["stride"])


class TestDataNoiseGuard(unittest.TestCase):
    def test_raw_hex_and_garbage_yield_no_hits(self):
        stats = {}
        hits = lane_scan.scan_lane_patterns(
            NOISE_LINES + GOLDEN_CX5_IDIOM + NOISE_LINES, stats=stats)
        self.assertEqual(len(by_kind(hits, "shl_stride")), 1)
        self.assertEqual(stats["skipped"], 6)

    def test_noise_inside_window_does_not_create_hits(self):
        stats = {}
        interleaved = (GOLDEN_CX5_IDIOM[:4] + NOISE_LINES
                       + GOLDEN_CX5_IDIOM[4:])
        hits = lane_scan.scan_lane_patterns(interleaved, stats=stats)
        rfc = by_kind(hits, "regfile_cluster")
        self.assertEqual(len(rfc), 1)
        self.assertEqual(rfc[0]["addr"], 0x9d8ec0)
        self.assertEqual(stats["skipped"], 3)


class TestLoopLaneCount(unittest.TestCase):
    def test_compare_style_bound_with_backedge(self):
        hits = lane_scan.scan_lane_patterns(GOLDEN_LOOP)
        loops = by_kind(hits, "loop_lanecount")
        self.assertEqual(len(loops), 1)
        self.assertEqual(loops[0]["stride"], 8)
        self.assertEqual(loops[0]["addr"], 0x781308)

    def test_forward_branch_is_not_a_loop(self):
        lines = [
            "00781308  14870008  subsi r7,r4,0x8",
            "0078130c  a4000040  b.f.0x0 zero,0x781348",
        ]
        self.assertEqual(lane_scan.scan_lane_patterns(lines), [])

    def test_non_lane_bound_not_reported(self):
        lines = [
            "00781308  14870037  subsi r7,r4,0x37",
            "0078130c  a400fff4  b.f.0x0 zero,0x7812dc",
        ]
        self.assertEqual(lane_scan.scan_lane_patterns(lines), [])


class TestRoleTable(unittest.TestCase):
    def test_lw_r_indexed_by_shifted_lane_register(self):
        hits = lane_scan.scan_lane_patterns(GOLDEN_ROLE_TABLE)
        rt = by_kind(hits, "role_table")
        self.assertEqual(len(rt), 1)
        self.assertEqual(rt[0]["stride"], 2)
        self.assertEqual(rt[0]["addr"], 0x7813dc)
        self.assertEqual(rt[0]["line_no"], 4)

    def test_plain_load_without_shift_is_not_role_table(self):
        lines = ["007813dc  fcc52a19  lw.r r5,r6,r5"]
        self.assertEqual(lane_scan.scan_lane_patterns(lines), [])


class TestRangeParameterization(unittest.TestCase):
    def test_empty_ranges_disable_regfile_clusters(self):
        hits = lane_scan.scan_lane_patterns(
            GOLDEN_CX5_IDIOM, serdes_ranges=[])
        self.assertEqual(by_kind(hits, "regfile_cluster"), [])
        self.assertEqual(by_kind(hits, "shl_stride"), [])

    def test_narrow_range_selects_only_matching_base(self):
        ranges = [(0x8c0000, 0x8fffff)]
        self.assertEqual(
            lane_scan.scan_lane_patterns(
                GOLDEN_CX5_IDIOM, serdes_ranges=ranges),
            [])
        hits = lane_scan.scan_lane_patterns(
            GOLDEN_LX_IDIOM, serdes_ranges=ranges)
        self.assertEqual(len(by_kind(hits, "regfile_cluster")), 1)

    def test_non_serdes_stride_addr_is_role_table_not_regfile(self):
        lines = [
            "00790000  fd071881  shl64.i r7,r5,0xf",
            "00790004  24160011  set2 r22,zero,0x11",
            "00790008  21560000  set3 r22,r22,0x0",
            "0079000c  fd079000  add r7,r7,r22",
            "00790014  6d002802  st.d r5,r7,0x0",
        ]
        hits = lane_scan.scan_lane_patterns(lines)
        self.assertEqual(by_kind(hits, "regfile_cluster"), [])
        self.assertEqual(by_kind(hits, "shl_stride"), [])
        rt = by_kind(hits, "role_table")
        self.assertEqual(len(rt), 1)
        self.assertEqual(rt[0]["stride"], 15)

    def test_hw_block_const_outside_ranges_is_not_role_table(self):
        lines = [
            "00790000  fd071881  shl64.i r7,r5,0xf",
            "00790004  24161234  set2 r22,zero,0x1234",
            "00790008  21560000  set3 r22,r22,0x0",
            "0079000c  fd079000  add r7,r7,r22",
            "00790014  6d002802  st.d r5,r7,0x0",
        ]
        self.assertEqual(lane_scan.scan_lane_patterns(lines), [])

    def test_family_presets_cover_doc130_blocks(self):
        lx = lane_scan.serdes_blocks("cx4lx")
        cx5 = lane_scan.serdes_blocks("cx5")
        self.assertIn((0x8c0000, 0x8cffff), lx)
        self.assertIn((0x8e0000, 0x8effff), lx)
        self.assertIn((0x8f0000, 0x8fffff), lx)
        for hi in (0x90, 0x93, 0x98, 0x9a, 0x9b, 0x9c, 0x9d, 0x9f):
            self.assertIn((hi << 16, (hi << 16) | 0xffff), cx5)
        self.assertIn((0x9d8000, 0x9d8fff), cx5)  # Gen4-EQ anchor
        self.assertEqual(lane_scan.serdes_blocks("cx4"), lx)


class TestStats(unittest.TestCase):
    def test_stats_counts_lines_parsed_skipped(self):
        stats = {}
        lane_scan.scan_lane_patterns(NOISE_LINES + GOLDEN_LOOP, stats=stats)
        self.assertEqual(stats["lines"], 6)
        self.assertEqual(stats["parsed"], 3)
        self.assertEqual(stats["skipped"], 3)


# Verbatim core of the cx4lx dc 0x781364..0x7813a8 idiom: dual lane shift
# into a SerDes base, align-mask `and`, CR 0x28 strobe, store.
GOLDEN_LX_DUALSHIFT = [
    "0078131c  240a008c  set2 r10,zero,0x8c",
    "00781330  fd114881  shl64.i r17,r8,0x9",
    "00781328  240e1fff  set2 r14,zero,0x1fff",
    "0078132c  208efffc  set3 r14,r14,0xfffc",
    "0078134c  2c850003  ands r5,r4,0x3",
    "00781350  fc861083  shr r6,r4,0x2",
    "00781364  fca76081  shl64.i r7,r5,0xc",
    "00781368  fcc87881  shl64.i r8,r6,0xf",
    "0078136c  fd073800  add r7,r8,r7",
    "00781370  fce78800  add r7,r7,r17",
    "00781374  21480ddf  set3 r8,r10,0xddf",
    "00781378  fce74000  add r7,r7,r8",
    "0078137c  fce81883  shr r8,r7,0x3",
    "00781380  fd08700a  and r8,r8,r14",
    "007813a4  4cc00028  csr.w r6,zero,0x28",
    "007813a8  6d002802  st.d r5,r8,0x0",
]


class TestLxDualShiftIdiom(unittest.TestCase):
    def test_and_mask_preserves_serdes_addr(self):
        hits = lane_scan.scan_lane_patterns(
            GOLDEN_LX_DUALSHIFT, serdes_ranges=lane_scan.serdes_blocks("cx4lx"))
        rfc = by_kind(hits, "regfile_cluster")
        self.assertEqual(len(rfc), 1)
        self.assertEqual(rfc[0]["addr"], 0x8c0ddf)
        self.assertEqual(rfc[0]["stride"], 15)
        strides = sorted(h["stride"] for h in by_kind(hits, "shl_stride"))
        self.assertEqual(strides, [9, 12, 15])


class TestCLI(unittest.TestCase):
    def test_end_to_end_over_mini_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sec = root / "cx5" / "16_35_1012" / "MCX516A-CDA" / "sections" / "04"
            sec.mkdir(parents=True)
            (sec / "disasm.txt").write_text(
                "\n".join(GOLDEN_CX5_IDIOM + NOISE_LINES) + "\n")
            (sec / "funcs.tsv").write_text(
                "entry_dc\tend_dc\tsize_words\tframe\tn_callers\n"
                "0x786000\t0x786400\t256\t1\t2\n")
            missing = root / "cx5" / "16_35_1012" / "MCX516A-CDA" / "sections" / "02"
            missing.mkdir(parents=True)
            out = root / "lane-hits.json"
            rc = lane_scan.main([
                "--corpus", str(root),
                "--sections", "0x02,0x04",
                "--lineage", "cx5/16_35_1012/MCX516A-CDA=trio",
                "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["schema"], 1)
            img = data["images"][0]
            self.assertEqual(img["label"], "cx5/16_35_1012/MCX516A-CDA")
            self.assertEqual(img["lineage"], "trio")
            self.assertEqual(img["sections"]["02"]["disasm"], "absent")
            self.assertEqual(img["sections"]["04"]["hits"],
                             {"shl_stride": 1, "regfile_cluster": 1})
            self.assertEqual(img["sections"]["04"]["skipped"], 3)
            self.assertEqual(len(img["clusters"]), 1)
            self.assertEqual(img["clusters"][0]["addr"], "0x9d8ec0")
            self.assertEqual(img["clusters"][0]["functions"], ["0x786000"])
            self.assertTrue(data["hits"])
            for hit in data["hits"]:
                self.assertEqual(hit["lineage"], "trio")
                self.assertEqual(set(hit) - HIT_KEYS,
                                 {"image", "section"})


if __name__ == "__main__":
    unittest.main()
