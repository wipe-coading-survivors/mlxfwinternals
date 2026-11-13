import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-prov"))

import ccir_scan as cs  # noqa: E402


CRYPTO_HIT_KEYS = {"name", "offset", "order", "match"}
MUL_HIT_KEYS = {"kind", "line_no", "addr", "shifts", "loop"}


class TestCryptoTables(unittest.TestCase):
    def test_generated_tables_match_known_constants(self):
        tables = cs.build_crypto_tables()
        self.assertEqual(
            tables["sha256_k"]["be"][:16].hex(),
            "428a2f9871374491b5c0fbcfe9b5dba5")
        self.assertEqual(
            tables["sha512_k"]["be"][:16].hex(),
            "428a2f98d728ae227137449123ef65cd")
        self.assertEqual(
            tables["sha512_h"]["be"][:16].hex(),
            "6a09e667f3bcc908bb67ae8584caa73b")
        self.assertEqual(
            tables["aes_sbox"]["be"][:16].hex(),
            "637c777bf26b6fc53001672bfed7ab76")
        self.assertEqual(
            tables["aes_t0"]["be"][:16].hex(),
            "c66363a5f87c7c84ee777799f67b7b8d")
        self.assertEqual(
            tables["aes_t1"]["be"][:16].hex(),
            "a5c6636384f87c7c99ee77778df67b7b")
        self.assertEqual(
            tables["aes_t2"]["be"][:16].hex(),
            "63a5c6637c84f87c7799ee777b8df67b")
        self.assertEqual(
            tables["aes_t3"]["be"][:16].hex(),
            "6363a5c67c7c84f8777799ee7b7b8df6")
        self.assertEqual(
            tables["ghash_r"]["be"].hex(), "e1" + "00" * 15)

    def test_aes_t_tables_are_word_rotations_of_t0(self):
        tables = cs.build_crypto_tables()
        t0 = tables["aes_t0"]["be"]
        for name, rot in (("aes_t1", 1), ("aes_t2", 2), ("aes_t3", 3)):
            tb = tables[name]["be"]
            self.assertEqual(len(tb), 1024)
            for a in (0, 1, 0x53, 0xFF):
                word = t0[4 * a:4 * a + 4]
                expect = word[-rot:] + word[:-rot] if rot else word
                self.assertEqual(tb[4 * a:4 * a + 4], expect,
                                 "%s[%02x]" % (name, a))

    def test_table_sizes_and_endianness(self):
        tables = cs.build_crypto_tables()
        self.assertEqual(len(tables["sha256_k"]["be"]), 64 * 4)
        self.assertEqual(len(tables["sha512_k"]["be"]), 80 * 8)
        self.assertEqual(len(tables["sha512_h"]["be"]), 64)
        self.assertEqual(len(tables["aes_sbox"]["be"]), 256)
        for name in ("aes_t0", "aes_t1", "aes_t2", "aes_t3"):
            self.assertEqual(len(tables[name]["be"]), 1024)
        self.assertEqual(len(tables["ghash_r"]["be"]), 16)
        le = tables["sha256_k"]["le"]
        self.assertEqual(le[:4].hex(), "982f8a42")
        self.assertEqual(le[4:8].hex(), "91443771")

    def test_control_tables_are_not_crypto_discriminators(self):
        tables = cs.build_control_tables()
        self.assertEqual(
            tables["crc32_reflected"]["be"][4:8].hex(), "77073096")
        self.assertEqual(len(tables["crc32_reflected"]["be"]), 1024)
        self.assertEqual(
            tables["crc16_ccitt"]["be"][2:4].hex(), "1021")
        self.assertNotIn("sha256_k", tables)


class TestScanConstants(unittest.TestCase):
    def test_full_be_and_le_hits_report_offset(self):
        tables = cs.build_crypto_tables()
        blob = b"\xaa" * 100 + tables["sha256_k"]["be"] + b"\xbb" * 10
        hits = cs.scan_constants(blob, tables)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(set(hit), CRYPTO_HIT_KEYS)
        self.assertEqual(hit["name"], "sha256_k")
        self.assertEqual(hit["offset"], 100)
        self.assertEqual(hit["order"], "be")
        self.assertEqual(hit["match"], "full")

        blob_le = b"\x00" * 5 + tables["aes_t0"]["le"]
        hits = cs.scan_constants(blob_le, tables)
        self.assertEqual(hits[0]["name"], "aes_t0")
        self.assertEqual(hits[0]["order"], "le")
        self.assertEqual(hits[0]["offset"], 5)

    def test_prefix_hit_when_table_truncated(self):
        tables = cs.build_crypto_tables()
        blob = tables["sha512_h"]["be"][:16] + b"\xff" * 32
        hits = cs.scan_constants(blob, tables)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["match"], "prefix")
        self.assertEqual(hits[0]["offset"], 0)

    def test_random_data_yields_no_hits(self):
        tables = cs.build_crypto_tables()
        blob = bytes(range(256)) * 8
        self.assertEqual(cs.scan_constants(blob, tables), [])


# Unrolled shift-add product: x*(2^3 + 2^1) = x*10 — both shifted
# copies of r5 are consumed as addends.
MUL_BY_10 = [
    "30005000  fd043081  shl64.i r4,r5,0x3",
    "30005004  fca62081  shl64.i r6,r5,0x1",
    "30005008  fc873000  add r7,r4,r6",
]

# Bit-serial 32x32 loop: product shift-left-1 of itself, multiplier
# shift-right-1 of itself, backward branch closes the loop.
MUL_BITSERIAL = [
    "30006000  fd041081  shl64.i r4,r4,0x1",
    "30006004  fc851883  shr r5,r5,0x1",
    "30006008  a400fff8  b.f.0x0 zero,0x30006000",
]

# Same body closed by two backward branches (inner + outer): one
# physical bit-serial cycle must be reported once, not twice.
NESTED_BITSERIAL = [
    "30006000  fd041081  shl64.i r4,r4,0x1",
    "30006004  fc851883  shr r5,r5,0x1",
    "30006008  a400fff8  b.f.0x0 zero,0x30006000",
    "3000600c  a400fff4  b.f.0x0 zero,0x30006000",
]

# Two disjoint bit-serial loops: both are real physical cycles.
TWO_BITSERIAL_LOOPS = [
    "30006000  fd041081  shl64.i r4,r4,0x1",
    "30006004  fc851883  shr r5,r5,0x1",
    "30006008  a400fff8  b.f.0x0 zero,0x30006000",
    "3000600c  fd041081  shl64.i r4,r4,0x1",
    "30006010  fc851883  shr r5,r5,0x1",
    "30006014  a400fff4  b.f.0x0 zero,0x3000600c",
]

# Source register r5 is redefined BETWEEN the two shifts: the addends
# are shifts of DIFFERENT values — must not merge into mul_shiftadd.
SRC_REDEFINED_BETWEEN_SHIFTS = [
    "3000c000  fd043081  shl64.i r4,r5,0x3",
    "3000c004  2405009d  set2 r5,zero,0x9d",
    "3000c008  fca62081  shl64.i r6,r5,0x1",
    "3000c00c  fc873000  add r7,r4,r6",
]

# Source register r5 is redefined AFTER the first shifted copy was
# consumed: the pending group must be dropped, not extended by the
# second-generation shift.
SRC_REDEFINED_AFTER_FIRST_ADD = [
    "3000d000  fd043081  shl64.i r4,r5,0x3",
    "3000d004  fc883000  add r8,r4,r22",
    "3000d008  2405009d  set2 r5,zero,0x9d",
    "3000d00c  fca62081  shl64.i r6,r5,0x1",
    "3000d010  fc873000  add r7,r6,r22",
]

# Single structural shift consumed by one add — the lane/struct idiom,
# must NOT be reported as multiplication.
LANE_STRUCT_IDIOM = [
    "30007000  fd043081  shl64.i r4,r5,0xd",
    "30007004  2416009d  set2 r22,zero,0x9d",
    "30007008  fd079000  add r7,r4,r22",
]

DOUBLING = [
    "30008000  fc843000  add r4,r5,r5",
    "30008004  fc863000  add r6,r4,r4",
]

FORWARD_ONLY = [
    "30009000  fd043081  shl64.i r4,r5,0x3",
    "30009004  fca62081  shl64.i r6,r5,0x1",
    "30009008  fc873000  add r7,r4,r6",
    "3000900c  a4000020  b.f.0x0 zero,0x3000902c",
]

# Same shifts but never consumed by an add: no hit.
SHIFT_NO_ADD = [
    "3000a000  fd043081  shl64.i r4,r5,0x3",
    "3000a004  fca62081  shl64.i r6,r5,0x1",
    "3000a008  24030001  set2 r3,zero,0x1",
]

NOISE = [
    "3000b000  deadbeef  raw 0xdeadbeef",
    "",
]


class TestScanMulCycles(unittest.TestCase):
    def test_unrolled_shiftadd_product(self):
        hits = cs.scan_mul_cycles(MUL_BY_10)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(set(hit), MUL_HIT_KEYS)
        self.assertEqual(hit["kind"], "mul_shiftadd")
        self.assertEqual(hit["shifts"], [1, 3])
        self.assertFalse(hit["loop"])
        self.assertEqual(hit["addr"], 0x30005008)

    def test_bitserial_loop_inside_backward_branch(self):
        hits = cs.scan_mul_cycles(MUL_BITSERIAL)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["kind"], "mul_bitserial")
        self.assertTrue(hits[0]["loop"])
        self.assertEqual(hits[0]["shifts"], [1])

    def test_nested_bitserial_branches_reported_once(self):
        hits = cs.scan_mul_cycles(NESTED_BITSERIAL)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["kind"], "mul_bitserial")
        self.assertEqual(hits[0]["addr"], 0x3000600c)

    def test_disjoint_bitserial_loops_both_reported(self):
        hits = cs.scan_mul_cycles(TWO_BITSERIAL_LOOPS)
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(h["kind"] == "mul_bitserial" for h in hits))
        self.assertEqual([h["addr"] for h in hits],
                         [0x30006008, 0x30006014])

    def test_src_register_redefined_between_shifts_is_not_mul(self):
        self.assertEqual(
            cs.scan_mul_cycles(SRC_REDEFINED_BETWEEN_SHIFTS), [])

    def test_src_register_redefined_after_first_add_is_not_mul(self):
        self.assertEqual(
            cs.scan_mul_cycles(SRC_REDEFINED_AFTER_FIRST_ADD), [])

    def test_structural_shift_is_not_mul(self):
        self.assertEqual(cs.scan_mul_cycles(LANE_STRUCT_IDIOM), [])
        self.assertEqual(cs.scan_mul_cycles(SHIFT_NO_ADD), [])

    def test_doubling_chain(self):
        hits = cs.scan_mul_cycles(DOUBLING)
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(h["kind"] == "mul_doubling"
                            for h in hits))

    def test_forward_branch_is_not_a_loop(self):
        hits = cs.scan_mul_cycles(FORWARD_ONLY)
        self.assertEqual(len(hits), 1)
        self.assertFalse(hits[0]["loop"])

    def test_noise_lines_are_skipped(self):
        hits = cs.scan_mul_cycles(NOISE + MUL_BY_10 + NOISE)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["addr"], 0x30005008)


class TestLaneReuse(unittest.TestCase):
    def test_delegates_to_lane_scan_patterns(self):
        golden = [
            "007862ec  62e40000  ld.b r4,r23,0x0",
            "007862f0  fc846881  shl64.i r4,r4,0xd",
            "007862f4  2405009d  set2 r5,zero,0x9d",
            "007862f8  20a68ec0  set3 r6,r5,0x8ec0",
            "007862fc  fc863000  add r6,r4,r6",
            "0078631c  fcc51883  shr r5,r6,0x3",
            "00786320  6ca02002  st.d r4,r5,0x0",
        ]
        out = cs.scan_lane_section(golden, family="cx5")
        self.assertEqual(out["counts"].get("regfile_cluster"), 1)
        self.assertEqual(out["counts"].get("shl_stride"), 1)
        self.assertEqual(len(out["hits"]), 2)


class TestReadableStrings(unittest.TestCase):
    def test_filters_noise_and_maps_to_function(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "strings.txt").write_text(
                "dc\tstring\n"
                "0x30007558\tNvidia ztr_rttcc v0.12\n"
                "0x30007570\tBW_G, bandwidth in gbits/s\n"
                "0x300042e4\tl p~l xzl \n")
            (root / "funcs.tsv").write_text(
                "entry_dc\tend_dc\tsize_words\tframe\tn_callers\n"
                "0x30007400\t0x30007560\t96\t0\t1\n")
            out = cs.readable_strings(root / "strings.txt",
                                      funcs=root / "funcs.tsv")
            texts = [s["text"] for s in out]
            self.assertIn("Nvidia ztr_rttcc v0.12", texts)
            self.assertIn("BW_G, bandwidth in gbits/s", texts)
            self.assertNotIn("l p~l xzl ", texts)
            by_text = {s["text"]: s for s in out}
            self.assertEqual(by_text["Nvidia ztr_rttcc v0.12"]["function"],
                             "0x30007400")
            self.assertEqual(
                by_text["BW_G, bandwidth in gbits/s"]["region"], "tail")


class TestSectionCallgraph(unittest.TestCase):
    def _image(self, root):
        sec = root / "cx6dx" / "22_50_1002" / "TEST" / "sections"
        sec0d = sec / "0D"
        sec0d.mkdir(parents=True)
        (sec0d / "calls.tsv").write_text(
            "site_dc\ttarget_dc\ttarget_section\n"
            "0x2000008c\t0x20000214\t0D\n"
            "0x20000114\t0x21000020\t-\n")
        (sec0d / "funcs.tsv").write_text(
            "entry_dc\tend_dc\tsize_words\tframe\tn_callers\n"
            "0x20000000\t0x2000001c\t8\t0\t1\n"
            "0x20000d84\t0x20000d90\t4\t1\t0\n")
        (sec0d / "meta.json").write_text(json.dumps(
            {"param0": 536870912, "param1": 536874372}))
        sec03 = sec / "03"
        sec03.mkdir()
        (sec03 / "calls.tsv").write_text(
            "site_dc\ttarget_dc\ttarget_section\n"
            "0x2100abcd\t0x20000000\t0D\n")
        sec15 = sec / "15"
        sec15.mkdir()
        (sec15 / "calls.tsv").write_text(
            "site_dc\ttarget_dc\ttarget_section\n"
            "0x10c44\t0x23bc0\t15\n")
        return sec

    def test_callgraph_edges_and_entry(self):
        with tempfile.TemporaryDirectory() as td:
            sections = self._image(Path(td))
            out = cs.section_callgraph(sections, "0D")
            self.assertEqual(out["n_funcs"], 2)
            self.assertEqual(out["internal_edges"], 1)
            self.assertEqual(len(out["outgoing_external"]), 1)
            self.assertEqual(out["outgoing_external"][0]["target"],
                             "0x21000020")
            self.assertEqual(len(out["incoming_external"]), 1)
            self.assertEqual(out["incoming_external"][0]["from_section"],
                             "03")
            self.assertEqual(out["entries_no_callers"], ["0x20000d84"])
            self.assertEqual(out["param1_entry"], "0x20000d84")


class TestCLI(unittest.TestCase):
    def test_end_to_end_over_mini_corpus(self):
        tables = cs.build_crypto_tables()
        ctl_tables = cs.build_control_tables()
        ztr = b"Nvidia ztr_rttcc v0.12\x00"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sec = root / "corpus" / "cx6dx" / "22_50_1002" / "TEST" \
                / "sections"
            sec0e = sec / "0E"
            sec0e.mkdir(parents=True)
            (sec0e / "dc.bin").write_bytes(
                b"\x11" * 32 + tables["sha256_k"]["be"] + ztr
                + b"\x22" * 16)
            (sec0e / "raw.bin").write_bytes(b"\x11" * 8)
            (sec0e / "disasm.txt").write_text(
                "\n".join(MUL_BY_10 + NOISE) + "\n")
            (sec0e / "funcs.tsv").write_text(
                "entry_dc\tend_dc\tsize_words\tframe\tn_callers\n"
                "0x30005000\t0x3000500c\t3\t0\t0\n")
            (sec0e / "calls.tsv").write_text(
                "site_dc\ttarget_dc\ttarget_section\n"
                "0x30005004\t0x30005000\t0E\n")
            (sec0e / "strings.txt").write_text(
                "dc\tstring\n0x30000030\tNvidia ztr_rttcc v0.12\n")
            (sec0e / "meta.json").write_text(json.dumps(
                {"param0": 805322752, "param1": 805330324}))
            sec0d = sec / "0D"
            sec0d.mkdir()
            (sec0d / "dc.bin").write_bytes(
                ctl_tables["crc32_reflected"]["be"][:1024])
            (sec0d / "disasm.txt").write_text(
                "\n".join(LANE_STRUCT_IDIOM) + "\n")
            (sec0d / "funcs.tsv").write_text(
                "entry_dc\tend_dc\tsize_words\tframe\tn_callers\n"
                "0x20000000\t0x20000020\t8\t0\t1\n")
            (sec0d / "calls.tsv").write_text(
                "site_dc\ttarget_dc\ttarget_section\n")
            (sec0d / "strings.txt").write_text("dc\tstring\n")
            (sec0d / "meta.json").write_text(json.dumps(
                {"param0": 536870912, "param1": 536874372}))
            ctl = root / "ctl" / "cx6" / "20_43_1014" / "NIC" / "sections" \
                / "02"
            ctl.mkdir(parents=True)
            (ctl / "dc.bin").write_bytes(b"\x33" * 64)
            (ctl / "raw.bin").write_bytes(b"\x33" * 64)
            whole = root / "img.bin"
            whole.write_bytes(b"\x00" * 4096)
            out = root / "ccir-battery.json"
            rc = cs.main([
                "--corpus", str(root / "corpus"),
                "--image", "cx6dx/22_50_1002/TEST",
                "--sections", "0x0d,0x0e",
                "--whole-image", str(whole),
                "--markers", "ztr_rttcc",
                "--control", "cx6/20_43_1014/NIC:" + str(root / "ctl"),
                "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["schema"], 1)
            self.assertEqual(data["target"]["label"],
                             "cx6dx/22_50_1002/TEST")
            crypto_0e = data["target"]["sections"]["0E"]["crypto_hits"]
            self.assertEqual(len(crypto_0e), 1)
            self.assertEqual(crypto_0e[0]["name"], "sha256_k")
            self.assertEqual(crypto_0e[0]["offset"], 32)
            self.assertEqual(
                data["target"]["sections"]["0E"]["mul_hits"][0]["kind"],
                "mul_shiftadd")
            self.assertEqual(
                data["target"]["sections"]["0E"]["marker_hits"],
                [{"marker": "ztr_rttcc", "where": "strings.txt"}])
            self.assertEqual(
                data["target"]["sections"]["0D"]["control_hits"][0]
                ["name"], "crc32_reflected")
            self.assertEqual(
                data["whole_image"]["crypto_hits"], [])
            ctl_rec = data["controls"][0]
            self.assertEqual(ctl_rec["label"], "cx6/20_43_1014/NIC")
            self.assertEqual(ctl_rec["crypto_hits"], [])
            self.assertEqual(ctl_rec["marker_hits"], [])


if __name__ == "__main__":
    unittest.main()
