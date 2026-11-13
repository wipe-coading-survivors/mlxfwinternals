"""Tests for scripts/probes/rate_param_trace.py (rate-knob task 3).

Synthetic-data tests for the same-silicon SKU-pair section diff with
known-field classification, the GC-3 rate scan (GT/s + MHz scales with
context bytes), the window-slot 6-bit field geometry decoder and the
schedule-domain run reader; plus CLI smoke runs.
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import rate_param_trace as rpt  # noqa: E402


class TestDiffSections(unittest.TestCase):
    def test_diff_lists_exactly_differing_bytes(self):
        a = bytes.fromhex("0011223344")
        b = bytes.fromhex("0012a23344")
        self.assertEqual(rpt.diff_sections(a, b),
                         [(1, 0x11, 0x12), (2, 0x22, 0xA2)])
        self.assertEqual(rpt.diff_sections(a, a), [])

    def test_diff_truncates_to_common_length(self):
        a = bytes(8)
        b = bytes(4) + b"\xff"
        self.assertEqual(rpt.diff_sections(a, b), [(4, 0x00, 0xFF)])


class TestClassify(unittest.TestCase):
    def test_known_fields(self):
        self.assertIn("max_speed", rpt.classify(0x08, 0x23))
        self.assertIn("count-pair", rpt.classify(0x08, 0x12A))
        self.assertIn("tuning", rpt.classify(0x09, 0x86C))
        self.assertIn("tuning", rpt.classify(0x09, 0x86F))
        self.assertIn("cap_index", rpt.classify(0x11, 0x93))
        self.assertIn("device_id", rpt.classify(0x11, 0x2D))
        self.assertIn("x16", rpt.classify(0x11, 0x47))

    def test_unknown_offset(self):
        self.assertEqual(rpt.classify(0x08, 0x55), rpt.UNKNOWN)


class TestRateScan(unittest.TestCase):
    def test_gts_be16_hit(self):
        blob = bytes.fromhex("00003e80")
        hits = rpt.rate_scan(blob)
        # overlapping BE32 (offset 0) + BE16 (offset 2) hits, by design
        self.assertEqual([h[:4] for h in hits],
                         [(0, "BE32", 16000, "16000GT/s"),
                          (2, "BE16", 16000, "16000GT/s")])

    def test_gts_le16_hit(self):
        blob = bytes.fromhex("c409")
        hits = rpt.rate_scan(blob)
        self.assertIn((0, "LE16", 2500, "2500GT/s"), [h[:4] for h in hits])

    def test_mhz_be16_only(self):
        blob = bytes.fromhex("0050")
        hits = rpt.rate_scan(blob)
        self.assertEqual([h[:4] for h in hits], [(0, "BE16", 80, "80MHz")])

    def test_context_hex_present(self):
        blob = bytes(4) + bytes.fromhex("0064") + bytes(4)
        hits = rpt.rate_scan(blob)
        hit = [h for h in hits if h[2] == 100][0]
        self.assertEqual(hit[0], 4)
        self.assertTrue(hit[4].startswith("00000000"))
        self.assertIn("0064", hit[4])

    def test_zeros_no_hits(self):
        self.assertEqual(rpt.rate_scan(bytes(64)), [])


class TestWindowFields(unittest.TestCase):
    def test_speeds123_packed_geometry(self):
        # canon: speed fields are 6-bit at shifts 0/6/12 (mask 0x3f)
        w = 1 | (2 << 6) | (3 << 12)
        self.assertEqual(rpt.window_fields(w, "speeds123"), (1, 2, 3))

    def test_speed4_shift4(self):
        w = (5 << 4) | 0x800000
        self.assertEqual(rpt.window_fields(w, "speed4"), 5)

    def test_bit21_raw(self):
        self.assertEqual(rpt.window_fields(1 << 21, "speed4"), 0)
        self.assertEqual(rpt.bit21(1 << 21), 1)
        self.assertEqual(rpt.bit21(0x00010000), 0)

    def test_area_fill_word_decodes_speed3_16(self):
        # the live CX-5 fill 0x00010000 would decode speed-3 as 16 --
        # the GC-3 coincidence documented in the journal (fill, not data)
        self.assertEqual(rpt.window_fields(0x00010000, "speeds123"), (0, 0, 16))


class TestSchedRun(unittest.TestCase):
    def test_run_stops_outside_domain(self):
        blob = bytes.fromhex("0654") + bytes.fromhex("0640") + b"\x00\x00\x00\x64"
        self.assertEqual(rpt.sched_run(blob, 0), [0x654, 0x640])

    def test_empty_when_first_word_outside(self):
        blob = bytes.fromhex("006401e8")
        self.assertEqual(rpt.sched_run(blob, 0), [])


class TestCLI(unittest.TestCase):
    def test_pair_diff_known_only_rc0(self):
        with tempfile.TemporaryDirectory() as td:
            a = bytearray(0x130)
            b = bytearray(0x130)
            a[0x23] = 0x87
            b[0x23] = 0x8F
            pa = Path(td) / "pair.0x08.bin"
            pb = Path(td) / "pair-b.0x08.bin"
            pa.write_bytes(bytes(a))
            pb.write_bytes(bytes(b))
            rc = rpt.main([str(pa), str(pb)])
            self.assertEqual(rc, 0)

    def test_pair_diff_unknown_byte_rc1(self):
        with tempfile.TemporaryDirectory() as td:
            a = bytearray(0x130)
            b = bytearray(0x130)
            b[0x55] = 0xFF
            pa = Path(td) / "pair.0x08.bin"
            pb = Path(td) / "pair-b.0x08.bin"
            pa.write_bytes(bytes(a))
            pb.write_bytes(bytes(b))
            rc = rpt.main([str(pa), str(pb)])
            self.assertEqual(rc, 1)

    def test_rate_scan_mode(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.0x09.bin"
            p.write_bytes(bytes.fromhex("03e8") + bytes(30))
            self.assertEqual(rpt.main(["--rate-scan", str(p)]), 0)


if __name__ == "__main__":
    unittest.main()
