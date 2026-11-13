"""Tests for scripts/probes/scan_0c.py (rate-knob task-04 scanner).

Synthetic-data tests for the 0x0C slot-signature scanner: op_class
(hi-byte ranges vs exact ops, incl. the full-op-vs-hi-byte regression
the /tmp scanner hit on calibration), the 16B-aligned slot scan with
maximal non-nop runs, window density (journal
2026-10-24-pcie-phy-rate-knob-task-04.md §2: CX-5 488/488 with non-nop
count, CX-6Dx 4462/4902) and CLI smoke runs.
"""
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import scan_0c as s0c  # noqa: E402


def slot(op, a=0, b=0, c=0, d=0):
    return b"\x00" * 6 + struct.pack(">5H", op, a, b, c, d)


class TestOpClass(unittest.TestCase):
    def test_hi_byte_ranges(self):
        self.assertEqual(s0c.op_class(0x5000), "rd")
        self.assertEqual(s0c.op_class(0x5F12), "rd")
        self.assertEqual(s0c.op_class(0x6000), "wr")
        self.assertEqual(s0c.op_class(0x7F21), "wr")

    def test_exact_ops(self):
        self.assertEqual(s0c.op_class(0x4000), "delay")
        self.assertEqual(s0c.op_class(0x2000), "cond")
        self.assertEqual(s0c.op_class(0x8520), "sync")
        self.assertEqual(s0c.op_class(0x0000), "nop")

    def test_unknown_ops(self):
        for op in (0x4100, 0x9000, 0x8500, 0x1F00):
            self.assertIsNone(s0c.op_class(op))

    def test_hi_byte_not_full_op_regression(self):
        # calibration bug (journal task-04 §2): comparing the full BE16
        # op against hi-byte ranges missed the whole CX-5 table
        self.assertEqual(s0c.op_class(0x6049), "wr")
        self.assertEqual(s0c.op_class(0x5030), "rd")


class TestScan(unittest.TestCase):
    def test_runs_and_slot_likes(self):
        img = (b"\xde\xad" * 8
               + slot(0x5010) + slot(0x2000) + slot(0x6049)
               + slot(0x0000)
               + slot(0x4000)
               + b"\xff" * 16)
        res = s0c.scan(img)
        self.assertEqual(res.slot_likes, 5)
        self.assertEqual(res.non_nop, 4)
        runs2 = [(s, n) for s, n in res.runs if n >= 2]
        self.assertEqual(runs2, [(16, 3)])

    def test_unchanged_run_of_one_not_reported(self):
        img = slot(0x4000) + b"\xff" * 16 + slot(0x5010)
        res = s0c.scan(img)
        self.assertEqual(res.slot_likes, 2)
        self.assertEqual([n for _, n in res.runs], [1, 1])

    def test_unaligned_pattern_ignored(self):
        img = b"\xff" * 8 + slot(0x5010) + b"\xff" * 8
        res = s0c.scan(img)
        # the rd slot at +8 is not counted; the all-zero a,b,c,d tail
        # of it lands aligned and reads as a nop slot-like
        self.assertEqual(res.slot_likes, 1)
        self.assertEqual(res.non_nop, 0)

    def test_short_tail_ignored(self):
        img = slot(0x5010) + b"\x00" * 7
        res = s0c.scan(img)
        self.assertEqual(res.slot_likes, 1)


class TestDensity(unittest.TestCase):
    def test_window_density_counts_nop_and_non_nop(self):
        slots = [slot(0x5010)] * 28 + [slot(0)] * 2 + [slot(0x6049)] * 2
        img = bytes(48) + b"".join(slots)
        likes, total, non_nop = s0c.density(img, 48, 32 * 16)
        self.assertEqual((likes, total, non_nop), (32, 32, 30))

    def test_window_before_section(self):
        img = bytes(64) + slot(0x5010)
        likes, total, non_nop = s0c.density(img, 0, 64)
        self.assertEqual((likes, total, non_nop), (4, 4, 0))


class TestCLI(unittest.TestCase):
    def test_scan_file_rc0(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "img.bin"
            p.write_bytes(slot(0x5010) + slot(0x6049) + b"\xff" * 16)
            self.assertEqual(s0c.main([str(p)]), 0)

    def test_headline_counts_non_nop_with_nop_note(self):
        # journal task-04 §2 headline semantics: "slot-likes" is the
        # non-nop count ("nop отдельно"); nop-likes (zero padding) are
        # reported in parentheses, never inflating the headline
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "img.bin"
            p.write_bytes(slot(0x5010) + slot(0) + b"\x00" * 32
                          + b"\xff" * 16)
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(s0c.main([str(p)]), 0)
            line = buf.getvalue().splitlines()[0]
            self.assertIn("slot-likes: 1 (+3 nop)", line)
            self.assertIn("runs>=2: 0", line)

    def test_scan_empty_result_rc0(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "img.bin"
            p.write_bytes(b"\xff" * 64)
            self.assertEqual(s0c.main([str(p)]), 0)

    def test_window_arg(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "img.bin"
            p.write_bytes(bytes(48) + slot(0x5010) + slot(0x6049))
            self.assertEqual(
                s0c.main([str(p), "--window", "0x30:0x20"]), 0)

    def test_bad_window_rc2(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "img.bin"
            p.write_bytes(b"\xff" * 64)
            self.assertEqual(
                s0c.main([str(p), "--window", "nope"]), 2)


if __name__ == "__main__":
    unittest.main()
