import struct  # noqa: E402
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "phyuc"))

import phyuc_classify  # noqa: E402
import phyuc_diff  # noqa: E402


def rec(op, a, b, c, d):
    return (op, a, b, c, d)


def blob08(off, entries, pair_off, pair):
    data = bytearray(0x140)
    for i, v in enumerate(entries):
        struct.pack_into(">H", data, off + 2 * i, v)
    struct.pack_into(">2H", data, pair_off, *pair)
    return bytes(data)


LX_TABLE = [0x654, 0x640, 0x671, 0x655, 0x6df]
C5_TABLE = [0x654, 0x640, 0x671, 0x655, 0x6c0, 0x827]

LX08 = blob08(0xF0, LX_TABLE, 0x128, (0x64, 160))
C508 = blob08(0xF0, C5_TABLE, 0x110, (0x64, 488))
LEGACY08 = blob08(0x110, [0x655, 0x744], 0x114, (0x64, 261))

C5_SLOTS = [
    rec(0x5044, 0x654, 0x100, 0x6c0, 0x6c),
    rec(0x4000, 0x645, 0, 0, 0),
    rec(0x2000, 0, 0, 0x65, 0x5671),
    rec(0x2000, 0, 0, 0x72, 0xA74D),
    rec(0x5044, 0x74D, 0x100, 0x6c0, 0x6c),
    rec(0x5044, 0x827, 0x100, 0x6c0, 0x6c),
]
LX_SLOTS = [
    rec(0x5044, 0x654, 0x100, 0x6c0, 0x6c),
    rec(0x4000, 0x6df, 0, 0, 0),
]


class TestParseSchedule(unittest.TestCase):
    def test_lx_layout_f0_zero_terminated(self):
        s = phyuc_diff.parse_schedule(LX08)
        self.assertEqual(s["off"], 0xF0)
        self.assertEqual(s["entries"], LX_TABLE)
        self.assertEqual(s["pair"], (0x64, 160))
        self.assertEqual(s["pair_off"], 0x128)

    def test_cx5_layout_pair_right_after_table(self):
        s = phyuc_diff.parse_schedule(C508)
        self.assertEqual(s["off"], 0xF0)
        self.assertEqual(s["entries"], C5_TABLE)
        self.assertEqual(s["pair"], (0x64, 488))
        self.assertEqual(s["pair_off"], 0x110)

    def test_1619_layout_0x110_domain_terminated(self):
        s = phyuc_diff.parse_schedule(LEGACY08)
        self.assertEqual(s["off"], 0x110)
        self.assertEqual(s["entries"], [0x655, 0x744])
        self.assertEqual(s["pair"], (0x64, 261))

    def test_no_table_returns_none(self):
        self.assertIsNone(phyuc_diff.parse_schedule(b"\x00" * 0x140))


class TestScheduleReport(unittest.TestCase):
    def test_cx5_envelope_and_domain(self):
        r = phyuc_diff.schedule_report(C5_SLOTS, phyuc_diff.parse_schedule(C508))
        self.assertEqual(r["max_a"], 0x827)
        self.assertEqual(r["table_max"], 0x827)
        self.assertTrue(r["envelope_match"])
        self.assertEqual(r["first_sched_a"], 0x654)
        self.assertTrue(r["first_is_table0"])
        self.assertEqual(r["domain_inter"], [0x654, 0x827])

    def test_lx_envelope(self):
        r = phyuc_diff.schedule_report(LX_SLOTS, phyuc_diff.parse_schedule(LX08))
        self.assertTrue(r["envelope_match"])
        self.assertEqual(r["table_max"], 0x6df)

    def test_envelope_mismatch_detected(self):
        r = phyuc_diff.schedule_report(
            [rec(0x4000, 0x700, 0, 0, 0)], phyuc_diff.parse_schedule(LX08))
        self.assertFalse(r["envelope_match"])

    def test_cond_handlers_in_schedule_domain(self):
        r = phyuc_diff.schedule_report(C5_SLOTS, phyuc_diff.parse_schedule(C508))
        by_c = {c["c"]: c for c in r["conds"]}
        self.assertEqual(by_c[0x65]["lo12"], 0x671)
        self.assertTrue(by_c[0x65]["in_table"])
        self.assertEqual(by_c[0x65]["tag"], 0x5)
        self.assertEqual(by_c[0x72]["lo12"], 0x74D)
        self.assertFalse(by_c[0x72]["in_table"])
        self.assertTrue(by_c[0x72]["in_aset"])


class TestRateHits(unittest.TestCase):
    def test_hits_tagged_by_field_domain(self):
        slots = [
            rec(0x6041, 0x0E, 0x79CC, 0x480, 0x50),
            rec(0x6173, 0x00, 0x09CC, 0x10, 0x1),
            rec(0x6161, 0x10, 0x09CC, 0x180, 0x1),
            rec(0x4000, 0x19, 0, 0, 0),
            rec(0x2000, 0, 0, 0x64, 0x1064),
        ]
        hits = phyuc_diff.rate_hits(slots)
        tags = {(h[2], h[3]) for h in hits}
        self.assertIn(("wr-d", 0x50), tags)
        self.assertIn(("wr-c", 0x10), tags)
        self.assertIn(("wr-a", 0x10), tags)
        self.assertIn(("delay-a", 0x19), tags)
        self.assertIn(("cond-c", 0x64), tags)
        lo = [h for h in hits if h[2] == "cond-d.lo12"]
        self.assertEqual(lo[0][3], 0x64)

    def test_no_false_positives(self):
        slots = [rec(0x6045, 0x27, 0x39CC, 0x420, 0x74)]
        self.assertEqual(phyuc_diff.rate_hits(slots), [])


MARKUP_LINES = [
    "0 " + (b"\x00" * 6 + struct.pack(">5H", 0x6165, 0x27, 0x39CC, 0x400, 0)).hex() + " skeleton",
    "1 " + (b"\x00" * 6 + struct.pack(">5H", 0x2000, 0, 0, 0x65, 0x5671)).hex() + " cx5-only-cond",
    "2 " + (b"\x00" * 6 + struct.pack(">5H", 0x6049, 0x27, 0x39CC, 0x510, 0x6A)).hex() + " cx5-only",
    "3 " + (b"\x00" * 6 + struct.pack(">5H", 0x6165, 0x27, 0x39CC, 0x400, 0)).hex() + " skeleton",
]


class TestCondContext(unittest.TestCase):
    def test_load_markup_roundtrip(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(MARKUP_LINES) + "\n")
            path = f.name
        markup = phyuc_classify.load_markup(path)
        Path(path).unlink()
        self.assertEqual([i for i, _, _ in markup], [0, 1, 2, 3])
        self.assertEqual(markup[1][2], "cx5-only-cond")
        self.assertEqual(markup[1][1][6:], struct.pack(">5H", 0x2000, 0, 0, 0x65, 0x5671))

    def test_cond_context_nearest_skeleton(self):
        markup = [(0, b"", "skeleton"), (1, b"", "cx5-only-cond"),
                  (2, b"", "cx5-only"), (3, b"", "skeleton")]
        ctx = phyuc_classify.cond_context(markup, window=2)
        self.assertEqual(ctx["conds"], [1])
        self.assertEqual(ctx["nearest_skeleton"], {1: 1})
        self.assertEqual(ctx["insert_share"], {1: 1 / 3})

    def test_cond_context_no_skeleton_in_window(self):
        markup = [(0, b"", "skeleton"), (1, b"", "cx5-only"),
                  (2, b"", "cx5-only-cond"), (3, b"", "cx5-only"),
                  (4, b"", "cx5-only"), (5, b"", "skeleton")]
        ctx = phyuc_classify.cond_context(markup, window=2)
        self.assertEqual(ctx["nearest_skeleton"][2], 2)
        self.assertEqual(ctx["insert_share"][2], 3 / 4)


if __name__ == "__main__":
    unittest.main()
