import struct  # noqa: E402
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "phyuc"))

import phyuc_classify  # noqa: E402


def slot(op, a, b, c, d):
    return b"\x00" * 6 + struct.pack(">5H", op, a, b, c, d)


def rec(op, a, b, c, d):
    return (op, a, b, c, d)


R0 = (0x6041, 0x000A, 0x59CC, 0x0490, 0x0043)
R1 = (0x5064, 0x0640, 0x1200, 0x0100, 0x0010)
R2 = (0x4000, 0x0654, 0x0000, 0x0000, 0x0000)
COND = (0x2000, 0x0000, 0x0000, 0x0064, 0x7700)
PERLANE = (0x5256, 0x0001, 0x01EC, 0x0010, 0x0001)
FUSE = (0x6125, 0x0027, 0x39CC, 0x0680, 0x000B)

CX4 = [rec(*R0), rec(*R1), rec(*R2)]
CX5 = [
    rec(*R0),
    rec(0x5064, 0x0680, 0x1200, 0x0100, 0x0010),
    rec(0x6041, 0x000A, 0x59CC, 0x0490, 0x0081),
    rec(*COND),
    rec(*PERLANE),
    rec(*FUSE),
]
CX6 = [rec(*COND), rec(*PERLANE), rec(*FUSE),
       rec(0x6647, 1, 0x39CC, 0x0100, 1),
       rec(0x6089, 2, 0x39CC, 0x0200, 1)]
CX6DX = [rec(*COND), rec(*FUSE),
         rec(0x6089, 2, 0x39CC, 0x0200, 2),
         rec(0x6765, 1, 0x39CC, 0x0300, 1)]


class TestClassify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.markup, cls.summary = phyuc_classify.classify(CX4, CX5, CX6, CX6DX)

    def test_classes_per_record(self):
        self.assertEqual([c for _, _, c in self.markup], [
            "skeleton", "resched", "skeleton-add",
            "gen4-cond", "cx5-only", "gen4"])

    def test_markup_indices_and_slots(self):
        self.assertEqual([i for i, _, _ in self.markup], list(range(6)))
        self.assertEqual(self.markup[3][1], slot(*COND))

    def test_format_markup_greppable(self):
        lines = phyuc_classify.format_markup(self.markup).splitlines()
        self.assertEqual(len(lines), 6)
        for line, (i, s, cls) in zip(lines, self.markup):
            parts = line.split(" ")
            self.assertEqual(len(parts), 3)
            self.assertEqual(parts[0], str(i))
            self.assertEqual(parts[1], s.hex())
            self.assertEqual(parts[2], cls)

    def test_summary_records(self):
        self.assertEqual(self.summary["records"],
                         {"cx4": 3, "cx5": 6, "cx6": 5, "cx6dx": 4})

    def test_summary_class_counts(self):
        self.assertEqual(dict(self.summary["classes"]), {
            "skeleton": 1, "resched": 1, "skeleton-add": 1,
            "gen4": 1, "gen4-cond": 1, "cx5-only": 1})

    def test_summary_skeleton_keys(self):
        self.assertEqual(self.summary["skeleton_keys"],
                         {"cx4": 3, "cx5": 2, "cx6": 0, "cx6dx": 0})

    def test_summary_gen4_keys(self):
        self.assertEqual(self.summary["gen4_keys"], 2)

    def test_summary_serdes_delta(self):
        self.assertEqual(self.summary["serdes_delta"],
                         {"cx6_only_keys": 2, "cx6dx_only_keys": 1})

    def test_summary_cx6_growth(self):
        self.assertEqual(self.summary["cx6_growth"],
                         {"raw_diff": 5 - 6, "new_key_instances": 2})

    def test_summary_gen4_ops(self):
        self.assertEqual(self.summary["gen4_ops"], [0x2000, 0x6125])
        self.assertEqual(self.summary["ops_all_four"], [])

    def test_summary_op_hist(self):
        self.assertEqual(self.summary["op_hist"]["cx5"][0x2000], 1)
        self.assertEqual(self.summary["op_hist"]["cx4"][0x6041], 1)


class TestPairingOrder(unittest.TestCase):
    def test_byte_equal_preferred_over_key_greedy(self):
        # two cx5 instances of one cx4 key: byte-equal one + extra d value;
        # greedy first-match must not mislabel the byte-equal instance
        cx4 = [rec(0x6045, 1, 0x39CC, 0x400, 0x70),
               rec(0x6045, 1, 0x39CC, 0x400, 0x80)]
        cx5 = [rec(0x6045, 1, 0x39CC, 0x400, 0x80),
               rec(0x6045, 1, 0x39CC, 0x400, 0x75),
               rec(0x6045, 1, 0x39CC, 0x400, 0x70)]
        markup, _ = phyuc_classify.classify(
            cx4, cx5, [rec(0x7000, 1, 1, 1, 1)], [rec(0x7000, 2, 2, 2, 2)])
        self.assertEqual([c for _, _, c in markup],
                         ["skeleton", "skeleton-add", "skeleton"])


if __name__ == "__main__":
    unittest.main()
