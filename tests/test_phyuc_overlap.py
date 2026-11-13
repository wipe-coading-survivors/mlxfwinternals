import struct
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "phyuc"))

import phyuc_overlap  # noqa: E402


def rec(op, a, b, c, d):
    return (op, a, b, c, d)


WR_A = (0x6045, 0x06DF, 0x39CC, 0x0400, 0x0070)
WR_B = (0x6165, 0x06E0, 0x39CC, 0x0410, 0x0001)
WR_C = (0x6173, 0x06E1, 0x49CC, 0x00C0, 0x0001)
RD_A = (0x5456, 0x06E2, 0x0100, 0x3400, 0x0340)
COND = (0x2000, 0x0000, 0x0000, 0x0064, 0x1648)
DELAY = (0x4000, 0x0010, 0x0000, 0x0000, 0x0000)
NOP = (0x0000, 0x0000, 0x0000, 0x0000, 0x0000)
SYNC = (0x8520, 0x002E, 0x1000, 0x0030, 0x0000)
LANE = (0x4C40, 0x0000, 0x0117, 0x0030, 0x000A)
MASK = (0x3000, 0x0000, 0x0000, 0x0000, 0x1FFF)


class TestAddrSets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.S = [rec(*WR_A), rec(*WR_B), rec(*WR_C), rec(*RD_A),
                 rec(*COND), rec(*DELAY), rec(*NOP), rec(*SYNC),
                 rec(*LANE), rec(*MASK)]
        cls.sets = phyuc_overlap.addr_sets(cls.S)

    def test_write_pairs_and_projections(self):
        self.assertEqual(self.sets["write"]["pairs"],
                         {(0x39CC, 0x0400), (0x39CC, 0x0410), (0x49CC, 0x00C0)})
        self.assertEqual(self.sets["write"]["b"], {0x39CC, 0x49CC})
        self.assertEqual(self.sets["write"]["c"], {0x0400, 0x0410, 0x00C0})

    def test_read_pairs(self):
        self.assertEqual(self.sets["read"]["pairs"], {(0x0100, 0x3400)})

    def test_lane_ops_join_read_domain_only(self):
        self.assertEqual(self.sets["lane"]["pairs"], {(0x0117, 0x0030)})
        self.assertIn((0x0117, 0x0030), self.sets["read+lane"]["pairs"])
        self.assertNotIn((0x0117, 0x0030), self.sets["write"]["pairs"])

    def test_excluded_ops_carry_no_addresses(self):
        pairs = {p for d in ("write", "read", "read+lane")
                 for p in self.sets[d]["pairs"]}
        excluded_pairs = {(COND[2], COND[3]), (DELAY[2], DELAY[3]),
                          (NOP[2], NOP[3]), (SYNC[2], SYNC[3]),
                          (MASK[2], MASK[3])}
        self.assertEqual(excluded_pairs & pairs, set())

    def test_excluded_domains_report_op2000(self):
        dom = phyuc_overlap.excluded_domains(self.S)
        self.assertEqual(dom["op2000"]["c"], {0x0064})
        self.assertEqual(dom["op2000"]["d"], {0x1648})
        self.assertEqual(dom["delay"]["a"], {0x0010})
        self.assertEqual(dom["op3000"]["d"], {0x1FFF})
        self.assertEqual(dom["op8520"]["b"], {0x1000})


class TestOverlapSemantics(unittest.TestCase):
    def test_disjoint_sections_have_no_write_overlap(self):
        a = phyuc_overlap.addr_sets([rec(*WR_A), rec(*WR_B)])
        b = phyuc_overlap.addr_sets([rec(0x6045, 0x06DF, 0xFFB8, 0x147C, 1)])
        self.assertEqual(a["write"]["pairs"] & b["write"]["pairs"], set())

    def test_shared_pairs_intersect(self):
        a = phyuc_overlap.addr_sets([rec(*WR_A)])
        b = phyuc_overlap.addr_sets([rec(0x6041, 0x0700, 0x39CC, 0x0400, 2)])
        self.assertEqual(a["write"]["pairs"] & b["write"]["pairs"],
                         {(0x39CC, 0x0400)})

    def test_lane_family_range(self):
        for op in (0x4840, 0x4940, 0x4A40, 0x4B40, 0x4C40, 0x4D50):
            self.assertTrue(phyuc_overlap.is_lane_op(op))
        for op in (0x4740, 0x4E40, 0x5440, 0x6045):
            self.assertFalse(phyuc_overlap.is_lane_op(op))


class TestFmt(unittest.TestCase):
    def test_fmt_val_scalar_and_tuple(self):
        self.assertEqual(phyuc_overlap.fmt_val(0x39CC), "0x39cc")
        self.assertEqual(phyuc_overlap.fmt_val((0x39CC, 0x0400)),
                         "(0x39cc,0x0400)")

    def test_fmt_rng_tuple(self):
        out = phyuc_overlap.fmt_rng({(0x39CC, 0x0400), (0x09CC, 0x0010)})
        self.assertIn("2 distinct", out)
        self.assertIn("(0x09cc,0x0010)", out)


if __name__ == "__main__":
    unittest.main()
