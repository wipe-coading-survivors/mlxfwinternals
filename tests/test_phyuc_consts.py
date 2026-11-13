import struct
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "phyuc"))

import phyuc_consts  # noqa: E402
import phyuc_dis  # noqa: E402


def be32(words):
    return struct.pack(f">{len(words)}I", *words)


def tbl(tid, rows, stride=None, cls="mixed"):
    words_n = rows if stride is None else rows * stride
    return phyuc_consts.ConstsTable(
        tid=tid, offset=tid * 16, length=words_n * 4, stride=stride,
        row_count=rows, sub_stride=None, entropy_class=cls)


A_COLS = (0x11, 0x12, 0x13, 0x14)
B_COLS = (0x21, 0x22, 0x23, 0x24, 0x25, 0x26)
TWO_STRIDE = be32(list(A_COLS) * 5 + list(B_COLS) * 3)


class TestParseConsts(unittest.TestCase):
    def test_two_stride_tables_both_found(self):
        lay = phyuc_consts.parse_consts(TWO_STRIDE)
        self.assertEqual(len(lay.tables), 2)
        strides = sorted(t.stride for t in lay.tables)
        self.assertEqual(strides, [4, 6])
        offsets = [t.offset for t in lay.tables]
        self.assertEqual(offsets, [0, 80])
        for t in lay.tables:
            self.assertEqual(t.entropy_class, "analog-looking")
        self.assertEqual(lay.grid, None)

    def test_row_counts_follow_stride(self):
        lay = phyuc_consts.parse_consts(TWO_STRIDE)
        by_stride = {t.stride: t for t in lay.tables}
        self.assertEqual(by_stride[4].row_count, 5)
        self.assertEqual(by_stride[6].row_count, 3)

    def test_grid_layout_detected(self):
        hdr = [0x1404, 0x154AA, 0xBB8, 0x1FF, 0xF424, 0x1802, 0x8822, 0x3360]
        varied = []
        for j in range(8):
            varied.extend(0x200 + j * 0x40 + i for i in range(8))
        shared = [0x800 + i * 0x10 for i in range(8)]
        tables = varied + shared * 8
        lay = phyuc_consts.parse_consts(be32(hdr + tables))
        self.assertNotEqual(lay.grid, None)
        self.assertEqual((lay.grid.stride, lay.grid.header_words,
                          lay.grid.count), (8, 8, 16))
        self.assertEqual(len(lay.tables), 17)
        self.assertEqual(lay.strides, (8,))
        self.assertEqual(lay.tables[0].stride, None)
        self.assertEqual(lay.tables[0].entropy_class, "mixed")
        self.assertEqual({t.stride for t in lay.tables[1:]} | {None}, {None})
        self.assertEqual([t.row_count for t in lay.tables[1:]], [8] * 16)
        self.assertEqual([t.offset for t in lay.tables[1:]][0], 32)

    def test_zero_payload_single_zero_table(self):
        lay = phyuc_consts.parse_consts(b"\x00" * 1280)
        self.assertEqual(len(lay.tables), 1)
        t = lay.tables[0]
        self.assertEqual((t.stride, t.entropy_class, t.row_count),
                         (None, "zero", 320))
        self.assertEqual(lay.grid, None)
        self.assertEqual(lay.strides, ())

    def test_flat_payload_single_mixed_table(self):
        words = [0x9000, 0x1000, 0x8000, 0x1400, 0x7000, 0x1100,
                 0x8800, 0x1500, 0x6800, 0x1200, 0x7800, 0x1600]
        lay = phyuc_consts.parse_consts(be32(words))
        self.assertEqual(len(lay.tables), 1)
        t = lay.tables[0]
        self.assertEqual((t.stride, t.entropy_class, t.row_count),
                         (None, "mixed", 12))

    def test_timing_ramp_pairs(self):
        col0 = [0x3FC00] * 3 + [0x3F58A] * 3 + [0x3F20F] * 3 + [0x3EF94] * 3
        col1 = [0x67200] * 3 + [0x67203] * 3 + [0x67205] * 3 + [0x67207] * 3
        pairs = [w for pair in zip(col0, col1) for w in pair]
        lay = phyuc_consts.parse_consts(be32(pairs))
        self.assertEqual(len(lay.tables), 1)
        t = lay.tables[0]
        self.assertEqual((t.stride, t.entropy_class), (2, "timing-looking"))

    def test_counter_like_run(self):
        words = [5, 6, 7, 8, 9, 10, 11, 12, 0x500, 0x200, 0x900]
        lay = phyuc_consts.parse_consts(be32(words))
        self.assertEqual(lay.tables[0].entropy_class, "counter-like")

    def test_bad_size_rejected(self):
        with self.assertRaises(ValueError):
            phyuc_consts.parse_consts(b"\x00\x01\x02")
        with self.assertRaises(ValueError):
            phyuc_consts.parse_consts(b"")


class TestIndexAlignment(unittest.TestCase):
    LAYOUT = phyuc_consts.ConstsLayout(
        n_words=10, strides=(), grid=None,
        tables=(tbl(0, 2), tbl(1, 2), tbl(2, 4, stride=5)))

    def test_index_field_yields_match(self):
        k = 3
        scripts = [(0x6045, 0, 0x09CC, 0x10, 1),
                   (0x6045, 1, 0x09CC, 0x10, 2),
                   (0x6045, k, 0x09CC, 0x10, 2)]
        matches = phyuc_consts.index_alignment(self.LAYOUT, scripts)
        got = {(m.table, m.idx) for m in matches}
        self.assertEqual(got, {(2, 0), (2, 1), (2, 3)})
        self.assertIn(phyuc_consts.Match(table=2, idx=k, slot=2, field="a"),
                      matches)

    def test_row_space_excludes_small_tables(self):
        scripts = [(0x6045, 0, 0x09CC, 0x10, 1), (0x6045, 3, 0x09CC, 0x10, 2)]
        matches = phyuc_consts.index_alignment(self.LAYOUT, scripts)
        self.assertEqual(sorted((m.table, m.idx) for m in matches),
                         [(2, 0), (2, 3)])

    def test_b_field_never_indexed(self):
        scripts = [(0x6045, 0x700, 0, 0x10, 1), (0x6045, 0x701, 1, 0x10, 1),
                   (0x6045, 0x702, 2, 0x10, 1), (0x6045, 0x703, 3, 0x10, 1)]
        self.assertEqual(phyuc_consts.index_alignment(self.LAYOUT, scripts), [])

    def test_min_zero_required(self):
        scripts = [(0x6045, 1, 0x09CC, 0x10, 1), (0x6045, 2, 0x09CC, 0x10, 1)]
        self.assertEqual(phyuc_consts.index_alignment(self.LAYOUT, scripts), [])

    def test_full_row_space_required(self):
        scripts = [(0x6045, 0, 0x09CC, 0x10, 1), (0x6045, 200, 0x09CC, 0x10, 1)]
        self.assertEqual(phyuc_consts.index_alignment(self.LAYOUT, scripts), [])

    def test_density_required(self):
        layout = phyuc_consts.ConstsLayout(
            n_words=10, strides=(), grid=None, tables=(tbl(0, 16, stride=2),))
        scripts = [(0x6045, v, 0x09CC, 0x10, 1) for v in (0, 2, 4, 6, 8, 10)]
        self.assertEqual(phyuc_consts.index_alignment(layout, scripts), [])


class TestRecordShapes(unittest.TestCase):
    LAYOUT = phyuc_consts.ConstsLayout(
        n_words=10, strides=(), grid=None,
        tables=(tbl(0, 2), tbl(1, 2), tbl(2, 4, stride=5)))
    FIVE = [(0x0000, 0, 0, 0, 0),
            (0x6045, 0, 0x09CC, 0x10, 1),
            (0x6045, 1, 0x09CC, 0x10, 2),
            (0x6045, 3, 0x09CC, 0x10, 2)]

    def test_phyuc_dis_shaped_records_match(self):
        five = [r for r in self.FIVE if r[0]]
        six = [(i,) + r for i, r in enumerate(five)]
        self.assertEqual(phyuc_consts.index_alignment(self.LAYOUT, five),
                         phyuc_consts.index_alignment(self.LAYOUT, six))

    def test_phyuc_dis_slots_end_to_end(self):
        five = [r for r in self.FIVE if r[0]]
        raw = b"".join(struct.pack(">6x5H", *r) for r in self.FIVE)
        six = phyuc_dis.slots(raw)
        m5 = phyuc_consts.index_alignment(self.LAYOUT, five)
        m6 = phyuc_consts.index_alignment(self.LAYOUT, six)
        self.assertEqual([(m.table, m.idx, m.field) for m in m5],
                         [(m.table, m.idx, m.field) for m in m6])
        self.assertEqual([m.slot for m in m6], [1, 2, 3])

    def test_malformed_shapes_raise(self):
        bad = [
            [(0x6045, 0, 0x09CC, 0x10)],
            [(0, 1, 2, 3, 4, 5, 6)],
            [("x", 0, 0, 0, 0)],
            [(-1, 0x6045, 0, 0, 0, 0)],
            [(0x6045, 0, 0, 0x10000, 0)],
            ["6045"],
        ]
        for recs in bad:
            with self.assertRaises(ValueError):
                phyuc_consts.index_alignment(self.LAYOUT, recs)


class TestFamily(unittest.TestCase):
    def test_family_names(self):
        f = phyuc_consts._family
        self.assertEqual(f(0x6045), "write")
        self.assertEqual(f(0x5456), "read")
        self.assertEqual(f(0x2000), "op2000")
        self.assertEqual(f(0x3000), "op3000")
        self.assertEqual(f(0x4000), "delay")
        self.assertEqual(f(0x8520), "op8520")
        self.assertEqual(f(0x4C40), "lane")
        self.assertEqual(f(0), "nop")


if __name__ == "__main__":
    unittest.main()
