"""Tests for scripts/probes/cx4lx_gen4_window.py (gen4-window decoder,
plan 2026-10-24-cx4lx-gen4-window task 3).

Synthetic-data tests for per-word classification (off/4 unmapped / пуст /
area-fill / заполнен), slot field extraction (6-bit fields, bit-21 raw) and
the spec §5 stop-table predicate; plus a smoke run over the committed dump
files when present.
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import cx4lx_gen4_window as gw  # noqa: E402

DUMPS = REPO / "scripts" / "dumps" / "cx-4" / "cx4lx-gen4-window"


def word(addr, value):
    return gw.Word(addr, value)


class TestClassify(unittest.TestCase):
    def test_off4_pattern_is_unmapped_not_data(self):
        # value == addr>>2 is a PATTERN (unmapped default), never «заполнен»
        self.assertEqual(gw.classify(word(0x43758, 0x00010DD6)), "unmapped")

    def test_zero_is_empty(self):
        self.assertEqual(gw.classify(word(0x4eae4, 0)), "пуст")

    def test_dominant_fill_10000_is_area_fill(self):
        self.assertEqual(gw.classify(word(0x4dd64, 0x00010000)), "area-fill")

    def test_other_nonzero_is_filled(self):
        self.assertEqual(gw.classify(word(0x4eae4, 0x000005D0)), "заполнен")

    def test_fill_zero_is_not_area_fill(self):
        # 0x00010000 at a real address is not off/4 and not empty
        w = word(0x4dd4c, 0x00010000)
        self.assertNotEqual(gw.classify(w), "unmapped")
        self.assertNotEqual(gw.classify(w), "пуст")

    def test_dump_level_summary_counts(self):
        words = [word(0x1000, 0x00010000), word(0x1004, 0x00010000),
                 word(0x1008, 0x00000003)]
        s = gw.summarize(words)
        self.assertEqual((s["area-fill"], s["заполнен"], s["пуст"],
                          s["unmapped"]), (2, 1, 0, 0))
        self.assertEqual(s["dominant"], 0x00010000)


class TestSlotDecode(unittest.TestCase):
    def test_speeds123_fields_6bit(self):
        # three 6-bit packed fields at shifts 0/6/12
        w = (0o77) | (0o52 << 6) | (0o15 << 12)
        f = gw.slot_fields("cx5", "speeds123", w)
        self.assertEqual((f["speed1"], f["speed2"], f["speed3"]),
                         (0o77, 0o52, 0o15))

    def test_speed4_field_shift4(self):
        self.assertEqual(gw.slot_fields("lx", "speed4", 0x02A0)["speed4"],
                         0x2A)

    def test_lx_speed4_bit21_raw(self):
        # bit 21 recorded raw, no interpretation
        f0 = gw.slot_fields("lx", "speed4", 0)
        f1 = gw.slot_fields("lx", "speed4", 1 << 21)
        self.assertEqual((f0["bit21"], f1["bit21"]), (0, 1))

    def test_fields_only_for_filled_words(self):
        # 6-bit speed fields ONLY for non-fill words; bit21 stays raw
        self.assertIsNone(gw.slot_fields("cx5", "speeds123", 0x00010000))
        self.assertEqual(gw.slot_fields("lx", "speed4", 0), {"bit21": 0})
        self.assertNotIn("speed4", gw.slot_fields("lx", "speed4",
                                                  0x00010000))


class TestStopTable(unittest.TestCase):
    def _decode(self, cx5_g4_s4, cx5_g3_s4, lx_s4, lx_unmapped=False):
        return {
            "cx5_gen4_speed4": gw.classify(word(0x4dd64, cx5_g4_s4)),
            "cx5_gen3_speed4": gw.classify(word(0x4dd64, cx5_g3_s4)),
            "lx_speed4": ("unmapped" if lx_unmapped
                          else gw.classify(word(0x4eae4, lx_s4))),
            "lx_window_unmapped": lx_unmapped,
        }

    def test_row2_lx_speed4_filled(self):
        d = self._decode(0x2A0, 0x0, 0x2A0)
        self.assertEqual(gw.stop_row(d), 2)

    def test_row2_precedes_invalid_control(self):
        d = self._decode(0x00010000, 0x00010000, 0x2A0)
        self.assertEqual(gw.stop_row(d), 2)

    def test_row3_control_area_fill_no_differential(self):
        d = self._decode(0x00010000, 0x00010000, 0x0)
        self.assertEqual(gw.stop_row(d), 3)

    def test_row3_control_unmapped(self):
        d = self._decode(0x00013759, 0x0, 0x0)
        self.assertEqual(gw.stop_row(d), 3)

    def test_row3_control_filled_but_no_gen_differential(self):
        d = self._decode(0x000002A0, 0x000002A0, 0x0)
        self.assertEqual(gw.stop_row(d), 3)

    def test_row4_lx_window_unmapped_valid_control(self):
        d = self._decode(0x2A0, 0x0, 0, lx_unmapped=True)
        self.assertEqual(gw.stop_row(d), 4)

    def test_row1_valid_control_lx_empty(self):
        d = self._decode(0x2A0, 0x0, 0x0)
        self.assertEqual(gw.stop_row(d), 1)

    def test_row1_valid_control_lx_unmapped_slot(self):
        d = {"cx5_gen4_speed4": "заполнен",
             "cx5_gen3_speed4": "пуст",
             "lx_speed4": "unmapped",
             "lx_window_unmapped": False}
        self.assertEqual(gw.stop_row(d), 1)

    def test_row0_valid_control_lx_area_fill(self):
        # erratum: area-fill = «нет различимых данных» — spec row 1
        # admits only пуст/unmapped; must NOT fall through to row 1
        d = self._decode(0x2A0, 0x0, 0x00010000)
        self.assertEqual(gw.stop_row(d), 0)

    def test_row0_missing_slot_input(self):
        d = {"cx5_gen4_speed4": "заполнен",
             "cx5_gen3_speed4": "пуст",
             "lx_speed4": "missing",
             "lx_window_unmapped": False}
        self.assertEqual(gw.stop_row(d), 0)


class TestPredicateInputsPartial(unittest.TestCase):
    def test_lx_window_missing_speed4_slot(self):
        # partial window: lx dump lacks the 0x4eae4 slot address —
        # explicit «missing» marker feeding row 0, not a KeyError
        decodes = {
            "cx5_gen4": [word(0x4dd64, 0x000002A0), word(0x4ddc4, 0x0)],
            "cx5_gen3": [word(0x4dd64, 0x0), word(0x4ddc4, 0x0)],
            "lx": [word(0x4eb44, 0x0)],
        }
        d = gw.predicate_inputs(decodes)
        self.assertEqual(d["lx_speed4"], "missing")
        self.assertEqual(gw.stop_row(d), 0)

    def test_card_absent_from_decodes(self):
        decodes = {"cx5_gen4": [word(0x4dd64, 0x000002A0)]}
        d = gw.predicate_inputs(decodes)
        self.assertEqual(d["cx5_gen3_speed4"], "missing")
        self.assertEqual(d["lx_speed4"], "missing")
        self.assertEqual(gw.stop_row(d), 0)

    def test_emit_partial_window_row0(self):
        import contextlib
        import io
        decodes = {
            "cx5_gen4": [word(0x4dd64, 0x000002A0)],
            "cx5_gen3": [word(0x4dd64, 0x0)],
            "lx": [word(0x4eb44, 0x0)],
        }
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = gw.emit(decodes)
        self.assertEqual(rc, 0)
        self.assertIn("missing", out.getvalue())
        self.assertIn("row 0", out.getvalue())


class TestRealDumps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (DUMPS / "c1xx-cx4lx-4ea7c-4ecb0.txt").is_file():
            raise unittest.SkipTest("gen4-window dumps not present")
        cls.files = {
            "cx5_gen4": DUMPS / "81xx-cx5ex-gen4-4dd4c-4de70.txt",
            "cx5_gen4_naive": DUMPS / "81xx-cx5ex-gen4-43750-437a0.txt",
            "cx5_gen3": DUMPS / "1xx-cx5-gen3-4dd4c-4de70.txt",
            "lx": DUMPS / "c1xx-cx4lx-4ea7c-4ecb0.txt",
            "cx4_hyp": DUMPS / "42xx-cx4-4ea7c-4ecb0.txt",
        }
        cls.decodes = {k: gw.decode_dump(v)
                       for k, v in cls.files.items()}

    def test_line_counts(self):
        self.assertEqual([len(self.decodes[k]) for k in
                          ("cx5_gen4", "cx5_gen4_naive", "cx5_gen3", "lx",
                           "cx4_hyp")], [74, 21, 74, 142, 142])

    def test_cx5_pair_area_fill_with_one_transient(self):
        for k in ("cx5_gen4", "cx5_gen3"):
            s = gw.summarize(self.decodes[k])
            self.assertEqual(s["area-fill"], 74 if k == "cx5_gen3" else 73)
        tr = [w for w in self.decodes["cx5_gen4"] if w.cls == "заполнен"]
        self.assertEqual([(w.addr, w.value) for w in tr],
                         [(0x4DE48, 0x00000003)])

    def test_naive_range_all_unmapped_off4(self):
        s = gw.summarize(self.decodes["cx5_gen4_naive"])
        self.assertEqual(s["unmapped"], 21)

    def test_naive_dump_not_merged_into_gen4_window(self):
        # same 81xx filename prefix as the x4-window dump — card_name must
        # keep them apart (naive range check), not merge words
        self.assertEqual(gw.card_name(str(self.files["cx5_gen4_naive"]),
                                      self.decodes["cx5_gen4_naive"]),
                         "cx5_gen4_naive")
        self.assertEqual(gw.summarize(self.decodes["cx5_gen4"])["n"], 74)

    def test_lx_mapped_zero_one_transient(self):
        s = gw.summarize(self.decodes["lx"])
        self.assertEqual((s["пуст"], s["заполнен"]), (141, 1))
        tr = [w for w in self.decodes["lx"] if w.cls == "заполнен"][0]
        self.assertEqual((tr.addr, tr.value), (0x4EAFC, 0x000005D0))

    def test_slots(self):
        slots = gw.slot_words(self.decodes)
        self.assertEqual(slots["cx5_gen4"]["speed4"].cls, "area-fill")
        self.assertEqual(slots["cx5_gen4"]["speeds123"].cls, "area-fill")
        self.assertEqual(slots["cx5_gen3"]["speed4"].cls, "area-fill")
        self.assertEqual(slots["lx"]["speed4"].cls, "пуст")
        self.assertEqual(slots["lx"]["speeds123"].cls, "пуст")
        self.assertEqual(slots["cx4_hyp"]["speed4"].cls, "пуст")

    def test_stop_row_on_real_data(self):
        self.assertEqual(gw.stop_row(gw.predicate_inputs(self.decodes)), 3)

    def test_cli_real_dumps(self):
        rc = gw.main([str(p) for p in self.files.values()])
        self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
