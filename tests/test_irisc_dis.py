import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "irisc"))

import irisc_dis  # noqa: E402


class TestBranchTargets(unittest.TestCase):
    def test_branch_forward(self):
        self.assertIn("0x91774", irisc_dis.dis(0xA0100002, 0x9176C))

    def test_branch_cc_selector(self):
        self.assertEqual(irisc_dis.dis(0xA0100002, 0x9176C), "b.t.0x10 zero,0x91774")

    def test_branch_backward(self):
        self.assertIn("0xd3e10", irisc_dis.dis(0xA003FFFE, 0xD3E18))

    def test_bbit_target(self):
        self.assertIn("0x22128", irisc_dis.dis(0xA8850004, 0x22118))


class TestCallJump(unittest.TestCase):
    def test_call_main_init_4030(self):
        self.assertEqual(irisc_dis.dis(0x940002DE, 0x1D594), "call 0x1e10c")

    def test_injection_word_decodes_to_cave(self):
        self.assertEqual(irisc_dis.dis(0x940DC067, 0x1D594), "call 0x38d730")

    def test_jump_self(self):
        self.assertEqual(irisc_dis.dis(0x95000000, 0x1D598), "jump 0x1d598")


class TestMemOffsets(unittest.TestCase):
    def test_st_d_small(self):
        self.assertEqual(irisc_dis.dis(0x6C201806, 0), "st.d r3,r1,0x4")

    def test_st_d_frame(self):
        self.assertEqual(irisc_dis.dis(0x6C20888E, 0), "st.d r17,r1,0x8c")

    def test_st_w_scaled(self):
        self.assertEqual(irisc_dis.dis(0x6EE02007, 0), "st.w r4,r23,0x6")

    def test_st_q_1e(self):
        self.assertEqual(irisc_dis.dis(0x7820281C, 0), "st.q.1e r5,r1,0x18")

    def test_ld_d(self):
        self.assertEqual(irisc_dis.dis(0x6437000A, 0), "ld.d r23,r1,0x8")

    def test_ld_d_next(self):
        self.assertEqual(irisc_dis.dis(0x6436000E, 0), "ld.d r22,r1,0xc")


class TestQFormEaMask(unittest.TestCase):
    def test_st_q_1e_sha_init_word_4030(self):
        self.assertEqual(irisc_dis.dis(0x78802914, 0), "st.q.1e r5,r4,0x110")

    def test_ld_q_17_masked(self):
        self.assertEqual(irisc_dis.dis(0x5C850114, 0), "ld.q.17 r5,r4,0x110")

    def test_st_q_1e_negative_align_down(self):
        self.assertEqual(irisc_dis.dis(0x783F2FFC, 0), "st.q.1e r5,r1,-0x8")

    def test_st_d_1e_raw(self):
        self.assertEqual(irisc_dis.dis(0x7820281E, 0), "st.d.1e r5,r1,0x1c")

    def test_ld_d_17_raw(self):
        self.assertEqual(irisc_dis.dis(0x5C850116, 0), "ld.d.17 r5,r4,0x114")


class TestMask32ShiftBits(unittest.TestCase):
    def test_shift_is_bits_5_10(self):
        self.assertEqual(irisc_dis.dis(0xC9090124, 0), "mask32 r9,r8,0x9,4")

    def test_shift_zero_byte_align(self):
        self.assertEqual(irisc_dis.dis(0xC9080003, 0), "mask32 r8,r8,0x0,3")

    def test_shift_16(self):
        self.assertEqual(irisc_dis.dis(0xC9080200, 0), "mask32 r8,r8,0x10,0")


class TestAndsImmRendering(unittest.TestCase):
    def test_ands_imm_unsigned(self):
        self.assertEqual(irisc_dis.dis(0x2C84FFFC, 0), "ands r4,r4,0xfffc")

    def test_ands_imm_small(self):
        self.assertEqual(irisc_dis.dis(0x2C84000F, 0), "ands r4,r4,0xf")


class TestCanonSyncAndHiDepC022(unittest.TestCase):
    # golden pairs: actual Ghidra canon output (canon-sync task-01,
    # build/irisc-crosscheck/ghidra-repo.txt; and.hi — конструктор
    # 061d7e0 op=0x0d; 0x34 lo11=0x022 смёржен как :dep.c литерал,
    # canon-sync 2026-11-02 — named bclr.1-рендер снят, слово идёт
    # lossless catch-all op0x34)

    def test_and_hi_ghidra_canon_26cc(self):
        self.assertEqual(irisc_dis.dis(0x34E700F0, 0x26CC), "and.hi r7,r7,0xf0")

    def test_and_hi_imm_bit15_unsigned(self):
        # imm16=0x9000 (bit 15 set): slaspec imm16 token is unsigned,
        # Ghidra prints 0x9000 (ghidra-repo.txt @0x4944)
        self.assertEqual(irisc_dis.dis(0x34849000, 0x4944), "and.hi r4,r4,0x9000")

    def test_and_hi_rd_ne_rs(self):
        self.assertEqual(irisc_dis.dis(0x3493F000, 0x41C0), "and.hi r19,r4,0xf000")

    def test_dep_c_022_rosetta_site_8c124(self):
        # Rosetta site word d0840822 (rt=1): bclr.1-рендер снят
        # (canon-sync 2026-11-02, :dep.c литерал 0x022), рендер
        # catch-all — rt-поле читается, roundtrip бит-экзакт
        self.assertEqual(irisc_dis.dis(0xD0840822, 0x8C124),
                         "op0x34 r4,r4,r1 imm=0x0822")

    def test_dep_c_022_canonical_rt_zero(self):
        self.assertEqual(irisc_dis.dis(0xD0840022, 0),
                         "op0x34 r4,r4,zero imm=0x0022")

    def test_dep_c_022_not_matched_other_lo11(self):
        # op=0x34 with lo11 != 0x022 stays generic op0xNN
        self.assertEqual(irisc_dis.dis(0xD0840823, 0),
                         "op0x34 r4,r4,r1 imm=0x0823")


class TestCanonSync0x0cAndmskHi(unittest.TestCase):
    # canon-sync 2026-11-01: op 0x0c imm hi-and mask renamed or ->
    # andmsk.hi (semantics merged 06be769); goldens are stock/builder
    # words from the corpus (the fuzz5 dump site @0xa864 word 30849fff
    # was verified textually as `or r4,r4,0x9fff` upstream-side)

    def test_andmsk_hi_golden_m2_word(self):
        self.assertEqual(irisc_dis.dis(0x30C600FF, 0),
                         "andmsk.hi r6,r6,0xff")

    def test_andmsk_hi_golden_c_src_word(self):
        self.assertEqual(irisc_dis.dis(0x308800FF, 0),
                         "andmsk.hi r8,r4,0xff")

    def test_andmsk_hi_imm_bit15_unsigned(self):
        # imm16=0x9fff (bit 15 set): unsigned token both sides
        self.assertEqual(irisc_dis.dis(0x30849FFF, 0xA864),
                         "andmsk.hi r4,r4,0x9fff")

    def test_register_or_unrenamed(self):
        # the register form (op 0x3f funct=8) keeps the inherited `or`
        self.assertEqual(irisc_dis.dis(0xFEC5B008, 0), "or r5,r22,r22")


class TestTargetWrap32(unittest.TestCase):
    def test_jump_wraps_to_32bit(self):
        self.assertEqual(irisc_dis.dis(0x95800001, 0), "jump 0xfe000004")

    def test_call_wraps_to_32bit(self):
        self.assertEqual(irisc_dis.dis(0x94800000, 0), "call 0xfe000000")

    def test_branch_wraps_to_32bit(self):
        self.assertEqual(irisc_dis.dis(0xA400FFFF, 0), "b.f.0x0 zero,0xfffffffc")


if __name__ == "__main__":
    unittest.main()
