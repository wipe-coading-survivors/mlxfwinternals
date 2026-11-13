import re
import struct
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "irisc"))

import enc  # noqa: E402
import irisc_dis as d  # noqa: E402

LD_WORDS = {
    0x2DE4: 0x64250011,
    0x306C: 0x6424002F,
    0xE4310: 0x6428009B,
}


def _reg(name):
    return 0 if name == "zero" else int(name[1:])


def enc_from_dis(word):
    m = re.match(r"ld\.w (zero|r\d+),(zero|r\d+),(-?0x[0-9a-f]+)$", d.dis(word, 0))
    assert m is not None, d.dis(word, 0)
    return enc.ld_w(_reg(m.group(1)), _reg(m.group(2)), int(m.group(3), 16))


class TestEncGolden(unittest.TestCase):
    def test_set3_r10_2390(self):
        self.assertEqual(enc.set3(10, 0, 0x2390), 0x200A2390)

    def test_set2_r4_10(self):
        self.assertEqual(enc.set2(4, 0x10), 0x24040010)

    def test_set3_r4_8494(self):
        self.assertEqual(enc.set3(4, 0, 0x8494), 0x20048494)

    def test_st_d_golden(self):
        self.assertEqual(enc.st_d(3, 1, 0x4), 0x6C201806)

    def test_jump_self(self):
        self.assertEqual(enc.jump(0x1D598, 0x1D598), 0x95000000)

    def test_call_main_init(self):
        self.assertEqual(enc.call(0x1D594, 0x1E10C), 0x940002DE)

    def test_cmp36_v1(self):
        self.assertEqual(enc.cmp36(0x00, 5, 6, 2), 0xD8A03002)

    def test_cmp36_v4(self):
        self.assertEqual(enc.cmp36(0x01, 5, 6, 2), 0xD8A13002)

    def test_b_t_cc0a(self):
        self.assertEqual(enc.b_t(0x0A, 0x100, 0x108), 0xA00A0002)

    def test_b_f_cc0a(self):
        self.assertEqual(enc.b_f(0x0A, 0x100, 0x108), 0xA40A0002)

    def test_b_bset(self):
        # b.bset sh, rs, REL16 (op 0x2a): branch if bit sh of rs is set.
        self.assertEqual(enc.b_bset(16, 4, 0x100, 0x10C), 0xA8900003)

    def test_b_bclr(self):
        # b.bclr sh, rs, REL16 (op 0x2b): branch if bit sh of rs is clear.
        self.assertEqual(enc.b_bclr(0, 4, 0x100, 0x10C), 0xAC800003)

    def test_b_bset_roundtrip(self):
        # enc/dec agree on sh, rs, and target (branch on a register bit;
        # stock precedent: the 0x2af04 `ld.i`+`b.bset` polling loop):
        w = enc.b_bset(16, 4, 0x38D7B4, 0x38D7C0)
        self.assertEqual(d.dis(w, 0x38D7B4), 'b.bset 16,r4,0x38d7c0')

    def test_b_bclr_roundtrip(self):
        w = enc.b_bclr(0, 4, 0x38D7B4, 0x38D7C0)
        self.assertEqual(d.dis(w, 0x38D7B4), 'b.bclr 0,r4,0x38d7c0')

    # Goldens below: exact words from the SHA-256 suite of MAIN_CODE 16.35.4030
    # (build/ghidra-4030cda-main03-ac-dc.bin; algorithmically verified by the
    # I2-b 15-vector emulation, journal 2026-09-23-irisc-isa-i2b-rosetta.md).

    def test_subsi_sha_golden(self):
        self.assertEqual(enc.subsi(4, 23, 0x0), 0x16E40000)

    def test_subsi_sha_golden_fill(self):
        # Golden word at FW offset 0x2b1620 (SHA fill fragment, while r4 != 0x37)
        self.assertEqual(enc.subsi(5, 4, 0x37), 0x14850037)

    def test_addi_sha_golden(self):
        self.assertEqual(enc.addi(6, 0, 0x80), 0x00060080)

    def test_set1_sha_golden(self):
        self.assertEqual(enc.set1(5, 5, 0xE667), 0x1CA5E667)

    def test_b_t_cc0_sha_golden(self):
        self.assertEqual(enc.b_t(0x00, 0x2B1344, 0x2B1398), 0xA0000015)

    def test_b_f_cc0_sha_golden(self):
        self.assertEqual(enc.b_f(0x00, 0x2B1624, 0x2B1614), 0xA400FFFC)

    def test_cmp38_v8(self):
        # I2-a vector V8 golden word (op 0x38, sel=eq32, rs=r5, rt=zero, lo11=2)
        self.assertEqual(enc.cmp38(0x00, 5, 0, 2), 0xE0A00002)

    # S2-v2 selector API (plan-fix R9, journal
    # 2026-09-24-irisc-ondemand-s2-task-07-debug.md §Вердикт/Рекомендация):
    # the comparison selector sub-block is funct5 (lo11), NOT the sel bits;
    # funct5=2 (eq32) is the live-proven form, funct5=0 traps/stalls the CPU.

    def test_cmp38_sel_eq32_live_proven(self):
        # fuzz-2 live-proven word P2 e0a00002: funct5=2 (eq32), rs=r5, rt=zero
        self.assertEqual(enc.cmp38_sel(2, 5, 0), 0xE0A00002)

    def test_cmp38_sel_stub_compare_v2(self):
        # S2-v2 stub compare word: funct5=2 (eq32), rs=r12 (input[0]),
        # rt=r13 (MAGIC) -> 0xE1806802; v1 burnt word 0xE1806800 had funct5=0
        self.assertEqual(enc.cmp38_sel(2, 12, 13), 0xE1806802)

    def test_cmp38_sel_decode_fallback(self):
        # irisc_dis has no dedicated op-0x38 selector decode; the generic
        # fallback must keep funct5 visible in imm16 (decode-consistency)
        self.assertEqual(d.dis(enc.cmp38_sel(2, 12, 13), 0),
                         'op0x38 zero,r12,r13 imm=0x6802')

    # S2 stub encoders: goldens from the base image words
    # (journal 2026-09-24-irisc-ondemand-s2-task-03.md, Step 1).

    def test_ret_r_reg_jump(self):
        self.assertEqual(enc.ret_r(0, 0, 12), 0xFC006025)

    def test_ret_r_stdret(self):
        self.assertEqual(enc.ret_r(8, 0, 3), 0xFD001825)

    def test_st_d_push(self):
        self.assertEqual(enc.st_d_push(-0x28), 0x703F0FDA)

    def test_st_d_save(self):
        self.assertEqual(enc.st_d(3, 1, 0x4), 0x6C201806)

    def test_or_mov(self):
        self.assertEqual(enc.or_(19, 4, 4), 0xFC932008)

    def test_st_w_golden(self):
        # st.w r5,r23,0x0 @0x9c4 and st.w r15,r1,0x2da @0xe4c
        self.assertEqual(enc.st_w(5, 23, 0x0), 0x6EE02801)
        self.assertEqual(enc.st_w(15, 1, 0x2DA), 0x6C207ADB)

    def test_ld_w_roundtrip(self):
        # ld.w r5,r1,0x10 @0x2de4; ld.w r4,r1,0x2e @0x306c; ld.w r8,r1,0x9a @0xe4310
        for a in (0x2DE4, 0x306C, 0xE4310):
            word = LD_WORDS[a]
            self.assertEqual(enc_from_dis(word), word)

    # T23 (v5d copy path): ld.d is op 0x19 + is32bit (bit1) — the SAME op
    # family as ld.w/ld.q, off14 = (bits 15..2)<<2.  Goldens are the
    # stock-exact code sites from the task-23 scan (de-clcrc MAIN_CODE,
    # classifier code regions): ld.d r3,r11,0x0 (0x65630002) is a real
    # stock word, and rs=11^rd=3 is a x2-precedented combo (offs 0 and 4).

    def test_ld_d_golden_stock_exact(self):
        self.assertEqual(enc.ld_d(3, 11, 0x0), 0x65630002)
        self.assertEqual(enc.ld_d(3, 11, 0x4), 0x65630006)

    def test_ld_d_decode_roundtrip(self):
        self.assertEqual(d.dis(enc.ld_d(3, 11, 0), 0), "ld.d r3,r11,0x0")
        self.assertEqual(d.dis(enc.ld_d(3, 11, 4), 0), "ld.d r3,r11,0x4")
        self.assertEqual(d.dis(enc.ld_d(3, 12, 0x20), 0), "ld.d r3,r12,0x20")

    def test_ld_d_bit_layout(self):
        # bit0=is16bit=0, bit1=is32bit=1, off scaled by 4 into bits 15..2
        for off in (0, 4, 8, 0x20, 0x100):
            w = enc.ld_d(3, 11, off)
            self.assertEqual(w & 0x3, 2)
            self.assertEqual(((w >> 2) & 0x3FFF) << 2, off)

    # S2B v5n (plan-2 s2b2, Task-1 CENSUS): the m2' X1-from-p0 block.
    # w10 0xFC843081 = shl64.i r4,r4,6 (op 0x3f funct 0x081, stock x253
    # in code space); w11 0x1C848FC0 = set1 r4,r4,0x8fc0 (stock x3,
    # sites 0x82a74/0x90b14/0x90c04 byte-exact).

    def test_shl64_i_golden(self):
        self.assertEqual(enc.shl64_i(4, 4, 6), 0xFC843081)

    def test_shl64_i_decode(self):
        self.assertEqual(d.dis(enc.shl64_i(4, 4, 6), 0), "shl64.i r4,r4,0x6")

    def test_shl64_i_stock_words_from_fields(self):
        # op 0x3f funct 0x081 words (Task-1 CENSUS: the stock word
        # x253 + the diag-golden) reproduce from their own decoded
        # fields (rd/rs/shamt)
        for word in (0xFC843081, 0xFC846881):
            self.assertEqual(word >> 26, 0x3F)
            self.assertEqual(word & 0x1FF, 0x81)
            self.assertEqual(enc.shl64_i((word >> 16) & 0x1F,
                                         (word >> 21) & 0x1F,
                                         (word >> 11) & 0x1F), word)

    def test_set1_w11_golden(self):
        self.assertEqual(enc.set1(4, 4, 0x8FC0), 0x1C848FC0)

    def test_set1_w11_decode(self):
        self.assertEqual(d.dis(0x1C848FC0, 0), "set1 r4,r4,0x8fc0")

    def test_set1_w11_stock_sites(self):
        # Task-1 CENSUS: the three stock sites, byte-exact in the
        # de-crc'd code file
        code = REPO / "build" / "4030cda-main03-code-patched3.bin"
        if not code.exists():
            self.skipTest("de-crc'd code not present")
        raw = code.read_bytes()
        for a in (0x82A74, 0x90B14, 0x90C04):
            self.assertEqual(struct.unpack_from(">I", raw, a)[0], 0x1C848FC0)


if __name__ == "__main__":
    unittest.main()
