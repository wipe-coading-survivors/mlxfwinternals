import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "irisc"))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import mlxfwutil  # noqa: E402
from iron_boot_probe import decrc  # noqa: E402
import enc  # noqa: E402
import pytest  # noqa: E402
try:
    from build_fuzz_aca import (  # noqa: E402
        IMG_PATH, INJ_DC, MARKER_SLOT, PROBES, RESUME, SC, SC_WORDS,
        NOT_TAKEN, TAKEN, build, build_fuzz2, fuzz2_words, shellcode_words,
        MEM_SLOT, build_fuzz3a, build_fuzz3b, fuzz3a_words, fuzz3b_words,
        build_fuzz3bp, fuzz3bp_words)
except FileNotFoundError:
    pytest.skip("hardware.local.md hw registry not present",
                allow_module_level=True)

pytestmark = pytest.mark.slow


def dc_words(code, addr, n):
    return [struct.unpack_from(">I", code, addr + 4 * i)[0] for i in range(n)]


# fuzz-2 golden shellcode (task-05 §4.5, enc-assembled by task-05 agent;
# blocks: marker 3 + P1 9 + P2 6 + P3 7 + C1 6 + C2 9 + resume 1 = 41)
FUZZ2_GOLDENS = (
    0x2406BADC, 0x20C60001, 0x6C0433F2,
    0x20050005, 0x20060003, 0xD8A13002, 0xA00A0004, 0x00050002, 0x6C042B82,
    0x95000003, 0x00050001, 0x6C042B82,
    0x1C050001, 0x00060001, 0xE0A00002, 0xA00A0002, 0x00060002, 0x6C043386,
    0xD8A02800, 0xA00A0004, 0x00050002, 0x6C042B8A, 0x95000003, 0x00050001,
    0x6C042B8A,
    0x20050000, 0x00060001, 0x14A50000, 0xA0000002, 0x00060002, 0x6C043392,
    0x20050005, 0x20060005, 0xD8A03002, 0xA40A0004, 0x00050002, 0x6C042B96,
    0x95000003, 0x00050001, 0x6C042B96,
    0x95F23F74,
)

# fuzz-3 golden shellcodes — дизайн-журнал 2026-10-05-fuzz3-vector-design.md
# §4 (эммитер-верифицировано 1:1; блоки по возрастанию CR-слотов,
# spillover-правило):
#   A (41) = marker 3 + C1 5 + S1 6 + S2 7 + S3 6 + S-V 8 + S-M 5 + resume 1
#   B (35) = marker 3 + C1 5 + W0 7 + X1 6 + W2a 7 + W2b 6 + resume 1
#   B' (41) = B без resume + Cz 6 (subsi/b.t.cc0 known-taken контроль,
#   слот 0x2394; поправка после C1-гейт-сбола burn#1, owner-решение) + resume
FUZZ3A_GOLDENS = (
    0x2406BADC, 0x20C60001, 0x6C0433F2, 0xE0A02802, 0x00060001, 0xA00A0002,
    0x00060002, 0x6C043382, 0x20050000, 0xD8A00004, 0x00060001, 0xA00A0002,
    0x00060002, 0x6C043386, 0x20050005, 0x20060005, 0xD8A03402, 0x00060001,
    0xA00A0002, 0x00060002, 0x6C04338A, 0x20060005, 0xD8A0300A, 0x00060001,
    0xA00A0002, 0x00060002, 0x6C04338E, 0x24058000, 0x20A50000, 0x20060001,
    0xD8A03002, 0x00060001, 0xA00A0002, 0x00060002, 0x6C043392, 0x2406BADC,
    0x20C60002, 0x6C043396, 0x20052394, 0xD8A03002, 0x95F23F74,
)

FUZZ3B_GOLDENS = (
    0x2406BADC, 0x20C60001, 0x6C0433F2, 0xE0A02802, 0x00060001, 0xA00A0002,
    0x00060002, 0x6C043382, 0x20050005, 0x20060003, 0xE0A03002, 0x00060001,
    0xA00A0002, 0x00060002, 0x6C043386, 0x20060003, 0xE0A13002, 0x00060001,
    0xA00A0002, 0x00060002, 0x6C04338A, 0x24068000, 0x20C60005, 0xE0A03002,
    0x00060001, 0xA00A0002, 0x00060002, 0x6C04338E, 0x20060002, 0xE0A03002,
    0x00060001, 0xA00A0002, 0x00060002, 0x6C043392, 0x95F23F7A,
)

# B' (41): B без resume + Cz (fuzz-2 C1-идиома: subsi r5,r5,0 @r5=0 -> Z=1,
# b.t.cc0; known-taken при ЛЮБОЙ cmp-модели) слот 0x2394 + resume @word 40
FUZZ3BP_GOLDENS = (
    0x2406BADC, 0x20C60001, 0x6C0433F2, 0xE0A02802, 0x00060001, 0xA00A0002,
    0x00060002, 0x6C043382, 0x20050005, 0x20060003, 0xE0A03002, 0x00060001,
    0xA00A0002, 0x00060002, 0x6C043386, 0x20060003, 0xE0A13002, 0x00060001,
    0xA00A0002, 0x00060002, 0x6C04338A, 0x24068000, 0x20C60005, 0xE0A03002,
    0x00060001, 0xA00A0002, 0x00060002, 0x6C04338E, 0x20060002, 0xE0A03002,
    0x00060001, 0xA00A0002, 0x00060002, 0x6C043392, 0x20050000, 0x00060001,
    0x14A50000, 0xA0000002, 0x00060002, 0x6C043396, 0x95F23F74,
)


@unittest.skipUnless(IMG_PATH.is_file(), "ACA8008 image not present")
class TestBuildFuzz1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = "/tmp/opencode/fuzz/aca-fuzz1-test.bin"
        cls.buf = build(cls.out)

    def test_file_written_and_deterministic(self):
        self.assertEqual(hashlib.md5(self.buf).hexdigest(),
                         hashlib.md5(Path(self.out).read_bytes()).hexdigest())
        buf2 = build(self.out + ".det")
        self.assertEqual(hashlib.md5(self.buf).hexdigest(),
                         hashlib.md5(buf2).hexdigest())

    def test_injection_word(self):
        img = mlxfwutil.Image(self.buf, "fuzz1")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(INJ_DC), enc.call(INJ_DC, SC))
        self.assertEqual(w(INJ_DC), 0x940DC342)
        # dead self-jump after the call stays stock
        self.assertEqual(w(INJ_DC + 4), 0x95000000)

    def test_shellcode_words(self):
        img = mlxfwutil.Image(self.buf, "fuzz1")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        words = shellcode_words()
        self.assertLessEqual(len(words), SC_WORDS)
        self.assertEqual(dc_words(code, SC, len(words)), words)
        self.assertNotEqual(words[0], 0)
        # marker: CR 0x23f0 = 0xbadc0001 (S0-exact value build, docs/250-re/120-irisc/025-boot-injection.md)
        self.assertEqual(words[0], 0x2406BADC)
        self.assertEqual(words[1], 0x20C60001)
        self.assertEqual(words[2], enc.st_d(6, 0, MARKER_SLOT))
        # final word: jump back to main-init
        self.assertEqual(words[-1], enc.jump(SC + 4 * (len(words) - 1), RESUME))

    def test_probe_golden_words(self):
        img = mlxfwutil.Image(self.buf, "fuzz1")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        blk = dc_words(code, SC, 42)
        # I2-a journal goldens: V1/V2/V5 cmp36 words (rs=r5, rt=r6)
        self.assertIn(0xD8A03002, blk)  # V1 eq32 lo11=2, 5 vs 5
        self.assertIn(0xD8A03005, blk)  # V2 eq32 lo11=5, 5 vs 3
        self.assertIn(0xD8A33002, blk)  # V5 ugt32 lo11=2, 0xFFFFFFFF vs 0
        # V5 32-bit operand build (set2 hi + set3 combine, S0 idiom)
        self.assertIn(enc.set2(5, 0xFFFF), blk)
        self.assertIn(enc.set3(5, 5, 0xFFFF), blk)
        # small operand constants land in the LOW half: set3 rd,zero,imm
        # (set2 loads the HIGH half: S0 live set2 6,zero,0xbadc -> 0xbadc0000)
        self.assertIn(enc.set3(5, 0, 5), blk)   # V1/V2 r5 = 5
        self.assertIn(enc.set3(6, 0, 5), blk)   # V1 r6 = 5
        self.assertIn(enc.set3(6, 0, 3), blk)   # V2 r6 = 3
        self.assertIn(enc.set3(6, 0, 0), blk)   # V5 r6 = 0
        self.assertNotIn(enc.set2(5, 5), blk)   # would be r5 = 0x50000
        self.assertNotIn(enc.set2(6, 3), blk)   # would be r6 = 0x30000
        # every probe stores distinct outcome codes into its own CR slot
        for (_, _, sel, lo11, slot) in PROBES:
            self.assertIn(enc.cmp36(sel, 5, 6, lo11), blk)
            self.assertIn(enc.set2(5, NOT_TAKEN), blk)
            self.assertIn(enc.set2(5, TAKEN), blk)
            self.assertIn(enc.st_d(5, 0, slot), blk)
        slots = [p[4] for p in PROBES]
        self.assertEqual(len(set(slots)), len(slots))

    def test_word_diff_vs_stock(self):
        img = mlxfwutil.Image(self.buf, "fuzz1")
        stock = mlxfwutil.Image(IMG_PATH.read_bytes(), "aca")
        new_code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        old_code = decrc(stock.section_data(stock.find_entry("ITOC", 0x03)))
        n = len(shellcode_words())
        exp = {INJ_DC} | {SC + 4 * i for i in range(n)}
        got = {a for a in range(0, min(len(new_code), len(old_code)), 4)
               if new_code[a:a + 4] != old_code[a:a + 4]}
        self.assertEqual(got, exp)

    def test_verify_deep(self):
        img = mlxfwutil.Image(self.buf, "fuzz1")
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_rejects_nonstock_image(self):
        import build_fuzz_aca as bfa
        bad = bytearray(IMG_PATH.read_bytes())
        bad[0x5000] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(bytes(bad))
            try:
                bfa.IMG_PATH = Path(tf.name)
                with self.assertRaises(ValueError):
                    build("/tmp/opencode/fuzz/aca-fuzz1-bad.bin")
            finally:
                bfa.IMG_PATH = IMG_PATH


@unittest.skipUnless(IMG_PATH.is_file(), "ACA8008 image not present")
class TestBuildFuzz2(unittest.TestCase):
    """fuzz-2 image (task-05 §4.5): known-taken control C1 (subsi/b.t.cc0),
    polarity control C2 (b.f.cc0a), probes P1/P2/P3, card GUID/MAC injected
    (task-04 values) for the --use_image_guids burn (Task 7)."""

    GUID = int(mlxfwutil.hw("CARD_CX5_25G", "guid"), 16)  # task-04 journal
    MAC = int(mlxfwutil.hw("CARD_CX5_25G", "mac"), 16)    # task-04 journal

    @classmethod
    def setUpClass(cls):
        cls.out = "/tmp/opencode/fuzz/aca-fuzz2-test.bin"
        cls.buf = build_fuzz2(cls.out)

    def _code(self):
        img = mlxfwutil.Image(self.buf, "fuzz2")
        return decrc(img.section_data(img.find_entry("ITOC", 0x03)))

    def test_file_written_and_deterministic(self):
        self.assertEqual(hashlib.md5(self.buf).hexdigest(),
                         hashlib.md5(Path(self.out).read_bytes()).hexdigest())
        buf2 = build_fuzz2(self.out + ".det")
        self.assertEqual(hashlib.md5(self.buf).hexdigest(),
                         hashlib.md5(buf2).hexdigest())

    def test_injection_word(self):
        code = self._code()
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(INJ_DC), enc.call(INJ_DC, SC))
        self.assertEqual(w(INJ_DC), 0x940DC342)
        # dead self-jump after the call stays stock
        self.assertEqual(w(INJ_DC + 4), 0x95000000)

    def test_shellcode_golden_words(self):
        # task-05 §4.5 golden table: all 41 words bit-exact (marker 3 +
        # P1 9 + P2 6 + P3 7 + C1 6 + C2 9 + resume 1; word 42 = zero sink)
        self.assertEqual(len(FUZZ2_GOLDENS), 41)
        words = fuzz2_words()
        self.assertEqual(len(words), 41)
        self.assertLessEqual(len(words), SC_WORDS)
        code = self._code()
        self.assertEqual(dc_words(code, SC, 41), list(FUZZ2_GOLDENS))
        self.assertEqual(dc_words(code, SC, 41), words)
        # sink word 42 (0x38e364) stays stock zero
        self.assertEqual(dc_words(code, SC + 4 * 41, 1), [0])
        # spot-check enc-only assembly vs §4.5 first/last words
        self.assertEqual(words[0], 0x2406BADC)
        self.assertEqual(words[-1], enc.jump(SC + 4 * 40, RESUME))
        self.assertEqual(words[-1], 0x95F23F74)

    def test_word_diff_vs_stock(self):
        img = mlxfwutil.Image(self.buf, "fuzz2")
        stock = mlxfwutil.Image(IMG_PATH.read_bytes(), "aca")
        new_code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        old_code = decrc(stock.section_data(stock.find_entry("ITOC", 0x03)))
        n = len(fuzz2_words())
        exp = {INJ_DC} | {SC + 4 * i for i in range(n)}
        got = {a for a in range(0, min(len(new_code), len(old_code)), 4)
               if new_code[a:a + 4] != old_code[a:a + 4]}
        self.assertEqual(got, exp)

    def test_guid_mac_injected(self):
        img = mlxfwutil.Image(self.buf, "fuzz2")
        # DEV_INFO: write_uids fields + INSECTION CRC (cmd_guides FS4 path)
        m = mlxfwutil.MDevInfo.parse(img.section_data(img.find_entry("DTOC", 0xE1)))
        self.assertEqual(m.guid, self.GUID)
        self.assertEqual(m.mac, self.MAC)
        self.assertTrue(m.crc_ok())
        # stock carries zeroed uids -> the injection is a real change
        stock = mlxfwutil.Image(IMG_PATH.read_bytes(), "aca")
        ms = mlxfwutil.MDevInfo.parse(stock.section_data(stock.find_entry("DTOC", 0xE1)))
        self.assertEqual((ms.guid, ms.mac), (0, 0))
        # MFG_INFO copy (guid@0x28, mac@0x38)
        d0 = img.section_data(img.find_entry("DTOC", 0xE0))
        self.assertEqual(int.from_bytes(d0[0x28:0x30], "big"), self.GUID)
        self.assertEqual(int.from_bytes(d0[0x38:0x40], "big"), self.MAC)

    def test_verify_deep(self):
        img = mlxfwutil.Image(self.buf, "fuzz2")
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])


@unittest.skipUnless(IMG_PATH.is_file(), "ACA8008 image not present")
class TestBuildFuzz3(unittest.TestCase):
    """fuzz-3 images (дизайн-журнал 2026-10-05-fuzz3-vector-design.md §2):
    A = идентичность op-0x36 (C1/S1/S2/S3/S-V/S-M, 41 слово), B = пин ширины
    cmp.w + sel-ось 0x38 (C1/W0/X1/W2a/W2b, 35 слов); GUID/MAC карты
    инъектированы (значения task-04)."""

    GUID = int(mlxfwutil.hw("CARD_CX5_25G", "guid"), 16)
    MAC = int(mlxfwutil.hw("CARD_CX5_25G", "mac"), 16)

    @classmethod
    def setUpClass(cls):
        cls.out_a = "/tmp/opencode/fuzz/aca-fuzz3a-test.bin"
        cls.buf_a = build_fuzz3a(cls.out_a)
        cls.out_b = "/tmp/opencode/fuzz/aca-fuzz3b-test.bin"
        cls.buf_b = build_fuzz3b(cls.out_b)
        cls.out_bp = "/tmp/opencode/fuzz/aca-fuzz3bp-test.bin"
        cls.buf_bp = build_fuzz3bp(cls.out_bp)

    def _code(self, buf):
        img = mlxfwutil.Image(buf, "fuzz3")
        return decrc(img.section_data(img.find_entry("ITOC", 0x03)))

    def test_fuzz3a_golden_words(self):
        self.assertEqual(len(FUZZ3A_GOLDENS), 41)
        words = fuzz3a_words()
        self.assertEqual(len(words), 41)
        self.assertLessEqual(len(words), SC_WORDS)
        self.assertEqual(words, list(FUZZ3A_GOLDENS))
        code = self._code(self.buf_a)
        self.assertEqual(dc_words(code, SC, 41), list(FUZZ3A_GOLDENS))
        # sink слово 42 (0x38e364) остаётся stock-zero
        self.assertEqual(dc_words(code, SC + 4 * 41, 1), [0])
        self.assertEqual(words[0], 0x2406BADC)
        self.assertEqual(words[-1], enc.jump(SC + 4 * 40, RESUME))
        self.assertEqual(words[-1], 0x95F23F74)
        # S-M блок: sentinel 0xbadc0002 предзаписан в [0x2394], затем BARE
        # cmp36 (без ветки) с r5 = 0x2394
        self.assertIn(enc.st_d(6, 0, MEM_SLOT), words)
        self.assertIn(enc.set3(5, 0, MEM_SLOT), words)
        self.assertIn(enc.cmp36(0x00, 5, 6, 2), words)

    def test_fuzz3b_golden_words(self):
        self.assertEqual(len(FUZZ3B_GOLDENS), 35)
        words = fuzz3b_words()
        self.assertEqual(len(words), 35)
        self.assertLessEqual(len(words), SC_WORDS)
        self.assertEqual(words, list(FUZZ3B_GOLDENS))
        code = self._code(self.buf_b)
        self.assertEqual(dc_words(code, SC, 35), list(FUZZ3B_GOLDENS))
        self.assertEqual(words[-1], enc.jump(SC + 4 * 34, RESUME))
        self.assertEqual(words[-1], 0x95F23F7A)
        # width-дискриминаторы: W2a (hi16 diff: 0x80000005) vs W2b (hi16 eq)
        self.assertIn(enc.set2(6, 0x8000), words)
        self.assertIn(enc.set3(6, 6, 0x5), words)
        self.assertIn(enc.set3(6, 0, 0x2), words)

    def test_fuzz3bp_golden_words(self):
        self.assertEqual(len(FUZZ3BP_GOLDENS), 41)
        words = fuzz3bp_words()
        self.assertEqual(len(words), 41)
        self.assertLessEqual(len(words), SC_WORDS)
        self.assertEqual(words, list(FUZZ3BP_GOLDENS))
        code = self._code(self.buf_bp)
        self.assertEqual(dc_words(code, SC, 41), list(FUZZ3BP_GOLDENS))
        self.assertEqual(words[-1], enc.jump(SC + 4 * 40, RESUME))
        self.assertEqual(words[-1], 0x95F23F74)
        # Cz блок: subsi r5,r5,0 @r5=0 -> b.t.cc0 -> st_d r6, 0x2394
        self.assertIn(enc.subsi(5, 5, 0x0), words)
        self.assertIn(enc.st_d(6, 0, 0x2394), words)

    def test_file_written_and_deterministic(self):
        for buf, out, buildfn in (
                (self.buf_a, self.out_a, build_fuzz3a),
                (self.buf_b, self.out_b, build_fuzz3b),
                (self.buf_bp, self.out_bp, build_fuzz3bp)):
            self.assertEqual(hashlib.md5(buf).hexdigest(),
                             hashlib.md5(Path(out).read_bytes()).hexdigest())
            self.assertEqual(hashlib.md5(buf).hexdigest(),
                             hashlib.md5(buildfn(out + ".det")).hexdigest())

    def test_injection_word(self):
        for buf in (self.buf_a, self.buf_b, self.buf_bp):
            code = self._code(buf)
            w = lambda a: struct.unpack_from(">I", code, a)[0]
            self.assertEqual(w(INJ_DC), enc.call(INJ_DC, SC))
            self.assertEqual(w(INJ_DC), 0x940DC342)
            # dead self-jump после call остаётся stock
            self.assertEqual(w(INJ_DC + 4), 0x95000000)

    def test_word_diff_vs_stock(self):
        stock = mlxfwutil.Image(IMG_PATH.read_bytes(), "aca")
        old_code = decrc(stock.section_data(stock.find_entry("ITOC", 0x03)))
        for buf, n in ((self.buf_a, 41), (self.buf_b, 35), (self.buf_bp, 41)):
            img = mlxfwutil.Image(buf, "fuzz3")
            new_code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
            exp = {INJ_DC} | {SC + 4 * i for i in range(n)}
            got = {a for a in range(0, min(len(new_code), len(old_code)), 4)
                   if new_code[a:a + 4] != old_code[a:a + 4]}
            self.assertEqual(got, exp)

    def test_guid_mac_injected(self):
        for buf in (self.buf_a, self.buf_b, self.buf_bp):
            img = mlxfwutil.Image(buf, "fuzz3")
            m = mlxfwutil.MDevInfo.parse(img.section_data(img.find_entry("DTOC", 0xE1)))
            self.assertEqual((m.guid, m.mac), (self.GUID, self.MAC))
            self.assertTrue(m.crc_ok())
            d0 = img.section_data(img.find_entry("DTOC", 0xE0))
            self.assertEqual(int.from_bytes(d0[0x28:0x30], "big"), self.GUID)
            self.assertEqual(int.from_bytes(d0[0x38:0x40], "big"), self.MAC)

    def test_verify_deep(self):
        for buf in (self.buf_a, self.buf_b, self.buf_bp):
            img = mlxfwutil.Image(buf, "fuzz3")
            self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])


if __name__ == "__main__":
    unittest.main()
