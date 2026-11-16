import struct
import sys
import unittest
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import mlxfwutil  # noqa: E402
from mlxfwutil import (DEVINFO_MAGIC, DTOC_HDR, FS4_MAGIC, ITOC_HDR,  # noqa: E402
                       crc16_mlx, set_bits)
from scripts.probes.romdump import rc3_port  # noqa: E402

RI = REPO / "refs/fw/cx-5-6/dumps/cx5-rom-2026-11-15/ri_stock.bin"

GOLDEN_STUB = [
    0x642600B2, 0x6E403012, 0x642600B6, 0x6E403016, 0x642600BA, 0x6E40301A,
    0x642600BE, 0x6E40301E, 0x642600C2, 0x6E403022, 0x642600C6, 0x6E403026,
    0x642600CA, 0x6E40302A, 0x642600CE, 0x6E40302E, 0x642600D2, 0x6E403032,
    0x642600D6, 0x6E403036, 0x000443C8, 0x0884008E, 0xFC002025,
]


class TestCanonPins(unittest.TestCase):
    def test_stub_golden_words(self):
        self.assertEqual(rc3_port.stub_words(), GOLDEN_STUB)

    def test_hook_word_canon(self):
        self.assertEqual(rc3_port.hook_word(), 0x940AA4EC)

    def test_site_pins(self):
        self.assertEqual(rc3_port.SITE_WORDS[rc3_port.HOOK_DC], 0x00130000)
        self.assertEqual(rc3_port.SITE_WORDS[0x0E43C0], 0xC88B0102)
        self.assertEqual(rc3_port.SITE_WORDS[0x0E437C], 0x9402A57A)
        self.assertEqual(rc3_port.SITE_WORDS[0x25A3EC], 0x0011001F)
        self.assertEqual(rc3_port.STUB_DC, 0x38D774)
        self.assertEqual(rc3_port.RESUME_RT, 0x8E43C8)
        self.assertEqual(len(rc3_port.SITE_WORDS), 9)

    def test_stub_composition(self):
        words = rc3_port.stub_words()
        loads = [w for w in words if (w >> 24) == 0x64]
        stores = [w for w in words if (w >> 24) == 0x6E]
        self.assertEqual(len(loads), 10)
        self.assertEqual(len(stores), 10)
        self.assertEqual(words[-3:], [0x000443C8, 0x0884008E, 0xFC002025])


SYNTH_MAIN_ADDR = rc3_port.MAIN_ADDR
SYNTH_INI_ADDR = 0x3EE000
SYNTH_SIG_ADDR = 0x3EF000
SYNTH_DEVINFO_ADDR = 0x3F0000
SYNTH_INI_VENDOR = [
    ";; vendor comment line %d padded with filler text" % i for i in range(30)
]
SYNTH_INI_KV = ["key%d=%d" % (i, i) for i in range(8)]

_SYNTH = None


def _toc_hdr(hdr16, nent):
    h = bytearray(32)
    h[0:16] = hdr16
    set_bits(h, 184, 8, nent)
    set_bits(h, 240, 16, crc16_mlx(bytes(h[:28])))
    return bytes(h)


def _ent(t, size, addr, crcf=0, sec_crc=0, clcrc=0, param0=0):
    r = bytearray(32)
    set_bits(r, 0, 8, t)
    set_bits(r, 8, 22, size // 4)
    set_bits(r, 161, 29, addr // 4)
    set_bits(r, 32, 1, 0)
    set_bits(r, 33, 1, clcrc)
    set_bits(r, 34, 30, param0)
    set_bits(r, 205, 3, crcf)
    set_bits(r, 208, 16, sec_crc)
    set_bits(r, 240, 16, crc16_mlx(bytes(r[:28])))
    return bytes(r)


def _devinfo():
    d = bytearray(0x40)
    d[0:16] = DEVINFO_MAGIC
    d[0x10:0x14] = (0x00000200).to_bytes(4, "big")
    struct.pack_into(">H", d, 0x3E, crc16_mlx(bytes(d[:0x3C])))
    return bytes(d)


def _synth_ini():
    lines = [rc3_port.BANNER] + SYNTH_INI_VENDOR + SYNTH_INI_KV
    return "\n".join(lines) + "\n"


def _synth_budget():
    floor = [rc3_port.BANNER, rc3_port.BUILD_ID] + SYNTH_INI_KV
    packed = len(zlib.compress(("\n".join(floor) + "\n").encode("latin1"), 9))
    size = packed + rc3_port.HEADROOM_MIN + 30 + 128
    return size + (4 - size % 4) % 4


def synth_ri():
    global _SYNTH
    if _SYNTH is None:
        code = bytearray(rc3_port.CODE_LEN)
        for dc, word in rc3_port.SITE_WORDS.items():
            struct.pack_into(">I", code, dc, word)
        raw = mlxfwutil.clcrc_wrap(bytes(code), b"\x00" * 4)
        assert len(raw) == rc3_port.MAIN_SIZE
        ini_data = zlib.compress(_synth_ini().encode("latin1"), 9)
        ini_size = _synth_budget()
        ini_data += b"\x00" * (ini_size - len(ini_data))
        sig = bytearray(0x140)
        sig[0x20:0x40] = bytes(range(0x41, 0x61))
        ents = [
            _ent(0x03, len(raw), SYNTH_MAIN_ADDR, clcrc=1,
                 param0=0x800000, sec_crc=crc16_mlx(raw)),
            _ent(0x30, ini_size, SYNTH_INI_ADDR, sec_crc=crc16_mlx(ini_data)),
            _ent(0xA0, 0x140, SYNTH_SIG_ADDR, crcf=1),
            _ent(0xFF, 0, 0),
        ]
        buf = bytearray(0x3F1000)
        buf[0:16] = FS4_MAGIC
        buf[0x1000:0x1020] = _toc_hdr(ITOC_HDR, len(ents) - 1)
        for i, ent in enumerate(ents):
            buf[0x1020 + i * 32:0x1040 + i * 32] = ent
        buf[0x1100:0x1120] = _toc_hdr(DTOC_HDR, 1)
        buf[0x1120:0x1140] = _ent(0xE1, 0x40, SYNTH_DEVINFO_ADDR, crcf=2)
        buf[0x1140:0x1160] = _ent(0xFF, 0, 0)
        buf[SYNTH_MAIN_ADDR:SYNTH_MAIN_ADDR + len(raw)] = raw
        buf[SYNTH_INI_ADDR:SYNTH_INI_ADDR + len(ini_data)] = ini_data
        buf[SYNTH_SIG_ADDR:SYNTH_SIG_ADDR + 0x140] = sig
        buf[SYNTH_DEVINFO_ADDR:SYNTH_DEVINFO_ADDR + 0x40] = _devinfo()
        _SYNTH = bytes(buf)
    return _SYNTH


def synth_mutate_main_word(buf, dc, word):
    img = mlxfwutil.Image(bytes(buf), "synth")
    e = img.find_entry("ITOC", 0x03)
    out = bytearray(buf)
    base = img.sec_abs(e) + (dc // 64) * 68
    struct.pack_into(">I", out, base + (dc % 64), word)
    line = bytes(out[base:base + 68])
    struct.pack_into("<H", out, base + 66, mlxfwutil.clcrc_calc(line[:66]))
    return bytes(out)


@pytest.mark.slow
class TestVerifyBaseSynthetic(unittest.TestCase):
    def test_valid(self):
        v = rc3_port.verify_base(synth_ri())
        self.assertEqual(v["reasons"], [])
        self.assertTrue(v["ok"])
        self.assertEqual(v["main_code"]["addr"], rc3_port.MAIN_ADDR)
        self.assertEqual(v["main_code"]["size"], rc3_port.MAIN_SIZE)
        self.assertEqual(v["main_code"]["param0"], 0x800000)
        self.assertTrue(v["clcrc_roundtrip"])
        self.assertEqual(v["cave_nonzero"], [])
        self.assertEqual(v["free_slot_words"], 34)
        self.assertEqual(v["stub_slack"], 34 - len(rc3_port.stub_words()))

    def test_shifted_hook_site(self):
        bad = synth_mutate_main_word(synth_ri(), rc3_port.HOOK_DC, 0x00130001)
        v = rc3_port.verify_base(bad)
        self.assertFalse(v["ok"])
        self.assertTrue(any("0e43c4" in r for r in v["reasons"]), v["reasons"])

    def test_occupied_cave(self):
        bad = synth_mutate_main_word(synth_ri(), rc3_port.STUB_DC, 0xDEADBEEF)
        v = rc3_port.verify_base(bad)
        self.assertFalse(v["ok"])
        self.assertTrue(any("38d774" in r or "cave" in r for r in v["reasons"]),
                        v["reasons"])

    def test_graft_word_touched(self):
        bad = synth_mutate_main_word(synth_ri(), 0x25A3EC, 0xFCB1C083)
        v = rc3_port.verify_base(bad)
        self.assertFalse(v["ok"])
        self.assertTrue(any("25a3ec" in r for r in v["reasons"]), v["reasons"])

    def test_geometry_rejected(self):
        buf = bytearray(synth_ri())
        img = mlxfwutil.Image(bytes(buf), "synth")
        e = img.find_entry("ITOC", 0x03)
        ent_off = img.itoc_off + 32 + e.index * 32
        ent = bytearray(buf[ent_off:ent_off + 32])
        set_bits(ent, 8, 22, (e.size + 64) // 4)
        set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
        buf[ent_off:ent_off + 32] = ent
        v = rc3_port.verify_base(bytes(buf))
        self.assertFalse(v["ok"])
        self.assertTrue(any("MAIN_CODE" in r for r in v["reasons"]), v["reasons"])


@pytest.mark.slow
class TestBuildSynthetic(unittest.TestCase):
    def test_build_rejects_incompatible_base(self):
        bad = synth_mutate_main_word(synth_ri(), rc3_port.STUB_DC, 0xDEADBEEF)
        with self.assertRaises(rc3_port.Rc3PortError):
            rc3_port.build(bad)

    def test_build_full_pipeline(self):
        base = synth_ri()
        out = rc3_port.build(base)
        self.assertEqual(rc3_port.build(base), out)

        fimg = mlxfwutil.Image(out, "built")
        self.assertEqual(mlxfwutil.verify_image(fimg, deep=True), [])
        status, _, _ = mlxfwutil.sig_status(fimg)
        self.assertEqual(status, "fresh")
        bimg = mlxfwutil.Image(base, "base")
        bstatus, _, _ = mlxfwutil.sig_status(bimg)
        self.assertEqual(bstatus, "stale")

        fe = fimg.find_entry("ITOC", 0x03)
        be = bimg.find_entry("ITOC", 0x03)
        fcode, _ = mlxfwutil.clcrc_unwrap(fimg.section_data(fe))
        bcode, _ = mlxfwutil.clcrc_unwrap(bimg.section_data(be))
        w = lambda c, a: struct.unpack_from(">I", c, a)[0]
        changed = [dc for dc in range(0, len(bcode), 4)
                   if w(fcode, dc) != w(bcode, dc)]
        want = sorted([rc3_port.HOOK_DC]
                      + [rc3_port.STUB_DC + 4 * i for i in range(23)])
        self.assertEqual(sorted(changed), want)
        self.assertEqual(w(fcode, rc3_port.HOOK_DC), 0x940AA4EC)
        self.assertEqual([w(fcode, rc3_port.STUB_DC + 4 * i) for i in range(23)],
                         GOLDEN_STUB)
        self.assertEqual(w(fcode, 0x25A3EC), 0x0011001F)

        e30n = fimg.find_entry("ITOC", 0x30)
        e30b = bimg.find_entry("ITOC", 0x30)
        self.assertEqual(e30n.addr, e30b.addr)
        self.assertLessEqual(e30n.size, e30b.size)
        text = zlib.decompress(fimg.section_data(e30n)).decode("latin1")
        lines = text.splitlines()
        self.assertEqual(lines[lines.index(rc3_port.BANNER) + 1],
                         rc3_port.BUILD_ID)
        for kv in SYNTH_INI_KV:
            self.assertIn(kv, text)

        dg = rc3_port.diff_gate(bimg, out,
                                sorted({dc // 64 for dc in want}))
        self.assertEqual(dg["stray"], [])
        self.assertEqual(dg["section_diff"], ["ITOC 0x03", "ITOC 0x30",
                                              "ITOC 0xA0"])

    def test_edit_ini_trims_only_vendor_comments(self):
        text = _synth_ini()
        floor = "\n".join([rc3_port.BANNER, rc3_port.BUILD_ID]
                          + SYNTH_INI_KV) + "\n"
        size = len(zlib.compress(floor.encode("latin1"), 9)) \
            + rc3_port.HEADROOM_MIN + 8
        new_text, dropped = rc3_port.edit_ini(text, size)
        self.assertNotEqual(dropped, [])
        lines = new_text.splitlines()
        self.assertEqual(lines[lines.index(rc3_port.BANNER) + 1],
                         rc3_port.BUILD_ID)
        for d in dropped:
            self.assertTrue(d.startswith(";;"))
        for kv in SYNTH_INI_KV:
            self.assertIn(kv, new_text)
        packed = len(zlib.compress(new_text.encode("latin1"), 9))
        self.assertLessEqual(packed, size - rc3_port.HEADROOM_MIN)


@pytest.mark.slow
class TestRealBase(unittest.TestCase):
    def setUp(self):
        if not RI.exists():
            raise unittest.SkipTest("refs/fw/cx-5-6/dumps/cx5-rom-2026-11-15 not present")

    def test_ri_stock_md5(self):
        import hashlib
        self.assertEqual(hashlib.md5(RI.read_bytes()).hexdigest(), rc3_port.RI_MD5)

    def test_verify_base_real(self):
        v = rc3_port.verify_base(RI.read_bytes())
        self.assertEqual(v["reasons"], [])
        self.assertTrue(v["ok"])

    def test_build_real_deterministic_whitelist(self):
        import hashlib
        base = RI.read_bytes()
        out = rc3_port.build(base)
        self.assertEqual(hashlib.md5(out).hexdigest(),
                         hashlib.md5(rc3_port.build(base)).hexdigest())
        bimg = mlxfwutil.Image(base, "ri")
        fimg = mlxfwutil.Image(out, "built")
        self.assertEqual(mlxfwutil.verify_image(fimg, deep=True), [])
        status, _, _ = mlxfwutil.sig_status(fimg)
        self.assertEqual(status, "fresh")
        want = sorted([rc3_port.HOOK_DC]
                      + [rc3_port.STUB_DC + 4 * i for i in range(23)])
        dg = rc3_port.diff_gate(bimg, out, sorted({dc // 64 for dc in want}))
        self.assertEqual(dg["stray"], [])
        self.assertEqual(dg["section_diff"], ["ITOC 0x03", "ITOC 0x30",
                                              "ITOC 0xA0"])
        be = bimg.find_entry("ITOC", 0x03)
        bcode, _ = mlxfwutil.clcrc_unwrap(bimg.section_data(be))
        self.assertEqual(struct.unpack_from(">I", bcode, 0x25A3EC)[0],
                         0x0011001F)
