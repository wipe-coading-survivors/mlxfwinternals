import sys
import tempfile
import unittest
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-arc-d"))

import build_l1l2  # noqa: E402

import mlxfwutil  # noqa: E402
from mlxfwutil import CNTX_MAGIC, ITOC_HDR, Image, crc16_mlx, set_bits  # noqa: E402

from scripts.irisc import AsmError  # noqa: E402


# Step-1-derived expectations (docs/superpowers/journal/
# 2026-11-12-serdes-arc-d-task-01.md §1.4): bit6=0x40 is 56G, bit7=0x80 is
# 100G on the Lx family; anchors: CX-4 MCX456A-FCA 0x5b (bit6 set), CX-4
# MCX416A-CCA / MCX455A-ECA 0xbb (bit7 set), MCX456A-ECA 0xfb (both bits),
# Lx 1p stock GCA 0x3b; discriminators 0x7b (T5) / 0xbb (T4) from
# docs/superpowers/journal/2026-10-06-cx4lx-qsfp28-ib.md:785-805.
class TestDeriveLclBits(unittest.TestCase):
    def test_56g_from_stock(self):
        self.assertEqual(build_l1l2.derive_lcl_bits(0x3b, "56G"), 0x7b)

    def test_100g_cumulative(self):
        l1 = build_l1l2.derive_lcl_bits(0x3b, "56G")
        self.assertEqual(build_l1l2.derive_lcl_bits(l1, "100G"), 0xfb)

    def test_cumulative_chain_equals_one_shot(self):
        chain = build_l1l2.derive_lcl_bits(
            build_l1l2.derive_lcl_bits(0x3b, "56G"), "100G")
        self.assertEqual(chain, 0x3b | build_l1l2.validate_mask(0xC0))

    def test_100g_from_stock_matches_cx4_reference(self):
        self.assertEqual(build_l1l2.derive_lcl_bits(0x3b, "100G"), 0xbb)

    def test_idempotent_when_bit_already_set(self):
        self.assertEqual(build_l1l2.derive_lcl_bits(0x7b, "56G"), 0x7b)

    def test_invalid_feature_raises_asm_error_class(self):
        for bad in ("200G", "56g", "", "IB"):
            with self.assertRaises(AsmError):
                build_l1l2.derive_lcl_bits(0x3b, bad)

    def test_invalid_lcl_value_raises(self):
        for bad in (-1, 0x100, 0x1000):
            with self.assertRaises(AsmError):
                build_l1l2.derive_lcl_bits(bad, "56G")


class TestValidateMask(unittest.TestCase):
    def test_known_masks(self):
        self.assertEqual(build_l1l2.validate_mask(0x40), 0x40)
        self.assertEqual(build_l1l2.validate_mask(0x80), 0x80)
        self.assertEqual(build_l1l2.validate_mask(0xC0), 0xC0)

    def test_invalid_masks_raise(self):
        for bad in (0x00, 0x20, 0x01, 0x100, 0xFF & ~0xC0 | 0x04):
            with self.assertRaises(AsmError):
                build_l1l2.validate_mask(bad)


# Synthetic FS3 fixture modeled after the GCA-1912 base layout (tests/
# test_sign.py SynthMixin style): ITOC @0x1000 with FW_MAIN_CFG 0x12 (lcl
# pair at +0x30b/+0x317 like the real layout), DBG_FW_INI 0x30 (zlib ini
# with the Mellanox anchor + PRS speed lines), SIG_256 0xA0 with a stale
# 32B digest slot.
FIX_OFF_12 = 0x2000
FIX_OFF_A0 = 0x2C00
FIX_OFF_30 = 0x2D00
FIX_OFF_E1 = 0x3200
FIX_OFF_E0 = 0x3300
FIX_SIZE_30 = 0x400

FIX_INI = "\n".join([
    ";; Generated automatically by iniprep tool",
    "",
    ";; Mellanox Technologies LTD",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed1Gb   = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed10Gb  = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed20Gb  = 0x0",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed25Gb  = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed40Gb  = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed50Gb  = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed56Gb  = 0x0",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed100Gb = 0x0",
])

BUILD_ID = ("; mlxini test L1 (2026-11-12, journal"
            " 2026-11-12-serdes-arc-d-task-01): lcl[0] patch")


def _toc_hdr(nent):
    h = bytearray(32)
    h[0:16] = ITOC_HDR
    set_bits(h, 184, 8, nent)
    set_bits(h, 240, 16, crc16_mlx(bytes(h[:28])))
    return bytes(h)


def _toc_ent(t, size, addr, sec_crc, rel=1, dev=0):
    r = bytearray(32)
    set_bits(r, 0, 8, t)
    set_bits(r, 8, 22, size // 4)
    set_bits(r, 161, 29, addr // 4)
    set_bits(r, 160, 1, rel)
    set_bits(r, 206, 1, dev)
    set_bits(r, 208, 16, sec_crc)
    set_bits(r, 240, 16, crc16_mlx(bytes(r[:28])))
    return bytes(r)


def _fs3_fixture():
    buf = bytearray(0x10000)
    buf[0:16] = CNTX_MAGIC
    buf[0x24] = 3
    sec12 = bytearray(0xC00)
    for i in range(len(sec12)):
        sec12[i] = (i * 11 + 5) & 0xFF
    sec12[0x30B] = 0x3B
    sec12[0x317] = 0x00
    sig = bytearray(0x40)
    sig[0x00:0x10] = b"\x00" * 16
    sig[0x10:0x20] = b"\x00" * 16
    sig[0x20:0x40] = b"\x22" * 32
    ini30 = zlib.compress(FIX_INI.encode("latin1"), 9)
    ini30 += b"\x00" * (FIX_SIZE_30 - len(ini30))
    dev = bytes(0x40)
    ents = [
        _toc_ent(0x12, len(sec12), FIX_OFF_12, crc16_mlx(bytes(sec12))),
        _toc_ent(0xA0, 0x40, FIX_OFF_A0, crc16_mlx(bytes(sig))),
        _toc_ent(0x30, len(ini30), FIX_OFF_30, crc16_mlx(ini30)),
        _toc_ent(0xE1, 0x40, FIX_OFF_E1, crc16_mlx(dev), rel=0, dev=1),
        _toc_ent(0xE0, 0x40, FIX_OFF_E0, crc16_mlx(dev), rel=0, dev=1),
        _toc_ent(0xFF, 0, 0, 0),
    ]
    buf[0x1000:0x1020] = _toc_hdr(len(ents) - 1)
    for i, ent in enumerate(ents):
        buf[0x1020 + i * 32:0x1040 + i * 32] = ent
    buf[FIX_OFF_12:FIX_OFF_12 + len(sec12)] = sec12
    buf[FIX_OFF_A0:FIX_OFF_A0 + 0x40] = sig
    buf[FIX_OFF_30:FIX_OFF_30 + len(ini30)] = ini30
    buf[FIX_OFF_E1:FIX_OFF_E1 + 0x40] = dev
    buf[FIX_OFF_E0:FIX_OFF_E0 + 0x40] = dev
    return bytes(buf), bytes(sec12), bytes(sig)


class TestBuildImage(unittest.TestCase):
    def setUp(self):
        self.base, self.sec12, self.sig = _fs3_fixture()
        self.img = Image(self.base, "fixture")

    def _entry_off(self, typ):
        e = self.img.find_entry("ITOC", typ)
        return self.img.itoc_off + 32 + e.index * 32

    def test_l2_patch_on_synthetic(self):
        res = build_l1l2.build_image(self.base, 0xC0, BUILD_ID)
        out, zones = res.final, res.zones
        self.assertEqual(out[FIX_OFF_12 + 0x30B], 0xFB)
        self.assertEqual(out[FIX_OFF_12 + 0x317], 0x00)
        vimg = Image(out, "out")
        self.assertFalse(mlxfwutil.verify_image(vimg, deep=True))

    def test_stock_guard_rejects_patched_base(self):
        patched = bytearray(self.base)
        patched[FIX_OFF_12 + 0x30B] = 0x7B
        with self.assertRaises(AsmError):
            build_l1l2.build_image(bytes(patched), 0x80, BUILD_ID)

    def test_prs_guard_rejects_56g_ini(self):
        bad_ini = FIX_INI.replace("Speed56Gb  = 0x0", "Speed56Gb  = 0x1")
        buf = bytearray(self.base)
        data = zlib.compress(bad_ini.encode("latin1"), 9)
        data += b"\x00" * (FIX_SIZE_30 - len(data))
        buf[FIX_OFF_30:FIX_OFF_30 + 0x400] = b"\x00" * 0x400
        buf[FIX_OFF_30:FIX_OFF_30 + len(data)] = data
        ent = bytearray(self.img.find_entry("ITOC", 0x30).raw)
        set_bits(ent, 8, 22, len(data) // 4)
        set_bits(ent, 208, 16, crc16_mlx(data))
        set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
        off = self._entry_off(0x30)
        buf[off:off + 32] = ent
        with self.assertRaises(AsmError):
            build_l1l2.build_image(bytes(buf), 0x40, BUILD_ID)

    def test_build_id_injected_after_anchor(self):
        out = build_l1l2.build_image(self.base, 0x40, BUILD_ID).final
        img = Image(out, "out")
        ini = zlib.decompress(mlxfwutil.extract_section(img, 0x30))
        text = ini.decode("latin1")
        anchor = text.index(";; Mellanox Technologies LTD")
        marker = text.index(BUILD_ID)
        self.assertGreater(marker, anchor)
        self.assertIn(BUILD_ID, text.split("\n"))

    def test_expected_zones_cover_actual_diff(self):
        res = build_l1l2.build_image(self.base, 0xC0, BUILD_ID)
        out, zones = res.final, res.zones
        diffs = {i for i in range(len(out)) if out[i] != self.base[i]}
        stray = diffs - zones
        self.assertEqual(stray, set())
        self.assertIn(FIX_OFF_12 + 0x30B, diffs)
        ent12 = set(range(self._entry_off(0x12) + 0x1A, self._entry_off(0x12) + 0x20))
        self.assertTrue(diffs & ent12)

    def test_sign_step_fresh_after_build(self):
        out = build_l1l2.build_image(self.base, 0xC0, BUILD_ID).final
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "img.bin"
            p.write_bytes(out)
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                rc = mlxfwutil.main(["sign", str(p)])
            self.assertEqual(rc, 0)
            signed = p.read_bytes()
            img = Image(signed, "signed")
            status, _, _ = mlxfwutil.sig_status(img)
            self.assertEqual(status, "fresh")
            self.assertFalse(mlxfwutil.verify_image(img, deep=True))
            digest_zone = set(range(FIX_OFF_A0 + 0x20, FIX_OFF_A0 + 0x40))
            ent = self.img.find_entry("ITOC", 0xA0)
            eo = self.img.itoc_off + 32 + ent.index * 32
            digest_zone |= {eo + 0x1A, eo + 0x1B, eo + 0x1E, eo + 0x1F}
            diffs = {i for i in range(len(signed)) if signed[i] != out[i]}
            self.assertLessEqual(diffs, digest_zone)
            self.assertTrue(diffs & digest_zone)


class TestFeatureBitsConstants(unittest.TestCase):
    def test_feature_bits_match_doc015_map(self):
        self.assertEqual(build_l1l2.FEATURE_BITS, {"56G": 0x40, "100G": 0x80})

    def test_lcl_offsets_match_field_map3(self):
        self.assertEqual(build_l1l2.LCL0_OFF, 0x30B)
        self.assertEqual(build_l1l2.LCL1_OFF, 0x317)


if __name__ == "__main__":
    unittest.main()
