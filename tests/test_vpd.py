import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402

import mlxfwutil  # noqa: E402
from mlxfwutil import DTOC_HDR, FS4_MAGIC, ITOC_HDR, Image, crc16_mlx  # noqa: E402

from test_mlxfwutil import REPO  # noqa: E402
from test_repack_resize import (_assert_outside_identity, _fs3_synth,  # noqa: E402
                                _payload, _run)
from test_sign import SynthMixin  # noqa: E402

LX_C1 = REPO / "refs" / "fw" / "cx-4" / "dumps" / "lx_c1_pre_gen4-20260919.bin"
E0_PRE = REPO / "refs" / "fw" / "cx-5-6" / "dumps" / "e0_pre_raw.bin"

# fs3: rel-блок + dev-хвост (0xE3 VPD_R0 dev=1, как на lx_c1: 0x78 @0xff8140)
FS3_VPD_LAYOUT = [
    (0x05, 0x10000, 0x100, 1, 0),
    (0x30, 0x20000, 0x80, 1, 0),
    (0xA0, 0x21000, 0x40, 1, 0),
    (0xE3, 0x40000, 0x78, 0, 1),
    (0xE0, 0x41000, 0x140, 0, 1),
]

FS3_NO_VPD_LAYOUT = [
    (0x05, 0x10000, 0x100, 1, 0),
    (0xA0, 0x21000, 0x40, 1, 0),
    (0xE0, 0x40000, 0x140, 0, 1),
]

FS3_EMPTY_VPD_LAYOUT = [
    (0x05, 0x10000, 0x100, 1, 0),
    (0xA0, 0x21000, 0x40, 1, 0),
    (0xE3, 0x40000, 0, 0, 1),
    (0xE0, 0x41000, 0x140, 0, 1),
]

FS4_ITOC_LAYOUT = [
    (0x08, 0x2000, 0x100),
    (0xA0, 0x2100, 0x40),
]

FS4_DEVINFO_ADDR = 0x30000
FS4_VPD_ADDR = 0x40000
FS4_VPD_SIZE = 0x78


def _fs4_vpd_synth(itoc_sections, vpd_addr=FS4_VPD_ADDR, vpd_size=FS4_VPD_SIZE,
                   devinfo_addr=FS4_DEVINFO_ADDR, bufsize=0x50000):
    # по образцу _fs4_synth (test_repack_resize), DTOC расширен строкой 0xE3
    m = SynthMixin()
    buf = bytearray(b"\xff" * bufsize)
    buf[0:16] = FS4_MAGIC
    rows, data = [], []
    for i, (t, addr, size) in enumerate(itoc_sections):
        if t == 0xA0:
            d = m._sig_data(slot=b"\x11" * 32)[:size]
            rows.append(m._toc_ent(0xA0, size, addr, crcf=1))
        else:
            d = _payload(i, size)
            rows.append(m._toc_ent(t, size, addr, sec_crc=crc16_mlx(d)))
        data.append((addr, d))
    rows.append(m._toc_ent(0xFF, 0, 0))
    buf[0x1000:0x1020] = m._toc_hdr(ITOC_HDR, len(rows) - 1)
    for i, row in enumerate(rows):
        buf[0x1020 + i * 32:0x1040 + i * 32] = row
    vpd = _payload(0xA3, vpd_size)
    drows = [m._toc_ent(0xE1, 0x40, devinfo_addr, crcf=2),
             m._toc_ent(0xE3, vpd_size, vpd_addr, sec_crc=crc16_mlx(vpd)),
             m._toc_ent(0xFF, 0, 0)]
    buf[0x1100:0x1120] = m._toc_hdr(DTOC_HDR, len(drows) - 1)
    for i, row in enumerate(drows):
        buf[0x1120 + i * 32:0x1140 + i * 32] = row
    for addr, d in data:
        buf[addr:addr + len(d)] = d
    buf[devinfo_addr:devinfo_addr + 0x40] = m._devinfo()
    buf[vpd_addr:vpd_addr + vpd_size] = vpd
    return bytes(buf)


class TestVpdCore(unittest.TestCase):
    """vpd_section/replace_vpd на fast-синтетике: FS3 0xE3 dev=1 в ITOC,
    FS4 0xE3 в DTOC; same-size replace с CRC-обвязкой; отказы класса
    {size=0, size-mismatch, нет секции} до любых записей."""

    def _fs3(self):
        return Image(_fs3_synth(FS3_VPD_LAYOUT), "synth")

    def _fs4(self):
        return Image(_fs4_vpd_synth(FS4_ITOC_LAYOUT), "synth4")

    def test_fs3_vpd_section_resolves_itoc(self):
        toc, e = mlxfwutil.vpd_section(self._fs3())
        self.assertEqual(toc, "ITOC")
        self.assertEqual((e.type, e.size, e.dev), (0xE3, 0x78, 1))

    def test_fs4_vpd_section_resolves_dtoc(self):
        toc, e = mlxfwutil.vpd_section(self._fs4())
        self.assertEqual(toc, "DTOC")
        self.assertEqual((e.type, e.size), (0xE3, 0x78))

    def test_missing_section_keyerror(self):
        img = Image(_fs3_synth(FS3_NO_VPD_LAYOUT), "synth")
        with self.assertRaises(KeyError):
            mlxfwutil.vpd_section(img)

    def test_fs3_replace_same_data_identical(self):
        img = self._fs3()
        _, e = mlxfwutil.vpd_section(img)
        out = mlxfwutil.replace_vpd(img, img.section_data(e))
        self.assertEqual(out, img.buf)
        self.assertEqual(mlxfwutil.verify_image(Image(out, "out")), [])

    def test_fs3_replace_modified_crc_changed(self):
        img = self._fs3()
        _, e = mlxfwutil.vpd_section(img)
        mod = _payload(0x77, e.size)
        out = mlxfwutil.replace_vpd(img, mod)
        vimg = Image(out, "out")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        ne = vimg.find_entry("ITOC", 0xE3)
        self.assertEqual(vimg.section_data(ne), mod)
        self.assertNotEqual(ne.sec_crc, e.sec_crc)
        self.assertNotEqual(ne.entry_crc, e.entry_crc)
        row = img.itoc_off + 32 + e.index * 32, img.itoc_off + 32 + (e.index + 1) * 32
        _assert_outside_identity(
            self, img.buf, out,
            [(img.sec_abs(e), img.sec_abs(e) + e.size), row])

    def test_fs4_replace_dtoc_verify_pass(self):
        img = self._fs4()
        _, e = mlxfwutil.vpd_section(img)
        mod = _payload(0xB5, e.size)
        out = mlxfwutil.replace_vpd(img, mod)
        vimg = Image(out, "out")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        ne = vimg.find_entry("DTOC", 0xE3)
        self.assertEqual(vimg.section_data(ne), mod)
        self.assertNotEqual(ne.entry_crc, e.entry_crc)
        row = img.dtoc_off + 32 + e.index * 32, img.dtoc_off + 32 + (e.index + 1) * 32
        _assert_outside_identity(
            self, img.buf, out,
            [(img.sec_abs(e), img.sec_abs(e) + e.size), row])

    def test_replace_size_mismatch_refused(self):
        img = self._fs3()
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.replace_vpd(img, b"\x00" * 0x10)
        self.assertIn("size", str(cm.exception))

    def test_replace_empty_section_refused(self):
        img = Image(_fs3_synth(FS3_EMPTY_VPD_LAYOUT), "synth")
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.replace_vpd(img, b"\x00" * 0x10)
        self.assertIn("empty", str(cm.exception))

    def test_replace_refusal_writes_nothing(self):
        img = self._fs3()
        with self.assertRaises(ValueError):
            mlxfwutil.replace_vpd(img, b"\x00" * 0x10)


class TestVpdCLI(unittest.TestCase):
    """CLI vpd IMAGE [--dump FILE] | [--set FILE -o OUT]: extract обоих
    поколений, replace с self-verify (прецедент cmd_patch), отказы rc 2
    до записи output."""

    def test_dump_fs3(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, dumpp = Path(td) / "m.bin", Path(td) / "vpd.bin"
            imgp.write_bytes(_fs3_synth(FS3_VPD_LAYOUT))
            rc, _, err = _run(["vpd", str(imgp), "--dump", str(dumpp)])
            self.assertEqual(rc, 0, err)
            img = Image(imgp.read_bytes(), "m")
            self.assertEqual(dumpp.read_bytes(), img.section_data(
                mlxfwutil.vpd_section(img)[1]))

    def test_dump_fs4(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, dumpp = Path(td) / "m.bin", Path(td) / "vpd.bin"
            imgp.write_bytes(_fs4_vpd_synth(FS4_ITOC_LAYOUT))
            rc, _, err = _run(["vpd", str(imgp), "--dump", str(dumpp)])
            self.assertEqual(rc, 0, err)
            img = Image(imgp.read_bytes(), "m")
            self.assertEqual(dumpp.read_bytes(), img.section_data(
                mlxfwutil.vpd_section(img)[1]))

    def test_set_same_roundtrip_identical(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, dumpp, outp = (Path(td) / n for n in ("m.bin", "vpd.bin", "o.bin"))
            imgp.write_bytes(_fs3_synth(FS3_VPD_LAYOUT))
            rc, _, err = _run(["vpd", str(imgp), "--dump", str(dumpp)])
            self.assertEqual(rc, 0, err)
            rc, _, err = _run(["vpd", str(imgp), "--set", str(dumpp),
                               "-o", str(outp)])
            self.assertEqual(rc, 0, err)
            self.assertEqual(outp.read_bytes(), imgp.read_bytes())

    def test_set_modified_self_verify_pass(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, dumpp, modp, outp = (Path(td) / n for n in
                                       ("m.bin", "vpd.bin", "mod.bin", "o.bin"))
            imgp.write_bytes(_fs4_vpd_synth(FS4_ITOC_LAYOUT))
            rc, _, err = _run(["vpd", str(imgp), "--dump", str(dumpp)])
            self.assertEqual(rc, 0, err)
            data = bytearray(dumpp.read_bytes())
            data[0] ^= 0x5A
            modp.write_bytes(bytes(data))
            rc, _, err = _run(["vpd", str(imgp), "--set", str(modp),
                               "-o", str(outp)])
            self.assertEqual(rc, 0, err)
            rc, out, _ = _run(["verify", str(outp)])
            self.assertEqual(rc, 0)
            self.assertIn("RESULT: PASS", out)

    def test_set_size_mismatch_rc2_no_output(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, modp, outp = (Path(td) / n for n in ("m.bin", "mod.bin", "o.bin"))
            imgp.write_bytes(_fs3_synth(FS3_VPD_LAYOUT))
            modp.write_bytes(b"\x00" * 0x10)
            rc, _, err = _run(["vpd", str(imgp), "--set", str(modp),
                               "-o", str(outp)])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("error:", err)
            self.assertIn("size", err)

    def test_set_empty_section_rc2(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, modp, outp = (Path(td) / n for n in ("m.bin", "mod.bin", "o.bin"))
            imgp.write_bytes(_fs3_synth(FS3_EMPTY_VPD_LAYOUT))
            modp.write_bytes(b"\x00" * 0x10)
            rc, _, err = _run(["vpd", str(imgp), "--set", str(modp),
                               "-o", str(outp)])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("error:", err)
            self.assertIn("empty", err)

    def test_no_section_rc2(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, dumpp = Path(td) / "m.bin", Path(td) / "vpd.bin"
            imgp.write_bytes(_fs3_synth(FS3_NO_VPD_LAYOUT))
            rc, _, err = _run(["vpd", str(imgp), "--dump", str(dumpp)])
            self.assertEqual(rc, 2)
            self.assertFalse(dumpp.exists())
            self.assertIn("error:", err)

    def test_set_requires_output_rc2(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, modp = Path(td) / "m.bin", Path(td) / "mod.bin"
            imgp.write_bytes(_fs3_synth(FS3_VPD_LAYOUT))
            modp.write_bytes(_payload(1, 0x78))
            rc, _, err = _run(["vpd", str(imgp), "--set", str(modp)])
            self.assertEqual(rc, 2)
            self.assertIn("error:", err)


class TestVpdRefsFs3(unittest.TestCase):
    """slow roundtrip на lx_c1-дампе (FS3 ITOC 0xE3 0x78): только
    структура/CRC/roundtrip, без ассертов на значения полей VPD."""

    @classmethod
    def setUpClass(cls):
        if not LX_C1.is_file():
            raise unittest.SkipTest(f"refs image not present: {LX_C1.name}")

    @pytest.mark.slow
    def test_lx_c1_roundtrip_same_identical(self):
        with tempfile.TemporaryDirectory() as td:
            dumpp, outp = Path(td) / "vpd.bin", Path(td) / "o.bin"
            rc, _, err = _run(["vpd", str(LX_C1), "--dump", str(dumpp)])
            self.assertEqual(rc, 0, err)
            rc, _, err = _run(["vpd", str(LX_C1), "--set", str(dumpp),
                               "-o", str(outp)])
            self.assertEqual(rc, 0, err)
            self.assertEqual(outp.read_bytes(), LX_C1.read_bytes())
            rc, out, _ = _run(["verify", str(outp)])
            self.assertEqual(rc, 0)
            self.assertIn("RESULT: PASS", out)

    @pytest.mark.slow
    def test_lx_c1_replace_modified_verify_pass(self):
        with tempfile.TemporaryDirectory() as td:
            dumpp, modp, outp = (Path(td) / n for n in
                                 ("vpd.bin", "mod.bin", "o.bin"))
            rc, _, err = _run(["vpd", str(LX_C1), "--dump", str(dumpp)])
            self.assertEqual(rc, 0, err)
            data = bytearray(dumpp.read_bytes())
            data[0] ^= 0x5A
            modp.write_bytes(bytes(data))
            rc, _, err = _run(["vpd", str(LX_C1), "--set", str(modp),
                               "-o", str(outp)])
            self.assertEqual(rc, 0, err)
            rc, out, _ = _run(["verify", str(outp)])
            self.assertEqual(rc, 0)
            self.assertIn("RESULT: PASS", out)


class TestVpdRefsFs4(unittest.TestCase):
    """slow roundtrip на e0_pre_raw (FS4 DTOC 0xE3 0xcc): только
    структура/CRC/roundtrip, без ассертов на значения полей VPD."""

    @classmethod
    def setUpClass(cls):
        if not E0_PRE.is_file():
            raise unittest.SkipTest(f"refs image not present: {E0_PRE.name}")

    @pytest.mark.slow
    def test_e0_roundtrip_same_identical(self):
        with tempfile.TemporaryDirectory() as td:
            dumpp, outp = Path(td) / "vpd.bin", Path(td) / "o.bin"
            rc, _, err = _run(["vpd", str(E0_PRE), "--dump", str(dumpp)])
            self.assertEqual(rc, 0, err)
            rc, _, err = _run(["vpd", str(E0_PRE), "--set", str(dumpp),
                               "-o", str(outp)])
            self.assertEqual(rc, 0, err)
            self.assertEqual(outp.read_bytes(), E0_PRE.read_bytes())
            rc, out, _ = _run(["verify", str(outp)])
            self.assertEqual(rc, 0)
            self.assertIn("RESULT: PASS", out)

    @pytest.mark.slow
    def test_e0_replace_modified_verify_pass(self):
        with tempfile.TemporaryDirectory() as td:
            dumpp, modp, outp = (Path(td) / n for n in
                                 ("vpd.bin", "mod.bin", "o.bin"))
            rc, _, err = _run(["vpd", str(E0_PRE), "--dump", str(dumpp)])
            self.assertEqual(rc, 0, err)
            data = bytearray(dumpp.read_bytes())
            data[0] ^= 0x5A
            modp.write_bytes(bytes(data))
            rc, _, err = _run(["vpd", str(E0_PRE), "--set", str(modp),
                               "-o", str(outp)])
            self.assertEqual(rc, 0, err)
            rc, out, _ = _run(["verify", str(outp)])
            self.assertEqual(rc, 0)
            self.assertIn("RESULT: PASS", out)


if __name__ == "__main__":
    unittest.main()
