import argparse
import hashlib
import os
import sys
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mlxfwutil  # noqa: E402
from mlxfwutil import (CNTX_MAGIC, DTOC_HDR, FS4_MAGIC, ITOC_HDR, Image, SLOT_SIZE,
                    _flash_layout, _image, ab_devtail, ab_devtail_fs4, ab_diff,
                    ab_state, ab_truncated, crc16_mlx, detect_slot,
                    diff_sections, extract_section, image_info_fields,
                    inject_ini, merge_fields, merge_section, parse_set_spec,
                    patch_sections, repack, set_bits, set_psid, swap_repack)

import pytest  # noqa: E402

pytestmark = pytest.mark.slow

REPO = Path(__file__).resolve().parent.parent
DELL = REPO / "refs" / "fw" / "cx-5-6" / (
    "fw-ConnectX5-rel-16_27_6120-09FTMY_071C1T_Ax-UEFI-14.20.27-FlexBoot-3.5.903.signed.bin")
HPE = REPO / "refs" / "fw" / "cx-5-6" / (
    "fw-ConnectX5-rel-16_35_4030-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin")
FW = REPO / "refs" / "fw" / "cx-5-6"
DUMPS = FW / "dumps"
CX6DX_IMG0 = FW / "bazzite-img0-22.50.1002-guides.bin"
REFDUMPS = REPO / "refs" / "dumps"
ADA1012 = FW / "fw-ConnectX5-rel-16_35_1012-MCX512A-ADA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin"
D1RAW = DUMPS / "d1_raw.bin"
ACA8008 = FW / "fw-ConnectX5-rel-16_35_8008-MCX512A-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin"
EDA1012 = FW / "fw-ConnectX5-rel-16_35_1012-MCX556A-EDA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin"
ECA8008 = FW / "fw-ConnectX5-rel-16_35_8008-MCX556A-ECA_Ax-UEFI-14.29.15-FlexBoot-3.6.902.bin"
ADA8008 = FW / "fw-ConnectX5-rel-16_35_8008-MCX512A-ADA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin"
FW4 = REPO / "refs" / "fw" / "cx-4"
ACA1912 = FW4 / "fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"
BCA1912 = FW4 / "fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-BCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"
GCA1912 = FW4 / "fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"
E455_2302 = FW4 / "fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-UEFI-14.21.17-FlexBoot-3.6.102.bin"
E456_4706 = FW4 / "fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"
F456_4706 = FW4 / "fw-ConnectX4-rel-12_28_4706-MCX456A-FCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin"
FS3_ALL = (ACA1912, BCA1912, GCA1912, E455_2302, E456_4706, F456_4706)
FS2_IMG = (REPO / "refs" / "fw" /
           "Update_HP_0F60000010_Branded_Mellanox_ConnectX-2_MT26448_for_RDMA" /
           "Update_HP_0F60000010_Branded_Mellanox_ConnectX-2_MT26448_for_RDMA" /
           "firmware-image.bin")


class Fw4Mixin:
    @classmethod
    def setUpClass(cls):
        if not all(p.is_file() for p in FS3_ALL):
            raise unittest.SkipTest("refs/fw/cx-4 images not present")


def slot_b_fs3(src: bytes) -> bytes:
    img = Image(src, "src")
    buf = bytearray(b"\xff" * 16 * 1024 * 1024)
    buf[SLOT_SIZE:SLOT_SIZE + 0x4000] = src[0:0x4000]
    for e in img.entries("ITOC"):
        if e.rel:
            buf[e.addr + SLOT_SIZE:e.addr + SLOT_SIZE + e.size] = src[e.addr:e.addr + e.size]
        elif e.size:
            buf[e.addr:e.addr + e.size] = src[e.addr:e.addr + e.size]
    return bytes(buf)


ROUND_TRIP_PAIRS = [
    ("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin",
     "refs/fw/cx-4/MCX4121A-ACA_Ax-dc.ini"),
    ("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-BCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin",
     "refs/fw/cx-4/MCX4131A-BCA_Ax-dc.ini"),
    ("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin",
     "refs/fw/cx-4/MCX4131A-GCA_Ax-dc.ini"),
    ("refs/fw/cx-4/fw-ConnectX4-rel-12_28_2302-MCX455A-ECA_Ax-UEFI-14.21.17-FlexBoot-3.6.102.bin",
     "refs/fw/cx-4/MCX455A-ECA_Ax-dc.ini"),
    ("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin",
     "refs/fw/cx-4/MCX456A-ECA_Ax-dc.ini"),
    ("refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-FCA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin",
     "refs/fw/cx-4/MCX456A-FCA_Ax-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX512A-ADA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin",
     "refs/fw/cx-5-6/MCX512A-ADA_Ax_Bx-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX516A-CDA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin",
     "refs/fw/cx-5-6/MCX516A-CDA_Ax_Bx-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX546A-EDAN_Ax-UEFI-14.28.15-FlexBoot-3.6.804.bin",
     "refs/fw/cx-5-6/MCX546A-EDAN_Ax-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX556A-ECA_Ax-UEFI-14.28.15-FlexBoot-3.6.804.bin",
     "refs/fw/cx-5-6/MCX556A-ECA_Ax-1012-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX556A-ECU_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin",
     "refs/fw/cx-5-6/MCX556A-ECU_Ax_Bx-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX556A-EDA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin",
     "refs/fw/cx-5-6/MCX556A-EDA_Ax_Bx-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512A-ADA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin",
     "refs/fw/cx-5-6/MCX512A-ADA_Ax_Bx-8008-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512F-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin",
     "refs/fw/cx-5-6/MCX512F-ACA_Ax_Bx-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX546A-CDAN_Ax-UEFI-14.29.15-FlexBoot-3.6.902.bin",
     "refs/fw/cx-5-6/MCX546A-CDAN_Ax-8008-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX556A-ECA_Ax-UEFI-14.29.15-FlexBoot-3.6.902.bin",
     "refs/fw/cx-5-6/MCX556A-ECA_Ax-8008-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX6-rel-20_43_1014-MCX654105A-HCA_Ax-UEFI-14.36.16-FlexBoot-3.7.500.bin",
     "refs/fw/cx-5-6/MCX654105A-HCA_Ax-dc.ini"),
    ("refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AE-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.bin",
     "refs/fw/cx-5-6/MCX623435AE-CDA_Ax-dc.ini"),
]


def _mini_fs3(dev_addr: int = 0x10000) -> tuple:
    # Минимальный FS3: маг + version word + ITOC (0x30, 0x32, dev 0xE0, END)
    buf = bytearray(b"\xff" * 0x20000)
    buf[0:16] = CNTX_MAGIC
    buf[0x24:0x28] = b"\x03\x17\x01\x01"
    itoc = 0x1000
    hdr = bytearray(32)
    hdr[0:16] = ITOC_HDR
    hdr[0x1E:0x20] = struct.pack(">H", crc16_mlx(bytes(hdr[:28])))
    buf[itoc:itoc + 32] = hdr
    ini = b"[ADAPTER]\nPSID = MT_MINI\n"

    def entry(i, typ, size, addr, rel=1, dev=0, data=None):
        e = bytearray(32)
        e[0] = typ
        set_bits(e, 8, 22, size // 4)
        set_bits(e, 160, 1, rel)
        set_bits(e, 161, 29, addr // 4)
        set_bits(e, 206, 1, dev)
        if data is not None:
            buf[addr:addr + size] = data
        set_bits(e, 208, 16, crc16_mlx(bytes(buf[addr:addr + size])))
        set_bits(e, 240, 16, crc16_mlx(bytes(e[:28])))
        buf[itoc + 32 + i * 32:itoc + 64 + i * 32] = e

    entry(0, 0x30, 0x100, 0x2000, data=zlib.compress(ini, 9))
    entry(1, 0x32, 0x100, 0x2100, data=b"\x00" * 0x100)
    entry(2, 0xE0, 0x140, dev_addr, rel=0, dev=1, data=b"\x00" * 0x140)
    entry(3, 0xFF, 0, 0)
    return bytes(buf), ini


E1_SWAPS = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x18]

CODE_SECTIONS = [(0x02, 0, 0x2e140), (0x03, 0, 0x3d2220), (0x04, 0, 0x13cd0),
                 (0x05, 0, 0x15624), (0x06, 0, 0xb90), (0x07, 0, 0x1cc0),
                 (0x0a, 0, 0x9920), (0x0b, 0, 0x2c80), (0x0c, 0, 0x1e80),
                 (0x20, 0, 0x100)]


def _crc_ref(data: bytes) -> int:
    def step(crc, bit):
        msb = (crc >> 15) & 1
        crc = ((crc << 1) | bit) & 0xFFFF
        if msb:
            crc ^= 0x100B
        return crc
    crc = 0xFFFF
    for b in data:
        for i in range(7, -1, -1):
            crc = step(crc, (b >> i) & 1)
    for _ in range(16):
        crc = step(crc, 0)
    return crc ^ 0xFFFF


class RefsMixin:
    @classmethod
    def setUpClass(cls):
        if not (DELL.is_file() and HPE.is_file()):
            raise unittest.SkipTest("refs/fw images not present")


def hw_id(label, field):
    try:
        return int(mlxfwutil.hw(label, field), 16)
    except (FileNotFoundError, KeyError):
        raise unittest.SkipTest(f"hw registry value not present: {label}_{field}")


class TestCrc(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(crc16_mlx(b""), 0x0955)

    def test_cross_check_reference(self):
        for n in (1, 3, 4, 16, 100, 4096):
            for _ in range(20):
                d = os.urandom(n)
                self.assertEqual(crc16_mlx(d), _crc_ref(d))


class TestParse(RefsMixin, unittest.TestCase):
    def test_dell_toc(self):
        img = Image(DELL.read_bytes(), "dell")
        self.assertEqual(img.itoc_off, 0x4000)
        self.assertEqual(img.dtoc_off, 0xFFF000)
        self.assertEqual(len(img.entries("ITOC")), 25)
        self.assertEqual(len(img.entries("DTOC")), 7)
        e = img.find_entry("ITOC", 0x10)
        self.assertEqual(img.section_data(e)[0x24:0x34].split(b"\x00")[0], b"DEL0000000004")

    def test_hpe_toc(self):
        img = Image(HPE.read_bytes(), "hpe")
        self.assertEqual(img.itoc_off, 0x5000)
        self.assertEqual(len(img.entries("ITOC")), 25)
        e = img.find_entry("ITOC", 0x10)
        self.assertEqual(img.section_data(e)[0x24:0x34].split(b"\x00")[0], b"HPE0000000009")


class TestVerify(RefsMixin, unittest.TestCase):
    def test_verify_ok(self):
        self.assertEqual(mlxfwutil.cmd_verify(Image(DELL.read_bytes(), "dell")), 0)
        self.assertEqual(mlxfwutil.cmd_verify(Image(HPE.read_bytes(), "hpe")), 0)

    def test_verify_detects_section_corruption(self):
        buf = bytearray(HPE.read_bytes())
        src = Image(bytes(buf), "hpe")
        e = src.find_entry("ITOC", 0x12)
        buf[e.addr + 0x10] ^= 0xFF
        self.assertEqual(mlxfwutil.cmd_verify(Image(bytes(buf), "hpe")), 1)

    def test_verify_detects_entry_corruption(self):
        buf = bytearray(HPE.read_bytes())
        src = Image(bytes(buf), "hpe")
        e = src.find_entry("ITOC", 0x08)
        ent_off = src.itoc_off + 32 + e.index * 32
        buf[ent_off + 1] ^= 0xFF
        self.assertEqual(mlxfwutil.cmd_verify(Image(bytes(buf), "hpe")), 1)

    def test_info_smoke(self):
        self.assertEqual(mlxfwutil.cmd_info(Image(HPE.read_bytes(), "hpe")), 0)


class TestVerifyClcrc(RefsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        img = Image(HPE.read_bytes(), "hpe")
        cls.crc_secs = [e for e in img.entries("ITOC")
                        if e.clcrc and not e.zipped and e.size >= 68]
        if not cls.crc_secs:
            raise unittest.SkipTest("no clcrc=1 sections in HPE")

    def test_clcrc_lines_errors_unit(self):
        line = bytes(range(64)) + b"\x00\x00"
        raw = line + struct.pack("<H", mlxfwutil.clcrc_calc(line))
        self.assertEqual(mlxfwutil.clcrc_lines_errors(raw), [])
        bad = bytearray(raw)
        bad[3] ^= 0x01
        errs = mlxfwutil.clcrc_lines_errors(bytes(bad))
        self.assertEqual(len(errs), 1)
        self.assertEqual(errs[0][0], 0)
        self.assertEqual(errs[0][1], int.from_bytes(raw[66:68], "little"))

    def test_deep_clcrc_ok_stock(self):
        errs = mlxfwutil.verify_image(Image(HPE.read_bytes(), "hpe"), deep=True)
        self.assertEqual([x for x in errs if "clcrc" in x], [])

    def test_deep_clcrc_detects_corruption(self):
        buf = bytearray(HPE.read_bytes())
        img = Image(bytes(buf), "hpe")
        e = self.crc_secs[0]
        buf[img.sec_abs(e) + 1] ^= 0xFF
        errs = mlxfwutil.verify_image(Image(bytes(buf), "hpe"), deep=True)
        hits = [x for x in errs if "clcrc" in x]
        self.assertEqual(len(hits), 1)
        self.assertIn(f"ITOC[{e.index}]", hits[0])
        self.assertIn("line 0", hits[0])
        plain = mlxfwutil.verify_image(Image(bytes(buf), "hpe"))
        self.assertEqual([x for x in plain if "clcrc" in x], [])


class TestVerifySemantics(RefsMixin, unittest.TestCase):
    def _img(self):
        return Image(ADA1012.read_bytes(), "ada")

    def test_factory_green(self):
        self.assertEqual(mlxfwutil.verify_image(self._img()), [])

    def test_two_valid_devinfo_detected(self):
        b = bytearray(ADA1012.read_bytes())
        # скопировать валидный mDevInfo на второй слот → 2 валидных
        b[0xfe0000:0xfe0000 + 0x200] = b[0xfd0000:0xfd0000 + 0x200]
        img = Image(bytes(b), "x")
        errs = mlxfwutil.verify_image(img)
        self.assertTrue(any("DEV_INFO" in e for e in errs), errs)

    def test_no_valid_devinfo_detected(self):
        b = bytearray(ADA1012.read_bytes())
        b[0xfd0000:0xfd0010] = b"\x00" * 16  # сломать сигнатуру единственного
        img = Image(bytes(b), "x")
        errs = mlxfwutil.verify_image(img)
        self.assertTrue(any("DEV_INFO" in e for e in errs), errs)

    def test_insection_corruption_detected(self):
        b = bytearray(ADA1012.read_bytes())
        b[0xfd0000 + 0x50] ^= 0xFF  # VSD-область, внутри mDevInfo
        img = Image(bytes(b), "x")
        errs = mlxfwutil.verify_image(img)
        self.assertTrue(any("CRC" in e for e in errs), errs)

    def test_crcf1_ignored(self):
        img = self._img()
        # 0xE6 MTCF crcf=1 — порча данных не даёт section-CRC ошибки
        b = bytearray(img.buf)
        e6 = img.find_entry("DTOC", 0xE6)
        b[e6.addr + 4] ^= 0xFF
        errs = [e for e in mlxfwutil.verify_image(Image(bytes(b), "x")) if "0xE6" in e or "MTCF" in e]
        self.assertEqual(errs, [])


class TestExtract(RefsMixin, unittest.TestCase):
    def test_extract_0x30_dell_prs(self):
        img = Image(DELL.read_bytes(), "dell")
        data = extract_section(img, 0x30)
        self.assertEqual(data[:2], b"\x78\xda")
        ini = zlib.decompress(data)
        self.assertEqual(len(ini), 16556)
        self.assertEqual(ini, (REPO / "refs" / "fw" / "cx-5-6" / "cx5-09FTMY_071C1T-dell-dc.ini").read_bytes())

    def test_extract_0x30_hpe_prs(self):
        img = Image(HPE.read_bytes(), "hpe")
        ini = zlib.decompress(extract_section(img, 0x30))
        self.assertEqual(len(ini), 18416)
        self.assertEqual(ini, (REPO / "refs" / "fw" / "cx-5-6" / "cx5-872726-HP-dc.ini").read_bytes())

    def test_extract_raw_section(self):
        img = Image(HPE.read_bytes(), "hpe")
        e = img.find_entry("ITOC", 0x12)
        self.assertEqual(extract_section(img, 0x12), img.buf[e.addr:e.addr + e.size])

    def test_extract_missing_section(self):
        img = Image(HPE.read_bytes(), "hpe")
        with self.assertRaises(KeyError):
            extract_section(img, 0x01)

    def test_extract_cli_0x30(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "prs.ini"
            rc = mlxfwutil.cmd_extract(Image(DELL.read_bytes(), "dell"),
                                    argparse.Namespace(section=0x30, output=str(out), raw=False))
            self.assertEqual(rc, 0)
            self.assertEqual(out.read_bytes(),
                             (REPO / "refs" / "fw" / "cx-5-6" / "cx5-09FTMY_071C1T-dell-dc.ini").read_bytes())


class TestDiff(RefsMixin, unittest.TestCase):
    def setUp(self):
        self.a = Image(DELL.read_bytes(), "dell")
        self.b = Image(HPE.read_bytes(), "hpe")
        self.res = diff_sections(self.a, self.b)

    def by(self, toc, typ):
        for r in self.res:
            if r.toc == toc and r.type == typ:
                return r
        raise KeyError((toc, typ))

    def test_identical_sections(self):
        for t in (0x0A, 0x0C, 0x20, 0x32, 0xEB, 0xA1, 0xA2, 0xA4):
            self.assertEqual(self.by("ITOC", t).diff_bytes, 0, hex(t))

    def test_config_sizes_and_diffs(self):
        self.assertEqual((self.by("ITOC", 0x08).size_a, self.by("ITOC", 0x08).size_b), (0x140, 0x140))
        self.assertEqual(self.by("ITOC", 0x08).diff_bytes, 8)
        self.assertEqual((self.by("ITOC", 0x09).size_a, self.by("ITOC", 0x09).size_b), (0x1580, 0x980))
        self.assertEqual((self.by("ITOC", 0x11).size_a, self.by("ITOC", 0x11).size_b), (0x400, 0x4C0))
        self.assertEqual((self.by("ITOC", 0x12).size_a, self.by("ITOC", 0x12).size_b), (0xC00, 0xB00))
        self.assertEqual(self.by("ITOC", 0x10).diff_bytes, 141)
        self.assertEqual(self.by("ITOC", 0x0B).diff_bytes, 320)

    def test_annotation_marked(self):
        r = self.by("ITOC", 0x08)
        self.assertIn(0x23, [off for off, _ in r.annotations])


class TestPsid(RefsMixin, unittest.TestCase):
    def test_set_fields_and_crc(self):
        img = Image(HPE.read_bytes(), "hpe")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.bin"
            args = argparse.Namespace(image="hpe", psid="DEL0000000004",
                                      name="09FTMY_071C1T_Ax",
                                      description="Mellanox ConnectX-5 Ex Dual Port 100 GbE QSFP Network Adapter",
                                      output=str(out))
            self.assertEqual(mlxfwutil.cmd_psid(img, args), 0)
            check = Image(out.read_bytes(), "out")
            self.assertEqual(mlxfwutil.cmd_verify(check), 0)
            f = image_info_fields(check.section_data(check.find_entry("ITOC", 0x10)))
            self.assertEqual(f["psid"], "DEL0000000004")
            self.assertEqual(f["name"], "09FTMY_071C1T_Ax")
            self.assertEqual(f["description"],
                             "Mellanox ConnectX-5 Ex Dual Port 100 GbE QSFP Network Adapter")
            self.assertEqual(f["prod_ver"], "rel-16_35_4030")

    def test_noop_keeps_image_byte_identical(self):
        img = Image(HPE.read_bytes(), "hpe")
        f = image_info_fields(img.section_data(img.find_entry("ITOC", 0x10)))
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.bin"
            args = argparse.Namespace(image="hpe", psid=f["psid"], name=f["name"],
                                      description=f["description"], output=str(out))
            self.assertEqual(mlxfwutil.cmd_psid(img, args), 0)
            self.assertEqual(out.read_bytes(), HPE.read_bytes())

    def test_psid_too_long_rejected(self):
        img = Image(HPE.read_bytes(), "hpe")
        with tempfile.TemporaryDirectory() as td:
            args = argparse.Namespace(image="hpe", psid="X" * 17, name=None,
                                      description=None, output=str(Path(td) / "o.bin"))
            with self.assertRaises(ValueError):
                mlxfwutil.cmd_psid(img, args)

    def test_psid_requires_at_least_one_field(self):
        img = Image(HPE.read_bytes(), "hpe")
        with tempfile.TemporaryDirectory() as td:
            args = argparse.Namespace(image="hpe", psid=None, name=None,
                                      description=None, output=str(Path(td) / "o.bin"))
            self.assertEqual(mlxfwutil.cmd_psid(img, args), 2)

    def test_psid_slot_b_dump(self):
        if not D1RAW.is_file():
            raise unittest.SkipTest("d1_raw.bin not present")
        img = Image(D1RAW.read_bytes(), "d1", base=detect_slot(D1RAW.read_bytes()))
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "o.bin"
            args = argparse.Namespace(image="d1", psid="DEL0000000001", name=None,
                                      description=None, output=str(out))
            self.assertEqual(mlxfwutil.cmd_psid(img, args), 0)
            check = Image(out.read_bytes(), "o", base=0x800000)
            f = image_info_fields(check.section_data(check.find_entry("ITOC", 0x10)))
            self.assertEqual(f["psid"], "DEL0000000001")
            self.assertEqual(mlxfwutil.cmd_verify(check), 0)


class TestMergeSection(unittest.TestCase):
    def test_equal_sizes(self):
        self.assertEqual(merge_section(b"AAAA", b"BBBB"), b"AAAA")

    def test_prio_larger(self):
        self.assertEqual(merge_section(b"AAAAAA", b"BBB"), b"AAAAAA")

    def test_prio_smaller_tail_from_other(self):
        self.assertEqual(merge_section(b"AA", b"BBBBBB"), b"AA" + b"BBBBBB"[2:])


class TestRepack(RefsMixin, unittest.TestCase):
    def test_roundtrip_identity(self):
        out = repack(str(HPE), str(HPE), "new")
        self.assertEqual(out, HPE.read_bytes())
        self.assertEqual(mlxfwutil.cmd_verify(Image(out, "out")), 0)

    def test_s1_new_canary(self):
        out = repack(str(HPE), str(DELL), "new")
        img = Image(out, "s1new")
        src_n = Image(HPE.read_bytes(), "hpe")
        src_o = Image(DELL.read_bytes(), "dell")
        self.assertEqual(mlxfwutil.cmd_verify(img), 0)
        for t in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0C,
                  0x11, 0x18, 0x20, 0x32, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4):
            self.assertEqual(img.section_data(img.find_entry("ITOC", t)),
                             src_n.section_data(src_n.find_entry("ITOC", t)), hex(t))
        f = image_info_fields(img.section_data(img.find_entry("ITOC", 0x10)))
        self.assertEqual(f["psid"], "DEL0000000004")
        self.assertEqual(f["name"], "09FTMY_071C1T_Ax")
        self.assertEqual(f["prod_ver"], "rel-16_35_4030")
        d09 = img.section_data(img.find_entry("ITOC", 0x09))
        n09 = src_n.section_data(src_n.find_entry("ITOC", 0x09))
        o09 = src_o.section_data(src_o.find_entry("ITOC", 0x09))
        self.assertEqual(len(d09), 0x1580)
        self.assertEqual(d09[:0x980], n09)
        self.assertEqual(d09[0x980:], o09[0x980:])
        d12 = img.section_data(img.find_entry("ITOC", 0x12))
        n12 = src_n.section_data(src_n.find_entry("ITOC", 0x12))
        o12 = src_o.section_data(src_o.find_entry("ITOC", 0x12))
        self.assertEqual(len(d12), 0xC00)
        self.assertEqual(d12[:0xB00], n12)
        self.assertEqual(d12[0xB00:], o12[0xB00:])
        for e in src_o.itoc:
            if e.type == 0xFF or not (e.type == 0x30 or 0xE0 <= e.type <= 0xEF):
                continue
            ne = img.find_entry("ITOC", e.type)
            self.assertEqual(img.section_data(ne), src_o.section_data(e),
                             f"0x{e.type:02x}")
        for e in src_n.dtoc:
            if e.type == 0xFF:
                continue
            ne = img.entry_at(e.toc, e.index)
            self.assertEqual(img.section_data(ne), src_n.section_data(e),
                             f"{e.toc}[{e.index}]")

    def test_s1_old(self):
        out = repack(str(HPE), str(DELL), "old")
        img = Image(out, "s1old")
        src_n = Image(HPE.read_bytes(), "hpe")
        src_o = Image(DELL.read_bytes(), "dell")
        self.assertEqual(mlxfwutil.cmd_verify(img), 0)
        for t in (0x08, 0x09, 0x12):
            self.assertEqual(img.section_data(img.find_entry("ITOC", t)),
                             src_o.section_data(src_o.find_entry("ITOC", t)), hex(t))
        d11 = img.section_data(img.find_entry("ITOC", 0x11))
        o11 = src_o.section_data(src_o.find_entry("ITOC", 0x11))
        n11 = src_n.section_data(src_n.find_entry("ITOC", 0x11))
        self.assertEqual(len(d11), 0x4C0)
        self.assertEqual(d11[:0x400], o11)
        self.assertEqual(d11[0x400:], n11[0x400:])
        f = image_info_fields(img.section_data(img.find_entry("ITOC", 0x10)))
        self.assertEqual(f["psid"], "DEL0000000004")
        for t in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0A, 0x0B, 0x0C, 0x18,
                  0x20, 0x32, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4):
            self.assertEqual(img.section_data(img.find_entry("ITOC", t)),
                             src_n.section_data(src_n.find_entry("ITOC", t)), hex(t))
        for e in src_o.itoc:
            if e.type == 0xFF or not (e.type == 0x30 or 0xE0 <= e.type <= 0xEF):
                continue
            ne = img.find_entry("ITOC", e.type)
            self.assertEqual(img.section_data(ne), src_o.section_data(e),
                             f"0x{e.type:02x}")
        for e in src_n.dtoc:
            if e.type == 0xFF:
                continue
            ne = img.entry_at(e.toc, e.index)
            self.assertEqual(img.section_data(ne), src_n.section_data(e),
                             f"{e.toc}[{e.index}] 0x{e.type:02x}")

    def test_diff_s1old_s1new_only_config(self):
        a = Image(repack(str(HPE), str(DELL), "old"), "s1old")
        b = Image(repack(str(HPE), str(DELL), "new"), "s1new")
        diffed = {(r.toc, r.type) for r in diff_sections(a, b)
                  if r.diff_bytes or r.size_a != r.size_b}
        self.assertEqual(diffed, {("ITOC", 0x08), ("ITOC", 0x09), ("ITOC", 0x11), ("ITOC", 0x12)})

    def test_layout(self):
        base_b = HPE.read_bytes()
        out = repack(str(HPE), str(DELL), "old")
        base = Image(base_b, "hpe")
        img = Image(out, "s1old")
        self.assertEqual(len(out), 16 * 1024 * 1024)
        self.assertEqual(out[:0x1000], base_b[:0x1000])  # boot-область; ITOC-строки переупорядочены
        self.assertEqual(out[0xF90000:], base_b[0xF90000:])
        moved = [e for e in img.entries("ITOC") if e.type in (0x09, 0x12, 0xE9)]
        self.assertEqual([e.type for e in moved], [0x12, 0x09, 0xE9])  # исходный ITOC-порядок
        self.assertEqual([e.type for e in img.entries("ITOC")[-3:]],
                         [0x12, 0x09, 0xE9])  # релоцированные — в конце массива
        cur = max(e.addr + e.size for e in base.entries("ITOC"))
        for x in moved:
            cur = (cur + 0xFFFF) & ~0xFFFF  # 64K-выровненный последовательный хвост
            self.assertEqual(x.addr, cur)
            self.assertLess(x.addr + x.size, 0xF90000)
            self.assertEqual(x.addr % 0x10000, 0)
            self.assertEqual(base_b[x.addr:x.addr + x.size],
                             b"\xFF" * x.size, "base gap not erased")
            cur += x.size
        for e in base.entries("ITOC"):  # нерелоцированные — на своих местах
            if e.type in (0x09, 0x12, 0xE9):
                continue
            self.assertEqual(img.find_entry("ITOC", e.type).addr, e.addr,
                             f"0x{e.type:02x} moved unexpectedly")
        for t in (0x09, 0x12, 0xE9):  # старые места зачищены
            be = base.find_entry("ITOC", t)
            self.assertEqual(out[be.addr:be.addr + be.size], b"\xFF" * be.size, hex(t))
        iv = sorted((e.addr, e.addr + e.size) for e in img.itoc + img.dtoc
                    if e.type != 0xFF)
        for (s1, e1), (s2, e2) in zip(iv, iv[1:]):
            self.assertLessEqual(e1, s2, "sections overlap")


class TestSwapRepack(RefsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for p in (ADA1012, ACA8008, EDA1012):
            if not p.is_file():
                raise unittest.SkipTest(f"{p.name} not present")

    def test_noop_swap_identical(self):
        out = swap_repack(str(HPE), [(str(HPE), [0x09, 0x18])])
        self.assertEqual(out, HPE.read_bytes())

    def test_single_section_swap(self):
        out = swap_repack(str(ADA1012), [(str(ACA8008), [0x18])])
        img = Image(out, "out")
        self.assertEqual(mlxfwutil.cmd_verify(img), 0)
        base = Image(ADA1012.read_bytes(), "ada")
        src = Image(ACA8008.read_bytes(), "aca")
        self.assertEqual(img.section_data(img.find_entry("ITOC", 0x18)),
                         src.section_data(src.find_entry("ITOC", 0x18)))
        for t in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x30):
            self.assertEqual(img.section_data(img.find_entry("ITOC", t)),
                             base.section_data(base.find_entry("ITOC", t)), hex(t))
        self.assertEqual(out[:0x1000], base.buf[:0x1000])  # boot-область; ITOC переупорядочен
        ne = img.find_entry("ITOC", 0x18)  # grown 0x18 (0x6f028 -> 0x6fc28) — релокация
        self.assertEqual(ne.addr, 0x510000)  # align64k(max ITOC end 0x507e8c)
        self.assertEqual(img.entries("ITOC")[-1].type, 0x18)
        self.assertEqual(ADA1012.read_bytes()[ne.addr:ne.addr + ne.size],
                         b"\xFF" * ne.size)
        self.assertEqual(mlxfwutil.burn_order_check(img), [])

    def test_grown_section_to_gap(self):
        out = swap_repack(str(HPE), [(str(DELL), [0x09])])
        img = Image(out, "out")
        self.assertEqual(mlxfwutil.cmd_verify(img), 0)
        ne = img.find_entry("ITOC", 0x09)
        self.assertEqual(ne.size, 0x1580)
        self.assertEqual(ne.addr, 0x510000)  # align64k(max ITOC end 0x50da54)
        self.assertEqual(ne.addr % 0x10000, 0)
        self.assertLess(ne.addr + ne.size, 0xF90000)
        self.assertEqual(img.entries("ITOC")[-1].type, 0x09)  # последняя в ITOC
        self.assertEqual(HPE.read_bytes()[ne.addr:ne.addr + ne.size], b"\xFF" * ne.size)
        self.assertEqual(mlxfwutil.burn_order_check(img), [])

    def test_missing_section_in_source(self):
        with self.assertRaises(KeyError):
            swap_repack(str(HPE), [(str(DELL), [0x13])])

    def test_two_sources_conflict(self):
        with self.assertRaises(ValueError):
            swap_repack(str(HPE), [(str(DELL), [0x09]), (str(HPE), [0x09])])

    def test_signature_section_rejected(self):
        with self.assertRaises(ValueError):
            swap_repack(str(HPE), [(str(DELL), [0xA1])])

    def test_reflow_triggers_for_e1(self):
        out = swap_repack(str(ADA1012), [(str(ACA8008), E1_SWAPS)])
        img = Image(out, "out")
        self.assertEqual(mlxfwutil.cmd_verify(img), 0)
        for e in img.entries("ITOC"):
            self.assertLess(e.addr + e.size, 0x800000,
                            f"0x{e.type:02x} ends at 0x{e.addr + e.size:x} (>= 0x800000)")

    def test_reflow_composition(self):
        out = swap_repack(str(ADA1012), [(str(ACA8008), E1_SWAPS)])
        img = Image(out, "out")
        base = Image(ADA1012.read_bytes(), "ada")
        src = Image(ACA8008.read_bytes(), "aca")
        for t in E1_SWAPS:
            ne = img.find_entry("ITOC", t)
            self.assertLess(ne.addr, 0x800000, hex(t))
            self.assertEqual(img.section_data(ne),
                             src.section_data(src.find_entry("ITOC", t)), hex(t))
        for t in (0x08, 0x09, 0x10, 0x11, 0x12, 0x30):
            self.assertEqual(img.section_data(img.find_entry("ITOC", t)),
                             base.section_data(base.find_entry("ITOC", t)), hex(t))

    def test_gapfill_preserved_e4(self):
        out = swap_repack(str(ADA1012), [(str(EDA1012), E1_SWAPS)])
        self.assertEqual(hashlib.md5(out).hexdigest(), "cd95e4febf6b8bbe6768c66665aab3e7")
        self.assertEqual(out, ADA1012.read_bytes())

    def test_gapfill_small_growth_no_reflow(self):
        out = swap_repack(str(ADA1012), [(str(EDA1012), [0x30])])
        img = Image(out, "out")
        self.assertEqual(mlxfwutil.cmd_verify(img), 0)
        base = Image(ADA1012.read_bytes(), "ada")
        src = Image(EDA1012.read_bytes(), "eda")
        ne = img.find_entry("ITOC", 0x30)
        self.assertEqual(img.section_data(ne), src.section_data(src.find_entry("ITOC", 0x30)))
        self.assertEqual(ne.addr, 0x510000)  # align64k(max ITOC end 0x507e8c)
        self.assertEqual(img.entries("ITOC")[-1].type, 0x30)  # последняя в ITOC
        self.assertLess(ne.addr + ne.size, 0x800000)
        for e in base.entries("ITOC"):
            if e.type == 0x30:
                continue
            self.assertEqual(img.find_entry("ITOC", e.type).addr, e.addr,
                             f"0x{e.type:02x} moved (reflow triggered?)")
        self.assertEqual(mlxfwutil.burn_order_check(img), [])


class TestPatch(RefsMixin, unittest.TestCase):
    def test_noop_patch_identical(self):
        img = Image(HPE.read_bytes(), "hpe")
        b = img.section_data(img.find_entry("ITOC", 0x08))[0x23:0x24]
        self.assertEqual(patch_sections(img, [(0x08, 0x23, b)]), HPE.read_bytes())

    def test_single_byte_patch(self):
        img = Image(HPE.read_bytes(), "hpe")
        out = patch_sections(img, [(0x08, 0x23, b"\x04")])
        chk = Image(out, "out")
        self.assertEqual(mlxfwutil.cmd_verify(chk), 0)
        ne = chk.find_entry("ITOC", 0x08)
        self.assertEqual(chk.section_data(ne)[0x23], 0x04)
        self.assertEqual(ne.size, 0x140)
        self.assertEqual(out[:0x5000], HPE.read_bytes()[:0x5000])
        o9 = chk.section_data(chk.find_entry("ITOC", 0x09))
        self.assertEqual(o9, img.section_data(img.find_entry("ITOC", 0x09)))

    def test_multi_edits_same_section(self):
        img = Image(HPE.read_bytes(), "hpe")
        out = patch_sections(img, [(0x08, 0x23, b"\x04"), (0x08, 0x00, b"\xAB\xCD")])
        chk = Image(out, "out")
        self.assertEqual(mlxfwutil.cmd_verify(chk), 0)
        d = chk.section_data(chk.find_entry("ITOC", 0x08))
        self.assertEqual(d[0x23], 0x04)
        self.assertEqual(d[0:2], b"\xAB\xCD")

    def test_out_of_range(self):
        img = Image(HPE.read_bytes(), "hpe")
        with self.assertRaises(ValueError):
            patch_sections(img, [(0x08, 0x140, b"\x00")])

    def test_missing_section(self):
        img = Image(HPE.read_bytes(), "hpe")
        with self.assertRaises(KeyError):
            patch_sections(img, [(0x13, 0x0, b"\x00")])

    def test_bad_spec(self):
        for bad in ("0x08+0x23", "0x08+0x23=XYZ", "+0x23=00", "0x08+=00", "0x08+0x23="):
            with self.assertRaises(ValueError, msg=bad):
                parse_set_spec(bad)


class TestAb(RefsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for n in ("c178_s1new_fixed_raw.bin", "4fbc_after56g_raw.bin",
                  "718ecf_s1new_dense_ri.bin", "205c6ec4_56g_good_ri.bin"):
            if not (DUMPS / n).is_file():
                raise unittest.SkipTest(f"ref dump {n} not present")

    def test_c178_state(self):
        st = ab_state((DUMPS / "c178_s1new_fixed_raw.bin").read_bytes())
        self.assertEqual(st["A"].magic, "zeroed4")
        self.assertEqual(st["A"].itoc_off, 0x5000)
        self.assertEqual(st["A"].dtoc_off, -1)
        self.assertEqual(st["B"].magic, "intact")
        self.assertEqual(st["B"].itoc_off, 0x5000)
        # slot B truncation @0x430000: секция 0x10 (IMAGE_INFO @0x43dac8) стёрта;
        # поле psid[17] (II_PSID) => 17 байт 0xFF (не 16, как в брифе/R2)
        self.assertEqual(st["B"].psid, "\xff" * 17)
        self.assertEqual(st["B"].dtoc_off, 0x7FF000)
        self.assertTrue(st["B"].mtcf)

    def test_c178_slotb_truncation(self):
        raw = (DUMPS / "c178_s1new_fixed_raw.bin").read_bytes()
        s1n = (REPO / "build" / "dell_s1_newprio.bin").read_bytes()
        self.assertEqual(raw[0x800000:0x800000 + 0x430000], s1n[:0x430000])
        self.assertNotEqual(raw[0x800000 + 0x430000], s1n[0x430000])

    def test_after56g_state(self):
        st = ab_state((DUMPS / "4fbc_after56g_raw.bin").read_bytes())
        self.assertEqual(st["A"].magic, "erased")
        self.assertEqual(st["B"].magic, "intact")
        # тот же truncation @0x430000, что и c178: дельта vs c178 = 190 B,
        # секция 0x10 @0x43dac8 не затронута — стёрта (R2: c178/4fbc slot B
        # PSID erased; в брифе осталась устаревшая поправка — "DEL0000000004")
        self.assertEqual(st["B"].psid, "\xff" * 17)

    def test_ri_dump_logical_view(self):
        st = ab_state((DUMPS / "205c6ec4_56g_good_ri.bin").read_bytes())
        self.assertEqual(st["A"].magic, "intact")
        self.assertEqual(st["A"].itoc_off, 0x5000)
        self.assertEqual(st["B"].magic, "zeroed16")
        self.assertEqual(st["B"].itoc_off, -1)
        self.assertEqual(st["B"].dtoc_off, 0x7FF000)
        st2 = ab_state((DUMPS / "718ecf_s1new_dense_ri.bin").read_bytes())
        self.assertEqual(st2["A"].magic, "intact")
        self.assertEqual(st2["A"].psid, "DEL0000000004")
        self.assertEqual(st2["B"].magic, "erased")

    def test_diff_190(self):
        a = (DUMPS / "c178_s1new_fixed_raw.bin").read_bytes()
        b = (DUMPS / "4fbc_after56g_raw.bin").read_bytes()
        self.assertEqual(ab_diff(a, b)["total"], 190)


class TestFs3AbSlot(Fw4Mixin, unittest.TestCase):
    @staticmethod
    def dual_intact(src: bytes) -> bytes:
        img = Image(src, "src")
        buf = bytearray(src.ljust(16 * 1024 * 1024, b"\xff"))
        buf[SLOT_SIZE:SLOT_SIZE + 0x4000] = src[0:0x4000]
        for e in img.entries("ITOC"):
            if e.rel and e.size:
                buf[e.addr + SLOT_SIZE:e.addr + SLOT_SIZE + e.size] = src[e.addr:e.addr + e.size]
        return bytes(buf)

    def test_dual_intact_slot_states(self):
        st = ab_state(self.dual_intact(ACA1912.read_bytes()))
        self.assertEqual(st["A"].magic, "intact")
        self.assertEqual(st["A"].itoc_off, 0x2000)
        self.assertEqual(st["A"].entries, 31)
        self.assertEqual(st["A"].psid, "MT_2420110034")
        self.assertEqual(st["A"].prod_ver, "rel-14_32_1912")
        self.assertEqual(st["A"].dtoc_off, -1)
        self.assertFalse(st["A"].mtcf)
        self.assertEqual(st["B"].magic, "intact")
        self.assertEqual(st["B"].base, 0x800000)
        self.assertEqual(st["B"].itoc_off, 0x2000)
        self.assertEqual(st["B"].entries, 31)
        self.assertEqual(st["B"].psid, "MT_2420110034")

    def test_slot_b_zeroed4(self):
        buf = bytearray(self.dual_intact(ACA1912.read_bytes()))
        buf[SLOT_SIZE:SLOT_SIZE + 4] = b"\x00" * 4
        st = ab_state(bytes(buf))
        self.assertEqual(st["A"].magic, "intact")
        self.assertEqual(st["B"].magic, "zeroed4")
        import io, contextlib
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "raw.bin"
            p.write_bytes(bytes(buf))
            with contextlib.redirect_stdout(out):
                self.assertEqual(mlxfwutil.main(["ab", str(p)]), 0)
            self.assertIn("verdict: valid slots = A", out.getvalue())

    def test_cmd_ab_fs3_rc0(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "raw.bin"
            p.write_bytes(self.dual_intact(ACA1912.read_bytes()))
            self.assertEqual(mlxfwutil.main(["ab", str(p)]), 0)

    def test_devtail_dual_intact(self):
        raw = self.dual_intact(ACA1912.read_bytes())
        tail = ab_devtail(raw, ab_state(raw))
        self.assertEqual(tail["slot"], "A")
        self.assertIsNone(tail["warn"])
        self.assertEqual(tail["mfg"]["addr"], 0xFF8000)
        self.assertEqual(tail["mfg"]["psid"], "MT_2420110034")
        self.assertEqual(tail["mfg"]["override_en"], 1)
        self.assertEqual(tail["mfg"]["guid"], 0)
        self.assertEqual(tail["mfg"]["mac"], 0)
        self.assertEqual(tail["devinfo"]["addr"], 0xFEE000)
        self.assertTrue(tail["devinfo"]["sig_ok"])
        self.assertEqual(tail["devinfo"]["major"], 2)
        self.assertEqual(tail["devinfo"]["guid"], 0)
        self.assertEqual(tail["devinfo"]["mac"], 0)

    def test_devtail_no_intact_slot(self):
        buf = bytearray(self.dual_intact(ACA1912.read_bytes()))
        buf[0:4] = b"\x00" * 4
        buf[SLOT_SIZE:SLOT_SIZE + 4] = b"\x00" * 4
        raw = bytes(buf)
        self.assertEqual(ab_devtail(raw, ab_state(raw)), {})

    def test_devtail_addr_mismatch_warn(self):
        raw = bytearray(self.dual_intact(ACA1912.read_bytes()))
        st = ab_state(bytes(raw))
        img0 = Image(ACA1912.read_bytes(), "aca")
        e0 = img0.find_entry("ITOC", 0xE0)
        off = SLOT_SIZE + st["B"].itoc_off + 32 + e0.index * 32
        ent = bytearray(raw[off:off + 32])
        set_bits(ent, 161, 29, e0.addr + 0x40)
        raw[off:off + 32] = ent
        tail = ab_devtail(bytes(raw), ab_state(bytes(raw)))
        self.assertIn("0xe0", tail["warn"])
        self.assertIn("mismatch", tail["warn"])

    def test_ab_diff_fs3(self):
        raw1 = self.dual_intact(ACA1912.read_bytes())
        raw2 = bytearray(raw1)
        raw2[SLOT_SIZE + 0x4000] ^= 0xFF  # 1 байт в FW-регионе слота B
        d = ab_diff(raw1, bytes(raw2))
        self.assertEqual(d["A"]["bytes"], 0)
        self.assertEqual(d["B"]["bytes"], 1)
        self.assertEqual(d["total"], 1)


class TestAbFs4Devtail(RefsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for n in ("t53i_final_raw.bin", "x0_fnp_dead_raw.bin", "e0_pre_raw.bin"):
            if not (DUMPS / n).is_file():
                raise unittest.SkipTest(f"ref dump {n} not present")
        cls.EDR100_GUID = hw_id("CARD_CX5_EDR100", "guid")
        cls.EDR100_MAC = hw_id("CARD_CX5_EDR100", "mac")
        cls.CX5_25G_GUID = hw_id("CARD_CX5_25G", "guid")

    def test_devtail_t53i(self):
        raw = (DUMPS / "t53i_final_raw.bin").read_bytes()
        tail = ab_devtail_fs4(raw)
        self.assertEqual(tail["dtoc_off"], 0xFFF000)
        mfg = tail["mfg"]
        self.assertEqual(mfg["addr"], 0xFF8000)
        self.assertEqual(mfg["psid"], "MT_0000000008")
        self.assertEqual(mfg["override_en"], 1)
        self.assertEqual(mfg["major"], 1)
        self.assertEqual(mfg["guid"], self.EDR100_GUID)
        self.assertEqual(mfg["mac"], self.EDR100_MAC)
        di = tail["devinfos"]
        self.assertEqual(len(di), 2)
        self.assertEqual(di[0]["addr"], 0xFD0000)
        self.assertTrue(di[0]["sig_ok"])
        self.assertEqual(di[0]["major"], 2)
        self.assertTrue(di[0]["crc_ok"])
        self.assertEqual(di[0]["guid"], self.EDR100_GUID)
        self.assertEqual(di[0]["mac"], self.EDR100_MAC)
        self.assertEqual(di[1]["addr"], 0xFE0000)
        self.assertFalse(di[1]["sig_ok"])
        self.assertEqual(di[1]["guid"], 0)
        self.assertEqual(di[1]["mac"], 0)

    def test_devtail_dead_flash(self):
        raw = (DUMPS / "x0_fnp_dead_raw.bin").read_bytes()
        st = ab_state(raw)
        self.assertEqual(st["A"].magic, "intact")
        self.assertNotEqual(st["B"].magic, "intact")
        tail = ab_devtail_fs4(raw)
        self.assertEqual(tail["mfg"]["psid"], "MT_0000000013")
        self.assertEqual(tail["mfg"]["guid"], self.EDR100_GUID)
        self.assertTrue(tail["devinfos"][0]["sig_ok"])
        self.assertEqual(tail["devinfos"][0]["guid"], self.EDR100_GUID)

    def test_devtail_second_copy_valid(self):
        raw = (DUMPS / "e0_pre_raw.bin").read_bytes()
        tail = ab_devtail_fs4(raw)
        self.assertEqual(tail["mfg"]["guid"], self.CX5_25G_GUID)
        self.assertEqual(tail["devinfos"][0]["addr"], 0xFD0000)
        self.assertFalse(tail["devinfos"][0]["sig_ok"])
        self.assertEqual(tail["devinfos"][1]["addr"], 0xFE0000)
        self.assertTrue(tail["devinfos"][1]["sig_ok"])
        self.assertEqual(tail["devinfos"][1]["guid"], self.CX5_25G_GUID)

    def test_devtail_no_dtoc(self):
        self.assertEqual(ab_devtail_fs4(b"\xff" * 16 * 1024 * 1024), {})

    def test_devtail_bad_dtoc_crc(self):
        raw = bytearray((DUMPS / "t53i_final_raw.bin").read_bytes())
        raw[0xFFF000 + 0x1E] ^= 0x01
        self.assertEqual(ab_devtail_fs4(bytes(raw)), {})

    def test_cmd_ab_fs4_devtail_stdout(self):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(mlxfwutil.main(["ab", str(DUMPS / "t53i_final_raw.bin")]), 0)
        s = out.getvalue()
        self.assertIn("dev tail (shared, DTOC @0xfff000):", s)
        self.assertIn("0xE0 MFG_INFO @0xff8000: psid=MT_0000000008 override_en=1 "
                      "major=1 guid=0x%x mac=0x%x" % (self.EDR100_GUID, self.EDR100_MAC), s)
        self.assertIn("0xE1 DEV_INFO @0xfd0000: sig=OK major=2 crc=OK "
                      "guid=0x%x mac=0x%x" % (self.EDR100_GUID, self.EDR100_MAC), s)
        self.assertIn("0xE1 DEV_INFO @0xfe0000: sig=NG major=2 crc=OK "
                      "guid=0x0 mac=0x0", s)
        self.assertIn("verdict: valid slots = B", s)


class TestHwPointers(RefsMixin, unittest.TestCase):
    def test_known_hw_pointers_ada1012(self):
        ptrs = mlxfwutil.hw_pointers(ADA1012.read_bytes())
        self.assertEqual(len(ptrs), 16)
        # верифицировано 2026-09-11 по factory-образу (md5 cd95e4fe...)
        self.assertEqual(ptrs["boot_record_ptr"][:2], (0x100, 0x75F8))
        self.assertEqual(ptrs["boot2_ptr"][:2], (0x1000, 0xEB67))
        self.assertEqual(ptrs["toc_ptr"][:2], (0x5000, 0x5658))
        self.assertEqual(ptrs["tools_ptr"][:2], (0x500, 0x8359))
        for name in ("boot_record_ptr", "boot2_ptr", "toc_ptr", "tools_ptr"):
            self.assertTrue(ptrs[name][2], name)
        self.assertEqual(ptrs["hashes_table_pointer"][0], 0xFFFFFFFF)
        self.assertFalse(ptrs["hashes_table_pointer"][2])

    def test_hw_ptr_crc_variants(self):
        e = bytearray(8)
        struct.pack_into(">I", e, 0, 0x5000)
        sw = mlxfwutil.crc16_mlx(struct.pack(">I", 0x5000))
        struct.pack_into(">I", e, 4, sw)
        self.assertTrue(mlxfwutil.hw_ptr_crc_ok(bytes(e))[0])
        hw = mlxfwutil.calc_hw_crc(bytes(e[:4]) + bytes(2))
        e[4:6] = hw.to_bytes(2, "big")
        self.assertTrue(mlxfwutil.hw_ptr_crc_ok(bytes(e))[1])

    def test_all_16_entries_sw_or_hw(self):
        for img in (ADA1012, D1RAW):
            if not img.is_file():
                continue
            for name, (ptr, crc, valid) in mlxfwutil.hw_pointers(img.read_bytes()).items():
                if ptr in (0, 0xFFFFFFFF):
                    self.assertFalse(valid, (img.name, name))


class TestAb32Mib(RefsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not CX6DX_IMG0.is_file():
            raise unittest.SkipTest("ref image bazzite-img0 not present")

    def test_flash_layout(self):
        self.assertEqual(_flash_layout(0x1000000), (0x800000, (0x0, 0x800000)))
        self.assertEqual(_flash_layout(0x2000000), (0x1000000, (0x0, 0x1000000)))

    def test_flash_layout_bad_size(self):
        for size in (0x3F00000, 0x2100000, 0x40, 0):
            with self.assertRaises(ValueError) as cm:
                _flash_layout(size)
            self.assertIn("16MiB or 32MiB", str(cm.exception))

    def test_ab_state_bad_size(self):
        with self.assertRaises(ValueError) as cm:
            ab_state(b"\xff" * 0x3F00000)
        self.assertIn("16MiB or 32MiB", str(cm.exception))

    def test_ab_state_vendor_32mib(self):
        st = ab_state(CX6DX_IMG0.read_bytes())
        self.assertEqual(st["A"].base, 0x0)
        self.assertEqual(st["A"].magic, "intact")
        self.assertEqual(st["A"].itoc_off, 0x5000)
        self.assertEqual(st["A"].entries, 29)
        self.assertEqual(st["A"].psid, "MT_0000000695")
        self.assertEqual(st["A"].prod_ver, "rel-22_50_1002")
        self.assertEqual(st["A"].dtoc_off, -1)
        self.assertFalse(st["A"].mtcf)
        self.assertEqual(st["B"].base, 0x1000000)
        self.assertEqual(st["B"].magic, "erased")
        self.assertEqual(st["B"].itoc_off, -1)
        self.assertEqual(st["B"].dtoc_off, 0xFFF000)
        self.assertFalse(st["B"].mtcf)

    def test_ab_state_real_32mib(self):
        for n in ("localhost-cx6-raw-32mib-2026-09-18.bin",
                  "bazzite-cx6dx-raw-32mib-2026-09-18.bin"):
            p = REFDUMPS / n
            if not p.is_file():
                raise unittest.SkipTest(f"32MiB dump {n} not present")
            st = ab_state(p.read_bytes())
            self.assertEqual(st["A"].base, 0x0)
            self.assertEqual(st["B"].base, 0x1000000)
            for s in (st["A"], st["B"]):
                self.assertIn(s.magic, ("intact", "zeroed4", "zeroed16", "erased"), n)
                if s.magic == "intact":
                    self.assertIn(s.itoc_off, (0x4000, 0x5000), n)
                    self.assertGreater(s.entries, 0, n)
            self.assertEqual(st["B"].dtoc_off, 0xFFF000, n)

    def test_devtail_real_32mib(self):
        p = REFDUMPS / "bazzite-cx6dx-raw-32mib-2026-09-18.bin"
        if not p.is_file():
            raise unittest.SkipTest("32MiB dump not present")
        tail = ab_devtail_fs4(p.read_bytes())
        self.assertEqual(tail["dtoc_off"], 0x1FFF000)
        self.assertIsNotNone(tail["mfg"])
        self.assertEqual(tail["mfg"]["addr"], 0x1FF8000)
        self.assertEqual([d["addr"] for d in tail["devinfos"]],
                         [0x1F60000, 0x1F70000])
        self.assertEqual(sum(1 for d in tail["devinfos"] if d["sig_ok"]), 1)

    def test_ab_diff_32mib(self):
        a = bytearray(0x2000000)
        b = bytearray(0x2000000)
        a[0x1000] = 0xAA
        b[0x1000] = 0xBB
        a[0x1500000] = 0x11
        a[0x1FFF000] = 0x22
        d = ab_diff(bytes(a), bytes(b))
        self.assertEqual(d["A"]["bytes"], 1)
        self.assertEqual(d["A"]["first"], 0x1000)
        self.assertEqual(d["B"]["bytes"], 2)
        self.assertEqual(d["B"]["first"], 0x500000)
        self.assertEqual(d["B"]["last"], 0xFFF000)
        self.assertEqual(d["total"], 3)

    def test_ab_diff_mixed_size(self):
        with self.assertRaises(ValueError) as cm:
            ab_diff(b"\xff" * 0x1000000, b"\xff" * 0x2000000)
        self.assertIn("same size", str(cm.exception))

    def test_truncated_32mib_flash(self):
        p = REFDUMPS / "bazzite-cx6dx-img0-ok-raw-2026-09-17.bin"
        if not p.is_file():
            raise unittest.SkipTest("ref dump not present")
        raw = p.read_bytes()
        self.assertEqual(
            ab_truncated(raw, ab_state(raw)),
            "warning: 16MiB dump of 32MiB flash (IMAGE_INFO log_step=24): "
            "'slot B @0x800000' is the second half of slot A; "
            "real slot B @0x1000000 not in dump")

    def test_truncated_16mib_flash(self):
        p = DUMPS / "t53i_final_raw.bin"
        if not p.is_file():
            raise unittest.SkipTest("ref dump not present")
        raw = p.read_bytes()
        self.assertIsNone(ab_truncated(raw, ab_state(raw)))

    def test_truncated_dead_flash(self):
        raw = b"\xff" * 0x1000000
        self.assertIsNone(ab_truncated(raw, ab_state(raw)))

    def test_cmd_ab_32mib_stdout(self):
        import contextlib
        import io
        p = REFDUMPS / "bazzite-cx6dx-raw-32mib-2026-09-18.bin"
        if not p.is_file():
            raise unittest.SkipTest("32MiB dump not present")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(mlxfwutil.main(["ab", str(p)]), 0)
        s = out.getvalue()
        self.assertIn("slot A @0x0:", s)
        self.assertIn("slot B @0x1000000:", s)
        self.assertIn("dev tail (shared, DTOC @0x1fff000):", s)
        self.assertIn("verdict: valid slots =", s)
        self.assertNotIn("log_step=24", err.getvalue())

    def test_cmd_ab_16mib_truncated_stderr(self):
        import contextlib
        import io
        p = REFDUMPS / "bazzite-cx6dx-img0-ok-raw-2026-09-17.bin"
        if not p.is_file():
            raise unittest.SkipTest("ref dump not present")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(mlxfwutil.main(["ab", str(p)]), 0)
        self.assertIn("log_step=24", err.getvalue())
        self.assertIn("slot B @0x800000:", out.getvalue())


class TestHashesTable(RefsMixin, unittest.TestCase):
    def _mk(self, types, max_num=None, hsize=64, version=0, htype=1):
        max_num = len(types) if max_num is None else max_num
        total = 12 + 16 + max_num * (8 + hsize) + 8
        d = bytearray(total)
        struct.pack_into(">II", d, 0, 0, total // 4)
        struct.pack_into(">H", d, 10, mlxfwutil.crc16_mlx(bytes(d[0:8])))
        struct.pack_into(">IBBH", d, 12, version, len(types), htype, hsize)
        for i, t in enumerate(types):
            off = 16 + max_num * 8 + i * hsize
            struct.pack_into(">I", d, 28 + i * 8, (t << 16) | off)
            h = hashlib.sha512(t.to_bytes(1, "big")).digest()
            d[12 + off:12 + off + hsize] = h
        struct.pack_into(">H", d, total - 2, mlxfwutil.crc16_mlx(bytes(d[0:total - 4])))
        return bytes(d)

    def test_parse_and_crcs(self):
        t = self._mk([0x08, 0x09])
        ht = mlxfwutil.HashesTable.from_bytes(t, ptr=0x1000)
        self.assertEqual(ht.version, 0)
        self.assertEqual(ht.num, 2)
        self.assertEqual(ht.max_num, 2)
        self.assertEqual(ht.hash_size, 64)
        self.assertEqual(ht.entries, [(0x08, 32), (0x09, 96)])
        self.assertTrue(ht.header_crc_ok())
        self.assertTrue(ht.data_crc_ok())
        self.assertEqual(ht.hash_addr(1), 0x1000 + 12 + 96)

    def test_bad_header_crc(self):
        t = bytearray(self._mk([0x08]))
        t[10] ^= 0xFF  # stored header CRC (last 2 bytes of 12B header)
        self.assertFalse(mlxfwutil.HashesTable.from_bytes(bytes(t), 0x1000).header_crc_ok())

    def test_bad_data_crc(self):
        t = bytearray(self._mk([0x08]))
        t[12 + 24] ^= 0xFF  # первый байт хеша
        self.assertFalse(mlxfwutil.HashesTable.from_bytes(bytes(t), 0x1000).data_crc_ok())

    def test_update_existing_entry(self):
        t = self._mk([0x08])
        ht = mlxfwutil.HashesTable.from_bytes(t, ptr=0)
        newdata = b"changed"
        img = bytearray(t)
        ht.update_into(img, {0x08: newdata}, {0x08})
        self.assertEqual(hashlib.sha512(newdata).digest(), img[12 + 24:12 + 88])
        ht2 = mlxfwutil.HashesTable.from_bytes(bytes(img), 0)
        self.assertTrue(ht2.data_crc_ok())
        self.assertEqual(ht2.num, 1)
        self.assertEqual(len(img), len(t))

    def test_update_new_entry(self):
        t = self._mk([0x08], max_num=2)
        ht = mlxfwutil.HashesTable.from_bytes(t, ptr=0)
        img = bytearray(t)
        ht.update_into(img, {0x09: b"new"}, {0x08, 0x09})
        ht2 = mlxfwutil.HashesTable.from_bytes(bytes(img), 0)
        self.assertEqual(ht2.num, 2)
        self.assertEqual(ht2.entries, [(0x08, 32), (0x09, 96)])
        self.assertTrue(ht2.data_crc_ok())
        self.assertEqual(hashlib.sha512(b"new").digest(),
                         bytes(img[12 + 96:12 + 160]))

    def test_skip_sig_types_and_dtoc(self):
        t = self._mk([0xA0])
        ht = mlxfwutil.HashesTable.from_bytes(t, ptr=0)
        img = bytearray(t)
        ht.update_into(img, {0xA0: b"x", 0x08: b"y"}, {0xA0})
        self.assertEqual(bytes(img), t)


class TestPatchRepackHashes(RefsMixin, unittest.TestCase):
    # --- синтетика: минимальный FS4-образ с АКТИВНОЙ hashes table ---
    def _toc_hdr(self, hdr16, nent):
        h = bytearray(32)
        h[0:16] = hdr16
        mlxfwutil.set_bits(h, 184, 8, nent)
        mlxfwutil.set_bits(h, 240, 16, mlxfwutil.crc16_mlx(bytes(h[:28])))
        return bytes(h)

    def _toc_ent(self, t, size, addr):
        r = bytearray(32)
        mlxfwutil.set_bits(r, 0, 8, t)
        mlxfwutil.set_bits(r, 8, 22, size // 4)
        mlxfwutil.set_bits(r, 161, 29, addr // 4)
        mlxfwutil.set_bits(r, 240, 16, mlxfwutil.crc16_mlx(bytes(r[:28])))
        return bytes(r)

    def _hashes_tbl(self, sect_data, sect_type, max_num=28, hsize=64):
        total = 12 + 16 + max_num * (8 + hsize) + 8
        d = bytearray(total)
        struct.pack_into(">II", d, 0, 0, total // 4)
        struct.pack_into(">H", d, 10, mlxfwutil.crc16_mlx(bytes(d[0:8])))
        struct.pack_into(">IBBH", d, 12, 0, 1, 1, hsize)
        off = 16 + max_num * 8
        struct.pack_into(">I", d, 28, (sect_type << 16) | off)
        d[12 + off:12 + off + hsize] = hashlib.sha512(sect_data).digest()
        struct.pack_into(">H", d, total - 2, mlxfwutil.crc16_mlx(bytes(d[0:total - 4])))
        return bytes(d)

    def _synth(self, sect_data=b"SECTION08DATA123"):
        buf = bytearray(0x4000)
        buf[0:16] = FS4_MAGIC
        taddr = 0x3000
        struct.pack_into(">I", buf, 0x18 + 15 * 8, taddr)      # hashes_table_pointer
        struct.pack_into(">H", buf, 0x18 + 15 * 8 + 4,
                         mlxfwutil.crc16_mlx(struct.pack(">I", taddr)))
        buf[0x1000:0x1020] = self._toc_hdr(ITOC_HDR, 1)
        buf[0x1020:0x1040] = self._toc_ent(0x08, len(sect_data), 0x2000)
        buf[0x1040:0x1060] = self._toc_ent(0xFF, 0, 0)
        buf[0x1100:0x1120] = self._toc_hdr(DTOC_HDR, 0)
        buf[0x1120:0x1140] = self._toc_ent(0xFF, 0, 0)
        buf[0x2000:0x2000 + len(sect_data)] = sect_data
        ht = self._hashes_tbl(sect_data, 0x08)
        buf[taddr:taddr + len(ht)] = ht
        return bytes(buf)

    def test_synth_parses_and_hashes_present(self):
        img = Image(self._synth(), "synth")
        ht = mlxfwutil.HashesTable.from_image(img)
        self.assertIsNotNone(ht)
        self.assertTrue(ht.header_crc_ok())
        self.assertTrue(ht.data_crc_ok())
        self.assertEqual(ht.entry_by_type(0x08)[0], 0)

    def test_patch_updates_hash(self):
        img = Image(self._synth(), "synth")
        newdata = b"PATCHED08DATA123"
        out = mlxfwutil.patch_sections(img, [(0x08, 0x0, newdata)])
        oimg = Image(out, "out")
        self.assertEqual(oimg.section_data(oimg.find_entry("ITOC", 0x08)), newdata)
        ht2 = mlxfwutil.HashesTable.from_image(oimg)
        self.assertIsNotNone(ht2)
        self.assertTrue(ht2.data_crc_ok())
        _, off = ht2.entry_by_type(0x08)
        self.assertEqual(bytes(ht2.data[12 + off:12 + off + ht2.hash_size]),
                         hashlib.sha512(newdata).digest())

    def test_info_hashes_block_absent(self):
        import io, contextlib
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            self.assertEqual(mlxfwutil.cmd_info(Image(ADA1012.read_bytes(), "ada")), 0)
        self.assertIn("hashes table: present=no", f.getvalue())


class TestDetectSlot(RefsMixin, unittest.TestCase):
    def test_factory_slot_a(self):
        self.assertEqual(mlxfwutil.detect_slot(ADA1012.read_bytes()), 0x0)

    def test_d1_slot_b(self):
        if not D1RAW.is_file():
            raise unittest.SkipTest("d1_raw.bin not present")
        self.assertEqual(mlxfwutil.detect_slot(D1RAW.read_bytes()), 0x800000)

    def test_not_16m(self):
        self.assertEqual(mlxfwutil.detect_slot(b"MTFW" + b"\x00" * 0x3FFF), 0x0)

    def test_no_intact(self):
        b = bytearray(ADA1012.read_bytes())
        b[0:16] = b"\x00" * 16
        b[0x800000:0x800010] = b"\x00" * 16
        with self.assertRaises(ValueError):
            mlxfwutil.detect_slot(bytes(b))


class TestImageBase(RefsMixin, unittest.TestCase):
    def test_d1_base_b(self):
        if not D1RAW.is_file():
            raise unittest.SkipTest("d1_raw.bin not present")
        d1 = D1RAW.read_bytes()
        img = Image(d1, "d1", base=0x800000)
        self.assertEqual(img.itoc_off, 0x805000)
        self.assertEqual(img.dtoc_off, 0xFFF000)
        e = img.find_entry("ITOC", 0x10)
        self.assertIn(b"MT_0000000361", img.section_data(e))

    def test_factory_base_default_unchanged(self):
        img = Image(ADA1012.read_bytes(), "ada")
        self.assertEqual(img.itoc_off, 0x5000)
        self.assertEqual(img.dtoc_off, 0xFFF000)


class TestMDevInfo(RefsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.CX5_25G_GUID = hw_id("CARD_CX5_25G", "guid")
        cls.CX5_25G_MAC = hw_id("CARD_CX5_25G", "mac")

    def test_parse_factory(self):
        img = Image(ADA1012.read_bytes(), "ada")
        e = img.find_entry("DTOC", 0xE1)  # первый 0xE1 = 0xfd0000
        m = mlxfwutil.MDevInfo.parse(img.section_data(e))
        self.assertEqual(m.guid, 0)
        self.assertEqual(m.mac, 0)
        self.assertEqual(m.version, 0x00000200)
        self.assertEqual(m.vsd_vendor_id, 0x0)
        self.assertTrue(m.crc_ok())

    def test_ensure_valid_zeroed(self):
        m = mlxfwutil.MDevInfo.parse(bytes(bytearray(0x200)))  # нулевая секция (worst case; реальный 2-й 0xE1 — не нулевой полностью)
        m.ensure_valid()
        self.assertTrue(mlxfwutil.devinfo_sig_ok(bytes(m.sec)))
        self.assertEqual(m.version, 0x00000200)
        self.assertEqual(m.vsd_vendor_id, 0x15B3)
        out = m.write_uids(self.CX5_25G_GUID, self.CX5_25G_MAC)
        m2 = mlxfwutil.MDevInfo.parse(out)
        self.assertTrue(m2.crc_ok())
        self.assertEqual(m2.guid, self.CX5_25G_GUID)

    def test_write_uids_crc(self):
        img = Image(ADA1012.read_bytes(), "ada")
        e = img.find_entry("DTOC", 0xE1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(e))
        out = m.write_uids(self.CX5_25G_GUID, self.CX5_25G_MAC)
        self.assertEqual(len(out), len(img.section_data(e)))
        m2 = mlxfwutil.MDevInfo.parse(out)
        self.assertEqual(m2.guid, self.CX5_25G_GUID)
        self.assertEqual(m2.mac, self.CX5_25G_MAC)
        self.assertTrue(m2.crc_ok())
        # остальные байты as-is
        self.assertEqual(out[0x40:0x1FC], img.section_data(e)[0x40:0x1FC])

    def test_find_valid_devinfo(self):
        img = Image(ADA1012.read_bytes(), "ada")
        v = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual([e.addr for e in v], [0xfd0000])


class TestGuides(RefsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.GUID = hw_id("CARD_CX5_25G", "guid")
        cls.MAC = hw_id("CARD_CX5_25G", "mac")

    def _ns(self, image, out):
        import argparse
        return argparse.Namespace(image=str(image), guid=self.GUID, mac=self.MAC, output=str(out))

    def test_factory_slot_a(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.bin"
            self.assertEqual(mlxfwutil.cmd_guides(self._ns(ADA1012, out)), 0)
            data = out.read_bytes()
            self.assertEqual(len(data), 0x1000000)
            img = Image(data, "out")
            self.assertEqual(mlxfwutil.verify_image(img), [])
            m = mlxfwutil.MDevInfo.parse(img.section_data(img.find_entry("DTOC", 0xE1)))
            self.assertEqual(m.guid, self.GUID)
            self.assertEqual(m.mac, self.MAC)
            self.assertTrue(m.crc_ok())
            e0 = img.find_entry("DTOC", 0xE0)
            d = img.section_data(e0)
            self.assertEqual(int.from_bytes(d[0x28:0x30], "big"), self.GUID)
            self.assertEqual(int.from_bytes(d[0x38:0x40], "big"), self.MAC)
            # 0xfe0000 (второй DEV_INFO) не тронут
            base = ADA1012.read_bytes()
            self.assertEqual(data[0xfe0000:0xfe0000 + 0x200], base[0xfe0000:0xfe0000 + 0x200])

    def test_d1_slot_b(self):
        if not D1RAW.is_file():
            raise unittest.SkipTest("d1_raw.bin not present")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.bin"
            self.assertEqual(mlxfwutil.cmd_guides(self._ns(D1RAW, out)), 0)
            data = out.read_bytes()
            self.assertEqual(len(data), 0x1000000)
            # slot B intact не сломан
            self.assertEqual(data[0x800000:0x800010], FS4_MAGIC)
            img = Image(data, "out", base=0x800000)
            self.assertEqual(mlxfwutil.verify_image(img), [])
            e = min((x for x in img.entries("DTOC") if x.type == 0xE1), key=lambda x: x.addr)
            m = mlxfwutil.MDevInfo.parse(img.section_data(e))
            self.assertEqual(m.guid, self.GUID)
            self.assertTrue(m.crc_ok())
            # diff только в device-области (0xfb0000+)
            base = D1RAW.read_bytes()
            diff = [i for i in range(len(base)) if base[i] != data[i]]
            self.assertTrue(all(i >= 0xfb0000 for i in diff), min(diff))

    def test_two_valid_rejected(self):
        b = bytearray(ADA1012.read_bytes())
        b[0xfe0000:0xfe0000 + 0x200] = b[0xfd0000:0xfd0000 + 0x200]
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "two.bin"
            src.write_bytes(bytes(b))
            self.assertEqual(mlxfwutil.cmd_guides(self._ns(src, Path(td) / "o.bin")), 1)

    def test_create_when_none_valid(self):
        b = bytearray(ADA1012.read_bytes())
        b[0xfd0000:0xfd0010] = b"\x00" * 16  # сломать единственный валидный
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "nosig.bin"
            src.write_bytes(bytes(b))
            out = Path(td) / "out.bin"
            self.assertEqual(mlxfwutil.cmd_guides(self._ns(src, out)), 0)
            img = Image(out.read_bytes(), "out")
            e = min((x for x in img.entries("DTOC") if x.type == 0xE1), key=lambda x: x.addr)
            m = mlxfwutil.MDevInfo.parse(img.section_data(e))
            self.assertEqual(m.guid, self.GUID)
            self.assertTrue(m.crc_ok())
            self.assertEqual(mlxfwutil.verify_image(img), [])

    def test_self_verify_failure_no_output(self):
        # сломать ITOC-header CRC -> self-verify должен упасть, файла не будет
        b = bytearray(ADA1012.read_bytes())
        itoc = 0x5000
        b[itoc + 30] ^= 0xFF  # header CRC field
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "bad.bin"
            src.write_bytes(bytes(b))
            out = Path(td) / "out.bin"
            self.assertEqual(mlxfwutil.cmd_guides(self._ns(src, out)), 1)
            self.assertFalse(out.exists())


class TestMergeSpec(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(
            mlxfwutil.parse_merge_spec("0x11+0x2b7+1,0x10+0x0+16"),
            [(0x11, 0x2b7, 1), (0x10, 0, 16)])

    def test_valid_decimal_spaces(self):
        self.assertEqual(
            mlxfwutil.parse_merge_spec("0x11 + 4 + 8 , 18+0+16"),
            [(0x11, 4, 8), (0x12, 0, 16)])

    def test_bad_entries(self):
        for spec in ("0x11+0x2b7", "0x11+0x2b7+0", "0x11+0x2b7+4+5",
                     "xyz+0+1", "0x11+0x2b7+-4", "0x11+-1+4",
                     "0x11+0x2b7+4,,0x10+0+1", "0x0+0+1", "0x100+0+1", ""):
            with self.assertRaises(ValueError, msg=spec):
                mlxfwutil.parse_merge_spec(spec)


class TestMerge(RefsMixin, unittest.TestCase):
    def test_noop_same_image(self):
        img = Image(ADA1012.read_bytes(), "ada")
        out = mlxfwutil.merge_fields(img, img, [(0x11, 0x2b7, 4), (0x10, 0, 16)])
        self.assertEqual(out, img.buf)

    def test_field_copied_and_crc_ok(self):
        base = Image(HPE.read_bytes(), "hpe")
        src = Image(DELL.read_bytes(), "dell")
        out = mlxfwutil.merge_fields(base, src, [(0x10, 0, 16)])
        img = Image(out, "out")
        e_out = img.find_entry("ITOC", 0x10)
        e_base = base.find_entry("ITOC", 0x10)
        e_src = src.find_entry("ITOC", 0x10)
        self.assertEqual(img.section_data(e_out)[0:16],
                         src.section_data(e_src)[0:16])
        self.assertEqual(img.section_data(e_out)[16:e_out.size],
                         base.section_data(e_base)[16:e_base.size])
        self.assertEqual(mlxfwutil.verify_image(img), [])

    def test_boundary_range_ok(self):
        img = Image(ADA1012.read_bytes(), "ada")
        e = img.find_entry("ITOC", 0x12)
        out = mlxfwutil.merge_fields(img, img, [(0x12, e.size - 8, 8)])
        self.assertEqual(out, img.buf)

    def test_range_exceeds_src(self):
        base = Image(HPE.read_bytes(), "hpe")
        src = Image(DELL.read_bytes(), "dell")
        with self.assertRaises(ValueError):
            mlxfwutil.merge_fields(base, src, [(0x30, 0, 0xd1c)])

    def test_range_exceeds_base(self):
        base = Image(DELL.read_bytes(), "dell")
        src = Image(HPE.read_bytes(), "hpe")
        with self.assertRaises(ValueError):
            mlxfwutil.merge_fields(base, src, [(0x30, 0, 0xd1c)])

    def test_unknown_section(self):
        img = Image(ADA1012.read_bytes(), "ada")
        with self.assertRaises(ValueError):
            mlxfwutil.merge_fields(img, img, [(0x55, 0, 4)])

    def test_unknown_section_in_src(self):
        base = Image(ADA1012.read_bytes(), "base")
        b = bytearray(ADA1012.read_bytes())
        e = base.find_entry("ITOC", 0x11)
        ent_off = base.itoc_off + 32 + e.index * 32
        b[ent_off] = 0x55
        src = Image(bytes(b), "src")
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.merge_fields(base, src, [(0x11, 0, 4)])
        self.assertIn("src", str(cm.exception))

    def test_negative_offset_direct_api(self):
        img = Image(ADA1012.read_bytes(), "ada")
        with self.assertRaises(ValueError):
            mlxfwutil.merge_fields(img, img, [(0x11, -1, 4)])

    def test_8mib_half_guard(self):
        b = bytearray(ADA1012.read_bytes())
        img0 = Image(bytes(b), "ada")
        e = img0.find_entry("ITOC", 0x12)
        ent_off = img0.itoc_off + 32 + e.index * 32
        ent = bytearray(b[ent_off:ent_off + 32])
        mlxfwutil.set_bits(ent, 161, 29, 0x7FFC00 // 4)
        b[ent_off:ent_off + 32] = ent
        img = Image(bytes(b), "corrupt")
        with self.assertRaises(ValueError):
            mlxfwutil.merge_fields(img, img, [(0x12, 0, 4)])

    def test_8mib_half_guard_src(self):
        base = Image(ADA1012.read_bytes(), "base")
        b = bytearray(ADA1012.read_bytes())
        e = base.find_entry("ITOC", 0x12)
        ent_off = base.itoc_off + 32 + e.index * 32
        ent = bytearray(b[ent_off:ent_off + 32])
        set_bits(ent, 161, 29, 0x7FFC00 // 4)
        b[ent_off:ent_off + 32] = ent
        src = Image(bytes(b), "src")
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.merge_fields(base, src, [(0x12, 0, 4)])
        self.assertIn("src", str(cm.exception))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "merged.bin"
            src = Image(DELL.read_bytes(), "dell")
            expect = src.section_data(src.find_entry("ITOC", 0x10))[0:16]
            rc = mlxfwutil.main(["merge", "--base", str(HPE), "--src", str(DELL),
                              "--spec", "0x10+0x0+16", "-o", str(out)])
            self.assertEqual(rc, 0)
            img = Image(out.read_bytes(), "out")
            self.assertEqual(img.section_data(img.find_entry("ITOC", 0x10))[0:16], expect)
            self.assertEqual(mlxfwutil.verify_image(img), [])

    def test_cli_error_path(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "merged.bin"
            rc = mlxfwutil.main(["merge", "--base", str(HPE), "--src", str(DELL),
                              "--spec", "0x55+0+4", "-o", str(out)])
            self.assertEqual(rc, 2)
            self.assertFalse(out.exists())


class TestCh5EcodeMergeRepro(RefsMixin, unittest.TestCase):
    """ch5 T5.1: t52_g4/t53_final пересобраны из 8008-ECA + field-map
    (журнал 2026-09-12-eda-ib-node-ch5-task-02), md5 зафиксированы X/Y.
    build/ — git-ignored, образы пересобираются на месте (tmp dir)."""

    BASE_MD5 = "d80c5b311ff85b9d0260b5b079a9a21a"   # 8008-ECA (refs)
    T52_MD5 = "cee795cb06896702b427030d4b3745a7"    # 8008-ECA + Gen4 (4 поля) = X
    T53_MD5 = "5e15694311f6bbad85734cb52caf33ce"    # t52 + 0x11+0x2b7=03 = Y
    GEN4 = ["0x08+0x23=0f", "0x09+0x86c=62fc62fc",
            "0x11+0x47=1a", "0x11+0x93=47"]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not (ECA8008.is_file() and ADA8008.is_file()):
            raise unittest.SkipTest("8008-ECA/8008-ADA refs not present")

    def test_base_md5(self):
        self.assertEqual(hashlib.md5(ECA8008.read_bytes()).hexdigest(), self.BASE_MD5)

    def test_t52_g4(self):
        img = Image(ECA8008.read_bytes(), "eca8008")
        out = patch_sections(img, [parse_set_spec(s) for s in self.GEN4])
        self.assertEqual(mlxfwutil.verify_image(Image(out, "t52")), [])
        self.assertEqual(hashlib.md5(out).hexdigest(), self.T52_MD5)

    def test_t53_final(self):
        img = Image(ECA8008.read_bytes(), "eca8008")
        out = patch_sections(img, [parse_set_spec(s)
                                   for s in self.GEN4 + ["0x11+0x2b7=03"]])
        self.assertEqual(mlxfwutil.verify_image(Image(out, "t53")), [])
        self.assertEqual(hashlib.md5(out).hexdigest(), self.T53_MD5)

    def test_t53_cli_repro(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "t53_final.bin"
            args = ["patch", str(ECA8008)]
            args += [a for s in self.GEN4 + ["0x11+0x2b7=03"]
                     for a in ("--set", s)]
            args += ["-o", str(out)]
            self.assertEqual(mlxfwutil.main(args), 0)
            self.assertEqual(hashlib.md5(out.read_bytes()).hexdigest(), self.T53_MD5)

    def test_noop_code_merge(self):
        base = Image(ECA8008.read_bytes(), "eca8008")
        src = Image(ADA8008.read_bytes(), "ada8008")
        out = mlxfwutil.merge_fields(base, src, CODE_SECTIONS)
        self.assertEqual(out, base.buf)


class TestWrapper(RefsMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.CX5_25G_GUID = hw_id("CARD_CX5_25G", "guid")
        cls.CX5_25G_MAC = hw_id("CARD_CX5_25G", "mac")

    def test_wrapper_passthrough(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.bin"
            r = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "probes" / "inject_guids.py"),
                 str(ADA1012), "--guid", hex(self.CX5_25G_GUID),
                 "--mac", hex(self.CX5_25G_MAC), "--out", str(out)],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(out.is_file())
            img = Image(out.read_bytes(), "out")
            self.assertEqual(mlxfwutil.verify_image(img), [])
            m = mlxfwutil.MDevInfo.parse(img.section_data(img.find_entry("DTOC", 0xE1)))
            self.assertEqual(m.guid, self.CX5_25G_GUID)
            self.assertEqual(m.mac, self.CX5_25G_MAC)


class TestDetectFormat(Fw4Mixin, unittest.TestCase):
    def test_fs3_vendor(self):
        self.assertEqual(mlxfwutil.detect_format(ACA1912.read_bytes()), ("fs3", 0x0))

    def test_fs4_vendor(self):
        self.assertEqual(mlxfwutil.detect_format(DELL.read_bytes()), ("fs4", 0x0))

    def test_fs2_rejected(self):
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.detect_format(FS2_IMG.read_bytes())
        self.assertIn("FS2", str(cm.exception))

    def test_unknown_magic(self):
        with self.assertRaises(ValueError):
            mlxfwutil.detect_format(b"\x00" * 0x5000)

    def test_16mib_both_slots_prefers_a(self):
        src = ACA1912.read_bytes()
        buf = bytearray(b"\xff" * 16 * 1024 * 1024)
        buf[0:len(src)] = src
        buf[0x800000:0x800000 + 0x30] = src[0:0x30]
        self.assertEqual(mlxfwutil.detect_format(bytes(buf)), ("fs3", 0x0))

    def test_16mib_slot_b_only(self):
        src = ACA1912.read_bytes()
        buf = bytearray(b"\xff" * 16 * 1024 * 1024)
        buf[0x800000:0x800000 + 0x30] = src[0:0x30]
        self.assertEqual(mlxfwutil.detect_format(bytes(buf)), ("fs3", 0x800000))


class TestFs3Parse(Fw4Mixin, unittest.TestCase):
    def test_aca_parse(self):
        img = Image(ACA1912.read_bytes(), "aca")
        self.assertEqual((img.fmt, img.itoc_off, img.dtoc_off), ("fs3", 0x2000, None))
        self.assertEqual(len(img.entries("ITOC")), 31)
        self.assertEqual(len(img.entries("DTOC")), 0)
        e10 = img.find_entry("ITOC", 0x10)
        self.assertEqual((e10.addr, e10.size), (0x4CE000, 0x400))
        e30 = img.find_entry("ITOC", 0x30)
        self.assertEqual((e30.addr, e30.size), (0x4CE400, 0x7CC))
        e0 = img.find_entry("ITOC", 0xE0)
        self.assertEqual((e0.addr, e0.size, e0.rel, e0.dev, e0.crcf), (0xFF8000, 0x140, 0, 1, 0))
        self.assertEqual(img.find_entry("ITOC", 0xE6).crcf, 1)
        self.assertEqual(img.find_entry("ITOC", 0x05).rel, 1)
        for e in img.entries("ITOC"):
            self.assertTrue(img.entry_crc_ok(e), hex(e.type))

    def test_all_six_parse(self):
        for p in FS3_ALL:
            with self.subTest(p.name):
                img = Image(p.read_bytes(), p.name)
                self.assertEqual(img.itoc_off, 0x2000)
                self.assertEqual(len(img.entries("ITOC")), 31)

    def test_slot_b(self):
        src = ACA1912.read_bytes()
        buf = slot_b_fs3(src)
        self.assertEqual(mlxfwutil.detect_format(buf), ("fs3", 0x800000))
        img = Image(buf, "aca-b", base=0x800000)
        self.assertEqual(img.itoc_off, 0x802000)
        ref = Image(src, "aca")
        for t in (0x05, 0x10, 0x30, 0xE0, 0xE1, 0xE6):
            self.assertEqual(img.section_data(img.find_entry("ITOC", t)),
                             ref.section_data(ref.find_entry("ITOC", t)), hex(t))

    def test_itoc_first_valid_header_crc(self):
        buf = bytearray(ACA1912.read_bytes())
        buf[0x1000:0x1010] = ITOC_HDR
        self.assertEqual(Image(bytes(buf), "x").itoc_off, 0x2000)

    def test_itoc_bad_header_crc_rejected(self):
        buf = bytearray(ACA1912.read_bytes())
        buf[0x2000 + 0x1E] ^= 0xFF
        with self.assertRaises(ValueError):
            Image(bytes(buf), "x")

    def test_fs4_auto_fmt(self):
        if not DELL.is_file():
            raise unittest.SkipTest("refs/fw/cx-5-6 not present")
        img = Image(DELL.read_bytes(), "dell")
        self.assertEqual((img.fmt, img.itoc_off), ("fs4", 0x4000))
        self.assertEqual((img.find_entry("ITOC", 0x10).rel,
                          img.find_entry("ITOC", 0x10).dev), (0, 0))


class TestFs3Verify(Fw4Mixin, unittest.TestCase):
    def test_verify_all_six(self):
        for p in FS3_ALL:
            with self.subTest(p.name):
                self.assertEqual(mlxfwutil.cmd_verify(Image(p.read_bytes(), p.name)), 0)

    def test_verify_detects_section_corruption(self):
        buf = bytearray(ACA1912.read_bytes())
        img = Image(bytes(buf), "aca")
        e = img.find_entry("ITOC", 0x12)
        buf[img.sec_abs(e) + 0x10] ^= 0xFF
        self.assertEqual(mlxfwutil.cmd_verify(Image(bytes(buf), "aca")), 1)

    def test_verify_no_crc_section_ignored(self):
        buf = bytearray(ACA1912.read_bytes())
        img = Image(bytes(buf), "aca")
        e = img.find_entry("ITOC", 0xE6)
        buf[img.sec_abs(e) + 0x10] ^= 0xFF
        self.assertEqual(mlxfwutil.cmd_verify(Image(bytes(buf), "aca")), 0)

    def test_verify_entry_crc_ng(self):
        buf = bytearray(ACA1912.read_bytes())
        img = Image(bytes(buf), "aca")
        e = img.find_entry("ITOC", 0x08)
        buf[img.itoc_off + 32 + e.index * 32 + 1] ^= 0xFF
        self.assertEqual(mlxfwutil.cmd_verify(Image(bytes(buf), "aca")), 1)

    def test_verify_mfg_info_missing(self):
        buf = bytearray(ACA1912.read_bytes())
        img = Image(bytes(buf), "aca")
        e = img.find_entry("ITOC", 0xE0)
        buf[img.itoc_off + 32 + e.index * 32] = 0x13  # тип 0xE0 -> 0x13 (запись "пропадает")
        errs = mlxfwutil.verify_image(Image(bytes(buf), "aca"))
        self.assertTrue(any("MFG_INFO" in x for x in errs))

    def test_info_smoke(self):
        import io
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(mlxfwutil.cmd_info(Image(ACA1912.read_bytes(), "aca")), 0)
        text = out.getvalue()
        self.assertIn("ITOC @ 0x2000", text)
        self.assertNotIn("DTOC", text)
        self.assertIn("MFG_INFO", text)
        self.assertNotIn("hashes table", text)
        self.assertIn("rel=1", text)


class TestFs3Extract(Fw4Mixin, unittest.TestCase):
    def test_extract_ini_matches_dc_dump(self):
        img = Image(ACA1912.read_bytes(), "aca")
        data = extract_section(img, 0x30)
        self.assertEqual(zlib.decompress(data), (FW4 / "MCX4121A-ACA_Ax-dc.ini").read_bytes())

    def test_extract_image_info_psid(self):
        img = Image(ACA1912.read_bytes(), "aca")
        self.assertEqual(image_info_fields(extract_section(img, 0x10))["psid"],
                         "MT_2420110034")


class TestFs3Diff(Fw4Mixin, unittest.TestCase):
    def test_diff_aca_bca(self):
        self.assertEqual(mlxfwutil.cmd_diff(Image(ACA1912.read_bytes(), "a"),
                                         Image(BCA1912.read_bytes(), "b")), 0)

    def test_diff_format_mismatch(self):
        if not DELL.is_file():
            raise unittest.SkipTest("refs/fw/cx-5-6 not present")
        self.assertEqual(mlxfwutil.cmd_diff(Image(ACA1912.read_bytes(), "a"),
                                         Image(DELL.read_bytes(), "d")), 2)


class TestFs3PatchMerge(Fw4Mixin, unittest.TestCase):
    def test_patch_fw_section(self):
        img = Image(ACA1912.read_bytes(), "aca")
        out = patch_sections(img, [(0x32, 0x0, b"\xCD")])
        self.assertEqual(mlxfwutil.verify_image(Image(out, "out")), [])
        vimg = Image(out, "out")
        self.assertEqual(vimg.section_data(vimg.find_entry("ITOC", 0x32))[0], 0xCD)

    def test_patch_dev_section(self):
        img = Image(ACA1912.read_bytes(), "aca")
        out = patch_sections(img, [(0xE0, 0x20, b"\x01")])
        vimg = Image(out, "out")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        e = vimg.find_entry("ITOC", 0xE0)
        self.assertEqual(vimg.section_data(e)[0x20], 1)

    def test_patch_dev_section_slot_b(self):
        buf = slot_b_fs3(ACA1912.read_bytes())
        img = Image(buf, "b", base=0x800000)
        out = patch_sections(img, [(0xE0, 0x20, b"\x01")])
        vimg = Image(out, "out", base=0x800000)
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        e = vimg.find_entry("ITOC", 0xE0)
        self.assertEqual(vimg.section_data(e)[0x20], 1)

    def test_patch_past_section_end_rejected(self):
        img = Image(ACA1912.read_bytes(), "aca")
        with self.assertRaises(ValueError):
            patch_sections(img, [(0xE0, 0x13F, b"\x01\x02")])

    def test_merge_hw_boot_cfg(self):
        base = Image(ACA1912.read_bytes(), "a")
        src = Image(BCA1912.read_bytes(), "b")
        out = merge_fields(base, src, [(0x08, 0x0, 0x140)])
        self.assertEqual(mlxfwutil.verify_image(Image(out, "out")), [])

    def test_merge_dev_section(self):
        base = Image(ACA1912.read_bytes(), "a")
        src = Image(BCA1912.read_bytes(), "b")
        out = merge_fields(base, src, [(0xE0, 0x0, 0x140)])
        self.assertEqual(mlxfwutil.verify_image(Image(out, "out")), [])

    def test_merge_format_mismatch(self):
        if not DELL.is_file():
            raise unittest.SkipTest("refs/fw/cx-5-6 not present")
        with self.assertRaises(ValueError):
            merge_fields(Image(ACA1912.read_bytes(), "a"),
                         Image(DELL.read_bytes(), "d"), [(0x08, 0x0, 4)])

    def test_patch_self_verify_failure_no_output(self):
        # base с чужим битым CRC: patch применяется, self-verify FAIL -> rc=1, файла нет
        if not HPE.is_file():
            raise unittest.SkipTest("refs/fw/cx-5-6 not present")
        b = bytearray(HPE.read_bytes())
        img0 = Image(bytes(b), "hpe")
        e = img0.find_entry("ITOC", 0x12)
        b[e.addr + 0x10] ^= 0xFF
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "corrupt.bin"
            src.write_bytes(bytes(b))
            out = Path(td) / "out.bin"
            rc = mlxfwutil.main(["patch", str(src), "--set", "0x08+0x0=01", "-o", str(out)])
            self.assertEqual(rc, 1)
            self.assertFalse(out.exists())


class TestFs3Psid(Fw4Mixin, unittest.TestCase):
    def test_psid_double_write(self):
        img = Image(ACA1912.read_bytes(), "aca")
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "o.bin"
            args = argparse.Namespace(image="aca", psid="MT_TESTFS30001", name=None,
                                      description=None, output=str(out))
            self.assertEqual(mlxfwutil.cmd_psid(img, args), 0)
            check = Image(out.read_bytes(), "o")
            self.assertEqual(mlxfwutil.cmd_verify(check), 0)
            self.assertEqual(image_info_fields(check.section_data(check.find_entry("ITOC", 0x10)))["psid"],
                             "MT_TESTFS30001")
            e0 = check.find_entry("ITOC", 0xE0)
            self.assertEqual(check.section_data(e0)[0:14], b"MT_TESTFS30001")

    def test_psid_mfg_too_long(self):
        img = Image(ACA1912.read_bytes(), "aca")
        with tempfile.TemporaryDirectory() as td:
            args = argparse.Namespace(image="aca", psid="MT_" + "X" * 13, name=None,
                                      description=None, output=str(Path(td) / "o.bin"))
            with self.assertRaises(ValueError):
                mlxfwutil.cmd_psid(img, args)


class TestFs3Guides(Fw4Mixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.GUID = hw_id("CARD_CX5_25G", "guid")
        cls.MAC = hw_id("CARD_CX5_25G", "mac")

    def _ns(self, image, out):
        import argparse
        return argparse.Namespace(image=str(image), guid=self.GUID, mac=self.MAC, output=str(out))

    def _mutate(self, muts):
        src = bytearray(ACA1912.read_bytes())
        img0 = Image(bytes(src), "aca")
        for t, fn in muts.items():
            e = img0.find_entry("ITOC", t)
            a = img0.sec_abs(e)
            sec = bytearray(src[a:a + e.size])
            fn(sec)
            src[a:a + e.size] = sec
            off = img0.itoc_off + 32 + e.index * 32
            ent = bytearray(src[off:off + 32])
            set_bits(ent, 208, 16, crc16_mlx(bytes(sec)))
            set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
            src[off:off + 32] = ent
        return bytes(src)

    def test_guides_success(self):
        src = ACA1912.read_bytes()
        img0 = Image(src, "aca")
        e0, e1 = img0.find_entry("ITOC", 0xE0), img0.find_entry("ITOC", 0xE1)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "o.bin"
            self.assertEqual(mlxfwutil.cmd_guides(self._ns(ACA1912, out)), 0)
            data = out.read_bytes()
            self.assertEqual(len(data), len(src))
            self.assertEqual(mlxfwutil.verify_image(Image(data, "out")), [])
            for e in (e0, e1):
                s = data[e.addr:e.addr + e.size]
                self.assertEqual(int.from_bytes(s[0x28:0x30], "big"), self.GUID)
                self.assertEqual(int.from_bytes(s[0x38:0x40], "big"), self.MAC)
                sa = src[e.addr:e.addr + e.size]
                self.assertEqual(s[:0x28], sa[:0x28])
                self.assertEqual(s[0x30:0x38], sa[0x30:0x38])
                self.assertEqual(s[0x40:], sa[0x40:])
            self.assertEqual(data[e0.addr:e0.addr + 14], b"MT_2420110034\x00")
            self.assertEqual(data[e0.addr + 0x1F] & 1, 1)
            itoc_end = img0.itoc_off + 32 + len(img0.itoc) * 32
            self.assertEqual(data[0:img0.itoc_off], src[0:img0.itoc_off])
            for e in img0.itoc:
                if e.type in (0xE0, 0xE1):
                    continue
                off = img0.itoc_off + 32 + e.index * 32
                self.assertEqual(data[off:off + 32], src[off:off + 32])
            for e in (e0, e1):
                off = img0.itoc_off + 32 + e.index * 32
                self.assertEqual(data[off:off + 0x1A], src[off:off + 0x1A])
                self.assertEqual(data[off + 0x1C:off + 0x1E], src[off + 0x1C:off + 0x1E])
                self.assertEqual(int.from_bytes(data[off + 0x1A:off + 0x1C], "big"),
                                 crc16_mlx(data[e.addr:e.addr + e.size]))
                self.assertEqual(int.from_bytes(data[off + 0x1E:off + 0x20], "big"),
                                 crc16_mlx(data[off:off + 0x1C]))
            lo, hi = (e1, e0) if e1.addr < e0.addr else (e0, e1)
            self.assertEqual(data[itoc_end:lo.addr], src[itoc_end:lo.addr])
            self.assertEqual(data[lo.addr + lo.size:hi.addr], src[lo.addr + lo.size:hi.addr])
            self.assertEqual(data[hi.addr + hi.size:], src[hi.addr + hi.size:])

    def test_devinfo_major1_rejected(self):
        def bad(sec):
            sec[0x12] = 1
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "m1.bin"
            src.write_bytes(self._mutate({0xE1: bad}))
            out = Path(td) / "o.bin"
            self.assertNotEqual(mlxfwutil.cmd_guides(self._ns(src, out)), 0)
            self.assertFalse(out.exists())

    def test_mfg_major0_rejected(self):
        def bad(sec):
            sec[0x1C] = 0
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "m0.bin"
            src.write_bytes(self._mutate({0xE0: bad}))
            out = Path(td) / "o.bin"
            self.assertNotEqual(mlxfwutil.cmd_guides(self._ns(src, out)), 0)
            self.assertFalse(out.exists())

    def test_override_en0_warns_rc0(self):
        def bad(sec):
            sec[0x1F] &= ~1
        import io, contextlib
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "ovr0.bin"
            src.write_bytes(self._mutate({0xE0: bad}))
            out = Path(td) / "o.bin"
            with contextlib.redirect_stderr(err):
                self.assertEqual(mlxfwutil.cmd_guides(self._ns(src, out)), 0)
            self.assertIn("guids_override_en=0", err.getvalue())
            data = out.read_bytes()
            e0 = Image(data, "o").find_entry("ITOC", 0xE0)
            s = data[e0.addr:e0.addr + e0.size]
            self.assertEqual(int.from_bytes(s[0x28:0x30], "big"), self.GUID)


class TestInjectUnit(unittest.TestCase):
    def test_in_place_shrink(self):
        buf, _ = _mini_fs3()
        img = Image(buf, "mini")
        out = mlxfwutil.inject_ini(img, "[ADAPTER]\nPSID = X\n")
        vimg = Image(out, "o")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        e = vimg.find_entry("ITOC", 0x30)
        self.assertEqual(e.addr, 0x2000)
        self.assertLess(e.size, 0x100)
        self.assertEqual(zlib.decompress(vimg.section_data(e)), b"[ADAPTER]\nPSID = X\n")

    def test_grow_relocate_tail(self):
        # dev-секция отнесена к 0x18000: rel-only хвост 0x10000 помещается
        # до non-relative границы (64K-выравнивание съело дефолтный gap 0x2200)
        buf, ini = _mini_fs3(dev_addr=0x18000)
        img = Image(buf, "mini")
        big = ini + os.urandom(4096)  # несжимаемое: lvl9-размер > 0x100 -> grow-путь
        out = mlxfwutil.inject_ini(img, big.decode("latin1"), force=True)
        vimg = Image(out, "o")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        e = vimg.find_entry("ITOC", 0x30)
        self.assertNotEqual(e.addr, 0x2000)
        self.assertEqual(e.addr, 0x10000)  # align64k(rel-only max end 0x2200)
        self.assertEqual(e.addr % 0x10000, 0)
        self.assertEqual([x.type for x in vimg.entries("ITOC")], [0x32, 0x30, 0xE0])
        self.assertEqual(e.index, 1)  # релоцированная запись — конец rel-блока (до dev)
        self.assertEqual(zlib.decompress(vimg.section_data(e)), big)
        self.assertEqual(bytes(vimg.buf[0x2000:0x2100]), b"\xFF" * 0x100)  # старое место стёрто
        self.assertEqual(mlxfwutil.burn_order_check(vimg), [])

    def test_grow_guard_no_force(self):
        buf, ini = _mini_fs3()
        img = Image(buf, "mini")
        big = ini + os.urandom(4096)
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.inject_ini(img, big.decode("latin1"))
        self.assertIn("--repack-force", str(cm.exception))

    def test_grow_guard_no_force_fs4(self):
        if not D1RAW.is_file():
            raise unittest.SkipTest("d1_raw.bin not present")
        img = Image(D1RAW.read_bytes(), "d1", base=0x800000)
        ini = zlib.decompress(extract_section(img, 0x30))
        big = ini + os.urandom(4096)
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.inject_ini(img, big.decode("latin1"))
        self.assertIn("--repack-force", str(cm.exception))

    def test_inject_cli_guard_rc(self):
        buf, ini = _mini_fs3(dev_addr=0x18000)  # rel-only хвост 0x10000 ниже dev
        big = (ini + os.urandom(4096)).decode("latin1")
        with tempfile.TemporaryDirectory() as td:
            imgp = Path(td) / "mini.bin"
            inip = Path(td) / "big.ini"
            outp = Path(td) / "out.bin"
            imgp.write_bytes(buf)
            inip.write_text(big, encoding="latin1")
            import contextlib
            import io
            # --no-autosign: у мини-фикстуры нет 0xA0 (missing) — автознак
            # после релокации отказал бы; тест про --repack-force, не про sign
            ns = argparse.Namespace(image=str(imgp), ini=str(inip),
                                    output=str(outp), repack_force=False,
                                    no_autosign=True, unsafe_relocation=False)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(mlxfwutil.cmd_inject(ns), 2)
            self.assertIn("--repack-force", err.getvalue())
            ns.repack_force = True
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(mlxfwutil.cmd_inject(ns), 0)
            self.assertTrue(outp.is_file())

    def test_grow_no_space(self):
        buf, ini = _mini_fs3(dev_addr=0x2200)  # dev-секция сразу за 0x32 — tail-gap пуст
        img = Image(buf, "mini")
        big = ini + os.urandom(4096)  # несжимаемое: lvl9-размер > 0x100 -> grow-путь
        with self.assertRaises(ValueError):
            mlxfwutil.inject_ini(img, big.decode("latin1"), force=True)

    def test_zlib_header_78da(self):
        buf, ini = _mini_fs3()
        out = mlxfwutil.inject_ini(Image(buf, "mini"), ini.decode("latin1"))
        e = Image(out, "o").find_entry("ITOC", 0x30)
        self.assertEqual(Image(out, "o").section_data(e)[:2], b"\x78\xda")

    def test_inject_fs4_slot_b_grow(self):
        if not D1RAW.is_file():
            raise unittest.SkipTest("d1_raw.bin not present")
        img = Image(D1RAW.read_bytes(), "d1", base=0x800000)
        ini = zlib.decompress(extract_section(img, 0x30))
        big = ini + os.urandom(4096)  # несжимаемое -> grow-путь
        out = mlxfwutil.inject_ini(img, big.decode("latin1"), force=True)
        vimg = Image(out, "o", base=0x800000)
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        self.assertEqual(zlib.decompress(extract_section(vimg, 0x30)), big)


class TestInjectRoundTrip(RefsMixin, unittest.TestCase):
    def test_roundtrip_all_pairs(self):
        for binp, inip in ROUND_TRIP_PAIRS:
            binp, inip = REPO / binp, REPO / inip
            with self.subTest(bin=binp.name):
                if not (binp.is_file() and inip.is_file()):
                    raise unittest.SkipTest(f"refs pair missing: {binp.name}")
                img = _image(str(binp))
                ini = inip.read_bytes()
                out = mlxfwutil.inject_ini(img, ini.decode("latin1"), force=True)
                vimg = Image(out, "out")
                self.assertEqual(mlxfwutil.verify_image(vimg), [], binp.name)
                self.assertEqual(zlib.decompress(extract_section(vimg, 0x30)), ini, binp.name)


class TestFs3RepackStocks(Fw4Mixin, unittest.TestCase):
    """FS3-ветки repack/swap на реальных 1912-стоках: raise «FS4 only»
    закрыт (arc D task-5, спека repack-burn-safety §9) — гейты те же."""

    def test_repack_swap_fs3(self):
        out = swap_repack(str(ACA1912), [(str(BCA1912), [0x08])])
        img = Image(out, "swap")
        self.assertEqual(mlxfwutil.verify_image(img), [])
        self.assertEqual(mlxfwutil.burn_order_check(img), [])
        bca = Image(BCA1912.read_bytes(), "bca")
        self.assertEqual(img.section_data(img.find_entry("ITOC", 0x08)),
                         bca.section_data(bca.find_entry("ITOC", 0x08)))

    def test_repack_legacy_fs3(self):
        out = repack(str(ACA1912), str(BCA1912), "new")
        img = Image(out, "legacy")
        self.assertEqual(mlxfwutil.verify_image(img), [])
        self.assertEqual(mlxfwutil.burn_order_check(img), [])

    def test_demo_build(self):
        img = Image(ACA1912.read_bytes(), "aca")
        out = set_psid(img, "MT_DEMOFS30001")
        out = patch_sections(Image(out, "o1"), [(0x32, 0x0, b"\xCD")])
        ini = (FW4 / "MCX4121A-ACA_Ax-dc.ini").read_text(encoding="latin1")
        ini = ini.replace("psid = MT_2420110034", "psid = MT_DEMOFS30001", 1)
        out = inject_ini(Image(out, "o2"), ini, force=True)
        vimg = Image(out, "demo")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        self.assertEqual(image_info_fields(vimg.section_data(vimg.find_entry("ITOC", 0x10)))["psid"],
                         "MT_DEMOFS30001")
        self.assertEqual(vimg.section_data(vimg.find_entry("ITOC", 0xE0))[0:14], b"MT_DEMOFS30001")
        self.assertEqual(zlib.decompress(extract_section(vimg, 0x30)),
                         ini.encode("latin1"))


class TestTocEntryParams(unittest.TestCase):
    def _toc_buf(self, entry: bytes) -> bytes:
        buf = bytearray(64)
        buf[0:16] = ITOC_HDR
        buf[0x1E:0x20] = struct.pack(">H", crc16_mlx(bytes(buf[:28])))
        buf[32:64] = entry
        return bytes(buf)

    def _entry(self, typ=0x03, param0=0, param1=0) -> bytes:
        e = bytearray(32)
        e[0] = typ
        set_bits(e, 8, 22, 0x100)
        set_bits(e, 34, 30, param0)
        set_bits(e, 64, 32, param1)
        set_bits(e, 161, 29, 0x1000)
        set_bits(e, 240, 16, crc16_mlx(bytes(e[:28])))
        return bytes(e)

    def test_fs4_param0_param1(self):
        ents = mlxfwutil.parse_toc(
            self._toc_buf(self._entry(param0=0x00800000, param1=0x0081cf18)),
            0, "ITOC", "fs4")
        self.assertEqual(len(ents), 1)
        self.assertEqual(ents[0].param0, 0x00800000)
        self.assertEqual(ents[0].param1, 0x0081cf18)

    def test_fs3_param0_param1(self):
        ents = mlxfwutil.parse_toc(
            self._toc_buf(self._entry(param0=0x00800000, param1=0x00806bb8)),
            0, "ITOC", "fs3")
        self.assertEqual(ents[0].param0, 0x00800000)
        self.assertEqual(ents[0].param1, 0x00806bb8)

    def test_zero_params(self):
        ents = mlxfwutil.parse_toc(self._toc_buf(self._entry()), 0, "ITOC", "fs4")
        self.assertEqual(ents[0].param0, 0)
        self.assertEqual(ents[0].param1, 0)


class TestTocHeaderParse(unittest.TestCase):
    def _hdr(self, flv=0, ver=1, num=0) -> bytes:
        h = bytearray(32)
        h[0:16] = ITOC_HDR
        set_bits(h, 128, 8, flv)
        set_bits(h, 152, 8, ver)
        set_bits(h, 184, 8, num)
        h[0x1E:0x20] = struct.pack(">H", crc16_mlx(bytes(h[:28])))
        return bytes(h)

    def test_fs4_fields(self):
        th = mlxfwutil.parse_toc_header(self._hdr(flv=1, ver=1, num=29), "fs4")
        self.assertEqual((th.version, th.flv, th.num_entries), (1, 1, 29))

    def test_fs3_reserved_none(self):
        th = mlxfwutil.parse_toc_header(self._hdr(flv=0x55, ver=1, num=0x77),
                                     "fs3")
        self.assertEqual(th.version, 1)
        self.assertIsNone(th.flv)
        self.assertIsNone(th.num_entries)


class TestImageHeaders(RefsMixin, unittest.TestCase):
    def test_fs4_image_headers(self):
        img = Image(ADA1012.read_bytes(), "ada")
        self.assertEqual(img.itoc_header.version, 1)
        self.assertEqual(img.itoc_header.flv, 1)
        self.assertEqual(img.itoc_header.num_entries, 0)
        self.assertEqual(img.dtoc_header.version, 1)
        self.assertEqual(img.dtoc_header.flv, 1)
        self.assertEqual(img.dtoc_header.num_entries, 0)

    def test_fs3_image_headers(self):
        img = Image(ACA1912.read_bytes(), "aca")
        self.assertIsNone(img.dtoc_header)
        self.assertEqual(img.itoc_header.version, 1)
        self.assertIsNone(img.itoc_header.flv)
        self.assertIsNone(img.itoc_header.num_entries)


class TestInfoTocMeta(RefsMixin, unittest.TestCase):
    def _info(self, path: Path) -> str:
        import io, contextlib
        img = Image(path.read_bytes(), path.name)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(mlxfwutil.cmd_info(img), 0)
        return out.getvalue()

    def test_fs4_header_lines_unchanged(self):
        lines = self._info(ADA1012).splitlines()
        self.assertIn("  ITOC @ 0x5000: flash_layout_ver=1 ver=1 "
                      "num_entries=0 hdr_crc=OK", lines)
        self.assertIn("  DTOC @ 0xfff000: flash_layout_ver=1 ver=1 "
                      "num_entries=0 hdr_crc=OK", lines)

    def test_fs3_header_line_no_reserved(self):
        text = self._info(ACA1912)
        self.assertIn("  ITOC @ 0x2000: ver=1 hdr_crc=OK", text)
        self.assertNotIn("flash_layout_ver", text)
        self.assertNotIn("num_entries", text)

    def test_ram_map_block_fs4(self):
        lines = self._info(ADA1012).splitlines()
        self.assertIn("  RAM map (param0/param1, non-zero only):", lines)
        main = [l for l in lines if "load=" in l and "MAIN_CODE" in l]
        self.assertEqual(len(main), 1)
        self.assertTrue(main[0].endswith(
            "load=0x00800000 jump=0x0081cf18"), main[0])

    def test_ram_map_block_fs3(self):
        lines = self._info(ACA1912).splitlines()
        self.assertIn("  RAM map (param0/param1, non-zero only):", lines)
        main = [l for l in lines if "load=" in l and "MAIN_CODE" in l]
        self.assertEqual(len(main), 1)
        self.assertTrue(main[0].endswith(
            "load=0x00800000 jump=0x00807edc"), main[0])

    def test_entry_lines_format_unchanged(self):
        import re
        pat = re.compile(
            r"^    \[\s*\d+\] 0x[0-9a-f]{2} .+ size=0x[0-9a-f]+ "
            r"addr=0x[0-9a-f]+ sec_crc=.+ entry_crc=0x[0-9a-f]{4}"
            r"\((OK|NG)\) .+$")
        for path in (ADA1012, ACA1912):
            for l in self._info(path).splitlines():
                if l.startswith("    [") and " sec_crc=" in l:
                    self.assertIsNotNone(pat.match(l), l)

    def test_ram_map_count(self):
        img = Image(ADA1012.read_bytes(), "ada")
        expected = sum(1 for e in img.itoc + img.dtoc
                       if e.type != 0xFF and (e.param0 or e.param1))
        actual = len([l for l in self._info(ADA1012).splitlines()
                      if l.startswith("    [") and "load=" in l])
        self.assertEqual(actual, expected)
        self.assertGreater(expected, 0)


class TestVerifyTocMeta(RefsMixin, unittest.TestCase):
    def test_clean_corpus(self):
        for p in (ADA1012, E456_4706, CX6DX_IMG0, D1RAW):
            img = Image(p.read_bytes(), p.name,
                        base=detect_slot(p.read_bytes()))
            self.assertEqual(mlxfwutil.verify_warnings(img), [], p.name)

    def _patched(self, mut):
        buf = bytearray(ADA1012.read_bytes())
        img0 = Image(bytes(buf), "ada")
        mut(buf, img0)
        return Image(bytes(buf), "ada")

    def test_num_entries_mismatch(self):
        def mut(buf, img0):
            off = img0.itoc_off
            set_bits(buf, off * 8 + 184, 8, 5)
            buf[off + 0x1E:off + 0x20] = struct.pack(
                ">H", crc16_mlx(bytes(buf[off:off + 0x1C])))
        img = self._patched(mut)
        actual = len(img.entries("ITOC"))
        self.assertEqual(
            mlxfwutil.verify_warnings(img),
            [f"ITOC header num_of_entries=5 != {actual} "
             f"entries (excluding END)"])

    def test_flv_mismatch(self):
        def mut(buf, img0):
            off = img0.dtoc_off
            set_bits(buf, off * 8 + 128, 8, 0)
            buf[off + 0x1E:off + 0x20] = struct.pack(
                ">H", crc16_mlx(bytes(buf[off:off + 0x1C])))
        img = self._patched(mut)
        self.assertEqual(
            mlxfwutil.verify_warnings(img),
            ["flash_layout_version: ITOC=1 > DTOC=0 (mstflint would require "
             "device-section alignment)"])

    def test_flv_reverse_no_warning(self):
        def mut(buf, img0):
            off = img0.itoc_off
            set_bits(buf, off * 8 + 128, 8, 0)
            buf[off + 0x1E:off + 0x20] = struct.pack(
                ">H", crc16_mlx(bytes(buf[off:off + 0x1C])))
        img = self._patched(mut)
        self.assertEqual(mlxfwutil.verify_warnings(img), [])

    def test_cmd_verify_stderr_and_rc(self):
        import io, contextlib
        buf = bytearray(ADA1012.read_bytes())
        img0 = Image(bytes(buf), "ada")
        off = img0.itoc_off
        set_bits(buf, off * 8 + 184, 8, 5)
        buf[off + 0x1E:off + 0x20] = struct.pack(
            ">H", crc16_mlx(bytes(buf[off:off + 0x1C])))
        img = Image(bytes(buf), "ada")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mlxfwutil.cmd_verify(img)
        self.assertEqual(rc, 0)
        self.assertIn("RESULT: PASS", out.getvalue())
        self.assertIn("warning: ITOC header num_of_entries=5",
                      err.getvalue())


class TestRewritePreservesParams(RefsMixin, unittest.TestCase):
    def test_patch_preserves_param_bits(self):
        img = Image(ADA1012.read_bytes(), "ada")
        e = img.find_entry("ITOC", 0x10)
        d = img.section_data(e)
        out = mlxfwutil.patch_sections(img, [(0x10, 0x00, bytes([d[0] ^ 1]))])
        chk = Image(out, "out")
        ne = chk.find_entry("ITOC", 0x10)
        self.assertEqual(bytes(ne.raw[0x04:0x0C]), bytes(e.raw[0x04:0x0C]))
        self.assertEqual(bytes(ne.raw[:0x04]), bytes(e.raw[:0x04]))
        self.assertNotEqual(bytes(ne.raw[0x1A:0x20]), bytes(e.raw[0x1A:0x20]))
        self.assertEqual(mlxfwutil.cmd_verify(chk), 0)


if __name__ == "__main__":
    unittest.main()
