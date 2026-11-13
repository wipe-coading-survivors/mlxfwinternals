import contextlib
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import mlxfwutil  # noqa: E402
import pytest  # noqa: E402
from mlxfwutil import (CNTX_MAGIC, DTOC_HDR, FS4_MAGIC, ITOC_HDR, Image,  # noqa: E402
                     burn_order_check, crc16_mlx, set_bits)

from test_mlxfwutil import REPO  # noqa: E402
from test_sign import SynthMixin  # noqa: E402

GCA1912 = REPO / "refs" / "fw" / "cx-4" / (
    "fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")

# fs3-синтетика: все sec/entry CRC валидны (verify_image чист), 0xA0 crcf=0
# со слотом @+0x20 (автознак-способность), dev-запись non-rel — граница хвоста
FS3_LAYOUT = [
    (0x05, 0x10000, 0x100, 1, 0),
    (0x0C, 0x11000, 0x80, 1, 0),
    (0x30, 0x20000, 0x80, 1, 0),
    (0xA0, 0x21000, 0x40, 1, 0),
    (0xE0, 0x40000, 0x140, 0, 1),
]


def _fs3_synth(sections, bufsize=0x50000):
    end = max((addr + size for _, addr, size, _, _ in sections), default=0)
    buf = bytearray(b"\xff" * max(end + 0x1000, bufsize))
    buf[0:16] = CNTX_MAGIC
    buf[0x24:0x28] = b"\x03\x17\x01\x01"
    rows, data = [], []
    for i, (t, addr, size, rel, dev) in enumerate(sections):
        if t == 0xA0:
            d = SynthMixin()._sig_data(slot=b"\x11" * 32)[:size]
            crcf = 0
        else:
            d = bytes((i * 37 + j * 13 + 7) % 251 for j in range(size))
            crcf = 0
        rows.append(SynthMixin()._toc_ent_fs3(t, size, addr, rel=rel, dev=dev,
                                               crcf=crcf, sec_crc=crc16_mlx(d)))
        data.append((addr, d))
    rows.append(SynthMixin()._toc_ent_fs3(0xFF, 0, 0))
    buf[0x1000:0x1020] = SynthMixin()._toc_hdr(ITOC_HDR, len(rows) - 1)
    for i, row in enumerate(rows):
        buf[0x1020 + i * 32:0x1040 + i * 32] = row
    for addr, d in data:
        buf[addr:addr + len(d)] = d
    return bytes(buf)


def _fs4_synth(sections, bufsize=0x50000, devinfo_addr=0x30000):
    # FS4-путь resize (механически тот же планировщик): 0xA0 crcf=1,
    # DTOC — один валидный mDevInfo
    m = SynthMixin()
    buf = bytearray(b"\xff" * bufsize)
    buf[0:16] = FS4_MAGIC
    rows, data = [], []
    for i, (t, addr, size) in enumerate(sections):
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
    buf[0x1100:0x1120] = m._toc_hdr(DTOC_HDR, 1)
    buf[0x1120:0x1140] = m._toc_ent(0xE1, 0x40, devinfo_addr, crcf=2)
    buf[0x1140:0x1160] = m._toc_ent(0xFF, 0, 0)
    for addr, d in data:
        buf[addr:addr + len(d)] = d
    buf[devinfo_addr:devinfo_addr + 0x40] = m._devinfo()
    return bytes(buf)


def _payload(seed, size):
    # без байтов 0xFF: новые данные не путаются со стертостью
    return bytes((seed * 37 + j * 13 + 7) % 251 for j in range(size))


def _fw_view_end(buf):
    """(fw_end, client_end): диапазон деста FW-side TOC-walk на MCC-компоненте
    vs клиентский sizeOfImgData. Компонент = [0, sizeOfImgData) с magic16 и
    dev-строками, замаскированными в 0xFF (FwExtract4MBImage maskDevToc,
    fs3_ops.cpp:3618/3659); walk заканчивается на первой строке type==0xFF
    (fs3_ops.cpp:616) — маскированная dev-строка и есть терминатор, строки
    после неё FW не видит (live 2026-11-12: img-G4a MCC 0x2)."""
    img = Image(buf, "fw")
    assert img.fmt == "fs3"
    client_end = img.base
    for e in img.entries("ITOC"):
        if e.rel:
            client_end = max(client_end, img.sec_abs(e) + e.size)
    fw_end = img.base
    for e in img.entries("ITOC"):
        if e.type == 0xFF or not e.rel:
            break
        fw_end = max(fw_end, img.sec_abs(e) + e.size)
    return fw_end, client_end


def _assert_outside_identity(case, before, after, regions):
    case.assertEqual(len(before), len(after))
    pos = 0
    for s, e in sorted(regions):
        case.assertLessEqual(pos, s, "overlapping identity regions")
        case.assertEqual(before[pos:s], after[pos:s],
                         f"identity violated at 0x{pos:x}..0x{s:x}")
        pos = max(pos, e)
    case.assertEqual(before[pos:], after[pos:])


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = mlxfwutil.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestResizeCore(unittest.TestCase):
    """repack_resize на синтетике (arc D task-5 Step 2): рост средней секции
    -> tail-placement (спека repack-burn-safety §9.2), уменьшение -> in-place;
    ITOC согласован (re-enumeration валидна), вне-регион byte-identity."""

    def _img(self):
        return Image(_fs3_synth(FS3_LAYOUT), "synth")

    def test_grow_relocates_middle_section_to_tail(self):
        img = self._img()
        old = img.find_entry("ITOC", 0x0C)
        grow = _payload(9, 0x180)
        out = mlxfwutil.repack_resize(img, 0x0C, grow)
        vimg = Image(out, "out")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        self.assertEqual(burn_order_check(vimg), [])
        e = vimg.find_entry("ITOC", 0x0C)
        self.assertEqual((e.size, e.addr, e.rel, e.dev, e.zipped, e.clcrc),
                         (0x180, 0x30000, 1, 0, 0, 0))  # align64k(rel max end)
        self.assertEqual(vimg.section_data(e), grow)
        self.assertEqual([x.type for x in vimg.entries("ITOC")],
                         [0x05, 0x30, 0xA0, 0x0C, 0xE0])  # строка — в rel-блоке
        self.assertEqual(out[0x11000:0x11080], b"\xFF" * 0x80)  # старое место
        for t in (0x05, 0x30, 0xA0, 0xE0):  # прочие секции не тронуты
            be, ae = img.find_entry("ITOC", t), vimg.find_entry("ITOC", t)
            self.assertEqual((ae.addr, ae.size), (be.addr, be.size), hex(t))
            self.assertEqual(vimg.section_data(ae), img.section_data(be), hex(t))

    def test_grow_outside_region_identity(self):
        img = self._img()
        out = mlxfwutil.repack_resize(img, 0x0C, _payload(9, 0x180))
        rows = 0x1020, 0x1020 + (len(FS3_LAYOUT) + 1) * 32
        _assert_outside_identity(
            self, img.buf, out,
            [(0x11000, 0x11080), (0x30000, 0x30180), rows])

    def test_shrink_in_place(self):
        img = self._img()
        small = _payload(5, 0x40)
        out = mlxfwutil.repack_resize(img, 0x0C, small)
        vimg = Image(out, "out")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        self.assertEqual(burn_order_check(vimg), [])
        e = vimg.find_entry("ITOC", 0x0C)
        self.assertEqual((e.size, e.addr, e.index), (0x40, 0x11000, 1))  # на месте
        self.assertEqual(vimg.section_data(e), small)
        self.assertEqual(out[0x11040:0x11080], b"\xFF" * 0x40)  # хвост экстента
        rows = 0x1020, 0x1040 + (len(FS3_LAYOUT) + 1) * 32
        _assert_outside_identity(self, img.buf, out, [(0x11000, 0x11080), rows])

    def test_same_size_in_place_no_relocation(self):
        img = self._img()
        out = mlxfwutil.repack_resize(img, 0x0C, _payload(7, 0x80))
        vimg = Image(out, "out")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        rows = 0x1020, 0x1040 + (len(FS3_LAYOUT) + 1) * 32
        _assert_outside_identity(self, img.buf, out, [(0x11000, 0x11080), rows])

    def test_not_dw_aligned_refused(self):
        img = self._img()
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.repack_resize(img, 0x0C, _payload(1, 0x41))
        self.assertIn("DW-aligned", str(cm.exception))

    def test_missing_section_keyerror(self):
        img = self._img()
        with self.assertRaises(KeyError):
            mlxfwutil.repack_resize(img, 0x18, b"\x00" * 0x10)

    def test_grow_dev_section_refused(self):
        img = self._img()
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.repack_resize(img, 0xE0, b"\x00" * 0x200)
        self.assertIn("fixed", str(cm.exception))

    def test_grow_no_room_refused(self):
        # dev bound 0x40000: хвост 0x30000 + 0x10080 не влезает -> RelocNoRoom
        img = self._img()
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.repack_resize(img, 0x0C, _payload(3, 0x10080))
        self.assertIn("tail bound", str(cm.exception))

    def test_fs4_grow_relocates_to_tail(self):
        img = Image(_fs4_synth([(0x08, 0x2000, 0x100), (0xA0, 0x2100, 0x40),
                                (0x0C, 0x4000, 0x80)]), "synth4")
        out = mlxfwutil.repack_resize(img, 0x0C, _payload(6, 0x180))
        vimg = Image(out, "out")
        self.assertEqual(mlxfwutil.verify_image(vimg), [])
        self.assertEqual(burn_order_check(vimg), [])
        e = vimg.find_entry("ITOC", 0x0C)
        self.assertEqual((e.size, e.addr), (0x180, 0x10000))  # align64k(max end)
        self.assertEqual(out[0x4000:0x4080], b"\xFF" * 0x80)


class TestMccTocOrder(unittest.TestCase):
    """FS3 порядок ITOC-строк vs FW-side дест-гейт MCC (live 2026-11-12,
    img-G4a: MCC 0x2 после полного download). MCC-компонент несёт dev-строки,
    замаскированные в 0xFF (maskDevToc, fs3_ops.cpp:3659), а строка
    type==0xFF — FS3_END-терминатор ITOC-обхода (fs3_ops.cpp:616): FW-walk
    заканчивается на первой dev-строке, rel-строка ПОСЛЕ dev-блока невидима
    (digest-диапазон FW < sizeOfImgData клиента). Релоцированная строка
    обязана оставаться внутри rel-блока — до dev-строк."""

    def test_fs3_relocated_row_before_dev_block(self):
        img = Image(_fs3_synth(FS3_LAYOUT), "synth")
        out = mlxfwutil.repack_resize(img, 0x0C, _payload(9, 0x180))
        vimg = Image(out, "out")
        self.assertEqual([x.type for x in vimg.entries("ITOC")],
                         [0x05, 0x30, 0xA0, 0x0C, 0xE0])
        self.assertLess(vimg.find_entry("ITOC", 0x0C).index,
                        vimg.find_entry("ITOC", 0xE0).index)

    def test_fw_view_range_equals_client_range(self):
        img = Image(_fs3_synth(FS3_LAYOUT), "synth")
        out = mlxfwutil.repack_resize(img, 0x0C, _payload(9, 0x180))
        fw_end, client_end = _fw_view_end(out)
        self.assertEqual(fw_end, client_end,
                         f"FW walk {fw_end:#x} != client {client_end:#x}")

    def test_fw_view_detects_rel_after_dev(self):
        violating = [(0x05, 0x10000, 0x100, 1, 0), (0xE0, 0x40000, 0x140, 0, 1),
                     (0x0C, 0x11000, 0x80, 1, 0)]
        buf = _fs3_synth(violating)
        fw_end, client_end = _fw_view_end(buf)
        self.assertEqual(fw_end, 0x10100)
        self.assertEqual(client_end, 0x11080)

    def test_verify_flags_rel_after_dev(self):
        violating = [(0x05, 0x10000, 0x100, 1, 0), (0xE0, 0x40000, 0x140, 0, 1),
                     (0x0C, 0x11000, 0x80, 1, 0)]
        errs = mlxfwutil.verify_image(Image(_fs3_synth(violating), "v"))
        self.assertTrue(any("after device-data" in e for e in errs), errs)

    def test_fs4_relocated_row_still_last(self):
        img = Image(_fs4_synth([(0x08, 0x2000, 0x100), (0xA0, 0x2100, 0x40),
                                (0x0C, 0x4000, 0x80)]), "synth4")
        out = mlxfwutil.repack_resize(img, 0x0C, _payload(6, 0x180))
        vimg = Image(out, "out")
        self.assertEqual([x.type for x in vimg.entries("ITOC")],
                         [0x08, 0xA0, 0x0C])

    def test_legacy_repack_fs3_row_before_dev(self):
        old_layout = [(0x05, 0x10000, 0x100, 1, 0), (0x0C, 0x11000, 0x80, 1, 0),
                      (0x30, 0x20000, 0x200, 1, 0), (0xA0, 0x21000, 0x40, 1, 0),
                      (0xE0, 0x40000, 0x140, 0, 1)]
        with tempfile.TemporaryDirectory() as td:
            newp, oldp = Path(td) / "new.bin", Path(td) / "old.bin"
            newp.write_bytes(_fs3_synth(FS3_LAYOUT))
            oldp.write_bytes(_fs3_synth(old_layout))
            out = mlxfwutil.repack(str(newp), str(oldp), "new")
        vimg = Image(out, "out")
        self.assertLess(vimg.find_entry("ITOC", 0x30).index,
                        vimg.find_entry("ITOC", 0xE0).index)
        fw_end, client_end = _fw_view_end(out)
        self.assertEqual(fw_end, client_end)

    def test_swap_fs3_row_before_dev(self):
        src_layout = [(0x05, 0x10000, 0x100, 1, 0), (0x0C, 0x11000, 0x180, 1, 0),
                      (0x30, 0x20000, 0x80, 1, 0), (0xA0, 0x21000, 0x40, 1, 0),
                      (0xE0, 0x40000, 0x140, 0, 1)]
        with tempfile.TemporaryDirectory() as td:
            basep, srcp = Path(td) / "base.bin", Path(td) / "src.bin"
            basep.write_bytes(_fs3_synth(FS3_LAYOUT))
            srcp.write_bytes(_fs3_synth(src_layout))
            out = mlxfwutil.swap_repack(str(basep), [(str(srcp), [0x0C])])
        vimg = Image(out, "out")
        self.assertLess(vimg.find_entry("ITOC", 0x0C).index,
                        vimg.find_entry("ITOC", 0xE0).index)
        fw_end, client_end = _fw_view_end(out)
        self.assertEqual(fw_end, client_end)


class TestResizeCLI(unittest.TestCase):
    """CLI resize: те же гейты, что inject/repack (спека §2.2/§2.4/§9.2):
    self-verify, предзаписной burn-order отказ rc 2, автознак 0xA0 после
    релокации, --no-autosign research-обход, невалидный вход rc 2."""

    def test_cli_grow_autosigns_and_passes_gates(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, payp, outp = (Path(td) / n for n in ("m.bin", "p.bin", "o.bin"))
            imgp.write_bytes(_fs3_synth(FS3_LAYOUT))
            payp.write_bytes(_payload(9, 0x180))
            rc, out, err = _run(["resize", str(imgp), "-s", "0x0C",
                                 "-p", str(payp), "-o", str(outp)])
            self.assertEqual(rc, 0, err)
            img = Image(outp.read_bytes(), "out")
            self.assertEqual(mlxfwutil.verify_image(img), [])
            self.assertEqual(burn_order_check(img), [])
            e = img.find_entry("ITOC", 0xA0)
            slot = img.section_data(e)[mlxfwutil.SIG_SLOT_OFF:mlxfwutil.SIG_SLOT_OFF + 32]
            self.assertEqual(slot, mlxfwutil.sha256_digest(img))
            self.assertEqual(mlxfwutil.sig_status(img)[0], "fresh")

    def test_cli_no_autosign_keeps_0xa0(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, payp, outp = (Path(td) / n for n in ("m.bin", "p.bin", "o.bin"))
            synth = _fs3_synth(FS3_LAYOUT)
            imgp.write_bytes(synth)
            payp.write_bytes(_payload(9, 0x180))
            rc, _, err = _run(["resize", str(imgp), "-s", "0x0C",
                               "-p", str(payp), "-o", str(outp), "--no-autosign"])
            self.assertEqual(rc, 0, err)
            img = Image(outp.read_bytes(), "out")
            self.assertEqual(mlxfwutil.sig_status(img)[0], "stale")
            self.assertIn("--no-autosign", err)
            before = Image(synth, "b")
            self.assertEqual(img.section_data(img.find_entry("ITOC", 0xA0)),
                             before.section_data(before.find_entry("ITOC", 0xA0)))

    def test_cli_refuses_burn_order_violation_rc2(self):
        # in-place shrink: выход наследует нарушение базы -> предзаписной отказ
        violation = [(0x18, 0x1FF00, 0x200, 1, 0), (0x0C, 0x10080, 0x80, 1, 0),
                     (0xE0, 0x40000, 0x140, 0, 1)]
        with tempfile.TemporaryDirectory() as td:
            imgp, payp, outp = (Path(td) / n for n in ("m.bin", "p.bin", "o.bin"))
            imgp.write_bytes(_fs3_synth(violation))
            payp.write_bytes(_payload(2, 0x40))
            rc, _, err = _run(["resize", str(imgp), "-s", "0x0C",
                               "-p", str(payp), "-o", str(outp)])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("error:", err)
            self.assertIn("sector 0x10000", err)

    def test_cli_missing_section_rc2(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, payp, outp = (Path(td) / n for n in ("m.bin", "p.bin", "o.bin"))
            imgp.write_bytes(_fs3_synth(FS3_LAYOUT))
            payp.write_bytes(_payload(1, 0x10))
            rc, _, err = _run(["resize", str(imgp), "-s", "0x18",
                               "-p", str(payp), "-o", str(outp)])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("error:", err)

    def test_cli_not_dw_aligned_rc2(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, payp, outp = (Path(td) / n for n in ("m.bin", "p.bin", "o.bin"))
            imgp.write_bytes(_fs3_synth(FS3_LAYOUT))
            payp.write_bytes(_payload(1, 0x41))
            rc, _, err = _run(["resize", str(imgp), "-s", "0x0C",
                               "-p", str(payp), "-o", str(outp)])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("DW-aligned", err)


class TestFs3RepackLegs(unittest.TestCase):
    """FS3-ветки swap_repack/repack (закрытие raise «FS4 only», спека §9.2):
    grown-swap -> tail-placement; dev=1 не свапается; legacy --new/--old на
    FS3-паре; гейты те же."""

    def test_swap_grown_section_to_tail(self):
        base_layout = FS3_LAYOUT
        src_layout = [(0x05, 0x10000, 0x100, 1, 0), (0x0C, 0x11000, 0x180, 1, 0),
                      (0x30, 0x20000, 0x80, 1, 0), (0xA0, 0x21000, 0x40, 1, 0),
                      (0xE0, 0x40000, 0x140, 0, 1)]
        with tempfile.TemporaryDirectory() as td:
            basep, srcp = Path(td) / "base.bin", Path(td) / "src.bin"
            basep.write_bytes(_fs3_synth(base_layout))
            srcp.write_bytes(_fs3_synth(src_layout))
            out = mlxfwutil.swap_repack(str(basep), [(str(srcp), [0x0C])])
            vimg = Image(out, "out")
            self.assertEqual(mlxfwutil.verify_image(vimg), [])
            self.assertEqual(burn_order_check(vimg), [])
            src = Image(srcp.read_bytes(), "src")
            e = vimg.find_entry("ITOC", 0x0C)
            self.assertEqual((e.size, e.addr), (0x180, 0x30000))
            self.assertEqual(vimg.section_data(e),
                             src.section_data(src.find_entry("ITOC", 0x0C)))
            self.assertEqual(out[0x11000:0x11080], b"\xFF" * 0x80)

    def test_swap_refuses_dev_section(self):
        with tempfile.TemporaryDirectory() as td:
            basep, srcp = Path(td) / "base.bin", Path(td) / "src.bin"
            basep.write_bytes(_fs3_synth(FS3_LAYOUT))
            srcp.write_bytes(_fs3_synth(FS3_LAYOUT))
            with self.assertRaises(ValueError) as cm:
                mlxfwutil.swap_repack(str(basep), [(str(srcp), [0xE0])])
            self.assertIn("not swappable", str(cm.exception))

    def test_legacy_repack_fs3_grown_relocates(self):
        # legacy pick(): 0x30 берётся из --old; grown -> planner tail-placement
        old_layout = [(0x05, 0x10000, 0x100, 1, 0), (0x0C, 0x11000, 0x80, 1, 0),
                      (0x30, 0x20000, 0x200, 1, 0), (0xA0, 0x21000, 0x40, 1, 0),
                      (0xE0, 0x40000, 0x140, 0, 1)]
        with tempfile.TemporaryDirectory() as td:
            newp, oldp = Path(td) / "new.bin", Path(td) / "old.bin"
            newp.write_bytes(_fs3_synth(FS3_LAYOUT))
            oldp.write_bytes(_fs3_synth(old_layout))
            out = mlxfwutil.repack(str(newp), str(oldp), "new")
            vimg = Image(out, "out")
            self.assertEqual(mlxfwutil.verify_image(vimg), [])
            self.assertEqual(burn_order_check(vimg), [])
            old = Image(oldp.read_bytes(), "old")
            e = vimg.find_entry("ITOC", 0x30)
            self.assertEqual((e.size, e.addr), (0x200, 0x30000))
            self.assertEqual(vimg.section_data(e),
                             old.section_data(old.find_entry("ITOC", 0x30)))
            self.assertEqual(out[0x20000:0x20080], b"\xFF" * 0x80)
            # dev-секция не релоцирована и не переупорядочена до записей rel
            de = vimg.find_entry("ITOC", 0xE0)
            self.assertEqual((de.addr, de.size, de.rel), (0x40000, 0x140, 0))


class TestRealImageGate(unittest.TestCase):
    """Реальный гейт (arc D task-5 Step 3): GCA-1912, resize 0x0C
    0xA00 -> 0x1E80 placeholder -> verify --deep PASS, burn-order чист,
    вне-регион byte-identity, ITOC-энумерация вне 0x0C не тронута."""

    @classmethod
    def setUpClass(cls):
        if not GCA1912.is_file():
            raise unittest.SkipTest(f"refs image not present: {GCA1912.name}")

    def test_gca1912_resize_0x0c_gate(self):
        img = mlxfwutil._image(str(GCA1912))
        placeholder = _payload(0x0C, 7808)
        out = mlxfwutil.repack_resize(img, 0x0C, placeholder)
        vimg = Image(out, "out")
        self.assertEqual(mlxfwutil.verify_image(vimg, deep=True), [])
        self.assertEqual(burn_order_check(vimg), [])
        e = vimg.find_entry("ITOC", 0x0C)
        self.assertEqual((e.size, e.addr, e.rel), (0x1E80, 0x4D0000, 1))
        self.assertEqual(vimg.section_data(e), placeholder)
        self.assertEqual(out[0x137000:0x137A00], b"\xFF" * 0xA00)  # старое место
        # MCC-модель (live-факт 07a/G4a): релоцированная строка — до dev-блока,
        # FW-walk видит весь rel-блок (диапазон деста == sizeOfImgData)
        self.assertLess(vimg.find_entry("ITOC", 0x0C).index,
                        vimg.find_entry("ITOC", 0xE6).index)
        fw_end, client_end = _fw_view_end(out)
        self.assertEqual(fw_end, client_end)
        # ITOC-энумерация до/после: вне 0x0C все секции byte-идентичны (адреса
        # и данные), rel/dev-флаги сохранены
        for be in img.entries("ITOC"):
            if be.type == 0x0C:
                continue
            ae = vimg.find_entry("ITOC", be.type)
            self.assertEqual((ae.addr, ae.size, ae.rel, ae.dev),
                             (be.addr, be.size, be.rel, be.dev), hex(be.type))
            self.assertEqual(vimg.section_data(ae), img.section_data(be),
                             hex(be.type))
        rows = img.itoc_off + 32, img.itoc_off + 32 + (len(img.itoc) + 1) * 32
        _assert_outside_identity(
            self, img.buf, out,
            [(0x137000, 0x137A00), (0x4D0000, 0x4D1E80), rows])

    def test_gca1912_resize_cli_deep_verify(self):
        with tempfile.TemporaryDirectory() as td:
            imgp, payp, outp = (Path(td) / n for n in ("m.bin", "p.bin", "o.bin"))
            imgp.write_bytes(GCA1912.read_bytes())
            payp.write_bytes(_payload(0x0C, 7808))
            rc, out, err = _run(["resize", str(imgp), "-s", "0x0C",
                                 "-p", str(payp), "-o", str(outp)])
            self.assertEqual(rc, 0, err)
            rc, out, _ = _run(["verify", str(outp), "--deep"])
            self.assertEqual(rc, 0)
            self.assertIn("RESULT: PASS", out)
            img = Image(outp.read_bytes(), "out")
            self.assertEqual(mlxfwutil.sig_status(img)[0], "fresh")  # автознак


if __name__ == "__main__":
    unittest.main()
