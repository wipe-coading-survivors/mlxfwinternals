import hashlib
import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import mlxfwutil  # noqa: E402
import pytest  # noqa: E402
from mlxfwutil import (CNTX_MAGIC, DTOC_HDR, FS4_MAGIC, ITOC_HDR,  # noqa: E402
                     Image, burn_damage_predict, burn_order_check, crc16_mlx,
                     set_bits)

from test_mlxfwutil import ROUND_TRIP_PAIRS, REPO, _mini_fs3, hw_id  # noqa: E402
from test_sign import SynthMixin as SignSynthMixin  # noqa: E402

CDA_PAIR = ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_1012-MCX516A-CDA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin",
            "refs/fw/cx-5-6/MCX516A-CDA_Ax_Bx-dc.ini")
HPE = REPO / "refs" / "fw" / "cx-5-6" / (
    "fw-ConnectX5-rel-16_35_4030-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin")
DELL = REPO / "refs" / "fw" / "cx-5-6" / (
    "fw-ConnectX5-rel-16_27_6120-09FTMY_071C1T_Ax-UEFI-14.20.27-FlexBoot-3.5.903.signed.bin")
FS3_STOCK = REPO / "refs" / "fw" / "cx-4" / (
    "fw-ConnectX4Lx-rel-14_32_1912-MCX4111A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")


class SynthMixin:
    def _toc_hdr(self, hdr16, nent):
        h = bytearray(32)
        h[0:16] = hdr16
        set_bits(h, 184, 8, nent)
        set_bits(h, 240, 16, crc16_mlx(bytes(h[:28])))
        return bytes(h)

    def _toc_ent(self, t, size, addr, crcf=0, sec_crc=0):
        r = bytearray(32)
        set_bits(r, 0, 8, t)
        set_bits(r, 8, 22, size // 4)
        set_bits(r, 161, 29, addr // 4)
        set_bits(r, 205, 3, crcf)
        set_bits(r, 208, 16, sec_crc)
        set_bits(r, 240, 16, crc16_mlx(bytes(r[:28])))
        return bytes(r)

    def _toc_ent_fs3(self, t, size, addr, rel=1, dev=0, crcf=0, sec_crc=0):
        r = bytearray(32)
        set_bits(r, 0, 8, t)
        set_bits(r, 8, 22, size // 4)
        set_bits(r, 161, 29, addr // 4)
        set_bits(r, 160, 1, rel)
        set_bits(r, 206, 1, dev)
        set_bits(r, 207, 1, crcf)
        set_bits(r, 208, 16, sec_crc)
        set_bits(r, 240, 16, crc16_mlx(bytes(r[:28])))
        return bytes(r)

    @staticmethod
    def _pattern(sec_i, size):
        # без байтов 0xFF: повреждение (стертость) не путается с данными
        return bytes((sec_i * 37 + j * 13 + 7) % 251 for j in range(size))

    def _fs4_burn_synth(self, sections, base=0):
        # sections: [(type, slot_rel_addr, size)] в порядке ITOC; фон 0xFF —
        # стёртая флеш (planner требует 0xFF в хвостовом gap)
        end = max((addr + size for _, addr, size in sections), default=0)
        buf = bytearray(b"\xff" * (base + max(end, 0x4000) + 0x1000))
        buf[base:base + 16] = FS4_MAGIC
        ents = [self._toc_ent(t, size, addr) for t, addr, size in sections]
        ents.append(self._toc_ent(0xFF, 0, 0))
        buf[base + 0x1000:base + 0x1020] = self._toc_hdr(ITOC_HDR, len(ents) - 1)
        for i, ent in enumerate(ents):
            buf[base + 0x1020 + i * 32:base + 0x1040 + i * 32] = ent
        buf[base + 0x1100:base + 0x1120] = self._toc_hdr(DTOC_HDR, 0)
        buf[base + 0x1120:base + 0x1140] = self._toc_ent(0xFF, 0, 0)
        for i, (_, addr, size) in enumerate(sections):
            buf[base + addr:base + addr + size] = self._pattern(i, size)
        return bytes(buf)

    def _fs3_burn_synth(self, sections):
        # sections: [(type, addr, size, rel)] в порядке ITOC; фон 0xFF
        end = max((addr + size for _, addr, size, _ in sections), default=0)
        buf = bytearray(b"\xff" * (max(end, 0x4000) + 0x1000))
        buf[0:16] = CNTX_MAGIC
        buf[0x24] = 3
        ents = [self._toc_ent_fs3(t, size, addr, rel=rel)
                for t, addr, size, rel in sections]
        ents.append(self._toc_ent(0xFF, 0, 0))
        buf[0x1000:0x1020] = self._toc_hdr(ITOC_HDR, len(ents) - 1)
        for i, ent in enumerate(ents):
            buf[0x1020 + i * 32:0x1040 + i * 32] = ent
        for i, (_, addr, size, _rel) in enumerate(sections):
            buf[addr:addr + size] = self._pattern(i, size)
        return bytes(buf)

    def _fs4_img(self, sections, base=0):
        return Image(self._fs4_burn_synth(sections, base), "synth", base=base)


class TestBurnOrder(SynthMixin, unittest.TestCase):
    MID_LIST = [(0x18, 0x1FF00, 0x200), (0x30, 0x10080, 0x80)]
    MONOTONIC = [(0x08, 0x10000, 0x80), (0x09, 0x10080, 0x80), (0x18, 0x20000, 0x80)]

    def test_monotonic_ok(self):
        img = self._fs4_img(self.MONOTONIC)
        self.assertEqual(burn_order_check(img), [])

    def test_mid_list_relocation_detected(self):
        img = self._fs4_img(self.MID_LIST)
        v = burn_order_check(img)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].entry.type, 0x30)
        self.assertEqual(v[0].sector, 0x10000)
        self.assertEqual([e.type for e in v[0].victims], [0x18])
        self.assertIn("0x10000", v[0].explanation)

    def test_tail_unaligned_detected(self):
        img = self._fs4_img([(0x30, 0x21000, 0x80), (0xEB, 0x10000, 0x11000)])
        v = burn_order_check(img)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].entry.type, 0xEB)
        self.assertEqual(v[0].sector, 0x20000)
        self.assertEqual([e.type for e in v[0].victims], [0x30])

    def test_tail_aligned_ok(self):
        img = self._fs4_img([(0x30, 0x30000, 0x80), (0xEB, 0x10000, 0x11000)])
        self.assertEqual(burn_order_check(img), [])

    def test_jump_back_fresh_sector_ok(self):
        img = self._fs4_img([(0x18, 0x30000, 0x80), (0x30, 0x10000, 0x80)])
        self.assertEqual(burn_order_check(img), [])

    def test_revisit_via_several_entries(self):
        img = self._fs4_img([(0x08, 0x10000, 0x80), (0x09, 0x20000, 0x80),
                             (0x10, 0x30000, 0x80), (0x30, 0x10080, 0x80)])
        v = burn_order_check(img)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].entry.type, 0x30)
        self.assertEqual([e.type for e in v[0].victims], [0x08])

    def test_base_offset_slot_b(self):
        clean = self._fs4_img(self.MONOTONIC, base=0x800000)
        self.assertEqual(burn_order_check(clean), [])
        v = burn_order_check(self._fs4_img(self.MID_LIST, base=0x800000))
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].sector, 0x810000)
        self.assertEqual([e.type for e in v[0].victims], [0x18])

    def test_sector_size_param(self):
        layout_64k_only = [(0x08, 0x11000, 0x100), (0x09, 0x21000, 0x100),
                           (0x30, 0x12000, 0x80)]
        img = self._fs4_img(layout_64k_only)
        self.assertEqual(len(burn_order_check(img)), 1)
        self.assertEqual(burn_order_check(img, sector_size=0x40000), [])
        layout_256k_only = [(0x08, 0x10000, 0x100), (0x09, 0x50000, 0x100),
                            (0x30, 0x30000, 0x80)]
        img = self._fs4_img(layout_256k_only)
        self.assertEqual(burn_order_check(img), [])
        v = burn_order_check(img, sector_size=0x40000)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].sector, 0x0)
        self.assertEqual([e.type for e in v[0].victims], [0x08])

    def test_fs3_entries_model(self):
        good = Image(self._fs3_burn_synth(
            [(0x05, 0x10000, 0x80, 1), (0x30, 0x10080, 0x80, 1),
             (0x18, 0x20000, 0x80, 1)]), "fs3")
        self.assertEqual(burn_order_check(good), [])
        bad = Image(self._fs3_burn_synth(
            [(0x05, 0x1FF00, 0x200, 1), (0xE2, 0x30000, 0x40, 0),
             (0x30, 0x10080, 0x80, 1)]), "fs3")
        v = burn_order_check(bad)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].entry.type, 0x30)
        self.assertEqual([e.type for e in v[0].victims], [0x05])

    def test_damage_predict_crc(self):
        img = self._fs4_img(self.MID_LIST)
        preds = burn_damage_predict(img)
        self.assertEqual(len(preds), 1)
        p = preds[0]
        self.assertEqual(p.entry.type, 0x18)
        expected = b"\xff" * 0x100 + self._pattern(0, 0x200)[0x100:]
        self.assertEqual(p.data, expected)
        self.assertEqual(p.crc16, crc16_mlx(expected))
        self.assertEqual(p.erased_ranges, [(0, 0x100)])
        self.assertEqual(burn_damage_predict(self._fs4_img(self.MONOTONIC)), [])


class TestPlannerTail(SynthMixin, unittest.TestCase):
    """planner-direct синтетика: tail-placement, FS3 rel-only, HALF-гвард,
    зачистка _reflow (спека repack-burn-safety §2.3)."""

    def _fs3_rel_img(self):
        # rel: 0x30 @0x10000 (end 0x10100), 0x32 @0x10100 (end 0x10200);
        # non-rel dev 0xE0 @0x30000 — не участвует в rel-max, но граница хвоста
        sections = [(0x30, 0x10000, 0x100, 1), (0x32, 0x10100, 0x100, 1),
                    (0xE0, 0x30000, 0x140, 0)]
        return Image(self._fs3_burn_synth(sections), "fs3rel")

    def test_fs3_rel_only_max_and_bound(self):
        img = self._fs3_rel_img()
        e = img.find_entry("ITOC", 0x30)
        data = bytes((j * 13 + 7) % 251 for j in range(0x8000))
        plan = mlxfwutil.plan_relocations(img, [(e, data, None)])
        # align64k(rel-only max end 0x10200) = 0x20000; dev 0x30000+0x140
        # в max не входит (иначе хвост был бы 0x40000)
        self.assertEqual(plan.moves[0].new_abs, 0x20000)
        self.assertEqual([e.type for e in plan.order], [0x32, 0x30, 0xE0])
        # не влезает до non-rel границы 0x30000 -> отказ
        big = bytes((j * 13 + 7) % 251 for j in range(0x22000))
        with self.assertRaises(ValueError) as cm:
            mlxfwutil.plan_relocations(img, [(e, big, None)])
        self.assertIn("0x30000", str(cm.exception))

    def test_half_guard(self):
        ok = self._fs4_img([(0x18, 0x600000, 0x100), (0x30, 0x10000, 0x80)],
                           base=0x800000)
        plan = mlxfwutil.plan_relocations(
            ok, [(ok.find_entry("ITOC", 0x30), b"\xAA" * 0x80, None)])
        # slot B (base!=0) — валидная раскладка: хвост в rel-координатах
        self.assertEqual(plan.moves[0].new_abs, 0x800000 + 0x610000)
        for base in (0, 0x800000):
            near = self._fs4_img([(0x18, 0x7F0000, 0x100), (0x30, 0x10000, 0x80)],
                                 base=base)
            with self.assertRaises(ValueError, msg=hex(base)) as cm:
                mlxfwutil.plan_relocations(
                    near, [(near.find_entry("ITOC", 0x30), b"\xAA" * 0x80, None)])
            self.assertIn("half", str(cm.exception))
            self.assertIn("0x800000", str(cm.exception))

    def test_half_guard_legacy_repack(self):
        # латентный дефект repack() (спека §2.6): grown 0x30 у 8MiB-границы —
        # отказ через legacy-ветку repack(), planner подключён к ней
        sections_new = [(0x30, 0x10000, 0x100), (0x18, 0x7F0000, 0x100)]
        sections_old = [(0x30, 0x10000, 0x2000), (0x18, 0x7F0000, 0x100)]
        with tempfile.TemporaryDirectory() as td:
            p_new = Path(td) / "new.bin"
            p_old = Path(td) / "old.bin"
            p_new.write_bytes(self._fs4_burn_synth(sections_new))
            p_old.write_bytes(self._fs4_burn_synth(sections_old))
            with self.assertRaises(ValueError) as cm:
                mlxfwutil.repack(str(p_new), str(p_old), "new")
            self.assertIn("half", str(cm.exception))

    def test_swap_dirty_gap_refuses(self):
        # нестерый хвостовой gap — интегрити-отказ (НЕ повод для _reflow):
        # до-цикловое поведение "base gap not erased" восстановлено
        sections_base = [(0x30, 0x10000, 0x100), (0x18, 0x20000, 0x100)]
        sections_src = [(0x30, 0x10000, 0x1000), (0x18, 0x20000, 0x100)]
        with tempfile.TemporaryDirectory() as td:
            p_base, p_src = Path(td) / "base.bin", Path(td) / "src.bin"
            buf = bytearray(self._fs4_burn_synth(sections_base))
            buf += b"\xff" * (0x40000 - len(buf))  # буфер покрывает хвост 0x30000
            buf[0x30000:0x30010] = b"\xCD" * 0x10  # грязный хвостовой gap
            p_base.write_bytes(bytes(buf))
            p_src.write_bytes(self._fs4_burn_synth(sections_src))
            with self.assertRaises(ValueError) as cm:
                mlxfwutil.swap_repack(str(p_base), [(str(p_src), [0x30])])
            self.assertIn("not erased", str(cm.exception))
            self.assertNotIsInstance(cm.exception, mlxfwutil.RelocNoRoom)

    def test_swap_tail_shortage_reflows(self):
        # нехватка хвоста (не влезает до HALF/bound) — единственный триггер
        # _reflow fallback (спека §2.3)
        sections_base = [(0x30, 0x10000, 0x100), (0x18, 0x700000, 0x100)]
        sections_src = [(0x30, 0x10000, 0x100000), (0x18, 0x700000, 0x100)]
        with tempfile.TemporaryDirectory() as td:
            p_base, p_src = Path(td) / "base.bin", Path(td) / "src.bin"
            p_base.write_bytes(self._fs4_burn_synth(sections_base))
            p_src.write_bytes(self._fs4_burn_synth(sections_src))
            out = mlxfwutil.swap_repack(str(p_base), [(str(p_src), [0x30])])
            vimg = Image(out, "r")
            src = Image(p_src.read_bytes(), "s")
            e30 = vimg.find_entry("ITOC", 0x30)
            self.assertEqual(e30.size, 0x100000)
            self.assertEqual(vimg.section_data(e30),
                             src.section_data(src.find_entry("ITOC", 0x30)))
            for e in vimg.entries("ITOC"):
                self.assertLess(e.addr + e.size, 0x800000, hex(e.type))
            self.assertEqual(out[0x700000:0x700100], b"\xFF" * 0x100)  # старое место 0x18
            self.assertEqual(burn_order_check(vimg), [])

    def test_reflow_cleanup_vacated(self):
        img = self._fs4_img([(0x30, 0x20000, 0x1000), (0x18, 0x40000, 0x2000),
                             (0x09, 0x60000, 0x800)])
        mut = bytearray(img.buf)
        mut[0x50000:0x50010] = b"\xCD" * 0x10  # вне секций: зачистка не трогает
        base = Image(bytes(mut), "b")
        out = mlxfwutil._reflow(base, {}, {})
        vimg = Image(out, "r")
        self.assertEqual([e.addr for e in vimg.entries("ITOC")],
                         [0x20000, 0x21000, 0x23000])
        for e_new, e_old in zip(vimg.entries("ITOC"), base.entries("ITOC")):
            self.assertEqual(vimg.section_data(e_new), base.section_data(e_old))
        self.assertEqual(out[0x40000:0x42000], b"\xFF" * 0x2000)  # старое место 0x18
        self.assertEqual(out[0x60000:0x60800], b"\xFF" * 0x800)   # старое место 0x09
        self.assertEqual(out[0x50000:0x50010], b"\xCD" * 0x10)    # вне секций
        self.assertTrue(all(vimg.entry_crc_ok(e) for e in vimg.itoc))
        self.assertEqual(burn_order_check(vimg), [])


class TestPlannerRefs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for p in (REPO / CDA_PAIR[0], REPO / CDA_PAIR[1], HPE, DELL):
            if not p.is_file():
                raise unittest.SkipTest(f"refs image not present: {p.name}")

    def _grown_ini(self, binp, inip):
        img = mlxfwutil._image(str(binp))
        ini = inip.read_bytes().decode("latin1")
        return img, ini + os.urandom(0xC0).decode("latin1")  # сток 0x928 -> ~0x9e8

    def test_inject_grow_relocates_to_aligned_tail(self):
        img, ini = self._grown_ini(REPO / CDA_PAIR[0], REPO / CDA_PAIR[1])
        out = mlxfwutil.inject_ini(img, ini, force=True)
        vimg = Image(out, "out")
        e = vimg.find_entry("ITOC", 0x30)
        tail = (max(img.sec_abs(x) + x.size for x in img.entries("ITOC"))
                + 0xFFFF) & ~0xFFFF
        self.assertEqual(e.addr, tail)                 # align64k(max_end)
        self.assertEqual(e.addr % 0x10000, 0)
        self.assertGreater(e.size, 0x928)              # grown (сток 0x928 -> ~0x9e8)
        self.assertEqual(vimg.entries("ITOC")[-1].type, 0x30)  # последняя в ITOC

    def test_old_place_erased(self):
        img, ini = self._grown_ini(REPO / CDA_PAIR[0], REPO / CDA_PAIR[1])
        out = mlxfwutil.inject_ini(img, ini, force=True)
        old = img.find_entry("ITOC", 0x30)
        a, n = img.sec_abs(old), old.size
        self.assertEqual(bytes(out[a:a + n]), b"\xFF" * n)

    def test_relocated_image_selfverifies(self):
        img, ini = self._grown_ini(REPO / CDA_PAIR[0], REPO / CDA_PAIR[1])
        out = mlxfwutil.inject_ini(img, ini, force=True)
        self.assertEqual(mlxfwutil.verify_image(Image(out, "out")), [])

    def test_relocated_passes_burn_order(self):
        img, ini = self._grown_ini(REPO / CDA_PAIR[0], REPO / CDA_PAIR[1])
        out = mlxfwutil.inject_ini(img, ini, force=True)
        self.assertEqual(burn_order_check(Image(out, "out")), [])

    def test_multi_relocation_sequential_tails(self):
        out = mlxfwutil.repack(str(HPE), str(DELL), "old")
        img = Image(out, "s1old")
        base = Image(HPE.read_bytes(), "hpe")
        self.assertEqual(mlxfwutil.verify_image(img), [])
        moved = [e for e in img.entries("ITOC") if e.type in (0x09, 0x12, 0xE9)]
        self.assertEqual([e.type for e in moved], [0x12, 0x09, 0xE9])  # порядок ITOC
        self.assertEqual([e.type for e in img.entries("ITOC")[-3:]],
                         [0x12, 0x09, 0xE9])  # хвост массива записей
        cur = max(base.sec_abs(e) + e.size for e in base.entries("ITOC"))
        for e in moved:
            cur = (cur + 0xFFFF) & ~0xFFFF
            self.assertEqual(e.addr, cur)
            cur += e.size
        ends = sorted((e.addr, e.addr + e.size) for e in moved)
        for (_, e1), (s2, _) in zip(ends, ends[1:]):
            self.assertLessEqual(e1, s2, "tails overlap")
        for t in (0x09, 0x12, 0xE9):  # старые места зачищены
            be = base.find_entry("ITOC", t)
            self.assertEqual(out[be.addr:be.addr + be.size], b"\xFF" * be.size, hex(t))
        self.assertEqual(burn_order_check(img), [])


class TestRefsStocksCorpus(unittest.TestCase):
    """Корпус вендорских стоков refs/fw (Task 5 Step 1): все FS3+FS4 стоки
    (refs/fw/**/fw-*.bin, все поколения CX-3..CX-7) -> burn_order_check == []
    — вендорский инвариант «порядок записей == монотонный рост адресов».
    Нарушение в стоке — STOP-finding (журнал/док, чекер НЕ править): тест
    падает с полным пояснением чекера. Не-fw-* файлы refs/fw (лаб-дампы
    *_ri/_sp, кастомные bazzite-*, DPU-контейнер, CX-2 FS2) в корпус
    вендорской монотонности не входят."""

    @classmethod
    def setUpClass(cls):
        if not (REPO / "refs" / "fw").is_dir():
            raise unittest.SkipTest("refs/fw not present")

    @pytest.mark.slow
    def test_vendor_stocks_burn_order_clean(self):
        stocks = sorted((REPO / "refs" / "fw").rglob("fw-*.bin"))
        self.assertGreater(len(stocks), 20, "refs/fw stock corpus unexpectedly small")
        checked = 0
        for p in stocks:
            with self.subTest(stock=p.name):
                try:
                    img = mlxfwutil._image(str(p))
                except ValueError as e:
                    # вне корпуса (ограничения формата, НЕ нарушения):
                    # CX-3 стоки — FS2 (version byte @0x24 = 0); CX-7 .signed
                    # контейнеры — нет открытого ITOC (первый банк зашифрован,
                    # открыт только DTOC) — burn_order_check неприменим
                    self.assertRegex(
                        str(e), "FS2 is not supported|ITOC not found",
                        f"unexpected parse failure: {p}")
                    continue
                self.assertIn(img.fmt, ("fs3", "fs4"), p.name)
                self.assertEqual(
                    burn_order_check(img), [],
                    f"vendor stock burn-order violation: {p}")
                checked += 1
        self.assertGreater(checked, 40, "FS3+FS4 corpus unexpectedly small")


class TestPlannerMisc(unittest.TestCase):
    def test_non_relocation_path_byte_identical(self):
        # ini помещается in-place -> вывод побайтово == до-цикловому поведению
        # (md5 снят на базе Task 1 до правок grow-ветки)
        buf, ini = _mini_fs3()
        out = mlxfwutil.inject_ini(Image(buf, "mini"), ini.decode("latin1"))
        self.assertEqual(hashlib.md5(out).hexdigest(),
                         "c6181c5d146cb7c2c1df93a08c9ad629")
        e = Image(out, "o").find_entry("ITOC", 0x30)
        self.assertEqual((e.addr, e.index), (0x2000, 0))  # на месте, без переупорядочения

    @pytest.mark.slow
    def test_roundtrip_refs_ini_and_burn_order(self):
        for binp, inip in ROUND_TRIP_PAIRS:
            with self.subTest(bin=Path(binp).name):
                binp, inip = REPO / binp, REPO / inip
                if not (binp.is_file() and inip.is_file()):
                    self.skipTest(f"refs pair missing: {binp.name}")
                img = mlxfwutil._image(str(binp))
                ini = inip.read_bytes()
                out = mlxfwutil.inject_ini(img, ini.decode("latin1"), force=True)
                vimg = Image(out, "out")
                self.assertEqual(mlxfwutil.verify_image(vimg), [], binp.name)
                self.assertEqual(zlib.decompress(
                    mlxfwutil.extract_section(vimg, 0x30)), ini, binp.name)
                self.assertEqual(burn_order_check(vimg), [], binp.name)
                e = vimg.find_entry("ITOC", 0x30)
                self.assertEqual(e.addr % 0x10000, 0, binp.name)  # релокация неизбежна
                # FS3: релоцированная строка — до dev-блока (MCC TOC-walk);
                # для FS4-пар из корпуса — по-прежнему последняя
                if vimg.fmt == "fs3":
                    first_dev = next(x.index for x in vimg.entries("ITOC")
                                     if x.type != 0xFF and not x.rel)
                    self.assertLess(e.index, first_dev, binp.name)
                else:
                    self.assertEqual(vimg.entries("ITOC")[-1].type, 0x30,
                                     binp.name)


class TestGates(SynthMixin, unittest.TestCase):
    """CLI-гейты инварианта burn-order (спека repack-burn-safety §2.2):
    verify — FAIL rc 1 с пояснением; inject/repack (обе ветки) — отказ rc 2
    ДО записи выходного файла. Синтетика-база с ГОТОВЫМ нарушением:
    relocation-free выход наследует его -> гейт (план, Global Constraints)."""

    # 0x18 заканчивается в секторе 0x10000, следующая по ITOC запись 0x30
    # входит в него повторно -> нарушение (механика v4, спека §1.1)
    FS3_VIOLATION = [(0x18, 0x1FF00, 0x200, 1), (0x30, 0x10080, 0x80, 1),
                     (0xE0, 0x30000, 0x140, 1)]
    FS3_CLEAN = [(0x08, 0x10000, 0x80, 1), (0x09, 0x10080, 0x80, 1),
                 (0x18, 0x20000, 0x80, 1), (0xE0, 0x30000, 0x140, 1)]
    # делит 64K-сектор с ранней записью, но целиком внутри 256K-сектора
    FS3_64K_ONLY = [(0x08, 0x11000, 0x100, 1), (0x09, 0x21000, 0x100, 1),
                    (0x30, 0x12000, 0x80, 1), (0xE0, 0x30000, 0x140, 1)]
    FS4_VIOLATION = [(0x18, 0x1FF00, 0x200), (0x30, 0x10080, 0x80),
                     (0x09, 0x30000, 0x100)]

    def _fs3_cli_synth(self, sections):
        # как _fs3_burn_synth, но sec CRC валидны -> verify_image чист:
        # вердикт CLI-гейтов определяет только burn-order укладка
        end = max((addr + size for _, addr, size, _ in sections), default=0)
        buf = bytearray(b"\xff" * (max(end, 0x4000) + 0x1000))
        buf[0:16] = CNTX_MAGIC
        buf[0x24] = 3
        ents = [self._toc_ent_fs3(t, size, addr, rel=rel,
                                  sec_crc=crc16_mlx(self._pattern(i, size)))
                for i, (t, addr, size, rel) in enumerate(sections)]
        ents.append(self._toc_ent_fs3(0xFF, 0, 0))
        buf[0x1000:0x1020] = self._toc_hdr(ITOC_HDR, len(ents) - 1)
        for i, ent in enumerate(ents):
            buf[0x1020 + i * 32:0x1040 + i * 32] = ent
        for i, (_, addr, size, _rel) in enumerate(sections):
            buf[addr:addr + size] = self._pattern(i, size)
        return bytes(buf)

    def test_verify_fails_on_violation_rc1(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "viol.bin"
            p.write_bytes(self._fs3_cli_synth(self.FS3_VIOLATION))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = mlxfwutil.main(["verify", str(p)])
            self.assertEqual(rc, 1)
            self.assertIn("RESULT: FAIL", out.getvalue())
            self.assertIn("sector 0x10000", out.getvalue())  # пояснение чекера

    def test_verify_ok_rc0(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "clean.bin"
            p.write_bytes(self._fs3_cli_synth(self.FS3_CLEAN))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = mlxfwutil.main(["verify", str(p)])
            self.assertEqual(rc, 0)
            self.assertIn("RESULT: PASS", out.getvalue())

    def test_verify_sector_size_flag(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "s64k.bin"
            p.write_bytes(self._fs3_cli_synth(self.FS3_64K_ONLY))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = mlxfwutil.main(["verify", str(p)])
            self.assertEqual(rc, 1)
            self.assertIn("RESULT: FAIL", out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = mlxfwutil.main(["verify", str(p), "--sector-size", "0x40000"])
            self.assertEqual(rc, 0)
            self.assertIn("RESULT: PASS", out.getvalue())

    def test_inject_refuses_violation_rc2(self):
        # in-place ini (без релокации): выход наследует нарушение базы
        buf = self._fs3_cli_synth(self.FS3_VIOLATION)
        with tempfile.TemporaryDirectory() as td:
            imgp, inip, outp = (Path(td) / n for n in ("m.bin", "i.ini", "o.bin"))
            imgp.write_bytes(buf)
            inip.write_text("[ADAPTER]\nPSID = GATE\n", encoding="latin1")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                rc = mlxfwutil.main(["inject", str(imgp), str(inip), "-o", str(outp)])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("error:", err.getvalue())
            self.assertIn("sector 0x10000", err.getvalue())

    def test_repack_refuses_violation_rc2(self):
        # legacy-ветка: --new == --old -> ни одной релокации, нарушение
        # базы наследуется выходом
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "same.bin"
            outp = Path(td) / "out.bin"
            src.write_bytes(self._fs4_burn_synth(self.FS4_VIOLATION))
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                rc = mlxfwutil.main(["repack", "--new", str(src), "--old", str(src),
                                  "--prio", "new", "-o", str(outp)])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("error:", err.getvalue())
            self.assertIn("sector 0x10000", err.getvalue())

    def test_swap_repack_refuses_violation_rc2(self):
        # ветка --base/--swap: заменяемая секция не растёт -> выход
        # наследует нарушение базы
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "base.bin"
            src = Path(td) / "src.bin"
            outp = Path(td) / "out.bin"
            base.write_bytes(self._fs4_burn_synth(self.FS4_VIOLATION))
            src.write_bytes(self._fs4_burn_synth(self.FS4_VIOLATION))
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                rc = mlxfwutil.main(["repack", "--base", str(base),
                                  "--swap", f"{src}:0x09", "-o", str(outp)])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("error:", err.getvalue())
            self.assertIn("sector 0x10000", err.getvalue())


class TestAutosignUnsafe(SignSynthMixin, unittest.TestCase):
    """Автознак 0xA0 после релокации — CLI-слой (спека §2.4): матрица 4 путей
    (inject grow / repack legacy / repack --base/--swap gap-fill / →_reflow),
    отказ rsa/v2/missing/empty rc 2 без файла, --no-autosign, и legacy-режим
    --unsafe-relocation (§2.5: до-цикловый align4-tail аллокатор, запись на
    месте, обход предзаписного гейта)."""

    # порядок ITOC монотонен по адресам: 0x30 < 0xA0 < 0x08
    BASE = [(0x30, 0x2000, 0x100), (0xA0, 0x2100, 0x40), (0x08, 0x4000, 0x100)]
    # grown 0x30 из src (swap/legacy): 0x220 > 0x100
    GROWN = [(0x30, 0x2000, 0x220), (0xA0, 0x2100, 0x40), (0x08, 0x4000, 0x100)]
    # хвост не влезает до HALF (0x18 @0x700000 -> tail 0x710000 + 0x100000)
    REFLOW_BASE = [(0x30, 0x2000, 0x100), (0xA0, 0x2100, 0x40),
                   (0x18, 0x700000, 0x100)]
    REFLOW_SRC = [(0x30, 0x2000, 0x100000), (0xA0, 0x2100, 0x40),
                  (0x18, 0x700000, 0x100)]
    DEVINFO_ADDR = 0x30000  # DTOC-секция высоко: planner bound не режет хвост
    HASHES_PTR = 0x20000    # валидная V1-таблица (ниже devinfo, вне tail 0x10000)

    @staticmethod
    def _hashes_table() -> bytes:
        # минимальная валидная V1-таблица (64xSHA-512) с одной записью 0x30:
        # sig_status -> v2, при этом _hashes_update/self-verify работают
        size = 12 + 16 + 64 * (8 + 64) + 8
        t = bytearray(b"\x00" * size)
        t[12:16] = struct.pack(">I", 1)   # version 1 -> max_num 64
        t[16] = 1                          # num: одна запись
        t[18:20] = struct.pack(">H", 64)   # hash_size
        t[28:32] = struct.pack(">I", (0x30 << 16) | (16 + 64 * 8))  # 0x30, off 528
        t[10:12] = struct.pack(">H", crc16_mlx(bytes(t[0:8])))
        t[-4:] = struct.pack(">I", crc16_mlx(bytes(t[0:size - 4])))
        return bytes(t)

    @staticmethod
    def _pattern(sec_i, size):
        # без байтов 0xFF: повреждение (стертость) не путается с данными
        return bytes((sec_i * 37 + j * 13 + 7) % 251 for j in range(size))

    def _rel_synth(self, sections, sig_slot=b"\x11" * 32,
                   keypair=b"\x00" * 16, with_sig=True, hashes_ptr=None,
                   bufsize=0x40000):
        # sections: [(type, addr, size)] в порядке ITOC; 0xA0 -> SIG-данные
        # (crcf=1, слот @+0x20), прочие — паттерн с валидным sec_crc;
        # DTOC: один валидный mDevInfo (crcf=2)
        buf = bytearray(b"\xff" * bufsize)
        buf[0:16] = FS4_MAGIC
        if hashes_ptr is not None:
            struct.pack_into(">I", buf, 0x18 + 15 * 8, hashes_ptr)
            struct.pack_into(">H", buf, 0x18 + 15 * 8 + 4,
                             crc16_mlx(struct.pack(">I", hashes_ptr)))
            buf[hashes_ptr:hashes_ptr + len(self._hashes_table())] = \
                self._hashes_table()
        rows, data = [], []
        for i, (t, addr, size) in enumerate(sections):
            if t == 0xA0 and with_sig:
                rows.append(self._toc_ent(0xA0, size, addr, crcf=1))
                data.append((addr, self._sig_data(keypair=keypair,
                                                  slot=sig_slot)[:size]))
            elif t != 0xA0:
                d = self._pattern(i, size)
                rows.append(self._toc_ent(t, size, addr, sec_crc=crc16_mlx(d)))
                data.append((addr, d))
        rows.append(self._toc_ent(0xFF, 0, 0))
        buf[0x1000:0x1020] = self._toc_hdr(ITOC_HDR, len(rows) - 1)
        for i, row in enumerate(rows):
            buf[0x1020 + i * 32:0x1040 + i * 32] = row
        buf[0x1100:0x1120] = self._toc_hdr(DTOC_HDR, 1)
        buf[0x1120:0x1140] = self._toc_ent(0xE1, 0x40, self.DEVINFO_ADDR, crcf=2)
        buf[0x1140:0x1160] = self._toc_ent(0xFF, 0, 0)
        for addr, d in data:
            buf[addr:addr + len(d)] = d
        buf[self.DEVINFO_ADDR:self.DEVINFO_ADDR + 0x40] = self._devinfo()
        return bytes(buf)

    def _grown_ini(self, tag=b"AUTOSIGN"):
        # несжимаемый хвост -> lvl9-размер > 0x100 -> grow-ветка
        return (b"[ADAPTER]\nPSID = " + tag + b"\n" + os.urandom(0x180))

    def _write(self, td, name, blob):
        p = Path(td) / name
        p.write_bytes(blob)
        return p

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mlxfwutil.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _drive_matrix_path(self, path, td):
        # -> (rc, out_path); на каждом пути происходит релокация 0x30
        outp = Path(td) / f"out-{path}.bin"
        if path == "inject-grow":
            imgp = self._write(td, "inject.bin", self._rel_synth(self.BASE))
            inip = self._write(td, "big.ini", self._grown_ini())
            rc, _, _ = self._run(["inject", str(imgp), str(inip), "-o", str(outp),
                                  "--repack-force"])
        elif path == "repack-legacy":
            newp = self._write(td, "new.bin", self._rel_synth(self.BASE))
            oldp = self._write(td, "old.bin", self._rel_synth(self.GROWN))
            rc, _, _ = self._run(["repack", "--new", str(newp), "--old", str(oldp),
                                  "--prio", "new", "-o", str(outp)])
        elif path == "swap-gap-fill":
            basep = self._write(td, "base.bin", self._rel_synth(self.BASE))
            srcp = self._write(td, "src.bin", self._rel_synth(self.GROWN))
            rc, _, _ = self._run(["repack", "--base", str(basep),
                                  "--swap", f"{srcp}:0x30", "-o", str(outp)])
        elif path == "swap-reflow":
            basep = self._write(td, "rbase.bin",
                                self._rel_synth(self.REFLOW_BASE, bufsize=0x800000))
            srcp = self._write(td, "rsrc.bin",
                               self._rel_synth(self.REFLOW_SRC, bufsize=0x110000))
            rc, _, _ = self._run(["repack", "--base", str(basep),
                                  "--swap", f"{srcp}:0x30", "-o", str(outp)])
        else:
            raise AssertionError(path)
        return rc, outp

    def test_autosign_matrix_four_paths(self):
        for path in ("inject-grow", "repack-legacy", "swap-gap-fill", "swap-reflow"):
            with self.subTest(path=path):
                with tempfile.TemporaryDirectory() as td:
                    rc, outp = self._drive_matrix_path(path, td)
                    self.assertEqual(rc, 0)
                    img = Image(outp.read_bytes(), "out")
                    self.assertEqual(burn_order_check(img), [])
                    e = img.find_entry("ITOC", 0xA0)
                    slot = img.section_data(e)[mlxfwutil.SIG_SLOT_OFF:
                                               mlxfwutil.SIG_SLOT_OFF + 32]
                    self.assertEqual(slot, mlxfwutil.sha256_digest(img))
                    self.assertEqual(mlxfwutil.sig_status(img)[0], "fresh")

    def test_autosign_rsa_refuses_rc2(self):
        base = self._rel_synth(self.BASE, keypair=b"\x01" + b"\x00" * 15)
        with tempfile.TemporaryDirectory() as td:
            imgp = self._write(td, "rsa.bin", base)
            inip = self._write(td, "big.ini", self._grown_ini())
            outp = Path(td) / "out.bin"
            rc, _, err = self._run(["inject", str(imgp), str(inip), "-o", str(outp),
                                    "--repack-force"])
            self.assertEqual(rc, 2)
            self.assertFalse(outp.exists())
            self.assertIn("rsa", err)
            self.assertIn("--no-autosign", err)

    def test_autosign_v2_missing_empty_refuse(self):
        cases = {
            "v2": self._rel_synth(self.BASE, hashes_ptr=self.HASHES_PTR),
            "missing": self._rel_synth(self.BASE, with_sig=False),
            "empty": self._rel_synth(self.BASE, sig_slot=b"\x00" * 32),
        }
        for name, base in cases.items():
            with self.subTest(status=name):
                with tempfile.TemporaryDirectory() as td:
                    imgp = self._write(td, f"{name}.bin", base)
                    inip = self._write(td, "big.ini", self._grown_ini())
                    outp = Path(td) / "out.bin"
                    rc, _, err = self._run(["inject", str(imgp), str(inip),
                                            "-o", str(outp), "--repack-force"])
                    self.assertEqual(rc, 2)
                    self.assertFalse(outp.exists())
                    self.assertIn(name, err)
                    self.assertIn("--no-autosign", err)

    def test_no_autosign_flag(self):
        base = self._rel_synth(self.BASE)
        before = Image(base, "base").section_data(
            Image(base, "base").find_entry("ITOC", 0xA0))
        with tempfile.TemporaryDirectory() as td:
            imgp = self._write(td, "base.bin", base)
            inip = self._write(td, "big.ini", self._grown_ini(b"NOAS"))
            outp = Path(td) / "out.bin"
            rc, _, err = self._run(["inject", str(imgp), str(inip), "-o", str(outp),
                                    "--repack-force", "--no-autosign"])
            self.assertEqual(rc, 0)
            self.assertTrue(outp.is_file())
            img = Image(outp.read_bytes(), "out")
            self.assertEqual(img.section_data(img.find_entry("ITOC", 0xA0)),
                             before)  # 0xA0 нетронут
            self.assertEqual(mlxfwutil.sig_status(img)[0], "stale")
            self.assertIn("--no-autosign", err)

    def test_unsafe_relocation_legacy_behavior(self):
        # на стоке: точный до-цикловый align4-tail (mlxfwutil.py:767-769 у
        # 9d2f418), запись ITOC на месте, старое место 0xFF (:775-776),
        # чекер != [] (mid-list релокация)
        cda = REPO / CDA_PAIR[0]
        if not cda.is_file():
            self.skipTest(f"refs image not present: {cda.name}")
        img = mlxfwutil._image(str(cda))
        ini = (zlib.decompress(mlxfwutil.extract_section(img, 0x30))
               + os.urandom(0xC0))  # сток 0x928 -> ~0x9e8
        with tempfile.TemporaryDirectory() as td:
            inip = self._write(td, "big.ini", ini)
            outp = Path(td) / "out.bin"
            rc, _, err = self._run(["inject", str(cda), str(inip), "-o", str(outp),
                                    "--repack-force", "--unsafe-relocation",
                                    "--no-autosign"])
            self.assertEqual(rc, 0)
            out = Image(outp.read_bytes(), "out")
            e = out.find_entry("ITOC", 0x30)
            legacy = (max(img.sec_abs(x) + x.size for x in img.entries("ITOC"))
                      + 3) & ~3
            self.assertEqual(out.sec_abs(e), legacy)      # align4(max_end)
            self.assertNotEqual(legacy % 0x10000, 0)      # не 64K-tail планировщика
            self.assertEqual(e.index, img.find_entry("ITOC", 0x30).index)  # на месте
            self.assertEqual([x.type for x in out.entries("ITOC")],
                             [x.type for x in img.entries("ITOC")])
            old = img.find_entry("ITOC", 0x30)
            a, n = img.sec_abs(old), old.size
            self.assertEqual(out.buf[a:a + n], b"\xFF" * n)  # старое место стёрто
            self.assertNotEqual(burn_order_check(out), [])
            self.assertIn("--unsafe-relocation", err)


class TestFs3StockAutosignCLI(unittest.TestCase):
    """Финал-ревью repack-burn-safety: пин mainline-ветки автознака FS3
    crcf=0 (все 22 FS3-стока — crcf=0) на реальном стоке через CLI:
    grown-INI inject -> релокация -> автознак пересчитывает слот 0xA0 И
    sec/entry CRC записи (mlxfwutil.py:719-725). Пин существующего корректного
    поведения — GREEN сразу, RED-фазы нет."""

    @classmethod
    def setUpClass(cls):
        if not FS3_STOCK.is_file():
            raise unittest.SkipTest(f"refs image not present: {FS3_STOCK.name}")

    @staticmethod
    def _run(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mlxfwutil.main(argv)
        return rc, out.getvalue(), err.getvalue()

    @pytest.mark.slow
    def test_fs3_crcf0_stock_autosign_cli(self):
        img = mlxfwutil._image(str(FS3_STOCK))
        # тестируем именно FS3 crcf=0-ветку автознака
        self.assertEqual((img.fmt, img.find_entry("ITOC", 0xA0).crcf), ("fs3", 0))
        ini = zlib.decompress(mlxfwutil.extract_section(img, 0x30)) + os.urandom(0xC0)
        with tempfile.TemporaryDirectory() as td:
            inip = Path(td) / "big.ini"
            inip.write_bytes(ini)
            outp = Path(td) / "out.bin"
            rc, _, _ = self._run(["inject", str(FS3_STOCK), str(inip),
                                  "-o", str(outp), "--repack-force"])
            self.assertEqual(rc, 0)
            self.assertTrue(outp.is_file())
            out = Image(outp.read_bytes(), "out")
            self.assertNotEqual(out.sec_abs(out.find_entry("ITOC", 0x30)),
                                img.sec_abs(img.find_entry("ITOC", 0x30)))  # была релокация
            self.assertEqual(mlxfwutil.verify_image(out), [])
            self.assertEqual(burn_order_check(out), [])
            e = out.find_entry("ITOC", 0xA0)
            slot = out.section_data(e)[mlxfwutil.SIG_SLOT_OFF:mlxfwutil.SIG_SLOT_OFF + 32]
            self.assertEqual(slot, mlxfwutil.sha256_digest(out))  # sig fresh
            self.assertEqual(mlxfwutil.sig_status(out)[0], "fresh")
            # crcf=0: sec_crc записи 0xA0 обновлён под новый слот
            self.assertEqual(e.sec_crc, crc16_mlx(out.section_data(e)))


GOLDEN_P3 = REPO / "build" / "4030-cda-patched3.bin"
GOLDEN_P4 = REPO / "build" / "4030-cda-patched4.bin"
GOLDEN_SIM = REPO / "build" / "recon-1031" / "sim-v4.bin"


class TestGoldenV4(unittest.TestCase):
    """Офлайн-golden на исторической базе v4 (спека §3.2, план Global
    Constraints): p3 + INI(0x9e8) из p4 + guides-финализация. Все тесты
    skip при отсутствии gitignored-артефактов build/."""

    @classmethod
    def setUpClass(cls):
        missing = [p.name for p in (GOLDEN_P3, GOLDEN_P4, GOLDEN_SIM)
                   if not p.is_file()]
        if missing:
            raise unittest.SkipTest(f"golden artifacts not present: {missing}")
        cls.GOLDEN_GUID = hw_id("CARD_CX5_EDR100", "guid")
        cls.GOLDEN_MAC = hw_id("CARD_CX5_EDR100", "mac")

    def _recipe(self, outp: Path, unsafe=True, no_autosign=True) -> int:
        # inject (legacy/безопасный) + guides; rc 0 на каждом шаге
        ini_text = zlib.decompress(
            mlxfwutil.extract_section(mlxfwutil._image(str(GOLDEN_P4)), 0x30))
        with tempfile.TemporaryDirectory() as td:
            inip = Path(td) / "ini.txt"
            inip.write_bytes(ini_text)
            step1 = Path(td) / "step1.bin"
            argv = ["inject", str(GOLDEN_P3), str(inip), "-o", str(step1),
                    "--repack-force"]
            if unsafe:
                argv.append("--unsafe-relocation")
            if no_autosign:
                argv.append("--no-autosign")
            rc, _, _ = self._run(argv)
            if rc:
                return rc
            rc, _, _ = self._run(["guides", str(step1), "--guid", hex(self.GOLDEN_GUID),
                                  "--mac", hex(self.GOLDEN_MAC), "-o", str(outp)])
            return rc

    @staticmethod
    def _run(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mlxfwutil.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_golden_v4_predictions(self):
        with tempfile.TemporaryDirectory() as td:
            outp = Path(td) / "golden-unsafe.bin"
            self.assertEqual(self._recipe(outp), 0)
            img = Image(outp.read_bytes(), "golden")
            e30 = img.find_entry("ITOC", 0x30)
            self.assertEqual(img.sec_abs(e30), 0x557660)  # legacy align4-tail
            self.assertEqual(e30.size, 0x9E8)
            preds = burn_damage_predict(img)
            by = {p.entry.type: p for p in preds}
            self.assertEqual(set(by), {0x18, 0x30})  # ROM_CODE + DBG_FW_INI
            self.assertEqual(by[0x18].crc16, 0x408A)  # in-FNP verify §13.3
            self.assertEqual(by[0x30].crc16, 0xBD51)
            self.assertEqual(by[0x30].data, b"\xFF" * 0x9E8)  # положена и стёрта
            self.assertEqual(by[0x30].erased_ranges, [(0, 0x9E8)])

    def test_golden_v4_legacy_byteexact(self):
        with tempfile.TemporaryDirectory() as td:
            outp = Path(td) / "golden-byte.bin"
            self.assertEqual(self._recipe(outp, unsafe=True, no_autosign=True), 0)
            self.assertEqual(outp.read_bytes(), GOLDEN_P4.read_bytes())

    def test_golden_v4_damage_matches_sim(self):
        sim = GOLDEN_SIM.read_bytes()
        with tempfile.TemporaryDirectory() as td:
            outp = Path(td) / "golden-sim.bin"
            self.assertEqual(self._recipe(outp), 0)
            img = Image(outp.read_bytes(), "golden")
            preds = burn_damage_predict(img)
            self.assertEqual(len(preds), 2)
            for p in preds:
                a = img.sec_abs(p.entry)
                self.assertEqual(sim[a:a + p.entry.size], p.data,
                                 hex(p.entry.type))
                runs, i = [], 0  # erased_ranges == максимальные FF-прогоны
                while i < len(p.data):
                    if p.data[i] == 0xFF:
                        j = i
                        while j < len(p.data) and p.data[j] == 0xFF:
                            j += 1
                        runs.append((i, j - i))
                        i = j
                    else:
                        i += 1
                self.assertEqual(p.erased_ranges, runs, hex(p.entry.type))

    def test_golden_v4_safe_paths_clean(self):
        # tail-placement (CLI, без unsafe; автознак активен) И _reflow
        # (src=p4: 0x30 grown) -> burn_order_check == [] на обоих
        with tempfile.TemporaryDirectory() as td:
            outp = Path(td) / "golden-safe.bin"
            self.assertEqual(self._recipe(outp, unsafe=False, no_autosign=False), 0)
            safe = Image(outp.read_bytes(), "safe")
            self.assertEqual(burn_order_check(safe), [])
            self.assertEqual(mlxfwutil.sig_status(safe)[0], "fresh")  # автознак
            base = mlxfwutil._image(str(GOLDEN_P3))
            p4 = mlxfwutil._image(str(GOLDEN_P4))
            reflowed = mlxfwutil._reflow(base, {str(GOLDEN_P4): p4},
                                      {0x30: str(GOLDEN_P4)})
            rimg = Image(reflowed, "reflow")
            self.assertEqual(burn_order_check(rimg), [])
            e30 = rimg.find_entry("ITOC", 0x30)
            self.assertEqual(e30.size, 0x9E8)
            self.assertEqual(rimg.section_data(e30), p4.section_data(
                p4.find_entry("ITOC", 0x30)))


if __name__ == "__main__":
    unittest.main()
