import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import ch347i2c as m  # noqa: E402


class W1Frames(unittest.TestCase):
    """T5 W1: байтовая точность кадров write-механики (спека §3.3, канон
    §2.2/§2.4/§7.3 п.2). Ожидаемые кадры — независимые константы
    (AA-обвязка + токены, addrW=0x48<<1=0x90, BE32)."""

    P16 = bytes(range(0x10, 0x20))

    def test_v1_frame26(self):
        fr, ack = m.cr_write_block_frames(0x48, 0xF0410, self.P16)
        self.assertEqual(
            fr, bytes.fromhex("aa749590" + "000f0410" + self.P16.hex() + "7500"))
        self.assertEqual((len(fr), ack), (26, 21))

    def test_v1_frame42_upper_bound(self):
        p32 = bytes((0xA0 + i) & 0xFF for i in range(32))
        fr, ack = m.cr_write_block_frames(0x48, 0xF0410, p32)
        self.assertEqual((len(fr), ack, fr[2]), (42, 37, 0x80 | 37))

    def test_v3_multi_out_tokens(self):
        fr, ack = m.cr_write_block_frames(0x48, 0xF0410, self.P16,
                                          split_out=True)
        self.assertEqual(
            fr,
            bytes.fromhex("aa748590" + "000f0410" + "90" + self.P16.hex()
                          + "7500"))
        self.assertEqual((len(fr), ack), (27, 21))

    def test_v4_out_continuation(self):
        head, frames, ack = m.cr_write_block_cont_frames(0x48, 0xF0410,
                                                         self.P16, chunk=8)
        self.assertEqual(head, bytes.fromhex("aa748590" + "000f0410"))
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0],
                         bytes.fromhex("aa88" + self.P16[0:8].hex()))
        self.assertEqual(
            frames[1],
            bytes.fromhex("aa88" + self.P16[8:16].hex() + "7500"))
        self.assertEqual(ack, 21)

    def test_v5_mwrite4_regression(self):
        fr, ack = m.cr_write_frames(0x48, 0xF0014, 0x12345678)
        self.assertEqual(fr,
                         bytes.fromhex("aa748990" + "000f0014" + "12345678"
                                       + "7500"))
        self.assertEqual(ack, 9)


class DataSane(unittest.TestCase):
    """T3 review #1: data_sane обязан отвергать vendor=0 паттерн 00 00 02 09."""

    def test_rejects_vendor0_jedec(self):
        self.assertFalse(m.data_sane(bytes.fromhex("00000209")))

    def test_rejects_vendor0_prefix(self):
        self.assertFalse(m.data_sane(bytes.fromhex("00000209") + b"\x00" * 12))

    def test_rejects_all_ff_all_00(self):
        self.assertFalse(m.data_sane(b"\xff" * 16))
        self.assertFalse(m.data_sane(b"\x00" * 16))

    def test_accepts_valid(self):
        self.assertTrue(m.data_sane(bytes.fromhex("01000209")))
        self.assertTrue(m.data_sane(bytes(range(0x10, 0x20))))


class FakeUsb:
    """Модель карты для офлайн-прогонов GW-циклов (T6): регистры CR
    (writes сохраняются), DATA-окно 16Б, probe всегда ACK (или NAK при
    probe_ok=False); CR-адрес вне decoded → OSError (NAK). bulk()
    исполняет AA-стрим как последовательность i2c-транзакций (поддержка
    packed-кадров T6-opt: несколько STA…STO групп в одном кадре)."""

    def __init__(self, regs=None, data16=None, decoded=None,
                 probe_ok=True):
        self.regs = {0xF0400: 0x00000000, 0xF0420: 0x00000001,
                     0xF0404: 0x00000000}
        if regs:
            self.regs.update(regs)
        self.data16 = data16 if data16 is not None else bytes(range(16))
        self.decoded = decoded
        self.probe_ok = probe_ok
        self.fail_data = 0
        self.frames = []

    def _decoded_ok(self, cr):
        return self.decoded is None or cr in self.decoded

    def bulk(self, ep_out, data, rlen):
        fr = bytes(data)
        self.frames.append(fr)
        if (rlen == 1 and len(fr) == 6 and fr[1] == 0x74
                and fr[2] == 0x80 and fr[4] == 0x75):
            return b"\x01" if self.probe_ok else b"\x00"
        resp = b""
        pos = 1
        addr_phase = b""
        acks = 0
        in_len = 0
        while pos < len(fr) and fr[pos] != 0x00:
            t = fr[pos]
            if t == 0x74:
                pass
            elif t == 0x75:
                cr = int.from_bytes(addr_phase[1:5], "big")
                if not self._decoded_ok(cr):
                    raise OSError(f"NAK @0x{cr:08x}")
                if in_len:
                    if cr == 0xF0410 and self.fail_data:
                        self.fail_data -= 1
                        raise OSError(f"NAK @0x{cr:08x} (sim data fail)")
                    resp += b"\x01" * acks
                    if cr == 0xF0410 and in_len == 16:
                        resp += self.data16
                    else:
                        v = self.regs.get(cr, 0).to_bytes(4, "big")
                        resp += (v + bytes(in_len - 4)
                                 if in_len >= 4 else v[:in_len])
                else:
                    if len(addr_phase) >= 9:
                        self.regs[cr] = int.from_bytes(addr_phase[5:9],
                                                       "big")
                    resp += b"\x01" * acks
                addr_phase, acks, in_len = b"", 0, 0
            elif 0x80 <= t <= 0xBF:
                n = t & 0x3F
                addr_phase += fr[pos + 1:pos + 1 + n]
                acks += n
                pos += n
            elif t >= 0xC0:
                n = t & 0x3F
                in_len += n if n else 1
            pos += 1
        if len(resp) != rlen:
            raise OSError(f"FakeUsb: resp {len(resp)} != rlen {rlen} "
                          f"(fr={fr.hex()})")
        return resp


class FakeUsbMixin:
    """Конструктор мока для тест-классов (self.make → FakeUsb)."""

    @staticmethod
    def make(regs=None, data16=None, decoded=None, probe_ok=True):
        return FakeUsb(regs=regs, data16=data16, decoded=decoded,
                       probe_ok=probe_ok)


class GwDumpCycle(FakeUsbMixin, unittest.TestCase):
    """T6: §8.2-цикл одного 16Б-блока — ровно 9 транзакций, байт-точно
    (адрес блока в ADDR-кадре, константы CMD, restore в unlock)."""

    def test_block_cycle_frames_and_state(self):
        u = self.make(data16=bytes(range(0x20, 0x30)))
        pace = lambda: None  # noqa: E731
        data = m.gw_read_block_cycle(u, 0x48, 0x000ABC10, pace)
        self.assertEqual(data, bytes(range(0x20, 0x30)))
        exp = [
            m.cr_read_frames(0x48, 0xF0400, 4)[0],
            m.cr_read_frames(0x48, 0xF0420, 4)[0],
            m.cr_write_frames(0x48, 0xF0420, 0x00000000)[0],
            m.cr_write_frames(0x48, 0xF0404, 0x000ABC10)[0],
            m.cr_write_frames(0x48, 0xF0400, 0xC003041D)[0],
            m.cr_read_frames(0x48, 0xF0410, 16)[0],
            m.cr_read_frames(0x48, 0xF0420, 4)[0],
            m.cr_write_frames(0x48, 0xF0420, 0x00000001)[0],
            m.cr_write_frames(0x48, 0xF0400, 0x00000000)[0],
        ]
        self.assertEqual(u.frames, exp)
        self.assertEqual((u.regs[0xF0420], u.regs[0xF0400]), (1, 0))

    def test_force_lock_releases_stale_semaphore(self):
        """FNP force-lock (T15-прецедент): при бит31=1 — release stale
        (W CMD=0) + повторное чтение → RMW; без исключения; счётчик
        GW_FORCED_LOCKS растёт."""
        u = self.make(regs={0xF0400: 0xB90B4C6E})
        before = m.GW_FORCED_LOCKS
        pace = lambda: None  # noqa: E731
        m.gw_lock(u, 0x48, pace, poll_ms=1, timeout_s=0.2, force=True)
        self.assertEqual(m.GW_FORCED_LOCKS, before + 1)
        self.assertEqual(
            u.frames[:3],
            [m.cr_read_frames(0x48, 0xF0400, 4)[0],
             m.cr_write_frames(0x48, 0xF0400, 0x00000000)[0],
             m.cr_read_frames(0x48, 0xF0400, 4)[0]])
        self.assertEqual(u.regs[0xF0400], 0x00000000)
        self.assertEqual(u.regs[0xF0420], 0x00000000)

    def test_force_lock_in_dump_cycle(self):
        """Дамп-цикл с force: при занятом семафоре цикл проходит
        (release-stale + RMW + чтение), данные возвращаются."""
        u = self.make(regs={0xF0400: 0x80000000},
                      data16=bytes(range(0x40, 0x50)))
        pace = lambda: None  # noqa: E731
        data = m.gw_read_block_cycle(u, 0x48, 0x0, pace, force=True)
        self.assertEqual(data, bytes(range(0x40, 0x50)))
        self.assertEqual(u.regs[0xF0420], 1)


class GwDumpRun(FakeUsbMixin, unittest.TestCase):
    """T6: gwdump — файл/sidecar/resume/md5 (нулевые паузы, FakeUsb)."""

    def test_partial_then_resume_completes(self):
        import hashlib
        import json
        import os
        import tempfile
        u = self.make(data16=bytes(range(16)))
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "dump.bin")
            s1 = m.gwdump_run(u, 0x48, out, flash_size=256, speed=1,
                              intra_ms=0, inter_ms=0, max_blocks=10,
                              marker_every=4)
            self.assertFalse(s1["done"])
            self.assertEqual((s1["blocks"], s1["next_block"]), (10, 10))
            self.assertEqual(os.path.getsize(out), 160)
            self.assertEqual(
                json.load(open(out + ".progress"))["next_block"], 10)
            s2 = m.gwdump_run(u, 0x48, out, flash_size=256, speed=1,
                              intra_ms=0, inter_ms=0, resume=True,
                              marker_every=16)
            self.assertTrue(s2["done"])
            self.assertEqual((s2["blocks"], s2["next_block"]), (6, 16))
            self.assertEqual(os.path.getsize(out), 256)
            self.assertEqual(
                s2["md5"], hashlib.md5(bytes(range(16)) * 16).hexdigest())


class GwDumpOpt(FakeUsbMixin, unittest.TestCase):
    """T6-opt: packed-кадр (3 транзакции §8.2 одним AA-стримом) и
    batch-lock режимы gwdump."""

    def test_packed_frame_bytes(self):
        fr, ack = m.gw_read_block_packed_frames(0x48, 0x00012340)
        self.assertEqual(
            fr,
            bytes.fromhex("aa"
                          + "74" + "89" + "90" + "000f0404" + "00012340"
                          + "75"
                          + "74" + "89" + "90" + "000f0400" + "c003041d"
                          + "75"
                          + "74" + "85" + "90" + "000f0410"
                          + "74" + "81" + "91" + "cf" + "c0"
                          + "75" + "00"))
        self.assertEqual((len(fr), ack), (39, 24))

    def test_packed_roundtrip(self):
        u = self.make(data16=bytes(range(0x60, 0x70)))
        data = m.gw_read_block_packed(u, 0x48, 0x0000F010)
        self.assertEqual(data, bytes(range(0x60, 0x70)))
        self.assertEqual(u.regs[0xF0404], 0x0000F010)
        self.assertEqual(u.regs[0xF0400], 0xC003041D)

    def test_gwdump_opt1_and_opt2_complete(self):
        import os
        import tempfile
        for opt in (1, 2):
            u = self.make(data16=bytes(range(16)))
            with tempfile.TemporaryDirectory() as td:
                out = os.path.join(td, f"dump{opt}.bin")
                s = m.gwdump_run(u, 0x48, out, flash_size=256, speed=1,
                                 intra_ms=0, inter_ms=0, max_blocks=None,
                                 marker_every=8, force=False, opt=opt,
                                 batch=4)
                self.assertTrue(s["done"], f"opt={opt}")
                self.assertEqual(os.path.getsize(out), 256)
                self.assertEqual((u.regs[0xF0420], u.regs[0xF0400]),
                                 (1, 0), f"opt={opt}: финальный unlock")


class GwDumpRetryCap(FakeUsbMixin, unittest.TestCase):
    """T6-fix#1: ретраи блока ограничены — 3 подряд неудачных попытки
    одного блока → STOP (block-retry-cap); единичная неудача переживается
    ретраем после wedge_recover (мок — всегда успех: живой USB)."""

    def setUp(self):
        self._orig = m.wedge_recover
        m.wedge_recover = lambda u, speed, tries=3: True

    def tearDown(self):
        m.wedge_recover = self._orig

    def test_cap_stops_after_3_consecutive_failures(self):
        import os
        import tempfile
        u = self.make()
        u.fail_data = 10 ** 9
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "d.bin")
            s = m.gwdump_run(u, 0x48, out, flash_size=256, speed=1,
                             intra_ms=0, inter_ms=0, marker_every=64)
            self.assertFalse(s["done"])
            self.assertTrue(s["stop_reason"].startswith("block-retry-cap"))
            self.assertEqual((s["blocks"], s["errors"], s["resets"]),
                             (0, 3, 2))

    def test_single_failure_recovered_by_retry(self):
        import hashlib
        import os
        import tempfile
        u = self.make(data16=bytes(range(16)))
        u.fail_data = 1
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "d.bin")
            s = m.gwdump_run(u, 0x48, out, flash_size=256, speed=1,
                             intra_ms=0, inter_ms=0, marker_every=16)
            self.assertTrue(s["done"])
            self.assertEqual((s["errors"], s["resets"]), (1, 1))
            self.assertEqual(
                s["md5"], hashlib.md5(bytes(range(16)) * 16).hexdigest())


class HromScan(FakeUsbMixin, unittest.TestCase):
    """T6: bounded-скан — NAK-кандидаты зафиксированы, контроли читаются,
    hang-контракт (probe NAK) рвёт скан."""

    KNOWN = {0xF0014, 0xF0400, 0xF0420, 0xF0410, 0xF0404}

    def test_full_scan(self):
        u = self.make(regs={0xF0014: 0x000A020D}, decoded=self.KNOWN)
        pace = lambda: None  # noqa: E731
        results, completed = m.hrom_scan(u, 0x48, pace, repeat_gap_s=0)
        self.assertTrue(completed)
        self.assertEqual(len(results), len(m.HROM_CANDIDATES))
        by_tag = {r["tag"]: r for r in results}
        self.assertIsNone(by_tag["ctrl-devid"]["err"])
        self.assertIn("000a020d", by_tag["ctrl-devid"]["r1"])
        for tag in ("vec0", "vec0+1000", "zoneA-head", "zoneB1-head",
                    "zoneB2-head", "aperture", "ctrl-dead"):
            self.assertIsNotNone(by_tag[tag]["err"])

    def test_hang_contract_stops_scan(self):
        u = self.make(regs={0xF0014: 0x000A020D}, decoded=self.KNOWN,
                      probe_ok=False)
        pace = lambda: None  # noqa: E731
        results, completed = m.hrom_scan(u, 0x48, pace, repeat_gap_s=0)
        self.assertFalse(completed)
        self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()
