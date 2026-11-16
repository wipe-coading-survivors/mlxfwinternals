import json
import random
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.probes.romdump import zone_dump  # noqa: E402

STRIDE = zone_dump.READ_STRIDE


class FakeChannel:
    def __init__(self, fail_at=None):
        self.rng = random.Random(0xBEEF)
        self.fail_at = fail_at
        self.calls = []

    def read_chunk(self, addr, nbytes):
        self.calls.append((addr, nbytes))
        if self.fail_at is not None and len(self.calls) > self.fail_at:
            raise zone_dump.ChannelError("simulated wedge at 0x%x" % addr)
        nwords = nbytes // 4 + (1 if nbytes % 4 else 0)
        data = self.rng.randbytes(nwords * 4)[:nbytes]
        self.last = data
        return data


class MemChannel(FakeChannel):
    def __init__(self, image, base):
        super().__init__()
        self.image = image
        self.base = base

    def read_chunk(self, addr, nbytes):
        self.calls.append((addr, nbytes))
        if self.fail_at is not None and len(self.calls) > self.fail_at:
            raise zone_dump.ChannelError("simulated wedge at 0x%x" % addr)
        return self.image[addr - self.base:addr - self.base + nbytes]


class TestPlanChunks(unittest.TestCase):
    def test_chunk_plan_exact(self):
        zone = zone_dump.ZoneSpec("t", 0xB97E00, 0x100)
        chunks = zone_dump.plan_chunks(zone, chunk_cmds=2)
        self.assertEqual([(c.addr, c.nbytes) for c in chunks],
                         [(0xB97E00, 0x50), (0xB97E50, 0x50),
                          (0xB97EA0, 0x50), (0xB97EF0, 0x10)])

    def test_chunk_plan_partial_tail(self):
        zone = zone_dump.ZoneSpec("t", 0x1000, 0xF0)
        chunks = zone_dump.plan_chunks(zone, chunk_cmds=2)
        self.assertEqual([(c.addr, c.nbytes) for c in chunks],
                         [(0x1000, 0x50), (0x1050, 0x50), (0x10A0, 0x50)])

    def test_zone_extent(self):
        zone = zone_dump.ZoneSpec("A", 0xB97E00, 0x110200)
        self.assertEqual(zone.end, 0xCA8000)
        self.assertEqual(zone_dump.ZONES["B"].end, 0x1080000)


class TestRunZoneResume(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="zonedump-test-"))
        self.image = random.Random(7).randbytes(0x1000)
        self.zone = zone_dump.ZoneSpec("t", 0x800000, len(self.image))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_run_writes_expected_bytes(self):
        ch = MemChannel(self.image, 0x800000)
        res = zone_dump.run_zone(self.zone, ch, self.tmp, chunk_cmds=2)
        self.assertTrue(res["complete"])
        partial = self.tmp / "t.partial"
        self.assertEqual(partial.read_bytes(), self.image)
        self.assertEqual((self.tmp / "t.state.json").exists(), True)

    def test_state_tracks_progress(self):
        ch = MemChannel(self.image, 0x800000)
        zone_dump.run_zone(self.zone, ch, self.tmp, chunk_cmds=2)
        st = json.loads((self.tmp / "t.state.json").read_text())
        self.assertEqual(st["zone"], "t")
        self.assertEqual(st["next_index"], 52)

    def test_resume_after_failure_keeps_prefix(self):
        ch = MemChannel(self.image, 0x800000)
        ch.fail_at = 5
        with self.assertRaises(zone_dump.ChannelError):
            zone_dump.run_zone(self.zone, ch, self.tmp, chunk_cmds=2)
        st = json.loads((self.tmp / "t.state.json").read_text())
        self.assertEqual(st["next_index"], 5)
        self.assertEqual(len(ch.calls), 6)
        partial = (self.tmp / "t.partial").read_bytes()
        self.assertEqual(partial, self.image[:5 * 0x50])

        ch2 = MemChannel(self.image, 0x800000)
        res = zone_dump.run_zone(self.zone, ch2, self.tmp, chunk_cmds=2)
        self.assertTrue(res["complete"])
        self.assertEqual(len(ch2.calls), 52 - 5)
        self.assertEqual((self.tmp / "t.partial").read_bytes(), self.image)

    def test_finalize_writes_artifact_sidecar_and_manifest_line(self):
        import hashlib
        ch = MemChannel(self.image, 0x800000)
        zone_dump.run_zone(self.zone, ch, self.tmp, chunk_cmds=2)
        out = self.tmp / "t.bin"
        line = zone_dump.finalize(self.zone, self.tmp, out)
        self.assertEqual(out.read_bytes(), self.image)
        md5 = hashlib.md5(self.image).hexdigest()
        self.assertEqual(line,
                         "%s  %s" % (md5, "refs/fw/cx-5-6/dumps/"
                                    "cx5-rom-2026-11-15/t.bin"))
        self.assertEqual((self.tmp / "t.bin.md5").read_text(),
                         "%s  %s\n" % (md5, out))

    def test_finalize_refuses_incomplete(self):
        ch = MemChannel(self.image, 0x800000)
        ch.fail_at = 3
        with self.assertRaises(zone_dump.ChannelError):
            zone_dump.run_zone(self.zone, ch, self.tmp, chunk_cmds=2)
        with self.assertRaises(zone_dump.ZoneDumpError):
            zone_dump.finalize(self.zone, self.tmp, self.tmp / "t.bin")

    def test_chunk_commit_is_atomic_order(self):
        writes = []

        class OrderChannel(MemChannel):
            def read_chunk(self, addr, nbytes):
                data = super().read_chunk(addr, nbytes)
                writes.append(("data", addr))
                return data

        real_append = zone_dump._append_partial

        def spy(partial, data):
            real_append(partial, data)
            writes.append(("commit", partial.stat().st_size))

        zone_dump._append_partial = spy
        try:
            zone_dump.run_zone(self.zone, OrderChannel(self.image, 0x800000),
                               self.tmp, chunk_cmds=2)
        finally:
            zone_dump._append_partial = real_append
        commits = [w for w in writes if w[0] == "commit"]
        self.assertEqual([c[1] for c in commits],
                         [80 * (i + 1) if i < 51 else len(self.image)
                          for i in range(52)])


class TestStallGuard(unittest.TestCase):
    def test_stall_aperture_refused(self):
        zone = zone_dump.ZoneSpec("bad", 0xFFFF7000, 0x10000)
        with self.assertRaises(zone_dump.ZoneDumpError):
            zone_dump.check_stall(zone)

    def test_safe_zone_passes(self):
        zone_dump.check_stall(zone_dump.ZoneSpec("ok", 0xB97E00, 4))
        zone_dump.check_stall(zone_dump.ZoneSpec("ok", 0x1078000, 0x4000))

    def test_chunk_addrs_guarded(self):
        self.assertRaises(zone_dump.ZoneDumpError,
                          zone_dump.check_stall,
                          zone_dump.ZoneSpec("bad", 0xFFFF8000, 0x28))


class TestZones(unittest.TestCase):
    def test_canonical_zone_defs(self):
        self.assertEqual(zone_dump.ZONES["A"].start, 0xB97E00)
        self.assertEqual(zone_dump.ZONES["A"].end, 0xCA8000)
        self.assertEqual(zone_dump.ZONES["B"].start, 0x1001000)
        self.assertEqual(zone_dump.ZONES["B"].length, 0x7F000)
        self.assertEqual(zone_dump.ZONES["B"].end, 0x1080000)
