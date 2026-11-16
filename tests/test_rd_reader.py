import struct
import sys
import unittest
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import mlxfwutil  # noqa: E402
from scripts.probes.romdump import rc3_port, rd_reader  # noqa: E402
from tests.test_rc3_port import RI, synth_ri, synth_mutate_main_word  # noqa: E402

EXIT_TRIPLE = [0x000443C8, 0x0884008E, 0xFC002025]


class TestReaderStubCanon(unittest.TestCase):
    def test_stub_word_count_and_slack(self):
        words = rd_reader.stub_words()
        self.assertEqual(len(words), 24)
        v = rc3_port.verify_base(RI.read_bytes()) if RI.exists() else None
        free = 34 if v is None else v["free_slot_words"]
        self.assertEqual(free - len(words), 10)

    def test_first_word_is_address_intake(self):
        w0 = rd_reader.stub_words()[0]
        text = rc3_port.dis(w0, rd_reader.STUB_DC)
        self.assertEqual(text, "ld.d r7,r1,0xb0")
        self.assertEqual(rd_reader._assemble(text, rd_reader.STUB_DC)[0], w0)

    def test_stub_composition(self):
        words = rd_reader.stub_words()
        loads = [w for w in words if (w >> 24) == 0x64]
        stores = [w for w in words if (w >> 24) == 0x6E]
        self.assertEqual(len(loads), 11)
        self.assertEqual(len(stores), 10)
        self.assertEqual(words[-3:], EXIT_TRIPLE)

    def test_hook_word_canon(self):
        self.assertEqual(rd_reader.hook_word(), 0x940AA4EC)

    def test_stub_deterministic(self):
        self.assertEqual(rd_reader.stub_words(), rd_reader.stub_words())

    def test_gate_stub_rejects_wrong_writes(self):
        words = list(rd_reader.stub_words())
        words[0] = rc3_port._assemble("ld.d r19,r1,0xb0",
                                      rd_reader.STUB_DC)[0]
        with self.assertRaises(rc3_port.Rc3PortError):
            rd_reader._gate_stub(words, 34)

    def test_gate_stub_rejects_short_slack(self):
        with self.assertRaises(rc3_port.Rc3PortError):
            rd_reader._gate_stub(rd_reader.stub_words(), 25)


@pytest.mark.slow
class TestBuildSynthetic(unittest.TestCase):
    def test_build_rejects_incompatible_base(self):
        bad = synth_mutate_main_word(synth_ri(), rc3_port.STUB_DC, 0xDEADBEEF)
        with self.assertRaises(rc3_port.Rc3PortError):
            rd_reader.build(bad)

    def test_build_full_pipeline(self):
        base = synth_ri()
        out = rd_reader.build(base)
        self.assertEqual(rd_reader.build(base), out)

        fimg = mlxfwutil.Image(out, "built")
        self.assertEqual(mlxfwutil.verify_image(fimg, deep=True), [])
        status, _, _ = mlxfwutil.sig_status(fimg)
        self.assertEqual(status, "fresh")

        bimg = mlxfwutil.Image(base, "base")
        fe = fimg.find_entry("ITOC", 0x03)
        be = bimg.find_entry("ITOC", 0x03)
        fcode, _ = mlxfwutil.clcrc_unwrap(fimg.section_data(fe))
        bcode, _ = mlxfwutil.clcrc_unwrap(bimg.section_data(be))
        w = lambda c, a: struct.unpack_from(">I", c, a)[0]
        changed = [dc for dc in range(0, len(bcode), 4)
                   if w(fcode, dc) != w(bcode, dc)]
        want = sorted([rd_reader.HOOK_DC]
                      + [rd_reader.STUB_DC + 4 * i for i in range(24)])
        self.assertEqual(sorted(changed), want)
        self.assertEqual(w(fcode, rd_reader.HOOK_DC), 0x940AA4EC)
        self.assertEqual([w(fcode, rd_reader.STUB_DC + 4 * i)
                          for i in range(24)], rd_reader.stub_words())
        self.assertEqual(w(fcode, 0x25A3EC), 0x0011001F)

        e30n = fimg.find_entry("ITOC", 0x30)
        e30b = bimg.find_entry("ITOC", 0x30)
        self.assertEqual(e30n.addr, e30b.addr)
        self.assertLessEqual(e30n.size, e30b.size)
        text = zlib.decompress(fimg.section_data(e30n)).decode("latin1")
        lines = text.splitlines()
        self.assertEqual(lines[lines.index(rc3_port.BANNER) + 1],
                         rd_reader.BUILD_ID)

        dg = rc3_port.diff_gate(bimg, out, sorted({dc // 64 for dc in want}))
        self.assertEqual(dg["stray"], [])
        self.assertEqual(dg["section_diff"], ["ITOC 0x03", "ITOC 0x30",
                                              "ITOC 0xA0"])


@pytest.mark.slow
class TestRealBase(unittest.TestCase):
    def setUp(self):
        if not RI.exists():
            raise unittest.SkipTest(
                "refs/fw/cx-5-6/dumps/cx5-rom-2026-11-15 not present")

    def test_build_real_deterministic_whitelist(self):
        import hashlib
        base = RI.read_bytes()
        out = rd_reader.build(base)
        self.assertEqual(hashlib.md5(out).hexdigest(),
                          hashlib.md5(rd_reader.build(base)).hexdigest())
        bimg = mlxfwutil.Image(base, "ri")
        fimg = mlxfwutil.Image(out, "built")
        self.assertEqual(mlxfwutil.verify_image(fimg, deep=True), [])
        status, _, _ = mlxfwutil.sig_status(fimg)
        self.assertEqual(status, "fresh")
        want = sorted([rd_reader.HOOK_DC]
                      + [rd_reader.STUB_DC + 4 * i for i in range(24)])
        dg = rc3_port.diff_gate(bimg, out, sorted({dc // 64 for dc in want}))
        self.assertEqual(dg["stray"], [])
        self.assertEqual(dg["section_diff"], ["ITOC 0x03", "ITOC 0x30",
                                              "ITOC 0xA0"])
        fe = fimg.find_entry("ITOC", 0x03)
        fcode, _ = mlxfwutil.clcrc_unwrap(fimg.section_data(fe))
        self.assertEqual(
            [struct.unpack_from(">I", fcode, rd_reader.STUB_DC + 4 * i)[0]
             for i in range(24)], rd_reader.stub_words())
