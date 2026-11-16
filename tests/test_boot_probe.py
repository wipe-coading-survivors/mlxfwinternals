import struct
import sys
import unittest
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import mlxfwutil  # noqa: E402
from scripts.probes.romdump import boot_probe, rc3_port, rd_reader  # noqa: E402
from tests.test_rc3_port import RI, synth_ri, synth_mutate_main_word  # noqa: E402


def w32(buf, off):
    return struct.unpack_from(">I", buf, off)[0]


class TestProbePlan(unittest.TestCase):
    def test_default_candidates_aperture_last(self):
        self.assertEqual(boot_probe.CANDIDATES[-1], 0xFFFF8000)
        self.assertNotIn(0xFFFF8000, boot_probe.CANDIDATES[:-1])
        self.assertEqual(len(boot_probe.CANDIDATES), 5)
        self.assertEqual(len(set(boot_probe.CANDIDATES)), 5)

    def test_stash_sites_cr_window(self):
        sites = boot_probe.STASH_SITES
        self.assertEqual(len(sites), len(boot_probe.CANDIDATES) + 1)
        self.assertEqual(sites[0], 0x23F0)
        for s in sites:
            self.assertGreaterEqual(s, 0x2000)
            self.assertLess(s, 0x10000)
            self.assertEqual(s % 4, 0)
        self.assertEqual(len(set(sites)), len(sites))

    def test_geometry_stub_fits_guard(self):
        stub_end = (boot_probe.BOOT_STUB_DC
                    + 4 * boot_probe.stub_words_len(
                        len(boot_probe.CANDIDATES)))
        self.assertGreaterEqual(boot_probe.BOOT_STUB_DC,
                                rc3_port.SLOT_ZONE[1])
        self.assertLessEqual(stub_end, rc3_port.GUARD_ZONE[1])

    def test_reader_part_reused_verbatim(self):
        self.assertEqual(boot_probe.reader_stub_words(),
                         rd_reader.stub_words())
        self.assertEqual(boot_probe.reader_hook_word(), 0x940AA4EC)


class TestBootStub(unittest.TestCase):
    def test_word_count(self):
        words = boot_probe.boot_stub_words(boot_probe.CANDIDATES)
        self.assertEqual(len(words), 6 * 5 + 6)

    def test_deterministic(self):
        self.assertEqual(boot_probe.boot_stub_words(boot_probe.CANDIDATES),
                         boot_probe.boot_stub_words(boot_probe.CANDIDATES))

    def test_magic_block_first(self):
        words = boot_probe.boot_stub_words(boot_probe.CANDIDATES)
        slot0 = boot_probe.STASH_SITES[0]
        want = [
            "set2 r6,zero,0x%x" % (boot_probe.MAGIC >> 16),
            "set3 r6,r6,0x%x" % (boot_probe.MAGIC & 0xFFFF),
            "set2 r5,zero,0x%x" % (slot0 >> 16),
            "set3 r5,r5,0x%x" % (slot0 & 0xFFFF),
            "st.d r6,r5,0x0",
        ]
        for i, text in enumerate(want):
            dc = boot_probe.BOOT_STUB_DC + 4 * i
            self.assertEqual(rc3_port.dis(words[i], dc), text)

    def test_candidate_blocks(self):
        cands = [0x0, 0x01002000, 0x00B97E00, 0x01001000, 0xFFFF8000]
        words = boot_probe.boot_stub_words(cands)
        for k, cand in enumerate(cands):
            slot = boot_probe.STASH_SITES[k + 1]
            base = 5 + 6 * k
            want = [
                "set2 r5,zero,0x%x" % (cand >> 16),
                "set3 r5,r5,0x%x" % (cand & 0xFFFF),
                "ld.d r6,r5,0x0",
                "set2 r5,zero,0x%x" % (slot >> 16),
                "set3 r5,r5,0x%x" % (slot & 0xFFFF),
                "st.d r6,r5,0x0",
            ]
            for i, text in enumerate(want):
                dc = boot_probe.BOOT_STUB_DC + 4 * (base + i)
                self.assertEqual(rc3_port.dis(words[base + i], dc), text)

    def test_resume_jump_last(self):
        words = boot_probe.boot_stub_words(boot_probe.CANDIDATES)
        dc = boot_probe.BOOT_STUB_DC + 4 * (len(words) - 1)
        self.assertEqual(rc3_port.dis(words[-1], dc), "jump 0x1e10c")

    def test_hook_words(self):
        boot_hook = boot_probe.boot_hook_word()
        self.assertNotEqual(boot_hook, 0x940002DE)
        self.assertEqual(rc3_port.dis(boot_hook, boot_probe.BOOT_HOOK_DC),
                         "call 0x%x" % boot_probe.BOOT_STUB_DC)
        self.assertEqual(rc3_port.dis(0x940002DE, boot_probe.BOOT_HOOK_DC),
                         "call 0x1e10c")

    def test_gate_rejects_wrong_writes(self):
        words = list(boot_probe.boot_stub_words(boot_probe.CANDIDATES))
        words[0] = rc3_port._assemble("set2 r19,zero,0x0",
                                      boot_probe.BOOT_STUB_DC)[0]
        with self.assertRaises(rc3_port.Rc3PortError):
            boot_probe._gate_boot_stub(words, boot_probe.CANDIDATES)

    def test_gate_rejects_site_count_mismatch(self):
        with self.assertRaises(rc3_port.Rc3PortError):
            boot_probe.build_plan(boot_probe.CANDIDATES[:-1])

    def test_gate_rejects_out_of_window_site(self):
        bad = list(boot_probe.STASH_SITES)
        bad[1] = 0x10000
        with self.assertRaises(rc3_port.Rc3PortError):
            boot_probe.build_plan(boot_probe.CANDIDATES,
                                  stash_sites=bad)

    def test_gate_rejects_over_cave(self):
        cands = [0x1000 + 4 * i for i in range(64)]
        sites = list(range(0x2000, 0x2000 + 4 * 65, 4))
        with self.assertRaisesRegex(rc3_port.Rc3PortError, "guard slack"):
            boot_probe.build_plan(cands, stash_sites=sites)

    def test_gate_rejects_duplicate_candidates(self):
        with self.assertRaises(rc3_port.Rc3PortError):
            boot_probe.build_plan([0x0, 0x0])

    def test_gate_rejects_wide_address(self):
        with self.assertRaises(rc3_port.Rc3PortError):
            boot_probe.build_plan([0x1_0000_0000])


class TestDecodeVerify(unittest.TestCase):
    def test_sim_matches_expected_stash_layout(self):
        cands = [0x0, 0x01002000, 0x00B97E00, 0x01001000, 0xFFFF8000]
        words = boot_probe.boot_stub_words(cands)
        sim_mem = {c: 0xA0000000 + i for i, c in enumerate(cands)}
        res = boot_probe.decode_verify(words, cands, sim_mem)
        self.assertTrue(res["ok"], res.get("reasons"))
        self.assertEqual(
            res["stash"],
            [boot_probe.MAGIC] + [sim_mem[c] for c in cands])
        self.assertEqual(res["sites"], boot_probe.STASH_SITES)

    def test_sim_zero_memory_gives_zero_reads(self):
        cands = [0x0, 0x1000]
        sites = [0x23F0, 0x2C00, 0x4C00]
        words = boot_probe.boot_stub_words(cands, sites)
        res = boot_probe.decode_verify(words, cands, {}, sites)
        self.assertTrue(res["ok"], res.get("reasons"))
        self.assertEqual(res["stash"], [boot_probe.MAGIC, 0, 0])

    def test_sim_tracks_candidate_order(self):
        cands = [0x0, 0x01002000]
        sites = [0x23F0, 0x2C00, 0x4C00]
        words = boot_probe.boot_stub_words(cands, sites)
        sim_mem = {0x0: 0x111, 0x01002000: 0x222}
        res = boot_probe.decode_verify(words, cands, sim_mem, sites)
        self.assertEqual(res["stash"],
                         [boot_probe.MAGIC, 0x111, 0x222])

    def test_sim_detects_semantic_drift(self):
        cands = [0x0, 0x1000]
        sites = [0x23F0, 0x2C00, 0x4C00]
        words = boot_probe.boot_stub_words(cands, sites)
        swapped = (words[:5] + words[11:17] + words[5:11] + words[17:])
        res = boot_probe.decode_verify(swapped, cands, {}, sites)
        self.assertFalse(res["ok"])

    def test_sim_detects_missing_write(self):
        cands = [0x0, 0x1000]
        sites = [0x23F0, 0x2C00, 0x4C00]
        words = list(boot_probe.boot_stub_words(cands, sites))
        words[5 + 6 * 1 + 5] = rc3_port._assemble(
            "set2 r5,zero,0x0",
            boot_probe.BOOT_STUB_DC + 4 * (5 + 6 * 1 + 5))[0]
        res = boot_probe.decode_verify(words, cands, {}, sites)
        self.assertFalse(res["ok"])


class TestParseReadout(unittest.TestCase):
    def _blob(self, words):
        return struct.pack(">%dI" % len(words), *words)

    def test_verdicts(self):
        cands = [0x0, 0x01002000, 0x00B97E00, 0x01001000, 0xFFFF8000]
        blob = self._blob([boot_probe.MAGIC, 0x480300BC, 0, 0xFFFFFFFF,
                           0x00000001, 0xD8C01703])
        res = boot_probe.parse_readout(blob, cands)
        self.assertTrue(res["magic_ok"])
        self.assertEqual(res["verdicts"], ["data", "00-fill", "ff-fill",
                                           "data", "data"])
        self.assertEqual(res["words"][hex(0xFFFF8000)], 0xD8C01703)

    def test_bad_magic(self):
        res = boot_probe.parse_readout(self._blob([0, 1, 2, 3, 4, 5]),
                                       [0x0, 0x1, 0x2, 0x3, 0x4])
        self.assertFalse(res["magic_ok"])
        self.assertEqual(res["verdicts"], [])

    def test_short_blob_rejected(self):
        with self.assertRaises(ValueError):
            boot_probe.parse_readout(b"\x00" * 8, [0x0, 0x1])

    def test_readout_sites(self):
        self.assertEqual(boot_probe.readout_sites(),
                         [(s, 4) for s in boot_probe.STASH_SITES])


@pytest.mark.slow
class TestBuildSynthetic(unittest.TestCase):
    def test_build_rejects_incompatible_base(self):
        bad = synth_mutate_main_word(synth_ri(), rc3_port.BOOT_WORD_DC,
                                     0xDEADBEEF)
        with self.assertRaises(rc3_port.Rc3PortError):
            boot_probe.build(bad)

    def test_build_full_pipeline(self):
        base = synth_ri()
        out = boot_probe.build(base)
        self.assertEqual(boot_probe.build(base), out)

        fimg = mlxfwutil.Image(out, "built")
        self.assertEqual(mlxfwutil.verify_image(fimg, deep=True), [])
        status, _, _ = mlxfwutil.sig_status(fimg)
        self.assertEqual(status, "fresh")

        bimg = mlxfwutil.Image(base, "base")
        fe = fimg.find_entry("ITOC", 0x03)
        be = bimg.find_entry("ITOC", 0x03)
        fcode, _ = mlxfwutil.clcrc_unwrap(fimg.section_data(fe))
        bcode, _ = mlxfwutil.clcrc_unwrap(bimg.section_data(be))
        changed = [dc for dc in range(0, len(bcode), 4)
                   if w32(fcode, dc) != w32(bcode, dc)]
        rw = rd_reader.stub_words()
        bw = boot_probe.boot_stub_words(boot_probe.CANDIDATES)
        want = sorted([boot_probe.BOOT_HOOK_DC, rd_reader.HOOK_DC]
                      + [rd_reader.STUB_DC + 4 * i for i in range(len(rw))]
                      + [boot_probe.BOOT_STUB_DC + 4 * i
                         for i in range(len(bw))])
        self.assertEqual(sorted(changed), want)
        self.assertEqual(w32(fcode, boot_probe.BOOT_HOOK_DC),
                         boot_probe.boot_hook_word())
        self.assertEqual(w32(fcode, rd_reader.HOOK_DC), 0x940AA4EC)
        self.assertEqual(
            [w32(fcode, boot_probe.BOOT_STUB_DC + 4 * i)
             for i in range(len(bw))], bw)
        self.assertEqual(
            [w32(fcode, rd_reader.STUB_DC + 4 * i) for i in range(len(rw))],
            rw)
        for k in range(len(boot_probe.CANDIDATES) + 1):
            self.assertNotIn(boot_probe.STASH_SITES[k], want)
        self.assertEqual(w32(fcode, 0x25A3EC), 0x0011001F)

        e30n = fimg.find_entry("ITOC", 0x30)
        e30b = bimg.find_entry("ITOC", 0x30)
        self.assertEqual(e30n.addr, e30b.addr)
        self.assertLessEqual(e30n.size, e30b.size)
        text = zlib.decompress(fimg.section_data(e30n)).decode("latin1")
        lines = text.splitlines()
        self.assertEqual(lines[lines.index(rc3_port.BANNER) + 1],
                         boot_probe.BUILD_ID)

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
        out = boot_probe.build(base)
        self.assertEqual(hashlib.md5(out).hexdigest(),
                          hashlib.md5(boot_probe.build(base)).hexdigest())
        bimg = mlxfwutil.Image(base, "ri")
        fimg = mlxfwutil.Image(out, "built")
        self.assertEqual(mlxfwutil.verify_image(fimg, deep=True), [])
        status, _, _ = mlxfwutil.sig_status(fimg)
        self.assertEqual(status, "fresh")
        rw = rd_reader.stub_words()
        bw = boot_probe.boot_stub_words(boot_probe.CANDIDATES)
        want = sorted([boot_probe.BOOT_HOOK_DC, rd_reader.HOOK_DC]
                      + [rd_reader.STUB_DC + 4 * i for i in range(len(rw))]
                      + [boot_probe.BOOT_STUB_DC + 4 * i
                         for i in range(len(bw))])
        dg = rc3_port.diff_gate(bimg, out, sorted({dc // 64 for dc in want}))
        self.assertEqual(dg["stray"], [])
        self.assertEqual(dg["section_diff"], ["ITOC 0x03", "ITOC 0x30",
                                              "ITOC 0xA0"])
        fe = fimg.find_entry("ITOC", 0x03)
        fcode, _ = mlxfwutil.clcrc_unwrap(fimg.section_data(fe))
        self.assertEqual(w32(fcode, boot_probe.BOOT_HOOK_DC),
                         boot_probe.boot_hook_word())
        self.assertEqual(
            [w32(fcode, boot_probe.BOOT_STUB_DC + 4 * i)
             for i in range(len(bw))], bw)
