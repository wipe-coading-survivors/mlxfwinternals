import json
import struct  # noqa: E402
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import cable_gate_diff  # noqa: E402
import cable_gate_patch  # noqa: E402
import irisc_addr_scan  # noqa: E402
import irisc_loadgrid  # noqa: E402
from mlxfwutil import Image  # noqa: E402

ACA8008 = (REPO / "refs" / "fw" / "cx-5-6"
            / "fw-ConnectX5-rel-16_35_8008-MCX512A-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin")
ACA1012 = (REPO / "refs" / "fw" / "cx-5-6"
            / "fw-ConnectX5-rel-16_35_1012-MCX512A-ACA_Ax_Bx-UEFI-14.28.15-FlexBoot-3.6.804.bin")
ACA1912 = (REPO / "refs" / "fw" / "cx-4"
            / "fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")
CDA4030 = (REPO / "refs" / "fw" / "cx-5-6"
           / "fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin")


class TestCableGateDiff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ACA8008.is_file() or not ACA1012.is_file():
            raise unittest.SkipTest("refs/fw/cx-5-6 8008/1012 not present")
        cls.A = cable_gate_diff.main_section(ACA8008.read_bytes())
        cls.B = cable_gate_diff.main_section(ACA1012.read_bytes())

    def test_size_8008(self):
        self.assertEqual(len(self.A), 0x3d2220)

    def test_self_diff_empty(self):
        self.assertEqual(cable_gate_diff.hunk_map(self.A, self.A), [])

    def test_gate_strings_in_flagged_hunks(self):
        hunks = cable_gate_diff.hunk_map(self.A, self.B)
        self.assertTrue(hunks)
        for s in (b"Cable speed not enabled", b"FDR10 speed is not supported"):
            off = self.A.find(s)
            self.assertNotEqual(off, -1, f"{s!r} not in 8008 MAIN_CODE")
            flagged = [h for h in hunks
                       if h["a_off"] <= off < h["a_end"]
                       and cable_gate_diff.gate_flag(self.A, h)]
            self.assertTrue(flagged,
                            f"{s!r} at {off:#x} not inside a GATE hunk")

    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "hunks.json"
            rc = cable_gate_diff.main(
                [str(ACA8008), str(ACA1012), "--json", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["a_size"], 0x3d2220)
            self.assertTrue(any(h["gate"] for h in data["hunks"]))


class TestIriscAddrScan(unittest.TestCase):
    def test_words16_synthetic(self):
        buf = b"\x00" * 8 + (0x0004DFAC).to_bytes(4, "big") + b"\x00" * 8
        self.assertEqual(irisc_addr_scan.scan_words16(buf, 0x3BDFAC), [8])

    def test_words32rel_synthetic(self):
        buf = (0x00123456).to_bytes(4, "big") * 4
        self.assertEqual(
            irisc_addr_scan.scan_words32(buf, 0x00123456), [0, 4, 8, 12])

    def test_ldb_synthetic(self):
        data = b"\x00" * 8
        data += struct.pack(">I", (0x18 << 26) | 0xABCD)
        data += b"\x00" * 8
        self.assertEqual(irisc_addr_scan.scan_ldb(data, 0x1234ABCD), [8])

    def test_ldb_no_false_on_other_ops(self):
        data = struct.pack(">I", (0x19 << 26) | 0xABCD)
        self.assertEqual(irisc_addr_scan.scan_ldb(data, 0xABCD), [])

    @staticmethod
    def _irisc(op, rd, rs, imm):
        return struct.pack(">I", (op << 26) | (rs << 21) | (rd << 16) | imm)

    def test_set3_pair_synthetic(self):
        data = b"\x00" * 40
        data += self._irisc(0x08, 5, 0, 0xDFAC)
        data += self._irisc(0x09, 5, 5, 0x0000)
        data += b"\x00" * 8
        res = irisc_addr_scan.scan_set3(data, 0x3BDFAC, 0, 0x20, 40)
        self.assertEqual(res, [(40, 5, (44, 0))])

    def test_set3_nopair_synthetic(self):
        data = b"\x00" * 40
        data += self._irisc(0x08, 5, 0, 0xDFAC)
        data += b"\x00" * 16
        res = irisc_addr_scan.scan_set3(data, 0x3BDFAC, 0, 0x20, 40)
        self.assertEqual(res, [(40, 5, None)])

    def test_set3_wrong_register_not_paired(self):
        data = b"\x00" * 40
        data += self._irisc(0x08, 5, 0, 0xDFAC)
        data += self._irisc(0x09, 7, 7, 0x0000)
        data += b"\x00" * 8
        res = irisc_addr_scan.scan_set3(data, 0x3BDFAC, 0, 0x20, 40)
        self.assertEqual(res, [(40, 5, None)])

    def test_set3_real_8008_wall(self):
        if not ACA8008.is_file():
            self.skipTest("refs/fw/cx-5-6 8008 not present")
        raw = ACA8008.read_bytes()
        sect, _base = irisc_addr_scan.main_section(raw)
        for target in (0x3BDEED, 0x3BDF74, 0x3BDFAC, 0x3BDFC4):
            hits = irisc_addr_scan.scan_set3(sect, target, 0, 0x20, 40)
            print(f"8008 set3 {target:#x}: {len(hits)} site(s)")
            self.assertEqual(hits, [])

    def test_build_pairs_synthetic(self):
        data = b"\x00" * 40
        data += self._irisc(0x08, 5, 0, 0xA6F4)
        data += self._irisc(0x09, 5, 5, 0x003D)
        data += b"\x00" * 8
        res = irisc_addr_scan.scan_build_pairs(data, {0xA6F4}, {0x3D}, 40)
        self.assertEqual(res, [(40, 44, 5, 0x003DA6F4)])
        data = b"\x00" * 40
        data += self._irisc(0x09, 5, 5, 0x003D)
        data += self._irisc(0x00, 5, 5, 0xA6F4)
        data += b"\x00" * 8
        res = irisc_addr_scan.scan_build_pairs(data, {0xA6F4}, {0x3D}, 40)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0][3], 0x003DA6F4)

    def test_build_pairs_real_8008_wall(self):
        if not ACA8008.is_file():
            self.skipTest("refs/fw/cx-5-6 8008 not present")
        raw = ACA8008.read_bytes()
        for lo_set, hi_set in (({0xDEED, 0xDF74, 0xDFAC, 0xDFC4}, {0x3B}),
                               ({0xA635, 0xA6BC, 0xA6F4, 0xA70C}, {0x3D})):
            hits = irisc_addr_scan.scan_all_itoc_build_pairs(
                raw, lo_set, hi_set, 100)
            self.assertEqual(hits, [], f"build-pair for {sorted(lo_set)}")

    def test_words16_real_1912(self):
        if not ACA1912.is_file():
            self.skipTest("refs/fw/cx-4 1912 not present")
        raw = ACA1912.read_bytes()
        sect, _base = irisc_addr_scan.main_section(raw)
        cs = sect.find(b"Cable speed not enabled")
        self.assertNotEqual(cs, -1)
        hits = irisc_addr_scan.scan_words16(raw, cs)
        print(f"1912 CS@{cs:#x}: {len(hits)} words16 hit(s)")
        self.assertGreaterEqual(len(hits), 3)


class TestIriscLoadGrid(unittest.TestCase):
    def test_ldd_decode_synthetic(self):
        # ld.d r5, r12, OFF14=3 -> byte offset 12
        w = (0x19 << 26) | (12 << 21) | (5 << 16) | 3
        self.assertEqual(irisc_loadgrid.scan_loads(struct.pack(">I", w)),
                         [{"dc": 0, "op": "ld.d", "rs": 12, "rd": 5,
                           "off": 3 * 4}])

    def test_ldb_negative_imm(self):
        # ld.b r5, r12, simm16 = -1
        w = (0x18 << 26) | (12 << 21) | (5 << 16) | 0xFFFF
        self.assertEqual(irisc_loadgrid.scan_loads(struct.pack(">I", w)),
                         [{"dc": 0, "op": "ld.b", "rs": 12, "rd": 5,
                           "off": -1}])

    def test_effective_address_filter(self):
        w = (0x19 << 26) | (12 << 21) | (5 << 16) | 3
        data = struct.pack(">I", w)
        self.assertEqual(len(irisc_loadgrid.hits(
            data, base=0x3D9A00, lo=0x3D9A00, hi=0x3D9A10)), 1)
        self.assertEqual(irisc_loadgrid.hits(
            data, base=0x1000, lo=0x3D9A00, hi=0x3D9A10), [])

    def test_lwr_recorded_without_off(self):
        w = (0x3F << 26) | (12 << 21) | (5 << 16)
        self.assertEqual(irisc_loadgrid.scan_loads(struct.pack(">I", w)),
                         [{"dc": 0, "op": "lw.r", "rs": 12, "rt": 5,
                           "off": None}])


class TestCableGatePatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CDA4030.is_file():
            raise unittest.SkipTest("refs/fw/cx-5-6 4030-CDA not present")
        cls.img = Image(CDA4030.read_bytes(), str(CDA4030))
        e = cls.img.find_entry("ITOC", 0x03)
        assert e.clcrc == 1
        cls.raw = cls.img.section_data(e)
        cls.code, cls.tail = cable_gate_patch.deframe(cls.raw, e.clcrc)

    @staticmethod
    def _spec(off=0x100, new=b"\x00\x00\x00\x00", exp=None):
        return {"section": 3, "patches": [
            {"offset": f"0x{off:x}", "bytes": new.hex(),
             "expected_before": exp, "kind": "data", "note": "test"}]}

    def test_golden_detour_word(self):
        w = int.from_bytes(self.code[0x1d594:0x1d598], "big")
        self.assertEqual(w, 0x940002DE)

    def test_reframe_roundtrip(self):
        self.assertEqual(cable_gate_patch.reframe(self.code, self.tail),
                         self.raw)

    def test_check_ok(self):
        s = self._spec()
        s["patches"][0]["expected_before"] = self.code[0x100:0x104].hex()
        self.assertEqual(cable_gate_patch.check_spec(s, self.img), [])

    def test_check_wrong_expected(self):
        errs = cable_gate_patch.check_spec(self._spec(exp="ff" * 4), self.img)
        self.assertTrue(any("CHECK FAIL" in e for e in errs))

    def test_check_out_of_range(self):
        s = self._spec(off=0x397dc0 - 2)
        errs = cable_gate_patch.check_spec(s, self.img)
        self.assertTrue(any("OUT OF RANGE" in e for e in errs))

    def test_apply_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.bin"
            rc = cable_gate_patch.apply_spec(self._spec(new=b"\xde\xad\xbe\xef"),
                                             CDA4030, out)
            self.assertEqual(rc, 0)
            img2 = Image(out.read_bytes(), str(out))
            e2 = img2.find_entry("ITOC", 0x03)
            code2, _ = cable_gate_patch.deframe(img2.section_data(e2), e2.clcrc)
            self.assertEqual(code2[0x100:0x104], b"\xde\xad\xbe\xef")
