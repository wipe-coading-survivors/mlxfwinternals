import contextlib
import hashlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

import mlxfwutil  # noqa: E402
from mlxfwutil import (CNTX_MAGIC, DEVINFO_MAGIC, DTOC_HDR, FS4_MAGIC, ITOC_HDR,  # noqa: E402
                    Image, crc16_mlx, set_bits)

REPO = Path(__file__).resolve().parent.parent


class SynthMixin:
    # Синтетика по образцу реальных стоков: FS4 (ADA1012-подобный: 0xA0
    # crcf=1, DTOC 0xE1 crcf=2 с валидным mDevInfo) и FS3 (ACA1912-подобный:
    # все секции crcf=0 с валидным sec_crc, dev-записи non-rel, 0xE0 в ITOC).
    FS4_SEC_ADDR = 0x2000
    FS4_SIG_ADDR = 0x2100
    FS4_DEVINFO_ADDR = 0x3000
    FS3_SEC_ADDR = 0x2000
    FS3_SEC_SIZE = 0x40
    FS3_SIG_ADDR = 0x2100
    FS3_E2_ADDR = 0x2050
    FS3_DEV1_ADDR = 0x3000
    FS3_MFG_ADDR = 0x3100

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

    def _devinfo(self):
        d = bytearray(0x40)
        d[0:16] = DEVINFO_MAGIC
        d[0x10:0x14] = (0x00000200).to_bytes(4, "big")
        struct.pack_into(">H", d, 0x3E, crc16_mlx(bytes(d[:0x3C])))
        return bytes(d)

    def _sig_data(self, sig_uuid=b"\x00" * 16, keypair=b"\x00" * 16, slot=None):
        d = bytearray(0x40)
        d[0x00:0x10] = sig_uuid
        d[0x10:0x20] = keypair
        if slot is not None:
            d[0x20:0x40] = slot
        return bytes(d)

    def _fs4_synth(self, sig_data=None, with_sig=True, sig_size=0x40,
                   sec_size=0x100, hashes_ptr=None):
        buf = bytearray(0x10000)
        buf[0:16] = FS4_MAGIC
        if hashes_ptr is not None:
            struct.pack_into(">I", buf, 0x18 + 15 * 8, hashes_ptr)
            struct.pack_into(">H", buf, 0x18 + 15 * 8 + 4,
                             crc16_mlx(struct.pack(">I", hashes_ptr)))
        ents = [self._toc_ent(0x08, sec_size, self.FS4_SEC_ADDR,
                              sec_crc=crc16_mlx(bytes((i * 7 + 3) & 0xFF for i in range(sec_size))))]
        if with_sig:
            ents.append(self._toc_ent(0xA0, sig_size, self.FS4_SIG_ADDR, crcf=1))
        ents.append(self._toc_ent(0xFF, 0, 0))
        buf[0x1000:0x1020] = self._toc_hdr(ITOC_HDR, len(ents) - 1)
        for i, ent in enumerate(ents):
            buf[0x1020 + i * 32:0x1040 + i * 32] = ent
        buf[0x1100:0x1120] = self._toc_hdr(DTOC_HDR, 1)
        buf[0x1120:0x1140] = self._toc_ent(0xE1, 0x40, self.FS4_DEVINFO_ADDR, crcf=2)
        buf[0x1140:0x1160] = self._toc_ent(0xFF, 0, 0)
        buf[self.FS4_SEC_ADDR:self.FS4_SEC_ADDR + sec_size] = \
            bytes((i * 7 + 3) & 0xFF for i in range(sec_size))
        if with_sig:
            data = sig_data if sig_data is not None else self._sig_data()
            buf[self.FS4_SIG_ADDR:self.FS4_SIG_ADDR + sig_size] = data[:sig_size]
        buf[self.FS4_DEVINFO_ADDR:self.FS4_DEVINFO_ADDR + 0x40] = self._devinfo()
        return bytes(buf)

    def _fs3_synth(self, sig_data=None):
        buf = bytearray(0x10000)
        buf[0:16] = CNTX_MAGIC
        buf[0x24] = 3
        sec = bytes((i * 11 + 5) & 0xFF for i in range(self.FS3_SEC_SIZE))
        sig = sig_data if sig_data is not None else self._sig_data()
        e2 = b"\xe2" * 0x40
        ents = [
            self._toc_ent_fs3(0x05, self.FS3_SEC_SIZE, self.FS3_SEC_ADDR,
                              rel=1, sec_crc=crc16_mlx(sec)),
            self._toc_ent_fs3(0xA0, 0x40, self.FS3_SIG_ADDR, rel=1,
                              sec_crc=crc16_mlx(sig)),
            self._toc_ent_fs3(0xE2, 0x40, self.FS3_E2_ADDR, rel=0, dev=1,
                              sec_crc=crc16_mlx(e2)),
            self._toc_ent_fs3(0xE1, 0x40, self.FS3_DEV1_ADDR, rel=0, dev=1,
                              sec_crc=crc16_mlx(bytes(0x40))),
            self._toc_ent_fs3(0xE0, 0x40, self.FS3_MFG_ADDR, rel=0, dev=1,
                              sec_crc=crc16_mlx(bytes(0x40))),
            self._toc_ent(0xFF, 0, 0),
        ]
        buf[0x1000:0x1020] = self._toc_hdr(ITOC_HDR, len(ents) - 1)
        for i, ent in enumerate(ents):
            buf[0x1020 + i * 32:0x1040 + i * 32] = ent
        buf[self.FS3_SEC_ADDR:self.FS3_SEC_ADDR + self.FS3_SEC_SIZE] = sec
        buf[self.FS3_SIG_ADDR:self.FS3_SIG_ADDR + 0x40] = sig
        buf[self.FS3_E2_ADDR:self.FS3_E2_ADDR + 0x40] = e2
        return bytes(buf)


class TestSignCore(SynthMixin, unittest.TestCase):
    def test_fs4_masks_and_slot(self):
        slot = bytes(range(32))
        buf = self._fs4_synth(sig_data=self._sig_data(sig_uuid=b"\xaa" * 16, slot=slot))
        img = Image(buf, "fs4")
        end = self.FS4_SIG_ADDR + 0x40
        m = bytearray(buf[0:end])
        m[0:16] = b"\xff" * 16
        m[0x1040:0x1060] = b"\xff" * 32
        m[self.FS4_SIG_ADDR:self.FS4_SIG_ADDR + 0x40] = b"\xff" * 0x40
        self.assertEqual(mlxfwutil.sha256_digest(img), hashlib.sha256(bytes(m)).digest())
        buf2 = bytearray(self._fs4_synth(sig_data=self._sig_data(sig_uuid=b"\x55" * 16, slot=slot)))
        buf2[self.FS4_SIG_ADDR] ^= 0xFF
        self.assertEqual(mlxfwutil.sha256_digest(Image(bytes(buf2), "fs4b")),
                         mlxfwutil.sha256_digest(img))
        d = mlxfwutil.sha256_digest(img)
        fresh = Image(self._fs4_synth(sig_data=self._sig_data(slot=d)), "fresh")
        self.assertEqual(mlxfwutil.sig_status(fresh), ("fresh", d, d))
        wrong_off = Image(self._fs4_synth(
            sig_data=self._sig_data(sig_uuid=d, slot=b"\x11" * 32)), "wrong")
        self.assertEqual(mlxfwutil.sig_status(wrong_off), ("stale", b"\x11" * 32, d))

    def test_fs4_range_all_entries(self):
        sec_size = 0x300
        buf = bytearray(self._fs4_synth(
            sec_size=sec_size, sig_data=self._sig_data(slot=b"\x22" * 32)))
        img = Image(bytes(buf), "range")
        end = self.FS4_SEC_ADDR + sec_size
        m = bytearray(buf[0:end])
        m[0:16] = b"\xff" * 16
        m[0x1040:0x1060] = b"\xff" * 32
        m[self.FS4_SIG_ADDR:self.FS4_SIG_ADDR + 0x40] = b"\xff" * 0x40
        base_d = mlxfwutil.sha256_digest(img)
        self.assertEqual(base_d, hashlib.sha256(bytes(m)).digest())
        buf[end - 1] ^= 0xFF
        self.assertNotEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "r1")), base_d)
        buf[end - 1] ^= 0xFF
        buf[end] = 0x5A
        self.assertEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "r2")), base_d)
        buf[self.FS4_DEVINFO_ADDR + 0x20] ^= 0xFF
        self.assertEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "r3")), base_d)

    def test_fs3_range_relative_only(self):
        buf = bytearray(self._fs3_synth())
        img = Image(bytes(buf), "fs3")
        end = self.FS3_SIG_ADDR + 0x40
        m = bytearray(buf[0:end])
        m[0:16] = b"\xff" * 16
        m[0x1040:0x1060] = b"\xff" * 32
        for i in (2, 3, 4):
            m[0x1020 + i * 32:0x1040 + i * 32] = b"\xff" * 32
        m[self.FS3_SIG_ADDR:self.FS3_SIG_ADDR + 0x40] = b"\xff" * 0x40
        base_d = mlxfwutil.sha256_digest(img)
        self.assertEqual(base_d, hashlib.sha256(bytes(m)).digest())
        buf[self.FS3_SEC_ADDR + self.FS3_SEC_SIZE - 1] ^= 0xFF
        self.assertNotEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "a")), base_d)
        buf[self.FS3_SEC_ADDR + self.FS3_SEC_SIZE - 1] ^= 0xFF
        buf[end] = 0x77
        self.assertEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "b")), base_d)
        buf[self.FS3_DEV1_ADDR + 0x20] ^= 0xFF
        self.assertEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "c")), base_d)

    def test_fs3_dev_entry_masked(self):
        buf = bytearray(self._fs3_synth())
        base_d = mlxfwutil.sha256_digest(Image(bytes(buf), "d0"))
        buf[0x1060 + 6] ^= 0x01
        self.assertEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "d1")), base_d)
        buf[0x1060 + 6] ^= 0x01
        buf[0x1020 + 6] ^= 0x01
        self.assertNotEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "d2")), base_d)
        buf[0x1020 + 6] ^= 0x01
        buf[self.FS3_E2_ADDR + 8] ^= 0x01
        self.assertNotEqual(mlxfwutil.sha256_digest(Image(bytes(buf), "d3")), base_d)

    def test_base_offset_image(self):
        d0 = mlxfwutil.sha256_digest(Image(self._fs4_synth(), "base0"))
        src = self._fs4_synth()
        big = bytearray(0x810000)
        big[0x3000:0x3040] = src[self.FS4_DEVINFO_ADDR:self.FS4_DEVINFO_ADDR + 0x40]
        big[0x800000:0x810000] = src
        big[0x100] = 0xEE
        big[0x800000 + 0x2140 + 0x10] = 0xEE
        img = Image(bytes(big), "slotB", base=0x800000)
        self.assertEqual(mlxfwutil.sha256_digest(img), d0)

    def test_status_fresh_stale_rsa_empty_missing(self):
        d = mlxfwutil.sha256_digest(Image(self._fs4_synth(), "s0"))
        fresh = Image(self._fs4_synth(sig_data=self._sig_data(slot=d)), "s1")
        self.assertEqual(mlxfwutil.sig_status(fresh), ("fresh", d, d))
        stale_slot = bytes([d[0] ^ 0x01]) + d[1:]
        stale = Image(self._fs4_synth(sig_data=self._sig_data(slot=stale_slot)), "s2")
        self.assertEqual(mlxfwutil.sig_status(stale), ("stale", stale_slot, d))
        rsa = Image(self._fs4_synth(sig_data=self._sig_data(
            keypair=b"\x01" + b"\x00" * 15, slot=d)), "s3")
        self.assertEqual(mlxfwutil.sig_status(rsa), ("rsa", d, None))
        rsa_ff = Image(self._fs4_synth(sig_data=self._sig_data(
            keypair=b"\xff" * 16, slot=b"\x00" * 32)), "s4")
        self.assertEqual(mlxfwutil.sig_status(rsa_ff)[0], "rsa")
        for slot in (b"\x00" * 32, b"\xff" * 32, b"\x00" * 16 + b"\xff" * 16):
            empty = Image(self._fs4_synth(sig_data=self._sig_data(slot=slot)), "s5")
            self.assertEqual(mlxfwutil.sig_status(empty), ("empty", slot, None))
        missing = Image(self._fs4_synth(with_sig=False), "s6")
        self.assertEqual(mlxfwutil.sig_status(missing), ("missing", None, None))
        small = Image(self._fs4_synth(sig_size=0x20, sig_data=self._sig_data()), "s7")
        self.assertEqual(mlxfwutil.sig_status(small), ("empty", None, None))

    def test_status_v2(self):
        d = mlxfwutil.sha256_digest(Image(self._fs4_synth(), "v0"))
        img = Image(self._fs4_synth(hashes_ptr=0x4000,
                                     sig_data=self._sig_data(slot=d)), "v1")
        self.assertEqual(mlxfwutil.sig_status(img), ("v2", None, None))


class TestSignCmd(SynthMixin, unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mlxfwutil.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _tmp_image(self, data):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = Path(d.name) / "img.bin"
        p.write_bytes(data)
        return p

    def test_write_fs4_changes_only_slot(self):
        src = self._fs4_synth(sig_data=self._sig_data(sig_uuid=b"\xaa" * 16,
                                                      slot=b"\x22" * 32))
        p = self._tmp_image(src)
        rc, out, err = self._run(["sign", str(p)])
        self.assertEqual(rc, 0)
        new = p.read_bytes()
        self.assertEqual(len(new), len(src))
        slot = set(range(self.FS4_SIG_ADDR + 0x20, self.FS4_SIG_ADDR + 0x40))
        diff = {i for i in range(len(src)) if src[i] != new[i]}
        self.assertTrue(diff)
        self.assertLessEqual(diff, slot)
        img = Image(new, "out")
        data = img.section_data(img.find_entry("ITOC", 0xA0))
        self.assertEqual(data[0x00:0x10], b"\xaa" * 16)
        self.assertEqual(data[0x10:0x20], b"\x00" * 16)
        self.assertEqual(data[0x20:0x40], mlxfwutil.sha256_digest(Image(src, "in")))

    def test_write_idempotent(self):
        src = self._fs4_synth(sig_data=self._sig_data(slot=b"\x22" * 32))
        p1 = self._tmp_image(src)
        self.assertEqual(self._run(["sign", str(p1)])[0], 0)
        mid = p1.read_bytes()
        p2 = self._tmp_image(mid)
        self.assertEqual(self._run(["sign", str(p2)])[0], 0)
        self.assertEqual(p2.read_bytes(), mid)
        d = mlxfwutil.sha256_digest(Image(src, "s"))
        fresh = self._fs4_synth(sig_data=self._sig_data(slot=d))
        p3 = self._tmp_image(fresh)
        rc, out, err = self._run(["sign", str(p3)])
        self.assertEqual(rc, 0)
        self.assertEqual(p3.read_bytes(), fresh)

    def test_fs3_write_updates_crcs(self):
        src = self._fs3_synth(sig_data=self._sig_data(slot=b"\x33" * 32))
        p = self._tmp_image(src)
        rc, out, err = self._run(["sign", str(p)])
        self.assertEqual(rc, 0)
        img = Image(p.read_bytes(), "out")
        self.assertEqual(mlxfwutil.verify_image(img), [])
        e = img.find_entry("ITOC", 0xA0)
        self.assertTrue(img.entry_crc_ok(e))
        self.assertEqual(e.sec_crc, crc16_mlx(img.section_data(e)))
        self.assertEqual(img.section_data(e)[0x20:0x40],
                         mlxfwutil.sha256_digest(Image(src, "in")))

    def test_check_fresh_rc0_stale_rc1(self):
        d = mlxfwutil.sha256_digest(Image(self._fs4_synth(), "s"))
        fresh = self._fs4_synth(sig_data=self._sig_data(slot=d))
        stale = self._fs4_synth(sig_data=self._sig_data(slot=b"\x22" * 32))
        pf = self._tmp_image(fresh)
        rc, out, err = self._run(["sign", "--check", str(pf)])
        self.assertEqual(rc, 0)
        self.assertIn("fresh", out)
        self.assertEqual(pf.read_bytes(), fresh)
        ps = self._tmp_image(stale)
        rc, out, err = self._run(["sign", "--check", str(ps)])
        self.assertEqual(rc, 1)
        self.assertIn("stale", out)
        self.assertEqual(ps.read_bytes(), stale)

    def test_refuse_rsa_rc2(self):
        rsa = self._fs4_synth(sig_data=self._sig_data(
            keypair=b"\x01" + b"\x00" * 15, slot=b"\x22" * 32))
        p = self._tmp_image(rsa)
        rc, out, err = self._run(["sign", str(p)])
        self.assertEqual(rc, 2)
        self.assertIn("--force", err)
        self.assertEqual(p.read_bytes(), rsa)

    def test_force_rsa_normalizes(self):
        rsa = self._fs4_synth(sig_data=self._sig_data(
            sig_uuid=b"\xab" * 16, keypair=b"\xcd" * 16, slot=b"\x22" * 32))
        d = mlxfwutil.sha256_digest(Image(rsa, "rsa"))
        p = self._tmp_image(rsa)
        rc, out, err = self._run(["sign", "--force", str(p)])
        self.assertEqual(rc, 0)
        img = Image(p.read_bytes(), "forced")
        data = img.section_data(img.find_entry("ITOC", 0xA0))
        self.assertEqual(data[0x00:0x20], b"\x00" * 32)
        self.assertEqual(data[0x20:0x40], d)
        rc, out, err = self._run(["sign", "--check", str(p)])
        self.assertEqual(rc, 0)
        self.assertIn("fresh", out)

    def test_refuse_v2_rc2(self):
        v2 = self._fs4_synth(hashes_ptr=0x4000,
                             sig_data=self._sig_data(slot=b"\x22" * 32))
        p = self._tmp_image(v2)
        rc, out, err = self._run(["sign", str(p)])
        self.assertEqual(rc, 2)
        rc, out, err = self._run(["sign", "--force", str(p)])
        self.assertEqual(rc, 2)
        self.assertEqual(p.read_bytes(), v2)

    def test_missing_section_rc2(self):
        miss = self._fs4_synth(with_sig=False)
        p = self._tmp_image(miss)
        rc, out, err = self._run(["sign", str(p)])
        self.assertEqual(rc, 2)
        self.assertEqual(p.read_bytes(), miss)

    def test_output_digest_matches_core(self):
        src = self._fs4_synth(sig_data=self._sig_data(slot=b"\x22" * 32))
        p = self._tmp_image(src)
        rc, out, err = self._run(["sign", str(p)])
        self.assertEqual(rc, 0)
        self.assertIn(mlxfwutil.sha256_digest(Image(src, "s")).hex(), out)

    def test_verify_info_line_stale(self):
        stale = self._fs4_synth(sig_data=self._sig_data(slot=b"\x22" * 32))
        p = self._tmp_image(stale)
        rc, out, err = self._run(["verify", str(p)])
        self.assertEqual(rc, 0)
        self.assertIn("signature 0xA0: stale", out)
        self.assertIn("RESULT: PASS", out)

    def test_verify_info_line_fresh(self):
        d = mlxfwutil.sha256_digest(Image(self._fs4_synth(), "s"))
        fresh = self._fs4_synth(sig_data=self._sig_data(slot=d))
        p = self._tmp_image(fresh)
        rc, out, err = self._run(["verify", str(p)])
        self.assertEqual(rc, 0)
        self.assertIn(f"signature 0xA0: fresh {d.hex()[:8]}", out)


STALE_KNOWN = {  # our old builds/dumps (spec §6, builder-check)
    "cx-4/cx4_4706_sp_v3.bin", "cx-4/cx4_4706_sp_v4.bin",
    "cx-5-6/fw-ConnectX5-rel-16_35_8008-DEV.bin", "cx-5-6/t42_pre_ri.bin",
}

RSA_KNOWN = {  # Dell/HP OEM-signed, Facebook ri, CX-6Dx secure-boot stocks
    "cx-5-6/fw-ConnectX5-rel-16_27_6120-09FTMY_071C1T_Ax-UEFI-14.20.27-FlexBoot-3.5.903.signed.bin",
    "cx-5-6/fw-ConnectX5-rel-16_35_4030-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin",
    "cx-5-6/fw-ConnectX5-rel-16_35_8008-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin",
    "cx-5-6/FB-BKP/fb/MCX623435MC-CDAE_FB_Ax-ocr-ri.bin",
    "cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX621102AC-ADA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin",
    "cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623105AC-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin",
    "cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623432AC-ADA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin",
    "cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin",
    "cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-VDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin",
    "cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623436AC-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin",
    "cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623436AS-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin",
}


@pytest.mark.slow
@unittest.skipUnless((REPO / "refs" / "fw").is_dir(), "refs/fw corpus not available")
class TestBitEquivRefs(unittest.TestCase):
    # Verification vectors over the vendor-stock corpus (spec §6.2): core
    # is already merged, expectation is PASS. Paths with a "dumps"
    # component (raw card dumps, custom builds) are excluded from the
    # vendor-stock set entirely (coordinator ruling); FS4-magic files
    # without a parseable ITOC (CX-7 PLDM wrappers) are unclassifiable.
    _scan = None

    @classmethod
    def _classify(cls):
        if cls._scan is not None:
            return cls._scan
        fw = REPO / "refs" / "fw"
        scan = {"digest": {}, "rsa": set(), "counts": {}}
        for p in sorted(fw.rglob("*")):
            if not p.is_file():
                continue
            relpath = p.relative_to(fw)
            rel = relpath.as_posix()
            try:
                buf = p.read_bytes()
                fmt, base = mlxfwutil.detect_format(buf)
                img = Image(buf, rel, base=base, fmt=fmt)
                status, stored, _calc = mlxfwutil.sig_status(img)
            except (OSError, ValueError):
                continue
            is_dumps = "dumps" in relpath.parts
            key = status + ("/dumps" if is_dumps else "/stock")
            scan["counts"][key] = scan["counts"].get(key, 0) + 1
            if is_dumps:
                continue
            if status in ("fresh", "stale"):
                scan["digest"][rel] = (status, stored)
            elif status == "rsa":
                scan["rsa"].add(rel)
        cls._scan = scan
        return scan

    def test_bitexact_vendor_stocks(self):
        scan = self._classify()
        bad = []
        for rel, (status, stored) in scan["digest"].items():
            if rel in STALE_KNOWN:
                continue
            if status != "fresh":
                bad.append((rel, status))
                continue
            p = REPO / "refs" / "fw" / rel
            buf = p.read_bytes()
            fmt, base = mlxfwutil.detect_format(buf)
            self.assertEqual(mlxfwutil.sha256_digest(Image(buf, rel, base=base, fmt=fmt)),
                             stored, f"{rel}: direct sha256_digest != stored slot")
        self.assertEqual(bad, [], "digest-only vendor stocks outside STALE_KNOWN "
                                  "must be bit-exact fresh (spec §7 STOP list)")

    def test_stale_vectors(self):
        scan = self._classify()
        present = {rel: st for rel, (st, _stored) in scan["digest"].items()
                   if rel in STALE_KNOWN}
        self.assertTrue(present, "no STALE_KNOWN vectors found in refs/fw")
        for rel, status in present.items():
            self.assertEqual(status, "stale", rel)

    def test_rsa_vectors(self):
        scan = self._classify()
        checked = 0
        for rel in sorted(RSA_KNOWN):
            p = REPO / "refs" / "fw" / rel
            if not p.is_file():
                continue
            buf = p.read_bytes()
            fmt, base = mlxfwutil.detect_format(buf)
            self.assertEqual(mlxfwutil.sig_status(Image(buf, rel, base=base, fmt=fmt))[0],
                             "rsa", rel)
            checked += 1
        self.assertGreaterEqual(checked, 4, "known Dell/HP/SB/FB RSA vectors missing")
        self.assertGreaterEqual(len(scan["rsa"]), checked)

    def test_fresh_count_floor(self):
        scan = self._classify()
        fresh = sum(1 for st, _ in scan["digest"].values() if st == "fresh")
        self.assertGreaterEqual(fresh, 50, "corpus filter regression: fresh stocks < 50")
