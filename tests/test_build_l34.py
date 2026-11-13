"""serdes-arc-d task-03 tests: L3/L4 builder (IB mask word + slot 1351).

Golden pins:
  * T2 mask site (journal docs/superpowers/journal/
    2026-11-12-serdes-arc-d-task-02.md, "Патч-спека"): 1912-GCA dc
    0x1f2054, old word fcb1c083, L3 word 0011001f (addi r17,zero,0x1f),
    L4 0011003f (0x1f|0x20; bit5=EDR is convention-derived — live
    confirmation deferred to T4 readback);
  * slot 1351 (docs/250-re/100-formats/075-phyuc-consts.md §5 + ruling
    commit 8dfc65f): 0x0A record wr6165 p=0x27 blk=3 reg=0x9cc addr=0x820;
    Lx stock val=1, CX-4 val=0 -> patch 1->0 (CX-4-like differential;
    byte 0x547f = slot_idx*16 + 15, low byte of the BE16 d field);
  * VPI byte (T4c finding + ruling commit 4dde8c3): 1912-GCA stock is
    an EN image, section 0x11 +0x2af (abs 0x172af) = 0x0a, so the card
    cannot enter IB mode (mstconfig set LINK_TYPE_P1=IB -> Unknown
    Parameter) -> L3v/L4v = L3/L4 + VPI 0x0a->0x07 (qsfp28-ib T4.5/T4.8
    precedent: VPI swaps burned Active on this card family);
  * CRC policy (docs/250-re/100-formats/025-crc.md §6): sec_crc first,
    then entry_crc; a forgotten entry_crc = invalid ITOC and the
    verify --deep gate must catch it (Review Focus 3, plan
    docs/superpowers/plans/2026-11-12-serdes-arc-d.md);
  * build-ID (mellanox-fw-build R1, fix round per controller ruling):
    the arc-D ladder marker ("; mlxini serdes-arc-d L…-…", right after
    the anchor) is REPLACED line-for-line per level (T1 filled the
    physical 0x30 slot, accumulation cannot fit) — each image carries
    exactly one current-level marker.
"""
import contextlib
import io
import struct
import sys
import tempfile
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-arc-d"))

import build_l34  # noqa: E402

import mlxfwutil  # noqa: E402
from mlxfwutil import CNTX_MAGIC, ITOC_HDR, clcrc_wrap, crc16_mlx, set_bits  # noqa: E402

from scripts.irisc import AsmError  # noqa: E402

IMG_L2 = REPO / "build" / "serdes-arc-d" / "img-L2.bin"
IMG_L2_MD5 = "f7ac6cf4a75c99d034e5cb49ddfa8588"

FIX_DC = 0x254
FIX_NLINES = 0x40
FIX_TAIL = b"\xaa\xbb\xcc\xdd"
FIX_OFF_03 = 0x4000
FIX_OFF_0A = 0x6000
FIX_OFF_11 = 0x1200
FIX_SIZE_11 = 0x400
FIX_VPI_OFF = FIX_OFF_11 + 0x2AF
FIX_OFF_A0 = 0xC000
FIX_OFF_E1 = 0xC100
FIX_OFF_E0 = 0xC200
FIX_OFF_30 = 0xC400
FIX_SIZE_30 = 0x400

PREV_MARKER = ("; mlxini serdes-arc-d 100G (2026-11-12, test): "
               "lcl[0] 0x3b->0xfb @0x30b")

FIX_INI = "\n".join([
    ";; Generated automatically by iniprep tool",
    "",
    ";; Mellanox Technologies LTD",
    PREV_MARKER,
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed1Gb   = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed10Gb  = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed25Gb  = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed40Gb  = 0x1",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed100Gb = 0x1",
])

L3_ID = ("; mlxini serdes-arc-d L3-4xFDR (2026-11-12, fixture): "
          "ib mask fcb1c083->0011001f + slot1351 1->0")
L4_ID = ("; mlxini serdes-arc-d L4-4xEDR (2026-11-12, fixture): "
          "ib mask 0011001f->0011003f (EDR bit)")
L3V_ID = ("; mlxini serdes-arc-d L3v-4xFDR-IB (2026-11-12, fixture): "
          "vpi 0a->07 @0x172af")
L4V_ID = ("; mlxini serdes-arc-d L4v-4xEDR-IB (2026-11-12, fixture): "
          "vpi 0a->07 @0x172af")


def _toc_hdr(nent):
    h = bytearray(32)
    h[0:16] = ITOC_HDR
    set_bits(h, 184, 8, nent)
    set_bits(h, 240, 16, crc16_mlx(bytes(h[:28])))
    return bytes(h)


def _toc_ent(t, size, addr, sec_crc, rel=1, dev=0, cl=0):
    r = bytearray(32)
    set_bits(r, 0, 8, t)
    set_bits(r, 8, 22, size // 4)
    set_bits(r, 161, 29, addr // 4)
    set_bits(r, 160, 1, rel)
    set_bits(r, 206, 1, dev)
    set_bits(r, 33, 1, cl)
    set_bits(r, 208, 16, sec_crc)
    set_bits(r, 240, 16, crc16_mlx(bytes(r[:28])))
    return bytes(r)


def _sec03_payload():
    payload = bytearray(FIX_NLINES * 64)
    for i in range(len(payload)):
        payload[i] = (i * 7 + 3) & 0xFF
    payload[FIX_DC:FIX_DC + 4] = build_l34.MASK_WORD_OLD
    return bytes(payload)


def _sec0a_data():
    data = bytearray(build_l34.SLOT_IDX * 16 + 16)
    data[0 * 16 + 6:0 * 16 + 16] = struct.pack(">5H", 0x4000, 0x64, 0, 0, 0)
    data[3 * 16 + 6:3 * 16 + 16] = struct.pack(
        ">5H", build_l34.SLOT_OP, build_l34.SLOT_A, 0x19CC,
        build_l34.SLOT_C, build_l34.SLOT_D_BASE)
    data[build_l34.SLOT_IDX * 16 + 6:build_l34.SLOT_IDX * 16 + 16] = \
        struct.pack(">5H", build_l34.SLOT_OP, build_l34.SLOT_A,
                    build_l34.SLOT_B, build_l34.SLOT_C,
                    build_l34.SLOT_D_BASE)
    return bytes(data)


def _sec11_data():
    data = bytearray(FIX_SIZE_11)
    for i in range(len(data)):
        data[i] = (i * 11 + 5) & 0xFF
    data[build_l34.VPI_OFF] = build_l34.VPI_OLD
    return bytes(data)


def _fs3_fixture(cl_03=1):
    framed = clcrc_wrap(_sec03_payload(), FIX_TAIL)
    sec0a = _sec0a_data()
    sec11 = _sec11_data()
    sig = bytearray(0x40)
    sig[0x20:0x40] = b"\x22" * 32
    dev = bytes(0x40)
    ini30 = zlib.compress(FIX_INI.encode("latin1"), 9)
    ini30 += b"\x00" * (FIX_SIZE_30 - len(ini30))
    ents = [
        _toc_ent(0x03, len(framed), FIX_OFF_03, crc16_mlx(framed), cl=cl_03),
        _toc_ent(0x0A, len(sec0a), FIX_OFF_0A, crc16_mlx(sec0a)),
        _toc_ent(0x11, FIX_SIZE_11, FIX_OFF_11, crc16_mlx(sec11)),
        _toc_ent(0xA0, 0x40, FIX_OFF_A0, crc16_mlx(bytes(sig))),
        _toc_ent(0x30, FIX_SIZE_30, FIX_OFF_30, crc16_mlx(ini30)),
        _toc_ent(0xE1, 0x40, FIX_OFF_E1, crc16_mlx(dev), rel=0, dev=1),
        _toc_ent(0xE0, 0x40, FIX_OFF_E0, crc16_mlx(dev), rel=0, dev=1),
        _toc_ent(0xFF, 0, 0, 0),
    ]
    buf = bytearray(0xD000)
    buf[0:16] = CNTX_MAGIC
    buf[0x24] = 3
    buf[0x1000:0x1020] = _toc_hdr(len(ents) - 1)
    for i, ent in enumerate(ents):
        buf[0x1020 + i * 32:0x1040 + i * 32] = ent
    buf[FIX_OFF_03:FIX_OFF_03 + len(framed)] = framed
    buf[FIX_OFF_0A:FIX_OFF_0A + len(sec0a)] = sec0a
    buf[FIX_OFF_11:FIX_OFF_11 + FIX_SIZE_11] = sec11
    buf[FIX_OFF_A0:FIX_OFF_A0 + 0x40] = sig
    buf[FIX_OFF_E1:FIX_OFF_E1 + 0x40] = dev
    buf[FIX_OFF_E0:FIX_OFF_E0 + 0x40] = dev
    buf[FIX_OFF_30:FIX_OFF_30 + FIX_SIZE_30] = ini30
    return bytes(buf)


def _entry_abs_off(img, typ):
    e = img.find_entry("ITOC", typ)
    return img.itoc_off + 32 + e.index * 32


def _diffs(new, old):
    return {i for i in range(min(len(new), len(old))) if new[i] != old[i]}


def _ini_text(buf):
    img = mlxfwutil.Image(buf, "r")
    data = mlxfwutil.extract_section(img, 0x30)
    return zlib.decompress(data).decode("latin1")


class TestPinnedConstants:

    def test_mask_site_pins(self):
        assert build_l34.MASK_DC == 0x1F2054
        assert build_l34.MASK_WORD_OLD.hex() == "fcb1c083"
        assert build_l34.MASK_WORDS["L3"].hex() == "0011001f"
        assert build_l34.MASK_WORDS["L4"].hex() == "0011003f"

    def test_edr_delta_is_one_byte(self):
        l3, l4 = build_l34.MASK_WORDS["L3"], build_l34.MASK_WORDS["L4"]
        assert l4[:3] == l3[:3]
        assert l3[3] == 0x1F
        assert l4[3] == 0x3F

    def test_word_within_one_clcrc_line(self):
        assert build_l34.MASK_DC % 64 == 0x14
        assert build_l34.MASK_DC % 64 + 4 <= 64

    def test_slot_pins(self):
        assert build_l34.SLOT_IDX == 1351
        assert (build_l34.SLOT_OP, build_l34.SLOT_A, build_l34.SLOT_B,
                build_l34.SLOT_C) == (0x6165, 0x27, 0x39CC, 0x820)
        assert build_l34.SLOT_D_BASE == 1
        assert build_l34.SLOT_D_CX4 == 0
        assert build_l34.SLOT_IDX * 16 + 15 == 0x547F

    def test_vpi_pins(self):
        assert build_l34.VPI_SEC == 0x11
        assert build_l34.VPI_OFF == 0x2AF
        assert build_l34.VPI_ABS == 0x172AF
        assert (build_l34.VPI_OLD, build_l34.VPI_NEW) == (0x0A, 0x07)

    def test_v_levels(self):
        assert build_l34.V_LEVELS == {"L3v": "L3", "L4v": "L4"}
        assert build_l34.DEFAULT_LABELS["L3v"] == "L3v-4xFDR-IB"
        assert build_l34.DEFAULT_LABELS["L4v"] == "L4v-4xEDR-IB"

    def test_levels(self):
        assert build_l34.PATCHES_SLOT == {"L3": True, "L4": False}

    def test_default_labels(self):
        assert build_l34.DEFAULT_LABELS == {
            "L3": "L3-4xFDR", "L4": "L4-4xEDR",
            "L3v": "L3v-4xFDR-IB", "L4v": "L4v-4xEDR-IB"}


class TestPatchSlot:

    def setUp_base(self):
        self.base = _fs3_fixture()
        return self.base

    def test_patch_and_roundtrip(self):
        base = self.setUp_base()
        out, zones = build_l34.patch_slot(base)
        img = mlxfwutil.Image(out, "out")
        rec = build_l34.slot_at(
            img.section_data(img.find_entry("ITOC", 0x0A)))
        assert rec[1:6] == (build_l34.SLOT_OP, build_l34.SLOT_A,
                            build_l34.SLOT_B, build_l34.SLOT_C,
                            build_l34.SLOT_D_CX4)
        assert out[FIX_OFF_0A + 0x547F] == 0
        assert base[FIX_OFF_0A + 0x547F] == 1
        assert not mlxfwutil.verify_image(img, deep=True)

    def test_diff_exactly_declared_zone(self):
        base = self.setUp_base()
        out, zones = build_l34.patch_slot(base)
        diffs = _diffs(out, base)
        assert diffs <= zones
        assert FIX_OFF_0A + 0x547F in diffs
        img = mlxfwutil.Image(base, "base")
        eo = _entry_abs_off(img, 0x0A)
        assert diffs & {eo + 0x1A, eo + 0x1B, eo + 0x1E, eo + 0x1F}

    def test_rejects_wrong_record(self):
        base = bytearray(_fs3_fixture())
        base[FIX_OFF_0A + build_l34.SLOT_IDX * 16 + 6] = 0x62
        with pytest.raises(AsmError):
            build_l34.patch_slot(bytes(base))

    def test_rejects_already_patched_base(self):
        base = _fs3_fixture()
        l3, _ = build_l34.patch_slot(base)
        with pytest.raises(AsmError):
            build_l34.patch_slot(l3)


class TestPatchMask:

    def test_l3_patch_and_verify(self):
        base = _fs3_fixture()
        out, zones = build_l34.patch_mask(base, "L3", dc=FIX_DC)
        img = mlxfwutil.Image(out, "out")
        assert not mlxfwutil.verify_image(img, deep=True)
        assert out[FIX_OFF_03 + 9 * 68 + 0x14:FIX_OFF_03 + 9 * 68 + 0x18] == \
            build_l34.MASK_WORDS["L3"]
        diffs = _diffs(out, base)
        assert diffs <= zones
        assert FIX_OFF_03 + 9 * 68 + 0x14 in diffs

    def test_line_crc_recomputed(self):
        base = _fs3_fixture()
        out, _ = build_l34.patch_mask(base, "L3", dc=FIX_DC)
        ln = FIX_DC // 64
        lo = FIX_OFF_03 + ln * 68
        line66 = bytearray(out[lo:lo + 66])
        assert out[lo + 66:lo + 68] == struct.pack(
            "<H", mlxfwutil.clcrc_calc(bytes(line66)))
        assert out[lo + 66:lo + 68] != base[lo + 66:lo + 68]

    def test_l4_delta_is_exactly_edr_bit(self):
        base = _fs3_fixture()
        l3, _ = build_l34.patch_mask(base, "L3", dc=FIX_DC)
        l4, zones = build_l34.patch_mask(l3, "L4", dc=FIX_DC)
        diffs = _diffs(l4, l3)
        wo = FIX_OFF_03 + 9 * 68 + 0x14
        assert l4[wo + 3] == 0x3F and l3[wo + 3] == 0x1F
        assert diffs <= zones
        assert wo + 3 in diffs

    def test_rejects_wrong_old_word(self):
        base = _fs3_fixture()
        with pytest.raises(AsmError):
            build_l34.patch_mask(base, "L4", dc=FIX_DC)

    def test_rejects_corrupt_stock_line_crc(self):
        base = bytearray(_fs3_fixture())
        ln = 2
        base[FIX_OFF_03 + ln * 68 + 66] ^= 0xFF
        with pytest.raises(AsmError):
            build_l34.patch_mask(bytes(base), "L3", dc=FIX_DC)

    def test_rejects_non_clcrc_section(self):
        base = _fs3_fixture(cl_03=0)
        with pytest.raises(AsmError):
            build_l34.patch_mask(base, "L3", dc=FIX_DC)


class TestBuildID:
    """R1 fix round: the arc-D ladder marker is REPLACED line-for-line
    (T1 filled the physical 0x30 slot; accumulation cannot fit)."""

    def test_marker_replaces_prev_level_marker(self):
        base = _fs3_fixture()
        res = build_l34.build_level(base, "L3", dc=FIX_DC, build_id=L3_ID)
        lines = _ini_text(res.final).split("\n")
        assert L3_ID in lines
        assert PREV_MARKER not in lines
        assert lines.index(L3_ID) == lines.index(
            ";; Mellanox Technologies LTD") + 1
        assert not mlxfwutil.verify_image(
            mlxfwutil.Image(res.final, "l3"), deep=True)

    def test_l4_replaces_l3_marker(self):
        base = _fs3_fixture()
        l3 = build_l34.build_level(base, "L3", dc=FIX_DC,
                                   build_id=L3_ID).final
        l4 = build_l34.build_level(l3, "L4", dc=FIX_DC, build_id=L4_ID).final
        lines = _ini_text(l4).split("\n")
        assert L4_ID in lines
        assert L3_ID not in lines
        assert PREV_MARKER not in lines
        assert ";; Generated automatically by iniprep tool" in lines
        assert lines.index(L4_ID) == lines.index(
            ";; Mellanox Technologies LTD") + 1
        assert not mlxfwutil.verify_image(
            mlxfwutil.Image(l4, "l4"), deep=True)

    def test_inserts_after_anchor_when_no_marker(self):
        base = _fs3_fixture()
        img = mlxfwutil.Image(base, "base")
        raw = img.section_data(img.find_entry("ITOC", 0x30))
        lines = zlib.decompress(raw).decode("latin1").split("\n")
        lines.remove(PREV_MARKER)
        buf = bytearray(base)
        data = zlib.compress("\n".join(lines).encode("latin1"), 9)
        data += b"\x00" * (FIX_SIZE_30 - len(data))
        buf[FIX_OFF_30:FIX_OFF_30 + FIX_SIZE_30] = data
        ent = bytearray(img.find_entry("ITOC", 0x30).raw)
        set_bits(ent, 208, 16, crc16_mlx(data))
        set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
        eo = _entry_abs_off(img, 0x30)
        buf[eo:eo + 32] = ent
        res = build_l34.build_level(bytes(buf), "L3", dc=FIX_DC,
                                    build_id=L3_ID)
        got = _ini_text(res.final).split("\n")
        assert got.index(L3_ID) == got.index(
            ";; Mellanox Technologies LTD") + 1

    def test_rejects_multiple_ladder_markers(self):
        base = _fs3_fixture()
        img = mlxfwutil.Image(base, "base")
        raw = img.section_data(img.find_entry("ITOC", 0x30))
        text = zlib.decompress(raw).decode("latin1").replace(
            PREV_MARKER, PREV_MARKER + "\n" + "; mlxini serdes-arc-d dup")
        data = zlib.compress(text.encode("latin1"), 9)
        data += b"\x00" * (FIX_SIZE_30 - len(data))
        buf = bytearray(base)
        buf[FIX_OFF_30:FIX_OFF_30 + FIX_SIZE_30] = data
        ent = bytearray(img.find_entry("ITOC", 0x30).raw)
        set_bits(ent, 208, 16, crc16_mlx(data))
        set_bits(ent, 240, 16, crc16_mlx(bytes(ent[:28])))
        eo = _entry_abs_off(img, 0x30)
        buf[eo:eo + 32] = ent
        with pytest.raises(AsmError):
            build_l34.patch_build_id(bytes(buf), L3_ID)

    def test_zones_cover_0x30_diff(self):
        base = _fs3_fixture()
        res = build_l34.build_level(base, "L3", dc=FIX_DC, build_id=L3_ID)
        diffs = _diffs(res.final, base)
        assert diffs <= res.zones
        assert diffs & set(range(FIX_OFF_30, FIX_OFF_30 + FIX_SIZE_30))
        img = mlxfwutil.Image(base, "base")
        eo = _entry_abs_off(img, 0x30)
        assert diffs & set(range(eo, eo + 32))

    def test_rejects_malformed_build_id(self):
        base = _fs3_fixture()
        for bad in ("no-prefix-line", "; two\nlines", ""):
            with pytest.raises(AsmError):
                build_l34.build_level(base, "L3", dc=FIX_DC, build_id=bad)

    def test_rejects_missing_build_id(self):
        base = _fs3_fixture()
        with pytest.raises(AsmError):
            build_l34.build_level(base, "L3", dc=FIX_DC)


class TestRoundtripITOC:
    """Review Focus 3: ITOC sec_crc/entry_crc coherence on the 0x0A edit.

    Positive: the full builder flow leaves a verify --deep-clean image
    (Round-trip ITOC). Negative: skipping the entry_crc recompute (only
    the section data + sec_crc updated) must FAIL verify --deep.
    """

    def test_full_l3_roundtrip_itoc_ok(self):
        base = _fs3_fixture()
        res = build_l34.build_level(base, "L3", dc=FIX_DC, build_id=L3_ID)
        img = mlxfwutil.Image(res.final, "l3")
        assert not mlxfwutil.verify_image(img, deep=True)
        assert res.final[FIX_OFF_03 + 9 * 68 + 0x14:FIX_OFF_03 + 9 * 68
                         + 0x18] == build_l34.MASK_WORDS["L3"]
        assert res.final[FIX_OFF_0A + 0x547F] == 0

    def test_forgotten_entry_crc_fails_verify_deep(self):
        base = bytearray(_fs3_fixture())
        img = mlxfwutil.Image(bytes(base), "base")
        eo = _entry_abs_off(img, 0x0A)
        new0a = bytearray(img.section_data(img.find_entry("ITOC", 0x0A)))
        new0a[0x547F] = 0
        base[FIX_OFF_0A + 0x547F] = 0
        ent = bytearray(base[eo:eo + 32])
        set_bits(ent, 208, 16, crc16_mlx(bytes(new0a)))
        base[eo:eo + 32] = ent
        broken = mlxfwutil.Image(bytes(base), "broken")
        errs = mlxfwutil.verify_image(broken, deep=True)
        assert any("entry CRC NG" in e and "0x0a" in e for e in errs)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "broken.bin"
            p.write_bytes(bytes(base))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                rc = mlxfwutil.main(["verify", "--deep", str(p)])
            assert rc == 1

    def test_forgotten_sec_crc_fails_verify_deep(self):
        base = bytearray(_fs3_fixture())
        base[FIX_OFF_0A + 0x547F] = 0
        img = mlxfwutil.Image(bytes(base), "broken")
        errs = mlxfwutil.verify_image(img, deep=True)
        assert any("section CRC WRONG" in e and "0x0a" in e for e in errs)


class TestPatchVpi:
    """T4c/4dde8c3: 0x11+0x2af VPI byte 0x0a->0x07 (EN->VPI, old-assert)."""

    def test_patch_and_roundtrip(self):
        base = _fs3_fixture()
        out, zones = build_l34.patch_vpi(base)
        img = mlxfwutil.Image(out, "out")
        assert out[FIX_VPI_OFF] == 0x07
        assert base[FIX_VPI_OFF] == 0x0A
        assert not mlxfwutil.verify_image(img, deep=True)
        diffs = _diffs(out, base)
        assert diffs <= zones
        assert FIX_VPI_OFF in diffs
        eo = _entry_abs_off(mlxfwutil.Image(base, "base"), 0x11)
        assert diffs & {eo + 0x1A, eo + 0x1B, eo + 0x1E, eo + 0x1F}

    def test_rejects_wrong_old_value(self):
        for bad in (0x07, 0x0B, 0x00):
            base = bytearray(_fs3_fixture())
            base[FIX_VPI_OFF] = bad
            with pytest.raises(AsmError):
                build_l34.patch_vpi(bytes(base))

    def test_rejects_reapply(self):
        base = _fs3_fixture()
        out, _ = build_l34.patch_vpi(base)
        with pytest.raises(AsmError):
            build_l34.patch_vpi(out)


class TestBuildV:
    """L3v = L3 + VPI byte + L3v marker; L4v = L4 + the same (ruling
    4dde8c3). Predecessor mask/slot state is asserted, not re-patched."""

    def test_l3v_from_l3(self):
        base = _fs3_fixture()
        l3 = build_l34.build_level(base, "L3", dc=FIX_DC,
                                   build_id=L3_ID).final
        res = build_l34.build_v_variant(l3, "L3v", dc=FIX_DC,
                                        build_id=L3V_ID)
        assert res.final[FIX_VPI_OFF] == 0x07
        assert not mlxfwutil.verify_image(
            mlxfwutil.Image(res.final, "l3v"), deep=True)
        lines = _ini_text(res.final).split("\n")
        assert L3V_ID in lines
        assert L3_ID not in lines
        assert lines.index(L3V_ID) == lines.index(
            ";; Mellanox Technologies LTD") + 1
        diffs = _diffs(res.final, l3)
        assert diffs <= res.zones
        assert FIX_VPI_OFF in diffs
        assert diffs & set(range(FIX_OFF_30, FIX_OFF_30 + FIX_SIZE_30))

    def test_l4v_from_l4(self):
        base = _fs3_fixture()
        l3 = build_l34.build_level(base, "L3", dc=FIX_DC,
                                   build_id=L3_ID).final
        l4 = build_l34.build_level(l3, "L4", dc=FIX_DC,
                                   build_id=L4_ID).final
        res = build_l34.build_v_variant(l4, "L4v", dc=FIX_DC,
                                        build_id=L4V_ID)
        assert res.final[FIX_VPI_OFF] == 0x07
        assert not mlxfwutil.verify_image(
            mlxfwutil.Image(res.final, "l4v"), deep=True)
        lines = _ini_text(res.final).split("\n")
        assert L4V_ID in lines
        assert L4_ID not in lines
        assert _diffs(res.final, l4) <= res.zones

    def test_rejects_stock_mask_base(self):
        base = _fs3_fixture()
        with pytest.raises(AsmError):
            build_l34.build_v_variant(base, "L3v", dc=FIX_DC,
                                      build_id=L3V_ID)

    def test_rejects_wrong_predecessor_level(self):
        base = _fs3_fixture()
        l3 = build_l34.build_level(base, "L3", dc=FIX_DC,
                                   build_id=L3_ID).final
        with pytest.raises(AsmError):
            build_l34.build_v_variant(l3, "L4v", dc=FIX_DC,
                                      build_id=L4V_ID)

    def test_rejects_unknown_level(self):
        base = _fs3_fixture()
        with pytest.raises(AsmError):
            build_l34.build_v_variant(base, "L2v", dc=FIX_DC,
                                      build_id=L3V_ID)

    def test_rejects_missing_build_id(self):
        base = _fs3_fixture()
        l3 = build_l34.build_level(base, "L3", dc=FIX_DC,
                                   build_id=L3_ID).final
        with pytest.raises(AsmError):
            build_l34.build_v_variant(l3, "L3v", dc=FIX_DC)

    def test_rejects_vpi_already_swapped(self):
        base = _fs3_fixture()
        l3 = build_l34.build_level(base, "L3", dc=FIX_DC,
                                   build_id=L3_ID).final
        l3v = build_l34.build_v_variant(l3, "L3v", dc=FIX_DC,
                                        build_id=L3V_ID).final
        with pytest.raises(AsmError):
            build_l34.build_v_variant(l3v, "L3v", dc=FIX_DC,
                                      build_id=L3V_ID)


class TestBuildLevel:

    def test_l3_zones_cover_diff(self):
        base = _fs3_fixture()
        res = build_l34.build_level(base, "L3", dc=FIX_DC, build_id=L3_ID)
        diffs = _diffs(res.final, base)
        assert diffs <= res.zones
        assert FIX_OFF_03 + 9 * 68 + 0x14 in diffs
        assert FIX_OFF_0A + 0x547F in diffs

    def test_l4_requires_l3_lineage(self):
        base = _fs3_fixture()
        with pytest.raises(AsmError):
            build_l34.build_level(base, "L4", dc=FIX_DC, build_id=L4_ID)

    def test_l3_rejects_reapply(self):
        base = _fs3_fixture()
        res = build_l34.build_level(base, "L3", dc=FIX_DC, build_id=L3_ID)
        with pytest.raises(AsmError):
            build_l34.build_level(res.final, "L3", dc=FIX_DC, build_id=L3_ID)

    def test_l4_keeps_slot_patched(self):
        base = _fs3_fixture()
        l3 = build_l34.build_level(base, "L3", dc=FIX_DC,
                                   build_id=L3_ID).final
        l4 = build_l34.build_level(l3, "L4", dc=FIX_DC, build_id=L4_ID).final
        assert l4[FIX_OFF_0A + 0x547F] == 0
        assert not mlxfwutil.verify_image(mlxfwutil.Image(l4, "l4"), deep=True)


@pytest.mark.slow
class TestRealImageL2:

    def test_real_l2_ladder(self):
        if not IMG_L2.exists():
            pytest.skip("img-L2.bin not built (run task-01 builder)")
        import hashlib
        base = IMG_L2.read_bytes()
        if hashlib.md5(base).hexdigest() != IMG_L2_MD5:
            pytest.skip("img-L2.bin md5 drift (lineage broken)")
        bid3 = build_l34.default_build_id("L3", "2026-11-12", IMG_L2_MD5,
                                          0x37F258)
        res = build_l34.build_level(base, "L3", build_id=bid3)
        img = mlxfwutil.Image(res.final, "l3")
        assert not mlxfwutil.verify_image(img, deep=True)
        assert res.final[0x37F258:0x37F25C] == build_l34.MASK_WORDS["L3"]
        assert res.final[0x13D47F] == 0
        assert _diffs(res.final, base) <= res.zones
        assert "mlxini serdes-arc-d L3-4xFDR" in _ini_text(res.final)
        assert "serdes-arc-d L2 100GbE" not in _ini_text(res.final)
        md5_l3 = hashlib.md5(res.final).hexdigest()
        bid4 = build_l34.default_build_id("L4", "2026-11-12", md5_l3,
                                          0x37F258)
        l4 = build_l34.build_level(res.final, "L4", build_id=bid4).final
        img4 = mlxfwutil.Image(l4, "l4")
        assert not mlxfwutil.verify_image(img4, deep=True)
        assert l4[0x37F25B] == 0x3F
        assert l4[0x13D47F] == 0
        assert "mlxini serdes-arc-d L4-4xEDR" in _ini_text(l4)
        assert "L3-4xFDR" not in _ini_text(l4)

    def test_real_l3_vpi_variant(self):
        img_l3 = REPO / "build" / "serdes-arc-d" / "img-L3.bin"
        img_l3_md5 = "561f9a73820d1e5de8c74325140a633c"
        if not img_l3.exists():
            pytest.skip("img-L3.bin not built (run task-03 builder)")
        import hashlib
        base = img_l3.read_bytes()
        if hashlib.md5(base).hexdigest() != img_l3_md5:
            pytest.skip("img-L3.bin md5 drift (lineage broken)")
        bid = build_l34.default_build_id("L3v", "2026-11-12", img_l3_md5,
                                         0x37F258)
        res = build_l34.build_v_variant(base, "L3v", build_id=bid)
        img = mlxfwutil.Image(res.final, "l3v")
        assert not mlxfwutil.verify_image(img, deep=True)
        assert res.final[build_l34.VPI_ABS] == 0x07
        assert res.final[0x37F258:0x37F25C] == build_l34.MASK_WORDS["L3"]
        assert res.final[0x13D47F] == 0
        assert _diffs(res.final, base) <= res.zones
        text = _ini_text(res.final)
        assert "mlxini serdes-arc-d L3v-4xFDR-IB" in text
        assert "serdes-arc-d L3-4xFDR" not in text


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
