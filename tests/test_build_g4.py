"""serdes-arc-d task-06 tests: Gen4 builder (D2-S1 raw / D2-S2 adapted).

Golden pins (journal docs/superpowers/journal/
2026-11-12-serdes-arc-d-task-06.md Step 0/1):
  * P2a bytes on the GCA-1912 base (re-verified, ACA-derived pins hold):
    0x08+0x23 = 0x87 -> 0x8f, 0x11+0x8b = 0x43 -> 0x47 (doc 130 §3/§5.1);
  * schedule table @0x08+0xf0 (BE16, Lx 14 entries / CX-5 16 entries,
    doc 130 §10.3); the 0x11 copy is a FULL-table copy at a layout-dependent
    offset: Lx-14.32 +0x94 (re-derived — the doc's "+0x9e" is the 16.35
    entry[1] anchor of the full table @+0x9c);
  * 0x0C PCIE_PHY_UC_CODE: Lx 2560 B md5 2a2be17b…, CX-5 7808 B md5
    a2c3dc94… == 8008-ACA == 8008-ADA == 1012-ACA == 1012-ADA (doc 130 §5.3);
  * operand adaptation (design §3 D2-S2): per-op mapping derived from the
    0x0A/0x0C common-(b,c) differential — the real Lx<->CX-5 pair yields an
    EMPTY mapping (the only per-ASIC operand patches, 0x0A 17 B / 5 keys, are
    never referenced by any 0x0C record) -> payload written as-is;
  * G4c tuning value: underivable (per-SerDes-variant ratios ×1.09/×1.28/×1.41,
    no MT27710 Gen4 reference) -> variant skipped, no image, no patch code;
  * resize zones (T5 machinery): ITOC row re-enumeration block + old data
    erase (0xFF) + new tail-placement data region; outside-region identity.
"""
import hashlib
import struct
import sys
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-arc-d"))

try:
    import build_g4  # noqa: E402
except FileNotFoundError:
    pytest.skip("hardware.local.md hw registry not present",
                allow_module_level=True)

import mlxfwutil  # noqa: E402
from mlxfwutil import CNTX_MAGIC, ITOC_HDR, crc16_mlx, set_bits  # noqa: E402

GCA1912 = REPO / "refs" / "fw" / "cx-4" / (
    "fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")
CX5_DIR = REPO / "build" / "corpus" / "cx5" / "16_35_1012" / "MCX512A-ADA"

LX_TABLE = bytes.fromhex("0654064006710655068f0672068f0690068f0690068f069006df0690")
CX5_TABLE = bytes.fromhex("065406400671065506c006a306e606c10797074e07b107980827"
                          "07b206a20672")
G4A_ID = ("; mlxini serdes-arc-d G4a-raw (2026-11-13, fixture): p2a + 0x0C as-is")
G4B_ID = ("; mlxini serdes-arc-d G4b-adapted (2026-11-13, fixture): "
          "+ schedule sync")

FIX_OFF_08 = 0x4000
FIX_OFF_11 = 0x5000
FIX_OFF_0C = 0x6000
FIX_SIZE_0C = 0xA00
FIX_OFF_A0 = 0xA000
FIX_OFF_30 = 0xB000
FIX_SIZE_30 = 0x400
FIX_OFF_E1 = 0x13000
FIX_OFF_E0 = 0x13100

FIX_INI = "\n".join([
    ";; Generated automatically by iniprep tool",
    "",
    ";; Mellanox Technologies LTD",
    "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed25Gb = 0x1",
])


def _toc_hdr(nent):
    h = bytearray(32)
    h[0:16] = ITOC_HDR
    set_bits(h, 184, 8, nent)
    set_bits(h, 240, 16, crc16_mlx(bytes(h[:28])))
    return bytes(h)


def _toc_ent(t, size, addr, sec_crc, rel=1, dev=0):
    r = bytearray(32)
    set_bits(r, 0, 8, t)
    set_bits(r, 8, 22, size // 4)
    set_bits(r, 161, 29, addr // 4)
    set_bits(r, 160, 1, rel)
    set_bits(r, 206, 1, dev)
    set_bits(r, 208, 16, sec_crc)
    set_bits(r, 240, 16, crc16_mlx(bytes(r[:28])))
    return bytes(r)


def _sec08_data(table=LX_TABLE):
    d = bytearray(0x140)
    for i in range(len(d)):
        d[i] = (i * 5 + 1) & 0xFF
    d[0x23] = 0x87
    d[0xE8:0xF0] = b"\x00" * 8
    d[0xF0:0xF0 + len(table)] = table
    d[0xF0 + len(table):0x118] = b"\x00" * (0x118 - 0xF0 - len(table))
    return bytes(d)


def _sec11_data(table=LX_TABLE, copy_off=0x94):
    d = bytearray(0x4C0)
    for i in range(len(d)):
        d[i] = (i * 11 + 5) & 0xFF
    d[0x8B] = 0x43
    d[0x8C:copy_off] = b"\x00" * (copy_off - 0x8C)
    d[copy_off:copy_off + len(table)] = table
    d[copy_off + len(table):copy_off + len(table) + 8] = b"\x00" * 8
    return bytes(d)


def _sec0c_data():
    d = bytearray(FIX_SIZE_0C)
    for i in range(0, len(d), 16):
        d[i + 6:i + 16] = struct.pack(">5H", 0x6005, 0x27, 0x39CC, 0x100, 1)
    return bytes(d)


def _fs3_fixture(sec08=None, sec11=None, sec0c=None):
    sec08 = sec08 or _sec08_data()
    sec11 = sec11 or _sec11_data()
    sec0c = sec0c or _sec0c_data()
    sig = bytearray(0x40)
    sig[0x20:0x40] = b"\x22" * 32
    dev = bytes(0x40)
    ini30 = zlib.compress(FIX_INI.encode("latin1"), 9)
    ini30 += b"\x00" * (FIX_SIZE_30 - len(ini30))
    ents = [
        _toc_ent(0x08, len(sec08), FIX_OFF_08, crc16_mlx(sec08)),
        _toc_ent(0x11, len(sec11), FIX_OFF_11, crc16_mlx(sec11)),
        _toc_ent(0x0C, len(sec0c), FIX_OFF_0C, crc16_mlx(sec0c)),
        _toc_ent(0xA0, 0x40, FIX_OFF_A0, crc16_mlx(bytes(sig))),
        _toc_ent(0x30, FIX_SIZE_30, FIX_OFF_30, crc16_mlx(ini30)),
        _toc_ent(0xE1, 0x40, FIX_OFF_E1, crc16_mlx(dev), rel=0, dev=1),
        _toc_ent(0xE0, 0x40, FIX_OFF_E0, crc16_mlx(dev), rel=0, dev=1),
        _toc_ent(0xFF, 0, 0, 0),
    ]
    buf = bytearray(b"\xff" * 0x14000)
    buf[0:16] = CNTX_MAGIC
    buf[0x24] = 3
    buf[0x1000:0x1020] = _toc_hdr(len(ents) - 1)
    for i, ent in enumerate(ents):
        buf[0x1020 + i * 32:0x1040 + i * 32] = ent
    for off, d in ((FIX_OFF_08, sec08), (FIX_OFF_11, sec11),
                   (FIX_OFF_0C, sec0c), (FIX_OFF_A0, bytes(sig)),
                   (FIX_OFF_30, ini30), (FIX_OFF_E1, dev), (FIX_OFF_E0, dev)):
        buf[off:off + len(d)] = d
    return bytes(buf)


def _grow_payload(n_slots=488):
    d = bytearray(n_slots * 16)
    for i in range(n_slots):
        d[i * 16 + 6:i * 16 + 16] = struct.pack(
            ">5H", 0x60B3, 0x20, 0x49CC, 0xC0, 0x19)
    return bytes(d)


def _diffs(new, old):
    return {i for i in range(min(len(new), len(old))) if new[i] != old[i]}


def _ini_text(buf):
    img = mlxfwutil.Image(buf, "r")
    data = mlxfwutil.extract_section(img, 0x30)
    return zlib.decompress(data).decode("latin1")


class TestScheduleResolver:
    """resolve_schedule: version-aware (Lx-14.32 vs 16.35 layouts)."""

    def test_lx_layout_full_table_copy_at_0x94(self):
        lay = build_g4.resolve_schedule(_sec08_data(), _sec11_data())
        assert lay.table_off == 0xF0
        assert lay.n_entries == 14
        assert lay.copy_off == 0x94

    def test_cx5_layout_16_entries_copy_at_0x9c(self):
        sec08 = _sec08_data(table=CX5_TABLE)
        sec11 = _sec11_data(table=CX5_TABLE, copy_off=0x9C)
        lay = build_g4.resolve_schedule(sec08, sec11)
        assert lay.n_entries == 16
        assert lay.copy_off == 0x9C

    def test_table_bytes_roundtrip(self):
        lay = build_g4.resolve_schedule(_sec08_data(), _sec11_data())
        sec08 = _sec08_data()
        assert build_g4.table_bytes(sec08, lay) == LX_TABLE

    def test_rejects_missing_copy(self):
        sec11 = bytearray(_sec11_data())
        sec11[0x94:0x94 + len(LX_TABLE)] = b"\x00" * len(LX_TABLE)
        with pytest.raises(build_g4.G4Error):
            build_g4.resolve_schedule(_sec08_data(), bytes(sec11))

    def test_rejects_short_table(self):
        sec08 = bytearray(_sec08_data())
        sec08[0xFA:0x110] = b"\x00" * (0x110 - 0xFA)
        with pytest.raises(build_g4.G4Error):
            build_g4.resolve_schedule(bytes(sec08), _sec11_data())

    @pytest.mark.skipif(not GCA1912.exists(), reason="no GCA-1912 stock")
    def test_real_gca1912_pins(self):
        buf = GCA1912.read_bytes()
        img = mlxfwutil.Image(buf, "r")
        lay = build_g4.resolve_schedule(
            img.section_data(img.find_entry("ITOC", 0x08)),
            img.section_data(img.find_entry("ITOC", 0x11)))
        assert (lay.table_off, lay.n_entries, lay.copy_off) == (0xF0, 14, 0x94)
        assert build_g4.table_bytes(
            img.section_data(img.find_entry("ITOC", 0x08)), lay) == LX_TABLE

    @pytest.mark.skipif(not (CX5_DIR / "sections" / "08" / "raw.bin").exists(),
                        reason="no CX-5 corpus dump")
    def test_real_cx5_1012_pins(self):
        sec08 = (CX5_DIR / "sections" / "08" / "raw.bin").read_bytes()
        sec11 = (CX5_DIR / "sections" / "11" / "raw.bin").read_bytes()
        lay = build_g4.resolve_schedule(sec08, sec11)
        assert (lay.n_entries, lay.copy_off) == (16, 0x9C)
        assert build_g4.table_bytes(sec08, lay) == CX5_TABLE


def _slot(op, a, b, c, d):
    rec = bytearray(16)
    rec[6:16] = struct.pack(">5H", op, a, b, c, d)
    return bytes(rec)


class TestOperandAdaptation:
    """derive/apply: deterministic; real pair -> identity (empty mapping)."""

    def test_deterministic_and_flavor_level(self):
        lx_0a = (_slot(0x6173, 0x28, 0x49CC, 0xC0, 1)
                 + _slot(0x6173, 0x8, 0x49CC, 0xC0, 0)
                 + _slot(0x6005, 9, 0x39CC, 0x100, 5))
        cx_0a = (_slot(0x6173, 0x20, 0x49CC, 0xC0, 1)
                 + _slot(0x6173, 0x8, 0x49CC, 0xC0, 0)
                 + _slot(0x6005, 9, 0x39CC, 0x100, 5))
        lx_0c = _slot(0x6005, 9, 0x39CC, 0x100, 5)
        cx_0c = (_slot(0x6173, 0x20, 0x49CC, 0xC0, 1)
                 + _slot(0x6173, 0x8, 0x49CC, 0xC0, 0x6)
                 + _slot(0x4000, 0x64, 0, 0, 0)
                 + _slot(0x6005, 9, 0x39CC, 0x100, 5))
        m1 = build_g4.derive_operand_adaptation(lx_0a, lx_0c, cx_0a, cx_0c)
        m2 = build_g4.derive_operand_adaptation(lx_0a, lx_0c, cx_0a, cx_0c)
        assert m1 == m2
        assert list(m1) == sorted(m1)
        assert m1 == {(0x6173, 0x49CC, 0xC0, 0x20): 0x28}

    def test_common_flavor_not_mapped(self):
        lx_0a = (_slot(0x6173, 0x28, 0x49CC, 0xC0, 1)
                 + _slot(0x6173, 0x8, 0x49CC, 0xC0, 0))
        cx_0a = (_slot(0x6173, 0x20, 0x49CC, 0xC0, 1)
                 + _slot(0x6173, 0x8, 0x49CC, 0xC0, 0))
        lx_0c = _slot(0x6005, 9, 0x39CC, 0x100, 5)
        cx_0c = _slot(0x6173, 0x8, 0x49CC, 0xC0, 0x6)
        assert build_g4.derive_operand_adaptation(lx_0a, lx_0c, cx_0a, cx_0c) == {}

    def test_apply_rewrites_mapped_flavor_only(self):
        payload = (_slot(0x6173, 0x20, 0x49CC, 0xC0, 1)
                   + _slot(0x6173, 0x8, 0x49CC, 0xC0, 0x6)
                   + _slot(0x6005, 9, 0x39CC, 0x100, 5))
        mapping = {(0x6173, 0x49CC, 0xC0, 0x20): 0x28}
        out = build_g4.apply_operand_adaptation(payload, mapping)
        assert out[6:16] == struct.pack(">5H", 0x6173, 0x28, 0x49CC, 0xC0, 1)
        assert out[16 + 6:16 + 16] == payload[16 + 6:16 + 16]
        assert out[32 + 6:32 + 16] == payload[32 + 6:32 + 16]

    def test_identity_on_empty_mapping(self):
        payload = _grow_payload(3)
        assert build_g4.apply_operand_adaptation(payload, {}) == payload

    def test_unreferenced_rename_not_mapped(self):
        lx_0a = _slot(0x6173, 0x28, 0x49CC, 0xC0, 1)
        cx_0a = _slot(0x6173, 0x20, 0x49CC, 0xC0, 1)
        lx_0c = _slot(0x6005, 9, 0x39CC, 0x100, 5)
        cx_0c = _slot(0x6005, 9, 0x39CC, 0x100, 5)
        assert build_g4.derive_operand_adaptation(lx_0a, lx_0c, cx_0a, cx_0c) == {}

    @pytest.mark.skipif(not (CX5_DIR / "sections" / "0C" / "raw.bin").exists()
                        or not GCA1912.exists(), reason="no real pair")
    def test_real_pair_identity(self):
        buf = GCA1912.read_bytes()
        img = mlxfwutil.Image(buf, "r")
        lx_0a = img.section_data(img.find_entry("ITOC", 0x0A))
        lx_0c = img.section_data(img.find_entry("ITOC", 0x0C))
        cx_0c = (CX5_DIR / "sections" / "0C" / "raw.bin").read_bytes()
        cx_0a = (CX5_DIR / "sections" / "0A" / "raw.bin").read_bytes()
        mapping = build_g4.derive_operand_adaptation(lx_0a, lx_0c, cx_0a, cx_0c)
        assert mapping == {}
        assert build_g4.apply_operand_adaptation(cx_0c, mapping) == cx_0c


class TestPairFamiliarity:

    def test_classification_counts(self):
        lx_0a = (_slot(0x6173, 0x28, 0x49CC, 0xC0, 1)
                 + _slot(0x6005, 9, 0x39CC, 0x100, 5))
        lx_0c = _slot(0x6005, 9, 0x39CC, 0x100, 5)
        cx_0c = (_slot(0x6005, 9, 0x39CC, 0x100, 5)
                 + _slot(0x60B3, 1, 0x39CC, 0x480, 2)
                 + _slot(0x60B3, 1, 0x5566, 0x10, 3))
        rep = build_g4.pair_familiarity(cx_0c, lx_0a, lx_0c)
        assert rep["wr_pairs"] == 3
        assert rep["familiar"] == 1
        assert rep["same_bank_new_offset"] == [(0x39CC, 0x480)]
        assert rep["unknown_banks"] == [0x5566]

    @pytest.mark.skipif(not (CX5_DIR / "sections" / "0C" / "raw.bin").exists()
                        or not GCA1912.exists(), reason="no real pair")
    def test_real_pair_no_unknown_banks(self):
        buf = GCA1912.read_bytes()
        img = mlxfwutil.Image(buf, "r")
        lx_0a = img.section_data(img.find_entry("ITOC", 0x0A))
        lx_0c = img.section_data(img.find_entry("ITOC", 0x0C))
        cx_0c = (CX5_DIR / "sections" / "0C" / "raw.bin").read_bytes()
        rep = build_g4.pair_familiarity(cx_0c, lx_0a, lx_0c)
        assert rep["wr_pairs"] == 74
        assert rep["familiar"] == 42
        assert rep["unknown_banks"] == []


class TestBuildImage:

    def test_g4a_raw_patches_p2a_and_0c_only(self):
        base = _fs3_fixture()
        payload = _grow_payload(8)
        res = build_g4.build_image(base, payload, sync_schedule=False,
                                   build_id=G4A_ID)
        img = mlxfwutil.Image(res.final, "r")
        assert img.find_entry("ITOC", 0x0C).size == len(payload)
        assert img.section_data(img.find_entry("ITOC", 0x0C)) == payload
        assert res.final[FIX_OFF_08 + 0x23] == 0x8F
        assert res.final[FIX_OFF_11 + 0x8B] == 0x47
        assert res.final[FIX_OFF_08 + 0xF0:FIX_OFF_08 + 0xF0 + 28] == LX_TABLE
        assert res.final[FIX_OFF_11 + 0x94:FIX_OFF_11 + 0x94 + 28] == LX_TABLE
        assert G4A_ID in _ini_text(res.final)

    def test_g4b_syncs_schedule_both_copies(self):
        base = _fs3_fixture()
        payload = _grow_payload(8)
        res = build_g4.build_image(base, payload, sync_schedule=True,
                                   cx5_table=CX5_TABLE, build_id=G4B_ID)
        assert res.final[FIX_OFF_08 + 0xF0:FIX_OFF_08 + 0xF0 + 32] == CX5_TABLE
        assert res.final[FIX_OFF_11 + 0x94:FIX_OFF_11 + 0x94 + 32] == CX5_TABLE
        assert G4B_ID in _ini_text(res.final)

    def test_g4b_requires_cx5_table(self):
        with pytest.raises(build_g4.G4Error):
            build_g4.build_image(_fs3_fixture(), _grow_payload(8),
                                 sync_schedule=True, build_id=G4B_ID)

    def test_zones_cover_every_diff_byte(self):
        base = _fs3_fixture()
        payload = _grow_payload(8)
        for sync, bid in ((False, G4A_ID), (True, G4B_ID)):
            res = build_g4.build_image(base, payload, sync_schedule=sync,
                                       cx5_table=CX5_TABLE, build_id=bid)
            for new, old, zones in ((res.step_resize, base, res.zones_resize),
                                    (res.step_content, res.step_resize,
                                     res.zones_content),
                                    (res.final, base, res.zones)):
                stray = _diffs(new, old) - zones
                assert not stray, f"sync={sync}: stray {sorted(stray)[:8]}"

    def test_resize_relocation_and_outside_identity(self):
        base = _fs3_fixture()
        payload = _grow_payload()
        img = mlxfwutil.Image(base, "r")
        e = img.find_entry("ITOC", 0x0C)
        old_abs = img.sec_abs(e)
        res = build_g4.build_image(base, payload, sync_schedule=False,
                                   build_id=G4A_ID)
        assert set(range(old_abs, old_abs + FIX_SIZE_0C)) <= res.zones_resize
        img2 = mlxfwutil.Image(res.step_resize, "r")
        e2 = img2.find_entry("ITOC", 0x0C)
        new_abs = img2.sec_abs(e2)
        assert new_abs > FIX_OFF_30
        assert set(range(new_abs, new_abs + len(payload))) <= res.zones_resize
        assert res.step_resize[old_abs:old_abs + FIX_SIZE_0C] == \
            b"\xFF" * FIX_SIZE_0C

    def test_verify_deep_and_burn_order_pass_each_step(self):
        base = _fs3_fixture()
        payload = _grow_payload(8)
        res = build_g4.build_image(base, payload, sync_schedule=True,
                                   cx5_table=CX5_TABLE, build_id=G4B_ID)
        for buf in (res.step_resize, res.step_content, res.final):
            img = mlxfwutil.Image(buf, "r")
            assert mlxfwutil.verify_image(img, deep=True) == []
            assert mlxfwutil.burn_order_check(img) == []

    def test_rejects_non_pristine_p2a(self):
        bad = bytearray(_fs3_fixture())
        bad[FIX_OFF_08 + 0x23] = 0x8F
        with pytest.raises(build_g4.G4Error):
            build_g4.build_image(bytes(bad), _grow_payload(8),
                                 sync_schedule=False, build_id=G4A_ID)

    def test_rejects_wrong_0c_md5(self):
        base = _fs3_fixture()
        with pytest.raises(build_g4.G4Error):
            build_g4.build_image(base, _grow_payload(8), sync_schedule=False,
                                 build_id=G4A_ID,
                                 expect_0c_md5="0" * 32)

    def test_rejects_non_dw_payload(self):
        with pytest.raises(build_g4.G4Error):
            build_g4.build_image(_fs3_fixture(), b"\x00" * 33,
                                 sync_schedule=False, build_id=G4A_ID)

    @pytest.mark.skipif(not GCA1912.exists()
                        or not (CX5_DIR / "sections" / "0C" / "raw.bin").exists(),
                        reason="no real base/payload")
    def test_real_gca_build_gates(self):
        base = GCA1912.read_bytes()
        payload = (CX5_DIR / "sections" / "0C" / "raw.bin").read_bytes()
        sec08 = (CX5_DIR / "sections" / "08" / "raw.bin").read_bytes()
        sec11 = (CX5_DIR / "sections" / "11" / "raw.bin").read_bytes()
        lay = build_g4.resolve_schedule(sec08, sec11)
        cx5_table = build_g4.table_bytes(sec08, lay)
        for sync, bid in ((False, G4A_ID), (True, G4B_ID)):
            res = build_g4.build_image(
                base, payload, sync_schedule=sync, cx5_table=cx5_table,
                build_id=bid, expect_0c_md5=build_g4.LX_0C_MD5)
            img = mlxfwutil.Image(res.final, "r")
            assert mlxfwutil.verify_image(img, deep=True) == []
            assert mlxfwutil.burn_order_check(img) == []
            assert img.section_data(
                img.find_entry("ITOC", 0x0C)) == payload
            stray = _diffs(res.final, base) - res.zones
            assert not stray, f"sync={sync}: stray {sorted(stray)[:8]}"
