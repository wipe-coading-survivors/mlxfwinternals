"""serdes-arc-d task-02 tests: ibmask_hunt on synthetic anchor fixtures.

Golden anchors (docs + corpus-verified, journal
docs/superpowers/journal/2026-11-12-serdes-arc-d-task-02.md):
  * cx4lx 14.32.1900 GCA: shr site dc 0x1f1f00 word fcb1c083, stock
    force `0011001f` (addi r17,zero,0x1f) at dc 0x1f1f38;
  * cx4lx 14.32.1912 GCA: shr site dc 0x1f2054 word fcb1c083, force
    at dc 0x1f208c;
  * Rosetta self-check: the tight pattern re-derives the documented
    4030 (dc 0x25a3e8, force @0x25a424) and 8008 (dc 0x25ab54, force
    @0x25ab90) sites from doc 025 §7;
  * raw offsets: dc 0x1f1f00 -> image 0x37e0f0 (flash_addr 1495040,
    = the c1 raw offset from cx4lx-sfp28-ib-node-final §3);
    dc 0x1f2054 -> 0x37f258 (flash_addr 1499136).
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-arc-d"))

import ibmask_hunt as ibh  # noqa: E402

CORPUS_1900 = (REPO / "build" / "corpus" / "cx4lx" / "14_32_1900" /
               "MCX4131A-GCA" / "sections" / "03")
CORPUS_1912 = (REPO / "build" / "corpus" / "cx4lx" / "14_32_1912" /
               "MCX4131A-GCA" / "sections" / "03")
IMG_1900 = (REPO / "refs" / "fw" / "cx-4" /
            "fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-"
            "FlexBoot-3.6.502.bin")
IMG_1912 = (REPO / "refs" / "fw" / "cx-4" /
            "fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-"
            "FlexBoot-3.6.502.bin")


def synth_site_lines(shr_rt, force_off=14, mask_reg="r17"):
    ld = f"{shr_rt - 4:08x}  6425004e  ld.d r5,r1,0x4c"
    shr = f"{shr_rt:08x}  fcb1c083  shr {mask_reg},r5,0x18"
    lines = [ld, shr]
    for i in range(force_off - 1):
        lines.append(f"{shr_rt + 4 * (i + 1):08x}  00000000  "
                     f"addi zero,zero,0x0")
    lines.append(f"{shr_rt + 4 * force_off:08x}  0011001f  "
                 f"addi {mask_reg},zero,0x1f")
    return lines


class TestFindStampSite:

    def test_synthetic_anchor_found(self):
        instrs = ibh.parse_disasm_lines(synth_site_lines(0x009f1f00))
        sites = ibh.find_stamp_site(instrs)
        assert len(sites) == 1
        s = sites[0]
        assert s["shr_addr_rt"] == 0x009F1F00
        assert s["shr_word"] == "fcb1c083"
        assert s["mask_reg"] == "r17"
        assert s["force"]["imm"] == 0x1F
        assert s["force"]["word"] == "0011001f"

    def test_no_site_negative(self):
        lines = [f"{0x009f1f00:08x}  6c20b80e  st.d r23,r1,0xc"]
        assert ibh.find_stamp_site(ibh.parse_disasm_lines(lines)) == []

    def test_ld_without_shr_is_not_a_site(self):
        lines = [f"{0x009f1f00:08x}  6425004e  ld.d r5,r1,0x4c",
                 f"{0x009f1f04:08x}  00000000  addi zero,zero,0x0"]
        assert ibh.find_stamp_site(ibh.parse_disasm_lines(lines)) == []

    def test_clobbered_mask_reg_blocks_force(self):
        lines = synth_site_lines(0x009f1f00)
        lines.insert(2, f"{0x009f1f04:08x}  fe85a008  or r17,r5,r5")
        sites = ibh.find_stamp_site(ibh.parse_disasm_lines(lines))
        assert len(sites) == 1
        assert sites[0]["force"] is None

    def test_alternate_register_and_field_0x44(self):
        lines = [
            "00a50000  64250046  ld.d r5,r3,0x44",
            "00a50004  fcb1c083  shr r9,r5,0x18",
            "00a50008  00000000  addi zero,zero,0x0",
            "00a5000c  0009001f  addi r9,zero,0x1f",
        ]
        sites = ibh.find_stamp_site(ibh.parse_disasm_lines(lines))
        assert len(sites) == 1
        assert sites[0]["mask_reg"] == "r9"
        assert sites[0]["force"]["imm"] == 0x1F


class TestAddiForceWord:

    def test_stock_force_encoding(self):
        assert ibh.addi_force_word(17, 0x1F) == "0011001f"

    def test_l3_l4_patch_words(self):
        assert ibh.addi_force_word(17, ibh.MASKS["L3_4xFDR"]) == "0011001f"
        assert ibh.addi_force_word(17, ibh.MASKS["L4_4xEDR"]) == "0011003f"

    def test_imm_range_guard(self):
        with pytest.raises(ValueError):
            ibh.addi_force_word(17, 0x10000)


class TestRawImageOffset:

    def test_1900_anchor_matches_c1_precedent(self):
        assert ibh.raw_image_offset(0x1F1F00, 1495040) == 0x37E0F0

    def test_1912_anchor(self):
        assert ibh.raw_image_offset(0x1F2054, 1499136) == 0x37F258

    def test_line_framing_math(self):
        assert ibh.raw_image_offset(0, 0) == 0
        assert ibh.raw_image_offset(64, 0) == 68
        assert ibh.raw_image_offset(65, 0) == 69

    def test_negative_rejected(self):
        with pytest.raises(ValueError):
            ibh.raw_image_offset(-1, 0)


class TestBitMap:

    def test_map_covers_plan_speeds(self):
        names = set(ibh.BIT_MAP.values())
        assert {"QDR", "FDR10", "FDR", "EDR"} <= names

    def test_l4_is_l3_plus_edr_bit(self):
        assert ibh.MASKS["L4_4xEDR"] == ibh.MASKS["L3_4xFDR"] | 0x20


@pytest.mark.parametrize("section_dir,image,flash_addr,dc,raw", [
    pytest.param(CORPUS_1900, IMG_1900, None, 0x1F1F00, 0x37E0F0,
                 id="1900-gca"),
    pytest.param(CORPUS_1912, IMG_1912, None, 0x1F2054, 0x37F258,
                 id="1912-gca"),
])
def test_corpus_golden(section_dir, image, flash_addr, dc, raw):
    if not section_dir.exists():
        pytest.skip("arc-A corpus not built (make corpus)")
    if not image.exists():
        pytest.skip(f"stock image missing: {image.name}")
    report = ibh.hunt(str(section_dir), image=str(image),
                      flash_addr=flash_addr)
    golden = [s for s in report["sites"] if s["shr_word"] == "fcb1c083"]
    assert len(golden) == 1
    s = golden[0]
    assert s["shr_addr_dc"] == dc
    assert s["shr_word"] == "fcb1c083"
    assert s["force"] is not None
    assert s["force"]["imm"] == 0x1F
    assert s["patch_words"]["L3_4xFDR"] == "0011001f"
    assert s["patch_words"]["L4_4xEDR"] == "0011003f"
    assert s["raw_image_offset"] == raw
    assert s["image_word_at_offset"] == "fcb1c083"
    roles = [c.get("role") for c in s["chain"]["chain"]]
    assert roles[0] == "apply_stamping_ib"
    assert roles[1] == "set_pm_speed_and_width"
