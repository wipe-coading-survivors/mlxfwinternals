"""cx4lx-fdr-gate tests: loader_reverse (arc F / F2).

Golden anchors (journal
docs/superpowers/journal/2026-11-23-serdes-arc-f-task-01.md):

  * The parsed INI table is served over keyed mailboxes (banks 0xd6c80 /
    0x11c480 Lx, 0x11c880 CX-4); the ONLY image-code emitters of the bank
    constants are the mailbox-client helpers (MAIN_CODE 0xa0bef8 and its
    POST_IRON_BOOT twin) -- no server exists in the image.
  * POST_IRON_BOOT (section 06, entry rt 0x740254 in 14.32.1912-GCA) is
    the table loader: zero-init of 0x1000 words through bank A, then
    record fill from flash via the csr 0x101/0x100 engine (data window
    0xf410, handshake RAM word 0xc100 bit 30), header in RAM words
    0x38f0..0x38f4 (no image-code writer -> ROM/hw staged).
  * Loader region remap thresholds 0x27, 0x2c7 .. 0x2f67 (stride 0x2a0);
    identical chain in the CX-4 12.28 section 06.
  * Getter (MAIN_CODE 0xa0bfb8) field math: word = param>>7,
    field = (param>>5)&3, bit offset = field*20 + (31 - param&0x1f);
    0x776 -> word 14, field 3, offset 69.
  * Special path (event dispatcher) polarity per iRISC.slaspec cc table:
    Lx 0x9be0f4: event==0 OR event > bits[9..11](mirror);
    CX-4 0x9979cc: event==0 OR event >= 3.
  * Corpus class map: 0x12 dword@+0x280 / dword@+0x2c4 and 0x11 byte
    +0x35 extend the speed-class taxonomy (ECA vs 416A vs 40/56G Lx).
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "probes" / "cx4lx-fdr-gate"))

import loader_reverse as lr  # noqa: E402

CORPUS = REPO / "build" / "corpus"
LX_GCA_06 = CORPUS / "cx4lx/14_32_1912/MCX4131A-GCA/sections/06"
CX4_ECA_06 = CORPUS / "cx4/12_28_4706/MCX456A-ECA/sections/06"


def sec06(build):
    d = CORPUS / build
    if not (d / "disasm.txt").exists():
        pytest.skip("corpus section 06 absent: %s" % build)
    return d


# ---------------------------------------------------------------- param math

def test_param_word_field_offset_776():
    assert lr.param_word(0x776) == 14
    assert lr.param_field(0x776) == 3
    assert lr.param_bit_offset(0x776) == 3 * 20 + (31 - 0x16)


def test_param_bit_offset_components():
    # field x20 stride; sub-offset = 31 - low5 (inverted 5-bit)
    assert lr.param_bit_offset(0x60C) == lr.param_field(0x60C) * 20 + (
        31 - (0x60C & 0x1F))
    for p in (0x2EC, 0x28C, 0x36C, 0x40C, 0x2B6, 0x2AC, 0x776, 0x60C):
        w, f = lr.param_word(p), lr.param_field(p)
        assert 0 <= f <= 3
        off = lr.param_bit_offset(p)
        assert f * 20 <= off < f * 20 + 32


# ------------------------------------------------------------- region remap

def test_region_thresholds_stride():
    assert lr.REGION_THRESHOLDS[0] == 0x27
    deltas = {b - a for a, b in zip(lr.REGION_THRESHOLDS,
                                    lr.REGION_THRESHOLDS[1:])}
    assert deltas == {0x2A0}
    assert len(lr.REGION_THRESHOLDS) == 19


def test_region_for_param():
    assert lr.region_for_param(0x00) == 0
    assert lr.region_for_param(0x26) == 0
    assert lr.region_for_param(0x27) == 1
    assert lr.region_for_param(0x2C6) == 1
    assert lr.region_for_param(0x2C7) == 2
    assert lr.region_for_param(0x776) == 3
    assert lr.region_for_param(0x2F67) == 19
    # remap formula of loader 0x740414: word' = region*0x2A0 - param
    assert lr.loader_word_remap(0x776) == 3 * 0x2A0 - 0x776


# ------------------------------------------------------ special-path polarity

def test_cc_slot_semantics_registry():
    # iRISC.slaspec cc table (canon); b.t.<slot> tests these formulas
    assert lr.CC_SLOTS[0x0] == "eq32"
    assert lr.CC_SLOTS[0x2] == "lt32"
    assert lr.CC_SLOTS[0x3] == "ugt32"
    assert lr.CC_SLOTS[0x4] == "ult32"


def test_special_path_lx():
    # Lx 0x9be0f4: subsi event-1 / b.t.0x2 -> event==0; then
    # subs event-field / b.f.0x3 skip when event<=field
    for ev in range(8):
        assert lr.special_path_lx(ev, field=3) == (ev == 0 or ev > 3)
    # field 2 reproduces CX-4 behavior bit-for-bit
    for ev in range(8):
        assert lr.special_path_lx(ev, field=2) == \
            lr.special_path_cx4(ev)
    assert lr.special_path_cx4(2) is False
    assert lr.special_path_cx4(3) is True
    assert lr.special_path_cx4(0x3F) is True


def test_mirror_field_extract():
    # mask32 rd,rs,0x9,3: 4th operand is the mask NUMBER n -> &((1<<n)-1)
    assert lr.mirror_field(1 << 9) == 1
    assert lr.mirror_field(1 << 11) == 4
    assert lr.mirror_field((5 << 9) | 0x1FF) == 5  # low bits don't leak


# ------------------------------------------------------- loader disasm scan

def test_scan_loader_lx_golden():
    rep = lr.scan_loader(sec06("cx4lx/14_32_1912/MCX4131A-GCA/sections/06"))
    assert rep["banks"] == {0xD6C80: 0x7402F4, 0x11C480: 0x740300}
    z = rep["zero_init"]
    assert z["site_subsi"] == 0x7403F8 and z["iterations"] == 0x1000
    assert z["bank_selector"] == 0  # zero-init goes to bank A only
    th = rep["region_thresholds"]
    assert th["first_site"] == 0x740528
    assert th["values"][:4] == [0x27, 0x2C7, 0x567, 0x807]
    assert rep["header_reads"] == [0x38F3, 0x38F4, 0x38F0, 0x38F1, 0x38F2]
    assert rep["header_base"] == 0x38F0
    assert rep["flash_window"] == 0xF0410
    assert rep["flash_handshake"] == 0xC100
    assert rep["mailbox_client"] == 0x7402EC
    assert rep["entry"] == 0x740254


def test_scan_loader_cx4_invariance():
    rep = lr.scan_loader(sec06("cx4/12_28_4706/MCX456A-ECA/sections/06"))
    # bank A conserved; bank B shifted +0x100 on CX-4 (0x11c880)
    assert 0xD6C80 in rep["banks"]
    assert 0x11C880 in rep["banks"]
    assert rep["zero_init"]["iterations"] == 0x1000
    assert rep["region_thresholds"]["values"] == list(lr.REGION_THRESHOLDS)
    # header block layout delta: CX-4 12.28 stages at 0x3a70..0x3a74
    assert rep["header_reads"] == [0x3A73, 0x3A74, 0x3A70, 0x3A71, 0x3A72]
    assert rep["header_base"] == 0x3A70
    assert rep["flash_window"] == 0xF0410


def test_scan_loader_rejects_main_code():
    # MAIN_CODE (section 03) has the client twin but none of the loader
    # parts (the table writer lives only in POST_IRON_BOOT)
    d = CORPUS / "cx4lx/14_32_1912/MCX4131A-GCA/sections/03"
    if not (d / "disasm.txt").exists():
        pytest.skip("corpus absent")
    rep = lr.scan_loader(d)
    assert rep["zero_init"] is None
    assert rep["region_thresholds"] is None
    assert rep["header_reads"] == []
    assert rep["flash_window"] is None
    assert rep["mailbox_client"] == 0xA0BEF8  # the getter-side twin


# -------------------------------------------------------- corpus class rows

def test_corpus_class_rows_lx_gca():
    rows = lr.scan_corpus_classes(CORPUS)
    if not rows:
        pytest.skip("corpus absent")
    gca = rows["cx4lx/14_32_1912/MCX4131A-GCA"]
    assert gca["class_0x158"] == 0x30
    assert gca["dw_0x280"] == 0
    assert gca["dw_0x2c4"] == 0
    assert gca["sec11_0x35"] == 0x00
    assert gca["family_byte_0x151"] == 0x27


def test_corpus_class_rows_ib_vs_eth_patterns():
    rows = lr.scan_corpus_classes(CORPUS)
    if not rows:
        pytest.skip("corpus absent")
    fca = rows["cx4/12_28_4706/MCX456A-FCA"]
    eca = rows["cx4/12_28_4706/MCX456A-ECA"]
    assert fca["class_0x158"] == 0x10 and eca["class_0x158"] == 0x31
    assert fca["dw_0x280"] == 0 and eca["dw_0x280"] == 0x12
    assert eca["dw_0x2c4"] == 0x00100000
    # every Lx build: ETH class byte, no 0x11 variant byte
    for name, row in rows.items():
        if name.startswith("cx4lx/"):
            assert row["class_0x158"] == 0x30, name
            assert row["sec11_0x35"] == 0x00, name
    # 2x25G Lx carries the ECA-like dword pair (product-speed marker)
    assert rows["cx4lx/14_32_1912/MCX4121A-ACA"]["dw_0x280"] == 0x12
    assert rows["cx4lx/14_32_1912/MCX4131A-BCA"]["dw_0x280"] == 0x11


def test_f3_patch_targets():
    rows = lr.scan_corpus_classes(CORPUS)
    if not rows:
        pytest.skip("corpus absent")
    tgt = lr.f3_targets(rows, "cx4lx/14_32_1912/MCX4131A-GCA")
    # P1 minimal byte: +0x158 0x30->0x10 (FCA-like)
    assert ("12", 0x158, 0x10) in tgt["p1"]
    # P2 tuple: +0x158 must carry the ECA/EDR class 0x31, NOT the FDR
    # value inherited from P1 (fix round 1 regression guard)
    assert ("12", 0x158, 0x31) in tgt["p2_eca_like"]
    assert ("12", 0x158, 0x10) not in tgt["p2_eca_like"]
    # P2 dword companions: dw@+0x280 -> 0x12, dw@+0x2c4 -> 0x00100000
    assert ("12", 0x283, 0x12) in tgt["p2_eca_like"]
    assert ("12", 0x2C5, 0x10) in tgt["p2_eca_like"]
