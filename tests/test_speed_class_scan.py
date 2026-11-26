"""cx4lx-fdr-gate tests: speed_class_scan parser + corpus golden rows.

Golden anchors (corpus arc A, journal
docs/superpowers/journal/2026-11-23-cx4lx-fdr-gate-codehunt.md steps 4-5):
  * cx4/12_28_4706/MCX456A-FCA: prs cx4_MCX456A_2p_x16_fdr,
    {ena 0x7, ext_ena 0x1, ext_sup 0x1, supported 0x1}, class byte
    +0x158 = 0x10, +0x2c5 = 0x00, lcl0 = 0x5b;
  * cx4/12_28_4706/MCX456A-ECA: prs ..._edr, ext_ena/ext_sup 0x3,
    class 0x31, secondary 0x10, lcl0/lcl1 0xfb;
  * cx4lx/14_32_1912/MCX4131A-GCA: prs cx4-lx_MCX4131A_1p_x8_50g,
    NO link_speed ini fields at all, class 0x30, lcl0 0x3b;
  * FCA<->ECA 0x12 diff is exactly 5 bytes
    {+0x158, +0x283, +0x2c5, +0x30b, +0x317}.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "probes" / "cx4lx-fdr-gate"))

import speed_class_scan as scs  # noqa: E402

CORPUS = REPO / "build" / "corpus"


def corpus_build(rel):
    d = CORPUS / rel
    if not (d / "sections" / "30" / "dc.bin").exists():
        pytest.skip("corpus build absent: %s" % rel)
    return d


def test_parse_ini_text_extracts_prs_and_fields():
    text = (
        ";; Generated automatically by iniprep tool on Wed Jan 21 15:42:39 IST 2026"
        " from ./cx4_MCX456A_2p_x16_fdr.prs;; FW version: 12.28.4706\n"
        "[fw_main_config]\n"
        "management.port_info.link_speed_ena = 0x7\n"
        "management.port_info.link_speed_ext_ena = 0x1\n"
        "phy_fw_main_config.phy_shomron.lcl[0].eth_speeds_supported.Speed56Gb = 0x1\n"
    )
    prs, fields = scs.parse_ini_text(text)
    assert prs == "cx4_MCX456A_2p_x16_fdr"
    assert fields == {"link_speed_ena": "0x7", "link_speed_ext_ena": "0x1"}


def test_parse_ini_text_lx_has_no_link_speed_fields():
    text = (
        ";; Generated from ./cx4-lx_MCX4131A_1p_x8_50g.prs\n"
        "[fw_main_config]\n"
        "leds.port_leds_gt_mode = 1\n"
    )
    prs, fields = scs.parse_ini_text(text)
    assert prs == "cx4-lx_MCX4131A_1p_x8_50g"
    assert fields == {}


def test_classify_by_ini_fields():
    fca = {"link_speed_ena": "0x7", "link_speed_ext_ena": "0x1",
           "link_speed_ext_sup": "0x1", "link_speed_supported": "0x1"}
    eca = {"link_speed_ena": "0x7", "link_speed_ext_ena": "0x3",
           "link_speed_ext_sup": "0x3", "link_speed_supported": "0x1"}
    eth = {"link_speed_ena": "0x1", "link_speed_ext_ena": "0x1",
           "link_speed_ext_sup": "0x3"}
    assert scs.classify({"ini_link_speed": fca}) == "ib-fdr"
    assert scs.classify({"ini_link_speed": eca}) == "ib-edr"
    assert scs.classify({"ini_link_speed": eth}) == "eth"
    assert scs.classify({"ini_link_speed": {}}) == "eth"


def test_corpus_fca_golden():
    row = scs.scan_build(corpus_build("cx4/12_28_4706/MCX456A-FCA"))
    assert row["prs"] == "cx4_MCX456A_2p_x16_fdr"
    assert row["ini_link_speed"]["link_speed_ena"] == "0x7"
    assert row["ini_link_speed"]["link_speed_ext_ena"] == "0x1"
    assert row["class_0x158"] == 0x10
    assert row["secondary_0x2c5"] == 0x00
    assert row["lcl0"] == 0x5B and row["lcl1"] == 0x5B
    assert scs.classify(row) == "ib-fdr"


def test_corpus_eca_golden_and_fca_eca_diff():
    fca = (corpus_build("cx4/12_28_4706/MCX456A-FCA") / "sections" / "12" /
           "dc.bin").read_bytes()
    eca = (corpus_build("cx4/12_28_4706/MCX456A-ECA") / "sections" / "12" /
           "dc.bin").read_bytes()
    row = scs.scan_build(corpus_build("cx4/12_28_4706/MCX456A-ECA"))
    assert row["prs"] == "cx4_MCX456A_2p_x16_edr"
    assert row["ini_link_speed"]["link_speed_ext_ena"] == "0x3"
    assert row["class_0x158"] == 0x31
    assert row["secondary_0x2c5"] == 0x10
    assert row["lcl0"] == 0xFB and row["lcl1"] == 0xFB
    assert scs.classify(row) == "ib-edr"
    diff = [i for i in range(len(fca)) if fca[i] != eca[i]]
    assert diff == [0x158, 0x283, 0x2C5, 0x30B, 0x317]


def test_corpus_lx_golden_eth_class_everywhere():
    rows = scs.scan_corpus(CORPUS)
    if not rows:
        pytest.skip("corpus absent")
    lx = {k: v for k, v in rows.items() if k.startswith("cx4lx/")}
    assert lx
    for name, row in lx.items():
        assert row["ini_link_speed"] == {}, (name, row["ini_link_speed"])
        assert row["class_0x158"] == 0x30, name
        assert scs.classify(row) == "eth", name
    gca = rows["cx4lx/14_32_1912/MCX4131A-GCA"]
    assert gca["prs"] == "cx4-lx_MCX4131A_1p_x8_50g"
    assert gca["lcl0"] == 0x3B
