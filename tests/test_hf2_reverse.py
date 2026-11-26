"""cx4lx-fdr-gate tests: hf2_reverse (arc H-F2 / G1 task-02).

Golden anchors:

  * Dispatcher special-path sites (MAIN_CODE, Lx 14.32.1912-GCA):
    rt 0x9be0f4 "ib_speed_nego" and its twin rt 0x9fc44c "ib_force_edr"
    both gate on mirror RAM word 0x3686 (= byte 0xDA18) bits[9..11]
    (mask32 0x9,3); the CX-4 12.28 homologs (0x9979cc / 0x9d1670) use the
    constant 3 (subsi r4,r23,0x3; b.t.0x4) -- class-dependent difference.
  * Polling arms of the send hub (jump-table 0x13 arms): Lx rt 0x9b32d0 /
    0x9b3320 iterate exactly `field` times (cmd 0x21/0x20); the CX-4
    homologs (rt 0x98da04 / 0x98da40) loop on a constant compare
    (subsi r4,r23,0x3, counter 1..2) -> exactly 2 iterations, no mirror.
  * Patch: `ld.i r4,0x3686` -> `addi r4,zero,0x400` (field := 2) at the
    field-source word of both dispatchers + both polling count-source
    words; semantics bit-equivalent to CX-4 (event>2 <=> event>=3).
"""
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "cx4lx-fdr-gate"))

from mlxfwutil import Image, clcrc_unwrap  # noqa: E402
import cable_gate_patch as cgp  # noqa: E402
import loader_reverse as lr  # noqa: E402
import hf2_reverse as hf  # noqa: E402

BASE = (REPO / "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-"
        "UEFI-14.25.17-FlexBoot-3.6.502.bin")
ECA = (REPO / "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-MCX456A-ECA_Ax-"
       "UEFI-14.21.21-FlexBoot-3.6.103.bin")
SPEC_PATH = REPO / "scripts/probes/gate-specs/hf2-dispatcher-cx4lx-1912.json"

LOAD_BASE = 0x800000
MIRROR_WORD = 0x3686


def _base():
    if not BASE.is_file():
        pytest.skip("refs base image not present")
    return BASE


def _eca():
    if not ECA.is_file():
        pytest.skip("refs ECA image not present")
    return ECA


@pytest.fixture(scope="module")
def base_dc():
    _base()
    img, e, dc = hf.load_main_code(BASE)
    return img, e, dc


@pytest.fixture(scope="module")
def eca_dc():
    _eca()
    img, e, dc = hf.load_main_code(ECA)
    return img, e, dc


# --------------------------------------------------- group 1: rt -> dc map

class TestRtToDc:
    def test_param0_is_load_base(self, base_dc):
        _img, e, _dc = base_dc
        assert e.type == 3 and e.clcrc
        assert e.param0 == LOAD_BASE

    def test_dispatcher_site(self, base_dc):
        _img, e, dc = base_dc
        assert hf.rt_to_dc(0x9be0f4) == 0x1be0f4
        assert hf.rt_to_dc(0x9be124) == 0x1be124
        assert dc[0x1be124:0x1be124 + 4] == bytes.fromhex("16e40001")
        assert dc[0x1be0f4:0x1be0f4 + 4] == bytes.fromhex("480300bc")

    def test_polling_sites(self, base_dc):
        _img, _e, dc = base_dc
        assert hf.rt_to_dc(0x9b32d0) == 0x1b32d0
        assert hf.rt_to_dc(0x9b3320) == 0x1b3320
        for off in (0x1b32d0, 0x1b3320):
            assert dc[off:off + 4] == bytes.fromhex("4a043686")

    def test_twin_dispatcher_site(self, base_dc):
        _img, _e, dc = base_dc
        assert hf.rt_to_dc(0x9fc44c) == 0x1fc44c
        assert hf.rt_to_dc(0x9fc480) == 0x1fc480
        assert dc[0x1fc480:0x1fc480 + 4] == bytes.fromhex("16e40001")

    def test_image_offset_round_trip(self, base_dc):
        # dc word == framed image bytes at (flash abs + in-line off), stock
        img, e, dc = base_dc
        for dc_off in (0x1be124, 0x1be12c, 0x1fc488, 0x1b330c, 0x1b335c):
            loc = hf.dc_to_image(img, e, dc_off)
            assert loc["in_line"] == dc_off % 64
            line = img.section_data(e)[loc["clcrc_line"] * 68:
                                       loc["clcrc_line"] * 68 + 68]
            got = line[loc["in_line"]:loc["in_line"] + 4]
            assert got == dc[dc_off:dc_off + 4]
            assert img.buf[loc["flash_abs"]:loc["flash_abs"] + 4] == got


# ---------------------------------------- group 2: decode == arc F reference

class TestDispatcherDecode:
    def test_reference_six_words(self, base_dc):
        _img, _e, _dc = base_dc
        d = hf.dispatcher_words(BASE)
        texts = [w["text"] for w in d["words"]]
        assert texts == [
            "subsi r4,r23,0x1",
            "b.t.0x2 zero,0x9be13c",
            "ld.i r4,0x3686",
            "mask32 r4,r4,0x9,3",
            "subs r4,r23,r4",
            "b.f.0x3 zero,0x9be180",
        ]
        assert [w["rt"] for w in d["words"]] == [
            0x9be124, 0x9be128, 0x9be12c, 0x9be130, 0x9be134, 0x9be138]

    def test_site_identity(self, base_dc):
        _img, _e, _dc = base_dc
        d = hf.dispatcher_words(BASE)
        assert d["site_rt"] == 0x9be0f4 and d["site_dc"] == 0x1be0f4
        assert d["load_base"] == LOAD_BASE
        assert d["ini_id"] == "N/A"
        assert "ib_speed_nego got bad pport" in d["special_string"]["text"]

    def test_field_source_word(self, base_dc):
        _img, _e, _dc = base_dc
        d = hf.dispatcher_words(BASE)
        fs = d["field_source"]
        assert fs["rt"] == 0x9be12c and fs["dc"] == 0x1be12c
        assert fs["word"] == "4a043686"
        assert fs["text"] == "ld.i r4,0x3686"

    def test_twin_is_same_idiom(self, base_dc):
        _img, _e, _dc = base_dc
        d = hf.dispatcher_words(BASE)
        t = d["twin"]
        assert t["site_rt"] == 0x9fc44c and t["site_dc"] == 0x1fc44c
        assert [w["text"] for w in t["words"]] == [
            "subsi r4,r23,0x1",
            "b.t.0x2 zero,0x9fc498",
            "ld.i r4,0x3686",
            "mask32 r4,r4,0x9,3",
            "subs r4,r23,r4",
            "b.f.0x3 zero,0x9fc4dc",
        ]
        assert t["field_source"]["dc"] == 0x1fc488
        assert "ib_force_edr got bad pport" in t["special_string"]["text"]

    def test_structural_scan_finds_exactly_two(self, base_dc):
        _img, _e, dc = base_dc
        sites = hf.find_dispatcher_sites(dc)
        assert [s["cmp_dc"] for s in sites] == [0x1be124, 0x1fc480]


class TestPollingDecode:
    def test_arm_tails(self, base_dc):
        _img, _e, dc = base_dc
        arms = hf.find_polling_arms(dc)
        assert sorted(a["cmd"] for a in arms) == [0x20, 0x21]
        by = {a["cmd"]: a for a in arms}
        a21 = by[0x21]
        assert a21["rt"] == 0x9b32d0 and a21["dc"] == 0x1b32d0
        assert a21["count_rt"] == 0x9b330c and a21["count_dc"] == 0x1b330c
        assert a21["loop_head_rt"] == 0x9b32e8
        assert a21["sender_rt"] == 0x9b33d0
        tail = [t for _rt, _w, t in a21["tail_words"]]
        assert tail == ["ld.i r4,0x3686", "mask32 r4,r4,0x9,3",
                        "subs r4,r4,r23", "b.t.0x3 zero,0x9b32e8"]
        a20 = by[0x20]
        assert a20["rt"] == 0x9b3320 and a20["count_dc"] == 0x1b335c
        assert a20["loop_head_rt"] == 0x9b3338
        tail20 = [t for _rt, _w, t in a20["tail_words"]]
        assert tail20[2] == "subs r4,r4,r23"
        assert tail20[3] == "b.t.0x3 zero,0x9b3338"

    def test_gate_words(self, base_dc):
        _img, _e, dc = base_dc
        arms = hf.find_polling_arms(dc)
        for a in arms:
            gate = [t for _rt, _w, t in a["gate_words"]]
            assert gate[0] == "ld.i r4,0x3686"
            assert gate[1].startswith("op0x36 zero,r4,zero imm=0x0123")
            assert gate[2].startswith("b.t.0xa ")


# ---------------------------------- group 3: patch words + semantic equality

class TestPatchWords:
    def test_patch_words_locations_and_bytes(self, base_dc):
        _img, _e, _dc = base_dc
        words = hf.patch_words(BASE)
        assert words == [
            (0x1be12c, bytes.fromhex("00040400")),
            (0x1fc488, bytes.fromhex("00040400")),
            (0x1b330c, bytes.fromhex("00040400")),
            (0x1b335c, bytes.fromhex("00040400")),
        ]

    def test_patch_words_assemble_strict_cx4lx(self, base_dc):
        # decode-verify: the patch bytes assemble (strict profile) from
        # their own disasm text back to the same word, and the assembled
        # word re-decodes to the expected instruction.
        from scripts.irisc import assemble, disasm
        from scripts.irisc.profiles import load_profile
        prof = load_profile("cx4lx")
        for dc_off, wb in hf.patch_words(BASE):
            rt = hf.dc_to_rt(dc_off)
            w = struct.unpack(">I", wb)[0]
            text = disasm(w, rt)
            assert text == "addi r4,zero,0x400"
            out = assemble(text, base=rt, profile=prof)
            assert out == wb

    def test_stock_words_decode_to_ldi(self, base_dc):
        from scripts.irisc import disasm
        _img, _e, dc = base_dc
        for dc_off, _wb in hf.patch_words(BASE):
            w = struct.unpack(">I", dc[dc_off:dc_off + 4])[0]
            assert disasm(w, hf.dc_to_rt(dc_off)) == "ld.i r4,0x3686"


class TestTruthTable:
    def test_stock_dispatcher_matches_special_path_lx(self, base_dc):
        _img, _e, dc = base_dc
        d = hf.dispatcher_words(BASE)
        for site in (d, d["twin"]):
            words = {w["rt"]: w["word_int"] for w in site["words"]}
            special_pc = site["words"][1]["branch_target"]
            for event in list(range(0, 16)) + [0x2a, 0x3f]:
                for field in range(8):
                    mirror = (field << 9) | 0x1
                    got = hf.interp_dispatcher(words, site["words"][0]["rt"],
                                               event, mirror) == special_pc
                    assert got == lr.special_path_lx(event, field), \
                        (hex(event), field)

    def test_patched_dispatcher_equals_cx4(self, base_dc):
        _img, _e, dc = base_dc
        d = hf.dispatcher_words(BASE)
        for site in (d, d["twin"]):
            words = {w["rt"]: w["word_int"] for w in site["words"]}
            special_pc = site["words"][1]["branch_target"]
            for dc_off, wb in hf.patch_words(BASE):
                rt = hf.dc_to_rt(dc_off)
                if rt in words:
                    words[rt] = struct.unpack(">I", wb)[0]
            for event in list(range(0, 16)) + [0x2a, 0x3f]:
                for field in range(8):
                    mirror = (field << 9) | 0x2
                    got = hf.interp_dispatcher(words, site["words"][0]["rt"],
                                               event, mirror) == special_pc
                    assert got == lr.special_path_cx4(event), \
                        (hex(event), field)

    def test_cx4_dispatcher_homolog_matches_special_path_cx4(self, eca_dc):
        _img, _e, dc = eca_dc
        sites = hf.find_cx4_dispatcher_sites(dc)
        assert len(sites) == 2
        for site in sites:
            words = {rt: w for rt, w, _t in site["words"]}
            special_pc = site["special_rt"]
            for event in list(range(0, 16)) + [0x2a, 0x3f]:
                got = hf.interp_dispatcher(words, site["words"][0][0],
                                           event, mirror=0) == special_pc
                assert got == lr.special_path_cx4(event), hex(event)


class TestPollingSemantics:
    def test_stock_lx_arm_iterations_equal_field(self, base_dc):
        _img, _e, dc = base_dc
        arms = hf.find_polling_arms(dc)
        assert len(arms) == 2
        for a in arms:
            for field in range(1, 8):
                mirror = (field << 9) | 0x5
                n = hf.interp_polling_arm(a, mirror, gate="field_zero")
                assert n == field, (a["cmd"], field)
            # field == 0 with the zero-guard gate -> no iterations
            assert hf.interp_polling_arm(a, 0, gate="field_zero") == 0
            # gate forced open, field == 0 -> 1 iteration (head increments
            # before the check) -- documents why CX-4 has no gate
            assert hf.interp_polling_arm(a, 0, gate="pass") == 1

    def test_patched_lx_arm_two_iterations_any_mirror(self, base_dc):
        _img, _e, dc = base_dc
        patched = bytearray(dc)
        for dc_off, wb in hf.patch_words(BASE):
            patched[dc_off:dc_off + 4] = wb
        arms = hf.find_polling_arms(bytes(patched))
        assert len(arms) == 2
        for a in arms:
            for field in range(1, 8):
                mirror = (field << 9) | 0x123
                for mode in ("field_zero", "pass"):
                    n = hf.interp_polling_arm(a, mirror, gate=mode)
                    assert n == 2, (a["cmd"], field, mode)

    def test_cx4_arm_two_iterations_constant(self, eca_dc):
        _img, _e, dc = eca_dc
        arms = hf.find_cx4_polling_arms(dc)
        assert sorted(a["cmd"] for a in arms) == [0x20, 0x21]
        for a in arms:
            assert a["compare_const"] == 3
            for mirror in (0, 0x400, 0x7f):
                assert hf.interp_polling_arm(a, mirror) == 2


# ------------------------------------------------ group 4: spec + canary

class TestSpec:
    def test_spec_file_matches_tool_output(self):
        if not SPEC_PATH.is_file():
            pytest.fail("gate spec JSON missing")
        _base()
        import json
        on_disk = json.loads(SPEC_PATH.read_text())
        assert on_disk == hf.build_spec(BASE)

    def test_check_spec_passes_on_stock(self, base_dc):
        import json
        spec = json.loads(SPEC_PATH.read_text())
        img = Image(BASE.read_bytes(), str(BASE))
        errs = cgp.check_spec(spec, img)
        assert errs == []

    def test_spec_expected_before_from_stock(self, base_dc):
        import json
        spec = json.loads(SPEC_PATH.read_text())
        _img, _e, dc = base_dc
        for p in spec["patches"]:
            off = int(p["offset"], 0)
            assert dc[off:off + 4].hex() == \
                p["expected_before"].replace(" ", "")
            assert bytes.fromhex(p["bytes"].replace(" ", "")) == \
                bytes.fromhex("00040400")

    def test_apply_spec_canary_clean(self, base_dc, tmp_path):
        import json
        spec = json.loads(SPEC_PATH.read_text())
        img, e, dc = base_dc
        out = tmp_path / "hf2-dispatcher.bin"
        rc = cgp.apply_spec(spec, BASE, out)
        assert rc == 0
        new = out.read_bytes()
        base = BASE.read_bytes()
        # allowed: patch bytes (framed) + clcrc bytes of touched lines +
        # ITOC entry crc fields (0x1A-0x1B section crc, 0x1E-0x1F entry crc)
        allowed = set()
        for dc_off, wb in hf.patch_words(BASE):
            loc = hf.dc_to_image(img, e, dc_off)
            line = loc["clcrc_line"]
            for i in range(4):
                allowed.add(img.sec_abs(e) + line * 68 + loc["in_line"] + i)
            allowed.update(img.sec_abs(e) + line * 68 + b for b in (66, 67))
        ent_off = img.itoc_off + 32 + e.index * 32
        allowed.update(range(ent_off + 0x1A, ent_off + 0x20))
        diff = [i for i in range(len(base)) if base[i] != new[i]]
        assert set(diff) <= allowed, [hex(i) for i in diff if i not in allowed]
        assert diff  # something must actually change
        # patched dc view: stock with patch words applied; per-line clcrc OK
        nimg = Image(new, str(out))
        ne = nimg.find_entry("ITOC", 3)
        ndc, _tail = clcrc_unwrap(nimg.section_data(ne))
        expected = bytearray(dc)
        for dc_off, wb in hf.patch_words(BASE):
            expected[dc_off:dc_off + 4] = wb
        assert ndc == bytes(expected)


# --------------------------------------------- group 5: CX-4 ECA homologs

class TestCx4Homologs:
    def test_dispatcher_homolog_decode(self, eca_dc):
        _img, _e, dc = eca_dc
        sites = hf.find_cx4_dispatcher_sites(dc)
        texts = [[t for _rt, _w, t in s["words"]] for s in sites]
        assert texts[0] == [
            "subsi r4,r23,0x1",
            "b.t.0x2 zero,0x997a0c",
            "subsi r4,r23,0x3",
            "b.t.0x4 zero,0x997a50",
        ]
        assert texts[1] == [
            "subsi r4,r23,0x1",
            "b.t.0x2 zero,0x9d16b4",
            "subsi r4,r23,0x3",
            "b.t.0x4 zero,0x9d16f8",
        ]
        assert sites[0]["site_rt"] == 0x9979cc
        assert sites[1]["site_rt"] == 0x9d1670
        assert "ib_speed_nego" in sites[0]["special_string"]["text"]
        assert "ib_force_edr" in sites[1]["special_string"]["text"]

    def test_no_mirror_read_in_cx4_dispatcher(self, eca_dc):
        _img, _e, dc = eca_dc
        for s in hf.find_cx4_dispatcher_sites(dc):
            for _rt, _w, t in s["words"]:
                assert "ld.i r" not in t
                assert "mask32" not in t

    def test_cx4_polling_homolog_no_mirror(self, eca_dc):
        _img, _e, dc = eca_dc
        for a in hf.find_cx4_polling_arms(dc):
            assert a["rt"] in (0x98da04, 0x98da40)
            assert a["gate_words"] is None
            for _rt, _w, t in a["tail_words"]:
                assert "0x3686" not in t and "mask32" not in t
            texts = [t for _rt, _w, t in a["tail_words"]]
            assert texts[-2].startswith("subsi r4,r23,0x3")

    def test_polling_verdict_target(self, base_dc, eca_dc):
        _base()
        _eca()
        v = hf.polling_verdict(BASE, ECA)
        assert v["verdict"] == "target"
        assert v["second_patch_site"] is True
        assert v["cx4_homolog"]["count_semantics"] == "constant-2"
        assert v["cx4_homolog"]["lx_semantics"] == "mirror-field"
        proof = v["proof"]
        assert proof["cx4_arms"][0]["rt"] == 0x98da04
        assert proof["cx4_arms"][0]["iterations"] == 2
        assert proof["cx4_arms"][1]["rt"] == 0x98da40
        assert proof["cx4_arms"][1]["iterations"] == 2
        assert proof["twin_dispatcher"]["site_rt"] == 0x9fc44c
        assert proof["twin_dispatcher"]["cx4_site_rt"] == 0x9d1670


# --------------------- group 6: ETH speed-enable trace (H2, task-03)
#
# Golden anchors (journal task-03): the protocol-choice sites read the
# ETH-визави param 0x60c (nbits 0x14) or the IB param 0x776 (nbits 0xa)
# through ONE getter (Lx rt 0xa0bfb8 / CX-4 rt 0x9e184c) from the same
# parsed table, selected by the port protocol word (Lx RAM 0x38f5 / CX-4
# 0x3a75, &3) -- and store the result into the same ctx[0x5c] slot.

CORPUS = REPO / "build" / "corpus"
ECA_REL = "cx4/12_28_4706/MCX456A-ECA"


def _corpus():
    if not CORPUS.is_dir():
        pytest.skip("corpus not built (rebuild: make corpus)")
    return CORPUS


def _corpus_dc(rel, secnum="03"):
    p = CORPUS / rel / "sections" / secnum / "dc.bin"
    if not p.is_file():
        pytest.skip("corpus section absent: %s" % p)
    return p.read_bytes()


class TestEthChoiceSites:
    def test_lx_two_sites(self, base_dc):
        _img, _e, dc = base_dc
        sites = hf.find_eth_choice_sites(dc)
        assert [s["proto_rt"] for s in sites] == [0x9CCD4C, 0x9DFEAC]

    def test_lx_site_decode(self, base_dc):
        _img, _e, dc = base_dc
        s = hf.find_eth_choice_sites(dc)[0]
        assert s["proto_word"] == 0x38F5
        assert s["eth_param"] == 0x60C and s["eth_nbits"] == 0x14
        assert s["ib_param"] == 0x776 and s["ib_nbits"] == 0xA
        assert s["eth_branch_rt"] == 0x9CCD60
        assert s["ib_branch_rt"] == 0x9CCD6C
        # b.f.0xa (cmpres) skips to the IB branch; jump merges both
        assert s["branch_target"] == s["ib_branch_rt"]
        assert s["merge_rt"] == 0x9CCD74
        assert s["getter_rt"] == 0xA0BFB8
        assert s["store"] == {"rt": 0x9CCD80, "text": "st.d r4,r23,0x5c"}
        texts = [t for _rt, _w, t in s["window"]]
        assert texts == [
            "ld.i r5,0x38f5",
            "ld.d r4,r21,0x0",
            "ands r20,r5,0x3",
            "op0x36 zero,r5,r1 imm=0x0c02",
            "b.f.0xa zero,0x9ccd6c",
            "addi r5,zero,0x60c",
            "addi r6,zero,0x14",
            "jump 0x9ccd74",
        ]

    def test_lx_second_site_same_getter(self, base_dc):
        _img, _e, dc = base_dc
        s = hf.find_eth_choice_sites(dc)[1]
        assert s["ib_branch_rt"] == 0x9E008C
        assert s["merge_rt"] == 0x9E0094
        assert s["getter_rt"] == 0xA0BFB8
        assert s["store"]["rt"] == 0x9E00A0
        assert s["store"]["text"] == "st.d r4,r1,0x6c"

    def test_cx4_homolog(self):
        edc = _corpus_dc(ECA_REL)
        sites = hf.find_cx4_eth_choice_sites(edc)
        assert [s["proto_rt"] for s in sites] == [0x9A60B8, 0x9B8B68]
        s = sites[0]
        assert s["proto_word"] == 0x3A75
        assert s["eth_param"] == 0x60C and s["eth_nbits"] == 0x14
        assert s["ib_param"] == 0x776 and s["ib_nbits"] == 0xA
        assert s["eth_branch_rt"] == 0x9A60CC
        assert s["ib_branch_rt"] == 0x9A60D8
        assert s["getter_rt"] == 0x9E184C
        assert s["store"] == {"rt": 0x9A60EC, "text": "st.d r4,r23,0x5c"}
        assert sites[1]["getter_rt"] == 0x9E184C

    def test_60c_site_census(self, base_dc):
        _img, _e, dc = base_dc
        assert hf.find_60c_sites(dc) == [0x9CCD60, 0x9DFEC0, 0x9ED0E4,
                                         0x9FBA48]
        edc = _corpus_dc(ECA_REL)
        assert hf.find_60c_sites(edc) == [0x9A60CC, 0x9B8B7C, 0x9C3D90,
                                          0x9D0C88]

    def test_param_math_one_table(self):
        # 0x60c (ETH) and 0x776 (IB) are two params of one table
        # (loader_reverse getter math, basecalc-verified in journal).
        assert lr.param_word(0x60C) == 12
        assert lr.param_field(0x60C) == 0
        assert lr.param_bit_offset(0x60C) == 19
        assert lr.param_word(0x776) == 14
        assert lr.param_field(0x776) == 3
        assert lr.param_bit_offset(0x776) == 69


# ------------------------- group 7: EDR-class tuple (0x12, ECA reference)

TUPLE_EXPECTED = [
    (0x158, 0x30, 0x31),
    (0x283, 0x00, 0x12),
    (0x2C5, 0x00, 0x10),
    (0x30B, 0x3B, 0xFB),
    (0x317, 0x00, 0xFB),
]


class TestEthTuple:
    def test_tuple_bytes_stock_and_eca(self):
        _base()
        t = hf.eth_tuple(BASE, CORPUS)
        got = [(b["offset"], b["stock"], b["target"])
               for b in t["bytes"]]
        assert got == TUPLE_EXPECTED
        assert t["section"] == 0x12
        assert "MCX456A-ECA" in t["reference"]

    def test_tuple_identifier_set(self):
        _base()
        img = Image(BASE.read_bytes(), str(BASE))
        e = img.find_entry("ITOC", 0x12)
        t = hf.eth_tuple(BASE, CORPUS)
        ent_off = img.itoc_off + 32 + e.index * 32
        for b in t["bytes"]:
            assert b["image_abs"] == img.sec_abs(e) + b["offset"]
            assert b["itoc_index"] == e.index
            assert b["crc_sites"]["sec_crc"] == \
                [ent_off + 0x1A, ent_off + 0x1B]
            assert b["crc_sites"]["entry_crc"] == \
                [ent_off + 0x1E, ent_off + 0x1F]
        by_off = {b["offset"]: b for b in t["bytes"]}
        assert by_off[0x158]["ini_id"].startswith("N/A")
        assert by_off[0x283]["ini_id"].startswith("N/A")
        assert by_off[0x2C5]["ini_id"].startswith("N/A")
        assert "lcl[0].eth_speeds_supported" in by_off[0x30B]["ini_id"]
        assert "lcl[1].eth_speeds_supported" in by_off[0x317]["ini_id"]

    def test_fca_eca_diff_is_exactly_tuple(self):
        fca = _corpus_dc("cx4/12_28_4706/MCX456A-FCA", "12")
        eca = _corpus_dc(ECA_REL, "12")
        diffs = hf.diff_offsets(fca, eca)
        assert diffs == [(0x158, 0x10, 0x31), (0x283, 0x00, 0x12),
                         (0x2C5, 0x00, 0x10), (0x30B, 0x5B, 0xFB),
                         (0x317, 0x5B, 0xFB)]

    def test_same_board_eth_speed_diffs_in_tuple(self):
        _corpus()
        rows = hf.corpus_eth_speed_diffs(CORPUS)
        by = {r["label"]: r for r in rows}
        # Lx same board: 56G-class vector lands exactly in tuple bytes
        lx = by["lx 4131A 40/56G vs 50G (same board)"]
        assert lx["diffs"] == [(0x283, 0x11, 0x00),
                               (0x2C5, 0x10, 0x00),
                               (0x30B, 0x1B, 0x3B)]
        assert lx["outside_tuple"] == []
        # cx4 same board: only the lcl 56G bit
        cx = by["cx4 413A 40/56G vs 50G (same board)"]
        assert cx["diffs"] == [(0x30B, 0x5B, 0x3B)]
        assert cx["outside_tuple"] == []
        # 100G product: class vector in tuple bytes (dw280 hi 0x12 ==
        # ECA value, lcl 0xbb); remaining bytes are cross-board noise
        # (0x159 board byte, dw2c4 low bytes of the 2p x16 layout)
        g100 = by["cx4 416A 100G vs 413A 50G (cross board 2p x16)"]
        assert g100["outside_tuple"] == [0x159, 0x2C4, 0x2C6, 0x2C7]
        assert g100["conforms"] is True
        # port-count noise only in lcl[1]
        pc = by["cx4 414A 2p vs 413A 1p (port count)"]
        assert pc["diffs"] == [(0x317, 0x3B, 0x00)]
        assert pc["outside_tuple"] == []

    def test_ini_link_speed_projection(self):
        _corpus()
        rows = hf.corpus_ini_link_speed(CORPUS)
        by = {r["build"]: r for r in rows}
        assert by[ECA_REL]["ini_link_speed"] == {
            "link_speed_ena": "0x7", "link_speed_ext_ena": "0x3",
            "link_speed_ext_sup": "0x3", "link_speed_supported": "0x1"}
        assert by["cx4/12_28_4706/MCX456A-FCA"]["ini_link_speed"] == {
            "link_speed_ena": "0x7", "link_speed_ext_ena": "0x1",
            "link_speed_ext_sup": "0x1", "link_speed_supported": "0x1"}
        # every cx4lx build lacks the INI projection entirely
        for r in rows:
            if r["build"].startswith("cx4lx/"):
                assert r["ini_link_speed"] == {}

    def test_lcl_bits_match_prs(self):
        _corpus()
        rows = hf.corpus_ini_link_speed(CORPUS)
        by = {r["build"]: r for r in rows}
        # lcl[0] byte == eth_speeds_supported bit map of the .prs
        # (bit0=1G..bit7=100G): GCA 0x3b (no 56/100), ECA 0xfb (56+100)
        assert by["cx4lx/14_32_1912/MCX4131A-GCA"]["lcl0"] == 0x3B
        assert by["cx4lx/14_32_1912/MCX4131A-GCA"]["eth_mask"] == 0x3B
        assert by[ECA_REL]["lcl0"] == 0xFB
        assert by[ECA_REL]["eth_mask"] == 0xFB
        assert by["cx4/12_28_4706/MCX416A-CCA"]["lcl0"] == 0xBB
        assert by["cx4/12_28_4706/MCX416A-CCA"]["eth_mask"] == 0xBB


# ------------------------------ group 8: eth_verdict (H2, mode unified)

class TestEthVerdict:
    def test_mode_unified(self):
        _base()
        _corpus_dc(ECA_REL)
        v = hf.eth_verdict(BASE, CORPUS)
        assert v["mode"] == "unified"
        assert v["sites"] == []

    def test_verdict_tuple_consumable(self):
        _base()
        _corpus_dc(ECA_REL)
        v = hf.eth_verdict(BASE, CORPUS)
        assert [(b["offset"], b["stock"], b["target"])
                for b in v["tuple"]["bytes"]] == TUPLE_EXPECTED
        # every tuple byte is a data byte of section 0x12 -- the ETH
        # path adds NO MAIN_CODE code sites (polling/dispatcher words
        # of task-02 stay untouched)
        for b in v["tuple"]["bytes"]:
            assert b["section"] == 0x12

    def test_verdict_carries_trace_and_proof(self):
        _base()
        _corpus_dc(ECA_REL)
        v = hf.eth_verdict(BASE, CORPUS)
        tr = v["eth_trace"]
        assert [s["proto_rt"] for s in tr["lx_choice_sites"]] == \
            [0x9CCD4C, 0x9DFEAC]
        assert all(s["getter_rt"] == 0xA0BFB8
                   for s in tr["lx_choice_sites"])
        assert [s["proto_rt"] for s in tr["cx4_choice_sites"]] == \
            [0x9A60B8, 0x9B8B68]
        assert all(s["getter_rt"] == 0x9E184C
                   for s in tr["cx4_choice_sites"])
        assert tr["param_math"]["eth"]["word"] == 12
        assert tr["param_math"]["ib"]["word"] == 14
        proof = v["corpus_proof"]
        assert proof["fca_eca_diff"] == "tuple-exact"
        assert proof["speed_pairs_all_in_tuple"] is True
        assert proof["ini_projection"] == \
            "cx4: link_speed_* present; cx4lx: absent (lcl carries ETH mask)"

    def test_task2_patch_words_unchanged(self, base_dc):
        # the ETH verdict work must not disturb the dispatcher/polling
        # patch set of task-02 (polling words are closed behaviorally)
        _base()
        assert hf.patch_words(BASE) == [
            (0x1BE12C, bytes.fromhex("00040400")),
            (0x1FC488, bytes.fromhex("00040400")),
            (0x1B330C, bytes.fromhex("00040400")),
            (0x1B335C, bytes.fromhex("00040400")),
        ]
