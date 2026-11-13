import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.irisc import assemble, AsmError  # noqa: E402
from scripts.irisc.profiles import annotate, load_profile  # noqa: E402

OP36_WORD = (0x36 << 26) | (2 << 21) | (1 << 16) | (3 << 11) | 0x1234


def test_cx5_profile_facts():
    p = load_profile("cx5")
    assert any("4030" in v for v in p.verified_on)
    assert p.census["0x36"]["count_code"] == 3774
    assert p.load_base["MAIN_CODE"] == 8388608
    assert p.anchors["sha256_k_table_dc"] == "0x3940a8"
    assert p.form_status("set2") == "live"
    assert p.form_status("nonsense") == "assumed"


def test_cx4lx_profile_facts():
    p = load_profile("cx4lx")
    assert "14.32.1900-GCA" in p.verified_on
    assert p.anchors["sha256_k_table_dc"] == "0x319850"
    assert p.load_base["MAIN_CODE"] == 8388608
    assert "×0.98–1.12" in p.census["0x36"]["note"]
    assert p.form_status("ld.d") == "live"


def test_unknown_profile_name_rejected():
    from scripts.irisc.profiles import ProfileError
    with pytest.raises(ProfileError):
        load_profile("cx6")


def test_strict_gate_blocks_assumed_form():
    with pytest.raises(AsmError):
        assemble("ld.q r5,r1,0x10", profile="cx4lx")
    blob = assemble("ld.q r5,r1,0x10", profile="cx4lx", allow_assumed=True)
    assert struct.unpack(">I", blob)[0] == 0x64250010


def test_strict_gate_off_without_profile_or_strict_false():
    assert assemble("ld.q r5,r1,0x10")
    assert assemble("ld.q r5,r1,0x10", profile="cx4lx", strict=False)


def test_strict_gate_live_forms_pass():
    src = "\n".join([
        "set2 r5,zero,0x0", "set3 r5,r5,0x23f0",
        "ld.d r6,r5,0x0", "jump 0xc"])
    assert len(assemble(src, profile="cx4lx")) == 16
    assert len(assemble("cmp38_eq32 r5,zero", profile="cx5")) == 4


def test_strict_gate_per_profile_status():
    with pytest.raises(AsmError):
        assemble("ret.r zero,r8,r3", profile="cx4lx")
    assert assemble("ret.r zero,r8,r3", profile="cx5",
                    allow_assumed=False)


def test_cx4lx_cmp38_eq32_live_witness_ra3():
    """Live witness: reports/cx4lx-dumpcycle-ra3.md, verdict table row
    'Фильтр cmp — позитив (op38 eq32)' (seed -> K-constants event, silence
    without seed) + 'Негатив-контроль' (163.8 s armed, total_events=0);
    channel-B duplicate in cx4lx-dumpcycle-ra4.md check-table. The stub
    cmp word (build_dump_ra3.py EXPECTED_C w5) ran live on 14.32.1900."""
    blob = assemble("cmp38_eq32 r7,r6", profile="cx4lx")
    assert struct.unpack(">I", blob)[0] == 0xe0e03002


def test_cx4lx_or_live_witness_ra3():
    """Live witness: reports/cx4lx-dumpcycle-ra3.md, 'Дискриминатор
    image-ld.d' verdict (r11 = address echo) + ground-truth classes 2-3
    (r11 = 0xb1cba0 / 0x2314). Stub word `or r11,r3,r3` (w17,
    0xfc6b1808) is the sole r11 writer; the echo arrived in every
    iteration-1 C-cycle (p1/code1/ram1/id2/id3)."""
    blob = assemble("or r11,r3,r3", profile="cx4lx")
    assert struct.unpack(">I", blob)[0] == 0xfc6b1808


def test_0x0c_forms_split_register_vs_immediate():
    """canon-sync 0x0c (2026-11-01): the profile key `or` stays with the
    REGISTER form (or#alu gates on the bare mnemonic before the
    ALU-alias strips the suffix); the immediate hi-and form got its own
    key andmsk.hi — live on cx5 (fuzz5 battery V-C2R-0Cx01ff,
    live=unique:H-0c-hiand), static on cx4lx/cx6dx."""
    p5 = load_profile("cx5")
    p4 = load_profile("cx4lx")
    p6 = load_profile("cx6dx")
    assert p5.form_status("or") == "live"
    assert p4.form_status("or") == "live"
    assert p6.form_status("or") == "static"
    assert p5.form_status("andmsk.hi") == "live"
    assert p4.form_status("andmsk.hi") == "static"
    assert p6.form_status("andmsk.hi") == "static"
    # both forms strict-pass on all three profiles
    assemble("andmsk.hi r6,r6,0xff", profile="cx5")
    assemble("andmsk.hi r6,r6,0xff", profile="cx4lx")
    assemble("andmsk.hi r6,r6,0xff", profile="cx6dx")
    assemble("or r5,r22,r22", profile="cx5")
    assemble("or r11,r3,r3", profile="cx4lx")
    assemble("or r5,r22,r22", profile="cx6dx")


def test_cx4lx_csr_w_live_witness_ra3_ra4():
    """Live witness: reports/cx4lx-dumpcycle-ra3.md — link-restore
    `csr.w r17,zero,0xbc` (w18, 0x4e2000bc) executed in every live C-stub
    run (positives, 3 ground-truth classes, idempotence x3, disarm
    miss-path), card alive asserts=0; cx4lx-dumpcycle-ra4.md — B-split
    tail csr.w in all B-cycles + negative miss-path; ra4b.md E0 unarmed
    bare-trigger miss-path (rc=0, 12.8/12.4 ms, both copydone variants)."""
    blob = assemble("csr.w r17,zero,0xbc", profile="cx4lx")
    assert struct.unpack(">I", blob)[0] == 0x4e2000bc


def test_strict_gate_accepts_profile_object():
    p = load_profile("cx5")
    assert assemble("set2 r5,zero,0x0", profile=p)
    with pytest.raises(AsmError):
        assemble("ld.q r5,r1,0x10", profile=p)


def test_strict_gate_raw_layer_not_gated():
    blob = assemble("op0x36 r1,r2,r3 imm=0x1234", profile="cx4lx")
    assert struct.unpack(">I", blob)[0] == OP36_WORD
    blob = assemble("unk.r 0x36,r1,r2,r3,0x25", profile="cx5")
    assert len(blob) == 4


def test_strict_gate_error_names_form_and_profile():
    with pytest.raises(AsmError, match="ld.q.*cx4lx"):
        assemble("ld.q r5,r1,0x10", profile="cx4lx")


def test_annotate_census_suffix():
    p5 = load_profile("cx5")
    line = "op0x36 r1,r2,r3 imm=0x1234"
    assert annotate(line, p5).endswith("; [cx5] predicate-compare; f5 map open")
    assert annotate(line, None) == line
    assert annotate("set2 r5,zero,0x0", p5) == "set2 r5,zero,0x0"
    assert annotate("op0x3d r1,r2,r3 imm=0x0", p5) == "op0x3d r1,r2,r3 imm=0x0"


def test_annotate_multiline_text():
    p5 = load_profile("cx5")
    text = "set2 r5,zero,0x0\nop0x36 r1,r2,r3 imm=0x1234\njump 0x0\n"
    lines = annotate(text, p5).split("\n")
    assert lines[0] == "set2 r5,zero,0x0"
    assert lines[1].endswith("; [cx5] predicate-compare; f5 map open")
    assert lines[2] == "jump 0x0"
