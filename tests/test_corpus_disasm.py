import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import scripts.corpus.disasm_build as disasm_build  # noqa: E402
from scripts.corpus.disasm_build import (  # noqa: E402
    PROFILE_ABSENT,
    PROFILE_DRIFT,
    disasm_section,
    disasm_stage,
    disasm_txt,
    profile_for,
    recount_delta,
)
from scripts.corpus.manifest import T1, T2, T3  # noqa: E402
from scripts.irisc.profiles import load_profile  # noqa: E402

GOLDEN = [
    (0x940002DE, 0x1D594, "call 0x1e10c"),
    (0x940DC067, 0x1D594, "call 0x38d730"),
    (0x95000000, 0x1D598, "jump 0x1d598"),
    (0x6C201806, 0, "st.d r3,r1,0x4"),
    (0x6C20888E, 0, "st.d r17,r1,0x8c"),
    (0x6EE02007, 0, "st.w r4,r23,0x6"),
    (0x7820281C, 0, "st.q.1e r5,r1,0x18"),
    (0x6437000A, 0, "ld.d r23,r1,0x8"),
    (0xC9090124, 0, "mask32 r9,r8,0x9,4"),
    (0xC9080003, 0, "mask32 r8,r8,0x0,3"),
    (0xC9080200, 0, "mask32 r8,r8,0x10,0"),
    (0x2C84FFFC, 0, "ands r4,r4,0xfffc"),
    (0x2C84000F, 0, "ands r4,r4,0xf"),
    (0xA0100002, 0x9176C, "b.t.0x10 zero,0x91774"),
]


def pack(*words):
    return struct.pack(">%dI" % len(words), *words)


@pytest.mark.parametrize("w,off,expected", GOLDEN)
def test_golden_words_render_exact_lines(w, off, expected):
    lines = disasm_section(pack(w), off)
    assert len(lines) == 1
    line = lines[0]
    assert set(line) == {"dc", "w", "text"}
    assert line["dc"] == off
    assert line["w"] == w
    assert line["text"] == "%08x  %08x  %s" % (off, w, expected)


def test_dc_increments_by_four_and_tail_ignored():
    words = [0x940002DE, 0x95000000, 0x6C201806]
    dc = pack(*words) + b"\xab\xcd"
    lines = disasm_section(dc, 0x1000)
    assert [l["dc"] for l in lines] == [0x1000, 0x1004, 0x1008]
    assert [l["w"] for l in lines] == words


def test_all_ones_lossless_no_exception():
    lines = disasm_section(pack(0xFFFFFFFF), 0x38d730)
    assert len(lines) == 1
    assert lines[0]["text"] == "0038d730  ffffffff  alu.0x1ff r31,r31,r31"


def test_dis_raise_renders_raw_word(monkeypatch):
    def boom(w, off):
        if w == 0x6C201806:
            raise ValueError("synthetic decoder failure")
        return "addi zero,zero,0x0"

    monkeypatch.setattr(disasm_build, "disasm", boom)
    lines = disasm_section(pack(0x00000000, 0x6C201806), 0)
    assert lines[1]["text"] == "00000004  6c201806  raw 0x6c201806"


def test_empty_dc():
    assert disasm_section(b"", 0x100) == []
    assert disasm_section(b"\x01\x02", 0x100) == []


PROFILE_FOR_CASES = [
    ("cx4", "12_28_4706", "cx4-1228", False),
    ("cx4lx", "14_32_1900", "cx4lx", False),
    ("cx4lx", "14_32_1912", "cx4lx", False),
    ("cx5", "16_35_4030", "cx5", False),
    ("cx5", "16_35_8008", "cx5", False),
    ("cx5", "16_35_1012", "cx5", False),
    ("cx5", "16_19_1200", "cx5", True),
    ("cx6", "20_43_1014", "cx6-2043", False),
    ("cx6dx", "22_50_1002", "cx6dx", False),
    ("cx6dx", "22_47_3576", "cx6dx", True),
    ("cx6lx", "26_50_1002", "cx6lx-2650", False),
    ("cx4", "12_28_2302", "cx4-1228", True),
    ("cx5", "16_27_6120", "cx5", True),
    ("cx6", "20_43_8016", "cx6-2043", False),
]


@pytest.mark.parametrize("family,ver,name,off_version", PROFILE_FOR_CASES)
def test_profile_for_mapping(family, ver, name, off_version):
    assert profile_for(family, ver) == (name, off_version)


def test_profile_for_covers_all_manifest_images():
    for ref in T1 + T2 + T3:
        name, off_version = profile_for(ref.family, ref.ver)
        assert isinstance(name, str) and name
        assert isinstance(off_version, bool)


def test_recount_delta_drift_on_new_op():
    profile = load_profile("cx5")
    dc = pack(0x00000000, 0xD8000000, 0xF4000000, 0xF4010000)
    delta = recount_delta(dc, profile)
    assert delta["new_ops"] == ["0x3d"]
    assert delta["counts"] == {"0x36": 1, "0x3d": 2}
    assert delta["flag"] == PROFILE_DRIFT


def test_recount_delta_no_drift_without_new_ops():
    profile = load_profile("cx5")
    dc = pack(0x00000000, 0xD8000000, 0xD0000000, 0xFFFFFFFF, 0xFEC5B008)
    delta = recount_delta(dc, profile)
    assert delta["new_ops"] == []
    assert delta["counts"] == {"0x34": 1, "0x36": 1}
    assert delta["flag"] is None


def test_recount_delta_empty():
    assert recount_delta(b"", load_profile("cx5")) == {
        "new_ops": [], "counts": {}, "flag": None}


def test_recount_delta_lines_match_derived():
    dc = pack(0xD0000000, 0x00000000, 0xF4000000, 0xD8000000)
    profile = load_profile("cx5")
    lines = disasm_section(dc, 0x21000000)
    assert recount_delta(dc, profile) == recount_delta(
        dc, profile, lines=lines)


def test_disasm_stage_lines_single_pass_matches_derived():
    dc = pack(0xD0000000, 0x00000000, 0xF4000000)
    lines = disasm_section(dc, 0x21000000)
    derived = disasm_stage(dc, 0x21000000, "cx5", "16_35_4030")
    threaded = disasm_stage(dc, 0x21000000, "cx5", "16_35_4030",
                            lines=lines)
    assert derived == threaded


def test_disasm_txt_annotates_census_ops():
    profile = load_profile("cx5")
    text = disasm_txt(pack(0xD0000000), 0, profile)
    assert text == (
        "00000000  d0000000  op0x34 zero,zero,zero imm=0x0000"
        " ; [cx5] Phase I0 static: reg-reg bit-ops")


def test_disasm_txt_none_profile_is_plain_join():
    dc = pack(0xD0000000, 0x00000000)
    text = disasm_txt(dc, 0x100, None)
    assert text == "\n".join(l["text"] for l in disasm_section(dc, 0x100))


def test_disasm_stage_profile_absent_guard(monkeypatch):
    from scripts.irisc.profiles import ProfileError

    def missing(name):
        raise ProfileError("unknown profile %r" % name)

    monkeypatch.setattr(disasm_build, "load_profile", missing)
    dc = pack(0xD0000000)
    result = disasm_stage(dc, 0, "cx4", "12_28_4706")
    assert result["profile"] == "cx4-1228"
    assert result["status"] == PROFILE_ABSENT
    assert result["off_version"] is False
    assert result["delta"] is None
    assert result["drift"] is False
    assert result["text"] == disasm_section(dc, 0)[0]["text"]


def test_disasm_stage_ok_with_drift():
    dc = pack(0xF4000000, 0xD8000000)
    result = disasm_stage(dc, 0, "cx5", "16_35_4030")
    assert result["profile"] == "cx5"
    assert result["status"] == "OK"
    assert result["off_version"] is False
    assert result["delta"]["new_ops"] == ["0x3d"]
    assert result["drift"] is True
    assert result["text"] == disasm_txt(dc, 0, load_profile("cx5"))


def test_disasm_stage_off_version_anchor():
    result = disasm_stage(pack(0xD8000000), 0, "cx6dx", "22_47_3576")
    assert result["profile"] == "cx6dx"
    assert result["off_version"] is True
    assert result["status"] == "OK"
    assert result["drift"] is False
