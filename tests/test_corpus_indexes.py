import struct
import sys
from dataclasses import fields
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.corpus.disasm_build import disasm_section  # noqa: E402
from scripts.corpus.indexes import (  # noqa: E402
    CallRec,
    ConstRec,
    XrefRec,
    build_calls,
    build_consts,
    build_strings,
    build_xref,
    dense_tables,
    write_calls_tsv,
    write_consts_tsv,
    write_strings_txt,
    write_xref_tsv,
)
from scripts.irisc import disasm  # noqa: E402

BASE = 0x1000
RET_R = 0xFC000025


def w_call(dc, target):
    return (0x25 << 26) | (((target - dc) // 4) & 0xFFFFFF)


def w_jump(dc, target):
    return (0x25 << 26) | (1 << 24) | (((target - dc) // 4) & 0xFFFFFF)


def w_bt(dc, target, cc=0x10):
    return (0x28 << 26) | (cc << 16) | (((target - dc) // 4) & 0xFFFF)


def w_addi(rd, rs, imm):
    return (0x00 << 26) | (rs << 21) | (rd << 16) | (imm & 0xFFFF)


def w_ld_i(rd, imm):
    return (0x12 << 26) | (1 << 25) | (rd << 16) | (imm & 0xFFFF)


def w_ld_d(rs, rd, off):
    return (0x19 << 26) | (rs << 21) | (rd << 16) | (off & 0xFFFC) | 2


def w_st_d(rs, rt, off):
    return (0x1B << 26) | (rs << 21) | (((off >> 11) & 0x1F) << 16) | \
        (rt << 11) | (off & 0x7FC) | 2


def pack(*words):
    return struct.pack(">%dI" % len(words), *words)


def lines_of(base, words):
    return disasm_section(pack(*words), base)


def test_word_builders_match_dis_render():
    assert disasm(w_ld_i(5, 0x2B5), 0) == "ld.i r5,0x2b5"
    assert disasm(w_ld_d(1, 5, 0x220), 0) == "ld.d r5,r1,0x220"
    assert disasm(w_st_d(1, 4, 0x1230), 0) == "st.d r4,r1,0x1230"
    assert disasm(w_call(BASE, 0x1020), BASE) == "call 0x1020"
    assert disasm(w_bt(BASE + 8, BASE), BASE + 8) == "b.t.0x10 zero,0x1000"


def test_plan_interface_shapes():
    assert [f.name for f in fields(CallRec)] == [
        "site_dc", "target_dc", "target_section"]
    assert [f.name for f in fields(XrefRec)] == ["dc", "kind", "value"]
    assert [f.name for f in fields(ConstRec)] == ["value", "count"]


def test_build_calls_default_no_windows():
    lines = lines_of(BASE, [
        w_call(BASE, 0x1020),
        w_jump(BASE + 4, BASE + 0x10),
        w_call(BASE + 8, 0x5000),
    ])
    assert build_calls(lines) == [
        CallRec(BASE, 0x1020, None),
        CallRec(BASE + 8, 0x5000, None),
    ]


def test_build_calls_section_windows():
    lines = lines_of(BASE, [
        w_call(BASE, 0x1020),
        w_call(BASE + 4, 0x5000),
        w_call(BASE + 8, 0x99998),
    ])
    windows = [("BOOT2", 0x0, 0x100), ("MAIN", 0x4000, 0x8000)]
    assert build_calls(lines, windows) == [
        CallRec(BASE, 0x1020, None),
        CallRec(BASE + 4, 0x5000, "MAIN"),
        CallRec(BASE + 8, 0x99998, None),
    ]


def test_section_window_end_exclusive():
    lines = lines_of(BASE, [w_call(BASE, 0x2000)])
    assert build_calls(lines, [("S", 0x1000, 0x2000)]) == [
        CallRec(BASE, 0x2000, None)]
    assert build_calls(lines, [("S", 0x1000, 0x2004)]) == [
        CallRec(BASE, 0x2000, "S")]


def test_build_xref_kinds():
    lines = lines_of(BASE, [
        w_call(BASE, 0x1020),
        w_jump(BASE + 4, BASE + 0x10),
        w_bt(BASE + 8, BASE + 4),
        w_ld_i(5, 0x2B5),
        w_ld_d(1, 5, 0x220),
        w_st_d(1, 4, 0x1230),
        RET_R,
    ])
    assert build_xref(lines) == [
        XrefRec(BASE, "call_target", 0x1020),
        XrefRec(BASE + 4, "jump_target", BASE + 0x10),
        XrefRec(BASE + 8, "jump_target", BASE + 4),
        XrefRec(BASE + 0xC, "ram_word", 0xAD4),
        XrefRec(BASE + 0x10, "abs_addr", 0x220),
        XrefRec(BASE + 0x14, "abs_addr", 0x1230),
    ]


def test_build_consts_imm_histogram():
    lines = lines_of(BASE, [
        w_addi(2, 3, 0x77),
        w_ld_i(5, 0x2B5),
        w_addi(6, 7, 0x77),
        w_addi(8, 9, 0x11),
        w_st_d(1, 4, 0x1230),
        w_bt(BASE + 0x18, BASE),
    ])
    assert build_consts(lines) == [
        ConstRec(0x77, 2),
        ConstRec(0x11, 1),
        ConstRec(0x2B5, 1),
    ]


def test_build_consts_signed_imm():
    lines = lines_of(BASE, [w_addi(2, 3, 0xFFFF), w_addi(4, 5, 0xFFFF)])
    assert build_consts(lines) == [ConstRec(-1, 2)]


def test_dense_tables():
    dc = pack(*([0, 0] + [0xA1] * 8 + [0] + [0xB2] * 7 + [0] + [0xC3] * 8)) + \
        b"\xab\xcd"
    assert dense_tables(dc) == [(8, 8), (76, 8)]


def test_dense_tables_exact_minimum():
    assert dense_tables(pack(*[1] * 8)) == [(0, 8)]
    assert dense_tables(pack(*[1] * 7)) == []


def test_build_strings():
    dc = b"\x00\x01hell\x02o world\x00xyz\x00"
    assert build_strings(dc) == [(2, "hell"), (7, "o world")]
    assert build_strings(b"abcd") == [(0, "abcd")]
    assert build_strings(b"abc") == []


def test_empty_inputs():
    assert build_calls([]) == []
    assert build_xref([]) == []
    assert build_consts([]) == []
    assert dense_tables(b"") == []
    assert build_strings(b"") == []


def test_artifact_writers(tmp_path):
    lines = lines_of(BASE, [w_call(BASE, 0x5000), w_ld_i(5, 0x2B5)])
    calls = build_calls(lines, [("MAIN", 0x4000, 0x8000)]) + \
        build_calls(lines_of(BASE + 4, [w_call(BASE + 4, 0x99998)]))
    p_calls = tmp_path / "calls.tsv"
    write_calls_tsv(calls, p_calls)
    assert p_calls.read_text() == (
        "site_dc\ttarget_dc\ttarget_section\n"
        "0x1000\t0x5000\tMAIN\n"
        "0x1004\t0x99998\t-\n"
    )
    p_xref = tmp_path / "xref.tsv"
    write_xref_tsv(build_xref(lines), p_xref)
    assert p_xref.read_text() == (
        "dc\tkind\tvalue\n"
        "0x1000\tcall_target\t0x5000\n"
        "0x1004\tram_word\t0xad4\n"
    )
    p_consts = tmp_path / "consts.tsv"
    write_consts_tsv(build_consts(lines), p_consts)
    assert p_consts.read_text() == (
        "value\tcount\n"
        "693\t1\n"
    )
    p_str = tmp_path / "strings.txt"
    write_strings_txt(build_strings(b"\x00hi there"), p_str)
    assert p_str.read_text() == (
        "dc\tstring\n"
        "0x1\thi there\n"
    )
