import struct
import sys
from dataclasses import fields
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.corpus.boundaries import (  # noqa: E402
    FuncBoundary,
    Functions,
    block_name,
    call_sites,
    find_functions,
    is_call,
    is_frame_push,
    is_ret,
    jump_sites,
    write_funcs_tsv,
)
from scripts.corpus.disasm_build import disasm_section  # noqa: E402
from scripts.irisc import disasm  # noqa: E402

PUSH = 0x703F27FA
RET_R = 0xFC000025
RET_D = 0xFC00002D
ADDI = 0x00000000
DATA = 0xDEADBEEF


def w_call(dc, target):
    return (0x25 << 26) | (((target - dc) // 4) & 0xFFFFFF)


def w_jump(dc, target):
    return (0x25 << 26) | (1 << 24) | (((target - dc) // 4) & 0xFFFFFF)


def w_bt(dc, target, cc=0x10):
    return (0x28 << 26) | (cc << 16) | (((target - dc) // 4) & 0xFFFF)


def pack(*words):
    return struct.pack(">%dI" % len(words), *words)


def lines_of(base, words):
    return disasm_section(pack(*words), base)


def test_word_builders_match_dis_render():
    assert disasm(PUSH, 0) == "st.d! r4,r1,-0x8"
    assert disasm(RET_R, 0) == "ret.r zero,zero,zero"
    assert disasm(RET_D, 0) == "ret.d zero,zero,zero"
    assert disasm(w_call(0x1D594, 0x1E10C), 0x1D594) == "call 0x1e10c"
    assert disasm(w_jump(0x1D598, 0x1D598), 0x1D598) == "jump 0x1d598"
    assert disasm(w_bt(0x9176C, 0x91774), 0x9176C) == "b.t.0x10 zero,0x91774"


def test_predicates():
    assert is_call(w_call(0, 0x10))
    assert not is_call(w_jump(0, 0x10))
    assert not is_call(PUSH)
    assert is_frame_push(PUSH)
    assert not is_frame_push(0x6C201806)
    assert not is_frame_push(0x70201806 | 1)
    assert is_ret(RET_R)
    assert is_ret(RET_D)
    assert not is_ret(0xFE850008)


def test_plan_interface_shapes():
    assert [f.name for f in fields(FuncBoundary)] == [
        "entry_dc", "end_dc", "size_words", "frame_push_count"]
    assert [f.name for f in fields(Functions)] == ["funcs", "blocks", "metrics"]


def test_two_functions_and_data_block():
    A = 0x1000
    B = 0x1014
    lines = lines_of(A, [
        PUSH,
        w_call(0x1004, B),
        RET_R,
        DATA,
        DATA,
        PUSH,
        RET_R,
    ])
    res = find_functions(lines, [A])
    assert res.funcs == [
        FuncBoundary(A, 0x1008, 3, 1),
        FuncBoundary(B, 0x1018, 2, 1),
    ]
    assert res.blocks == [(0x100C, 0x1010)]
    assert block_name(0x100C) == "block_100c"
    assert res.metrics["n_funcs"] == 2
    assert res.metrics["n_blocks"] == 1
    assert res.metrics["words_in_bounds_ratio"] == pytest.approx(5 / 7)
    assert res.metrics["call_targets_on_prologue_ratio"] == 1.0


def test_call_target_not_on_prologue_reflected_in_metrics():
    lines = lines_of(0x2000, [
        ADDI,
        w_call(0x2004, 0x200C),
        RET_R,
        RET_R,
    ])
    res = find_functions(lines, [0x2000])
    assert res.funcs == [
        FuncBoundary(0x2000, 0x2008, 3, 0),
        FuncBoundary(0x200C, 0x200C, 1, 0),
    ]
    assert res.blocks == []
    assert res.metrics["words_in_bounds_ratio"] == 1.0
    assert res.metrics["call_targets_on_prologue_ratio"] == 0.0


def test_branches_do_not_create_entries():
    lines = lines_of(0x3000, [
        PUSH,
        w_bt(0x3004, 0x3000),
        RET_R,
        w_jump(0x300C, 0x3000),
        DATA,
    ])
    res = find_functions(lines, [0x3000])
    assert res.funcs == [FuncBoundary(0x3000, 0x3008, 3, 1)]
    assert res.blocks == [(0x300C, 0x3010)]
    assert res.metrics["n_funcs"] == 1
    assert res.metrics["n_blocks"] == 1


def test_multiple_ret_r_last_one_ends_function():
    lines = lines_of(0x4000, [
        PUSH,
        RET_R,
        w_call(0x4008, 0x4014),
        RET_R,
        PUSH,
        RET_R,
    ])
    res = find_functions(lines, [0x4000])
    assert res.funcs == [
        FuncBoundary(0x4000, 0x400C, 4, 1),
        FuncBoundary(0x4014, 0x4014, 1, 0),
    ]
    assert res.blocks == [(0x4010, 0x4010)]


def test_function_without_ret_ends_at_next_entry():
    lines = lines_of(0x5000, [PUSH, ADDI, RET_R])
    res = find_functions(lines, [0x5000, 0x5008])
    assert res.funcs == [
        FuncBoundary(0x5000, 0x5004, 2, 1),
        FuncBoundary(0x5008, 0x5008, 1, 0),
    ]
    assert res.blocks == []
    assert res.metrics["words_in_bounds_ratio"] == 1.0


def test_out_of_section_targets_and_entries_dropped():
    lines = lines_of(0x6000, [PUSH, w_call(0x6004, 0x99999), RET_R])
    res = find_functions(lines, [0x6000, 0x88888])
    assert res.funcs == [FuncBoundary(0x6000, 0x6008, 3, 1)]
    assert res.blocks == []
    assert res.metrics["call_targets_on_prologue_ratio"] == 1.0


def test_empty_lines():
    res = find_functions([], [0x1000])
    assert res.funcs == []
    assert res.blocks == []
    assert res.metrics == {
        "words_in_bounds_ratio": 0.0,
        "call_targets_on_prologue_ratio": 1.0,
        "n_funcs": 0,
        "n_blocks": 0,
    }


def test_call_and_jump_site_extraction():
    lines = lines_of(0, [w_call(0, 0x10), w_jump(4, 0x20), w_bt(8, 0x1C)])
    assert call_sites(lines) == [(0x0, 0x10)]
    assert jump_sites(lines) == [(0x4, 0x20), (0x8, 0x1C)]


def test_funcs_tsv_writer(tmp_path):
    R = 0x7010
    lines = lines_of(0x7000, [
        PUSH,
        w_call(0x7004, R),
        w_call(0x7008, R),
        RET_R,
        PUSH,
        RET_R,
    ])
    res = find_functions(lines, [0x7000])
    out = tmp_path / "funcs.tsv"
    write_funcs_tsv(lines, res, out)
    assert out.read_text() == (
        "entry_dc\tend_dc\tsize_words\tframe\tn_callers\n"
        "0x7000\t0x700c\t4\t1\t0\n"
        "0x7010\t0x7014\t2\t1\t2\n"
    )


def test_ret_d_epilogue_ends_function_before_gap():
    lines = lines_of(0x8000, [PUSH, ADDI, RET_D, DATA, DATA])
    res = find_functions(lines, [0x8000])
    assert res.funcs == [FuncBoundary(0x8000, 0x8008, 3, 1)]
    assert res.blocks == [(0x800C, 0x8010)]
    assert res.metrics["n_blocks"] == 1
    assert res.metrics["words_in_bounds_ratio"] == pytest.approx(3 / 5)


def test_ret_d_epilogue_wins_over_interior_ret_r():
    lines = lines_of(0x9000, [PUSH, RET_R, ADDI, RET_D, DATA])
    res = find_functions(lines, [0x9000])
    assert res.funcs == [FuncBoundary(0x9000, 0x900C, 4, 1)]
    assert res.blocks == [(0x9010, 0x9010)]

