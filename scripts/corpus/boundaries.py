import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.irisc.irisc_dis import s16, s24

_CALL_OP = 0x25
_JUMP_FLAG = 1 << 24
_BRANCH_OPS = (0x28, 0x29, 0x2A, 0x2B)
_RET_OP = 0x3F
_RET_FUNCTS = (0x25, 0x2D)
_ST_AUTOINC_OP = 0x1C


def is_call(w):
    return w >> 26 == _CALL_OP and not w & _JUMP_FLAG


def is_jump(w):
    if w >> 26 == _CALL_OP:
        return bool(w & _JUMP_FLAG)
    return w >> 26 in _BRANCH_OPS


def is_ret(w):
    return w >> 26 == _RET_OP and w & 0x1FF in _RET_FUNCTS


def is_frame_push(w):
    return w >> 26 == _ST_AUTOINC_OP and w & 3 == 2


def call_target(dc, w):
    return (dc + s24(w) * 4) & 0xFFFFFFFF


def jump_target(dc, w):
    if w >> 26 == _CALL_OP:
        return (dc + s24(w) * 4) & 0xFFFFFFFF
    return (dc + s16(w) * 4) & 0xFFFFFFFF


def call_sites(lines):
    return [(l["dc"], call_target(l["dc"], l["w"]))
            for l in lines if is_call(l["w"])]


def jump_sites(lines):
    return [(l["dc"], jump_target(l["dc"], l["w"]))
            for l in lines if is_jump(l["w"])]


def block_name(start_dc):
    return "block_%x" % start_dc


@dataclass
class FuncBoundary:
    entry_dc: int
    end_dc: int
    size_words: int
    frame_push_count: int


@dataclass
class Functions:
    funcs: list
    blocks: list
    metrics: dict


def _uncovered_blocks(dcs, spans):
    in_func = set()
    for entry, end in spans:
        in_func.update(range(entry, end + 1, 4))
    runs = []
    for dc in dcs:
        if dc in in_func:
            continue
        if runs and dc == runs[-1][1] + 4:
            runs[-1][1] = dc
        else:
            runs.append([dc, dc])
    return [(start, end) for start, end in runs]


def find_functions(lines, entries):
    by_dc = {l["dc"]: l for l in lines}
    dcs = sorted(by_dc)
    calls = call_sites(lines)
    entry_dcs = {e for e in entries if e in by_dc}
    entry_dcs.update(t for _, t in calls if t in by_dc)
    ordered = sorted(entry_dcs)
    funcs = []
    for i, entry in enumerate(ordered):
        limit = ordered[i + 1] if i + 1 < len(ordered) else dcs[-1] + 4
        last_ret = None
        dc = entry
        while dc < limit:
            if is_ret(by_dc[dc]["w"]):
                last_ret = dc
            dc += 4
        end = last_ret if last_ret is not None else limit - 4
        pushes = 0
        dc = entry
        while dc <= end:
            if is_frame_push(by_dc[dc]["w"]):
                pushes += 1
            dc += 4
        funcs.append(FuncBoundary(entry, end, (end - entry) // 4 + 1, pushes))
    blocks = _uncovered_blocks(dcs, [(f.entry_dc, f.end_dc) for f in funcs])
    words_in_funcs = sum(f.size_words for f in funcs)
    targets = {t for _, t in calls if t in by_dc}
    on_prologue = sum(1 for t in targets if is_frame_push(by_dc[t]["w"]))
    metrics = {
        "words_in_bounds_ratio":
            words_in_funcs / len(lines) if lines else 0.0,
        "call_targets_on_prologue_ratio":
            on_prologue / len(targets) if targets else 1.0,
        "n_funcs": len(funcs),
        "n_blocks": len(blocks),
    }
    return Functions(funcs, blocks, metrics)


def write_funcs_tsv(lines, functions, path):
    callers = Counter(t for _, t in call_sites(lines))
    rows = ["entry_dc\tend_dc\tsize_words\tframe\tn_callers"]
    for f in sorted(functions.funcs, key=lambda f: f.entry_dc):
        rows.append("0x%x\t0x%x\t%d\t%d\t%d" % (
            f.entry_dc, f.end_dc, f.size_words, f.frame_push_count,
            callers.get(f.entry_dc, 0)))
    Path(path).write_text("\n".join(rows) + "\n")
