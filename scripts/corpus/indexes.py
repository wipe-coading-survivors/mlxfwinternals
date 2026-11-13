import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.corpus.boundaries import call_target, is_call, is_jump, jump_target
from scripts.irisc.irisc_dis import s14, s16, storeoff

_LD_I_OP = 0x12
_LD_I_FLAG = 1 << 25
_LD_D_OP = 0x19
_ST_D_OP = 0x1B
_D_WIDTH = 2
_IMM_HIST_OPS = frozenset(range(0x00, 0x0F))
_MIN_TABLE_WORDS = 8
_MIN_STR_LEN = 4
_PRINTABLE_LO = 0x20
_PRINTABLE_HI = 0x7E


@dataclass
class CallRec:
    site_dc: int
    target_dc: int
    target_section: str | None


@dataclass
class XrefRec:
    dc: int
    kind: str
    value: int


@dataclass
class ConstRec:
    value: int
    count: int


def is_ld_i(w):
    return w >> 26 == _LD_I_OP and w & _LD_I_FLAG


def is_ld_d(w):
    return w >> 26 == _LD_D_OP and w & 3 == _D_WIDTH


def is_st_d(w):
    return w >> 26 == _ST_D_OP and w & 3 == _D_WIDTH


def mem_offset(w):
    if w >> 26 == _LD_D_OP:
        return s14(w >> 2) * 4
    return storeoff(w, 2)


def ram_word(w):
    return (w & 0xFFFF) << 2


def _section_for(dc, windows):
    for name, start, end in windows:
        if start <= dc < end:
            return name
    return None


def build_calls(lines, section_windows=None):
    windows = section_windows if section_windows is not None else []
    recs = []
    for line in lines:
        if not is_call(line["w"]):
            continue
        target = call_target(line["dc"], line["w"])
        recs.append(CallRec(line["dc"], target, _section_for(target, windows)))
    return recs


def build_xref(lines):
    recs = []
    for line in lines:
        dc, w = line["dc"], line["w"]
        if is_call(w):
            recs.append(XrefRec(dc, "call_target", call_target(dc, w)))
        elif is_jump(w):
            recs.append(XrefRec(dc, "jump_target", jump_target(dc, w)))
        elif is_ld_i(w):
            recs.append(XrefRec(dc, "ram_word", ram_word(w)))
        elif is_ld_d(w) or is_st_d(w):
            recs.append(XrefRec(dc, "abs_addr", mem_offset(w)))
    return recs


def build_consts(lines):
    hist = Counter()
    for line in lines:
        w = line["w"]
        if w >> 26 in _IMM_HIST_OPS or is_ld_i(w):
            hist[s16(w)] += 1
    ordered = sorted(hist.items(), key=lambda kv: (-kv[1], kv[0]))
    return [ConstRec(value, count) for value, count in ordered]


def dense_tables(dc):
    tables = []
    run_start = None
    n_words = len(dc) // 4
    for i in range(n_words):
        if int.from_bytes(dc[i * 4:i * 4 + 4], "big"):
            if run_start is None:
                run_start = i
        elif run_start is not None:
            if i - run_start >= _MIN_TABLE_WORDS:
                tables.append((run_start * 4, i - run_start))
            run_start = None
    if run_start is not None and n_words - run_start >= _MIN_TABLE_WORDS:
        tables.append((run_start * 4, n_words - run_start))
    return tables


def build_strings(dc):
    out = []
    start = None
    for i, b in enumerate(dc):
        if _PRINTABLE_LO <= b <= _PRINTABLE_HI:
            if start is None:
                start = i
        elif start is not None:
            if i - start >= _MIN_STR_LEN:
                out.append((start, dc[start:i].decode("ascii")))
            start = None
    if start is not None and len(dc) - start >= _MIN_STR_LEN:
        out.append((start, dc[start:].decode("ascii")))
    return out


def write_calls_tsv(calls, path):
    rows = ["site_dc\ttarget_dc\ttarget_section"]
    for c in calls:
        rows.append("0x%x\t0x%x\t%s" % (
            c.site_dc, c.target_dc, c.target_section or "-"))
    Path(path).write_text("\n".join(rows) + "\n")


def write_xref_tsv(xrefs, path):
    rows = ["dc\tkind\tvalue"]
    rows.extend("0x%x\t%s\t0x%x" % (x.dc, x.kind, x.value) for x in xrefs)
    Path(path).write_text("\n".join(rows) + "\n")


def write_consts_tsv(consts, path):
    rows = ["value\tcount"]
    rows.extend("%d\t%d" % (c.value, c.count) for c in consts)
    Path(path).write_text("\n".join(rows) + "\n")


def write_strings_txt(strings, path):
    rows = ["dc\tstring"]
    rows.extend("0x%x\t%s" % (dc, s) for dc, s in strings)
    Path(path).write_text("\n".join(rows) + "\n")
