import bisect
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.corpus.boundaries import (
    call_sites,
    is_call,
    is_frame_push,
    is_jump,
    jump_target,
)
from scripts.irisc.irisc_dis import storeoff

SKELETON_MARKER = "<!-- SKELETON: mechanical, untrusted -->"

_IMM_TOKEN_RE = re.compile(
    r"(?<![0-9A-Za-z_.])-?0x-?[0-9a-fA-F]+(?![0-9A-Za-z_])")
_LITERAL_BODY_RE = re.compile(r"^(op0x|unk\.|raw )")
_FRAME_DEALLOC_RE = re.compile(r"^addi r1,r1,(-?0x-?[0-9a-fA-F]+)$")


def _body(line):
    parts = line["text"].split("  ", 2)
    return parts[2] if len(parts) == 3 else ""


def _imm_value(token):
    if token.startswith("-0x") or token.startswith("0x-"):
        return -int(token[3:], 16)
    return int(token[2:], 16)


class _ImmNames:
    def __init__(self):
        self._by_value = {}

    def name(self, value):
        if value not in self._by_value:
            self._by_value[value] = "v%d" % len(self._by_value)
        return self._by_value[value]


def _render_body(line, names):
    body = _body(line)
    if _LITERAL_BODY_RE.match(body):
        return body
    matches = list(_IMM_TOKEN_RE.finditer(body))
    if not matches:
        return body
    skip_last = is_call(line["w"]) or is_jump(line["w"])
    if skip_last:
        matches = matches[:-1]
    out = []
    pos = 0
    for m in matches:
        out.append(body[pos:m.start()])
        out.append(names.name(_imm_value(m.group(0))))
        pos = m.end()
    out.append(body[pos:])
    return "".join(out)


def _nest_depths(flines):
    intervals = []
    for line in flines:
        if not is_jump(line["w"]):
            continue
        site, target = line["dc"], jump_target(line["dc"], line["w"])
        if target > site:
            intervals.append((site + 4, target - 4))
        else:
            intervals.append((target, site - 4))
    return {
        line["dc"]: sum(1 for lo, hi in intervals if lo <= line["dc"] <= hi)
        for line in flines
    }


def _frame_info(flines):
    pushes = [line["w"] for line in flines if is_frame_push(line["w"])]
    frame_words = abs(storeoff(pushes[0], 2)) // 4 if pushes else 0
    pops = 0
    for line in flines:
        m = _FRAME_DEALLOC_RE.match(_body(line))
        if m and _imm_value(m.group(1)) > 0:
            pops += 1
    return len(pushes), pops, frame_words


def _function_section(lines, dcs, func, n_callers):
    lo = bisect.bisect_left(dcs, func.entry_dc)
    hi = bisect.bisect_right(dcs, func.end_dc)
    flines = lines[lo:hi]
    push, pop, frame_words = _frame_info(flines)
    out = [
        "## f_%x  size=%dw  callers=%d" % (
            func.entry_dc, func.size_words, n_callers),
        "frame: push=%d pop=%d words=%d" % (push, pop, frame_words),
        "calls:",
    ]
    out.extend("- 0x%x -> 0x%x" % c for c in call_sites(flines))
    out.append("body:")
    names = _ImmNames()
    depths = _nest_depths(flines)
    for line in flines:
        out.append("%s%08x  %s" % (
            "  " * (1 + depths[line["dc"]]), line["dc"],
            _render_body(line, names)))
    return out


def _block_section(lines, dcs, start, end):
    out = ["## block_%x  size=%dw" % (start, (end - start) // 4 + 1)]
    lo = bisect.bisect_left(dcs, start)
    hi = bisect.bisect_right(dcs, end)
    for line in lines[lo:hi]:
        out.append("  %08x  raw 0x%08x" % (line["dc"], line["w"]))
    return out


def skeleton_section(lines, funcs):
    callers = Counter(target for _, target in call_sites(lines))
    out = [SKELETON_MARKER, ""]
    dcs = [line["dc"] for line in lines]
    for func in sorted(funcs.funcs, key=lambda f: f.entry_dc):
        out.extend(
            _function_section(lines, dcs, func,
                              callers.get(func.entry_dc, 0)))
        out.append("")
    for start, end in funcs.blocks:
        out.extend(_block_section(lines, dcs, start, end))
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"
