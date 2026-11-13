import json
import re
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.corpus.boundaries import find_functions  # noqa: E402
from scripts.corpus.disasm_build import disasm_section  # noqa: E402
from scripts.corpus.skeleton import SKELETON_MARKER, skeleton_section  # noqa: E402

GOLDEN = Path(__file__).parent / "fixtures" / "corpus" / "golden"

SYNTH_WORDS = [
    0x480300BC, 0x703F0FDA, 0x00050001, 0x00060002, 0xA0000004,
    0x00050001, 0x94000020, 0xFD494808, 0x00210028, 0xFD001825,
    0x11223344, 0xDEADBEE0, 0x00000001, 0x00000002, 0xCAFEBABE,
    0x00000000,
]

SYNTH_EXPECTED = """\
<!-- SKELETON: mechanical, untrusted -->

## f_1000  size=10w  callers=0
frame: push=1 pop=1 words=10
calls:
- 0x1018 -> 0x1098
body:
  00001000  csr.r r3,csr0xbc
  00001004  st.d! r1,r1,v0
  00001008  addi r5,zero,v1
  0000100c  addi r6,zero,v2
  00001010  b.t.0x0 zero,0x1020
    00001014  addi r5,zero,v1
    00001018  call 0x1098
    0000101c  or r9,r10,r9
  00001020  addi r1,r1,v3
  00001024  ret.r zero,r8,r3

## block_1028  size=6w
  00001028  raw 0x11223344
  0000102c  raw 0xdeadbee0
  00001030  raw 0x00000001
  00001034  raw 0x00000002
  00001038  raw 0xcafebabe
  0000103c  raw 0x00000000
"""


def synth_lines(words, base=0x1000):
    blob = struct.pack(">%dI" % len(words), *words)
    return disasm_section(blob, base)


def load_golden_lines(name, entry_dc):
    hex_path = GOLDEN / (name + ".hex")
    words = [int(tok, 16) for tok in hex_path.read_text().split()]
    blob = struct.pack(">%dI" % len(words), *words)
    return disasm_section(blob, entry_dc)


def parse_function_block(md, entry_dc):
    header = "## f_%x  " % entry_dc
    lines = md.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith(header))
    block = {"calls": [], "push": 0, "pop": 0, "frame_words": 0,
             "size_words": 0}
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        if line.startswith("frame: push="):
            frame = line[len("frame: push="):]
            push, rest = frame.split(" pop=")
            pop, words = rest.split(" words=")
            block["push"] = int(push)
            block["pop"] = int(pop)
            block["frame_words"] = int(words)
        elif line.startswith("- 0x") and " -> 0x" in line:
            site, target = line[2:].split(" -> ")
            block["calls"].append((site, target))
    head = lines[start]
    m = re.match(r"## f_[0-9a-f]+  size=(\d+)w  callers=(\d+)$", head)
    block["size_words"] = int(m.group(1))
    return block


def test_synthetic_function_exact_block():
    lines = synth_lines(SYNTH_WORDS)
    funcs = find_functions(lines, entries=[0x1000])
    assert skeleton_section(lines, funcs) == SYNTH_EXPECTED


def test_marker_is_first_line():
    lines = synth_lines([0xFD001825])
    funcs = find_functions(lines, entries=[0x1000])
    md = skeleton_section(lines, funcs)
    assert md.splitlines()[0] == SKELETON_MARKER
    assert md.count(SKELETON_MARKER) == 1


@pytest.mark.parametrize("name,entry_dc", [
    ("sha256_transform", 0x2B13B0),
    ("apply_stamping_ib", 0x25A2F0),
    ("lx_serializer", 0x2A48AC),
])
def test_golden_skeleton_reproduces_doc_expectations(name, entry_dc):
    lines = load_golden_lines(name, entry_dc)
    funcs = find_functions(lines, entries=[entry_dc])
    md = skeleton_section(lines, funcs)
    exp = json.loads((GOLDEN / ("expected_%s.json" % name)).read_text())
    assert md.splitlines()[0] == SKELETON_MARKER
    block = parse_function_block(md, entry_dc)
    assert block["size_words"] == exp["size_words"]
    assert block["push"] == exp["frame_push_count"]
    assert block["frame_words"] == exp["frame_words"]
    assert block["calls"] == [(site, target) for site, target in exp["calls"]]


@pytest.mark.parametrize("name,entry_dc", [
    ("sha256_transform", 0x2B13B0),
    ("apply_stamping_ib", 0x25A2F0),
    ("lx_serializer", 0x2A48AC),
])
def test_golden_fixture_size_limit(name, entry_dc):
    hex_path = GOLDEN / (name + ".hex")
    assert hex_path.stat().st_size <= 2048
    assert all(len(tok) == 8 for tok in hex_path.read_text().split())
