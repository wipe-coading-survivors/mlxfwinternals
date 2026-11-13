#!/usr/bin/env python3
"""Cable-speed gate bracketing: chunk diff of MAIN_CODE (0x03) between two
FS3 images. 16_35_8008 (gate present) vs 16_35_1012 (gate absent), same
board MCX512A-ACA. Offsets are MAIN_CODE section-relative.
"""
import argparse
import hashlib
import json
import sys
from difflib import SequenceMatcher
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

GATE_STRINGS = [
    b"Cable speed not enabled",
    b"FDR10 speed is not supported",
]


def main_section(img: bytes, sect: int = 0x03) -> bytes:
    im = mlxfwutil.Image(img, "img")
    se = im.find_entry("ITOC", sect)
    return im.section_data(se)


def _chunk_hashes(data: bytes, n: int):
    return [hashlib.sha1(data[i:i + n]).digest()
            for i in range(0, len(data) - n + 1, n)]


def hunk_map(a: bytes, b: bytes, n: int = 256) -> list:
    sm = SequenceMatcher(None, _chunk_hashes(a, n), _chunk_hashes(b, n),
                         autojunk=False)
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        out.append({"tag": tag,
                    "a_off": i1 * n, "a_end": min(i2 * n, len(a)),
                    "b_off": j1 * n, "b_end": min(j2 * n, len(b))})
    return out


def gate_flag(a: bytes, h: dict) -> list:
    return [s.decode() for s in GATE_STRINGS
            if s in a[h["a_off"]:h["a_end"]]]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image_a", help="image with gate (8008)")
    ap.add_argument("image_b", help="image without gate (1012)")
    ap.add_argument("--chunk", type=lambda s: int(s, 0), default=256)
    ap.add_argument("--json", metavar="OUT")
    a = ap.parse_args(argv)
    A = main_section(Path(a.image_a).read_bytes())
    B = main_section(Path(a.image_b).read_bytes())
    hunks = hunk_map(A, B, a.chunk)
    for h in hunks:
        line = (f"HUNK {h['tag']:8s} a=0x{h['a_off']:06x}-0x{h['a_end']:06x}"
                f" ({h['a_end'] - h['a_off']}B)"
                f" b=0x{h['b_off']:06x}-0x{h['b_end']:06x}")
        flags = gate_flag(A, h)
        if flags:
            line += "  GATE: " + ", ".join(flags)
        print(line)
    print(f"SUMMARY a={len(A):#x} b={len(B):#x} hunks={len(hunks)}")
    if a.json:
        Path(a.json).write_text(json.dumps(
            {"a_size": len(A), "b_size": len(B),
             "hunks": [{**h, "gate": gate_flag(A, h)} for h in hunks]},
            indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
