#!/usr/bin/env python3
"""Apply a MAIN_CODE patch spec to an FS3/FS4 image (offline).

Spec JSON: {"id", "card", "section": 3, "patches": [
  {"offset": "0x…", "bytes": "AA BB", "expected_before": "CC DD",
   "kind": "data|code", "note": "..."}]}
Offsets are MAIN_CODE **dc** offsets — de-framed code view for clcrc=1
sections (== Ghidra addresses of the dc project). Pipeline per
scripts/irisc/build_4030_patch.py: decrc -> check/patch dc bytes ->
re-clcrc frame (64 code + 2 pad 00 + 2 clcrc LE16 per line, tail kept) ->
mlxfwutil.patch_sections (ITOC entry CRC) -> mlxfwutil.py verify (deep,
incl. per-line clcrc).
"""
import argparse
import json
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))
from mlxfwutil import Image, clcrc_calc, patch_sections  # noqa: E402
from iron_boot_probe import decrc  # noqa: E402

CLCRC_LINE = 68
CODE_LINE = 64


def deframe(raw: bytes, clcrc: int):
    if not clcrc:
        return raw, b""
    n = len(raw) // CLCRC_LINE
    return decrc(raw), raw[n * CLCRC_LINE:]


def reframe(code: bytes, tail: bytes) -> bytes:
    assert len(code) % CODE_LINE == 0, len(code)
    out = bytearray()
    for i in range(len(code) // CODE_LINE):
        line = bytearray(code[i * CODE_LINE:(i + 1) * CODE_LINE]) + b"\x00\x00"
        line += struct.pack("<H", clcrc_calc(bytes(line)))
        out += line
    return bytes(out) + tail


def check_spec(spec: dict, img: Image) -> list:
    errs = []
    sect = int(spec["section"])
    e = img.find_entry("ITOC", sect)
    code, _tail = deframe(img.section_data(e), e.clcrc)
    for p in spec["patches"]:
        off = int(p["offset"], 0)
        new = bytes.fromhex(p["bytes"].replace(" ", ""))
        exp = p.get("expected_before")
        if exp:
            cur = code[off:off + len(new)].hex()
            if cur != exp.replace(" ", ""):
                errs.append(f"CHECK FAIL 0x{sect:x}+dc 0x{off:x}: "
                            f"expected {exp.replace(' ', '')} got {cur}")
        if off + len(new) > len(code):
            errs.append(f"OUT OF RANGE 0x{sect:x}+dc 0x{off:x}+{len(new):#x} "
                        f"> code {len(code):#x}")
    return errs


def apply_spec(spec: dict, in_path: Path, out_path: Path) -> int:
    img = Image(Path(in_path).read_bytes(), str(in_path))
    sect = int(spec["section"])
    e = img.find_entry("ITOC", sect)
    raw = img.section_data(e)
    code, tail = deframe(raw, e.clcrc)
    if e.clcrc and reframe(code, tail) != raw:
        raise ValueError("reframe round-trip FAILED on stock section")
    code = bytearray(code)
    for p in spec["patches"]:
        off = int(p["offset"], 0)
        new = bytes.fromhex(p["bytes"].replace(" ", ""))
        code[off:off + len(new)] = new
    new_raw = reframe(bytes(code), tail) if e.clcrc else bytes(code)
    out = patch_sections(img, [(sect, 0, new_raw)])
    Path(out_path).write_bytes(out)
    r = subprocess.run([sys.executable, str(REPO / "mlxfwutil.py"),
                        "verify", str(out_path)],
                       capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spec")
    ap.add_argument("image")
    ap.add_argument("-o", "--out")
    ap.add_argument("--check-only", action="store_true")
    a = ap.parse_args(argv)
    spec = json.loads(Path(a.spec).read_text())
    img = Image(Path(a.image).read_bytes(), a.image)
    errs = check_spec(spec, img)
    for e in errs:
        print(e, file=sys.stderr)
    if errs:
        print(f"RESULT: FAIL ({len(errs)} check error(s))", file=sys.stderr)
        return 1
    if a.check_only:
        print("RESULT: PASS (spec checks OK)")
        return 0
    if not a.out:
        print("error: -o/--out required for apply", file=sys.stderr)
        return 2
    return apply_spec(spec, Path(a.image), Path(a.out))


if __name__ == "__main__":
    sys.exit(main())
