#!/usr/bin/env python3
"""iRISC load-grid scanner: enumerate data loads (ld.d/ld.b/lw.r) in
MAIN_CODE and compute effective addresses for a candidate data-base.

Ops (docs/250-re/120-irisc/010-isa.md, docs/250-re/130-cable-gate/010-wall.md): ld.d op 0x19 = RS + OFF14 (signed, x4);
ld.b op 0x18 = RS + simm16 (byte, signed); lw.r op 0x3f = [ram](RS + RT)
(register offset — recorded as a pair, no immediate).

Input is the DE-FRAMED (decrc) code view: MAIN_CODE 0x03 of 4030 is
clcrc-framed (68B lines = 64 code + 2 pad + 2 clcrc); scanning the raw
section would decode pad/clcrc bytes as instructions. dc offsets here ==
Ghidra addresses of the de-framed project.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import mlxfwutil  # noqa: E402
from iron_boot_probe import decrc  # noqa: E402


def _s(v: int, bits: int) -> int:
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def scan_loads(data: bytes) -> list:
    out = []
    for dc in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[dc:dc + 4], "big")
        op = (w >> 26) & 0x3F
        if op == 0x19:
            out.append({"dc": dc, "op": "ld.d",
                        "rs": (w >> 21) & 0x1F, "rd": (w >> 16) & 0x1F,
                        "off": _s(w & 0x3FFF, 14) * 4})
        elif op == 0x18:
            out.append({"dc": dc, "op": "ld.b",
                        "rs": (w >> 21) & 0x1F, "rd": (w >> 16) & 0x1F,
                        "off": _s(w & 0xFFFF, 16)})
        elif op == 0x3F:
            out.append({"dc": dc, "op": "lw.r",
                        "rs": (w >> 21) & 0x1F, "rt": (w >> 16) & 0x1F,
                        "off": None})
    return out


def hits(data: bytes, base: int, lo: int, hi: int, rs: int = None) -> list:
    out = []
    for e in scan_loads(data):
        if e["off"] is None or (rs is not None and e["rs"] != rs):
            continue
        eff = base + e["off"]
        if lo <= eff < hi:
            out.append({**e, "eff": eff})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image")
    ap.add_argument("--base", type=lambda s: int(s, 0),
                    help="candidate data-base value")
    ap.add_argument("--lo", type=lambda s: int(s, 0))
    ap.add_argument("--hi", type=lambda s: int(s, 0))
    ap.add_argument("--rs", type=lambda s: int(s, 0),
                    help="filter by base register (RS field)")
    ap.add_argument("--json", metavar="OUT")
    a = ap.parse_args(argv)
    im = mlxfwutil.Image(Path(a.image).read_bytes(), a.image)
    e = im.find_entry("ITOC", 0x03)
    raw = im.section_data(e)
    data = decrc(raw) if e.clcrc else raw
    loads = scan_loads(data)
    per_op, per_rs = {}, {}
    for ld in loads:
        per_op[ld["op"]] = per_op.get(ld["op"], 0) + 1
        per_rs[ld["rs"]] = per_rs.get(ld["rs"], 0) + 1
    print(f"SUMMARY clcrc={e.clcrc} words={len(data) // 4} "
          f"loads={len(loads)} per_op={per_op}")
    print("TOP-RS " + " ".join(f"r{k}:{v}" for k, v in
                               sorted(per_rs.items(), key=lambda x: -x[1])[:10]))
    if a.base is not None:
        hs = hits(data, a.base,
                  a.lo if a.lo is not None else 0,
                  a.hi if a.hi is not None else 1 << 32, a.rs)
        print(f"HITS base={a.base:#x} rs={a.rs} "
              f"range=[{a.lo:#x},{a.hi:#x}) count={len(hs)}")
        for h in hs[:200]:
            print(f"  HIT dc={h['dc']:#x} {h['op']} rs=r{h['rs']} "
                  f"rd=r{h['rd']} off={h['off']:+#x} eff={h['eff']:#x}")
        if a.json:
            Path(a.json).write_text(json.dumps(hs, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
