#!/usr/bin/env python3
"""iRISC string-address locator. Verified: iRISC (BE32) does NOT embed
full 32-bit string addresses (no word == abs/sect-rel) and does NOT use
ld.b immediates for strings. Strings are referenced via 16-bit offsets
(low 16 bits, big-endian word tail) inside word-aligned words with a
variable hi16 tag (families 0x94xx / 0x009a / 0x0000 ...).
Modes:
  words16    (default) word-aligned 32-bit words whose low 2 bytes
             equal low16(target), whole image
  words32rel 32-bit words in MAIN_CODE equal to sect-rel target
  words32abs 32-bit words in whole image equal to abs target
  ldb        ld.b (op 0x18) sites with simm16 == low16(target)
              (kept for completeness; verified empty for gate strings)
  set3       set3 (op 0x08) sites with imm16 == low16(target), plus the
              control set2/set3 pair check: a set2 (op 0x09) with the SAME
              target register and imm16 in --hi16-range (default 0x0..0x20)
              within --win words => 32-bit pool offset (hi16<<16|lo16);
              verifies base+offset (default --base 0x3b0000) is the target.
 """
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402


def main_section(img: bytes, sect: int = 0x03):
    im = mlxfwutil.Image(img, "img")
    se = im.find_entry("ITOC", sect)
    return im.section_data(se), se.addr


def scan_words16(raw: bytes, target: int) -> list:
    b = (target & 0xFFFF).to_bytes(2, "big")
    return [o for o in range(0, len(raw) - 3, 4)
            if raw[o + 2:o + 4] == b]


def scan_words32(buf: bytes, value: int) -> list:
    b = value.to_bytes(4, "big")
    return [o for o in range(0, len(buf) - 3, 4) if buf[o:o + 4] == b]


def scan_ldb(data: bytes, target: int) -> list:
    imm = target & 0xFFFF
    out = []
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "big")
        if (w >> 26) & 0x3F == 0x18 and (w & 0xFFFF) == imm:
            out.append(off)
    return out


def scan_set3(data: bytes, target: int, hi_lo: int = 0, hi_hi: int = 0x20,
              window: int = 40):
    """Return [(off, rd, pair)] where pair is None or (pair_off, hi16).

    set3 (op 0x08) sets bits 0..15; set2 (op 0x09) sets bits 16..31.
    word = (op<<26)|(RS<<21)|(RD<<16)|imm16. A pool offset is built as
    (hi16<<16)|lo16. pair is the nearby set2 on the SAME RD with hi16 in
    [hi_lo, hi_hi].
    """
    imm = target & 0xFFFF
    n = len(data)

    def w(off):
        return int.from_bytes(data[off:off + 4], "big")

    out = []
    for off in range(0, n - 3, 4):
        ww = w(off)
        if (ww >> 26) & 0x3F != 0x08 or (ww & 0xFFFF) != imm:
            continue
        rd = (ww >> 16) & 0x1F
        pair = None
        lo, hi = off - 4 * window, off + 4 * (window + 1)
        for o in range(max(0, lo), min(n, hi), 4):
            if o == off:
                continue
            wp = w(o)
            if ((wp >> 26) & 0x3F == 0x09 and (wp >> 16) & 0x1F == rd
                    and hi_lo <= (wp & 0xFFFF) <= hi_hi):
                pair = (o, wp & 0xFFFF)
                break
        out.append((off, rd, pair))
    return out


def scan_build_pairs(data: bytes, lo_set: set, hi_set: set,
                     window: int = 100) -> list:
    """Return [(off_lo, off_hi, rd, value)] for 32-bit address construction.

    A 'lo' insn (set3 op 0x08 / addi op 0x00 / addi op 0x01) with imm16 in
    lo_set on register R, paired within `window` words by a 'hi' insn
    (set2 op 0x09 / addi.hi op 0x02 / addi.hi op 0x03) with imm16 in hi_set
    on the SAME R, builds value = (hi16 << 16) | lo16. Covers both the
    set3+set2 and addi+set2/addi.hi forms (3R4: neither ever appears in the
    8008 image for the gate-string addresses).
    """
    n = len(data)

    def w(off):
        return int.from_bytes(data[off:off + 4], "big")

    out = []
    for o in range(0, n - 3, 4):
        ww = w(o)
        if (ww >> 26) & 0x3F not in (0x08, 0x00, 0x01):
            continue
        lo = ww & 0xFFFF
        if lo not in lo_set:
            continue
        rd = (ww >> 16) & 0x1F
        lo_b, hi_b = max(0, o - 4 * window), min(n, o + 4 * (window + 1))
        for j in range(lo_b, hi_b, 4):
            if j == o:
                continue
            wp = w(j)
            if (((wp >> 26) & 0x3F) in (0x09, 0x02, 0x03)
                    and (wp >> 16) & 0x1F == rd
                    and (wp & 0xFFFF) in hi_set):
                out.append((o, j, rd, ((wp & 0xFFFF) << 16) | lo))
                break
    return out


def iter_itoc(img: bytes):
    im = mlxfwutil.Image(img, "img")
    for t in range(0x40):
        try:
            e = im.find_entry("ITOC", t)
        except Exception:
            e = None
        if e is not None:
            yield t, im.section_data(e)


def scan_all_itoc_build_pairs(img: bytes, lo_set: set, hi_set: set,
                              window: int = 100) -> list:
    """Whole-image: [(sect, off_lo, off_hi, rd, value)] across all ITOC."""
    out = []
    for t, data in iter_itoc(img):
        for h in scan_build_pairs(data, lo_set, hi_set, window):
            out.append((t,) + h)
    return out


def _print_ctx(buf: bytes, hits: list, ctx: int, base: int, size: int,
                show_rel: bool):
    for h in hits[:64]:
        tag = ""
        if show_rel and base <= h < base + size:
            tag = f" (sect-rel {h - base:#x})"
        print(f"  HIT {h:#x}{tag}")
        lo = max(0, h - 4 * ctx)
        hi = min(len(buf), h + 4 * (ctx + 1))
        for i in range(0, hi - lo - 3, 4):
            mark = ">>" if lo + i == h else "  "
            print(f"    {mark} {lo + i:#x}: {buf[lo + i:lo + i + 4].hex()}")
    if len(hits) > 64:
        print(f"  ... {len(hits) - 64} more")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image")
    ap.add_argument("targets", nargs="+", help="hex sect-rel addresses")
    ap.add_argument("--mode", default="words16",
                    choices=["words16", "words32rel", "words32abs", "ldb",
                             "set3", "build"])
    ap.add_argument("--ctx", type=lambda s: int(s, 0), default=8,
                    help="words of context around each hit")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=0x3b0000,
                    help="pool base for set3 mode (default 0x3b0000)")
    ap.add_argument("--hi16", type=lambda s: int(s, 0), default=None,
                    help="set2 hi16 range 'lo-hi' for set3 mode "
                         "(default 0-0x20)")
    ap.add_argument("--win", type=lambda s: int(s, 0), default=40,
                    help="word window for set3 pair search")
    a = ap.parse_args(argv)
    hi_lo, hi_hi = 0, 0x20
    if a.hi16 is not None:
        lo_s, hi_s = a.hi16.split("-")
        hi_lo, hi_hi = int(lo_s, 0), int(hi_s, 0)
    raw = Path(a.image).read_bytes()
    sect, base = main_section(raw)
    for t in a.targets:
        target = int(t, 0)
        if a.mode == "words16":
            hits = scan_words16(raw, target)
            print(f"TARGET {target:#x} lo16={target & 0xFFFF:#06x} "
                  f"[words16, abs]: {len(hits)} hit(s)")
            _print_ctx(raw, hits, a.ctx, base, len(sect), True)
        elif a.mode == "words32rel":
            hits = scan_words32(sect, target)
            print(f"TARGET {target:#x} [words32rel]: {len(hits)} hit(s)")
            _print_ctx(sect, hits, a.ctx, 0, 0, False)
        elif a.mode == "words32abs":
            hits = scan_words32(raw, base + target)
            print(f"TARGET {target:#x} abs={base + target:#x} "
                  f"[words32abs]: {len(hits)} hit(s)")
            _print_ctx(raw, hits, a.ctx, base, len(sect), True)
        elif a.mode == "set3":
            hits = scan_set3(sect, target, hi_lo, hi_hi, a.win)
            npair = sum(1 for _, _, p in hits if p)
            print(f"TARGET {target:#x} lo16={target & 0xFFFF:#06x} "
                  f"[set3 op08, hi16 {hi_lo:#x}-{hi_hi:#x} "
                  f"win {a.win}]: {len(hits)} set3 site(s), {npair} paired")
            for off, rd, pair in hits[:64]:
                if pair:
                    po, hi16 = pair
                    off32 = (hi16 << 16) | (target & 0xFFFF)
                    print(f"  PAIR set3@{off:#x} r{rd} + set2@{po:#x} "
                          f"hi16={hi16:#06x} => off32={off32:#06x} "
                          f"base+off={a.base + off32:#x} "
                          f"(want {a.base + target:#x})")
                else:
                    print(f"  HIT  set3@{off:#x} r{rd} (no set2 pair)")
            if len(hits) > 64:
                print(f"  ... {len(hits) - 64} more")
        elif a.mode == "build":
            lo_set = {target & 0xFFFF}
            hi_set = {(target >> 16) & 0xFFFF}
            hits = scan_all_itoc_build_pairs(raw, lo_set, hi_set, a.win)
            print(f"TARGET {target:#x} lo16={target & 0xFFFF:#06x} "
                  f"hi16={target >> 16:#06x} [build, whole-image]: "
                  f"{len(hits)} pair(s)")
            for t, o, j, rd, val in hits[:64]:
                print(f"  sect 0x{t:02x}: lo@{o:#x} hi@{j:#x} r{rd} "
                      f"=> value={val:#06x}")
        else:
            hits = scan_ldb(sect, target)
            print(f"TARGET {target:#x} [ldb]: {len(hits)} hit(s)")
            _print_ctx(sect, hits, a.ctx, 0, 0, False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
