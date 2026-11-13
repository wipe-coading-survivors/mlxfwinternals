#!/usr/bin/env python3
"""cx4lx-detour D2: scan MAIN_CODE db0 for dead format strings with N >= 2
%x-family tokens (dump-semifabricate marker strings).

Deadness criterion (D1/L3 precedent): the rt constant (dc + 0x800000) has
ZERO addi/addi.hi loaders in MAIN_CODE and never appears as a raw BE word.

Tokens: %x/%X/%d/%u/%i render word values (valid params); any other
conversion (%s/%p/%c/...) disqualifies the string (params are numbers).
Candidate starts: every offset inside a printable NUL-terminated segment
(suffixes of live strings are dead if that exact rt has no loader).

Usage: scan_dead_strings.py [--base PATH] [--min-tokens N]
Log: build/cx4lx-d2-dead-strings.log
"""
import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WT))
sys.path.insert(0, str(WT / 'scripts/irisc'))
import mlxfwutil  # noqa: E402

RT = 0x800000
DB0_DC = 0x2d6900
DB0_SIZE = 0x44a00
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
VALID_CONV = frozenset(b'xXdui')  # ints; compare token byte c[0]
TOKEN_RE = re.compile(rb'%[-+ #0]*[0-9]*(?:\.[0-9]+)?(?:hh|h|ll|l)?(.)', re.S)


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i*68:i*68+64]
    return bytes(out)


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', default=str(WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'))
    ap.add_argument('--min-tokens', type=int, default=2)
    args = ap.parse_args()

    lines = []
    def say(s=''):
        lines.append(s)
        print(s)

    buf = Path(args.base).read_bytes()
    md5 = hashlib.md5(buf).hexdigest()
    say('base=%s md5=%s' % (args.base.split('/')[-1], md5))
    if md5 != BASE_MD5:
        say('NOTE: base md5 differs from GCA stock %s (foreign base: scan results are base-local)' % BASE_MD5)
    img = mlxfwutil.Image(buf, args.base)
    e = img.find_entry('ITOC', 0x03)
    code = decrc(img.section_data(e))
    n = len(code) // 4
    words = struct.unpack('>%dI' % n, code)
    say('MAIN_CODE: addr=0x%x size=0x%x words=%d; db0 dc [0x%x,0x%x)' % (
        e.addr, e.size, n, DB0_DC, DB0_DC + DB0_SIZE))

    loaded = set()
    prev = None
    for i in range(n - 1):
        w = words[i]
        op = w >> 26
        if op in (0x00, 0x01):
            prev = (i, (w >> 16) & 0x1f, s16(w & 0xffff))
        elif op in (0x02, 0x03) and prev is not None:
            poff, prd, pimm = prev
            if poff + 1 == i and prd == (w >> 16) & 0x1f:
                loaded.add((pimm + ((w & 0xffff) << 16)) & 0xffffffff)
            prev = None
    say('loaded rt constants (addi/addi.hi pairs): %d' % len(loaded))

    db0 = code[DB0_DC:DB0_DC + DB0_SIZE]
    segs = []
    i = 0
    while i < len(db0):
        if 0x20 <= db0[i] < 0x7f:
            j = i
            while j < len(db0) and 0x20 <= db0[j] < 0x7f:
                j += 1
            if j < len(db0) and db0[j] == 0 and j - i >= 4:
                segs.append((i, j))
            i = j + 1
        else:
            i += 1
    say('printable NUL-terminated segments >=4B in db0: %d' % len(segs))

    cands = []
    for s0, s1 in segs:
        seg = db0[s0:s1]
        matches = sorted((m.start(), m.group(1)[0] in VALID_CONV)
                         for m in TOKEN_RE.finditer(seg))
        if not matches:
            continue
        last_bad = max((p for p, ok in matches if not ok), default=-1)
        starts = sorted({0} | {p for p, _ in matches} | {last_bad + 1})
        for st in starts:
            if st < 0 or st <= last_bad or st >= len(seg):
                continue
            nv = sum(1 for p, ok in matches if p >= st and ok)
            if nv >= args.min_tokens:
                rt = DB0_DC + s0 + st + RT
                cands.append((nv, rt, s0 + st, seg[st:]))

    def is_dead(rt):
        if rt in loaded:
            return False
        return code.find(struct.pack('>I', rt)) == -1

    cands = [c for c in cands if is_dead(c[1])]
    cands.sort(key=lambda c: (-c[0], c[1]))
    say('DEAD candidates >=%d valid tokens (suffix starts incl.): %d' % (
        args.min_tokens, len(cands)))
    say('--- top dead strings by token count:')
    shown = 0
    for nv, rt, dcoff, sub in cands:
        say('  rt 0x%08x dc 0x%x tokens=%d len=%d text=%r' % (
            rt, rt - RT, nv, len(sub), sub[:100]))
        shown += 1
        if shown >= 25:
            break

    out = WT / 'build/cx4lx-d2-dead-strings.log'
    out.parent.mkdir(exist_ok=True)
    out.write_text('\n'.join(lines) + '\n')
    print('DONE log=%s' % out)


if __name__ == '__main__':
    main()
