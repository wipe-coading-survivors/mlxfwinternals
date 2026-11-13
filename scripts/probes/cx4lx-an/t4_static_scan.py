#!/usr/bin/env python3
"""Static scan helpers for CX-4 Lx 14.32 MAIN_CODE (de-clcrc form).

Cycle cx4lx-an task-04 byproduct: the three scanners used to audit the
AN event path / PHY-UC config surface. All offsets are de-clcrc ("dc");
runtime address = dc + 0x800000; raw-image mapping is non-uniform —
verify candidate sites by direct word search + context, never by formula
(recon §2 formula is wrong, coordinator-confirmed 2026-10-09).

Usage:
  t4_static_scan.py calls  <dc>...          # REL24 call/jump xrefs
  t4_static_scan.py consts <hex32>...       # addi/addi.hi (+or/set2) pair refs
  t4_static_scan.py keyed  <field-hex>...   # set2/set3 keyed bit-field refs
  t4_static_scan.py extract                 # (re)build /tmp main03.bin from refs

Expects MAIN_CODE blob at /tmp/opencode/cx4lx-an/main03.bin (make extract).
"""
import os
import re
import struct
import sys

MAIN03 = '/tmp/opencode/cx4lx-an/main03.bin'
IMG = (os.path.expanduser('~/git/IMPLEMENTATION/mlxini/refs/fw/cx-4/') +
       'fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin')


def load():
    return open(MAIN03, 'rb').read()


def extract():
    import mlxfwutil
    img = mlxfwutil.Image(open(IMG, 'rb').read(), IMG)
    data = img.section_data(img.find_entry('ITOC', 0x03))
    out = bytearray()
    for i in range(0, len(data), 68):
        out += data[i:i + 64]
    open(MAIN03, 'wb').write(out)
    print('extracted 0x%x bytes -> %s' % (len(out), MAIN03))


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def s24(v):
    v &= 0xffffff
    return v - 0x1000000 if v & 0x800000 else v


def words(buf):
    n = len(buf) // 4
    return struct.unpack_from('>%dI' % n, buf)


def scan_calls(buf, targets):
    tset = set(targets)
    res = {t: [] for t in targets}
    n = len(buf) // 4
    ws = words(buf)
    for i in range(n):
        w = ws[i]
        if (w >> 26) == 0x25:
            tgt = i * 4 + s24(w) * 4
            if tgt in tset:
                res[tgt].append((i * 4, 'jump' if (w >> 24) & 1 else 'call'))
    return res


CODE_END = 0x2d6900  # db0 string area start: code only below this


def scan_consts(buf, vals):
    res = {v: [] for v in vals}
    n = len(buf) // 4
    ws = words(buf)
    for i in range(0, CODE_END // 4):
        w1 = ws[i]
        op1 = w1 >> 26
        rd1 = (w1 >> 16) & 0x1f
        if op1 in (0x00, 0x01):
            lo = s16(w1 & 0xffff)
            for j in range(i + 1, min(i + 7, n)):
                w2 = ws[j]
                op2 = w2 >> 26
                if op2 in (0x02, 0x03):
                    built = (lo + ((w2 & 0xffff) << 16)) & 0xffffffff
                    if built in res:
                        res[built].append((i * 4, 'addi/addi.hi'))
                elif op2 == 0x0c:
                    built = (lo | (w2 & 0xffff)) & 0xffffffff
                    if built in res:
                        res[built].append((i * 4, 'addi/or'))
        elif op1 == 0x09 and ((w1 >> 21) & 0x1f) == 0:
            hi = w1 & 0xffff
            for j in range(i + 1, min(i + 7, n)):
                w2 = ws[j]
                if (w2 >> 26) in (0x00, 0x01) and ((w2 >> 16) & 0x1f) == rd1:
                    built = ((hi << 16) + s16(w2 & 0xffff)) & 0xffffffff
                    if built in res:
                        res[built].append((i * 4, 'set2/addi'))
    for i in range(n):
        if ws[i] in res:
            res[ws[i]].append((i * 4, 'word'))
    return res


def scan_keyed(buf, fields):
    """fields: keyed bit-address low bits (e.g. 0xbb7c for K+0x3bb7c) —
    detects the 'set2 rX,zero,<hi16>; set3 rX,rX,<lo16>' address idiom."""
    res = {f: [] for f in fields}
    ws = words(buf)
    for i in range(1, len(ws)):
        w = ws[i]
        if (w >> 26) == 0x08 and (w & 0xffff) in res:
            w2 = ws[i - 1]
            if (w2 >> 26) == 0x09 and ((w2 >> 21) & 0x1f) == 0:
                res[w & 0xffff].append(i * 4)
    return res


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    mode = sys.argv[1]
    args = sys.argv[2:]
    if mode == 'extract':
        extract()
        return 0
    buf = load()
    if mode == 'calls':
        targets = [int(a, 0) for a in args]
        for t, hits in scan_calls(buf, targets).items():
            print('0x%x -> %s' % (t, ['%s@0x%x' % (k, o) for o, k in hits] or 'NONE'))
    elif mode == 'consts':
        vals = [int(a, 0) for a in args]
        for v, hits in scan_consts(buf, vals).items():
            print('0x%08x -> %s' % (v, ['%s@0x%x' % (k, o) for o, k in hits] or 'NONE'))
    elif mode == 'keyed':
        fields = [int(a, 0) & 0xffff for a in args]
        for f, hits in scan_keyed(buf, fields).items():
            print('keyed+0x%x -> %s' % (f, ['0x%x' % o for o in hits] or 'NONE'))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
