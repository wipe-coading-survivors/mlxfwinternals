#!/usr/bin/env python3
"""Read-only: find all jump/call targets in safe-zone stubs (0x38d730-0x38d7d8)
in v2-guided and v4c MAIN_CODE. Reveals hook sites."""
import os, struct, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
V4C = '/tmp/opencode/s1/4030-cda-s1-v4c.bin'
V2G = '/tmp/opencode/s1/4030-cda-s1-redesign-guided.bin'
sys.path.insert(0, REPO + '/scripts/probes')
sys.path.insert(0, REPO)
import mlxfwutil
from iron_boot_probe import decrc

def u32(b, o): return struct.unpack_from('>I', b, o)[0]

def maincode(path):
    data = open(path, 'rb').read()
    img = mlxfwutil.Image(data, path)
    e = img.find_entry('ITOC', 0x03)
    return decrc(img.section_data(e))

TARGETS = {0x38d730: 'S0-marker-stub', 0x38d750: 'S0-id-stub-A',
           0x38d760: 'S0-id-stub-B', 0x38d770: 'CAPTURE-stub (v2)'}

for name, path in (('v2-guided', V2G), ('v4c', V4C)):
    code = maincode(path)
    print('=== %s: jump/call sites targeting safe-zone stubs ===' % name)
    found = False
    for a in range(0, len(code) - 3, 4):
        w = u32(code, a)
        if ((w >> 26) & 0x3f) != 0x25:
            continue
        kind = 'jump' if (w >> 24) & 1 else 'call'
        o = w & 0xffffff
        if o & 0x800000: o -= 0x1000000
        tgt = a + o * 4
        if tgt in TARGETS:
            found = True
            print('  0x%06x %s %08x -> 0x%06x  %s' % (a, kind, w, tgt, TARGETS[tgt]))
    if not found:
        print('  (none)')

print()
print('=== v2-guided: decode capture stub @0x38d770 (27 words) ===')
code2 = maincode(V2G)

def dec(w, pc):
    op = (w >> 26) & 0x3f
    if op == 0x25:
        kind = 'jump' if (w >> 24) & 1 else 'call'
        o = w & 0xffffff
        if o & 0x800000: o -= 0x1000000
        return '%s -> 0x%06x' % (kind, pc + o * 4)
    if op == 0x09:
        return 'set2 r%d, 0x%04x' % ((w >> 16) & 0x1f, w & 0xffff)
    if op == 0x08:
        return 'set3 r%d, r%d, 0x%04x' % ((w >> 16) & 0x1f, (w >> 21) & 0x1f, w & 0xffff)
    if op == 0x07:
        return 'set1 r%d, r%d, 0x%04x' % ((w >> 16) & 0x1f, (w >> 21) & 0x1f, w & 0xffff)
    if op == 0x12:
        return 'csr.r r%d, 0x%03x' % ((w >> 16) & 0x1f, w & 0x7ff)
    if op in (0x19, 0x1a, 0x1b):
        ld = 'st.d' if op == 0x1b else ('ld.d?' if op == 0x19 else 'ld.d')
        rs = (w >> 21) & 0x1f
        rd = (w >> 16) & 0x1f
        rt = (w >> 11) & 0x1f
        off = ((((w >> 16) & 0x1f) << 11) | (((w >> 2) & 0x1ff) << 2))
        if off & 0x1000: off -= 0x2000
        return '%s r%d, r%d, 0x%x%s' % (ld, rd, rt, off, '!' if (w >> 1) & 1 else '')
    if op == 0x38:
        return 'cmp38 sel=%d r%d, r%d, lo=0x%03x' % ((w >> 16) & 0x1f, (w >> 21) & 0x1f, (w >> 11) & 0x1f, w & 0x7ff)
    if op == 0x36:
        return 'cmp36 sel=%d r%d, r%d, lo=0x%03x' % ((w >> 16) & 0x1f, (w >> 21) & 0x1f, (w >> 11) & 0x1f, w & 0x7ff)
    if op in (0x28, 0x29):
        cc = (w >> 16) & 0x1f
        o = w & 0xffff
        if o & 0x8000: o -= 0x10000
        return ('b_t' if op == 0x28 else 'b_f') + ' cc=%d -> 0x%06x' % (cc, pc + o * 4)
    if op == 0x3f:
        return 'op=0x3f funct=0x%03x' % ((w >> 16) & 0x3ff)
    if op == 0x00:
        return 'addi r%d, r%d, 0x%04x' % ((w >> 16) & 0x1f, (w >> 21) & 0x1f, w & 0xffff)
    if w == 0:
        return 'nop'
    return 'op=0x%02x undecoded' % op

for i in range(27):
    a = 0x38d770 + 4 * i
    print('  0x%06x %08x  %s' % (a, u32(code2, a), dec(u32(code2, a), a)))

print()
print('=== context around S0 stub jump-back targets (v2-guided) ===')
for tgt in (0x01e10c, 0x090b88, 0x090bf0):
    print('  target 0x%06x, preceding 12 words:' % tgt)
    for j in range(12, 0, -1):
        a = tgt - 4 * j
        print('    0x%06x %08x  %s' % (a, u32(code2, a), dec(u32(code2, a), a)))
