#!/usr/bin/env python3
"""Read-only forensics: v4c image vs v2-guided (known-good).
Extract MAIN_CODE (ITOC 0x03), de-clcrc, diff, dump hook+stub words."""
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
V4C = '/tmp/opencode/s1/4030-cda-s1-v4c.bin'
V2G = '/tmp/opencode/s1/4030-cda-s1-redesign-guided.bin'

sys.path.insert(0, REPO + '/scripts/probes')
sys.path.insert(0, REPO)
import mlxfwutil
from iron_boot_probe import decrc

def md5(p):
    h = hashlib.md5()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()

def u32(b, o): return struct.unpack_from('>I', b, o)[0]

def maincode(path):
    data = open(path, 'rb').read()
    img = mlxfwutil.Image(data, path)
    e = img.find_entry('ITOC', 0x03)
    raw = img.section_data(e)
    code = decrc(raw)
    return code

def decode(w, pc):
    op = (w >> 26) & 0x3f
    if op == 0x25:
        kind = 'jump' if (w >> 24) & 1 else 'call'
        o = w & 0xffffff
        if o & 0x800000: o -= 0x1000000
        return '%s -> 0x%06x' % (kind, pc + o * 4)
    if op == 0x12:
        return 'csr.r r%d, 0x%03x' % ((w >> 16) & 0x1f, w & 0x7ff)
    if op in (0x1a, 0x1b):
        ld = 'ld.d' if op == 0x1a else 'st.d'
        rd = (w >> 16) & 0x1f
        rt = (w >> 11) & 0x1f
        off = (((w >> 16) & 0x1f) << 11) | (((w >> 2) & 0x1ff) << 2)
        if off & 0x1000: off -= 0x2000
        return '%s r%d, r%d, 0x%x%s' % (ld, rd, rt, off & 0xfffff, '!' if (w >> 1) & 1 else '')
    if op == 0x3f:
        return 'op=0x3f funct=0x%03x' % ((w >> 16) & 0x3ff)
    if w == 0:
        return 'nop (0)'
    return 'op=0x%02x (undecoded)' % op

print('md5 v4c     :', md5(V4C), '(expect 39cb367e8f698b8771a998ed68d17edd)')
print('md5 v2-guided:', md5(V2G))

c4c = maincode(V4C)
c2g = maincode(V2G)
print('main_code len v4c=0x%x v2g=0x%x' % (len(c4c), len(c2g)))
assert len(c4c) == len(c2g)

diff = [a for a in range(0, len(c4c), 4) if c4c[a:a+4] != c2g[a:a+4]]
print('\n=== DIFF v2-guided vs v4c: %d words ===' % len(diff))
for a in diff:
    v2, v4 = u32(c2g, a), u32(c4c, a)
    print('0x%06x  v2=%08x  v4c=%08x' % (a, v2, v4))

print('\n=== HOOK @0x18d964 (v4c) ===')
for i in range(3):
    a = 0x18d964 + 4 * i
    w = u32(c4c, a)
    print('0x%06x %08x  %s' % (a, w, decode(w, a)))

print('\n=== original FN_A prologue @0x18d964 (v2-guided) ===')
for i in range(3):
    a = 0x18d964 + 4 * i
    w = u32(c2g, a)
    print('0x%06x %08x  %s' % (a, w, decode(w, a)))

print('\n=== STUB zone @0x38d770 (27 words), v2-guided vs v4c ===')
for i in range(27):
    a = 0x38d770 + 4 * i
    w2, w4 = u32(c2g, a), u32(c4c, a)
    mark = '  <-- DIFF' if w2 != w4 else ''
    print('0x%06x  v2=%08x  v4c=%08x  %s%s' % (a, w2, w4, decode(w4, a), mark))

print('\n=== safe zone context @0x38d730-0x38d770 (v4c, S0 stub area) ===')
for a in range(0x38d730, 0x38d770, 4):
    w = u32(c4c, a)
    if w or a % 32 == 0:
        print('0x%06x %08x  %s' % (a, w, decode(w, a)))

print('\n=== post-stub zone @0x38d7d8-0x38d800 (v4c) ===')
for a in range(0x38d7d8, 0x38d800, 4):
    print('0x%06x %08x' % (a, u32(c4c, a)))
