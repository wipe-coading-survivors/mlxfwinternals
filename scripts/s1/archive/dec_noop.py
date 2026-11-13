#!/usr/bin/env python3
# Decode (BE) verification for no-op detour build + S1-fixed2 hook cross-check.
# iRISC words in memory are BIG-ENDIAN: u32 = unpack_from('>I').
# Jump/call encoding (iRISC.slaspec REL24): tgt = pc + 4*simm24(w & 0xffffff).
import os, struct, hashlib, sys, importlib.util

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
sys.path.insert(0, REPO + '/scripts/probes')
sys.path.insert(0, REPO)
import mlxfwutil
from iron_boot_probe import decrc

spec = importlib.util.spec_from_file_location('dec2', '/tmp/opencode/s1/dec2.py')
dec2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(dec2)

def u32(b, o): return struct.unpack_from('>I', b, o)[0]

def show(name, code, addrs):
    print('== %s ==' % name)
    for a in addrs:
        w = u32(code, a)
        print('  %06x  %08x  %s' % (a, w, dec2.dis(w, a)))

# ---- S0 code (fresh extract from base image) ----
base = open(REPO + '/build/4030-cda-patched3.bin', 'rb').read()
print('S0 base: size=%d md5=%s' % (len(base), hashlib.md5(base).hexdigest()))
img = mlxfwutil.Image(base, 'base')
e = img.find_entry('ITOC', 0x03)
raw = img.section_data(e)
s0 = decrc(raw)
print('S0 code: size=0x%x md5=%s' % (len(s0), hashlib.md5(s0).hexdigest()))
prev = open('/tmp/opencode/s1/main03-code-s0.bin','rb').read()
print('S0 code == prev main03-code-s0.bin:', s0 == prev)

HOOKS = [0x090b7c, 0x090be4, 0x0d3cf4]
STUBS = [0x38d750, 0x38d760, 0x38d770]

# S0: original prologues + free zone + S0 marker + injection
show('S0 hook sites (original prologue, 3 words each) + 4th word (S+0xC)', s0,
     [a + 4*i for a in HOOKS for i in range(4)])
show('S0 free zone 0x38d750..0x38d77c (must be all zero)', s0,
     list(range(0x38d750, 0x38d77c+4, 4)))
show('S0 marker 0x38d730..0x38d748 + injection 0x1d594', s0,
     list(range(0x38d730, 0x38d748, 4)) + [0x1d594])

# free-zone zero check
fz = [u32(s0, a) for a in range(0x38d750, 0x38d77c+4, 4)]
print('S0 0x38d750..0x38d77c all zero:', all(w == 0 for w in fz), '(12 words)')

# ---- new no-op detour patch words (BE) -> decode targets ----
patch = {
  0x090b7c: 0x950bf2f5, 0x090b80: 0x00000000, 0x090b84: 0x00000000,
  0x090be4: 0x950bf2df, 0x090be8: 0x00000000, 0x090bec: 0x00000000,
  0x0d3cf4: 0x950ae69f, 0x0d3cf8: 0x00000000, 0x0d3cfc: 0x00000000,
  0x38d750: 0x480300bc, 0x38d754: 0x6c201806, 0x38d758: 0x703f0ff2, 0x38d75c: 0x95f40d0b,
  0x38d760: 0x480300bc, 0x38d764: 0x6c201806, 0x38d768: 0x703f0ffa, 0x38d76c: 0x95f40d21,
  0x38d770: 0x480300bc, 0x38d774: 0x6c201806, 0x38d778: 0x703f0fda, 0x38d77c: 0x95f51961,
}
print('== new no-op detour patch words (decode) ==')
for a in sorted(patch):
    w = patch[a]
    print('  %06x  %08x  %s' % (a, w, dec2.dis(w, a)))

def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o*4

print('== new patch: jump targets (formula tgt=pc+4*simm24) ==')
exp = {0x090b7c: 0x38d750, 0x090be4: 0x38d760, 0x0d3cf4: 0x38d770,
       0x38d75c: 0x090b88, 0x38d76c: 0x090bf0, 0x38d77c: 0x0d3d00}
ok = True
for pc, want in exp.items():
    w = patch[pc]
    got = jt(w, pc)
    jmpop = (w >> 24) & 1
    mark = 'OK ' if (got == want and jmpop == 1) else 'FAIL'
    if mark == 'FAIL': ok = False
    print('  %s %06x %08x -> 0x%06x (want 0x%06x, jmpop=%d)' % (mark, pc, w, got, want, jmpop))
print('new patch jump targets all OK:', ok)

# stub re-prologue must equal S0 original prologue at hook site
print('== stub re-prologue vs S0 original prologue ==')
pairs = [(0x38d750, 0x090b7c), (0x38d760, 0x090be4), (0x38d770, 0x0d3cf4)]
okp = True
for stub, site in pairs:
    sw = [patch[stub + 4*i] for i in range(3)]
    ow = [u32(s0, site + 4*i) for i in range(3)]
    m = 'OK ' if sw == ow else 'FAIL'
    if m == 'FAIL': okp = False
    print('  %s stub@%06x prologue %s == S0@%06x %s' % (m, stub,
          ['%08x'%x for x in sw], site, ['%08x'%x for x in ow]))
print('re-prologue identical:', okp)

# ---- S1-fixed2 hooks (task C) ----
f2 = open('/tmp/opencode/s1/main03-code-s1-fixed2.bin','rb').read()
print('\nS1-fixed2 code: size=0x%x md5=%s' % (len(f2), hashlib.md5(f2).hexdigest()))
show('S1-fixed2 hooks (3 words each)', f2, [a + 4*i for a in HOOKS for i in range(3)])
print('== S1-fixed2 hook jump words -> actual BE targets ==')
for site, idn in zip(HOOKS, (0,1,2)):
    wj = u32(f2, site + 8)
    print('  hook%d @%06x: jump word %08x -> 0x%06x (jmpop=%d) | word0=%08x (%s) word1=%08x (%s)' %
          (idn, site, wj, jt(wj, site+8), (wj>>24)&1,
           u32(f2, site), dec2.dis(u32(f2, site), site),
           u32(f2, site+4), dec2.dis(u32(f2, site+4), site+4)))

# ---- decoder sanity anchors (RE §11) ----
print('\n== dec2 anchors ==')
stock = open(REPO + '/build/ghidra-4030cda-main03-ac-dc.bin','rb').read()
print('stock ghidra main03: md5=%s size=0x%x' % (hashlib.md5(stock).hexdigest(), len(stock)))
w = u32(stock, 0x0d3f48)
print('  stock @0x0d3f48: %08x -> %s (Ghidra: call 0x0d3a0c)' % (w, dec2.dis(w, 0x0d3f48)))
w = u32(stock, 0x1d594)
print('  stock @0x1d594:  %08x -> %s (doc: call 0x01e10c)' % (w, dec2.dis(w, 0x1d594)))
w = u32(s0, 0x1d594)
print('  S0    @0x1d594:  %08x -> %s (doc: call 0x38d730)' % (w, dec2.dis(w, 0x1d594)))
w = u32(s0, 0x38d738)
print('  S0    @0x38d738: %08x -> %s (doc: jump 0x01e10c)' % (w, dec2.dis(w, 0x38d738)))
w = u32(stock, 0x0d3cf4)
print('  stock @0x0d3cf4: %08x -> %s' % (w, dec2.dis(w, 0x0d3cf4)))
