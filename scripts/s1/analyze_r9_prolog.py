#!/usr/bin/env python3
# RE: (A) do hooked fns 0x090b7c/0x090be4/0x0d3cf4 save r9 in prologue?
#     (B) decode (BE) S1-fixed2 LOC 0x38d750..0x38d84f: flag-check + capture
#         + dispatch + re-prologue, confirm structure + jump targets.
# iRISC words BIG-ENDIAN ('>I'). dec2.py = verified decoder.
# slaspec: st.d RT,RS,OFF => value=rt(bits11-15), base=rs(bits21-25);
#   dec2 prints 'st.d base,value,off' (RS,RT). Verified vs Ghidra:
#   stock 0x0d3d00 'st.d r17l,r1l,0x24' (Ghidra) must decode 'st.d r1,r17,0x24'.
# OFFLINE, read-only.
import os, struct, sys, importlib.util

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
STOCK = open(REPO + '/build/ghidra-4030cda-main03-ac-dc.bin', 'rb').read()
F2 = open('/tmp/opencode/s1/main03-code-s1-fixed2.bin', 'rb').read()

spec = importlib.util.spec_from_file_location('dec2', '/tmp/opencode/s1/dec2.py')
dec2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(dec2)

def u32(b, o): return struct.unpack_from('>I', b, o)[0]
def s16(v): return v - 0x10000 if v & 0x8000 else v
def s14(v): return v - 0x4000 if v & 0x2000 else v
def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o * 4
def brt(w, pc):
    return (pc + 4) + s16(w & 0xffff) * 4
def fields(w):
    return (w >> 26) & 0x3f, (w >> 16) & 0x1f, (w >> 21) & 0x1f, (w >> 11) & 0x1f, w & 0xffff

def die(m):
    print('FATAL: ' + m); sys.exit(1)

print('stock size=0x%x  f2 size=0x%x' % (len(STOCK), len(F2)))
if len(STOCK) != 0x397dc0 or len(F2) != 0x397dc0:
    die('unexpected code size')

# ============ 0. decoder anchors (BE) ============
print('== 0. decoder anchors (stock) ==')
anchors = [
    (0x0afe44, 0x66cc0142, 'ld.d r12,r22,0x140'),
    (0x0d3f48, 0x94fffeb1, 'call 0x0d3a0c'),
    (0x090b84, 0x703f0ff2, 'st.d! r1,r1,0x-10'),   # dec2 prints negative offs as 0x-10
    (0x0d3cfc, 0x703f0fda, 'st.d! r1,r1,0x-28'),
    (0x0d3d00, None, 'st.d r1,r17,0x24'),   # Ghidra: st.d r17l,r1l,0x24 (RS=r1 base, RT=r17 val)
]
for a, w, exp in anchors:
    real = u32(STOCK, a)
    got = dec2.dis(real, a)
    ok = got == exp and (w is None or real == w)
    print('  @0x%06x %08x  %-22s exp=%s %s' % (a, real, got, exp, 'OK' if ok else 'MISMATCH'))
    if not ok: die('anchor mismatch')
print('  STDRET 0xfd001825 -> %s' % dec2.dis(0xfd001825, 0))
if dec2.dis(0xfd001825, 0) != 'STDRET (return [r3])': die('STDRET anchor')
print('  anchors: ALL OK (incl. Ghidra RS/RT order cross-check 0x0d3d00)')

# ============ A. prologues of hooked fns ============
SITES = [(0x090b7c, 'ID0'), (0x090be4, 'ID1'), (0x0d3cf4, 'ID2')]
STOCK_PROLOG = {
    0x090b7c: [0x480300bc, 0x6c201806, 0x703f0ff2],
    0x090be4: [0x480300bc, 0x6c201806, 0x703f0ffa],
    0x0d3cf4: [0x480300bc, 0x6c201806, 0x703f0fda],
}

def find_func_end(b, start, max_span=0x4000):
    # epilogue 3-pattern: addi r1,r1,imm ; ld.d r3,r1,0x4 ; ret.r zero,r8,r3 (STDRET)
    n = len(b) // 4
    for i in range(start // 4 + 1, min((start + max_span) // 4, n - 2)):
        w0, w1, w2 = u32(b, i * 4), u32(b, (i + 1) * 4), u32(b, (i + 2) * 4)
        op0, rd0, rs0, _, _ = fields(w0)
        op1, rd1, rs1, _, _ = fields(w1)
        op2, rd2, rs2, rt2, _ = fields(w2)
        if (op0 in (0x00, 0x01) and rd0 == 1 and rs0 == 1 and
            op1 == 0x19 and (w1 & 2) and not (w1 & 1) and rd1 == 3 and rs1 == 1 and
            ((w1 >> 2) & 0x3fff) == 1 and
            op2 == 0x3f and (w2 & 0x1ff) == 0x25 and rd2 == 0 and rs2 == 8 and rt2 == 3):
            return i * 4, (w0 & 0xffff)
    return None, None

def scan_r9(b, lo, hi):
    stores, loads = [], []
    for a in range(lo, hi, 4):
        w = u32(b, a)
        op, rd, rs, rt, imm = fields(w)
        if op in (0x1a, 0x1b, 0x1c, 0x1e) and rt == 9:
            stores.append((a, w, 'base=%s' % ('r%d' % rs), dec2.dis(w, a)))
        elif op == 0x19 and rd == 9:
            loads.append((a, w, 'base=%s' % ('r%d' % rs), dec2.dis(w, a)))
    return stores, loads

print()
print('== A. hooked-fn prologues (STOCK) ==')
for site, tag in SITES:
    got = [u32(STOCK, site + 4 * i) for i in range(3)]
    if got != STOCK_PROLOG[site]:
        die('A: stock prologue @%06x = %s, want %s' % (site, [hex(x) for x in got], STOCK_PROLOG[site]))
    end, frame = find_func_end(STOCK, site)
    if end is None:
        die('A: no epilogue found for fn @%06x' % site)
    print()
    print('-- fn @0x%06x (%s): stock prologue intact, epilogue @0x%06x (addi r1,r1,0x%x), span=0x%x' %
          (site, tag, end, frame, end + 4 - site))
    print('  prologue decode (first 16 words):')
    for i in range(16):
        a = site + 4 * i
        if a > end: break
        w = u32(STOCK, a)
        print('    %06x  %08x  %s' % (a, w, dec2.dis(w, a)))
    st9, ld9 = scan_r9(STOCK, site, end + 4)
    print('  r9-stack stores in [site..epi]: %s' %
          (['%06x %08x %s (%s)' % (a, w, d, bs) for a, w, bs, d in st9] if st9 else 'NONE'))
    print('  r9-stack loads  in [site..epi]: %s' %
          (['%06x %08x %s (%s)' % (a, w, d, bs) for a, w, bs, d in ld9] if ld9 else 'NONE'))
    verdict = 'SAVES r9' if st9 else 'does NOT save r9 (r9 scratch for this fn)'
    print('  VERDICT %s: %s' % (tag, verdict))

# ============ B. S1-fixed2 LOC decode ============
print()
print('== B. S1-fixed2 LOC 0x38d750..0x38d84f (BE) ==')
def show(b, name, lo, hi):
    print('-- %s [0x%06x..0x%06x] --' % (name, lo, hi))
    for a in range(lo, hi + 1, 4):
        w = u32(b, a)
        op, rd, rs, rt, imm = fields(w)
        extra = ''
        if op == 0x25:
            extra = '  -> 0x%06x (jmpop=%d)' % (jt(w, a), (w >> 24) & 1)
        elif op in (0x28, 0x29):
            extra = '  -> 0x%06x' % brt(w, a)
        elif op in (0x2a, 0x2b):
            extra = '  -> 0x%06x' % brt(w, a)
        print('  %06x  %08x  %-28s%s' % (a, w, dec2.dis(w, a), extra))

show(F2, 'flag-check + capture', 0x38d750, 0x38d810)
show(F2, 'dispatch + re-prologue', 0x38d814, 0x38d84f)

# B.1 structural asserts
print()
print('== B.1 structural asserts ==')
EXP_FLAGCHECK = {
    0x38d750: (0x240e0000, 'set2 r14,zero,0x0'),
    0x38d754: (0x21ce2390, 'set3 r14,r14,0x2390'),
    0x38d758: (0x65cc0002, 'ld.d r12,r14,0x0'),
    0x38d75c: (0x158c0000, 'subsi r12,r12,0x0'),
    0x38d760: (0xa000002c, 'b.t.00 zero,0x38d814'),
}
for a, (ew, ed) in EXP_FLAGCHECK.items():
    w = u32(F2, a)
    if w != ew: die('B: @%06x = %08x, want %08x' % (a, w, ew))
    got = dec2.dis(w, a)
    print('  @0x%06x %08x %-26s %s' % (a, w, got, 'OK' if got == ed else 'MISMATCH: ' + ed))
    if got != ed: die('B: decode mismatch @%06x: %s != %s' % (a, got, ed))
if brt(u32(F2, 0x38d760), 0x38d760) != 0x38d814: die('B: b.t @0x38d760 target != 0x38d814')
print('  flag-check: 5 words, CR-read 0x2390 via r14 base -> r12, Z32=(flag==0), b.t.00 -> 0x38d814: OK')

EXP_DISPATCH = {
    0x38d814: (0xa9210009, 0x38d83c, 'b.bset 1,r9'),
    0x38d818: (0xa9200004, 0x38d82c, 'b.bset 0,r9'),
}
for a, (ew, tgt, ed) in EXP_DISPATCH.items():
    w = u32(F2, a)
    if w != ew: die('B: @%06x = %08x, want %08x' % (a, w, ew))
    got = dec2.dis(w, a)
    if brt(w, a) != tgt: die('B: @%06x branch target 0x%x != 0x%x' % (a, brt(w, a), tgt))
    print('  @0x%06x %08x %-26s -> 0x%06x  OK' % (a, w, got, tgt))
print('  dispatch: b.bset 1,r9 -> 0x38d83c (ID2); b.bset 0,r9 -> 0x38d82c (ID1); fallthrough 0x38d81c (ID0): OK')

REPRO = {
    0x38d81c: (0x090b88, 0x703f0ff2),
    0x38d82c: (0x090bf0, 0x703f0ffa),
    0x38d83c: (0x0d3d00, 0x703f0fda),
}
for g, (want_tgt, w_st) in REPRO.items():
    w0, w1, w2, w3 = (u32(F2, g + 4 * i) for i in range(4))
    if (w0, w1, w2) != (0x480300bc, 0x6c201806, w_st):
        die('B: re-prologue @%06x != stock 3 words: %s' % (g, [hex(x) for x in (w0, w1, w2)]))
    if jt(w3, g + 12) != want_tgt:
        die('B: re-prologue @%06x jump -> 0x%x, want 0x%x' % (g, jt(w3, g + 12), want_tgt))
    print('  re-prologue @0x%06x: [%08x %08x %08x %08x] = stock 3w + jump 0x%06x: OK' %
          (g, w0, w1, w2, w3, want_tgt))
print('  re-prologue: 3 groups x [csr.r r3,retaddr; st.d r3,r1,0x4; st.d! r1,r1,-off; jump S+0xC]: OK')

# B.2 sanity for task C: the word to be patched
w_cur = u32(F2, 0x38d750)
print()
print('== B.2 task-C sanity ==')
print('  current @0x38d750 = %08x (%s)' % (w_cur, dec2.dis(w_cur, 0x38d750)))
if w_cur != 0x240e0000: die('B.2: @0x38d750 != 0x240e0000 (set2 r14,zero,0)')
PW = 0x95000031
op, rd, rs, rt, imm = fields(PW)
print('  patch word %08x: op=0x%02x jmpop=%d simm24=0x%x' % (PW, op, (PW >> 24) & 1, PW & 0xffffff))
if op != 0x25 or ((PW >> 24) & 1) != 1: die('B.2: patch word is not a jump')
if jt(PW, 0x38d750) != 0x38d814: die('B.2: jump target != 0x38d814')
print('  decode: %s -> target 0x%06x == 0x38d814 (dispatch): CONFIRMED' % (dec2.dis(PW, 0x38d750), jt(PW, 0x38d750)))

print()
print('DONE (A+B)')
