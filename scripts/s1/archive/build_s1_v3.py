#!/usr/bin/env python3
"""S1 v3 build: v2 guided + FN_A hook @0x18d964 + capture stub @0x38d7e0."""
import os, struct, hashlib, sys, importlib.util

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = '/tmp/opencode/s1/4030-cda-s1-redesign-guided.bin'
OUT  = '/tmp/opencode/s1/4030-cda-s1-v3.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-v3.bin'

def die(msg): print('FATAL: %s' % msg); sys.exit(1)
def md5(p):
    h = hashlib.md5()
    with open(p,'rb') as f:
        for c in iter(lambda: f.read(1<<20), b''): h.update(c)
    return h.hexdigest()

# --- instruction encoders (BE, F = word index) ---
def jump_word(pc, tgt):
    o = (tgt - pc) // 4
    assert o * 4 == tgt - pc
    o &= 0xffffff
    return (0x25 << 26) | (1 << 24) | o

def b_t(cc, pc, tgt):
    o = (tgt - (pc + 4)) // 4
    assert o * 4 == tgt - (pc + 4)
    o &= 0xffff
    return (0x28 << 26) | (cc << 21) | (0 << 16) | o

def set2(rd, imm16): return (0x09 << 26) | (rd << 21) | imm16
def set3(rd, rs, imm16): return (0x10 << 26) | (rs << 21) | (rd << 16) | imm16
def ld_d(rd, rs, f): return (0x19 << 26) | (rs << 21) | (rd << 16) | (f << 2) | 0x2
def st_d(rs, rt, f): return (0x1b << 26) | (rs << 21) | (0 << 16) | (rt << 11) | (f << 2) | 0x2
def subsi(rd, rs, imm): return (0x05 << 26) | (rs << 21) | (rd << 16) | (imm & 0xfff)
def addi(rd, rs, imm): return (0x00 << 26) | (rs << 21) | (rd << 16) | (imm & 0xfff)
def nop(): return 0

# --- addresses ---
HOOK_PA = 0x18d964
STUB_PA = 0x38d7e0
J_BACK  = 0x18d970

# --- Hook: 3 words ---
HOOK = [
    jump_word(HOOK_PA, STUB_PA),
    nop(),
    nop(),
]

# --- Stub: 22 words ---
# Build stub words
stub_words = [
    0x480300bc,              # csr.r r3,csr0xbc  (r3 = ra)
    0x6c201806,              # st.d r3,r1,0x4    (re-prologue)
    0x703f0fda,              # st.d! r1,r1,-0x28 (frame 0x28)
    set2(10, 0),             # r10 = 0
    set3(10, 10, 0x2390),    # r10 = 0x2390
    ld_d(10, 10, 0),         # r10 = [0x2390] = flag
    subsi(10, 10, 0),        # Z32 = (flag==0)
]
BT = len(stub_words)  # index 7
# b.t at index 7: if flag==0 -> capture (index 9)
bt_addr = STUB_PA + 4*BT
stub_words.append(b_t(0, bt_addr, STUB_PA + 4*(BT+2)))
# jump back at index 8
jb1_addr = STUB_PA + 4*(BT+1)
stub_words.append(jump_word(jb1_addr, J_BACK))
# capture (one-shot) at index 9..21
stub_words += [
    set2(10, 0),             # r10 = 0
    set3(10, 10, 0x2380),    # r10 = 0x2380
    st_d(10, 3, 0),          # CR 0x2380 = r3 (ra)
    st_d(10, 3, 1),          # CR 0x2384 = r3 (ra)
    set2(12, 0),             # r12 = 0
    set3(12, 12, 0x3),       # r12 = 0x3 (FN_A marker)
    st_d(10, 12, 2),         # CR 0x2388 = 0x3
    set2(12, 0x5331),        # r12 = 0x5331
    set3(12, 12, 0x1),       # r12 = 0x53310001
    st_d(10, 12, 3),         # CR 0x238c = magic
    addi(12, 0, 1),          # r12 = 1
    st_d(10, 12, 4),         # CR 0x2390 = 1 (flag)
]
jb2_addr = STUB_PA + 4*len(stub_words)
stub_words.append(jump_word(jb2_addr, J_BACK))

STUB = stub_words
assert len(HOOK) == 3
assert len(STUB) == 22, 'stub=%d want 22' % len(STUB)

# --- PATCH dict ---
PATCH = {}
for i, w in enumerate(HOOK):
    PATCH[HOOK_PA + 4*i] = w
for i, w in enumerate(STUB):
    PATCH[STUB_PA + 4*i] = w

# --- imports ---
sys.path.insert(0, REPO + '/scripts/probes')
sys.path.insert(0, REPO)
import mlxfwutil
from iron_boot_probe import decrc

# HW CRC-16: reflect-таблица poly 0xD008 (эквивалент crc16table2 из
# mstflint mft_utils/calc_hw_crc.c); генерируется
HW_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xD008 if _c & 1 else _c >> 1
    HW_CRC_TABLE.append(_c)
def calc_hwcrc(crc, data):
    for b in data:
        crc = (crc >> 8) ^ HW_CRC_TABLE[(b ^ (crc & 0xFF)) & 0xFF]
    return crc
def clcrc(code, tail=b''):
    assert len(code) % 64 == 0
    out = bytearray()
    for i in range(len(code) // 64):
        line = bytearray(code[i*64:(i+1)*64]) + b'\x00\x00'
        line += struct.pack('<H', calc_hwcrc(0x0000, bytes(line)))
        out += line
    return bytes(out) + tail
def be32(w): return struct.pack('>I', w)
def u32(b, o): return struct.unpack_from('>I', b, o)[0]

# ============ 0. base ============
base_bytes = open(BASE, 'rb').read()
print('[0] base: %s size=%d md5=%s' % (BASE, len(base_bytes), md5(BASE)))

# ============ 1. extract + de-clcrc ============
img = mlxfwutil.Image(base_bytes, BASE)
e = img.find_entry('ITOC', 0x03)
raw = img.section_data(e)
assert e.size == 0x3d15a0 and e.clcrc == 1 and e.addr == 0x1c748
code = decrc(raw)
assert len(code) == 0x397dc0, hex(len(code))
nlines = len(code) // 64
tail = raw[nlines*68:]
print('[1] MAIN_CODE: size=0x%x de-clcrc=0x%x lines=%d' % (len(raw), len(code), nlines))

# ============ 2. round-trip ============
rt = clcrc(code, tail)
if rt != raw: die('round-trip failed')
print('[2] ROUND-TRIP: PASS (%d lines)' % nlines)

# ============ 3. sanity ============
# FN_A stock prologue
fn_a_prolog = [u32(code, HOOK_PA + 4*i) for i in range(3)]
print('[3] FN_A prologue @0x%06x: %s' % (HOOK_PA, ['%08x' % w for w in fn_a_prolog]))
# Free zone for stub
for a in range(STUB_PA, STUB_PA + 88, 4):
    if u32(code, a) != 0: die('sanity: stub zone @0x%x not zero: %08x' % (a, u32(code, a)))
print('[3] stub free zone 0x%06x-0x%06x: all zero' % (STUB_PA, STUB_PA + 84))

# ============ 4. apply patch ============
code_b = bytearray(code)
for a, w in sorted(PATCH.items()):
    code_b[a:a+4] = be32(w)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
dwords = sorted(a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4])
if dwords != sorted(PATCH): die('patch touched unexpected words: %d vs %d' % (len(dwords), len(PATCH)))
print('[4] patch applied: %d words (3 hook + %d stub)' % (len(PATCH), len(STUB)))

# ============ 5. re-clcrc ============
praw = clcrc(code_b, tail)
assert len(praw) == len(raw)
diff_lines = sorted(i for i in range(nlines) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68])
exp_lines = sorted({a // 64 for a in PATCH})
if diff_lines != exp_lines: die('unexpected changed-line set')
print('[5] re-clcrc: %d changed lines' % len(diff_lines))

# ============ 6. build image ============
edits = [(0x03, i*68, praw[i*68:(i+1)*68]) for i in diff_lines]
out = mlxfwutil.patch_sections(img, edits)
open(OUT, 'wb').write(out)
print('[6] image: %s md5=%s' % (OUT, md5(OUT)))

# ============ 7. verify ============
pimg = mlxfwutil.Image(out, OUT, base=img.base, fmt=img.fmt)
pe = pimg.find_entry('ITOC', 0x03)
praw2 = pimg.section_data(pe)
assert praw2 == praw, 'built section raw mismatch'
pcode = decrc(praw2)
rt2 = clcrc(pcode, praw2[nlines*68:])
if rt2 != praw2: die('per-line clcrc round-trip FAILED')
print('[7.1] per-line clcrc round-trip: PASS')
errs = mlxfwutil.verify_image(pimg, deep=True)
print('[7.2] mlxfwutil verify --deep: %s' % ('PASS' if not errs else errs))
if errs: die('mlxfwutil verify failed')

# ============ 8. mstflint verify ============
import subprocess
r = subprocess.run(['mstflint', '-i', OUT, 'verify'], capture_output=True, text=True)
if 'bootable' not in r.stdout: die('mstflint verify: %s' % r.stdout)
print('[8] mstflint verify: PASS (bootable)')

# ============ 9. decode verify ============
print('[9] decode verify:')
def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o * 4
def bt_tgt(w, pc):
    o = w & 0xffff
    if o & 0x8000: o -= 0x10000
    return (pc + 4) + o * 4

ok = True
w = u32(pcode, HOOK_PA)
t = jt(w, HOOK_PA)
if t != STUB_PA: print('  FAIL hook: -> 0x%x (want 0x%x)' % (t, STUB_PA)); ok = False
else: print('  OK hook 0x%06x -> 0x%06x' % (HOOK_PA, t))

# stub jumps (index BT+1 and last)
for idx in [BT+1, len(STUB)-1]:
    addr = STUB_PA + 4*idx
    w = u32(pcode, addr)
    t = jt(w, addr)
    if t != J_BACK: print('  FAIL stub jump 0x%x -> 0x%x (want 0x%x)' % (addr, t, J_BACK)); ok = False
    else: print('  OK stub jump 0x%06x -> 0x%06x' % (addr, t))

# stub branch
addr = STUB_PA + 4*BT
w = u32(pcode, addr)
t = bt_tgt(w, addr)
want = STUB_PA + 4*(BT+2)
if t != want: print('  FAIL b.t 0x%x -> 0x%x (want 0x%x)' % (addr, t, want)); ok = False
else: print('  OK b.t 0x%06x -> 0x%06x' % (addr, t))

if not ok: die('decode verify failed')

# ============ 10. scratch-only ============
for i, w in enumerate(STUB):
    op = (w >> 26) & 0x3f
    if op in (0x19, 0x1b):  # ld.d / st.d
        rd = (w >> 16) & 0x1f
        rt = (w >> 11) & 0x1f
        if rd >= 13: die('r%d clobber in stub[%d]' % (rd, i))
        if rt >= 13: die('r%d clobber in stub[%d]' % (rt, i))
print('[10] scratch-only: PASS')

print('\nDONE %s md5=%s' % (OUT, md5(OUT)))
