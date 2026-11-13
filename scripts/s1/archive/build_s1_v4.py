#!/usr/bin/env python3
"""S1 v4: v2 guided + FN_A hook + capture stub in safe zone (replaces ID2 stub)."""
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = '/tmp/opencode/s1/4030-cda-s1-redesign-guided.bin'
OUT  = '/tmp/opencode/s1/4030-cda-s1-v4.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-v4.bin'

sys.path.insert(0, REPO + '/scripts/irisc')
import enc

def die(msg): print('FATAL: %s' % msg); sys.exit(1)
def md5(p):
    h = hashlib.md5()
    with open(p,'rb') as f:
        for c in iter(lambda: f.read(1<<20), b''): h.update(c)
    return h.hexdigest()
def be32(w): return struct.pack('>I', w)
def u32(b, o): return struct.unpack_from('>I', b, o)[0]

# --- addresses ---
HOOK_PA  = 0x18d964   # FN_A entry
STUB_PA  = 0x38d770   # ID2 stub location (safe zone)
J_BACK   = 0x18d970   # FN_A body (after 3-word prologue)
FN_A_RA  = 0x18d970   # expected ra when called from FN_A

# --- Hook: 3 words at FN_A ---
HOOK = [
    enc.jump(HOOK_PA, STUB_PA),
    0,  # NOP
    0,  # NOP
]

# --- Capture stub: replaces ID2 stub at 0x38d770 ---
# Logic:
#   if ra == 0x18d970 (FN_A): capture ra/marker/magic/flag, ret.d
#   else (ID2 or other): ret.d (no-op)
stub = []

# 1. Load FN_A RA into r10
stub.append(enc.set2(10, 0x18))          # r10 = 0x18
stub.append(enc.set3(10, 10, 0xd970))    # r10 = 0x18d970

# 2. Compare r3 (ra) with r10 (FN_A RA)
stub.append(enc.cmp38(0x00, 3, 10, lo11=2))  # cmp.w eq32: r3 vs r10

# 3. If NOT equal (not FN_A), skip to ret
ret_idx = None  # will be set later
stub.append(0)  # placeholder for b_f

# 4. Capture code (only runs if ra == FN_A_RA)
stub.append(enc.set2(10, 0x23))          # r10 = 0x23
stub.append(enc.set3(10, 10, 0x80))      # r10 = 0x2380
stub.append(enc.st_d(3, 10, 0))          # [0x2380] = r3 (ra)
stub.append(enc.set2(10, 0x23))          # r10 = 0x23
stub.append(enc.set3(10, 10, 0x88))      # r10 = 0x2388
stub.append(enc.set2(12, 0x3))           # r12 = 3 (FN_A marker)
stub.append(enc.st_d(12, 10, 0))         # [0x2388] = 3
stub.append(enc.set2(10, 0x23))          # r10 = 0x23
stub.append(enc.set3(10, 10, 0x8c))      # r10 = 0x238c
stub.append(enc.set2(12, 0x5331))        # r12 = 0x5331
stub.append(enc.set3(12, 12, 0x01))      # r12 = 0x53310001
stub.append(enc.st_d(12, 10, 0))         # [0x238c] = magic
stub.append(enc.set2(10, 0x23))          # r10 = 0x23
stub.append(enc.set3(10, 10, 0x90))      # r10 = 0x2390
stub.append(enc.set2(12, 0x1))           # r12 = 1 (flag)
stub.append(enc.st_d(12, 10, 0))         # [0x2390] = 1

# 5. Return
stub.append((0x3f << 26) | (0x2d << 16))  # ret.d (op 0x3f, funct 0x2d)

# Fix b_f at index 3: jump to ret (last word)
ret_addr = STUB_PA + 4 * (len(stub) - 1)
b_f_pc = STUB_PA + 4 * 3
stub[3] = enc.b_f(0x0A, b_f_pc, ret_addr)

STUB = stub
assert len(HOOK) == 3
print('[stub] %d words' % len(STUB))

# ID2 stub space is 27 words (0x38d770-0x38d7d8)
# Our stub is len(STUB) words; zero out the rest
ID2_STUB_SIZE = 27
if len(STUB) > ID2_STUB_SIZE:
    die('stub too large: %d > %d' % (len(STUB), ID2_STUB_SIZE))
STUB_PADDED = STUB + [0] * (ID2_STUB_SIZE - len(STUB))

# --- PATCH dict ---
PATCH = {}
for i, w in enumerate(HOOK):
    PATCH[HOOK_PA + 4*i] = w
for i, w in enumerate(STUB_PADDED):
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
fn_a_prolog = [u32(code, HOOK_PA + 4*i) for i in range(3)]
print('[3] FN_A prologue @0x%06x: %s' % (HOOK_PA, ['%08x' % w for w in fn_a_prolog]))

# Verify safe zone: last safe address is 0x38d7d8 (inclusive)
SAFETY_END = 0x38d7d8
for a in range(STUB_PA, STUB_PA + 4*ID2_STUB_SIZE, 4):
    if a > SAFETY_END:
        die('sanity: @0x%x is beyond safe zone (end=0x%06x)' % (a, SAFETY_END))
print('[3] stub zone 0x%06x-0x%06x: within safe zone (end=0x%06x)' % (STUB_PA, STUB_PA + 4*ID2_STUB_SIZE - 4, SAFETY_END))

# Verify we're NOT touching the dangerous zone
DANGER_START = 0x38d780
DANGER_END = 0x38dbe8
for a in PATCH:
    if DANGER_START <= a < DANGER_END and a >= STUB_PA + 4*ID2_STUB_SIZE:
        die('sanity: patch @0x%x in danger zone' % a)
print('[3] no patches in danger zone [0x%06x, 0x%06x)' % (DANGER_START, DANGER_END))

# ============ 4. apply patch ============
code_b = bytearray(code)
for a, w in sorted(PATCH.items()):
    code_b[a:a+4] = be32(w)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
dwords = sorted(a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4])
if dwords != sorted(PATCH): die('patch touched unexpected words: %d vs %d' % (len(dwords), len(PATCH)))
print('[4] patch applied: %d words (3 hook + %d stub+pad)' % (len(HOOK), len(STUB_PADDED)))

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
    return pc + o * 4

ok = True
# Hook: jump to stub
w = u32(pcode, HOOK_PA)
t = jt(w, HOOK_PA)
if t != STUB_PA: print('  FAIL hook: -> 0x%x (want 0x%x)' % (t, STUB_PA)); ok = False
else: print('  OK hook 0x%06x -> 0x%06x' % (HOOK_PA, t))

# Stub: b_f at index 3 should jump to ret (last non-zero word)
b_f_addr = STUB_PA + 4*3
w = u32(pcode, b_f_addr)
t = bt_tgt(w, b_f_addr)
ret_addr_expected = STUB_PA + 4*(len(STUB)-1)
if t != ret_addr_expected:
    print('  FAIL b_f: 0x%06x -> 0x%x (want 0x%x)' % (b_f_addr, t, ret_addr_expected)); ok = False
else:
    print('  OK b_f  0x%06x -> 0x%06x (ret)' % (b_f_addr, t))

# Stub: ret.d at last word
ret_w = u32(pcode, STUB_PA + 4*(len(STUB)-1))
op = (ret_w >> 26) & 0x3f
funct = (ret_w >> 16) & 0x3ff
if op != 0x3f or funct != 0x2d:
    print('  FAIL ret: op=0x%x funct=0x%x (want 0x3f/0x2d)' % (op, funct)); ok = False
else:
    print('  OK ret.d at 0x%06x' % (STUB_PA + 4*(len(STUB)-1)))

# Verify no non-zero beyond STUB_PA + 4*ID2_STUB_SIZE
for i in range(len(STUB), ID2_STUB_SIZE):
    a = STUB_PA + 4*i
    v = u32(pcode, a)
    if v != 0:
        print('  FAIL pad @0x%06x = 0x%08x (want 0)' % (a, v)); ok = False

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

# ============ 11. print stub ============
print('\n[11] Stub words:')
for i, w in enumerate(STUB):
    print('  [%2d] 0x%06x  %08x' % (i, STUB_PA + 4*i, w))

print('\nDONE %s md5=%s' % (OUT, md5(OUT)))
