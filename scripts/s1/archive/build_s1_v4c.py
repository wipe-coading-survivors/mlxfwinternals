#!/usr/bin/env python3
"""S1 v4c: v2 guided + FN_A hook + no-op detour stub at 0x38d770.

Reconstruction (2026-09-24): v4c was originally built with an inline
one-liner (not versioned). This script reconstructs it from the verified
image forensics (journal 2026-09-24-irisc-ondemand-s1-v4c-postboot.md):
diff v2-guided -> v4c = exactly 27 words (3 hook @0x18d964 + stub zone
0x38d77c-0x38d7d8). Rebuild MUST reproduce md5 39cb367e8f698b8771a998ed68d17edd.

KNOWN FLAW (root cause of v4c FAIL, verified byte-level): the stub slot
0x38d770 already held the ACTIVE v2 ID2 capture stub (hook @0x0d3cf4,
jump-back 0x0d3d00). Replacing it with the FN_A stub (jump-back 0x18d970)
breaks the ID2 context: calls to 0x0d3cf4 fly into the FN_A body.
This build is kept for the bisection record, not as a design to extend.
See build_s1_v4d.py (if present) / status report for the fix.
"""
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = '/tmp/opencode/s1/4030-cda-s1-redesign-guided.bin'
OUT  = '/tmp/opencode/s1/4030-cda-s1-v4c.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-v4c.bin'

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
STUB_PA  = 0x38d770   # stub slot (OCCUPIED by v2 ID2 capture stub — flaw)
J_BACK   = 0x18d970   # FN_A body (after 3-word prologue)

# --- Hook: 3 words at FN_A ---
HOOK = [
    enc.jump(HOOK_PA, STUB_PA),
    0,  # NOP
    0,  # NOP
]

# --- No-op detour stub: orig FN_A prologue + jump back ---
# re-prologue words must be bit-identical to stock FN_A @0x18d964
# (checked against BASE at [3] below).
REPRO = [0x480300bc, 0x6c201806, 0x703f0fda]
STUB = REPRO + [enc.jump(STUB_PA + 4*len(REPRO), J_BACK)]

assert len(HOOK) == 3
print('[stub] %d words' % len(STUB))

# ID2 stub space is 27 words (0x38d770-0x38d7d8); zero out the rest
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
if fn_a_prolog != REPRO:
    die('re-prologue constants mismatch stock FN_A prologue: %s' % ['%08x' % w for w in fn_a_prolog])
print('[3] re-prologue == stock FN_A prologue (bit-identical): PASS')

# Verify safe zone: last safe address is 0x38d7d8 (inclusive)
SAFETY_END = 0x38d7d8
for a in range(STUB_PA, STUB_PA + 4*ID2_STUB_SIZE, 4):
    if a > SAFETY_END:
        die('sanity: @0x%x is beyond safe zone (end=0x%06x)' % (a, SAFETY_END))
print('[3] stub zone 0x%06x-0x%06x: within safe zone (end=0x%06x)' % (STUB_PA, STUB_PA + 4*ID2_STUB_SIZE - 4, SAFETY_END))

# ============ 4. apply patch ============
code_b = bytearray(code)
for a, w in sorted(PATCH.items()):
    code_b[a:a+4] = be32(w)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
# expected changed words = PATCH entries differing from base (re-prologue
# words are identical to base -> not part of the actual diff)
exp_words = sorted(a for a in PATCH if code[a:a+4] != be32(PATCH[a]))
dwords = sorted(a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4])
if dwords != exp_words: die('patch touched unexpected words: %d vs %d' % (len(dwords), len(exp_words)))
print('[4] patch applied: %d changed words (of %d patch entries)' % (len(dwords), len(PATCH)))

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
import subprocess, shutil
if shutil.which('mstflint'):
    r = subprocess.run(['mstflint', '-i', OUT, 'verify'], capture_output=True, text=True)
    if 'bootable' not in r.stdout: die('mstflint verify: %s' % r.stdout)
    print('[8] mstflint verify: PASS (bootable)')
else:
    print('[8] mstflint not found — SKIPPED (md5 round-trip is the rebuild check)')

# ============ 9. decode verify ============
print('[9] decode verify:')
def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o * 4

ok = True
# Hook: jump to stub
w = u32(pcode, HOOK_PA)
t = jt(w, HOOK_PA)
if t != STUB_PA: print('  FAIL hook: -> 0x%x (want 0x%x)' % (t, STUB_PA)); ok = False
else: print('  OK hook 0x%06x -> 0x%06x' % (HOOK_PA, t))

# Stub: re-prologue bit-identical to stock FN_A prologue
for i in range(3):
    a = STUB_PA + 4*i
    if u32(pcode, a) != REPRO[i]:
        print('  FAIL re-prologue @0x%06x = %08x (want %08x)' % (a, u32(pcode, a), REPRO[i])); ok = False
print('  OK re-prologue (3 words) == stock FN_A prologue')

# Stub: jump back at word 3
a = STUB_PA + 4*3
w = u32(pcode, a)
t = jt(w, a)
if t != J_BACK: print('  FAIL jump-back: 0x%06x -> 0x%x (want 0x%x)' % (a, t, J_BACK)); ok = False
else: print('  OK jump-back 0x%06x -> 0x%06x' % (a, t))

# Verify no non-zero beyond word 4 (pad zeros)
for i in range(4, ID2_STUB_SIZE):
    a = STUB_PA + 4*i
    v = u32(pcode, a)
    if v != 0:
        print('  FAIL pad @0x%06x = 0x%08x (want 0)' % (a, v)); ok = False

if not ok: die('decode verify failed')

# ============ 10. print stub ============
print('\n[10] Stub words:')
for i, w in enumerate(STUB):
    print('  [%2d] 0x%06x  %08x' % (i, STUB_PA + 4*i, w))

print('\nDONE %s md5=%s' % (OUT, md5(OUT)))
