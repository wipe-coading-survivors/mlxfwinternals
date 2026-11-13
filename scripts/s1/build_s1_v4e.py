#!/usr/bin/env python3
"""S1 v4e: v4d base + FN_A ra-capture stub at 0x38d770 (variant c, no op-check).

НЕ в scripts/s1/archive/: билдер текущего образа карты 81:00.0 (v4e,
662f593e); без него running-image невоспроизводим.
Мемо: docs/superpowers/memos/2026-09-24-s1-script-archive.md

v4e = v4d + ONLY the rewrite of stub-slot words w3-w15 @0x38d77c-0x38d7ac
(13 words). w0-w2 (re-prologue) and the pad (w16-w26) are unchanged from v4d,
so diff v4d->v4e MUST be exactly 13 words @0x38d77c-0x38d7ac (checked [10]).

Capture idiom is taken from the v2-guided ID2 capture stub (live-verified,
boot OK): set2/set3 base register + st.d exfil into host-CR 0x2380-0x2390.
Variant (c) per coordinator: quiescent ra capture - no op-check, no memory
read (no ld.d/subs/b.f), so zero fault risk on the first FN_A call.

Register discipline (coordinator): Clobber = {r3, r12, r13} ONLY.
  - r3  : re-prologue output (retaddr), consumed by exfil; the FN_A body
          reloads r3 from the frame before STDRET @0x18da64 (safe).
  - r12 : scratch for the 0x09320003 / 0x53310001 / 1 constants.
  - r13 : exfil base (=0x2380). v2 used r10; the 5 v2 st.d words are
          patched rs r10->r13 (decode-back mandatory).
  - NOT touched: r1 (frame), r4-r11 (FN_A args / r9 = v1 ALLOC_UAR lesson),
          r14-r23. r10 forbidden: the body saves r10->r18 @0x18d98c and
          restores r10=r18 @0x18da08, so clobbering r10 would corrupt the
          body's argument.

Mandatory pre-check (coordinator): the FN_A body 0x18d970-0x18da6c must NOT
use r12 or r13 (opcode-aware register scan, run at [3]); if it did, the base
would move to r14/r15/r16. It does not (verified), so base stays r13.
"""
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = '/tmp/opencode/s1/4030-cda-s1-v4d.bin'
BASE_MD5 = 'c710012c210427e3b48da056d3a66688'
OUT  = '/tmp/opencode/s1/4030-cda-s1-v4e.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-v4e.bin'

sys.path.insert(0, REPO + '/scripts/irisc')
sys.path.insert(0, REPO + '/scripts/s1')
import enc
import dec2

def die(msg): print('FATAL: %s' % msg); sys.exit(1)
def md5(p):
    h = hashlib.md5()
    with open(p,'rb') as f:
        for c in iter(lambda: f.read(1<<20), b''): h.update(c)
    return h.hexdigest()
def be32(w): return struct.pack('>I', w)
def u32(b, o): return struct.unpack_from('>I', b, o)[0]
def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o * 4

# --- addresses ---
HOOK_PA   = 0x18d964    # FN_A entry (hook: jump -> stub, unchanged from v4d)
STUB_PA   = 0x38d770    # stub slot
J_BACK    = 0x18d970    # FN_A body (after 3-word prologue)
FN_BODY   = 0x18d970    # FN_A body start
FN_BODY_END = 0x18da6c  # FN_A body end (exclusive)
ID2_HOOK  = 0x0d3cf4    # v4d restored stock here (must stay stock)
PATCH_START = 0x38d77c  # w3
PATCH_END   = 0x38d7ac  # w15 (inclusive)
STUB_SIZE   = 27        # full slot 0x38d770-0x38d7d8

# --- stock prologue (FN_A @0x18d964; also stock @ ID2 site) ---
REPRO = [0x480300bc, 0x6c201806, 0x703f0fda]

# --- v2 exfil st.d words (base r10), live-verified from v2-guided ---
#   CR 0x2380 = ra, CR 0x2384 = ra, CR 0x2388 = const, CR 0x238c = const,
#   CR 0x2390 = 1. Patched rs r10->r13 below.
V2_STD = [0x6d401802, 0x6d401806, 0x6d40600a, 0x6d40600e, 0x6d406012]
def patch_rs(w, old, new):
    if ((w >> 21) & 0x1f) != old:
        die('patch_rs: rs of 0x%08x is %d, want %d' % (w, (w>>21)&0x1f, old))
    return (w & ~(0x1f << 21)) | (new << 21)

# --- build the 13 patch words w3..w15 ---
STD_R13 = [patch_rs(w, 10, 13) for w in V2_STD]
W = {}
W[PATCH_START + 4*0]  = enc.set2(13, 0)                        # w3  r13 = 0
W[PATCH_START + 4*1]  = enc.set3(13, 13, 0x2380)               # w4  r13 = 0x2380 (base)
W[PATCH_START + 4*2]  = STD_R13[0]                             # w5  CR 0x2380 = r3 (ra)
W[PATCH_START + 4*3]  = STD_R13[1]                             # w6  CR 0x2384 = r3 (ra)
W[PATCH_START + 4*4]  = enc.set2(12, 0x0932)                   # w7  r12 = 0x09320000
W[PATCH_START + 4*5]  = enc.set3(12, 12, 0x3)                  # w8  r12 = 0x09320003 (op<<16|ID3)
W[PATCH_START + 4*6]  = STD_R13[2]                             # w9  CR 0x2388 = r12
W[PATCH_START + 4*7]  = enc.set2(12, 0x5331)                   # w10 r12 = 0x53310000
W[PATCH_START + 4*8]  = enc.set3(12, 12, 0x1)                  # w11 r12 = 0x53310001 (magic)
W[PATCH_START + 4*9]  = STD_R13[3]                             # w12 CR 0x238c = r12
W[PATCH_START + 4*10] = enc.addi(12, 0, 0x1)                   # w13 r12 = 1
W[PATCH_START + 4*11] = STD_R13[4]                             # w14 CR 0x2390 = 1 (flag)
W[PATCH_START + 4*12] = enc.jump(PATCH_START + 4*12, J_BACK)   # w15 jump-back

PATCH = dict(W)
if len(PATCH) != 13: die('expected 13 patch words, got %d' % len(PATCH))
print('[patch] 13 words @0x%06x-0x%06x' % (PATCH_START, PATCH_END))

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

# --- opcode-aware register fields (per iRISC slaspec) ---
def regfields(w):
    op = w >> 26
    f  = w & 0x1ff
    rd = (w >> 16) & 0x1f
    rs = (w >> 21) & 0x1f
    rt = (w >> 11) & 0x1f
    if op in (0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x0a,0x0b,0x0c,0x0e,0x17,0x18,0x19,0x32):
        return (rd, rs)
    if op == 0x09:   return (rd,)
    if op == 0x12:   return (rd,)
    if op in (0x1a,0x1b,0x1c,0x1e): return (rt, rs)
    if op in (0x28,0x29,0x2a,0x2b): return (rs,)
    if op in (0x36,0x38):           return (rs, rt)
    if op == 0x25:   return ()
    if op == 0x3f:
        if f in (0x080,0x025,0x02d,0x000,0x001,0x004,0x005,0x008,0x00a,0x00b,0x00e):
            return (rd, rs, rt)
        if f in (0x081,0x083,0x085,0x08a,0x08b):
            return (rd, rs)
    return (rd, rs, rt)  # unknown: conservative

# ============ 0. base ============
if md5(BASE) != BASE_MD5:
    die('base v4d md5 mismatch: %s (want %s)' % (md5(BASE), BASE_MD5))
base_bytes = open(BASE, 'rb').read()
print('[0] base: %s size=%d md5=%s' % (BASE, len(base_bytes), BASE_MD5))

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

# ============ 3. sanity: base v4d content + mandatory r12/r13 body check ============
# 3a. hook @0x18d964 intact (jump -> stub + 2 nop)
hook_base = [u32(code, HOOK_PA + 4*i) for i in range(3)]
exp_hook = [enc.jump(HOOK_PA, STUB_PA), 0, 0]
print('[3a] hook @0x%06x (base): %s' % (HOOK_PA, ['%08x' % w for w in hook_base]))
if hook_base != exp_hook:
    die('base hook @0x%06x != expected (jump->0x%06x + 2 nop): %s' % (HOOK_PA, STUB_PA, ['%08x' % w for w in hook_base]))
print('[3a] hook intact: PASS')

# 3b. ID2 site stock (as restored by v4d)
id2_base = [u32(code, ID2_HOOK + 4*i) for i in range(3)]
if id2_base != REPRO:
    die('base @0x%06x != stock prologue: %s' % (ID2_HOOK, ['%08x' % w for w in id2_base]))
print('[3b] ID2 site stock: PASS')

# 3c. stub slot in base v4d: w0-w2 repro, w3 jump-back 0x95f8007d, w4-w26 zero
for i in range(3):
    a = STUB_PA + 4*i
    if u32(code, a) != REPRO[i]:
        die('base stub w%d @0x%06x != re-prologue %08x (got %08x)' % (i, a, REPRO[i], u32(code, a)))
w3 = u32(code, PATCH_START)
if w3 != 0x95f8007d or jt(w3, PATCH_START) != J_BACK:
    die('base stub w3 @0x%06x = %08x, expected jump->0x%06x (0x95f8007d)' % (PATCH_START, w3, J_BACK))
for i in range(4, STUB_SIZE):
    a = STUB_PA + 4*i
    v = u32(code, a)
    if v != 0:
        die('base stub w%d @0x%06x = 0x%08x, expected 0 (pad)' % (i, a, v))
print('[3c] base stub slot: w0-w2 repro, w3 jump->0x18d970 (0x95f8007d), w4-w26 zero: PASS')

# 3d. MANDATORY: FN_A body must NOT use r12/r13 (opcode-aware scan)
body_refs = []
for a in range(FN_BODY, FN_BODY_END, 4):
    w = u32(code, a)
    for r in regfields(w):
        if r in (12, 13):
            body_refs.append((a, r, dec2.dis(w, a)))
if body_refs:
    for a, r, d in body_refs:
        print('  BODY REF r%d @0x%06x: %s' % (r, a, d))
    die('MANDATORY CHECK FAILED: FN_A body 0x%06x-0x%06x uses r12/r13 - move exfil base to r14/r15/r16' % (FN_BODY, FN_BODY_END))
print('[3d] MANDATORY r12/r13 body check: PASS (FN_A body 0x%06x-0x%06x uses neither)' % (FN_BODY, FN_BODY_END))

# 3e. stub zone within safe zone
SAFETY_END = 0x38d7d8
for a in range(STUB_PA, STUB_PA + 4*STUB_SIZE, 4):
    if a > SAFETY_END:
        die('sanity: @0x%x is beyond safe zone (end=0x%06x)' % (a, SAFETY_END))
print('[3e] stub zone 0x%06x-0x%06x: within safe zone (end=0x%06x)' % (STUB_PA, STUB_PA + 4*STUB_SIZE - 4, SAFETY_END))

# ============ 4. apply patch ============
code_b = bytearray(code)
for a, w in sorted(PATCH.items()):
    code_b[a:a+4] = be32(w)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
dwords = sorted(a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4])
exp_words = sorted(a for a in PATCH if code[a:a+4] != be32(PATCH[a]))
if dwords != exp_words: die('patch touched unexpected words: %d vs %d' % (len(dwords), len(exp_words)))
print('[4] patch applied: %d changed words' % len(dwords))

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
    print('[8] mstflint not found - SKIPPED (md5 round-trip is the rebuild check)')

# ============ 9. decode verify ============
print('[9] decode verify:')
ok = True
# hook unchanged: jump to stub
w = u32(pcode, HOOK_PA)
t = jt(w, HOOK_PA)
if t != STUB_PA: print('  FAIL hook: -> 0x%x (want 0x%x)' % (t, STUB_PA)); ok = False
else: print('  OK hook 0x%06x -> 0x%06x' % (HOOK_PA, t))

# re-prologue bit-identical to stock FN_A prologue
for i in range(3):
    a = STUB_PA + 4*i
    if u32(pcode, a) != REPRO[i]:
        print('  FAIL re-prologue @0x%06x = %08x (want %08x)' % (a, u32(pcode, a), REPRO[i])); ok = False
print('  OK re-prologue (3 words) == stock FN_A prologue')

# patch words: exact disassembly
EXP_DIS = [
    'set2 r13,zero,0x0',
    'set3 r13,r13,0x2380',
    'st.d r13,r3,0x0',
    'st.d r13,r3,0x4',
    'set2 r12,zero,0x932',
    'set3 r12,r12,0x3',
    'st.d r13,r12,0x8',
    'set2 r12,zero,0x5331',
    'set3 r12,r12,0x1',
    'st.d r13,r12,0xc',
    'addi r12,zero,0x1',
    'st.d r13,r12,0x10',
]
for i, exp in enumerate(EXP_DIS):
    a = PATCH_START + 4*i
    w = u32(pcode, a)
    d = dec2.dis(w, a)
    if d != exp:
        print('  FAIL w%d @0x%06x: %s (want %s)' % (3+i, a, d, exp)); ok = False
if ok:
    print('  OK w3-w14 decode-back: all 12 exfil words match (base r13, targets 0x2380/84/88/8c/90)')

# w15 jump-back
a = PATCH_END
w = u32(pcode, a)
t = jt(w, a)
if t != J_BACK: print('  FAIL jump-back: 0x%06x -> 0x%x (want 0x%x)' % (a, t, J_BACK)); ok = False
else: print('  OK jump-back 0x%06x -> 0x%06x' % (a, t))

# pad zeros w16-w26
for i in range(16, STUB_SIZE):
    a = STUB_PA + 4*i
    v = u32(pcode, a)
    if v != 0:
        print('  FAIL pad @0x%06x = 0x%08x (want 0)' % (a, v)); ok = False
print('  OK pad w16-w26 == 0')

# no ret.d / ld.d / b.f anywhere in the slot (variant c: no memory read, no branch, no ret.d)
for i in range(STUB_SIZE):
    a = STUB_PA + 4*i
    w = u32(pcode, a)
    op = w >> 26
    f  = w & 0x1ff
    if op == 0x19: print('  FAIL ld.d @0x%06x' % a); ok = False
    if op == 0x29: print('  FAIL b.f @0x%06x' % a); ok = False
    if op == 0x3f and f == 0x02d: print('  FAIL ret.d @0x%06x' % a); ok = False
print('  OK no ret.d / ld.d / b.f in stub slot')

# clobber set: every register field in the 13 patch words must be in {r0, r3, r12, r13}
ALLOW = {0, 3, 12, 13}
for a in sorted(PATCH):
    w = u32(pcode, a)
    for r in regfields(w):
        if r not in ALLOW:
            print('  FAIL clobber: r%d in 0x%06x (%s), allowed %s' % (r, a, dec2.dis(w, a), sorted(ALLOW))); ok = False
print('  OK clobber set: patch words touch only r0/r3/r12/r13 (w0-w2 stock repro: r1/r3 = FN_A own frame)')

if not ok: die('decode verify failed')

# ============ 10. diff v4d -> v4e (md5-guarded) ============
v4d_code = code  # already verified md5 at [0]
diff4e = [a for a in range(0, len(pcode), 4) if pcode[a:a+4] != v4d_code[a:a+4]]
EXP_DIFF = [PATCH_START + 4*i for i in range(13)]
print('[10] diff v4d->v4e: %d words (expected 13 @0x38d77c-0x38d7ac)' % len(diff4e))
for a in diff4e:
    print('      0x%06x  v4d=%08x  v4e=%08x' % (a, u32(v4d_code, a), u32(pcode, a)))
if diff4e != EXP_DIFF: die('diff v4d->v4e != 13 words @0x38d77c-0x38d7ac: %s' % ['0x%06x' % a for a in diff4e])
print('[10] diff v4d->v4e: PASS (exactly 13 words @0x38d77c-0x38d7ac)')

# ============ 11. print full stub ============
print('\n[11] v4e stub words (0x%06x-0x%06x):' % (STUB_PA, STUB_PA + 4*STUB_SIZE - 4))
for i in range(STUB_SIZE):
    a = STUB_PA + 4*i
    w = u32(pcode, a)
    tag = ''
    if a in PATCH: tag = '  <== PATCH'
    print('  [%2d] 0x%06x  %08x  %s%s' % (i, a, w, dec2.dis(w, a), tag))

print('\nDONE %s md5=%s' % (OUT, md5(OUT)))
