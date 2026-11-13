#!/usr/bin/env python3
# НЕ в scripts/s1/archive/: без него невоспроизводима цепочка образов
# (v2-guided known-good 0b315e12 = redesign + mlxfwutil guides; база v4d->v4e).
# Мемо: docs/superpowers/memos/2026-09-24-s1-script-archive.md
# S1 redesign build: S0 + 3 ID-specific boot-safe stubs (capture ONLY in ID2).
# Hooks (same as no-op detour, [jump, NOP, NOP]):
#   ID0 @0x090b7c -> stub0 @0x38d750
#   ID1 @0x090be4 -> stub1 @0x38d760
#   ID2 @0x0d3cf4 -> stub2 @0x38d770
# Stubs:
#   stub0 @0x38d750: [re-prologue_ID0 x3, jump 0x090b88]  (boot-safe no-op, 4 words)
#   stub1 @0x38d760: [re-prologue_ID1 x3, jump 0x090bf0]  (boot-safe no-op, 4 words)
#   stub2 @0x38d770: [re-prologue_ID2 x3, flag-check, op-check (shamt=16!),
#                     capture (scratch-only r10/r11/r12), jump 0x0d3d00] (26 words)
# Flag logic FIXED: flag==0 -> capture (one-shot) + flag:=1; flag!=0 -> no-op.
# iRISC words BIG-ENDIAN ('>I'); jump tgt = pc + 4*simm24 (REL24).
# OFFLINE: no live-HW, no burn. Repo read-only (artifacts in /tmp/opencode/s1).
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = REPO + '/build/4030-cda-patched3.bin'
OUT  = '/tmp/opencode/s1/4030-cda-s1-redesign.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-redesign.bin'
RAW_OUT  = '/tmp/opencode/s1/main03-raw-s1-redesign.bin'
BASE_MD5 = '082e9678b54d0512cec2f155037e82b7'

NOP = 0x00000000

def jump_word(pc, tgt):
    # jump convention: jt = pc + o*4  =>  o = (tgt - pc)//4
    o = (tgt - pc) // 4
    assert o * 4 == tgt - pc, 'jump offset not word-aligned'
    o &= 0xffffff
    return (0x25 << 26) | (1 << 24) | o

def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o * 4

def b_t(cc, pc, tgt):
    o = (tgt - (pc + 4)) // 4
    assert o * 4 == tgt - (pc + 4), 'branch offset not word-aligned'
    o &= 0xffff
    return (0x28 << 26) | (cc << 21) | (0 << 16) | o

def b_f(cc, pc, tgt):
    o = (tgt - (pc + 4)) // 4
    assert o * 4 == tgt - (pc + 4), 'branch offset not word-aligned'
    o &= 0xffff
    return (0x29 << 26) | (cc << 21) | (0 << 16) | o

# ---- instruction encoders (from dis.py + S1-fixed2 reference) ----
def set2(rd, imm): return (0x09 << 26) | (0 << 21) | (rd << 16) | (imm & 0xffff)
def set3(rd, rs, imm): return (0x08 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)
def ld_d(rd, rs, off): return (0x19 << 26) | (rs << 21) | (rd << 16) | (off << 2) | 0x2
def subsi(rd, rs, imm): return (0x05 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)
def shr(rd, rs, amt): return (0x3f << 26) | (rs << 21) | (rd << 16) | (amt << 11) | 0x83
def subs(rd, rs, rt): return (0x3f << 26) | (rs << 21) | (rd << 16) | (rt << 11) | 0x05
def st_d(rs, rt, off): return (0x1b << 26) | (rs << 21) | (0 << 16) | (rt << 11) | (off << 2) | 0x2
def addi(rd, rs, imm): return (0x00 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)

# ---- addresses ----
HOOK0, HOOK1, HOOK2 = 0x090b7c, 0x090be4, 0x0d3cf4
STUB0, STUB1, STUB2 = 0x38d750, 0x38d760, 0x38d770
J0, J1, J2 = 0x090b88, 0x090bf0, 0x0d3d00   # jump back (S+0xC)

# ---- stock prologues (re-prologue) ----
PROLOG0 = [0x480300bc, 0x6c201806, 0x703f0ff2]
PROLOG1 = [0x480300bc, 0x6c201806, 0x703f0ffa]
PROLOG2 = [0x480300bc, 0x6c201806, 0x703f0fda]

# ---- build PATCH dict ----
PATCH = {}
# hooks (same as no-op detour: [jump, NOP, NOP])
PATCH[HOOK0] = jump_word(HOOK0, STUB0); PATCH[HOOK0+4] = NOP; PATCH[HOOK0+8] = NOP
PATCH[HOOK1] = jump_word(HOOK1, STUB1); PATCH[HOOK1+4] = NOP; PATCH[HOOK1+8] = NOP
PATCH[HOOK2] = jump_word(HOOK2, STUB2); PATCH[HOOK2+4] = NOP; PATCH[HOOK2+8] = NOP
# stub0 (boot-safe no-op)
for i, w in enumerate(PROLOG0): PATCH[STUB0 + 4*i] = w
PATCH[STUB0+12] = jump_word(STUB0+12, J0)
# stub1 (boot-safe no-op)
for i, w in enumerate(PROLOG1): PATCH[STUB1 + 4*i] = w
PATCH[STUB1+12] = jump_word(STUB1+12, J1)
# stub2 (capture): re-prologue + flag-check + op-check + capture + jump back
a = STUB2
for i, w in enumerate(PROLOG2): PATCH[a + 4*i] = w
a += 12
# flag-check: read flag (CR 0x2390), Z32 = (flag==0)
PATCH[a]     = set2(10, 0)            # r10 = 0
PATCH[a+4]   = set3(10, 10, 0x2390)   # r10 = 0x2390
PATCH[a+8]   = ld_d(10, 10, 0)        # r10 = [0x2390] = flag
PATCH[a+12]  = subsi(10, 10, 0)       # Z32 = (r10==0) = (flag==0)
BT_FLAG = a + 16                       # b.t.00 -> op-check (a+24 = OC)
PATCH[BT_FLAG] = b_t(0, BT_FLAG, a+24) # if flag==0 -> op-check
NOP_FLAG = a + 20                      # jump back (flag!=0, no-op)
PATCH[NOP_FLAG] = jump_word(NOP_FLAG, J2)
# op-check: opcode = [r6+0x28]>>16, Z32 = (opcode==0x0932)
OC = a + 24                            # op-check start
PATCH[OC]     = ld_d(11, 6, 0x0a)     # r11 = [r6+0x28] (F=0x0a = byte 0x28)
PATCH[OC+4]   = shr(11, 11, 16)       # r11 = r11 >> 16  (shamt=16! word 0xfd6b8083)
PATCH[OC+8]   = set2(12, 0x932)       # r12 = 0x932
PATCH[OC+12]  = subs(12, 12, 11)      # Z32 = (r12==r11) = (opcode==0x0932)
BF_OC = OC + 16                        # b.f.00 -> jump back (op!=0x0932)
JB = BF_OC + 4 + 48                    # jump back = CAP + 48 (computed before b_f)
PATCH[BF_OC] = b_f(0, BF_OC, JB)       # -> jump back (JB)
# capture: write exfil (CR base 0x2380, r10), scratch-only r10/r12
CAP = BF_OC + 4                        # capture start (a+24+16+4 = a+44)
PATCH[CAP]     = set2(10, 0)           # r10 = 0
PATCH[CAP+4]   = set3(10, 10, 0x2380)  # r10 = 0x2380 (CR base)
PATCH[CAP+8]   = st_d(10, 3, 0)        # CR 0x2380 = r3 (ra)
PATCH[CAP+12]  = st_d(10, 3, 1)        # CR 0x2384 = r3 (ra) (F=1 = byte 0x04)
PATCH[CAP+16]  = set2(12, 0x932)       # r12 = 0x932
PATCH[CAP+20]  = set3(12, 12, 0x0002)  # r12 = 0x09320002 (op<<16|ID2)
PATCH[CAP+24]  = st_d(10, 12, 2)       # CR 0x2388 = r12 (F=2 = byte 0x08)
PATCH[CAP+28]  = set2(12, 0x5331)      # r12 = 0x5331
PATCH[CAP+32]  = set3(12, 12, 0x0001)  # r12 = 0x53310001 (magic)
PATCH[CAP+36]  = st_d(10, 12, 3)       # CR 0x238c = r12 (F=3 = byte 0x0c)
PATCH[CAP+40]  = addi(12, 0, 1)        # r12 = 1
PATCH[CAP+44]  = st_d(10, 12, 4)       # CR 0x2390 = r12 = 1 (flag:=1) (F=4 = byte 0x10)
assert JB == CAP + 48, 'JB/CAP mismatch'
PATCH[JB] = jump_word(JB, J2)

# sanity: stub2 layout (STUB2=0x38d770; a=STUB2+12)
assert JB == STUB2 + 104, 'stub2 layout: JB=%x want %x' % (JB, STUB2+104)
assert CAP == STUB2 + 56, 'stub2 layout: CAP=%x want %x' % (CAP, STUB2+56)
assert OC == STUB2 + 36, 'stub2 layout: OC=%x want %x' % (OC, STUB2+36)
assert NOP_FLAG == STUB2 + 32, 'stub2 layout: NOP_FLAG=%x' % NOP_FLAG
assert BT_FLAG == STUB2 + 28, 'stub2 layout: BT_FLAG=%x' % BT_FLAG
assert BF_OC == STUB2 + 52, 'stub2 layout: BF_OC=%x' % BF_OC

# EXP jump targets (addr -> (want, role))
EXP_JT = {
    HOOK0: (STUB0, 'hook0'), HOOK1: (STUB1, 'hook1'), HOOK2: (STUB2, 'hook2'),
    STUB0+12: (J0, 'stub0'), STUB1+12: (J1, 'stub1'),
    NOP_FLAG: (J2, 'stub2-nop'), JB: (J2, 'stub2-jb'),
}
# EXP branch targets
EXP_BT = {
    BT_FLAG: (OC, 'b.t.00 flag==0'),
    BF_OC: (JB, 'b.f.00 op!=0x0932'),
}

sys.path.insert(0, REPO + '/scripts/probes')
sys.path.insert(0, REPO)
import mlxfwutil
from iron_boot_probe import decrc
import importlib.util
spec = importlib.util.spec_from_file_location('dec2', '/tmp/opencode/s1/dec2.py')
dec2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(dec2)

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
def die(msg):
    print('FATAL: ' + msg); sys.exit(1)

# ============ 0. base md5 ============
base_bytes = open(BASE, 'rb').read()
md5_base = hashlib.md5(base_bytes).hexdigest()
print('[0] base S0: %s size=%d md5=%s' % (BASE, len(base_bytes), md5_base))
if md5_base != BASE_MD5: die('base md5 mismatch')

# ============ 1. extract + de-clcrc ============
img = mlxfwutil.Image(base_bytes, BASE)
e = img.find_entry('ITOC', 0x03)
raw = img.section_data(e)
assert e.size == 0x3d15a0 and e.clcrc == 1 and e.addr == 0x1c748
code = decrc(raw)
assert len(code) == 0x397dc0, hex(len(code))
nlines = len(code) // 64
tail = raw[nlines*68:]
print('[1] raw MAIN_CODE: size=0x%x de-clcrc code=0x%x lines=%d' % (len(raw), len(code), nlines))

# ============ 2. round-trip ============
rt = clcrc(code, tail)
if rt != raw: die('round-trip failed')
print('[2] ROUND-TRIP: PASS (%d lines)' % nlines)

# ============ 3. sanity (pre-patch) ============
for site, pro in ((HOOK0, PROLOG0), (HOOK1, PROLOG1), (HOOK2, PROLOG2)):
    got = [u32(code, site + 4*i) for i in range(3)]
    if got != pro: die('sanity: S0 @%06x = %s, want %s' % (site, [hex(x) for x in got], [hex(x) for x in pro]))
# free zone: all stub2 words must be zero pre-patch
for a in range(STUB2, JB+4, 4):
    if u32(code, a) != 0: die('sanity: free zone @%06x not zero: %08x' % (a, u32(code, a)))
# S0 marker intact
exp_marker = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001, 0x6ca03002, 0x95f24272]
assert [u32(code, 0x38d730 + 4*i) for i in range(6)] == exp_marker, 'S0 marker unexpected'
print('[3] sanity: stock prologues OK; stub2 free zone (0x%06x-0x%06x) all zero; S0 marker intact' % (STUB2, JB))

# ============ 4. apply patch (BE) ============
code_b = bytearray(code)
for a, w in PATCH.items():
    code_b[a:a+4] = be32(w)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
dwords = sorted(a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4])
if dwords != sorted(PATCH): die('patch touched unexpected words')
print('[4] patch applied: %d words (9 hook + 4 stub0 + 4 stub1 + %d stub2)' % (len(PATCH), (JB-STUB2)//4 + 1))

# ============ 5. re-clcrc ============
praw = clcrc(code_b, tail)
assert len(praw) == len(raw)
diff_lines = sorted(i for i in range(nlines) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68])
exp_lines = sorted({a // 64 for a in PATCH})
if diff_lines != exp_lines: die('unexpected changed-line set')
print('[5] re-clcrc: %d changed lines' % len(diff_lines))
open(RAW_OUT, 'wb').write(praw)

# ============ 6. build image ============
edits = [(0x03, i*68, praw[i*68:(i+1)*68]) for i in diff_lines]
out = mlxfwutil.patch_sections(img, edits)
md5_out = hashlib.md5(out).hexdigest()
open(OUT, 'wb').write(out)
print('[6] image built: %s size=%d md5=%s' % (OUT, len(out), md5_out))

# ============ 7. verify ============
pimg = mlxfwutil.Image(out, OUT, base=img.base, fmt=img.fmt)
pe = pimg.find_entry('ITOC', 0x03)
praw2 = pimg.section_data(pe)
assert praw2 == praw, 'built section raw != clcrc raw'
pcode = decrc(praw2)
rt2 = clcrc(pcode, praw2[nlines*68:])
if rt2 != praw2: die('per-line clcrc round-trip FAILED')
print('[7.1] per-line clcrc round-trip: PASS')
errs = mlxfwutil.verify_image(pimg, deep=True)
print('[7.2] mlxfwutil verify --deep: %s' % ('PASS' if not errs else errs))
if errs: die('mlxfwutil verify failed')

# ============ 8. decode-verify jumps + branches in built image ============
print('[8] post-patch decode of jumps + branches (built image):')
ok = True
for pc in sorted(EXP_JT):
    w = u32(pcode, pc); want, role = EXP_JT[pc]
    got = jt(w, pc); jmpop = (w >> 24) & 1
    m = 'OK ' if (got == want and jmpop == 1) else 'FAIL'
    if m == 'FAIL': ok = False
    print('      %s %-12s %06x  %08x  %s -> 0x%06x (want 0x%06x)' % (m, role, pc, w, dec2.dis(w, pc), got, want))
for pc in sorted(EXP_BT):
    w = u32(pcode, pc); want, role = EXP_BT[pc]
    o = w & 0xffff
    if o & 0x8000: o -= 0x10000
    got = (pc + 4) + o * 4
    op = w >> 26
    m = 'OK ' if got == want else 'FAIL'
    if m == 'FAIL': ok = False
    print('      %s %-18s %06x  %08x  b.%s.0x%x -> 0x%06x (want 0x%06x)' % (m, role, pc, w, 't' if op==0x28 else 'f', (w>>21)&0x1f, got, want))
if not ok: die('jump/branch target mismatch in built image')

# ============ 9. capture scratch-only check (r13-r23 not clobbered) ============
print('[9] capture scratch-only check (stub2 words, rd/rt fields must be <= r12):')
bad = []
for a in range(STUB2, JB+4, 4):
    w = u32(pcode, a)
    op = w >> 26
    if op in (0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0e,0x3f):
        rd = (w >> 16) & 0x1f
        if rd >= 13: bad.append((a, 'rd=r%d' % rd, w))
    if op == 0x1b:  # st.d: rt = value register (read), rs = base (read); no clobber
        pass
if bad:
    for a, why, w in bad:
        print('      CLOBBER %06x %08x %s %s' % (a, w, why, dec2.dis(w, a)))
    die('capture clobbers preserved register (r13-r23)')
print('      PASS: no r13-r23 clobber in stub2 (only r10/r11/r12 scratch)')

# ============ 10. S0 parts integrity ============
assert u32(pcode, 0x1d594) == 0x940dc067, 'S0 injection changed'
assert [u32(pcode, 0x38d730 + 4*i) for i in range(6)] == exp_marker, 'S0 marker changed'
zone_diff = [a for a in range(0, len(code), 4) if code[a:a+4] != pcode[a:a+4] and a not in PATCH]
if zone_diff: die('unexpected word diff outside patch set: %s' % [hex(x) for x in zone_diff[:10]])
print('[10] S0 injection + marker intact; word diff vs S0 == patch set only')

print()
print('DONE %s md5=%s size=%d' % (OUT, md5_out, len(out)))
