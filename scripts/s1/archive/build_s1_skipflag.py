#!/usr/bin/env python3
# S1 skip-flag-check build (BISECT image, 1 burn): S1-fixed2 + 1 word:
#   0x38d750: 0x240e0000 (set2 r14,zero,0) -> 0x95000031 (jump 0x38d814)
# Fresh-boot common path becomes:
#   hook [nop; or r9,zero,ID; jump 0x38d750] -> jump 0x38d814 (dispatch)
#   -> b.bset 1,r9 / b.bset 0,r9 -> re-prologue -> jump S+0xC
# REMOVED vs S1-fixed2 (fresh boot): flag-check 0x38d750..0x38d760
#   (r14 writes, CR-read 0x2390 -> r12, subsi r12, b.t.00) + capture path
#   0x38d764..0x38d810 (unreachable anyway on fresh boot).
# KEPT: hook r9-set (clobber r9) + dispatch (b.bset on r9).
# What the burn tests:
#   boot OK  => RC in flag-check (CR-read 0x2390 / clobber r12 [+r14])
#   fail     => RC in clobber r9 / dispatch
# iRISC words BIG-ENDIAN ('>I'); jump tgt = pc + 4*simm24 (REL24).
# Pipeline (build_s1_fixed2.py structure): extract raw 0x03 -> de-clcrc ->
# round-trip -> sanity -> patch 1 word (BE) -> re-clcrc (per-line
# calc_hwcrc seed 0x0000) -> mlxfwutil.patch_sections (section CRC 0x03
# crc16_mlx + entry CRC 0x03 crc16_mlx entry[0:28]) -> verify -> decode.
# OFFLINE: no live-HW, no burn. Repo read-only (artifacts in /tmp/opencode/s1).
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = '/tmp/opencode/s1/4030-cda-s1-fixed2.bin'
OUT  = '/tmp/opencode/s1/4030-cda-s1-skipflag.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-skipflag.bin'
RAW_OUT  = '/tmp/opencode/s1/main03-raw-s1-skipflag.bin'

BASE_MD5 = 'f258edf0022d0ab4b8f92a3704e36a46'
ADDR, OLD_W, NEW_W = 0x38d750, 0x240e0000, 0x95000031

sys.path.insert(0, REPO + '/scripts/probes')
sys.path.insert(0, REPO)
import mlxfwutil
from iron_boot_probe import decrc

# decoder (verified BE)
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
def s16(v): return v - 0x10000 if v & 0x8000 else v
def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o * 4
def brt(w, pc):
    return (pc + 4) + s16(w & 0xffff) * 4

def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)

# ============ 0. base image md5 ============
base_bytes = open(BASE, 'rb').read()
md5_base = hashlib.md5(base_bytes).hexdigest()
print('[0] base S1-fixed2: %s size=%d md5=%s' % (BASE, len(base_bytes), md5_base))
if md5_base != BASE_MD5:
    die('base md5 mismatch (want %s)' % BASE_MD5)

# ============ 1. extract raw MAIN_CODE + de-clcrc ============
img = mlxfwutil.Image(base_bytes, BASE)
e = img.find_entry('ITOC', 0x03)
raw = img.section_data(e)
assert e.size == 0x3d15a0 and e.clcrc == 1 and e.addr == 0x1c748, (hex(e.size), e.clcrc, hex(e.addr))
assert e.param0 == 0x800000 and e.param1 == 0x81d58c
code = decrc(raw)
assert len(code) == 0x397dc0, hex(len(code))
nlines = len(code) // 64
tail = raw[nlines*68:]
print('[1] raw MAIN_CODE: size=0x%x addr=0x%x clcrc=1; de-clcrc code=0x%x lines=%d tail(4B)=%s' %
      (len(raw), e.addr, len(code), nlines, tail.hex()))

# ============ 2. round-trip (pre-patch) ============
rt = clcrc(code, tail)
if rt != raw:
    first = next(i for i in range(len(raw)) if rt[i] != raw[i])
    die('round-trip failed at raw byte 0x%x (line %d)' % (first, first // 68))
print('[2] ROUND-TRIP: re-clcrc(code)+tail == S1-fixed2 raw (0x%x bytes) IDENTICAL (%d lines)' % (len(raw), nlines))

# ============ 3. sanity (BE decode, pre-patch) ============
# 3.1 patch site
w = u32(code, ADDR)
print('[3] @0x%06x pre-patch: %08x  %s' % (ADDR, w, dec2.dis(w, ADDR)))
if w != OLD_W:
    die('sanity: @0x%06x = %08x, want %08x (set2 r14,zero,0)' % (ADDR, w, OLD_W))
# 3.2 flag-check rest + dispatch + re-prologue intact (decode-verified in analyze step)
EXP = {
    0x38d754: (0x21ce2390, 'set3 r14,r14,0x2390'),
    0x38d758: (0x65cc0002, 'ld.d r12,r14,0x0'),
    0x38d75c: (0x158c0000, 'subsi r12,r12,0x0'),
    0x38d760: (0xa000002c, 'b.t.00 zero,0x38d814'),
    0x38d814: (0xa9210009, 'b.bset 1,r9,0x38d83c'),
    0x38d818: (0xa9200004, 'b.bset 0,r9,0x38d82c'),
}
for a, (ew, ed) in EXP.items():
    gw = u32(code, a)
    if gw != ew or dec2.dis(gw, a) != ed:
        die('sanity: @0x%06x = %08x (%s), want %08x (%s)' % (a, gw, dec2.dis(gw, a), ew, ed))
if brt(u32(code, 0x38d760), 0x38d760) != 0x38d814: die('sanity: b.t @0x38d760 target')
if brt(u32(code, 0x38d814), 0x38d814) != 0x38d83c: die('sanity: b.bset @0x38d814 target')
if brt(u32(code, 0x38d818), 0x38d818) != 0x38d82c: die('sanity: b.bset @0x38d818 target')
REPRO = {0x38d81c: (0x090b88, 0x703f0ff2), 0x38d82c: (0x090bf0, 0x703f0ffa), 0x38d83c: (0x0d3d00, 0x703f0fda)}
for g, (want_tgt, wst) in REPRO.items():
    w0, w1, w2, w3 = (u32(code, g + 4*i) for i in range(4))
    if (w0, w1, w2) != (0x480300bc, 0x6c201806, wst) or jt(w3, g + 12) != want_tgt:
        die('sanity: re-prologue @%06x corrupted' % g)
# 3.3 hooks (r9-set + jump 0x38d750) intact
HOOKS = {0x090b7c: 0x090b80, 0x090be4: 0x090be8, 0x0d3cf4: 0x0d3cf8}
def is_r9set(w, idv):
    # or r9,zero,ID  (op 0x0c, rd=9, rs=0, imm16=ID)
    return ((w >> 26) & 0x3f) == 0x0c and ((w >> 16) & 0x1f) == 9 and \
           ((w >> 21) & 0x1f) == 0 and (w & 0xffff) == idv
HOOK_ID = {0x090b7c: 0, 0x090be4: 1, 0x0d3cf4: 2}
for site, r9addr in HOOKS.items():
    h = [u32(code, site + 4*i) for i in range(3)]
    if h[0] != 0 or not is_r9set(h[1], HOOK_ID[site]):
        die('sanity: hook @%06x r9-set word corrupted: %s' % (site, ['%08x' % x for x in h]))
    if jt(h[2], site + 8) != 0x38d750:
        die('sanity: hook @%06x jump target != 0x38d750' % site)
# 3.4 S0 marker + injection intact
inj = u32(code, 0x1d594)
exp_marker = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001, 0x6ca03002, 0x95f24272]
assert inj == 0x940dc067, 'S0 injection dc 0x1d594 unexpected: %08x' % inj
assert [u32(code, 0x38d730 + 4*i) for i in range(6)] == exp_marker, 'S0 marker unexpected'
print('[3] sanity: flag-check/dispatch/re-prologue/hooks/S0-marker all intact (BE decode verified)')

# ============ 4. apply 1-word patch ============
# verify patch word decodes as jump 0x38d814
op, rd, rs, rt, imm = NEW_W >> 26, (NEW_W >> 16) & 0x1f, (NEW_W >> 21) & 0x1f, (NEW_W >> 11) & 0x1f, NEW_W & 0xffff
if op != 0x25 or ((NEW_W >> 24) & 1) != 1:
    die('patch word %08x is not a jump' % NEW_W)
if jt(NEW_W, ADDR) != 0x38d814:
    die('patch word jump target != 0x38d814')
print('[4] patch word %08x: %s -> target 0x%06x (dispatch): verified' %
      (NEW_W, dec2.dis(NEW_W, ADDR), jt(NEW_W, ADDR)))
code_b = bytearray(code)
code_b[ADDR:ADDR+4] = be32(NEW_W)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
md5_code = hashlib.md5(code_b).hexdigest()
dwords = [a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4]]
if dwords != [ADDR]:
    die('patch touched more than 1 word: %s' % [hex(x) for x in dwords])
print('[4] 1-word patch applied: 0x%06x %08x -> %08x; code md5=%s' % (ADDR, OLD_W, NEW_W, md5_code))

# ============ 5. re-clcrc + changed lines ============
praw = clcrc(code_b, tail)
assert len(praw) == len(raw) == 0x3d15a0
diff_lines = [i for i in range(nlines) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
exp_line = ADDR // 64
if diff_lines != [exp_line]:
    die('unexpected changed-line set: %s (want [%d])' % (diff_lines, exp_line))
o = exp_line * 68
oldc = struct.unpack('<H', raw[o+66:o+68])[0]
newc = struct.unpack('<H', praw[o+66:o+68])[0]
print('[5] re-clcrc: exactly 1 line changed: line %d dc 0x%06x raw 0x%06x..0x%06x clcrc 0x%04x -> 0x%04x' %
      (exp_line, exp_line*64, o, o+68, oldc, newc))
open(RAW_OUT, 'wb').write(praw)

# ============ 6. build image (section CRC 0x03 + entry CRC 0x03 via patch_sections) ============
edits = [(0x03, exp_line*68, praw[exp_line*68:(exp_line+1)*68])]
out = mlxfwutil.patch_sections(img, edits)
md5_out = hashlib.md5(out).hexdigest()
open(OUT, 'wb').write(out)
print('[6] image built: %s size=%d md5=%s' % (OUT, len(out), md5_out))

# ============ 7. verify ============
# 7.1 per-line clcrc full round-trip on new raw
pimg = mlxfwutil.Image(out, OUT, base=img.base, fmt=img.fmt)
pe = pimg.find_entry('ITOC', 0x03)
praw2 = pimg.section_data(pe)
assert praw2 == praw, 'built section raw != clcrc raw'
pcode = decrc(praw2)
rt2 = clcrc(pcode, praw2[nlines*68:])
if rt2 != praw2:
    inv = [i for i in range(nlines) if praw2[i*68:(i+1)*68] != rt2[i*68:(i+1)*68]]
    die('per-line clcrc round-trip FAILED: lines %s' % inv[:10])
print('[7.1] per-line clcrc round-trip: ALL %d lines recompute == stored (PASS)' % nlines)

# 7.2 mlxfwutil verify --deep (in-process)
errs = mlxfwutil.verify_image(pimg, deep=True)
print('[7.2] mlxfwutil verify --deep (in-process): %s' % ('PASS' if not errs else errs))
if errs:
    die('mlxfwutil verify failed')

# 7.3 ITOC entry 0x03 CRC fields
def crcs(ent):
    return struct.unpack_from('>H', ent.raw, 26)[0], struct.unpack_from('>H', ent.raw, 30)[0]
b_sec, b_ent = crcs(img.find_entry('ITOC', 0x03))
n_sec, n_ent = crcs(pimg.find_entry('ITOC', 0x03))
print('[7.3] ITOC entry 0x03: S1fixed2 sec_crc=0x%04x entry_crc=0x%04x -> skipflag sec_crc=0x%04x entry_crc=0x%04x' %
      (b_sec, b_ent, n_sec, n_ent))
assert (n_sec, n_ent) != (b_sec, b_ent), 'entry CRCs unchanged'
assert n_sec == mlxfwutil.crc16_mlx(praw2), 'sec_crc != crc16_mlx(section data)'
assert n_ent == mlxfwutil.crc16_mlx(pimg.find_entry('ITOC', 0x03).raw[:28]), 'entry_crc != crc16_mlx(entry[0:28])'
print('      sec_crc == crc16_mlx(data) and entry_crc == crc16_mlx(entry[0:28]): verified')

# ============ 8. byte diff S1-fixed2 vs skipflag ============
diffs = [i for i in range(len(out)) if out[i] != base_bytes[i]]
sec_off = img.sec_abs(e)
sec_diff = [i for i in diffs if sec_off <= i < sec_off + len(raw)]
toc_diff = [i for i in diffs if not (sec_off <= i < sec_off + len(raw))]
print('[8] byte diff S1fixed2 vs skipflag: %d bytes total (section payload %d + ITOC %s)' %
      (len(diffs), len(sec_diff), ['0x%x' % i for i in toc_diff]))
bad_off = [i for i in sec_diff if (i - sec_off) // 68 != exp_line]
if bad_off:
    die('section diff outside the one changed line: %s' % [hex(i - sec_off) for i in bad_off])
line_diff = [b for b in range(68) if praw[o+b] != raw[o+b]]
print('      inside line %d: %d bytes differ (word @0x%02x..0x%02x + clcrc 0x42..0x43)' %
      (exp_line, len(line_diff), (ADDR-o)//4*4, (ADDR-o)//4*4+3))
assert len(toc_diff) <= 4, 'ITOC diff > 4 bytes: %s' % [hex(i) for i in toc_diff]
for i in toc_diff:
    print('      ITOC byte 0x%04x: %02x -> %02x' % (i, base_bytes[i], out[i]))
# full word diff of de-clcrc code == [ADDR]
wdiff = [a for a in range(0, len(code), 4) if code[a:a+4] != pcode[a:a+4]]
if wdiff != [ADDR]:
    die('code word diff != [0x%06x]: %s' % (ADDR, [hex(x) for x in wdiff]))
print('[8] code word diff == [0x%06x] only; nothing else' % ADDR)

# ============ 9. decode-verify in built image ============
print('[9] post-patch decode of the new common path (built image):')
for a in (ADDR, ADDR+4, ADDR+8, ADDR+12, ADDR+16):
    w = u32(pcode, a)
    extra = ''
    op = w >> 26
    if op == 0x25: extra = '  -> 0x%06x (jmpop=%d)' % (jt(w, a), (w >> 24) & 1)
    elif op in (0x28, 0x29, 0x2a, 0x2b): extra = '  -> 0x%06x' % brt(w, a)
    print('      %06x  %08x  %-28s%s' % (a, w, dec2.dis(w, a), extra))
w = u32(pcode, ADDR)
assert w == NEW_W and jt(w, ADDR) == 0x38d814 and ((w >> 24) & 1) == 1
print('      0x%06x = %08x = jump 0x38d814 (jmpop=1): CONFIRMED in built image' % (ADDR, w))
for a in (0x38d814, 0x38d818):
    w = u32(pcode, a)
    assert dec2.dis(w, a) == ('b.bset 1,r9,0x38d83c' if a == 0x38d814 else 'b.bset 0,r9,0x38d82c')
print('      dispatch 0x38d814/0x38d818 (b.bset on r9): intact')
for g, (want_tgt, wst) in REPRO.items():
    w0, w1, w2, w3 = (u32(pcode, g + 4*i) for i in range(4))
    assert (w0, w1, w2) == (0x480300bc, 0x6c201806, wst) and jt(w3, g+12) == want_tgt
print('      re-prologue groups 0x38d81c/0x38d82c/0x38d83c -> 0x090b88/0x090bf0/0x0d3d00: intact')
for site, r9addr in HOOKS.items():
    h = [u32(pcode, site + 4*i) for i in range(3)]
    assert h[0] == 0 and is_r9set(h[1], HOOK_ID[site]) and jt(h[2], site+8) == 0x38d750
print('      hooks [nop; or r9,zero,ID; jump 0x38d750]: intact (r9-set KEPT)')

# ============ 10. S0-parts integrity ============
assert u32(pcode, 0x1d594) == 0x940dc067
assert [u32(pcode, 0x38d730+4*i) for i in range(6)] == exp_marker
zone_diff = [a for a in list(range(0x090b7c, 0x090b88, 4)) + list(range(0x090be4, 0x090bf0, 4)) +
             list(range(0x0d3cf4, 0x0d3d00, 4)) + list(range(0x38d750, 0x38d8f4, 4))
             if code[a:a+4] != pcode[a:a+4]]
if zone_diff != [ADDR]:
    die('hooks/LOC/TAB zone diff != [0x%06x]: %s' % (ADDR, [hex(x) for x in zone_diff]))
print('[10] built image: S0 injection + marker intact; hooks/LOC/TAB zone diff == [0x%06x] only' % ADDR)

print()
print('DONE %s md5=%s size=%d' % (OUT, md5_out, len(out)))
