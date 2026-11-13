#!/usr/bin/env python3
# S1 no-op detour build (DIAGNOSTIC image): S0 + pure no-op detour.
# 3 hooks (jump -> stub + 2 NOP) + 3 stubs (re-prologue of the original 3 words
# + jump S+0xC) at 0x38d750/0x38d760/0x38d77c-free zone. NO LOC logic
# (no r9-set, no op-check, no CR-read 0x2390, no TAB, no save/restore).
# State at S+0xC identical to stock; delta vs stock = PC-history + 2 jumps + 2 NOPs.
# iRISC words in memory are BIG-ENDIAN ('>I'); jump tgt = pc + 4*simm24 (REL24).
# Pipeline (build_s1_fixed2.py structure):
#   extract raw 0x03 -> de-clcrc -> round-trip -> sanity -> patch 24 words (BE) ->
#   re-clcrc (per-line calc_hwcrc seed 0x0000) -> mlxfwutil.patch_sections
#   (section CRC 0x03 crc16_mlx + entry CRC 0x03 crc16_mlx entry[0:28]) ->
#   verify (round-trip + mlxfwutil --deep) -> decode-verify jump targets.
# OFFLINE: no live-HW, no burn. Repo read-only (artifacts in /tmp/opencode/s1).
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = REPO + '/build/4030-cda-patched3.bin'
OUT  = '/tmp/opencode/s1/4030-cda-s1-noop-detour.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-noop-detour.bin'
RAW_OUT  = '/tmp/opencode/s1/main03-raw-s1-noop-detour.bin'

BASE_MD5 = '082e9678b54d0512cec2f155037e82b7'

# ---- patch words (BE), addr -> word ----
PATCH = {
    0x090b7c: 0x950bf2f5, 0x090b80: 0x00000000, 0x090b84: 0x00000000,  # hook0: jump 0x38d750
    0x090be4: 0x950bf2df, 0x090be8: 0x00000000, 0x090bec: 0x00000000,  # hook1: jump 0x38d760
    0x0d3cf4: 0x950ae69f, 0x0d3cf8: 0x00000000, 0x0d3cfc: 0x00000000,  # hook2: jump 0x38d770
    0x38d750: 0x480300bc, 0x38d754: 0x6c201806, 0x38d758: 0x703f0ff2, 0x38d75c: 0x95f40d0b,  # stub0 -> 0x090b88
    0x38d760: 0x480300bc, 0x38d764: 0x6c201806, 0x38d768: 0x703f0ffa, 0x38d76c: 0x95f40d21,  # stub1 -> 0x090bf0
    0x38d770: 0x480300bc, 0x38d774: 0x6c201806, 0x38d778: 0x703f0fda, 0x38d77c: 0x95f51961,  # stub2 -> 0x0d3d00
}
EXP_JT = {  # addr -> (want_target, role)
    0x090b7c: (0x38d750, 'hook0'), 0x090be4: (0x38d760, 'hook1'), 0x0d3cf4: (0x38d770, 'hook2'),
    0x38d75c: (0x090b88, 'stub0'), 0x38d76c: (0x090bf0, 'stub1'), 0x38d77c: (0x0d3d00, 'stub2'),
}
STOCK_PROLOG = {
    0x090b7c: [0x480300bc, 0x6c201806, 0x703f0ff2],
    0x090be4: [0x480300bc, 0x6c201806, 0x703f0ffa],
    0x0d3cf4: [0x480300bc, 0x6c201806, 0x703f0fda],
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

def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o * 4

def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)

# ============ 0. base image md5 ============
base_bytes = open(BASE, 'rb').read()
md5_base = hashlib.md5(base_bytes).hexdigest()
print('[0] base S0: %s size=%d md5=%s' % (BASE, len(base_bytes), md5_base))
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
print('[2] ROUND-TRIP: re-clcrc(code)+tail == S0 raw (0x%x bytes) IDENTICAL (%d lines)' % (len(raw), nlines))

# ============ 3. sanity (BE decode, pre-patch) ============
print('[3] pre-patch S0 words at hook sites (original prologue):')
for site, pro in STOCK_PROLOG.items():
    got = [u32(code, site + 4*i) for i in range(3)]
    if got != pro:
        die('sanity: S0 @%06x = %s, want stock prologue %s' %
            (site, ['%08x' % x for x in got], ['%08x' % x for x in pro]))
    for i in range(3):
        print('      %06x  %08x  %s' % (site + 4*i, got[i], dec2.dis(got[i], site + 4*i)))
fz = [u32(code, a) for a in range(0x38d750, 0x38d77c + 4, 4)]
if not all(w == 0 for w in fz):
    die('sanity: free zone 0x38d750..0x38d77c NOT all zero: %s' %
        ['%08x' % x for x in fz if x != 0])
print('[3] free zone 0x38d750..0x38d77c (12 words) all zero: True')
inj = u32(code, 0x1d594)
exp_marker = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001, 0x6ca03002, 0x95f24272]
assert inj == 0x940dc067, 'S0 injection dc 0x1d594 unexpected: %08x' % inj
assert [u32(code, 0x38d730 + 4*i) for i in range(6)] == exp_marker, 'S0 marker unexpected'
print('[3] S0 injection 0x1d594=0x940dc067 (call 0x38d730) + marker 0x38d730..0x38d747 intact')

# ============ 4. apply 24-word no-op detour patch (BE) ============
code_b = bytearray(code)
for a, w in PATCH.items():
    code_b[a:a+4] = be32(w)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
md5_code = hashlib.md5(code_b).hexdigest()
dwords = sorted(a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4])
if dwords != sorted(PATCH):
    die('patch touched unexpected words: diff=%s want=%s' %
        ([hex(x) for x in dwords], [hex(x) for x in sorted(PATCH)]))
print('[4] no-op detour applied: %d words (9 hook + 12 stub = 3x3 hooks + 3x4 stubs); code md5=%s' %
      (len(PATCH), md5_code))

# ============ 5. re-clcrc + changed lines ============
praw = clcrc(code_b, tail)
assert len(praw) == len(raw) == 0x3d15a0
diff_lines = sorted(i for i in range(nlines) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68])
exp_lines = sorted({a // 64 for a in PATCH})
if diff_lines != exp_lines:
    die('unexpected changed-line set: %s (want %s)' % (diff_lines, exp_lines))
for i in diff_lines:
    o = i * 68
    oldc = struct.unpack('<H', raw[o+66:o+68])[0]
    newc = struct.unpack('<H', praw[o+66:o+68])[0]
    print('[5] changed line %d (dc 0x%06x..0x%06x): clcrc 0x%04x -> 0x%04x' % (i, i*64, i*64+63, oldc, newc))
open(RAW_OUT, 'wb').write(praw)

# ============ 6. build image (section CRC 0x03 + entry CRC 0x03 via patch_sections) ============
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
if rt2 != praw2:
    inv = [i for i in range(nlines) if praw2[i*68:(i+1)*68] != rt2[i*68:(i+1)*68]]
    die('per-line clcrc round-trip FAILED: lines %s' % inv[:10])
print('[7.1] per-line clcrc round-trip: ALL %d lines recompute == stored (PASS)' % nlines)

errs = mlxfwutil.verify_image(pimg, deep=True)
print('[7.2] mlxfwutil verify --deep: %s' % ('PASS' if not errs else errs))
if errs:
    die('mlxfwutil verify failed')

def crcs(ent):
    return struct.unpack_from('>H', ent.raw, 26)[0], struct.unpack_from('>H', ent.raw, 30)[0]
b_sec, b_ent = crcs(img.find_entry('ITOC', 0x03))
n_sec, n_ent = crcs(pimg.find_entry('ITOC', 0x03))
print('[7.3] ITOC entry 0x03: S0 sec_crc=0x%04x entry_crc=0x%04x -> noop sec_crc=0x%04x entry_crc=0x%04x' %
      (b_sec, b_ent, n_sec, n_ent))
assert (n_sec, n_ent) != (b_sec, b_ent), 'entry CRCs unchanged'
assert n_sec == mlxfwutil.crc16_mlx(praw2), 'sec_crc != crc16_mlx(section data)'
assert n_ent == mlxfwutil.crc16_mlx(pimg.find_entry('ITOC', 0x03).raw[:28]), 'entry_crc != crc16_mlx(entry[0:28])'
print('      sec_crc == crc16_mlx(data) and entry_crc == crc16_mlx(entry[0:28]): verified')

# ============ 8. byte diff S0 vs new ============
diffs = [i for i in range(len(out)) if out[i] != base_bytes[i]]
sec_off = img.sec_abs(e)
sec_diff = [i for i in diffs if sec_off <= i < sec_off + len(raw)]
toc_diff = [i for i in diffs if not (sec_off <= i < sec_off + len(raw))]
bad_off = [i for i in sec_diff if (i - sec_off) // 68 not in diff_lines]
if bad_off:
    die('section diff outside changed lines: %s' % [hex(i - sec_off) for i in bad_off])
print('[8] byte diff S0 vs noop-detour: %d bytes total (section payload %d + ITOC %s)' %
      (len(diffs), len(sec_diff), ['0x%x' % i for i in toc_diff]))
assert len(toc_diff) <= 4, 'ITOC diff > 4 bytes: %s' % [hex(i) for i in toc_diff]
for i in toc_diff:
    print('      ITOC byte 0x%04x: %02x -> %02x' % (i, base_bytes[i], out[i]))
print('[8] section diff confined to the %d changed 68B lines: PASS' % len(diff_lines))

# ============ 9. decode-verify all 6 hook/stub jumps in the built image (BE) ============
print('[9] post-patch decode of 6 hook/stub jump words (built image):')
ok = True
for pc in sorted(EXP_JT):
    w = u32(pcode, pc)
    want, role = EXP_JT[pc]
    got = jt(w, pc)
    jmpop = (w >> 24) & 1
    m = 'OK ' if (got == want and jmpop == 1) else 'FAIL'
    if m == 'FAIL': ok = False
    print('      %s %s %06x  %08x  %s -> 0x%06x (want 0x%06x)' % (m, role, pc, w, dec2.dis(w, pc), got, want))
if not ok:
    die('jump target mismatch in built image')
# hook full 3-word form + stub 4-word form
for site, stub in ((0x090b7c, 0x38d750), (0x090be4, 0x38d760), (0x0d3cf4, 0x38d770)):
    hw = [u32(pcode, site + 4*i) for i in range(3)]
    sw = [u32(pcode, stub + 4*i) for i in range(4)]
    if hw[1] != 0 or hw[2] != 0:
        die('hook @%06x words 1-2 not NOP: %s' % (site, ['%08x' % x for x in hw]))
    if sw[:3] != STOCK_PROLOG[site]:
        die('stub @%06x re-prologue != stock prologue: %s' % (stub, ['%08x' % x for x in sw]))
    if sw[3] != PATCH[stub + 12]:
        die('stub @%06x jump word mismatch' % stub)
print('[9] hooks = [jump, NOP, NOP]; stubs = [stock prologue x3, jump S+0xC]: verified')

# ============ 10. S0 parts integrity in built image ============
assert u32(pcode, 0x1d594) == 0x940dc067, 'S0 injection changed'
assert [u32(pcode, 0x38d730 + 4*i) for i in range(6)] == exp_marker, 'S0 marker changed'
zone_diff = [a for a in range(0, len(code), 4)
             if code[a:a+4] != pcode[a:a+4] and a not in PATCH]
if zone_diff:
    die('unexpected word diff outside patch set: %s' % [hex(x) for x in zone_diff[:10]])
print('[10] built image: S0 injection + marker intact; word diff vs S0 == patch set (24 words) only')

print()
print('DONE %s md5=%s size=%d' % (OUT, md5_out, len(out)))
