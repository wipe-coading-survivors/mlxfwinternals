#!/usr/bin/env python3
# S1 bisect "nor14" diagnostic image (1 burn):
#   S1-fixed2 + flag-check CR base r14 -> r11 (scratch).
#   Eliminates the r14 (callee-saved) clobber; KEEPS the CR-read 0x2390.
# RC hypothesis: LOC flag-check `set2/set3 r14; ld.d r12,r14` clobbers r14
# (callee-saved per ABI scan 603/603) with no save/restore -> caller r14
# corrupted -> ALLOC_UAR assert. r9/r12 are scratch (ABI-legal).
# Interpretation: boot OK => r14-clobber was RC; fail(same assert) => CR-read
# 0x2390 side-effect implicated (r9/r12 scratch clobbers kept, ABI-legal).
# Pipeline (verbatim build_s1_fixed2.py): extract raw 0x03 -> de-clcrc ->
# round-trip -> sanity -> patch 3 words (BE) -> re-clcrc -> patch_sections
# (sec CRC 0x03 crc16_mlx + entry CRC 0x03) -> verify -> decode-verify.
# OFFLINE: no live-HW, no burn. Repo read-only (artifacts in /tmp/opencode/s1).
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = '/tmp/opencode/s1/4030-cda-s1-fixed2.bin'
OUT  = '/tmp/opencode/s1/4030-cda-s1-bisect-nor14.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-bisect-nor14.bin'
RAW_OUT  = '/tmp/opencode/s1/main03-raw-s1-bisect-nor14.bin'

BASE_MD5 = 'f258edf0022d0ab4b8f92a3704e36a46'

# flag-check CR base r14 -> r11 (scratch); CR-read 0x2390 kept, r12 dest kept
PATCH = {
    0x38d750: 0x240b0000,  # set2 r11,zero,0x0        (was set2 r14,zero,0x0  0x240e0000)
    0x38d754: 0x216b2390,  # set3 r11,r11,0x2390      (was set3 r14,r14,0x2390 0x21ce2390)
    0x38d758: 0x656c0002,  # ld.d  r12,r11,0x0        (was ld.d  r12,r14,0x0  0x65cc0002)
}
OLD = {0x38d750: 0x240e0000, 0x38d754: 0x21ce2390, 0x38d758: 0x65cc0002}

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

# ============ 3. sanity: current flag-check words ============
print('[3] pre-patch decode 0x38d750..0x38d764 (flag-check):')
for a in range(0x38d750, 0x38d764, 4):
    w = u32(code, a)
    print('      %06x  %08x  %s' % (a, w, dec2.dis(w, a)))
    if a in OLD and w != OLD[a]:
        die('sanity: word @0x%06x = %08x, want %08x' % (a, w, OLD[a]))
print('[3] sanity: flag-check == S1-fixed2 (set2/set3 r14; ld.d r12,r14; subsi; b.t): confirmed')

# ============ 4. apply 3-word patch (r14 -> r11) ============
code_b = bytearray(code)
for a, w in PATCH.items():
    code_b[a:a+4] = be32(w)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
md5_code = hashlib.md5(code_b).hexdigest()
dwords = sorted(a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4])
if dwords != sorted(PATCH):
    die('patch touched unexpected words: %s want %s' % ([hex(x) for x in dwords], [hex(x) for x in sorted(PATCH)]))
print('[4] flag-check r14->r11 applied: %d words; code md5=%s' % (len(PATCH), md5_code))

# 4.1 S0 parts + hooks + rest of LOC intact
inj = u32(code_b, 0x1d594)
assert inj == 0x940dc067, 'injection dc 0x1d594 changed'
exp_marker = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001, 0x6ca03002, 0x95f24272]
assert [u32(code_b, 0x38d730+4*i) for i in range(6)] == exp_marker, 'S0 marker changed'
# hooks (r9 clobber + jump) must be UNCHANGED
for site in (0x090b7c, 0x090be4, 0x0d3cf4):
    assert code_b[site:site+12] == code[site:site+12], 'hook @%06x changed' % site
print('[4.1] S0 injection+marker + 3 hooks + rest of LOC byte-identical (only 3 flag-check words changed)')

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

# ============ 6. build image (section CRC 0x03 + entry CRC 0x03) ============
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
print('[7.3] ITOC entry 0x03: fixed2 sec_crc=0x%04x entry_crc=0x%04x -> nor14 sec_crc=0x%04x entry_crc=0x%04x' %
      (b_sec, b_ent, n_sec, n_ent))
assert (n_sec, n_ent) != (b_sec, b_ent), 'entry CRCs unchanged'
assert n_sec == mlxfwutil.crc16_mlx(praw2), 'sec_crc != crc16_mlx(section data)'
assert n_ent == mlxfwutil.crc16_mlx(pimg.find_entry('ITOC', 0x03).raw[:28]), 'entry_crc != crc16_mlx(entry[0:28])'
print('      sec_crc == crc16_mlx(data) and entry_crc == crc16_mlx(entry[0:28]): verified')

# ============ 8. byte diff fixed2 vs nor14 ============
diffs = [i for i in range(len(out)) if out[i] != base_bytes[i]]
sec_off = img.sec_abs(e)
sec_diff = [i for i in diffs if sec_off <= i < sec_off + len(raw)]
toc_diff = [i for i in diffs if not (sec_off <= i < sec_off + len(raw))]
bad_off = [i for i in sec_diff if (i - sec_off) // 68 not in diff_lines]
if bad_off:
    die('section diff outside changed lines: %s' % [hex(i - sec_off) for i in bad_off])
print('[8] byte diff fixed2 vs nor14: %d bytes total (section payload %d + ITOC %s)' %
      (len(diffs), len(sec_diff), ['0x%x' % i for i in toc_diff]))
assert len(toc_diff) <= 4, 'ITOC diff > 4 bytes: %s' % [hex(i) for i in toc_diff]
for i in toc_diff:
    print('      ITOC byte 0x%04x: %02x -> %02x' % (i, base_bytes[i], out[i]))
print('[8] section diff confined to the %d changed 68B lines: PASS' % len(diff_lines))

# ============ 9. decode-verify flag-check (post-patch, BE) ============
print('[9] post-patch decode 0x38d750..0x38d764 (flag-check, r14->r11):')
for a in range(0x38d750, 0x38d764, 4):
    w = u32(pcode, a)
    print('      %06x  %08x  %s' % (a, w, dec2.dis(w, a)))
assert u32(pcode, 0x38d750) == 0x240b0000 and dec2.dis(u32(pcode, 0x38d750), 0x38d750) == 'set2 r11,zero,0x0'
assert u32(pcode, 0x38d754) == 0x216b2390 and dec2.dis(u32(pcode, 0x38d754), 0x38d754) == 'set3 r11,r11,0x2390'
assert u32(pcode, 0x38d758) == 0x656c0002 and dec2.dis(u32(pcode, 0x38d758), 0x38d758) == 'ld.d r12,r11,0x0'
assert u32(pcode, 0x38d75c) == 0x158c0000, 'subsi r12 word changed'
assert u32(pcode, 0x38d760) == 0xa000002c, 'b.t word changed'
print('[9] flag-check: CR base now r11 (scratch); CR-read 0x2390 + r12 dest + branch INTACT; r14 no longer written')

# ============ 10. full LOC/hooks zone diff vs fixed2 ============
sec_b = pimg.section_data(pe)
c_sec = decrc(sec_b)
zone = list(range(0x090b7c, 0x090b88, 4)) + list(range(0x090be4, 0x090bf0, 4)) + \
       list(range(0x0d3cf4, 0x0d3d00, 4)) + list(range(0x38d750, 0x38d8f4, 4))
zone_diff = [a for a in zone if code[a:a+4] != c_sec[a:a+4]]
if zone_diff != sorted(PATCH):
    die('hooks/LOC zone diff != the 3 flag-check words: %s' % [hex(x) for x in zone_diff])
assert u32(c_sec, 0x1d594) == 0x940dc067
print('[10] built image: S0 injection+marker+hooks intact; LOC/hooks zone diff == 3 flag-check words only')

print()
print('DONE %s md5=%s size=%d' % (OUT, md5_out, len(out)))
