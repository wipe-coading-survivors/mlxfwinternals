#!/usr/bin/env python3
# S1-fixed2 build: 1-word op-check offset fix in S1-fixed MAIN_CODE (0x03):
#   0x38d774: 0x64cb0072 (ld.d r11,r6,0x1c = byte+0x70, WRONG)
#           -> 0x64cb002a (ld.d r11,r6,0x0a = byte+0x28, CORRECT)
# RE root-cause: opcode = [D+0x28]>>16, D = r6 = completion descriptor base.
# Pipeline (PC4 / build_s1_fixed.py structure):
#   extract raw 0x03 -> de-clcrc -> round-trip -> sanity -> patch 1 word ->
#   re-clcrc (per-line calc_hwcrc seed 0x0000) -> mlxfwutil.patch_sections
#   (section CRC 0x03 crc16_mlx + entry CRC 0x03 crc16_mlx entry[0:28]) ->
#   verify (round-trip + mlxfwutil --deep) -> cross-check vs S1-fixed.
# OFFLINE: no live-HW, no burn. Repo read-only (artifacts in /tmp/opencode/s1).
import os, struct, hashlib, sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = '/tmp/opencode/s1/4030-cda-s1-fixed.bin'
OUT  = '/tmp/opencode/s1/4030-cda-s1-fixed2.bin'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1-fixed2.bin'
RAW_OUT  = '/tmp/opencode/s1/main03-raw-s1-fixed2.bin'

ADDR, OLD_W, NEW_W = 0x38d774, 0x64cb0072, 0x64cb002a

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

def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)

# dis.py (raw-word decoder, /tmp/opencode/irisc/dis.py)
import importlib.util
spec = importlib.util.spec_from_file_location('dis', '/tmp/opencode/irisc/dis.py')
dismod = importlib.util.module_from_spec(spec); spec.loader.exec_module(dismod)

# ============ 0. base image md5 ============
base_bytes = open(BASE, 'rb').read()
md5_base = hashlib.md5(base_bytes).hexdigest()
print('[0] base S1-fixed: %s size=%d md5=%s' % (BASE, len(base_bytes), md5_base))
if md5_base != '3fec53b044f12a77c2972f564821b511':
    die('base md5 mismatch')

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
print('[2] ROUND-TRIP: re-clcrc(code)+tail == S1-fixed raw (0x%x bytes) IDENTICAL (%d lines)' % (len(raw), nlines))

# ============ 3. sanity: current words @0x38d770..0x38d780 ============
pre = {a: u32(code, a) for a in range(0x38d770, 0x38d780, 4)}
print('[3] pre-patch decode 0x38d770..0x38d780:')
for a, w in pre.items():
    print('      %06x  %08x  %s' % (a, w, dismod.dis(w, a)))
if pre[ADDR] != OLD_W:
    die('sanity: word @0x%06x = %08x, want %08x (addr/word mismatch)' % (ADDR, pre[ADDR], OLD_W))
shr_txt = dismod.dis(pre[ADDR + 4], ADDR + 4)
if shr_txt != 'shr r11,r11,0x16':
    die('sanity: word @0x%06x decodes %r, want shr r11,r11,0x16' % (ADDR + 4, shr_txt))
print('[3] sanity: @0x38d774 == 0x64cb0072 (ld.d r11,r6,0x1c = byte+0x70) and @0x38d778 == shr r11,r11,0x16 (intact)')

# ============ 4. apply 1-word fix ============
code_b = bytearray(code)
code_b[ADDR:ADDR+4] = be32(NEW_W)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
md5_code = hashlib.md5(code_b).hexdigest()
# only that word changed
dwords = [a for a in range(0, len(code), 4) if code[a:a+4] != code_b[a:a+4]]
if dwords != [ADDR]:
    die('patch touched more than 1 word: %s' % [hex(x) for x in dwords])
print('[4] 1-word fix applied: 0x%06x %08x -> %08x; code md5=%s' % (ADDR, OLD_W, NEW_W, md5_code))

# 4.1 S0 marker + injection + locator rest intact (only 0x38d774 changed)
inj = u32(code_b, 0x1d594)
assert inj == 0x940dc067, 'injection dc 0x1d594 changed'
exp_marker = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001, 0x6ca03002, 0x95f24272]
assert [u32(code_b, 0x38d730+4*i) for i in range(6)] == exp_marker, 'S0 marker changed'
assert code_b[ADDR+4:ADDR+8] == be32(u32(code, ADDR+4)), 'shr word changed'
print('[4.1] S0 injection 0x1d594=0x940dc067 + S0 marker 0x38d730..0x38d747 + rest of LOC byte-identical')

# ============ 5. re-clcrc + line diff vs base raw ============
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

# 7.2 mlxfwutil verify --deep
errs = mlxfwutil.verify_image(pimg, deep=True)
print('[7.2] mlxfwutil verify --deep: %s' % ('PASS' if not errs else errs))
if errs:
    die('mlxfwutil verify failed')

# 7.3 ITOC entry 0x03 CRC fields (entry.raw: sec_crc @26-27 BE, entry_crc @30-31 BE)
def crcs(ent):
    return struct.unpack_from('>H', ent.raw, 26)[0], struct.unpack_from('>H', ent.raw, 30)[0]
b_sec, b_ent = crcs(img.find_entry('ITOC', 0x03))
n_sec, n_ent = crcs(pimg.find_entry('ITOC', 0x03))
print('[7.3] ITOC entry 0x03: S1fixed sec_crc=0x%04x entry_crc=0x%04x -> S1fixed2 sec_crc=0x%04x entry_crc=0x%04x' %
      (b_sec, b_ent, n_sec, n_ent))
assert (n_sec, n_ent) != (b_sec, b_ent), 'entry CRCs unchanged'
assert n_sec == mlxfwutil.crc16_mlx(praw2), 'sec_crc != crc16_mlx(section data)'
assert n_ent == mlxfwutil.crc16_mlx(pimg.find_entry('ITOC', 0x03).raw[:28]), 'entry_crc != crc16_mlx(entry[0:28])'
print('      sec_crc == crc16_mlx(data) and entry_crc == crc16_mlx(entry[0:28]): verified')

# ============ 8. cross-check S1-fixed vs S1-fixed2 ============
diffs = [i for i in range(len(out)) if out[i] != base_bytes[i]]
sec_off = img.sec_abs(e)
sec_diff = [i for i in diffs if sec_off <= i < sec_off + len(raw)]
toc_diff = [i for i in diffs if not (sec_off <= i < sec_off + len(raw))]
print('[8] byte diff S1fixed vs S1fixed2: %d bytes total (section payload %d + ITOC %s)' %
      (len(diffs), len(sec_diff), ['0x%x' % i for i in toc_diff]))
bad_off = [i for i in sec_diff if (i - sec_off) // 68 != exp_line]
if bad_off:
    die('section diff outside the one changed line: %s' % [hex(i - sec_off) for i in bad_off])
line_diff = [b for b in range(68) if praw[o+b] != raw[o+b]]
print('      inside line %d: %d bytes differ (word 0x%02x..0x%02x + clcrc 0x42..0x43): %s' %
      (exp_line, len(line_diff), (ADDR - o) >> 2 and (ADDR-o)//4, (ADDR-o)//4+1, line_diff))
assert not bad_off
assert len(toc_diff) <= 4, 'ITOC diff > 4 bytes: %s' % [hex(i) for i in toc_diff]
for i in toc_diff:
    print('      ITOC byte 0x%04x: %02x -> %02x' % (i, base_bytes[i], out[i]))
print('[8] cross-check: exactly 1 word (0x38d774) + clcrc of its line + ITOC fields; nothing else')

# ============ 9. decode-verify op-check region (post-patch) ============
print('[9] post-patch decode 0x38d770..0x38d780:')
for a in range(0x38d770, 0x38d780, 4):
    w = u32(pcode, a)
    print('      %06x  %08x  %s' % (a, w, dismod.dis(w, a)))
assert u32(pcode, ADDR) == NEW_W
assert dismod.dis(u32(pcode, ADDR), ADDR) == 'ld.d r11,r6,0xa'
assert u32(pcode, ADDR+4) == u32(code, ADDR+4) and dismod.dis(u32(pcode, ADDR+4), ADDR+4) == 'shr r11,r11,0x16'
print('[9] op-check: 0x38d774 = 0x64cb002a (ld.d r11,r6,0x0a = byte+0x28) + 0x38d778 = shr r11,r11,0x16 (intact)')

# ============ 10. final S0-parts integrity in the built image ============
sec_b = pimg.section_data(pe)
c_sec = decrc(sec_b)
assert u32(c_sec, 0x1d594) == 0x940dc067
assert [u32(c_sec, 0x38d730+4*i) for i in range(6)] == exp_marker
# full LOC/TAB/hooks zone identical to S1fixed except 0x38d774
zone_diff = [a for a in list(range(0x090b7c, 0x090b88, 4)) + list(range(0x090be4, 0x090bf0, 4)) +
             list(range(0x0d3cf4, 0x0d3d00, 4)) + list(range(0x38d750, 0x38d8f4, 4))
             if code[a:a+4] != c_sec[a:a+4]]
if zone_diff != [ADDR]:
    die('hooks/LOC/TAB zone diff != [0x38d774]: %s' % [hex(x) for x in zone_diff])
print('[10] built image: S0 injection + marker intact; hooks/LOC/TAB zone diff == [0x38d774] only')

print()
print('DONE %s md5=%s size=%d' % (OUT, md5_out, len(out)))
