#!/usr/bin/env python3
"""cx4lx-detour L2: build boot-detour v1 image for CX-4 Lx 14.32.1900.

Base = refs stock 1900-GCA (one-factor experiment, no L2'/AN stacking).
Patch = 1-word injection at raw 0x1756d0 (dc 0x7ee4 entry `call main-init`
94000003 -> 940c532f `call 0x31cba0`) + 6-word shellcode in the EOF-pad cave
dc 0x31cba0..0x31cc00 (raw 0x4bb858..): set2/set3 r5=0x23f0, set2/set3
r6=0xbadc0001, st.d r6,r5,0 (marker -> CR 0x23f0), jump 0x7ef0 (resume
main-init). Plus VPI byte 0x11+0x2af=0x07 (card runs IB class, keep it) and
card GUID/MAC via mlxfwutil guides. Section 0x30 untouched (spec L2 rule).

Gates: base-md5 / expected_before (injection word + 24 all-zero cave words) /
raw<->dc mapping vs L1 ground truth / entry-block pattern unique in MAIN_CODE
/ decode of every patched word / round-trip de-clcrc+re-clcrc / changed-line
set == {507, 50990} / verify --deep / step-by-step byte-diff vs base exactly
covering: 7 detour words + line clcrc + ITOC entry[18] CRC + VPI + guides
sections / mstflint verify bootable / mstflint q identity."""
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[3])
BASE = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
OUT = REPO + '/build/cx4lx-detour-v1.bin'
STEP1 = REPO + '/build/cx4lx-detour-step1.bin'
STEP2 = REPO + '/build/cx4lx-detour-step2.bin'
LOG = REPO + '/build/cx4lx-detour-v1-build.log'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
INJ_RAW = 0x1756d0
INJ_DC = 0x7ee4
INJ_BEFORE = 0x94000003
INJ_AFTER = 0x940c532f
CAVE_RAW = 0x4bb858
CAVE_DC = 0x31cba0
CAVE_END_DC = 0x31cc00
CAVE_WORDS = 24
ENTRY_DC = 0x7edc
ENTRY_BLOCK = [0x94fff51b, 0x703f07fa, 0x94000003, 0x95000000, 0x95000000]
SHELLCODE = [
    (0x24050000, 'set2 r5,zero,0x0'),
    (0x20a523f0, 'set3 r5,r5,0x23f0'),
    (0x2406badc, 'set2 r6,zero,0xbadc'),
    (0x20c60001, 'set3 r6,r6,0x1'),
    (0x6ca03002, 'st.d r6,r5,0x0'),
    (0x95f3accf, 'jump 0x7ef0'),
]
VPI_OFF = 0x172af
VPI_VAL = 0x07

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

def clcrc(code):
    assert len(code) % 64 == 0
    out = bytearray()
    for i in range(len(code) // 64):
        line = bytearray(code[i*64:(i+1)*64]) + b'\x00\x00'
        line += struct.pack('<H', calc_hwcrc(0x0000, bytes(line)))
        out += line
    return bytes(out)

def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i*68:i*68+64]
    return bytes(out)

def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)

def w32be(b, o):
    return struct.unpack_from('>I', b, o)[0]

def raw_to_dc(off):
    line, within = divmod(off - SEC_ADDR, 68)
    return line, within, line * 64 + within

sys.path.insert(0, REPO)
sys.path.insert(0, REPO + '/scripts/irisc')
import mlxfwutil
GUID = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'guid')
MAC = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'mac')
import irisc_dis

lines_out = []
def say(msg=''):
    print(msg)
    lines_out.append(msg)

buf = open(BASE, 'rb').read()
md5_base = hashlib.md5(buf).hexdigest()
say('[1] base md5=%s size=%d' % (md5_base, len(buf)))
if md5_base != BASE_MD5:
    die('base md5 mismatch')

img = mlxfwutil.Image(buf, BASE)
e = img.find_entry('ITOC', 0x03)
say('[2] MAIN_CODE: type=0x%02x index=%d addr=0x%x size=0x%x clcrc=%d param0=0x%x param1=0x%x' % (
    e.type, e.index, e.addr, e.size, e.clcrc, e.param0, e.param1))
if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
    die('MAIN_CODE header mismatch')

raw = img.section_data(e)
code = decrc(raw)
tail = raw[(len(code)//64)*68:]
if len(tail):
    die('unexpected non-empty section tail: %s' % tail.hex())
if w32be(buf, INJ_RAW) != INJ_BEFORE:
    die('expected_before injection: raw 0x%x = %08x != %08x' % (INJ_RAW, w32be(buf, INJ_RAW), INJ_BEFORE))
cave_zeros = all(w32be(code, CAVE_DC + 4*i) == 0 for i in range(CAVE_WORDS))
if not cave_zeros:
    die('cave not all-zero in de-clcrc view: dc 0x%x..0x%x' % (CAVE_DC, CAVE_END_DC))
say('[3] expected_before OK: raw 0x%x=%08x (entry call main-init); cave dc 0x%x..0x%x all-zero (%d words, de-clcrc view; raw code bytes of lines straddle pad+clcrc, checked in dc)' % (
    INJ_RAW, INJ_BEFORE, CAVE_DC, CAVE_END_DC, CAVE_WORDS))

li, wi, dci = raw_to_dc(INJ_RAW)
lc, wc, dcc = raw_to_dc(CAVE_RAW)
sc_end_dc = CAVE_DC + 4*len(SHELLCODE)
say('[4] mapping: inj raw 0x%x -> line %d within %d -> dc 0x%x (expect 0x%x); cave raw 0x%x -> line %d within %d -> dc 0x%x (expect 0x%x)' % (
    INJ_RAW, li, wi, dci, INJ_DC, CAVE_RAW, lc, wc, dcc, CAVE_DC))
if (dci, dcc) != (INJ_DC, CAVE_DC):
    die('raw offsets do not map to L1 geometry sites')
if li == lc:
    die('injection and shellcode unexpectedly in the same clcrc line')
if sc_end_dc > CAVE_END_DC:
    die('shellcode exceeds cave end')
if (sc_end_dc - 1) // 64 != lc:
    die('shellcode crosses a clcrc line boundary (build script assumes single line)')
changed_lines = sorted([li, lc])

def dc_word(dco):
    ln, w = divmod(dco, 64)
    return w32be(buf, SEC_ADDR + ln*68 + w)

for i, want in enumerate(ENTRY_BLOCK):
    o = ENTRY_DC + i*4
    if dc_word(o) != want:
        die('entry block word dc 0x%x = %08x != %08x' % (o, dc_word(o), want))
say('[5] structural context OK: entry block dc 0x%x..0x%x == L1 decode (call sp_init / st.d! / call main-init / self-jump x2)' % (
    ENTRY_DC, ENTRY_DC + 16))
pat = b''.join(struct.pack('>I', w) for w in ENTRY_BLOCK)
code_all = decrc(raw)
if code_all.count(pat) != 1:
    die('entry 5-word pattern not unique in MAIN_CODE: %d hits' % code_all.count(pat))
say('    5-word entry pattern unique in section (1 hit)')

pdec = irisc_dis.dis(INJ_AFTER, INJ_DC)
sdec = irisc_dis.dis(INJ_BEFORE, INJ_DC)
if pdec != 'call 0x31cba0' or sdec != 'call 0x7ef0':
    die('injection decode mismatch: stock "%s" -> patched "%s"' % (sdec, pdec))
say('[5b] injection decode: "%s" -> "%s"' % (sdec, pdec))
for i, (w, want) in enumerate(SHELLCODE):
    d = irisc_dis.dis(w, CAVE_DC + 4*i)
    if d != want:
        die('shellcode word %d decode "%s" != "%s"' % (i, d, want))
    say('    sc[%d] dc 0x%x %08x = %s' % (i, CAVE_DC + 4*i, w, d))

rt = clcrc(code)
if rt != raw:
    die('round-trip de-clcrc/re-clcrc failed')
say('[6] round-trip: OK (0x%x bytes, %d lines, no tail)' % (len(raw), len(code)//64))

pcode = bytearray(code)
struct.pack_into('>I', pcode, INJ_DC, INJ_AFTER)
for i, (w, _) in enumerate(SHELLCODE):
    struct.pack_into('>I', pcode, CAVE_DC + 4*i, w)
pcode = bytes(pcode)
praw = clcrc(pcode)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != changed_lines:
    die('unexpected changed-line set: %s (expect %s)' % (diff_lines, changed_lines))
step1 = mlxfwutil.patch_sections(img, [(0x03, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
say('[7] step1 (base+detour): changed lines %s only; verify(deep)=%s' % (changed_lines, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
for off, want, name in [(INJ_RAW, INJ_AFTER, 'injection'), (CAVE_RAW, SHELLCODE[0][0], 'sc[0]'),
                        (CAVE_RAW + 4*5, SHELLCODE[5][0], 'sc[5]')]:
    if w32be(step1, off) != want:
        die('step1 %s word@0x%x = %08x != %08x' % (name, off, w32be(step1, off), want))
say('    words: 0x%x=%08x; cave sc[0]=%08x sc[5]=%08x; clcrc line %d 0x%04x->0x%04x, line %d 0x%04x->0x%04x' % (
    INJ_RAW, INJ_AFTER, SHELLCODE[0][0], SHELLCODE[5][0],
    li, struct.unpack_from('<H', raw, li*68+66)[0], struct.unpack_from('<H', praw, li*68+66)[0],
    lc, struct.unpack_from('<H', raw, lc*68+66)[0], struct.unpack_from('<H', praw, lc*68+66)[0]))
open(STEP1, 'wb').write(step1)

r = subprocess.run(['python3', 'mlxfwutil.py', 'patch', '--set', '0x11+0x2af=%02x' % VPI_VAL,
                    '-o', STEP2, STEP1], cwd=REPO, capture_output=True, text=True)
say('[8] step2 (VPI 0x%02x): rc=%d %s%s' % (VPI_VAL, r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('VPI patch step failed')
step2 = open(STEP2, 'rb').read()

r = subprocess.run(['python3', 'mlxfwutil.py', 'guides', '--guid', GUID, '--mac', MAC,
                    '-o', OUT, STEP2], cwd=REPO, capture_output=True, text=True)
say('[9] step3 (guides): rc=%d %s%s' % (r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('guides step failed')

out = open(OUT, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
for name, got, want in [
        ('word@0x%x' % INJ_RAW, '%08x' % w32be(out, INJ_RAW), '%08x' % INJ_AFTER),
        ('vpi@0x%x' % VPI_OFF, '%02x' % out[VPI_OFF], '%02x' % VPI_VAL)]:
    if got != want:
        die('%s = %s != %s' % (name, got, want))
for i, (w, _) in enumerate(SHELLCODE):
    if w32be(out, CAVE_RAW + 4*i) != w:
        die('cave word %d lost in final image' % i)
say('[10] final words OK: 0x%x=%08x, cave %d words intact, vpi=%02x' % (INJ_RAW, INJ_AFTER, len(SHELLCODE), VPI_VAL))
say('[10] final md5=%s size=%d' % (md5_out, len(out)))

ent_off = 0x2000 + 32 + e.index*32
allowed_step1 = set(range(INJ_RAW, INJ_RAW + 4)) | set(range(CAVE_RAW, CAVE_RAW + 4*len(SHELLCODE)))
allowed_step1 |= {li*68+66+SEC_ADDR, li*68+67+SEC_ADDR, lc*68+66+SEC_ADDR, lc*68+67+SEC_ADDR}
allowed_step1 |= set(range(ent_off+0x1a, ent_off+0x20))

def sec_ranges(image, sec_type):
    ent = image.find_entry('ITOC', sec_type)
    eo = 0x2000 + 32 + ent.index*32
    return set(range(ent.addr, ent.addr + ent.size)) | set(range(eo, eo + 32)), ent

img1 = mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt)
img2 = mlxfwutil.Image(step2, 'step2', base=img.base, fmt=img.fmt)
allowed_vpi, ent11 = sec_ranges(img1, 0x11)
allowed_guides = set()
for st in (0xE1, 0xE0):
    rng, ent = sec_ranges(img1, st)
    allowed_guides |= rng
    say('    guides section 0x%02x: index=%d addr=0x%x size=0x%x' % (st, ent.index, ent.addr, ent.size))

def diff_check(label, new, old, allowed):
    diffs = [i for i in range(min(len(new), len(old))) if new[i] != old[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    say('[11] %s: %d diff bytes, stray=%s' % (label, len(diffs), stray if stray else 'NONE'))
    say('    diffs: %s' % ' '.join(hex(i) for i in diffs))
    if stray:
        die('stray diff bytes in %s: %s' % (label, stray))
    return diffs

d1 = diff_check('step1 vs base (detour)', step1, buf, allowed_step1)
eo11 = 0x2000 + 32 + ent11.index*32
allowed_vpi_step = {VPI_OFF} | set(range(eo11+0x1a, eo11+0x20))
d2 = diff_check('step2 vs step1 (VPI)', step2, step1, allowed_vpi_step)
d3 = diff_check('final vs step2 (guides)', out, step2, allowed_guides)
say('[11] VPI delta = data byte 0x%x (%02x->%02x) + ITOC entry[%d] (section 0x11) CRC bytes 0x%x..+0x%x: %s' % (
    VPI_OFF, step1[VPI_OFF], step2[VPI_OFF], ent11.index, eo11+0x1a, eo11+0x20,
    'OK' if set(d2) <= allowed_vpi_step and VPI_OFF in d2 else 'FAIL'))
if not set(d2) <= allowed_vpi_step or VPI_OFF not in d2:
    die('VPI step changed unexpected bytes')

r = subprocess.run(['mstflint', '-i', OUT, 'verify'], capture_output=True, text=True)
say('[12] mstflint verify: rc=%d' % r.returncode)
say('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
if r.returncode != 0:
    die('mstflint verify failed')
r = subprocess.run(['mstflint', '-i', OUT, 'q'], capture_output=True, text=True)
say('[13] mstflint q:')
ok13 = {}
for l in (r.stdout + r.stderr).splitlines():
    if any(k in l for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC')):
        say('    ' + l.strip())
        for k, v in (('Image type', 'FS3'), ('FW Version', '14.32.1900'), ('PSID', 'MT_2430110032'),
                     ('Base GUID', mlxfwutil.hw('CARD_CX4LX_BCAT', 'guid')), ('Base MAC', mlxfwutil.hw('CARD_CX4LX_BCAT', 'mac'))):
            if l.startswith(k):
                ok13[k] = v in l
for k, v in ok13.items():
    if not v:
        die('identity check failed: %s' % k)
if set(ok13) != {'Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC'}:
    die('identity lines missing in q output')

open(LOG, 'w').write('\n'.join(lines_out) + '\n')
say('DONE %s md5=%s log=%s' % (OUT, md5_out, LOG))
