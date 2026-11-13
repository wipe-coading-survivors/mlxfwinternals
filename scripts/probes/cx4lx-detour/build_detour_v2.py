#!/usr/bin/env python3
"""cx4lx-detour L3: build boot-detour v2 image for CX-4 Lx 14.32.1900.

v2 = v1 boot-detour (marker CR 0x23f0) + iTrace runtime hook:
- reader word0 (unlock-check fn 0xd4c8c, raw 0x24f294) 2404badc -> 95091fcc
  `jump 0x31cbbc' (flash-op trigger, preserves semantics via inline body)
- cave stub @0x31cbbc (14 words): save link csr0xbc -> r10, emit dead db0
  string rt 0x00ada612 'got an unexpected memory profile value,
  memory_profile = 0x%x' param 0xbad via emit1 0x603c (no gate -> ring
  write regardless of mask), restore link, inline reader body, ret.d.
- v1 block @0x31cba0 unchanged (6 words) -> total 20 of 24 cave words.

Base = refs stock 1900-GCA (one-factor experiment; built fresh from stock,
not from the v1 binary). Plus VPI 0x07 + card GUID/MAC (as v1). Section 0x30
untouched.

Gates: base-md5 / expected_before (injection word + 24 zero cave words +
reader word0 + reader body words 1..7) / raw<->dc mapping / entry-block
pattern unique / decode of every patched word / round-trip de-clcrc+re-clcrc
/ changed-line set == {507, 13618, 50990, 50991} / verify --deep / step
diff vs base (stray=NONE per step) / diff vs v1 image exactly hook delta /
mstflint verify bootable / mstflint q identity."""
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[3])
BASE = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
OUT = REPO + '/build/cx4lx-detour-v2.bin'
V1 = REPO + '/build/cx4lx-detour-v1.bin'
V1_MD5 = 'e91cac9ccf9bdf6e3729a215f641fc48'
STEP1 = REPO + '/build/cx4lx-detour-v2-step1.bin'
STEP2 = REPO + '/build/cx4lx-detour-v2-step2.bin'
LOG = REPO + '/build/cx4lx-detour-v2-build.log'
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
READER_DC = 0xd4c8c
READER_BEFORE = 0x2404badc
READER_AFTER = 0x95091fcb
READER_BODY = [0x20850ffe, 0x4a0608fc, 0x00040001, 0xfca53005,
               0xa4000002, 0x00040000, 0xfc00002d]
STUB_DC = 0x31cbb8
STUB = [0x480a00bc, 0x0004a612, 0x088400ae, 0x00050bad, 0x94f3a51d,
        0x4d4000bc, 0x2404badc, 0x20850ffe, 0x4a0608fc, 0x00040001,
        0xfca53005, 0xa4000002, 0x00040000, 0xfc00002d]
V1_SHELLCODE = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001,
                0x6ca03002, 0x95f3accf]
SHELLCODE = V1_SHELLCODE + STUB
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


def dc_to_raw(dc):
    line, within = divmod(dc, 64)
    return SEC_ADDR + line * 68 + within


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
    die('cave not all-zero in de-clcrc view')
READER_RAW = dc_to_raw(READER_DC)
if w32be(buf, READER_RAW) != READER_BEFORE:
    die('expected_before reader word0: raw 0x%x = %08x != %08x' % (READER_RAW, w32be(buf, READER_RAW), READER_BEFORE))
for i, want in enumerate(READER_BODY):
    if w32be(buf, dc_to_raw(READER_DC + 4*(i+1))) != want:
        die('reader body word %d mismatch' % (i+1))
say('[3] expected_before OK: inj raw 0x%x=%08x; cave dc 0x%x..0x%x all-zero (dc view); reader 0x%x=%08x + body 7 words intact (raw 0x%x)' % (
    INJ_RAW, INJ_BEFORE, CAVE_DC, CAVE_END_DC, READER_DC, READER_BEFORE, READER_RAW))

li, wi, dci = raw_to_dc(INJ_RAW)
lc, wc, dcc = raw_to_dc(CAVE_RAW)
lr, wr, dcr = raw_to_dc(READER_RAW)
sc_end_dc = CAVE_DC + 4*len(SHELLCODE)
if (dci, dcc, dcr) != (INJ_DC, CAVE_DC, READER_DC):
    die('raw offsets do not map to L1/L3 geometry sites')
if sc_end_dc > CAVE_END_DC:
    die('shellcode exceeds cave end')
if STUB_DC != CAVE_DC + 4*len(V1_SHELLCODE):
    die('stub does not follow v1 block')
patched_dcs = [INJ_DC, READER_DC] + [CAVE_DC + 4*i for i in range(len(SHELLCODE))]
changed_lines = sorted({dc // 64 for dc in patched_dcs})
if changed_lines != [507, 13618, 50990, 50991]:
    die('unexpected changed-line set: %s' % changed_lines)
say('[4] mapping: inj raw 0x%x -> dc 0x%x; cave raw 0x%x -> dc 0x%x; reader raw 0x%x -> dc 0x%x; changed lines %s' % (
    INJ_RAW, INJ_DC, CAVE_RAW, CAVE_DC, READER_RAW, READER_DC, changed_lines))

def dc_word(dco):
    ln, w = divmod(dco, 64)
    return w32be(buf, SEC_ADDR + ln*68 + w)

for i, want in enumerate(ENTRY_BLOCK):
    o = ENTRY_DC + i*4
    if dc_word(o) != want:
        die('entry block word dc 0x%x = %08x != %08x' % (o, dc_word(o), want))
pat = b''.join(struct.pack('>I', w) for w in ENTRY_BLOCK)
if code.count(pat) != 1:
    die('entry 5-word pattern not unique: %d hits' % code.count(pat))
say('[5] entry block == L1 decode, pattern unique; [5b] decodes:')

pdec = irisc_dis.dis(INJ_AFTER, INJ_DC)
sdec = irisc_dis.dis(INJ_BEFORE, INJ_DC)
rdec_after = irisc_dis.dis(READER_AFTER, READER_DC)
rdec_before = irisc_dis.dis(READER_BEFORE, READER_DC)
if pdec != 'call 0x31cba0' or sdec != 'call 0x7ef0':
    die('injection decode: "%s" -> "%s"' % (sdec, pdec))
if rdec_after != 'jump 0x31cbb8' or rdec_before != 'set2 r4,zero,0xbadc':
    die('reader patch decode: "%s" -> "%s"' % (rdec_before, rdec_after))
say('    inj: "%s" -> "%s"; reader: "%s" -> "%s"' % (sdec, pdec, rdec_before, rdec_after))
want_stub_dis = ['csr.r r10,csr0xbc', 'addi r4,zero,0x-59ee', 'addi.hi r4,r4,0xae',
                 'addi r5,zero,0xbad', 'call 0x603c', 'csr.w r10,zero,0xbc',
                 'set2 r4,zero,0xbadc', 'set3 r5,r4,0xffe', 'ld.i r6,0x8fc',
                 'addi r4,zero,0x1', 'subs r5,r5,r6', 'b.f.0x0 zero,0x31cbec',
                 'addi r4,zero,0x0', 'ret.d zero,zero,zero']
for i, (w, want) in enumerate(zip(STUB, want_stub_dis)):
    d = irisc_dis.dis(w, STUB_DC + 4*i)
    if d != want:
        die('stub word %d decode "%s" != "%s"' % (i, d, want))
    say('    stub[%2d] dc 0x%x %08x = %s' % (i, STUB_DC + 4*i, w, d))
lo = STUB[1] & 0xffff
lo_s = lo - 0x10000 if lo & 0x8000 else lo
if (lo_s + ((STUB[2] & 0xffff) << 16)) & 0xffffffff != 0x00ada612:
    die('string pair does not compose to rt 0x00ada612')

rt = clcrc(code)
if rt != raw:
    die('round-trip de-clcrc/re-clcrc failed')
say('[6] round-trip: OK (%d lines)' % (len(code)//64))

pcode = bytearray(code)
struct.pack_into('>I', pcode, INJ_DC, INJ_AFTER)
struct.pack_into('>I', pcode, READER_DC, READER_AFTER)
for i, w in enumerate(SHELLCODE):
    struct.pack_into('>I', pcode, CAVE_DC + 4*i, w)
pcode = bytes(pcode)
praw = clcrc(pcode)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != changed_lines:
    die('unexpected changed-line set: %s (expect %s)' % (diff_lines, changed_lines))
step1 = mlxfwutil.patch_sections(img, [(0x03, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
say('[7] step1 (base+detour v2): changed lines %s only; verify(deep)=%s' % (
    changed_lines, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
for off, want, name in [(INJ_RAW, INJ_AFTER, 'injection'), (READER_RAW, READER_AFTER, 'reader-patch'),
                        (dc_to_raw(STUB_DC), STUB[0], 'stub[0]'),
                        (dc_to_raw(STUB_DC + 4*13), STUB[13], 'stub[13]')]:
    if w32be(step1, off) != want:
        die('step1 %s word@0x%x = %08x != %08x' % (name, off, w32be(step1, off), want))
for ln in changed_lines:
    say('    line %d clcrc %04x -> %04x' % (ln,
        struct.unpack_from('<H', raw, ln*68+66)[0], struct.unpack_from('<H', praw, ln*68+66)[0]))
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
if w32be(out, INJ_RAW) != INJ_AFTER or out[VPI_OFF] != VPI_VAL or w32be(out, READER_RAW) != READER_AFTER:
    die('final identity words lost')
for i, w in enumerate(SHELLCODE):
    if w32be(out, dc_to_raw(CAVE_DC + 4*i)) != w:
        die('cave word %d lost in final image' % i)
say('[10] final words OK: inj=%08x, reader=%08x, cave %d words, vpi=%02x; md5=%s size=%d' % (
    INJ_AFTER, READER_AFTER, len(SHELLCODE), VPI_VAL, md5_out, len(out)))

ent_off = 0x2000 + 32 + e.index*32
allowed_step1 = set()
for dc in patched_dcs:
    allowed_step1 |= set(range(dc_to_raw(dc), dc_to_raw(dc) + 4))
for ln in changed_lines:
    allowed_step1 |= {ln*68+66+SEC_ADDR, ln*68+67+SEC_ADDR}
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

def diff_check(label, new, old, allowed):
    diffs = [i for i in range(min(len(new), len(old))) if new[i] != old[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    say('[11] %s: %d diff bytes, stray=%s' % (label, len(diffs), stray if stray else 'NONE'))
    if stray:
        die('stray diff bytes in %s: %s' % (label, stray))
    return diffs

diff_check('step1 vs base (detour v2)', step1, buf, allowed_step1)
eo11 = 0x2000 + 32 + ent11.index*32
allowed_vpi_step = {VPI_OFF} | set(range(eo11+0x1a, eo11+0x20))
diff_check('step2 vs step1 (VPI)', step2, step1, allowed_vpi_step)
diff_check('final vs step2 (guides)', out, step2, allowed_guides)

v1 = open(V1, 'rb').read()
if hashlib.md5(v1).hexdigest() != V1_MD5:
    die('v1 image md5 mismatch (expected %s)' % V1_MD5)
allowed_v1diff = set(allowed_step1)
d = diff_check('v2(final) vs v1 image (hook delta)', out, v1, allowed_v1diff)
new_bytes = [hex(i) for i in d if i not in set(range(INJ_RAW, INJ_RAW+4)) | {VPI_OFF}]
region_ok = all(SEC_ADDR <= i < SEC_ADDR+SEC_SIZE or 0x2000 <= i < 0x2900 for i in d)
say('    hook-delta bytes (excl shared inj/vpi): %d; all within MAIN_CODE+ITOC region: %s' % (
    len(new_bytes), 'OK' if region_ok else 'FAIL'))
if not region_ok:
    die('hook delta escaped MAIN_CODE/ITOC region')

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
