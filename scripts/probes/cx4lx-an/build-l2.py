#!/usr/bin/env python3
"""cx4lx-an-fsm task-03: build L2 image (refs 1900 stock + VPI 0x07 + GUIDs +
raw 0x341154 00050001->0005000f, set_preset_mask chosen literal 1->0xf:
cfg-test full enabled set first attempt). Result must differ from the running
t48 image by the L2 patch only."""
import hashlib
import os
import struct
import subprocess
import sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
T48 = REPO + '/build/img_lxqsfp28_t48_1900ib.bin'
OUT = REPO + '/build/cx4lx-l2-1900ib.bin'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
T48_MD5 = '58512bc7bf6bea54db99324751ea0839'
RAW_OFF = 0x341154
BEFORE = 0x00050001
AFTER = 0x0005000f
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
VPI_OFF = 0x172af
VPI_VAL = 0x07
SITE_DC = 0x1b88c8
CONTEXT_EXPECTED = {
    SITE_DC - 8: 0x66c5005a,
    SITE_DC - 4: 0xd8a01107,
    SITE_DC + 4: 0xa00a0002,
}

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

sys.path.insert(0, REPO)
sys.path.insert(0, REPO + '/scripts/probes')
import mlxfwutil
GUID = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'guid')
MAC = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'mac')

buf = open(BASE, 'rb').read()
md5_base = hashlib.md5(buf).hexdigest()
print('[1] base md5=%s size=%d' % (md5_base, len(buf)))
if md5_base != BASE_MD5:
    die('base md5 mismatch')

img = mlxfwutil.Image(buf, BASE)
e = img.find_entry('ITOC', 0x03)
print('[2] MAIN_CODE: type=0x%02x index=%d addr=0x%x size=0x%x clcrc=%d param0=0x%x param1=0x%x' % (
    e.type, e.index, e.addr, e.size, e.clcrc, e.param0, e.param1))
if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
    die('MAIN_CODE header mismatch')

raw = img.section_data(e)
if w32be(buf, RAW_OFF) != BEFORE:
    die('expected_before mismatch: raw 0x%x = %08x != %08x' % (RAW_OFF, w32be(buf, RAW_OFF), BEFORE))
print('[3] expected_before OK: word@0x%x = %08x' % (RAW_OFF, BEFORE))

sect_off = RAW_OFF - SEC_ADDR
line, within = divmod(sect_off, 68)
dc = line * 64 + within
print('[4] raw 0x%x -> line %d (0x%x) within %d -> de-clcrc 0x%x (recon site 0x%x)' % (
    RAW_OFF, line, line, within, dc, SITE_DC))
if dc != SITE_DC or within % 4:
    die('raw offset does not map to the recon set_preset_mask site')

def dc_word(dco):
    ln, w = divmod(dco, 64)
    return w32be(buf, SEC_ADDR + ln*68 + w)

bad = [(hex(o), '%08x' % dc_word(o), '%08x' % want) for o, want in CONTEXT_EXPECTED.items()
       if dc_word(o) != want]
if bad:
    die('structural context mismatch (recon sec6 op0x36 test imm 0x1107 + b.t.0xa): %s' % bad)
ctx_pat = b''.join(struct.pack('>I', w) for w in
                   (dc_word(SITE_DC-8), dc_word(SITE_DC-4), dc_word(SITE_DC)))
code_all = decrc(raw)
if code_all.count(ctx_pat) != 1:
    die('context pattern not unique in MAIN_CODE: %d hits' % code_all.count(ctx_pat))
print('[5] structural context OK: op0x36 test [ctx+0x58]&0x1107 (66c5005a/d8a01107) '
     '-> addi r5,zero,0x1 -> b.t.0xa (a00a0002); 3-word pattern unique in section')

code = decrc(raw)
tail = raw[(len(code)//64)*68:]
rt = clcrc(code, tail)
if rt != raw:
    die('round-trip de-clcrc/re-clcrc failed')
print('[6] round-trip: OK (0x%x bytes, %d lines, tail %s)' % (len(raw), len(code)//64, tail.hex()))

pcode = bytearray(code)
struct.pack_into('>I', pcode, dc, AFTER)
pcode = bytes(pcode)
praw = clcrc(pcode, tail)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != [line]:
    die('unexpected changed-line set: %s' % diff_lines)
step1 = mlxfwutil.patch_sections(img, [(0x03, line*68, praw[line*68:line*68+68])])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
print('[7] step1 (base+L2): changed line %d only; verify(deep)=%s' % (line, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
w1 = w32be(step1, RAW_OFF)
if w1 != AFTER:
    die('step1 word@0x%x = %08x != %08x' % (RAW_OFF, w1, AFTER))
print('    word@0x%x = %08x, line clcrc 0x%04x -> 0x%04x' % (
    RAW_OFF, w1,
    struct.unpack_from('<H', raw, line*68+66)[0],
    struct.unpack_from('<H', praw, line*68+66)[0]))

step1_path = REPO + '/build/cx4lx-l2-step1.bin'
open(step1_path, 'wb').write(step1)
r = subprocess.run(['python3', 'mlxfwutil.py', 'patch', '--set', '0x11+0x2af=%02x' % VPI_VAL,
                    '-o', REPO + '/build/cx4lx-l2-step2.bin', step1_path],
                   cwd=REPO, capture_output=True, text=True)
print('[8] step2 (VPI 0x%02x): rc=%d %s%s' % (VPI_VAL, r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('VPI patch step failed')
r = subprocess.run(['python3', 'mlxfwutil.py', 'guides', '--guid', GUID, '--mac', MAC,
                    '-o', OUT, REPO + '/build/cx4lx-l2-step2.bin'],
                   cwd=REPO, capture_output=True, text=True)
print('[9] step3 (guides): rc=%d %s%s' % (r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('guides step failed')

out = open(OUT, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
checks = [
    ('word@0x%x' % RAW_OFF, '%08x' % w32be(out, RAW_OFF), '%08x' % AFTER),
    ('vpi@0x%x' % VPI_OFF, '%02x' % out[VPI_OFF], '%02x' % VPI_VAL),
]
for name, got, want in checks:
    if got != want:
        die('%s = %s != %s' % (name, got, want))
    print('[10] %s = %s OK' % (name, got))
print('[10] final md5=%s size=%d' % (md5_out, len(out)))

try:
    t48 = open(T48, 'rb').read()
except FileNotFoundError:
    t48 = None
if t48 is not None:
    if hashlib.md5(t48).hexdigest() != T48_MD5:
        die('t48 canary file md5 mismatch')
    diffs = [i for i in range(len(out)) if out[i] != t48[i]]
    ent_off = 0x2000 + 32 + e.index*32
    allowed = {RAW_OFF+3, line*68+66+SEC_ADDR, line*68+67+SEC_ADDR}
    allowed |= set(range(ent_off+0x1a, ent_off+0x20))
    stray = [hex(i) for i in diffs if i not in allowed]
    print('[11] canary vs t48: %d diff bytes, allowed-set covers all: %s' % (len(diffs), not stray))
    print('    diffs: %s' % ' '.join(hex(i) for i in diffs))
    print('    meanings: 0x%x word byte 01->0f; 0x%x/0x%x line clcrc; 0x%x..+6 ITOC entry[%d] sec/entry CRC' % (
        RAW_OFF+3, line*68+66+SEC_ADDR, line*68+67+SEC_ADDR, ent_off+0x1a, e.index))
    if stray:
        die('stray diff bytes vs t48: %s' % stray)

r = subprocess.run(['mstflint', '-i', OUT, 'verify'], capture_output=True, text=True)
print('[12] mstflint verify: rc=%d' % r.returncode)
print('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
if r.returncode != 0:
    die('mstflint verify failed')
r = subprocess.run(['mstflint', '-i', OUT, 'q'], capture_output=True, text=True)
print('[13] mstflint q:')
for l in (r.stdout + r.stderr).splitlines():
    if any(k in l for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC', 'Device ID')):
        print('    ' + l.strip())
print('DONE %s md5=%s' % (OUT, md5_out))
