#!/usr/bin/env python3
"""cx4lx-an-fsm task-03 round 2: build L2' image (refs 1900 stock + VPI 0x07 +
GUIDs + TWO-SITE raw patch: 0x341154 00050001->0005000f (set_preset_mask chosen
literal 1->0xf) AND 0x341158 a00a0002->a40a0002 (b.t.0xa -> b.f.0xa: branch
always taken, live set3 skipped, chosen = literal 0xf). Round 1 proved the
single-site literal dead (live set3 path overwrites it 294/294). Both sites are
in the same clcrc line; result must differ from the running t48 image by the L2'
patch only, and from the round-1 L2 image by the branch site only."""
import hashlib
import os
import struct
import subprocess
import sys

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
T48 = REPO + '/build/img_lxqsfp28_t48_1900ib.bin'
L2R1 = REPO + '/build/cx4lx-l2-1900ib.bin'
OUT = REPO + '/build/cx4lx-l2p-1900ib.bin'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
T48_MD5 = '58512bc7bf6bea54db99324751ea0839'
L2R1_MD5 = '32624fceeba3314634a794e25f0c1cab'
RAW1_OFF = 0x341154
RAW2_OFF = 0x341158
BEFORE1 = 0x00050001
AFTER1 = 0x0005000f
BEFORE2 = 0xa00a0002
AFTER2 = 0xa40a0002
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
VPI_OFF = 0x172af
VPI_VAL = 0x07
SITE1_DC = 0x1b88c8
SITE2_DC = 0x1b88cc
BLOCK_DC = 0x1b88c0
BLOCK_EXPECTED = [
    (0x66c5005a, 'ld.d r5,r22,0x58'),
    (0xd8a01107, None),
    (0x00050001, 'addi r5,zero,0x1'),
    (0xa00a0002, 'b.t.0xa zero,0x1b88d4'),
    (0x20850001, 'set3 r5,r4,0x1'),
    (0x6ec0283a, 'st.d r5,r22,0x38'),
    (0x00040040, 'addi r4,zero,0x40'),
    (0x00050001, 'addi r5,zero,0x1'),
    (0x94f935ac, None),
]

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
sys.path.insert(0, REPO + '/scripts/irisc')
import mlxfwutil
GUID = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'guid')
MAC = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'mac')
import irisc_dis

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
for off, want, name in ((RAW1_OFF, BEFORE1, 'site1-literal'), (RAW2_OFF, BEFORE2, 'site2-branch')):
    if w32be(buf, off) != want:
        die('expected_before mismatch %s: raw 0x%x = %08x != %08x' % (name, off, w32be(buf, off), want))
print('[3] expected_before OK both sites: 0x%x=%08x (literal), 0x%x=%08x (b.t.0xa)' % (
    RAW1_OFF, BEFORE1, RAW2_OFF, BEFORE2))

def raw_to_dc(off):
    line, within = divmod(off - SEC_ADDR, 68)
    return line, within, line * 64 + within

l1, w1in, dc1 = raw_to_dc(RAW1_OFF)
l2, w2in, dc2 = raw_to_dc(RAW2_OFF)
print('[4] site1: raw 0x%x -> line %d within %d -> dc 0x%x (expect 0x%x); site2: raw 0x%x -> line %d within %d -> dc 0x%x (expect 0x%x)' % (
    RAW1_OFF, l1, w1in, dc1, SITE1_DC, RAW2_OFF, l2, w2in, dc2, SITE2_DC))
if dc1 != SITE1_DC or dc2 != SITE2_DC:
    die('raw offsets do not map to the recon sites')
if l1 != l2:
    die('sites not in the same clcrc line: %d vs %d' % (l1, l2))
if w1in % 4 or w2in % 4 or w2in - w1in != 4:
    die('sites not consecutive aligned words in one line')
line = l1

def dc_word(dco):
    ln, w = divmod(dco, 64)
    return w32be(buf, SEC_ADDR + ln*68 + w)

for i, (want, _) in enumerate(BLOCK_EXPECTED):
    o = BLOCK_DC + i*4
    if dc_word(o) != want:
        die('block word dc 0x%x = %08x != %08x' % (o, dc_word(o), want))
print('[5] structural context OK: full 9-word block dc 0x%x..0x%x == journal task-03 9.1 decode' % (
    BLOCK_DC, BLOCK_DC + 32))
pat5 = b''.join(struct.pack('>I', w) for w in
                (dc_word(SITE1_DC-8), dc_word(SITE1_DC-4), dc_word(SITE1_DC),
                 dc_word(SITE1_DC+4), dc_word(SITE1_DC+8)))
code_all = decrc(raw)
if code_all.count(pat5) != 1:
    die('5-word context pattern not unique in MAIN_CODE: %d hits' % code_all.count(pat5))
print('    5-word pattern unique in section (1 hit)')

pdec1 = irisc_dis.dis(AFTER1, SITE1_DC)
pdec2 = irisc_dis.dis(AFTER2, SITE2_DC)
sdec2 = irisc_dis.dis(BEFORE2, SITE2_DC)
print('[5b] encoding decode: patched site1 "%s"; site2 stock "%s" -> patched "%s"' % (pdec1, sdec2, pdec2))
if pdec1 != 'addi r5,zero,0xf':
    die('patched literal does not decode to addi r5,zero,0xf')
if pdec2 != 'b.f.0xa zero,0x1b88d4' or sdec2 != 'b.t.0xa zero,0x1b88d4':
    die('branch polarity decode mismatch (expect b.t.0xa -> b.f.0xa, same target 0x1b88d4)')

code = decrc(raw)
tail = raw[(len(code)//64)*68:]
rt = clcrc(code, tail)
if rt != raw:
    die('round-trip de-clcrc/re-clcrc failed')
print('[6] round-trip: OK (0x%x bytes, %d lines, tail %s)' % (len(raw), len(code)//64, tail.hex()))

pcode = bytearray(code)
struct.pack_into('>I', pcode, dc1, AFTER1)
struct.pack_into('>I', pcode, dc2, AFTER2)
pcode = bytes(pcode)
praw = clcrc(pcode, tail)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != [line]:
    die('unexpected changed-line set: %s (expect only [%d])' % (diff_lines, line))
step1 = mlxfwutil.patch_sections(img, [(0x03, line*68, praw[line*68:line*68+68])])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
print('[7] step1 (base+L2prime): changed line %d only; verify(deep)=%s' % (line, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
for off, want in ((RAW1_OFF, AFTER1), (RAW2_OFF, AFTER2)):
    if w32be(step1, off) != want:
        die('step1 word@0x%x = %08x != %08x' % (off, w32be(step1, off), want))
print('    words: 0x%x=%08x, 0x%x=%08x; line clcrc 0x%04x -> 0x%04x' % (
    RAW1_OFF, AFTER1, RAW2_OFF, AFTER2,
    struct.unpack_from('<H', raw, line*68+66)[0],
    struct.unpack_from('<H', praw, line*68+66)[0]))

step1_path = REPO + '/build/cx4lx-l2p-step1.bin'
open(step1_path, 'wb').write(step1)
r = subprocess.run(['python3', 'mlxfwutil.py', 'patch', '--set', '0x11+0x2af=%02x' % VPI_VAL,
                    '-o', REPO + '/build/cx4lx-l2p-step2.bin', step1_path],
                   cwd=REPO, capture_output=True, text=True)
print('[8] step2 (VPI 0x%02x): rc=%d %s%s' % (VPI_VAL, r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('VPI patch step failed')
r = subprocess.run(['python3', 'mlxfwutil.py', 'guides', '--guid', GUID, '--mac', MAC,
                    '-o', OUT, REPO + '/build/cx4lx-l2p-step2.bin'],
                   cwd=REPO, capture_output=True, text=True)
print('[9] step3 (guides): rc=%d %s%s' % (r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('guides step failed')

out = open(OUT, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
checks = [
    ('word@0x%x' % RAW1_OFF, '%08x' % w32be(out, RAW1_OFF), '%08x' % AFTER1),
    ('word@0x%x' % RAW2_OFF, '%08x' % w32be(out, RAW2_OFF), '%08x' % AFTER2),
    ('vpi@0x%x' % VPI_OFF, '%02x' % out[VPI_OFF], '%02x' % VPI_VAL),
]
for name, got, want in checks:
    if got != want:
        die('%s = %s != %s' % (name, got, want))
    print('[10] %s = %s OK' % (name, got))
print('[10] final md5=%s size=%d' % (md5_out, len(out)))

ent_off = 0x2000 + 32 + e.index*32
clcrc_lo = line*68+66+SEC_ADDR
clcrc_hi = clcrc_lo + 1
entry_crc = set(range(ent_off+0x1a, ent_off+0x20))
lit_byte = RAW1_OFF+3
br_byte = RAW2_OFF
allowed_t48 = {lit_byte, br_byte, clcrc_lo, clcrc_hi} | entry_crc
allowed_l2r1 = {br_byte, clcrc_lo, clcrc_hi} | entry_crc

def canary(path, md5w, label, allowed):
    try:
        ref = open(path, 'rb').read()
    except FileNotFoundError:
        print('[11] %s: canary file missing, skipped' % label)
        return
    if hashlib.md5(ref).hexdigest() != md5w:
        die('%s canary file md5 mismatch' % label)
    diffs = [i for i in range(len(out)) if out[i] != ref[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    print('[11] canary vs %s: %d diff bytes, allowed-set covers all: %s' % (label, len(diffs), not stray))
    print('    diffs: %s' % ' '.join(hex(i) for i in diffs))
    if stray:
        die('stray diff bytes vs %s: %s' % (label, stray))
    if label == 't48':
        print('    meanings: 0x%x literal byte 01->0f; 0x%x branch MSB a0->a4; '
              '0x%x/0x%x line clcrc; 0x%x..+6 ITOC entry[%d] sec/entry CRC' % (
                  lit_byte, br_byte, clcrc_lo, clcrc_hi, ent_off+0x1a, e.index))
    else:
        print('    meanings vs round-1 L2: 0x%x branch MSB a0->a4 (round-2 delta = '
              'branch-polarity site only); 0x%x/0x%x line clcrc; 0x%x..+6 ITOC entry[%d] CRC' % (
                  br_byte, clcrc_lo, clcrc_hi, ent_off+0x1a, e.index))

canary(T48, T48_MD5, 't48', allowed_t48)
canary(L2R1, L2R1_MD5, 'l2-round1', allowed_l2r1)

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
