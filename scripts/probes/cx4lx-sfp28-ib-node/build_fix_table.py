#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task-04t: build the C12 fix-table image (OFFLINE).

Image = consumer stock ri (base md5 dacbcf0e...) + TWO MAIN_CODE patches
+ R1 build-ID in 0x30:

1) C12-gate-lift word (0x1f, MANDATORY): dc 0x1f1f00 (raw 0x37e0f0)
   0xfcb1c083 -> 0x0011001f (addi r17,zero,0x1f). Lifts the C12 gate pm 0->2
   (Polling) so the AN path is active for the C12 module. Without it the port
   is gated (pm=0) and AN never starts (OUTCOME Y). Reused verbatim from the
   0x1f+H0/H6 dump images (task-04l/04o).

2) BOOT-INJECTION trampoline (the fix): write 0x6005014 to iRISC RAM 0x0D600C
   at boot, BEFORE AN. Root-fix for the deterministic 14.32 Lx C12 assert:
   F1 flag1 lookup (dc 0x18c05c) reads ONE word 0x0D600C, 7x3-bit fields
   field_i=(word>>4i)&7. runtime 0x5014 -> valid {0,1,4,5}; key 6 (C12) absent
   -> assert ext_synd 0x8bb4 (log-and-continue) -> AN hangs -> watchdog -> card
   latch. 0x5014 -> 0x6005014: field6=bits[26:24]=6 -> key 6 valid; keys
   {0,1,4,5} preserved. Provenance (04s): 0x0D600C = HW reset default, NOT
   written by any iRISC code / data / INI / scatter (all disproven) => data
   patch impossible => boot code-injection.

   Design (trampoline, re-execute original + continue at site+4, caller-agnostic):
     site dc 0x7ef0 (main-init prologue 1st instr; stock 0x480300bc =
       csr.r r3,csr0xbc): -> jump 0x31cba0
     stub (cave dc 0x31cba0, all-zero, D2 precedent region; 7 words):
       set2 r5,zero,0x6005   r5 = 0x60050000
       set3 r5,r5,0x0014     r5 = 0x6005014   (VALUE)
       set2 r3,zero,0xd      r3 = 0x000d0000
       set3 r3,r3,0x600c     r3 = 0x0d600c    (ADDR)
       st.d r5,r3,0x0        [0x0d600c] = 0x6005014
       csr.r r3,csr0xbc      re-execute stock 0x7ef0 (r3 = link)
       jump 0x7ef4           continue at site+4
   Register safety (verified vs stock bytes): r5 unused in main-init
   0x7ef4..0x7f0c (first r5 use = ld.i r5,0x8e89 @0x7f0c); r3 restored by the
   re-executed csr.r (r3 = link) before jump 0x7ef4; link (csr 0xbc) untouched
   by jump (only `call` sets it; call 0x7ef0 @0x7ee4 already set link=0x7ee8).

   NOTE (correction to brief): the brief said the 1st instr of main-init is
   "ld.i r4,0x65d"; that instruction is actually at dc 0x7f00. dc 0x7ef0 =
   csr.r r3,csr0xbc (prologue). The SITE (0x7ef0) is correct.

Gates G0..G10 (recipe 04l/04o, adapted): base-md5 / pre-patch words + cave
zero + entry block / stub+site decode / clcrc round-trip + changed-line set /
diff vs base stray=NONE / verify deep / mstflint verify bootable / mstflint q
identity / 0x30 budget+addr+dc-head marker / final==step1 outside 0x30 /
determinism. D2 mechanics REUSED (clcrc/decrc/dc_to_raw/encoders), not
reimplemented.
"""
import argparse
import hashlib
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + '/scripts/irisc')
import mlxfwutil
import irisc_dis

THEIR_RI_MD5 = 'dacbcf0e1cbc1bed3d5e916520fe6803'
GCA_REF = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0

# 0x1f patch (C12-gate lift, mandatory)
X1F_DC = 0x1f1f00
X1F_RAW = 0x37e0f0
X1F_BEFORE = 0xfcb1c083
X1F_AFTER = 0x0011001f
X1F_DIS = 'addi r17,zero,0x1f'
X1F_CTX = [(0x1f1ee0, 'fc852008'), (0x1f1ee4, '00040001'), (0x1f1ef4, 'fe85a008'),
           (0x1f1f04, '6430000a'), (0x1f1f38, '0011001f'), (0x1f1f3c, '4a043ae4')]

# boot-injection (the fix)
SITE_DC = 0x7ef0
SITE_BEFORE = 0x480300bc
SITE_DIS = 'csr.r r3,csr0xbc'
JUMP_BACK_DC = 0x7ef4
STUB_DC = 0x31cba0
STUB_END_DC = 0x31cc00
STUB_WORDS_BUDGET = 24
TABLE_ADDR = 0x0d600c
TABLE_VALUE = 0x6005014

# entry block (stock boot path, must stay intact)
ENTRY_DC = 0x7edc
ENTRY_BLOCK = [0x94fff51b, 0x703f07fa, 0x94000003, 0x95000000, 0x95000000]

# device identity (guides skip: base ri already carries it)
EXPECT_GUID = '0x' + mlxfwutil.hw('CARD_CX4LX_XCAT', 'guid')
EXPECT_MAC = '0x' + mlxfwutil.hw('CARD_CX4LX_XCAT', 'mac')

BUILD_ID_DATE = '2026-10-12'
BUILD_ID = ('; mlxini cx4lx-fix-table (2026-10-12, dacbcf0e1cbc1bed3d5e916520fe6803): '
            '0x1f mask (dc 0x1f1f00) + boot-inj @0x7ef0 -> iRISC RAM 0x0D600C = '
            '0x6005014 (F1 key6/C12 valid; sfp28-ib-node root-fix)')
INI_ANCHOR = ';; Mellanox Technologies LTD'
INI_TRIM_DESC_LEN = 60

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


def dc_to_raw(dc):
    line, within = divmod(dc, 64)
    return SEC_ADDR + line*68 + within


def enc_set2(rd, imm):
    return (0x09 << 26) | (rd << 16) | (imm & 0xffff)


def enc_set3(rd, rs, imm):
    return (0x08 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def enc_csr_r(rd, csr):
    return (0x12 << 26) | (rd << 16) | (csr & 0x7ff)


def enc_st_d(rd, rs, off):
    # register-indirect 32-bit store, scale 2; only offset 0 is needed here
    assert off == 0, 'fix-table stub only stores at offset 0'
    return (0x1b << 26) | (rs << 21) | (rd << 11) | 2


def enc_jump(pc, tgt):
    return (0x25 << 26) | (1 << 24) | (((tgt - pc) // 4) & 0xffffff)


def parse_args():
    p = argparse.ArgumentParser(description='build the C12 fix-table image (0x1f + boot-injection)')
    p.add_argument('--base', default=REPO + '/build/c1-00-ri.bin')
    p.add_argument('--base-md5', default=THEIR_RI_MD5, help='"none" to skip')
    p.add_argument('--gca-ref', default=GCA_REF)
    p.add_argument('--build-id-text', default=BUILD_ID)
    p.add_argument('--out', default=REPO + '/build/cx4lx-fix-table.bin')
    args = p.parse_args()
    return args


args = parse_args()
lines_out = []
def say(msg=''):
    print(msg)
    lines_out.append(msg)


# [1] base md5
buf = open(args.base, 'rb').read()
md5_base = hashlib.md5(buf).hexdigest()
say('[1/G0] base=%s md5=%s size=%d' % (args.base.split('/')[-1], md5_base, len(buf)))
if args.base_md5 != 'none':
    if md5_base != args.base_md5:
        die('base md5 mismatch: %s != %s' % (md5_base, args.base_md5))
    say('    base md5 gate PASS')
else:
    say('    base-md5 gate SKIPPED (--base-md5 none)')

if '\n' in args.build_id_text or not args.build_id_text.startswith('; '):
    die('bad build-ID line: single "; "-comment required (R1)')

img = mlxfwutil.Image(buf, args.base)
e = img.find_entry('ITOC', 0x03)
say('[2] MAIN_CODE: type=0x%02x index=%d addr=0x%x size=0x%x clcrc=%d' % (
    e.type, e.index, e.addr, e.size, e.clcrc))
if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
    die('MAIN_CODE header mismatch (not the 14.32.1900 geometry)')
raw = img.section_data(e)
code = decrc(raw)
if len(raw) != (len(code)//64)*68:
    die('unexpected non-empty section tail')

# GCA byte-compare (informational)
try:
    gbuf = open(args.gca_ref, 'rb').read()
    gimg = mlxfwutil.Image(gbuf, args.gca_ref)
    ge = gimg.find_entry('ITOC', 0x03)
    gcode = decrc(gimg.section_data(ge))
    if gcode == code:
        say('    MAIN_CODE ACA<->GCA verdict: BYTE-IDENTICAL (%d B)' % len(code))
    else:
        dl = sorted({i // 64 for i in range(min(len(code), len(gcode))) if code[i] != gcode[i]})
        say('    MAIN_CODE ACA<->GCA verdict: DIFFERS (%d lines) - structural gates decide on THIS base' % len(dl))
except FileNotFoundError:
    say('    GCA ref not found - byte-compare skipped')

# [3/G1] pre-patch words + cave zero + entry block
SITE_RAW = dc_to_raw(SITE_DC)
if w32be(buf, SITE_RAW) != SITE_BEFORE:
    die('site dc 0x%x raw 0x%x = %08x != %08x (main-init 1st instr not stock)' % (
        SITE_DC, SITE_RAW, w32be(buf, SITE_RAW), SITE_BEFORE))
if w32be(buf, X1F_RAW) != X1F_BEFORE:
    die('0x1f word raw 0x%x = %08x != %08x' % (X1F_RAW, w32be(buf, X1F_RAW), X1F_BEFORE))
for off, want in X1F_CTX:
    if '%08x' % w32be(buf, dc_to_raw(off)) != want:
        die('0x1f context word dc 0x%x mismatch' % off)
if not all(w32be(code, STUB_DC + 4*i) == 0 for i in range(STUB_WORDS_BUDGET)):
    die('cave dc 0x%x..0x%x not all-zero' % (STUB_DC, STUB_END_DC))
for i, want in enumerate(ENTRY_BLOCK):
    if w32be(code, ENTRY_DC + i*4) != want:
        die('entry block word mismatch at +%d' % i)
epat = b''.join(struct.pack('>I', w) for w in ENTRY_BLOCK)
if code.count(epat) != 1:
    die('entry 5-word pattern not unique: %d hits' % code.count(epat))
say('[3/G1] pre-patch OK: site 0x%x=%08x (%s); 0x1f 0x%x=%08x + %d ctx; cave %d words zero; entry block intact+unique'
    % (SITE_DC, SITE_BEFORE, SITE_DIS, X1F_DC, X1F_BEFORE, len(X1F_CTX), STUB_WORDS_BUDGET))

# [4/G2a] build the stub (decode-verified per word)
stub_words = []
def emit(w, want_dis, label):
    dc = STUB_DC + 4*len(stub_words)
    d = irisc_dis.dis(w, dc)
    if d != want_dis:
        die('stub %s dc 0x%x %08x decodes "%s" != "%s"' % (label, dc, w, d, want_dis))
    stub_words.append((dc, w, d))

emit(enc_set2(5, (TABLE_VALUE >> 16) & 0xffff),
     'set2 r5,zero,0x%x' % ((TABLE_VALUE >> 16) & 0xffff), 'val-hi')
emit(enc_set3(5, 5, TABLE_VALUE & 0xffff),
     'set3 r5,r5,0x%x' % (TABLE_VALUE & 0xffff), 'val-lo')
emit(enc_set2(3, (TABLE_ADDR >> 16) & 0xffff),
     'set2 r3,zero,0x%x' % ((TABLE_ADDR >> 16) & 0xffff), 'addr-hi')
emit(enc_set3(3, 3, TABLE_ADDR & 0xffff),
     'set3 r3,r3,0x%x' % (TABLE_ADDR & 0xffff), 'addr-lo')
emit(enc_st_d(5, 3, 0), 'st.d r5,r3,0x0', 'store')
emit(SITE_BEFORE, SITE_DIS, 're-execute')
emit(enc_jump(STUB_DC + 4*len(stub_words), JUMP_BACK_DC), 'jump 0x%x' % JUMP_BACK_DC, 'jump-back')
if len(stub_words) > STUB_WORDS_BUDGET:
    die('stub %d words exceeds cave budget %d' % (len(stub_words), STUB_WORDS_BUDGET))
say('[4/G2a] stub %d/%d cave words (value 0x%08x in r5, addr 0x%06x in r3, store, re-execute, jump-back):'
    % (len(stub_words), STUB_WORDS_BUDGET, TABLE_VALUE, TABLE_ADDR))
for dc, w, d in stub_words:
    say('    dc 0x%x %08x = %s' % (dc, w, d))

# [5/G2b] site jump decode
SITE_AFTER = enc_jump(SITE_DC, STUB_DC)
sd = irisc_dis.dis(SITE_AFTER, SITE_DC)
if sd != 'jump 0x%x' % STUB_DC:
    die('site jump decode "%s" != "jump 0x%x"' % (sd, STUB_DC))
say('[5/G2b] site 0x%x: %08x -> %08x (%s); jump-back on instr boundary (0x%x)'
    % (SITE_DC, SITE_BEFORE, SITE_AFTER, sd, JUMP_BACK_DC))

# [6/G3] clcrc round-trip (unpatched) before patching
rt0 = clcrc(code)
if rt0 != raw:
    die('round-trip de-clcrc/re-clcrc failed (base)')
say('[6/G3] round-trip base: OK (%d lines)' % (len(code)//64))

# [7] patch code
pcode = bytearray(code)
struct.pack_into('>I', pcode, X1F_DC, X1F_AFTER)
struct.pack_into('>I', pcode, SITE_DC, SITE_AFTER)
for dc, w, _ in stub_words:
    struct.pack_into('>I', pcode, dc, w)
pcode = bytes(pcode)
praw = clcrc(pcode)
patched_dcs = [X1F_DC, SITE_DC] + [dc for dc, _, _ in stub_words]
changed_lines = sorted({dc // 64 for dc in patched_dcs})
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != changed_lines:
    die('changed-line set drifted: %s != %s' % (diff_lines, changed_lines))
say('[7/G3] clcrc re-framed; changed lines %s only (diff set == expected)' % changed_lines)

step1 = mlxfwutil.patch_sections(img, [(0x03, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
say('[8/G5] step1 (base+0x1f+site+stub): changed lines %s only; verify(deep)=%s'
    % (changed_lines, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
if w32be(step1, X1F_RAW) != X1F_AFTER:
    die('step1 0x1f word lost')
if w32be(step1, SITE_RAW) != SITE_AFTER:
    die('step1 site word lost')
for dc, w, _ in stub_words:
    if w32be(step1, dc_to_raw(dc)) != w:
        die('step1 stub word @dc 0x%x lost' % dc)
STEP1 = args.out + '.step1'
open(STEP1, 'wb').write(step1)

# [9] guides skip: base ri carries DEV_INFO+MFG_INFO with expected identity
found = {}
for name, stype in (('DEV_INFO', 0xE1), ('MFG_INFO', 0xE0)):
    ent = img.find_entry('ITOC', stype)
    sd = img.section_data(ent)
    g = int.from_bytes(sd[0x28:0x30], 'big')
    m = int.from_bytes(sd[0x38:0x40], 'big')
    found[name] = (ent, g, m)
eg, em = int(EXPECT_GUID, 0), int(EXPECT_MAC, 0)
for name, (ent, g, m) in found.items():
    if g != eg or m != em:
        die('device-sections gate: %s guid=0x%x mac=0x%x != expected' % (name, g, m))
    say('    %s @0x%x: guid=0x%x mac=0x%x == expected' % (name, ent.addr, g, m))
open(args.out, 'wb').write(step1)
say('[9/G7] guides SKIPPED: base ri carries DEV_INFO+MFG_INFO with expected identity; final-code = step1')

# [10] 0x30 build-ID (R1/R2)
fc = open(args.out, 'rb').read()
img_fc = mlxfwutil.Image(fc, 'final-code', base=img.base, fmt=img.fmt)
e30 = img_fc.find_entry('ITOC', 0x30)
raw30 = img_fc.section_data(e30)
if raw30[:2] != b'\x78\xda':
    die('0x30 section is not zlib (starts 0x%02x%02x)' % (raw30[0], raw30[1]))
ini_lines = zlib.decompress(raw30).decode('latin1').split('\n')
if ini_lines.count(INI_ANCHOR) != 1:
    die('ini anchor %r not found exactly once' % INI_ANCHOR)

def zw_pad(text):
    d = zlib.compress(text.encode('latin1'), 9)
    return len(d) + (4 - len(d) % 4) % 4

def with_marker(ls):
    a = ls.index(INI_ANCHOR)
    return ls[:a + 1] + [args.build_id_text] + ls[a + 1:]

budget30 = e30.size - 32
kv_lines = [l for l in ini_lines if not l.startswith(';;')]
new_lines = with_marker(ini_lines)
n_untrimmed = zw_pad('\n'.join(new_lines))
trimmed_idx = []
if n_untrimmed > budget30:
    psi = ini_lines.index(';;[PS_INFO]') if ';;[PS_INFO]' in ini_lines else None
    psi_end = psi
    if psi is not None:
        while psi_end < len(ini_lines) and ini_lines[psi_end].startswith(';;'):
            psi_end += 1
    dropped = set()
    for i, l in enumerate(ini_lines):
        if l.startswith(';; Generated automatically by iniprep tool'):
            dropped.add(i)
        elif psi is not None and psi <= i < psi_end:
            dropped.add(i)
        elif l.startswith(';;') and len(l) > INI_TRIM_DESC_LEN:
            dropped.add(i)
    trimmed_idx = sorted(dropped)
    new_lines = with_marker([l for i, l in enumerate(ini_lines) if i not in dropped])
    for i in trimmed_idx:
        if not ini_lines[i].startswith(';;'):
            die('trim touched non-comment line %d (key=value forbidden)' % i)
    kept_kv = [l for i, l in enumerate(ini_lines) if i not in dropped and not l.startswith(';;')]
    if kept_kv != kv_lines:
        die('trim filter-check: key=value line sequence changed')
    nav_kept = [l for i, l in enumerate(ini_lines) if i not in dropped and l.startswith(';;;;')]
    nav_all = [l for l in ini_lines if l.startswith(';;;;') and len(l) <= INI_TRIM_DESC_LEN]
    if nav_kept != nav_all:
        die('trim dropped navigational ;;;; comments')
ini_final = '\n'.join(new_lines)
n_final = zw_pad(ini_final)
say('[10/G8] ini build-ID (R1/R2): "%s"' % args.build_id_text)
say('    0x30 e.size=%d budget=%d; zlib9+DWpad: no-trim=%d -> final=%d (slack %d)%s'
    % (e30.size, budget30, n_untrimmed, n_final, budget30 - n_final,
       '' if trimmed_idx else ', no trim needed'))
if trimmed_idx:
    say('    trim: %d ;;-comment lines dropped: %s' % (
        len(trimmed_idx), ['%d (%d B)' % (i, len(ini_lines[i])) for i in trimmed_idx]))
if n_final > budget30:
    die('0x30 budget exceeded even after trim (%d > %d): STOP, no --repack-force (R2)' % (n_final, budget30))
try:
    out_buf = mlxfwutil.inject_ini(img_fc, ini_final)
except ValueError as ex:
    die('inject_ini: %s (STOP per R2, no --repack-force)' % ex)
open(args.out, 'wb').write(out_buf)
img_fin = mlxfwutil.Image(out_buf, args.out, base=img.base, fmt=img.fmt)
rt = mlxfwutil.extract_section(img_fin, 0x30)
rt_ini = zlib.decompress(rt) if rt[:2] == b'\x78\xda' else rt
if rt_ini != ini_final.encode('latin1'):
    die('round-trip failed: extract != ini-final (cmp)')
e30n = img_fin.find_entry('ITOC', 0x30)
if e30n.addr != e30.addr:
    die('0x30 relocated: 0x%x -> 0x%x' % (e30.addr, e30n.addr))
if e30n.size > e30.size:
    die('0x30 grew: 0x%x -> 0x%x' % (e30.size, e30n.size))
errs = mlxfwutil.verify_image(img_fin, deep=True)
if errs:
    die('final verify(deep) after inject: %s' % errs)
open(args.out.replace('.bin', '-ini-final.ini'), 'w', encoding='latin1').write(ini_final)
say('    round-trip extract == ini-final; 0x30 in place @0x%x size 0x%x -> 0x%x; verify(deep)=PASS'
    % (e30n.addr, e30.size, e30n.size))

# [11/G2c] final identity words
out = open(args.out, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
if w32be(out, X1F_RAW) != X1F_AFTER or w32be(out, SITE_RAW) != SITE_AFTER:
    die('final identity words lost (0x1f/site)')
for dc, w, _ in stub_words:
    if w32be(out, dc_to_raw(dc)) != w:
        die('final stub word @dc 0x%x lost' % dc)
say('[11/G2c] final words OK (0x1f=%08x, site=%08x, %d stub words); md5=%s size=%d'
    % (X1F_AFTER, SITE_AFTER, len(stub_words), md5_out, len(out)))

# [12/G4] diff vs base: only the intended zones changed
ent_off = img.itoc_off + 32 + e.index*32
allowed = set()
for dc in patched_dcs:
    allowed |= set(range(dc_to_raw(dc), dc_to_raw(dc) + 4))
for ln in changed_lines:
    allowed |= {SEC_ADDR + ln*68 + 66, SEC_ADDR + ln*68 + 67}
allowed |= set(range(ent_off + 0x1a, ent_off + 0x20))
allowed |= set(range(img_fc.sec_abs(e30), img_fc.sec_abs(e30) + max(e30.size, e30n.size)))
ent_off30 = img_fc.itoc_off + 32 + e30.index*32
allowed |= set(range(ent_off30, ent_off30 + 32))

def diff_check(label, new, old, allow):
    diffs = [i for i in range(min(len(new), len(old))) if new[i] != old[i]]
    stray = [hex(i) for i in diffs if i not in allow]
    say('[12/G4] %s: %d diff bytes, stray=%s' % (label, len(diffs), stray if stray else 'NONE'))
    if stray:
        die('stray diff bytes in %s: %s' % (label, stray[:16]))
    return diffs

if len(out) != len(buf):
    die('image size changed: %d != %d' % (len(out), len(buf)))
diff_check('final vs base (0x1f+site+stub+0x30)', out, buf, allowed)

# [13/G9] final == step1 outside 0x30 intent zones
e30s = mlxfwutil.Image(step1, 'step1').find_entry('ITOC', 0x30)
a3 = img_fin.sec_abs(e30n)
g9_allowed = set(range(a3, a3 + max(e30s.size, e30n.size)))
g9_allowed |= set(range(ent_off30, ent_off30 + 32))
g9_diffs = [i for i in range(len(step1)) if step1[i] != out[i]]
g9_stray = [hex(i) for i in g9_diffs if i not in g9_allowed]
say('[13/G9] final == step1 outside 0x30 intent zones: %d bytes differ, stray=%s'
    % (len(g9_diffs), g9_stray if g9_stray else 'NONE'))
if g9_stray:
    die('[G9] stray: %s' % g9_stray[:16])

# [14/G6] mstflint verify bootable
r = subprocess.run(['mstflint', '-i', args.out, 'verify'], capture_output=True, text=True)
say('[14/G6] mstflint verify: rc=%d' % r.returncode)
say('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
if r.returncode != 0:
    die('mstflint verify failed')

# [15/G7] mstflint q identity
r = subprocess.run(['mstflint', '-i', args.out, 'q'], capture_output=True, text=True)
say('[15/G7] mstflint q:')
ok15 = {}
for l in (r.stdout + r.stderr).splitlines():
    if any(k in l for k in ('Image type', 'FW Version', 'Base GUID', 'Base MAC')):
        say('    ' + l.strip())
    for k, v in (('Image type', 'FS3'), ('FW Version', '14.32.1900'),
                 ('Base GUID', EXPECT_GUID[2:]), ('Base MAC', EXPECT_MAC[2:])):
        if l.startswith(k):
            ok15[k] = v in l
for k, v in ok15.items():
    if not v:
        die('identity check failed: %s' % k)
if not all(k in ok15 for k in ('Image type', 'FW Version', 'Base GUID', 'Base MAC')):
    die('identity lines missing in q output')

# [16/G8] mstflint dc: build-ID is the first content line
r = subprocess.run(['mstflint', '-i', args.out, 'dc'], capture_output=True, text=True)
dl = [l.rstrip() for l in (r.stdout + r.stderr).splitlines()]
NOISE = ('-E-', '-W-', '-I-', '-')
try:
    mi = next(i for i, l in enumerate(dl) if args.build_id_text in l)
except StopIteration:
    mi = -1
if mi < 0:
    die('mstflint dc does not show the build-ID marker')
pre = [l for l in dl[:mi] if l.strip() and not l.startswith(NOISE)]
if any(not l.startswith(';;') for l in pre) or len(pre) > 1:
    die('build-ID is not the first content line of dc (pre-content: %r)' % pre)
say('[16/G8] mstflint dc: build-ID is the first content line (line %d of dc):' % (mi + 1))
say('    ' + dl[mi])

LOG = args.out.replace('.bin', '-build.log')
open(LOG, 'w').write('\n'.join(lines_out) + '\n')
say('DONE %s md5=%s size=%d log=%s' % (args.out, md5_out, len(out), LOG))
