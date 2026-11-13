#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task-04v-b step 3: build the 4030 (CX-5, 16.35.4030)
runtime-dump image.

base = build/4030graft-c12min.bin (md5 51f3f7276b14a82082eb1e17539fd996):
server identity, SOX C12min fix intact (dc 0x25a3ec = 0011001f), burn target.

Hook = dc 0x2224d4 in the ib_speed_nego_fsm cnf_test state handler
(function 0x2222cc, AN path, BEFORE the 0x2544xx cluster, OUTSIDE the
C12min zone): stock gated emit5 `call 0x1b5e0' (class 0x40, level 1,
string rt 0x00b5b0b7 'ib_speed_nego_fsm: ... cnf_test. agreed_ts3 ...')
replaced with `call 0x397ce0' (cave stub). Autonomous trigger: the AN-FSM
cnf_test state on every AN (re)negotiation while the C12min gate is lifted
(the base already carries the lift) - the 4030 analog of c1-D2 H6
(init_ib_an_fsm, class 0x40 L1).

Stub (19/24 cave words, additive-read, c1-D2 mechanics):
    csr.r r17,csr0xbc      link (hook+4) -> r17 (callee-saved; 0 tail mentions)
    call 0x1b5e0           stock event FIRST (site args in place; gated:
                           fires only when the host arms the class mask)
    addi/addi.hi r4,rt     dead db0 string rt 0x00b5dbf3
                           ('icmd_push_db (skip_qpc_check = 0x%x): gvmi = 0x%x,
                            qpn = 0x%x, qpi = 0x%x, req_res_ = 0x%x,
                            schedq_number = 0x%x, mode = 0x%x' - 7 x 0x%x)
    ld.i r5,0x2            self-check param = local w2 (trace mask)
    set2/set3 r3,0x0D6008  table base (flag0 word)
    ld.d r6..r10,r3,0..0x10 table words 0x0D6008/0C/10/14/18 (offset-batched)
    set2/set3 r3,0x0D5DC + ld.d r11,r3,0x0   gate word 0x0D5DC (second base:
                           0x28AC below table base, beyond ld.d +-0x1FF8)
    call 0x1b8c4           emit7: r4=string, r5..r11 -> one UNGATED trace
                           event (core 0x1b430 writes ring via csr0x8/csr0xc)
    ld.d r8,r23,0x4        restore r8: the tail (ret.r zero,r8,r3 @0x2224ec)
                           returns r8; stock set it at 0x2224b4 from [r23+4];
                           r23 is callee-saved and survives both stub calls
    csr.w r17,zero,0xbc    restore link CSR
    ret.d

Diff vs base = ONLY: hook word + 17 stub words + clcrc line tails +
ITOC 0x03 entry (sec_crc bits 208..223 / entry_crc bits 240..255) +
FS4 hashes-table SHA512(0x03) + its data CRC + 0x30 section (zlib
recompressed IN PLACE, address fixed, size unchanged-or-smaller,
vendor ;;-comments trimmed for budget) + ITOC 0x30 entry (build-ID
comment, R1/R2).

Gates: [1] base md5 / [2] MAIN_CODE geometry + de-frame / [3] expected_before
(hook + 9 site ctx + C12min word + 24 cave zeros + entry word + emit5/emit7/
core prologue words) / [4] GATE ld.i witnesses (g-fn 0x3577 + wrapper w2/w3
readers) / [5] r17: 0 mentions in tail (site..ret) / [6] param regs r5..r11:
r5,r6,r7,r9,r10,r11 write-first in tail; r8 special - stock origin
ld.d r8,r23,0x4 @0x2224b4, read-only in tail, stub reloads it / [7] stub
per-word decode + budget / [8] dead string on THIS base (0 loaders, 0 raw) /
[9] round-trip clcrc / [10] hook patch decode + changed lines / [11] step1
patch + verify(deep) + word readback / [11b] 0x30 build-ID (R1/R2: anchor,
zlib9+DWpad budget vs e.size-32, ;;-comment trim, inject, round-trip,
no relocation/growth, verify(deep)) / [12] device identity from base
(DEV_INFO/MFG_INFO guid/mac) / [13] diff FINAL vs base: allowed zones only,
stray=NONE / [14] mstflint verify / [15] mstflint q identity == base q /
[16] final words + md5."""
import hashlib
import re
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

BASE = REPO + '/build/4030graft-c12min.bin'
BASE_MD5 = '51f3f7276b14a82082eb1e17539fd996'
OUT = REPO + '/build/4030-dump-an.bin'

BUILD_ID = ('; mlxini cx4lx-sfp28-ib-node 4030-dump-an (2026-10-13, '
            '51f3f7276b14a82082eb1e17539fd996): C12min + emit7 AN-time dump '
            'hook @ cnf_test 0x2224d4 (table+gate, class 0x40)')
INI_ANCHOR = ';; Mellanox Technologies LTD'
INI_TRIM_DESC_LEN = 60

SEC_TYPE = 0x03
SEC_RAW = 0x1c748
SEC_SIZE = 0x3d15a0
DE_SIZE = 0x397dc0

HOOK_DC = 0x2224d4
HOOK_BEFORE = 0x94f7e443
STOCK_EMIT = 0x1b5e0
STOCK_EMIT_N = 5
FN_START_DC = 0x2222cc
SITE_CTX = [
    (0x2224b0, '66c9002e'),
    (0x2224b4, '66e80006'),
    (0x2224b8, '66e70002'),
    (0x2224bc, '0006b0b7'),
    (0x2224c0, '08c600b6'),
    (0x2224c4, 'c8aa01c2'),
    (0x2224c8, 'c88b01c2'),
    (0x2224cc, '00040040'),
    (0x2224d0, '00050001'),
]
C12MIN = (0x25a3ec, 0x0011001f)
ENTRY_DC = 0x1d58c
ENTRY_WORD = 0x94fff3d6
EMIT5_PROLOG = {0x1b5e0: '480300bc', 0x1b5ec: '6c20901e', 0x1b600: '6c20b80a'}
EMIT7_PROLOG = {0x1b8c4: '480300bc', 0x1b8cc: '703f0fda',
                0x1b8f0: '00050007', 0x1b8f4: '94fffecf', 0x1b900: 'fd001825'}
CORE_PROLOG = {0x1b430: '48070008'}
WITNESSES = [(0x21de88, 'ld.i r4,0x3577'),
             (0x1b628, 'ld.i r6,0x2'),
             (0x1b638, 'ld.i r4,0x3')]

CAVE_DC = 0x397ce0
CAVE_WORDS = 24
EMIT7 = 0x1b8c4
STRING_RT = 0x00b5dbf3
TBL_BASE = 0x0D6008
TBL_OFFS = (0x0, 0x4, 0x8, 0xc, 0x10)
GATE_BASE = 0x0D5DC

# HW CRC-16: reflect-таблица poly 0xD008 (эквивалент crc16table2 из
# mstflint mft_utils/calc_hw_crc.c); генерируется
HW_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xD008 if _c & 1 else _c >> 1
    HW_CRC_TABLE.append(_c)

LINK_REG = 17
RET_D = 0xFC00002D
lines_out = []


def say(msg=''):
    print(msg)
    lines_out.append(msg)


def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)


def w32be(b, o):
    return struct.unpack_from('>I', b, o)[0]


def dc_to_raw(dc):
    line, within = divmod(dc, 64)
    return SEC_RAW + line*68 + within


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def enc_call(pc, tgt):
    return (0x25 << 26) | (((tgt - pc) // 4) & 0xffffff)


def enc_addi(rd, rs, imm):
    return (0x00 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def enc_addi_hi(rd, rs, imm):
    return (0x02 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def enc_set2(rd, imm):
    return (0x09 << 26) | (rd << 16) | (imm & 0xffff)


def enc_set3(rd, rs, imm):
    return (0x08 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def enc_ld_i(rd, idx):
    return (0x12 << 26) | (1 << 25) | (rd << 16) | (idx & 0xffff)


def enc_ld_d(rd, rs, off):
    assert off % 4 == 0 and -0x1FF8 <= off <= 0x1FF8
    return (0x19 << 26) | (rs << 21) | (rd << 16) | (((off >> 2) & 0x3fff) << 2) | (1 << 1)


def enc_csr_r(rd, csr):
    return (0x12 << 26) | (rd << 16) | (csr & 0x7ff)


def enc_csr_w(rs, rt, csr):
    return (0x13 << 26) | (rs << 21) | (rt << 11) | (csr & 0x7ff)


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


buf = open(BASE, 'rb').read()
md5_base = hashlib.md5(buf).hexdigest()
say('[1] base=%s md5=%s size=%d' % (BASE.split('/')[-1], md5_base, len(buf)))
if md5_base != BASE_MD5:
    die('base md5 mismatch: %s != %s' % (md5_base, BASE_MD5))

img = mlxfwutil.Image(buf, BASE)
e = img.find_entry('ITOC', SEC_TYPE)
say('[2] MAIN_CODE: type=0x%02x index=%d addr=0x%x size=0x%x clcrc=%d' % (
    e.type, e.index, e.addr, e.size, e.clcrc))
if (e.addr, e.size, e.clcrc) != (SEC_RAW, SEC_SIZE, 1):
    die('MAIN_CODE header mismatch (not the 4030 FS4 geometry)')
raw = img.section_data(e)
code = decrc(raw)
if len(code) != DE_SIZE:
    die('de-framed MAIN_CODE size 0x%x != 0x%x' % (len(code), DE_SIZE))


def dc_word(dco):
    ln, w = divmod(dco, 64)
    return w32be(buf, SEC_RAW + ln*68 + w)


if w32be(buf, dc_to_raw(HOOK_DC)) != HOOK_BEFORE:
    die('hook site word raw 0x%x = %08x != %08x' % (
        dc_to_raw(HOOK_DC), w32be(buf, dc_to_raw(HOOK_DC)), HOOK_BEFORE))
for off, want in SITE_CTX:
    if '%08x' % dc_word(off) != want:
        die('hook site context word dc 0x%x = %08x != %s' % (off, dc_word(off), want))
c12_dc, c12_w = C12MIN
if dc_word(c12_dc) != c12_w:
    die('C12min word dc 0x%x = %08x != %08x (base must carry the SOX fix)' % (
        c12_dc, dc_word(c12_dc), c12_w))
if not all(dc_word(CAVE_DC + 4*i) == 0 for i in range(CAVE_WORDS)):
    die('cave dc 0x%x..0x%x not all-zero' % (CAVE_DC, CAVE_DC + 4*CAVE_WORDS))
if dc_word(ENTRY_DC) != ENTRY_WORD:
    die('entry word dc 0x%x = %08x != %08x' % (ENTRY_DC, dc_word(ENTRY_DC), ENTRY_WORD))
for off, want in {**EMIT5_PROLOG, **EMIT7_PROLOG, **CORE_PROLOG}.items():
    if '%08x' % dc_word(off) != want:
        die('emit prologue word dc 0x%x = %08x != %s (emit family not as RE-d)' % (
            off, dc_word(off), want))
say('[3] expected_before OK: hook %08x + %d ctx; C12min %08x; cave %d words zero; '
    'entry %08x; emit5/emit7/core prologues' % (
        HOOK_BEFORE, len(SITE_CTX), c12_w, CAVE_WORDS, ENTRY_WORD))

for dc, want in WITNESSES:
    d = irisc_dis.dis(dc_word(dc), dc)
    if d != want:
        die('GATE witness dc 0x%x = "%s" != "%s"' % (dc, d, want))
say('[4] GATE ld.i witnesses OK: g-fn gate 0x3577 (0x0D5DC), wrapper w2/w3 readers')

fn_end = None
for dc in range(HOOK_DC + 4, HOOK_DC + 0x400, 4):
    d = irisc_dis.dis(dc_word(dc), dc)
    if d.startswith('ret'):
        fn_end = dc
        break
if fn_end is None:
    die('function end not found after hook site')
for dc in range(HOOK_DC + 4, fn_end + 4, 4):
    d = irisc_dis.dis(dc_word(dc), dc)
    if re.search(r'\br%d\b' % LINK_REG, d):
        die('link reg r%d read at dc 0x%x ("%s") inside hooked function tail' % (
            LINK_REG, dc, d))
say('[5] link reg r%d: 0 mentions in tail (site..ret 0x%x) - safe' % (LINK_REG, fn_end))

RW = re.compile(r'\b(r\d+)\b')
WR_OPS = ('addi', 'addi.hi', 'set2', 'set3', 'or', 'subs', 'subsi', 'ands', 'and',
          'shr', 'shl', 'mask32', 'alu', 'add', 'xor')
init = set()
r8_reads = 0
for dc in range(HOOK_DC + 4, fn_end + 4, 4):
    d = irisc_dis.dis(dc_word(dc), dc)
    tok = d.split()[0]
    rs = [int(x[1:]) for x in RW.findall(d)]
    if tok.startswith('call'):
        init |= set(range(5, 12))
        continue
    for r in (5, 6, 7, 9, 10, 11):
        if r in rs:
            writes_it = rs and rs[0] == r and (
                tok in WR_OPS or tok.startswith('ld.') or tok.startswith('lw.'))
            if not writes_it and r not in init:
                die('param reg r%d read-before-write at dc 0x%x ("%s") after site' % (r, dc, d))
            init.add(r)
    if 8 in rs:
        writes_it = rs and rs[0] == 8 and (
            tok in WR_OPS or tok.startswith('ld.') or tok.startswith('lw.'))
        if writes_it:
            die('r8 written at dc 0x%x ("%s") in tail (expected read-only use)' % (dc, d))
        r8_reads += 1
d8 = irisc_dis.dis(dc_word(0x2224b4), 0x2224b4)
if d8 != 'ld.d r8,r23,0x4':
    die('r8 stock origin dc 0x2224b4 = "%s" != "ld.d r8,r23,0x4"' % d8)
if r8_reads != 1:
    die('r8 reads in tail = %d (expected exactly 1, the ret.r)' % r8_reads)
say('[6] param regs r5,r6,r7,r9,r10,r11 write-first in tail; r8: stock origin '
    'ld.d r8,r23,0x4 @0x2224b4, 1 read in tail (ret.r), stub reloads from r23 '
    '(callee-saved, survives stock emit5 + emit7 + core 0x1b430)')

stub = []
stub.append((enc_csr_r(LINK_REG, 0xbc), 'csr.r r%d,csr0xbc' % LINK_REG))
stub.append((enc_call(CAVE_DC + 4, STOCK_EMIT), 'call 0x%x' % STOCK_EMIT))
lo = STRING_RT & 0xffff
hi = (STRING_RT >> 16) & 0xffff
carry = 1 if lo & 0x8000 else 0
if hi + carry > 0xffff:
    die('string rt 0x%x not encodable as addi+addi.hi pair' % STRING_RT)
stub.append((enc_addi(4, 0, lo), 'addi r4,zero,0x%x' % s16(lo)))
stub.append((enc_addi_hi(4, 4, hi + carry), 'addi.hi r4,r4,0x%x' % (hi + carry)))
stub.append((enc_ld_i(5, 2), 'ld.i r5,0x2'))
stub.append((enc_set2(3, (TBL_BASE >> 16) & 0xffff), 'set2 r3,zero,0x%x' % ((TBL_BASE >> 16) & 0xffff)))
stub.append((enc_set3(3, 3, TBL_BASE & 0xffff), 'set3 r3,r3,0x%x' % (TBL_BASE & 0xffff)))
for i, off in enumerate(TBL_OFFS):
    rd = 6 + i
    stub.append((enc_ld_d(rd, 3, off), 'ld.d r%d,r3,0x%x' % (rd, off)))
stub.append((enc_set2(3, (GATE_BASE >> 16) & 0xffff), 'set2 r3,zero,0x%x' % ((GATE_BASE >> 16) & 0xffff)))
stub.append((enc_set3(3, 3, GATE_BASE & 0xffff), 'set3 r3,r3,0x%x' % (GATE_BASE & 0xffff)))
stub.append((enc_ld_d(11, 3, 0), 'ld.d r11,r3,0x0'))
stub.append((enc_call(CAVE_DC + 4*15, EMIT7), 'call 0x%x' % EMIT7))
stub.append((enc_ld_d(8, 23, 4), 'ld.d r8,r23,0x4'))
stub.append((enc_csr_w(LINK_REG, 0, 0xbc), 'csr.w r%d,zero,0xbc' % LINK_REG))
stub.append((RET_D, 'ret.d zero,zero,zero'))

stub_dc_words = []
for i, (w, want_dis) in enumerate(stub):
    dc = CAVE_DC + 4*i
    d = irisc_dis.dis(w, dc)
    if d != want_dis:
        die('stub word dc 0x%x %08x decodes "%s" != "%s"' % (dc, w, d, want_dis))
    stub_dc_words.append((dc, w, d))
if len(stub_dc_words) > CAVE_WORDS:
    die('stub %d words exceeds cave budget %d' % (len(stub_dc_words), CAVE_WORDS))
say('[7] stub %d/%d cave words (stock emit%d first, then emit7, 7 params, '
    'r8 reload, link r%d):' % (len(stub_dc_words), CAVE_WORDS, STOCK_EMIT_N, LINK_REG))
for dc, w, d in stub_dc_words:
    say('    dc 0x%x %08x = %s' % (dc, w, d))

prev = None
loaders = 0
n_words = len(code) // 4
for i in range(n_words - 1):
    w = struct.unpack_from('>I', code, i*4)[0]
    op = w >> 26
    if op in (0x00, 0x01):
        prev = (i, (w >> 16) & 0x1f, s16(w & 0xffff))
    elif op in (0x02, 0x03) and prev is not None:
        poff, prd, pimm = prev
        if poff + 1 == i and prd == (w >> 16) & 0x1f:
            composed = (pimm + ((w & 0xffff) << 16)) & 0xffffffff
            if composed == STRING_RT:
                loaders += 1
        prev = None
    else:
        prev = None
if loaders:
    die('string rt 0x%x has %d stock loaders - not dead' % (STRING_RT, loaders))
if struct.pack('>I', STRING_RT) in code:
    die('string rt 0x%x appears as raw data word - not dead' % STRING_RT)
str_end = code.find(b'\0', STRING_RT - 0x800000)
say('[8] string rt 0x%08x dead on THIS base (0 loaders, 0 raw words): %r' % (
    STRING_RT, code[STRING_RT - 0x800000:str_end][:80]))

rt = clcrc(code)
if len(raw) < len(rt) or raw[:len(rt)] != rt:
    die('round-trip de-clcrc/re-clcrc failed')
tail = len(raw) - len(rt)
if tail >= 68 or tail % 4:
    die('section tail %d bytes: not a <68B packer remainder' % tail)
say('[9] round-trip: OK (%d lines)%s' % (
    len(code)//64, ' + %d tail bytes preserved as-is' % tail if tail else ''))

HOOK_AFTER = enc_call(HOOK_DC, CAVE_DC)
d = irisc_dis.dis(HOOK_AFTER, HOOK_DC)
if d != 'call 0x%x' % CAVE_DC:
    die('hook patch decode "%s"' % d)
patched_dcs = [HOOK_DC] + [dc for dc, _, _ in stub_dc_words]
changed_lines = sorted({dc // 64 for dc in patched_dcs})
say('[10] hook %08x -> %08x ("%s"); changed lines %s' % (
    HOOK_BEFORE, HOOK_AFTER, d, changed_lines))

pcode = bytearray(code)
struct.pack_into('>I', pcode, HOOK_DC, HOOK_AFTER)
for dc, w, _ in stub_dc_words:
    struct.pack_into('>I', pcode, dc, w)
pcode = bytes(pcode)
praw = clcrc(pcode)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != changed_lines:
    die('changed-line set drifted: %s != %s' % (diff_lines, changed_lines))
step1 = mlxfwutil.patch_sections(img, [(SEC_TYPE, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
say('[11] step1 (base+hook+stub): changed lines %s only; verify(deep)=%s' % (
    changed_lines, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed: %s' % errs)
if w32be(step1, dc_to_raw(HOOK_DC)) != HOOK_AFTER:
    die('step1 hook word lost')
for dc, w, _ in stub_dc_words:
    if w32be(step1, dc_to_raw(dc)) != w:
        die('step1 stub word @dc 0x%x lost' % dc)
if w32be(step1, dc_to_raw(c12_dc)) != c12_w:
    die('step1 C12min word lost (SOX fix must stay intact)')
open(OUT, 'wb').write(step1)

# [11b] 0x30 build-ID (R1/R2)
fc = open(OUT, 'rb').read()
img_fc = mlxfwutil.Image(fc, OUT, base=img.base, fmt=img.fmt)
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
    return ls[:a + 1] + [BUILD_ID] + ls[a + 1:]


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
say('[11b/G8] ini build-ID (R1/R2): "%s"' % BUILD_ID)
say('    0x30 e.size=%d budget=%d; zlib9+DWpad: no-trim=%d -> final=%d (slack %d)%s'
    % (e30.size, budget30, n_untrimmed, n_final, budget30 - n_final,
       '' if trimmed_idx else ', no trim needed'))
if trimmed_idx:
    say('    trim: %d ;;-comment lines dropped: %s' % (
        len(trimmed_idx), ['%d (%d B)' % (i, len(ini_lines[i])) for i in trimmed_idx]))
if n_final > budget30:
    die('0x30 budget exceeded even after trim (%d > %d): STOP (R2, no relocation)'
        % (n_final, budget30))
try:
    out_buf = mlxfwutil.inject_ini(img_fc, ini_final)
except ValueError as ex:
    die('inject_ini: %s (STOP per R2, no --repack-force)' % ex)
open(OUT, 'wb').write(out_buf)
img_fin = mlxfwutil.Image(out_buf, OUT, base=img.base, fmt=img.fmt)
rt30 = mlxfwutil.extract_section(img_fin, 0x30)
rt_ini = zlib.decompress(rt30) if rt30[:2] == b'\x78\xda' else rt30
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
open(OUT.replace('.bin', '-ini-final.ini'), 'w', encoding='latin1').write(ini_final)
say('    round-trip extract == ini-final; 0x30 in place @0x%x size 0x%x -> 0x%x; verify(deep)=PASS'
    % (e30n.addr, e30.size, e30n.size))

ndev = 0
for name, stype in (('DEV_INFO', 0xE1), ('MFG_INFO', 0xE0)):
    try:
        ents = [x for x in img.entries('DTOC') if x.type == stype]
    except KeyError:
        ents = []
    for ent in ents:
        sd = img.section_data(ent)
        a = img.sec_abs(ent)
        if step1[a:a + ent.size] != buf[a:a + ent.size]:
            die('device section %s @0x%x altered by the patch' % (name, ent.addr))
        ndev += 1
        say('    %s idx=%d @0x%x size=0x%x: guid=0x%016x mac=0x%016x (== base, preserved)' % (
            name, ent.index, ent.addr, ent.size,
            int.from_bytes(sd[0x28:0x30], 'big'), int.from_bytes(sd[0x38:0x40], 'big')))
if ndev < 2:
    die('device sections: expected DEV_INFO+MFG_INFO in DTOC (found %d)' % ndev)
say('[12] device identity (server) preserved: DEV_INFO+MFG_INFO byte-identical to base')

out_final = open(OUT, 'rb').read()
ht = mlxfwutil.HashesTable.from_image(img)
ent_off = img.itoc_off + 32 + e.index*32
ent30_off = img.itoc_off + 32 + e30.index*32
allowed = set()
for dc in patched_dcs:
    allowed |= set(range(dc_to_raw(dc), dc_to_raw(dc) + 4))
for ln in changed_lines:
    allowed |= {SEC_RAW + ln*68 + 66, SEC_RAW + ln*68 + 67}
allowed |= set(range(ent_off, ent_off + 32))
allowed |= set(range(e30.addr, e30.addr + e30.size))
allowed |= set(range(ent30_off, ent30_off + 32))
ht_note = 'hashes-table zone: NONE (table absent)'
if ht is not None:
    hit = ht.entry_by_type(SEC_TYPE)
    if hit is None:
        die('hashes table: no entry for 0x03 (patch machinery inconsistent)')
    hi_i, hi_off = hit
    ht_abs = ht.ptr
    allowed |= set(range(ht_abs + 12 + hi_off, ht_abs + 12 + hi_off + ht.hash_size))
    allowed |= set(range(ht_abs + len(ht.data) - 4, ht_abs + len(ht.data)))
    ht_note = 'hashes-table SHA512(0x03)@0x%x + data CRC (table @0x%x)' % (
        ht_abs + 12 + hi_off, ht_abs)
diffs = [i for i in range(len(out_final)) if out_final[i] != buf[i]]
stray = [hex(i) for i in diffs if i not in allowed]
say('[13] final vs base: %d diff bytes, allowed zones: hook+stub words, %d clcrc '
    'tails, ITOC 0x03 entry @0x%x, 0x30 section @0x%x(+0x%x) + ITOC 0x30 entry '
    '@0x%x, %s; stray=%s' % (
        len(diffs), len(changed_lines), ent_off, e30.addr, e30.size, ent30_off,
        ht_note, stray if stray else 'NONE'))
if stray:
    die('stray diff bytes: %s' % stray)

r = subprocess.run(['mstflint', '-i', OUT, 'verify'], capture_output=True, text=True)
say('[14] mstflint verify: rc=%d' % r.returncode)
say('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
if r.returncode != 0:
    die('mstflint verify failed')


def q_identity(path):
    r = subprocess.run(['mstflint', '-i', path, 'q'], capture_output=True, text=True)
    if r.returncode != 0:
        die('mstflint q failed for %s' % path)
    out = {}
    for l in (r.stdout + r.stderr).splitlines():
        for k in ('Device type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC'):
            if l.strip().startswith(k):
                out[k] = l.strip()
    return out


qbase = q_identity(BASE)
qout = q_identity(OUT)
say('[15] mstflint q identity:')
for k in ('Device type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC'):
    say('    base: %s' % qbase.get(k, 'MISSING'))
    say('    final: %s' % qout.get(k, 'MISSING'))
    if qbase.get(k) != qout.get(k):
        die('identity line %s differs: base %r != final %r' % (
            k, qbase.get(k), qout.get(k)))
for k in ('FW Version', 'PSID', 'Base GUID', 'Base MAC'):
    if k not in qbase:
        die('identity line %s missing in mstflint q output' % k)

out = open(OUT, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
if w32be(out, dc_to_raw(HOOK_DC)) != HOOK_AFTER:
    die('final hook word lost')
for dc, w, _ in stub_dc_words:
    if w32be(out, dc_to_raw(dc)) != w:
        die('final stub word @dc 0x%x lost' % dc)
if w32be(out, dc_to_raw(c12_dc)) != c12_w:
    die('final C12min word lost')
say('[16] final words OK (hook=%08x, C12min=%08x, %d stub words); md5=%s size=%d' % (
    HOOK_AFTER, c12_w, len(stub_dc_words), md5_out, len(out)))

LOG = OUT.replace('.bin', '-build.log')
open(LOG, 'w').write('\n'.join(lines_out) + '\n')
say('DONE %s md5=%s log=%s' % (OUT, md5_out, LOG))
