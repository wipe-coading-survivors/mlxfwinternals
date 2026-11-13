#!/usr/bin/env python3
"""cx4lx-detour D1: build dump-semifabricate image for CX-4 Lx 14.32.1900.

Core of the future D2 semifabricate: stock base + H0 runtime hook whose
cave stub dumps a caller-defined word list as one trace event.

- H0 hook: trace-site word @dc 0xd3850 in access-register handler 0xd3804
  (stock emit2 `call 0x6064' = 94fcca05) -> `call <cave stub>' (0x31cba0).
- Cave stub @0x31cba0 (24-word cave, fully free - NO boot block in this
  image: entry word 0x7ee4 stays stock 94000003; no VPI patch - the base
  is pure stock GCA, only hook words + guides differ from stock):
    csr.r r17,csr0xbc      save link (r10/r11 are emit7 params; r17 is
                            callee-saved and unused in 0xd3804 tail)
    call 0x6064            stock emit2 FIRST (site args r4/r5/r6 in place)
    addi/addi.hi r4,<rt>   dead db0 string rt (default 0x00ada612, one %x)
    <param loads r5..>     one instruction group per --addrs entry:
                            - offset-batched ld.d from materialized base
                            - ld.i word-index for addr<=0x2000 (GATE's own
                              reader form: `ld.i rX,0x2' reads local RAM
                              word 2 = trace mask)
                            - set2/set3 r3,addr + ld.d rX,r3,0 otherwise
    call <emitN>           default emit7 0x63bc (7 params r5..r11)
    csr.w r17,zero,0xbc    restore link
    ret.d
- D1 defaults: addrs = 8,12 (w2/w3 mask/level ground truth),
  0x0D600C..0x0D6018 (4-word bitset, offset-batched), 0xE2B4 (gate);
  emit7 -> 18 of 24 cave words.

Gates: base-md5 / hook expected_before + site context / cave all-zero /
entry word NOT patched (no boot block) + entry pattern unique / GATE ld.i
witnesses / link-reg liveness scan in 0xd3804 tail / dead-string loader
scan / decode of every patched word / budget <= 24 / round-trip
de-clcrc+re-clcrc / changed-line set / verify --deep / step diff vs base
stray=NONE / mstflint verify bootable / mstflint q identity."""
import argparse
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + '/scripts/irisc')
import mlxfwutil
import irisc_dis

BASE_MD5_D1 = '3bd3230b1deae0cf74a08e31d59021d9'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
INJ_RAW = 0x1756d0
INJ_STOCK = 0x94000003
ENTRY_DC = 0x7edc
ENTRY_BLOCK = [0x94fff51b, 0x703f07fa, 0x94000003, 0x95000000, 0x95000000]
HOOK_DC = 0xd3850
HOOK_BEFORE = 0x94fcca05
STOCK_EMIT2 = 0x6064
CAVE_DC = 0x31cba0
CAVE_END_DC = 0x31cc00
CAVE_WORDS = 24
EMIT_ADDR = {1: 0x603c, 2: 0x6064, 3: 0x6090, 4: 0x6008, 7: 0x63bc}
EMIT_PARAMS = {1: 1, 2: 2, 3: 3, 4: 4, 7: 7}
LD_I_ZONE = 0x2000
GATE_DC = 0x5f90
GATE_LD_I = [(0x5fac, 'ld.i r6,0x2'), (0x5fc0, 'ld.i r4,0x3')]
FN_START_DC = 0xd3804
SITE_CTX = [(0xd382c, '24040400'), (0xd3830, '00050001'), (0xd3834, '94fcc9d7'),
            (0xd3840, '0004a88c'), (0xd3844, '088400ae'),
            (0xd3848, 'fec5b008'), (0xd384c, 'fee6b808')]

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


RET_D = 0xFC00002D


def parse_args():
    p = argparse.ArgumentParser(description='build CX-4 Lx dump-semifabricate image')
    p.add_argument('--base', default=REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin')
    p.add_argument('--base-md5', default=BASE_MD5_D1, help='expected base md5; "none" to skip (D2: foreign base)')
    p.add_argument('--guid', default='0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'guid'))
    p.add_argument('--mac', default='0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'mac'))
    p.add_argument('--addrs', default='0x8,0xC,0x0D600C,0x0D6010,0x0D6014,0x0D6018,0xE2B4',
                   help='comma-separated word addresses to dump (order = param order)')
    p.add_argument('--string-rt', default='0x00ada612', help='dead db0 string rt (single %%x shows first param)')
    p.add_argument('--emit', type=int, default=7, choices=sorted(EMIT_ADDR), help='our emit wrapper')
    p.add_argument('--link-reg', type=int, default=17, help='link holder register')
    p.add_argument('--out', default=REPO + '/build/cx4lx-dump-d1.bin')
    return p.parse_args()


args = parse_args()
lines_out = []
def say(msg=''):
    print(msg)
    lines_out.append(msg)


addrs = [int(a, 0) for a in args.addrs.split(',') if a.strip()]
string_rt = int(args.string_rt, 0)
emit_addr = EMIT_ADDR[args.emit]
nparams = EMIT_PARAMS[args.emit]
if not addrs:
    die('empty --addrs')
if len(addrs) > nparams:
    die('%d addrs exceed emit%d param slots (%d)' % (len(addrs), args.emit, nparams))
if not (5 <= args.link_reg <= 23) or args.link_reg in (0,):
    die('bad link reg %d' % args.link_reg)

buf = open(args.base, 'rb').read()
md5_base = hashlib.md5(buf).hexdigest()
say('[1] base=%s md5=%s size=%d' % (args.base.split('/')[-1], md5_base, len(buf)))
if args.base_md5 != 'none':
    if md5_base != args.base_md5:
        die('base md5 mismatch: %s != %s' % (md5_base, args.base_md5))
else:
    say('    base-md5 gate SKIPPED (--base-md5 none): structural gates below must carry the verification')

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
HOOK_RAW = dc_to_raw(HOOK_DC)
if w32be(buf, HOOK_RAW) != HOOK_BEFORE:
    die('hook site word raw 0x%x = %08x != %08x (MAIN_CODE differs from GCA stock?)' % (
        HOOK_RAW, w32be(buf, HOOK_RAW), HOOK_BEFORE))
for off, want in SITE_CTX:
    if '%08x' % w32be(buf, dc_to_raw(off)) != want:
        die('hook site context word dc 0x%x mismatch (site neighborhood not stock)' % off)
if not all(w32be(code, CAVE_DC + 4*i) == 0 for i in range(CAVE_WORDS)):
    die('cave dc 0x%x..0x%x not all-zero' % (CAVE_DC, CAVE_END_DC))
if w32be(buf, INJ_RAW) != INJ_STOCK:
    die('entry injection word raw 0x%x = %08x != %08x (base must have STOCK boot path)' % (
        INJ_RAW, w32be(buf, INJ_RAW), INJ_STOCK))
say('[3] expected_before OK: hook 0x%x=%08x + site context; cave %d words zero; boot word 0x%x STOCK (no boot block)' % (
    HOOK_RAW, HOOK_BEFORE, CAVE_WORDS, INJ_RAW))


def dc_word(dco):
    ln, w = divmod(dco, 64)
    return w32be(buf, SEC_ADDR + ln*68 + w)


for i, want in enumerate(ENTRY_BLOCK):
    if dc_word(ENTRY_DC + i*4) != want:
        die('entry block word mismatch at +%d' % i)
pat = b''.join(struct.pack('>I', w) for w in ENTRY_BLOCK)
if code.count(pat) != 1:
    die('entry 5-word pattern not unique: %d hits' % code.count(pat))
for dc, want in GATE_LD_I:
    d = irisc_dis.dis(dc_word(dc), dc)
    if d != want:
        die('GATE ld.i witness dc 0x%x = "%s" != "%s"' % (dc, d, want))
say('[4] entry block intact+unique; GATE ld.i witnesses OK (mask=w2, level=w3 reader form)')

import re
fn_end = None
for dc in range(HOOK_DC + 4, FN_START_DC + 0x400, 4):
    d = irisc_dis.dis(dc_word(dc), dc)
    if d.startswith('ret.'):
        fn_end = dc
        break
    if re.search(r'\br%d\b' % args.link_reg, d):
        die('link reg r%d read at dc 0x%x ("%s") inside hooked function tail' % (args.link_reg, dc, d))
if fn_end is None:
    die('function end not found after hook site')
say('[5] link reg r%d: 0 mentions in 0x%x tail (site..ret 0x%x) - safe' % (args.link_reg, FN_START_DC, fn_end))

for a in addrs:
    if a % 4:
        die('addr 0x%x not 4-aligned' % a)

stub_dc_words = []
def emit_word(w, want_dis):
    dc = CAVE_DC + 4*len(stub_dc_words)
    d = irisc_dis.dis(w, dc)
    if d != want_dis:
        die('stub word dc 0x%x %08x decodes "%s" != "%s"' % (dc, w, d, want_dis))
    stub_dc_words.append((dc, w, d))


emit_word(enc_csr_r(args.link_reg, 0xbc), 'csr.r r%d,csr0xbc' % args.link_reg)
emit_word(enc_call(CAVE_DC + 4, STOCK_EMIT2), 'call 0x%x' % STOCK_EMIT2)
lo = string_rt & 0xffff
hi = (string_rt >> 16) & 0xffff
carry = 1 if lo & 0x8000 else 0
if hi + carry > 0xffff:
    die('string rt 0x%x not encodable as addi+addi.hi pair' % string_rt)
emit_word(enc_addi(4, 0, lo), 'addi r4,zero,0x%x' % s16(lo))
emit_word(enc_addi_hi(4, 4, hi + carry), 'addi.hi r4,r4,0x%x' % (hi + carry))

used_regs = {3, 4}
base_val = None
for i, a in enumerate(addrs):
    rd = 5 + i
    used_regs.add(rd)
    off = a - base_val if base_val is not None else None
    if base_val is not None and off % 4 == 0 and -0x1FF8 <= off <= 0x1FF8:
        emit_word(enc_ld_d(rd, 3, off), 'ld.d r%d,r3,0x%x' % (rd, off))
    elif a <= LD_I_ZONE and (a >> 2) <= 0xFFFF:
        emit_word(enc_ld_i(rd, a >> 2), 'ld.i r%d,0x%x' % (rd, a >> 2))
    else:
        emit_word(enc_set2(3, (a >> 16) & 0xffff), 'set2 r3,zero,0x%x' % ((a >> 16) & 0xffff))
        emit_word(enc_set3(3, 3, a & 0xffff), 'set3 r3,r3,0x%x' % (a & 0xffff))
        emit_word(enc_ld_d(rd, 3, 0), 'ld.d r%d,r3,0x0' % rd)
        base_val = a
if args.link_reg in used_regs:
    die('link reg r%d collides with param/string regs %s' % (args.link_reg, sorted(used_regs)))
emit_word(enc_call(CAVE_DC + 4*len(stub_dc_words), emit_addr), 'call 0x%x' % emit_addr)
emit_word(enc_csr_w(args.link_reg, 0, 0xbc), 'csr.w r%d,zero,0xbc' % args.link_reg)
emit_word(RET_D, 'ret.d zero,zero,zero')
say('[6] stub %d/%d cave words (emit%d, %d addrs, link r%d):' % (len(stub_dc_words), CAVE_WORDS, args.emit, len(addrs), args.link_reg))
for dc, w, d in stub_dc_words:
    say('    dc 0x%x %08x = %s' % (dc, w, d))
if len(stub_dc_words) > CAVE_WORDS:
    die('stub exceeds cave budget')

prev = None
loaders = 0
for off in range(0, len(code) - 4, 4):
    w = struct.unpack_from('>I', code, off)[0]
    op = w >> 26
    if op in (0x00, 0x01):
        prev = (off, (w >> 16) & 0x1f, s16(w & 0xffff))
    elif op in (0x02, 0x03) and prev is not None:
        poff, prd, pimm = prev
        if poff + 4 == off and prd == (w >> 16) & 0x1f:
            composed = ((pimm & 0xffffffff) + (((w & 0xffff)) << 16)) & 0xffffffff
            if composed == string_rt:
                loaders += 1
        prev = None
if loaders:
    die('string rt 0x%x has %d stock loaders - not dead' % (string_rt, loaders))
say('[7] string rt 0x%08x dead (0 addi/addi.hi loaders in MAIN_CODE)' % string_rt)

rt = clcrc(code)
if rt != raw:
    die('round-trip de-clcrc/re-clcrc failed')
say('[8] round-trip: OK (%d lines)' % (len(code)//64))

HOOK_AFTER = enc_call(HOOK_DC, CAVE_DC)
d = irisc_dis.dis(HOOK_AFTER, HOOK_DC)
if d != 'call 0x%x' % CAVE_DC:
    die('hook patch decode "%s"' % d)
patched_dcs = [HOOK_DC] + [dc for dc, _, _ in stub_dc_words]
changed_lines = sorted({dc // 64 for dc in patched_dcs})
say('[9] hook %08x -> %08x ("%s"); changed lines %s' % (HOOK_BEFORE, HOOK_AFTER, d, changed_lines))

pcode = bytearray(code)
struct.pack_into('>I', pcode, HOOK_DC, HOOK_AFTER)
for dc, w, _ in stub_dc_words:
    struct.pack_into('>I', pcode, dc, w)
pcode = bytes(pcode)
praw = clcrc(pcode)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != changed_lines:
    die('changed-line set drifted: %s != %s' % (diff_lines, changed_lines))
step1 = mlxfwutil.patch_sections(img, [(0x03, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
say('[10] step1 (stock+hook+stub): changed lines %s only; verify(deep)=%s' % (
    changed_lines, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
if w32be(step1, HOOK_RAW) != HOOK_AFTER:
    die('step1 hook word lost')
for dc, w, _ in stub_dc_words:
    if w32be(step1, dc_to_raw(dc)) != w:
        die('step1 stub word @dc 0x%x lost' % dc)
STEP1 = args.out + '.step1'
open(STEP1, 'wb').write(step1)

r = subprocess.run(['python3', 'mlxfwutil.py', 'guides', '--guid', args.guid, '--mac', args.mac,
                    '-o', args.out, STEP1], cwd=REPO, capture_output=True, text=True)
say('[11] guides (guid=%s mac=%s): rc=%d %s%s' % (args.guid, args.mac, r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('guides step failed')

out = open(args.out, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
if w32be(out, HOOK_RAW) != HOOK_AFTER or w32be(out, INJ_RAW) != INJ_STOCK:
    die('final identity words lost')
for dc, w, _ in stub_dc_words:
    if w32be(out, dc_to_raw(dc)) != w:
        die('final stub word @dc 0x%x lost' % dc)
say('[12] final words OK (hook=%08x, boot=stock, %d stub words); md5=%s size=%d' % (
    HOOK_AFTER, len(stub_dc_words), md5_out, len(out)))

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
    return set(range(ent.addr, ent.addr + ent.size)) | set(range(eo, eo + 32))


img1 = mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt)
allowed_guides = set()
for st in (0xE1, 0xE0):
    allowed_guides |= sec_ranges(img1, st)


def diff_check(label, new, old, allowed):
    diffs = [i for i in range(min(len(new), len(old))) if new[i] != old[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    say('[13] %s: %d diff bytes, stray=%s' % (label, len(diffs), stray if stray else 'NONE'))
    if stray:
        die('stray diff bytes in %s: %s' % (label, stray))
    return diffs


diff_check('step1 vs base (hook+stub)', step1, buf, allowed_step1)
diff_check('final vs step1 (guides)', out, step1, allowed_guides)

r = subprocess.run(['mstflint', '-i', args.out, 'verify'], capture_output=True, text=True)
say('[14] mstflint verify: rc=%d' % r.returncode)
say('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
if r.returncode != 0:
    die('mstflint verify failed')
r = subprocess.run(['mstflint', '-i', args.out, 'q'], capture_output=True, text=True)
say('[15] mstflint q:')
ok15 = {}
for l in (r.stdout + r.stderr).splitlines():
    if any(k in l for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC')):
        say('    ' + l.strip())
        for k, v in (('Image type', 'FS3'), ('FW Version', '14.32.1900'),
                     ('Base GUID', args.guid[2:]), ('Base MAC', args.mac[2:])):
            if l.startswith(k):
                ok15[k] = v in l
for k, v in ok15.items():
    if not v:
        die('identity check failed: %s' % k)
if 'Image type' not in ok15 or 'FW Version' not in ok15 or 'Base GUID' not in ok15:
    die('identity lines missing in q output (PSID printed for reference only)')

LOG = args.out.replace('.bin', '-build.log')
open(LOG, 'w').write('\n'.join(lines_out) + '\n')
say('DONE %s md5=%s log=%s' % (args.out, md5_out, LOG))
