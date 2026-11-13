#!/usr/bin/env python3
"""cx4lx-detour T2a (phase VIII cable-path): build the hook image for
CX-4 Lx 14.32.1900 (fresh stock GCA-1900 base, md5-gated).

Two additive hooks from the T0 design (report cx4lx-detour-t0 s.5; T1
calibration: H-AN ~3.3 evt/s active AN -> emit2 safe, H-CYC dropped;
markers 0x00aeea41/0x00ad7547 dead-confirmed live, 0x00aecfec BANNED):

- H-AN @dc 0x1b9da4: stock `call 0x6008' (emit4 of the init_ib_an_fsm
  trace site, class 0x40 L1, GATE-gated -> our emit inherits the gate)
  -> cave stub: stock emit4 FIRST (site args r4..r8 in place), then our
  emit2 (marker rt 0x00aeea41, params [ctx+0x5c] speed/width word +
  [ctx+0xa0] substate word; r22=ctx survives the stock call), emit5
  (--emit 5: marker rt 0x00ae58cd, 5 ctx words; 7 fixed + 5 param words
  = 12 -> with H-DEC 23/24, the max both-hooks variant; the 6-token
  candidates 0x00b08ace/0x00af2589 were REJECTED by the dead-gate: one
  live loader each), or emit7
  (--emit 7: marker rt 0x00aeb83b, 7 ctx words). NOTE: a full emit7 stub
  is 7 fixed + 7 param words = 14, NOT the 13 of the T0 sketch (T0 s.5.1
  undercounted) -> emit7 + H-DEC = 25 > 24: the literal emit7 image is
  buildable H-AN-only (--hook-site H-AN --emit 7), emit5 is the max
  variant that keeps both hooks.
- H-DEC @dc 0x233094: stock `call 0x222670' (is_sfp verdict at the MM SM
  branch point) -> cave stub: stock is_sfp FIRST, save verdict to r10
  (NOT r8: emit core 0x6124 clobbers r8 - verified offline), emit2
  (marker rt 0x00ad7547, params module (r22) + verdict), restore r4
  verdict for the branch below, ret. 11 words.

Cave 0x31cba0..0x31cc00 = 24 words, all-zero on stock: H-AN + H-DEC =
20 <= 24 (emit2 build, slack 4) or 23/24 (emit5 build); emit7 H-AN-only
= 14/24. No old
hooks carried: boot word @0x7ee4 stays STOCK, entry block untouched.

Register safety (decode gates below): live-after H-AN {r1,r2,r21,r22,r23},
H-DEC {r1,r4,r18,r19,r21,r22,r23} (T0 set, conservative union with the
re-run branch-aware scan; r4 = the verdict, restored by the stub).
Link r12 + verdict-save r10 + ctx r22 verified absent from every callee
write-set (emit family {r1,r3,r5,r6}, core 0x6124 {r5..r9}, is_sfp
{r4,r5,r6,r7}; transitive closure hardcoded and gated).

Plus the B2-lineage card config: VPI 0x11+0x2af=0x07 (stock byte 0x0a =
EN-only -> IB experiments need def-IB; the running bank B image carries
0x07), card GUID/MAC via guides (stock sections are zeroed; skill Rule 3),
and the .ini build-ID (skill R1/R2 with trim).

Gates: base-md5 / MAIN_CODE geometry+param1 / expected_before + site
context (per site) / cave zero / boot word stock / entry block unique /
marker dead-on-this-base (loaders+raw) + banned-live-marker list /
register gates (clobber vs live-after, callee write-sets, link-reg tail
witness) / per-word decode / rel24 / budget (cave <= 24) / round-trip
clcrc / changed-line set / verify --deep per step / step diffs vs base
stray=NONE (hook words+clcrc+ITOC CRC, VPI, guides, 0x30) / final words /
mstflint verify bootable / mstflint q identity + PSID invariant vs base /
mstflint dc build-ID first content line."""
import argparse
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

GCA_REF = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
ENTRY_PARAM1 = 0x807edc
INJ_RAW = 0x1756d0
INJ_STOCK = 0x94000003
ENTRY_DC = 0x7edc
ENTRY_BLOCK = [0x94fff51b, 0x703f07fa, 0x94000003, 0x95000000, 0x95000000]
CAVE_DC = 0x31cba0
CAVE_END_DC = 0x31cc00
CAVE_WORDS = 24
REL24_LIMIT = 0x2000000
EMIT_ADDR = {2: 0x6064, 5: 0x6348, 7: 0x63bc}
EMIT_PARAMS = {2: 2, 5: 5, 7: 7}
BANNED_RT = {0x00aecfec}  # live at AN with a module (T1 s.4): forbidden marker
CALLEE_WRITES = {  # transitive (body + called cores), offline-verified
    0x6008: {1, 3, 5, 6, 7, 8, 9},   # emit4 -> core 0x6124
    0x6064: {1, 3, 5, 6, 7, 8, 9},   # emit2 -> core 0x6124
    0x6348: {1, 3, 5, 6, 7, 8, 9},   # emit5 -> core 0x6124
    0x63bc: {1, 3, 5, 6, 7, 8, 9},   # emit7 -> core 0x6124
    0x222670: {4, 5, 6, 7},          # is_sfp (leaf)
}
AN_WORDS_DEFAULT = {2: '0x5c,0xa0', 5: '0x58,0x5c,0x68,0xa0,0xa4',
                    7: '0x0,0x30,0x58,0x5c,0x68,0xa0,0xa4'}
AN_MARKER_DEFAULT = {2: 0x00aeea41, 5: 0x00ae58cd, 7: 0x00aeb83b}
DEC_MARKER_DEFAULT = 0x00ad7547

SITES = {
    'H-AN': dict(hook_dc=0x1b9da4, hook_before=0x94f93099, stock_tgt=0x6008,
                 stock_emit_n=4, fn_start=0x1b9d50, tail_win=0x400,
                 live_after={1, 2, 21, 22, 23}, restored=set(),
                 name='init_ib_an_fsm emit4 site (class 0x40 L1, gate-inherited)',
                 ctx=[(0x1b9d74, '00040040'), (0x1b9d78, '00050001'), (0x1b9d7c, '94f93085'),
                      (0x1b9d80, '14840000'), (0x1b9d84, 'a0000009'), (0x1b9d88, '66a60006'),
                      (0x1b9d8c, '66a50002'), (0x1b9d90, '66c8005e'), (0x1b9d94, '0004cc56'),
                      (0x1b9d98, '088400af'), (0x1b9d9c, '2d0700ff'), (0x1b9da0, 'c9080105')]),
    'H-DEC': dict(hook_dc=0x233094, hook_before=0x94ffbd77, stock_tgt=0x222670,
                  stock_emit_n=None, fn_start=0x231910, tail_win=0x1100,
                  live_after={1, 4, 18, 19, 21, 22, 23}, restored={4},
                  name='MM SM is_sfp verdict site (functional branch point)',
                  ctx=[(0x233070, 'fc842800'), (0x233074, 'fc851883'), (0x233078, 'fca5380a'),
                       (0x23307c, '2c84001e'), (0x233080, '3884001f'), (0x233084, 'fcc62080'),
                       (0x233088, '4c800028'), (0x23308c, '6ca03002'), (0x233090, 'fec4b008'),
                       (0x233098, '14840000'), (0x23309c, 'a000002b'), (0x2330a0, 'fec41881'),
                       (0x2330a4, 'fec51081')]),
}

VPI_OFF = 0x172af
VPI_VAL = 0x07
GUID = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'guid')
MAC = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'mac')
BUILD_ID_DATE = '2026-10-14'
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


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def enc_call(pc, tgt):
    if abs(tgt - pc) >= REL24_LIMIT:
        die('rel24 overflow: 0x%x -> 0x%x (delta 0x%x)' % (pc, tgt, abs(tgt - pc)))
    return (0x25 << 26) | (((tgt - pc) // 4) & 0xffffff)


def enc_addi(rd, rs, imm):
    return (0x00 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def enc_addi_hi(rd, rs, imm):
    return (0x02 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def enc_or(rd, rs, rt):
    return (0x3f << 26) | (rs << 21) | (rd << 16) | (rt << 11) | 8


def enc_ld_d(rd, rs, off):
    assert off % 4 == 0 and -0x1FF8 <= off <= 0x1FF8
    return (0x19 << 26) | (rs << 21) | (rd << 16) | (((off >> 2) & 0x3fff) << 2) | (1 << 1)


def enc_csr_r(rd, csr):
    return (0x12 << 26) | (rd << 16) | (csr & 0x7ff)


def enc_csr_w(rs, rt, csr):
    return (0x13 << 26) | (rs << 21) | (rt << 11) | (csr & 0x7ff)


RET_D = 0xFC00002D


def parse_args():
    p = argparse.ArgumentParser(description='build CX-4 Lx T2a cable-path hook image (phase VIII)')
    p.add_argument('--base', default=GCA_REF, help='stock GCA-1900 refs base')
    p.add_argument('--base-md5', default=BASE_MD5)
    p.add_argument('--hook-site', default='H-AN,H-DEC',
                   help='comma list of hook sites (subset of H-AN/H-DEC)')
    p.add_argument('--emit', type=int, default=2, choices=(2, 5, 7),
                   help='H-AN our-emit variant (H-DEC is always emit2); emit7 does not '
                        'co-fit with H-DEC in the 24-word cave (25>24): H-AN-only image')
    p.add_argument('--words', default=None,
                   help='H-AN ctx word offsets (ld.d from r22), e.g. 0x5c,0xa0; '
                        'default per --emit: emit2 "0x5c,0xa0", emit5 "0x58,0x5c,0x68,0xa0,0xa4", '
                        'emit7 "0x0,0x30,0x58,0x5c,0x68,0xa0,0xa4"')
    p.add_argument('--an-marker', type=lambda x: int(x, 0), default=None,
                   help='H-AN dead-string rt (default: emit2 0x00aeea41 / emit7 0x00aeb83b)')
    p.add_argument('--dec-marker', type=lambda x: int(x, 0), default=DEC_MARKER_DEFAULT)
    p.add_argument('--link-reg', type=int, default=12)
    p.add_argument('--verdict-reg', type=int, default=10,
                   help='H-DEC verdict save reg (r8 FORBIDDEN: emit core 0x6124 clobbers it)')
    p.add_argument('--ctx-reg', type=int, default=22, help='ctx/module base reg at both sites')
    p.add_argument('--guid', default=GUID)
    p.add_argument('--mac', default=MAC)
    p.add_argument('--no-vpi', action='store_true', help='skip the VPI 0x07 byte (stock keeps 0x0a = EN-only)')
    p.add_argument('--build-id-text', default=None)
    p.add_argument('--build-id-date', default=BUILD_ID_DATE)
    p.add_argument('--out', default=None,
                   help='default: build/cx4lx-cable-t2.bin (emit5: ...-an5.bin, emit7: ...-an7.bin)')
    args = p.parse_args()
    if args.out is None:
        args.out = REPO + '/build/cx4lx-cable-t2%s.bin' % {2: '', 5: '-an5', 7: '-an7'}[args.emit]
    args.sites_list = [s.strip() for s in args.hook_site.split(',') if s.strip()]
    for s in args.sites_list:
        if s not in SITES:
            die('unknown hook site %r (known: %s)' % (s, sorted(SITES)))
    if args.words is None:
        args.words = AN_WORDS_DEFAULT[args.emit]
    args.an_words = [int(w, 0) for w in args.words.split(',') if w.strip()]
    if args.an_marker is None:
        args.an_marker = AN_MARKER_DEFAULT[args.emit]
    if 'H-AN' in args.sites_list and len(args.an_words) != args.emit:
        die('--words has %d entries but emit%d needs exactly %d' % (
            len(args.an_words), args.emit, args.emit))
    if len(set(args.an_words)) != len(args.an_words):
        die('duplicate H-AN word offsets: %s' % [hex(w) for w in args.an_words])
    for w in args.an_words:
        if w % 4 or not -0x1FF8 <= w <= 0x1FF8:
            die('H-AN word offset 0x%x not 4-aligned/ld.d-range' % w)
    if args.verdict_reg == 8:
        die('verdict reg r8 forbidden: emit core 0x6124 clobbers r8 (offline-verified)')
    return args


args = parse_args()
lines_out = []
def say(msg=''):
    print(msg)
    lines_out.append(msg)


buf = open(args.base, 'rb').read()
md5_base = hashlib.md5(buf).hexdigest()
say('[1] base=%s md5=%s size=%d' % (args.base.split('/')[-1], md5_base, len(buf)))
if md5_base != args.base_md5:
    die('base md5 mismatch: %s != %s' % (md5_base, args.base_md5))

img = mlxfwutil.Image(buf, args.base)
e = img.find_entry('ITOC', 0x03)
say('[2] MAIN_CODE: type=0x%02x index=%d addr=0x%x size=0x%x clcrc=%d param1=0x%x' % (
    e.type, e.index, e.addr, e.size, e.clcrc, e.param1))
if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
    die('MAIN_CODE header mismatch (not the 14.32.1900 geometry)')
if e.param1 != ENTRY_PARAM1:
    die('entry vector param1 0x%x != 0x%x' % (e.param1, ENTRY_PARAM1))
raw = img.section_data(e)
code = decrc(raw)
if len(raw) != (len(code)//64)*68:
    die('unexpected non-empty section tail')


def dc_word(dco):
    ln, w = divmod(dco, 64)
    return w32be(buf, SEC_ADDR + ln*68 + w)


for name in args.sites_list:
    st = SITES[name]
    hw = dc_to_raw(st['hook_dc'])
    if w32be(buf, hw) != st['hook_before']:
        die('%s hook site word raw 0x%x = %08x != %08x (MAIN_CODE not stock?)' % (
            name, hw, w32be(buf, hw), st['hook_before']))
    for off, want in st['ctx']:
        if '%08x' % dc_word(off) != want:
            die('%s context word dc 0x%x mismatch (site neighborhood not stock)' % (name, off))
if not all(w32be(code, CAVE_DC + 4*i) == 0 for i in range(CAVE_WORDS)):
    die('cave dc 0x%x..0x%x not all-zero' % (CAVE_DC, CAVE_END_DC))
if w32be(buf, INJ_RAW) != INJ_STOCK:
    die('boot word raw 0x%x = %08x != %08x (base must have STOCK boot path - no old hooks!)' % (
        INJ_RAW, w32be(buf, INJ_RAW), INJ_STOCK))
for i, want in enumerate(ENTRY_BLOCK):
    if dc_word(ENTRY_DC + i*4) != want:
        die('entry block word mismatch at +%d' % i)
pat = b''.join(struct.pack('>I', w) for w in ENTRY_BLOCK)
if code.count(pat) != 1:
    die('entry 5-word pattern not unique: %d hits' % code.count(pat))
say('[3] expected_before OK: %s; cave %d words zero; boot word STOCK; entry block intact+unique' % (
    '; '.join('%s @dc 0x%x=%08x + %d ctx words' % (
        n, SITES[n]['hook_dc'], SITES[n]['hook_before'], len(SITES[n]['ctx'])) for n in args.sites_list),
    CAVE_WORDS))

markers = []
if 'H-AN' in args.sites_list:
    markers.append(('H-AN', args.an_marker))
if 'H-DEC' in args.sites_list:
    markers.append(('H-DEC', args.dec_marker))
seen_rt = {}
for name, rt in markers:
    if rt in BANNED_RT:
        die('%s marker rt 0x%08x is BANNED (live at AN with a module, T1)' % (name, rt))
    if rt in seen_rt:
        die('marker rt 0x%08x used by both %s and %s' % (rt, seen_rt[rt], name))
    seen_rt[rt] = name
    loaders = 0
    prev = None
    for i in range(len(code)//4 - 1):
        w = struct.unpack_from('>I', code, i*4)[0]
        op = w >> 26
        if op in (0x00, 0x01):
            prev = ((w >> 16) & 0x1f, s16(w & 0xffff))
        elif op in (0x02, 0x03) and prev is not None:
            prd, pimm = prev
            if prd == (w >> 16) & 0x1f and (pimm + ((w & 0xffff) << 16)) & 0xffffffff == rt:
                loaders += 1
            prev = None
        else:
            prev = None
    raw_hits = 0
    i = code.find(struct.pack('>I', rt))
    while i != -1 and i < 0x2d6900:
        raw_hits += 1
        i = code.find(struct.pack('>I', rt), i + 1)
    if loaders or raw_hits:
        die('%s marker rt 0x%08x not dead on THIS base (%d loaders, %d raw words)' % (
            name, rt, loaders, raw_hits))
    str_end = code.find(b'\0', rt - 0x800000)
    say('[4] %s marker rt 0x%08x dead (0 loaders, 0 raw words): %r' % (
        name, rt, code[rt - 0x800000:str_end][:78]))

LINK, VR, CTXR = args.link_reg, args.verdict_reg, args.ctx_reg
used_callees = set()
for name in args.sites_list:
    used_callees.add(SITES[name]['stock_tgt'])
if 'H-AN' in args.sites_list:
    used_callees.add(EMIT_ADDR[args.emit])
if 'H-DEC' in args.sites_list:
    used_callees.add(EMIT_ADDR[2])
for callee, wr in sorted((hex(c), w) for c, w in CALLEE_WRITES.items() if c in used_callees):
    say('    callee %s writes %s' % (callee, sorted(wr)))
for probe, what in ((LINK, 'link reg'), (VR, 'verdict reg'), (CTXR, 'ctx/module reg')):
    for callee in used_callees:
        if probe in CALLEE_WRITES[callee]:
            die('%s r%d is written by callee 0x%x (%s)' % (what, probe, callee, sorted(CALLEE_WRITES[callee])))
say('[5] reg gates: link r%d / verdict r%d / ctx r%d absent from all used-callee write-sets' % (LINK, VR, CTXR))

fn_end = {}
for name in args.sites_list:
    st = SITES[name]
    end = None
    for dc in range(st['hook_dc'] + 4, st['hook_dc'] + st['tail_win'], 4):
        d = irisc_dis.dis(dc_word(dc), dc)
        if d.startswith('ret'):
            end = dc
            break
        if re.search(r'\br%d\b' % LINK, d):
            die('link reg r%d mentioned at dc 0x%x ("%s") in %s tail' % (LINK, dc, d, name))
    if end is None:
        die('%s function end not found within 0x%x after hook site' % (name, st['tail_win']))
    fn_end[name] = end
say('[6] link reg r%d: 0 mentions in each hooked-function tail (site..ret %s)' % (
    LINK, {n: hex(fn_end[n]) for n in fn_end}))

stub_words = {}
stub_dc0 = {}


def emit_stub(name, start_dc):
    st = SITES[name]
    words = []

    def push(w, want_dis):
        dc = start_dc + 4*len(words)
        d = irisc_dis.dis(w, dc)
        if d != want_dis:
            die('%s stub word dc 0x%x %08x decodes %r != %r' % (name, dc, w, d, want_dis))
        words.append((w, d))

    def push_rt_load(rt):
        lo = rt & 0xffff
        hi = (rt >> 16) & 0xffff
        carry = 1 if lo & 0x8000 else 0
        if hi + carry > 0xffff:
            die('rt 0x%x not encodable as addi+addi.hi pair' % rt)
        push(enc_addi(4, 0, lo), 'addi r4,zero,0x%x' % s16(lo))
        push(enc_addi_hi(4, 4, hi + carry), 'addi.hi r4,r4,0x%x' % (hi + carry))
        got = (s16(lo) + ((hi + carry) << 16)) & 0xffffffff
        if got != rt:
            die('marker pair composes to 0x%08x != 0x%08x' % (got, rt))

    dc = start_dc
    push(enc_csr_r(LINK, 0xbc), 'csr.r r%d,csr0xbc' % LINK)
    dc += 4
    push(enc_call(dc, st['stock_tgt']), 'call 0x%x' % st['stock_tgt'])
    dc += 4
    if name == 'H-AN':
        push_rt_load(args.an_marker)
        dc += 8
        for i, off in enumerate(args.an_words):
            rd = 5 + i
            push(enc_ld_d(rd, CTXR, off), 'ld.d r%d,r%d,0x%x' % (rd, CTXR, off))
            dc += 4
        push(enc_call(start_dc + 4*len(words), EMIT_ADDR[args.emit]),
             'call 0x%x' % EMIT_ADDR[args.emit])
        dc += 4
    else:
        push(enc_or(VR, 4, 4), 'or r%d,r4,r4' % VR)
        dc += 4
        push_rt_load(args.dec_marker)
        dc += 8
        push(enc_or(5, CTXR, CTXR), 'or r5,r%d,r%d' % (CTXR, CTXR))
        dc += 4
        push(enc_or(6, VR, VR), 'or r6,r%d,r%d' % (VR, VR))
        dc += 4
        push(enc_call(start_dc + 4*len(words), EMIT_ADDR[2]), 'call 0x%x' % EMIT_ADDR[2])
        dc += 4
        push(enc_or(4, VR, VR), 'or r4,r%d,r%d' % (VR, VR))
        dc += 4
    push(enc_csr_w(LINK, 0, 0xbc), 'csr.w r%d,zero,0xbc' % LINK)
    dc += 4
    push(RET_D, 'ret.d zero,zero,zero')
    return words


clobbers = {}
if 'H-AN' in args.sites_list:
    clobbers['H-AN'] = set(range(4, 5 + args.emit)) | {LINK}
if 'H-DEC' in args.sites_list:
    clobbers['H-DEC'] = {4, 5, 6, VR, LINK}
for name in args.sites_list:
    st = SITES[name]
    bad = clobbers[name] - st['restored']
    clash = bad & st['live_after']
    if clash:
        die('%s stub clobbers live-after regs %s (live-after %s)' % (
            name, sorted(clash), sorted(st['live_after'])))
    say('[7] %s clobber %s (restored %s) vs live-after %s: clean' % (
        name, sorted(clobbers[name]), sorted(st['restored']) or '-', sorted(st['live_after'])))

order = [n for n in ('H-AN', 'H-DEC') if n in args.sites_list]
cursor = CAVE_DC
for name in order:
    stub_dc0[name] = cursor
    stub_words[name] = emit_stub(name, cursor)
    cursor += 4*len(stub_words[name])
if cursor > CAVE_END_DC:
    die('stubs exceed cave end (0x%x > 0x%x)' % (cursor, CAVE_END_DC))
total_words = sum(len(v) for v in stub_words.values())
say('[8] stubs: %s (cave words %d/%d, slack %d)' % (
    ', '.join('%s @dc 0x%x..0x%x %d words' % (
        n, stub_dc0[n], stub_dc0[n] + 4*len(stub_words[n]), len(stub_words[n])) for n in order),
    total_words, CAVE_WORDS, CAVE_WORDS - total_words))
for name in order:
    for i, (w, d) in enumerate(stub_words[name]):
        say('    %s[%2d] dc 0x%x %08x = %s' % (name, i, stub_dc0[name] + 4*i, w, d))

rt_data = clcrc(code)
if rt_data != raw:
    die('round-trip de-clcrc/re-clcrc failed')
say('[9] round-trip: OK (%d lines)' % (len(code)//64))

hook_after = {}
patched_dcs = []
for name in order:
    st = SITES[name]
    wa = enc_call(st['hook_dc'], stub_dc0[name])
    d = irisc_dis.dis(wa, st['hook_dc'])
    if d != 'call 0x%x' % stub_dc0[name]:
        die('%s hook patch decode %r' % (name, d))
    hook_after[name] = wa
    patched_dcs.append(st['hook_dc'])
for name in order:
    patched_dcs += [stub_dc0[name] + 4*i for i in range(len(stub_words[name]))]
changed_lines = sorted({dc // 64 for dc in patched_dcs})
say('[10] hooks: %s; changed lines %s' % (
    ', '.join('%s %08x -> %08x ("call 0x%x")' % (
        n, SITES[n]['hook_before'], hook_after[n], stub_dc0[n]) for n in order), changed_lines))

pcode = bytearray(code)
for name in order:
    struct.pack_into('>I', pcode, SITES[name]['hook_dc'], hook_after[name])
    for i, (w, _) in enumerate(stub_words[name]):
        struct.pack_into('>I', pcode, stub_dc0[name] + 4*i, w)
pcode = bytes(pcode)
praw = clcrc(pcode)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != changed_lines:
    die('changed-line set drifted: %s != %s' % (diff_lines, changed_lines))
step1 = mlxfwutil.patch_sections(img, [(0x03, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
say('[11] step1 (base+hooks+stubs): changed lines %s only; verify(deep)=%s' % (
    changed_lines, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
for name in order:
    if w32be(step1, dc_to_raw(SITES[name]['hook_dc'])) != hook_after[name]:
        die('step1 %s hook word lost' % name)
    for i, (w, _) in enumerate(stub_words[name]):
        if w32be(step1, dc_to_raw(stub_dc0[name] + 4*i)) != w:
            die('step1 %s stub word @dc 0x%x lost' % (name, stub_dc0[name] + 4*i))
STEP1 = args.out + '.step1'
open(STEP1, 'wb').write(step1)

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


def diff_check(label, new, old, allowed):
    diffs = [i for i in range(min(len(new), len(old))) if new[i] != old[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    say('[d] %s: %d diff bytes, stray=%s' % (label, len(diffs), stray if stray else 'NONE'))
    if stray:
        die('stray diff bytes in %s: %s' % (label, stray))
    return diffs


diff_check('step1 vs base (hooks+stubs+clcrc+ITOC CRC)', step1, buf, allowed_step1)

img1 = mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt)
next_in = STEP1
if not args.no_vpi:
    STEP2 = args.out + '.step2'
    r = subprocess.run(['python3', 'mlxfwutil.py', 'patch', '--set', '0x11+0x2af=%02x' % VPI_VAL,
                        '-o', STEP2, STEP1], cwd=REPO, capture_output=True, text=True)
    say('[12] step2 (VPI 0x%02x, stock 0x%02x): rc=%d %s%s' % (
        VPI_VAL, buf[VPI_OFF], r.returncode, r.stdout.strip(), r.stderr.strip()))
    if r.returncode != 0:
        die('VPI patch step failed')
    step2 = open(STEP2, 'rb').read()
    if step2[VPI_OFF] != VPI_VAL:
        die('VPI byte not set at 0x%x' % VPI_OFF)
    allowed_vpi, ent11 = sec_ranges(img1, 0x11)
    eo11 = 0x2000 + 32 + ent11.index*32
    diff_check('step2 vs step1 (VPI)', step2, step1, {VPI_OFF} | set(range(eo11+0x1a, eo11+0x20)))
    next_in = STEP2
    img1 = mlxfwutil.Image(step2, 'step2', base=img.base, fmt=img.fmt)

STEP3 = args.out + '.step3'
r = subprocess.run(['python3', 'mlxfwutil.py', 'guides', '--guid', args.guid, '--mac', args.mac,
                    '-o', STEP3, next_in], cwd=REPO, capture_output=True, text=True)
say('[13] step3 (guides %s/%s; stock sections were zeroed): rc=%d %s%s' % (
    args.guid, args.mac, r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('guides step failed')
step3 = open(STEP3, 'rb').read()
prev_buf = open(next_in, 'rb').read()
allowed_guides = set()
for stt in (0xE1, 0xE0):
    rng, _ = sec_ranges(img1, stt)
    allowed_guides |= rng
diff_check('step3 vs step2 (guides)', step3, prev_buf, allowed_guides)

words_desc = '/'.join('%x' % w for w in args.an_words)
build_id = args.build_id_text or (
    '; mlxini cx4lx-cable-t2%s (%s, %s): VIII hooks H-AN@0x1b9da4 emit%d ctx[%s] '
    '+ H-DEC@0x233094 is_sfp verdict, cave@0x31cba0, markers %06x/%06x' % (
        '' if args.emit == 2 else '-an%d' % args.emit, args.build_id_date, md5_base,
        args.emit, words_desc, args.an_marker & 0xffffff, args.dec_marker & 0xffffff))
if '\n' in build_id or not build_id.startswith('; '):
    die('bad build-ID line: single "; "-comment required (R1)')

img_fc = mlxfwutil.Image(step3, 'step3', base=img.base, fmt=img.fmt)
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
    return ls[:a + 1] + [build_id] + ls[a + 1:]


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
say('[14] ini build-ID (R1/R2): "%s"' % build_id)
say('    0x30 e.size=%d budget=%d; zlib9+DWpad: no-trim=%d -> final=%d (slack %d)%s' % (
    e30.size, budget30, n_untrimmed, n_final, budget30 - n_final,
    '' if trimmed_idx else ', no trim needed'))
if trimmed_idx:
    say('    trim: %d ;;-comment lines dropped: %s' % (
        len(trimmed_idx), ['%d (%d B)' % (i, len(ini_lines[i])) for i in trimmed_idx]))
if n_final > budget30:
    die('0x30 budget exceeded even after trim (%d > %d): STOP, no --repack-force (R2)' % (n_final, budget30))
try:
    out_buf = mlxfwutil.inject_ini(img_fc, ini_final)
except ValueError as ex:
    die('inject_ini: %s (STOP per R2)' % ex)
open(args.out, 'wb').write(out_buf)
img_fin = mlxfwutil.Image(out_buf, args.out, base=img.base, fmt=img.fmt)
rt30 = mlxfwutil.extract_section(img_fin, 0x30)
rt_ini = zlib.decompress(rt30) if rt30[:2] == b'\x78\xda' else rt30
if rt_ini != ini_final.encode('latin1'):
    die('round-trip failed: extract != ini-final')
e30n = img_fin.find_entry('ITOC', 0x30)
if e30n.addr != e30.addr:
    die('0x30 relocated: 0x%x -> 0x%x' % (e30.addr, e30n.addr))
if e30n.size > e30.size:
    die('0x30 grew: 0x%x -> 0x%x' % (e30.size, e30n.size))
errs = mlxfwutil.verify_image(img_fin, deep=True)
if errs:
    die('final verify(deep) after inject: %s' % errs)
open(args.out.replace('.bin', '-ini-final.ini'), 'w', encoding='latin1').write(ini_final)
say('    round-trip extract == ini-final; 0x30 in place @0x%x size 0x%x -> 0x%x; verify(deep)=PASS' % (
    e30n.addr, e30.size, e30n.size))
allowed_ini, _ = sec_ranges(img_fc, 0x30)
diff_check('final vs step3 (0x30 build-ID)', out_buf, step3, allowed_ini)

out = open(args.out, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
for name in order:
    if w32be(out, dc_to_raw(SITES[name]['hook_dc'])) != hook_after[name]:
        die('final %s hook word lost' % name)
    for i, (w, _) in enumerate(stub_words[name]):
        if w32be(out, dc_to_raw(stub_dc0[name] + 4*i)) != w:
            die('final %s stub word @dc 0x%x lost' % (name, stub_dc0[name] + 4*i))
if not args.no_vpi and out[VPI_OFF] != VPI_VAL:
    die('final VPI byte lost')
say('[15] final words OK (%s, %d stub words, vpi=%02x); md5=%s size=%d' % (
    ', '.join('%s=%08x' % (n, hook_after[n]) for n in order),
    total_words, out[VPI_OFF], md5_out, len(out)))

r = subprocess.run(['mstflint', '-i', args.out, 'verify'], capture_output=True, text=True)
say('[16] mstflint verify: rc=%d' % r.returncode)
say('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
if r.returncode != 0:
    die('mstflint verify failed')


def q_identity(path):
    r = subprocess.run(['mstflint', '-i', path, 'q'], capture_output=True, text=True)
    vals = {}
    for l in (r.stdout + r.stderr).splitlines():
        for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC'):
            if l.startswith(k + ':'):
                v = l.split(':', 1)[1].strip()
                vals[k] = v.split()[0] if k in ('Base GUID', 'Base MAC') else v
    return vals, (r.stdout + r.stderr)


qv, qtxt = q_identity(args.out)
bv, _ = q_identity(args.base)
for l in qtxt.splitlines():
    if any(l.startswith(k + ':') for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC')):
        say('    ' + l.strip())
for k in ('Image type', 'FW Version', 'PSID'):
    if qv.get(k) != bv.get(k):
        die('identity not invariant vs base: %s %r -> %r' % (k, bv.get(k), qv.get(k)))
for k, want in (('Base GUID', args.guid[2:]), ('Base MAC', args.mac[2:])):
    if qv.get(k) != want:
        die('identity check failed: %s = %r != %s' % (k, qv.get(k), want))
if set(qv) != {'Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC'}:
    die('identity lines missing in q output: %s' % sorted(qv))
say('[17] mstflint q: PSID/FW/type invariant vs base; GUID/MAC == card (%s/%s, Rule 3)' % (
    args.guid, args.mac))

r = subprocess.run(['mstflint', '-i', args.out, 'dc'], capture_output=True, text=True)
dl = [l.rstrip() for l in (r.stdout + r.stderr).splitlines()]
NOISE = ('-E-', '-W-', '-I-', '-')
try:
    mi = next(i for i, l in enumerate(dl) if build_id in l)
except StopIteration:
    mi = -1
if mi < 0:
    die('mstflint dc does not show the build-ID marker')
pre = [l for l in dl[:mi] if l.strip() and not l.startswith(NOISE)]
if any(not l.startswith(';;') for l in pre) or len(pre) > 1:
    die('build-ID is not the first content line of dc (pre-content: %r)' % pre)
say('[18] mstflint dc: build-ID is the first content line (line %d of dc):' % (mi + 1))
say('    ' + dl[mi])

LOG = args.out.replace('.bin', '-build.log')
open(LOG, 'w').write('\n'.join(lines_out) + '\n')
say('DONE %s md5=%s log=%s' % (args.out, md5_out, LOG))
