#!/usr/bin/env python3
"""cx4lx-detour D2: build dump-semifabricate images for a consumer session
(CX-4 Lx 14.32.1900, consumer stock-ri base).

VENDORED (cx4lx-sfp28-ib-node task-04l): byte-identical copy of
scripts/probes/cx4lx-detour/build_dump_d2.py (branch cx4lx-detour,
2026-10-11, md5 cd05d3d68c66cce0cb2f9fcf93ac6cb8) so the sfp28-ib-node
cycle does not depend on the detour worktree. Single functional change:
--extra-patch (repeatable dc:before:after[:want_dis]) adds extra
MAIN_CODE word patches to the SAME clcrc/verify flow (pre-gated on
before, after decode-verified against want_dis); all other gates and
mechanics are verbatim. The detour-branch original stays authoritative
for the detour cycle.

Two triggers, same cave stub (D1 mechanics, no boot block):
- H0 (default): hook @dc 0xd3850 in access-register handler 0xd3804
  (stock emit2 `call 0x6064' = 94fcca05) -> call cave stub. Live-proven
  form (v3 + D1): trigger = any register command (host-controlled polling).
- H6: hook @dc 0x1b9da4 in the init_ib_an_fsm trace site
  (stock emit4 `call 0x6008' = 94f93099, site class 0x40 level 1) -> call
  cave stub. Autonomous trigger: AN-FSM loop (~0.4 s) while AN is active.
  NOT live-validated: consumer fallback is the H0 image.

Stub (18/24 words, additive-read: straight line, no branches, no timing
changes; stock site emit FIRST, then one emit7 with 7 dump params):
    csr.r r17,csr0xbc      save link (r17 callee-saved, 0 tail mentions)
    call <stock emitN>     stock event first (site args in place)
    addi/addi.hi r4,<rt>   dead db0 string (default rt 0x00aeb83b:
                           '%x, var1=0x%x, ... var6=0x%x' - 7 params!)
    ld.i r5,0x2            local RAM w2 = trace mask (self-check param)
    set2/set3 r3,0x0D600C  bitset base
    ld.d r6..r9,r3,0/4/8/c bitset words (offset-batched)
    set2/set3 r3,0xE2B4    gate base (0xE2B4 far from bitset: new pair)
    ld.d r10,r3,0x0        gate word 0xE2B4
    ld.d r11,r3,-0xcd8     gate word 0xD5DC (0xD5DC - 0xE2B4)
    call 0x63bc            emit7: r5..r11 -> one trace event
    csr.w r17,zero,0xbc    restore link
    ret.d

D2 vs D1: --trigger H0|H6; consumer ri base (md5-gated to the known-good
stock ri dacbcf0e...); MAIN_CODE ACA<->GCA byte-compare gate (verdict
printed; on mismatch: diff report + structural gates keep deciding, no
silent abort); --guides skip (default): consumer ri already carries
DEV_INFO/MFG_INFO -> gate them (present + GUID/MAC == expected) and keep
final == step1 instead of rewriting device data.

D2b (.ini build-ID, owner directive 2026-10-11, skill mellanox-fw-build
R1/R2, spec VI s.3): both deliverables carry an ini build-ID marker --
line right after ";; Mellanox Technologies LTD" (R1), text
"; mlxini cx4lx-dump-<h0|h6> (<date>, <base md5>): <essence>". Budget
(R2): zlib9+DW-pad of the edited ini <= 0x30 e.size - 32; over budget ->
trim ONLY vendor ;;-comment lines (iniprep banner, ";;[PS_INFO]" dup
block, long >60-char ;;;; prose descriptions, INI_TRIM_DESC_LEN); key=value lines and
navigational ;;;; comments are never touched (filter-checked); if still
over -> STOP (no --repack-force). Round-trip: extract == edited ini.
Discrimination: mstflint -i <img> dc shows the marker as the first
content line.

Gates: base-md5 / MAIN_CODE geometry + GCA byte-compare / expected_before
+ site context (per trigger) / cave zero / boot word stock / entry block
unique / GATE ld.i witnesses / r17 liveness + r5..r11 write-first after
site / dead string (loaders + raw word, on THIS base) / per-word decode /
budget <= 24 / round-trip clcrc / changed-line set / verify --deep / step
diff vs base stray=NONE / device-sections (guides skip) / ini build-ID
(marker+budget+trim filter-check+round-trip+0x30 in place+final deep
verify) / final identity words + md5 / diffs vs base stray=NONE (hook
words+clcrc+ITOC CRC+0x30+0x30 entry CRC) / mstflint verify bootable /
mstflint q identity / mstflint dc first content line == marker."""
import argparse
import hashlib
import struct
import subprocess
import sys
import zlib
from pathlib import Path
import re

REPO = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + '/scripts/irisc')
import mlxfwutil
import irisc_dis

THEIR_RI_MD5 = 'dacbcf0e1cbc1bed3d5e916520fe6803'
GCA_REF = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
INJ_RAW = 0x1756d0
INJ_STOCK = 0x94000003
ENTRY_DC = 0x7edc
ENTRY_BLOCK = [0x94fff51b, 0x703f07fa, 0x94000003, 0x95000000, 0x95000000]
CAVE_DC = 0x31cba0
CAVE_END_DC = 0x31cc00
CAVE_WORDS = 24
EMIT_ADDR = {1: 0x603c, 2: 0x6064, 3: 0x6090, 4: 0x6008, 7: 0x63bc}
EMIT_PARAMS = {1: 1, 2: 2, 3: 3, 4: 4, 7: 7}
LD_I_ZONE = 0x2000
GATE_LD_I = [(0x5fac, 'ld.i r6,0x2'), (0x5fc0, 'ld.i r4,0x3')]
TRIGGERS = {
    'H0': dict(hook_dc=0xd3850, hook_before=0x94fcca05, stock_emit=0x6064, stock_emit_n=2,
               fn_start=0xd3804, name='register handler 0xd3804 (H0, live-proven)',
               site_ctx=[(0xd382c, '24040400'), (0xd3830, '00050001'), (0xd3834, '94fcc9d7'),
                         (0xd3840, '0004a88c'), (0xd3844, '088400ae'),
                         (0xd3848, 'fec5b008'), (0xd384c, 'fee6b808')]),
    'H6': dict(hook_dc=0x1b9da4, hook_before=0x94f93099, stock_emit=0x6008, stock_emit_n=4,
               fn_start=0x1b9d50, name='init_ib_an_fsm trace site (H6, class 0x40 L1)',
               site_ctx=[(0x1b9d74, '00040040'), (0x1b9d78, '00050001'), (0x1b9d7c, '94f93085'),
                         (0x1b9d88, '66a60006'), (0x1b9d8c, '66a50002'), (0x1b9d90, '66c8005e'),
                         (0x1b9d94, '0004cc56'), (0x1b9d98, '088400af'),
                         (0x1b9d9c, '2d0700ff'), (0x1b9da0, 'c9080105')]),
}

BUILD_ID_DATE = '2026-10-11'
BUILD_ID_ESSENCE = {
    'H0': 'H0 dump hook @0xd3850 + emit7, var1=self-check mask, var2-5 bitset 0x0D600C.., '
          'var6 gate 0xE2B4, var7 gate 0xD5DC (cx4lx-detour-d2)',
    'H6': 'H6 dump hook @0x1b9da4 (AN-FSM, live-unvalidated, fallback h0) + emit7, '
          'var1=self-check mask, var2-5 bitset 0x0D600C.., var6 gate 0xE2B4, var7 gate 0xD5DC (cx4lx-detour-d2)',
}
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
    p = argparse.ArgumentParser(description='build CX-4 Lx D2 dump images (consumer ri base)')
    p.add_argument('--base', default=REPO + '/build/c1-00-ri.bin',
                   help='consumer stock ri (scp from their card)')
    p.add_argument('--base-md5', default=THEIR_RI_MD5,
                   help='expected base md5 (their known-good stock ri); "none" to skip')
    p.add_argument('--gca-ref', default=GCA_REF, help='GCA stock for MAIN_CODE byte-compare')
    p.add_argument('--trigger', default='H0', choices=sorted(TRIGGERS))
    p.add_argument('--guides', default='skip', choices=('skip', 'run'),
                   help='skip: base ri already carries DEV_INFO/MFG_INFO (gated); run: rewrite guid/mac')
    p.add_argument('--guid', default='0x' + mlxfwutil.hw('CARD_CX4LX_XCAT', 'guid'), help='guid for --guides run')
    p.add_argument('--mac', default='0x' + mlxfwutil.hw('CARD_CX4LX_XCAT', 'mac'), help='mac for --guides run')
    p.add_argument('--expect-guid', default='0x' + mlxfwutil.hw('CARD_CX4LX_XCAT', 'guid'), help='expected guid in base device sections')
    p.add_argument('--expect-mac', default='0x' + mlxfwutil.hw('CARD_CX4LX_XCAT', 'mac'), help='expected mac in base device sections')
    p.add_argument('--addrs', default='0x8,0x0D600C,0x0D6010,0x0D6014,0x0D6018,0xE2B4,0xD5DC',
                   help='comma-separated word addresses (order = param order r5..)')
    p.add_argument('--string-rt', default='0x00aeb83b',
                   help='dead db0 string rt (default: 7-token "%%x, var1=0x%%x, ... var6" dump string)')
    p.add_argument('--emit', type=int, default=7, choices=sorted(EMIT_ADDR))
    p.add_argument('--link-reg', type=int, default=17)
    p.add_argument('--build-id-text', default=None,
                   help='override the ini build-ID line (default: mlxini cx4lx-dump-<trig> (date, base md5): <essence>)')
    p.add_argument('--build-id-date', default=BUILD_ID_DATE,
                   help='date inside the default build-ID line (pin for reproducible md5)')
    p.add_argument('--out', default=None, help='default: build/cx4lx-dump-d2-<trigger>.bin')
    p.add_argument('--extra-patch', action='append', default=[],
                   metavar='DC:BEFORE:AFTER[:WANT_DIS]',
                   help='repeatable extra MAIN_CODE word patch (pre-gated on BEFORE, '
                        'AFTER decode-verified against WANT_DIS when given)')
    args = p.parse_args()
    if args.out is None:
        args.out = REPO + '/build/cx4lx-dump-d2-%s.bin' % args.trigger.lower()
    return args


args = parse_args()
lines_out = []
def say(msg=''):
    print(msg)
    lines_out.append(msg)


TR = TRIGGERS[args.trigger]
HOOK_DC = TR['hook_dc']
HOOK_BEFORE = TR['hook_before']
STOCK_EMIT = TR['stock_emit']
FN_START_DC = TR['fn_start']
addrs = [int(a, 0) for a in args.addrs.split(',') if a.strip()]
string_rt = int(args.string_rt, 0)
emit_addr = EMIT_ADDR[args.emit]
nparams = EMIT_PARAMS[args.emit]
if not addrs:
    die('empty --addrs')
if len(addrs) > nparams:
    die('%d addrs exceed emit%d param slots (%d)' % (len(addrs), args.emit, nparams))
if not (5 <= args.link_reg <= 23):
    die('bad link reg %d' % args.link_reg)

EXTRA = []
for spec in args.extra_patch:
    parts = spec.split(':')
    if len(parts) not in (3, 4):
        die('bad --extra-patch %r (want dc:before:after[:want_dis])' % spec)
    try:
        edc, ebefore, eafter = (int(parts[0], 16), int(parts[1], 16), int(parts[2], 16))
    except ValueError:
        die('bad --extra-patch %r (hex fields)' % spec)
    ewant = parts[3] if len(parts) == 4 else None
    if not (0 <= edc < (SEC_SIZE // 68) * 64):
        die('--extra-patch dc 0x%x outside MAIN_CODE code range' % edc)
    if edc % 4 or (edc % 64) + 4 > 64:
        die('--extra-patch dc 0x%x not 4-aligned or crosses clcrc line' % edc)
    if edc == TRIGGERS[args.trigger]['hook_dc'] or CAVE_DC <= edc < CAVE_END_DC:
        die('--extra-patch dc 0x%x collides with hook site or cave' % edc)
    EXTRA.append((edc, ebefore, eafter, ewant))

buf = open(args.base, 'rb').read()
md5_base = hashlib.md5(buf).hexdigest()
say('[1] trigger=%s (%s)' % (args.trigger, TR['name']))
say('    base=%s md5=%s size=%d' % (args.base.split('/')[-1], md5_base, len(buf)))
if args.base_md5 != 'none':
    if md5_base != args.base_md5:
        die('base md5 mismatch: %s != %s' % (md5_base, args.base_md5))
else:
    say('    base-md5 gate SKIPPED (--base-md5 none): structural gates below must carry the verification')

build_id = args.build_id_text or '; mlxini cx4lx-dump-%s (%s, %s): %s' % (
    args.trigger.lower(), args.build_id_date, md5_base, BUILD_ID_ESSENCE[args.trigger])
if '\n' in build_id or not build_id.startswith('; '):
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

try:
    gbuf = open(args.gca_ref, 'rb').read()
    gimg = mlxfwutil.Image(gbuf, args.gca_ref)
    ge = gimg.find_entry('ITOC', 0x03)
    gcode = decrc(gimg.section_data(ge))
    if gcode == code:
        say('    MAIN_CODE ACA<->GCA verdict: BYTE-IDENTICAL (%d B) - hook/cave/string offsets carry over 1:1' % len(code))
    else:
        dl = sorted({i // 64 for i in range(min(len(code), len(gcode))) if code[i] != gcode[i]})
        first = [hex(d) for d in (i for i in range(min(len(code), len(gcode))) if code[i] != gcode[i])]
        say('    MAIN_CODE ACA<->GCA verdict: DIFFERS (%d lines): %s%s' % (
            len(dl), first[:8], '...' if len(first) > 8 else ''))
        say('    continuing: structural gates (expected_before/cave/site context) decide on THIS base')
except FileNotFoundError:
    say('    GCA ref not found (%s) - byte-compare skipped' % args.gca_ref)

HOOK_RAW = dc_to_raw(HOOK_DC)
if w32be(buf, HOOK_RAW) != HOOK_BEFORE:
    die('hook site word raw 0x%x = %08x != %08x (MAIN_CODE differs from stock?)' % (
        HOOK_RAW, w32be(buf, HOOK_RAW), HOOK_BEFORE))
for off, want in TR['site_ctx']:
    if '%08x' % w32be(buf, dc_to_raw(off)) != want:
        die('hook site context word dc 0x%x mismatch (site neighborhood not stock)' % off)
if not all(w32be(code, CAVE_DC + 4*i) == 0 for i in range(CAVE_WORDS)):
    die('cave dc 0x%x..0x%x not all-zero' % (CAVE_DC, CAVE_END_DC))
if w32be(buf, INJ_RAW) != INJ_STOCK:
    die('entry injection word raw 0x%x = %08x != %08x (base must have STOCK boot path)' % (
        INJ_RAW, w32be(buf, INJ_RAW), INJ_STOCK))
for edc, ebefore, eafter, ewant in EXTRA:
    if w32be(buf, dc_to_raw(edc)) != ebefore:
        die('extra-patch pre-patch word dc 0x%x = %08x != %08x (base not as expected)' % (
            edc, w32be(buf, dc_to_raw(edc)), ebefore))
extra_say = ('; extra: ' + ' '.join('dc 0x%x=%08x' % (edc, ebefore) for edc, ebefore, _, _ in EXTRA)) if EXTRA else ''
say('[3] expected_before OK: hook 0x%x=%08x + %d ctx words; cave %d words zero; boot word STOCK (no boot block)%s' % (
    HOOK_DC, HOOK_BEFORE, len(TR['site_ctx']), CAVE_WORDS, extra_say))


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
say('[4] entry block intact+unique; GATE ld.i witnesses OK (mask=w2 reader form)')

RW = re.compile(r'\b(r\d+)\b')
WR_OPS = ('addi', 'addi.hi', 'set2', 'set3', 'or', 'subs', 'subsi', 'ands', 'and',
          'shr', 'shl', 'mask32', 'alu', 'add', 'xor')
fn_end = None
for dc in range(HOOK_DC + 4, HOOK_DC + 0x400, 4):
    d = irisc_dis.dis(dc_word(dc), dc)
    if d.startswith('ret'):
        fn_end = dc
        break
    if re.search(r'\br%d\b' % args.link_reg, d):
        die('link reg r%d read at dc 0x%x ("%s") inside hooked function tail' % (args.link_reg, dc, d))
if fn_end is None:
    die('function end not found after hook site')
say('[5] link reg r%d: 0 mentions in tail (site..ret 0x%x) - safe' % (args.link_reg, fn_end))

PARAM_REGS = list(range(5, 5 + nparams))
init = set()
for dc in range(HOOK_DC + 4, fn_end, 4):
    d = irisc_dis.dis(dc_word(dc), dc)
    tok = d.split()[0]
    rs = [int(x[1:]) for x in RW.findall(d)]
    if tok.startswith('call'):
        init |= set(PARAM_REGS)
        continue
    for r in PARAM_REGS:
        if r in rs:
            writes_it = rs and rs[0] == r and (tok in WR_OPS or tok.startswith('ld.') or tok.startswith('lw.'))
            if not writes_it and r not in init:
                die('param reg r%d read-before-write at dc 0x%x ("%s") after site' % (r, dc, d))
            init.add(r)
say('[6] param regs %s: write-first (or call-clobbered) throughout tail - stub clobber safe' % (
    ['r%d' % r for r in PARAM_REGS]))

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
emit_word(enc_call(CAVE_DC + 4, STOCK_EMIT), 'call 0x%x' % STOCK_EMIT)
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
        emit_word(enc_ld_d(rd, 3, off), 'ld.d r%d,r3,%s0x%x' % (rd, '-' if off < 0 else '', abs(off)))
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
say('[7] stub %d/%d cave words (stock emit%d first, our emit%d, %d addrs, link r%d):' % (
    len(stub_dc_words), CAVE_WORDS, TR['stock_emit_n'], args.emit, len(addrs), args.link_reg))
for dc, w, d in stub_dc_words:
    say('    dc 0x%x %08x = %s' % (dc, w, d))
if len(stub_dc_words) > CAVE_WORDS:
    die('stub exceeds cave budget')

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
            if composed == string_rt:
                loaders += 1
        prev = None
if loaders:
    die('string rt 0x%x has %d stock loaders - not dead' % (string_rt, loaders))
if struct.pack('>I', string_rt) in code:
    die('string rt 0x%x appears as raw data word - not dead' % string_rt)
str_end = code.find(b'\0', string_rt - 0x800000)
say('[8] string rt 0x%08x dead on THIS base (0 loaders, 0 raw words): %r' % (
    string_rt, code[string_rt - 0x800000:str_end][:80]))

rt_data = clcrc(code)
if rt_data != raw:
    die('round-trip de-clcrc/re-clcrc failed')
say('[9] round-trip: OK (%d lines)' % (len(code)//64))

HOOK_AFTER = enc_call(HOOK_DC, CAVE_DC)
d = irisc_dis.dis(HOOK_AFTER, HOOK_DC)
if d != 'call 0x%x' % CAVE_DC:
    die('hook patch decode "%s"' % d)
for edc, ebefore, eafter, ewant in EXTRA:
    d = irisc_dis.dis(eafter, edc)
    if ewant is not None and d != ewant:
        die('extra-patch dc 0x%x %08x decodes "%s" != "%s"' % (edc, eafter, d, ewant))
    elif ewant is None and d.startswith('unknown'):
        die('extra-patch dc 0x%x %08x does not decode ("%s")' % (edc, eafter, d))
patched_dcs = [HOOK_DC] + [dc for dc, _, _ in stub_dc_words] + [edc for edc, _, _, _ in EXTRA]
changed_lines = sorted({dc // 64 for dc in patched_dcs})
say('[10] hook %08x -> %08x ("%s"); changed lines %s' % (HOOK_BEFORE, HOOK_AFTER, d, changed_lines))

pcode = bytearray(code)
struct.pack_into('>I', pcode, HOOK_DC, HOOK_AFTER)
for dc, w, _ in stub_dc_words:
    struct.pack_into('>I', pcode, dc, w)
for edc, ebefore, eafter, ewant in EXTRA:
    struct.pack_into('>I', pcode, edc, eafter)
pcode = bytes(pcode)
praw = clcrc(pcode)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != changed_lines:
    die('changed-line set drifted: %s != %s' % (diff_lines, changed_lines))
step1 = mlxfwutil.patch_sections(img, [(0x03, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
say('[11] step1 (base+hook+stub): changed lines %s only; verify(deep)=%s' % (
    changed_lines, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
if w32be(step1, HOOK_RAW) != HOOK_AFTER:
    die('step1 hook word lost')
for dc, w, _ in stub_dc_words:
    if w32be(step1, dc_to_raw(dc)) != w:
        die('step1 stub word @dc 0x%x lost' % dc)
for edc, ebefore, eafter, ewant in EXTRA:
    if w32be(step1, dc_to_raw(edc)) != eafter:
        die('step1 extra-patch word @dc 0x%x lost' % edc)
STEP1 = args.out + '.step1'
open(STEP1, 'wb').write(step1)

if args.guides == 'run':
    r = subprocess.run(['python3', 'mlxfwutil.py', 'guides', '--guid', args.guid, '--mac', args.mac,
                        '-o', args.out, STEP1], cwd=REPO, capture_output=True, text=True)
    say('[12] guides (guid=%s mac=%s): rc=%d %s%s' % (args.guid, args.mac, r.returncode, r.stdout.strip(), r.stderr.strip()))
    if r.returncode != 0:
        die('guides step failed')
else:
    found = {}
    for name, stype in (('DEV_INFO', 0xE1), ('MFG_INFO', 0xE0)):
        try:
            ent = img.find_entry('ITOC', stype)
            sd = img.section_data(ent)
            g = int.from_bytes(sd[0x28:0x30], 'big')
            m = int.from_bytes(sd[0x38:0x40], 'big')
            found[name] = (ent, g, m)
        except KeyError:
            die('device-sections gate: %s (0x%02x) missing in base ri (--guides run needed?)' % (name, stype))
    eg, em = int(args.expect_guid, 0), int(args.expect_mac, 0)
    for name, (ent, g, m) in found.items():
        if g != eg or m != em:
            die('device-sections gate: %s guid=0x%x mac=0x%x != expected (0x%x/0x%x)' % (name, g, m, eg, em))
        say('    %s @0x%x size=0x%x: guid=0x%x mac=0x%x == expected' % (name, ent.addr, ent.size, g, m))
    open(args.out, 'wb').write(step1)
    say('[12] guides SKIPPED: base ri carries DEV_INFO+MFG_INFO with the expected identity (gated above); final = step1')

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
say('[13] ini build-ID (R1/R2): "%s"' % build_id)
say('    0x30 e.size=%d budget=%d; zlib9+DWpad: no-trim=%d -> final=%d (slack %d)%s' % (
    e30.size, budget30, n_untrimmed, n_final, budget30 - n_final,
    '' if trimmed_idx else ', no trim needed'))
if trimmed_idx:
    say('    trim: %d ;;-comment lines dropped (banner/;;[PS_INFO] dup/long ;;;; >%d B): %s' % (
        len(trimmed_idx), INI_TRIM_DESC_LEN,
        ['%d (%d B)' % (i, len(ini_lines[i])) for i in trimmed_idx]))
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
say('    round-trip extract == ini-final (cmp); 0x30 in place @0x%x size 0x%x -> 0x%x; verify(deep)=PASS' % (
    e30n.addr, e30.size, e30n.size))

out = open(args.out, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
if w32be(out, HOOK_RAW) != HOOK_AFTER or w32be(out, INJ_RAW) != INJ_STOCK:
    die('final identity words lost')
for dc, w, _ in stub_dc_words:
    if w32be(out, dc_to_raw(dc)) != w:
        die('final stub word @dc 0x%x lost' % dc)
for edc, ebefore, eafter, ewant in EXTRA:
    if w32be(out, dc_to_raw(edc)) != eafter:
        die('final extra-patch word @dc 0x%x lost' % edc)
say('[14] final words OK (hook=%08x, boot=stock, %d stub words%s); md5=%s size=%d' % (
    HOOK_AFTER, len(stub_dc_words),
    ', %d extra' % len(EXTRA) if EXTRA else '', md5_out, len(out)))

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
if args.guides == 'run':
    for st in (0xE1, 0xE0):
        allowed_guides |= sec_ranges(img1, st)
allowed_ini = sec_ranges(img_fc, 0x30)


def diff_check(label, new, old, allowed):
    diffs = [i for i in range(min(len(new), len(old))) if new[i] != old[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    say('[15] %s: %d diff bytes, stray=%s' % (label, len(diffs), stray if stray else 'NONE'))
    if stray:
        die('stray diff bytes in %s: %s' % (label, stray))
    return diffs


diff_check('step1 vs base (hook+stub)', step1, buf, allowed_step1)
diff_check('final-code vs step1 (%s)' % args.guides, fc, step1, allowed_guides)
diff_check('final vs final-code (0x30 build-ID)', out, fc, allowed_ini)

r = subprocess.run(['mstflint', '-i', args.out, 'verify'], capture_output=True, text=True)
say('[16] mstflint verify: rc=%d' % r.returncode)
say('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
if r.returncode != 0:
    die('mstflint verify failed')
r = subprocess.run(['mstflint', '-i', args.out, 'q'], capture_output=True, text=True)
say('[17] mstflint q:')
ok16 = {}
for l in (r.stdout + r.stderr).splitlines():
    if any(k in l for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC')):
        say('    ' + l.strip())
        guid_s = args.guid if args.guides == 'run' else args.expect_guid
        mac_s = args.mac if args.guides == 'run' else args.expect_mac
        for k, v in (('Image type', 'FS3'), ('FW Version', '14.32.1900'),
                     ('Base GUID', guid_s[2:]), ('Base MAC', mac_s[2:])):
            if l.startswith(k):
                ok16[k] = v in l
for k, v in ok16.items():
    if not v:
        die('identity check failed: %s' % k)
if 'Image type' not in ok16 or 'FW Version' not in ok16 or 'Base GUID' not in ok16:
    die('identity lines missing in q output (PSID printed for reference only)')

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
