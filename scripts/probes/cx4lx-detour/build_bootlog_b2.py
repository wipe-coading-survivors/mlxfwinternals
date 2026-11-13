#!/usr/bin/env python3
"""cx4lx-detour B2 (phase VII): build the boot-log image for CX-4 Lx 14.32.1900.

Two boot-path hooks (B0-recommended pair, w0x2ef-fork independent -- both
fork arms converge at 0x8024 -> 0x8040):
- C1 @dc 0x7ee4 (boot-entry `call 0x7ef0' = 94000003, live-proven site):
  additive-call into the cave, v1 TAIL form -- captures fire BEFORE
  main-init, stub ends `jump 0x7ef0' so the stock link (0x7ee8) stays in
  csr0xbc and main-init returns exactly as stock (L2 live-proven 4/4;
  no new register-preservation assumptions on the boot path).
- C2 @dc 0x8040 (main-init tail `call 0x243bc8' = 9408eee2, unconditional):
  additive-call, H0 form -- save link csr0xbc -> r17 (callee-saved; main-init
  itself saves/restores r23 through the stack, docs/250-re/120-irisc/035-cx4lx-trace.md convention), call
  stock 0x243bc8 FIRST, then capture POST-init words, restore link, ret.d
  to 0x8044 (stock epilogue needs only r1: B0 S4 live-across = ['r1']).

Both stubs write the CR reserve with the L2-proven mechanism (v1 form:
set2/set3 absolute base + st.d offset stores; v1 wrote CR 0x23f0 exactly
this way at boot):
- boot words: C1 -> csr0x70 (entry snapshot; live: constant 0x00b1cba8
  bit-identical across boots, 0 on stock) @base+0x0, RAM w0x2ef (ROM
  cpu-mask, the B1 s.4 open fork question) @base+0x4;
  C2 -> csr0x70 (post-init snapshot) @base+0x8, RAM w0xc001 (init-handshake
  flag) @base+0xc. C-B2 discriminator (as-lived, report s.7.4): site
  executes pre-host-contact by construction + negative control (no
  boot stub -> reserve reads 0) + boot magics distinct from v3/badc0ffe.
- boot-ready magic @0x23e4 (last reserve word; live-verified zero on v3;
  0x23f8 from the brief/docs57 s.8 is OCCUPIED live -- 0x036c4d48 static,
  writer outside MAIN_CODE, B0 scan covered MAIN_CODE only): C1 writes
  0xffffb00d, C2 overwrites with 0xffffb002 (last writer = site order).
- marker @0x23f0 (C1 only, keeps single-writer semantics): 0xffffbadc --
  distinct from the v3 boot marker 0xbadc0001 and from badc0ffe unlock.

Register budget: C1 clobbers r5/r6 only (write-first in main-init on both
fork arms, v1-proven); C2 clobbers r5/r6 (dead after site per B0 S4) and
r17 (saved/restored). Cave budget: C1 11 + C2 12 = 23 of 24 words.

Plus the v3-lineage card config: VPI 0x11+0x2af=0x07, card GUID/MAC via
guides, and the .ini build-ID (skill mellanox-fw-build R1/R2 with trim).

Gates: base-md5 / MAIN_CODE geometry+param1 / expected_before + site
context (per site) + cave zero / entry block unique / per-word decode /
liveness structure asserts / budget (cave <= 24 words, captures per site
<= 35//2, slots in-range non-overlapping) / round-trip clcrc / changed-line
set == {507, 513, 50990, 50991} / verify --deep per step / step diffs vs
base stray=NONE (hook words+clcrc+ITOC CRC, VPI, guides, 0x30) / mstflint
verify bootable / mstflint q identity / mstflint dc build-ID first content
line. Determinism: run twice with different --out, cmp (external gate)."""
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

GCA_REF = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
CAVE_DC = 0x31cba0
CAVE_END_DC = 0x31cc00
CAVE_WORDS = 24
ENTRY_DC = 0x7edc
ENTRY_BLOCK = [0x94fff51b, 0x703f07fa, 0x94000003, 0x95000000, 0x95000000]
MAIN_INIT_HEAD = [(0x7ef0, '480300bc'), (0x7ef4, '6c201806')]
V1_MD5 = 'e91cac9ccf9bdf6e3729a215f641fc48'

SITES = {
    'C1': dict(hook_dc=0x7ee4, hook_before=0x94000003, stock_tgt=0x7ef0, form='tail',
               name='boot-entry call main-init (B0 C1, live-proven v1)',
               ctx=MAIN_INIT_HEAD),
    'C2': dict(hook_dc=0x8040, hook_before=0x9408eee2, stock_tgt=0x243bc8, form='h0',
               name='main-init tail call 0x243bc8 (B0 C2, unconditional both forks)',
               ctx=[(0x8034, '94ffdff3'), (0x8038, '14840000'), (0x803c, 'a000fffa'),
                    (0x8044, '00040000'), (0x8048, '6437000e'), (0x804c, '00210010'),
                    (0x8050, '64230006'), (0x8054, 'fd001825')]),
}
RESERVE_BASE = 0x2314
RESERVE_WORDS = 53  # word-index 0x8c5..0x8f9 inclusive (B0 R1 range); "35" in docs is 0x35 hex
RESERVE_PER_SITE_CAP = 17  # brief budget: N <= 35/2 per site (decimal, conservative)
BOOT_READY_CR = 0x23e4
MARKER_CR = 0x23f0
V3_MARKER = 0xbadc0001
UNLOCK_WORD = 0xbadc0ffe
VPI_OFF = 0x172af
VPI_VAL = 0x07
GUID = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'guid')
MAC = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'mac')
BUILD_ID_DATE = '2026-10-11'
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


def addi_value(imm16):
    v = s16(imm16) & 0xffffffff
    return v


def enc_call(pc, tgt):
    return (0x25 << 26) | (((tgt - pc) // 4) & 0xffffff)


def enc_jump(pc, tgt):
    return (0x25 << 26) | (1 << 24) | (((tgt - pc) // 4) & 0xffffff)


def enc_addi(rd, rs, imm):
    return (0x00 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def enc_set2(rd, imm):
    return (0x09 << 26) | (rd << 16) | (imm & 0xffff)


def enc_set3(rd, rs, imm):
    return (0x08 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def enc_ld_i(rd, idx):
    return (0x12 << 26) | (1 << 25) | (rd << 16) | (idx & 0xffff)


def enc_csr_r(rd, csr):
    return (0x12 << 26) | (rd << 16) | (csr & 0x7ff)


def enc_csr_w(rs, rt, csr):
    return (0x13 << 26) | (rs << 21) | (rt << 11) | (csr & 0x7ff)


def enc_st_d(src, base, off):
    assert off % 4 == 0 and 0 <= off <= 0x3fc
    return (0x1b << 26) | (base << 21) | ((src & 0x1f) << 11) | (((off >> 2) & 0xff) << 2) | 2


RET_D = 0xFC00002D


def parse_captures(spec):
    out = []
    if not spec:
        return out
    for tok in spec.split(','):
        parts = tok.strip().split(':')
        if len(parts) != 3:
            die('capture token %r must be kind:src:offset (kind csr|ram)' % tok)
        kind, src, off = parts[0].strip(), int(parts[1], 0), int(parts[2], 0)
        if kind not in ('csr', 'ram'):
            die('capture kind %r not in {csr, ram}' % kind)
        if off % 4:
            die('capture offset 0x%x not 4-aligned' % off)
        out.append((kind, src, off))
    return out


def parse_args():
    p = argparse.ArgumentParser(description='build CX-4 Lx B2 boot-log image (phase VII C-B2)')
    p.add_argument('--base', default=GCA_REF, help='stock GCA-1900 refs base')
    p.add_argument('--base-md5', default=BASE_MD5)
    p.add_argument('--sites', default='C1,C2', help='subset of ' + '/'.join(sorted(SITES)))
    p.add_argument('--reserve-base', type=lambda x: int(x, 0), default=RESERVE_BASE)
    p.add_argument('--boot-ready-cr', type=lambda x: int(x, 0), default=BOOT_READY_CR)
    p.add_argument('--marker-cr', type=lambda x: int(x, 0), default=MARKER_CR)
    p.add_argument('--magic-c1', type=lambda x: int(x, 0), default=0xb00d,
                   help='addi imm16 for the C1 boot-ready value (0xffff<imm>)')
    p.add_argument('--magic-c2', type=lambda x: int(x, 0), default=0xb002)
    p.add_argument('--marker-val', type=lambda x: int(x, 0), default=0xbadc,
                   help='addi imm16 for the 0x23f0 marker value (written by C1)')
    p.add_argument('--captures-c1', default='csr:0x70:0x0,ram:0x2ef:0x4',
                   help='kind:src:offset list; kind=csr -> csr.r, kind=ram -> ld.i word index')
    p.add_argument('--captures-c2', default='csr:0x70:0x8,ram:0xc001:0xc')
    p.add_argument('--guid', default=GUID)
    p.add_argument('--mac', default=MAC)
    p.add_argument('--no-vpi', action='store_true', help='skip the VPI 0x07 byte (v3-lineage keeps it)')
    p.add_argument('--build-id-text', default=None)
    p.add_argument('--build-id-date', default=BUILD_ID_DATE)
    p.add_argument('--out', default=None, help='default: build/cx4lx-bootlog-b2.bin')
    args = p.parse_args()
    if args.out is None:
        args.out = REPO + '/build/cx4lx-bootlog-b2.bin'
    args.sites_list = [s.strip() for s in args.sites.split(',') if s.strip()]
    for s in args.sites_list:
        if s not in SITES:
            die('unknown site %r (known: %s)' % (s, sorted(SITES)))
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
say('[2] MAIN_CODE: type=0x%02x index=%d addr=0x%x size=0x%x clcrc=%d param0=0x%x param1=0x%x' % (
    e.type, e.index, e.addr, e.size, e.clcrc, e.param0, e.param1))
if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
    die('MAIN_CODE header mismatch (not the 14.32.1900 geometry)')
if e.param1 != 0x807edc:
    die('entry vector param1 0x%x != 0x807edc (boot entry moved?)' % e.param1)
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
for i, want in enumerate(ENTRY_BLOCK):
    if dc_word(ENTRY_DC + i*4) != want:
        die('entry block word mismatch at +%d' % i)
pat = b''.join(struct.pack('>I', w) for w in ENTRY_BLOCK)
if code.count(pat) != 1:
    die('entry 5-word pattern not unique: %d hits' % code.count(pat))
say('[3] expected_before OK: %s; cave %d words zero; entry block intact+unique' % (
    '; '.join('%s @dc 0x%x=%08x + %d ctx words' % (
        n, SITES[n]['hook_dc'], SITES[n]['hook_before'], len(SITES[n]['ctx'])) for n in args.sites_list),
    CAVE_WORDS))

cap1 = parse_captures(args.captures_c1)
cap2 = parse_captures(args.captures_c2)
boot_ready_off = args.boot_ready_cr - args.reserve_base
marker_off = args.marker_cr - args.reserve_base
magic_c1_full = addi_value(args.magic_c1)
magic_c2_full = addi_value(args.magic_c2)
marker_full = addi_value(args.marker_val)
if boot_ready_off < 0 or boot_ready_off > 4*(RESERVE_WORDS - 1) or boot_ready_off % 4:
    die('boot-ready CR 0x%x outside reserve window' % args.boot_ready_cr)
if marker_off != 0xdc:
    die('marker CR must stay 0x23f0 (offset 0xdc from reserve base), got offset 0x%x' % marker_off)
if magic_c1_full == magic_c2_full:
    die('C1/C2 boot-ready magics must differ')
for v, n in ((magic_c1_full, 'C1 magic'), (magic_c2_full, 'C2 magic'), (marker_full, 'marker')):
    if v in (V3_MARKER, UNLOCK_WORD) or v == 0:
        die('%s value 0x%08x collides (v3 marker / unlock word / zero)' % (n, v))
per_site_slots = {}
all_slots = {}
for site_name, caps in (('C1', cap1), ('C2', cap2)):
    if len(caps) > RESERVE_PER_SITE_CAP:
        die('%s captures %d exceed reserve budget per site (%d)' % (site_name, len(caps), RESERVE_WORDS // 2))
    slots = []
    for kind, src, off in caps:
        if off % 4 or off < 0 or off > 4*(RESERVE_WORDS - 1):
            die('%s capture offset 0x%x outside reserve window/alignment' % (site_name, off))
        if off in (boot_ready_off,):
            die('%s capture offset 0x%x collides with boot-ready slot' % (site_name, off))
        if off in all_slots:
            die('capture slot offset 0x%x used twice (%s and %s)' % (off, all_slots[off], site_name))
        all_slots[off] = site_name
        slots.append(off)
        if kind == 'csr' and not (0 <= src <= 0x7ff):
            die('csr index 0x%x out of csr.r range' % src)
        if kind == 'ram' and not (0 <= src <= 0xffff):
            die('ram word index 0x%x out of ld.i range' % src)
    per_site_slots[site_name] = slots
say('[4] budget: reserve %d words; C1 slots %s + boot-ready 0x%x; C2 slots %s + boot-ready 0x%x; '
    'marker 0x%x (C1-only writer); magics C1=0x%08x C2=0x%08x marker=0x%08x' % (
        RESERVE_WORDS,
        [hex(o) for o in per_site_slots['C1']], boot_ready_off,
        [hex(o) for o in per_site_slots['C2']], boot_ready_off,
        marker_off, magic_c1_full, magic_c2_full, marker_full))
if 'C1' not in args.sites_list and cap1:
    die('C1 captures given but C1 not in --sites')
if 'C2' not in args.sites_list and cap2:
    die('C2 captures given but C2 not in --sites')

stub_words = {}
stub_dc0 = {}


def stub_len(site_name, caps):
    st = SITES[site_name]
    n = 2 + 2*len(caps) + 2
    if site_name == 'C1':
        n += 2
    if st['form'] == 'h0':
        n += 3
    else:
        n += 1
    return n


def emit_stub(site_name, caps, start_dc):
    st = SITES[site_name]
    words = []
    rel24_ok = abs(st['stock_tgt'] - start_dc) < 0x2000000

    def push(w, want_dis, dc):
        d = irisc_dis.dis(w, dc)
        if d != want_dis:
            die('%s stub word dc 0x%x %08x decodes %r != %r' % (site_name, dc, w, d, want_dis))
        words.append((w, d))


    base = args.reserve_base
    dc = start_dc
    if st['form'] == 'h0':
        if not rel24_ok:
            die('%s stock target out of rel24 from cave' % site_name)
        push(enc_csr_r(17, 0xbc), 'csr.r r17,csr0xbc', dc)
        dc += 4
        push(enc_call(dc, st['stock_tgt']), 'call 0x%x' % st['stock_tgt'], dc)
        dc += 4
    push(enc_set2(5, (base >> 16) & 0xffff), 'set2 r5,zero,0x%x' % ((base >> 16) & 0xffff), dc)
    dc += 4
    push(enc_set3(5, 5, base & 0xffff), 'set3 r5,r5,0x%x' % (base & 0xffff), dc)
    dc += 4
    for kind, src, off in caps:
        if kind == 'csr':
            push(enc_csr_r(6, src), 'csr.r r6,csr0x%x' % src, dc)
        else:
            push(enc_ld_i(6, src), 'ld.i r6,0x%x' % src, dc)
        dc += 4
        push(enc_st_d(6, 5, off), 'st.d r6,r5,0x%x' % off, dc)
        dc += 4
    if site_name == 'C1':
        push(enc_addi(6, 0, args.magic_c1), 'addi r6,zero,0x%x' % s16(args.magic_c1), dc)
        dc += 4
        push(enc_st_d(6, 5, boot_ready_off), 'st.d r6,r5,0x%x' % boot_ready_off, dc)
        dc += 4
        push(enc_addi(6, 0, args.marker_val), 'addi r6,zero,0x%x' % s16(args.marker_val), dc)
        dc += 4
        push(enc_st_d(6, 5, marker_off), 'st.d r6,r5,0x%x' % marker_off, dc)
        dc += 4
    else:
        push(enc_addi(6, 0, args.magic_c2), 'addi r6,zero,0x%x' % s16(args.magic_c2), dc)
        dc += 4
        push(enc_st_d(6, 5, boot_ready_off), 'st.d r6,r5,0x%x' % boot_ready_off, dc)
        dc += 4
    if st['form'] == 'tail':
        if not rel24_ok:
            die('%s stock target out of rel24 from cave' % site_name)
        push(enc_jump(dc, st['stock_tgt']), 'jump 0x%x' % st['stock_tgt'], dc)
        dc += 4
    else:
        push(enc_csr_w(17, 0, 0xbc), 'csr.w r17,zero,0xbc', dc)
        dc += 4
        push(RET_D, 'ret.d zero,zero,zero', dc)
        dc += 4
    return words


order = [n for n in ('C1', 'C2') if n in args.sites_list]
cursor = CAVE_DC
for name in order:
    stub_dc0[name] = cursor
    cursor += 4*stub_len(name, cap1 if name == 'C1' else cap2)
if cursor > CAVE_END_DC:
    die('stubs exceed cave end (0x%x > 0x%x)' % (cursor, CAVE_END_DC))
for name in order:
    stub_words[name] = emit_stub(name, cap1 if name == 'C1' else cap2, stub_dc0[name])
total_words = sum(len(v) for v in stub_words.values())
live_c1 = {1, 23}
live_c2 = {1}
clob = {5, 6} | ({17} if 'C2' in args.sites_list else set())
if 'C1' in stub_words and clob & live_c1:
    die('C1 stub clobbers live-in regs of the boot entry {r1,r23}')
if 'C2' in stub_words and clob & live_c2:
    die('C2 stub clobbers live-in regs at 0x8040 {r1}')
if 'C2' in stub_words:
    tail = [d for _, d in stub_words['C2'][-2:]]
    if tail != ['csr.w r17,zero,0xbc', 'ret.d zero,zero,zero']:
        die('C2 stub must end with link-restore + ret.d (got %r)' % tail)
if 'C1' in stub_words:
    d = stub_words['C1'][-1][1]
    if d != 'jump 0x%x' % SITES['C1']['stock_tgt']:
        die('C1 stub must end with the v1 tail jump (got %r)' % d)
say('[5] stubs: %s (cave words %d/%d, slack %d); clobber set %s (C1 live-in {r1,r23}; C2 live-in {r1})' % (
    ', '.join('%s @dc 0x%x..0x%x %d words (%s form)' % (
        n, stub_dc0[n], stub_dc0[n] + 4*len(stub_words[n]), len(stub_words[n]), SITES[n]['form']) for n in order),
    total_words, CAVE_WORDS, CAVE_WORDS - total_words, sorted(clob)))
for name in order:
    for i, (w, d) in enumerate(stub_words[name]):
        say('    %s[%2d] dc 0x%x %08x = %s' % (name, i, stub_dc0[name] + 4*i, w, d))

rt = clcrc(code)
if rt != raw:
    die('round-trip de-clcrc/re-clcrc failed')
say('[6] round-trip: OK (%d lines)' % (len(code)//64))

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
say('[7] hooks: %s; changed lines %s' % (
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
say('[8] step1 (base+hooks+stubs): changed lines %s only; verify(deep)=%s' % (
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

allowed_step1 = set()
for dc in patched_dcs:
    allowed_step1 |= set(range(dc_to_raw(dc), dc_to_raw(dc) + 4))
for ln in changed_lines:
    allowed_step1 |= {ln*68+66+SEC_ADDR, ln*68+67+SEC_ADDR}
ent_off = 0x2000 + 32 + e.index*32
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
    say('[9] step2 (VPI 0x%02x): rc=%d %s%s' % (VPI_VAL, r.returncode, r.stdout.strip(), r.stderr.strip()))
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
say('[10] step3 (guides %s/%s): rc=%d %s%s' % (args.guid, args.mac, r.returncode, r.stdout.strip(), r.stderr.strip()))
if r.returncode != 0:
    die('guides step failed')
step3 = open(STEP3, 'rb').read()
prev_buf = open(next_in, 'rb').read()
allowed_guides = set()
for stt in (0xE1, 0xE0):
    rng, _ = sec_ranges(img1, stt)
    allowed_guides |= rng
diff_check('step3 vs step2 (guides)', step3, prev_buf, allowed_guides)

build_id = args.build_id_text or '; mlxini cx4lx-bootlog-b2 (%s, %s): boot stubs C1@0x7ee4+C2@0x8040 -> CR 0x2314.. boot words, boot-ready 0x23e4, marker 0x23f0 (phase VII C-B2)' % (
    args.build_id_date, md5_base)
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
say('[11] ini build-ID (R1/R2): "%s"' % build_id)
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
say('[12] final words OK (%s, %d stub words, vpi=%02x); md5=%s size=%d' % (
    ', '.join('%s=%08x' % (n, hook_after[n]) for n in order),
    total_words, out[VPI_OFF], md5_out, len(out)))

r = subprocess.run(['mstflint', '-i', args.out, 'verify'], capture_output=True, text=True)
say('[13] mstflint verify: rc=%d' % r.returncode)
say('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
if r.returncode != 0:
    die('mstflint verify failed')
r = subprocess.run(['mstflint', '-i', args.out, 'q'], capture_output=True, text=True)
say('[14] mstflint q:')
ok14 = {}
for l in (r.stdout + r.stderr).splitlines():
    if any(k in l for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC')):
        say('    ' + l.strip())
        for k, v in (('Image type', 'FS3'), ('FW Version', '14.32.1900'), ('PSID', 'MT_2430110032'),
                     ('Base GUID', args.guid[2:]), ('Base MAC', args.mac[2:])):
            if l.startswith(k):
                ok14[k] = v in l
for k, v in ok14.items():
    if not v:
        die('identity check failed: %s' % k)
if set(ok14) != {'Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC'}:
    die('identity lines missing in q output')

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
say('[15] mstflint dc: build-ID is the first content line (line %d of dc):' % (mi + 1))
say('    ' + dl[mi])

LOG = args.out.replace('.bin', '-build.log')
open(LOG, 'w').write('\n'.join(lines_out) + '\n')
say('DONE %s md5=%s log=%s' % (args.out, md5_out, LOG))
