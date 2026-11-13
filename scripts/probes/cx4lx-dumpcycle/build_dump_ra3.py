#!/usr/bin/env python3
"""cx4lx-dumpcycle R-A3 (phase IX): build the dump-cycle image for
CX-4 Lx 14.32.1900 (fresh stock GCA-1900 base, md5-gated).

Channel C (canonical, R-A1 s.1.1 + the two R-A2 deviations): H0 hook
@dc 0xd3850 (stock `call 0x6064' = 94fcca05, the register-handler emit2
site, live-proven D1) -> cave stub 0x31cba0, 20 of 24 words:

  csr.r r17,csr0xbc          link save (r17 dead in the site tail, R-A1 G1)
  call 0x6064                stock emit2 FIRST (v3/D1 form)
  ld.i r6,0x8c5              magic word from the CR reserve (R-A2 dev. (a):
                             inline 0x805 seeds are cleared by reg traffic)
  set2 r7,zero,0x4455        MAGIC 0x44554D31 ('DUM1'; R-A1 0x444d5031 was
  set3 r7,r7,0x4d31          the placeholder - Review Focus 5)
  cmp38_eq32 r7,r6           filter, sel=eq32 (funct5=2); --cmp op36 = same
                             form with opcode 0x36 (RE-fallback branch)
  b.f.0xa zero,<out>         miss -> clean exit
  ld.i r3,0x8c6              dump address word from the reserve (dev. (a))
  ld.d r5..r10,r3,0x0..0x14  6 words from the seeded address
  addi/addi.hi r4            marker string rt 0x00aeb83b (7x%x, DEAD)
  or r11,r3,r3               param 7 = address echo
  call 0x63bc                emit7 (r5..r11)
  csr.w r17,zero,0xbc        link restore
  ret.d

Channel B (--chan b, R-A1 s.1.3 SPLIT + the two deviations, Task 4): hook
-> `call 0x31cb70' (fragment entry, 9 w: link save, stock emit2, magic
filter with b.f -> the cave-tail csr.w clean exit, seed loads, ld.d r5)
+ bridge `jump 0x31cba0' as the LAST fragment word; cave tail 16 w:
ld.d r7..r11, set-pair response base CR 0x2320 (deviation (b): the R-A1
0x2314 base would overwrite the request; READY lands on the clean word
w0x8c8), st.d r6(READY = magic echo)/r5/r7..r11 to 0x2320+0..0x18,
link restore, ret.d. 26/34 words (fragment 10 + cave 24, slack 8).

Channel G (--chan g, R-A4b generic exec: R-A1 s.2 copy-loop + the addendum
deviations (a)-(d)): hook -> `call 0x31cba0' (cave entry), the stub seeds
from the CR reserve, filters on MAGIC, then copies N payload words
(reserve payload zone, src-pair 0x0/0x231c) into the ZERO fragment
rt 0xb1cb70 (dst-pair 0xb1/0xcb70, runtime buffer - NOT written in the
image) and jumps there (exec-from-cave live). --copydone on (default,
deviation (d), 23/24 w): COPY-DONE marker `st.d r6,zero,0x2320' @0x31cbec
(r6 = last copied word -> w0x8c8; base-zero st.d not live on cx4lx, R-A1
s.5.4 - runtime-verified by payload P4), exec-jump @0x31cbf0, csr.w
@0x31cbf4, ret.d @0x31cbf8; b.f-miss + payload tail -> 0x31cbf4.
--copydone off: R-A1 s.2 verbatim 22/24 w layout (exec-jump @0x31cbec,
tail 0x31cbf0/0x31cbf4, b.f-miss + payload tail -> 0x31cbf0; fallback
variant, the --cmp precedent). Payload words/listings: ra4b_payloads.py.

Plus the T2-lineage card config: VPI 0x11+0x2af=0x07 (stock 0x0a),
lcl[0] 0x12+0x30b=0xfb (stock 0x3b; 56G+100G bits 6+7, owner directive
T2c(d)), card GUID/MAC via guides, and the .ini build-ID (skill
mellanox-fw-build R1/R2 with trim).

Per-word decode-verify: the stub is assembled TWICE with irisc_asm
(cx4lx profile): strict with raw `op0xNN' forms for the cx4lx-'assumed'
ops (cmp38/cmp36/csr.w/or - R-A1 s.5.12) and sugared with
allow_assumed=True; both must be bit-exact to each other AND to the
expected word listing (R-A1 s.1.1 + deviations, hardcoded below).

Gates: base-md5 / MAIN_CODE geometry+param1 / expected_before + site
context / cave 24w zero + fragment 10w zero / boot word stock / entry
block unique / marker dead-on-this-base + %x count >= emit params (D1
s.5.2) / r17 liveness tail / strict+sugar assemble bit-exact to the
listing (both --cmp forms every run, both channels) / budget / round-trip
clcrc / changed-line set (+chan b: fragment lines outside the cave
accounted) / verify --deep per step / step diffs vs base
stray=NONE (hook+stubs+clcrc+ITOC CRC, VPI, lcl, guides, 0x30) /
expected-bytes magic-layout scan (Review Focus 5; chan b: response-base
set-pair 0x2320 + READY store) / mstflint verify
bootable / mstflint q identity + PSID invariant vs base / mstflint dc
build-ID first content line / determinism x2 (self re-exec, byte-exact).
"""
import argparse
import hashlib
import os
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
from scripts.irisc import assemble, AsmError
from scripts.irisc.profiles import load_profile

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
FRAG_DC = 0x31cb70
FRAG_WORDS = 10
HOOK_DC = 0xd3850
HOOK_BEFORE = 0x94fcca05
FN_START_DC = 0xd3804
STOCK_EMIT2 = 0x6064
EMIT7 = 0x63bc
SITE_CTX = [(0xd382c, '24040400'), (0xd3830, '00050001'), (0xd3834, '94fcc9d7'),
            (0xd3840, '0004a88c'), (0xd3844, '088400ae'),
            (0xd3848, 'fec5b008'), (0xd384c, 'fee6b808')]

MAGIC = 0x44554D31          # 'DUM1' (Task-1 LAYOUT::MAGIC, Review Focus 5)
W_MAGIC = 0x8c5             # reserve seed word: magic (CR 0x2314)
W_ADDR = 0x8c6              # reserve seed word: address / count N (CR 0x2318;
                            # == LAYOUT::W_COUNT of the Task-7 tool side)
W_PLD = 0x8c7               # first payload word (CR 0x231c; Task-7 LAYOUT::W_PLD,
                            # PLD_MAX=10 words 0x8c7..0x8d0 — Review Focus 3)
W_RESP = 0x8c8              # channel-B response base (CR 0x2320, Task 4)
RESP_BASE = W_RESP * 4      # channel-B response base, CR offset (dev. (b))
READY_ST_W = 0x6c803002     # st.d r6,r4,0x0 - READY store (R-A1 s.1.3 listing)
MARKER_RT = 0x00aeb83b      # '%x, var1=0x%x .. var6=0x%x' (7 params, DEAD)
STUB_WORDS = 20             # R-A1 s.1.1 canonical (slack 4 in the cave)
B_FRAG_WORDS = 10           # R-A1 s.1.3 split: 9-word entry + 1 bridge
B_TAIL_WORDS = 16           # R-A1 s.1.3 split: cave tail (slack 8 in 34)

CMP_WORD = {'op38': 0xe0e03002, 'op36': 0xd8e03002}
CMP_RAW_FORM = {'op38': 'op0x38 zero,r7,r6 imm=0x0002',
                'op36': 'op0x36 zero,r7,r6 imm=0x0002'}
CMP_SUGAR_FORM = {'op38': 'cmp38_eq32 r7,r6', 'op36': 'cmp36_eq32 r7,r6'}
# R-A1 s.1.1 listing with the R-A2 deviations applied: (a) ld.i seeds from
# the reserve (0x805/0x806 -> 0x8c5/0x8c6); MAGIC 0x44554D31 set-pair;
# cmp word per --cmp. Everything else bit-identical to the report listing.
EXPECTED_C = {
    'op38': [0x481100bc, 0x94f3a530, 0x4a0608c5, 0x24074455, 0x20e74d31,
             0xe0e03002, 0xa40a000c, 0x4a0308c6, 0x64650002, 0x64660006,
             0x6467000a, 0x6468000e, 0x64690012, 0x646a0016, 0x0004b83b,
             0x088400af, 0xfc6b1808, 0x94f3a5f6, 0x4e2000bc, 0xfc00002d],
    'op36': None,  # filled at import: same listing with the op36 cmp word
}
EXPECTED_C['op36'] = EXPECTED_C['op38'][:5] + [CMP_WORD['op36']] + EXPECTED_C['op38'][6:]
PLACEHOLDER_PAIR = (0x2407444d, 0x20e75031)  # R-A1 placeholder magic 0x444d5031

# R-A1 s.1.3 SPLIT listing (decode-verified words from the R-A1 helper log,
# build/cx4lx-dumpcycle-ra1.log 'B set-pair SPLIT layout') with the plan
# Global Constraints deviations applied: (a) ld.i seeds 0x805/0x806 ->
# 0x8c5/0x8c6; MAGIC set-pair 0x4455/0x4d31; cmp word per --cmp; (b) the
# response-base set3 immediate 0x2314 -> 0x2320 (do not clobber the request;
# READY lands on the clean CR word 0x2320 = w0x8c8). Everything else
# bit-identical to the R-A1 listing (same word positions: b.f -> 0x31cbd8,
# bridge jump at the LAST fragment word, tail csr.w @0x31cbd8).
B_OUT_DC = CAVE_DC + 4*14    # b.f miss-exit = tail csr.w (clean exit)
BRIDGE_W = 0x95000003        # jump 0x31cba0 from PC 0x31cb94 (frag word 9)
EXPECTED_B_FRAG = {
    'op38': [0x481100bc, 0x94f3a53c, 0x4a0608c5, 0x24074455, 0x20e74d31,
             0xe0e03002, 0xa40a0014, 0x4a0308c6, 0x64650002, 0x95000003],
    'op36': None,  # filled at import: same listing with the op36 cmp word
}
EXPECTED_B_FRAG['op36'] = EXPECTED_B_FRAG['op38'][:5] + [CMP_WORD['op36']] + EXPECTED_B_FRAG['op38'][6:]
EXPECTED_B_TAIL = [0x64670006, 0x6468000a, 0x6469000e, 0x646a0012, 0x646b0016,
                   0x24040000, 0x20842320, 0x6c803002, 0x6c802806, 0x6c80380a,
                   0x6c80400e, 0x6c804812, 0x6c805016, 0x6c80581a, 0x4e2000bc,
                   0xfc00002d]

# R-A1 s.2 copy-loop listing with the R-A4b addendum deviations applied:
# (a) ld.i seeds 0x805 -> 0x8c5 (magic), 0x807 -> 0x8c6 (count N); (b) src-pair
# 0x0/0x2020 -> 0x0/0x231c (reserve payload zone, set2=hi16/set3=lo16);
# (c) MAGIC 0x444d5031 -> 0x44554d31; (d) --copydone on inserts the COPY-DONE
# marker `st.d r6,zero,0x2320' @0x31cbec after the loop (+1 word shift:
# exec-jump @0x31cbf0, csr.w @0x31cbf4, ret.d @0x31cbf8, b.f-miss -> 0x31cbf4);
# off = the s.2 verbatim layout (b.f-miss -> 0x31cbf0). cmp word per --cmp;
# the loop body (words 12..18) is bit-identical to the s.2 report listing.
G_SRC_BASE = 0x231c             # src-pair lo16: reserve payload zone CR (w0x8c7..)
G_DST_HI, G_DST_LO = 0xb1, 0xcb70   # dst-pair: fragment rt 0xb1cb70 (buffer)
G_OUT_DC = {'on': CAVE_DC + 4*21, 'off': CAVE_DC + 4*20}  # b.f miss -> tail csr.w
G_MARKER_DC = CAVE_DC + 4*19    # COPY-DONE marker slot (on only) = 0x31cbec
G_EXEC_DC = {'on': CAVE_DC + 4*20, 'off': CAVE_DC + 4*19}  # exec-jump 0x31cb70
G_TAIL_DC = {'on': 0x31cbf4, 'off': 0x31cbf0}  # payload tail convention (GC (d))
MARKER_ST_W = 0x6c043322        # st.d r6,zero,0x2320 (base-zero, R-A1 s.5.4)
G_STUB_WORDS = {'on': 23, 'off': 22}   # cave budget: slack 1 / 2 of 24
EXPECTED_G = {
    'on': {
        'op38': [0x481100bc, 0x94f3a530, 0x4a0608c5, 0x24074455, 0x20e74d31,
                 0xe0e03002, 0xa40a000f, 0x4a0508c6, 0x24030000, 0x2063231c,
                 0x240400b1, 0x2084cb70, 0x14a50001, 0xa0000006, 0x64660002,
                 0x6c803002, 0x00630004, 0x00840004, 0x95fffffa, 0x6c043322,
                 0x95ffffe0, 0x4e2000bc, 0xfc00002d],
        'op36': None,
    },
    'off': {
        'op38': [0x481100bc, 0x94f3a530, 0x4a0608c5, 0x24074455, 0x20e74d31,
                 0xe0e03002, 0xa40a000e, 0x4a0508c6, 0x24030000, 0x2063231c,
                 0x240400b1, 0x2084cb70, 0x14a50001, 0xa0000006, 0x64660002,
                 0x6c803002, 0x00630004, 0x00840004, 0x95fffffa, 0x95ffffe1,
                 0x4e2000bc, 0xfc00002d],
        'op36': None,
    },
}
for _cd in ('on', 'off'):
    EXPECTED_G[_cd]['op36'] = (EXPECTED_G[_cd]['op38'][:5] + [CMP_WORD['op36']]
                               + EXPECTED_G[_cd]['op38'][6:])

VPI_OFF = 0x172af
VPI_VAL = 0x07
LCL0_OFF = 0x1630b
LCL0_STOCK = 0x3b
LCL0_VAL = 0xfb
LCL1_OFF = 0x16317
GUID = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'guid')
MAC = '0x' + mlxfwutil.hw('CARD_CX4LX_BCAT', 'mac')
BUILD_ID_DATE = '2026-10-16'
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
    rel = tgt - pc
    if abs(rel) >= 0x2000000:
        die('rel24 overflow: 0x%x -> 0x%x' % (pc, tgt))
    return (0x25 << 26) | ((rel // 4) & 0xffffff)


def parse_args():
    p = argparse.ArgumentParser(description='build CX-4 Lx phase IX dump-cycle image (R-A3/R-A4b)')
    p.add_argument('--chan', choices=('c', 'b', 'g'), default='c',
                   help='c = canonical cave stub (ra3c); b = B-split: fragment entry 0x31cb70 '
                        '+ bridge jump + cave tail, response base CR 0x2320 (ra3b); '
                        'g = generic-exec copy-loop cave stub, payload -> zero fragment '
                        '0x31cb70 at runtime (ra4b)')
    p.add_argument('--cmp', choices=('op38', 'op36'), default='op38',
                   help='filter cmp opcode: op38 sel=eq32 word e0e03002 (default, '
                        'cross-chip-live); op36 = same form opcode 0x36 (RE-fallback)')
    p.add_argument('--copydone', choices=('on', 'off'), default=None,
                   help='chan g only: COPY-DONE marker st.d r6,zero,0x2320 after the '
                        'copy loop (addendum dev. (d)); on (default) = 23/24 words, '
                        'tail 0x31cbf4; off = R-A1 s.2 verbatim 22/24, tail 0x31cbf0')
    p.add_argument('--base', default=GCA_REF, help='stock GCA-1900 refs base')
    p.add_argument('--base-md5', default=BASE_MD5)
    p.add_argument('--guid', default=GUID)
    p.add_argument('--mac', default=MAC)
    p.add_argument('--build-id-text', default=None)
    p.add_argument('--build-id-date', default=None,
                   help='default: 2026-10-16 (chan c/b) / 2026-10-17 (chan g)')
    p.add_argument('--out', default=None,
                   help='default: build/cx4lx-dump-ra3c.bin (--chan b: ra3b; --chan g: '
                        'ra4b, or ra4b-off when --copydone off)')
    return p.parse_args()


args = parse_args()
if args.chan != 'g' and args.copydone is not None:
    die('--copydone applies to --chan g only')
COPYDONE = args.copydone or 'on'
if args.build_id_date is None:
    args.build_id_date = '2026-10-17' if args.chan == 'g' else BUILD_ID_DATE
if args.out is None:
    args.out = REPO + '/build/cx4lx-dump-%s.bin' % (
        {'c': 'ra3c', 'b': 'ra3b'}.get(args.chan)
        or ('ra4b' if COPYDONE == 'on' else 'ra4b-off'))
args.out = str(Path(args.out).resolve())
# side-artifact suffix base: NEVER derive side paths with .replace('.bin',..)
# — a no-op for a .bin-less --out would overwrite the artifact itself.
OUT_BASE = re.sub(r'\.bin$', '', args.out)
STUB_TARGET_DC = CAVE_DC if args.chan in ('c', 'g') else FRAG_DC

lines_out = []
def say(msg=''):
    print(msg)
    lines_out.append(msg)


def stub_text(cmp_mnem, raw_forms):
    return ('csr.r r17,csr0xbc\n'
            'call 0x%x\n'
            'ld.i r6,0x%x\n'
            'set2 r7,zero,0x%x\n'
            'set3 r7,r7,0x%x\n'
            '%s\n'
            'b.f.0xa zero,0x%x\n'
            'ld.i r3,0x%x\n'
            'ld.d r5,r3,0x0\n'
            'ld.d r6,r3,0x4\n'
            'ld.d r7,r3,0x8\n'
            'ld.d r8,r3,0xc\n'
            'ld.d r9,r3,0x10\n'
            'ld.d r10,r3,0x14\n'
            'addi r4,zero,0x%x\n'
            'addi.hi r4,r4,0x%x\n'
            '%s\n'
            'call 0x%x\n'
            '%s\n'
            'ret.d zero,zero,zero\n') % (
        STOCK_EMIT2,
        W_MAGIC, (MAGIC >> 16) & 0xffff, MAGIC & 0xffff,
        cmp_mnem,
        CAVE_DC + 4*18,
        W_ADDR,
        s16(MARKER_RT & 0xffff), ((MARKER_RT >> 16) & 0xffff) + (1 if MARKER_RT & 0x8000 else 0),
        'op0x3f r11,r3,r3 imm=0x0008' if raw_forms else 'or r11,r3,r3',
        EMIT7,
        'op0x13 zero,r17,zero imm=0x00bc' if raw_forms else 'csr.w r17,zero,0xbc')


def b_frag_text(cmp_mnem, raw_forms):
    return ('csr.r r17,csr0xbc\n'
            'call 0x%x\n'
            'ld.i r6,0x%x\n'
            'set2 r7,zero,0x%x\n'
            'set3 r7,r7,0x%x\n'
            '%s\n'
            'b.f.0xa zero,0x%x\n'
            'ld.i r3,0x%x\n'
            'ld.d r5,r3,0x0\n'
            'jump 0x%x\n') % (
        STOCK_EMIT2,
        W_MAGIC, (MAGIC >> 16) & 0xffff, MAGIC & 0xffff,
        cmp_mnem,
        B_OUT_DC,
        W_ADDR,
        CAVE_DC)


def b_tail_text(raw_forms):
    return ('ld.d r7,r3,0x4\n'
            'ld.d r8,r3,0x8\n'
            'ld.d r9,r3,0xc\n'
            'ld.d r10,r3,0x10\n'
            'ld.d r11,r3,0x14\n'
            'set2 r4,zero,0x0\n'
            'set3 r4,r4,0x%x\n'
            'st.d r6,r4,0x0\n'
            'st.d r5,r4,0x4\n'
            'st.d r7,r4,0x8\n'
            'st.d r8,r4,0xc\n'
            'st.d r9,r4,0x10\n'
            'st.d r10,r4,0x14\n'
            'st.d r11,r4,0x18\n'
            '%s\n'
            'ret.d zero,zero,zero\n') % (
        RESP_BASE,
        'op0x13 zero,r17,zero imm=0x00bc' if raw_forms else 'csr.w r17,zero,0xbc')


def g_stub_text(cmp_mnem, copydone, raw_forms):
    marker = 'st.d r6,zero,0x%x\n' % (W_RESP * 4) if copydone == 'on' else ''
    return ('csr.r r17,csr0xbc\n'
            'call 0x%x\n'
            'ld.i r6,0x%x\n'
            'set2 r7,zero,0x%x\n'
            'set3 r7,r7,0x%x\n'
            '%s\n'
            'b.f.0xa zero,0x%x\n'
            'ld.i r5,0x%x\n'
            'set2 r3,zero,0x0\n'
            'set3 r3,r3,0x%x\n'
            'set2 r4,zero,0x%x\n'
            'set3 r4,r4,0x%x\n'
            'subsi r5,r5,0x1\n'
            'b.t.0x0 zero,0x%x\n'
            'ld.d r6,r3,0x0\n'
            'st.d r6,r4,0x0\n'
            'addi r3,r3,0x4\n'
            'addi r4,r4,0x4\n'
            'jump 0x%x\n'
            '%s'
            'jump 0x%x\n'
            '%s\n'
            'ret.d zero,zero,zero\n') % (
        STOCK_EMIT2,
        W_MAGIC, (MAGIC >> 16) & 0xffff, MAGIC & 0xffff,
        cmp_mnem,
        G_OUT_DC[copydone],
        W_ADDR,
        G_SRC_BASE,
        G_DST_HI, G_DST_LO,
        G_MARKER_DC,
        CAVE_DC + 4*12,
        marker,
        FRAG_DC,
        'op0x13 zero,r17,zero imm=0x00bc' if raw_forms else 'csr.w r17,zero,0xbc')


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


if w32be(buf, dc_to_raw(HOOK_DC)) != HOOK_BEFORE:
    die('hook site word raw 0x%x = %08x != %08x (MAIN_CODE not stock?)' % (
        dc_to_raw(HOOK_DC), w32be(buf, dc_to_raw(HOOK_DC)), HOOK_BEFORE))
for off, want in SITE_CTX:
    if '%08x' % dc_word(off) != want:
        die('hook site context word dc 0x%x mismatch (site neighborhood not stock)' % off)
if not all(w32be(code, CAVE_DC + 4*i) == 0 for i in range(CAVE_WORDS)):
    die('cave dc 0x%x..0x%x not all-zero' % (CAVE_DC, CAVE_END_DC))
if not all(w32be(code, FRAG_DC + 4*i) == 0 for i in range(FRAG_WORDS)):
    die('fragment dc 0x%x..0x%x not all-zero (not the R-A1 s.4 clean fragment?)' % (
        FRAG_DC, FRAG_DC + 4*FRAG_WORDS))
if w32be(buf, INJ_RAW) != INJ_STOCK:
    die('boot word raw 0x%x = %08x != %08x (base must have STOCK boot path - no old hooks!)' % (
        INJ_RAW, w32be(buf, INJ_RAW), INJ_STOCK))
for i, want in enumerate(ENTRY_BLOCK):
    if dc_word(ENTRY_DC + i*4) != want:
        die('entry block word mismatch at +%d' % i)
pat = b''.join(struct.pack('>I', w) for w in ENTRY_BLOCK)
if code.count(pat) != 1:
    die('entry 5-word pattern not unique: %d hits' % code.count(pat))
say('[3] expected_before OK: hook @dc 0x%x=%08x + %d ctx words; cave %dw zero; '
    'fragment 0x%x %dw zero; boot word raw 0x%x STOCK; entry block intact+unique' % (
    HOOK_DC, HOOK_BEFORE, len(SITE_CTX), CAVE_WORDS, FRAG_DC, FRAG_WORDS, INJ_RAW))

str_dc = MARKER_RT - 0x800000
nul = code.find(b'\x00', str_dc)
if nul < 0:
    die('marker string not NUL-terminated')
mtext = code[str_dc:nul].decode('latin1')
loaders = 0
prev = None
for i in range(len(code)//4 - 1):
    w = struct.unpack_from('>I', code, i*4)[0]
    op = w >> 26
    if op in (0x00, 0x01):
        prev = ((w >> 16) & 0x1f, s16(w & 0xffff))
    elif op in (0x02, 0x03) and prev is not None:
        prd, pimm = prev
        if prd == (w >> 16) & 0x1f and (pimm + ((w & 0xffff) << 16)) & 0xffffffff == MARKER_RT:
            loaders += 1
        prev = None
    else:
        prev = None
raw_hits = code.count(struct.pack('>I', MARKER_RT))
if loaders or raw_hits:
    die('marker rt 0x%08x not dead on THIS base (%d loaders, %d raw words)' % (
        MARKER_RT, loaders, raw_hits))
if mtext.count('%x') < 7:
    die('marker string has %d %%x < 7 emit7 params (D1 s.5.2)' % mtext.count('%x'))
say('[4] marker rt 0x%08x dead (0 loaders, 0 raw words), %d %%x >= 7 params: %r' % (
    MARKER_RT, mtext.count('%x'), mtext[:60]))

fn_end = None
r17_hits = []
for dc in range(HOOK_DC + 4, FN_START_DC + 0x400, 4):
    d = irisc_dis.dis(dc_word(dc), dc)
    if d.startswith('ret.'):
        fn_end = dc
        break
    if re.search(r'\br17\b', d):
        r17_hits.append((dc, d))
if fn_end is None:
    die('function end not found after hook site')
if r17_hits:
    die('link reg r17 live in tail 0x%x..0x%x: %s' % (HOOK_DC + 4, fn_end, r17_hits[:4]))
say('[5] r17 liveness: 0 mentions in tail dc 0x%x..0x%x (site..ret) - safe' % (HOOK_DC + 4, fn_end))

prof = load_profile('cx4lx')


def dual_assemble(label, text_raw, text_sugar, base):
    try:
        d_raw = assemble(text_raw, base=base, profile=prof, strict=True)
        d_sugar = assemble(text_sugar, base=base, profile=prof, allow_assumed=True)
    except AsmError as ex:
        die('%s assembly failed: %s' % (label, ex))
    if d_raw != d_sugar:
        die('%s: strict raw form != sugar form (must be bit-exact)' % label)
    return list(struct.unpack('>%dI' % (len(d_raw)//4), d_raw))


frag_words = []
if args.chan == 'c':
    stub_data = {}
    for variant in ('op38', 'op36'):
        words = dual_assemble('c stub (%s)' % variant,
                              stub_text(CMP_RAW_FORM[variant], True),
                              stub_text(CMP_SUGAR_FORM[variant], False), CAVE_DC)
        if words != EXPECTED_C[variant]:
            die('%s: assembled words != expected R-A1 s.1.1+deviations listing\n'
                '  got      %s\n  expected %s'
                % (variant, ['%08x' % w for w in words],
                   ['%08x' % w for w in EXPECTED_C[variant]]))
        stub_data[variant] = words
    stub_words = stub_data[args.cmp]
    if len(stub_words) != STUB_WORDS:
        die('stub is %d words, canonical is %d' % (len(stub_words), STUB_WORDS))
    cmp_dc = CAVE_DC + 4*5
elif args.chan == 'g':
    g_data = {}
    for cd in ('on', 'off'):
        for variant in ('op38', 'op36'):
            words = dual_assemble('g stub (copydone %s, %s)' % (cd, variant),
                                  g_stub_text(CMP_RAW_FORM[variant], cd, True),
                                  g_stub_text(CMP_SUGAR_FORM[variant], cd, False), CAVE_DC)
            if words != EXPECTED_G[cd][variant]:
                die('copydone %s %s: assembled words != expected R-A1 s.2+addendum-deviations'
                    ' listing\n  got      %s\n  expected %s'
                    % (cd, variant, ['%08x' % w for w in words],
                       ['%08x' % w for w in EXPECTED_G[cd][variant]]))
            g_data[(cd, variant)] = words
    stub_words = g_data[(COPYDONE, args.cmp)]
    if len(stub_words) != G_STUB_WORDS[COPYDONE]:
        die('g stub is %d words, --copydone %s expects %d (of %d cave)'
            % (len(stub_words), COPYDONE, G_STUB_WORDS[COPYDONE], CAVE_WORDS))
    cmp_dc = CAVE_DC + 4*5
    bf_w = stub_words[6]
    bf_dis = irisc_dis.dis(bf_w, CAVE_DC + 4*6)
    if bf_w != (0xa40a000f if COPYDONE == 'on' else 0xa40a000e) \
            or bf_dis != 'b.f.0xa zero,0x%x' % G_OUT_DC[COPYDONE]:
        die('b.f word %08x decode %r (want miss -> tail csr.w 0x%x)'
            % (bf_w, bf_dis, G_OUT_DC[COPYDONE]))
    exec_w = stub_words[20] if COPYDONE == 'on' else stub_words[19]
    exec_dis = irisc_dis.dis(exec_w, G_EXEC_DC[COPYDONE])
    if exec_dis != 'jump 0x%x' % FRAG_DC:
        die('exec-jump word %08x decode %r @0x%x (want jump 0x%x into the zero fragment)'
            % (exec_w, exec_dis, G_EXEC_DC[COPYDONE], FRAG_DC))
    if COPYDONE == 'on':
        mk_w = stub_words[19]
        mk_dis = irisc_dis.dis(mk_w, G_MARKER_DC)
        if mk_w != MARKER_ST_W or mk_dis != 'st.d r6,zero,0x%x' % (W_RESP * 4):
            die('COPY-DONE marker word %08x decode %r (want %08x st.d r6,zero,0x%x)'
                % (mk_w, mk_dis, MARKER_ST_W, W_RESP * 4))
    else:
        if MARKER_ST_W in stub_words:
            die('copydone off must NOT carry the marker word')
else:
    frag_data = {}
    for variant in ('op38', 'op36'):
        words = dual_assemble('b frag (%s)' % variant,
                              b_frag_text(CMP_RAW_FORM[variant], True),
                              b_frag_text(CMP_SUGAR_FORM[variant], False), FRAG_DC)
        if words != EXPECTED_B_FRAG[variant]:
            die('%s: assembled words != expected R-A1 s.1.3+deviations split listing\n'
                '  got      %s\n  expected %s'
                % (variant, ['%08x' % w for w in words],
                   ['%08x' % w for w in EXPECTED_B_FRAG[variant]]))
        frag_data[variant] = words
    stub_words = dual_assemble('b tail', b_tail_text(True), b_tail_text(False), CAVE_DC)
    if stub_words != EXPECTED_B_TAIL:
        die('b tail: assembled words != expected R-A1 s.1.3+deviations split listing\n'
            '  got      %s\n  expected %s'
            % (['%08x' % w for w in stub_words],
               ['%08x' % w for w in EXPECTED_B_TAIL]))
    frag_words = frag_data[args.cmp]
    if len(frag_words) != B_FRAG_WORDS or len(stub_words) != B_TAIL_WORDS:
        die('b split is %d+%d words, R-A1 s.1.3 is %d+%d (26/34 budget)' % (
            len(frag_words), len(stub_words), B_FRAG_WORDS, B_TAIL_WORDS))
    cmp_dc = FRAG_DC + 4*5
    bd = irisc_dis.dis(frag_words[9], FRAG_DC + 4*9)
    if frag_words[9] != BRIDGE_W or bd != 'jump 0x%x' % CAVE_DC:
        die('bridge word decode %r (%08x)' % (bd, frag_words[9]))
cmp_w = stub_words[5] if args.chan in ('c', 'g') else frag_words[5]
cmp_dis = irisc_dis.dis(cmp_w, cmp_dc)
if cmp_w != CMP_WORD[args.cmp] or not cmp_dis.startswith(
        'op0x%s zero,r7,r6 imm=' % ('38' if args.cmp == 'op38' else '36')) \
        or (cmp_w & 0x1f) != 2:
    die('cmp word %08x decode %r (want op0xNN zero,r7,r6 funct5=2 eq32)' % (cmp_w, cmp_dis))
if args.chan == 'c':
    say('[6] stub (chan c, --cmp %s): strict raw (cx4lx) == sugar (allow_assumed) == '
        'R-A1 s.1.1+deviations listing, %d words; cmp word %08x (%s, funct5=2 eq32); '
        'BOTH cmp variants gated (op38 e0e03002 / op36 d8e03002)' % (
            args.cmp, len(stub_words), cmp_w, cmp_dis))
elif args.chan == 'g':
    say('[6] g copy-loop (chan g, --cmp %s, --copydone %s): %d/%d words (slack %d); '
        'strict raw (cx4lx) == sugar (allow_assumed) == R-A1 s.2+addendum listing '
        '(BOTH cmp variants x BOTH copydone variants gated every run); '
        'cmp word %08x (%s, funct5=2 eq32); b.f -> 0x%x (tail csr.w); '
        'src-pair 0x0/0x%x (dev b), dst-pair 0x%x/0x%x -> fragment rt 0x%x; '
        'exec-jump %08x ("%s") @0x%x; payload tail -> 0x%x%s' % (
            args.cmp, COPYDONE, len(stub_words), CAVE_WORDS, CAVE_WORDS - len(stub_words),
            cmp_w, cmp_dis, G_OUT_DC[COPYDONE], G_SRC_BASE, G_DST_HI, G_DST_LO,
            (G_DST_HI << 16) | G_DST_LO, exec_w, exec_dis, G_EXEC_DC[COPYDONE],
            G_TAIL_DC[COPYDONE],
            ('; COPY-DONE marker %08x ("%s") @0x%x -> w0x%x (r6 = last copied word)'
             % (mk_w, mk_dis, G_MARKER_DC, W_RESP)) if COPYDONE == 'on'
            else '; NO marker (R-A1 s.2 verbatim)'))
else:
    say('[6] b-split (chan b, --cmp %s): fragment %dw @0x%x + cave tail %dw @0x%x = '
        '%d/%d words (slack %d); strict raw (cx4lx) == sugar (allow_assumed) == '
        'R-A1 s.1.3+deviations listing (BOTH cmp variants gated every run); '
        'cmp word %08x (%s, funct5=2 eq32); bridge word 9 %08x = %s; '
        'b.f -> 0x%x (tail csr.w clean exit); response base CR 0x%x (dev. b)' % (
            args.cmp, len(frag_words), FRAG_DC, len(stub_words), CAVE_DC,
            len(frag_words) + len(stub_words), FRAG_WORDS + CAVE_WORDS,
            FRAG_WORDS + CAVE_WORDS - len(frag_words) - len(stub_words),
            cmp_w, cmp_dis, frag_words[9], bd, B_OUT_DC, RESP_BASE))
for i, w in enumerate(frag_words):
    say('    [f%2d] dc 0x%x %08x = %s' % (i, FRAG_DC + 4*i, w, irisc_dis.dis(w, FRAG_DC + 4*i)))
for i, w in enumerate(stub_words):
    say('    [%2d] dc 0x%x %08x = %s' % (i, CAVE_DC + 4*i, w, irisc_dis.dis(w, CAVE_DC + 4*i)))

hook_after = enc_call(HOOK_DC, STUB_TARGET_DC)
hd = irisc_dis.dis(hook_after, HOOK_DC)
if hd != 'call 0x%x' % STUB_TARGET_DC:
    die('hook patch decode %r' % hd)
say('[7] hook: %08x -> %08x ("%s")' % (HOOK_BEFORE, hook_after, hd))

rt_data = clcrc(code)
if rt_data != raw:
    die('round-trip de-clcrc/re-clcrc failed')
say('[8] round-trip: OK (%d lines)' % (len(code)//64))

patched_dcs = [HOOK_DC] + [CAVE_DC + 4*i for i in range(len(stub_words))]
if args.chan == 'b':
    patched_dcs += [FRAG_DC + 4*i for i in range(len(frag_words))]
changed_lines = sorted({dc // 64 for dc in patched_dcs})
expected_lines = sorted({HOOK_DC // 64, CAVE_DC // 64, (CAVE_DC + 4*(len(stub_words)-1)) // 64}
                        | ({FRAG_DC // 64} if args.chan == 'b' else set()))
say('[9] patched dcs -> clcrc lines %s (expected set %s)' % (changed_lines, expected_lines))

pcode = bytearray(code)
struct.pack_into('>I', pcode, HOOK_DC, hook_after)
for i, w in enumerate(stub_words):
    struct.pack_into('>I', pcode, CAVE_DC + 4*i, w)
for i, w in enumerate(frag_words):
    struct.pack_into('>I', pcode, FRAG_DC + 4*i, w)
pcode = bytes(pcode)
praw = clcrc(pcode)
diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
if diff_lines != changed_lines:
    die('changed-line set drifted: %s != %s' % (diff_lines, changed_lines))
if changed_lines != expected_lines:
    die('changed-line set != expected: %s != %s' % (changed_lines, expected_lines))
if args.chan == 'b':
    cave_lns = {(CAVE_DC + 4*i) // 64 for i in range(len(stub_words))}
    frag_lns = {(FRAG_DC + 4*i) // 64 for i in range(len(frag_words))}
    frag_only = sorted(frag_lns - cave_lns)
    if not set(frag_only) <= set(diff_lines):
        die('chan b: fragment words outside the cave (lines %s) not accounted '
            'in changed lines %s' % (frag_only, diff_lines))
    say('[9b] chan b: fragment lines %s, cave-tail lines %s, frag-only outside '
        'cave %s accounted in changed-lines' % (sorted(frag_lns), sorted(cave_lns), frag_only))
if args.chan == 'g':
    cave_lns_g = {(CAVE_DC + 4*i) // 64 for i in range(len(stub_words))}
    frag_lns_g = {(FRAG_DC + 4*i) // 64 for i in range(FRAG_WORDS)}
    frag_only_g = sorted(frag_lns_g - cave_lns_g)
    if set(frag_only_g) & set(diff_lines):
        die('chan g: fragment-only lines %s MUST NOT change (runtime buffer stays '
            'zero in the image; shared cave lines OK)' % frag_only_g)
    if any(w32be(pcode, FRAG_DC + 4*i) != 0 for i in range(FRAG_WORDS)):
        die('chan g: fragment words not all-zero in patched code (buffer!)')
    say('[9b] chan g: fragment 0x%x..0x%x stays ZERO in the image (%d words, runtime '
        'copy buffer; fragment lines %s, of which fragment-only %s NOT in changed-lines; '
        'line 50990 shared with cave head is legit)' % (
            FRAG_DC, FRAG_DC + 4*FRAG_WORDS, FRAG_WORDS, sorted(frag_lns_g), frag_only_g))
step1 = mlxfwutil.patch_sections(img, [(0x03, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
say('[10] step1 (base+hook+stub): changed lines %s only; verify(deep)=%s' % (
    changed_lines, 'PASS' if not errs else errs))
if errs:
    die('step1 verify failed')
if w32be(step1, dc_to_raw(HOOK_DC)) != hook_after:
    die('step1 hook word lost')
for i, w in enumerate(stub_words):
    if w32be(step1, dc_to_raw(CAVE_DC + 4*i)) != w:
        die('step1 stub word @dc 0x%x lost' % (CAVE_DC + 4*i))
for i, w in enumerate(frag_words):
    if w32be(step1, dc_to_raw(FRAG_DC + 4*i)) != w:
        die('step1 frag word @dc 0x%x lost' % (FRAG_DC + 4*i))
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


diff_check('step1 vs base (hook+stub+clcrc+ITOC CRC)', step1, buf, allowed_step1)

img1 = mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt)


def mlxfwutil_patch(label, set_spec, out_path, in_path):
    r = subprocess.run(['python3', 'mlxfwutil.py', 'patch', '--set', set_spec,
                        '-o', out_path, in_path], cwd=REPO, capture_output=True, text=True)
    if r.returncode != 0:
        die('%s patch step failed: %s%s' % (label, r.stdout.strip(), r.stderr.strip()))
    return open(out_path, 'rb').read()


STEP2 = args.out + '.step2'
if buf[VPI_OFF] != 0x0a:
    die('stock VPI byte @0x%x = %02x != 0x0a' % (VPI_OFF, buf[VPI_OFF]))
step2 = mlxfwutil_patch('VPI', '0x11+0x2af=%02x' % VPI_VAL, STEP2, STEP1)
if step2[VPI_OFF] != VPI_VAL:
    die('VPI byte not set at 0x%x' % VPI_OFF)
_, ent11 = sec_ranges(img1, 0x11)
eo11 = 0x2000 + 32 + ent11.index*32
diff_check('step2 vs step1 (VPI)', step2, step1, {VPI_OFF} | set(range(eo11+0x1a, eo11+0x20)))
say('[11] VPI: stock 0x0a -> 0x%02x @0x%x (sec 0x11+0x2af; sec/entry CRC recomputed)' % (
    VPI_VAL, VPI_OFF))

STEP2B = args.out + '.step2b'
img2 = mlxfwutil.Image(step2, 'step2', base=img.base, fmt=img.fmt)
if buf[LCL0_OFF] != LCL0_STOCK:
    die('stock lcl[0] byte @0x%x = %02x != %02x' % (LCL0_OFF, buf[LCL0_OFF], LCL0_STOCK))
if buf[LCL1_OFF] != 0x00:
    die('stock lcl[1] byte @0x%x = %02x != 0x00 (single-port assumption broken)' % (LCL1_OFF, buf[LCL1_OFF]))
step2b = mlxfwutil_patch('lcl[0]', '0x12+0x30b=%02x' % LCL0_VAL, STEP2B, STEP2)
if step2b[LCL0_OFF] != LCL0_VAL:
    die('lcl[0] byte not set at 0x%x' % LCL0_OFF)
if step2b[LCL1_OFF] != 0x00:
    die('lcl[1] byte @0x%x changed' % LCL1_OFF)
_, ent12 = sec_ranges(img2, 0x12)
eo12 = 0x2000 + 32 + ent12.index*32
diff_check('step2b vs step2 (lcl[0] 56G+100G)', step2b, step2,
           {LCL0_OFF} | set(range(eo12+0x1a, eo12+0x20)))
say('[12] lcl[0].eth_speeds_supported: 0x%02x -> 0x%02x @0x%x (bit6|56G + bit7|100G; '
    'lcl[1] @0x%x untouched 0x00)' % (LCL0_STOCK, LCL0_VAL, LCL0_OFF, LCL1_OFF))

STEP3 = args.out + '.step3'
img2b = mlxfwutil.Image(step2b, 'step2b', base=img.base, fmt=img.fmt)
r = subprocess.run(['python3', 'mlxfwutil.py', 'guides', '--guid', args.guid, '--mac', args.mac,
                    '-o', STEP3, STEP2B], cwd=REPO, capture_output=True, text=True)
if r.returncode != 0:
    die('guides step failed: %s%s' % (r.stdout.strip(), r.stderr.strip()))
step3 = open(STEP3, 'rb').read()
allowed_guides = set()
for stt in (0xE1, 0xE0):
    rng, _ = sec_ranges(img2b, stt)
    allowed_guides |= rng
diff_check('step3 vs step2b (guides)', step3, step2b, allowed_guides)
say('[13] guides: GUID %s / MAC %s (stock sections zeroed; Rule 3)' % (args.guid, args.mac))

if args.chan == 'b':
    build_id = args.build_id_text or (
        '; mlxini cx4lx-dump-ra3b (%s, %s): IX dump-cycle B-split H0@0xd3850 -> frag 0x31cb70 + cave tail, '
        'response base CR 0x2320 (READY+6w), cmp %s' % (
            args.build_id_date, md5_base, args.cmp))
elif args.chan == 'g':
    build_id = args.build_id_text or (
        '; mlxini cx4lx-dump-ra4b (%s, %s): IX generic-exec copy-loop H0@0xd3850 -> cave@0x31cba0, '
        'payload<=10w -> frag 0x31cb70, seeds 0x8c5/0x8c6, magic 0x%08x, cmp %s, copydone %s' % (
            args.build_id_date, md5_base, MAGIC, args.cmp, COPYDONE))
else:
    build_id = args.build_id_text or (
        '; mlxini cx4lx-dump-ra3c (%s, %s): IX dump-cycle C-canon H0@0xd3850 -> cave@0x31cba0 emit7, '
        'seed w0x8c5/w0x8c6 reserve, magic 0x%08x, cmp %s eq32' % (
            args.build_id_date, md5_base, MAGIC, args.cmp))
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
open(OUT_BASE + '-ini-final.ini', 'w', encoding='latin1').write(ini_final)
say('    round-trip extract == ini-final; 0x30 in place @0x%x size 0x%x -> 0x%x; verify(deep)=PASS' % (
    e30n.addr, e30.size, e30n.size))
allowed_ini, _ = sec_ranges(img_fc, 0x30)
diff_check('final vs step3 (0x30 build-ID)', out_buf, step3, allowed_ini)

# expected-bytes magic-layout scan (Review Focus 5 / addendum Review Focus 3):
# the final MAIN_CODE must carry the tool-layout constants (Task-1/Task-7
# LAYOUT: W_COUNT=0x8c6, W_PLD=0x8c7, PLD_MAX=10, MAGIC=0x44554D31) and NOT
# the R-A1 placeholder magic.
pcode_final = decrc(img_fin.section_data(img_fin.find_entry('ITOC', 0x03)))
set2_w = (0x09 << 26) | (7 << 16) | ((MAGIC >> 16) & 0xffff)
set3_w = (0x08 << 26) | (7 << 21) | (7 << 16) | (MAGIC & 0xffff)
ldi_magic_w = (0x12 << 26) | (1 << 25) | (6 << 16) | W_MAGIC
cnt_reg = 5 if args.chan == 'g' else 3
ldi_count_w = (0x12 << 26) | (1 << 25) | (cnt_reg << 16) | W_ADDR
pair_at = pcode_final.find(struct.pack('>II', set2_w, set3_w))
magic_pair_dc = FRAG_DC + 4*3 if args.chan == 'b' else CAVE_DC + 4*3
if pair_at != magic_pair_dc:
    die('magic set2/set3 pair 0x%04x/0x%04x not adjacent @dc 0x%x (found %s)' % (
        (MAGIC >> 16) & 0xffff, MAGIC & 0xffff, magic_pair_dc,
        hex(pair_at) if pair_at >= 0 else 'NOWHERE'))
if pcode_final.count(struct.pack('>I', ldi_magic_w)) < 1 or \
        pcode_final.count(struct.pack('>I', ldi_count_w)) < 1:
    die('ld.i seed words 0x%x/0x%x not found in stub words' % (W_MAGIC, W_ADDR))
if struct.pack('>II', *PLACEHOLDER_PAIR) in pcode_final:
    die('R-A1 placeholder magic pair 0x444d/0x5031 still present (Review Focus 5)')
if ((struct.unpack_from('>I', pcode_final, magic_pair_dc)[0] & 0xffff) << 16) | \
        (struct.unpack_from('>I', pcode_final, magic_pair_dc + 4)[0] & 0xffff) != MAGIC:
    die('set-pair does not compose to MAGIC 0x%08x' % MAGIC)
if args.chan == 'b':
    resp_set2_w = (0x09 << 26) | (4 << 16)
    resp_set3_w = (0x08 << 26) | (4 << 21) | (4 << 16) | RESP_BASE
    resp_pair_at = pcode_final.find(struct.pack('>II', resp_set2_w, resp_set3_w))
    if resp_pair_at != CAVE_DC + 4*5:
        die('chan b: response-base set-pair 0x0000/0x%04x not adjacent @dc 0x%x (found %s)' % (
            RESP_BASE, CAVE_DC + 4*5, hex(resp_pair_at) if resp_pair_at >= 0 else 'NOWHERE'))
    if ((struct.unpack_from('>I', pcode_final, CAVE_DC + 4*5)[0] & 0xffff) << 16) | \
            (struct.unpack_from('>I', pcode_final, CAVE_DC + 4*6)[0] & 0xffff) != W_RESP*4:
        die('chan b: response set-pair composes to 0x%x != CR 0x%x (W_RESP 0x%x x4)' % (
            ((struct.unpack_from('>I', pcode_final, CAVE_DC + 4*5)[0] & 0xffff) << 16) |
            (struct.unpack_from('>I', pcode_final, CAVE_DC + 4*6)[0] & 0xffff), W_RESP*4, W_RESP))
    if struct.unpack_from('>I', pcode_final, CAVE_DC + 4*7)[0] != READY_ST_W:
        die('chan b: READY store st.d r6,r4,0x0 word %08x not @dc 0x%x' % (
            READY_ST_W, CAVE_DC + 4*7))
if args.chan == 'g':
    src_set2_w = (0x09 << 26) | (3 << 16)
    src_set3_w = (0x08 << 26) | (3 << 21) | (3 << 16) | G_SRC_BASE
    src_pair_at = pcode_final.find(struct.pack('>II', src_set2_w, src_set3_w))
    if src_pair_at != CAVE_DC + 4*8:
        die('chan g: src set-pair 0x0/0x%x not adjacent @dc 0x%x (found %s)' % (
            G_SRC_BASE, CAVE_DC + 4*8, hex(src_pair_at) if src_pair_at >= 0 else 'NOWHERE'))
    dst_set2_w = (0x09 << 26) | (4 << 16) | G_DST_HI
    dst_set3_w = (0x08 << 26) | (4 << 21) | (4 << 16) | G_DST_LO
    dst_pair_at = pcode_final.find(struct.pack('>II', dst_set2_w, dst_set3_w))
    if dst_pair_at != CAVE_DC + 4*10:
        die('chan g: dst set-pair 0x%x/0x%x not adjacent @dc 0x%x (found %s)' % (
            G_DST_HI, G_DST_LO, CAVE_DC + 4*10,
            hex(dst_pair_at) if dst_pair_at >= 0 else 'NOWHERE'))
    if ((struct.unpack_from('>I', pcode_final, CAVE_DC + 4*10)[0] & 0xffff) << 16) | \
            (struct.unpack_from('>I', pcode_final, CAVE_DC + 4*11)[0] & 0xffff) \
            != (G_DST_HI << 16) | G_DST_LO:
        die('chan g: dst set-pair composes to 0x%x != rt 0x%x' % (
            ((struct.unpack_from('>I', pcode_final, CAVE_DC + 4*10)[0] & 0xffff) << 16) |
            (struct.unpack_from('>I', pcode_final, CAVE_DC + 4*11)[0] & 0xffff),
            (G_DST_HI << 16) | G_DST_LO))
    if ((struct.unpack_from('>I', pcode_final, CAVE_DC + 4*8)[0] & 0xffff) << 16) | \
            (struct.unpack_from('>I', pcode_final, CAVE_DC + 4*9)[0] & 0xffff) \
            != W_PLD * 4:
        die('chan g: src set-pair composes to CR 0x%x != 0x%x (W_PLD 0x%x x4)' % (
            ((struct.unpack_from('>I', pcode_final, CAVE_DC + 4*8)[0] & 0xffff) << 16) |
            (struct.unpack_from('>I', pcode_final, CAVE_DC + 4*9)[0] & 0xffff),
            W_PLD * 4, W_PLD))
    if any(struct.unpack_from('>I', pcode_final, FRAG_DC + 4*i)[0] != 0
           for i in range(FRAG_WORDS)):
        die('chan g: fragment not ZERO in the FINAL image (runtime buffer!)')
    if COPYDONE == 'on':
        if struct.unpack_from('>I', pcode_final, G_MARKER_DC)[0] != MARKER_ST_W:
            die('chan g: COPY-DONE marker word %08x not @dc 0x%x' % (
                MARKER_ST_W, G_MARKER_DC))
    elif struct.pack('>I', MARKER_ST_W) in pcode_final:
        die('chan g: --copydone off must NOT carry the marker word 0x%08x' % MARKER_ST_W)
say('[15] expected-bytes (Review Focus 5/3): set2/set3 pair %04x/%04x adjacent @dc 0x%x '
    '== MAGIC 0x%08x (Task-1/7 LAYOUT); ld.i imm 0x%x/0x%x (CR 0x%x/0x%x) present; '
    'placeholder 0x444d/0x5031 ABSENT%s' % (
    (MAGIC >> 16) & 0xffff, MAGIC & 0xffff,
    FRAG_DC + 4*3 if args.chan == 'b' else CAVE_DC + 4*3, MAGIC,
    W_MAGIC, W_ADDR, W_MAGIC*4, W_ADDR*4,
    ('; chan b: response-base set-pair 0x0000/0x%04x @dc 0x%x composes to CR 0x%x '
     '(W_RESP 0x%x x4), READY st.d %08x @dc 0x%x' % (
         RESP_BASE, CAVE_DC + 4*5, W_RESP*4, W_RESP, READY_ST_W, CAVE_DC + 4*7))
    if args.chan == 'b' else
    ('; chan g: src set-pair 0x0/0x%x @dc 0x%x -> CR 0x%x (W_PLD 0x%x x4), '
     'dst set-pair 0x%x/0x%x @dc 0x%x -> rt 0x%x (fragment %dw ZERO in image), '
     'tail 0x%x%s' % (
         G_SRC_BASE, CAVE_DC + 4*8, W_PLD * 4, W_PLD,
         G_DST_HI, G_DST_LO, CAVE_DC + 4*10, (G_DST_HI << 16) | G_DST_LO, FRAG_WORDS,
         G_TAIL_DC[COPYDONE],
         ', COPY-DONE marker %08x @dc 0x%x -> CR 0x%x (W_RESP 0x%x x4)'
         % (MARKER_ST_W, G_MARKER_DC, W_RESP * 4, W_RESP) if COPYDONE == 'on'
         else ', no marker (off)'))
    if args.chan == 'g' else ''))

out = open(args.out, 'rb').read()
md5_out = hashlib.md5(out).hexdigest()
if w32be(out, dc_to_raw(HOOK_DC)) != hook_after:
    die('final hook word lost')
for i, w in enumerate(stub_words):
    if w32be(out, dc_to_raw(CAVE_DC + 4*i)) != w:
        die('final stub word @dc 0x%x lost' % (CAVE_DC + 4*i))
for i, w in enumerate(frag_words):
    if w32be(out, dc_to_raw(FRAG_DC + 4*i)) != w:
        die('final frag word @dc 0x%x lost' % (FRAG_DC + 4*i))
if out[VPI_OFF] != VPI_VAL or out[LCL0_OFF] != LCL0_VAL:
    die('final VPI/lcl[0] byte lost')
say('[16] final words OK (hook=%08x, %d stub words, %d frag words, vpi=%02x, lcl0=%02x); '
    'md5=%s size=%d' % (hook_after, len(stub_words), len(frag_words),
                        out[VPI_OFF], out[LCL0_OFF], md5_out, len(out)))

r = subprocess.run(['mstflint', '-i', args.out, 'verify'], capture_output=True, text=True)
say('[17] mstflint verify: rc=%d' % r.returncode)
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
say('[18] mstflint q: PSID/FW/type invariant vs base; GUID/MAC == card (%s/%s, Rule 3)' % (
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
say('[19] mstflint dc: build-ID is the first content line (line %d of dc):' % (mi + 1))
say('    ' + dl[mi])

LOG = OUT_BASE + '-build.log'
open(LOG, 'w').write('\n'.join(lines_out) + '\n')

if os.environ.get('MLXINI_RA3_DET_CHILD'):
    say('DONE (det-child) %s md5=%s' % (args.out, md5_out))
else:
    det_out = OUT_BASE + '-det.bin'
    det_base = OUT_BASE + '-det'
    env = dict(os.environ, MLXINI_RA3_DET_CHILD='1')
    r = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                        '--chan', args.chan, '--cmp', args.cmp, '--out', det_out,
                        '--base', args.base, '--base-md5', args.base_md5,
                        '--guid', args.guid, '--mac', args.mac,
                        '--build-id-date', args.build_id_date]
                       + (['--copydone', COPYDONE] if args.chan == 'g' else [])
                       + (['--build-id-text', args.build_id_text] if args.build_id_text else []),
                       cwd=REPO, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        die('determinism re-build failed: %s%s' % (r.stdout.strip()[-2000:], r.stderr.strip()[-2000:]))
    det = open(det_out, 'rb').read()
    if det != out:
        die('determinism: second build differs (%s vs %s)' % (args.out, det_out))
    for p in map(Path, [det_out, det_out + '.step1', det_out + '.step2', det_out + '.step2b',
                        det_out + '.step3', det_base + '-build.log',
                        det_base + '-ini-final.ini']):
        if p.exists():
            p.unlink()
    say('[20] determinism: second build (--chan %s --cmp %s%s) byte-exact cmp; md5=%s' % (
        args.chan, args.cmp, ' --copydone %s' % COPYDONE if args.chan == 'g' else '',
        md5_out))
    say('DONE %s md5=%s log=%s' % (args.out, md5_out, LOG))
