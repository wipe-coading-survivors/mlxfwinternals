#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node-v2 task-6c step-1: build the c1 04z1 image (bounded-wait
bound 0x9 -> 0x7fff, OFFLINE). 04z1 = the live-built 04z image (bounded-wait
dispatch) + ONE extra word, variant V2a (task-5 journal "Fix round 1", 04z
memo LIVE REVISION):

Image = consumer stock ri (base md5 dacbcf0e...) + 0x1f-force + F1-entry hook
+ 22-word trampoline stub in the all-zero cave dc 0x31cba0 + 04z BOUNDED-WAIT
DISPATCH word dc 0x243c10 + NEW BOUND word dc 0x243cac + R1 build-ID in 0x30.

Patches (1)-(3) are byte-identical to 04z (build_04z_boundedwait.py); the ONLY
code difference vs 04z is patch (4), the bound word.

1) C12-gate-lift word (0x1f, MANDATORY): dc 0x1f1f00 (raw 0x37e0f0)
   0xfcb1c083 -> 0x0011001f (addi r17,zero,0x1f). Same word as 04w/04y/04z.

2) F1-ENTRY hook (validated in 04y, T4b): dc 0x18c05c (stock 0x480300bc)
   -> 0x950642d1 = jump 0x31cba0; 22-word trampoline stub in the all-zero cave
   dc 0x31cba0; jump-back 0x18c060. UNCHANGED from 04y/04z.

3) BOUNDED-WAIT DISPATCH word (the 04z fix, UNCHANGED in 04z1): dc 0x243c10
   0xa000002d (b.t.0x0 zero,0x243cc4, unbounded) -> 0xa0000012
   (b.t.0x0 zero,0x243c58, bounded path). Verified present in the 04z
   reference image; re-applied here from the stock base.

4) BOUND word (the 04z1 fix, variant V2a): the 04z bounded path (arg1==2,
   fn 0x243bec) loops `while counter < 0x9` (<=10 iters, microseconds) - too
   short for the boot-time port-init handshake (ms-scale, csr0x1a4==2), which
   timed out and triggered the live assert 0x857f (task-6a, 2/2). The bound
   immediate at dc 0x243cac (subsi r6,r5,0x9) is raised to 0x7fff (max
   POSITIVE signed 16-bit; 0xffff == -1 would break the loop, task-5 [V]):
       dc 0x243cac (raw 0x3d5074): 0x14a60009 (subsi r6,r5,0x9)
                              -> 0x14a67fff (subsi r6,r5,0x7fff)
   32767 iters ~= 3-16 ms (iRISC ~500M-1G; iter = csr.r csr0x1a4 + 5 insn) -
   covers the ms handshake [H, task-5 V2a]. The stock arg1==2 caller
   (0x25b618) gets a larger bound on a fast op - low risk [V, task-5].
   The before-word (0x14a60009) is verified at raw 0x3d5074 in BOTH the stock
   base and the 04z reference BEFORE the patch; a mismatch is a STOP.

5) build-ID in 0x30 DBG_FW_INI (R1/R2):
   `; mlxini cx4lx-04z1-bound (2026-10-14, 8c4a097f): 04z + bounded-wait
    bound 0x9->0x7fff (dc 0x243cac)`
   in-place only, budget <= e.size-32, ;;-comment trim, no relocation.

Gates (all mandatory, each result in the journal):
  [1/G0] base-md5; [2/G0] MAIN_CODE geometry+GCA; [2b/G1] VPI byte;
  [3/G1] pre-patch words in the base (0x1f + hook + jump-back + cave +
  dispatch before-word + BOUND before-word); [3b] 04z REF md5 + before-words
  (dispatch a0000012 already applied, bound 14a60009 still stock);
  [4/G2a] stub encode->decode + budget + addr constants; [5/G2b] hook jump
  decode; [5b/G2e] dispatch word: decode before/after + enc.b_t check;
  [5c] BOUND word: decode before/after + enc.subsi re-encode (imm s16,
  0x7fff max positive); [6/G2c] clobber gate (f1-caller-regscan); [7/G3]
  clcrc round-trip; [8/G3] patch (0x1f + hook + stub + dispatch + bound) +
  changed-line set; [9/G5] step1 verify(deep) + ITOC recompute; [10/G7a]
  guides skip; [11/G8] 0x30 build-ID budget+first-line+round-trip; [12/G2d]
  final identity words; [13/G4] diff vs base stray=NONE (full 04z set +
  bound word); [13c] DIFF VS 04z = exactly the bound word (+ its line CRC) +
  MAIN_CODE ITOC CRC fields + 0x30 build-ID, nothing else; [14/G9]
  final==step1 outside 0x30; [15/G6] mstflint verify; [16/G7b] mstflint q
  identity; [17/G8b] mstflint dc build-ID first content line; [18/G10]
  determinism (two builds, one md5).
"""
import argparse
import hashlib
import os
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
import enc

THEIR_RI_MD5 = 'dacbcf0e1cbc1bed3d5e916520fe6803'
GCA_REF = REPO + '/refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0

# 0x1f patch (C12-gate lift, mandatory)
X1F_DC = 0x1f1f00
X1F_RAW = 0x37e0f0
X1F_BEFORE = 0xfcb1c083
X1F_AFTER = 0x0011001f
X1F_NEXT = 0x6430000a

# F1-entry hook (the fix)
HOOK_DC = 0x18c05c
HOOK_RAW_EXPECTED = 0x311c60
HOOK_BEFORE = 0x480300bc
HOOK_BEFORE_DIS = 'csr.r r3,csr0xbc'
HOOK_AFTER_EXPECTED = 0x950642d1   # task-1c spec (enc.jump(0x18c05c, 0x31cba0))
JUMP_BACK_DC = 0x18c060           # F1 word 1 (st.d r3,r1,0x4) - jump-back target
JUMP_BACK_WORD = 0x6c201806

# cave (all-zero data region, 24-word budget)
CAVE_DC = 0x31cba0
CAVE_RAW_EXPECTED = 0x4bb858
CAVE_BUDGET = 24

# 04z bounded-wait DISPATCH word (unchanged in 04z1; re-applied from base)
BW_DC = 0x243c10
BW_RAW_EXPECTED = 0x3d4fd0            # dc_to_raw(BW_DC), verified against base
BW_BEFORE = 0xa000002d                # b.t.0x0 zero,0x243cc4 (unbounded path)
BW_BEFORE_DIS = 'b.t.0x0 zero,0x243cc4'
BW_AFTER = 0xa0000012                 # b.t.0x0 zero,0x243c58 (bounded path)
BW_AFTER_DIS = 'b.t.0x0 zero,0x243c58'
BW_BEFORE_TARGET = 0x243cc4
BW_AFTER_TARGET = 0x243c58

# 04z1 BOUND word (the new fix, variant V2a): bounded-path loop bound 0x9 ->
# 0x7fff (max positive signed 16-bit; 0xffff == -1 is forbidden)
BD_DC = 0x243cac
BD_RAW_EXPECTED = 0x3d5074            # dc_to_raw(BD_DC), verified against base
BD_BEFORE = 0x14a60009                # subsi r6,r5,0x9
BD_BEFORE_DIS = 'subsi r6,r5,0x9'
BD_AFTER = 0x14a67fff                 # subsi r6,r5,0x7fff
BD_AFTER_DIS = 'subsi r6,r5,0x7fff'
BD_IMM_BEFORE = 0x9
BD_IMM_AFTER = 0x7fff

# 04z reference image (04z1 must differ from it by EXACTLY the bound word +
# its line CRC + MAIN_CODE ITOC CRC fields + the 0x30 build-ID; nothing else)
O4Z_REF = REPO + '/build/cx4lx-04z-boundedwait.bin'
O4Z_REF_MD5 = '8c4a097f0e7c1c079401a7b7f1afd6dc'

# table (iRISC RAM addresses, written by the stub at runtime)
TABLE_VALUE = 0x46573201
TABLE_ADDR_FLAG1 = 0x0d600c
TABLE_ADDR_FLAG0 = 0x0d6008
STR_RT = 0x00aeb83b               # emit7 string rt (dead pointer, reused - T1c)

# device identity (guides skip: base ri already carries it)
EXPECT_GUID = '0x' + mlxfwutil.hw('CARD_CX4LX_XCAT', 'guid')
EXPECT_MAC = '0x' + mlxfwutil.hw('CARD_CX4LX_XCAT', 'mac')
EXPECT_PSID = 'MT_2420110034'
EXPECT_FW = '14.32.1900'

# T1c clobber-gate expected verdict (f1-caller-regscan.py, "any mention" metric)
REGSCAN = REPO + '/scripts/probes/cx4lx-sfp28-ib-node/f1-caller-regscan.py'
REGSCAN_VERDICT = 'VERDICT: r11/r12 unused in 5/12 F1-caller functions'

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


def csr_w(rs, rt, csr):
    # dump_d2_core pattern (task-1c): enc.csr_w has the wrong field layout
    # for this ISA.
    return (0x13 << 26) | (rs << 21) | (rt << 11) | (csr & 0x7ff)


def addi_hi(rd, rs, imm):
    # addi.hi (ADD-style, 32-bit truncation; docs/250-re/120-irisc/010-isa.md, task-1c)
    return (0x02 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def build_stub():
    """Encode the 22-word trampoline (task-1c spec) and decode-verify each word."""
    words = []

    def emit(w, want_dis, label):
        dc = CAVE_DC + 4*len(words)
        d = irisc_dis.dis(w, dc)
        if d != want_dis:
            die('stub %s dc 0x%x %08x decodes "%s" != "%s"' % (label, dc, w, d, want_dis))
        words.append((dc, w, d))

    emit(enc.csr_r(3, 0xbc), 'csr.r r3,csr0xbc', 'w0 r3=L (link from CSR)')
    emit(enc.or_(11, 3, 3), 'or r11,r3,r3', 'w1 save L (r11)')
    emit(enc.or_(12, 5, 5), 'or r12,r5,r5', 'w2 save F (r12)')
    emit(enc.or_(10, 6, 6), 'or r10,r6,r6', 'w3 save K (r10)')
    emit(enc.set2(3, (TABLE_ADDR_FLAG1 >> 16) & 0xffff),
         'set2 r3,zero,0x%x' % ((TABLE_ADDR_FLAG1 >> 16) & 0xffff), 'w4 A hi')
    emit(enc.set3(3, 3, TABLE_ADDR_FLAG1 & 0xffff),
         'set3 r3,r3,0x%x' % (TABLE_ADDR_FLAG1 & 0xffff), 'w5 A lo -> r3=0x0d600c')
    emit(enc.set2(8, (TABLE_VALUE >> 16) & 0xffff),
         'set2 r8,zero,0x%x' % ((TABLE_VALUE >> 16) & 0xffff), 'w6 V hi')
    emit(enc.set3(8, 8, TABLE_VALUE & 0xffff),
         'set3 r8,r8,0x%x' % (TABLE_VALUE & 0xffff), 'w7 V lo -> r8=0x46573201')
    emit(enc.st_d(8, 3, 0), 'st.d r8,r3,0x0', 'w8 [0x0d600c] := 0x46573201 (flag1)')
    emit(enc.st_d(8, 3, -4), 'st.d r8,r3,-0x4', 'w9 [0x0d6008] := 0x46573201 (flag0)')
    emit(enc.addi(4, 0, (STR_RT & 0xffff)),
         'addi r4,zero,0x-47c5', 'w10 S lo (s16 sign-ext)')
    emit(addi_hi(4, 4, 0xaf), 'addi.hi r4,r4,0xaf', 'w11 S hi (ADD) -> r4=0x00aeb83b')
    emit(enc.addi(9, 0, 0), 'addi r9,zero,0x0', 'w12 p4=0')
    emit(enc.or_(5, 10, 10), 'or r5,r10,r10', 'w13 p0=K')
    emit(enc.or_(6, 12, 12), 'or r6,r12,r12', 'w14 p1=F')
    emit(enc.or_(7, 11, 11), 'or r7,r11,r11', 'w15 p2=L')
    emit(enc.call(CAVE_DC + 4*len(words), 0x63bc), 'call 0x63bc', 'w16 emit7 (count=7)')
    emit(csr_w(11, 0, 0xbc), 'csr.w r11,zero,0xbc', 'w17 restore link CSR')
    emit(enc.or_(3, 11, 11), 'or r3,r11,r11', 'w18 r3=L (F1 entry ABI)')
    emit(enc.or_(5, 12, 12), 'or r5,r12,r12', 'w19 r5=F')
    emit(enc.or_(6, 10, 10), 'or r6,r10,r10', 'w20 r6=K')
    emit(enc.jump(CAVE_DC + 4*21, JUMP_BACK_DC), 'jump 0x%x' % JUMP_BACK_DC, 'w21 jump-back F1 w1')
    if len(words) > CAVE_BUDGET:
        die('stub %d words exceeds cave budget %d' % (len(words), CAVE_BUDGET))
    return words


def run_build(out, base, base_md5, build_id):
    lines_out = []

    def say(msg=''):
        print(msg)
        lines_out.append(msg)

    # [1/G0] base md5
    buf = open(base, 'rb').read()
    md5_base = hashlib.md5(buf).hexdigest()
    say('[1/G0] base=%s md5=%s size=%d' % (base.split('/')[-1], md5_base, len(buf)))
    if base_md5 != 'none':
        if md5_base != base_md5:
            die('base md5 mismatch: %s != %s' % (md5_base, base_md5))
        say('    base md5 gate PASS')
    else:
        say('    base-md5 gate SKIPPED (--base-md5 none)')

    if '\n' in build_id or not build_id.startswith('; '):
        die('bad build-ID line: single "; "-comment required (R1)')

    img = mlxfwutil.Image(buf, base)
    e = img.find_entry('ITOC', 0x03)
    say('[2/G0] MAIN_CODE: type=0x%02x index=%d addr=0x%x size=0x%x clcrc=%d' % (
        e.type, e.index, e.addr, e.size, e.clcrc))
    if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
        die('MAIN_CODE header mismatch (not the 14.32.1900 geometry)')
    raw = img.section_data(e)
    code = decrc(raw)
    if len(raw) != (len(code)//64)*68:
        die('unexpected non-empty section tail')

    # GCA byte-compare (informational)
    try:
        gbuf = open(GCA_REF, 'rb').read()
        gimg = mlxfwutil.Image(gbuf, GCA_REF)
        ge = gimg.find_entry('ITOC', 0x03)
        gcode = decrc(gimg.section_data(ge))
        if gcode == code:
            say('    MAIN_CODE ACA<->GCA verdict: BYTE-IDENTICAL (%d B)' % len(code))
        else:
            dl = sorted({i // 64 for i in range(min(len(code), len(gcode))) if code[i] != gcode[i]})
            say('    MAIN_CODE ACA<->GCA verdict: DIFFERS (%d lines) - structural gates decide on THIS base' % len(dl))
    except FileNotFoundError:
        say('    GCA ref not found - byte-compare skipped')

    # [2b/G1] VPI byte: port1 (c1:00.1) must be IB (0x07)
    e11 = img.find_entry('ITOC', 0x11)
    vpi = img.section_data(e11)[0x2b3]
    if vpi != 0x07:
        die('base VPI byte 0x11+0x2b3 = 0x%02x != 0x07 (IB) - STOP' % vpi)
    say('[2b/G1] base VPI OK (0x11+0x2b3 = 07, IB)')

    # [3/G1] pre-patch words in the BASE: 0x1f site+next, hook site (F1 w0),
    #        jump-back (F1 w1), cave zero, dispatch before-word, BOUND before-word
    HOOK_RAW = dc_to_raw(HOOK_DC)
    if HOOK_RAW != HOOK_RAW_EXPECTED:
        die('hook dc 0x%x -> raw 0x%x != expected 0x%x (dc->raw mapping wrong)' % (
            HOOK_DC, HOOK_RAW, HOOK_RAW_EXPECTED))
    CAVE_RAW = dc_to_raw(CAVE_DC)
    if CAVE_RAW != CAVE_RAW_EXPECTED:
        die('cave dc 0x%x -> raw 0x%x != expected 0x%x (dc->raw mapping wrong)' % (
            CAVE_DC, CAVE_RAW, CAVE_RAW_EXPECTED))
    BW_RAW = dc_to_raw(BW_DC)
    if BW_RAW != BW_RAW_EXPECTED:
        die('dispatch dc 0x%x -> raw 0x%x != expected 0x%x (dc->raw mapping wrong)' % (
            BW_DC, BW_RAW, BW_RAW_EXPECTED))
    BD_RAW = dc_to_raw(BD_DC)
    if BD_RAW != BD_RAW_EXPECTED:
        die('bound dc 0x%x -> raw 0x%x != expected 0x%x (dc->raw mapping wrong)' % (
            BD_DC, BD_RAW, BD_RAW_EXPECTED))
    if w32be(buf, HOOK_RAW) != HOOK_BEFORE:
        die('hook dc 0x%x raw 0x%x = %08x != %08x (F1 entry word 0 not stock: %s)' % (
            HOOK_DC, HOOK_RAW, w32be(buf, HOOK_RAW), HOOK_BEFORE, HOOK_BEFORE_DIS))
    jb = w32be(buf, dc_to_raw(JUMP_BACK_DC))
    if jb != JUMP_BACK_WORD:
        die('jump-back dc 0x%x = %08x != stock 0x6c201806 (st.d r3,r1,0x4); F1 word 1 not intact' % (
            JUMP_BACK_DC, jb))
    if w32be(buf, X1F_RAW) != X1F_BEFORE:
        die('0x1f word raw 0x%x = %08x != %08x' % (X1F_RAW, w32be(buf, X1F_RAW), X1F_BEFORE))
    if w32be(buf, X1F_RAW + 4) != X1F_NEXT:
        die('0x1f next word raw 0x%x = %08x != %08x' % (
            X1F_RAW + 4, w32be(buf, X1F_RAW + 4), X1F_NEXT))
    if not all(w32be(code, CAVE_DC + 4*i) == 0 for i in range(CAVE_BUDGET)):
        die('cave dc 0x%x..0x%x not all-zero' % (CAVE_DC, CAVE_DC + 4*CAVE_BUDGET))
    bw_word = w32be(buf, BW_RAW)
    if bw_word != BW_BEFORE:
        die('dispatch dc 0x%x raw 0x%x = %08x != %08x (arg1==1 dispatch not '
            'stock %s) - STOP' % (BW_DC, BW_RAW, bw_word, BW_BEFORE, BW_BEFORE_DIS))
    bd_word = w32be(buf, BD_RAW)
    if bd_word != BD_BEFORE:
        die('bound dc 0x%x raw 0x%x = %08x != %08x (bounded-path bound not '
            'stock %s) - STOP' % (BD_DC, BD_RAW, bd_word, BD_BEFORE, BD_BEFORE_DIS))
    say('[3/G1] pre-patch OK: hook dc 0x%x raw 0x%x=%08x (%s); jump-back 0x%x=6c201806; '
        '0x1f 0x%x=%08x next=%08x; cave %d words zero (raw 0x%x..); '
        'dispatch dc 0x%x raw 0x%x=%08x (%s); bound dc 0x%x raw 0x%x=%08x (%s)' % (
            HOOK_DC, HOOK_RAW, HOOK_BEFORE, HOOK_BEFORE_DIS, JUMP_BACK_DC,
            X1F_DC, X1F_BEFORE, X1F_NEXT, CAVE_BUDGET, CAVE_RAW,
            BW_DC, BW_RAW, BW_BEFORE, BW_BEFORE_DIS,
            BD_DC, BD_RAW, BD_BEFORE, BD_BEFORE_DIS))

    # [3b] 04z REFERENCE image: md5 + before-words. The 04z image must already
    # carry the dispatch word (a0000012) and still have the stock bound word
    # (14a60009) - 04z1 changes only the bound.
    if not os.path.exists(O4Z_REF):
        die('04z reference image not found: %s' % O4Z_REF)
    o4z = open(O4Z_REF, 'rb').read()
    o4z_md5 = hashlib.md5(o4z).hexdigest()
    if o4z_md5 != O4Z_REF_MD5:
        die('04z ref md5 mismatch: %s != %s' % (o4z_md5, O4Z_REF_MD5))
    o4z_bw = w32be(o4z, BW_RAW)
    o4z_bd = w32be(o4z, BD_RAW)
    if o4z_bw != BW_AFTER:
        die('04z ref dispatch word raw 0x%x = %08x != %08x (04z ref does not '
            'carry the 04z dispatch %s) - STOP' % (BW_RAW, o4z_bw, BW_AFTER, BW_AFTER_DIS))
    if o4z_bd != BD_BEFORE:
        die('04z ref bound word raw 0x%x = %08x != %08x (04z ref bound not '
            'stock %s) - STOP' % (BD_RAW, o4z_bd, BD_BEFORE, BD_BEFORE_DIS))
    o4z_img = mlxfwutil.Image(o4z, O4Z_REF)
    o4z_e = o4z_img.find_entry('ITOC', 0x03)
    if (o4z_e.addr, o4z_e.size, o4z_e.clcrc) != (e.addr, e.size, e.clcrc):
        die('04z ref MAIN_CODE geometry differs from base: (%08x,%08x,%d) != (%08x,%08x,%d)'
            % (o4z_e.addr, o4z_e.size, o4z_e.clcrc, e.addr, e.size, e.clcrc))
    say('[3b] 04z ref OK: md5=%s; dispatch raw 0x%x=%08x (%s, UNCHANGED in 04z1); '
        'bound raw 0x%x=%08x (stock %s); MAIN_CODE geometry == base'
        % (o4z_md5, BW_RAW, o4z_bw, BW_AFTER_DIS, BD_RAW, o4z_bd, BD_BEFORE_DIS))

    # [4/G2a] build the stub (encode -> decode round-trip per word) + address constants
    stub_words = build_stub()
    # address-constant simulation (semantics: set2=imm<<16, set3=(rd&0xffff0000)|imm,
    # addi=s16 sign-extend, addi.hi=ADD trunc32; task-1c / docs/250-re/120-irisc/010-isa.md)
    r3 = ((TABLE_ADDR_FLAG1 >> 16) & 0xffff) << 16
    r3 = (r3 & 0xffff0000) | (TABLE_ADDR_FLAG1 & 0xffff)
    if r3 != TABLE_ADDR_FLAG1:
        die('addr-const sim: r3 = 0x%08x != 0x%06x (set2/set3 sequence)' % (r3, TABLE_ADDR_FLAG1))
    r8 = ((TABLE_VALUE >> 16) & 0xffff) << 16
    r8 = (r8 & 0xffff0000) | (TABLE_VALUE & 0xffff)
    if r8 != TABLE_VALUE:
        die('addr-const sim: r8 = 0x%08x != 0x%08x (set2/set3 sequence)' % (r8, TABLE_VALUE))
    imm16 = STR_RT & 0xffff
    imm_se = imm16 - 0x10000 if imm16 & 0x8000 else imm16   # addi: s16 sign-extend
    r4 = (imm_se) & 0xffffffff
    r4 = (r4 + (0xaf << 16)) & 0xffffffff                   # addi.hi: ADD, trunc32
    if r4 != STR_RT:
        die('addr-const sim: r4 = 0x%08x != 0x%08x (addi/addi.hi composition)' % (r4, STR_RT))
    say('[4/G2a] stub %d/%d cave words (r3=0x%06x, r8=0x%08x, r4=0x%08x simulated OK):'
        % (len(stub_words), CAVE_BUDGET, TABLE_ADDR_FLAG1, TABLE_VALUE, STR_RT))
    for dc, w, d in stub_words:
        say('    dc 0x%x %08x = %s' % (dc, w, d))

    # [5/G2b] hook word: encode + decode (JUMP, not call: link must stay untouched)
    HOOK_AFTER = enc.jump(HOOK_DC, CAVE_DC)
    if HOOK_AFTER != HOOK_AFTER_EXPECTED:
        die('hook word %08x != task-1c spec word %08x' % (HOOK_AFTER, HOOK_AFTER_EXPECTED))
    sd = irisc_dis.dis(HOOK_AFTER, HOOK_DC)
    if sd != 'jump 0x%x' % CAVE_DC:
        die('hook jump decode "%s" != "jump 0x%x"' % (sd, CAVE_DC))
    if (HOOK_AFTER >> 24) & 1 != 1:
        die('hook patch is a call (bit24=0) - would corrupt the link register')
    say('[5/G2b] hook dc 0x%x raw 0x%x: %08x -> %08x (%s); jump-back target 0x%x; link untouched'
        % (HOOK_DC, HOOK_RAW, HOOK_BEFORE, HOOK_AFTER, sd, JUMP_BACK_DC))

    # [5b/G2e] dispatch word: decode before/after + enc.b_t re-encode check
    bwd_before = irisc_dis.dis(BW_BEFORE, BW_DC)
    bwd_after = irisc_dis.dis(BW_AFTER, BW_DC)
    if bwd_before != BW_BEFORE_DIS:
        die('dispatch before decode "%s" != "%s"' % (bwd_before, BW_BEFORE_DIS))
    if bwd_after != BW_AFTER_DIS:
        die('dispatch after decode "%s" != "%s"' % (bwd_after, BW_AFTER_DIS))
    enc_after = enc.b_t(0, BW_DC, BW_AFTER_TARGET)
    if enc_after != BW_AFTER:
        die('enc.b_t(0, 0x%x, 0x%x) = %08x != %08x (dispatch after-word wrong)' % (
            BW_DC, BW_AFTER_TARGET, enc_after, BW_AFTER))
    enc_before = enc.b_t(0, BW_DC, BW_BEFORE_TARGET)
    if enc_before != BW_BEFORE:
        die('enc.b_t(0, 0x%x, 0x%x) = %08x != %08x (dispatch before-word wrong)' % (
            BW_DC, BW_BEFORE_TARGET, enc_before, BW_BEFORE))
    say('[5b/G2e] dispatch dc 0x%x raw 0x%x: %08x (%s) -> %08x (%s); '
        'enc.b_t re-encode OK (imm16=0x%x)' % (
            BW_DC, BW_RAW, BW_BEFORE, BW_BEFORE_DIS, BW_AFTER, BW_AFTER_DIS,
            (BW_AFTER_TARGET - BW_DC) // 4))

    # [5c] BOUND word (the 04z1 fix): decode before/after + enc.subsi re-encode
    # check; the immediate is SIGNED 16-bit - 0x7fff is the max positive value
    # (0xffff == -1 would break the `counter < imm` loop, task-5 [V]).
    bnd_before = irisc_dis.dis(BD_BEFORE, BD_DC)
    bnd_after = irisc_dis.dis(BD_AFTER, BD_DC)
    if bnd_before != BD_BEFORE_DIS:
        die('bound before decode "%s" != "%s"' % (bnd_before, BD_BEFORE_DIS))
    if bnd_after != BD_AFTER_DIS:
        die('bound after decode "%s" != "%s"' % (bnd_after, BD_AFTER_DIS))
    enc_bd_before = enc.subsi(6, 5, BD_IMM_BEFORE)
    if enc_bd_before != BD_BEFORE:
        die('enc.subsi(6,5,0x%x) = %08x != %08x (bound before-word wrong)' % (
            BD_IMM_BEFORE, enc_bd_before, BD_BEFORE))
    enc_bd_after = enc.subsi(6, 5, BD_IMM_AFTER)
    if enc_bd_after != BD_AFTER:
        die('enc.subsi(6,5,0x%x) = %08x != %08x (bound after-word wrong)' % (
            BD_IMM_AFTER, enc_bd_after, BD_AFTER))
    if BD_IMM_AFTER > 0x7fff:
        die('bound imm 0x%x exceeds max positive s16 0x7fff' % BD_IMM_AFTER)
    say('[5c] bound dc 0x%x raw 0x%x: %08x (%s) -> %08x (%s); '
        'enc.subsi(6,5,.) re-encode OK; imm s16: 0x%x -> 0x%x (max positive)' % (
            BD_DC, BD_RAW, BD_BEFORE, BD_BEFORE_DIS, BD_AFTER, BD_AFTER_DIS,
            BD_IMM_BEFORE, BD_IMM_AFTER))

    # [6/G2c] clobber gate: f1-caller-regscan verdict on the base image
    r = subprocess.run([sys.executable, REGSCAN, base], capture_output=True, text=True)
    rl = [l.rstrip() for l in (r.stdout + r.stderr).splitlines() if l.strip()]
    verdict = [l for l in rl if l.startswith('VERDICT:')]
    if len(verdict) != 1 or verdict[0] != REGSCAN_VERDICT:
        die('clobber gate: regscan verdict %r != expected %r (rc=%d)' % (
            verdict, REGSCAN_VERDICT, r.returncode))
    if r.returncode != 1:
        die('clobber gate: regscan rc=%d (expected 1: 7/12 functions mention r11/r12 by design)'
            % r.returncode)
    say('[6/G2c] clobber gate PASS: %s (rc=1 by design; safety per T1c = '
        '"not live across the call", 0/12 straddles; coordinator ruling (a) ACCEPTED)'
        % verdict[0])

    # [7/G3] clcrc round-trip (unpatched) before patching
    rt0 = clcrc(code)
    if rt0 != raw:
        die('round-trip de-clcrc/re-clcrc failed (base)')
    say('[7/G3] round-trip base: OK (%d lines)' % (len(code)//64))

    # [8/G3] patch code (0x1f + hook + stub + dispatch + BOUND)
    pcode = bytearray(code)
    struct.pack_into('>I', pcode, X1F_DC, X1F_AFTER)
    struct.pack_into('>I', pcode, HOOK_DC, HOOK_AFTER)
    for dc, w, _ in stub_words:
        struct.pack_into('>I', pcode, dc, w)
    struct.pack_into('>I', pcode, BW_DC, BW_AFTER)
    struct.pack_into('>I', pcode, BD_DC, BD_AFTER)
    pcode = bytes(pcode)
    praw = clcrc(pcode)
    patched_dcs = [X1F_DC, HOOK_DC] + [dc for dc, _, _ in stub_words] + [BW_DC, BD_DC]
    changed_lines = sorted({dc // 64 for dc in patched_dcs})
    diff_lines = [i for i in range(len(code)//64) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
    if diff_lines != changed_lines:
        die('changed-line set drifted: %s != %s' % (diff_lines, changed_lines))
    say('[8/G3] clcrc re-framed; changed lines %s only (diff set == expected)' % changed_lines)

    # [9/G5] step1: base + code patch; ITOC 0x03 sec_crc/entry_crc recomputed by
    # patch_sections; verify(deep)
    step1 = mlxfwutil.patch_sections(img, [(0x03, ln*68, praw[ln*68:ln*68+68]) for ln in changed_lines])
    errs = mlxfwutil.verify_image(mlxfwutil.Image(step1, 'step1', base=img.base, fmt=img.fmt), deep=True)
    say('[9/G5] step1 (base+0x1f+hook+stub+dispatch+bound): changed lines %s only; '
        'ITOC sec_crc/entry_crc recomputed; verify(deep)=%s'
        % (changed_lines, 'PASS' if not errs else errs))
    if errs:
        die('step1 verify failed')
    if w32be(step1, X1F_RAW) != X1F_AFTER:
        die('step1 0x1f word lost')
    if w32be(step1, HOOK_RAW) != HOOK_AFTER:
        die('step1 hook word lost')
    if w32be(step1, BW_RAW) != BW_AFTER:
        die('step1 dispatch word lost')
    if w32be(step1, BD_RAW) != BD_AFTER:
        die('step1 bound word lost')
    for dc, w, _ in stub_words:
        if w32be(step1, dc_to_raw(dc)) != w:
            die('step1 stub word @dc 0x%x lost' % dc)
    STEP1 = out + '.step1'
    open(STEP1, 'wb').write(step1)

    # [10/G7a] guides skip: base ri carries DEV_INFO+MFG_INFO with expected identity
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
    open(out, 'wb').write(step1)
    say('[10/G7a] guides SKIPPED: base ri carries DEV_INFO+MFG_INFO with expected identity; final-code = step1')

    # [11/G8] 0x30 build-ID (R1/R2)
    fc = open(out, 'rb').read()
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
    say('[11/G8] ini build-ID (R1/R2): "%s"' % build_id)
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
    open(out, 'wb').write(out_buf)
    img_fin = mlxfwutil.Image(out_buf, out, base=img.base, fmt=img.fmt)
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
    open(out.replace('.bin', '-ini-final.ini'), 'w', encoding='latin1').write(ini_final)
    say('    round-trip extract == ini-final; 0x30 in place @0x%x size 0x%x -> 0x%x; verify(deep)=PASS'
        % (e30n.addr, e30.size, e30n.size))

    # [12/G2d] final identity words
    fin = open(out, 'rb').read()
    md5_out = hashlib.md5(fin).hexdigest()
    if (w32be(fin, X1F_RAW) != X1F_AFTER or w32be(fin, HOOK_RAW) != HOOK_AFTER
            or w32be(fin, BW_RAW) != BW_AFTER or w32be(fin, BD_RAW) != BD_AFTER):
        die('final identity words lost (0x1f/hook/dispatch/bound)')
    for dc, w, _ in stub_words:
        if w32be(fin, dc_to_raw(dc)) != w:
            die('final stub word @dc 0x%x lost' % dc)
    say('[12/G2d] final words OK (0x1f=%08x, hook=%08x, dispatch=%08x, bound=%08x, %d stub words); '
        'md5=%s size=%d' % (X1F_AFTER, HOOK_AFTER, BW_AFTER, BD_AFTER, len(stub_words),
                            md5_out, len(fin)))

    # [13/G4] diff vs base: full 04z set + the bound word; nothing else
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
        say('[13/G4] %s: %d diff bytes, stray=%s' % (label, len(diffs), stray if stray else 'NONE'))
        if stray:
            die('stray diff bytes in %s: %s' % (label, stray[:16]))
        return diffs

    if len(fin) != len(buf):
        die('image size changed: %d != %d' % (len(fin), len(buf)))
    diff_check('final vs base (0x1f+hook+stub+dispatch+bound+0x30)', fin, buf, allowed)

    # [13c] diff 04z1 vs 04z: EXACTLY the bound word (+ its line CRC) + the
    # MAIN_CODE ITOC CRC fields (recomputed) + the 0x30 build-ID; nothing else
    z_e30 = o4z_img.find_entry('ITOC', 0x30)
    o4z_e30_abs = o4z_img.sec_abs(z_e30)
    o4z_e30_ent = o4z_img.itoc_off + 32 + z_e30.index * 32
    z1_e30_abs = img_fc.sec_abs(e30n)
    z1_e30_ent = img_fc.itoc_off + 32 + e30n.index * 32
    bd_line = BD_DC // 64
    allow_04z = set(range(BD_RAW, BD_RAW + 4))
    allow_04z |= {SEC_ADDR + bd_line * 68 + 66, SEC_ADDR + bd_line * 68 + 67}
    # the MAIN_CODE (0x03) ITOC entry CRC fields: 04z1 has one extra patched
    # word (bound) vs 04z, so the section/entry CRC recomputed by
    # patch_sections differs. Size/addr are unchanged (asserted in [3b]).
    mc_ent_off = img.itoc_off + 32 + e.index * 32
    allow_04z |= set(range(mc_ent_off + 0x18, mc_ent_off + 0x20))
    allow_04z |= set(range(min(o4z_e30_abs, z1_e30_abs),
                           max(o4z_e30_abs + z_e30.size, z1_e30_abs + e30n.size)))
    allow_04z |= set(range(min(o4z_e30_ent, z1_e30_ent),
                           max(o4z_e30_ent, z1_e30_ent) + 32))
    diffs_04z = [i for i in range(min(len(fin), len(o4z))) if fin[i] != o4z[i]]
    dset = set(diffs_04z)
    stray_04z = [hex(i) for i in diffs_04z if i not in allow_04z]
    # the bound word before/after differ in the last 2 bytes (0009 -> 7fff),
    # so check the whole 4-byte word range
    if not (dset & set(range(BD_RAW, BD_RAW + 4))):
        die('diff vs 04z: bound word @raw 0x%x..0x%x NOT in diff (patch did not '
            'land)' % (BD_RAW, BD_RAW + 3))
    if w32be(fin, BD_RAW) != BD_AFTER:
        die('diff vs 04z: bound word in 04z1 final = %08x != %08x'
            % (w32be(fin, BD_RAW), BD_AFTER))
    if w32be(o4z, BD_RAW) != BD_BEFORE:
        die('diff vs 04z: 04z reference word @raw 0x%x = %08x != %08x (04z ref not '
            'stock at the site)' % (BD_RAW, w32be(o4z, BD_RAW), BD_BEFORE))
    say('[13c] diff 04z1 vs 04z: %d diff bytes, stray=%s; bound word @raw 0x%x '
        '%08x->%08x present' % (
            len(diffs_04z), stray_04z if stray_04z else 'NONE', BD_RAW,
            w32be(o4z, BD_RAW), w32be(fin, BD_RAW)))
    if stray_04z:
        die('stray diff bytes vs 04z (beyond bound word + CRC + 0x30): %s' % stray_04z[:16])

    # [14/G9] final == step1 outside 0x30 intent zones
    e30s = mlxfwutil.Image(step1, 'step1').find_entry('ITOC', 0x30)
    a3 = img_fin.sec_abs(e30n)
    g9_allowed = set(range(a3, a3 + max(e30s.size, e30n.size)))
    g9_allowed |= set(range(ent_off30, ent_off30 + 32))
    g9_diffs = [i for i in range(len(step1)) if step1[i] != fin[i]]
    g9_stray = [hex(i) for i in g9_diffs if i not in g9_allowed]
    say('[14/G9] final == step1 outside 0x30 intent zones: %d bytes differ, stray=%s'
        % (len(g9_diffs), g9_stray if g9_stray else 'NONE'))
    if g9_stray:
        die('[G9] stray: %s' % g9_stray[:16])

    # [15/G6] mstflint verify bootable
    r = subprocess.run(['mstflint', '-i', out, 'verify'], capture_output=True, text=True)
    say('[15/G6] mstflint verify: rc=%d' % r.returncode)
    say('    ' + ' | '.join(l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()))
    if r.returncode != 0:
        die('mstflint verify failed')

    # [16/G7b] mstflint q identity
    r = subprocess.run(['mstflint', '-i', out, 'q'], capture_output=True, text=True)
    say('[16/G7b] mstflint q:')
    ok16 = {}
    for l in (r.stdout + r.stderr).splitlines():
        if any(k in l for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC')):
            say('    ' + l.strip())
        for k, v in (('Image type', 'FS3'), ('FW Version', EXPECT_FW),
                     ('PSID', EXPECT_PSID), ('Base GUID', EXPECT_GUID[2:]),
                     ('Base MAC', EXPECT_MAC[2:])):
            if l.startswith(k):
                ok16[k] = v in l
    for k, v in ok16.items():
        if not v:
            die('identity check failed: %s' % k)
    if not all(k in ok16 for k in ('Image type', 'FW Version', 'PSID', 'Base GUID', 'Base MAC')):
        die('identity lines missing in q output')

    # [17/G8b] mstflint dc: build-ID is the first content line
    r = subprocess.run(['mstflint', '-i', out, 'dc'], capture_output=True, text=True)
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
    say('[17/G8b] mstflint dc: build-ID is the first content line (line %d of dc):' % (mi + 1))
    say('    ' + dl[mi])

    LOG = out.replace('.bin', '-build.log')
    open(LOG, 'w').write('\n'.join(lines_out) + '\n')
    say('DONE %s md5=%s size=%d log=%s' % (out, md5_out, len(fin), LOG))
    return md5_out


def parse_args():
    p = argparse.ArgumentParser(
        description='build the c1 04z1 image (04z + bound word 0x243cac '
                    '14a60009->14a67fff, variant V2a)')
    p.add_argument('--base', default=REPO + '/build/c1-00-ri.bin')
    p.add_argument('--base-md5', default=THEIR_RI_MD5, help='"none" to skip')
    p.add_argument('--out', default=REPO + '/build/cx4lx-04z1-bound.bin')
    args = p.parse_args()
    return args


def main():
    args = parse_args()
    # build-ID per plan T6c (literal): the ref is the 04z md5 prefix
    build_id = ('; mlxini cx4lx-04z1-bound (2026-10-14, 8c4a097f): '
                '04z + bounded-wait bound 0x9->0x7fff (dc 0x243cac)')

    md5_1 = run_build(args.out, args.base, args.base_md5, build_id)

    # [18/G10] determinism: a second full build must be byte-identical
    det_out = args.out + '.det2'
    md5_2 = run_build(det_out, args.base, args.base_md5, build_id)
    for p in (det_out, det_out + '.step1',
              det_out.replace('.bin', '-ini-final.ini'),
              det_out.replace('.bin', '-build.log')):
        if os.path.exists(p):
            os.unlink(p)
    say_det = ('[18/G10] determinism: build#1 md5=%s; build#2 md5=%s -> %s'
               % (md5_1, md5_2, 'IDENTICAL' if md5_1 == md5_2 else 'DIVERGED'))
    print(say_det)
    if md5_1 != md5_2:
        die('determinism gate failed: %s != %s' % (md5_1, md5_2))
    LOG = args.out.replace('.bin', '-build.log')
    with open(LOG, 'a') as f:
        f.write(say_det + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
