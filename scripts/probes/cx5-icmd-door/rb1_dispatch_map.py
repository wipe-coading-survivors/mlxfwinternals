#!/usr/bin/env python3
"""cx5 icmd-door R-B1: anchor recon on ConnectX-5 FW 16.35.4030 (offline).

Fixes anchor facts reproducibly (plan 2026-10-18-cx5-icmd-door-rb, Task 1;
spec 2026-10-18-cx5-icmd-door-design):
  [G1] base image md5 a8c60c90... (live base pinned)
  [G2] ITOC 0x03 MAIN_CODE clcrc round-trip (0 bad-CRC, wrap(unwrap)==raw)
  [G3] MAIN_CODE geometry: de-clcrc 941936 words (0xE5F70) = 0x397dc0 bytes;
       dc unit = byte offset into de-clcrc buffer (decoder convention), so the
       cutoff is dc in [0, 0x397dc0) bytes == [0, 0xE5F70) words; code/data
       extent via the recount-codehist window classifier
  [G4] anchor strings present in MAIN_CODE: icmd_generic_reg_access (str_rt
       0xb4ab27), isr_icmd (str_rt 0xb7fe75); optional mailbox-class string
  [G5] both tsv anchors reproduced on the base (trace-sites.tsv rows 600/609):
       string at dc(str_rt-0x800000) + call-word decode-verify at site
       (0x106390/0x107884 -> call 0x1b15c) + class/level words
  [XV] string xrefs: every address-load of an anchor string is a verified
       addi/addi.hi composition resolving to exactly its rt (L4 6.5 method),
       linked to an emit call of wrapper 0x1b15c; tsv sites among them
  [RD] badc0ffe reader @dc 0x1076f0 (FUN_001076f0, docs/250-re/120-irisc/025-boot-injection.md): set-pair
       0xbadc/0x0ffe, ld.i r6,0x8fc @0x1076f8, subs check; census over the
       whole MAIN_CODE is gated: imm-form slot 0x8fc refs == 1 (the reader)
       and EA-form 0x23f0 refs == 0
Plus (obs, non-gating - stop conditions stay on the anchors G4/G5/XV/RD):
 cluster function map 0x105c00-0x108400 (door candidate 0x1077f0 obs)
 and the reg-access chain draft 0x106350 -> classifier 0x105d08 (ranges
 0x900f/0x402d/0x5050 + table rt 0xbabd28) -> flash 0x106148 / regular
 0x105ec4 dispatchers (forms-of-access draft for Task 3 gate G10).
Task 2 (this run) adds, additively:
  [G6] door triad: fn 0x1077f0 [0x1077f0..0x1079dc) contains the isr_icmd
       trace site 0x107884; CR doorbell slot 0x8ff (ld.i r19,0x8ff
       @0x107814, census whole image: 1 ld.i / 0 st.i); door word semantics
       bit0=valid, bit1=extm, hi16=opcode (L4 lo16 hypothesis REFUTED on
       4030); entry: exactly one caller = lock trampoline 0x1f2154
       (call @0x1f2174, lock 0x1e714/unlock 0x1e718), itself referenced
       only by a data rt-pointer @dc 0x391588 (ROM/iron registration analog)
  [G7] validation: door -> validate 0x1072f0 (w0x457 bit1 + CR 0x23f4
       gates) -> whitelist 0x1071a0 (sole caller census=1): ranges
       0x9002/0x83ff/-0x8004/-0x8400 composes, literal 0x2831, bitmask
       1<<(op-0x9003) & 0xe000000d, second bitmask 1<<(op-0x74) &
       0x10000401, fallback w0x457 bit3; 0x9001 EXPLICITLY allowed
       (set3 r6,r6,0x9001 @0x1072c8 -> allow-exit @0x1072e0) - no
       contradiction with the v5r live fact
  [G8] dispatcher 0x107488 (door call @0x107988, census=1): range cascade
       + jump tables (rt entries, shl64.i x4 + lw.r + ret.r no-link):
       [0x8400..0x8405] @dc 0x38bdd4, [0x9001..0x9006] @dc 0x38bdec,
       [0x8004..0x8007] @dc 0x38bdc4; equality handlers 0x9020/0x9021/
       0x9022/0xf003; 0x9001 handler block 0x10751c -> call reg-access
       0x106350 (sole caller census=1) - door->dispatcher->handler->reg
       chain unbroken
  [G9] CR window (0x2000..0x23fc <-> slots 0x800..0x8ff): ld.i/st.i slot
       counters over the code region (st.i into window gated to 0); EA-form
       window refs verified (inline copy-loop 0x2014+ @0x105f74, extm pair
       0x23e8/0x23ec @0x1073fc -> slots 0x8fa/0x8fb occupied via EA, handler
       point-reads); offset-form 0x2000 hits with non-window base excluded
       (L4 6.5 noise class, e.g. st.d r9,r10,0x2000 @0x2bf02c); window
       boot-init fn 0x105668 (zero 0x2000..0x2020 + default words from
       rt 0xcd80/0xc9a4) invoked solely as door command 0x8007 (census=1);
       full zone table, slot 0x8fe (CR 0x23f8) zero refs in all forms,
       reserves 0x8c5-0x8cf/0x8d1-0x8d3/0x8d5-0x8f9 (mapped status unknown)
  [LY] layer connectivity (Review Focus 1): reg handler reachable ONLY via
       door->dispatcher (censuses); mailbox fn 0x0e4250 [0x0e4250..0x0e4424)
       has 0 calls into the door cluster; S1-S3 mailbox facts listed as
       not-the-door; extm-mailbox fn 0x1073d4 (door extm branch, L4
       0xd4948 analog) mapped separately from the reg path
Task 3 (this run) adds, additively:
  [G10] forms-of-access in the reg handler chain (REGACC 0x106350,
        classifier 0x105d08, REGULAR 0x105ec4, FLASH 0x106148) - every form
        gated with instruction addresses + decoder-verified words:
        (1) ld.i-imm header reads from window slots (0x801 hdr/reg_id,
        0x800/0x804 flash addr+size);
        (2) EA copy-loops window->stack: regular ld.d r6,r4,0x2014
        @0x105f74 (whole inline zone 0x2014..0x2313, 0x300 B), flash
        ld.d r7,r4,0x0 @0x106194 base 0x2000 @0x106184 (r22 words);
        (3) stack staging: regular frame 0x6c8 with staging buffer
        [r1+0x3a0..0x6ac) (0x30c B) + output buffer [r1+0x90..0x3a0),
        flash frame 0x140 with copy at [r1+0x14+);
        (4) RESPONSE write-backs stack->window via st.d! walking-base
        loops (NOT visible to the constant-offset EA scan of G9):
        regular WB-A @0x1060b4 (dest 0x2014+[r1+0x34], count [r1+0x38]>>2
        words) and WB-B @0x1060f8 (dest 0x2014..0x2310 = whole inline
        zone), flash WB @0x106230 (dest from 0x2000, r22 words).
        st.d! semantics per slaspec: store [rs+imm] then rs += imm
        (post-increment; cross-checked vs window-init zeroing 0x2000..0x2020).
        VERDICT R-B2 = (a) window-inline: handler reads the frame from
        window words (ld.i slots + EA copy-loops) and writes the response
        back into the window; stack holds derived working copies only
        (window->stack->window hierarchy, no interpretation conflict -
        Review Focus 5 outcome (v) not triggered). NB obs ISA note: the
        loop-counter idiom subi rX,rY,0x0 / addi rX,rX,0x1 / while rX!=0
        (20 sites) only terminates for subi = imm - rs (reverse subtract;
        slaspec line has it as rs - imm) - recorded as an I-track
        correction candidate; the gate checks words bit-exactly and does
        not depend on subi direction.
Log: build/cx5-icmd-door-rb1.log
"""
import hashlib
import re
import struct
import sys
from collections import Counter
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WT))
sys.path.insert(0, str(WT / 'scripts/irisc'))
import mlxfwutil
import irisc_dis

BASE = WT / 'refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin'
LOG = WT / 'build/cx5-icmd-door-rb1.log'
BASE_MD5 = 'a8c60c90473078288b01009c7cad471b'
RAW_MD5 = 'bcfe0526b43de4abf324b5056f91c112'
RT = 0x800000
MAIN_WORDS = 941936
MAIN_BYTES = MAIN_WORDS * 4
ITOC3_SIZE = 0x3d15a0
ITOC3_ADDR = 0x1c748

EMIT_A2 = 0x1b15c
ANCHORS = [
    dict(name='icmd_generic_reg_access', site=0x106390, target=0x1b15c,
         str_rt=0xb4ab27, cls=0x4000000, level=1,
         text=b'icmd_generic_reg_access: reg_is_flash_reg_access=%d, register_id=0x%.4x'),
    dict(name='isr_icmd', site=0x107884, target=0x1b15c,
         str_rt=0xb7fe75, cls=0x4000000, level=0,
         text=b'isr_icmd, opcode=0x%x, extm=%d, '),
]
READER = 0x1076f0
MBX_TEXT = b'icmd_mailbox_access_over_external_memory'
CL_LO, CL_HI = 0x105c00, 0x108400
FN_NOTES = {
    0x105d08: 'is_flash-classifier cand (L4 0xd31b8 analog)',
    0x105ec4: 'regular dispatcher cand (L4 0xd3388 analog)',
    0x106148: 'flash dispatcher cand (L4 0xd3600 analog)',
    0x106350: 'reg-access fn (L4 0xd3804 analog; tsv site 0x106390)',
    0x1077f0: 'door candidate (tsv site 0x107884; Task 2 gates the triad)',
}

DOOR = 0x1077f0
DOOR_HI = 0x1079dc
DOOR_NEXT = 0x107a08
TRAMP = 0x1f2154
TRAMP_CALL = 0x1f2174
TRAMP_LOCK = 0x1e714
TRAMP_UNLOCK = 0x1e718
TRAMP_PTR = 0x391588
VALIDATE = 0x1072f0
EXECW = 0x107374
WHITELIST = 0x1071a0
DISPATCH = 0x107488
DISP_CALL = 0x107988
REGACC = 0x106350
HANDLER_9001 = 0x10751c
EXTM_FN = 0x1073d4
WINIT = 0x105668
MBX_FN, MBX_HI = 0x0e4250, 0x0e4424
REGACC_CLASSIFIER = 0x105d08
REGACC_REGULAR = 0x105ec4
REGACC_FLASH = 0x106148
JTABLES = [
    dict(name='A', base=0x8400, dc=0x38bdd4, cnt=6, lo=0x1074c0),
    dict(name='B', base=0x9001, dc=0x38bdec, cnt=6, lo=0x107508),
    dict(name='C', base=0x8004, dc=0x38bdc4, cnt=4, lo=0x107540),
]
NAMED_SLOTS = {
    0x800: ('eff.opcode / flash addr', 373),
    0x801: ('hdr reg_id<<16 | method/len', 112),
    0x802: ('hdr/sizes', 41),
    0x803: ('hdr/sizes', 23),
    0x804: ('flash size bits (CR 0x2010)', 35),
    0x8fa: ('extm-mailbox addr pair (EA form)', 0),
    0x8fb: ('extm-mailbox addr pair (EA form)', 0),
    0x8fc: ('unlock marker (badc0ffe reader)', 1),
    0x8fd: ('flash semaphore (CR 0x23f4)', 41),
    0x8fe: ('FREE - zero refs in all forms', 0),
    0x8ff: ('doorbell (CR 0x23fc, bit0 valid)', 1),
}
INLINE_LO, INLINE_HI = 0x805, 0x8c4
MBX_FACTS = [
    'fn 0x0e4250 [0x0e4250..0x0e4424) - cmdq/mailbox machine (QUERY-path analog)',
    'call-site 0x0e437c, FN_A 0x18d964, wrapper 0x18d8b0 (plan GC S1-S3)',
    'mailbox frame = RAM stack copy [r1+0x98+k] (S3-T3) - cmdq layer fact',
]

KNOWN30 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
           0x0b, 0x0c, 0x0e, 0x12, 0x13, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
           0x1e, 0x25, 0x28, 0x29, 0x2a, 0x2b, 0x32, 0x3f}
PRINTABLE = set(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
W_N, S_N = 64, 8
TH_ZERO, TH_ASCII, TH_KNOWN, TH_MONO, TH_ANCH = 0.25, 0.30, 0.62, 0.85, 2


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


class Ctx:
    o = None
    xrefs = None


def fail(o, msg):
    o('FATAL: ' + msg)
    LOG.write_text('\n'.join(o.lines) + '\n')
    sys.exit(1)


def rt_of(dc):
    return dc + RT


def dc_of(rt_addr):
    return rt_addr - RT


def in_main(dc):
    return 0 <= dc < MAIN_BYTES


def dec_at(c, dc):
    return c.dec[dc // 4]


def chk(c, off, want, why, strict=True):
    got = dec_at(c, off)
    if got != want:
        msg = '%s @0x%x: "%s" != "%s"' % (why, off, got, want)
        if strict:
            fail(c.o, msg)
        c.o('[obs-MISS] ' + msg)
        return False
    return True


def code_mask(words, n):
    def feats(w):
        op = w >> 26
        rs, rd = (w >> 21) & 0x1f, (w >> 16) & 0x1f
        b = (w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, (w >> 24) & 0xff)
        is_zero = w == 0
        is_str = all(x in PRINTABLE or x == 0 for x in b) and \
            sum(x in PRINTABLE for x in b) >= 3
        is_call = op == 0x25 and not (w >> 24) & 1
        is_ret = op == 0x3f and (w & 0x1ff) in (0x25, 0x2d)
        is_plg = op == 0x12 and not (w >> 25) & 1 and (w & 0x7ff) == 0xbc and rd != 0
        is_epl = op == 0x13 and (w & 0x7ff) == 0xbc
        is_frm = op == 0x1c and rs == 1
        return op, is_zero, is_str, is_call, is_ret, is_plg, is_epl, is_frm

    ft = [feats(w) for w in words]
    ops = [f[0] for f in ft]
    known = [1 if o in KNOWN30 else 0 for o in ops]
    zero = [1 if f[1] else 0 for f in ft]
    astr = [1 if f[2] else 0 for f in ft]
    anch = [1 if (f[3] or f[4] or f[5] or f[6] or f[7]) else 0 for f in ft]
    functs = [(w & 0x1ff) if o == 0x3f else None for o, w in zip(ops, words)]
    votes = [0] * n
    cover = [0] * n
    for start in range(0, n - W_N + 1, S_N):
        sl = slice(start, start + W_N)
        na = sum(anch[sl])
        top_op, top_cnt = Counter(ops[sl]).most_common(1)[0]
        mono = top_cnt / W_N >= TH_MONO
        if mono and top_op == 0x3f:
            fs = {f for f in functs[sl] if f is not None}
            mono = len(fs) <= 3
        is_code = not (sum(zero[sl]) / W_N >= TH_ZERO
                       or sum(astr[sl]) / W_N >= TH_ASCII
                       or (mono and na < TH_ANCH)
                       or (sum(known[sl]) / W_N < TH_KNOWN and na < TH_ANCH))
        for i in range(start, start + W_N):
            cover[i] += 1
            if is_code:
                votes[i] += 1
    return [votes[i] * 2 >= cover[i] for i in range(n)]


def gate_g1_g2_g3(c):
    o = c.o
    buf = BASE.read_bytes()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail(o, 'base md5 mismatch')
    o('[G1] base md5 OK (%s, %d B)' % (BASE_MD5, len(buf)))
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', 0x03)
    raw = img.section_data(e)
    if not (e.size == ITOC3_SIZE and e.addr == ITOC3_ADDR and e.clcrc == 1
            and e.param0 == RT):
        fail(o, 'ITOC03 params: size=%#x addr=%#x clcrc=%s p0=%#x'
             % (e.size, e.addr, e.clcrc, e.param0))
    if hashlib.md5(raw).hexdigest() != RAW_MD5:
        fail(o, 'MAIN_CODE raw md5 mismatch')
    errs = mlxfwutil.clcrc_lines_errors(raw)
    if errs:
        fail(o, 'clcrc bad lines: %d (first %s)' % (len(errs), errs[0]))
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw:
        fail(o, 'clcrc round-trip mismatch')
    o('[G2] clcrc round-trip OK: %d lines 0 bad-CRC, wrap(unwrap)==raw '
      '(%#x B), tail=%s' % (len(raw) // 68, len(raw), tail.hex()))
    if len(code) != MAIN_BYTES or len(code) // 4 != MAIN_WORDS:
        fail(o, 'MAIN_CODE geometry: %#x B / %d words' % (len(code), len(code) // 4))
    n = len(code) // 4
    c.img, c.raw, c.code, c.tail, c.n = img, raw, code, tail, n
    c.words = struct.unpack('>%dI' % n, code)
    c.dec = [irisc_dis.dis(w, i * 4) for i, w in enumerate(c.words)]
    c.mask = code_mask(c.words, n)
    ncode = sum(c.mask)
    o('[G3] MAIN_CODE geometry OK: %d words (0x%x) == 0x%x B; dc unit = byte '
      'offset, cutoff dc in [0, 0x%x); code region %d words (%.1f%%), '
      'rt = dc + 0x%x'
      % (n, MAIN_WORDS, MAIN_BYTES, MAIN_BYTES, ncode, 100.0 * ncode / n, RT))


def gate_g4(c):
    o = c.o
    for a in ANCHORS:
        needle = a['text'][:24]
        found = []
        i = c.code.find(needle)
        while i != -1:
            found.append(i)
            i = c.code.find(needle, i + 1)
        if not found:
            fail(o, 'anchor string not found in MAIN_CODE: %r' % a['text'][:32])
        for dc in found:
            if not in_main(dc):
                fail(o, 'string hit outside geometry: %#x' % dc)
        a['str_dcs'] = found
        o('[G4] %-26s %d hit(s): %s (data-region=%s)'
          % (a['name'], len(found),
             ' '.join('dc=%#x rt=%#x' % (dc, rt_of(dc)) for dc in found),
             not c.mask[found[0] // 4]))
    i = c.code.find(MBX_TEXT)
    if i != -1:
        o('[G4] optional mailbox-class string: dc=%#x rt=%#x (cmdq layer, '
          'not the door; do not extrapolate)' % (i, rt_of(i)))
    else:
        o('[G4] optional mailbox-class string: not found (informational)')


def gate_g5(c):
    o = c.o
    for a in ANCHORS:
        sdc = dc_of(a['str_rt'])
        if not in_main(sdc):
            fail(o, 'str_rt %#x -> dc %#x outside MAIN_CODE' % (a['str_rt'], sdc))
        if c.code[sdc:sdc + len(a['text'])] != a['text']:
            fail(o, 'string at dc %#x (str_rt %#x): %r'
                 % (sdc, a['str_rt'], c.code[sdc:sdc + 40]))
        if not in_main(a['site']):
            fail(o, 'site %#x outside MAIN_CODE' % a['site'])
        chk(c, a['site'], 'call 0x%x' % a['target'], '%s tsv call-site' % a['name'])
        chk(c, a['site'] - 0x10, 'set2 r4,zero,0x%x' % (a['cls'] >> 16),
            '%s class word' % a['name'])
        chk(c, a['site'] - 0x0c, 'addi r5,zero,0x%x' % a['level'],
            '%s level word' % a['name'])
        o('[G5] %-26s reproduced: str @dc %#x (rt %#x), call 0x%x @site %#x, '
          'class %#x (set2 hi16) + level %d words verified'
          % (a['name'], sdc, a['str_rt'], a['target'], a['site'], a['cls'],
             a['level']))


def compose_hits(c, rt_addr):
    lo = rt_addr & 0xffff
    slo = lo - 0x10000 if lo & 0x8000 else lo
    hi_c = (rt_addr >> 16) + (1 if lo & 0x8000 else 0)
    out = []
    for i in range(c.n - 2):
        if not c.mask[i]:
            continue
        d0, d1 = c.dec[i], c.dec[i + 1]
        m = re.match(r'^addi (r\d+),zero,(0x-?[0-9a-f]+)$', d0)
        if m and int(m.group(2)[2:], 16) == slo:
            m1 = re.match(r'^addi\.hi (r\d+),(r\d+),0x([0-9a-f]+)$', d1)
            if m1 and m1.group(2) == m.group(1) and int(m1.group(3), 16) == hi_c:
                out.append((i * 4, 'addi/addi.hi -> %s' % m1.group(1)))
                continue
        m = re.match(r'^set2 (r\d+),zero,0x([0-9a-f]+)$', d0)
        if m and int(m.group(2), 16) == (rt_addr >> 16):
            m1 = re.match(r'^set3 (r\d+),(r\d+),0x([0-9a-f]+)$', d1)
            if m1 and m1.group(2) == m.group(1) and int(m1.group(3), 16) == lo:
                out.append((i * 4, 'set2/set3 -> %s' % m1.group(1)))
    return out


def gate_xv(c):
    o = c.o
    calls = [i * 4 for i in range(c.n)
             if c.mask[i] and c.dec[i] == 'call 0x%x' % EMIT_A2]
    if not calls:
        fail(o, 'no call sites of wrapper 0x%x in code region' % EMIT_A2)
    chk(c, EMIT_A2, 'csr.r r3,csr0xbc', 'emit wrapper prologue')
    verified = 0
    for a in ANCHORS:
        hits = compose_hits(c, a['str_rt'])
        if not hits:
            fail(o, 'no verified load of %s (rt %#x) in code region'
                 % (a['name'], a['str_rt']))
        loads = []
        emit_sites = []
        for off, form in hits:
            emit = [w for w in range(off + 8, off + 0x24, 4)
                    if dec_at(c, w) == 'call 0x%x' % EMIT_A2]
            if len(emit) != 1:
                fail(o, 'xref @%#x of %s: %d emit calls nearby'
                     % (off, a['name'], len(emit)))
            loads.append(off)
            emit_sites.append(emit[0])
            mark = ' (tsv site)' if emit[0] == a['site'] else ''
            o('[XV] %-26s load @dc %#x [%s] -> emit call @dc %#x%s'
              % (a['name'], off, form, emit[0], mark))
            verified += 1
        if a['site'] not in emit_sites:
            fail(o, 'tsv site %#x not linked to an xref of %s' % (a['site'], a['name']))
        c.xrefs[a['name']] = loads
    o('[XV] wrapper 0x%x: %d call sites in code region; anchor string xrefs '
      '%d/%d with decoder-verified load instructions (100%%)'
      % (EMIT_A2, len(calls), verified, verified))


def gate_rd(c):
    o = c.o
    if not in_main(READER):
        fail(o, 'reader dc %#x outside MAIN_CODE' % READER)
    for off, want, why in [
            (0x1076f0, 'set2 r4,zero,0xbadc', 'reader: set-pair hi 0xbadc'),
            (0x1076f4, 'set3 r5,r4,0xffe', 'reader: set-pair lo 0x0ffe (rs=rd OR)'),
            (0x1076f8, 'ld.i r6,0x8fc', 'reader: slot 0x8fc read (docs/250-re/120-irisc/025-boot-injection.md)'),
            (0x107700, 'subs r5,r5,r6', 'reader: equality check'),
            (0x10770c, 'ret.d zero,zero,zero', 'reader: leaf ret'),
            (0x107710, 'csr.r r3,csr0xbc', 'next fn prologue (bounds the leaf)')]:
        chk(c, off, want, why)
    refs = []
    for i in range(c.n):
        d = c.dec[i]
        m = re.match(r'^(ld|st)\.i (?:r\d+|zero),0x([0-9a-f]+)$', d)
        if m and int(m.group(2), 16) == 0x8fc:
            refs.append((i * 4, d))
    ea = [(i * 4, c.dec[i]) for i in range(c.n)
          if c.dec[i].startswith(('ld.', 'st.'))
          and not c.dec[i].startswith(('ld.i', 'st.i'))
          and c.dec[i].endswith(',0x23f0')]
    if len(refs) != 1 or refs[0][0] != 0x1076f8:
        fail(o, 'slot 0x8fc census: %s' % refs)
    if ea:
        fail(o, 'EA 0x23f0 refs must be zero (docs/250-re/120-irisc/025-boot-injection.md single access): %s' % ea)
    o('[RD] badc0ffe reader @dc %#x verified vs docs/250-re/120-irisc/025-boot-injection.md: set2/set3 '
      '0xbadc/0x0ffe (r5=0xbadc0ffe), ld.i r6,0x8fc @0x1076f8, subs; slot '
      '0x8fc census over whole MAIN_CODE (gated): %d imm-form ref (reader '
      'only), EA 0x23f0 refs: %d (must be 0)' % (READER, len(refs), len(ea)))


def fn_starts(c):
    return [off for off in range(CL_LO + 4, CL_HI, 4)
            if c.dec[off // 4] == 'csr.r r3,csr0xbc'
            and c.dec[(off - 4) // 4].startswith(('ret', 'jump '))]


def map_cluster(c):
    o = c.o
    starts = fn_starts(c)
    o('[MAP] cluster function map (prologue csr.r r3,csr0xbc after ret/jump; '
      'dc range %#x-%#x, %d fns + 1 leaf):' % (CL_LO, CL_HI, len(starts)))
    for s in starts:
        o('  fn %#x%s' % (s, ' <- ' + FN_NOTES[s] if s in FN_NOTES else ''))
    o('  leaf %#x <- badc0ffe reader (no prologue, ret.d @0x10770c)' % READER)
    for a in ANCHORS:
        owner = max([s for s in starts if s <= a['site']], default=None)
        o('  tsv site %#x contained in fn %#x' % (a['site'], owner))
    for off in (0x106350, 0x1077f0):
        chk(c, off, 'csr.r r3,csr0xbc', 'anchor-fn prologue', strict=False)
    obs = [
        (0x107814, 'ld.i r19,0x8ff', 'door-cand: doorbell CR 0x23fc (word 0x8ff)'),
        (0x10784c, 'subsi r4,r18,0x2820', 'door-cand: ACCESS_REG 0x2820 test'),
        (0x107868, 'ld.i r21,0x800', 'door-cand: eff.opcode from CR 0x2000'),
        (0x10788c, 'call 0x1072f0', 'door-cand: call A (validate/exec cand, Task 2)'),
        (0x1078a0, 'call 0x107374', 'door-cand: call B (validate/exec cand, Task 2)')]
    ok = all([chk(c, off, want, why, strict=False) for off, want, why in obs])
    o('[MAP] door candidate fn %#x (contains isr_icmd site %#x): doorbell '
      'machine words %s (obs; Task 2 gates the triad)'
      % (0x1077f0, 0x107884, 'verified' if ok else 'PARTIAL - see obs-MISS'))


def map_reg_chain(c):
    o = c.o
    calls = [(off, dec_at(c, off)) for off in range(0x106350, 0x1063c4, 4)
             if dec_at(c, off).startswith('call ')]
    ok = all([chk(c, off, want, why, strict=False) for off, want, why in [
            (0x106364, 'ld.i r4,0x801', 'regacc: CR 0x2004 hdr read'),
            (0x106368, 'shr r23,r4,0x10', 'regacc: reg_id = word>>16'),
            (0x106370, 'call 0x105d08', 'regacc: classifier call'),
            (0x106390, 'call 0x1b15c', 'regacc: emit call (tsv site)'),
            (0x1063a0, 'call 0x106148', 'regacc: flash dispatcher'),
            (0x1063ac, 'call 0x105ec4', 'regacc: regular dispatcher'),
            (0x105d14, 'set3 r6,r6,0x900f', 'classifier: range 0x900f'),
            (0x105d20, 'subsi r6,r5,0x402d', 'classifier: reg 0x402d'),
            (0x105d28, 'subsi r6,r5,0x5050', 'classifier: reg 0x5050'),
            (0x105d5c, 'addi r5,zero,0x-42d8', 'classifier: table ptr lo (rt 0xbabd28)'),
            (0x105d60, 'addi.hi r5,r5,0xb9', 'classifier: table ptr hi'),
            (0x105d68, 'lw.r r5,r6,r5', 'classifier: table load'),
            (0x105d6c, 'ret.r zero,r8,r5', 'classifier: tail jump'),
            (0x10615c, 'ld.i r4,0x800', 'flash: addr bits CR 0x2000'),
            (0x106164, 'ld.i r5,0x804', 'flash: size bits CR 0x2010'),
            (0x106184, 'addi r4,zero,0x2000', 'flash: window base 0x2000'),
            (0x106194, 'ld.d r7,r4,0x0', 'flash: window EA read'),
            (0x106198, 'st.d! r7,r6,0x4', 'flash: -> stack copy [r1+0x14]'),
            (0x105ee8, 'addi r20,r1,0x3a0', 'regular: staging base [r1+0x3a0]'),
            (0x105eec, 'addi r4,r20,0x30c', 'regular: staging len 0x30c')]])
    o('[CHAIN] reg-access fn 0x106350 calls: %s (chain words %s; obs/draft - '
      'non-gating, Task 3 gate G10 formalizes)'
      % (', '.join('%#x=%s' % (off, d[5:]) for off, d in calls),
         'verified' if ok else 'PARTIAL - see obs-MISS'))
    o('[CHAIN] draft map (L4 1.4 analog): 0x106350 (hdr CR 0x2004, reg_id '
      'word>>16) -> classifier 0x105d08 (ranges 0x900f/0x402d/0x5050/0x900a '
      'match L4 is_flash literally; table @rt 0xbabd28 = dc 0x3abd28, '
      'lw.r+ret.r) -> flash 0x106148 (CR 0x2000/0x2010; window EA 0x2000+ '
      'read -> stack) | regular 0x105ec4 (stack staging 0x30c B @ [r1+0x3a0])')
    o('[CHAIN] forms-of-access DRAFT (Task 3 gate G10 decides): flash path '
      'reads frame words from window EA 0x2000+; regular path stages 0x30c B '
      'on stack; both forms present in the two live paths - no verdict here')


def anchor_table(c):
    o = c.o
    o('[ANCHORS] summary (dc = byte offset in de-clcrc MAIN_CODE; rt = dc + 0x800000):')
    o('  %-26s %-9s %-9s %-9s %-9s %-9s %s'
      % ('anchor', 'str_dc', 'str_rt', 'load', 'emit', 'target', 'level/class'))
    for a in ANCHORS:
        load = c.xrefs[a['name']][0]
        o('  %-26s %-9s %-9s %-9s %-9s %-9s L%d/ICMD(%#x)'
          % (a['name'], hex(dc_of(a['str_rt'])), hex(a['str_rt']), hex(load),
             hex(a['site']), hex(a['target']), a['level'], a['cls']))
    o('  %-26s %-9s %-9s %-9s %-9s %-9s %s'
      % ('badc0ffe-reader', '-', '-', '-', hex(READER), '-', 'slot 0x8fc x1'))


def census(c, text, lo=None, hi=None):
    lo = 0 if lo is None else lo
    hi = c.n * 4 if hi is None else hi
    return [i * 4 for i in range(lo // 4, hi // 4) if c.dec[i] == text]


def imm_refs(c, slot):
    pat = re.compile(r'^(ld|st)\.i (?:r\d+|zero),0x%x$' % slot)
    return [(i * 4, c.dec[i]) for i in range(c.n) if pat.match(c.dec[i])]


def ea_refs(c, ea):
    out = []
    for i in range(c.n):
        d = c.dec[i]
        if d.startswith(('ld.', 'st.')) and not d.startswith(('ld.i', 'st.i')) \
                and d.endswith(',0x%x' % ea):
            out.append((i * 4, d))
    return out


def code_ea_refs(c, ea_lo, ea_hi):
    out = []
    for i in range(c.n):
        if not c.mask[i]:
            continue
        d = c.dec[i]
        if d.startswith(('ld.', 'st.')) and not d.startswith(('ld.i', 'st.i')):
            m = re.search(r',0x([0-9a-f]+)$', d)
            if m and ea_lo <= int(m.group(1), 16) < ea_hi:
                out.append((i * 4, int(m.group(1), 16), d))
    return out


def compose_rt(c, off):
    m0 = re.match(r'^addi (r\d+),zero,(0x-?[0-9a-f]+)$', dec_at(c, off))
    m1 = re.match(r'^addi\.hi (?:r\d+),%s,0x([0-9a-f]+)$' % m0.group(1),
                  dec_at(c, off + 4))
    if not (m0 and m1):
        return None
    return (int(m1.group(1), 16) << 16) + int(m0.group(2)[2:], 16)


def gate_g6(c):
    o = c.o
    for off, want, why in [
            (DOOR, 'csr.r r3,csr0xbc', 'door: fn prologue'),
            (0x107814, 'ld.i r19,0x8ff', 'door: doorbell CR 0x23fc read'),
            (0x107818, 'mask32 r4,r19,0x0,1', 'door: bit0 = valid'),
            (0x10781c, 'subsi r4,r4,0x0', 'door: valid test'),
            (0x107820, 'b.t.0x0 zero,0x1078e0', 'door: invalid -> early exit'),
            (0x107844, 'mask32 r18,r19,0x10,16', 'door: opcode = hi16 (L4 lo16 refuted)'),
            (0x107858, 'mask32 r23,r19,0x1,1', 'door: bit1 = extm'),
            (0x10784c, 'subsi r4,r18,0x2820', 'door: ACCESS_REG 0x2820 test'),
            (0x107868, 'ld.i r21,0x800', 'door: 0x2820 -> eff.opcode from CR 0x2000'),
            (0x10788c, 'call 0x%x' % VALIDATE, 'door: validate call'),
            (0x1078a0, 'call 0x%x' % EXECW, 'door: exec wrapper call'),
            (0x1078d8, 'csr.w zero,r5,0x1', 'door: completion csr 0x1'),
            (DOOR_NEXT, 'csr.r r3,csr0xbc', 'door: next fn prologue (bounds the fn)')]:
        chk(c, off, want, why)
    if not (DOOR <= ANCHORS[1]['site'] < DOOR_HI):
        fail(o, 'isr_icmd site %#x not inside door fn range' % ANCHORS[1]['site'])
    refs = imm_refs(c, 0x8ff)
    if len(refs) != 1 or refs[0][0] != 0x107814:
        fail(o, 'slot 0x8ff census: %s (want exactly the door read)' % refs)
    isr = ANCHORS[1]
    if not (DOOR <= c.xrefs['isr_icmd'][0] < DOOR_HI
            and DOOR <= isr['site'] < DOOR_HI):
        fail(o, 'isr_icmd xref/emit not inside door fn')
    calls = census(c, 'call 0x%x' % DOOR) + census(c, 'jump 0x%x' % DOOR)
    if len(calls) != 1 or calls[0] != TRAMP_CALL:
        fail(o, 'door entry scan: %s (want exactly the trampoline call)'
             % calls)
    if compose_hits(c, rt_of(DOOR)):
        fail(o, 'compose loads of door rt must be 0')
    if [i * 4 for i in range(c.n) if c.words[i] == rt_of(DOOR)]:
        fail(o, 'data rt-pointers to the door itself must be 0')
    for off, want, why in [
            (TRAMP, 'csr.r r3,csr0xbc', 'trampoline: fn prologue'),
            (TRAMP_CALL - 8, 'call 0x%x' % TRAMP_LOCK, 'trampoline: lock'),
            (TRAMP_CALL, 'call 0x%x' % DOOR, 'trampoline: door call'),
            (TRAMP_CALL + 0xc, 'call 0x%x' % TRAMP_UNLOCK, 'trampoline: unlock')]:
        chk(c, off, want, why)
    if census(c, 'call 0x%x' % TRAMP):
        fail(o, 'trampoline must have 0 code callers (registration by pointer)')
    if compose_hits(c, rt_of(TRAMP)):
        fail(o, 'compose loads of trampoline rt must be 0')
    ptrs = [i * 4 for i in range(c.n) if c.words[i] == rt_of(TRAMP)]
    if len(ptrs) != 1 or ptrs[0] != TRAMP_PTR or c.mask[TRAMP_PTR // 4]:
        fail(o, 'trampoline rt-pointers: %s (want exactly 1 in data region)'
             % ptrs)
    o('[G6] door triad verified: fn %#x [%#x..%#x) contains isr_icmd site '
      '%#x; CR doorbell slot 0x8ff (ld.i r19 @0x107814, census 1 ld.i / 0 '
      'st.i); door word = bit0 valid, bit1 extm, hi16 opcode (L4 1.1 lo16 '
      'hypothesis REFUTED on 4030); 0x2820 -> eff.opcode <- CR 0x2000; '
      'entry: 1 caller = lock trampoline %#x (call @%#x), 0 code callers, '
      '1 data rt-ptr @dc %#x (ROM/iron registration analog; L4 6.3 "0 refs" '
      'expectation refined, not contradicted)'
      % (DOOR, DOOR, DOOR_HI, ANCHORS[1]['site'], TRAMP, TRAMP_CALL, TRAMP_PTR))


def gate_g7(c):
    o = c.o
    for off, want, why in [
            (VALIDATE, 'csr.r r3,csr0xbc', 'validate: prologue'),
            (0x107310, 'ld.i r4,0x457', 'validate: RAM w0x457 bit1 gate'),
            (0x107318, 'b.bclr 1,r4,0x107338', 'validate: bit1-clear skip'),
            (0x10731c, 'ld.i r4,0x8fd', 'validate: CR 0x23f4 flash semaphore'),
            (0x10733c, 'call 0x%x' % WHITELIST, 'validate: whitelist call'),
            (0x107344, 'b.f.0x0 zero,0x107358', 'validate: whitelist!=0 -> plain return'),
            (EXECW, 'csr.r r3,csr0xbc', 'exec wrapper: prologue'),
            (0x10738c, 'ld.i r5,0x457', 'exec wrapper: w0x457 gate'),
            (0x107394, 'ld.i r22,0x8fd', 'exec wrapper: CR 0x23f4'),
            (WHITELIST, 'csr.r r3,csr0xbc', 'whitelist: prologue'),
            (0x1071b8, 'set3 r7,r6,0x9002', 'whitelist: range 0x9002'),
            (0x107220, 'set3 r6,r6,0x83ff', 'whitelist: range 0x83ff'),
            (0x10722c, 'set2 r6,zero,0xffff', 'whitelist: -0x8004 compose lo'),
            (0x107230, 'set3 r6,r6,0x7ffc', 'whitelist: -0x8004 compose hi'),
            (0x107240, 'subsi r6,r5,0x2831', 'whitelist: opcode 0x2831'),
            (0x1071d0, 'set2 r6,zero,0xffff', 'whitelist: -0x9003 compose lo'),
            (0x1071d4, 'set3 r6,r6,0x6ffd', 'whitelist: -0x9003 compose hi'),
            (0x1071e8, 'shl64.r r7,r7,r6', 'whitelist: bitmask 1<<(op-0x9003)'),
            (0x1071ec, 'set2 r8,zero,0xe000', 'whitelist: mask 0xe000000d hi'),
            (0x1071f0, 'set3 r8,r8,0xd', 'whitelist: mask 0xe000000d lo'),
            (0x1071f4, 'ands r7,r7,r8', 'whitelist: bitmask test'),
            (0x107254, 'set2 r6,zero,0xffff', 'whitelist: -0x74 compose lo'),
            (0x107258, 'set3 r6,r6,0x8c', 'whitelist: -0x74 compose hi'),
            (0x10726c, 'shl64.r r6,r7,r6', 'whitelist: bitmask 1<<(op-0x74)'),
            (0x107270, 'set2 r7,zero,0x100', 'whitelist: mask 0x10000401 hi'),
            (0x107274, 'set3 r7,r7,0x401', 'whitelist: mask 0x10000401 lo'),
            (0x107278, 'ands r6,r6,r7', 'whitelist: second bitmask test'),
            (0x10729c, 'ld.i r4,0x457', 'whitelist: fallback RAM w0x457'),
            (0x1072a0, 'mask32 r4,r4,0x3,1', 'whitelist: fallback bit3'),
            (0x1072c8, 'set3 r6,r6,0x9001', 'whitelist: 0x9001 EXPLICITLY allowed'),
            (0x1072e0, 'addi r4,zero,0x1', 'whitelist: allow-exit (r4=1)'),
            (0x1072d4, 'set3 r6,r6,0xf003', 'whitelist: opcode 0xf003')]:
        chk(c, off, want, why)
    if census(c, 'call 0x%x' % WHITELIST) != [0x10733c]:
        fail(o, 'whitelist must have exactly 1 caller (the validator)')
    o('[G7] validation verified: door -> validate %#x (w0x457 bit1 + CR '
      '0x23f4 gates) -> whitelist %#x (sole caller): ranges 0x9002/0x83ff + '
      '-0x8004/-0x8400 composes, literal 0x2831, bitmask 1<<(op-0x9003) & '
      '0xe000000d, second bitmask 1<<(op-0x74) & 0x10000401, fallback w0x457 '
      'bit3; 0x9001 EXPLICITLY allowed (set3 literal @0x1072c8 -> allow-exit '
      '@0x1072e0; polarity: whitelist 1 -> validate 0 -> door executes) - no '
      'contradiction with the v5r live fact (0x9001 markers => allowed)'
      % (VALIDATE, WHITELIST))


def gate_g8(c):
    o = c.o
    for off, want, why in [
            (DISPATCH, 'csr.r r3,csr0xbc', 'disp: prologue'),
            (0x107980, 'or r4,r21,r21', 'door->disp: arg r4 = eff.opcode'),
            (0x107984, 'or r5,r22,r22', 'door->disp: arg r5 = 0x2820 flag'),
            (DISP_CALL, 'call 0x%x' % DISPATCH, 'door->disp: call (sole)'),
            (0x1074a0, 'set3 r7,r6,0x9000', 'disp: range hi 0x9000'),
            (0x1074e8, 'set3 r6,r6,0x901f', 'disp: range 0x901f window'),
            (0x1074f4, 'set2 r6,zero,0xffff', 'disp: -0x9001 compose lo'),
            (0x1074f8, 'set3 r6,r6,0x6fff', 'disp: -0x9001 compose hi'),
            (0x107510, 'shl64.i r4,r4,0x2', 'disp: index x4'),
            (0x107514, 'lw.r r4,r4,r6', 'disp: table load'),
            (0x107518, 'ret.r zero,r8,r4', 'disp: no-link tail jump'),
            (0x107568, 'set2 r6,zero,0x0', 'disp: equality-handler cascade'),
            (0x1075a0, 'call 0x106f88', 'disp: op 0x9021 handler'),
            (0x107684, 'call 0x106e74', 'disp: op 0x9020 handler'),
            (0x107698, 'call 0x10707c', 'disp: op 0x9022 handler'),
            (0x1075d0, 'call 0x105518', 'disp: op 0xf003 handler'),
            (HANDLER_9001, 'addi r23,zero,0x0', 'handler 0x9001: entry'),
            (0x107524, 'b.f.0x0 zero,0x1076c8', 'handler 0x9001: flag gate'),
            (0x107528, 'call 0x%x' % REGACC, 'handler 0x9001: -> reg-access')]:
        chk(c, off, want, why)
    handlers = {}
    for t in JTABLES:
        got = compose_rt(c, t['lo'])
        if got != rt_of(t['dc']):
            fail(o, 'table %s compose @%#x -> rt %#x != %#x'
                 % (t['name'], t['lo'], got, rt_of(t['dc'])))
        for i in range(t['cnt']):
            v = c.words[(t['dc'] + 4 * i) // 4]
            dc = v - RT
            if not (0x1074d4 <= dc < 0x1076f0):
                fail(o, 'table %s entry %d: %#x not a dispatcher handler block'
                     % (t['name'], i, v))
            handlers[t['base'] + i] = dc
    if handlers.get(0x9001) != HANDLER_9001:
        fail(o, 'table B entry for 0x9001 must be %#x, got %#x'
             % (HANDLER_9001, handlers.get(0x9001)))
    if census(c, 'call 0x%x' % DISPATCH) != [DISP_CALL]:
        fail(o, 'dispatcher must have exactly 1 caller (the door)')
    if census(c, 'call 0x%x' % REGACC) != [0x107528]:
        fail(o, 'reg-access fn must have exactly 1 caller (the 0x9001 handler)')
    o('[G8] dispatcher verified: fn %#x (door call @%#x, sole; args '
      'eff.opcode + 0x2820-flag); range cascade + jump tables (rt entries, '
      'shl64.i x4 + lw.r + ret.r):' % (DISPATCH, DISP_CALL))
    for t in JTABLES:
        o('  table %s [%#06x..%#06x] @dc %#x (rt %#x): %s'
          % (t['name'], t['base'], t['base'] + t['cnt'] - 1, t['dc'],
             rt_of(t['dc']), ', '.join('%#06x->%#x' % (t['base'] + i,
                                                       handlers[t['base'] + i])
                                       for i in range(t['cnt']))))
    o('  equality handlers: 0x9020->0x106e74, 0x9021->0x106f88, '
      '0x9022->0x10707c, 0xf003->0x105518; fall-through -> r23=1 unhandled')
    o('  0x9001 path: table B[0] -> %#x -> call reg-access %#x (sole call '
      'site in the image); chain door@%#x -> disp -> handler -> reg-access '
      'UNBROKEN (all links decode-verified, censuses single-path)'
      % (HANDLER_9001, REGACC, DISP_CALL))


def gate_g9(c):
    o = c.o
    ld_cnt, st_cnt = {}, {}
    for i in range(c.n):
        if not c.mask[i]:
            continue
        d = c.dec[i]
        m = re.match(r'^ld\.i (?:r\d+|zero),0x([0-9a-f]+)$', d)
        if m:
            w = int(m.group(1), 16)
            ld_cnt[w] = ld_cnt.get(w, 0) + 1
        m = re.match(r'^st\.i (?:r\d+|zero),0x([0-9a-f]+)$', d)
        if m:
            w = int(m.group(1), 16)
            st_cnt[w] = st_cnt.get(w, 0) + 1
    win_st = {w: n for w, n in st_cnt.items() if 0x800 <= w <= 0x8ff}
    if win_st:
        fail(o, 'st.i into window slots (code region): %s' % win_st)
    for off, want, why in [
            (0x105f74, 'ld.d r6,r4,0x2014', 'window: inline-data copy base (regular disp)'),
            (0x105f80, 'subsi r6,r4,0x300', 'window: inline-data len 0x300 B'),
            (0x1073fc, 'ld.d r7,r5,0x23e8', 'window: extm-mailbox addr pair'),
            (0x106a64, 'ld.d r6,r4,0x2000', 'window: handler point-read base'),
            (0x106868, 'ld.d r5,r19,0x2018', 'window: handler read 0x2018'),
            (0x106f18, 'ld.d r6,r5,0x2008', 'window: handler read 0x2008'),
            (0x107130, 'ld.d r6,r5,0x2008', 'window: handler read 0x2008 (2)'),
            (WINIT, 'addi r4,zero,0x1ffc', 'window-init: zero-loop start'),
            (0x10566c, 'st.d! zero,r4,0x4', 'window-init: zero store (0x2000..0x2020)'),
            (0x10567c, 'set3 r5,zero,0xcd80', 'window-init: defaults table rt 0xcd80'),
            (0x105688, 'st.d r6,r4,0x2000', 'window-init: defaults -> 0x2000..0x200c'),
            (0x1056a8, 'addi r5,zero,0x2010', 'window-init: second zone base 0x2010'),
            (0x1056ac, 'set3 r6,zero,0xc9a4', 'window-init: defaults table rt 0xc9a4'),
            (0x1056b4, 'st.d! r7,r5,0x4', 'window-init: defaults -> 0x2010..0x201c'),
            (0x1076e8, 'call 0x%x' % WINIT, 'window-init: door command 0x8007 handler call')]:
        chk(c, off, want, why)
    if census(c, 'call 0x%x' % WINIT) != [0x1076e8]:
        fail(o, 'window-init must be invoked solely via door command 0x8007')
    if ea_refs(c, 0x23f8):
        fail(o, 'CR 0x23f8 (slot 0x8fe) EA refs must be 0')
    if imm_refs(c, 0x8fe):
        fail(o, 'CR 0x23f8 (slot 0x8fe) imm refs must be 0')
    if census(c, 'addi r4,zero,0x23f8') + census(c, 'addi r5,zero,0x23f8') \
            + census(c, 'addi r6,zero,0x23f8'):
        fail(o, 'CR 0x23f8 (slot 0x8fe) window-base compose refs must be 0')
    chk(c, 0x2bf02c, 'st.d r9,r10,0x2000', 'offset-form noise sample',
        strict=False)
    zones, reserves = [], []
    classified = 0
    for s in range(0x800, 0x900):
        n_ld = ld_cnt.get(s, 0)
        if s in NAMED_SLOTS:
            purpose, expect = NAMED_SLOTS[s]
            if s in (0x800, 0x801, 0x804, 0x8fc, 0x8fd, 0x8ff) and n_ld != expect:
                fail(o, 'slot %#x ld.i count %d != expected %d' % (s, n_ld, expect))
            zones.append((s, s, purpose, n_ld))
        elif INLINE_LO <= s <= INLINE_HI:
            zones.append((s, s, 'inline register data', n_ld))
        elif n_ld:
            zones.append((s, s, 'point read (handler)', n_ld))
        else:
            reserves.append(s)
        classified += 1
    if classified != 256:
        fail(o, 'window classification covered %d/256 slots' % classified)
    inline_ld = sum(n for lo, hi, p, n in zones
                    if p == 'inline register data')
    compact = []
    for lo, hi, purpose, n_ld in zones:
        if purpose == 'inline register data':
            if compact and compact[-1][2] == purpose and compact[-1][1] == lo - 1:
                compact[-1] = (compact[-1][0], hi, purpose,
                               compact[-1][3] + n_ld)
            else:
                compact.append((lo, hi, purpose, n_ld))
        else:
            compact.append((lo, hi, purpose, n_ld))
    if inline_ld != sum(n for lo, hi, p, n in compact
                        if p == 'inline register data'):
        fail(o, 'zone compaction lost inline-zone refs')

    def ranges(slots):
        out = []
        for s in slots:
            if out and s == out[-1][1] + 1:
                out[-1][1] = s
            else:
                out.append([s, s])
        return out

    ea_all = code_ea_refs(c, 0x2000, 0x2400)
    ea_win = [x for x in ea_all if x[0] < 0x110000]
    o('[G9] CR window (RAM 0x2000..0x23fc <-> slots 0x800..0x8ff): st.i into '
      'window 0 (imm-form stores: none - but the host is NOT the only '
      'window writer: FW response write-backs use walking-base st.d!, '
      'see G10 F4); '
      'slot 0x8fe (CR 0x23f8) zero refs in all forms; EA-scan code region '
      '%d hits, %d window-relevant (base zero/loop-counter, verified): '
      'inline copy 0x2014..0x2313 @0x105f74, extm pair 0x23e8/0x23ec '
      '@0x1073fc (slots 0x8fa/0x8fb occupied via EA - dual form matters), '
      'handler point-reads; offset-form 0x2000 hits with non-window base '
      'excluded (L4 6.5 noise class, e.g. st.d r9,r10,0x2000 @0x2bf02c)'
      % (len(ea_all), len(ea_win)))
    o('  window boot-init: fn %#x (L4 0xd2bf8 analog) - zero 0x2000..0x2020, '
      '4 default words from table rt 0xcd80 -> 0x2000..0x200c, 4 from rt '
      '0xc9a4 -> 0x2010..0x201c, csr 0x28/0x4/0x9 writes; invoked ONLY as '
      'door command 0x8007 (table C -> 0x1076dc -> call @0x1076e8)' % WINIT)
    o('  zone table (slot / CR / purpose / ld.i count):')
    for lo, hi, purpose, n_ld in compact:
        span = ('0x%03x' % lo) if lo == hi else ('0x%03x..0x%03x' % (lo, hi))
        cr = ('CR %#06x' % (lo * 4)) if lo == hi \
            else ('CR %#06x..%#06x' % (lo * 4, hi * 4))
        note = (' (copy-loop @0x105f74 reads 0x2014..0x2313 = whole zone)'
                if purpose == 'inline register data' else '')
        o('    %-13s %-19s %s%s  [%d ld.i]' % (span, cr, purpose, note, n_ld))
    o('  reserves (0 refs in imm+EA forms; mapped status UNKNOWN - live '
      'check is detour-spec domain): %s = %d slots'
      % (', '.join('0x%03x..0x%03x (CR 0x%x..0x%x)' % (a, b, a * 4, b * 4)
                   for a, b in ranges(reserves)), len(reserves)))
    o('[G9] PASS: full zone table - every slot 0x800..0x8ff classified '
      '(named / inline-data zone / point-read / reserve / door-protocol)')


def gate_layers(c):
    o = c.o
    for off, want, why in [
            (MBX_FN, 'csr.r r3,csr0xbc', 'mailbox fn: prologue'),
            (MBX_HI, 'csr.r r3,csr0xbc', 'mailbox fn: next prologue bounds it')]:
        chk(c, off, want, why)
    bad = []
    for i in range(MBX_FN // 4, MBX_HI // 4):
        m = re.match(r'^call 0x([0-9a-f]+)$', c.dec[i])
        if m:
            t = int(m.group(1), 16)
            if CL_LO <= t < CL_HI or t in (DOOR, DISPATCH, TRAMP, REGACC):
                bad.append((i * 4, c.dec[i]))
    if bad:
        fail(o, 'mailbox fn 0x%x calls into the door layer: %s' % (MBX_FN, bad))
    for off, want, why in [
            (0x107970, 'call 0x%x' % EXTM_FN, 'door: extm branch -> extm-mailbox fn'),
            (0x107414, 'addi r5,zero,0x4263', 'extm: mailbox str compose lo'),
            (0x107418, 'addi.hi r6,r5,0xb8', 'extm: mailbox str rt 0xb84263'),
            (0x107440, 'call 0x1b5e0', 'extm: emit call (tsv mailbox site)'),
            (EXTM_FN, 'csr.r r3,csr0xbc', 'extm: prologue')]:
        chk(c, off, want, why)
    o('[LY] layer connectivity: reg-access %#x reachable ONLY via door %#x '
      '-> dispatcher %#x -> handler %#x (censuses: 1/1/1); mailbox fn %#x '
      '[%#x..%#x) has 0 calls into the door cluster %#x..%#x - layers '
      'separated (Review Focus 1)' % (REGACC, DOOR, DISPATCH, HANDLER_9001,
                                      MBX_FN, MBX_FN, MBX_HI, CL_LO, CL_HI))
    o('[LY] not-the-door section (mailbox/cmdq layer, plan GC S1-S3 facts, '
      'not re-RE):')
    for fact in MBX_FACTS:
        o('  - ' + fact)
    o('  - extm-mailbox fn %#x (L4 0xd4948 analog): door extm branch @0x107970,'
      ' reads CR 0x23e8/0x23ec pair (EA @0x1073fc), str rt 0xb84263, emit '
      '@0x107440 (tsv site) - separate from the reg path' % EXTM_FN)


def gate_g10(c):
    o = c.o
    for off, want, why in [
            (REGACC, 'csr.r r3,csr0xbc', 'regacc: prologue'),
            (0x106364, 'ld.i r4,0x801', 'F1 hdr: window slot 0x801 read (REGACC)'),
            (0x106368, 'shr r23,r4,0x10', 'F1 hdr: reg_id = word>>16'),
            (0x105f30, 'ld.i r4,0x801', 'F1 hdr: window slot 0x801 re-read (regular)'),
            (0x10615c, 'ld.i r4,0x800', 'F1 flash: addr bits from window slot 0x800'),
            (0x106164, 'ld.i r5,0x804', 'F1 flash: size bits from window slot 0x804'),
            (0x105f6c, 'addi r4,zero,0x0', 'F2 regular copy: index = 0'),
            (0x105f70, 'addi r5,r20,0xc', 'F2 regular copy: dest = staging r1+0x3ac'),
            (0x105f74, 'ld.d r6,r4,0x2014', 'F2 regular copy: window EA read 0x2014+idx'),
            (0x105f78, 'st.d! r6,r5,0x4', 'F2 regular copy: -> stack staging'),
            (0x105f7c, 'addi r4,r4,0x4', 'F2 regular copy: idx += 4'),
            (0x105f80, 'subsi r6,r4,0x300', 'F2 regular copy: bound 0x300 B (whole inline zone)'),
            (0x105f84, 'b.f.0x0 zero,0x105f74', 'F2 regular copy: loop'),
            (0x106184, 'addi r4,zero,0x2000', 'F2 flash copy: window base 0x2000'),
            (0x106188, 'subi r5,r22,0x0', 'F2 flash copy: counter seed r22'),
            (0x106194, 'ld.d r7,r4,0x0', 'F2 flash copy: window EA read walking'),
            (0x106198, 'st.d! r7,r6,0x4', 'F2 flash copy: -> stack [r1+0x14+]'),
            (0x1061a0, 'addi r5,r5,0x1', 'F2 flash copy: counter step'),
            (0x1061a4, 'subsi r7,r5,0x0', 'F2 flash copy: counter test'),
            (0x1061a8, 'b.f.0x0 zero,0x106194', 'F2 flash copy: loop'),
            (0x105ecc, 'st.d! r1,r1,-0x6c8', 'F3 regular: frame 0x6c8'),
            (0x105ee8, 'addi r20,r1,0x3a0', 'F3 regular: staging base [r1+0x3a0]'),
            (0x105eec, 'addi r4,r20,0x30c', 'F3 regular: staging len 0x30c'),
            (0x105ef4, 'st.d! zero,r5,0x4', 'F3 regular: staging zero-loop'),
            (0x106150, 'st.d! r1,r1,-0x140', 'F3 flash: frame 0x140'),
            (0x10609c, 'ld.d r5,r1,0x34', 'F4 WB-A: dest offset field from reg handler'),
            (0x1060a8, 'addi r5,r5,0x2010', 'F4 WB-A: dest base 0x2010+off (stores at 0x2014+)'),
            (0x1060b0, 'ld.d r7,r6,0x0', 'F4 WB-A: read stack output buffer'),
            (0x1060b4, 'st.d! r7,r5,0x4', 'F4 WB-A: write window walking'),
            (0x1060ec, 'addi r4,zero,0x2010', 'F4 WB-B: dest base (stores 0x2014..0x2310)'),
            (0x1060f0, 'addi r5,zero,0x10', 'F4 WB-B: src index 0x10..0x30c'),
            (0x1060f4, 'lw.r r6,r20,r5', 'F4 WB-B: read stack output [r1+0x90+idx]'),
            (0x1060f8, 'st.d! r6,r4,0x4', 'F4 WB-B: write window walking'),
            (0x106100, 'subsi r6,r5,0x310', 'F4 WB-B: bound 0x300 B (whole inline zone)'),
            (0x106104, 'b.f.0x0 zero,0x1060f4', 'F4 WB-B: loop'),
            (0x106224, 'addi r5,zero,0x1ffc', 'F4 flash WB: dest base (stores from 0x2000)'),
            (0x10622c, 'ld.d r7,r23,0x0', 'F4 flash WB: read stack copy'),
            (0x106230, 'st.d! r7,r5,0x4', 'F4 flash WB: write window walking')]:
        chk(c, off, want, why)
    o('[G10] forms-of-access in the reg handler chain (all words '
      'decode-verified):')
    o('  F1 ld.i-imm hdr reads FROM WINDOW SLOTS: 0x801 @0x106364 (+reg_id '
      'shr>>16 @0x106368; re-read @0x105f30), flash 0x800 @0x10615c + 0x804 '
      '@0x106164')
    o('  F2 EA copy-loops WINDOW->STACK: regular @0x105f74 ld.d r6,r4,0x2014 '
      'idx 0..0x300 (whole inline zone 0x2014..0x2313) -> staging; flash '
      '@0x106194 ld.d r7,r4,0x0 base 0x2000 @0x106184 (r22 words) -> '
      '[r1+0x14+]')
    o('  F3 stack staging (derived working copies): regular frame 0x6c8 '
      '@0x105ecc, staging [r1+0x3a0..0x6ac) 0x30c B + output [r1+0x90..0x3a0); '
      'flash frame 0x140 @0x106150')
    o('  F4 RESPONSE write-backs STACK->WINDOW (st.d! walking base - outside '
      'the constant-offset EA scan of G9): regular WB-A @0x1060b4 dest '
      '0x2014+[r1+0x34] count [r1+0x38]>>2 words; WB-B @0x1060f8 dest '
      '0x2014..0x2310 (slots 0x805..0x8c4 = whole inline zone); flash WB '
      '@0x106230 dest from 0x2000 (r22 words)')
    o('[G10] VERDICT R-B2 = (a) WINDOW-INLINE: handler reads the frame from '
      'window words (F1 ld.i slots + F2 copy-loops, sources all CR window) '
      'and writes the response back into the window (F4); stack buffers are '
      'derived copies only (window->stack->window hierarchy - both forms '
      'present in live paths but NO interpretation conflict, Review Focus 5: '
      'verdict (v) not triggered; mailbox-path stack-frame fact does NOT '
      'extrapolate here - LY)')
    o('[G10] obs ISA note: counter idiom subi rX,rY,0x0 + addi rX,rX,0x1 + '
      'while rX!=0 (20 code-region sites incl. @0x106188/@0x1060a0/@0x106228) '
      'terminates only for subi = imm - rs (slaspec has rs - imm) - I-track '
      'correction candidate; gate words are bit-exact, direction-independent')


def main():
    c = Ctx()
    c.o = Out()
    c.xrefs = {}
    o = c.o
    o('cx5 icmd-door rb1 anchor recon: %s' % BASE.name)
    gate_g1_g2_g3(c)
    gate_g4(c)
    gate_g5(c)
    gate_xv(c)
    gate_rd(c)
    map_cluster(c)
    map_reg_chain(c)
    anchor_table(c)
    gate_g6(c)
    gate_g7(c)
    gate_g8(c)
    gate_g9(c)
    gate_layers(c)
    gate_g10(c)
    o('ALL GATES PASS (G1 G2 G3 G4 G5 XV RD G6 G7 G8 G9 LY G10)')
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE log=%s' % LOG)


if __name__ == '__main__':
    main()
