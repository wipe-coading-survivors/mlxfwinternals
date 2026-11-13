#!/usr/bin/env python3
"""cx5 cond-stub R-F1: H1/H2 site recon + door cc inventory (offline).

Task 1 of plan 2026-10-23-cx5-cond-stub (spec 2026-10-23-cx5-cond-stub-design,
C-RF1). Door map canon: docs/superpowers/reports/cx5-icmd-door-rb1.md (1.1/1.2/
1.3, 3 hook table); precedent helper: scripts/probes/cx5-icmd-door/
rb1_dispatch_map.py. Produces for Task 3 (SITE_TABLE + HOOK_PATCHES) and
Task 2 (DOOR_CC_INVENTORY) as importable module-level data.

Gates (in-script, run = full verification against the stock image):
  [0] base image md5 a8c60c90... == canon + MAIN_CODE geometry (words count,
      clcrc round-trip; rb1 G2/G3 class)
  [GS] stock site words vs rb1 canon: H1 @0x10788c = 0x94fffe99 call 0x1072f0,
      H2 @0x1078a0 = 0x94fffeb5 call 0x107374, H0 ref @0x106390 = 0x94fc5373
      call 0x1b15c, H3 @0x107528 call 0x106350; door context anchors
      (doorbell/hi16-opcode/eff.opcode/extm words, trace site 0x107884,
      prologue/epilogue); replaced-fn live-in evidence (validator reads r4
      @0x107308; exec passes r4 to classifier 0x10627c whose first word reads
      r4; save/restore preservation words)
  [GF] flow-scan (CFG backward liveness over the door body from site+4):
      LIVE/DEAD(rewritten-before-read)/UNUSED per site == SITE_TABLE sets;
      scratch cap LIVE = empty; rb1 3 claims re-verified with the r20
      refinement (rb1 said r18-r23 LIVE; scan: r20 is rewritten @0x107890
      immediately after H1 -> DEAD, safe direction)
  [GH] hook patch words: call 0x38d750 at each site assembled strict cx5
      (per-word decode-verify is built into irisc_asm.assemble) + re-disasm
      check; simm24 = (slot-site)/4 in range; distance class vs precedents
      (S2 0xAA4F5, R-E 0xA1CF0); H0 hook word reproduces the R-E canon
      0x940a1cf0
  [GV] v3-form applicability per site: 13-word scheme smoke (stock-call first,
      S2/M1-order cmp38 filter, echo, link-restore + ret.d exit - the R-E
      v3/v4 live-proven skeleton class) assembled strict cx5 at 0x38d750;
      prelude touches only scratch; r4 (stock-ret channel) untouched by the
      stub; budget 13 <= 34-2. SCHEME SMOKE ONLY - the real filter canon and
      word list are Task 3's ruling
  [GC] door cc inventory: census over 8 path windows (door / validator /
      whitelist / exec / exec_classifier / dispatcher / regacc_to_H0 /
      is_flash): cmp38 writers and cc0a consumers == 0 across the whole door
      path (the static core of the poisoning argument); subs pairs (reg-form)
      re-paired with nearest b.* consumer == DOOR_CC_INVENTORY lists exactly
      (matched cc2 / cross-slot cc0 classes); reference pair 0x1071bc/0x1071c0
      present

Journal: docs/superpowers/journal/2026-10-23-cx5-cond-stub-task-01.md
(1 site table, 2 clobber, 3 cc inventory + researched-and-excluded).
Log: build/cx5-cond-stub.log
"""
import hashlib
import re
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WT))
sys.path.insert(0, str(WT / 'scripts/irisc'))
import mlxfwutil
import irisc_dis
from irisc_asm import assemble

BASE = WT / 'refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin'
LOG = WT / 'build/cx5-cond-stub.log'
BASE_MD5 = 'a8c60c90473078288b01009c7cad471b'
RAW_MD5 = 'bcfe0526b43de4abf324b5056f91c112'
RT = 0x800000
MAIN_WORDS = 941936
MAIN_BYTES = MAIN_WORDS * 4
ITOC3_SIZE = 0x3d15a0
ITOC3_ADDR = 0x1c748

DOOR, DOOR_HI = 0x1077f0, 0x1079dc
H0, H1, H2, H3 = 0x106390, 0x10788c, 0x1078a0, 0x107528
H0_STOCK_WORD = 0x94fc5373
H0_HOOK_WORD = 0x940a1cf0
H1_STOCK_WORD = 0x94fffe99
H2_STOCK_WORD = 0x94fffeb5
H3_STOCK_WORD = 0x94fffb8a
STUB_SLOT = 0x38d750
STUB_SLOT_WORDS = 34
VALIDATE, VALIDATE_HI = 0x1072f0, 0x107374
EXECW, EXECW_HI = 0x107374, 0x1073d4
WHITELIST = 0x1071a0
EXEC_CLS = 0x10627c
DISPATCH = 0x107488
REGACC = 0x106350
IS_FLASH = 0x105d08
PREC_S2_SIMM24 = 0xAA4F5
PREC_RE_SIMM24 = 0xA1CF0

UNUSED_REGS = [2, 7] + list(range(9, 18)) + list(range(24, 32))
SCRATCH_REGS = [5, 6, 7, 9, 10, 11]


def _hook_word(site):
    text = 'call 0x%x' % STUB_SLOT
    blob = assemble(text, base=site, profile='cx5')
    w = struct.unpack('>I', blob)[0]
    if irisc_dis.dis(w, site) != text:
        raise RuntimeError('hook word re-disasm mismatch @%#x' % site)
    return w


HOOK_PATCHES = {
    'H0': dict(site=H0, stock_word=H0_STOCK_WORD, word=_hook_word(H0),
               simm24=(STUB_SLOT - H0) // 4),
    'H1': dict(site=H1, stock_word=H1_STOCK_WORD, word=_hook_word(H1),
               simm24=(STUB_SLOT - H1) // 4),
    'H2': dict(site=H2, stock_word=H2_STOCK_WORD, word=_hook_word(H2),
               simm24=(STUB_SLOT - H2) // 4),
}

_SITE_COMMON = dict(
    live_after=[4, 18, 19, 21, 22, 23],
    live_after_note='r4 = stock-ret channel (door reads it right after the '
                    'site: subsi r4,r4,0x0); r18 @0x1078bc, r19 @0x107910 '
                    '(op0x33), r21 @0x10789c/0x107980+, r22 @0x107984+, '
                    'r23 @0x1078f8/0x107964',
    dead_after=[5, 6, 20],
    dead_after_note='r5 def @0x1078c8/e0/e8/918/984 before the read @0x10793c '
                    'on every path; r6 defs only (@0x1078cc, 0x107914); r20 '
                    'def @0x107890 (immediately after H1) / @0x1078ac|74|8c '
                    'before first read on every H2 path',
    unused_after=UNUSED_REGS,
    globals_note='r1 stack; r8 ret.r-mechanics (rb1 canon; nuance: stock '
                 'whitelist itself defs r8 @0x1071ec/f0 on every allowed '
                 'command); r3 free in the door body (epilogue re-def '
                 '@0x10795c, stock fn clobbers it, H0-v1 precedent used r3)',
    scratch=SCRATCH_REGS,
    scratch_note='canon spec 5 scratch = dead{r5,r6} + unused{r7,r9-r11}; '
                 'verified extras: r20 (dead), r12-r17/r2/r24-r31 (unused), '
                 'r3 (free after the stock call)',
    rb1_claims=dict(
        dead_r5_r6_r7='HOLDS (r5/r6 rewritten-before-read; r7 never '
                      'referenced after the site - stronger than dead)',
        unused_r9_r11='HOLDS',
        live_r18_r23='REFINED: r18/r19/r21/r22/r23 LIVE confirmed; r20 DEAD '
                     '(rewritten @0x107890+ before any read) - rb1 was '
                     'over-conservative at set level, safe direction'),
)

SITE_TABLE = {
    'H1': dict(
        _SITE_COMMON,
        name='H1 (early cmd-site, L4-H1 analog; rb1 3)',
        site=H1,
        stock_word=H1_STOCK_WORD,
        stock_dis='call 0x%x' % VALIDATE,
        stock_target=VALIDATE,
        replaced_fn_range=(VALIDATE, VALIDATE_HI),
        replaced_fn_liveins_semantic=[4],
        replaced_fn_liveins_scan=[4, 21, 22, 23],
        livein_evidence=['or r22,r4,r4 @0x107308 (sole external read; r21-r23 '
                         'save/restore-preserved: st.d @0x1072fc..04 / ld.d '
                         '@0x10735c..64)'],
        arg_marshal=(0x107888, 'or r4,r21,r21'),
        hook=HOOK_PATCHES['H1'],
        trigger='EVERY door command incl. rejected (validate call site)',
        noise='hot-path: driver polling may duplicate hits; filter must be '
              'cheap (spec 5 risk)',
        v3=dict(
            applicable=True,
            stock_first='call 0x%x' % VALIDATE,
            prelude_touches=[9],
            r4_passthrough=True,
            exit='link save csr.r r9,csr0xbc at entry; csr.w r9,zero,0xbc + '
                 'ret.d at exit (R-E v3/v4 live canon: nested stock call + '
                 'ret.d works)',
            budget_words=13, slot_words=STUB_SLOT_WORDS, slack=STUB_SLOT_WORDS - 13),
        verdict='BUILDABLE',
    ),
    'H2': dict(
        _SITE_COMMON,
        name='H2 (post-validate, L4-H2 analog; rb1 3)',
        site=H2,
        stock_word=H2_STOCK_WORD,
        stock_dis='call 0x%x' % EXECW,
        stock_target=EXECW,
        replaced_fn_range=(EXECW, EXECW_HI),
        replaced_fn_liveins_semantic=[4],
        replaced_fn_liveins_scan=[4, 22, 23],
        livein_evidence=['r4 passed to classifier: call 0x10627c @0x107398, '
                         'its first word or r5,r4,r4 @0x10627c reads r4; '
                         'r22/r23 save/restore-preserved; on the skip path '
                         '(b.bclr @0x107390) incoming r4 is not read at all'],
        arg_marshal=(0x10789c, 'or r4,r21,r21'),
        hook=HOOK_PATCHES['H2'],
        trigger='every ALLOWED command (post-validate exec call)',
        noise='pre-filtered by the validator - fewer duplicate triggers '
              'than H1',
        v3=dict(
            applicable=True,
            stock_first='call 0x%x' % EXECW,
            prelude_touches=[9],
            r4_passthrough=True,
            exit='same link save/restore + ret.d skeleton as H1',
            budget_words=13, slot_words=STUB_SLOT_WORDS, slack=STUB_SLOT_WORDS - 13),
        verdict='BUILDABLE',
    ),
    'H3_note': dict(
        name='H3 (table-handler bonus; PASSIVE - out of spec scope, build '
             'only if H0/H1/H2 all fall)',
        site=H3, stock_word=H3_STOCK_WORD, stock_dis='call 0x%x' % REGACC,
        stock_target=REGACC,
        note='REGACC reads slot 0x801 itself (ld.i r4,0x801 @0x106364), '
             'incoming r4 ignored; r23 LIVE after; r5-r11 at the common exit '
             '0x1076c4 NOT flow-scanned (rb1 3) - per-site scan required '
             'before any H3 build',
    ),
    'H0_ref': dict(
        name='H0 (reference; R-E matrix v1-v12 site - dead conditionality, '
             'RF2 explains)',
        site=H0, stock_word=H0_STOCK_WORD, stock_dis='call 0x1b15c',
        hook=HOOK_PATCHES['H0'],
        note='hook word reproduces the R-E canon 0x940a1cf0 (gate GH)',
    ),
}

DOOR_CC_INVENTORY = {
    'path': ('door 0x1077f0 -> validator 0x1072f0 -> whitelist 0x1071a0 '
             '(validation layer) -> exec wrapper 0x107374 [-> exec-classifier '
             '0x10627c when w0x457 bit1] -> dispatcher 0x107488 [-> 0x9001 '
             'handler 0x10751c] -> REGACC 0x106350 [-> is_flash 0x105d08] -> '
             'H0 0x106390'),
    'windows': [
        ('door', DOOR, DOOR_HI),
        ('validator', VALIDATE, VALIDATE_HI),
        ('whitelist', WHITELIST, VALIDATE),
        ('exec', EXECW, EXECW_HI),
        ('exec_classifier', EXEC_CLS, REGACC),
        ('dispatcher', DISPATCH, 0x1076f0),
        ('regacc_to_h0', REGACC, H0 + 4),
        ('is_flash', IS_FLASH, 0x105da8),
    ],
    'cmp38_writers': [],
    'cc0a_consumers': [],
    'cmp38_note': ('ZERO cmp38 words and ZERO b.*.0xa consumers across the '
                   'whole door path (gated census): the live-proven '
                   'cmp38/cc0a sites (S2 0x0e437c-class, R-D2 0x0e43c4) are '
                   'mailbox-layer, not door-path - stock gives no evidence '
                   'for or against the mechanism at ANY door-path site'),
    'subs_pairs': [
        dict(addr=0x1071bc, window='whitelist', consumer=0x1071c0,
             slot=2, pair='matched',
             liveness='REFERENCE PAIR (etlon): every allowed command'),
        dict(addr=0x1071c8, window='whitelist', consumer=0x1071cc,
             slot=2, pair='matched', liveness='every allowed command'),
        dict(addr=0x107224, window='whitelist', consumer=0x107228,
             slot=2, pair='matched', liveness='every allowed command'),
        dict(addr=0x107288, window='whitelist', consumer=0x10728c,
             slot=0, pair='cross-slot',
             liveness='f009/0xf00a-range paths'),
        dict(addr=0x107294, window='whitelist', consumer=0x107298,
             slot=0, pair='cross-slot', liveness='0x830e/0xf018 paths'),
        dict(addr=0x1072d8, window='whitelist', consumer=0x1072dc,
             slot=0, pair='cross-slot',
             liveness='ALLOW-EXIT: every allowed command - the allow branch '
                      'itself reads cc0 written by subs (multi-flag '
                      'hypothesis, RF2 Step 3)'),
        dict(addr=0x10628c, window='exec_classifier', consumer=0x106290,
             slot=2, pair='matched',
             liveness='when w0x457 bit1 set (exec wrapper gate)'),
        dict(addr=0x106298, window='exec_classifier', consumer=0x10629c,
             slot=2, pair='matched', liveness='conditional (w0x457 bit1)'),
        dict(addr=0x1062b0, window='exec_classifier', consumer=0x1062b4,
             slot=2, pair='matched', liveness='conditional (w0x457 bit1)'),
        dict(addr=0x106310, window='exec_classifier', consumer=0x106314,
             slot=0, pair='cross-slot', liveness='conditional'),
        dict(addr=0x106330, window='exec_classifier', consumer=0x106334,
             slot=0, pair='cross-slot', liveness='conditional'),
        dict(addr=0x10633c, window='exec_classifier', consumer=0x106340,
             slot=0, pair='cross-slot', liveness='conditional'),
        dict(addr=0x1074a4, window='dispatcher', consumer=0x1074a8,
             slot=2, pair='matched',
             liveness='ENTRY: every non-extm post-exec dispatch (incl. the '
                      '0x9001/mstreg path)'),
        dict(addr=0x1074ec, window='dispatcher', consumer=0x1074f0,
             slot=2, pair='matched', liveness='entry cascade (every '
                                             'dispatch)'),
        dict(addr=0x107570, window='dispatcher', consumer=0x107574,
             slot=2, pair='matched',
             liveness='equality-handler block (0x9021-class) - NOT on the '
                      '0x9001 path'),
        dict(addr=0x10757c, window='dispatcher', consumer=0x107580,
             slot=0, pair='cross-slot',
             liveness='equality-handler block - not on 0x9001 path'),
        dict(addr=0x10758c, window='dispatcher', consumer=0x107590,
             slot=0, pair='cross-slot',
             liveness='equality-handler block - not on 0x9001 path'),
        dict(addr=0x1075ac, window='dispatcher', consumer=0x1075b0,
             slot=0, pair='cross-slot',
             liveness='equality-handler block - not on 0x9001 path'),
        dict(addr=0x1075bc, window='dispatcher', consumer=0x1075c0,
             slot=0, pair='cross-slot',
             liveness='equality-handler block - not on 0x9001 path'),
        dict(addr=0x105d18, window='is_flash', consumer=0x105d1c,
             slot=2, pair='matched',
             liveness='EVERY reg command - the LAST cc pair executed before '
                      'H0 on the mstreg/0x9001 path'),
        dict(addr=0x105d38, window='is_flash', consumer=0x105d3c,
             slot=0, pair='cross-slot',
             liveness='0x900f-range return path'),
    ],
    'reference_pair': (0x1071bc, 0x1071c0),
    'residue': {
        'H0': ('REGACC tail 0x106374..0x106390 writes NO cc at all (0 cc '
               'instructions in the regacc_to_h0 window) -> latch at H0 '
               'entry = is_flash-cascade residue (path-dependent last pair: '
               '0x105d18 cc2 / 0x105d38 cross / subsi cc0)'),
        'H1': ('last cc writer = subsi r4,r18,0x2820 @0x10785c (cc0, consumed '
               'by b.f.0x0 @0x107864); 0x107868..0x107888 = ld.i/addi/addi.hi/'
               'set2/or only (no cc writes)'),
        'H2': ('validator+whitelist cascade residue, path-dependent; the '
               'allow-exit ends on the cross-slot pair 0x1072d8/0x1072dc'),
    },
    'argument': (
        'Static poisoning argument (global vs H0-local), with caveats: '
        '(1) cmp38/cc0a is stock-UNUSED on the entire door path (0 writers / '
        '0 consumers, gated) - the mechanism has zero stock evidence at any '
        'door-path site, so "globally poisonous" and "H0-local" are '
        'statically INDISTINGUISHABLE; (2) cc mechanics as such is live '
        'along the whole path: subsi/cc0 in the door body and validator, '
        'subs/cc2 in the validation layer (reference 0x1071bc), dispatcher '
        'entry and is_flash (the last cc pair before H0); (3) no H0-specific '
        'static anomaly is visible in the inventory - the REGACC tail to H0 '
        'is cc-clean, and the emit wrapper interior is RF2 Step 2 scope; '
        '(4) caveats: statics cannot see ISR/preemption interleavings, '
        'CSR-mediated flag effects or the emit body; the subs multi-flag '
        'semantics is a hypothesis (allow-exit evidence), not canon. '
        'Conclusion: the poisoning question stays OPEN for live '
        'discrimination (RF2 discriminators, RF3 matrix); H1/H2 inherit an '
        'absence of stock evidence, not a proven poison.'),
}


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


class Ctx:
    o = None


def fail(o, msg):
    o('FATAL: ' + msg)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
    sys.exit(1)


def dec_at(c, dc):
    return c.dec[dc // 4]


def word_at(c, dc):
    return c.words[dc // 4]


def chk(c, off, want, why, strict=True):
    got = dec_at(c, off)
    if got != want:
        msg = '%s @0x%x: "%s" != "%s"' % (why, off, got, want)
        if strict:
            fail(c.o, msg)
        c.o('[obs-MISS] ' + msg)
        return False
    return True


def gate_base(c):
    o = c.o
    buf = BASE.read_bytes()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail(o, 'base md5 mismatch (canon %s)' % BASE_MD5)
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', 0x03)
    raw = img.section_data(e)
    if not (e.size == ITOC3_SIZE and e.addr == ITOC3_ADDR and e.clcrc == 1
            and e.param0 == RT):
        fail(o, 'ITOC03 params: size=%#x addr=%#x clcrc=%s p0=%#x'
             % (e.size, e.addr, e.clcrc, e.param0))
    if hashlib.md5(raw).hexdigest() != RAW_MD5:
        fail(o, 'MAIN_CODE raw md5 mismatch')
    if mlxfwutil.clcrc_lines_errors(raw):
        fail(o, 'clcrc bad lines present')
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw or len(code) != MAIN_BYTES:
        fail(o, 'clcrc round-trip / geometry mismatch (%#x B)' % len(code))
    n = len(code) // 4
    c.img, c.raw, c.code, c.n = img, raw, code, n
    c.words = struct.unpack('>%dI' % n, code)
    c.dec = [irisc_dis.dis(w, i * 4) for i, w in enumerate(c.words)]
    o('[0] base md5 OK (%s); MAIN_CODE %d words (0x%x B), clcrc round-trip '
      'OK; dc = byte offset, rt = dc + 0x%x'
      % (BASE_MD5, n, len(code), RT))


def gate_stock(c):
    o = c.o
    for off, word, want, why in [
            (H1, H1_STOCK_WORD, 'call 0x%x' % VALIDATE,
             'H1 stock word (rb1 1.1/3: validator call)'),
            (H2, H2_STOCK_WORD, 'call 0x%x' % EXECW,
             'H2 stock word (rb1 1.1/3: exec wrapper call)'),
            (H0, H0_STOCK_WORD, 'call 0x1b15c',
             'H0 stock word (rb1 3 / R-E canon 0x94fc5373)'),
            (H3, H3_STOCK_WORD, 'call 0x%x' % REGACC,
             'H3 stock word (rb1 1.3: reg-access call)'),
            (0x107888, None, 'or r4,r21,r21', 'H1 arg marshal (r4=eff.opcode)'),
            (0x10789c, None, 'or r4,r21,r21', 'H2 arg marshal'),
            (0x1077f0, None, 'csr.r r3,csr0xbc', 'door prologue'),
            (0x107814, None, 'ld.i r19,0x8ff', 'door doorbell word (rb1 G6)'),
            (0x107844, None, 'mask32 r18,r19,0x10,16',
             'door opcode = hi16 (rb1 G6)'),
            (0x107858, None, 'mask32 r23,r19,0x1,1', 'door extm bit1'),
            (0x107860, None, 'or r21,r18,r18', 'eff.opcode <- r18'),
            (0x107884, None, 'call 0x1b15c', 'isr_icmd trace site (tsv)'),
            (0x107960, None, 'ret.r zero,r8,r3', 'door stock tail (ret.r)'),
            (0x107308, None, 'or r22,r4,r4',
             'validator live-in evidence: reads r4 (sole external read)'),
            (0x1072fc, None, 'st.d r21,r1,0x14', 'validator saves r21'),
            (0x107364, None, 'ld.d r21,r1,0x14', 'validator restores r21'),
            (0x107398, None, 'call 0x%x' % EXEC_CLS,
             'exec wrapper -> classifier (r4 arg)'),
            (0x10627c, None, 'or r5,r4,r4',
             'exec classifier live-in evidence: reads r4'),
            (0x107380, None, 'st.d r22,r1,0xc', 'exec wrapper saves r22'),
            (0x1073c4, None, 'ld.d r22,r1,0xc', 'exec wrapper restores r22')]:
        if word is not None and word_at(c, off) != word:
            fail(o, '%s @0x%x: raw word 0x%08x != canon 0x%08x'
                 % (why, off, word_at(c, off), word))
        chk(c, off, want, why)
    o('[GS] stock site words verified vs rb1 canon: H1 @%#x = 0x%08x '
      '(call 0x%x), H2 @%#x = 0x%08x (call 0x%x), H0 ref @%#x = 0x%08x, H3 '
      '@%#x = 0x%08x; arg marshals or r4,r21,r21 @0x107888/@0x10789c; door '
      'anchors (doorbell 0x8ff, hi16-opcode, extm, trace site, ret.r tail); '
      'replaced-fn live-in evidence (both read r4 only; r21-r23/r22-r23 '
      'save/restore-preserved)'
      % (H1, H1_STOCK_WORD, VALIDATE, H2, H2_STOCK_WORD, EXECW, H0,
         H0_STOCK_WORD, H3, H3_STOCK_WORD))


def _usedef(d):
    parts = d.split(None, 1)
    mn, rest = parts[0], parts[1] if len(parts) > 1 else ''
    a = [t.strip() for t in rest.split(',')]

    def rg(*toks):
        out = set()
        for t in toks:
            if t.startswith('r') and t[1:].isdigit():
                out.add(int(t[1:]))
        return out

    if mn in ('addi', 'addi.hi', 'subi', 'subsi', 'set0', 'set1', 'set2',
              'set3', 'and', 'ands', 'or', 'xor', 'shl64.i', 'shr', 'shrh',
              'mask32'):
        return rg(a[1]), rg(a[0]), ('fall', None)
    if mn in ('add', 'adds', 'sub', 'subs', 'lw.r', 'shl64.r') \
            or mn.startswith('alu.'):
        return rg(a[1], a[2]), rg(a[0]), ('fall', None)
    if mn == 'ret.r':
        return rg(a[1], a[2]), set(), ('exit', None)
    if mn == 'ret.d':
        return set(), set(), ('exit', None)
    if mn == 'ld.i':
        return set(), rg(a[0]), ('fall', None)
    if mn == 'csr.r':
        return set(), rg(a[0]), ('fall', None)
    if mn == 'st.i':
        return rg(a[0]), set(), ('fall', None)
    if mn == 'csr.w':
        return rg(a[0], a[1]), set(), ('fall', None)
    if mn.startswith('ld.'):
        return rg(a[1]), rg(a[0]), ('fall', None)
    if mn.startswith('st.'):
        return (rg(a[0], a[1]), rg(a[1]) if mn.endswith('!') else set(),
                ('fall', None))
    if mn == 'jump':
        return set(), set(), ('jump', int(a[0], 0))
    if mn == 'call':
        return set(), {4}, ('fall', None)
    if mn.startswith('b.t.') or mn.startswith('b.f.'):
        return rg(a[0]), set(), ('br', int(a[1], 0))
    if mn in ('b.bset', 'b.bclr'):
        return rg(a[1]), set(), ('br', int(a[2], 0))
    if mn.startswith('op0x'):
        aa = [t.strip() for t in rest.replace(' imm=', ',').split(',')][:3]
        return rg(aa[1], aa[2]), rg(aa[0]), ('fall', None)
    raise ValueError('unmodeled mnemonic: %r' % d)


def flow_scan(c, entry, lo, hi):
    order = list(range(lo, hi, 4))
    info = {o: _usedef(dec_at(c, o)) for o in order}
    succ = {}
    for o in order:
        kind = info[o][2]
        if kind[0] == 'fall':
            nxt = [o + 4]
        elif kind[0] == 'exit':
            nxt = []
        elif kind[0] == 'jump':
            nxt = [kind[1]]
        else:
            nxt = [o + 4, kind[1]]
        for t in nxt:
            if not lo <= t < hi:
                raise ValueError('control leaves window [%#x..%#x): %#x -> %#x'
                                 % (lo, hi, o, t))
        succ[o] = nxt
    live = {o: set() for o in order}
    changed = True
    while changed:
        changed = False
        for o in reversed(order):
            out = set()
            for t in succ[o]:
                out |= info[t][0] | (live[t] - info[t][1])
            if out != live[o]:
                live[o] = out
                changed = True
    first = entry
    lin = info[first][0] | (live[first] - info[first][1])
    reach, wl = {first}, [first]
    while wl:
        o = wl.pop()
        for t in succ[o]:
            if t not in reach:
                reach.add(t)
                wl.append(t)
    refd = set()
    for o in reach:
        refd |= info[o][0] | info[o][1]
    return lin, refd


def _regs_compact(regs):
    out, run = [], None
    for r in sorted(regs):
        if run and r == run[1] + 1:
            run[1] = r
        else:
            run = [r, r]
            out.append(run)
    parts = []
    for a, b in out:
        if a == b:
            parts.append('r%d' % a)
        elif b == a + 1:
            parts.append('r%d,r%d' % (a, b))
        else:
            parts.append('r%d-r%d' % (a, b))
    return ','.join(parts)


def gate_flow(c):
    o = c.o
    for key in ('H1', 'H2'):
        t = SITE_TABLE[key]
        lin, refd = flow_scan(c, t['site'] + 4, DOOR, DOOR_HI)
        frozen = {0, 1, 3, 8}
        live = sorted(lin - frozen)
        dead = sorted((refd - lin) - frozen)
        unused = sorted((set(range(2, 32)) - frozen) - refd)
        if live != t['live_after'] or dead != t['dead_after'] \
                or unused != t['unused_after']:
            fail(o, '%s flow-scan mismatch vs SITE_TABLE:\n  live   %s != %s'
                 '\n  dead   %s != %s\n  unused %s != %s'
                 % (key, live, t['live_after'], dead, t['dead_after'],
                    unused, t['unused_after']))
        scratch = set(t['scratch']) | set(t['dead_after']) \
            | set(t['unused_after'])
        if scratch & set(live):
            fail(o, '%s scratch/dead/unused intersects LIVE: %s'
                 % (key, sorted(scratch & set(live))))
        if not {5, 6, 7} <= (set(dead) | set(unused)):
            fail(o, '%s rb1 claim r5/r6/r7 dead: violated' % key)
        if not {9, 10, 11} <= set(unused):
            fail(o, '%s rb1 claim r9-r11 unused: violated' % key)
        if not {18, 19, 21, 22, 23} <= set(live):
            fail(o, '%s rb1 claim r18-r23 LIVE: r18/r19/r21/r22/r23 must '
                 'stay live' % key)
        if 20 not in dead:
            fail(o, '%s r20 refinement: expected DEAD (rewritten before '
                 'read)' % key)
        o('[GF] %s @%#x flow-scan OK: LIVE=%s (+globals r1/r8; r3 free in '
          'body), DEAD(rewritten)=%s, UNUSED=%s; scratch %s cap LIVE = 0; '
          'rb1 claims re-verified with the r20 refinement (DEAD, safe '
          'direction)'
          % (key, t['site'],
             ','.join('r%d' % r for r in live),
             ','.join('r%d' % r for r in dead),
             _regs_compact(unused),
             ','.join('r%d' % r for r in t['scratch'])))
    v_lin, _ = flow_scan(c, VALIDATE, VALIDATE, VALIDATE_HI)
    if 4 not in v_lin:
        fail(o, 'validator fn-local live-in must contain r4')
    o('[GF] replaced fns: validator fn-local scan live-in %s (r21-r23 are '
      'save/restore words - semantically preserved); exec wrapper reads '
      'incoming r4 only via the classifier call (gate GS evidence words); '
      'semantic live-in = {r4} for both'
      % ','.join('r%d' % r for r in sorted(v_lin - {0, 1, 3, 8})))


def gate_hooks(c):
    o = c.o
    for key in ('H1', 'H2'):
        h = HOOK_PATCHES[key]
        site, simm = h['site'], h['simm24']
        if not -0x800000 <= simm <= 0x7fffff:
            fail(o, '%s hook simm24 %#x out of rel24 range' % (key, simm))
        if word_at(c, site) != h['stock_word']:
            fail(o, '%s site word drifted from canon' % key)
        if irisc_dis.dis(h['word'], site) != 'call 0x%x' % STUB_SLOT:
            fail(o, '%s hook word re-disasm mismatch' % key)
        d_re = abs(simm - PREC_RE_SIMM24)
        d_s2 = abs(simm - PREC_S2_SIMM24)
        o('[GH] %s hook: stock 0x%08x -> patch 0x%08x `call 0x%x\' (offset '
          '%#x, simm24 %#x); decode-verify OK (strict cx5); distance class: '
          'd(RE %#x-form)=%#x, d(S2 %#x-form)=%#x - same forward class'
          % (key, h['stock_word'], h['word'], STUB_SLOT,
             STUB_SLOT - site, simm, PREC_RE_SIMM24, d_re,
             PREC_S2_SIMM24, d_s2))
    h0 = HOOK_PATCHES['H0']
    if h0['word'] != H0_HOOK_WORD or h0['simm24'] != PREC_RE_SIMM24:
        fail(o, 'H0 reference hook must reproduce the R-E canon word '
             '0x%08x / simm24 %#x, got 0x%08x / %#x'
             % (H0_HOOK_WORD, PREC_RE_SIMM24, h0['word'], h0['simm24']))
    o('[GH] H0 reference reproduced: stock 0x%08x -> 0x%08x `call 0x%x\' '
      '(simm24 %#x == R-E canon)' % (h0['stock_word'], h0['word'],
                                     STUB_SLOT, h0['simm24']))


SCHEME_SMOKE_WORDS = 13


def scheme_smoke(stock_target):
    miss = STUB_SLOT + 11 * 4
    lines = [
        'csr.r r9,csr0xbc',
        'call 0x%x' % stock_target,
        'ld.i r6,0x8c5',
        'set3 r7,zero,0x4d31',
        'cmp38_eq32 r6,r7',
        'b.f.0xa zero,0x%x' % miss,
        'ld.i r3,0x8c6',
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r7,zero,0x2320',
        'st.d r5,r7,0x0',
        'csr.w r9,zero,0xbc',
        'ret.d zero,zero,zero',
    ]
    blob = assemble('\n'.join(lines), base=STUB_SLOT, profile='cx5')
    if len(blob) != SCHEME_SMOKE_WORDS * 4:
        raise RuntimeError('scheme smoke word count')
    return lines


def _smoke_usedef(line):
    if line.startswith('cmp38_eq32 '):
        a = [t.strip() for t in line.split(None, 1)[1].split(',')]
        rg = {int(t[1:]) for t in a if t.startswith('r')}
        return rg, set()
    return _usedef(line)


def gate_v3(c):
    o = c.o
    for key in ('H1', 'H2'):
        t = SITE_TABLE[key]
        lines = scheme_smoke(t['stock_target'])
        _, pre_defs, _ = _usedef(lines[0])
        post_defs = set()
        for ln in lines[2:]:
            post_defs |= _smoke_usedef(ln)[1]
        if 4 in post_defs:
            fail(o, '%s scheme smoke writes r4 (stock-ret channel must pass '
                 'through untouched)' % key)
        if not pre_defs <= set(t['scratch']):
            fail(o, '%s prelude touches non-scratch regs: %s'
                 % (key, sorted(pre_defs)))
        allowed = set(t['scratch']) | set(t['dead_after']) \
            | set(t['unused_after']) | {3}
        bad = post_defs - allowed
        if bad:
            fail(o, '%s scheme smoke writes outside scratch/dead/unused/{r3}: '
                 '%s' % (key, sorted(bad)))
        if SCHEME_SMOKE_WORDS > STUB_SLOT_WORDS - 2:
            fail(o, '%s scheme smoke exceeds slot budget' % key)
        o('[GV] %s v3-form APPLICABLE (scheme smoke, 13 words, strict cx5 '
          'decode-verified): stock-call first (`call 0x%x\') - door already '
          'marshals r4=eff.opcode at the site, prelude touches only r9 '
          '(scratch link-save); filter/echo on scratch r5/r6/r7 + r3 (free in '
          'door body); r4 stock-ret passes through untouched; exit = '
          'csr.w r9,zero,0xbc + ret.d (R-E v3/v4 live canon); budget 13 <= '
          '34-2. NB: smoke proves the FORM, not the filter canon - canon/'
          'operand ruling belongs to Task 3' % (key, t['stock_target']))


def gate_cc(c):
    o = c.o
    exp = {p['addr']: p for p in DOOR_CC_INVENTORY['subs_pairs']}
    got_pairs = {}
    cmp38, cc0a = [], []
    for name, lo, hi in DOOR_CC_INVENTORY['windows']:
        for off in range(lo, hi, 4):
            d = dec_at(c, off)
            w = word_at(c, off)
            if (w >> 26) == 0x38:
                cmp38.append((off, d, name))
            m = re.match(r'^b\.[tf]\.0x([0-9a-f]+)', d)
            if m and int(m.group(1), 16) == 0xa:
                cc0a.append((off, d, name))
            if d.startswith('subs '):
                consumer, slot = None, None
                for nxt in range(off + 4, min(off + 0x24, hi), 4):
                    mb = re.match(r'^b\.[tf]\.0x([0-9a-f]+)', dec_at(c, nxt))
                    if mb:
                        consumer, slot = nxt, int(mb.group(1), 16)
                        break
                got_pairs[off] = dict(
                    addr=off, window=name, consumer=consumer, slot=slot,
                    pair=('matched' if slot == 2 else
                          'cross-slot' if slot == 0 else 'orphan'))
    if cmp38:
        fail(o, 'cmp38 words on the door path (canon says none): %s' % cmp38)
    if cc0a:
        fail(o, 'cc0a consumers on the door path (canon says none): %s' % cc0a)
    if set(got_pairs) != set(exp):
        fail(o, 'subs census mismatch: got %s, expected %s'
             % (sorted(hex(a) for a in got_pairs),
                sorted(hex(a) for a in exp)))
    for addr, p in got_pairs.items():
        e = exp[addr]
        if (p['consumer'], p['slot'], p['pair']) != \
                (e['consumer'], e['slot'], e['pair']):
            fail(o, 'subs pair @%#x: got consumer=%#x slot=%s pair=%s, '
                 'expected %#x/%s/%s'
                 % (addr, p['consumer'], p['slot'], p['pair'],
                    e['consumer'], e['slot'], e['pair']))
    ref = DOOR_CC_INVENTORY['reference_pair']
    if got_pairs[ref[0]]['consumer'] != ref[1] \
            or got_pairs[ref[0]]['pair'] != 'matched':
        fail(o, 'reference pair 0x1071bc/0x1071c0 not matched in the image')
    matched = [p for p in exp.values() if p['pair'] == 'matched']
    cross = [p for p in exp.values() if p['pair'] == 'cross-slot']
    o('[GC] door cc inventory verified: cmp38 writers 0 / cc0a consumers 0 '
      'across all 8 path windows (gated - the live cmp38/cc0a canon is '
      'mailbox-layer, not door-path); subs pairs %d total: %d matched cc2 '
      '(reference 0x1071bc/0x1071c0 etlon + dispatcher entry 0x1074a4/0x1074ec '
      '+ is_flash 0x105d18 - the LAST cc pair before H0 on every reg command) '
      '+ %d cross-slot cc0 (subs -> b.*.0x0; whitelist allow-exit '
      '0x1072d8/0x1072dc among them - subs appears to write a usable cc0 on '
      'the live stream, multi-flag hypothesis for RF2)'
      % (len(exp), len(matched), len(cross)))
    o('[GC] residue at stub entry: H0 = is_flash-cascade residue (REGACC '
      'tail 0x106374..0x106390 writes no cc); H1 = subsi r4,r18,0x2820 '
      '@0x10785c (cc0) then cc-clean marshal words; H2 = validator+whitelist '
      'cascade residue (path-dependent)')
    o('[GC] POISONING ARGUMENT (static, caveats in DOOR_CC_INVENTORY): '
      'cmp38/cc0a is stock-unused on the whole door path -> "globally '
      'poisonous" vs "H0-local" statically INDISTINGUISHABLE; cc mechanics '
      'as such is live along the entire path (subsi/cc0 + subs/cc2); no '
      'H0-specific static anomaly in the inventory -> question stays OPEN '
      'for live discrimination (RF2/RF3)')


def main():
    c = Ctx()
    c.o = Out()
    o = c.o
    o('cx5 cond-stub rf1 site recon: %s' % BASE.name)
    gate_base(c)
    gate_stock(c)
    gate_flow(c)
    gate_hooks(c)
    gate_v3(c)
    gate_cc(c)
    o('ALL GATES PASS ([0] GS GF GH GV GC)')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE log=%s' % LOG)


if __name__ == '__main__':
    main()
