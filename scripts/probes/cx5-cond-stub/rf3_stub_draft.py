#!/usr/bin/env python3
"""cx5 cond-stub R-F3a (Task 3): site ruling + conditional stub draft
(offline). Words + G-class gates; precedent re1_stub_draft.py.

Task 3 of plan 2026-10-23-cx5-cond-stub (spec 2026-10-23-cx5-cond-stub-design
C-RF3 offline part). Step 0 ruling (coordinator, fixed verbatim in the
journal before the words): site = H0-repair (0x106390), filter mechanism =
subs + b.f.0x0 (cc0=eq) allow-exit idiom (RF2 H0_VERDICT; live anchor on the
door path itself: validator 0x1071bc + whitelist cascade alive after the
door trace-call). Matrix: w-a = D1 two-arm probe (NOT a landing), w-b =
conditional H0 stub (build only on D1-positive), w-c = H2 fallback sketch
(cheap). D2 optional (order-symmetric equality -> SUB_MODEL does not block
the H0 path).

Products for Task 4 (module-level, importable):
  SITE_CHOICE  ruling summary (site/mechanism/criteria/matrix + inputs)
  STUB_WORDS   {'w-a': [(dc, w)...], 'w-b': [...], 'w-c': [...]} at
               0x38d750+, strict-cx5 decode-verified per word
  VERSIONS     per-version metadata (purpose, polarity, exit, budget,
               slack, hook, build conditions)
  HOOK_SITE/HOOK_STOCK_WORD/HOOK_WORD  primary hook (H0 canon 0x940a1cf0)
  HOOKS        per-version hook patches (w-a/w-b -> H0, w-c -> H2)

Stub shapes (all: v3-form prologue, stock call FIRST, filter on the
subs/cc0 allow-exit idiom, v4-exact echo tail, link-restore + ret.d exit):

  w-a (18 w, H0, == rf2 D1 two-arm probe, words bit-exact the assembled
      rf2 D1_TEXT): csr.r r19 / call 0x1b15c / ld.i r6,0x8c5 / set2+set3
      MAGIC / subs r7,r7,r6 (0xfce73005, validator class) / b.f.0x0 ->
      ARM_NE arm (taken, stores 0xAAAA0001) ; fallthrough = ARM_EQ arm
      (stores 0xAAAA0002) ; jump join / csr.w r19 / ret.d.
  w-b (14 w, H0, THE conditional stub): same prologue + filter; miss ->
      taken -> words 12-13 (csr.w + ret.d, ZERO stores on the path);
      hit -> fallthrough -> v4-exact echo (ld.i 0x8c6 / addi.hi 0x80 /
      ld.d / addi r4,0x2320 / st.d) -> csr.w r19 / ret.d.
  w-c (14 w, H2 0x1078a0 fallback sketch): same idiom, stock call
      0x107374 (exec wrapper), link r9 (scratch; r19 LIVE at H1/H2),
      store base r7 (r4 = stock-ret channel, untouched), no r4/r18-r23
      mentions anywhere.

Gates (in-script; run = full verification against the stock image):
  [0]  base md5 + MAIN_CODE geometry + slot 34 w zero + cutout zero +
       stock words at H0/H1/H2 + H0 site context (re1 SITE_CTX) +
       REGACC-tail scratch evidence (0 mentions r5-r7/r9-r11/r19-r21,
       r22/r23 mentioned = LIVE, r4 first mention is a def)
  [GR]  ruling inputs re-checked against rf1.SITE_TABLE (BUILDABLE
       verdicts, H1 noise / H2 trigger) and rf2.H0_VERDICT (idiom words,
       D1 gate, H1/H2 fallback)
  G1a/G2a  w-a: decode-verify + budget + bit-exact the assembled rf2
       D1 words + pins (subs 0xfce73005, b.f class/target, jump join,
       both marker constants, exactly 2 store words)
  G1b/G2b  w-b: decode-verify + budget + pins (filter operand words
       bit-exact re1 v2; subs word == 0xfce73005 == w-a word 5; b.f word
       identical to w-a's; hit tail [7:12] bit-exact re1 v4 [2:7];
       epilogue bit-exact v4; single branch; 0 cmp38)
  G1c/G2c  w-c: decode-verify + budget + pins (stock call target ==
       rf1 H2 stock_target; link r9 in rf1 H2 scratch; filter words
       [2:6] bit-exact w-b; store base r7; 0 r4/r18-r23 mentions)
  G3   hooks: H0 patch word reproduces the R-E canon 0x940a1cf0;
       H2 patch word decode-verified; stock asserts from the image
  G4   SEED_LAYOUT: every ld.i/st.d seed reference inside the reserve
       canon 0x8c5-0x8cf; CR 0x2320 (word 0x8c8) store base; 0x8d0/0x8d4
       never referenced
  G5   branch-target resolution from the ENCODED bits (own-dc anchor,
       s16/s24 field * 4) == intended for every pc-relative word of
       every version + stock calibration pin (b.f @0x8ed0 -> 0x8f00)
  G6   scratch/clobber: pre-stock-call defs == {link reg} only; post-
       call defs within the site dead/unused/{r3} set; defs intersect
       LIVE = empty (H0: r22/r23; H2: rf1 SITE_TABLE live_after)
  G7   miss-path silence (w-b/w-c): word-by-word symbolic walk of the
       taken path from the filter branch to the exit - zero st.* words
       executed, zero CR-window writes; hit path: exactly one st.d to
       CR 0x2320; w-a (probe): both arms store (expected, not landing)
  G8   polarity: the b.f target == the miss exit / ARM_NE arm head;
       the fallthrough word == the hit-path / ARM_EQ head

Journal: docs/superpowers/journal/2026-10-23-cx5-cond-stub-task-03.md.
Log: build/cx5-cond-stub.log (appended).
"""
import hashlib
import re
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WT))
sys.path.insert(0, str(WT / 'scripts/irisc'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(WT / 'scripts/probes/cx5-door-detour'))
import mlxfwutil
import irisc_dis
from irisc_asm import assemble
import rf1_site_recon as rf1
import rf2_cc_trace as rf2
import re1_stub_draft as re1

BASE = WT / 'refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin'
LOG = WT / 'build/cx5-cond-stub.log'
BASE_MD5 = 'a8c60c90473078288b01009c7cad471b'
RAW_MD5 = 'bcfe0526b43de4abf324b5056f91c112'
RT = 0x800000
MAIN_WORDS = 941936
MAIN_BYTES = MAIN_WORDS * 4
ITOC3_SIZE = 0x3d15a0
ITOC3_ADDR = 0x1c748

STUB_SLOT = 0x38d750
STUB_SLOT_WORDS = 34
STUB_MAX_WORDS = 32
SLACK_MIN = 2
CUTOUT = (0x38d748, 0x38d74f)

H0 = 0x106390
H0_STOCK_WORD = 0x94fc5373
H0_STOCK_TARGET = 0x1b15c
H0_HOOK_WORD = 0x940a1cf0
H0_HOOK_SIMM24 = 0xA1CF0
H2 = 0x1078a0
EMIT_WRAPPER = 0x1b15c

MAGIC = 0x44554D31
W_MAGIC, W_ADDR, W_COUNT, W_RESP = 0x8c5, 0x8c6, 0x8c7, 0x8c8
RESP_CR = W_RESP * 4
RESERVE_CANON = [(0x8c5, 0x8cf), (0x8d1, 0x8d3), (0x8d5, 0x8f9), (0x8fe, 0x8fe)]
RESERVE_FORBIDDEN = (0x8d0, 0x8d4)
SEED_LAYOUT = re1.SEED_LAYOUT

ARM_EQ_MARK = rf2.ARM_EQ_MARK
ARM_NE_MARK = rf2.ARM_NE_MARK
SUBS_CLASS_WORD = 0xfce73005
BF_ALLOW_CLASS = 0xa4000002

WA_ARM_NE_DC = STUB_SLOT + 4 * 12
WA_JOIN_DC = STUB_SLOT + 4 * 16
WB_MISS_DC = STUB_SLOT + 4 * 12
WC_MISS_DC = STUB_SLOT + 4 * 12

H0_LINK_REG = 19
H2_LINK_REG = 9
H0_ALLOWED_SCRATCH = {3, 4, 5, 6, 7, 9, 10, 11, 19, 20, 21}
H0_LIVE = {22, 23}

RULING = (
    'Site = H0-repair (0x106390). Filter mechanism = subs + b.f.0.0 '
    '(cc0=eq) allow-exit idiom (RF2 H0_VERDICT; live anchor on the path '
    'itself: validator 0x1071bc + whitelist cascade alive after the door '
    'trace-call). Criteria: (1) mechanism liveness - H0 is the only site '
    'with a live-anchored in-door-context mechanism (cmp38/cc0a pairs on '
    'the path: 0, mailbox anchors out of context); (2) clobber - H0 '
    '{r4-r7 dead + r9-r11 unused, r22/r23 LIVE}, live-proven by v4-echo; '
    'H1/H2 scratch {r5,r6,r7,r9-r11}; (3) noise - H0 (REGACC only) < H2 '
    '(allowed) < H1 (all+polling). Matrix: w-a = D1 two-arm probe (H0, '
    'markers of both arms - NOT a landing, strict negative inapplicable '
    'to a probe); w-b = conditional H0 stub (miss -> silent exit, hit -> '
    'v4-echo) - built only on D1-positive (H0_VERDICT gate); w-c = H2 '
    'fallback (site shift, same idiom) - sketch if cheap; D2 optional '
    '(order-symmetric equality -> SUB_MODEL does not block the H0 path).'
)

SITE_CHOICE = {
    'site': 'H0-repair',
    'site_dc': H0,
    'stock_word': H0_STOCK_WORD,
    'stock_target': H0_STOCK_TARGET,
    'mechanism': 'subs + b.f.0x0 (cc0=eq) allow-exit idiom (whitelist '
                 '0x1072d8/0x1072dc class; subs word class 0xfce73005)',
    'criteria': {
        'mechanism_liveness': 'the idiom is live-anchored on the door '
                              'path itself (validator 0x1071bc/0x1071c0 '
                              '+ whitelist cascade decide live after the '
                              'door trace-call 0x107884); on-slot '
                              'operand dependence untested -> w-a probe '
                              'first; cmp38/cc0a has ZERO stock pairs on '
                              'the whole door path (rf1 GC / rf2 CC_MAP)',
        'clobber_budget': 'H0: r4-r7 dead, r9-r11 unused, r19-r21 dead '
                          '(REGACC-tail scan gate [0]); r22/r23 LIVE '
                          'untouched; slot live-proven by R-E v3/v4/v5',
        'noise': 'H0 (REGACC-only reg traffic) < H2 (allowed commands) '
                 '< H1 (every command incl. rejected + driver polling) '
                 '- H1 excluded, not built',
    },
    'matrix': {
        'w-a': 'D1 two-arm probe at H0 - burn FIRST; positive (seeded -> '
               '0x%08x ARM_EQ fallthrough, no-seed -> 0x%08x ARM_NE '
               'taken) unlocks w-b; constant marker -> conditional '
               'branching dead at the slot -> w-c' % (ARM_EQ_MARK,
                                                      ARM_NE_MARK),
        'w-b': 'conditional H0 stub - build/burn ONLY on w-a positive '
               '(rf2 H0_VERDICT gate); landing candidate',
        'w-c': 'H2 fallback sketch (site shift, same idiom) - cheap '
               '(14 w), drawn now, burned only if the H0 path dies',
        'D2': 'optional (subs-rd echo): order-symmetric equality means '
              'SUB_MODEL does not block the H0 filter decision',
    },
    'ruling': RULING,
    'inputs': {
        'rf1_SITE_TABLE': 'H1/H2 BUILDABLE, scratch {r5,r6,r7,r9-r11}, '
                          'live_after {r4,r18,r19,r21,r22,r23}',
        'rf2_H0_VERDICT': 'FIXABLE-CANDIDATE gated on D1; idiom = subs + '
                          'b.f.0x0; fallback H1/H2',
    },
}


def wa_text():
    return rf2.D1_TEXT


def wb_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % H0_LINK_REG,
        'call 0x%x' % H0_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'subs r7,r7,r6',
        'b.f.0x0 zero,0x%x' % WB_MISS_DC,
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r4,zero,0x%x' % RESP_CR,
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % H0_LINK_REG,
        'ret.d zero,zero,zero',
    ])


def wc_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % H2_LINK_REG,
        'call 0x%x' % rf1.SITE_TABLE['H2']['stock_target'],
        'ld.i r6,0x%x' % W_MAGIC,
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'subs r7,r7,r6',
        'b.f.0x0 zero,0x%x' % WC_MISS_DC,
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r7,zero,0x%x' % RESP_CR,
        'st.d r5,r7,0x0',
        'csr.w r%d,zero,0xbc' % H2_LINK_REG,
        'ret.d zero,zero,zero',
    ])


def _words(text, base=STUB_SLOT):
    blob = assemble(text, base=base, profile='cx5')
    return list(struct.unpack('>%dI' % (len(blob) // 4), blob))


def _placed(words):
    return [(STUB_SLOT + 4 * i, w) for i, w in enumerate(words)]


STUB_WORDS = {
    'w-a': _placed(_words(wa_text())),
    'w-b': _placed(_words(wb_text())),
    'w-c': _placed(_words(wc_text())),
}

HOOK_SITE = H0
HOOK_STOCK_WORD = H0_STOCK_WORD
HOOK_WORD = _words('call 0x%x' % STUB_SLOT, H0)[0]

HOOKS = {
    'w-a': dict(site=H0, stock_word=H0_STOCK_WORD, word=HOOK_WORD,
                simm24=(STUB_SLOT - H0) // 4),
    'w-b': dict(site=H0, stock_word=H0_STOCK_WORD, word=HOOK_WORD,
                simm24=(STUB_SLOT - H0) // 4),
    'w-c': dict(site=H2, stock_word=rf1.H2_STOCK_WORD,
                word=rf1.HOOK_PATCHES['H2']['word'],
                simm24=(STUB_SLOT - H2) // 4),
}


def _ver(tag, text, site, stock_target, link, purpose, polarity, exit_,
         landing, builds_on):
    ws = STUB_WORDS[tag]
    return dict(
        tag=tag, site=site, stock_target=stock_target, link_reg=link,
        text=text, words=ws, n_words=len(ws),
        budget=len(ws), slot_words=STUB_SLOT_WORDS,
        slack=STUB_SLOT_WORDS - len(ws),
        purpose=purpose, polarity=polarity, exit=exit_, landing=landing,
        builds_on=builds_on, hook=HOOKS[tag],
    )


VERSIONS = {
    'w-a': _ver(
        'w-a', wa_text(), 'H0-repair', H0_STOCK_TARGET, H0_LINK_REG,
        'live probe: operand dependence of the cc0-via-subs branch at '
        'the H0 slot (rf2 discriminator D1); markers of BOTH arms '
        'stored - NOT a landing, strict negative inapplicable',
        'match (equal diff) -> cc0 true -> b.f.0x0 NOT taken -> '
        'fallthrough ARM_EQ arm stores 0x%08x; miss -> taken -> ARM_NE '
        'arm stores 0x%08x' % (ARM_EQ_MARK, ARM_NE_MARK),
        'arm join (jump) -> csr.w r19,zero,0xbc + ret.d (v3-form canon)',
        False, 'rf2 DISCRIMINATORS.D1_subs_cc0_two_arm'),
    'w-b': _ver(
        'w-b', wb_text(), 'H0-repair', H0_STOCK_TARGET, H0_LINK_REG,
        'THE conditional stub: miss -> silent exit (zero writes to '
        '0x8c5-0x8cf), hit -> v4-exact echo; landing candidate',
        'match -> b.f.0x0 NOT taken -> fallthrough = hit path (echo); '
        'miss -> taken -> words 12-13 (csr.w + ret.d), no store on the '
        'path',
        'miss-exit at word 12 (csr.w r19,zero,0xbc) + ret.d; hit path '
        'falls through to the v4 echo then the same epilogue',
        True, 'w-a positive (rf2 H0_VERDICT gate: D1 must show operand-'
              'dependent arm selection)'),
    'w-c': _ver(
        'w-c', wc_text(), 'H2-fallback', rf1.SITE_TABLE['H2']['stock_target'],
        H2_LINK_REG,
        'H2 fallback sketch (site shift, same idiom): stock exec-wrapper '
        'call first, r4 stock-ret channel untouched, store base r7; '
        'burned only if the H0 path dies (D1 constant)',
        'same idiom: match -> fallthrough hit path; miss -> taken -> '
        'words 12-13, silent',
        'csr.w r9,zero,0xbc + ret.d (H1/H2 exit canon per rf1 GV)',
        True, 'D1-constant outcome (rf2 fallback: site selection shifts '
              'to H1/H2)'),
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
    with LOG.open('a') as f:
        f.write('\n'.join(o.lines) + '\n')
    sys.exit(1)


def word_at(c, dc):
    return c.words[dc // 4]


def dec_at(c, dc):
    return c.dec[dc // 4]


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
        fail(o, 'ITOC03 params mismatch')
    if hashlib.md5(raw).hexdigest() != RAW_MD5:
        fail(o, 'MAIN_CODE raw md5 mismatch')
    if mlxfwutil.clcrc_lines_errors(raw):
        fail(o, 'clcrc bad lines present')
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw or len(code) != MAIN_BYTES:
        fail(o, 'clcrc round-trip / geometry mismatch')
    c.img, c.code, c.n = img, code, len(code) // 4
    c.words = struct.unpack('>%dI' % c.n, code)
    c.dec = [irisc_dis.dis(w, i * 4) for i, w in enumerate(c.words)]
    if not all(word_at(c, STUB_SLOT + 4 * i) == 0
               for i in range(STUB_SLOT_WORDS)):
        fail(o, 'stub slot not zero on the stock base')
    if not all(word_at(c, dc) == 0
               for dc in range(CUTOUT[0], CUTOUT[1] + 1, 4)):
        fail(o, 'cutout not zero on the stock base')
    for off, word, want, why in [
            (H0, H0_STOCK_WORD, 'call 0x%x' % H0_STOCK_TARGET,
             'H0 stock word (R-E canon)'),
            (rf1.H1, rf1.H1_STOCK_WORD, 'call 0x%x' % rf1.VALIDATE,
             'H1 stock word (rf1 canon)'),
            (H2, rf1.H2_STOCK_WORD, 'call 0x%x' % rf1.EXECW,
             'H2 stock word (rf1 canon)')]:
        if word_at(c, off) != word or dec_at(c, off) != want:
            fail(o, '%s @%#x drifted: %#x "%s"' % (why, off,
                 word_at(c, off), dec_at(c, off)))
    for dc, want in re1.SITE_CTX:
        if word_at(c, dc) != want:
            fail(o, 'H0 site context word @%#x: %#x != %#x'
                 % (dc, word_at(c, dc), want))
    tail_end = 0x106394
    while tail_end < 0x106394 + 0x400:
        if dec_at(c, tail_end).startswith('ret.'):
            break
        tail_end += 4
    else:
        fail(o, 'REGACC tail end not found')
    c.regacc_tail = (0x106394, tail_end)

    def mentions(reg, lo, hi):
        hits = []
        for dc in range(lo, hi + 4, 4):
            d = dec_at(c, dc)
            if ('r%d,' % reg) in d or d.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in d:
                hits.append((dc, d))
        return hits

    for reg in (5, 6, 7, 9, 10, 11, 19, 20, 21):
        if mentions(reg, *c.regacc_tail):
            fail(o, 'r%d referenced in the REGACC tail (scratch '
                 'evidence broken): %s' % (reg, mentions(reg,
                                                         *c.regacc_tail)))
    for reg in H0_LIVE:
        if not mentions(reg, *c.regacc_tail):
            fail(o, 'r%d must be LIVE at H0 (referenced in the tail)'
                 % reg)
    r4m = mentions(4, *c.regacc_tail)
    if not r4m or not (r4m[0][1].startswith(('ld.i r4,', 'or r4,'))
                       or r4m[0][1].startswith('subsi r4,')):
        fail(o, 'r4 first tail mention must be a def (dead-confirm): %s'
             % r4m[:1])
    wrap = [d for _, d in rf2.WRAPPER_BODY]
    if any(('r%d,' % H0_LINK_REG) in d or d.endswith(',r%d' % H0_LINK_REG)
           or (',r%d,' % H0_LINK_REG) in d for d in wrap):
        fail(o, 'emit wrapper touches r%d (link stash unsafe)' % H0_LINK_REG)
    o('[0] base md5 OK (%s); MAIN_CODE %d words, clcrc round-trip OK; '
      'slot %dw + cutout zero; stock words H0 %#x/H1/H2 verified; H0 '
      'site ctx %d words == re1 canon; REGACC tail 0x%x..0x%x scratch '
      'evidence: 0 mentions r5/r6/r7/r9/r10/r11/r19/r20/r21, r22/r23 '
      'referenced (LIVE), r4 first mention is a def (dead); emit '
      'wrapper never touches r19'
      % (BASE_MD5, c.n, STUB_SLOT_WORDS, H0, len(re1.SITE_CTX),
         c.regacc_tail[0], c.regacc_tail[1]))


def gate_ruling(c):
    o = c.o
    for key in ('H1', 'H2'):
        if rf1.SITE_TABLE[key]['verdict'] != 'BUILDABLE':
            fail(o, 'rf1 %s verdict drifted from BUILDABLE' % key)
    if rf1.SITE_TABLE['H1']['trigger'] != 'EVERY door command incl. ' \
            'rejected (validate call site)':
        fail(o, 'rf1 H1 noise factor drifted (ruling input)')
    if rf1.SITE_TABLE['H2']['trigger'] != 'every ALLOWED command ' \
            '(post-validate exec call)':
        fail(o, 'rf1 H2 trigger drifted (ruling input)')
    idiom = rf2.H0_VERDICT['idiom']
    if idiom['words'] != ['subs r7,r7,r6', 'b.f.0x0 zero,<miss_exit>']:
        fail(o, 'rf2 H0 idiom words drifted: %s' % idiom['words'])
    if 'D1' not in rf2.H0_VERDICT['gate'] \
            or 'H1/H2' not in rf2.H0_VERDICT['fallback']:
        fail(o, 'rf2 H0 verdict must gate on D1 and fall back to H1/H2')
    if SITE_CHOICE['site_dc'] != rf2.H0_VERDICT['site']:
        fail(o, 'SITE_CHOICE site != rf2 H0_VERDICT site')
    if 'cmp38' in SITE_CHOICE['mechanism']:
        fail(o, 'mechanism must NOT be the dead cmp38/cc0a channel')
    v = VERSIONS
    if v['w-b']['site'] != 'H0-repair' or v['w-c']['site'] != 'H2-fallback':
        fail(o, 'matrix sites drifted from the ruling')
    if v['w-b']['landing'] is not True or v['w-a']['landing'] is not False:
        fail(o, 'w-a must be a probe (not landing), w-b the landing '
             'candidate')
    o('[GR] ruling inputs verified against rf1/rf2 products: H1/H2 '
      'BUILDABLE (H1 noise = every command incl. rejected -> excluded '
      'by criterion 3; H2 = allowed commands -> fallback), rf2 idiom = '
      '%s, gate = D1, fallback = H1/H2; SITE_CHOICE = H0-repair with '
      'the subs+b.f.0.0 idiom (not cmp38/cc0a); matrix w-a(probe)/'
      'w-b(landing, D1-gated)/w-c(H2 sketch)' % idiom['words'])


def _dv_words(o, tag, placed, anchors):
    for i, (dc, w) in enumerate(placed):
        if dc != STUB_SLOT + 4 * i:
            fail(o, '%s placement drift at %d: %#x' % (tag, i, dc))
        if not STUB_SLOT <= dc < STUB_SLOT + 4 * STUB_SLOT_WORDS:
            fail(o, '%s word %d dc %#x outside the slot' % (tag, i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, '%s word %d dc %#x inside the cutout' % (tag, i, dc))
        d = irisc_dis.dis(w, dc)
        again = struct.unpack(
            '>I', assemble(d, base=dc, profile='cx5'))[0]
        if again != w:
            fail(o, '%s word %d (%#x) dis->re-assemble drift: %#x'
                 % (tag, i, w, again))
        if 'subi' in d:
            fail(o, '%s word %d uses subi (4030 reversed-order trap): %s'
                 % (tag, i, d))
    for i, want in anchors.items():
        got = irisc_dis.dis(placed[i][1], STUB_SLOT + 4 * i)
        if got != want:
            fail(o, '%s structure anchor %d: "%s" != "%s"'
                 % (tag, i, got, want))


def gate_g1a(c):
    o = c.o
    wa = STUB_WORDS['w-a']
    if len(wa) != 18:
        fail(o, 'w-a is %d words, D1 canonical draft is 18' % len(wa))
    d1_ref = _words(rf2.D1_TEXT, rf2.STUB_SLOT)
    if [w for _, w in wa] != d1_ref:
        fail(o, 'w-a words not bit-exact the assembled rf2 D1_TEXT '
             '(same slot %#x)' % rf2.STUB_SLOT)
    if wa[5][1] != SUBS_CLASS_WORD:
        fail(o, 'w-a subs word %#x != validator class %#x'
             % (wa[5][1], SUBS_CLASS_WORD))
    _dv_words(o, 'w-a', wa, {
        0: 'csr.r r19,csr0xbc', 1: 'call 0x%x' % H0_STOCK_TARGET,
        2: 'ld.i r6,0x%x' % W_MAGIC,
        5: 'subs r7,r7,r6',
        6: 'b.f.0x0 zero,0x%x' % WA_ARM_NE_DC,
        7: 'set2 r5,zero,0x%x' % ((ARM_EQ_MARK >> 16) & 0xffff),
        8: 'set3 r5,r5,0x%x' % (ARM_EQ_MARK & 0xffff),
        9: 'addi r4,zero,0x%x' % RESP_CR, 10: 'st.d r5,r4,0x0',
        11: 'jump 0x%x' % WA_JOIN_DC,
        12: 'set2 r5,zero,0x%x' % ((ARM_NE_MARK >> 16) & 0xffff),
        13: 'set3 r5,r5,0x%x' % (ARM_NE_MARK & 0xffff),
        14: 'addi r4,zero,0x%x' % RESP_CR, 15: 'st.d r5,r4,0x0',
        16: 'csr.w r19,zero,0xbc', 17: 'ret.d zero,zero,zero'})
    txt = [irisc_dis.dis(w, dc) for dc, w in wa]
    if sum(1 for t in txt if t.startswith('st.')) != 2:
        fail(o, 'w-a must store exactly twice (both arms visible)')
    if any('cmp38' in t or 'op0x38' in t for t in txt):
        fail(o, 'w-a must not use cmp38 (dead channel)')
    o('[G1a] w-a (D1 two-arm probe): %d words, every word decode-'
      'verified (strict cx5 + dis->re-assemble bit-exact), bit-exact '
      'the assembled rf2 D1_TEXT at the same slot; subs word %#x == '
      'validator class; b.f.0x0 -> ARM_NE arm @%#x, fallthrough = '
      'ARM_EQ arm; markers 0x%08x/0x%08x composed; exactly 2 stores; 0 '
      'cmp38; 0 subi' % (len(wa), SUBS_CLASS_WORD, WA_ARM_NE_DC,
                         ARM_EQ_MARK, ARM_NE_MARK))
    o('      dc       rt       word     disasm')
    for dc, w in wa:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w,
                                              irisc_dis.dis(w, dc)))


def gate_g1b(c):
    o = c.o
    wb = STUB_WORDS['w-b']
    if len(wb) != 14:
        fail(o, 'w-b is %d words, canonical draft is 14' % len(wb))
    v2 = [w for _, w in re1.STUB_B2_WORDS]
    v4 = [w for _, w in re1.STUB_B4_WORDS]
    ws = [w for _, w in wb]
    if ws[2:5] != v2[2:5]:
        fail(o, 'w-b filter operand words not bit-exact re1 v2 (ld.i/'
             'set2/set3)')
    if ws[5] != SUBS_CLASS_WORD:
        fail(o, 'w-b subs word %#x != validator class %#x'
             % (ws[5], SUBS_CLASS_WORD))
    if ws[5] != STUB_WORDS['w-a'][5][1]:
        fail(o, 'w-b subs word differs from the w-a probe subs word')
    if ws[6] != STUB_WORDS['w-a'][6][1]:
        fail(o, 'w-b b.f word differs from the w-a probe b.f word '
             '(same dc, same target class)')
    if ws[7:12] != v4[2:7]:
        fail(o, 'w-b hit tail not bit-exact the R-E v4 echo words')
    if ws[12:14] != v4[7:9]:
        fail(o, 'w-b epilogue not bit-exact the R-E v4 epilogue')
    _dv_words(o, 'w-b', wb, {
        0: 'csr.r r19,csr0xbc', 1: 'call 0x%x' % H0_STOCK_TARGET,
        2: 'ld.i r6,0x%x' % W_MAGIC,
        5: 'subs r7,r7,r6',
        6: 'b.f.0x0 zero,0x%x' % WB_MISS_DC,
        7: 'ld.i r3,0x%x' % W_ADDR, 8: 'addi.hi r3,r3,0x80',
        9: 'ld.d r5,r3,0x0', 10: 'addi r4,zero,0x%x' % RESP_CR,
        11: 'st.d r5,r4,0x0', 12: 'csr.w r19,zero,0xbc',
        13: 'ret.d zero,zero,zero'})
    txt = [irisc_dis.dis(w, dc) for dc, w in wb]
    branches = [t for t in txt if t.startswith(('b.', 'jump'))]
    if len(branches) != 1:
        fail(o, 'w-b must contain exactly one branch (the filter), got '
             '%s' % branches)
    if any('cmp38' in t or 'op0x38' in t for t in txt):
        fail(o, 'w-b must not use cmp38 (dead channel)')
    o('[G1b] w-b (conditional H0 stub): %d words, every word decode-'
      'verified; filter operand words bit-exact re1 v2, subs word == '
      'validator class == w-a probe word, b.f word identical to w-a '
      '(same dc/target), hit tail [7:12] bit-exact R-E v4 echo, '
      'epilogue bit-exact v4; single branch; 0 cmp38; 0 subi'
      % len(wb))
    o('      dc       rt       word     disasm')
    for dc, w in wb:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w,
                                              irisc_dis.dis(w, dc)))


def gate_g1c(c):
    o = c.o
    wc = STUB_WORDS['w-c']
    if len(wc) != 14:
        fail(o, 'w-c is %d words, canonical draft is 14' % len(wc))
    wb = [w for _, w in STUB_WORDS['w-b']]
    ws = [w for _, w in wc]
    if ws[2:7] != wb[2:7]:
        fail(o, 'w-c filter+branch words [2:7] not bit-exact w-b')
    if ws[7:10] != wb[7:10]:
        fail(o, 'w-c echo read words [7:10] not bit-exact w-b/v4')
    _dv_words(o, 'w-c', wc, {
        0: 'csr.r r%d,csr0xbc' % H2_LINK_REG,
        1: 'call 0x%x' % rf1.SITE_TABLE['H2']['stock_target'],
        2: 'ld.i r6,0x%x' % W_MAGIC,
        5: 'subs r7,r7,r6',
        6: 'b.f.0x0 zero,0x%x' % WC_MISS_DC,
        7: 'ld.i r3,0x%x' % W_ADDR, 8: 'addi.hi r3,r3,0x80',
        9: 'ld.d r5,r3,0x0', 10: 'addi r7,zero,0x%x' % RESP_CR,
        11: 'st.d r5,r7,0x0', 12: 'csr.w r%d,zero,0xbc' % H2_LINK_REG,
        13: 'ret.d zero,zero,zero'})
    if H2_LINK_REG not in rf1.SITE_TABLE['H2']['scratch']:
        fail(o, 'w-c link reg r%d not in the rf1 H2 scratch set'
             % H2_LINK_REG)
    if rf1.SITE_TABLE['H2']['stock_target'] != rf1.EXECW:
        fail(o, 'w-c stock target drifted from the rf1 H2 site table')
    for reg in (4, 18, 19, 20, 21, 22, 23):
        for i, (dc, w) in enumerate(wc):
            d = irisc_dis.dis(w, dc)
            if ('r%d,' % reg) in d or d.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in d:
                fail(o, 'w-c word %d touches r%d (LIVE/stock-ret at '
                     'H1/H2): %s' % (i, reg, d))
    o('[G1c] w-c (H2 fallback sketch): %d words, every word decode-'
      'verified; stock call == rf1 H2 stock_target (exec wrapper '
      '0x%x); link r%d in the rf1 H2 scratch set; filter+branch words '
      '[2:7] bit-exact w-b, echo read words bit-exact v4; store base '
      'r7 (NOT r4); zero r4/r18-r23 mentions (stock-ret channel and '
      'LIVE regs untouched); 0 subi'
      % (len(wc), rf1.SITE_TABLE['H2']['stock_target'], H2_LINK_REG))
    o('      dc       rt       word     disasm')
    for dc, w in wc:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w,
                                              irisc_dis.dis(w, dc)))


def gate_g2(c):
    o = c.o
    for tag in ('w-a', 'w-b', 'w-c'):
        n = len(STUB_WORDS[tag])
        slack = STUB_SLOT_WORDS - n
        if n > STUB_MAX_WORDS or slack < SLACK_MIN:
            fail(o, '%s budget: %d words, slack %d (max %d, slack >= %d)'
                 % (tag, n, slack, STUB_MAX_WORDS, SLACK_MIN))
        o('[G2%s] budget: %s %d/%d words (slack %d); <= %d with slack '
          '>= %d' % (tag[-1], tag, n, STUB_SLOT_WORDS, slack,
                     STUB_MAX_WORDS, SLACK_MIN))


def gate_g3(c):
    o = c.o
    if HOOK_WORD != H0_HOOK_WORD:
        fail(o, 'H0 hook word %#x != R-E canon %#x'
             % (HOOK_WORD, H0_HOOK_WORD))
    if (STUB_SLOT - H0) // 4 != H0_HOOK_SIMM24:
        fail(o, 'H0 hook simm24 %#x != canon %#x'
             % ((STUB_SLOT - H0) // 4, H0_HOOK_SIMM24))
    if irisc_dis.dis(HOOK_WORD, H0) != 'call 0x%x' % STUB_SLOT:
        fail(o, 'H0 hook word re-disasm mismatch')
    if word_at(c, H0) != H0_STOCK_WORD:
        fail(o, 'H0 site word drifted from stock (assert input)')
    h2w = HOOKS['w-c']['word']
    if word_at(c, H2) != rf1.H2_STOCK_WORD:
        fail(o, 'H2 site word drifted from stock (assert input)')
    if irisc_dis.dis(h2w, H2) != 'call 0x%x' % STUB_SLOT:
        fail(o, 'H2 hook word re-disasm mismatch')
    simm = (STUB_SLOT - H2) // 4
    if not -0x800000 <= simm <= 0x7fffff:
        fail(o, 'H2 hook simm24 %#x out of rel24 range' % simm)
    for tag in ('w-a', 'w-b'):
        if HOOKS[tag]['word'] != H0_HOOK_WORD:
            fail(o, '%s hook must be the H0 canon word' % tag)
    o('[G3] hooks: H0 stock %#x -> patch %#x `call 0x%x\' (simm24 '
      '%#x == R-E canon, decode-verified; site word still stock in the '
      'image); w-c hook: H2 stock %#x -> %#x `call 0x%x\' (simm24 '
      '%#x, same forward class as the precedents, decode-verified)'
      % (H0_STOCK_WORD, HOOK_WORD, STUB_SLOT, H0_HOOK_SIMM24,
         rf1.H2_STOCK_WORD, h2w, STUB_SLOT, simm))


def _seed_refs(tag):
    """Seed-window reads (ld.i word numbers) and writes (st.* CR
    addresses, base resolved through addi consts) per version."""
    words = [w for _, w in STUB_WORDS[tag]]
    reads, writes = [], []
    consts = {}
    for i, w in enumerate(words):
        d = irisc_dis.dis(w, STUB_SLOT + 4 * i)
        m = re.match(r'^ld\.i r\d+,0x([0-9a-f]+)$', d)
        if m:
            reads.append(int(m.group(1), 16))
        m = re.match(r'^addi r(\d+),zero,0x([0-9a-f]+)$', d)
        if m:
            consts[int(m.group(1))] = int(m.group(2), 16)
        m = re.match(r'^st\.[dwq]+!?\s+r\d+,r(\d+),0x([0-9a-f]+)$', d)
        if m:
            base = int(m.group(1))
            if base not in consts:
                fail(Ctx.o, '%s word %d: store base r%d has no const '
                     'producer' % (tag, i, base))
            writes.append(consts[base] + int(m.group(2), 16))
    return reads, writes


def gate_g4(c):
    o = c.o
    for tag in ('w-a', 'w-b', 'w-c'):
        reads, writes = _seed_refs(tag)
        for w in reads:
            if not any(lo <= w <= hi for lo, hi in RESERVE_CANON):
                fail(o, '%s reads word %#x outside the reserve canon'
                     % (tag, w))
        for addr in writes:
            w = addr // 4
            if not any(lo <= w <= hi for lo, hi in RESERVE_CANON):
                fail(o, '%s writes CR %#x (word %#x) outside the '
                     'reserve canon' % (tag, addr, w))
            if RESERVE_FORBIDDEN[0] <= w <= RESERVE_FORBIDDEN[1]:
                fail(o, '%s writes forbidden word %#x' % (tag, w))
            if addr != RESP_CR:
                fail(o, '%s store CR %#x != the response CR %#x'
                     % (tag, addr, RESP_CR))
        if W_MAGIC not in reads:
            fail(o, '%s must read the magic seed word %#x' % (tag,
                                                              W_MAGIC))
        if tag in ('w-b', 'w-c') and W_ADDR not in reads:
            fail(o, '%s must read the addr seed word %#x' % (tag, W_ADDR))
    if SEED_LAYOUT is not re1.SEED_LAYOUT:
        fail(o, 'SEED_LAYOUT must be the re1 canon object (unchanged)')
    lay = SEED_LAYOUT
    if (lay['magic']['word'], lay['addr_dc']['word'],
            lay['count_n']['word'], lay['resp']['word']) != \
            (W_MAGIC, W_ADDR, W_COUNT, W_RESP):
        fail(o, 'SEED_LAYOUT drift vs the re1 canon words')
    o('[G4] SEED_LAYOUT: unchanged re1 canon (magic @%#x, addr @%#x, N '
      '@%#x, resp zone %#x-%#x); every stub seed reference (ld.i '
      '0x8c5[/0x8c6]; stores: base-resolved CR %#x = word %#x only) '
      'inside the reserve canon; 0x8d0/0x8d4 never referenced'
      % (W_MAGIC, W_ADDR, W_COUNT, W_RESP, 0x8cf, RESP_CR, W_RESP))


def _s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def _s24(v):
    v &= 0xffffff
    return v - 0x1000000 if v & 0x800000 else v


def _branch_target(w, dc):
    op = w >> 26
    if op in (0x28, 0x29):
        return (dc + _s16(w & 0xffff) * 4) & 0xffffffff
    if op == 0x25:
        return (dc + _s24(w & 0xffffff) * 4) & 0xffffffff
    return None


STOCK_PIN = (0x8ed0, 0xa40a000c, 0x8f00, 'ret.d zero,zero,zero')


def gate_g5(c):
    o = c.o
    intended = {
        'w-a': {1: H0_STOCK_TARGET, 6: WA_ARM_NE_DC, 11: WA_JOIN_DC},
        'w-b': {1: H0_STOCK_TARGET, 6: WB_MISS_DC},
        'w-c': {1: rf1.SITE_TABLE['H2']['stock_target'], 6: WC_MISS_DC},
    }
    resolved = 0
    for tag, tgt_map in intended.items():
        for i, (dc, w) in enumerate(STUB_WORDS[tag]):
            tgt = _branch_target(w, dc)
            if tgt is None:
                continue
            if i not in tgt_map:
                fail(o, 'G5 %s: unexpected pc-relative word at %d'
                     % (tag, i))
            d = irisc_dis.dis(w, dc)
            m = re.search(r'0x([0-9a-f]+)$', d)
            if not m or int(m.group(1), 16) != tgt:
                fail(o, 'G5 %s word %d: disasm target != encoded target'
                     % (tag, i))
            if tgt != tgt_map[i]:
                fail(o, 'G5 %s word %d @%#x resolves to %#x != intended '
                     '%#x' % (tag, i, dc, tgt, tgt_map[i]))
            resolved += 1
    dc, want_w, want_tgt, want_landing = STOCK_PIN
    w = word_at(c, dc)
    if w != want_w:
        fail(o, 'G5 stock pin word @%#x drifted: %#x' % (dc, w))
    tgt = _branch_target(w, dc)
    if tgt != want_tgt or dec_at(c, tgt) != want_landing:
        fail(o, 'G5 stock pin: %#x -> %#x (%r) != guard-exit calibration'
             % (dc, tgt, dec_at(c, tgt)))
    o('[G5] branch-target resolution: all %d pc-relative stub words '
      '(w-a call/b.f/jump, w-b/w-c call/b.f) resolve from the ENCODED '
      'bits (anchor = own dc, s16/s24 field *4) to the intended '
      'targets == the disasm-printed targets; stock calibration pin: '
      'b.f @%#x -> %#x = %r OK' % (resolved, dc, tgt, want_landing))


def _defs_reads(d):
    u = rf1._usedef(d)
    if d.startswith('cmp38_eq32 '):
        a = [t.strip() for t in d.split(None, 1)[1].split(',')]
        return {int(t[1:]) for t in a if t.startswith('r')}, set()
    return u[0], u[1]


def gate_g6(c):
    o = c.o
    for tag, link, allowed, live in (
            ('w-a', H0_LINK_REG, H0_ALLOWED_SCRATCH, H0_LIVE),
            ('w-b', H0_LINK_REG, H0_ALLOWED_SCRATCH, H0_LIVE),
            ('w-c', H2_LINK_REG,
             set(rf1.SITE_TABLE['H2']['scratch'])
             | set(rf1.SITE_TABLE['H2']['dead_after'])
             | set(rf1.SITE_TABLE['H2']['unused_after']) | {3},
             set(rf1.SITE_TABLE['H2']['live_after']))):
        if link not in allowed:
            fail(o, '%s link reg r%d is not in the site scratch set '
                 '(would clobber LIVE state)' % (tag, link))
        txt = [irisc_dis.dis(w, dc) for dc, w in STUB_WORDS[tag]]
        pre_defs = set()
        for ln in txt[:1]:
            pre_defs |= _defs_reads(ln)[1]
        if pre_defs != {link}:
            fail(o, '%s pre-stock-call defs %s != {%d} (live-ins must '
                 'be untouched before the stock call)'
                 % (tag, sorted(pre_defs), link))
        post_defs = set()
        for ln in txt[2:]:
            post_defs |= _defs_reads(ln)[1]
        post_defs.discard(0)
        bad = post_defs - allowed
        if bad:
            fail(o, '%s post-call defs outside the site scratch set: %s'
                 % (tag, sorted(bad)))
        clash = post_defs & live
        if clash:
            fail(o, '%s defs intersect LIVE %s: %s'
                 % (tag, sorted(live), sorted(clash)))
        if 4 in post_defs and tag == 'w-c':
            fail(o, 'w-c writes r4 (stock-ret channel)')
        o('[G6%s] %s scratch: link r%d in the site scratch set; '
          'pre-call defs == {r%d} (link save only, stock-call live-ins '
          'untouched); post-call defs %s within the site dead/unused/'
          '{r3} set; intersect LIVE %s = empty'
          % (tag[-1], tag, link, link,
             ','.join('r%d' % r for r in sorted(post_defs)),
             ','.join('r%d' % r for r in sorted(live))))


def _walk_path(words, start_idx, taken):
    """Word-by-word execution walk over the stub word list from
    start_idx; at the first conditional branch follow `taken` (True =
    taken). Returns the executed word indices; raises on any second
    conditional branch or unwalkable form."""
    idx, path, decided = start_idx, [], False
    while 0 <= idx < len(words):
        d = irisc_dis.dis(words[idx], STUB_SLOT + 4 * idx)
        path.append(idx)
        if d.startswith('jump '):
            idx = (int(d.split('0x')[1], 16) - STUB_SLOT) // 4
            continue
        if d.startswith('ret.'):
            return path
        m = re.match(r'^b\.[tf]\.0x[0-9a-f]+ zero,0x([0-9a-f]+)$', d)
        if m:
            if decided:
                raise RuntimeError('second conditional branch on one '
                                   'path: %s' % d)
            decided = True
            tgt = (int(m.group(1), 16) - STUB_SLOT) // 4
            idx = tgt if taken else idx + 1
            continue
        if d.startswith('b.'):
            raise RuntimeError('unwalkable branch form: %s' % d)
        idx += 1
    raise RuntimeError('walk left the stub without an exit word')


def gate_g7(c):
    o = c.o
    for tag, br_idx in (('w-b', 6), ('w-c', 6)):
        words = [w for _, w in STUB_WORDS[tag]]
        pre = list(range(0, br_idx))
        post = _walk_path(words, br_idx, True)
        miss_path = pre + post
        stores = [i for i in miss_path
                  if irisc_dis.dis(words[i],
                                   STUB_SLOT + 4 * i).startswith('st.')]
        if stores:
            fail(o, '%s miss path executes store words: %s'
                 % (tag, stores))
        for i in miss_path:
            d = irisc_dis.dis(words[i], STUB_SLOT + 4 * i)
            if d.startswith('csr.w') and ',0xbc' not in d:
                fail(o, '%s miss-path csr.w target != link CSR 0xbc: %s'
                     % (tag, d))
        hit = _walk_path(words, br_idx, False)
        hit_full = pre + hit
        hit_stores = [i for i in hit_full
                      if irisc_dis.dis(words[i],
                                       STUB_SLOT + 4 * i).startswith(
                                           'st.')]
        if hit_stores != [11]:
            fail(o, '%s hit path must execute exactly one store at '
                 'word 11 (CR %#x), got %s' % (tag, RESP_CR, hit_stores))
        o('[G7%s] %s miss-path silence (word-by-word walk): executed '
          'words %s - ZERO st.* words, zero writes to 0x%03x-0x%03x '
          '(only csr.w rLINK -> CSR 0xbc link restore + the stock call '
          'whose writes are stock semantics, executed by every reg '
          'command unhooked); hit path %s executes exactly one store: '
          'word 11 st.d -> CR %#x (word 0x%x)'
          % (tag[-1], tag, miss_path, W_MAGIC, 0x8cf, hit_full, RESP_CR,
             W_RESP))
    wa_words = [w for _, w in STUB_WORDS['w-a']]
    for taken, mark, arm in ((True, ARM_NE_MARK, 'NE'), (False,
                                                         ARM_EQ_MARK,
                                                         'EQ')):
        path = _walk_path(wa_words, 6, taken)
        stores = [i for i in path
                  if irisc_dis.dis(wa_words[i],
                                   STUB_SLOT + 4 * i).startswith('st.')]
        if len(stores) != 1 or stores[0] not in (10, 15):
            fail(o, 'w-a %s arm must store exactly once (arm word), '
                 'got %s' % (arm, stores))
        o('[G7a] w-a %s arm (b.f %s): path %s, exactly one marker store '
          '(word %d -> CR %#x, value 0x%08x) - probe semantics, NOT a '
          'landing (strict negative inapplicable per the ruling)'
          % (arm, 'taken' if taken else 'not taken', path, stores[0],
             RESP_CR, mark))


def word_at_from(placed, dc):
    for d, w in placed:
        if d == dc:
            return w
    raise KeyError(hex(dc))


def gate_g8(c):
    o = c.o
    for tag, br_idx, miss_head, hit_head in (
            ('w-b', 6, 'csr.w r19,zero,0xbc', 'ld.i r3,0x%x' % W_ADDR),
            ('w-c', 6, 'csr.w r9,zero,0xbc', 'ld.i r3,0x%x' % W_ADDR)):
        words = STUB_WORDS[tag]
        w, dc = words[br_idx][1], words[br_idx][0]
        d = irisc_dis.dis(w, dc)
        if not d.startswith('b.f.0x0 '):
            fail(o, '%s filter branch must be b.f.0x0 (cc0=eq allow-'
                 'exit class): %s' % (tag, d))
        tgt = _branch_target(w, dc)
        tgt_d = irisc_dis.dis(word_at_from(words, tgt), tgt)
        if tgt_d != miss_head:
            fail(o, '%s b.f target word is %r != miss head %r'
                 % (tag, tgt_d, miss_head))
        fall = irisc_dis.dis(words[br_idx + 1][1],
                             words[br_idx + 1][0])
        if fall != hit_head:
            fail(o, '%s fallthrough word is %r != hit head %r'
                 % (tag, fall, hit_head))
        o('[G8%s] %s polarity: b.f.0x0 @%#x - match (equal diff -> '
          'cc0 true) NOT taken -> fallthrough %r = hit path; miss -> '
          'taken -> %#x %r = silent exit; branch word class %#x '
          '(allow-exit 0x1072dc form)'
          % (tag[-1], tag, dc, fall, tgt, tgt_d, BF_ALLOW_CLASS))
    wa = STUB_WORDS['w-a']
    w, dc = wa[6][1], wa[6][0]
    if _branch_target(w, dc) != WA_ARM_NE_DC:
        fail(o, 'w-a b.f target must be the ARM_NE arm')
    if irisc_dis.dis(wa[7][1], wa[7][0]) != \
            'set2 r5,zero,0x%x' % ((ARM_EQ_MARK >> 16) & 0xffff):
        fail(o, 'w-a fallthrough must be the ARM_EQ compose head')
    if irisc_dis.dis(wa[12][1], wa[12][0]) != \
            'set2 r5,zero,0x%x' % ((ARM_NE_MARK >> 16) & 0xffff):
        fail(o, 'w-a taken target must be the ARM_NE compose head')
    o('[G8a] w-a polarity: match -> fallthrough ARM_EQ arm '
      '(0x%08x @word 7); miss -> taken -> ARM_NE arm @%#x (0x%08x '
      '@word 12); branch word class %#x == w-b/w-c'
      % (ARM_EQ_MARK, WA_ARM_NE_DC, ARM_NE_MARK,
         STUB_WORDS['w-a'][6][1]))


def main():
    c = Ctx()
    c.o = Out()
    o = c.o
    o('cx5 cond-stub rf3 stub draft: %s' % BASE.name)
    gate_base(c)
    gate_ruling(c)
    gate_g1a(c)
    gate_g1b(c)
    gate_g1c(c)
    gate_g2(c)
    gate_g3(c)
    gate_g4(c)
    gate_g5(c)
    gate_g6(c)
    gate_g7(c)
    gate_g8(c)
    o('ALL GATES PASS ([0] GR G1a G2a G1b G2b G1c G2c G3 G4 G5 G6 G7 G8)')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open('a') as f:
        f.write('\n'.join(o.lines) + '\n')
    o('DONE log+= %s' % LOG)


if __name__ == '__main__':
    main()
