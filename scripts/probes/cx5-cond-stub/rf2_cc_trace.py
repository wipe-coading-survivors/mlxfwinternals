#!/usr/bin/env python3
"""cx5 cond-stub R-F2: cc-source RE on H0 (offline).

Door-path trace + latch map for ONE mstreg command (op 0x9001 /
reg_id 0x9040), matrix v1-v12 explanation, H0 verdict, live
discriminators. Task 2 of plan 2026-10-23-cx5-cond-stub; door map canon
rb1; matrix/live verdicts: re1_stub_draft + R-E report 3.4; ISA facts
docs/250-re/120-irisc/010-isa.md (cmp38 CC-only + CMPRES @0x81008, cc0=eq, subi-delta); Task 1
DOOR_CC_INVENTORY imported from rf1_site_recon.

Products for Task 3/5 (module-level, importable): TRACE, CC_MAP,
SUB_MODEL, MATRIX_EXPLANATION, H0_VERDICT, DISCRIMINATORS.

Gates (in-script, run = full verification against the stock image):
  [0]  base md5 == canon + MAIN_CODE geometry (rf1 [0] class)
  [GT] trace connected: every entry word/dis == image, every flow edge
       (fall / br-taken / br-not-taken / call / ret / tail) consistent
       with the next entry, branch targets == decoder-printed absolute
       targets, every traced instruction renders a named mnemonic
  [GW] emit wrapper 0x1b15c..0x1b1e8: enumerated body == image; 0 cmp38
       inside; r4-r8 clobber evidence; model-free quiet-path derivation
       for the H0 quintuplet (level=1, class=0x4000000) -> last cc
       writer = tst @0x1b1a0
  [GM] whitelist trajectory evaluator: SUB_MODEL (reversed, pos) ->
       op 0x9001 ALLOW / op 0x1234 REJECT; model arbitration table
       reproduced exactly; C-flip robustness re-run
  [GI] inventory completeness: subs-pair census over the 8 rf1 windows
       == imported DOOR_CC_INVENTORY; CC_MAP executed lists ==
       TRACE-derived scans
  [GD] discriminators D1/D2/D3: strict cx5 assemble (per-word
       decode-verify built in), budgets <= 32, branch-target resolution
       == intended, D3 filter words bit-exact the re1 v6 words
  [GX] matrix completeness: every class covered by cause or explicit
       open+discriminator; the four R-E live facts explicitly checked

Journal: docs/superpowers/journal/2026-10-23-cx5-cond-stub-task-02.md.
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

DOOR, H0, STUB_SLOT = 0x1077f0, 0x106390, 0x38d750
VALIDATE, WHITELIST, EXECW, EXEC_CLS = 0x1072f0, 0x1071a0, 0x107374, 0x10627c
DISPATCH, REGACC, IS_FLASH = 0x107488, 0x106350, 0x105d08
EMIT_WRAPPER, EMIT_WRAPPER_END = 0x1b15c, 0x1b1e8
TABLE_B_DC = 0x38bdec
TABLE_B_9001_WORD = 0x0090751c
H0_STOCK_WORD = 0x94fc5373

MAGIC = 0x44554D31
W_MAGIC, W_RESP = 0x8c5, 0x8c8
ARM_EQ_MARK = 0xAAAA0002
ARM_NE_MARK = 0xAAAA0001

SUB_MODEL = {
    'name': '4030 sub-family semantics (RF2; static + live-anchored)',
    'subs_operand_order': 'reversed: subs rd,rs,rt computes rt - rs '
                          '(second minus first)',
    'subsi_operand_order': 'reversed: subsi rd,rs,imm computes imm - rs '
                           '(== the live rb1 sec5 subi-delta canon)',
    'cc0': 'eq/zero (Z) - unchanged from docs/250-re/120-irisc/010-isa.md',
    'cc2': 'ORDER condition, strictly-positive class: Z==0 && N==0 '
           '(result nonzero and not negative); FALSE on equal operands',
    'slaspec_crossref': 'matches :sub (RD = RTsrc - RSsrc) and the '
                        'subsi C32=(rs>imm) carry model; the :subs '
                        'construct (RD = RSsrc - RTsrc) is the outlier '
                        'and is contradicted by the arbitration below',
    'anchors': [
        'whitelist trajectory (live): op 0x9001 must reach the allow '
        'exit (mstreg rc=0) - only (reversed, pos) or (normal, '
        'lt-signed) combos survive the cascade (gate GM);',
        'v10 boot (live): unseeded diff = const-0 = 0x44554d31 - '
        'strictly-positive reads FALSE under reversed (negative diff), '
        'TRUE under normal -> boot silence pins the reversed order;',
        'v11/v12 seeded silence (live): under reversed order the final '
        'mask word computes 1-ne = 1 on match -> echo&1 -> GT word even '
        '-> 0 stored; under normal order the mask is 0xffffffff and the '
        'echo must appear - v11/v12 arbitrate the whitelist ambiguity '
        'toward (reversed, pos).',
    ],
    'status': 'HYPOTHESIS (high confidence, three independent live '
              'anchors; final live lock-in = discriminator D2)',
}

CC_MAP = {
    'command': 'mstreg GET MTRC_CAP 0x9040 (op 0x9001) - the R-E '
               'trigger; executed order, one door invocation',
    'channels': {
        'cc0a_cmpres': {
            'writers_on_path': [],
            'consumers_on_path': [],
            'writers_in_emit_wrapper': [],
            'note': 'ZERO cmp38 words and ZERO b.*.0xa consumers on '
                    'the whole door path incl. the emit wrapper (Task 1 '
                    'GC census + gate GW): the channel is stock-unused '
                    'where our stub runs; stock evidence for it exists '
                    'only in the mailbox layer',
            'live_contrasite': 'S2 prefix filter (cmp38_sel(2) + '
                               'b_f.cc0A, 0x0e437c-class) ran '
                               'operand-dependently live on this card '
                               'in the s2 v5q/v5r cycle',
        },
        'cc0_eq': {
            'writers': [
                (0x10781c, 'subsi r4,r4,0x0', 0x107820,
                 'not-taken (valid bit=1)'),
                (0x107834, 'subsi r4,r4,0x0', 0x107838,
                 'taken [runtime callee]'),
                (0x10784c, 'subsi r4,r18,0x2820', 0x107850,
                 'not-taken (op != 0x2820)'),
                (0x10785c, 'subsi r4,r18,0x2820', 0x107864,
                 'taken (op != 0x2820 -> no substitution)'),
                (0x10732c, 'subsi r4,r4,0x0', 0x107330,
                 'ALT path only (w0x457 bit1)'),
                (0x1072d8, 'subs r5,r6,r5', 0x1072dc,
                 'not-taken (EQUAL -> allow) - THE ANCHOR'),
                (0x107340, 'subsi r4,r4,0x0', 0x107344,
                 'taken (whitelist ret 1)'),
                (0x107894, 'subsi r4,r4,0x0', 0x107898,
                 'not-taken (validate ret 0 = allowed)'),
                (0x10739c, 'subsi r4,r4,0x0', 0x1073a0,
                 'ALT path only (w0x457 bit1)'),
                (0x1078a4, 'subsi r4,r4,0x0', 0x1078a8,
                 'taken (exec ret 0)'),
                (0x107964, 'subsi r4,r23,0x0', 0x107968,
                 'taken (extm=0)'),
                (0x107520, 'subsi r4,r5,0x0', 0x107524,
                 'not-taken (r5=0)'),
                (0x105d38, 'subs r5,r6,r5', 0x105d3c,
                 'not-taken (0x9162 != 0x9040)'),
                (0x1b190, 'subsi r7,r6,0x0', 0x1b194,
                 'wrapper: not-taken (tst 2)'),
                (0x1b1a0, 'subsi r6,r6,0x0', 0x1b1a4,
                 'wrapper: TAKEN (tst 0) - last on quiet path'),
            ],
            'polarity_anchor': 'allow-exit 0x1072d8/0x1072dc: equal -> '
                               'b.f.0.0 NOT taken -> r4=1 allow; live '
                               'via mstreg rc=0 (0x9001 allowed). '
                               '0x2820-pair 0x10785c/0x107864: '
                               'not-equal -> b.f.0.0 taken -> opcode '
                               'stays hi16 (live: reg command reaches '
                               'table B)',
        },
        'cc2_order': {
            'writers': [
                (0x1071bc, 'subs r7,r7,r5', 0x1071c0, 'taken (b.f.0.2)'),
                (0x107224, 'subs r6,r6,r5', 0x107228, 'taken (b.t.0.2)'),
                (0x1074a4, 'subs r7,r7,r4', 0x1074a8, 'taken (b.t.0.2)'),
                (0x1074ec, 'subs r6,r6,r4', 0x1074f0,
                 'not-taken (b.t.0.2)'),
                (0x105d18, 'subs r6,r6,r5', 0x105d1c, 'taken (b.t.0.2)'),
                (0x1b1ac, 'subs r5,r5,r6', 0x1b1b0,
                 'wrapper: not on the quiet path'),
            ],
            'semantics': 'ORDER condition (strictly-positive class '
                         'under the reversed sub order; SUB_MODEL) - '
                         'FALSE on equal diffs; the v10 stub assumed '
                         'cc2 = eq',
            'alt_path_writers': 'exec-classifier pairs 0x10628c/290, '
                                '0x106298/29c, 0x1062b0/b4, 0x106310/14, '
                                '0x106330/34, 0x10633c/40 (w0x457 bit1 '
                                'only)',
        },
        'cc1_cc3_cc4': {
            'writers': [
                (0x1072b4, 'subsi r7,r6,0x5', 0x1072b8,
                 'cc3 taken (0xC01 > 5)'),
                (0x107500, 'subsi r6,r4,0x5', 0x107504,
                 'cc3 not-taken (0 > 5 false)'),
                (0x105d54, 'subsi r8,r6,0x26', 0x105d58,
                 'cc3 taken (0x30 > 0x26)'),
                (0x105d78, 'subsi r7,r6,0x1a', 0x105d7c,
                 'cc3 taken (0xFFFFFFF6 > 0x1a)'),
                (0x1b184, 'subsi r7,r5,0x1', 0x1b188,
                 'cc1 not-taken (1 > 1 false)'),
            ],
            'semantics': 'range-cascade guards: cc3 = ugt-class '
                         '(C32 = rs > imm per subsi), cc4 = ult-class; '
                         'model-free on the trace (constant operands)',
        },
    },
    'emit_wrapper': {
        'range': (EMIT_WRAPPER, EMIT_WRAPPER_END),
        'cmp38_inside': 0,
        'cc_writers': [
            (0x1b184, 'subsi r7,r5,0x1', 0x1b188, 'b.t.0x1'),
            (0x1b190, 'subsi r7,r6,0x0', 0x1b194, 'b.t.0x0'),
            (0x1b1a0, 'subsi r6,r6,0x0', 0x1b1a4, 'b.t.0x0'),
            (0x1b1a8, 'ands r6,r4,0xff', 0x1b1ac, 'feeds subs'),
            (0x1b1ac, 'subs r5,r5,r6', 0x1b1b0, 'b.t.0x2'),
            (0x1b1b8, 'subsi r5,r4,0x0', 0x1b1bc, 'b.t.0x0'),
        ],
        'callees': [(0x1b1c0, 0x2ae5bc), (0x1b1d0, 0x1b4e0)],
        'r4_r8_clobber_evidence': 'canon (rb1 3 / R-E) says "emit '
                         'wrapper clobbers r4-r8"; word-level in the '
                         'enumerated body: defs proven ONLY for '
                         'r4 (ld.i/shr/or @0x1b19c/b4/c4), r5 '
                         '(subsi/subs/or @0x1b184/ac/c8), r6 (or/addi/'
                         'ld.i/and/ands @0x1b17c-cc), r7 (subsi '
                         '@0x1b184/90); r8 is READ (or r23,r8,r8 '
                         '@0x1b174; ret.r zero,r8,r3 @0x1b1e8) and '
                         'NOT defined - r8 defs are possible only in '
                         'the deep callees (0x2ae5bc/0x1b4e0); the '
                         'quiet path (H0 quintuplet) calls neither, '
                         'so on it r8 is preserved',
        'quiet_path_h0': 'for the H0 quintuplet (level=1, class='
                         '0x4000000): 0x1b188 not-taken (cc1: 1>1 '
                         'false) -> 0x1b194 not-taken (tst 2) -> r6 = '
                         '2 & 0x4000000 = 0 -> 0x1b1a4 TAKEN (tst 0) -> '
                         'exit, no core callee; model-free (no sub-order '
                         'dependence)',
    },
    'latch_at_stub_filter': {
        'when': 'immediately after the v3-form stock call 0x1b15c '
                'returns, before the first filter word',
        'cc0a_cmpres': 'NOT written anywhere on the door path nor in '
                       'the wrapper -> holds pre-door residue '
                       '(mailbox-layer cmp38 traffic or boot value); '
                       'constant-false is the candidate consistent '
                       'with v7/v8 always-taken b.f.0xa',
        'flags': 'from the wrapper quiet-exit tst @0x1b1a0 (operand 0):'
                 ' Z=1 N=0 C=0 -> cc0 TRUE, cc1 FALSE, cc3 FALSE, cc2 '
                 'FALSE (both SUB_MODEL cc2 candidate readings); '
                 'caveat: the wrapper path is level/class-dependent '
                 '(quiet path derived model-free for the H0 params, '
                 'gate GW)',
        'pre_wrapper_residue': 'last on-path writers before the '
                               'wrapper: 0x105d18 subs (cc2) and '
                               '0x105d38 subs (cc0 false) in is_flash; '
                               'the REGACC tail 0x106374..0x106390 is '
                               'cc-clean',
    },
}

MATRIX_EXPLANATION = {
    'v1_v2_filter': {
        'versions': 'v1 (magic + r8 double filter), v2 (magic-only)',
        'live': 'silent (v1: unarmed x2 + armed; v2: x2)',
        'cause': 'cc0a-branch class - see v6_v9: the b.f.0xa miss-exit '
                 'is taken operand-independently at the stub slot; v1 '
                 'never reaches its second (r8) filter',
        'class': 'cc0a-dead-at-slot',
    },
    'v3_v5_unconditional': {
        'versions': 'v3 (canary store), v4 (echo), v5 (link echoes)',
        'live': 'ALIVE: v3 const x3, v4 4/4 GT, v5 both links exact',
        'cause': 'no cc/branch machinery at all - alive by '
                 'construction; these bound the dead mechanism to the '
                 'cc/branch class, not to loads/stores/composes at '
                 'the slot',
        'class': 'contrast-class (alive)',
    },
    'v6_v9_cc0a_branches': {
        'versions': 'v6 (S2 port), v7 (two arms), v8 (zero-hi const), '
                    'v9 (upper-clean full magic)',
        'live': 'v6 silent x2 with bit-exact S2 words; v7 b.f TAKEN x4 '
                '(both predicate inputs, deterministic); v8 taken x5; '
                'v9 silent x2',
        'cause': 'THE dead mechanism: at the H0 stub slot the b.*.0xa '
                 'decision is operand-INdependent - v7 proves it '
                 'across both operand classes with visible arms, '
                 'v8/v9 remove const-width/upper-dirt as causes. The '
                 'cmp38 write, the CMPRES latch and the cc0a read are '
                 'inert as a chain at the slot (which element is '
                 'open - see sub_hypotheses). NOT an operand-semantics '
                 'issue.',
        'sub_hypotheses': [
            '(a) cmp38 latch-write inert in the door/H0 execution '
            'context (e.g. privilege/lock state - the door runs inside '
            'the 0x1f2154 lock-trampoline);',
            '(b) b.*.0xa read disconnected at the slot region;',
            '(c) CMPRES frozen at a constant-false value AND (a).',
        ],
        'exclusions': [
            'operand order/width/upper-dirt: excluded by v8/v9 (R-E '
            '38/41) - the decision does not follow operands at all;',
            'emit-wrapper poisons following cc-writes: EXCLUDED - the '
            'door trace-call @0x107884 (same wrapper!) precedes the '
            'validator/whitelist cascade on EVERY command and its '
            'cc0/cc2 branches decide correctly live (0x9001 allowed '
            'via subs/b.f.0.0 and subs/b.*.0.2 pairs);',
            'cc0a aliases the Z flag: EXCLUDED - the wrapper quiet '
            'exit leaves Z=TRUE (tst 0 @0x1b1a0, gate GW) while v7 '
            'read FALSE (always-taken b.f) - selector 0xa does not '
            'read Z;',
            'branch encoding/target error at the slot: excluded by '
            'the R-E G5 branch-target gate and v7 markers landing '
            'exactly in the taken arm.',
        ],
        'open': 'root split (a) vs (b): discriminator D3 (v6-exact '
                'words WITHOUT the stock call); the general branch '
                'mechanism at the slot: D1',
        'class': 'cc0a-dead-at-slot',
    },
    'v10_subs_cc2': {
        'versions': 'v10 (validator idiom subs + b.f.0x2)',
        'live': 'silent x2 (seeded smoke) + boot miss 0x8c8=0',
        'cause': 'WRONG SELECTOR, not a dead channel: cc2 is an ORDER '
                 'condition (strictly-positive class under the '
                 'reversed sub order, SUB_MODEL) - FALSE on an equal '
                 'diff -> b.f.0.2 taken -> miss-exit -> silence. The '
                 'correct equality selector is cc0 (b.f.0.0/b.t.0.0). '
                 'R-E 3.4 verdict 42 ("both cc channels dead at H0") '
                 'is CORRECTED: v10 never tested cc0 and its cc2 '
                 'reading assumed eq.',
        'live_compat': 'seeded (equal diff) -> cc2 false -> taken -> '
                       'silent OK; boot (unseeded: diff = const-0, '
                       'negative under the reversed order) -> cc2 '
                       'false -> taken -> 0x8c8=0 OK - both '
                       'observations reproduced by healthy silicon',
        'anchors': 'whitelist trajectory (gate GM): the live 0x9001 '
                   'allow requires exactly this cc2 semantics class '
                   'in the working stock cascade',
        'class': 'selector-semantics (healthy silicon)',
    },
    'v11_v12_branchless': {
        'versions': 'v11 (mask chain), v12 (+ upper cleans)',
        'live': 'v11 silent (seeded; no-seed trivially 0); v12 silent '
                'x2 (seeded)',
        'cause': 'CANDIDATE (high confidence): sub-family operand-order'
                 ' reversal (SUB_MODEL) - the final mask word '
                 'subs r7,r7,r8 (intended ne-1 = 0xffffffff on match) '
                 'computes r8-r7 = 1-ne = 1 on match -> mask=1 -> '
                 'echo&1 -> the GT word 0x480300bc is even -> 0 '
                 'stored. Silent on match AND trivially on miss; '
                 'branch mechanics not involved (branchless).',
        'requires': 'or/shr/ands/addi/set2/set3/ld.i/ld.d/st.d '
                    'value-semantics healthy at the slot - '
                    'stock-certain at their own sites (rd-value '
                    'consumers: or 34154, shr 12710, ands 12374, subs '
                    '345 sites in MAIN_CODE, gate GI census), '
                    'slot-transfer unproven',
        'alt': 'normal order + one chain op (or/shr/ands) broken at '
               'the slot - the v12 cleans already excluded 64-bit '
               'dirty inputs (R-E 44, stands); D2 arbitrates',
        'open': 'discriminator D2 (three-way: 0x00000001 normal / '
                '0xffffffff reversed / const = rd-inert)',
        'class': 'sub-order (or chain-op-at-slot, D2 arbitrates)',
    },
    'unified': 'Single dead mechanism remains: '
               'cmp38->CMPRES->b.*.0xa inert AT THE H0 STUB SLOT '
               '(v1/v2/v6-v9). v10 is explained by cc2 selector '
               'semantics (order condition, false on equal) with '
               'healthy silicon; v11/v12 by the reversed sub-family '
               'operand order (mask = 1 on match). v3/v4/v5 alive '
               'bounds the death to the cc/branch class. The R-E '
               'conclusion "conditional filtering at H0 dead" is '
               'downgraded to "the cc0a channel at the slot is dead"; '
               'cc0-via-subs branching was never tested '
               'operand-dependently at the slot - see H0_VERDICT.',
    'live_facts_checklist': {
        'v7 always-taken x4 deterministic':
            'v6_v9 cause IS the operand-independence - compatible by '
            'construction',
        'v6 bit-exact S2 words silent':
            'the S2 contrasite proves the words work elsewhere (same '
            'card); the slot/context is the variable - compatible',
        'v3/v4/v5 unconditional alive':
            'contrast-class: no cc/branch words - compatible',
        'v5 links exact (store, load/addr/conversion, magic-read, '
        'set-pair)':
            'pins the v11/v12 chain inputs (diff low32 = 0 on match '
            'is v5-proven) - the mask story needs ONLY the final '
            'subs word order - compatible',
    },
}

H0_VERDICT = {
    'site': H0,
    'stock_word': H0_STOCK_WORD,
    'stock_dis': 'call 0x1b15c',
    'verdict': 'FIXABLE-CANDIDATE, gated on D1: conditional filtering '
               'at H0 is NOT proven dead - the matrix killed only the '
               'cmp38/cc0a channel at the slot; cc0-via-subs '
               'branching was never tested operand-dependently there '
               '(v10 used cc2 under an eq assumption)',
    'idiom': {
        'name': 'allow-exit pair (whitelist 0x1072d8/0x1072dc class)',
        'words': ['subs r7,r7,r6', 'b.f.0x0 zero,<miss_exit>'],
        'polarity': 'match (equal diff) -> cc0 true -> b.f.0.0 NOT '
                    'taken -> fallthrough = hit path; miss -> taken '
                    '-> clean exit',
        'rationale': 'cc0=eq is live-anchored ON THIS VERY PATH by '
                     'the allow-exit (every allowed mstreg command) '
                     'and the 0x2820-pair; subs cc-writes '
                     'demonstrably work in door context post-wrapper '
                     '(the whitelist cascade branches live after the '
                     'door trace-call @0x107884)',
        'order_note': 'equality is order-symmetric - the SUB_MODEL '
                      'reversal does not affect this idiom',
        'for_task3': 'assemble strict cx5 at 0x38d750 after the D1 '
                     'gate passes: v3-form prologue (stock call '
                     'first), ld.i + set-pair filter operands '
                     '(v5-proven words), the subs + b.f.0.0 pair, '
                     'proven hit-path/echo tail',
    },
    'gate': 'D1 (two-arm subs/cc0 probe) must show operand-dependent '
            'arm selection before Task 3 builds the conditional stub '
            'on H0',
    'fallback': 'D1 constant -> conditional branching structurally '
                'dead at the slot beyond cmp38 -> site selection '
                'shifts to H1/H2 (Task 1: BUILDABLE, v3-form '
                'applicable, scratch/clobber gated)',
}

DISCRIMINATORS = {
    'D1_subs_cc0_two_arm': {
        'question': 'does any conditional branch work operand-'
                    'dependently at the H0 stub slot (cc0 via subs)?',
        'shape': 'v3-form prologue (stock call first) + v5-proven '
                 'filter operand words (ld.i magic, set-pair const) + '
                 'subs + b.f.0x0 -> branch-taken arm, fallthrough '
                 'arm, both arms store distinct markers (v7 '
                 'arm/store forms); MARKER SEMANTICS: 0x%08x = '
                 'ARM_EQ (operands equal, cc0 true, b.f NOT taken -> '
                 'fallthrough arm), 0x%08x = ARM_NE (not equal, b.f '
                 'taken -> target arm)' % (ARM_EQ_MARK, ARM_NE_MARK),
        'inputs': 'seeded (magic == const, equal diff) vs no-seed '
                  '(r6 = 0, diff != 0)',
        'expectations': {
            'seeded -> 0x%08x (ARM_EQ, fallthrough) AND no-seed -> '
            '0x%08x (ARM_NE, taken)' % (ARM_EQ_MARK, ARM_NE_MARK):
                'cc0-branching ALIVE at the slot -> H0 fixable: '
                'build the conditional stub with subs + b.f.0.0 '
                '(Task 3)',
            'constant marker regardless of seed':
                'conditional branching structurally dead at the slot '
                '-> H0 not fixable conditionally -> H1/H2 (plan '
                'negative landing)',
            'no marker at all':
                'store/arm path broken - re-check against the v3/v7 '
                'canaries first',
        },
        'decides': 'the H0_VERDICT gate; completes/excludes the v6_v9 '
                   'sub-hypothesis (b) for the general branch '
                   'mechanism',
    },
    'D2_subs_rd_echo': {
        'question': 'sub-family operand order + subs rd-write at the '
                    'slot (the v11/v12 root)',
        'shape': 'v5-shape: stock call, ld.i r6 (magic), set-pair r7 '
                 '(const), subs r7,r7,r6, echo r7 to 0x8c8 (proven '
                 'store words)',
        'inputs': 'seed magic = const-1 (0x44554d30): diff = +/-1, '
                  'splits the order',
        'expectations': {
            '0x8c8 = 0x00000001':
                'NORMAL order (rd = rs - rt) - v11/v12 then need the '
                'chain-op alternative (or/shr/ands at the slot): '
                'escalate to a chain-intermediate echo probe',
            '0x8c8 = 0xffffffff':
                'REVERSED order (rd = rt - rs) - SUB_MODEL live-'
                'locked; v11/v12 closed (mask = 1 on match); the '
                'docs/250-re/120-irisc/010-isa.md sub-family note to be amended',
            '0x8c8 = 0x44554d31':
                'subs rd-write INERT at the slot (compare-only like '
                'cmp38) - v11/v12 closed differently; stock 345 '
                'rd-value sites make silicon-wide inertness '
                'impossible -> slot-context cc-op suppression '
                '(merges with the v6_v9 mystery)',
        },
        'decides': 'SUB_MODEL final lock-in; the v11/v12 class '
                   'closure',
    },
    'D3_cc0a_no_stock_call': {
        'question': 'is the cc0a death caused by the preceding stock '
                    'emit call (context) or by the slot region itself?',
        'shape': 'v6 filter words BIT-EXACT (ld.i r6,0x8c5 / set3 '
                 'r7,zero,0x4d31 / cmp38_eq32 r6,r7 / b.f.0xa) but '
                 'the prologue DROPS the stock call 0x1b15c (link '
                 'save only) + v7-style visible arms',
        'inputs': 'seeded vs no-seed (same as D1)',
        'expectations': {
            'arms discriminate (seeded -> 0x%08x ARM_EQ fallthrough, '
            'no-seed -> 0x%08x ARM_NE taken)' % (ARM_EQ_MARK,
                                                 ARM_NE_MARK):
                'the stock-call PRESENCE is the poison -> H0 fixable '
                'even with cmp38: reorder the filter BEFORE the '
                'stock call (Task 3 layout change; also frees r8 '
                'for reg_id filtering)',
            'still constant':
                'slot-region/context structural for cc0a; combined '
                'with D1-alive => only the cmp38 channel is dead; '
                'combined with D1-constant => the whole branch '
                'mechanism is dead at the slot -> H1/H2',
        },
        'decides': 'the v6_v9 sub-hypothesis split (a) vs (b)',
    },
}


def _run(lo, hi, tag, note=None):
    return [(a, 'fall', (note if a == lo else None) or tag)
            for a in range(lo, hi, 4)]


TRACE = (
    _run(0x1077f0, 0x107818, 'door prologue') + [
        (0x107818, 'fall', 'valid bit0'),
        (0x10781c, 'fall', 'tst'),
        (0x107820, 'br-not-taken', 'valid=1 -> continue'),
        (0x107824, 'fall', None),
        (0x107828, 'fall', None),
        (0x10782c, 'fall', None),
        (0x107830, 'call-ext', 'semaphore-check callee 0x10ae18 (not '
                               'linearized; non-cc canon)'),
        (0x107834, 'fall', 'tst callee ret'),
        (0x107838, 'br-taken', 'runtime; alt arm 0x10783c/40 (warning '
                               'emit 0x1d59c) converges at 0x107844'),
        (0x107844, 'fall', 'opcode = hi16'),
        (0x107848, 'fall', 'r22 = 1 (0x2820 flag)'),
        (0x10784c, 'fall', 'subsi 0x2820 #1'),
        (0x107850, 'br-not-taken', 'op 0x9001 != 0x2820'),
        (0x107854, 'fall', 'r22 = 0'),
        (0x107858, 'fall', 'extm bit1'),
        (0x10785c, 'fall', 'subsi 0x2820 #2 (H1 residue writer)'),
        (0x107860, 'fall', 'eff.opcode <- r18'),
        (0x107864, 'br-taken', 'not-equal -> no CR 0x2000 substitution '
                               '(alt 0x107868 not executed)'),
    ] + _run(0x10786c, 0x107884, 'isr_icmd quintuplet compose') + [
        (0x107884, 'call', 'trace-site emit (isr_icmd L0)'),
    ] + _run(0x1b15c, 0x1b188, 'emit wrapper: quiet path') + [
        (0x1b188, 'br-not-taken', 'cc1: level=1 (1>1 false)'),
        (0x1b18c, 'fall', None),
        (0x1b190, 'fall', 'tst 2'),
        (0x1b194, 'br-not-taken', '2 != 0'),
        (0x1b198, 'fall', 'r6 = 2 & class 0x4000000 = 0'),
        (0x1b19c, 'fall', None),
        (0x1b1a0, 'fall', 'tst 0 - LAST cc writer before return'),
        (0x1b1a4, 'br-taken', 'Z=1 -> skip the emit core'),
    ] + _run(0x1b1d4, 0x1b1e8, 'emit wrapper: epilogue') + [
        (0x1b1e8, 'ret', 'ret -> 0x107888'),
        (0x107888, 'fall', 'marshal r4 = eff.opcode'),
        (0x10788c, 'call', 'H1: validator'),
    ] + _run(0x1072f0, 0x107318, 'validator') + [
        (0x107318, 'br-taken', 'b.bclr bit1 of w0x457 (runtime; alt '
                               'semaphore arm 0x10731c..34 converges at '
                               '0x107338)'),
        (0x107338, 'fall', None),
        (0x10733c, 'call', 'whitelist'),
    ] + _run(0x1071a0, 0x1071c0, 'whitelist prologue') + [
        (0x1071c0, 'br-taken', 'SUB_MODEL: op-0x9002 negative -> cc2 '
                               'false -> b.f taken -> 0x83ff block'),
        (0x107220, 'fall', None),
        (0x107224, 'fall', 'subs vs 0x83ff'),
        (0x107228, 'br-taken', 'op-0x83ff positive -> cc2 true -> b.t '
                               'taken -> -0x8400 block'),
    ] + _run(0x1072a8, 0x1072b8, '-0x8400 range block') + [
        (0x1072b8, 'br-taken', 'cc3: 0xC01 > 5 -> literal block'),
        (0x1072c4, 'fall', 'compose 0x9001'),
        (0x1072c8, 'fall', None),
        (0x1072cc, 'jump', 'to the shared literal compare'),
        (0x1072d8, 'fall', 'subs 0x9001 - op - THE ALLOW PAIR'),
        (0x1072dc, 'br-not-taken', 'EQUAL -> allow (live anchor)'),
        (0x1072e0, 'fall', 'r4 = 1 = ALLOW'),
        (0x1072e4, 'fall', None),
        (0x1072e8, 'fall', None),
        (0x1072ec, 'ret', 'ret -> 0x107340'),
        (0x107340, 'fall', 'tst whitelist ret'),
        (0x107344, 'br-taken', 'ret=1 != 0 -> skip'),
    ] + _run(0x107358, 0x107370, 'validator epilogue') + [
        (0x107370, 'ret', 'ret -> 0x107894'),
        (0x107894, 'fall', 'tst validate ret'),
        (0x107898, 'br-not-taken', 'ret=0 = allowed -> exec'),
        (0x10789c, 'fall', 'marshal'),
        (0x1078a0, 'call', 'H2: exec wrapper'),
    ] + _run(0x107374, 0x107390, 'exec wrapper') + [
        (0x107390, 'br-taken', 'b.bclr bit1 of w0x457 (runtime; alt '
                               'classifier arm 0x107394..b8, pairs '
                               '0x10628c..0x106340, converges at '
                               '0x1073bc)'),
    ] + _run(0x1073bc, 0x1073d0, 'exec wrapper epilogue') + [
        (0x1073d0, 'ret', 'ret -> 0x1078a4'),
        (0x1078a4, 'fall', 'tst exec ret'),
        (0x1078a8, 'br-taken', 'ret=0 -> post-exec'),
        (0x107964, 'fall', 'tst extm'),
        (0x107968, 'br-taken', 'extm=0 -> non-extm dispatch'),
        (0x107980, 'fall', 'marshal r4=op r5=flag'),
        (0x107984, 'fall', None),
        (0x107988, 'call', 'dispatcher'),
    ] + _run(0x107488, 0x1074a8, 'dispatcher entry') + [
        (0x1074a8, 'br-taken', 'op-0x9000 positive -> cc2 true'),
        (0x1074e8, 'fall', None),
        (0x1074ec, 'fall', 'subs vs 0x901f'),
        (0x1074f0, 'br-not-taken', 'op-0x901f negative -> cc2 false'),
    ] + _run(0x1074f4, 0x107504, 'table-B range block') + [
        (0x107504, 'br-not-taken', 'cc3: 0 > 5 false'),
    ] + _run(0x107508, 0x107518, 'table-B jump-table load') + [
        (0x107518, 'tail', 'ret.r tail-jump via table B[0] '
                           '(image word %#x @dc 0x38bdec, rb1 canon '
                           '0x9001 -> 0x10751c)' % TABLE_B_9001_WORD),
        (0x10751c, 'fall', 'block B: r23 = 0'),
        (0x107520, 'fall', 'tst r5'),
        (0x107524, 'br-not-taken', 'r5=0 -> equal -> REGACC'),
        (0x107528, 'call', 'H3-class: REGACC'),
    ] + _run(0x106350, 0x106370, 'REGACC head') + [
        (0x106370, 'call', 'is_flash classifier'),
        (0x105d08, 'fall', None),
        (0x105d0c, 'fall', None),
        (0x105d10, 'fall', None),
        (0x105d14, 'fall', None),
        (0x105d18, 'fall', 'subs vs 0x900f'),
        (0x105d1c, 'br-taken', 'reg_id-0x900f positive -> cc2 true -> '
                               '0x900f-range block'),
    ] + _run(0x105d48, 0x105d58, 'is_flash 0x900f-range') + [
        (0x105d58, 'br-taken', 'cc3: 0x30 > 0x26'),
    ] + _run(0x105d70, 0x105d7c, 'is_flash bitmask-range') + [
        (0x105d7c, 'br-taken', 'cc3: 0xFFFFFFF6 > 0x1a'),
        (0x105d9c, 'fall', None),
        (0x105da0, 'fall', 'compose 0x9162'),
        (0x105da4, 'jump', 'to the literal compare'),
        (0x105d38, 'fall', 'subs 0x9162 - reg_id'),
        (0x105d3c, 'br-not-taken', '0x9162 != 0x9040 -> not flash'),
        (0x105d40, 'fall', 'r4 = 0'),
        (0x105d44, 'ret', 'ret.d -> 0x106374'),
    ] + _run(0x106374, 0x106390, 'REGACC tail (cc-clean) + quintuplet') + [
        (0x106390, 'call', 'H0: stock emit -> the stub slot when '
                           'hooked (R-E canon word 0x94fc5373)'),
    ]
)


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


def dec_at(c, dc):
    return c.dec[dc // 4]


def word_at(c, dc):
    return c.words[dc // 4]


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
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw or len(code) != MAIN_BYTES:
        fail(o, 'clcrc round-trip / geometry mismatch')
    c.img, c.code, c.n = img, code, len(code) // 4
    c.words = struct.unpack('>%dI' % c.n, code)
    c.dec = [irisc_dis.dis(w, i * 4) for i, w in enumerate(c.words)]
    o('[0] base md5 OK (%s); MAIN_CODE %d words, clcrc round-trip OK'
      % (BASE_MD5, c.n))


def _br_target(d):
    m = re.match(r'^(?:b\.[tf]\.0x[0-9a-f]+|jump) (?:zero,)?(0x[0-9a-f]+)$',
                 d)
    if m:
        return int(m.group(1), 16)
    m = re.match(r'^b\.b(?:clr|set) [^,]+,r\d+,(0x[0-9a-f]+)$', d)
    return int(m.group(1), 16) if m else None


def _call_target(d):
    m = re.match(r'^call (0x[0-9a-f]+)$', d)
    return int(m.group(1), 16) if m else None


RET_TO = {0x1b1e8: 0x107888, 0x1072ec: 0x107340, 0x107370: 0x107894,
          0x1073d0: 0x1078a4, 0x105d44: 0x106374}


def gate_trace(c):
    o = c.o
    named = re.compile(r'^[a-z][a-z0-9.]*!?\s')
    bad_named, bad_flow = [], []
    for i, (addr, flow, _note) in enumerate(TRACE):
        d = dec_at(c, addr)
        nxt = TRACE[i + 1][0] if i + 1 < len(TRACE) else None
        if not named.match(d) or d.startswith(('op0x', 'unk.')):
            bad_named.append((addr, d))
        if flow in ('fall', 'br-not-taken'):
            if nxt != addr + 4:
                bad_flow.append((addr, flow, nxt))
        elif flow in ('br-taken', 'jump', 'call'):
            t = _br_target(d) or _call_target(d)
            if flow == 'call' and t is None:
                bad_flow.append((addr, 'call-no-target', d))
            elif nxt is None and i + 1 == len(TRACE):
                pass
            elif t is None or nxt != t:
                bad_flow.append((addr, flow, 'target=%s next=%s'
                                 % (hex(t) if t else None,
                                    hex(nxt) if nxt else None)))
        elif flow == 'call-ext':
            t = _call_target(d)
            if t is None or nxt != addr + 4:
                bad_flow.append((addr, flow, d))
        elif flow == 'ret':
            if nxt is not None and RET_TO.get(addr) is not None \
                    and nxt != RET_TO[addr]:
                bad_flow.append((addr, 'ret', nxt))
        elif flow == 'tail':
            if nxt != 0x10751c or word_at(c, TABLE_B_DC) != \
                    TABLE_B_9001_WORD:
                bad_flow.append((addr, 'tail', nxt))
    if bad_named:
        fail(o, 'trace words without a named mnemonic: %s' % bad_named)
    if bad_flow:
        fail(o, 'trace flow discontinuities: %s' % bad_flow)
    n_br = sum(1 for _, f, _ in TRACE if f.startswith('br-'))
    o('[GT] trace connected: %d entries, %d branches resolved '
      '(target == decoder-printed absolute target), all call/ret/tail '
      'edges land; every traced word decode-consistent with the image '
      '(%d named mnemonics, 0 raw forms)'
      % (len(TRACE), n_br, len(TRACE)))


WRAPPER_BODY = [
    (0x1b15c, 'csr.r r3,csr0xbc'), (0x1b160, 'st.d r3,r1,0x4'),
    (0x1b164, 'st.d! r1,r1,-0x18'), (0x1b168, 'st.d r21,r1,0x14'),
    (0x1b16c, 'st.d r22,r1,0x10'), (0x1b170, 'st.d r23,r1,0xc'),
    (0x1b174, 'or r23,r8,r8'), (0x1b178, 'or r22,r7,r7'),
    (0x1b17c, 'or r21,r6,r6'), (0x1b180, 'addi r6,zero,0x1'),
    (0x1b184, 'subsi r7,r5,0x1'), (0x1b188, 'b.t.0x1 zero,0x1b19c'),
    (0x1b18c, 'ld.i r6,0x2'), (0x1b190, 'subsi r7,r6,0x0'),
    (0x1b194, 'b.t.0x0 zero,0x1b1d4'), (0x1b198, 'and r6,r6,r4'),
    (0x1b19c, 'ld.i r4,0x3'), (0x1b1a0, 'subsi r6,r6,0x0'),
    (0x1b1a4, 'b.t.0x0 zero,0x1b1d4'), (0x1b1a8, 'ands r6,r4,0xff'),
    (0x1b1ac, 'subs r5,r5,r6'), (0x1b1b0, 'b.t.0x2 zero,0x1b1d4'),
    (0x1b1b4, 'shr r4,r4,0x10'), (0x1b1b8, 'subsi r5,r4,0x0'),
    (0x1b1bc, 'b.t.0x0 zero,0x1b1c4'), (0x1b1c0, 'call 0x2ae5bc'),
    (0x1b1c4, 'or r4,r21,r21'), (0x1b1c8, 'or r5,r22,r22'),
    (0x1b1cc, 'or r6,r23,r23'), (0x1b1d0, 'call 0x1b4e0'),
    (0x1b1d4, 'ld.d r23,r1,0xc'), (0x1b1d8, 'ld.d r22,r1,0x10'),
    (0x1b1dc, 'ld.d r21,r1,0x14'), (0x1b1e0, 'addi r1,r1,0x18'),
    (0x1b1e4, 'ld.d r3,r1,0x4'), (0x1b1e8, 'ret.r zero,r8,r3'),
]


def gate_wrapper(c):
    o = c.o
    for addr, want in WRAPPER_BODY:
        if dec_at(c, addr) != want:
            fail(o, 'wrapper body drift @%#x: "%s" != "%s"'
                 % (addr, dec_at(c, addr), want))
    if any('cmp38' in d or 'op0x38' in d for _, d in WRAPPER_BODY):
        fail(o, 'cmp38 inside the emit wrapper (canon says none)')
    defs, reads = set(), set()
    for _, d in WRAPPER_BODY:
        u = rf1._usedef(d)
        defs |= u[1]
        reads |= u[0]
    if not {4, 5, 6, 7} <= defs:
        fail(o, 'wrapper r4-r7 def evidence incomplete: defs=%s '
             '(r8 has NO defs in the body - see the honest note)'
             % sorted(defs))
    if 8 in defs:
        fail(o, 'r8 unexpectedly DEFINED in the wrapper body - the '
             'honesty note and CC_MAP field must be re-derived')
    if 8 not in reads:
        fail(o, 'wrapper r8 read evidence missing (or r23,r8,r8 / '
             'ret.r zero,r8,r3)')
    lvl, cls = 1, 0x4000000
    t188 = lvl > 1
    t194 = (2 == 0)
    t1a4 = ((2 & cls) == 0)
    if t188 or t194 or not t1a4:
        fail(o, 'wrapper quiet-path derivation broken for the H0 '
             'quintuplet')
    cc = CC_MAP['emit_wrapper']['cc_writers']
    for addr, d, cons, _ in cc:
        if dec_at(c, addr) != d or dec_at(c, cons) is None:
            fail(o, 'wrapper cc inventory drift @%#x' % addr)
    o('[GW] emit wrapper 0x%06x..0x%06x: body == image (36 words); 0 '
      'cmp38 inside; register evidence: defs word-proven for '
      'r4/r5/r6/r7; r8 is READ (or r23,r8,r8 @0x1b174, ret.r '
      'zero,r8,r3 @0x1b1e8), NOT defined in the body - r8 defs are '
      'possible only in the deep callees (0x2ae5bc/0x1b4e0), which '
      'the quiet path does not take: on the H0 quiet path r8 is '
      'preserved (the rb1/R-E "clobbers r4-r8" canon is word-proven '
      'for r4-r7 only); internal cc branches: %d writers -> '
      'consumers %s; quiet path '
      'for the H0 quintuplet (level=1, class=0x4000000) derived '
      'model-free: 0x1b188 not-taken (1>1 false) -> 0x1b194 '
      'not-taken (tst 2) -> r6 = 2&0x4000000 = 0 -> 0x1b1a4 taken '
      '(tst 0) -> exit WITHOUT the core callees; last cc writer = '
      'subsi @0x1b1a0, Z=1'
      % (EMIT_WRAPPER, EMIT_WRAPPER_END, len(cc),
         '/'.join('%#x->%#x' % (a, cc[i][2])
                  for i, (a, _, _, _) in enumerate(cc))))


def _reg(t):
    return 0 if t == 'zero' else int(t[1:])


def wl_eval(c, op, order, cc2kind, cflip=False):
    """Symbolic executor of the whitelist fn for a given opcode.

    Returns (allow, visited). order: 'normal' (rd = rs - rt) or
    'reversed' (rd = rt - rs; imm - rs). cc2kind: 'pos' (Z==0 && N==0)
    or 'neg' (N==1). cflip: invert the carry reading (C = rs_u > imm_u
    vs its complement).
    """
    r = {i: 0 for i in range(32)}
    r[4] = op & 0xffffffff
    pc, visited, steps = WHITELIST, [], 0
    flags = {}

    def setflags(res, rs_u, rt_u):
        flags['Z'] = res == 0
        flags['N'] = (res & 0x80000000) != 0
        c_ = rs_u > rt_u
        flags['C'] = (not c_) if cflip else c_

    while pc <= 0x1072ec and steps < 200:
        steps += 1
        d = dec_at(c, pc)
        visited.append(pc)
        a = [t.strip() for t in d.split(None, 1)[1].split(',')]
        mn = d.split(None, 1)[0]

        if mn in ('st.d', 'st.d!', 'st.w'):
            pass
        elif mn == 'or':
            r[_reg(a[0])] = (r[_reg(a[1])] | r[_reg(a[2])]) \
                if len(a) > 2 and a[2].startswith('r') \
                else r[_reg(a[1])] | int(a[2], 0)
        elif mn == 'addi':
            r[_reg(a[0])] = (r[_reg(a[1])] + int(a[2], 0)) & 0xffffffff
        elif mn in ('set2', 'set3'):
            lo = int(a[2], 0)
            r[_reg(a[0])] = ((r[_reg(a[0])] & 0xffff0000) | lo) \
                if mn == 'set3' else ((r[_reg(a[0])] & 0xffff) | lo << 16)
        elif mn == 'add':
            r[_reg(a[0])] = (r[_reg(a[1])] + r[_reg(a[2])]) & 0xffffffff
        elif mn == 'subs':
            rs, rt = r[_reg(a[1])], r[_reg(a[2])]
            res = (rs - rt) if order == 'normal' else (rt - rs)
            res &= 0xffffffff
            r[_reg(a[0])] = res
            setflags(res, rs, rt)
        elif mn == 'subsi':
            rs, imm = r[_reg(a[1])], int(a[2], 0) & 0xffffffff
            res = (rs - imm) if order == 'normal' else (imm - rs)
            res &= 0xffffffff
            r[_reg(a[0])] = res
            setflags(res, rs, imm)
        elif mn == 'and':
            r[_reg(a[0])] = r[_reg(a[1])] & r[_reg(a[2])]
        elif mn == 'ands':
            src = r[_reg(a[2])] if a[2].startswith('r') \
                else int(a[2], 0) & 0xffffffff
            v = r[_reg(a[1])] & src & 0xffffffff
            r[_reg(a[0])] = v
            flags['Z'] = v == 0
            flags['N'] = (v & 0x80000000) != 0
        elif mn == 'shl64.r':
            r[_reg(a[0])] = (r[_reg(a[1])] << (r[_reg(a[2])] & 63)) \
                & 0xffffffff
        elif mn == 'ld.i':
            raise RuntimeError('runtime CR value depends on a branch '
                               'decision (ld.i @%#x)' % pc)
        elif mn == 'call':
            raise RuntimeError('external callee on the evaluated path '
                               '@%#x' % pc)
        elif mn == 'jump':
            pc = int(a[0], 0)
            continue
        elif mn == 'ret.r':
            return r[4] == 1, visited
        elif mn.startswith('b.'):
            m = re.match(r'^b\.([tf])\.0x([0-9a-f]+)', mn)
            sel, want = int(m.group(2), 16), m.group(1) == 't'
            if sel == 0x0:
                val = flags.get('Z')
            elif sel in (0x1, 0x3):
                val = flags.get('C')
            elif sel == 0x2:
                if cc2kind == 'pos':
                    val = flags.get('Z') is False and \
                        flags.get('N') is False
                else:
                    val = flags.get('N')
            elif sel == 0x4:
                val = flags.get('Z') is False and flags.get('C') is False
            else:
                raise RuntimeError('unmodeled cc selector %#x @%#x'
                                   % (sel, pc))
            if val is None:
                raise RuntimeError('branch on stale flags @%#x' % pc)
            if val == want:
                pc = int(a[1], 0)
                continue
        pc += 4
    raise RuntimeError('whitelist eval did not terminate')


ARB_TABLE = {
    ('normal', 'pos'): False, ('normal', 'neg'): True,
    ('reversed', 'pos'): True, ('reversed', 'neg'): False,
}


def gate_model(c):
    o = c.o
    for (order, kind), allow in ARB_TABLE.items():
        for cflip in (False, True):
            got, _v = wl_eval(c, 0x9001, order, kind, cflip)
            if got != allow:
                fail(o, 'arbitration drift: (%s,%s,cflip=%s) 0x9001 -> '
                     'allow=%s, expected %s'
                     % (order, kind, cflip, got, allow))
    allow, visited = wl_eval(c, 0x9001, 'reversed', 'pos')
    if not allow:
        fail(o, 'SUB_MODEL must allow op 0x9001')
    rej, _ = wl_eval(c, 0x1234, 'reversed', 'pos')
    if rej:
        fail(o, 'SUB_MODEL must reject op 0x1234')
    wl_trace = [a for a in [e[0] for e in TRACE]
                if WHITELIST <= a < VALIDATE]
    if visited != wl_trace:
        fail(o, 'TRACE whitelist segment != evaluator trajectory:\n'
             '  eval: %s\n  trace: %s' % (visited, wl_trace))
    o('[GM] whitelist trajectory: SUB_MODEL (reversed, pos) allows op '
      '0x9001 (allow-exit 0x1072d8/0x1072dc reached, EQUAL -> not-'
      'taken) and rejects 0x1234; the evaluator trajectory == the '
      'TRACE whitelist segment word-for-word; model arbitration '
      'reproduced: only (reversed,pos) and (normal,neg) allow 0x9001 '
      '- (normal,pos)/(reversed,neg) reject - stable under the carry-'
      'reading flip (x8 runs); v10/v11/v12 live facts arbitrate the '
      'ambiguity to (reversed, pos) = SUB_MODEL')


def _cc_words(d):
    return (d.startswith(('subs ', 'subsi ', 'ands ', 'adds '))
            or re.match(r'^b\.[tf]\.0x', d) is not None)


def gate_inv(c):
    o = c.o
    inv = rf1.DOOR_CC_INVENTORY
    got = {}
    for name, lo, hi in inv['windows']:
        for off in range(lo, hi, 4):
            d = dec_at(c, off)
            if d.startswith('subs '):
                consumer, slot = None, None
                for nxt in range(off + 4, min(off + 0x24, hi), 4):
                    mb = re.match(r'^b\.[tf]\.0x([0-9a-f]+)',
                                  dec_at(c, nxt))
                    if mb:
                        consumer, slot = nxt, int(mb.group(1), 16)
                        break
                got[off] = (consumer, slot,
                            'matched' if slot == 2 else
                            'cross-slot' if slot == 0 else 'orphan')
    exp = {p['addr']: (p['consumer'], p['slot'], p['pair'])
           for p in inv['subs_pairs']}
    if got != exp:
        fail(o, 'subs census drift vs rf1 DOOR_CC_INVENTORY: %s'
             % {k: (got.get(k), exp.get(k))
                for k in set(got) | set(exp) if got.get(k) != exp.get(k)})
    wins = [(lo, hi) for _, lo, hi in inv['windows']]
    inwin = lambda a: any(lo <= a < hi for lo, hi in wins) \
        or EMIT_WRAPPER <= a <= EMIT_WRAPPER_END
    trace_cc = [(a, dec_at(c, a)) for a, _, _ in TRACE
                if _cc_words(dec_at(c, a))]
    for a, d in trace_cc:
        if not inwin(a):
            fail(o, 'TRACE cc word %#x outside the census windows' % a)
    mapd = set()
    for ch in ('cc0_eq', 'cc2_order', 'cc1_cc3_cc4'):
        for w in CC_MAP['channels'][ch]['writers']:
            mapd.add(w[0])
            mapd.add(w[2])
    for a, d, cons, _ in CC_MAP['emit_wrapper']['cc_writers']:
        mapd.add(a)
        mapd.add(cons)
    missing = [a for a, d in trace_cc if a not in mapd]
    if missing:
        fail(o, 'TRACE cc words missing from CC_MAP: %s'
             % [(hex(a), dec_at(c, a)) for a in missing])
    trace_addrs = [a for a, _, _ in TRACE]
    for ch in ('cc0_eq', 'cc2_order', 'cc1_cc3_cc4'):
        for w in CC_MAP['channels'][ch]['writers']:
            note = w[3]
            if w[0] not in trace_addrs and 'ALT' not in note \
                    and 'wrapper' not in note \
                    and 'not on the quiet path' not in note:
                fail(o, 'CC_MAP %s writer %#x neither on the TRACE nor '
                     'marked ALT/wrapper' % (ch, w[0]))
    if word_at(c, rf1.H0) != H0_STOCK_WORD:
        fail(o, 'H0 stock word drifted')
    o('[GI] inventory: subs-pair census over the 8 rf1 windows == '
      'imported DOOR_CC_INVENTORY (%d pairs); all %d TRACE cc words '
      'inside the windows and covered by CC_MAP; every CC_MAP writer '
      'is on the TRACE or explicitly ALT/wrapper; H0 stock word '
      '0x%08x verified' % (len(exp), len(trace_cc), H0_STOCK_WORD))


def _rd_value_census(c, mnem, window=24):
    total = consumed = 0
    for i in range(c.n - window):
        d = c.dec[i]
        if not d.startswith(mnem + ' '):
            continue
        total += 1
        rd = d.split(None, 1)[1].split(',')[0]
        if rd == 'zero':
            continue
        rd = int(rd[1:])
        for j in range(i + 1, i + window + 1):
            dj = c.dec[j]
            try:
                u = rf1._usedef(dj)
            except ValueError:
                break
            if rd in u[0]:
                consumed += 1
                break
            if rd in u[1] and rd not in u[0]:
                break
    return total, consumed


def gate_census(c):
    o = c.o
    mins = {'subs': (9000, 300), 'ands': (18000, 12000),
            'or': (90000, 30000), 'shr': (13000, 12000),
            'sub': (800, 700)}
    for mnem, (tmin, cmin) in mins.items():
        total, consumed = _rd_value_census(c, mnem)
        if total < tmin or consumed < cmin:
            fail(o, 'stock rd-value census low for %s: %d sites / %d '
                 'consumed (min %d/%d)' % (mnem, total, consumed,
                                           tmin, cmin))
        o('[GI+] stock rd-value census %-4s: %5d sites, %5d '
          'read-before-overwrite rd consumers (>= %d/%d) - the '
          'value-write of %s is stock-exercised; the v11/v12 '
          '"requires" clause stands' % (mnem, total, consumed, tmin,
                                        cmin, mnem))


D1_ARM_A = STUB_SLOT + 4 * 12
D1_JOIN = STUB_SLOT + 4 * 16
D3_ARM_T = STUB_SLOT + 4 * 10
D3_JOIN = STUB_SLOT + 4 * 14

D1_TEXT = '\n'.join([
    'csr.r r19,csr0xbc',
    'call 0x1b15c',
    'ld.i r6,0x%x' % W_MAGIC,
    'set2 r7,zero,0x4455',
    'set3 r7,r7,0x4d31',
    'subs r7,r7,r6',
    'b.f.0x0 zero,0x%x' % D1_ARM_A,
    'set2 r5,zero,0xaaaa',
    'set3 r5,r5,0x2',
    'addi r4,zero,0x2320',
    'st.d r5,r4,0x0',
    'jump 0x%x' % D1_JOIN,
    'set2 r5,zero,0xaaaa',
    'set3 r5,r5,0x1',
    'addi r4,zero,0x2320',
    'st.d r5,r4,0x0',
    'csr.w r19,zero,0xbc',
    'ret.d zero,zero,zero',
])

D2_TEXT = '\n'.join([
    'csr.r r19,csr0xbc',
    'call 0x1b15c',
    'ld.i r6,0x%x' % W_MAGIC,
    'set2 r7,zero,0x4455',
    'set3 r7,r7,0x4d31',
    'subs r7,r7,r6',
    'addi r4,zero,0x2320',
    'st.d r7,r4,0x0',
    'csr.w r19,zero,0xbc',
    'ret.d zero,zero,zero',
])

D3_TEXT = '\n'.join([
    'csr.r r19,csr0xbc',
    'ld.i r6,0x%x' % W_MAGIC,
    'set3 r7,zero,0x4d31',
    'cmp38_eq32 r6,r7',
    'b.f.0xa zero,0x%x' % D3_ARM_T,
    'set2 r5,zero,0xaaaa',
    'set3 r5,r5,0x2',
    'addi r4,zero,0x2320',
    'st.d r5,r4,0x0',
    'jump 0x%x' % D3_JOIN,
    'set2 r5,zero,0xaaaa',
    'set3 r5,r5,0x1',
    'addi r4,zero,0x2320',
    'st.d r5,r4,0x0',
    'csr.w r19,zero,0xbc',
    'ret.d zero,zero,zero',
])


def _probe_words(text, tag, o):
    blob = assemble(text, base=STUB_SLOT, profile='cx5')
    ws = list(struct.unpack('>%dI' % (len(blob) // 4), blob))
    if len(ws) > 32:
        fail(o, '%s budget: %d words > 32' % (tag, len(ws)))
    for i, w in enumerate(ws):
        dc = STUB_SLOT + 4 * i
        d = irisc_dis.dis(w, dc)
        again = struct.unpack(
            '>I', assemble(d, base=dc, profile='cx5'))[0]
        if again != w:
            fail(o, '%s word %d roundtrip drift %#x' % (tag, i, w))
        if 'subi' in d and 'subs' not in d:
            fail(o, '%s word %d uses subi (reversed-order trap): %s'
                 % (tag, i, d))
        if d.startswith(('b.', 'jump')) and not re.match(
                r'^b\.[tf]\.0x[0-9a-f]+ zero,0x[0-9a-f]+$|^jump '
                r'0x[0-9a-f]+$', d):
            fail(o, '%s word %d unexpected branch render: %s'
                 % (tag, i, d))
    return ws


def gate_disc(c):
    o = c.o
    d1 = _probe_words(D1_TEXT, 'D1', o)
    d2 = _probe_words(D2_TEXT, 'D2', o)
    d3 = _probe_words(D3_TEXT, 'D3', o)
    if d1[5] != 0xfce73005:
        fail(o, 'D1 subs word != the v10/validator class word fce73005 '
             '(got %#x)' % d1[5])
    if (d1[6] >> 26) != (0xa4000002 >> 26) or \
            (d1[6] & 0x001f0000) != 0:
        fail(o, 'D1 b.f word is not the b.f.0x0 allow-exit class')
    if irisc_dis.dis(d1[6], STUB_SLOT + 4 * 6) != \
            'b.f.0x0 zero,0x%x' % D1_ARM_A:
        fail(o, 'D1 b.f target resolution mismatch')
    if d1[11] != 0 and irisc_dis.dis(d1[11], STUB_SLOT + 4 * 11) != \
            'jump 0x%x' % D1_JOIN:
        fail(o, 'D1 jump target resolution mismatch')
    canary_base = re1.STUB_B3_WORDS[4][1]
    if d2[6] != canary_base:
        fail(o, 'D2 store base word != the proven canary addi '
             '(got %#x want %#x)' % (d2[6], canary_base))
    if irisc_dis.dis(d2[7], STUB_SLOT + 4 * 7) != 'st.d r7,r4,0x0':
        fail(o, 'D2 echo store form mismatch')
    v6 = re1.STUB_B6_WORDS
    if [w for _, w in v6[2:5]] != d3[1:4]:
        fail(o, 'D3 filter words not bit-exact the re1 v6 filter '
             'words (ld.i/set3/cmp38)')
    if not irisc_dis.dis(d3[4], STUB_SLOT + 4 * 4).startswith(
            'b.f.0xa zero,0x%x' % D3_ARM_T):
        fail(o, 'D3 b.f.0xa form/target mismatch')
    marks = ('0x%x' % ((ARM_EQ_MARK >> 16) & 0xffff),
             '0x%x' % (ARM_EQ_MARK & 0xffff),
             '0x%x' % ((ARM_NE_MARK >> 16) & 0xffff),
             '0x%x' % (ARM_NE_MARK & 0xffff))
    for tag, ws in (('D1', d1), ('D3', d3)):
        txt = ' '.join(irisc_dis.dis(w, STUB_SLOT + 4 * i)
                       for i, w in enumerate(ws))
        for mk in marks:
            if mk not in txt:
                fail(o, '%s does not compose marker halfword %s'
                     % (tag, mk))
    o('[GD] discriminators assembled strict cx5 (per-word decode-'
      'verify + roundtrip bit-exact): D1 subs/cc0 two-arm %d w (subs '
      'word == the validator class 0xfce73005; b.f.0.0 allow-exit '
      'class; markers 0x%08x = ARM_EQ fallthrough / 0x%08x = ARM_NE '
      'taken), D2 subs-rd echo %d w (store base '
      'bit-exact the v3 canary word), D3 cc0a-no-stock-call %d w '
      '(filter words bit-exact the re1 v6 words; single b.f.0xa; '
      'same ARM_EQ/ARM_NE marker semantics); '
      'budgets %d/%d/%d <= 32; 0 subi/subsi anywhere (reversed-order '
      'trap avoided); branch targets resolved from the encoded forms'
      % (len(d1), ARM_EQ_MARK, ARM_NE_MARK, len(d2), len(d3),
         len(d1), len(d2), len(d3)))


CANON_FACTS = (
    'v7 always-taken x4 deterministic',
    'v6 bit-exact S2 words silent',
    'v3/v4/v5 unconditional alive',
    'v5 links exact (store, load/addr/conversion, magic-read, '
    'set-pair)',
)


def gate_matrix(c):
    o = c.o
    for key in ('v1_v2_filter', 'v3_v5_unconditional',
                'v6_v9_cc0a_branches', 'v10_subs_cc2',
                'v11_v12_branchless', 'unified',
                'live_facts_checklist'):
        if key not in MATRIX_EXPLANATION:
            fail(o, 'MATRIX_EXPLANATION missing %s' % key)
    for key in ('v1_v2_filter', 'v3_v5_unconditional',
                'v6_v9_cc0a_branches', 'v10_subs_cc2',
                'v11_v12_branchless'):
        cls = MATRIX_EXPLANATION[key]
        for req in ('versions', 'live', 'cause', 'class'):
            if req not in cls:
                fail(o, 'class %s missing %s' % (key, req))
    for req in ('sub_hypotheses', 'exclusions', 'open'):
        if req not in MATRIX_EXPLANATION['v6_v9_cc0a_branches']:
            fail(o, 'v6_v9 missing %s' % req)
    for req in ('alt', 'open'):
        if req not in MATRIX_EXPLANATION['v11_v12_branchless']:
            fail(o, 'v11_v12 missing %s' % req)
    got_facts = set(MATRIX_EXPLANATION['live_facts_checklist'])
    for f in CANON_FACTS:
        if not any(f.startswith(g) for g in got_facts):
            fail(o, 'live fact not checked in the matrix: %s' % f)
    idiom = H0_VERDICT['idiom']
    if 'subs r7,r7,r6' not in idiom['words'] or \
            'b.f.0x0' not in idiom['words'][1]:
        fail(o, 'H0 idiom words must be the subs + b.f.0.0 pair')
    if 'D1' not in H0_VERDICT['gate'] or \
            'H1/H2' not in H0_VERDICT['fallback']:
        fail(o, 'H0 verdict must gate on D1 and fall back to H1/H2')
    if len(DISCRIMINATORS) < 2:
        fail(o, 'need >= 2 discriminators')
    for k, dd in DISCRIMINATORS.items():
        for req in ('question', 'shape', 'inputs', 'expectations',
                    'decides'):
            if req not in dd:
                fail(o, 'discriminator %s missing %s' % (k, req))
        if len(dd['expectations']) < 2:
            fail(o, 'discriminator %s needs >= 2 expected outcomes' % k)
    for k in ('cc0a_cmpres', 'cc0_eq', 'cc2_order', 'cc1_cc3_cc4'):
        if k not in CC_MAP['channels']:
            fail(o, 'CC_MAP missing channel %s' % k)
    for k in ('cc0a_cmpres', 'flags', 'pre_wrapper_residue'):
        if k not in CC_MAP['latch_at_stub_filter']:
            fail(o, 'latch map missing %s' % k)
    o('[GX] matrix complete: 5 classes covered (cause or explicit '
      'open+discriminator), all four R-E live facts explicitly '
      'compatibility-checked; H0_VERDICT = fixable-candidate with the '
      'subs+b.f.0.0 allow-exit idiom, gated on D1, fallback H1/H2; %d '
      'discriminators with per-outcome expectations; CC_MAP channels '
      '+ latch state complete' % len(DISCRIMINATORS))


def main():
    c = Ctx()
    c.o = Out()
    o = c.o
    o('cx5 cond-stub rf2 cc trace: %s' % BASE.name)
    gate_base(c)
    gate_trace(c)
    gate_wrapper(c)
    gate_model(c)
    gate_inv(c)
    gate_census(c)
    gate_disc(c)
    gate_matrix(c)
    o('ALL GATES PASS ([0] GT GW GM GI GI+ GD GX)')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open('a') as f:
        f.write('\n'.join(o.lines) + '\n')
    o('DONE log+= %s' % LOG)


if __name__ == '__main__':
    main()
