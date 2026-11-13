#!/usr/bin/env python3
"""fuzz-5 vector matrix (offline): live battery vectors from census_map.json.

Protocol (fuzz-4 §3, unchanged): 10 words (40B BE) per vector — up to 7
free code words + fixed resume tail to rt 0x8E43C8; word0-nop gate is the
tool's; writes only to echo [r18+0x10..0x38) and CR rt 0x2320..0x233c;
push/frame forbidden; r11/r17..r23 untouched.  Gates per vector are reused
from cx5-fuzz4/gen_vectors.py (assemble strict cx5 = decode-verify of every
word, write-discipline, compose, tail/budget asserts).

Vector families (plan Task 2):
- fuzz4rem: eq32/eq16 separator (width-masked pair), ltV known-T
  predecessor probe, cmp38-self repeat with separating operand, 0x0c
  H-0c-hi-and discriminator.
- map36: one anchor per f5 axis 0..31 (i6=0 reg-reg where the census row
  has sites, f5_fill synthetic i6=0, mask-only rows at their own i6;
  live_only=true for zero-site rows) + imm6-form sample of top-site i6!=0
  rows.
- map33/map34: per-f5 class vectors, idx sampling = boundary {0,1,15,16,31}
  (within availability) + Rosetta (max-4030-site row of the class);
  class-specific hypothesis spaces (deposit replace/merge, minmax, clamp,
  bclr, ALU fallback); zero-site f5 axes as live_only synthetic anchors.
- c2rare: 0x16 shift-family discriminators (negative seeded rs), 0x39/0x3c
  second-support captures, 0x0c imm-axis robustness extras, 0x38 sel=4
  value-form anchor (sel 1/20 need rd=r1/r20 — frozen).

Expectations are generated ONLY programmatically from the model registry
below; the registry passes a sanity gate reproducing every known live
value (V-33-1/2/3, V-34-1/6, V-0c-1/2/3, V-r-16).  Value-vector
expectations are low32-only (8 hex digits): the high32 channel is the
unverified 4B-store class (fuzz-4 runner LOW32 verdicts, stale rd upper).
cc0a vectors write a deterministically built operand register, so their
F-path expectations are full 64-bit; T-path expectations are the CR
sentinel 0xdeadbeef (or 'stock' echo for the wide-operand echo form).

Operand choice per row = argmax separation over the FULL hypothesis space
of the row (calc-table method WP-1 §6): value vectors maximize the number
of pairwise-distinct low32 outcomes; cc0a vectors maximize the smaller
side of the T/F partition of the surviving predicate space.  Ties break
deterministically (cheaper operand encoding, then lexicographic).

Output: fuzz5_vectors.json — fuzz-4 record format (array; id/group/words/
seeds/expectations/controls/notes) + additive fields live_only (zero-site
synthetics), census_rows (coverage join keys), stale_t (reserved; all
fuzz-5 cc0a vectors carry a known-state predecessor).  The battery order
is the file order minus V-F4-MARKER (health vector, record copied from
fuzz4_vectors.json); zero-site anchors are emitted last.

Coverage gate (fix round 1): skips of mandatory census rows are ONLY
possible via the reviewed CURATED_SKIPS rule table (static reasons, no
per-row auto-assignment); the design target sets (design33/design34/
anchor36/imm36_samples/OC_DESIGN_IMMS/OP38_DESIGN_SELS) are the single
source shared by builders and the gate — every required row MUST be
covered by a vector (assert_required fails otherwise), and an uncovered
mandatory row outside the curated rules fails finalize().  Degradation
of targeting therefore falls; changes to the design/curated tables are
explicit, diff-reviewable curation decisions.
"""
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'scripts' / 'probes' / 'cx5-fuzz4'))

import gen_vectors as f4
from scripts.irisc import AsmError

CENSUS = Path(__file__).resolve().parent / 'census_map.json'
F4JSON = REPO / 'scripts' / 'probes' / 'cx5-fuzz4' / 'fuzz4_vectors.json'
OUT = Path(__file__).resolve().parent / 'fuzz5_vectors.json'

M32 = 0xffffffff
M64 = 0xffffffffffffffff


def s32(v):
    v &= M32
    return v - 0x100000000 if v & 0x80000000 else v


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


# --------------------------------------------------------------- models ---

def dep_r(rs, rt, w, idx):
    if w == 0:
        return rs & M64
    m = (((1 << w) - 1) << idx) & M64
    return ((rs & ~m) & M64) | (((rt & ((1 << w) - 1)) << idx) & M64)


def dep_m(rs, rt, w, idx):
    if w == 0:
        return rs & M64
    return (rs | (((rt & ((1 << w) - 1)) << idx) & M64)) & M64


def bclr(rs, rt, idx):
    return rs & ~(1 << idx) & M64


def alu_min(rs, rt, sel):
    return min(rs & M32, rt & M32)


def alu_max(rs, rt, sel):
    return max(rs & M32, rt & M32)


def alu_add(rs, rt, sel):
    return (rs + rt) & M32


def alu_sub(rs, rt, sel):
    return (rs - rt) & M32


def alu_and(rs, rt, sel):
    return rs & rt & M32


def alu_or(rs, rt, sel):
    return (rs | rt) & M32


def alu_xor(rs, rt, sel):
    return (rs ^ rt) & M32


def pass_rs(rs, rt, sel):
    return rs & M64


def zero_rd(rs, rt, sel):
    return 0


def clamp16(rs, rt, sel):
    return ((min(rs & M32, rt & M32) & 0xffff) << sel['idx']) & M64


def fldmin16(rs, rt, sel):
    idx = sel['idx']
    return ((min((rs >> idx) & 0xffff, rt & 0xffff)) << idx) & M64


def minsh(rs, rt, sel):
    return ((min(rs & M32, rt & M32)) << sel['idx']) & M64


ALU8 = [('H-min', alu_min), ('H-max', alu_max), ('H-add', alu_add),
        ('H-sub', alu_sub), ('H-and', alu_and), ('H-or', alu_or),
        ('H-xor', alu_xor)]

PRED36 = {
    'H-eq32': lambda a, b: (a & M32) == (b & M32),
    'H-eq16': lambda a, b: (a & 0xffff) == (b & 0xffff),
    'H-ne32': lambda a, b: (a & M32) != (b & M32),
    'H-lt32': lambda a, b: s32(a) < s32(b),
    'H-lt16': lambda a, b: s16(a) < s16(b),
    'H-uge32': lambda a, b: (a & M32) >= (b & M32),
    'H-ugt32': lambda a, b: (a & M32) > (b & M32),
    'H-ule32': lambda a, b: (a & M32) <= (b & M32),
    'H-V': lambda a, b: False,
}

PRIOR36 = {
    0x2: ['H-uge32', 'H-ugt32', 'H-V'],
    0xa: ['H-lt32', 'H-eq32', 'H-eq16', 'H-ule32', 'H-V'],
}

EQSPACE = [('H-eq32', PRED36['H-eq32']), ('H-eq16', PRED36['H-eq16']),
           ('H-uge32', PRED36['H-uge32']), ('H-ule32', PRED36['H-ule32'])]

LTVSPACE = [('H-lt32', PRED36['H-lt32']), ('H-lt16', PRED36['H-lt16']),
            ('H-uge32', PRED36['H-uge32']), ('H-ugt32', PRED36['H-ugt32']),
            ('H-V', PRED36['H-V'])]


def imm6_space(i6):
    def eq(rs, rt):
        return (rs & M32) == i6

    def ne(rs, rt):
        return (rs & M32) != i6

    def lt(rs, rt):
        return s32(rs) < i6

    def uge(rs, rt):
        return (rs & M32) >= i6
    return [('H-eq32i', eq), ('H-ne32i', ne), ('H-lt32i', lt),
            ('H-uge32i', uge), ('H-V', PRED36['H-V'])]


def bswap16(v):
    return ((v & 0xff) << 8) | ((v >> 8) & 0xff)


def op0c_space():
    def mk(fn):
        return lambda rs, rt, sel: fn(rs & M32, sel['imm16']) & M32
    return [
        ('H-0c-hiand', mk(lambda r, i: r & ((i << 16) | 0xffff))),
        ('H-0c-andn-raw', mk(lambda r, i: r & ~i)),
        ('H-0c-andn-sh16', mk(lambda r, i: r & ~(i << 16))),
        ('H-0c-and-raw', mk(lambda r, i: r & i)),
        ('H-0c-and-sh16', mk(lambda r, i: r & (i << 16))),
        ('H-0c-or', mk(lambda r, i: r | i)),
        ('H-0c-bswap', mk(lambda r, i: r & ~(bswap16(i) << 16))),
        ('H-0c-repl', mk(lambda r, i: r & (i | (i << 16)))),
        ('H-0c-loonly', mk(lambda r, i: r & 0xffff)),
        ('H-0c-pass', mk(lambda r, i: r)),
    ]


def op16_space(lo11):
    sh = lo11 & 0x3f

    def u64(rs, rt, sel):
        return (rs >> sh) & M64

    def a64(rs, rt, sel):
        v = rs
        for _ in range(sh):
            v = (v >> 1) | (v & 0x8000000000000000)
        return v & M64

    def u32(rs, rt, sel):
        return (rs & M32) >> sh

    def a32(rs, rt, sel):
        lo = rs & M32
        for _ in range(sh):
            lo = (lo >> 1) | (lo & 0x80000000)
        return lo & M32
    if sh == 0:
        return [('H-16-pass', lambda rs, rt, sel: rs),
                ('H-16-zero', lambda rs, rt, sel: 0),
                ('H-16-hi2lo', lambda rs, rt, sel: rs >> 32)]
    return [('H-16-shr64u', u64), ('H-16-shr64a', a64),
            ('H-16-shr32u', u32), ('H-16-shr32a', a32)]


def op39_space():
    return [('H-39-lo', lambda rs, rt, sel: rs & M32),
            ('H-39-hi-swap', lambda rs, rt, sel: rs >> 32),
            ('H-39-zero', lambda rs, rt, sel: 0)]


def op3c_space(lo11):
    return [('H-3c-zero', lambda rs, rt, sel: 0),
            ('H-3c-pass', lambda rs, rt, sel: rs & M32),
            ('H-3c-rt', lambda rs, rt, sel: rt & M32),
            ('H-3c-andn-lo11', lambda rs, rt, sel: rs & ~lo11 & M32),
            ('H-3c-and-lo11', lambda rs, rt, sel: rs & lo11)]


def op38v_space():
    return [('H-38v-bool-eq', lambda rs, rt, sel: 1 if (rs & M32) == (rt & M32) else 0),
            ('H-38v-bool-ne', lambda rs, rt, sel: 1 if (rs & M32) != (rt & M32) else 0),
            ('H-38v-rs', lambda rs, rt, sel: rs & M32),
            ('H-38v-rt', lambda rs, rt, sel: rt & M32)]


def sanity_models():
    ck = []
    r = dep_r(0, 1, 1, 25) & M32
    ck.append(('V-33-1 bit@25', r == 0x02000000))
    ck.append(('V-33-2 min', alu_min(5, 3, None) == 3))
    ck.append(('V-33-3 clamp16', clamp16(0x168000, 0x100, {'idx': 14}) & M32 == 0x400000))
    ck.append(('V-34-1 bclr', bclr(M64, 0, 1) == 0xfffffffffffffffd))
    r = dep_r(0x00000000ffffffff, 0, 6, 4) & M32
    ck.append(('V-34-6 depR W6@4', r == 0xfffffc0f))
    hiand = lambda r_, i: r_ & ((i << 16) | 0xffff)
    ck.append(('V-0c-1', hiand(0xabcd1234, 0x00ff) == 0x00cd1234))
    ck.append(('V-0c-2', hiand(0, 0xff00) == 0))
    ck.append(('V-0c-3', hiand(0x12345678, 0x0f00) == 0x02005678))
    ck.append(('V-r-16 shr', (0x00100000 >> 0x28) == 0))
    bad = [n for n, ok in ck if not ok]
    if bad:
        raise AsmError('model sanity failed: %s' % ', '.join(bad))


# ------------------------------------------------------------ operands ---

class Opnd:
    def __init__(self, kind, val, cost):
        self.kind = kind
        self.val = val
        self.cost = cost

    @property
    def sort(self):
        return ('%s:%016x' % (self.kind, self.val))


ADDI_POOL = [0, 1, 2, 3, 5, 7, 0x0a, 0x0c, 0x0f, 0x21, 0x25, 0x3c, 0x55,
             0x5a, 0x0f0, 0xa5, 0xf0, 0xff, 0x1234, 0x1fff, 0x7ffe, 0x7fff]
CONST32_POOL = [0x00010005, 0x00020005, 0x0f0f0f0f, 0x12345678, 0x0ff00ff0,
                0x55aa55aa, 0x00020003, 0x1e5a5c3f]
SEED_POOL = [(0xffffffff, 0xffffffff), (0, 0xffffffff), (0, 0xa5a5f0f0),
             (0, 0xffff0000), (0, 0x80000000), (0x80000000, 0),
             (0xffffffff, 0x80000000), (0x89abcdef, 0x12345678),
             (0, 0x0f0f0f0f), (0, 0x12345678), (0, 0x00020005),
             (0xffffffff, 0x0f0f0f0f), (0x5a5a5a5a, 0xa5a5f0f0)]


def reg64(v):
    return (v & M32, 0xffffffff if v & 0x8000000000000000 else 0)


def signext64(v16):
    v16 &= 0xffff
    return (v16 - 0x10000 if v16 & 0x8000 else v16) & M64


def operand_pool():
    pool = [Opnd('addi', signext64(v), 1) for v in ADDI_POOL]
    pool += [Opnd('const32', v, 2) for v in CONST32_POOL]
    pool += [Opnd('seed', (hi << 32) | lo, 2) for hi, lo in SEED_POOL]
    return pool


CANDS = operand_pool()


def argmax_value(space, sel, fixed_rt=None, fixed_rs=None):
    best = None
    rss = fixed_rs if fixed_rs else CANDS
    rts = [fixed_rt] if fixed_rt else CANDS
    for rs in rss:
        for rt in rts:
            if rs.kind == 'seed' and rt.kind == 'seed':
                continue
            cost = rs.cost + rt.cost
            if cost > 3:
                continue
            outs = [(h, fn(rs.val, rt.val, sel) & M32) for h, fn in space]
            score = len(set(v for _, v in outs))
            key = (-score, cost, rs.sort, rt.sort)
            if best is None or key < best[0]:
                best = (key, rs, rt, outs)
    if best is None or -best[0][0] < 2:
        raise AsmError('argmax_value degenerate for sel %r' % sel)
    return best[1], best[2], best[3]


# ------------------------------------------------------------ builders ---

def opnd_words(spec, reg):
    if spec.kind == 'addi':
        hi = 0xffffffff if spec.val & 0x8000000000000000 else 0
        return ['addi %s,zero,0x%x' % (reg, spec.val & 0xffff)], \
            (spec.val & M32, hi)
    if spec.kind == 'const32':
        lo, hi = spec.val & 0xffff, (spec.val >> 16) & 0xffff
        if lo >= 0x8000 or hi >= 0x8000:
            raise AsmError('const32 negative half')
        return ['addi %s,zero,0x%x' % (reg, lo),
                'addi.hi %s,%s,0x%x' % (reg, reg, hi)], (spec.val & M32, 0)
    hiw, low = (spec.val >> 32) & M32, spec.val & M32
    return (['addi r7,zero,0x%x' % f4.SEED_A_RT, 'ld.d %s,r7,0' % reg],
            (low, hiw))


def value_vec(vid, group, op_line, rs, rt, space, sel, census_rows,
              live_only=False, extra_notes=''):
    w5, v5 = opnd_words(rs, 'r5')
    w6, v6 = opnd_words(rt, 'r6')
    if rs.kind == 'seed' and rt.kind == 'seed':
        raise AsmError('%s: double seed' % vid)
    if rs.kind == 'seed' and rt.kind == 'addi':
        body = w5 + w6
        opidx = 3
    elif rt.kind == 'seed':
        body = w6[:1] + w5 + w6[1:]
        opidx = 3
    else:
        body = w5 + w6
        opidx = len(body)
    body = body[:opidx] + [op_line] + body[opidx:]
    body += ['addi r3,zero,0x%x' % f4.CR_SLOT_RT, 'st.d r4,r3,0',
             'st.d r4,r18,0x10']
    regs = {'r5': v5, 'r6': v6}
    exps = {}
    for h, fn in space:
        lo = fn(rs.val, rt.val, sel) & M32
        exps[h] = {'0x8c8': '0x%08x' % lo, 'echo': '0x%08x' % lo}
    vec = {
        'id': vid, 'group': group, 'body': body,
        'reg_checks': [f4.ck(opidx, **regs)],
        'expectations': exps,
        'census_rows': census_rows,
        'notes': '%s | space %d H, split %d distinct low32%s' % (
            extra_notes, len(space), len(exps_set(exps)),
            ' | live_only (zero-site synthetic)' if live_only else ''),
    }
    seeds = {}
    if rs.kind == 'seed':
        seeds['0x8c6'], seeds['0x8c7'] = '%08x' % (rs.val & M32), '%08x' % ((rs.val >> 32) & M32)
    if rt.kind == 'seed':
        seeds['0x8c6'], seeds['0x8c7'] = '%08x' % (rt.val & M32), '%08x' % ((rt.val >> 32) & M32)
    if seeds:
        vec['seeds'] = seeds
    if live_only:
        vec['live_only'] = True
    return vec


def exps_set(exps):
    return {(e['0x8c8']) for e in exps.values()}


PAIR_POOL = [(3, 5), (5, 3), (7, 3), (3, 7), (0, 1), (1, 0),
             (0x1234, 0x1235), (5, 0x7fff), (0x7fff, 5), (0, 5), (5, 0),
             (1, 2), (2, 1), (0x5a, 0xa5), (0xa5, 0x5a), (0x7ffe, 0x7fff),
             (0xffffffffffff8000, 0x7fff), (0x7fff, 0xffffffffffff8000),
             (0x0000000000010005, 0x7fff)]


def argmax_pair(space, pairs):
    best = None
    for a, b in pairs:
        t = [h for h, fn in space if fn(a, b)]
        f = [h for h, fn in space if not fn(a, b)]
        key = (-min(len(t), len(f)), -max(len(t), len(f)),
               1 if b == 0 else 0, a, b)
        if best is None or key < best[0]:
            best = (key, a, b, t, f)
    return best[1], best[2], best[3], best[4]


def addi_ok(v):
    return 0 <= v <= 0x7fff


def cc0a_cr_vec(vid, group, f5, pair, space, census_rows, live_only=False,
                extra_notes=''):
    a, b = pair
    seeds = None
    if addi_ok(a) and addi_ok(b):
        body = ['addi r3,zero,0x%x' % f4.CR_SLOT_RT,
                'addi r5,zero,0x%x' % a, 'addi r6,zero,0x%x' % b,
                'cmp38_eq32 r5,r6',
                'op0x36 zero,r5,r6 imm=0x%03x' % f5,
                'b.t.0xa zero,tail', 'st.d r6,r3,0']
        checks = [f4.ck(3, r5=(a, 0), r6=(b, 0))]
        controls = {'cr_sentinel': f4.SENTINEL}
        wexp = '0x%016x' % b
        chan = '0x8c8'
        wval = {chan: wexp}
        tval = {chan: '0xdeadbeef'}
        form = 'CR-sentinel form'
    elif addi_ok(b) or addi_ok(a):
        if addi_ok(a):
            a, b = b, a
        body = ['addi r7,zero,0x%x' % f4.SEED_A_RT, 'ld.d r5,r7,0',
                'addi r6,zero,0x%x' % b, 'cmp38_eq32 r5,r6',
                'op0x36 zero,r5,r6 imm=0x%03x' % f5,
                'b.t.0xa zero,tail', 'st.d r6,r18,0x10']
        checks = [f4.ck(3, r5=(a & M32, (a >> 32) & M32), r6=(b, 0))]
        controls = {'echo_stale': 'stock'}
        wexp = '0x%016x' % b
        wval = {'echo': wexp}
        tval = {'echo': 'stock'}
        seeds = {'0x8c6': '%08x' % (a & M32),
                 '0x8c7': '%08x' % ((a >> 32) & M32)}
        form = 'echo form (seeded wide operand rs)'
    else:
        raise AsmError('%s: pair not realizable in 7 words' % vid)
    exps = {}
    for h, fn in space:
        exps[h] = tval if fn(a, b) else wval
    vec = {'id': vid, 'group': group, 'body': body,
           'reg_checks': checks,
           'expectations': exps, 'controls': controls,
           'census_rows': census_rows,
           'notes': 'f5=%d i6=0 pair (0x%x,0x%x) known-F predecessor; '
                    'T->no-write, F->write rt; %s%s%s' % (
                        f5, a, b, form,
                        ' | live_only (zero-site synthetic)' if live_only else '',
                        ' | ' + extra_notes if extra_notes else '')}
    if seeds is not None:
        vec['seeds'] = seeds
    if live_only:
        vec['live_only'] = True
    return vec


def cc0a_echo_vec(vid, group, f5, seed_pair, space, census_rows,
                  extra_notes=''):
    a, b = seed_pair
    body = ['addi r7,zero,0x%x' % f4.SEED_A_RT, 'ld.d r5,r7,0',
            'addi r6,zero,0x%x' % b, 'cmp38_eq32 r5,r6',
            'op0x36 zero,r5,r6 imm=0x%03x' % f5,
            'b.t.0xa zero,tail', 'st.d r6,r18,0x10']
    exps = {}
    for h, fn in space:
        exps[h] = {'echo': 'stock' if fn(a, b) else '0x%016x' % signext64(b)}
    return {'id': vid, 'group': group, 'body': body,
            'seeds': {'0x8c6': '%08x' % (a & M32),
                      '0x8c7': '%08x' % ((a >> 32) & M32)},
            'reg_checks': [f4.ck(3, r5=(a & M32, (a >> 32) & M32),
                                 r6=(signext64(b) & M32, 0))],
            'expectations': exps, 'controls': {'echo_stale': 'stock'},
            'census_rows': census_rows,
            'notes': 'f5=%d i6=0 width-masked pair (0x%x,0x%x) echo form '
                     '(seed delivers the wide operand within budget); '
                     'known-F predecessor; T->stock, F->write rt | %s'
                     % (f5, a, b, extra_notes)}


def imm6_vec(vid, group, f5, i6, rs_val, space, census_rows,
             live_only=False, extra_notes=''):
    lo11 = (i6 << 5) | f5
    other = rs_val ^ 1
    body = ['addi r3,zero,0x%x' % f4.CR_SLOT_RT,
            'addi r5,zero,0x%x' % rs_val, 'addi r6,zero,0x%x' % other,
            'cmp38_eq32 r5,r6',
            'op0x36 zero,r5,zero imm=0x%03x' % lo11,
            'b.t.0xa zero,tail', 'st.d r5,r3,0']
    exps = {}
    for h, fn in space:
        exps[h] = {'0x8c8': '0xdeadbeef' if fn(signext64(rs_val), 0)
                   else '0x%016x' % signext64(rs_val)}
    vec = {'id': vid, 'group': group, 'body': body,
           'reg_checks': [f4.ck(3, r5=reg64(signext64(rs_val)),
                                r6=reg64(signext64(other)))],
           'expectations': exps, 'controls': {'cr_sentinel': f4.SENTINEL},
           'census_rows': census_rows,
           'notes': 'imm6 form f5=%d i6=%d rs=0x%x (rt field zero); known-F '
                    'predecessor; F-path writes rs%s%s' % (
                        f5, i6, rs_val,
                        ' | live_only (zero-site mask row)' if live_only else '',
                        ' | ' + extra_notes if extra_notes else '')}
    if live_only:
        vec['live_only'] = True
    return vec


def argmax_imm6(i6):
    best = None
    for v in ADDI_POOL:
        t = [h for h, fn in imm6_space(i6) if fn(signext64(v), 0)]
        f = [h for h, fn in imm6_space(i6) if not fn(signext64(v), 0)]
        key = (-min(len(t), len(f)), -max(len(t), len(f)),
               1 if v == 0 else 0, v)
        if best is None or key < best[0]:
            best = (key, v)
    return best[1]


# --------------------------------------------------------------- census ---

def load_census():
    data = json.loads(CENSUS.read_text())
    rows = data['rows']
    byid = {r['id']: r for r in rows}
    return data, rows, byid


def row_id33(op, f5, idx, flag):
    return 'op%02x_f5=%02x_idx=%02x_flag=%d' % (op, f5, idx, flag)


def row_id36(f5, i6):
    return 'op36_f5=%02x_i6=%02x' % (f5, i6)


def row_id0c(imm):
    return 'op0c_imm=%04x' % imm


def row_id38(sel):
    return 'op38_sel=%02x' % sel


def row_idrare(op, lo11):
    return 'op%02x_lo11=%03x' % (op, lo11)


def total_sites(r):
    return sum(r['sites'].values())


def f5_map(op, rows):
    m = {}
    for r in rows:
        if int(r['op'], 16) == op and 'f5' in r['selector']:
            m.setdefault(r['selector']['f5'], []).append(r)
    return m


def rosetta_row(rs):
    best = None
    for r in rs:
        key = (-r['sites'].get('4030', 0), -total_sites(r),
               r['selector'].get('idx', 0))
        if best is None or key < best[0]:
            best = (key, r)
    return best[1]


def space33(f5, idx):
    if f5 == 1 or f5 in (4, 8):
        return [('H-depR', lambda rs, rt, sel: dep_r(rs, rt, f5, sel['idx'])),
                ('H-depM', lambda rs, rt, sel: dep_m(rs, rt, f5, sel['idx']))]
    if f5 == 24:
        sp = [('H-depR', lambda rs, rt, sel: dep_r(rs, rt, 24, sel['idx'])),
              ('H-depM', lambda rs, rt, sel: dep_m(rs, rt, 24, sel['idx'])),
              ('H-min', alu_min)]
        if idx == 0:
            return sp + [('H-max', alu_max), ('H-add', alu_add),
                         ('H-or', alu_or)]
        return sp + [('H-minsh', minsh)]
    if f5 == 16:
        return [('H-depR', lambda rs, rt, sel: dep_r(rs, rt, 16, sel['idx'])),
                ('H-depM', lambda rs, rt, sel: dep_m(rs, rt, 16, sel['idx'])),
                ('H-clamp16', clamp16), ('H-fldmin16', fldmin16)]
    if f5 == 0:
        return [('H-pass', pass_rs), ('H-zero', zero_rd)] + ALU8
    return ([('H-depR', lambda rs, rt, sel: dep_r(rs, rt, f5, sel['idx'])),
             ('H-depM', lambda rs, rt, sel: dep_m(rs, rt, f5, sel['idx']))]
            + ALU8)


def space34(f5, idx):
    if f5 == 2:
        return [('H-bclr', lambda rs, rt, sel: bclr(rs, rt, sel['idx'])),
                ('H-depR', lambda rs, rt, sel: dep_r(rs, rt, 2, sel['idx'])),
                ('H-depM', lambda rs, rt, sel: dep_m(rs, rt, 2, sel['idx']))]
    if f5 in (4, 6, 8, 12):
        return [('H-depR', lambda rs, rt, sel: dep_r(rs, rt, f5, sel['idx'])),
                ('H-depM', lambda rs, rt, sel: dep_m(rs, rt, f5, sel['idx']))]
    if f5 == 0:
        return [('H-pass', pass_rs), ('H-zero', zero_rd)] + ALU8
    return ([('H-depR', lambda rs, rt, sel: dep_r(rs, rt, f5, sel['idx'])),
             ('H-depM', lambda rs, rt, sel: dep_m(rs, rt, f5, sel['idx']))]
            + ALU8)


# ---------------------------------------------------------- group build ---

def build_fuzz4rem(cov):
    vecs = []
    eq_pair = (0x00010005, 0x0005)
    a, b = eq_pair
    v = cc0a_echo_vec('V-F5R-EQ', 'fuzz4rem', 4, eq_pair, EQSPACE,
                      [row_id36(4, 0)],
                      'eq32/eq16 separator: width-masked descendant of the '
                      '(0x10005,0x20003) start pair — low16 equal, high16 '
                      'differ (0x10005 vs 0x0005); T={eq16} F={eq32,uge32,'
                      'ule32}; with fuzz-4 deaths (uge/ule) the outcome '
                      'pins eq16 vs eq32; 7-word budget forces seed+addi '
                      '(const32 pair + predecessor = 8)')
    vecs.append(v)
    cov.claim(row_id36(4, 0), 'V-F5R-EQ')

    pair, t, f = (3, 5), None, None
    v = cc0a_cr_vec('V-F5R-LTV', 'fuzz4rem', 2, pair, LTVSPACE,
                    [row_id36(2, 0)],
                    extra_notes='ltV known-T: resolves the fuzz-4 stale-T '
                    'ambiguity (both ltV vectors wrote F-path); T=>{lt32,'
                    'lt16} write cc, F=>{uge32,ugt32,V} — survivors of the '
                    'ltV pair; seed not needed, CR sentinel fits 7 slots')
    vecs.append(v)
    cov.claim(row_id36(2, 0), 'V-F5R-LTV')

    body = ['addi r5,zero,0x1234', 'addi r6,zero,5', 'addi r7,zero,5',
            'cmp38_eq32 r6,r7', 'cmp38_eq32 r5,r5',
            'b.t.0xa zero,tail', 'st.d r5,r18,0x10']
    vecs.append({
        'id': 'V-F5R-38SELF', 'group': 'fuzz4rem', 'body': body,
        'reg_checks': [f4.ck(4, r5=(0x1234, 0))],
        'expectations': {'H-38self-false': {'echo': '0x0000000000001234'},
                         'H-38self-keepT': {'echo': 'stock'}},
        'controls': {'echo_stale': 'stock'},
        'census_rows': [row_id38(0)],
        'notes': 'cmp38-self repeat with separating operand 0x1234 (fuzz-4 '
                 'used 7==7 for both predecessor and self); known-T '
                 'predecessor on an independent pair r6,r7=5,5 — T-path '
                 'echo=stock is decisive (predecessor set cc)',
    })
    cov.claim(row_id38(0), 'V-F5R-38SELF')
    return vecs


def build_0c_vec(vid, group, imm, cov, rows0c, notes):
    sel = {'imm16': imm}
    space = op0c_space()
    best = None
    for cand in CANDS:
        if cand.cost > 2:
            continue
        o = [(h, fn(cand.val, 0, sel) & M32) for h, fn in space]
        sc = len(set(v for _, v in o))
        key = (-sc, cand.cost, cand.sort)
        if best is None or key < best[0]:
            best = (key, cand, o)
    rs = best[1]
    op = 'andmsk.hi r4,r5,0x%04x' % imm
    v = value_vec(vid, group, op, rs, Opnd('addi', 0, 1), space, sel,
                  [row_id0c(imm)], live_only=False,
                  extra_notes=notes)
    cov.claim(row_id0c(imm), vid)
    return v


def anchor36(rows, f5):
    rs_ = [r for r in rows if int(r['op'], 16) == 0x36
           and r['selector']['f5'] == f5]
    has0 = next((r for r in rs_ if r['selector']['i6'] == 0
                 and r['class'] == 'has-sites'), None)
    if has0 is not None:
        return has0
    fill0 = next((r for r in rs_ if r['selector']['i6'] == 0), None)
    if fill0 is not None:
        return fill0
    return rosetta_row(rs_) if rs_ else None


def imm36_samples(rows):
    nz = sorted((r for r in rows if int(r['op'], 16) == 0x36
                 and r['selector']['i6'] != 0
                 and r['class'] == 'has-sites'),
                key=lambda r: (-r['sites'].get('4030', 0),
                               -total_sites(r), r['id']))
    picked = []
    seen_f5 = set()
    for r in nz:
        if len(picked) >= 3:
            break
        if r['selector']['f5'] not in seen_f5:
            picked.append(r)
            seen_f5.add(r['selector']['f5'])
    reg = next((r for r in nz if r['selector'] == {'f5': 4, 'i6': 32,
                                                   'lo11': 0x404}), None)
    if reg is not None and reg not in picked:
        picked.append(reg)
    b63 = next((r for r in nz if r['selector']['i6'] == 63), None)
    if b63 is not None and b63 not in picked:
        picked.append(b63)
    return picked


def build_map36(cov, rows):
    vecs = []
    full36 = [(h, PRED36[h]) for h in PRED36]
    anchors = [anchor36(rows, f5) for f5 in range(32)]
    for r in anchors:
        if r is None or r['selector']['f5'] == 4:
            continue
        f5 = r['selector']['f5']
        i6 = r['selector']['i6']
        live = r['class'] == 'zero-sites'
        if i6 == 0:
            space = ([(h, PRED36[h]) for h in PRIOR36[f5]]
                     if f5 in PRIOR36 else full36)
            a, b, t, f = argmax_pair(space, PAIR_POOL)
            vid = 'V-M36-f5%02d' % f5
            vecs.append(cc0a_cr_vec(vid, 'map36', f5, (a, b), space,
                                    [r['id']], live_only=live))
            cov.claim(r['id'], vid)
        else:
            rs_val = argmax_imm6(i6)
            vid = 'V-M36-f5%02d-i6%02d' % (f5, i6)
            vecs.append(imm6_vec(vid, 'map36', f5, i6, rs_val,
                                 imm6_space(i6), [r['id']], live_only=True))
            cov.claim(r['id'], vid)
    for r in imm36_samples(rows):
        f5, i6 = r['selector']['f5'], r['selector']['i6']
        rs_val = argmax_imm6(i6)
        vid = 'V-M36-f5%02d-i6%02d' % (f5, i6)
        vecs.append(imm6_vec(vid, 'map36', f5, i6, rs_val, imm6_space(i6),
                             [r['id']]))
        cov.claim(r['id'], vid)
    return vecs


def map_op_rows(op, targets, cov, group, vprefix, space_fn):
    vecs = []
    seen = set()
    for f5, idx, flag in targets:
        if (f5, idx, flag) in seen:
            continue
        seen.add((f5, idx, flag))
        sel = {'f5': f5, 'idx': idx, 'flag': flag}
        lo11 = (flag << 10) | (idx << 5) | f5
        space = space_fn(f5, idx)
        fixed_rt = None
        if op == 0x34 and lo11 == 0x022:
            fixed_rt = Opnd('addi', 0, 1)
        rs, rt, outs = argmax_value(space, sel, fixed_rt=fixed_rt)
        rtreg = 'zero' if fixed_rt is not None else 'r6'
        op_line = 'op0x%02x r4,r5,%s imm=0x%03x' % (op, rtreg, lo11)
        vid = '%s-f5%02d-i%02d' % (vprefix, f5, idx)
        if flag:
            vid += '-f1'
        rid = row_id33(op, f5, idx, flag)
        note = 'census row %s lo11=0x%03x' % (rid, lo11)
        if f5 == 24:
            note += ' | minmax class: live min (V-33-2) vs dep-R(W=24)'
        if f5 == 16 and idx == 14:
            note += ' | clamp row (V-33-3 live 0x400000)'
        if op == 0x34 and f5 == 2 and idx == 5 and flag == 0:
            note += ' | OPEN row: rogue 0x000400ff unexplained by bclr/W=2'
        if op == 0x34 and f5 == 12 and idx == 10 and flag == 1:
            note += ' | V-34-7 rogue row 0x00004c00'
        v = value_vec(vid, group, op_line, rs, rt, space, sel, [rid],
                      extra_notes=note)
        vecs.append(v)
        cov.claim(rid, vid)
    return vecs


def design33(rows):
    """Reviewed sampling design for op 0x33: (targets, zero-axis anchor).

    Targets: f5=1 boundary idx {0,1,15,16,31}; f5 in {4,8} {0,1,16} +
    rosetta; f5 in {2,3,5,6,7} idx0 + second boundary/rosetta; f5=16
    {14,0}; f5=24 {0,rosetta}; every other has-site f5 class its idx=0
    (or first available) row; f5=0 flag=1.  Zero-axis anchor: f5=19
    max-site zero row.  This function is the single source of the
    design: builders AND the coverage gate both consume it.
    """
    m33 = f5_map(0x33, rows)
    has_f5 = sorted(f5 for f5, rs_ in m33.items()
                    if any(r['class'] == 'has-sites' for r in rs_))
    targets = []

    def idx_avail(f5, flag=0):
        return sorted(r['selector']['idx'] for r in m33.get(f5, [])
                      if r['selector']['flag'] == flag
                      and r['class'] == 'has-sites')

    def rosetta(f5):
        rr = rosetta_row([r for r in m33.get(f5, [])
                          if r['class'] == 'has-sites'])
        return rr['selector']['idx']

    bnd = [i for i in F5_BOUNDARY_IDX if i in idx_avail(1)]
    targets += [(1, i, 0) for i in bnd]
    for f5 in (4, 8):
        av = idx_avail(f5)
        sel = [i for i in (0, 1, 16) if i in av] + [rosetta(f5)]
        targets += [(f5, i, 0) for i in sorted(set(sel))]
    for f5 in (2, 3, 5, 6, 7):
        extra = rosetta(f5)
        if extra == 0:
            av = [i for i in F5_BOUNDARY_IDX[1:] if i in idx_avail(f5)]
            extra = av[0] if av else sorted(set(idx_avail(f5)) - {0})[0]
        targets += [(f5, 0, 0), (f5, extra, 0)]
    targets += [(16, 14, 0), (16, 0, 0)]
    targets += [(24, 0, 0), (24, rosetta(24), 0)]
    wide = [f for f in has_f5 if f not in
            (0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 24)]
    targets += [(f5, 0, 0) for f5 in wide]
    targets += [(0, 0, 1)]
    z19 = [r for r in m33.get(19, []) if r['class'] == 'zero-sites']
    zrow = rosetta_row(z19) if z19 else None
    return targets, zrow


def build_map33(cov, rows):
    targets, zrow = design33(rows)
    vecs = map_op_rows(0x33, targets, cov, 'map33', 'V-M33', space33)
    if zrow is not None:
        idx = zrow['selector']['idx']
        sel = {'f5': 19, 'idx': idx, 'flag': 0}
        lo11 = idx << 5 | 19
        space = space33(19, idx)
        rs, rt, outs = argmax_value(space, sel)
        v = value_vec('V-M33-f519-i%02d' % idx, 'map33',
                      'op0x33 r4,r5,r6 imm=0x%03x' % lo11, rs, rt, space,
                      sel, [zrow['id']], live_only=True,
                      extra_notes='f5=19 axis anchor (zero-site class)')
        vecs.append(v)
        cov.claim(zrow['id'], v['id'])
    return vecs


def design34(rows):
    """Reviewed sampling design for op 0x34: (targets, zero-axis anchors).

    Targets: f5=2 {merged (1,0), OPEN (5,0), (0,0), rosetta, mid flag=1};
    f5=6 {0, V-34-6 class row 4}; f5 in {4,8} {0, rosetta, mid flag=1};
    f5=12 {(0,0),(10,0),(10,1)=V-34-7 rogue}; f5=0 (0,0); f5=11 first
    flag=1 row; f5=27 {rosetta, rosetta flag=1}; every other has-site
    class idx=0 (or first available, flag=0 preferred).  Zero-axis
    anchors: f5_fill synthetic rows for f5 in {1,19,21,23,25}.
    """
    m34 = f5_map(0x34, rows)
    has_f5 = sorted(f5 for f5, rs_ in m34.items()
                    if any(r['class'] == 'has-sites' for r in rs_))

    def rows_of(f5, flag):
        return [r for r in m34.get(f5, [])
                if r['selector']['flag'] == flag
                and r['class'] == 'has-sites']

    def rosetta(f5):
        rr = rosetta_row([r for r in m34.get(f5, [])
                          if r['class'] == 'has-sites'])
        return rr['selector']['idx'], rr['selector']['flag']

    targets = [(2, 1, 0), (2, 5, 0), (2, 0, 0)]
    ri, rfl = rosetta(2)
    targets.append((2, ri, rfl))
    f1 = sorted(r['selector']['idx'] for r in rows_of(2, 1))
    if f1:
        targets.append((2, f1[len(f1) // 2], 1))
    targets += [(6, 0, 0), (6, 4, 0)]
    for f5 in (4, 8):
        ri, rfl = rosetta(f5)
        targets += [(f5, 0, 0), (f5, ri, rfl)]
        f1 = sorted(r['selector']['idx'] for r in rows_of(f5, 1))
        if f1:
            targets.append((f5, f1[len(f1) // 2], 1))
    targets += [(12, 0, 0), (12, 10, 0), (12, 10, 1)]
    targets += [(0, 0, 0)]
    f11 = sorted(r['selector']['idx'] for r in rows_of(11, 1))
    if f11:
        targets.append((11, f11[0], 1))
    ri, rfl = rosetta(27)
    targets += [(27, ri, 0), (27, ri, 1)]
    special = (0, 2, 4, 6, 8, 11, 12, 27)
    for f5 in has_f5:
        if f5 in special:
            continue
        f0 = sorted(r['selector']['idx'] for r in rows_of(f5, 0))
        if f0:
            targets.append((f5, 0 if 0 in f0 else f0[0], 0))
        else:
            f1 = sorted(r['selector']['idx'] for r in rows_of(f5, 1))
            if f1:
                targets.append((f5, f1[0], 1))
    zfills = []
    for f5 in OP34_FILL_AXES:
        r0 = next((r for r in m34.get(f5, []) if r['selector'] == {
            'f5': f5, 'idx': 0, 'flag': 0, 'lo11': f5}), None)
        if r0 is not None:
            zfills.append(r0)
    return targets, zfills


def build_map34(cov, rows):
    targets, zfills = design34(rows)
    vecs = map_op_rows(0x34, targets, cov, 'map34', 'V-M34', space34)
    for r0 in zfills:
        f5 = r0['selector']['f5']
        sel = {'f5': f5, 'idx': 0, 'flag': 0}
        space = space34(f5, 0)
        rs, rt, outs = argmax_value(space, sel)
        v = value_vec('V-M34-f5%02d-i00' % f5, 'map34',
                      'op0x34 r4,r5,r6 imm=0x%03x' % f5, rs, rt, space,
                      sel, [r0['id']], live_only=True,
                      extra_notes='f5=%d axis anchor (f5_fill synthetic)' % f5)
        vecs.append(v)
        cov.claim(r0['id'], v['id'])
    return vecs


def build_c2rare(cov, rows, rows0c):
    vecs = []
    for lo11 in (0x028, 0x03c, 0x07d, 0x000):
        space = op16_space(lo11)
        sel = {}
        fixed = [Opnd('seed', (hi << 32) | lo, 2)
                 for hi, lo in ((0xffffffff, 0x80000000),
                                (0x80000000, 0xa5a5f0f0),
                                (0x89abcdef, 0x12345678),
                                (0xffffffff, 0xa5a5f0f0))]
        best = None
        for cand in fixed:
            o = [(h, fn(cand.val, 0, sel) & M32) for h, fn in space]
            sc = len(set(v for _, v in o))
            key = (-sc, cand.sort)
            if best is None or key < best[0]:
                best = (key, cand, o)
        rs = best[1]
        rid = row_idrare(0x16, lo11)
        v = value_vec('V-C2R-16i%03x' % lo11, 'c2rare',
                      'op0x16 r4,r5,zero imm=0x%03x' % lo11, rs,
                      Opnd('addi', 0, 1), space, sel, [rid],
                      extra_notes='H-16-shr second support; negative seeded '
                      'rs discriminates logical-vs-arithmetic and 64-vs-32 '
                      'width in low32 at shift %d' % (lo11 & 0x3f))
        vecs.append(v)
        cov.claim(rid, v['id'])
    for lo11 in (0x000, 0x7ff):
        space = op39_space()
        sel = {}
        rs = Opnd('seed', (0x89abcdef << 32) | 0x12345678, 2)
        op = 'op0x39 r4,r4,zero imm=0x%03x' % lo11
        rid = row_idrare(0x39, lo11)
        hiw, low = 0x89abcdef, 0x12345678
        body = ['addi r7,zero,0x%x' % f4.SEED_A_RT, 'ld.d r4,r7,0', op,
                'addi r3,zero,0x%x' % f4.CR_SLOT_RT, 'st.d r4,r3,0',
                'st.d r4,r18,0x10']
        exps = {}
        for h, fn in space:
            lo = fn(rs.val, 0, sel) & M32
            exps[h] = {'0x8c8': '0x%08x' % lo, 'echo': '0x%08x' % lo}
        vecs.append({
            'id': 'V-C2R-39i%03x' % lo11, 'group': 'c2rare', 'body': body,
            'seeds': {'0x8c6': '%08x' % low, '0x8c7': '%08x' % hiw},
            'reg_checks': [f4.ck(2, r4=(low, hiw))],
            'expectations': exps, 'census_rows': [rid],
            'notes': '0x39 second support (fuzz-4: rs.low passthrough, '
                     '1-method); in-place rd=rs=r4 seeded, halves distinct',
        })
        cov.claim(rid, vecs[-1]['id'])
    for lo11 in (0x000, 0x7ff):
        space = op3c_space(lo11)
        sel = {}
        rs = Opnd('seed', (0x5a5a5a5a << 32) | 0xa5a5f0f0, 2)
        rt = Opnd('addi', 0x3c, 1)
        rid = row_idrare(0x3c, lo11)
        v = value_vec('V-C2R-3ci%03x' % lo11, 'c2rare',
                      'op0x3c r4,r5,r6 imm=0x%03x' % lo11, rs, rt, space,
                      sel, [rid],
                      extra_notes='0x3c second support (fuzz-4: writes '
                      'zero); controlled rt=r6 instead of r31')
        vecs.append(v)
        cov.claim(rid, v['id'])
    for imm in OC_DESIGN_IMMS[1:]:
        vecs.append(build_0c_vec('V-C2R-0Cx%04x' % imm, 'c2rare', imm, cov,
                                 rows0c,
                                 '0x0c imm-axis robustness for H-0c-hi-and '
                                 '(op-level parametric model; design imms '
                                 '0x00ff/0x0000/0x01ff)'))
    rs = Opnd('seed', (0x89abcdef << 32) | 0x12345678, 2)
    rt = Opnd('addi', 0x5a, 1)
    space = op38v_space()
    sel = {}
    rid = row_id38(4)
    v = value_vec('V-C2R-38v', 'c2rare', 'op0x38 r4,r5,r6 imm=0x018', rs,
                  rt, space, sel, [rid], live_only=True,
                  extra_notes='0x38 value-form anchor: sel=rd field; sel=4 '
                  '(rd=r4) is the only dst-legal selector; FW site '
                  '@0x154e50 uses rd=r1 rt=r23 funct5=24 (imm=0x018)')
    vecs.append(v)
    cov.claim(rid, v['id'])
    return vecs


# ------------------------------------------------------------- coverage ---

F5_BOUNDARY_IDX = (0, 1, 15, 16, 31)
OP34_FILL_AXES = (1, 19, 21, 23, 25)
OC_DESIGN_IMMS = (0x00ff, 0x0000, 0x01ff)
OP38_DESIGN_SELS = (0, 4)

CURATED_SKIPS = [
    ('33-34-idx-flag-axis',
     lambda r: int(r['op'], 16) in (0x33, 0x34)
     and r['class'] == 'has-sites',
     'idx/flag-axis sampled: row outside the design33/design34 target '
     'set (boundary+rosetta+class specials); class is anchored by '
     'design rows'),
    ('33-34-zero-nonaxis',
     lambda r: int(r['op'], 16) in (0x33, 0x34)
     and r['class'] == 'zero-sites',
     'zero-site row: f5-axis anchors only, no idx cross-product '
     '(T1/T2 ruling)'),
    ('36-i6-axis',
     lambda r: int(r['op'], 16) == 0x36 and r['class'] == 'has-sites',
     'i6-axis sampled: row outside the anchor36/imm36_samples design '
     'set (f5 axis anchored + top-site imm6 samples)'),
    ('36-zero-nonaxis',
     lambda r: int(r['op'], 16) == 0x36 and r['class'] == 'zero-sites',
     'zero-site row: f5-axis anchors only, no i6 cross-product '
     '(T1/T2 ruling)'),
    ('0c-imm-axis',
     lambda r: int(r['op'], 16) == 0x0c and r['class'] == 'has-sites',
     'imm16-axis sampled: H-0c-hi-and op-level parametric mask model, '
     'design imms 0x00ff/0x0000/0x01ff only'),
    ('0c-zero-imm',
     lambda r: int(r['op'], 16) == 0x0c and r['class'] == 'zero-sites',
     'zero-site imm16 row: imm16 space has no f5 axis to anchor; '
     'op-level model sampled at has-site design imms'),
    ('38-sel-frozen',
     lambda r: int(r['op'], 16) == 0x38,
     'sel=rd field: sel 1/20 (has-sites) and 3/7/21 (zero) need frozen '
     'dst regs r1/r20/r3/r7/r21; value-form family anchored at sel=4, '
     'sel=0 covered by cmp38-self'),
]


def design_required(rows):
    """Row ids the battery MUST cover: design targets + zero-axis
    anchors + 0x0c design imms + 0x38 design sels.  Derived from the
    same design functions the builders consume (single source), so a
    builder bug (dropped target) or a census change (new class) that
    leaves a required row uncovered fails the run."""
    req = set()
    t33, z33 = design33(rows)
    for f5, idx, flag in t33:
        req.add(row_id33(0x33, f5, idx, flag))
    if z33 is not None:
        req.add(z33['id'])
    t34, z34 = design34(rows)
    for f5, idx, flag in t34:
        req.add(row_id33(0x34, f5, idx, flag))
    req.update(r['id'] for r in z34)
    for f5 in range(32):
        a = anchor36(rows, f5)
        if a is not None:
            req.add(a['id'])
    req.update(r['id'] for r in imm36_samples(rows))
    byid = {r['id']: r for r in rows}
    for imm in OC_DESIGN_IMMS:
        rid = row_id0c(imm)
        if rid not in byid or byid[rid]['class'] != 'has-sites':
            raise AsmError('design imm 0x%04x is not a has-sites census '
                           'row' % imm)
        req.add(rid)
    for sel in OP38_DESIGN_SELS:
        rid = row_id38(sel)
        if rid not in byid:
            raise AsmError('design sel %d missing from census' % sel)
        req.add(rid)
    return req


class Cov:
    MANDATORY_OPS = (0x33, 0x34, 0x36, 0x0c, 0x38)

    def __init__(self, rows):
        self.rows = rows
        self.byid = {r['id']: r for r in rows}
        self.covered = {}
        self.uncovered = {}
        self.required = design_required(rows)

    def claim(self, rid, vid):
        self.covered.setdefault(rid, []).append(vid)

    def finalize(self):
        stray = []
        for r in self.rows:
            op = int(r['op'], 16)
            rid = r['id']
            if op not in self.MANDATORY_OPS or rid in self.covered:
                continue
            if rid in self.required:
                stray.append(rid)
                continue
            for name, match, reason in CURATED_SKIPS:
                if match(r):
                    self.uncovered[rid] = '%s [%s]' % (reason, name)
                    break
            else:
                stray.append(rid)
        if stray:
            raise AsmError('coverage gate: mandatory rows neither covered '
                           'nor curated-skipped (required rows must get '
                           'vectors): %s' % stray[:10])

    def assert_required(self):
        miss = sorted(self.required - set(self.covered))
        if miss:
            raise AsmError('coverage gate: required design rows not '
                           'covered by any vector: %s' % miss[:10])

    def assert_complete(self):
        miss = []
        for r in self.rows:
            op = int(r['op'], 16)
            if op in self.MANDATORY_OPS and r['id'] not in self.covered \
                    and r['id'] not in self.uncovered:
                miss.append(r['id'])
        if miss:
            raise AsmError('coverage assert failed (unaccounted rows): %s'
                           % miss[:10])

    def report(self):
        print('=== coverage (mandatory ops 0x33/0x34/0x36/0x0c/0x38) ===')
        print('required design rows: %d, covered: %d, curated-skipped: %d'
              % (len(self.required),
                 len(self.required & set(self.covered)),
                 len(self.uncovered)))
        for op in self.MANDATORY_OPS:
            ro = [r for r in self.rows if int(r['op'], 16) == op]
            hs = [r for r in ro if r['class'] == 'has-sites']
            zs = [r for r in ro if r['class'] == 'zero-sites']
            ch = sum(1 for r in hs if r['id'] in self.covered)
            zh = sum(1 for r in zs if r['id'] in self.covered)
            print('op 0x%02x: has-sites %d/%d covered, zero-sites %d/%d '
                  'anchored, uncovered-listed %d' % (
                      op, ch, len(hs), zh, len(zs),
                      sum(1 for r in ro if r['id'] in self.uncovered)))
        rare = [r for r in self.rows if int(r['op'], 16) in (0x16, 0x39, 0x3c)]
        print('c2rare best-effort: %d/%d rows covered' % (
            sum(1 for r in rare if r['id'] in self.covered), len(rare)))


# ------------------------------------------------------------------ main ---

def main():
    sanity_models()
    data, rows, byid = load_census()
    rows0c = [r for r in rows if int(r['op'], 16) == 0x0c]
    cov = Cov(rows)
    top_imm = sorted((r for r in rows0c if r['class'] == 'has-sites'),
                     key=lambda r: (-r['sites'].get('4030', 0),
                                    -total_sites(r), r['id']))
    f4r = build_fuzz4rem(cov)
    if top_imm and top_imm[0]['selector']['imm16'] != OC_DESIGN_IMMS[0]:
        raise AsmError('census drift: top-site 0x0c imm 0x%04x != design '
                       'imm 0x%04x' % (top_imm[0]['selector']['imm16'],
                                       OC_DESIGN_IMMS[0]))
    v0c = build_0c_vec('V-F5R-0C', 'fuzz4rem', OC_DESIGN_IMMS[0], cov,
                       rows0c,
                       '0x0c new hypothesis H-0c-hi-and (T1): rd_lo = '
                       'rs_lo & ((imm16<<16)|0xffff); full refuted-space '
                       're-check in one slot')
    f4r.append(v0c)
    m36 = build_map36(cov, rows)
    m36_has = [v for v in m36 if not v.get('live_only')]
    m36_zero = [v for v in m36 if v.get('live_only')]
    m33 = build_map33(cov, rows)
    m33_has = [v for v in m33 if not v.get('live_only')]
    m33_zero = [v for v in m33 if v.get('live_only')]
    m34 = build_map34(cov, rows)
    m34_has = [v for v in m34 if not v.get('live_only')]
    m34_zero = [v for v in m34 if v.get('live_only')]
    c2 = build_c2rare(cov, rows, rows0c)
    c2_core = [v for v in c2 if not v.get('live_only')]
    c2_zero = [v for v in c2 if v.get('live_only')]
    cov.finalize()
    cov.assert_required()
    cov.assert_complete()
    for op in (0x33, 0x34):
        axes = {}
        for r in rows:
            if int(r['op'], 16) == op and r['class'] == 'has-sites':
                axes.setdefault(r['selector']['f5'], []).append(r['id'])
        bare = [f5 for f5, rids in sorted(axes.items())
                if not any(rid in cov.covered for rid in rids)]
        if bare:
            raise AsmError('op 0x%02x has-site f5 axes without any vector: '
                           '%s' % (op, bare))
    covered36 = {byid[rid]['selector']['f5']
                 for rid in cov.covered
                 if byid[rid]['op'] == '0x36'}
    if covered36 != set(range(32)):
        raise AsmError('0x36 f5 axes incomplete: missing %s'
                       % sorted(set(range(32)) - covered36))

    ordered = (f4r + m36_has + m33_has + m34_has + c2_core
               + m36_zero + m33_zero + m34_zero + c2_zero)
    ids = [v['id'] for v in ordered]
    if len(set(ids)) != len(ids):
        dups = sorted({i for i in ids if ids.count(i) > 1})
        raise AsmError('duplicate vector ids: %s' % dups)
    f4.TAIL_WORDS = list(struct.unpack('>3I', f4.assemble(
        '\n'.join(f4.TAIL), base=0, profile=f4.PROFILE)))
    recs = []
    for v in ordered:
        rec = f4.emit(v)
        rec['census_rows'] = v['census_rows']
        if v.get('live_only'):
            rec['live_only'] = True
        recs.append(rec)
    marker = [r for r in json.loads(F4JSON.read_text())
              if r['id'] == 'V-F4-MARKER'][0]
    out = [marker] + recs
    OUT.write_text(json.dumps(out, indent=1) + '\n')
    counts = {}
    for r in recs:
        counts[r['group']] = counts.get(r['group'], 0) + 1
    print('%d vectors (+1 marker), ALL DECODE-VERIFY, ALL WRITE-DISCIPLINE,'
          ' ALL COMPOSE-OK, budget<=7+tail' % len(recs))
    for g in sorted(counts):
        print('  %-9s %d' % (g, counts[g]))
    lo = sum(1 for r in recs if r.get('live_only'))
    print('live_only (zero-site synthetics): %d' % lo)
    cov.report()
    unc = sorted(cov.uncovered.items())
    print('uncovered rows accounted (reason): %d' % len(unc))
    by_reason = {}
    for rid, reason in unc:
        by_reason.setdefault((int(byid[rid]['op'], 16), reason), []).append(rid)
    for (op, reason), rids in sorted(by_reason.items()):
        print('  op 0x%02x [%d rows] %s (e.g. %s)' % (
            op, len(rids), reason, ', '.join(rids[:4])))
    print('full per-row accounting is reconstructible: census_map.json '
          'minus census_rows fields of this file')
    print('written: %s' % OUT)
    return 0


if __name__ == '__main__':
    sys.exit(main())
