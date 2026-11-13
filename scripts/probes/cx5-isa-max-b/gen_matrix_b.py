#!/usr/bin/env python3
"""isa-max cycle B matrix generator (offline, C-B.1).

Derives the B live-battery vector matrix from cycle-A artifacts (read-only
inputs): scripts/probes/cx5-isa-max/{fuzz5_live.json, select_merges_a.json,
p34_table.json, rare_verdicts.json}.  Vector discipline, model functions and
emission gates are reused from the fuzz-5 precedent (cx5-fuzz5/gen_matrix.py
on top of cx5-fuzz4/gen_vectors.py): every word decode-verified strict
(profile cx5), write-discipline, compose checks, roundtrip, <=7 free words
+ fixed tail, CR/echo channels only.

Groups (run priority, contiguous blocks): map36 -> inv33 -> [inv38v] ->
c3csep -> cmpself -> rtfed34; V-F4-MARKER first.  inv38v (>= 10 repeats of
one 0x38 sel=4 vector) is distributed through the session by an irregular
schedule (counter/time/DIV-remainder discrimination); the schedule and
per-repeat insertion positions are recorded in the notes and in
battery_meta.inv38v_schedule.

Derivation rules (documented, md5-pinned in battery_meta.pins):
- map36 axes: fuzz5_live.json rows op 0x36 live_verdict=="multi" (class =
  alive_set) + select_merges_a.json audit op 0x36 category
  "excluded.conflict" section MAIN (class = live alive_set {H-V} union the
  static eq-family {H-eq32, H-eq16} per the family-grade A ruling).
- rtfed34 axes: p34_table.json phases.B rows with
  static_verdict=="H-34-rt-fed" (the "49 rt-fed contradict" residual of the
  A-report C-A.2/C-A.6); two vectors per axis (rt=X=0xffffffff / rt=Y=0,
  fixed rs=0x1234): P-formula predicted (rt-invariant) vs the rt-dependent
  alternative (deposit moves with rt).
- inv33: 0x33 f5=0x0f corroborating dep-class probe at an idx outside the
  live-covered point; c3csep: 0x3c/000 live-multi separator design; cmpself:
  cmp38_self canon repeat + known-T predecessor variation.

Separator gate: for every axis each unordered model pair must be separated
by >= 1 vector with distinct expectations; the single whitelisted exception
is 0x3c/MAIN/lo11=000 ({H-3c-zero, H-3c-and-lo11} both predict rd=0 there —
inseparable by design; verdict transfer relies on the literal-uniformity
assumption, tested at lo11 in {0x001, 0x400} with rs=0xffffffff).

Output: matrix_b_vectors.json — a plain list of fuzz-4/fuzz-5 records
(consumable by cx5-fuzz4/run_battery.py --vectors) with additive `axis`
(join-key) fields; md5 pins and per-axis separator report live in the
`battery_meta` field of the marker record.  Deterministic: no timestamps,
byte-identical on regeneration.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'scripts' / 'probes' / 'cx5-fuzz4'))
sys.path.insert(0, str(REPO / 'scripts' / 'probes' / 'cx5-fuzz5'))

import gen_vectors as f4
import gen_matrix as f5m
from scripts.irisc import AsmError

A_DIR = REPO / 'scripts' / 'probes' / 'cx5-isa-max'
F4JSON = REPO / 'scripts' / 'probes' / 'cx5-fuzz4' / 'fuzz4_vectors.json'

INPUT_DEFAULTS = {
    'fuzz5_live': 'fuzz5_live.json',
    'select_merges_a': 'select_merges_a.json',
    'p34_table': 'p34_table.json',
    'rare_verdicts': 'rare_verdicts.json',
}

M32 = 0xffffffff

GROUP_ORDER = ['map36', 'inv33', 'inv38v', 'c3csep', 'cmpself', 'rtfed34']

CLASS5 = ('H-eq32', 'H-eq16', 'H-uge32', 'H-ugt32', 'H-V')
CLASS_F51 = ('H-ne32', 'H-lt32', 'H-lt16', 'H-ule32')
CLASS_CONFLICT = ('H-eq32', 'H-eq16', 'H-V')
CLASS_IMM_A = ('H-eq32i', 'H-uge32i', 'H-V')
CLASS_IMM_B = ('H-lt32i', 'H-ne32i')

REG_RECIPES = {
    frozenset(CLASS5): [
        ('eqw', 0x00010005, 0x0005,
         'EQ separator, width-masked pair (0x10005,0x0005): low16 equal, '
         'high16 differ -> eq16 T; eq32/V F; uge32/ugt32 T'),
        ('ord', 0x8000, 0x7fff,
         'eq-vs-uge/ugt separator (0x8000,0x7fff): uge32/ugt32 T; '
         'eq32/eq16/V F (the pair that killed uge/ugt on f5=2 in fuzz-5)'),
        ('self', 5, 5,
         'rs==rt pair (5,5): uge32 T / ugt32 F / V F / eq32,eq16 T; '
         'known-F predecessor via cmp38_eq32 r5,r3 (r3=0x2320, rs==rt '
         'makes the stock r5,r6 predecessor T and useless)'),
    ],
    frozenset(CLASS_F51): [
        ('nehi', 5, 3,
         'ne32-vs-signed pair (5,3): ne32 T; lt32/lt16/ule32 F'),
        ('s16w', 0x8000, 0,
         'width-masked signed pair (0x8000,0): s16(0x8000)=-32768<0 -> '
         'lt16 T, ne32 T; lt32 (32768<0 F), ule32 F'),
        ('sgnw', 0x80000000, 1,
         'sign-boundary pair (0x80000000,1): s32 negative -> lt32 T, '
         'lt16 T (low16 0<1), ne32 T; ule32 F'),
    ],
    frozenset(CLASS_CONFLICT): [
        ('eqw', 0x00010005, 0x0005,
         'EQ separator, width-masked pair (0x10005,0x0005): eq16 T; '
         'eq32/V F'),
        ('self', 5, 5,
         'rs==rt pair (5,5): eq32/eq16 T / V F (live said H-V, static '
         'eq-family -> conflict axis re-probe)'),
    ],
}

IMM_RECIPES = {
    frozenset(CLASS_IMM_A): [
        ('i0', 'i6', 'rs==i6: eq32i T, uge32i T, V F (V separation)'),
        ('i1', 'i6+1', 'rs==i6+1: eq32i F, uge32i T (eq-vs-uge split)'),
    ],
    frozenset(CLASS_IMM_B): [
        ('i1', 'i6+1', 'rs==i6+1: ne32i T, lt32i F (ne-vs-lt split)'),
    ],
}

INV33_F5 = 15
RTFED_RS = 0x1234
RTFED_X = 0xffffffff
RTFED_Y = 0x00000000

INV38V_TOTAL = 12
INV38V_AFTER_GROUPS = ['map36', 'inv33', 'c3csep', 'cmpself']
INV38V_BASE_OFFSETS = [5, 13, 27, 41, 60, 74, 89]
INV38V_NOTE_N = 98  # rtfed vector count the base schedule was drawn for

SEP_WHITELIST = {
    '0x3c|MAIN|lo11=000':
        'by-design: {H-3c-zero, H-3c-and-lo11} both predict rd=0 at '
        'lo11=000 (A-report C-A.6); the verdict transfer to lo11=000 '
        'relies on the literal-uniformity assumption, separated at '
        'lo11 in {0x001,0x400} with rs=0xffffffff (adjudication T3 '
        'must record the assumption; uniformity violation -> residual)',
}

RT_FED_RULE = ("p34_table.json phases.B rows with "
               "static_verdict=='H-34-rt-fed' (the A-report C-A.2/C-A.6 "
               "'49 rt-fed contradict' residual: FW rt-live contexts vs "
               "the constant P-deposit)")

CONFLICT_RULE = ("select_merges_a.json audit op 0x36 category "
                 "excluded.conflict section MAIN -> axes f5=2/f5=0xa; "
                 "class = live alive_set {H-V} (live unique on the axis) "
                 "union static eq-family {H-eq32,H-eq16} (H-36-eq-usage "
                 "family-grade ruling A)")


class SepError(Exception):
    pass


# --------------------------------------------------------------- inputs ---

def load_inputs(paths):
    raw = {}
    for key, p in paths.items():
        raw[key] = json.loads(Path(p).read_text())
    return {'paths': {k: Path(v) for k, v in paths.items()}, 'raw': raw}


def input_md5s(inputs):
    out = {}
    for key, p in inputs['paths'].items():
        out[INPUT_DEFAULTS[key]] = hashlib.md5(p.read_bytes()).hexdigest()
    return out


# ------------------------------------------------------------- axis key ---

def axis_key(op, section, selector):
    parts = []
    for k in sorted(selector):
        v = selector[k]
        if k == 'lo11':
            parts.append('%s=%03x' % (k, v))
        elif k == 'flag':
            parts.append('%s=%d' % (k, v))
        else:
            parts.append('%s=%02x' % (k, v))
    return '0x%02x|%s|%s' % (int(op, 16) if isinstance(op, str) else op,
                             section, ','.join(parts))


def row_id36(selector):
    return 'op36_f5=%02x_i6=%02x' % (selector['f5'], selector['i6'])


# ------------------------------------------------------------ derivation ---

def derive_axes_36(inputs):
    rows = inputs['raw']['fuzz5_live']['rows']
    axes = []
    for rid, r in sorted(rows.items()):
        if r.get('op') != '0x36' or r.get('live_verdict') != 'multi':
            continue
        sel = r['selector']
        if not {'f5', 'i6', 'lo11'} <= set(sel):
            raise AsmError('row %s: selector without f5/i6/lo11' % rid)
        axes.append({
            'axis': axis_key('0x36', r['section'], sel),
            'section': r['section'],
            'selector': sel,
            'models': sorted(r['alive_set']),
            'row_id': rid,
            'kind': 'reg' if sel['i6'] == 0 else 'imm6',
        })
    audit = inputs['raw']['select_merges_a']['audit']
    for a in sorted(audit, key=lambda x: axis_key(
            x['key']['op'], x['key']['section'], x['key']['selector'])):
        if a.get('category') != 'excluded.conflict':
            continue
        key = a['key']
        if key['op'] != '0x36' or key['section'] != 'MAIN':
            continue
        sel = key['selector']
        rid = row_id36(sel)
        row = rows.get(rid)
        if row is None or row.get('live_verdict') != 'unique' \
                or 'H-V' not in row.get('alive_set', []):
            raise AsmError('conflict axis %s: live premise (unique H-V on '
                           'the row) does not hold' % rid)
        models = sorted(set(row['alive_set']) | {'H-eq32', 'H-eq16'})
        axes.append({
            'axis': axis_key('0x36', 'MAIN', sel),
            'section': 'MAIN',
            'selector': sel,
            'models': models,
            'row_id': rid,
            'kind': 'conflict',
        })
    seen = set()
    for a in axes:
        if a['axis'] in seen:
            raise AsmError('duplicate axis %s' % a['axis'])
        seen.add(a['axis'])
    return axes


def derive_rt_fed(inputs):
    rows = inputs['raw']['p34_table']['phases']['B']['rows']
    out = []
    for r in rows:
        if r.get('static_verdict') != 'H-34-rt-fed':
            continue
        key = r['key']
        if key['op'] != '0x34':
            raise AsmError('rt-fed row with op %s' % key['op'])
        sel = key['selector']
        mask, deposit = p_formula_recompute(sel)
        if ('0x%08x' % mask != r['predicted']['mask']
                or '0x%08x' % deposit != r['predicted']['deposit']):
            raise AsmError('rt-fed row %s: predicted does not match the '
                           'P-formula recompute' % axis_key(
                               '0x34', key['section'], sel))
        out.append({
            'axis': axis_key('0x34', key['section'], sel),
            'key': key,
            'predicted': r['predicted'],
        })
    return out


def p_formula_recompute(sel):
    f5, idx, flag = sel['f5'], sel['idx'], sel['flag']
    mask32 = M32 if f5 == 0 else (1 << f5) - 1
    return ((mask32 << idx) & M32,
            (((0xc | flag) & mask32) << idx) & M32)


def derive_inv33(inputs):
    rows = inputs['raw']['fuzz5_live']['rows']
    covered = sorted(r['selector']['idx'] for r in rows.values()
                     if r.get('op') == '0x33'
                     and r['selector'].get('f5') == INV33_F5
                     and r.get('live_verdict') == 'unique')
    allrows = sorted(r['selector']['idx'] for r in rows.values()
                     if r.get('op') == '0x33'
                     and r['selector'].get('f5') == INV33_F5
                     and r['selector'].get('flag', 0) == 0)
    for idx in allrows:
        if idx not in covered:
            return {'f5': INV33_F5, 'idx': idx, 'covered_idx': covered}
    raise AsmError('inv33: no 0x33 f5=0x0f idx outside the covered point')


def derive_c3csep_premise(inputs):
    rows = inputs['raw']['rare_verdicts']['phases']['B']['rows']
    for r in rows:
        key = r['key']
        if (key['op'] == '0x3c' and key['section'] == 'MAIN'
                and key['selector'].get('lo11') == 0
                and (r.get('live_join') or {}).get('live_verdict') == 'multi'):
            return True
    raise AsmError('c3csep premise: rare_verdicts.json has no live-multi '
                   '0x3c MAIN lo11=000 row')


# ------------------------------------------------------------- builders ---

def _init_tail():
    if not f4.TAIL_WORDS:
        f4.TAIL_WORDS = list(struct.unpack(
            '>3I', f4.assemble('\n'.join(f4.TAIL), base=0,
                               profile=f4.PROFILE)))


def cc0a_eq_vec(vid, group, f5, val, space, extra_notes):
    a = val
    body = ['addi r3,zero,0x%x' % f4.CR_SLOT_RT,
            'addi r5,zero,0x%x' % a,
            'addi r6,zero,0x%x' % a,
            'cmp38_eq32 r5,r3',
            'op0x36 zero,r5,r6 imm=0x%03x' % f5,
            'b.t.0xa zero,tail', 'st.d r6,r3,0']
    exps = {}
    for h, fn in space:
        exps[h] = {'0x8c8': f4.SENTINEL if fn(a, a)
                   else '0x%016x' % a}
    return {'id': vid, 'group': group, 'body': body,
            'reg_checks': [f4.ck(3, r5=(a, 0), r6=(a, 0))],
            'expectations': exps,
            'controls': {'cr_sentinel': f4.SENTINEL},
            'notes': extra_notes}


def build_map36(inputs):
    axes = derive_axes_36(inputs)
    vecs = []
    for a in axes:
        ax = a['axis']
        f5 = a['selector']['f5']
        i6 = a['selector']['i6']
        base_id = 'V-B36-f5%02x-i6%02x' % (f5, i6)
        klass = frozenset(a['models'])
        if a['kind'] in ('reg', 'conflict'):
            if klass not in REG_RECIPES:
                raise AsmError('axis %s: no reg recipe for class %s'
                               % (ax, sorted(a['models'])))
            space = [(h, f5m.PRED36[h]) for h in sorted(a['models'])]
            for tag, pa, pb, note in REG_RECIPES[klass]:
                vid = '%s-%s' % (base_id, tag)
                if pa == pb:
                    v = cc0a_eq_vec(vid, 'map36', f5, pa, space, note)
                else:
                    v = f5m.cc0a_cr_vec(vid, 'map36', f5, (pa, pb), space,
                                        [], extra_notes=note)
                v['_axis'] = ax
                v['notes'] += (' | axis %s | class %s' %
                               (ax, ','.join(sorted(a['models']))))
                vecs.append(v)
        else:
            if klass not in IMM_RECIPES:
                raise AsmError('axis %s: no imm6 recipe for class %s'
                               % (ax, sorted(a['models'])))
            space = [(h, fn) for h, fn in f5m.imm6_space(i6)
                     if h in a['models']]
            for tag, which, note in IMM_RECIPES[klass]:
                rs_val = i6 if which == 'i6' else i6 + 1
                vid = '%s-%s' % (base_id, tag)
                v = f5m.imm6_vec(vid, 'map36', f5, i6, rs_val, space, [],
                                 extra_notes=note)
                v['_axis'] = ax
                v['notes'] += (' | axis %s | class %s' %
                               (ax, ','.join(sorted(a['models']))))
                vecs.append(v)
    return vecs


def build_inv33(inputs):
    info = derive_inv33(inputs)
    f5, idx = info['f5'], info['idx']
    lo11 = (idx << 5) | f5
    space = [
        ('H-depR', lambda rs, rt, s: f5m.dep_r(rs, rt, f5, s['idx'])),
        ('H-depM', lambda rs, rt, s: f5m.dep_m(rs, rt, f5, s['idx'])),
    ]
    rs = f5m.Opnd('const32', 0x00100000, 2)
    rt = f5m.Opnd('addi', 5, 1)
    note = ('invariant B: corroborating 0x33 f5=0x0f dep-class probe at '
            'idx=0x%02x (outside the live-unique depR point idx=%s); '
            'rs=0x00100000 has field bits (mask 0x%03x) not covered by '
            'rt=5 -> depR replaces the field, depM ORs into it'
            % (idx, ','.join('0x%02x' % i for i in info['covered_idx']),
               (((1 << f5) - 1) << idx) & M32))
    v = f5m.value_vec('V-B33-f5%02x-i%02x' % (f5, idx), 'inv33',
                      'op0x33 r4,r5,r6 imm=0x%03x' % lo11, rs, rt, space,
                      {'idx': idx}, [], extra_notes=note)
    v['_axis'] = axis_key('0x33', 'MAIN', {'f5': f5, 'flag': 0, 'idx': idx,
                                           'lo11': lo11})
    v['notes'] += ' | axis %s' % v['_axis']
    return [v]


def build_c3csep(inputs):
    if not derive_c3csep_premise(inputs):
        raise AsmError('c3csep premise gate failed')
    vecs = []
    design = [
        (0x000, (0x5a5a5a5a << 32) | 0xa5a5f0f0, 'i000',
         '0x3c/lo11=000 live-multi {zero,and-lo11}: both predict rd=0 '
         '(inseparable by design at this literal; verdict transfer relies '
         'on literal-uniformity — separation at lo11 0x001/0x400 with '
         'rs=0xffffffff); rs seeded nonzero, halves distinct'),
        (0x001, 0x00000000ffffffff, 'i001',
         'intermediate separation point: H-3c-zero -> 0, H-3c-and-lo11 -> '
         'rs&lo11 = 0x1'),
        (0x400, 0x00000000ffffffff, 'i400',
         'intermediate separation point: H-3c-zero -> 0, H-3c-and-lo11 -> '
         'rs&lo11 = 0x400'),
    ]
    for lo11, rs_val, tag, note in design:
        space = [(h, fn) for h, fn in f5m.op3c_space(lo11)
                 if h in ('H-3c-zero', 'H-3c-and-lo11')]
        rs = f5m.Opnd('seed', rs_val, 2)
        rt = f5m.Opnd('addi', 0x3c, 1)
        v = f5m.value_vec('V-B3C-%s' % tag, 'c3csep',
                          'op0x3c r4,r5,r6 imm=0x%03x' % lo11, rs, rt,
                          space, {}, [], extra_notes=note)
        v['_axis'] = axis_key('0x3c', 'MAIN', {'lo11': lo11})
        v['notes'] += ' | axis %s' % v['_axis']
        vecs.append(v)
    return vecs


def build_cmpself(inputs):
    canon = inputs['raw']['fuzz5_live']['cmp38_self']
    if canon.get('unique_model') != 'H-38self-false':
        raise AsmError('cmp38_self canon drift: unique_model=%r'
                       % canon.get('unique_model'))
    vecs = []
    specs = [
        ('V-B38S-REP', 0x1234, 5,
         'cmp38-self -> F repeat (double-live canon V-op38-self + '
         'V-F5R-38SELF): separating operand 0x1234, known-T predecessor '
         'cmp38 r6,r7=5,5 (independent pair); self->F writes echo, '
         'keep-T leaves stock'),
        ('V-B38S-VAR', 0x4321, 0x7fff,
         'known-T predecessor variation: cmp38 r6,r7=0x7fff,0x7fff, '
         'separating operand 0x4321; same expectations from the '
         'H-38self-false canon'),
    ]
    for vid, opnd, pre, note in specs:
        body = ['addi r5,zero,0x%x' % opnd,
                'addi r6,zero,0x%x' % pre,
                'addi r7,zero,0x%x' % pre,
                'cmp38_eq32 r6,r7',
                'cmp38_eq32 r5,r5',
                'b.t.0xa zero,tail', 'st.d r5,r18,0x10']
        v = {'id': vid, 'group': 'cmpself', 'body': body,
             'reg_checks': [f4.ck(4, r5=(opnd, 0))],
             'expectations': {
                 'H-38self-false': {'echo': '0x%016x' % opnd},
                 'H-38self-keepT': {'echo': 'stock'}},
             'controls': {'echo_stale': 'stock'},
             'notes': note}
        v['_axis'] = axis_key('0x38', 'MAIN', {'sel': 0})
        v['notes'] += ' | axis %s' % v['_axis']
        vecs.append(v)
    return vecs


def build_rtfed(inputs):
    rows = derive_rt_fed(inputs)
    vecs = []
    for row in rows:
        sel = row['key']['selector']
        f5, idx, flag = sel['f5'], sel['idx'], sel['flag']
        lo11 = (flag << 10) | (idx << 5) | f5
        mask = int(row['predicted']['mask'], 16)
        deposit = int(row['predicted']['deposit'], 16)
        wmask = M32 if f5 == 0 else (1 << f5) - 1
        rd_p = ((RTFED_RS & ~mask) & M32) | deposit
        for which, rt in (('x', RTFED_X), ('y', RTFED_Y)):
            rd_rt = (((RTFED_RS & ~mask) & M32)
                     | ((rt & wmask) << idx)) & M32
            # lo11=0x022 (bclr.1 selector) renders lossy since the
            # canon-sync: the bit-exact escape is the raw dword literal
            # (decode-verify exempt by design, op_word pins the golden;
            # fuzz-4 V-34-1 / fuzz-5 map_op_rows precedent)
            if lo11 == 0x022:
                op_word = (0x34 << 26) | (5 << 21) | (4 << 16) | (6 << 11) | lo11
                op_line = 'dword 0x%08x' % op_word
                op_note = ' | dword escape: lo11=0x022 bclr.1 lossy render'
            else:
                op_word = None
                op_line = 'op0x34 r4,r5,r6 imm=0x%03x' % lo11
                op_note = ''
            note = ('rt-fed residual row %s: P-formula predicted '
                    '(rt-invariant) vs rt-dependent alternative (deposit '
                    'moves with rt); fixed rs=0x%04x, rt=%s%s'
                    % (row['axis'], RTFED_RS,
                       'X=0xffffffff' if which == 'x' else 'Y=0', op_note))
            if which == 'x':
                body = ['set2 r6,zero,0xffff', 'set3 r6,r6,0xffff',
                        'addi r5,zero,0x%x' % RTFED_RS, op_line,
                        'addi r3,zero,0x%x' % f4.CR_SLOT_RT,
                        'st.d r4,r3,0', 'st.d r4,r18,0x10']
                checks = [f4.ck(3, r5=(RTFED_RS, 0),
                                r6=(RTFED_X & M32, None))]
                op_idx = 3
            else:
                body = ['addi r6,zero,0x0',
                        'addi r5,zero,0x%x' % RTFED_RS, op_line,
                        'addi r3,zero,0x%x' % f4.CR_SLOT_RT,
                        'st.d r4,r3,0', 'st.d r4,r18,0x10']
                checks = [f4.ck(2, r5=(RTFED_RS, 0), r6=(0, 0))]
                op_idx = 2
            v = {'id': 'V-B34-%s-%s' % (_sec_tag(row['key']['section']),
                                        _sel_tag(sel, which)),
                 'group': 'rtfed34', 'body': body,
                 'reg_checks': checks,
                 'expectations': {
                     'H-34-p-formula': {'0x8c8': '0x%08x' % rd_p,
                                        'echo': '0x%08x' % rd_p},
                     'H-34-rt-fed': {'0x8c8': '0x%08x' % rd_rt,
                                     'echo': '0x%08x' % rd_rt}},
                 'notes': note}
            if op_word is not None:
                v['op_word'] = (op_idx, op_word)
            v['_axis'] = row['axis']
            v['notes'] += ' | axis %s' % row['axis']
            vecs.append(v)
    return vecs


def _sec_tag(section):
    return {'MAIN': 'M', 'IRON_PREP': 'IP', 'PCI': 'PC'}[section]


def _sel_tag(sel, which):
    return 'f5%02x-i%02x-f%d-%s' % (sel['f5'], sel['idx'], sel['flag'],
                                     which)


def build_inv38v():
    rs = f5m.Opnd('seed', (0x89abcdef << 32) | 0x12345678, 2)
    rt = f5m.Opnd('addi', 0x5a, 1)
    space = f5m.op38v_space()
    base_note = ('inv38v sel=4 value-form repeat (nondeterminism probe: '
                 'bits [23:16] volatile 03/06/01, A-report C-A.6); one '
                 'vector repeated on an irregular schedule (counter/time/'
                 'DIV-remainder discrimination); expectations from the '
                 'fuzz-5 op38v space')
    vecs = []
    for n in range(1, INV38V_TOTAL + 1):
        v = f5m.value_vec('V-B38v-R%02d' % n, 'inv38v',
                          'op0x38 r4,r5,r6 imm=0x018', rs, rt, space, {},
                          [], extra_notes=base_note)
        v['_axis'] = axis_key('0x38', 'MAIN', {'sel': 4})
        vecs.append(v)
    return vecs


# -------------------------------------------------------------- schedule ---

def inv38v_offsets(n_rtfed):
    inside = min(len(INV38V_BASE_OFFSETS),
                 INV38V_TOTAL - len(INV38V_AFTER_GROUPS) - 1, n_rtfed)
    offs = []
    for k in range(inside):
        ideal = INV38V_BASE_OFFSETS[k] * n_rtfed // INV38V_NOTE_N
        p = max(ideal, k + 1)
        p = min(p, n_rtfed - (inside - 1 - k))
        if offs:
            p = max(p, offs[-1] + 1)
        offs.append(p)
    return offs


def assemble_order(blocks, inv38v_vecs, rtfed_vecs):
    """File order = run order: contiguous group blocks in GROUP_ORDER
    priority with the distributed inv38v repeats interleaved.  Each repeat
    records its insertion position in the notes (and the full schedule is
    returned for battery_meta)."""
    order = []
    schedule = []
    ri = 0
    pending = [('map36', blocks['map36']), ('inv33', blocks['inv33']),
               ('c3csep', blocks['c3csep']), ('cmpself', blocks['cmpself'])]
    for gname, vecs in pending:
        order.extend(vecs)
        if gname in INV38V_AFTER_GROUPS and ri < len(inv38v_vecs):
            v = inv38v_vecs[ri]
            v['notes'] += ' | repeat %d/%d; insert position: after group ' \
                '%s' % (ri + 1, len(inv38v_vecs), gname)
            order.append(v)
            schedule.append({'repeat': ri + 1, 'after': gname})
            ri += 1
    offs = inv38v_offsets(len(rtfed_vecs))
    for i, v in enumerate(rtfed_vecs):
        order.append(v)
        if len(offs) and (i + 1) == offs[0]:
            rep = inv38v_vecs[ri]
            rep['notes'] += ' | repeat %d/%d; insert position: inside ' \
                'group rtfed34 after vector %d of %d' \
                % (ri + 1, len(inv38v_vecs), i + 1, len(rtfed_vecs))
            order.append(rep)
            schedule.append({'repeat': ri + 1, 'inside': 'rtfed34',
                             'after_vector': i + 1})
            ri += 1
            offs = offs[1:]
    while ri < len(inv38v_vecs):
        v = inv38v_vecs[ri]
        v['notes'] += ' | repeat %d/%d; insert position: after group ' \
            'rtfed34 (session end)' % (ri + 1, len(inv38v_vecs))
        order.append(v)
        schedule.append({'repeat': ri + 1, 'after': 'rtfed34'})
        ri += 1
    if ri != len(inv38v_vecs):
        raise AsmError('inv38v placement: %d of %d repeats placed'
                       % (ri, len(inv38v_vecs)))
    return order, schedule


# ----------------------------------------------------------------- gates ---

def _norm_exp(exp):
    v = exp.get('0x8c8', exp.get('echo'))
    if v is None:
        raise SepError('expectation without 0x8c8/echo channel: %r' % exp)
    s = str(v).strip().lower()
    if s == 'stock':
        return 'stock'
    return int(s, 16) & M32


def separator_gate(records, whitelist):
    axes = {}
    for r in records:
        ax = r.get('axis')
        if not ax:
            continue
        axes.setdefault(ax, []).append(r)
    report = {}
    for ax in sorted(axes):
        models = []
        for r in axes[ax]:
            for m in r.get('expectations', {}):
                if m not in models:
                    models.append(m)
        models.sort()
        inseparable = []
        separated = 0
        total = 0
        for i in range(len(models)):
            for j in range(i + 1, len(models)):
                m1, m2 = models[i], models[j]
                total += 1
                split = any(
                    _norm_exp(r['expectations'][m1])
                    != _norm_exp(r['expectations'][m2])
                    for r in axes[ax]
                    if m1 in r['expectations'] and m2 in r['expectations'])
                if split:
                    separated += 1
                elif ax in whitelist:
                    inseparable.append({
                        'pair': [m1, m2],
                        'status': 'inseparable_by_design',
                        'reason': whitelist[ax]})
                else:
                    raise SepError(
                        'axis %s: models %s/%s not separated by any vector'
                        % (ax, m1, m2))
        report[ax] = {'models': models, 'pairs_total': total,
                      'pairs_separated': separated,
                      'inseparable': inseparable}
    return report


def coverage_gate(records):
    ids = [r['id'] for r in records]
    if len(set(ids)) != len(ids):
        dups = sorted({i for i in ids if ids.count(i) > 1})
        raise AsmError('duplicate vector ids: %s' % dups)
    if records[0]['id'] != 'V-F4-MARKER':
        raise AsmError('V-F4-MARKER must be the first record')
    known = set(GROUP_ORDER) | {'marker'}
    for r in records:
        if r['group'] not in known:
            raise AsmError('unknown group %r' % r['group'])
        if r['id'] != 'V-F4-MARKER' and 'axis' not in r:
            raise AsmError('record %s without axis' % r['id'])
    groups = [r['group'] for r in records[1:] if r['group'] != 'inv38v']
    blocks = [g for i, g in enumerate(groups) if i == 0 or groups[i - 1] != g]
    if blocks != [g for g in GROUP_ORDER if g != 'inv38v']:
        raise AsmError('group blocks %s violate the priority order %s'
                       % (blocks, GROUP_ORDER))
    inv = [r for r in records if r['group'] == 'inv38v']
    if len(inv) < 10:
        raise AsmError('inv38v: %d repeats, want >= 10' % len(inv))
    if len({tuple(r['words']) for r in inv}) != 1:
        raise AsmError('inv38v repeats are not one identical vector')
    for r in inv:
        if 'insert' not in r['notes'] or 'repeat' not in r['notes']:
            raise AsmError('inv38v %s: notes lack insertion position'
                           % r['id'])
    c3_axes = {r['axis'] for r in records if r['group'] == 'c3csep'}
    for want in ('0x3c|MAIN|lo11=000', '0x3c|MAIN|lo11=001',
                 '0x3c|MAIN|lo11=400'):
        if want not in c3_axes:
            raise AsmError('c3csep incomplete: missing %s' % want)
    if len([r for r in records if r['group'] == 'cmpself']) != 2:
        raise AsmError('cmpself must be exactly 2 vectors')
    if not any(r['group'] == 'inv33' for r in records):
        raise AsmError('inv33 missing')
    rtf = {}
    for r in records:
        if r['group'] == 'rtfed34':
            rtf.setdefault(r['axis'], []).append(r)
    for ax, vecs in rtf.items():
        tags = sorted(v['id'].rsplit('-', 1)[-1] for v in vecs)
        if len(vecs) != 2 or tags != ['x', 'y']:
            raise AsmError('rtfed34 axis %s: want exactly rt=X/rt=Y pair, '
                           'got %s' % (ax, [v['id'] for v in vecs]))
    m36 = {}
    for r in records:
        if r['group'] == 'map36':
            m36.setdefault(r['axis'], 0)
            m36[r['axis']] += 1
    if not m36 or any(n == 0 for n in m36.values()):
        raise AsmError('map36 axis without vectors')
    return {'map36_axes': len(m36), 'rtfed34_axes': len(rtf),
            'inv38v_repeats': len(inv)}


# ------------------------------------------------------------------ main ---

def build_all(paths):
    inputs = load_inputs(paths)
    _init_tail()
    blocks = {
        'map36': build_map36(inputs),
        'inv33': build_inv33(inputs),
        'c3csep': build_c3csep(inputs),
        'cmpself': build_cmpself(inputs),
    }
    rtfed = build_rtfed(inputs)
    inv38v = build_inv38v()
    ordered, schedule = assemble_order(blocks, inv38v, rtfed)

    records = []
    for v in ordered:
        rec = f4.emit(v)
        rec['axis'] = v['_axis']
        records.append(rec)

    marker = [r for r in json.loads(F4JSON.read_text())
              if r['id'] == 'V-F4-MARKER'][0]
    full = [marker] + records
    sep_report = separator_gate(full, SEP_WHITELIST)
    cov = coverage_gate(full)
    counts = {}
    for r in full:
        counts[r['group']] = counts.get(r['group'], 0) + 1
    marker['battery_meta'] = {
        'cycle': 'isa-max-b task-1 (C-B.1)',
        'generated_by': 'scripts/probes/cx5-isa-max-b/gen_matrix_b.py',
        'pins': input_md5s(inputs),
        'pins_note': 'md5 of the cycle-A artifacts consumed (read-only)',
        'rt_fed_rule': RT_FED_RULE,
        'conflict_axes_rule': CONFLICT_RULE,
        'group_priority': GROUP_ORDER,
        'group_counts': counts,
        'coverage': cov,
        'inv38v_schedule': schedule,
        'inv38v_note': 'irregular step by design (counter/time/DIV '
                       'discrimination); repeats of one sel=4 vector',
        'separator_gate': sep_report,
        'separator_whitelist': SEP_WHITELIST,
    }
    return full


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='isa-max cycle B matrix generator (see module docstring)')
    ap.add_argument('--out', default=str(
        Path(__file__).resolve().parent / 'matrix_b_vectors.json'))
    for key, name in INPUT_DEFAULTS.items():
        ap.add_argument('--' + key, default=str(A_DIR / name))
    args = ap.parse_args(argv)
    paths = {k: getattr(args, k) for k in INPUT_DEFAULTS}
    records = build_all(paths)
    out = Path(args.out)
    out.write_text(json.dumps(records, indent=1) + '\n')
    text = out.read_text()
    md5 = hashlib.md5(text.encode()).hexdigest()
    counts = {}
    for r in records:
        counts[r['group']] = counts.get(r['group'], 0) + 1
    print('%d vectors (+marker included), ALL DECODE-VERIFY STRICT, ALL '
          'WRITE-DISCIPLINE, ALL COMPOSE-OK, budget<=7+tail'
          % (len(records) - 1))
    for g in GROUP_ORDER + ['marker']:
        if g in counts:
            print('  %-9s %d' % (g, counts[g]))
    meta = records[0]['battery_meta']
    print('axes: map36=%d rtfed34=%d separator-whitelisted=%d'
          % (meta['coverage']['map36_axes'],
             meta['coverage']['rtfed34_axes'],
             sum(1 for e in meta['separator_gate'].values() if e['inseparable'])))
    print('inv38v repeats: %d (schedule in battery_meta)' % counts['inv38v'])
    print('md5(%s): %s' % (out.name, md5))
    print('written: %s' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
