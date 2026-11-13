#!/usr/bin/env python3
"""isa-max A task-5 (C-A.2): offline model of the op 0x34 rogue P-table
from the captured fuzz-5 data, dual validation (live + static).

Model (fit on the captured observed set, 52/52 observations):

    rd = (rs & ~((mask32(f5) << idx) & 0xffffffff))
         | ((((0xc | flag) & mask32(f5)) << idx) & 0xffffffff)
    mask32(0) = 0xffffffff (width 32), mask32(f5>0) = 2^f5 - 1

Two extensions past the fuzz-5 "simple formula" resolve the disc points
that stayed outside it:
- the deposit base is masked to the field width: P0 = (0xc|flag) &
  mask32(f5) -> f5=3 deposits 0x4 (the "(0,0)/f5=3 -> P=0x4" fact),
  f5=2 deposits 0/1 (the (2,.,1) bset-dead points);
- f5=0 is a full-width field (x86 (32-f5)&31 shift-wrap semantics),
  verified on the single live f5=0 point (rs=3 -> 0xc).
OPDEP-B (8,10,1)->0x37ff and F0B (0xb,0,0)->0x100c fit as-is; rogue
values move with rs because rs survives outside the mask (OPDEP-A).

Two phases (anti-circular, T4 pattern):
- Phase A (never reads fuzz5_live.json): row universe = 0x34 has-sites
  rows of BOTH maps (census_corpus all sections + census_map MAIN);
  per-row raw def-use over the strict corpus sites (rt provenance as
  the const-deposit contradiction signal, rs provenance, rd next-use)
  -> static_verdict ('H-34-rt-fed' = rt-fed cluster >= RT_FED_MIN,
  else 'H-34-field-consistent'; no strict sites -> null, reason);
  `predicted` serializes the model P-table entry (mask + deposit);
- Phase B (separate run): join fuzz5_live.json op34 rows -- live_join
  compares the model prediction with EVERY observation[] value of the
  row (not just the first); disc-extras (keys outside the census
  universe) are synthesized as explicitly marked rows; meta carries
  model_form + dual validation + dep_merge_unblocked_rows.

Residual rule: a contradiction in ANY leg (live mismatch or static
rt-fed) -> the row model_form is 'residual' and the row is out of
dep_merge_unblocked_rows.

rt_live adjudication (owner ruling 2026-11-01, final-review round 2):
a merge-candidate row carrying a raw rt_live signal below RT_FED_MIN
is not silently thresholded -- every rt-live site is adjudicated
offline against its decoded def-use window (RT_LIVE_ADJUDICATION);
noise-with-reason keeps the row mergeable, real/unadjudicated fails
closed to residual.  Rows at/above RT_FED_MIN are untouched.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

OUT = HERE / 'p34_table.json'

# committed inputs are md5-pinned: refuse silent drift
PIN_SITES = '18918f8f07cc7716b783df7a1934ee7b'
PIN_CENSUS = '78b1f6964f508bc654c39ee6add28d1d'
PIN_CENSUS_MAP = 'c6b8dbfaa4ca42f77a5d79e705cc1a75'
PIN_LIVE = '42358ef7acab628637cd0c7c2925ad04'

# def-use parameters (windows follow h36_grind precedents)
PROV_BACK = 24             # words scanned back for operand provenance
USE_FWD = 12               # words scanned forward for the rd next-use
RT_FED_MIN = 3             # rt-live sites that mark a row rt-fed
SITE_SAMPLES = 3           # basis site samples per row

# Fuzz-5 owner ruling «ось f5=2 idx=5 не трогать»: the axis stays OPEN
# (census_map OPEN-34-f5=2-idx=5; select_merges.py OPEN_RECS keeps it out
# of merges).  The fuzz-4 observation that made it OPEN -- V-34-2
# (rs=0xff, rt=1) -> 0x000400ff -- is NOT reproduced by the P-formula
# (predict(2,5,0,0xff) = 0x9f: neither deposit 0/1 nor bclr bits explain
# 0x000400ff) and is not part of fuzz5_live.json; the only fuzz-5 battery
# point on the key (rs=0x21 -> 0x01) is non-discriminating (deposit and
# bclr readings coincide).  Ruling-excluded rows keep their model fields
# but never enter dep_merge_unblocked_rows.
RULING_EXCLUDED = {
    '{"op": "0x34", "section": "MAIN", "selector": '
    '{"f5": 2, "flag": 0, "idx": 5, "lo11": 162}}':
    'fuzz-5 ruling «ось f5=2 idx=5 не трогать»: axis stays OPEN '
    '(census_map OPEN-34-f5=2-idx=5, select_merges.py OPEN_RECS). '
    'Fuzz-4 V-34-2 (rs=0xff, rt=1) observed 0x000400ff -- outside the '
    'P-formula (predict -> 0x9f) and outside fuzz5_live.json; the '
    'single fuzz-5 battery point (rs=0x21 -> 0x01) is '
    'non-discriminating (deposit and bclr readings coincide)',
}

# 2026-11-01 owner ruling (final-review round 2): the raw rt_live
# counter-signal below RT_FED_MIN on a MERGE-CANDIDATE row (live match,
# no conflict) is not silently suppressed by the threshold -- every
# rt-live site of the row is adjudicated offline against its decoded
# def-use window (producer of rt, the 0x34 site, consumers of rd,
# forward liveness of rt).  'noise' = the rt liveness has a concrete
# non-rt explanation (another consumer reads rt; rt itself dead at
# the site -- def consumed before it, no post-site readers; rd
# dead/overwritten; cross-function-boundary or self-aliasing
# artifact of the linear window) -- the row stays mergeable.  'real' = rt's value would have
# to flow into rd's consumers -- contradiction of the const-deposit
# model, the row fails closed to residual.  A merge-candidate row with
# rt_live > 0 and NO complete adjudication on file also fails closed
# ('unadjudicated').  Rows already at/above RT_FED_MIN keep their
# H-34-rt-fed residual status untouched (not un-residualed).
RT_LIVE_ADJUDICATION = {
    '{"op": "0x34", "section": "MAIN", "selector": '
    '{"f5": 27, "flag": 1, "idx": 5, "lo11": 1211}}': {
        'row_verdict': 'noise',
        'sites': [{
            'fw': 'LX1900', 'section': 'MAIN', 'dc_offset': '0x153c04',
            'word': '0xd14a1cbb', 'verdict': 'noise',
            'reason': 'rt=r3 def @-16 (fc63480a and r3,r3,r9, after '
                      'shr r3,r2,0x3 @-17) is the copy-loop dword '
                      'count: its sole consumer is the st.d base @-11 '
                      '(6c60f002 st.d r30,r3,0), BEFORE the site; r3 '
                      'has no post-site consumers until the re-def '
                      '@+67 (64230006 ld.d r3,r1,0x4, epilogue '
                      'restore, read by ret.r @+68) -- r3 is dead at '
                      'the site (fd4b1883 @+13 is shr r11,r10,0x3, a '
                      'shamt-immediate form reading only r10, not an '
                      'r3 consumer); rd=r10 is read @+1 by csr.w '
                      'r10,zero,0x28 (4d400028) as the model value '
                      '(r10&0x1f)|0x1a0 -- the rt slot names a dead '
                      'register (register-reuse artifact)',
        }],
        'note': '1 rt-live site of 51: noise (rt dead at the site: '
                'sole consumer before it, none after until the re-def; '
                'rd consumed as the model constant by csr.w)',
    },
    '{"op": "0x34", "section": "MAIN", "selector": '
    '{"f5": 28, "flag": 0, "idx": 0, "lo11": 28}}': {
        'row_verdict': 'noise',
        'sites': [{
            'fw': 'CX6DX', 'section': 'MAIN', 'dc_offset': '0x666a4',
            'word': '0xd084401c', 'verdict': 'noise',
            'reason': 'rt=r8 is the link register: the scanned def @-19 '
                      '(fee8b808 or r8,r23,r23) belongs to the previous '
                      "function's tail (arg of call @-18) and is cut "
                      'off by ret.r @-12 (fd001825, itself reading r8); '
                      'call @-2 (94017193) implicitly rewrites r8; r8 '
                      'is live through the site only for this '
                      "function's own ret.r @+15 -- rd=r4 = "
                      '(r4&0xf0000000)|0xc is stored back @+1 '
                      '(6c202016 st.d r4,r1,0x14); the rt value is a '
                      'return address, unrelated to rd (cross-function '
                      'boundary artifact of the linear 24-word window)',
        }],
        'note': '1 rt-live site of 4: noise (link-register liveness '
                'for another consumer; def across a ret.r boundary)',
    },
    '{"op": "0x34", "section": "MAIN", "selector": '
    '{"f5": 4, "flag": 1, "idx": 16, "lo11": 1540}}': {
        'row_verdict': 'noise',
        'sites': [{
            'fw': 'CX6DX', 'section': 'MAIN', 'dc_offset': '0x14abb8',
            'word': '0xd0842604', 'verdict': 'noise',
            'reason': 'rt==rs==rd=r4: the flagged live rt def IS the rs '
                      'def (66e40036 ld.d r4,r23,0x34 @-1); the site is '
                      'a table-field patch load -> deposit 0xd<<16 -> '
                      'st.d @+1 (6ee02036), one of a series (0x2205, '
                      'set2 ...) -- the rt field names the same '
                      'register as rs, no independent rt operand '
                      'exists; the const-deposit model covers the '
                      'dataflow (self-aliasing artifact)',
        }],
        'note': '1 rt-live site of 22: noise (rt==rs==rd, the flagged '
                'def feeds rs itself)',
    },
    '{"op": "0x34", "section": "MAIN", "selector": '
    '{"f5": 8, "flag": 1, "idx": 24, "lo11": 1800}}': {
        'row_verdict': 'noise',
        'sites': [
            {
                'fw': 'CX6DX', 'section': 'MAIN',
                'dc_offset': '0x28e6e0', 'word': '0xd0a52708',
                'verdict': 'noise',
                'reason': 'rt=r4 is the descriptor loaded @-4 (66c40002 '
                          'ld.d r4,r22,0x0) with its own extraction '
                          'chain AFTER the site (308700c0 andmsk.hi '
                          'r7,r4,0xc0 @+3; fc87380a and r7,r4,r7 @+10; '
                          'fc89300a and r9,r4,r6 @+12); rd=r5 is the '
                          'top-byte deposit (r5&0x00ffffff)|0x0d000000 '
                          'of the word from [r22+0x20], stored @+1 '
                          '(6ec02822) -- rt is live for other '
                          'consumers',
            },
            {
                'fw': 'CX6DX', 'section': 'MAIN',
                'dc_offset': '0xe5aac', 'word': '0xd0840f08',
                'verdict': 'noise',
                'reason': 'rd=r4 is dead (rd_use=none in the 12-word '
                          'window; the only later reference is the '
                          'don\'t-care rt field of addi.hi r8,r5 @+23, '
                          '08a8214f, rs=r5/rt=r4); rt=r1 is the stack '
                          'pointer of the epilogue (6437000e ld.d '
                          'r23,r1,0xc @+1; 00210010 addi r1,r1,0x10 '
                          '@+2; ld.d r3,r1,0x4 @+3; ret.r @+4); the '
                          'scanned def @-23 (00210028) sits across the '
                          'ret.r @-21 boundary in the previous '
                          "function's epilogue (dead rd + stack-pointer "
                          'liveness for another consumer)',
            },
        ],
        'note': '2 rt-live sites of 884: both noise (other consumers / '
                'dead rd + SP-liveness across a ret.r boundary)',
    },
}


def adjudication_for(jkey, rt_live):
    """Per-row adjudication of the raw rt_live counter-signal (owner
    ruling 2026-11-01): the table entry when complete, 'unadjudicated'
    (fail closed) when absent, SystemExit on count drift (the table no
    longer matches the recomputed def-use)."""
    adj = RT_LIVE_ADJUDICATION.get(jkey)
    if adj is None:
        return {
            'verdict': 'unadjudicated', 'sites': [],
            'note': 'no offline adjudication on file for the rt-live '
                    'signal -- fail closed: row residual, out of '
                    'dep_merge_unblocked_rows',
        }
    if len(adj['sites']) != rt_live:
        raise SystemExit(
            'adjudication table drift %s: %d sites listed, %d rt-live '
            'recomputed' % (jkey, len(adj['sites']), rt_live))
    if any(s['verdict'] == 'real' for s in adj['sites']):
        verdict = 'real'
    elif all(s['verdict'] == 'noise' for s in adj['sites']):
        verdict = 'noise'
    else:
        verdict = 'unadjudicated'
    return {'verdict': verdict, 'sites': adj['sites'],
            'note': adj['note']}

# register-writer decode helpers (opcode classes per slaspec)
NON_WRITERS = frozenset((0x13, 0x1a, 0x1b, 0x1c, 0x1e, 0x25,
                         0x28, 0x29, 0x2a, 0x2b))
SET_OPS = frozenset((0x06, 0x07, 0x08, 0x09))
ADDI_OPS = frozenset((0x00, 0x01, 0x02, 0x03))
STORE_OPS = frozenset((0x13, 0x1a, 0x1b, 0x1c, 0x1e))


def md5_of(path):
    return hashlib.md5(Path(path).read_bytes()).hexdigest()


def check_pin(path, pin):
    got = md5_of(path)
    if got != pin:
        raise SystemExit('input drift %s: md5 %s != pin %s'
                         % (path, got, pin))


def rd_of(w):
    return (w >> 16) & 0x1f


def rs_of(w):
    return (w >> 21) & 0x1f


def rt_of(w):
    return (w >> 11) & 0x1f


# ---------------------------------------------------------------- model

def mask32(f5):
    """Field mask of the rogue model: f5=0 is the full 32-bit word
    (width-32 wrap, the x86 (32-f5)&31 shift semantics), f5>0 the plain
    2^f5-1 run of ones."""
    return 0xFFFFFFFF if f5 == 0 else (1 << f5) - 1


def p0(f5, flag):
    """Deposit base: 0xc|flag masked to the field width."""
    return (0xC | flag) & mask32(f5)


def field_mask(f5, idx):
    return (mask32(f5) << idx) & 0xFFFFFFFF


def deposit(f5, idx, flag=0):
    return (p0(f5, flag) << idx) & 0xFFFFFFFF


def predict(f5, idx, flag, rs):
    return ((rs & ~field_mask(f5, idx)) | deposit(f5, idx, flag)) \
        & 0xFFFFFFFF


def row_model_form(f5, idx, flag, points):
    """'formula' iff the model prediction matches EVERY (rs, expected)
    observation point of the row; a single mismatch -> 'residual'."""
    for rs, want in points:
        if predict(f5, idx, flag, rs) != want:
            return 'residual'
    return 'formula'


# ---------------------------------------------------------------- def-use

def prov_class(words, i, reg, back=PROV_BACK):
    """Last def of `reg` before word i: (kind, delta).

    kind: 'imm' (set0..3 or addi/addi.hi from zero), 'other' (any other
    register writer -- loads, ALU results: a live value), 'none', or
    'zero-reg' for the hardwired zero."""
    if reg == 0:
        return ('zero-reg', 0)
    for j in range(i - 1, max(-1, i - 1 - back), -1):
        w = words[j]
        op = w >> 26
        if op in NON_WRITERS:
            continue
        if rd_of(w) == reg:
            if op in SET_OPS:
                return ('imm', j - i)
            if op in ADDI_OPS and rs_of(w) == 0:
                return ('imm', j - i)
            return ('other', j - i)
    return ('none', 0)


def next_use(words, i, reg, fwd=USE_FWD):
    """First use of `reg` after word i: (kind, delta).

    kind: 'store' (an st.* source), 'read' (any other reader),
    'clobber' (a writer to reg before any use), 'none', 'zero'."""
    if reg == 0:
        return ('zero', 0)
    for j in range(i + 1, min(len(words), i + 1 + fwd)):
        w = words[j]
        op = w >> 26
        if op in STORE_OPS:
            if rs_of(w) == reg or rt_of(w) == reg:
                return ('store', j - i)
            continue
        if op in NON_WRITERS:
            continue
        if rs_of(w) == reg or rt_of(w) == reg:
            return ('read', j - i)
        if rd_of(w) == reg:
            return ('clobber', j - i)
    return ('none', 0)


def site_facts(words, i):
    """Raw def-use facts of the 0x34 site at word i."""
    w = words[i]
    rt = rt_of(w)
    rt_prov = prov_class(words, i, rt)
    return {
        'rt': rt,
        'rt_prov': rt_prov[0],
        'rt_prov_dist': rt_prov[1],
        'rs_prov': prov_class(words, i, rs_of(w))[0],
        'rd_use': next_use(words, i, rd_of(w))[0],
        'rt_live': rt != 0 and rt_prov[0] == 'other',
    }


def row_static_verdict(facts):
    """Raw def-use verdict of a row from its strict-site facts.

    'H-34-rt-fed' (>= RT_FED_MIN sites with a live rt def: the corpus
    feeds a value through rt -- dep-shape usage, contradiction of the
    const-deposit model), 'H-34-field-consistent' (sites exist, no
    rt-fed cluster), None (no strict sites: the static leg is silent)."""
    if not facts:
        return None
    if sum(1 for f in facts if f['rt_live']) >= RT_FED_MIN:
        return 'H-34-rt-fed'
    return 'H-34-field-consistent'


# ------------------------------------------------------------- corpus load

def load_sections():
    """Extract every irisc section of corpus_sections.json from the
    md5-pinned images (payload md5 verified per section)."""
    spec = importlib.util.spec_from_file_location(
        'corpus_sections', HERE / 'corpus_sections.py')
    if spec is None or spec.loader is None:
        raise SystemExit('cannot import corpus_sections.py')
    cs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cs)
    doc = json.loads((HERE / 'corpus_sections.json').read_text())
    out = {}
    images = {}
    for r in doc['sections']:
        if r['classification'] != 'irisc':
            continue
        ver = r['fw']
        if ver not in images:
            images[ver] = cs.load_image(ver)
        img = images[ver]
        e = img.find_entry('ITOC', int(r['type'], 16))
        payload, _tail = cs.extract_payload(img.section_data(e), e.clcrc)
        if hashlib.md5(payload).hexdigest() != r['md5']:
            raise SystemExit('payload drift %s %s' % (ver, r['type']))
        n = len(payload) // 4
        out[(ver, r['short'])] = struct.unpack_from('>%dI' % n, payload, 0)
    return out


def selector_of(w):
    lo11 = w & 0x7ff
    return {'f5': lo11 & 0x1f, 'idx': (lo11 >> 5) & 0x1f,
            'flag': (lo11 >> 10) & 1, 'lo11': lo11}


def load_sites():
    """strict 0x34 sites grouped by (section, selector-json)."""
    path = HERE / 'corpus_sites.jsonl'
    check_pin(path, PIN_SITES)
    sites = collections.defaultdict(list)
    for line in path.read_text().splitlines():
        s = json.loads(line)
        w = int(s['word'], 16)
        if w >> 26 != 0x34 or not s['strict']:
            continue
        sel = selector_of(w)
        sites[(s['section'], json.dumps(sel, sort_keys=True))].append({
            'fw': s['fw'], 'section': s['section'],
            'dc_offset': s['dc_offset'], 'word': s['word'],
            '_idx': int(s['dc_offset'], 16) // 4, '_w': w,
        })
    for lst in sites.values():
        lst.sort(key=lambda s: (s['fw'], s['section'], s['dc_offset']))
    return sites


# ------------------------------------------------------------- phase A

def build_phase_a():
    check_pin(HERE / 'census_corpus.json', PIN_CENSUS)
    census = json.loads((HERE / 'census_corpus.json').read_text())
    cm_path = REPO / 'scripts/probes/cx5-fuzz5/census_map.json'
    check_pin(cm_path, PIN_CENSUS_MAP)
    census_map = json.loads(cm_path.read_text())

    # universe: 0x34 has-sites rows of BOTH maps (T7 consumes this
    # surface from both maps; lossless selector keys, form not part of
    # the key -- 0x34 has no form axis)
    rows = {}
    for r in census['rows']:
        if r['key']['op'] != '0x34' or r['class'] != 'has-sites':
            continue
        key = {'section': r['key']['section'], 'op': '0x34',
               'selector': dict(r['key']['selector'])}
        rows[json.dumps(key, sort_keys=True)] = key
    for r in census_map['rows']:
        if r['op'] != '0x34' or r['class'] != 'has-sites':
            continue
        key = {'section': 'MAIN', 'op': '0x34',
               'selector': dict(r['selector'])}
        rows.setdefault(json.dumps(key, sort_keys=True), key)

    sections = load_sections()
    sites = load_sites()

    phase_rows = []
    for jkey in sorted(rows):
        key = rows[jkey]
        sel = key['selector']
        row_sites = sites.get(
            (key['section'], json.dumps(sel, sort_keys=True)), [])
        facts = []
        agg = collections.Counter()
        for s in row_sites:
            words = sections.get((s['fw'], s['section']))
            if words is None or s['_idx'] >= len(words):
                continue
            f = site_facts(words, s['_idx'])
            facts.append((s, f))
            agg['sites'] += 1
            agg['rt:' + f['rt_prov']] += 1
            agg['use:' + f['rd_use']] += 1
            if f['rt_live']:
                agg['rt_live'] += 1
        verdict = row_static_verdict([f for _s, f in facts])
        static_conflict = verdict == 'H-34-rt-fed'
        pred = {
            'mask': '0x%08x' % field_mask(sel['f5'], sel['idx']),
            'deposit': '0x%08x' % deposit(sel['f5'], sel['idx'],
                                          sel['flag']),
        }
        row = {
            'key': key,
            'static_verdict': verdict,
            'predicted': pred,
            'unique': not static_conflict,
            'basis': [{
                'type': 'site',
                'site': {'fw': s['fw'], 'section': s['section'],
                         'dc_offset': s['dc_offset'], 'word': s['word']},
                'def_use': {k: f[k] for k in
                            ('rt', 'rt_prov', 'rt_prov_dist', 'rs_prov',
                             'rd_use', 'rt_live')},
            } for s, f in facts[:SITE_SAMPLES]],
            'conflict': static_conflict,
            'live_join': None,
            'model_form': 'residual' if static_conflict else 'formula',
            'def_use': dict(sorted(agg.items())),
        }
        if verdict is None:
            row['reason'] = 'no strict sites for this selector ' \
                            '(static leg silent)'
        phase_rows.append(row)

    n_fed = sum(1 for r in phase_rows if r['static_verdict']
                == 'H-34-rt-fed')
    doc = {
        'meta': {
            'cycle': 'isa-max-a task-5 (C-A.2 0x34 rogue P-table model)',
            'model_spec': {
                'formula': 'rd = (rs & ~(mask32(f5) << idx)) | '
                           '(((0xc | flag) & mask32(f5)) << idx)  '
                           '[32-bit]',
                'mask32': 'mask32(0) = 0xffffffff (width-32 wrap, '
                          'verified on the single live f5=0 point); '
                          'mask32(f5>0) = 2^f5 - 1',
                'p_table': 'P0(f5,flag) = (0xc|flag) & mask32(f5): '
                           'f5>=4 -> 0xc/0xd; f5=3 -> 0x4/0x5 (flag=1 '
                           'unobserved); f5=2 -> 0x0/0x1; f5=1 -> 0x0 '
                           '(flag=1 unobserved); f5=0 -> 0xc/0xd '
                           '(flag=1 unobserved)',
                'f5=2_note': 'flag=1 deposits 1<<idx; the bclr-of-idx '
                             'reading coincides on all three captured '
                             'points (rs bit idx was set each time); '
                             'axis f5=2 idx=5 stays OPEN per the '
                             'fuzz-5 ruling (modeled + validated only, '
                             'no semantics change)',
                'operand_dependence': 'rogue values move with rs '
                                      'because rs survives outside the '
                                      'mask (OPDEP-A/B captured shape); '
                                      'the deposit itself is '
                                      'rs-independent',
            },
            'pins': {
                'corpus_sites.jsonl': PIN_SITES,
                'census_corpus.json': PIN_CENSUS,
                'census_map.json': PIN_CENSUS_MAP,
                'fuzz5_live.json': PIN_LIVE,
            },
            'static_rule': 'H-34-rt-fed iff >= %d strict sites with a '
                           'live rt def (contradiction of the '
                           'const-deposit model); else '
                           'H-34-field-consistent when strict sites '
                           'exist; no strict sites -> null (silent '
                           'static leg). H-34-field-consistent means '
                           'NO rt-fed contradiction was detected -- it '
                           'is the absence of a contradiction signal, '
                           'not positive corroboration of the deposit '
                           'value (offline def-use cannot see the '
                           'deposited constant). A residual raw rt_live '
                           'signal (1..%d sites) on a merge-candidate '
                           'row is adjudicated per-row offline (see '
                           'rt_live_adjudication_rule), not silently '
                           'thresholded away'
                           % (RT_FED_MIN, RT_FED_MIN - 1),
            'residual_rule': 'contradiction in any leg (live mismatch '
                             'or static rt-fed) -> row model_form '
                             '= residual',
            'coverage': {
                'universe_rows': len(phase_rows),
                'strict_sites': sum(r['def_use'].get('sites', 0)
                                    for r in phase_rows),
                'rt_fed_rows': n_fed,
            },
            'addressing_note': 'dc offsets only; no dc<->rt base '
                               'arithmetic needed (per-section param0 '
                               'bases live in corpus_sections.json)',
        },
        'phases': {
            'A': {'rows': phase_rows},
        },
    }
    return doc


# ------------------------------------------------------------- phase B

def live_points(rec):
    """(rs, obs) checkable observation points of a live record; a valued
    observation without a captured rs operand is NOT checkable (counted
    as value-silent by the callers, never silently rs=0)."""
    pts = []
    for o in rec.get('observations', []):
        val = o.get('observed')
        seed = o.get('operands_seed') or {}
        if val is None or 'rs' not in seed:
            continue
        rs = int(seed['rs'], 16) & 0xFFFFFFFF
        pts.append((rs, int(val, 16), o['vector_id']))
    return pts


def build_phase_b(a_doc):
    check_pin(HERE / 'fuzz5_live.json', PIN_LIVE)
    live = json.loads((HERE / 'fuzz5_live.json').read_text())

    def lkey(v):
        return json.dumps({'section': v['section'], 'op': '0x34',
                           'selector': v['selector']}, sort_keys=True)

    live_rows = {lkey(v): v for v in live['rows'].values()
                 if v['op'] == '0x34'}

    rows = []
    stats = collections.Counter()
    join_stats = collections.Counter()
    obs_checked = 0
    dep_unblocked = []
    ruling_excluded = []
    for r in a_doc['phases']['A']['rows']:
        rec = dict(r)
        jkey = json.dumps(rec['key'], sort_keys=True)
        lrow = live_rows.get(jkey)
        sel = rec['key']['selector']
        if lrow is None:
            status = 'silence'
            note = 'no live row for selector'
            n_obs = n_chk = n_silent = 0
        else:
            obs = lrow.get('observations', [])
            pts = live_points(lrow)
            n_obs = len(obs)
            n_chk = len(pts)
            n_silent = n_obs - n_chk
            obs_checked += n_chk
            bad = [vid for rs, want, vid in pts
                   if predict(sel['f5'], sel['idx'], sel['flag'], rs)
                   != want]
            if n_chk == 0:
                status = 'silence'
                note = ('live row without captured values '
                        '(expectation-free rogue rows of the battery)')
            elif bad:
                status = 'contradiction'
                note = 'model misses %d/%d observed values' % (
                    len(bad), n_chk)
            else:
                status = 'match'
                note = 'model agrees with all %d captured values' % n_chk
        join_stats[status] += 1
        if status == 'match':
            stats['vl_match'] += 1
        if n_chk:
            stats['vl_observed_total'] += 1
        live_conflict = status == 'contradiction'
        rec['live_join'] = {
            'status': status,
            'note': note,
            'live_verdict': lrow['live_verdict'] if lrow else None,
            'n_observations': n_obs,
            'n_checked': n_chk,
            'n_value_silent': n_silent,
        }
        rec['conflict'] = bool(rec['conflict'] or live_conflict)
        rec['model_form'] = 'residual' if rec['conflict'] \
            else 'formula'
        rec['unique'] = bool(rec['predicted']) and not rec['conflict']
        # 2026-11-01 owner ruling: a merge-candidate row carrying a raw
        # rt_live signal below RT_FED_MIN needs a complete per-row
        # adjudication; noise keeps it mergeable, anything else (real,
        # unadjudicated) fails closed to residual
        rt_live = (rec.get('def_use') or {}).get('rt_live', 0)
        if rt_live and not rec['conflict'] and status == 'match':
            adj = adjudication_for(jkey, rt_live)
            rec['rt_live_adjudication'] = adj
            if adj['verdict'] != 'noise':
                rec['conflict'] = True
                rec['model_form'] = 'residual'
                rec['unique'] = False
        if jkey in RULING_EXCLUDED:
            rec['ruling_excluded'] = True
            rec['ruling_note'] = RULING_EXCLUDED[jkey]
            rec['live_join']['note'] += '; ruling-excluded: ' \
                + RULING_EXCLUDED[jkey]
            ruling_excluded.append(jkey)
        elif not rec['conflict'] and status == 'match':
            dep_unblocked.append(jkey)
        rows.append(rec)

    # disc-extras and zero-site census rows observed live but outside
    # the has-sites universe: synthesized, static leg explicitly silent
    for jkey in sorted(set(live_rows) - {
            json.dumps(r['key'], sort_keys=True)
            for r in a_doc['phases']['A']['rows']}):
        lrow = live_rows[jkey]
        key = json.loads(jkey)
        sel = key['selector']
        pts = live_points(lrow)
        bad = [vid for rs, want, vid in pts
               if predict(sel['f5'], sel['idx'], sel['flag'], rs)
               != want]
        if not pts:
            status = 'silence'
            note = 'live row without captured values'
        elif bad:
            status = 'contradiction'
            note = 'model misses %d/%d observed values' % (
                len(bad), len(pts))
        else:
            status = 'match'
            note = 'model agrees with all %d captured values' % len(pts)
        join_stats[status] += 1
        obs_checked += len(pts)
        if pts:
            stats['vl_observed_total'] += 1
            if status == 'match':
                stats['vl_match'] += 1
        live_conflict = status == 'contradiction'
        rec = {
            'key': key,
            'static_verdict': None,
            'predicted': {
                'mask': '0x%08x' % field_mask(sel['f5'], sel['idx']),
                'deposit': '0x%08x' % deposit(sel['f5'], sel['idx'],
                                              sel['flag']),
            },
            'unique': bool(pts) and not live_conflict,
            'basis': [],
            'conflict': live_conflict,
            'live_join': {
                'status': status,
                'note': note,
                'live_verdict': lrow['live_verdict'],
                'n_observations': len(lrow.get('observations', [])),
                'n_checked': len(pts),
                'n_value_silent': len(lrow.get('observations', []))
                - len(pts),
            },
            'model_form': 'residual' if live_conflict else 'formula',
            'extra': True,
            'reason': 'outside the has-sites universe (census '
                      'zero-sites row or disc-restored key); static '
                      'leg silent',
        }
        if jkey in RULING_EXCLUDED:
            rec['ruling_excluded'] = True
            rec['ruling_note'] = RULING_EXCLUDED[jkey]
            rec['live_join']['note'] += '; ruling-excluded: ' \
                + RULING_EXCLUDED[jkey]
            ruling_excluded.append(jkey)
        elif status == 'match' and not live_conflict:
            dep_unblocked.append(jkey)
        rows.append(rec)
    rows.sort(key=lambda r: json.dumps(r['key'], sort_keys=True))

    n_resid = sum(1 for r in rows if r['model_form'] == 'residual')
    if stats['vl_match'] == stats['vl_observed_total'] \
            and stats['vl_observed_total']:
        model_form = 'formula'
    elif n_resid < len(rows):
        model_form = 'table'
    else:
        model_form = 'residual'

    # cross-gate: the fuzz-5 OPDEP precedents must reproduce
    for key_sel, wants in (
            ('op34_f5=04_idx=00_flag=0', (0xC, 0x7FFC)),
            ('op34_f5=08_idx=0a_flag=1', (0x3634, 0x37FF))):
        v = live['rows'][key_sel]
        pts = live_points(v)
        sel = v['selector']
        got = tuple(predict(sel['f5'], sel['idx'], sel['flag'], rs)
                    for rs, _w, _v in pts)
        if got != wants:
            raise SystemExit('gate: OPDEP precedent %s: %s'
                             % (key_sel, got))

    n_checked_static = sum(1 for r in rows
                           if r['static_verdict'] is not None)
    n_rt_fed = sum(1 for r in rows
                   if r['static_verdict'] == 'H-34-rt-fed')
    # the dual-validation meta is TOP-LEVEL (single consumer surface:
    # T8 reads model_form + validation_* + dep_merge_unblocked_rows
    # from doc.meta, not from a phase)
    a_doc['phases']['B'] = {
        'rows': rows,
        'join_stats': dict(sorted(join_stats.items())),
    }
    a_doc['meta'].update({
        'model_form': model_form,
        'model_form_note': 'formula: the uniform P-model fits every '
                           'captured observed value; rows with an '
                           'any-leg contradiction keep their prediction '
                           'but are itemized as residual'
                           if model_form == 'formula' else
                           'see residual rows',
        'validation_live': {
            'match': stats['vl_match'],
            'observed_total': stats['vl_observed_total'],
            'observations_checked': obs_checked,
        },
        'validation_static': {
            'checked': n_checked_static,
            'unobserved': len(rows) - n_checked_static,
            'match': n_checked_static - n_rt_fed,
            'contradict': n_rt_fed,
        },
        'dep_merge_unblocked_rows': dep_unblocked,
        'rt_live_adjudication_rule':
            'owner ruling 2026-11-01 (final-review round 2): a '
            'merge-candidate row (live match, no conflict) with a raw '
            'rt_live counter-signal below RT_FED_MIN carries a per-row '
            'offline adjudication of EVERY rt-live site (decoded '
            'def-use window: rt producer, the 0x34 site, rd consumers, '
            'rt forward liveness). noise = concrete non-rt explanation '
            '(another consumer of rt / rt dead at the site / dead rd / '
            'cross-function or self-aliasing artifact) keeps the row '
            'mergeable; real = '
            "rt's value would flow into rd's consumers -> conflict -> "
            'residual; a missing or incomplete adjudication also fails '
            'closed (unadjudicated -> residual). Rows at/above '
            'RT_FED_MIN keep their H-34-rt-fed residual status (not '
            'un-residualed).',
        'rt_live_adjudicated_rows': [
            jkey for jkey in sorted(RT_LIVE_ADJUDICATION)
            if jkey in dep_unblocked
        ],
        'ruling_excluded_rows': ruling_excluded,
        'ruling_note': 'fuzz-5 owner ruling «ось f5=2 idx=5 не трогать» '
                       'EXCLUDES the axis from any merge-ready claim '
                       '(select_merges.py OPEN_RECS precedent): the '
                       'fuzz-4 V-34-2 observation (rs=0xff, rt=1 -> '
                       '0x000400ff, census_map OPEN-34-f5=2-idx=5) '
                       'contradicts the P-formula and is outside '
                       'fuzz5_live.json; excluded rows carry '
                       'ruling_excluded + ruling_note',
        'residual_rows': sum(1 for r in rows
                             if r['model_form'] == 'residual'),
        'extras_note': 'disc-extra records (family-level '
                       'live_verdict:"rogue" assigned by T3 at '
                       'build_live_table.py:529) are joined by their '
                       'captured VALUES only; the family tag is not '
                       'used by the model or the join',
        'unblocked_note': 'rows with no contradiction in either leg '
                          '(live match + static not rt-fed), MINUS the '
                          'ruling-excluded OPEN axis keys '
                          '(ruling_excluded_rows); merge-candidates '
                          'with a raw rt_live signal below RT_FED_MIN '
                          'carry rt_live_adjudication (noise-with-reason '
                          'per site; anything less fails closed to '
                          'residual, see rt_live_adjudication_rule)',
    })
    return a_doc


# ------------------------------------------------------------------- main

def write_doc(doc):
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + '\n')


def main():
    ap = argparse.ArgumentParser(
        description='isa-max A task-5: 0x34 rogue P-table model')
    ap.add_argument('--phase-a', action='store_true',
                    help='recompute Phase A (static only) and write it')
    ap.add_argument('--phase-b', action='store_true',
                    help='join fuzz5_live into Phase B (requires A)')
    ap.add_argument('--check', action='store_true',
                    help='recompute A+B and diff against the artifact')
    args = ap.parse_args()

    if args.check:
        have = json.loads(OUT.read_text())
        if 'A' not in have.get('phases', {}):
            raise SystemExit('CHECK FAIL: artifact has no Phase A')
        fresh = build_phase_b(build_phase_a())
        if fresh == have:
            print('CHECK PASS: p34_table.json reproduces '
                  '(%d phase-A rows)' % len(fresh['phases']['A']['rows']))
            return
        raise SystemExit('CHECK FAIL: p34_table.json drift')

    if args.phase_a:
        doc = build_phase_a()
        if OUT.exists():
            try:
                old = json.loads(OUT.read_text())
            except json.JSONDecodeError:
                old = {}
            if 'B' in old.get('phases', {}):
                doc = build_phase_b(doc)
        write_doc(doc)
        fed = doc['meta']['coverage']['rt_fed_rows']
        print('phase A: %d rows, %d strict sites, %d rt-fed'
              % (len(doc['phases']['A']['rows']),
                 doc['meta']['coverage']['strict_sites'], fed))
        print('wrote %s' % OUT)
        return

    if args.phase_b:
        doc = json.loads(OUT.read_text())
        if 'A' not in doc.get('phases', {}):
            raise SystemExit('no Phase A in artifact; run --phase-a first')
        doc = build_phase_b(doc)
        write_doc(doc)
        b = doc['phases']['B']
        print('phase B: join %s; live %s/%s; unblocked %d rows'
              % (b['join_stats'],
                 doc['meta']['validation_live']['match'],
                 doc['meta']['validation_live']['observed_total'],
                 len(doc['meta']['dep_merge_unblocked_rows'])))
        print('wrote %s' % OUT)
        return

    ap.print_help()


if __name__ == '__main__':
    main()
