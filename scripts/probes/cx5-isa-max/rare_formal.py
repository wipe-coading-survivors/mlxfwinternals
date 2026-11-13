#!/usr/bin/env python3
"""isa-max A task-7 (C-A.4 + C-A.5 pre-sweep): 0x39/0x3c static
formalization (lo-passthrough / zero) + cmp38-self def-use sweep.

Candidate formulas (live-double-anchored, formalized here statically):

    0x39  H-39-lo    rd_lo = zext32(rs_lo)   (lo-passthrough)
    0x3c  H-3c-zero  rd = 0                   (zero-write)

Phase A (NEVER reads fuzz5_live.json): row universe = the 0x39/0x3c rows
of BOTH maps (census_corpus all sections + census_map MAIN, lossless);
per row, raw def-use over every strict corpus site of the
(section, op, lo11): rs provenance and rd consumer classification reuse
the T6 h16_reform framework verbatim (imported, single source of the
def-use semantics), plus a per-op const value check -- a proven rs const
reaching a const-test consumer of rd (cmp0/cmpC/ztest/pred0) adjudicates
the formula: the FW tests exactly the value the candidate computes ->
'match', any other constant -> 'mismatch' (hard contradiction). Per-row
verdict: 'H-39-lo-consistent'/'H-3c-zero-consistent' iff strict sites
exist and no value mismatch; silent (None) when no strict sites;
conflict=True on a mismatch.

cmp38-self pre-sweep (C-A.5, static part): every rs==rt site of the
merged cmp.w (0x38 sel=0) in corpus_sites.jsonl (strict AND non-strict:
the sweep is a hazard check, fail-closed) gets a linear cc0a scan after
the site -- to the first b.t/b.f cc=0x0a consumer or the first cc0a
writer (any 0x36, or a 0x38 sel=0; value-forms 0x38 sel!=0 do NOT write
the latch), no distance cap (cc-latch semantics). consumer_insensitive
= killed / no-consumer / dead-branch consumer (noop or skip-noop); a
live branch consumer is sensitive. aggregate.formalizable iff ALL sites
are insensitive (the input of the T8 sanctioned rule).

Phase B (separate run): join fuzz5_live.json op39/op3c MAIN rows (the
candidate prediction is checked against EVERY captured observation
value) + the cmp38_self record (both live supports); merge_ready rows
are advisory/derived -- T8 decides by contract.

Outputs: rare_verdicts.json next to this script (committed). `--phase-a`
writes/refreshes phases.A; `--phase-b` requires phases.A; `--check`
recomputes both and diffs byte-for-byte.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

OUT = HERE / 'rare_verdicts.json'

# committed inputs are md5-pinned: refuse silent drift
PIN_SITES = '18918f8f07cc7716b783df7a1934ee7b'
PIN_CENSUS = '78b1f6964f508bc654c39ee6add28d1d'
PIN_CENSUS_MAP = 'c6b8dbfaa4ca42f77a5d79e705cc1a75'
PIN_LIVE = '42358ef7acab628637cd0c7c2925ad04'

RARE_OPS = (0x39, 0x3c)

# def-use windows/tables and the corpus loader come from the T6 script
# (imported: identical def-use semantics across the T4-T7 grind scripts)
SITE_SAMPLES = 3           # basis site samples per row

FORMULAS = {
    '0x39': {
        'id': 'H-39-lo',
        'formula': 'rd_lo = zext32(rs_lo)',
        'note': 'lo-passthrough: the low 32 bits of rs pass to rd '
                '(live vectors are in-place rd==rs); lo11-independent '
                '(live unique at lo11 0x000 and 0x7ff)',
    },
    '0x3c': {
        'id': 'H-3c-zero',
        'formula': 'rd = 0',
        'note': 'zero-write; lo11-independent (the 0x7ff live point '
                'killed H-3c-and-lo11; lo11=000 stays live-multi '
                'zero|and-lo11 -- both predict 0 there)',
    },
}


def load_h16():
    spec = importlib.util.spec_from_file_location(
        'h16_reform', HERE / 'h16_reform.py')
    if spec is None or spec.loader is None:
        raise SystemExit('cannot import h16_reform.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


H16 = load_h16()
check_pin = H16.check_pin
load_sections = H16.load_sections
rd_of = H16.rd_of
rs_of = H16.rs_of
rt_of = H16.rt_of
prov_value = H16.prov_value
rd_consumer = H16.rd_consumer


def s24(v):
    v &= 0xffffff
    return v - 0x1000000 if v & 0x800000 else v


# ---------------------------------------------------------------- formula

def predict(op, lo11, rs):
    """Candidate formula value (low 32 bits, the live-observable half)."""
    if op == 0x39:
        return rs & 0xFFFFFFFF
    if op == 0x3c:
        return 0
    raise ValueError('op 0x%02x outside the task-7 rare set' % op)


def verdict_id(op):
    return 'H-%02x-%s-consistent' % (op, 'lo' if op == 0x39 else 'zero')


# ---------------------------------------------------------------- def-use

def site_facts(op, words, i):
    """Raw def-use facts of the 0x39/0x3c site at word i (h16 framework
    + the per-op value check against the candidate formula)."""
    w = words[i]
    rs = rs_of(w)
    rd = rd_of(w)
    lo11 = w & 0x7ff
    prov, val = prov_value(words, i, rs)
    consumer, detail, cj = rd_consumer(words, i, rd)
    facts = {
        'rs': rs,
        'rd': rd,
        'rt': rt_of(w),
        'rd_eq_rs': rd == rs,
        'rs_prov': prov,
        'rs_value': val,
        'consumer': consumer,
        'consumer_detail': detail,
        'consumer_class': H16.CONSUMER_CLASS[consumer],
        'consumer_dist': (cj - i) if cj is not None else None,
        'cmp_const': detail if consumer in ('cmp0', 'cmpC') else None,
        'value_check': None,
        'value_expected': None,
    }
    if val is not None:
        pred = predict(op, lo11, val)
        facts['value_expected'] = pred
        if consumer == 'cmp0':
            facts['value_check'] = 'match' if pred == 0 else 'mismatch'
        elif consumer == 'cmpC':
            facts['value_check'] = ('match' if pred == detail
                                    else 'mismatch')
        elif consumer == 'ztest' and isinstance(detail, str):
            mask = int(detail, 16)
            facts['value_check'] = ('match'
                                    if pred & mask == 0 else 'mismatch')
        elif consumer == 'pred0':
            f5 = 0
            if isinstance(detail, str) and detail.startswith('f5='):
                f5 = int(detail.split('_')[0].split('=')[1], 16)
            facts['value_check'] = ('match'
                                    if pred & ((1 << f5) - 1) == 0
                                    else 'mismatch')
    return facts


def row_verdict(op, lo11, facts):
    """Per-row verdict from raw site facts (no live access)."""
    if not facts:
        return {'static_verdict': None, 'unique': False,
                'conflict': False,
                'reason': 'no strict sites for this selector '
                          '(static leg silent)'}
    bad = [f for f in facts if f.get('value_check') == 'mismatch']
    if bad:
        return {'static_verdict': None, 'unique': False, 'conflict': True,
                'reason': 'const value check mismatch at %d site(s): the '
                          'FW tests a constant the candidate formula '
                          'does not compute' % len(bad)}
    return {'static_verdict': verdict_id(op), 'unique': True,
            'conflict': False}


# ------------------------------------------------- cmp38-self cc0a sweep

def cc0a_scan(words, i):
    """Linear cc0a scan after word i: the first cc0a CONSUMER (b.t/b.f
    with cc field 0x0a, with the dead-branch check) or the first cc0a
    WRITER (any 0x36, or a 0x38 sel=0). No distance cap: the CMPRES
    latch holds until overwritten. Value-form 0x38 (sel!=0) and every
    other op leave the latch alone."""
    for j in range(i + 1, len(words)):
        w = words[j]
        op = w >> 26
        if op in (0x28, 0x29) and ((w >> 16) & 0x1f) == 0x0a:
            tgt = j + H16.s16(w)
            fall = j + 1
            dead = tgt == fall
            if not dead and 0 <= tgt < len(words):
                tw = words[tgt]
                if tw >> 26 == 0x25 and tgt + s24(tw) == fall:
                    dead = True
            return {'state': 'consumer', 'dist': j - i,
                    'polarity': 't' if op == 0x28 else 'f',
                    'dead_branch': dead,
                    'consumer_dc': '0x%x' % (j * 4)}
        if op == 0x36:
            return {'state': 'killed', 'dist': j - i, 'killer': '0x36',
                    'killer_dc': '0x%x' % (j * 4)}
        if op == 0x38 and rd_of(w) == 0:
            return {'state': 'killed', 'dist': j - i, 'killer': 'cmp.w',
                    'killer_dc': '0x%x' % (j * 4)}
    return {'state': 'no-consumer', 'dist': None}


def site_sensitivity(words, i):
    """Per-site sensitivity record of the rs==rt cmp.w site at word i."""
    st = cc0a_scan(words, i)
    insensitive = st['state'] != 'consumer' or st['dead_branch']
    rec = dict(st)
    rec['consumer_insensitive'] = bool(insensitive)
    return rec


def sweep_aggregate(sites):
    """Aggregate over per-site sensitivity records (T8 rule input)."""
    n = len(sites)
    n_ins = sum(1 for s in sites if s['consumer_insensitive'])
    return {'rs_eq_rt_sites': n, 'insensitive': n_ins,
            'formalizable': bool(n > 0 and n_ins == n)}


def cmp38_self_sites():
    """Every rs==rt site of the merged cmp.w (0x38 sel=0) from the
    pinned site manifest (strict and non-strict alike)."""
    check_pin(HERE / 'corpus_sites.jsonl', PIN_SITES)
    out = []
    for line in (HERE / 'corpus_sites.jsonl').read_text().splitlines():
        s = json.loads(line)
        w = int(s['word'], 16)
        if w >> 26 != 0x38:
            continue
        if rs_of(w) == rt_of(w) and rd_of(w) == 0:
            s['_word'] = w
            s['_idx'] = int(s['dc_offset'], 16) // 4
            out.append(s)
    out.sort(key=lambda s: (s['fw'], s['section'], s['dc_offset']))
    return out


def build_cmp38_self_sweep(sections):
    sites = cmp38_self_sites()
    recs = []
    for s in sites:
        words = sections.get((s['fw'], s['section']))
        rec = {'fw': s['fw'], 'section': s['section'],
               'dc_offset': s['dc_offset'], 'word': s['word'],
               'strict': s['strict'],
               'rs': rs_of(s['_word']), 'rt': rt_of(s['_word']),
               'lo11': s['_word'] & 0x7ff}
        if words is None or s['_idx'] >= len(words):
            rec.update({'state': 'unresolved', 'consumer_insensitive': False,
                        'note': 'section payload unavailable'})
        else:
            rec.update(site_sensitivity(words, s['_idx']))
            if not s['strict']:
                rec['note'] = ('mask-only site (non-strict): the raw scan '
                               'still counts (fail-closed); mask-only is '
                               'never proof in either direction')
        recs.append(rec)
    aggregate = sweep_aggregate(recs)
    strict_recs = [r for r in recs if r['strict']]
    aggregate['strict_sites'] = len(strict_recs)
    aggregate['strict_insensitive'] = sum(
        1 for r in strict_recs if r['consumer_insensitive'])
    return {'sites': recs, 'aggregate': aggregate}


# ------------------------------------------------------------- phase A

def load_rare_sites():
    """ALL 0x39/0x3c sites of corpus_sites.jsonl grouped by
    (section, op, lo11), strict flagged."""
    check_pin(HERE / 'corpus_sites.jsonl', PIN_SITES)
    sites = collections.defaultdict(list)
    for line in (HERE / 'corpus_sites.jsonl').read_text().splitlines():
        s = json.loads(line)
        w = int(s['word'], 16)
        op = w >> 26
        if op not in RARE_OPS:
            continue
        rec = {'fw': s['fw'], 'section': s['section'],
               'dc_offset': s['dc_offset'], 'word': s['word'],
               'strict': s['strict'],
               '_idx': int(s['dc_offset'], 16) // 4, '_w': w}
        sites[(s['section'], op, w & 0x7ff)].append(rec)
    for lst in sites.values():
        lst.sort(key=lambda s: (s['fw'], s['dc_offset']))
    return sites


def build_phase_a():
    check_pin(HERE / 'census_corpus.json', PIN_CENSUS)
    census = json.loads((HERE / 'census_corpus.json').read_text())
    cm_path = REPO / 'scripts/probes/cx5-fuzz5/census_map.json'
    check_pin(cm_path, PIN_CENSUS_MAP)
    census_map = json.loads(cm_path.read_text())

    # universe: rare-op rows of BOTH maps (lossless union)
    rows = {}
    for r in census['rows']:
        if r['key']['op'] not in ('0x39', '0x3c'):
            continue
        op = int(r['key']['op'], 16)
        key = {'section': r['key']['section'], 'op': r['key']['op'],
               'selector': {'lo11': r['key']['selector']['lo11']}}
        rows[json.dumps(key, sort_keys=True)] = key
    n_map_only = 0
    for r in census_map['rows']:
        if r.get('op') not in ('0x39', '0x3c'):
            continue
        key = {'section': 'MAIN', 'op': r['op'],
               'selector': {'lo11': r['selector']['lo11']}}
        jkey = json.dumps(key, sort_keys=True)
        if jkey not in rows:
            rows[jkey] = key
            n_map_only += 1

    sections = load_sections()
    sites = load_rare_sites()

    phase_rows = []
    stats = collections.Counter()
    for jkey in sorted(rows):
        key = rows[jkey]
        section = key['section']
        op = int(key['op'], 16)
        lo11 = key['selector']['lo11']
        row_sites = [s for s in sites.get((section, op, lo11), [])
                     if s['strict']]
        facts = []
        agg = collections.Counter()
        for s in row_sites:
            words = sections.get((s['fw'], s['section']))
            if words is None or s['_idx'] >= len(words):
                continue
            f = site_facts(op, words, s['_idx'])
            facts.append((s, f))
            agg['sites'] += 1
            agg['rs_prov:' + f['rs_prov']] += 1
            agg['consumer:' + f['consumer']] += 1
            agg['class:' + f['consumer_class']] += 1
            if f['rd_eq_rs']:
                agg['rd_eq_rs'] += 1
            if f['value_check'] is not None:
                agg['value_adjudicable'] += 1
                agg['value_check:' + f['value_check']] += 1
        v = row_verdict(op, lo11, [f for _s, f in facts])
        stats['rows'] += 1
        stats['rows_with_sites'] += 1 if facts else 0
        stats['strict_sites'] += agg.get('sites', 0)
        stats['value_adjudicable_sites'] += agg.get('value_adjudicable', 0)
        stats['value_mismatches'] += agg.get('value_check:mismatch', 0)
        row = {
            'key': key,
            'formula': FORMULAS[key['op']],
            'static_verdict': v['static_verdict'],
            'unique': v['unique'],
            'basis': [{
                'type': 'site',
                'site': {'fw': s['fw'], 'section': s['section'],
                         'dc_offset': s['dc_offset'], 'word': s['word']},
                'def_use': {k: f[k] for k in
                            ('rs', 'rd', 'rt', 'rd_eq_rs', 'rs_prov',
                             'consumer', 'consumer_detail',
                             'consumer_class', 'cmp_const',
                             'value_check', 'value_expected')},
            } for s, f in facts[:SITE_SAMPLES]],
            'conflict': v['conflict'],
            'def_use': dict(sorted(agg.items())),
            'live_join': None,
            'merge_ready': False,
        }
        if v['static_verdict'] is not None:
            row['static_source'] = 'raw-def-use'
        else:
            row['reason'] = v['reason']
        phase_rows.append(row)

    sweep = build_cmp38_self_sweep(sections)

    # corpus-wide positive-evidence counts (computed, not fixed)
    n_const_test = sum(r['def_use'].get('class:const-test', 0)
                       for r in phase_rows)
    n_3c_cmp0 = sum(r['def_use'].get('consumer:cmp0', 0)
                    for r in phase_rows if r['key']['op'] == '0x3c')

    doc = {
        'meta': {
            'cycle': 'isa-max-a task-7 (C-A.4 0x39/0x3c formalization + '
                     'C-A.5 cmp38-self pre-sweep)',
            'method': 'raw def-use over every strict corpus site per '
                      '(section, op, lo11) row of BOTH maps; def-use '
                      'framework imported from h16_reform (T6: single '
                      'source of the semantics); per-op const value '
                      'check against the candidate formula; cmp38-self: '
                      'linear cc0a consumer scan over every rs==rt '
                      'sel0 site (strict and non-strict, fail-closed)',
            'verdict_rule': "%s/%s iff the row has strict sites and no "
                            "const value-check mismatch; silent (None) "
                            "when no strict sites; conflict=True on a "
                            "mismatch (the FW tests a constant the "
                            "candidate formula does not compute)"
                            % (verdict_id(0x39), verdict_id(0x3c)),
            'static_rule_note': 'consistent = NO raw def-use '
                                'contradiction detected (absence-of-'
                                'contradiction signal, not positive '
                                'corroboration); the positive static '
                                'evidence is counted separately '
                                '(const-test consumers + adjudicable '
                                'value checks in def_use: %d const-test '
                                'consumers corpus-wide, %d adjudicable '
                                'value checks; 0x39 has NO adjudicable '
                                'pair in this corpus -- consistency-only '
                                'leg; 0x3c carries %d cmp0 const-test '
                                'consumers, the positive zero-write '
                                'corroboration)'
                                % (n_const_test,
                                   stats['value_adjudicable_sites'],
                                   n_3c_cmp0),
            'formulas': {k: dict(v) for k, v in FORMULAS.items()},
            'pins': {
                'corpus_sites.jsonl': PIN_SITES,
                'census_corpus.json': PIN_CENSUS,
                'census_map.json': PIN_CENSUS_MAP,
                'fuzz5_live.json': PIN_LIVE,
            },
            'coverage': {
                'universe_rows': stats['rows'],
                'census_map_only_rows': n_map_only,
                'rows_with_strict_sites': stats['rows_with_sites'],
                'strict_sites': stats['strict_sites'],
                'const_test_consumers': n_const_test,
                'value_adjudicable_sites':
                    stats['value_adjudicable_sites'],
                'value_mismatches': stats['value_mismatches'],
                'rows_39_with_adjudicable': sum(
                    1 for r in phase_rows
                    if r['key']['op'] == '0x39'
                    and r['def_use'].get('value_adjudicable')),
            },
            'cmp38_self': {
                'merged_semantics': 'cmp.w (0x38 sel=0, slaspec 4f4f7b3):'
                                    ' CMPRES = (RSlosrc == RTlosrc); '
                                    'consumers b.t/b.f cc=0x0a; cc0a '
                                    'writers: any 0x36 + 0x38 sel0',
                'insensitive_states': ['killed (cc0a writer first)',
                                       'no-consumer (latch never read)',
                                       'dead-branch consumer (noop / '
                                       'skip-noop)'],
                'fail_closed_note': 'non-strict (mask-only) sites are '
                                    'scanned with the same code and their '
                                    'raw readings count toward the '
                                    'aggregate (mask-only is never proof '
                                    'in either direction); the strict '
                                    'view is reported separately in the '
                                    'aggregate (strict_sites/'
                                    'strict_insensitive)',
                'linear_model_note': 'linear stream scan (no reachability'
                                     ' offline): a branch between the '
                                     'site and its linear consumer may '
                                     'divert execution; precedent: the '
                                     'h36/T4 def-use windows are linear '
                                     'too. A no-consumer reading is '
                                     'insensitive under this model.',
            },
            'ceiling': [
                '0x39: no adjudicable const-chain pair exists in this '
                'corpus (the single cmpC consumer has non-const '
                'provenance) -- the 0x39 static leg is consistency-only; '
                'positive lo-passthrough evidence remains live-only '
                '(double-live at lo11 0x000/0x7ff)',
                '0x3c: %d cmp0 const-test consumers (%d adjudicable '
                'match: proven rs const, consumer tests 0); no cmpC-'
                'nonzero adjudicable pair corroborates the competing '
                'H-3c-and-lo11 anywhere in the corpus'
                % (n_3c_cmp0, stats['value_adjudicable_sites']),
                'PCI/ACE bulk (0x39 %d / 0x3c %d strict sites outside '
                'MAIN): dataflow shapes only (read/clobber/dead/rd-zero) '
                '-- no semantic adjudication offline, rows stay '
                'consistency-silent-with-sites outside MAIN'
                % (sum(r['def_use'].get('sites', 0) for r in phase_rows
                       if r['key']['op'] == '0x39'
                       and r['key']['section'] != 'MAIN'),
                   sum(r['def_use'].get('sites', 0) for r in phase_rows
                       if r['key']['op'] == '0x3c'
                       and r['key']['section'] != 'MAIN')),
                'cmp38-self: the aggregate is the T8 rule input; the '
                'sensitive strict sites (live b.t cmpres consumers) are '
                'listed with coordinates in phases.A.cmp38_self.sites',
            ],
            'addressing_note': 'dc offsets only; no dc<->rt base '
                               'arithmetic needed (per-section param0 '
                               'bases live in corpus_sections.json)',
        },
        'phases': {
            'A': {
                'rows': phase_rows,
                'cmp38_self': sweep,
            },
        },
    }
    return doc


# ------------------------------------------------------------- phase B

def live_points(rec):
    """(rs, observed, vector_id) checkable points of a live record."""
    pts = []
    for o in rec.get('observations', []):
        val = o.get('observed')
        seed = o.get('operands_seed') or {}
        if val is None or 'rs' not in seed:
            continue
        pts.append((int(seed['rs'], 16), int(val, 16), o['vector_id']))
    return pts


def build_phase_b(a_doc):
    check_pin(HERE / 'fuzz5_live.json', PIN_LIVE)
    live = json.loads((HERE / 'fuzz5_live.json').read_text())

    def lkey(v):
        return json.dumps({'section': 'MAIN', 'op': v['op'],
                           'selector': {'lo11': v['selector']['lo11']}},
                          sort_keys=True)

    live_rows = {lkey(v): v for v in live['rows'].values()
                 if v['op'] in ('0x39', '0x3c')}

    rows = []
    join_stats = collections.Counter()
    obs_checked = 0
    for r in a_doc['phases']['A']['rows']:
        rec = dict(r)
        jkey = json.dumps(rec['key'], sort_keys=True)
        lrow = live_rows.get(jkey)
        op = int(rec['key']['op'], 16)
        lo11 = rec['key']['selector']['lo11']
        if lrow is None:
            status = 'silence'
            note = 'no live row for selector'
            n_chk = 0
        else:
            pts = live_points(lrow)
            n_chk = len(pts)
            obs_checked += n_chk
            bad = [vid for rs, want, vid in pts
                   if predict(op, lo11, rs) != want]
            um = lrow.get('unique_model')
            formula_id = FORMULAS[rec['key']['op']]['id']
            if bad:
                status = 'contradiction'
                note = 'candidate formula misses %d/%d observed values' \
                    % (len(bad), n_chk)
            elif n_chk == 0:
                status = 'silence'
                note = ('live %s (no captured values to join)'
                        % lrow['live_verdict'])
            elif lrow['live_verdict'] != 'unique' or not um:
                status = 'silence'
                note = ('live %s: all %d captured values agree with the '
                        'candidate but there is no unique model to join '
                        '(2-confirmation needs the unique-model leg)'
                        % (lrow['live_verdict'], n_chk))
            elif um != formula_id:
                status = 'contradiction'
                note = ('live unique model %s outside the candidate '
                        'family %s' % (um, formula_id))
            else:
                status = 'match'
                note = ('live unique model %s inside the candidate '
                        'family; agrees with all %d captured values'
                        % (um, n_chk))
        join_stats[status] += 1
        rec['live_join'] = {
            'status': status,
            'note': note,
            'live_verdict': lrow['live_verdict'] if lrow else None,
            'unique_model': lrow.get('unique_model') if lrow else None,
            'n_observations': len(lrow.get('observations', []))
            if lrow else 0,
            'n_checked': n_chk,
        }
        if status == 'contradiction':
            rec['conflict'] = True
            rec['merge_ready'] = False
        else:
            rec['merge_ready'] = bool(rec['static_verdict'] is not None
                                      and status == 'match')
        rows.append(rec)

    unmatched = sorted(set(live_rows) - {
        json.dumps(r['key'], sort_keys=True)
        for r in a_doc['phases']['A']['rows']})
    if unmatched:
        raise SystemExit('live rows outside the phase-A universe: %s'
                         % unmatched)

    # cmp38-self Phase B: join the sweep with the double-live record
    sweep = a_doc['phases']['A']['cmp38_self']
    agg = sweep['aggregate']
    sup = live.get('cmp38_self', {}).get('supports', [])
    double_live = len(sup) >= 2
    sensitive = [s for s in sweep['sites']
                 if not s['consumer_insensitive']]
    merge = bool(double_live and agg['formalizable'])
    if merge:
        concl = ('double-live AND all %d rs==rt sites consumer-'
                 'insensitive: the T8 sanctioned category '
                 '(merge.double_live_formalizable) applies'
                 % agg['rs_eq_rt_sites'])
    elif double_live:
        concl = ('double-live holds (both live supports cited) but the '
                 'sweep found %d consumer-sensitive site(s) (%d of them '
                 'strict code): a self->F carve-out changes the '
                 'decompiled control flow of those FW sites vs the '
                 'merged eq32 constructor -- NOT formalizable offline, '
                 'the T8 sanctioned category must NOT fire; residual '
                 '(live/owner resolution)'
                 % (len(sensitive),
                    agg['strict_sites'] - agg['strict_insensitive']))
    else:
        concl = ('live record does not carry two supports '
                 '(double-live broken)')

    ready = [r for r in rows if r['merge_ready']]
    a_doc['phases']['B'] = {
        'rows': rows,
        'join_stats': dict(sorted(join_stats.items())),
        'cmp38_self': {
            'aggregate': agg,
            'live_join': {
                'double_live': double_live,
                'supports': sup,
                'unique_model': live.get('cmp38_self', {}).get(
                    'unique_model'),
            },
            'sensitive_sites': [
                {'fw': s['fw'], 'section': s['section'],
                 'dc_offset': s['dc_offset'], 'word': s['word'],
                 'strict': s['strict'], 'state': s['state'],
                 'dist': s.get('dist'),
                 'polarity': s.get('polarity'),
                 'consumer_dc': s.get('consumer_dc')}
                for s in sensitive],
            'merge': merge,
            'conclusion': concl,
        },
    }
    a_doc['meta']['c_a4_summary'] = {
        'merge_candidate_rows': sorted(
            '%s/lo11=0x%03x' % (r['key']['op'], r['key']['selector']['lo11'])
            for r in ready),
        'merge_ready_note': 'advisory/derived flag; T8 decides by the '
                            'per-row contract (static verdict + unique '
                            'live model match + no conflict)',
        'observations_checked': obs_checked,
    }
    return a_doc


# ------------------------------------------------------------------- main

def write_doc(doc):
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + '\n')


def main():
    ap = argparse.ArgumentParser(
        description='isa-max A task-7: 0x39/0x3c formalization + '
                    'cmp38-self pre-sweep')
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
            print('CHECK PASS: rare_verdicts.json reproduces '
                  '(%d phase-A rows, cmp38-self %s)'
                  % (len(fresh['phases']['A']['rows']),
                     fresh['phases']['A']['cmp38_self']['aggregate']))
            return
        raise SystemExit('CHECK FAIL: rare_verdicts.json drift')

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
        cov = doc['meta']['coverage']
        print('phase A: %d rows, %d with strict sites, %d strict sites, '
              'value-adjudicable %d, mismatches %d'
              % (cov['universe_rows'], cov['rows_with_strict_sites'],
                 cov['strict_sites'], cov['value_adjudicable_sites'],
                 cov['value_mismatches']))
        print('cmp38-self: %s' % doc['phases']['A']['cmp38_self']
              ['aggregate'])
        print('wrote %s' % OUT)
        return

    if args.phase_b:
        doc = json.loads(OUT.read_text())
        if 'A' not in doc.get('phases', {}):
            raise SystemExit('no Phase A in artifact; run --phase-a first')
        doc = build_phase_b(doc)
        write_doc(doc)
        print('phase B: join %s; merge_ready %s'
              % (doc['phases']['B']['join_stats'],
                 doc['meta']['c_a4_summary']['merge_candidate_rows']))
        print('cmp38-self: merge=%s; %s'
              % (doc['phases']['B']['cmp38_self']['merge'],
                 doc['phases']['B']['cmp38_self']['conclusion']))
        print('wrote %s' % OUT)
        return

    ap.print_help()


if __name__ == '__main__':
    main()
