#!/usr/bin/env python3
"""isa-max A task-6 (C-A.3): H-16-shr reformulation (width 32 + imm=0
carve-out) with ALL 0x16 verdicts recomputed from RAW def-use contexts.

Conflict being resolved (irisc-fuzz5 report, select_merges.json excluded
op-0x16 entry): the old static binding H-16-shr `rd = rs >> (imm & 0x3f)`
(64-bit shift right) covers the whole lo11 axis including imm=000
(has-sites, 5 sites in 4030 MAIN), but live at lo11=000 is unique
H-16-zero (rd=0 on seeded rs=0x80000000a5a5f0f0 != rs>>0). Constructor
narrowing imm11!=0 was REJECTED (the static binding covers the whole
axis); the reformulation keeps the constructor continuous:

    rd = 0                             if lo11 == 0        (imm=0 carve-out)
    rd = 0                             if (lo11 & 0x3f) >= 32   (width 32)
    rd = zext32(rs) >> (lo11 & 0x3f)   otherwise (s == 0, lo11 != 0
                                       -> zext32(rs) passthrough)

Phase A (NEVER reads fuzz5_live.json): row universe = the 421 census
0x16 rows (census_corpus all sections; the census_map MAIN-39 set is a
subset); per row, raw def-use over every strict corpus site of the
(section, lo11): rs provenance (imm-chain consts incl. setN-from-zero
chunk positions per the slaspec), rd consumer classification
(const-test: pred0/cmp0/cmpC/ztest -- the consumer sees a FIXED constant,
the value does not flow onward; carry: store/read; dead: clobber/none;
rd-zero: result discarded), and a const value check when both legs are
available (proven rs const x const-test consumer: the FW tests exactly
the value the reformulated formula computes -> 'match', any other
constant -> 'mismatch' = hard contradiction). Per-row verdict:
'H-16-shr32u0-consistent' iff strict sites exist and no value mismatch;
silent when no strict sites; conflict on a mismatch.

Phase B (separate run): join fuzz5_live.json op16 rows -- the
reformulated prediction is checked against EVERY captured observation
value; the old imm=000 conflict row must now MATCH (rd=0 is inside the
family); merge_ready = static verdict present AND live match. The
imm=0 dossier (meta) fixes the def-use of the 5 imm=000 sites of 4030
MAIN with coordinates: the two strict code sites consume rd by const
tests only (consumers see 0, not rs), the three data-region words are
mask-only (never proof).

Outputs: h16_verdicts.json next to this script (committed). `--phase-a`
writes/refreshes phases.A; `--phase-b` requires phases.A; `--check`
recomputes both and diffs byte-for-byte.
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

OUT = HERE / 'h16_verdicts.json'

# committed inputs are md5-pinned: refuse silent drift
PIN_SITES = '18918f8f07cc7716b783df7a1934ee7b'
PIN_CENSUS = '78b1f6964f508bc654c39ee6add28d1d'
PIN_CENSUS_MAP = 'c6b8dbfaa4ca42f77a5d79e705cc1a75'
PIN_LIVE = '42358ef7acab628637cd0c7c2925ad04'

# def-use parameters (windows follow h36_grind/p34_model precedents)
PROV_BACK = 24             # words scanned back for operand provenance
USE_FWD = 12               # words scanned forward for the rd consumer
SITE_SAMPLES = 3           # basis site samples per row

# register-writer decode helpers (opcode classes per slaspec)
NON_WRITERS = frozenset((0x13, 0x1a, 0x1b, 0x1c, 0x1e, 0x25,
                         0x28, 0x29, 0x2a, 0x2b))
STORE_OPS = frozenset((0x13, 0x1a, 0x1b, 0x1c, 0x1e))
SET_OPS = frozenset((0x06, 0x07, 0x08, 0x09))
ADDI_OPS = frozenset((0x00, 0x01, 0x02, 0x03))
# setN chunk positions per iRISC.slaspec:
#   set0 (0x06) bits 63:48, set1 (0x07) bits 47:32,
#   set3 (0x08) bits 15:0,  set2 (0x09) bits 31:16
SET_POS = {0x06: 48, 0x07: 32, 0x08: 0, 0x09: 16}

U64 = 0xFFFFFFFFFFFFFFFF


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


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def s64(v):
    v &= U64
    return v - 0x10000000000000000 if v & (1 << 63) else v


# ---------------------------------------------------------------- formula

def predict(lo11, rs):
    """Reformulated H-16: width 32 + imm=0 carve-out."""
    if lo11 == 0:
        return 0
    s = lo11 & 0x3f
    if s >= 32:
        return 0
    return (rs & 0xFFFFFFFF) >> s


def predict_old(lo11, rs):
    """Old H-16-shr (rejected): 64-bit shift right, whole axis."""
    return (rs >> (lo11 & 0x3f)) & U64


def predicted_class(lo11):
    if lo11 == 0:
        return 'imm0-carveout'
    s = lo11 & 0x3f
    if s >= 32:
        return 'width32-zero'
    if s == 0:
        return 'pass32'
    return 'shr32'


FORMULA = {
    'width': 32,
    'imm0_carveout': 'rd = 0 when lo11 == 0: the imm=0 point writes a '
                     'constant zero (live lo11=000 rd=0 on seeded rs); '
                     'consumers see 0, not rs',
    'shift': 'rd = zext32(rs) >> (lo11 & 0x3f); result 0 when '
             '(lo11 & 0x3f) >= 32 (width 32); lo11 != 0 with shift-mask '
             '0 -> zext32(rs)',
}


# ---------------------------------------------------------------- def-use

def prov_value(words, i, reg, back=PROV_BACK):
    """Last-def provenance of `reg` before word i: (kind, value).

    Full-value consts only: setN-from-zero (clean chunk write, value =
    imm16 << pos) and addi-from-zero (sign-extended imm16). setN with
    rs==rd is an OR into the old value (partial write) -> 'other'.
    """
    if reg == 0:
        return ('zero-reg', 0)
    for j in range(i - 1, max(-1, i - 1 - back), -1):
        w = words[j]
        op = w >> 26
        if op in NON_WRITERS:
            continue
        if rd_of(w) == reg:
            if op in SET_OPS and rs_of(w) == 0:
                return ('imm', ((w & 0xffff) << SET_POS[op]) & U64)
            if op == 0x00 and rs_of(w) == 0:
                return ('imm', s64(s16(w & 0xffff)) & U64)
            if op in ADDI_OPS and rs_of(w) == 0:
                return ('imm-other', None)
            return ('other', None)
    return ('none', None)


def rd_consumer(words, i, rd, fwd=USE_FWD):
    """First consumer of `rd` after word i (raw def-use classification).

    Returns (consumer, detail, j). const-test forms (pred0/cmp0/cmpC/
    ztest) read rd only inside a comparison against a FIXED constant:
    the consumer sees a fixed value (0 under the carve-out / the shifted
    constant), a data flow of rs never continues through them. carry
    forms forward the value (store/read). dead forms never read it."""
    if rd == 0:
        return ('rd-zero', None, None)
    for j in range(i + 1, min(len(words), i + 1 + fwd)):
        w = words[j]
        op = w >> 26
        if op in STORE_OPS:
            if rt_of(w) == rd or rs_of(w) == rd:
                return ('store', None, j)
            continue
        rsj = rs_of(w)
        rdj = rd_of(w)
        rtj = rt_of(w)
        if op in (0x2a, 0x2b):                    # b.bset/b.bclr bit test
            if rsj == rd:
                return ('bittest',
                        'bit=%d:%s' % ((w >> 16) & 0x1f,
                                       'set' if op == 0x2a else 'clr'), j)
            continue
        if op in NON_WRITERS:
            continue
        if op == 0x05 and rsj == rd:                    # subsi rd,C
            c = w & 0xffff
            return ('cmp0' if c == 0 else 'cmpC', c, j)
        if op == 0x36 and rsj == rd:                    # 0x36 producer
            lo11 = w & 0x7ff
            return ('pred0', 'f5=0x%02x_i6=0x%02x'
                    % (lo11 & 0x1f, (lo11 >> 5) & 0x3f), j)
        if op == 0x0b and rsj == rd:                    # ands: Z=(rd&M)==0
            return ('ztest', '0x%x' % (w & 0xffff), j)
        if rsj == rd or rtj == rd:
            return ('read', 'op=0x%02x' % op, j)
        if rdj == rd:
            return ('clobber', 'op=0x%02x' % op, j)
    return ('none', None, None)


CONSUMER_CLASS = {
    'pred0': 'const-test', 'cmp0': 'const-test', 'cmpC': 'const-test',
    'ztest': 'const-test', 'bittest': 'const-test',
    'store': 'carry', 'read': 'carry',
    'clobber': 'dead', 'none': 'dead',
    'rd-zero': 'rd-zero',
}


def site_facts(words, i):
    """Raw def-use facts of the 0x16 site at word i."""
    w = words[i]
    rs = rs_of(w)
    rd = rd_of(w)
    lo11 = w & 0x7ff
    prov, val = prov_value(words, i, rs)
    consumer, detail, cj = rd_consumer(words, i, rd)
    facts = {
        'rs': rs,
        'rd': rd,
        'rs_prov': prov,
        'rs_value': val,
        'consumer': consumer,
        'consumer_detail': detail,
        'consumer_class': CONSUMER_CLASS[consumer],
        'consumer_dist': (cj - i) if cj is not None else None,
        'cmp_const': detail if consumer in ('cmp0', 'cmpC') else None,
        'value_check': None,
        'value_expected': None,
    }
    # const value check: proven rs const x const-test consumer -> does
    # the FW test exactly the value the reformulated formula computes?
    if val is not None and consumer == 'cmp0':
        facts['value_expected'] = predict(lo11, val)
        facts['value_check'] = ('match' if predict(lo11, val) == 0
                                else 'mismatch')
    elif val is not None and consumer == 'cmpC':
        facts['value_expected'] = predict(lo11, val)
        facts['value_check'] = ('match' if predict(lo11, val) == detail
                                else 'mismatch')
    elif val is not None and consumer == 'ztest' \
            and isinstance(detail, str):
        mask = int(detail, 16)
        facts['value_expected'] = predict(lo11, val) & mask
        facts['value_check'] = ('match'
                                if predict(lo11, val) & mask == 0
                                else 'mismatch')
    elif val is not None and consumer == 'pred0':
        f5 = 0
        if isinstance(detail, str) and detail.startswith('f5='):
            f5 = int(detail.split('_')[0].split('=')[1], 16)
        facts['value_expected'] = predict(lo11, val) & ((1 << f5) - 1)
        facts['value_check'] = ('match'
                                if predict(lo11, val) & ((1 << f5) - 1) == 0
                                else 'mismatch')
    return facts


def row_verdict(lo11, facts):
    """Per-row verdict from raw site facts (recompute path; no live).

    'H-16-shr32u0-consistent' iff strict sites exist and no value-check
    mismatch; silent (None) when no sites; conflict on a mismatch.
    """
    if not facts:
        return {'static_verdict': None, 'unique': False,
                'conflict': False,
                'reason': 'no strict sites for this selector '
                          '(static leg silent)'}
    bad = [f for f in facts if f.get('value_check') == 'mismatch']
    if bad:
        return {'static_verdict': None, 'unique': False, 'conflict': True,
                'reason': 'const value check mismatch at %d site(s): the '
                          'FW tests a constant the reformulated formula '
                          'does not compute' % len(bad)}
    return {'static_verdict': 'H-16-shr32u0-consistent', 'unique': True,
            'conflict': False}


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


def load_sites():
    """ALL 0x16 sites of corpus_sites.jsonl grouped by (section, lo11),
    strict flagged (non-strict sites stay in the imm=0 dossier only)."""
    path = HERE / 'corpus_sites.jsonl'
    check_pin(path, PIN_SITES)
    sites = collections.defaultdict(list)
    for line in path.read_text().splitlines():
        s = json.loads(line)
        w = int(s['word'], 16)
        if w >> 26 != 0x16:
            continue
        rec = {'fw': s['fw'], 'section': s['section'],
               'dc_offset': s['dc_offset'], 'word': s['word'],
               'strict': s['strict'],
               '_idx': int(s['dc_offset'], 16) // 4, '_w': w}
        sites[(s['section'], w & 0x7ff)].append(rec)
    for lst in sites.values():
        lst.sort(key=lambda s: (s['fw'], s['dc_offset']))
    return sites


def imm0_dossier_sites():
    """Every imm=000 site across the corpus (strict + non-strict), for
    the meta dossier: what is written/read, fixed with coordinates."""
    out = []
    for line in (HERE / 'corpus_sites.jsonl').read_text().splitlines():
        s = json.loads(line)
        w = int(s['word'], 16)
        if w >> 26 == 0x16 and (w & 0x7ff) == 0:
            out.append({'fw': s['fw'], 'section': s['section'],
                        'dc_offset': s['dc_offset'], 'word': s['word'],
                        'strict': s['strict'],
                        'rd': rd_of(w), 'rs': rs_of(w)})
    out.sort(key=lambda s: (s['fw'], s['section'], s['dc_offset']))
    return out


# ------------------------------------------------------------- phase A

def build_phase_a():
    check_pin(HERE / 'census_corpus.json', PIN_CENSUS)
    census = json.loads((HERE / 'census_corpus.json').read_text())
    cm_path = REPO / 'scripts/probes/cx5-fuzz5/census_map.json'
    check_pin(cm_path, PIN_CENSUS_MAP)
    census_map = json.loads(cm_path.read_text())

    # universe: census 0x16 rows of BOTH maps (lossless: the census_map
    # MAIN-39 set is a subset of the census_corpus MAIN rows)
    rows = {}
    for r in census['rows']:
        if r['key']['op'] != '0x16':
            continue
        key = {'section': r['key']['section'], 'op': '0x16',
               'selector': {'lo11': r['key']['selector']['lo11']}}
        rows[json.dumps(key, sort_keys=True)] = key
    n_map_only = 0
    for r in census_map['rows']:
        if r.get('op') != '0x16':
            continue
        key = {'section': 'MAIN', 'op': '0x16',
               'selector': {'lo11': r['selector']['lo11']}}
        jkey = json.dumps(key, sort_keys=True)
        if jkey not in rows:
            rows[jkey] = key
            n_map_only += 1

    sections = load_sections()
    sites = load_sites()

    phase_rows = []
    stats = collections.Counter()
    for jkey in sorted(rows):
        key = rows[jkey]
        section = key['section']
        lo11 = key['selector']['lo11']
        row_sites = [s for s in sites.get((section, lo11), [])
                     if s['strict']]
        facts = []
        agg = collections.Counter()
        for s in row_sites:
            words = sections.get((s['fw'], s['section']))
            if words is None or s['_idx'] >= len(words):
                continue
            f = site_facts(words, s['_idx'])
            facts.append((s, f))
            agg['sites'] += 1
            agg['rs_prov:' + f['rs_prov']] += 1
            agg['consumer:' + f['consumer']] += 1
            agg['class:' + f['consumer_class']] += 1
            if f['value_check'] is not None:
                agg['value_adjudicable'] += 1
                agg['value_check:' + f['value_check']] += 1
        v = row_verdict(lo11, [f for _s, f in facts])
        stats['rows'] += 1
        stats['rows_with_sites'] += 1 if facts else 0
        stats['value_adjudicable_sites'] += agg.get('value_adjudicable', 0)
        stats['value_mismatches'] += agg.get('value_check:mismatch', 0)
        row = {
            'key': key,
            'formula': dict(FORMULA),
            'predicted_class': predicted_class(lo11),
            'static_verdict': v['static_verdict'],
            'unique': v['unique'],
            'basis': [{
                'type': 'site',
                'site': {'fw': s['fw'], 'section': s['section'],
                         'dc_offset': s['dc_offset'], 'word': s['word']},
                'def_use': {k: f[k] for k in
                            ('rs', 'rd', 'rs_prov', 'rs_value',
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

    # imm=0 dossier: def-use of every imm=000 site, with the 5 sites of
    # 4030 MAIN called out (the letter of the C-A.3 brief)
    dossier = []
    for s in imm0_dossier_sites():
        entry = {'fw': s['fw'], 'section': s['section'],
                 'dc_offset': s['dc_offset'], 'word': s['word'],
                 'strict': s['strict'],
                 'written': {'rd': s['rd']},
                 'read': {'rs': s['rs']}}
        if s['strict']:
            words = sections.get((s['fw'], s['section']))
            idx = int(s['dc_offset'], 16) // 4
            if words is not None and idx < len(words):
                f = site_facts(words, idx)
                entry['def_use'] = {
                    'consumer': f['consumer'],
                    'consumer_detail': f['consumer_detail'],
                    'consumer_class': f['consumer_class'],
                    'rs_prov': f['rs_prov'],
                }
                entry['read'] = {'rs': f['rs'],
                                 'consumer': f['consumer']}
            else:
                entry['def_use'] = {'consumer_class': 'unresolved'}
        else:
            entry['def_use'] = {'consumer_class': 'data-region'}
        dossier.append(entry)
    n_4030 = sum(1 for s in dossier if s['fw'] == '4030'
                 and s['section'] == 'MAIN')

    # corpus-wide aggregate for the meta coverage (computed, not fixed)
    n_const_test = sum(r['def_use'].get('class:const-test', 0)
                       for r in phase_rows)
    n_zero_const_test = 0
    for r in phase_rows:
        if r['predicted_class'] in ('imm0-carveout', 'width32-zero'):
            n_zero_const_test += r['def_use'].get('class:const-test', 0)

    doc = {
        'meta': {
            'cycle': 'isa-max-a task-6 (C-A.3 H-16-shr reformulation: '
                     'width 32 + imm=0 carve-out)',
            'method': 'ALL 0x16 verdicts recomputed from RAW def-use '
                      'contexts over the strict corpus sites (rs '
                      'provenance incl. setN-from-zero chunk consts, rd '
                      'consumer classification, const value check); '
                      'phase A never reads fuzz5_live.json',
            'verdict_rule': "H-16-shr32u0-consistent iff the row has "
                            "strict sites and no const value-check "
                            "mismatch; silent (None) when no strict "
                            "sites; conflict=True on a mismatch (the FW "
                            "tests a constant the reformulated formula "
                            "does not compute)",
            'static_rule_note': "H-16-shr32u0-consistent means NO raw "
                                "def-use contradiction was detected -- "
                                "the absence of a contradiction signal, "
                                "not positive corroboration of the "
                                "shifted value; the positive static "
                                "evidence is counted separately as "
                                "const-test consumers (class:const-test "
                                "in def_use; %d corpus-wide, %d of them "
                                "on predicted-zero classes imm0/width32)"
                                % (n_const_test, n_zero_const_test),
            'formula': dict(FORMULA),
            'old_formula_note': 'rejected H-16-shr `rd = rs >> '
                                '(imm & 0x3f)` (64-bit): diverges from '
                                'the reformulation at lo11=0 (pass-rs '
                                'degenerate vs rd=0) and at shift>=32 '
                                'with hi32-set rs (e.g. predict_old('
                                '0x28, 0x80000000a5a5f0f0) = 0x800000 '
                                'vs 0)',
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
                'strict_sites': sum(r['def_use'].get('sites', 0)
                                    for r in phase_rows),
                'const_test_consumers': n_const_test,
                'const_test_on_predicted_zero': n_zero_const_test,
                'value_adjudicable_sites':
                    stats['value_adjudicable_sites'],
                'value_mismatches': stats['value_mismatches'],
            },
            'imm0_dossier': {
                'semantics': 'imm=0 carve-out: rd = 0 (constant zero); '
                             'consumers of rd at the imm=000 sites see 0, '
                             'not rs',
                'note_sites_4030': n_4030,
                'sites_4030_note': 'the two strict 4030 MAIN code sites '
                                   '(0x218858: 0x36 f5=2 rs-vs-zero '
                                   'predicate + b.t cc0a; 0x218c74: '
                                   'subsi r4,r4,1 + b.f cc0) consume rd '
                                   'by const tests only; 0x3936d0/d8/700 '
                                   'are data-region words (mask-only, '
                                   'never proof)',
                'sites': dossier,
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
        return json.dumps({'section': 'MAIN', 'op': '0x16',
                           'selector': {'lo11': v['selector']['lo11']}},
                          sort_keys=True)

    live_rows = {lkey(v): v for v in live['rows'].values()
                 if v['op'] == '0x16'}

    rows = []
    join_stats = collections.Counter()
    obs_checked = 0
    for r in a_doc['phases']['A']['rows']:
        rec = dict(r)
        jkey = json.dumps(rec['key'], sort_keys=True)
        lrow = live_rows.get(jkey)
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
                   if predict(lo11, rs) != want]
            if n_chk == 0:
                status = 'silence'
                note = 'live row without captured values'
            elif bad:
                status = 'contradiction'
                note = 'reformulated formula misses %d/%d observed ' \
                       'values' % (len(bad), n_chk)
            else:
                status = 'match'
                note = 'reformulated formula agrees with all %d ' \
                       'captured values' % n_chk
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
        live_conflict = status == 'contradiction'
        if live_conflict:
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

    # the C-A.3 conflict-resolution gate: the imm=000 row that blocked
    # the old H-16-shr merge must now MATCH the reformulated formula
    k000 = json.dumps({'section': 'MAIN', 'op': '0x16',
                       'selector': {'lo11': 0}}, sort_keys=True)
    by_key = {json.dumps(r['key'], sort_keys=True): r for r in rows}
    imm0_match = by_key[k000]['live_join']['status'] == 'match'
    n_match = sum(1 for r in rows if r['live_join']['status'] == 'match')
    outcome = 'resolved' if (imm0_match and n_match == 4
                             and not by_key[k000]['conflict']) \
        else 'remains'
    ready = [r for r in rows if r['merge_ready']]
    a_doc['phases']['B'] = {
        'rows': rows,
        'join_stats': dict(sorted(join_stats.items())),
    }
    a_doc['meta'].update({
        'h16_conflict_resolution': {
            'old_formula': 'H-16-shr `rd = rs >> (imm & 0x3f)` '
                           '(64-bit; select_merges.json excluded op-0x16 '
                           'entry, flag conflict)',
            'conflict': 'op16_lo11=000: live unique H-16-zero (rd=0 on '
                        'seeded rs=0x80000000a5a5f0f0) vs the old '
                        'pass-rs degenerate at shift 0; constructor '
                        'narrowing imm11!=0 was rejected (static binding '
                        'covers the whole axis)',
            'reformulated': 'width 32 + imm=0 carve-out (this artifact)',
            'imm0_row_status': by_key[k000]['live_join']['status'],
            'live_rows_matched': n_match,
            'observations_checked': obs_checked,
            'outcome': outcome,
            'merge_ready_rows': sorted(
                r['key']['selector']['lo11'] for r in ready),
        },
    })
    return a_doc


# ------------------------------------------------------------------- main

def write_doc(doc):
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + '\n')


def main():
    ap = argparse.ArgumentParser(
        description='isa-max A task-6: H-16-shr reformulation '
                    '(width 32 + imm=0 carve-out)')
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
            print('CHECK PASS: h16_verdicts.json reproduces '
                  '(%d phase-A rows)' % len(fresh['phases']['A']['rows']))
            return
        raise SystemExit('CHECK FAIL: h16_verdicts.json drift')

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
              'value-adjudicable %d'
              % (cov['universe_rows'], cov['rows_with_strict_sites'],
                 cov['strict_sites'], cov['value_adjudicable_sites']))
        print('wrote %s' % OUT)
        return

    if args.phase_b:
        doc = json.loads(OUT.read_text())
        if 'A' not in doc.get('phases', {}):
            raise SystemExit('no Phase A in artifact; run --phase-a first')
        doc = build_phase_b(doc)
        write_doc(doc)
        cr = doc['meta']['h16_conflict_resolution']
        print('phase B: join %s; conflict outcome %s; merge_ready %s'
              % (doc['phases']['B']['join_stats'], cr['outcome'],
                 [hex(x) for x in cr['merge_ready_rows']]))
        print('wrote %s' % OUT)
        return

    ap.print_help()


if __name__ == '__main__':
    main()
