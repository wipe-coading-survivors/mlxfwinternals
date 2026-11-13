#!/usr/bin/env python3
"""isa-max A task-4 (C-A.1): 0x36 predicate-producer static support grind
over the expanded corpus (offline; two-phase, anti-circular).

Phase A (def-use -> static verdicts; NEVER reads fuzz5_live.json):
- def-use framework over corpus_sites.jsonl strict 0x36 sites: linear
  cc0a-consumer window (first b.t/b.f cc=0x0a before any cc-writer killer
  -- another 0x36 or a cmp.w 0x38 sel0), operand shapes, imm-chain
  provenance, dead-branch consumer forms (noop / skip-noop), const-prop
  operand sites;
- directed Rosetta: every strict 0x36 site is aligned into the
  old-compiler binaries (1619 primary; LX1900/CX6DX/8008 secondary) with
  a const-fingerprint aligner (>=3 matching 16-bit anchors at a common
  delta +-2 inside a +-20-word window); at the aligned position a
  position-strict known-op idiom classifier extracts the predicate idiom
  the old compiler used for the same source comparison (eq family:
  ands/and/and.hi+ztest, subsi-vs-const, subs reg-eq; ord family:
  sub/subi feeding a b.cc3/b.cc4 consumer);
- per-axis (f5 x form) programmatic verdict assignment: H-36-eq-usage iff
  eq share >= EQ_SHARE_MIN and ord share <= ORD_SHARE_MAX over >=
  MIN_CLASSIFIED deduplicated pairs; a secondary family above the noise
  gate marks the axis conflict (mixed usage), verdict stays null.

  The letter-of-the-brief Rosetta leg (1619's own strict 0x36 sites) is
  empty: both 1619 code-mask 0x36 sites are non-strict data-region words
  (documented in the journal; Global Constraints: mask-only is never
  proof). The directed alignment above is the productive reading of the
  same cross-version method (WP-1 bclr precedent, direction reversed).

Phase B (join with fuzz5_live.json; separate run, separate artifact):
- per-row live_join: match (live unique_model inside the static eq
  family), conflict (live unique model outside the family, e.g. H-V
  against eq-shaped FW usage), silence (unobserved/multi/rogue/div or a
  section without live coverage);
- merge_ready axes: static unique AND live unique_model matched;
- C-A.1 summary: (a) axes closed by static support, (b) structural
  ceiling checklist.

Outputs: h36_verdicts.json next to this script (committed). `--phase-a`
writes/refreshes phases.A only; `--phase-b` requires phases.A and writes
phases.B; `--check` recomputes both and diffs byte-for-byte.
"""
import argparse
import bisect
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

OUT = HERE / 'h36_verdicts.json'

# committed inputs are md5-pinned: refuse silent drift
PIN_SITES = '18918f8f07cc7716b783df7a1934ee7b'
PIN_CENSUS = '78b1f6964f508bc654c39ee6add28d1d'
PIN_CENSUS_MAP = 'c6b8dbfaa4ca42f77a5d79e705cc1a75'
PIN_LIVE = '42358ef7acab628637cd0c7c2925ad04'

# def-use parameters
CONSUMER_WINDOW = 8        # words scanned after the producer
PROV_BACK = 24             # words scanned back for operand provenance
# verdict assignment thresholds (documented in artifact meta)
EQ_SHARE_MIN = 0.90
ORD_SHARE_MAX = 0.05
MIN_CLASSIFIED = 5
ORD_CONFLICT_MIN = 3       # ord pairs that turn a noisy axis into mixed

# Rosetta alignment parameters
ALIGN_WIN = 20             # +- words for the const fingerprint
ANCHORS = 4                # rarest anchor candidates tried
TOL = 2                    # anchor delta tolerance (words)
MIN_ANCHOR_MATCH = 3       # matching consts required

# live models inside the static eq-usage family (Phase B join): the
# static claim is the eq IDIOM (masked zero-test / const-eq / reg-eq with
# the consumer choosing polarity), so negated-eq live models are inside
# the family; H-V (never fires) is outside by construction
EQ_FAMILY_MODELS = ('H-eq32', 'H-eq16', 'H-ne32', 'H-eq32i', 'H-ne32i')

# register-writer decode helpers
BR_OPS = (0x25, 0x28, 0x29, 0x2a, 0x2b)
NON_WRITERS = frozenset((0x13, 0x1a, 0x1b, 0x1c, 0x1e) + BR_OPS)
SET_OPS = frozenset((0x06, 0x07, 0x08, 0x09))
ADDI_OPS = frozenset((0x00, 0x01, 0x02, 0x03))


def md5_of(path):
    return hashlib.md5(Path(path).read_bytes()).hexdigest()


def check_pin(path, pin):
    got = md5_of(path)
    if got != pin:
        raise SystemExit('input drift %s: md5 %s != pin %s'
                         % (path, got, pin))


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def rd_of(w):
    return (w >> 16) & 0x1f


def rs_of(w):
    return (w >> 21) & 0x1f


def rt_of(w):
    return (w >> 11) & 0x1f


# ---------------------------------------------------------------- def-use

def provenance(words, i, reg, back=PROV_BACK):
    """Last def of `reg` before word i: (kind, delta, word-hex).

    kind: 'imm' (set0..3, or addi/addi.hi from zero), 'other' (any other
    register writer), 'none' (no def inside the window)."""
    if reg == 0:
        return ('zero-reg', 0, '0x0')
    for j in range(i - 1, max(-1, i - 1 - back), -1):
        w = words[j]
        op = w >> 26
        if op in NON_WRITERS:
            continue
        if rd_of(w) == reg:
            if op in SET_OPS:
                return ('imm', j - i, '0x%08x' % w)
            if op in ADDI_OPS and rs_of(w) == 0:
                return ('imm', j - i, '0x%08x' % w)
            return ('other', j - i, '0x%08x' % w)
    return ('none', 0, '0x0')


def consumer_of(words, i, window=CONSUMER_WINDOW):
    """First cc0a consumer before any cc-writer killer.

    Returns (j, polarity) or ('killed', killer) or None."""
    for j in range(i + 1, min(len(words), i + 1 + window)):
        w = words[j]
        op = w >> 26
        if op in (0x28, 0x29) and ((w >> 16) & 0x1f) == 0x0a:
            return (j, 't' if op == 0x28 else 'f')
        if op == 0x36:
            return ('killed', '0x36')
        if op == 0x38 and rd_of(w) == 0:
            return ('killed', 'cmp.w')
    return None


def s24(v):
    v &= 0xffffff
    return v - 0x1000000 if v & 0x800000 else v


def is_dead_branch(words, j):
    """Structurally dead cc0a consumer: noop branch (target == the
    instruction right after the branch) or skip-noop (target is a jump
    back to that same instruction)."""
    w = words[j]
    tgt = j + s16(w)
    fall = j + 1
    if tgt == fall:
        return True
    if 0 <= tgt < len(words):
        tw = words[tgt]
        if tw >> 26 == 0x25 and tgt + s24(tw) == fall:
            return True
    return False


def defuse_context(words, i, window=CONSUMER_WINDOW):
    """Full def-use context of the 0x36 producer at word i."""
    w = words[i]
    lo11 = w & 0x7ff
    f5 = lo11 & 0x1f
    i6 = (lo11 >> 5) & 0x3f
    rs = rs_of(w)
    rt = rt_of(w)
    if i6 != 0:
        shape = 'imm'
    elif rt == 0:
        shape = 'rs-vs-zero'
    elif rs == rt:
        shape = 'self'
    else:
        shape = 'rs-vs-rt'
    prov_rs = provenance(words, i, rs)
    prov_rt = provenance(words, i, rt)
    const_both = (prov_rs[0] == 'imm'
                  and prov_rt[0] in ('imm', 'zero-reg'))
    ctx = {
        'state': 'no-consumer',
        'polarity': None,
        'dist': None,
        'killed_by': None,
        'dead_branch': False,
        'shape': shape,
        'const_both': const_both,
        'prov_rs': prov_rs,
        'prov_rt': prov_rt,
    }
    got = consumer_of(words, i, window)
    if got is None:
        return ctx
    if got[0] == 'killed':
        ctx['state'] = 'killed'
        ctx['killed_by'] = got[1]
        return ctx
    j, pol = got
    ctx['state'] = 'consumer'
    ctx['polarity'] = pol
    ctx['dist'] = j - i
    ctx['dead_branch'] = is_dead_branch(words, j)
    return ctx


# ------------------------------------------------------- Rosetta classifier

# ops that overwrite Z between a setter and its flag consumer
Z_CLOBBER_OPS = frozenset((0x04, 0x05, 0x0b))
Z_CLOBBER_ALU_F = frozenset((0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b))


def classify_at(words, pi):
    """Position-strict known-op idiom candidates at the aligned position.

    The compare sequence of the old compiler must START within
    [pi-2, pi+3]. Returns [(family, detail, setter_j)] with family
    'eq'/'ord'; the candidate counts only if a matching flag consumer
    follows within 4 words (b.cc0 for eq, b.cc3/b.cc4 for ord) with no
    intervening Z-clobber."""
    out = []
    for j in range(max(0, pi - 2), min(len(words), pi + 4)):
        w = words[j]
        op = w >> 26
        fam = detail = None
        if op == 0x0b:                                   # ands: Z=(rs&M)==0
            fam, detail = 'eq', 'ztest:0x%x' % (w & 0xffff)
        elif op == 0x05:                                 # subsi: Z=(rs==C)
            c = w & 0xffff
            prep = ''
            if j - 1 >= 0 and rd_of(words[j - 1]) == rs_of(w):
                wp = words[j - 1]
                opp = wp >> 26
                if opp == 0x0b:
                    prep = '/ands:0x%x' % (wp & 0xffff)
                elif opp == 0x0a:
                    prep = '/and:0x%x' % (wp & 0xffff)
                elif opp == 0x0d:
                    prep = '/andhi:0x%x' % ((wp & 0xffff) << 16)
                elif opp == 0x0e:
                    prep = '/xor'
                elif opp in (0x83, 0x8a):
                    prep = '/shr:%d' % ((wp >> 11) & 0x1f)
            fam, detail = 'eq', 'subsi0x%x%s' % (c, prep)
        elif op == 0x3f and (w & 0x1ff) == 5:            # subs: Z=(rs==rt)
            fam, detail = 'eq', 'sub-regs'
        elif op == 0x3f and (w & 0x1ff) == 4:            # sub (ordering)
            fam, detail = 'ord', 'sub'
        elif op == 0x04:                                 # subi (ordering)
            fam, detail = 'ord', 'subi:0x%x' % (w & 0xffff)
        if fam is None:
            continue
        ccs = (0x0,) if fam == 'eq' else (0x3, 0x4)
        for k in range(j + 1, min(len(words), j + 5)):
            wk = words[k]
            opk = wk >> 26
            if opk == 0x25:
                break
            if opk in (0x28, 0x29) and ((wk >> 16) & 0x1f) in ccs:
                out.append((fam, detail, j))
                break
            if opk in Z_CLOBBER_OPS or (
                    opk == 0x3f and (wk & 0x1ff) in Z_CLOBBER_ALU_F):
                break
    return out


def assign_axis_verdict(pairs):
    """Per-axis verdict from classified Rosetta pairs.

    H-36-eq-usage iff >= MIN_CLASSIFIED pairs, eq share >= EQ_SHARE_MIN,
    ord share <= ORD_SHARE_MAX. A secondary ord cluster >= ORD_CONFLICT_MIN
    pairs above the ord gate marks the axis mixed (conflict, no verdict).
    """
    n = len(pairs)
    n_eq = sum(1 for p in pairs if p['fam'] == 'eq')
    n_ord = sum(1 for p in pairs if p['fam'] == 'ord')
    conflict = (n >= MIN_CLASSIFIED and n_ord >= ORD_CONFLICT_MIN
                and n_ord / n > ORD_SHARE_MAX)
    verdict = None
    unique = False
    if (n >= MIN_CLASSIFIED and n_ord <= ORD_SHARE_MAX * n
            and n_eq / n >= EQ_SHARE_MIN):
        verdict = 'H-36-eq-usage'
        unique = True
    return {'static_verdict': verdict, 'unique': unique,
            'conflict': conflict}


# ------------------------------------------------------------ Rosetta align

def const_fingerprint(words, lo, hi):
    """Distinctive 16-bit anchors: set*/add*/and*/xor/subsi imms > 0xff,
    ld.i indices, csr indices (tagged)."""
    out = []
    for j in range(max(0, lo), min(len(words), hi)):
        w = words[j]
        op = w >> 26
        if op in (0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
                  0x0a, 0x0b, 0x0e, 0x05):
            v = w & 0xffff
            if v > 0xff:
                out.append((j, v))
        elif op == 0x12 and (w >> 25) & 1:
            v = w & 0xffff
            if v > 0xff:
                out.append((j, v))
        elif op in (0x12, 0x13):
            v = w & 0x7ff
            if v > 0xff:
                out.append((j, 0x10000 | v))
    return out


def align(src_words, i, tgt_words, tgt_index):
    """Align the source producer into the target by const fingerprint.

    Returns (aligned_target_index, score) or None."""
    cs = const_fingerprint(src_words, i - ALIGN_WIN, i + ALIGN_WIN + 1)
    if len(cs) < MIN_ANCHOR_MATCH:
        return None
    ranked = [cv for cv in sorted(cs, key=lambda cv: len(
        tgt_index.get(cv[1], ()))) if tgt_index.get(cv[1])]
    if not ranked:
        return None
    best = None
    for (j1, v1) in ranked[:ANCHORS]:
        for tj1 in tgt_index[v1]:
            delta = tj1 - j1
            matches = 1
            for (j2, v2) in cs:
                if j2 == j1:
                    continue
                want = j2 + delta
                pos = tgt_index.get(v2)
                if not pos:
                    continue
                k2 = bisect.bisect_left(pos, want - TOL)
                if k2 < len(pos) and pos[k2] <= want + TOL:
                    matches += 1
            if matches >= MIN_ANCHOR_MATCH:
                pi = i + delta
                if best is None or matches > best[1]:
                    best = (pi, matches)
    return best


# ------------------------------------------------------------- corpus load

def load_sections():
    """Extract every irisc section of corpus_sections.json from the
    md5-pinned images, verifying payload md5 pins."""
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
    path = HERE / 'corpus_sites.jsonl'
    check_pin(path, PIN_SITES)
    sites = []
    for line in path.read_text().splitlines():
        s = json.loads(line)
        w = int(s['word'], 16)
        if w >> 26 == 0x36 and s['strict']:
            s['_word'] = w
            s['_idx'] = int(s['dc_offset'], 16) // 4
            sites.append(s)
    return sites


def count_1619_mask_sites():
    """Non-strict (mask-only) 0x36 sites in 1619: the letter-of-the-brief
    Rosetta leg (ceiling item, computed from the pinned manifest)."""
    n = 0
    for line in (HERE / 'corpus_sites.jsonl').read_text().splitlines():
        s = json.loads(line)
        if (s['fw'] == '1619' and not s['strict']
                and int(s['word'], 16) >> 26 == 0x36):
            n += 1
    return n


def dual_encoding_count(sections, sites):
    """In-corpus dual encoding: reg-form (i6==0) strict 0x36 sites with a
    cmp.w (0x38 sel0) comparing the same operand pair (either order)
    within +-12 words (ceiling item, computed)."""
    n = 0
    for s in sites:
        w = s['_word']
        if (w >> 5) & 0x3f:
            continue                      # imm form: rt is not the comparand
        words = sections[(s['fw'], s['section'])]
        i = s['_idx']
        rs = rs_of(w)
        rt = rt_of(w)
        for j in range(max(0, i - 12), min(len(words), i + 13)):
            if j == i:
                continue
            wj = words[j]
            if wj >> 26 == 0x38 and rd_of(wj) == 0:
                a, b = rs_of(wj), rt_of(wj)
                if (a, b) in ((rs, rt), (rt, rs)):
                    n += 1
                    break
    return n


# ------------------------------------------------------------- phase A

def build_phase_a():
    check_pin(HERE / 'census_corpus.json', PIN_CENSUS)
    census = json.loads((HERE / 'census_corpus.json').read_text())
    cm_path = REPO / 'scripts/probes/cx5-fuzz5/census_map.json'
    check_pin(cm_path, PIN_CENSUS_MAP)
    census_map = json.loads(cm_path.read_text())

    sections = load_sections()
    sites = load_sites()

    # def-use pass (all strict sites)
    site_ctx = {}
    agg = collections.defaultdict(collections.Counter)
    sel_buckets = collections.defaultdict(list)
    for s in sites:
        words = sections[(s['fw'], s['section'])]
        ctx = defuse_context(words, s['_idx'])
        site_ctx[(s['fw'], s['section'], s['dc_offset'])] = ctx
        w = s['_word']
        f5 = w & 0x1f
        i6 = (w >> 5) & 0x3f
        axis = ('reg' if i6 == 0 else 'imm6', f5)
        agg[axis]['sites'] += 1
        agg[axis]['state:' + ctx['state']] += 1
        agg[axis]['shape:' + ctx['shape']] += 1
        if ctx['dead_branch']:
            agg[axis]['dead_branch'] += 1
        if ctx['const_both']:
            agg[axis]['const_prop'] += 1
        sel_buckets[w & 0x7ff].append(s)

    # Rosetta pass: align every strict site into every other version's
    # sections; classify known-op idioms at non-0x36 aligned positions.
    tcache = {}
    for key, words in sections.items():
        idx = collections.defaultdict(list)
        for j, v in const_fingerprint(words, 0, len(words)):
            idx[v].append(j)
        tcache[key] = (words, idx)

    pairs = []          # classified (dedup by target position+setter)
    drift = []          # aligned target is 0x36 with a different selector
    seen_pair = set()
    seen_drift = set()
    aligned_sites = set()
    for s in sites:
        sw = sections[(s['fw'], s['section'])]
        i = s['_idx']
        w = s['_word']
        lo11 = w & 0x7ff
        for (tfw, tsec), (tw, tidx) in tcache.items():
            if (tfw, tsec) == (s['fw'], s['section']):
                continue
            al = align(sw, i, tw, tidx)
            if not al:
                continue
            pi, score = al
            if not (0 <= pi < len(tw)):
                continue
            aligned_sites.add((s['fw'], s['section'], s['dc_offset']))
            tword = tw[pi]
            if tword >> 26 == 0x36:
                tsel = tword & 0x7ff
                if tsel != lo11:
                    k = (tfw, tsec, pi, tsel, lo11)
                    if k not in seen_drift:
                        seen_drift.add(k)
                        drift.append({
                            'src': {'fw': s['fw'],
                                    'section': s['section'],
                                    'dc_offset': s['dc_offset'],
                                    'selector': lo11},
                            'tgt': {'fw': tfw, 'section': tsec,
                                    'dc_offset': '0x%x' % (pi * 4),
                                    'selector': tsel},
                        })
                continue
            for fam, detail, setter in classify_at(tw, pi):
                k = (tfw, tsec, pi, setter)
                if k in seen_pair:
                    continue
                seen_pair.add(k)
                pairs.append({
                    'src': {'fw': s['fw'], 'section': s['section'],
                            'dc_offset': s['dc_offset'],
                            'selector': lo11},
                    'tgt': {'fw': tfw, 'section': tsec,
                            'dc_offset': '0x%x' % (pi * 4)},
                    'fam': fam,
                    'detail': detail,
                    'setter': '0x%x' % (setter * 4),
                    'score': score,
                })

    # axis aggregation over classified pairs
    pair_axes = collections.defaultdict(list)
    for p in pairs:
        f5 = p['src']['selector'] & 0x1f
        i6 = (p['src']['selector'] >> 5) & 0x3f
        pair_axes[('reg' if i6 == 0 else 'imm6', f5)].append(p)

    # imm-form masked-field structure stats (research note for cycle B):
    # masked 1619 idioms whose (shift, width) match the producer (i6, f5)
    imm_masked = 0
    imm_shift_width = 0
    imm_const_eq = 0
    imm_const_eq_i6 = 0
    for p in pairs:
        sel = p['src']['selector']
        if not (sel >> 5) & 0x3f or p['fam'] != 'eq':
            continue
        det = p['detail']
        if det.startswith('subsi'):
            c = int(det[5:].split('/')[0], 16)
            imm_const_eq += 1
            if c == ((sel >> 5) & 0x3f):
                imm_const_eq_i6 += 1
        if '/' not in det:
            continue
        prep = det.split('/')[1]
        if not prep.startswith(('ands', 'and:', 'andhi')):
            continue
        m = int(prep.split(':')[1], 16)
        if not m:
            continue
        lo = (m & -m).bit_length() - 1
        w = bin(m).count('1')
        imm_masked += 1
        if (m >> lo) == ((1 << w) - 1) and lo == (
                (sel >> 5) & 0x3f) and w == (sel & 0x1f):
            imm_shift_width += 1

    axes_meta = {}
    for axis, plist in sorted(pair_axes.items()):
        v = assign_axis_verdict(plist)
        n_eq = sum(1 for p in plist if p['fam'] == 'eq')
        n_ord = len(plist) - n_eq
        axes_meta['%s/f5=%02x' % axis] = {
            'pairs': len(plist), 'eq': n_eq, 'ord': n_ord,
            'eq_share': round(n_eq / len(plist), 4),
            **v,
            'def_use': dict(sorted(agg[axis].items())),
        }

    # rows: census_corpus 0x36 rows + census_map MAIN f5_fill rows
    rows = {}
    for r in census['rows']:
        if r['key']['op'] != '0x36':
            continue
        sel = dict(r['key']['selector'])
        key = {'section': r['key']['section'], 'op': '0x36',
               'selector': sel}
        rows[json.dumps(key, sort_keys=True)] = key
    for r in census_map['rows']:
        if r['op'] != '0x36':
            continue
        sel = {'f5': r['selector']['f5'], 'i6': r['selector']['i6'],
               'lo11': r['selector']['f5'] | (r['selector']['i6'] << 5)}
        key = {'section': 'MAIN', 'op': '0x36', 'selector': sel}
        rows.setdefault(json.dumps(key, sort_keys=True), key)

    phase_rows = []
    for jkey in sorted(rows):
        key = rows[jkey]
        f5 = key['selector']['f5']
        i6 = key['selector']['i6']
        form = 'reg' if i6 == 0 else 'imm6'
        axis = (form, f5)
        v = assign_axis_verdict(pair_axes.get(axis, []))
        # basis: Rosetta pairs of this axis, exact-selector matches of
        # the row first, then other selectors of the axis (verdict is
        # per-f5; basis prefers the row's own selector evidence)
        lo11 = f5 | (i6 << 5)
        plist = pair_axes.get(axis, [])
        plist = sorted(
            plist,
            key=lambda p: (p['src']['selector'] != lo11, -p['score'],
                           p['tgt']['dc_offset']))[:12]
        basis = [{
            'type': 'rosetta',
            'src': dict(p['src'], dc_offset=p['src']['dc_offset']),
            'tgt': dict(p['tgt']),
            'fam': p['fam'],
            'detail': p['detail'],
            'score': p['score'],
        } for p in plist]
        axis_sites = sel_buckets.get(f5 | (i6 << 5), [])
        # cap site samples at 3 deterministic picks
        for s in axis_sites[:3]:
            ctx = site_ctx[(s['fw'], s['section'], s['dc_offset'])]
            basis.append({
                'type': 'site',
                'site': {'fw': s['fw'], 'section': s['section'],
                         'dc_offset': s['dc_offset'],
                         'word': s['word']},
                'def_use': {k2: ctx[k2] for k2 in
                            ('state', 'polarity', 'dist', 'shape')},
            })
        row = {
            'key': key,
            'form': form,
            'static_verdict': v['static_verdict'],
            'unique': v['unique'],
            'basis': basis,
            'conflict': v['conflict'],
            'live_join': None,
            'constructor_scope': form,
            'v_support': None,
        }
        if not v['static_verdict']:
            n_pairs = len(pair_axes.get(axis, []))
            row['reason'] = (
                'no classified Rosetta pairs for the axis' if not n_pairs
                else 'classified pairs %d below threshold %d'
                     % (n_pairs, MIN_CLASSIFIED))
        phase_rows.append(row)

    total_dead = sum(1 for c in site_ctx.values() if c['dead_branch'])
    total_const = sum(1 for c in site_ctx.values() if c['const_both'])
    n_1619_strict = sum(1 for s in sites if s['fw'] == '1619')
    n_1619_mask = count_1619_mask_sites()
    n_dual = dual_encoding_count(sections, sites)
    doc = {
            'meta': {
                'cycle': 'isa-max-a task-4 (C-A.1 0x36 static support grind)',
                'method': 'def-use window over corpus_sites strict 0x36 '
                          'sites + directed Rosetta alignment of every '
                          'strict site into the old-compiler binaries '
                          '(1619 primary, LX1900/CX6DX/8008 secondary) '
                          'by const fingerprint; position-strict known-op '
                          'idiom classification at the aligned position',
                'verdict_rule': 'H-36-eq-usage iff classified pairs >= %d '
                                'and eq share >= %.2f and ord share <= '
                                '%.2f; ord cluster >= %d pairs above the '
                                'gate = mixed axis (conflict, no verdict)'
                                % (MIN_CLASSIFIED, EQ_SHARE_MIN,
                                   ORD_SHARE_MAX, ORD_CONFLICT_MIN),
                'pins': {
                    'corpus_sites.jsonl': PIN_SITES,
                    'census_corpus.json': PIN_CENSUS,
                    'census_map.json': PIN_CENSUS_MAP,
                    'fuzz5_live.json': PIN_LIVE,
                },
                'coverage': {
                    'strict_sites': len(sites),
                    'defuse_consumer': sum(
                        1 for c in site_ctx.values()
                        if c['state'] == 'consumer'),
                    'defuse_killed': sum(
                        1 for c in site_ctx.values()
                        if c['state'] == 'killed'),
                    'defuse_no_consumer': sum(
                        1 for c in site_ctx.values()
                        if c['state'] == 'no-consumer'),
                    'sites_aligned': len(aligned_sites),
                    'classified_pairs': len(pairs),
                    'drift_pairs': len(drift),
                },
                'v_axes_search': {
                    'dead-branch': {
                        'forms': ['noop branch (target == fall-through)',
                                  'skip-noop (target jumps to '
                                  'fall-through)'],
                        'sites': total_dead,
                        'supports_v': total_dead > 0,
                        'verdict': 'found' if total_dead else
                                   'not found',
                    },
                    'const-prop': {
                        'forms': ['both operands imm-chain constants'],
                        'sites': total_const,
                        'supports_v': False,
                        'verdict': 'sites exist but the predicate outcome '
                                   'is not statically observable '
                                   '(no reachability); not a V support '
                                   'form offline',
                    },
                },
                'rosetta_1619_strict_leg': 'empty: both 1619 code-mask '
                                          '0x36 sites are non-strict '
                                          'data-region words '
                                          '(0x24e764/0x24e780); mask-only '
                                          'is never proof',
                'imm_field_note': 'imm-form clusters carry a real '
                                  'sub-dominant structure: masked field '
                                  'tests whose (shift, width) match the '
                                  'producer (i6, f5) -- %d/%d masked '
                                  'pairs in this production run (%d/%d '
                                  'in the exploration run), while the '
                                  'unmasked const-compare consts equal '
                                  'i6 in only %d/%d pairs (version drift '
                                  'confound, cf. CR-index drift '
                                  '0x9887/0x9948/0x9307); below the '
                                  'dominance gate -> no separate '
                                  'verdict, parked for cycle B'
                                  % (imm_shift_width, imm_masked, 59, 247,
                                     imm_const_eq_i6, imm_const_eq),
                'ceiling_inputs': {
                    'rosetta_1619_strict_sites': n_1619_strict,
                    'rosetta_1619_mask_only_sites': n_1619_mask,
                    'dual_encoding_sites': n_dual,
                },
                'ord_gate_note': 'ord-family detection is conservative: '
                                 'any flag-writing word between the '
                                 'setter and its cc3/cc4 consumer rejects '
                                 'the candidate; ordering idioms with a '
                                 'clobbered flag path are not counted '
                                 '(ord share is a lower bound)',
                'ceiling': [
                    'Rosetta strict-sites of 0x36 in 1619: %d (mask-only '
                    'code-mask sites: %d -- data-region words, not proof '
                    'per Global Constraints)' % (n_1619_strict,
                                                 n_1619_mask),
                    'in-corpus dual encoding (cmp.w with the same '
                    'operand pair within +-12 words of a reg-form '
                    'producer): %d sites' % n_dual,
                    'dead-branch V-form: %d sites' % total_dead,
                    'const-prop V-form: %d sites, outcome not statically '
                    'observable (no reachability analysis offline)'
                    % total_const,
                    'imm-form (i6!=0): aligned compare consts drift with '
                    'versions (C==i6 in %d/%d pairs); field(shift=i6,'
                    'width=f5) structure sub-dominant (%d/%d masked '
                    'pairs) -> no model-grade static verdict'
                    % (imm_const_eq_i6, imm_const_eq,
                       imm_shift_width, imm_masked),
                ],
                'template_drift_note': 'cross-version aligned 0x36 sites '
                                       'freely interchange f5 inside '
                                       '{2,3,4}, {8}, {9,10,11} (same '
                                       'wait-loop template instantiated '
                                       'with f5=0xb/0xa/9 in '
                                       '4030/LX1900/CX6DX); recorded as '
                                       'drift_pairs, not verdict-grade',
            },
            'phases': {
                'A': {
                    'rows': phase_rows,
                    'axes': axes_meta,
                    # drift list capped at 200 entries (artifact size);
                    # the full count is drift_pairs_total + meta.coverage
                    'drift_pairs': drift[:200],
                    'drift_pairs_total': len(drift),
                },
            },
        }
    return doc


# ------------------------------------------------------------- phase B

def build_phase_b(a_doc):
    check_pin(HERE / 'fuzz5_live.json', PIN_LIVE)
    live = json.loads((HERE / 'fuzz5_live.json').read_text())

    def live_key(sel):
        return 'op36_f5=%02x_i6=%02x' % (sel['f5'], sel['i6'])

    def axis_pairs(key):
        form = 'reg' if key['selector']['i6'] == 0 else 'imm6'
        ax = a_doc['phases']['A']['axes'].get(
            '%s/f5=%02x' % (form, key['selector']['f5']))
        return ax['pairs'] if ax else 0

    rows = []
    merge_ready = []
    join_stats = collections.Counter()
    for r in a_doc['phases']['A']['rows']:
        key = r['key']
        # unified T4-T7 contract: the phase-B row EXTENDS the phase-A row
        # (all eight fields present; live_join is filled in here)
        rec = dict(r)
        lrow = None
        if key['section'] == 'MAIN':
            lrow = live['rows'].get(live_key(key['selector']))
        if lrow is None:
            status = 'silence'
            note = ('no live coverage (fuzz-5 battery is MAIN-only; '
                    'expanded sections are outside the live mandate)'
                    if key['section'] != 'MAIN' else
                    'no live row for selector')
        else:
            lv = lrow['live_verdict']
            um = lrow.get('unique_model')
            if r['static_verdict'] and lv == 'unique' and um:
                if um in EQ_FAMILY_MODELS:
                    status = 'match'
                    note = ('live %s inside the static eq-usage family'
                            % um)
                    if r['unique'] and not r['conflict']:
                        merge_ready.append(key)
                else:
                    status = 'conflict'
                    note = ('live unique model %s outside the static '
                            'eq-usage family (FW usage of this axis is '
                            'eq-shaped in %d aligned idiom contexts); '
                            'usage-vs-semantics tension, unresolved '
                            'offline' % (um, axis_pairs(key)))
            elif lv in ('multi', 'rogue', 'div', 'unobserved'):
                status = 'silence'
                note = 'live %s (no unique model to join)' % lv
            else:
                status = 'silence'
                note = 'live verdict %s' % lv
        join_stats[status] += 1
        rec['live_join'] = {
            'status': status,
            'note': note,
            'live_verdict': lrow['live_verdict'] if lrow else None,
            'unique_model': lrow.get('unique_model') if lrow else None,
            'alive_set': lrow.get('alive_set') if lrow else None,
            'n_observations': len(lrow.get('observations', []))
            if lrow else 0,
        }
        rows.append(rec)

    closed = sorted(k for k, v in a_doc['phases']['A']['axes'].items()
                    if v['static_verdict'])
    return {
        'rows': rows,
        'merge_ready': merge_ready,
        'join_stats': dict(join_stats),
        'c_a1_summary': {
            'axes_closed_by_static': closed,
            'axes_closed_note': 'family-level eq-usage support '
                                '(H-36-eq-usage); no axis gets a '
                                'model-grade static verdict offline',
            'merge_ready': [('%s/f5=%02x/i6=%02x'
                             % (k['section'], k['selector']['f5'],
                                k['selector']['i6']))
                            for k in merge_ready],
            'structural_ceiling': a_doc['meta']['ceiling'],
        },
    }


# ------------------------------------------------------------------- main

def write_doc(doc):
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + '\n')


def main():
    docstring = __doc__ or ''
    ap = argparse.ArgumentParser(
        description=docstring.splitlines()[0] if docstring else
        'isa-max A task-4 0x36 static support grind')
    ap.add_argument('--phase-a', action='store_true',
                    help='recompute Phase A (static only) and write it')
    ap.add_argument('--phase-b', action='store_true',
                    help='join fuzz5_live into Phase B (requires A)')
    ap.add_argument('--check', action='store_true',
                    help='recompute A+B and diff against the artifact')
    args = ap.parse_args()

    if args.check:
        have = json.loads(OUT.read_text())
        fresh_a = build_phase_a()
        if 'phases' not in have or 'A' not in have.get('phases', {}):
            raise SystemExit('CHECK FAIL: artifact has no Phase A')
        fresh_b = build_phase_b(fresh_a)
        fresh = dict(fresh_a)
        fresh['phases']['B'] = fresh_b
        if fresh == have:
            print('CHECK PASS: h36_verdicts.json reproduces '
                  '(%d phase-A rows)' % len(fresh_a['phases']['A']['rows']))
            return
        raise SystemExit('CHECK FAIL: h36_verdicts.json drift')

    if args.phase_a:
        doc = build_phase_a()
        # a rerun keeps an existing phase B consistent with the fresh
        # phase A (same join --check performs) instead of dropping it
        if OUT.exists():
            try:
                old = json.loads(OUT.read_text())
            except json.JSONDecodeError:
                old = {}
            if 'B' in old.get('phases', {}):
                doc['phases']['B'] = build_phase_b(doc)
        write_doc(doc)
        print('phase A: %d rows, %d axes, verdicts on %d axes'
              % (len(doc['phases']['A']['rows']),
                 len(doc['phases']['A']['axes']),
                 sum(1 for v in doc['phases']['A']['axes'].values()
                     if v['static_verdict'])))
        print('wrote %s' % OUT)
        return

    if args.phase_b:
        doc = json.loads(OUT.read_text())
        if 'A' not in doc.get('phases', {}):
            raise SystemExit('no Phase A in artifact; run --phase-a first')
        doc['phases']['B'] = build_phase_b(doc)
        write_doc(doc)
        stats = doc['phases']['B']['join_stats']
        print('phase B: join %s; merge_ready %d axes'
              % (stats, len(doc['phases']['B']['merge_ready'])))
        print('wrote %s' % OUT)
        return

    ap.print_help()


if __name__ == '__main__':
    main()
