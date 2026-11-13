#!/usr/bin/env python3
"""fuzz5 T5 merge selection: programmatic live x static join (2 confirmations).

Rule (plan Global Constraints): a semantic model enters iRISC.slaspec only
with TWO independent confirmations — a live battery verdict (T4: observed ==
expected of the single surviving model on a census row) AND a static census
hypothesis (T1: static.verdict_id attached to census rows, asserting the same
formula).  Manual cherry-picking is forbidden: the decision below is derived
entirely from the joined data.

Inputs (read-only):
- census_map.json           static leg (rows with static attachments + verdicts)
- fuzz5_vectors.json        battery census_rows join keys / live_only flags
- --state-battery <p>       T4 live verdicts state json (battery round)
- --state-disc <p>          T4 live verdicts state json (disc round)

Live verdict per census row = intersection of alive hypothesis sets over all
covering battery vectors, then narrowing by PRIOR_DEAD (fuzz-4 prior deaths,
same table as consolidate_battery.py) and DISC_RESOLVE (disc-round outcomes
recorded in task-4 Appendix A; disc vectors carry no census_rows keys, so the
reviewed row-level outcome is transcribed with its T4 source).  Empty alive
set -> 'rogue'; one survivor -> 'unique:<M>'; else 'multi:{...}'.

Static semantics table STATIC_SEM quotes the census verdict formulas; records
without an rd-semantics formula (usage/context notes), live-fact records
(1-method), merged records and open records are non-mergeable by
construction.

Decision per semantic static hypothesis:
  MERGE   iff >=1 attached+live-covered row resolves to a unique model in the
           hypothesis family AND zero attached+covered rows contradict it
           (rogue, div, or a unique model outside the family);
  otherwise REJECT with the conflicting rows / reason.

Output: stdout report + --out json (default: select_merges.json beside
this script).
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]

PRIOR_DEAD = {
    # from consolidate_battery.py (fuzz-4 deaths, context for alive-sets)
    'op36:f5=04': ['H-uge32', 'H-ule32'],
}

DISC_RESOLVE = {
    # task-4 Appendix A annotations (Fix round 1): final row outcome after
    # the discriminator round; value = alive hypothesis id or None=rogue
    'op36_f5=0a_i6=00': ('H-V',
                         'V-D36-F0A-EQ16/EQ kill eq16/eq32/ule32 (T4 §3.1)'),
    'op33_f5=00_idx=00_flag=1': ('H-pass',
                                 'V-D33-F0F1 + cross-point kill min/max '
                                 '(T4 §3.2)'),
    'op34_f5=0b_idx=10_flag=1': (None,
                                 'rogue-collision (T4 Appendix A)'),
}

STATIC_SEM = {
    # census verdict id -> semantic family it asserts (formulas quoted from
    # census_map.json verdicts[])
    'H-33-dep-R': {
        'op': '0x33', 'family': ('H-depR',),
        'formula': 'rd = (rs & ~((2^f5-1)<<idx)) | ((rt & (2^f5-1))<<idx); '
                   'W = f5 (replace deposit)'},
    'H-33-bit': {
        'op': '0x33', 'family': ('H-depR',),
        'formula': 'single-bit deposit: W=1 case of H-33-dep-R (census '
                   'verdict text) — same formula'},
    'H-0c-hi-and': {
        'op': '0x0c', 'family': ('H-0c-hiand',),
        'formula': 'rd_lo = rs_lo & ((imm16<<16) | 0xffff)'},
    'H-16-shr': {
        'op': '0x16',
        'family': ('H-16-shr32u', 'H-16-shr64u', 'H-16-shr32a',
                   'H-16-shr64a', 'H-16-pass'),
        'formula': 'rd = rs >> (imm & 0x3f) (64-bit shift right; the live '
                   'battery separated the shr family from pass/hi2lo/zero '
                   'models; H-16-pass is the sh=0 degenerate of the family)'},
    'H-34-dep-R': {
        'op': '0x34', 'family': ('H-depR',),
        'formula': 'replace-deposit W=f5, flag=0 classes (same formula as '
                   'H-33-dep-R)'},
}

NON_SEMANTIC = {
    # attached census records without an rd-semantics formula -> nothing to
    # merge regardless of live outcome
    'H-34-mmio': 'usage hypothesis (bit-array MMIO address helper), no '
                 'rd-formula',
    'V-38-selne0': 'value-form closure (non-cc-writers); the only live-'
                   'covered attached row (sel=4) is DIV — volatile field, '
                   'not a merge candidate by ruling',
}
REFUTED_STATIC = {
    # static hypotheses whose own attached+covered rows live-resolve to a
    # different unique model: the static side died, the live winner is
    # recorded here (journal); they ground no merge themselves
    'H-33-minmax': ('H-depR', 'live dep-R explains both f5=24 points; min '
                              'dead (V-M33-f524-i00), max dead (disc '
                              'cross-point)'),
    'H-33-clamp16': ('H-depR', 'live dep-R explains the clamp row (obs '
                               '0x0000bffe); clamp16 dead'),
}
OUT_OF_LIVE_MANDATE = {
    # ops with no live coverage by design (T2 design §1: static track only)
    'C2-0x1d', 'C2-0x20', 'C2-0x22', 'C2-0x2d', 'C2-0x3a', 'C2-0x3b',
}
LIVE_FACT_STATUSES = ('live-fact',)
ALREADY_MERGED = {'MERGED-0d', 'MERGED-34-bclr1', 'V-38-sel0'}
OPEN_RECS = {'OPEN-34-f5=2-idx=5'}


def load_json(p):
    return json.loads(Path(p).read_text())


def row_prior_key(row):
    sel = row['selector']
    if row['op'] == '0x36' and 'f5' in sel:
        return 'op36:f5=%02x' % sel['f5']
    return None


def live_verdicts(census_rows, vectors, state):
    """row_id -> (verdict_tag, [covering vector ids], div_flag)."""
    by_row = defaultdict(list)
    for v in vectors:
        if v['id'] == 'V-F4-MARKER':
            continue
        st = state.get(v['id'])
        if st is None or 'verdicts' not in st:
            raise SystemExit('no verdicts for vector %s' % v['id'])
        alive = frozenset(h for h, x in st['verdicts'].items()
                          if x['verdict'] == 'жива')
        div = bool(st.get('divergence'))
        for rid in v.get('census_rows', []):
            by_row[rid].append((v['id'], alive, div, bool(v.get('live_only'))))
    out = {}
    for row in census_rows:
        rid = row['id']
        covers = by_row.get(rid, [])
        if not covers:
            continue
        alive = frozenset.intersection(
            *[a for _, a, _, _ in covers]) if covers else frozenset()
        pk = row_prior_key(row)
        dead = PRIOR_DEAD.get(pk, []) if pk is not None else []
        alive = alive - set(dead)
        tag = 'multi'
        if rid in DISC_RESOLVE:
            res, _src = DISC_RESOLVE[rid]
            alive = frozenset({res}) if res else frozenset()
            tag = 'disc'
        if any(d for _, _, d, _ in covers):
            out[rid] = ('div', alive, covers)
            continue
        if not alive:
            out[rid] = ('rogue', alive, covers)
        elif len(alive) == 1:
            out[rid] = ('unique', alive, covers)
        else:
            out[rid] = (tag if tag != 'multi' else 'multi', alive, covers)
    return out


def vtag(alive):
    return ','.join(sorted(alive)) if alive else '-'


def main():
    ap = argparse.ArgumentParser(
        description='fuzz5 T5 merge selection (live x static, 2 confirmations)')
    ap.add_argument('--state-battery', required=True,
                    help='T4 live verdicts state json (battery round)')
    ap.add_argument('--state-disc', required=True,
                    help='T4 live verdicts state json (disc round)')
    ap.add_argument('--out', default=str(HERE / 'select_merges.json'),
                    help='output report json path')
    args = ap.parse_args()

    census = load_json(HERE / 'census_map.json')
    vectors = load_json(HERE / 'fuzz5_vectors.json')
    state_b = load_json(args.state_battery)
    state_d = load_json(args.state_disc)
    state = {}
    state.update(state_b['completed'])
    state.update(state_d['completed'])
    rows = census['rows']
    recs = {r['id']: r for r in census['verdicts']}

    live = live_verdicts(rows, vectors, state)

    # ---- static groups: verdict_id -> [(row, live outcome)] ----
    groups = defaultdict(list)
    for row in rows:
        st = row.get('static') or {}
        vid = st.get('verdict_id')
        if vid:
            groups[vid].append((row, live.get(row['id'])))
    report = {'merges': [], 'excluded': [], 'live_only_rows': {},
              'live_covered': len(live), 'census_rows': len(rows)}

    # ---- decision per static record ----
    for vid in sorted(groups):
        entries = groups[vid]
        rec = recs[vid]
        covered = [(r, lo) for r, lo in entries if lo]
        base = {'static_id': vid, 'op': rec['op'],
                'attached_rows': len(entries),
                'covered_rows': len(covered)}
        if vid in ALREADY_MERGED:
            base.update(flag='already_merged',
                        reason='census status merged (prior slaspec commit)')
            report['excluded'].append(base)
            continue
        if not covered:
            base.update(flag='no_live_coverage',
                        reason='no live-covered attached rows (outside the '
                               'T2 live mandate, static track only)')
            report['excluded'].append(base)
            continue
        if vid in REFUTED_STATIC:
            winner, why = REFUTED_STATIC[vid]
            base.update(flag='static_refuted',
                        reason='attached rows live-resolve to %s: %s'
                               % (winner, why))
            report['excluded'].append(base)
            continue
        if vid in OPEN_RECS:
            live_side = [(r['id'], vtag(lo[1])) for r, lo in covered]
            base.update(flag='open_conflict',
                        reason='static record refutes both bclr and W=2 '
                               'replace (fuzz-4 V-34-2 rogue), live battery '
                               'row resolves to bclr — unresolved reading '
                               'conflict, ruling: f5=2 axis untouched')
            base['live_rows'] = live_side
            report['excluded'].append(base)
            continue
        if rec['status'] in LIVE_FACT_STATUSES:
            base.update(flag='static_livefact',
                        reason='census record is a 1-method live fact '
                               '(static leg contributed contexts only, no '
                               'semantic formula) — live x static not met')
            report['excluded'].append(base)
            continue
        if vid in NON_SEMANTIC:
            base.update(flag='static_no_semantics',
                        reason=NON_SEMANTIC[vid])
            report['excluded'].append(base)
            continue
        if vid not in STATIC_SEM:
            base.update(flag='static_unclassified',
                        reason='no semantics table entry')
            report['excluded'].append(base)
            continue

        sem = STATIC_SEM[vid]
        fam = set(sem['family'])
        confirms, conflicts, nonsep, divrows = [], [], [], []
        for r, lo in covered:
            rid = r['id']
            kind, alive, covers = lo
            vids = [c[0] for c in covers]
            if kind == 'div':
                divrows.append((rid, 'div', vids))
            elif kind == 'rogue':
                conflicts.append((rid, 'rogue', vids))
            elif alive <= fam:
                if len(alive) == 1:
                    confirms.append((rid, vtag(alive), vids))
                else:
                    nonsep.append((rid, vtag(alive), vids))
            else:
                outside = sorted(alive - fam)
                if len(alive) == 1:
                    conflicts.append((rid, 'unique-out-of-family %s'
                                      % vtag(alive), vids))
                else:
                    nonsep.append((rid, '%s (outside: %s)'
                                   % (vtag(alive), ','.join(outside)), vids))
        base.update(formula=sem['formula'], confirms=confirms,
                    non_separating=nonsep, conflicts=conflicts,
                    div_rows=divrows)
        if conflicts:
            base.update(flag='conflict',
                        reason='live x static conflict on attached covered '
                               'rows (rule: conflict => no merge, journal)')
            report['excluded'].append(base)
        elif confirms:
            base.update(flag='MERGE',
                        reason='live unique verdict x static hypothesis, '
                               'zero conflicts on attached covered rows')
            report['merges'].append(base)
        else:
            base.update(flag='no_unique_live',
                        reason='no attached covered row resolved to a unique '
                               'in-family model')
            report['excluded'].append(base)

    # ---- live-covered rows without static attachment ----
    lo_by_op = defaultdict(list)
    for row in rows:
        vid = row.get('static', {}).get('verdict_id')
        lo = live.get(row['id'])
        if lo and not vid:
            kind, alive, covers = lo
            lo_by_op[row['op']].append(
                (row['id'], kind, vtag(alive),
                 covers[0][0], sum(1 for c in covers if not c[3])))
    for op, items in sorted(lo_by_op.items()):
        report['live_only_rows'][op] = {
            'rows': len(items),
            'unique_examples': [i for i in items if i[1] == 'unique'][:6],
            'rogue_rows': sum(1 for i in items if i[1] == 'rogue'),
            'note': 'live verdicts without census static attachment: '
                    '1-method (live_only) rows, never merge candidates; for '
                    'op 0x33 they corroborate (not ground) the merged dep '
                    'constructor; op 0x36 axis has no static leg at all'}

    out = Path(args.out)
    out.write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')

    print('=== fuzz5 T5 merge selection (live x static) ===')
    print('census rows %d, live-covered %d' % (len(rows), len(live)))
    print('\n-- MERGE candidates --')
    for m in report['merges']:
        print('%s (op %s): %d confirm row(s), %d non-separating, '
              '0 conflicts' % (m['static_id'], m['op'],
                               len(m['confirms']), len(m['non_separating'])))
        for rid, tag, vids in m['confirms']:
            print('   %s live=unique:%s vectors=%s' % (rid, tag, vids))
        for rid, tag, vids in m['non_separating']:
            print('   %s live=multi:%s (non-separating) vectors=%s'
                  % (rid, tag, vids))
    print('\n-- EXCLUDED --')
    for e in report['excluded']:
        print('%-24s op %-4s flag=%-20s %s' % (
            e['static_id'], e['op'], e['flag'], e.get('reason', '')))
        for rid, tag, _vids in e.get('conflicts', [])[:8]:
            print('   conflict: %s live=%s' % (rid, tag))
    print('\n-- live-only rows (no static attachment) --')
    for op, d in report['live_only_rows'].items():
        print('op %s: %d rows (%d rogue)' % (op, d['rows'], d['rogue_rows']))
        for rid, kind, tag, vid, nhas in d['unique_examples'][:3]:
            print('   e.g. %s %s:%s %s (has-site covers %d)'
                  % (rid, kind, tag, vid, nhas))
    print('\nwritten: %s' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
