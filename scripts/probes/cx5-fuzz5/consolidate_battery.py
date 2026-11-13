#!/usr/bin/env python3
"""fuzz5 T4 consolidation: per-census-row verdict table + coverage check."""
import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]

ap = argparse.ArgumentParser()
ap.add_argument('--vectors', required=True, help='fuzz5 battery vectors json')
ap.add_argument('--disc', required=True, help='fuzz5 disc vectors json')
ap.add_argument('--state-battery', required=True, help='T4 battery state json')
ap.add_argument('--state-disc', required=True, help='T4 disc state json')
ap.add_argument('--out', help='write the per-row table to this file')
args = ap.parse_args()

vec = json.loads(Path(args.vectors).read_text())
disc = json.loads(Path(args.disc).read_text())
census = json.loads((REPO / 'scripts/probes/cx5-fuzz5/census_map.json').read_text())
rows = census['rows']
st_b = json.loads(Path(args.state_battery).read_text())
st_d = json.loads(Path(args.state_disc).read_text())
st_all = {}
st_all.update(st_b['completed'])
st_all.update(st_d['completed'])

PRIOR_DEAD = {  # killed in fuzz-4/fuzz5 earlier cycles (context for alive-sets)
    'op36:f5=4': ['H-uge32', 'H-ule32'],
}

# 1. every vector completed with verdicts?
miss = [v['id'] for v in vec + disc
        if v['id'] != 'V-F4-MARKER'
        and ('verdicts' not in st_all.get(v['id'], {}))]
print('vectors without verdicts:', miss or 'NONE (142+11 complete)')

# 2. per census row: vectors covering it -> live verdicts
by_row = {}
for v in vec + disc:
    for r in v.get('census_rows', []):
        by_row.setdefault(r, []).append(v['id'])
mand = {'0x33', '0x34', '0x36', '0x0c', '0x38'}
out_rows = []
covered = set()
for r in rows:
    op = r['op']
    vids = by_row.get(r['id'], [])
    if not vids:
        continue
    covered.add(r['id'])
    for vid in vids:
        c = st_all[vid]
        alive = sorted(h for h, x in c['verdicts'].items() if x['verdict'] == 'жива')
        und = sorted(h for h, x in c['verdicts'].items() if x['verdict'] == 'неопределена')
        obs = next(iter(c['verdicts'].values())).get('observed', {})
        cr = obs.get('cr0x8c8', (c.get('chosen') or {}).get('cr_post', ['-'])[0])
        div = c.get('divergence', False)
        out_rows.append((r['id'], op, r['class'], vid, cr, alive, und, div))

print('\n=== live-covered census rows: %d (of %d total) ===' % (len(covered), len(rows)))
w = max(len(x[0]) for x in out_rows), max(len(x[3]) for x in out_rows)
for rid, op, cls, vid, cr, alive, und, div in out_rows:
    tag = ' DIV' if div else ''
    print('%-*s %s %-2s %-*s obs=%-10s жива={%s}%s%s' % (
        w[0], rid, op, 'H' if cls == 'has-sites' else 'Z',
        w[1], vid, cr, ','.join(alive) or '-',
        ' und={%s}' % ','.join(und) if und else '', tag))

# 3. coverage split by op/class for mandatory ops
print('\n=== coverage vs census (mandatory ops) ===')
for op in ('0x33', '0x34', '0x36', '0x0c', '0x38', '0x16', '0x39', '0x3c'):
    ro = [r for r in rows if r['op'] == op]
    hs = [r for r in ro if r['class'] == 'has-sites']
    zs = [r for r in ro if r['class'] == 'zero-sites']
    print('op %s: has %d/%d, zero %d/%d, total rows %d' % (
        op,
        sum(1 for r in hs if r['id'] in covered), len(hs),
        sum(1 for r in zs if r['id'] in covered), len(zs), len(ro)))

# 4. verdict counts per group
print('\n=== verdict counts (per hypothesis record) ===')
cnt = {}
for v in vec + disc:
    if v['id'] == 'V-F4-MARKER':
        continue
    for h, x in st_all[v['id']]['verdicts'].items():
        k = x['verdict']
        cnt.setdefault(v.get('group', '?'), {}).setdefault(k, 0)
        cnt[v['group']][k] += 1
for g, d in sorted(cnt.items()):
    print('%-9s %s' % (g, d))

if args.out:
    Path(args.out).write_text(
        '\n'.join('%s | %s | %s | %s | %s | %s | %s | %s' % x
                  for x in out_rows))
