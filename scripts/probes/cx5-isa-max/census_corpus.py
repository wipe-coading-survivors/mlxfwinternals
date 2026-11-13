#!/usr/bin/env python3
"""isa-max A per-section selector census over the expanded iRISC corpus
(offline, no hardware). Plan task 2026-10-31-irisc-isa-max-a Task 2 (C-A.0).

Methodology:
- sections: corpus_sections.json (committed pin) -- every classification
  'irisc' row is re-extracted from the md5-pinned image and payload-md5
  checked against the pin; census runs only on iRISC sections;
- selector models / op set: census_map.py (imported, single source of
  truth: CORE_OPS, selector_of, sel_key, row_id, attach_static);
- strict criterion: census_map strict_mask with the ptr window taken from
  the per-section ITOC.param0 -- [param0, param0 + payload_size) -- the
  census_map.py:146 0x800000 hardcode is NOT inherited; param0==0 (ACE
  0x15) disables the ptr exclusion (no load base known for the window);
- rows: per (section, op, selector), sites = code-mask counts per version,
  sites_strict = strict counts; class = has-sites iff >=1 strict site in
  any version (mask_only recorded when mask sites exist but strict do
  not -- never treated as proof);
- corpus_sites.jsonl: ALL sites of the target ops (0x0c/0x16/0x33/0x34/
  0x36/0x38/0x39/0x3c) with coordinates {fw, section, dc_offset, word,
  strict}; site coordinates come ONLY from this manifest.

Sanity gates (refuse to write on failure):
- MAIN per-op sums (code-mask, CORE_OPS) vs census_map OP_LEVEL_EXPECTED,
  tolerance 0 for 4030/8008/1619/CX6DX. LX1900 lineage gate instead
  (journal 2026-11-01-irisc-isa-max-a-task-02 §0.2: the census_map bin is
  a raw clcrc-framed 14.32.1912 section): fresh clean 1900-GCA sums ==
  PROFILE_CX4LX census (tolerance 0), == OP_LEVEL_EXPECTED - KNOWN_DELTA
  on the delta ops, and the residual framing deviation 0x3c==7 pinned;
- IRON_PREP 8008 unk share < 10% (order-of-magnitude check vs the
  reachable-Ghidra domain of journal 2026-09-14: total=1241, unk=21);
- bclr.1 continuity anchor: MAIN/0x34 f5=2 idx=1 flag=0 has its strict
  site at dc 0x8c124 in 4030 (census_map sanity gate 1);
- selector sums == per-section op counts; jsonl row counter == per-op
  site sums.

Outputs: census_corpus.json + corpus_sites.jsonl next to this script
(committed). `--check` recomputes and diffs both.
"""
import collections
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

import corpus_sections as CS
from corpus_sections import load_census_map
from scripts.irisc import recount_codehist as RC

OUT = HERE / 'census_corpus.json'
SITES = HERE / 'corpus_sites.jsonl'

cm = load_census_map()

# def-use target ops (plan T2: all-site manifest)
TARGET_OPS = (0x0c, 0x16, 0x33, 0x34, 0x36, 0x38, 0x39, 0x3c)
CENSUS_OPS = cm.CORE_OPS

# journal §0.2: census_map 'LX1900' expected values reflect the raw
# clcrc-framed 1912 input bin; the clean 1900-GCA corpus deviates on the
# documented KNOWN_DELTA ops plus this residual:
LX1900_FRAMING_RESIDUAL = {0x3c: 7}


def strict_mask(words, n, code, base):
    """WP-1 §1.6 strict criterion; ptr window = [base, base+size) from the
    per-section ITOC.param0 (census_map.py:146 hardcode not inherited).
    base==0 -> no ptr window (load base unknown: ACE 0x15)."""
    size = n * 4
    known = [1 if (w >> 26) in RC.KNOWN30 else 0 for w in words]
    isbr = [1 if (w >> 26) in (0x25, 0x28, 0x29, 0x2a, 0x2b) else 0
            for w in words]
    if base:
        lo, hi = base, base + size
        isptr = [1 if lo <= w < hi else 0 for w in words]
    else:
        isptr = [0] * n
    strict = [False] * n
    for i in range(n):
        if not code[i]:
            continue
        lo, hi = max(0, i - 8), min(n, i + 9)
        lk = sum(known[lo:hi]) - known[i]
        denom = (hi - lo) - 1
        if denom > 0 and lk / denom < 0.75:
            continue
        if sum(isbr[lo:hi]) < 1:
            continue
        if sum(isptr[lo:hi]) / (hi - lo) >= 0.25:
            continue
        strict[i] = True
    return strict


def census_section(cells, op_counts, sites_out, fw, section, words, code,
                   strict):
    """Accumulate per-(section,op,selector) cells, per-section op counts and
    target-op site coordinates for one classified section."""
    opc = op_counts.setdefault(section, collections.Counter())
    for i, w in enumerate(words):
        op = w >> 26
        if op not in CENSUS_OPS or not code[i]:
            continue
        opc[op] += 1
        key = (section, op,
               () if op == 0x0d else cm.sel_key(op, cm.selector_of(op, w)))
        cell = cells.setdefault(key, {'sites': {}, 'sites_strict': {}})
        cell['sites'][fw] = cell['sites'].get(fw, 0) + 1
        if strict[i]:
            cell['sites_strict'][fw] = cell['sites_strict'].get(fw, 0) + 1
        if op in TARGET_OPS:
            sites_out.append({
                'fw': fw,
                'section': section,
                'dc_offset': '0x%x' % (i * 4),
                'word': '0x%08x' % w,
                'strict': bool(strict[i]),
            })


def build_rows(cells, versions):
    rows = []
    for (section, op, key) in sorted(
            cells, key=lambda k: (k[0], k[1], k[2])):
        cell = cells[(section, op, key)]
        sites = {v: cell['sites'].get(v, 0) for v in versions}
        sites_strict = {v: cell['sites_strict'].get(v, 0) for v in versions}
        strict_total = sum(sites_strict.values())
        mask_total = sum(sites.values())
        if op in (0x33, 0x34):
            sel = {'f5': key[0], 'idx': key[1], 'flag': key[2],
                   'lo11': key[0] | (key[1] << 5) | (key[2] << 10)}
        elif op == 0x36:
            sel = {'f5': key[0], 'i6': key[1],
                   'lo11': key[0] | (key[1] << 5)}
        elif op == 0x0c:
            sel = {'imm16': key[0]}
        elif op == 0x38:
            sel = {'sel': key[0]}
        elif op in cm.RARE_OPS:
            sel = {'lo11': key[0]}
        else:
            sel = {}
        row = {
            'key': {'section': section, 'op': '0x%02x' % op,
                    'selector': sel},
            'id': '%s|%s' % (section, cm.row_id(op, sel)),
            'sites': sites,
            'sites_strict': sites_strict,
            'class': 'has-sites' if strict_total > 0 else 'zero-sites',
        }
        if mask_total and not strict_total:
            row['mask_only'] = True
        rows.append(row)
    # census_map.attach_static works on flat rows ({op, selector}); project
    flat = [{'op': r['key']['op'], 'selector': r['key']['selector']}
            for r in rows]
    cm.attach_static(flat)
    for r, f in zip(rows, flat):
        if 'static' in f:
            r['static'] = f['static']
    return rows


def load_irisc_sections():
    """Re-extract every 'irisc' row of the committed corpus_sections.json,
    verifying image + payload md5 pins."""
    doc = json.loads((HERE / 'corpus_sections.json').read_text())
    out = []
    images = {}
    for r in doc['sections']:
        if r['classification'] != 'irisc':
            continue
        ver = r['fw']
        if ver not in images:
            images[ver] = CS.load_image(ver)
        img = images[ver]
        typ = int(r['type'], 16)
        e = img.find_entry('ITOC', typ)
        payload, tail = CS.extract_payload(img.section_data(e), e.clcrc)
        md5 = hashlib.md5(payload).hexdigest()
        if md5 != r['md5']:
            raise SystemExit('input drift %s 0x%02x: md5 %s != pin %s'
                             % (ver, typ, md5, r['md5']))
        out.append((ver, r['short'], typ, r['param0'], payload))
    return doc, out


def build_census():
    cs_doc, sections = load_irisc_sections()
    versions = list(CS.IMAGES)
    cells = {}
    op_counts = {}
    sites_out = []
    iron8008 = {'unk': 0, 'code': 0}
    for ver, short, typ, param0, payload in sections:
        n = len(payload) // 4
        words = struct.unpack_from('>%dI' % n, payload, 0)
        feat, ops, code, cover, votes, wstats = RC.classify(words, n)
        strict = strict_mask(words, n, code, param0)
        census_section(cells, op_counts, sites_out, ver, short, words,
                       code, strict)
        if (ver, short) == ('8008', 'IRON_PREP'):
            iron8008['unk'] = sum(
                1 for i, w in enumerate(words)
                if code[i] and (w >> 26) not in RC.KNOWN30)
            iron8008['code'] = sum(code)
    rows = build_rows(cells, versions)
    sec_op = collections.defaultdict(collections.Counter)
    for (section, op, key), cell in cells.items():
        for ver, cnt in cell['sites'].items():
            sec_op[(ver, section)][op] += cnt
    return {
        'cs_doc': cs_doc,
        'versions': versions,
        'rows': rows,
        'cells': cells,
        'sec_op': sec_op,
        'op_counts': op_counts,
        'sites': sites_out,
        'iron8008': iron8008,
    }


def sanity(res):
    fails = []
    rows = res['rows']
    cells = res['cells']
    op_counts = res['op_counts']
    sec_op = res['sec_op']
    versions = res['versions']

    # 1. MAIN per-op sums vs OP_LEVEL_EXPECTED, tolerance 0 (4 versions)
    for ver in ('4030', '8008', '1619', 'CX6DX'):
        for op, cnt in cm.OP_LEVEL_EXPECTED[ver].items():
            got = sec_op[(ver, 'MAIN')].get(op, 0)
            if got != cnt:
                fails.append('MAIN %s op 0x%02x: %d != %d'
                             % (ver, op, got, cnt))
    # 2. LX1900 lineage gate: profile census + documented framing deltas
    for op, cnt in cm.PROFILE_CX4LX.items():
        got = sec_op[('LX1900', 'MAIN')].get(op, 0)
        if got != cnt:
            fails.append('LX1900 profile op 0x%02x: %d != %d'
                         % (op, got, cnt))
    for op, cnt in cm.OP_LEVEL_EXPECTED['LX1900'].items():
        got = sec_op[('LX1900', 'MAIN')].get(op, 0)
        if op in cm.PROFILE_CX4LX_KNOWN_DELTA:
            exp = cnt - cm.PROFILE_CX4LX_KNOWN_DELTA[op]
        elif op in LX1900_FRAMING_RESIDUAL:
            exp = LX1900_FRAMING_RESIDUAL[op]
        else:
            exp = cnt
        if got != exp:
            fails.append('LX1900 MAIN op 0x%02x: %d != %d (lineage gate)'
                         % (op, got, exp))
    # 3. bclr.1 continuity anchor (census_map sanity gate 1)
    anchor = [r for r in rows if r['id'] == 'MAIN|op34_f5=02_idx=01_flag=0']
    if not anchor or not (anchor[0]['sites_strict']['4030'] == 1
                          and anchor[0]['class'] == 'has-sites'):
        fails.append('bclr.1 MAIN anchor row lost: %s' % anchor)
    hit = [s for s in res['sites']
           if s['fw'] == '4030' and s['section'] == 'MAIN'
           and s['dc_offset'] == '0x8c124']
    if not hit or not hit[0]['strict']:
        fails.append('bclr.1 site @0x8c124 not strict in jsonl')
    # 4. IRON_PREP 8008 unk share < 10% (journal 2026-09-14 order check)
    share = res['iron8008']['unk'] / max(1, res['iron8008']['code'])
    if share >= 0.10:
        fails.append('IRON_PREP 8008 unk share %.3f >= 0.10' % share)
    # 5. selector sums == per-section op counts (aggregated over versions)
    for section, opc in op_counts.items():
        for op, total in opc.items():
            cellsum = sum(sec_op[(v, section)].get(op, 0) for v in versions)
            if cellsum != total:
                fails.append('selector sums %s 0x%02x: %d != %d'
                             % (section, op, cellsum, total))
    # 6. jsonl row counter == target-op site sums per (fw, section)
    per_line = collections.Counter()
    for s in res['sites']:
        per_line[(s['fw'], s['section'])] += 1
    per_cells = collections.Counter()
    for (section, op, key), cell in cells.items():
        if op not in TARGET_OPS:
            continue
        for ver, cnt in cell['sites'].items():
            per_cells[(ver, section)] += cnt
    if per_line != per_cells:
        fails.append('jsonl row counter != per-op site sums (%d vs %d)'
                     % (sum(per_line.values()), sum(per_cells.values())))
    return fails


def build_baseline(res):
    baseline = {}
    for leg in ('MAIN', 'EXPANDED'):
        baseline[leg] = {}
        for ver in res['versions']:
            per = collections.Counter({op: 0 for op in CENSUS_OPS})
            for (v2, section), opmap in res['sec_op'].items():
                if v2 != ver or (section == 'MAIN') != (leg == 'MAIN'):
                    continue
                per.update(opmap)
            baseline[leg][ver] = {'0x%02x' % op: cnt
                                  for op, cnt in sorted(per.items())}
    return baseline


def main():
    res = build_census()
    fails = sanity(res)
    if fails:
        for f in fails:
            print('SANITY FAIL: %s' % f, file=sys.stderr)
        raise SystemExit(1)

    rows = res['rows']
    summary = {}
    for r in rows:
        skey = '%s|%s' % (r['key']['section'], r['key']['op'])
        s = summary.setdefault(skey,
                               {'rows': 0, 'has_sites': 0, 'zero_sites': 0})
        s['rows'] += 1
        s['has_sites' if r['class'] == 'has-sites' else 'zero_sites'] += 1

    doc = {
        'meta': {
            'cycle': 'isa-max-a task-2 (C-A.0 per-section selector census)',
            'method': 'census over corpus_sections.json irisc rows; '
                      'selector models = census_map.py (imported); strict '
                      'ptr window = per-section ITOC.param0 (hardcode of '
                      'census_map.py:146 not inherited; param0==0 ACE -> '
                      'ptr exclusion off)',
            'target_ops': ['0x%02x' % op for op in TARGET_OPS],
            'sites_definition': 'sites = code-mask counts per version; '
                                'sites_strict = strict counts; class = '
                                'has-sites iff >=1 strict site in any '
                                'version; mask_only never proof',
            'lineage': res['cs_doc']['meta']['lineage'],
            'iron_prep_8008_unk_share': round(
                res['iron8008']['unk']
                / max(1, res['iron8008']['code']), 4),
            'linear_baseline': build_baseline(res),
        },
        'summary': summary,
        'rows': rows,
    }

    sites_text = ''.join(json.dumps(s) + '\n' for s in res['sites'])
    if '--check' in sys.argv:
        have = json.loads(OUT.read_text())
        fresh = {k: doc[k] for k in ('meta', 'summary', 'rows')}
        old = {k: have[k] for k in ('meta', 'summary', 'rows')}
        if fresh == old and SITES.read_text() == sites_text:
            print('CHECK PASS: census_corpus.json + corpus_sites.jsonl '
                  'reproduce (%d rows, %d sites)'
                  % (len(rows), len(res['sites'])))
            return
        raise SystemExit('CHECK FAIL: census_corpus/corpus_sites drift')
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + '\n')
    SITES.write_text(sites_text)
    print('rows=%d sites=%d (%s)' % (
        len(rows), len(res['sites']),
        ', '.join('%s:%d' % (k, v['rows'])
                  for k, v in sorted(summary.items()))))
    print('wrote %s + %s' % (OUT, SITES))


if __name__ == '__main__':
    main()
