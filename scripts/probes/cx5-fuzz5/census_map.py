#!/usr/bin/env python3
"""fuzz-5 census map: full selector-space census of core-op iRISC across 5 FW
versions + WP-4 static squeeze verdicts (offline, no hardware).

Methodology (WP-1 / I2-c, journal 2026-10-25-irisc-isa-i2-bitops-grind.md §2-3):
- code/data classification: window classifier recount_codehist.classify()
  (code-mask, majority vote) + per-word strict criterion (local_known>=0.75 in
  +-8, >=1 branch/call/jump in +-8, not ptr-dense);
- sites: code-mask counts (comparable with WP-1 §2.1 / docs/250-re/120-irisc/010-isa.md tables) and
  strict counts recorded per version; class = has-sites iff >=1 strict site
  anywhere ("real site" criterion of WP-1 §7), else zero-sites (mask_only flag
  when mask sites exist but strict do not);
- selector models: 0x33/0x34 lo11 = flag[10]|idx[9:5]|f5[4:0] (docs/250-re/120-irisc/010-isa.md);
  0x36 lo11 = imm6[10:5]|funct5[4:0]; 0x0c value-form = imm16; 0x38
  value-form = bits 16..20 (rd/cmpop field; 0 = cmp.w); rare ops = lo11;
  0x0d = op-level row (merged and.hi sanity anchor).

Inputs: MAIN_CODE de-clcrc bins — four in build/ (WP-1 §0), CX6-Dx extracted
on demand from refs/fw (recipe WP-1 §3: Image -> ITOC 0x03 -> clcrc_unwrap)
into build/. All md5 pinned: census refuses silent input drift.

Outputs: census_map.json next to this script (committed artifact). `--check`
recomputes and diffs against the committed JSON (rows/verdicts/summary only).

Live facts used by verdicts (fuzz-4, report irisc-fuzz4.md + journal task-06):
merged and.hi (0x0d) / bclr.1 (0x34 lo11=0x022); rogue V-0c-1/3, V-34-2/6/7;
1-method live: 0x16/0x39/0x3c writes, V-33-1/2/3, f5map (3,5)/(7,3)/(5,3),
ltV pair, cmp38-self.
"""
import collections
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from mlxfwutil import Image, clcrc_unwrap
from scripts.irisc import recount_codehist as RC

OUT = Path(__file__).resolve().parent / 'census_map.json'

CX6_REF = (REPO / 'refs/fw/cx-5-6/'
           'fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC-CDA_Ax-UEFI-14.43.10-'
           'FlexBoot-3.9.101.signed.bin')

# version -> (path, md5, extract-from-refs-if-missing)
BINS = collections.OrderedDict([
    ('4030', (REPO / 'build/ghidra-4030cda-main03-ac-dc.bin',
              '1b73520497bd20f49fe4e5200a6c86dd', False)),
    ('8008', (REPO / 'build/8008_main03_dc.bin',
              '3a5cd549edb83cd052b01bed276cf6b2', False)),
    ('1619', (REPO / 'build/ghidra-oldmain-1619.bin',
              'd88fe3c1976bc4a9919bd78de204f283', False)),
    ('LX1900', (REPO / 'build/ghidra-lx-main-code.bin',
                'bea1027c0430a215598c7349e413053a', False)),
    ('CX6DX', (REPO / 'build/cx6dx_main03_dc.bin',
               '7e4db04c2a744391ba4edc642462f651', True)),
])

OP_LEVEL_EXPECTED = {
    '4030': {0x0d: 3393, 0x33: 2115, 0x34: 1492, 0x36: 3774, 0x16: 65,
             0x1d: 32, 0x22: 15, 0x39: 10, 0x3c: 11, 0x20: 6, 0x3a: 6,
             0x2d: 4, 0x3b: 2, 0x38: 28},
    '8008': {0x0d: 3399, 0x33: 2114, 0x34: 1494, 0x36: 3787, 0x16: 65,
             0x1d: 32, 0x22: 15, 0x39: 10, 0x3c: 11, 0x20: 6, 0x3a: 6,
             0x2d: 4, 0x3b: 2, 0x38: 28},
    '1619': {0x0d: 4842, 0x33: 231, 0x34: 0, 0x36: 2, 0x16: 1,
             0x1d: 3, 0x22: 1, 0x39: 0, 0x3c: 0, 0x20: 0, 0x3a: 0,
             0x2d: 2, 0x3b: 0, 0x38: 2},
    'LX1900': {0x0d: 3011, 0x33: 1804, 0x34: 1321, 0x36: 3670, 0x16: 5,
               0x1d: 5, 0x22: 2, 0x39: 4, 0x3c: 4, 0x20: 1, 0x3a: 2,
               0x2d: 4, 0x3b: 2, 0x38: 3},
    'CX6DX': {0x0d: 5373, 0x33: 3614, 0x34: 1638, 0x36: 5554, 0x16: 82,
              0x1d: 54, 0x22: 21, 0x39: 16, 0x3c: 18, 0x20: 45, 0x3a: 17,
              0x2d: 10, 0x3b: 5, 0x38: 50},
}

PROFILE_CX5 = {0x36: 3774, 0x0d: 3393, 0x33: 2115, 0x34: 1492, 0x16: 65,
               0x38: 28, 0x1d: 32, 0x39: 10, 0x3c: 11, 0x22: 15, 0x20: 6,
               0x3a: 6, 0x2d: 4, 0x3b: 2}
PROFILE_CX4LX = {0x36: 3667, 0x0d: 3010, 0x33: 1803, 0x34: 1319, 0x16: 5,
                 0x38: 3, 0x1d: 5}
PROFILE_CX4LX_KNOWN_DELTA = {0x36: 3, 0x0d: 1, 0x33: 1, 0x34: 2}

RARE_OPS = (0x16, 0x1d, 0x39, 0x3c, 0x20, 0x3a, 0x2d, 0x3b, 0x22)
CORE_OPS = (0x33, 0x34, 0x36, 0x0c, 0x38, 0x0d) + RARE_OPS


def dec_f5_idx_flag(lo11):
    return ((lo11 >> 10) & 1, (lo11 >> 5) & 0x1f, lo11 & 0x1f)


def selector_of(op, w):
    lo11 = w & 0x7ff
    if op in (0x33, 0x34):
        flag, idx, f5 = dec_f5_idx_flag(lo11)
        return {'f5': f5, 'idx': idx, 'flag': flag, 'lo11': lo11}
    if op == 0x36:
        return {'f5': lo11 & 0x1f, 'i6': (lo11 >> 5) & 0x3f, 'lo11': lo11}
    if op == 0x0c:
        return {'imm16': w & 0xffff}
    if op == 0x38:
        return {'sel': (w >> 16) & 0x1f}
    if op in RARE_OPS:
        return {'lo11': lo11}
    return {}


def sel_key(op, s):
    if op in (0x33, 0x34):
        return (s['f5'], s['idx'], s['flag'])
    if op == 0x36:
        return (s['f5'], s['i6'])
    if op == 0x0c:
        return (s['imm16'],)
    if op == 0x38:
        return (s['sel'],)
    if op in RARE_OPS:
        return (s['lo11'],)
    return ()


def row_id(op, s):
    if op in (0x33, 0x34):
        return 'op%02x_f5=%02x_idx=%02x_flag=%d' % (op, s['f5'], s['idx'], s['flag'])
    if op == 0x36:
        return 'op36_f5=%02x_i6=%02x' % (s['f5'], s['i6'])
    if op == 0x0c:
        return 'op0c_imm=%04x' % s['imm16']
    if op == 0x38:
        return 'op38_sel=%02x' % s['sel']
    if op in RARE_OPS:
        return 'op%02x_lo11=%03x' % (op, s['lo11'])
    return 'op%02x' % op


def strict_mask(words, n, code):
    size = n * 4
    known = [1 if (w >> 26) in RC.KNOWN30 else 0 for w in words]
    isbr = [1 if (w >> 26) in (0x25, 0x28, 0x29, 0x2a, 0x2b) else 0
            for w in words]
    isptr = [1 if 0x800000 <= w < 0x800000 + size else 0 for w in words]
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


def load_version(ver, spec):
    path, md5_expect, extract = spec
    if not path.exists() and extract:
        img = Image(open(CX6_REF, 'rb').read(), str(CX6_REF))
        e = img.find_entry('ITOC', 0x03)
        payload, _tail = clcrc_unwrap(img.section_data(e))
        path.write_bytes(payload)
    buf = path.read_bytes()
    md5 = hashlib.md5(buf).hexdigest()
    if md5 != md5_expect:
        raise SystemExit('input drift %s: %s md5 %s != %s'
                         % (ver, path, md5, md5_expect))
    n = len(buf) // 4
    words = struct.unpack_from('>%dI' % n, buf, 0)
    feat, ops, code, cover, votes, wstats = RC.classify(words, n)
    strict = strict_mask(words, n, code)
    return words, code, strict


def build_census():
    versions = {}
    for ver, spec in BINS.items():
        versions[ver] = load_version(ver, spec)

    cells = {}
    op_counts = {v: collections.Counter() for v in versions}
    for ver, (words, code, strict) in versions.items():
        for i, w in enumerate(words):
            op = w >> 26
            if op not in CORE_OPS or not code[i]:
                continue
            op_counts[ver][op] += 1
            if op == 0x0d:
                key = ()
            else:
                key = sel_key(op, selector_of(op, w))
            cell = cells.setdefault((op, key),
                                    {'sites': {}, 'sites_strict': {},
                                     'ex': collections.defaultdict(list)})
            cell['sites'][ver] = cell['sites'].get(ver, 0) + 1
            if strict[i]:
                cell['sites_strict'][ver] = cell['sites_strict'].get(ver, 0) + 1
                ex = cell['ex'][ver]
                if len(ex) < 4:
                    ex.append('0x%x' % (i * 4))

    rows = []
    for (op, key) in sorted(cells, key=lambda k: (k[0], k[1])):
        cell = cells[(op, key)]
        sites = {v: cell['sites'].get(v, 0) for v in versions}
        sites_strict = {v: cell['sites_strict'].get(v, 0) for v in versions}
        mask_total = sum(sites.values())
        strict_total = sum(sites_strict.values())
        if op == 0x0d:
            sel = {}
        else:
            if op in (0x33, 0x34):
                flag, idx, f5 = dec_f5_idx_flag(key[0] | (key[1] << 5) | (key[2] << 10))
                sel = {'f5': f5, 'idx': idx, 'flag': flag, 'lo11': key[0] | (key[1] << 5) | (key[2] << 10)}
            elif op == 0x36:
                sel = {'f5': key[0], 'i6': key[1], 'lo11': key[0] | (key[1] << 5)}
            elif op == 0x0c:
                sel = {'imm16': key[0]}
            elif op == 0x38:
                sel = {'sel': key[0]}
            else:
                sel = {'lo11': key[0]}
        cls = 'has-sites' if strict_total > 0 else 'zero-sites'
        row = {
            'id': row_id(op, sel),
            'op': '0x%02x' % op,
            'selector': sel,
            'sites': sites,
            'sites_strict': sites_strict,
            'class': cls,
        }
        if mask_total and not strict_total:
            row['mask_only'] = True
        if any(cell['ex'].get(v) for v in versions):
            row['site_examples'] = {v: ex for v, ex in cell['ex'].items() if ex}
        rows.append(row)

    observed_f5 = {op: set() for op in (0x33, 0x34, 0x36)}
    for row in rows:
        if 'f5' in row['selector'] and int(row['op'], 16) in observed_f5:
            observed_f5[int(row['op'], 16)].add(row['selector']['f5'])
    fill = {0x33: ('idx', 0), 0x34: ('idx', 0), 0x36: ('i6', 0)}
    for op, (mid, mval) in fill.items():
        for f5 in range(32):
            if f5 in observed_f5[op]:
                continue
            sel = {'f5': f5, mid: mval, 'lo11': f5 | (mval << 5)}
            if mid == 'idx':
                sel['flag'] = 0
            rows.append({
                'id': row_id(op, sel),
                'op': '0x%02x' % op,
                'selector': sel,
                'sites': {v: 0 for v in versions},
                'sites_strict': {v: 0 for v in versions},
                'class': 'zero-sites',
                'f5_fill': True,
            })
    rows.sort(key=lambda r: (int(r['op'], 16), r['id']))

    if not any(r['id'] == 'op34_f5=02_idx=05_flag=0' for r in rows):
        rows.append({
            'id': 'op34_f5=02_idx=05_flag=0',
            'op': '0x34',
            'selector': {'f5': 2, 'idx': 5, 'flag': 0, 'lo11': 0x0a2},
            'sites': {v: 0 for v in versions},
            'sites_strict': {v: 0 for v in versions},
            'class': 'zero-sites',
            'synthetic': 'fuzz-4 V-34-2 anchor (live rogue 0x000400ff)',
        })

    return rows, versions, op_counts


VERDICTS = [
    dict(id='MERGED-0d', op='0x0d', selector=None, status='merged',
         verdict='and.hi: RDlo = RSlo & (imm16 << 16); rt-field absent '
                 '(bits 11..15 are imm16)',
         evidence=['live V-0d-2/3/4/5 exact (fuzz-4 journal task-06)',
                   'static WP-1 §2.4 dead-code + def-use, §1.1',
                   'slaspec commit 061d7e0'],
         conf=0.99),
    dict(id='MERGED-34-bclr1', op='0x34',
         selector={'f5': 2, 'idx': 1, 'flag': 0}, status='merged',
         verdict='bclr.1: RDlo = RSlo & ~2 (fixed lo11=0x022 constructor)',
         evidence=['live V-34-1 exact 0xfffffffd (fuzz-4 task-06)',
                   'Rosetta 4030 dc 0x08c124 <-> 1619 dc 0x057514 (WP-1 §2.2)',
                   'idx-generalization dead (V-34-2 rogue)',
                   'slaspec commit 061d7e0'],
         conf=0.99),
    dict(id='H-33-dep-R', op='0x33', selector={'f5_set': [1, 4, 8]},
         status='hypothesis',
         verdict='bitfield deposit REPLACE (not merge): '
                 'rd = (rs & ~((2^f5 - 1) << idx)) | ((rt & (2^f5 - 1)) << idx); '
                 'width W = f5 bits (f5=1 bit, 4 nibble, 8 byte), arbitrary bit '
                 'position idx; closes WP-4 replace-vs-merge',
         evidence=['258/280 strict f5=4/8 sites are bare ld.d -> op0x33 -> st.d '
                   'with no field clear (merge would keep stale field bits); '
                   '0/22 apparent clear-before sites clear the deposited field '
                   '(all coincidental: value reloaded between clear and deposit)',
                   'dc 0x1a8788/0x1acb98: manual and r5,r5,0xff0f clears an '
                   'adjacent field of the same word, then 0x33 f5=4 idx=0 '
                   'deposits without clear — compiler would have used 0xff00 '
                   'mask if the deposit merged',
                   'dual-branch dc 0x52a14 (op0x33 f5=4 idx=28 deposit) vs '
                   '0x52a20 (manual shr 0x1c extract of the same field)',
                   'loop flag-set dc 0x3b820: lw.r -> op0x33 f5=4 idx=0 -> st.d '
                   'over table elements (field init semantics)',
                   'cross-op: 0x34 f5=6 idx=4 live rogue 0xfffffc0f == '
                   'replace-clear of 6-bit field @4 (V-34-6)'],
         conf=0.85),
    dict(id='H-34-dep-R', op='0x34',
         selector={'f5_set': [4, 6, 8, 0xc], 'flag': 0}, status='hypothesis',
         verdict='same replace-deposit formula as H-33-dep-R for flag=0 '
                 'classes (W = f5); flag=1 variant open (V-34-7 rogue '
                 '0x00004c00 unexplained by the model)',
         evidence=['live V-34-6 (f5=6 idx=4 flag=0, rt=zero, rs=0xffffffff): '
                   'observed 0xfffffc0f == (rs & ~(0x3f << 4)) exact',
                   'WP-1 §2.6 ESW manual 14-bit clear+insert idiom parallel to '
                   'f5=0xc idx=10 deposits (same-field replace equivalence)',
                   'f5=8 idx in {0,8,16,24} byte-aligned (WP-1 §1.4)'],
         conf=0.8),
    dict(id='H-34-mmio', op='0x34', selector={'f5': 27}, status='hypothesis',
         verdict='bit-array MMIO address helper (csr.w 0x28 immediately after)',
         evidence=['WP-1 §2.6: 2 MMIO contexts; census sites dc examples in '
                   'site_examples of f5=27 rows'],
         conf=0.5),
    dict(id='H-33-minmax', op='0x33', selector={'f5': 0x18}, status='hypothesis',
         verdict='MIN/MAX merge of table elements (f5=0x18 idx=0: min live-proven)',
         evidence=['live V-33-2 (5,3) -> 3 = min exact, 1-method (fuzz-4 '
                   'task-06); max/add/or dead on that point',
                   'WP-1 §2.7: merge tables of log sizes, top lo11=0x018 x331'],
         conf=0.75),
    dict(id='H-33-clamp16', op='0x33', selector={'f5': 0x10, 'idx': 14},
         status='hypothesis',
         verdict='clamp/min of 16-bit field @14',
         evidence=['live V-33-3 exact 0x00400000, 1-method (fuzz-4 task-06)',
                   'WP-1 §2.7: borrow-test context dc 0x38b0'],
         conf=0.7),
    dict(id='H-33-bit', op='0x33', selector={'f5': 1}, status='hypothesis',
         verdict='single-bit deposit (W=1 case of H-33-dep-R): '
                 'rd = (rs & ~(1 << idx)) | ((rt & 1) << idx)',
         evidence=['live V-33-1 (rs=0, rt=1, idx=25) -> 0x02000000 exact, '
                   '1-method (fuzz-4 task-06)',
                   'WP-1 §2.7: idx covers all 32 positions; capability '
                   'assembly series; replace model from H-33-dep-R squeeze'],
         conf=0.75),
    dict(id='H-0c-hi-and', op='0x0c', selector=None, status='hypothesis',
         verdict='rd_lo = rs_lo & ((imm16 << 16) | 0x0000ffff): high-half '
                 'mask with low-half passthrough ("clear field for insert" '
                 'complement of and.hi). Supersedes H-0c-ANDN (dead) and the '
                 'or-imm render',
         evidence=['reproduces all three live results exactly: V-0c-1 '
                   '(0xabcd1234, 0x00ff) -> 0x00cd1234; V-0c-2 (0, 0xff00) -> '
                   '0; V-0c-3 (0x12345678, 0x0f00) -> 0x02005678 (byte3 '
                   '0x12 & 0x0f = 0x02)',
                   'WP-1 §2.4 idiom coherence: pair (0x0c imm=0xf0ff, 0x0d '
                   'imm=0x0f00) — mask (0xf0ff<<16)|0xffff clears exactly '
                   'bits 24..27, the field the shl64+0x0d branch inserts',
                   'strict imm histogram is 16-bit-mask-shaped (0xff x1396, '
                   '0x1ff, 0x7fff, 0xfff, 0xbfff, 0xf7ff, 0xff00, 0xefff...)',
                   'imm=0 (1176 strict sites): low-half extract; no FW '
                   'contradiction found (moves of already-16-bit values are '
                   'no-ops under the model)'],
         conf=0.9),
    dict(id='H-16-shr', op='0x16', selector=None, status='hypothesis',
         verdict='rd = rs >> (imm & 0x3f) (64-bit shift right; logical vs '
                 'arithmetic open). Lea (rd = rs + imm / +(imm<<k)) REFUTED. '
                 'Closes WP-4 0x16 lea-scale question',
         evidence=['live V-r-16 (rs=0x00100000, imm=0x28): rd = 0 — additive '
                   'lea impossible; shift 40 of 2^20 = 0 exact (fuzz-4 '
                   'task-06 c2rare)',
                   'b.bclr consumers read one source bit: imm=38 -> b.bclr 7, '
                   'imm=39 -> b.bclr 6 (dc 0x20945c/0x209948/0x209d04/'
                   '0x209cb0) — constant source bit 45 under rd=rs>>imm',
                   'imm>63 sites meaningful only under shift = imm & 0x3f: '
                   'imm=125 -> rs<2^61 bound test (dc 0x212bfc/0x215070 '
                   'subsi-zero); imm=149/151 -> subi 0x20 zero-tests (dc '
                   '0x217844/0x218908...); imm=152 -> b.bclr/b.bset bit0 = '
                   'source bit 24 (dc 0x2184c0/0x218dec/0x2197a8); imm=284 -> '
                   'b.bclr 2 = source bit 30 (dc 0x214c4c)',
                   'field-extract: dc 0x210684 mask32 -> ld -> ands 0x3f -> '
                   'op0x16 imm=3 -> subsi 0x2b (range check via >>3)',
                   'imm histogram small offsets (7, 38/39/40, 59/60, 151/152 '
                   'runs) — consecutive shifts for adjacent single-bit tests'],
         conf=0.8),
    dict(id='OPEN-34-f5=2-idx=5', op='0x34',
         selector={'f5': 2, 'idx': 5, 'flag': 0}, status='open',
         verdict='f5=2 idx=5 (strict sites in 4030/8008/LX/CX6DX): neither '
                 'bclr-style ~(1<<idx) (V-34-2 expected 0xdf, observed '
                 '0x000400ff) nor W=2 replace-deposit (0xbf) fits; live-'
                 'candidate for T2 map34 with discriminating rt values',
         evidence=['dc 0x224b14 manual parallel idiom ands r4,r5,0x60 + '
                   'subsi 0x20 bounds the class to a 2-bit field @5',
                   'fuzz-4 task-06 V-34-2 rogue 0x000400ff (rs=0xff, rt=1)'],
         conf=0.4),
    dict(id='C2-0x1d', op='0x1d', selector=None, status='verdict',
         verdict='rare, no impact: lo11-sibling of 0x16 family; 95% of '
                 'occurrences are a data table; not worth live slots',
         evidence=['WP-1 §4 (65/40 = 4030 mask/strict; i2a §5 cluster '
                   '0x20f-0x21a chains)'], conf=0.9),
    dict(id='C2-0x39', op='0x39', selector=None, status='live-fact',
         verdict='rare 64-bit transform in timestamp/counter code; live 1-'
                 'method: rs.low passthrough (V-r-39 echo 0x12345678) — '
                 'live-candidate for second confirmation',
         evidence=['WP-1 §4 (dc 0x2b254/0x12b1f4 contexts)', 'fuzz-4 task-06 '
                   'c2rare: alive, low32 = rs.low'], conf=0.7),
    dict(id='C2-0x3c', op='0x3c', selector=None, status='live-fact',
         verdict='rare 64-bit limit-compare helper (cert/timestamp paths); '
                 'live 1-method: writes 0 (V-r-3c sentinel -> 0) — '
                 'live-candidate for second confirmation',
         evidence=['WP-1 §4 (dc 0x154e58/0x2b29c4 contexts)', 'fuzz-4 task-06 '
                   'c2rare: alive, zero-write'], conf=0.7),
    dict(id='C2-0x3a', op='0x3a', selector=None, status='verdict',
         verdict='rare 64-bit mask/extract in timer code, no impact',
         evidence=['WP-1 §4 (ld.q.17 + masks 0xfffffffc003f, 6/3 sites)'],
         conf=0.85),
    dict(id='C2-0x20', op='0x20', selector=None, status='verdict',
         verdict='rare 64-bit increment/shift in timer block, no impact',
         evidence=['WP-1 §4 (dc 0x19a9a4 ld.q.17 + imm=1, 6/4 sites)'],
         conf=0.85),
    dict(id='C2-0x2d', op='0x2d', selector=None, status='verdict',
         verdict='noise-level, no impact', evidence=['WP-1 §4 (4/1 sites)'],
         conf=0.85),
    dict(id='C2-0x3b', op='0x3b', selector=None, status='verdict',
         verdict='noise-level (context = data zone A), no impact',
         evidence=['WP-1 §4 (2/1 sites)'], conf=0.85),
    dict(id='C2-0x22', op='0x22', selector=None, status='closed',
         verdict='branch-target instruction, definitive',
         evidence=['WP-1 §4 references earlier closure (recount §3: b.bset '
                   'targets an 0x22 word)'], conf=0.95),
    dict(id='V-38-sel0', op='0x38', selector={'sel': 0}, status='merged',
         verdict='cmp.w eq32 -> CMPRES latch (cmpop=0), merged in slaspec '
                 '(4f4f7b3); cmp38-self live fact: self-compare writes F',
         evidence=['fuzz-2 P2 live + task-08 §1-4 static 26/28 branch '
                   'consistency', 'fuzz-4 V-op38-self (7==7) -> F (1-method)',
                   'slaspec commit 4f4f7b3'], conf=0.95),
    dict(id='V-38-selne0', op='0x38', selector={'sel_set': 'ne0'},
         status='verdict',
         verdict='sel!=0 (rd-field) value-forms: closed as non-cc-writers in '
                 'tested forms (fuzz-4 ltV family-incompatibility); value '
                 'semantics open, census rows carry sites for completeness',
         evidence=['WP-2 §5: 7/32 words rd!=0 rendered UnkOp catch-all, C3 '
                   'closed without them', 'fuzz-4 task-06: sel!=0 on ltV '
                   'vectors — cmp does not write cc'], conf=0.7),
]


def attach_static(rows):
    by_id = {v['id']: v for v in VERDICTS}
    for row in rows:
        op = int(row['op'], 16)
        sel = row['selector']
        vid = None
        if op == 0x0d:
            vid = 'MERGED-0d'
        elif op == 0x0c:
            vid = 'H-0c-hi-and'
        elif op == 0x16:
            vid = 'H-16-shr'
        elif op == 0x34 and sel.get('f5') == 2 and sel.get('idx') == 1 \
                and sel.get('flag') == 0:
            vid = 'MERGED-34-bclr1'
        elif op == 0x34 and sel.get('f5') == 2 and sel.get('idx') == 5 \
                and sel.get('flag') == 0:
            vid = 'OPEN-34-f5=2-idx=5'
        elif op == 0x34 and sel.get('flag') == 0 and sel.get('f5') in (4, 6, 8, 0xc):
            vid = 'H-34-dep-R'
        elif op == 0x34 and sel.get('f5') == 27:
            vid = 'H-34-mmio'
        elif op == 0x33 and sel.get('f5') in (1, 4, 8):
            vid = 'H-33-dep-R' if sel['f5'] in (4, 8) else 'H-33-bit'
        elif op == 0x33 and sel.get('f5') == 0x18:
            vid = 'H-33-minmax'
        elif op == 0x33 and sel.get('f5') == 0x10 and sel.get('idx') == 14:
            vid = 'H-33-clamp16'
        elif op == 0x38 and sel.get('sel') == 0:
            vid = 'V-38-sel0'
        elif op == 0x38:
            vid = 'V-38-selne0'
        elif op in (0x1d, 0x39, 0x3c, 0x3a, 0x20, 0x2d, 0x3b, 0x22):
            vid = 'C2-0x%02x' % op
        if vid in by_id:
            row['static'] = {'verdict_id': vid,
                             'status': by_id[vid]['status']}
    return by_id


def h0c_model(rs, imm):
    return rs & ((imm << 16) | 0xffff) & 0xffffffff


def dep_replace_model(rs, rt, f5, idx):
    w = (1 << f5) - 1
    return ((rs & ~(w << idx)) | ((rt & w) << idx)) & 0xffffffff


def h16_model(rs, imm):
    return (rs >> (imm & 0x3f)) & 0xffffffffffffffff


def sanity(rows, versions, op_counts):
    fails = []
    by_id = {r['id']: r for r in rows}

    r = by_id['op34_f5=02_idx=01_flag=0']
    if not (r['class'] == 'has-sites' and r['sites']['4030'] == 1
            and r['site_examples']['4030'] == ['0x8c124']):
        fails.append('0x34 f5=2 idx=1 flag=0 row != merged bclr.1 fact: %s' % r)

    r = [x for x in rows if x['op'] == '0x0d'][0]
    if not (r['class'] == 'has-sites' and r['sites']['4030'] == 3393
            and r['static']['verdict_id'] == 'MERGED-0d'):
        fails.append('0x0d row != merged and.hi fact: %s' % r)

    live = [(0xabcd1234, 0x00ff, 0x00cd1234),
            (0x00000000, 0xff00, 0x00000000),
            (0x12345678, 0x0f00, 0x02005678)]
    for rs, imm, exp in live:
        got = h0c_model(rs, imm)
        if got != exp:
            fails.append('H-0c-hi-and live mismatch (%x,%x): %x != %x'
                         % (rs, imm, got, exp))
    if dep_replace_model(0xffffffff, 0, 6, 4) != 0xfffffc0f:
        fails.append('H-33/34-dep-R V-34-6 rogue mismatch')
    if h16_model(0x00100000, 0x28) != 0:
        fails.append('H-16-shr live mismatch')

    for ver, exp in OP_LEVEL_EXPECTED.items():
        for op, cnt in exp.items():
            if op_counts[ver][op] != cnt:
                fails.append('op-level %s op 0x%02x: %d != %d'
                             % (ver, op, op_counts[ver][op], cnt))
    for op, cnt in PROFILE_CX5.items():
        if op_counts['4030'][op] != cnt:
            fails.append('profile cx5 op 0x%02x: %d != %d'
                         % (op, op_counts['4030'][op], cnt))
    for op, cnt in PROFILE_CX4LX.items():
        exp = cnt + PROFILE_CX4LX_KNOWN_DELTA.get(op, 0)
        if op_counts['LX1900'][op] != exp:
            fails.append('profile cx4lx op 0x%02x: %d != %d (+known delta)'
                         % (op, op_counts['LX1900'][op], exp))

    for op in CORE_OPS:
        orows = [r for r in rows if int(r['op'], 16) == op and not r.get('f5_fill')]
        if op == 0x0d:
            continue
        total = sum(sum(r['sites'].values()) for r in orows)
        ops_total = sum(op_counts[v][op] for v in versions)
        if total != ops_total:
            fails.append('selector sums op 0x%02x: %d != %d'
                         % (op, total, ops_total))
    return fails


def main():
    rows, versions, op_counts = build_census()
    attach_static(rows)
    fails = sanity(rows, versions, op_counts)
    if fails:
        for f in fails:
            print('SANITY FAIL: %s' % f, file=sys.stderr)
        raise SystemExit(1)

    summary = {}
    for op in CORE_OPS:
        orows = [r for r in rows if int(r['op'], 16) == op]
        if orows:
            summary['0x%02x' % op] = {
                'rows': len(orows),
                'has_sites': sum(1 for r in orows if r['class'] == 'has-sites'),
                'zero_sites': sum(1 for r in orows if r['class'] == 'zero-sites'),
            }

    doc = {
        'meta': {
            'cycle': 'fuzz-5 task-1 (WP-4 static squeeze + census)',
            'method': 'code-mask = scripts/irisc/recount_codehist.classify; '
                      'strict = WP-1 journal §1.6 criterion; class = has-sites '
                      'iff >=1 strict site in any of 5 versions',
            'bins': {v: {'path': str(BINS[v][0].relative_to(REPO)),
                         'md5': BINS[v][1]} for v in BINS},
            'sites_definition': 'sites = code-mask counts (WP-1 §2.1 '
                                'compatible); sites_strict = strict counts',
            'f5_fill_rows': 'zero-site anchor rows completing f5 axis 0..31 '
                            'for ops 0x33/0x34/0x36 (selector f5-fill for '
                            'T2 sweep design)',
        },
        'summary': summary,
        'verdicts': VERDICTS,
        'rows': rows,
    }

    if '--check' in sys.argv:
        have = json.loads(OUT.read_text())
        fresh = {k: doc[k] for k in ('summary', 'verdicts', 'rows')}
        old = {k: have[k] for k in ('summary', 'verdicts', 'rows')}
        if fresh == old:
            print('CHECK PASS: census_map.json reproduces (%d rows)'
                  % len(rows))
            return
        raise SystemExit('CHECK FAIL: census_map.json drift')

    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + '\n')
    print('rows=%d (%s)' % (len(rows), ', '.join(
        '0x%02x:%d(has %d/zero %d)' % (int(k, 16), v['rows'], v['has_sites'],
                                       v['zero_sites'])
        for k, v in summary.items())))
    print('wrote %s' % OUT)


if __name__ == '__main__':
    main()
