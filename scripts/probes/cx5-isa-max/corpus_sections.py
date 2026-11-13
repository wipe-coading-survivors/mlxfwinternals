#!/usr/bin/env python3
"""isa-max A corpus expansion: ITOC enumeration + per-section classification
(offline, no hardware). Plan task 2026-10-31-irisc-isa-max-a Task 2 (C-A.0).

Methodology:
- enumerate ALL ITOC entries of the 5 md5-pinned FW images (entry/header CRC
  gated; refuse on image md5 drift);
- extract section payloads (de-clcrc via mlxfwutil.clcrc_unwrap when cl=1);
- classification: domain_prior from the docs/250-re/100-formats/040-fs4-domains.md VERIFIED execution
  domain table (iRISC = 0x02/0x03/0x04/0x05/0x06/0x07/0x0d/0x0e/0x15;
  PHY 0x0a/0x0b/0x0c = data; 0x18 = x86) and the docs/250-re/100-formats/020-fs3-sections.md part map
  (config/sig/device-data = data). Prior is confirmed per-instance by
  recount_codehist.classify() majority vote -- but ONLY for decode
  candidates: docs/250-re/100-formats/040-fs4-domains.md marks the classifier signal on PHY 16B-stride
  tables as false (iRISC-ratio 0.92-0.94), so PHY/ROM/config/sig sections
  are recorded with their prior and NOT decoded;
- 0x01/0x20 are not verified in docs/250-re/100-formats/040-fs4-domains.md: classified per-instance (evidence
  in journal 2026-11-01-irisc-isa-max-a-task-02.md);
- prior-vs-instance disagreement on a decode candidate: PriorDisagreement
  (hard stop, never a silent inclusion).

MAIN payload lineage vs census_map.py BINS: 4030/1619/CX6DX payloads are
byte-identical to the census bins; the 8008 census bin keeps an 8-byte tail
(payload+tail pinned there, payload pinned here); the census_map 'LX1900'
bin is a raw clcrc-framed 14.32.1912 section (journal §0.2) -- this corpus
pins the clean de-clcrc'd 14.32.1900-GCA payload, which reproduces the
cx4lx profile census exactly (7/7 ops).

Outputs: corpus_sections.json next to this script (committed); raw section
payloads + md5 manifest under build/cx5-isa-max/ (reproducible by
extraction, not committed). `--check` recomputes and diffs against the
committed JSON.
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

OUT = Path(__file__).resolve().parent / 'corpus_sections.json'
BUILD = REPO / 'build' / 'cx5-isa-max'
SECTIONS_DIR = BUILD / 'sections'

# version -> (image path relative to repo root, md5)
IMAGES = collections.OrderedDict([
    ('4030', ('refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx'
              '-UEFI-14.29.15-FlexBoot-3.6.902.bin',
              'a8c60c90473078288b01009c7cad471b')),
    ('8008', ('refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512A-ACA_Ax_Bx'
              '-UEFI-14.29.15-FlexBoot-3.6.902.bin',
              '7dce14844bb0aad995f9c4379836e0b7')),
    ('1619', ('refs/fw/cx-5-6/fw-ConnectX5-rel-16_19_1200-MCX556A-ECA_Ax'
              '-FlexBoot-3.5.110.bin',
              'ab4c5ac04bbbdeec6772611f79014d13')),
    ('LX1900', ('refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax'
                '-UEFI-14.25.17-FlexBoot-3.6.502.bin',
                '3bd3230b1deae0cf74a08e31d59021d9')),
    ('CX6DX', ('refs/fw/cx-5-6/fw-ConnectX6Dx-rel-22_50_1002-MCX623435AC'
               '-CDA_Ax-UEFI-14.43.10-FlexBoot-3.9.101.signed.bin',
               '35cb50eaefc8ac7da5e5c6c4e68870a6')),
])

SECTION_NAMES = {
    0x01: 'BOOT_CODE', 0x02: 'PCI_CODE', 0x03: 'MAIN_CODE',
    0x04: 'PCIE_LINK_CODE', 0x05: 'IRON_PREP_CODE',
    0x06: 'POST_IRON_BOOT_CODE', 0x07: 'UPGRADE_CODE', 0x08: 'HW_BOOT_CFG',
    0x09: 'HW_MAIN_CFG', 0x0a: 'PHY_UC_CODE', 0x0b: 'PHY_UC_CONSTS',
    0x0c: 'PCIE_PHY_UC_CODE', 0x0d: 'CCIR_INFRA_CODE',
    0x0e: 'CCIR_ALGO_CODE', 0x10: 'IMAGE_INFO', 0x11: 'FW_BOOT_CFG',
    0x12: 'FW_MAIN_CFG', 0x15: 'ACE_CODE', 0x18: 'ROM_CODE',
    0x20: 'RESET_INFO', 0x30: 'DBG_FW_INI', 0x32: 'DBG_FW_PARAMS',
    0x40: 'SLOT_DEPENDENT_INI',
}
# census key names (corpus_sites.jsonl / census_corpus.json 'section')
SHORT_NAMES = {
    0x01: 'BOOT', 0x02: 'PCI', 0x03: 'MAIN', 0x04: 'PCIE_LINK',
    0x05: 'IRON_PREP', 0x06: 'POST_IRON', 0x07: 'UPGRADE',
    0x0d: 'CCIR_INFRA', 0x0e: 'CCIR_ALGO', 0x15: 'ACE',
    0x20: 'RESET_INFO',
}

# docs/250-re/100-formats/040-fs4-domains.md verified execution domains + 020-fs3-sections.md part map (configs/signature/
# device data are non-executable blobs). 0x01/0x20 intentionally absent:
# not verified in docs/250-re/100-formats/040-fs4-domains.md -> per-instance classification.
DOMAIN_PRIOR = {}
for _t in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0d, 0x0e, 0x15):
    DOMAIN_PRIOR[_t] = 'irisc'
for _t in (0x0a, 0x0b, 0x0c):
    DOMAIN_PRIOR[_t] = 'data'  # PHY: 16B-stride tables, classifier false-signal
DOMAIN_PRIOR[0x18] = 'x86'    # FlexBoot option ROM
for _t in (0x08, 0x09, 0x10, 0x11, 0x12, 0x30, 0x32, 0x40):
    DOMAIN_PRIOR[_t] = 'data'  # config
for _t in range(0xa0, 0xae):   # signature v1/v2
    DOMAIN_PRIOR[_t] = 'data'
for _t in range(0xe0, 0xfc):   # device data / FS4 extras
    DOMAIN_PRIOR[_t] = 'data'

# sections the per-instance classifier runs on (docs/250-re/100-formats/040-fs4-domains.md prior + unverified)
DECODE_CANDIDATES = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x0d, 0x0e, 0x15, 0x20}

IRISC_MIN_CODE_FRAC = 0.5


class PriorDisagreement(Exception):
    pass


def load_image(ver):
    rel, md5_expect = IMAGES[ver]
    path = REPO / rel
    buf = path.read_bytes()
    md5 = hashlib.md5(buf).hexdigest()
    if md5 != md5_expect:
        raise SystemExit('input drift %s: %s md5 %s != %s'
                         % (ver, path, md5, md5_expect))
    return Image(buf, str(path))


def extract_payload(raw, cl):
    if cl:
        return clcrc_unwrap(raw)
    return raw, b''


def section_stats(payload):
    n = len(payload) // 4
    if n == 0:
        return {'words': 0, 'code_words': 0, 'code_frac': None,
                'known_frac': None, 'unk_code_words': 0}
    words = struct.unpack_from('>%dI' % n, payload, 0)
    feat, ops, code, cover, votes, wstats = RC.classify(words, n)
    ncode = sum(code)
    known = sum(1 for w in words if (w >> 26) in RC.KNOWN30)
    unk_code = sum(1 for i, w in enumerate(words)
                   if code[i] and (w >> 26) not in RC.KNOWN30)
    return {'words': n, 'code_words': ncode,
            'code_frac': round(ncode / n, 4),
            'known_frac': round(known / n, 4),
            'unk_code_words': unk_code}


def classify_section(section_type, payload):
    """(classification, decode_stats). Prior-vs-instance disagreement on a
    decode candidate raises PriorDisagreement (never a silent inclusion)."""
    prior = DOMAIN_PRIOR.get(section_type)
    if section_type not in DECODE_CANDIDATES:
        return (prior if prior else 'unknown'), None
    stats = section_stats(payload)
    frac = stats['code_frac'] or 0.0
    instance = 'irisc' if frac >= IRISC_MIN_CODE_FRAC else 'data'
    if prior == 'irisc' and instance != 'irisc':
        raise PriorDisagreement(
            'section 0x%02x: docs/250-re/100-formats/040-fs4-domains.md prior irisc but classifier says %s '
            '(code_frac %.3f) -- stop and investigate, do not include'
            % (section_type, instance, frac))
    return instance, stats


def load_census_map():
    import importlib.util
    p = REPO / 'scripts' / 'probes' / 'cx5-fuzz5' / 'census_map.py'
    spec = importlib.util.spec_from_file_location('census_map', p)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(str(p))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def lineage_checks(mains):
    """Cross-pin MAIN payloads against the census_map.py BINS lineage."""
    cm = load_census_map()
    fails = []
    for ver in ('4030', '1619', 'CX6DX'):
        if mains[ver]['payload_md5'] != cm.BINS[ver][1]:
            fails.append('%s MAIN payload md5 != census_map bin pin' % ver)
    p8 = mains['8008']['payload_with_tail_md5']
    if p8 != cm.BINS['8008'][1]:
        fails.append('8008 MAIN payload+tail md5 != census_map bin pin')
    # LX1900: census bin is a raw clcrc-framed 14.32.1912 section (journal
    # §0.2) -- no byte equality possible with the clean 1900-GCA payload;
    # the corpus pin below is the lineage anchor instead.
    if mains['LX1900']['payload_md5'] != (
            '2c3188aa1c92b0380c02e316b7b74017'):
        fails.append('LX1900 MAIN payload md5 != 1900-GCA lineage pin')
    return fails


def enumerate_sections(write_bins=True):
    rows = []
    mains = {}
    manifest = []
    for ver in IMAGES:
        img = load_image(ver)
        if not img.header_crc_ok('ITOC'):
            raise SystemExit('%s: ITOC header CRC bad' % ver)
        for e in img.entries('ITOC'):
            if not img.entry_crc_ok(e):
                raise SystemExit('%s: ITOC entry 0x%02x CRC bad'
                                 % (ver, e.type))
            if e.type in DECODE_CANDIDATES and (e.zipped or e.enc):
                raise SystemExit('%s: decode candidate 0x%02x zipped/encrypted'
                                 ' -- unsupported' % (ver, e.type))
            raw = img.section_data(e)
            payload, tail = extract_payload(raw, e.clcrc)
            classification, stats = classify_section(e.type, payload)
            row = {
                'fw': ver,
                'type': '0x%02x' % e.type,
                'name': SECTION_NAMES.get(e.type, 'UNKNOWN'),
                'short': SHORT_NAMES.get(e.type),
                'size': e.size,
                'cl': e.clcrc,
                'zipped': e.zipped,
                'param0': e.param0,
                'param1': e.param1,
                'flash_addr': e.addr,
                'payload_size': len(payload),
                'tail_size': len(tail),
                'md5': hashlib.md5(payload).hexdigest(),
                'domain_prior': DOMAIN_PRIOR.get(e.type),
                'classification': classification,
                'decode_stats': stats,
            }
            rows.append(row)
            if e.type == 0x03:
                mains[ver] = {
                    'payload_md5': row['md5'],
                    'payload_with_tail_md5': hashlib.md5(
                        payload + tail).hexdigest(),
                }
            if write_bins and payload:
                name = '%s_%s.bin' % (ver, row['short'] or row['type'])
                SECTIONS_DIR.mkdir(parents=True, exist_ok=True)
                (SECTIONS_DIR / name).write_bytes(payload)
                manifest.append('%s  %s' % (row['md5'], name))
    if write_bins:
        BUILD.mkdir(parents=True, exist_ok=True)
        (BUILD / 'sections.md5').write_text('\n'.join(manifest) + '\n')
    return rows, mains


def sanity(rows, mains):
    fails = lineage_checks(mains)
    mains_rows = [r for r in rows if r['type'] == '0x03']
    if len(mains_rows) != len(IMAGES):
        fails.append('MAIN 0x03 rows != 5')
    for r in mains_rows:
        if not (r['cl'] == 1 and r['classification'] == 'irisc'
                and r['param0'] != 0):
            fails.append('MAIN %s unexpected shape: %s' % (r['fw'], r))
    reset = [r for r in rows if r['type'] == '0x20']
    if len(reset) != len(IMAGES):
        fails.append('RESET_INFO rows != 5')
    for r in reset:
        if r['classification'] != 'data' or \
                r['decode_stats']['code_words'] != 0:
            fails.append('RESET_INFO %s not data/zero-code: %s'
                         % (r['fw'], r['decode_stats']))
    # docs/250-re/100-formats/020-fs3-sections.md: param0 nonzero only for code sections; ACE 0x15 is the
    # sole prior-irisc exception in this corpus (param0=0 -> ptr window of
    # the strict criterion disabled, journal)
    for r in rows:
        if r['domain_prior'] == 'irisc' and r['param0'] == 0 \
                and r['type'] != '0x15':
            fails.append('prior-irisc 0x%s with param0=0' % r['type'])
    # per-instance verdicts for docs/250-re/100-formats/040-fs4-domains.md-unverified 0x20 are part of the gate
    return fails


def build_doc():
    rows, mains = enumerate_sections()
    fails = sanity(rows, mains)
    if fails:
        for f in fails:
            print('SANITY FAIL: %s' % f, file=sys.stderr)
        raise SystemExit(1)
    return {
        'meta': {
            'cycle': 'isa-max-a task-2 (C-A.0 corpus expansion)',
            'method': 'ITOC enumeration of 5 pinned FW images; payload '
                      'de-clcrc at cl=1; domain_prior = docs/250-re/100-formats/040-fs4-domains.md '
                      'verified execution domains (+020-fs3-sections.md '
                      'part map); '
                      'per-instance confirm = recount_codehist.classify '
                      'majority vote, decode candidates only; '
                      'prior/instance disagreement = hard stop',
            'images': {v: {'path': p, 'md5': m}
                       for v, (p, m) in IMAGES.items()},
            'irisc_min_code_frac': IRISC_MIN_CODE_FRAC,
            'lineage': {
                'main_vs_census_map_bins': '4030/1619/CX6DX payload md5 == '
                                          'census_map bin pins; 8008 payload'
                                          '+tail == pin (bin keeps tail)',
                'LX1900': 'census_map bin bea1027c is a raw clcrc-framed '
                          '14.32.1912 section (journal '
                          '2026-11-01-irisc-isa-max-a-task-02 §0.2); corpus '
                          'pins the clean 1900-GCA payload (reproduces the '
                          'cx4lx profile census 7/7 ops)',
                'LX1900_main_payload_md5': mains['LX1900']['payload_md5'],
            },
            'unverified_types': '0x01 absent in all 5 images; 0x20 '
                                'RESET_INFO classified per-instance: data '
                                '(0 code words in all 5; byte-identical '
                                'across 4030/8008/LX1900/CX6DX, differs in '
                                '1619)',
            'raw_bins': 'build/cx5-isa-max/sections/ + sections.md5 '
                        '(reproducible by extraction, not committed)',
        },
        'sections': rows,
    }


def main():
    doc = build_doc()
    if '--check' in sys.argv:
        have = json.loads(OUT.read_text())
        if have == doc:
            print('CHECK PASS: corpus_sections.json reproduces (%d rows)'
                  % len(doc['sections']))
            return
        raise SystemExit('CHECK FAIL: corpus_sections.json drift')
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + '\n')
    print('sections=%d (%s)' % (
        len(doc['sections']),
        ', '.join('%s:%d' % (v, sum(1 for r in doc['sections']
                                    if r['fw'] == v)) for v in IMAGES)))
    print('wrote %s' % OUT)


if __name__ == '__main__':
    main()
