#!/usr/bin/env python3
"""cx5 cond-stub RF3b (Task 4): burn-ready image builder (offline).

Builds build/cx5-cond-stub-{w-a,w-b,w-c}.bin from the CANONICAL stock 4030
CDA image: S0 boot-marker (docs/250-re/120-irisc/025-boot-injection.md canon, cross-checked against
scripts/s2/build_s2.py) + site hook (H0 0x106390 for w-a/w-b, H2 0x1078a0
for w-c) + conditional stub (Task 3 rf3_stub_draft STUB_WORDS, imported
as-is) + card GUID/MAC bake (Rule 3) + 0x30 DBG_FW_INI build-ID (Rules 1-2).
NO burn here (owner-gated Task 5); no live operations.

Per-version patch map (dc = MAIN_CODE de-clcrc byte offset, rt = dc+0x800000):
  dc 0x1d594          stock 0x940002de call 0x1e10c -> 0x940DC067
                      call 0x38d730 (S0 boot injection, docs/250-re/120-irisc/025-boot-injection.md)
  dc 0x38d730..0x38d744  6-word S0 shellcode: CR 0x23f0 = 0xbadc0001
  w-a/w-b: dc 0x106390  stock 0x94fc5373 call 0x1b15c -> 0x940a1cf0
                      call 0x38d750 (H0 hook, R-E canon)
  w-c:     dc 0x1078a0  stock 0x94fffeb5 call 0x107374 -> 0x940a17ac
                      call 0x38d750 (H2 hook, rf1 canon word)
  dc 0x38d750..       STUB_WORDS[ver] (w-a 18 w / w-b 14 w / w-c 14 w of
                      the 34-w slot, slack >= 2; cutout 0x38d748..0x38d74f
                      stays zero)
  DTOC 0xE1/0xE0      Base GUID/MAC from hw registry CARD_CX5_EDR100
  ITOC 0x30           build-ID '; mlxini cx5 cond-stub <ver> ...' after
                      the banner; vendor ';;' comments trimmed to keep the
                      section in place with >=32 B headroom (Rule 2)

Gates (in-script, log APPEND build/cx5-cond-stub.log):
  [0] base md5 + MAIN_CODE geometry + stock words (injection site + dead
      self-jump, hook sites H0/H2, S0 zone/slot/cutout zero)
  G1 S0 literals decode-verified (strict cx5 assemble + per-word
      dis->re-assemble bit-exact) + canon cross-check docs/250-re/120-irisc/025-boot-injection.md x
      scripts/s2/build_s2.py (all 7 words in docs/250-re/120-irisc/025-boot-injection.md; injection word +
      S0 zone constants in build_s2.py) — plan fix R-E 1a45647
  G2 stub import gates: STUB_WORDS/HOOKS from rf3_stub_draft as-is
      (counts 18/14/14, placement in slot, slack >= 2, per-word
      dis->re-assemble re-verify, branch targets re-check, hook words:
      H0 == R-E canon 0x940a1cf0, H2 decode-verified)
  [1] code patch per version: word-diff == exactly the intended words;
      cutout zero; changed 68B clcrc lines == expected; patch_sections;
      step1 verify --deep PASS
  [2] 0x30 build-ID: banner insert, ';;'-only trim to headroom >= 32,
      mlxfwutil.py inject (no force), entry addr unchanged, size <=,
      round-trip
  [3] mlxfwutil.py guides: GUID/MAC baked (mDevInfo + MFG_INFO,
      self-verify) + library re-asserts + MAIN_CODE untouched
  [4] mlxfwutil.py verify --deep -> PASS
  [5] mstflint -i verify -> 'Image is bootable'; -i q identity
      (GUID/MAC embedded, PSID/FW invariant); -i dc build-ID is the first
      content line after the banner (Rule 1)
  [6] byte-diff vs stock: allowed = {MAIN_CODE changed lines + entry
      0x03 CRC bytes, 0x30 section + entry, mDevInfo, MFG_INFO + entry
      CRC bytes}; strays = none; every zone present; section-level diff
      == {ITOC 0x03, ITOC 0x30, DTOC 0xE1, DTOC 0xE0}
  [7] GT table build/cx5-cond-stub-gt.txt: dc->word, both classes
      (code + ro-data/string), words re-read from the STOCK image, stock
      == built in all three finals, all GT lines outside the patch zones
      of every build (w-c hook zone differs — recomputed per version)
  [8] determinism: full second pipeline run per version -> md5 identical
"""
import hashlib
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / 'scripts/probes/cx5-door-detour'))
import mlxfwutil
import rf3_stub_draft as rf3
import rf1_site_recon as rf1
from scripts.irisc import assemble, disasm as dis
from scripts.irisc.profiles import load_profile

BASE = rf3.BASE
BASE_MD5 = rf3.BASE_MD5
LOG = REPO / 'build/cx5-cond-stub.log'
GT = REPO / 'build/cx5-cond-stub-gt.txt'
DOC_S0_CANON = REPO / 'docs/250-re/120-irisc/025-boot-injection.md'
BUILD_S2 = REPO / 'scripts/s2/build_s2.py'

VERS = ('w-a', 'w-b', 'w-c')
OUT = {v: REPO / ('build/cx5-cond-stub-%s.bin' % v) for v in VERS}

CARD_GUID = int(mlxfwutil.hw('CARD_CX5_EDR100', 'guid'), 16)
CARD_MAC = int(mlxfwutil.hw('CARD_CX5_EDR100', 'mac'), 16)


def _site_tag(site):
    return 'H0' if site == rf3.H0 else 'H2'


BUILD_ID = {v: ('; mlxini cx5 cond-stub %s (2026-10-23, R-F spec): '
                '%s-hook -> stub @0x38d750, conditional echo'
                % (v, _site_tag(rf3.HOOKS[v]['site'])))
            for v in VERS}
BANNER = ';; Mellanox Technologies LTD'
HEADROOM_MIN = 32

S0_INJ_DC = 0x1d594
S0_INJ_STOCK = 0x940002de
S0_INJ_WORD = 0x940DC067
S0_SC_DC = 0x38d730
S0_SC_WORDS = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001,
               0x6ca03002, 0x95f24272]
S0_SC_DECODE = ['set2 r5,zero,0x0', 'set3 r5,r5,0x23f0',
                'set2 r6,zero,0xbadc', 'set3 r6,r6,0x1',
                'st.d r6,r5,0x0', 'jump 0x1e10c']

GT_CODE = [(0x01b15c, 'emit wrapper prologue (stock assert of re1/rb1)'),
           (0x106350, 'REGACC fn head word (rb1 1.4, contains H0)')]
GT_RODATA = [(0x34ab28, 'bytes of "icmd_generic_reg_access" string (rb1 L1)'),
             (0x37fe78, 'bytes of "isr_icmd, opcode=..." string (rb1 L0)')]


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


def fail(o, msg):
    o('FATAL: ' + msg)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open('a') as f:
        f.write('\n'.join(o.lines) + '\n')
    sys.exit(1)


def run(o, cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO))
    o('$ ' + ' '.join(cmd))
    for stream in (r.stdout, r.stderr):
        for line in stream.strip().splitlines():
            o('    ' + line)
    if r.returncode != 0:
        fail(o, 'rc=%d: %s' % (r.returncode, ' '.join(cmd)))
    return r


def wa(text, base):
    data = assemble(text, base=base, profile=load_profile('cx5'),
                    strict=True)
    return list(struct.unpack('>%dI' % (len(data) // 4), data))


def w32(b, off):
    return struct.unpack_from('>I', b, off)[0]


def gate0(o, buf):
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail(o, 'base md5 mismatch (canon %s)' % BASE_MD5)
    img = mlxfwutil.Image(bytes(buf), str(BASE))
    e = img.find_entry('ITOC', 0x03)
    if (e.addr, e.size, e.clcrc) != (rf3.ITOC3_ADDR, rf3.ITOC3_SIZE, 1):
        fail(o, 'MAIN_CODE header mismatch: addr=0x%x size=0x%x clcrc=%d'
             % (e.addr, e.size, e.clcrc))
    raw = img.section_data(e)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw or \
            len(code) != rf3.MAIN_BYTES:
        fail(o, 'de-clcrc round-trip / geometry failed on stock')
    if w32(code, S0_INJ_DC) != S0_INJ_STOCK or \
            dis(w32(code, S0_INJ_DC), S0_INJ_DC) != 'call 0x1e10c':
        fail(o, 'S0 injection site 0x%x is not stock call 0x1e10c'
             % S0_INJ_DC)
    if w32(code, S0_INJ_DC + 4) != 0x95000000:
        fail(o, 'dead self-jump @0x1d598 changed (docs/250-re/120-irisc/025-boot-injection.md)')
    if w32(code, rf3.H0) != rf3.H0_STOCK_WORD or \
            dis(w32(code, rf3.H0), rf3.H0) != \
            'call 0x%x' % rf3.H0_STOCK_TARGET:
        fail(o, 'H0 hook site 0x%x is not stock call 0x%x'
             % (rf3.H0, rf3.H0_STOCK_TARGET))
    if w32(code, rf3.H2) != rf1.H2_STOCK_WORD or \
            dis(w32(code, rf3.H2), rf3.H2) != \
            'call 0x%x' % rf1.EXECW:
        fail(o, 'H2 hook site 0x%x is not stock call 0x%x'
             % (rf3.H2, rf1.EXECW))
    zones = [('S0 shellcode zone', S0_SC_DC,
              S0_SC_DC + 4 * len(S0_SC_WORDS) - 1),
             ('stub slot', rf3.STUB_SLOT,
              rf3.STUB_SLOT + 4 * rf3.STUB_SLOT_WORDS - 4),
             ('cutout', rf3.CUTOUT[0], rf3.CUTOUT[1])]
    for name, lo, hi in zones:
        if any(w32(code, dc) for dc in range(lo, hi + 1, 4)):
            fail(o, '%s 0x%x..0x%x not zero on the stock base'
                 % (name, lo, hi))
    o('[0] base md5 OK (%s); MAIN_CODE addr=0x%x size=0x%x clcrc=1 '
      '(de-clcrc round-trip OK, %d words); inj site 0x%x=%08x '
      '"call 0x1e10c" + dead self-jump 0x1d598 intact; hook sites: '
      'H0 0x%x=%08x "call 0x%x", H2 0x%x=%08x "call 0x%x"; S0 zone 6w + '
      'slot %dw + cutout 2w zero'
      % (BASE_MD5, e.addr, e.size, rf3.MAIN_WORDS, S0_INJ_DC, S0_INJ_STOCK,
         rf3.H0, rf3.H0_STOCK_WORD, rf3.H0_STOCK_TARGET,
         rf3.H2, rf1.H2_STOCK_WORD, rf1.EXECW, rf3.STUB_SLOT_WORDS))
    return img, e, raw, code, tail


def gate_g1(o):
    if len(S0_SC_WORDS) != 6 or S0_SC_DECODE[5] != 'jump 0x1e10c':
        fail(o, 'S0 literal table shape drift')
    for i, (w, want) in enumerate(zip(S0_SC_WORDS, S0_SC_DECODE)):
        dc = S0_SC_DC + 4 * i
        got = dis(w, dc)
        if got != want:
            fail(o, 'S0 word %d decode %r != %r' % (i, got, want))
        if wa(got, dc)[0] != w:
            fail(o, 'S0 word %d dis->re-assemble drift' % i)
    if dis(S0_INJ_WORD, S0_INJ_DC) != 'call 0x%x' % S0_SC_DC:
        fail(o, 'S0 injection word decode drift')
    if wa(dis(S0_INJ_WORD, S0_INJ_DC), S0_INJ_DC)[0] != S0_INJ_WORD:
        fail(o, 'S0 injection word re-assemble drift')
    canon_txt = DOC_S0_CANON.read_text().lower()
    for w in S0_SC_WORDS + [S0_INJ_WORD]:
        if ('0x%08x' % w) not in canon_txt:
            fail(o, 'S0 word 0x%08x not found in docs/250-re/120-irisc/025-boot-injection.md canon text' % w)
    s2src = BUILD_S2.read_text()
    if '0x940DC067' not in s2src:
        fail(o, 'injection word 0x940DC067 not in scripts/s2/build_s2.py')
    if '0x38D730, 0x38D748' not in s2src:
        fail(o, 'S0 zone constants 0x38D730..0x38D748 not in build_s2.py')
    if 'S0 shellcode 0x38d730-0x38d747' not in s2src:
        fail(o, 'S0 zone assert string not in build_s2.py')
    o('[G1] S0: 6 shellcode words + injection word decode-verified (strict'
      ' cx5 assemble + dis->re-assemble bit-exact); canon cross-check '
      'docs/250-re/120-irisc/025-boot-injection.md (7/7 words present) x scripts/s2/build_s2.py (injection '
      'word 0x940DC067 + S0 zone 0x38D730..0x38D748 + zone assert) — '
      'canons agree (plan fix R-E 1a45647)')
    o('      dc       word     disasm')
    for i, w in enumerate(S0_SC_WORDS):
        o('      0x%06x  %08x  %s' % (S0_SC_DC + 4 * i, w, S0_SC_DECODE[i]))
    o('      0x%06x  %08x  %s' % (S0_INJ_DC, S0_INJ_WORD,
                                   dis(S0_INJ_WORD, S0_INJ_DC)))


def gate_g2(o):
    canon = {'w-a': 18, 'w-b': 14, 'w-c': 14}
    intended = {
        'w-a': {1: rf3.H0_STOCK_TARGET, 6: rf3.WA_ARM_NE_DC,
                11: rf3.WA_JOIN_DC},
        'w-b': {1: rf3.H0_STOCK_TARGET, 6: rf3.WB_MISS_DC},
        'w-c': {1: rf1.SITE_TABLE['H2']['stock_target'],
                6: rf3.WC_MISS_DC},
    }
    for ver in VERS:
        ws = rf3.STUB_WORDS[ver]
        n = len(ws)
        if n != canon[ver]:
            fail(o, '%s stub is %d words, canon %d' % (ver, n, canon[ver]))
        slack = rf3.STUB_SLOT_WORDS - n
        if slack < rf3.SLACK_MIN or n > rf3.STUB_MAX_WORDS:
            fail(o, '%s budget: %d words, slack %d' % (ver, n, slack))
        for i, (dc, w) in enumerate(ws):
            if dc != rf3.STUB_SLOT + 4 * i:
                fail(o, '%s placement drift at %d: dc 0x%x' % (ver, i, dc))
            if not rf3.STUB_SLOT <= dc < \
                    rf3.STUB_SLOT + 4 * rf3.STUB_SLOT_WORDS:
                fail(o, '%s word %d dc 0x%x outside the slot' % (ver, i, dc))
            if rf3.CUTOUT[0] <= dc <= rf3.CUTOUT[1]:
                fail(o, '%s word %d dc 0x%x inside the cutout' % (ver, i, dc))
            if wa(dis(w, dc), dc)[0] != w:
                fail(o, '%s word %d dis->re-assemble drift' % (ver, i))
        for i, (dc, w) in enumerate(ws):
            tgt = rf3._branch_target(w, dc)
            if tgt is None:
                continue
            if i not in intended[ver] or tgt != intended[ver][i]:
                fail(o, '%s G5 re-check: word %d @0x%x resolves 0x%x != '
                     'intended' % (ver, i, dc, tgt))
        h = rf3.HOOKS[ver]
        if dis(h['word'], h['site']) != 'call 0x%x' % rf3.STUB_SLOT:
            fail(o, '%s hook word decode drift' % ver)
        if h['simm24'] != (rf3.STUB_SLOT - h['site']) // 4:
            fail(o, '%s hook simm24 drift' % ver)
    if rf3.HOOKS['w-a']['word'] != rf3.H0_HOOK_WORD or \
            rf3.HOOKS['w-b']['word'] != rf3.H0_HOOK_WORD:
        fail(o, 'w-a/w-b hook word != R-E canon 0x940a1cf0')
    if rf3.HOOKS['w-c']['word'] != rf1.HOOK_PATCHES['H2']['word']:
        fail(o, 'w-c hook word != rf1 H2 canon word')
    o('[G2] stub import: STUB_WORDS/HOOKS from rf3_stub_draft as-is '
      '(w-a 18 w / w-b 14 w / w-c 14 w of %d, slack %d/%d/%d >= %d); '
      'placement in slot, cutout untouched; every word re-verified '
      'dis->re-assemble bit-exact; branch targets re-resolved from the '
      'encoded bits == intended; hooks: H0 %08x (== R-E canon 0x940a1cf0) '
      'for w-a/w-b, H2 %08x (rf1 canon) for w-c, both decode '
      '"call 0x%x"'
      % (rf3.STUB_SLOT_WORDS, rf3.STUB_SLOT_WORDS - 18,
         rf3.STUB_SLOT_WORDS - 14, rf3.STUB_SLOT_WORDS - 14,
         rf3.SLACK_MIN, rf3.HOOK_WORD, rf3.HOOKS['w-c']['word'],
         rf3.STUB_SLOT))


def build_code(o, img, raw, code, tail, ver):
    h = rf3.HOOKS[ver]
    patch = {S0_INJ_DC: S0_INJ_WORD, h['site']: h['word']}
    for i, w in enumerate(S0_SC_WORDS):
        patch[S0_SC_DC + 4 * i] = w
    for dc, w in rf3.STUB_WORDS[ver]:
        patch[dc] = w
    intended = 6 + 1 + 1 + len(rf3.STUB_WORDS[ver])
    if len(patch) != intended:
        fail(o, '%s patch map size drift: %d != %d'
             % (ver, len(patch), intended))
    new_code = bytearray(code)
    for dc, w in patch.items():
        new_code[dc:dc + 4] = struct.pack('>I', w)
    new_code = bytes(new_code)
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(new_code, dc)]
    if sorted(changed) != sorted(patch):
        fail(o, '%s word-diff 0x..: %s != intended %d words'
             % (ver, [hex(d) for d in changed], len(patch)))
    for dc in changed:
        if w32(new_code, dc) != patch[dc]:
            fail(o, '%s patched word @0x%x mismatch' % (ver, dc))
    if any(w32(new_code, dc) for dc in
           range(rf3.CUTOUT[0], rf3.CUTOUT[1] + 1, 4)):
        fail(o, '%s cutout 0x38d748-0x38d74f touched' % ver)
    exp_lines = sorted({dc // 64 for dc in patch})
    new_raw = mlxfwutil.clcrc_wrap(new_code, tail)
    diff_lines = [i for i in range(len(code) // 64)
                  if raw[i * 68:(i + 1) * 68] !=
                  new_raw[i * 68:(i + 1) * 68]]
    if diff_lines != exp_lines:
        fail(o, '%s changed 68B lines %s != expected %s'
             % (ver, diff_lines, exp_lines))
    edits = [(0x03, i * 68, new_raw[i * 68:(i + 1) * 68])
             for i in diff_lines]
    out = mlxfwutil.patch_sections(img, edits)
    pimg = mlxfwutil.Image(out, 'step1', base=img.base, fmt=img.fmt)
    praw = pimg.section_data(pimg.find_entry('ITOC', 0x03))
    if praw != new_raw:
        fail(o, '%s built MAIN_CODE raw mismatch' % ver)
    if mlxfwutil.clcrc_wrap(*mlxfwutil.clcrc_unwrap(praw)) != praw:
        fail(o, '%s per-line clcrc round-trip failed on step1' % ver)
    errs = mlxfwutil.verify_image(pimg, deep=True)
    if errs:
        fail(o, '%s step1 verify --deep failed: %s' % (ver, errs))
    step1 = REPO / ('build/cx5-cond-stub-%s.step1.bin' % ver)
    step1.write_bytes(out)
    o('[1] %s code patch: %d words (S0 6 + inj 1 + hook 1 @0x%x + stub '
      '%d); word-diff == exactly the intended set; cutout zero; changed '
      '68B clcrc lines %s == expected; patch_sections OK (sec/entry CRC);'
      ' step1 verify --deep PASS; md5 %s'
      % (ver, len(patch), h['site'], len(rf3.STUB_WORDS[ver]),
         [hex(i) for i in diff_lines], hashlib.md5(out).hexdigest()))
    return step1, exp_lines


def gate_030(o, step1, img, ver):
    e30 = img.find_entry('ITOC', 0x30)
    ini = REPO / ('build/cx5-cond-stub-%s.ini' % ver)
    ini_rt = REPO / ('build/cx5-cond-stub-%s.ini.rt' % ver)
    step2 = REPO / ('build/cx5-cond-stub-%s.step2.bin' % ver)
    run(o, ['python3', 'mlxfwutil.py', 'extract', str(step1), '-s', '0x30',
            '-o', str(ini)])
    text = ini.read_text(encoding='latin1')
    lines = text.splitlines(keepends=True)
    banners = [i for i, l in enumerate(lines) if l.startswith(BANNER)]
    if len(banners) != 1:
        fail(o, '%s: expected exactly one %r banner, got %d'
             % (ver, BANNER, len(banners)))
    if any(l.startswith('; mlxini ') for l in lines):
        fail(o, '%s: stock ini already carries a build-ID line' % ver)
    bi = banners[0]
    lines.insert(bi + 1, BUILD_ID[ver] + '\n')
    kv0 = sum(1 for l in lines if l.strip() and not l.startswith(';'))
    cand = [i for i, l in enumerate(lines)
            if l.startswith(';;') and i != bi]
    dropped = []

    def cur_text():
        ds = set(dropped)
        return ''.join(l for i, l in enumerate(lines) if i not in ds)

    def zw_pad(t):
        d = zlib.compress(t.encode('latin1'), 9)
        return len(d) + (4 - len(d) % 4) % 4

    while zw_pad(cur_text()) > e30.size - HEADROOM_MIN:
        if not cand:
            fail(o, '%s 0x30: no ;; lines left to trim, still over budget'
                 % ver)
        dropped.append(cand.pop(0))
    ini_final = cur_text()
    kv1 = sum(1 for l in lines if l.strip() and not l.startswith(';'))
    if kv0 != kv1:
        fail(o, '%s key=value line count changed: %d -> %d'
             % (ver, kv0, kv1))
    if zw_pad(ini_final) > e30.size - HEADROOM_MIN:
        fail(o, '%s 0x30 budget: packed %d > %d - %d'
             % (ver, zw_pad(ini_final), e30.size, HEADROOM_MIN))
    o('[2] %s 0x30: stock packed %d vs e.size %d (local zlib drift, '
      'docs/250-re/120-irisc/025-boot-injection.md); build-ID inserted after the banner; trimmed %d '
      'vendor ;; comment lines (key=value lines intact: %d); final '
      'packed %d, headroom %d >= %d'
      % (ver, zw_pad(text), e30.size, len(dropped), kv1,
         zw_pad(ini_final), e30.size - zw_pad(ini_final), HEADROOM_MIN))
    for i in dropped:
        o('      trim: %r' % lines[i].rstrip())
    ini.write_text(ini_final, encoding='latin1')
    run(o, ['python3', 'mlxfwutil.py', 'inject', str(step1), str(ini), '-o',
            str(step2)])
    simg = mlxfwutil.Image(step2.read_bytes(), 'step2', base=img.base,
                        fmt=img.fmt)
    e30n = simg.find_entry('ITOC', 0x30)
    if e30n.addr != e30.addr:
        fail(o, '%s 0x30 relocated: 0x%x -> 0x%x'
             % (ver, e30.addr, e30n.addr))
    if e30n.size > e30.size or e30.size - e30n.size < HEADROOM_MIN:
        fail(o, '%s 0x30 size gate: 0x%x -> 0x%x (headroom %d)'
             % (ver, e30.size, e30n.size, e30.size - e30n.size))
    run(o, ['python3', 'mlxfwutil.py', 'extract', str(step2), '-s', '0x30',
            '-o', str(ini_rt)])
    if ini_rt.read_text(encoding='latin1') != ini_final:
        fail(o, '%s 0x30 round-trip mismatch' % ver)
    o('      0x30 in place @0x%x, size 0x%x -> 0x%x (headroom %d), '
      'round-trip == edited text OK'
      % (e30n.addr, e30.size, e30n.size, e30.size - e30n.size))
    ini_rt.unlink()
    ini.unlink()
    return step2


def gate_guides(o, step2, img, ver):
    out = OUT[ver]
    run(o, ['python3', 'mlxfwutil.py', 'guides', str(step2), '--guid',
            '0x%016x' % CARD_GUID, '--mac', '0x%012x' % CARD_MAC,
            '-o', str(out)])
    fimg = mlxfwutil.Image(out.read_bytes(), 'final', base=img.base,
                        fmt=img.fmt)
    valid = mlxfwutil.find_valid_devinfo(fimg)
    if len(valid) != 1:
        fail(o, '%s: expected exactly 1 valid mDevInfo, got %d'
             % (ver, len(valid)))
    m = mlxfwutil.MDevInfo.parse(fimg.section_data(valid[0]))
    if (m.guid, m.mac) != (CARD_GUID, CARD_MAC) or not m.crc_ok():
        fail(o, '%s mDevInfo guid/mac mismatch after bake: 0x%x/0x%x'
             % (ver, m.guid, m.mac))
    d0 = fimg.section_data(fimg.find_entry('DTOC', 0xE0))
    baked = (int.from_bytes(d0[0x28:0x30], 'big'),
             int.from_bytes(d0[0x38:0x40], 'big'))
    if baked != (CARD_GUID, CARD_MAC):
        fail(o, '%s MFG_INFO guid/mac mismatch after bake: %x/%x'
             % (ver, baked[0], baked[1]))
    s1 = mlxfwutil.Image(step2.read_bytes(), 'step2-r', base=img.base,
                      fmt=img.fmt)
    if fimg.section_data(fimg.find_entry('ITOC', 0x03)) != \
            s1.section_data(s1.find_entry('ITOC', 0x03)):
        fail(o, '%s guides bake touched MAIN_CODE' % ver)
    o('[3] %s guides: mDevInfo guid %016x mac %012x + MFG_INFO baked, '
      'CRC ok, self-verify PASS (CLI); MAIN_CODE untouched by the bake'
      % (ver, CARD_GUID, CARD_MAC))
    return fimg


def gate_mstflint(o, ver):
    out = OUT[ver]
    r = run(o, ['mstflint', '-i', str(out), 'verify'])
    if 'bootable' not in (r.stdout + r.stderr) or \
            'verification succeeded' not in (r.stdout + r.stderr):
        fail(o, '%s mstflint verify did not report bootable' % ver)

    def q(path):
        r = subprocess.run(['mstflint', '-i', str(path), 'q'],
                           capture_output=True, text=True, cwd=str(REPO))
        got = {}
        for l in (r.stdout + r.stderr).splitlines():
            for k in ('FW Version', 'PSID', 'Base GUID', 'Base MAC'):
                if l.strip().startswith(k + ':'):
                    rest = l.split(':', 1)[1].split()
                    got[k] = rest[0] if rest else ''
        return got
    qs, qf = q(BASE), q(out)
    for k in ('FW Version', 'PSID'):
        if qf.get(k) != qs.get(k):
            fail(o, '%s identity %s changed vs stock: %r -> %r'
                 % (ver, k, qs.get(k), qf.get(k)))
    if qf.get('Base GUID', '').lower() != '%016x' % CARD_GUID or \
            qf.get('Base MAC', '').lower() != '%012x' % CARD_MAC:
        fail(o, '%s identity guid/mac not the card ones: %r' % (ver, qf))
    o('      stock q: Base GUID %s, Base MAC %s (zeros baked -> N/A)'
      % (qs.get('Base GUID'), qs.get('Base MAC')))
    for k in ('FW Version', 'PSID', 'Base GUID', 'Base MAC'):
        o('      %s: %s' % (k, qf.get(k)))
    r = subprocess.run(['mstflint', '-i', str(out), 'dc'],
                       capture_output=True, text=True, cwd=str(REPO))
    if r.returncode != 0:
        fail(o, '%s mstflint dc rc=%d: %s'
             % (ver, r.returncode, r.stderr.strip()))
    dl = [l.rstrip() for l in (r.stdout + r.stderr).splitlines()]
    try:
        mi = next(i for i, l in enumerate(dl) if BUILD_ID[ver] in l)
    except StopIteration:
        fail(o, '%s mstflint dc does not show the build-ID' % ver)
    pre = [l for l in dl[:mi]
           if l.strip() and not l.startswith(('-E-', '-W-', '-I-', '-'))]
    if any(not l.startswith(';;') for l in pre) or len(pre) > 1:
        fail(o, '%s build-ID is not right after the banner (pre: %r)'
             % (ver, pre))
    o('[5] %s mstflint: verify bootable; q identity (GUID/MAC embedded, '
      'FW/PSID invariant vs stock); dc build-ID is the first content line '
      'after the banner (Rule 1)' % ver)


def gate_diff(o, img, fimg, ver, exp_lines):
    buf = BASE.read_bytes()
    out = OUT[ver].read_bytes()
    e03 = img.find_entry('ITOC', 0x03)
    e30 = img.find_entry('ITOC', 0x30)
    e1 = img.find_entry('DTOC', 0xE1)
    e0 = img.find_entry('DTOC', 0xE0)
    ent03 = img.itoc_off + 32 + e03.index * 32
    ent30 = img.itoc_off + 32 + e30.index * 32
    entE0 = img.dtoc_off + 32 + e0.index * 32
    zones = {}
    for ln in exp_lines:
        zones['MAIN_CODE line %d' % ln] = range(e03.addr + ln * 68,
                                                e03.addr + ln * 68 + 68)
    zones['ITOC 0x03 entry CRC'] = range(ent03 + 0x1a, ent03 + 0x20)
    zones['0x30 section'] = range(e30.addr, e30.addr + e30.size)
    zones['ITOC 0x30 entry'] = range(ent30, ent30 + 32)
    zones['mDevInfo'] = range(e1.addr, e1.addr + e1.size)
    zones['MFG_INFO'] = range(e0.addr, e0.addr + e0.size)
    zones['DTOC 0xE0 entry CRC'] = range(entE0 + 0x1a, entE0 + 0x20)
    allowed = set()
    for r in zones.values():
        allowed |= set(r)
    diffs = [i for i in range(len(out)) if out[i] != buf[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    o('[6] %s byte-diff vs stock: %d bytes in %d zones; strays: %s'
      % (ver, len(diffs), len(zones), stray or 'none'))
    if stray:
        fail(o, '%s stray diff bytes outside the intended zones: %s'
             % (ver, stray))
    for name, r in zones.items():
        if not any(i in diffs for i in r):
            fail(o, '%s expected zone has no diff bytes: %s' % (ver, name))
    fdata = {}
    for toc in ('ITOC', 'DTOC'):
        for e in fimg.entries(toc):
            fdata[(toc, e.type)] = e
    changed_secs = []
    for toc in ('ITOC', 'DTOC'):
        for e in img.entries(toc):
            fe = fdata.get((toc, e.type))
            if fe is None or img.section_data(e) != fimg.section_data(fe):
                changed_secs.append('%s 0x%02x' % (toc, e.type))
    if sorted(changed_secs) != ['DTOC 0xe0', 'DTOC 0xe1',
                                'ITOC 0x03', 'ITOC 0x30']:
        fail(o, '%s section-level diff %s != {ITOC 0x03, ITOC 0x30, '
             'DTOC 0xE1, DTOC 0xE0}' % (ver, sorted(changed_secs)))
    o('      section-level diff: %s (Rule 4: S0/hook/stub lines inside '
      'MAIN_CODE 0x03, 0x30, mDevInfo/MFG_INFO only)'
      % sorted(changed_secs))


def gate_gt(o, img, finals, exp_lines_all):
    code, _ = mlxfwutil.clcrc_unwrap(
        img.section_data(img.find_entry('ITOC', 0x03)))
    fcodes = {}
    for ver in VERS:
        fcodes[ver] = mlxfwutil.clcrc_unwrap(
            finals[ver].section_data(finals[ver].find_entry('ITOC', 0x03)))[0]
    entries = []
    for dc, note in GT_CODE + GT_RODATA:
        if dc % 4:
            fail(o, 'GT dc 0x%x not ld.d-aligned' % dc)
        for ver in VERS:
            if dc // 64 in exp_lines_all[ver]:
                fail(o, 'GT dc 0x%x falls into a patched 68B line of %s'
                     % (dc, ver))
        w_stock = w32(code, dc)
        for ver in VERS:
            if w32(fcodes[ver], dc) != w_stock:
                fail(o, 'GT dc 0x%x word changed stock->built (%s)'
                     % (dc, ver))
        entries.append((dc, w_stock, note))
    body = [
        '# cx5 cond-stub ground truth (Task 4 Step 5; consumed by Task 5)',
        '# words read from the STOCK image MAIN_CODE (ITOC 0x03 de-clcrc);',
        '# dc = MAIN_CODE byte offset, rt = dc + 0x800000; all dc are '
        'ld.d-aligned (dc % 4 == 0)',
        '# gate: every word unchanged in build/cx5-cond-stub-{w-a,w-b,'
        'w-c}.bin and outside their patch lines',
        '# format: <dc-hex> <word-hex> ; "#"-lines are comments',
        '# class code (MAIN_CODE instruction words):',
    ]
    for dc, w, note in entries[:len(GT_CODE)]:
        body.append('0x%06x 0x%08x  # %s [%s]' % (dc, w, dis(w, dc), note))
    body.append('# class ro-data/string (ASCII bytes of the door trace '
                'strings):')
    for dc, w, note in entries[len(GT_CODE):]:
        body.append('0x%06x 0x%08x  # %r [%s]'
                    % (dc, w, struct.pack('>I', w), note))
    GT.parent.mkdir(parents=True, exist_ok=True)
    GT.write_text('\n'.join(body) + '\n')
    for l in body:
        o('      ' + l)
    o('[7] GT table: %d code + %d ro-data entries re-read from the STOCK '
      'image, stock == built word-wise in all three finals, outside the '
      'patched lines of every build (w-c hook zone recomputed) -> %s'
      % (len(GT_CODE), len(GT_RODATA), GT))


def pipeline(o, ver):
    """[1] code patch -> [2] 0x30 -> [3] guides for one version.
    Returns (final Image, exp_lines)."""
    buf = BASE.read_bytes()
    img, e, raw, code, tail = gate0(o, buf)
    step1, exp_lines = build_code(o, img, raw, code, tail, ver)
    step2 = gate_030(o, step1, img, ver)
    fimg = gate_guides(o, step2, img, ver)
    step1.unlink()
    step2.unlink()
    return fimg, exp_lines


def main():
    o = Out()
    o('cx5 cond-stub image builder (offline): stock %s -> %s'
      % (BASE.name, ', '.join(OUT[v].name for v in VERS)))
    buf = BASE.read_bytes()
    img, e, raw, code, tail = gate0(o, buf)
    gate_g1(o)
    gate_g2(o)
    exp_lines_all = {}
    finals = {}
    for ver in VERS:
        o('--- version %s (site %s @0x%x, %d stub words) ---'
          % (ver, rf3.VERSIONS[ver]['site'], rf3.HOOKS[ver]['site'],
             len(rf3.STUB_WORDS[ver])))
        fimg, exp_lines = pipeline(o, ver)
        finals[ver] = fimg
        exp_lines_all[ver] = exp_lines
        run(o, ['python3', 'mlxfwutil.py', 'verify', '--deep',
                str(OUT[ver])])
        o('[4] %s mlxfwutil.py verify --deep: PASS' % ver)
        gate_mstflint(o, ver)
        gate_diff(o, img, fimg, ver, exp_lines)
        e30 = img.find_entry('ITOC', 0x30)
        e30f = fimg.find_entry('ITOC', 0x30)
        if e30f.addr != e30.addr or e30f.size > e30.size or \
                e30.size - e30f.size < HEADROOM_MIN:
            fail(o, '%s final Rule-2 re-check failed (addr/size/headroom)'
                 % ver)
        det = REPO / ('build/cx5-cond-stub-%s.det.bin' % ver)
        saved, OUT[ver] = OUT[ver], det
        pipeline(o, ver)
        OUT[ver] = saved
        md5_a = hashlib.md5(saved.read_bytes()).hexdigest()
        md5_b = hashlib.md5(det.read_bytes()).hexdigest()
        if md5_a != md5_b:
            fail(o, '%s determinism: md5 %s != %s' % (ver, md5_a, md5_b))
        det.unlink()
        o('[8] %s determinism: second full pipeline run md5 %s == first'
          % (ver, md5_a))
        o('      %s md5=%s' % (saved.name, md5_a))
    gate_gt(o, img, finals, exp_lines_all)
    o('ALL GATES PASS ([0] G1 G2 [1]-[8] x w-a/w-b/w-c)')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open('a') as f:
        f.write('\n'.join(o.lines) + '\n')
    o('DONE log+= %s' % LOG)


if __name__ == '__main__':
    main()
