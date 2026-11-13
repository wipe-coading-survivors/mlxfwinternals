#!/usr/bin/env python3
"""cx5 door-detour R-E3 (Task 3) / Task 5b v2-v12 respins: burn-ready image
builder (offline).

Builds build/cx5-door-detour-v12.bin from the CANONICAL stock 4030 CDA image:
S0 boot-marker (docs/250-re/120-irisc/025-boot-injection.md canon) + H0 hook + B12-stub (Task 5b v12 words,
imported from re1_stub_draft — upper-clean subs mask, final filter attempt) + card GUID/MAC bake (Rule 3) + 0x30 DBG_FW_INI build-ID
(Rules 1-2).
NO burn here (owner-gated Task 5b Step 3); no live operations.

v12 delta (ruling R23): v11 + the pre-subs upper-half cleanings
(set1/set0 on r6 AND r7) RESTORED - the 64-bit-subs hypothesis test:
clean inputs -> diff = 0 iff fully equal -> mask = 0xFFFFFFFF on match /
0 on miss. Everything else bit-exact v11. Build-ID line v12.

Patch map (dc = MAIN_CODE de-clcrc byte offset, rt = dc + 0x800000):
  dc 0x1d594          stock 0x940002de call 0x1e10c -> 0x940dc067
                      call 0x38d730 (S0 boot injection, docs/250-re/120-irisc/025-boot-injection.md)
  dc 0x38d730..0x38d744  6-word S0 shellcode: CR 0x23f0 = 0xbadc0001
                      boot-liveness marker, jump 0x1e10c resume
  dc 0x106390         stock 0x94fc5373 call 0x1b15c -> HOOK_WORD
                      call 0x38d750 (H0 door hook, rb1 canon)
  dc 0x38d750..       STUB_B12_WORDS (28 of 34, slack 6; Task 5b
                      decode-verified; cutout 0x38d748..0x38d74f stays
                      zero)
  DTOC 0xE1/0xE0      Base GUID/MAC from hw registry CARD_CX5_EDR100
  ITOC 0x30           build-ID '; mlxini cx5 door-detour v12 ...' after the
                      banner; vendor ';;' comments trimmed to keep the
                      section in place with >=32 B headroom (Rule 2; the
                      local zlib already packs the stock text 4 B over
                      e.size — docs/250-re/120-irisc/025-boot-injection.md zlib drift)

Gates (in-script, log build/cx5-door-detour.log):
  [0] base md5 + MAIN_CODE geometry + stock words (injection site, S0
      zone/slot/cutout zero, hook site) + emit wrapper prologue intact
  G1 S0 literals decode-verified (strict cx5 assemble + per-word
      dis->re-assemble bit-exact) + canon text cross-checks (docs/250-re/120-irisc/025-boot-injection.md
      table, scripts/s2/build_s2.py STOCK_WORDS)
  G2 stub import gates: STUB_B12_WORDS as-is (28 w, v1-v11 exports intact),
      placement in slot, slack >= 2, per-word decode re-verify,
      STUB_C_WORDS is None (B)
  G5 branch-target gates: every pc-relative stub word resolved from the
      encoded bits (own-dc anchor, s16/s24*4) == intended + stock
      calibration pin (b.f 0x8ed0 -> ret.d 0x8f00)
  [1] code patch: word-diff == exactly the 27 intended words; cutout
      zero; changed 68B clcrc lines == expected set; patch_sections
      step1; built section == re-clcrc(raw)
  [2] 0x30 build-ID: banner insert, ';;'-only trim to headroom >= 32,
      mlxfwutil.py inject (no force), entry addr unchanged, size <=,
      round-trip
  [3] mlxfwutil.py guides: GUID/MAC baked (mDevInfo + MFG_INFO,
      self-verify) + library re-asserts + MAIN_CODE untouched
  [4] mlxfwutil.py verify --deep -> PASS
  [5] mstflint -i verify -> 'Image is bootable'; -i q identity
      (GUID/MAC embedded, PSID invariant); -i dc build-ID is the first
      content line after the banner (Rule 1)
  [6] byte-diff vs stock: allowed = {MAIN_CODE changed lines + entry
      0x03 CRC bytes, 0x30 section + entry, mDevInfo, MFG_INFO + entry
      CRC bytes}; strays = none; every zone present; section-level diff
      == {0x03, 0x30, 0xE1, 0xE0}
  [7] GT table build/cx5-door-detour-gt.txt: dc->word, both classes
      (code + ro-data/string), words from the stock image, stock==built
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
import mlxfwutil
import re1_stub_draft as re1
from scripts.irisc import assemble, disasm as dis
from scripts.irisc.profiles import load_profile

BASE = re1.BASE
BASE_MD5 = re1.BASE_MD5
LOG = REPO / 'build/cx5-door-detour.log'
OUT = REPO / 'build/cx5-door-detour-v12.bin'
GT = REPO / 'build/cx5-door-detour-gt.txt'
STEP1 = REPO / 'build/cx5-door-detour.step1.bin'
STEP2 = REPO / 'build/cx5-door-detour.step2.bin'
INI = REPO / 'build/cx5-door-detour.ini'
INI_RT = REPO / 'build/cx5-door-detour.ini.rt'

CARD_GUID = int(mlxfwutil.hw('CARD_CX5_EDR100', 'guid'), 16)
CARD_MAC = int(mlxfwutil.hw('CARD_CX5_EDR100', 'mac'), 16)
BUILD_ID = ('; mlxini cx5 door-detour v12 (2026-10-19, R-E spec): '
            'H0 hook @0x106390 -> stub @0x38d750, upper-clean subs mask '
            '(64-bit value path, final filter attempt)')
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
DOC_S0_CANON = REPO / 'docs/250-re/120-irisc/025-boot-injection.md'
BUILD_S2 = REPO / 'scripts/s2/build_s2.py'

GT_CODE = [(0x1b15c, 'emit wrapper prologue (stock assert of re1/rb1)'),
           (0x106350, 'REGACC fn head word (rb1 1.4, contains H0)')]
GT_RODATA = [(0x34ab28, 'bytes of "icmd_generic_reg_access" @dc 0x34ab27 (rb1 L1)'),
             (0x37fe78, 'bytes of "isr_icmd, opcode=..." @dc 0x37fe75 (rb1 L0)')]


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


def fail(o, msg):
    o('FATAL: ' + msg)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
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


def zw_pad(text):
    d = zlib.compress(text.encode('latin1'), 9)
    return len(d) + (4 - len(d) % 4) % 4


def wa(text, base):
    data = assemble(text, base=base, profile=load_profile('cx5'), strict=True)
    return list(struct.unpack('>%dI' % (len(data) // 4), data))


def w32(b, off):
    return struct.unpack_from('>I', b, off)[0]


def gate0(o, buf):
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail(o, 'base md5 mismatch (GC gate)')
    img = mlxfwutil.Image(bytes(buf), str(BASE))
    e = img.find_entry('ITOC', 0x03)
    if (e.addr, e.size, e.clcrc) != (re1.SEC_ADDR, re1.SEC_SIZE, 1):
        fail(o, 'MAIN_CODE header mismatch: addr=0x%x size=0x%x clcrc=%d'
             % (e.addr, e.size, e.clcrc))
    raw = img.section_data(e)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw:
        fail(o, 'de-clcrc round-trip failed on stock')
    if w32(code, S0_INJ_DC) != S0_INJ_STOCK or \
            dis(w32(code, S0_INJ_DC), S0_INJ_DC) != 'call 0x1e10c':
        fail(o, 'S0 injection site 0x%x is not stock call 0x1e10c'
             % S0_INJ_DC)
    if w32(code, S0_INJ_DC + 4) != 0x95000000:
        fail(o, 'dead self-jump @0x1d598 changed (docs/250-re/120-irisc/025-boot-injection.md)')
    for dc, want in re1.SITE_CTX:
        if w32(code, dc) != want:
            fail(o, 'site context word dc 0x%x drifted' % dc)
    if w32(code, re1.HOOK_DC) != re1.HOOK_STOCK_WORD or \
            dis(w32(code, re1.HOOK_DC), re1.HOOK_DC) != \
            'call 0x%x' % re1.HOOK_STOCK_TARGET:
        fail(o, 'hook site word is not the stock rb1 H0 call 0x%x'
             % re1.HOOK_STOCK_TARGET)
    zones = [('S0 shellcode zone', re1.S0_ZONE[0], re1.S0_ZONE[1]),
             ('stub slot', re1.STUB_SLOT_DC,
              re1.STUB_SLOT_DC + 4 * re1.STUB_SLOT_WORDS - 4),
             ('cutout', re1.CUTOUT[0], re1.CUTOUT[1])]
    for name, lo, hi in zones:
        if any(w32(code, dc) for dc in range(lo, hi + 1, 4)):
            fail(o, '%s 0x%x..0x%x not zero on the stock base' % (name, lo, hi))
    o('[0] base md5 OK; MAIN_CODE addr=0x%x size=0x%x clcrc=1 '
      '(de-clcrc round-trip OK); inj site 0x%x=%08x "call 0x1e10c" + '
      'dead self-jump 0x1d598 intact; hook 0x%x=%08x "call 0x%x" + %d '
      'ctx words OK; S0 zone %dw + slot %dw + cutout %dw zero'
      % (re1.SEC_ADDR, re1.SEC_SIZE, S0_INJ_DC, S0_INJ_STOCK, re1.HOOK_DC,
         re1.HOOK_STOCK_WORD, re1.HOOK_STOCK_TARGET, len(re1.SITE_CTX),
         (re1.S0_ZONE[1] - re1.S0_ZONE[0] + 4) // 4, re1.STUB_SLOT_WORDS,
         (re1.CUTOUT[1] - re1.CUTOUT[0] + 4) // 4))
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
    canon_txt = DOC_S0_CANON.read_text()
    for w in S0_SC_WORDS + [S0_INJ_WORD]:
        if ('0x%08x' % w).lower() not in canon_txt.lower():
            fail(o, 'S0 word 0x%08x not found in docs/250-re/120-irisc/025-boot-injection.md canon text' % w)
    s2src = BUILD_S2.read_text()
    if '0x%08X' % S0_INJ_WORD not in s2src:
        fail(o, 'injection word 0x%08X not found in scripts/s2/build_s2.py'
             % S0_INJ_WORD)
    o('[G1] S0: 6 shellcode words + injection word decode-verified (strict '
      'cx5 assemble + dis->re-assemble bit-exact); literals cross-checked '
      'against docs/250-re/120-irisc/025-boot-injection.md canon text (7/7) and scripts/s2/build_s2.py '
      'STOCK_WORDS (injection word)')
    o('      dc       word     disasm')
    for i, w in enumerate(S0_SC_WORDS):
        o('      0x%06x  %08x  %s' % (S0_SC_DC + 4 * i, w, S0_SC_DECODE[i]))
    o('      0x%06x  %08x  %s' % (S0_INJ_DC, S0_INJ_WORD,
                                   dis(S0_INJ_WORD, S0_INJ_DC)))


def gate_g2(o):
    if re1.STUB_C_WORDS is not None:
        fail(o, 'STUB_C_WORDS is not None (channel B: no C finalization)')
    if len(re1.STUB_B_WORDS) != 19:
        fail(o, 'v1 exports drifted: STUB_B_WORDS is %d words, not 19'
             % len(re1.STUB_B_WORDS))
    if len(re1.STUB_B2_WORDS) != 14:
        fail(o, 'v2 exports drifted: STUB_B2_WORDS is %d words, not 14'
             % len(re1.STUB_B2_WORDS))
    if len(re1.STUB_B3_WORDS) != 8:
        fail(o, 'v3 exports drifted: STUB_B3_WORDS is %d words, not 8'
             % len(re1.STUB_B3_WORDS))
    if len(re1.STUB_B4_WORDS) != 9:
        fail(o, 'v4 exports drifted: STUB_B4_WORDS is %d words, not 9'
             % len(re1.STUB_B4_WORDS))
    if len(re1.STUB_B5_WORDS) != 11:
        fail(o, 'v5 exports drifted: STUB_B5_WORDS is %d words, not 11'
             % len(re1.STUB_B5_WORDS))
    if len(re1.STUB_B6_WORDS) != 13:
        fail(o, 'v6 exports drifted: STUB_B6_WORDS is %d words, not 13'
             % len(re1.STUB_B6_WORDS))
    if len(re1.STUB_B7_WORDS) != 17:
        fail(o, 'v7 exports drifted: STUB_B7_WORDS is %d words, not 17'
             % len(re1.STUB_B7_WORDS))
    if len(re1.STUB_B8_WORDS) != 18:
        fail(o, 'v8 exports drifted: STUB_B8_WORDS is %d words, not 18'
             % len(re1.STUB_B8_WORDS))
    if len(re1.STUB_B9_WORDS) != 18:
        fail(o, 'v9 exports drifted: STUB_B9_WORDS is %d words, not 18'
             % len(re1.STUB_B9_WORDS))
    if len(re1.STUB_B10_WORDS) != 18:
        fail(o, 'v10 exports drifted: STUB_B10_WORDS is %d words, not 18'
             % len(re1.STUB_B10_WORDS))
    if len(re1.STUB_B11_WORDS) != 24:
        fail(o, 'v11 exports drifted: STUB_B11_WORDS is %d words, not 24'
             % len(re1.STUB_B11_WORDS))
    n = len(re1.STUB_B12_WORDS)
    slack = re1.STUB_SLOT_WORDS - n
    if n != 28 or slack < re1.SLACK_MIN or n > re1.STUB_MAX_WORDS:
        fail(o, 'v12 stub budget: %d words, slack %d' % (n, slack))
    for i, (dc, w) in enumerate(re1.STUB_B12_WORDS):
        if dc != re1.STUB_SLOT_DC + 4 * i:
            fail(o, 'stub placement drift at %d: dc 0x%x' % (i, dc))
        if not re1.STUB_SLOT_DC <= dc < \
                re1.STUB_SLOT_DC + 4 * re1.STUB_SLOT_WORDS:
            fail(o, 'stub word %d dc 0x%x outside the slot' % (i, dc))
        if re1.CUTOUT[0] <= dc <= re1.CUTOUT[1]:
            fail(o, 'stub word %d dc 0x%x inside the cutout' % (i, dc))
        if wa(dis(w, dc), dc)[0] != w:
            fail(o, 'stub word %d dis->re-assemble drift' % i)
    if dis(re1.HOOK_WORD, re1.HOOK_DC) != 'call 0x%x' % re1.STUB_SLOT_DC:
        fail(o, 'hook word decode drift')
    intended = {1: re1.HOOK_STOCK_TARGET}
    for i, (dc, w) in enumerate(re1.STUB_B12_WORDS):
        tgt = re1._branch_target(w, dc)
        if tgt is None:
            continue
        if i not in intended or tgt != intended[i]:
            fail(o, 'G5: word %d @0x%x resolves 0x%x != intended' %
                 (i, dc, tgt))
    o('[G2] stub (v12): %d/%d words imported from re1_stub_draft '
      'as-is (no restate), slack %d >= %d; placement inside the slot, '
      'cutout untouched; every word re-verified dis->re-assemble '
      'bit-exact; v1-v11 exports intact (19/14/8/9/11/13/17/18/18/18/24 w); G5 '
      'branch-target re-check in-script; STUB_C_WORDS is None; HOOK_WORD '
      '%08x decodes "call 0x%x"'
      % (n, re1.STUB_SLOT_WORDS, slack, re1.SLACK_MIN, re1.HOOK_WORD,
         re1.STUB_SLOT_DC))


def patch_code(o, img, raw, code, tail):
    patch = {S0_INJ_DC: S0_INJ_WORD, re1.HOOK_DC: re1.HOOK_WORD}
    for i, w in enumerate(S0_SC_WORDS):
        patch[S0_SC_DC + 4 * i] = w
    for dc, w in re1.STUB_B12_WORDS:
        patch[dc] = w
    if len(patch) != 6 + 1 + 1 + len(re1.STUB_B12_WORDS):
        fail(o, 'patch map size drift: %d' % len(patch))
    new_code = bytearray(code)
    for dc, w in patch.items():
        new_code[dc:dc + 4] = struct.pack('>I', w)
    new_code = bytes(new_code)
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(new_code, dc)]
    if sorted(changed) != sorted(patch):
        fail(o, 'word-diff 0x..: %s != intended %d words'
             % ([hex(d) for d in changed], len(patch)))
    for dc in changed:
        if w32(new_code, dc) != patch[dc]:
            fail(o, 'patched word @0x%x mismatch' % dc)
    if any(w32(new_code, dc) for dc in
           range(re1.CUTOUT[0], re1.CUTOUT[1] + 1, 4)):
        fail(o, 'cutout 0x38d748-0x38d74f touched')
    exp_lines = sorted({dc // 64 for dc in patch})
    new_raw = mlxfwutil.clcrc_wrap(new_code, tail)
    diff_lines = [i for i in range(len(code) // 64)
                  if raw[i * 68:(i + 1) * 68] !=
                  new_raw[i * 68:(i + 1) * 68]]
    if diff_lines != exp_lines:
        fail(o, 'changed 68B lines %s != expected %s'
             % (diff_lines, exp_lines))
    edits = [(0x03, i * 68, new_raw[i * 68:(i + 1) * 68]) for i in diff_lines]
    out = mlxfwutil.patch_sections(img, edits)
    pimg = mlxfwutil.Image(out, 'step1', base=img.base, fmt=img.fmt)
    praw = pimg.section_data(pimg.find_entry('ITOC', 0x03))
    if praw != new_raw:
        fail(o, 'built MAIN_CODE raw mismatch')
    if mlxfwutil.clcrc_wrap(*mlxfwutil.clcrc_unwrap(praw)) != praw:
        fail(o, 'per-line clcrc round-trip failed on step1')
    errs = mlxfwutil.verify_image(pimg, deep=True)
    if errs:
        fail(o, 'step1 verify --deep failed: %s' % errs)
    STEP1.write_bytes(out)
    o('[1] code patch: %d words (S0 6 + inj 1 + hook 1 + stub %d); '
      'word-diff == exactly the intended set; cutout zero; changed 68B '
      'clcrc lines %s == expected; patch_sections OK (sec/entry CRC); '
      'step1 verify --deep PASS; md5 %s'
      % (len(patch), len(re1.STUB_B12_WORDS),
         [hex(i) for i in diff_lines], hashlib.md5(out).hexdigest()))
    return out, exp_lines


def gate_030(o, step1, img):
    e30 = img.find_entry('ITOC', 0x30)
    run(o, ['python3', 'mlxfwutil.py', 'extract', str(STEP1), '-s', '0x30',
            '-o', str(INI)])
    text = INI.read_text(encoding='latin1')
    lines = text.splitlines(keepends=True)
    banners = [i for i, l in enumerate(lines) if l.startswith(BANNER)]
    if len(banners) != 1:
        fail(o, 'expected exactly one %r banner, got %d' % (BANNER, len(banners)))
    if any(l.startswith('; mlxini ') for l in lines):
        fail(o, 'stock ini already carries a build-ID line')
    bi = banners[0]
    lines.insert(bi + 1, BUILD_ID + '\n')
    kv0 = sum(1 for l in lines if l.strip() and not l.startswith(';'))
    cand = [i for i, l in enumerate(lines)
            if l.startswith(';;') and i != bi]
    dropped = []

    def cur_text():
        ds = set(dropped)
        return ''.join(l for i, l in enumerate(lines) if i not in ds)

    while zw_pad(cur_text()) > e30.size - HEADROOM_MIN:
        if not cand:
            fail(o, '0x30: no ;; lines left to trim, still over budget')
        dropped.append(cand.pop(0))
    ini_final = cur_text()
    kv1 = sum(1 for l in lines if l.strip() and not l.startswith(';'))
    if kv0 != kv1:
        fail(o, 'key=value line count changed: %d -> %d' % (kv0, kv1))
    if zw_pad(ini_final) > e30.size - HEADROOM_MIN:
        fail(o, '0x30 budget: packed %d > %d - %d'
             % (zw_pad(ini_final), e30.size, HEADROOM_MIN))
    o('[2] 0x30: stock packed %d vs e.size %d (local zlib drift, ' +
      'docs/250-re/120-irisc/025-boot-injection.md); build-ID inserted after the banner; trimmed %d vendor ;; '
      'comment lines (key=value lines intact: %d); final packed %d, '
      'headroom %d >= %d'
      % (zw_pad(text), e30.size, len(dropped), kv1, zw_pad(ini_final),
         e30.size - zw_pad(ini_final), HEADROOM_MIN))
    for i in dropped:
        o('      trim: %r' % lines[i].rstrip())
    INI.write_text(ini_final, encoding='latin1')
    run(o, ['python3', 'mlxfwutil.py', 'inject', str(STEP1), str(INI), '-o',
            str(STEP2)])
    simg = mlxfwutil.Image(STEP2.read_bytes(), 'step2', base=img.base, fmt=img.fmt)
    e30n = simg.find_entry('ITOC', 0x30)
    if e30n.addr != e30.addr:
        fail(o, '0x30 relocated: 0x%x -> 0x%x' % (e30.addr, e30n.addr))
    if e30n.size > e30.size or e30.size - e30n.size < HEADROOM_MIN:
        fail(o, '0x30 size gate: 0x%x -> 0x%x (headroom %d)'
             % (e30.size, e30n.size, e30.size - e30n.size))
    run(o, ['python3', 'mlxfwutil.py', 'extract', str(STEP2), '-s', '0x30',
            '-o', str(INI_RT)])
    if INI_RT.read_text(encoding='latin1') != ini_final:
        fail(o, '0x30 round-trip mismatch')
    o('      0x30 in place @0x%x, size 0x%x -> 0x%x (headroom %d), '
      'round-trip == edited text OK'
      % (e30n.addr, e30.size, e30n.size, e30.size - e30n.size))
    return ini_final


def gate_guides(o, img):
    run(o, ['python3', 'mlxfwutil.py', 'guides', str(STEP2),
            '--guid', '0x%016x' % CARD_GUID, '--mac', '0x%012x' % CARD_MAC,
            '-o', str(OUT)])
    fimg = mlxfwutil.Image(OUT.read_bytes(), 'final', base=img.base, fmt=img.fmt)
    valid = mlxfwutil.find_valid_devinfo(fimg)
    if len(valid) != 1:
        fail(o, 'expected exactly 1 valid mDevInfo, got %d' % len(valid))
    m = mlxfwutil.MDevInfo.parse(fimg.section_data(valid[0]))
    if (m.guid, m.mac) != (CARD_GUID, CARD_MAC) or not m.crc_ok():
        fail(o, 'mDevInfo guid/mac mismatch after bake: 0x%x/0x%x'
             % (m.guid, m.mac))
    d0 = fimg.section_data(fimg.find_entry('DTOC', 0xE0))
    baked = (int.from_bytes(d0[0x28:0x30], 'big'),
             int.from_bytes(d0[0x38:0x40], 'big'))
    if baked != (CARD_GUID, CARD_MAC):
        fail(o, 'MFG_INFO guid/mac mismatch after bake: %x/%x' % baked)
    s1 = mlxfwutil.Image(STEP1.read_bytes(), 'step1-r', base=img.base, fmt=img.fmt)
    if fimg.section_data(fimg.find_entry('ITOC', 0x03)) != s1.section_data(
            s1.find_entry('ITOC', 0x03)):
        fail(o, 'guides bake touched MAIN_CODE')
    o('[3] guides: mDevInfo guid %016x mac %012x + MFG_INFO baked, CRC ok, '
      'self-verify PASS (CLI); MAIN_CODE untouched by the bake'
      % (CARD_GUID, CARD_MAC))
    return fimg


def gate_mstflint(o, img):
    r = run(o, ['mstflint', '-i', str(OUT), 'verify'])
    if 'bootable' not in (r.stdout + r.stderr) or \
            'verification succeeded' not in (r.stdout + r.stderr):
        fail(o, 'mstflint verify did not report bootable')

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
    qs, qf = q(BASE), q(OUT)
    for k in ('FW Version', 'PSID'):
        if qf.get(k) != qs.get(k):
            fail(o, 'identity %s changed vs stock: %r -> %r'
                 % (k, qs.get(k), qf.get(k)))
    if qf.get('Base GUID', '').lower() != '%016x' % CARD_GUID or \
            qf.get('Base MAC', '').lower() != '%012x' % CARD_MAC:
        fail(o, 'identity guid/mac not the card ones: %r' % qf)
    o('      stock q: Base GUID %s, Base MAC %s (zeros baked -> N/A)'
      % (qs.get('Base GUID'), qs.get('Base MAC')))
    for k in ('FW Version', 'PSID', 'Base GUID', 'Base MAC'):
        o('      %s: %s' % (k, qf.get(k)))
    r = subprocess.run(['mstflint', '-i', str(OUT), 'dc'],
                       capture_output=True, text=True, cwd=str(REPO))
    if r.returncode != 0:
        fail(o, 'mstflint dc rc=%d: %s' % (r.returncode, r.stderr.strip()))
    dl = [l.rstrip() for l in (r.stdout + r.stderr).splitlines()]
    shown = 0
    for l in dl:
        if l.strip() and not l.startswith(('-E-', '-W-', '-I-', '-')):
            o('      dc| ' + l)
            shown += 1
        if shown >= 4:
            break
    try:
        mi = next(i for i, l in enumerate(dl) if BUILD_ID in l)
    except StopIteration:
        fail(o, 'mstflint dc does not show the build-ID')
    pre = [l for l in dl[:mi]
           if l.strip() and not l.startswith(('-E-', '-W-', '-I-', '-'))]
    if any(not l.startswith(';;') for l in pre) or len(pre) > 1:
        fail(o, 'build-ID is not right after the banner (pre: %r)' % pre)
    o('[5] mstflint: verify bootable; q identity (GUID/MAC embedded, '
      'FW/PSID invariant vs stock); dc build-ID is the first content line '
      'after the banner (Rule 1)')


def gate_diff(o, img, fimg, exp_lines):
    buf = BASE.read_bytes()
    out = OUT.read_bytes()
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
    o('[6] byte-diff vs stock: %d bytes in %d zones; strays: %s'
      % (len(diffs), len(zones), stray or 'none'))
    if stray:
        fail(o, 'stray diff bytes outside the intended zones: %s' % stray)
    for name, r in zones.items():
        if not any(i in diffs for i in r):
            fail(o, 'expected zone has no diff bytes: %s' % name)
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
        fail(o, 'section-level diff %s != {ITOC 0x03, ITOC 0x30, '
             'DTOC 0xE1, DTOC 0xE0}' % sorted(changed_secs))
    o('      section-level diff: %s (Rule 4: S0/hook/stab lines inside '
      'MAIN_CODE 0x03, 0x30, mDevInfo/MFG_INFO only)' % sorted(changed_secs))


def gate_gt(o, img, fimg, exp_lines):
    code, _ = mlxfwutil.clcrc_unwrap(
        img.section_data(img.find_entry('ITOC', 0x03)))
    fcode, _ = mlxfwutil.clcrc_unwrap(
        fimg.section_data(fimg.find_entry('ITOC', 0x03)))
    entries = []
    for dc, note in GT_CODE + GT_RODATA:
        if dc % 4:
            fail(o, 'GT dc 0x%x not ld.d-aligned' % dc)
        if dc // 64 in exp_lines:
            fail(o, 'GT dc 0x%x falls into a patched 68B line' % dc)
        w_stock = w32(code, dc)
        if w32(fcode, dc) != w_stock:
            fail(o, 'GT dc 0x%x word changed stock->built' % dc)
        entries.append((dc, w_stock, note))
    body = [
        '# cx5 door-detour ground truth (Task 3 Step 5; consumed by Task 5)',
        '# words read from the STOCK image MAIN_CODE (ITOC 0x03 de-clcrc);',
        '# dc = MAIN_CODE byte offset, rt = dc + 0x800000; all dc are '
        'ld.d-aligned (dc % 4 == 0)',
        '# format: <dc-hex> <word-hex> ; "#"-lines are comments',
        '# class code (MAIN_CODE instruction words):',
    ]
    for dc, w, note in entries[:len(GT_CODE)]:
        body.append('0x%06x 0x%08x  # %s [%s]' % (dc, w, dis(w, dc), note))
    body.append('# class ro-data/string (ASCII bytes of the door trace strings):')
    for dc, w, note in entries[len(GT_CODE):]:
        body.append('0x%06x 0x%08x  # %r [%s]'
                    % (dc, w, struct.pack('>I', w), note))
    GT.parent.mkdir(parents=True, exist_ok=True)
    GT.write_text('\n'.join(body) + '\n')
    for l in body:
        o('      ' + l)
    o('[7] GT table: %d code + %d ro-data entries, stock==built word-wise, '
      'outside the patched lines -> %s' % (len(GT_CODE), len(GT_RODATA), GT))


def main():
    o = Out()
    buf = BASE.read_bytes()
    o('cx5 door-detour image builder (offline): stock %s -> %s'
      % (BASE.name, OUT.name))
    img, _, raw, code, tail = gate0(o, buf)
    gate_g1(o)
    gate_g2(o)
    step1, exp_lines = patch_code(o, img, raw, code, tail)
    gate_030(o, step1, img)
    fimg = gate_guides(o, img)
    run(o, ['python3', 'mlxfwutil.py', 'verify', '--deep', str(OUT)])
    o('[4] mlxfwutil.py verify --deep: PASS')
    gate_mstflint(o, img)
    gate_diff(o, img, fimg, exp_lines)
    gate_gt(o, img, fimg, exp_lines)
    e30 = img.find_entry('ITOC', 0x30)
    e30f = fimg.find_entry('ITOC', 0x30)
    if e30f.addr != e30.addr or e30f.size > e30.size or \
            e30.size - e30f.size < HEADROOM_MIN:
        fail(o, 'final Rule-2 re-check failed (addr/size/headroom)')
    INI_RT.unlink()
    for p in (INI, STEP1, STEP2):
        p.unlink()
    md5 = hashlib.md5(OUT.read_bytes()).hexdigest()
    o('ALL GATES PASS ([0] G1 G2 [1]-[7])')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE %s md5=%s log=%s' % (OUT, md5, LOG))


if __name__ == '__main__':
    main()
