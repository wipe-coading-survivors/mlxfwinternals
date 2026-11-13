#!/usr/bin/env python3
"""cx5 fuzz-4 (Task 3): exec-trampoline image builder (offline).

Builds build/irisc-fuzz4-v1.bin from the R-C3 base
build/cx5-successpath-rc3-v1.bin (canon md5 fac6452e...): the 23-word R-C3
H1b stub in the S0-cave slot is replaced by a 3-word exec trampoline +
zeros; the hook word stays UNCHANGED. NO burn here (Task 4); no live
operations; no GUID/MAC re-bake (the base already carries the Rule-3 bake
- re-baking is an F4 violation).

Trampoline (fuzz4 spec C-F4.3, S2 v5l no-link transfer form, target
register from the site clobber set - r9 instead of the v5l r11: on the
late-site r11 is the mask32 result @0x0e43c0 with a runtime consumer,
canon rc12 s7 / R-C3 spec s0; r8 is re-established by the stock word
@0x0e43d8 (addi r8,zero,0x40) BEFORE any consumption):
  dc 0x38d774  addi r8,zero,0x0     0x00080000  zero the transfer base
                                        (the addi-zero stock class: the
                                        hook-site stock word 0x00130000 =
                                        addi r19,zero,0x0 itself, rt->r8)
  dc 0x38d778  addi r9,r1,0xac      0x002900AC  payload ptr = the S2
                                        landing [r1+0xac] (v5l w9
                                        0x002B00AC addi r11,r1,0xac,
                                        rt->r9)
  dc 0x38d77c  ret.r zero,r8,r9     0xFD004825  no-link computed jump
                                        (v5l w12 0xFD005825, rt->r9; the
                                        rs=8 class: csr0xbc untouched)
Exec-from-input live-proven v5j/v5k/v5l (S2 report). Write discipline:
ZERO memory writes anywhere in the trampoline (transfer only).

Patch map (dc = MAIN_CODE de-clcrc byte offset):
  dc 0x38d774..0x38d7cc  23-word R-C3 stub zone -> trampoline (3) + zeros
  dc 0x38d7d0,0x38d7d4   2-word slot slack -> zeros (already zero on the
                         base - fact-checked in [0]; no-op patch)
  dc 0x0E43C4            hook word 0x940aa4ec (call 0x38d774) - NOT
                         touched ([0] gate: == canon, target == trampoline
                         start)
  ITOC 0x30              build-ID '; mlxini irisc fuzz4 v1 ...' inserted
                         right after the banner (above the retained R-C3
                         and v4-echo build-ID lines); vendor ';;' comments
                         trimmed to headroom >= 32 (Rule 2)

Gates (in-script, log build/irisc-fuzz4-build.log):
  [0] R-C3 base md5 + v4-echo md5 + MAIN_CODE geometry + clcrc round-trip
      + hook word == 0x940aa4ec + mask32 r11 producer @0x0e43c0 + stock
      r8 re-establish word @0x0e43d8 + BadParam call-site/H0/S0-inj/S0
      zone words + R-C3 vs v4-echo word-diff == hook + the 23 stub-zone
      words + slot occupancy (9-word R-E canary == re1 STUB_B4_WORDS,
      slack 2 zero) -> free zone 25 words
  [F1] trampoline: strict cx5 assemble (decode-verify built in) + per-word
      dis->re-assemble bit-exact; == 3 words; write discipline: ZERO
      stores, zero pc-relative words, register writes {r8,r9} ⊆ r3..r10,
      zero writes to r11/r17..r23; golden lineage pins (addi-zero class of
      the hook-site stock word; v5l w9/w12 with rt->r9); hook word call
      class + simm24 resolves to the trampoline start
  [F2] graft MAIN_CODE: word-diff vs R-C3 == exactly the 23 stub-zone
      words; changed 68B clcrc lines == expected; patch_sections; step1
      verify --deep PASS
  [F3] 0x30 build-ID: insert after banner, ';;'-trim to headroom >= 32,
      key=value count invariant, inject (no force), entry addr unchanged,
      size <= old, round-trip extract == edited text, R-C3 + v4 build-IDs
      retained
  [F4] invariants + verify + determinism: final MAIN_CODE word-diff vs
      R-C3 == the 23 stub-zone words only; canary 9 words byte-equal;
      slack zero; cutout/S0/H0/S0-inj/BadParam-site untouched; byte-diff
      vs base = MAIN_CODE changed lines + 0x03 entry CRC + 0x30 section +
      0x30 entry only (guides NOT re-baked); section-level diff ==
      {ITOC 0x03, ITOC 0x30}; mlxfwutil.py verify --deep PASS; mstflint -i
      verify bootable; -i q identity == base (FW/PSID/GUID/MAC); -i dc
      build-ID is the first content line after the banner; full rebuild
      -> identical md5; ALL GATES PASS
"""
import hashlib
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'scripts/probes/cx5-door-detour'))
import mlxfwutil
import re1_stub_draft as re1
from scripts.irisc import assemble, disasm as dis
from scripts.irisc.profiles import load_profile

RC3 = REPO / 'build/cx5-successpath-rc3-v1.bin'
RC3_MD5 = 'fac6452e1b8e9708199f7a2bfed79ea4'
V4ECHO = REPO / 'build/cx5-door-detour-v4.bin'
V4ECHO_MD5 = '366b9945824571af83a6f36f7cce70f2'
LOG = REPO / 'build/irisc-fuzz4-build.log'
OUT = REPO / 'build/irisc-fuzz4-v1.bin'
STEP1 = REPO / 'build/irisc-fuzz4.step1.bin'
DET1 = REPO / 'build/irisc-fuzz4.det1.bin'
DET2 = REPO / 'build/irisc-fuzz4.det2.bin'
INI = REPO / 'build/irisc-fuzz4.ini'
INI_RT = REPO / 'build/irisc-fuzz4.ini.rt'

BUILD_ID = ('; mlxini irisc fuzz4 v1 (2026-10-25, fuzz4 spec): '
            'exec trampoline 0x38d774, hook 940aa4ec 0x0E43C4, base rc3')
RC3_BUILD_ID_PREFIX = '; mlxini cx5-successpath rc3 v1 '
V4_BUILD_ID_PREFIX = '; mlxini cx5 door-detour v4 '
BANNER = ';; Mellanox Technologies LTD'
HEADROOM_MIN = 32

LATE_SITE = 0x0E43C4
HOOK_WORD = 0x940AA4EC
LATE_STOCK_WORD = 0x00130000
MASK32_SITE = 0x0E43C0
R8_REEST_SITE = 0x0E43D8
R8_REEST_WORD = 0x00080040
R8_REEST_DIS = 'addi r8,zero,0x40'
CALL_SITE, CALL_SITE_WORD = 0x0E437C, 0x9402A57A
H0_SITE, H0_WORD = 0x106390, 0x940A1CF0
S0_INJ, S0_INJ_WORD = 0x1D594, 0x940DC067
S0_ZONE = (0x38D730, 0x38D747)
S0_WORDS = [0x24050000, 0x20A523F0, 0x2406BADC, 0x20C60001,
            0x6CA03002, 0x95F24272]
CUTOUT = re1.CUTOUT
SLOT_DC, SLOT_WORDS = re1.STUB_SLOT_DC, re1.STUB_SLOT_WORDS
CANARY_WORDS = 9
STUB_ZONE_WORDS = 23
SLACK_WORDS = 2
TRAMP_WORDS_N = 3
TRAMP_DC = SLOT_DC + 4 * CANARY_WORDS
ZONA_LAST_DC = SLOT_DC + 4 * (SLOT_WORDS - 1)
LANDING_OFF = 0xAC
RT5_MASK, RT5_SH = 0x001F0000, 16
RET_RT5_MASK, RET_RT5_SH = 0x0000F800, 11
V5L_W9 = 0x002B00AC
V5L_TRANSFER = 0xFD005825
TRAMP_TEXT = ('addi r8,zero,0\n'
              'addi r9,r1,0x%x\n'
              'ret.r zero,r8,r9\n' % LANDING_OFF)
TRAMP_GOLDEN = [0x00080000, 0x002900AC, 0xFD004825]
ALLOWED_WRITES = set(range(3, 11))
FORBIDDEN_WRITES = {11, 17, 18, 19, 20, 21, 22, 23}
NO_WRITE_PREFIX = ('st.', 'ret.', 'b.', 'jump', 'call')


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


def w32(b, off):
    return struct.unpack_from('>I', b, off)[0]


def gate0(o):
    buf = RC3.read_bytes()
    if hashlib.md5(buf).hexdigest() != RC3_MD5:
        fail(o, 'R-C3 base md5 mismatch (expected %s)' % RC3_MD5)
    if hashlib.md5(V4ECHO.read_bytes()).hexdigest() != V4ECHO_MD5:
        fail(o, 'v4-echo diff reference md5 mismatch (expected %s)'
             % V4ECHO_MD5)
    img = mlxfwutil.Image(bytes(buf), str(RC3))
    e = img.find_entry('ITOC', 0x03)
    if (e.addr, e.size, e.clcrc, e.param0) != \
            (re1.SEC_ADDR, re1.SEC_SIZE, 1, 0x800000):
        fail(o, 'MAIN_CODE header mismatch: addr=0x%x size=0x%x clcrc=%s '
             'param0=%#x' % (e.addr, e.size, e.clcrc, e.param0))
    raw = img.section_data(e)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw:
        fail(o, 'de-clcrc round-trip failed on the R-C3 base')
    if w32(code, LATE_SITE) != HOOK_WORD or \
            dis(w32(code, LATE_SITE), LATE_SITE) != 'call 0x%x' % TRAMP_DC:
        fail(o, 'hook site 0x%x is not the canon %08x (call 0x%x)'
             % (LATE_SITE, HOOK_WORD, TRAMP_DC))
    if dis(w32(code, MASK32_SITE), MASK32_SITE) != 'mask32 r11,r4,0x8,2':
        fail(o, 'r11 producer @0x%x drifted (forbidden-reg context)'
             % MASK32_SITE)
    if w32(code, R8_REEST_SITE) != R8_REEST_WORD or \
            dis(w32(code, R8_REEST_SITE), R8_REEST_SITE) != R8_REEST_DIS:
        fail(o, 'stock r8 re-establish word @0x%x drifted (the trampoline '
             'r8-zero safety argument)' % R8_REEST_SITE)
    for dc, want in [(CALL_SITE, CALL_SITE_WORD), (H0_SITE, H0_WORD),
                     (S0_INJ, S0_INJ_WORD)]:
        if w32(code, dc) != want:
            fail(o, 'site 0x%x drifted: %08x != %08x'
                 % (dc, w32(code, dc), want))
    for i in range(6):
        if w32(code, S0_ZONE[0] + 4 * i) != S0_WORDS[i]:
            fail(o, 'S0 shellcode word %d drifted' % i)
    if any(w32(code, dc) for dc in range(CUTOUT[0], CUTOUT[1] + 1, 4)):
        fail(o, 'cutout 0x38d748-0x38d74f not zero on the base')
    vimg = mlxfwutil.Image(V4ECHO.read_bytes(), str(V4ECHO))
    vcode, _ = mlxfwutil.clcrc_unwrap(
        vimg.section_data(vimg.find_entry('ITOC', 0x03)))
    diff = [dc for dc in range(0, len(code), 4)
            if w32(code, dc) != w32(vcode, dc)]
    expect = sorted([LATE_SITE]
                    + [TRAMP_DC + 4 * i for i in range(STUB_ZONE_WORDS)])
    if sorted(diff) != expect:
        fail(o, 'R-C3 vs v4-echo word-diff %s != hook + the %d stub-zone '
             'words' % ([hex(d) for d in sorted(diff)], STUB_ZONE_WORDS))
    slot = [w32(code, SLOT_DC + 4 * i) for i in range(SLOT_WORDS)]
    canary = [w for _, w in re1.STUB_B4_WORDS]
    if slot[:CANARY_WORDS] != canary or len(canary) != CANARY_WORDS:
        fail(o, 'slot canary words != re1 STUB_B4_WORDS (R-E echo stub)')
    if any(slot[CANARY_WORDS + STUB_ZONE_WORDS:]):
        fail(o, 'slot slack %d words not zero on the base'
             % SLACK_WORDS)
    if not all(slot[CANARY_WORDS:CANARY_WORDS + STUB_ZONE_WORDS]):
        fail(o, 'the 23-word R-C3 stub zone is not fully occupied '
             '(unexpected zero word - not the R-C3 canon layout)')
    free = STUB_ZONE_WORDS + SLACK_WORDS
    if free < TRAMP_WORDS_N + SLACK_WORDS:
        fail(o, 'free zone %d words < trampoline %d + slack %d'
             % (free, TRAMP_WORDS_N, SLACK_WORDS))
    o('[0] R-C3 base md5 OK (%s); MAIN_CODE addr=0x%x size=0x%x clcrc=1 '
      'param0=0x800000 (de-clcrc round-trip OK); hook 0x%x == canon %08x '
      '"call 0x%x"; mask32 r11 producer @0x%x + stock r8 re-establish '
      '@0x%x (%s) intact; BadParam call-site/H0/S0-inj/S0 words OK; R-C3 '
      'vs v4-echo diff == hook + %d stub-zone words; slot: %dw canary == '
      're1 STUB_B4_WORDS, R-C3 stub %dw @0x%x..0x%x occupied, slack %dw '
      'zero, free zone %dw @0x%x..0x%x'
      % (RC3_MD5, re1.SEC_ADDR, re1.SEC_SIZE, LATE_SITE, HOOK_WORD,
         TRAMP_DC, MASK32_SITE, R8_REEST_SITE, R8_REEST_DIS,
         STUB_ZONE_WORDS, CANARY_WORDS, STUB_ZONE_WORDS, TRAMP_DC,
         TRAMP_DC + 4 * (STUB_ZONE_WORDS - 1), SLACK_WORDS, free, TRAMP_DC,
         ZONA_LAST_DC))
    return img, e, raw, code, tail


def gate_f1(o, code):
    data = assemble(TRAMP_TEXT, base=TRAMP_DC, profile=load_profile('cx5'),
                    strict=True)
    words = list(struct.unpack('>%dI' % (len(data) // 4), data))
    if len(words) != TRAMP_WORDS_N:
        fail(o, 'trampoline is %d words, spec C-F4.3 = %d'
             % (len(words), TRAMP_WORDS_N))
    writes = set()
    for i, w in enumerate(words):
        dc = TRAMP_DC + 4 * i
        text = dis(w, dc)
        one = assemble(text, base=dc, profile=load_profile('cx5'),
                       strict=True)
        if struct.unpack('>I', one[:4])[0] != w:
            fail(o, 'trampoline word %d dis->re-assemble drift' % i)
        mnem = text.split()[0]
        if mnem.startswith('st.'):
            fail(o, 'trampoline word %d is a store (%s) - write discipline '
                 'violated: ZERO memory writes' % (i, text))
        if mnem.startswith(('b.', 'jump', 'call')):
            fail(o, 'trampoline word %d is pc-relative (%s)' % (i, text))
        if mnem.startswith(NO_WRITE_PREFIX):
            continue
        first = text.split()[1].split(',')[0]
        if not first.startswith('r') or not first[1:].isdigit():
            fail(o, 'trampoline word %d unparsable destination: %s'
                 % (i, text))
        dst = int(first[1:])
        writes.add(dst)
        if dst not in ALLOWED_WRITES:
            fail(o, 'trampoline word %d writes r%d (allowed r3..r10 only)'
                 % (i, dst))
        if dst in FORBIDDEN_WRITES:
            fail(o, 'trampoline word %d writes forbidden r%d' % (i, dst))
    if writes != {8, 9}:
        fail(o, 'trampoline writes %s != {r8, r9} (the site clobber set)'
             % sorted(writes))
    golden = [(LATE_STOCK_WORD & ~RT5_MASK) | (8 << RT5_SH),
              (V5L_W9 & ~RT5_MASK) | (9 << RT5_SH),
              (V5L_TRANSFER & ~RET_RT5_MASK) | (9 << RET_RT5_SH)]
    if words != golden or words != TRAMP_GOLDEN:
        fail(o, 'trampoline %s != golden lineage %s / canon %s'
             % ([hex(w) for w in words], [hex(w) for w in golden],
                [hex(w) for w in TRAMP_GOLDEN]))
    hook = w32(code, LATE_SITE)
    off = hook & 0xFFFFFF
    if off != (TRAMP_DC - LATE_SITE) // 4 or off > 0x7FFFFF:
        fail(o, 'hook simm24 0x%x does not resolve to the trampoline start'
             % off)
    reasm = assemble('call 0x%x' % TRAMP_DC, base=LATE_SITE,
                     profile=load_profile('cx5'), strict=True)
    if struct.unpack('>I', reasm[:4])[0] != HOOK_WORD:
        fail(o, 're-assembled hook != canon %08x' % HOOK_WORD)
    o('[F1] exec trampoline: %d words strict-cx5 assembled (decode-verify '
      'built in) + per-word dis->re-assemble bit-exact; write discipline: '
      'ZERO stores (transfer only), zero pc-relative words, register '
      'writes {r8,r9} ⊆ r3..r10, zero writes to r11/r17..r23; golden '
      'lineage pins OK (w0 = addi-zero class of the stock hook-site word '
      '0x00130000; w1 = v5l w9 %08x, w2 = v5l transfer %08x, rt->r9); '
      'hook %08x simm24 0x%x -> trampoline start 0x%x (== hook target)'
      % (len(words), V5L_W9, V5L_TRANSFER, hook, off, TRAMP_DC))
    o('      dc       rt       word     disasm')
    for i, w in enumerate(words):
        o('      0x%06x  0x%06x  %08x  %s'
          % (TRAMP_DC + 4 * i, TRAMP_DC + 4 * i + 0x800000, w,
             dis(w, TRAMP_DC + 4 * i)))
    return words


def graft(o, img, raw, code, tail, tramp_words):
    zone = STUB_ZONE_WORDS + SLACK_WORDS
    new_words = list(tramp_words) + [0] * (zone - TRAMP_WORDS_N)
    patch = {TRAMP_DC + 4 * i: w for i, w in enumerate(new_words)}
    if len(patch) != zone:
        fail(o, 'patch map size drift: %d' % len(patch))
    new_code = bytearray(code)
    for dc, w in patch.items():
        new_code[dc:dc + 4] = struct.pack('>I', w)
    new_code = bytes(new_code)
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(new_code, dc)]
    want = sorted(TRAMP_DC + 4 * i for i in range(STUB_ZONE_WORDS))
    if sorted(changed) != want:
        fail(o, 'word-diff %s != the %d R-C3 stub-zone words (the slack '
             'must stay zero-zero)' % ([hex(d) for d in sorted(changed)],
                                       STUB_ZONE_WORDS))
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
    o('[F2] graft MAIN_CODE: %d-word slot zone patched @0x%x..0x%x '
      '(trampoline %d + zeros %d incl. slack %d); word-diff vs R-C3 == '
      'exactly the %d R-C3 stub-zone words (slack zero-zero no-op); '
      'changed 68B clcrc lines %s == expected; patch_sections OK (per-line '
      'clcrc + section/entry CRC); step1 verify --deep PASS; md5 %s'
      % (zone, TRAMP_DC, ZONA_LAST_DC, TRAMP_WORDS_N,
         zone - TRAMP_WORDS_N, SLACK_WORDS, STUB_ZONE_WORDS,
         [hex(i) for i in diff_lines], hashlib.md5(out).hexdigest()))
    return out, exp_lines


def inject_030(o, step1_path, ini_path, ini_rt_path, out_path):
    img = mlxfwutil.Image(RC3.read_bytes(), str(RC3))
    e30 = img.find_entry('ITOC', 0x30)
    run(o, ['python3', 'mlxfwutil.py', 'extract', str(step1_path), '-s', '0x30',
            '-o', str(ini_path)])
    text = ini_path.read_text(encoding='latin1')
    lines = text.splitlines(keepends=True)
    banners = [i for i, l in enumerate(lines) if l.startswith(BANNER)]
    if len(banners) != 1:
        fail(o, 'expected exactly one banner, got %d' % len(banners))
    bi = banners[0]
    prior = [l for l in lines if l.startswith('; mlxini ')]
    if len(prior) != 2 or not any(l.startswith(RC3_BUILD_ID_PREFIX)
                                  for l in prior) \
            or not any(l.startswith(V4_BUILD_ID_PREFIX) for l in prior):
        fail(o, 'base ini does not carry exactly the rc3 + v4 build-ID '
             'lines: %r' % prior)
    rc3_id, v4_id = prior[0], prior[1]
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
    for keep in (v4_id, rc3_id, BUILD_ID):
        if keep not in ini_final:
            fail(o, 'edited ini lost a build-ID line: %r' % keep)
    if ini_final.splitlines().index(BUILD_ID) != \
            ini_final.splitlines().index(BANNER) + 1:
        fail(o, 'fuzz4 build-ID is not right after the banner')
    ini_path.write_text(ini_final, encoding='latin1')
    run(o, ['python3', 'mlxfwutil.py', 'inject', str(step1_path), str(ini_path),
            '-o', str(out_path)])
    simg = mlxfwutil.Image(Path(out_path).read_bytes(), 'step2', base=img.base,
                        fmt=img.fmt)
    e30n = simg.find_entry('ITOC', 0x30)
    if e30n.addr != e30.addr:
        fail(o, '0x30 relocated: 0x%x -> 0x%x' % (e30.addr, e30n.addr))
    if e30n.size > e30.size or e30.size - e30n.size < HEADROOM_MIN:
        fail(o, '0x30 size gate: 0x%x -> 0x%x (headroom %d)'
             % (e30.size, e30n.size, e30.size - e30n.size))
    run(o, ['python3', 'mlxfwutil.py', 'extract', str(out_path), '-s', '0x30',
            '-o', str(ini_rt_path)])
    if ini_rt_path.read_text(encoding='latin1') != ini_final:
        fail(o, '0x30 round-trip mismatch')
    o('[F3] 0x30 build-ID: base packed %d vs e.size %d (headroom %d); '
      'fuzz4 BUILD_ID inserted right after the banner (rc3 + v4 build-IDs '
      'retained below it); trimmed %d vendor ;; lines (key=value lines '
      'intact: %d); final packed %d, headroom %d >= %d; entry in place '
      '@0x%x, size 0x%x -> 0x%x; round-trip == edited text OK'
      % (zw_pad(text), e30.size, e30.size - zw_pad(text), len(dropped), kv1,
         zw_pad(ini_final), e30.size - zw_pad(ini_final), HEADROOM_MIN,
         e30n.addr, e30.size, e30n.size))
    for i in dropped:
        o('      trim: %r' % lines[i].rstrip())
    return ini_final


def gate_f4(o, base_img, exp_lines):
    out = OUT.read_bytes()
    img = mlxfwutil.Image(out, 'final', base=base_img.base, fmt=base_img.fmt)
    e03 = img.find_entry('ITOC', 0x03)
    b03 = base_img.find_entry('ITOC', 0x03)
    e30 = base_img.find_entry('ITOC', 0x30)
    code, _ = mlxfwutil.clcrc_unwrap(img.section_data(e03))
    bcode, _ = mlxfwutil.clcrc_unwrap(base_img.section_data(b03))
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(bcode, dc)]
    want = sorted(TRAMP_DC + 4 * i for i in range(STUB_ZONE_WORDS))
    if sorted(changed) != want:
        fail(o, 'final MAIN_CODE word-diff %s != the %d stub-zone words'
             % ([hex(d) for d in sorted(changed)], len(want)))
    for i in range(CANARY_WORDS):
        if w32(code, SLOT_DC + 4 * i) != w32(bcode, SLOT_DC + 4 * i):
            fail(o, 'canary slot word %d modified' % i)
    if any(w32(code, dc) for dc in range(CUTOUT[0], CUTOUT[1] + 1, 4)):
        fail(o, 'cutout touched in the final image')
    for dc in [CALL_SITE, H0_SITE, S0_INJ, LATE_SITE, MASK32_SITE] + \
            list(range(S0_ZONE[0], S0_ZONE[1] + 1, 4)):
        if w32(code, dc) != w32(bcode, dc):
            fail(o, 'site word 0x%x drifted in the final image' % dc)
    if w32(code, LATE_SITE) != HOOK_WORD:
        fail(o, 'final hook word != canon %08x' % HOOK_WORD)
    slot_tail = [w32(code, TRAMP_DC + 4 * i)
                 for i in range(TRAMP_WORDS_N, SLOT_WORDS - CANARY_WORDS)]
    if any(slot_tail):
        fail(o, 'final slot tail beyond the trampoline is not zero')
    ent03 = base_img.itoc_off + 32 + b03.index * 32
    ent30 = base_img.itoc_off + 32 + e30.index * 32
    zones = {}
    for ln in exp_lines:
        zones['MAIN_CODE line %d' % ln] = range(b03.addr + ln * 68,
                                                b03.addr + ln * 68 + 68)
    zones['ITOC 0x03 entry CRC'] = range(ent03 + 0x1A, ent03 + 0x20)
    zones['0x30 section'] = range(e30.addr, e30.addr + e30.size)
    zones['ITOC 0x30 entry'] = range(ent30, ent30 + 32)
    allowed = set()
    for r in zones.values():
        allowed |= set(r)
    buf = RC3.read_bytes()
    diffs = [i for i in range(len(out)) if out[i] != buf[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    if stray:
        fail(o, 'stray diff bytes outside the intended zones: %s' % stray)
    for name, r in zones.items():
        if not any(i in diffs for i in r):
            fail(o, 'expected zone has no diff bytes: %s' % name)
    changed_secs = []
    for toc in ('ITOC', 'DTOC'):
        bes = list(base_img.entries(toc))
        fes = list(img.entries(toc))
        if len(bes) != len(fes):
            fail(o, '%s entry count changed %d -> %d' % (toc, len(bes),
                                                         len(fes)))
        for e, fe in zip(bes, fes):
            if fe.type != e.type or img.section_data(fe) != \
                    base_img.section_data(e):
                changed_secs.append('%s 0x%02x' % (toc, e.type))
    if sorted(changed_secs) != ['ITOC 0x03', 'ITOC 0x30']:
        fail(o, 'section-level diff %s != {ITOC 0x03, ITOC 0x30} '
             '(guides must NOT be re-baked)' % sorted(changed_secs))
    o('[F4] invariants: final MAIN_CODE word-diff vs R-C3 == the %d '
      'stub-zone words only; canary %dw byte-equal; slot tail (zeros %dw '
      '+ slack %dw) zero; cutout/S0/H0/S0-inj/BadParam-site/hook/mask32-r11 '
      'untouched; byte-diff vs base: %d bytes in %d zones, strays none; '
      'section-level diff %s (guides inherited, not re-baked)'
      % (STUB_ZONE_WORDS, CANARY_WORDS, STUB_ZONE_WORDS - TRAMP_WORDS_N,
         SLACK_WORDS, len(diffs), len(zones), sorted(changed_secs)))
    run(o, ['python3', 'mlxfwutil.py', 'verify', '--deep', str(OUT)])
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
    qb, qf = q(RC3), q(OUT)
    for k in ('FW Version', 'PSID', 'Base GUID', 'Base MAC'):
        if qf.get(k) != qb.get(k):
            fail(o, 'identity %s changed vs base: %r -> %r'
                 % (k, qb.get(k), qf.get(k)))
    if qf.get('Base GUID', '').lower() != mlxfwutil.hw('CARD_CX5_EDR100', 'guid'):
        fail(o, 'Base GUID is not the card canon: %r' % qf)
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
        if shown >= 5:
            break
    mi = None
    for i, l in enumerate(dl):
        if BUILD_ID in l:
            mi = i
            break
    if mi is None:
        fail(o, 'mstflint dc does not show the fuzz4 build-ID')
    pre = [l for l in dl[:mi]
           if l.strip() and not l.startswith(('-E-', '-W-', '-I-', '-'))]
    if any(not l.startswith(';;') for l in pre) or len(pre) > 1:
        fail(o, 'build-ID is not right after the banner (pre: %r)' % pre)
    md5 = hashlib.md5(OUT.read_bytes()).hexdigest()
    o('[F4] verify: mlxfwutil.py verify --deep PASS; mstflint -i verify '
      '"Image is bootable"; -i q identity == base (FW %s, PSID %s, GUID '
      '%s, MAC %s - Rule-3 bake inherited); dc build-ID is the first '
      'content line after the banner (Rule 1); image md5 %s'
      % (qf.get('FW Version'), qf.get('PSID'), qf.get('Base GUID'),
         qf.get('Base MAC'), md5))
    return md5


def determinism(o, raw, code, tail, tramp_words, md5):
    o('[F4] determinism: full rebuild below via the same [F2]/[F3] '
      'pipeline into temp paths, then md5 compare')
    img = mlxfwutil.Image(RC3.read_bytes(), str(RC3))
    det1, _ = graft(o, img, raw, code, tail, tramp_words)
    DET1.write_bytes(det1)
    inject_030(o, DET1, INI, INI_RT, DET2)
    md5b = hashlib.md5(DET2.read_bytes()).hexdigest()
    if md5b != md5:
        fail(o, 'determinism: rebuild md5 %s != %s' % (md5b, md5))
    o('[F4] determinism: full rebuild (graft + 0x30 inject) md5 %s == '
      'first pass' % md5b)


def main():
    o = Out()
    o('cx5 fuzz4 exec-trampoline image builder (offline): %s -> %s'
      % (RC3.name, OUT.name))
    img, e, raw, code, tail = gate0(o)
    tramp_words = gate_f1(o, code)
    step1, exp_lines = graft(o, img, raw, code, tail, tramp_words)
    STEP1.write_bytes(step1)
    inject_030(o, STEP1, INI, INI_RT, OUT)
    md5 = gate_f4(o, img, exp_lines)
    determinism(o, raw, code, tail, tramp_words, md5)
    for p in (INI, INI_RT, STEP1, DET1, DET2):
        p.unlink()
    o('ALL GATES PASS ([0] F1 F2 F3 F4)')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE %s md5=%s log=%s' % (OUT, md5, LOG))


if __name__ == '__main__':
    main()
