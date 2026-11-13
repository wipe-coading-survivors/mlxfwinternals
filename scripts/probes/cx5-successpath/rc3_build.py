#!/usr/bin/env python3
"""cx5 successpath R-C3 (Task 2): H1b burn-ready image builder (offline).

Builds build/cx5-successpath-rc3-v1.bin by grafting the H1b success-path
detour onto the ON-DISK v4-echo base build/cx5-door-detour-v4.bin (R-E canon
md5; the current build_door_detour.py builds v12 only - the v4 base is a
build artifact, not rebuildable in-tree). NO burn here (Task 4); no live
operations; no GUID/MAC re-bake (the v4-echo base already carries the
Rule-3 bake - re-baking is a B4 violation).

H1b (R-C3 spec): unconditional 40B echo through the QUERY completion path.
Site HC-1 late-site dc 0x0E43C4 (stock word 0x00130000 dead-write
addi r19,zero - AFTER the collector merges, BEFORE the completion tail
call @0x0e43e4 with r9=response/r8=0x40). Stub live-ins: r18=response,
r1=frame, r20=ctx, r22=obj; clobber ONLY r3..r10; r11 (mask32 result with a
runtime consumer @0x0e43c0) and r17..r23 are NEVER written.

Patch map (dc = MAIN_CODE de-clcrc byte offset, rt = dc + 0x800000):
  dc 0x0E43C4          stock 0x00130000 -> HOOK_WORD 0x940aa4ec
                       call 0x38d774 (same 0x94 rel24 class as the rc2 G8
                       sketch idiom 0x940aa4e3 = call slot-start; +9 words
                       = free-zone start past the 9-word R-E echo canary)
  dc 0x38d774..0x38d7cc  23-word H1b stub in the free zone of the S0-cave
                       slot 0x38d750..0x38d7d7 (34 w; words 0..8 = R-E v4
                       echo stub canary, untouched; 25 free, slack 2):
                       10x (ld.d r6,r1,0xb0+4k; st.d r6,r18,0x10+4k) -
                       frame copy [r1+0x98..0xd8) mirrors the QUERY input,
                       so [r1+0xb0..0xd8) = input[0x18..0x40) = 40B payload
                       (ld.d/st.d are 32-bit moves - re1 canon "st.d stores
                       the low 32"; 10 pairs cover the window) - then the
                       exit triple addi r4,zero,0x43c8 / addi.hi r4,r4,0x8e
                       / ret.r zero,zero,r4 = resume rt 0x8E43C8 composed
                       absolute (registration-compose idiom @0x0a93d8; no
                       pc-relative encoding anywhere in the stub body).
                       Writes response+0x10..0x38 (out_mb verbatim window);
                       out+0x0..0x8 (status) and out+0x38..0x40 (stock
                       merges, 6f28 canary) are never targeted.
  ITOC 0x30            build-ID '; mlxini cx5-successpath rc3 v1 ...'
                       inserted right after the banner (above the retained
                       v4 door-detour build-ID line - keep-echo provenance);
                       vendor ';;' comments trimmed to headroom >= 32 (the
                       v4 base ini is packed to 1 B headroom; Rule 2: 0x30
                       stays in place)

Gates (in-script, log build/cx5-successpath-rc3-build.log):
  [0] v4-echo base md5 + stock base md5 + MAIN_CODE geometry + clcrc
      round-trip + hook-site stock words (0x0E43C4 dead-write, 0x0e437c
      BadParam call-site, H0 0x106390, S0 inj 0x1d594) + v4-echo vs stock
      word-diff == the 17 known R-E words + slot occupancy (9-word canary
      == re1 STUB_B4_WORDS, tail zero, cutout zero) -> free zone >= 23+2
  [B1] stub: strict cx5 assemble (decode-verify built in) + per-word
      dis->re-assemble bit-exact; == 23 words, slack >= 2; ld.d/st.d width
      parity (10+10, offsets paired 0xb0+4k -> 0x10+4k, spans 0x28/0x28);
      register discipline: every written register in {r3..r10} (disasm
      assert; stores/ret write no register), zero writes to r11/r17..r23;
      zero pc-relative words in the body; golden pins (first pair ==
      rc2 G8 sketch words 0x642600b2/0x6e403012; exit triple pinned);
      hook word call-class + simm24 resolves to the stub start
  [B2] graft MAIN_CODE: word-diff vs v4-echo == exactly hook + 23 stub
      words; changed 68B clcrc lines == expected; patch_sections; step1
      verify --deep PASS
  [B3] 0x30 build-ID: insert after banner, ';;'-trim to headroom >= 32,
      key=value count invariant, inject (no force), entry addr unchanged,
      size <= old, round-trip extract == edited text, v4 build-ID retained
  [B4] invariants: MAIN_CODE word-diff on the final image == hook + stub
      only; canary 9 words byte-equal to the base; cutout/S0/H0/0x1d594/
      0x0e437c untouched; byte-diff vs base = MAIN_CODE changed lines +
      0x03 entry CRC + 0x30 section + entry only (guides NOT re-baked);
      section-level diff == {ITOC 0x03, ITOC 0x30}
  [B5] verify + determinism: mlxfwutil.py verify --deep PASS; mstflint -i
      verify bootable; -i q identity == base (FW/PSID/GUID/MAC, Rule-3
      bake inherited); -i dc build-ID is the first content line after the
      banner (Rule 1, Task-4 activation discriminator); full rebuild ->
      identical md5; ALL GATES PASS
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

V4ECHO = REPO / 'build/cx5-door-detour-v4.bin'
V4ECHO_MD5 = '366b9945824571af83a6f36f7cce70f2'
STOCK = re1.BASE
LOG = REPO / 'build/cx5-successpath-rc3-build.log'
OUT = REPO / 'build/cx5-successpath-rc3-v1.bin'
DET1 = REPO / 'build/cx5-successpath-rc3.det1.bin'
DET2 = REPO / 'build/cx5-successpath-rc3.det2.bin'
INI = REPO / 'build/cx5-successpath-rc3.ini'
INI_RT = REPO / 'build/cx5-successpath-rc3.ini.rt'

BUILD_ID = ('; mlxini cx5-successpath rc3 v1 (2026-10-21, R-C3 spec): '
            'H1b unconditional echo, HC-1 0x0E43C4, base v4-echo keep-echo')
V4_BUILD_ID_PREFIX = '; mlxini cx5 door-detour v4 '
BANNER = ';; Mellanox Technologies LTD'
HEADROOM_MIN = 32

LATE_SITE = 0x0E43C4
LATE_STOCK = 0x00130000
LATE_STOCK_DIS = 'addi r19,zero,0x0'
RESUME_RT = 0x8E43C8
HOOK_IDIOM = 0x940AA4E3
CALL_SITE, CALL_SITE_WORD = 0x0E437C, 0x9402A57A
H0_SITE, H0_WORD = 0x106390, 0x940A1CF0
S0_INJ, S0_INJ_WORD = 0x1D594, 0x940DC067
S0_ZONE = (0x38D730, 0x38D747)
S0_WORDS = [0x24050000, 0x20A523F0, 0x2406BADC, 0x20C60001,
            0x6CA03002, 0x95F24272]
CUTOUT = re1.CUTOUT
SLOT_DC, SLOT_WORDS = re1.STUB_SLOT_DC, re1.STUB_SLOT_WORDS
CANARY_WORDS = 9
STUB_WORDS = 23
SLACK_MIN = 2
DATA_REG = 6
EXIT_REG = 4
READ_LO, READ_HI = 0xB0, 0xD8
WRITE_LO, WRITE_HI = 0x10, 0x38
PAIRS = (READ_HI - READ_LO) // 4
GOLDEN_PAIR = [0x642600B2, 0x6E403012]
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


def wa(text, base):
    data = assemble(text, base=base, profile=load_profile('cx5'), strict=True)
    return list(struct.unpack('>%dI' % (len(data) // 4), data))


def w32(b, off):
    return struct.unpack_from('>I', b, off)[0]


def stub_text():
    lines = []
    for k in range(PAIRS):
        lines.append('ld.d r%d,r1,0x%x' % (DATA_REG, READ_LO + 4 * k))
        lines.append('st.d r%d,r18,0x%x' % (DATA_REG, WRITE_LO + 4 * k))
    lines.append('addi r%d,zero,0x%x' % (EXIT_REG, RESUME_RT & 0xffff))
    lines.append('addi.hi r%d,r%d,0x%x' % (EXIT_REG, EXIT_REG,
                                            RESUME_RT >> 16))
    lines.append('ret.r zero,zero,r%d' % EXIT_REG)
    return '\n'.join(lines) + '\n'


def parse_write(text):
    mnem = text.split()[0]
    if mnem.startswith(NO_WRITE_PREFIX):
        return None
    first = text.split()[1].split(',')[0]
    if not first.startswith('r') or not first[1:].isdigit():
        return 'BAD:%s' % text
    return int(first[1:])


def gate0(o):
    buf = V4ECHO.read_bytes()
    if hashlib.md5(buf).hexdigest() != V4ECHO_MD5:
        fail(o, 'v4-echo base md5 mismatch (expected %s)' % V4ECHO_MD5)
    if hashlib.md5(STOCK.read_bytes()).hexdigest() != re1.BASE_MD5:
        fail(o, 'stock base md5 mismatch (diff reference drifted)')
    img = mlxfwutil.Image(bytes(buf), str(V4ECHO))
    e = img.find_entry('ITOC', 0x03)
    if (e.addr, e.size, e.clcrc, e.param0) != \
            (re1.SEC_ADDR, re1.SEC_SIZE, 1, 0x800000):
        fail(o, 'MAIN_CODE header mismatch: addr=0x%x size=0x%x clcrc=%s '
             'param0=%#x' % (e.addr, e.size, e.clcrc, e.param0))
    raw = img.section_data(e)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw:
        fail(o, 'de-clcrc round-trip failed on the v4-echo base')
    if w32(code, LATE_SITE) != LATE_STOCK or \
            dis(w32(code, LATE_SITE), LATE_SITE) != LATE_STOCK_DIS:
        fail(o, 'hook site 0x%x is not the stock dead-write %08x'
             % (LATE_SITE, LATE_STOCK))
    if dis(w32(code, 0x0E43C0), 0x0E43C0) != 'mask32 r11,r4,0x8,2':
        fail(o, 'r11 producer @0x0e43c0 drifted (forbidden-reg context)')
    for dc, want in [(CALL_SITE, CALL_SITE_WORD), (H0_SITE, H0_WORD),
                     (S0_INJ, S0_INJ_WORD)]:
        if w32(code, dc) != want:
            fail(o, 'site 0x%x drifted: %08x != %08x'
                 % (dc, w32(code, dc), want))
    if any(w32(code, dc) for dc in range(CUTOUT[0], CUTOUT[1] + 1, 4)):
        fail(o, 'cutout 0x38d748-0x38d74f not zero on the base')
    simg = mlxfwutil.Image(STOCK.read_bytes(), str(STOCK))
    scode, _ = mlxfwutil.clcrc_unwrap(
        simg.section_data(simg.find_entry('ITOC', 0x03)))
    diff = [dc for dc in range(0, len(code), 4)
            if w32(code, dc) != w32(scode, dc)]
    expect = sorted([S0_INJ, H0_SITE]
                    + list(range(S0_ZONE[0], S0_ZONE[1] + 1, 4))
                    + [SLOT_DC + 4 * i for i in range(CANARY_WORDS)])
    if sorted(diff) != expect:
        fail(o, 'v4-echo vs stock word-diff %s != the %d known R-E words'
             % ([hex(d) for d in sorted(diff)], len(expect)))
    for i in range(6):
        if w32(code, S0_ZONE[0] + 4 * i) != S0_WORDS[i]:
            fail(o, 'S0 shellcode word %d drifted' % i)
    slot = [w32(code, SLOT_DC + 4 * i) for i in range(SLOT_WORDS)]
    canary = [w for _, w in re1.STUB_B4_WORDS]
    if slot[:CANARY_WORDS] != canary:
        fail(o, 'slot canary words != re1 STUB_B4_WORDS (R-E echo stub)')
    if len(canary) != CANARY_WORDS:
        fail(o, 're1 STUB_B4_WORDS is %d words, not %d'
             % (len(canary), CANARY_WORDS))
    if any(slot[CANARY_WORDS:]):
        fail(o, 'slot tail beyond the canary is not zero on the base')
    free = SLOT_WORDS - CANARY_WORDS
    stub_dc = SLOT_DC + 4 * CANARY_WORDS
    if free < STUB_WORDS + SLACK_MIN:
        fail(o, 'free zone %d words < %d + slack %d'
             % (free, STUB_WORDS, SLACK_MIN))
    o('[0] v4-echo base md5 OK (%s); MAIN_CODE addr=0x%x size=0x%x clcrc=1 '
      'param0=0x800000 (de-clcrc round-trip OK); hook site 0x%x=%08x '
      '"%s" + mask32 r11 producer @0x0e43c0 intact; BadParam call-site/H0/'
      'S0-inj stock words OK; v4-echo vs stock diff == %d known R-E words '
      '(S0 6 + stub 9 + inj + H0); slot: %dw canary == re1 STUB_B4_WORDS, '
      'cutout zero, free contiguous zone %dw @0x%x..0x%x (>= %d + slack %d)'
      % (V4ECHO_MD5, re1.SEC_ADDR, re1.SEC_SIZE, LATE_SITE, LATE_STOCK,
         LATE_STOCK_DIS, len(expect), CANARY_WORDS, free, stub_dc,
         SLOT_DC + 4 * (SLOT_WORDS - 1), STUB_WORDS, SLACK_MIN))
    return img, e, raw, code, tail, stub_dc, free


def gate_b1(o, stub_dc, free):
    words = wa(stub_text(), stub_dc)
    if len(words) != STUB_WORDS:
        fail(o, 'stub is %d words, plan canon H1b = %d'
             % (len(words), STUB_WORDS))
    slack = free - len(words)
    if slack < SLACK_MIN:
        fail(o, 'stub slack %d < %d' % (slack, SLACK_MIN))
    loads, stores, writes = [], [], set()
    for i, w in enumerate(words):
        dc = stub_dc + 4 * i
        text = dis(w, dc)
        if wa(text, dc)[0] != w:
            fail(o, 'stub word %d dis->re-assemble drift' % i)
        mnem, rest = text.split(' ', 1)
        ops = rest.split(',')
        if mnem == 'ld.d':
            if ops[1].strip() != 'r1':
                fail(o, 'ld.d %d base %s != r1 (frame live-in)' % (i, ops[1]))
            loads.append((int(ops[0].strip()[1:]), int(ops[2].strip(), 16)))
        elif mnem == 'st.d':
            if ops[1].strip() != 'r18':
                fail(o, 'st.d %d base %s != r18 (response live-in)'
                     % (i, ops[1]))
            stores.append((int(ops[0].strip()[1:]), int(ops[2].strip(), 16)))
        if mnem.startswith(('b.', 'jump', 'call')):
            fail(o, 'stub word %d is pc-relative (%s) - body must be '
                 'position-independent' % (i, text))
        dst = parse_write(text)
        if dst is not None:
            if not isinstance(dst, int):
                fail(o, 'stub word %d has an unparsable destination: %s'
                     % (i, text))
            writes.add(dst)
            if dst not in ALLOWED_WRITES:
                fail(o, 'stub word %d writes r%d (allowed r3..r10 only): %s'
                     % (i, dst, text))
            if dst in FORBIDDEN_WRITES:
                fail(o, 'stub word %d writes forbidden r%d: %s'
                     % (i, dst, text))
    if len(loads) != PAIRS or len(stores) != PAIRS:
        fail(o, 'width parity: %d ld.d / %d st.d != %d pairs'
             % (len(loads), len(stores), PAIRS))
    for k, ((lr, lo), (sr, so)) in enumerate(zip(loads, stores)):
        if lo != READ_LO + 4 * k or so != WRITE_LO + 4 * k:
            fail(o, 'pair %d offsets 0x%x/0x%x break the byte mapping '
                 '0x%x+4k -> 0x%x+4k' % (k, lo, so, READ_LO, WRITE_LO))
        if lr != DATA_REG or sr != DATA_REG:
            fail(o, 'pair %d uses r%d/r%d != data r%d' % (k, lr, sr,
                                                          DATA_REG))
    if writes - {DATA_REG, EXIT_REG}:
        fail(o, 'stub writes unexpected regs %s' % sorted(writes))
    if words[:2] != GOLDEN_PAIR:
        fail(o, 'first pair %s != rc2 G8 sketch golden %s'
             % ([hex(w) for w in words[:2]], [hex(w) for w in GOLDEN_PAIR]))
    exit_text = [dis(words[i], stub_dc + 4 * i)
                 for i in range(len(words) - 3, len(words))]
    want_exit = ['addi r%d,zero,0x%x' % (EXIT_REG, RESUME_RT & 0xffff),
                 'addi.hi r%d,r%d,0x%x' % (EXIT_REG, EXIT_REG,
                                           RESUME_RT >> 16),
                 'ret.r zero,zero,r%d' % EXIT_REG]
    if exit_text != want_exit:
        fail(o, 'exit triple %s != %s (resume rt 0x%08X compose)'
             % (exit_text, want_exit, RESUME_RT))
    hook = wa('call 0x%x' % stub_dc, LATE_SITE)[0]
    if dis(hook, LATE_SITE) != 'call 0x%x' % stub_dc:
        fail(o, 'hook word decode drift')
    off = hook & 0xFFFFFF
    if off != (stub_dc - LATE_SITE) // 4 or off > 0x7FFFFF:
        fail(o, 'hook simm24 0x%x does not resolve to the stub start '
             '(or out of rel24 reach)' % off)
    if (hook >> 24) != (HOOK_IDIOM >> 24) or \
            hook - HOOK_IDIOM != (stub_dc - SLOT_DC) // 4:
        fail(o, 'hook word %08x is not the 0x94 call class of the G8 '
             'sketch idiom %08x + free-zone delta' % (hook, HOOK_IDIOM))
    o('[B1] H1b stub: %d words strict-cx5 assembled (decode-verify built '
      'in) + per-word dis->re-assemble bit-exact; slack %d >= %d; width '
      'parity %d+%d (ld.d/st.d 32-bit, offsets 0x%x+4k -> 0x%x+4k, spans '
      '0x%x/0x%x bytes); register discipline: writes %s ⊆ r3..r10, zero '
      'writes to r11/r17..r23, bases r1/r18 read-only; zero pc-relative '
      'body words; first pair == G8 golden %08x/%08x; exit triple '
      'composes resume rt 0x%08X (addi/addi.hi + ret.r); hook word %08x '
      '"call 0x%x" (simm24 0x%x, class == G8 idiom %08x + %d words)'
      % (len(words), slack, SLACK_MIN, len(loads), len(stores), READ_LO,
         WRITE_LO, READ_HI - READ_LO, WRITE_HI - WRITE_LO,
         sorted(writes), words[0], words[1], RESUME_RT, hook, stub_dc,
         off, HOOK_IDIOM, (stub_dc - SLOT_DC) // 4))
    o('      dc       rt       word     disasm')
    for i, w in enumerate(words):
        o('      0x%06x  0x%06x  %08x  %s'
          % (stub_dc + 4 * i, stub_dc + 4 * i + 0x800000, w,
             dis(w, stub_dc + 4 * i)))
    return words, hook


def graft(o, img, raw, code, tail, stub_dc, stub_words, hook):
    patch = {LATE_SITE: hook}
    for i, w in enumerate(stub_words):
        patch[stub_dc + 4 * i] = w
    if len(patch) != 1 + STUB_WORDS:
        fail(o, 'patch map size drift: %d' % len(patch))
    new_code = bytearray(code)
    for dc, w in patch.items():
        new_code[dc:dc + 4] = struct.pack('>I', w)
    new_code = bytes(new_code)
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(new_code, dc)]
    if sorted(changed) != sorted(patch):
        fail(o, 'word-diff %s != intended %d words'
             % ([hex(d) for d in changed], len(patch)))
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
    o('[B2] graft MAIN_CODE: %d words (hook 1 @0x%x + stub %d @0x%x..0x%x); '
      'word-diff vs v4-echo == exactly the intended set; changed 68B clcrc '
      'lines %s == expected; patch_sections OK (per-line clcrc + section/'
      'entry CRC); step1 verify --deep PASS; md5 %s'
      % (len(patch), LATE_SITE, len(stub_words), stub_dc,
         stub_dc + 4 * (len(stub_words) - 1), [hex(i) for i in diff_lines],
         hashlib.md5(out).hexdigest()))
    return out, exp_lines


def inject_030(o, step1_path, ini_path, ini_rt_path, out_path):
    img = mlxfwutil.Image(V4ECHO.read_bytes(), str(V4ECHO))
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
    if len(prior) != 1 or not prior[0].startswith(V4_BUILD_ID_PREFIX):
        fail(o, 'base ini does not carry exactly the v4 door-detour '
             'build-ID line: %r' % prior)
    v4_id = prior[0]
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
    if v4_id not in ini_final or BUILD_ID not in ini_final:
        fail(o, 'edited ini lost the v4 build-ID or the R-C3 build-ID')
    if ini_final.splitlines().index(BUILD_ID) != \
            ini_final.splitlines().index(BANNER) + 1:
        fail(o, 'R-C3 build-ID is not right after the banner')
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
    o('[B3] 0x30 build-ID: base packed %d vs e.size %d (headroom %d); '
      'R-C3 BUILD_ID inserted right after the banner (v4 door-detour ID '
      'retained below it); trimmed %d vendor ;; lines (key=value lines '
      'intact: %d); final packed %d, headroom %d >= %d; entry in place '
      '@0x%x, size 0x%x -> 0x%x; round-trip == edited text OK'
      % (zw_pad(text), e30.size, e30.size - zw_pad(text), len(dropped), kv1,
         zw_pad(ini_final), e30.size - zw_pad(ini_final), HEADROOM_MIN,
         e30n.addr, e30.size, e30n.size))
    for i in dropped:
        o('      trim: %r' % lines[i].rstrip())
    return ini_final


def gate_b4(o, base_img, exp_lines, stub_dc, stub_words):
    out = OUT.read_bytes()
    img = mlxfwutil.Image(out, 'final', base=base_img.base, fmt=base_img.fmt)
    e03 = img.find_entry('ITOC', 0x03)
    b03 = base_img.find_entry('ITOC', 0x03)
    e30 = base_img.find_entry('ITOC', 0x30)
    code, _ = mlxfwutil.clcrc_unwrap(img.section_data(e03))
    bcode, _ = mlxfwutil.clcrc_unwrap(base_img.section_data(b03))
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(bcode, dc)]
    want = sorted([LATE_SITE] + [stub_dc + 4 * i for i in range(STUB_WORDS)])
    if sorted(changed) != want:
        fail(o, 'final MAIN_CODE word-diff %s != hook+stub %d words'
             % ([hex(d) for d in changed], len(want)))
    for i in range(CANARY_WORDS):
        if w32(code, SLOT_DC + 4 * i) != w32(bcode, SLOT_DC + 4 * i):
            fail(o, 'canary slot word %d modified' % i)
    if any(w32(code, dc) for dc in range(CUTOUT[0], CUTOUT[1] + 1, 4)):
        fail(o, 'cutout touched in the final image')
    for dc in [CALL_SITE, H0_SITE, S0_INJ] + \
            list(range(S0_ZONE[0], S0_ZONE[1] + 1, 4)):
        if w32(code, dc) != w32(bcode, dc):
            fail(o, 'R-E zone word 0x%x drifted in the final image' % dc)
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
    buf = V4ECHO.read_bytes()
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
            fail(o, '%s entry count changed %d -> %d (per-type keys collide '
                 'on the dual 0xE1 DTOC entries)' % (toc, len(bes), len(fes)))
        for e, fe in zip(bes, fes):
            if fe.type != e.type or img.section_data(fe) != \
                    base_img.section_data(e):
                changed_secs.append('%s 0x%02x' % (toc, e.type))
    if sorted(changed_secs) != ['ITOC 0x03', 'ITOC 0x30']:
        fail(o, 'section-level diff %s != {ITOC 0x03, ITOC 0x30} '
             '(guides must NOT be re-baked)' % sorted(changed_secs))
    o('[B4] invariants: final MAIN_CODE word-diff == hook + %d stub words '
      'only; canary %dw byte-equal to the base; cutout/S0/H0/S0-inj/'
      'BadParam-site untouched; byte-diff vs base: %d bytes in %d zones, '
      'strays none; section-level diff %s (guides inherited, not re-baked)'
      % (STUB_WORDS, CANARY_WORDS, len(diffs), len(zones),
         sorted(changed_secs)))


def gate_b5(o, base_img):
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
    qb, qf = q(V4ECHO), q(OUT)
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
        if shown >= 4:
            break
    mi = None
    for i, l in enumerate(dl):
        if BUILD_ID in l:
            mi = i
            break
    if mi is None:
        fail(o, 'mstflint dc does not show the R-C3 build-ID')
    pre = [l for l in dl[:mi]
           if l.strip() and not l.startswith(('-E-', '-W-', '-I-', '-'))]
    if any(not l.startswith(';;') for l in pre) or len(pre) > 1:
        fail(o, 'build-ID is not right after the banner (pre: %r)' % pre)
    md5 = hashlib.md5(OUT.read_bytes()).hexdigest()
    o('[B5] verify: mlxfwutil.py verify --deep PASS; mstflint -i verify '
      '"Image is bootable"; -i q identity == base (FW %s, PSID %s, GUID '
      '%s, MAC %s - Rule-3 bake inherited); dc build-ID is the first '
      'content line after the banner (Rule 1); image md5 %s'
      % (qf.get('FW Version'), qf.get('PSID'), qf.get('Base GUID'),
         qf.get('Base MAC'), md5))
    return md5


def determinism(o, raw, code, tail, stub_dc, stub_words, hook, md5):
    o('[B5] determinism: full rebuild below via the same [B2]/[B3] '
      'pipeline into temp paths, then md5 compare')
    img = mlxfwutil.Image(V4ECHO.read_bytes(), str(V4ECHO))
    det1, _ = graft(o, img, raw, code, tail, stub_dc, stub_words, hook)
    DET1.write_bytes(det1)
    inject_030(o, DET1, INI, INI_RT, DET2)
    md5b = hashlib.md5(DET2.read_bytes()).hexdigest()
    if md5b != md5:
        fail(o, 'determinism: rebuild md5 %s != %s' % (md5b, md5))
    o('[B5] determinism: full rebuild (graft + 0x30 inject) md5 %s == '
      'first pass' % md5b)


def main():
    o = Out()
    o('cx5 successpath rc3 H1b image builder (offline): %s -> %s'
      % (V4ECHO.name, OUT.name))
    img, e, raw, code, tail, stub_dc, free = gate0(o)
    stub_words, hook = gate_b1(o, stub_dc, free)
    step1, exp_lines = graft(o, img, raw, code, tail, stub_dc, stub_words,
                             hook)
    STEP1 = REPO / 'build/cx5-successpath-rc3.step1.bin'
    STEP1.write_bytes(step1)
    inject_030(o, STEP1, INI, INI_RT, OUT)
    gate_b4(o, img, exp_lines, stub_dc, stub_words)
    md5 = gate_b5(o, img)
    determinism(o, raw, code, tail, stub_dc, stub_words, hook, md5)
    for p in (INI, INI_RT, STEP1, DET1, DET2):
        p.unlink()
    o('ALL GATES PASS ([0] B1 B2 B3 B4 B5)')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE %s md5=%s log=%s' % (OUT, md5, LOG))


if __name__ == '__main__':
    main()
