#!/usr/bin/env python3
# S1 image build (T3): S0 base + 3 hooks (9 words) + locator (93 words @0x38d750)
# + TAB (42 words @0x38d8c4), all in MAIN_CODE section 0x03.
# Pipeline (PC4 / build_4030_patch3.py verbatim structure):
#   extract raw 0x03 -> de-clcrc -> round-trip -> patch -> re-clcrc ->
#   line-diff -> mlxfwutil.patch_sections (sec/entry CRC) -> verify.
# Single source of words: /tmp/opencode/irisc/s1_loc_out.txt (T2, verified
# 17/17 enc + decode-back 93/93). OFFLINE: no live-HW, no burn.
import os, struct, hashlib, sys, re

REPO = os.path.expanduser('~/git/IMPLEMENTATION/mlxini')
BASE = REPO + '/build/4030-cda-patched3.bin'          # S0 image
OUT  = '/tmp/opencode/s1/4030-cda-s1.bin'
WORDS_FILE = '/tmp/opencode/irisc/s1_loc_out.txt'
CODE_OUT = '/tmp/opencode/s1/main03-code-s1.bin'
RAW_OUT  = '/tmp/opencode/s1/main03-raw-s1.bin'

sys.path.insert(0, REPO + '/scripts/probes')
sys.path.insert(0, REPO)
import mlxfwutil
from iron_boot_probe import decrc

# HW CRC-16: reflect-таблица poly 0xD008 (эквивалент crc16table2 из
# mstflint mft_utils/calc_hw_crc.c); генерируется
HW_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xD008 if _c & 1 else _c >> 1
    HW_CRC_TABLE.append(_c)

def calc_hwcrc(crc, data):
    for b in data:
        crc = (crc >> 8) ^ HW_CRC_TABLE[(b ^ (crc & 0xFF)) & 0xFF]
    return crc

def clcrc(code, tail=b''):
    assert len(code) % 64 == 0
    out = bytearray()
    for i in range(len(code) // 64):
        line = bytearray(code[i*64:(i+1)*64]) + b'\x00\x00'
        line += struct.pack('<H', calc_hwcrc(0x0000, bytes(line)))
        out += line
    return bytes(out) + tail

def be32(w): return struct.pack('>I', w)
def u32(b, o): return struct.unpack_from('>I', b, o)[0]

def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)

# ============ 0. base image md5 ============
base_bytes = open(BASE, 'rb').read()
md5_base = hashlib.md5(base_bytes).hexdigest()
print('[0] S0 base: %s md5=%s' % (BASE, md5_base))
if md5_base != '082e9678b54d0512cec2f155037e82b7':
    die('S0 base md5 mismatch')

# ============ 1. parse words from s1_loc_out.txt (single source) ============
sec_re = re.compile(r'^\s*(?:0x)?([0-9a-fA-F]{6,8})\s+([0-9a-fA-F]{8})\s*(?:;|$)')
loc_words, tab_words, hook_words = [], [], []
decode_back = {}   # addr -> decoded text (from DECODE-BACK section of s1_loc_out.txt)
section = None
for ln in open(WORDS_FILE, 'r'):
    s = ln.rstrip('\n')
    if s.startswith('=== LOC code'):
        section = 'loc'; continue
    if s.startswith('=== TAB'):
        section = 'tab'; continue
    if s.startswith('=== HOOKS'):
        section = 'hooks'; continue
    if s.startswith('=== DECODE-BACK'):
        section = 'db'; continue
    if s.startswith('=== '):
        section = None; continue
    if section == 'db':
        m = re.match(r'^\s*([0-9a-fA-F]{8})\s+(.*?)\s*;.*$', s)
        if m:
            decode_back[int(m.group(1), 16)] = m.group(2).strip()
        continue
    if s.startswith('total:') or s.startswith('hook frame check'):
        section = None; continue
    m = sec_re.match(s)
    if not m:
        continue
    a, w = int(m.group(1), 16), int(m.group(2), 16)
    if section == 'loc':   loc_words.append((a, w))
    elif section == 'tab': tab_words.append((a, w))
    elif section == 'hooks': hook_words.append((a, w))

assert len(loc_words) == 93, ('loc', len(loc_words))
assert len(tab_words) == 42, ('tab', len(tab_words))
assert len(hook_words) == 9, ('hooks', len(hook_words))
for i, (a, w) in enumerate(loc_words):
    assert a == 0x38d750 + 4*i, (i, hex(a))
for i, (a, w) in enumerate(tab_words):
    assert a == 0x38d8c4 + 4*i, (i, hex(a))
exp_hook_addrs = [0x090b7c+4*i for i in range(3)] + [0x090be4+4*i for i in range(3)] + [0x0d3cf4+4*i for i in range(3)]
for a, w in hook_words:
    assert a in exp_hook_addrs, hex(a)
# cross-check hook words vs dispatch prompt values
exp_hooks = {0x090b7c:0x703f0fc2,0x090b80:0x30090000,0x090b84:0x950bf2f3,
             0x090be4:0x703f0fc2,0x090be8:0x30090001,0x090bec:0x950bf2d9,
             0x0d3cf4:0x703f0fc2,0x0d3cf8:0x30090002,0x0d3cfc:0x950ae695}
for a, w in hook_words:
    assert w == exp_hooks[a], (hex(a), '%08x' % w, '%08x' % exp_hooks[a])
print('[1] parsed s1_loc_out.txt: LOC 93 words @0x38d750, TAB 42 words @0x38d8c4, hooks 9 words; addrs sequential; hook words == prompt values')
print('    decode-back reference entries: %d' % len(decode_back))

# ============ 2. extract raw MAIN_CODE from S0 image ============
img = mlxfwutil.Image(base_bytes, BASE)
e = img.find_entry('ITOC', 0x03)
raw = img.section_data(e)
assert e.size == 0x3d15a0 and e.clcrc == 1 and e.addr == 0x1c748, (hex(e.size), e.clcrc, hex(e.addr))
assert e.param0 == 0x800000 and e.param1 == 0x81d58c
md5_raw = hashlib.md5(raw).hexdigest()
print('[2] raw MAIN_CODE from S0 image: size=0x%x addr=0x%x clcrc=1 md5=%s' % (len(raw), e.addr, md5_raw))

code = decrc(raw)
assert len(code) == 0x397dc0, hex(len(code))
md5_code = hashlib.md5(code).hexdigest()
nlines = len(code) // 64
tail = raw[nlines*68:]
print('[2] de-clcrc code: size=0x%x md5=%s lines=%d tail(4B)=%s' % (len(code), md5_code, nlines, tail.hex()))

# ============ 3. ROUND TRIP (S0 raw, pre-patch) ============
rt = clcrc(code, tail)
if rt != raw:
    first = next(i for i in range(len(raw)) if rt[i] != raw[i])
    die('S0 round-trip failed at raw byte 0x%x (line %d)' % (first, first // 68))
print('[3] ROUND-TRIP: re-clcrc(code)+tail == S0 raw (0x%x bytes) IDENTICAL (all %d lines clcrc ok)' % (len(raw), nlines))

# ============ 4. pre-conditions on S0 code ============
def words_at(base, n):
    return [u32(code, base + 4*i) for i in range(n)]

# 4.1 hook-site originals (stock prologue words, must be intact in S0)
orig = {}
for S, frame in ((0x090b7c, 0x703f0ff2), (0x090be4, 0x703f0ffa), (0x0d3cf4, 0x703f0fda)):
    w = words_at(S, 3)
    assert w[0] == 0x480300bc, (hex(S), 'csr.r', '%08x' % w[0])
    assert w[1] == 0x6c201806, (hex(S), 'st.d retaddr', '%08x' % w[1])
    assert w[2] == frame, (hex(S), 'frame', '%08x' % w[2], '%08x' % frame)
    orig[S] = w
    print('[4.1] hook site 0x%06x original: %s (intact stock prologue)' % (S, ' '.join('%08x' % x for x in w)))

# 4.2 S0 injection + marker (must be preserved by S1)
inj = u32(code, 0x1d594)
assert inj == 0x940dc067, 'S0 injection dc 0x1d594 = %08x (want 940dc067)' % inj
marker = words_at(0x38d730, 6)
exp_marker = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001, 0x6ca03002, 0x95f24272]
assert marker == exp_marker, ('S0 marker', [hex(x) for x in marker])
print('[4.2] S0 injection dc 0x1d594 = 0x%08x (call 0x38d730) + marker 0x38d730..0x38d747 intact: %s' %
      (inj, ' '.join('%08x' % x for x in marker)))

# 4.3 free region 0x38d750..0x38dbe8 all zeros
free = code[0x38d750:0x38dbe8]
assert all(b == 0 for b in free), 'free region 0x38d750..0x38dbe8 not all zeros'
print('[4.3] free region 0x38d750..0x38dbe8: all zero (%d bytes)' % len(free))

# 4.4 placement / overlap math
LOC0, LOC1 = 0x38d750, 0x38d750 + 93*4          # 0x38d8c4
TAB0, TAB1 = 0x38d8c4, 0x38d8c4 + 42*4          # 0x38d96c
MK0,  MK1  = 0x38d730, 0x38d730 + 6*4           # 0x38d748
MC_SIZE = 0x397dc0
assert LOC1 == TAB0, 'locator/TAB adjacency'
assert MK1 < LOC0, 'S0 marker vs locator overlap'
assert TAB1 <= MC_SIZE, 'TAB exceeds MAIN_CODE'
print('[4.4] placement: S0-marker [%06x,%06x)  LOC [%06x,%06x)  TAB [%06x,%06x)  MAIN_CODE size 0x%x' %
      (MK0, MK1, LOC0, LOC1, TAB0, TAB1, MC_SIZE))
print('      gap marker->LOC = 0x%x bytes; tail margin TAB->end = 0x%x bytes; no overlaps; all within MAIN_CODE' %
      (LOC0 - MK1, MC_SIZE - TAB1))

# ============ 5. apply S1 patch ============
code_b = bytearray(code)
for a, w in hook_words:
    code_b[a:a+4] = be32(w)
for a, w in loc_words:
    code_b[a:a+4] = be32(w)
for a, w in tab_words:
    code_b[a:a+4] = be32(w)
code_b = bytes(code_b)
open(CODE_OUT, 'wb').write(code_b)
md5_pcode = hashlib.md5(code_b).hexdigest()
print('[5] S1 patch applied: 9 hook + 93 LOC + 42 TAB = 144 words; patched code md5=%s' % md5_pcode)

# 5.1 post-patch: S0 parts untouched
assert u32(code_b, 0x1d594) == 0x940dc067
assert [struct.unpack_from('>I', code_b, 0x38d730+4*i)[0] for i in range(6)] == exp_marker, 'S0 marker clobbered'
assert code_b[0x38d748:0x38d74c] == b'\x00\x00\x00\x00', 'S0 marker tail clobbered'
print('[5.1] post-patch: S0 injection + marker 0x38d730..0x38d74b (7 words) byte-identical')

# ============ 6. decode-verify (raw words + dis.py decode-back) ============
import importlib.util
spec = importlib.util.spec_from_file_location('dis', '/tmp/opencode/irisc/dis.py')
dismod = importlib.util.module_from_spec(spec); spec.loader.exec_module(dismod)

# 6.1 raw-word bit-exact check (primary; dis.py has ret.r/jalr mnemonic bug for op=0x3f f=0x25 —
#     no such words in LOC, but raw comparison is the gate)
bad = 0
for a, w in loc_words + tab_words + hook_words:
    if u32(code_b, a) != w:
        bad += 1
        print('    RAW MISMATCH @%06x: got %08x want %08x' % (a, u32(code_b, a), w))
assert bad == 0
print('[6.1] raw words: 144/144 bit-exact (93 LOC + 42 TAB + 9 hooks)')

# 6.2 dis.py decode-back of all 93 LOC words vs T2 DECODE-BACK reference
db_bad = []
for a, w in loc_words:
    ref = decode_back.get(a)
    got = dismod.dis(w, a)
    if ref is not None and got != ref:
        db_bad.append((a, got, ref))
for a, w in hook_words:
    print('    hook %06x  %s' % (a, dismod.dis(w, a)))
assert len(decode_back) == 93, len(decode_back)
if db_bad:
    for a, g, r in db_bad[:10]:
        print('    DECODE MISMATCH @%06x:\n      got %s\n      ref %s' % (a, g, r))
    die('decode-back mismatch: %d' % len(db_bad))
print('[6.2] decode-back: 93/93 LOC words decode identically to T2 reference (dis.py)')

# 6.3 control-flow targets (jumps/branches) sanity
def tgt_op25(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o*4
cf = 0
for a, w in hook_words + loc_words:
    if w >> 26 == 0x25:
        t = tgt_op25(w, a)
        print('    %06x  %08x  %s 0x%06x' % (a, w, 'jump' if (w>>24)&1 else 'call', t))
        cf += 1
        assert 0 <= t < MC_SIZE, (a, hex(t))
    elif w >> 26 in (0x28, 0x29, 0x2a, 0x2b):
        o = w & 0xffff
        if o & 0x8000: o -= 0x10000
        t = (a+4) + o*4
        assert 0x38d750 <= t < 0x38d96c or t == 0x38d850, (a, hex(t))
print('[6.3] control flow: %d jump/call in LOC+hooks, all targets within MAIN_CODE; all rel16 branch targets inside LOC' % cf)

# ============ 7. re-clcrc + line diff vs S0 raw ============
praw = clcrc(code_b, tail)
assert len(praw) == len(raw) == 0x3d15a0
diff_lines = [i for i in range(nlines) if raw[i*68:(i+1)*68] != praw[i*68:(i+1)*68]]
def lines_for(r0, r1):
    return set(range(r0//64, (r1-1)//64 + 1))
exp_lines = sorted(lines_for(0x090b7c, 0x090b88) | lines_for(0x090be4, 0x090bf0) |
                   lines_for(0x0d3cf4, 0x0d3d00) | lines_for(LOC0, TAB1))
print('[7] changed 68B lines vs S0 raw: %s' % diff_lines)
print('    expected: %s' % exp_lines)
if diff_lines != exp_lines:
    die('unexpected changed-line set')
for i in diff_lines:
    o = i*68
    oldc = struct.unpack('<H', raw[o+66:o+68])[0]
    newc = struct.unpack('<H', praw[o+66:o+68])[0]
    print('    line %5d dc 0x%06x raw 0x%06x..0x%06x: clcrc 0x%04x -> 0x%04x' % (i, i*64, o, o+68, oldc, newc))
open(RAW_OUT, 'wb').write(praw)
print('[7] patched raw: 0x%x bytes, %d lines changed, all others byte-identical' % (len(praw), len(diff_lines)))

# ============ 8. build image via mlxfwutil.patch_sections ============
edits = [(0x03, i*68, praw[i*68:(i+1)*68]) for i in diff_lines]
out = mlxfwutil.patch_sections(img, edits)
md5_out = hashlib.md5(out).hexdigest()
open(OUT, 'wb').write(out)
print('[8] S1 image built: %s md5=%s' % (OUT, md5_out))

# 8.1 byte diff S1 vs S0 image
diffs = [i for i in range(len(out)) if out[i] != base_bytes[i]]
print('[8.1] S1 vs S0 image byte-diff: %d bytes' % len(diffs))
# expected: 12 lines * 68B (section data) + 4B ITOC entry 0x03 (sec_crc+entry_crc)
print('      expected max: %d (12*68 + 4 ITOC)' % (len(diff_lines)*68 + 4))
assert len(diffs) <= len(diff_lines)*68 + 4
# all section-data diffs must lie inside the 12 changed lines of section 0x03
sec_off = img.sec_abs(e)
print('      section 0x03 payload offset in image: 0x%x' % sec_off)
sec_diff = [i for i in diffs if sec_off <= i < sec_off + len(raw)]
toc_diff = [i for i in diffs if not (sec_off <= i < sec_off + len(raw))]
assert len(sec_diff) + len(toc_diff) == len(diffs)
print('      diff in section payload: %d bytes; diff in ITOC: %d bytes at %s' %
      (len(sec_diff), len(toc_diff), ['0x%x' % i for i in toc_diff]))
assert len(toc_diff) <= 4
# section payload diffs must be subset of changed lines
bad_off = [i for i in sec_diff if (i - sec_off) // 68 not in set(diff_lines)]
assert not bad_off, bad_off[:10]
print('      all section-payload diffs inside the %d changed lines: OK' % len(diff_lines))

# ============ 9. verify ============
# 9.1 per-line clcrc full round-trip on S1 raw (recompute == stored, ALL lines)
pimg = mlxfwutil.Image(out, OUT, base=img.base, fmt=img.fmt)
pe = pimg.find_entry('ITOC', 0x03)
praw2 = pimg.section_data(pe)
assert praw2 == praw, 'S1 section raw != built raw'
pcode = decrc(praw2)
rt2 = clcrc(pcode, praw2[nlines*68:])
if rt2 != praw2:
    inv = []
    for i in range(nlines):
        if praw2[i*68:(i+1)*68] != rt2[i*68:(i+1)*68]:
            inv.append((i, '%04x' % struct.unpack('<H', praw2[i*68+66:i*68+68])[0],
                        '%04x' % struct.unpack('<H', rt2[i*68+66:i*68+68])[0]))
            if len(inv) > 10: break
    die('per-line clcrc round-trip FAILED: %s' % inv)
print('[9.1] per-line clcrc round-trip: ALL %d lines recompute == stored (PASS)' % nlines)

# 9.2 mlxfwutil verify --deep
errs = mlxfwutil.verify_image(pimg, deep=True)
print('[9.2] mlxfwutil verify --deep: %s' % ('PASS' if not errs else errs))
if errs:
    die('mlxfwutil verify failed')

# 9.3 ITOC entry 0x03 CRC fields (entry.raw: sec_crc @26-27 BE, entry_crc @30-31 BE)
def crcs(e):
    return struct.unpack_from('>H', e.raw, 26)[0], struct.unpack_from('>H', e.raw, 30)[0]
s0_sec, s0_ent = crcs(img.find_entry('ITOC', 0x03))
s1_sec, s1_ent = crcs(pimg.find_entry('ITOC', 0x03))
print('[9.3] ITOC entry 0x03: S0 sec_crc=0x%04x entry_crc=0x%04x -> S1 sec_crc=0x%04x entry_crc=0x%04x' %
      (s0_sec, s0_ent, s1_sec, s1_ent))
assert (s0_sec, s0_ent) == (0x1844, 0xbd8f), 'S0 entry CRC not as expected (PC4 journal)'
assert (s1_sec, s1_ent) != (s0_sec, s0_ent), 'entry CRCs unchanged'
print('      (chain: stock 0x29fc/0x7ebf -> S0 0x1844/0xbd8f -> S1 0x%04x/0x%04x)' % (s1_sec, s1_ent))
if toc_diff:
    for i in toc_diff:
        print('      byte 0x%04x: S0 %02x -> S1 %02x' % (i, base_bytes[i], out[i]))
print('[9.3] ITOC 0x03 CRC bytes updated: %s' % ('yes (%d bytes)' % len(toc_diff) if toc_diff else 'NO - CHECK'))
assert toc_diff, 'ITOC entry CRC not updated?'

print()
print('DONE %s md5=%s' % (OUT, md5_out))
