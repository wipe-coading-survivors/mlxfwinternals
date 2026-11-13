#!/usr/bin/env python3
"""fuzz-4 vector artifacts (offline): marker + w1prio + fuzz3rem + c2rare.

Protocol (spec 2026-10-25-irisc-fuzz4-design.md §3): 10 words (40B BE) per
vector — 7 free code words + fixed tail triple resuming to rt 0x8E43C8
(table_id word @input[0x14..0x18) is supplied by the tool, not part of the
payload); writes only to echo [r18+0x10..0x38) and CR rt 0x2320..0x233c;
seeds are per-slot u32 planted by host at slots 0x8c6/0x8c7 (rt 0x2318/
0x231c); ld.d seed loads always use base 0x2318 (reads 0x8c6+0x8c7, never
base 0x231c which would read into the result slot).
32-bit constants: addi+addi.hi only when both halves are non-negative s16
(addi sign-extends, addi.hi = rs+(s16<<16) mod 2^32 — docs/250-re/120-irisc/010-isa.md); otherwise
live-proven set2/set3 (insert halfwords into bits 31..16 / 15..0; upper 32
bits of the register stay stale). Composed values are re-verified from the
disassembly by check_compose.
Expectations transcribed from WP-1 calc tables (journal
2026-10-25-irisc-isa-i2-bitops-grind.md §6) and fuzz-3 §2.6.
st.d to CR writes 8 bytes: expectation key "0x8c8" means low32 at 0x8c8 and
high32 at 0x8c9 (pair-check); "echo" is the 8-byte echo zone at [r18+0x10].
"""
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from scripts.irisc import assemble, disasm, AsmError

OUT = Path(__file__).resolve().parent / 'fuzz4_vectors.json'

PROFILE = 'cx5'
CR_SLOT_RT = 0x2320
CR_SLOT_ID = '0x8c8'
SEED_A_RT = 0x2318
SENTINEL = '0xdeadbeef'

NOP0 = 'addi zero,zero,0'
TAIL = ['addi r4,zero,0x43c8', 'addi.hi r4,r4,0x8e', 'ret.r zero,zero,r4']


def _pnum(tok):
    if tok.startswith('0x-'):
        tok = '-0x' + tok[3:]
    return int(tok, 0)


def const32(valreg, value):
    lo, hi = value & 0xffff, (value >> 16) & 0xffff
    if lo < 0x8000 and hi < 0x8000:
        return ['addi %s,zero,0x%x' % (valreg, lo),
                'addi.hi %s,%s,0x%x' % (valreg, valreg, hi)]
    return ['set2 %s,zero,0x%x' % (valreg, hi),
            'set3 %s,%s,0x%x' % (valreg, valreg, lo)]


def seed_single(dst):
    return ['addi r3,zero,0x%x' % SEED_A_RT, 'ld.d %s,r3,0' % dst]


def cr_write(valreg):
    return ['addi r3,zero,0x%x' % CR_SLOT_RT, 'st.d %s,r3,0' % valreg]


def echo_write(valreg):
    return ['st.d %s,r18,0x10' % valreg]


def cc0a_body(op_line, wr_line, pre=None):
    body = list(pre or [])
    body += [op_line, 'b.t.0xa zero,tail', wr_line]
    return body


TAIL_WORDS = None


def build_vector(body):
    if len(body) > 7:
        raise AsmError('body budget exceeded: %d words, want <=7' % len(body))
    body = body + [NOP0] * (7 - len(body))
    lines = body + ['lbl tail'] + TAIL
    data = assemble('\n'.join(lines), base=0, profile=PROFILE)
    words = list(struct.unpack('>%dI' % (len(data) // 4), data))
    if len(words) != 10:
        raise AsmError('budget: got %d words, want 10' % len(words))
    if words[7:] != TAIL_WORDS:
        raise AsmError('tail triple mismatch: %r' % [hex(w) for w in words[7:]])
    return words


_STORES = ('st.d', 'st.d!', 'st.d.1e', 'st.w', 'st.w!', 'st.q', 'st.q!',
           'st.b')
_ECHO_MAX = {'st.d': 0x30, 'st.d!': 0x30, 'st.d.1e': 0x30,
             'st.w': 0x34, 'st.w!': 0x34, 'st.q': 0x28, 'st.q!': 0x28,
             'st.b': 0x37}
_DST_LESS = {'st.b', 'st.w', 'st.d', 'st.q', 'st.w!', 'st.d!', 'st.q!',
             'st.d.1e', 'st.q.1e', 'b.t', 'b.f', 'b.bset', 'b.bclr',
             'jump', 'call', 'csr.w', 'st.i'}
_FORBIDDEN_DST = ({'r1', 'r2', 'r11'} | {'r%d' % i for i in range(12, 17)}
                  | {'r%d' % i for i in range(17, 24)})


def check_write_discipline(words, vid):
    consts = {}
    writes = 0
    for i, w in enumerate(words):
        line = disasm(w, i * 4)
        mnem = line.split(None, 1)[0]
        args = [a.strip() for a in line.split(None, 1)[1].split(',')] \
            if ' ' in line else []
        if mnem == 'call':
            raise AsmError('%s: call forbidden (link r11): %s' % (vid, line))
        if mnem == 'addi' and len(args) == 3 and args[1] == 'zero':
            consts[args[0]] = _pnum(args[2]) & 0xffff
        elif mnem == 'addi.hi' and len(args) == 3 and args[0] == args[1]:
            consts[args[0]] = ((consts.get(args[0], 0) & 0xffff)
                               | ((_pnum(args[2]) & 0xffff) << 16))
        if mnem in _STORES:
            if '!' in mnem:
                raise AsmError('%s: push/store-with-update forbidden: %s'
                               % (vid, line))
            base, off = args[1], int(args[2], 0)
            if base == 'r18':
                if not (0x10 <= off <= _ECHO_MAX[mnem]):
                    raise AsmError('%s: echo offset 0x%x out of range for '
                                   '%s (spans past 0x38): %s'
                                   % (vid, off, mnem, line))
                writes += 1
            elif consts.get(base) is not None \
                    and 0x2320 <= consts[base] <= 0x233c:
                writes += 1
            else:
                raise AsmError('%s: bad store target: %s' % (vid, line))
        if mnem not in _DST_LESS and args:
            dst = args[0].split('=')[-1].strip()
            if dst in _FORBIDDEN_DST:
                raise AsmError('%s: forbidden dst %s: %s' % (vid, dst, line))
    if writes < 1:
        raise AsmError('%s: no write channel' % vid)
    return writes


def check_compose(words, vid, checks, seeds):
    st = {}
    consts = {}
    lines = []
    for i, w in enumerate(words):
        lines.append((i, disasm(w, i * 4)))
    by_idx = {}
    for idx, regs in checks:
        by_idx.setdefault(idx, {}).update(regs)
    for i, line in lines:
        if i in by_idx:
            for reg, (want_lo, want_hi) in by_idx[i].items():
                if reg not in st:
                    raise AsmError('%s: compose check r%d@%d: no state'
                                   % (vid, int(reg[1:]), i))
                lo, hi = st[reg]
                if lo != want_lo & 0xffffffff:
                    raise AsmError(
                        '%s: compose r%s@%d low32 %08x != %08x (%s)'
                        % (vid, reg, i, lo, want_lo & 0xffffffff, line))
                if want_hi is not None and hi != want_hi:
                    raise AsmError(
                        '%s: compose r%s@%d upper32 %s != %08x'
                        % (vid, reg, i, 'stale' if hi is None else
                           '%08x' % hi, want_hi))
        mnem = line.split(None, 1)[0]
        args = [a.strip() for a in line.split(None, 1)[1].split(',')] \
            if ' ' in line else []
        if mnem == 'addi' and len(args) == 3:
            v = _pnum(args[2])
            se = v - 0x10000 if v & 0x8000 else v
            if args[1] == 'zero':
                st[args[0]] = (se & 0xffffffff, 0 if se >= 0 else 0xffffffff)
            else:
                st.pop(args[0], None)
        elif mnem == 'addi.hi' and len(args) == 3:
            v = _pnum(args[2])
            se = v - 0x10000 if v & 0x8000 else v
            if args[0] == args[1] and args[0] in st:
                lo, hi = st[args[0]]
                st[args[0]] = ((lo + ((se & 0xffffffff) << 16)) & 0xffffffff,
                               hi)
            else:
                st.pop(args[0], None)
        elif mnem in ('set2', 'set3') and len(args) == 3:
            lo, hi = st.get(args[0], (0, None))
            imm = _pnum(args[2]) & 0xffff
            if mnem == 'set2':
                st[args[0]] = ((lo & 0xffff) | (imm << 16), None)
            else:
                st[args[0]] = ((lo & 0xffff0000) | imm, None)
        elif mnem == 'ld.d' and len(args) == 3:
            base, off = args[1], int(args[2], 0)
            addr = consts.get(base)
            addr = None if addr is None else addr + off
            if addr == SEED_A_RT and seeds:
                lo = int(seeds.get('0x8c6', '0'), 16)
                hi = int(seeds.get('0x8c7', '0'), 16)
                st[args[0]] = (lo, hi)
            else:
                st.pop(args[0], None)
        elif mnem == 'shl64.i' and len(args) == 3:
            if args[1] in st and st[args[1]][1] is not None:
                lo, hi = st[args[1]]
                v = ((hi << 32) | lo) << (_pnum(args[2]) & 0x1f)
                st[args[0]] = (v & 0xffffffff, (v >> 32) & 0xffffffff)
            else:
                st.pop(args[0], None)
        else:
            if args and args[0].startswith('r'):
                st.pop(args[0], None)
        if mnem == 'addi' and len(args) == 3 and args[1] == 'zero':
            consts[args[0]] = _pnum(args[2]) & 0xffff
        elif mnem == 'addi.hi' and len(args) == 3 and args[0] == args[1]:
            consts[args[0]] = ((consts.get(args[0], 0) & 0xffff)
                               | ((_pnum(args[2]) & 0xffff) << 16))
    if any(i >= len(words) for i in by_idx):
        raise AsmError('%s: compose check index out of range' % vid)


def roundtrip_word(w, pos):
    text = disasm(w, pos)
    back = assemble(text, base=pos, profile=PROFILE)
    w2 = struct.unpack('>I', back)[0]
    # canon roundtrip semantics: exact or fixpoint (lossy renders
    # stabilize); only DRIFT fails
    return w2 == w or disasm(w2, pos) == text, text


NOTE_CR = ('; st.d CR pair-check: low32 @0x8c8, high32 @0x8c9')
NOTE_SEEDS = ('; seeds u32/slot: 0x8c6=lo/0x8c7=hi word, ld.d base 0x2318 '
              'only')


def emit(vec):
    words = build_vector(vec['body'])
    vid = vec['id']
    check_write_discipline(words, vid)
    seeds = vec.get('seeds', {})
    check_compose(words, vid, vec.get('reg_checks', []), seeds)
    for i, w in enumerate(words):
        ok, text = roundtrip_word(w, i * 4)
        if not ok:
            raise AsmError('%s: word %d roundtrip DRIFT: %08x %s'
                           % (vid, i, w, text))
    if 'op_word' in vec:
        idx, want = vec['op_word']
        if words[idx] != want:
            raise AsmError('%s: op word %08x != journal %08x'
                           % (vec['id'], words[idx], want))
    rec = {'id': vid, 'group': vec['group'],
           'words': ['%08x' % w for w in words]}
    if seeds:
        rec['seeds'] = seeds
    if vec.get('expectations'):
        rec['expectations'] = vec['expectations']
    if vec.get('controls'):
        rec['controls'] = vec['controls']
    notes = vec.get('notes', '')
    has_cr = any(k == CR_SLOT_ID for e in vec.get('expectations', {}).values()
                 for k in e)
    if has_cr:
        notes += NOTE_CR
    if seeds:
        notes += NOTE_SEEDS
    rec['notes'] = notes.strip('; ')
    return rec


def ck(idx, **regs):
    return (idx, regs)


def rc(lo, hi=None):
    return (lo, hi)


VECTORS = [
    {
        'id': 'V-F4-MARKER', 'group': 'marker',
        'body': ['set2 r3,zero,0xf00d', 'set3 r3,r3,0xf00d',
                 'st.d r3,r18,0x10', 'addi r4,zero,0x%x' % CR_SLOT_RT,
                 'st.d r3,r4,0'],
        'reg_checks': [ck(2, r3=rc(0xf00df00d))],
        'expectations': {'H-marker': {CR_SLOT_ID: '0xf00df00d',
                                      'echo': '0xf00df00d'}},
        'notes': 'execution marker 0xF00DF00D to echo [r18+0x10] and CR '
                 'rt 0x2320; CR word must be exactly 0xF00DF00D; echo '
                 'upper 32 bits unspecified (set2/set3 load, low32 check)',
    },
    {
        'id': 'V-0c-1', 'group': 'w1prio',
        'body': seed_single('r5') + ['andmsk.hi r4,r5,0x00ff']
                + cr_write('r4') + echo_write('r4'),
        'seeds': {'0x8c6': '0xabcd1234', '0x8c7': '0x00000000'},
        'reg_checks': [ck(2, r5=rc(0xabcd1234, 0))],
        'expectations': {
            'H-0c-ANDN-raw': {'0x8c8': '0xabcd1200', 'echo': '0xabcd1200'},
            'H-0c-ANDN-sh16': {'0x8c8': '0xab001234', 'echo': '0xab001234'},
            'H-0c-OR': {'0x8c8': '0xabcd12ff', 'echo': '0xabcd12ff'}},
        'notes': 'or-imm revision trio 1/3: rs=0xabcd1234 imm=0x00ff, '
                 'three outcomes pairwise distinct; rs seeded (hi half '
                 '0xabcd is negative s16, inline pair would leave upper '
                 'stale)',
    },
    {
        'id': 'V-0c-2', 'group': 'w1prio',
        'body': ['addi r5,zero,0', 'andmsk.hi r4,r5,0xff00']
                + cr_write('r4') + echo_write('r4'),
        'reg_checks': [ck(1, r5=rc(0, 0))],
        'expectations': {
            'H-0c-ANDN-raw': {'0x8c8': '0x0000000000000000',
                              'echo': '0x0000000000000000'},
            'H-0c-ANDN-sh16': {'0x8c8': '0x0000000000000000',
                               'echo': '0x0000000000000000'},
            'H-0c-OR': {'0x8c8': '0x000000000000ff00',
                        'echo': '0x000000000000ff00'}},
        'notes': 'or-imm trio 2/3: rs=0 imm=0xff00, only OR-raw nonzero '
                 '(closes position for ANDN=0 cases jointly with V-0c-1/3)',
    },
    {
        'id': 'V-0c-3', 'group': 'w1prio',
        'body': const32('r5', 0x12345678) + ['andmsk.hi r4,r5,0x0f00']
                + cr_write('r4') + echo_write('r4'),
        'reg_checks': [ck(2, r5=rc(0x12345678, 0))],
        'expectations': {
            'H-0c-ANDN-raw': {'0x8c8': '0x12345078', 'echo': '0x12345078'},
            'H-0c-ANDN-sh16': {'0x8c8': '0x10345678', 'echo': '0x10345678'},
            'H-0c-OR': {'0x8c8': '0x12345f78', 'echo': '0x12345f78'}},
        'notes': 'or-imm trio 3/3: rs=0x12345678 imm=0x0f00, all three '
                 'outcomes pairwise distinct',
    },
    {
        'id': 'V-34-1', 'group': 'w1prio',
        # the rosetta word is bit-exact (rt=1); since the canon-sync
        # bclr.1 render (5a292d0) lo11=0x022 words render lossy, so the
        # bit-exact escape is the dword raw literal (decode-verify
        # exempt by design; op_word below still pins the golden)
        'body': seed_single('r5') + ['dword 0xd0a40822']
                + cr_write('r4') + echo_write('r4'),
        'seeds': {'0x8c6': '0xffffffff', '0x8c7': '0xffffffff'},
        'reg_checks': [ck(2, r5=rc(0xffffffff, 0xffffffff))],
        'op_word': (2, 0xd0a40822),
        'expectations': {'H-34-clr': {'0x8c8': '0xfffffffffffffffd',
                                      'echo': '0xfffffffffffffffd'}},
        'notes': 'rosetta f5=2 bit-clr: FW word @0x08c124 bit-exact '
                 '(rt=r1 read-only, value irrelevant for clr)',
    },
    {
        'id': 'V-34-2', 'group': 'w1prio',
        'body': ['addi r5,zero,0xff', 'op0x34 r4,r5,r1 imm=0x0a22']
                + cr_write('r4') + echo_write('r4'),
        'reg_checks': [ck(1, r5=rc(0xff, 0))],
        'op_word': (1, 0xd0a40a22),
        'expectations': {'H-34-clr': {'0x8c8': '0x000000df',
                                      'echo': '0x000000df'}},
        'notes': 'rosetta f5=2 idx=5 on rs=0xff: idx-semantics check '
                 '(clr bit5 -> 0xdf)',
    },
    {
        'id': 'V-34-6', 'group': 'w1prio',
        'body': seed_single('r5') + ['op0x34 r4,r5,zero imm=0x0086']
                + cr_write('r4') + echo_write('r4'),
        'seeds': {'0x8c6': '0xffffffff', '0x8c7': '0x00000000'},
        'reg_checks': [ck(2, r5=rc(0xffffffff, 0))],
        'op_word': (2, 0xd0a40086),
        'expectations': {
            'H-34-6-clr-lo': {'0x8c8': '0x00000000fffffff0',
                              'echo': '0x00000000fffffff0'},
            'H-34-6-clr-hi': {'0x8c8': '0x00000000ffffff0f',
                              'echo': '0x00000000ffffff0f'}},
        'notes': 'ESW-top class @0x3156c4: f5=6 idx=4, clr-nibble@4 '
                 'sub-hypotheses (nibble position open); rs seeded 64-bit '
                 '0x00000000ffffffff (upper=0 required by expectations)',
    },
    {
        'id': 'V-34-7', 'group': 'w1prio',
        'body': ['addi r5,zero,0', 'addi r9,zero,0x1234',
                 'op0x34 r4,r5,r9 imm=0x4d4c']
                + cr_write('r4') + echo_write('r4'),
        'reg_checks': [ck(2, r5=rc(0, 0), r9=rc(0x1234, 0))],
        'op_word': (2, 0xd0a44d4c),
        'expectations': {
            'H-34-7-w14': {'0x8c8': '0x003ffc00', 'echo': '0x003ffc00'},
            'H-34-7-w10': {'0x8c8': '0x003fc00', 'echo': '0x003fc00'},
            'H-34-7-w8': {'0x8c8': '0x00ffc00', 'echo': '0x00ffc00'}},
        'notes': 'rosetta-context f5=0xc idx=10: FW word @0x3157c8 '
                 'bit-exact, rt=r9=0x1234, deposit@10 width? (14/10/8)',
    },
    {
        'id': 'V-0d-2', 'group': 'w1prio',
        'body': seed_single('r5') + ['op0x0d r4,r5,zero imm=0x00ff']
                + cr_write('r4') + echo_write('r4'),
        'seeds': {'0x8c6': '0xffffffff', '0x8c7': '0x00000000'},
        'reg_checks': [ck(2, r5=rc(0xffffffff, 0))],
        'op_word': (2, 0x34a400ff),
        'expectations': {
            'H-0d-A': {'0x8c8': '0x0000000000ff0000',
                       'echo': '0x0000000000ff0000'},
            'H-0d-raw': {'0x8c8': '0x00000000000000ff',
                         'echo': '0x00000000000000ff'},
            'H-0d-sh16': {'0x8c8': '0x00000000000000ff',
                          'echo': '0x00000000000000ff'}},
        'notes': 'mask position discriminator: unit mask 0x00ff on '
                 'rs=0x00000000ffffffff; H-0d-sh16 gives 0xff (same as '
                 'H-raw here, position closed by V-0d-3/4)',
    },
    {
        'id': 'V-0d-3', 'group': 'w1prio',
        'body': seed_single('r5') + ['op0x0d r4,r5,zero imm=0xff00']
                + cr_write('r4') + echo_write('r4'),
        'seeds': {'0x8c6': '0xccdd2233', '0x8c7': '0x0011aabb'},
        'reg_checks': [ck(2, r5=rc(0xccdd2233, 0x0011aabb))],
        'op_word': (2, 0x34a4ff00),
        'expectations': {
            'H-0d-A': {'0x8c8': '0x00000000cc000000',
                       'echo': '0x00000000cc000000'},
            'H-0d-raw': {'0x8c8': '0x0000000000002200',
                         'echo': '0x0000000000002200'},
            'H-0d-sh16': {'0x8c8': '0x000000000000cc00',
                          'echo': '0x000000000000cc00'}},
        'notes': 'mask position discriminator 2: imm=0xff00, all three '
                 'outcomes pairwise distinct',
    },
    {
        'id': 'V-0d-4', 'group': 'w1prio',
        'body': seed_single('r5') + ['op0x0d r4,r5,zero imm=0x8000']
                + cr_write('r4') + echo_write('r4'),
        'seeds': {'0x8c6': '0x80000000', '0x8c7': '0x00000000'},
        'reg_checks': [ck(2, r5=rc(0x80000000, 0))],
        'op_word': (2, 0x34a48000),
        'expectations': {
            'H-0d-A': {'0x8c8': '0x0000000080000000',
                       'echo': '0x0000000080000000'},
            'H-0d-raw': {'0x8c8': '0x0000000000000000',
                         'echo': '0x0000000000000000'},
            'H-0d-sh16': {'0x8c8': '0x0000000080000000',
                          'echo': '0x0000000080000000'}},
        'notes': 'mask position discriminator 3: imm=0x8000 on '
                 'rs=0x80000000 (H-A and H-sh16 coincide here, split by '
                 'V-0d-2/3)',
    },
    {
        'id': 'V-0d-5', 'group': 'w1prio',
        'body': ['addi r5,zero,0xabc', 'shl64.i r5,r5,0x10',
                 'op0x0d r4,r5,zero imm=0x0f00']
                + cr_write('r4') + echo_write('r4'),
        'reg_checks': [ck(2, r5=rc(0x0abc0000, 0))],
        'op_word': (2, 0x34a40f00),
        'expectations': {
            'H-0d-A': {'0x8c8': '0x000000000a000000',
                       'echo': '0x000000000a000000'},
            'H-0d-raw': {'0x8c8': '0x0000000000000000',
                         'echo': '0x0000000000000000'},
            'H-0d-sh16': {'0x8c8': '0x0000000000000a00',
                          'echo': '0x0000000000000a00'}},
        'notes': 'FW idiom check (shl64+0x0d): rs built by shl64.i '
                 '0xabc,0x10 -> 0x0abc0000; journal used 0xabcd<<0xc — '
                 '0xabcd is negative s16 (addi sign-extends, upper '
                 'polluted), substituted with positive-s16 constant of '
                 'the same mask class (three outcomes still pairwise '
                 'distinct)',
    },
    {
        'id': 'V-33-2', 'group': 'w1prio',
        'body': ['addi r5,zero,5', 'addi r6,zero,3',
                 'op0x33 r4,r5,r6 imm=0x3018']
                + cr_write('r4') + echo_write('r4'),
        'reg_checks': [ck(2, r5=rc(5, 0), r6=rc(3, 0))],
        'op_word': (2, 0xcca43018),
        'expectations': {
            'H-33-2-min': {'0x8c8': '0x3', 'echo': '0x3'},
            'H-33-2-max': {'0x8c8': '0x5', 'echo': '0x5'},
            'H-33-2-add': {'0x8c8': '0x8', 'echo': '0x8'},
            'H-33-2-or': {'0x8c8': '0x7', 'echo': '0x7'}},
        'notes': 'FW-top class @0x1636bc/0x3062c8: f5=0x18 idx=0, four '
                 'outcomes pairwise distinct (min/max/add/or) — 4-in-1 slot',
    },
    {
        'id': 'V-33-1', 'group': 'w1prio',
        'body': ['addi r5,zero,0', 'addi r6,zero,1',
                 'op0x33 r4,r5,r6 imm=0x3321']
                + cr_write('r4') + echo_write('r4'),
        'reg_checks': [ck(2, r5=rc(0, 0), r6=rc(1, 0))],
        'op_word': (2, 0xcca43321),
        'expectations': {'H-33-bit': {'0x8c8': '0x2000000',
                                      'echo': '0x2000000'}},
        'notes': 'bit-deposit f5=1 idx=25: rt=1 into rs=0',
    },
    {
        'id': 'V-33-3', 'group': 'w1prio',
        'body': seed_single('r5') + ['addi r6,zero,0x100',
                 'op0x33 r4,r5,r6 imm=0x31d0'] + cr_write('r4'),
        'seeds': {'0x8c6': '0x00168000', '0x8c7': '0x00000000'},
        'reg_checks': [ck(3, r5=rc(0x00168000, 0), r6=rc(0x100, 0))],
        'op_word': (3, 0xcca431d0),
        'expectations': {
            'H-33-3-clamp': {'0x8c8': '0x400000'},
            'H-33-3-pass': {'0x8c8': '0x168000'}},
        'notes': 'FW word @0x38b0: f5=0x10 idx=14, clamp16@14 '
                 '(0x5a<<14 = 0x168000, rt=0x100 clamp limit) vs pass; '
                 'rs seeded 64-bit (upper=0)',
    },
    {
        'id': 'V-f5map-1', 'group': 'fuzz3rem',
        'body': cc0a_body('op0x36 zero,r5,r6 imm=0x3004',
                          'st.d r6,r3,0',
                          pre=['addi r3,zero,0x%x' % CR_SLOT_RT,
                               'addi r5,zero,3', 'addi r6,zero,5',
                               'cmp38_eq32 r5,r6']),
        'controls': {'cr_sentinel': SENTINEL},
        'expectations': {
            'H-36-f5p4-eq32': {'0x8c8': '0x5'},
            'H-36-f5p4-uge32': {'0x8c8': '0x5'},
            'H-36-f5p4-ule32': {'0x8c8': SENTINEL},
            'H-36-f5p4-eq16': {'0x8c8': '0x5'}},
        'notes': 'f5=4 map, pair (rs=3, rt=5); known-FALSE predecessor '
                 'cmp38(3,5) — T can only come from op0x36; T-path skips '
                 'write -> sentinel stays; F-path writes rt value 5; '
                 'T=>{ule32}, F=>{eq32,uge32,eq16, no-cc-write}',
    },
    {
        'id': 'V-f5map-2', 'group': 'fuzz3rem',
        'body': cc0a_body('op0x36 zero,r5,r6 imm=0x3004',
                          'st.d r6,r3,0',
                          pre=['addi r3,zero,0x%x' % CR_SLOT_RT,
                               'addi r5,zero,7', 'addi r6,zero,3',
                               'cmp38_eq32 r5,r6']),
        'controls': {'cr_sentinel': SENTINEL},
        'expectations': {
            'H-36-f5p4-uge32': {'0x8c8': SENTINEL},
            'H-36-f5p4-eq32': {'0x8c8': '0x3'},
            'H-36-f5p4-eq16': {'0x8c8': '0x3'},
            'H-36-f5p4-ule32': {'0x8c8': '0x3'}},
        'notes': 'f5=4 map, pair (rs=7, rt=3) [journal tuple (3,7); '
                 'orientation chosen so uge vs eq discriminate]; '
                 'known-FALSE predecessor cmp38(7,3); T=>{uge32}, '
                 'F=>{eq32,eq16,ule32,no-cc-write}',
    },
    {
        'id': 'V-f5map-3', 'group': 'fuzz3rem',
        'body': cc0a_body('op0x36 zero,r5,r6 imm=0x300a',
                          'st.d r6,r3,0',
                          pre=['addi r3,zero,0x%x' % CR_SLOT_RT,
                               'addi r5,zero,5', 'addi r6,zero,3',
                               'cmp38_eq32 r5,r6']),
        'controls': {'cr_sentinel': SENTINEL},
        'expectations': {
            'H-36-f5pa-ne32': {'0x8c8': SENTINEL},
            'H-36-f5pa-gt32': {'0x8c8': SENTINEL},
            'H-36-f5pa-ugt32': {'0x8c8': SENTINEL},
            'H-36-f5pa-lt32': {'0x8c8': '0x3'}},
        'notes': 'f5=0xa map, pair (rs=5, rt=3); known-FALSE predecessor '
                 'cmp38(5,3); T=>{ne32,gt32,ugt32}, F=>{lt32,no-cc-write}',
    },
    {
        'id': 'V-ltV-1', 'group': 'fuzz3rem',
        'body': cc0a_body('op0x36 zero,r5,r6 imm=0x3002',
                          'st.d r6,r18,0x10',
                          pre=const32('r5', 0x7fffffff)
                          + const32('r6', 0x80000000)),
        'controls': {'echo_stale': 'stock'},
        'expectations': {
            'H-36-f5p2-lt32': {'echo': '0x0000000080000000'},
            'H-36-f5p2-lt16': {'echo': 'stock'},
            'H-36-f5p2-V': {'echo': 'stock'}},
        'notes': 'f5=2 lt32-vs-lt16-vs-V discriminator 1 '
                 '(0x7FFFFFFF vs 0x80000000), operands inline (seed pair '
                 'structurally impossible: slots are 4-byte strided, '
                 'ld.d@+4 would read result slot 0x8c8); no predecessor '
                 '(budget), T-vs-stale-T ambiguity noted; F=>{lt32} '
                 'writes echo, T=>{lt16,V} leaves stock golden echo',
    },
    {
        'id': 'V-ltV-2', 'group': 'fuzz3rem',
        'body': cc0a_body('op0x36 zero,r5,r6 imm=0x3002',
                          'st.d r6,r18,0x10',
                          pre=const32('r5', 0x00010005)
                          + const32('r6', 0x00020003)),
        'controls': {'echo_stale': 'stock'},
        'expectations': {
            'H-36-f5p2-lt32': {'echo': 'stock'},
            'H-36-f5p2-lt16': {'echo': '0x0000000000020003'},
            'H-36-f5p2-V': {'echo': '0x0000000000020003'}},
        'notes': 'f5=2 discriminator 2 (0x00010005 vs 0x00020003), '
                 'operands inline; T=>{lt32} stale, F=>{lt16,V} writes '
                 'echo=0x00020003; splits lt32 from lt16/V jointly with '
                 'V-ltV-1; no predecessor (budget)',
    },
    {
        'id': 'V-imm6', 'group': 'fuzz3rem',
        'body': cc0a_body('op0x36 zero,r5,zero imm=0x0404',
                          'st.d r5,r3,0',
                          pre=['addi r3,zero,0x%x' % CR_SLOT_RT,
                               'addi r5,zero,5', 'addi r6,zero,9',
                               'cmp38_eq32 r5,r6']),
        'controls': {'cr_sentinel': SENTINEL},
        'expectations': {
            'H-36-imm6-lt32': {'0x8c8': SENTINEL},
            'H-36-imm6-ne32': {'0x8c8': SENTINEL},
            'H-36-imm6-eq32reg': {'0x8c8': '0x5'}},
        'notes': 'imm6 form (S2 precedent lo11=i6<<5|f5, i6=32 f5=4): '
                 'rs=5 vs imm6=32; known-FALSE predecessor cmp38(5,9) '
                 '(stale-cc0a control); T=>{lt32,ne32}, F=>{eq32 reg-reg '
                 '(rt field zero = 0), no-cc-write}; F-path writes rs '
                 'value 5',
    },
    {
        'id': 'V-op38-self', 'group': 'fuzz3rem',
        'body': cc0a_body('cmp38_eq32 r5,r5', 'st.d r6,r18,0x10',
                          pre=['addi r5,zero,7', 'addi r6,zero,7',
                               'cmp38_eq32 r5,r6']),
        'controls': {'echo_stale': 'stock'},
        'expectations': {
            'H-op38-self-false': {'echo': '0x7'},
            'H-op38-self-keepT': {'echo': 'stock'}},
        'notes': 'self-exclusion: known-T predecessor (7==7 P2-form) '
                 'then self cmp38_eq32 r5,r5; self=>FALSE leaves echo=7 '
                 '(branch not taken), keep-T => stock echo',
    },
    {
        'id': 'V-r-3c', 'group': 'c2rare',
        'body': seed_single('r5') + ['op0x3c r4,r5,r31 imm=0xffff']
                + cr_write('r4') + echo_write('r4'),
        'seeds': {'0x8c6': '0x00001234', '0x8c7': '0x0000abcd'},
        'reg_checks': [ck(2, r5=rc(0x00001234, 0x0000abcd))],
        'notes': 'rare 0x3c (0x154e58-form): 64-bit shift/mask candidate; '
                 'rt=r31 read-only unknown; rd captured in CR+echo, '
                 'halves analyzed offline',
    },
    {
        'id': 'V-r-39', 'group': 'c2rare',
        'body': ['addi r3,zero,0x%x' % SEED_A_RT, 'ld.d r4,r3,0',
                 'op0x39 r4,r4,zero imm=0x0000'] + cr_write('r4')
                + echo_write('r4'),
        'seeds': {'0x8c6': '0x12345678', '0x8c7': '0x89abcdef'},
        'reg_checks': [ck(2, r4=rc(0x12345678, 0x89abcdef))],
        'notes': 'rare 0x39: 64-bit transform on rs=rd=r4; both halves '
                 'distinct pattern in seed',
    },
    {
        'id': 'V-r-16', 'group': 'c2rare',
        'body': const32('r5', 0x00100000) + ['op0x16 r4,r5,zero imm=0x0028']
                + cr_write('r4'),
        'reg_checks': [ck(2, r5=rc(0x00100000, 0))],
        'notes': 'rare 0x16: lea-semantics candidate rd = rs +imm / '
                 '+(imm<<k); rs=0x00100000 known, rd-rs analyzed offline',
    },
]


def main():
    global TAIL_WORDS
    TAIL_WORDS = list(struct.unpack('>3I', assemble(
        '\n'.join(TAIL), base=0, profile=PROFILE)))
    recs = [emit(v) for v in VECTORS]
    counts = {}
    for r in recs:
        counts[r['group']] = counts.get(r['group'], 0) + 1
    OUT.write_text(json.dumps(recs, indent=1) + '\n')
    print('%d vectors, ALL DECODE-VERIFY, ALL WRITE-DISCIPLINE, '
          'ALL COMPOSE-OK' % len(recs))
    for g in sorted(counts):
        print('  %-9s %d' % (g, counts[g]))
    print('written: %s' % OUT)
    return 0


if __name__ == '__main__':
    sys.exit(main())
