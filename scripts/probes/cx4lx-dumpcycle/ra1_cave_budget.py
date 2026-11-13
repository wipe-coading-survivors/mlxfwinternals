#!/usr/bin/env python3
"""cx4lx-dumpcycle R-A1: cave budget for the phase IX dump-cycle stubs (offline).

Task R-A1 of spec 2026-10-16-cx4lx-dumpcycle-design.md (C-RA1):
  [G1] link-reg r17 liveness in the 0xd3804 tail (D1 gate method, re-run on stock)
  [G2] channel-C marker string rt 0x00aeb83b: content, %x count, deadness
  [G3] stock witnesses: cmp op0x36/0x38 funct5=2 + branch cc adjacency;
       base-zero st.d stores with EA>=0x2000; zero-source stores; emit5/CORE
       writes to r4 (emit5x2 reload question)
  [G4] iteration-1 stub sketches (channel C emit7, C+self-consume, channel B
       set-pair and base-zero, emit5x2 fallback) + iteration-2 generic-exec
       copy-loop stub: assembled with irisc_asm (cx4lx profile, every word
       decode-verified), strict-mode blockers listed, word budget vs 24
  [G5] second cave / split-site scan (l1_geometry method, runs >=8 w,
       xref/access/ptr must be clean), region tags (code/db0/tail)
  [G6] iteration-2 payload-buffer arithmetic (fragment capacity, bridges)

All addresses are dc offsets in MAIN_CODE of stock GCA 14.32.1900
(rt = dc + 0x800000). Log: build/cx4lx-dumpcycle-ra1.log.
"""
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
BASE = WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
DCBUF = WT / 'build/cx4lx-detour-l0-main03-dc.bin'
LOG = WT / 'build/cx4lx-dumpcycle-ra1.log'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
SEC_ADDR = 0x16d000
SEC_SIZE = 0x34e8c0
RT = 0x800000
CODE_END = 0x2d6900
DB0_LO, DB0_HI = 0x2d6900, 0x31b300

CAVE_DC = 0x31cba0
CAVE_END = 0x31cc00
CAVE_WORDS = 24
HOOK_DC = 0xd3850
FN_START_DC = 0xd3804
STOCK_EMIT2 = 0x6064
EMIT5 = 0x6348
EMIT7 = 0x63bc
CORE = 0x6124

WIN_MAGIC_W = 0x805     # RAM 0x2014, inline-data zone (0x805..0x8c4)
WIN_ADDR_W = 0x806      # RAM 0x2018
WIN_COUNT_W = 0x807     # RAM 0x201c
WIN_PAY_W = 0x808       # RAM 0x2020, first payload word (iteration 2)
RESERVE = 0x2314        # channel-B result base (word 0x8c5)
MAGIC = 0x444d5031      # placeholder constant 'DMP1' (final value = R-A3 choice)
STR_RT = 0x00aeb83b     # candidate marker string (7x%x expected)
FRAG1_DC = 0x31cab8     # near-cave zero fragment (L1: 9 w clean)
FRAG2_DC = 0x31cb70     # near-cave zero fragment (L1: 10 w clean)


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def s24(v):
    v &= 0xffffff
    return v - 0x1000000 if v & 0x800000 else v


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


def main():
    sys.path.insert(0, str(WT))
    sys.path.insert(0, str(WT / 'scripts/irisc'))
    import hashlib
    import re
    import mlxfwutil
    import irisc_dis
    from scripts.irisc import assemble, AsmError
    from scripts.irisc.profiles import load_profile

    o = Out()

    def fail(msg):
        o('FATAL: ' + msg)
        LOG.write_text('\n'.join(o.lines) + '\n')
        sys.exit(1)
        raise AssertionError('unreachable')

    buf = BASE.read_bytes()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail('base md5 mismatch')
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', 0x03)
    if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
        fail('MAIN_CODE geometry mismatch')
    code = DCBUF.read_bytes() if DCBUF.is_file() else decrc(img.section_data(e))
    if code != decrc(img.section_data(e)):
        fail('dc buffer != de-clcrc(section)')
    n = len(code) // 4
    words = struct.unpack('>%dI' % n, code)
    o('[0] base md5 OK; MAIN_CODE %d words, EOF dc 0x%x; cave 0x%x..0x%x (%d w)'
      % (n, len(code), CAVE_DC, CAVE_END, CAVE_WORDS))
    if not all(w == 0 for w in words[CAVE_DC // 4:CAVE_END // 4]):
        fail('cave not all-zero on stock base')

    def dw(off):
        return words[off // 4]

    def dis(off):
        return irisc_dis.dis(dw(off), off)

    # [G1] r17 liveness in the hooked-function tail (D1 gate [5] method)
    fn_end = None
    hits = []
    for off in range(HOOK_DC + 4, FN_START_DC + 0x400, 4):
        d = dis(off)
        if d.startswith('ret.'):
            fn_end = off
            break
        if re.search(r'\br17\b', d):
            hits.append((off, d))
    if fn_end is None:
        fail('function end not found after hook site')
    o('[G1] r17 liveness in 0x%x tail (0x%x..ret 0x%x): %d mentions -> %s'
      % (FN_START_DC, HOOK_DC, fn_end, len(hits),
         'SAFE (dead at site, callee-saved)' if not hits else 'LIVE - unusable'))
    if hits:
        fail('r17 live in tail: %s' % hits[:4])

    # [G2] marker string
    str_dc = STR_RT - RT
    raw = code[str_dc:str_dc + 96]
    nul = raw.find(b'\x00')
    if nul < 0:
        fail('marker string not NUL-terminated within 96 B')
    text = raw[:nul].decode('latin1')
    o('[G2] string @rt 0x%08x (dc 0x%x): %r' % (STR_RT, str_dc, text))
    o('    %%x count = %d, len = %d B' % (text.count('%x'), nul))
    loaders = 0
    for i in range(n - 1):
        d0, d1 = dis(i * 4), dis((i + 1) * 4)
        if d0.startswith('addi r') and ',zero,' in d0 and d1.startswith('addi.hi r'):
            r0 = d0.split()[1].split(',')[0]
            if r0 == d1.split()[1].split(',')[0]:
                try:
                    lo = int(d0.split(',zero,')[1], 0) & 0xffff
                    hi = int(d1.split(',')[2], 0) & 0xffff
                except ValueError:
                    continue
                if ((s16(lo) + (hi << 16)) & 0xffffffff) == STR_RT:
                    loaders += 1
    raw_hits = sum(1 for w in words if w == STR_RT)
    o('    deadness: addi/addi.hi loaders = %d, raw words = %d -> %s'
      % (loaders, raw_hits, 'DEAD' if not (loaders or raw_hits) else 'LIVE - reject'))
    if loaders or raw_hits:
        fail('marker string rt 0x%x not dead' % STR_RT)

    # [G3] stock witnesses
    cmp_sites = {0x36: [], 0x38: []}
    cmp_exact = {0x36: [], 0x38: []}
    for i, w in enumerate(words):
        op = w >> 26
        if op in cmp_sites:
            lo11 = w & 0x7ff
            if lo11 & 0x1f == 2:
                cmp_sites[op].append(i * 4)
                if lo11 == 0x002 and ((w >> 21) & 0x1f) and ((w >> 11) & 0x1f):
                    cmp_exact[op].append(i * 4)
    o('[G3] cmp funct5=2 (eq32-selector) sites: op0x36=%d op0x38=%d;'
      ' EXACT reg-reg imm6=0 (lo11==0x002, rs!=0, rt!=0): op0x36=%d op0x38=%d'
      % (len(cmp_sites[0x36]), len(cmp_sites[0x38]),
         len(cmp_exact[0x36]), len(cmp_exact[0x38])))

    def br_cc_hist(sites, tag):
        hist = {}
        for s in sites:
            for k in (1, 2, 3):
                if s + 4 * k + 4 > len(code):
                    break
                w2 = dw(s + 4 * k)
                if (w2 >> 26) in (0x28, 0x29):
                    cc = (w2 >> 16) & 0x1f
                    key = ('b.t' if (w2 >> 26) == 0x28 else 'b.f', cc)
                    hist[key] = hist.get(key, 0) + 1
                    break
        o('    %s cmp->branch(+1..3 w) cc histogram: %s'
          % (tag, ' '.join('%s/cc0x%x=%d' % (k[0], k[1], v)
                           for k, v in sorted(hist.items())) or '(none)'))
        return hist

    br_cc_hist(cmp_sites[0x36], 'op0x36 f5=2 all')
    h36 = br_cc_hist(cmp_exact[0x36], 'op0x36 EXACT')
    h38 = br_cc_hist(cmp_sites[0x38], 'op0x38 f5=2 all')
    for op, sites in ((0x36, cmp_exact[0x36]), (0x38, cmp_sites[0x38])):
        for s in sites[:2]:
            o('    sample op%02x @0x%x: %s ; +4: %s'
              % (op, s, dis(s), dis(s + 4)))

    st_d_bz = []
    st_d_bz_hi = []
    for i, w in enumerate(words):
        if (w >> 26) == 0x1b and ((w >> 21) & 0x1f) == 0:
            lo = ((w >> 2) & 0x1ff) << 2
            ea = (((w >> 16) & 0x1f) << 11) | lo
            st_d_bz.append((i * 4, ea))
            if ea >= 0x2000:
                st_d_bz_hi.append((i * 4, ea))
    o('    LITERAL base-zero st.d (op0x1b rs=0) stock sites: %d total,'
      ' EA>=0x2000: %d %s' % (len(st_d_bz), len(st_d_bz_hi),
                              ['@0x%x->0x%x' % x for x in st_d_bz_hi[:4]]))
    st_d_zsrc = sum(1 for w in words
                    if (w >> 26) == 0x1b and ((w >> 11) & 0x1f) == 0
                    and ((w >> 21) & 0x1f) != 0)
    o('    plain st.d with rt=r0 (zero source, base!=0): %d' % st_d_zsrc)

    wr_ops = ('addi', 'addi.hi', 'set2', 'set3', 'or', 'subs', 'subsi', 'ands',
              'and', 'shr', 'shl', 'ld.i', 'ld.d', 'ld.w', 'lw.r', 'mask32',
              'alu', 'op', 'add')
    r4w = []
    for off in list(range(CORE, CORE + 0x60, 4)) + list(range(EMIT5, EMIT5 + 0x38, 4)):
        d = dis(off)
        if d.startswith('ret'):
            continue
        toks = re.findall(r'\br\d+\b|\bzero\b', d)
        if toks and toks[0] == 'r4' and d.split()[0] in wr_ops:
            r4w.append((off, d))
    o('    CORE 0x%x + emit5 0x%x: writes to r4: %d -> %s'
      % (CORE, EMIT5, len(r4w),
         'r4 preserved statically' if not r4w else 'r4 CLOBBERED: %s' % r4w[:3]))

    # [G4] stub sketches
    prof = load_profile('cx4lx')
    m_hi, m_lo = (MAGIC >> 16) & 0xffff, MAGIC & 0xffff
    s_lo = STR_RT & 0xffff
    s_hi = ((STR_RT >> 16) & 0xffff) + (1 if s_lo & 0x8000 else 0)

    def filt():
        return ('ld.i r6,0x%x\n'
                'set2 r7,zero,0x%x\n'
                'set3 r7,r7,0x%x\n'
                'cmp38_eq32 r7,r6\n'
                'b.f.0xa zero,out\n' % (WIN_MAGIC_W, m_hi, m_lo))

    def filt36():
        return ('ld.i r6,0x%x\n'
                'set2 r7,zero,0x%x\n'
                'set3 r7,r7,0x%x\n'
                'cmp36_eq32 r7,r6\n'
                'b.f.0xa zero,out\n' % (WIN_MAGIC_W, m_hi, m_lo))

    def head2():
        return 'csr.r r17,csr0xbc\ncall 0x%x\n' % STOCK_EMIT2

    tail = 'lbl out\ncsr.w r17,zero,0xbc\nret.d zero,zero,zero\n'
    strload = 'addi r4,zero,0x%x\naddi.hi r4,r4,0x%x\n' % (s_lo, s_hi)
    reads6 = ('ld.i r3,0x%x\n' % WIN_ADDR_W
              + ''.join('ld.d r%d,r3,0x%x\n' % (r, k) for r, k in
                        ((5, 0), (6, 4), (7, 8), (8, 0xc), (9, 0x10), (10, 0x14))))
    reads5_skip6 = ('ld.i r3,0x%x\n' % WIN_ADDR_W
                    + ''.join('ld.d r%d,r3,0x%x\n' % (r, k) for r, k in
                              ((5, 0), (7, 4), (8, 8), (9, 0xc), (10, 0x10), (11, 0x14))))

    variants = {}
    variants['C emit7 (no echo)'] = (
        head2() + filt() + reads6 + strload + 'call 0x%x\n' % EMIT7 + tail)
    variants['C emit7 + addr echo (canonical)'] = (
        head2() + filt() + reads6 + strload + 'or r11,r3,r3\n'
        + 'call 0x%x\n' % EMIT7 + tail)
    variants['C emit7 + echo + self-consume (st.d zero,zero)'] = (
        head2() + filt() + 'st.d zero,zero,0x%x\n' % (WIN_MAGIC_W * 4)
        + reads6 + strload + 'or r11,r3,r3\n' + 'call 0x%x\n' % EMIT7 + tail)
    variants['C emit7 + echo + self-consume (set-pair base)'] = (
        head2() + filt()
        + 'set2 r12,zero,0x0\nset3 r12,r12,0x%x\nst.d zero,r12,0x0\n' % (WIN_MAGIC_W * 4)
        + reads6 + strload + 'or r11,r3,r3\n' + 'call 0x%x\n' % EMIT7 + tail)
    variants['B set-pair base (B2 live form)'] = (
        head2() + filt() + reads5_skip6
        + 'set2 r4,zero,0x0\nset3 r4,r4,0x%x\n' % RESERVE
        + 'st.d r6,r4,0x0\n'
        + ''.join('st.d r%d,r4,0x%x\n' % (r, k) for r, k in
                  ((5, 4), (7, 8), (8, 0xc), (9, 0x10), (10, 0x14), (11, 0x18)))
        + tail)
    b_full = ('csr.r r17,csr0xbc\ncall 0x%x\n' % STOCK_EMIT2 + filt() + reads5_skip6
              + 'set2 r4,zero,0x0\nset3 r4,r4,0x%x\n' % RESERVE
              + 'st.d r6,r4,0x0\n'
              + ''.join('st.d r%d,r4,0x%x\n' % (r, k) for r, k in
                        ((5, 4), (7, 8), (8, 0xc), (9, 0x10), (10, 0x14), (11, 0x18))))
    b_lines = [l for l in b_full.split('\n') if l.strip()]
    variants['B base-zero abs stores'] = (
        head2() + filt() + reads5_skip6
        + 'st.d r6,zero,0x%x\n' % RESERVE
        + ''.join('st.d r%d,zero,0x%x\n' % (r, RESERVE + k) for r, k in
                  ((5, 4), (7, 8), (8, 0xc), (9, 0x10), (10, 0x14), (11, 0x18)))
        + tail)
    variants['C emit5 x2 (conservative reloads)'] = (
        head2() + filt() + reads6[:len('ld.i r3,0x%x\n' % WIN_ADDR_W)]
        + strload
        + ''.join('ld.d r%d,r3,0x%x\n' % (r, k) for r, k in
                  ((5, 0), (6, 4), (7, 8), (8, 0xc), (9, 0x10)))
        + 'call 0x%x\n' % EMIT5
        + 'ld.i r3,0x%x\nld.d r5,r3,0x14\n' % WIN_ADDR_W
        + strload + 'call 0x%x\n' % EMIT5 + tail)
    if not r4w:
        variants['C emit5 x2 (r4 static-preserved)'] = (
            head2() + filt() + 'ld.i r3,0x%x\n' % WIN_ADDR_W + strload
            + ''.join('ld.d r%d,r3,0x%x\n' % (r, k) for r, k in
                      ((5, 0), (6, 4), (7, 8), (8, 0xc), (9, 0x10)))
            + 'call 0x%x\n' % EMIT5
            + 'ld.i r3,0x%x\nld.d r5,r3,0x14\n' % WIN_ADDR_W
            + 'call 0x%x\n' % EMIT5 + tail)
    dst_rt = RT + FRAG2_DC
    variants['C emit7 + addr echo (op36 filter, on-target witnessed)'] = (
        head2() + filt36() + reads6 + strload + 'or r11,r3,r3\n'
        + 'call 0x%x\n' % EMIT7 + tail)
    variants['I2 generic-exec copy-loop'] = (
        head2() + filt()
        + 'ld.i r5,0x%x\n' % WIN_COUNT_W
        + 'set2 r3,zero,0x0\nset3 r3,r3,0x%x\n' % (WIN_PAY_W * 4)
        + 'set2 r4,zero,0x%x\nset3 r4,r4,0x%x\n' % (dst_rt >> 16, dst_rt & 0xffff)
        + 'lbl loop\n'
        + 'subsi r5,r5,0x1\n'
        + 'b.t.0x0 zero,done\n'
        + 'ld.d r6,r3,0x0\n'
        + 'st.d r6,r4,0x0\n'
        + 'addi r3,r3,0x4\n'
        + 'addi r4,r4,0x4\n'
        + 'jump loop\n'
        + 'lbl done\n'
        + 'jump 0x%x\n' % FRAG2_DC
        + tail)

    o('')
    o('[G4] stub sketches @cave 0x%x (profile cx4lx, decode-verify per word):' % CAVE_DC)
    results = {}
    for name, text in variants.items():
        nwords = len([l for l in text.split('\n')
                      if l.strip() and not l.strip().startswith('lbl')])
        try:
            data = assemble(text, base=CAVE_DC, profile=prof, allow_assumed=True)
        except AsmError as ex:
            o('  %-42s ASM FAIL: %s' % (name, ex))
            results[name] = None
            continue
        got = len(data) // 4
        assert got == nwords, '%s: %d != %d' % (name, got, nwords)
        results[name] = got
        o('  %-42s %2d/%d w  slack %+d  %s'
          % (name, got, CAVE_WORDS, CAVE_WORDS - got,
             'FIT' if got <= CAVE_WORDS else 'OVER'))

    o('')
    o('  B set-pair SPLIT layout (entry in frag2, bridge, tail in cave):')
    split_at = 9
    n2_body = len(b_lines) - split_at
    out_dc = CAVE_DC + 4 * n2_body
    p1_lines = [('b.f.0xa zero,0x%x' % out_dc if l.startswith('b.f') else l)
                for l in b_lines[:split_at]]
    p1 = '\n'.join(p1_lines) + '\njump 0x%x\n' % CAVE_DC
    p2 = '\n'.join(b_lines[split_at:]) + '\nlbl out\ncsr.w r17,zero,0xbc\nret.d zero,zero,zero\n'
    d1 = assemble(p1, base=FRAG2_DC, profile=prof, allow_assumed=True)
    d2 = assemble(p2, base=CAVE_DC, profile=prof, allow_assumed=True)
    n1, n2 = len(d1) // 4, len(d2) // 4
    o('    frag2 @0x%x: %d w (9 stub + 1 bridge jump 0x%x), b.f -> 0x%x;'
      ' cave @0x%x: %d w; total %d w vs capacity 10+24 = 34, slack %+d'
      % (FRAG2_DC, n1, CAVE_DC, out_dc, CAVE_DC, n2, n1 + n2, 34 - n1 - n2))
    for tag, base, data in (('frag2', FRAG2_DC, d1), ('cave', CAVE_DC, d2)):
        o('      --- %s part ---' % tag)
        for k in range(len(data) // 4):
            w = struct.unpack_from('>I', data, k * 4)[0]
            o('      0x%08x  %08x  %s' % (base + 4 * k, w, irisc_dis.dis(w, base + 4 * k)))

    o('')
    o('  word listings (canonical + key variants):')
    for name in ('C emit7 + addr echo (canonical)',
                 'C emit7 + echo + self-consume (st.d zero,zero)',
                 'B base-zero abs stores', 'I2 generic-exec copy-loop'):
        text = variants[name]
        data = assemble(text, base=CAVE_DC, profile=prof, allow_assumed=True)
        o('  --- %s (%d w)' % (name, len(data) // 4))
        for k in range(len(data) // 4):
            w = struct.unpack_from('>I', data, k * 4)[0]
            o('    0x%08x  %08x  %s' % (CAVE_DC + 4 * k, w, irisc_dis.dis(w, CAVE_DC + 4 * k)))

    def gate_name(mnem):
        m = re.fullmatch(r'b\.(t|f)\.0x[0-9a-fA-F]+', mnem)
        if m:
            return 'b.t' if m.group(1) == 't' else 'b.f'
        if re.fullmatch(r'alu\.0x[0-9a-fA-F]{1,3}', mnem):
            return 'alu'
        return mnem.split('#', 1)[0] if '#' in mnem else mnem

    all_blockers = {}
    for name, text in variants.items():
        blocked = set()
        for line in text.split('\n'):
            line = line.strip()
            if not line or line.startswith('lbl'):
                continue
            mnem = line.split()[0]
            if re.fullmatch(r'op0x[0-9a-fA-F]{2}', mnem):
                continue
            status = prof.form_status(gate_name(mnem))
            if status in ('assumed', 'unknown'):
                blocked.add('%s(%s)' % (mnem, status))
        all_blockers[name] = sorted(blocked)
    o('')
    o('  strict-gate assumed-status forms per variant (cx4lx profile):')
    for k, v in all_blockers.items():
        o('    %-42s %s' % (k, ', '.join(v) or '(none)'))

    raw_cmp = ('op0x38 zero,r7,r6 imm=0x0002')
    try:
        w = assemble(raw_cmp, base=CAVE_DC, profile=prof, strict=True)
        o('  strict-legal cmp form: %s -> %08x (%d w) OK'
          % (raw_cmp, struct.unpack('>I', w)[0], len(w) // 4))
    except AsmError as ex:
        o('  strict-legal cmp form FAILED: %s' % ex)

    # [G5] second cave / split scan
    def xref_map():
        m = {}
        for i, w in enumerate(words):
            op = w >> 26
            if op in (0x25, 0x28, 0x29, 0x2a, 0x2b):
                t = (i * 4 + (s24(w) if op == 0x25 else s16(w)) * 4) & 0xffffffff
                if t < len(code):
                    m.setdefault(t, []).append(i * 4)
        return m

    xrefs = xref_map()

    def access_scan(lo, hi):
        hits = []
        for i, w in enumerate(words):
            off = i * 4
            op = w >> 26
            if op == 0x12 and (w >> 25) & 1:
                a = (w & 0xffff) * 4
                if lo <= a < hi:
                    hits.append((off, 'ld.i'))
            if op == 0x13 and ((w >> 16) & 0x1f) == 0x1b:
                a = (w & 0x7ff) * 4
                if lo <= a < hi:
                    hits.append((off, 'st.i'))
            if op in (0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1e) and ((w >> 21) & 0x1f) == 0:
                if op == 0x17:
                    a = s16(((w >> 2) & 0x3fff) << 2)
                elif op == 0x18:
                    a = s16(w)
                elif op == 0x19:
                    a = s16((w >> 1) & 0x7fff) << 1 if w & 1 else s16(((w >> 2) & 0x3fff) << 2)
                elif op == 0x1a:
                    a = s16(w)
                else:
                    scale = 1 if (op in (0x1b, 0x1c) and (w & 1)) else 2
                    a = s16((((w >> 16) & 0x1f) << 11)
                            | (((((w >> (1 if scale == 1 else 2)) & (0x3ff if scale == 1 else 0x1ff))
                                << (1 if scale == 1 else 2)))))
                if lo <= a < hi + 8:
                    hits.append((off, 'base-zero'))
        return hits

    def ptr_scan(lo, hi):
        return [(i * 4, w - RT) for i, w in enumerate(words)
                if RT + lo <= w < RT + hi]

    zero_runs = []
    i = 0
    while i < n:
        if words[i] == 0:
            j = i
            while j < n and words[j] == 0:
                j += 1
            zero_runs.append((i * 4, j - i))
            i = j
        else:
            i += 1
    o('')
    o('[G5] second cave / split scan: %d zero runs; clean runs >=8 w:' % len(zero_runs))
    for off, ln in sorted(zero_runs, key=lambda t: (-t[1], t[0])):
        if ln < 8:
            break
        hi = off + ln * 4
        xr = [t for t in range(off, hi, 4) if t in xrefs]
        acc = access_scan(off, hi)
        ptr = ptr_scan(off, hi)
        region = ('code' if hi <= CODE_END else
                  'db0' if DB0_LO <= off and hi <= DB0_HI else
                  'EOF-pad' if off >= CAVE_DC else 'tail-tables')
        ok = not xr and not acc and not ptr
        o('  %#08x+%2dw  region=%-11s xref=%d acc=%d ptr=%d  %s'
          % (off, ln, region, len(xr), len(acc), len(ptr),
             'CLEAN' if ok else 'REJECT'))
    o('  (regions: code <0x%x; db0 strings/ro-data [0x%x,0x%x) per D2;'
      ' tail-tables = ptr/data tables; EOF-pad = last 0x%x B of section.'
      % (CODE_END, DB0_LO, DB0_HI, len(code) - CAVE_DC))
    o('   db1 (MTRC_CAP) = rt 0x00528270 size 0x3200, ROM-resident,'
      ' does NOT intersect MAIN_CODE; db0/tail-tables runs are data-block'
      ' holes - excluded as code-landing per brief (cave/EOF-pad and the'
      ' two adjacent clean fragments are the landing class)')

    # [G6] iteration-2 payload arithmetic
    frag2_len = 10
    frag1_len = 9
    cave_slack = CAVE_WORDS - results.get('I2 generic-exec copy-loop', 0)
    o('')
    o('[G6] iteration-2 layout: stub %d w @cave (slack %d); payload buffer:'
      % (results.get('I2 generic-exec copy-loop', 0), cave_slack))
    o('  copy loop needs ONE contiguous dst: max = frag2 0x%x+%dw'
      ' (copy dst rt 0x%x)' % (FRAG2_DC, frag2_len, RT + FRAG2_DC))
    o('  payload 16 w (brief assumption): does NOT fit - no contiguous zero'
      ' region >=16 w outside db0 (G5); options:')
    o('    a) cap payload at %d w (frag2, single loop, stub %d w in cave)'
      ' - RECOMMENDED start;' % (frag2_len, results.get('I2 generic-exec copy-loop', 0)))
    o('    b) 16-w payload -> two copy loops (2nd dst set-pair + 2nd loop'
      ' ~+8 w): stub ~30 w > cave 24 -> split stub frag2+cave (capacity 34),'
      ' feasible on paper, +1 clcrc line, plan-level decision;')
    o('    c) hypothetical 2nd cave >=18 w contiguous: none exists (G5).')
    lines = sorted({CAVE_DC // 64, (CAVE_END - 4) // 64, FRAG1_DC // 64,
                    (FRAG1_DC + frag1_len * 4 - 4) // 64, FRAG2_DC // 64,
                    (FRAG2_DC + frag2_len * 4 - 4) // 64})
    o('  clcrc lines touched by cave+fragments: %s (option a: %s only)'
      % (lines, sorted({FRAG2_DC // 64, CAVE_DC // 64, (CAVE_END - 4) // 64})))

    o('')
    o('DONE')
    LOG.write_text('\n'.join(o.lines) + '\n')


if __name__ == '__main__':
    main()
