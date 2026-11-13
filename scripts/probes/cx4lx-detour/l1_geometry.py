#!/usr/bin/env python3
"""cx4lx-detour L1: boot-detour geometry of CX-4 Lx 14.32 MAIN_CODE.

Probes (spec 2026-10-11-cx4lx-detour-design.md s4 L1):
  [P1] entry decode + injection point (call <main-init>), dead-code
       xref proof, encoded detour word (rel24 in signed24)
  [P2] cave scan: zero runs, xref/access/ptr silence, db0 membership
  [P3] CR result-channel slot: FW store-target scan (st.i / base-zero
       abs / csr.w / const-base dataflow) + unlock-reader analogs
  [P4] scratch registers: main-init prologue first-read/first-write
  [P5] summary block for L2 (dc/raw/words)
"""
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
BASE = WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
RAW = WT / 'build/cx4lx-detour-l0-main03-raw.bin'
DC = WT / 'build/cx4lx-detour-l0-main03-dc.bin'
LOG = WT / 'build/cx4lx-detour-l1-geometry.log'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
SEC_TYPE = 0x03
SEC_ADDR = 0x16d000
RUNTIME_BASE = 0x800000
ENTRY_DC = 0x7edc
SP_INIT = 0x5348
MAIN_INIT = 0x7ef0
INJ_DC = 0x7ee4
DEAD1_DC = 0x7ee8
DEAD2_DC = 0x7eec
DB0_LO, DB0_HI = 0x2d6900, 0x31b000
CR_UNLOCK_WORD = 0x8fc
CR_SPARE1_WORD = 0x8fe
CR_SPARE2_WORD = 0x8fb
GT_MAP = [(0x341154, 0x1b88c8, 0x00050001), (0x341158, 0x1b88cc, 0xa00a0002),
          (0x34115c, 0x1b88d0, 0x20850001), (0x341168, 0x1b88dc, 0x00050001)]


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i*68:i*68+64]
    return bytes(out)


def s16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


def s24(v):
    v &= 0xffffff
    return v - 0x1000000 if v & 0x800000 else v


def storeoff(w, scale):
    hi = (w >> 16) & 0x1f
    if scale == 0:
        lo = w & 0x7ff
    elif scale == 1:
        lo = ((w >> 1) & 0x3ff) << 1
    else:
        lo = ((w >> 2) & 0x1ff) << 2
    return s16((hi << 11) | lo)


def cf_target(w, off):
    op = w >> 26
    if op == 0x25:
        o = s24(w)
    else:
        o = s16(w)
    return off + o * 4


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
    import mlxfwutil
    import irisc_dis
    import enc

    o = Out()
    buf = BASE.read_bytes()
    md5 = hashlib.md5(buf).hexdigest()
    if md5 != BASE_MD5:
        o('FATAL base md5 %s' % md5)
        sys.exit(1)
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', SEC_TYPE)
    code = DC.read_bytes()
    if code != decrc(RAW.read_bytes()) or code != decrc(img.section_data(e)):
        o('FATAL dc buffer != de-clcrc(raw/section)')
        sys.exit(1)
    n = len(code) // 4
    words = struct.unpack('>%dI' % n, code)
    o('[0] base md5 OK; MAIN_CODE addr=0x%x size=0x%x param0=0x%x param1=0x%x; dc=%d B (%d words); EOF dc=0x%x' % (
        e.addr, e.size, e.param0, e.param1, len(code), n, len(code)))
    if e.param1 - RUNTIME_BASE != ENTRY_DC:
        o('FATAL entry dc 0x%x != 0x%x' % (e.param1 - RUNTIME_BASE, ENTRY_DC))
        sys.exit(1)

    def dw(off):
        return irisc_dis.dis(words[off // 4], off)

    def dis_range(lo, hi):
        for off in range(lo, hi, 4):
            o('  %08x  %08x  %s' % (off, words[off // 4], dw(off)))

    def xref_map():
        m = {}
        for i, w in enumerate(words):
            op = w >> 26
            if op in (0x25, 0x28, 0x29, 0x2a, 0x2b):
                t = cf_target(w, i * 4)
                m.setdefault(t, []).append(i * 4)
        return m

    xrefs = xref_map()

    o('')
    o('[M] raw<->dc mapping self-check (journal task-03 9.3 ground truth):')
    map_ok = True
    for raw_off, dc_off, wref in GT_MAP:
        line, within = dc_off // 64, dc_off % 64
        calc = SEC_ADDR + line * 68 + within
        fw = struct.unpack_from('>I', buf, raw_off)[0]
        dww = words[dc_off // 4]
        ok = calc == raw_off and fw == dww == wref
        map_ok &= ok
        o('  dc %#x -> raw %#x calc %#x img %08x dc %08x ref %08x %s' % (
            dc_off, raw_off, calc, fw, dww, wref, 'OK' if ok else 'FAIL'))
    if not map_ok:
        sys.exit(1)

    def file_word(dc_off):
        line, within = dc_off // 64, dc_off % 64
        return struct.unpack_from('>I', buf, SEC_ADDR + line * 68 + within)[0]

    o('')
    o('[P1] entry decode 0x%#x..0x%#x:' % (ENTRY_DC - 4, MAIN_INIT))
    dis_range(ENTRY_DC - 4, MAIN_INIT + 0x10)
    pat_ok = (words[ENTRY_DC // 4] == 0x94fff51b and dw(ENTRY_DC) == 'call 0x%x' % SP_INIT
              and dw(ENTRY_DC + 4).startswith('st.d!') and words[(ENTRY_DC + 8) // 4] == 0x94000003
              and dw(ENTRY_DC + 8) == 'call 0x%x' % MAIN_INIT
              and words[DEAD1_DC // 4] == 0x95000000 and words[DEAD2_DC // 4] == 0x95000000
              and dw(DEAD1_DC) == 'jump 0x%x' % DEAD1_DC and dw(DEAD2_DC) == 'jump 0x%x' % DEAD2_DC)
    o('  pattern call sp_init; st.d!; call main-init; self-jump x2: %s' % ('PASS' if pat_ok else 'FAIL'))
    o('  sp_init decode:')
    dis_range(SP_INIT, SP_INIT + 0x18)
    for d in (DEAD1_DC, DEAD2_DC):
        o('  xrefs to dead self-jump 0x%x: %d (self only: %s)' % (
            d, len(xrefs.get(d, [])), 'yes' if xrefs.get(d, []) == [d] else 'NO'))
    inj_xref = [t for t in xrefs.get(INJ_DC, []) if t != INJ_DC]
    o('  xrefs to injection word 0x%x: %d external' % (INJ_DC, len(inj_xref)))
    o('  main-init 0x%x xrefs (call sites): %d' % (MAIN_INIT, len(xrefs.get(MAIN_INIT, []))))

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

    def classify_ctx(lo, ln):
        hi = lo + ln * 4
        ctx_lo = max(0, lo - 32)
        ctx_hi = min(len(code), hi + 32)
        ptrs = z = asc = mag = 0
        for off in range(ctx_lo, ctx_hi, 4):
            w = words[off // 4]
            if w == 0:
                z += 1
            elif RUNTIME_BASE <= w < RUNTIME_BASE + len(code):
                ptrs += 1
            if w in (0x4d544657, 0x5746544d, 0xdead9270, 0x7092adde, 0x4154beef, 0xefbe5441):
                mag += 1
            b = code[off:off + 4]
            if all(0x20 <= x < 0x7f or x == 0 for x in b):
                asc += 1
        m = (ctx_hi - ctx_lo) // 4
        invals = sum(1 for off in range(ctx_lo, ctx_hi, 4)
                     if words[off // 4] in (0, 1) and not (lo <= off < hi))
        tags = []
        if hi >= len(code):
            tags.append('EOF-pad')
        if ptrs / m >= 0.25:
            tags.append('ptr-table-zone')
        if mag:
            tags.append('magic-header-near')
        if invals >= 6:
            tags.append('01-array-zone')
        if asc / m >= 0.5:
            tags.append('string-zone')
        return '/'.join(tags or ['plain'])

    def access_scan(lo, hi):
        hits = []
        for i, w in enumerate(words):
            off = i * 4
            op = w >> 26
            if op == 0x12 and (w >> 25) & 1:
                a = (w & 0xffff) * 4
                if lo <= a < hi:
                    hits.append((off, 'ld.i ->0x%x' % a))
            if op == 0x13 and ((w >> 16) & 0x1f) == 0x1b:
                a = (w & 0x7ff) * 4
                if lo <= a < hi:
                    hits.append((off, 'st.i ->0x%x' % a))
            if op in (0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1e) and ((w >> 21) & 0x1f) == 0:
                if op == 0x17:
                    a = s16(((w >> 2) & 0x3fff) << 2)
                elif op == 0x18:
                    a = s16(w)
                elif op == 0x19:
                    if w & 1:
                        a = s16((w >> 1) & 0x7fff) << 1
                    else:
                        a = s16(((w >> 2) & 0x3fff) << 2)
                elif op == 0x1a:
                    a = storeoff(w, 0)
                else:
                    a = storeoff(w, 1 if (w & 1) else 2)
                if lo <= a < hi + 8:
                    hits.append((off, 'base-zero mem op 0x%02x ->0x%x' % (op, a)))
        return hits

    def ptr_scan(lo, hi):
        hits = []
        for i, w in enumerate(words):
            if RUNTIME_BASE + lo <= w < RUNTIME_BASE + hi:
                hits.append((i * 4, w - RUNTIME_BASE))
        return hits

    o('')
    o('[P2] cave scan: %d zero runs total; runs >=6 words:' % len(zero_runs))
    cands = [(off, ln) for off, ln in zero_runs if ln >= 6]
    cands.sort(key=lambda t: -t[1])
    cave_pick = None
    cave_alt = []
    for off, ln in cands:
        hi = off + ln * 4
        xr = [t for t, srcs in ((x, xrefs[x]) for x in range(off, hi, 4) if x in xrefs)]
        acc = access_scan(off, hi)
        ptr = ptr_scan(off, hi)
        db0 = DB0_LO <= off and hi <= DB0_HI
        tag = classify_ctx(off, ln)
        ok = not xr and not acc and not ptr
        o('  %#08x+%2dw (%#05x B) db0=%-5s %-28s xref=%d acc=%d ptr=%d %s' % (
            off, ln, ln * 4, db0, tag, len(xr), len(acc), len(ptr), 'CLEAN' if ok else 'REJECT'))
        if ok:
            if cave_pick is None and ln >= 12:
                cave_pick = (off, ln, tag)
            elif ok and ln >= 8:
                cave_alt.append((off, ln, tag, db0))
    if cave_pick is None and cands:
        off, ln = cands[0]
        cave_pick = (off, ln, classify_ctx(off, ln))
    o('  CAVE PICK: %#x (%d w, %s) ; alts: %s' % (
        cave_pick[0], cave_pick[1], cave_pick[2],
        ', '.join('%#x(%dw,db0=%s)' % (a, l, d) for a, l, t, d in cave_alt[:4])))
    cave_dc = cave_pick[0]
    o('  cave boundary dump:')
    dis_range(max(0, cave_dc - 0x10), cave_dc)
    o('  ... (zeros) ... EOF=0x%x' % len(code))

    rel24 = (cave_dc - INJ_DC) // 4
    new_word = enc.call(INJ_DC, cave_dc)
    o('  injection: dc 0x%x orig %08x -> %08x (call 0x%x; rel24=%#x signed24=%s; decode "%s")' % (
        INJ_DC, words[INJ_DC // 4], new_word, cave_dc, rel24,
        'OK' if -0x800000 <= rel24 <= 0x7fffff else 'OUT', irisc_dis.dis(new_word, INJ_DC)))

    st_i = {}
    abszero = {}
    csrw = {}
    constbase = {}
    sethist = {}
    for i, w in enumerate(words):
        off = i * 4
        op = w >> 26
        rd = (w >> 16) & 0x1f
        rs = (w >> 21) & 0x1f
        rt = (w >> 11) & 0x1f
        if op in (0x06, 0x07, 0x08, 0x09):
            sethist[(i, rd)] = None
        if op == 0x13 and ((w >> 16) & 0x1f) == 0x1b:
            st_i[(w & 0x7ff) * 4] = st_i.get((w & 0x7ff) * 4, 0) + 1
        elif op == 0x13:
            a = 0x40000 + 4 * (w & 0x7ff)
            csrw[a] = csrw.get(a, 0) + 1
        if op in (0x1a, 0x1b, 0x1c, 0x1e) and rs == 0:
            scale = 1 if (op in (0x1b, 0x1c) and (w & 1)) else (0 if op == 0x1a else 2)
            a = storeoff(w, scale) if op != 0x1a else s16(w)
            if a is not None:
                abszero[a] = abszero.get(a, 0) + 1
        if op in (0x1a, 0x1b, 0x1c, 0x1e) and rs != 0:
            for j in range(max(0, i - 8), i):
                wj = words[j]
                opj = wj >> 26
                if opj in (0x06, 0x07, 0x08, 0x09):
                    lo16 = wj & 0xffff
                    for k in range(max(0, j - 4), j):
                        wk = words[k]
                        opk = wk >> 26
                        if opk in (0x06, 0x07, 0x08, 0x09) and ((wk >> 16) & 0x1f) == ((wj >> 16) & 0x1f):
                            hi16 = wk & 0xffff
                            base = (hi16 << 16) | lo16
                            scale = 1 if (op in (0x1b, 0x1c) and (w & 1)) else (0 if op == 0x1a else 2)
                            a = base + (storeoff(w, scale) if op != 0x1a else s16(w))
                            if a < 0x40000:
                                constbase[a] = constbase.get(a, 0) + 1

    o('')
    o('[P3] FW store targets in CR/RAM space (<0x40000):')
    o('  st.i: %d sites, %d distinct, max target 0x%x' % (
        sum(st_i.values()), len(st_i), max(st_i) if st_i else -1))
    o('  base-zero abs stores (EA<0x40000): %d distinct; EA>=0x2000: %s' % (
        len(abszero), ' '.join('%#x(x%d)' % kv for kv in sorted(kv for kv in abszero.items() if 0x2000 <= kv[0] < 0x40000)) or '(none)'))
    o('  csr.w regspace: %d distinct; imm11 max target 0x%x (regspace cap 0x41ffc)' % (
        len(csrw), 0x40000 + 4 * 0x7ff))
    o('  const-base stores (set2/set3 window heuristic, EA<0x40000): %d hits (upper bound)' % (
        sum(constbase.values())))
    for slot, name in ((CR_UNLOCK_WORD * 4, '0x23f0 unlock (word 0x8fc)'),
                       (CR_SPARE1_WORD * 4, '0x23f8 spare1 (word 0x8fe)'),
                       (CR_SPARE2_WORD * 4, '0x23ec spare2 (word 0x8fb)'),
                       (0x23f4, '0x23f4 neighbor (word 0x8fd)'),
                       (0x23fc, '0x23fc neighbor (word 0x8ff)'),
                       (0x2000, '0x2000 rejected (word 0x800)'),
                       (0x2004, '0x2004 rejected (word 0x801)')):
        o('  FW writes to %s: st.i=%d abs0=%d const=%d csr=%d' % (
            name, st_i.get(slot, 0), abszero.get(slot, 0), constbase.get(slot, 0),
            csrw.get(0x40000 + slot, 0)))
    ldi = {}
    for i, w in enumerate(words):
        if (w >> 26) == 0x12 and (w >> 25) & 1:
            ldi.setdefault(w & 0xffff, []).append(i * 4)
    o('  ld.i readers by word: 0x8fc=%d 0x8fd=%d 0x8fe=%d 0x8ff=%d 0x8fb=%d 0x800=%d 0x801=%d' % (
        len(ldi.get(0x8fc, [])), len(ldi.get(0x8fd, [])), len(ldi.get(0x8fe, [])),
        len(ldi.get(0x8ff, [])), len(ldi.get(0x8fb, [])), len(ldi.get(0x800, [])),
        len(ldi.get(0x801, []))))
    o('  unlock reader 0xd4c8c..0xd4ca8 (word 0x8fc, unique ld.i site 0x%x):' % ldi[CR_UNLOCK_WORD][0])
    dis_range(0xd4c8c, 0xd4cac)
    unl_callers = [i * 4 for i, w in enumerate(words)
                   if (w >> 26) == 0x25 and not ((w >> 24) & 1)
                   and i * 4 + s24(w) * 4 == 0xd4c8c]
    o('  unlock reader call sites: %d (first: %s) - all runtime code, i.e. after boot entry' % (
        len(unl_callers), ' '.join('%#x' % c for c in unl_callers[:6])))
    o('  spare2 rejection evidence - 0x23fc single reader (behavioral):')
    dis_range(0xd4d7c, 0xd4d90)

    o('')
    o('[P4] main-init prologue 0x%x..0x%x:' % (MAIN_INIT, MAIN_INIT + 0x70))
    dis_range(MAIN_INIT, MAIN_INIT + 0x70)
    first = {}

    def touch(r, mode):
        if r and mode == 'r':
            first.setdefault(r, 'r')
        elif r:
            first.setdefault(r, 'w')

    for off in range(MAIN_INIT, MAIN_INIT + 0x70, 4):
        w = words[off // 4]
        op = w >> 26
        rd, rs, rt = (w >> 16) & 0x1f, (w >> 21) & 0x1f, (w >> 11) & 0x1f
        if op in (0x1a, 0x1b, 0x1c, 0x1e):
            touch(rs, 'r')
            touch(rt, 'r')
        elif op == 0x13 and ((w >> 16) & 0x1f) == 0x1b:
            touch(rs, 'r')
        elif op == 0x13:
            touch(rs, 'r')
            touch(rt, 'r')
        elif op in (0x17, 0x18, 0x19):
            touch(rd, 'w')
            touch(rs, 'r')
        elif op == 0x12 and (w >> 25) & 1:
            touch(rd, 'w')
        elif op == 0x12:
            touch(rd, 'w')
        elif op in (0x28, 0x29, 0x2a, 0x2b):
            touch(rs, 'r')
        elif op == 0x25:
            pass
        elif op == 0x3f:
            f = w & 0x1ff
            if f == 0x25:
                touch(rs, 'r')
            elif f in (0x81, 0x83, 0x8a, 0x8b):
                touch(rd, 'w')
                touch(rs, 'r')
            else:
                touch(rd, 'w')
                touch(rs, 'r')
                touch(rt, 'r')
        else:
            touch(rd, 'w')
            touch(rs, 'r')
    o('  first-use map (r= read before write = live-in, w= written first = dead-in): %s' % ' '.join(
        'r%d=%s' % kv for kv in sorted(first.items())))
    for r in (1, 3, 4, 5, 6, 23):
        v = first.get(r, 'w')
        o('  r%d: %s' % (r, {'r': 'READ before write (live-in - preserve)',
                             'w': 'WRITTEN before read (dead-in)'}[v]))
    sp_init_touch = set()
    for off in range(SP_INIT, SP_INIT + 0x18, 4):
        w = words[off // 4]
        sp_init_touch.add('%d' % ((w >> 16) & 0x1f))
    o('  sp_init returns (ret.d @0x%x); writes r1; touches r4,r5 as temps' % (SP_INIT + 0x1c))

    o('')
    o('[P5] SUMMARY FOR L2')
    line = INJ_DC // 64
    within = INJ_DC % 64
    raw_off = SEC_ADDR + line * 68 + within
    o('  injection: dc 0x%x raw(file) 0x%x orig %08x -> new %08x (call cave)' % (
        INJ_DC, raw_off, words[INJ_DC // 4], new_word))
    o('  mapping check: img word @0x%x = %08x == dc word %08x %s' % (
        raw_off, file_word(INJ_DC), words[INJ_DC // 4],
        'OK' if file_word(INJ_DC) == words[INJ_DC // 4] else 'FAIL'))
    cline = cave_dc // 64
    cwith = cave_dc % 64
    craw = SEC_ADDR + cline * 68 + cwith
    o('  cave: dc %#x..%#x (%d w) raw(file) %#x..%#x ctx=%s db0=%s' % (
        cave_dc, cave_dc + cave_pick[1] * 4, cave_pick[1], craw,
        craw + cave_pick[1] * 4, cave_pick[2], DB0_LO <= cave_dc < DB0_HI))
    o('  mapping check: img word @cave start = %08x == dc %08x %s' % (
        file_word(cave_dc), words[cave_dc // 4],
        'OK' if file_word(cave_dc) == words[cave_dc // 4] else 'FAIL'))
    o('  slot: primary CR 0x23f0 (word 0x8fc, unlock-reader equiv); spare1 CR 0x23f8 (word 0x8fe, inert); spare2 CR 0x23ec (word 0x8fb, inert)')
    o('  scratch: r5 r6 (write-first in main-init on both paths; r5 also clobbered by sp_init)')
    mk = 0xbadc0001
    sc = [enc.set2(5, 0x0000), enc.set3(5, 5, CR_UNLOCK_WORD * 4), enc.set2(6, 0xbadc),
          enc.set3(6, 6, 0x0001), enc.st_d(6, 5, 0), enc.jump(cave_dc + 0x14, MAIN_INIT)]
    o('  shellcode draft @cave (6 w):')
    for k, w in enumerate(sc):
        o('    %#x  %08x  %s' % (cave_dc + k * 4, w, irisc_dis.dis(w, cave_dc + k * 4)))
    o('DONE')
    LOG.write_text('\n'.join(o.lines) + '\n')


if __name__ == '__main__':
    main()
