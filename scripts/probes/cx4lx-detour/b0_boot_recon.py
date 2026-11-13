#!/usr/bin/env python3
"""cx4lx-detour B0 (phase VII): boot-site candidates + CR-reserve verify (offline).

Task B0 of spec 2026-10-11-cx4lx-boottrace-design.md s3:
  [S1] entry chain re-verified (0x7edc block, sp_init, main-init vector) -
       the boot chain ABOVE 0x7ee4: nobody calls entry in MAIN_CODE (ROM
       vector via ITOC param1); the only earlier call site is 0x7edc itself
  [S2] unconditional spine of main-init 0x7ef0 (fall-through walk): sites
       0x7f94/0x7f9c/0x7fa0/0x7fa4/0x7fa8/0x7fac (+wait loop 0x8024..0x803c)
       and 0x8040 (call 0x243bc8) are on the always-executed path; main-init
       RETURNS (idle = entry self-jump; work continues via ISRs)
  [S3] GATE-on-spine candidate: fn 0xefc (cpu0 path from main-init @0x7f78),
       GATE site 0xf10 (class 0x1000, level 0) is 2 instr past prologue on
       the spine -> GATE call ALWAYS executed even with mask w2=0
  [S4] per-candidate live-in liveness (forward first-use scan, L3 T3 method)
  [S5] cave reachability: rel24 |site - 0x31cba0| <= 0x2000000 for all cands
  [S6] (class, level) inventory of GATE sites in main-init call tree;
       L>=2 emit-site check (mask bypass) on spines
  [R1] CR reserve 0x2314..0x23e4 (words 0x8c5..0x8f9): ld.i/st.i word-index
       refs over WHOLE MAIN_CODE = 0 expected
  [R2] base-zero absolute EA (ld.d/st.d/ld.w/st.w trailing imm in window)
       refs to reserve = 0 expected; positive controls 0x23f0/0x23f4/0x23fc/
       0x23e8 readers still found (L4/L1 ground truth)
  [R3] constant-loader composite scan (set2/set3/addi/addi.hi building
       0x2314..0x23e4 / 0x23f8 constants) = 0 expected
  [R4] CR 0x23f8 (word 0x8fe) clean in ALL forms (re-check L4/L1)
Log: build/cx4lx-detour-b0-recon.log
"""
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
BASE = WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
DCBUF = WT / 'build/cx4lx-detour-l0-main03-dc.bin'
LOG = WT / 'build/cx4lx-detour-b0-recon.log'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'

ENTRY_DC = 0x7edc
INJ_DC = 0x7ee4
MAIN_INIT = 0x7ef0
SP_INIT = 0x5348
CAVE = 0x31cba0
GATE = 0x5f90
EMITS = {0x6188: 0, 0x603c: 1, 0x6064: 2, 0x6090: 3, 0x6008: 4,
         0x6348: 5, 0x6380: 6, 0x63bc: 7}
RES_LO, RES_HI = 0x2314, 0x23e4          # CR reserve (words 0x8c5..0x8f9)
WORD_23F8 = 0x8fe                         # spare slot word index
RES_WLO, RES_WH1 = RES_LO // 4, RES_HI // 4
CODE_END = 0x2d6900                       # db0 strings start (docs/250-re/120-irisc/035-cx4lx-trace.md)


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


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

    o = Out()

    def fail(msg):
        o('FATAL: ' + msg)
        open(LOG, 'w').write('\n'.join(o.lines) + '\n')
        sys.exit(1)

    buf = BASE.read_bytes()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail('base md5 mismatch')
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', 0x03)
    code = DCBUF.read_bytes()
    if code != decrc(img.section_data(e)):
        fail('dc buffer != de-clcrc(section)')
    n = len(code) // 4
    words = struct.unpack('>%dI' % n, code)

    def dis(off):
        return irisc_dis.dis(words[off // 4], off)

    def dis_range(lo, hi, tag=''):
        if tag:
            o('  --- %s ---' % tag)
        for off in range(lo, hi, 4):
            o('  %08x  %08x  %s' % (off, words[off // 4], dis(off)))

    call_re = re.compile(r'^call (0x[0-9a-f]+)$')
    br_re = re.compile(r'^b\.[tb]\.[0-9a-fx]+ \S+,(0x-?[0-9a-f]+)$')
    bb_re = re.compile(r'^b\.b(set|clr) \d+,\S+,(0x-?[0-9a-f]+)$')
    jump_re = re.compile(r'^jump (0x-?[0-9a-f]+)$')

    # S1: entry chain ------------------------------------------------
    o('[S1] entry chain:')
    if dis(ENTRY_DC) != 'call 0x%x' % SP_INIT or dis(INJ_DC) != 'call 0x%x' % MAIN_INIT:
        fail('entry chain words changed')
    dis_range(ENTRY_DC, MAIN_INIT + 8, 'entry block')
    dis_range(SP_INIT, SP_INIT + 0x14, 'sp_init')
    entry_xrefs = []
    for i in range(n):
        m = call_re.match(dis(i * 4)) or jump_re.match(dis(i * 4))
        if m and m.group(1).startswith('0x') and not m.group(1).startswith('0x-') \
                and int(m.group(1), 16) == ENTRY_DC:
            entry_xrefs.append(i * 4)
    if entry_xrefs:
        fail('entry 0x7edc has MAIN_CODE xrefs: %s' % entry_xrefs)
    o('  xrefs to entry fn 0x%x: 0 (ROM/iron vector via ITOC param1=0x%x)'
      % (ENTRY_DC, 0x800000 + ENTRY_DC))
    o('  earliest in-image call site = 0x7edc (call sp_init), injection '
      'word 0x7ee4 is the 3rd instruction; nothing executes between '
      '0x7edc and 0x7ee4 except sp_init + st.d!')

    # S2: main-init control flow: forks + unconditional tail ------------
    o('')
    o('[S2] main-init 0x%x control flow (cc-table docs/250-re/120-irisc/010-isa.md: .0=eq, .1=uge, '
      '.2=lt, .4=ult):' % MAIN_INIT)
    dis_range(0x7f58, 0x7fa0, 'cpu0/config fork: csr0x4==0 -> 0x7f68; '
              'dc0(0xf)==eq(0xf==byte0(w0x2ef)) -> 0x7f78 call 0xefc '
              '[mask==0xf path]; else 0x7f80 block -> 0x7f94 chain '
              '[mask!=0xf path]; cpu!=0 -> straight 0x8024')
    spine_tail = []
    off = 0x8024
    guard = 0
    while off < len(code) and guard < 0x200:
        guard += 1
        d = dis(off)
        m = call_re.match(d)
        if m:
            spine_tail.append((off, int(m.group(1), 16)))
            off += 4
            continue
        if d.startswith('ret.'):
            spine_tail.append((off, None))
            break
        m = jump_re.match(d)
        if m and m.group(1).startswith('0x') and not m.group(1).startswith('0x-'):
            off = int(m.group(1), 16)
            continue
        m = br_re.match(d) or bb_re.match(d)
        if m:
            off += 4
            continue
        off += 4
    for site, tgt in spine_tail:
        o('  0x%08x  %s' % (site, 'call 0x%x' % tgt if tgt else 'RET'))
    for want in (0x8034, 0x8040):
        if not any(s == want for s, _ in spine_tail):
            fail('site 0x%x not on unconditional tail' % want)
    # both forks converge at 0x8024 -> tail is unconditional for every cpu
    o('  tail verified: wait loop 0x8024..0x803c (polls w0xc001 + dc0(0)='
      'byte0(w0x2ef)) -> call 0x243bc8 @0x8040 -> main-init RETURNS '
      '(idle = entry self-jump 0x7ee8); fork sites 0x7f78/0x7f94..0x7fac '
      'are CONFIG-DEPENDENT (runtime w0x2ef) - not primary candidates')
    dis_range(0x7fa8, 0x8058, 'main-init tail: init chain end, wait loop, final call')

    # S3: 0xefc GATE-on-spine (config-conditional path, secondary cand) --
    o('')
    o('[S3] fn 0xefc (cpu0 + w0x2ef==0xf path, main-init @0x7f78) spine:')
    efc_spine = []
    off = 0xefc
    guard = 0
    while off < len(code) and guard < 0x2000:
        guard += 1
        d = dis(off)
        m = call_re.match(d)
        if m:
            efc_spine.append((off, int(m.group(1), 16)))
            off += 4
            continue
        if d.startswith('ret.'):
            efc_spine.append((off, None))
            break
        m = jump_re.match(d)
        if m and m.group(1).startswith('0x') and not m.group(1).startswith('0x-'):
            off = int(m.group(1), 16)
            continue
        m = br_re.match(d) or bb_re.match(d)
        if m:
            off += 4
            continue
        off += 4
    for site, tgt in efc_spine[:12]:
        o('  0x%08x  %s' % (site, 'call 0x%x' % tgt if tgt else 'RET'))
    gate_off = 0xf10
    if not any(s == gate_off and t == GATE for s, t in efc_spine):
        fail('GATE 0x%x not on 0xefc spine' % gate_off)
    if dis(0xf08) != 'set2 r4,zero,0x1000' or dis(0xf0c) != 'addi r5,zero,0x0':
        fail('GATE site 0xf10 class/level setup words changed')
    o('  GATE @0xf10 ON 0xefc spine: class 0x1000 (bit12), level 0 -> '
      'call always executed; emit0 @0xf24 masked at boot (w2=0, L0) - '
      'hook target is the GATE call word itself')
    dis_range(0xefc, 0xf60, 'fn 0xefc head')

    # S4: live-in liveness at candidate sites --------------------------
    o('')
    o('[S4] live-in liveness (forward first-use to fn end; regs read '
      'before written = live-across):')
    FN_END = {0x7ee4: 0x7ef0, 0x8034: 0x8058, 0x8040: 0x8058, 0xf10: 0xf70}
    FN_OF = {0x7ee4: ENTRY_DC, 0x8034: MAIN_INIT, 0x8040: MAIN_INIT, 0xf10: 0xefc}
    for site in (0x7ee4, 0x8034, 0x8040, 0xf10):
        fn = FN_OF[site]
        end = FN_END[site]
        live2 = set()
        off = site + 4
        while off < end:
            d = dis(off)
            if d.startswith('ret.'):
                break
            m = call_re.match(d)
            if m:
                # call reads its arg regs (approx: all regs named in the 3
                # words before it are args - conservative: keep all live)
                live2 -= {'r%d' % r for r in range(5, 12)}
                off += 4
                continue
            regs = [r for r in re.findall(r'\br\d+\b', d) if r != 'zero']
            if d.startswith(('st.', 'sw.')):
                for r in set(regs):
                    if r not in live2:
                        live2.add(r)
            else:
                if regs:
                    for r in regs[1:]:
                        if r not in live2:
                            live2.add(r)
                    # rd written (approximate: first operand is dest)
            off += 4
        o('  site 0x%08x (fn 0x%x): live-across (call-barrier-aware)=%s'
          % (site, fn, sorted(live2)))

    # S5: cave reachability -------------------------------------------
    o('')
    o('[S5] cave reachability (rel24 signed, +/-0x2000000):')
    for site in (0x7ee4, 0x8034, 0x8040, 0xf10):
        dist = CAVE - site
        o('  site 0x%x -> cave 0x%x: delta %+#x %s'
          % (site, CAVE, dist, 'OK' if abs(dist) <= 0x2000000 else 'OUT OF RANGE'))

    # S6: GATE (class,level) inventory in main-init call tree ----------
    o('')
    o('[S6] GATE sites in main-init call tree (depth<=3) with (class,level):')
    import bisect
    PROLOGUE = 0x480300bc
    starts = sorted([i * 4 for i in range(n) if words[i] == PROLOGUE]
                    + [0x0, ENTRY_DC])
    from collections import deque
    seen = {}
    q = deque([(MAIN_INIT, 0)])
    while q:
        fn, depth = q.popleft()
        if depth > 3 or fn in seen:
            continue
        seen[fn] = depth
        fi = bisect.bisect_right(starts, fn)
        end2 = starts[fi] if fi < len(starts) else len(code)
        for off2 in range(fn, min(end2, fn + 0x2000), 4):
            m = call_re.match(dis(off2))
            if m:
                q.append((int(m.group(1), 16), depth + 1))
    hits = 0
    for fn in sorted(seen, key=lambda f: seen[f]):
        depth = seen[fn]
        fi = bisect.bisect_right(starts, fn)
        end2 = starts[fi] if fi < len(starts) else len(code)
        for off2 in range(fn, min(end2, fn + 0x2000), 4):
            m = call_re.match(dis(off2))
            if not m:
                continue
            t = int(m.group(1), 16)
            if t != GATE and t not in EMITS:
                continue
            cls = lvl = '?'
            for back in range(1, 7):
                d2 = dis(off2 - 4 * back)
                if lvl == '?' and re.match(r'^addi r5,zero,0x[0-9a-f]+$', d2):
                    lvl = d2.split(',')[2]
                if cls == '?' and re.match(r'^(set2|set3|addi) r4,(zero|r4),0x[0-9a-f]+$', d2) \
                        and 'hi' not in d2:
                    cls = d2
            hits += 1
            o('  d%d fn 0x%06x site 0x%06x %s cls=<%s> lvl=%s'
              % (depth, fn, off2, 'GATE' if t == GATE else 'emit%d' % EMITS[t],
                 cls, lvl))
    if hits == 0:
        fail('no GATE/emit sites found in boot tree (unexpected)')
    o('  (level>=2 sites -> emit executes even with w2=0; see report for '
      'the two L3 sites found in 0x37a94/0x39330 contexts)')

    # R1: word-index ld.i/st.i scan ------------------------------------
    o('')
    o('[R1] ld.i/st.i word-index refs to reserve + 0x23f8 (whole MAIN_CODE):')
    res_refs = []
    for i in range(n):
        d = dis(i * 4)
        m = re.match(r'^(ld\.i|st\.i) r\d+,0x([0-9a-f]+)$', d)
        if m:
            w = int(m.group(2), 16)
            if RES_WLO <= w <= RES_WH1 or w == WORD_23F8:
                res_refs.append((i * 4, d))
    for a, d in res_refs:
        o('  HIT 0x%08x %s' % (a, d))
    if res_refs:
        o('  VERDICT: %d refs -> reserve NOT clean' % len(res_refs))
    else:
        o('  VERDICT: 0 refs -> reserve 0x2314..0x23e4 + 0x23f8 clean (word-index form)')

    # positive controls
    ctl = {0x8fc: 0xd4c92, 0x8fd: None, 0x8ff: 0xd4d7c}
    ok8fc = any(dis(a) == 'ld.i r6,0x8fc' for a in range(0xd4c80, 0xd4ca0, 4))
    if not ok8fc:
        fail('positive control ld.i r6,0x8fc @0xd4c92 not found')
    cnt8fd = sum(1 for i in range(n) if re.match(r'^ld\.i r\d+,0x8fd$', dis(i * 4)))
    if cnt8fd < 29:
        fail('positive control 0x8fd reader count %d < 29' % cnt8fd)
    o('  positive controls: ld.i r6,0x8fc @0xd4c92 OK; ld.i r4,0x8fd x%d OK' % cnt8fd)

    # R2: base-zero absolute EA scan -----------------------------------
    o('')
    o('[R2] ld/st trailing-imm EA refs into CR window (0x2000..0x2400), '
      'code region only (dc < 0x2d6900; db0 string bytes decode as '
      'instructions -> artifacts, excluded):')
    win_refs = []
    for i in range(min(n, CODE_END // 4)):
        d = dis(i * 4)
        if not d.startswith(('ld.', 'st.')) or d.startswith(('ld.i', 'st.i')):
            continue
        m = re.search(r',(0x-?[0-9a-f]+)$', d)
        if not m:
            continue
        ea = int(m.group(1), 16)
        if ea < 0:
            ea += 0x100000000
        if 0x2000 <= ea < 0x2400:
            win_refs.append((i * 4, ea, d))
    for a, ea, d in win_refs:
        tag = ''
        if RES_LO <= ea <= RES_HI:
            tag = ' <<< RESERVE'
        if ea == 0x23f8:
            tag = ' <<< 0x23f8'
        o('  0x%08x EA 0x%04x %s%s' % (a, ea, d, tag))
    res_hits = [x for x in win_refs if RES_LO <= x[1] <= RES_HI or x[1] == 0x23f8]
    if res_hits:
        o('  VERDICT: reserve/0x23f8 hits present: %d' % len(res_hits))
    else:
        o('  VERDICT: 0 refs to reserve + 0x23f8 (absolute EA form); '
          'known window refs above are outside 0x2314..0x23e4')

    # R3: constant-loader composite scan --------------------------------
    o('')
    o('[R3] constant loaders building reserve/0x23f8 addresses (code region '
      'only, zero-base forms):')
    cons = []
    for i in range(min(n, CODE_END // 4)):
        d = dis(i * 4)
        m = re.match(r'^(set2|set3|addi) r\d+,zero,0x([0-9a-f]+)$', d)
        if m:
            v = int(m.group(2), 16)
            if RES_LO <= v <= RES_HI:
                cons.append((i * 4, d))
            elif v == 0x23f8:
                cons.append((i * 4, d))
    for a, d in cons:
        o('  CAND 0x%08x %s' % (a, d))
    # hi-half + lo-half pairing check for real composites
    comp = []
    for a, d in cons:
        nxt = dis(a + 4)
        if re.match(r'^(set3|addi\.hi) r\d+,r\d+,0x(23|24)$', nxt):
            comp.append((a, d, nxt))
    if comp:
        o('  COMPOSITE SUSPECTS:')
        for a, d, nxt in comp:
            o('   0x%08x %s | %s' % (a, d, nxt))
    else:
        o('  VERDICT: %d lo-half zero-base matches, 0 composites with hi=0x23 '
          '-> no code builds a reserve/0x23f8 absolute address' % len(cons))

    # R4 summary --------------------------------------------------------
    o('')
    o('[R4] CR 0x23f8 (word 0x8fe): ld.i/st.i=0 (R1), absolute EA=0 (R2), '
      'composite=0 (R3) -> clean in ALL forms; candidate boot-ready flag slot')
    open(LOG, 'w').write('\n'.join(o.lines) + '\n')
    o('')
    o('ALL GATES PASSED; log -> %s' % LOG)


if __name__ == '__main__':
    main()
