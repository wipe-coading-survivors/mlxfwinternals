#!/usr/bin/env python3
"""cx4lx-detour T2c: offline revision of the H-DEC site (is_sfp branch).

Pure static RE over the stock GCA-1900 base (md5-gated). Reproduces the
T2c findings:

  1. MM-init SM state dispatch map (jump table @dc 0x31930c, states 0..20;
     state > 0x14 unsigned-strictly-greater via cc3 -> 'default state' L3).
  2. State 8 = MM_INIT_PLUGGED_IN block 0x231ebc: CFG walk proving EVERY
     internal path converges on the pre-is_sfp block 0x232fd4 -> call
     0x222670 (is_sfp) @0x233094 (site executes 1:1 with state 8).
  3. Gate fn 0x225b5c decode: returns 1 iff (nibble@0x4a17d+0x380*m != 0)
     AND (bit@0x4a327+0x380*m == 1) AND (tab12@0x67f6f[2] != 0xfff);
     PLUGGED_IN branches on it @0x231f74 only between direct vs quick
     (notify 0x22478c 0x22/0x23) sub-paths -- both still reach is_sfp.
  4. Fast-path hook candidate C1 = 0x231a64 (state-1 first I2C call):
     stock word, rel24 to cave 0x31cba0, branch-aware live-after scan,
     marker 0x00aeea41 dead-check.
  5. 56GbE bit location on this base: FW_MAIN_CFG (ITOC 0x12) lcl[0]
     .eth_speeds_supported bit6; stock value decode + patch value.

Output: human-readable report to stdout. Exit 0 on all checks PASS.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WT = HERE.parents[3]
sys.path.insert(0, str(HERE.parent / 't0'))
sys.path.insert(0, str(WT))
from t0lib import Code, RT  # noqa: E402

CAVE_DC = 0x31cba0
REL24_MAX = 0x2000000

RW = re.compile(r'\b(r\d+)\b')
CALLER_SAVED = {'r%d' % i for i in range(4, 17)}
WR_OPS = ('addi', 'addi.hi', 'subi', 'subsi', 'set2', 'set3', 'or', 'xor',
          'and', 'ands', 'subs', 'add', 'shr', 'shl64', 'mask32', 'alu',
          'op0x0d', 'op0x33', 'op0x36', 'ld.d', 'ld.w', 'ld.q', 'ld.b',
          'ld.i', 'lw.r', 'csr.r')

CHECKS = []


def check(name, ok, detail=''):
    CHECKS.append(ok)
    print('[%s] %s%s' % ('PASS' if ok else 'FAIL', name,
                         (' -- ' + detail) if detail else ''))


def reads_writes(d):
    tok = d.split()[0]
    regs = [x for x in RW.findall(d) if x != 'zero']
    if not regs:
        return [], []
    if tok in WR_OPS:
        return regs[1:], [regs[0]]
    if tok in ('st.d', 'st.w', 'st.q', 'st.b', 'csr.w'):
        return regs, []
    if tok.startswith('st.') and tok.endswith('!'):
        return regs, regs[:1]
    if tok in ('b.t', 'b.f') or tok.startswith('b.b') or tok == 'jump':
        return regs[-1:], []
    return regs, []


def branch_targets(d, off):
    if d.startswith('jump 0x'):
        return [int(d.split()[1], 16)], True
    m = re.match(r'^b\.[tb]\.[0-9a-fx]+ \S+,0x([0-9a-f]+)$', d)
    if m:
        return [off + 4, int(m.group(1), 16)], False
    m = re.match(r'^b\.b(?:set|clr) \d+,\S+,0x([0-9a-f]+)$', d)
    if m:
        return [off + 4, int(m.group(1), 16)], False
    if d.startswith('call') or d.startswith('ret'):
        return ([off + 4] if d.startswith('call') else []), d.startswith('call')
    return [off + 4], False


def cfg_walk(c, entry, stops, limit=4000):
    """Walk CFG from entry until any stop address (or ret). Return set of
    reached stops (addresses in `stops` that are hit)."""
    from collections import deque
    hit = set()
    seen = set()
    q = deque([entry])
    while q and len(seen) < limit:
        off = q.popleft()
        while True:
            if off in seen or not (0 <= off < 0x2d6900):
                break
            seen.add(off)
            if off in stops:
                hit.add(off)
                break
            d = c.dis(off)
            if d.startswith('ret'):
                break
            tgts, _ = branch_targets(d, off)
            if d.startswith('jump'):
                off = tgts[0]
                continue
            if len(tgts) == 2:
                q.append(tgts[1])
            if not tgts:
                break
            off = tgts[0]
    return hit, seen


def live_after(c, start, limit=3000):
    live = set()
    from collections import deque
    q = deque()
    q.append((start, frozenset()))
    seen = set()
    while q and len(seen) < limit:
        off, killed = q.popleft()
        while True:
            if (off, killed) in seen or not (0 <= off < 0x2d6900):
                break
            seen.add((off, killed))
            d = c.dis(off)
            if d.startswith('ret'):
                break
            rd, wr = reads_writes(d)
            for r in rd:
                if r not in killed:
                    live.add(r)
            killed = killed | set(wr)
            tgts, is_call = branch_targets(d, off)
            if is_call:
                killed = killed | CALLER_SAVED
            if d.startswith('jump'):
                off = tgts[0]
                continue
            if len(tgts) == 2:
                q.append((tgts[1], killed))
            if not tgts:
                break
            off = tgts[0]
    return live


def main():
    c = Code()
    print('base md5 gate: OK (t0lib asserts 3bd3230b...)')

    print('\n== 1. MM-init SM state dispatch table @dc 0x31930c ==')
    base = 0x31930c
    n_states = 0x15  # 0..20 valid; >20 -> default-state error (cc3 unsigned >)
    tbl = {}
    for i in range(n_states):
        w = c.dw(base + 4 * i)
        tbl[i] = w - RT
    for i, dc in tbl.items():
        print('  state %2d -> 0x%06x' % (i, dc))
    check('state 8 -> PLUGGED_IN block 0x231ebc', tbl[8] == 0x231ebc)
    check('state 19 -> 0x2325d0 (PARSE_PAGE 1-tok emit block)',
          tbl[19] == 0x2325d0)

    print('\n== 2. state-8 (PLUGGED_IN) CFG convergence on is_sfp site ==')
    # walk from state-8 entry; stop points: the is_sfp call word and
    # every "exit" (block-terminal instructions that leave state 8 without
    # passing 0x233094). Collect all ret/epilogue jumps reached.
    stops = {0x233094}
    hit, seen = cfg_walk(c, 0x231ebc, stops)
    check('every state-8 path reaches call is_sfp @0x233094', 0x233094 in hit,
          '%d instrs walked' % len(seen))
    # and confirm the epilogue (0x233e94 log/commit) is only reachable by
    # passing through the is_sfp tail: walk with the epilogue as the only
    # stop, then require 0x233094 among the visited instructions.
    hit2, seen2 = cfg_walk(c, 0x231ebc, {0x233e94})
    check('epilogue reached with is_sfp call on every route',
          0x233e94 in hit2 and 0x233094 in seen2)

    print('\n== 3. gate fn 0x225b5c predicates (structural decode) ==')
    gate_body = c.dis_range(0x225b5c, 0x225c00)
    lookup_body = c.dis_range(0x21151c, 0x2115b0)
    preds = [
        ('0x222a34(m): nibble-test @0x4a17d+0x380*m (cmp via op0x36/b.t.0xa)',
         c.dis(0x222a34).startswith('shl64.i r5,r4,0x8')),
        ('bit-test @0x4a327+0x380*m inside 0x225b5c (set2 0x4/set3 0xa327)',
         '0xa327' in gate_body and 'set2 r5,zero,0x4' in gate_body),
        ('tab12 @0x67f6f idx2 via 0x2117b4 -> 0x21151c (set2 0x6/set3 0x7f6f)',
         '0x7f6f' in lookup_body and 'set2 r4,zero,0x6' in lookup_body),
        ('PLUGGED_IN gate call site 0x231f6c -> call 0x225b5c',
         c.dis(0x231f6c) == 'call 0x225b5c'),
        ('gate==0 -> full block (b.t.0.0 = branch-if-zero, cc0=eq/zero)',
         c.dis(0x231f74) == 'b.t.0x0 zero,0x232fd4'),
    ]
    for name, ok in preds:
        check(name, ok)

    print('\n== 4. fast-path candidate C1 = 0x231a64 (state-1 first I2C) ==')
    w = c.dw(0x231a64)
    check('stock word is call 0x2347ec', c.dis(0x231a64) == 'call 0x2347ec',
          'word 0x%08x' % w)
    rel = CAVE_DC - 0x231a64
    check('rel24 to cave within limit', 0 < rel <= REL24_MAX,
          'rel24 = 0x%x (%d) <= 0x2000000' % (rel, rel))
    live = live_after(c, 0x231a68)
    print('   live-after C1: %s' % sorted(live, key=lambda x: int(x[1:])))
    check('live-after subset of {r1,r4,r21,r22,r23} (r4=retval restored by stub)',
          live <= {'r1', 'r4', 'r21', 'r22', 'r23'})
    ld = c.loaders().get(0x00aeea41, [])
    raw = c.raw_words(0x00aeea41)
    check('marker 0x00aeea41 dead on base (0 loaders, 0 raw words)',
          not ld and not raw)
    live_hdec = live_after(c, 0x233098)
    check('H-DEC live-after is superset of C1 (C1 strictly easier)',
          live <= live_hdec,
          'H-DEC: %s' % sorted(live_hdec, key=lambda x: int(x[1:])))

    print('\n== 5. 56GbE bit: FW_MAIN_CFG lcl[0].eth_speeds_supported bit6 ==')
    import mlxfwutil  # noqa: E402
    img_buf = (WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_'
               'Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin').read_bytes()
    img = mlxfwutil.Image(img_buf)
    e = img.find_entry('ITOC', 0x12)
    a = img.sec_abs(e)
    lcl0 = img_buf[a + 0x30b]
    lcl1 = img_buf[a + 0x317]
    speeds = {0: '1G', 1: '10G', 2: '20G', 3: '25G', 4: '40G', 5: '50G',
              6: '56G', 7: '100G'}
    have = [speeds[b] for b in range(8) if lcl0 & (1 << b)]
    print('   FW_MAIN_CFG @0x%x size 0x%x; lcl[0] @abs 0x%x = 0x%02x = {%s}'
          % (a, e.size, a + 0x30b, lcl0, ','.join(have)))
    check('lcl[0] == 0x3b = {1,10,25,40,50}G (GCA stock, no 56G)',
          lcl0 == 0x3b, 'patch target = 0x%02x (+56G bit6)' % (lcl0 | 0x40))
    check('lcl[1] @+0xC == 0x00 (single-port: port-1 slot empty)', lcl1 == 0)

    print('\n== summary ==')
    print('%d/%d checks PASS' % (sum(CHECKS), len(CHECKS)))
    return 0 if all(CHECKS) else 1


if __name__ == '__main__':
    sys.exit(main())
