#!/usr/bin/env python3
"""T0(d) v2: correct branch-aware liveness with kill-on-write.
A reg is live-after-site iff on some CFG path from site+4 it is READ
before being WRITTEN (per-path). Calls: conservative callee clobber of
caller-saved r4..r16 EXCEPT regs the caller reads after the call on some
path -- approximated: a call KILLS r4..r16 (they're dead across it);
callee-saved r17..r23 + r1/r2/r3 survive calls."""
import re
import sys
sys.path.insert(0, '/tmp/opencode/t0')
from t0lib import Code

RW = re.compile(r'\b(r\d+)\b')
CALLER_SAVED = {'r%d' % i for i in range(4, 17)}
WR_OPS = ('addi', 'addi.hi', 'subi', 'subsi', 'set2', 'set3', 'or', 'xor',
          'and', 'ands', 'subs', 'add', 'shr', 'shl64', 'mask32', 'alu',
          'op0x0d', 'op0x33', 'op0x36', 'ld.d', 'ld.w', 'ld.q', 'ld.b',
          'ld.i', 'lw.r', 'csr.r')


def reads_writes(d):
    tok = d.split()[0]
    regs = [x for x in RW.findall(d) if x != 'zero']
    if not regs:
        return [], []
    if tok in WR_OPS:
        return regs[1:], [regs[0]]
    if tok in ('st.d', 'st.w', 'st.q', 'st.b', 'csr.w'):
        return regs, []
    if tok.startswith('st.') and tok.endswith('!'):   # st.d! rt,[rs],off
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


def scan(c, start, limit=2000):
    live = set()
    # BFS with per-path dead-set: state = (off, frozenset(not-yet-written regs seen written))
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


if __name__ == '__main__':
    c = Code()
    for name, start in [
            ('K1 0x1b9da8 (after emit4 stock call)', 0x1b9da8),
            ('K2 0x231f14 (after is_qsfp stock call)', 0x231f14),
            ('K3 0x1bdd00 (jump target after self-post call)', 0x1bdd00),
            ('K4 0x1bdbd4 (after init_ib_an_fsm call)', 0x1bdbd4)]:
        live = scan(c, start)
        print('== %s' % name)
        print('   live-after: %s' % sorted(live, key=lambda x: int(x[1:])))
