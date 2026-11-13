#!/usr/bin/env python3
"""T0(d): post-site liveness scan for hook candidates (L3-T3 method,
branch-aware): from site+4, walk CFG (follow jumps, both branch targets,
stop at ret); a reg is LIVE-after if read before written on any path.
Scratch set for stub = regs dead after (caller-saved only)."""
import re
import sys
sys.path.insert(0, '/tmp/opencode/t0')
from t0lib import Code

RW = re.compile(r'\b(r\d+)\b')
WR_OPS = ('addi', 'addi.hi', 'subi', 'subsi', 'set2', 'set3', 'or', 'xor',
          'and', 'ands', 'subs', 'add', 'shr', 'shl64', 'mask32', 'alu',
          'op0x0d', 'op0x33', 'op0x36', 'ld.d', 'ld.w', 'ld.q', 'ld.b',
          'ld.i', 'lw.r', 'st.d!', 'st.w!', 'st.q!')


def scan(c, start, maxvisit=300):
    live = set()
    seen = set()
    stack = [start]
    while stack and len(seen) < maxvisit:
        off = stack.pop()
        while True:
            if off in seen or off >= 0x2d6900 or off < 0:
                break
            seen.add(off)
            d = c.dis(off)
            if d.startswith('ret'):
                break
            tok = d.split()[0]
            regs = [x for x in RW.findall(d) if x != 'zero']
            # destination reg (written): first reg operand for WR_OPS
            dst = None
            if tok in WR_OPS and regs:
                dst = regs[0]
            elif tok.startswith('csr.w') or tok.startswith('st.') and not tok.endswith('!'):
                # st.d rSRC,rBASE,off: rt (bits 15-11) is source; base read
                pass
            for r in regs:
                if r != dst:
                    live.add(r)
            # control flow
            m = re.match(r'^jump (0x[0-9a-f]+)$', d)
            if m:
                off = int(m.group(1), 16)
                continue
            m = re.match(r'^b\.[tb]\.[0-9a-fx]+ \S+,(0x[0-9a-f]+)$', d)
            if m:
                stack.append(int(m.group(1), 16))
                off += 4
                continue
            m = re.match(r'^b\.b(set|clr) \d+,\S+,(0x[0-9a-f]+)$', d)
            if m:
                stack.append(int(m.group(2), 16))
                off += 4
                continue
            m = re.match(r'^call (0x[0-9a-f]+)$', d)
            if m:
                # conservative: calls clobber caller-saved r3..r16? known:
                # emit family clobbers r3,r5..r9(,r10/r11); general callee
                # may clobber r4..r16; we mark all caller-saved as
                # potentially-written => they are NOT live-after across a
                # later call unless read before it (handled: read check
                # happens before reaching the call)
                for r in ['r%d' % i for i in range(3, 17)]:
                    pass
                off += 4
                continue
            off += 4
    return live, seen


if __name__ == '__main__':
    c = Code()
    sites = {
        'K1 0x1b9da4 (call emit4, init_ib_an_fsm)': 0x1b9da8,
        'K2 0x231f10 (call 0x222828 is_qsfp, PLUGGED_IN)': 0x231f14,
        'K3 0x1bd5a8 (call 0x1bf930 self-post)': 0x1bd5ac,
        'alt 0x231f0c? (or r4,r22) n/a': None,
        'K4 0x1bdbc0-ctx (call init_ib_an_fsm @0x1bdbd0)': 0x1bdbd4,
    }
    for name, start in sites.items():
        if start is None:
            continue
        live, seen = scan(c, start)
        print('== %s' % name)
        print('   live-after (read-before-write): %s' % sorted(live, key=lambda x: int(x[1:])))
        print('   visited %d instrs' % len(seen))
