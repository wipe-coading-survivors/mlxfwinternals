#!/usr/bin/env python3
"""T0(b): find SFF identifier compares in module-mgmt region.

Scan for mask32 rd,rs,0,8 (byte0 extract) followed within 8 instrs by a
compare against SFF identifier constants (3=SFP, 0xc=QSFP, 0xd=QSFP+,
0x11=QSFP28, 0x1e/0x1f?, 0xe?) or a subsi/addi-1 dispatch. Also dump
direct subsi rX,rY,K with those K anywhere in module region.
"""
import re
import sys
sys.path.insert(0, '/tmp/opencode/t0')
from t0lib import Code

SFF = {0x3: 'SFP/SFP+', 0xc: 'QSFP', 0xd: 'QSFP+', 0x11: 'QSFP28', 0xe: 'EDR?',
       0x1e: 'CMIS?', 0x1f: '?', 0x10: '?', 0x17: '?', 0x18: '?', 0x19: '?', 0x1a: '?'}

c = Code()
LO, HI = 0x219000, 0x23c000
print('--- mask32 byte0 extract + nearby compare ---')
for off in range(LO, HI, 4):
    d = c.dis(off)
    m = re.match(r'^mask32 (r\d+),(r\d+),0x0,8$', d)
    if not m:
        continue
    rd = m.group(1)
    for off2 in range(off + 4, off + 0x24, 4):
        d2 = c.dis(off2)
        m2 = re.match(r'^(subsi|addi) %s,(r\d+|zero),(0x-?[0-9a-f]+)$' % rd, d2)
        if m2:
            imm = int(m2.group(3).replace('0x-', '-0x'), 16)
            if imm in SFF or -imm in SFF:
                print('0x%x %s | 0x%x %s -> %s' % (
                    off, d, off2, d2, SFF.get(imm) or SFF.get(-imm)))
            break
        if d2.startswith(('b.', 'jump', 'call')):
            print('0x%x %s | 0x%x %s (branch before compare)' % (off, d, off2, d2))
            break

print()
print('--- subsi rX,rY,K (K in SFF set) whole code ---')
for off in range(0, 0x2d6900, 4):
    d = c.dis(off)
    m = re.match(r'^subsi (r\d+),(r\d+|zero),(0x-?[0-9a-f]+)$', d)
    if not m:
        continue
    imm = int(m.group(3).replace('0x-', '-0x'), 16)
    if imm in SFF and c.dis(off + 4).startswith('b.'):
        # context: preceding instr loads something into rs?
        print('0x%x  %-28s | prev: %s' % (off, d, c.dis(off - 4)))
