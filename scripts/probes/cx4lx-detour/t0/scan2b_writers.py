#!/usr/bin/env python3
"""T0(b)-2: map descriptor/bitfield constant users (builders), classify
reader/writer, find the identifier STORE (parse path) and cage-bit writer."""
import re
import sys
sys.path.insert(0, '/tmp/opencode/t0')
from t0lib import Code

CONSTS = {0x942c: 'module-desc w0 (byte0=identifier)',
          0x6776f: 'bitfield-A (is_sfp port-bit)',
          0x4a17d: 'bitfield-B (qsfp byte+bit)'}

c = Code()
# collect builders: set3 rX,zero,C / set3 rX,rX,C with C in CONSTS, or addi pairs
builders = {}
for i in range(c.n):
    d = c.dis(i * 4)
    m = re.match(r'^set3 (r\d+),zero,(0x[0-9a-f]+)$', d)
    if m and int(m.group(2), 16) in CONSTS:
        builders.setdefault(int(m.group(2), 16), []).append(i * 4)

for val, name in sorted(CONSTS.items()):
    sites = builders.get(val, [])
    print('== 0x%x (%s): %d set3-builder sites' % (val, name, len(sites)))
    for s in sites[:40]:
        # look ahead 12 instrs for st. (writer) or lw.r (reader)
        kind = '?'
        for off in range(s, s + 0x34, 4):
            d = c.dis(off)
            if re.match(r'^st\.[dwqb]', d):
                kind = 'WRITER st'
                break
            if d.startswith('lw.r') or d.startswith('ld.'):
                kind = 'reader'
                break
            if d.startswith(('call', 'jump', 'ret')):
                kind = 'base-only/' + d.split()[0]
                break
        print('   0x%-8x %s' % (s, kind))
