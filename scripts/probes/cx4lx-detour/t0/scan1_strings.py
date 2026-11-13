#!/usr/bin/env python3
"""T0(a): scan db0 for cable/module/SFP/QSFP/AN/I2C/SFF-topic strings.

For each hit: rt addr, liveness (loader present?), and for live ones the
GATE (class, level) + emit family from the site. Output: grouped table.
"""
import re
import sys
from pathlib import Path
sys.path.insert(0, '/tmp/opencode/t0')
from t0lib import Code, RT, DB0_DC, DB0_SIZE

KW = re.compile(
    rb'(?i)\b(sfp|qsfp|cable|cbl|module|mod_|transceiver|xceiver|i2c|sff|'
    rb'an[_ .]|an$|_an|autoneg|auto_neg|link_|_link|serdes|phy|'
    rb'cmis|ddm|dom|optics|speed|lane)\b')

c = Code()
loaded = c.loaders()
segs = c.db0_strings()
print('db0 segments: %d; loaded rt constants: %d' % (len(segs), len(loaded)))

hits = []
for dc, s in segs:
    if KW.search(s):
        rt = dc + RT
        sites = loaded.get(rt, [])
        live = bool(sites) or bool(c.raw_words(rt))
        hits.append((dc, s, rt, live, sites))

print('keyword hits: %d (live %d, dead %d)' % (
    len(hits), sum(1 for h in hits if h[3]), sum(1 for h in hits if not h[3])))
print()

live_rows = []
for dc, s, rt, live, sites in sorted(hits, key=lambda h: h[0]):
    if not live:
        continue
    for site in sites[:3]:
        cls, lvl = c.gate_context(site)
        em = c.emit_after(site)
        live_rows.append((dc, s, rt, site, cls, lvl, em))

print('=== LIVE topic strings (site context) ===')
for dc, s, rt, site, cls, lvl, em in live_rows:
    print('dc 0x%06x rt 0x%08x site 0x%06x class=%s level=%s emit=%s | %r' % (
        dc, rt, site, hex(cls) if cls is not None else '?',
        lvl, (hex(em[0]) + ' emit%d' % em[2]) if em else '?', s[:90]))
    if len(live_rows) > 400:
        break

print()
print('=== DEAD topic strings ===')
for dc, s, rt, live, sites in sorted(hits, key=lambda h: h[0]):
    if live:
        continue
    nx = len(re.findall(rb'%[-+ #0]*[0-9]*(?:hh|h|ll|l)?[xXdDui]', s))
    print('dc 0x%06x rt 0x%08x tokens=%d | %r' % (dc, rt, nx, s[:90]))
