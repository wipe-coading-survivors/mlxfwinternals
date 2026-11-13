import struct, sys, bisect

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4
words = [struct.unpack_from('>I', data, i * 4)[0] for i in range(n)]

prologues = set()
for i in range(n):
    w = words[i]
    if (w >> 26) == 0x12 and (w >> 25) & 1 == 0 and (w >> 16) & 0x1F == 3 and (w & 0x7FF) == 0xBC:
        prologues.add(i * 4)
plist = sorted(prologues)

def func_start(off):
    idx = bisect.bisect_right(plist, off) - 1
    return plist[idx] if idx >= 0 else None

def s16(v):
    return v - 0x10000 if v & 0x8000 else v

hits = []
for i in range(n):
    w = words[i]
    op = w >> 26
    rd = (w >> 16) & 0x1F
    rs = (w >> 21) & 0x1F
    F = (w >> 2) & 0x3FFF
    r_loaded = None
    base = None
    # Pattern A: direct load at byte 0x20 (F=8)
    if op in (0x17, 0x19) and F == 0x8 and rs != 0:
        r_loaded = rd
        base = 'ld'
    # Pattern B: pre-add base+0x20 then load F=0
    if op in (0x00, 0x01) and (w & 0xFFFF) == 0x20 and rs != 0 and rd != 0:
        r_loaded = None
        base = 'preadd'
        preadd_rd, preadd_rs = rd, rs
        for d in range(1, 9):
            if i + d >= n:
                break
            w2 = words[i + d]
            op2 = w2 >> 26
            if op2 in (0x17, 0x19) and ((w2 >> 2) & 0x3FFF) == 0 and ((w2 >> 21) & 0x1F) == preadd_rd:
                r_loaded = (w2 >> 16) & 0x1F
                base = 'preadd+ld'
                i2 = i + d
                break
    if r_loaded is None or r_loaded == 0:
        continue
    # look for shr-16 / mask32-sh16 on r_loaded within 8 words
    for d in range(1, 9):
        j = i + d
        if j >= n:
            break
        w2 = words[j]
        op2 = w2 >> 26
        f2 = w2 & 0x1FF
        sh = (w2 >> 11) & 0x1F
        rd2 = (w2 >> 16) & 0x1F
        rs2 = (w2 >> 21) & 0x1F
        if op2 == 0x3F and f2 in (0x83, 0x8A) and sh == 0x10 and rs2 == r_loaded:
            hits.append((i * 4, j * 4, base, r_loaded))
            break
        if op2 == 0x32 and sh == 0x10 and rs2 == r_loaded:
            hits.append((i * 4, j * 4, base, r_loaded))
            break

print('exact [r,0x20]>>16 pattern hits:', len(hits))
seen = set()
for lo, hi, base, r in hits:
    fs = func_start(lo)
    key = (fs, base)
    tag = ''
    if key in seen:
        tag = ' (fn already listed)'
    seen.add(key)
    print('  load@0x%06x (%s r%d)  shift@0x%06x  fn 0x%06x%s' % (lo, base, r, hi, fs, tag))
