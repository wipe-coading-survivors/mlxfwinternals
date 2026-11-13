import struct, sys, bisect

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4
words = [struct.unpack_from('>I', data, i * 4)[0] for i in range(n)]

CALLSITES = [0x0b0970, 0x0b16d0, 0x0b43c4, 0x0b48dc, 0x0b6078, 0x0e2e84,
             0x16101c, 0x161940, 0x169dc8, 0x2e7018, 0x31b41c, 0x32fbf0]

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

def sig(w):
    op = w >> 26
    f = w & 0x1FF
    rd = (w >> 16) & 0x1F
    rs = (w >> 21) & 0x1F
    shamt = (w >> 11) & 0x1F
    imm16 = w & 0xFFFF
    F = (w >> 2) & 0x3FFF
    if op == 0x3f and f == 0x25 and rd == 0 and rs == 0:
        return 'jalr r%d' % shamt
    if op == 0x3f and f in (0x83, 0x8A) and shamt == 0x10:
        return 'SHR-16 (opcode-cand) rd=%d rs=%d' % (rd, rs)
    if op == 0x3f and f in (0x83, 0x8A) and shamt == 0x20:
        return 'SHR-32 rd=%d rs=%d' % (rd, rs)
    if op == 0x32 and shamt == 0x10:
        return 'mask32 sh=16 mask=%d rd=%d rs=%d' % (w & 0x1F, rd, rs)
    if op == 0x32 and shamt == 0x20:
        return 'mask32 sh=32 mask=%d rd=%d rs=%d' % (w & 0x1F, rd, rs)
    if op in (0x17, 0x19) and F == 0x8:
        kind = {0x17: ('ld.d.17' if (w >> 1) & 1 else 'ld.q.17'),
                0x19: ('ld.w' if w & 1 else 'ld.d' if w & 2 else 'ld.q')}[op]
        return '%s [r%d,0x20]' % (kind, rs)
    if op == 0x18 and s16(imm16) == 0x20:
        return 'ld.b [r%d,0x20]' % rs
    if op in (0x00, 0x01) and imm16 == 0x20 and rs != 0:
        return 'addi r%d,r%d,0x20' % (rd, rs)
    return None

seen = set()
for cs in CALLSITES:
    fs = func_start(cs)
    if fs in seen:
        continue
    seen.add(fs)
    fsi = fs // 4
    j = bisect.bisect_left(plist, fs) + 1
    fe = plist[j] if j < len(plist) else n * 4
    fe = min(fe, fs + 0x4000)
    hits = []
    for i in range(fsi, fe // 4):
        s = sig(words[i])
        if s:
            hits.append((i * 4, s))
    print('callsite 0x%06x -> fn 0x%06x .. 0x%06x (0x%x)  hits: %d' % (cs, fs, fe, fe - fs, len(hits)))
    for off, s in hits:
        print('    0x%06x  %s' % (off, s))
