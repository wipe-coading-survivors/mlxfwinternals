import struct, sys

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4
words = [struct.unpack_from('>I', data, i * 4)[0] for i in range(n)]

CALLSITES = [0x0b0970, 0x0b16d0, 0x0b43c4, 0x0b48dc, 0x0b6078, 0x0e2e84,
             0x16101c, 0x161940, 0x169dc8, 0x2e7018, 0x31b41c, 0x32fbf0]

# prologue: csr.r r3,csr0xbc  -> op=0x12, bit25=0, rd=3, imm11=0xbc
prologues = set()
for i in range(n):
    w = words[i]
    if (w >> 26) == 0x12 and (w >> 25) & 1 == 0 and (w >> 16) & 0x1F == 3 and (w & 0x7FF) == 0xBC:
        prologues.add(i * 4)
import bisect
plist = sorted(prologues)
print('prologue candidates (csr.r r3,csr0xbc):', len(plist))

def func_start(off):
    idx = bisect.bisect_right(plist, off) - 1
    return plist[idx] if idx >= 0 else None

def sig(w):
    op = w >> 26
    f = w & 0x1FF
    rd = (w >> 16) & 0x1F
    rs = (w >> 21) & 0x1F
    shamt = (w >> 11) & 0x1F
    if op == 0x3f and f == 0x25 and rd == 0 and rs == 0:
        return 'jalr r%d' % ((w >> 11) & 0x1F)
    if op == 0x3f and f in (0x83, 0x8A) and shamt == 0x10:
        return 'shr 0x10'
    if op == 0x32 and shamt == 16:
        return 'mask32 shift=16'
    off14 = (w >> 2) & 0x3FFF
    if op in (0x17, 0x18, 0x19) and off14 == 0x20:
        return 'ld off=0x20'
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
    print('callsite 0x%06x -> fn 0x%06x .. 0x%06x (size 0x%x)  sig-hits: %d' % (cs, fs, fe, fe - fs, len(hits)))
    for off, s in hits[:20]:
        print('    0x%06x  %s' % (off, s))
