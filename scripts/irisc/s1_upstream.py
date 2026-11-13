import struct, sys

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4

HANDLERS = [0x0b0260, 0x0b13c0, 0x0b4258, 0x0b4780, 0x0b59cc, 0x0e2cf8,
            0x160f18, 0x1617c4, 0x1697cc, 0x2e6d00, 0x31b328, 0x32faac,
            0x0a0830, 0x0afd20]  # + known anchors F_T, F_C

def s24(v):
    return v - 0x1000000 if v & 0x800000 else v

hits = {t: [] for t in HANDLERS}
for i in range(n):
    w = struct.unpack_from('>I', data, i * 4)[0]
    off = i * 4
    if (w >> 26) == 0x25:
        tgt = off + s24(w & 0xFFFFFF) * 4
        jmp = 'jump' if (w >> 24) & 1 else 'call'
        if tgt in hits:
            hits[tgt].append((off, jmp))

for t in HANDLERS:
    h = hits[t]
    print('0x%06x: %d direct refs' % (t, len(h)))
    for off, jmp in h:
        print('    0x%06x  %s' % (off, jmp))
