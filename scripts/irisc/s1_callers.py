import struct, sys

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4

TARGETS = [0x0d3a0c, 0x0d3cf4]  # wrapper, and the fn right after it that calls wrapper

def s24(v):
    return v - 0x1000000 if v & 0x800000 else v

calls = {t: [] for t in TARGETS}
jalrs = []
op25_total = 0
op3f_25_rd0rs0 = 0

for i in range(n):
    w = struct.unpack_from('>I', data, i * 4)[0]
    off = i * 4
    op = w >> 26
    rd = (w >> 16) & 0x1F
    rs = (w >> 21) & 0x1F
    if op == 0x25:
        op25_total += 1
        tgt = off + s24(w & 0xFFFFFF) * 4
        jmp = 'jump' if (w >> 24) & 1 else 'call'
        for t in TARGETS:
            if tgt == t:
                calls[t].append((off, jmp))
    elif op == 0x3f:
        f = w & 0x1FF
        if f == 0x25 and rd == 0 and rs == 0:
            jalrs.append(off)

print('total op=0x25 (call/jump):', op25_total)
for t in TARGETS:
    print('target 0x%06x: %d hits' % (t, len(calls[t])))
    for off, jmp in calls[t]:
        print('   0x%06x  %s' % (off, jmp))
print('jalr (op=0x3f f=0x25 rd=0 rs=0):', len(jalrs))
print(','.join('0x%06x' % o for o in jalrs))
