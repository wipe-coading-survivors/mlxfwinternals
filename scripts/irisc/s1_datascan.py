import struct, sys

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4
words = [struct.unpack_from('>I', data, i * 4)[0] for i in range(n)]

# 1) data-region scan for BE32 == handler address (and +0x800000 variant)
HANDLERS = [0x0b0260, 0x0b13c0, 0x0b4258, 0x0b4780, 0x0b59cc, 0x0e2cf8,
            0x160f18, 0x1617c4, 0x1697cc, 0x2e6d00, 0x31b328, 0x32faac,
            0x0a0830, 0x0afd20, 0x091534, 0x198ffc, 0x088cb0]
need = {}
for h in HANDLERS:
    need[h] = 'H'
    need[h + 0x800000] = 'H+0x800000'

print('== data scan: BE32 == handler addr (any region, report region) ==')
for i, w in enumerate(words):
    if w in need:
        print('  0x%06x = 0x%08x (%s)' % (i * 4, w, need[w]))

# 2) opcode constant 0x0932: any instruction with imm16 == 0x932
print()
print('== imm16 == 0x932 anywhere ==')
cnt = 0
for i, w in enumerate(words):
    if (w & 0xFFFF) == 0x932:
        op = w >> 26
        print('  0x%06x  word=0x%08x  op=0x%02x' % (i * 4, w, op))
        cnt += 1
print('count:', cnt)

# 3) also 0x0930 (class base) imm16
print()
print('== imm16 == 0x930 anywhere ==')
cnt = 0
for i, w in enumerate(words):
    if (w & 0xFFFF) == 0x930:
        op = w >> 26
        print('  0x%06x  word=0x%08x  op=0x%02x' % (i * 4, w, op))
        cnt += 1
print('count:', cnt)
