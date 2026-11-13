import struct, sys

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4
words = [struct.unpack_from('>I', data, i * 4)[0] for i in range(n)]

HANDLERS = [0x0b0260, 0x0b13c0, 0x0b4258, 0x0b4780, 0x0b59cc, 0x0e2cf8,
            0x160f18, 0x1617c4, 0x1697cc, 0x2e6d00, 0x31b328, 0x32faac,
            0x0a0830, 0x0afd20, 0x0d3cf4, 0x0d3a0c]
pairs = {}
for h in HANDLERS:
    hi = (h >> 16) & 0xFFFF
    lo = h & 0xFFFF
    pairs[(hi, lo)] = h

print('== addi.hi(imm=HI) then set3(same rd, imm=LO) within 4 words ==')
for i in range(n - 4):
    w1 = words[i]
    if (w1 >> 26) in (0x02, 0x03):
        hi = w1 & 0xFFFF
        rd = (w1 >> 16) & 0x1F
        for d in range(1, 5):
            w2 = words[i + d]
            if (w2 >> 26) == 0x08 and (w2 >> 21) & 0x1F == rd:
                lo = w2 & 0xFFFF
                key = (hi, lo)
                if key in pairs:
                    print('  addr 0x%06x built at 0x%06x (addi.hi) +0x%x (set3)' %
                          (pairs[key], i * 4, d * 4))

# also: set3 with imm=LO preceded by addi.hi HI in previous 1..4 (reverse order less likely)
print()
print('== ld.i / addi with 16-bit == 0x0932-ish opcode immediates in data? (skip) ==')
