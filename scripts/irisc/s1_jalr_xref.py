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

def is_jalr(w):
    return (w >> 26) == 0x3F and (w & 0x1FF) == 0x25 and (w >> 16) & 0x1F == 0 and (w >> 21) & 0x1F == 0

def is_op16(w):
    op = w >> 26
    f = w & 0x1FF
    sh = (w >> 11) & 0x1F
    if op == 0x3F and f in (0x83, 0x8A) and sh == 0x10:
        return True
    if op == 0x32 and sh == 0x10:
        return True
    return False

def is_add(w):
    return (w >> 26) == 0x3F and (w & 0x1FF) == 0x00

def is_ld_f0(w):
    return (w >> 26) == 0x19 and (w & 2) and ((w >> 2) & 0x3FFF) == 0  # ld.d F=0

jalrs = []
for i in range(n):
    if is_jalr(words[i]):
        jalrs.append(i * 4)

print('total jalr:', len(jalrs))
print()
print('== jalr with: op16-extract in same fn AND (add or ld.d F=0) within 12 instr before jalr ==')
for j in jalrs:
    jwi = j // 4
    fs = func_start(j)
    fsi = fs // 4
    k = bisect.bisect_left(plist, fs) + 1
    fe = plist[k] if k < len(plist) else n * 4
    fe = min(fe, fs + 0x4000)
    has_op16 = any(is_op16(words[i]) for i in range(fsi, fe // 4))
    if not has_op16:
        continue
    pre = [i for i in range(max(fsi, jwi - 12), jwi)
           if is_add(words[i]) or is_ld_f0(words[i])]
    if pre:
        print('jalr 0x%06x  fn 0x%06x  pre-adds/ldF0: %s' % (j, fs, ['0x%06x' % (i*4) for i in pre]))
