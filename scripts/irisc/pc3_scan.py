import struct, sys
from collections import defaultdict

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4

def s16(v):
    return v if v < 0x8000 else v - 0x10000

cands = defaultdict(set)  # word_idx -> set of (kind, off)
solid = defaultdict(set)  # word_idx -> set of (kind, off), base-zero только
bases = defaultdict(list)  # base_value(32b) -> [off] где построена

def add(wi, kind, off, is_solid=True):
    cands[wi & 0xFFFF].add((kind, off))
    if is_solid:
        solid[wi & 0xFFFF].add((kind, off))

for i in range(n):
    w = struct.unpack_from('>I', data, i * 4)[0]
    off = i * 4
    op = w >> 26
    rd = (w >> 16) & 0x1F
    rs = (w >> 21) & 0x1F
    imm16 = w & 0xFFFF

    # --- direct absolute (base-zero) loads/stores ---
    if op == 0x12 and (w >> 25) & 1:
        add(imm16, 'ld.i', off)                      # ld.i rd,imm16: word idx = imm16
    elif op == 0x19 and rs == 0:
        b = (w >> 2) & 0x3FFF
        if w & 1:
            add(b, 'ld.w', off)
        elif w & 2:
            add(b, 'ld.d', off); add(b + 1, 'ld.d+1', off)
        else:
            for k in range(4):
                add(b + k, 'ld.q+%d' % k, off)
    elif op == 0x18 and rs == 0:
        o = s16(imm16)
        if o >= 0 and o % 4 == 0:
            add(o // 4, 'ld.b', off)
    elif op == 0x17 and rs == 0:
        b = (w >> 2) & 0x3FFF
        if (w >> 1) & 1:
            add(b, 'ld.d.17', off); add(b + 1, 'ld.d.17+1', off)
        else:
            for k in range(4):
                add(b + k, 'ld.q.17+%d' % k, off)
    elif op in (0x1A, 0x1B, 0x1C, 0x1E) and rs == 0:
        b = (w >> 2) & 0x3FFF
        nm = {0x1A: 'st.b', 0x1B: 'st.wdq', 0x1C: 'st.wdq!', 0x1E: 'st.dq.1e'}[op]
        if op == 0x1A:
            add(b, nm, off)
        elif op in (0x1B, 0x1C):
            if w & 1:
                add(b, nm + '.w', off)
            elif w & 2:
                add(b, nm + '.d', off); add(b + 1, nm + '.d+1', off)
            else:
                for k in range(4):
                    add(b + k, nm + '.q+%d' % k, off)
        else:
            if w & 2:
                add(b, nm + '.d', off); add(b + 1, nm + '.d+1', off)
            else:
                for k in range(4):
                    add(b + k, nm + '.q+%d' % k, off)

# --- dataflow: set0/set1/set2/set3 + addi → base; then ld/st base+off14 ---
reg = {}
MASK = {0x06: (0xFFFF, 48), 0x07: (0xFFFF, 32), 0x09: (0xFFFF, 16), 0x08: (0xFFFF, 0)}

def clear(rd):
    reg.pop(rd, None)

for i in range(n):
    w = struct.unpack_from('>I', data, i * 4)[0]
    off = i * 4
    op = w >> 26
    rd = (w >> 16) & 0x1F
    rs = (w >> 21) & 0x1F
    imm16 = w & 0xFFFF
    handled_rd = False

    if op in MASK:  # set0/set1/set2/set3
        m, sh = MASK[op]
        if rs == 0:
            reg[rd] = (imm16 & m) << sh
            handled_rd = True
        elif rs in reg:
            v = reg[rs]
            reg[rd] = (v & ~(m << sh)) | ((imm16 & m) << sh)
            handled_rd = True
        else:
            clear(rd)
    elif op in (0x00, 0x01):  # addi
        if rs == 0:
            reg[rd] = imm16 & 0xFFFF
            handled_rd = True
        elif rs in reg and imm16 < 0x8000:
            reg[rd] = (reg[rs] + imm16) & 0xFFFFFFFF
            handled_rd = True
        else:
            clear(rd)
    else:
        clear(rd)

    # resolve base+off loads/stores
    if rs != 0 and rs in reg and op in (0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1E):
        base = reg[rs] & 0xFFFFFFFF
        bases[base].append(off)
        if op == 0x18:
            o = s16(imm16)
            if o >= 0 and o % 4 == 0:
                add((base + o // 4), 'ld.b(base)', off, False)
        else:
            b = (w >> 2) & 0x3FFF
            if op in (0x1B, 0x1C) or (op == 0x1E and (w & 2)):
                add(base + b, 'st.d(base)', off, False); add(base + b + 1, 'st.d(base)+1', off, False)
            elif op == 0x1B and (w & 1):
                add(base + b, 'st.w(base)', off, False)
            elif op == 0x1A:
                add(base + b, 'st.b(base)', off, False)
            elif op == 0x17 and ((w >> 1) & 1):
                add(base + b, 'ld.d.17(base)', off, False); add(base + b + 1, 'ld.d.17(base)+1', off, False)
            else:
                add(base + b, 'ld?(base)', off, False); add(base + b + 1, 'ld?(base)+1', off, False)

    if op in (0x02, 0x03, 0x04, 0x05) and not handled_rd:
        pass  # addi.hi/subi/subsi: rd зависит от rs+shift — не трекаем (clear уже сделан)

# --- report ---
print('== distinct word-idx touched by absolute ld/st (base-zero + resolved base) ==')
print('total distinct word-idx:', len(cands))
hi = {k: v for k, v in cands.items() if k > 0x7FF}
lo = {k: v for k, v in cands.items() if k <= 0x7FF}
print('word-idx > 0x7ff (data-channel eligible):', len(hi))
print('word-idx <= 0x7ff (st.i-reachable):', len(lo))
print()
print('== candidates > 0x7ff: word-idx / CR-offset / evidence ==')
for k in sorted(hi):
    ev = hi[k]
    kinds = sorted(set(e[0] for e in ev))
    offs = sorted(e[1] for e in ev)
    print('0x%04x  CR 0x%05x  x%-3d %-28s first=0x%06x' % (k, 4 * k, len(offs), ','.join(kinds[:3]), offs[0]))
print()
shis = {k for k in hi if k in solid}
slos = {k for k in lo if k in solid}
print('== solid (base-zero) subset ==')
print('solid > 0x7ff:', len(shis), ' solid <= 0x7ff:', len(slos))
print()
print('== block histogram (0x100-word blocks) > 0x7ff: all vs solid ==')
blk = defaultdict(lambda: [0, 0])
for k in hi:
    blk[k >> 8][0] += 1
for k in shis:
    blk[k >> 8][1] += 1
for b in sorted(blk):
    a, s = blk[b]
    print('block 0x%05x-0x%05x  all=%-4d solid=%-4d' % (b << 8, (b << 8) + 0xFF, a, s))
print()
print('== compact candidate lists (for live probe) ==')
print('ALL_HI=' + ','.join('%04x' % k for k in sorted(hi)))
print()
print('SOLID_HI=' + ','.join('%04x' % k for k in sorted(shis)))
print()
print('== constructed 32-bit bases (set2/set3 chains), top by use ==')
for b, offs in sorted(bases.items(), key=lambda kv: -len(kv[1]))[:40]:
    print('base 0x%08x  x%-5d first=0x%06x' % (b, len(offs), offs[0]))
print('distinct bases:', len(bases))
