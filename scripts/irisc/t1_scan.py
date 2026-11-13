import struct, sys, bisect

BIN = sys.argv[1]
data = open(BIN, 'rb').read()
n = len(data) // 4
words = [struct.unpack_from('>I', data, i*4)[0] for i in range(n)]

def s24(v): return v - 0x1000000 if v & 0x800000 else v

PROLOG = []
STDR = []
OP25 = []   # (off, tgt, is_jump)
for i in range(n):
    w = words[i]
    off = i*4
    op = w >> 26
    if op == 0x12 and not ((w>>25)&1) and ((w>>16)&0x1F)==3 and (w&0x7FF)==0xBC:
        PROLOG.append(off)
    elif op == 0x3f and (w & 0x1FF) == 0x25:
        rd=(w>>16)&0x1F; rs=(w>>21)&0x1F; rt=(w>>11)&0x1F
        if rd==0 and rs==8 and rt==3:
            STDR.append(off)
    elif op == 0x25:
        tgt = off + s24(w & 0xFFFFFF)*4
        OP25.append((off, tgt, bool((w>>24)&1)))

print('prologues:', len(PROLOG), ' stdret:', len(STDR), ' op25:', len(OP25))

# pairing: segment [p_k, p_{k+1})
starts = PROLOG
funcs = []  # dict(start, end, nstd)
for k, p in enumerate(starts):
    nxt = starts[k+1] if k+1 < len(starts) else n*4
    i0 = bisect.bisect_left(STDR, p)
    i1 = bisect.bisect_left(STDR, nxt)
    cnt = i1 - i0
    if cnt > 0:
        end = STDR[i1-1] + 4
    else:
        end = nxt
    funcs.append((p, end, cnt))
# sanity: stdret before first prologue
print('stdret before first prologue:', [hex(s) for s in STDR if s < starts[0]])
multi = [f for f in funcs if f[2] > 1]
nostdr = [f for f in funcs if f[2] == 0]
print('segments with >1 stdret:', len(multi))
for p,e,c in multi[:20]: print('   0x%06x..0x%06x nstd=%d' % (p,e,c))
print('segments with 0 stdret:', len(nostdr))
for p,e,c in nostdr[:30]: print('   0x%06x..0x%06x' % (p,e))

fstarts = [f[0] for f in funcs]
def func_of(off):
    k = bisect.bisect_right(fstarts, off) - 1
    if k < 0: return None
    p,e,c = funcs[k]
    if off < e: return (p,e,c)
    return None  # in a gap [end, next prologue)

# call sites of interest
T = {0x090b7c:'respA', 0x090be4:'respB', 0x0d3a0c:'wrapper', 0x0d3cf4:'compl'}
sites = {t: [] for t in T}
for off, tgt, jmp in OP25:
    if tgt in sites:
        sites[tgt].append((off, jmp))
for t, name in T.items():
    print('target 0x%06x (%s): %d sites' % (t, name, len(sites[t])))

# candidate set
W = [0x0b0260,0x0b13c0,0x0b4258,0x0b4780,0x0b59cc,0x0e2cf8,
     0x160f18,0x1617c4,0x1697cc,0x2e6d00,0x31b328,0x32faac]
cand = {}   # start -> (end, tags)
for w in W:
    f = func_of(w)
    if f is None or f[0] != w:
        print('WRAPPER MISMATCH 0x%06x -> %s' % (w, f))
    cand[f[0]] = (f[1], ['W12'])
REG_LO, REG_HI = 0x0ae000, 0x0b8000
for t in (0x090b7c, 0x090be4):
    for off, jmp in sites[t]:
        if REG_LO <= off < REG_HI:
            f = func_of(off)
            if f is None:
                print('REGION CALLSITE 0x%06x (to 0x%06x, jump=%d) NOT IN ANY FUNC' % (off,t,jmp))
                continue
            if f[0] in cand:
                if 'R' not in cand[f[0]][1]: cand[f[0]] = (cand[f[0]][0], cand[f[0]][1]+['R'])
            else:
                cand[f[0]] = (f[1], ['R'])
print()
print('CANDIDATE SET: %d functions' % len(cand))
for p in sorted(cand):
    e, tags = cand[p]
    print('  0x%06x .. 0x%06x  (0x%04x)  %s' % (p, e, e-p, '/'.join(tags)))

# failure check: retaddr of calls (not jumps) to T1/T2/T3
print()
print('FAILURE CHECK (retaddr = site+4 for CALL sites to 0x090b7c/0x090be4/0x0d3a0c):')
cand_starts = set(cand)
nf = 0
for t in (0x090b7c, 0x090be4, 0x0d3a0c):
    for off, jmp in sites[t]:
        if jmp:
            print('  JUMP (no retaddr) @0x%06x -> 0x%06x' % (off,t))
            continue
        ra = off + 4
        f = func_of(ra)
        if f is None:
            print('  FAIL GAP   ra=0x%06x (site 0x%06x -> 0x%06x): in no function (gap)' % (ra,off,t))
            nf += 1
        elif f[0] not in cand_starts:
            print('  FAIL FN    ra=0x%06x (site 0x%06x -> 0x%06x): in fn 0x%06x..0x%06x (NOT candidate)'
                  % (ra,off,t,f[0],f[1]))
            nf += 1
print('total failures: %d' % nf)

# per-candidate: which sites/retaddrs it contains
print()
print('PER-CANDIDATE SITES:')
for p in sorted(cand):
    e = cand[p][0]
    row = []
    for t in (0x090b7c, 0x090be4, 0x0d3a0c, 0x0d3cf4):
        for off, jmp in sites[t]:
            if p <= off < e:
                row.append('0x%06x->0x%06x%s' % (off,t,'j' if jmp else ''))
    if row:
        print('  0x%06x: %s' % (p, ' '.join(row)))
