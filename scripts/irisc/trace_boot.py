import struct, sys
BIN=sys.argv[1]
data=open(BIN,'rb').read()
def w_at(off):
    if off<0 or off+4>len(data): return None
    return struct.unpack_from('>I',data,off)[0]

def s24(v): return v if v<0x800000 else v-0x1000000
def s16(v): return v if v<0x8000 else v-0x10000

# classify control-flow instructions, return (kind, target) or None
def cf(off):
    w=w_at(off)
    if w is None: return None
    op=w>>26
    if op==0x25:
        tgt=(off+4)+s24(w&0xffffff)*4
        return ('jump' if (w>>24)&1 else 'call', tgt)
    if op in (0x28,0x29):
        tgt=(off+4)+s16(w&0xffff)*4
        return ('b.t' if op==0x28 else 'b.f', tgt)
    if op in (0x2a,0x2b):
        tgt=(off+4)+s16(w&0xffff)*4
        return ('b.bset' if op==0x2a else 'b.bclr', tgt)
    # ret.d / jalr = fallout
    if op==0x3f and (w&0x1ff) in (0x25,0x2d):
        return ('ret', None)
    return None

# disassemble a linear run from 'start' until we hit a terminal (ret/jump) or max words,
# collecting control-flow edges.
def scan_run(start, maxw=400):
    edges=[]
    for i in range(maxw):
        off=start+i*4
        c=cf(off)
        if c:
            edges.append((off,c[0],c[1]))
            if c[0] in ('ret','jump'):
                # jump = end of run (terminal); ret = end
                break
    return edges

seen=set()
order=[]
def trace(start, depth=0, maxdepth=6):
    if start in seen or depth>maxdepth: return
    seen.add(start); order.append((depth,start))
    edges=scan_run(start)
    for (off,kind,tgt) in edges:
        if kind=='call':
            trace(tgt, depth+1, maxdepth)
        # also note jumps as fallthrough targets (linear)

# Start from entry
ENTRY=0x1d58c
trace(ENTRY,0,7)
print("== boot call tree (BFS order, depth, addr) ==")
for (depth,a) in order:
    print("%s0x%06x"%( "  "*depth, a))
