import struct, sys
BIN=sys.argv[1]
data=open(BIN,'rb').read()
n=len(data)//4
def w_at(i): return struct.unpack_from('>I',data,i*4)[0]

# 1) st.i rX, 0x800  (store to RAM word idx 0x800 = RAM[0x2000]); op=0x13, csrwfunct=0x1b
print("== st.i to RAM[0x2000] (idx 0x800) ==")
cnt=0
for i in range(n):
    w=w_at(i); op=w>>26
    if op==0x13 and ((w>>16)&0x1f)==0x1b and (w&0x7ff)==0x800:
        rt=(w>>11)&0x1f
        print("  0x%06x  st.i r%d, 0x800"%(i*4,rt)); cnt+=1
        if cnt>20: break
print("  (shown up to 20)")

# 2) ld.i / st.i to other interesting RAM idx near 0x800 (0x7ff..0x805) to map the 'control block'
print("== ld.i/st.i around RAM idx 0x7f0..0x810 ==")
from collections import defaultdict
m=defaultdict(list)
for i in range(n):
    w=w_at(i); op=w>>26
    if op==0x12 and ((w>>25)&1)==1:  # ld.i
        idx=w&0xffff
        if 0x7f0<=idx<=0x810: m[('ld',idx)].append(i*4)
    if op==0x13 and ((w>>16)&0x1f)==0x1b:  # st.i
        idx=w&0x7ff
        if 0x7f0<=idx<=0x810: m[('st',idx)].append(i*4)
for k in sorted(m): 
    print("  %s idx 0x%04x  x%d  e.g. 0x%06x"%(k[0],k[1],len(m[k]),m[k][0]))

# 3) free region 0x38d730: check for ld.i/st.i refs into it and any BE32 const pointing near it
print("== free region 0x38d730 (len 0x4b9) sanity ==")
print("  bytes 0x38d730..0x38dbe9 all zero:", all(b==0 for b in data[0x38d730:0x38dbe9]))
