import struct, sys
BIN=sys.argv[1]
data=open(BIN,'rb').read()
n=len(data)//4
def w_at(i): return struct.unpack_from('>I',data,i*4)[0]

# Decode set2/set3/set1/set0/addi.hi to find 64-bit address constructions.
# set0(0x06): imm<<48 ; set1(0x07): imm<<32 ; set2(0x09): imm<<16 ; set3(0x08): imm<<0
# We look for "base building" sequences: set2 rd,zero,HI  then set3 rd,rd,LO  (=> 32-bit addr in rd)
# Also addi.hi (0x02/0x03): rd = rs + (simm16<<16)
from collections import defaultdict
addrs=defaultdict(list)   # value -> [offsets]
for i in range(n):
    w=w_at(i); off=i*4
    op=w>>26; rd=(w>>16)&0x1f; rs=(w>>21)&0x1f; imm16=w&0xffff
    if op in (0x06,0x07,0x08,0x09) and rs==0:
        # rd = imm16 shifted; record the partial
        pass
    # detect pair: set2 rd,zero,HI at i, set3 rd,rd,LO at i+1
    if op==0x09 and rs==0:
        hi=imm16
        # next word
        if i+1<n:
            w2=w_at(i+1); op2=w2>>26; rd2=(w2>>16)&0x1f; rs2=(w2>>21)&0x1f
            if op2==0x08 and rd2==rd and rs2==rd:
                lo=w2&0xffff
                val=(hi<<16)|lo
                if val>=0x40000:   # >= 256KB, likely a base not a small const
                    addrs[val].append(off)
# report distinct constructed addresses with counts
print("== 32-bit address constructions (set2,zero,HI; set3,rd,LO), val>=0x40000 ==")
items=sorted(addrs.items(), key=lambda kv:-len(kv[1]))
for val,offs in items[:60]:
    print("0x%08x  x%-5d first=0x%06x"%(val,len(offs),offs[0]))
print("total distinct:",len(items))
