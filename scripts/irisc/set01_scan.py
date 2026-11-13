import struct, sys
from collections import defaultdict
BIN=sys.argv[1]
data=open(BIN,'rb').read()
n=len(data)//4
def w_at(i): return struct.unpack_from('>I',data,i*4)[0]
# set0(0x06)=imm<<48, set1(0x07)=imm<<32. Look for pairs building 64-bit addrs:
# set1 rd,zero,HI32 ; set3 rd,rd,LO32  -> 64-bit
res=defaultdict(list)
for i in range(n-1):
    w=w_at(i); op=w>>26; rd=(w>>16)&0x1f; rs=(w>>21)&0x1f; imm=w&0xffff
    if op==0x07 and rs==0:   # set1 rd, zero, HI
        w2=w_at(i+1); op2=w2>>26; rd2=(w2>>16)&0x1f; rs2=(w2>>21)&0x1f
        if op2==0x08 and rd2==rd and rs2==rd:  # set3 rd, rd, LO
            lo=w2&0xffff
            val=((imm)<<32)|lo
            if val>0: res[val].append(i*4)
print("== 64-bit addr via set1,zero,HI ; set3,rd,LO (top 40) ==")
for val,offs in sorted(res.items(),key=lambda kv:-len(kv[1]))[:40]:
    print("0x%016x  x%-5d first=0x%06x"%(val,len(offs),offs[0]))
print("distinct:",len(res))
