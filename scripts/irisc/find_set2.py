import struct, sys
BIN=sys.argv[1]; hi=int(sys.argv[2],0)
data=open(BIN,'rb').read()
n=len(data)//4
hits=[]
for i in range(n-1):
    w=struct.unpack_from('>I',data,i*4)[0]
    op=w>>26; rs=(w>>21)&0x1f; rd=(w>>16)&0x1f; imm=w&0xffff
    if op==0x09 and rs==0 and imm==hi:   # set2 rd, zero, hi
        w2=struct.unpack_from('>I',data,(i+1)*4)[0]
        op2=w2>>26; rd2=(w2>>16)&0x1f; rs2=(w2>>21)&0x1f
        lo=w2&0xffff
        ok = (op2==0x08 and rd2==rd and rs2==rd)
        hits.append((i*4, rd, lo, ok))
for (off,rd,lo,ok) in hits:
    print("0x%06x  set2 r%d,zero,0x%04x ; set3 r%d,r%d,0x%04x %s => 0x%04x%04x"%(
        off,rd,hi,rd,rd,lo,"(pair)" if ok else "(lo-mismatch)",hi,lo))
print("count:",len(hits))
