#!/usr/bin/env python3
"""Context snippets for top unknown ops, with CORRECTED formatting:
- branch/call/jump targets: tgt = PC + o*4 (Ghidra-verified, no +4)
- store offsets: STOREOFF14/16 = (bits16-20 << 11) | (bits lo << N)  (slaspec, dis.py is wrong here)
"""
import sys, struct, collections
sys.path.insert(0,'/tmp/opencode/irisc')
from recount_codehist import load, classify, KNOWN30

def R(x): return 'zero' if x==0 else 'r%d'%x
def s16(v): return v if v<0x8000 else v-0x10000
def fmt(w, off):
    op=w>>26; rd=(w>>16)&0x1f; rs=(w>>21)&0x1f; rt=(w>>11)&0x1f; imm16=w&0xffff
    so14=(((w>>16)&0x1f)<<11)|(((w>>2)&0x1ff)<<2)   # storeoff14
    so16=(((w>>16)&0x1f)<<11)|(w&0x7ff)             # storeoff16
    off14=(w>>2)&0x3fff
    if off14&0x2000: off14-=0x4000
    if op in (0x00,0x01): return 'addi %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op in (0x02,0x03): return 'addi.hi %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x04: return 'subi %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x05: return 'subsi %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x06: return 'set0 %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x07: return 'set1 %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x08: return 'set3 %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x09: return 'set2 %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x0a: return 'and %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x0b: return 'ands %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x0c: return 'or %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x0e: return 'xor %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x12:
        if (w>>25)&1: return 'ld.i %s,0x%x'%(R(rd),imm16)
        return 'csr.r %s,csr0x%x%s'%(R(rd),imm16&0x7ff,' (retaddr)' if (imm16&0x7ff)==0xbc else '')
    if op==0x13:
        if ((w>>16)&0x1f)==0x1b: return 'st.i %s,0x%x'%(R(rs),w&0x7ff)
        return 'csr.w %s,%s,0x%x%s'%(R(rs),R(rt),w&0x7ff,' (retaddr)' if (w&0x7ff)==0xbc else '')
    if op==0x17: return 'ld.%s.17 %s,%s,0x%x'%('d' if (w>>1)&1 else 'q',R(rd),R(rs),off14<<2&0xffff)
    if op==0x18: return 'ld.b %s,%s,%#x'%(R(rd),R(rs),s16(imm16))
    if op==0x19:
        if w&1: return 'ld.w %s,%s,0x%x'%(R(rd),R(rs),((w>>1)&0x7fff)<<1)
        if w&2: return 'ld.d %s,%s,0x%x'%(R(rd),R(rs),off14<<2)
        return 'ld.q %s,%s,0x%x'%(R(rd),R(rs),off14<<2)
    if op==0x1a: return 'st.b %s,%s,0x%x'%(R(rt),R(rs),so16)
    if op==0x1b:
        if w&1: return 'st.w %s,%s,0x%x'%(R(rs),R(rt),(((w>>1)&0x7fff)<<1))
        if w&2: return 'st.d %s,%s,0x%x'%(R(rs),R(rt),so14)
        return 'st.q %s,%s,0x%x'%(R(rs),R(rt),so14)
    if op==0x1c:
        if w&1: return 'st.w! %s,%s,0x%x'%(R(rs),R(rt),((w>>1)&0x7fff)<<1)
        if w&2: return 'st.d! %s,%s,0x%x'%(R(rs),R(rt),so14)
        return 'st.q! %s,%s,0x%x'%(R(rs),R(rt),so14)
    if op==0x1e:
        if w&2: return 'st.d.1e %s,%s,0x%x'%(R(rs),R(rt),so14)
        return 'st.q.1e %s,%s,0x%x'%(R(rs),R(rt),so14)
    if op==0x25:
        o=w&0xffffff
        if o&0x800000: o-=0x1000000
        return '%s 0x%08x'%('jump' if (w>>24)&1 else 'call', off+o*4)
    if op in (0x28,0x29):
        o=w&0xffff
        if o&0x8000: o-=0x10000
        return 'b.%s.0x%x %s,0x%08x'%('t' if op==0x28 else 'f',(w>>21)&0x1f,R(rs),off+o*4)
    if op in (0x2a,0x2b):
        o=w&0xffff
        if o&0x8000: o-=0x10000
        return 'b.b%s %d,%s,0x%08x'%('set' if op==0x2a else 'clr',(w>>16)&0x1f,R(rs),off+o*4)
    if op==0x32: return 'mask32 %s,%s,0x%x,%d'%(R(rd),R(rs),(w>>11)&0x1f,w&0x1f)
    if op==0x3f:
        f=w&0x1ff
        m={0:'add',1:'adds',4:'sub',5:'subs',8:'or',10:'and',11:'ands',14:'xor',
           0x18:'lw.r.zx',0x19:'lw.r',0x25:'ret.r/jalr',0x2d:'ret.d',
           0x80:'shl64.r',0x81:'shl64.i',0x83:'shr',0x8a:'shr',0x8b:'shrh'}
        if f in m: return '%s %s,%s,%s'%(m[f],R(rd),R(rs),R(rt))
        return 'alu.0x%x %s,%s,%s'%(f,R(rd),R(rs),R(rt))
    return 'op0x%02x %s,%s,%s imm=0x%04x'%(op,R(rd),R(rs),R(rt),imm16)

if __name__=='__main__':
    buf, words, n = load()
    feat, ops, code, cover, votes, wstats = classify(words, n)
    cf=[1 if f[3] else 0 for f in feat]
    def lk(i): return sum(1 for j in range(max(0,i-8),min(n,i+9)) if j!=i and ops[j] in KNOWN30)/16
    def cfnear(i): return any(cf[j] for j in range(max(0,i-8),min(n,i+9)))
    TOPS=[0x36,0x0d,0x33,0x34,0x16]
    NSNIP=int(sys.argv[1]) if len(sys.argv)>1 else 4
    for o in TOPS:
        L=[i for i in range(n) if ops[i]==o and code[i] and lk(i)>=0.9 and cfnear(i)]
        # spread: pick from different 64KB zones
        zones={}
        for i in L: zones.setdefault(i*4>>16,[]).append(i)
        picked=[]
        for z in sorted(zones, key=lambda z:-len(zones[z])):
            for i in zones[z]:
                if all(abs(i*4-p*4)>0x800 for p in picked):
                    picked.append(i); break
            if len(picked)>=NSNIP: break
        print('===== op 0x%02x (%d mask occ, %d strict) ====='%(o,sum(1 for i in range(n) if ops[i]==o and code[i]),len([i for i in range(n) if ops[i]==o and code[i] and lk(i)>=0.75 and cfnear(i)])))
        for i in picked[:NSNIP]:
            for j in range(max(0,i-5),min(n,i+6)):
                mark='>>' if j==i else '  '
                print('%s%08x %08x  %s'%(mark,j*4,words[j],fmt(words[j],j*4)))
            print()
