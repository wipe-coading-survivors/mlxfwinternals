# НЕ в scripts/s1/archive/: import-зависимость build_s1_v4e.py (import dec2);
# без него v4e-билдер не исполняется. Мемо:
# docs/superpowers/memos/2026-09-24-s1-script-archive.md
import struct

def R(x): return 'zero' if x==0 else ('r%d'%x)

def s14(v): return v-0x4000 if v&0x2000 else v
def s16(v): return v-0x10000 if v&0x8000 else v
def s24(v): return v-0x1000000 if v&0x800000 else v

def dis(w, pc):
    op = w>>26
    rd=(w>>16)&0x1f; rs=(w>>21)&0x1f; rt=(w>>11)&0x1f
    imm16=w&0xffff
    if op in (0x00,0x01):
        return 'addi %s,%s,0x%x'%(R(rd),R(rs),s16(imm16))
    if op in (0x02,0x03):
        return 'addi.hi %s,%s,0x%x'%(R(rd),R(rs),s16(imm16))
    if op==0x04: return 'subi %s,%s,0x%x'%(R(rd),R(rs),s16(imm16))
    if op==0x05: return 'subsi %s,%s,0x%x'%(R(rd),R(rs),s16(imm16))
    if op==0x06: return 'set0 %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x07: return 'set1 %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x08: return 'set3 %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x09: return 'set2 %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x0a: return 'and %s,%s,0x%x'%(R(rd),R(rs),s16(imm16))
    if op==0x0b: return 'ands %s,%s,0x%x'%(R(rd),R(rs),s16(imm16))
    if op==0x0c: return 'or %s,%s,0x%x'%(R(rd),R(rs),imm16)
    if op==0x0e: return 'xor %s,%s,0x%x'%(R(rd),R(rs),s16(imm16))
    if op==0x12:
        if (w>>25)&1: return 'ld.i %s,0x%x'%(R(rd),imm16)
        return 'csr.r %s,csr0x%x'%(R(rd),imm16&0x7ff)
    if op==0x13:
        cf=(w>>16)&0x1f
        if cf==0x1b: return 'st.i %s,0x%x'%(R(rs),w&0x7ff)
        return 'csr.w.%02x %s,%s,0x%x'%(cf,R(rs),R(rt),w&0x7ff)
    if op==0x17:
        f=(w>>2)&0x3fff
        if (w>>1)&1: return 'ld.d.17 %s,%s,0x%x'%(R(rd),R(rs),s14(f)*4)
        return 'ld.q.17 %s,%s,0x%x'%(R(rd),R(rs),s14(f)*4)
    if op==0x18:
        return 'ld.b %s,%s,0x%x'%(R(rd),R(rs),s16(imm16))
    if op==0x19:
        f=(w>>2)&0x3fff
        if w&1: return 'ld.w %s,%s,0x%x'%(R(rd),R(rs),s14(f)*2)
        if w&2: return 'ld.d %s,%s,0x%x'%(R(rd),R(rs),s14(f)*4)
        return 'ld.q %s,%s,0x%x'%(R(rd),R(rs),s14(f)*4)
    if op in (0x1a,0x1b,0x1c,0x1e):
        hi_u=(w>>16)&0x1f; lo=(w>>2)&0x1ff
        off14 = s14((hi_u<<9)|lo)
        if op==0x1a: return 'st.b %s,%s,0x%x'%(R(rs),R(rt),off14)
        if op==0x1b:
            if w&1: return 'st.w %s,%s,0x%x'%(R(rs),R(rt),off14*2)
            if w&2: return 'st.d %s,%s,0x%x'%(R(rs),R(rt),off14*4)
            return 'st.q %s,%s,0x%x'%(R(rs),R(rt),off14*4)
        if op==0x1c:
            if w&1: return 'st.w! %s,%s,0x%x'%(R(rs),R(rt),off14*2)
            if w&2: return 'st.d! %s,%s,0x%x'%(R(rs),R(rt),off14*4)
            return 'st.q! %s,%s,0x%x'%(R(rs),R(rt),off14*4)
        if op==0x1e:
            if w&2: return 'st.d.1e %s,%s,0x%x'%(R(rs),R(rt),off14*4)
            return 'st.q.1e %s,%s,0x%x'%(R(rs),R(rt),off14*4)
    if op==0x25:
        o=s24(w&0xffffff); tgt=pc+o*4
        return ('jump 0x%06x'%tgt) if (w>>24)&1 else ('call 0x%06x'%tgt)
    if op in (0x28,0x29):
        o=s16(imm16); tgt=(pc+4)+o*4; cc=(w>>16)&0x1f
        return 'b.%s.%02x %s,0x%06x'%('t' if op==0x28 else 'f',cc,R(rs),tgt)
    if op in (0x2a,0x2b):
        o=s16(imm16); tgt=(pc+4)+o*4; sh=(w>>16)&0x1f
        return 'b.b%s %d,%s,0x%06x'%('set' if op==0x2a else 'clr',sh,R(rs),tgt)
    if op==0x32: return 'mask32 %s,%s,0x%x,%d'%(R(rd),R(rs),(w>>11)&0x1f,w&0x1f)
    if op==0x3f:
        f=w&0x1ff
        m={0:'add',1:'adds',4:'sub',5:'subs',8:'or',10:'and',11:'ands',14:'xor',
           0x19:'lw.r',0x2d:'ret.d',0x80:'shl64.r',0x81:'shl64.i',
           0x83:'shr',0x8a:'shr',0x8b:'shrh'}
        if f==0x25:
            if rd==0 and rs==0: return 'jalr [r%d]'%rt
            if rs==8 and rt==3: return 'STDRET (return [r3])'
            return 'ret.r goto[r%d]'%rt
        if f in m:
            if f in (0x81,0x83,0x8a,0x8b): return '%s %s,%s,0x%x'%(m[f],R(rd),R(rs),(w>>11)&0x1f)
            return '%s %s,%s,%s'%(m[f],R(rd),R(rs),R(rt))
        return 'alu.0x%x %s,%s,%s'%(f,R(rd),R(rs),R(rt))
    return 'op0x%02x %s,%s,%s imm=0x%04x'%(op,R(rd),R(rs),R(rt),imm16)
