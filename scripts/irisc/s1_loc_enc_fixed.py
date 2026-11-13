import os, struct
BIN=os.path.expanduser('~/git/IMPLEMENTATION/mlxini/build/ghidra-4030cda-main03-ac-dc.bin')
buf=open(BIN,'rb').read()
W=lambda o: struct.unpack_from('>I',buf,o)[0]

# ---------- encoders (verified against iRISC.slaspec + binary) ----------
def addi(rd,rs,imm):  return (0x00<<26)|(rs<<21)|(rd<<16)|(imm&0xffff)
def subsi(rd,rs,imm): return (0x05<<26)|(rs<<21)|(rd<<16)|(imm&0xffff)
def set2(rd,rs,imm):  return (0x09<<26)|(rs<<21)|(rd<<16)|(imm&0xffff)
def set3(rd,rs,imm):  return (0x08<<26)|(rs<<21)|(rd<<16)|(imm&0xffff)
def orr(rd,rs,imm):   return (0x0c<<26)|(rs<<21)|(rd<<16)|(imm&0xffff)
def or3(rd,rs,rt):    return (0x3f<<26)|(rd<<16)|(rs<<21)|(rt<<11)|0x08
def subs(rd,rs,rt):   return (0x3f<<26)|(rd<<16)|(rs<<21)|(rt<<11)|0x05
def shr(rd,rs,sh):    return (0x3f<<26)|(rd<<16)|(rs<<21)|(sh<<11)|0x83
def shl64i(rd,rs,sh): return (0x3f<<26)|(rd<<16)|(rs<<21)|(sh<<11)|0x81
def ld_d(rd,rs,F):    return (0x19<<26)|(rs<<21)|(rd<<16)|((F&0x3fff)<<2)|0x2
def st_d(rt,rs,o14):
    v=(o14&0x3fff); hi=(v>>9)&0x1f; lo=v&0x1ff
    return (0x1b<<26)|(rs<<21)|(hi<<16)|(rt<<11)|(lo<<2)|0x2
def st_dl(rt,rs,o14):
    v=(o14&0x3fff); hi=(v>>9)&0x1f; lo=v&0x1ff
    return (0x1c<<26)|(rs<<21)|(hi<<16)|(rt<<11)|(lo<<2)|0x2
def csr_r(rd):        return (0x12<<26)|(rd<<16)|0xbc
def rel24(tgt,pc):
    r=(tgt-pc)//4; assert -0x800000<=r<0x800000, (tgt,pc,r)
    return (r&0xffffff)
def jump(tgt,pc):  return (0x25<<26)|(1<<24)|rel24(tgt,pc)
def rel16(tgt,pc):
    r=(tgt-pc)//4; assert -0x8000<=r<0x8000, (tgt,pc,r)
    return (r&0xffff)
def b_t(cc,tgt,pc):   return (0x28<<26)|(cc<<21)|rel16(tgt,pc+4)
def b_f(cc,tgt,pc):   return (0x29<<26)|(cc<<21)|rel16(tgt,pc+4)
def b_bset(sh,rs,tgt,pc): return (0x2a<<26)|(rs<<21)|(sh<<16)|rel16(tgt,pc+4)
def b_bclr(sh,rs,tgt,pc): return (0x2b<<26)|(rs<<21)|(sh<<16)|rel16(tgt,pc+4)

# ---------- verification pass: re-encode real FW words (same as T2) ----------
print('=== VERIFY: re-encode real binary words ===')
ok=True
def chk(name,got,want):
    global ok
    if got!=want: ok=False
    print('%s %-30s enc=%08x bin=%08x'%('OK ' if got==want else 'FAIL',name,got,want))
for S in (0x090b7c,0x090be4,0x0d3cf4):
    chk('csr.r @%06x'%S, csr_r(3), W(S))
    chk('st.d retaddr @%06x'%(S+4), st_d(3,1,1), W(S+4))
def off14_of(w):
    v=((w>>16)&0x1f)<<9 | ((w>>2)&0x1ff)
    return v-0x4000 if v>=0x2000 else v
for S in (0x090b7c,0x090be4,0x0d3cf4):
    w=W(S+8); o=off14_of(w)
    chk('st.d! frame @%06x (off14=%d)'%(S+8,o), st_dl(1,1,0x4000+o), w)
chk('or @000628', orr(4,4,0x73ff), 0x308473ff)
chk('set2 @000188', set2(5,0,0x0003), W(0x188))
chk('set3 @00018c', set3(5,5,0x92c0), W(0x18c))
chk('b.bset @0000f0', b_bset(30,6,0xf0,0xf0), W(0xf0))
chk('nop @01d588 (stock NOP in FW)', 0x00000000, W(0x01d588))
chk('addi @000034', addi((W(0x34)>>16)&0x1f,(W(0x34)>>21)&0x1f,W(0x34)&0xffff), W(0x34))
for off in range(0,len(buf),4):
    w=W(off)
    if w>>26==0x28 and (w>>21)==0:
        tgt=off+4+(((w&0xffff) if (w&0xffff)<0x8000 else (w&0xffff)-0x10000))*4
        chk('b.t.0x0 @%06x'%off, b_t(0,tgt,off), w); break
for off in range(0,len(buf),4):
    w=W(off)
    if w>>26==0x3f and (w&0x1ff)==0x05:
        chk('subs @%06x'%off, subs((w>>16)&0x1f,(w>>21)&0x1f,(w>>11)&0x1f), w); break
for off in range(0,len(buf),4):
    w=W(off)
    if w>>26==0x05:
        chk('subsi @%06x'%off, subsi((w>>16)&0x1f,(w>>21)&0x1f,w&0xffff), w); break
for off in range(0,len(buf),4):
    w=W(off)
    if w>>26==0x19 and (w&3)==2 and (w>>21)!=0:
        chk('ld.d @%06x'%off, ld_d((w>>16)&0x1f,(w>>21)&0x1f,(w>>2)&0x3fff), w); break
print('verify all ok:', ok)
assert ok

# ---------- build LOC (FIXED variant b: no save/restore, no frame) ----------
# Root cause (RE-confirmed): old locator saved/restored r2/r4-r8/r16-r23 with
# 32-bit st.d/ld.d (ld.d = zext32, slaspec L290-292) -> upper 32 bits of the
# caller's 64-bit args in r4-r8 zeroed -> ALLOC_UAR assert.
# Audit of old 93 words (s1_loc_audit.py): body WRITES only r9-r15 (+r3/r1 in
# the C-tail = re-exec of the site's own 3 original words); r4-r8 read-only;
# r2/r16-r23 untouched. -> save/restore NOT needed at all.
# Changes vs T2:
#   - removed 14x st.d save (was 0x38d750..0x38d784)
#   - removed 14x ld.d restore (was 0x38d850..0x38d884) + addi r1,r1,0x40
#   - L_OP: read r6 DIRECTLY (ld.d r11,r6,0x1c) instead of saved r6 from stack
#     (saves 1 word; old path also read the zext32-truncated copy)
#   - hook word1: st.d! r1,r1,-0x40 -> NOP 0x00000000 (addi zero,zero,0x0,
#     stock FW NOP @0x01d588, docs/250-re/120-irisc/025-boot-injection.md) -> hook stack-neutral
#   - DONE label now on the @bbc2 word (C-tail start)
LOC=0x38d750
NOP=0x00000000
CANDS=[(0x0aed40,0x0aee70),(0x0aee70,0x0aefb0),(0x0aefe4,0x0af218),(0x0b0260,0x0b0be4),
(0x0b13c0,0x0b1b34),(0x0b1fc4,0x0b2f20),(0x0b2f20,0x0b33b0),(0x0b4258,0x0b4470),
(0x0b4780,0x0b49b0),(0x0b49b0,0x0b4b78),(0x0b59cc,0x0b67c4),(0x0b6858,0x0b6924),
(0x0b7298,0x0b73b0),(0x0e2cf8,0x0e3970),(0x160f18,0x16119c),(0x1617c4,0x162340),
(0x1697cc,0x16a820),(0x2e6d00,0x2e7130),(0x31b328,0x31b48c),(0x32faac,0x32fdd4),
(0x0d3cf4,0x0d3fe4)]  # cand20 = utility 0x0d3cf4 (indirect marker)

P=[]
def add(cmt,word): P.append([cmt,word])

add('set2   r14,zero,0x0000', set2(14,0,0x0000))
add('set3   r14,r14,0x2390', set3(14,14,0x2390))
add('ld.d   r12,r14,0      ; flag', ld_d(12,14,0))
add('subsi  r12,r12,0', subsi(12,12,0))
add('@btflag b.t.0x0 zero,DONE', None)
add('csr.r  r10,csr0xbc   ; ra', csr_r(10))
add('or     r11,zero,0     ; op=0(unverified)', orr(11,0,0))
add('@bbid b.bset 1,r9,L_OP', None)
add('@jmap jump L_MAP', None)
add('@L_OP ld.d   r11,r6,0x1c ; [r6+0x70] op (direct r6, no frame)', ld_d(11,6,0x1c))
add('shr    r11,r11,0x16   ; op>>16', shr(11,11,0x16))
add('set2   r12,zero,0x932', set2(12,0,0x932))
add('subs   r12,r12,r11    ; op-0x932', subs(12,12,11))
add('@bfop b.f.0x0 zero,DONE', None)
add('@L_MAP set2  r14,zero,TAB_HI', None)
add('set3   r14,r14,TAB_LO', None)
add('addi   r12,zero,0      ; i=0', addi(12,0,0))
add('@L_LOOP ld.d r13,r14,0  ; start[i]', ld_d(13,14,0))
add('subs   r12,r13,r10     ; ra-start', subs(12,13,10))
add('@bbs1 b.bset 31,r12,L_INC ; ra<start', None)
add('ld.d   r15,r14,1       ; end[i]', ld_d(15,14,1))
add('subs   r12,r15,r10     ; ra-end', subs(12,15,10))
add('@bbc1 b.bclr 31,r12,L_INC ; ra>=end', None)
add('@jhit jump L_HIT', None)
add('@L_INC addi  r14,r14,0x8', addi(14,14,8))
add('addi   r12,r12,0x1', addi(12,12,1))
add('subsi  r12,r12,0x15    ; i-21', subsi(12,12,0x15))
add('@bflp b.f.0x0 zero,L_LOOP  ; i!=21', None)
add('@bbm2 b.bset 1,r9,L_MISS2', None)
add('@jdn2 jump DONE', None)
add('@L_MISS2 set2 r13,r10,0x8000 ; alert', set2(13,10,0x8000))
add('@L_HIT set2  r15,zero,0x0000', set2(15,0,0x0000))
add('set3   r15,r15,0x2380', set3(15,15,0x2380))
add('st.d   r13,r15,0       ; CR 0x2380=h|alert', st_d(13,15,0))
add('st.d   r10,r15,1       ; CR 0x2384=ra', st_d(10,15,1))
add('shl64.i r12,r11,0x10   ; op<<16', shl64i(12,11,0x10))
add('or3    r12,r12,r9      ; |ID', or3(12,12,9))
add('st.d   r12,r15,2       ; CR 0x2388', st_d(12,15,2))
add('set2   r12,zero,0x5331', set2(12,0,0x5331))
add('set3   r12,r12,0x0001', set3(12,12,1))
add('st.d   r12,r15,3       ; CR 0x238c=magic', st_d(12,15,3))
add('@bbna b.bset 1,r9,L_NOARG', None)
add('st.d   r4,r15,5        ; CR 0x2394', st_d(4,15,5))
add('st.d   r5,r15,6        ; CR 0x2398', st_d(5,15,6))
add('st.d   r6,r15,7        ; CR 0x239c', st_d(6,15,7))
add('st.d   r7,r15,8        ; CR 0x23a0', st_d(7,15,8))
add('st.d   r8,r15,9        ; CR 0x23a4', st_d(8,15,9))
add('@L_NOARG addi r12,zero,0x1', addi(12,0,1))
add('st.d   r12,r15,4       ; CR 0x2390=flag', st_d(12,15,4))
add('@DONE @bbc2 b.bset 1,r9,C2', None)
add('@bbc1c b.bset 0,r9,C1', None)
add('@C0 csr.r  r3,csr0xbc', csr_r(3))
add('st.d   r3,r1,1', st_d(3,1,1))
add('st.d!  r1,r1,-0x10', st_dl(1,1,0x4000-4))
add('@jc0 jump 0x090b88', None)
add('@C1 csr.r  r3,csr0xbc', csr_r(3))
add('st.d   r3,r1,1', st_d(3,1,1))
add('st.d!  r1,r1,-0x8', st_dl(1,1,0x4000-2))
add('@jc1 jump 0x090bf0', None)
add('@C2 csr.r  r3,csr0xbc', csr_r(3))
add('st.d   r3,r1,1', st_d(3,1,1))
add('st.d!  r1,r1,-0x28', st_dl(1,1,0x4000-10))
add('@jc2 jump 0x0d3d00', None)

assert len(P)==63, len(P)

idx={}
for i,(c,w) in enumerate(P):
    for tok in c.split():
        if tok.startswith('@'):
            assert tok[1:] not in idx, ('dup label', tok)
            idx[tok[1:]] = i
A=lambda i: LOC+4*i
TAB=LOC+4*len(P)
fixups={
 '@btflag': lambda i: b_t(0, A(idx['DONE']), A(i)),
 '@bfop':   lambda i: b_f(0, A(idx['DONE']), A(i)),
 '@bbs1':   lambda i: b_bset(31,12, A(idx['L_INC']), A(i)),
 '@bbc1':   lambda i: b_bclr(31,12, A(idx['L_INC']), A(i)),
 '@bflp':   lambda i: b_f(0,  A(idx['L_LOOP']), A(i)),
 '@bbid':   lambda i: b_bset(1,9, A(idx['L_OP']), A(i)),
 '@bbm2':   lambda i: b_bset(1,9, A(idx['L_MISS2']), A(i)),
 '@bbna':   lambda i: b_bset(1,9, A(idx['L_NOARG']), A(i)),
 '@bbc2':   lambda i: b_bset(1,9, A(idx['C2']), A(i)),
 '@bbc1c':  lambda i: b_bset(0,9, A(idx['C1']), A(i)),
 '@jmap':   lambda i: jump(A(idx['L_MAP']), A(i)),
 '@jhit':   lambda i: jump(A(idx['L_HIT']), A(i)),
 '@jdn2':   lambda i: jump(A(idx['DONE']), A(i)),
 '@jc0':    lambda i: jump(0x090b88, A(i)),
 '@jc1':    lambda i: jump(0x090bf0, A(i)),
 '@jc2':    lambda i: jump(0x0d3d00, A(i)),
}
for i,(c,w) in enumerate(P):
    if w is None:
        if c.startswith('@L_MAP set2'): P[i][1]=set2(14,0,(TAB>>16)&0xffff)
        elif c.startswith('set3   r14,r14,TAB_LO'): P[i][1]=set3(14,14,TAB&0xffff)
        else:
            tok=next(t for t in c.split() if t in fixups)
            P[i][1]=fixups[tok](i)
    assert P[i][1] is not None, c

# ---------- decode-back check with dis.py (FIXED: target check actually runs) ----------
import importlib.util
spec=importlib.util.spec_from_file_location('dis','/tmp/opencode/irisc/dis.py')
dismod=importlib.util.module_from_spec(spec); spec.loader.exec_module(dismod)
print()
print('=== DECODE-BACK (all LOC words) ===')
# NOTE: T2 had a latent bug (c.split()[0][1:] in exp_target never matched the
# '@'-prefixed keys -> target check never ran). Here the '@' is kept.
exp_target={
 '@btflag':idx['DONE'],'@bfop':idx['DONE'],'@bbs1':idx['L_INC'],'@bbc1':idx['L_INC'],
 '@bflp':idx['L_LOOP'],'@bbid':idx['L_OP'],'@bbm2':idx['L_MISS2'],'@bbna':idx['L_NOARG'],
 '@bbc2':idx['C2'],'@bbc1c':idx['C1'],'@jmap':idx['L_MAP'],'@jhit':idx['L_HIT'],'@jdn2':idx['DONE'],
 '@jc0':0x090b88,'@jc1':0x090bf0,'@jc2':0x0d3d00,
}
db_ok=True
nchk=0
for i,(c,w) in enumerate(P):
    d=dismod.dis(w,A(i))
    mark='  '
    for tok in [t for t in c.split() if t in exp_target]:
        t=exp_target[tok]
        want=t if tok in ('@jc0','@jc1','@jc2') else LOC+4*t
        okw = ('0x%08x'%want) in d
        if mark=='  ' or not okw: mark='OK' if okw else 'FAIL'
        nchk+=1
        if not okw: db_ok=False
    print('%s %08x  %-46s ; %s'%(mark,A(i),d,c))
print('decode-back branch/jump target checks: %d' % nchk)
print('decode-back ok:',db_ok)
assert db_ok
assert nchk==16, nchk

print()
print('=== LOC code @0x%06x (%d words) ==='%(LOC,len(P)))
for i,(c,w) in enumerate(P):
    print('%08x  %08x  ; %s'%(A(i),w,c))
print()
print('=== TAB @0x%06x (%d words) ==='%(TAB,2*len(CANDS)))
for i,(s,e) in enumerate(CANDS):
    print('%08x  %08x  ; cand%02d start=0x%06x'%(TAB+8*i,s,i,s))
    print('%08x  %08x  ; cand%02d end  =0x%06x'%(TAB+8*i+4,e,i,e))
end=TAB+8*len(CANDS)
print()
print('total: 0x%06x..0x%06x (%d words = %d bytes); free region 0x38d750..0x38dbe8'%(LOC,end,len(P)+2*len(CANDS),(len(P)+2*len(CANDS))*4))
assert end<=0x38dbe8
print()
print('=== HOOKS (3 words each) ===')
# word1 = NOP (was st.d! r1,r1,-0x40 frame alloc) -> hook stack-neutral;
# word2 (or r9,zero,ID) and word3 (jump LOC) unchanged from T2.
OLD_W2={0x090b7c:0x950bf2f3,0x090be4:0x950bf2d9,0x0d3cf4:0x950ae695}
for S,ID in ((0x090b7c,0),(0x090be4,1),(0x0d3cf4,2)):
    w0=NOP
    w1=orr(9,0,ID)
    w2=jump(LOC,S+8)
    assert w2==OLD_W2[S], (hex(S),'jump word changed: %08x vs %08x'%(w2,OLD_W2[S]))
    print('0x%06x  %08x  ; nop (was st.d! r1,r1,-0x40 hook frame)'%(S,w0))
    print('0x%06x  %08x  ; or r9,zero,%d (hook ID, unchanged)'%(S+4,w1,ID))
    print('0x%06x  %08x  ; jump 0x%06x (LOC, unchanged)'%(S+8,w2,LOC))
print()
print('hook check: word1=nop 0x%08x, word2=or r9,word3=jump LOC (same as T2)'%NOP)
