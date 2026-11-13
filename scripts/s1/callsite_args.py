import os, struct, sys
sys.path.insert(0,'.')
from dec2 import dis
buf=open(os.path.expanduser('~/git/IMPLEMENTATION/mlxini/build/ghidra-4030cda-main03-ac-dc.bin'),'rb').read()

def w(off): return struct.unpack_from('>I',buf,off)[0]

def rd_reg(inst_w):
    op=inst_w>>26
    if op in (0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0e):
        return (inst_w>>16)&0x1f
    if op==0x19: return (inst_w>>16)&0x1f
    if op==0x12 and (inst_w>>25)&1: return (inst_w>>16)&0x1f
    if op==0x3f: return (inst_w>>16)&0x1f
    if op==0x32: return (inst_w>>16)&0x1f
    return None

def is_call(inst_w, tgt):
    op=inst_w>>26
    if op==0x25 and (inst_w>>24)==0:
        o=inst_w&0xffffff
        if o&0x800000: o-=0x1000000
        return (inst_w>>24)&1==0 and (inst_w&0xffffff)*4+ ( (inst_w>>24)&1)*0 == 0 and False
    return False

def find_calls(tgt):
    sites=[]
    for off in range(0,len(buf),4):
        ww=w(off)
        if ww>>26==0x25 and (ww>>24)==0:
            o=ww&0xffffff
            if o&0x800000: o-=0x1000000
            if off+o*4==tgt:
                sites.append(off)
    return sites

for name,tgt in (('ID0 0x090b7c',0x090b7c),('ID1 0x090be4',0x090be4)):
    sites=find_calls(tgt)
    print('=== %s: %d call-sites ==='%(name,len(sites)))
    for cs in sites:
        # scan back 16 instr, track last write to r4..r8
        val={}
        for k in range(1,17):
            off=cs-4*k
            if off<0: break
            ww=w(off)
            r=rd_reg(ww)
            if r in (4,5,6,7,8):
                val[r]=dis(ww,off)
        desc=', '.join('%s:%s'%(r,val[r]) for r in sorted(val))
        print('%08x | %s'%(cs, desc))
