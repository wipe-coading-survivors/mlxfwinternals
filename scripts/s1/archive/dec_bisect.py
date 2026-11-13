#!/usr/bin/env python3
# Decode (BE) S1-fixed2 LOC + hooks + no-op detour, for the bisect analysis.
# iRISC words in MAIN_CODE are BIG-ENDIAN ('>I').
# dec2.py = verified decoder (anchors in journal). We add jump-target calc +
# per-instr field dump for the clobber/CR audit.
import os, struct, sys, importlib.util

def u32(b, o): return struct.unpack_from('>I', b, o)[0]
def jt(w, pc):
    o = w & 0xffffff
    if o & 0x800000: o -= 0x1000000
    return pc + o*4
def brt(w, pc):
    o = w & 0xffff
    if o & 0x8000: o -= 0x10000
    return (pc+4) + o*4

spec = importlib.util.spec_from_file_location('dec2', '/tmp/opencode/s1/dec2.py')
dec2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(dec2)

def R(x): return 'zero' if x==0 else ('r%d'%x)

def fields(w):
    op=w>>26; rd=(w>>16)&0x1f; rs=(w>>21)&0x1f; rt=(w>>11)&0x1f; imm=w&0xffff
    return op,rd,rs,rt,imm

def rd_written(w):
    # returns set of register numbers written (for clobber audit), None if unknown
    op,rd,rs,rt,imm = fields(w)
    if op==0x25: return set()            # jump/call: no reg write
    if op in (0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
              0x0a,0x0b,0x0c,0x0e,0x12,0x32):
        return {rd} if rd else set()
    if op==0x3f:
        f=w&0x1ff
        if f==0x25:
            # ret.r / jalr: no register write (goto/return)
            return set()
        if f in (0x81,0x83,0x85,0x8a,0x8b):  # shr/shl64.i -> RDlo
            return {rd} if rd else set()
        if f in (0x00,0x01,0x04,0x05,0x08,0x0a,0x0b,0x0e,0x80):
            return {rd} if rd else set()
        return {rd} if rd else set()
    if op in (0x17,0x18,0x19):
        return {rd} if rd else set()
    if op in (0x1a,0x1b,0x1c,0x1e):
        # store: writeback on ! (op 0x1c) updates rs low
        wb = {rs} if (op==0x1c and rs) else set()
        return wb
    if op in (0x28,0x29,0x2a,0x2b):
        return set()
    if op==0x13:
        return set()
    return None  # unknown

def show(code, name, lo, hi):
    print('== %s  [0x%06x..0x%06x] ==' % (name, lo, hi))
    for a in range(lo, hi+1, 4):
        w = u32(code, a)
        op,rd,rs,rt,imm = fields(w)
        d = dec2.dis(w, a)
        extra = ''
        if op==0x25:
            extra = '  -> 0x%06x (jmpop=%d)' % (jt(w,a), (w>>24)&1)
        elif op in (0x28,0x29,0x2a,0x2b):
            extra = '  -> 0x%06x' % brt(w,a)
        print('  %06x  %08x  %-28s%s' % (a, w, d, extra))

if __name__ == '__main__':
    f2   = open('/tmp/opencode/s1/main03-code-s1-fixed2.bin','rb').read()
    noop = open('/tmp/opencode/s1/main03-code-s1-noop-detour.bin','rb').read()
    print('f2 size=0x%x  noop size=0x%x' % (len(f2), len(noop)))

    # ---- decoder anchors (journal §11) ----
    stock = open(os.path.expanduser('~/git/IMPLEMENTATION/mlxini/build/ghidra-4030cda-main03-ac-dc.bin'),'rb').read()
    anchors = [
        (0x0afe44, 0x66cc0142, 'ld.d r12,r22,0x140'),
        (0x0d3f48, 0x94fffeb1, 'call 0x0d3a0c'),
        (0x090b7c, 0x703f0ff2, 'st.d! r1,r1,-0x10'),
    ]
    print('== decoder anchors ==')
    for a,w,exp in anchors:
        got = dec2.dis(w, a)
        real = u32(stock, a)
        print('  @0x%06x word=%08x (bin=%08x) dis=%-26s exp=%s %s' %
              (a, w, real, got, exp, 'OK' if (got==exp and real==w) else 'MISMATCH'))
    w = 0xfd001825
    print('  STDRET %08x -> %s (expect ret.r zero,r8,r3)' % (w, dec2.dis(w,0)))

    # ---- f2 hooks (3 words each) ----
    print()
    show(f2, 'S1-fixed2 HOOK 0x090b7c (ID0)', 0x090b7c, 0x090b84)
    show(f2, 'S1-fixed2 HOOK 0x090be4 (ID1)', 0x090be4, 0x090bec)
    show(f2, 'S1-fixed2 HOOK 0x0d3cf4 (ID2)', 0x0d3cf4, 0x0d3cfc)

    # ---- f2 full LOC+TAB ----
    print()
    show(f2, 'S1-fixed2 LOC+TAB 0x38d750..0x38d8f4 (105 words)', 0x38d750, 0x38d8f4)

    # ---- no-op detour hooks + stubs ----
    print()
    show(noop, 'NOOP HOOK 0x090b7c', 0x090b7c, 0x090b84)
    show(noop, 'NOOP HOOK 0x090be4', 0x090be4, 0x090bec)
    show(noop, 'NOOP HOOK 0x0d3cf4', 0x0d3cf4, 0x0d3cfc)
    show(noop, 'NOOP STUB 0x38d750..0x38d77c', 0x38d750, 0x38d77c)
