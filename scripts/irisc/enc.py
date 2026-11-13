try:
    from .irisc_asm import encode_form
except ImportError:
    from irisc_asm import encode_form


def set0(rd, rs, imm): return encode_form('set0', rd=rd, rs=rs, imm=imm)
def set1(rd, rs, imm): return encode_form('set1', rd=rd, rs=rs, imm=imm)
def set3(rd, rs, imm): return encode_form('set3', rd=rd, rs=rs, imm=imm)
def set2(rd, imm): return encode_form('set2', rd=rd, rs=0, imm=imm)
def addi(rd, rs, imm): return encode_form('addi', rd=rd, rs=rs, imm=imm)
def csr_r(rd, csr): return encode_form('csr.r', rd=rd, csr=csr)
def st_d(rt, rs, off): return encode_form('st.d', rt=rt, rs=rs, off=off)
def jump(pc, tgt): return encode_form('jump', tgt=tgt, pos=pc)
def call(pc, tgt): return encode_form('call', tgt=tgt, pos=pc)
def cmp36(sel, rs, rt, lo11=0): return encode_form('op0x36', rd=sel, rs=rs, rt=rt, imm=lo11)
def cmp38(sel, rs, rt, lo11=0): return encode_form('op0x38', rd=sel, rs=rs, rt=rt, imm=lo11)
def cmp38_sel(funct5, rs, rt): return encode_form('op0x38', rd=0, rs=rs, rt=rt, imm=funct5)
def subsi(rd, rs, imm): return encode_form('subsi', rd=rd, rs=rs, imm=imm)
def b_t(cc, pc, tgt): return encode_form('b.t', cc=cc, rs=0, tgt=tgt, pos=pc)
def b_f(cc, pc, tgt): return encode_form('b.f', cc=cc, rs=0, tgt=tgt, pos=pc)
def b_bset(sh, rs, pc, tgt): return encode_form('b.bset', sh=sh, rs=rs, tgt=tgt, pos=pc)
def b_bclr(sh, rs, pc, tgt): return encode_form('b.bclr', sh=sh, rs=rs, tgt=tgt, pos=pc)
def ld_w(rt, rs, off): return encode_form('ld.w', rd=rt, rs=rs, off=off)
def ld_d(rt, rs, off): return encode_form('ld.d', rd=rt, rs=rs, off=off)
def st_w(rt, rs, off): return encode_form('st.w', rt=rt, rs=rs, off=off)
def or_(rd, rs, rt): return encode_form('or#alu', rd=rd, rs=rs, rt=rt)
def ret_r(rs, rd, rt): return encode_form('ret.r', rd=rd, rs=rs, rt=rt)
def shl64_i(rd, rs, shamt): return encode_form('shl64.i', rd=rd, rs=rs, shamt=shamt)
def st_d_push(imm): return encode_form('st.d!', rt=1, rs=1, off=imm)
def csr_w(rd, csr): return encode_form('csr.w', rs=0, rt=rd, imm=csr)
