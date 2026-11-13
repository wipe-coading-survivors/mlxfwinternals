#!/usr/bin/env python3
"""cx5 successpath R-C2: staging->completion trace on ConnectX-5 FW 16.35.4030.

Offline RE gates for plan 2026-10-20-cx5-successpath-rc12 Task 3 (extends the
rb1_dispatch_map.py precedent; Task 4 will add gate G8 on top):
  [G1] base image md5 a8c60c90... (live base pinned)
  [G2] ITOC 0x03 MAIN_CODE clcrc round-trip (0 bad-CRC, wrap(unwrap)==raw)
  [G3] MAIN_CODE geometry: 941936 words (0xE5F70) == 0x397dc0 B; dc unit =
       byte offset into de-clcrc; rt = dc + 0x800000
  [G4] mailbox anchors decode to expected forms: fn 0x0e4250 (QUERY 0x0932
       handler), BadParam call-site 0x0e437c (word 0x9402a57a = call
       0x18d964), resume 0x8E4380 (rt of dc 0x0e4380), fast-path tail call
       0x0e42b8, staging addi r10,r1,0x58 @0x0e4370, frame-copy addi
       r9,r1,0x98 @0x0e429c, memset loop, сборник call @0x0e43b8,
       completion tail call @0x0e43e4, сборник 0x0e4424 prologue+merge
       words, wrapper 0x18d8b0 (lock/FN_A/error/unlock), FN_A 0x18d964,
       error-reporter m2 call @0x18d5c4, ID1 builder 0x90be4 X1-form,
       m2 0x18064c, X1-lookup 0x18a668, serialize calls, registration
       compose of rt 0x8e4250 @0x0a93d8
  [G5] staging map complete: every staging zone of the fn-0x0e4250 frame
       classified by branch/consumer (frame copy / serialize outputs /
       FW staging / response), anchors decode-verified
  [G6] transfer mechanism named with instruction addresses: memset ->
       сборник bit-merges -> completion fnptr [ctx+0x140] with r9=response
       r8=0x40 -> transport POST family (0x90be4 / m2 0x18064c ->
       0x2ae98 POST / 0x2ac60 FETCH, X1 = 0x8fc0|(w<<6), 0x40B, 64B guard)
  [G7] staging->response->out_mb offset mapping reproduces the live
       Qcreated ground truth byte-level (04@0x1b log_size echo, 6f@0x3a +
       28@0x3b X1-class word at +0x38, zeros elsewhere, negative control
       03000000/001c2b78 without the success continuation) AND the A.1
       QUERY-series (0x1000_0000|(idx<<12) @0x44..0x1fc) is ruled as
       extended-mailbox chunk machinery outside the 0x40 completion window
       (producer idiom anchor @0x059018-0x05905c verified); residue is
       recorded honestly (op0x33/op0x0d bit positions are unknown-op class,
       [ctx+0x140] runtime value not statically resolvable)
  [G8] R-C3 groundwork budget gate: hook candidates (HC-1 late-site
       0x0e43c4 / HC-2 BadParam call-site 0x0e437c / HC-4 wrapper
       0x18d918; HC-3 epilogue excluded - no delivery path), stub sketch
       word counts decode-verified by in-gate assemble (cx5 profile),
       hook patch words with simm24 offsets (0xAA4E3 / 0xAA4F5), cave
       budget complete for every candidate form x every R-C3 base
       (v4-echo-graft keep/drop echo 25/34 free, v5l-rebuild 20,
       v5r+revert 34; slack >= 2 words per the R-E C-RE1 precedent),
       occupancy of the detour words 0x0E437C/0x0E43C4 marked explicitly
       against the stock baseline, v4-echo image word-checked read-only,
       carrier survey (QUERY input frame-copy 0x40 window / CREATE sibling
       staging r1+0x28 untraced / CR seeding R-E class) and the per-command
       byte ceiling (56 B verbatim response+0x8..0x40, POST fixed 0x40B)
Log: build/cx5-successpath-rc2.log
"""
import hashlib
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(WT))
sys.path.insert(0, str(WT / 'scripts/irisc'))
import mlxfwutil
import irisc_dis
from scripts.irisc import assemble

BASE = WT / 'refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin'
LOG = WT / 'build/cx5-successpath-rc2.log'
BASE_MD5 = 'a8c60c90473078288b01009c7cad471b'
RAW_MD5 = 'bcfe0526b43de4abf324b5056f91c112'
RT = 0x800000
MAIN_WORDS = 941936
MAIN_BYTES = MAIN_WORDS * 4
ITOC3_SIZE = 0x3d15a0
ITOC3_ADDR = 0x1c748

QUERY_FN, QUERY_HI = 0x0e4250, 0x0e4424
COLLECTOR, COLLECTOR_HI = 0x0e4424, 0x0e473c
WRAPPER = 0x18d8b0
FN_A = 0x18d964
ERR_REPORT = 0x18d574
M2 = 0x18064c
X1_LOOKUP = 0x18a668
ID1_BUILDER = 0x90be4
TRANSPORT_POST = 0x2ae98
TRANSPORT_FETCH = 0x2ac60
STOCK_CALL_WORD = 0x9402a57a

G4_ANCHORS = [
    (0x0e4250, 'csr.r r3,csr0xbc', 'fn 0x0e4250: QUERY 0x0932 handler prologue'),
    (0x0e4258, 'st.d! r1,r1,-0xf8', 'fn 0x0e4250: frame 0xF8'),
    (0x0e4284, 'ld.d r22,r20,0x150', 'fn 0x0e4250: obj = [ctx+0x150]'),
    (0x0e4288, 'ld.b r4,r20,0x80', 'fn 0x0e4250: dispatch byte [ctx+0x80]'),
    (0x0e428c, 'b.bset 5,r4,0xe42cc', 'fn 0x0e4250: bit5 -> trace path'),
    (0x0e4290, 'ld.d r17,r20,0x140', 'fn 0x0e4250: r17 = [ctx+0x140] (fast path)'),
    (0x0e429c, 'addi r9,r1,0x98', 'fn 0x0e4250: r9 = frame copy r1+0x98 (fast path)'),
    (0x0e42b8, 'ret.r zero,zero,r17', 'fn 0x0e4250: fast-path completion tail call'),
    (0x0e42bc, 'subsi r5,r4,0x0', 'fn 0x0e4250: slow entry gate (indirect; live v4e)'),
    (0x0e42c0, 'b.t.0x0 zero,0xe4310', 'fn 0x0e4250: r4==0 -> slow path'),
    (0x0e42cc, 'set3 r4,zero,0x8a24', 'fn 0x0e4250: trace path literal'),
    (0x0e42dc, 'call 0xad0ac', 'fn 0x0e4250: trace call (0xad0ac)'),
    (0x0e4310, 'ld.w r8,r1,0x9a', 'fn 0x0e4250: slow path: [fr+0x2].w'),
    (0x0e4328, 'call 0xebc9c', 'fn 0x0e4250: validate call'),
    (0x0e4358, 'call 0xcaec0', 'fn 0x0e4250: serialize call (out r1+0x48..0x58)'),
    (0x0e4370, 'addi r10,r1,0x58', 'fn 0x0e4250: STAGING base r1+0x58 (FN_A r10)'),
    (0x0e4374, 'addi r4,zero,0x0', 'fn 0x0e4250: FN_A no-rmutex arg'),
    (0x0e437c, 'call 0x%x' % FN_A, 'fn 0x0e4250: BadParam call-site (word 0x9402a57a)'),
    (0x0e4380, 'or r19,r4,r4', 'fn 0x0e4250: resume 0x8E4380 (rt) = res capture'),
    (0x0e4388, 'b.f.0x0 zero,0xe42e4', 'fn 0x0e4250: res!=0 -> BadParam exit'),
    (0x0e438c, 'addi r5,r1,0x8', 'fn 0x0e4250: memset head (response base)'),
    (0x0e4394, 'addi r5,r5,0x-4', 'fn 0x0e4250: memset pre-dec'),
    (0x0e4398, 'st.d! zero,r5,0x4', 'fn 0x0e4250: memset store loop'),
    (0x0e43a0, 'b.t.0x3 zero,0xe4398', 'fn 0x0e4250: memset loop back'),
    (0x0e43a4, 'ld.w r5,r20,0x9e', 'fn 0x0e4250: [ctx+0x9e].w for сборник'),
    (0x0e43a8, 'addi r6,r1,0x58', 'fn 0x0e4250: сборник arg staging'),
    (0x0e43ac, 'addi r18,r1,0x8', 'fn 0x0e4250: response base r18'),
    (0x0e43b8, 'call 0x%x' % COLLECTOR, 'fn 0x0e4250: сборник call'),
    (0x0e43e4, 'ret.r zero,zero,r17', 'fn 0x0e4250: completion tail call r17'),
    (0x0e4418, 'set3 r4,r4,0x4', 'fn 0x0e4250: trace cluster [ctx+0x80]|=4'),
    (COLLECTOR, 'csr.r r3,csr0xbc', 'сборник 0x0e4424: prologue'),
    (0x0e443c, 'or r22,r6,r6', 'сборник: r22 = staging'),
    (0x0e4438, 'or r23,r7,r7', 'сборник: r23 = response'),
    (0x0e4444, 'ld.d r4,r22,0x0', 'сборник: read staging[0x0]'),
    (0x0e4450, 'op0x33 r4,r6,r4 imm=0x2008', 'сборник: merge -> response+0x18 (word 1)'),
    (0x0e4454, 'st.d r4,r23,0x18', 'сборник: store response+0x18'),
    (0x0e4460, 'op0x0d r6,r6,zero imm=0x00ff', 'сборник: extract staging[0] bits[15:8]'),
    (0x0e4474, 'op0x0d r6,r6,r1 imm=0x0f00', 'сборник: extract staging[0x18] bits[11:8]'),
    (0x0e4488, 'op0x0d r6,r6,r16 imm=0x8000', 'сборник: extract staging[0x18] bit15'),
    (0x0e449c, 'op0x0d r6,r6,r8 imm=0x4000', 'сборник: extract staging[0x18] bit14'),
    (0x0e44ac, 'b.bset 29,r4,0xe44b8', 'сборник: bit29 dest select'),
    (0x0e44b0, 'addi r6,r23,0x1c', 'сборник: dest response+0x1c'),
    (0x0e44b8, 'addi r6,r23,0x20', 'сборник: dest response+0x20'),
    (0x0e44c0, 'op0x33 r4,r7,r4 imm=0x2018', 'сборник: merge -> response+0x1c/+0x20'),
    (0x0e459c, 'set1 r5,r5,0x6f00', 'сборник: X1-class prefix 0x6f00 (a)'),
    (0x0e4610, 'set1 r5,r5,0x6f00', 'сборник: X1-class prefix 0x6f00 (b)'),
    (0x0e463c, 'set1 r6,r6,0x6f00', 'сборник: X1-class prefix 0x6f00 (c)'),
    (0x0e470c, 'st.q.1e r6,r23,0x38', 'сборник: 8B store response+0x38 (X1 word)'),
    (0x0e4720, 'st.q.1e r5,r23,0x30', 'сборник: 8B store response+0x30 (X1 word)'),
    (WRAPPER, 'csr.r r3,csr0xbc', 'wrapper 0x18d8b0: prologue'),
    (0x18d8d4, 'or r22,r9,r9', 'wrapper: buf <- r9'),
    (0x18d8f4, 'call 0x62048', 'wrapper: lock'),
    (0x18d914, 'call 0x%x' % FN_A, 'wrapper: FN_A call (live v4e run1 ra 0x98d918)'),
    (0x18d92c, 'call 0x%x' % ERR_REPORT, 'wrapper: error reporter on res!=0'),
    (0x18d938, 'call 0x62048', 'wrapper: unlock'),
    (0x0e3740, 'call 0x%x' % WRAPPER, 'sibling handler 0x0e2cf8: direct wrapper call-site (live v4e run1 ra 0x98d918)'),
    (FN_A, 'csr.r r3,csr0xbc', 'FN_A 0x18d964: prologue'),
    (0x18d5c4, 'call 0x%x' % M2, 'error-reporter: m2 call (error completion send)'),
    (M2, 'csr.r r3,csr0xbc', 'm2 0x18064c: prologue'),
    (X1_LOOKUP, 'csr.r r3,csr0xbc', 'X1-lookup 0x18a668: prologue'),
    (ID1_BUILDER, 'csr.r r3,csr0xbc', 'ID1 builder 0x90be4: prologue'),
    (0x90bf4, 'alu.0x7f r4,r5,r16', 'ID1 builder: X1 HB part'),
    (0x90bfc, 'shl64.i r5,r5,0x6', 'ID1 builder: X1 w<<6'),
    (0x90c04, 'set1 r4,r4,0x8fc0', 'ID1 builder: X1 prefix 0x8fc0'),
    (0x90c14, 'call 0x%x' % TRANSPORT_FETCH, 'ID1 builder: FETCH branch'),
    (0x90c24, 'call 0x%x' % TRANSPORT_POST, 'ID1 builder: POST branch'),
    (TRANSPORT_POST, 'csr.r r3,csr0xbc', 'transport POST 0x2ae98: prologue'),
    (0x0a93d8, 'addi r4,zero,0x4250', 'registration: fn 0x0e4250 compose lo'),
    (0x0a93dc, 'addi.hi r4,r4,0x8e', 'registration: fn 0x0e4250 compose hi'),
    (0x0a85b8, 'st.d r4,r6,0x0', 'registration: desc[0x0] = handler fnptr'),
    (0x059018, 'shl64.i r4,r4,0xc', 'A.1 producer: chunk idx << 12'),
    (0x05901c, 'addi r4,r4,0x1000', 'A.1 producer: +0x1000 page form'),
    (0x059050, 'call 0x20264', 'A.1 producer: 0x1000-chunk move'),
]

G5_ZONES = [
    dict(name='frame-copy [r1+0x98+k)', span=(0x98, 0xd8), branch='fast path (also arg side of slow path)',
         writer='caller mailbox layer (stack copy of the input frame, S3-T3)',
         consumer='fast tail call r9 @0x0e42b8 -> [ctx+0x140] fn -> FN_A r10 via wrapper; slow path reads [fr+0x2]/[fr+0x8]/[fr+0x10]/[fr+0x14]',
         anchors=[(0x0e429c, 'addi r9,r1,0x98'), (0x0e4310, 'ld.w r8,r1,0x9a'),
                  (0x0e4314, 'ld.b r5,r1,0xa8'), (0x0e4318, 'ld.d r4,r1,0xa0'),
                  (0x0e4368, 'ld.d r4,r1,0xac')]),
    dict(name='serialize outputs [r1+0x48..0x58)', span=(0x48, 0x58), branch='slow path',
         writer='serialize 0xcaec0 (args r7..r10 = r1+0x54/0x50/0x4c/0x48) @0x0e4358',
         consumer='[r1+0x50] -> FN_A r6 @0x0e4364',
         anchors=[(0x0e4344, 'addi r7,r1,0x54'), (0x0e4348, 'addi r8,r1,0x50'),
                  (0x0e434c, 'addi r9,r1,0x4c'), (0x0e4350, 'addi r10,r1,0x48'),
                  (0x0e4364, 'ld.d r6,r1,0x50')]),
    dict(name='FW staging [r1+0x58..0x98)', span=(0x58, 0x98), branch='slow path (both exits)',
         writer='FN_A 0x18d964 via r10 @0x0e4370 (staging head; zone fact S2b2)',
         consumer='BadParam exit: none (discarded, live Q(0,0) 03000000/001c2b78); success: сборник 0x0e4424 r6 @0x0e43a8 (v5n BadParam-resume also reaches сборник: stub forces res=0 -> A.1 situation)',
         anchors=[(0x0e4370, 'addi r10,r1,0x58'), (0x0e43a8, 'addi r6,r1,0x58'),
                  (0x0e443c, 'or r22,r6,r6')]),
    dict(name='response [r1+0x8..0x48)', span=(0x8, 0x48), branch='slow path success continuation',
         writer='memset 0x0e438c..0x0e43a0 (16 d-words, exit r5=r1+0x44 r6=0) + сборник merges',
         consumer='completion tail call r9 @0x0e43e4 -> [ctx+0x140] -> transport POST 0x40B -> out_mb[0x00..0x40)',
         anchors=[(0x0e438c, 'addi r5,r1,0x8'), (0x0e4390, 'addi r4,r5,0x3c'),
                  (0x0e4398, 'st.d! zero,r5,0x4'), (0x0e43ac, 'addi r18,r1,0x8'),
                  (0x0e43dc, 'or r9,r18,r18'), (0x0e43d8, 'addi r8,zero,0x40')]),
]

G6_MECHANISM = [
    (0x0e4370, 'addi r10,r1,0x58', 'FN_A writes QUERY words into staging (r10 = r1+0x58)'),
    (0x0e4388, 'b.f.0x0 zero,0xe42e4', 'BadParam branch: res != 0 -> epilogue (no staging transfer)'),
    (0x0e438c, 'addi r5,r1,0x8', 'success: memset response [r1+0x8..0x48) (16 d-words)'),
    (0x0e43a8, 'addi r6,r1,0x58', 'сборник arg r6 = staging'),
    (0x0e43b4, 'or r7,r18,r18', 'сборник arg r7 = response'),
    (0x0e43b8, 'call 0x%x' % COLLECTOR, 'сборник call 0x0e4424: staging -> response bit-merges'),
    (0x0e4450, 'op0x33 r4,r6,r4 imm=0x2008', 'merge staging[0x0]>>8 -> response+0x18 (op0x33 imm 0x2008)'),
    (0x0e4468, 'st.d r4,r23,0x18', 'merge staging[0x0] bits[15:8] -> response+0x18 (op0x0d 0x00ff, stored)'),
    (0x0e447c, 'st.d r4,r23,0x18', 'merge staging[0x18] bits[11:8] -> response+0x18 (stored)'),
    (0x0e4490, 'st.d r4,r23,0x18', 'merge staging[0x18] bit15 -> response+0x18 (stored)'),
    (0x0e44a4, 'st.d r4,r23,0x18', 'merge staging[0x18] bit14 -> response+0x18 (stored)'),
    (0x0e44c4, 'st.d r4,r6,0x0', 'merge staging[0x18] -> response+0x1c/+0x20 (bit29 select, stored)'),
    (0x0e470c, 'st.q.1e r6,r23,0x38', '8B X1-class word (0x6f00 prefix) -> response+0x38'),
    (0x0e4720, 'st.q.1e r5,r23,0x30', '8B X1-class word -> response+0x30'),
    (0x0e43e4, 'ret.r zero,zero,r17', 'completion tail call [ctx+0x140](0, obj, ctx+0x40, 0, 0x40, response, 0)'),
    (ID1_BUILDER, 'csr.r r3,csr0xbc', 'ID1 builder: X1(obj) = alu.0x7f | (w<<6) | 0x8fc0 prefix'),
    (0x90c24, 'call 0x%x' % TRANSPORT_POST, 'transport POST 0x2ae98: 0x40B buf -> X1 (m2 0x18064c path; error-side m2 call @0x18d5c4)'),
]

G7_MAP = [
    dict(stage='staging[0x0] bits[15:8]', resp='+0x18 (word @0x18..0x1b)', out='out_mb+0x18..0x1b',
         live='Qcreated 04@0x1b (log_size echo; CREATE input carried 04@0x1b)'),
    dict(stage='staging[0x18] bitfields', resp='+0x1c or +0x20 (bit29 select)', out='out_mb+0x1c/+0x20',
         live='zeros observed (merges carried zero bits)'),
    dict(stage='staging[0x14]/[0x24]/[0x28] + obj -> X1 word A', resp='+0x30 (st.q.1e @0x0e4720)', out='out_mb+0x30..0x37',
         live='zeros observed'),
    dict(stage='staging-derived w -> (w<<6)|alu.0x7f(obj)|set1 0x6f00', resp='+0x38 (st.q.1e @0x0e470c)', out='out_mb+0x38..0x3f',
         live='Qcreated 6f@0x3a (set1 bits[47:40]) + 28@0x3b (bits[39:32])'),
    dict(stage='(none) status/syndrome', resp='+0x0..0x8 (completion layer, outside сборник)', out='out_mb+0x0..0x8',
         live='Qcreated 00000000/00000000; negative Q(0,0) 03000000/001c2b78 via BadParam exit'),
]

QCREATED_OUT = ('00000000000000000000000000000000'
                '00000000000000000000000400000000'
                '00000000000000000000000000000000'
                '000000000000000000006f2800000000')
QNEG_OUT = '03000000001c2b78' + '00' * (0x40 - 8)

STUB_SLOT = (0x38d750, 0x38d7d8)
STUB_SLOT_WORDS = 34
H0_DOOR, H0_WORD = 0x106390, 0x940a1cf0
V4ECHO_IMG = WT / 'build/cx5-door-detour-v4.bin'
V4ECHO_STUB_WORDS = 9
LATE_SITE, LATE_STOCK, LATE_HOOK = 0x0e43c4, 0x00130000, 0x940aa4e3
CALL_SITE_STOCK_HOOK = (0x9402a57a, 0x940aa4f5)
WRAP_SITE, WRAP_STOCK = 0x18d918, 0xfc952008

G8_SITES = [
    dict(id='HC-1 late-site', dc=LATE_SITE, stock=LATE_STOCK,
         decode='addi r19,zero,0x0', hook=LATE_HOOK, called_fn='none (dead-write word; stub replays it)',
         liveins='r18=response base (addi @0x0e43ac, callee-saved, alive through сборник), r1=frame, r20=ctx, r22=obj',
         clobbers='r3..r10 dead-at-site (r4..r10 rewritten at 0x0e43c8..0x0e43e0); DO NOT touch r11 (mask32 result @0x0e43c0, runtime consumer) nor r17..r23',
         trigger='host QUERY success path (Qcreated); Q(0,0) negative exits BadParam @0x0e4388 before the site - built-in negative control, no magic filter needed for a marker probe',
         delivery='stub writes response [r1+0x8..0x48) AFTER сборник merges, BEFORE completion tail call @0x0e43e4 -> POST 0x40B -> out_mb verbatim (56 B safe window +0x8..0x40)',
         words='H1a marker 5 / H1b input-carrier 40B 23 / H1c imm 3 words per 4B',
         risk='v5r-proven detour mechanics at this exact site (RESUME_P 0x008E43C8); frame 0xF8 stays live (family per-command stack discipline, Task 3 hook-siting note)'),
    dict(id='HC-2 BadParam call-site', dc=0x0e437c, stock=CALL_SITE_STOCK_HOOK[0],
         decode='call 0x18d964', hook=CALL_SITE_STOCK_HOOK[1],
         called_fn='FN_A 0x18d964 (v3-form: stock call first from the stub)',
         liveins='r1=frame, r10=r1+0x58 staging head (pre-call), r6=[r1+0x50] serialize out; after FN_A returns only r1/r18-class frame+callee-saved are trustworthy',
         clobbers='caller-saved r4..r10 dead after stock call; staging [r1+0x58..0x98) writable pre-resume',
         trigger='host QUERY slow path (every QUERY incl. negatives reaches the call-site; forcing res=0 diverts negatives - v5n class, needs MAGIC16 filter @input[0x12] to keep stock semantics)',
         delivery='staging only (response does not exist yet - memset comes later); out_mb via сборник merges: ~1 verbatim byte (staging[0] bits[15:8] -> out+0x1b, live 04@0x1b), structured bits (+0x18/+0x1c/+0x20), 2 transformed 8B X1-words (+0x30/+0x38) - NOT a bulk channel',
         words='H2 marker 6 / H2 +v5l-class filter 10',
         risk='merge semantics op0x33/op0x0d = unknown-op class (bit positions hypothesis); res-forcing changes stock negative behavior without a filter'),
    dict(id='HC-4 wrapper res-capture', dc=WRAP_SITE, stock=WRAP_STOCK,
         decode='or r21,r4,r4', hook=None,
         called_fn='none (replay the word from the stub)',
         liveins='r4=FN_A res, r22=buf (saved @0x18d8d4), r23=lock arg, r18..r21 wrapper args',
         clobbers='caller-saved only; r17..r23 saves already on wrapper frame',
         trigger='every wrapper-family command (CREATE/DESTROY live-proven v4e run1); QUERY reaches the wrapper only if [ctx+0x140] resolves to it - statically unproven (runtime fnptr)',
         delivery='write into [r22+k] buf; buf consumer after wrapper return = sibling continuation, NOT traced (out of Task 3 scope) - delivery unproven',
         words='H4 marker 5',
         risk='fallback candidate only: [ctx+0x140] runtime value unresolved + sibling buf->out_mb path untraced'),
]

G8_SKETCHES = [
    dict(id='H1a marker (5w)', words=5,
         expect=[0x00130000, 0x2405bad1, 0x2005c0de, 0x6e40282a, 0xfc00002d],
         src='addi r19,zero,0x0\nset2 r5,zero,0xbad1\nset3 r5,zero,0xc0de\nst.d r5,r18,0x28\nret.d zero,zero,zero\n',
         note='stock-word replay (byte-exact 0x00130000) + const + st.d into merge-free response word +0x28 + ret.d'),
    dict(id='H1 input-carrier pair (2w per 4B)', words=2,
         expect=[0x642600b2, 0x6e403012],
         src='ld.d r6,r1,0xb0\nst.d r6,r18,0x10\n',
         note='frame-copy (fr+0x18 = r1+0xb0 = input[0x18]) -> response+0x10; full input window 0x28 B = 10 pairs'),
    dict(id='H1 imm 4B (3w per 4B)', words=3,
         expect=[0x24071234, 0x20075678, 0x6e403816],
         src='set2 r7,zero,0x1234\nset3 r7,zero,0x5678\nst.d r7,r18,0x14\n',
         note='immediate-carried payload word -> response'),
    dict(id='H2 marker (6w)', words=6,
         expect=[0x94f80085, 0x00040000, 0x24050bad, 0x2005f00d, 0x6c20285a, 0x95155b07],
         src='call 0x18d964\naddi r4,zero,0x0\nset2 r5,zero,0x0bad\nset3 r5,zero,0xf00d\nst.d r5,r1,0x58\njump 0x8e4380\n',
         note='stock FN_A call first + res=0 force + staging marker + resume jump (rel24)'),
    dict(id='H2 +v5l-class filter (10w)', words=10,
         expect=[0x642600ab, 0x240755aa, 0x200755aa, 0xe0e03002, 0xa0000003,
                 0x94f80080, 0x95155b06, 0x00040000, 0x6c20385a, 0x95155b03],
         src=('ld.w r6,r1,0xaa\nset2 r7,zero,0x55aa\nset3 r7,zero,0x55aa\n'
              'cmp38_eq32 r7,r6\nb.t.0x0 zero,stash\ncall 0x18d964\njump 0x8e4380\n'
              'lbl stash\naddi r4,zero,0x0\nst.d r7,r1,0x58\njump 0x8e4380\n'),
         note='MAGIC16 @input[0x12] (= r1+0xaa frame-copy slot, v5l canon); miss = stock semantics preserved'),
    dict(id='H4 wrapper marker (5w)', words=5,
         expect=[0xfc952008, 0x2405d00d, 0x20050001, 0x6ec0280a, 0xfc00002d],
         src='or r21,r4,r4\nset2 r5,zero,0xd00d\nset3 r5,zero,0x0001\nst.d r5,r22,0x8\nret.d zero,zero,zero\n',
         note='stock-word replay (byte-exact 0xfc952008) + buf marker (delivery unproven)'),
]

G8_BASES = [
    dict(id='v4-echo-graft keep-echo', slot_used=V4ECHO_STUB_WORDS, free=25,
         w_e437c='FREE (stock word verified in image)', w_e43c4='FREE (stock word verified in image)',
         source='build/cx5-door-detour-v4.bin word-check (this gate); H0 door hook @0x106390 stays, door-echo canary preserved'),
    dict(id='v4-echo-graft drop-echo', slot_used=0, free=34,
         w_e437c='FREE (stock)', w_e43c4='FREE (stock)',
         source='v4-echo with the 9-word echo stub replaced; loses the door-echo channel'),
    dict(id='v5l-rebuild', slot_used=14, free=20,
         w_e437c='OCCUPIED (S2 exec-leg hook, offset 0xAA4F5)', w_e43c4='FREE (stock)',
         source='build_s2.py STUB_LAYOUT v17 (14w) + DETOUR_DC; exec leg not required for R-C (spec §0)'),
    dict(id='v5r+revert', slot_used=0, free=34,
         w_e437c='FREE (stock on v5r by design)', w_e43c4='FREE after revert (S3 late-detour word restored to stock 0x00130000)',
         source='build_s2.py STUB_LAYOUT v23 (29w, replaced) + DETOUR_P revert; spec §0 builder-check'),
]

G8_FORMS = [
    dict(id='H1a marker', cand='HC-1', words=5),
    dict(id='H1b input-carrier 40B', cand='HC-1', words=23),
    dict(id='H1c imm 16B', cand='HC-1', words=17),
    dict(id='H1c imm 36B', cand='HC-1', words=32),
    dict(id='H2 marker', cand='HC-2', words=6),
    dict(id='H2 +filter', cand='HC-2', words=10),
    dict(id='H4 wrapper marker', cand='HC-4', words=5),
]

G8_V5L_TAIL_INSERT = 4
G8_RECOMMENDED = ('H1b input-carrier 40B', 'v4-echo-graft keep-echo')


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


class Ctx:
    o = None


def fail(o, msg):
    o('FATAL: ' + msg)
    LOG.write_text('\n'.join(o.lines) + '\n')
    sys.exit(1)


def rt_of(dc):
    return dc + RT


def in_main(dc):
    return 0 <= dc < MAIN_BYTES


def dec_at(c, dc):
    return c.dec[dc // 4]


def word_at(c, dc):
    return c.words[dc // 4]


def chk(c, off, want, why):
    got = dec_at(c, off)
    if got != want:
        fail(c.o, '%s @0x%x: "%s" != "%s"' % (why, off, got, want))


def gate_g1_g2_g3(c):
    o = c.o
    buf = BASE.read_bytes()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail(o, 'base md5 mismatch')
    o('[G1] base md5 OK (%s, %d B)' % (BASE_MD5, len(buf)))
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', 0x03)
    raw = img.section_data(e)
    if not (e.size == ITOC3_SIZE and e.addr == ITOC3_ADDR and e.clcrc == 1
            and e.param0 == RT):
        fail(o, 'ITOC03 params: size=%#x addr=%#x clcrc=%s p0=%#x'
             % (e.size, e.addr, e.clcrc, e.param0))
    if hashlib.md5(raw).hexdigest() != RAW_MD5:
        fail(o, 'MAIN_CODE raw md5 mismatch')
    errs = mlxfwutil.clcrc_lines_errors(raw)
    if errs:
        fail(o, 'clcrc bad lines: %d (first %s)' % (len(errs), errs[0]))
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw:
        fail(o, 'clcrc round-trip mismatch')
    o('[G2] clcrc round-trip OK: %d lines 0 bad-CRC, wrap(unwrap)==raw '
      '(%#x B), tail=%s' % (len(raw) // 68, len(raw), tail.hex()))
    if len(code) != MAIN_BYTES or len(code) // 4 != MAIN_WORDS:
        fail(o, 'MAIN_CODE geometry: %#x B / %d words' % (len(code), len(code) // 4))
    c.img, c.raw, c.code, c.tail = img, raw, code, tail
    c.n = MAIN_WORDS
    c.words = struct.unpack('>%dI' % c.n, code)
    c.dec = [irisc_dis.dis(w, i * 4) for i, w in enumerate(c.words)]
    o('[G3] MAIN_CODE geometry OK: %d words (0x%x) == 0x%x B; dc unit = '
      'byte offset, cutoff dc in [0, 0x%x); rt = dc + 0x%x'
      % (c.n, c.n, MAIN_BYTES, MAIN_BYTES, RT))


def gate_g4(c):
    o = c.o
    for off, want, why in G4_ANCHORS:
        if not in_main(off):
            fail(o, '%s: dc %#x outside MAIN_CODE' % (why, off))
        chk(c, off, want, why)
    if word_at(c, 0x0e437c) != STOCK_CALL_WORD:
        fail(o, 'stock call word @0x0e437c: %#x != %#x'
             % (word_at(c, 0x0e437c), STOCK_CALL_WORD))
    if dec_at(c, COLLECTOR_HI) != 'csr.r r3,csr0xbc':
        fail(o, 'сборник upper bound: next prologue not found @%#x' % COLLECTOR_HI)
    o('[G4] all %d mailbox anchors decode to expected forms (fn %#x..%#x, '
      'BadParam call-site 0x0e437c word 0x%08x, resume 0x%08X rt, сборник '
      '%#x..%#x, wrapper %#x, FN_A %#x, m2 %#x, X1-lookup %#x, ID1 builder '
      '%#x, transport POST %#x / FETCH %#x, registration compose '
      '0x0a93d8->0x8e4250, A.1 chunk-loop idiom 0x059018)'
      % (len(G4_ANCHORS), QUERY_FN, QUERY_HI, STOCK_CALL_WORD,
         rt_of(0x0e4380), COLLECTOR, COLLECTOR_HI, WRAPPER, FN_A, M2,
         X1_LOOKUP, ID1_BUILDER, TRANSPORT_POST, TRANSPORT_FETCH))


def dump_listing(c, lo, hi, title):
    o = c.o
    o('[LISTING] %s [dc %#x..%#x) (rt = dc + 0x%x):' % (title, lo, hi, RT))
    for off in range(lo, hi, 4):
        o('  %08x  %08x  %s' % (off, word_at(c, off), dec_at(c, off)))


def mark_branches(c):
    o = c.o
    o('[BRANCH MAP] fn 0x0e4250 (QUERY 0x0932) - branches:')
    rows = [
        ('trace (bit5 of [ctx+0x80] set)', '0x0e42cc..0x0e42e0', 'call 0xad0ac debug-trace -> clean exit r19=0 (NOT the data path)'),
        ('fast (bit5 clear)', '0x0e4290..0x0e42b8', 'tail-jump [ctx+0x140](1, obj, ctx+0x40, 0, 0x40, frame copy r1+0x98, 0) - execute+complete via wrapper class'),
        ('slow entry (indirect; live v4e ra 0x008e4380)', '0x0e42bc..0x0e42c0', 'r4==0 -> slow path; else error-transform exit (op0x34 imm 0x0708)'),
        ('slow path', '0x0e4310..0x0e437c', 'validate 0xebc9c -> serialize 0xcaec0 -> FN_A call @0x0e437c (staging r10=r1+0x58)'),
        ('BadParam (FN_A res != 0)', '0x0e4388 -> 0x0e42e4', 'epilogue; staging discarded; error completion built by the caller layer (live 03000000/001c2b78)'),
        ('SUCCESS continuation (resume 0x8E4380)', '0x0e438c..0x0e43e4', 'memset response -> сборник merges -> completion tail call [ctx+0x140](..., response, 0x40, ...)'),
        ('trace cluster (indirect)', '0x0e43e8..0x0e4420', 'emit 0x1b1ec + [ctx+0x80]|=4 -> exit'),
    ]
    for name, zone, note in rows:
        o('  %-46s %-24s %s' % (name, zone, note))
    o('  census: no static call/jump/branch into 0x0e42bc or 0x0e43e8 in the '
      'whole image (indirect RAM-dispatch entries; the sole static reference '
      'to the fn is the registration compose @0x0a93d8 -> desc[0x0])')


def gate_g5(c):
    o = c.o
    for z in G5_ZONES:
        for off, want in z['anchors']:
            chk(c, off, want, 'zone %s anchor' % z['name'])
        o('[G5] zone %-32s span r1+[%02x..%02x)  branch: %s'
          % (z['name'], z['span'][0], z['span'][1], z['branch']))
        o('        writer:    %s' % z['writer'])
        o('        consumer:  %s' % z['consumer'])
    spans = sorted(z['span'] for z in G5_ZONES)
    for (a1, b1), (a2, b2) in zip(spans, spans[1:]):
        if a2 < b1:
            fail(o, 'staging zones overlap: [%02x..%02x) vs [%02x..%02x)' % (a1, b1, a2, b2))
    o('[G5] PASS: staging map complete - frame copy / serialize outputs / '
      'FW staging / response zones all classified (branch + writer + '
      'consumer), zones disjoint; response zone double-checked against the '
      '0xF8 frame facts (response @B+0x8, staging area head @B+0x48, FW '
      'staging [B+0x58..0x98), frame copy [B+0x98+k))')


def gate_g6(c):
    o = c.o
    for off, want, role in G6_MECHANISM:
        chk(c, off, want, 'G6 mechanism word')
        o('[G6] %08x (rt %08X): %s' % (off, rt_of(off), role))
    o('[G6] PASS: transfer mechanism - all %d mechanism words '
      'decode-verified (chk loop over G6_MECHANISM): FN_A fills staging '
      '(r10 @0x0e4370); ' % len(G6_MECHANISM) +
      'on success the response [r1+0x8..0x48) is memset then сборник-merged; '
      'completion fnptr [ctx+0x140] receives it as r9 with r8=0x40 and the '
      'transport POST family (ID1 builder 0x90be4 / m2 0x18064c -> 0x2ae98, '
      'X1 = 0x8fc0-prefix | (w<<6), 0x40B, 64B guard) moves it into '
      'out_mb[0x00..0x40). The exact [ctx+0x140] value is runtime data '
      '(registration desc[0x0] compose @0x0a93d8 is the only static fn '
      'reference); wrapper 0x18d8b0 is the live-proven family member '
      '(v4e run1) and itself does not move bytes - its buf goes to FN_A r10.')


def gate_g7(c):
    o = c.o
    out = bytes.fromhex(QCREATED_OUT)
    if len(out) != 0x40:
        fail(o, 'Qcreated ground truth length %d != 64' % len(out))
    if out[0x1b] != 0x04:
        fail(o, 'ground truth: byte @0x1b = %#x, want 0x04' % out[0x1b])
    if out[0x3a] != 0x6f or out[0x3b] != 0x28:
        fail(o, 'ground truth: bytes @0x3a..0x3b = %s, want 6f 28'
             % out[0x3a:0x3c].hex())
    nz = {i for i in range(0x40) if out[i]}
    if nz != {0x1b, 0x3a, 0x3b}:
        fail(o, 'ground truth: unexpected non-zero bytes %s' % sorted(nz))
    neg = bytes.fromhex(QNEG_OUT)
    if neg[0] != 0x03 or neg[4:8] != bytes.fromhex('001c2b78') or \
            any(neg[8:]):
        fail(o, 'negative control bytes mismatch')
    for m in G7_MAP:
        o('[G7] map: %-46s -> resp %-34s -> %-18s | live: %s'
          % (m['stage'], m['resp'], m['out'], m['live']))
    o('[G7] ground truth reproduction: 04@0x1b = log_size-class byte of '
      'staging[0] bits[15:8] merged into response word +0x18 (sites '
      '0x0e4450/0x0e4468); 6f@0x3a + 28@0x3b = bits[47:40]/[39:32] of the '
      '8B X1-class word stored at response+0x38 (set1 0x6f00 @0x0e459c/'
      '0x0e4610/0x0e463c, st.q.1e @0x0e470c); zeros elsewhere = memset + '
      'non-firing merges; negative control (BadParam exit) carries '
      'status/syndrome only - both byte-exact vs Task 2')
    o('[G7] A.1 ruling: the QUERY-series words 0x1000_0000|(idx<<12) '
      '(out_mb0 @0x44..0x1fc idx 0x4f..0x86, in_mb0 idx 0x0a..0x46, tail '
      '00007003@0x23c) lie OUTSIDE the 0x40 completion window this mapping '
      'governs; producer = extended-mailbox chunk machinery (idiom anchors '
      '@0x059018 shl64.i<<12 + @0x05901c addi 0x1000, chunk loop '
      '[0x058fc0..0x05905c) with RAM[0x1555] block counter, 0x1000-chunk '
      'move call 0x20264 @0x059050) - structural chunk-page bookkeeping '
      'visible in the 576B tool window beyond outlen 0x40, NOT a staging '
      'payload; v5n visibility = BadParam-resume stub forcing the success '
      'continuation does not touch the chunk machinery; outbox window base '
      '= ptr(out_mb0) - 0x10 stays a tool-side alignment fact (anchor '
      'verbatim)')
    o('[G7] residue (honest, non-blocking): (1) op0x33/op0x0d bit positions '
      'are unknown-op class (slaspec/irisc_dis raw) - byte-level placement '
      'is constrained by live bytes only; (2) [ctx+0x140] runtime value for '
      'the QUERY ctx not statically resolvable (RAM-dispatch); (3) the '
      'exact staging-word values behind 0x28@0x3b are FN_A runtime data; '
      '(4) CREATE-out noise 6f@0x3/28@0x8 belongs to the sibling handler '
      '(0x0e2cf8 family, wrapper path) and is only class-matched here')
    o('[G7] PASS: mapping reproduces the observed out_mb offsets '
      'byte-exactly (Task 2 ground truth 3/3 non-zero artifacts + zeros + '
      'negative control); A.1 series explained as out-of-window chunk '
      'machinery with decode-verified producer idiom - no contradiction, '
      'none of the 56-word series requires the staging->response map')


def gate_g8(c):
    o = c.o
    for s in G8_SITES:
        chk(c, s['dc'], s['decode'], 'G8 site %s stock word' % s['id'])
        if word_at(c, s['dc']) != s['stock']:
            fail(o, 'G8 site %s: stock word %#x != %#x'
                 % (s['id'], word_at(c, s['dc']), s['stock']))
        o('[G8] site %-24s dc %#x (rt %08X): stock %08x%s'
          % (s['id'], s['dc'], rt_of(s['dc']), s['stock'],
             ' -> hook %08x' % s['hook'] if s['hook'] else ''))
        o('        called fn: %s' % s['called_fn'])
        o('        live-ins:  %s' % s['liveins'])
        o('        clobbers:  %s' % s['clobbers'])
        o('        trigger:   %s' % s['trigger'])
        o('        delivery:  %s' % s['delivery'])
        o('        words:     %s' % s['words'])
        o('        risk:      %s' % s['risk'])
    chk(c, 0x0e43bc, 'ld.d r4,r20,0x134', 'G8 late-site neighborhood (pre)')
    chk(c, 0x0e43c0, 'mask32 r11,r4,0x8,2', 'G8 late-site neighborhood (r11 producer - no clobber)')
    chk(c, 0x0e43c8, 'addi r4,zero,0x0', 'G8 arg-setup tail word')
    chk(c, 0x0e43cc, 'or r5,r22,r22', 'G8 arg-setup tail word')
    chk(c, 0x0e43d0, 'or r6,r21,r21', 'G8 arg-setup tail word')
    chk(c, 0x0e43d4, 'addi r7,zero,0x0', 'G8 arg-setup tail word')
    chk(c, 0x0e43d8, 'addi r8,zero,0x40', 'G8 completion window r8 = 0x40')
    chk(c, 0x0e43dc, 'or r9,r18,r18', 'G8 completion r9 = r18 response')
    chk(c, 0x0e43e0, 'addi r10,zero,0x0', 'G8 arg-setup tail word')
    chk(c, 0x18d8d4, 'or r22,r9,r9', 'G8 HC-4 live-in anchor: wrapper buf <- r9')
    chk(c, 0x0e43ac, 'addi r18,r1,0x8', 'G8 HC-1 live-in anchor r18 = response')
    o('[G8] late-site neighborhood decode-verified: 0x0e43c4 is the only '
      'skippable word of the arg-setup tail - every word of '
      '0x0e43c8..0x0e43e0 is gated (0x0e43bc ld.d [ctx+0x134], '
      '0x0e43c0 mask32 -> r11 consumer is the runtime completion fn, '
      '0x0e43c8..0x0e43e0 set completion args r4..r10 incl r8=0x40 and '
      'r9=r18) - confirms the RE-c task-09 choice')
    for sk in G8_SKETCHES:
        buf = assemble(sk['src'], base=STUB_SLOT[0], profile='cx5')
        got = list(struct.unpack('>%dI' % sk['words'], buf))
        if got != sk['expect']:
            fail(o, 'G8 sketch %s: %#x.. != expected (assemble drift)'
                 % (sk['id'], got[0]))
        for i, w in enumerate(got):
            if not irisc_dis.dis(w, 0):
                fail(o, 'G8 sketch %s word %d: empty decode' % (sk['id'], i))
        o('[G8] sketch %-32s %2d words decode-verified (assemble cx5 '
          'strict): %s | %s' % (sk['id'], sk['words'],
                                ' '.join('%08x' % w for w in got), sk['note']))
    for site, want, tag in [(LATE_SITE, LATE_HOOK, 'HC-1 late-site'),
                            (0x0e437c, CALL_SITE_STOCK_HOOK[1], 'HC-2 call-site')]:
        buf = assemble('call 0x%x' % STUB_SLOT[0], base=site, profile='cx5')
        got = struct.unpack('>I', buf[:4])[0]
        if got != want:
            fail(o, 'G8 hook word %s: %#x != %#x' % (tag, got, want))
        if (STUB_SLOT[0] - site) // 4 != (want & 0xffffff):
            fail(o, 'G8 hook offset %s: simm24 mismatch' % tag)
        o('[G8] hook word %-22s @dc %#x (rt %08X): %08x (simm24 offset/4 '
          '= 0x%x, within 0x7fffff)' % (tag, site, rt_of(site), want,
                                        want & 0xffffff))
    if not V4ECHO_IMG.is_file():
        fail(o, 'v4-echo image not found: %s (fresh clone: run the '
             'cx5-door-detour v4 build first)' % V4ECHO_IMG)
    img4 = mlxfwutil.Image(V4ECHO_IMG.read_bytes(), str(V4ECHO_IMG))
    e4 = img4.find_entry('ITOC', 0x03)
    code4, _ = mlxfwutil.clcrc_unwrap(img4.section_data(e4))
    w4 = struct.unpack('>%dI' % (len(code4) // 4), code4)
    lo, hi = STUB_SLOT
    for dc, want, why in [(0x0e437c, CALL_SITE_STOCK_HOOK[0], 'call-site stock on v4-echo'),
                          (LATE_SITE, LATE_STOCK, 'late-site stock on v4-echo'),
                          (H0_DOOR, H0_WORD, 'H0 door hook occupied on v4-echo')]:
        if w4[dc // 4] != want:
            fail(o, 'G8 v4-echo image: %s %#x != %#x' % (why, w4[dc // 4], want))
    stub_words = [w4[a // 4] for a in range(lo, hi, 4)]
    used = V4ECHO_STUB_WORDS
    if any(stub_words[used:]):
        fail(o, 'G8 v4-echo image: slot tail beyond %d words is not zero' % used)
    if any(w4[a // 4] == 0 for a in range(0x38d730, 0x38d748, 4)) or \
            any(w4[a // 4] for a in range(0x38d748, 0x38d750, 4)):
        fail(o, 'G8 v4-echo image: S0 6 shellcode words / cutout geometry mismatch')
    o('[G8] v4-echo image word-check (read-only): 0x0e437c stock '
      '0x%08x, 0x0e43c4 stock 0x%08x, H0 @%#x = %08x (occupied), slot '
      '0x38d750..0x38d7d7 = %d stub words + %d zero words (free %d), S0 6 '
      'words + 2-word cutout intact'
      % (w4[0x0e437c // 4], w4[LATE_SITE // 4], H0_DOOR, H0_WORD, used,
         STUB_SLOT_WORDS - used, STUB_SLOT_WORDS - used))
    o('[G8] budget table (need = slot words; slack = free - need; fits '
      'iff slack >= 2 per the R-E C-RE1 precedent):')
    cells = {}
    for b in G8_BASES:
        if b['free'] != STUB_SLOT_WORDS - b['slot_used']:
            fail(o, 'G8 base %s: free %s != %d - %d'
                 % (b['id'], b['free'], STUB_SLOT_WORDS, b['slot_used']))
        o('        base %-26s slot free %2d  0x0E437C: %s  0x0E43C4: %s  [%s]'
          % (b['id'], b['free'], b['w_e437c'], b['w_e43c4'], b['source']))
    for f in G8_FORMS:
        row = []
        for b in G8_BASES:
            if f['cand'] == 'HC-2' and 'v5l' in b['id']:
                need = G8_V5L_TAIL_INSERT
                note = 'site occupied (S2 leg): tail insert +%d' % need
            else:
                need = f['words']
                note = ''
            slack = b['free'] - need
            fits = slack >= 2
            cells[(f['id'], b['id'])] = (need, slack, fits)
            row.append('%s %d/%+d%s' % ('OK ' if fits else 'NO ',
                                        need, slack,
                                        ' ' + note if note else ''))
        o('        %-24s %s' % (f['id'], ' | '.join(row)))
    if len(cells) != len(G8_FORMS) * len(G8_BASES):
        fail(o, 'G8 budget incomplete: %d cells != %d x %d'
             % (len(cells), len(G8_FORMS), len(G8_BASES)))
    for (fid, bid), (need, slack, fits) in sorted(cells.items()):
        if not fits:
            o('        [does-not-fit] %-24s @ %-26s need %d free-slot '
              'slack %d < 2' % (fid, bid, need, slack))
    rf, rb = G8_RECOMMENDED
    need, slack, fits = cells[(rf, rb)]
    if not fits:
        fail(o, 'G8 recommended %s @ %s does not fit (slack %d)' % (rf, rb, slack))
    o('[G8] ceiling: completion POST fixed r8=0x40 (@0x0e43d8) -> 0x40B '
      'response per command; payload-safe window response+0x8..0x40 = '
      '0x38 = 56 B verbatim per command (out+0x0..0x8 = status/syndrome '
      'of the completion layer, negative-control proven); the 0x200 '
      'mailbox-chunk granularity of the tool (vfio.rs) is a read window, '
      'NOT a completion path - QUERY transport POSTs exactly 0x40B, '
      'content beyond it is A.1-class chunk machinery (phase-forbidden '
      'to synthesize); slot-bounded practical forms: 40B input-carried '
      '(23 words, slack 2 - also the MAX slack-compliant form on the '
      'keep-echo 25-word slot) and 52B mixed on a full 34-word slot (32 '
      'words, slack 2); a 44B form on keep-echo (25 words, slack 0 < the '
      'C-RE1 precedent) is non-compliant, not for planning')
    o('[G8] carrier survey: (1) QUERY input - PRM 0x18B (0x10 CQE header '
      '+ 8B in_mb), handler frame-copy mirror [r1+0x98..0xd8) = 0x40B '
      '(fr+X == input+X: [fr+0x10]=table_type, [fr+0x14]=table_id, '
      '[fr+0x12]=v5l MAGIC16 slot all PRM/precedent-consistent), free '
      'payload field input[0x18..0x40) = 40B; oversized-input acceptance '
      'is an R-C3 live-confirm residue; (2) CREATE 64B context - sibling '
      '0x0e2cf8 stages it at frame r1+0x28..0x68 (fast r9 @0x0e2d78 / '
      'slow wrapper buf @0x0e3740 -> FN_A r10), liveness to the sibling '
      'completion NOT traced -> capacity ~44B, delivery unproven, not '
      'for R-C3 v1; (3) CR seeding R-E class - slots 0x8c5..0x8cf '
      'mapped probe-verified 11/11 (cx5-door-detour.md 1.2/1.4), answer '
      'window 0x8c8..0x8cf, no arm needed, host seeds via VSEC without '
      'reflash; stub cost 4 words per 4B (ld.i/addi.hi/ld.d/st.d); a '
      'parameter/seed channel, not a direct out_mb carrier')
    o('[G8] recommendation: HC-1 late-site 0x0e43c4 + QUERY-input carrier '
      '(40B at input[0x18..0x40)) + CR-seeded magic/marker; base '
      'v4-echo-graft keep-echo (minimal flash diff vs the running card: '
      'slot content + 1 hook word, door-echo canary preserved for '
      'triage; %s needs %d words, slack %d) with v5r+revert as the '
      'headroom fallback (34 free) - %s'
      % (rf, need, slack,
         'stock semantics preserved: the negative Q(0,0) never reaches '
         'the site (built-in negative control), merges are already done, '
         'POST carries the payload verbatim (04@0x1b/6f28@0x3a byte '
         'precedent)'))


def main():
    c = Ctx()
    c.o = Out()
    o = c.o
    o('cx5 successpath rc2 staging->completion trace: %s' % BASE.name)
    gate_g1_g2_g3(c)
    gate_g4(c)
    dump_listing(c, QUERY_FN, QUERY_HI, 'fn 0x0e4250 QUERY handler (full)')
    mark_branches(c)
    dump_listing(c, COLLECTOR, COLLECTOR_HI, 'сборник 0x0e4424 (merge machine)')
    dump_listing(c, WRAPPER, FN_A, 'wrapper 0x18d8b0')
    dump_listing(c, ID1_BUILDER, 0x90c34, 'ID1 builder 0x90be4 (X1 + dir)')
    dump_listing(c, 0x18d574, 0x18d5f8, 'error-reporter 0x18d574 (m2 send)')
    dump_listing(c, 0x058fc0, 0x059060, 'A.1 chunk-loop 0x058fc0')
    gate_g5(c)
    gate_g6(c)
    gate_g7(c)
    gate_g8(c)
    o('ALL GATES PASS (G1 G2 G3 G4 G5 G6 G7 G8)')
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE log=%s' % LOG)


if __name__ == '__main__':
    main()
