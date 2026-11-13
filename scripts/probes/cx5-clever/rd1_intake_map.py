#!/usr/bin/env python3
"""cx5-clever R-D1: intake registration RE map on ConnectX-5 FW 16.35.4030.

Offline RE gates for plan 2026-10-21-cx5-clever-rd Task 2 (extends the
rc2_staging_map.py precedent; spec 2026-10-21-cx5-clever-rd-design.md,
delivery-spec addendum A.1 is the G2 canon):
  [G1] base image md5 a8c60c90... + ITOC 0x03 MAIN_CODE clcrc round-trip
       + geometry (941936 words == 0x397dc0 B; dc unit = byte offset,
       rt = dc + 0x800000)
  [G2] X1-lookup chain word-by-word vs A.1: wrapper 0x18a668 (key_raw,
       assert 0xB744AD, idx:=0x11), dispatch 0x908dc (range assert,
       base 0xB88A68, computed tail-jump), table @0x388a68 (20 rt ptrs,
       [0x10..0x13]=0x89090c), stub 0x9090c (HB = (alu.0x7f(obj,r16) |
       0xBCC3F4000000) + (C<<4)), reader 0x90b28 (flag=1 hardcoded),
       X1 formula 0x90abc ([buf+0xc]<<6 | 0x8fc0, -1 => assert 0xB688A5,
       non-fatal), key->idx table @0x388ac0 (0x90740, key 0x12 -> 0x13)
  [G3] 0x90b7c xref census: exactly 40 callers; the 11 flag=0 writer
       sites decode-verified (writer classification input)
  [G4] transport signatures: m2 0x18064c(r4=dir,r5=obj,r6=C,r7=buf; dir==0
       -> POST 0x2ae98, else FETCH 0x2ac60), 0x2ae98(r4=X1,r5=buf)->0x2a154,
       0x2ac60 (csr 0x1d0/0x1c0/0x1c4 + GO 0x34 + 0x10e1 window),
       ID1-builder 0x90be4(r4=dir,r5=obj,r6=v,r7=buf) with v <- [entry+8]
       consumers (0x911d8, 0xd3648)
  [G5] de-registration 0xd3e1c-0xd3e3c ([entry+8]:=[entry+0xc]:=-1, +0/+4
       zeroed, POST via 0x90b7c flag=0) + REG_WRITER 0xd372c (zero old page
       via 0x90be4 + write 16B entry)
  [G6] intake/C-slot of OUR command: fn 0x0e4250 slow-path arg setup
       0x0e435c..0x0e437c — C = [r1+0xac]|0xff computed INTO REGISTER r8
       right before the hook site 0x0e437c (input[0x14] = table_id for
       QUERY 0x0932); FN_A 0x18d964 -> F_SYN 0x18eaf4 -> m2(dir=1 FETCH,
       obj, C, staging) @0x18eb40; F_SYN validation fail => BadParam
       syndrome 0x31c2b78 @0x18ebe0 (the live Q(0,0) negative); prologue
       ctx slots (r20=ctx, r21=ctx+0x40, r22=obj=[ctx+0x150],
       r17=[ctx+0x140] sink); sink calls (dir=1 FETCH frame-copy /
       dir=0 POST response) on both paths
  [G7] writer classification vs the QUERY path: mailbox state machine
       0x0e2130 (C=[ctx+0xa8]|0xff @0x0e23d4, msg-type idx select
       0x11..0x14 @0x0e240c-0x0e2468, entry FETCH @0x0e247c, registered
       bit1 check @0x0e2480, register via 0xd3fe4 @0x0e24a0) is called
       ONLY by CREATE 0x0e2cf8 (@0x0e2da4, struct=ctx+0x80) and sibling
       0x0e2970 (@0x0e2af8); fn 0x0e4250 body has ZERO writer calls =>
       none of the 11 sites executes door->0x0E437C on a stock QUERY;
       the C=table_id|0xff entry is registered by CREATE before the
       QUERY exists (live-consistent: query(created) success via F_SYN
       FETCH, query(0) -> C=0xff -> -1 -> garbage FETCH -> 0x31c2b78)
  [G8] 16B entry format: +0 flags (bit 0x200 in-use RMW @0xd3bd8-0xd3bf8),
       +2.b bit1 = registered (intake check @0x0e2480), +4 id (|0xfff
       compare vs page data @0x09107c-0x091090), +8 = v page FETCH-side
       (0x911d8/0xd3648/0x091078 consumers), +0xc = v page m2-lookup-side
       (0x90abc); -1 = unregistered on both v fields (de-reg G5)
  [G9] m2'-miss unified reason: stock X1 = 0x8FC0_0000_0000|(v<<6)|F with
       v = [entry+0xc] (FW-assigned ICMC va page, registry-only source);
       arithmetic m2' built va from host IOVA (w = IOVA>>6) — ICMC trace
       miss va=0x8fc018000040 (v5q invented w=0x600001) and v5n
       (w=out_mb0 IOVA>>6) 0-DMA => va != IOVA; F-member (alu.0x7f(obj,
       r16) low bits) and C-domain are NOT the miss cause (m2' has no
       lookup; F is sub-page)
  [G10] verdict (a) + stub sketch: C resolvable at the hook site as r8
       (zero extra words); 14-word sketch (magic filter + miss=stock
       FN_A/resume + hit=m2(0,obj,r8-C,buf=r1+0xb0)+res0+resume)
       assemble-verified cx5 strict @ base 0x38d774; budget 14/25
       (slack 11 >= 2, R-E C-RE1); landing window: table-mailbox
       [0x00..0x40) (marker at buf+0x00..), readback via follow-up plain
       query(created) F_SYN FETCH -> staging[0] bits[15:8] -> response
       +0x18 -> out_mb0+0x1b (byte-exact merge, live 04@0x1b precedent)
Log: build/cx5-clever-rd1.log
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
LOG = WT / 'build/cx5-clever-rd1.log'
BASE_MD5 = 'a8c60c90473078288b01009c7cad471b'
RAW_MD5 = 'bcfe0526b43de4abf324b5056f91c112'
RT = 0x800000
MAIN_WORDS = 941936
MAIN_BYTES = MAIN_WORDS * 4

X1_LOOKUP = 0x18a668
M2 = 0x18064c
QUERY_FN = 0x0e4250
FN_A = 0x18d964
F_SYN = 0x18eaf4
HOOK_SITE = 0x0e437c
RESUME = 0x8e4380
CREATE_FN = 0x0e2cf8
SIBLING_FN = 0x0e2970
STATE_MACHINE = 0x0e2130

WRITER_SITES = [0x4ec40, 0x169e4c, 0x31b2c8, 0x547a8, 0xd37d4, 0xd3890,
                0xd3954, 0xd3b38, 0xd3bf8, 0xd3e3c, 0xd3f24]

G2_CHAIN = [
    (0x18a680, 'shr r4,r7,0x12', 'lookup: key member C>>18'),
    (0x18a684, 'shl64.i r5,r7,0xe', 'lookup: C<<14'),
    (0x18a688, 'op0x0d r5,r5,r16 imm=0x8000', 'lookup: op0x0d member (A.1)'),
    (0x18a68c, 'or r4,r5,r4', 'lookup: key_raw compose'),
    (0x18a690, 'subsi r5,r4,0x4', 'lookup: key-4 domain gate'),
    (0x18a694, 'b.f.0x4 zero,0x18a6a0', 'lookup: >=4 -> error branch'),
    (0x18a698, 'addi r5,r4,0x11', 'lookup: idx = key+0x11'),
    (0x18a6a0, 'addi r4,zero,0x44ad', 'lookup: assert lo 0x44ad'),
    (0x18a6a4, 'addi.hi r6,r4,0xb7', 'lookup: assert ID 0xB744AD'),
    (0x18a6c0, 'addi r5,zero,0x11', 'lookup: forced idx 0x11 (error path)'),
    (0x18a6cc, 'call 0x90b28', 'lookup: -> reader wrapper'),
    (0x908ec, 'addi r5,r9,0x-1', 'dispatch: idx-1'),
    (0x908f0, 'subsi r7,r5,0x13', 'dispatch: range 0..0x13 gate'),
    (0x908f4, 'b.t.0x3 zero,0x9097c', 'dispatch: >0x13 -> assert branch'),
    (0x908f8, 'addi r7,zero,0x-7598', 'dispatch: base lo 0xFFFF8A68'),
    (0x908fc, 'addi.hi r7,r7,0xb9', 'dispatch: base 0xB88A68 (file 0x388a68)'),
    (0x90904, 'lw.r r5,r5,r7', 'dispatch: table[idx-1] load'),
    (0x90908, 'ret.r zero,r8,r5', 'dispatch: computed tail-jump to stub'),
    (0x9090c, 'alu.0x7f r4,r4,r16', 'stub 0x9090c: F member'),
    (0x90910, 'set3 r5,zero,0x0', 'stub: base [15:0]=0'),
    (0x90914, 'set2 r5,r5,0xf400', 'stub: base [31:16]=0xf400'),
    (0x90a50, 'set1 r5,r5,0xbcc3', 'stub: base [47:32]=0xbcc3'),
    (0x90a54, 'or r4,r4,r5', 'stub: HB |= base'),
    (0x90a58, 'shl64.i r5,r6,0x4', 'stub: C<<4'),
    (0x90a5c, 'add r4,r4,r5', 'stub: HB = F|base + (C<<4)'),
    (0x90b48, 'addi r22,r1,0x8', 'reader 0x90b28: 16B stack buf'),
    (0x90b4c, 'addi r4,zero,0x1', 'reader: flag=1 hardcoded (FETCH)'),
    (0x90b58, 'call 0x90b7c', 'reader: -> generic 16B op'),
    (0x90ad0, 'ld.d r6,r23,0xc', 'formula 0x90abc: r6 = [entry+0xc]'),
    (0x90ad4, 'subsi r5,r6,0x-1', 'formula: -1 check'),
    (0x90ad8, 'b.f.0x0 zero,0x90b04', 'formula: != -1 -> X1 compose'),
    (0x90ae8, 'addi r4,zero,0x-775b', 'formula: assert lo 0xFFFF88A5'),
    (0x90aec, 'addi.hi r8,r4,0xb7', 'formula: assert ID 0xB688A5'),
    (0x90af0, 'set3 r4,zero,0x8fd1', 'formula: assert subtype 0x8fd1'),
    (0x90b04, 'alu.0x7f r5,r4,r16', 'formula: F member'),
    (0x90b0c, 'shl64.i r4,r4,0x6', 'formula: v<<6'),
    (0x90b10, 'or r4,r5,r4', 'formula: F | (v<<6)'),
    (0x90b14, 'set1 r4,r4,0x8fc0', 'formula: X1 lane |= 0x8fc0'),
]

G4_TRANSPORT = [
    (M2, 'csr.r r3,csr0xbc', 'm2 0x18064c: prologue'),
    (0x180660, 'or r23,r7,r7', 'm2: r23 = buf (arg r7)'),
    (0x180664, 'or r22,r4,r4', 'm2: r22 = dir (arg r4)'),
    (0x180670, 'call 0x18a668', 'm2: -> X1-lookup(obj, C)'),
    (0x180674, 'subsi r5,r22,0x0', 'm2: dir test'),
    (0x18067c, 'or r5,r23,r23', 'm2: buf -> transport'),
    (0x180680, 'call 0x2ac60', 'm2: dir!=0 -> FETCH 0x2ac60'),
    (0x180688, 'or r5,r23,r23', 'm2: buf -> transport'),
    (0x18068c, 'addi r6,zero,0x0', 'm2: POST arg'),
    (0x180690, 'call 0x2ae98', 'm2: dir==0 -> POST 0x2ae98'),
    (0x2ae98, 'csr.r r3,csr0xbc', 'transport POST 0x2ae98: prologue'),
    (0x2aea4, 'addi r7,zero,0x1', 'POST: flags member 1<<27'),
    (0x2aea8, 'addi r8,zero,0x4', 'POST: flags member 4<<22'),
    (0x2aeac, 'call 0x2a154', 'POST: -> window writer 0x2a154'),
    (0x2ac60, 'set2 r6,zero,0x900', 'FETCH 0x2ac60: csr0x1d0 <- 0x900'),
    (0x2ac68, 'shrh r6,r4,0x0', 'FETCH: X1[63:32]'),
    (0x2ac6c, 'csr.w r6,zero,0x1c0', 'FETCH: csr0x1c0 <- X1 hi'),
    (0x2ac70, 'csr.w r4,zero,0x1c4', 'FETCH: csr0x1c4 <- X1 lo'),
    (0x2ac80, 'csr.w r6,zero,0x34', 'FETCH: GO csr0x34'),
    (0x2ac84, 'set2 r7,zero,0x10e0', 'FETCH: window 0x10e0 base'),
    (0x2ac88, 'set3 r7,r7,0x1', 'FETCH: window |1'),
    (0x2a154, 'addi r9,zero,0x2', 'window writer 0x2a154: GO 2'),
    (0x2a15c, 'shl64.i r9,r7,0x1b', 'window: flags r7<<27'),
    (0x2a160, 'shl64.i r7,r8,0x16', 'window: flags r8<<22'),
    (0x2a168, 'csr.w r8,zero,0x1d0', 'window: csr0x1d0 <- flags'),
    (0x2a16c, 'shrh r8,r4,0x0', 'window: X1 hi'),
    (0x2a170, 'csr.w r8,zero,0x1c0', 'window: csr0x1c0 <- X1 hi'),
    (0x2a174, 'csr.w r4,zero,0x1c4', 'window: csr0x1c4 <- X1 lo'),
    (0x2a184, 'set2 r8,r4,0x10e0', 'window: 0x10e0 window select'),
    (0x90be4, 'csr.r r3,csr0xbc', 'ID1-builder 0x90be4: prologue'),
    (0x90bf4, 'alu.0x7f r4,r5,r16', 'ID1: F member (obj, r16)'),
    (0x90bf8, 'mask32 r5,r6,0x0,0', 'ID1: v = arg r6 full word'),
    (0x90bfc, 'shl64.i r5,r5,0x6', 'ID1: v<<6'),
    (0x90c04, 'set1 r4,r4,0x8fc0', 'ID1: lane |= 0x8fc0'),
    (0x90c08, 'subsi r5,r8,0x0', 'ID1: dir test'),
    (0x90c14, 'call 0x2ac60', 'ID1: dir!=0 -> FETCH'),
    (0x90c24, 'call 0x2ae98', 'ID1: dir==0 -> POST'),
]

G5_DEREG = [
    (0xd3e1c, 'addi r4,zero,0x-1', 'de-reg: -1 constant'),
    (0xd3e20, 'st.d r4,r20,0xc', 'de-reg: [entry+0xc] := -1'),
    (0xd3e24, 'st.d r4,r20,0x8', 'de-reg: [entry+8] := -1'),
    (0xd3e28, 'ld.d r6,r23,0x4', 'de-reg: idx <- [struct+4]'),
    (0xd3e2c, 'ld.q.17 r7,r23,0x8', 'de-reg: m <- [struct+8]'),
    (0xd3e30, 'addi r4,zero,0x0', 'de-reg: flag=0 (WRITE)'),
    (0xd3e3c, 'call 0x90b7c', 'de-reg: POST 16B entry'),
    (0xd3748, 'or r23,r8,r8', 'REG_WRITER 0xd372c: entry buf (arg r8)'),
    (0xd374c, 'or r22,r6,r6', 'REG_WRITER: idx (arg r6)'),
    (0xd3750, 'or r21,r4,r4', 'REG_WRITER: obj (arg r4)'),
    (0xd37a0, 'ld.d r6,r1,0x54', 'REG_WRITER: old v from frame+0x54'),
    (0xd37ac, 'addi r4,zero,0x0', 'REG_WRITER: dir=0 POST'),
    (0xd37b4, 'call 0x90be4', 'REG_WRITER: zero old page POST'),
    (0xd3bc4, 'addi r4,zero,0x1', 'REG_WRITER: FETCH entry flag=1'),
    (0xd3bd4, 'call 0x90b7c', 'REG_WRITER: read 16B entry'),
    (0xd3bd8, 'ld.d r4,r1,0x18', 'REG_WRITER: entry+0 read'),
    (0xd3bdc, 'set3 r4,r4,0x200', 'REG_WRITER: entry+0 |= 0x200 (in-use)'),
    (0xd3bf8, 'call 0x90b7c', 'REG_WRITER: write entry back (flag=0)'),
]

G6_INTAKE = [
    (0x0e4250, 'csr.r r3,csr0xbc', 'fn 0x0e4250: QUERY 0x0932 handler prologue'),
    (0x0e4278, 'or r20,r4,r4', 'QUERY: r20 = ctx (arg r4)'),
    (0x0e427c, 'addi r23,r20,0x80', 'QUERY: r23 = ctx+0x80'),
    (0x0e4280, 'addi r21,r20,0x40', 'QUERY: r21 = ctx+0x40 (sink keys struct)'),
    (0x0e4284, 'ld.d r22,r20,0x150', 'QUERY: obj = [ctx+0x150]'),
    (0x0e4290, 'ld.d r17,r20,0x140', 'QUERY: r17 = [ctx+0x140] (sink fnptr)'),
    (0x0e429c, 'addi r9,r1,0x98', 'QUERY: fast-path buf = frame copy'),
    (0x0e42b8, 'ret.r zero,zero,r17', 'QUERY: fast sink tail call'),
    (0x0e435c, 'ld.w r9,r1,0x9a', 'QUERY: r9 = [fr+0x2].w (input[2])'),
    (0x0e4360, 'ld.b r7,r1,0xa8', 'QUERY: r7 = [fr+0x18].b (input[0x18])'),
    (0x0e4364, 'ld.d r6,r1,0x50', 'QUERY: r6 = serialize out'),
    (0x0e4368, 'ld.d r4,r1,0xac', 'QUERY: r4 = [fr+0x14] = input[0x14] = table_id'),
    (0x0e436c, 'or r8,r4,0xff', 'QUERY: r8 = C = table_id|0xff (hook-site live)'),
    (0x0e4370, 'addi r10,r1,0x58', 'QUERY: staging r10 = r1+0x58'),
    (0x0e4374, 'addi r4,zero,0x0', 'QUERY: FN_A mode 0'),
    (0x0e4378, 'or r5,r22,r22', 'QUERY: FN_A obj'),
    (HOOK_SITE, 'call 0x%x' % FN_A, 'QUERY: HOOK SITE call FN_A (r8 = C live)'),
    (0x0e43c8, 'addi r4,zero,0x0', 'QUERY: completion dir=0 (POST)'),
    (0x0e43cc, 'or r5,r22,r22', 'QUERY: completion obj'),
    (0x0e43d0, 'or r6,r21,r21', 'QUERY: completion r6 = ctx+0x40 ptr'),
    (0x0e43d8, 'addi r8,zero,0x40', 'QUERY: completion len 0x40'),
    (0x0e43dc, 'or r9,r18,r18', 'QUERY: completion buf = response'),
    (0x0e43e4, 'ret.r zero,zero,r17', 'QUERY: completion sink tail call'),
    (FN_A, 'csr.r r3,csr0xbc', 'FN_A 0x18d964: prologue'),
    (0x18da00, 'or r8,r19,r19', 'FN_A: r8 = C (pass-through)'),
    (0x18da08, 'or r10,r18,r18', 'FN_A: r10 = staging'),
    (0x18da0c, 'call 0x%x' % F_SYN, 'FN_A: -> F_SYN'),
    (F_SYN, 'csr.r r3,csr0xbc', 'F_SYN 0x18eaf4: prologue'),
    (0x18eb18, 'or r20,r10,r10', 'F_SYN: buf'),
    (0x18eb28, 'or r22,r5,r5', 'F_SYN: obj'),
    (0x18eb30, 'addi r4,zero,0x1', 'F_SYN: dir=1 FETCH'),
    (0x18eb38, 'or r6,r8,r8', 'F_SYN: C -> m2 arg'),
    (0x18eb3c, 'or r7,r20,r20', 'F_SYN: buf -> m2 arg'),
    (0x18eb40, 'call 0x%x' % M2, 'F_SYN: stock FETCH of our command input'),
    (0x18eb48, 'ld.b r5,r20,0x3', 'F_SYN: staging[3] check'),
    (0x18eb54, 'ld.w r5,r20,0x6', 'F_SYN: staging[6..8] check'),
    (0x18ebe0, 'set2 r4,zero,0x31c', 'F_SYN: BadParam syndrome hi 0x31c'),
    (0x18ebe4, 'set3 r4,r4,0x2b78', 'F_SYN: BadParam syndrome 0x31c2b78'),
]

G7_WRITERS = [
    (STATE_MACHINE, 'csr.r r3,csr0xbc', 'state machine 0x0e2130: prologue'),
    (0x0e2150, 'ld.d r21,r23,0x28', 'state machine: [struct+0x28] key source'),
    (0x0e23d4, 'ld.d r4,r23,0x28', 'state machine: key load'),
    (0x0e23d8, 'or r6,r4,0xff', 'state machine: C = [struct+0x28]|0xff'),
    (0x0e240c, 'addi r21,zero,0x11', 'state machine: idx default 0x11'),
    (0x0e2410, 'mask32 r9,r4,0x10,8', 'state machine: msg-type [23:16]'),
    (0x0e2414, 'subsi r4,r9,0x8', 'state machine: type<8 -> idx 0x11'),
    (0x0e2424, 'subsi r4,r9,0x11', 'state machine: type<0x11 -> idx 0x12'),
    (0x0e2430, 'subsi r4,r9,0x15', 'state machine: type<0x15 -> idx 0x13'),
    (0x0e243c, 'subsi r4,r9,0x17', 'state machine: type<0x17 -> idx 0x14'),
    (0x0e246c, 'addi r8,r1,0x1f0', 'state machine: entry buf'),
    (0x0e2470, 'addi r4,zero,0x1', 'state machine: flag=1 FETCH'),
    (0x0e247c, 'call 0x90b7c', 'state machine: entry FETCH (reader!)'),
    (0x0e2480, 'ld.b r4,r1,0x1f2', 'state machine: [entry+2].b registered bit'),
    (0x0e24ac, 'call 0xd3fe4', 'state machine: register (unregistered path)'),
    (0x0e24b4, 'ld.q.17 r4,r1,0x20', 'state machine: reuse path'),
    (0x0e24c0, 'call 0xd3c5c', 'state machine: already-registered handler'),
    (0x0e2d20, 'or r23,r4,r4', 'CREATE 0x0e2cf8: ctx (arg r4)'),
    (0x0e2d24, 'addi r22,r23,0x80', 'CREATE: struct = ctx+0x80'),
    (0x0e2da0, 'or r5,r22,r22', 'CREATE: struct -> state machine'),
    (0x0e2da4, 'call 0x%x' % STATE_MACHINE, 'CREATE: -> registration state machine'),
    (0x0e2da8, 'ld.d r4,r22,0x0', 'CREATE: struct flags after register'),
    (0x0e2af8, 'call 0x%x' % STATE_MACHINE, 'sibling 0x0e2970: -> state machine'),
]

G8_ENTRY = [
    (0x091204, 'ld.d r6,r5,0x8', 'entry fmt: v-source [entry+8] (0x911d8)'),
    (0x091220, 'call 0x90be4', 'entry fmt: FETCH page via v=[entry+8]'),
    (0xd3674, 'addi r8,r1,0x8', 'entry fmt: 0xd3648 entry buf'),
    (0xd3680, 'call 0x90b7c', 'entry fmt: 0xd3648 entry FETCH'),
    (0xd3684, 'ld.d r6,r1,0x10', 'entry fmt: v = [entry+8] (frame+0x10)'),
    (0xd3694, 'call 0x90be4', 'entry fmt: FETCH page via v'),
    (0x09107c, 'ld.d r4,r20,0x4', 'entry fmt: id field [struct+4]'),
    (0x091080, 'or r4,r4,0xfff', 'entry fmt: id |0xfff mask'),
    (0x091084, 'ld.d r5,r1,0x10', 'entry fmt: page data word'),
    (0x091088, 'or r5,r5,0xfff', 'entry fmt: page data |0xfff'),
    (0x09108c, 'subs r4,r5,r4', 'entry fmt: id vs page compare'),
    (0x09105c, 'ld.d r6,r20,0x8', 'entry fmt: v=[struct+8] -1 precheck'),
    (0x091060, 'subsi r4,r6,0x-1', 'entry fmt: -1 => unregistered skip'),
    (0x091078, 'call 0x90be4', 'entry fmt: FETCH via v (registered)'),
]

G10_SKETCH = dict(
    words=14,
    src=(
        'ld.w r6,r1,0xaa\n'
        'set2 r7,zero,0x55aa\n'
        'set3 r7,r7,0x55aa\n'
        'cmp38_eq32 r7,r6\n'
        'b.t.0x0 zero,hit\n'
        'call 0x18d964\n'
        'jump 0x8e4380\n'
        'lbl hit\n'
        'or r5,r22,r22\n'
        'or r6,r8,r8\n'
        'addi r7,r1,0xb0\n'
        'addi r4,zero,0x0\n'
        'call 0x18064c\n'
        'addi r4,zero,0x0\n'
        'jump 0x8e4380\n'),
    expect=[0x642600ab, 0x240755aa, 0x20e755aa, 0xe0e03002, 0xa0000003,
            0x94f80077, 0x95155afd, 0xfec5b008, 0xfd064008, 0x002700b0,
            0x00040000, 0x94f7cbab, 0x00040000, 0x95155af6],
    slot_lo=0x38d774, slot_free=25,
)


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


def dec_at(c, dc):
    return c.dec[dc // 4]


def word_at(c, dc):
    return c.words[dc // 4]


def chk(c, off, want, why):
    got = dec_at(c, off)
    if got != want:
        fail(c.o, '%s @0x%x: "%s" != "%s"' % (why, off, got, want))


def gate_g1(c):
    o = c.o
    buf = BASE.read_bytes()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail(o, 'base md5 mismatch')
    o('[G1] base md5 OK (%s, %d B)' % (BASE_MD5, len(buf)))
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', 0x03)
    raw = img.section_data(e)
    if hashlib.md5(raw).hexdigest() != RAW_MD5:
        fail(o, 'MAIN_CODE raw md5 mismatch')
    errs = mlxfwutil.clcrc_lines_errors(raw)
    if errs:
        fail(o, 'clcrc bad lines: %d' % len(errs))
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw:
        fail(o, 'clcrc round-trip mismatch')
    if len(code) != MAIN_BYTES or len(code) // 4 != MAIN_WORDS:
        fail(o, 'MAIN_CODE geometry: %#x B' % len(code))
    c.img, c.raw, c.code, c.tail = img, raw, code, tail
    c.n = MAIN_WORDS
    c.words = struct.unpack('>%dI' % c.n, code)
    c.dec = [irisc_dis.dis(w, i * 4) for i, w in enumerate(c.words)]
    o('[G1] clcrc round-trip OK: %d lines 0 bad-CRC, %d words (0x%x B); '
      'dc = byte offset, rt = dc + 0x%x' % (len(raw) // 68, c.n, MAIN_BYTES, RT))


def gate_g2(c):
    o = c.o
    for off, want, why in G2_CHAIN:
        chk(c, off, want, 'G2 chain ' + why)
    table = [word_at(c, 0x388a68 + i * 4) for i in range(21)]
    want_tbl = [0x8909a0, 0x8909d0, 0x890a00, 0x890a10, 0x89091c, 0x89091c,
                0x890a24, 0x890a34, 0x890a44, 0x89092c, 0x89092c, 0x890940,
                0x890940, 0x890a64, 0x89096c, 0x89096c, 0x89090c, 0x89090c,
                0x89090c, 0x89090c, 0x0]
    if table != want_tbl:
        fail(o, 'G2 dispatch table mismatch: %s' % [hex(x) for x in table])
    keyidx = [word_at(c, 0x388ac0 + i * 4) for i in range(0x14)]
    if keyidx[0x11] != 0x13:
        fail(o, 'G2 key->idx table: key 0x12 -> %#x != 0x13' % keyidx[0x11])
    o('[G2] X1-lookup chain word-by-word == A.1 (%d anchors): key_raw/'
      'domain assert 0xB744AD/idx+0x11, dispatch base 0xB88A68, table '
      '[0x10..0x13] all -> stub 0x9090c (rt 0x89090c), HB = (alu.0x7f(obj,'
      'r16)|0xBCC3F4000000)+(C<<4), reader flag=1 @0x90b4c, X1 = F|('
      '[entry+0xc]<<6)|0x8FC0_0000_0000, -1 => assert 0xB688A5/0x8fd1 '
      '(compose 0xFFFF88A5+0xB70000 verified), key->idx table 0x388ac0 '
      '(key 0x12 -> idx 0x13)' % len(G2_CHAIN))


def gate_g3(c):
    o = c.o
    callers = []
    for i, d in enumerate(c.dec):
        if d == 'call 0x90b7c':
            callers.append(i * 4)
    if len(callers) != 40:
        fail(o, 'G3: 0x90b7c caller census %d != 40' % len(callers))
    missing = [s for s in WRITER_SITES if s not in callers]
    if missing:
        fail(o, 'G3: writer sites missing from census: %s'
             % [hex(s) for s in missing])
    for s in WRITER_SITES:
        chk(c, s, 'call 0x90b7c', 'G3 writer site')
    o('[G3] 0x90b7c xref: exactly 40 callers; all 11 flag=0 writer sites '
      'present: %s' % ' '.join('%06x' % s for s in WRITER_SITES))
    o('      readers (flag=1): 0x90b58 (hardcoded), 0x4ec04, 0x0e247c '
      '(intake state machine), 0x18e8a8/0x18ead8 (idx 0x11 static) + census')


def gate_g4(c):
    o = c.o
    for off, want, why in G4_TRANSPORT:
        chk(c, off, want, 'G4 ' + why)
    o('[G4] transport signatures decode-verified (%d anchors): m2 0x18064c'
      '(r4=dir, r5=obj, r6=C, r7=buf) dir==0 -> POST 0x2ae98 / else FETCH '
      '0x2ac60; 0x2ae98(r4=X1, r5=buf) -> 0x2a154 (flags 1<<27|4<<22, csr '
      '0x1d0/0x1c0/0x1c4, window 0x10e0); 0x2ac60(r4=X1, r5=buf) csr 0x1d0'
      '<-0x900 + GO 0x34 + window 0x10e1; ID1-builder 0x90be4(r4=dir, '
      'r5=obj, r6=v, r7=buf) X1 = F|(v<<6)|0x8fc0 — v passed by caller '
      '(from [entry+8] at 0x911d8/0xd3648, from [entry+0xc] at 0x90abc)'
      % len(G4_TRANSPORT))


def gate_g5(c):
    o = c.o
    for off, want, why in G5_DEREG:
        chk(c, off, want, 'G5 ' + why)
    o('[G5] de-registration 0xd3e1c-0xd3e3c: [entry+8]:=[entry+0xc]:=-1 '
      '(+0/+4 zeroed by the memset at 0xd3e08-0xd3e18) POSTed via '
      '0x90b7c(flag=0, obj, idx=[struct+4], m=[struct+8]); REG_WRITER '
      '0xd372c = zero-old-page (0x90be4 POST of 0x3c zeros) + 16B entry '
      'write; in-use bit 0x200 RMW @0xd3bd8-0xd3bf8')


def gate_g6(c):
    o = c.o
    for off, want, why in G6_INTAKE:
        chk(c, off, want, 'G6 ' + why)
    o('[G6] intake/C-slot of OUR command (%d anchors): fn 0x0e4250 slow '
      'path computes C = [r1+0xac]|0xff INTO REGISTER r8 @0x0e4368-'
      '0x0e436c — [fr+0x14] = input[0x14] = table_id (QUERY 0x0932 '
      'inline), the |0xff key convention; the HOOK SITE 0x0e437c receives '
      'r8 = C live (also r1=frame, r20=ctx, r22=obj, r6=serialize-out, '
      'r7=[fr+0x18].b, r9=[fr+0x2].w, r10=staging); FN_A passes C through (r8->F_SYN r8) -> m2(dir=1 '
      'FETCH, obj, C, staging) @0x18eb40 — the stock in-side FETCH of our '
      'command; validation staging[3]/[6..8] vs (input[0x18].b, serialize '
      'out) -> mismatch = BadParam syndrome 0x31c2b78 @0x18ebe0 (the live '
      'Q(0,0) negative); ctx slots: r20=ctx, r21=ctx+0x40 (sink keys '
      'struct), r22=obj=[ctx+0x150], r17=[ctx+0x140] sink fnptr; sink '
      'calls: fast (dir=1 FETCH into frame copy) / success (dir=0 POST '
      'response, len 0x40) — the out-side transport of our command'
      % len(G6_INTAKE))


def gate_g7(c):
    o = c.o
    for off, want, why in G7_WRITERS:
        chk(c, off, want, 'G7 ' + why)
    body_writers = [a for a in WRITER_SITES if QUERY_FN <= a < 0x0e4800]
    if body_writers:
        fail(o, 'G7: writer sites inside the mailbox-handler cluster: %s'
             % [hex(a) for a in body_writers])
    sm_callers = [i * 4 for i, d in enumerate(c.dec)
                  if d == 'call 0xe2130']
    if sorted(sm_callers) != [0x0e2af8, 0x0e2da4]:
        fail(o, 'G7: state machine callers %s != [0x0e2af8, 0x0e2da4]'
             % [hex(x) for x in sorted(sm_callers)])
    for probe in ('call 0xd3fe4', 'call 0xd372c'):
        in_query = [i * 4 for i, d in enumerate(c.dec)
                    if d == probe and QUERY_FN <= i * 4 < 0x0e4800]
        if in_query:
            fail(o, 'G7: %s inside handler cluster: %s'
                 % (probe, [hex(x) for x in in_query]))
    o('[G7] writer classification vs the QUERY path (door -> 0x0E437C): '
      'ZERO of the 11 flag=0 sites executes — fn 0x0e4250..0x0e4424 '
      'contains no writer calls (census both directions); the '
      'registration state machine 0x0e2130 (C=[ctx+0xa8]|0xff, msg-type '
      'idx select 0x11..0x14 all -> base 0xBCC3F4000000, entry FETCH '
      '0x0e247c, registered bit1 check [entry+2].b, register 0xd3fe4) is '
      'called ONLY by CREATE 0x0e2cf8 (@0x0e2da4, struct=ctx+0x80) and '
      'sibling 0x0e2970 (@0x0e2af8); => the C=table_id|0xff entry is '
      'registered by CREATE before our QUERY exists. Live-consistent: '
      'query(created) success (F_SYN FETCH resolves a valid entry), '
      'query(0) -> C=0xff -> -1 -> garbage FETCH -> 0x31c2b78; v5m TRIG '
      '(query0) POST miss harmless (A.1)')


def gate_g8(c):
    o = c.o
    for off, want, why in G8_ENTRY:
        chk(c, off, want, 'G8 ' + why)
    o('[G8] 16B entry format (all field anchors decode-verified): '
      '[+0x0] flags word (bit 0x200 in-use, RMW 0xd3bd8-0xd3bf8; zeroed '
      'by de-reg); [+0x2].b bit1 = registered (intake check @0x0e2480); '
      '[+0x4] id (compare |0xfff vs page data word @0x09107c-0x091090); '
      '[+0x8] v page FETCH-side — X1 source for direct-ID1 consumers '
      '(0x911d8 @0x091204-0x091220, 0xd3648 @0xd3684-0xd3694, '
      '0x091078); [+0xc] v page m2-lookup-side — X1 source in 0x90abc '
      '(the F_SYN/m2 path of our command); -1 = unregistered on either '
      'v field (assert 0xB688A5 on +0xc use, skip on +0x8 use); lane '
      '[47:32] of X1 = 0x8FC0 | (v>>26) — v top bits, F member = '
      'alu.0x7f(obj, r16) low bits (sub-page, runtime r16)')


def gate_g9(c):
    o = c.o
    chk(c, 0x90b14, 'set1 r4,r4,0x8fc0', 'G9 m2-lookup lane prefix')
    chk(c, 0x90c04, 'set1 r4,r4,0x8fc0', 'G9 ID1 lane prefix')
    chk(c, 0x90b0c, 'shl64.i r4,r4,0x6', 'G9 v<<6 (registry page)')
    chk(c, 0x90ad0, 'ld.d r6,r23,0xc', 'G9 v = [entry+0xc] (registry read)')
    o('[G9] m2-prime miss — unified reason: the stock X1 = 0x8FC0_0000_'
      '0000 | (v<<6) | F where v = [entry+0xc] is an FW-ASSIGNED ICMC va '
      'page whose ONLY source is the entry registry (writers: CREATE '
      'state machine / intake / de-reg); the arithmetic m2-prime (v5n/'
      'v5o/v5q) built va from host IOVA (w = IOVA>>6) — the hypothesis '
      '"ICMC va == host IOVA" is FALSE: v5q ICMC miss va=0x8fc018000040 '
      '(w=0x600001 invented, no translation) and v5n w=0x428b90 (out_mb0 '
      'IOVA>>6, MANAGE_PAGES-registered page) did 0 DMA — the tool pages '
      'live under FW-assigned va, not under their IOVA. F-member '
      '(alu.0x7f(obj,r16), sub-page low bits) and C-domain are NOT the '
      'miss cause (m2-prime does no lookup; F cannot fix a page-level '
      'translation miss). Verdict: v-page source = registry, not '
      'arithmetic')


def gate_g10(c):
    o = c.o
    sk = G10_SKETCH
    buf = assemble(sk['src'], base=sk['slot_lo'], profile='cx5')
    got = list(struct.unpack('>%dI' % sk['words'], buf))
    if got != sk['expect']:
        fail(o, 'G10 sketch: %s != expected' % [hex(w) for w in got[:4]])
    for i, w in enumerate(got):
        if not irisc_dis.dis(w, sk['slot_lo'] + i * 4):
            fail(o, 'G10 sketch word %d: empty decode' % i)
    if word_at(c, HOOK_SITE) != 0x9402a57a:
        fail(o, 'G10: stock call word @0x0e437c != 0x9402a57a')
    slack = sk['slot_free'] - sk['words']
    if slack < 2:
        fail(o, 'G10: budget slack %d < 2' % slack)
    o('[G10] VERDICT (a): C is resolvable at the hook site 0x0E437C — '
      'register r8 already holds the stock C = table_id|0xff (G6 chain '
      '0x0e4368-0x0e436c); stub sketch %d words assemble-verified (cx5 '
      'strict, base 0x%06x, decode-verify per word): %s'
      % (sk['words'], sk['slot_lo'], ' '.join('%08x' % w for w in got)))
    o('      w0-w4 magic filter (MAGIC16 @input[0x12] = [r1+0xaa], v5l '
      'canon, filter uses r6/r7 — r8 untouched); w5-w6 miss = stock FN_A '
      'call + resume (stock semantics); w7-w13 hit = or r5,r22,r22 (obj '
      'live) + or r6,r8,r8 (C — ZERO words spent deriving C) + addi '
      'r7,r1,0xb0 (buf = frame input copy [0xb0..0xf0) = input[0x18..'
      '0x58), marker p1..p3) + addi r4,zero,0x0 (dir=POST) + call '
      '0x18064c + res=0 + resume 0x8E4380')
    o('      budget: %d/%d free words @0x38d774 (v4-echo-graft slot), '
      'slack %d >= 2 (R-E C-RE1); TRIG must be query(created) so C = '
      'created_id|0xff is REGISTERED (query(0) -> C=0xff -> -1 -> v5m-'
      'class harmless garbage POST)' % (sk['words'], sk['slot_free'], slack))
    o('      landing window: m2 POST writes 0x40B buf -> the registered '
      'page X1 = F|(v_table<<6)|0x8FC0 = the flow-table mailbox '
      '(table-mailbox[0x00..0x40), marker at buf+0x00..); what the stock '
      'overwrites after resume: NOTHING in the table mailbox (the '
      'completion POST goes to the command out_mb via the ctx+0x40 keys, '
      'a different registration); READBACK channel: a follow-up plain '
      'query(created) runs the stock F_SYN FETCH of the SAME entry -> '
      'staging <- marker bytes -> сборник merge staging[0] bits[15:8] -> '
      'response+0x18 -> out_mb0+0x1b byte-exact (live 04@0x1b precedent, '
      'rc2 G7) + [0x18]-bitfields -> +0x1c/+0x20 — the second byte '
      'channel of phase R-D, independent of the XI completion site')


def main():
    c = Ctx()
    c.o = Out()
    o = c.o
    o('cx5-clever R-D1 intake registration map: %s' % BASE.name)
    gate_g1(c)
    gate_g2(c)
    gate_g3(c)
    gate_g4(c)
    gate_g5(c)
    gate_g6(c)
    gate_g7(c)
    gate_g8(c)
    gate_g9(c)
    gate_g10(c)
    o('ALL GATES PASS (G1 G2 G3 G4 G5 G6 G7 G8 G9 G10)')
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE log=%s' % LOG)


if __name__ == '__main__':
    main()
