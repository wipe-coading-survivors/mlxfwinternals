#!/usr/bin/env python3
"""cx5 door-detour R-E1 (Task 1): offline stub draft for ConnectX-5 FW
16.35.4030 - decode-verified words, word budget, hook patch, seed layout.

Phase R-E plan 2026-10-19-cx5-door-detour Task 1; door map canon
docs/superpowers/reports/cx5-icmd-door-rb1.md (H0 @dc 0x106390 stock
`call 0x1b15c' = 0x94fc5373, stub slot 0x38d750..0x38d7d7 = 34 words,
cutout 0x38d748..0x38d74f must stay zero, CR-window reserve canon rb1
1.5). Lx v3 precedent: scripts/probes/cx4lx-dumpcycle/build_dump_ra3.py.

B-stub (primary, channel B = reserve write-back), 19 of 34 words,
assembled strict with the cx5 profile (per-word decode-verify is built
into irisc_asm.assemble; G1 re-checks each word dis->re-assemble):

  dc 0x38d750 (rt 0xb8d750)
   0  csr.r r19,csr0xbc       link save (r19 dead: rb1 H0 clobber canon
                              "r19-r21 dead in REGACC"; gated: 0 r19
                              mentions in the site tail + emit wrapper)
   1  or r9,r8,r8             reg_id stash BEFORE the stock call - the
                              emit wrapper clobbers r4..r8 (rb1 3; full
                              body scanned: r9/r10/r11/r19 untouched)
   2  call 0x1b15c            stock emit FIRST (v3/Lx form; quintuplet
                              r4=class r5=level r6=str r7=is_flash
                              r8=reg_id still live at the hook word)
   3  ld.i r6,0x8c5           magic from the CR reserve (CR 0x2314)
   4  set2 r7,zero,0x4455     MAGIC 0x44554D31 ('DUM1', dump-module
   5  set3 r7,r7,0x4d31       default) - set-pair compose (rs=zero =
   6  cmp38_eq32 r7,r6        clean write); eq32 filter, funct5=2
   7  b.f.0xa zero,0x38d794   magic miss -> clean exit (link restore)
   8  set2 r7,zero,0x0        reg-id class check on the stashed r9:
   9  set3 r7,r7,0x9040       ICMD GET MTRC_CAP 0x9040 (dump-module
  10  cmp38_eq32 r7,r9        trigger). NOT addi: imm 0x9040 >= 0x8000
  11  b.f.0xa zero,0x38d794   sign-extends -> 0xffff9040 != reg_id
                              (reg-id miss -> clean exit)
  12  ld.i r3,0x8c6           dump address word (dc offset, CR 0x2318)
  13  addi.hi r3,r3,0x80      dc -> rt: +0x800000 (one word; no carry
                              risk: multiple of 0x10000)
  14  ld.d r5,r3,0x0          read ONE word at rt
  15  addi r4,zero,0x2320     response slot 0x8c8 (CR 0x2320 = 0x8c8*4;
  16  st.d r5,r4,0x0          imm < 0x8000 sign-safe; direct form per
                              stock flash-window idiom addi+ld.d/st.d
                              0x106184/0x106194 - WB walking-base is a
                              loop idiom, overhead for a single word)
  17  csr.w r19,zero,0xbc     <- miss-exit target: link restore
  18  ret.d zero,zero,zero    back to 0x106394

  Answer zone 0x8c8..0x8cf stays inside the reserve canon; 0x8d0/0x8d4
  (occupied, rb1 1.5) never touched. No subi/subsi anywhere in the stub
  -> the 4030 subi-inversion delta (rb1 5) cannot bite; the hi16-opcode
  door delta (rb1 1.6) does not touch the stub either (slot 0x8ff unused).

B2-stub (Task 5b v2, magic-only respin for H2a/H2c discrimination): v1
minus the r8-reg-id guard - the `or r9,r8,r8` stash and the 4-word class
filter (set2/set3 0x9040 + cmp38 + b.f) removed, magic check @0x8c5 is
the ONLY filter (grounding: Task 2 live negative-control - magic alone
holds against driver reg-traffic); miss-exit b.f retargets to the v2
link-restore word; store form identical word-for-word to v1 (direct
st.d to CR 0x2320). 14 of 34 words, slack 20. Gates G1b/G2b/G4b mirror
G1/G2/G4 and pin the one-variable discipline: v2 texts == v1 minus
exactly the 5 guard words (b.f retargeted), store/epilogue tail
bit-exact vs v1, zero r8/r9 mentions anywhere.

B3-stub (Task 5b v3, write-path canary per plan-fix 556c7a6 / ruling R12):
NO filter, NO loads - stock call 0x1b15c first (v3 form), then an
UNCONDITIONAL store of the constant 0x44554D32 ('DUM2') with the SAME
direct st.d form (same words) as v1/v2 to CR 0x2320 (word 0x8c8), link
restore, ret.d. Every H0 hit writes the constant. Settles write-path vs
(filter|load) in one burn: constant appears -> store form alive, culprit
is the magic filter or the dc->rt load (v4 targeted fix); absent ->
store form broken (v4 WB-walking-base). 8 of 34 words, slack 26.
Gates G1c/G2c/G4c mirror the G1/G2/G4 class + canary pins: zero loads
(no ld.i/ld.d), zero branches (unconditional), zero r8/r9, store words
bit-exact vs v1/v2, canary constant composed, magic filter absent.

B4-stub (Task 5b v4, echo per ruling R13): v2 minus the magic filter
(the 5 filter words ld.i r6,0x8c5/set2/set3/cmp38/b.f removed) - the
FULL seed->load->store data path with NO compare: stock call first, then
ld.i addr @0x8c6, dc->rt via addi.hi, ld.d ONE word, and the LOADED word
stored via the same direct st.d to CR 0x2320 (word 0x8c8). Data-path and
store words are bit-exact v2 (same operands, none pc-relative). Decision
table: seeded GT addr echoed as the GT word -> path works, culprit was
the magic filter (R12-i); other non-zero -> addr-read broken; zero ->
load broken or loaded word is 0 (R12-ii). 9 of 34 words, slack 25.
Gates G1d/G2d/G4d mirror the G-class + echo pins: exactly v2 minus the 5
filter words, zero branches/compares, zero r8/r9 (r6/r7 unused too),
addr-seed read present, magic-seed read absent, store tail bit-exact vs
v2 AND v3.

B5-stub (Task 5b v5, two-slot filter-link probe per ruling R14 / plan-fix
03155fd): no compares, no branches, no ld.d - TWO echoes isolating the
filter links: (1) echo the ld.i-READ magic word @0x8c5 into 0x8c8
(the word is bit-exact the v1/v2 ld.i r6,0x8c5), (2) echo the BUILT
constant 0x44554D31 into 0x8c9, composed with the SAME set2/set3 pair
words as v1/v2 (set2 r7,zero,0x4455 + set3 r7,r7,0x4d31 - the exact
words whose silicon result is under test). Stores use the proven
addi-base + st.d form (0x2320 addi word bit-exact v1-v4). 11 of 34
words, slack 23. Gates G1e/G2e/G4e mirror the G-class + probe pins:
zero compares/branches/ld.d, ld.i r6,0x8c5 and the set-pair bit-exact
vs v1 AND v2, store bases CR 0x2320/0x2324, no addr-seed read.

B6-stub (Task 5b v6 FINAL per ruling R15): v2 with ONLY the filter link
replaced by the S2 live-proven construction (scripts/s2/build_s2.py:637-641,
v5b/v5m prefix - ran live on THIS card in the v5q/v5r cycle): the compare
takes the LOADED value FIRST and the constant SECOND
(cmp38_sel(2, loaded, const) == our cmp38_eq32 r6,r7), and the constant is
a 16-bit set3 rs=zero write (the magic LOW halfword 0x4d31), not a 32-bit
set-pair. The S2 filter compared a zext BE halfword against set3-const16
with b_f.cc0A as the miss-exit - bit-identical branch form to ours.
Explaining hypothesis (recorded as hypothesis): the sel-2 predicate is
directional, pred = (rt == zext16(rs)) - S2 satisfies it, v1/v2 (const
first, both operands 0x44554D31) yield rt != zext16(rs) -> clean exit ->
the observed silence. 13 of 34 words, slack 21. Gates G1f/G2f/G4f mirror
the G-class + port pins: cmp word = cmp38_sel(2, 6, 7) form (loaded-first),
const word = set3 r7,zero,0x4d31 (S2 form), single b.f miss-exit, hit tail
bit-exact v2/v4, magic+addr seed reads, store CR 0x2320.

B7-stub (Task 5b v7, branch-direction probe per ruling R16): v6's exact
filter words (ld.i magic + set3-const16 + cmp38 loaded-first) followed by
a b.f whose target and fallthrough are two VISIBLE arms - no clean exit,
no filter semantics: ARM_HIT (the b.f target) stores 0xAAAA0001, ARM_MISS
(the fallthrough) stores 0xAAAA0002, both via the proven direct st.d to
CR 0x2320 (word 0x8c8), converging (jump) on link-restore + ret.d. 17 of
34 words, slack 17. Live read of 0x8c8 discriminates: 0xAAAA0001 =
branch TAKEN (pred false on equal operands - explains v1/v2/v6 silence),
0xAAAA0002 = branch NOT taken (pred true - filter should have worked),
0x00000000 = the branch landed outside both arms (anchor smoking gun).
Gates G1g/G2g/G4g mirror the G-class + G5 (NEW, R16): explicit
branch-target resolution from the ENCODED bits (anchor = the branch
word's own dc; branch tgt = dc + s16(field)*4; jump/call tgt = dc +
s24(field)*4 - irisc_asm.py:140-164 / irisc_dis.py:119-128, the same rule
enc.py:21 b_f used in the S2 live-proven filter) asserted == intended for
every pc-relative stub word, plus a pinned stock calibration guard branch
(b.f @0x8ed0 -> ret.d @0x8f00, the guard-to-function-exit idiom).

B8-stub (Task 5b v8, H-const vs H-dir discriminator per ruling R17):
v7 with ONE new word - the compare constant is built with an EXPLICIT
zero upper half: `set2 r7,zero,0x0` (clean hi write - the same live-
proven mechanism as v5's pair echo) chained with the v6/v7 `set3
r7,r7,0x4d31`; the set3/cmp38/b.f words are bit-exact v6/v7. Calibration:
stock has 12628 chained set2(rs=zero)+set3(rs=rd) pairs (3 with hi=0x0,
e.g. @0x4cbc set2 r5,zero,0x0 + set3 r5,r5,0xfffe) - the standard FW
32-bit-constant idiom; v5 live-proved the pair builds exactly. Decision:
seeded->0xAAAA0001 AND no-magic->0xAAAA0002 = H-const (branch now
conditional, filter fixable); both 0xAAAA0001 = H-dir (cc undriven);
seeded->0xAAAA0002 = inverted/directed compare. 18 of 34 words, slack 16.
Gates G1h/G2h/G4h mirror the G-class; G5 branch-target covers the new
pc-relative layout (call@1, b.f@6 -> ARM_HIT 0x38d780, jump@11 ->
ARM_JOIN 0x38d790).

B9-stub (Task 5b v9-F1 per ruling R21): the canonical sel-2/b.f filter
(v6/v8 words) with EXPLICIT cleaning of bits 63..32 of BOTH compare
operands - the eq64-with-dirty-upper hypothesis test. Width semantics
(docs/250-re/120-irisc/010-isa.md): registers are 64-bit; set0 writes bits 63..48, set1
47..32 (rs=zero = clean halfword write, low 32 untouched); set2/set3
write ONLY bits 31..0; ld.i writes the low 32 (upper stays post-emit
garbage). The constant is the FULL 32-bit magic (bit-exact the v1/v2
set-pair words): after both uppers are cleaned the operands are
0x0000000044554D31 == 0x0000000044554D31 - equal under ANY compare width
(eq64 and trunc32-eq alike), covering both readings of the canon-open
cmp.w width question. The arithmetic hit path (ld.i addr + addi.hi +
ld.d) is NOT cleaned - v4 proved it 32-bit-effective as-is. Decision:
answers with seed + silent without = eq64 confirmed, filter works ->
full C-RE4 battery; silent x2 = eq64 dead too -> BLOCKED. 18 of 34
words, slack 16. Gates G1i/G2i/G4i mirror the G-class + clean pins
(set1/set0 zero words on r6 AND r7 after their low-32 producers; cmp
word bit-exact v6/v7/v8; const pair bit-exact v1/v2; hit tail bit-exact
v2/v4; single b.f miss-exit; G5 layout).

B10-stub (Task 5b v10-F4 per ruling R22): v9 with ONLY the compare/
branch pair replaced by the VALIDATOR's own idiom - `subs r7,r7,r6`
(0xfce73005, the 0x1071bc form class fce72805: value diff = const -
magic, sets cc) + `b.f.0x2` (0xa4020006, the 0x1071c0 form class
a4020018: cc2 false = not-equal -> miss-exit; fallthrough = hit path).
A different compare op driving a different cc channel than the dead
cmp38/cc0a pair. All other 16 words bit-exact v9 (upper-cleaned
operands, full-magic const, v4 hit path). 18 of 34 words, slack 16.
Gates G1j/G2j/G4j mirror the G-class + validator-idiom pins (subs/b.f.0x2
word-form classes match the stock canon words; single branch; hit tail
bit-exact v4; G5 layout).

B11-stub (Task 5b v11-F2 per ruling R22): BRANCHLESS value-mask filter -
no branch instructions at all. Mask arithmetic (docs/250-re/120-irisc/010-isa.md semantics,
each word documented in the journal): diff = subs(const - magic)
(mod-2^32, 0 iff match) -> upper-clean both diff and its negation
(set1/set0) -> v = diff | -diff (or, 64-bit, inputs clean; bit31 = ne)
-> ne = v >> 31 (shr; clean input -> low32 = 0/1) -> mask = ne - 1
(subs with a 1-reg: 0xFFFFFFFF on match, 0 on miss) -> answer = loaded
& mask (ands; st.d stores the low 32 - v4/v5-proven exact). Prologue/
const/hit-path/store words bit-exact proven forms. Decision: seeded ->
GT word; no-seed -> 0 (mask kills the echo); else record. 24 of 34
words, slack 10. Gates G1k/G2k/G4k mirror the G-class + mask pins
(zero branches anywhere; the 10-word mask chain word-for-word; hit tail
bit-exact v4; G5 covers the single remaining pc-relative word - the
stock call).

B12-stub (Task 5b v12 per ruling R23 - FINAL filter attempt): v11 with
the upper-half cleanings (set1/set0 rs=zero) RESTORED on r6 AND r7
BEFORE the subs diff - the 64-bit-subs hypothesis test (v11 dropped
these cleans reasoning "mod-2^32"; if subs subtracts 64-bit, dirty
bits 63..32 made diff != 0 -> mask 0 -> the observed silence). With
clean inputs: diff = 0 iff fully equal -> ne = 0 -> mask = ne-1 =
0xFFFFFFFF on match / 0 on miss. The zero/one scratch regs (addi r8)
may carry dirty uppers - harmless: consumed by subs whose low-32 depends
only on input low-32s; the mask's own upper is irrelevant (st.d stores
the low 32 - proven). Cleanliness that MATTERS: first-subs inputs (r6,
r7), the or inputs (diff and negation - cleaned after their subs), the
shr input (v). 28 of 34 words, slack 6. Gates G1l/G2l/G4l mirror the
G-class + pins (v11 with exactly the 4 clean words inserted; mask chain
word-for-word; BRANCHLESS; G5 single pc-relative word).

C-stub (fallback, channel C = emit-class answer): ESTIMATE ONLY per the
brief (full assembly deferred until Task 2 picks C). Sketch = B prologue
+ filter (12 w) + read (3 w) + dead-rt-string second emit
(addi/addi.hi str compose 2, params or r7,r3 / or r8,r5, class/level
set2/addi, call 0x1b15c = 7 w; D1/emit7 precedent) + epilogue (2 w)
= 24 words (STUB_C_EST_WORDS); STUB_C_WORDS stays None until Task 3.

Hook patch (1 word @dc 0x106390): stock 0x94fc5373 `call 0x1b15c' ->
HOOK_WORD 0x940a1cf0 `call 0x38d750' (offset/4 = 0xA1CF0, simm24 fits).

SEED_LAYOUT: magic @0x8c5, addr-dc @0x8c6, N @0x8c7 (N=1 fixed for the
1-word dump; the stub does not read N), answer zone 0x8c8..0x8cf - the
same words the mlxscope dump module LAYOUT uses (crates/mlxscope).

Gates (in-script, log build/cx5-door-detour.log):
  [0] base md5 + MAIN_CODE geometry + stock hook site/context words +
      slot 34 w zero + cutout 2 w zero + r9/r19 liveness (REGACC tail +
      emit wrapper body scans)
  G1 every B word decode-verified (strict assemble + per-word
     dis->re-assemble bit-exact) + structure anchors + no-subi +
     placement inside the slot
  G2 budget: len(B) <= 32, C-estimate <= 32, slack >= 2 (slot 34)
  G3 hook: stock word verified against rb1 + patch word assembled and
     decode-verified, target 0x38d750
  G4 layout: all SEED_LAYOUT words inside the reserve canon, CR=word*4,
      answer zone 0x8c8..0x8cf, 0x8d0/0x8d4 unused, stub constants ==
      layout words (ld.i 0x8c5/0x8c6, st.d CR 0x2320)
  G1b/G2b/G4b: the same class of gates for STUB_B2_WORDS (v2) + the
      one-variable pin (exact v1->v2 word recipe, bit-exact store tail,
      no r8/r9, no 0x9040 constant)
  G1c/G2c/G4c: the same class of gates for STUB_B3_WORDS (v3 canary) +
      canary pins (zero loads, zero branches, store words bit-exact vs
      v1/v2, canary constant present, magic filter absent)
  G1d/G2d/G4d: the same class of gates for STUB_B4_WORDS (v4 echo) +
      echo pins (exactly v2 minus the 5 filter words, zero
      branches/compares, addr-seed read present, magic-seed read absent,
      store tail bit-exact vs v2 AND v3)
  G1e/G2e/G4e: the same class of gates for STUB_B5_WORDS (v5 probe) +
      probe pins (zero compares/branches/ld.d; ld.i r6,0x8c5 and the
      set2/set3 pair bit-exact vs v1 AND v2; stores to CR 0x2320/0x2324;
      no addr-seed read)
  G1f/G2f/G4f: the same class of gates for STUB_B6_WORDS (v6 final) +
      S2-port pins (cmp word = cmp38_sel(2,6,7) loaded-first form; const
      word = S2-form set3 rs=zero 16-bit; single b.f miss-exit; hit tail
      bit-exact v2/v4; v2 texts with only the filter link replaced)
  G1g/G2g/G4g: the same class of gates for STUB_B7_WORDS (v7 probe) +
      arm pins (both marker constants composed; single b.f/jump; v6
      filter words bit-exact; proven store form both arms)
  G5 branch-target resolution (R16): every pc-relative stub word
      resolved from the encoded bits (own-dc anchor, s16/s24*4) ==
      intended; pinned stock calibration (b.f 0x8ed0 -> ret.d 0x8f0)
  G1h/G2h/G4h: the same class of gates for STUB_B8_WORDS (v8 probe) +
      H-const pins (set2 zero-hi word chained before the bit-exact v6/v7
      set3+cmp words; arms/markers/stores as v7; G5 layout updated)
  G1i/G2i/G4i: the same class of gates for STUB_B9_WORDS (v9-F1) +
      upper-clean pins (set1/set0 zero words on r6 AND r7; const pair
      bit-exact v1/v2; cmp bit-exact v6/v7/v8; hit tail bit-exact v2/v4;
      G5 layout)
  G1j/G2j/G4j: the same class of gates for STUB_B10_WORDS (v10-F4) +
      validator-idiom pins (subs/b.f.0x2 word-form classes == stock
      0x1071bc/0x1071c0 canon; everything else bit-exact v9; G5 layout)
  G1k/G2k/G4k: the same class of gates for STUB_B11_WORDS (v11-F2) +
      branchless pins (ZERO branches anywhere; the 10-word mask chain
      word-for-word; const pair bit-exact v1/v2; hit tail bit-exact v4)
  G1l/G2l/G4l: the same class of gates for STUB_B12_WORDS (v12) +
      v11-with-cleans pins (exactly 4 inserted clean words; mask chain
      word-for-word; BRANCHLESS; hit tail bit-exact v4)
"""
import hashlib
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
import mlxfwutil
from scripts.irisc import assemble, disasm as dis
from scripts.irisc.profiles import load_profile

BASE = REPO / 'refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin'
LOG = REPO / 'build/cx5-door-detour.log'
BASE_MD5 = 'a8c60c90473078288b01009c7cad471b'
RT = 0x800000

SEC_ADDR = 0x1c748          # ITOC 0x03 MAIN_CODE (rb1 G2/G3 geometry)
SEC_SIZE = 0x3d15a0
MAIN_BYTES = 941936 * 4

HOOK_DC = 0x106390          # H0 (rb1 3): stock emit call site in REGACC
HOOK_STOCK_WORD = 0x94fc5373        # call 0x1b15c (rb1 G5/tsv row 600)
HOOK_STOCK_TARGET = 0x1b15c         # emit wrapper (reads r4..r8)
SITE_CTX = [                # quintuplet compose + post-site word (stock)
    (0x106378, 0x0004ab27),         # addi r4,zero,0x-54d9  (str lo)
    (0x10637c, 0x088600b5),         # addi.hi r6,r4,0xb5    (str rt 0xb4ab27)
    (0x106380, 0x24040400),         # set2 r4,zero,0x400    (class 0x4000000)
    (0x106384, 0x00050001),         # addi r5,zero,0x1      (level 1)
    (0x106388, 0xfec7b008),         # or r7,r22,r22         (is_flash)
    (0x10638c, 0xfee8b808),         # or r8,r23,r23         (reg_id)
    (0x106394, 0x4a0408fd),         # ld.i r4,0x8fd         (tail head)
]
REGACC_FN = 0x106350        # reg-access fn (contains H0; rb1 1.4)
EMIT_WRAPPER = 0x1b15c      # emit wrapper prologue: csr.r r3,csr0xbc

STUB_SLOT_DC = 0x38d750     # stub slot: 34 words (plan GC)
STUB_SLOT_WORDS = 34
STUB_MAX_WORDS = 32         # stub <= 32, slack >= 2 (plan GC)
SLACK_MIN = 2
CUTOUT = (0x38d748, 0x38d74f)       # must stay zero (plan GC)
S0_ZONE = (0x38d730, 0x38d747)      # S0 shellcode area (Task 3 builder)

MAGIC = 0x44554D31          # 'DUM1' (dump-module LAYOUT default)
CANARY = 0x44554D32         # 'DUM2' (v3 write-path canary constant)
REG_ID = 0x9040             # ICMD GET MTRC_CAP (dump-module trigger)

W_MAGIC = 0x8c5             # seed words (CR-window reserve canon rb1 1.5)
W_ADDR = 0x8c6
W_COUNT = 0x8c7
W_RESP = 0x8c8
RESP_ZONE = (0x8c8, 0x8cf)
RESERVE_CANON = [(0x8c5, 0x8cf), (0x8d1, 0x8d3), (0x8d5, 0x8f9), (0x8fe, 0x8fe)]
RESERVE_FORBIDDEN = (0x8d0, 0x8d4)  # occupied (rb1 1.5), never use

LINK_REG = 19               # link stash (rb1: r19-r21 dead in REGACC)
SCRATCH_REG = 9             # reg_id stash (rb1: r9-r11 unused; wrapper-safe)

SEED_LAYOUT = {
    'magic':   {'word': W_MAGIC, 'cr': W_MAGIC * 4, 'value': MAGIC},
    'addr_dc': {'word': W_ADDR, 'cr': W_ADDR * 4},
    'count_n': {'word': W_COUNT, 'cr': W_COUNT * 4, 'value': 1},
    'resp':    {'word': W_RESP, 'cr': W_RESP * 4,
                'zone_words': list(range(RESP_ZONE[0], RESP_ZONE[1] + 1)),
                'zone_cr': (RESP_ZONE[0] * 4, RESP_ZONE[1] * 4)},
}

STUB_C_EST_WORDS = 24       # sketch below; assembled only if Task 2 picks C
STUB_C_SKETCH = [
    'csr.r r%d,csr0xbc' % LINK_REG,
    'or r%d,r8,r8' % SCRATCH_REG,
    'call 0x%x' % HOOK_STOCK_TARGET,
    'ld.i r6,0x%x' % W_MAGIC,
    'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
    'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
    'cmp38_eq32 r7,r6',
    'b.f.0xa zero,<out>',
    'set2 r7,zero,0x0',
    'set3 r7,r7,0x%x' % REG_ID,
    'cmp38_eq32 r7,r9',
    'b.f.0xa zero,<out>',
    'ld.i r3,0x%x' % W_ADDR,
    'addi.hi r3,r3,0x80',
    'ld.d r5,r3,0x0',
    'addi r6,zero,<str-lo>',           # dead rt string (TBD: Task 2/3 RE)
    'addi.hi r6,r6,<str-hi>',
    'or r7,r3,r3',                     # emit param: addr echo
    'or r8,r5,r5',                     # emit param: answer value
    'set2 r4,zero,0x400',
    'addi r5,zero,0x1',
    'call 0x%x' % HOOK_STOCK_TARGET,   # second emit: D1/emit7 analog
    'csr.w r%d,zero,0xbc' % LINK_REG,  # <out
    'ret.d zero,zero,zero',
]
STUB_C_WORDS = None         # estimate only (brief Step 2); Task 3 fills it

OUT_DC = STUB_SLOT_DC + 4 * 17      # miss-exit = link-restore word
OUT2_DC = STUB_SLOT_DC + 4 * 12     # v2 miss-exit = its link-restore word
OUT6_DC = STUB_SLOT_DC + 4 * 11     # v6 miss-exit = its link-restore word
ARM_HIT_DC = STUB_SLOT_DC + 4 * 11  # v7 b.f target arm (marker 0xAAAA0001)
ARM_JOIN_DC = STUB_SLOT_DC + 4 * 15  # v7 arm convergence (link restore)
ARM_HIT_MARK = 0xAAAA0001           # v7 b.f-taken marker
ARM_MISS_MARK = 0xAAAA0002          # v7 fallthrough marker
ARM8_HIT_DC = STUB_SLOT_DC + 4 * 12  # v8 b.f target arm (one word bigger)
ARM8_JOIN_DC = STUB_SLOT_DC + 4 * 16  # v8 arm convergence (link restore)
OUT9_DC = STUB_SLOT_DC + 4 * 16     # v9 miss-exit = its link-restore word
OUT10_DC = STUB_SLOT_DC + 4 * 16    # v10 miss-exit = its link-restore word

def stub_b_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'or r%d,r8,r8' % SCRATCH_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'cmp38_eq32 r7,r6',
        'b.f.0xa zero,0x%x' % OUT_DC,
        'set2 r7,zero,0x0',
        'set3 r7,r7,0x%x' % REG_ID,
        'cmp38_eq32 r7,r9',
        'b.f.0xa zero,0x%x' % OUT_DC,
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


def _words(text, base):
    prof = load_profile('cx5')
    data = assemble(text, base=base, profile=prof, strict=True)
    return list(struct.unpack('>%dI' % (len(data) // 4), data))


STUB_B_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                enumerate(_words(stub_b_text(), STUB_SLOT_DC))]
HOOK_WORD = _words('call 0x%x' % STUB_SLOT_DC, HOOK_DC)[0]


def stub_b2_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'cmp38_eq32 r7,r6',
        'b.f.0xa zero,0x%x' % OUT2_DC,
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B2_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                 enumerate(_words(stub_b2_text(), STUB_SLOT_DC))]


def stub_b3_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'set2 r5,zero,0x%x' % ((CANARY >> 16) & 0xffff),
        'set3 r5,r5,0x%x' % (CANARY & 0xffff),
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B3_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                 enumerate(_words(stub_b3_text(), STUB_SLOT_DC))]


def stub_b4_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B4_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                 enumerate(_words(stub_b4_text(), STUB_SLOT_DC))]


def stub_b5_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r6,r4,0x0',
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'addi r4,zero,0x%x' % ((W_RESP + 1) * 4),
        'st.d r7,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B5_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                 enumerate(_words(stub_b5_text(), STUB_SLOT_DC))]


def stub_b6_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set3 r7,zero,0x%x' % (MAGIC & 0xffff),
        'cmp38_eq32 r6,r7',
        'b.f.0xa zero,0x%x' % OUT6_DC,
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B6_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                 enumerate(_words(stub_b6_text(), STUB_SLOT_DC))]


def stub_b7_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set3 r7,zero,0x%x' % (MAGIC & 0xffff),
        'cmp38_eq32 r6,r7',
        'b.f.0xa zero,0x%x' % ARM_HIT_DC,
        'set2 r5,zero,0x%x' % ((ARM_MISS_MARK >> 16) & 0xffff),
        'set3 r5,r5,0x%x' % (ARM_MISS_MARK & 0xffff),
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'jump 0x%x' % ARM_JOIN_DC,
        'set2 r5,zero,0x%x' % ((ARM_HIT_MARK >> 16) & 0xffff),
        'set3 r5,r5,0x%x' % (ARM_HIT_MARK & 0xffff),
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B7_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                 enumerate(_words(stub_b7_text(), STUB_SLOT_DC))]


def stub_b8_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set2 r7,zero,0x0',
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'cmp38_eq32 r6,r7',
        'b.f.0xa zero,0x%x' % ARM8_HIT_DC,
        'set2 r5,zero,0x%x' % ((ARM_MISS_MARK >> 16) & 0xffff),
        'set3 r5,r5,0x%x' % (ARM_MISS_MARK & 0xffff),
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'jump 0x%x' % ARM8_JOIN_DC,
        'set2 r5,zero,0x%x' % ((ARM_HIT_MARK >> 16) & 0xffff),
        'set3 r5,r5,0x%x' % (ARM_HIT_MARK & 0xffff),
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B8_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                 enumerate(_words(stub_b8_text(), STUB_SLOT_DC))]


def stub_b9_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set1 r6,zero,0x0',
        'set0 r6,zero,0x0',
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'set1 r7,zero,0x0',
        'set0 r7,zero,0x0',
        'cmp38_eq32 r6,r7',
        'b.f.0xa zero,0x%x' % OUT9_DC,
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B9_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                 enumerate(_words(stub_b9_text(), STUB_SLOT_DC))]


def stub_b10_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set1 r6,zero,0x0',
        'set0 r6,zero,0x0',
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'set1 r7,zero,0x0',
        'set0 r7,zero,0x0',
        'subs r7,r7,r6',
        'b.f.0x2 zero,0x%x' % OUT10_DC,
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B10_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                  enumerate(_words(stub_b10_text(), STUB_SLOT_DC))]


def stub_b11_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'subs r7,r7,r6',
        'set1 r7,zero,0x0',
        'set0 r7,zero,0x0',
        'addi r8,zero,0x0',
        'subs r8,r8,r7',
        'set1 r8,zero,0x0',
        'set0 r8,zero,0x0',
        'or r7,r7,r8',
        'shr r7,r7,0x1f',
        'addi r8,zero,0x1',
        'subs r7,r7,r8',
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'ands r5,r5,r7',
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B11_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                  enumerate(_words(stub_b11_text(), STUB_SLOT_DC))]


def stub_b12_text():
    return '\n'.join([
        'csr.r r%d,csr0xbc' % LINK_REG,
        'call 0x%x' % HOOK_STOCK_TARGET,
        'ld.i r6,0x%x' % W_MAGIC,
        'set1 r6,zero,0x0',
        'set0 r6,zero,0x0',
        'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
        'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
        'set1 r7,zero,0x0',
        'set0 r7,zero,0x0',
        'subs r7,r7,r6',
        'set1 r7,zero,0x0',
        'set0 r7,zero,0x0',
        'addi r8,zero,0x0',
        'subs r8,r8,r7',
        'set1 r8,zero,0x0',
        'set0 r8,zero,0x0',
        'or r7,r7,r8',
        'shr r7,r7,0x1f',
        'addi r8,zero,0x1',
        'subs r7,r7,r8',
        'ld.i r3,0x%x' % W_ADDR,
        'addi.hi r3,r3,0x80',
        'ld.d r5,r3,0x0',
        'ands r5,r5,r7',
        'addi r4,zero,0x%x' % (W_RESP * 4),
        'st.d r5,r4,0x0',
        'csr.w r%d,zero,0xbc' % LINK_REG,
        'ret.d zero,zero,zero',
    ])


STUB_B12_WORDS = [(STUB_SLOT_DC + 4 * i, w) for i, w in
                  enumerate(_words(stub_b12_text(), STUB_SLOT_DC))]


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


def fail(o, msg):
    o('FATAL: ' + msg)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
    sys.exit(1)


def w32be(b, o):
    return struct.unpack_from('>I', b, o)[0]


def dc_to_raw(dc):
    line, within = divmod(dc, 64)
    return SEC_ADDR + line * 68 + within


def dw(buf, dc):
    return w32be(buf, dc_to_raw(dc))


def dd(buf, dc):
    return dis(dw(buf, dc), dc)


def fn_end_dc(buf, start, bound=0x400):
    dc = start
    while dc < start + bound:
        if dd(buf, dc).startswith('ret.'):
            return dc
        dc += 4
    return None


def reg_mentions(buf, lo, hi, reg):
    hits = []
    for dc in range(lo, hi + 4, 4):
        if ('r%d,' % reg) in dd(buf, dc) or dd(buf, dc).endswith(',r%d' % reg) \
                or (',r%d,' % reg) in dd(buf, dc):
            hits.append((dc, dd(buf, dc)))
    return hits


def in_reserve(word):
    return any(lo <= word <= hi for lo, hi in RESERVE_CANON)


def prelude(o, buf):
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail(o, 'base md5 mismatch')
    img = mlxfwutil.Image(bytes(buf), str(BASE))
    e = img.find_entry('ITOC', 0x03)
    if (e.addr, e.size, e.clcrc) != (SEC_ADDR, SEC_SIZE, 1):
        fail(o, 'MAIN_CODE header mismatch: addr=0x%x size=0x%x clcrc=%d'
             % (e.addr, e.size, e.clcrc))
    if dw(buf, HOOK_DC) != HOOK_STOCK_WORD or dd(buf, HOOK_DC) != \
            'call 0x%x' % HOOK_STOCK_TARGET:
        fail(o, 'hook site word 0x%08x (%s) is not the stock rb1 H0 word'
             % (dw(buf, HOOK_DC), dd(buf, HOOK_DC)))
    for dc, want in SITE_CTX:
        if dw(buf, dc) != want:
            fail(o, 'site context word dc 0x%x: 0x%08x != 0x%08x'
                 % (dc, dw(buf, dc), want))
    if dd(buf, EMIT_WRAPPER) != 'csr.r r3,csr0xbc':
        fail(o, 'emit wrapper prologue changed')
    slot_zero = all(dw(buf, STUB_SLOT_DC + 4 * i) == 0
                    for i in range(STUB_SLOT_WORDS))
    cutout_zero = all(dw(buf, dc) == 0 for dc in
                      range(CUTOUT[0], CUTOUT[1] + 1, 4))
    if not slot_zero or not cutout_zero:
        fail(o, 'slot/cutout not zero on the stock base')
    tail_end = fn_end_dc(buf, HOOK_DC + 4)
    if tail_end is None:
        fail(o, 'REGACC tail end not found')
    for reg in (LINK_REG, SCRATCH_REG):
        hits = reg_mentions(buf, HOOK_DC + 4, tail_end, reg)
        if hits:
            fail(o, 'r%d live in REGACC tail 0x%x..0x%x: %s'
                 % (reg, HOOK_DC + 4, tail_end, hits))
    wrap_end = fn_end_dc(buf, EMIT_WRAPPER)
    if wrap_end is None:
        fail(o, 'emit wrapper end not found')
    wrap_hits = [r for r in (9, 10, 11, 19)
                 if reg_mentions(buf, EMIT_WRAPPER, wrap_end, r)]
    if wrap_hits:
        fail(o, 'emit wrapper touches stash regs %s' % wrap_hits)
    o('[0] base md5 OK; MAIN_CODE addr=0x%x size=0x%x clcrc=1; hook site '
      '0x%x=%08x "call 0x%x" + %d ctx words OK; emit wrapper prologue OK; '
      'slot %dw + cutout %dw zero; r%d/r%d: 0 mentions in REGACC tail '
      '0x%x..0x%x, 0 mentions in emit wrapper 0x%x..0x%x'
      % (SEC_ADDR, SEC_SIZE, HOOK_DC, HOOK_STOCK_WORD, HOOK_STOCK_TARGET,
         len(SITE_CTX), STUB_SLOT_WORDS,
         (CUTOUT[1] - CUTOUT[0] + 4) // 4, LINK_REG, SCRATCH_REG,
         HOOK_DC + 4, tail_end, EMIT_WRAPPER, wrap_end))
    return tail_end


def gate_g1(o):
    words = [w for _, w in STUB_B_WORDS]
    if len(words) != 19:
        fail(o, 'B stub is %d words, canonical draft is 19' % len(words))
    for i, (dc, w) in enumerate(STUB_B_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'word %d uses subi (4030 inversion delta): %s' % (i, text))
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'or r9,r8,r8',
               2: 'call 0x1b15c', 3: 'ld.i r6,0x8c5',
               7: 'b.f.0xa zero,0x%x' % OUT_DC,
               11: 'b.f.0xa zero,0x%x' % OUT_DC,
               16: 'st.d r5,r4,0x0', 17: 'csr.w r19,zero,0xbc',
               18: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'structure anchor %d: "%s" != "%s"' % (i, got, want))
    o('[G1] B stub: %d words, every word decode-verified (strict cx5 '
      'assemble + per-word dis->re-assemble bit-exact); structure anchors '
      'OK (link save / r9 stash / stock call first / both filter miss-exits '
      '-> 0x%x / direct answer store / link restore / ret.d); 0 subi words'
      % (len(STUB_B_WORDS), OUT_DC))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g1b(o):
    if len(STUB_B2_WORDS) != 14:
        fail(o, 'B2 stub is %d words, canonical v2 draft is 14'
             % len(STUB_B2_WORDS))
    if len(STUB_B2_WORDS) != len(STUB_B_WORDS) - 5:
        fail(o, 'one-variable drift: B2 %d words != v1 %d - 5 guard words'
             % (len(STUB_B2_WORDS), len(STUB_B_WORDS)))
    for i, (dc, w) in enumerate(STUB_B2_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B2 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B2 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B2 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B2 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'B2 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        for reg in (8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B2 word %d touches r%d (guard must be gone): %s'
                     % (i, reg, text))
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r6,0x8c5', 6: 'b.f.0xa zero,0x%x' % OUT2_DC,
               9: 'ld.d r5,r3,0x0', 11: 'st.d r5,r4,0x0',
               12: 'csr.w r19,zero,0xbc', 13: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B2_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B2 structure anchor %d: "%s" != "%s"' % (i, got, want))
    v1t = [dis(w, dc) for dc, w in STUB_B_WORDS]
    v2t = [dis(w, dc) for dc, w in STUB_B2_WORDS]
    recipe = [v1t[i] for i in (0, 2, 3, 4, 5, 6)] + \
        ['b.f.0xa zero,0x%x' % OUT2_DC] + [v1t[i] for i in range(12, 19)]
    if v2t != recipe:
        fail(o, 'B2 is not exactly v1 minus the 5 guard words (b.f '
             'retargeted): recipe delta')
    if [w for _, w in STUB_B2_WORDS][9:] != [w for _, w in STUB_B_WORDS][14:]:
        fail(o, 'B2 store/epilogue tail not bit-exact vs v1 (store form '
             'must be identical)')
    o('[G1b] B2 stub (v2 magic-only): %d words, every word decode-verified '
      '(strict cx5 assemble + per-word dis->re-assemble bit-exact); '
      'structure anchors OK (link save / stock call first / single filter '
      'miss-exit -> 0x%x / direct answer store / link restore / ret.d); '
      'one-variable pin: v1 texts minus exactly the 5 guard words (or r9 '
      'stash + set2/set3 0x%x/cmp38/b.f), b.f retargeted, store tail '
      'bit-exact vs v1; 0 r8/r9 mentions; 0 subi words'
      % (len(STUB_B2_WORDS), OUT2_DC, REG_ID))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B2_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2(o):
    n_b = len(STUB_B_WORDS)
    slack_b = STUB_SLOT_WORDS - n_b
    slack_c = STUB_SLOT_WORDS - STUB_C_EST_WORDS
    if n_b > STUB_MAX_WORDS or slack_b < SLACK_MIN:
        fail(o, 'B budget: %d words, slack %d (max %d, slack >= %d)'
             % (n_b, slack_b, STUB_MAX_WORDS, SLACK_MIN))
    if STUB_C_EST_WORDS > STUB_MAX_WORDS or slack_c < SLACK_MIN:
        fail(o, 'C estimate budget: %d words, slack %d (max %d, slack >= %d)'
             % (STUB_C_EST_WORDS, slack_c, STUB_MAX_WORDS, SLACK_MIN))
    if STUB_C_WORDS is not None:
        fail(o, 'C stub must stay an estimate in Task 1 (brief Step 2)')
    o('[G2] budget: B %d/%d words (slack %d), C estimate %d/%d words '
      '(slack %d); both <= %d with slack >= %d; STUB_C_WORDS is None '
      '(estimate only, assembled in Task 3 iff channel C is picked)'
      % (n_b, STUB_SLOT_WORDS, slack_b, STUB_C_EST_WORDS, STUB_SLOT_WORDS,
         slack_c, STUB_MAX_WORDS, SLACK_MIN))


def gate_g2b(o):
    n = len(STUB_B2_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B2 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2b] budget: B2 %d/%d words (slack %d; v1 was %d, -5 guard '
      'words); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, len(STUB_B_WORDS),
         STUB_MAX_WORDS, SLACK_MIN))


def gate_g1c(o):
    if len(STUB_B3_WORDS) != 8:
        fail(o, 'B3 canary is %d words, canonical v3 draft is 8'
             % len(STUB_B3_WORDS))
    for i, (dc, w) in enumerate(STUB_B3_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B3 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B3 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B3 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B3 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'B3 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        if text.startswith(('ld.i', 'ld.d', 'ld.w')):
            fail(o, 'B3 word %d loads (canary must not read anything): %s'
                 % (i, text))
        if text.startswith(('b.f', 'b.t', 'jump')):
            fail(o, 'B3 word %d branches (canary store is unconditional): '
                 '%s' % (i, text))
        if 'cmp38' in text or 'op0x38' in text:
            fail(o, 'B3 word %d compares (canary has no filter): %s'
                 % (i, text))
        for reg in (8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B3 word %d touches r%d: %s' % (i, reg, text))
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'set2 r5,zero,0x%x' % ((CANARY >> 16) & 0xffff),
               3: 'set3 r5,r5,0x%x' % (CANARY & 0xffff),
               4: 'addi r4,zero,0x%x' % (W_RESP * 4),
               5: 'st.d r5,r4,0x0', 6: 'csr.w r19,zero,0xbc',
               7: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B3_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B3 structure anchor %d: "%s" != "%s"' % (i, got, want))
    b3 = [w for _, w in STUB_B3_WORDS]
    v1_tail = [w for _, w in STUB_B_WORDS][15:]
    v2_tail = [w for _, w in STUB_B2_WORDS][10:]
    if b3[4:8] != v1_tail or b3[4:8] != v2_tail:
        fail(o, 'B3 store/epilogue tail (addi 0x%x/st.d/csr.w/ret.d) not '
            'bit-exact vs v1/v2 (store form must be identical)'
            % (W_RESP * 4))
    v1t = [dis(w, dc) for dc, w in STUB_B_WORDS]
    v2t = [dis(w, dc) for dc, w in STUB_B2_WORDS]
    b3t = [dis(w, dc) for dc, w in STUB_B3_WORDS]
    if b3t[:2] != [v1t[0], v1t[2]] or b3t[:2] != v2t[:2]:
        fail(o, 'B3 prologue (link save + stock call) is not the v1/v2 '
             'v3-form prologue')
    o('[G1c] B3 canary (v3): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); structure '
      'anchors OK (link save / stock call first / constant compose / '
      'direct answer store / link restore / ret.d); canary pins: 0 loads, '
      '0 branches, 0 compares, 0 r8/r9, 0 subi; store/epilogue tail '
      'bit-exact vs v1 AND v2; prologue == v3-form (csr.r+call)'
      % len(STUB_B3_WORDS))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B3_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2c(o):
    n = len(STUB_B3_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B3 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2c] budget: B3 %d/%d words (slack %d; v1 19, v2 14); <= %d with '
      'slack >= %d' % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4c(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B3_WORDS]
    if 'set2 r5,zero,0x%x' % ((CANARY >> 16) & 0xffff) not in stub_texts \
            or 'set3 r5,r5,0x%x' % (CANARY & 0xffff) not in stub_texts:
        fail(o, 'B3 does not compose the canary constant 0x%08x' % CANARY)
    if '0x%x' % (MAGIC & 0xffff) in ' '.join(stub_texts):
        fail(o, 'B3 carries the magic lo constant 0x%x (filter must be '
             'absent)' % (MAGIC & 0xffff))
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B3 answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    if 'ld.i' in ' '.join(stub_texts):
        fail(o, 'B3 reads a seed word (canary reads nothing)')
    o('[G4c] B3 layout: store targets CR 0x%x (word 0x%x) exactly like '
      'v1/v2; canary constant 0x%08x composed; no seed-word reads, no '
      'magic constant - write-path canary only'
      % (W_RESP * 4, W_RESP, CANARY))


def gate_g1d(o):
    if len(STUB_B4_WORDS) != 9:
        fail(o, 'B4 echo is %d words, canonical v4 draft is 9'
             % len(STUB_B4_WORDS))
    if len(STUB_B4_WORDS) != len(STUB_B2_WORDS) - 5:
        fail(o, 'one-variable drift: B4 %d words != v2 %d - 5 filter words'
             % (len(STUB_B4_WORDS), len(STUB_B2_WORDS)))
    for i, (dc, w) in enumerate(STUB_B4_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B4 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B4 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B4 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B4 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'B4 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        if text.startswith(('b.f', 'b.t', 'jump')):
            fail(o, 'B4 word %d branches (echo path is unconditional): %s'
                 % (i, text))
        if 'cmp38' in text or 'op0x38' in text:
            fail(o, 'B4 word %d compares (echo has no filter): %s'
                 % (i, text))
        for reg in (6, 7, 8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B4 word %d touches r%d (echo uses r3/r4/r5/r19 '
                     'only): %s' % (i, reg, text))
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r3,0x%x' % W_ADDR, 3: 'addi.hi r3,r3,0x80',
               4: 'ld.d r5,r3,0x0', 5: 'addi r4,zero,0x%x' % (W_RESP * 4),
               6: 'st.d r5,r4,0x0', 7: 'csr.w r19,zero,0xbc',
               8: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B4_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B4 structure anchor %d: "%s" != "%s"' % (i, got, want))
    v2t = [dis(w, dc) for dc, w in STUB_B2_WORDS]
    v3t = [dis(w, dc) for dc, w in STUB_B3_WORDS]
    b4t = [dis(w, dc) for dc, w in STUB_B4_WORDS]
    recipe = v2t[:2] + v2t[7:]
    if b4t != recipe:
        fail(o, 'B4 is not exactly v2 minus the 5 filter words '
             '(ld.i r6/set2/set3/cmp38/b.f): recipe delta')
    b4 = [w for _, w in STUB_B4_WORDS]
    v2_tail = [w for _, w in STUB_B2_WORDS][7:]
    v3_tail = [w for _, w in STUB_B3_WORDS][4:]
    if b4[2:] != v2_tail:
        fail(o, 'B4 data-path/store/epilogue tail not bit-exact vs v2')
    if b4[5:] != v3_tail:
        fail(o, 'B4 store/epilogue tail not bit-exact vs v3 (canary-'
             'proven words)')
    if b4t[:2] != v3t[:2]:
        fail(o, 'B4 prologue is not the v3-form prologue (csr.r+call)')
    o('[G1d] B4 echo (v4): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); structure '
      'anchors OK (link save / stock call first / addr load / dc->rt / '
      'ld.d / direct echo store / link restore / ret.d); echo pins: '
      '0 branches, 0 compares, 0 r6-r9, 0 subi; one-variable pin: v2 '
      'texts minus exactly the 5 filter words; data-path+store tail '
      'bit-exact vs v2; store/epilogue tail bit-exact vs canary-proven '
      'v3' % len(STUB_B4_WORDS))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B4_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2d(o):
    n = len(STUB_B4_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B4 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2d] budget: B4 %d/%d words (slack %d; v1 19, v2 14, v3 8); '
      '<= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4d(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B4_WORDS]
    if 'ld.i r3,0x%x' % W_ADDR not in stub_texts:
        fail(o, 'B4 does not read the addr seed word 0x%x' % W_ADDR)
    if 'ld.i r6,0x%x' % W_MAGIC in stub_texts:
        fail(o, 'B4 reads the magic seed word 0x%x (filter must be '
             'absent)' % W_MAGIC)
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B4 answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    joined = ' '.join(stub_texts)
    if '0x%x' % (MAGIC & 0xffff) in joined or \
            '0x%x' % (CANARY & 0xffff) in joined:
        fail(o, 'B4 carries a magic/canary lo constant (echo composes '
             'nothing)')
    o('[G4d] B4 layout: reads addr seed @0x%x only (magic @0x%x unread - '
      'no filter); store targets CR 0x%x (word 0x%x) exactly like '
      'v1/v2/v3; no constants composed - pure echo'
      % (W_ADDR, W_MAGIC, W_RESP * 4, W_RESP))


def gate_g1e(o):
    if len(STUB_B5_WORDS) != 11:
        fail(o, 'B5 probe is %d words, canonical v5 draft is 11'
             % len(STUB_B5_WORDS))
    for i, (dc, w) in enumerate(STUB_B5_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B5 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B5 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B5 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B5 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'B5 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        if text.startswith(('b.f', 'b.t', 'jump')):
            fail(o, 'B5 word %d branches (probe is unconditional): %s'
                 % (i, text))
        if 'cmp38' in text or 'op0x38' in text:
            fail(o, 'B5 word %d compares (probe has no filter): %s'
                 % (i, text))
        if text.startswith(('ld.d', 'ld.w')):
            fail(o, 'B5 word %d data-loads (probe echoes no memory): %s'
                 % (i, text))
        if text.startswith('ld.i') and text != 'ld.i r6,0x%x' % W_MAGIC:
            fail(o, 'B5 word %d is an unexpected ld.i (only the magic '
                 'read is allowed): %s' % (i, text))
        for reg in (8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B5 word %d touches r%d: %s' % (i, reg, text))
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r6,0x%x' % W_MAGIC,
               3: 'addi r4,zero,0x%x' % (W_RESP * 4),
               4: 'st.d r6,r4,0x0',
               5: 'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
               6: 'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
               7: 'addi r4,zero,0x%x' % ((W_RESP + 1) * 4),
               8: 'st.d r7,r4,0x0', 9: 'csr.w r19,zero,0xbc',
               10: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B5_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B5 structure anchor %d: "%s" != "%s"' % (i, got, want))
    b5 = [w for _, w in STUB_B5_WORDS]
    v1 = [w for _, w in STUB_B_WORDS]
    v2 = [w for _, w in STUB_B2_WORDS]
    v3 = [w for _, w in STUB_B3_WORDS]
    v4 = [w for _, w in STUB_B4_WORDS]
    if b5[2] != v1[3] or b5[2] != v2[2]:
        fail(o, 'B5 magic-read word is not bit-exact the v1/v2 ld.i '
             'r6,0x%x' % W_MAGIC)
    if b5[5:7] != v1[4:6] or b5[5:7] != v2[3:5]:
        fail(o, 'B5 constant-build pair is not bit-exact the v1/v2 '
             'set2/set3 words (the pair under test must be the original)')
    if b5[3] != v1[15] or b5[3] != v2[10] or b5[3] != v3[4] \
            or b5[3] != v4[5]:
        fail(o, 'B5 0x8c8 store base word is not bit-exact the proven '
             'addi r4,zero,0x%x' % (W_RESP * 4))
    v1t = [dis(w, dc) for dc, w in STUB_B_WORDS]
    v3t = [dis(w, dc) for dc, w in STUB_B3_WORDS]
    b5t = [dis(w, dc) for dc, w in STUB_B5_WORDS]
    if b5t[:2] != [v1t[0], v1t[2]] or b5t[:2] != v3t[:2]:
        fail(o, 'B5 prologue is not the v3-form prologue (csr.r+call)')
    if b5t[9:] != [t for t in v3t[6:]]:
        fail(o, 'B5 epilogue is not the proven csr.w+ret.d tail')
    o('[G1e] B5 probe (v5): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); structure '
      'anchors OK; probe pins: 0 compares, 0 branches, 0 data-loads, '
      'single ld.i = magic read, 0 r8/r9, 0 subi; magic-read word '
      'bit-exact v1/v2; set2/set3 pair bit-exact v1/v2 (the words under '
      'test); 0x8c8 base word bit-exact v1-v4; proven st.d form both '
      'stores; v3-form prologue/epilogue'
      % len(STUB_B5_WORDS))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B5_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2e(o):
    n = len(STUB_B5_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B5 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2e] budget: B5 %d/%d words (slack %d; v1 19, v2 14, v3 8, '
      'v4 9); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4e(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B5_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B5 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR in stub_texts:
        fail(o, 'B5 reads the addr seed word 0x%x (probe reads no addr)'
             % W_ADDR)
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts or \
            'addi r4,zero,0x%x' % ((W_RESP + 1) * 4) not in stub_texts:
        fail(o, 'B5 store bases 0x%x/0x%x != W_RESP*4/(W_RESP+1)*4'
             % (W_RESP * 4, (W_RESP + 1) * 4))
    if (W_RESP + 1) not in SEED_LAYOUT['resp']['zone_words'] or \
            not in_reserve(W_RESP + 1):
        fail(o, 'second slot word 0x%x outside the answer zone / reserve '
             'canon' % (W_RESP + 1))
    o('[G4e] B5 layout: reads magic @0x%x (the link under test); stores '
      'to CR 0x%x (word 0x%x) and CR 0x%x (word 0x%x) - both inside the '
      'answer zone/reserve canon; addr seed unread'
      % (W_MAGIC, W_RESP * 4, W_RESP, (W_RESP + 1) * 4, W_RESP + 1))


def gate_g1f(o):
    if len(STUB_B6_WORDS) != 13:
        fail(o, 'B6 final is %d words, canonical v6 draft is 13'
             % len(STUB_B6_WORDS))
    for i, (dc, w) in enumerate(STUB_B6_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B6 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B6 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B6 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B6 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'B6 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        for reg in (8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B6 word %d touches r%d: %s' % (i, reg, text))
    branches = [i for i, (dc, w) in enumerate(STUB_B6_WORDS)
                if dis(w, dc).startswith(('b.f', 'b.t', 'jump'))]
    if branches != [5]:
        fail(o, 'B6 must have exactly one branch (the miss-exit) at 5: %s'
             % branches)
    compares = [i for i, (dc, w) in enumerate(STUB_B6_WORDS)
                if 'cmp38' in dis(w, dc) or 'op0x38' in dis(w, dc)]
    if compares != [4]:
        fail(o, 'B6 must have exactly one compare at 4: %s' % compares)
    from scripts.irisc.enc import cmp38_sel, set3 as enc_set3
    CMP6_DIS = dis(cmp38_sel(2, 6, 7), STUB_SLOT_DC + 4 * 4)
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r6,0x%x' % W_MAGIC,
               3: 'set3 r7,zero,0x%x' % (MAGIC & 0xffff),
               4: CMP6_DIS,
               5: 'b.f.0xa zero,0x%x' % OUT6_DC,
               6: 'ld.i r3,0x%x' % W_ADDR, 7: 'addi.hi r3,r3,0x80',
               8: 'ld.d r5,r3,0x0', 9: 'addi r4,zero,0x%x' % (W_RESP * 4),
               10: 'st.d r5,r4,0x0', 11: 'csr.w r19,zero,0xbc',
               12: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B6_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B6 structure anchor %d: "%s" != "%s"' % (i, got, want))
    if STUB_B6_WORDS[4][1] != cmp38_sel(2, 6, 7):
        fail(o, 'B6 compare word is not the S2 form cmp38_sel(2, loaded, '
             'const) = cmp38_sel(2,6,7)')
    if STUB_B6_WORDS[3][1] != enc_set3(7, 0, MAGIC & 0xffff):
        fail(o, 'B6 constant word is not the S2 form set3 r7,zero,0x%x'
             % (MAGIC & 0xffff))
    b6 = [w for _, w in STUB_B6_WORDS]
    v2 = [w for _, w in STUB_B2_WORDS]
    v4 = [w for _, w in STUB_B4_WORDS]
    if b6[6:13] != v2[7:14] or b6[6:13] != v4[2:9]:
        fail(o, 'B6 hit-path/store/epilogue tail not bit-exact v2/v4 '
             '(proven words)')
    if b6[0:3] != v2[0:3]:
        fail(o, 'B6 prologue+magic-read not bit-exact v2 (proven words)')
    v2t = [dis(w, dc) for dc, w in STUB_B2_WORDS]
    b6t = [dis(w, dc) for dc, w in STUB_B6_WORDS]
    recipe = v2t[:3] + ['set3 r7,zero,0x%x' % (MAGIC & 0xffff),
                        CMP6_DIS,
                        'b.f.0xa zero,0x%x' % OUT6_DC] + v2t[7:]
    if b6t != recipe:
        fail(o, 'B6 is not v2 with only the filter link replaced '
             '(set2/set3hi/cmp38(r7,r6) -> set3/cmp38(r6,r7))')
    o('[G1f] B6 final (v6): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); structure '
      'anchors OK; S2-port pins: compare word == enc.cmp38_sel(2,6,7) '
      '(LOADED-first, the S2 operand order), constant word == enc.set3'
      '(7,0,0x%x) (S2 16-bit set3 rs=zero form), single b.f miss-exit -> '
      '0x%x; one-variable pin: v2 texts with ONLY the filter link '
      'replaced (set2+set3hi+cmp38(r7,r6) -> set3+cmp38(r6,r7)); '
      'prologue+magic-read and hit tail bit-exact v2 AND v4 (proven '
      'words); 0 r8/r9, 0 subi' % (len(STUB_B6_WORDS), MAGIC & 0xffff,
                                   OUT6_DC))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B6_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2f(o):
    n = len(STUB_B6_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B6 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2f] budget: B6 %d/%d words (slack %d; v1 19, v2 14, v3 8, v4 9, '
      'v5 11); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4f(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B6_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B6 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR not in stub_texts:
        fail(o, 'B6 does not read the addr seed word 0x%x' % W_ADDR)
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B6 answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    if 'set3 r7,zero,0x%x' % (MAGIC & 0xffff) not in stub_texts:
        fail(o, 'B6 filter constant is not the S2 16-bit set3 form '
             '(0x%x)' % (MAGIC & 0xffff))
    if 'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff) in stub_texts:
        fail(o, 'B6 still carries the v1/v2 32-bit set-pair hi word '
             '(filter link must be replaced)')
    o('[G4f] B6 layout: reads magic @0x%x + addr @0x%x; store targets '
      'CR 0x%x (word 0x%x); filter constant = magic LO halfword 0x%x in '
      'the S2 set3-16 form; set-pair hi word absent'
      % (W_MAGIC, W_ADDR, W_RESP * 4, W_RESP, MAGIC & 0xffff))


def gate_g1g(o):
    if len(STUB_B7_WORDS) != 17:
        fail(o, 'B7 probe is %d words, canonical v7 draft is 17'
             % len(STUB_B7_WORDS))
    for i, (dc, w) in enumerate(STUB_B7_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B7 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B7 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B7 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B7 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'B7 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        for reg in (8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B7 word %d touches r%d: %s' % (i, reg, text))
    b7 = [w for _, w in STUB_B7_WORDS]
    b6 = [w for _, w in STUB_B6_WORDS]
    if b7[0:5] != b6[0:5]:
        fail(o, 'B7 prologue+filter words not bit-exact v6 (the words '
             'under test)')
    branches = [(i, dis(w, dc)) for i, (dc, w) in enumerate(STUB_B7_WORDS)
                if dis(w, dc).startswith(('b.f', 'b.t', 'jump'))]
    if [i for i, _ in branches] != [5, 10]:
        fail(o, 'B7 must have exactly b.f@5 + jump@10: %s' % branches)
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r6,0x%x' % W_MAGIC,
               3: 'set3 r7,zero,0x%x' % (MAGIC & 0xffff),
               5: 'b.f.0xa zero,0x%x' % ARM_HIT_DC,
               6: 'set2 r5,zero,0x%x' % ((ARM_MISS_MARK >> 16) & 0xffff),
               7: 'set3 r5,r5,0x%x' % (ARM_MISS_MARK & 0xffff),
               9: 'st.d r5,r4,0x0', 10: 'jump 0x%x' % ARM_JOIN_DC,
               11: 'set2 r5,zero,0x%x' % ((ARM_HIT_MARK >> 16) & 0xffff),
               12: 'set3 r5,r5,0x%x' % (ARM_HIT_MARK & 0xffff),
               14: 'st.d r5,r4,0x0', 15: 'csr.w r19,zero,0xbc',
               16: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B7_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B7 structure anchor %d: "%s" != "%s"' % (i, got, want))
    if b7[8] != b7[13] or b7[8] != b6[9]:
        fail(o, 'B7 arm store bases not the proven addi 0x%x word'
            % (W_RESP * 4))
    if b7[9] != b7[14] or b7[9] != b6[10]:
        fail(o, 'B7 arm stores not the proven st.d word')
    o('[G1g] B7 probe (v7): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); structure '
      'anchors OK (link save / stock call / v6 filter words bit-exact / '
      'b.f -> ARM_HIT 0x%x / ARM_MISS fallthrough 0x%08x -> store / jump '
      'converge / ARM_HIT 0x%08x -> store / link restore / ret.d); arm '
      'stores = proven words; 0 r8/r9, 0 subi'
      % (len(STUB_B7_WORDS), ARM_HIT_DC, ARM_MISS_MARK, ARM_HIT_MARK))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B7_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2g(o):
    n = len(STUB_B7_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B7 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2g] budget: B7 %d/%d words (slack %d; v1 19, v2 14, v3 8, v4 9, '
      'v5 11, v6 13); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4g(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B7_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B7 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR in stub_texts:
        fail(o, 'B7 reads the addr seed word 0x%x (probe reads no addr)'
             % W_ADDR)
    marks = ('0x%x' % ((ARM_HIT_MARK >> 16) & 0xffff),
             '0x%x' % (ARM_HIT_MARK & 0xffff),
             '0x%x' % ((ARM_MISS_MARK >> 16) & 0xffff),
             '0x%x' % (ARM_MISS_MARK & 0xffff))
    for m in marks:
        if m not in ' '.join(stub_texts):
            fail(o, 'B7 does not compose the marker halfword %s' % m)
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B7 store base 0x%x != W_RESP*4' % (W_RESP * 4))
    o('[G4g] B7 layout: reads magic @0x%x only; both arms store to CR '
      '0x%x (word 0x%x) via the proven form; markers 0x%08x (b.f target) '
      '/ 0x%08x (fallthrough) composed'
      % (W_MAGIC, W_RESP * 4, W_RESP, ARM_HIT_MARK, ARM_MISS_MARK))


def gate_g1h(o):
    if len(STUB_B8_WORDS) != 18:
        fail(o, 'B8 probe is %d words, canonical v8 draft is 18'
             % len(STUB_B8_WORDS))
    for i, (dc, w) in enumerate(STUB_B8_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B8 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B8 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B8 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B8 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'B8 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        for reg in (8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B8 word %d touches r%d: %s' % (i, reg, text))
    b8 = [w for _, w in STUB_B8_WORDS]
    b7 = [w for _, w in STUB_B7_WORDS]
    v1 = [w for _, w in STUB_B_WORDS]
    if b8[2] != b7[2] or b8[5] != b7[4]:
        fail(o, 'B8 magic-read/cmp words not bit-exact the v6/v7 words '
             'under test')
    if b8[4] != v1[5]:
        fail(o, 'B8 chained set3 word is not bit-exact the v1/v2 pair '
             'set3 r7,r7,0x%x form' % (MAGIC & 0xffff))
    if b8[3] != _words('set2 r7,zero,0x0', STUB_SLOT_DC + 4 * 3)[0]:
        fail(o, 'B8 zero-hi word is not the chained set2 r7,zero,0x0')
    if b8[7:11] != b7[6:10] or b8[12:16] != b7[11:15]:
        fail(o, 'B8 arm bodies not bit-exact v7 (proven marker/store '
             'words)')
    branches = [i for i, (dc, w) in enumerate(STUB_B8_WORDS)
                if dis(w, dc).startswith(('b.f', 'b.t', 'jump'))]
    if branches != [6, 11]:
        fail(o, 'B8 must have exactly b.f@6 + jump@11: %s' % branches)
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r6,0x%x' % W_MAGIC, 3: 'set2 r7,zero,0x0',
               4: 'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
               6: 'b.f.0xa zero,0x%x' % ARM8_HIT_DC,
               11: 'jump 0x%x' % ARM8_JOIN_DC,
               16: 'csr.w r19,zero,0xbc', 17: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B8_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B8 structure anchor %d: "%s" != "%s"' % (i, got, want))
    o('[G1h] B8 probe (v8): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); H-const pins:'
      ' set2 r7,zero,0x0 (explicit zero hi, v5-live-proven pair mechanism'
      ' + stock idiom 12628x) chained before the bit-exact v6/v7 set3+'
      'cmp38 words; arms/markers/stores bit-exact v7; 0 r8/r9, 0 subi'
      % len(STUB_B8_WORDS))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B8_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2h(o):
    n = len(STUB_B8_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B8 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2h] budget: B8 %d/%d words (slack %d; v1 19, v2 14, v3 8, v4 9, '
      'v5 11, v6 13, v7 17); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4h(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B8_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B8 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'set2 r7,zero,0x0' not in stub_texts:
        fail(o, 'B8 constant hi not explicitly zero (H-const probe core)')
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B8 store base 0x%x != W_RESP*4' % (W_RESP * 4))
    o('[G4h] B8 layout: reads magic @0x%x; compare constant = 0x0000%04x '
      'with EXPLICIT zero upper (set2 0x0 + set3 lo); both arms store to '
      'CR 0x%x (word 0x%x)'
      % (W_MAGIC, MAGIC & 0xffff, W_RESP * 4, W_RESP))


def gate_g1i(o):
    if len(STUB_B9_WORDS) != 18:
        fail(o, 'B9 stub is %d words, canonical v9-F1 draft is 18'
             % len(STUB_B9_WORDS))
    for i, (dc, w) in enumerate(STUB_B9_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B9 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B9 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B9 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B9 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text:
            fail(o, 'B9 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        for reg in (8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B9 word %d touches r%d: %s' % (i, reg, text))
    b9 = [w for _, w in STUB_B9_WORDS]
    b6 = [w for _, w in STUB_B6_WORDS]
    v1 = [w for _, w in STUB_B_WORDS]
    v4 = [w for _, w in STUB_B4_WORDS]
    if b9[2] != b6[2]:
        fail(o, 'B9 magic-read word not bit-exact v6')
    if b9[5:7] != v1[4:6]:
        fail(o, 'B9 constant pair not bit-exact the v1/v2 set-pair words')
    if b9[9] != b6[4]:
        fail(o, 'B9 compare word not bit-exact v6/v7/v8')
    for idx, reg in ((3, 6), (4, 6), (7, 7), (8, 7)):
        want = _words('set%d r%d,zero,0x0' % (0 if idx in (4, 8) else 1,
                                              reg),
                      STUB_SLOT_DC + 4 * idx)[0]
        if b9[idx] != want:
            fail(o, 'B9 clean word %d is not set%d r%d,zero,0x0 (bits '
                 '63..32 zero, low 32 untouched)'
                 % (idx, 0 if idx in (4, 8) else 1, reg))
    if b9[11:18] != v4[2:9]:
        fail(o, 'B9 hit-path/store/epilogue tail not bit-exact v4 '
             '(proven words)')
    if b9[16] != b6[11] or b9[17] != b6[12]:
        fail(o, 'B9 epilogue not bit-exact v6 (link restore + ret.d)')
    branches = [i for i, (dc, w) in enumerate(STUB_B9_WORDS)
                if dis(w, dc).startswith(('b.f', 'b.t', 'jump'))]
    if branches != [10]:
        fail(o, 'B9 must have exactly one branch (b.f miss-exit) at 10: %s'
             % branches)
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r6,0x%x' % W_MAGIC, 3: 'set1 r6,zero,0x0',
               4: 'set0 r6,zero,0x0',
               5: 'set2 r7,zero,0x%x' % ((MAGIC >> 16) & 0xffff),
               6: 'set3 r7,r7,0x%x' % (MAGIC & 0xffff),
               7: 'set1 r7,zero,0x0', 8: 'set0 r7,zero,0x0',
               10: 'b.f.0xa zero,0x%x' % OUT9_DC,
               11: 'ld.i r3,0x%x' % W_ADDR, 15: 'st.d r5,r4,0x0',
               16: 'csr.w r19,zero,0xbc', 17: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B9_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B9 structure anchor %d: "%s" != "%s"' % (i, got, want))
    o('[G1i] B9 (v9-F1): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); upper-clean '
      'pins: set1/set0 zero words on r6 AND r7 (bits 63..32 -> 0, low 32 '
      'untouched, docs/250-re/120-irisc/010-isa.md width canon); const pair bit-exact '
      'v1/v2 (FULL magic - equal under any compare width after '
      'cleaning); cmp word bit-exact v6/v7/v8; hit tail bit-exact v4; '
      'single b.f miss-exit -> 0x%x; 0 r8/r9, 0 subi'
      % (len(STUB_B9_WORDS), OUT9_DC))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B9_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2i(o):
    n = len(STUB_B9_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B9 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2i] budget: B9 %d/%d words (slack %d; v1 19, v2 14, v3 8, v4 9, '
      'v5 11, v6 13, v7 17, v8 18); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4i(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B9_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B9 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR not in stub_texts:
        fail(o, 'B9 does not read the addr seed word 0x%x' % W_ADDR)
    if 'set1 r6,zero,0x0' not in stub_texts \
            or 'set1 r7,zero,0x0' not in stub_texts:
        fail(o, 'B9 does not clean bits 47..32 of both compare operands')
    if 'set0 r6,zero,0x0' not in stub_texts \
            or 'set0 r7,zero,0x0' not in stub_texts:
        fail(o, 'B9 does not clean bits 63..48 of both compare operands')
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B9 answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    o('[G4i] B9 layout: reads magic @0x%x + addr @0x%x; both compare '
      'operands upper-cleaned (bits 63..32 = 0); store targets CR 0x%x '
      '(word 0x%x); const = FULL magic 0x%08x (v1/v2 pair words)'
      % (W_MAGIC, W_ADDR, W_RESP * 4, W_RESP, MAGIC))


def gate_g1j(o):
    if len(STUB_B10_WORDS) != 18:
        fail(o, 'B10 stub is %d words, canonical v10-F4 draft is 18'
             % len(STUB_B10_WORDS))
    for i, (dc, w) in enumerate(STUB_B10_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B10 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B10 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B10 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B10 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text and not text.startswith('subs'):
            fail(o, 'B10 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        for reg in (8, 9):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B10 word %d touches r%d: %s' % (i, reg, text))
    b10 = [w for _, w in STUB_B10_WORDS]
    b9 = [w for _, w in STUB_B9_WORDS]
    if b10[:9] != b9[:9]:
        fail(o, 'B10 prologue+clean+const words not bit-exact v9')
    if b10[11:] != b9[11:]:
        fail(o, 'B10 hit-path/epilogue not bit-exact v9 (proven words)')
    if b10[9] != _words('subs r7,r7,r6', STUB_SLOT_DC + 4 * 9)[0]:
        fail(o, 'B10 compare word is not the validator subs form')
    if b10[9] & 0xFC0000FF != 0xFCE72805 & 0xFC0000FF:
        fail(o, 'B10 subs word not the 0x1071bc form class (op+funct '
             'match, register fields aside)')
    if b10[10] != _words('b.f.0x2 zero,0x%x' % OUT10_DC,
                         STUB_SLOT_DC + 4 * 10)[0]:
        fail(o, 'B10 branch word is not b.f.0x2')
    if b10[10] >> 26 != 0x29 or ((b10[10] >> 16) & 0x1F) != 0x2:
        fail(o, 'B10 branch is not the 0x1071c0 b.f.cc2 form class')
    branches = [i for i, (dc, w) in enumerate(STUB_B10_WORDS)
                if dis(w, dc).startswith(('b.f', 'b.t', 'jump'))]
    if branches != [10]:
        fail(o, 'B10 must have exactly one branch at 10: %s' % branches)
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               9: 'subs r7,r7,r6', 10: 'b.f.0x2 zero,0x%x' % OUT10_DC,
               15: 'st.d r5,r4,0x0', 16: 'csr.w r19,zero,0xbc',
               17: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B10_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B10 structure anchor %d: "%s" != "%s"' % (i, got, want))
    o('[G1j] B10 (v10-F4): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); validator-'
      'idiom pins: subs word = the 0x1071bc form class (value diff = '
      'const - magic + cc), b.f.0x2 word = the 0x1071c0 form class (cc2 '
      'not-equal -> miss-exit 0x%x); prologue/clean/const/hit-tail '
      'bit-exact v9 (proven words); one branch; 0 r8/r9'
      % (len(STUB_B10_WORDS), OUT10_DC))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B10_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2j(o):
    n = len(STUB_B10_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B10 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2j] budget: B10 %d/%d words (slack %d); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4j(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B10_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B10 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR not in stub_texts:
        fail(o, 'B10 does not read the addr seed word 0x%x' % W_ADDR)
    if 'subs r7,r7,r6' not in stub_texts:
        fail(o, 'B10 does not use the validator subs compare')
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B10 answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    o('[G4j] B10 layout: reads magic @0x%x + addr @0x%x; validator '
      'subs+b.f.0x2 compare; store targets CR 0x%x (word 0x%x)'
      % (W_MAGIC, W_ADDR, W_RESP * 4, W_RESP))


def gate_g1k(o):
    if len(STUB_B11_WORDS) != 24:
        fail(o, 'B11 stub is %d words, canonical v11-F2 draft is 24'
             % len(STUB_B11_WORDS))
    for i, (dc, w) in enumerate(STUB_B11_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B11 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B11 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B11 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        if text.startswith(('b.f', 'b.t', 'jump')):
            fail(o, 'B11 word %d is a branch (F2 is branchless): %s'
                 % (i, text))
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B11 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text and not text.startswith('subs'):
            fail(o, 'B11 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        for reg in (9,):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B11 word %d touches r%d: %s' % (i, reg, text))
    b11 = [w for _, w in STUB_B11_WORDS]
    v1 = [w for _, w in STUB_B_WORDS]
    v4 = [w for _, w in STUB_B4_WORDS]
    if b11[3:5] != v1[4:6]:
        fail(o, 'B11 constant pair not bit-exact the v1/v2 set-pair words')
    if b11[16:19] != v4[2:5]:
        fail(o, 'B11 addr/dc->rt/load words not bit-exact v4')
    if b11[20:24] != v4[5:9]:
        fail(o, 'B11 store/epilogue tail not bit-exact v4 (proven words)')
    chain = ['subs r7,r7,r6', 'set1 r7,zero,0x0', 'set0 r7,zero,0x0',
             'addi r8,zero,0x0', 'subs r8,r8,r7', 'set1 r8,zero,0x0',
             'set0 r8,zero,0x0', 'or r7,r7,r8', 'shr r7,r7,0x1f',
             'addi r8,zero,0x1', 'subs r7,r7,r8']
    for k, txt in enumerate(chain):
        want = _words(txt, STUB_SLOT_DC + 4 * (5 + k))[0]
        if b11[5 + k] != want:
            fail(o, 'B11 mask-chain word %d (%s) drifted' % (5 + k, txt))
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r6,0x%x' % W_MAGIC,
               5: 'subs r7,r7,r6', 12: 'or r7,r7,r8',
               13: 'shr r7,r7,0x1f', 15: 'subs r7,r7,r8',
               19: 'ands r5,r5,r7', 21: 'st.d r5,r4,0x0',
               22: 'csr.w r19,zero,0xbc', 23: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B11_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B11 structure anchor %d: "%s" != "%s"' % (i, got, want))
    o('[G1k] B11 (v11-F2): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); BRANCHLESS '
      'pin: 0 branch/jump words anywhere; mask chain word-for-word '
      '(subs diff -> set1/set0 clean x2 -> or -> shr31 -> ne-1 mask); '
      'const pair bit-exact v1/v2; hit/store tail bit-exact v4; 0 r9'
      % len(STUB_B11_WORDS))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B11_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2k(o):
    n = len(STUB_B11_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B11 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2k] budget: B11 %d/%d words (slack %d); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4k(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B11_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B11 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR not in stub_texts:
        fail(o, 'B11 does not read the addr seed word 0x%x' % W_ADDR)
    if 'ands r5,r5,r7' not in stub_texts:
        fail(o, 'B11 does not mask the loaded answer (ands missing)')
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B11 answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    o('[G4k] B11 layout: reads magic @0x%x + addr @0x%x; branchless '
      'value-mask filter (diff -> ne -> ne-1 mask -> ands); store '
      'targets CR 0x%x (word 0x%x)'
      % (W_MAGIC, W_ADDR, W_RESP * 4, W_RESP))


def gate_g1l(o):
    if len(STUB_B12_WORDS) != 28:
        fail(o, 'B12 stub is %d words, canonical v12 draft is 28'
             % len(STUB_B12_WORDS))
    for i, (dc, w) in enumerate(STUB_B12_WORDS):
        if dc != STUB_SLOT_DC + 4 * i:
            fail(o, 'B12 placement drift at %d: dc 0x%x' % (i, dc))
        if not STUB_SLOT_DC <= dc < STUB_SLOT_DC + 4 * STUB_SLOT_WORDS:
            fail(o, 'B12 word %d dc 0x%x outside the slot' % (i, dc))
        if CUTOUT[0] <= dc <= CUTOUT[1]:
            fail(o, 'B12 word %d dc 0x%x inside the cutout' % (i, dc))
        text = dis(w, dc)
        if text.startswith(('b.f', 'b.t', 'jump')):
            fail(o, 'B12 word %d is a branch (v12 is branchless): %s'
                 % (i, text))
        again = _words(text, dc)[0]
        if again != w:
            fail(o, 'B12 word %d (0x%08x) dis->re-assemble drift: 0x%08x'
                 % (i, w, again))
        if 'subi' in text and not text.startswith('subs'):
            fail(o, 'B12 word %d uses subi (4030 inversion delta): %s'
                 % (i, text))
        for reg in (9,):
            if ('r%d,' % reg) in text or text.endswith(',r%d' % reg) \
                    or (',r%d,' % reg) in text:
                fail(o, 'B12 word %d touches r%d: %s' % (i, reg, text))
    b12 = [w for _, w in STUB_B12_WORDS]
    b11 = [w for _, w in STUB_B11_WORDS]
    v1 = [w for _, w in STUB_B_WORDS]
    v4 = [w for _, w in STUB_B4_WORDS]
    if b12[:3] != b11[:3]:
        fail(o, 'B12 prologue not bit-exact v11')
    for idx, reg in ((3, 6), (4, 6), (7, 7), (8, 7)):
        want = _words('set%d r%d,zero,0x0' % (0 if idx in (4, 8) else 1,
                                              reg),
                      STUB_SLOT_DC + 4 * idx)[0]
        if b12[idx] != want:
            fail(o, 'B12 pre-subs clean word %d is not set%d r%d,zero,0x0'
                 % (idx, 0 if idx in (4, 8) else 1, reg))
    if b12[5:7] != b11[3:5] or b12[5:7] != v1[4:6]:
        fail(o, 'B12 constant pair not bit-exact v11/v1')
    if b12[9:20] != b11[5:16]:
        fail(o, 'B12 mask chain not word-for-word the v11 chain (shifted)')
    if b12[20:23] != b11[16:19] or b12[23:28] != b11[19:24]:
        fail(o, 'B12 hit/store/epilogue not bit-exact v11 (proven words)')
    if b12[20:23] != v4[2:5] or b12[24:28] != v4[5:9]:
        fail(o, 'B12 hit/store tail not bit-exact v4')
    anchors = {0: 'csr.r r19,csr0xbc', 1: 'call 0x1b15c',
               2: 'ld.i r6,0x%x' % W_MAGIC, 3: 'set1 r6,zero,0x0',
               4: 'set0 r6,zero,0x0', 9: 'subs r7,r7,r6',
               16: 'or r7,r7,r8', 17: 'shr r7,r7,0x1f',
               19: 'subs r7,r7,r8', 23: 'ands r5,r5,r7',
               25: 'st.d r5,r4,0x0', 26: 'csr.w r19,zero,0xbc',
               27: 'ret.d zero,zero,zero'}
    for i, want in anchors.items():
        got = dis(STUB_B12_WORDS[i][1], STUB_SLOT_DC + 4 * i)
        if got != want:
            fail(o, 'B12 structure anchor %d: "%s" != "%s"' % (i, got, want))
    o('[G1l] B12 (v12): %d words, every word decode-verified (strict '
      'cx5 assemble + per-word dis->re-assemble bit-exact); BRANCHLESS '
      'pin: 0 branches; exactly v11 + the 4 pre-subs clean words '
      '(set1/set0 on r6 AND r7); mask chain word-for-word v11; '
      'hit/store tail bit-exact v11/v4; 0 r9'
      % len(STUB_B12_WORDS))
    o('      dc       rt       word     disasm')
    for dc, w in STUB_B12_WORDS:
        o('      0x%06x  0x%06x  %08x  %s' % (dc, dc + RT, w, dis(w, dc)))


def gate_g2l(o):
    n = len(STUB_B12_WORDS)
    slack = STUB_SLOT_WORDS - n
    if n > STUB_MAX_WORDS or slack < SLACK_MIN:
        fail(o, 'B12 budget: %d words, slack %d (max %d, slack >= %d)'
             % (n, slack, STUB_MAX_WORDS, SLACK_MIN))
    o('[G2l] budget: B12 %d/%d words (slack %d); <= %d with slack >= %d'
      % (n, STUB_SLOT_WORDS, slack, STUB_MAX_WORDS, SLACK_MIN))


def gate_g4l(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B12_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B12 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR not in stub_texts:
        fail(o, 'B12 does not read the addr seed word 0x%x' % W_ADDR)
    if 'set1 r6,zero,0x0' not in stub_texts \
            or 'set1 r7,zero,0x0' not in stub_texts:
        fail(o, 'B12 does not pre-clean the subs inputs (bits 47..32)')
    if 'ands r5,r5,r7' not in stub_texts:
        fail(o, 'B12 does not mask the loaded answer (ands missing)')
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B12 answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    o('[G4l] B12 layout: reads magic @0x%x + addr @0x%x; upper-clean '
      '64-bit subs inputs; branchless ne-1 mask; store CR 0x%x (word '
      '0x%x)' % (W_MAGIC, W_ADDR, W_RESP * 4, W_RESP))


def _s16(v):
    return v - 0x10000 if v & 0x8000 else v


def _s24(v):
    return v - 0x1000000 if v & 0x800000 else v


def _branch_target(w, dc):
    op = w >> 26
    if op in (0x28, 0x29):
        return (dc + _s16(w & 0xffff) * 4) & 0xffffffff
    if op == 0x25:
        return (dc + _s24(w & 0xffffff) * 4) & 0xffffffff
    return None


STOCK_PIN = (0x8ed0, 0xa40a000c, 0x8f00, 'ret.d zero,zero,zero')


def gate_g5(o, buf):
    checks = [
        (STUB_B7_WORDS, {1: HOOK_STOCK_TARGET, 5: ARM_HIT_DC,
                         10: ARM_JOIN_DC}),
        (STUB_B8_WORDS, {1: HOOK_STOCK_TARGET, 6: ARM8_HIT_DC,
                         11: ARM8_JOIN_DC}),
        (STUB_B9_WORDS, {1: HOOK_STOCK_TARGET, 10: OUT9_DC}),
        (STUB_B10_WORDS, {1: HOOK_STOCK_TARGET, 10: OUT10_DC}),
        (STUB_B11_WORDS, {1: HOOK_STOCK_TARGET}),
        (STUB_B12_WORDS, {1: HOOK_STOCK_TARGET}),
    ]
    resolved = 0
    for words, intended in checks:
        for i, (dc, w) in enumerate(words):
            tgt = _branch_target(w, dc)
            if tgt is None:
                continue
            if i not in intended:
                fail(o, 'G5: unexpected pc-relative word at %d' % i)
            if tgt != intended[i]:
                fail(o, 'G5: word %d @0x%x resolves to 0x%x != intended '
                     '0x%x (anchor = own dc, offset*4)'
                     % (i, dc, tgt, intended[i]))
            resolved += 1
            o('      G5: %s word %d @0x%06x (%s) -> 0x%06x == intended'
              % ('v7' if words is STUB_B7_WORDS else
                 ('v8' if words is STUB_B8_WORDS else
                  ('v9' if words is STUB_B9_WORDS else
                   ('v10' if words is STUB_B10_WORDS else
                    ('v11' if words is STUB_B11_WORDS else 'v12')))),
                 i, dc, dis(w, dc), tgt))
    dc, want_w, want_tgt, want_landing = STOCK_PIN
    w = dw(buf, dc)
    if w != want_w:
        fail(o, 'G5 stock pin word @0x%x drifted: %08x' % (dc, w))
    tgt = _branch_target(w, dc)
    if tgt != want_tgt or dd(buf, tgt) != want_landing:
        fail(o, 'G5 stock pin: 0x%x -> 0x%x (%r) != guard-exit calibration'
             % (dc, tgt, dd(buf, tgt)))
    o('[G5] branch-target resolution (R16): all %d pc-relative stub words '
      '(v7 + v8) resolve from the ENCODED bits (anchor = own dc, s16/s24 '
      'field *4; irisc_asm.py:140-164 <-> irisc_dis.py:119-128, the same '
      'rule as the S2 live-proven enc.b_f) to the intended targets; stock '
      'calibration pin: b.f @0x%x (cc 0x0a) -> 0x%x = %r (guard-to-exit '
      'idiom) OK' % (resolved, dc, tgt, want_landing))


def gate_g3(o, buf):
    stock = dw(buf, HOOK_DC)
    if stock != HOOK_STOCK_WORD or dd(buf, HOOK_DC) != \
            'call 0x%x' % HOOK_STOCK_TARGET:
        fail(o, 'G3 stock hook word re-check failed')
    patch_dis = dis(HOOK_WORD, HOOK_DC)
    if patch_dis != 'call 0x%x' % STUB_SLOT_DC:
        fail(o, 'hook patch decode %r' % patch_dis)
    rel = STUB_SLOT_DC - HOOK_DC
    if rel // 4 != 0xA1CF0 or abs(rel // 4) > 0x7fffff:
        fail(o, 'hook patch offset/4 0x%x != 0xA1CF0 or simm24 overflow'
             % (rel // 4))
    if HOOK_WORD == stock:
        fail(o, 'hook patch equals the stock word')
    o('[G3] hook: stock 0x%08x "call 0x%x" (rb1 G5/tsv row 600, re-read '
      'from the base) -> patch 0x%08x "%s"; offset/4 = 0x%x (simm24 fits); '
      'patch decode-verified'
      % (stock, HOOK_STOCK_TARGET, HOOK_WORD, patch_dis, rel // 4))


def gate_g4(o):
    for name, part in SEED_LAYOUT.items():
        w = part['word']
        if not in_reserve(w):
            fail(o, 'layout %s word 0x%x outside the reserve canon' % (name, w))
        if w in RESERVE_FORBIDDEN:
            fail(o, 'layout %s word 0x%x is forbidden (occupied)' % (name, w))
        if part['cr'] != w * 4:
            fail(o, 'layout %s: CR 0x%x != word*4' % (name, part['cr']))
    zone = SEED_LAYOUT['resp']['zone_words']
    if zone != list(range(RESP_ZONE[0], RESP_ZONE[1] + 1)):
        fail(o, 'answer zone drift: %s' % zone)
    if not all(in_reserve(w) for w in zone) or \
            any(w in RESERVE_FORBIDDEN for w in zone):
        fail(o, 'answer zone outside the reserve canon / touches 0x8d0/0x8d4')
    if SEED_LAYOUT['resp']['zone_cr'] != (RESP_ZONE[0] * 4, RESP_ZONE[1] * 4):
        fail(o, 'answer zone CR mapping drift')
    stub_texts = [dis(w, dc) for dc, w in STUB_B_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'stub does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR not in stub_texts:
        fail(o, 'stub does not read the addr seed word 0x%x' % W_ADDR)
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'stub answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    o('[G4] layout: magic @0x%x (CR 0x%x) = 0x%08x, addr-dc @0x%x (CR 0x%x),'
      ' N @0x%x (CR 0x%x, N=1 host-side only), answer zone 0x%x..0x%x '
      '(CR 0x%x..0x%x) - all inside the reserve canon %s; 0x8d0/0x8d4 '
      'untouched; stub constants match the layout (ld.i 0x%x/0x%x, st.d '
      'base CR 0x%x)'
      % (W_MAGIC, W_MAGIC * 4, MAGIC, W_ADDR, W_ADDR * 4, W_COUNT,
          W_COUNT * 4, RESP_ZONE[0], RESP_ZONE[1], RESP_ZONE[0] * 4,
          RESP_ZONE[1] * 4,
          '/'.join('0x%x-0x%x' % r for r in RESERVE_CANON),
          W_MAGIC, W_ADDR, W_RESP * 4))


def gate_g4b(o):
    stub_texts = [dis(w, dc) for dc, w in STUB_B2_WORDS]
    if 'ld.i r6,0x%x' % W_MAGIC not in stub_texts:
        fail(o, 'B2 does not read the magic seed word 0x%x' % W_MAGIC)
    if 'ld.i r3,0x%x' % W_ADDR not in stub_texts:
        fail(o, 'B2 does not read the addr seed word 0x%x' % W_ADDR)
    if 'addi r4,zero,0x%x' % (W_RESP * 4) not in stub_texts:
        fail(o, 'B2 answer store base 0x%x != W_RESP*4' % (W_RESP * 4))
    if any('0x%x' % REG_ID in t for t in stub_texts):
        fail(o, 'B2 still carries the reg-id constant 0x%x (magic-only '
             'filter)' % REG_ID)
    o('[G4b] B2 layout: constants match the layout (ld.i 0x%x/0x%x, st.d '
      'base CR 0x%x); reg-id constant 0x%x absent - magic @0x%x is the '
      'only filter' % (W_MAGIC, W_ADDR, W_RESP * 4, REG_ID, W_MAGIC))


def main():
    o = Out()
    buf = BASE.read_bytes()
    o('cx5 door-detour re1 stub draft (offline): %s' % BASE.name)
    prelude(o, buf)
    gate_g1(o)
    gate_g2(o)
    gate_g3(o, buf)
    gate_g4(o)
    gate_g1b(o)
    gate_g2b(o)
    gate_g4b(o)
    gate_g1c(o)
    gate_g2c(o)
    gate_g4c(o)
    gate_g1d(o)
    gate_g2d(o)
    gate_g4d(o)
    gate_g1e(o)
    gate_g2e(o)
    gate_g4e(o)
    gate_g1f(o)
    gate_g2f(o)
    gate_g4f(o)
    gate_g1g(o)
    gate_g2g(o)
    gate_g4g(o)
    gate_g1h(o)
    gate_g2h(o)
    gate_g4h(o)
    gate_g1i(o)
    gate_g2i(o)
    gate_g4i(o)
    gate_g1j(o)
    gate_g2j(o)
    gate_g4j(o)
    gate_g1k(o)
    gate_g2k(o)
    gate_g4k(o)
    gate_g1l(o)
    gate_g2l(o)
    gate_g4l(o)
    gate_g5(o, buf)
    o('ALL GATES PASS (G1 G2 G3 G4 + G1b G2b G4b + G1c G2c G4c '
      '+ G1d G2d G4d + G1e G2e G4e + G1f G2f G4f + G1g G2g G4g '
      '+ G1h G2h G4h + G1i G2i G4i + G1j G2j G4j + G1k G2k G4k '
      '+ G1l G2l G4l + G5)')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE log=%s' % LOG)


if __name__ == '__main__':
    main()
