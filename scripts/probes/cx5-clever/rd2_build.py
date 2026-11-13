#!/usr/bin/env python3
"""cx5-clever R-D2 (Task 3): m2 stub image builder (offline).

Builds build/cx5-clever-rd2-v9.bin by grafting the R-D2 C-lever detour onto
the ON-DISK v4-echo base build/cx5-door-detour-v4.bin (R-E canon md5; not
rebuildable in-tree). NO burn here (Task 4); no live operations; no GUID/MAC
re-bake (the v4-echo base already carries the Rule-3 bake - re-baking is a
B4 violation).

v9 (RC round-6 adjudication build - the designed final filter fix): the v8
echo discriminator proved live x3 that the late site 0x0E43C4 EXECUTES on
the tool TRIG, the mirror is alive ([r1+0xb0] = 55 aa 25 8c byte-exact in
the echo) and stub writes land - localizing the v1-v7 defect to the 4-word
filter. RC round 6 excluded the offset-encoding suspect (the low bits of
the op-0x19 load imm are the WIDTH TAG, not address bits: stock
0x6429009b = 0x9a|1 ld.w, 0x642400ae = 0xac|2 ld.d; v8 re-proved the
[0xb0] slot bytes) and CONFIRMED the two real defects (word-level):
- M1: w2 cmp38 operand ORDER - our e1a06002 carries the CONST in rs /
  the LOADED value in rt; the live-proven v5b filter word (build_s2.py:
  637-639, HIT on S2b2) is e1806802 = cmp38 sel=2 rs=r12 (loaded) rt=r13
  (const); stock census: 23/23 in-code eq sites put the value under test
  in rs (rt=zero) - a register-form compare appears ONLY in v5b (value in
  rs). Under ideally-clean eq32 both orders are equivalent, but with any
  stale bits 16+ the asymmetry kills exactly ours.
- M2: w1 set3-const (200d55aa) - set3 is a halfword INSERT (docs/250-re/120-irisc/010-isa.md);
  its upper-bit behavior feeding a 32-bit compare is unproven (stock
  never feeds set3-built consts into cmp38) - trunc32 of the const may
  carry stale bits.
Both are cured by ONE construction: the v6-geometry stub VERBATIM (16
words, hook 0x940aa4ec @0x0E43C4) with EXACTLY TWO words changed:
- w1 -> 000d55aa `addi r13,zero,0x55aa` (clean mod-2^32 constant, stock
  addi idiom - the M2 fix);
- w2 -> e1806802 (the v5b-VERBATIM live-HIT cmp38 word: VALUE in rs,
  CONST in rt - the M1 fix);
all other 14 words byte-identical to the v6 lineage (stock-verbatim /
rc3-verbatim / v5m lineage; w10 buf-word `addi r7,r1,0xb0` remains
UNPROVEN-live - it only ever rode inert filters; the annotation stands).
[B1] pins the two new words (w1 addi form + exact const; w2 == the v5b
word with the operand-order decode rs=r12/rt=r13) and fails on the OLD
defect pair 200d55aa/e1a06002 - the orientation defect class can never
pass again. RESERVE discriminator (documented, NOT built): if v9 stays
inert live, the only unproven semantic left is cmp38 sel=2 itself -> w2
becomes `cmp38_eq32 r12,r12` (self-equal, always-true) - ONE burn turns
v9 into an always-hit probe of the whole hit path incl. m2/X1.
Predictions: TRIG -> hit -> m2 POST marker -> follow-up readback
out[0x1b] = 0x53; all controls golden (miss = the rc3 triplet no-op
resume).

v8 (RC round-5 adjudication build - the H2-mechanism discriminator): the
iTrace round excluded H1 (the late site 0x0E43C4 EXECUTES on the tool TRIG)
and H3 (encoding is stock canon), leaving H2 (the frame mirror holds no
magic at hook time) as the confirmed failure class with an open mechanism
(the rc3 paradox: rc3's H1b read this exact slot x9 on the same base). v8
removes EVERY non-rc3-proven word in one step: the stub is the rc3-H1b stub
VERBATIM - 23 words @0x38d774, 10x (ld.d r6,r1,0xb0+4k; st.d
r6,r18,0x10+4k) = an UNCONDITIONAL 40B echo [r1+0xb0..0xd8) ->
response+0x10..0x38 (mirror base r1+0x98: [r1+0xb0..0xd8) =
input[0x18..0x40)), then the rc3 absolute resume triple -> rt 0x8E43C8.
NO filter, NO branch, NO m2 call - every single word is rc3 live-proven x9
(rc3 task-05/06 ladders: 32/32 echo byte-exact). Hook: H1b's EXACT hook
word 0x940aa4ec `call 0x38d774` at H1b's EXACT site 0x0E43C4 (extracted
from rc3_build.py AND the burned rc3 image; same site+word as v6/v7 - the
site does NOT move); both previous hook sites are gated ([0] base pins +
[B4] final pins): 0x0E437C (v1-v5 early site) stays STOCK `call 0x18d964`,
0x0E43C4's stock dead-write 0x00130000 is replaced by exactly the hook.
Golden pins = the 23 words + hook; [B1] additionally cross-checks the
assembled stub + hook BIT-EXACT against the burned rc3 image
build/cx5-successpath-rc3-v1.bin (md5 fac6452e...) - the verbatim-port
gate. Echo semantics for the live round (rc3 precedent, task-05/06):
response+0x10..0x38 mirrors the mirror-window input[0x18..0x40)
byte-for-byte; the stock merge byte 04@0x1b INSIDE the echo zone is
REPLACED by payload (rc3 live, passport behavior); the 6f28@0x3a canary
SURVIVES (the +0x38..0x3c merge dword is outside the zone); neg QUERY
never reaches the site (stock golden `03000000001c2b78`+zeros); a
followup plain query echoes the mirror content at hook time (likely zeros
for short frames - the 04@0x1b disappearance vs stock golden is the cheap
differential control). Outcome split (RC round 5): echo PRESENT =>
site+mirror work for TRIG frames => the v1-v7 4-word filter/branch at
this depth is the defect (CMPRES window) => v9 = branchless rc3-lineage
filter; echo ABSENT => the mirror is genuinely empty for TRIG frames at
hook time => targeted transport-class trace (ICM_ACCESS|TRANSPORT, no
flood) of the input FETCH. Budget 23/25 words, slack 2; the phase X1/m2
question remains deliberately untested in v8 (no m2 call exists in this
image).

v7 (D8 discriminator, root-cause round 4 - adjudication build): v6's
inertness is UNPROVEN - at the late site a hit is transparent to the
response (the collector has already run before the hook; the hit path
resumes into the stock completion), so "TRIG out == stock golden" is
equally compatible with hit + silent m2 failure (X1 via runtime r16).
v7 discriminates in ONE burn: v6 stub VERBATIM (16 words) + 2
rc3-verbatim words on the hit path right after the m2 call - w13
`ld.d r6,r1,0xb0` (0x642600b2, rc3 w0 verbatim: load the input
[0x18..0x1c) pair = magic + marker head) and w14 `st.d r6,r18,0x28`
(0x6e40302a, rc3 st.d form: store into the response golden-zero window
[0x28..0x2c); merges land at +0x18/+0x1c/+0x20/+0x30/+0x38, never +0x28
- rc3-T3 golden: zeros except 04@0x1b, 6f28@0x3a). The rc3 resume triplet
shifts to w15-w17 UNCHANGED. 18/25 words, slack 7; slot, hook site
(0x0E43C4), hook word, filter, C-recompute, m2 call - all v6-verbatim.
r18 (rc3 response base) is READ only; the echo writes only r6 (after m2
consumed its args). Tool-side discriminator (live task): TRIG
out[0x28..0x2c) == input[0x18..0x1c) <=> HIT (failure = m2/X1 at stub
depth); echo absent <=> stub dead (iTrace probe next); followup
out[0x28..0x2c) = zeros is the differential control.

v6 (D7 fix, root-cause round 3 - live v5 round): every control stayed
golden on v5 but the filter NEVER hit: the magic is delivered to the host
mailbox byte-exact, yet it never materializes in the FW frame mirror at
[0x12]/[0x24] when in_len < 0x40 (header-normalization / FETCH-length
residuals). The mirror window that IS live-proven byte-exact x9 on this
base (rc3 H1b): payload [0x18..0x40) at in_len=0x40, plus [0x14] (table_id
- the C-success proof). The old hook site 0x0E437C does execute on the
tool's requests (merge->collector->site chain closed statically in RC
round 3), but the filter slot is undeliverable there. v6 = the RC round-3
sketch pinned word-for-word (golden == the sketch listing, 16/16):
- hook relocated to the rc3-proven LATE SITE 0x0E43C4: the stock word
  0x00130000 `addi r19,zero,0x0` is a DEAD WRITE (r19 is dead - the stub
  may skip it, rc3 precedent), located AFTER the collector merges and
  BEFORE the completion POST @0x0e43e4; the mirror payload [0x18..0x40)
  is byte-exact there for in_len=0x40 frames (rc3 H1b live x9 at this
  exact site). Hook word stays the call-to-stub idiom `call 0x38d774`
  (rc3 pin 0x940aa4ec); the old FN_A call-site 0x0E437C stays STOCK.
- magic filter relocated to input[0x18] (frame mirror base r1+0x98 ->
  ld.w from r1+0xb0) - the rc3-proven delivered slot; filter regs stay
  the S2 contract r12/r13 (D5 lineage).
- C recomputed from the mirror (2 words; r8 no longer holds C at the
  late site): `ld.d r4,r1,0xac` (table_id, the live [0x14] slot - the
  same load as the stock C-source @0x0e4368) + `andmsk.hi r6,r4,0xff`
  (C = table_id|0xff, the stock C-idiom shape, destination moved to the
  m2 arg register).
- miss semantics per RC (NOT the v5 tail-jump): the replaced stock word
  is a dead write, so miss = the rc3 absolute resume triplet to the next
  word rt(0x0e43c8): `addi r4,zero,0x43c8` + `addi.hi r4,r4,0x8e` +
  `ret.r zero,zero,r4` (rc3 live-proven x9; the ret.r consumes the hook
  call's RA slot exactly once - RA balance). FN_A is NOT re-invoked: at
  the late site it has already run (collector merges are done).
- hit: r5=obj (r22, live at the late site), r6=C recomputed, r7=buf=
  r1+0xb0 (input[0x18..0x58) = magic + marker payload), r4=dir=0 ->
  call 0x18064c (m2 WRITE-POST with the REGISTERED key) -> the same rc3
  resume triplet -> stock completion.
16/25 words (slack 9), set2-free (the resume is the rc3 addi/addi.hi
idiom, not the v5m set3/set2 r3 build of v3-v5); no jump anywhere (v6 is
jump-free - both paths exit via the return-class triplet).

v5 (D6 fix, fix round 4 - live v4 round, task-4 report Appendix 6): v4
closed D3/D5 live (control open clean; neg/query byte-exact golden incl. neg
3/0x1c2b78) but the probe stayed inert: the TRIG magic 0x55aa staged by the
host at in_mb0+0x02 (input[0x12]) post-completION never materialized in the
FW frame mirror read by the filter ([r1+0xaa]) on the v4-echo base - out_mb0
TRIG == follow-up byte-identical => the filter MISSED every dispatch, the
hit path / m2-POST never ran (D6). Counter-precedent: v5n on the S2b2 base
read magic @input[0x12] live - the differing variable is the v4-echo door
path (R-E H0 hook @0x106390; candidate mechanism: header normalization of
the mirror [0x10..0x18)). Fix: relocate MAGIC16 to input[0x24] - the slot
with PROVEN mirror delivery on THIS base (rc3 H1b live x9,
input[0x18..0x40)): w0 `ld.w r12,r1,0xbc` (0x642c00bd; q-form bit0 set, the
0xaa->0xab pattern). ONLY w0 changes; w1-w13 byte-identical v4; magic value
stays 0x55aa; budget stays 14/25. (Superseded by v6/D7: [0x24] is only
delivered on in_len=0x40 frames.)

v4 (D5 fix, root-cause round 2 - live on v3): v3 closed D4 (RA balance) but
stock QUERY through the hook still returned 3/0x66cbbb on EVERY dispatch
(neg and created, identically on v2/v3 - shared filter). Root cause: the
filter loaded its operand/const into r6/r7 - the LIVE FN_A arguments
(r6=[fr+0x50] serializer out, r7=tt byte) set up at 0x0e4360/0x0e4364
BEFORE the hook - so FN_A->F_SYN's tt-consistency check (r18 vs staging[3],
0x18eb48-0x18eb84) always failed -> 0x366cbbb & 0x7fffff = 0x66cbbb. The
R-D1 addendum's "v5l canon ld.w r6" was a MIS-CITATION: the live canon
(build_s2.py SLOT_FILTER_V5B; T17 live; v5l achieved live stock completion
with it) is `ld.w r12,r1,0xaa` under the S2 clobber contract
{r3,r11,r12,r13}. v4 = v3 with the filter retargeted to r12/r13: w0
0x642c00ab / w1 0x200d55aa / w2 0xe1a06002; w3..w13 byte-identical to v3.
[B1] register discipline extended (D5 regression gate): pre-FN_A (filter)
words may write ONLY {r3,r11,r12,r13} - FAILS on the v3 word set (r6/r7
writes), the class can never pass again.

v3 (D4 fix, task-4 report Appendix 4 — live on v2): v2 closed D3 (the FLR
fetch-fault) but broke stock QUERY semantics: neg Q(0,0) -> status 3 /
syndrome 0x66cbbb (golden 0x1c2b78); query(created) -> 3/0x66cbbb (golden
status=0). Root cause (S1/S2 class C->rot14->lookup 0x18a668->fetch->
PTR_OUT[3]!=B): the v5-family contract at the FN_A call-site hook is
miss = TAIL-JUMP FN_A (the hook call's RA slot is consumed by FN_A itself —
the stock word IS `call FN_A`) and hit-resume = ret.r r3 (return-class,
consumes the hook RA slot exactly once — rc3 absolute-resume / v5m
r3-preload live-proven at this site). v2's miss `call FN_A` + `jump resume`
added an extra call level and its hit `jump resume` never returned: the
hook's RA slot leaked -> broken F_SYN arg/frame context -> 0x66cbbb.
v3: miss = `jump 0x18d964` (dc operand, the D3 lesson; byte-exact the v5l
W_FAST word 0x95f80078 at the same address 0x38d784; NO resume word after
it on the miss path); hit = m2 call + r4=0 + the v5m r3 build (`set3
r3,zero,0x4380` + `set2 r3,r3,0x8e` — byte-exact the v5l/v5m w10/w11 pair)
+ `ret.r zero,r8,r3` (the canonical stock return word 0xfd001825, x8346).
14 words, slack 11. New gate [B7] RA-balance/v5m-idiom pins the word-level
contract and FAILS on the v2 word set.

v2 (root-cause fix, journal 2026-10-21-cx5-rd2-flr-assert, offline RE commit
3f73685): both v1 stub resume jumps were given the rt-numbered RESUME
(0x8e4380) over the assembler's dc-numbered base -> rel24 computed in mixed
spaces -> EFFECTIVE executed target 0x10E4380, outside MAIN_CODE
(0x800000..0xB97DC0) -> fetch fault in the FLR window -> per-core error IRQ
-> FW assert synd 0x8, deterministic 2/2 on VFIO open. v2 encodes the resume
as the dc operand 0x0e4380 (words 0x95f55afe/0x95f55af7; hardware lands at
live rt 0x8E4380). New gate [B6] decodes every emitted jump/call to its
EFFECTIVE executed target (live PC = dc + 0x800000 + 4*sext24(rel24)) and
enforces the MAIN_CODE window + the resume pin, so this defect class can
never pass again.

R-D2 stub INTENT (spec addendum R-D1 verdict (a), 2026-10-21; the original
v1-site design - C-from-r8 was valid at 0x0E437C only, v6 recomputes C from
the mirror at the late site): on a magic QUERY
frame call the stock m2 WRITE-POST transport 0x18064c(r4=0, r5=obj, r6=C,
r7=buf) with the REGISTERED key C = table_id|0xff. POST lands in the
registered table-mailbox page
X1 = F|(v_table<<6)|0x8FC0; readback channel = follow-up plain
query(created) -> stock F_SYN FETCH -> staging merge -> out_mb0+0x1b.

Sketch-vs-built delta (verify-before-fix, journal task-03): the addendum
G10 sketch built its filter const as set2+set3 (0x55aa55aa, 32-bit) and
branched with b.t.0x0 (cc=0). Both close the filter: ld.w is a 16-bit
zero-extending load (T17 live, v5a/v5b), and ALL 6 stock cmp38_eq32 ->
branch sites use cc=0xA (none cc=0; live: v5b b_f.cc0A, v5q b_t.cc0A at
this same hook site). A 32-bit magic via ld.d @0xaa is impossible by
design: it would overlap input[0x14] = table_id, and verdict (a) requires
C = created_id|0xff (FW-assigned runtime). Fix: one-word const
set3 r7,zero,0x55aa (v5b live-proven idiom) + b.t.0xa. 13 words (sketch
14), slack 12; the other 11 words are the sketch verbatim (position-shifted
call/jump rel re-encoded by the assembler; encoding-identical to the G10
expect list).

Patch map (dc = MAIN_CODE de-clcrc byte offset, rt = dc + 0x800000):
  dc 0x0E43C4          stock 0x00130000 `addi r19,zero,0x0` (dead write)
                       -> HOOK_WORD 0x940aa4ec `call 0x38d774` (the
                       rc3-pinned H1b word at the H1b exact site; same
                       site+word as v6/v7/v8). The old FN_A call-site
                       0x0E437C keeps the STOCK word 0x9402a57a.
  dc 0x38d774..0x38d7b0  16-word R-D2 stub in the v4-echo free zone (25 w
                         after the 9-word R-E echo canary @0x38d750):
                          w0-w3 magic filter: MAGIC16 0x55aa @input[0x18]
                          (ld.w r12,r1,0xb0 - the v8-live-proven mirror
                          slot; S2 contract regs r12/r13 - D5) + w1 the
                          clean addi const (v9, M2) + w2 the v5b-VERBATIM
                          cmp38 (v9, M1: VALUE in rs) + b.t.0xa -> hit w7
                          (cc 0xA stock canon);
                          w4-w6 MISS: the rc3 absolute resume triplet
                          (addi r4,zero,0x43c8 / addi.hi r4,r4,0x8e /
                          ret.r zero,zero,r4 -> rt 0x8E43C8; the stock dead
                          write skipped; NO FN_A call, NO jump);
                          w7-w12 HIT: or r5,r22,r22 (obj, stock-verbatim
                          @0x0e4378) -> ld.d r4,r1,0xac (table_id,
                          stock-verbatim @0x0e4368) -> andmsk.hi r6,r4,0xff
                          (C = table_id|0xff recomputed, stock form with
                          rd=r6) -> addi r7,r1,0xb0 (buf =
                          input[0x18..0x58), stock addi form; UNPROVEN-
                          live - only ever rode inert filters) -> addi
                          r4,zero,0x0 (dir=POST, stock-verbatim
                          @0x0e4374) -> call 0x18064c (m2);
                          w13-w15 the same rc3 resume triplet -> stock
                          completion POST @0x0e43e4.
                          Stub writes only r4/r5/r6/r7 + the filter contract
                          regs r12/r13 (filter/pre-branch words restricted
                          to the S2 clobber contract {r3,r11,r12,r13});
                          r8/r1/r22 (and the dead r19) never written; no
                          pushed frame; the m2 call is balanced by its own
                          return and each ret.r consumes the hook RA slot
                          exactly once (RA balance, gate [B7]).
     ITOC 0x30            build-ID '; mlxini cx5-clever rd2 v9 ...' inserted
                         right after the banner (above the retained v4
                         door-detour build-ID line - keep-echo provenance);
                         vendor ';;' comments trimmed to headroom >= 32 (the
                         v4 base ini is packed to 0 B headroom; Rule 2: 0x30
                         stays in place)

Gates (in-script, log build/cx5-clever-rd2-build.log):
  [0] v4-echo base md5 + stock base md5 + MAIN_CODE geometry + clcrc
      round-trip + hook-site stock word (0x0E43C4 dead-write 0x00130000
      `addi r19,zero,0x0` - the H1b exact late site the hook must replace
      EXACTLY) + the OLD FN_A call-site 0x0E437C still stock
      `call 0x18d964` + the stock C-source words @0x0e4368-0x0e436c (the
      C-recompute idiom replicated by stub w8/w9) + stock arg setup
      @0x0e4374/0x0e4378 + resume word @0x0e4380 + H0 0x106390 + S0 inj
      0x1d594 + v4-echo vs stock word-diff == the 17 known R-E words +
      slot occupancy (9-word canary == re1 STUB_B4_WORDS, tail zero, cutout
      zero) -> free zone >= 16+2
   [B1] stub: strict cx5 assemble (decode-verify built in) + per-word
        dis->re-assemble bit-exact; == 16 words, slack >= 2; register
        discipline (writes == {r4..r7} + filter {r12,r13}; filter/pre-branch
        words ONLY the S2 contract {r3,r11,r12,r13} - D5 gate; r8/r1/r22
        never written); set2-free stub (D1 + v6: the resume is the rc3
        addi/addi.hi idiom, not the v5m r3 build); branch cc census ground:
        all stock cmp38_eq32->branch sites use cc 0xA (D2); golden pins ==
        the FULL RC round-6 v9 word list (16 words; w1/w2 = the two v9
        changes); V9 FILTER PINS: w1 == 000d55aa `addi r13,zero,0x55aa`
        (clean mod-2^32 const - M2) + w2 == e1806802 == the v5b-VERBATIM
        live-HIT word (build_s2.py:639 enc.cmp38_sel(2,12,13): VALUE in
        rs=r12, CONST in rt=r13 - M1) + the operand-order decode check
        (rs == the loaded reg r12) + the OLD defect pair 200d55aa/e1a06002
        ABSENT anywhere in the stub (regression orientation: the
        swapped-order / insert-const class can never pass again); control
        targets pinned (b.t.0xa -> hit w7 / call 0x18064c hit / both rc3
        resume triplets verbatim); hook word 0x940aa4ec call-class
        @0x0E43C4 resolves to the stub start (replacing exactly the stock
        dead-write, pinned in [0] and [B4])
   [B2] graft MAIN_CODE: word-diff vs v4-echo == exactly hook + 16 stub
       words; changed 68B clcrc lines == expected; patch_sections; step1
       verify --deep PASS
   [B3] 0x30 build-ID: insert after banner, ';;'-trim to headroom >= 32,
       key=value count invariant, inject (no force), entry addr unchanged,
       size <= old, round-trip extract == edited text, v4 build-ID retained
   [B4] invariants: MAIN_CODE word-diff on the final image == hook + stub
       only; the late-site stock word 0x00130000 replaced by exactly the
       call-class hook word; the old FN_A call-site 0x0E437C STOCK; canary
       9 words byte-equal to the base; cutout/S0/H0/S0-inj untouched;
       byte-diff vs base = MAIN_CODE changed lines + 0x03 entry CRC + 0x30
       section + entry only (guides NOT re-baked); section-level diff ==
       {ITOC 0x03, ITOC 0x30}
   [B5] verify + determinism: mlxfwutil.py verify --deep PASS; mstflint -i
       verify bootable; -i q identity == base (FW/PSID/GUID/MAC, Rule-3
       bake inherited); -i dc build-ID is the first content line after the
       banner (Rule 1, Task-4 activation discriminator); full rebuild ->
       identical md5; ALL GATES PASS
   [B6] jump/call-target window (v2 regression gate): every emitted
        jump/call word (hook + stub) decoded to its EFFECTIVE executed
        target (live PC = dc + 0x800000 + 4*sext24(rel24)) must lie inside
        MAIN_CODE 0x800000..0xB97DC0; v9 is jump-free, so the window covers
        the hook call + the m2 call; the resume pin decodes BOTH rc3
        triplets: addi-lo | addi.hi-hi<<16 must compose rt(0x0e43c8) =
        0x8E43C8; fail loud otherwise (the rd2-v1 defect class: mis-spaced
        resume encodings -> FLR-window fetch fault -> FW assert synd 0x8)
   [B7] RA-balance / rc3-idiom (D4 regression gate, v9 = the v6-lineage
        late-site contract): hook word call-class (1 RA push); exactly one
        conditional branch (b.t.0xa); miss path == exactly the 3-word rc3
        absolute resume triplet ending in ret.r (return-class: consumes
        the hook RA slot exactly once; NO FN_A call, NO jump - at the late
        site the stock word is a dead write, miss = resume to the next
        word rt(0x0e43c8); the v5 miss tail-jump belonged to the OLD site
        where the stock word IS the FN_A call); hit path == exactly one
        `call 0x18064c` + the same triplet terminal; jump census == 0,
        ret census == 2 (one per path), no ret.d. FAILS on the v5 word set
        (14 words / miss tail-jump / v5m r3-build - the old-site contract)
        and on the v8 word set (23 words / unconditional echo)

Task-4 frame contract (tool-side, not image-side; the TRIG frame layout is
patched by the live task, not this builder): TRIG frame = the v7/v8 TRIG
UNCHANGED - in_len = 0x40 (the rc3-proven delivery class - the mirror
payload [0x18..0x40) is byte-exact only for full-length frames); MAGIC16 =
0x55aa at input[0x18..0x1a) (the v8-live-proven slot), read by w0
`ld.w r12,r1,0xb0`; marker p1..p3 (3 words) at input[0x1a..0x26) - inside
the delivered payload window, clear of the magic halfword; the marker must
not appear as a substring of the frame staging area (plan Review Focus 5);
id @input[0x14] = the created table id (C = table_id|0xff recomputed from
the mirror by w8/w9); TRIG must be query(created); negative control =
plain query without magic (stock byte-exact). v9 predictions: TRIG -> hit
(slot/form/const-cleanliness/operand-order - all live-proven components)
-> m2-POST marker into the table mailbox -> follow-up readback
out[0x1b] = 0x53; every control golden (miss = the rc3 triplet no-op
resume). RESERVE discriminator (documented, NOT built): if v9 stays inert,
the only unproven semantic left is cmp38 sel=2 itself -> w2 becomes
`cmp38_eq32 r12,r12` (self-equal, always-true) - ONE burn turns v9 into an
always-hit probe of the whole hit path incl. m2/X1.
"""
import hashlib
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'scripts/probes/cx5-door-detour'))
import mlxfwutil
import re1_stub_draft as re1
from scripts.irisc import assemble, disasm as dis
from scripts.irisc.profiles import load_profile

V4ECHO = REPO / 'build/cx5-door-detour-v4.bin'
V4ECHO_MD5 = '366b9945824571af83a6f36f7cce70f2'
STOCK = re1.BASE
LOG = REPO / 'build/cx5-clever-rd2-build.log'
OUT = REPO / 'build/cx5-clever-rd2-v9.bin'
DET1 = REPO / 'build/cx5-clever-rd2.det1.bin'
DET2 = REPO / 'build/cx5-clever-rd2.det2.bin'
INI = REPO / 'build/cx5-clever-rd2.ini'
INI_RT = REPO / 'build/cx5-clever-rd2.ini.rt'

BUILD_ID = ('; mlxini cx5-clever rd2 v9 (2026-10-21, R-D spec): '
            'm2 with registered C-key, hook 0x0E43C4, base v4-echo keep-echo')
V4_BUILD_ID_PREFIX = '; mlxini cx5 door-detour v4 '
BANNER = ';; Mellanox Technologies LTD'
HEADROOM_MIN = 32

HOOK_SITE, HOOK_STOCK, HOOK_STOCK_DIS = 0x0E43C4, 0x00130000, \
    'addi r19,zero,0x0'
FN_A_SITE, FN_A_STOCK, FN_A_STOCK_DIS = 0x0E437C, 0x9402A57A, \
    'call 0x18d964'
C_SRC_WORDS = [(0x0E4368, 0x642400AE, 'ld.d r4,r1,0xac'),
               (0x0E436C, 0x308800FF, 'andmsk.hi r8,r4,0xff')]
ARG_WORDS = [(0x0E4374, 0x00040000), (0x0E4378, 0xFEC5B008)]
RESUME_WORD = (0x0E4380, 0xFC932008, 'or r19,r4,r4')
H0_SITE, H0_WORD = 0x106390, 0x940A1CF0
S0_INJ, S0_INJ_WORD = 0x1D594, 0x940DC067
S0_ZONE = (0x38D730, 0x38D747)
S0_WORDS = [0x24050000, 0x20A523F0, 0x2406BADC, 0x20C60001,
            0x6CA03002, 0x95F24272]
CUTOUT = re1.CUTOUT
SLOT_DC, SLOT_WORDS = re1.STUB_SLOT_DC, re1.STUB_SLOT_WORDS
CANARY_WORDS = 9
STUB_DC = SLOT_DC + 4 * CANARY_WORDS
STUB_WORDS = 16
SLACK_MIN = 2
MAGIC16 = 0x55AA
MAGIC_MIRROR_OFF = 0xB0
FN_A = 0x18D964
M2 = 0x18064C
MAIN_BASE = 0x800000
RESUME_DC = 0x0E43C8
RESUME_RT = MAIN_BASE + RESUME_DC
HIT_WORD = 7
RESUME_TRIPLETS = ((4, 5, 6), (13, 14, 15))
W1_ADDI = 0x000D55AA
W2_V5B = 0xE1806802
W1_OLD_SET3 = 0x200D55AA
W2_OLD_SWAPPED = 0xE1A06002
GOLDEN = {0: 0x642C00B1, 1: 0x000D55AA, 2: 0xE1806802, 3: 0xA00A0004,
          4: 0x000443C8, 5: 0x0884008E, 6: 0xFC002025, 7: 0xFEC5B008,
          8: 0x642400AE, 9: 0x308600FF, 10: 0x002700B0, 11: 0x00040000,
          12: 0x94F7CBAA, 13: 0x000443C8, 14: 0x0884008E, 15: 0xFC002025}
ALLOWED_WRITES = {4, 5, 6, 7, 11, 12, 13}
EXPECTED_WRITES = {4, 5, 6, 7, 12, 13}
FILTER_ALLOWED_WRITES = {3, 11, 12, 13}
FORBIDDEN_REGS = {1, 8, 17, 18, 19, 20, 21, 22, 23}
NO_WRITE_PREFIX = ('st.', 'ret.', 'b.', 'jump', 'call', 'op0x38')


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


def run(o, cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO))
    o('$ ' + ' '.join(cmd))
    for stream in (r.stdout, r.stderr):
        for line in stream.strip().splitlines():
            o('    ' + line)
    if r.returncode != 0:
        fail(o, 'rc=%d: %s' % (r.returncode, ' '.join(cmd)))
    return r


def zw_pad(text):
    d = zlib.compress(text.encode('latin1'), 9)
    return len(d) + (4 - len(d) % 4) % 4


def wa(text, base):
    data = assemble(text, base=base, profile=load_profile('cx5'), strict=True)
    return list(struct.unpack('>%dI' % (len(data) // 4), data))


def w32(b, off):
    return struct.unpack_from('>I', b, off)[0]


def stub_text():
    return ('ld.w r12,r1,0x%x\n'
            'addi r13,zero,0x%x\n'
            'cmp38_eq32 r12,r13\n'
            'b.t.0xa zero,hit\n'
            'addi r4,zero,0x%x\n'
            'addi.hi r4,r4,0x%x\n'
            'ret.r zero,zero,r4\n'
            'lbl hit\n'
            'or r5,r22,r22\n'
            'ld.d r4,r1,0xac\n'
            'andmsk.hi r6,r4,0xff\n'
            'addi r7,r1,0xb0\n'
            'addi r4,zero,0x0\n'
            'call 0x%x\n'
            'addi r4,zero,0x%x\n'
            'addi.hi r4,r4,0x%x\n'
            'ret.r zero,zero,r4\n'
             % (MAGIC_MIRROR_OFF, MAGIC16,
                RESUME_RT & 0xFFFF, RESUME_RT >> 16, M2,
                RESUME_RT & 0xFFFF, RESUME_RT >> 16))

def parse_write(text):
    mnem = text.split()[0]
    if mnem.startswith(NO_WRITE_PREFIX):
        return None
    first = text.split()[1].split(',')[0]
    if not first.startswith('r') or not first[1:].isdigit():
        return 'BAD:%s' % text
    return int(first[1:])


def gate0(o):
    buf = V4ECHO.read_bytes()
    if hashlib.md5(buf).hexdigest() != V4ECHO_MD5:
        fail(o, 'v4-echo base md5 mismatch (expected %s)' % V4ECHO_MD5)
    if hashlib.md5(STOCK.read_bytes()).hexdigest() != re1.BASE_MD5:
        fail(o, 'stock base md5 mismatch (diff reference drifted)')
    img = mlxfwutil.Image(bytes(buf), str(V4ECHO))
    e = img.find_entry('ITOC', 0x03)
    if (e.addr, e.size, e.clcrc, e.param0) != \
            (re1.SEC_ADDR, re1.SEC_SIZE, 1, 0x800000):
        fail(o, 'MAIN_CODE header mismatch: addr=0x%x size=0x%x clcrc=%s '
             'param0=%#x' % (e.addr, e.size, e.clcrc, e.param0))
    raw = img.section_data(e)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    if mlxfwutil.clcrc_wrap(code, tail) != raw:
        fail(o, 'de-clcrc round-trip failed on the v4-echo base')
    if w32(code, HOOK_SITE) != HOOK_STOCK or \
            dis(w32(code, HOOK_SITE), HOOK_SITE) != HOOK_STOCK_DIS:
        fail(o, 'hook site 0x%x is not the stock dead-write %08x "%s" '
             '(the H1b exact late site the v9 hook must replace exactly)'
             % (HOOK_SITE, HOOK_STOCK, HOOK_STOCK_DIS))
    if w32(code, FN_A_SITE) != FN_A_STOCK or \
            dis(w32(code, FN_A_SITE), FN_A_SITE) != FN_A_STOCK_DIS:
        fail(o, 'old FN_A call-site 0x%x drifted from stock %08x "%s" '
             '(v9 keeps it STOCK - the hook lives at the late site)'
             % (FN_A_SITE, FN_A_STOCK, FN_A_STOCK_DIS))
    for dc, want, want_dis in C_SRC_WORDS:
        if w32(code, dc) != want or dis(w32(code, dc), dc) != want_dis:
            fail(o, 'stock C-source word @0x%x drifted (r8 producer)'
                 % dc)
    for dc, want in ARG_WORDS:
        if w32(code, dc) != want:
            fail(o, 'stock arg-setup word @0x%x drifted: %08x != %08x'
                 % (dc, w32(code, dc), want))
    if w32(code, RESUME_WORD[0]) != RESUME_WORD[1] or \
            dis(w32(code, RESUME_WORD[0]), RESUME_WORD[0]) != RESUME_WORD[2]:
        fail(o, 'resume word @0x%x drifted (r4 marshal)' % RESUME_WORD[0])
    for dc, want in [(H0_SITE, H0_WORD), (S0_INJ, S0_INJ_WORD)]:
        if w32(code, dc) != want:
            fail(o, 'site 0x%x drifted: %08x != %08x'
                 % (dc, w32(code, dc), want))
    if any(w32(code, dc) for dc in range(CUTOUT[0], CUTOUT[1] + 1, 4)):
        fail(o, 'cutout 0x38d748-0x38d74f not zero on the base')
    simg = mlxfwutil.Image(STOCK.read_bytes(), str(STOCK))
    scode, _ = mlxfwutil.clcrc_unwrap(
        simg.section_data(simg.find_entry('ITOC', 0x03)))
    diff = [dc for dc in range(0, len(code), 4)
            if w32(code, dc) != w32(scode, dc)]
    expect = sorted([S0_INJ, H0_SITE]
                    + list(range(S0_ZONE[0], S0_ZONE[1] + 1, 4))
                    + [SLOT_DC + 4 * i for i in range(CANARY_WORDS)])
    if sorted(diff) != expect:
        fail(o, 'v4-echo vs stock word-diff %s != the %d known R-E words'
             % ([hex(d) for d in sorted(diff)], len(expect)))
    for i in range(6):
        if w32(code, S0_ZONE[0] + 4 * i) != S0_WORDS[i]:
            fail(o, 'S0 shellcode word %d drifted' % i)
    slot = [w32(code, SLOT_DC + 4 * i) for i in range(SLOT_WORDS)]
    canary = [w for _, w in re1.STUB_B4_WORDS]
    if slot[:CANARY_WORDS] != canary:
        fail(o, 'slot canary words != re1 STUB_B4_WORDS (R-E echo stub)')
    if len(canary) != CANARY_WORDS:
        fail(o, 're1 STUB_B4_WORDS is %d words, not %d'
             % (len(canary), CANARY_WORDS))
    if any(slot[CANARY_WORDS:]):
        fail(o, 'slot tail beyond the canary is not zero on the base')
    free = SLOT_WORDS - CANARY_WORDS
    if free < STUB_WORDS + SLACK_MIN:
        fail(o, 'free zone %d words < %d + slack %d'
             % (free, STUB_WORDS, SLACK_MIN))
    o('[0] v4-echo base md5 OK (%s); MAIN_CODE addr=0x%x size=0x%x clcrc=1 '
      'param0=0x800000 (de-clcrc round-trip OK); hook site 0x%x=%08x "%s" '
      '(the H1b exact late-site dead-write the v9 hook replaces exactly); '
      'old FN_A call-site 0x%x STOCK %08x "%s"; stock C-source r8 producer '
      '@0x0e4368-6c ("ld.d r4,r1,0xac" + "andmsk.hi r8,r4,0xff" - the C-recompute '
      'idiom replicated by stub w8/w9) + arg setup 0x00040000/0xfec5b008 + '
      'resume marshal "or r19,r4,r4" @0x0e4380 intact; H0/S0 stock words '
      'OK; v4-echo vs stock diff == %d known R-E words (S0 6 + stub 9 + inj '
      '+ H0); slot: %dw canary == re1 STUB_B4_WORDS, cutout zero, free '
      'contiguous zone %dw @0x%x..0x%x (>= %d + slack %d)'
      % (V4ECHO_MD5, re1.SEC_ADDR, re1.SEC_SIZE, HOOK_SITE, HOOK_STOCK,
         HOOK_STOCK_DIS, FN_A_SITE, FN_A_STOCK, FN_A_STOCK_DIS, len(expect),
         CANARY_WORDS, free, STUB_DC,
         SLOT_DC + 4 * (SLOT_WORDS - 1), STUB_WORDS, SLACK_MIN))
    return img, e, raw, code, tail


def stock_cmp38_cc_census(code):
    census = {}
    for i in range(len(code) // 4 - 1):
        w = w32(code, 4 * i)
        if (w >> 26) != 0x38 or (w & 0x7FF) != 2:
            continue
        for j in (i + 1, i + 2, i + 3):
            w2 = w32(code, 4 * j)
            if (w2 >> 24) not in (0xA0, 0xA4):
                continue
            cc = (w2 >> 16) & 0x1F
            census[cc] = census.get(cc, 0) + 1
            break
    return census


def gate_b1(o, code):
    census = stock_cmp38_cc_census(code)
    if census.get(0xA, 0) < 1 or sorted(census) != [0xA]:
        fail(o, 'stock cmp38_eq32->branch cc census %s is not pure cc 0xA '
             '(the D2 fix basis)' % census)
    words = wa(stub_text(), STUB_DC)
    if len(words) != STUB_WORDS:
        fail(o, 'stub is %d words, design = %d (the RC round-6 v9 word '
             'list is 16 words)' % (len(words), STUB_WORDS))
    free = SLOT_WORDS - CANARY_WORDS
    slack = free - len(words)
    if slack < SLACK_MIN:
        fail(o, 'stub slack %d < %d' % (slack, SLACK_MIN))
    writes = set()
    word_dst = {}
    for i, w in enumerate(words):
        dc = STUB_DC + 4 * i
        text = dis(w, dc)
        if not text:
            fail(o, 'stub word %d has an empty decode' % i)
        if wa(text + '\n', dc)[0] != w:
            fail(o, 'stub word %d dis->re-assemble drift' % i)
        if 'set2' in text:
            fail(o, 'stub word %d contains set2 (D1 + v6-lineage: the stub is '
                 'set2-free - the resume is the rc3 addi/addi.hi idiom, '
                 'not the v5m r3 build): %s' % (i, text))
        dst = parse_write(text)
        if dst is not None:
            if not isinstance(dst, int):
                fail(o, 'stub word %d has an unparsable destination: %s'
                     % (i, text))
            word_dst[i] = dst
            writes.add(dst)
            if dst not in ALLOWED_WRITES:
                fail(o, 'stub word %d writes r%d (allowed: hit path '
                     'r4..r7, filter {r3,r11,r12,r13}): %s'
                     % (i, dst, text))
            if dst in FORBIDDEN_REGS:
                fail(o, 'stub word %d writes forbidden r%d (r8/r1=frame/'
                     'r22=obj/ctx live-ins, r19 dead-write skipped): %s'
                     % (i, dst, text))
    br_idx = [i for i in range(len(words))
              if dis(words[i], STUB_DC + 4 * i).split()[0].startswith('b.')]
    if len(br_idx) != 1:
        fail(o, 'stub must contain exactly one conditional branch (the '
             'filter boundary), got %d' % len(br_idx))
    for i in range(0, br_idx[0] + 1):
        dst = word_dst.get(i)
        if dst is not None and dst not in FILTER_ALLOWED_WRITES:
            fail(o, 'filter word w%d writes r%d — pre-branch words may '
                 'write ONLY the S2 clobber-contract regs {r3,r11,r12,r13} '
                 '(the D5 defect class: v1-v3 wrote the live FN_A args '
                 'r6=[fr+0x50]/r7=tt; v9 keeps the filter on the contract '
                 'regs at the late site too)' % (i, dst))
    if writes != EXPECTED_WRITES:
        fail(o, 'stub writes %s != exactly r4..r7 + filter r12/r13'
             % sorted(writes))
    for i, want in GOLDEN.items():
        if words[i] != want:
            fail(o, 'golden pin w%d %08x != %08x (RC round-6 v9 word)'
                 % (i, words[i], want))
    if words[1] != W1_ADDI or \
            dis(words[1], STUB_DC + 4) != 'addi r13,zero,0x%x' % MAGIC16:
        fail(o, 'v9 filter pin w1: expected the CLEAN addi const %08x '
             '"addi r13,zero,0x%x" (M2 fix: the set3 halfword-INSERT '
             'leaves bits 16+ stale for the eq32 feed - RC round 6), got '
             '%08x "%s"' % (W1_ADDI, MAGIC16, words[1],
                            dis(words[1], STUB_DC + 4)))
    if words[2] != W2_V5B or \
            dis(words[2], STUB_DC + 8) != 'op0x38 zero,r12,r13 imm=0x6802':
        fail(o, 'v9 filter pin w2: expected the v5b-VERBATIM live-HIT '
             'cmp38 word %08x (rs=r12 LOADED value, rt=r13 CONST - the M1 '
             'operand-order fix; build_s2.py:639 enc.cmp38_sel(2,12,13)), '
             'got %08x "%s"' % (W2_V5B, words[2],
                                dis(words[2], STUB_DC + 8)))
    for w, why in [(W1_OLD_SET3, 'w1 set3 insert-const (stale bits 16+ -> '
                    'eq32 trunc32 mismatch)'),
                   (W2_OLD_SWAPPED, 'w2 cmp38 swapped operands (const in '
                    'rs - never taken under stale uppers)')]:
        if w in words:
            fail(o, 'v9 regression: the OLD v4-v7 defect word %08x is '
                 'still present (%s - the RC round-6 confirmed defect '
                 'class can never pass again)' % (w, why))
    lo, hi = RESUME_RT & 0xFFFF, RESUME_RT >> 16
    want_ctrl = ['b.t.0xa zero,0x%x' % (STUB_DC + 4 * HIT_WORD),
                 'addi r4,zero,0x%x' % lo, 'addi.hi r4,r4,0x%x' % hi,
                 'ret.r zero,zero,r4',
                 'or r5,r22,r22', 'ld.d r4,r1,0xac', 'andmsk.hi r6,r4,0xff',
                 'addi r7,r1,0xb0', 'addi r4,zero,0x0', 'call 0x%x' % M2,
                 'addi r4,zero,0x%x' % lo, 'addi.hi r4,r4,0x%x' % hi,
                 'ret.r zero,zero,r4']
    got_ctrl = [dis(words[i], STUB_DC + 4 * i)
                for i in range(br_idx[0], len(words))]
    if got_ctrl != want_ctrl:
        fail(o, 'control/target pin mismatch:\n  %s\n  %s'
             % (got_ctrl, want_ctrl))
    hook = wa('call 0x%x' % STUB_DC, HOOK_SITE)[0]
    if dis(hook, HOOK_SITE) != 'call 0x%x' % STUB_DC:
        fail(o, 'hook word decode drift')
    off = hook & 0xFFFFFF
    if off != (STUB_DC - HOOK_SITE) // 4 or off > 0x7FFFFF:
        fail(o, 'hook simm24 0x%x does not resolve to the stub start '
             '(or out of rel24 reach)' % off)
    o('[B1] R-D2 stub: %d words strict-cx5 assembled (decode-verify built '
      'in) + per-word dis->re-assemble bit-exact; slack %d >= %d; register '
      'discipline: writes == {r4..r7} + filter {r12,r13} (filter/pre-branch '
      'words restricted to the S2 contract regs {r3,r11,r12,r13} — D5 '
      'lineage), r8/r1 (frame)/r22 (obj) NEVER written (the dead r19 '
      'skipped — rc3 precedent); set2-free stub (the resume is the rc3 '
      'addi/addi.hi idiom); branch cc fix D2 ground: stock cmp38_eq32 -> '
      'branch census %s (pure cc 0xA) -> b.t.0xa; golden pins == the FULL '
      'RC round-6 v9 listing (%s); V9 FILTER PINS: w1 == %08x clean addi '
      'const (M2) + w2 == %08x v5b-VERBATIM live-HIT cmp38 (rs=r12 value, '
      'rt=r13 const - M1) + old defect pair %08x/%08x ABSENT; control '
      'targets pinned (b.t -> hit w%d / call 0x%x hit / both rc3 resume '
      'triplets -> rt(0x%06x)=0x%06x); hook word %08x "call 0x%x" @0x%06x '
      '(simm24 0x%x, replaces the stock dead-write %08x pinned in [0])'
        % (len(words), slack, SLACK_MIN, census,
           ' '.join('%08x' % words[i] for i in sorted(GOLDEN)), W1_ADDI,
           W2_V5B, W1_OLD_SET3, W2_OLD_SWAPPED, HIT_WORD, M2,
           RESUME_DC, RESUME_RT, hook, STUB_DC, HOOK_SITE, off, HOOK_STOCK))
    o('      dc       rt       word     disasm')
    for i, w in enumerate(words):
        o('      0x%06x  0x%06x  %08x  %s'
          % (STUB_DC + 4 * i, STUB_DC + 4 * i + 0x800000, w,
             dis(w, STUB_DC + 4 * i)))
    return words, hook


def sext24(x):
    return x - 0x1000000 if x & 0x800000 else x


def live_target(word, dc):
    return MAIN_BASE + dc + 4 * sext24(word & 0xFFFFFF)


def _last_hex(text):
    return int(text.replace(',', ' ').split()[-1], 16)


def gate_b7(o, words, hook):
    dis_stub = [dis(w, STUB_DC + 4 * i) for i, w in enumerate(words)]
    mnems = [t.split()[0] for t in dis_stub]
    brs = [i for i, m in enumerate(mnems) if m.startswith(('b.t', 'b.f'))]
    if len(brs) != 1:
        fail(o, '[B7] expected exactly one conditional branch (the filter),'
             ' got %d' % len(brs))
    bi = brs[0]
    if not dis_stub[bi].startswith('b.t.0xa'):
        fail(o, '[B7] filter branch %r is not b.t.cc0A (stock canon)'
             % dis_stub[bi])
    hit_i = (_last_hex(dis_stub[bi]) - STUB_DC) // 4
    if not bi < hit_i <= len(words):
        fail(o, '[B7] filter branch target word %d out of range' % hit_i)
    triplet = ['addi r4,zero,0x%x' % (RESUME_RT & 0xFFFF),
               'addi.hi r4,r4,0x%x' % (RESUME_RT >> 16),
               'ret.r zero,zero,r4']
    miss = list(range(bi + 1, hit_i))
    if [dis_stub[i] for i in miss] != triplet:
        fail(o, '[B7] miss path %s is not the rc3 absolute resume triplet '
             '(v9 late-site contract: the stock word being replaced is a '
             'DEAD WRITE — miss = resume to the next word rt(0x%06x) via '
             'addi/addi.hi r4 + ret.r; the FN_A tail-jump of v3-v5 belongs '
             'to the OLD site 0x0E437C where the stock word IS the FN_A '
             'call)' % ([dis_stub[i] for i in miss], RESUME_DC))
    miss_push = sum(1 for i in miss if mnems[i] == 'call')
    if miss_push:
        fail(o, '[B7] miss path pushes %d RA slots (must be 0: at the late '
             'site FN_A has already run — the collector merges are done; '
             'the ret.r consumes the hook RA slot exactly once)'
             % miss_push)
    hit = list(range(hit_i, len(words)))
    hit_calls = [i for i in hit if mnems[i] == 'call']
    if len(hit_calls) != 1 or _last_hex(dis_stub[hit_calls[0]]) != M2:
        fail(o, '[B7] hit path calls %s != exactly one m2 call 0x%x (the '
             'call is balanced by m2 own return; any second call adds an '
             'RA level)' % ([dis_stub[i] for i in hit_calls], M2))
    if [dis_stub[i] for i in hit[-3:]] != triplet:
        fail(o, '[B7] hit path must end with the same rc3 resume triplet '
             '(return-class, consumes the hook RA slot exactly once): %r'
             % dis_stub[-3:])
    rets = [i for i, m in enumerate(mnems) if m.startswith('ret.')]
    if rets != [len(miss) + bi, len(words) - 1]:
        fail(o, '[B7] return-class words %s != exactly the two path-'
             'terminal ret.r (one per path; a ret at any other depth would '
             'eat the RA slot wrongly)' % rets)
    if any(m == 'ret.d' for m in mnems):
        fail(o, '[B7] ret.d in the stub (unconditional pop at stub depth '
             'would consume the wrong RA slot)')
    jumps = [i for i, m in enumerate(mnems) if m == 'jump']
    if jumps:
        fail(o, '[B7] jump words %s — v9 is jump-free (both paths exit '
             'via the return-class rc3 triplet; a jump resume leaks the '
             'hook RA slot — the D4 defect class of v2, and the v5 miss '
             'tail-jump is the OLD-site contract)' % jumps)
    r4 = ((words[miss[1]] & 0xFFFF) << 16) | (words[miss[0]] & 0xFFFF)
    r4b = ((words[-2] & 0xFFFF) << 16) | (words[-3] & 0xFFFF)
    if r4 != RESUME_RT or r4b != RESUME_RT:
        fail(o, '[B7] resume triplets compose 0x%x/0x%x != rt(0x%06x) = '
             '0x%06x (the register-targeted rc3 resume must preload r4 '
             'with the word after the late-site hook)'
             % (r4, r4b, RESUME_DC, RESUME_RT))
    if dis(hook, HOOK_SITE).split()[0] != 'call':
        fail(o, '[B7] hook word is not call-class (its single RA push is '
             'what both ret.r exits consume — the rc3 idiom at this site)')
    o('[B7] RA-balance / rc3-idiom (late site): hook = call-class (1 RA '
      'push); miss = the rc3 absolute resume triplet alone (0 calls, 0 '
      'jumps — the stock dead write skipped, ret.r consumes the hook RA '
      'slot exactly once; rc3 live x9 precedent); hit = exactly one call '
      '0x%x (balanced by m2 own return) + the same triplet terminal; jump '
      'census == 0, ret census == 2 (one per path), no ret.d; both '
      'triplets compose 0x%06x == rt(0x%06x) — net RA-slot leak 0 (the '
      'D4 class: a leaked hook call level breaks stock QUERY; the v5 '
      'word set fails here — 14 words / miss tail-jump / v5m r3-build)'
      % (M2, RESUME_RT, RESUME_DC))


def gate_b6(o, code, words, hook):
    end = MAIN_BASE + len(code)
    checked = []
    for dc, w, tag in [(HOOK_SITE, hook, 'hook')] + \
            [(STUB_DC + 4 * i, w, 'w%d' % i) for i, w in enumerate(words)]:
        mnem = dis(w, dc).split()[0]
        if mnem not in ('jump', 'call'):
            continue
        tgt = live_target(w, dc)
        if not MAIN_BASE <= tgt < end:
            fail(o, '[B6] %s %s EFFECTIVE executed target 0x%07x is outside '
                 'the MAIN_CODE window 0x%06x..0x%06x (hardware adds '
                 '4*sext24(rel24) to the live PC = dc + 0x800000; this is '
                 'the rd2-v1 FLR-assert defect class: rt-numbered operand '
                 'over a dc-numbered assembler base)' % (tag, mnem, tgt,
                                                         MAIN_BASE, end))
        checked.append((tag, mnem, tgt))
    for lo, hi, rt_i in RESUME_TRIPLETS:
        r4 = ((words[hi] & 0xFFFF) << 16) | (words[lo] & 0xFFFF)
        if dis(words[lo], STUB_DC + 4 * lo) != \
                'addi r4,zero,0x%x' % (RESUME_RT & 0xFFFF) or \
                dis(words[hi], STUB_DC + 4 * hi) != \
                'addi.hi r4,r4,0x%x' % (RESUME_RT >> 16) or \
                dis(words[rt_i], STUB_DC + 4 * rt_i) != \
                'ret.r zero,zero,r4' or r4 != RESUME_RT:
            fail(o, '[B6] resume triplet w%d/w%d/w%d composes 0x%x != '
                 'rt(0x%06x) = 0x%06x (the register-targeted rc3 resume '
                 'must preload r4 with the word after the late-site hook; '
                 'addi lo + addi.hi hi<<16 + ret.r transfer)'
                 % (lo, hi, rt_i, r4, RESUME_DC, RESUME_RT))
    o('[B6] jump/call-target window: %d jump/call words (hook + stub) '
      'decoded to EFFECTIVE executed targets (live PC = dc + 0x800000 + '
      '4*sext24(rel24)): all inside MAIN_CODE 0x%06x..0x%06x (v9 is '
      'jump-free — the window covers the hook call + the m2 call); '
      'register-targeted resume: both rc3 triplets compose 0x%06x == '
      'rt(0x%06x) (%s)'
      % (len(checked), MAIN_BASE, end, RESUME_RT, RESUME_DC,
         ' '.join('%s %s->0x%07x' % (t, m, g) for t, m, g in checked)))


def graft(o, img, raw, code, tail, stub_words, hook):
    patch = {HOOK_SITE: hook}
    for i, w in enumerate(stub_words):
        patch[STUB_DC + 4 * i] = w
    if len(patch) != 1 + STUB_WORDS:
        fail(o, 'patch map size drift: %d' % len(patch))
    new_code = bytearray(code)
    for dc, w in patch.items():
        new_code[dc:dc + 4] = struct.pack('>I', w)
    new_code = bytes(new_code)
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(new_code, dc)]
    if sorted(changed) != sorted(patch):
        fail(o, 'word-diff %s != intended %d words'
             % ([hex(d) for d in changed], len(patch)))
    exp_lines = sorted({dc // 64 for dc in patch})
    new_raw = mlxfwutil.clcrc_wrap(new_code, tail)
    diff_lines = [i for i in range(len(code) // 64)
                  if raw[i * 68:(i + 1) * 68] !=
                  new_raw[i * 68:(i + 1) * 68]]
    if diff_lines != exp_lines:
        fail(o, 'changed 68B lines %s != expected %s'
             % (diff_lines, exp_lines))
    edits = [(0x03, i * 68, new_raw[i * 68:(i + 1) * 68]) for i in diff_lines]
    out = mlxfwutil.patch_sections(img, edits)
    pimg = mlxfwutil.Image(out, 'step1', base=img.base, fmt=img.fmt)
    praw = pimg.section_data(pimg.find_entry('ITOC', 0x03))
    if praw != new_raw:
        fail(o, 'built MAIN_CODE raw mismatch')
    if mlxfwutil.clcrc_wrap(*mlxfwutil.clcrc_unwrap(praw)) != praw:
        fail(o, 'per-line clcrc round-trip failed on step1')
    errs = mlxfwutil.verify_image(pimg, deep=True)
    if errs:
        fail(o, 'step1 verify --deep failed: %s' % errs)
    o('[B2] graft MAIN_CODE: %d words (hook 1 @0x%x + stub %d @0x%x..0x%x); '
      'word-diff vs v4-echo == exactly the intended set; changed 68B clcrc '
      'lines %s == expected; patch_sections OK (per-line clcrc + section/'
      'entry CRC); step1 verify --deep PASS; md5 %s'
      % (len(patch), HOOK_SITE, len(stub_words), STUB_DC,
         STUB_DC + 4 * (len(stub_words) - 1), [hex(i) for i in diff_lines],
         hashlib.md5(out).hexdigest()))
    return out, exp_lines


def inject_030(o, step1_path, ini_path, ini_rt_path, out_path):
    img = mlxfwutil.Image(V4ECHO.read_bytes(), str(V4ECHO))
    e30 = img.find_entry('ITOC', 0x30)
    run(o, ['python3', 'mlxfwutil.py', 'extract', str(step1_path), '-s', '0x30',
            '-o', str(ini_path)])
    text = ini_path.read_text(encoding='latin1')
    lines = text.splitlines(keepends=True)
    banners = [i for i, l in enumerate(lines) if l.startswith(BANNER)]
    if len(banners) != 1:
        fail(o, 'expected exactly one banner, got %d' % len(banners))
    bi = banners[0]
    prior = [l for l in lines if l.startswith('; mlxini ')]
    if len(prior) != 1 or not prior[0].startswith(V4_BUILD_ID_PREFIX):
        fail(o, 'base ini does not carry exactly the v4 door-detour '
             'build-ID line: %r' % prior)
    v4_id = prior[0]
    lines.insert(bi + 1, BUILD_ID + '\n')
    kv0 = sum(1 for l in lines if l.strip() and not l.startswith(';'))
    cand = [i for i, l in enumerate(lines)
            if l.startswith(';;') and i != bi]
    dropped = []

    def cur_text():
        ds = set(dropped)
        return ''.join(l for i, l in enumerate(lines) if i not in ds)

    while zw_pad(cur_text()) > e30.size - HEADROOM_MIN:
        if not cand:
            fail(o, '0x30: no ;; lines left to trim, still over budget')
        dropped.append(cand.pop(0))
    ini_final = cur_text()
    kv1 = sum(1 for l in lines if l.strip() and not l.startswith(';'))
    if kv0 != kv1:
        fail(o, 'key=value line count changed: %d -> %d' % (kv0, kv1))
    if v4_id not in ini_final or BUILD_ID not in ini_final:
        fail(o, 'edited ini lost the v4 build-ID or the R-D2 build-ID')
    if ini_final.splitlines().index(BUILD_ID) != \
            ini_final.splitlines().index(BANNER) + 1:
        fail(o, 'R-D2 build-ID is not right after the banner')
    ini_path.write_text(ini_final, encoding='latin1')
    run(o, ['python3', 'mlxfwutil.py', 'inject', str(step1_path), str(ini_path),
            '-o', str(out_path)])
    simg = mlxfwutil.Image(Path(out_path).read_bytes(), 'step2', base=img.base,
                        fmt=img.fmt)
    e30n = simg.find_entry('ITOC', 0x30)
    if e30n.addr != e30.addr:
        fail(o, '0x30 relocated: 0x%x -> 0x%x' % (e30.addr, e30n.addr))
    if e30n.size > e30.size or e30.size - e30n.size < HEADROOM_MIN:
        fail(o, '0x30 size gate: 0x%x -> 0x%x (headroom %d)'
             % (e30.size, e30n.size, e30.size - e30n.size))
    run(o, ['python3', 'mlxfwutil.py', 'extract', str(out_path), '-s', '0x30',
            '-o', str(ini_rt_path)])
    if ini_rt_path.read_text(encoding='latin1') != ini_final:
        fail(o, '0x30 round-trip mismatch')
    o('[B3] 0x30 build-ID: base packed %d vs e.size %d (headroom %d); '
      'R-D2 BUILD_ID inserted right after the banner (v4 door-detour ID '
      'retained below it); trimmed %d vendor ;; lines (key=value lines '
      'intact: %d); final packed %d, headroom %d >= %d; entry in place '
      '@0x%x, size 0x%x -> 0x%x; round-trip == edited text OK'
      % (zw_pad(text), e30.size, e30.size - zw_pad(text), len(dropped), kv1,
         zw_pad(ini_final), e30.size - zw_pad(ini_final), HEADROOM_MIN,
         e30n.addr, e30.size, e30n.size))
    for i in dropped:
        o('      trim: %r' % lines[i].rstrip())
    return ini_final


def gate_b4(o, base_img, exp_lines, stub_words, hook):
    out = OUT.read_bytes()
    img = mlxfwutil.Image(out, 'final', base=base_img.base, fmt=base_img.fmt)
    e03 = img.find_entry('ITOC', 0x03)
    b03 = base_img.find_entry('ITOC', 0x03)
    e30 = base_img.find_entry('ITOC', 0x30)
    code, _ = mlxfwutil.clcrc_unwrap(img.section_data(e03))
    bcode, _ = mlxfwutil.clcrc_unwrap(base_img.section_data(b03))
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(bcode, dc)]
    want = sorted([HOOK_SITE] + [STUB_DC + 4 * i for i in range(STUB_WORDS)])
    if sorted(changed) != want:
        fail(o, 'final MAIN_CODE word-diff %s != hook+stub %d words'
             % ([hex(d) for d in changed], len(want)))
    if w32(bcode, HOOK_SITE) != HOOK_STOCK:
        fail(o, 'base word at the late site 0x%x is not the stock '
             'dead-write %08x' % (HOOK_SITE, HOOK_STOCK))
    if w32(code, HOOK_SITE) != hook:
        fail(o, 'final word at the late site 0x%x is %08x, not exactly the '
             'hook word %08x (the v9 hook must replace exactly the stock '
             'dead-write %08x)' % (HOOK_SITE, w32(code, HOOK_SITE), hook,
                                   HOOK_STOCK))
    if w32(code, FN_A_SITE) != FN_A_STOCK or \
            w32(bcode, FN_A_SITE) != FN_A_STOCK:
        fail(o, 'the old FN_A call-site 0x%x must stay STOCK %08x in the '
             'final image (the v9 hook lives at the late site 0x%x)'
             % (FN_A_SITE, FN_A_STOCK, HOOK_SITE))
    for i in range(CANARY_WORDS):
        if w32(code, SLOT_DC + 4 * i) != w32(bcode, SLOT_DC + 4 * i):
            fail(o, 'canary slot word %d modified' % i)
    if any(w32(code, dc) for dc in range(CUTOUT[0], CUTOUT[1] + 1, 4)):
        fail(o, 'cutout touched in the final image')
    for dc in [H0_SITE, S0_INJ] + \
            list(range(S0_ZONE[0], S0_ZONE[1] + 1, 4)):
        if w32(code, dc) != w32(bcode, dc):
            fail(o, 'R-E zone word 0x%x drifted in the final image' % dc)
    ent03 = base_img.itoc_off + 32 + b03.index * 32
    ent30 = base_img.itoc_off + 32 + e30.index * 32
    zones = {}
    for ln in exp_lines:
        zones['MAIN_CODE line %d' % ln] = range(b03.addr + ln * 68,
                                                b03.addr + ln * 68 + 68)
    zones['ITOC 0x03 entry CRC'] = range(ent03 + 0x1A, ent03 + 0x20)
    zones['0x30 section'] = range(e30.addr, e30.addr + e30.size)
    zones['ITOC 0x30 entry'] = range(ent30, ent30 + 32)
    allowed = set()
    for r in zones.values():
        allowed |= set(r)
    buf = V4ECHO.read_bytes()
    diffs = [i for i in range(len(out)) if out[i] != buf[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    if stray:
        fail(o, 'stray diff bytes outside the intended zones: %s' % stray)
    for name, r in zones.items():
        if not any(i in diffs for i in r):
            fail(o, 'expected zone has no diff bytes: %s' % name)
    changed_secs = []
    for toc in ('ITOC', 'DTOC'):
        bes = list(base_img.entries(toc))
        fes = list(img.entries(toc))
        if len(bes) != len(fes):
            fail(o, '%s entry count changed %d -> %d (per-type keys collide '
                 'on the dual 0xE1 DTOC entries)' % (toc, len(bes), len(fes)))
        for e, fe in zip(bes, fes):
            if fe.type != e.type or img.section_data(fe) != \
                    base_img.section_data(e):
                changed_secs.append('%s 0x%02x' % (toc, e.type))
    if sorted(changed_secs) != ['ITOC 0x03', 'ITOC 0x30']:
        fail(o, 'section-level diff %s != {ITOC 0x03, ITOC 0x30} '
             '(guides must NOT be re-baked)' % sorted(changed_secs))
    o('[B4] invariants: final MAIN_CODE word-diff == hook + %d stub words '
      'only; the late-site stock dead-write %08x @0x%06x replaced by '
      'exactly the call-class hook %08x; the old FN_A call-site 0x%06x '
      'STOCK; canary %dw byte-equal to the base; cutout/S0/H0/S0-inj '
      'untouched; byte-diff vs base: %d bytes in %d zones, strays none; '
      'section-level diff %s (guides inherited, not re-baked)'
      % (STUB_WORDS, HOOK_STOCK, HOOK_SITE, hook, FN_A_SITE, CANARY_WORDS,
         len(diffs), len(zones), sorted(changed_secs)))


def gate_b5(o, base_img):
    run(o, ['python3', 'mlxfwutil.py', 'verify', '--deep', str(OUT)])
    r = run(o, ['mstflint', '-i', str(OUT), 'verify'])
    if 'bootable' not in (r.stdout + r.stderr) or \
            'verification succeeded' not in (r.stdout + r.stderr):
        fail(o, 'mstflint verify did not report bootable')

    def q(path):
        r = subprocess.run(['mstflint', '-i', str(path), 'q'],
                           capture_output=True, text=True, cwd=str(REPO))
        got = {}
        for l in (r.stdout + r.stderr).splitlines():
            for k in ('FW Version', 'PSID', 'Base GUID', 'Base MAC'):
                if l.strip().startswith(k + ':'):
                    rest = l.split(':', 1)[1].split()
                    got[k] = rest[0] if rest else ''
        return got
    qb, qf = q(V4ECHO), q(OUT)
    for k in ('FW Version', 'PSID', 'Base GUID', 'Base MAC'):
        if qf.get(k) != qb.get(k):
            fail(o, 'identity %s changed vs base: %r -> %r'
                 % (k, qb.get(k), qf.get(k)))
    if qf.get('Base GUID', '').lower() != mlxfwutil.hw('CARD_CX5_EDR100', 'guid'):
        fail(o, 'Base GUID is not the card canon: %r' % qf)
    r = subprocess.run(['mstflint', '-i', str(OUT), 'dc'],
                       capture_output=True, text=True, cwd=str(REPO))
    if r.returncode != 0:
        fail(o, 'mstflint dc rc=%d: %s' % (r.returncode, r.stderr.strip()))
    dl = [l.rstrip() for l in (r.stdout + r.stderr).splitlines()]
    shown = 0
    for l in dl:
        if l.strip() and not l.startswith(('-E-', '-W-', '-I-', '-')):
            o('      dc| ' + l)
            shown += 1
        if shown >= 4:
            break
    mi = None
    for i, l in enumerate(dl):
        if BUILD_ID in l:
            mi = i
            break
    if mi is None:
        fail(o, 'mstflint dc does not show the R-D2 build-ID')
    pre = [l for l in dl[:mi]
           if l.strip() and not l.startswith(('-E-', '-W-', '-I-', '-'))]
    if any(not l.startswith(';;') for l in pre) or len(pre) > 1:
        fail(o, 'build-ID is not right after the banner (pre: %r)' % pre)
    md5 = hashlib.md5(OUT.read_bytes()).hexdigest()
    o('[B5] verify: mlxfwutil.py verify --deep PASS; mstflint -i verify '
      '"Image is bootable"; -i q identity == base (FW %s, PSID %s, GUID '
      '%s, MAC %s - Rule-3 bake inherited); dc build-ID is the first '
      'content line after the banner (Rule 1); image md5 %s'
      % (qf.get('FW Version'), qf.get('PSID'), qf.get('Base GUID'),
         qf.get('Base MAC'), md5))
    return md5


def determinism(o, raw, code, tail, stub_words, hook, md5):
    o('[B5] determinism: full rebuild below via the same [B2]/[B3] '
      'pipeline into temp paths, then md5 compare')
    img = mlxfwutil.Image(V4ECHO.read_bytes(), str(V4ECHO))
    det1, _ = graft(o, img, raw, code, tail, stub_words, hook)
    DET1.write_bytes(det1)
    inject_030(o, DET1, INI, INI_RT, DET2)
    md5b = hashlib.md5(DET2.read_bytes()).hexdigest()
    if md5b != md5:
        fail(o, 'determinism: rebuild md5 %s != %s' % (md5b, md5))
    o('[B5] determinism: full rebuild (graft + 0x30 inject) md5 %s == '
      'first pass' % md5b)


def main():
    o = Out()
    o('cx5-clever R-D2 image builder (offline): %s -> %s'
      % (V4ECHO.name, OUT.name))
    img, e, raw, code, tail = gate0(o)
    stub_words, hook = gate_b1(o, code)
    gate_b6(o, code, stub_words, hook)
    gate_b7(o, stub_words, hook)
    step1, exp_lines = graft(o, img, raw, code, tail, stub_words, hook)
    STEP1 = REPO / 'build/cx5-clever-rd2.step1.bin'
    STEP1.write_bytes(step1)
    inject_030(o, STEP1, INI, INI_RT, OUT)
    gate_b4(o, img, exp_lines, stub_words, hook)
    md5 = gate_b5(o, img)
    determinism(o, raw, code, tail, stub_words, hook, md5)
    for p in (INI, INI_RT, STEP1, DET1, DET2):
        p.unlink()
    o('ALL GATES PASS ([0] B1 B2 B3 B4 B5 B6 B7)')
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text('\n'.join(o.lines) + '\n')
    o('DONE %s md5=%s log=%s' % (OUT, md5, LOG))
    o('T4 frame contract: TRIG = the v7/v8 frame UNCHANGED - in_len=0x40 '
       '(the rc3-proven delivery class); MAGIC16=0x55aa @input[0x18..0x1a) '
       '(the v8-live-proven slot, read by w0 ld.w r12,r1,0xb0); marker '
       'p1..p3 (3 words) @input[0x1a..0x26) clear of the magic halfword, '
       '!= staging substring (tool-side TRIG layout - live task); id '
       '@input[0x14] = created table id (C recomputed from the mirror by '
       'w8/w9); TRIG = query(created); negative control = plain query (no '
       'magic). v9 predictions: TRIG -> hit -> m2-POST marker -> follow-up '
       'readback out[0x1b]=0x53; controls golden (miss = rc3 triplet '
       'no-op). RESERVE (NOT built): if v9 inert -> w2 cmp38_eq32 r12,r12 '
       'always-true - one burn probes the whole hit path incl. m2/X1')


if __name__ == '__main__':
    main()
