#!/usr/bin/env python3
"""S2 image builder (mode A): call-site detour + stack-payload stub.

Base: build/4030-cda-patched3.bin (S0 boot-marker image).  Diff = 1 word
@0x0e437c (`call 0x18d964` -> `call 0x38d750`) + stub <=34 words in the
proven ID zone 0x38d750-0x38d7d7 + ITOC 0x03 CRC fixup.

Stub v2 (mode A): MAGIC filter on command-input word[0] (T2: input[k] =
[r1_fn+0xa0+k] = [r20+0x58+k]); copy N payload words onto the stack frame
(T1: STUB_FRAME_OK=0x40, clobber {r3,r11,r12,r13} + r4/r5/r6), jump to the
stack payload with r4=result-buffer / r5 / r6 from the header (spec 3.5),
then restore and tail-jump FN_A (stock BadParam completion).  Non-magic
commands take the fast path: straight tail-jump with stock args.

Stub v4 (task-09/task-10): dispatcher routes on input[0..2] (R5 live fact),
so the v2 MAGIC@0 filter is dead.  v4 filters on DISCRIM32=0x0432434D at
input[8..0xC) (T9: TT=0x04 passes the TT gates live-proven class, pad=0x32
non-stock, table_number unchecked; input[4..8) MUST be 0 for validator
gates G5/G6/G7).  v4 header: N@0xC, r5-init@0x10, code@0x14..0x24 (<=4
words).  r6-init dropped (r6 keeps its call-site value; save/restore pair
kept so a payload writing r6 cannot corrupt the site args) -> budget 34->33
words.  Echo: 0x2380 <- compared word (=DISCRIM32 on a magic run),
0x2384 <- N.  Everything else (copy loop, resume, tail-jump) as in v2.

Stub v5a (task-16, after T15-final "no decode-proven filter slot"): tiny
diagnostic echo-probe — NO filter, NO frame, NO payload, NO csr_r.  On
EVERY 0x0932 arrival at the detour it echoes 4 candidate 16-bit halfwords
`ld.w r12,[r1+X]; st.d r12,0,CR_X` for X in {0xa0 (control: tn, landing
decode/live-proven), 0xaa, 0xac, 0xb2 (candidate tail slots)} ->
CR {0x2380, 0x2384, 0x2388, 0x238C}, then tail-jumps FN_A stock-style
(ra lives in csr0xbc untouched until FN_A's own prologue reads it).
Clobber: r12 only.  One burn + probe matrix (T17) -> empirical landing
map -> v5b filter decision.

Stub v5b (task-18, consumes T17 verdict): C1-attempt image with the
LIVE-PROVEN filter slot.  Filter: `ld.w r12,[r1+0xaa]` (h = input[0x12]
<<8|input[0x13], BE halfword, zext — T17 live) vs `set3 r13,zero,0x5332`
(1-word const, fuzz-task-03 behavioral proof) via cmp38_sel(2) eq32;
miss -> W_FAST fast path.  On magic: echo halfword -> 0x2380, N (16-bit,
input[0xC..0xE) via [r1+0xa4]) -> 0x2384 loaded into r13 (the subsi loop
counter — r13's filter const is dead after the cmp; gauntlet reloads r13),
then a stub-side N guard (set3 r12,zero,4; cmp38_sel(2) eq32; b_f.cc0A ->
W_FAST — same clean fast exit as a filter miss) so a garbage N from the
hypothesis-grade slot never reaches the copy loop, then push frame, copy N
payload words input+0x14 -> [r1+0x20).  Copy loop keeps the v2/v4 shape but uses
TWO ld.w/st.w halfword pairs per addi-4 iteration: ld.w/st.w are 16-bit
ops (slaspec *[ram]:2, T17 live width), so the v2/v4 single-pair loop
would copy only every other halfword (never caught: v2/v4 filters were
dead live).  MANDATORY gauntlet (T17 reconciliation: landing for k>=0x15
is a hypothesis — marshal-writer zone): before any payload jump the first
copied halfword ([r1+0x20], hi halfword of word[0]) is checked against
0x2407 (marker-lite word[0]=0x24075332); miss -> pop + tail-jump FN_A
(clean stock completion, garbage never executes).  No r4/r5/r6 init
(marker-lite needs none) -> clobber is exactly {r3,r11,r12,r13}; resume
block = pop + tail-jump (r3 is dead: FN_A prologue re-reads csr0xbc —
v5a-proven idiom).  33 of 34 zone words; ra-save kept as v2 lineage.

Stub v5c-A (task-20, plan addendum 4694434): frame-only DIAGNOSTIC probe for
the write-path host-freeze (task-19-debug2: gauntlet-neg froze the host 2/2;
RC1 = zero-precedent forms).  v5b prefix words 0-11 verbatim (live-proven;
b_f.cc0A immediates retargeted to the new W_FAST @word 20 = 0x38d7a0), then
M0 -> push `st.d! r1,r1,-0x40` -> M1 -> pop `addi r1,r1,0x40` (both
stock-identical, 185/185 exact stock sites) -> M2 -> tail-jump FN_A.  Stage
markers: `set3 r12,zero,VAL` + `st.d r12,zero,0x238C` (VAL 1/2/3) — the st.d
word 0x6C04638E is the v5a-live byte-exact CR-0x238C probe word; set3 rd=12
is stock-precedented (362 code sites) and v5b-live (N-guard const 0x200C0004
ran clean in the G-echo run).  NO saves, NO copy loop, NO gauntlet, NO
payload — on the freeze frame the last live marker in CR 0x238C names the
stage (0 = before M0: filter region; 1 = froze at push; 2 = froze at pop;
3 = stub survived: freeze is later => RC1 narrowed to saves/copy/gauntlet,
go v5c-B).  21 of 34 zone words.

Stub v5c-B (task-21, task-19-debug2 §v5c-B + task-20 Phase-2 ruling): the
FULL v5b write path instrumented — every suspect word VERBATIM (ra-save,
dst-init addi, copy loop: two ld.w/st.w pairs + addi strides + subsi +
b_f.cc00 back-edge, gauntlet: ld.w + set3-const + cmp38_sel + b_f) — to
pinpoint the freeze group {saves, copy-loop, gauntlet} left after v5c-A
proved prefix/push/pop innocent (live x2, CR=M2).  Budget resolution for
the hard 34-word zone (brief's maximal design — markers M0..M4 + gauntlet +
payload-jump block + counter = 43 words — cannot fit): drop M0/M4 (brackets
of the already-exonerated push/pop), drop M3 + the payload-jump block
(match-path only: THE test frame is gauntlet-neg = miss, and payload words
never executed in the v5b freeze runs) => exactly 34 words WITH the counter.
Markers: M1=2 after the save, M2=3 after the copy loop (`set3 r12,zero,VAL`
+ `st.d r12,zero,0x238C`, v5a-live/v5cA-live word) — values keep the brief's
interpretation semantics (freeze -> CR 0x238C: <2 = saves (push innocent),
2 = copy-loop, 3 = gauntlet (pop innocent); clean completion = survived).
In-loop iteration-counter snapshot `st.d r13,zero,0x2388` after the 2nd
st.w (values 4/3/2/1 across the 4 iterations): rt=13/rs=zero = the
v5b-live N-echo word form (0x6C046B86 ran in every live magic run), CR
0x2388 = the v5a-live probe-3 target (0x6C04638A).  Copy-loop back-edge
immediate -7 -> -8 (counter word inserted; same loop-head target — the
task-19-debug2 §v5c-B documented shift).  No payload jump: on a gauntlet
MATCH the fallthrough reaches the pop too (clean stock completion both
ways).  34 of 34 zone words; W_FAST @word 33 = 0x38d7d4.

Stub v5d (task-23, task-22 audit verdict + Step-7 sketch, review-approved):
C1-candidate with a stock-conformance copy data path.  v5b flow verbatim;
ONLY the copy-loop data words change: the two 16-bit ld.w/st.w halfword
pairs (st.w rt=3 and rs=12 — both 0/1947 stock, the top residual suspects
of the task-22 audit) collapse to ONE 32-bit ld.d/st.d pair (both new
words byte-exact stock: ld.d r3,[r11+0] x1 code site / combo x2; st.d
r3,[r12+0] x46, all off=0).  Strides/subsi/back-edge as v5b (back-edge
imm -7 -> -5: 0xA400FFFB stock x314); subsi rd=13 remains THE one
0-precedent field (r13 = reserved stock-ABI register; live-writable;
constrained minimum per review — remapping bases to r13 is 0/71030 worse).
Recorded shape residual: adjacent ld.d r3 -> st.d r3 = 0 stock.  M-marker
(set3 r12,zero,7 + st.d r12,zero,0x238C, VAL=7 = "copy done") after
loop-exit — the 2 words saved pay for it, so gauntlet/payload/resume/
W_FAST and prefix branch immediates stay v5b byte-exact at v5b indices.
33 of 34 zone words; W_FAST @word 32 = 0x38d7d0 (== v5b).  Interpretation:
clean exec + CR 0x2388=0x53324F4B => C1; a persisting freeze excludes RC1
(zero-precedent forms) => RC2/RC3.

Stub v5e (task-25, journal task-24 «Errata + v5e rev.2», review-driven):
ESCALATION N-GATES bisection stub — freeze at frame-N=k names the block.
Prefix = live-exact v5b filter/echo/N-load+echo (w0-w8); the v5b N-guard
is replaced by the escalation flow: push + saves (v5d-verbatim 0-combo
suspect), L2 gate (set3 r12,zero,2 [v5cA-live M1] + cmp38_sel(2,13,12)
[v5b-live guard] + b_t.cc0A -> TAIL [stock x56]) early-exits on N==2;
dst-init (v5d-verbatim suspect) + one ld.d/st.d pair (v5d-verbatim
suspects), L3 gate (set3 r12,zero,3 [v5cA-live M2] + cmp38 + b_t.cc0A
-> TAIL [stock x75]) exits on N==3; dst RE-INIT (addi r12,r1,0x20 — the
dst-init word itself; fixes the rev.1 N=4 absolute-EA corruption the L3
gate's r12-clobber caused) and the v5d-VERBATIM do-while loop (w21-w26
== v5d w15-w20).  Shared TAIL: marker st.d r13,zero,0x238C (echo-word
retarget 0x2384->0x238C; values N=2->2, N=3->3, N=4->0, N=1->0) -> pop
-> W_FAST jump FN_A last (w29 = 0x38d7c4).  30 of 34 zone words.
Residuals (documented): echo-N1 runs the write path at depth 1
(idempotent 1-word write into the own frame); no garbage-N guard (builder
frames only, payload.py asserts N in [1..4]); N=3 conflates dst-init vs
pair (disambiguator: L3-gate reorder, journal rev.2).

Register budget (T1/T3 journals + rulings R1-R4):
  r3  ra capture / copy temp / resume PC (restored);
  r11 input ptr / loop src;  r12 loop dst / payload ptr;  r13 MAGIC/N;
  r4 result buffer, restored via `addi r4,zero,0` (stock word @0x0e4374);
  r5 header init (v4: input[0x10]), restored via `or r5,r22,r22`
  (stock word @0x0e4378);
  r6 site value: v4 no longer initializes it from the header; saved/restored
  via st.d/ld.w pair (fw-native mixed-width save/restore, e.g.
  0x0e5fd0->0x0e5fd8);
  r14+ never touched (callee-saved image-wide).  csr_w not used.

Stub v5f (task-27, journal task-26 §Step 7, freeze-#6 fix): v5e flow with
BOTH N-gates replaced by the STOCK SKIP-IDIOM `[cmp38; b_f.cc0A +2;
jump TAIL]` — b_t-taken (freeze-#6: the single taken op=0x28 observed on
4030 froze the host at v5e neg-N2) is eliminated from the stub: equality
makes the b_f NOT-taken so the UNCONDITIONAL jump TAIL executes;
inequality takes the b_f +2 skip (b_f.cc0A at CMPRES=false — the ONLY
live-proven clean taken-conditional class on 4030, x5 boots via the w5
fallthrough).  Prefix w0-w10 = v5e byte-exact (only w5's immediate
retargets +24->+26 to the new W_FAST @w31; 0xA40A001A stock-exact x10).
Gate words: set3 consts = v5cA-live M1/M2; cmp38_sel(2,13,12) = v5b-live
guard; skip 0xA40A0002 stock x94 (74/94 right after op36/op38); exits
0x9500000F x222 / 0x95000008 x365.  dst-init/pair/L3/dst-RE-INIT keep
their v5e words at +1 word (the L2 gate gained its jump word); loop
w23-w28 == v5d w15-w20 byte-exact; shared TAIL: marker st.d r13,zero,
0x238C @w29 (values N=2->2, N=3->3, N=4->0, N=1->0) -> pop -> W_FAST
jump FN_A LAST (w31 = 0x38d7cc).  32 of 34 zone words.  Interpretation:
freeze@N=2/3 => skip-idiom/jump class (saves exonerated: v5e echo-N1 ran
the whole write path — prefix+push+saves+dst+pair+loop+tail — clean);
freeze@N=4 => loop-back-edge-taken named (-> unrolled v5g with counted
fixed-offset tuples); all-clean => gauntlet/M/v5d-only-deltas suspects
(-> v5g C1-attempt).

Stub v5g (task-28, linear fork-test): v5b flow MINUS gauntlet MINUS
payload-block MINUS ALL N-gates — fully LINEAR (the only clean magic-run
shape on 4030: v5cA and echo-N1 were linear; all five freezes carried a
forward block-skip/jump from a late stub position).  Fork-test: freeze at
N=2+ names H-INPUT (payload-tail bytes + N>=2 triggered; forward
control-flow exonerated — none exists), all-clean names H-SKIP (the
late forward skips were the trigger; write-path + loop + back-edge +
input-tails all rehabilitated).  Prefix w0-w10 = v5e/v5f byte-exact
(only w5's immediate retargets +26->+17 to the new W_FAST @w22 — the
shorter stub shifts it; 0xA40A001A->0xA40A0011 stock-exact x15); magic
filter + all-N acceptance as v5e/f (NO N==4 guard: N in {1..4} all
proceed).  Then: dst-init + ONE ld.d/st.d pair (v5d-verbatim suspects)
+ the v5d-VERBATIM do-while loop (w14-w19 == v5d w15-w20 byte-exact;
runs xN, back-edge b_f.cc00 taken xN-1 — the ONLY taken conditional
possible on a magic path, never-clean-live = the H-SKIP-side fork
variable) -> TAIL marker st.d r13,zero,0x238C (r13=0 after the loop for
every N>=1 — uninformative, live-form kept for uniformity) -> pop ->
W_FAST jump FN_A LAST (w22 = 0x38d7a8).  ZERO gates, ZERO skips, ZERO
b_t words; 23 of 34 zone words (brief's ~26-28 estimate was high: v5f
32 - L2 4 - L3 4 - dst re-init 1 = 23).

Stub v5h (task-29, named-suspect SAVE test): v5g MINUS the save word —
`st.d r3,r1,0x0` (v5g w10 = 0x6C201802, the sole surviving 0-combo
rt=3/rs=r1/off=0 store; stock census x0) is NAMED the freeze
common-denominator (journal task-28 phase-2: freeze@N=2 reproduced on
the fully-linear v5g + ledger — the SAVE ran on every freeze path AND
every clean magic path, the tail-frames being the difference); r3 is
dead at the detour per R3 — the save was vestigial paranoia.  Fork:
tail-frames clean => SAVE x TAIL named (write-path fully rehabilitated
-> v5i-C1 next); freeze => deeper (pair/loop x tail-CONTENT — copied
VALUES matter; next disambiguator: neutral constants vs tail bytes).
Everything else keeps the v5g shape byte-exact: prefix w0-w4/w6-w9 ==
v5g (only w5's immediate retargets +17->+16, W_FAST w22->w21 with the
-1 word shift: 0xA40A0010 stock-exact x22) -> push -> [NO SAVE] ->
dst-init (w10, the v5d word) -> pair (w11-w12, v5d words) -> loop
w13-w18 == v5d w15-w20 byte-exact (the back-edge word 0xA400FFFB is
UNCHANGED: its -5 offset is relative, both ends shifted together) ->
TAIL marker st.d r13,zero,0x238C -> pop -> W_FAST jump FN_A LAST
(w21 = 0x38d7a4, 0x95F80070 live-form x0).  22 of 34 zone words.

Stub v5i (task-31, neutral-write discriminator after freeze #9 on v5h
— journal task-29 phase-2: tail-frame x ANY extra write into the pushed
frame => freeze, save OR copies; push-ra + CR writes always clean):
v5h with the pair+loop block REPLACED by ONE NEUTRAL-CONSTANT frame
write — `set3 r12,zero,0xA5A5` + `st.d r12,r1,0x30` (stock x1, class
addi/const -> st.d-r1-relative; the free frame slot 0x30, never
written by any prior version) — NO input-derived values in the write
path: no save, no dst-init, no pair, no loop, no back-edge.  Prefix
w0-w9 == v5h byte-exact (only w5's immediate retargets +16->+9,
0xA40A0009 stock-exact x48); conditionals = filter w5 ONLY; N echoed
(0x2384=N), never used for control; r13=N survives to the TAIL marker
(the loop that zeroed it is gone — documented erratum vs the brief's
"0x238C=0": clean completion => 0x238C=N, freeze => fresh-baseline 0).
Fork: freeze => H-FRAMEGUARD (ANY extra frame-write x tail-frame,
content-independent -> C1 avoids frame writes entirely, task-30 RE);
clean => H-CONTENT (copied VALUES were the trigger -> C1 = copy-free
OR sanitize/validate before copying).  15 of 34 zone words; W_FAST
jump FN_A LAST (w14 = 0x38d788, 0x95F80077 live-form x0).

Stub v5j (task-32, THE C1 PIVOT — exec-from-input; journal task-30 Q4
sketch + errata f0e4804; task-31 phase-2: zero extra frame writes =
live-proven safe class; rev.2 = T32-review Exit-C redesign): the
payload EXECUTES IN-PLACE from the input landing zone [r1+0xac..0xbc)
— ZERO frame writes (no push, no save, no copy, no neutral write; the
stub's only stores are the CR echoes — the always-clean class), so the
freeze-#9 class (tail-frame x any extra write into the pushed frame)
cannot in principle fire.  Prefix w0-w8 == v5i byte-exact (only w5's
immediate retargets +9 -> +6: 0xA40A0006 stock-exact x70, the
lineage's best); NO N-guard, NO gauntlet (N echoed 0x2384=N, never
controls).  w9 re-establishes r11 = r1+0xac (the w1 word) right
before w10 = `ret.r zero,r8,r11` (0xFD005825) — THE SINGLE
register-target transfer, rs=8 COMPUTED-JR CLASS, NO LINK (csr0xbc
keeps the pre-detour ra; word stock-exact x3, class x8986 live — the
canonical return idiom, journal task-30 return-state inventory; NOT
the rs=0 LINKING jalr of rev.1 — review Important-2: a linking
transfer wrote csr0xbc = W_FAST and looped FN_A<->W_FAST).  W_FAST
jump FN_A LAST (w11 = 0x38d77c).  12 of 34 zone words.  Payload
(payload.payload_v5j, rev.2: 4 words, frame 36B = the STANDARD
neg-frame size, all bytes k<=0x23 — inside the T2 strictly-clean
window, ceiling 0x38, NO corruption-zone exposure; review
Important-3): set3-lo + set2-hi build r12=0x53324F4B, st.d S2OK ->
CR 0x2388 (the FULL C1 signal — the rev.1 landing echo is dropped,
S2OK self-validates), then `jump` to the LIVE FN_A 0x98d964 (= file
0x18d964 + 0x800000 — review Critical-1: rev.1 encoded the file-space
address, 0x800000 low) from live PC r1+0xb8 (k=0x20; s24 imm fits
every stack base 0x7d1ff8..0x7ffff8, worst-case 0x6ee2d).  Exit
semantics: p3 -> FN_A ret.d -> csr0xbc = pre-detour ra -> stock
return into the dispatcher (the SAME completion as every v5-series
clean run; NO link anywhere on the path).  Interpretation (rev.2):
clean + 0x2388=0x53324F4B => FULL C1; freeze + 0x2388=S2OK => payload
ran, exit derailed; freeze + 0x2388=0 => stack-exec/w10 class failed;
clean + 0x2388=0 => w10 landing/fetch failed (echoes distinguish).

Stub v5k rev.2 (task-33 T33-review 40d902a fix — Critical-1/Important-2,
stub-side EPILOGUE REPLICA exit): the rev.1 Exit-D read [r1+4] at the
detour — but the detour path (0x0e4258 push 0xf8 -> 0x0e42b8 linking
ret.r r17 -> 0x0e42bc -> b_t 0x0e4310 -> call 0xebc9c @0x0e4328 ->
call 0xcaec0 @0x0e4358 -> detour 0x0e437c) NEVER pops the fn's 0xf8
frame, so detour-time r1 = R-0xf8 and [r1+4] is the INNER slot — the
last nested-call resume 0x8E435C: rev.1's p3 re-entered the detour
deterministically (livelock; the region [0x0e435c,0x0e437c) decodes
LINEAR into the detour call), and r17-r23 (saved @0x0e425c-74,
restored ONLY on the epilogue path 0x0e42e8-0x0e4300) leaked.  THE
FIX: the stub carries a 10-word BYTE-EXACT copy of the fn's own
epilogue (REPLICA_WORDS — decoded from the base @0x0e42e8..0x0e430c,
construction-verified at build time: 7 restores r23..r17 from
[r1+0xdc..0xf4], `addi r1,r1,0xf8` pop, `ld.d r3,r1,0x4` — NOW the
OUTER [R+4], the fn's true saved dispatcher ra written by the
prologue @0x0e4254 BEFORE the push — and the fn's own final
`ret.r zero,r8,r3` @0x0e430c) and PRELOADS r3 with the replica's
ABSOLUTE live address BEFORE the transfer: w10 `set3 r3,zero,lo16`
(rs=zero — CLEAN under BOTH insert and OR semantics; the proven
S2OK-p0/p1 build pattern) THEN w11 `set2 r3,r3,hi16` (hi-insert —
after w10 hi16(r3)=0 so both semantics agree; the w0 csr.r residue
0x8E4380 cannot leak: w10's source is the zero REGISTER).  The
payload p3 `ret.r zero,r8,r3` (UNCHANGED 0xFD001825) exits into the
replica -> fn-epilogue completed: registers restored, frame popped,
return to the dispatcher.  Livelock GONE by design (single transit);
r17-r23 leak GONE.  r4-equivalence: the replica omits the epilogue's
first word `or r4,r19,r19` (@0x0e42e4 — result-marshal); at the
detour r4=0 already (stock arg setup `addi r4,zero,0` @0x0e4374) ==
the stock post-FN_A BadParam value the epilogue would marshal.
Prefix w0-w8 == v5j byte-exact (only w5's immediate retargets +6 ->
+18: 0xA40A0012 stock-exact x27); w9 payload ptr (== w1); w12 THE
transfer `ret.r zero,r8,r11` (0xFD005825, stock x3, rs=8 no-link);
w13-w22 the REPLICA (10/10 words byte-exact stock — the strongest
precedent class possible: census x6/x7/x6/x5/x5/x3/x2/x17/x8347/
x8346); W_FAST jump FN_A LAST (w23 = 0x38d7ac, 0x95F8006E
live-form x0).  24 of 34 zone words.  ZERO memory writes outside
the CR echoes on every path (restores are READS; the pop is the
stock SP-restore register word); ZERO b_t; r4/r5/r6/r14-r16 never
touched.  Interpretation (rev.2): clean + 0x2388=0x53324F4B =>
FULL C1 (replica exit); clean + 0x2388 != S2OK => construction
issue (the CR value names it); card-wedge/host-alive + S2OK
readable => replica/return issue (diagnosable); host-freeze => new
class (unexpected — zero frame writes); the rev.1 livelock
signature GONE BY DESIGN.

Stub v5l (task-34, journal task-33 phase-2 grounding — commit bf0157c:
C1 criterion ACHIEVED live, CR 0x2388 = 0x53324F4B EXACT, payload 4/4
executed from the input landing; wedge AT the exit — the replica
skipped the fn body AFTER the call-site, which builds the QUERY
completion): v5k rev.2 MINUS the replica.  The stub preloads r3 with
THE CALL-SITE RESUME 0x008E4380 (= PC_BASE + DETOUR_DC + 4 — the
resume of the detoured `call FN_A'; the value csr0xbc holds at detour
entry; the value stock FN_A itself returns through: FN_A's prologue
`csr.r r3,csr0xbc` @0x18d964 is byte-exact the stub's w0) — w10
`set3 r3,zero,0x4380` (rs=zero — CLEAN under BOTH insert and OR
semantics; the proven v5k pattern) THEN w11 `set2 r3,r3,0x008e`
(hi-insert; the w0 residue IS 0x8E4380 already — the pair rebuilds it
explicitly, deterministic from ANY residue).  The payload p3
`ret.r zero,r8,r3` (UNCHANGED 0xFD001825, stock x8346) returns INTO
THE FN BODY at the resume point, as FN_A's return would: the body
marshals r4 (`or r19,r4,r4` @0x0E4380; r4=0 — the v5i-documented
stock arg value `addi r4,zero,0` @0x0E4374 == the stock post-FN_A
BadParam value), branches on it (`subsi` + `b.f.0x0 ->0x8E42E4`
early-exit vs the 0x0E438C+ QUERY path), builds the QUERY completion
and reaches its OWN epilogue (r17-r23 restores, the 0xf8 pop, the
outer-[R+4] return — everything the v5k replica tried to synthesize,
now by the fn's own words) — STOCK COMPLETION.  r1 keeps R-0xf8 (the
BODY pops).  THE REPLICA IS DELETED — no fn-exit words, no restores,
NO POP, zero memory writes outside the CR echoes, zero r1 writes at
all, r17-r23 never touched (the body's epilogue restores them), and
nothing executes from the stub zone after the w12 transfer (the
task-33 wedge-hypothesis (ii) cannot fire).  Layout: 14 words —
prefix w0-w8 == v5k byte-exact except w5's immediate +18 -> +8
(0xA40A0008 stock-exact x74 — the best prefix-retarget count of the
lineage); w9 payload ptr (== w1); w10/w11 the r3 build; w12
`ret.r zero,r8,r11` THE transfer (stock x3, rs=8 no-link); w13 W_FAST
jump FN_A LAST (0x38d784, 0x95F80078 live-form x0).  14 of 34 zone
words.  Payload (payload.payload_v5l): the UNCHANGED v5k words
(live-proven exact S2OK + canonical p3) — frame 36B identical to the
v5k TRIG; base-independent (the exit target is the ABSOLUTE resume).
Interpretation: clean completion + 0x2388=0x53324F4B => FULL C1
(execution + stock completion — the complete S2 goal); wedge/other +
S2OK => body-dependency on FN_A effects (diagnosable; S2OK already
banked); clean + no S2OK => construction regression (the CR value
names it).

Stub v5m (task-2 s2b, mode "B" — THE OUTPUT-MAILBOX stub; Task-1 RE3
verdict MARSHAL_MECH m2): the v5l flow with the stub TAIL extended by
the m2 WRITE-POST block.  On a magic frame, after the echo prefix and
BEFORE the payload transfer, the stub calls the stock transport wrapper
`0x18064c(r4=0, r5=obj, r6=C, r7=buf)` (= X1=0x18a668(obj,C) lookup ->
0x2ae98 -> 0x2a154: DMA 0x40 bytes buf -> host X1, byte-exact — ONE
call instead of hand-building X1 + 0x2a154).  r4=0 selects the dir==0
WRITE-POST subpath (stock decode 0x180674-0x180690: `or r22,r4,r4`/
`or r4,r5,r5`/`or r5,r6,r6`/`call 0x18a668`; dir!=0 -> READ-FETCH
0x2ac60); obj = r22 (callee-saved, set in the fn prologue — read only);
C = [r1+0xac]|0xff (ld.d then or-imm — the same key the stock F_SYN
FETCH uses on every fallthrough run; on the v5m TRIG frame
[r1+0xac]=p0=0x200C4F4B => C=0x200C4FFF); buf = r1+0xb0 =
input[0x18..0x58) = payload p1..p3 + stack tail — ZERO new FW-RAM
writes: the POSTed bytes are the TRIG frame's own, delivered by the
host.  The call is a REAL call (links csr0xbc; its own prologue is
`csr.r r3,csr0xbc` — byte-exact the stub's w0) and clobbers the
caller-saved set, so per the Task-1 class note r3/r11 are (RE)BUILT
AFTER the m2 block: w15 restores r4=0 (the body marshals r4 at the
resume — the v5i-documented stock arg value), w16 re-establishes the
payload ptr, w17/w18 rebuild r3 = RESUME_LIVE 0x008E4380 with the
proven OR-safe lo-first pair.  csr0xbc after the call is DIRTY (the
call resume) — verified safe: the post-resume body path writes csr0xbc
via its own `call 0x0e4424' @0x0e43b8 before any read (region
0x0E4380-0x0E4424 contains no csr.r-csr0xbc / ret.d), and the
early-exit path reads only the outer [R+4].  Layout: 21 words — prefix
w0-w8 == v5l byte-exact except w5's immediate retargets +8 -> +15
(W_FAST moved w13 -> w20: 0xA40A000F stock-exact x19); w9-w15 the m2
block (0x00040000 x9351 / 0xFEC5B008 x3226 / 0x642600AE x5 / the
GOLDEN immediate-mask 0x30C600FF x47 — enc.py has no op-0x0C encoder,
golden word extracted from the blob per the T3-S2 precedent, encoded
inline / 0x002700B0 x5 / the site-imm call word 0x94F7CBB1); w16-w19
== v5l w9-w12 byte-exact (shifted +7); w20 W_FAST jump FN_A LAST
(0x95F80071 — byte-exact the v5cA W_FAST word: the same address
0x38d7a0).  21 of 34 zone words.  Live-gate risks documented by Task 1
(Task 3 owns them): (a) X1-miss posts to a garbage host address —
pilot = marker POST + tool-buffer scan + STOP-protocol; (b) X1 = the
tool's own command block is a hypothesis; (c) calls-from-detour are a
new behavioral class — step echo-first.

CRC: per-line clcrc over changed 68B lines + mlxfwutil.patch_sections
(section crc16_mlx + ITOC entry CRC).

v3 = v2 + baked card GUID/MAC; v4 = v2-lineage stub v4 + the same GUID bake
(same mechanism as `mlxfwutil.py guides`: mDevInfo write_uids + MFG_INFO
uid/mac + section/entry CRC).
"""
import hashlib
import shutil
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "irisc"))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import mlxfwutil  # noqa: E402
import enc  # noqa: E402

BASE = REPO / "build" / "4030-cda-patched3.bin"
BASE_MD5 = "082e9678b54d0512cec2f155037e82b7"
DETOUR_DC, STUB, FN_A = 0x0E437C, 0x38D750, 0x18D964
MAGIC = 0x5332434D
DISCRIM32 = 0x0432434D
ECHO_MAGIC, ECHO_LEN = 0x2380, 0x2384
CTX_REG = 20                       # T1: ctx lives in r20 at 0x0e437c
IN_OFF = 0xA0                      # T2: input[k] = [r1_fn+IN_OFF+k] (= [r20+0x58+k])
INPUT_BASE_V5B = 0x98              # T17 live: input[k] -> [r1+0x98+k] (tail k>=0x12 proven)
SLOT_FILTER_V5B = INPUT_BASE_V5B + 0x12   # [r1+0xaa]: input[0x12..0x14) BE halfword
SLOT_N_V5B = INPUT_BASE_V5B + 0xC         # [r1+0xa4]: input[0xC..0xE) 16-bit N
PAY_SRC_OFF_V5B = INPUT_BASE_V5B + 0x14   # [r1+0xac]: code src (k=0x14 proven)
PAY_SRC_OFF = IN_OFF + 0x10        # v2: payload words = input[4..4+N) (16B header)
PAY_SRC_OFF_V4 = IN_OFF + 0x14     # v4: code = input[0x14..0x14+4N) (20B header)
N_OFF_V4 = IN_OFF + 0xC            # v4: N = input[0xC..0x10)
PC_BASE = 0x800000                 # live PC = file offset + 0x800000
FRAME = 0x40                       # T1: STUB_FRAME_OK (incl. saved regs)
S_RA, S_R6 = 0x00, 0x18            # frame slots (S_R4/S_R5 rematerialized)
PAY_OFF, RES_OFF = 0x20, 0x34      # payload words / result buffer
R5_SRC = IN_OFF + 8 + FRAME        # v2: input[2] via stub r1 (pushed)
R5_SRC_V4 = IN_OFF + 0x10 + FRAME  # v4: input[0x10] via stub r1 (pushed)
R6_SRC = IN_OFF + 12 + FRAME       # v2: input[3]
OBJ_REG = 22                       # T1: r22 = [ctx+0x150], live at the site
ZONE_WORDS = 34                    # 0x38d750..0x38d7d8
S0_LO, GUARD_LO = 0x38D730, 0x38D748
FATAL_LO, FATAL_HI = 0x38D7DC, 0x38DBE8
RESUME_LIVE = 0x008E4380           # v5l/v5m: the call-site resume (live PC)
JUMP_B = 0x008E43A4                # Task-6 RE-b': mode-B exit — first stock
                                    # word AFTER the memset, before the CQE-POST
                                    # arg-setup (BODY_DEP=SAFE: all skipped-body
                                    # regs re-set before any use)
DETOUR_P = 0x0E43C4                # v5r (C1, RE-c task-09): the LATE detour
                                    # point — the first (only) skippable tail
                                    # word AFTER the stock CQE-POST: `addi
                                    # r19,zero,0x0` (redundant — r19 is dead
                                    # from here to the fn's ret.r @0x0e43e4).
RESUME_P = 0x008E43C8              # v5r: the detour's ra (live PC = P + 4;
                                    # stock `addi r4,zero,0x0`).  C1 exits:
                                    # BOTH mode A and B return to it (the
                                    # v5q body-absolutes RESUME_LIVE/JUMP_B
                                    # are back in the body at a late point
                                    # -> double CQE-POST).
MODE_SLOT_V5Q = INPUT_BASE_V5B + 0x10  # [r1+0xa8]: frame word[4] hi-half
                                   # (16-bit, ld.w): A = 0, B = 1.  The stub
                                   # loads it (16-bit) and compares to 0:
                                   # CMPRES = (mode == A).  A-frame word[4]
                                   # stays 0x00005332 (== v5o live frame).
M2_TRANSPORT = 0x18064C            # v5m mode B: the WRITE-POST wrapper (file)
M2_POST_DIRECT = 0x2AE98           # v5n mode B: прямой транспорт (file)
M2_KEY_R1_OFF = 0xAC               # C = [r1+0xac]|0xff (the FETCH/POST key)
M2_KEY_OR = 0xFF
M2_BUF_R1_OFF = 0xB0               # buf = r1+0xb0 = input[0x18..0x58)
STUB_LAYOUT = {                    # version -> (total words, tail-jump word index)
    2: (34, 33),
    4: (33, 32),
    5: (9, 8),
    6: (33, 32),                   # v5b (T18+review): W_FAST @word 32 = 0x38d7d0
    7: (21, 20),                   # v5c-A (T20): W_FAST @word 20 = 0x38d7a0
    8: (34, 33),                   # v5c-B (T21): W_FAST @word 33 = 0x38d7d4
    9: (33, 32),                   # v5d (T23): W_FAST @word 32 = 0x38d7d0 (== v5b)
    10: (30, 29),                  # v5e (T25): W_FAST @word 29 = 0x38d7c4 (last)
    11: (32, 31),                  # v5f (T27): W_FAST @word 31 = 0x38d7cc (last)
    12: (23, 22),                  # v5g (T28): W_FAST @word 22 = 0x38d7a8 (last)
    13: (22, 21),                  # v5h (T29): W_FAST @word 21 = 0x38d7a4 (last)
    14: (15, 14),                  # v5i (T31): W_FAST @word 14 = 0x38d788 (last)
    15: (12, 11),                  # v5j (T32): W_FAST @word 11 = 0x38d77c (last)
    16: (24, 23),                  # v5k rev.2 (T33-review): W_FAST @word 23 = 0x38d7ac (last)
    17: (14, 13),                  # v5l (T34): W_FAST @word 13 = 0x38d784 (last)
    18: (21, 20),                  # v5m (T02 s2b, mode B): W_FAST @word 20 = 0x38d7a0 (last)
    19: (22, 21),                  # v5n (plan-2 s2b2, mode B): W_FAST @word 21 = 0x38d7a4 (last)
    20: (22, 21),                  # v5o (plan-3 s2b2, mode B): stub == v5n byte-exact (w-independent m2'; w = in_mb0 via TRIG p0)
    22: (32, 31),                  # v5q (plan-4 s3, mode B): v5o prefix + runtime mode branch (A/B blocks + shared tail); W_FAST @word 31 = 0x38d7cc (last)
    23: (29, 28),                  # v5r (plan-4 s3 C1, mode B): v5q prefix + mode branch, C1 late exits (A/B -> RESUME_P via the payload p3; W_FAST = no-op ret.d); detour @DETOUR_P; W_FAST @word 28 = 0x38d7c0 (last)
}
V5A_PROBES = (                     # (r1-offset, CR echo slot): X -> CR_X
    (0xA0, 0x2380),                # control: tn (landing proven, S-map §12.2)
    (0xAA, 0x2384),                # candidate: [D+0xA..0xC) window
    (0xAC, 0x2388),                # candidate: [D+0x10..0x14) window
    (0xB2, 0x238C),                # candidate: [D+0x1A] hybrid tail slot
)
STOCK_WORDS = {
    DETOUR_DC: 0x9402A57A,         # stock `call 0x18d964`
    DETOUR_P: 0x00130000,          # stock @P `addi r19,zero,0x0` (RE-c)
    0x1D594: 0x940DC067,           # S0 injection `call 0x38d730`
    FN_A: 0x480300BC,              # stock FN_A prologue `csr.r r3,csr0xbc`
}

CARD_GUID = int(mlxfwutil.hw('CARD_CX5_EDR100', 'guid'), 16)
CARD_MAC = int(mlxfwutil.hw('CARD_CX5_EDR100', 'mac'), 16)

# v5k rev.2 (T33-review 40d902a): the fn 0x0e4250 epilogue replica —
# a BYTE-EXACT copy of the stock words @0x0e42e8..0x0e430c (7 restores
# r23..r17 from [r1+0xdc..0xf4] — mirror image of the saves
# @0x0e425c-74; the 0xf8 pop; the OUTER [R+4] load; the fn's own final
# ret.r).  Verified against the base image at build time (build_code)
# — any base drift fails the build fail-loud.
EPILOGUE_REPLICA_SRC = 0x0E42E8
REPLICA_WORDS = (
    0x643700DE,        # ld.d r23,r1,0xdc   (@0x0e42e8, stock x6)
    0x643600E2,        # ld.d r22,r1,0xe0   (@0x0e42ec, stock x7)
    0x643500E6,        # ld.d r21,r1,0xe4   (@0x0e42f0, stock x6)
    0x643400EA,        # ld.d r20,r1,0xe8   (@0x0e42f4, stock x5)
    0x643300EE,        # ld.d r19,r1,0xec   (@0x0e42f8, stock x5)
    0x643200F2,        # ld.d r18,r1,0xf0   (@0x0e42fc, stock x3)
    0x643100F6,        # ld.d r17,r1,0xf4   (@0x0e4300, stock x2)
    0x002100F8,        # addi r1,r1,0xf8    (@0x0e4304, stock x17 — pop)
    0x64230006,        # ld.d r3,r1,0x4     (@0x0e4308, stock x8347 — outer ra)
    0xFD001825,        # ret.r zero,r8,r3   (@0x0e430c, stock x8346 — final)
)


def stub_words(mode="A", version=2):
    if mode == "v5cA":             # task-20 alias
        mode, version = "A", 7
    if version == "v5cA":
        version = 7
    if mode == "v5cB":             # task-21 alias
        mode, version = "A", 8
    if version == "v5cB":
        version = 8
    if mode == "v5d":              # task-23 alias
        mode, version = "A", 9
    if version == "v5d":
        version = 9
    if mode == "v5e":              # task-25 alias
        mode, version = "A", 10
    if version == "v5e":
        version = 10
    if mode == "v5f":              # task-27 alias
        mode, version = "A", 11
    if version == "v5f":
        version = 11
    if mode == "v5g":              # task-28 alias
        mode, version = "A", 12
    if version == "v5g":
        version = 12
    if mode == "v5h":              # task-29 alias
        mode, version = "A", 13
    if version == "v5h":
        version = 13
    if mode == "v5i":              # task-31 alias
        mode, version = "A", 14
    if version == "v5i":
        version = 14
    if mode == "v5j":              # task-32 alias
        mode, version = "A", 15
    if version == "v5j":
        version = 15
    if mode == "v5k":              # task-33 alias
        mode, version = "A", 16
    if version == "v5k":
        version = 16
    if mode == "v5l":              # task-34 alias
        mode, version = "A", 17
    if version == "v5l":
        version = 17
    if mode == "v5m":              # task-02 s2b alias (mode B)
        mode, version = "B", 18
    if version == "v5m":
        version = 18
    if mode == "v5n":              # plan-2 s2b2 alias (mode B)
        mode, version = "B", 19
    if version == "v5n":
        version = 19
    if mode == "v5o":              # plan-3 s2b2 alias (mode B)
        mode, version = "B", 20
    if version == "v5o":
        version = 20
    if mode not in ("A", "B"):
        raise ValueError(f"unsupported mode {mode!r} (A/B)")
    if version not in STUB_LAYOUT:
        raise ValueError(f"unsupported stub version {version!r} (known: {sorted(STUB_LAYOUT)})")
    if (mode == "B") != (version in (18, 19, 20, 22, 23)):
        raise ValueError(f"mode {mode!r} does not build stub version {version!r} "
                          f"(v5m=18/v5n=19/v5o=20/v5q=22/v5r=23 are the mode-B "
                          f"stubs; all other versions are mode A)")
    pc = lambda i: STUB + 4 * i
    ws = []
    if version == 18:
        # v5m (task-02 s2b, mode "B" — THE OUTPUT-MAILBOX stub; Task-1
        # RE3 verdict MARSHAL_MECH m2): the v5l flow with the stub TAIL
        # extended by the m2 WRITE-POST block.  On a magic frame,
        # after the echo prefix and BEFORE the payload transfer, the
        # stub calls the stock transport wrapper
        # `0x18064c(r4=0, r5=obj, r6=C, r7=buf)' (= X1=0x18a668(obj,C)
        # -> 0x2ae98 -> 0x2a154: DMA 0x40 bytes buf -> host X1,
        # byte-exact — ONE call instead of hand-building X1+0x2a154).
        # r4=0 selects the dir==0 WRITE-POST subpath (stock decode
        # 0x180674-0x180690); obj=r22 (callee-saved fn-prologue value,
        # READ ONLY); C=[r1+0xac]|0xff (the same key the stock F_SYN
        # FETCH uses every fallthrough run; on the v5m TRIG frame C =
        # p0|0xff = 0x200C4FFF); buf=r1+0xb0 = input[0x18..0x58) =
        # payload p1..p3 + stack tail — ZERO new FW-RAM writes (the
        # POSTed bytes are the TRIG frame's own).  The call is a REAL
        # call (links csr0xbc; clobbers the caller-saved set — its own
        # prologue `csr.r r3,csr0xbc' is byte-exact the stub's w0), so
        # r3/r11 are (RE)BUILT AFTER the m2 block per the Task-1 class
        # note: w15 restores r4=0 (the body marshals r4 at the resume:
        # `or r19,r4,r4' @0x0E4380 — the v5i-documented stock arg
        # value), w16 re-establishes the payload ptr, w17/w18 rebuild
        # r3 = RESUME_LIVE 0x008E4380 (the proven OR-safe lo-first
        # pair — byte-exact the v5l w10/w11 words).  csr0xbc after the
        # call is DIRTY (the call resume) — verified safe by the blob
        # scan: the post-resume body path writes csr0xbc via its own
        # `call 0x0e4424' @0x0e43b8 before any read, and the
        # early-exit path reads only the outer [R+4].
        # Layout: 21 words — prefix w0-w8 == v5l byte-exact except
        # w5's immediate retargets +8 -> +15 (W_FAST moved w13 -> w20:
        # 0xA40A000F stock-exact x19); w9-w15 the m2 block (w9
        # `addi r4,zero,0' 0x00040000 x9351 — the stock arg-setup word
        # @0x0e4374 itself; w10 `or r5,r22,r22' 0xFEC5B008 x3226 —
        # the stock obj-marshal word @0x0e4378 itself; w11 `ld.d
        # r6,r1,0xac' 0x642600AE x5; w12 `andmsk.hi r6,r6,0xff' — THE GOLDEN
        # immediate-mask word 0x30C600FF x47, extracted from the blob
        # (enc.py has no op-0x0C encoder; T3-S2 precedent — encoded
        # inline, reported in the journal); w13 `addi r7,r1,0xb0'
        # 0x002700B0 x5; w14 the site-imm call word 0x94F7CBB1; w15
        # the r4 restore); w16-w19 == v5l w9-w12 byte-exact (payload
        # ptr, r3 build, THE transfer — all shifted +7); w20 W_FAST
        # jump FN_A LAST (0x95F80071 — byte-exact the v5cA W_FAST
        # word: the same address 0x38d7a0).  21 of 34 zone words.
        # Sim-verified contracts: the m2 call fires ONLY on the magic
        # path with the exact signature; the POST precedes the payload
        # execution (the exfil = pristine TRIG bytes); r1 NEVER
        # written (the callee frame is balanced, the body pops); the
        # stub itself makes ZERO memory writes outside the CR echoes;
        # the exit is the call-site resume at every SP base.
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5l
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w8 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (echo only)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.addi(4, 0, 0)]                        # w9:  m2 r4=dir=0
        ws += [enc.or_(5, OBJ_REG, OBJ_REG)]             # w10: m2 r5=obj
        ws += [enc.ld_d(6, 1, M2_KEY_R1_OFF)]            # w11: m2 r6=C raw
        ws += [(0x0C << 26) | (6 << 21) | (6 << 16)      # w12: m2 r6=C|0xff
               | M2_KEY_OR]                              # (GOLDEN 0x30C600FF,
        #  ^ stock x47; enc.py has no immediate-OR encoder — the golden
        #  word is extracted from the blob (T3-S2 precedent), inline)
        ws += [enc.addi(7, 1, M2_BUF_R1_OFF)]            # w13: m2 r7=buf
        ws += [enc.call(pc(len(ws)), M2_TRANSPORT)]      # w14: THE WRITE-POST
        ws += [enc.addi(4, 0, 0)]                        # w15: restore r4=0
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w16: payload ptr
        resume_live = RESUME_LIVE                        # 0x008E4380
        ws += [enc.set3(3, 0, resume_live & 0xFFFF)]     # w17: lo CLEAN
        ws += [(0x09 << 26) | (3 << 21) | (3 << 16)      # w18: set2 r3,r3,hi
               | ((resume_live >> 16) & 0xFFFF)]         # (rs-bearing form,
        #  ^ the enc.set2 vocabulary has no rs operand; the rs=rd form
        #  is the payload._set2 idiom (the live-exact S2OK p1 class))
        ws += [enc.ret_r(8, 0, 11)]                      # w19: transfer, no-link
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        if ws[14] != enc.call(STUB + 4 * 14, M2_TRANSPORT) \
                or ws[12] != 0x30C600FF:
            raise ValueError("v5m m2-block words drifted")
        if ws[17:20] != [enc.set3(3, 0, RESUME_LIVE & 0xFFFF),
                         (0x09 << 26) | (3 << 21) | (3 << 16)
                         | ((RESUME_LIVE >> 16) & 0xFFFF),
                         enc.ret_r(8, 0, 11)]:
            raise ValueError("v5m r3-build/transfer words drifted")
        return ws
    if version in (19, 20):
        # v5n/v5o (plan-2/plan-3 s2b2, mode "B" — m2' X1-from-p0,
        # THE DIRECT POST): v5o (20) builds the SAME 22 words as
        # v5n (19) — the m2' block reads p0 (w) from the TRIG frame
        # at RUNTIME (image w-independent); the version exists for
        # ladder lineage (Б.2); identity is a TESTED contract
        # (built(20) == built(19), md5 golden — TestS2BuildV5O).
        # The v5m flow with the m2 wrapper-call REPLACED by a
        # hand-built X1 + the DIRECT transport call 0x2ae98
        # (r4=X1, r5=buf, r6=status=0).  X1 comes from the TRIG
        # frame's OWN p0 (ZERO new data): w9 `ld.d r4,r1,0xac' =
        # zext32(p0) = w (w = IOVA>>6 of the output mailbox), w10
        # `shl64.i r4,r4,6' = w<<6, w11 `set1 r4,r4,0x8fc0' (bits
        # 32-47 := 0x8fc0) => X1 = 0x8FC010A2E400 for w = 0x428B90
        # (64B-aligned by construction — X1 & 0x3F = 0).  The call
        # is a REAL call (links csr0xbc; T1 clobber-set
        # {r3,r4,r5,r7-r11}; r12 NOT written; r1 NEVER written), so
        # the tail re-establishes after it: w15 restores r4=0 (the
        # body marshals r4 at the resume), w16 rebuilds r12 — THE
        # S2OK-LO WORD (== v5m p0, live-proven): the prefix w2
        # (`ld.w r12,r1,0xaa') loaded the frame-magic 0x5332 into
        # r12, and without the rebuild p1 `set2 r12,r12,0x5332'
        # would keep 0x5332 in the LO half — CR 0x2388 would be
        # 0x53325332, not 0x53324F4B (T1 G-a: the cause is the w2
        # load, NOT the call); w17 the payload ptr; w18/w19 rebuild
        # r3 = RESUME_LIVE 0x008E4380 (byte-exact the v5m w17/w18
        # OR-safe lo-first pair); w20 THE transfer.  Layout: 22
        # words — prefix w0-w8 == v5m byte-exact except w5's
        # immediate +15 -> +16 (W_FAST moved w20 -> w21:
        # 0xA40A0010 stock-exact x22); w21 W_FAST jump FN_A LAST
        # (0x95F80070 — byte-exact the v5h W_FAST word: the same
        # address 0x38d7a4).  22 of 34 zone words.  The payload is
        # p0 = w (DATA; decodes to a harmless addi, P0_SAFE) +
        # p1..p3 the v5m marker verbatim — the transfer executes
        # p0..p3 in-place; the exit is the call-site resume
        # 0x8E4380 (the body completes stock).
        ws += [enc.csr_r(3, 0xBC)]                       # w0: prefix == v5m
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w8 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # w5: b_f.cc0A -> W_FAST (+16)
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # w6: echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # w7: N -> r13
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # w8: echo N
        ws += [enc.ld_d(4, 1, M2_KEY_R1_OFF)]            # w9:  r4 = zext32(p0) = w
        ws += [enc.shl64_i(4, 4, 6)]                     # w10: r4 = w << 6
        ws += [enc.set1(4, 4, 0x8FC0)]                   # w11: r4 = X1
        ws += [enc.addi(5, 1, M2_BUF_R1_OFF)]            # w12: r5 = buf
        ws += [enc.addi(6, 0, 0)]                        # w13: r6 = status = 0
        ws += [enc.call(pc(len(ws)), M2_POST_DIRECT)]    # w14: THE DIRECT POST
        ws += [enc.addi(4, 0, 0)]                        # w15: restore r4=0
        ws += [enc.set3(12, 0, 0x4F4B)]                  # w16: r12 := S2OK-lo
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w17: payload ptr
        resume_live = RESUME_LIVE                        # 0x008E4380
        ws += [enc.set3(3, 0, resume_live & 0xFFFF)]     # w18: r3 lo
        ws += [(0x09 << 26) | (3 << 21) | (3 << 16)      # w19: set2 r3,r3,hi
               | ((resume_live >> 16) & 0xFFFF)]
        #  ^ the enc.set2 vocabulary has no rs operand; the rs=rd form
        #  is the payload._set2 idiom (the live-exact S2OK p1 class)
        ws += [enc.ret_r(8, 0, 11)]                      # w20: transfer, no-link
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # w21: W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        if ws[14] != enc.call(STUB + 4 * 14, M2_POST_DIRECT) \
                or ws[11] != enc.set1(4, 4, 0x8FC0) \
                or ws[10] != enc.shl64_i(4, 4, 6):
            raise ValueError("v5n m2'-block words drifted")
        if ws[16] != enc.set3(12, 0, 0x4F4B):
            raise ValueError("v5n r12-rebuild word drifted")
        if ws[18:21] != [enc.set3(3, 0, RESUME_LIVE & 0xFFFF),
                         (0x09 << 26) | (3 << 21) | (3 << 16)
                         | ((RESUME_LIVE >> 16) & 0xFFFF),
                         enc.ret_r(8, 0, 11)]:
            raise ValueError("v5n r3-build/transfer words drifted")
        return ws
    if version == 22:
        # v5q (plan-4 s3 trigger-probe, mode "B" — RUNTIME detour-mode
        # bit A/B): the v5o (20) prefix (magic filter + m2' DIRECT
        # POST) + the MODE BRANCH.  The mode is a FRAME bit, not an
        # image bit (v5q serves BOTH modes from one image; the TRIG
        # frame selects): frame word[4] hi-half ([0x10..0x12), the
        # zero half of the magic16 word) carries 0 (A) / 1 (B); the
        # stub loads it at [r1+0xa8] (MODE_SLOT_V5Q) with ld.w (a
        # 16-bit zero-extend load — slaspec: :ld.w = zext(*[ram]:2)),
        # so r13 = the mode halfword (0/1), and compares it against
        # 0 (w17 set3 r12,zero,0): CMPRES = (mode == A).  (Review
        # Critical-1 fix: the first build compared the 16-bit half
        # against the whole-word const 0x5332 — always false, so A
        # was unreachable and A ≡ B.)  A -> r3 = RESUME_LIVE
        # 0x008E4380 (byte-exact v5o exit); B -> the Task-6 RE-b'
        # status block ([r1+0x8] = 0x00030000, [r1+0xc] = 0) +
        # r3 = JUMP_B 0x008E43A4 (first stock word AFTER the memset,
        # before the CQE-POST — BODY_DEP=SAFE).  The A frame is
        # BYTE-EXACT the v5o live frame (mode half = 0).
        #
        # Control flow (two exclusive blocks + one shared tail need
        # TWO control words):
        #   w18  CMPRES = (mode == A)
        #   w19  b.t  -> A_block   (A: skip the B block)
        #   B_block (fall-through, mode != A): status + r3 = JUMP_B
        #   w25  jump -> tail      (unconditional transfer of A_block;
        #        `jump` (op 0x25, jmpop=1) IS available — same op as
        #        the w31 W_FAST — so no register-bit idiom is needed)
        #   A_block (w19 target, mode == A): r3 = RESUME (byte-exact
        #        v5o exit), falls through to the tail
        #   tail (w25 target + A fall-through): r12 = S2OK-lo rebuild
        #        (w17's set3 clobbered r12) + payload ptr + transfer
        #   w31  W_FAST (tail-jump FN_A)
        # Layout: 32 words; W_FAST @w31 = 0x38d7cc (position-dependent,
        # regenerated below).  32 of 34 zone words.  The B-path words
        # are the Task-6 contract VERBATIM: 0x24040003 = set2 r4,zero,
        # 0x3 (set2 imm -> [31:16], low32 = 0x00030000; the set1 form
        # 0x1C040003 would have stored 0 — review Critical-1; the LE
        # fallback 0x00040003 is a T2b live check, not pre-empted) +
        # 0x6C20200A st.d r4,r1,0x8 (the stock memset slot) +
        # 0x6C20000E st.d zero,r1,0xc (syndrome 0).  r4 = 0x00030000
        # on the B exit is harmless: the stock arg-setup at JUMP_B
        # (0x0e43a4-0x0e43b4) re-establishes r4 before any use
        # (Task-6 BODY_DEP=SAFE).  F_EXACT = none (Task-7 RE-a: the
        # 0x2ae98/0x2a154 transport forwards X1 whole, no
        # validation/mask/branch on F) -> the live T1/T2 w pair.
        ws += [enc.csr_r(3, 0xBC)]                       # w0: prefix == v5o
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w8 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # w5: b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]
        ws += [enc.st_d(13, 0, ECHO_LEN)]
        ws += [enc.ld_d(4, 1, M2_KEY_R1_OFF)]            # w9:  r4 = zext32(p0) = w
        ws += [enc.shl64_i(4, 4, 6)]                     # w10: r4 = w << 6
        ws += [enc.set1(4, 4, 0x8FC0)]                   # w11: r4 = X1
        ws += [enc.addi(5, 1, M2_BUF_R1_OFF)]            # w12: r5 = buf
        ws += [enc.addi(6, 0, 0)]                        # w13: r6 = status = 0
        ws += [enc.call(pc(len(ws)), M2_POST_DIRECT)]    # w14: THE DIRECT POST
        ws += [enc.addi(4, 0, 0)]                        # w15: restore r4=0 (A value)
        ws += [enc.ld_w(13, 1, MODE_SLOT_V5Q)]           # w16: mode halfword (16-bit, 0/1) -> r13
        ws += [enc.set3(12, 0, 0)]                       # w17: 0 -> r12 (A == mode half 0)
        ws += [enc.cmp38_sel(2, 13, 12)]                 # w18: CMPRES = (r13 == 0) = (mode == A)
        w_mode_bt = len(ws)
        ws += [0]                                        # w19: b_t.cc0A -> A_block
        # --- B block (fall-through, mode != A): Task-6 status + JUMP_B
        ws += [0x24040003]                               # w20: set2 r4,zero,0x3
        ws += [0x6C20200A]                               # w21: st.d r4,r1,0x8 (STATUS_SLOT)
        ws += [0x6C20000E]                               # w22: st.d zero,r1,0xc (syndrome 0)
        ws += [enc.set3(3, 0, JUMP_B & 0xFFFF)]          # w23: r3 lo
        ws += [(0x09 << 26) | (3 << 21) | (3 << 16)      # w24: set2 r3,r3,0x8E
                | ((JUMP_B >> 16) & 0xFFFF)]             #     (== v5o w19 word 0x2463008E)
        w_skip_ab = len(ws)
        ws += [0]                                        # w25: jump -> tail (uncond)
        # --- A block (w19 target, mode == A): byte-exact v5o exit
        a_block = len(ws)
        ws += [enc.set3(3, 0, RESUME_LIVE & 0xFFFF)]     # w26: r3 lo
        ws += [(0x09 << 26) | (3 << 21) | (3 << 16)      # w27: set2 r3,r3,0x8E
                | ((RESUME_LIVE >> 16) & 0xFFFF)]        #     (== v5o w19 word 0x2463008E)
        # --- common tail (w25 target + A fall-through)
        tail = len(ws)
        ws += [enc.set3(12, 0, 0x4F4B)]                  # w28: r12 := S2OK-lo
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w29: payload ptr
        ws += [enc.ret_r(8, 0, 11)]                      # w30: transfer, no-link
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws[w_mode_bt] = enc.b_t(0x0A, pc(w_mode_bt), pc(a_block))
        ws[w_skip_ab] = enc.jump(pc(w_skip_ab), pc(tail))
        ws += [enc.jump(w_fast, FN_A)]                   # w31: W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        if ws[14] != enc.call(STUB + 4 * 14, M2_POST_DIRECT) \
                or ws[11] != enc.set1(4, 4, 0x8FC0) \
                or ws[10] != enc.shl64_i(4, 4, 6):
            raise ValueError("v5q m2'-block words drifted")
        # mode-branch control words (review finding 2: pin the branch
        # targets + the 16-bit mode compare, not just word presence):
        if ws[w_mode_bt] != enc.b_t(0x0A, pc(w_mode_bt), pc(a_block)) \
                or ws[w_skip_ab] != enc.jump(pc(w_skip_ab), pc(tail)) \
                or ws[w_filter_bf] != enc.b_f(0x0A, pc(w_filter_bf), w_fast) \
                or ws[16] != enc.ld_w(13, 1, MODE_SLOT_V5Q) \
                or ws[17] != enc.set3(12, 0, 0) \
                or ws[18] != enc.cmp38_sel(2, 13, 12):
            raise ValueError("v5q mode-branch words drifted")
        if ws[20:25] != [0x24040003, 0x6C20200A, 0x6C20000E,
                         enc.set3(3, 0, JUMP_B & 0xFFFF),
                         (0x09 << 26) | (3 << 21) | (3 << 16)
                         | ((JUMP_B >> 16) & 0xFFFF)]:
            raise ValueError("v5q mode-B words drifted (Task-6 contract)")
        if ws[26:28] != [enc.set3(3, 0, RESUME_LIVE & 0xFFFF),
                         (0x09 << 26) | (3 << 21) | (3 << 16)
                         | ((RESUME_LIVE >> 16) & 0xFFFF)]:
            raise ValueError("v5q A-block words drifted")
        if ws[28:31] != [enc.set3(12, 0, 0x4F4B),
                          enc.addi(11, 1, PAY_SRC_OFF_V5B),
                          enc.ret_r(8, 0, 11)]:
            raise ValueError("v5q tail words drifted")
        return ws
    if version == 23:
        # v5r (plan-4 s3 trigger-probe, mode "B" — the C1 LATE stub):
        # the v5q (22) prefix (magic filter + m2' DIRECT POST) + the
        # MODE BRANCH, with the C1 late exits.  The detour is at the
        # LATE point P (DETOUR_P, RE-c task-09) — after the stock
        # CQE-POST — so the v5q exits are WRONG here: the magic-path
        # r3 absolutes (RESUME_LIVE 0x008E4380 A / JUMP_B 0x008E43A4
        # B) are back in the BODY (double CQE-POST), and the magic-miss
        # tail-jump FN_A would run FN_A over the stock word.  C1:
        #   (1) magic path: the POST fires, then the stub returns to
        #       the detour's ra (P+4 = RESUME_P, live 0x008E43C8);
        #       (2) the mode bit keeps the v5q branch — A: no status,
        #       B: the Task-6 CQE status block ([r1+0x8] =
        #       0x00030000 class BadParameter, [r1+0xc] = 0) — and
        #       BOTH return to ra (the B block's r3 = JUMP_B setup is
        #       REMOVED); (3) magic miss: a NO-OP return to ra.
        #
        # The POST (w14 call 0x2ae98) is a real call — T1 clobber-set
        # {r3,r4,r5,r7-r11} — so r3 (the w0 csr.r capture = the
        # detour's ra, since the detour is at the fixed P) is
        # RE-ESTABLISHED in the shared tail as the constant RESUME_P
        # (the lo-first OR-safe pair, the v5o idiom) BEFORE the
        # transfer.  The tail transfer (ret.r zero,r8,r11, generic
        # form — goto [r11], no-link, retaddr untouched) executes
        # p0..p3 IN-PLACE from the input buffer; the payload's p3
        # (ret.r zero,r8,r3, the canonical return — stock x8346) is
        # the actual exit: PC := r3 = RESUME_P, retaddr := r8.  The
        # stock tail from P+4 (0x0e43c8..0x0e43e4) re-marshals r4
        # (addi r4,zero,0) and takes NO calls / returns until the fn's
        # no-link ret.r zero,zero,r17 — so the handoff is live-safe
        # exactly as the v5o/v5q T2 early-resume handoff was.
        #
        # Magic-miss W_FAST = ret.d (0xFC00002D, the stock canonical
        # no-arg return — 3403x in stock): return [retaddr] — the
        # detour's call set retaddr := P+4 and nothing on the filter
        # path (w0-w5) touches it, so the miss is a true no-op return
        # to ra.  (NOT the v5q tail-jump FN_A — at a late point FN_A
        # would re-run the stock POST wrapper over the stock word.)
        #
        # Control flow (two exclusive paths + one shared tail, ONE
        # control word for the mode branch):
        #   w18  CMPRES = (mode == A)
        #   w19  b_t -> tail      (A: skip the B status block)
        #   B_block (fall-through, mode != A): the 3 status words
        #   tail (w19 target + B fall-through): r3 = RESUME_P rebuild
        #        (w17's set3 clobbered r12) + r12 = S2OK-lo + payload
        #        ptr + transfer
        #   w28  W_FAST: ret.d (no-op return to ra)
        # Layout: 29 words; W_FAST @w28 = 0x38d7c0 (last).  29 of 34
        # zone words.  The B-path status words are the Task-6
        # contract VERBATIM (0x24040003/0x6C20200A/0x6C20000E); r4 =
        # 0x00030000 on the B exit is harmless — the stock tail at
        # P+4 (0x0e43c8) re-establishes r4 = 0 before any use.
        ws += [enc.csr_r(3, 0xBC)]                       # w0: prefix == v5q
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w1-w15 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # w5: b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]
        ws += [enc.st_d(13, 0, ECHO_LEN)]
        ws += [enc.ld_d(4, 1, M2_KEY_R1_OFF)]            # w9:  r4 = zext32(p0) = w
        ws += [enc.shl64_i(4, 4, 6)]                     # w10: r4 = w << 6
        ws += [enc.set1(4, 4, 0x8FC0)]                   # w11: r4 = X1
        ws += [enc.addi(5, 1, M2_BUF_R1_OFF)]            # w12: r5 = buf
        ws += [enc.addi(6, 0, 0)]                        # w13: r6 = status = 0
        ws += [enc.call(pc(len(ws)), M2_POST_DIRECT)]    # w14: THE DIRECT POST
        ws += [enc.addi(4, 0, 0)]                        # w15: restore r4=0 (A value)
        ws += [enc.ld_w(13, 1, MODE_SLOT_V5Q)]           # w16: mode halfword (16-bit, 0/1)
        ws += [enc.set3(12, 0, 0)]                       # w17: 0 -> r12 (A == mode half 0)
        ws += [enc.cmp38_sel(2, 13, 12)]                 # w18: CMPRES = (mode == A)
        tail = len(ws) + 4                               # w23: after the B block
        w_mode_bt = len(ws)
        ws += [0]                                        # w19: b_t.cc0A -> tail
        # --- B block (fall-through, mode != A): Task-6 status VERBATIM
        ws += [0x24040003]                               # w20: set2 r4,zero,0x3
        ws += [0x6C20200A]                               # w21: st.d r4,r1,0x8 (STATUS_SLOT)
        ws += [0x6C20000E]                               # w22: st.d zero,r1,0xc (syndrome 0)
        # --- shared tail (w19 target + B fall-through): the C1 exit
        ws += [enc.set3(3, 0, RESUME_P & 0xFFFF)]        # w23: r3 lo (P+4; POST clobbered r3)
        ws += [(0x09 << 26) | (3 << 21) | (3 << 16)      # w24: set2 r3,r3,hi
                | ((RESUME_P >> 16) & 0xFFFF)]           #     (== v5o w19 word 0x2463008E)
        ws += [enc.set3(12, 0, 0x4F4B)]                  # w25: r12 := S2OK-lo
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w26: payload ptr
        ws += [enc.ret_r(8, 0, 11)]                      # w27: transfer, no-link
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws[w_mode_bt] = enc.b_t(0x0A, pc(w_mode_bt), pc(tail))
        ws += [0xFC00002D]                               # w28: W_FAST: ret.d (no-op return)
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        if ws[14] != enc.call(STUB + 4 * 14, M2_POST_DIRECT) \
                or ws[11] != enc.set1(4, 4, 0x8FC0) \
                or ws[10] != enc.shl64_i(4, 4, 6):
            raise ValueError("v5r m2'-block words drifted")
        if ws[16] != enc.ld_w(13, 1, MODE_SLOT_V5Q) \
                or ws[17] != enc.set3(12, 0, 0) \
                or ws[18] != enc.cmp38_sel(2, 13, 12) \
                or ws[w_mode_bt] != enc.b_t(0x0A, pc(w_mode_bt), pc(tail)) \
                or ws[w_filter_bf] != enc.b_f(0x0A, pc(w_filter_bf), w_fast):
            raise ValueError("v5r mode-branch words drifted")
        if ws[20:23] != [0x24040003, 0x6C20200A, 0x6C20000E]:
            raise ValueError("v5r mode-B words drifted (Task-6 contract)")
        if ws[23:28] != [enc.set3(3, 0, RESUME_P & 0xFFFF),
                         (0x09 << 26) | (3 << 21) | (3 << 16)
                         | ((RESUME_P >> 16) & 0xFFFF),
                         enc.set3(12, 0, 0x4F4B),
                         enc.addi(11, 1, PAY_SRC_OFF_V5B),
                         enc.ret_r(8, 0, 11)]:
            raise ValueError("v5r tail words drifted (C1 exit)")
        if ws[wfast_idx] != 0xFC00002D:
            raise ValueError("v5r W_FAST is not the no-op ret.d")
        return ws
    if version == 17:
        # v5l (task-34, journal task-33 phase-2 grounding — commit
        # bf0157c: **C1 criterion ACHIEVED live: CR 0x2388 =
        # 0x53324F4B EXACT**, payload 4/4 executed from the input
        # landing; the card WEDGED at the exit — the replica skipped
        # the fn body AFTER the call-site, which builds the QUERY
        # completion): v5k rev.2 MINUS the replica — the stub
        # preloads r3 with THE CALL-SITE RESUME 0x008E4380 (live =
        # file DETOUR_DC 0x0E437C + 4 — the resume of the detoured
        # `call FN_A'; the value csr0xbc holds at detour entry; the
        # value stock FN_A itself returns through: FN_A's own
        # prologue `csr.r r3,csr0xbc' @0x18d964 is BYTE-EXACT the
        # stub's w0) — and the payload p3 returns INTO THE FN BODY
        # at the resume point, as FN_A's return would.  The body
        # then runs STOCK: `or r19,r4,r4' @0x0E4380 marshals r4 (our
        # r4 = 0 — the v5i-documented stock arg setup `addi r4,zero,
        # 0' @0x0E4374 == the stock post-FN_A BadParam value),
        # `subsi r4,r19,0x0' + `b.f.0x0 ->0x8E42E4' branch on it
        # (early-exit epilogue vs the 0x0E438C+ QUERY path), the
        # QUERY completion is built, the fn's OWN epilogue runs (the
        # r17-r23 restores, the 0xf8 pop, the outer-[R+4] return —
        # everything the v5k replica tried to synthesize, now by the
        # fn's own words) — STOCK COMPLETION, the complete S2 goal.
        # r1 keeps R-0xf8 (as at any FN_A return; the BODY pops).
        # r3 build (w10/w11): the proven v5k OR-safe pattern —
        # w10 `set3 r3,ZERO,0x4380' (rs=zero — lo16 CLEAN under BOTH
        # insert and OR semantics, the journal task-32 lesson) THEN
        # w11 `set2 r3,r3,0x008e' (hi-insert — after w10 hi16(r3)==0
        # so insert and OR agree; the w0 csr.r residue IS 0x8E4380
        # already — the pair rebuilds the value EXPLICITLY,
        # deterministic from ANY residue: belt-and-suspenders, and
        # the payload words never touch r3 so the preload survives
        # to p3).  THE REPLICA IS DELETED: no fn-exit words, no
        # restores, no pop — the wedge-hypothesis (ii) of task-33
        # (fetch/exec at the 0xB8D7A0 stub-zone page) cannot fire:
        # v5l executes NOTHING from the stub zone after the w12
        # transfer.  Layout: 14 words — prefix w0-w8 == v5k
        # byte-exact except w5's immediate retargets +18 -> +8
        # (W_FAST moved w23 -> w13: 0xA40A0008 stock-exact x74 — the
        # BEST prefix-retarget count of the lineage), w9 payload ptr
        # (== w1), w10/w11 the r3 build (live-form words: set3
        # rs=zero class x7348 + set2 rs=rd hi-insert = the
        # live-exact S2OK p1 class), w12 `ret.r zero,r8,r11' THE
        # transfer (stock x3, rs=8 no-link), w13 W_FAST jump FN_A
        # LAST (0x38d784, 0x95F80078 live-form x0 — the W_FAST
        # class).  ZERO memory writes outside the CR echoes on every
        # path; ZERO r1 writes AT ALL (no pop — the body pops); ZERO
        # b_t; r4/r5/r6/r14-r16 never touched; r17-r23 NEVER touched
        # (the body's own epilogue restores them — the fn's
        # semantics, not ours).  Interpretation: clean completion +
        # 0x2388=0x53324F4B => FULL C1 (execution + stock
        # completion — the complete S2 goal); wedge/other + S2OK =>
        # body-dependency on FN_A effects (diagnosable; S2OK already
        # banked); clean + no S2OK => construction regression (the
        # CR value names it: 0x53325F7B = OR+residue — build failed;
        # other = p0 delivery).
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5k
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w8 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (echo only)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w9: payload ptr
        resume_live = PC_BASE + DETOUR_DC + 4             # 0x008E4380
        ws += [enc.set3(3, 0, resume_live & 0xFFFF)]     # w10: lo CLEAN (rs=zero)
        ws += [(0x09 << 26) | (3 << 21) | (3 << 16)      # w11: set2 r3,r3,hi
               | ((resume_live >> 16) & 0xFFFF)]         # (rs-bearing form,
        #  ^ the enc.set2 vocabulary has no rs operand; the rs=rd form
        #  is the payload._set2 idiom (the live-exact S2OK p1 class))
        ws += [enc.ret_r(8, 0, 11)]                      # w12: THE transfer, no-link
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        if ws[10] != enc.set3(3, 0, resume_live & 0xFFFF) \
                or ws[11] != (0x09 << 26) | (3 << 21) | (3 << 16) \
                | ((resume_live >> 16) & 0xFFFF):
            raise ValueError("v5l r3-build words drifted")
        return ws
    if version == 16:
        # v5k rev.2 (T33-review 40d902a fix — Critical-1 + Important-2,
        # stub-side EPILOGUE REPLICA exit): the rev.1 Exit-D was
        # MISVERIFIED — the detour path (0x0e4258 push 0xf8 -> 0x0e42b8
        # linking ret.r r17 -> 0x0e42bc -> b_t 0x0e4310 -> call 0xebc9c
        # @0x0e4328 -> call 0xcaec0 @0x0e4358 -> detour 0x0e437c) NEVER
        # pops the fn's 0xf8 frame: each nested callee prologue
        # overwrites the INNER [(R-0xf8)+4] with its resume (last
        # writer call 0xcaec0 -> 0x8E435C), so the rev.1 w10 `ld.d
        # r3,r1,0x4' loaded the residue and p3 re-entered the detour
        # path => DETERMINISTIC LIVELOCK (review Critical-1; grounded:
        # the region [0x0e435c,0x0e437c) decodes LINEAR into the detour
        # call); and r17-r23 (saved @0x0e425c-74, restored ONLY on the
        # epilogue path 0x0e42e8-0x0e4300) leaked on the non-epilogue
        # exit (review Important-2).  THE FIX: the stub carries a
        # 10-word BYTE-EXACT copy of the fn's own epilogue
        # (REPLICA_WORDS, decoded from the base @0x0e42e8..0x0e430c —
        # 7 restores + pop + outer-ra load + the fn's final ret.r;
        # every word stock-exact, the strongest precedent class) and
        # PRELOADS r3 with the replica's ABSOLUTE live address (stub
        # zone = absolute space, base-independent by construction)
        # BEFORE the transfer: w10 `set3 r3,ZERO,lo16' (rs=zero — the
        # lo16 is CLEAN under BOTH insert and OR semantics, the
        # journal task-32 lesson; the SAME proven build pattern as the
        # S2OK payload p0/p1) THEN w11 `set2 r3,r3,hi16' (hi-insert —
        # after w10 hi16(r3)==0 so insert and OR agree here too; the
        # w0 csr.r residue 0x8E4380 cannot leak: w10's source is the
        # zero REGISTER).  The payload p3 = `ret.r zero,r8,r3'
        # (UNCHANGED 0xFD001825, stock x8346) exits into the replica,
        # which completes the fn's epilogue: r17-r23 restored, frame
        # popped, return THROUGH the OUTER [R+4] — the fn's true saved
        # dispatcher ra (written by the fn prologue @0x0e4254 from
        # csr0xbc at fn entry, BEFORE the 0xf8 push; the value chain
        # verified from the stock decode) — single transit, livelock
        # GONE by design.  r4-equivalence note: the replica omits the
        # epilogue's first word `or r4,r19,r19' (@0x0e42e4 — the
        # result-marshal); at the detour r4 = 0 already (stock arg
        # setup `addi r4,zero,0' @0x0e4374) == the stock post-FN_A
        # BadParam value the epilogue would marshal — the caller sees
        # the same r4 either way.
        # Layout: 24 words — prefix w0-w8 == v5j byte-exact (only w5's
        # immediate retargets +6 -> +18 to the new W_FAST @w23:
        # 0xA40A0012 stock-exact x27), w9 payload ptr (== w1), w10/w11
        # the r3 build (live-form words: set3 rs=zero class x7348 +
        # set2 rs=rd hi-insert = the live-exact S2OK p1 class), w12
        # `ret.r zero,r8,r11' THE transfer (stock x3, rs=8 no-link),
        # w13-w22 the REPLICA (all 10 words byte-exact stock), w23
        # W_FAST jump FN_A LAST (0x38d7ac, 0x95F8086E live-form x0 —
        # the W_FAST class).  ZERO memory writes outside the CR echoes
        # on every path (restores are READS; the pop addi r1,r1,0xf8
        # is the stock SP-restore register word itself — stock-exact,
        # and the frame-write discipline concerns memory writes);
        # ZERO b_t; r4/r5/r6/r14-r16 never touched; r17-r23 touched
        # ONLY by the replica restores (the fn's own epilogue
        # semantics).  Interpretation (rev.2): clean + 0x2388 =
        # 0x53324F4B => FULL C1 (replica exit — the fn's own epilogue
        # executed from the stub); clean + 0x2388 != S2OK =>
        # construction issue (the CR value names it: 0x53325F7B again
        # = OR+residue — Fix 1 failed live; other = p0 delivery);
        # card-wedge/host-alive + S2OK readable => replica/return
        # issue (diagnosable — restore/pop/outer-read derailed; echoes
        # 0x2380/0x2384 distinguish the prefix); host-freeze => new
        # class (unexpected — zero frame writes).  The rev.1 livelock
        # signature is GONE BY DESIGN (no re-execution: the exit
        # consumes the outer ra exactly once).
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5j
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w8 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (echo only)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w9: payload ptr
        replica_live = PC_BASE + STUB + 4 * 13           # w13 replica start
        ws += [enc.set3(3, 0, replica_live & 0xFFFF)]    # w10: lo CLEAN (rs=zero)
        ws += [(0x09 << 26) | (3 << 21) | (3 << 16)      # w11: set2 r3,r3,hi
               | ((replica_live >> 16) & 0xFFFF)]        # (rs-bearing form,
        #  ^ the enc.set2 vocabulary has no rs operand; the rs=rd form
        #  is the payload._set2 idiom (the live-exact S2OK p1 class))
        ws += [enc.ret_r(8, 0, 11)]                      # w12: THE transfer, no-link
        ws += list(REPLICA_WORDS)                        # w13-w22: the replica
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        if ws[13:23] != list(REPLICA_WORDS):
            raise ValueError("v5k rev.2 replica words drifted")
        return ws
    if version == 15:
        # v5j rev.2 (T32-review Exit-C; THE C1 PIVOT — exec-from-input;
        # journal task-30 Q4 sketch + errata f0e4804; task-31 phase-2
        # verdict: ZERO extra frame writes = live-proven safe class):
        # the payload EXECUTES IN-PLACE from the input landing zone
        # [r1+0xac..0xbc).  ZERO frame writes — NO push, NO save, NO
        # copy, NO neutral write: the stub's only stores are the CR
        # echoes (always-clean class, v5i live x4 images); the
        # pushed-frame freeze class (#9: tail-frame x ANY extra write
        # into the pushed frame) cannot in principle fire — there is NO
        # pushed frame.  Prefix w0-w8 == v5i byte-exact (only w5's
        # immediate retargets +9 -> +6 to the new W_FAST @w11:
        # 0xA40A0006 stock-exact x70 — the BEST count of the whole
        # lineage); NO N-guard, NO gauntlet: N is echoed (0x2384=N)
        # and NEVER used for control.  w9 re-establishes r11 = r1+0xac
        # (the w1 word — dead in v5i, the payload ptr here;
        # 0x98+0x14=0xac, T17-proven k=0x14) immediately before
        # w10 = `ret.r zero,r8,r11` (0xFD005825): THE SINGLE
        # register-target transfer into the landing — rs=8
        # COMPUTED-JR CLASS, NO LINK (csr0xbc keeps the pre-detour
        # ra 0x0e4380: word stock-exact x3, class x8986 — canonical
        # return x8346 + jr x640, live on every completion, journal
        # task-30 return-state inventory; NOT the rev.1 rs=0 LINKING
        # jalr — review Important-2: the link wrote csr0xbc = W_FAST
        # and FN_A's ret.d would loop FN_A<->W_FAST).  W_FAST jump
        # FN_A LAST (w11 = 0x38d77c, 0x95F8007A live-form x0).  12 of
        # 34 zone words.  Payload (payload.payload_v5j rev.2: 4 words
        # at input k=0x14..0x24 -> [r1+0xac..0xbc); frame 36B = the
        # STANDARD neg-frame size, all bytes k<=0x23 — inside the T2
        # strictly-clean window, ceiling 0x38: NO corruption-zone
        # exposure, review Important-3 closed): p0 set3-lo + p1
        # set2-hi build r12=0x53324F4B (insert semantics —
        # deterministic), p2 st.d S2OK -> CR 0x2388 (gate G5; the FULL
        # C1 signal — the rev.1 landing echo dropped, S2OK
        # self-validates), p3 `jump` to the LIVE FN_A 0x98d964 (=
        # file 0x18d964 + 0x800000 — review Critical-1: rev.1 encoded
        # the file-space target, off 0x800000) from live PC r1+0xb8
        # (k=0x20; s24 imm fits every stack base 0x7d1ff8..0x7ffff8,
        # worst-case 0x6ee2d, margin 0x7911d2 words).  Exit
        # semantics: p3 -> FN_A ret.d -> csr0xbc = pre-detour ra ->
        # stock return into the dispatcher (the SAME completion as
        # every v5-series clean run; NO link anywhere on the path).
        # Interpretation (rev.2): clean + 0x2388=0x53324F4B => FULL
        # C1 (no freeze expected — the exit is the proven class);
        # freeze + 0x2388=S2OK readable => payload ran, exit derailed
        # (investigate); freeze + 0x2388=0 => stack-exec/w10 class
        # failed; clean + 0x2388=0 => w10 landing/fetch failed
        # (echoes distinguish prefix-ran).
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5i
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w8 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (echo only)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w9: payload ptr
        ws += [enc.ret_r(8, 0, 11)]                      # w10: THE transfer, no-link
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 14:
        # v5i (T31, neutral-write discriminator): v5h with the
        # pair+loop block REPLACED by ONE NEUTRAL-CONSTANT frame
        # write — `set3 r12,zero,0xA5A5` + `st.d r12,r1,0x30` — no
        # input-derived values in the write path.  Discriminator after
        # freeze #9 (journal task-29 phase-2: freeze@N=2 on v5h = v5g
        # minus the save): tail-frame x ANY extra write into the
        # pushed frame => freeze (save OR copies); push-ra + CR
        # writes always clean.  Fork: freeze => H-FRAMEGUARD (ANY
        # extra frame-write x tail-frame, content-independent -> C1
        # must avoid frame writes entirely, task-30 RE); clean =>
        # H-CONTENT (the copied VALUES were the trigger -> C1 =
        # copy-free OR sanitize before copying).  Prefix w0-w9 ==
        # v5h byte-exact (only w5's immediate retargets +16 -> +9 to
        # the new W_FAST @w14: 0xA40A0009 stock-exact x48, the best
        # count of the lineage); NO save, NO dst-init, NO pair, NO
        # loop, NO back-edge (conditionals = filter w5 ONLY; N echoed
        # 0x2384=N, never used for control).  Neutral tuple stock
        # census: st.d r12,r1,0x30 = 0x6C206032 x1 (precedented — the
        # brief's fallback clause never fires); class st.d rt=12,
        # rs=r1,* x26; set3 r12,zero,0xA5A5 = 0x200CA5A5 x0 exact but
        # live-FORM (set3 r12,zero,* stock x11 + v5b/v5cA-live
        # consts).  TAIL marker word unchanged (st.d r13,zero,0x238C)
        # — with the loop GONE nothing zeroes r13, so a clean
        # completion leaves 0x238C = N (documented erratum vs the
        # brief's "0x238C=0": the word-level "TAIL unchanged" mandate
        # wins; freeze => 0x238C stays at the fresh baseline 0 — the
        # marker is the LAST CR write on the path) -> pop -> W_FAST
        # jump FN_A LAST (w14 = 0x38d788, 0x95F80077 live-form x0).
        # 15 of 34 zone words.
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5h
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w9 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]         # (r11 dead: no loop)
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (echo only)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.st_d_push(-FRAME)]                    # push, stock-exact
        ws += [enc.set3(12, 0, 0xA5A5)]                  # NEUTRAL const
        ws += [enc.st_d(12, 1, 0x30)]                    # NEUTRAL frame write
        ws += [enc.st_d(13, 0, 0x238C)]                  # TAIL marker (r13=N)
        ws += [enc.addi(1, 1, FRAME)]                    # pop, stock-exact
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 13:
        # v5h (T29, named-suspect SAVE test): v5g MINUS the save word —
        # `st.d r3,r1,0x0` (v5g w10 = 0x6C201802, the sole 0-combo
        # rt=3/rs=r1/off=0 store; stock census x0) is NAMED the freeze
        # common-denominator (journal task-28 phase-2: freeze@N=2 on
        # the fully-linear v5g + ledger; the SAVE ran on every freeze
        # path AND every clean magic path).  r3 is dead at the detour
        # per R3 — the save was vestigial paranoia.  Fork: tail-frames
        # clean => SAVE x TAIL named (write-path fully rehabilitated);
        # freeze => pair/loop x tail-CONTENT (copied VALUES matter).
        # Prefix w0-w4/w6-w9 == v5g byte-exact (only w5's immediate
        # retargets +17->+16 to the new W_FAST @w21: 0xA40A0010
        # stock-exact x22).  NO save: dst-init directly after the
        # push; pair + the v5d-VERBATIM do-while loop (w13-w18 ==
        # v5d w15-w20; the back-edge word is UNCHANGED — relative -5,
        # both ends shifted together) runs xN for EVERY magic N in
        # {1..4}; TAIL marker st.d r13,zero,0x238C (r13=0 after the
        # loop, uninformative, live-form) -> pop -> W_FAST jump FN_A
        # LAST (w21 = 0x38d7a4).  22 of 34 zone words.
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5g
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w9 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (counter)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.st_d_push(-FRAME)]                    # push, stock-exact
        # NO save word (the named suspect): r3 dead at the detour (R3)
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst init (v5d word)
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0)]   # pair (v5d words)
        loop = len(ws)                                    # W_LOOP @ pc(loop)
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0),
               enc.addi(11, 11, 4), enc.addi(12, 12, 4),
               enc.subsi(13, 13, 1)]                     # v5d-verbatim loop
        ws += [enc.b_f(0x00, pc(len(ws)), pc(loop))]      # back-edge: imm -5
        ws += [enc.st_d(13, 0, 0x238C)]                  # TAIL marker (N>=1 -> 0)
        ws += [enc.addi(1, 1, FRAME)]                    # pop, stock-exact
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 12:
        # v5g (T28, linear fork-test): v5b flow MINUS gauntlet MINUS
        # payload-block MINUS ALL N-gates — fully LINEAR.  The five
        # freezes (v5b/v5cB/v5d N=4: gauntlet forward skip; v5e N=2:
        # forward taken b_t +14; v5f N=2: forward taken jump +15) ALL
        # carried a forward block-skip from a late stub position; the
        # clean magic-run union (v5cA, echo-N1) was LINEAR.  v5g keeps
        # exactly the linear clean shape + the never-clean-live loop
        # back-edge: freeze@N=2+ => H-INPUT (tail-bytes/N-triggered,
        # forward control-flow exonerated); all-clean => H-SKIP.
        # Prefix w0-w10 = v5e/v5f byte-exact (only w5's immediate
        # retargets to the new W_FAST @w22: 0xA40A0011 stock-exact x15).
        # NO N-guard, NO gates, NO gauntlet: dst-init + ONE pair +
        # the v5d-VERBATIM do-while loop (w14-w19 == v5d w15-w20) runs
        # xN for EVERY magic N in {1..4} (back-edge taken xN-1 at latch
        # FALSE — the ONLY taken conditional possible); TAIL marker
        # st.d r13,zero,0x238C (r13=0 after the loop, uninformative,
        # live-form) -> pop -> W_FAST jump FN_A LAST (w22 = 0x38d7a8).
        # 23 of 34 zone words.
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5e/v5f
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w10 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (counter)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.st_d_push(-FRAME)]                    # push, stock-exact
        ws += [enc.st_d(3, 1, S_RA)]                     # saves (v5b-verbatim)
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst init (v5d word)
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0)]   # pair (v5d words)
        loop = len(ws)                                    # W_LOOP @ pc(loop)
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0),
               enc.addi(11, 11, 4), enc.addi(12, 12, 4),
               enc.subsi(13, 13, 1)]                     # v5d-verbatim loop
        ws += [enc.b_f(0x00, pc(len(ws)), pc(loop))]      # back-edge: imm -5
        ws += [enc.st_d(13, 0, 0x238C)]                  # TAIL marker (N>=1 -> 0)
        ws += [enc.addi(1, 1, FRAME)]                    # pop, stock-exact
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 11:
        # v5f (T27, journal task-26 §Step 7, freeze-#6 fix): v5e flow,
        # BOTH N-gates replaced by the STOCK SKIP-IDIOM [cmp38;
        # b_f.cc0A +2; jump TAIL] — b_t-taken (the ONE taken op=0x28
        # observed on 4030 = freeze-#6 at v5e neg-N2) is ELIMINATED:
        # equality -> b_f NOT-taken -> the UNCONDITIONAL jump TAIL
        # executes; inequality -> the b_f +2 skip fires (b_f.cc0A at
        # CMPRES=false, the only live-proven clean taken-conditional
        # class on 4030 — the w5 fallthrough, x5 boots).  Prefix w0-w10
        # = v5e byte-exact (only w5's immediate retargets to the new
        # W_FAST @w31: 0xA40A001A stock-exact x10).  L2 (w11-w14) /
        # L3 (w18-w21) gates: set3 consts = v5cA-live M1/M2, cmp38 =
        # v5b-live guard, skip word 0xA40A0002 stock x94 (74/94 right
        # after op36/op38 d=1), exit jumps stock x222/x365.  dst-init /
        # pair / dst-RE-INIT keep their v5e words at +1 word (the L2
        # gate gained its jump word); loop w23-w28 == v5d w15-w20
        # byte-exact (N=4 falls straight in; the pair's earlier write
        # is an idempotent duplicate).  Shared TAIL = marker st.d r13,
        # zero,0x238C @w29 (values N=2->2, N=3->3, N=4->0, N=1->0) ->
        # pop -> W_FAST jump FN_A LAST (w31 = 0x38d7cc).  32 of 34
        # zone words.
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5e
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w10 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (counter)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.st_d_push(-FRAME)]                    # push, stock-exact
        ws += [enc.st_d(3, 1, S_RA)]                     # saves — SUSPECT #1
        ws += [enc.set3(12, 0, 2)]                       # L2: v5cA-live M1
        ws += [enc.cmp38_sel(2, 13, 12)]                 # N vs 2 (v5b guard)
        w_l2_bf = len(ws)
        ws += [0]                                        # skip: b_f.cc0A +2
        w_l2_j = len(ws)
        ws += [0]                                        # exit: jump -> TAIL
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst init — SUSPECT #2
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0)]   # pair — SUSPECT #3
        ws += [enc.set3(12, 0, 3)]                       # L3: v5cA-live M2
        ws += [enc.cmp38_sel(2, 13, 12)]                 # N vs 3 (v5b guard)
        w_l3_bf = len(ws)
        ws += [0]                                        # skip: b_f.cc0A +2
        w_l3_j = len(ws)
        ws += [0]                                        # exit: jump -> TAIL
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst RE-INIT (rev.2)
        loop = len(ws)                                    # W_LOOP @ pc(loop)
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0),
               enc.addi(11, 11, 4), enc.addi(12, 12, 4),
               enc.subsi(13, 13, 1)]                     # v5d-verbatim loop
        ws += [enc.b_f(0x00, pc(len(ws)), pc(loop))]      # back-edge: imm -5
        tail = pc(len(ws))                                # TAIL = marker
        ws += [enc.st_d(13, 0, 0x238C)]                  # shared marker
        ws += [enc.addi(1, 1, FRAME)]                    # pop, stock-exact
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws[w_l2_bf] = enc.b_f(0x0A, pc(w_l2_bf), pc(w_l2_bf + 2))
        ws[w_l2_j] = enc.jump(pc(w_l2_j), tail)
        ws[w_l3_bf] = enc.b_f(0x0A, pc(w_l3_bf), pc(w_l3_bf + 2))
        ws[w_l3_j] = enc.jump(pc(w_l3_j), tail)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 10:
        # v5e (T25, journal task-24 «Errata + v5e rev.2», review-driven
        # rework of the old Option A whose N=4 path wrote absolute EAs —
        # the gates clobbered the dst pointer): ESCALATION N-GATES
        # bisection stub — freeze at frame-N=k names the block.  Prefix
        # w0-w8 = live-exact v5b filter/echo/N-load+echo (only w5's
        # immediate retargets to the new W_FAST; stock-exact x14); the
        # v5b N-guard is REPLACED by the escalation flow that accepts
        # N in {1,2,3,4}.  L2 (w11-w13) sits between saves and dst-init
        # (r12 provably free: last read w6, next def w14) — N==2 exits
        # to TAIL => a freeze at N=2 names the SAVES block.  L3 (w17-w19)
        # sits after dst-init + the single ld.d/st.d pair — N==3 exits
        # => WRITE-PAIR block (dst-init vs pair conflated: gate-reorder
        # disambiguator documented in the journal).  The gate set3 words
        # clobber r12, so w20 RE-INITS the dst pointer with the dst-init
        # word itself (0-TUPLE, any-imm combo x2 no-store-follows — no
        # new word-class) before the v5d-VERBATIM do-while loop (w21-w26
        # == v5d w15-w20 byte-exact) — N==4 falls straight in (iteration
        # 1 re-copies word0 over the pair's identical write: idempotent
        # duplicate) => LOOP block.  Every gate word live-exact (set3 =
        # v5cA-live M1/M2, cmp38_sel(2,13,12) = v5b-live guard) or
        # stock-exact (b_t.cc0A exits x56/x75; b_t.cc0A class x2315,
        # [cmp38->b_t.cc0A] adjacency x15).  Shared TAIL = marker
        # st.d r13,zero,0x238C (echo-word form retargeted to the
        # live-marker offset; values N=2->2, N=3->3, N=4->0, N=1->0;
        # the N=1==N=4 collision is protocol-disambiguated: echo runs
        # first) -> pop -> W_FAST jump FN_A LAST (w29 = 0x38d7c4).
        # 30 of 34 zone words (removing the old L4 guard -3 and 3
        # pre-loop words -3 pays for the marker +1 and re-init +1).
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5b
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-w4 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (counter)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.st_d_push(-FRAME)]                    # push, stock-exact
        ws += [enc.st_d(3, 1, S_RA)]                     # saves — SUSPECT #1
        ws += [enc.set3(12, 0, 2)]                       # L2: v5cA-live M1
        ws += [enc.cmp38_sel(2, 13, 12)]                 # N vs 2 (v5b guard)
        w_l2_bt = len(ws)
        ws += [0]                                        # b_t.cc0A -> TAIL
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst init — SUSPECT #2
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0)]   # pair — SUSPECT #3
        ws += [enc.set3(12, 0, 3)]                       # L3: v5cA-live M2
        ws += [enc.cmp38_sel(2, 13, 12)]                 # N vs 3 (v5b guard)
        w_l3_bt = len(ws)
        ws += [0]                                        # b_t.cc0A -> TAIL
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst RE-INIT (rev.2)
        loop = len(ws)                                    # W_LOOP @ pc(loop)
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0),
               enc.addi(11, 11, 4), enc.addi(12, 12, 4),
               enc.subsi(13, 13, 1)]                     # v5d-verbatim loop
        ws += [enc.b_f(0x00, pc(len(ws)), pc(loop))]      # back-edge: imm -5
        tail = pc(len(ws))                                # TAIL = marker
        ws += [enc.st_d(13, 0, 0x238C)]                  # shared marker
        ws += [enc.addi(1, 1, FRAME)]                    # pop, stock-exact
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws[w_l2_bt] = enc.b_t(0x0A, pc(w_l2_bt), tail)
        ws[w_l3_bt] = enc.b_t(0x0A, pc(w_l3_bt), tail)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 9:
        # v5d (T23, task-22 audit "no smoking gun" + Step-7 sketch,
        # review-approved): C1-candidate with a STOCK-CONFORMANCE copy data
        # path.  v5b flow verbatim (live-proven prefix w0-11, push, saves,
        # gauntlet, payload block, resume tail); ONLY the copy-loop data
        # words change: the two 16-bit ld.w/st.w pairs (st.w rt=3 AND rs=12
        # — the top 0/1947 residual suspects) collapse to ONE 32-bit
        # ld.d/st.d pair, both byte-exact stock words (ld.d r3,[r11+0]
        # x1 code site, combo rs=11^rd=3 x2; st.d r3,[r12+0] x46, all
        # off=0).  Strides addi +4 stay (verbatim stock in-loop words),
        # subsi r13,r13,1 = THE one 0-precedent field (0/37907; r13
        # reserved by stock ABI; live-writable per every v5b magic run;
        # constrained minimum per task-22 review — do NOT remap to r13
        # bases), back-edge b_f.cc00 imm -7 -> -5 (0xA400FFFB stock x314).
        # Recorded shape residual (journal task-23): adjacent
        # ld.d r3 -> st.d r3 = 0 stock (fields precedented, shape novel).
        # M-marker set3 r12,zero,7 + st.d r12,zero,0x238C after loop-exit
        # (v5a-live CR word + v5cA-live marker form, VAL=7 = "copy done"):
        # the 2 words saved by the pair collapse pay for it, so the
        # gauntlet/payload/resume/W_FAST and the prefix b_f immediates
        # stay v5b byte-exact at v5b indices.  33 of 34 zone words.
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5b
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-11 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (counter)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.set3(12, 0, 4)]                       # guard bound = 4
        ws += [enc.cmp38_sel(2, 13, 12)]                 # eq32 N vs 4
        w_guard_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d_push(-FRAME)]                    # push, stock-exact
        ws += [enc.st_d(3, 1, S_RA)]                     # save ra (v5b-verbatim)
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst init (v5b-verbatim)
        loop = len(ws)                                    # W_LOOP @ pc(loop)
        ws += [enc.ld_d(3, 11, 0), enc.st_d(3, 12, 0),
               enc.addi(11, 11, 4), enc.addi(12, 12, 4),
               enc.subsi(13, 13, 1)]                     # NEW data path (T23)
        ws += [enc.b_f(0x00, pc(len(ws)), pc(loop))]      # back-edge: imm -5
        ws += [enc.set3(12, 0, 7), enc.st_d(12, 0, 0x238C)]   # M: copy done
        ws += [enc.ld_w(12, 1, PAY_OFF)]                 # gauntlet read (v5b)
        ws += [enc.set3(13, 0, 0x2407)]                  # hi маркер-слова
        ws += [enc.cmp38_sel(2, 12, 13)]                 # (v5b-verbatim)
        w_gaunt_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> RESUME
        ws += [enc.addi(12, 1, PAY_OFF)]                 # ptr payload (v5b)
        resume = STUB + 4 * (len(ws) + 3)                 # живой PC = +0x800000
        ws += [enc.set2(3, (PC_BASE + resume) >> 16),
               enc.set3(3, 3, (PC_BASE + resume) & 0xFFFF),
               enc.ret_r(0, 0, 12)]                      # прыжок в стек-payload
        if pc(len(ws)) != resume:
            raise ValueError("v5d resume layout drift")
        ws += [enc.addi(1, 1, FRAME)]                    # RESUME: pop (общий для
        w_fast = pc(len(ws))                              #  payload-return и gauntlet-miss)
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws[w_guard_bf] = enc.b_f(0x0A, pc(w_guard_bf), w_fast)
        ws[w_gaunt_bf] = enc.b_f(0x0A, pc(w_gaunt_bf), resume)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 8:
        # v5c-B (T21, task-19-debug2 §v5c-B + task-20 Phase-2 ruling): full
        # v5b write path under stage markers — suspects VERBATIM (save,
        # dst-init, copy loop, gauntlet) to pinpoint the freeze group.
        # Budget (34-word zone) drops M0/M4 (push/pop exonerated by v5c-A)
        # and the match-path-only payload block => exactly 34 WITH counter.
        # Freeze -> CR 0x238C: <2 saves (push innocent), 2 copy-loop
        # (+0x2388 iteration), 3 gauntlet (pop innocent); clean = survived.
        ws += [enc.csr_r(3, 0xBC)]                       # prefix == v5b/v5cA
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # w0-11 live-proven
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (counter)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.set3(12, 0, 4)]                       # guard bound = 4
        ws += [enc.cmp38_sel(2, 13, 12)]                 # eq32 N vs 4
        w_guard_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d_push(-FRAME)]                    # push, stock-exact
        ws += [enc.st_d(3, 1, S_RA)]                     # SAVE — suspect #1 (v5b-verbatim)
        ws += [enc.set3(12, 0, 2), enc.st_d(12, 0, 0x238C)]   # M1: saves survived
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst init — suspect (v5b-verbatim)
        loop = len(ws)                                    # W_LOOP @ pc(loop)
        ws += [enc.ld_w(3, 11, 0), enc.st_w(3, 12, 0),
               enc.ld_w(3, 11, 2), enc.st_w(3, 12, 2)]   # suspects (v5b-verbatim)
        ws += [enc.st_d(13, 0, 0x2388)]                  # counter snapshot (4/3/2/1)
        ws += [enc.addi(11, 11, 4), enc.addi(12, 12, 4),
               enc.subsi(13, 13, 1)]                     # suspects (v5b-verbatim)
        ws += [enc.b_f(0x00, pc(len(ws)), pc(loop))]      # back-edge: imm -7 -> -8
        ws += [enc.set3(12, 0, 3), enc.st_d(12, 0, 0x238C)]   # M2: copy survived
        ws += [enc.ld_w(12, 1, PAY_OFF)]                 # gauntlet read — suspect
        ws += [enc.set3(13, 0, 0x2407)]                  # hi маркер-слова (v5b-verbatim)
        ws += [enc.cmp38_sel(2, 12, 13)]                 # (v5b-verbatim)
        w_gaunt_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> pop (miss)
        w_pop = len(ws)
        ws += [enc.addi(1, 1, FRAME)]                    # pop, stock-exact
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws[w_guard_bf] = enc.b_f(0x0A, pc(w_guard_bf), w_fast)
        ws[w_gaunt_bf] = enc.b_f(0x0A, pc(w_gaunt_bf), pc(w_pop))
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 7:
        # v5c-A (T20, task-19-debug2 design + review "M0 before push"):
        # frame-only diagnostic probe for the write-path host-freeze.
        # Prefix == v5b words 0-11 (live-proven; b_f immediates retargeted
        # to the new W_FAST), then stage markers M0/M1/M2 (set3 r12,zero,VAL
        # + st.d r12,zero,0x238C — the v5a-live byte-exact CR word; set3
        # rd=12: 362 stock sites + v5b-live guard const) bracketing the
        # stock-identical push/pop.  NO saves, NO copy loop, NO gauntlet,
        # NO payload: freeze -> last live marker in 0x238C names the stage.
        ws += [enc.csr_r(3, 0xBC)]                       # ra capture (lineage)
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # dead (no loop): v5b prefix kept verbatim
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]         # MAGIC16 filter (T17 slot)
        ws += [enc.set3(13, 0, 0x5332)]
        ws += [enc.cmp38_sel(2, 12, 13)]                 # eq32, live-proven
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # echo MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # echo N
        ws += [enc.set3(12, 0, 4)]                       # guard bound = 4
        ws += [enc.cmp38_sel(2, 13, 12)]                 # eq32 N vs 4
        w_guard_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST (N != 4)
        ws += [enc.set3(12, 0, 1), enc.st_d(12, 0, 0x238C)]   # M0 (before push)
        ws += [enc.st_d_push(-FRAME)]                    # push, stock-identical
        ws += [enc.set3(12, 0, 2), enc.st_d(12, 0, 0x238C)]   # M1
        ws += [enc.addi(1, 1, FRAME)]                    # pop, stock-identical
        ws += [enc.set3(12, 0, 3), enc.st_d(12, 0, 0x238C)]   # M2
        w_fast = pc(len(ws))
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws[w_guard_bf] = enc.b_f(0x0A, pc(w_guard_bf), w_fast)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 5:
        for off, cr in V5A_PROBES:
            ws += [enc.ld_w(12, 1, off), enc.st_d(12, 0, cr)]
        tail = pc(len(ws))
        ws += [enc.jump(tail, FN_A)]                 # tail-jump FN_A (stock-style)
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, tail_idx = STUB_LAYOUT[version]
        if len(ws) != total or tail != STUB + 4 * tail_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"tail-jump @0x{tail:x} (want {total}/0x{STUB + 4 * tail_idx:x})")
        return ws
    if version == 6:
        # v5b (T18, fix review Critical-1/Important-2): [r1+0xaa] MAGIC16
        # filter (T17 live), N@[r1+0xa4] -> r13 (счётчик subsi), stub-side
        # N-guard (set3 4 / cmp38 eq32 / b_f.cc0A -> W_FAST: [r1+0xa4] —
        # гипотеза, мусорный N не доходит до цикла), 2-pairs-per-word copy
        # loop (16-bit ld.w/st.w), mandatory gauntlet.
        ws += [enc.csr_r(3, 0xBC)]                       # захват ra (lineage)
        ws += [enc.addi(11, 1, PAY_SRC_OFF_V5B)]         # src = [r1+0xac] (T17: k=0x14)
        ws += [enc.ld_w(12, 1, SLOT_FILTER_V5B)]         # h([r1+0xaa]) — слот T17
        ws += [enc.set3(13, 0, 0x5332)]                  # 1 слово (fuzz-T3: rd=imm)
        ws += [enc.cmp38_sel(2, 12, 13)]                 # eq32, live-proven
        w_filter_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST
        ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # эхо MAGIC16
        ws += [enc.ld_w(13, 1, SLOT_N_V5B)]              # N -> r13 (счётчик цикла)
        ws += [enc.st_d(13, 0, ECHO_LEN)]                # эхо N
        ws += [enc.set3(12, 0, 4)]                       # guard: bound = PAYLOAD_MAX
        ws += [enc.cmp38_sel(2, 13, 12)]                 # eq32 N vs 4
        w_guard_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> W_FAST (N != 4)
        ws += [enc.st_d_push(-FRAME)]                    # r1 -= FRAME
        ws += [enc.st_d(3, 1, S_RA)]                     # save ra (lineage)
        ws += [enc.addi(12, 1, PAY_OFF)]                 # dst = payload slot
        loop = len(ws)                                    # W_LOOP @ pc(loop)
        ws += [enc.ld_w(3, 11, 0), enc.st_w(3, 12, 0),
               enc.ld_w(3, 11, 2), enc.st_w(3, 12, 2),   # 16-бит ops: 2 пары/слово
               enc.addi(11, 11, 4), enc.addi(12, 12, 4),
               enc.subsi(13, 13, 1)]
        ws += [enc.b_f(0x00, pc(len(ws)), pc(loop))]      # пока N!=0 -> тело
        ws += [enc.ld_w(12, 1, PAY_OFF)]                 # gauntlet: слово[0].hi
        ws += [enc.set3(13, 0, 0x2407)]                  # hi маркер-слова 0x24075332
        ws += [enc.cmp38_sel(2, 12, 13)]
        w_gaunt_bf = len(ws)
        ws += [0]                                        # b_f.cc0A -> RESUME (мимо)
        ws += [enc.addi(12, 1, PAY_OFF)]                 # ptr payload
        resume = STUB + 4 * (len(ws) + 3)                 # живой PC = +0x800000
        ws += [enc.set2(3, (PC_BASE + resume) >> 16),
               enc.set3(3, 3, (PC_BASE + resume) & 0xFFFF),
               enc.ret_r(0, 0, 12)]                      # прыжок в стек-payload
        if pc(len(ws)) != resume:
            raise ValueError("v5b resume layout drift")
        ws += [enc.addi(1, 1, FRAME)]                    # RESUME: pop (общий для
        w_fast = pc(len(ws))                              #  payload-return и gauntlet-miss)
        ws[w_filter_bf] = enc.b_f(0x0A, pc(w_filter_bf), w_fast)
        ws[w_guard_bf] = enc.b_f(0x0A, pc(w_guard_bf), w_fast)
        ws[w_gaunt_bf] = enc.b_f(0x0A, pc(w_gaunt_bf), resume)
        ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
        if len(ws) > ZONE_WORDS:
            raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
        total, wfast_idx = STUB_LAYOUT[version]
        if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
            raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                             f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
        return ws
    if version == 2:
        filter_word = enc.ld_w(12, 1, IN_OFF)
        const = (MAGIC >> 16, MAGIC & 0xFFFF)
        n_word = enc.ld_w(13, 1, IN_OFF + 4)
        src = enc.addi(11, 1, PAY_SRC_OFF)
        r5_word = enc.ld_w(5, 1, R5_SRC)
        r6_init = [enc.ld_w(6, 1, R6_SRC)]
    else:
        filter_word = enc.ld_w(12, 1, IN_OFF + 8)
        const = (DISCRIM32 >> 16, DISCRIM32 & 0xFFFF)
        n_word = enc.ld_w(13, 1, N_OFF_V4)
        src = enc.addi(11, 1, PAY_SRC_OFF_V4)
        r5_word = enc.ld_w(5, 1, R5_SRC_V4)
        r6_init = []
    ws += [enc.csr_r(3, 0xBC)]                       # захват ra (csr0xbc)
    ws += [src]                                      # r11 = &payload src
    ws += [filter_word]                              # слово-дискриминатор
    ws += [enc.set2(13, const[0]), enc.set3(13, 13, const[1])]
    ws += [enc.cmp38_sel(2, 12, 13)]                 # eq32: funct5=2, live-proven (fuzz-2; funct5=0 trap/stall — live-инцидент task-07-debug, plan-fix R9)
    ws += [0]                                        # b_f.cc0A -> W_FAST (ниже)
    ws += [enc.st_d(12, 0, ECHO_MAGIC)]              # эхо сравнённого слова (v4: DISCRIM32)
    ws += [n_word]                                   # N
    ws += [enc.st_d(13, 0, ECHO_LEN)]                # эхо N
    ws += [enc.st_d_push(-FRAME)]                    # r1 -= FRAME
    ws += [enc.st_d(3, 1, S_RA), enc.st_d(6, 1, S_R6)]
    ws += [enc.addi(12, 1, PAY_OFF)]                 # dst = payload slot
    loop = len(ws)                                    # W_LOOP @ pc(loop)
    ws += [enc.ld_w(3, 11, 0), enc.st_w(3, 12, 0),
           enc.addi(11, 11, 4), enc.addi(12, 12, 4),
           enc.subsi(13, 13, 1)]
    ws += [enc.b_f(0x00, pc(len(ws)), pc(loop))]      # пока N!=0 -> тело
    ws += [enc.addi(12, 1, PAY_OFF)]                 # рематериализация ptr payload
    ws += [enc.addi(4, 1, RES_OFF)]                  # r4 = result-буфер
    ws += [r5_word] + r6_init                        # r5/r6 init (v4: r6 не трогаем)
    resume = STUB + 4 * (len(ws) + 4)                 # живой PC = +0x800000
    ws += [enc.set2(3, (PC_BASE + resume) >> 16),
           enc.set3(3, 3, (PC_BASE + resume) & 0xFFFF),
           enc.ret_r(0, 0, 12)]                      # прыжок в стек-payload
    while len(ws) < (resume - STUB) // 4:             # W_RESUME nop-выравнивание
        ws += [enc.or_(0, 0, 0)]
    ws += [enc.ld_w(3, 1, S_RA), enc.addi(4, 0, 0),  # r4=0 (stock @0x0e4374)
           enc.or_(5, OBJ_REG, OBJ_REG),              # r5=obj (stock @0x0e4378)
           enc.ld_w(6, 1, S_R6), enc.addi(1, 1, FRAME)]
    w_fast = pc(len(ws))
    ws[6] = enc.b_f(0x0A, pc(6), w_fast)             # не-дискриминатор -> fast
    ws += [enc.jump(w_fast, FN_A)]                   # W_FAST: tail-jump FN_A
    if len(ws) > ZONE_WORDS:
        raise ValueError(f"stub {len(ws)} words > zone {ZONE_WORDS}")
    total, wfast_idx = STUB_LAYOUT[version]
    if len(ws) != total or w_fast != STUB + 4 * wfast_idx:
        raise ValueError(f"stub v{version} layout drift: {len(ws)} words, "
                         f"W_FAST @0x{w_fast:x} (want {total}/0x{STUB + 4 * wfast_idx:x})")
    return ws


def trig_frames_v5q():
    """v5q (builder v22) TRIG frames: (mode A/B) x (F0/F40) = 4 frames.
    The mode is the frame word[4] hi-half (MODE_SLOT_V5Q, frame
    [0x10..0x12)): 0 -> A (the frame is BYTE-EXACT the v5n/v5o live
    frame), 1 -> B.  F is the p0 (w) parity: w even -> F = 0, w odd
    -> F = 0x40 (F = (w<<6) & 0x7F = (w&1)<<6; RE-a: F_EXACT = none,
    no FW validation on F -> the live T1/T2 P0_SAFE pair is reused).
    """
    import payload as pl
    w_f0, w_f40 = 0x00600000, 0x00600001
    frames = {}
    for mode, mhi in (("A", 0), ("B", 1)):
        for fname, w in (("F0", w_f0), ("F40", w_f40)):
            words = pl.payload_v5n(w)
            assert len(words) == pl.PAYLOAD_MAX_V5M
            b = bytearray(0x14)
            b[0:4] = struct.pack(">I", pl.OPCODE_V5B)
            b[0xC:0xE] = struct.pack(">H", len(words))
            b[0x10:0x12] = struct.pack(">H", mhi)
            b[0x12:0x14] = struct.pack(">H", pl.MAGIC16)
            frames[(mode, fname)] = bytes(b) + struct.pack(
                ">%dI" % len(words), *words)
    return frames


def trig_frames_v5r():
    """v5r (builder v23, C1 late stub) TRIG frames: (mode A/B) x
    (F0/F40) = 4 frames — IDENTICAL to the v5q (v22) frames: the mode
    is the frame word[4] hi-half (MODE_SLOT_V5Q), F is the p0 (w)
    parity.  The C1 change is in the STUB's exits (late point P,
    return-to-ra), not the frame: the v23 stub reads the same frame
    slots (filter [r1+0xaa], N [r1+0xa4], mode [r1+0xa8], p0
    [r1+0xac]) and executes the same payload p0..p3 in place.
    """
    return trig_frames_v5q()


def build_code(mode="A", version=4):
    src = BASE.read_bytes()
    if hashlib.md5(src).hexdigest() != BASE_MD5:
        raise ValueError("base patched3 md5 mismatch")
    img = mlxfwutil.Image(src, "s2-base")
    e = img.find_entry("ITOC", 0x03)
    raw = img.section_data(e)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    nlines = len(code) // 64
    if mlxfwutil.clcrc_wrap(code, tail) != raw:
        raise ValueError("de-clcrc round-trip failed (method drift?)")

    w = lambda b, a: struct.unpack_from(">I", b, a)[0]
    for a, want in STOCK_WORDS.items():
        if w(code, a) != want:
            raise ValueError(f"stock word @0x{a:x} is 0x{w(code, a):08x}, want 0x{want:08x}")
    if version == 16:
        # v5k rev.2 replica byte-exactness is CONSTRUCTION-verified: the
        # 10 words embedded in the stub must equal the fn 0x0e4250
        # epilogue words in THIS base image (any base drift fails loud)
        stock_epi = [w(code, EPILOGUE_REPLICA_SRC + 4 * i) for i in range(10)]
        if stock_epi != list(REPLICA_WORDS):
            raise ValueError(f"stock epilogue @0x{EPILOGUE_REPLICA_SRC:x} drifted: "
                             f"{['%08x' % x for x in stock_epi]}")
    if any(w(code, a) for a in range(GUARD_LO, STUB, 4)):
        raise ValueError("forbidden cut 0x38d748-0x38d74f not zero in stock")
    if any(w(code, a) for a in range(STUB, STUB + 4 * ZONE_WORDS, 4)):
        raise ValueError("stub zone 0x38d750-0x38d7d8 not all-zero in stock")
    if any(w(code, a) for a in range(FATAL_LO, FATAL_HI, 4)):
        raise ValueError("fatal zone 0x38d7dc-0x38dbe8 not all-zero in stock")
    s0_stock = [w(code, a) for a in range(S0_LO, GUARD_LO)]
    if not all(s0_stock):
        raise ValueError("S0 shellcode 0x38d730-0x38d747 missing in stock")

    words = stub_words(mode, version)
    if len(words) > ZONE_WORDS:
        raise ValueError(f"stub {len(words)} words > zone {ZONE_WORDS}")
    # the detour site: v5r (23) uses the LATE point P (the early
    # @DETOUR_DC stays stock — anti-confound, no two POSTs); every
    # other version uses the early @DETOUR_DC.
    detour_site = DETOUR_P if version == 23 else DETOUR_DC
    new_code = bytearray(code)
    new_code[detour_site:detour_site + 4] = struct.pack(">I", enc.call(detour_site, STUB))
    for i, word in enumerate(words):
        new_code[STUB + 4 * i:STUB + 4 * i + 4] = struct.pack(">I", word)
    new_code = bytes(new_code)

    if [w(new_code, a) for a in range(S0_LO, GUARD_LO)] != s0_stock:
        raise ValueError("S0 shellcode zone changed")
    if any(w(new_code, a) for a in range(GUARD_LO, STUB, 4)):
        raise ValueError("forbidden cut 0x38d748-0x38d74f touched")
    for a in range(STUB + 4 * ZONE_WORDS, FATAL_HI, 4):
        if w(new_code, a) != w(code, a):
            raise ValueError(f"guarded word @0x{a:x} changed")
    if w(new_code, detour_site) != enc.call(detour_site, STUB):
        raise ValueError("detour word mismatch")
    if version == 23:
        # the early detour must be RESTORED TO STOCK (anti-confound):
        if w(new_code, DETOUR_DC) != STOCK_WORDS[DETOUR_DC]:
            raise ValueError("v5r: early detour @DETOUR_DC not stock")

    new_raw = mlxfwutil.clcrc_wrap(new_code, tail)
    diff = [i for i in range(nlines)
            if raw[i * 68:(i + 1) * 68] != new_raw[i * 68:(i + 1) * 68]]
    exp = sorted({a // 64 for a in [detour_site] + [STUB + 4 * i for i in range(len(words))]})
    if diff != exp:
        raise ValueError(f"unexpected changed clcrc lines: {diff} != {exp}")

    edits = [(0x03, i * 68, new_raw[i * 68:(i + 1) * 68]) for i in diff]
    out = mlxfwutil.patch_sections(img, edits)

    pimg = mlxfwutil.Image(out, f"s2-core-v{version}", base=img.base, fmt=img.fmt)
    pe = pimg.find_entry("ITOC", 0x03)
    praw = pimg.section_data(pe)
    if praw != new_raw:
        raise ValueError("built section raw mismatch")
    if mlxfwutil.clcrc_wrap(*mlxfwutil.clcrc_unwrap(praw)) != praw:
        raise ValueError("per-line clcrc round-trip failed on built image")
    errs = mlxfwutil.verify_image(pimg, deep=True)
    if errs:
        raise ValueError(f"mlxfwutil verify --deep failed: {errs}")
    if w(mlxfwutil.clcrc_unwrap(praw)[0], 0x1D594) != 0x940DC067:
        raise ValueError("S0 injection word lost in built image")
    return out


def bake_guids(data, guid, mac):
    fmt, base = mlxfwutil.detect_format(data)
    if fmt != "fs4":
        raise ValueError(f"guids bake supports FS4 only (got {fmt})")
    img = mlxfwutil.Image(data, "s2-guides", base=base)
    buf = bytearray(img.buf)
    valid = mlxfwutil.find_valid_devinfo(img)
    if len(valid) > 1:
        raise ValueError(f"{len(valid)} valid mDevInfo sections; resolve manually")
    if valid:
        target = valid[0]
    else:
        cands = [e for e in img.entries("DTOC") if e.type == 0xE1]
        if not cands:
            raise ValueError("no DEV_INFO (0xE1) section in DTOC")
        target = min(cands, key=lambda e: e.addr)
    m = mlxfwutil.MDevInfo.parse(img.section_data(target))
    m.ensure_valid()
    new_di = m.write_uids(guid, mac)
    buf[target.addr:target.addr + target.size] = new_di[:target.size]
    e0 = img.find_entry("DTOC", 0xE0)
    e0d = bytearray(img.section_data(e0))
    e0d[mlxfwutil.MDEVINFO_UID_OFF:mlxfwutil.MDEVINFO_UID_OFF + 8] = guid.to_bytes(8, "big")
    e0d[mlxfwutil.MDEVINFO_MAC_OFF:mlxfwutil.MDEVINFO_MAC_OFF + 8] = mac.to_bytes(8, "big")
    buf[e0.addr:e0.addr + e0.size] = e0d
    if e0.crcf != 0:
        raise ValueError(f"MFG_INFO crcf={e0.crcf}: section CRC would go stale")
    sec_crc = mlxfwutil.crc16_mlx(bytes(e0d))
    ent_off = img.dtoc_off + 32 + e0.index * 32
    ent = bytearray(buf[ent_off:ent_off + 32])
    mlxfwutil.set_bits(ent, 208, 16, sec_crc)
    mlxfwutil.set_bits(ent, 240, 16, mlxfwutil.crc16_mlx(bytes(ent[:28])))
    buf[ent_off:ent_off + 32] = ent
    return bytes(buf)


def build_v2(mode="A"):
    return build_code(mode, 2)


def build(out_path, mode=None, version=4):
    # mode None => inferred from the version (v5m=18/v5n=19/v5o=20/
    # v5q=22/v5r=23 are the mode-B stubs; every other version is
    # mode A) so the CLI `OUT [VERSION]` works unchanged; an EXPLICIT
    # mode is validated by stub_words (mode "B" builds
    # v5m/v5n/v5o/v5q/v5r ONLY, mode "A" never builds 18/19/20/22/23).
    if mode is None:
        mode = "B" if version in (18, 19, 20, 22, 23) else "A"
    core = build_code(mode, version)
    out = bake_guids(core, CARD_GUID, CARD_MAC)

    vimg = mlxfwutil.Image(out, f"s2v{version}")
    errs = mlxfwutil.verify_image(vimg, deep=True)
    if errs:
        raise ValueError(f"mlxfwutil verify --deep failed: {errs}")
    valid = mlxfwutil.find_valid_devinfo(vimg)
    if len(valid) != 1:
        raise ValueError(f"expected exactly 1 valid mDevInfo section, got {len(valid)}")
    m = mlxfwutil.MDevInfo.parse(vimg.section_data(valid[0]))
    if (m.guid, m.mac) != (CARD_GUID, CARD_MAC) or not m.crc_ok():
        raise ValueError(f"DEV_INFO guid/mac mismatch after bake: 0x{m.guid:x}/0x{m.mac:x}")
    d0 = vimg.section_data(vimg.find_entry("DTOC", 0xE0))
    baked = (int.from_bytes(d0[mlxfwutil.MDEVINFO_UID_OFF:mlxfwutil.MDEVINFO_UID_OFF + 8], "big"),
             int.from_bytes(d0[mlxfwutil.MDEVINFO_MAC_OFF:mlxfwutil.MDEVINFO_MAC_OFF + 8], "big"))
    if baked != (CARD_GUID, CARD_MAC):
        raise ValueError("MFG_INFO guid/mac mismatch after bake")
    cimg = mlxfwutil.Image(core, f"s2-core-v{version}")
    if vimg.section_data(vimg.find_entry("ITOC", 0x03)) != cimg.section_data(cimg.find_entry("ITOC", 0x03)):
        raise ValueError("guids bake touched ITOC 0x03 (code section)")

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(out)

    if shutil.which("mstflint"):
        r = subprocess.run(["mstflint", "-i", str(out_path), "verify"],
                           capture_output=True, text=True)
        if "bootable" not in r.stdout:
            raise ValueError(f"mstflint verify: {r.stdout}")
        print("mstflint verify: PASS (bootable)")
    else:
        print("mstflint not found - SKIPPED (md5 round-trip is the rebuild check)")
    print("md5", hashlib.md5(out).hexdigest(), "size", len(out), "->", out_path)
    return out


if __name__ == "__main__":
    argv = sys.argv[1:]
    out = argv[0] if argv else "/tmp/opencode/s2/4030-cda-s2-v4.bin"
    version = int(argv[1], 0) if len(argv) > 1 else 4
    build(out, version=version)
