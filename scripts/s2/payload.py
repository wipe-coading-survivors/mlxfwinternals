#!/usr/bin/env python3
"""S2 payload toolkit: marker codegen + host-side input-block builder (spec 3.5).

Input block v2 (BE words): [0]=MAGIC, [1]=N, [2]=r5-init, [3]=r6-init,
[4..4+N)=payload code.  The stub v2 (build_s2.py, mode A) copies the code onto
the stack and enters it with r4=result buffer, r5/r6 from the header; payload
exits via `ret.r zero,zero,r3` (resume PC set by the stub).  Payloads must
not use `call` (no valid frame) and must not write r4 (result-buffer pointer).

IN_SIZE=0x24 strictly-clean host bytes (T2) => PAYLOAD_MAX = 20 (5 words).
Marker v2 (ruling R7, exactly 5 words): S2OK=0x53324F4B -> CR 0x2388 (gate G5),
r5 -> CR 0x238c; r6 write dropped (budget).  input_block() enforces the
fail-loud host contract (ruling R8): N in [1..5] (stub copy loop is do-while;
N>5 overwrites the stub's own result buffer), words and r5/r6 are u32.

Input block v4 (task-09/task-10): [0]=opcode word 0x09320000 (fixed — the
dispatcher routes on bytes 09 32), [4..8)=0 (validator G5/G6/G7 demand
H=0/L=0 on input[4..8)), [8..0xC)=DISCRIM32=0x0432434D (stub filter),
[0xC..0x10)=N, [0x10..0x14)=r5-init, [0x14..0x14+4N)=code.  The v4 header
carries no r6 slot (r6 keeps its call-site value).  Code window is 16B =>
PAYLOAD_MAX_V4=4 words; marker_lite() (gate G5' for T11) drops the r5 echo
to fit exactly 4 words.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts" / "irisc"))

import enc  # noqa: E402

MAGIC = 0x5332434D
S2OK = 0x53324F4B
CR_S2OK, CR_R5 = 0x2388, 0x238C
IN_SIZE = 0x24
PAYLOAD_MAX = IN_SIZE - 16
DISCRIM32 = 0x0432434D
OPCODE_V4 = 0x09320000
PAYLOAD_MAX_V4 = 4
MAGIC16 = 0x5332                       # v5b filter: input[0x12..0x14) BE halfword
GAUNTLET_HI = 0x2407                   # hi halfword of marker-lite word[0] 0x24075332
OPCODE_V5B = OPCODE_V4
PAYLOAD_MAX_V5B = 4
FN_A_V5J = 0x18D964                    # stock BadParam completion, FILE offset (== build_s2 FN_A)
PC_BASE_V5J = 0x800000                 # live PC = file offset + 0x800000
FN_A_LIVE_V5J = PC_BASE_V5J + FN_A_V5J  # 0x98D964: the p3 jump target in LIVE space (rev.2)
R1_DEFAULT_V5J = 0x7D1FF8              # SP-init top-of-stack, cpu0 (task-30 Q1)
R1_MIN_V5J, R1_MAX_V5J = 0x7D1FF8, 0x7FFFF8   # stack-base range: SP-init cpu0..cpu14
P3_PC_OFF_V5J = 0xB8                   # p3 @k=0x20 -> live PC = r1+0x98+0x20 (rev.2)
PAYLOAD_MAX_V5J = 4
PAYLOAD_MAX_V5K = 4
# v5k rev.2 note: the [r1+4]-as-dispatch-ra constant of rev.1
# (DISPATCH_RA_LIVE_V5K = 0x8E42BC) is DELETED — the T33 review
# disproved the model: at detour time r1 = R-0xf8 (the fn frame is
# pushed), so [r1+4] is the INNER slot (nested-call resume residue,
# 0x8E435C — the livelock value), while the TRUE dispatcher ra lives
# at the OUTER [R+4] (the fn prologue store @0x0e4254); the rev.2
# exit goes through the stub-side epilogue replica, which pops first
# and reads [R+4] (see build_s2.REPLICA_WORDS).
PAYLOAD_MAX_V5L = 4
# v5l (task-34): the exit returns INTO the fn body at the CALL-SITE
# RESUME — r3 = 0x008E4380 = PC_BASE + DETOUR_DC + 4 (the value
# csr0xbc holds at detour entry; the value stock FN_A returns
# through: FN_A's own prologue `csr.r r3,csr0xbc' @0x18d964).  The
# fn body then marshals r4 (`or r19,r4,r4' @0x0E4380 — r4=0, the
# v5i-documented stock arg value), builds the QUERY completion and
# reaches its OWN epilogue — stock completion.  See
# build_s2.stub_words(version=17) for the stub-side r3 preload.
PAYLOAD_MAX_V5M = 4
# v5m (task-02 s2b, mode "B"): the payload words are UNCHANGED v5l
# (Task-1 verdict: "Payload — 4 слова без изменений"); mode B lives
# entirely in the burnt STUB (the m2 WRITE-POST block calls
# 0x18064c(r4=0, r5=obj, r6=C, r7=buf) BEFORE the transfer — see
# build_s2.stub_words(mode="B", version=18)).  The POST buf r1+0xb0
# exfils input[0x18..0x58) = p1..p3 + stack tail as PRISTINE TRIG
# bytes (the payload executes only AFTER the call; S2OK goes to CR
# space, never to buf); the key C = [r1+0xac]|0xff = p0|0xff =
# 0x200C4FFF (documented for the Task-3 live gate: the tool buffer
# scan looks for the p1..p3 marker bytes; no marker in tool memory
# => STOP, no blind retries).


def _check_u32(value, what):
    assert isinstance(value, int) and 0 <= value <= 0xFFFFFFFF, \
        f"{what}={value!r} does not fit u32"


def marker(r5, r6):
    _check_u32(r5, "r5")
    _check_u32(r6, "r6")
    return [
        enc.set2(7, S2OK >> 16),
        enc.set3(7, 7, S2OK & 0xFFFF),
        enc.st_d(7, 0, CR_S2OK),
        enc.st_d(5, 0, CR_R5),
        enc.ret_r(0, 0, 3),
    ]


def input_block(words, r5, r6):
    n = len(words)
    assert 1 <= n <= PAYLOAD_MAX // 4, \
        f"payload length N={n} outside 1..{PAYLOAD_MAX // 4} " \
        f"(stub copy loop is do-while: N=0 still copies 1 word, " \
        f"N>5 overwrites the stub result buffer)"
    for i, w in enumerate(words):
        assert isinstance(w, int) and 0 <= w <= 0xFFFFFFFF, \
            f"word[{i}]={w!r} does not fit u32"
    _check_u32(r5, "r5")
    _check_u32(r6, "r6")
    return struct.pack(">4I", MAGIC, n, r5, r6) + struct.pack(f">{n}I", *words)


def marker_lite():
    return [
        enc.set2(7, S2OK >> 16),
        enc.set3(7, 7, S2OK & 0xFFFF),
        enc.st_d(7, 0, CR_S2OK),
        enc.ret_r(0, 0, 3),
    ]


def input_block_v4(words, r5):
    n = len(words)
    assert 1 <= n <= PAYLOAD_MAX_V4, \
        f"payload length N={n} outside 1..{PAYLOAD_MAX_V4} " \
        f"(v4 code window input[0x14..0x24), strictly-clean IN_SIZE=0x24)"
    for i, w in enumerate(words):
        assert isinstance(w, int) and 0 <= w <= 0xFFFFFFFF, \
            f"word[{i}]={w!r} does not fit u32"
    _check_u32(r5, "r5")
    return struct.pack(">5I", OPCODE_V4, 0, DISCRIM32, n, r5) \
        + struct.pack(f">{n}I", *words)


def input_block_v5b(words):
    """v5b host-side input block (T17-proven filter slot).

    Layout (36B strictly-clean window): [0..4)=0x09320000 opcode word (the
    dispatcher routes on bytes 09 32), [4..8)=0 (validator gates G5/G6/G7),
    [8..0xC)=0 (TT=0 class + tn=0 — tn-bearing inputs die at the pre-handler
    validator BEFORE the detour, T17 Step 6), [0xC..0xE)=N (16-bit BE, word
    count), [0xE..0x12)=0, [0x12..0x14)=MAGIC16 bytes 53 32 (LIVE-PROVEN
    filter slot [r1+0xaa]), [0x14..0x14+4N)=code.  Fail-loud (ruling R8):
    N==len(words) in [1..4] (stub copy loop is do-while: N=0 still copies 1
    word; N>4 overflows the 16B code window), words are u32.
    """
    n = len(words)
    assert 1 <= n <= PAYLOAD_MAX_V5B, \
        f"payload length N={n} outside 1..{PAYLOAD_MAX_V5B} " \
        f"(v5b code window input[0x14..0x24), strictly-clean IN_SIZE=0x24)"
    for i, w in enumerate(words):
        assert isinstance(w, int) and 0 <= w <= 0xFFFFFFFF, \
            f"word[{i}]={w!r} does not fit u32"
    b = bytearray(0x14)
    b[0:4] = struct.pack(">I", OPCODE_V5B)
    b[0xC:0xE] = struct.pack(">H", n)
    b[0x12:0x14] = struct.pack(">H", MAGIC16)
    return bytes(b) + struct.pack(f">{n}I", *words)


def _set2(rd, rs, imm):
    return (0x09 << 26) | (rs << 21) | (rd << 16) | (imm & 0xffff)


def payload_v5j(landing_r1=R1_DEFAULT_V5J):
    """v5j rev.2 (Exit-C, T32-review redesign) exec-from-input payload:
    4 words that EXECUTE IN-PLACE from the landing zone [r1+0xac..0xbc)
    — frame 36B (0x14 header + 4 words), the STANDARD neg-frame size,
    fully inside the T2 strictly-clean window (last byte k=0x23; window
    ceiling 0x38) — NO corruption-zone exposure (review Important-3).

    p0 `set3 r12,r12,0x4f4b` inserts the LO half, p1 `set2 r12,r12,
    0x5332` the HI half (slaspec insert semantics — the v2-marker
    hi/lo idiom, rd remapped to r12) => r12 = 0x53324F4B
    DETERMINISTICALLY.  p2 `st.d r12,zero,0x2388` writes S2OK (gate
    G5; the v5a-live probe word) — the FULL C1 signal, self-validating
    (rev.2 DROPS the rev.1 landing-echo st.d: no run-#1 measurement,
    S2OK suffices).  p3 = `jump` to the LIVE FN_A 0x0098D964 (= file
    0x18D964 + PC_BASE 0x800000 — review Critical-1: the payload runs
    at live stack PCs; the rev.1 file-space target landed 0x800000
    low) from live PC r1+0xb8 (k=0x20 => r1+0x98+0x20).

    Exit semantics (Exit-C): p3 -> FN_A ret.d -> csr0xbc = the
    PRE-DETOUR ra (the w10 transfer is the rs=8 computed-jr class —
    NO LINK; nothing on the path writes csr0xbc) -> stock return into
    the dispatcher — the SAME completion every v5-series clean run
    took live.

    p3 is POSITION-DEPENDENT on the assumed stack base (never measured
    live; SP-init 0x7d1ff8 + (cpuinfo&0xf)<<13 minus call-chain
    depth): the immediate is built for `landing_r1`.  Fail-loud
    (ruling R8): landing_r1 is u32, 4-aligned (the jump encoding needs
    whole-word steps), and the s24 immediate must fit — it does for
    EVERY stack base 0x7d1ff8..0x7ffff8 (worst-case imm 0x6ee2d at
    the smallest base; s24 margin 0x7911d2 words — asserted by the
    rev.2 tests over the full base sweep).
    """
    assert isinstance(landing_r1, int) and 0 < landing_r1 <= 0xFFFFFFFF, \
        f"landing_r1={landing_r1!r} does not fit u32"
    assert landing_r1 & 3 == 0, \
        f"landing_r1=0x{landing_r1:x} not 4-aligned (jump needs word steps)"
    pc = landing_r1 + P3_PC_OFF_V5J
    diff = FN_A_LIVE_V5J - pc
    assert diff % 4 == 0 and -0x800000 <= diff // 4 <= 0x7FFFFF, \
        f"p3 jump imm 0x{diff // 4:x} (base 0x{landing_r1:x}) does not fit s24"
    return [
        enc.set3(12, 12, 0x4F4B),                    # p0: lo16 insert
        _set2(12, 12, 0x5332),                       # p1: hi16 insert -> S2OK
        enc.st_d(12, 0, CR_S2OK),                    # p2: S2OK gate G5
        enc.jump(pc, FN_A_LIVE_V5J),                 # p3: exit to LIVE FN_A
    ]


def input_block_v5j(landing_r1=R1_DEFAULT_V5J):
    """v5j rev.2 exec-from-input host frame (36B, neg-shape with the
    payload at k=0x14..0x24 — the STANDARD neg-frame size).

    Layout: [0..4)=0x09320000 opcode word, [4..0xC)=0 (validator
    gates), [0xC..0xE)=N=PAYLOAD_MAX_V5J (BE16; ECHOED to 0x2384 and
    NEVER used for control — the v5j stub has no N-guard and no
    gauntlet), [0xE..0x12)=0, [0x12..0x14)=MAGIC16 bytes 53 32
    (live-proven filter slot [r1+0xaa]), [0x14..0x24)=the 4 payload
    words (payload_v5j).  The whole frame sits inside the T2
    strictly-clean window (nothing at k>=0x24; transfer window ceiling
    0x38) — the rev.1 40B novelty is gone (review Important-3 moot).
    v5j accepts exactly ONE magic frame shape: the full TRIG (every
    magic frame transfers into the landing — the lineage's 24B echo /
    28-32B neg frames are NOT valid v5j inputs).
    """
    words = payload_v5j(landing_r1)
    assert len(words) == PAYLOAD_MAX_V5J
    b = bytearray(0x14)
    b[0:4] = struct.pack(">I", OPCODE_V5B)
    b[0xC:0xE] = struct.pack(">H", len(words))
    b[0x12:0x14] = struct.pack(">H", MAGIC16)
    return bytes(b) + struct.pack(">%dI" % len(words), *words)


def payload_v5k():
    """v5k rev.2 (T33-review 40d902a fix) exec-from-input payload: 4
    words that EXECUTE IN-PLACE from the landing zone [r1+0xac..0xbc)
    — frame 36B (0x14 header + 4 words), the STANDARD neg-frame size,
    fully inside the T2 strictly-clean window (last byte k=0x23).

    Fix 1 (exact S2OK construction — the live ROOT-CAUSE of the v5j
    lo16 anomaly, journal task-32 phase-2: set3 ORs imm into the
    SOURCE's lo16 when building, so the v5j p0 `set3 r12,r12,0x4f4b`
    produced 0x5332|0x4F4B = 0x5F7B — the observed CR 0x2388 value
    EXACTLY): p0 = `set3 r12,ZERO,0x4f4b` — rs=zero gives lo16 =
    0x0000|0x4F4B CLEAN under BOTH the insert (slaspec) and the OR
    (live) semantics, from ANY incoming r12 (the 0x5332 filter
    residue included); the v5i-neutral-write live class (set3 r12,
    zero,* + st.d ran clean x4 images; class set3 rs=zero stock
    x7348).  p1 = `set2 r12,r12,0x5332` UNCHANGED — the live-exact
    v5j word (the hi half landed 0x5332 EXACTLY live; post-p0 the
    hi16 is 0, so insert and OR agree here too) => r12 = 0x53324F4B
    DETERMINISTIC.  p2 `st.d r12,zero,0x2388` writes S2OK (gate G5;
    the v5a-live probe word) — the FULL C1 signal, self-validating.

    Fix 2 (rev.2 — stub-side epilogue replica; UNCHANGED WORDS): p3
    = `ret.r zero,r8,r3` (0xFD001825, THE canonical return word —
    stock x8346, byte-exact fn 0x0e4250's own final word @0x0e430c)
    — exits THROUGH r3, which the STUB's w10/w11 preloaded with the
    ABSOLUTE live address of the replica block (the stub zone is
    absolute space — base-independent by construction; the payload
    words never touch r3, so the preload survives to p3).  The
    replica (stub w13-w22, build_s2.REPLICA_WORDS) executes the
    fn's own epilogue: restores r17-r23 from [r1+0xdc..0xf4], pops
    the 0xf8 frame, reads the OUTER [R+4] (the dispatcher ra the fn
    prologue saved @0x0e4254 BEFORE the push) and returns — the
    rev.1 livelock (inner-residue re-entry, review Critical-1) and
    the r17-r23 leak (Important-2) are both GONE by design.  NO word
    of the payload encodes ANY stack absolute: ONE frame serves
    EVERY SP base.  Residual (accepted, coordinator note):
    FN_A-skip — the exit skips FN_A and the post-detour marshalling
    (r4 is 0 at the detour via the stock arg setup @0x0e4374, the
    same value the epilogue would marshal); the C1 signal is
    written BEFORE p3, so a derailed exit cannot mask it.
    """
    return [
        enc.set3(12, 0, 0x4F4B),                    # p0: lo16 CLEAN (rs=zero)
        _set2(12, 12, 0x5332),                      # p1: hi16 insert -> S2OK
        enc.st_d(12, 0, CR_S2OK),                   # p2: S2OK gate G5
        enc.ret_r(8, 0, 3),                         # p3: exit INTO the replica
    ]


def input_block_v5k():
    """v5k (Exit-D, T33) exec-from-input host frame (36B, neg-shape
    with the payload at k=0x14..0x24 — the STANDARD neg-frame size).

    Layout: [0..4)=0x09320000 opcode word, [4..0xC)=0 (validator
    gates), [0xC..0xE)=N=PAYLOAD_MAX_V5K (BE16; ECHOED to 0x2384 and
    NEVER used for control — the v5k stub has no N-guard and no
    gauntlet), [0xE..0x12)=0, [0x12..0x14)=MAGIC16 bytes 53 32
    (live-proven filter slot [r1+0xaa]), [0x14..0x24)=the 4 payload
    words (payload_v5k).  The whole frame sits inside the T2
    strictly-clean window (nothing at k>=0x24).  v5k accepts exactly
    ONE magic frame shape: the full TRIG (every magic frame transfers
    into the landing — the lineage's 24B echo / 28-32B neg frames
    are NOT valid v5k inputs).  THE v5k novelty: NO base parameter —
    the frame is base-independent (the same 36 bytes at every SP
    base 0x7d1ff8..0x7efff8 and anywhere else).
    """
    words = payload_v5k()
    assert len(words) == PAYLOAD_MAX_V5K
    b = bytearray(0x14)
    b[0:4] = struct.pack(">I", OPCODE_V5B)
    b[0xC:0xE] = struct.pack(">H", len(words))
    b[0x12:0x14] = struct.pack(">H", MAGIC16)
    return bytes(b) + struct.pack(">%dI" % len(words), *words)


def payload_v5l():
    """v5l (task-34, journal task-33 phase-2 grounding) exec-from-input
    payload: 4 words — THE SAME WORDS AS v5k (Fix 1 exact-S2OK build,
    live-PROVEN 4/4 executed with CR 0x2388 = 0x53324F4B EXACT in the
    task-33 phase-2 run), NEW EXIT SEMANTICS.

    p0 = `set3 r12,ZERO,0x4f4b` (rs=zero — lo16 CLEAN under BOTH
    insert and OR semantics, from ANY incoming r12; the live
    root-caused v5j anomaly 0x5332|0x4F4B = 0x5F7B eliminated).
    p1 = `set2 r12,r12,0x5332` (hi16 insert, live-exact) =>
    r12 = 0x53324F4B deterministically.  p2 = `st.d r12,zero,0x2388`
    writes S2OK (gate G5) — the FULL C1 signal, self-validating (the
    v5k live run proved it lands EXACT).

    p3 = `ret.r zero,r8,r3` (0xFD001825, THE canonical return word —
    stock x8346, byte-exact fn 0x0e4250's own final word @0x0e430c) —
    exits THROUGH r3, which the v5l STUB's w10/w11 preloaded with
    0x008E4380 = THE CALL-SITE RESUME (live = file 0x0E437C detour
    call + 4; the value csr0xbc holds at detour entry; the value
    stock FN_A returns through — FN_A's own prologue `csr.r
    r3,csr0xbc' @0x18d964 is byte-exact the stub's w0).  The payload
    RETURNS INTO THE FN BODY at the resume point, as FN_A's return
    would: the body marshals r4 (`or r19,r4,r4' @0x0E4380; our r4=0
    — the v5i-documented stock arg value `addi r4,zero,0' @0x0E4374),
    branches on it (`subsi r4,r19,0x0` + `b.f.0x0 ->0x8E42E4` early
    exit vs the 0x0E438C+ QUERY path), builds the QUERY completion
    and reaches its OWN epilogue (the r17-r23 restores + the 0xf8 pop
    + the outer-[R+4] return the v5k replica tried to synthesize —
    now executed by the fn's own words on HW) — STOCK COMPLETION.
    The payload never touches r3 (the preload survives to p3); NO
    word encodes ANY stack absolute — base-independent by
    construction (ONE frame serves EVERY SP base; the exit target is
    the ABSOLUTE resume, also base-independent).
    """
    return [
        enc.set3(12, 0, 0x4F4B),                    # p0: lo16 CLEAN (rs=zero)
        _set2(12, 12, 0x5332),                      # p1: hi16 insert -> S2OK
        enc.st_d(12, 0, CR_S2OK),                   # p2: S2OK gate G5
        enc.ret_r(8, 0, 3),                         # p3: exit INTO the fn body
    ]


def input_block_v5l():
    """v5l (task-34) exec-from-input host frame (36B, neg-shape with
    the payload at k=0x14..0x24 — the STANDARD neg-frame size).

    Layout: [0..4)=0x09320000 opcode word, [4..0xC)=0 (validator
    gates), [0xC..0xE)=N=PAYLOAD_MAX_V5L (BE16; ECHOED to 0x2384 and
    NEVER used for control — the v5l stub has no N-guard and no
    gauntlet), [0xE..0x12)=0, [0x12..0x14)=MAGIC16 bytes 53 32
    (live-proven filter slot [r1+0xaa]), [0x14..0x24)=the 4 payload
    words (payload_v5l).  The whole frame sits inside the T2
    strictly-clean window (nothing at k>=0x24).  v5l accepts exactly
    ONE magic frame shape: the full TRIG (every magic frame transfers
    into the landing).  The frame BYTES are IDENTICAL to the v5k TRIG
    (the same 4 payload words; the live-proven v5k delivery carries
    over unchanged — only the burnt stub differs): ONE fixed frame
    for ALL SP bases, no base parameter.
    """
    words = payload_v5l()
    assert len(words) == PAYLOAD_MAX_V5L
    b = bytearray(0x14)
    b[0:4] = struct.pack(">I", OPCODE_V5B)
    b[0xC:0xE] = struct.pack(">H", len(words))
    b[0x12:0x14] = struct.pack(">H", MAGIC16)
    return bytes(b) + struct.pack(">%dI" % len(words), *words)


def payload_v5m():
    """v5m (task-02 s2b, mode "B") exec-from-input payload: 4 words —
    THE UNCHANGED v5l WORD LIST (Task-1 verdict: the mode-B difference
    lives entirely in the burnt STUB's m2 WRITE-POST block, which
    runs BEFORE the transfer).

    p0 `set3 r12,ZERO,0x4f4b' + p1 `set2 r12,r12,0x5332' build
    r12 = 0x53324F4B deterministically (the live-proven v5k/v5l
    exact-S2OK build); p2 `st.d r12,zero,0x2388' writes S2OK (gate
    G5 — the C1 signal); p3 `ret.r zero,r8,r3' (0xFD001825, the
    canonical return, stock x8346) returns THROUGH r3, which the v5m
    STUB's w17/w18 preloaded with 0x008E4380 = THE CALL-SITE RESUME
    (== v5l's w10/w11 — the payload RETURNS INTO THE FN BODY, stock
    completion).  The payload never touches r3; NO word encodes ANY
    stack absolute — base-independent by construction.

    Mode-B note: the m2 POST (stub w14) fires BEFORE these words
    execute, so the exfil'd buf [r1+0xb0..0xf0) = input[0x18..0x58)
    carries p1..p3 as PRISTINE TRIG bytes; the key C = p0|0xff =
    0x200C4FFF (the Task-3 live-gate marker protocol constant).
    """
    return [
        enc.set3(12, 0, 0x4F4B),                    # p0: lo16 CLEAN (rs=zero)
        _set2(12, 12, 0x5332),                      # p1: hi16 insert -> S2OK
        enc.st_d(12, 0, CR_S2OK),                   # p2: S2OK gate G5
        enc.ret_r(8, 0, 3),                         # p3: exit INTO the fn body
    ]


def input_block_v5m():
    """v5m (task-02 s2b, mode "B") exec-from-input host frame (36B,
    neg-shape with the payload at k=0x14..0x24 — the STANDARD
    neg-frame size).

    Layout: [0..4)=0x09320000 opcode word, [4..0xC)=0 (validator
    gates), [0xC..0xE)=N=PAYLOAD_MAX_V5M (BE16; ECHOED to 0x2384 and
    NEVER used for control), [0xE..0x12)=0, [0x12..0x14)=MAGIC16
    bytes 53 32 (live-proven filter slot [r1+0xaa]), [0x14..0x24)=
    the 4 payload words (payload_v5m).  The whole frame sits inside
    the T2 strictly-clean window (nothing at k>=0x24).  The frame
    BYTES are IDENTICAL to the v5l TRIG (the same 4 payload words —
    the live-proven v5l delivery carries over; only the burnt stub
    differs): v5m accepts exactly ONE magic frame shape — the full
    36B TRIG (every magic frame POSTs AND transfers into the
    landing).  ONE fixed frame for ALL SP bases, no base parameter.
    """
    words = payload_v5m()
    assert len(words) == PAYLOAD_MAX_V5M
    b = bytearray(0x14)
    b[0:4] = struct.pack(">I", OPCODE_V5B)
    b[0xC:0xE] = struct.pack(">H", len(words))
    b[0x12:0x14] = struct.pack(">H", MAGIC16)
    return bytes(b) + struct.pack(">%dI" % len(words), *words)


V5N_W_CANDIDATES = {"out_mb0": 0x428B90, "in_mb0": 0x428B80, "cqe": 0x400000}


def payload_v5n(w=V5N_W_CANDIDATES["out_mb0"]):
    """v5n (plan-2 s2b2, mode "B" — m2' X1-from-p0): 4 words with
    p0 = w (DATA, not code) and p1..p3 = the v5m marker VERBATIM
    (the delivery target: the S2OK build + the fn-body return).

    w is the X1 base: w = IOVA>>6 of the output mailbox, and the
    v5n STUB's m2' block builds X1 = (0x8FC0<<32)|(w<<6) from it
    (ld.d r4,r1,0xac = zext32(p0) -> shl64.i r4,r4,6 -> set1
    r4,r4,0x8fc0) and calls the DIRECT transport 0x2ae98
    (r4=X1, r5=r1+0xb0, r6=0) BEFORE the transfer.  The transfer
    (ret.r zero,r8,r11) then executes p0..p3 IN-PLACE: p0 decodes
    to a HARMLESS addi (op 0x00, rd/rs in {0,2} — T1 P0_SAFE: r2
    is caller-saved, the post-resume body has ZERO r2 uses; the
    cqe candidate leaves r2 alone), p1..p3 land S2OK and return
    into the fn body through the stub-built r3 = 0x008E4380.

    Fail-loud (ruling R8): w is in (0, 0x4000000) (p0 must decode
    to op 0x00) and must not decode to an r1 touch (rd/rs != 1 —
    the stack pointer is NEVER written).
    """
    assert isinstance(w, int) and 0 < w < 0x4000000, \
        f"w={w!r} outside (0, 0x4000000): p0 must decode to op 0x00 addi"
    assert (w >> 16) & 0x1F != 1 and (w >> 21) & 0x1F != 1, \
        f"w=0x{w:x} decodes to an r1 touch (rd/rs = 1)"
    vm = payload_v5m()
    return [w] + vm[1:]


def trig_v5n(w=V5N_W_CANDIDATES["out_mb0"]):
    """v5n (plan-2 s2b2) TRIG frame (36B, the standard neg-frame
    size): [0..4)=0x09320000 opcode, [4..0xC)=0 (validator gates),
    [0xC..0xE)=N=4 (BE16; ECHOED to 0x2384), [0xE..0x12)=0,
    [0x12..0x14)=MAGIC16 bytes 53 32 (the live-proven filter slot),
    [0x14..0x24)=payload_v5n(w).  The whole frame sits inside the
    strictly-clean window (last byte k=0x23).  ONE fixed frame
    shape per w; no base parameter.
    """
    words = payload_v5n(w)
    assert len(words) == PAYLOAD_MAX_V5M
    b = bytearray(0x14)
    b[0:4] = struct.pack(">I", OPCODE_V5B)
    b[0xC:0xE] = struct.pack(">H", len(words))
    b[0x12:0x14] = struct.pack(">H", MAGIC16)
    return bytes(b) + struct.pack(">%dI" % len(words), *words)


if __name__ == "__main__":
    import irisc_dis
    for i, w in enumerate(marker(1, 2)):
        print(f"{i:2d} {w:08x}  {irisc_dis.dis(w, 0)}")
    print(input_block(marker(1, 2), 1, 2).hex())
    for i, w in enumerate(marker_lite()):
        print(f"{i:2d} {w:08x}  {irisc_dis.dis(w, 0)}")
    print(input_block_v4(marker_lite(), 1).hex())
    print(input_block_v5b(marker_lite()).hex())
    for i, w in enumerate(payload_v5j()):
        print(f"p{i} {w:08x}  {irisc_dis.dis(w, 0 if i < 3 else R1_DEFAULT_V5J + P3_PC_OFF_V5J)}")
    print(input_block_v5j().hex())
    for i, w in enumerate(payload_v5k()):
        print(f"q{i} {w:08x}  {irisc_dis.dis(w, 0)}")
    print(input_block_v5k().hex())
    for i, w in enumerate(payload_v5l()):
        print(f"r{i} {w:08x}  {irisc_dis.dis(w, 0)}")
    print(input_block_v5l().hex())
    for i, w in enumerate(payload_v5m()):
        print(f"m{i} {w:08x}  {irisc_dis.dis(w, 0)}")
    print(input_block_v5m().hex())
    for i, w in enumerate(payload_v5n()):
        print(f"n{i} {w:08x}  {irisc_dis.dis(w, 0)}")
    print(trig_v5n().hex())
