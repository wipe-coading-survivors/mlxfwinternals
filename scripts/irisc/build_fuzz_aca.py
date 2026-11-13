#!/usr/bin/env python3
"""ACA8008 fuzz image builder: boot-call detour + CR marker + cmp36 probes.

Image under test: stock MCX512A-ACA 16.35.8008 (sacrificial card, Task 4
live-HW burn).  The built image keeps stock DEV_INFO/MFG_INFO PSID — only
MAIN_CODE (ITOC 0x03) words change; fuzz-2 additionally injects the card
GUID/MAC (Constraint fix for the zero-MAC netdev seen in task-04).

Layout (task-02 verdict + docs/250-re/120-irisc/025-boot-injection.md S0 playbook):
  - injection  dc 0x1d5b8: stock `call 0x1e130` (0x940002DE) ->
    `call 0x38e2c0` (0x940DC342); 0x1d5bc dead self-jump stays stock;
  - shellcode  dc 0x38e2c0.. (safe prefix of the primary cave, 42 words):
    marker 0xbadc0001 -> CR 0x23f0 (liveness), then probes -> CR slots,
    then `jump 0x1e130` (resume main-init).

fuzz-1 (build(), bit-exact with the task-04 burned image):
  V1  eq32  5 vs 5   lo11=2 -> taken     -> code 0xB0
  V2  eq32  5 vs 3   lo11=5 -> not-taken -> code 0xB1
  V5  ugt32 0xFFFFFFFF vs 0 lo11=2 -> taken -> code 0xB0
Outcome codes are set2-loaded into the high half, so slot words read
0x00B00000 (taken) / 0x00B10000 (not-taken) / 0 (store never reached;
docs/250-re/120-irisc/025-boot-injection.md channel).

fuzz-2 (build_fuzz2(), task-05 §4.5 design): closes the fuzz-1
methodological gap — no known-taken control existed.
  C1  0x2390  subsi r5,r5,0; b.t.cc0 — known-taken control on the
      algorithmically verified SHA semantics (I2-b): must read 1;
  C2  0x2394  V1 operands bit-exact + b.f.cc0a — polarity/latch control;
  P1  0x2380  op36 sel=gt32, 5 vs 3 (I2-a V4 word);
  P2  0x2384  op38 sel=eq32, 1<<32 vs 0 (I2-a V8 word);
  P3  0x2388  op36 minimal form: sel=0, rs==rt, lo11=0.
Outcome convention (new, unified): slot = 1 (taken) / 2 (not-taken) /
0 (store never reached) — addi-loaded full 32-bit values, no set2
high-half codes.  Blocks ordered by ascending CR slot (task-03 §5
spillover rule); cmp->branch distance = 1 word everywhere.

Registers: r5/r6 scratch only (S0 evidence: main-init needs r1/r3/r4/r23).
Stores: st.d rt, zero, off — base-zero absolute form; the FW itself emits it
for low RAM/CR slots (offsets up to 0x35ec seen in stock MAIN_CODE), and
r0 provably reads 0 in the boot-entry context (SP-init uses `set2 ..,zero`).

GUID/MAC injection (fuzz-2+): card values from the task-04 journal
(mstflint q pre-burn) go into DEV_INFO (MDevInfo.write_uids: guid@0x28,
mac@0x38 + INSECTION CRC) and MFG_INFO (guid/mac copy, sec/entry CRC when
crcf=0) — the FS4 path of mlxfwutil cmd_guides.  Task 7: mstflint 4.36.0
f3a3dab rejects --use_image_guids (FS2-only, source-verified); the
in-image injection survives the plain fuzz-1-flag burn end-to-end
(post-burn netdev MAC = card MAC from hw registry CARD_CX5_25G).

CRC fixup: per-line clcrc over changed 68B lines + mlxfwutil.patch_sections
(section crc16_mlx + ITOC entry CRC, mstflint-authoritative).
"""
import hashlib
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "irisc"))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import mlxfwutil  # noqa: E402
import enc  # noqa: E402
from iron_boot_probe import decrc  # noqa: E402

IMG_PATH = REPO / "refs" / "fw" / "cx-5-6" / (
    "fw-ConnectX5-rel-16_35_8008-MCX512A-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin")
IMG_MD5 = "7dce14844bb0aad995f9c4379836e0b7"
INJ_DC = 0x1D5B8            # entry chain: call main-init (stock 0x940002DE)
INJ_STOCK = 0x940002DE
INJ_DEAD = 0x95000000       # 0x1d5bc self-jump: stays stock, never touched
RESUME = 0x1E130            # main-init
SC = 0x38E2C0               # shellcode cave prefix start
SC_WORDS = 42               # safe zone 0x38e2c0..0x38e367 (0xa8 B, task-02)
MARKER = 0xBADC0001         # liveness marker (S0 value)
MARKER_SLOT = 0x23F0        # host-CR device-unlock slot (docs/250-re/120-irisc/025-boot-injection.md)
TAKEN = 0xB0                # probe outcome codes; 0 = store never reached
NOT_TAKEN = 0xB1
CC_CMP = 0x0A               # b.t/b.f cc for the 0x36/0x38 compare latch

# (vec1, vec2, sel, lo11, slot) — I2-a §7 vectors V1/V2/V5 verbatim
PROBES = (
    (5, 5, 0x00, 2, 0x2380),            # V1: eq32, expect taken
    (5, 3, 0x00, 5, 0x2384),            # V2: eq32, expect not-taken
    (0xFFFFFFFF, 0, 0x03, 2, 0x2388),   # V5: ugt32, expect taken
)

# fuzz-2 (task-05 §4): unified outcome codes, cc0 = subsi eq/zero (I2-b)
FUZZ2_TAKEN = 0x1                # slot = 1: branch taken
FUZZ2_NOT_TAKEN = 0x2            # slot = 2: branch not taken (0 = no store)
CC_ZERO = 0x00                   # cc0: eq/zero flags from subsi (SHA-verified)
# card 01:00.0 identity, task-04 journal (mstflint q pre-burn)
CARD_GUID = int(mlxfwutil.hw('CARD_CX5_25G', 'guid'), 16)
CARD_MAC = int(mlxfwutil.hw('CARD_CX5_25G', 'mac'), 16)

# fuzz-3 (дизайн-журнал 2026-10-05-fuzz3-vector-design.md):
SENTINEL = 0xBADC0002           # S-M: предзаписанное значение [0x2394]
MEM_SLOT = 0x2394               # S-M слот (и адрес-операнд bare cmp36)


def clcrc(code, tail=b""):
    out = bytearray()
    for i in range(len(code) // 64):
        line = bytearray(code[i * 64:(i + 1) * 64]) + b"\x00\x00"
        line += struct.pack("<H", mlxfwutil.clcrc_calc(bytes(line)))
        out += line
    return bytes(out) + tail


def _ld32(rd, val):
    """Build a 32-bit constant in rd via set2/set3 (docs/250-re/120-irisc/025-boot-injection.md idiom).

    Halfword semantics (S0 live words + I2-b sha-init ground truth):
    set2 rd,zero,imm loads imm into the HIGH half (rd = imm<<16;
    S0: set2 6,zero,0xbadc -> 0xbadc0000), set3 rd,rs,imm inserts imm
    into the LOW half bits 15..0 (sha256_init starts with
    `set3 r5,zero,0xae85` => set3 rd,zero,imm -> rd = imm).  Hence small
    constants MUST use set3 rd,zero,val; full 32-bit values use the S0
    idiom set2(hi)+set3(rd,rd,lo).
    """
    val &= 0xFFFFFFFF
    if val < 0x10000:
        return [enc.set3(rd, 0, val)]
    return [enc.set2(rd, (val >> 16) & 0xFFFF), enc.set3(rd, rd, val & 0xFFFF)]


def marker_words():
    """CR[0x23f0] = 0xbadc0001 (S0-exact value words)."""
    return [
        enc.set2(6, (MARKER >> 16) & 0xFFFF),
        enc.set3(6, 6, MARKER & 0xFFFF),
        enc.st_d(6, 0, MARKER_SLOT),
    ]


def probe_words(vec1, vec2, sel, lo11, slot, base):
    """One cmp36 probe: slot = taken ? 0xB0 : 0xB1. Returns (words, end_pc).

    Layout: [loads r5/r6][cmp36][b.t.cc0a -> taken][nt: val/store/jump]
            [taken: val/store]  (end_pc = next instruction after the probe)
    """
    if not 0 < slot <= 0xFFFC or slot % 4:
        raise ValueError(f"bad CR slot 0x{slot:x} (base-zero st.d reach)")
    head = _ld32(5, vec1) + _ld32(6, vec2)
    p_cmp = base + 4 * len(head)
    p_bra = p_cmp + 4
    p_nt = p_bra + 4
    p_jmp = p_nt + 8
    p_tak = p_jmp + 4
    p_end = p_tak + 8
    words = head + [
        enc.cmp36(sel, 5, 6, lo11),
        enc.b_t(CC_CMP, p_bra, p_tak),
        enc.set2(5, NOT_TAKEN),
        enc.st_d(5, 0, slot),
        enc.jump(p_jmp, p_end),
        enc.set2(5, TAKEN),
        enc.st_d(5, 0, slot),
    ]
    return words, p_end


def shellcode_words(probes=PROBES):
    words = list(marker_words())
    pc = SC + 4 * len(words)
    for vec1, vec2, sel, lo11, slot in probes:
        pw, pc = probe_words(vec1, vec2, sel, lo11, slot, pc)
        words += pw
    words.append(enc.jump(pc, RESUME))
    return words


def _resolve(items):
    """Two-pass label resolution at SC: item list -> flat word list.

    Items: ('raw', word) | ('b', 'b.t'|'b.f', cc, 'label'|addr) |
    ('b', 'jump', None, 'label'|addr) | ('label', name).  Every word comes
    from an enc.* function — no hand-written constants.
    """
    addr, labels = SC, {}
    for it in items:
        if it[0] == "label":
            labels[it[1]] = addr
        else:
            addr += 4
    words, pc = [], SC
    for it in items:
        if it[0] == "label":
            continue
        if it[0] == "raw":
            words.append(it[1](pc) if callable(it[1]) else it[1])
        else:
            _, kind, cc, tgt = it
            t = labels[tgt] if isinstance(tgt, str) else tgt
            if kind == "jump":
                words.append(enc.jump(pc, t))
            elif kind == "b.t":
                words.append(enc.b_t(cc, pc, t))
            else:
                words.append(enc.b_f(cc, pc, t))
        pc += 4
    return words


def fuzz2_words():
    """fuzz-2 shellcode (task-05 §4.5): 41 words, enc-assembled only.

    Blocks by ascending CR slot (st.d spillover rule, task-03 §5):
    marker 3 + P1 9 (dual-store) + P2 6 (bool idiom) + P3 7 (dual-store) +
    C1 6 (bool idiom) + C2 9 (dual-store) + resume 1 = 41 of 42 safe-zone
    words; word 42 (0x38e364) stays the stock zero sink.
    """
    items = []
    A = items.append
    # marker (fuzz-1 bit-exact): CR[0x23f0] = 0xbadc0001
    A(("raw", enc.set2(6, (MARKER >> 16) & 0xFFFF)))
    A(("raw", enc.set3(6, 6, MARKER & 0xFFFF)))
    A(("raw", enc.st_d(6, 0, MARKER_SLOT)))
    # P1 slot 0x2380: op36 sel=gt32, r5=5 vs r6=3, lo11=2 (=V4 word);
    # signed/unsigned-unambiguous gt (task-05 §4.4 deviation note)
    A(("raw", enc.set3(5, 0, 0x5)))
    A(("raw", enc.set3(6, 0, 0x3)))
    A(("raw", enc.cmp36(0x01, 5, 6, 2)))
    A(("b", "b.t", CC_CMP, "P1_taken"))
    A(("raw", enc.addi(5, 0, FUZZ2_NOT_TAKEN)))
    A(("raw", enc.st_d(5, 0, 0x2380)))
    A(("b", "jump", None, "P1_merge"))
    A(("label", "P1_taken"))
    A(("raw", enc.addi(5, 0, FUZZ2_TAKEN)))
    A(("raw", enc.st_d(5, 0, 0x2380)))
    A(("label", "P1_merge"))
    # P2 slot 0x2384: op38 sel=eq32, r5=1<<32 (set1 hw1 idiom) vs zero,
    # lo11=2 (=V8 word); bool idiom — value reg loaded before compare
    A(("raw", enc.set1(5, 0, 0x1)))
    A(("raw", enc.addi(6, 0, FUZZ2_TAKEN)))
    A(("raw", enc.cmp38(0x00, 5, 0, 2)))
    A(("b", "b.t", CC_CMP, "P2_store"))
    A(("raw", enc.addi(6, 0, FUZZ2_NOT_TAKEN)))
    A(("label", "P2_store"))
    A(("raw", enc.st_d(6, 0, 0x2384)))
    # P3 slot 0x2388: op36 minimal form — sel=0, rs==rt (r5 with itself),
    # lo11=0; value-independent always-eq under any operand model
    A(("raw", enc.cmp36(0x00, 5, 5, 0)))
    A(("b", "b.t", CC_CMP, "P3_taken"))
    A(("raw", enc.addi(5, 0, FUZZ2_NOT_TAKEN)))
    A(("raw", enc.st_d(5, 0, 0x2388)))
    A(("b", "jump", None, "P3_merge"))
    A(("label", "P3_taken"))
    A(("raw", enc.addi(5, 0, FUZZ2_TAKEN)))
    A(("raw", enc.st_d(5, 0, 0x2388)))
    A(("label", "P3_merge"))
    # C1 slot 0x2390: known-taken control — subsi r5,r5,0 at r5=0 -> Z=1
    # (SHA form @0x2b160c); b.t.cc0 must take; taken value in r6 (subsi
    # writes rd=r5)
    A(("raw", enc.set3(5, 0, 0x0)))
    A(("raw", enc.addi(6, 0, FUZZ2_TAKEN)))
    A(("raw", enc.subsi(5, 5, 0x0)))
    A(("b", "b.t", CC_ZERO, "C1_store"))
    A(("raw", enc.addi(6, 0, FUZZ2_NOT_TAKEN)))
    A(("label", "C1_store"))
    A(("raw", enc.st_d(6, 0, 0x2390)))
    # C2 slot 0x2394: polarity control — V1 operands bit-exact, b.f.cc0a
    A(("raw", enc.set3(5, 0, 0x5)))
    A(("raw", enc.set3(6, 0, 0x5)))
    A(("raw", enc.cmp36(0x00, 5, 6, 2)))
    A(("b", "b.f", CC_CMP, "C2_taken"))
    A(("raw", enc.addi(5, 0, FUZZ2_NOT_TAKEN)))
    A(("raw", enc.st_d(5, 0, 0x2394)))
    A(("b", "jump", None, "C2_merge"))
    A(("label", "C2_taken"))
    A(("raw", enc.addi(5, 0, FUZZ2_TAKEN)))
    A(("raw", enc.st_d(5, 0, 0x2394)))
    A(("label", "C2_merge"))
    # resume main-init
    A(("b", "jump", None, RESUME))
    words = _resolve(items)
    if len(words) != 41:
        raise ValueError(f"fuzz-2 shellcode is {len(words)} words, want 41 (task-05 §4.5)")
    return words


def _bool_probe(items, A, name, cmp_word, slot):
    """bool-идиома fuzz-2, prov ПОСЛЕ cmp (r6 может быть rt-операндом):
    [cmp] [addi r6,1] [b.t cc0a -> store] [addi r6,2] [st_d r6, slot].
    Слот получает 1 (taken) / 2 (not-taken); 5 слов."""
    A(("raw", cmp_word))
    A(("raw", enc.addi(6, 0, FUZZ2_TAKEN)))
    A(("b", "b.t", CC_CMP, f"{name}_store"))
    A(("raw", enc.addi(6, 0, FUZZ2_NOT_TAKEN)))
    A(("label", f"{name}_store"))
    A(("raw", enc.st_d(6, 0, slot)))


def fuzz3a_words():
    """fuzz-3 Образ A (дизайн-журнал §2): 41 слово, enc-only.

    Идентичность op-0x36 (lo11 = imm6|funct5, i2b-rosetta):
    C1  0x2380  cmp38 self-eq (r5 vs r5) — known-taken cc0a-базовая
    S1  0x2384  cmp36 lo11=0x004 (f5=4) sel=0, rs=0 vs r0
    S2  0x2388  cmp36 lo11=0x402 (f5=2, i6=32) sel=0, 5 vs 5 (imm6 != 0)
    S3  0x238c  cmp36 lo11=0x00a (f5=0xa) sel=0, 5 vs 5 (обязательный f5)
    S-V 0x2390  cmp36 lo11=2: r5=0x80000000 (INT32_MIN) vs r6=1 —
              signed overflow V=1 (task-08 §10, op36-специфичная)
    S-M 0x2394  BARE cmp36 lo11=2, r5=0x2394, sentinel 0xbadc0002 в [0x2394]
              (memory-write-проба; host-read: sentinel = нет store,
              иное = 0x36 пишет [r5])
    """
    items = []
    A = items.append
    # маркер (S0-exact): CR[0x23f0] = 0xbadc0001
    A(("raw", enc.set2(6, (MARKER >> 16) & 0xFFFF)))
    A(("raw", enc.set3(6, 6, MARKER & 0xFFFF)))
    A(("raw", enc.st_d(6, 0, MARKER_SLOT)))
    # C1: cmp38 self-eq — known-taken cc0a (P2-факт fuzz-2)
    _bool_probe(items, A, "C1", enc.cmp38(0x00, 5, 5, 2), 0x2380)
    # S1: lo11=0x004, rs=0 (r0=0) vs r0
    A(("raw", enc.set3(5, 0, 0x0)))
    _bool_probe(items, A, "S1", enc.cmp36(0x00, 5, 0, 0x004), 0x2384)
    # S2: lo11=0x402 (i6=32 != 0), 5 vs 5
    A(("raw", enc.set3(5, 0, 0x5)))
    A(("raw", enc.set3(6, 0, 0x5)))
    _bool_probe(items, A, "S2", enc.cmp36(0x00, 5, 6, 0x402), 0x2388)
    # S3: lo11=0x00a (обязательный f5=0xa), 5 vs 5
    A(("raw", enc.set3(6, 0, 0x5)))
    _bool_probe(items, A, "S3", enc.cmp36(0x00, 5, 6, 0x00A), 0x238C)
    # S-V: overflow — r5=0x80000000 (INT32_MIN), r6=1
    A(("raw", enc.set2(5, 0x8000)))
    A(("raw", enc.set3(5, 5, 0x0)))
    A(("raw", enc.set3(6, 0, 0x1)))
    _bool_probe(items, A, "SV", enc.cmp36(0x00, 5, 6, 2), 0x2390)
    # S-M: sentinel -> [0x2394]; r5 = 0x2394; BARE cmp36 (без ветки)
    A(("raw", enc.set2(6, (SENTINEL >> 16) & 0xFFFF)))
    A(("raw", enc.set3(6, 6, SENTINEL & 0xFFFF)))
    A(("raw", enc.st_d(6, 0, MEM_SLOT)))
    A(("raw", enc.set3(5, 0, MEM_SLOT)))
    A(("raw", enc.cmp36(0x00, 5, 6, 2)))
    # resume main-init
    A(("b", "jump", None, RESUME))
    words = _resolve(items)
    if len(words) != 41:
        raise ValueError(
            f"fuzz-3A shellcode is {len(words)} words, want 41 "
            "(дизайн-журнал 2026-10-05-fuzz3-vector-design.md §2)")
    return words


def _fuzz3b_items(with_cz):
    """Образ B (дизайн-журнал §2): пин ширины cmp.w + sel-ось 0x38.

    C1  0x2380  cmp38 self-eq — known-taken cc0a-базовая (EQ-модель) /
                негативный контроль (NE-модель: self -> FALSE)
    W0  0x2384  cmp38 eq32 5 vs 3 — EQ/NE-дискриминатор
    X1  0x2388  cmp38 sel=0x01 (gt32) 5 vs 3 — sel-ось (5>3 -> expect taken)
    W2a 0x238c  cmp38 eq32 0x00000005 vs 0x80000005 (lo16 eq, bits16-31 diff)
    W2b 0x2390  cmp38 eq32 0x00000005 vs 0x00000002 (lo16 diff, bits16-31 eq)
    Cz  0x2394  (только B') subsi r5,r5,0 @r5=0 -> Z=1 (SHA-verified);
                b.t.cc0 — known-taken при ЛЮБОЙ cmp-модели (fuzz-2 C1-идиома)
    """
    items = []
    A = items.append
    # маркер (S0-exact): CR[0x23f0] = 0xbadc0001
    A(("raw", enc.set2(6, (MARKER >> 16) & 0xFFFF)))
    A(("raw", enc.set3(6, 6, MARKER & 0xFFFF)))
    A(("raw", enc.st_d(6, 0, MARKER_SLOT)))
    # C1: known-taken базовая
    _bool_probe(items, A, "C1", enc.cmp38(0x00, 5, 5, 2), 0x2380)
    # W0: known-FALSE гейт, 5 vs 3
    A(("raw", enc.set3(5, 0, 0x5)))
    A(("raw", enc.set3(6, 0, 0x3)))
    _bool_probe(items, A, "W0", enc.cmp38(0x00, 5, 6, 2), 0x2384)
    # X1: sel-ось, 5 vs 3
    A(("raw", enc.set3(6, 0, 0x3)))
    _bool_probe(items, A, "X1", enc.cmp38(0x01, 5, 6, 2), 0x2388)
    # W2a: 0x00000005 vs 0x80000005 (hi16 diff)
    A(("raw", enc.set2(6, 0x8000)))
    A(("raw", enc.set3(6, 6, 0x5)))
    _bool_probe(items, A, "W2a", enc.cmp38(0x00, 5, 6, 2), 0x238C)
    # W2b: 0x00000005 vs 0x00000002 (hi16 eq)
    A(("raw", enc.set3(6, 0, 0x2)))
    _bool_probe(items, A, "W2b", enc.cmp38(0x00, 5, 6, 2), 0x2390)
    if with_cz:
        # Cz: model-independent known-taken контроль (fuzz-2 C1-идиома),
        # слот 0x2394 (в B свободен); поправка после C1-гейт-сбола burn#1
        A(("raw", enc.set3(5, 0, 0x0)))
        A(("raw", enc.addi(6, 0, FUZZ2_TAKEN)))
        A(("raw", enc.subsi(5, 5, 0x0)))
        A(("b", "b.t", CC_ZERO, "Cz_store"))
        A(("raw", enc.addi(6, 0, FUZZ2_NOT_TAKEN)))
        A(("label", "Cz_store"))
        A(("raw", enc.st_d(6, 0, 0x2394)))
    # resume main-init
    A(("b", "jump", None, RESUME))
    return items


def fuzz3b_words():
    """fuzz-3 Образ B (дизайн-журнал §2): 35 слов, enc-only."""
    words = _resolve(_fuzz3b_items(False))
    if len(words) != 35:
        raise ValueError(
            f"fuzz-3B shellcode is {len(words)} words, want 35 "
            "(дизайн-журнал 2026-10-05-fuzz3-vector-design.md §2)")
    return words


def fuzz3bp_words():
    """fuzz-3 Образ B' (поправка burn#1, owner-решение): B + Cz, 41 слово.

    Cz — known-taken контроль (subsi/b.t.cc0, SHA-verified) при любой
    cmp-модели; C1 self-eq становится негативным контролем (NE-модель: 2),
    W0 (5v3, f5=2) — прямой EQ/NE-дискриминатор.
    """
    words = _resolve(_fuzz3b_items(True))
    if len(words) != 41:
        raise ValueError(
            f"fuzz-3B' shellcode is {len(words)} words, want 41 "
            "(поправка плана после burn#1, C1-гейт)")
    return words


def build(out_path, probes=PROBES):
    buf = _patch_image(shellcode_words(probes))
    Path(out_path).write_bytes(buf)
    return buf


def build_fuzz2(out_path):
    """fuzz-2 image: §4.5 shellcode + card GUID/MAC injection."""
    buf = _inject_uids(_patch_image(fuzz2_words()))
    Path(out_path).write_bytes(buf)
    return buf


def build_fuzz3a(out_path):
    """fuzz-3 Образ A: §2-шеллкод + инъекция GUID/MAC карты."""
    buf = _inject_uids(_patch_image(fuzz3a_words()))
    Path(out_path).write_bytes(buf)
    return buf


def build_fuzz3b(out_path):
    """fuzz-3 Образ B: §2-шеллкод + инъекция GUID/MAC карты."""
    buf = _inject_uids(_patch_image(fuzz3b_words()))
    Path(out_path).write_bytes(buf)
    return buf


def build_fuzz3bp(out_path):
    """fuzz-3 Образ B': B + Cz-контроль + инъекция GUID/MAC карты."""
    buf = _inject_uids(_patch_image(fuzz3bp_words()))
    Path(out_path).write_bytes(buf)
    return buf


def _patch_image(words):
    """Apply the injection word + shellcode words to MAIN_CODE (+CRCs)."""
    src = IMG_PATH.read_bytes()
    if hashlib.md5(src).hexdigest() != IMG_MD5:
        raise ValueError("stock ACA8008 image md5 mismatch")
    img = mlxfwutil.Image(src, "aca")
    e = img.find_entry("ITOC", 0x03)
    raw = img.section_data(e)
    code = decrc(raw)
    nlines = len(code) // 64
    tail = raw[nlines * 68:]
    if clcrc(code, tail) != raw:
        raise ValueError("de-clcrc round-trip failed (method drift?)")

    w = lambda a: struct.unpack_from(">I", code, a)[0]
    if w(INJ_DC) != INJ_STOCK:
        raise ValueError(f"stock word @0x{INJ_DC:x} is "
                         f"0x{w(INJ_DC):08x}, want 0x{INJ_STOCK:08x}")
    if w(INJ_DC + 4) != INJ_DEAD:
        raise ValueError(f"dead-code word @0x{INJ_DC + 4:x} is "
                         f"0x{w(INJ_DC + 4):08x}, want 0x{INJ_DEAD:08x}")
    nz = [SC + 4 * i for i in range(SC_WORDS) if w(SC + 4 * i) != 0]
    if nz:
        raise ValueError(f"safe zone 0x{SC:x}..0x{SC + 4 * SC_WORDS - 1:x} "
                         f"not all-zero in stock (first non-zero @0x{nz[0]:x})")

    if len(words) > SC_WORDS:
        raise ValueError(f"shellcode {len(words)} words > safe zone {SC_WORDS}")

    new_code = bytearray(code)
    new_code[INJ_DC:INJ_DC + 4] = struct.pack(">I", enc.call(INJ_DC, SC))
    for i, word in enumerate(words):
        new_code[SC + 4 * i:SC + 4 * i + 4] = struct.pack(">I", word)
    new_raw = clcrc(bytes(new_code), tail)

    diff = [i for i in range(nlines) if raw[i * 68:(i + 1) * 68] != new_raw[i * 68:(i + 1) * 68]]
    exp = sorted({a // 64 for a in [INJ_DC] + [SC + 4 * i for i in range(len(words))]})
    if diff != exp:
        raise ValueError(f"unexpected changed clcrc lines: {diff} != {exp}")

    edits = [(0x03, i * 68, new_raw[i * 68:(i + 1) * 68]) for i in diff]
    return mlxfwutil.patch_sections(img, edits)


def _inject_uids(buf, guid=CARD_GUID, mac=CARD_MAC):
    """Write card GUID/MAC into DEV_INFO + MFG_INFO (cmd_guides FS4 path).

    DEV_INFO: MDevInfo.write_uids (guid@0x28, mac@0x38 + INSECTION CRC);
    MFG_INFO: guid/mac copy, sec/entry CRC refreshed when crcf=0.  Stock
    ships zeroed uids — this is what turned the netdev MAC zero after the
    task-04 burn; task-07 verified the injection survives the plain
    fuzz-1-flag burn (mstflint rejects --use_image_guids, FS2-only).
    """
    img = mlxfwutil.Image(buf, "uid-inject")
    out = bytearray(buf)
    dv = mlxfwutil.find_valid_devinfo(img)
    if len(dv) != 1:
        raise ValueError(f"expected exactly one valid DEV_INFO, found {len(dv)}")
    new_di = mlxfwutil.MDevInfo.parse(img.section_data(dv[0])).write_uids(guid, mac)
    a = img.sec_abs(dv[0])
    out[a:a + dv[0].size] = new_di[:dv[0].size]

    e0 = img.find_entry("DTOC", 0xE0)
    d0 = bytearray(img.section_data(e0))
    d0[mlxfwutil.MDEVINFO_UID_OFF:mlxfwutil.MDEVINFO_UID_OFF + 8] = guid.to_bytes(8, "big")
    d0[mlxfwutil.MDEVINFO_MAC_OFF:mlxfwutil.MDEVINFO_MAC_OFF + 8] = mac.to_bytes(8, "big")
    a0 = img.sec_abs(e0)
    out[a0:a0 + e0.size] = d0
    if e0.crcf == 0:
        ent = bytearray(e0.raw)
        mlxfwutil.set_bits(ent, 208, 16, mlxfwutil.crc16_mlx(bytes(d0)))
        mlxfwutil.set_bits(ent, 240, 16, mlxfwutil.crc16_mlx(bytes(ent[:28])))
        ent_off = img.dtoc_off + 32 + e0.index * 32
        out[ent_off:ent_off + 32] = ent
    return bytes(out)


if __name__ == "__main__":
    argv = sys.argv[1:]
    if argv and argv[0] == "fuzz2":
        out = argv[1] if len(argv) > 1 else "/tmp/opencode/fuzz/aca-fuzz2.bin"
        b = build_fuzz2(out)
    elif argv and argv[0] == "fuzz3a":
        out = argv[1] if len(argv) > 1 else "/tmp/opencode/fuzz/aca-fuzz3a.bin"
        b = build_fuzz3a(out)
    elif argv and argv[0] == "fuzz3b":
        out = argv[1] if len(argv) > 1 else "/tmp/opencode/fuzz/aca-fuzz3b.bin"
        b = build_fuzz3b(out)
    elif argv and argv[0] == "fuzz3bp":
        out = argv[1] if len(argv) > 1 else "/tmp/opencode/fuzz/aca-fuzz3bp.bin"
        b = build_fuzz3bp(out)
    else:
        out = argv[0] if argv else "/tmp/opencode/fuzz/aca-fuzz1.bin"
        b = build(out)
    print("md5", hashlib.md5(b).hexdigest(), "size", len(b))
