#!/usr/bin/env python3
"""cx4lx-fdr-gate: H-F2 G1 reverse of the special-path MAIN_CODE sites.

Offline research tool (arc H-F2, spec
docs/superpowers/specs/2026-11-24-serdes-arc-hf2-design.md §3; journals
docs/superpowers/journal/2026-11-25-serdes-arc-hf2-task-02.md and
-task-03.md).  Findings encoded here:

  * There are TWO field-gated event dispatchers in Lx 14.32.1912
    MAIN_CODE, not one: rt 0x9be0f4 ("ib_speed_nego", the arc F site) and
    its twin rt 0x9fc44c ("ib_force_edr" -- same prologue, same mirror
    field, same polarity; special-path strings differ).  The CX-4 12.28
    homologs 0x9979cc / 0x9d1670 both use the constant 3
    (subsi r4,r23,0x3; b.t.0x4) -- the difference is class-dependent, so
    both Lx sites are patch targets.
  * Polling arms (send-hub jump-table arms 17/18, cmd 0x21/0x20): Lx
    rt 0x9b32d0 / 0x9b3320 iterate exactly bits[9..11](mirror 0x3686)
    times; the CX-4 homologs rt 0x98da04 / 0x98da40 loop on a constant
    compare (subsi r4,r23,0x3, counter 1..2) -> exactly 2 iterations and
    no mirror read at all.  Verdict: TARGET (second patch site per spec
    §3 1b).
  * Patch (minimal, one word per site, uniform idiom): the field-source
    word `ld.i r4,0x3686` -> `addi r4,zero,0x400` (field := 2), at
    dc 0x1be12c (dispatcher), 0x1fc488 (twin), 0x1b330c / 0x1b335c
    (polling count sources).  Patched dispatcher: special <=> event==0
    OR event>2 <=> event>=3 -- bit-equivalent to CX-4 for every 32-bit
    event.  Patched arms: exactly 2 iterations (subjects 0,1) for any
    mirror.  Words are assembled with the strict cx4lx profile
    (decode-verify inside assemble).
  * The polling-arm entry gates (ld.i 0x3686 + op0x36 imm=0x0123 +
    b.t.0xa) are NOT patched: predicate semantics is f5-open, but its
    imm coordinates (9, 3) match the mask32 field coords (zero-guard of
    the subject count) and the live arc F configure-loop wall proves the
    runtime field >= 1, so the gates pass (see journal).
  * H2 (task-03): the ETH speed-enable is UNIFIED with the IB side --
    the protocol-choice sites (Lx rt 0x9ccd4c / 0x9dfeac; CX-4 homologs
    0x9a60b8 / 0x9b8b68) read param 0x60c (nbits 0x14,
    management.port_info.link_speed_*) when the port is ETH and param
    0x776 (nbits 0xa) when IB, through ONE getter (Lx rt 0xa0bfb8 /
    CX-4 rt 0x9e184c) from the same IRON parsed table, storing the same
    ctx[0x5c] slot.  Every ETH-speed byte of the corpus lives inside
    the 5-byte EDR-class tuple {0x158, 0x283, 0x2c5, lcl 0x30b/0x317}
    (FCA<->ECA diff is tuple-exact; same-board ETH-speed pairs carry
    only tuple bytes) -- there are NO separate ETH sites.
    `eth_verdict(base, corpus)` -> {'mode': 'unified', 'sites': [],
    'tuple': {...}}; the tuple (ECA reference, lcl fb/fb) is the G2
    patch-set input.

Usage:
  python3 hf2_reverse.py [--base PATH] [--eca PATH] [--out SPEC.json]

Stdlib only; offline (no hardware, no ssh).
"""
import argparse
import json
import re
import struct
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

from mlxfwutil import Image, clcrc_unwrap  # noqa: E402
from scripts.irisc import assemble, disasm  # noqa: E402
from scripts.irisc.profiles import load_profile  # noqa: E402
import loader_reverse as lr  # noqa: E402

BASE_REFS = (REPO / "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-"
             "MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")
ECA_REFS = (REPO / "refs/fw/cx-4/fw-ConnectX4-rel-12_28_4706-"
            "MCX456A-ECA_Ax-UEFI-14.21.21-FlexBoot-3.6.103.bin")
SPEC_PATH = REPO / "scripts/probes/gate-specs/hf2-dispatcher-cx4lx-1912.json"

LOAD_BASE = 0x800000       # ITOC param0 of section 0x03 (cx4lx profile)
MIRROR_WORD = 0x3686       # RAM word (byte 0xDA18), bits[9..11] = field
MAIN_CODE = 3

# ---- stock/patched word constants (big-endian image words) ----------------
W_SUBSI_R4_R23_1 = bytes.fromhex("16e40001")   # subsi r4,r23,0x1
W_SUBSI_R4_R23_3 = bytes.fromhex("16e40003")   # subsi r4,r23,0x3
W_LDI_R4_MIRROR = bytes.fromhex("4a043686")    # ld.i r4,0x3686
W_ADDI_R4_400 = bytes.fromhex("00040400")      # addi r4,zero,0x400 (patch)
W_MASK32_9_3 = bytes.fromhex("c8840123")       # mask32 r4,r4,0x9,3
W_SUBS_R4_R23_R4 = bytes.fromhex("fee42005")   # subs r4,r23,r4
W_SUBS_R4_R4_R23 = bytes.fromhex("fc84b805")   # subs r4,r4,r23
W_OR_R22_R5 = bytes.fromhex("fcb62808")        # or r22,r5,r5
W_OR_R23_R4 = bytes.fromhex("fc972008")        # or r23,r4,r4
W_CSR_R3_BC = bytes.fromhex("480300bc")        # csr.r r3,csr0xbc (prologue)
W_OP36_0123 = bytes.fromhex("d8800123")        # op0x36 ... imm=0x0123
W_ADDI_R23_0 = bytes.fromhex("00170000")       # addi r23,zero,0x0
W_ADDI_R23_1 = bytes.fromhex("00170001")       # addi r23,zero,0x1
W_ADDI_R23_INC = bytes.fromhex("02f70001")     # addi r23,r23,0x1
W_BF0_BACK = bytes.fromhex("a400fff6")         # b.f.0x0 <backward>

FIELD_SRC_WORDS = (W_LDI_R4_MIRROR, W_ADDI_R4_400)

R_ADDI = re.compile(r"^addi (\w+),(\w+),(0x-?[0-9a-f]+)$")
R_ADDI_HI = re.compile(r"^addi\.hi (\w+),(\w+),(0x-?[0-9a-f]+)$")
R_SUBSI = re.compile(r"^subsi (\w+),(\w+),(0x-?[0-9a-f]+)$")
R_SUBS = re.compile(r"^subs (\w+),(\w+),(\w+)$")
R_OR = re.compile(r"^or (\w+),(\w+),(\w+)$")
R_LDI = re.compile(r"^ld\.i (\w+),(0x[0-9a-f]+)$")
R_MASK32 = re.compile(r"^mask32 (\w+),(\w+),(0x[0-9a-f]+),(\d+)$")
R_BR = re.compile(r"^b\.(t|f)\.0x([0-9a-f]+) (\w+),(0x[0-9a-f]+)$")
R_JUMP = re.compile(r"^jump (0x[0-9a-f]+)$")
R_CALL = re.compile(r"^call (0x[0-9a-f]+)$")
R_OP36 = re.compile(r"^op0x36 ")


def _imm(s):
    """Parse a disasm immediate ('0x1ca5' / '0x-1ca5' / '-0x1ca5')."""
    return int(s.replace("0x-", "-0x"), 0)

M32 = 0xFFFFFFFF


# ------------------------------------------------------------------ helpers

def _reg(name):
    return 0 if name == "zero" else int(name[1:])


def load_main_code(path):
    """Image + ITOC 0x03 entry + de-framed dc view (per-line clcrc checked)."""
    p = Path(path)
    img = Image(p.read_bytes(), str(p))
    e = img.find_entry("ITOC", MAIN_CODE)
    dc, _tail = clcrc_unwrap(img.section_data(e))
    return img, e, dc


def rt_to_dc(rt, load_base=LOAD_BASE):
    return rt - load_base


def dc_to_rt(dc, load_base=LOAD_BASE):
    return dc + load_base


def dc_to_image(img, e, dc_off):
    """dc offset -> framed position (68B clcrc line = 64 code + 2 pad +
    2 LE16 crc)."""
    line, in_line = divmod(dc_off, 64)
    framed = line * 68 + in_line
    return {"clcrc_line": line, "in_line": in_line, "framed_off": framed,
            "flash_abs": img.sec_abs(e) + framed}


def _words(dc, dc_off, n):
    return [struct.unpack_from(">I", dc, dc_off + 4 * i)[0] for i in range(n)]


def _decode(dc, dc_off, n, load_base=LOAD_BASE):
    out = []
    for i, w in enumerate(_words(dc, dc_off, n)):
        rt = dc_off + 4 * i + load_base
        out.append((rt, w, disasm(w, rt)))
    return out


def read_cstring(dc, rt, load_base=LOAD_BASE, limit=256):
    off = rt_to_dc(rt, load_base)
    end = dc.find(b"\x00", off, off + limit)
    if end < 0:
        return None
    return dc[off:end].decode("latin1")


def _branch_target(text):
    m = R_BR.match(text)
    return int(m.group(4), 0) if m else None


def _jump_target(text):
    m = R_JUMP.match(text)
    return int(m.group(1), 0) if m else None


def _is_call(word):
    return (word >> 26) == 0x25 and not ((word >> 24) & 1)


def _is_branch(word, taken, cc):
    return (word >> 26) == (0x28 if taken else 0x29) and \
        ((word >> 16) & 0x1F) == cc


def _special_string(dc, special_rt, load_base=LOAD_BASE):
    """addi r4,zero,LO + addi.hi r8,r4,HI in the special path -> C-string."""
    win = _decode(dc, rt_to_dc(special_rt, load_base), 8, load_base)
    for i in range(len(win) - 1):
        m1 = R_ADDI.match(win[i][2])
        m2 = R_ADDI_HI.match(win[i + 1][2])
        if m1 and m2 and m1.group(1) == "r4" and m2.group(1) == "r8" \
                and m2.group(2) == "r4":
            lo, hi = _imm(m1.group(3)), _imm(m2.group(3))
            rt = (lo + (hi << 16)) & M32
            return {"rt": rt, "text": read_cstring(dc, rt, load_base)}
    return None


def _func_head(dc, cmp_dc, load_base=LOAD_BASE, back=16):
    """Prologue start (csr.r r3,csr0xbc) above the compare window."""
    for i in range(back):
        off = cmp_dc - 4 * (i + 1)
        if off >= 0 and dc[off:off + 4] == W_CSR_R3_BC:
            return off + load_base
    return None


# ------------------------------------------------------- structural finders

def find_dispatcher_sites(dc, load_base=LOAD_BASE):
    """Lx field-gated dispatcher sites (stock OR already patched).

    Anchor: subsi r4,r23,0x1 | b.t.0x2 | <field-src> | mask32 0x9,3 |
    subs r4,r23,r4 | b.f.0x3, with the or r22,r5,r5 / or r23,r4,r4
    prologue tail right above.  Returns sites sorted by compare offset.
    """
    sites = []
    step = 4
    for o in range(0, len(dc) - 6 * step, step):
        if dc[o:o + 4] != W_SUBSI_R4_R23_1:
            continue
        if dc[o + 8:o + 12] not in FIELD_SRC_WORDS:
            continue
        if dc[o + 12:o + 16] != W_MASK32_9_3:
            continue
        if dc[o + 16:o + 20] != W_SUBS_R4_R23_R4:
            continue
        w1, w5 = _words(dc, o, 6)[1], _words(dc, o, 6)[5]
        if not _is_branch(w1, True, 0x2) or not _is_branch(w5, False, 0x3):
            continue
        if dc[o - 8:o - 4] != W_OR_R22_R5 or dc[o - 4:o] != W_OR_R23_R4:
            continue
        words = _decode(dc, o, 6, load_base)
        special_rt = _branch_target(words[1][2])
        head_rt = _func_head(dc, o, load_base)
        if head_rt is None:
            continue
        sites.append({
            "cmp_dc": o,
            "cmp_rt": o + load_base,
            "site_rt": head_rt,
            "site_dc": head_rt - load_base,
            "words": [
                {"rt": rt, "dc": rt - load_base,
                 "word": dc[rt - load_base:rt - load_base + 4].hex(),
                 "word_int": w, "text": t,
                 "branch_target": _branch_target(t)}
                for rt, w, t in words],
            "field_source": {
                "rt": o + 8 + load_base, "dc": o + 8,
                "word": dc[o + 8:o + 12].hex(),
                "word_int": _words(dc, o + 8, 1)[0],
                "text": disasm(_words(dc, o + 8, 1)[0], o + 8 + load_base)},
            "special_rt": special_rt,
            "special_string": _special_string(dc, special_rt, load_base),
        })
    return sites


def find_cx4_dispatcher_sites(dc, load_base=LOAD_BASE):
    """CX-4 constant-3 dispatcher sites (ib_speed_nego / ib_force_edr)."""
    sites = []
    step = 4
    for o in range(0, len(dc) - 4 * step, step):
        if dc[o:o + 4] != W_SUBSI_R4_R23_1:
            continue
        if dc[o + 8:o + 12] != W_SUBSI_R4_R23_3:
            continue
        w1, w3 = _words(dc, o, 4)[1], _words(dc, o, 4)[3]
        if not _is_branch(w1, True, 0x2) or not _is_branch(w3, True, 0x4):
            continue
        if dc[o - 8:o - 4] != W_OR_R22_R5 or dc[o - 4:o] != W_OR_R23_R4:
            continue
        words = _decode(dc, o, 4, load_base)
        special_rt = _branch_target(words[1][2])
        head_rt = _func_head(dc, o, load_base)
        if head_rt is None:
            continue
        sites.append({
            "cmp_dc": o,
            "cmp_rt": o + load_base,
            "site_rt": head_rt,
            "words": [(rt, w, t) for rt, w, t in words],
            "compare_const": 3,
            "special_rt": special_rt,
            "special_string": _special_string(dc, special_rt, load_base),
        })
    return sites


def find_polling_arms(dc, load_base=LOAD_BASE):
    """Lx polling arms (cmd 0x21/0x20), stock OR already patched."""
    arms = []
    step = 4
    for o in range(0, len(dc) - 7 * step, step):
        w_cmd = struct.unpack_from(">I", dc, o)[0]
        if w_cmd not in (0x00060021, 0x00060020):
            continue
        if not _is_call(struct.unpack_from(">I", dc, o + 4)[0]):
            continue
        if dc[o + 8:o + 12] not in FIELD_SRC_WORDS:
            continue
        if dc[o + 12:o + 16] != W_MASK32_9_3:
            continue
        if dc[o + 16:o + 20] != W_SUBS_R4_R4_R23:
            continue
        w_bt = struct.unpack_from(">I", dc, o + 20)[0]
        if not _is_branch(w_bt, True, 0x3) or (w_bt & 0xFFFF) < 0x8000:
            continue  # must jump backward (loop)
        gate_dc = None
        for j in range(o - 4, max(0, o - 0x40), -step):
            if dc[j:j + 4] == W_LDI_R4_MIRROR and \
                    dc[j + 4:j + 8] == W_OP36_0123 and \
                    dc[j + 8:j + 10] == b"\xa0\x0a":
                gate_dc = j
                break
        if gate_dc is None:
            continue
        cmd = w_cmd & 0xFFFF
        loop_head_rt = _branch_target(disasm(w_bt, o + 20 + load_base))
        sender_rt = int(disasm(struct.unpack_from(">I", dc, o + 4)[0],
                               o + 4 + load_base).split()[-1], 0)
        exit_rt = _jump_target(disasm(
            struct.unpack_from(">I", dc, o + 24)[0], o + 24 + load_base))
        window = {rt: w for rt, w, _t in
                  _decode(dc, gate_dc, (o + 28 - gate_dc) // 4, load_base)}
        arms.append({
            "cmd": cmd,
            "rt": gate_dc + load_base,
            "dc": gate_dc,
            "gate_words": _decode(dc, gate_dc, 3, load_base),
            "counter_init": 0,
            "loop_head_rt": loop_head_rt,
            "count_rt": o + 8 + load_base,
            "count_dc": o + 8,
            "sender_rt": sender_rt,
            "sender_call_rt": o + 4 + load_base,
            "tail_words": _decode(dc, o + 8, 4, load_base),
            "exit_rt": exit_rt,
            "window": window,
            "compare_const": None,
        })
    return arms


def find_cx4_polling_arms(dc, load_base=LOAD_BASE):
    """CX-4 polling arms: constant compare, no mirror, no gate."""
    arms = []
    step = 4
    for o in range(0, len(dc) - 6 * step, step):
        w_cmd = struct.unpack_from(">I", dc, o)[0]
        if w_cmd not in (0x00060021, 0x00060020):
            continue
        if not _is_call(struct.unpack_from(">I", dc, o + 4)[0]):
            continue
        if dc[o + 8:o + 12] != W_ADDI_R23_INC:
            continue
        if dc[o + 12:o + 16] != W_SUBSI_R4_R23_3:
            continue
        if dc[o + 16:o + 20] != W_BF0_BACK:
            continue
        head_dc = None
        for j in range(o - step, max(0, o - 0x30), -step):
            if dc[j:j + 4] == W_ADDI_R23_1:
                head_dc = j
                break
        if head_dc is None:
            continue
        cmd = w_cmd & 0xFFFF
        w_bf = struct.unpack_from(">I", dc, o + 16)[0]
        loop_head_rt = _branch_target(disasm(w_bf, o + 16 + load_base))
        exit_rt = _jump_target(disasm(
            struct.unpack_from(">I", dc, o + 20)[0], o + 20 + load_base))
        sender_rt = int(disasm(struct.unpack_from(">I", dc, o + 4)[0],
                               o + 4 + load_base).split()[-1], 0)
        window = {rt: w for rt, w, _t in
                  _decode(dc, head_dc, (o + 24 - head_dc) // 4, load_base)}
        arms.append({
            "cmd": cmd,
            "rt": head_dc + load_base,
            "dc": head_dc,
            "gate_words": None,
            "counter_init": 1,
            "loop_head_rt": loop_head_rt,
            "count_rt": None,
            "count_dc": None,
            "sender_rt": sender_rt,
            "sender_call_rt": o + 4 + load_base,
            "tail_words": _decode(dc, o + 8, 3, load_base),
            "exit_rt": exit_rt,
            "window": window,
            "compare_const": 3,
        })
    return arms


# --------------------------------------------- mini interpreter (semantics)

class _Cpu:
    """Register/flag model for the compare/branch subset used here.

    Flags follow the iRISC.slaspec cc formulas (loader_reverse.CC_SLOTS
    canon): subsi C=RS>imm, N=(RS-imm)s<0; subs C=RT<RS.  Only compare
    instructions set flags; b.t/b.f evaluate the cc slot against them.
    """

    def __init__(self, mirror, gate="field_zero"):
        self.regs = [0] * 32
        self.mirror = mirror
        self.gate = gate
        self.z = self.c = self.n = False
        self.pred = False

    def field(self):
        return lr.mirror_field(self.mirror)

    def set_reg(self, name, val):
        idx = _reg(name)
        if idx:
            self.regs[idx] = val & M32

    def get_reg(self, name):
        return self.regs[_reg(name)]

    def _set_flags_sub(self, rs, rt_u):
        val = (rs - rt_u) & M32
        self.z = val == 0
        self.c = rs > rt_u
        self.n = bool(val & 0x80000000)
        return val

    def step(self, pc, w):
        """Execute one decoded word; returns next pc."""
        t = disasm(w, pc)
        nxt = pc + 4
        m = R_SUBSI.match(t)
        if m:
            val = self._set_flags_sub(self.get_reg(m.group(2)),
                                      _imm(m.group(3)) & 0xFFFF)
            self.set_reg(m.group(1), val)
            return nxt
        m = R_SUBS.match(t)
        if m:
            val = self._set_flags_sub(self.get_reg(m.group(2)),
                                      self.get_reg(m.group(3)))
            self.set_reg(m.group(1), val)
            return nxt
        m = R_ADDI.match(t)
        if m:
            val = (self.get_reg(m.group(2)) + _imm(m.group(3))) & M32
            self.set_reg(m.group(1), val)
            return nxt
        m = R_OR.match(t)
        if m:
            val = self.get_reg(m.group(2)) | self.get_reg(m.group(3))
            self.set_reg(m.group(1), val)
            return nxt
        m = R_LDI.match(t)
        if m:
            addr = int(m.group(2), 0)
            if addr != MIRROR_WORD:
                raise ValueError("interp: unexpected ld.i 0x%x at 0x%x"
                                 % (addr, pc))
            self.set_reg(m.group(1), self.mirror)
            return nxt
        m = R_MASK32.match(t)
        if m:
            val = (self.get_reg(m.group(2)) >> int(m.group(3), 0)) & \
                ((1 << int(m.group(4))) - 1)
            self.set_reg(m.group(1), val)
            return nxt
        m = R_BR.match(t)
        if m:
            cond = self._cc(int(m.group(2), 16))
            taken = cond if m.group(1) == "t" else not cond
            return int(m.group(4), 0) if taken else nxt
        if R_OP36.match(t):
            if self.gate == "field_zero":
                self.pred = self.field() == 0
            elif self.gate == "pass":
                self.pred = False
            elif self.gate == "fail":
                self.pred = True
            else:
                raise ValueError("gate model %r" % self.gate)
            return nxt
        m = R_JUMP.match(t)
        if m:
            return int(m.group(1), 0)
        if R_CALL.match(t):
            return nxt
        return nxt  # ld.d/st.d/csr/set*/... -- straight-line here

    def _cc(self, cc):
        if cc == 0x0:
            return self.z
        if cc == 0x2:
            return self.n
        if cc == 0x3:
            return self.c
        if cc == 0x4:
            return (not self.z) and (not self.c)
        if cc == 0xA:
            return self.pred
        raise ValueError("cc slot 0x%x not modelled" % cc)


def interp_dispatcher(words, start, event, mirror, max_steps=64):
    """Run a dispatcher compare window; returns the exit pc.

    words: {rt: word_int}.  The special-path pc is words[1]'s b.t.0x2
    target (also the fall-through of the last branch); the skip pc is
    the b.f.0x3 / b.t.0x4 target.
    """
    cpu = _Cpu(mirror)
    cpu.regs[23] = event & M32
    pc = start
    for _ in range(max_steps):
        if pc not in words:
            return pc
        pc = cpu.step(pc, words[pc])
    raise RuntimeError("interp_dispatcher: step budget exceeded")


def interp_polling_arm(arm, mirror, gate="field_zero", max_steps=512):
    """Count sender calls of one polling arm (gate model for op0x36)."""
    cpu = _Cpu(mirror, gate=gate)
    count_pc = arm["sender_call_rt"]
    calls = 0
    pc = arm["rt"]
    words = arm["window"]
    for _ in range(max_steps):
        if pc not in words:
            return calls
        w = words[pc]
        if pc == count_pc:
            calls += 1
        pc = cpu.step(pc, w)
    raise RuntimeError("interp_polling_arm: step budget exceeded")


# ---------------------------------------------------------- public outputs

PATCH_TEXT = "addi r4,zero,0x400"


def _patch_word(rt):
    prof = load_profile("cx4lx")
    return assemble(PATCH_TEXT, base=rt, profile=prof)


def patch_words(base_path=BASE_REFS):
    """[(dc_off, bytes)] -- one word per site, strict cx4lx (decode-verify)."""
    _img, _e, dc = load_main_code(base_path)
    out = []
    for site in find_dispatcher_sites(dc):
        fs = site["field_source"]
        if dc[fs["dc"]:fs["dc"] + 4] != W_LDI_R4_MIRROR:
            raise ValueError("field source at dc 0x%x is not stock ld.i"
                             % fs["dc"])
        out.append((fs["dc"], _patch_word(fs["rt"])))
    for arm in find_polling_arms(dc):
        if dc[arm["count_dc"]:arm["count_dc"] + 4] != W_LDI_R4_MIRROR:
            raise ValueError("count source at dc 0x%x is not stock ld.i"
                             % arm["count_dc"])
        out.append((arm["count_dc"], _patch_word(arm["count_rt"])))
    if len(out) != 4:
        raise ValueError("expected 4 patch sites, found %d" % len(out))
    return out


def _site_report(img, e, dc, site):
    for w in site["words"]:
        w["image"] = dc_to_image(img, e, w["dc"])
        w["crc_sites"] = {
            "clcrc_line": w["image"]["clcrc_line"],
            "itoc_entry": "ITOC[%d] 0x03 (section_crc + entry_crc via "
                          "patch_sections)" % e.index,
        }
    fs = site["field_source"]
    fs["image"] = dc_to_image(img, e, fs["dc"])
    fs["crc_sites"] = {
        "clcrc_line": fs["image"]["clcrc_line"],
        "itoc_entry": "ITOC[%d] 0x03" % e.index,
    }
    site["load_base"] = e.param0
    site["ini_id"] = "N/A"
    return site


def dispatcher_words(base_path=BASE_REFS):
    """Identifier set of the special-path dispatcher site (+ twin)."""
    img, e, dc = load_main_code(base_path)
    sites = find_dispatcher_sites(dc)
    if len(sites) != 2:
        raise ValueError("expected 2 dispatcher sites, found %d" % len(sites))
    main = _site_report(img, e, dc, sites[0])
    twin_full = _site_report(img, e, dc, sites[1])
    twin = {
        "site_rt": twin_full["site_rt"],
        "site_dc": twin_full["site_dc"],
        "special_string": twin_full["special_string"],
        "words": twin_full["words"],
        "field_source": twin_full["field_source"],
        "ini_id": "N/A",
    }
    main["twin"] = twin
    return main


def polling_verdict(base_path=BASE_REFS, eca_path=ECA_REFS):
    """TARGET / not-a-target verdict for the polling sites (spec §3 1b)."""
    _img, _e, dc = load_main_code(base_path)
    arms = find_polling_arms(dc)
    if len(arms) != 2:
        raise ValueError("expected 2 polling arms, found %d" % len(arms))
    eimg, _ee, edc = load_main_code(eca_path)
    cx4_arms = find_cx4_polling_arms(edc)
    if len(cx4_arms) != 2:
        raise ValueError("expected 2 CX-4 polling arms, found %d"
                         % len(cx4_arms))
    cx4_disp = find_cx4_dispatcher_sites(edc)
    lx_twin = find_dispatcher_sites(dc)[1]

    cx4_proof = []
    for a in cx4_arms:
        cx4_proof.append({
            "rt": a["rt"], "dc": a["dc"], "cmd": a["cmd"],
            "compare_const": a["compare_const"],
            "counter_init": a["counter_init"],
            "gate": None,
            "iterations": interp_polling_arm(a, mirror=0),
        })
    lx_proof = []
    for a in arms:
        lx_proof.append({
            "rt": a["rt"], "dc": a["dc"], "cmd": a["cmd"],
            "count_rt": a["count_rt"], "count_dc": a["count_dc"],
            "gate_words": [t for _rt, _w, t in a["gate_words"]],
            "stock_iterations_at_field": {
                f: interp_polling_arm(a, (f << 9) | 1, gate="field_zero")
                for f in range(1, 8)},
            "stock_gate_field0": interp_polling_arm(a, 0, gate="field_zero"),
        })

    constant = all(p["compare_const"] == 3 for p in cx4_proof)
    no_mirror = all(a["gate_words"] is None and a["count_dc"] is None
                    for a in cx4_arms)
    class_dependent = constant and no_mirror

    return {
        "verdict": "target" if class_dependent else "not-a-target",
        "second_patch_site": class_dependent,
        "lx_arms": lx_proof,
        "cx4_homolog": {
            "count_semantics": "constant-2" if class_dependent else "?",
            "lx_semantics": "mirror-field",
            "hub_rt_cx4": 0x98D4BC,
            "hub_rt_lx": 0x9B2D84,
            "arms": cx4_proof,
        },
        "proof": {
            "cx4_arms": cx4_proof,
            "lx_arms": lx_proof,
            "gate": {
                "word": "op0x36 zero,r4,zero imm=0x0123 (f5 map open)",
                "coords": "imm6=0x9/funct5=0x3 == mask32 (0x9,3) field "
                          "coords -> zero-guard of the subject count",
                "runtime": "field >= 1 live-evidenced (arc F configure-"
                           "loop wall => event <= field, event != 0)",
                "patched": "gate untouched; passes at runtime; residual "
                           "documented in journal",
            },
            "twin_dispatcher": {
                "site_rt": lx_twin["site_rt"],
                "site_dc": lx_twin["site_dc"],
                "special_string": lx_twin["special_string"],
                "cx4_site_rt": cx4_disp[1]["site_rt"] if len(cx4_disp) > 1
                else None,
                "cx4_compare_const": cx4_disp[1]["compare_const"]
                if len(cx4_disp) > 1 else None,
                "included_in_patch": True,
            },
        },
        "patch": [{"dc": dc_off, "bytes": wb.hex()}
                  for dc_off, wb in patch_words(base_path)],
    }


SPEC_ID = "HF2-DISPATCHER-CX4LX-1912"
SPEC_CARD = "cx4lx-14_32_1912-MCX4131A-GCA (refs stock)"


def build_spec(base_path=BASE_REFS):
    """cable_gate_patch-format spec (dc offsets + stock expected_before)."""
    words = patch_words(base_path)
    notes = {
        0x1BE12C: "ib_speed_nego dispatcher (site rt 0x9be0f4, first "
                  "compare word rt 0x9be124, special label rt 0x9be13c): "
                  "field source ld.i r4,0x3686 (mirror RAM 0x3686 = byte "
                  "0xDA18, bits[9..11]) -> addi r4,zero,0x400 (field := 2). "
                  "Patched special <=> event==0 OR event>=3, bit-equal to "
                  "CX-4 0x9979cc (subsi r4,r23,0x3; b.t.0x4) for every "
                  "32-bit event. Arc F task-01 decode reference; spec "
                  "2026-11-24-serdes-arc-hf2 §3 (1).",
        0x1FC488: "ib_force_edr twin dispatcher (site rt 0x9fc44c, compare "
                  "rt 0x9fc480): same field idiom -> field := 2; CX-4 "
                  "homolog 0x9d1670 uses the constant 3 -> class-dependent, "
                  "second special-path word (spec §3 'word(s)').",
        0x1B330C: "polling arm cmd 0x21 (arm head rt 0x9b32d0, send-hub "
                  "jump-table arm 17, loop head rt 0x9b32e8, sender "
                  "0x9b33d0): loop count source -> field := 2 => exactly 2 "
                  "iterations (subjects 0,1) == CX-4 0x98da04 (subsi "
                  "r4,r23,0x3, counter 1..2). Spec §3 (1b) second "
                  "consumer of bits[9..11].",
        0x1B335C: "polling arm cmd 0x20 (arm head rt 0x9b3320, arm 18, "
                  "loop head rt 0x9b3338): count source -> field := 2 => 2 "
                  "iterations == CX-4 0x98da40.",
    }
    patches = []
    for dc_off, wb in words:
        patches.append({
            "offset": "0x%x" % dc_off,
            "bytes": " ".join("%02x" % b for b in wb),
            "expected_before": " ".join(
                "%02x" % b for b in W_LDI_R4_MIRROR),
            "kind": "code",
            "note": notes[dc_off],
        })
    return {"id": SPEC_ID, "card": SPEC_CARD, "section": MAIN_CODE,
            "patches": patches}


# ============================= H2: ETH speed-enable (task-03, spec §3 2) ===
#
# The ETH-визави of the IB speed-enable param: the protocol-choice sites
# read param 0x60c (nbits 0x14 -- management.port_info.link_speed_*,
# 20 bits) when the port is ETH and param 0x776 (nbits 0xa) when IB,
# through ONE getter (Lx rt 0xa0bfb8 / CX-4 rt 0x9e184c) from the same
# IRON parsed table (arc F task-01), storing the same ctx[0x5c] slot.
# The binary carrier of the table content is the 0x12 region (live
# proven by arc F P1: class byte 0x30->0x10 raised Enabled(IB)) -- the
# ETH speed bytes live in the same EDR-class tuple, so the ETH path is
# UNIFIED with the IB path (no separate ETH sites).

# protocol word (RAM): Lx 0x38f5 / CX-4 0x3a75 (layout shift +0x180)
PROTO_WORD_LX = 0x38F5
PROTO_WORD_CX4 = 0x3A75
GETTER_LX = 0xA0BFB8          # parsed-table param getter (arc F)
GETTER_CX4 = 0x9E184C         # CX-4 12.28 homolog of the getter
ETH_PARAM = 0x60C             # management.port_info.link_speed_* family
IB_PARAM = 0x776              # IB speed/width enable (arc F)
ETH_NBITS = 0x14              # 20 bits (link_speed_* packing)
IB_NBITS = 0xA                # 10 bits

# stock/patched word constants (big-endian image words)
W_LDI_R5_38F5 = bytes.fromhex("4a0538f5")   # ld.i r5,0x38f5 (Lx proto)
W_LDI_R5_3A75 = bytes.fromhex("4a053a75")   # ld.i r5,0x3a75 (CX-4 proto)
W_ADDI_R5_60C = bytes.fromhex("0005060c")   # addi r5,zero,0x60c
W_ADDI_R6_14 = bytes.fromhex("00060014")    # addi r6,zero,0x14
W_ADDI_R5_776 = bytes.fromhex("00050776")   # addi r5,zero,0x776
W_ADDI_R6_0A = bytes.fromhex("0006000a")    # addi r6,zero,0xa
W_OP36_0C02 = bytes.fromhex("d8a00c02")     # op0x36 zero,r5,r1 imm=0x0c02
W_ADDI_R7_0 = bytes.fromhex("00070000")     # addi r7,zero,0x0 (read mode)
W_ADDI_R8_0 = bytes.fromhex("00080000")     # addi r8,zero,0x0

# EDR-class tuple (0x12 FW_MAIN_CFG, ECA reference; brief task-3):
# +0x158 class byte, +0x283 dw280 hi (SerDes speed vector), +0x2c5 dw2c4
# hi, lcl +0x30b/+0x317 (eth_speeds_supported advertisement bits).
TUPLE_SECTION = 0x12
TUPLE_BYTES = (0x158, 0x283, 0x2C5, 0x30B, 0x317)
ECA_CORPUS_REL = "cx4/12_28_4706/MCX456A-ECA"
FCA_CORPUS_REL = "cx4/12_28_4706/MCX456A-FCA"
TUPLE_INI = {
    0x158: "N/A (.mlx FWParameters mapping unavailable; class byte)",
    0x283: "N/A (dw280 hi byte, product SerDes/speed vector)",
    0x2C5: "N/A (dw2c4 hi byte, dw2c4 -> 0x00100000)",
    0x30B: "phy_fw_main_config.phy_shomron.lcl[0]."
           "eth_speeds_supported",
    0x317: "phy_fw_main_config.phy_shomron.lcl[1]."
           "eth_speeds_supported",
}
TUPLE_FIELDS = {
    0x158: "IB speed-class byte {0x30 ETH, 0x10 FDR, 0x31 EDR}",
    0x283: "dw280 hi byte: product SerDes/speed vector "
           "(0x12 = EDR/100G class, ECA and 416A carry it)",
    0x2C5: "dw2c4 hi byte (ECA dword value 0x00100000)",
    0x30B: "lcl[0]: eth_speeds_supported bit map "
           "(bit0=1G .. bit5=50G, bit6=56G, bit7=100G)",
    0x317: "lcl[1]: port-2 eth_speeds_supported (GCA is 1-port: 0x00)",
}

# corpus same-board ETH-speed pairs: (build_a, build_b, label,
# allowed_extra) -- diffs outside the tuple must stay inside
# allowed_extra (documented board/port noise), else separate sites.
ETH_SPEED_PAIRS = (
    ("cx4lx/14_32_1912/MCX4131A-BCA",
     "cx4lx/14_32_1912/MCX4131A-GCA",
     "lx 4131A 40/56G vs 50G (same board)", ()),
    ("cx4/12_28_4706/MCX413A-BCA",
     "cx4/12_28_4706/MCX413A-GCA",
     "cx4 413A 40/56G vs 50G (same board)", ()),
    ("cx4/12_28_4706/MCX416A-CCA",
     "cx4/12_28_4706/MCX413A-GCA",
     "cx4 416A 100G vs 413A 50G (cross board 2p x16)",
     (0x159, 0x2C4, 0x2C6, 0x2C7)),
    ("cx4/12_28_4706/MCX414A-GCA",
     "cx4/12_28_4706/MCX413A-GCA",
     "cx4 414A 2p vs 413A 1p (port count)", ()),
)

SPEED_KEYS = ("link_speed_ena", "link_speed_ext_ena",
              "link_speed_ext_sup", "link_speed_supported")
LCL_SPEED_BIT = {1: 0, 10: 1, 20: 2, 25: 3, 40: 4, 50: 5, 56: 6, 100: 7}
LCL_SPEED_RE = re.compile(
    r"lcl\[0\]\.eth_speeds_supported\.Speed(\d+)Gb\s*=\s*(\S+)\s*$")


def _is_jump(word):
    return (word >> 26) == 0x25 and ((word >> 24) & 1)


def _call_target(word, pc):
    return int(disasm(word, pc).split()[-1], 0)


def _find_param_choice(dc, proto_ldi, getter_rt, load_base=LOAD_BASE):
    """Protocol-choice sites: ETH 0x60c/nbits 0x14 <-> IB 0x776/nbits 0xa.

    Structural anchor (bit-identical Lx 1912 / CX-4 12.28, only the
    proto word and getter literals differ):
      ld.i r5,<proto> ; <port load> ; ands rX,r5,0x3 ;
      op0x36 zero,r5,r1 imm=0x0c02 ; b.f.0xa <ib> ;
      addi r5,zero,0x60c ; addi r6,zero,0x14 ; jump <merge> ;
      [ib] addi r5,zero,0x776 ; addi r6,zero,0xa ;
      [merge] addi r7,zero,0x0 ; addi r8,zero,0x0 ; call <getter> ;
      st.d r4,<ctx>,<slot>
    """
    sites = []
    step = 4
    for o in range(0, len(dc) - 13 * step, step):
        if dc[o:o + 4] != proto_ldi:
            continue
        if dc[o + 8] != 0x2C or dc[o + 10:o + 12] != b"\x00\x03":
            continue  # ands rX,r5,0x3 (o+4 is the port load)
        if dc[o + 12:o + 16] != W_OP36_0C02:
            continue
        w_br = struct.unpack_from(">I", dc, o + 16)[0]
        if not _is_branch(w_br, False, 0xA):
            continue
        if dc[o + 20:o + 24] != W_ADDI_R5_60C or \
                dc[o + 24:o + 28] != W_ADDI_R6_14:
            continue
        w_j = struct.unpack_from(">I", dc, o + 28)[0]
        if not _is_jump(w_j):
            continue
        ib_rt = _branch_target(disasm(w_br, o + 16 + load_base))
        merge_rt = int(disasm(w_j, o + 28 + load_base).split()[-1], 0)
        ib_dc = rt_to_dc(ib_rt, load_base)
        if dc[ib_dc:ib_dc + 4] != W_ADDI_R5_776 or \
                dc[ib_dc + 4:ib_dc + 8] != W_ADDI_R6_0A:
            continue
        merge_dc = rt_to_dc(merge_rt, load_base)
        if dc[merge_dc:merge_dc + 4] != W_ADDI_R7_0 or \
                dc[merge_dc + 4:merge_dc + 8] != W_ADDI_R8_0:
            continue
        w_call = struct.unpack_from(">I", dc, merge_dc + 8)[0]
        if not _is_call(w_call) or \
                _call_target(w_call, merge_rt + 8) != getter_rt:
            continue
        w_store = struct.unpack_from(">I", dc, merge_dc + 12)[0]
        sites.append({
            "proto_rt": o + load_base,
            "proto_word": int(disasm(struct.unpack_from(
                ">I", dc, o)[0], o + load_base).split(",")[-1], 0),
            "eth_param": ETH_PARAM,
            "eth_nbits": ETH_NBITS,
            "eth_branch_rt": o + 20 + load_base,
            "ib_param": IB_PARAM,
            "ib_nbits": IB_NBITS,
            "ib_branch_rt": ib_rt,
            "branch_target": ib_rt,
            "merge_rt": merge_rt,
            "getter_rt": _call_target(w_call, merge_rt + 8),
            "store": {
                "rt": merge_rt + 12,
                "text": disasm(w_store, merge_rt + 12),
            },
            "window": _decode(dc, o, 8, load_base),
        })
    return sites


def find_eth_choice_sites(dc, load_base=LOAD_BASE):
    """Lx protocol-choice sites (rt 0x9ccd4c / 0x9dfeac in 1912-GCA)."""
    return _find_param_choice(dc, W_LDI_R5_38F5, GETTER_LX, load_base)


def find_cx4_eth_choice_sites(dc, load_base=LOAD_BASE):
    """CX-4 12.28 homologs (rt 0x9a60b8 / 0x9b8b68 in MCX456A-ECA)."""
    return _find_param_choice(dc, W_LDI_R5_3A75, GETTER_CX4, load_base)


def find_60c_sites(dc, load_base=LOAD_BASE):
    """All `addi r5,zero,0x60c` sites (ETH-визави param loads).

    4 sites on each generation; every one feeds the same getter (the
    two protocol-choice sites structurally, the two mode-branch sites
    by the same merge idiom).
    """
    sites = []
    step = 4
    for o in range(0, len(dc) - 4, step):
        if dc[o:o + 4] == W_ADDI_R5_60C:
            sites.append(o + load_base)
    return sites


# ------------------------------------------------------ corpus data views

def diff_offsets(a, b):
    """[(off, a[i], b[i])] for every differing byte (0x12 diffs)."""
    n = min(len(a), len(b))
    return [(i, a[i], b[i]) for i in range(n) if a[i] != b[i]]


def _corpus_sec12(corpus_root, rel):
    p = Path(corpus_root) / rel / "sections" / "12" / "dc.bin"
    if not p.is_file():
        raise ValueError("corpus build section not found: %s "
                         "(rebuild: make corpus)" % p)
    return p.read_bytes()


def corpus_eth_speed_diffs(corpus_root):
    """Same-board ETH-speed 0x12 diffs: separate-site search.

    Rows carry the raw diffs plus `outside_tuple` (offsets beyond the
    5-byte EDR-class tuple) and `conforms` (outside_tuple stays inside
    the pair's documented board/port noise allow-list).
    """
    rows = []
    for rel_a, rel_b, label, allowed in ETH_SPEED_PAIRS:
        a = _corpus_sec12(corpus_root, rel_a)
        b = _corpus_sec12(corpus_root, rel_b)
        diffs = diff_offsets(a, b)
        outside = [i for i, _x, _y in diffs if i not in TUPLE_BYTES]
        rows.append({
            "label": label,
            "builds": (rel_a, rel_b),
            "diffs": diffs,
            "outside_tuple": outside,
            "allowed_extra": list(allowed),
            "conforms": set(outside) <= set(allowed),
        })
    return rows


def corpus_ini_link_speed(corpus_root):
    """INI projection rows (0x30 .prs): link_speed_* keys + lcl bit map.

    Every cx4 build carries management.port_info.link_speed_* (values
    track the speed class); every cx4lx build lacks the keys entirely
    (the Lx ETH mask lives in the lcl layer). lcl[0] byte == the
    eth_speeds_supported bit map of the .prs (bit0=1G .. bit7=100G).
    """
    rows = []
    root = Path(corpus_root)
    for fam in ("cx4", "cx4lx"):
        famdir = root / fam
        if not famdir.is_dir():
            continue
        for verdir in sorted(famdir.iterdir()):
            if not verdir.is_dir():
                continue
            for d in sorted(verdir.iterdir()):
                p30 = d / "sections" / "30" / "dc.bin"
                if not p30.is_file():
                    continue
                text = zlib.decompress(p30.read_bytes()).decode("latin1")
                fields = {}
                eth_bits = {}
                for ln in text.splitlines():
                    if "link_speed" in ln and "=" in ln:
                        key, val = ln.split("=", 1)
                        fields[key.strip().split(".")[-1]] = val.strip()
                    m = LCL_SPEED_RE.search(ln)
                    if m:
                        speed = int(m.group(1))
                        if int(m.group(2), 0) and speed in LCL_SPEED_BIT:
                            eth_bits[speed] = 1
                lcl0 = None
                p12 = d / "sections" / "12" / "dc.bin"
                if p12.is_file():
                    lcl0 = p12.read_bytes()[0x30B]
                mask = 0
                for speed in eth_bits:
                    mask |= 1 << LCL_SPEED_BIT[speed]
                rows.append({
                    "build": "%s/%s/%s" % (fam, verdir.name, d.name),
                    "ini_link_speed": {k: v for k, v in fields.items()
                                       if k in SPEED_KEYS},
                    "lcl0": lcl0,
                    "eth_mask": mask,
                })
    return rows


# --------------------------------------------------- tuple + H2 verdict

def eth_tuple(base_path=BASE_REFS, corpus_root=None):
    """EDR-class tuple composition (5 bytes, ECA reference).

    Full identifier set per byte: section, dc offset, stock value,
    ECA target, image (flash) offset, ITOC entry index, CRC sites,
    INI projection, field semantics.
    """
    if corpus_root is None:
        corpus_root = REPO / "build" / "corpus"
    p = Path(base_path)
    img = Image(p.read_bytes(), str(p))
    e = img.find_entry("ITOC", TUPLE_SECTION)
    sec = img.section_data(e)
    eca = _corpus_sec12(corpus_root, ECA_CORPUS_REL)
    ent_off = img.itoc_off + 32 + e.index * 32
    out = []
    for off in TUPLE_BYTES:
        out.append({
            "section": TUPLE_SECTION,
            "offset": off,
            "stock": sec[off],
            "target": eca[off],
            "image_abs": img.sec_abs(e) + off,
            "itoc_index": e.index,
            "crc_sites": {
                "sec_crc": [ent_off + 0x1A, ent_off + 0x1B],
                "entry_crc": [ent_off + 0x1E, ent_off + 0x1F],
            },
            "ini_id": TUPLE_INI[off],
            "field": TUPLE_FIELDS[off],
        })
    return {
        "section": TUPLE_SECTION,
        "reference": "%s (corpus, lcl=%02x/%02x)" % (
            ECA_CORPUS_REL, eca[0x30B], eca[0x317]),
        "bytes": out,
    }


def eth_verdict(base_path=BASE_REFS, corpus_root=None):
    """H2 verdict (spec 2026-11-24-serdes-arc-hf2 §1 H2 / §3 p.2).

    {'mode': 'unified'|'separate'|'stena', 'sites': [...], 'tuple':
    {...}} -- unified: the ETH speed-enable (param 0x60c family) is
    read through the same getter/parsed table as the IB param 0x776
    and every ETH-speed byte of the corpus lives inside the EDR-class
    tuple; separate: ETH-speed bytes outside the tuple (sites list);
    stena: the chain cannot be established. The tuple (with the full
    identifier set) is the G2 patch-set input either way.
    """
    if corpus_root is None:
        corpus_root = REPO / "build" / "corpus"
    _img, _e, dc = load_main_code(base_path)
    lx_choice = find_eth_choice_sites(dc)
    unified_code = len(lx_choice) == 2 and \
        all(s["getter_rt"] == GETTER_LX and s["eth_param"] == ETH_PARAM
            and s["ib_param"] == IB_PARAM for s in lx_choice)

    eca03 = Path(corpus_root) / ECA_CORPUS_REL / "sections" / "03" / \
        "dc.bin"
    if not eca03.is_file():
        raise ValueError("corpus ECA MAIN_CODE view not found: %s "
                         "(rebuild: make corpus)" % eca03)
    edc = eca03.read_bytes()
    cx4_choice = find_cx4_eth_choice_sites(edc)
    homolog = len(cx4_choice) == 2 and \
        all(s["getter_rt"] == GETTER_CX4 for s in cx4_choice)

    fca = _corpus_sec12(corpus_root, FCA_CORPUS_REL)
    eca12 = _corpus_sec12(corpus_root, ECA_CORPUS_REL)
    fca_eca = diff_offsets(fca, eca12)
    fca_eca_ok = [i for i, _x, _y in fca_eca
                  if i not in TUPLE_BYTES] == [] and \
        len(fca_eca) == len(TUPLE_BYTES)

    speed_rows = corpus_eth_speed_diffs(corpus_root)
    separate = [i for r in speed_rows if not r["conforms"]
                for i in r["outside_tuple"]]

    ini_rows = corpus_ini_link_speed(corpus_root)
    ini_by = {r["build"]: r for r in ini_rows}
    ini_ok = ECA_CORPUS_REL in ini_by and \
        FCA_CORPUS_REL in ini_by and \
        ini_by[ECA_CORPUS_REL]["ini_link_speed"] and \
        ini_by[FCA_CORPUS_REL]["ini_link_speed"] and \
        ini_by[ECA_CORPUS_REL]["eth_mask"] == \
        ini_by[ECA_CORPUS_REL]["lcl0"]

    tuple_ = eth_tuple(base_path, corpus_root)
    trace = {
        "lx_choice_sites": lx_choice,
        "cx4_choice_sites": cx4_choice,
        "lx_60c_sites": find_60c_sites(dc),
        "cx4_60c_sites": find_60c_sites(edc),
        "param_math": {
            "eth": {"param": ETH_PARAM, "word": lr.param_word(ETH_PARAM),
                    "field": lr.param_field(ETH_PARAM),
                    "bit": lr.param_bit_offset(ETH_PARAM),
                    "nbits": ETH_NBITS},
            "ib": {"param": IB_PARAM, "word": lr.param_word(IB_PARAM),
                   "field": lr.param_field(IB_PARAM),
                   "bit": lr.param_bit_offset(IB_PARAM),
                   "nbits": IB_NBITS},
        },
        "source": "one IRON parsed table (banks 0xd6c80/0x11c480, "
                  "writer POST_IRON_BOOT from flash records; 0x12 "
                  "carrier live-proven by arc F P1)",
    }
    proof = {
        "fca_eca_diff": "tuple-exact" if fca_eca_ok else "unexpected",
        "speed_pairs": [{k: v for k, v in r.items() if k != "builds"}
                        for r in speed_rows],
        "speed_pairs_all_in_tuple": all(r["conforms"]
                                        for r in speed_rows),
        "ini_projection": "cx4: link_speed_* present; cx4lx: absent "
                          "(lcl carries ETH mask)" if ini_ok else
                          "unexpected",
    }

    if unified_code and homolog and fca_eca_ok and \
            proof["speed_pairs_all_in_tuple"] and ini_ok and \
            not separate:
        mode = "unified"
        sites = []
    elif separate:
        mode = "separate"
        sites = [{
            "kind": "data",
            "section": TUPLE_SECTION,
            "offset": off,
            "note": "ETH-speed byte outside the EDR-class tuple "
                    "(corpus same-board diff)",
        } for off in sorted(set(separate))]
    else:
        mode = "stena"
        sites = []

    return {
        "mode": mode,
        "sites": sites,
        "tuple": tuple_,
        "eth_trace": trace,
        "corpus_proof": proof,
        "h2": "unified: ETH speed-enable (0x60c) and IB (0x776) share "
              "one getter/parsed table; ETH speed bytes live inside "
              "the EDR-class tuple (lcl = advertisement layer, "
              "dw280/dw2c4 = product speed vector). lcl 0xfb alone "
              "opens 100G advertisement (arc D confound): an ETH "
              "100/56 observation is not tuple-delivery proof -- H2 "
              "is settled offline by this verdict.",
    }


def main(argv=None):
    desc = (__doc__ or "").splitlines()[0]
    ap = argparse.ArgumentParser(description=desc)
    ap.add_argument("--base", type=Path, default=BASE_REFS)
    ap.add_argument("--eca", type=Path, default=ECA_REFS)
    ap.add_argument("--out", type=Path, default=SPEC_PATH)
    ap.add_argument("--corpus", type=Path, default=None,
                    help="corpus root for the eth_verdict tuple "
                         "(default build/corpus)")
    a = ap.parse_args(argv)
    spec = build_spec(a.base)
    verdict = polling_verdict(a.base, a.eca)
    report = {"spec": spec, "polling_verdict": verdict,
              "dispatcher": {k: v for k, v in
                             dispatcher_words(a.base).items()
                             if k != "twin"}}
    try:
        report["eth_verdict"] = {k: v for k, v in
                                 eth_verdict(a.base, a.corpus).items()
                                 if k != "eth_trace"}
    except ValueError as exc:
        report["eth_verdict"] = {"error": str(exc)}
    out = json.dumps(report, indent=1, ensure_ascii=False)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(spec, indent=1, ensure_ascii=False) + "\n")
    print(out)
    print("spec written: %s" % a.out, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
