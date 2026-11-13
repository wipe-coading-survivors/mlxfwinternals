#!/usr/bin/env python3
"""Build the C9a-v2 runtime-injection spec (live RAM dump of the SFP28 gate chain).

C9a design (c9-injection-report) re-applied on the CURRENT bazzite lineage
base 4030graft-vpi0-c4c6-c7-c8-bazzite.bin: boot detour dc 0x1d594,
scheduler hooks dc 0x2ae82c/0x2ae87c, cpu0-gated 39-word dump routines,
host-CR 0x23f0 slot-walk protocol, guard 0xbadc0ffe, table @ runtime
0xb8d880. Shellcode is byte-identical to C9a (code layout unchanged);
the only delta vs the C9a spec is the dump TABLE (slots 26-31):

- C8 burn verdict (c8-burn-report) pinned 0x3498 bit1/bit2 as the main
  residual unknown (mode gate feeding driver 0x2a9e04 -> sink 0x1edab4),
  so the 6 C9a repeat slots (G1,G2,S0,S1,T0,T1) are replaced by the gate
  word 0x3498 (byte 0xd260) + its PM-fed neighbors 0x3499..0x349d
  (bytes 0xd264..0xd274). 0x349e/0x349f do not fit the 32-entry walk
  (idx is 5-bit) and are dropped.
- idx 0-25 unchanged vs C9a: G1/G2/G3 cap globals, T0/T1 type containers,
  M0 word 0x800, R44/R3c records t=0..7, S0/S1 status words (bitaddr
  0x4f1ee+port*0x60 IS word 0x9e3c+port*0xc bits 17-18 — same word, so
  the notify-field request is covered by S0/S1), W0/W1 raw PM-window
  slots. All 32 entries distinct -> decode is unambiguous.
"""
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes"))
sys.path.insert(0, str(REPO / "scripts" / "irisc"))
from mlxfwutil import Image
from iron_boot_probe import decrc
import irisc_dis
import enc

SLOT = 0x38d730
BOOT_ENTRY = 0x38d730
MARKER = 0x5A5A0001
CR_CHAN = 0x23F0
GUARD = 0xBADC0FFE
TAG_BASE = 0xD0000000
SUBST_BASE = 0xFE000000
TBL_N = 32

TABLE_SRC = [
    (0x0000D330, "G1: cap global word 0x34cc (byte 0xd330)"),
    (0x0000D338, "G2: cap global word 0x34ce (byte 0xd338)"),
    (0x0000D3EC, "G3: cap global word 0x34fb (byte 0xd3ec)"),
    (0x0000B820, "T0: port0 module-type container (bit 0x5c107)"),
    (0x0000B8B8, "T1: port1 module-type container (bit 0x5c5c7)"),
    (0x00002000, "M0: RAM word 0x800 (module type global)"),
]
for t in range(8):
    TABLE_SRC.append((0x9450 + 0x70 * t, "R44[t=%d]: record 0x940c+0x70t+0x44 (SCS feeder)" % t))
for t in range(8):
    TABLE_SRC.append((0x9448 + 0x70 * t, "R3c[t=%d]: record 0x940c+0x70t+0x3c" % t))
TABLE_SRC += [
    (0x00009E3C, "S0: status word port0 = bitaddr 0x4f1ee+0*0x60 (b0 present, b17-18 status)"),
    (0x00009E48, "S1: status word port1 = bitaddr 0x4f1ee+1*0x60 (b0 present, b17-18 status)"),
    (0x0000F690, "W0: raw PM-window slot word port0 (bit 0x7b494)"),
    (0x0000FD10, "W1: raw PM-window slot word port1 (bit 0x7e894)"),
    (0x0000D260, "MODE: residual gate word 0x3498 (bit1 gate A/driver, bit2 sink select)"),
    (0x0000D264, "N99: PM-fed neighbor word 0x3499"),
    (0x0000D268, "N9a: PM-fed neighbor word 0x349a"),
    (0x0000D26C, "N9b: PM-fed neighbor word 0x349b"),
    (0x0000D270, "N9c: PM-fed neighbor word 0x349c"),
    (0x0000D274, "N9d: PM-fed neighbor word 0x349d"),
]
assert len(TABLE_SRC) == TBL_N
assert len(set(s for s, _ in TABLE_SRC)) == TBL_N

HOOKS = [
    (0x1D594, 0x940002DE, BOOT_ENTRY, "boot detour: call 0x1e10c -> call boot stub (docs/250-re/120-irisc/025-boot-injection.md v3 verbatim 0x940dc067)"),
    (0x2AE82C, 0x94F5BDD2, None, "work-dispatch hook: call 0x1df74 -> call routine W"),
    (0x2AE87C, 0x94FFFE28, None, "idle-sample hook: call 0x2ae11c -> call routine I"),
]


def w_lw_r(rd, rs, rt):
    return (0x3F << 26) | (rs << 21) | (rd << 16) | (rt << 11) | 0x19


def w_alu(funct, rd, rs, rt):
    return (0x3F << 26) | (rs << 21) | (rd << 16) | (rt << 11) | funct


class Asm:
    def __init__(self, base):
        self.base = base
        self.words = []

    def emit(self, word, note):
        self.words.append((word, note))

    def addr(self, i):
        return self.base + 4 * i


def build_boot_stub():
    a = Asm(0x38D730)
    a.emit(enc.set2(5, 0x0000), "r5 = 0")
    a.emit(enc.set3(5, 5, CR_CHAN), "r5 = 0x23f0 (host-CR channel)")
    a.emit(enc.set2(6, MARKER >> 16), "r6 = 0x5a5a0000")
    a.emit(enc.set3(6, 6, MARKER & 0xFFFF), "r6 = 0x5a5a0001 boot marker")
    a.emit(enc.st_d(6, 5, 0), "[0x23f0] = marker")
    a.emit(enc.jump(a.addr(5), 0x1E10C), "resume main init (docs/250-re/120-irisc/025-boot-injection.md verbatim)")
    return a


def build_routine(base, exit_note, arg_fixup, exit_target, tbl_lo):
    """arg_fixup: list of (encoder-lambda, note) words emitted at EXIT before the jump."""
    a = Asm(base)
    gate = [
        (0x48040004, "csr.r r4,cpuinfo"),
        (0xC8840124, "mask32 r4,r4,0,4 (cpu id; blob-verbatim 0x2ae778)"),
        (enc.subsi(4, 4, 0), "subsi r4,r4,0"),
    ]
    for w, n in gate:
        a.emit(w, n)
    i_btag = len(a.words)
    a.emit(0, "b.t.0x0 zero,GO (cpu==0)")
    i_jexit1 = len(a.words)
    a.emit(0, "jump EXIT (non-cpu0: pass through)")
    i_go = len(a.words)
    a.emit(enc.set2(5, 0x0000), "GO: r5 = 0")
    a.emit(enc.set3(5, 5, CR_CHAN), "r5 = 0x23f0")
    a.emit(enc.ld_d(4, 5, 0), "r4 = slot value V")
    br_idx = []
    for sh, kind in ((31, "clr"), (30, "clr"), (29, "set"), (28, "clr")):
        br_idx.append(len(a.words))
        a.emit(0, "b.b%s %d,r4,NOTAG (tag top nibble 0xD test)" % (kind, sh))
    a.emit((0x0B << 26 | (4 << 21) | (4 << 16) | 0x1F), "VAL: ands r4,r4,0x1f (idx from tag)")
    a.emit(enc.set2(6, 0x00B8), "r6 = 0x00b80000 (table hi)")
    a.emit(enc.set3(6, 6, tbl_lo), "r6 = table byte base 0x%08x" % (0x00B80000 | tbl_lo))
    a.emit(enc.shl64_i(4, 4, 2), "r4 = idx*4")
    a.emit(w_alu(0x00, 6, 6, 4), "r6 = &table[idx]")
    a.emit(w_lw_r(6, 6, 0), "r6 = source byte addr (lw.r)")
    a.emit(w_lw_r(4, 6, 0), "r4 = value = mem32[source] (lw.r)")
    a.emit(enc.set2(6, GUARD >> 16), "r6 = 0xbadc0000")
    a.emit(enc.set3(6, 6, GUARD & 0xFFFF), "r6 = 0xbadc0ffe guard")
    a.emit(enc.cmp38(0, 4, 6, 2), "cmp.w r4,r6 -> cmpres=(value==guard)")
    a.emit(enc.ld_d(6, 5, 0), "r6 = re-read tag from slot")
    i_bsubst = len(a.words)
    a.emit(0, "b.t.cmpres SUBST")
    a.emit(enc.st_d(4, 5, 0), "[0x23f0] = value")
    i_jexit2 = len(a.words)
    a.emit(0, "jump EXIT")
    i_subst = len(a.words)
    a.emit((0x0B << 26) | (6 << 21) | (6 << 16) | 0x1F, "SUBST: ands r6,r6,0x1f (idx)")
    a.emit(enc.set2(4, SUBST_BASE >> 16), "r4 = 0xfe000000")
    a.emit(w_alu(0x00, 4, 4, 6), "r4 = 0xfe000000|idx")
    a.emit(enc.st_d(4, 5, 0), "[0x23f0] = guard substitute")
    i_jexit3 = len(a.words)
    a.emit(0, "jump EXIT")
    i_notag = len(a.words)
    a.emit(enc.addi(4, 4, 1), "NOTAG: r4 = V+1")
    a.emit((0x0B << 26) | (4 << 21) | (4 << 16) | 0x1F, "ands r4,r4,0x1f (next idx)")
    a.emit(enc.set2(6, TAG_BASE >> 16), "r6 = 0xd0000000")
    a.emit(w_alu(0x00, 6, 6, 4), "r6 = 0xd0000000|idx (tag)")
    a.emit(enc.st_d(6, 5, 0), "[0x23f0] = tag")
    i_jexit4 = len(a.words)
    a.emit(0, "jump EXIT")
    i_exit = len(a.words)
    for w, n in arg_fixup:
        a.emit(w, n)
    a.emit(enc.jump(a.addr(i_exit + len(arg_fixup)), exit_target), exit_note)

    for i in br_idx:
        kind = "clr" if i in (br_idx[0], br_idx[1], br_idx[3]) else "set"
        sh = {br_idx[0]: 31, br_idx[1]: 30, br_idx[2]: 29, br_idx[3]: 28}[i]
        encf = enc.b_bclr if kind == "clr" else enc.b_bset
        a.words[i] = (encf(sh, 4, a.addr(i), a.addr(i_notag)), a.words[i][1])
    a.words[i_btag] = (enc.b_t(0x0, a.addr(i_btag), a.addr(i_go)), a.words[i_btag][1])
    a.words[i_bsubst] = (enc.b_t(0x0A, a.addr(i_bsubst), a.addr(i_subst)), a.words[i_bsubst][1])
    for i in (i_jexit1, i_jexit2, i_jexit3, i_jexit4):
        tgt = a.addr(i_exit)
        a.words[i] = (enc.jump(a.addr(i), tgt), a.words[i][1])
    return a


def decode_expect(w, off):
    return irisc_dis.dis(w, off)


def main():
    lineage = REPO / "build" / "4030graft-vpi0-c4c6-c7-c8-bazzite.bin"
    img = Image(lineage.read_bytes(), str(lineage))
    e = img.find_entry("ITOC", 3)
    code = decrc(img.section_data(e))
    for dc, orig, _t, _n in HOOKS:
        cur = struct.unpack_from(">I", code, dc)[0]
        assert cur == orig, "hook site 0x%x: expected %08x got %08x" % (dc, orig, cur)
    assert struct.unpack_from(">I", code, 0x1EDAE4)[0] == 0x00170002, "C8 word missing on base"
    for off in range(SLOT, 0x38DBE8, 4):
        assert struct.unpack_from(">I", code, off)[0] == 0, "slot not zero at 0x%x" % off

    boot = build_boot_stub()
    w_routine = build_routine(
        0x38D748,
        "tail-jump to 0x1df74 (original callee)",
        [(enc.set3(4, 0, 0x8111), "restore r4 = 0x8111 (callee arg, was 0x2ae828)")],
        0x1DF74,
        0,
    )
    i_base = 0x38D748 + 4 * len(w_routine.words)
    i_routine = build_routine(
        i_base,
        "tail-jump to 0x2ae11c (original callee)",
        [(w_alu(0x08, 4, 23, 23), "restore r4 = r23 (clock buf ptr, was 0x2ae878)")],
        0x2AE11C,
        0,
    )
    tbl_dc = i_base + 4 * len(i_routine.words)
    tbl_runtime_lo = (0x800000 + tbl_dc) & 0xFFFF
    for a in (w_routine, i_routine):
        for idx, (w, n) in enumerate(a.words):
            if "table byte base" in n:
                a.words[idx] = (enc.set3(6, 6, tbl_runtime_lo), "r6 = table byte base 0x%08x" % (0x00B80000 | tbl_runtime_lo))

    patches = []
    for dc, orig, tgt, note in HOOKS:
        if tgt is None:
            tgt = w_routine.addr(0) if dc == 0x2AE82C else i_routine.addr(0)
        patches.append({"offset": "0x%x" % dc, "bytes": "%08x" % enc.call(dc, tgt),
                        "expected_before": "%08x" % orig, "kind": "code", "note": note})

    listing = []
    for a, name in ((boot, "boot stub @0x38d730"), (w_routine, "routine W @0x%08x" % w_routine.addr(0)),
                    (i_routine, "routine I @0x%08x" % i_routine.addr(0))):
        listing.append("== %s (%d words)" % (name, len(a.words)))
        for idx, (w, n) in enumerate(a.words):
            off = a.addr(idx)
            dec = decode_expect(w, off)
            listing.append("  %08x  %08x  %-44s | %s" % (off, w, dec, n))
            patches.append({"offset": "0x%x" % off, "bytes": "%08x" % w,
                            "expected_before": "00000000", "kind": "code", "note": "%s: %s" % (name, n)})
    listing.append("== dump table @0x%08x (runtime 0x%08x, %d words)" % (tbl_dc, 0x800000 + tbl_dc, TBL_N))
    for idx, (src, note) in enumerate(TABLE_SRC):
        w = src
        listing.append("  %08x  %08x  -> mem32[0x%08x]  | [%02d] %s" % (tbl_dc + 4 * idx, w, src, idx, note))
        patches.append({"offset": "0x%x" % (tbl_dc + 4 * idx), "bytes": "%08x" % w,
                        "expected_before": "00000000", "kind": "data", "note": "table[%02d]: %s" % (idx, note)})

    end = tbl_dc + 4 * TBL_N
    assert end <= SLOT + 223 * 4, "shellcode overruns 223-word budget: end 0x%x" % end
    total = (end - SLOT) // 4
    print("\n".join(listing))
    print("slot usage: %d/%d words (budget 223), end dc 0x%x (slot ends 0x38dbe8)" % (total, 302, end))

    for p in patches:
        off = int(p["offset"], 0)
        w = int(p["bytes"], 16)
        if p["kind"] == "code":
            dec = decode_expect(w, off)
            if (w >> 26) == 0x38:
                assert (w >> 21) & 0x1F == 4 and (w >> 11) & 0x1F == 6 and (w & 0xFFFF) == 0x3002, \
                    "cmp.w field mismatch at 0x%x: %08x" % (off, w)
            else:
                assert not dec.startswith("op0x"), "unverifiable word at 0x%x: %08x -> %s" % (off, w, dec)
    spec = {"id": "C9a2", "card": "cx5-16_35_4030-ACA-graft", "section": 3, "patches": patches}
    out = REPO / "build" / "ch3-spec-c9a2.json"
    out.write_text(json.dumps(spec, indent=2) + "\n")
    print("spec: %s (%d patch words)" % (out, len(patches)))


if __name__ == "__main__":
    main()
