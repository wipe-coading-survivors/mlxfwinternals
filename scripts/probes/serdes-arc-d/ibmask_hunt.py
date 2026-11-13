#!/usr/bin/env python3
"""serdes-arc-d task-02: IB Enabled-mask source hunt in 14.32 Lx MAIN_CODE.

Arc-D offline research tool (plan Task 2). Locates the C12-isomorph
IB stamping site in a corpus MAIN_CODE (arc-A corpus, section 03),
extracts the mask feeder (stock force constant), walks the
find-chain (apply_stamping_ib <- set_pm_speed_and_width <- port
dispatcher), and computes the flash-image patch spec for T3.

Method anchors (docs-first):
  * docs/250-re/130-cable-gate/025-ch3-results.md §7 — C12-isomorph
    chain over the arc-A corpus; 8008 addresses as Rosetta
    (classification 0x28ffe0 / set_pm 0x25ad1c / apply_stamping_ib
    0x25aa5c; module-term ld.d+shr site dc 0x25ab54-58, stock force
    `0011001f` @dc 0x25ab90).
  * docs/250-re/130-cable-gate/002-transceiver-ib-gate.md §6 —
    Lx 14.32 C12-analog: dc 0x1f1f00 (raw 0x37e0f0),
    `fcb1c083` -> `0011001f` (c1 live: pm 0->2, AN path alive).
  * docs/superpowers/reports/cx4lx-sfp28-ib-node-final.md §2-§3 —
    post-stamp mask 0x17 (post-filter artifact), mask patched in
    flash image, not CR.

Site signature (tight, register-agnostic):
  line i:   ld.d rA,rB,0x4c|0x44        (module-term word of the
            0xdc-byte module-class descriptor copied from the record
            table at RAM 0x4a000+class*0x380 — isomorph of the 4030
            record 0x940c+type*0x70 in lw.r index units)
  line i+1: shr rC,rA,0x18              (term byte = mask, word
            `fcb1c083` in every pinned build)
  forward <=20 words: addi rC,zero,IMM (IMM<=0xff) before any other
            write to rC — the stock force path (encoding-identical
            to the C12 replacement word).

Bit map of the mask low byte (prior arc 56-100g, live PDDR
"Enabled (IB)": scripts/probes/sweep_ib_mask.py H2; consistent with
the site code: bit2 mandatory `ands r4,r17,0x4` @1900 rt 0x9f2014,
bit0x10 conditional clear `and r5,r5,0x-11` @rt 0x9f1ff8,
EDR-limiter window 0x7b230+local*0x2800, idiom `or r7,r17,0xffffff00`):

  0x01 SDR  0x02 DDR  0x04 QDR  0x08 FDR10  0x10 FDR  0x20 EDR

Pinned masks (T3 consumes; see task-02 report for the deviation note
vs the plan's "0x0f->0x1f" expectation): L3 (4xFDR) = 0x1f,
L4 (4xEDR) = 0x3f.

Patch-word derivation is encoding-safe by construction: the stock
force word (0x0011_0000 | IMM for IMM<=0xff, i.e. addi r17,zero,IMM)
already exists in each pinned build; the patch copies it over the shr
word with the target IMM. dc->raw flash offset uses the 68B clcrc
line framing (docs/250-re/100-formats/020): raw = (dc//64)*68 + dc%64
+ flash_addr(section 03). Verified: 1900-GCA dc 0x1f1f00 -> image
0x37e0f0 (byte-exact `fcb1c083` in the stock image, = the c1 raw
offset from sfp28-ib-node-final §3); 1912-GCA dc 0x1f2054 -> image
0x37f258 (byte-exact).

Usage:
  ibmask_hunt.py --section-dir build/corpus/cx4lx/14_32_1912/MCX4131A-GCA/sections/03 \
      [--image refs/fw/cx-4/<stock>.bin] [--json OUT]

Stdlib only; offline (no hardware, no ssh).
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

DISASM_RE = re.compile(r"^([0-9a-f]{8})\s+([0-9a-f]{8})\s+(.*)$")
LD_TERM_RE = re.compile(r"^ld\.d (r\d+),(r\d+),0x(4c|44)$")
SHR_RE = re.compile(r"^shr (r\d+),(r\d+),0x18$")
FORCE_RE = re.compile(r"^addi (r\d+),zero,(0x[0-9a-f]+)$")
WRITES_RE = re.compile(r"^(?:or|add|sub|shr|shl|ld\.d|ld\.b|ld\.w|set\d|alu|mask32) (r\d+),")

BIT_MAP = {
    0x01: "SDR",
    0x02: "DDR",
    0x04: "QDR",
    0x08: "FDR10",
    0x10: "FDR",
    0x20: "EDR",
}
MASKS = {
    "L3_4xFDR": 0x1F,
    "L4_4xEDR": 0x3F,
}
FORCE_WINDOW = 20
FORCE_IMM_MAX = 0xFF
LOAD_BASE = 0x800000


class Instr:
    __slots__ = ("addr", "word", "text")

    def __init__(self, addr, word, text):
        self.addr = addr
        self.word = word
        self.text = text


def parse_disasm_lines(lines):
    out = []
    for line in lines:
        m = DISASM_RE.match(line)
        if not m:
            continue
        text = m.group(3).split(";")[0].strip()
        out.append(Instr(int(m.group(1), 16), m.group(2), text))
    return out


def parse_disasm(path):
    return parse_disasm_lines(Path(path).read_text().splitlines())


def addi_force_word(rd, imm):
    if not 0 <= imm <= 0xFFFF:
        raise ValueError(f"imm out of range: {imm:#x}")
    return f"{(0x00 << 24) | (rd << 16) | imm:08x}"


def find_stamp_site(instrs):
    """Tight C12-analog site scan over parsed disasm lines.

    Returns a dict per hit (usually exactly one per MAIN_CODE) or an
    empty list when the signature is absent (negative verdict for the
    wall gate).
    """
    hits = []
    for i in range(len(instrs) - 1):
        m_ld = LD_TERM_RE.match(instrs[i].text)
        if not m_ld:
            continue
        m_shr = SHR_RE.match(instrs[i + 1].text)
        if not m_shr or m_shr.group(2) != m_ld.group(1):
            continue
        tgt = m_shr.group(1)
        force = None
        for j in range(i + 2, min(i + 2 + FORCE_WINDOW, len(instrs))):
            m_f = FORCE_RE.match(instrs[j].text)
            if m_f and m_f.group(1) == tgt:
                imm = int(m_f.group(2), 16)
                if imm <= FORCE_IMM_MAX:
                    force = {
                        "addr_rt": instrs[j].addr,
                        "word": instrs[j].word,
                        "imm": imm,
                    }
                break
            m_w = WRITES_RE.match(instrs[j].text)
            if m_w and m_w.group(1) == tgt:
                break
        hits.append({
            "ld_addr_rt": instrs[i].addr,
            "ld_field": m_ld.group(3),
            "shr_addr_rt": instrs[i + 1].addr,
            "shr_word": instrs[i + 1].word,
            "mask_reg": tgt,
            "force": force,
        })
    return hits


def load_funcs(path):
    rows = []
    for line in Path(path).read_text().splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 5:
            rows.append((int(parts[0], 16), int(parts[1], 16), parts[2],
                         parts[3], int(parts[4])))
    return rows


def load_calls(path):
    rows = []
    for line in Path(path).read_text().splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 2:
            rows.append((int(parts[0], 16), int(parts[1], 16)))
    return rows


def fn_of(funcs, addr):
    for s, e, size, frame, ncallers in funcs:
        if s <= addr < e:
            return {"entry_rt": s, "end_rt": e, "size_words": size,
                    "frame": frame, "n_callers": ncallers}
    return None


def chain_report(section_dir, shr_addr_rt):
    """apply_stamping_ib <- set_pm_speed_and_width <- dispatcher walk."""
    funcs_p = Path(section_dir) / "funcs.tsv"
    calls_p = Path(section_dir) / "calls.tsv"
    if not funcs_p.exists() or not calls_p.exists():
        return {"note": "funcs.tsv/calls.tsv absent; chain not walked"}
    funcs = load_funcs(funcs_p)
    calls = load_calls(calls_p)
    chain = []
    cur = shr_addr_rt
    for level, name in (("apply_stamping_ib", None),
                        ("set_pm_speed_and_width", None),
                        ("dispatcher_zone", None)):
        fn = fn_of(funcs, cur)
        if fn is None:
            chain.append({"role": level, "note": "no enclosing fn"})
            break
        callers = [s for s, t in calls if t == fn["entry_rt"]]
        chain.append({"role": level, **fn, "call_sites_rt": [
            hex(c) for c in callers]})
        if not callers:
            break
        cur = callers[0]
    return {"chain": chain}


def raw_image_offset(dc_off, flash_addr):
    if dc_off < 0 or flash_addr < 0:
        raise ValueError("negative offset")
    line, rem = divmod(dc_off, 64)
    return line * 68 + rem + flash_addr


def read_image_word(image_path, off):
    data = Path(image_path).read_bytes()
    if off + 4 > len(data):
        raise ValueError(f"offset {off:#x} beyond image end {len(data):#x}")
    return data[off:off + 4].hex()


def hunt(section_dir, image=None, flash_addr=None):
    d = Path(section_dir)
    meta_p = d / "meta.json"
    flash = flash_addr
    if flash is None and meta_p.exists():
        meta = json.loads(meta_p.read_text())
        flash = meta.get("flash_addr")
    instrs = parse_disasm(d / "disasm.txt")
    sites = find_stamp_site(instrs)
    report = {
        "section_dir": str(d),
        "load_base": LOAD_BASE,
        "flash_addr": flash,
        "bit_map": {f"{k:#04x}": v for k, v in BIT_MAP.items()},
        "masks": {k: f"{v:#04x}" for k, v in MASKS.items()},
        "sites": [],
    }
    for s in sites:
        dc = s["shr_addr_rt"] - LOAD_BASE
        entry = dict(s)
        entry["shr_addr_dc"] = dc
        entry["golden"] = s["shr_word"] == "fcb1c083" and s["force"] is not None
        if s["force"]:
            entry["patch_words"] = {
                name: addi_force_word(int(s["mask_reg"][1:]), imm)
                for name, imm in MASKS.items()
            }
        if flash is not None:
            entry["raw_image_offset"] = raw_image_offset(dc, flash)
            if image:
                entry["image_word_at_offset"] = read_image_word(
                    image, entry["raw_image_offset"])
        entry["chain"] = chain_report(d, s["shr_addr_rt"])
        report["sites"].append(entry)
    return report


def main(argv=None):
    desc = (__doc__ or "ibmask hunt").splitlines()[0]
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--section-dir", action="append", required=True,
                        help="corpus section dir (e.g. build/corpus/cx4lx/"
                             "14_32_1912/MCX4131A-GCA/sections/03)")
    parser.add_argument("--image", action="append",
                        help="stock flash image to verify the raw word "
                             "(paired with --section-dir order)")
    parser.add_argument("--flash-addr", type=lambda x: int(x, 0),
                        action="append",
                        help="override section-03 flash_addr (decimal or "
                             "0x-hex; pairs with --section-dir order)")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    reports = []
    for i, sd in enumerate(args.section_dir):
        img = args.image[i] if args.image and i < len(args.image) else None
        fa = args.flash_addr[i] if args.flash_addr and i < len(
            args.flash_addr) else None
        reports.append(hunt(sd, image=img, flash_addr=fa))

    out = json.dumps(reports, indent=1)
    if args.json:
        args.json.write_text(out + "\n")
    print(out)
    n = sum(len(r["sites"]) for r in reports)
    pinned = all(any(s.get("golden") for s in r["sites"])
                 for r in reports)
    print(f"sites={n} golden_pinned={'yes' if pinned else 'NO'}",
          file=sys.stderr)
    return 0 if (n and pinned) else 1


if __name__ == "__main__":
    raise SystemExit(main())
