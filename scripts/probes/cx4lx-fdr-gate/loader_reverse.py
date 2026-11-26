#!/usr/bin/env python3
"""cx4lx-fdr-gate: 0x12->RAM loader reverse (arc F / F2).

Offline research tool (journal
docs/superpowers/journal/2026-11-23-serdes-arc-f-task-01.md).
Findings encoded here:

  * The runtime parsed-INI table is NOT plain image RAM: MAIN_CODE's
    getter (Lx 14.32.1912 rt 0xa0bfb8, 168 callers; param 0x776 = word 14
    field 3) is an IPC *client* of a keyed mailbox (helper 0xa0bef8:
    lock word (tag<<17)|0xe000/0xc000, bit-30 spin, 3-dword payload),
    banks 0xd6c80 / 0x11c480 (Lx) / 0x11c880 (CX-4 12.28).  No server
    exists anywhere in the image sections -> the table lives in the IRON
    coprocessor domain (IRON_PREP_CODE/POST_IRON_BOOT naming, "from
    IRON" strings in MAIN_CODE).
  * The table *writer* inside the image is POST_IRON_BOOT (section 06,
    ITOC param1 entry 0x740254): zero-init of 0x1000 table words through
    bank A, then per-record fill -- records are read from flash through
    the csr 0x101/0x100 engine (16-byte transactions from the 0xf410
    window, completion = RAM word 0xc100 bit 30), sources/counts from
    the ROM-staged header words RAM 0x38f0..0x38f4 (no image-code writer
    exists: st.i cannot reach (imm11), no register-constant emitters in
    sections 02-07; BOOT_CODE section 0x01 is absent from the image).
  * Loader param->word remap: region thresholds 0x27, 0x2c7, .. 0x2f67
    (stride 0x2a0, 19 boundaries -> 20 regions), word' = region*0x2A0 -
    param (inverted in-region index), bank B only for region 1.
    The chain is word-for-word conserved between Lx 14.32 and CX-4 12.28
    (only RAM-word/CSR literals differ).
  * Event-dispatcher special path (Lx 0x9be0f4 vs CX-4 0x9979cc), cc
    polarity per iRISC.slaspec (cc2=lt32 N, cc3=ugt32 C==1,
    cc4=ult32 !Z&&!C; subsi C=RS>imm; subs C=RT<RS):
      Lx:   special  <=>  event==0 OR event > bits[9..11](mirror 0x3686)
      CX-4: special  <=>  event==0 OR event >= 3 (constant)
    mirror_field=2 reproduces CX-4 behavior bit-for-bit.  This corrects
    the codehunt journal reading ("event==1 OR event==mask").

Usage:
  loader_reverse.py [--corpus DIR] [--section06 DIR] [--json OUT]
      [--require-corpus]

Stdlib only; offline (no hardware, no ssh).
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
DEFAULT_CORPUS = REPO / "build" / "corpus"

# --- loader constants (POST_IRON_BOOT, section 06) ------------------------
BANK_A = 0xD6C80
BANK_B_LX = 0x11C480
BANK_B_CX4 = 0x11C880
ZERO_INIT_ITERATIONS = 0x1000
FLASH_WINDOW = 0xF0410
FLASH_HANDSHAKE = 0xC100
HEADER_WORDS = (0x38F0, 0x38F1, 0x38F2, 0x38F3, 0x38F4)

# 0x740528 threshold chain: subsi r6,r5,<th>; b.t.0x3 -> r6=idx
REGION_THRESHOLDS = (
    0x27, 0x2C7, 0x567, 0x807, 0xAA7, 0xD47, 0xFE7, 0x1287, 0x1527,
    0x17C7, 0x1A67, 0x1D07, 0x1FA7, 0x2247, 0x24E7, 0x2787, 0x2A27,
    0x2CC7, 0x2F67,
)

# --- cc-slot formulas (iRISC.slaspec, canon; slaspec lines 168-184) -------
CC_SLOTS = {
    0x0: "eq32",    # Z32
    0x1: "gt32",    # C32 == 1  (no-borrow: a > b unsigned, >= when equal)
    0x2: "lt32",    # N32 == 1  (signed negative result)
    0x3: "ugt32",   # C32 == 1
    0x4: "ult32",   # Z32 == 0 && C32 == 0 (borrow: a < b unsigned)
    0xA: "cmpres",
    0xC: "neg32",
    0xD: "pos32",
}

# --- corpus class bytes ----------------------------------------------------
CLASS_BYTE = 0x158        # 0x12: {eth 0x30, fdr 0x10, edr 0x31}
FAMILY_BYTE_0x151 = 0x151  # 0x12: Lx 0x27 / cx4 0x21
DW_0x280_OFF = 0x280      # 0x12 dword: product-speed vector
DW_0x2C4_OFF = 0x2C4      # 0x12 dword: secondary product bits
SEC11_0x35 = 0x35         # 0x11: FCA<->ECA single-byte diff; Lx all 0x00
LCL0_BYTE = 0x30B

DIS_LINE_RE = re.compile(r"^([0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)$")
SET2_RE = re.compile(r"^set2 (r\d+),(r\d+|zero),(0x[0-9a-f]+)$")
SET3_RE = re.compile(r"^set3 (r\d+),(r\d+|zero),(0x[0-9a-f]+)$")
SUBSI_RE = re.compile(r"^subsi (r\d+),(r\d+),(0x[0-9a-f]+)$")
LDI_RE = re.compile(r"^ld\.i (r\d+),(0x[0-9a-f]+)$")


# ------------------------------------------------------------ param math

def param_word(param):
    """Getter 0xa0bfb8: mailbox tag = param>>7 (table word index)."""
    return param >> 7


def param_field(param):
    """mask32 r4,r17,0x5,2 -> (param>>5)&3 (field inside 96-bit word)."""
    return (param >> 5) & 3


def param_bit_offset(param):
    """Bit offset inside the 96-bit entry: field*20 + (31 - low5).

    r6 = field*20 (shl 4 + shl 2 add) + (~param & 0x1f) = 31 - low5.
    """
    return param_field(param) * 20 + (31 - (param & 0x1F))


def region_for_param(param):
    """Number of REGION_THRESHOLDS <= param (0-based region index)."""
    return sum(1 for t in REGION_THRESHOLDS if t <= param)


def loader_word_remap(param):
    """0x740414 in-region inverted index: word' = region*0x2A0 - param."""
    return region_for_param(param) * 0x2A0 - param


# ------------------------------------------------- special-path polarity

def mirror_field(mirror):
    """mask32 rd,rs,0x9,3: 3 is the mask NUMBER -> &((1<<3)-1)=bits 9..11."""
    return (mirror >> 9) & 7


def special_path_lx(event, field):
    """Lx 0x9be0f4: subsi e-1/b.t.0x2 (event==0) OR subs e-f/b.f.0x3
    (continue while C==1 <=> event > field)."""
    return event == 0 or event > field


def special_path_cx4(event):
    """CX-4 0x9979cc: subsi e-1/b.t.0x2 (event==0) OR subsi e-3 with
    b.t.0x4 skip on borrow (event<3) -> special when event>=3."""
    return event == 0 or event >= 3


# ------------------------------------------------------- disasm scanning

def load_dis(path):
    lines = []
    text = Path(path).read_text().splitlines()
    for ln in text:
        m = DIS_LINE_RE.match(ln)
        if m:
            lines.append((int(m.group(1), 16), m.group(2)))
    return lines


def find_bank_emits(lines):
    """set2/set3 pairs building full constants -> {constant: site_addr}."""
    banks = {}
    for i, (addr, txt) in enumerate(lines):
        m = SET2_RE.match(txt)
        if not m:
            continue
        rd, _rs, hi = m.group(1), m.group(2), int(m.group(3), 0)
        for j in range(i + 1, min(i + 4, len(lines))):
            m3 = SET3_RE.match(lines[j][1])
            if m3 and m3.group(1) == rd:
                val = (hi << 16) | int(m3.group(3), 0)
                if val in (BANK_A, BANK_B_LX, BANK_B_CX4):
                    banks[val] = addr
                break
            if m3:
                break
    return banks


def find_zero_init(lines):
    """0x7403ac: loop mailbox(bank=0, tag=i, WRITE) terminated by
    `subsi rX,rY,0x1000; b.f.0x0 <backward>` with the client call and
    `addi rZ,zero,0x1` (write-mode arg) inside the 10 lines above."""
    for i, (addr, txt) in enumerate(lines):
        m = SUBSI_RE.match(txt)
        if not m or int(m.group(3), 0) != ZERO_INIT_ITERATIONS:
            continue
        if i + 1 >= len(lines):
            continue
        mb = re.match(r"^b\.f\.0x[0-9a-f]+ zero,(0x[0-9a-f]+)$",
                      lines[i + 1][1])
        if not mb or int(mb.group(1), 0) > addr:
            continue  # must jump backward (loop)
        window = [t for _a, t in lines[max(0, i - 10):i]]
        if not any(t.startswith("call ") for t in window):
            continue
        # mailbox write-mode convention: addi r7,zero,0x1 + bank 0
        if "addi r7,zero,0x1" not in window:
            continue
        if "addi r4,zero,0x0" not in window:
            continue
        return {
            "site_subsi": addr,
            "iterations": ZERO_INIT_ITERATIONS,
            "bank_selector": 0,
        }
    return None


def find_region_thresholds(lines):
    """0x740528 chain: subsi r6,r5,<th>; b.t.0x3 -> jump into setter."""
    vals = []
    first_site = None
    for i, (addr, txt) in enumerate(lines):
        m = SUBSI_RE.match(txt)
        if not m or m.group(2) != "r5":
            continue
        val = int(m.group(3), 0)
        nxt = lines[i + 1][1] if i + 1 < len(lines) else ""
        if not re.match(r"^b\.[tf]\.0x3 zero,", nxt):
            continue
        if val not in REGION_THRESHOLDS:
            continue
        if not vals:
            first_site = addr
        elif val != vals[-1] + 0x2A0:
            break
        vals.append(val)
    if len(vals) < 4:
        return None
    return {"first_site": first_site, "values": vals}


def find_header_reads(lines):
    """ROM-staged loader header words, by structural signature (build
    specific: Lx 1912 0x38f0..0x38f4, CX-4 12.28 0x3a70..0x3a74):

      loop A: ld.i W3; ld.i W4; andmsk.hi rX,rX,0x3f; addi rX,rX,0x3
      loop B: ld.i W0; ld.i W1; ld.i W2; andmsk.hi rX,rX,0x3f;
              addi rX,rX,0xf
    """
    seen = []
    for i, (_addr, txt) in enumerate(lines):
        if "andmsk.hi" not in txt or "0x3f" not in txt:
            continue
        for j in range(i + 1, min(i + 3, len(lines))):
            m = re.match(r"^addi (r\d+),r\d+,(0x3|0xf)$", lines[j][1])
            if not m:
                continue
            want = 2 if m.group(2) == "0x3" else 3
            words = []
            k = i - 1
            while k >= 0 and len(words) < want:
                mm = LDI_RE.match(lines[k][1])
                if mm:
                    words.insert(0, int(mm.group(2), 0))
                elif not lines[k][1].startswith("ld.i"):
                    break
                k -= 1
            if len(words) == want:
                seen.extend(words)
            break
    return seen


def find_flash_window(lines):
    """set2 rN,zero,0xf + set3 rN,rN,0x410 -> 0xF0410 data window."""
    for i, (addr, txt) in enumerate(lines):
        m = SET2_RE.match(txt)
        if not m or m.group(2) != "zero" or int(m.group(3), 0) != 0xF:
            continue
        for j in range(i + 1, min(i + 3, len(lines))):
            m3 = SET3_RE.match(lines[j][1])
            if m3 and m3.group(1) == m.group(1) and \
                    int(m3.group(3), 0) == (FLASH_WINDOW & 0xFFFF):
                return FLASH_WINDOW
            if m3:
                break
    return None


def find_entry(lines):
    """Entry (ITOC param1 0x740254): the `call <stack-setup>` that is
    followed by st.d! / call <main> / self-parking `jump <own addr>`."""
    for i, (addr, txt) in enumerate(lines):
        if not txt.startswith("jump "):
            continue
        try:
            tgt = int(txt.split()[-1], 0)
        except ValueError:
            continue
        if tgt != addr:
            continue  # self-park
        for j in range(max(0, i - 3), i):
            if lines[j][1].startswith("call "):
                return lines[j][0]
    return None


def find_mailbox_client(lines):
    """Function whose first instructions are the bank-select subsi/b.t
    (0x7402ec / 0xa0bef8 pattern: subsi rX,r4,0x1 then b.t.0x0)."""
    for i, (addr, txt) in enumerate(lines):
        m = SUBSI_RE.match(txt)
        if not m or m.group(2) != "r4" or int(m.group(3), 0) != 1:
            continue
        if i + 1 < len(lines) and "b.t.0x0" in lines[i + 1][1]:
            # banks must be emitted right after the branch
            window = [t for _a, t in lines[i + 2:i + 8]]
            if any("set3" in t and "0x6c80" in t for t in window):
                return addr
    return None


def scan_loader(section_dir):
    """Scan one section directory (disasm.txt) for the loader chain."""
    d = Path(section_dir)
    dis = d / "disasm.txt"
    if not dis.exists():
        return None
    lines = load_dis(dis)
    entry = find_entry(lines)
    header = find_header_reads(lines)
    return {
        "section_dir": str(d),
        "entry": entry,
        "header_base": min(header) if header else None,
        "banks": find_bank_emits(lines),
        "zero_init": find_zero_init(lines),
        "region_thresholds": find_region_thresholds(lines),
        "header_reads": find_header_reads(lines),
        "flash_window": find_flash_window(lines),
        "flash_handshake": FLASH_HANDSHAKE,
        "mailbox_client": find_mailbox_client(lines),
    }


# ------------------------------------------------------ corpus class scan

def scan_build_classes(build_dir):
    d = Path(build_dir)
    s11 = d / "sections" / "11" / "dc.bin"
    s12 = d / "sections" / "12" / "dc.bin"
    if not s11.exists() or not s12.exists():
        return None
    b11 = s11.read_bytes()
    b12 = s12.read_bytes()
    return {
        "class_0x158": b12[CLASS_BYTE],
        "family_byte_0x151": b12[FAMILY_BYTE_0x151],
        "dw_0x280": struct.unpack_from(">I", b12, DW_0x280_OFF)[0],
        "dw_0x2c4": struct.unpack_from(">I", b12, DW_0x2C4_OFF)[0],
        "sec11_0x35": b11[SEC11_0x35],
        "lcl0": b12[LCL0_BYTE],
    }


def scan_corpus_classes(corpus_root):
    rows = {}
    root = Path(corpus_root)
    for fam in ("cx4", "cx4lx"):
        famdir = root / fam
        if not famdir.is_dir():
            continue
        for verdir in sorted(famdir.iterdir()):
            if not verdir.is_dir():
                continue
            for d in sorted(verdir.iterdir()):
                r = scan_build_classes(d)
                if r:
                    rows[f"{fam}/{verdir.name}/{d.name}"] = r
    return rows


def classify_class_byte(v):
    return {0x10: "ib-fdr", 0x31: "ib-edr"}.get(v, "eth")


def f3_targets(rows, base):
    """F3 patch-candidate derivation for `base` (key into rows).

    P1 (minimal byte): 0x12+0x158 0x30->0x10 (FCA-like FDR class).
    Rationale from the corpus map: FCA carries dw_0x280=0 and dw_0x2c4=0
    exactly like every ETH Lx build, so no other 0x12 dword must move for
    the FDR class byte.
    P2 (ECA-like tuple): 0x12+0x158 0x30->0x31 (EDR class byte) plus
    dword@+0x280 -> 0x12 and dword@+0x2c4 -> 0x00100000 (the FCA<->ECA
    carrier diff minus the lcl advertisement bytes).
    Open questions (owner decision input): 0x11+0x35 (FCA 0x12 vs Lx
    0x00, boot-time section, single byte) and the ROM-staged loader
    header (RAM 0x38f0..0x38f4) whose flash source region is not
    image-addressable.
    """
    row = rows[base]
    cur = row["class_0x158"]
    p1 = []
    p2 = []
    if cur == 0x30:
        p1.append(("12", CLASS_BYTE, 0x10))
        p2.append(("12", CLASS_BYTE, 0x31))
    if row["dw_0x280"] != 0x12:
        p2.append(("12", DW_0x280_OFF + 3, 0x12))  # byte view of dword
    if row["dw_0x2c4"] != 0x00100000:
        p2.append(("12", DW_0x2C4_OFF + 1, 0x10))
    return {
        "p1": p1,
        "p2_eca_like": p2,
        "base_class": classify_class_byte(cur),
        "open_questions": [
            "sec11+0x35: FCA=0x12 vs Lx=0x00 (FW_BOOT_CFG, boot-time)",
            "loader header RAM 0x38f0..0x38f4 staged by ROM/hw; flash "
            "source region of the records not provable from the image",
        ],
    }


def main(argv=None):
    desc = (__doc__ or "").splitlines()[0]
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--section06", type=Path, default=None,
                        help="scan a single section-06 dir for the loader")
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--require-corpus", action="store_true")
    args = parser.parse_args(argv)

    report = {"loader": None, "classes": {}, "f3": None}
    if args.section06:
        report["loader"] = scan_loader(args.section06)
    rows = scan_corpus_classes(args.corpus)
    for k, v in sorted(rows.items()):
        v = dict(v)
        v["class"] = classify_class_byte(v["class_0x158"])
        report["classes"][k] = v
    base_key = "cx4lx/14_32_1912/MCX4131A-GCA"
    if base_key in rows:
        report["f3"] = f3_targets(rows, base_key)
    out = json.dumps(report, indent=1)
    if args.json:
        args.json.write_text(out + "\n")
    print(out)
    print("builds=%d" % len(rows), file=sys.stderr)
    if args.require_corpus and not rows:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
