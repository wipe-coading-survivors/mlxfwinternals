#!/usr/bin/env python3
"""serdes-arc-d task-06: Gen4 candidate image builder (D2-S1 raw / D2-S2 adapted).

Arc-D Gen4 ladder part 2, offline (journal
docs/superpowers/journal/2026-11-12-serdes-arc-d-task-06.md — Step 1
decisions are binding for this code):

  * img-G4a (D2-S1 raw): P2a bytes + CX-5 0x0C PCIE_PHY_UC_CODE as-is
    (resize 0xA00 -> 0x1E80 via the T5 repack_resize core); schedule
    pair NOT touched (raw-µcode attribution stays clean vs the P2a-only
    precedent img2, doc 130 §5.1);
  * img-G4b (D2-S2 adapted): the same + schedule sync — the CX-5 table
    (16 BE16 entries, 0x08+0xf0) written into BOTH Lx slots (0x08+0xf0
    and the 0x11 full-table copy @+0x94, re-derived pin: the doc-130
    "+0x9e" is the 16.35 entry[1] anchor; both layouts carry a full
    copy — Lx @+0x94, CX-5 @+0x9c). Doc 130 §5.3: swapping 0x0C without
    0x08 desynchronizes the schedules (CX-5 read/delay-`a` domain
    0x6c0..0x827 vs Lx table coverage 0x654..0x6df);
  * operand adaptation (design §3 D2-S2) is DERIVED, never assumed:
    per-op mapping from the 0x0A/0x0C common-(b,c) differential. The
    real Lx<->CX-5 pair yields an EMPTY mapping (the only per-ASIC
    operand patches — 0x0A, 17 B, 5 keys (6173/60b3/6053 b=0x49cc
    c=0xc0 a-flavor 0x28/0x38->0x20/0x2a; 6125 b 0x3a00->0x780) — are
    referenced by ZERO of the 488 CX-5 0x0C records; no d-overrides on
    the 55 shared (op,b,c) keys; no unknown banks: all 74 write pairs
    use banks present in Lx 0x0A∪0x0C) -> payload written byte-as-is.
    G4a->G4b delta = schedule pair only: falsifiable layer attribution;
  * img-G4c (tuning 0x09+0x1518..0x151b): SKIPPED — value underivable
    (per-SerDes-variant ratios ×1.09/×1.28/×1.41 on MT27800 with no
    MT27710 Gen4 reference; the Lx field 8ca07c38 is the unequal-halves
    exception), plan-allowed skip, journal Step 1.

mellanox-fw-build skill: R1 build-ID in 0x30 (build_l34.patch_build_id —
insertion after the anchor on a stock base); R2 in-place budget (trim
fallback, never a silent relocation); R3 GUID/MAC via `guides` CLI before
burn-handoff; R4 offline gates (verify --deep, mstflint -i verify,
sign --check, diff-control exactly-declared-zones); R5 fresh 0xA0 via
`mlxfwutil.py sign`. Base pins: GCA-1912 stock md5 098fa9c0…, P2a stock
0x87/0x43, 0x0C md5 2a2be17b… (Lx family), CX-5 payload md5 a2c3dc94….

CLI: build_g4.py --base <img> --cx5-dir <corpus-sku-dir> --variant G4a|G4b
            --out <bin> [--guid 0xHEX --mac 0xHEX] [--build-id "..."]
            [--date D] [--skip-mstflint]
"""
import argparse
import hashlib
import struct
import subprocess
import sys
from collections import namedtuple
from datetime import date as _date
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-arc-d"))

import mlxfwutil  # noqa: E402
from build_l1l2 import _diff_control, _entry_crc_bytes, _run_cli  # noqa: E402
from build_l34 import patch_build_id  # noqa: E402
from scripts.irisc import AsmError  # noqa: E402
from scripts.phyuc.phyuc_dis import slots as _uc_slots  # noqa: E402

HW_BOOT_CFG = 0x08
CAP_SEC = 0x11
PCIE_PHY_UC = 0x0C
DBG_FW_INI = 0x30
SIG_256 = 0xA0
DEV_INFO = 0xE1
MFG_INFO = 0xE0

P2A_STOCK = {HW_BOOT_CFG: (0x23, 0x87, 0x8F), CAP_SEC: (0x8B, 0x43, 0x47)}
SCHED_TABLE_OFF = 0xF0
SCHED_DOMAIN = range(0x0600, 0x0900)
SCHED_MIN_ENTRIES = 8
SCHED_COPY_WINDOW = range(0x80, 0x110)
LX_0C_MD5 = "2a2be17b94cf1a6700558f36064994c9"
CX5_0C_MD5 = "a2c3dc948abeec5d39f82e341eb01410"
BASE_MD5 = "098fa9c079cdd195c1974df84a598cbd"
GCA_GUID = int(mlxfwutil.hw("CARD_CX4LX_BCAT", "guid"), 16)
GCA_MAC = int(mlxfwutil.hw("CARD_CX4LX_BCAT", "mac"), 16)

SchedLayout = namedtuple("SchedLayout", "table_off n_entries copy_off")
BuildResult = namedtuple("BuildResult", "final zones step_resize zones_resize "
                                       "step_content zones_content step_ini "
                                       "zones_ini")


class G4Error(AsmError):
    """Invalid Gen4 build request (layout drift, lineage, alignment)."""


def resolve_schedule(sec08: bytes, sec11: bytes) -> SchedLayout:
    """Version-aware schedule-pair resolver for the 0x08/0x11 sections.

    Table anchor 0xf0 is family-stable (Lx-14.32 and 16.35 both verified,
    journal Step 0); the entry count and the 0x11 full-copy offset are
    layout-derived: Lx-14.32 = 14 entries / copy @+0x94, CX-5 16.35 =
    16 entries / copy @+0x9c (the doc-130 "+0x9e" pin anchors entry[1]
    of the same full copy). Raises G4Error when either half is missing.
    """
    n = 0
    while True:
        off = SCHED_TABLE_OFF + n * 2
        if off + 2 > len(sec08):
            break
        val = int.from_bytes(sec08[off:off + 2], "big")
        if val not in SCHED_DOMAIN:
            break
        n += 1
    if n < SCHED_MIN_ENTRIES:
        raise G4Error(f"schedule table @0x{SCHED_TABLE_OFF:x}: only {n} "
                      f"in-domain entries (<{SCHED_MIN_ENTRIES}) — base "
                      "layout is neither Lx-14.32 nor 16.35-like")
    table = sec08[SCHED_TABLE_OFF:SCHED_TABLE_OFF + n * 2]
    copy = sec11.find(table)
    if copy not in SCHED_COPY_WINDOW:
        raise G4Error(f"0x11 full-table copy not found in "
                      f"0x{min(SCHED_COPY_WINDOW):x}..0x{max(SCHED_COPY_WINDOW):x}"
                      f" (find -> {copy}) — layout drift")
    return SchedLayout(SCHED_TABLE_OFF, n, copy)


def table_bytes(sec08: bytes, layout: SchedLayout) -> bytes:
    """Full schedule table bytes (n_entries BE16 words) from 0x08 data."""
    return sec08[layout.table_off:layout.table_off + layout.n_entries * 2]


def _is_write(op):
    return 0x60 <= (op >> 8) <= 0x7F


def _is_addr_op(op):
    """Address-class op (register model): write or read/poll family.

    Non-address ops (nop 0x0, delay 0x4000, op2000/0x3000/0x8520 — the
    phyuc_overlap excluded domains) never enter the operand mapping:
    their fields are schedule/flavor counters, not register operands.
    """
    return 0x50 <= (op >> 8) <= 0x7F


def derive_operand_adaptation(lx_0a: bytes, lx_0c: bytes, cx_0a: bytes,
                              cx_0c: bytes) -> dict:
    """Flavor-level operand mapping for a CX-5 0x0C payload onto an Lx bank.

    Design §3 D2-S2 path: per-op operand adaptation from the 0x0A
    differential (the only per-ASIC operand patches in the shared µcode
    family). Semantics (journal Step 1(b), corrected round 1): the 0x0A
    tables define, per address-class key (op,b,c), which a-flavors exist
    on each ASIC (Lx 0x28/0x38 vs CX-5 0x20/0x2a on bank 0x49cc; a=0x8
    common). A payload record needs a rewrite ONLY when its flavor is
    CX-5-specific: mapping {(op,b,c,a_cx): a_lx}, resolved unambiguously
    (single Lx-specific flavor, else d-matched). Records with common or
    foreign flavors stay as-is. Deterministic (sorted iteration); empty
    dict = identity — the real arc-D pair: the payload references the two
    renamed keys ONLY with the common flavor a=0x8 (records 59/62/76/79).
    """
    def flavor_recs(data):
        out = {}
        for _, op, a, b, c, d in _uc_slots(data):
            if _is_addr_op(op):
                out.setdefault((op, b, c), set()).add((a, d))
        return out

    la, ca = flavor_recs(lx_0a), flavor_recs(cx_0a)
    seen, mapping = set(), {}
    for _, op, a, b, c, d in _uc_slots(cx_0c):
        if not _is_addr_op(op) or (op, b, c, a) in seen:
            continue
        seen.add((op, b, c, a))
        key = (op, b, c)
        if key not in la or key not in ca:
            continue
        lx_a = {fa for fa, _ in la[key]}
        cx_a = {fa for fa, _ in ca[key]}
        if a in lx_a or a not in cx_a:
            continue
        spec_lx = lx_a - cx_a
        if len(spec_lx) == 1:
            mapping[(op, b, c, a)] = next(iter(spec_lx))
            continue
        ds = {fd for fa, fd in ca[key] if fa == a}
        cands = {fa for fa, fd in la[key] if fd in ds and fa in spec_lx}
        if len(cands) == 1:
            mapping[(op, b, c, a)] = next(iter(cands))
    return dict(sorted(mapping.items()))


def apply_operand_adaptation(payload: bytes, mapping: dict) -> bytes:
    """Rewrite the a-flavor of payload slots per the derived mapping.

    Identity on an empty mapping (the real arc-D pair); mapped slots keep
    their op/b/c/d, only the flavor word changes, 16B framing preserved.
    """
    if not mapping:
        return payload
    if len(payload) % 16:
        raise G4Error(f"0x0C payload {len(payload):#x} not slot-aligned")
    out = bytearray(payload)
    for i in range(0, len(out), 16):
        op, a, b, c, d = _uc_slots(payload[i:i + 16])[0][1:]
        if (op, b, c, a) in mapping:
            out[i + 8:i + 10] = mapping[(op, b, c, a)].to_bytes(2, "big")
    return bytes(out)


def pair_familiarity(cx_0c: bytes, lx_0a: bytes, lx_0c: bytes) -> dict:
    """Write-(b,c) classification of a CX-5 0x0C payload vs the Lx bank.

    Report (journal Step 1(b) evidence): familiar pairs (present in Lx
    0x0A∪0x0C), same-bank new-offset pairs, unknown banks. The real
    arc-D pair: 74/42/32/[] — no unknown banks, so no bank renormalization
    (doc 130 §10.4 renames live in the iRISC regfile domain, not here).
    """
    def wr_pairs(data):
        return {(b, c) for _, op, a, b, c, d in _uc_slots(data)
                if _is_write(op)}

    lx_bank = wr_pairs(lx_0a) | wr_pairs(lx_0c)
    lx_banks = {b for b, _ in lx_bank}
    cx = wr_pairs(cx_0c)
    familiar = cx & lx_bank
    ext = sorted(cx - lx_bank)
    return {
        "wr_pairs": len(cx),
        "familiar": len(familiar),
        "same_bank_new_offset": [(b, c) for b, c in ext if b in lx_banks],
        "unknown_banks": sorted({b for b, _ in ext if b not in lx_banks}),
    }


def _entry_row_range(img, typ):
    e = img.find_entry("ITOC", typ)
    off = img.itoc_off + 32 + e.index * 32
    return set(range(off, off + 32))


def _resize_zones(buf_before, buf_after, typ) -> set:
    """Declared diff regions of a resize: re-enumerated ITOC row block +
    old data erase + new tail-placement data (T5 planner semantics)."""
    ib = mlxfwutil.Image(buf_before, "b")
    ia = mlxfwutil.Image(buf_after, "a", fmt=ib.fmt)
    eb = ib.find_entry("ITOC", typ)
    ea = ia.find_entry("ITOC", typ)
    zones = set(range(ib.sec_abs(eb), ib.sec_abs(eb) + eb.size))
    zones |= set(range(ia.sec_abs(ea), ia.sec_abs(ea) + ea.size))
    zones |= _entry_row_range(ib, typ)
    zones |= _entry_row_range(ia, typ)
    rows_b = {e.type: e.index for e in ib.itoc if e.type != 0xFF}
    rows_a = {e.type: e.index for e in ia.itoc if e.type != 0xFF}
    for t in sorted(set(rows_b) | set(rows_a)):
        if t == typ or rows_b.get(t) == rows_a.get(t):
            continue
        img_with = ib if t in rows_b else ia
        e = img_with.find_entry("ITOC", t)
        off = img_with.itoc_off + 32 + e.index * 32
        zones |= set(range(off, off + 32))
        if t in rows_a:
            e2 = ia.find_entry("ITOC", t)
            off2 = ia.itoc_off + 32 + e2.index * 32
            zones |= set(range(off2, off2 + 32))
    return zones


def build_image(base_buf: bytes, cx5_payload: bytes, sync_schedule: bool,
                build_id: str, cx5_table: bytes = None,
                expect_0c_md5: str = None) -> BuildResult:
    """Staged Gen4 build: resize 0x0C -> P2a (+schedule sync) -> build-ID.

    The `final` buffer is content-complete but UNSIGNED: run
    `mlxfwutil.py sign` (R5) and the guides step (R3) in the CLI flow.
    Zones are the allowed diff byte sets vs the immediately preceding
    stage (zones_resize/zones_content/zones_ini) and vs the base (zones).
    """
    if len(cx5_payload) % 4:
        raise G4Error(f"0x0C payload {len(cx5_payload):#x} not DW-aligned")
    if not build_id or "\n" in build_id or not build_id.startswith("; "):
        raise G4Error('build-ID must be a single "; "-comment line (R1)')
    img = mlxfwutil.Image(base_buf, "base")
    if img.fmt != "fs3":
        raise G4Error(f"base is {img.fmt}, expected fs3")
    e0c = img.find_entry("ITOC", PCIE_PHY_UC)
    md5_0c = hashlib.md5(img.section_data(e0c)).hexdigest()
    if expect_0c_md5 and md5_0c != expect_0c_md5:
        raise G4Error(f"base 0x0C md5 {md5_0c} != pinned {expect_0c_md5} "
                      "(not the expected Lx-family base)")

    sec08 = img.section_data(img.find_entry("ITOC", HW_BOOT_CFG))
    sec11 = img.section_data(img.find_entry("ITOC", CAP_SEC))
    layout = resolve_schedule(sec08, sec11)
    patches = []
    for typ, (off, old, new) in P2A_STOCK.items():
        a = img.sec_abs(img.find_entry("ITOC", typ))
        cur = base_buf[a + off]
        if cur != old:
            raise G4Error(f"P2a byte 0x{typ:02x}+0x{off:x} = {cur:#04x} != "
                          f"stock {old:#04x} (base not pristine)")
        patches.append((typ, off, bytes([new])))
    sched_zones = set()
    if sync_schedule:
        if not cx5_table or len(cx5_table) % 2 or \
                len(cx5_table) // 2 < SCHED_MIN_ENTRIES:
            raise G4Error("schedule sync requires the CX-5 table bytes "
                          "(resolve_schedule on the donor 0x08)")
        t_len = len(cx5_table)
        for typ, off in ((HW_BOOT_CFG, layout.table_off),
                         (CAP_SEC, layout.copy_off)):
            a = img.sec_abs(img.find_entry("ITOC", typ))
            sec = sec08 if typ == HW_BOOT_CFG else sec11
            if off + t_len > len(sec):
                raise G4Error(f"schedule write 0x{typ:02x}+0x{off:x}"
                              f"+{t_len:#x} overflows section")
            pad_start = off + layout.n_entries * 2
            if any(sec[pad_start:off + t_len]):
                raise G4Error(f"0x{typ:02x}+0x{pad_start:x}..0x{off + t_len:x} "
                              "padding not zero — layout drift, refusing to "
                              "extend the table")
            patches.append((typ, off, cx5_table))
            sched_zones |= set(range(a + off, a + off + t_len))

    step_resize = mlxfwutil.repack_resize(img, PCIE_PHY_UC, cx5_payload)
    img_r = mlxfwutil.Image(step_resize, "resized", fmt=img.fmt)
    errs = mlxfwutil.verify_image(img_r, deep=True)
    if errs:
        raise G4Error(f"resize step verify(deep): {errs}")
    if mlxfwutil.burn_order_check(img_r):
        raise G4Error("resize step burn-order violation")
    if img_r.section_data(img_r.find_entry("ITOC", PCIE_PHY_UC)) \
            != cx5_payload:
        raise G4Error("resize payload round-trip failed")
    zones_resize = _resize_zones(base_buf, step_resize, PCIE_PHY_UC)

    step_content = mlxfwutil.patch_sections(
        img_r, [(typ, off, data) for typ, off, data in patches])
    img_c = mlxfwutil.Image(step_content, "content", fmt=img.fmt)
    errs = mlxfwutil.verify_image(img_c, deep=True)
    if errs:
        raise G4Error(f"content step verify(deep): {errs}")
    zones_content = set(sched_zones)
    for typ, (off, old, new) in P2A_STOCK.items():
        zones_content |= {img_r.sec_abs(img_r.find_entry("ITOC", typ)) + off}
    for typ in (HW_BOOT_CFG, CAP_SEC):
        zones_content |= _entry_crc_bytes(img_r, typ)

    step_ini, zones_ini = patch_build_id(step_content, build_id)
    zones = zones_resize | zones_content | set(zones_ini)
    img_f = mlxfwutil.Image(step_ini, "final", fmt=img.fmt)
    errs = mlxfwutil.verify_image(img_f, deep=True)
    if errs:
        raise G4Error(f"final verify(deep): {errs}")
    if img_f.section_data(img_f.find_entry("ITOC", PCIE_PHY_UC)) \
            != cx5_payload:
        raise G4Error("final 0x0C payload lost")
    for typ, (off, old, new) in P2A_STOCK.items():
        a = img_f.sec_abs(img_f.find_entry("ITOC", typ))
        if step_ini[a + off] != new:
            raise G4Error(f"final P2a byte 0x{typ:02x}+0x{off:x} lost")
    return BuildResult(step_ini, zones, step_resize, zones_resize,
                       step_content, zones_content, step_ini, zones_ini)


def default_build_id(variant: str, date: str, md5_base: str) -> str:
    if variant == "G4a":
        what = "p2a 87->8f @0x1a023 + 43->47 @0x1708b + 0x0C cx5 7808B as-is"
    else:
        what = ("G4a + schedule sync 0x08+0xf0/0x11+0x94 (cx5 16-entry "
                "table; operand adaptation derived empty, as-is)")
    return (f"; mlxini serdes-arc-d {variant} "
            f"({'raw' if variant == 'G4a' else 'adapted'} Gen4, {date}, "
            f"{md5_base[:8]}): {what}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="arc D Gen4 builder: P2a + CX-5 0x0C resize (+schedule "
                    "sync for G4b) + R1 build-ID + offline gates")
    ap.add_argument("--base", required=True)
    ap.add_argument("--cx5-dir", required=True,
                    help="CX-5 corpus SKU dir with sections/{08,11,0C}/raw.bin")
    ap.add_argument("--variant", required=True, choices=["G4a", "G4b"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--guid", type=lambda s: int(s, 0), help="R3: base GUID")
    ap.add_argument("--mac", type=lambda s: int(s, 0), help="R3: base MAC")
    ap.add_argument("--build-id", help="full build-ID line override (R1)")
    ap.add_argument("--date", default=_date.today().isoformat())
    ap.add_argument("--skip-mstflint", action="store_true")
    args = ap.parse_args(argv)

    cx5_0c = (Path(args.cx5_dir) / "sections" / "0C" / "raw.bin").read_bytes()
    md5_payload = hashlib.md5(cx5_0c).hexdigest()
    if md5_payload != CX5_0C_MD5:
        raise SystemExit(f"FATAL: CX-5 0x0C md5 {md5_payload} != pinned "
                         f"{CX5_0C_MD5}")
    sec08 = (Path(args.cx5_dir) / "sections" / "08" / "raw.bin").read_bytes()
    sec11 = (Path(args.cx5_dir) / "sections" / "11" / "raw.bin").read_bytes()
    donor = resolve_schedule(sec08, sec11)
    cx5_table = table_bytes(sec08, donor)

    base_buf = Path(args.base).read_bytes()
    md5_base = hashlib.md5(base_buf).hexdigest()
    img_b = mlxfwutil.Image(base_buf, "base")
    cx_0a = (Path(args.cx5_dir) / "sections" / "0A" / "raw.bin").read_bytes()
    mapping = derive_operand_adaptation(
        img_b.section_data(img_b.find_entry("ITOC", 0x0A)),
        img_b.section_data(img_b.find_entry("ITOC", 0x0C)),
        cx_0a, cx5_0c)
    cx5_0c = apply_operand_adaptation(cx5_0c, mapping)
    md5_adapted = hashlib.md5(cx5_0c).hexdigest()
    print(f"[1] base {args.base}: md5 {md5_base} size {len(base_buf)}; "
          f"CX-5 0x0C payload {len(cx5_0c)} B (md5 {md5_payload}, 4-way "
          f"pinned); donor schedule {donor.n_entries} entries "
          f"(copy @0x11+0x{donor.copy_off:x})")
    flavor_note = repr(mapping) if mapping else \
        "(empty - payload uses common flavors only)"
    print(f"[1a] operand adaptation (derived, journal Step 1(b)): "
          f"{len(mapping)} flavor rewrite(s) {flavor_note}; "
          f"payload md5 after apply: {md5_adapted}")
    build_id = args.build_id or default_build_id(args.variant, args.date,
                                                 md5_base)
    res = build_image(base_buf, cx5_0c,
                      sync_schedule=args.variant == "G4b",
                      cx5_table=cx5_table, build_id=build_id,
                      expect_0c_md5=LX_0C_MD5)
    img_r = mlxfwutil.Image(res.step_resize, "r")
    e_old = mlxfwutil.Image(base_buf, "b").find_entry("ITOC", PCIE_PHY_UC)
    e_new = img_r.find_entry("ITOC", PCIE_PHY_UC)
    print(f"[2] resize (T5 core): 0x0C 0x{e_old.size:x}@0x"
          f"{mlxfwutil.Image(base_buf, 'b').sec_abs(e_old):x} -> "
          f"0x{e_new.size:x}@0x{img_r.sec_abs(e_new):x} (idx {e_old.index}->"
          f"{e_new.index}, ITOC re-enumerated); verify(deep)=PASS; "
          f"burn-order clean")
    _diff_control("resize vs base (0x0C data+rows)", res.step_resize,
                  base_buf, res.zones_resize)
    what = "P2a bytes" if args.variant == "G4a" else \
        "P2a bytes + schedule sync (both Lx slots)"
    print(f"[3] content ({what}): 0x08+0x23 87->8f, 0x11+0x8b 43->47"
          + (f"; 0x08+0xf0/0x11+0x94 <- cx5 table {cx5_table.hex()}"
             if args.variant == "G4b" else "")
          + "; operand adaptation: derived EMPTY (as-is); sec/entry CRC "
            "recomputed; verify(deep)=PASS")
    _diff_control("content vs resize (P2a"
                  + ("+schedule" if args.variant == "G4b" else "")
                  + " + entry CRCs)", res.step_content, res.step_resize,
                  res.zones_content)
    print(f'[4] ini build-ID (R1): "{build_id}"')
    _diff_control("build-ID step (0x30 + entry)", res.step_ini,
                  res.step_content, res.zones_ini)

    zones = set(res.zones)
    final = res.final
    if (args.guid is None) != (args.mac is None):
        raise SystemExit("FATAL: --guid and --mac must be given together (R3)")
    p1 = Path(args.out + ".pre-guides")
    p1.write_bytes(res.final)
    if args.guid is not None and args.mac is not None:
        pg = Path(args.out + ".guides")
        rc, o, e = _run_cli(["guides", "--guid", hex(args.guid),
                             "--mac", hex(args.mac), "-o", str(pg), str(p1)])
        print(f"[5] guides (R3): GUID {args.guid:#x} / MAC {args.mac:#x}: "
              f"rc={rc} {' '.join(o.split())}")
        if rc != 0:
            raise SystemExit(f"FATAL: guides failed: {e.strip()}")
        final = pg.read_bytes()
        img_pre = mlxfwutil.Image(res.final, "pre-guides")
        zones_guides = set()
        for typ in (DEV_INFO, MFG_INFO):
            de = img_pre.find_entry("ITOC", typ)
            zones_guides |= set(range(img_pre.sec_abs(de),
                                      img_pre.sec_abs(de) + de.size))
            zones_guides |= _entry_row_range(img_pre, typ)
        zones |= zones_guides
        _diff_control("guides vs ini (E1+E0)", final, res.final,
                      zones_guides)
    else:
        print("[5] guides (R3): SKIPPED (--guid/--mac not given; "
              "embed before burn)")

    pf = Path(args.out)
    pf.write_bytes(final)
    rc, o, e = _run_cli(["sign", str(pf)])
    print(f"[6] sign (R5): rc={rc} {' '.join(o.split())}")
    if rc != 0:
        raise SystemExit(f"FATAL: sign failed: {e.strip()}")
    final = pf.read_bytes()
    img_b = mlxfwutil.Image(base_buf, "b")
    ea = img_b.find_entry("ITOC", SIG_256)
    aa = img_b.sec_abs(ea)
    zones |= set(range(aa + mlxfwutil.SIG_SLOT_OFF,
                       aa + mlxfwutil.SIG_SLOT_OFF + 32))
    zones |= _entry_crc_bytes(img_b, SIG_256)

    rc, o, e = _run_cli(["verify", "--deep", str(pf)])
    print(f"[7] mlxfwutil verify --deep: rc={rc}")
    print("    " + "\n    ".join(o.strip().split("\n")[-2:]))
    if rc != 0:
        raise SystemExit("FATAL: verify --deep FAILED")
    rc, o, e = _run_cli(["sign", "--check", str(pf)])
    print(f"[8] sign --check: rc={rc} ({' '.join(o.split())})")
    if rc != 0:
        raise SystemExit("FATAL: 0xA0 digest not fresh")

    if not args.skip_mstflint:
        r = subprocess.run(["mstflint", "-i", str(pf), "verify"],
                           capture_output=True, text=True)
        tail = " ".join((r.stdout + r.stderr).strip().split("\n")[-3:])
        print(f"[9] mstflint -i verify: rc={r.returncode} {tail}")
        if r.returncode != 0:
            raise SystemExit("FATAL: mstflint verify FAILED")

    diffs = _diff_control(
        f"final vs base ({args.variant}: 0x0C resize + P2a"
        + (" + schedule" if args.variant == "G4b" else "")
        + " + build-ID + guides + digest)", final, base_buf, zones)
    if final[img_r.sec_abs(e_new):img_r.sec_abs(e_new) + len(cx5_0c)] \
            != cx5_0c:
        raise SystemExit("FATAL: final 0x0C payload lost")
    md5_out = hashlib.md5(final).hexdigest()
    print(f"[10] {pf}: md5 {md5_out} size {len(final)}, "
          f"{len(diffs)} changed bytes (all in expected zones)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
