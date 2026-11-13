#!/usr/bin/env python3
"""serdes-arc-d task-03: L3/L4 image builder (IB mask word + slot 1351).

Arc-D network-feature ladder, offline part (cumulative on the T1 images):

  * L3 = img-L2 + IB Enabled-mask word 0x1f + 0x0A slot-1351 val 1->0;
  * L4 = img-L3 + mask word 0x1f->0x3f (exactly the EDR bit delta).

T4c extension (ruling 4dde8c3, EN->VPI amendment):

  * L3v = img-L3 + VPI byte 0x0a->0x07 + L3v build-ID + fresh 0xA0;
  * L4v = img-L4 + the same single byte. The 1912-GCA stock base is an
    EN image (VPI byte @0x172af = 0x0a), so the card cannot enter IB
    mode («Unknown Parameter» on mstconfig set LINK_TYPE_P1=IB) — the
    VPI swap unblocks IB mode (qsfp28-ib T4.5/T4.8 precedent: VPI
    swaps burned Active on this card family). img-L3/img-L4 generation
    is unchanged (burned/recorded); the v-variants are built from the
    non-v predecessor images with mask/slot lineage asserted, not
    re-patched.

Pins and sources:

  * Mask site (T2, journal docs/superpowers/journal/
    2026-11-12-serdes-arc-d-task-02.md "Патч-спека"): 1912-GCA MAIN_CODE
    dc 0x1f2054 (raw 0x37f258 = flash_addr(03) 0x16e000 + line*68 +
    within, clcrc 64+2+2 framing), old word fcb1c083 (shr r17,r5,0x18);
    L3 word 0011001f = addi r17,zero,0x1f, L4 word 0011003f (0x3f).
    bit5=EDR is convention-derived (T2 §Fix round 1) — live confirmation
    is the T4 readback.
  * Slot 1351 (doc 075 §5; direction ruling commit 8dfc65f): the only
    CX-4<->CX-4Lx ucode differential (1 byte of 39200 in 0x0A), record
    wr6165 p=0x27 blk=3 reg=0x9cc addr=0x820; Lx stock val=1, CX-4
    val=0 — arc-C "val 0->1" was the cx4->Lx diff direction, so the
    L3 patch on the Lx base is 1->0 (CX-4-like differential, direct
    test of the bit-gate hypothesis).
  * VPI byte (T4c journal 2026-11-12-serdes-arc-d-task-04c.md §6;
    qsfp28-ib journal 2026-10-06-cx4lx-qsfp28-ib.md "0x11+0x2af"):
    section 0x11 @0x17000 +0x2af = abs 0x172af, EN stock 0x0a -> 0x07
    (VPI, ib+eth def-IB); old-value asserted; 0x0158 (0x12) NOT touched
    (ruling: VPI byte only).
  * CRC policy (doc 025 §6): 0x03 clcrc per-line recompute (deframe ->
    patch -> reframe, cable_gate_patch pipeline) + sec_crc/entry_crc via
    mlxfwutil.patch_sections (sec_crc first, then entry_crc); 0x0A
    and 0x11 sec_crc/entry_crc the same way. A forgotten entry_crc =
    invalid ITOC — caught by verify --deep (tests/test_build_l34.py
    TestRoundtripITOC negative case).
  * mellanox-fw-build skill: R1 per-level build-ID comment in 0x30
    (fix round per controller ruling: T4 discriminates L2/L3/L4 on-card
    by `mstflint dc | grep mlxini`). The arc-D ladder line
    ("; mlxini serdes-arc-d …", right after the anchor) is REPLACED
    line-for-line per level: T1 filled the physical 0x30 slot
    (stock 0x6a4 -> data 0x640), so accumulation cannot fit — the
    current-step line names the build; full lineage lives in the md5
    manifest (journal). R4 offline gates (verify --deep, mstflint -i
    verify, diff-control exactly-declared-zones), R5 fresh 0xA0 via
    `mlxfwutil.py sign`. R3 GUID/MAC: already embedded in img-L2 (T1)
    — re-embedding would break md5 lineage.

CLI: build_l34.py --base <img> --level L3|L4|L3v|L4v --out <bin>
            [--base-md5 <hex>] [--label L] [--build-id "..."] [--date D]
            [--skip-mstflint]
"""
import argparse
import hashlib
import subprocess
import sys
import zlib
from collections import namedtuple
from datetime import date as _date
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "scripts" / "probes"))

import mlxfwutil  # noqa: E402
from cable_gate_patch import deframe, reframe  # noqa: E402
from scripts.irisc import AsmError  # noqa: E402
from scripts.phyuc import phyuc_dis  # noqa: E402

from build_l1l2 import (  # noqa: E402
    INI_ANCHOR, _diff_control, _entry_crc_bytes, _entry_off, _run_cli,
    _trim_ini, _with_marker, _zw_pad)

MAIN_CODE = 0x03
PHY_UC = 0x0A
VPI_SEC = 0x11
DBG_FW_INI = 0x30
SIG_256 = 0xA0

MASK_DC = 0x1F2054
MASK_WORD_OLD = bytes.fromhex("fcb1c083")
MASK_WORDS = {"L3": bytes.fromhex("0011001f"), "L4": bytes.fromhex("0011003f")}
MASK_EXPECT_OLD = {"L3": MASK_WORD_OLD, "L4": MASK_WORDS["L3"]}

SLOT_IDX = 1351
SLOT_OP = 0x6165
SLOT_A = 0x27
SLOT_B = 0x39CC
SLOT_C = 0x820
SLOT_D_BASE = 1
SLOT_D_CX4 = 0
SLOT_BYTE_OFF = SLOT_IDX * 16 + 15

VPI_OFF = 0x2AF
VPI_ABS = 0x172AF
VPI_OLD = 0x0A
VPI_NEW = 0x07

PATCHES_SLOT = {"L3": True, "L4": False}
V_LEVELS = {"L3v": "L3", "L4v": "L4"}
DEFAULT_LABELS = {"L3": "L3-4xFDR", "L4": "L4-4xEDR",
                  "L3v": "L3v-4xFDR-IB", "L4v": "L4v-4xEDR-IB"}
MARKER_PREFIX = "; mlxini serdes-arc-d"

BuildResult = namedtuple("BuildResult", "final zones step_mask zones_mask "
                                       "step_slot zones_slot step_ini "
                                       "zones_ini")
VBuildResult = namedtuple("VBuildResult", "final zones step_vpi zones_vpi "
                                          "step_ini zones_ini")


class L34Error(AsmError):
    """Invalid L3/L4 request (site mismatch, base lineage, CRC)."""


def slot_at(data: bytes, idx: int = SLOT_IDX) -> tuple:
    """Parsed 16B slot record (phyuc_dis) at idx: (i, op, a, b, c, d)."""
    try:
        return phyuc_dis.slots(data)[idx]
    except (ValueError, IndexError) as ex:
        raise L34Error(f"0x0A slot {idx}: {ex}") from ex


def _check_slot_record(rec: tuple) -> None:
    want = (SLOT_OP, SLOT_A, SLOT_B, SLOT_C)
    got = rec[1:5]
    if got != want:
        raise L34Error(f"slot {SLOT_IDX}: record op/a/b/c = "
                       f"{tuple(hex(x) for x in got)} != wr6165 p=0x27 "
                       f"blk=0x3 reg=0x9cc addr=0x820 {tuple(hex(x) for x in want)}")


def patch_slot(base_buf: bytes) -> tuple:
    """0x0A slot-1351 val 1->0 (CX-4-like, ruling 8dfc65f).

    Returns (out, zones): zones = the allowed diff byte set vs base
    (slot byte + 0x0A entry sec/entry CRC bytes). ITOC CRCs via
    mlxfwutil.patch_sections (sec_crc first, then entry_crc, doc 025 §6).
    """
    img = mlxfwutil.Image(base_buf, "slot-base")
    e = img.find_entry("ITOC", PHY_UC)
    rec = slot_at(img.section_data(e))
    _check_slot_record(rec)
    if rec[5] != SLOT_D_BASE:
        raise L34Error(f"slot {SLOT_IDX} val={rec[5]:#06x} != Lx stock "
                       f"{SLOT_D_BASE:#06x} (base is not img-L2 lineage)")
    out = mlxfwutil.patch_sections(
        img, [(PHY_UC, SLOT_BYTE_OFF, bytes([SLOT_D_CX4]))])
    img2 = mlxfwutil.Image(out, "slot-out", fmt=img.fmt)
    errs = mlxfwutil.verify_image(img2, deep=True)
    if errs:
        raise L34Error(f"slot step verify(deep): {errs}")
    rec2 = slot_at(img2.section_data(img2.find_entry("ITOC", PHY_UC)))
    if rec2[1:5] != (SLOT_OP, SLOT_A, SLOT_B, SLOT_C) \
            or rec2[5] != SLOT_D_CX4:
        raise L34Error(f"slot round-trip failed: {rec2}")
    zones = {img.sec_abs(e) + SLOT_BYTE_OFF} | _entry_crc_bytes(img, PHY_UC)
    return out, zones


def check_slot_lineage(buf: bytes, expect_d: int) -> None:
    """Assert the slot-1351 record identity + val (L4 base must be L3)."""
    img = mlxfwutil.Image(buf, "slot-check")
    e = img.find_entry("ITOC", PHY_UC)
    rec = slot_at(img.section_data(e))
    _check_slot_record(rec)
    if rec[5] != expect_d:
        raise L34Error(f"slot {SLOT_IDX} val={rec[5]:#06x} != expected "
                       f"{expect_d:#06x} (base lineage broken)")


def patch_vpi(base_buf: bytes) -> tuple:
    """VPI byte 0x11+0x2af 0x0a->0x07 (EN->VPI, ruling 4dde8c3 / T4c).

    The byte's absolute pin is 0x172af (0x11 @0x17000); the offset is
    section-relative, the CLI flow pins the absolute layout. Old-value
    assert = EN 0x0a (lineage gate: rejects already-swapped / wrong
    bases). Returns (out, zones): zones = the allowed diff byte set vs
    base (VPI byte + 0x11 entry sec/entry CRC bytes). ITOC CRCs via
    mlxfwutil.patch_sections (sec_crc first, then entry_crc, doc 025
    §6). 0x0158 (0x12) is NOT touched (ruling: VPI byte only).
    """
    img = mlxfwutil.Image(base_buf, "vpi-base")
    try:
        e = img.find_entry("ITOC", VPI_SEC)
    except KeyError as ex:
        raise L34Error(f"section 0x{VPI_SEC:02x} absent (VPI site "
                       f"assumption broken): {ex}") from ex
    a = img.sec_abs(e)
    cur = base_buf[a + VPI_OFF]
    if cur != VPI_OLD:
        raise L34Error(f"VPI byte @0x{a + VPI_OFF:x} = {cur:#04x} != EN "
                       f"{VPI_OLD:#04x} (base is not an EN predecessor)")
    out = mlxfwutil.patch_sections(
        img, [(VPI_SEC, VPI_OFF, bytes([VPI_NEW]))])
    img2 = mlxfwutil.Image(out, "vpi-out", fmt=img.fmt)
    errs = mlxfwutil.verify_image(img2, deep=True)
    if errs:
        raise L34Error(f"vpi step verify(deep): {errs}")
    if out[a + VPI_OFF] != VPI_NEW:
        raise L34Error("vpi round-trip failed")
    zones = {a + VPI_OFF} | _entry_crc_bytes(img, VPI_SEC)
    return out, zones


def check_mask_lineage(base_buf: bytes, word: bytes, dc: int = MASK_DC) -> None:
    """Assert the clcrc-framed 0x03 word at the T2 site equals `word`.

    Shared lineage gate: patch_mask uses it for the expected old word,
    build_v_variant for the predecessor level word (L3v waits 0011001f,
    L4v waits 0011003f — v-variants never re-patch the mask).
    """
    img = mlxfwutil.Image(base_buf, "mask-check")
    e = img.find_entry("ITOC", MAIN_CODE)
    if not e.clcrc:
        raise L34Error("0x03 is not clcrc-framed (T2 site assumption broken)")
    raw = img.section_data(e)
    code, tail = deframe(raw, e.clcrc)
    if reframe(code, tail) != raw:
        raise L34Error("clcrc round-trip FAILED on stock 0x03 "
                       "(corrupt line CRC / non-canonical framing)")
    if code[dc:dc + 4] != word:
        raise L34Error(f"mask word @dc 0x{dc:x} = {code[dc:dc + 4].hex()} "
                       f"!= expected {word.hex()} (base lineage broken)")


def patch_mask(base_buf: bytes, level: str, dc: int = MASK_DC) -> tuple:
    """MAIN_CODE IB-mask word patch at the T2 site (clcrc-aware).

    dc defaults to the T2 pin (0x1f2054); the synthetic tests pass a
    small dc with identical within-line geometry. Pipeline per
    cable_gate_patch: deframe -> byte-verified old word -> patch ->
    reframe (per-line clcrc) -> patch_sections (sec/entry CRC) ->
    verify --deep. Returns (out, zones).
    """
    if level not in MASK_WORDS:
        raise L34Error(f"unknown level {level!r} (known: {sorted(MASK_WORDS)})")
    new = MASK_WORDS[level]
    expect = MASK_EXPECT_OLD[level]
    check_mask_lineage(base_buf, expect, dc=dc)
    img = mlxfwutil.Image(base_buf, "mask-base")
    e = img.find_entry("ITOC", MAIN_CODE)
    raw = img.section_data(e)
    code, tail = deframe(raw, e.clcrc)
    within = dc % 64
    if within + 4 > 64:
        raise L34Error(f"word @dc 0x{dc:x} crosses a clcrc line boundary")
    code = code[:dc] + new + code[dc + 4:]
    new_raw = reframe(code, tail)
    out = mlxfwutil.patch_sections(img, [(MAIN_CODE, 0, new_raw)])
    img2 = mlxfwutil.Image(out, "mask-out", fmt=img.fmt)
    errs = mlxfwutil.verify_image(img2, deep=True)
    if errs:
        raise L34Error(f"mask step verify(deep): {errs}")
    a = img.sec_abs(e)
    line_off = (dc // 64) * 68
    zones = set(range(a + line_off + within, a + line_off + within + 4))
    zones |= {a + line_off + 66, a + line_off + 67}
    zones |= _entry_crc_bytes(img, MAIN_CODE)
    return out, zones


def patch_build_id(base_buf: bytes, build_id: str) -> tuple:
    """R1: set the arc-D ladder build-ID comment in 0x30 (T1 mechanism).

    REPLACES the existing "; mlxini serdes-arc-d …" line (insertion
    after the anchor when absent): T1 filled the physical 0x30 slot, so
    a line-for-line swap is the only in-place option (R2: never a
    silent relocation). Budget = current entry size (inject_ini
    in-place bound) with the T1 ;;-comment trim fallback. Returns
    (out, zones): zones cover the whole 0x30 section + its ITOC entry.
    """
    if not build_id or "\n" in build_id or not build_id.startswith("; "):
        raise L34Error('build-ID must be a single "; "-comment line (R1)')
    img = mlxfwutil.Image(base_buf, "ini-base")
    e30 = img.find_entry("ITOC", DBG_FW_INI)
    raw30 = img.section_data(e30)
    if raw30[:2] != b"\x78\xda":
        raise L34Error("0x30 section is not zlib")
    ini_lines = zlib.decompress(raw30).decode("latin1").split("\n")
    if ini_lines.count(INI_ANCHOR) != 1:
        raise L34Error(f"ini anchor {INI_ANCHOR!r} not found exactly once")
    ladder = [i for i, l in enumerate(ini_lines)
              if l.startswith(MARKER_PREFIX)]
    if len(ladder) > 1:
        raise L34Error(f"multiple {MARKER_PREFIX!r} lines "
                       f"{ladder}: ambiguous ladder state")
    budget30 = e30.size
    if ladder:
        i = ladder[0]
        new_lines = ini_lines[:i] + [build_id] + ini_lines[i + 1:]
    else:
        new_lines = _with_marker(ini_lines, build_id)
    n_untrimmed = _zw_pad("\n".join(new_lines))
    if n_untrimmed > budget30:
        trimmed = _trim_ini(ini_lines)
        if ladder:
            i = [j for j, l in enumerate(trimmed)
                 if l.startswith(MARKER_PREFIX)]
            if len(i) != 1:
                raise L34Error("trim dropped the arc-D ladder line "
                               "(forbidden)")
            new_lines = trimmed[:i[0]] + [build_id] + trimmed[i[0] + 1:]
        else:
            new_lines = _with_marker(trimmed, build_id)
    ini_final = "\n".join(new_lines)
    n_final = _zw_pad(ini_final)
    if n_final > budget30:
        raise L34Error(f"0x30 budget exceeded even after line swap + trim "
                       f"({n_final} > {budget30}): STOP per R2 — physical "
                       f"slot full (T1); shorten the build-ID line")
    out = mlxfwutil.inject_ini(img, ini_final)
    img_fin = mlxfwutil.Image(out, "ini-out", fmt=img.fmt)
    rt30 = mlxfwutil.extract_section(img_fin, DBG_FW_INI)
    rt_ini = zlib.decompress(rt30) if rt30[:2] == b"\x78\xda" else rt30
    if rt_ini != ini_final.encode("latin1"):
        raise L34Error("0x30 round-trip failed: extract != ini-final")
    e30n = img_fin.find_entry("ITOC", DBG_FW_INI)
    if e30n.addr != e30.addr or e30n.size > e30.size:
        raise L34Error(f"0x30 moved/grew: 0x{e30.addr:x}+0x{e30.size:x} -> "
                       f"0x{e30n.addr:x}+0x{e30n.size:x}")
    errs = mlxfwutil.verify_image(img_fin, deep=True)
    if errs:
        raise L34Error(f"build-ID step verify(deep): {errs}")
    zones = set(range(img.sec_abs(e30), img.sec_abs(e30) + e30.size))
    zones |= set(range(_entry_off(img, DBG_FW_INI),
                       _entry_off(img, DBG_FW_INI) + 32))
    return out, zones


def default_build_id(level: str, date: str, md5_base: str, word_abs: int) -> str:
    """R1 build-ID line (T1 format, compact ref: the 0x30 slot is full
    after T1, so the ladder line must stay short; full md5s live in the
    journal md5 manifest)."""
    label = DEFAULT_LABELS[level]
    if level in V_LEVELS:
        what = f"vpi {VPI_OLD:02x}->{VPI_NEW:02x} @0x{VPI_ABS:x}"
    elif level == "L3":
        what = (f"mask {MASK_WORD_OLD.hex()}->{MASK_WORDS[level].hex()} "
                f"@0x{word_abs:x} + slot1351 {SLOT_D_BASE}->{SLOT_D_CX4}")
    else:
        what = (f"mask {MASK_WORDS['L3'].hex()}->{MASK_WORDS[level].hex()} "
                f"(EDR bit) @0x{word_abs:x}")
    return (f"{MARKER_PREFIX} {label} ({date}, {md5_base[:8]}): {what}")


def build_level(base_buf: bytes, level: str, dc: int = MASK_DC,
                build_id=None) -> BuildResult:
    """Apply the level patch set; returns staged buffers + diff zones.

    L3 = mask(old -> 0x1f word) + slot 1351 val 1->0 + build-ID;
    L4 = mask(0x1f -> 0x3f word) + build-ID, slot asserted already
    patched. The `final` buffer is content-complete but UNSIGNED: run
    `mlxfwutil.py sign` (R5) in the CLI flow for a burn-ready image.
    """
    if level not in MASK_WORDS:
        raise L34Error(f"unknown level {level!r} (known: {sorted(MASK_WORDS)})")
    if not build_id:
        raise L34Error("build-ID required (R1: every custom image carries "
                       "its marker)")
    step_mask, zones_mask = patch_mask(base_buf, level, dc=dc)
    zones = set(zones_mask)
    if PATCHES_SLOT[level]:
        step_slot, zones_slot = patch_slot(step_mask)
        zones |= zones_slot
    else:
        check_slot_lineage(step_mask, SLOT_D_CX4)
        step_slot, zones_slot = None, set()
    step_ini, zones_ini = patch_build_id(
        step_slot if step_slot is not None else step_mask, build_id)
    zones |= zones_ini
    final = step_ini
    img = mlxfwutil.Image(final, "final")
    if img.section_data(img.find_entry("ITOC", MAIN_CODE))[
            (dc // 64) * 68 + (dc % 64):(dc // 64) * 68 + (dc % 64) + 4] \
            != MASK_WORDS[level]:
        raise L34Error("final mask word lost")
    check_slot_lineage(final, SLOT_D_CX4)
    return BuildResult(final, zones, step_mask, zones_mask, step_slot,
                       zones_slot, step_ini, zones_ini)


def build_v_variant(base_buf: bytes, level: str, dc: int = MASK_DC,
                    build_id=None) -> VBuildResult:
    """Apply the VPI variant patch set (T4c amendment, ruling 4dde8c3).

    L3v = img-L3 + VPI byte 0x0a->0x07 + L3v build-ID; L4v = img-L4 +
    the same single byte (built from the non-v predecessor image, NOT a
    chain rebuild — img-L3/img-L4 generation stays untouched). The
    predecessor mask word + slot-1351 val=0 are ASSERTED (lineage
    gates), never re-patched. The `final` buffer is content-complete
    but UNSIGNED: run `mlxfwutil.py sign` (R5) in the CLI flow.
    """
    if level not in V_LEVELS:
        raise L34Error(f"unknown level {level!r} (known: {sorted(V_LEVELS)})")
    if not build_id:
        raise L34Error("build-ID required (R1: every custom image carries "
                       "its marker)")
    word = MASK_WORDS[V_LEVELS[level]]
    check_mask_lineage(base_buf, word, dc=dc)
    check_slot_lineage(base_buf, SLOT_D_CX4)
    step_vpi, zones_vpi = patch_vpi(base_buf)
    step_ini, zones_ini = patch_build_id(step_vpi, build_id)
    zones = set(zones_vpi) | set(zones_ini)
    final = step_ini
    check_mask_lineage(final, word, dc=dc)
    check_slot_lineage(final, SLOT_D_CX4)
    img = mlxfwutil.Image(final, "final-v")
    if img.section_data(img.find_entry("ITOC", VPI_SEC))[VPI_OFF] != VPI_NEW:
        raise L34Error("final VPI byte lost")
    return VBuildResult(final, zones, step_vpi, zones_vpi, step_ini,
                        zones_ini)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="arc D L3/L4/L3v/L4v builder: T2 IB-mask word + "
                    "0x0A slot 1351 (1->0) + VPI byte 0x0a->0x07 "
                    "(L3v/L4v, T4c) + R1 build-ID + offline gates")
    ap.add_argument("--base", required=True)
    ap.add_argument("--level", required=True,
                    choices=sorted(set(MASK_WORDS) | set(V_LEVELS)))
    ap.add_argument("--out", required=True)
    ap.add_argument("--base-md5", help="expected base md5 (lineage gate)")
    ap.add_argument("--label", help="ladder step name for the build-ID (R1)")
    ap.add_argument("--build-id", help="full build-ID line override (R1)")
    ap.add_argument("--date", default=_date.today().isoformat(),
                    help="build-ID date (default: today)")
    ap.add_argument("--skip-mstflint", action="store_true")
    args = ap.parse_args(argv)

    base_buf = Path(args.base).read_bytes()
    md5_base = hashlib.md5(base_buf).hexdigest()
    print(f"[1] base {args.base}: md5 {md5_base} size {len(base_buf)} "
          f"-> {args.level}")
    if args.base_md5 and md5_base != args.base_md5:
        raise SystemExit(f"FATAL: base md5 {md5_base} != pinned "
                         f"{args.base_md5} (lineage broken)")

    img = mlxfwutil.Image(base_buf, args.base)
    if img.fmt != "fs3":
        raise SystemExit(f"FATAL: base is {img.fmt}, expected fs3")
    e03 = img.find_entry("ITOC", MAIN_CODE)
    a03 = img.sec_abs(e03)
    line_off = (MASK_DC // 64) * 68
    word_abs = a03 + line_off + MASK_DC % 64
    build_id = args.build_id or default_build_id(args.level, args.date,
                                                 md5_base, word_abs)
    if args.label:
        build_id = build_id.replace(DEFAULT_LABELS[args.level], args.label)
    vpi_abs = VPI_ABS

    if args.level in V_LEVELS:
        e11 = img.find_entry("ITOC", VPI_SEC)
        vpi_abs = img.sec_abs(e11) + VPI_OFF
        if vpi_abs != VPI_ABS:
            raise SystemExit(f"FATAL: 0x{VPI_SEC:02x}+0x{VPI_OFF:x} = "
                             f"0x{vpi_abs:x} != pinned 0x{VPI_ABS:x} "
                             f"(layout drift)")
        expect_word = MASK_WORDS[V_LEVELS[args.level]]
        res = build_v_variant(base_buf, args.level, build_id=build_id)
        print(f"[2] lineage asserted: mask word {expect_word.hex()} @dc "
              f"0x{MASK_DC:x} + slot 1351 val=0 ({V_LEVELS[args.level]} "
              f"predecessor, no mask/slot re-patch)")
        print(f"[3] VPI byte @0x{vpi_abs:x} (0x{VPI_SEC:02x}+0x{VPI_OFF:x}): "
              f"{VPI_OLD:#04x}->{VPI_NEW:#04x} (EN->VPI, T4c ruling "
              f"4dde8c3; 0x0158 untouched); sec/entry CRC recomputed; "
              f"verify(deep)=PASS")
        _diff_control(f"vpi step vs base ({args.level}: VPI byte + 0x11 "
                      f"entry CRC)", res.step_vpi, base_buf, res.zones_vpi)
        print(f'[4] ini build-ID (R1): "{build_id}"')
        _diff_control("build-ID step (0x30 + entry)", res.step_ini,
                      res.step_vpi, res.zones_ini)
        final_label = f"{args.level}: VPI byte + build-ID + CRCs + digest"
    else:
        expect_word = MASK_WORDS[args.level]
        res = build_level(base_buf, args.level, build_id=build_id)
        print(f"[2] mask word @dc 0x{MASK_DC:x} (raw 0x{word_abs:x}): "
              f"{MASK_EXPECT_OLD[args.level].hex()} -> "
              f"{MASK_WORDS[args.level].hex()}; clcrc line 0x{MASK_DC // 64:x} "
              f"reframed; sec/entry CRC recomputed; verify(deep)=PASS")
        _diff_control(f"mask step vs base ({args.level} word + line CRC + 0x03 "
                      f"entry CRC)", res.step_mask, base_buf, res.zones_mask)
        if res.step_slot is not None:
            print(f"[3] slot 1351: wr6165 p=0x27 blk=0x3 reg=0x9cc addr=0x820 "
                  f"val {SLOT_D_BASE:#x}->{SLOT_D_CX4:#x} (CX-4-like, ruling "
                  f"8dfc65f); sec/entry CRC recomputed; verify(deep)=PASS")
            _diff_control("slot step vs mask (0x0A byte + entry CRC)",
                          res.step_slot, res.step_mask, res.zones_slot)
        else:
            print("[3] slot 1351: already val=0 (L3 lineage asserted, no 0x0A "
                  "edit in L4)")
        print(f'[4] ini build-ID (R1): "{build_id}"')
        _diff_control("build-ID step (0x30 + entry)", res.step_ini,
                      res.step_slot if res.step_slot is not None else res.step_mask,
                      res.zones_ini)
        final_label = (f"{args.level}: mask word + slot + build-ID + CRCs "
                       f"+ digest")

    pf = Path(args.out)
    pf.write_bytes(res.final)
    rc, o, e = _run_cli(["sign", str(pf)])
    print(f"[5] sign (R5): rc={rc} {' '.join(o.split())}")
    if rc != 0:
        raise SystemExit(f"FATAL: sign failed: {e.strip()}")
    final = pf.read_bytes()
    ea = img.find_entry("ITOC", SIG_256)
    aa = img.sec_abs(ea)
    zones_sign = set(range(aa + mlxfwutil.SIG_SLOT_OFF,
                           aa + mlxfwutil.SIG_SLOT_OFF + 32))
    zones_sign |= _entry_crc_bytes(img, SIG_256)
    res_zones = set(res.zones) | zones_sign

    rc, o, e = _run_cli(["verify", "--deep", str(pf)])
    print(f"[6] mlxfwutil verify --deep: rc={rc}")
    print("    " + "\n    ".join(o.strip().split("\n")[-2:]))
    if rc != 0:
        raise SystemExit("FATAL: verify --deep FAILED")
    rc, o, e = _run_cli(["sign", "--check", str(pf)])
    print(f"[7] sign --check: rc={rc} ({' '.join(o.split())})")
    if rc != 0:
        raise SystemExit("FATAL: 0xA0 digest not fresh")

    if not args.skip_mstflint:
        r = subprocess.run(["mstflint", "-i", str(pf), "verify"],
                           capture_output=True, text=True)
        tail = " ".join((r.stdout + r.stderr).strip().split("\n")[-3:])
        print(f"[8] mstflint -i verify: rc={r.returncode} {tail}")
        if r.returncode != 0:
            raise SystemExit("FATAL: mstflint verify FAILED")

    diffs = _diff_control(f"final vs base ({final_label})",
                          final, base_buf, res_zones)
    if final[word_abs:word_abs + 4] != expect_word:
        raise SystemExit("FATAL: final mask word lost")
    if args.level in V_LEVELS and final[vpi_abs] != VPI_NEW:
        raise SystemExit("FATAL: final VPI byte lost")
    if final[a03] != base_buf[a03]:
        raise SystemExit("FATAL: unexpected MAIN_CODE byte drift")
    md5_out = hashlib.md5(final).hexdigest()
    print(f"[9] {pf}: md5 {md5_out} size {len(final)}, "
          f"{len(diffs)} changed bytes (all in expected zones)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
