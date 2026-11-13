#!/usr/bin/env python3
"""serdes-arc-d task-01: L1/L2 image builder (lcl[0] 56G/100G speed bits).

Arc-D network-feature ladder, offline part: L1 = base + bit6 (56GbE),
L2 = base + bit6|bit7 (100GbE, cumulative). Bit derivation with sources —
docs/superpowers/journal/2026-11-12-serdes-arc-d-task-01.md Step 1:

  * lcl[0].eth_speeds_supported lives in FW_MAIN_CFG (0x12) at rel +0x30B
    (field map No.3, docs/750-exp/190-serdes-sku-provisioning.md); the
    1-port GCA base carries 0x3b, lcl[1] at +0x317 is 0x00 and stays so.
  * bit6 (0x40) = 56G, bit7 (0x80) = 100G (docs/250-re/130-cable-gate/
    015-speed-bits.md §2; corpus anchors CX-4 MCX456A-FCA 0x5b,
    MCX416A-CCA 0xbb, MCX456A-ECA 0xfb; refs MCX455A-ECA 12_28_2302 0xbb;
    live discriminators 0x7b/0xbb — journal 2026-10-06-cx4lx-qsfp28-ib.md:
    785-805).
  * sec_crc/entry_crc recomputed by mlxfwutil (CRC-16 poly 0x100B,
    docs/250-re/100-formats/025-crc.md §6: sec_crc first, then entry_crc).

mellanox-fw-build skill rules applied: R1 build-ID comment in 0x30 after
the ";; Mellanox Technologies LTD" anchor; R2 in-place ini budget with
;;-comment trim fallback (never --repack-force silently); R3 GUID/MAC
embedding via `mlxfwutil.py guides` before burn-handoff; R4 offline gates
(verify --deep, mstflint -i verify, diff-control vs base, sign --check);
R5 fresh 0xA0 digest via `mlxfwutil.py sign`.

CLI: build_l1l2.py --base <img> --lcl-bits <hex> --out <bin>
            [--guid 0xHEX --mac 0xHEX] [--label L] [--build-id "..."]
"""
import argparse
import contextlib
import hashlib
import io
import re
import subprocess
import sys
import zlib
from collections import namedtuple
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

import mlxfwutil  # noqa: E402
from scripts.irisc import AsmError  # noqa: E402

FW_MAIN_CFG = 0x12
DBG_FW_INI = 0x30
SIG_256 = 0xA0
DEV_INFO = 0xE1
MFG_INFO = 0xE0

LCL0_OFF = 0x30B
LCL1_OFF = 0x317
STOCK_LCL0 = 0x3B
FEATURE_BITS = {"56G": 0x40, "100G": 0x80}
INI_ANCHOR = ";; Mellanox Technologies LTD"
INI_TRIM_DESC_LEN = 120
PRS_RE = re.compile(
    r"lcl\[0\]\.eth_speeds_supported\.Speed(56|100)Gb\s*=\s*0x([01])")


class LclError(AsmError):
    """Invalid lcl request (unknown feature bit, non-stock base, budget)."""


def derive_lcl_bits(cur: int, feature: str) -> int:
    """OR one Step-1-derived feature bit into an lcl speed-mask value."""
    if not isinstance(cur, int) or isinstance(cur, bool) or not 0 <= cur <= 0xFF:
        raise LclError(f"lcl value out of byte range: {cur!r}")
    if feature not in FEATURE_BITS:
        raise LclError(f"unknown feature {feature!r} "
                       f"(known: {sorted(FEATURE_BITS)})")
    return cur | FEATURE_BITS[feature]


def validate_mask(mask: int) -> int:
    """Accept only nonzero sub-masks of the 56G/100G feature bits."""
    allowed = 0
    for bit in FEATURE_BITS.values():
        allowed |= bit
    if not isinstance(mask, int) or isinstance(mask, bool) \
            or mask <= 0 or mask & ~allowed:
        raise LclError(f"lcl-bits mask {mask!r} must be a nonzero sub-mask "
                       f"of {allowed:#x} ({'/'.join(FEATURE_BITS)})")
    return mask


def mask_label(mask: int) -> str:
    mask = validate_mask(mask)
    feats = [f for f, b in sorted(FEATURE_BITS.items(), key=lambda kv: kv[1])
             if mask & b]
    return "+".join(feats)


def prs_lcl0_speeds(img) -> dict:
    """56G/100G flags of lcl[0] from the 0x30 ini (empty when absent)."""
    try:
        data = mlxfwutil.extract_section(img, DBG_FW_INI)
    except KeyError:
        return {}
    if data[:2] != b"\x78\xda":
        return {}
    out = {}
    for m in PRS_RE.finditer(zlib.decompress(data).decode("latin1")):
        out[m.group(1) + "G"] = int(m.group(2))
    return out


def _entry_off(img, typ: int) -> int:
    e = img.find_entry("ITOC", typ)
    return img.itoc_off + 32 + e.index * 32


def _entry_crc_bytes(img, typ: int) -> set:
    eo = _entry_off(img, typ)
    return {eo + 0x1A, eo + 0x1B, eo + 0x1E, eo + 0x1F}


def _zw_pad(text: str) -> int:
    d = zlib.compress(text.encode("latin1"), 9)
    return len(d) + (4 - len(d) % 4) % 4


def _with_marker(lines: list, build_id: str) -> list:
    a = lines.index(INI_ANCHOR)
    return lines[:a + 1] + [build_id] + lines[a + 1:]


def _trim_ini(ini_lines: list) -> list:
    psi = None
    psi_end = 0
    if ";;[PS_INFO]" in ini_lines:
        psi = psi_end = ini_lines.index(";;[PS_INFO]")
        while psi_end < len(ini_lines) and ini_lines[psi_end].startswith(";;"):
            psi_end += 1
    dropped = set()
    for i, line in enumerate(ini_lines):
        if line.startswith(";; Generated automatically by iniprep tool"):
            dropped.add(i)
        elif psi is not None and psi <= i < psi_end:
            dropped.add(i)
        elif line.startswith(";;") and len(line) > INI_TRIM_DESC_LEN:
            dropped.add(i)
    kept = [l for i, l in enumerate(ini_lines) if i not in dropped]
    if [l for l in kept if not l.startswith(";;")] != \
            [l for l in ini_lines if not l.startswith(";;")]:
        raise LclError("ini trim touched key=value lines (forbidden)")
    nav_kept = [l for i, l in enumerate(ini_lines)
                if i not in dropped and l.startswith(";;;;")]
    nav_all = [l for l in ini_lines
               if l.startswith(";;;;") and len(l) <= INI_TRIM_DESC_LEN]
    if nav_kept != nav_all:
        raise LclError("ini trim dropped navigational ;;;; comments")
    return kept


BuildResult = namedtuple("BuildResult", "final zones step1 zones_lcl zones_ini")


def build_image(base_buf: bytes, mask: int, build_id: str) -> BuildResult:
    """Patch lcl[0] + inject the R1 build-ID; return staged buffers + zones.

    The `final` buffer is fully CRC-valid but UNSIGNED: run
    `mlxfwutil.py sign` (R5) and the guides step (R3) in the CLI flow to
    get a burn-ready image. Zones are the allowed diff byte sets vs the
    base: `zones_lcl` for the lcl step, `zones_ini` for the 0x30 build-ID
    step, `zones` = both combined.
    """
    mask = validate_mask(mask)
    if "\n" in build_id or not build_id.startswith("; "):
        raise LclError('build-ID must be a single "; "-comment line (R1)')
    img = mlxfwutil.Image(base_buf, "base")
    if img.fmt != "fs3":
        raise LclError(f"base is {img.fmt}, expected fs3")
    e12 = img.find_entry("ITOC", FW_MAIN_CFG)
    a12 = img.sec_abs(e12)
    stock = base_buf[a12 + LCL0_OFF]
    if stock != STOCK_LCL0:
        raise LclError(f"base lcl[0] @0x{a12 + LCL0_OFF:x} = {stock:#04x} "
                       f"!= stock {STOCK_LCL0:#04x} (base not pristine?)")
    if base_buf[a12 + LCL1_OFF] != 0x00:
        raise LclError("base lcl[1] != 0x00 (single-port assumption broken)")
    prs = prs_lcl0_speeds(img)
    hot = [f for f in ("56G", "100G") if prs.get(f) == 1]
    if hot:
        raise LclError(f"PRS lcl[0] already carries {hot} (base not pristine)")

    new_lcl0 = stock | mask
    out = mlxfwutil.patch_sections(
        img, [(FW_MAIN_CFG, LCL0_OFF, bytes([new_lcl0]))])
    errs = mlxfwutil.verify_image(
        mlxfwutil.Image(out, "step1", fmt=img.fmt), deep=True)
    if errs:
        raise LclError(f"step1 verify(deep): {errs}")
    zones_lcl = {a12 + LCL0_OFF} | _entry_crc_bytes(img, FW_MAIN_CFG)

    img1 = mlxfwutil.Image(out, "step1", fmt=img.fmt)
    e30 = img1.find_entry("ITOC", DBG_FW_INI)
    raw30 = img1.section_data(e30)
    if raw30[:2] != b"\x78\xda":
        raise LclError("0x30 section is not zlib")
    ini_lines = zlib.decompress(raw30).decode("latin1").split("\n")
    if ini_lines.count(INI_ANCHOR) != 1:
        raise LclError(f"ini anchor {INI_ANCHOR!r} not found exactly once")
    budget30 = e30.size - 32
    new_lines = _with_marker(ini_lines, build_id)
    n_untrimmed = _zw_pad("\n".join(new_lines))
    if n_untrimmed > budget30:
        new_lines = _with_marker(_trim_ini(ini_lines), build_id)
    ini_final = "\n".join(new_lines)
    n_final = _zw_pad(ini_final)
    if n_final > budget30:
        raise LclError(f"0x30 budget exceeded even after trim "
                       f"({n_final} > {budget30}): STOP per R2")
    out2 = mlxfwutil.inject_ini(img1, ini_final)
    img_fin = mlxfwutil.Image(out2, "final", fmt=img.fmt)
    rt30 = mlxfwutil.extract_section(img_fin, DBG_FW_INI)
    rt_ini = zlib.decompress(rt30) if rt30[:2] == b"\x78\xda" else rt30
    if rt_ini != ini_final.encode("latin1"):
        raise LclError("0x30 round-trip failed: extract != ini-final")
    e30n = img_fin.find_entry("ITOC", DBG_FW_INI)
    if e30n.addr != e30.addr or e30n.size > e30.size:
        raise LclError(f"0x30 moved/grew: 0x{e30.addr:x}+0x{e30.size:x} -> "
                       f"0x{e30n.addr:x}+0x{e30n.size:x}")
    errs = mlxfwutil.verify_image(img_fin, deep=True)
    if errs:
        raise LclError(f"final verify(deep) after inject: {errs}")
    zones_ini = set(range(img1.sec_abs(e30), img1.sec_abs(e30) + e30.size))
    zones_ini |= set(range(_entry_off(img1, DBG_FW_INI),
                           _entry_off(img1, DBG_FW_INI) + 32))
    return BuildResult(out2, zones_lcl | zones_ini, out, zones_lcl, zones_ini)


def _run_cli(argv: list) -> tuple:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = mlxfwutil.main(argv)
    return rc, out.getvalue(), err.getvalue()


def _diff_control(label: str, new: bytes, old: bytes, allowed: set) -> list:
    diffs = [i for i in range(min(len(new), len(old))) if new[i] != old[i]]
    stray = [i for i in diffs if i not in allowed]
    print(f"[d] {label}: {len(diffs)} diff bytes, "
          f"stray={[hex(i) for i in stray] if stray else 'NONE'}")
    if len(new) != len(old):
        raise SystemExit(f"FATAL: size changed {len(old)} -> {len(new)}")
    if stray:
        raise SystemExit(f"FATAL: stray diff bytes in {label}: "
                         f"{[hex(i) for i in stray]}")
    return diffs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="arc D L1/L2 builder: lcl[0] speed-bit patch + gates")
    ap.add_argument("--base", required=True)
    ap.add_argument("--lcl-bits", required=True, type=lambda s: int(s, 0),
                    help="OR-mask over {0x40:56G, 0x80:100G} (L1=0x40, L2=0xc0)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--guid", type=lambda s: int(s, 0),
                    help="base GUID to embed (R3, mstflint q of the target card)")
    ap.add_argument("--mac", type=lambda s: int(s, 0),
                    help="base MAC to embed (R3)")
    ap.add_argument("--label", help="ladder step name for the build-ID")
    ap.add_argument("--build-id", help="full build-ID line override (R1)")
    ap.add_argument("--date", default="2026-11-12")
    ap.add_argument("--skip-mstflint", action="store_true")
    args = ap.parse_args(argv)

    mask = validate_mask(args.lcl_bits)
    base_buf = Path(args.base).read_bytes()
    md5_base = hashlib.md5(base_buf).hexdigest()
    print(f"[1] base {args.base}: md5 {md5_base} size {len(base_buf)}")
    img = mlxfwutil.Image(base_buf, args.base)
    e12 = img.find_entry("ITOC", FW_MAIN_CFG)
    a12 = img.sec_abs(e12)
    label = args.label or mask_label(mask)
    build_id = args.build_id or (
        f"; mlxini serdes-arc-d {label} ({args.date}, {md5_base}): "
        f"lcl[0] {STOCK_LCL0:#04x}->{base_buf[a12 + LCL0_OFF] | mask:#04x} "
        f"@0x{a12 + LCL0_OFF:x} ({mask_label(mask)} bit(s), "
        f"journal 2026-11-12-serdes-arc-d-task-01)")

    res = build_image(base_buf, mask, build_id)
    new_lcl0 = base_buf[a12 + LCL0_OFF] | mask
    print(f"[2] lcl[0]: {STOCK_LCL0:#04x} -> {new_lcl0:#04x} "
          f"@0x{a12 + LCL0_OFF:x} (0x12+{LCL0_OFF:#x}); lcl[1] @0x{a12 + LCL1_OFF:x} "
          f"untouched; sec/entry CRC recomputed; verify(deep)=PASS")
    _diff_control("step1 vs base (lcl + 0x12 CRC)", res.step1, base_buf,
                  res.zones_lcl)
    print(f"[3] ini build-ID (R1/R2): \"{build_id}\"")
    e30 = img.find_entry("ITOC", DBG_FW_INI)
    print(f"    0x30 in place @0x{img.sec_abs(e30):x} size 0x{e30.size:x}; "
          f"round-trip OK")
    _diff_control("ini vs step1 (0x30 build-ID)", res.final, res.step1,
                  res.zones_ini)

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
        print(f"[4] guides (R3): GUID {args.guid:#x} / MAC {args.mac:#x}: "
              f"rc={rc} {' '.join(o.split())}")
        if rc != 0:
            raise SystemExit(f"FATAL: guides failed: {e.strip()}")
        final = pg.read_bytes()
        zones_guides = set()
        for typ in (DEV_INFO, MFG_INFO):
            de = img.find_entry("ITOC", typ)
            zones_guides |= set(range(img.sec_abs(de), img.sec_abs(de) + de.size))
            zones_guides |= set(range(_entry_off(img, typ),
                                      _entry_off(img, typ) + 32))
        zones |= zones_guides
        _diff_control("guides vs ini (E1+E0)", final, res.final, zones_guides)
    else:
        print("[4] guides (R3): SKIPPED (--guid/--mac not given; "
              "embed before burn)")

    pf = Path(args.out)
    pf.write_bytes(final)
    rc, o, e = _run_cli(["sign", str(pf)])
    print(f"[5] sign (R5): rc={rc} {' '.join(o.split())}")
    if rc != 0:
        raise SystemExit(f"FATAL: sign failed: {e.strip()}")
    final = pf.read_bytes()
    ea = img.find_entry("ITOC", SIG_256)
    aa = img.sec_abs(ea)
    zones |= set(range(aa + mlxfwutil.SIG_SLOT_OFF,
                       aa + mlxfwutil.SIG_SLOT_OFF + 32))
    zones |= _entry_crc_bytes(img, SIG_256)

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

    diffs = _diff_control("final vs base (lcl + CRCs + 0x30 + guides + digest)",
                          final, base_buf, zones)
    if final[a12 + LCL0_OFF] != new_lcl0:
        raise SystemExit("FATAL: final lcl[0] byte lost")
    md5_out = hashlib.md5(final).hexdigest()
    print(f"[9] {pf}: md5 {md5_out} size {len(final)}, "
          f"{len(diffs)} changed bytes (all in expected zones)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
