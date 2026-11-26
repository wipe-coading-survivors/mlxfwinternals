#!/usr/bin/env python3
"""cx4lx-fdr-gate: arc F patch-candidate builder (F3).

Offline builder for the arc F burn ladder (journal
docs/superpowers/journal/2026-11-23-serdes-arc-f-task-02.md; spec
docs/superpowers/specs/2026-11-23-serdes-arc-f-design.md §3).  Targets
are pinned by the T1 verdict (loader chain proven up to the ROM wall;
0x12+0x158 not refuted as the class carrier):

  p1     FCA-like minimal: 0x12+0x158 0x30->0x10 (FDR class byte).
  p1v    p1 + VPI byte 0x11+0x2af 0x0a->0x07 (EN->VPI, IB-proto switch
         for the pre-link PDDR discriminator; plan amendment f4aa8878).
         Pin: scripts/probes/serdes-arc-d/build_l34.py:88,106-109
         (VPI_SEC=0x11, VPI_OFF=0x2AF -> abs 0x172AF on the 1912-GCA
         layout, VPI_OLD=0x0a EN stock -> VPI_NEW=0x07 ib+eth def-IB).
  p2     ECA-like tuple:   0x12+0x158->0x31, +0x283->0x12,
         +0x2c5->0x10 (byte view of the big-endian dwords dw@+0x280 /
         dw@+0x2c4 of loader_reverse.f3_targets).
  p2full p2 + lcl advertisement pair +0x30b/+0x317 set from the FCA
         corpus reference (default build/corpus/cx4/12_28_4706/
         MCX456A-FCA: 5b/5b).  The ECA reference carries fb/fb instead;
         picking FCA values is a coordinator decision (task-02 brief).
  P3 is inactive (T1 did not refute +0x158); 0x11+0x35 is parked.

Pipeline per image: byte patch through mlxfwutil.patch_sections (this
recomputes sec_crc + entry_crc of the touched section, patch-matrix
docs/550-poc/100-mlxfwutil/020-patch-matrix.md §1), then an in-memory
0xA0 SHA-256 digest refresh (mlxfwutil.autosign_after_relocation, the
cmd_sign semantics -- mandatory before a plain/MCC burn on a non-secure
card, docs/850-howto/100-cross-flash-ops.md §6), then offline gates:
verify_image + burn-order invariant + fresh 0xA0 + byte-diff canary.
The canary enumerates its allowed zones (patch bytes, 0x12 entry
CRC bytes, 0xA0 digest slot + entry CRC bytes) from ITOC metadata --
never from the observed diff -- so it cannot be tautological.

Usage:
  build_arc_f.py --variant {p1,p1v,p2,p2full} [--base PATH] [--out PATH]
      [--corpus DIR] [--fca-ref REL] [--json OUT]

Stdlib only; offline (no hardware, no ssh).  Images land in build/
(git-ignored) and are never committed.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import mlxfwutil as fw  # noqa: E402

DEFAULT_BASE = REPO / "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin"
DEFAULT_CORPUS = REPO / "build" / "corpus"
FCA_REF_REL = "cx4/12_28_4706/MCX456A-FCA"
DEFAULT_OUT_DIR = REPO / "build"

SECTION = 0x12
CLASS_BYTE = 0x158
P2_TUPLE = ((0x158, 0x31), (0x283, 0x12), (0x2C5, 0x10))
LCL_BYTES = (0x30B, 0x317)

# VPI byte (arc D primary source scripts/probes/serdes-arc-d/
# build_l34.py:88,106-109): section 0x11, rel +0x2af = abs 0x172af on
# the 1912-GCA layout (0x11 @0x17000), EN stock 0x0a -> 0x07
# (VPI, ib+eth, def-IB).
VPI_SEC = 0x11
VPI_OFF = 0x2AF
VPI_NEW = 0x07

# Pinned preconditions of the 1912-GCA Lx stock base (corpus ground
# truth re-verified 2026-11-24, raw.bin == dc.bin for section 0x12;
# 0x11+0x2af EN live-re-verified against the refs image 2026-11-24).
EXPECTED_BASE = {
    0x12: {0x158: 0x30, 0x283: 0x00, 0x2C5: 0x00,
           0x30B: 0x3B, 0x317: 0x00},
    0x11: {0x2AF: 0x0A},
}

VARIANTS = ("p1", "p1v", "p2", "p2full")


class BuildError(Exception):
    """Refuse to build: wrong base / reference / variant."""


def variant_edits(variant, lcl=(None, None)):
    """Deterministic edit list [(section, off, bytes)] for a variant."""
    if variant == "p1":
        return [(SECTION, CLASS_BYTE, bytes([0x10]))]
    if variant == "p1v":
        return variant_edits("p1") + [(VPI_SEC, VPI_OFF, bytes([VPI_NEW]))]
    if variant == "p2":
        return [(SECTION, off, bytes([v])) for off, v in P2_TUPLE]
    if variant == "p2full":
        if lcl[0] is None or lcl[1] is None:
            raise BuildError("p2full requires the FCA reference lcl pair")
        edits = variant_edits("p2")
        edits += [(SECTION, off, bytes([v])) for off, v in zip(LCL_BYTES, lcl)]
        return edits
    raise BuildError(f"unknown variant {variant!r} (want {'|'.join(VARIANTS)})")


def fca_lcl_from_corpus(corpus_root=DEFAULT_CORPUS, ref=FCA_REF_REL):
    """lcl0/lcl1 (+ sanity class byte) from a corpus FCA build dir."""
    d = Path(corpus_root) / ref / "sections" / "12"
    src = None
    for name in ("raw.bin", "dc.bin"):
        if (d / name).is_file():
            src = d / name
            break
    if src is None:
        raise BuildError(f"FCA reference section not found: {d}/raw.bin "
                         "(rebuild the corpus: make corpus)")
    b = src.read_bytes()
    if b[CLASS_BYTE] != 0x10:
        raise BuildError(f"FCA reference {ref}: 0x12+0x158="
                         f"0x{b[CLASS_BYTE]:02x}, want 0x10 (not an FCA "
                         "build -- refusing to source lcl values)")
    return {"ref": str(Path(corpus_root) / ref), "src": str(src),
            "class_0x158": b[CLASS_BYTE],
            "lcl0": b[LCL_BYTES[0]], "lcl1": b[LCL_BYTES[1]]}


def check_base(img):
    """Refuse anything but the pinned Lx-GCA stock byte layout."""
    for t, want_map in sorted(EXPECTED_BASE.items()):
        sec = img.section_data(img.find_entry("ITOC", t))
        for off, want in sorted(want_map.items()):
            got = sec[off]
            if got != want:
                raise BuildError(
                    f"base 0x{t:02x}+0x{off:x}=0x{got:02x}, expected "
                    f"0x{want:02x} (not the pinned 14.32.1912 MCX4131A-GCA "
                    "stock; refusing)")


def _entry_crc_zones(img, e, label):
    """ITOC-entry CRC byte ranges that a section rewrite may touch."""
    ent_off = img.itoc_off + 32 + e.index * 32
    # sec_crc = bits 208..223 (bytes 0x1A-0x1B), entry_crc = bits
    # 240..255 (bytes 0x1E-0x1F) of the 32-byte ITOC entry
    return [{"kind": "sec_crc", "abs": ent_off + 0x1A, "size": 2,
             "note": f"{label} entry sec_crc"},
            {"kind": "entry_crc", "abs": ent_off + 0x1E, "size": 2,
             "note": f"{label} entry_crc"}]


def byte_diff_canary(base_img, out_img, edits):
    """Diff base<->out must be EXACTLY the patch bytes, inside an
    explicitly enumerated allow-list of CRC/digest zones.

    Zones come from ITOC metadata (entry offsets) and the 0xA0 layout
    (digest slot @+0x20), never from the observed diff.  ok = every
    patch byte changed (no missing) AND nothing changed outside the
    zones (no extra).
    """
    zones = []
    by_type = {}
    for t, off, data in edits:
        by_type.setdefault(t, []).append((off, data))
    for t, ed in by_type.items():
        e = base_img.find_entry("ITOC", t)
        a = base_img.sec_abs(e)
        for off, data in ed:
            zones.append({"kind": "patch", "abs": a + off,
                          "size": len(data), "rel": off,
                          "section": f"0x{t:02x}", "required": True})
        zones += _entry_crc_zones(base_img, e, f"0x{t:02x}")
    e_sig = base_img.find_entry("ITOC", 0xA0)
    zones.append({"kind": "digest_slot",
                  "abs": base_img.sec_abs(e_sig) + fw.SIG_SLOT_OFF,
                  "size": 32, "note": "0xA0 SHA-256 digest @+0x20"})
    zones += _entry_crc_zones(base_img, e_sig, "0xA0")

    if len(base_img.buf) != len(out_img.buf):
        return {"ok": False, "error": "size mismatch",
                "zones": zones, "content": [], "extra": [], "missing": []}

    a, b = base_img.buf, out_img.buf
    diffs = []
    chunk = 1 << 20
    for start in range(0, len(a), chunk):
        if a[start:start + chunk] == b[start:start + chunk]:
            continue
        diffs.extend(i for i in range(start, min(start + chunk, len(a)))
                     if a[i] != b[i])

    def zone_of(i):
        for z in zones:
            if z["abs"] <= i < z["abs"] + z["size"]:
                return z
        return None

    content, extra = [], []
    for i in diffs:
        z = zone_of(i)
        if z is None:
            extra.append({"abs": i, "old": a[i], "new": b[i]})
        elif z["kind"] == "patch":
            content.append({"abs": i, "rel": z["rel"],
                            "section": z["section"],
                            "old": a[i], "new": b[i]})
    missing = []
    for z in zones:
        z["changed"] = any(z["abs"] <= i < z["abs"] + z["size"] for i in diffs)
        if z["kind"] == "patch" and not z["changed"]:
            missing.append({"section": z["section"], "rel": z["rel"],
                            "expected": "0x%02x" % out_img.buf[z["abs"]]})
    ok = not extra and not missing
    return {"ok": ok, "content": content, "extra": extra, "missing": missing,
            "zones": zones}


def build(base_buf, variant, lcl=(None, None)):
    """base bytes -> (image bytes, report).  Gates inside the report."""
    img = fw.Image(base_buf, "<base>")
    errs = fw.verify_image(img)
    if errs:
        raise BuildError(f"base image does not verify: {errs}")
    base_sig = fw.sig_status(img)[0]
    check_base(img)
    edits = variant_edits(variant, lcl)

    patched = fw.patch_sections(img, edits)
    status, signed, digest = fw.autosign_after_relocation(
        patched, img.base, img.fmt)
    if signed is None:
        raise BuildError(f"0xA0 {status}: cannot refresh the digest")

    vimg = fw.Image(signed, "<out>", base=img.base, fmt=img.fmt)
    gates = {
        "verify_image": fw.verify_image(vimg) == [],
        "burn_order": fw.burn_order_check(vimg) == [],
        "sig_fresh": fw.sig_status(vimg)[0] == "fresh",
    }
    canary = byte_diff_canary(img, vimg, edits)
    gates["canary"] = bool(canary["ok"])
    report = {
        "variant": variant,
        "base": {"size": len(base_buf),
                 "md5": hashlib.md5(base_buf).hexdigest(),
                 "sig_status": base_sig},
        "edits": [{"section": f"0x{t:02x}", "offset": off,
                   "old": "0x%02x" % img.section_data(
                       img.find_entry("ITOC", t))[off],
                   "new": "0x%02x" % data[0],
                   "abs": img.sec_abs(img.find_entry("ITOC", t)) + off}
                  for t, off, data in edits],
        "digest_0xa0": digest.hex(),
        "md5": hashlib.md5(signed).hexdigest(),
        "size": len(signed),
        "gates": gates,
        "canary": canary,
        "burn_order_violations": [v.explanation for v in
                                  fw.burn_order_check(vimg)],
        "verify_errors": fw.verify_image(vimg),
    }
    return signed, report


def main(argv=None):
    desc = (__doc__ or "").splitlines()[0]
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE,
                        help="stock base image (default: refs 1912-GCA)")
    parser.add_argument("--variant", required=True, choices=VARIANTS)
    parser.add_argument("--out", type=Path, default=None,
                        help="output image (default: build/arc-f-<variant>.bin)")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--fca-ref", default=FCA_REF_REL,
                        help="corpus FCA build dir (lcl source for p2full)")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    out = args.out or (DEFAULT_OUT_DIR / f"arc-f-{args.variant}.bin")
    lcl = (None, None)
    fca = None
    if args.variant == "p2full":
        fca = fca_lcl_from_corpus(args.corpus, args.fca_ref)
        lcl = (fca["lcl0"], fca["lcl1"])
        print(f"fca reference: {fca['src']} -> lcl0=0x{lcl[0]:02x} "
              f"lcl1=0x{lcl[1]:02x}")

    if not args.base.is_file():
        print(f"error: base image not found: {args.base}", file=sys.stderr)
        return 2
    try:
        signed, report = build(args.base.read_bytes(), args.variant, lcl=lcl)
    except BuildError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(signed)
    report["output"] = str(out)
    report["fca_reference"] = fca
    for e in report["edits"]:
        print(f"edit: {e['section']}+0x{e['offset']:x} "
              f"{e['old']} -> {e['new']} (abs 0x{e['abs']:x})")
    print(f"digest 0xA0: {report['digest_0xa0']}")
    print(f"gates: {report['gates']}")
    can = report["canary"]
    print(f"canary: ok={can['ok']} content={len(can['content'])}B "
          f"extra={len(can['extra'])} missing={len(can['missing'])}")
    print(f"{out}: md5 {report['md5']} ({len(signed)} bytes)")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    return 0 if all(report["gates"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
