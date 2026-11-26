#!/usr/bin/env python3
"""cx4lx-fdr-gate: arc H-F2 hf2-max builder (G2).

Offline builder of the single max image `hf2-max` (spec
docs/superpowers/specs/2026-11-24-serdes-arc-hf2-design.md §4; plan
docs/superpowers/plans/2026-11-25-serdes-arc-hf2.md task 4; journals
2026-11-25-serdes-arc-hf2-task-0{1,2,3}.md).  Patch set (max by design,
ruling §2.5 -- full identifier set, diff minimization is not a goal):

  VPI byte    0x11+0x2af 0x0a->0x07 (EN->VPI; mstconfig LINK_TYPE_P1
              switching, precedent P1v / arc D L3v, ruling §2.3).
  EDR tuple   0x12 {+0x158->0x31, +0x283->0x12, +0x2c5->0x10,
              lcl +0x30b->0xfb, +0x317->0xfb} -- task-03 eth_verdict
              (mode=unified: the ETH speed-enable lives in the same
              tuple, NO separate ETH sites; ECA reference, lcl fb/fb).
  MAIN_CODE   4 words of the task-02 spec
              scripts/probes/gate-specs/hf2-dispatcher-cx4lx-1912.json
              (dispatcher 0x1be12c + twin 0x1fc488 + polling
              0x1b330c/0x1b335c; ld.i r4,0x3686 -> addi r4,zero,0x400)
              through the cable-gate pipeline (decrc -> patch dc bytes
              -> clcrc reframe -> ITOC entry CRC).
  build-ID    Rule 1 comment in the 0x30 DBG_FW_INI (exact string
              BUILD_ID below) right after the ";; Mellanox Technologies
              LTD" line.
  GUID/MAC    card identity embedded pre-burn (Rule 3, FNP risk class):
              ONLY from explicit CLI args --guid/--mac (source: task-01
              journal, mstflint q on 05:00.0), pinned in the JSON
              report.
  0xA0        re-signed after every content step (Rule 5; idempotent --
              checked in-gate), `sign --check` rc 0 fresh at handoff.

0x30 growth handling: the base budget (0x6a4) does not fit the
build-ID (1806 > 1700) -> inject with force (the gated-safe
relocation: plan_relocations, burn-order invariant checked, autosign);
`;;`-trimming is deliberately NOT used (minimization is not a goal).

Canary: byte-diff vs the base is allowed ONLY inside zones enumerated
from ITOC metadata and the relocation plan BEFORE comparing (never
from the observed diff): patch bytes, clcrc of the touched MAIN_CODE
lines, 0x30 (old erased range / new range / moved ITOC rows), entry
CRCs of the touched sections, guides uid/mac 0xE1/0xE0 zones, the 0xA0
digest slot.  ok = no extra bytes AND no missing required zone AND old
0x30 fully erased AND guides bytes equal the CLI values.

FS3 note: `verify --deep` checks per-line clcrc on FS4 only; this
builder gates per-line clcrc explicitly (clcrc_lines_errors over every
clcrc=1 section of the output image) -- the "per-line clcrc" gate of
the brief for our FS3 image.

Usage:
  build_hf2.py --guid <card-guid-hex> --mac <card-mac-hex>
      [--base PATH] [--spec PATH] [--out PATH] [--json PATH]
  (real lab identifiers are never hardcoded here: they come from the
  task-01 journal and are passed explicitly at build time)

Stdlib + mlxfwutil + cable_gate_patch only; offline (no hardware, no
ssh).  The image lands in build/ (git-ignored) and is never committed;
the md5 pin goes to the task-04 journal.
"""
import argparse
import hashlib
import json
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
for _p in (str(REPO), str(REPO / "scripts" / "probes")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import mlxfwutil as fw  # noqa: E402
import cable_gate_patch as cgp  # noqa: E402

DEFAULT_BASE = (REPO / "refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-"
                "MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")
SPEC_PATH = REPO / "scripts/probes/gate-specs/hf2-dispatcher-cx4lx-1912.json"
DEFAULT_OUT = REPO / "build" / "hf2-max.bin"
DEFAULT_JSON = REPO / "build" / "hf2-max.json"

# Rule 1 (exact, ruling §2.5): iniprep-style comment right after the
# ";; Mellanox Technologies LTD" line of the 0x30 ini.
BUILD_ID = ("; mlxini hf2-max (2026-11-24, docs/superpowers/specs/"
            "2026-11-24-serdes-arc-hf2-design.md): dispatcher "
            "special-path + EDR-class tuple + ETH 100/56 unlock\n")
INI_ANCHOR = ";; Mellanox Technologies LTD\n"

# VPI byte (arc D primary source scripts/probes/serdes-arc-d/
# build_l34.py:88,106-109): section 0x11, rel +0x2af, EN stock 0x0a ->
# 0x07 (VPI, ib+eth, def-IB).
VPI_SEC = 0x11
VPI_OFF = 0x2AF
VPI_NEW = 0x07

# EDR-class tuple (task-03 hf2_reverse.eth_verdict, ECA reference,
# lcl fb/fb): 0x12 FW_MAIN_CFG bytes.
TUPLE_0x12 = {0x158: 0x31, 0x283: 0x12, 0x2C5: 0x10,
              0x30B: 0xFB, 0x317: 0xFB}
TUPLE_NOTES = {
    0x158: "IB speed-class byte (0x30 ETH stock -> 0x31 EDR class)",
    0x283: "dw280 hi byte: product SerDes/speed vector (0x12 = EDR/100G)",
    0x2C5: "dw2c4 hi byte (ECA dword value 0x00100000)",
    0x30B: "lcl[0] eth_speeds_supported (fb = +56G+100G bits)",
    0x317: "lcl[1] eth_speeds_supported (GCA 1-port stock 0x00 -> fb)",
}

# task-03 verdict: mode=unified, sites=[] -- the ETH speed-enable lives
# inside the EDR-class tuple; there are NO separate ETH patch sites.
ETH_SITES = ()

GUID_SOURCE = ("docs/superpowers/journal/2026-11-25-serdes-arc-hf2-"
               "task-01.md (mstflint -d 05:00.0 q, root-bazzite)")

# Pinned preconditions of the 1912-GCA Lx stock base (corpus ground
# truth re-verified 2026-11-24; 0x11+0x2af EN live-re-verified).
EXPECTED_BASE = {
    0x12: {0x158: 0x30, 0x283: 0x00, 0x2C5: 0x00,
           0x30B: 0x3B, 0x317: 0x00},
    0x11: {0x2AF: 0x0A},
}

CLCRC_LINE = 68
CLCRC_CRC_OFF = 66

GUIDES_SECTIONS = (0xE1, 0xE0)
GUIDES_UID_OFF = 0x28
GUIDES_MAC_OFF = 0x38


class BuildError(Exception):
    """Refuse to build: wrong base / spec / identifiers."""


def edits():
    """Deterministic edit list [(section, off, bytes)]: VPI + tuple."""
    return ([(VPI_SEC, VPI_OFF, bytes([VPI_NEW]))]
            + [(0x12, off, bytes([v])) for off, v in sorted(TUPLE_0x12.items())])


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


def load_spec(path):
    spec = json.loads(Path(path).read_text())
    for key in ("id", "section", "patches"):
        if key not in spec:
            raise BuildError(f"spec {path}: missing key {key!r}")
    for p in spec["patches"]:
        for key in ("offset", "bytes"):
            if key not in p:
                raise BuildError(f"spec {path}: patch missing {key!r}")
        int(p["offset"], 0)
        bytes.fromhex(p["bytes"].replace(" ", ""))
    return spec


# ------------------------------------------------------------- MAIN_CODE

def mc_word_map(img, spec):
    """Spec patches -> {dc_off: (framed_abs, clcrc_abs, word_bytes)}.

    A spec word must live inside a single 64B clcrc line (the reframe
    pipeline is line-oriented); framed/clcrc offsets are enumerated
    from the ITOC metadata (sec_abs) and the dc offset arithmetic.
    """
    sect = int(spec["section"])
    e = img.find_entry("ITOC", sect)
    a = img.sec_abs(e)
    out = {}
    for p in spec["patches"]:
        off = int(p["offset"], 0)
        wb = bytes.fromhex(p["bytes"].replace(" ", ""))
        line, in_line = divmod(off, 64)
        if in_line + len(wb) > 64:
            raise BuildError(f"spec word 0x{off:x}+{len(wb)}B crosses a "
                             "clcrc line (68B framing)")
        out[off] = (a + line * CLCRC_LINE + in_line,
                    a + line * CLCRC_LINE + CLCRC_CRC_OFF, wb)
    return out


def patch_main_code(img, spec):
    """cable-gate pipeline: decrc -> check/patch dc bytes -> reframe ->
    patch_sections (sec_crc + entry_crc)."""
    sect = int(spec["section"])
    errs = cgp.check_spec(spec, img)
    if errs:
        raise BuildError("MAIN_CODE spec check: " + "; ".join(errs))
    e = img.find_entry("ITOC", sect)
    raw = img.section_data(e)
    code, tail = cgp.deframe(raw, e.clcrc)
    if e.clcrc and cgp.reframe(code, tail) != raw:
        raise BuildError("clcrc round-trip FAILED on stock MAIN_CODE")
    code = bytearray(code)
    for p in spec["patches"]:
        off = int(p["offset"], 0)
        wb = bytes.fromhex(p["bytes"].replace(" ", ""))
        code[off:off + len(wb)] = wb
    new_raw = cgp.reframe(bytes(code), tail) if e.clcrc else bytes(code)
    return fw.patch_sections(img, [(sect, 0, new_raw)])


# ------------------------------------------------------------------ 0x30

def extract_ini_text(img):
    data = fw.extract_section(img, 0x30)
    if data[:2] != b"\x78\xda":
        raise BuildError(f"0x30: not a zlib stream (magic {data[:2].hex()})")
    return zlib.decompress(data).decode("latin1")


def add_build_id(text, build_id=BUILD_ID):
    i = text.find(INI_ANCHOR)
    if i < 0:
        raise BuildError("0x30 ini: anchor line not found "
                         f"({INI_ANCHOR!r})")
    j = i + len(INI_ANCHOR)
    if build_id in text:
        raise BuildError("0x30 ini: build-ID already present")
    return text[:j] + build_id + text[j:]


def inject_build_id(img, new_text):
    """0x30 re-inject: in-place if the budget fits, else the gated-safe
    relocation (plan_relocations).  Refuses on burn-order violations
    (the cmd inject pre-write gate)."""
    try:
        out = fw.inject_ini(img, new_text, force=True)
    except ValueError as ex:
        raise BuildError(f"0x30 inject: {ex}")
    vimg = fw.Image(out, "<0x30>", base=img.base, fmt=img.fmt)
    violations = fw.burn_order_check(vimg)
    if violations:
        raise BuildError("0x30 inject: burn-order violation, refusing: "
                         + violations[0].explanation)
    return out


# ---------------------------------------------------------------- guides

def embed_guids(img, guid, mac):
    """Rule 3: card identity into DEV_INFO (0xE1) + MFG_INFO (0xE0) of
    the FS3 image (the cmd_guides_fs3 write path: uid @+0x28, mac
    @+0x38, sec_crc + entry_crc for crcf=0, self-verify)."""
    if guid is None or mac is None:
        raise BuildError("guid/mac are required (explicit CLI args only; "
                         "source: task-01 journal)")
    try:
        e1 = img.find_entry("ITOC", 0xE1)
        e0 = img.find_entry("ITOC", 0xE0)
    except KeyError as ex:
        raise BuildError(f"guides: {ex}")
    d1 = bytearray(img.section_data(e1))
    if not fw.devinfo_sig_ok(bytes(d1)):
        raise BuildError("guides: DEV_INFO (0xE1) signature not OK")
    major1 = ((d1[0x11] & 1) << 8) | d1[0x12]
    if major1 != 2:
        raise BuildError(f"guides: DEV_INFO major_version {major1} "
                         "(need 2, cx4fw layout)")
    d0 = bytearray(img.section_data(e0))
    if d0[fw.MFG3_MAJOR_OFF] != 1:
        raise BuildError(f"guides: MFG_INFO major_version "
                         f"{d0[fw.MFG3_MAJOR_OFF]} (need 1, cx4fw layout)")
    warning = None
    if not d0[fw.MFG3_OVR_OFF] & 1:
        warning = "MFG_INFO guids_override_en=0 (mstflint setguid would " \
                  "require -ocr); wrote both nodes anyway"
    b = bytearray(img.buf)
    g = guid.to_bytes(8, "big")
    m = mac.to_bytes(8, "big")
    changes = []
    for e, d in ((e1, d1), (e0, d0)):
        name = "DEV_INFO" if e is e1 else "MFG_INFO"
        a = img.sec_abs(e)
        d[GUIDES_UID_OFF:GUIDES_UID_OFF + 8] = g
        d[GUIDES_MAC_OFF:GUIDES_MAC_OFF + 8] = m
        b[a:a + e.size] = bytes(d)
        if e.crcf == 1:
            changes.append(f"{name} @0x{a:x}: uid+mac (no_crc=1, no CRC)")
            continue
        sec_crc = fw.crc16_mlx(bytes(d))
        ent_off = img.itoc_off + 32 + e.index * 32
        ent = bytearray(b[ent_off:ent_off + 32])
        fw.set_bits(ent, 208, 16, sec_crc)
        fw.set_bits(ent, 240, 16, fw.crc16_mlx(bytes(ent[:28])))
        b[ent_off:ent_off + 32] = ent
        changes.append(f"{name} @0x{a:x}: uid+mac, sec_crc "
                       f"0x{e.sec_crc:04x}->0x{sec_crc:04x}, entry_crc "
                       "updated")
    vimg = fw.Image(bytes(b), "<guides>", base=img.base, fmt=img.fmt)
    errs = fw.verify_image(vimg)
    if errs:
        raise BuildError(f"guides self-verify FAIL: {errs[0]}")
    return bytes(b), changes, warning


# ----------------------------------------------------------------- gates

def clcrc_all_ok(img):
    """Explicit FS3 per-line clcrc gate (verify --deep checks FS4 only).
    """
    for e in img.entries("ITOC"):
        if not e.clcrc or e.zipped or e.size < CLCRC_LINE:
            continue
        if fw.clcrc_lines_errors(img.section_data(e)):
            return False
    return True


def _sign(buf, base, fmt, step):
    status, signed, digest = fw.autosign_after_relocation(buf, base, fmt)
    if signed is None:
        raise BuildError(f"0xA0 {status}: cannot sign after {step}")
    return signed, digest


def _self_verify(buf, base, fmt, step):
    errs = fw.verify_image(fw.Image(buf, step, base=base, fmt=fmt))
    if errs:
        raise BuildError(f"{step}: self-verify FAIL: {errs[0]}")


# ---------------------------------------------------------------- canary

def _entry_crc_zones(img, e, label):
    ent_off = img.itoc_off + 32 + e.index * 32
    return [{"kind": "sec_crc", "abs": ent_off + 0x1A, "size": 2,
             "note": f"{label} entry sec_crc"},
            {"kind": "entry_crc", "abs": ent_off + 0x1E, "size": 2,
             "note": f"{label} entry_crc"}]


def _build_zones(base_img, out_img, spec, guid, mac):
    """Allowed diff zones, enumerated from ITOC metadata + the
    relocation layout -- BEFORE any diff comparison."""
    zones = []
    for t, off, data in edits():
        e = base_img.find_entry("ITOC", t)
        zones.append({"kind": "patch", "section": "0x%02x" % t,
                      "rel": off, "abs": base_img.sec_abs(e) + off,
                      "size": len(data), "required": True})
    sect = int(spec["section"])
    e03 = base_img.find_entry("ITOC", sect)
    a03 = base_img.sec_abs(e03)
    for p in spec["patches"]:
        off = int(p["offset"], 0)
        wb = bytes.fromhex(p["bytes"].replace(" ", ""))
        line, in_line = divmod(off, 64)
        zones.append({"kind": "patch", "section": "0x%02x" % sect,
                      "rel": off, "size": len(wb),
                      "abs": a03 + line * CLCRC_LINE + in_line,
                      "required": True})
        zones.append({"kind": "clcrc", "section": "0x%02x" % sect,
                      "rel": off, "size": 2,
                      "abs": a03 + line * CLCRC_LINE + CLCRC_CRC_OFF})
    # 0x30: relocation layout from the base/out ITOC metadata
    e30b = base_img.find_entry("ITOC", 0x30)
    e30o = out_img.find_entry("ITOC", 0x30)
    if base_img.sec_abs(e30b) != out_img.sec_abs(e30o):
        zones.append({"kind": "sec30_old", "abs": base_img.sec_abs(e30b),
                      "size": e30b.size, "erased": True,
                      "note": "relocated 0x30 old place (must be 0xFF)"})
        zones.append({"kind": "sec30_new", "abs": out_img.sec_abs(e30o),
                      "size": e30o.size, "note": "relocated 0x30 data"})
        lo, hi = sorted((e30b.index, e30o.index))
        zones.append({"kind": "itoc_row",
                      "abs": base_img.itoc_off + 32 + lo * 32,
                      "size": (hi - lo + 1) * 32,
                      "note": "moved ITOC rows (0x30 + shifted rows)"})
        moved = (lo, hi)
    else:
        zones.append({"kind": "sec30", "abs": base_img.sec_abs(e30b),
                      "size": max(e30b.size, e30o.size),
                      "note": "0x30 section data (in-place inject)"})
        zones.append({"kind": "itoc_row",
                      "abs": base_img.itoc_off + 32 + e30o.index * 32,
                      "size": 32, "note": "0x30 ITOC row"})
        moved = (e30o.index, e30o.index)
    # entry CRCs of every other touched section (row position stable)
    for t in (sect, 0x11, 0x12, 0xA0) + GUIDES_SECTIONS:
        e = out_img.find_entry("ITOC", t)
        if moved[0] <= e.index <= moved[1]:
            continue  # row covered by the move zone
        zones += _entry_crc_zones(out_img, e, "0x%02x" % t)
    # guides uid/mac zones
    for t in GUIDES_SECTIONS:
        e = base_img.find_entry("ITOC", t)
        a = base_img.sec_abs(e)
        for rel, size in ((GUIDES_UID_OFF, 8), (GUIDES_MAC_OFF, 8)):
            zones.append({"kind": "guides", "section": "0x%02x" % t,
                          "rel": rel, "abs": a + rel, "size": size,
                          "required": True,
                          "note": "card identity (guides)"})
    # 0xA0 digest slot
    ea = base_img.find_entry("ITOC", 0xA0)
    zones.append({"kind": "digest_slot",
                  "abs": base_img.sec_abs(ea) + fw.SIG_SLOT_OFF,
                  "size": 32, "required": True,
                  "note": "0xA0 SHA-256 digest @+0x20"})
    # ETH sites: task-03 verdict unified -> none (documented empty set)
    return zones, (guid, mac)


def canary(base_buf, out_buf, spec, guid, mac):
    """Byte-diff base<->out must touch ONLY the enumerated zones.

    Zones come from ITOC metadata and the relocation layout, never from
    the observed diff.  ok = no extra bytes AND no missing required
    zone AND the old 0x30 place is fully erased AND the guides zones
    hold exactly the CLI guid/mac values.
    """
    base_img = fw.Image(base_buf, "<base>")
    out_img = fw.Image(out_buf, "<out>")
    zones, (guid, mac) = _build_zones(base_img, out_img, spec, guid, mac)

    if len(base_img.buf) != len(out_img.buf):
        return {"ok": False, "error": "size mismatch", "zones": zones,
                "content": [], "extra": [], "missing": [],
                "erased_ok": False, "guides_ok": False}

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
            content.append(z)
    seen = {id(z) for z in content}
    content = [z for z in zones if id(z) in seen]
    missing = []
    for z in zones:
        z["changed"] = any(z["abs"] <= i < z["abs"] + z["size"]
                           for i in diffs)
        if z.get("required") and not z["changed"]:
            missing.append({"kind": z["kind"], "abs": z["abs"],
                            "rel": z.get("rel")})
    erased_ok = all(
        all(b[i] == 0xFF for i in range(z["abs"], z["abs"] + z["size"]))
        for z in zones if z.get("erased"))
    guides_ok = True
    for z in zones:
        if z["kind"] != "guides":
            continue
        want = guid if z["rel"] == GUIDES_UID_OFF else mac
        if bytes(b[z["abs"]:z["abs"] + z["size"]]) != \
                want.to_bytes(z["size"], "big"):
            guides_ok = False
    ok = not extra and not missing and erased_ok and guides_ok
    return {"ok": ok, "content": [
        {"section": z["section"], "rel": z["rel"],
         "old": a[z["abs"]:z["abs"] + z["size"]].hex(),
         "new": b[z["abs"]:z["abs"] + z["size"]].hex(),
         "abs": z["abs"], "size": z["size"]}
        for z in content], "extra": extra, "missing": missing,
        "erased_ok": erased_ok, "guides_ok": guides_ok, "zones": zones}


# ------------------------------------------------------------------ build

def build(base_buf, spec, guid, mac, build_id=BUILD_ID):
    """base bytes -> (image bytes, report).  All gates inside the
    report; BuildError on any refusal."""
    img = fw.Image(base_buf, "<base>")
    errs = fw.verify_image(img)
    if errs:
        raise BuildError(f"base image does not verify: {errs}")
    base_sig = fw.sig_status(img)[0]
    check_base(img)
    base_md5 = hashlib.md5(base_buf).hexdigest()

    # -- step 1: byte edits 0x12/0x11 (patch_sections: sec+entry CRC)
    edits_ = edits()
    old_vals = {t: img.section_data(img.find_entry("ITOC", t))
                for t in (0x12, 0x11)}
    out = fw.patch_sections(img, edits_)
    _self_verify(out, img.base, img.fmt, "byte edits")
    out, _ = _sign(out, img.base, img.fmt, "byte edits")

    # -- step 2: MAIN_CODE words (cable-gate pipeline)
    img2 = fw.Image(out, "<s2>", base=img.base, fmt=img.fmt)
    mc_map = mc_word_map(img2, spec)
    mc_report = []
    for p in spec["patches"]:
        off = int(p["offset"], 0)
        framed, clcrc_abs, wb = mc_map[off]
        line, in_line = divmod(off, 64)
        e03 = img2.find_entry("ITOC", int(spec["section"]))
        dc = img2.section_data(e03)
        code, _tail = cgp.deframe(dc, e03.clcrc)
        mc_report.append({
            "dc": off, "line": line, "in_line": in_line,
            "framed": framed, "abs": framed, "clcrc_abs": clcrc_abs,
            "old": code[off:off + len(wb)].hex(), "new": wb.hex(),
            "note": p.get("note", "")})
    out = patch_main_code(img2, spec)
    _self_verify(out, img.base, img.fmt, "MAIN_CODE")
    out, _ = _sign(out, img.base, img.fmt, "MAIN_CODE")

    # -- step 3: 0x30 build-ID (in-place or gated-safe relocation)
    img3 = fw.Image(out, "<s3>", base=img.base, fmt=img.fmt)
    old_text = extract_ini_text(img3)
    new_text = add_build_id(old_text, build_id)
    e30b = img3.find_entry("ITOC", 0x30)
    old30 = {"abs": img3.sec_abs(e30b), "size": e30b.size,
             "index": e30b.index}
    zlib_old = len(fw.extract_section(img3, 0x30))
    out = inject_build_id(img3, new_text)
    img3b = fw.Image(out, "<s3b>", base=img.base, fmt=img.fmt)
    e30o = img3b.find_entry("ITOC", 0x30)
    new30 = {"abs": img3b.sec_abs(e30o), "size": e30o.size,
             "index": e30o.index}
    relocated = old30["abs"] != new30["abs"]
    zlib_new = len(fw.extract_section(img3b, 0x30))
    _self_verify(out, img.base, img.fmt, "0x30 inject")
    out, _ = _sign(out, img.base, img.fmt, "0x30 inject")

    # -- step 4: guides (Rule 3: card identity, self-verify)
    img4 = fw.Image(out, "<s4>", base=img.base, fmt=img.fmt)
    out, guides_changes, guides_warning = embed_guids(img4, guid, mac)
    _self_verify(out, img.base, img.fmt, "guides")
    out, digest = _sign(out, img.base, img.fmt, "guides")

    # -- sign idempotency (Rule 5: fresh image re-signs to 0 diff)
    out2, _ = _sign(out, img.base, img.fmt, "idempotency")
    sign_idempotent = out2 == out

    # -- final gates
    vimg = fw.Image(out, "<out>", base=img.base, fmt=img.fmt)
    round_trip = extract_ini_text(vimg) == new_text
    guides_ok = True
    for t in GUIDES_SECTIONS:
        d = vimg.section_data(vimg.find_entry("ITOC", t))
        if d[GUIDES_UID_OFF:GUIDES_UID_OFF + 8] != guid.to_bytes(8, "big") \
                or d[GUIDES_MAC_OFF:GUIDES_MAC_OFF + 8] != mac.to_bytes(8, "big"):
            guides_ok = False
    gates = {
        "verify_image": fw.verify_image(vimg, deep=True) == [],
        "burn_order": fw.burn_order_check(vimg) == [],
        "sig_fresh": fw.sig_status(vimg)[0] == "fresh",
        "clcrc_lines": clcrc_all_ok(vimg),
        "round_trip": round_trip,
        "sign_idempotent": sign_idempotent,
        "guides": guides_ok,
    }
    can = canary(base_buf, out, spec, guid, mac)
    gates["canary"] = bool(can["ok"])

    report = {
        "variant": "hf2-max",
        "base": {"size": len(base_buf), "md5": base_md5,
                 "sig_status": base_sig},
        "build_id": build_id,
        "edits": [
            {"section": "0x%02x" % t, "offset": off,
             "old": "0x%02x" % old_vals[t][off], "new": "0x%02x" % data[0],
             "abs": (img.sec_abs(img.find_entry("ITOC", t)) + off),
             "note": (TUPLE_NOTES.get(off) or "VPI byte")
             if t == 0x12 else "VPI byte (EN->VPI, mstconfig switching)"}
            for t, off, data in edits_],
        "main_code": {"spec": spec.get("id"), "patches": mc_report},
        "eth_sites": list(ETH_SITES),
        "ini30": {
            "build_id_line": build_id, "relocated": relocated,
            "old_text_len": len(old_text), "new_text_len": len(new_text),
            "zlib_old": zlib_old, "zlib_new": zlib_new,
            "budget": old30["size"], "old": old30, "new": new30,
            "round_trip": round_trip},
        "guid": "%016x" % guid if guid is not None else None,
        "mac": "%012x" % mac if mac is not None else None,
        "guid_source": GUID_SOURCE,
        "guides": {"changes": guides_changes, "warning": guides_warning},
        "digest_0xa0": digest.hex(),
        "md5": hashlib.md5(out).hexdigest(),
        "size": len(out),
        "gates": gates,
        "canary": can,
        "discriminator_expectation": "Enabled(IB) 0x1f -> 0x3f "
                                     "(corroboration, not a gate-stop)",
        "verify_errors": fw.verify_image(vimg, deep=True),
        "burn_order_violations": [v.explanation for v in
                                  fw.burn_order_check(vimg)],
    }
    return out, report


# -------------------------------------------------------------------- CLI

def main(argv=None):
    desc = (__doc__ or "").splitlines()[0]
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--guid", required=True,
                        help="Base GUID, hex without colons "
                             "(task-01 journal)")
    parser.add_argument("--mac", required=True,
                        help="Base MAC, hex without colons")
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE,
                        help="stock base image (default: refs 1912-GCA)")
    parser.add_argument("--spec", type=Path, default=SPEC_PATH,
                        help="MAIN_CODE patch spec (default: task-02 "
                             "hf2-dispatcher spec)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="output image (default: build/hf2-max.bin)")
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON,
                        help="JSON report (default: build/hf2-max.json)")
    args = parser.parse_args(argv)
    try:
        guid = int(args.guid, 16)
        mac = int(args.mac, 16)
    except ValueError:
        print("error: --guid/--mac must be hex strings", file=sys.stderr)
        return 2
    if not 0 < guid <= 0xFFFFFFFFFFFFFFFF:
        print("error: --guid out of range (64-bit)", file=sys.stderr)
        return 2
    if not 0 < mac <= 0xFFFFFFFFFFFF:
        print("error: --mac out of range (48-bit)", file=sys.stderr)
        return 2
    if not args.base.is_file():
        print(f"error: base image not found: {args.base}", file=sys.stderr)
        return 2
    if not args.spec.is_file():
        print(f"error: spec not found: {args.spec}", file=sys.stderr)
        return 2
    try:
        spec = load_spec(args.spec)
        out, report = build(args.base.read_bytes(), spec, guid, mac)
    except BuildError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(out)
    report["output"] = str(args.out)
    for e in report["edits"]:
        print(f"edit: {e['section']}+0x{e['offset']:x} "
              f"{e['old']} -> {e['new']} (abs 0x{e['abs']:x})")
    for p in report["main_code"]["patches"]:
        print(f"main_code: dc 0x{p['dc']:x} {p['old']} -> {p['new']} "
              f"(line {p['line']}, abs 0x{p['abs']:x})")
    i30 = report["ini30"]
    print(f"0x30: {'relocated' if i30['relocated'] else 'in-place'} "
          f"(zlib {i30['zlib_old']} -> {i30['zlib_new']}, budget "
          f"{i30['budget']}); build-id round-trip "
          f"{i30['round_trip']}")
    print(f"guides: guid {report['guid']} mac {report['mac']} "
          f"(source: task-01 journal)")
    print(f"digest 0xA0: {report['digest_0xa0']}")
    print(f"gates: {report['gates']}")
    can = report["canary"]
    print(f"canary: ok={can['ok']} content={len(can['content'])} zones "
          f"extra={len(can['extra'])} missing={len(can['missing'])} "
          f"erased_ok={can['erased_ok']} guides_ok={can['guides_ok']}")
    print(f"{args.out}: md5 {report['md5']} ({len(out)} bytes)")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    return 0 if all(report["gates"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
