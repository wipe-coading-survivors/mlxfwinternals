#!/usr/bin/env python3
"""1900 vs 1912 FS3 diff + IB-mask sweep (plan 2026-10-07-cx4lx-56-100g,
task 4.6).

Decisive question: is the IB-enabled-mask difference
(14.32.1900 Enabled (IB) = 0x1f vs 14.32.1912 = 0x07, measured live;
PSID not a factor per T4.5) a CONFIG difference (patchable config
byte) or a MAIN_CODE (iRISC) difference between the two FW versions.

Inputs (defaults):
  --img1900  refs/fw/cx-4/dumps/lx_c1_final_rollback-20260919.bin
             (16 MiB flash dump; slot A @0x0 = the live 14.32.1900
             image, base 0; slot B erased; the full dump is loaded so
             the dev sections 0xe0-0xe6 @0xfa0000+ are present too —
             for everything below 8 MiB the dump == the 8 MiB slot A
             slice from step 2)
  --img1912g refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-GCA_*.bin
  --img1912a refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-ACA_*.bin

Product caveat: 1900 = MCX4121A (2p SFP28, PSID MT_2420110034),
GCA = MCX4131A (1p QSFP28, PSID MT_2430110032), ACA = MCX4121A (2p
SFP28, PSID MT_2420110034 = same product AND same PSID as 1900).
The triple (1900, GCA, ACA) separates FW-version diffs (1912-GCA ==
1912-ACA) from product diffs (GCA != ACA).

Analysis:
  A. section inventory of all three images (type/size/addr/clcrc);
  B. config-section byte diff (0x08/0x09/0x10/0x11/0x12 + service
     sections), every differing byte as a triple with class:
       VER   = 1912-GCA == 1912-ACA != 1900  (FW-version diff)
       PGCA  = 1900 == 1912-GCA != 1912-ACA  (product diff)
       PACA  = 1900 == 1912-ACA != 1912-GCA  (product diff)
       MIXED = all three differ
     flags: IB1F07 (1900=0x1f & both 1912=0x07), FDRB (1900 carries
     FDR10/FDR/EDR bits 0x08/0x10/0x20 that 1912 lacks), REV (and
     vice versa), plus anchor windows VPI 0x11+0x2af +/-0x40 and
     lcl 0x12+0x30b +/-0x40; 0x10 fields annotated; 0x30 handled as
     zlib-ini text diff;
  C. MAIN_CODE (0x03) diff: raw md5, de-clcrc view (verified line
     layout 66B data + 2B crc per 68B line, clcrc_lines_errors == 0),
     data-view md5, common prefix/suffix, 66B-line diff clusters,
     longest common contiguous block (k-mer binary search), ASCII
     string inventory comparison (speed/PDDR-relevant);
  D. IB-mask sweep (step 5): ALL ITOC sections, no size limit —
     patterns P1 {1900:0x1f, 1912GCA:0x07, 1912ACA:0x07} and
     P2 {1900:0x0f|0x1f, 1912GCA:0x07, 1912ACA:0x07}; same-size
     sections compared byte-for-byte; different-size sections
     compared up to min length and reported as NOISE (layout shift,
     task 3: no common frame between the builds).

Stdlib only + mlxfwutil.Image (repo root) for ITOC parsing. Offline: no
hardware, no ssh.

Usage: python3 scripts/probes/diff_1900_1912.py [--json OUT]
Exit: 0 ok (verdict printed), 2 missing input / section.
"""
import argparse
import hashlib
import json
import re
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from mlxfwutil import Image, clcrc_lines_errors  # noqa: E402

DEFAULT_1900 = "refs/fw/cx-4/dumps/lx_c1_final_rollback-20260919.bin"
DEFAULT_1912G = ("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4131A-"
                 "GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")
DEFAULT_1912A = ("refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1912-MCX4121A-"
                 "ACA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin")

CONFIG_SECTIONS = [0x08, 0x09, 0x10, 0x11, 0x12, 0x30]
SERVICE_SECTIONS = [0x0b, 0x20, 0x32, 0xe9]
FDR_BITS = 0x08 | 0x10 | 0x20  # FDR10 / FDR / EDR

SECT_NAMES = {
    0x02: "PCI_CODE", 0x03: "MAIN_CODE", 0x04: "PCIE_LINK_CODE",
    0x05: "IRON_PREP_CODE", 0x06: "POST_IRON_BOOT",
    0x07: "UPGRADE_CODE", 0x08: "HW_BOOT_CFG", 0x09: "HW_MAIN_CFG",
    0x0a: "PHY_UC_CODE", 0x0b: "PHY_UC_CONSTS",
    0x0c: "PCIE_PHY_UC_CODE", 0x10: "IMAGE_INFO",
    0x11: "FW_BOOT_CFG", 0x12: "FW_MAIN_CFG", 0x18: "ROM_CODE",
    0x20: "RESET_INFO", 0x30: "DBG_FW_INI", 0x32: "DBG_FW_PARAMS",
    0xa0: "SIG_256", 0xa1: "PUB_KEYS_2048", 0xa2: "FORBIDDEN_VER",
    0xa3: "SIG_512", 0xa4: "PUB_KEYS_4096", 0xe0: "MFG_INFO",
    0xe1: "DEV_INFO", 0xe3: "VPD_R0", 0xe4: "NV_DATA2",
    0xe5: "FW_NV_LOG", 0xe6: "NV_DATA0", 0xe9: "CRDUMP_MASK",
    0xeb: "PROG_HW_FW1",
}

# (section, rel offset, note) — known anchors / forbidden bytes
ANNOT = {
    (0x10, 0x1C): "pci_device_id", (0x10, 0x24): "psid",
    (0x10, 0x1C0): "prod_ver", (0x10, 0x1D0): "description",
    (0x10, 0x340): "name", (0x10, 0x380): "prs_name",
    (0x11, 0x2AF): "VPI port0 (0x0a=EN, 0x07=IB)",
    (0x11, 0x2B3): "VPI port1 (0x0a=EN, 0x07=IB)",
    (0x12, 0x158): "0x158 (0x30=EN; DO NOT TOUCH — T6)",
    (0x12, 0x283): "host-mgmt p0 (not IB gate, live 10-07)",
    (0x12, 0x2C5): "host-mgmt p1 (not IB gate, live 10-07)",
    (0x12, 0x30B): "lcl[0] ETH speed mask",
    (0x12, 0x317): "lcl[1] ETH speed mask",
}
WINDOWS = [
    (0x11, 0x2AF, "VPI-p0 +/-0x40"),
    (0x12, 0x30B, "lcl[0] +/-0x40"),
]


def load(path: str):
    buf = Path(path).read_bytes()
    img = Image(buf, path)
    secs = {}
    meta = {}
    for e in img.entries("ITOC"):
        secs[e.type] = img.section_data(e)
        meta[e.type] = {"size": e.size, "addr": e.addr,
                        "clcrc": e.clcrc, "rel": e.rel, "dev": e.dev}
    return img, secs, meta


def declcrc(raw: bytes) -> bytes:
    if len(raw) % 68:
        raise ValueError(f"de-clcrc: size {len(raw):#x} not multiple of 68")
    return b"".join(raw[i:i + 66] for i in range(0, len(raw), 68))


def md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def prefix_suffix(a: bytes, b: bytes):
    n = min(len(a), len(b))
    p = 0
    while p < n and a[p] == b[p]:
        p += 1
    s = 0
    while s < n - p and a[len(a) - 1 - s] == b[len(b) - 1 - s]:
        s += 1
    return p, s


def longest_common_block(a: bytes, b: bytes) -> int:
    """Longest common contiguous block (estimate) via fingerprinted
    k-gram binary search. Fingerprints = first 32 + last 32 bytes
    (k >= 64), subsampled to <= 200k probes; a fingerprint hit is
    verified by full byte compare. Monotonicity holds up to
    subsampling sparseness, so the result is order-of-magnitude."""
    n = min(len(a), len(b))
    if n < 16:
        return n

    def fp(x: bytes, i: int, k: int) -> bytes:
        if k >= 64:
            return x[i:i + 32] + x[i + k - 32:i + k]
        return x[i:i + k]

    def exists(k: int) -> bool:
        step = max(1, (n - k + 1) // 200_000)
        seen = {}
        for i in range(0, n - k + 1, step):
            seen.setdefault(fp(a, i, k), i)
        for j in range(0, n - k + 1, step):
            i = seen.get(fp(b, j, k))
            if i is not None and a[i:i + k] == b[j:j + k]:
                return True
        return False

    if not exists(16):
        return 0
    lo, hi = 16, n
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if exists(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


STR_RE = re.compile(rb"[\x20-\x7e]{6,}")


def strings(b: bytes):
    return {m.group(0).decode() for m in STR_RE.finditer(b)}


def classify(v0: int, vg: int, va: int) -> str:
    if vg == va and v0 != vg:
        return "VER"
    if v0 == vg and va != vg:
        return "PGCA"
    if v0 == va and vg != va:
        return "PACA"
    return "MIXED"


def flags(v0: int, vg: int, va: int, sect: int, off: int) -> list:
    f = []
    if v0 == 0x1F and vg == 0x07 and va == 0x07:
        f.append("IB1F07")
    if v0 in (0x0F, 0x1F) and vg == 0x07 and va == 0x07:
        f.append("P2")
    extra = (v0 & FDR_BITS) & ~vg
    if extra:
        f.append(f"FDRB+{extra:02x}")
    missing = (vg & FDR_BITS) & ~v0
    if missing:
        f.append(f"REV-{missing:02x}")
    note = ANNOT.get((sect, off))
    if note:
        f.append(f"ANCHOR:{note}")
    for s, c, wname in WINDOWS:
        if sect == s and c - 0x40 <= off <= c + 0x40:
            f.append(f"WIN:{wname}")
    return f


def config_diff(secs, meta, out):
    rows = []
    for sect in CONFIG_SECTIONS + SERVICE_SECTIONS:
        if sect not in secs["1900"] or sect not in secs["1912g"]:
            continue
        d0, dg, da = (secs[k].get(sect, b"") for k in
                      ("1900", "1912g", "1912a"))
        if sect == 0x30:
            ini0 = zlib.decompress(d0) if d0[:2] == b"\x78\xda" else d0
            inig = zlib.decompress(dg) if dg[:2] == b"\x78\xda" else dg
            inia = zlib.decompress(da) if da[:2] == b"\x78\xda" else da
            l0, lg, la = (x.splitlines(keepends=True)
                          for x in (ini0, inig, inia))
            n = max(len(l0), len(lg), len(la))
            for i in range(n):
                a0 = l0[i] if i < len(l0) else b"<absent>"
                ag = lg[i] if i < len(lg) else b"<absent>"
                aa = la[i] if i < len(la) else b"<absent>"
                if not (a0 == ag == aa):
                    rows.append({
                        "section": f"0x{sect:02x}", "ini_line": i + 1,
                        "1900": a0.decode(errors="replace").rstrip("\n"),
                        "1912gca": ag.decode(errors="replace").rstrip("\n"),
                        "1912aca": aa.decode(errors="replace").rstrip("\n"),
                    })
            out["ini_30"] = {
                "size_1900": hex(len(ini0)), "size_1912gca": hex(len(inig)),
                "size_1912aca": hex(len(inia)),
            }
            continue
        n = min(len(d0), len(dg), len(da))
        if len(d0) != len(dg) or len(d0) != len(da):
            out.setdefault("size_mismatch", []).append(
                {"section": f"0x{sect:02x}",
                 "1900": hex(len(d0)), "1912gca": hex(len(dg)),
                 "1912aca": hex(len(da))})
        for i in range(n):
            v0, vg, va = d0[i], dg[i], da[i]
            if v0 == vg == va:
                continue
            rows.append({
                "section": f"0x{sect:02x}", "offset": f"0x{i:03x}",
                "1900": f"0x{v0:02x}", "1912gca": f"0x{vg:02x}",
                "1912aca": f"0x{va:02x}", "class": classify(v0, vg, va),
                "flags": flags(v0, vg, va, sect, i),
            })
    out["config_rows"] = rows
    return rows


def main_code_diff(secs, out):
    r0, rg = secs["1900"].get(0x03, b""), secs["1912g"].get(0x03, b"")
    ra = secs["1912a"].get(0x03, b"")
    out["maincode"] = {
        "raw_md5_1900": md5(r0), "raw_md5_1912gca": md5(rg),
        "raw_md5_1912aca": md5(ra),
        "raw_equal_1912ga": rg == ra,
        "raw_size_1900": hex(len(r0)), "raw_size_1912": hex(len(rg)),
    }
    d0, dg, da = declcrc(r0), declcrc(rg), declcrc(ra)
    out["maincode"].update({
        "data_md5_1900": md5(d0), "data_md5_1912gca": md5(dg),
        "data_md5_1912aca": md5(da),
        "data_equal_1912ga": dg == da,
        "data_size_1900": hex(len(d0)), "data_size_1912": hex(len(dg)),
        "line_errors_1900": len(clcrc_lines_errors(r0)),
        "line_errors_1912": len(clcrc_lines_errors(rg)),
    })
    p, s = prefix_suffix(d0, dg)
    p_r, s_r = prefix_suffix(r0, rg)
    out["maincode"].update({
        "common_prefix_data": hex(p), "common_suffix_data": hex(s),
        "common_prefix_raw": hex(p_r), "common_suffix_raw": hex(s_r),
    })
    # 66-byte line diff clusters (1900 coordinates)
    lines = len(d0) // 66
    diff_lines = [i for i in range(lines)
                  if d0[i * 66:(i + 1) * 66]
                  != dg[i * 66:(i + 1) * 66]]
    clusters = []
    if diff_lines:
        st = pr = diff_lines[0]
        for x in diff_lines[1:]:
            if x == pr + 1:
                pr = x
            else:
                clusters.append((st, pr - st + 1))
                st = pr = x
        clusters.append((st, pr - st + 1))
    out["maincode"].update({
        "lines_1900": lines, "lines_1912": len(dg) // 66,
        "diff_lines": len(diff_lines),
        "identical_lines_pct": round(100.0 * (lines - len(diff_lines)) / lines, 2),
        "clusters": [[hex(a * 66), hex(b * 66)] for a, b in clusters],
        "n_clusters": len(clusters),
        "largest_cluster_lines": max((b for _, b in clusters), default=0),
    })
    out["maincode"]["longest_common_block_data"] = hex(longest_common_block(d0, dg))
    # string inventory
    s0, sg, sa = strings(d0), strings(dg), strings(da)
    rel = ("speed", "FDR", "EDR", "PDDR", "link", "port_info", "cable")
    rel0 = sorted(x for x in s0 - sg if any(k in x for k in rel))
    relg = sorted(x for x in sg - s0 if any(k in x for k in rel))
    out["maincode"]["strings"] = {
        "n_1900": len(s0), "n_1912": len(sg),
        "common": len(s0 & sg),
        "only_1900": len(s0 - sg), "only_1912": len(sg - s0),
        "rel_only_1900": rel0, "rel_only_1912": relg,
    }
    for label, b, base in (("1900", d0, 0), ("1912", dg, 0)):
        for needle, name in (
                (b"Cable speed not enabled", "Cable speed not enabled"),
                (b"speed_enabled.ib", "speed_enabled.ib"),
                (b"link_speed_ext_ena", "link_speed_ext_ena"),
                (b"ib_speed_supported", "ib_speed_supported"),
        ):
            off = b.find(needle)
            out["maincode"].setdefault("anchors", {})[f"{label}:{name}"] = (
                hex(off) if off >= 0 else None)
    return out


def sweep(secs, meta, out):
    hits = []
    swept = []
    t0 = set(meta["1900"]) & set(meta["1912g"]) & set(meta["1912a"])
    for t in sorted(t0):
        d0, dg, da = (secs[k][t] for k in ("1900", "1912g", "1912a"))
        same = meta["1900"][t]["size"] == meta["1912g"][t]["size"] == \
            meta["1912a"][t]["size"]
        n = min(len(d0), len(dg), len(da))
        p1 = p2 = 0
        for i in range(n):
            v0, vg, va = d0[i], dg[i], da[i]
            if vg != 0x07 or va != 0x07:
                continue
            if v0 == 0x1F:
                p1 += 1
                if not same:
                    continue
                hits.append({"section": f"0x{t:02x}",
                             "name": SECT_NAMES.get(t, ""),
                             "offset": f"0x{i:05x}",
                             "1900": "0x1f", "1912gca": "0x07",
                             "1912aca": "0x07", "pattern": "P1",
                             "same_size": same})
            elif v0 == 0x0F:
                p2 += 1
                if not same:
                    continue
                hits.append({"section": f"0x{t:02x}",
                             "name": SECT_NAMES.get(t, ""),
                             "offset": f"0x{i:05x}",
                             "1900": "0x0f", "1912gca": "0x07",
                             "1912aca": "0x07", "pattern": "P2",
                             "same_size": same})
        swept.append({"section": f"0x{t:02x}",
                      "name": SECT_NAMES.get(t, ""),
                      "bytes": hex(n), "same_size": same,
                      "hits_p1": p1, "hits_p2": p2})
    out["sweep"] = {"per_section": swept, "hits_same_size": hits}
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--img1900", default=str(ROOT / DEFAULT_1900))
    ap.add_argument("--img1912g", default=str(ROOT / DEFAULT_1912G))
    ap.add_argument("--img1912a", default=str(ROOT / DEFAULT_1912A))
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    for p in (args.img1900, args.img1912g, args.img1912a):
        if not Path(p).is_file():
            print(f"missing input: {p}", file=sys.stderr)
            return 2
    out = {}
    secs = {}
    meta = {}
    for k, p in (("1900", args.img1900), ("1912g", args.img1912g),
                 ("1912a", args.img1912a)):
        _, s, m = load(p)
        secs[k], meta[k] = s, m
    out["sections"] = {
        k: {f"0x{t:02x}": {**v, "name": SECT_NAMES.get(t, "")}
            for t, v in m.items()}
        for k, m in meta.items()
    }
    rows = config_diff(secs, meta, out)
    main_code_diff(secs, out)
    sweep(secs, meta, out)
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=1))
    # --- text report ---
    print("== section inventory (type: size @ addr, clcrc)")
    for k in ("1900", "1912g", "1912a"):
        print(f"-- {k}")
        for t in sorted(meta[k]):
            m = meta[k][t]
            print(f"   0x{t:02x} {SECT_NAMES.get(t, '?'):16s} "
                  f"size={m['size']:08x} addr={m['addr']:08x} "
                  f"cl={m['clcrc']} rel={m['rel']} dev={m['dev']}")
    print("\n== config diff (1900 vs 1912-GCA / 1912-ACA), "
          "all differing bytes")
    n_by_class = {}
    for r in rows:
        if "offset" in r:
            n_by_class[r["class"]] = n_by_class.get(r["class"], 0) + 1
    print(f"total diff bytes: {sum(n_by_class.values())}, "
          f"by class: {n_by_class}")
    for r in rows:
        if "ini_line" in r:
            print(f"  0x30 ini:{r['ini_line']:4d}  "
                  f"1900={r['1900']!r}  gca={r['1912gca']!r}  "
                  f"aca={r['1912aca']!r}")
        else:
            fl = f"  [{','.join(r['flags'])}]" if r["flags"] else ""
            print(f"  {r['section']}+{r['offset']}  "
                  f"1900={r['1900']} gca={r['1912gca']} aca={r['1912aca']}  "
                  f"{r['class']}{fl}")
    mc = out["maincode"]
    print("\n== MAIN_CODE (0x03)")
    for k in ("raw_md5_1900", "raw_md5_1912gca", "raw_md5_1912aca",
              "raw_equal_1912ga", "raw_size_1900", "raw_size_1912",
              "data_md5_1900", "data_md5_1912gca", "data_md5_1912aca",
              "data_equal_1912ga", "data_size_1900", "data_size_1912",
              "line_errors_1900", "line_errors_1912",
              "common_prefix_data", "common_suffix_data",
              "common_prefix_raw", "common_suffix_raw",
              "lines_1900", "lines_1912", "diff_lines",
              "identical_lines_pct", "n_clusters",
              "largest_cluster_lines", "longest_common_block_data"):
        print(f"  {k:24s} {mc[k]}")
    print(f"  clusters (start..len, 1900 data-view offsets): "
          f"{mc['clusters']}")
    st = mc["strings"]
    print(f"  strings: 1900={st['n_1900']} 1912={st['n_1912']} "
          f"common={st['common']} only1900={st['only_1900']} "
          f"only1912={st['only_1912']}")
    if st["rel_only_1900"]:
        print(f"  rel-only-1900: {st['rel_only_1900']}")
    if st["rel_only_1912"]:
        print(f"  rel-only-1912: {st['rel_only_1912']}")
    for k, v in mc.get("anchors", {}).items():
        print(f"  anchor {k}: {v}")
    print("\n== IB-mask sweep (all sections, no size limit)")
    for s in out["sweep"]["per_section"]:
        print(f"  {s['section']} {s['name']:16s} bytes={s['bytes']:9s} "
              f"same_size={s['same_size']}  P1={s['hits_p1']} P2={s['hits_p2']}")
    print(f"same-size hits: {len(out['sweep']['hits_same_size'])}")
    for h in out["sweep"]["hits_same_size"]:
        print(f"  {h['section']} {h['name']}+{h['offset']} "
              f"1900={h['1900']} 1912={h['1912gca']} [{h['pattern']}]")
    print("\n== anchors (0x11/0x12, direct read)")
    for sect, off, name in ((0x11, 0x2AF, "VPI p0"),
                            (0x11, 0x2B3, "VPI p1"),
                            (0x12, 0x158, "0x158"),
                            (0x12, 0x30B, "lcl[0]"),
                            (0x12, 0x317, "lcl[1]")):
        vals = []
        for k in ("1900", "1912g", "1912a"):
            d = secs[k].get(sect, b"")
            vals.append(f"0x{d[off]:02x}" if off < len(d) else "n/a")
        print(f"  0x{sect:02x}+0x{off:03x} {name:8s} 1900={vals[0]} "
              f"gca={vals[1]} aca={vals[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
