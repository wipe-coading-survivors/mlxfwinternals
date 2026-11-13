#!/usr/bin/env python3
"""A16 (PG171) baseline differential over pinned corpus images (arc B, T1).

Per-section byte diff (raw + de-clcrc when cl=1) of the A16 PCIe-switch
image against the NIC baselines of the same build line, plus the config
layer (0x08/0x09/0x11/0x12 via the config_sku_diff parser), DBG_FW_INI
(0x30, zlib) unified text diff and IMAGE_INFO identity diff.

Usage:
  python3 scripts/probes/serdes-prov/a16_diff.py \
      --a16 cx6/20_43_8002/PG171-NVD \
      --baseline cx6/20_43_8002/MCX654105A-HCA \
      --baseline cx6/20_43_1014/MCX654105A-HCA \
      --baseline cx6/20_43_8016/MCX654105A-HCA \
      --out-dir build/serdes-prov/arc-b

Artifacts: a16-sections.json (per-section verdicts, md5 per section,
config spans, image_info), a16-ini.{a,b,c,...}.diff.txt (unified ini
diff per baseline, in --baseline order; first two letters fixed by
plan/report).

Offline/read-only: no burn, no hardware.
"""
import argparse
import difflib
import hashlib
import json
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
PROBE_DIR = Path(__file__).resolve().parent
if str(PROBE_DIR) not in sys.path:
    sys.path.insert(0, str(PROBE_DIR))

from config_sku_diff import (  # noqa: E402
    AmbiguousSectionError,
    SectionDecodeError,
    diff_sections,
    section_payload,
)
from mlxfwutil import SECT_NAMES, Image, image_info_fields  # noqa: E402
from scripts.corpus.manifest import (  # noqa: E402
    CorpusManifestError,
    ImageRef,
    T1,
    T2,
    T3,
    verify_md5,
)

CONFIG_TYPES = (0x08, 0x09, 0x11, 0x12)
DEFAULT_A16 = "cx6/20_43_8002/PG171-NVD"
DEFAULT_BASELINES = (
    "cx6/20_43_8002/MCX654105A-HCA",
    "cx6/20_43_1014/MCX654105A-HCA",
    "cx6/20_43_8016/MCX654105A-HCA",
)


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def section_fingerprints(img) -> dict:
    fps = {}
    for e in img.entries("ITOC"):
        rec = {
            "size": e.size,
            "cl": bool(e.clcrc),
            "zipped": bool(e.zipped),
            "status": "OK",
            "status_reason": "",
            "md5_raw": _md5(img.section_data(e)),
            "md5_dc": None,
        }
        try:
            rec["md5_dc"] = _md5(section_payload(img, e.type))
        except (AmbiguousSectionError, SectionDecodeError, KeyError) as exc:
            rec["status"] = "ERROR"
            rec["status_reason"] = str(exc)
        fps[e.type] = rec
    return fps


def compare_fingerprints(fa: dict, fb: dict) -> dict:
    out = {}
    for typ in sorted(set(fa) | set(fb)):
        if typ not in fa or typ not in fb:
            out[typ] = {
                "verdict": "absent",
                "only_in": "a16" if typ in fa else "baseline",
            }
            continue
        a, b = fa[typ], fb[typ]
        rec = {
            "sizes": (a["size"], b["size"]),
            "raw_identical": a["md5_raw"] == b["md5_raw"],
        }
        if a["status"] != "OK" or b["status"] != "OK":
            rec["verdict"] = "error"
        elif a["md5_dc"] == b["md5_dc"]:
            rec["verdict"] = "identical"
        else:
            rec["verdict"] = "different"
        out[typ] = rec
    return out


def ini_text(img) -> str:
    data = section_payload(img, 0x30)
    try:
        raw = zlib.decompress(data)
    except zlib.error as exc:
        raise ValueError(
            f"{img.path}: 0x30 payload is not a zlib stream: {exc}"
        ) from exc
    return raw.decode("latin-1")


def unified_diff_text(a_text: str, b_text: str, fromfile: str,
                      tofile: str) -> str:
    return "".join(difflib.unified_diff(
        a_text.splitlines(keepends=True), b_text.splitlines(keepends=True),
        fromfile=fromfile, tofile=tofile))


def diff_line_counts(diff_text: str) -> dict:
    lines = diff_text.splitlines()
    return {
        "minus": sum(1 for l in lines
                     if l.startswith("-") and not l.startswith("---")),
        "plus": sum(1 for l in lines
                    if l.startswith("+") and not l.startswith("+++")),
    }


def image_info(img) -> dict:
    data = section_payload(img, 0x10)
    info = image_info_fields(data)
    info["device_id"] = "0x%04x" % int.from_bytes(data[0x1c:0x1e], "big")
    return info


def config_diffs(img_a, img_b, types=CONFIG_TYPES) -> dict:
    out = {}
    for typ in types:
        key = "%02x" % typ
        try:
            pa = section_payload(img_a, typ)
            pb = section_payload(img_b, typ)
        except KeyError:
            out[key] = {"absent": True}
            continue
        diffs = diff_sections({"a16": pa, "base": pb})
        for d in diffs:
            d["hex"] = {
                "a16": pa[d["offset"]:d["offset"] + d["span"]].hex(),
                "base": pb[d["offset"]:d["offset"] + d["span"]].hex(),
            }
        out[key] = diffs
    return out


def collect_images(refs_root: Path, labels: list) -> list:
    by_label = {}
    for ref in T1 + T2 + T3:
        by_label.setdefault(
            "/".join((ref.family, ref.ver, ref.sku)), ref)
    resolved = []
    for label in labels:
        if label not in by_label:
            raise CorpusManifestError(f"unknown image label: {label}")
        ref = by_label[label]
        full = ImageRef(path=refs_root / ref.path, md5=ref.md5,
                        family=ref.family, ver=ref.ver, sku=ref.sku,
                        tier=ref.tier, path_rel=ref.path)
        verify_md5(full)
        resolved.append(full)
    return resolved


def load_image(ref: ImageRef) -> Image:
    img = Image(ref.path.read_bytes(), path=str(ref.path))
    if not img.header_crc_ok("ITOC"):
        raise CorpusManifestError(f"ITOC header CRC mismatch: {ref.path}")
    bad = [e for e in img.entries("ITOC") if not img.entry_crc_ok(e)]
    if bad:
        raise CorpusManifestError(
            f"ITOC entry CRC mismatch: {ref.path}: "
            + ", ".join("0x%02x" % e.type for e in bad))
    return img


def build_report(a16_label, base_labels, images: dict, out_dir: Path) -> dict:
    a16_img = images[a16_label]
    fps = {label: section_fingerprints(img)
           for label, img in images.items()}
    sections = []
    for typ in sorted(set().union(*[set(f) for f in fps.values()])):
        rec = {
            "type": "%02x" % typ,
            "name": SECT_NAMES.get(typ, "UNKNOWN"),
            "a16": fps[a16_label].get(typ),
            "baselines": {},
        }
        for label in base_labels:
            cmp_rec = compare_fingerprints(
                fps[a16_label], fps[label]).get(typ, {})
            cmp_rec["fingerprint"] = fps[label].get(typ)
            rec["baselines"][label] = cmp_rec
        sections.append(rec)

    config = {}
    for label in base_labels:
        config[label] = config_diffs(a16_img, images[label])

    infos = {label: image_info(img) for label, img in images.items()}
    info_diff = {}
    for label in base_labels:
        info_diff[label] = sorted(
            k for k in infos[a16_label]
            if infos[a16_label][k] != infos[label][k])

    ini_texts = {label: ini_text(img) for label, img in images.items()}
    ini_stats = {}
    for i, label in enumerate(base_labels):
        diff_text = unified_diff_text(
            ini_texts[a16_label], ini_texts[label],
            a16_label + " (ini)", label + " (ini)")
        suffix = "ab"[i] if i < 2 else chr(ord("c") + i - 2)
        (out_dir / ("a16-ini.%s.diff.txt" % suffix)).write_text(diff_text)
        stats = diff_line_counts(diff_text)
        stats["a16_lines"] = len(ini_texts[a16_label].splitlines())
        stats["base_lines"] = len(ini_texts[label].splitlines())
        ini_stats[label] = stats

    return {
        "schema": 1,
        "a16": a16_label,
        "baselines": base_labels,
        "sections": sections,
        "config_diff": config,
        "image_info": infos,
        "image_info_diff_fields": info_diff,
        "ini_diff": ini_stats,
    }


def print_table(report: dict) -> None:
    a16_label = report["a16"]
    print(f"A16: {a16_label} vs baselines")
    for label in report["baselines"]:
        print(f"\n== baseline {label}")
        for sec in report["sections"]:
            b = sec["baselines"][label]
            verdict = b["verdict"]
            extra = ""
            if verdict == "absent":
                extra = f" only_in={b['only_in']}"
            elif verdict == "different":
                extra = f" sizes={b['sizes']}"
            elif verdict == "identical" and not b["raw_identical"]:
                extra = " framing-only"
            print(f"  0x{sec['type']} {sec['name']:<16} {verdict}{extra}")
        n_cfg = {k: len(v) if isinstance(v, list) else v
                 for k, v in report["config_diff"][label].items()}
        print(f"  config spans: {n_cfg}")
        print(f"  ini: {report['ini_diff'][label]}")
        print(f"  image_info diff fields: "
              f"{report['image_info_diff_fields'][label]}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="A16 (PG171) baseline differential (arc B, T1)")
    ap.add_argument("--a16", default=DEFAULT_A16, metavar="FAM/VER/SKU")
    ap.add_argument("--baseline", action="append", default=None,
                    metavar="FAM/VER/SKU",
                    help="baseline label, repeatable "
                         "(default: HCA 8002/1014/8016)")
    ap.add_argument("--refs", type=Path, default=REPO,
                    help="root containing refs/ (default repo root)")
    ap.add_argument("--out-dir", type=Path,
                    default=REPO / "build" / "serdes-prov" / "arc-b",
                    help="artifact directory")
    args = ap.parse_args(argv)

    base_labels = list(args.baseline or DEFAULT_BASELINES)
    if args.a16 in base_labels:
        print("a16 label must differ from baselines", file=sys.stderr)
        return 2
    try:
        refs = collect_images(args.refs, [args.a16] + base_labels)
    except CorpusManifestError as exc:
        print(f"a16_diff: refused: {exc}", file=sys.stderr)
        return 2
    try:
        images = {ref_label: load_image(ref) for ref_label, ref
                  in zip([args.a16] + base_labels, refs)}
    except CorpusManifestError as exc:
        print(f"a16_diff: refused: {exc}", file=sys.stderr)
        return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)
    try:
        report = build_report(args.a16, base_labels, images, args.out_dir)
    except (ValueError, KeyError) as exc:
        print(f"a16_diff: refused: {exc}", file=sys.stderr)
        return 2
    out_path = args.out_dir / "a16-sections.json"
    out_path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print_table(report)
    print(f"\n-> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
