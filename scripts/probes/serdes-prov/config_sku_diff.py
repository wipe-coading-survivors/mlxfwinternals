#!/usr/bin/env python3
"""Config-layer SKU differential over pinned corpus images (arc C, T1).

Diff of config sections (0x08 HW_BOOT_CFG, 0x09 HW_MAIN_CFG, 0x11
FW_BOOT_CFG, 0x12 FW_MAIN_CFG) between SKU variants of the md5-pinned
arc-A corpus images. Extraction mirrors scripts/corpus/extract.py
(mlxfwutil.Image ITOC walk + clcrc_unwrap when cl=1), with one new
gate: two ITOC entries of the same type in one image is a hard fail
(stock silently takes the first).

Usage:
  python3 scripts/probes/serdes-prov/config_sku_diff.py \
      --sku cx5/16_35_8008/MCX512A-ACA --sku cx5/16_35_8008/MCX512A-ADA \
      --sec 0x09 --out build/serdes-prov/config-diff-09-<pair>.json

Offline/read-only: no burn, no hardware.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from mlxfwutil import Image, clcrc_unwrap  # noqa: E402

DEFAULT_MANIFEST = REPO / "scripts" / "corpus" / "corpus_manifest.json"


class AmbiguousSectionError(Exception):
    pass


class SectionDecodeError(Exception):
    pass


def find_unique_entry(img, typ: int):
    matches = [e for e in img.entries("ITOC") if e.type == typ]
    if not matches:
        raise KeyError(f"{img.path}: section 0x{typ:02x} not in ITOC")
    if len(matches) > 1:
        raise AmbiguousSectionError(
            f"{img.path}: ambiguous section 0x{typ:02x}: "
            f"{len(matches)} ITOC entries")
    return matches[0]


def section_payload(img, typ: int) -> bytes:
    e = find_unique_entry(img, typ)
    if e.zipped:
        raise SectionDecodeError(
            f"{img.path}: section 0x{typ:02x} zipped, no decoder")
    raw = img.section_data(e)
    if e.clcrc:
        try:
            payload, _tail = clcrc_unwrap(raw)
        except ValueError as exc:
            raise SectionDecodeError(
                f"{img.path}: section 0x{typ:02x} cl=1 decode failed: {exc}"
            ) from exc
        return payload
    return raw


def diff_sections(payloads: dict) -> list:
    labels = sorted(payloads)
    if not labels:
        return []
    n = min(len(payloads[l]) for l in labels)
    diffs = []
    off = 0
    while off < n:
        vals = [payloads[l][off] for l in labels]
        if len(set(vals)) == 1:
            off += 1
            continue
        span = 1
        while off + span < n:
            nxt = [payloads[l][off + span] for l in labels]
            if len(set(nxt)) == 1:
                break
            span += 1
        diffs.append({
            "offset": off,
            "span": span,
            "values": {l: payloads[l][off] for l in labels},
        })
        off += span
    return diffs


def resolve_image_path(recorded: str, repo: Path) -> Path:
    p = Path(recorded)
    if p.is_absolute():
        parts = p.parts
        if "refs" in parts:
            local = repo.joinpath(*parts[parts.index("refs"):])
            if local.is_file():
                return local
        if p.is_file():
            return p
        raise FileNotFoundError(f"image not found: {recorded}")
    local = repo / p
    if local.is_file():
        return local
    raise FileNotFoundError(f"image not found: {recorded}")


def crosscheck_md5(payload: bytes, expected):
    if expected is None:
        return "absent"
    digest = hashlib.md5(payload).hexdigest()
    if digest != expected:
        raise ValueError(
            f"payload md5 mismatch: extracted {digest}, manifest {expected}")
    return "ok"


def load_manifest_images(manifest_path: Path, repo: Path) -> dict:
    data = json.loads(manifest_path.read_text())
    images = {}
    for entry in data["images"]:
        label = "/".join((entry["family"], entry["ver"], entry["sku"]))
        rec = (entry, resolve_image_path(entry["path"], repo))
        if label in images and images[label] != rec:
            raise ValueError(
                f"manifest label {label} maps to multiple images")
        images.setdefault(label, rec)
    return images


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Config-layer SKU differential over pinned corpus images")
    ap.add_argument("--images", default=str(DEFAULT_MANIFEST),
                    help="corpus manifest JSON (default: arc-A manifest)")
    ap.add_argument("--sku", action="append", required=True,
                    metavar="FAM/VER/SKU", help="image label, repeatable")
    ap.add_argument("--sec", required=True, metavar="0xNN",
                    help="ITOC section type, hex")
    ap.add_argument("--out", required=True, help="output JSON path")
    args = ap.parse_args()

    typ = int(args.sec, 16)
    if len(set(args.sku)) < 2:
        print("need at least two distinct --sku labels", file=sys.stderr)
        return 2
    repo = REPO
    manifest_path = Path(args.images)
    images = load_manifest_images(manifest_path, repo)

    payloads = {}
    meta = {}
    for label in args.sku:
        if label not in images:
            print(f"unknown sku label: {label}", file=sys.stderr)
            return 2
        entry, path = images[label]
        buf = path.read_bytes()
        digest = hashlib.md5(buf).hexdigest()
        if digest != entry["md5"]:
            print(f"md5 drift: {path}: pinned {entry['md5']}, found {digest}",
                  file=sys.stderr)
            return 2
        img = Image(buf, path=str(path))
        payloads[label] = section_payload(img, typ)
        e = find_unique_entry(img, typ)
        sec_rec = next((s for s in entry.get("sections", [])
                        if s.get("type") == "%02x" % typ), None)
        expected = sec_rec.get("md5_dc") if sec_rec else None
        meta[label] = {
            "path": (str(path.relative_to(repo))
                     if path.is_relative_to(repo) else str(path)),
            "md5": entry["md5"],
            "size": e.size,
            "cl": bool(e.clcrc),
            "zipped": bool(e.zipped),
            "payload_size": len(payloads[label]),
            "payload_md5": hashlib.md5(payloads[label]).hexdigest(),
            "crosscheck": crosscheck_md5(payloads[label], expected),
        }

    diffs = diff_sections(payloads)
    for d in diffs:
        d["hex"] = {l: payloads[l][d["offset"]:d["offset"] + d["span"]].hex()
                    for l in payloads}

    out = {
        "schema": 1,
        "section": "0x%02x" % typ,
        "manifest": str(manifest_path.relative_to(repo)
                        if manifest_path.is_relative_to(repo)
                        else manifest_path),
        "images": meta,
        "n_diffs": len(diffs),
        "diffs": diffs,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")

    sizes = {l: m["payload_size"] for l, m in meta.items()}
    size_note = "" if len(set(sizes.values())) == 1 else f" SIZES {sizes}"
    print(f"0x{typ:02x} {' vs '.join(args.sku)}: "
          f"{len(diffs)} diff spans{size_note} -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
