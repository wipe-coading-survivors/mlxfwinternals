#!/usr/bin/env python3
"""Corpus orchestrator (serdes-corpus arc A, spec 2026-11-11 §3/§7).

Pipeline per pinned image: md5 gate -> ITOC extraction (Task 2) ->
domain dispatch: iRISC sections get the full artifact set (disasm +
census annotations, trust-layer indexes, skeleton), PHY sections get
slots.tsv (phyuc_dis 16B-slot parse), ROM sections get raw + md5 +
signature sniff (no disasm), data sections raw + md5. Summary manifest
is committed next to this module. --check rebuilds into a tmp dir and
byte-diffs artifacts and manifest.

Usage:
  python3 -m scripts.corpus.build_corpus [--refs ROOT] [--out ROOT]
      [--manifest PATH] [--t3] [--only FAMILY/VER/SKU] [--jobs N] [--check]
"""
import argparse
import hashlib
import importlib.util
import json
import multiprocessing
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from mlxfwutil import Image
from scripts.corpus.boundaries import find_functions, write_funcs_tsv
from scripts.corpus.disasm_build import (
    PROFILE_ABSENT,
    disasm_section,
    disasm_stage,
)
from scripts.corpus.extract import (
    PriorDisagreement,
    sections_of,
    write_sections,
)
from scripts.corpus.indexes import (
    build_calls,
    build_consts,
    build_strings,
    build_xref,
    dense_tables,
    write_calls_tsv,
    write_strings_txt,
    write_xref_tsv,
)
from scripts.corpus.manifest import (
    CorpusManifestError,
    ImageRef,
    resolve_images,
    verify_md5,
)
from scripts.corpus.skeleton import skeleton_section

SCHEMA = 1
DEFAULT_REFS = REPO
OUT_ROOT = REPO / "build" / "corpus"
MANIFEST_PATH = Path(__file__).resolve().parent / "corpus_manifest.json"

ROM_SIGNATURES = ((b"\x55\xaa", "pci_oprom"), (b"MZ", "pe_mz"))


def _load_phyuc_dis():
    path = REPO / "scripts" / "phyuc" / "phyuc_dis.py"
    spec = importlib.util.spec_from_file_location("phyuc_dis", path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_PHYUC_DIS = _load_phyuc_dis()


class CorpusBuildError(Exception):
    pass


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def rom_signature(payload: bytes) -> str:
    for magic, name in ROM_SIGNATURES:
        if payload.startswith(magic):
            return name
    return "unknown"


def write_slots_tsv(slots, path) -> None:
    rows = ["idx\top\ta\tb\tc\td\tclass\tasm"]
    for i, op, a, b, c, d in slots:
        rows.append("%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%s\t%s" % (
            i, op, a, b, c, d, _PHYUC_DIS.op_class(op),
            _PHYUC_DIS.dis(i, op, a, b, c, d)))
    Path(path).write_text("\n".join(rows) + "\n")


def write_consts_merged(consts, tables, path) -> None:
    rows = ["kind\tvalue\tcount"]
    rows.extend("imm\t%d\t%d" % (c.value, c.count) for c in consts)
    rows.extend("table\t0x%x\t%d" % (base, n) for base, n in tables)
    Path(path).write_text("\n".join(rows) + "\n")


def section_windows(recs):
    wins = []
    for r in recs:
        if r.domain == "iRISC" and r.status == "OK" and r.dc and r.param0:
            wins.append(("%02X" % r.typ, r.param0, r.param0 + len(r.dc)))
    return sorted(wins)


def _profile_summary(stage):
    return {
        "name": stage["profile"],
        "status": "absent" if stage["status"] == PROFILE_ABSENT else "ok",
        "drift": bool(stage["drift"]),
    }


def process_section(rec, sec_dir, family, ver, windows):
    payload = rec.dc or rec.raw
    sec = {
        "type": "%02X" % rec.typ,
        "domain": rec.domain,
        "status": rec.status,
        "status_reason": rec.status_reason,
        "size": rec.size,
        "cl": rec.cl,
        "zipped": rec.zipped,
        "words": len(payload) // 4,
        "md5_raw": _md5(rec.raw),
        "md5_dc": _md5(rec.dc) if rec.dc else None,
        "metrics": None,
        "profile": None,
    }
    extra = {"words": sec["words"], "md5_raw": sec["md5_raw"],
             "md5_dc": sec["md5_dc"]}
    if rec.domain == "iRISC":
        if rec.status == "OK" and rec.dc:
            base_dc = rec.param0
            lines = disasm_section(rec.dc, base_dc)
            stage = disasm_stage(rec.dc, base_dc, family, ver,
                                 lines=lines)
            (sec_dir / "disasm.txt").write_text(stage["text"])
            entries = [rec.param1] if rec.param1 else []
            funcs = find_functions(lines, entries)
            write_funcs_tsv(lines, funcs, sec_dir / "funcs.tsv")
            write_calls_tsv(build_calls(lines, windows),
                            sec_dir / "calls.tsv")
            write_xref_tsv(build_xref(lines), sec_dir / "xref.tsv")
            write_consts_merged(
                build_consts(lines),
                [(base_dc + off, n)
                 for off, n in dense_tables(rec.dc)],
                sec_dir / "consts.tsv")
            write_strings_txt(
                [(base_dc + off, s)
                 for off, s in build_strings(rec.dc)],
                sec_dir / "strings.txt")
            (sec_dir / "pseudo.md").write_text(
                skeleton_section(lines, funcs))
            sec["metrics"] = funcs.metrics
            sec["profile"] = _profile_summary(stage)
            extra["metrics"] = funcs.metrics
            extra["profile"] = sec["profile"]
    elif rec.domain == "PHY":
        if rec.status == "OK" and rec.dc:
            try:
                slots = _PHYUC_DIS.slots(rec.dc)
            except ValueError as exc:
                rec.status = "ERROR"
                rec.status_reason = str(exc)
                sec["status"] = rec.status
                sec["status_reason"] = rec.status_reason
            else:
                write_slots_tsv(slots, sec_dir / "slots.tsv")
                extra["n_slots"] = len(slots)
    elif rec.domain == "ROM":
        extra["rom_signature"] = rom_signature(payload)
    return sec, extra


def build_image(ref: ImageRef, out_root: Path) -> dict:
    verify_md5(ref)
    entry = {
        "path": str(ref.path_rel or ref.path),
        "md5": ref.md5,
        "tier": ref.tier,
        "family": ref.family,
        "ver": ref.ver,
        "sku": ref.sku,
        "status": "OK",
        "status_reason": "",
        "sections": [],
    }
    try:
        buf = ref.path.read_bytes()
        image = Image(buf)
        if not image.header_crc_ok("ITOC"):
            raise CorpusBuildError("ITOC header CRC mismatch")
        bad = [e for e in image.entries("ITOC")
               if not image.entry_crc_ok(e)]
        if bad:
            raise CorpusBuildError(
                "ITOC entry CRC mismatch: "
                + ", ".join("0x%02x" % e.type for e in bad))
        recs = sections_of(image, family=ref.family)
    except PriorDisagreement:
        raise
    except CorpusBuildError as exc:
        entry["status"] = "ERROR"
        entry["status_reason"] = str(exc)
        return entry
    except Exception as exc:
        entry["status"] = "ERROR"
        entry["status_reason"] = "%s: %s" % (type(exc).__name__, exc)
        return entry
    recs = sorted(recs, key=lambda r: r.typ)
    windows = section_windows(recs)
    img_dir = out_root / ref.family / ref.ver / ref.sku
    sections = []
    extras = {}
    for rec in recs:
        sec_dir = img_dir / "sections" / ("%02X" % rec.typ)
        sec_dir.mkdir(parents=True, exist_ok=True)
        sec, extra = process_section(rec, sec_dir, ref.family, ref.ver,
                                     windows)
        sections.append(sec)
        extras[rec.typ] = extra
    write_sections(img_dir, recs, extra_meta=extras)
    entry["sections"] = sections
    return entry


def _build_image_task(args):
    ref, out_root = args
    return build_image(ref, Path(out_root))


def build_all(refs, out_root: Path, manifest_path: Path, jobs: int = 1) -> dict:
    ordered = sorted(refs, key=lambda r: (r.family, r.ver, r.sku,
                                          str(r.path)))
    if jobs > 1:
        with multiprocessing.Pool(jobs) as pool:
            images = pool.map(_build_image_task,
                              [(ref, out_root) for ref in ordered])
    else:
        images = [build_image(ref, out_root) for ref in ordered]
    summary = {"schema": SCHEMA, "images": images}
    manifest_path = Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(summary, indent=1, sort_keys=True) + "\n")
    return summary


def apply_only(refs, spec):
    if not spec:
        return list(refs)
    parts = spec.split("/")
    if len(parts) != 3:
        raise CorpusManifestError(
            "--only expects FAMILY/VER/SKU, got %r" % spec)
    family, ver, sku = parts
    return [r for r in refs
            if (r.family, r.ver, r.sku) == (family, ver, sku)]


def _tree_files(root: Path) -> dict:
    root = Path(root)
    return {p.relative_to(root).as_posix(): p
            for p in sorted(root.rglob("*")) if p.is_file()}


def diff_trees(left: Path, right: Path) -> list:
    lf, rf = _tree_files(left), _tree_files(right)
    problems = []
    for name in sorted(set(lf) - set(rf)):
        problems.append("only in %s: %s" % (left, name))
    for name in sorted(set(rf) - set(lf)):
        problems.append("only in %s: %s" % (right, name))
    for name in sorted(set(lf) & set(rf)):
        if lf[name].read_bytes() != rf[name].read_bytes():
            problems.append("differs: %s" % name)
    return problems


def run_check(refs, out_root: Path, manifest_path: Path, jobs: int = 1) -> int:
    tmp_base = Path(out_root).parent / "corpus-tmp"
    tmp_base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="corpus-check-",
                                     dir=tmp_base) as tmp_name:
        tmp = Path(tmp_name)
        rebuilt = tmp / "corpus"
        fresh_manifest = tmp / "corpus_manifest.json"
        build_all(refs, rebuilt, fresh_manifest, jobs=jobs)
        problems = diff_trees(out_root, rebuilt)
        if not manifest_path.is_file():
            problems.append("manifest missing: %s" % manifest_path)
        elif manifest_path.read_bytes() != fresh_manifest.read_bytes():
            problems.append("manifest differs: %s" % manifest_path)
    if problems:
        for line in problems:
            print("corpus-check: %s" % line)
        print("corpus-check: FAILED (%d problems)" % len(problems))
        return 1
    print("corpus-check: OK (%d images)" % len(refs))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="scripts.corpus.build_corpus",
        description="build the SerDes decompilation corpus "
                    "(spec 2026-11-11-serdes-corpus-a §3/§7)")
    parser.add_argument("--refs", type=Path, default=DEFAULT_REFS,
                        help="root containing refs/ (default repo root)")
    parser.add_argument("--out", type=Path, default=OUT_ROOT,
                        help="corpus output root (default build/corpus)")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH,
                        help="summary manifest path (committed)")
    parser.add_argument("--t3", action="store_true",
                        help="include T3 witness images")
    parser.add_argument("--jobs", type=int,
                        default=min(os.cpu_count() or 1, 8),
                        help="parallel image builds (default: "
                             "min(cpu_count, 8); 1 = serial)")
    parser.add_argument("--only",
                        help="restrict to FAMILY/VER/SKU")
    parser.add_argument("--check", action="store_true",
                        help="rebuild into a tmp dir and byte-diff "
                             "artifacts and manifest")
    args = parser.parse_args(argv)
    try:
        refs = resolve_images(args.refs, include_t3=args.t3)
        refs = apply_only(refs, args.only)
        if args.only and not refs:
            parser.error("--only %s: no images matched" % args.only)
        if args.check:
            return run_check(refs, args.out, args.manifest,
                             jobs=args.jobs)
        build_all(refs, args.out, args.manifest, jobs=args.jobs)
    except CorpusManifestError as exc:
        print("corpus: refused: %s" % exc, file=sys.stderr)
        return 2
    except PriorDisagreement as exc:
        print("corpus: PriorDisagreement (hard stop): %s" % exc,
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
