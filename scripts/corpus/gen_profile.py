#!/usr/bin/env python3
"""Provisional iRISC profile generator (corpus arc A).

Builds a provisional profile JSON (status "provisional", census =
recount-unknown-op histogram) from a refs firmware image pinned in the
corpus manifest. One-off, refs-dependent: JSON generation for
cx4-1228 / cx6-2043 / cx6lx-2650 runs in Task 9 on real refs images.

Usage:
  python3 -m scripts.corpus.gen_profile <image> <name> [--out FILE]
"""
import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from mlxfwutil import SECT_NAMES, Image
from scripts.corpus.extract import sections_of
from scripts.corpus.manifest import CorpusManifestError, T1, T2, T3
from scripts.irisc import recount_codehist as _RC

NOTE = "provisional recount census (corpus arc A); unverified"

MAIN_CODE_TYPE = {v: k for k, v in SECT_NAMES.items()}["MAIN_CODE"]

CHIP_BY_FAMILY = {
    "cx4": "ConnectX-4",
    "cx4lx": "ConnectX-4 Lx",
    "cx5": "ConnectX-5",
    "cx6": "ConnectX-6",
    "cx6dx": "ConnectX-6 Dx",
    "cx6lx": "ConnectX-6 Lx",
    "cx7": "ConnectX-7",
}


def census_hist(dc: bytes) -> dict:
    n = len(dc) // 4
    if n == 0:
        return {}
    words = struct.unpack_from(">%dI" % n, dc, 0)
    _, ops, code, _, _, _ = _RC.classify(words, n)
    hist = Counter()
    for i, op in enumerate(ops):
        if code[i] and op not in _RC.KNOWN30:
            hist[op] += 1
    return hist


def build_profile_json(hist: dict, name: str, chip: str, load_base: int,
                       source: str) -> dict:
    ranked = sorted(hist, key=lambda op: (-hist[op], op))
    unknown_ops = {
        "0x%02x" % op: {"count_code": hist[op], "note": NOTE} for op in ranked
    }
    return {
        "name": name,
        "chip": chip,
        "verified_on": [],
        "load_base": {"MAIN_CODE": load_base},
        "anchors": [],
        "forms": {},
        "unknown_ops": unknown_ops,
        "status": "provisional",
        "provisional_reason": "corpus-arc-A",
        "source": source,
    }


def find_ref(image_path: Path):
    digest = hashlib.md5(image_path.read_bytes()).hexdigest()
    for ref in T1 + T2 + T3:
        if ref.md5 == digest:
            return ref
    raise CorpusManifestError(
        "image %s: md5 %s not pinned in corpus manifest"
        % (image_path, digest))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="scripts.corpus.gen_profile",
        description="generate a provisional iRISC profile JSON "
                    "from a corpus-manifest-pinned refs image")
    parser.add_argument("image", type=Path,
                        help="refs firmware image (md5-pinned in manifest)")
    parser.add_argument("name", help="profile name, e.g. cx4-1228")
    parser.add_argument("--out", type=Path, default=None,
                        help="write JSON here instead of stdout")
    args = parser.parse_args(argv)

    ref = find_ref(args.image)
    chip = CHIP_BY_FAMILY.get(ref.family)
    if chip is None:
        raise CorpusManifestError(
            "family %r has no chip name mapping" % ref.family)
    recs = sections_of(Image(args.image.read_bytes()), family=ref.family)
    mains = [r for r in recs if r.typ == MAIN_CODE_TYPE]
    if len(mains) != 1:
        raise CorpusManifestError(
            "image %s: expected exactly one MAIN_CODE section, found %d"
            % (args.image, len(mains)))
    hist = census_hist(mains[0].dc)
    data = build_profile_json(hist, args.name, chip, mains[0].param0,
                              str(ref.path))
    text = json.dumps(data, indent=2) + "\n"
    if args.out is not None:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
