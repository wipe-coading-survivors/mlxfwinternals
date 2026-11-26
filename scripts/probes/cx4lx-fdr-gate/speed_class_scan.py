#!/usr/bin/env python3
"""cx4lx-fdr-gate: product speed-class scan over corpus sections 0x30/0x12.

Offline research tool (journal
docs/superpowers/journal/2026-11-23-cx4lx-fdr-gate-codehunt.md).
Correlates the per-product IB speed-class knobs with their binary
FW_MAIN_CFG (0x12) carriers:

  * section 0x30 (DBG_FW_INI, zlib text of the build .prs — a runtime
    shadow per docs/250-re/100-formats/067-prs-zlib.md §3) carries
    ``management.port_info.link_speed_ena / link_speed_ext_ena /
    link_speed_ext_sup`` and
    ``management.extended_port_info.link_speed_supported``;
  * section 0x12 carries the runtime binary class bytes; the class byte
    at +0x158 discriminates cx4 ETH (0x30) / cx4 FDR-VPI (0x10) /
    cx4 EDR-VPI (0x31); Lx builds are all 0x30 (ETH class, no IB ext
    bits). Verified on the arc-A corpus: FCA<->ECA differ in exactly
    {+0x158: 10->31, +0x283, +0x2c5: 00->10, +0x30b/+0x317: lcl 5b->fb}.

The IB speed-negotiation FSM seeds its speed_enable/width_enable from
INI param 0x776 (getter chain init 0x9bb624 -> ctx[0x5c]; identical
code in both builds), so the Lx/CX-4 handshake gate candidate is this
data, not FSM code.

Usage:
  speed_class_scan.py [--corpus DIR] [--json OUT] [--require-corpus]

Stdlib only; offline (no hardware, no ssh). Exit 1 with --require-corpus
when the corpus is absent (CI); without it a missing corpus is a skip.
"""
import argparse
import json
import re
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
DEFAULT_CORPUS = REPO / "build" / "corpus"

CLASS_BYTE = 0x158
SECONDARY_BYTE = 0x2C5
LCL0_BYTE = 0x30B
LCL1_BYTE = 0x317

PRS_RE = re.compile(r"from \./(.+?)\.prs")
LINK_SPEED_KEYS = (
    "link_speed_ena",
    "link_speed_ext_ena",
    "link_speed_ext_sup",
    "link_speed_supported",
)


def parse_ini_text(text):
    """Extract prs name + link_speed fields from a decompressed 0x30."""
    prs = ""
    fields = {}
    for ln in text.splitlines():
        if not prs:
            m = PRS_RE.search(ln)
            if m:
                prs = m.group(1)
        if "link_speed" in ln and "=" in ln:
            key, val = ln.split("=", 1)
            fields[key.strip().split(".")[-1]] = val.strip()
    return prs, fields


def scan_build(build_dir):
    """Scan one corpus build dir (contains sections/30 and sections/12)."""
    sec30 = build_dir / "sections" / "30" / "dc.bin"
    sec12 = build_dir / "sections" / "12" / "dc.bin"
    if not sec30.exists() or not sec12.exists():
        return None
    text = zlib.decompress(sec30.read_bytes()).decode("latin1")
    prs, fields = parse_ini_text(text)
    b = sec12.read_bytes()
    return {
        "prs": prs,
        "ini_link_speed": fields,
        "class_0x158": b[CLASS_BYTE],
        "secondary_0x2c5": b[SECONDARY_BYTE],
        "lcl0": b[LCL0_BYTE],
        "lcl1": b[LCL1_BYTE],
    }


def scan_corpus(corpus_root):
    """Scan every cx4/cx4lx build under the corpus root."""
    rows = {}
    for fam in ("cx4", "cx4lx"):
        famdir = Path(corpus_root) / fam
        if not famdir.is_dir():
            continue
        for verdir in sorted(famdir.iterdir()):
            if not verdir.is_dir():
                continue
            for d in sorted(verdir.iterdir()):
                r = scan_build(d)
                if r:
                    rows[f"{fam}/{verdir.name}/{d.name}"] = r
    return rows


def classify(row):
    """Map a scan row to the observed speed-class taxonomy.

    Classes (journal step 5): 'ib-fdr' (FCA), 'ib-edr' (ECA), 'eth'
    (everything else incl. all cx4lx). Based on the ini fields when
    present, else on the class byte alone.
    """
    ini = row["ini_link_speed"]
    ext_ena = int(ini.get("link_speed_ext_ena", "0x0"), 0)
    ena = int(ini.get("link_speed_ena", "0x0"), 0)
    if ena == 0x7 and ini.get("link_speed_supported"):
        return "ib-edr" if ext_ena & 0x2 else "ib-fdr"
    return "eth"


def main(argv=None):
    desc = (__doc__ or "").splitlines()[0]
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--require-corpus", action="store_true",
                        help="fail (exit 1) when no builds were scanned")
    args = parser.parse_args(argv)

    rows = scan_corpus(args.corpus)
    report = {}
    for name, row in sorted(rows.items()):
        report[name] = {**row, "class": classify(row)}
    out = json.dumps(report, indent=1)
    if args.json:
        args.json.write_text(out + "\n")
    print(out)
    print(f"builds={len(report)}", file=sys.stderr)
    if args.require_corpus and not report:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
