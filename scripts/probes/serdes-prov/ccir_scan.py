#!/usr/bin/env python3
"""CCIR identification battery over the arc-A corpus (arc B, T3).

Three scan classes for CCIR_INFRA (0x0D) / CCIR_ALGO (0x0E) on
CX-6Dx 22.50, plus controls:

  (a) crypto-Rosetta: SHA-256 K, SHA-512 K/H, AES S-box/T0-T3, GHASH R —
      all tables are *generated* (exact integer arithmetic), searched
      big/little-endian, full-table and 16-byte-prefix. CRC tables are
      control patterns ("expected everywhere": ITOC/clcrc families),
      never a discriminator.
  (b) mul-cycle heuristic: shift-add multiplication idioms (bit-serial
      32x32 loops, unrolled multi-shift products, doubling chains) —
      the RSA/ECC long-math signature on a mul-less ISA.
      lane-structures: delegates to lane_scan.scan_lane_patterns.
  (c) structural: readable strings attributed to corpus function
      boundaries, per-section call-graph (internal/outgoing/incoming
      edges, entry points without callers, param1 entry), crypto scan
      per section dc payload.

Controls: --whole-image (raw image sweep), --control LABEL:CORPUS_ROOT
(absence check of the same constants/markers on other images, e.g.
CX-4/5/6 anchors and the A16 T1 scratch corpus).

CLI:
  python3 scripts/probes/serdes-prov/ccir_scan.py \
      --image cx6dx/22_50_1002/MCX623435AC-CDA --sections 0x0d,0x0e \
      --control-sections 0x15 \
      --whole-image refs/fw/cx-5-6/<image>.bin \
      --markers ztr_rttcc \
      --control cx6/20_43_1014/MCX654105A-HCA:build/corpus \
      --out build/serdes-prov/arc-b/ccir-battery.json

Offline/read-only: no burn, no hardware.
"""
import argparse
import json
import math
import re
import sys
from pathlib import Path

import lane_scan

REPO = Path(__file__).resolve().parents[3]

PREFIX_LEN = 16
VALUE_WINDOW = 48

LINE_RE = re.compile(r"^([0-9a-f]{8})\s+([0-9a-f]{8})\s+(\S.*)$")
R = r"(?:zero|r[0-9]+)"
RE_SHLI = re.compile(r"^shl64[.]i (%s),(%s),(0x[0-9a-f]+)$" % (R, R))
RE_SHR = re.compile(r"^shr (%s),(%s),(0x[0-9a-f]+)$" % (R, R))
RE_ADD3 = re.compile(r"^add (%s),(%s),(%s)$" % (R, R, R))
MUL_KINDS = ("mul_bitserial", "mul_shiftadd", "mul_doubling")


def _primes(count):
    out = []
    n = 2
    while len(out) < count:
        if all(n % p for p in range(2, int(math.isqrt(n)) + 1)):
            out.append(n)
        n += 1
    return out


def _icbrt(n):
    x = int(round(n ** (1.0 / 3.0))) + 1
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


def _frac_cbrt_bits(p, bits):
    shift = 3 * bits
    return _icbrt(p << shift) - (_icbrt(p) << bits)


def _frac_sqrt_bits(p, bits):
    return math.isqrt(p << (2 * bits)) - (math.isqrt(p) << bits)


def _aes_tables():
    poly = 0x11B
    exp = [0] * 510
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x2 = (x << 1) ^ (poly if x & 0x80 else 0)
        x ^= x2 & 0xFF
    for i in range(255, 510):
        exp[i] = exp[i - 255]

    def inv(a):
        return 0 if a == 0 else exp[255 - log[a]]

    def mul(a, b):
        if a == 0 or b == 0:
            return 0
        return exp[log[a] + log[b]]

    sbox = bytearray(256)
    for a in range(256):
        b = inv(a)
        s = b
        for _ in range(4):
            b = ((b << 1) | (b >> 7)) & 0xFF
            s ^= b
        sbox[a] = s ^ 0x63
    t_tables = [bytearray(1024) for _ in range(4)]
    for a in range(256):
        s = sbox[a]
        word = bytes((mul(s, 2), s, s, mul(s, 3)))
        for t in range(4):
            t_tables[t][4 * a:4 * a + 4] = word[-t:] + word[:-t] \
                if t else word
    return bytes(sbox), tuple(bytes(t) for t in t_tables)


def _crc32_table():
    table = bytearray(1024)
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table[4 * i:4 * i + 4] = crc.to_bytes(4, "big")
    return bytes(table)


def _crc16_table():
    table = bytearray(512)
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 \
                else (crc << 1) & 0xFFFF
        table[2 * i:2 * i + 2] = crc.to_bytes(2, "big")
    return bytes(table)


def _with_endian(blob, word):
    if word <= 1:
        return {"be": blob}
    swapped = bytearray(len(blob))
    for off in range(0, len(blob), word):
        swapped[off:off + word] = blob[off:off + word][::-1]
    if bytes(swapped) == blob:
        return {"be": blob}
    return {"be": blob, "le": bytes(swapped)}


def build_crypto_tables():
    """Discriminator tables (exact integer arithmetic, no float error)."""
    sha256_k = b"".join(_frac_cbrt_bits(p, 32).to_bytes(4, "big")
                        for p in _primes(64))
    sha512_k = b"".join(_frac_cbrt_bits(p, 64).to_bytes(8, "big")
                        for p in _primes(80))
    sha512_h = b"".join(_frac_sqrt_bits(p, 64).to_bytes(8, "big")
                        for p in _primes(8))
    sbox, t_tables = _aes_tables()
    return {
        "sha256_k": _with_endian(sha256_k, 4),
        "sha512_k": _with_endian(sha512_k, 8),
        "sha512_h": _with_endian(sha512_h, 8),
        "aes_sbox": _with_endian(sbox, 1),
        "aes_t0": _with_endian(t_tables[0], 4),
        "aes_t1": _with_endian(t_tables[1], 4),
        "aes_t2": _with_endian(t_tables[2], 4),
        "aes_t3": _with_endian(t_tables[3], 4),
        "ghash_r": _with_endian(b"\xe1" + b"\x00" * 15, 16),
    }


def build_control_tables():
    """Expected-everywhere tables (ITOC/clcrc families): NOT discriminators."""
    return {
        "crc32_reflected": _with_endian(_crc32_table(), 4),
        "crc16_ccitt": _with_endian(_crc16_table(), 2),
    }


def _find_all(data, blob):
    out = []
    off = data.find(blob)
    while off != -1:
        out.append(off)
        off = data.find(blob, off + 1)
    return out


def scan_constants(data, tables):
    """Search generated tables in data; full match wins over same-name prefix.

    Returns [{name, offset, order, match}] sorted by offset; one prefix
    hit per (name, order) at the first occurrence.
    """
    hits = []
    full_names = set()
    for name in sorted(tables):
        for order, blob in sorted(tables[name].items()):
            for off in _find_all(data, blob):
                hits.append({"name": name, "offset": off,
                             "order": order, "match": "full"})
                full_names.add(name)
    for name in sorted(tables):
        if name in full_names:
            continue
        for order, blob in sorted(tables[name].items()):
            off = data.find(blob[:PREFIX_LEN])
            if off != -1:
                hits.append({"name": name, "offset": off,
                             "order": order, "match": "prefix"})
    return sorted(hits, key=lambda h: (h["offset"], h["name"], h["order"]))


def _reg(tok):
    return 0 if tok == "zero" else int(tok[1:])


def _br_target(body):
    m = lane_scan.RE_BR.match(body)
    return int(m.group(1), 16) if m else None


def scan_mul_cycles(lines):
    """Shift-add multiplication heuristic over canonical disasm lines.

    Kinds: mul_bitserial (backward loop with self shl<<1 and self shr>>1;
    overlapping/nested loop body ranges are deduplicated to one physical
    cycle), mul_shiftadd (>=2 distinct shifts of one source consumed as
    addends; the pending group is dropped when the source register is
    redefined, so shifts of different values never merge), mul_doubling
    (add rd,rs,rs). Hit keys: {kind, line_no, addr, shifts, loop}.
    """
    parsed = []
    for line_no, raw in enumerate(lines, 1):
        m = LINE_RE.match(raw.rstrip("\n"))
        if not m:
            continue
        body = m.group(3).split(" ; ", 1)[0]
        if body.startswith("raw ") or body.startswith("unk."):
            continue
        parsed.append((int(m.group(1), 16), line_no, body))
    loops = []
    for addr, line_no, body in parsed:
        target = _br_target(body)
        if target is not None and target < addr:
            loops.append((target, addr, line_no))
    bitserial = []
    for lo, hi, br_line in loops:
        has_shl1 = has_shr1 = False
        for addr, _, body in parsed:
            if not lo <= addr <= hi:
                continue
            m = RE_SHLI.match(body)
            if m and m.group(1) == m.group(2) and int(m.group(3), 16) == 1:
                has_shl1 = True
            m = RE_SHR.match(body)
            if m and m.group(1) == m.group(2) and int(m.group(3), 16) == 1:
                has_shr1 = True
        if has_shl1 and has_shr1:
            bitserial.append((lo, hi, br_line))
    bitserial.sort(key=lambda t: (t[0], t[1]))
    merged = []
    for lo, hi, br_line in bitserial:
        if merged and lo <= merged[-1][1]:
            mlo, mhi, mline = merged[-1]
            if hi > mhi:
                merged[-1] = (mlo, hi, br_line)
            continue
        merged.append((lo, hi, br_line))
    hits = [{"kind": "mul_bitserial", "line_no": t[2], "addr": t[1],
             "shifts": [1], "loop": True} for t in merged]
    pending = {}
    groups = {}
    seq = 0

    def redefine(rd_tok):
        pending.pop(_reg(rd_tok), None)
        groups.pop(rd_tok, None)
        for key in list(pending):
            if pending[key][0] == rd_tok:
                del pending[key]

    for addr, line_no, body in parsed:
        seq += 1
        for reg in list(pending):
            if seq - pending[reg][4] > VALUE_WINDOW:
                del pending[reg]
        m = RE_ADD3.match(body)
        if m:
            rd = m.group(1)
            for tok in (m.group(2), m.group(3)):
                rec = pending.get(_reg(tok))
                if rec is not None:
                    src, amount, _, _, _ = rec
                    groups.setdefault(src, {}).setdefault(amount,
                                                          (line_no, addr))
                    if len(groups[src]) >= 2:
                        amounts = sorted(groups[src])
                        hits.append({"kind": "mul_shiftadd",
                                     "line_no": line_no, "addr": addr,
                                     "shifts": amounts,
                                     "loop": any(lo <= addr <= hi
                                                 for lo, hi, _ in loops)})
                        del groups[src]
            if m.group(2) == m.group(3) and m.group(2) != "zero":
                hits.append({"kind": "mul_doubling", "line_no": line_no,
                             "addr": addr, "shifts": [1],
                             "loop": any(lo <= addr <= hi
                                         for lo, hi, _ in loops)})
            redefine(rd)
            continue
        m = RE_SHLI.match(body)
        if m:
            redefine(m.group(1))
            pending[_reg(m.group(1))] = (m.group(2), int(m.group(3), 16),
                                         line_no, addr, seq)
            continue
        m = lane_scan.RE_LEAD_REG.match(body)
        if m and not body.startswith(("st.", "call", "jump")):
            redefine(m.group(1))
    return hits


def scan_lane_section(lines, family):
    """lane_scan delegation: lane<<N / regfile / role_table hits."""
    stats = {}
    hits = lane_scan.scan_lane_patterns(
        lines, serdes_ranges=lane_scan.serdes_blocks(family), stats=stats)
    counts = {}
    for hit in hits:
        counts[hit["kind"]] = counts.get(hit["kind"], 0) + 1
    return {"counts": counts, "hits": hits,
            "stats": {"parsed": stats.get("parsed", 0),
                      "skipped": stats.get("skipped", 0)}}


READABLE_RE = re.compile(r"^[ -~]+$")


def _load_funcs(path):
    return lane_scan._load_funcs(Path(path))


def _func_of(funcs, addr):
    for entry, end in funcs:
        if entry <= addr < end:
            return entry
    return None


def readable_strings(strings_path, funcs=None):
    """Human-readable strings (>=8 printable chars, separator, alpha-major),
    attributed to corpus function boundaries (region func|tail)."""
    bounds = _load_funcs(funcs) if funcs else []
    out = []
    for row in Path(strings_path).read_text(errors="replace").splitlines()[1:]:
        dc_s, _, text = row.partition("\t")
        if len(text) < 8 or not READABLE_RE.match(text):
            continue
        if not (" " in text or "_" in text or "," in text):
            continue
        if sum(c.isalnum() for c in text) * 10 < 7 * len(text):
            continue
        dc = int(dc_s, 16)
        fn = _func_of(bounds, dc)
        out.append({"dc": dc, "text": text,
                    "function": None if fn is None else "0x%x" % fn,
                    "region": "func" if fn is not None else "tail"})
    return out


def _read_tsv(path):
    rows = []
    if not Path(path).is_file():
        return rows
    for row in Path(path).read_text().splitlines()[1:]:
        parts = row.split("\t")
        if len(parts) >= 3:
            rows.append(parts)
    return rows


def section_callgraph(sections_root, sec):
    """Who calls whom for one section; exports/entries view.

    incoming_external scans the sibling sections' calls.tsv for targets
    resolved into this section (corpus param0-window resolution).
    """
    sec_dir = Path(sections_root) / sec
    own = _read_tsv(sec_dir / "calls.tsv")
    internal = [r for r in own if r[2] == sec]
    outgoing = [r for r in own if r[2] != sec]
    incoming = []
    for other in sorted(p for p in Path(sections_root).iterdir()
                        if p.is_dir() and p.name != sec):
        for site, target, target_sec in _read_tsv(other / "calls.tsv"):
            if target_sec == sec:
                incoming.append({"from_section": other.name,
                                 "site": site, "target": target})
    funcs = _load_funcs(sec_dir / "funcs.tsv")
    n_callers = {}
    if (sec_dir / "funcs.tsv").is_file():
        for row in (sec_dir / "funcs.tsv").read_text().splitlines()[1:]:
            parts = row.split("\t")
            if len(parts) >= 5:
                n_callers[parts[0]] = int(parts[4])
    entries = sorted(e for e, n in n_callers.items() if n == 0)
    param1_entry = None
    meta = sec_dir / "meta.json"
    if meta.is_file():
        param1 = json.loads(meta.read_text()).get("param1")
        if param1 is not None:
            addr = "0x%x" % param1
            if addr in n_callers:
                param1_entry = addr
    return {"n_funcs": len(funcs), "n_edges": len(own),
            "internal_edges": len(internal),
            "outgoing_external": [{"site": r[0], "target": r[1],
                                   "target_section": r[2]}
                                  for r in outgoing],
            "incoming_external": incoming,
            "entries_no_callers": entries,
            "param1_entry": param1_entry}


def _scan_section(sec_dir, family, tables, control_tables, markers):
    payload = None
    for name in ("dc.bin", "raw.bin"):
        p = sec_dir / name
        if p.is_file() and p.stat().st_size:
            payload = p.read_bytes()
            break
    disasm = (sec_dir / "disasm.txt")
    lines = disasm.read_text().splitlines() if disasm.is_file() else []
    strings_txt = sec_dir / "strings.txt"
    marker_hits = []
    for marker in markers:
        where = None
        if strings_txt.is_file() and marker in strings_txt.read_text(
                errors="replace"):
            where = "strings.txt"
        elif payload is not None and marker.encode() in payload:
            where = "dc.bin"
        if where:
            marker_hits.append({"marker": marker, "where": where})
    return {
        "crypto_hits": scan_constants(payload, tables)
        if payload is not None else [],
        "control_hits": scan_constants(payload, control_tables)
        if payload is not None else [],
        "mul_hits": scan_mul_cycles(lines) if lines else [],
        "lane": scan_lane_section(lines, family) if lines else {},
        "strings": readable_strings(strings_txt,
                                    funcs=sec_dir / "funcs.tsv")
        if strings_txt.is_file() else [],
        "marker_hits": marker_hits,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="CCIR identification battery (arc B T3)")
    ap.add_argument("--corpus", default=str(REPO / "build" / "corpus"))
    ap.add_argument("--image", default="cx6dx/22_50_1002/MCX623435AC-CDA")
    ap.add_argument("--sections", default="0x0d,0x0e",
                    help="ITOC section types to scan, comma-separated hex")
    ap.add_argument("--control-sections", default="",
                    help="extra control sections (e.g. 0x15 ACE), same scan")
    ap.add_argument("--whole-image", help="raw firmware image to sweep")
    ap.add_argument("--markers", action="append", default=[],
                    help="string marker to track (repeatable)")
    ap.add_argument("--control", action="append", metavar="LABEL:CORPUS_ROOT",
                    help="absence-control image (repeatable)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    def norm(spec):
        return ["%02X" % int(s.strip(), 16)
                for s in spec.split(",") if s.strip()]

    try:
        sections = norm(args.sections)
        controls_secs = norm(args.control_sections)
    except ValueError:
        print("bad --sections/--control-sections value", file=sys.stderr)
        return 2

    tables = build_crypto_tables()
    control_tables = build_control_tables()
    image_root = Path(args.corpus) / args.image / "sections"
    family = args.image.split("/")[0]

    section_records = {}
    for role, spec in (("target", sections), ("control", controls_secs)):
        for sec in spec:
            sec_dir = image_root / sec
            if not sec_dir.is_dir():
                section_records[sec] = {"role": role, "absent": True}
                continue
            rec = _scan_section(sec_dir, family, tables, control_tables,
                                args.markers)
            rec["role"] = role
            rec["callgraph"] = section_callgraph(image_root, sec)
            section_records[sec] = rec

    whole = {"path": args.whole_image, "crypto_hits": [],
             "control_hits": [], "marker_hits": []}
    if args.whole_image:
        data = Path(args.whole_image).read_bytes()
        whole["crypto_hits"] = scan_constants(data, tables)
        whole["control_hits"] = scan_constants(data, control_tables)
        whole["marker_hits"] = [{"marker": m, "where": "image"}
                                for m in args.markers
                                if m.encode() in data]

    controls_out = []
    for spec in args.control or []:
        label, _, root = spec.partition(":")
        croot = Path(root) / label / "sections"
        rec = {"label": label, "corpus": str(root), "crypto_hits": [],
               "marker_hits": [], "sections_scanned": 0}
        if not croot.is_dir():
            rec["absent"] = True
        else:
            for sec_dir in sorted(croot.iterdir()):
                if not sec_dir.is_dir():
                    continue
                payload = None
                for name in ("dc.bin", "raw.bin"):
                    p = sec_dir / name
                    if p.is_file() and p.stat().st_size:
                        payload = p.read_bytes()
                        break
                if payload is None:
                    continue
                rec["sections_scanned"] += 1
                for hit in scan_constants(payload, tables):
                    hit = dict(hit)
                    hit["section"] = sec_dir.name
                    rec["crypto_hits"].append(hit)
                for marker in args.markers:
                    strings_txt = sec_dir / "strings.txt"
                    if marker.encode() in payload or (
                            strings_txt.is_file() and marker in
                            strings_txt.read_text(errors="replace")):
                        rec["marker_hits"].append(
                            {"marker": marker, "section": sec_dir.name})
        controls_out.append(rec)

    out = {"schema": 1, "corpus": args.corpus, "markers": args.markers,
           "crypto_tables": sorted(tables),
           "control_tables": sorted(control_tables),
           "target": {"label": args.image, "family": family,
                      "sections": section_records},
           "whole_image": whole,
           "controls": controls_out}
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")

    for sec in sorted(section_records):
        rec = section_records[sec]
        if rec.get("absent"):
            print("%s [%s]: absent" % (sec, rec["role"]))
            continue
        summary = ("crypto=%d control=%d mul=%d lane=%d strings=%d "
                   "ext_in=%d entries=%s") % (
            len(rec["crypto_hits"]), len(rec["control_hits"]),
            len(rec["mul_hits"]), sum(rec["lane"].get("counts",
                                                     {}).values()),
            len([s for s in rec["strings"]]),
            len(rec["callgraph"]["incoming_external"]),
            ",".join(rec["callgraph"]["entries_no_callers"]) or "-")
        print("%s [%s]: %s" % (sec, rec["role"], summary))
    for rec in controls_out:
        state = "absent" if rec.get("absent") else (
            "sections=%d crypto=%d markers=%d"
            % (rec["sections_scanned"], len(rec["crypto_hits"]),
               len(rec["marker_hits"])))
        print("control %s: %s" % (rec["label"], state))
    print("wrote %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
