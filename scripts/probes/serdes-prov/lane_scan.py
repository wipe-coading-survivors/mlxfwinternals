#!/usr/bin/env python3
"""Lane-arithmetic / role-structure scanner over the arc-A corpus (arc C, T2).

Scans `disasm.txt` artifacts (canonical `irisc_dis` renders, layout per
`scripts/corpus/README.md`) for lane-level structures: lane<<N strides,
lane-count loops, SerDes regfile access clusters and lane-indexed tables.

Kinds (LaneHit["kind"]):
  shl_stride      lane<<N consumed into a SerDes regfile address
  loop_lanecount  loop test with lane-count bound (1/2/4/8/16)
  regfile_cluster st/ld whose base resolves into a SerDes block
  role_table      memory access indexed by a shifted (lane) register

Pure API: scan_lane_patterns(lines) -> list[LaneHit]; LaneHit keys are
exactly {kind, line_no, addr, stride, lineage} (line_no 1-based; for
regfile_cluster `addr` is the SerDes base, elsewhere the code dc addr).

CLI:
  python3 scripts/probes/serdes-prov/lane_scan.py \
      --sections 0x02,0x04,0x05,0x06 --out build/serdes-prov/lane-hits.json

Offline/read-only: no burn, no hardware.
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

KINDS = ("shl_stride", "loop_lanecount", "regfile_cluster", "role_table")
LANE_BOUNDS = (1, 2, 4, 8, 16)
VALUE_WINDOW = 48
LOOP_LOOKAHEAD = 24
HW_BLOCK_FLOOR = 0x800000

LX_BLOCKS = [(0x8c0000, 0x8cffff), (0x8e0000, 0x8effff),
             (0x8f0000, 0x8fffff)]
CX5_BLOCKS = [
    (0x900000, 0x90ffff), (0x930000, 0x93ffff), (0x980000, 0x98ffff),
    (0x9a0000, 0x9affff), (0x9b0000, 0x9bffff), (0x9c0000, 0x9cffff),
    (0x9d0000, 0x9dffff), (0x9d8000, 0x9d8fff), (0x9f0000, 0x9fffff),
]
FAMILY_BLOCKS = {"cx4": LX_BLOCKS, "cx4lx": LX_BLOCKS, "cx5": CX5_BLOCKS}
DEFAULT_RANGES = sorted(set(LX_BLOCKS + CX5_BLOCKS))


def serdes_blocks(family):
    return list(FAMILY_BLOCKS.get(family, DEFAULT_RANGES))


def in_ranges(value, ranges):
    return any(lo <= value <= hi for lo, hi in ranges)


R = r"(?:zero|r[0-9]+)"
IMM = r"-?0x-?[0-9a-f]+"

LINE_RE = re.compile(r"^([0-9a-f]{8})  ([0-9a-f]{8})  (\S.*)$")
RE_SET = re.compile(r"^set([23]) (%s),(%s),(0x[0-9a-f]+)$" % (R, R))
RE_ADDI = re.compile(r"^(addi|subi) (%s),(%s),(%s)$" % (R, R, IMM))
RE_ALU3 = re.compile(r"^(add|sub|subs|or|xor|and) (%s),(%s),(%s)$"
                     % (R, R, R))
RE_ANDS = re.compile(r"^ands (%s),(%s),(%s)$" % (R, R, IMM))
RE_SHLI = re.compile(r"^shl64[.]i (%s),(%s),(0x[0-9a-f]+)$" % (R, R))
RE_SHLR = re.compile(r"^shl64[.]r (%s),(%s),(%s)$" % (R, R, R))
RE_SHR = re.compile(r"^shr (%s),(%s),(0x[0-9a-f]+)$" % (R, R))
RE_ST = re.compile(r"^st[.][dqwb]!? (%s),(%s),(%s)$" % (R, R, IMM))
RE_LD = re.compile(r"^ld[.][dqwb] (%s),(%s),(%s)$" % (R, R, IMM))
RE_LWR = re.compile(r"^lw[.]r (%s),(%s),(%s)$" % (R, R, R))
RE_SUBSI = re.compile(r"^subsi (%s),(%s),(%s)$" % (R, R, IMM))
RE_BR = re.compile(r"^b[.][tf][.]0x[0-9a-f]+ %s,(0x[0-9a-f]+)$" % R)
RE_LEAD_REG = re.compile(r"^[a-z][a-z0-9_.]*!? (%s)," % R)


def _reg(tok):
    return 0 if tok == "zero" else int(tok[1:])


def _imm(tok):
    neg = tok.startswith("-")
    tok = tok.lstrip("-")
    if tok.startswith("0x-"):
        neg = True
        tok = tok[3:]
    else:
        tok = tok[2:]
    v = int(tok, 16)
    return -v if neg else v


def _shifts(value):
    if value[0] == "shift":
        return [(value[1], value[2])]
    if value[0] in ("shifts", "sdaddr", "idxaddr"):
        return list(value[-1])
    return []


def _max_stride(shifts):
    return max((a for a, _ in shifts), default=None)


def _align_mask(mask):
    if mask < 0:
        return False
    top = (1 << mask.bit_length()) - 1
    if mask == top:
        return True
    for s in range(1, mask.bit_length()):
        if mask == (top ^ ((1 << s) - 1)):
            return True
    return False


class _Scanner:
    def __init__(self, ranges, lineage, stats):
        self.ranges = ranges
        self.lineage = lineage
        self.stats = stats
        self.regs = {}
        self.parsed_no = 0
        self.emitted_shl = set()

    def _get(self, reg):
        entry = self.regs.get(reg)
        if entry is None:
            return None
        value, at = entry
        if self.parsed_no - at > VALUE_WINDOW:
            del self.regs[reg]
            return None
        return value

    def _set(self, reg, value):
        if reg:
            self.regs[reg] = (value, self.parsed_no)

    def _drop(self, reg):
        self.regs.pop(reg, None)

    def _add(self, a, b):
        if a is None or b is None:
            return None
        if a[0] == "const" and b[0] == "const":
            return ("const", a[1] + b[1])
        if b[0] == "const":
            a, b = b, a
        if a[0] == "const":
            base = a[1]
            sh = _shifts(b)
            if sh:
                if in_ranges(base, self.ranges):
                    return ("sdaddr", base, sh)
                return ("idxaddr", base, sh)
            if b[0] == "sdaddr":
                return ("sdaddr", b[1], list(b[2]))
            if b[0] == "idxaddr":
                return ("idxaddr", b[1], list(b[2]))
            return None
        if a[0] in ("shift", "shifts") and b[0] in ("shift", "shifts"):
            return ("shifts", _shifts(a) + _shifts(b))
        if a[0] == "sdaddr":
            return ("sdaddr", a[1], _shifts(a) + _shifts(b))
        if a[0] == "idxaddr":
            return ("idxaddr", a[1], _shifts(a) + _shifts(b))
        if b[0] == "sdaddr":
            return ("sdaddr", b[1], _shifts(a) + _shifts(b))
        if b[0] == "idxaddr":
            return ("idxaddr", b[1], _shifts(a) + _shifts(b))
        return None

    def _add_op(self, rd, rs_tok, rt_tok, rs, rt):
        if rs is None and rt is None:
            self._drop(rd)
            return
        if rs is None or rt is None:
            shift_val = rt if rs is None else rs
            live_tok = rt_tok if rs is None else rs_tok
            if shift_val and shift_val[0] in ("shift", "shifts") \
                    and live_tok != "zero":
                sh = _shifts(shift_val)
                self._set(rd, ("idxaddr", ("reg", _reg(live_tok)), sh))
                return
            self._drop(rd)
            return
        self._set(rd, self._add(rs, rt))

    def _hit(self, kind, line_no, addr, stride):
        return {"kind": kind, "line_no": line_no, "addr": addr,
                "stride": stride, "lineage": self.lineage}

    def _emit_shl_strides(self, shifts, hits):
        for amount, line_no in shifts:
            if line_no not in self.emitted_shl:
                self.emitted_shl.add(line_no)
                hits.append(self._hit("shl_stride", line_no,
                                      self.line_addr.get(line_no, 0), amount))

    def _mem_access(self, base_value, line_no, addr, hits):
        if base_value is None:
            return
        if base_value[0] == "sdaddr":
            shifts = _shifts(base_value)
            hits.append(self._hit("regfile_cluster", line_no,
                                  base_value[1], _max_stride(shifts)))
            self._emit_shl_strides(shifts, hits)
        elif base_value[0] == "const":
            if in_ranges(base_value[1], self.ranges):
                hits.append(self._hit("regfile_cluster", line_no,
                                      base_value[1], None))
        elif base_value[0] == "idxaddr":
            base = base_value[1]
            if not isinstance(base, int) or base < HW_BLOCK_FLOOR:
                shifts = _shifts(base_value)
                if shifts:
                    hits.append(self._hit("role_table", line_no, addr,
                                          _max_stride(shifts)))

    def run(self, lines):
        hits = []
        parsed = []
        for line_no, raw in enumerate(lines, 1):
            line = raw.rstrip("\n")
            m = LINE_RE.match(line)
            if not m:
                self.stats["skipped"] += 1
                continue
            body = m.group(3).split(" ; ", 1)[0]
            if body.startswith("raw ") or body.startswith("unk."):
                self.stats["skipped"] += 1
                continue
            parsed.append((int(m.group(1), 16), line_no, body))
        self.line_addr = {line_no: addr for addr, line_no, _ in parsed}
        for idx, (addr, line_no, body) in enumerate(parsed):
            self.parsed_no += 1
            self.stats["parsed"] += 1
            self._instr(addr, line_no, body, parsed, idx, hits)
        return hits

    def _instr(self, addr, line_no, body, parsed, idx, hits):
        m = RE_SET.match(body)
        if m:
            rd, rs, imm = _reg(m.group(2)), _reg(m.group(3)), int(m.group(4), 16)
            src = ("const", 0) if rs == 0 else self._get(rs)
            op2 = m.group(1) == "2"
            if src is None or src[0] != "const" or (op2 and rs != 0 and rs != rd):
                val = None
            elif op2:
                val = ("const", (src[1] & 0xFFFF) | (imm << 16))
            else:
                val = ("const", (src[1] & 0xFFFF0000) | imm)
            self._set(rd, val)
            return
        m = RE_ADDI.match(body)
        if m:
            rd, rs = _reg(m.group(2)), _reg(m.group(3))
            imm = _imm(m.group(4))
            if m.group(1) == "subi":
                imm = -imm
            src = self._get(rs) if rs else ("const", 0)
            if src is None:
                self._drop(rd)
                return
            if src[0] == "const":
                self._set(rd, ("const", src[1] + imm))
            else:
                self._set(rd, src)
            return
        m = RE_ALU3.match(body)
        if m:
            op, rd = m.group(1), _reg(m.group(2))
            rs, rt = self._get(_reg(m.group(3))), self._get(_reg(m.group(4)))
            if op == "add":
                self._add_op(rd, m.group(3), m.group(4), rs, rt)
            elif op in ("sub", "subs"):
                if rs and rt and rs[0] == "const" and rt[0] == "const":
                    self._set(rd, ("const", rs[1] - rt[1]))
                else:
                    self._drop(rd)
            elif op == "and":
                if rt and rt[0] == "const":
                    self._and_value(rd, rs, rt[1])
                elif rs and rs[0] == "const":
                    self._and_value(rd, rt, rs[1])
                else:
                    self._drop(rd)
            elif op == "or":
                if m.group(3) == m.group(4):
                    self._set(rd, rs)
                elif m.group(3) == "zero":
                    self._set(rd, rt)
                elif m.group(4) == "zero":
                    self._set(rd, rs)
                else:
                    self._drop(rd)
            else:
                if rs and rt and rs[0] == "const" and rt[0] == "const":
                    self._set(rd, ("const", rs[1] ^ rt[1]))
                elif m.group(3) == m.group(4):
                    self._set(rd, ("const", 0))
                else:
                    self._drop(rd)
            return
        m = RE_ANDS.match(body)
        if m:
            rd, mask = _reg(m.group(1)), _imm(m.group(3))
            src = self._get(_reg(m.group(2)))
            self._and_value(rd, src, mask)
            return
        m = RE_SHLI.match(body)
        if m:
            rd, amount = _reg(m.group(1)), int(m.group(3), 16)
            src = self._get(_reg(m.group(2)))
            if src and src[0] == "const":
                self._set(rd, ("const", src[1] << amount))
            else:
                self._set(rd, ("shift", amount, line_no))
            return
        m = RE_SHLR.match(body)
        if m:
            self._drop(_reg(m.group(1)))
            return
        m = RE_SHR.match(body)
        if m:
            rd, amount = _reg(m.group(1)), int(m.group(3), 16)
            src = self._get(_reg(m.group(2)))
            if src is None:
                self._drop(rd)
            elif src[0] == "const":
                self._set(rd, ("const", src[1] >> amount))
            else:
                self._set(rd, src)
            return
        m = RE_ST.match(body)
        if m:
            base = self._get(_reg(m.group(2)))
            self._mem_access(base, line_no, addr, hits)
            self._drop(_reg(m.group(1)))
            return
        m = RE_LD.match(body)
        if m:
            rd, base = _reg(m.group(1)), self._get(_reg(m.group(2)))
            self._mem_access(base, line_no, addr, hits)
            self._drop(rd)
            return
        m = RE_LWR.match(body)
        if m:
            rd = _reg(m.group(1))
            base = self._get(_reg(m.group(2)))
            index = self._get(_reg(m.group(3)))
            if base and base[0] == "sdaddr":
                shifts = _shifts(base) + _shifts(index) if index else _shifts(base)
                hits.append(self._hit("regfile_cluster", line_no,
                                      base[1], _max_stride(shifts)))
                self._emit_shl_strides(shifts, hits)
            elif index and index[0] in ("shift", "shifts"):
                hits.append(self._hit("role_table", line_no, addr,
                                      _max_stride(_shifts(index))))
            elif base and base[0] == "idxaddr":
                shifts = _shifts(base)
                if shifts:
                    hits.append(self._hit("role_table", line_no, addr,
                                          _max_stride(shifts)))
            self._drop(rd)
            return
        m = RE_SUBSI.match(body)
        if m:
            rd, rs = _reg(m.group(1)), _reg(m.group(2))
            bound = _imm(m.group(3))
            src = self._get(rs)
            self._set(rd, ("const", src[1] - bound)
                      if src and src[0] == "const" else None)
            if bound in LANE_BOUNDS:
                self._loop_check(addr, line_no, bound, parsed, idx, hits)
            return
        if RE_BR.match(body) or body.startswith(("jump ", "call ", "ret.")):
            return
        m = re.match(r"^csr[.]r (%s)," % R, body)
        if m:
            self._drop(_reg(m.group(1)))
            return
        if body.startswith("csr."):
            return
        m = RE_LEAD_REG.match(body)
        if m:
            self._drop(_reg(m.group(1)))

    def _and_value(self, rd, src, mask):
        if src is None:
            self._drop(rd)
        elif src[0] == "const":
            self._set(rd, ("const", src[1] & mask))
        elif _align_mask(mask):
            self._set(rd, src)
        else:
            self._drop(rd)

    def _loop_check(self, addr, line_no, bound, parsed, idx, hits):
        for nxt in parsed[idx + 1:idx + 1 + LOOP_LOOKAHEAD]:
            m = RE_BR.match(nxt[2])
            if m:
                if int(m.group(1), 16) <= addr:
                    hits.append(self._hit("loop_lanecount", line_no, addr,
                                          bound))
                return


def scan_lane_patterns(lines, *, serdes_ranges=None, lineage=None, stats=None):
    """Scan disasm lines for lane patterns; see module docstring."""
    if serdes_ranges is None:
        serdes_ranges = DEFAULT_RANGES
    if stats is None:
        stats = {}
    stats.setdefault("lines", 0)
    stats.setdefault("parsed", 0)
    stats.setdefault("skipped", 0)
    lines = list(lines)
    stats["lines"] += len(lines)
    scanner = _Scanner(list(serdes_ranges), lineage, stats)
    return scanner.run(lines)


def _load_funcs(path):
    if not path.is_file():
        return []
    funcs = []
    rows = path.read_text().splitlines()
    for row in rows[1:]:
        parts = row.split("\t")
        if len(parts) < 2:
            continue
        try:
            funcs.append((int(parts[0], 16), int(parts[1], 16)))
        except ValueError:
            continue
    return sorted(funcs)


def _func_of(funcs, addr):
    for entry, end in funcs:
        if entry <= addr < end:
            return entry
    return None


def _iter_images(corpus):
    for fam in sorted(p for p in corpus.iterdir() if p.is_dir()):
        for ver in sorted(p for p in fam.iterdir() if p.is_dir()):
            for sku in sorted(p for p in ver.iterdir() if p.is_dir()):
                if (sku / "sections").is_dir():
                    yield fam.name, ver.name, sku.name, sku


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Lane-pattern scanner over the arc-A disasm corpus")
    ap.add_argument("--corpus", default=str(REPO / "build" / "corpus"),
                    help="corpus root (default: build/corpus)")
    ap.add_argument("--sections", required=True, metavar="0xNN,0xNN,...",
                    help="ITOC section types to scan, comma-separated hex")
    ap.add_argument("--sku", action="append", metavar="FAM/VER/SKU",
                    help="restrict to image label, repeatable")
    ap.add_argument("--lineage", action="append", metavar="KEY=TAG",
                    help="lineage override for a family or full label")
    ap.add_argument("--out", required=True, help="output JSON path")
    args = ap.parse_args(argv)

    try:
        sections = ["%02x" % int(s.strip(), 16)
                    for s in args.sections.split(",") if s.strip()]
    except ValueError:
        print("bad --sections value", file=sys.stderr)
        return 2
    corpus = Path(args.corpus)
    overrides = {}
    for spec in args.lineage or []:
        key, _, tag = spec.partition("=")
        overrides[key] = tag

    images_out = []
    hits_out = []
    n_images = 0
    for fam, ver, sku, root in _iter_images(corpus):
        label = "/".join((fam, ver, sku))
        if args.sku and label not in args.sku:
            continue
        n_images += 1
        lineage = overrides.get(label, overrides.get(fam, fam))
        ranges = serdes_blocks(fam)
        record = {"label": label, "lineage": lineage,
                  "ranges": "family" if fam in FAMILY_BLOCKS else "union",
                  "sections": {}, "clusters": []}
        cluster_map = {}
        for sec in sections:
            disasm = root / "sections" / sec / "disasm.txt"
            if not disasm.is_file():
                record["sections"][sec] = {"disasm": "absent"}
                continue
            lines = disasm.read_text().splitlines()
            stats = {}
            hits = scan_lane_patterns(
                lines, serdes_ranges=ranges, lineage=lineage, stats=stats)
            funcs = _load_funcs(root / "sections" / sec / "funcs.tsv")
            addr_of = {}
            for i, line in enumerate(lines, 1):
                if len(line) >= 8:
                    try:
                        addr_of[i] = int(line[:8], 16)
                    except ValueError:
                        pass
            kinds = {}
            for hit in hits:
                kinds[hit["kind"]] = kinds.get(hit["kind"], 0) + 1
                rec = dict(hit)
                rec["image"] = label
                rec["section"] = sec
                hits_out.append(rec)
                if hit["kind"] == "regfile_cluster":
                    key = (hit["addr"], hit["stride"])
                    entry = cluster_map.setdefault(
                        key, {"addr": "0x%x" % hit["addr"],
                              "stride": hit["stride"], "n": 0,
                              "sections": set(), "functions": set(),
                              "lineages": set()})
                    entry["n"] += 1
                    entry["sections"].add(sec)
                    entry["lineages"].add(lineage)
                    fn = _func_of(funcs, addr_of.get(hit["line_no"]))
                    if fn is not None:
                        entry["functions"].add("0x%x" % fn)
            record["sections"][sec] = {
                "disasm": "ok", "lines": stats.get("lines", 0),
                "parsed": stats.get("parsed", 0),
                "skipped": stats.get("skipped", 0),
                "hits": kinds}
        for entry in cluster_map.values():
            entry["sections"] = sorted(entry["sections"])
            entry["functions"] = sorted(entry["functions"])
            entry["lineages"] = sorted(entry["lineages"])
        record["clusters"] = sorted(cluster_map.values(),
                                    key=lambda c: (-c["n"], c["addr"]))
        images_out.append(record)

    out = {"schema": 1, "sections": sections, "corpus": str(corpus),
           "images": images_out, "hits": hits_out}
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")

    for record in images_out:
        kinds = {}
        for sec in record["sections"].values():
            for kind, n in sec.get("hits", {}).items():
                kinds[kind] = kinds.get(kind, 0) + n
        summary = " ".join("%s=%d" % (k, kinds[k]) for k in KINDS if k in kinds)
        print("%s [%s]: %s clusters=%d"
              % (record["label"], record["lineage"], summary or "no hits",
                 len(record["clusters"])))
    print("wrote %s (%d hits, %d images)" % (out_path, len(hits_out), n_images))
    return 0


if __name__ == "__main__":
    sys.exit(main())
