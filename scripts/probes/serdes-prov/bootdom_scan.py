#!/usr/bin/env python3
"""Boot-domain scanner over the arc-A corpus (arc C, T4, roadmap 190).

Static analysis of who parses config sections (0x08/0x09/0x11) and
writes CR/RAM windows in the boot chain (sections 0x05/0x06/0x02), to
indict or exonerate IRON_PREP. Offline/read-only: no burn, no hardware.

Kinds (hit["kind"], exactly the brief set):
  flash_addr_ref  arithmetic on flash addresses of config sections
                  (ld.i with imm<<2 == flash addr; const materialization)
  window_write    st.* whose const-tracked effective address touches a
                  window slot (word = byte_addr>>2 in window_slots)
  prelude_call    call target below the section load base. Both render
                  conventions: corpus-resolved absolute (PC + rel24*4,
                  iRISC.slaspec REL24 canon) and raw negative-space
                  0xfffeXXXX (resolved as load_base + signed32 per the
                  task brief / boot-chain journal shifted-view form).

Pure API: scan_bootdom(lines, flash_addrs, window_slots) -> BootHit;
BootHit = {"hits": [...], "load_base": int|None, "stats": {...}}.
flash_addrs: {section_type: addr | (lo, hi) | [addr | (lo, hi), ...]}
window_slots: RAM word indices (ld.i-imm convention: word<<2 = byte).

CLI:
  python3 scripts/probes/serdes-prov/bootdom_scan.py \
      --sections 0x05,0x06,0x02 --lineage cx6dx=witness \
      --out build/serdes-prov/bootdom-hits.json

Below-base call targets are classified by the first word of the target
where it lands inside a section window of the same image (word decoded
via scripts.irisc); otherwise "outside-image".
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from scripts.irisc import disasm as irisc_dis  # noqa: E402

KINDS = ("flash_addr_ref", "window_write", "prelude_call")
VALUE_WINDOW = 48
STORE_BYTES = {"d": 8, "q": 8, "w": 2, "b": 1}

LX_WINDOW = list(range(0x3a9f, 0x3b2d)) + [0x3ad1, 0x3ab9]
CX5_WINDOW = list(range(0x3753, 0x379d)) + [0x3771, 0x3759]
FAMILY_WINDOWS = {"cx4": LX_WINDOW, "cx4lx": LX_WINDOW, "cx5": CX5_WINDOW}

R = r"(?:zero|r[0-9]+)"
IMM = r"-?0x-?[0-9a-f]+"

LINE_RE = re.compile(r"^([0-9a-f]{8})  ([0-9a-f]{8})  (\S.*)$")
RE_SET = re.compile(r"^set([23]) (%s),(%s),(0x[0-9a-f]+)$" % (R, R))
RE_ADDI = re.compile(r"^(addi|subi) (%s),(%s),(%s)$" % (R, R, IMM))
RE_ALU3 = re.compile(r"^(add|sub|subs|or|xor|and) (%s),(%s),(%s)$"
                     % (R, R, R))
RE_ANDS = re.compile(r"^ands (%s),(%s),(%s)$" % (R, R, IMM))
RE_SHLI = re.compile(r"^shl64[.]i (%s),(%s),(0x[0-9a-f]+)$" % (R, R))
RE_SHR = re.compile(r"^shr (%s),(%s),(0x[0-9a-f]+)$" % (R, R))
RE_ST = re.compile(r"^st[.]([dqwb])(?:[.]1e)?(!)? (%s),(%s),(%s)$"
                   % (R, R, IMM))
RE_LD = re.compile(r"^ld[.][dqwb] (%s),(%s),(%s)$" % (R, R, IMM))
RE_LWR = re.compile(r"^lw[.]r (%s),(%s),(%s)$" % (R, R, R))
RE_LDI = re.compile(r"^ld[.]i (%s),0x([0-9a-f]+)$" % R)
RE_CALL = re.compile(r"^call 0x([0-9a-f]+)$")
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


def _norm_ranges(flash_addrs):
    ranges = []
    for section, value in flash_addrs.items():
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, tuple):
                ranges.append((item[0], item[1], str(section)))
            else:
                ranges.append((item, item, str(section)))
    return ranges


def _range_of(ranges, value):
    for lo, hi, section in ranges:
        if lo <= value <= hi:
            return section
    return None


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
    def __init__(self, ranges, slots, load_base, lineage, stats):
        self.ranges = ranges
        self.slots = set(slots)
        self.load_base = load_base
        self.lineage = lineage
        self.stats = stats
        self.regs = {}
        self.parsed_no = 0

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

    def _hit(self, kind, line_no, addr, extra):
        hit = {"kind": kind, "line_no": line_no, "addr": addr,
               "lineage": self.lineage}
        hit.update(extra)
        return hit

    def _flash_const(self, line_no, addr, value, hits):
        section = _range_of(self.ranges, value)
        if section is not None:
            hits.append(self._hit("flash_addr_ref", line_no, addr,
                                  {"cfg": section, "flash_addr": value,
                                   "how": "const"}))

    def _store(self, size_tok, push, base_tok, off, line_no, addr, hits):
        base_reg = _reg(base_tok)
        base = self._get(base_reg)
        if base is not None:
            eff = base + off
            last = (eff + STORE_BYTES[size_tok] - 1) >> 2
            for word in range(eff >> 2, last + 1):
                if word in self.slots:
                    hits.append(self._hit("window_write", line_no, addr,
                                          {"word": word}))
            if push:
                self._set(base_reg, eff)

    def _call(self, operand, line_no, addr, hits):
        value = int(operand, 16)
        if value >= 0x80000000:
            target = (self.load_base + value - (1 << 32)) & 0xFFFFFFFF
        else:
            target = value
        if target < self.load_base:
            hits.append(self._hit("prelude_call", line_no, addr,
                                  {"target": target, "imm": value}))

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
        if parsed and self.load_base is None:
            self.load_base = parsed[0][0]
        for addr, line_no, body in parsed:
            self.parsed_no += 1
            self.stats["parsed"] += 1
            self._instr(addr, line_no, body, hits)
        return hits

    def _instr(self, addr, line_no, body, hits):
        m = RE_LDI.match(body)
        if m:
            word_addr = int(m.group(2), 16) << 2
            section = _range_of(self.ranges, word_addr)
            if section is not None:
                hits.append(self._hit(
                    "flash_addr_ref", line_no, addr,
                    {"cfg": section, "flash_addr": word_addr,
                     "how": "ld.i imm<<2"}))
            self._drop(_reg(m.group(1)))
            return
        m = RE_CALL.match(body)
        if m:
            if self.load_base is not None:
                self._call(m.group(1), line_no, addr, hits)
            return
        m = RE_SET.match(body)
        if m:
            rd, rs, imm = _reg(m.group(2)), _reg(m.group(3)), \
                int(m.group(4), 16)
            src = 0 if rs == 0 else self._get(rs)
            op2 = m.group(1) == "2"
            if src is None or (op2 and rs != 0 and rs != rd):
                val = None
            elif op2:
                val = (src & 0xFFFF) | (imm << 16)
            else:
                val = (src & 0xFFFF0000) | imm
            self._set(rd, val)
            if val is not None:
                self._flash_const(line_no, addr, val, hits)
            return
        m = RE_ADDI.match(body)
        if m:
            rd, rs = _reg(m.group(2)), _reg(m.group(3))
            imm = _imm(m.group(4))
            if m.group(1) == "subi":
                imm = -imm
            src = 0 if rs == 0 else self._get(rs)
            if src is None:
                self._drop(rd)
                return
            val = src + imm
            self._set(rd, val)
            self._flash_const(line_no, addr, val, hits)
            return
        m = RE_ALU3.match(body)
        if m:
            self._alu3(m, line_no, addr, hits)
            return
        m = RE_ANDS.match(body)
        if m:
            rd, mask = _reg(m.group(1)), _imm(m.group(3))
            src = self._get(_reg(m.group(2)))
            if src is None or mask < 0:
                self._drop(rd)
                return
            val = src & mask
            self._set(rd, val)
            self._flash_const(line_no, addr, val, hits)
            return
        m = RE_SHLI.match(body)
        if m:
            rd, amount = _reg(m.group(1)), int(m.group(3), 16)
            src = self._get(_reg(m.group(2)))
            if src is None:
                self._set(rd, None)
                return
            val = src << amount
            self._set(rd, val)
            self._flash_const(line_no, addr, val, hits)
            return
        m = RE_SHR.match(body)
        if m:
            rd, amount = _reg(m.group(1)), int(m.group(3), 16)
            src = self._get(_reg(m.group(2)))
            if src is None:
                self._drop(rd)
                return
            val = src >> amount
            self._set(rd, val)
            self._flash_const(line_no, addr, val, hits)
            return
        m = RE_ST.match(body)
        if m:
            self._store(m.group(1), m.group(2), m.group(4),
                        _imm(m.group(5)), line_no, addr, hits)
            return
        m = RE_LD.match(body)
        if m:
            self._drop(_reg(m.group(1)))
            return
        m = RE_LWR.match(body)
        if m:
            self._drop(_reg(m.group(1)))
            return
        m = RE_LEAD_REG.match(body)
        if m:
            self._drop(_reg(m.group(1)))

    def _alu3(self, m, line_no, addr, hits):
        op, rd = m.group(1), _reg(m.group(2))
        rs_tok, rt_tok = m.group(3), m.group(4)
        rs, rt = self._get(_reg(rs_tok)), self._get(_reg(rt_tok))
        val = None
        if op in ("add", "sub", "subs"):
            if rs is not None and rt is not None:
                val = rs + rt if op == "add" else rs - rt
        elif op == "and":
            if rt is not None and rs is not None:
                val = rs & rt
            elif rt is not None and _align_mask(rt):
                val = rs
            elif rs is not None and _align_mask(rs):
                val = rt
        elif op == "or":
            if rs_tok == rt_tok:
                val = rs
            elif rs_tok == "zero":
                val = rt
            elif rt_tok == "zero":
                val = rs
        else:
            if rs is not None and rt is not None:
                val = rs ^ rt
            elif rs_tok == rt_tok:
                val = 0
        self._set(rd, val)
        if val is not None:
            self._flash_const(line_no, addr, val, hits)


def scan_bootdom(lines, flash_addrs, window_slots, *, load_base=None,
                 lineage=None, stats=None):
    """Scan boot-domain disasm lines; see module docstring."""
    if stats is None:
        stats = {}
    stats.setdefault("lines", 0)
    stats.setdefault("parsed", 0)
    stats.setdefault("skipped", 0)
    lines = list(lines)
    stats["lines"] += len(lines)
    scanner = _Scanner(_norm_ranges(flash_addrs), window_slots, load_base,
                       lineage, stats)
    hits = scanner.run(lines)
    return {"hits": hits, "load_base": scanner.load_base, "stats": stats}


def _load_funcs(path):
    if not path.is_file():
        return []
    funcs = []
    for row in path.read_text().splitlines()[1:]:
        parts = row.split("\t")
        if len(parts) < 2:
            continue
        try:
            funcs.append((int(parts[0], 16), int(parts[1], 16)))
        except ValueError:
            continue
    return sorted(funcs)


def _load_calls(path):
    if not path.is_file():
        return []
    calls = []
    for row in path.read_text().splitlines()[1:]:
        parts = row.split("\t")
        if len(parts) < 2:
            continue
        try:
            calls.append((int(parts[0], 16), int(parts[1], 16)))
        except ValueError:
            continue
    return calls


def _func_of(funcs, addr):
    for entry, end in funcs:
        if entry <= addr < end:
            return entry
    return None


def _end_of(funcs, entry):
    for e, end in funcs:
        if e == entry:
            return end
    return entry


def _iter_images(corpus):
    for fam in sorted(p for p in corpus.iterdir() if p.is_dir()):
        for ver in sorted(p for p in fam.iterdir() if p.is_dir()):
            for sku in sorted(p for p in ver.iterdir() if p.is_dir()):
                if (sku / "sections").is_dir():
                    yield fam.name, ver.name, sku.name, sku


def _section_windows(image_root):
    windows = []
    for secdir in sorted((image_root / "sections").iterdir()):
        meta = secdir / "meta.json"
        if not meta.is_file():
            continue
        m = json.loads(meta.read_text())
        base, words = m.get("param0", 0), m.get("words", 0)
        if base and words:
            windows.append((secdir.name, base, base + words * 4, secdir))
    return windows


def _first_word_type(windows, target):
    for name, lo, hi, secdir in windows:
        if lo <= target < hi and (target - lo) % 4 == 0:
            dc = secdir / "dc.bin"
            if not dc.is_file():
                return "sec%s:no-dump" % name
            raw = dc.read_bytes()
            off = target - lo
            if off + 4 > len(raw):
                return "sec%s:no-dump" % name
            word = int.from_bytes(raw[off:off + 4], "big")
            return "sec%s:%s" % (name, irisc_dis(word, target)
                                 .split()[0].rstrip(","))
    return "outside-image"


def _entry_tree(secdir, param1, windows):
    funcs = _load_funcs(secdir / "funcs.tsv")
    calls = _load_calls(secdir / "calls.tsv")
    if not funcs:
        return []
    entry = _func_of(funcs, param1)
    if entry is None:
        return []
    tree = []
    frontier = [entry]
    seen = {entry}
    for depth in (0, 1):
        nxt = []
        for fn in frontier:
            end = _end_of(funcs, fn)
            sites = [(s, t) for s, t in calls if fn <= s < end]
            classes = {}
            for _, target in sites:
                cls = _first_word_type(windows, target)
                classes[cls] = classes.get(cls, 0) + 1
            tree.append({"func": "0x%x" % fn, "depth": depth,
                         "n_calls": len(sites), "classes": classes})
            for _, target in sites:
                callee = _func_of(funcs, target)
                if callee is not None and callee not in seen:
                    seen.add(callee)
                    nxt.append(callee)
        frontier = nxt
    return tree


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Boot-domain scanner over the arc-A disasm corpus")
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
        flash_addrs = {}
        for cfg in ("08", "09", "11"):
            meta = root / "sections" / cfg / "meta.json"
            if meta.is_file():
                m = json.loads(meta.read_text())
                flash_addrs["0x" + cfg] = [
                    (m["flash_addr"], m["flash_addr"] + m["size"])]
        window = FAMILY_WINDOWS.get(fam, [])
        record = {"label": label, "lineage": lineage,
                  "window": "family" if fam in FAMILY_WINDOWS
                  else "no-anchor",
                  "flash_sections": sorted(flash_addrs),
                  "sections": {}}
        windows = _section_windows(root)
        for sec in sections:
            secdir = root / "sections" / sec
            disasm = secdir / "disasm.txt"
            meta = secdir / "meta.json"
            if not disasm.is_file():
                record["sections"][sec] = {"disasm": "absent"}
                continue
            param1 = 0
            if meta.is_file():
                param1 = json.loads(meta.read_text()).get("param1", 0)
            lines = disasm.read_text().splitlines()
            stats = {}
            result = scan_bootdom(lines, flash_addrs, window,
                                  lineage=lineage, stats=stats)
            kinds = {}
            for hit in result["hits"]:
                kinds[hit["kind"]] = kinds.get(hit["kind"], 0) + 1
                rec = dict(hit)
                rec["image"] = label
                rec["section"] = sec
                if hit["kind"] == "prelude_call":
                    rec["target_class"] = _first_word_type(
                        windows, hit["target"])
                hits_out.append(rec)
            record["sections"][sec] = {
                "disasm": "ok", "lines": stats.get("lines", 0),
                "parsed": stats.get("parsed", 0),
                "skipped": stats.get("skipped", 0),
                "load_base": result["load_base"],
                "hits": kinds,
                "entry_tree": _entry_tree(secdir, param1, windows)}
        images_out.append(record)

    out = {"schema": 1, "sections": sections, "corpus": str(corpus),
           "images": images_out, "hits": hits_out}
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")

    for record in images_out:
        parts = []
        for sec, srec in record["sections"].items():
            if srec.get("disasm") == "ok":
                parts.append("%s:%s" % (sec, srec["hits"] or "{}"))
            else:
                parts.append("%s:absent" % sec)
        print("%s [%s] window=%s flash=%s | %s"
              % (record["label"], record["lineage"], record["window"],
                 ",".join(record["flash_sections"]) or "-",
                 " ".join(parts)))
    print("wrote %s (%d hits, %d images)" % (out_path, len(hits_out),
                                             n_images))
    return 0


if __name__ == "__main__":
    sys.exit(main())
