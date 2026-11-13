#!/usr/bin/env python3
"""Якорный скан MAIN_CODE CX-6 22.50.1002 (task-02, вход для Tasks 3-5).

Кодифицирует сканы сессии журнала 2026-10-30-cx6dx-securefw-task-02:
один прогон = все секции. Поисковые паттерны — CX-5-прецеденты
docs/250-re/110-signing/035-securefw-map.md и 040-key-resolve.md
(адреса CX-5 НЕ адреса CX-6). Секции:

- crypto: DER DigestInfo (SHA-256/512/384/SHA-1) + SHA-таблицы (данные) +
  addi/addi.hi-сайты в крипто-константный блок + функции-контейнеры
  (пролог 0x480300bc);
- tables: rt-указательные серии (>=8 слов [base, base+len)) с долей
  call-таргетов + pair-сайты-потребители (addi/addi.hi -> база серии);
- regids: imm-сайты CX-5-идентификаторов MFPA 0x9010 / MFBA 0x9011 /
  MFBE 0x9012 / MCC-MCQI 0x9060-0x9064 / 0x9020 (поисковый паттерн);
- strings: строки-якоря burn/verify/uuid/signature/hash + pair-сайты;
- chain <dc>: всё call-дерево от функции (сверка call-цепочек Шага 2).

Запуск из корня репо:

  python3 scripts/cx6secfw/anchor_scan.py [blob] [--base 0x21000000]
  python3 scripts/cx6secfw/anchor_scan.py [blob] chain <dc-hex>
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402
from scripts.irisc.irisc_dis import s16  # noqa: E402

BLOB = "build/cx6dx-main03-dc.bin"
BASE = 0x21000000
PROLOGUE = 0x480300BC

DER = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
}
REGIDS = {0x9010: "MFPA", 0x9011: "MFBA", 0x9012: "MFBE", 0x9060: "MCC",
          0x9061: "MCDA", 0x9062: "MCQS", 0x9063: "MCQI", 0x9064: "RANGE64",
          0x9020: "RANGE20"}
STR_PATS = ("burn", "Burn", "verify", "Verify", "uuid", "UUID", "signature",
            "Signature", "ITOC", "itoc", "partition", "secure", "digest",
            "hash", "public key", "public_key")
STR_SKIP = ("cable", "CMIS", "SFF", "epl_burn", "PLDM", "sx_", "gvmi")


class Blob:
    def __init__(self, path, base):
        self.data = open(path, "rb").read()
        self.base = base
        self.n = len(self.data)
        self.callers = defaultdict(list)
        self.targets = set()
        self._index()
        self.pairs = self._pairs()

    def w(self, o):
        return int.from_bytes(self.data[o:o + 4], "big")

    def _index(self):
        for o in range(0, self.n - 3, 4):
            ww = self.w(o)
            if (ww >> 26) & 0x3F == 0x25:
                s = disasm(ww, o)
                t = int(s.split(" 0x")[-1], 16)
                self.targets.add(t)
                if s.startswith("call"):
                    self.callers[t].append(o)

    def _pairs(self):
        out = {}
        for o in range(0, self.n - 4, 4):
            ww = self.w(o)
            if (ww >> 26) & 0x3F not in (0x00, 0x01):
                continue
            rd = (ww >> 16) & 0x1F
            lo = ww & 0xFFFF
            for k in range(1, 4):
                wp = self.w(o + 4 * k)
                if (wp >> 26) & 0x3F not in (0x02, 0x03):
                    continue
                if ((wp >> 21) & 0x1F) != rd:
                    continue
                out[o] = ((((wp & 0xFFFF) << 16) + s16(lo))
                          & 0xFFFFFFFF) - self.base
                break
        return out

    def fstart(self, site):
        o = site & ~3
        while o > 4 and self.w(o) != PROLOGUE:
            o -= 4
        return o

    def pair_sites_to(self, lo, hi=None):
        hi = lo + 4 if hi is None else hi
        return [(o, d) for o, d in self.pairs.items() if lo <= d < hi]


def crypto(b):
    print("== crypto ==")
    for name, pat in DER.items():
        cnt = b.data.count(pat)
        p = b.data.find(pat)
        print(f"  DER {name}: {cnt}, first dc {p:#x}" if cnt
              else f"  DER {name}: 0")
    runs = []
    for name, (width, const) in {
            "sha512_h": (8, 0x6A09E667F3BCC908),
            "sha384_h": (8, 0xCBBB9D5DC1059ED8),
            "sha512_k": (8, 0x428A2F98D728AE22),
            "sha256_k": (4, 0x428A2F98)}.items():
        pat = const.to_bytes(width, "big")
        p = b.data.find(pat)
        if p >= 0:
            runs.append((p, name))
    for p, name in sorted(runs):
        print(f"  table {name} @ dc {p:#x}")
    if not runs:
        return
    lo = min(p for p, _ in runs) - 0x100
    hi = max(p for p, _ in runs) + 0x100
    for o, d in b.pair_sites_to(lo, hi):
        print(f"  xref site {o:#x} -> dc {d:#x} in func {b.fstart(o):#x}")


def tables(b, min_run=8, min_frac=0.10):
    print("== dispatch/pointer tables ==")
    runs, cur = [], None
    for o in range(0, b.n - 3, 4):
        v = b.w(o)
        if b.base <= v < b.base + b.n:
            cur = [o, 1] if cur is None else [cur[0], cur[1] + 1]
        else:
            if cur and cur[1] >= min_run:
                runs.append(tuple(cur))
            cur = None
    if cur and cur[1] >= min_run:
        runs.append(tuple(cur))
    for off, cnt in runs:
        ok = sum(1 for k in range(cnt)
                 if b.w(off + 4 * k) - b.base in b.targets)
        if ok / cnt < min_frac:
            continue
        sites = b.pair_sites_to(off, off + 0x40)
        print(f"  dc {off:#x} x{cnt}: {ok}/{cnt} call-tgts; "
              f"consumers {[f'{o:#x}(f {b.fstart(o):#x})' for o, _ in sites[:4]]}")


def regids(b):
    print("== reg-id sites (CX-5 ids as search patterns) ==")
    per = defaultdict(list)
    for o in range(0, b.n - 3, 4):
        s = disasm(b.w(o), o)
        if not re.match(r"^(set[0-3]|addi|subsi) ", s):
            continue
        try:
            imm = int(s.split(",")[-1], 16)
        except ValueError:
            continue
        if imm in REGIDS:
            per[REGIDS[imm]].append(o)
    for name in sorted(set(REGIDS.values())):
        sites = per.get(name, [])
        if sites:
            print(f"  {name}: {len(sites)}: "
                  f"{[hex(o) for o in sites[:8]]}")


def strings(b):
    print("== string anchors ==")
    by_tgt = defaultdict(list)
    for o, d in b.pairs.items():
        by_tgt[d].append(o)
    seen = set()
    for m in re.finditer(rb"[ -~]{6,}", b.data):
        s, t = m.start(), m.group().decode()
        if len(t) > 90 or not any(p in t for p in STR_PATS) \
                or any(k in t for k in STR_SKIP):
            continue
        sites = by_tgt.get(s, [])
        if not sites or t in seen:
            continue
        seen.add(t)
        fs = {b.fstart(x) for x in sites}
        print(f"  str {s:#x}: {t[:64]!r} sites {[hex(x) for x in sites[:3]]} "
              f"funcs {[hex(f) for f in sorted(fs)[:3]]}")


def chain(b, root, depth=3):
    print(f"== call chain from {root:#x} (depth {depth}) ==")
    level = {root: None}
    seen = {root}
    for d in range(depth):
        nxt = {}
        for f in level:
            for site in b.callers.get(f, []):
                g = b.fstart(site)
                if g not in seen:
                    nxt[g] = (f, site)
                    seen.add(g)
        for g, (f, site) in sorted(nxt.items()):
            print(f"  {'  ' * d}{g:#x} <- call@{site:#x} from {f:#x}")
        level = nxt


def main():
    args = sys.argv[1:]
    blob, base = BLOB, BASE
    if args and args[0] == "--base":
        base = int(args[1], 0)
        args = args[2:]
    if args and args[-1].endswith(".bin"):
        blob = args.pop()
    b = Blob(blob, base)
    print(f"blob {blob}: {b.n:#x} bytes, base {base:#x}, "
          f"call-tgts {len(b.targets)}, pairs {len(b.pairs)}")
    if args and args[0] == "chain":
        chain(b, int(args[1], 16))
        return
    crypto(b)
    tables(b)
    regids(b)
    strings(b)


if __name__ == "__main__":
    main()
