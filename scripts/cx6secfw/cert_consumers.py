#!/usr/bin/env python3
"""Поиск консюмеров cert-секций + X.509-якорей в MAIN_CODE CX-6 (task-03).

Кодифицирует сканы Step 1 задачи 3 цикла cx6dx-introspection: кто читает
DTOC cert-области / вольты (по адресам и по типам секций), есть ли
X.509/DER-парсер-якоря, и карта коллеров крипто-кластера (chain-walk).
Секции скана:

- imm: addi/addi.hi- и set2/set3-пары, собирающие константу из cert/vault
  флеш-диапазонов (адреса cert-секций refs-VDA из Task 1 + ITOC-адреса
  вольтов 0xA1/0xA4/0xA6), + сырые u32-слова в данных;
- sectype: call-сайты к TOC-примитивам чтения/запроса секций — какой
  тип секции грузится рядом (интерес: DTOC cert-класс 0xd0/0xeb..0xf7);
- der: DER DigestInfo + X.509-OID/DER-length маркеры в блобе;
- chain: коллеры крипто-кластера (rsa_verify_wrap и корней) с
  функциями-контейнерами (для boot-vs-runtime классификации).

Запуск из корня репо:

  python3 scripts/cx6secfw/cert_consumers.py [--base 0x21000000] [blob]
  python3 scripts/cx6secfw/cert_consumers.py --chain <dc-hex> [...] [blob]
  python3 scripts/cx6secfw/cert_consumers.py --prims <dc>,<dc>,... [blob]

FB-кросс-чек (база 0x20800000): --prims 0x1a2f68,0x19e4f8 --base 0x20800000
build/fb-main03-dc.bin (аналоги слот-ридера/find_itoc из journal task-02).
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

# cert-области refs-VDA (Task 1, flash-адреса): (имя, lo, hi)
CERT_AREAS = [
    ("0xd0_unnamed", 0xF80000, 0xFC0000),
    ("0xf6_root_certs1", 0xFC0000, 0xFD0000),
    ("0xf7_root_certs2", 0xFD0000, 0xFE0000),
    ("0xf4_chains1", 0xFE0000, 0xFF0000),
    ("0xf5_chains2", 0xFF0000, 0x1000000),
    ("0xeb_prog_hw1", 0x1FA0000, 0x1FC0000),
    ("0xec_prog_hw2", 0x1FC0000, 0x1FE0000),
    ("0xee_dig_cert_rw", 0x1FE0000, 0x1FEE000),
    ("0xf3_dig_cert_cacert", 0x1FEE000, 0x1FF2000),
    ("0xf2_cert_chain0", 0x1FF2000, 0x1FF4000),
    ("0xed_dig_cert_ptr", 0x1FF4000, 0x1FF4028),
]
# ключевые точки: точные адреса (подслоты 0xee + 0xed + база 0xd0)
CERT_POINTS = sorted({0x1FF4000, 0x1FF2000, 0x1FEE000, 0xF80000}
                     | {0x1FE0000 + i * 0x2000 for i in range(8)})
# вольты refs-VDA (ITOC: тип -> flash addr/size)
VAULTS = {0xA1: (0x6B2700, 0x900), 0xA4: (0x6B3380, 0x1100),
          0xA6: (0x6B4480, 0x1100), 0xA7: (0x6B5580, 0x600)}
# DTOC cert-класс: типы, потребление которых ищем у TOC-примитивов
CERT_TYPES = {0xD0, 0xEB, 0xEC, 0xED, 0xEE, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7}
# TOC-примитивы чтения/запроса секций (VDA; тип-аргумент ищем в ближайших
# словах перед call) — ридер вольта 0x3fe600 грузит тип в r8
SECTION_PRIMS = (0x37C0BC, 0x37C14C, 0x37C5DC, 0x37C904, 0x167F70,
                 0x24DA14, 0x24D154, 0x3FE600, 0x3FBaf0)
# X.509/DER-маркеры (данные): OID + DER-length-идиомы + DigestInfo
DER_MARKERS = {
    "digestinfo_sha256": bytes.fromhex("3031300d0609608648016503040201"),
    "digestinfo_sha512": bytes.fromhex("3051300d0609608648016503040203"),
    "oid_rsa_enc": bytes.fromhex("06092a864886f70d010101"),
    "oid_sha256_rsa": bytes.fromhex("06092a864886f70d01010b"),
    "oid_sha384_rsa": bytes.fromhex("06092a864886f70d01010c"),
    "oid_sha512_rsa": bytes.fromhex("06092a864886f70d01010d"),
    "oid_cn": bytes.fromhex("0603550403"),
    "oid_org": bytes.fromhex("060355040a"),
    "oid_country": bytes.fromhex("0603550406"),
    "oid_basic_constraints": bytes.fromhex("0603551d13"),
    "oid_key_usage": bytes.fromhex("0603551d0f"),
    "oid_ext_key_usage": bytes.fromhex("0603551d25"),
    "oid_auth_key_id": bytes.fromhex("0603551d23"),
    "oid_subj_key_id": bytes.fromhex("0603551d0e"),
    "oid_cert_policies": bytes.fromhex("0603551d20"),
    "oid_ecdsa_eccpub": bytes.fromhex("06072a8648ce3d0201"),
    "oid_ecdsa_sha256": bytes.fromhex("06082a8648ce3d040302"),
    "oid_ed25519": bytes.fromhex("0605030202060301"),
    "der_long_len_seq": bytes.fromhex("3082"),
    "der_oid_hdr9": bytes.fromhex("0609"),
}


def in_area(v):
    return next((n for n, lo, hi in CERT_AREAS if lo <= v < hi), None)


def vault_of(v):
    return next((t for t, (va, vs) in VAULTS.items() if va <= v < va + vs),
                None)


class Blob:
    def __init__(self, path, base):
        self.data = open(path, "rb").read()
        self.base = base
        self.n = len(self.data)

    def w(self, o):
        return int.from_bytes(self.data[o:o + 4], "big")

    def fstart(self, site):
        o = site & ~3
        while o > 4 and self.w(o) != PROLOGUE:
            o -= 4
        return o

    def call_index(self):
        callers = defaultdict(list)
        pat = re.compile(r"^call 0x([0-9a-f]+)$")
        for o in range(0, self.n - 3, 4):
            ww = self.w(o)
            if (ww >> 26) & 0x3F != 0x25:
                continue
            m = pat.match(disasm(ww, o))
            if m:
                callers[int(m.group(1), 16)].append(o)
        return callers

    def imm_pairs(self):
        """сайты addi lo + addi.hi (k=1..3) -> {site: value32}."""
        out = {}
        for o in range(0, self.n - 8, 4):
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
                out[o] = (((wp & 0xFFFF) << 16) + s16(lo)) & 0xFFFFFFFF
                break
        return out

    def set23_pairs(self):
        """Пары set2 rd,rs,hi + set3 rX,rd,lo (k=1..4) -> {site: value32}.

        Идиома (прецеденты cx6dx-main03 0x167664, 0x2b5a3c):
        set2 пишет биты 31..16 в rd, затем set3 с ИСТОЧНИКОМ rd
        дорисовывает биты 15..0 (dest set3 — любой, чаще тот же rd).
        """
        out = {}
        for o in range(0, self.n - 16, 4):
            s = disasm(self.w(o), o)
            if not s.startswith("set2 "):
                continue
            parts = [p.strip() for p in s.split(",")]
            if len(parts) != 3:
                continue
            rd = parts[0][len("set2 "):].strip()
            hi16 = int(parts[2], 16)
            for k in range(1, 5):
                sp = disasm(self.w(o + 4 * k), o + 4 * k)
                if not sp.startswith("set3 "):
                    continue
                pp = [p.strip() for p in sp.split(",")]
                if len(pp) == 3 and pp[1] == rd:
                    out[o] = ((hi16 << 16) | (int(pp[2], 16) & 0xFFFF))
                    break
        return out


def _classify(b, val):
    a = in_area(val) or in_area(val - b.base)
    if a:
        return a
    if any(val == p or val - b.base == p for p in CERT_POINTS):
        return "cert-point"
    vt = vault_of(val)
    if vt is not None:
        return "vault %#x" % vt
    return None


def scan_imm(b):
    print("== imm: константы cert/vault-диапазонов в коде ==")
    idioms = (("addi", b.imm_pairs()), ("set2/3", b.set23_pairs()))
    for name, pairs in idioms:
        print(f"  {name}-пар всего: {len(pairs)}")
    hits = defaultdict(list)
    for name, pairs in idioms:
        for site, val in sorted(pairs.items()):
            why = _classify(b, val)
            if why:
                hits[val].append((name, site, why))
    for val in sorted(hits):
        for name, site, why in hits[val]:
            print(f"  {name:7s} site {site:#x} -> {val:#x} ({why}) "
                  f"func {b.fstart(site):#x}")
        print(f"    = значение {val:#x}: {len(hits[val])} сайтов")
    print(f"  итого значений в cert/vault-диапазонах: {len(hits)}, "
          f"сайтов: {sum(len(v) for v in hits.values())}")
    print("== raw u32: cert/vault-адреса словами данных ==")
    dh = 0
    for o in range(0, b.n - 3, 4):
        v = b.w(o)
        a = in_area(v)
        vt = next((t for t, (va, vs) in VAULTS.items()
                   if va <= v < va + vs), None)
        if a or vt is not None:
            print(f"  data {o:#08x} = {v:#x}"
                  f"{' (' + a + ')' if a else ''}"
                  f"{' (vault %#x)' % vt if vt is not None else ''}")
            dh += 1
    print(f"  итого data-хитов: {dh}")


def scan_sectype(b, prims):
    print("== sectype: типы секций у TOC-примитивов ==")
    callers = b.call_index()
    imm_load = re.compile(r"^(addi|subsi) (\w+),\w+,0x([0-9a-f-]+)$")
    hits = defaultdict(list)
    for prim in prims:
        for site in callers.get(prim, []):
            for back in range(1, 11):
                s = disasm(b.w(site - 4 * back), site - 4 * back)
                m = imm_load.match(s)
                if not m:
                    continue
                v = int(m.group(3), 16) & 0xFFFF
                if v in CERT_TYPES or v in VAULTS:
                    hits[prim].append((site, back, v))
    if not hits:
        print("  сертификационных типов (0xd0/0xeb..0xf7) у примитивов НЕТ")
    for prim in sorted(hits):
        for site, back, v in hits[prim]:
            name = (f"vault {v:#x}" if v in VAULTS else f"CERT {v:#x}")
            print(f"  prim {prim:#x} <- call@{site:#x}: {name} "
                  f"(imm @{site - 4 * back:#x}) func {b.fstart(site):#x}")
    # свод по всем типам у примитивов (перепроверка полноты)
    per = defaultdict(set)
    for prim in prims:
        for site in callers.get(prim, []):
            for back in range(1, 11):
                s = disasm(b.w(site - 4 * back), site - 4 * back)
                m = imm_load.match(s)
                if m:
                    per[prim].add(int(m.group(3), 16) & 0xFFFF)
    for prim in sorted(per):
        print(f"  типы у {prim:#x}: {sorted(hex(x) for x in per[prim])}")


def scan_der(b):
    print("== der: X.509/DER-маркеры в блобе ==")
    for name, pat in DER_MARKERS.items():
        cnt = b.data.count(pat)
        first = b.data.find(pat)
        note = f", first dc {first:#x}" if cnt else ""
        print(f"  {name}: {cnt}{note}")


def scan_chain(b, roots):
    callers = b.call_index()
    for r in roots:
        print(f"== chain: коллеры {r:#x} ==")
        sites = callers.get(r, [])
        print(f"  call-сайтов: {len(sites)}")
        for s in sites:
            print(f"  site {s:#x} func {b.fstart(s):#x}")


def main():
    args = sys.argv[1:]
    roots = []
    prims = list(SECTION_PRIMS)
    if args and args[0] == "--chain":
        args = args[1:]
        while args and not args[0].startswith("--") \
                and not args[0].endswith(".bin"):
            roots.append(int(args[0], 16))
            args = args[1:]
    if args and args[0] == "--prims":
        prims = [int(a, 16) for a in args[1].split(",")]
        args = args[2:]
    blob, base = BLOB, BASE
    if args and args[0] == "--base":
        base = int(args[1], 0)
        args = args[2:]
    if args and args[-1].endswith(".bin"):
        blob = args.pop()
    b = Blob(blob, base)
    print(f"blob {blob}: {b.n:#x} B, base {base:#x}")
    if roots:
        scan_chain(b, roots)
        return
    scan_imm(b)
    scan_sectype(b, prims)
    scan_der(b)


if __name__ == "__main__":
    main()
