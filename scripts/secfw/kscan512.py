#!/usr/bin/env python3
"""Скан K512-констант customIV-transform (0x2b1f84) как imm-квадруплетов
set3/set2/set1/set0 в прологе.

Воспроизводит числа журнала task-03 §3.1 (с правкой по ревью): точных
FIPS-квадруплей 77/80; индексы 20/51/76 НЕ собирают FIPS-значение — на своих
слотах кадра (K[i] @ frame+0x8+i*8: [20]→+0xa8, [51]→+0x1a0, [76]→+0x268)
стоят девиантные полуслова (см. журнал). Запуск из корня репо:

  python3 scripts/secfw/kscan512.py [blob] [k512.json]

(blob по умолчанию build/secfw-main03-dc.bin — 8008-RE-база; для 4030
передайте путь выгрузки extract_main03.py и скорректируйте границы lo/hi
под 4030-трансформ ~0x2b17f0..0x2b2128).
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOB = sys.argv[1] if len(sys.argv) > 1 else "build/secfw-main03-dc.bin"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/opencode/t3/k512.json"
data = open(BLOB, "rb").read()
K512 = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92F6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5A19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4CBCB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
]
lo, hi = 0x2b1f84, 0x2b2900
imm_at = {}
for off in range(lo, hi, 4):
    w = int.from_bytes(data[off:off+4], "big")
    s = disasm(w, off)
    if s.startswith("set"):
        try:
            imm_at[off] = int(s.split(",")[-1], 16) & 0xffff
        except ValueError:
            pass
found = {}
for i, k in enumerate(K512):
    q = [k & 0xffff, (k >> 16) & 0xffff, (k >> 32) & 0xffff, (k >> 48) & 0xffff]
    for a in [a for a, v in imm_at.items() if v == q[0]]:
        if imm_at.get(a+4) == q[1] and imm_at.get(a+8) == q[2] and imm_at.get(a+12) == q[3]:
            found[i] = a
            break
hit = sorted(found)
print(f"K512 imm-quadruples: {len(hit)}/80")
miss = [i for i in range(80) if i not in found]
print("missing idx:", miss)
addrs = sorted(found.values())
print(f"build range: {addrs[0]:#x}..{addrs[-1]:#x}" if addrs else "-")
json.dump({str(k): v for k, v in found.items()}, open(OUT, "w"))
