#!/usr/bin/env python3
"""Раскрытие EM/DigestInfo вендорской 0xA3-подписи + НЕВЕРНАЯ маска-питфолл.

Роль (журнал task-03 §3.3/§3.4): доказывает структуру EM = 00 01 FF..(428) 00
|| DER-заголовок DigestInfo(SHA-512) || хеш-64B и извлекает встроенный хеш
(= целевой паритет-хеш 3e8a8944…bc8266). ВНИМАНИЕ — питфолл: маски-кандидаты
в этом скрипте кладут маску ITOC-entry по «addr−0x20» (ЗАПИСИ ЛЕЖАТ В
ТАБЛИЦЕ ITOC, а не перед данными!) — все кандидаты match=False; «full-mask»
даёт устаревший хеш a8d09060…de0e, ошибочно попавший в первую редакцию
журнала. Правильная маска — parity_gate.py. Запуск из корня репо:

  python3 scripts/secfw/parity_em_pitfall.py
"""
import sys
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

IMG = "refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin"
buf = open(IMG, "rb").read()
img = mlxfwutil.Image(buf, IMG)
ea0, ea3, ea4 = (img.find_entry("ITOC", t) for t in (0xA0, 0xA3, 0xA4))
entries = img.entries("ITOC")
tot = max((e.addr + e.size) for e in entries if e.type != 0xFF)
a4, a3 = img.section_data(ea4), img.section_data(ea3)
key0, exp0 = a4[0x20:0x220], int.from_bytes(a4[0xc:0x10], "big")
sig = a3[0x20:0x220]
n = int.from_bytes(key0, "big")
EM = pow(int.from_bytes(sig, "big"), exp0, n).to_bytes(512, "big")
T = EM[429:]
print("EM T-hex:", T[:19].hex(), "||", T[19:].hex())
print("DI hdr ok:", T[:18].hex(), "== 3051300d0609608648016503040203050004:", T[:18] == bytes.fromhex("3051300d0609608648016503040203050004"))
sig_hash = T[19:]
print("sig-embedded SHA512:", sig_hash.hex())

# candidate Ms
def mk(mask_a0=True, mask_a3=True, mask_magic=True, tail=tot, mask_entrycrc=False):
    M = bytearray(buf[:tail])
    if mask_magic: M[0:0x10] = b"\xff"*0x10
    if mask_a0:
        M[ea0.addr-0x20:ea0.addr-0x20+0x20] = b"\xff"*0x20
        M[ea0.addr:ea0.addr+ea0.size] = b"\xff"*ea0.size
    if mask_a3:
        M[ea3.addr-0x20:ea3.addr-0x20+0x20] = b"\xff"*0x20
        M[ea3.addr:ea3.addr+ea3.size] = b"\xff"*ea3.size
    return bytes(M)

import itertools
cands = {}
cands["full-mask"] = mk()
cands["no-magic-mask"] = mk(mask_magic=False)
cands["no-a0"] = mk(mask_a0=False)
cands["no-a3"] = mk(mask_a3=False)
cands["raw"] = buf[:tot]
for name, m in cands.items():
    h = hashlib.sha512(m).hexdigest()
    print(f"{name:15s} match={h == sig_hash.hex()}  {h[:32]}...")
