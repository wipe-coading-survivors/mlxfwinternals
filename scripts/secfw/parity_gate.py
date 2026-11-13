#!/usr/bin/env python3
"""РЕШАЮЩИЙ численный парити-гейт (журнал task-03 §3.4) — ВЕРДИКТ PARITY.

Проверяет вендорскую 0xA3-подпись pristine refs-8008 открытым ключом vault
slot0 (uuid c55d54e8 = 0xA3.keypair_uuid, e=0x10001) по КЛИЕНТСКОЙ формуле
SignForFwUpdate: M = image[0..sizeOfImgData), маска 0xFF = {magic16,
ITOC-entry(0xA0)+data, ITOC-entry(0xA3)+data} — записи ITOC лежат в ТАБЛИЦЕ
(itoc_off+0x20+idx*0x20), не «перед данными» (питфолл addr−0x20 — см.
parity_em_pitfall.py). Успех: SHA512(M) == хеш, встроенный в EM
(3e8a8944d7ca7ab2…e356bc8266) ⇒ формула подписчика == клиентская.
Негатив-контроли (снятие любой маски / 4MB cap) — match=False. Запуск из
корня репо:

  python3 scripts/secfw/parity_gate.py
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
tot = max(e.addr + e.size for e in entries)
a4, a3 = img.section_data(ea4), img.section_data(ea3)
key0, exp0 = a4[0x20:0x220], int.from_bytes(a4[0xc:0x10], "big")
sig = a3[0x20:0x220]
EM = pow(int.from_bytes(sig, "big"), exp0, int.from_bytes(key0, "big")).to_bytes(512, "big")
sig_hash = EM[429:][19:]
print("target SHA512:", sig_hash.hex())
print(f"itoc_off={img.itoc_off:#x} idx_a0={ea0.index} idx_a3={ea3.index}")

def entry_off(e):
    return img.itoc_off + 0x20 + e.index * 0x20

print(f"entry(0xA0) @ {entry_off(ea0):#x} magic-check: {buf[entry_off(ea0):entry_off(ea0)+4].hex()} type-byte={buf[entry_off(ea0)]}")
def mk(tail, mask_magic=True, mask_ea0=True, mask_da0=True, mask_ea3=True, mask_da3=True):
    M = bytearray(buf[:tail])
    if mask_magic: M[0:0x10] = b"\xff"*0x10
    if mask_ea0: M[entry_off(ea0):entry_off(ea0)+0x20] = b"\xff"*0x20
    if mask_da0: M[ea0.addr:ea0.addr+ea0.size] = b"\xff"*ea0.size
    if mask_ea3: M[entry_off(ea3):entry_off(ea3)+0x20] = b"\xff"*0x20
    if mask_da3: M[ea3.addr:ea3.addr+ea3.size] = b"\xff"*ea3.size
    return bytes(M)

tests = {
    "full-mask tot": (mk(tot), ),
    "4MB cap": (mk(0x400000), ),
    "no-magic": (mk(tot, mask_magic=False), ),
    "no-a0-at-all": (mk(tot, mask_ea0=False, mask_da0=False), ),
    "no-a3-at-all": (mk(tot, mask_ea3=False, mask_da3=False), ),
    "data-only-masks": (mk(tot, mask_ea0=False, mask_ea3=False), ),
}
for name, (m,) in tests.items():
    h = hashlib.sha512(m).hexdigest()
    print(f"{name:18s} len={len(m):#x} match={h == sig_hash.hex()}")
