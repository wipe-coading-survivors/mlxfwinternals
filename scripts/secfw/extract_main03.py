#!/usr/bin/env python3
"""Извлечение MAIN_CODE 0x03 (cl=1, clcrc-дефрейминг) для RE-базы и стока-4030.

Воспроизводит артефакты/числа журнала task-03 §0: размеры и md5 обоих
de-framed блобов (8008-RE-база → build/secfw-main03-dc.bin; сток-4030-CDA →
файл-эталон для кросс-карты §1). Запуск из корня репо:

  python3 scripts/secfw/extract_main03.py [out4030]

где out4030 — путь выгрузки сток-4030 (по умолчанию
/tmp/opencode/t3/cda4030-main03-dc.bin — как в сессии журнала; путь
параметризован, логика не менялась).
"""
import sys
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

pairs = [
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin",
     "build/secfw-main03-dc.bin"),
    ("refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin",
     sys.argv[1] if len(sys.argv) > 1 else "/tmp/opencode/t3/cda4030-main03-dc.bin"),
]
for src, dst in pairs:
    buf = open(src, "rb").read()
    img = mlxfwutil.Image(buf, src)
    e = img.find_entry("ITOC", 0x03)
    raw = img.section_data(e)
    dc, tail = mlxfwutil.clcrc_unwrap(raw) if e.clcrc else (raw, b"")
    open(dst, "wb").write(dc)
    print(f"{src}\n  clcrc={e.clcrc} raw={len(raw):#x} dc={len(dc):#x} tail={len(tail)} md5={hashlib.md5(dc).hexdigest()}")
