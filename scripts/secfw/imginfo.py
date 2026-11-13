#!/usr/bin/env python3
"""IMAGE_INFO (ITOC 0x10) dword0 трёх опорных образов — secure-биты.

Воспроизводит таблицу журнала task-03 §4.2: бегущий/refs-8008-HPE =
0x0003d9e0 (0x4000 SET, 0x8000 SET), 4030-CDA = 0x00030160 (оба clr).
Запуск из корня репо:

  python3 scripts/secfw/imginfo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

for src in [
    "build/hpe-872726-8008-gen4-56g-vpi-devid1019.bin",
    "refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-872726-B21_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.signed.bin",
    "refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_4030-MCX516A-CDA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin",
]:
    buf = open(src, "rb").read()
    img = mlxfwutil.Image(buf, src)
    e = img.find_entry("ITOC", 0x10)
    if e is None:
        print(f"{src}: no IMAGE_INFO"); continue
    data = img.section_data(e)
    d0 = int.from_bytes(data[0:4], "big")
    print(f"{src.split('/')[-1]}")
    print(f"  IMAGE_INFO dword0 = {d0:#010x}  bits: 0x4000={'SET' if d0 & 0x4000 else 'clr'} "
          f"0x8000={'SET' if d0 & 0x8000 else 'clr'} 0x20000000={'SET' if d0 & 0x20000000 else 'clr'}")
    print(f"  raw[0:16] = {data[:16].hex()}")
