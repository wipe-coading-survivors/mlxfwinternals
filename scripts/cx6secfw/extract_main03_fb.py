#!/usr/bin/env python3
"""Извлечение MAIN_CODE 0x03 (cl=1, clcrc-дефрейминг) из FB-бэкапа CX-6 Dx.

RE-база цикла cx6dx-introspection (task-02): FB — заводской бэкап
ri (32 MiB FS4, ITOC@0x5000), MAIN_CODE 22.32-эры. Отличается от
refs-VDA-базы extract_main03.py только входом/выходом; калибровка
rt = dc + 0x20800000 (param0 FB ≠ 0x21000000 VDA — своя для каждой
базы, rt_calib.py). Отдельный скрипт (не правка VDA-прецедента) —
канон «один закоммиченный entry-point на RE-базу» (secfw/cx6secfw).
Гейты: len(dc) % 4 == 0, clcrc-ошибок 0, md5 в журнал.

Запуск из корня репо:

  python3 scripts/cx6secfw/extract_main03_fb.py [image] [out]
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

SRC = "refs/fw/cx-5-6/FB-BKP/fb/MCX623435MC-CDAE_FB_Ax-ocr-ri.bin"
DST = "build/fb-main03-dc.bin"


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else SRC
    dst = sys.argv[2] if len(sys.argv) > 2 else DST
    buf = open(src, "rb").read()
    img = mlxfwutil.Image(buf, src)
    e = img.find_entry("ITOC", 0x03)
    raw = img.section_data(e)
    errs = mlxfwutil.clcrc_lines_errors(raw)
    print(f"{src}")
    print(f"  len={len(buf):#x} fmt={img.fmt} itoc_off={img.itoc_off:#x}")
    print(f"  MAIN_CODE: size={e.size:#x} flash={img.sec_abs(e):#x} "
          f"cl={e.clcrc} param0={e.param0:#x} param1={e.param1:#x}")
    print(f"  clcrc errors: {len(errs)} / {e.size // 68} lines")
    dc, tail = mlxfwutil.clcrc_unwrap(raw) if e.clcrc else (raw, b"")
    assert len(dc) % 4 == 0, f"dc not word-aligned: {len(dc):#x}"
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    open(dst, "wb").write(dc)
    print(f"  dc={len(dc):#x} tail={len(tail)} md5={hashlib.md5(dc).hexdigest()}")
    print(f"  wrote {dst}")
    if len(errs):
        sys.exit(1)


if __name__ == "__main__":
    main()
