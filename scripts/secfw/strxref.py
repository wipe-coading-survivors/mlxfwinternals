#!/usr/bin/env python3
"""Поиск call-сайтов по адресу trace-строки (addi/addi.hi-пара) в MAIN_CODE.

Используется журналом task-05 для привязки строк-якорей («fw_burn_fsm»,
«read_data_from_partition» и т.п.) к коду: строка лежит в блобе по dc-адресу
S, rt-адрес = S + 0x800000; типичная загрузка — addi rX,zero,lo16 (lo16 как
знаковое от rt) + addi.hi rX,rX,hi. Запуск из корня репо:

  python3 scripts/secfw/strxref.py <dc-hex>...
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOB = "build/secfw-main03-dc.bin"


def main():
    data = open(BLOB, "rb").read()
    targets = [int(a, 16) + 0x800000 for a in sys.argv[1:]]
    words = [(off, int.from_bytes(data[off:off + 4], "big"))
             for off in range(0, len(data) - 3, 4)]
    for off, w in words:
        s = disasm(w, off)
        if s.startswith("addi ") and "zero" in s:
            try:
                imm_s = s.split("imm=")[-1].split(" ")[0] if "imm=" in s \
                    else s.split(",")[-1].strip()
                neg = imm_s.startswith("0x-")
                imm = int(imm_s.replace("0x-", "0x"), 16)
                if neg:
                    imm -= 1 << 16
            except ValueError:
                continue
            for t in targets:
                if (t - (imm & 0xffff)) & 0xffff0000 == (t & 0xffff0000) \
                        and (imm & 0xffff) == (t & 0xffff) ^ (1 << 15) or \
                        (imm & 0xffff) == (t & 0xffff):
                    nxt = disasm(words[[o for o, _ in words].index(off) + 1][1], off + 4)
                    if nxt.startswith("addi.hi") and hex(t >> 16)[2:] in nxt:
                        print("%08x  %s   ; str dc %#x" % (off, s, t - 0x800000))
                        print("%08x  %s" % (off + 4, nxt))


if __name__ == "__main__":
    main()
