#!/usr/bin/env python3
"""inject_guids.py — совместимая обёртка над `mlxfwutil.py guides`.

Логика (GUID/MAC → mDevInfo + MFG_INFO, self-verify, пересчёт CRC) перенесена
в `mlxfwutil.py guides` (артефакт ROADMAP «один скрипт (subcommands)»). Файл
оставлен для совместимости с командами docs/750-exp/140-post-fnp-guid-desync. Интерфейс аргументов идентичен:

    python3 inject_guids.py <image.bin> --guid 0x… --mac 0x… [--out F]

Вход: FS4 `.bin` (16M) или raw flash dump 16M (детекция слота). Выход:
`<image>.inject` (или `--out`). Основание: docs/750-exp/140-post-fnp-guid-desync §8, docs/250-re/100-formats/035-fs4-hashes.md.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import mlxfwutil  # noqa: E402

if __name__ == "__main__":
    sys.exit(mlxfwutil.main(["guides"] + sys.argv[1:]))
