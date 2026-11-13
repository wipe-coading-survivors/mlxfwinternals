#!/usr/bin/env python3
"""SHA-констант-якорь скан RE-базы CX-6 (порт probes/sha_anchor_scan.py).

Прецедент работает с образом (mlxfwutil-разбор секции); порт принимает готовый
de-framed dc-блоб (build/cx6dx-main03-dc.bin из extract_main03.py) — офсеты
печатаются в dc-пространстве, движок серий (BE/LE, ≥4 подряд) реюзится из
probes-движка без изменений. Запуск из корня репо:

  python3 scripts/cx6secfw/sha_anchor_scan.py [blob]
"""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
spec = importlib.util.spec_from_file_location(
    "probes_sha_anchor_scan", REPO / "scripts" / "probes" / "sha_anchor_scan.py")
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

BLOB = sys.argv[1] if len(sys.argv) > 1 else "build/cx6dx-main03-dc.bin"
data = open(BLOB, "rb").read()
print(f"{BLOB}: {len(data):#x} bytes (dc-space)")
runs = mod.scan_runs(data)
if not runs:
    print("  no SHA constant anchors")
    sys.exit(0)
for r in runs:
    print(f"  dc 0x{r.offset:06x}  {r.algo:<8} {r.endian}  "
          f"0x{r.constant:0{mod.TABLES[r.algo][0] * 2}x}  x{r.length}")
