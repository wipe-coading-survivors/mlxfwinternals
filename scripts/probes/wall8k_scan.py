#!/usr/bin/env python3
"""8008 wall retest probe: clcrc deframe, addi+addi.hi pair scan, string/site map.

Reproduce: python3 scripts/probes/wall8k_scan.py [<image.bin>] [--out-dir build]
Default image = 8008-ACA (refs/fw/cx-5-6). Outputs: 8008_main03_dc.bin,
8008_site_map.json (out dir). Journal: docs/superpowers/journal/2026-10-15-8008-wall-retest.md
"""
import argparse
import collections
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "irisc"))
import mlxfwutil  # noqa: E402
from irisc_dis import s16  # noqa: E402

DEFAULT_IMG = "refs/fw/cx-5-6/fw-ConnectX5-rel-16_35_8008-MCX512A-ACA_Ax_Bx-UEFI-14.29.15-FlexBoot-3.6.902.bin"


def deframe(raw: bytes) -> bytes:
    out = bytearray()
    nl = len(raw) // 68
    for i in range(nl):
        out += raw[i * 68:i * 68 + 64]
    r = len(raw) - nl * 68
    out += raw[nl * 68:nl * 68 + min(r, 64)]
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image", nargs="?", default=DEFAULT_IMG)
    ap.add_argument("--out-dir", default="build")
    args = ap.parse_args()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    buf = open(args.image, "rb").read()
    im = mlxfwutil.Image(buf, args.image)
    e = im.find_entry("ITOC", 0x03)
    raw = im.section_data(e)
    print(f"MAIN_CODE size={e.size:#x} flash_addr={im.sec_abs(e):#x} cl={e.clcrc} "
          f"param0={e.param0:#x} param1={e.param1:#x}")
    errs = mlxfwutil.clcrc_lines_errors(raw)
    print(f"clcrc line errors: {len(errs)} / {e.size // 68} lines")

    dc = deframe(raw)
    print(f"dc blob len={len(dc):#x}")
    (out / "8008_main03_dc.bin").write_bytes(dc)

    l0 = raw[:68]
    print(f"line0[64:68]={l0[64:68].hex()} "
          f"crc16(line[:66])={mlxfwutil.clcrc_calc(l0[:66]):#x} "
          f"exp(le@66)={int.from_bytes(l0[66:68], 'little'):#x}")

    STR_RE = re.compile(rb"[ -~]{5,}")
    strs = [(m.start(), m.group().decode()) for m in STR_RE.finditer(dc)]
    starts = set(s for s, _ in strs)
    print(f"printable strings >=5: {len(strs)}")

    n = len(dc)
    w = lambda o: int.from_bytes(dc[o:o + 4], "big")
    pairs = []
    for o in range(0, n - 4, 4):
        ww = w(o)
        op = (ww >> 26) & 0x3F
        if op not in (0x00, 0x01):
            continue
        rd = (ww >> 16) & 0x1F
        rs_lo = (ww >> 21) & 0x1F
        lo = ww & 0xFFFF
        for k in range(1, 4):
            j = o + 4 * k
            if j + 4 > n:
                break
            wp = w(j)
            hop = (wp >> 26) & 0x3F
            if hop not in (0x02, 0x03):
                continue
            if ((wp >> 21) & 0x1F) != rd:
                continue
            hi = wp & 0xFFFF
            val = ((hi << 16) + s16(lo)) & 0xFFFFFFFF
            pairs.append((o, j, rd, rs_lo, (wp >> 16) & 0x1F, hi, lo, val))
            break
    print(f"pairs total: {len(pairs)} (rs_lo==0: {sum(1 for p in pairs if p[3] == 0)})")

    in_range = [p for p in pairs if 0x800000 <= p[7] < 0x800000 + len(dc)]
    exact = [p for p in pairs if p[7] - 0x800000 in starts]
    print(f"pairs -> [0x800000, 0x{0x800000 + len(dc):x}): {len(in_range)}")
    print(f"pairs -> exact string start (val-0x800000 in starts): {len(exact)}")
    hi_hist = collections.Counter(p[7] >> 16 for p in pairs)
    print("hi16 histogram (top 12):", [(hex(h), c) for h, c in hi_hist.most_common(12)])

    def find_str(sub):
        return [(s, t) for s, t in strs if sub in t]

    targets = [
        "High BER detected on module",
        "FDR10 speed is not supported",
        "Cable speed not enabled",
        "No issue was observed",
        "cable does not support any Infiniband speeds",
        "speed_enabled.ib=0x%x",
        "speed_and_width (PTYS)",
        "Module memory invalid",
        "ib_speed_nego_fsm",
        "ib_speed_nego",
        "set_pm_speed_and_width",
        "hal_set_ib_speed_and_width",
        "hal_get_ib_speed_and_width",
        "set_phy_properties",
        "apply_stamping",
        "stamping",
        "module_management_init_sm",
        "cable_module_read_write",
        "vs_diagnostic_page_num_to_pddr_page_select",
        "set_get_port_info",
        "pddr_page_size_in_bytes",
        "phy_manager_set_next_state",
        "open_pport",
    ]
    site_map = {}
    for t in targets:
        hits = find_str(t)
        print(f"\n### {t!r}: {len(hits)} hits")
        for s, txt in hits[:8]:
            print(f"  dc {s:#x}: {txt[:70]!r}")
            sites = [(o, val) for o, j, rd, rslo, rdh, hi, lo, val in pairs if val == 0x800000 + s]
            if sites:
                site_map[txt[:60]] = {"dc": s, "sites": [hex(o) for o, v in sites]}
                print(f"    pair-sites: {[hex(o) for o, v in sites]}")
    json.dump(site_map, open(out / "8008_site_map.json", "w"), indent=1)
    print(f"\nwrote {out / '8008_site_map.json'}")


if __name__ == "__main__":
    main()
