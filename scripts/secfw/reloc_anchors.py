#!/usr/bin/env python3
"""Релокация якорей burn-digest 4030 → 8008-RE-база поиском нормализованных
окон (W=8 слов) в полном дизасме.

Воспроизводит колонки таблицы якорей журнала task-03 §1 (первичный проход;
мультихиты листовых хелперов с одинаковыми прологами разрешаются кластерным
сдвигом и/или длинными окнами — reloc_anchors_long.py). Запуск из корня репо:

  python3 scripts/secfw/reloc_anchors.py [8008.dis] [4030.dis] [anchors.json]
"""
import sys
import json

DIS_A = sys.argv[1] if len(sys.argv) > 1 else "/tmp/opencode/t3/8008.dis"
DIS_B = sys.argv[2] if len(sys.argv) > 2 else "/tmp/opencode/t3/4030.dis"
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/opencode/t3/anchors.json"

def load(p):
    lines = open(p).read().splitlines()
    off, txt = [], []
    for ln in lines:
        a, _, c = ln.split(" ", 2)
        off.append(int(a, 16)); txt.append(c)
    return off, txt

oa, ta = load(DIS_A)
ob, tb = load(DIS_B)
off2idx_b = {o: i for i, o in enumerate(ob)}
off2idx_a = {o: i for i, o in enumerate(oa)}

ANCH = [
    ("digest_compare", 0x1d29f4), ("rsa_verify_full", 0x1d27b8),
    ("rsa_exit/jump", 0x1d2c0c), ("plain_memcmp_call", 0x1d2c20),
    ("plain_match_branch", 0x1d2c48), ("read_itoc", 0x1d7338),
    ("hash_init_both", 0x1d2ca4), ("digest_loop", 0x1d2574),
    ("digest_compute_both", 0x1d2cf4), ("digest_verify_driver", 0x1d2dc8),
    ("verify_image", 0x1d4744), ("fw_burn_fsm", 0x1d5458),
    ("state4_download", 0x1d5a90), ("state5_verify", 0x1d5ad4),
    ("state84_send_vstat", 0x1d5cd0), ("customiv_init", 0x2b2128),
    ("customiv_update", 0x2b2204), ("customiv_final", 0x2b2318),
    ("sha256_init", 0x2b16f0), ("sha256_update", 0x2b131c),
    ("sha256_final", 0x2b15d4), ("sha256_transform", 0x2b13b0),
    ("ini_chk_secure_0x4000", 0x1cf910), ("ini_chk_mode_0x8000", 0x1cfa5c),
    ("initialize_verify_params", 0x1d223c), ("verify_params_lookup", 0x1d2124),
    ("itoc_scan", 0x1957c), ("itoc_entry_search", 0x107bd8),
    ("ini_row_digest_tol", 0x1cf668), ("ini_row_present_enum", 0x1cf418),
    ("ini_enum", 0x1cf1ec), ("patch_gate_ini", 0x1cf74c),
    ("memcmp", 0x2add34), ("ini_row_c2", 0x1cf68c),
    ("rsa_branch_call_site", 0x1d2be0), ("rsa_select_alu39", 0x1d2bd0),
    ("get_master_action", 0x18f74), ("set_master_action", 0x18f80),
    ("get_flash_base", 0x18cb4), ("get_verify_len", 0x18eb8),
    ("flag_bit8", 0x18d34), ("flag_bit9", 0x18d40), ("flag_bit10", 0x18d4c),
    ("set_zoneA_start", 0x19040), ("set_zoneB_start", 0x18e34),
    ("set_zoneC_start", 0x19024), ("set_bit8_or", 0x18d58),
]

W = 8  # window words
out = {}
for name, a4030 in ANCH:
    i4030 = off2idx_b.get(a4030)
    if i4030 is None:
        # align down
        a4030 &= ~3
        i4030 = off2idx_b.get(a4030)
    win = tb[i4030:i4030 + W]
    hits = []
    for i in range(0, len(ta) - W + 1):
        if ta[i:i + W] == win:
            hits.append(oa[i])
    out[name] = (a4030, hits)
    hs = ", ".join(f"{h:#x}" for h in hits) if hits else "NO MATCH"
    print(f"{name:26s} 4030:{a4030:#09x} -> 8008: {hs}")
json.dump({k: v for k, v in out.items()}, open(OUT, "w"))
