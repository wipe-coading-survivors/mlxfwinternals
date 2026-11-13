#!/usr/bin/env python3
"""K512/H512 imm-квадруплет-скан MAIN_CODE CX-6 (порт secfw/kscan512.py).

Отличие от CX-5-прецедента: окно НЕ фиксируется (layout CX-6 неизвестен),
сканируется весь блоб. Квадруплет = 4 подряд set*-слова с imm
lo16→hi16 константы. Запуск из корня репо:

  python3 scripts/cx6secfw/kscan512.py [blob]

Ожидаемый результат на 22.50.1002 — 0 квадруплетов: K512/H512 на CX-6
лежат таблицами данных (dc 0x565930/0x565bb0, см. anchor_scan.py crypto),
imm-материализация CX-5 (customIV transform) не используется.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOB = sys.argv[1] if len(sys.argv) > 1 else "build/cx6dx-main03-dc.bin"
data = open(BLOB, "rb").read()
K512 = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92F6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5A19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4CBCB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
]
H512 = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
]

imm_at = {}
for off in range(0, len(data) - 3, 4):
    s = disasm(int.from_bytes(data[off:off + 4], "big"), off)
    if s.startswith("set"):
        try:
            imm_at[off] = int(s.split(",")[-1], 16) & 0xffff
        except ValueError:
            pass
found = {}
for table, tname in ((K512, "K512"), (H512, "H512")):
    for i, k in enumerate(table):
        q = [k & 0xffff, (k >> 16) & 0xffff, (k >> 32) & 0xffff, (k >> 48) & 0xffff]
        for a in [a for a, v in imm_at.items() if v == q[0]]:
            if imm_at.get(a + 4) == q[1] and imm_at.get(a + 8) == q[2] \
                    and imm_at.get(a + 12) == q[3]:
                found.setdefault(tname, {})[i] = a
                break
for tname, table in (("K512", K512), ("H512", H512)):
    f = found.get(tname, {})
    hit = sorted(f)
    print(f"{tname} imm-quadruples: {len(hit)}/{len(table)}")
    if hit:
        addrs = sorted(f.values())
        print(f"  idx range: {hit[0]}..{hit[-1]}; build range: "
              f"{addrs[0]:#x}..{addrs[-1]:#x}")
        miss = [i for i in range(len(table)) if i not in f]
        print("  missing idx:", miss)
