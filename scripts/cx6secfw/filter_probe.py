#!/usr/bin/env python3
"""Статический анализ веток рег-фильтра MFPA/MFBA/MFBE на CX-6 Dx (task-04).

Восстанавливает маршрутизацию flash-регистров прямого транспорта
(MFPA 0x9010 / MFBA 0x9011 / MFBE 0x9012) по конвейеру access-register
FW 22.50.1002 (база build/cx6dx-main03-dc.bin, rt = dc + 0x21000000),
вычисляет членство в ACL-окне гейта 0x18e714 и верифицирует one-word
патч (dc 0x18e770), открывающий MFPA+MFBA при сохранении ACL-проверки
MFBE (спека цикла §4: MFBE/erase не открываем).

Слои (dc-адреса, декод scripts.irisc):

  check_and_exec_access_register 0x109084
      перехватывает {0x5012, 0x9052, 0x9014} (0x109188..0x1091ac);
      прочие -> call exec_access_register
  exec_access_register 0x107ea0 (строка-якорь dc 0x5380cd
      "exec_access_register: gvmi=..reg_id=..")
      compare-дерево + срез большой таблицы диспетчеризации:
      dc 0x549bb8 = bigtable(0x547f20)[1830 + (reg-0x9009)],
      reg-ids 0x9009..0x907f (диапазон-гейт 0x107f44..0x107f68)
  0x10826c -> call 0x105538 — ЕДИНСТВЕННЫЙ хендлер для MFPA/MFBA/MFBE
      (таблица: ровно 3 энтри -> 0x10826c; MCC-кластер 0x905c/0x9060-64
      -> 0x107f6c -> 0x105e14; default 0x108e7c)
  0x105538: классификация длин (MFPA 0x20 / MFBA (size&0x1ff)+0xc<=0x10c /
      MFBE 0xc), дескриптор, acl=0x168b28(ctx), mode=0x16b704(ctx),
      call гейт 0x18e714(reg_id, cmdhw, acl, mode) @0x10569c
  гейт 0x18e714, окно для reg<=0x902f (0x18e76c..0x18e77c):
      r9  = reg + sext32(imm16 @0x18e770)          # set3 r9,r9,0x6ff0
      subsi r9,r9,0x3  (RS=r9, RD=r9-3)
      fall -> 0x19290 (ACL)  <=>  RD != 0 && RS <=u 3
      иначе b.f.0x4 -> 0x18e790: {0x9024,0x9025}(write) -> 0x19a40,
      прочие -> exit-0 (разрешено)
      для reg>0x902f: {0x905c,0x9062,0x9063} -> 0x19d4c (mode/ACL);
      {0x905e..0x9061} -> 0x18aa4 (capability bit9); {0x930..0x935} ->
      константная таблица dc 0x55b9a0
  исполнитель 0x1ae84: capability-бит0 (0x18980 -> слово 0x183ec из
      RAM[0xd840]/[0x7c0]/[0x7c4]/[0x7d6]) -> 0x1ad6c (semaphore 0xcf420,
      движок 0xcf2cc, копия ответа клиенту в 0x105538)

cc-семантика: name-faithful (cc0 eq / cc3 ugt = RS>u imm — live-proven;
cc2 lt32 = RS<RT; cc4 ult32 = RS<u imm) — валидирована живыми якорями:
MCC 0x9062/MCDA 0x9063 обязаны доходить до 0x107f6c (rb/verify работают
на secure-карте), MCQS/MCQI 0x9060/0x9061 — не ACL-глушиться.

Запуск (из корня репо):
  python3 scripts/cx6secfw/filter_probe.py            # разбор + вердикты
  python3 scripts/cx6secfw/filter_probe.py --patch    # эффект патч-слова
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.irisc import disasm  # noqa: E402

BLOB = "build/cx6dx-main03-dc.bin"
MD5 = "7e4db04c2a744391ba4edc642462f651"

SITE_DISPATCH_TABLE = 0x549bb8   # срез regs 0x9009..0x907f
GATE_WORD = 0x18e770             # set3 r9,r9,imm16 — база окна ACL
GATE_EXPECTED_ORIG = 0x21296FF0  # set3 r9,r9,0x6ff0 (reg-0x10)
PATCH_WORD = 0x21296FEE          # set3 r9,r9,0x6fee (reg-0x9012)
NAMES = {0x9010: "MFPA", 0x9011: "MFBA", 0x9012: "MFBE",
         0x9060: "MCQS", 0x9061: "MCQI", 0x9062: "MCC", 0x9063: "MCDA"}


def w32(data, off):
    return int.from_bytes(data[off:off + 4], "big")


def sext32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def dispatch_reg(data, reg):
    """compare-дерево exec_access_register 0x107ea0 -> адрес кейса."""
    if reg > 0x9008:                       # b.f.0x2 @0x107f34 не взят
        if reg > 0x9114:                   # b.t.0x2 @0x107f40 -> 0x107fd0
            return "other_bucket_0xb01e_c000"
        idx = reg - 0x9009
        if idx > 0x76:                     # b.t.0x3 @0x107f54 -> 0x1082d0
            return "other_bucket_0x90f3_9110"
        return w32(data, SITE_DISPATCH_TABLE + idx * 4) - 0x21000000
    if reg > 0x5000:                       # 0x107f8c..0x107f98
        return "other_bucket_0x5001_507e" if reg <= 0x507E else "other_bucket_0x7000s"
    return "other_bucket_le_0x5000"


def gate_route(data, reg, word=None):
    """Гейт 0x18e714 для reg<=0x902f: класс маршрута после окна 0x18e76c."""
    if reg > 0x902F:                       # b.f.0x2 @0x18e734
        off = reg - 0x905C
        if 0 <= off <= 7:                  # b.t.0x3 @0x18e748 не взят
            bit = 1 << off
            if bit & 0xC1:
                return "0x19d4c:mode/acl (MCC/MCDA/0x905c)"
            if bit & 0x82:
                return "allow (0x18e7c0 exit)"
            return "0x18aa4:capability_bit9"
        if 0 <= reg - 0x930 <= 5:
            v = w32(data, 0x55B9A0 + (reg - 0x930) * 4)
            return f"const_{v:#x}"
        return "allow (exit-0)"
    imm = ((w32(data, GATE_WORD) if word is None else word) & 0xFFFF)
    base = sext32(0xFFFF0000 | imm)        # r9 = reg + base
    rs = (reg + base) & 0xFFFFFFFF
    rd = (rs - 3) & 0xFFFFFFFF
    in_window = rd != 0 and rs <= 3        # cc4: Z==0 && C==0 (ult32)
    if in_window:
        return "0x19290:ACL (deny-by-default)"
    if reg in (0x9024, 0x9025):
        return "0x19a40:write-acl"
    return "allow (exit-0)"


def main():
    args = [a for a in sys.argv[1:] if a.startswith("--")]
    data = Path(BLOB).read_bytes()
    md5 = hashlib.md5(data).hexdigest()
    if md5 != MD5:
        sys.exit(f"md5 mismatch: {md5} != {MD5}")
    print(f"blob {BLOB} md5 {md5} OK")

    orig = w32(data, GATE_WORD)
    if orig != GATE_EXPECTED_ORIG:
        sys.exit(f"gate word guard failed @0x{GATE_WORD:x}: {orig:#010x}")
    print(f"gate window word @0x{GATE_WORD:x}: {orig:#010x} "
          f"'{disasm(orig, GATE_WORD)}'")

    # Живые якоря маршрутизации (MCC-кластер обязан доходить до роутера).
    for reg, want in ((0x9060, 0x107F6C), (0x9062, 0x107F6C), (0x9063, 0x107F6C)):
        got = dispatch_reg(data, reg)
        assert got == want, f"dispatch anchor failed for {reg:#x}: {got:#x}"
    print("dispatch anchors OK: MCQS/MCC/MCDA(0x9060-63) -> 0x107f6c "
          "(live rb/verify через MCC)")
    for reg in (0x9010, 0x9011, 0x9012):
        got = dispatch_reg(data, reg)
        assert got == 0x10826C, f"{reg:#x} != 0x10826c"
    print("dispatch: MFPA/MFBA/MFBE -> 0x10826c -> call 0x105538 "
          "(единственный хендлер тройки)")

    print("\n== gate routing, regs 0x9008..0x9070 (оригинал) ==")
    rows = []
    for reg in range(0x9008, 0x9071):
        rows.append((reg, gate_route(data, reg),
                     dispatch_reg(data, reg)))
    classes = {}
    for reg, g, _ in rows:
        classes.setdefault(g, []).append(reg)
    for g, regs in sorted(classes.items(), key=lambda kv: kv[1][0]):
        pretty = " ".join(f"{NAMES.get(r, hex(r))}" for r in regs)
        print(f"  {g:38s} <- {pretty}")

    print("\n== patch effect @0x18e770: "
          f"{GATE_EXPECTED_ORIG:#010x} -> {PATCH_WORD:#010x} "
          f"('{disasm(PATCH_WORD, GATE_WORD)}') ==")
    changed = []
    for reg in range(0x9008, 0x9071):
        before = gate_route(data, reg)
        after = gate_route(data, reg, PATCH_WORD)
        if before != after:
            changed.append((reg, before, after))
    for reg, b, a in changed:
        nm = NAMES.get(reg, hex(reg))
        print(f"  {nm}: {b}  ->  {a}")
    mpa = dict((r, a) for r, b, a in changed)
    ok_open = all(gate_route(data, r, PATCH_WORD) == "allow (exit-0)"
                  for r in (0x9010, 0x9011))
    ok_mfbe = gate_route(data, 0x9012, PATCH_WORD).startswith("0x19290:ACL")
    print(f"\nMFPA+MFBA released to gate-exit-0 (далее capability 0x18980): "
          f"{'YES' if ok_open else 'NO'}")
    print(f"MFBE still ACL-checked (spec p.4): "
          f"{'YES' if ok_mfbe else 'NO — VIOLATION'}")
    assert ok_open and ok_mfbe
    if "--patch" in args:
        print("\npatched blob word stream check omitted (Task 7 пересборка "
              "пересчитает clcrc-линию секции 0x03)")


if __name__ == "__main__":
    main()
