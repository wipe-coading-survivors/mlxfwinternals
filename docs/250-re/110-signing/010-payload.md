# 010. Payload подписи: что именно подписывается

> Источник: статический разбор OSS mstflint (`refs/src/mstflint`, rev `a2b9858b`),
> `GetImageDataForSign` `fs3_ops.cpp:3571` / `fs4_ops.cpp:603` (2026-09-06);
> бит-в-бит-подтверждения модели — журналы `2026-10-28-burn-digest-gate-task-01/-05/-06`,
> `2026-10-29-mlxini-sign-task-01/-05`, `2026-10-29-securefw-gates-task-01/-03`,
> `2026-10-30-cx6dx-securefw-task-05`; FS3-инвариант порядка строк —
> `2026-11-12-serdes-arc-d-task-07s0`.
> Связи: библиотека подписи → `005-mechanism.md`; секции → `015-key-sections.md`;
> Secure Boot payload → `025-secure-boot.md`; практические рецепты →
> `850-howto/170-signing-practical.md`.

## 1. Конвейер `GetImageDataForSign`

`GetImageDataForSign` (`mlxfwops/lib/fs3_ops.cpp:3571`, FS4-надстройка
`fs4_ops.cpp:603`):

1. `FwExtract4MBImage(img, maskMagicPatternAndDevToc=true)` (`fs3_ops.cpp:3595`):
   копирует образ из кэша `buf[imgStart … imgStart + getImageSize()]`, где
   `getImageSize() = sizeOfImgData - imgStart` (`fs3_ops.cpp:3566`).
2. **Маскирует magic**: первые 16 байт → `0xFF` (`memset(img, 0xFF, 16)`).
3. **`maskDevToc`** (`fs3_ops.cpp:3663`): записи ITOC с флагом `device_data`
   → `0xFF` (данные устройства не входят в подпись).
4. **Маскирует секции подписи** (`MaskItocSectionAndEntry`, `fs3_ops.cpp:3619`):
   запись + данные секции → `0xFF`
   - `SHA256`: маскирует `0xA0` (`FS3_IMAGE_SIGNATURE_256`);
   - `SHA512`: маскирует `0xA0` **и** `0xA3`.
5. FS4-надстройка (`fs4_ops.cpp:603`): для `secure_boot VERSION_2` (Carmel+)
   дополнительно `RemoveCRCsFromMainSection` + `MaskBootRecordCRC`
   (не для ConnectX-7).
6. Digest/подпись: `FwCalcSHA` (`fs3_ops.cpp:3864`) = `SHA256/512(masked_img)`
   (через `MlxSignSHA`), либо `signer.Sign(...)`.

Вывод: **подпись/дест — над образом с вырезанными magic, dev-TOC и самими
секциями подписи** (иначе бы подписывали сами себя).

## 2. Точная модель (подтверждена бит-в-бит)

Закрытый вопрос исходника «бит-в-бит SHA-256: точный imgStart/sizeOfImgData,
FS4-маски» — решён: модель ниже воспроизводит все десты/подписи корпуса
бит-в-бит.

```
M = image[0 .. sizeOfImgData):
      [0x00,0x10)         → 0xFF   (16B boot magic)
      ITOC-entry(0xA0)    → 0xFF   (32B)
      данные 0xA0         → 0xFF   (size секции)
      [для SHA-512/RSA:] ITOC-entry(0xA3) → 0xFF (32B); данные 0xA3 → 0xFF
      [только FS3:] ITOC-записи с device_data → 0xFF (entry, не данные)
      прочее              → как в образе (включая 0xA4 целиком)

sizeOfImgData = max(phys_addr + size) по relative ITOC-записям (fs3_ops.cpp:654-660)
digest(0xA0)  = SHA-256(M)                       — 32B-слот @+0x20 секции 0xA0
sig(0xA3)     = RSA_sign_PKCS1v1.5_SHA512( SHA512(M) )   — RSA-4096
```

### 2.1 FS3: инвариант порядка ITOC-строк (live 2026-11-12, цикл serdes-arc-d)

Клиентская формула **порядко-независима** (max по всем rel-записям), но
FW-side TOC-walk на MCC-компоненте — **порядко-зависим**: компонент
`FwExtract4MBImage(maskMagicPatternAndDevToc=true)` (fsctrl_ops.cpp:911 →
fs3_ops.cpp:3618/3659) несёт dev-data ITOC-строки, замаскированные в 0xFF, а
строка type==0xFF — FS3_END-терминатор обхода (fs3_ops.cpp:616): walk
заканчивается на первой dev-строке. Rel-строка ПОСЛЕ dev-блока невидима FW —
её конец не входит в digest-диапазон VERIFY_COMPONENT → MCC 0x2 «The Digest
in the signature is wrong» после полного download (live: img-G4a, relocated
0x0C row idx 30 после шести dev-строк; FW range 0x4CEAAC vs клиентский
0x4D1E80). Все вендорские FS3-образы корпуса (refs/fw/cx-4, 24 шт.)
держат порядок rel-блок → dev-блок → END; FS4 immune (dev-data в DTOC вне
компонента, maskDevToc no-op — relocated-last проходил live, цикл dell-base).
Клиентский фикс: mlxfwutil `_itoc_reloc_order` — релоцированная FS3-строка
вставляется в конец rel-блока (до dev-строк); гейт `verify` (rel-строка
после dev-строк = ошибка) — журнал `2026-11-12-serdes-arc-d-task-07s0`,
отчёт `.superpowers/sdd/2026-11-12-serdes-arc-d/task-7s0-report.md`.

Специфика FS4/CX-5: `maskDevToc` — no-op (`fs4_ops.cpp:4296-4301`; dev-data
живёт в DTOC вне компонента); DTOC-масок нет. Подпись RSA-4096 перед подписью
обнуляет младшую секцию: `Fs3MemSetSignature(0xA0)` → 0x00 (`fs3_ops.cpp:3284-3290`;
зеркально SHA-256-ключ обнулил бы `0xA3`).

Подтверждения:

- **Корпус digest-only**: все 82 fresh-образа `refs/fw` — stored дест == расчёт
  бит-в-бит (журнал `2026-10-29-mlxini-sign-task-01` §5); `mlxfwutil.py sign` —
  бит-эквивалент `mstflint -i <img> sign` (кросс-чек md5, журнал
  `2026-10-29-mlxini-sign-task-05`).
- **FW-side digest-гейт** plain-burn (VERIFY_COMPONENT, MCC 0x2): FW считает
  SHA-256 по маске/диапазону, эквивалентному клиентской — численное
  доказательство (RE: компаратор dc 0x1d29f4, memcmp 0x1d2c20 — журнал
  `2026-10-28-burn-digest-gate-task-06`; live-парный контроль стылый/fresh —
  `-task-05`).
- **RSA-parity**: FW-verify ≡ клиентская `SignForFwUpdate` — CX-5
  (вендорская подпись refs-8008, SHA512(M) =
  `3e8a8944d7ca7ab22a46f3180a431e89b893fd1b84e53200b64ac034e3cb4a65`, гейт
  `scripts/secfw/parity_gate.py`, журнал `2026-10-29-securefw-gates-task-03`
  §3.4) и CX-6Dx (гейт `scripts/cx6secfw/parity_gate.py`, журнал
  `2026-10-30-cx6dx-securefw-task-05`).

Порядок сборки self-signed: вольты `0xA4`/`0xA6`/`0xA7` входят в подписываемые
данные `0xA3` ⇒ **сначала `set_public_keys`, потом `sign`** (изменение вольта
после подписи ломает `0xA3`; журнал `2026-10-29-securefw-gates-task-01` §1.3).

## Постулаты / открытое

- [постулат] **V2-маски** (Carmel+: `RemoveCRCsFromMainSection`,
  `MaskBootRecordCRC`, `fs4_ops.cpp:603-628`): бит-в-бит паритет не доказан —
  в корпусе нет V2-образов (скан: v2=0; CX-6Dx 22.50.1002 — VERSION_1,
  применение V2-маски ломает паритет — негатив-контроль, журнал
  `2026-10-30-cx6dx-securefw-task-05`); `mlxfwutil.py sign` на V2 отказывает.
  Остаток закрытого вопроса «бит-в-бит SHA-256» (digest/RSA-часть — факт, §2).
