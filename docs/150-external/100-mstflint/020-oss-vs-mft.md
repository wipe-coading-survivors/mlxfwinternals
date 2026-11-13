# 020. OSS mstflint vs закрытая MFT: что есть / чего нет

> Источник: разбор OSS mstflint (`refs/src/mstflint@a2b9858b`) и сверка
> с 17 локальными образами `refs/fw/` (все CRC верифицированы
> OSS-алгоритмом); live-использование mstflint по всему проекту.
> Сводная pinned-ревизий — `docs/150-external/000-pinned-revs.md`.
>
> Связи: карты исходников mstflint (где что лежит) — `010-walkthrough.md`;
> детекция форматов —
> `docs/250-re/100-formats/005-detect.md`; FS2/HP-пакет — `…/010-fs2.md`;
> ini-секция 0x30 и `FwGetSection` —
> `docs/550-poc/100-mlxfwutil/010-ini-mapping.md`; подписи/secure-fw —
> `docs/250-re/110-signing/`.

## Что в OSS есть

- полная детекция: FS2/FS3/FS4/FS5(PLDM)/cable/comps (`005-detect`);
- парсинг TOC FS3/FS4, верификация CRC, `q`, `verify`, `dc` (ini);
- `UpdateSection` и для FS3 (по умолчанию FS3_DEV_INFO), и для FS4;
- `mlxsign_lib` — RSA + SHA256/512 (OpenSSL, PEM), не ECDSA.

## Чего в OSS нет / расхождения

- `mlxburn` (FS2-era) — отсутствует; есть только в HP-пакете (exe;
  `010-fs2`).
- `FwGetSection` — только DBG_FW_INI (`010-ini-mapping`).
- Ключи NVIDIA/FNP-подписи — закрытые; signed-образы принимаются
  только с их цепочкой (`110-signing`).
- Существенных расхождений между OSS-парсерами и реальными образами
  не найдено: все CRC в 17 локальных образах верифицированы
  OSS-алгоритмом.
