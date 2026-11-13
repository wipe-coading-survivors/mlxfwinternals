# 045. Ветки ошибок verify: event FW → код MCC

> Источник: цикл securefw-gates (2026-10-29) — RE-декод доставки кодов +
> live-исходы 2026-10-24/-29; журналы
> `docs/superpowers/journal/2026-10-29-securefw-gates-task-{04,07}.md`
> (адресация — `035-securefw-map.md` §1-2). Live-карта — `CARD_HPE_CX516A`.
> Связи: ключ-резолв (кто порождает ветки) → `040-key-resolve.md`;
> вершина «verify обязателен» → `035` §3; digest-гейт non-secure (код 0x2
> CDA-пути) и полный набор кодов MCC (`fw_comps_mgr.h:256-309`) →
> `750-exp/170-securefw-live-gates.md`.

## 1. Таблица веток (FW 8008 → клиент)

| ветка FW (8008) | event | клиент (MCC) | статус |
|---|---|---|---|
| uuid не найден (16 слотов) 0x1d3020 | (0xf0,7) | **0x7 KEY_NOT_APPLICABLE** | **live 2026-10-29 ×2, логи байт-идентичны (md5 7b58a97c…)** — НЕ 0x4/0x5 |
| RSA mismatch / auth_type ∉ {3,4} 0x1d30b8 | (0xf0,5) | 0x5 AUTH_FAILED | live 2026-10-24 |
| plain digest mismatch 0x1d337c | (0xf0,2) | 0x2 DIGEST_ERR | live (CDA, burn-digest) |
| Unsigned-ветка 0x1d33a0 / сбой чтения ITOC | (0xf0,6) | 0x6-семейство | декод |
| режим-отказ 0x1d3294 | (0xf0,0xa) | 0xa NOT_A_SECURED_FW | декод |

## 2. Доставка кода клиенту

verify_image ret 1 → progress 5 → state 0x84 → send_verify_status
(таблица 0x38efd8, диспетчер 0x1b8640, постер 0x1b8588): progress-5 хендлер
постит код 5, progress-7 — код 7; event-подкод (0xf0,7) доносится до
MCQS-поля как 7. Сверка client-маппинга: «The key is not applicable» =
`FWCOMPS_MCC_ERR_REJECTED_KEY_NOT_APPLICABLE` = 0x7
(`fw_comps_mgr.h:268`); **0x4 UNKNOWN_KEY в живых исходах не наблюдался**
(«ключ валиден, но непригоден по назначению/lifecycle» как источник 0x7 —
опровергнуто live-итерацией slot0 auth 0x80000004→0xd8000004, исход без
изменений; `040-key-resolve.md` §5).

## 3. Операционные инварианты (live)

- Reject не трогает running-слот: неактивный слот к моменту отказа уже стёрт
  и записан «полуобразом» (полный компонент без ACTIVATE; ~4.2 MiB residue) ⇒
  карта продолжает ботить со старого слота.
- После PASS — reboot/mstfwreset до следующего MCC-цикла.
- Каждый прогон = полный download ~4.2 MiB (минуты) — код рождается только
  на стадии VERIFY_COMPONENT, после записи.

## Постулаты / открытое

- [постулат] Проводка постера 0x1b8588 до байта MCQS-ответа (диспетчеризация
  событий декодирована, побайтовая проводка — нет).
