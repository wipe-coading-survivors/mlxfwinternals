#!/usr/bin/env python3
"""Decode/diff/synthesis for the CX-4/Lx Gen4 CR-window dumps
(spec 2026-10-24-cx4lx-gen4-window, task 3; offline).

Consumes the normalized dump files of Tasks 1-2 (one 32-bit word per line:
`<hex-addr> <8-hex-digit-word>`), classifies every word (spec §5 with the
2026-10-24 area-fill erratum), extracts 6-bit speed fields + raw bit 21 for
non-fill slot words only, and evaluates the spec §5 stop-table predicate.

Classification order (per word):
  value == addr>>2   -> «unmapped»   (off/4 PATTERN, never treated as data)
  value == 0x0       -> «пуст»
  value == 0x00010000-> «area-fill»  (dominant mapped-area fill observed on
                                      CX-5 16.35.4030, identical Gen3/Gen4,
                                      inside and outside the window — erratum)
  else               -> «заполнен»   (raw word; slot fields decoded offline)

Slots (spec §4.1, x4 convention regspace = 0x40000 + imm*4):
  CX-5 speeds1-3 = 0x4ddc4 (imm 0x3771, fields >>{0,6,12} & 0x3f)
  CX-5 speed-4   = 0x4dd64 (imm 0x3759, (w>>4) & 0x3f)
  LX  speeds1-3  = 0x4eb44 (imm 0x3ad1)
  LX  speed-4    = 0x4eae4 (imm 0x3ab9, + feature-gate bit 21, RAW)

Stop-table rows (§5): 2 = LX speed-4 non-fill «заполнен» (surprise, stop;
checked first — owner decision precedes everything); 3 = positive control
invalid (CX-5-Gen4 speed-4 not non-fill «заполнен», or no Gen3<->Gen4
differential); 4 = LX window unmapped at valid control; 1 = control valid
+ LX speed-4 «пуст/unmapped» (gen4 window gate closed). Row 0 = no row /
open item: a needed slot address is missing from the dumps (partial
window — explicit «missing» marker), or LX speed-4 is «area-fill» at
valid control (erratum: no discernible data — row 1 admits only
«пуст»/«unmapped»).

Usage: python3 scripts/probes/cx4lx_gen4_window.py DUMP [DUMP ...]
Files are matched to cards by filename prefix (81xx/1xx/c1xx/42xx), with
an address-range fallback; exit code = stop-table row (0 = no row).
"""
import re
import sys
from collections import Counter
from pathlib import Path

AREA_FILL = 0x00010000
MISSING = "missing"
LINE_RE = re.compile(r"^0x([0-9a-fA-F]+)\s+([0-9a-fA-F]{8})$")

SLOTS = {
    "cx5": {"speeds123": 0x4DDC4, "speed4": 0x4DD64},
    "lx": {"speeds123": 0x4EB44, "speed4": 0x4EAE4},
}
CARD_BY_RANGE = [
    ("cx5_gen4_naive", 0x43750, 0x437A0, "cx5"),
    ("cx5_gen4", 0x4DD4C, 0x4DE70, "cx5"),
    ("cx5_gen3", 0x4DD4C, 0x4DE70, "cx5"),
    ("lx", 0x4EA7C, 0x4ECB0, "lx"),
    ("cx4_hyp", 0x4EA7C, 0x4ECB0, "lx"),
]
FAM = {name: fam for name, _, _, fam in CARD_BY_RANGE}
PREFIX_CARD = {
    "81xx": "cx5_gen4",
    "1xx": "cx5_gen3",
    "c1xx": "lx",
    "42xx": "cx4_hyp",
}
ROW_TEXT = {
    0: "нет строки: открытый пункт (недостающий слот в дампах — missing, "
       "или LX speed-4 area-fill при валидном контроле — row 1 требует "
       "пуст/unmapped)",
    1: "контроль валиден; LX speed-4 пуст/unmapped -> (в) закрыт: данных "
       "Gen4 у Lx в window нет",
    2: "СТОП-СЮРПРИЗ: LX speed-4 «заполнен» -> отчёт владельцу, Task 4 не "
       "писать до решения",
    3: "положительный контроль НЕ валиден -> метод-артефакт, вердиктов нет",
    4: "LX window unmapped при валидном контроле -> нет данных через mcra",
}


class Word:
    __slots__ = ("addr", "value", "cls")

    def __init__(self, addr, value):
        self.addr = addr
        self.value = value
        self.cls = classify(self)

    def __repr__(self):
        return f"Word(0x{self.addr:x}, 0x{self.value:08x}, {self.cls!r})"


def classify(w: Word) -> str:
    if w.value == (w.addr >> 2):
        return "unmapped"
    if w.value == 0:
        return "пуст"
    if w.value == AREA_FILL:
        return "area-fill"
    return "заполнен"


def decode_dump(path) -> list:
    out = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        m = LINE_RE.match(line.strip())
        if not m:
            raise ValueError(f"{path}:{n}: bad line {line!r}")
        out.append(Word(int(m.group(1), 16), int(m.group(2), 16)))
    return out


CLASSES = ("unmapped", "пуст", "area-fill", "заполнен")


def summarize(words):
    d = {cls: 0 for cls in CLASSES}
    for w in words:
        d[w.cls] += 1
    dominant, _ = Counter(w.value for w in words).most_common(1)[0]
    d["dominant"] = dominant
    d["n"] = len(words)
    return d


def card_name(path, words) -> str:
    stem = Path(path).name.split("-")[0]
    name = PREFIX_CARD.get(stem)
    if name is None:
        a = {w.addr for w in words}
        for n, lo, hi, _ in CARD_BY_RANGE:
            if a and all(lo <= x <= hi for x in a):
                return n
        return "unknown"
    if name == "cx5_gen4":  # same card also dumped over the naive range
        a = {w.addr for w in words}
        if a and all(0x43750 <= x <= 0x437A0 for x in a):
            return "cx5_gen4_naive"
    return name


def slot_words(decodes):
    """{card: {slot: Word}} for every decoded card with known slots."""
    out = {}
    for card, words in decodes.items():
        fam = FAM.get(card)
        if fam not in SLOTS:
            continue
        found = {name: next((w for w in words if w.addr == addr), None)
                 for name, addr in SLOTS[fam].items()}
        if any(w is None for w in found.values()):
            continue  # card window does not carry slot addresses
        out[card] = found
    return out


def slot_fields(card, slot, value):
    """6-bit speed fields ONLY for «заполнен» (non-fill, non-pattern)
    values; LX speed-4 feature-gate bit 21 recorded RAW for any non-pattern
    class (never interpreted). None when nothing to report."""
    filled = value not in (0, AREA_FILL)
    f = {}
    if filled:
        if slot == "speeds123":
            f["speed1"] = (value >> 0) & 0x3F
            f["speed2"] = (value >> 6) & 0x3F
            f["speed3"] = (value >> 12) & 0x3F
        elif slot == "speed4":
            f["speed4"] = (value >> 4) & 0x3F
    if card in ("lx", "cx4_hyp") and slot == "speed4":
        f["bit21"] = (value >> 21) & 1
    return f or None


def _fields_for_word(card, slot, w):
    if w.cls == "unmapped":  # off/4 pattern is never data
        return None
    return slot_fields(card, slot, w.value)


def predicate_inputs(decodes):
    """Stop-table inputs from decoded dumps; a card/window whose dump
    lacks the needed speed-4 slot address yields an explicit «missing»
    marker (feeds row 0 = no row) instead of a KeyError."""
    def speed4_cls(card):
        words = decodes.get(card, [])
        w = next((x for x in words
                  if x.addr == SLOTS[FAM[card]]["speed4"]), None)
        return MISSING if w is None else w.cls

    lx_words = decodes.get("lx", [])
    return {
        "cx5_gen4_speed4": speed4_cls("cx5_gen4"),
        "cx5_gen3_speed4": speed4_cls("cx5_gen3"),
        "lx_speed4": speed4_cls("lx"),
        "lx_window_unmapped": bool(lx_words) and all(
            w.cls == "unmapped" for w in lx_words),
    }


def stop_row(d) -> int:
    """Spec §5 stop-table predicate on predicate_inputs(d); 0 = no row
    (open item: a slot input is missing, or LX speed-4 is «area-fill» at
    valid control — erratum class, row 1 admits only пуст/unmapped)."""
    if MISSING in (d["cx5_gen4_speed4"], d["cx5_gen3_speed4"],
                   d["lx_speed4"]):
        return 0
    if d["lx_speed4"] == "заполнен":
        return 2
    control_valid = (d["cx5_gen4_speed4"] == "заполнен"
                     and d["cx5_gen3_speed4"] != d["cx5_gen4_speed4"])
    if not control_valid:
        return 3
    if d["lx_speed4"] == "area-fill":
        return 0
    if d["lx_window_unmapped"]:
        return 4
    return 1


def emit(decodes):
    order = [c for c, _, _, _ in CARD_BY_RANGE]
    for card in [c for c in order if c in decodes]:
        words = decodes[card]
        s = summarize(words)
        print(f"== {card} n={s['n']} dominant=0x{s['dominant']:08x}")
        for cls in ("unmapped", "пуст", "area-fill", "заполнен"):
            if s.get(cls):
                print(f"   {cls:9s} {s[cls]:3d}")
        fam = FAM.get(card)
        if fam in SLOTS:
            for slot, addr in SLOTS[fam].items():
                w = next((x for x in words if x.addr == addr), None)
                if w is None:
                    continue
                extra = _fields_for_word(card, slot, w)
                tail = f" fields={extra}" if extra else ""
                print(f"   slot {slot:9s} 0x{addr:05x} = "
                      f"0x{w.value:08x} [{w.cls}]{tail}")
        for w in words:
            if w.cls == "заполнен":
                print(f"   non-fill word: 0x{w.addr:05x} = "
                      f"0x{w.value:08x}")
    if all(c in decodes for c in ("cx5_gen4", "cx5_gen3", "lx")):
        d = predicate_inputs(decodes)
        row = stop_row(d)
        print("== predicate inputs: " + ", ".join(
            f"{k}={v}" for k, v in d.items()))
        print(f"== stop-table row {row}: {ROW_TEXT[row]}")
        return row
    print("== stop-table: card set incomplete "
          "(need cx5_gen4 + cx5_gen3 + lx)")
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 2
    decodes = {}
    for p in argv:
        words = decode_dump(p)
        name = card_name(p, words)
        decodes.setdefault(name, []).extend(words)
        print(f"# {p}: {len(words)} words -> {name}", file=sys.stderr)
    return emit(decodes)


if __name__ == "__main__":
    sys.exit(main())
