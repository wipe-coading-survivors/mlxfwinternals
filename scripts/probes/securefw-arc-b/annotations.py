#!/usr/bin/env python3
# Валидатор sidecar-канона аннотаций boot2/секций (securefw-arc-b task-03/04).
# Схема image-дока boot2 (task-03):
#   {"image": "0800|0751", "entry": <word-off>,
#    "functions": [{"name", "start", "end", "kind": "verify|load|dispatch|misc",
#                   "notes"}],
#    "consumes": {"boot_record": [...], "hashes_table": [...], "toc_ptr": [...]}}
# Схема секционного дока (task-04, адреса — rt, как в листингах Task 2:
# boot3-0f.dis.txt base=param0 0x20500040, iron-05.dis.txt base=0x20710000;
# прямая сверяемость grep-ом по листингу):
#   {"image", "section": "0x0f|0x05", "base": <param0>, "entry": <param1>,
#    "functions": [...], "consumes": {...}}
# word-off boot2 = байтовый офсет слова в листинге (base=0, адрес строки
# boot2.dis.txt; word N -> 4N) — единое пространство с off/target в
# boot2.calls.json. Файл-канон boot2_annotations.json = JSON-список доков
# (0800 первым внутри каждой секции).
# validate_sidecar(data, artifacts=None) -> list[str] ошибок (пустой =
# валиден); artifacts = {"words": N} или {"words": последовательность}
# — тогда проверяются границы артефакта: boot2-док: entry/end/consumes.off
# < 4N; секционный док: [base, base+4N).
import sys

KINDS = ("verify", "load", "dispatch", "misc")
CONSUME_KEYS = ("boot_record", "hashes_table", "toc_ptr")
TOP_KEYS = ("image", "entry", "functions", "consumes")
SECTION_TOP_KEYS = ("image", "section", "base", "entry", "functions",
                    "consumes")
SECTIONS = ("0x0f", "0x05")
FN_KEYS = ("name", "start", "end", "kind", "notes")


def _word_off(v, what, limit, errors, base=0):
    if isinstance(v, bool) or not isinstance(v, int):
        errors.append("%s: word-off must be int, got %r" % (what, v))
        return
    if v < base:
        errors.append("%s: word-off %#x below base %#x" % (what, v, base))
    elif v % 4:
        errors.append("%s: word-off %#x not word-aligned" % (what, v))
    if limit is not None and isinstance(v, int) \
            and not isinstance(v, bool) and v % 4 == 0 \
            and not (base <= v < limit):
        errors.append("%s: word-off %#x out of artifact bounds "
                      "[%#x, %#x)" % (what, v, base, limit))


def _fn_keys_check(f, errors, base=0):
    if not isinstance(f, dict):
        errors.append("function: not an object: %r" % (f,))
        return
    extra = sorted(set(f) - set(FN_KEYS))
    missing = sorted(set(FN_KEYS) - set(f))
    if extra:
        errors.append("function %r: unexpected keys %s"
                      % (f.get("name", "?"), extra))
    if missing:
        errors.append("function %r: missing keys %s"
                      % (f.get("name", "?"), missing))
    if not isinstance(f.get("name"), str) or not f.get("name"):
        errors.append("function: bad name %r" % (f.get("name"),))
    if f.get("kind") not in KINDS:
        errors.append("function %r: kind %r not in %s"
                      % (f.get("name", "?"), f.get("kind"), list(KINDS)))
    if not isinstance(f.get("notes"), str):
        errors.append("function %r: notes must be str" % (f.get("name", "?"),))
    start = f.get("start")
    end = f.get("end")
    if isinstance(start, bool) or not isinstance(start, int):
        errors.append("function %r: start must be int, got %r"
                      % (f.get("name", "?"), start))
    if isinstance(end, bool) or not isinstance(end, int):
        errors.append("function %r: end must be int, got %r"
                      % (f.get("name", "?"), end))
    if isinstance(start, int) and not isinstance(start, bool):
        if start < base:
            errors.append("function %r: start %#x below base %#x"
                          % (f.get("name", "?"), start, base))
        elif start % 4:
            errors.append("function %r: start %#x not word-aligned"
                          % (f.get("name", "?"), start))
        if isinstance(end, int) and not isinstance(end, bool):
            if end % 4:
                errors.append("function %r: end %#x not word-aligned"
                              % (f.get("name", "?"), end))
            if start >= end:
                errors.append("function %r: start %#x >= end %#x"
                              % (f.get("name", "?"), start, end))


def validate_sidecar(data, artifacts=None):
    errors = []
    limit = None
    if artifacts is not None:
        words = artifacts["words"] if isinstance(artifacts, dict) else artifacts
        if isinstance(words, (list, tuple, str, bytes, set, frozenset)):
            n = len(words)
        elif isinstance(words, int) and not isinstance(words, bool):
            n = words
        else:
            n = 0
        limit = n * 4
    if not isinstance(data, dict):
        return ["sidecar: not an object: %r" % (data,)]
    is_section = "section" in data or "base" in data
    keys = SECTION_TOP_KEYS if is_section else TOP_KEYS
    schema = "section doc" if is_section else "boot2 doc"
    for k in sorted(set(data) - set(keys)):
        errors.append("top-level(%s): unexpected key %r" % (schema, k))
    for k in keys:
        if k not in data:
            errors.append("top-level(%s): missing key %r" % (schema, k))
    if errors:
        return errors
    if data["image"] not in ("0800", "0751"):
        errors.append("image: %r not in ['0800', '0751']" % (data["image"],))
    base = 0
    if is_section:
        if data["section"] not in SECTIONS:
            errors.append("section: %r not in %s"
                          % (data["section"], list(SECTIONS)))
        base = data["base"]
        if isinstance(base, bool) or not isinstance(base, int) \
                or base <= 0 or base % 4:
            errors.append("base: must be a positive word-aligned int, "
                          "got %r" % (base,))
            base = 0
        if limit is not None:
            limit += base
    _word_off(data["entry"], "entry", limit, errors, base)
    if not isinstance(data["functions"], list) or not data["functions"]:
        errors.append("functions: must be a non-empty list")
    else:
        for f in data["functions"]:
            _fn_keys_check(f, errors, base)
        names = [f.get("name") for f in data["functions"]
                 if isinstance(f, dict)]
        seen = set()
        for n in names:
            if n in seen:
                errors.append("functions: name %r must be unique" % (n,))
            seen.add(n)
        if limit is not None:
            for f in data["functions"]:
                if isinstance(f, dict) and isinstance(f.get("end"), int) \
                        and not isinstance(f.get("end"), bool) \
                        and not (base <= f["end"] <= limit):
                    errors.append("function %r: end %#x out of artifact "
                                  "bounds [%#x, %#x]"
                                  % (f.get("name", "?"), f["end"],
                                     base, limit))
    consumes = data["consumes"]
    if not isinstance(consumes, dict):
        errors.append("consumes: not an object: %r" % (consumes,))
    else:
        for k in sorted(set(consumes) - set(CONSUME_KEYS)):
            errors.append("consumes: unexpected key %r" % k)
        for k in CONSUME_KEYS:
            if k not in consumes:
                errors.append("consumes: missing key %r" % k)
                continue
            sites = consumes[k]
            if not isinstance(sites, list):
                errors.append("consumes.%s: must be a list" % k)
                continue
            for v in sites:
                _word_off(v, "consumes.%s" % k, limit, errors, base)
    return errors


if __name__ == "__main__":
    import json
    path = sys.argv[1] if len(sys.argv) > 1 else (
        __file__.rsplit("/", 1)[0] + "/boot2_annotations.json")
    docs = json.loads(open(path).read())
    if isinstance(docs, dict):
        docs = [docs]
    bad = 0
    for doc in docs:
        errs = validate_sidecar(doc)
        bad += len(errs)
        label = doc.get("image", "?")
        if "section" in doc:
            label += "/" + doc.get("section", "?")
        print("%s: %s" % (label, "OK" if not errs else "; ".join(errs)))
    sys.exit(1 if bad else 0)
