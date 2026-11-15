import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

_spec = importlib.util.spec_from_file_location(
    "annotations",
    REPO / "scripts" / "probes" / "securefw-arc-b" / "annotations.py")
annotations = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(annotations)

SIDECAR = REPO / "scripts" / "probes" / "securefw-arc-b" / "boot2_annotations.json"
ART = {"0751": REPO / "build" / "securefw-arc-b" / "0751",
       "0800": REPO / "build" / "securefw-arc-b" / "0800"}
SEC_ART = {"0x0f": "boot3-0f.dis.txt", "0x05": "iron-05.dis.txt"}
HAVE_ART = all((d / "boot2.dis.txt").is_file() for d in ART.values())
HAVE_SEC_ART = all(
    (ART[img] / name).is_file()
    for img in ART for name in SEC_ART.values())


def mk(**over):
    doc = {
        "image": "0800",
        "entry": 4,
        "functions": [
            {"name": "entry_gate", "start": 0, "end": 0x78,
             "kind": "misc", "notes": "synthetic"},
            {"name": "crc16_block", "start": 0x78, "end": 0x100,
             "kind": "verify", "notes": "synthetic"},
        ],
        "consumes": {"boot_record": [0x10], "hashes_table": [],
                     "toc_ptr": [0x20, 0x30]},
    }
    doc.update(over)
    return doc


def mk_section(**over):
    base = 0x20500040
    doc = {
        "image": "0800",
        "section": "0x0f",
        "base": base,
        "entry": base + 4,
        "functions": [
            {"name": "entry_halt", "start": base + 4, "end": base + 0x14,
             "kind": "dispatch", "notes": "synthetic"},
            {"name": "main", "start": base + 0x14, "end": base + 0x40,
             "kind": "dispatch", "notes": "synthetic"},
        ],
        "consumes": {"boot_record": [], "hashes_table": [],
                     "toc_ptr": [base + 0x20]},
    }
    doc.update(over)
    return doc


def fn(**over):
    f = {"name": "f", "start": 0x100, "end": 0x120, "kind": "load",
         "notes": ""}
    f.update(over)
    return f


def test_valid_sidecar_no_errors():
    assert annotations.validate_sidecar(mk()) == []


def test_top_level_keys_fixed():
    assert any("image" in e for e in annotations.validate_sidecar(
        {k: v for k, v in mk().items() if k != "image"}))
    assert any("entry" in e for e in annotations.validate_sidecar(
        {k: v for k, v in mk().items() if k != "entry"}))
    bad = mk()
    bad["extra"] = 1
    assert any("extra" in e for e in annotations.validate_sidecar(bad))


def test_image_enum():
    assert any("image" in e for e in annotations.validate_sidecar(
        mk(image="0600")))


def test_entry_word_off_rules():
    for bad_entry in (-4, 3, "4", 4.0, True):
        errs = annotations.validate_sidecar(mk(entry=bad_entry))
        assert errs, bad_entry
    assert annotations.validate_sidecar(mk(entry=1 << 40)) == []
    errs = annotations.validate_sidecar(mk(entry=1 << 40),
                                        artifacts={"words": 16})
    assert errs


def test_functions_schema():
    assert any("functions" in e for e in annotations.validate_sidecar(
        mk(functions=[])))
    for bad in ({"name": "x", "start": 0, "end": 4},
                {**fn(), "kind": "crypto"},
                {k: v for k, v in fn().items() if k != "notes"},
                {**fn(), "start": 5},
                {**fn(), "end": 0x100}):
        errs = annotations.validate_sidecar(
            mk(functions=[{"name": "entry_gate", "start": 0, "end": 0x78,
                           "kind": "misc", "notes": ""}, bad]))
        assert errs, bad
    dup = [fn(name="dup"), fn(name="dup", start=0x200)]
    assert any("unique" in e or "name" in e for e in
               annotations.validate_sidecar(mk(functions=dup)))


def test_consumes_keys_and_entries():
    bad = mk()
    bad["consumes"]["hw_ptr"] = []
    assert any("hw_ptr" in e or "consumes" in e
               for e in annotations.validate_sidecar(bad))
    for key in ("boot_record", "hashes_table", "toc_ptr"):
        bad = mk()
        del bad["consumes"][key]
        assert any(key in e or "consumes" in e
                   for e in annotations.validate_sidecar(bad))
    bad = mk()
    bad["consumes"]["toc_ptr"] = [0x21, -4, "0x30"]
    assert any("toc_ptr" in e for e in annotations.validate_sidecar(bad))


def test_artifact_bounds():
    artifacts = {"words": 16}
    small = mk(functions=[{"name": "gate", "start": 0, "end": 0x40,
                           "kind": "misc", "notes": ""}],
               consumes={"boot_record": [0x3c], "hashes_table": [],
                         "toc_ptr": []}, entry=0x3c)
    assert annotations.validate_sidecar(small, artifacts=artifacts) == []
    over = mk(functions=[{"name": "over", "start": 0, "end": 0x44,
                          "kind": "misc", "notes": ""}],
              consumes={"boot_record": [0x44], "hashes_table": [],
                        "toc_ptr": []}, entry=0x44)
    errs = annotations.validate_sidecar(over, artifacts=artifacts)
    assert any("over" in e for e in errs)
    assert any("entry" in e for e in errs)
    assert any("boot_record" in e for e in errs)
    words_tuple = {"words": tuple(range(64))}
    assert annotations.validate_sidecar(small, artifacts=words_tuple) == []


def test_section_schema():
    assert annotations.validate_sidecar(mk_section()) == []
    for key in ("section", "base"):
        bad = {k: v for k, v in mk_section().items() if k != key}
        assert any(key in e for e in annotations.validate_sidecar(bad)), key
    assert any("section" in e for e in annotations.validate_sidecar(
        mk_section(section="0x03")))
    bad = mk_section()
    bad["extra"] = 1
    assert any("extra" in e for e in annotations.validate_sidecar(bad))
    for bad_base in (-4, 0x41, "0x20500040", 4.0, True):
        errs = annotations.validate_sidecar(mk_section(base=bad_base))
        assert errs, bad_base
    assert annotations.validate_sidecar(mk_section(base=0x20500000)) == []


def test_section_word_off_rules():
    base = 0x20500040
    for bad_entry in (base - 4, base + 3, base + 4.0, True, "x"):
        errs = annotations.validate_sidecar(mk_section(entry=bad_entry))
        assert errs, bad_entry
    fn_bad = {"name": "f", "start": base + 5, "end": base + 0x40,
              "kind": "load", "notes": ""}
    assert annotations.validate_sidecar(
        mk_section(functions=[fn_bad]))
    fn_bad2 = {"name": "f", "start": base + 0x30, "end": base + 0x10,
               "kind": "load", "notes": ""}
    assert annotations.validate_sidecar(
        mk_section(functions=[fn_bad2]))
    bad = mk_section()
    bad["consumes"]["toc_ptr"] = [base - 4]
    assert any("toc_ptr" in e for e in annotations.validate_sidecar(bad))


def test_section_artifact_bounds_window():
    base = 0x20500040
    artifacts = {"words": 16}
    assert annotations.validate_sidecar(
        mk_section(), artifacts=artifacts) == []
    over = mk_section(functions=[
        {"name": "over", "start": base, "end": base + 0x44,
         "kind": "misc", "notes": ""}],
        consumes={"boot_record": [base + 0x44], "hashes_table": [],
                  "toc_ptr": []}, entry=base + 0x44)
    errs = annotations.validate_sidecar(over, artifacts=artifacts)
    assert any("over" in e for e in errs)
    assert any("entry" in e for e in errs)
    assert any("boot_record" in e for e in errs)
    assert annotations.validate_sidecar(over) == []


def test_boot2_doc_schema_unchanged():
    bad = mk()
    bad["section"] = "0x0f"
    errs = annotations.validate_sidecar(bad)
    assert errs and any("base" in e for e in errs)


@pytest.mark.slow
@pytest.mark.skipif(not (SIDECAR.is_file() and HAVE_ART),
                    reason="sidecar and/or Task 2 artifacts not built")
def test_sidecar_canon_validates_against_artifacts():
    docs = json.loads(SIDECAR.read_text())
    docs = [d for d in docs if "section" not in d]
    assert isinstance(docs, list) and len(docs) == 2
    assert [d["image"] for d in docs] == ["0800", "0751"]
    for doc in docs:
        listing = (ART[doc["image"]] / "boot2.dis.txt").read_text()
        text_at = {}
        for l in listing.splitlines():
            m = re.match(r"^([0-9a-f]{8})  [0-9a-f]{8}  (.*)$", l)
            if m:
                text_at[int(m.group(1), 16)] = m.group(2)
        words = len(text_at)
        calls = json.loads(
            (ART[doc["image"]] / "boot2.calls.json").read_text())
        assert words == calls["words"]
        assert annotations.validate_sidecar(
            doc, artifacts={"words": words}) == [], doc["image"]
        targets = {c["target"] for c in calls["calls"]}
        allowed = targets | {0, 0x204}
        ranges = [(f["start"], f["end"]) for f in doc["functions"]]
        for f in doc["functions"]:
            assert f["start"] in allowed, (doc["image"], f["name"])
            last = text_at.get(f["end"] - 4, "")
            boundary = (last.startswith(("ret.r", "ret.d"))
                        or (last.startswith("jump 0x")
                            and int(last.rsplit("0x", 1)[1], 16) == f["end"] - 4)
                        or f["end"] in targets)
            assert boundary, (doc["image"], f["name"], f["end"],
                              "end not a function boundary")
            for a, b in re.findall(
                    r"(?<!CSR )0x([0-9a-f]{3,4})-0x([0-9a-f]{3,4})",
                    f["notes"]):
                lo, hi = int(a, 16), int(b, 16)
                inside = any(s <= lo and hi <= e for s, e in ranges)
                assert inside, (doc["image"], f["name"], hex(lo), hex(hi),
                                "notes range outside annotated functions")
    names_b = {f["name"] for d in docs if d["image"] == "0800"
               for f in d["functions"]}
    names_a = {f["name"] for d in docs if d["image"] == "0751"
               for f in d["functions"]}
    assert names_a == names_b


def _listing_words(path):
    text_at = {}
    for l in path.read_text().splitlines():
        m = re.match(r"^([0-9a-f]{8})  [0-9a-f]{8}  (.*)$", l)
        if m:
            text_at[int(m.group(1), 16)] = m.group(2)
    return text_at


@pytest.mark.slow
@pytest.mark.skipif(not (SIDECAR.is_file() and HAVE_SEC_ART),
                    reason="sidecar and/or section artifacts not built")
def test_section_canon_validates_against_artifacts():
    docs = json.loads(SIDECAR.read_text())
    sec_docs = [d for d in docs if "section" in d]
    assert len(sec_docs) == 4
    assert [(d["section"], d["image"]) for d in sec_docs] == [
        ("0x0f", "0800"), ("0x0f", "0751"),
        ("0x05", "0800"), ("0x05", "0751")]
    fn_ptr_starts = {"0x0f": {0x20500054, 0x20500078}, "0x05": set()}
    for doc in sec_docs:
        listing = _listing_words(
            ART[doc["image"]] / SEC_ART[doc["section"]])
        words = len(listing)
        assert annotations.validate_sidecar(
            doc, artifacts={"words": words}) == [], (
                doc["image"], doc["section"])
        assert doc["entry"] >= doc["base"]
        targets = set()
        for a, t in listing.items():
            m = re.match(r"^(call|jump) 0x([0-9a-f]+)$", t)
            if m:
                targets.add(int(m.group(2), 16))
        allowed = (targets | {doc["entry"]} | fn_ptr_starts[doc["section"]])
        for f in doc["functions"]:
            assert f["start"] in allowed, (
                doc["image"], doc["section"], f["name"], hex(f["start"]))
            assert f["start"] >= doc["base"], (f["name"], "below base")
            last = listing.get(f["end"] - 4, "")
            boundary = (last.startswith(("ret.r", "ret.d"))
                        or (last.startswith("jump 0x")
                            and int(last.rsplit("0x", 1)[1], 16)
                            == f["end"] - 4)
                        or f["end"] in targets)
            assert boundary, (doc["image"], doc["section"], f["name"],
                              f["end"], "end not a function boundary")
    for section in ("0x0f", "0x05"):
        per_image = {}
        for img in ("0800", "0751"):
            per_image[img] = {f["name"]: f["kind"] for d in sec_docs
                              if d["image"] == img and d["section"] == section
                              for f in d["functions"]}
        shared = set(per_image["0800"]) & set(per_image["0751"])
        for name in shared:
            assert per_image["0800"][name] == per_image["0751"][name], (
                section, name)
    assert {f["name"] for d in sec_docs
            if d["image"] == "0751" and d["section"] == "0x0f"
            for f in d["functions"]} <= {f["name"] for d in sec_docs
                                         if d["image"] == "0800"
                                         and d["section"] == "0x0f"
                                         for f in d["functions"]}
    iron_b = {f["name"] for d in sec_docs
              if d["image"] == "0800" and d["section"] == "0x05"
              for f in d["functions"]}
    iron_a = {f["name"] for d in sec_docs
              if d["image"] == "0751" and d["section"] == "0x05"
              for f in d["functions"]}
    assert iron_a == iron_b
