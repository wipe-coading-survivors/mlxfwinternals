import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-prov"))

import bootdom_scan  # noqa: E402


# Brief Step-1 goldens, verbatim semantics. Window word 0x3ad1 lives at
# byte 0xeb44 (word<<2, spec 2026-10-24-cx4lx-gen4-window-design.md);
# flash addr 0x1a000 = ld.i imm 0x6800 << 2 (cx4lx/1900 0x08 layout).
GOLDEN_WINDOW_ST = [
    "00710000  24050000  set2 r5,zero,0x0",
    "00710004  20a5eb44  set3 r5,r5,0xeb44",
    "00710008  6c402802  st.d r4,r5,0x0",
]

GOLDEN_FLASH_CONST = [
    "00710000  24050001  set2 r5,zero,0x1",
    "00710004  20a5a000  set3 r5,r5,0xa000",
]

GOLDEN_PRELUDE_RAW = [
    "20710000  94ff90ba  call 0xfffe42e8",
]

GOLDEN_PRELUDE_RESOLVED = [
    "20710000  94ff90ba  call 0x206f42e8",
]

GOLDEN_INSECTION_CALL = [
    "20710000  9400746b  call 0x2072d254",
]

# Re-materialization idiom (slaspec set2/set3 replace the target half:
# set2 = (RS & 0x0000ffff) | imm<<16, set3 = (RS & 0xffff0000) | imm).
# Buggy OR tracking would yield 0x12345678 | 0x9ab00000 = 0x9ab45678.
GOLDEN_REMAT = [
    "00710000  24051234  set2 r5,zero,0x1234",
    "00710004  20a55678  set3 r5,r5,0x5678",
    "00710008  24059ab0  set2 r5,r5,0x9ab0",
    "0071000c  6c402802  st.d r4,r5,0x0",
]

WINDOW_SLOTS = [0x3ad1, 0x3ab9]
FLASH_ADDRS = {"0x08": 0x1a000}

NOISE_LINES = [
    "00710000  deadbeef  raw 0xdeadbeef",
    "00710004  12345678  unk.r r5,0x1",
    "garbage st.d r4,r5,0x0",
    "",
]

HIT_COMMON = {"kind", "line_no", "addr", "lineage"}
KIND_KEYS = {
    "flash_addr_ref": {"cfg", "flash_addr", "how"},
    "window_write": {"word"},
    "prelude_call": {"target", "imm"},
}


def by_kind(result, kind):
    return [h for h in result["hits"] if h["kind"] == kind]


class TestBriefGoldens(unittest.TestCase):
    def test_st_in_window_is_window_write(self):
        res = bootdom_scan.scan_bootdom(GOLDEN_WINDOW_ST, {}, WINDOW_SLOTS)
        ww = by_kind(res, "window_write")
        self.assertEqual(len(ww), 1)
        self.assertEqual(ww[0]["word"], 0x3ad1)
        self.assertEqual(ww[0]["line_no"], 3)
        self.assertEqual(ww[0]["addr"], 0x710008)

    def test_ldi_imm_x4_flash_addr_is_flash_addr_ref(self):
        res = bootdom_scan.scan_bootdom(
            ["00710000  4a066800  ld.i r6,0x6800"], FLASH_ADDRS, [])
        far = by_kind(res, "flash_addr_ref")
        self.assertEqual(len(far), 1)
        self.assertEqual(far[0]["cfg"], "0x08")
        self.assertEqual(far[0]["flash_addr"], 0x1a000)
        self.assertEqual(far[0]["how"], "ld.i imm<<2")
        self.assertEqual(far[0]["line_no"], 1)
        self.assertEqual(far[0]["addr"], 0x710000)

    def test_call_0xfffeXXXX_resolves_load_base_plus_signed32(self):
        res = bootdom_scan.scan_bootdom(GOLDEN_PRELUDE_RAW, {}, [])
        pc = by_kind(res, "prelude_call")
        self.assertEqual(len(pc), 1)
        self.assertEqual(pc[0]["target"], 0x20710000 + 0xfffe42e8
                         - (1 << 32))
        self.assertEqual(pc[0]["imm"], 0xfffe42e8)
        self.assertEqual(pc[0]["line_no"], 1)
        self.assertEqual(pc[0]["addr"], 0x20710000)
        self.assertEqual(res["load_base"], 0x20710000)

    def test_call_resolved_form_below_base_is_prelude(self):
        res = bootdom_scan.scan_bootdom(GOLDEN_PRELUDE_RESOLVED, {}, [])
        pc = by_kind(res, "prelude_call")
        self.assertEqual(len(pc), 1)
        self.assertEqual(pc[0]["target"], 0x206f42e8)
        self.assertEqual(pc[0]["imm"], 0x206f42e8)

    def test_insection_call_is_not_prelude(self):
        res = bootdom_scan.scan_bootdom(GOLDEN_INSECTION_CALL, {}, [])
        self.assertEqual(by_kind(res, "prelude_call"), [])

    def test_const_materialized_flash_addr_is_flash_addr_ref(self):
        res = bootdom_scan.scan_bootdom(GOLDEN_FLASH_CONST, FLASH_ADDRS, [])
        far = by_kind(res, "flash_addr_ref")
        self.assertEqual(len(far), 1)
        self.assertEqual(far[0]["cfg"], "0x08")
        self.assertEqual(far[0]["flash_addr"], 0x1a000)
        self.assertEqual(far[0]["how"], "const")
        self.assertEqual(far[0]["line_no"], 2)

    def test_set_rematerialization_replaces_half(self):
        res = bootdom_scan.scan_bootdom(
            GOLDEN_REMAT, {"0x08": 0x9ab05678}, [])
        far = by_kind(res, "flash_addr_ref")
        self.assertEqual([h["flash_addr"] for h in far], [0x9ab05678])
        self.assertEqual(far[0]["line_no"], 3)

    def test_set_rematerialization_store_window_word(self):
        res = bootdom_scan.scan_bootdom(GOLDEN_REMAT, {}, [0x26ac159e])
        ww = by_kind(res, "window_write")
        self.assertEqual([h["word"] for h in ww], [0x26ac159e])


class TestSchemaAndGuards(unittest.TestCase):
    def test_boot_hit_schema_and_kind_key_sets(self):
        for lines in (GOLDEN_WINDOW_ST, GOLDEN_PRELUDE_RAW):
            res = bootdom_scan.scan_bootdom(lines, FLASH_ADDRS, WINDOW_SLOTS)
            self.assertEqual(set(res), {"hits", "load_base", "stats"})
            for hit in res["hits"]:
                self.assertIn(hit["kind"], bootdom_scan.KINDS)
                self.assertTrue(HIT_COMMON <= set(hit))
                self.assertEqual(set(hit) - HIT_COMMON,
                                 KIND_KEYS[hit["kind"]])

    def test_noise_lines_skipped_no_hits(self):
        stats = {}
        res = bootdom_scan.scan_bootdom(NOISE_LINES, FLASH_ADDRS,
                                        WINDOW_SLOTS, stats=stats)
        self.assertEqual(res["hits"], [])
        self.assertEqual(stats["lines"], len(NOISE_LINES))
        self.assertEqual(stats["parsed"], 0)
        self.assertEqual(stats["skipped"], len(NOISE_LINES))

    def test_lineage_default_none_and_stamped(self):
        res = bootdom_scan.scan_bootdom(GOLDEN_WINDOW_ST, {}, WINDOW_SLOTS)
        self.assertTrue(all(h["lineage"] is None for h in res["hits"]))
        stamped = bootdom_scan.scan_bootdom(GOLDEN_WINDOW_ST, {},
                                            WINDOW_SLOTS, lineage="witness")
        self.assertTrue(stamped["hits"])
        self.assertTrue(all(h["lineage"] == "witness"
                            for h in stamped["hits"]))


class TestFlashAddrForms(unittest.TestCase):
    def test_range_tuple_form(self):
        res = bootdom_scan.scan_bootdom(
            ["00710000  4a066001  ld.i r6,0x6001"],
            {"0x09": (0x18000, 0x19600)}, [])
        far = by_kind(res, "flash_addr_ref")
        self.assertEqual(len(far), 1)
        self.assertEqual(far[0]["cfg"], "0x09")
        self.assertEqual(far[0]["flash_addr"], 0x18004)

    def test_list_form_mixed(self):
        res = bootdom_scan.scan_bootdom(
            ["00710000  4a067004  ld.i r6,0x7004"],
            {"0x11": [(0x17000, 0x174c0), 0x1c010]}, [])
        far = by_kind(res, "flash_addr_ref")
        self.assertEqual(len(far), 1)
        self.assertEqual(far[0]["flash_addr"], 0x1c010)

    def test_no_flash_input_no_hits(self):
        res = bootdom_scan.scan_bootdom(
            ["00710000  4a066800  ld.i r6,0x6800"], {}, [])
        self.assertEqual(by_kind(res, "flash_addr_ref"), [])

    def test_non_flash_const_not_reported(self):
        res = bootdom_scan.scan_bootdom(
            ["00710000  24050009  set2 r5,zero,0x9d",
             "00710004  20a58ec0  set3 r5,r5,0x8ec0"], FLASH_ADDRS, [])
        self.assertEqual(by_kind(res, "flash_addr_ref"), [])

    def test_store_address_in_flash_range_adds_no_store_hit(self):
        lines = ["00710000  24050001  set2 r5,zero,0x1",
                 "00710004  20a5a000  set3 r5,r5,0xa000",
                 "00710008  6c402802  st.d r4,r5,0x0"]
        res = bootdom_scan.scan_bootdom(lines, FLASH_ADDRS, [])
        far = by_kind(res, "flash_addr_ref")
        self.assertEqual(len(far), 1)
        self.assertEqual(far[0]["how"], "const")
        self.assertEqual(far[0]["line_no"], 2)


class TestWindowSemantics(unittest.TestCase):
    def test_base_plus_offset_and_straddling_st_d(self):
        lines = ["00710000  24050000  set2 r5,zero,0x0",
                 "00710004  20a5eb3c  set3 r5,r5,0xeb3c",
                 "00710008  6c402808  st.d r4,r5,0x8"]
        res = bootdom_scan.scan_bootdom(lines, {}, WINDOW_SLOTS)
        ww = by_kind(res, "window_write")
        self.assertEqual([h["word"] for h in ww], [0x3ad1])

    def test_st_d_straddle_reports_each_matched_word(self):
        slots = [0x3ad0, 0x3ad1]
        lines = ["00710000  24050000  set2 r5,zero,0x0",
                 "00710004  20a5eb40  set3 r5,r5,0xeb40",
                 "00710008  6c402802  st.d r4,r5,0x0"]
        res = bootdom_scan.scan_bootdom(lines, {}, slots)
        self.assertEqual(sorted(h["word"] for h in by_kind(res,
                                                            "window_write")),
                         [0x3ad0, 0x3ad1])

    def test_st_w_and_st_b_touch_own_bytes_only(self):
        lines = ["00710000  24050000  set2 r5,zero,0x0",
                 "00710004  20a5eae4  set3 r5,r5,0xeae4",
                 "00710008  6c402802  st.w r4,r5,0x0",
                 "0071000c  6c402802  st.b r4,r5,0x1"]
        res = bootdom_scan.scan_bootdom(lines, {}, WINDOW_SLOTS)
        ww = by_kind(res, "window_write")
        self.assertEqual(sorted(h["word"] for h in ww), [0x3ab9, 0x3ab9])

    def test_store_1e_and_push_forms(self):
        lines = ["00710000  24050000  set2 r5,zero,0x0",
                 "00710004  20a5eb44  set3 r5,r5,0xeb44",
                 "00710008  6c402802  st.d.1e r4,r5,0x0",
                 "0071000c  6c402802  st.d! zero,r1,-0x8"]
        res = bootdom_scan.scan_bootdom(lines, {}, WINDOW_SLOTS)
        ww = by_kind(res, "window_write")
        self.assertEqual([h["word"] for h in ww], [0x3ad1])

    def test_no_window_slots_no_hits(self):
        res = bootdom_scan.scan_bootdom(GOLDEN_WINDOW_ST, {}, [])
        self.assertEqual(by_kind(res, "window_write"), [])

    def test_unknown_base_no_false_hit(self):
        lines = ["00710000  6c402802  st.d r4,r5,0x0"]
        res = bootdom_scan.scan_bootdom(lines, {}, WINDOW_SLOTS)
        self.assertEqual(by_kind(res, "window_write"), [])

    def test_ands_on_const_is_exact_and(self):
        # 16-bit ands mask: exact const AND (non-align mask must still
        # track — window byte addresses live below 0x10000).
        lines = ["00710000  24050000  set2 r5,zero,0x0",
                 "00710004  20a5ebff  set3 r5,r5,0xebff",
                 "00710008  2c85fff4  ands r5,r5,0xfff4",
                 "0071000c  6c402802  st.d r4,r5,0x0"]
        res = bootdom_scan.scan_bootdom(lines, {}, [0x3afd])
        self.assertEqual([h["word"] for h in by_kind(res, "window_write")],
                         [0x3afd])

    def test_push_updates_base_register(self):
        # st.d! stores at base+off then base += off (slaspec st.d!):
        # push writes 0xeb48..0xeb4f (no slot), follow-up store only
        # lands on word 0x3ad1 if the base was updated to 0xeb48.
        lines = ["00710000  24050000  set2 r5,zero,0x0",
                 "00710004  20a5eb50  set3 r5,r5,0xeb50",
                 "00710008  703f07f8  st.d! zero,r5,-0x8",
                 "0071000c  6c402808  st.d r4,r5,-0x8"]
        res = bootdom_scan.scan_bootdom(lines, {}, WINDOW_SLOTS)
        self.assertEqual([h["word"] for h in by_kind(res, "window_write")],
                         [0x3ad1])


def _meta(typ, flash_addr, size, param0=0, param1=0, words=0, domain="iRISC"):
    return {"typ": typ, "size": size, "flash_addr": flash_addr,
            "param0": param0, "param1": param1, "cl": False,
            "zipped": False, "dev": False, "status": "OK",
            "status_reason": "", "domain": domain, "domain_override": "",
            "domain_evidence": None, "words": words,
            "md5_raw": "0" * 32, "md5_dc": "0" * 32}


class TestCliEndToEnd(unittest.TestCase):
    def test_mini_corpus_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "corpus"
            sec = root / "cx4lx" / "14_32_2000" / "TEST-SKU" / "sections"
            sec05 = sec / "05"
            sec05.mkdir(parents=True)
            disasm = [
                "00710000  24050000  set2 r5,zero,0x0",
                "00710004  20a5eb44  set3 r5,r5,0xeb44",
                "00710008  6c402802  st.d r4,r5,0x0",
                "0071000c  4a066800  ld.i r6,0x6800",
                "00710010  94000040  call 0x710100",
                "00710014  95000000  jump 0x710014",
            ]
            (sec05 / "disasm.txt").write_text(
                "\n".join(disasm) + "\n")
            (sec05 / "meta.json").write_text(json.dumps(
                _meta(5, 0x4000, 0x104, param0=0x710000,
                      param1=0x710010, words=0x41)))
            (sec05 / "funcs.tsv").write_text(
                "entry_dc\tend_dc\tsize_words\tframe\tn_callers\n"
                "0x710010\t0x710018\t2\t0\t0\n")
            (sec05 / "calls.tsv").write_text(
                "site_dc\ttarget_dc\ttarget_section\n"
                "0x710010\t0x710100\t05\n")
            payload = bytearray(0x104)
            payload[0x100:0x104] = (0x6c201806).to_bytes(4, "big")
            (sec05 / "dc.bin").write_bytes(bytes(payload))
            (sec / "08").mkdir()
            (sec / "08" / "meta.json").write_text(json.dumps(
                _meta(8, 0x1a000, 0x140, domain="data")))
            (sec / "09").mkdir()
            (sec / "09" / "meta.json").write_text(json.dumps(
                _meta(9, 0x18000, 0x100, domain="data")))
            (sec / "11").mkdir()
            (sec / "11" / "meta.json").write_text(json.dumps(
                _meta(0x11, 0x17000, 0x50, domain="data")))
            out = Path(tmp) / "out.json"
            rc = bootdom_scan.main([
                "--corpus", str(root), "--sections", "0x05",
                "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["schema"], 1)
            img = data["images"][0]
            self.assertEqual(img["label"], "cx4lx/14_32_2000/TEST-SKU")
            self.assertEqual(sorted(img["flash_sections"]),
                             ["0x08", "0x09", "0x11"])
            hits = img["sections"]["05"]["hits"]
            # LX window preset is dense (0x3a9f..0x3b2c): an 8-byte st.d
            # at 0xeb44 legitimately writes window words 0x3ad1+0x3ad2.
            self.assertEqual(hits.get("window_write"), 2)
            self.assertEqual(hits.get("flash_addr_ref"), 1)
            self.assertEqual(hits.get("prelude_call", 0), 0)
            rec_hits = [h for h in data["hits"]
                        if h["image"] == img["label"]]
            self.assertTrue(rec_hits)
            self.assertTrue(all(h["lineage"] == "cx4lx"
                                for h in rec_hits))
            tree = img["sections"]["05"]["entry_tree"]
            self.assertTrue(tree)
            depth0 = [t for t in tree if t["depth"] == 0]
            self.assertEqual(depth0[0]["func"], "0x710010")
            self.assertEqual(depth0[0]["classes"], {"sec05:st.d": 1})


if __name__ == "__main__":
    unittest.main()
