import random
import struct
import sys
import unittest
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import mlxfwutil  # noqa: E402
from scripts.probes.romdump import zone_classify  # noqa: E402

REFS = REPO / "refs/fw/cx-5-6/dumps/cx5-rom-2026-11-15"

BLOCK = 4096


def synth_zone(seed_bytes):
    return random.Random(0x5A5A).randbytes(2 * BLOCK + 123)


class TestMatchFormsSynthetic(unittest.TestCase):
    def setUp(self):
        self.needle = synth_zone(None)
        filler = b"\x11" * 512 + self.needle + b"\x22" * 512

    def test_raw_form_matches(self):
        report = zone_classify.match_forms(
            self.needle, {"raw_src": b"\x00" * 64 + self.needle})
        self.assertEqual(report["forms"]["raw_src"]["matched_windows"], 3)

    def test_no_match_in_unrelated_source(self):
        report = zone_classify.match_forms(
            self.needle, {"raw_src": b"\xab" * 8192})
        self.assertEqual(report["forms"]["raw_src"]["matched_windows"], 0)
        self.assertFalse(report["forms"]["raw_src"]["found"])

    def test_partial_window_match_counted(self):
        src = b"\x00" * 16 + self.needle[:BLOCK] + b"\x00" * 16
        report = zone_classify.match_forms(self.needle, {"raw_src": src})
        self.assertEqual(report["forms"]["raw_src"]["matched_windows"], 1)

    def test_first_offsets_reported(self):
        src = b"\x00" * 16 + self.needle
        report = zone_classify.match_forms(self.needle, {"raw_src": src})
        f = report["forms"]["raw_src"]
        self.assertEqual(f["first_zone_off"], 0)
        self.assertEqual(f["first_src_off"], 16)

    def test_clcrc_declcrc_form(self):
        payload = self.needle + b"\x00" * ((64 - len(self.needle) % 64) % 64)
        raw = mlxfwutil.clcrc_wrap(payload, b"\x00" * 4)
        self.assertNotIn(self.needle[:128], raw)
        sources = {"sec_payload": raw}
        report = zone_classify.match_forms(self.needle, sources)
        self.assertEqual(report["forms"]["sec_payload"]["matched_windows"], 0)
        decl = zone_classify.declcrc_source(raw)
        self.assertIn(self.needle[:BLOCK], decl)
        report2 = zone_classify.match_forms(
            self.needle, {"sec_declcrc": decl})
        self.assertEqual(report2["forms"]["sec_declcrc"]["matched_windows"], 3)

    def test_init_pages_form(self):
        pages = []
        for i in range(0, len(self.needle), BLOCK):
            page = self.needle[i:i + BLOCK]
            page += b"\x00" * (BLOCK - len(page))
            pages.append(struct.pack(">Q", 0x1000000 + i) + page)
        raw = b"".join(pages)
        self.assertNotIn(self.needle[:BLOCK], raw[:BLOCK])
        data = zone_classify.parse_init_records(raw)
        self.assertEqual(len(data), 3 * BLOCK)
        report = zone_classify.match_forms(self.needle,
                                           {"init_pages_data": data})
        self.assertEqual(report["forms"]["init_pages_data"]["matched_windows"],
                         3)

    def test_compressed_form(self):
        payload = b"".join(b"line %04d: romdump fixture\n" % i
                           for i in range(400))
        packed = zlib.compress(payload, 9)
        self.assertLess(len(packed), len(payload) // 2)
        self.assertNotIn(payload[:256], packed)
        forms = zone_classify.try_decompress(packed)
        self.assertIn("zlib", forms)
        self.assertIn(payload[:BLOCK], forms["zlib"])

    def test_incompressible_random_zone_matches_nothing(self):
        rng = random.Random(0xC0DE).randbytes(3 * BLOCK + 5)
        sources = {"raw_src": b"\x00" * 65536}
        report = zone_classify.match_forms(rng, sources)
        self.assertEqual(report["forms"]["raw_src"]["matched_windows"], 0)

    def test_degenerate_zero_windows_do_not_create_hits(self):
        zone = self.needle[:BLOCK] + b"\x00" * (2 * BLOCK) + self.needle[BLOCK:2 * BLOCK]
        report = zone_classify.match_forms(
            zone, {"raw_src": b"\x00" * 65536})
        self.assertEqual(report["degenerate_windows"], [BLOCK, 2 * BLOCK])
        self.assertEqual(report["forms"]["raw_src"]["matched_windows"], 0)

    def test_classify_verdict_helper(self):
        report = zone_classify.match_forms(
            self.needle, {"hit": self.needle, "miss": b"\x00" * 8192})
        v = zone_classify.classify(report)
        self.assertEqual(v, "hit")
        empty = zone_classify.match_forms(self.needle,
                                          {"miss": b"\x00" * 8192})
        self.assertEqual(zone_classify.classify(empty), "no_flash_match")


class TestDwordSwap(unittest.TestCase):
    def test_dswap_roundtrip(self):
        data = bytes(range(256)) * 8
        swapped = zone_classify.dword_swap(data)
        self.assertEqual(zone_classify.dword_swap(swapped), data)
        self.assertEqual(swapped[:4], bytes([3, 2, 1, 0]))


@pytest.mark.slow
class TestFlashSources(unittest.TestCase):
    def setUp(self):
        if not REFS.exists():
            raise unittest.SkipTest("refs/fw/cx-5-6/dumps not present")

    def test_inventory_keys_and_sizes(self):
        inv = zone_classify.flash_sources(REFS)
        for key in ("ri_raw", "flash_data_raw", "flash_data_dswap",
                    "itoc_03_payload", "itoc_03_declcrc",
                    "init_pages_raw", "init_pages_data", "boot_pages_data"):
            self.assertIn(key, inv, key)
        self.assertEqual(len(inv["ri_raw"]), 16 * 1024 * 1024)
        self.assertEqual(len(inv["itoc_03_declcrc"]), 0x397DC0)
        self.assertEqual(len(inv["boot_pages_data"]), 6 * 4096)
        self.assertEqual(len(inv["init_pages_data"]) % 4096, 0)

    def test_main_head_found_in_declcrc(self):
        inv = zone_classify.flash_sources(REFS)
        head = inv["itoc_03_declcrc"][:8192]
        report = zone_classify.match_forms(head, inv)
        self.assertGreater(
            report["forms"]["itoc_03_declcrc"]["matched_windows"], 0)
