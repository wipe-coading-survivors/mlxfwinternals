import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-prov"))

import config_sku_diff as csd  # noqa: E402
from mlxfwutil import clcrc_wrap  # noqa: E402


class TestDiffSections(unittest.TestCase):
    def test_single_two_byte_difference_merges_into_one_span(self):
        base = b"\x00" * 0x10 + bytes([0xBB, 0x01]) + b"\x00" * 8
        var = b"\x00" * 0x10 + bytes([0xFB, 0x02]) + b"\x00" * 8
        diffs = csd.diff_sections({"base": base, "var": var})
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0]["offset"], 0x10)
        self.assertEqual(diffs[0]["span"], 2)
        self.assertEqual(diffs[0]["values"], {"base": 0xBB, "var": 0xFB})

    def test_separated_differences_stay_separate(self):
        base = b"\x01\x00\x00\x02"
        var = b"\x03\x00\x00\x04"
        diffs = csd.diff_sections({"base": base, "var": var})
        self.assertEqual([(d["offset"], d["span"]) for d in diffs],
                         [(0, 1), (3, 1)])

    def test_identical_payloads_give_no_diff(self):
        self.assertEqual(csd.diff_sections({"a": b"abcd", "b": b"abcd"}), [])

    def test_diff_uses_common_prefix_length(self):
        diffs = csd.diff_sections({"a": b"\x00", "b": b"\x00\xFF"})
        self.assertEqual(diffs, [])


class TestSectionPayload(unittest.TestCase):
    def _img(self, entries, data=b""):
        return SimpleNamespace(
            path="img.bin",
            entries=lambda toc: entries,
            section_data=lambda e: data,
        )

    def test_cl1_frame_with_bad_crc_is_hard_error(self):
        framed = bytearray(clcrc_wrap(b"\xAA" * 64))
        framed[66] ^= 0xFF
        e = SimpleNamespace(type=0x09, zipped=0, clcrc=1)
        with self.assertRaises(csd.SectionDecodeError) as cm:
            csd.section_payload(self._img([e], bytes(framed)), 0x09)
        self.assertIn("cl=1", str(cm.exception))

    def test_cl1_frame_decodes_to_payload(self):
        e = SimpleNamespace(type=0x09, zipped=0, clcrc=1)
        out = csd.section_payload(
            self._img([e], clcrc_wrap(b"\xAA" * 64)), 0x09)
        self.assertEqual(out, b"\xAA" * 64)

    def test_cl0_payload_passes_through(self):
        e = SimpleNamespace(type=0x09, zipped=0, clcrc=0)
        out = csd.section_payload(self._img([e], b"\x01\x02"), 0x09)
        self.assertEqual(out, b"\x01\x02")

    def test_two_entries_same_type_is_ambiguous_section(self):
        e1 = SimpleNamespace(type=0x09, zipped=0, clcrc=0)
        e2 = SimpleNamespace(type=0x09, zipped=0, clcrc=0)
        with self.assertRaises(csd.AmbiguousSectionError) as cm:
            csd.section_payload(self._img([e1, e2]), 0x09)
        self.assertIn("ambiguous section", str(cm.exception))

    def test_missing_section_raises_keyerror(self):
        with self.assertRaises(KeyError):
            csd.section_payload(self._img([]), 0x09)

    def test_zipped_section_is_hard_error(self):
        e = SimpleNamespace(type=0x09, zipped=1, clcrc=0)
        with self.assertRaises(csd.SectionDecodeError):
            csd.section_payload(self._img([e], b"\x00"), 0x09)


class TestResolveAndCrosscheck(unittest.TestCase):
    def test_resolve_prefers_repo_local_refs_suffix(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            img = repo / "refs" / "fw" / "x.bin"
            img.parent.mkdir(parents=True)
            img.write_bytes(b"x")
            recorded = "/nonexistent/worktree/refs/fw/x.bin"
            self.assertEqual(csd.resolve_image_path(recorded, repo), img)

    def test_resolve_relative_path_against_repo(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            img = repo / "refs" / "fw" / "x.bin"
            img.parent.mkdir(parents=True)
            img.write_bytes(b"x")
            self.assertEqual(csd.resolve_image_path("refs/fw/x.bin", repo), img)

    def test_resolve_unresolvable_raises(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FileNotFoundError):
                csd.resolve_image_path("refs/fw/missing.bin", Path(td))

    def test_crosscheck_ok_absent_and_mismatch(self):
        payload = b"payload"
        digest = csd.hashlib.md5(payload).hexdigest()
        self.assertEqual(csd.crosscheck_md5(payload, digest), "ok")
        self.assertEqual(csd.crosscheck_md5(payload, None), "absent")
        with self.assertRaises(ValueError):
            csd.crosscheck_md5(payload, "0" * 32)


if __name__ == "__main__":
    unittest.main()
