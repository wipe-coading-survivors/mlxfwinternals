import hashlib
import sys
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "probes" / "serdes-prov"))

import a16_diff as ad  # noqa: E402
from mlxfwutil import clcrc_wrap, set_image_info_fields  # noqa: E402


def fake_img(section_specs, path="img.bin"):
    """Arc-C-convention synthetic image: {type: (payload, cl, zipped)}."""
    entries = []
    data = {}
    for typ, (payload, cl, zipped) in section_specs.items():
        raw = clcrc_wrap(payload) if cl and payload else payload
        e = SimpleNamespace(type=typ, zipped=zipped, clcrc=cl,
                            size=len(raw))
        entries.append(e)
        data[typ] = raw
    return SimpleNamespace(
        path=path,
        entries=lambda toc: list(entries),
        section_data=lambda e: data[e.type],
    )


class TestSectionFingerprints(unittest.TestCase):
    def test_cl0_fingerprint_dc_equals_raw(self):
        img = fake_img({0x08: (b"\x11" * 32, 0, 0)})
        fps = ad.section_fingerprints(img)
        self.assertEqual(fps[0x08]["status"], "OK")
        self.assertEqual(fps[0x08]["md5_dc"], fps[0x08]["md5_raw"])
        self.assertEqual(fps[0x08]["md5_raw"],
                         hashlib.md5(b"\x11" * 32).hexdigest())
        self.assertEqual(fps[0x08]["size"], 32)
        self.assertFalse(fps[0x08]["cl"])

    def test_cl1_fingerprint_decodes_payload(self):
        payload = b"\xAA" * 128
        img = fake_img({0x03: (payload, 1, 0)})
        fps = ad.section_fingerprints(img)
        self.assertEqual(fps[0x03]["status"], "OK")
        self.assertEqual(fps[0x03]["md5_dc"],
                         hashlib.md5(payload).hexdigest())
        self.assertNotEqual(fps[0x03]["md5_dc"], fps[0x03]["md5_raw"])
        self.assertTrue(fps[0x03]["cl"])

    def test_zipped_section_is_recorded_error(self):
        img = fake_img({0x0B: (b"\x00", 0, 1)})
        fps = ad.section_fingerprints(img)
        self.assertEqual(fps[0x0B]["status"], "ERROR")
        self.assertIn("zipped", fps[0x0B]["status_reason"])
        self.assertIsNone(fps[0x0B]["md5_dc"])

    def test_bad_clcrc_is_recorded_error(self):
        framed = bytearray(clcrc_wrap(b"\xBB" * 64))
        framed[66] ^= 0xFF
        e = SimpleNamespace(type=0x09, zipped=0, clcrc=1, size=len(framed))
        img = SimpleNamespace(path="img.bin", entries=lambda toc: [e],
                              section_data=lambda ent: bytes(framed))
        fps = ad.section_fingerprints(img)
        self.assertEqual(fps[0x09]["status"], "ERROR")
        self.assertIsNone(fps[0x09]["md5_dc"])

    def test_duplicate_entries_recorded_error(self):
        e1 = SimpleNamespace(type=0x08, zipped=0, clcrc=0, size=8)
        e2 = SimpleNamespace(type=0x08, zipped=0, clcrc=0, size=8)
        img = SimpleNamespace(path="img.bin", entries=lambda toc: [e1, e2],
                              section_data=lambda ent: b"\x00" * 8)
        fps = ad.section_fingerprints(img)
        self.assertEqual(fps[0x08]["status"], "ERROR")
        self.assertIn("ambiguous", fps[0x08]["status_reason"])
        self.assertIsNone(fps[0x08]["md5_dc"])


class TestVerdicts(unittest.TestCase):
    def test_identical_cl0(self):
        a = fake_img({0x05: (b"\x01" * 64, 0, 0)})
        b = fake_img({0x05: (b"\x01" * 64, 0, 0)})
        v = ad.compare_fingerprints(ad.section_fingerprints(a),
                                    ad.section_fingerprints(b))
        self.assertEqual(v[0x05]["verdict"], "identical")
        self.assertTrue(v[0x05]["raw_identical"])

    def test_different(self):
        a = fake_img({0x05: (b"\x01" * 64, 0, 0)})
        b = fake_img({0x05: (b"\x02" * 64, 0, 0)})
        v = ad.compare_fingerprints(ad.section_fingerprints(a),
                                    ad.section_fingerprints(b))
        self.assertEqual(v[0x05]["verdict"], "different")
        self.assertEqual(v[0x05]["sizes"], (64, 64))

    def test_size_mismatch_is_different(self):
        a = fake_img({0x0A: (b"\x01" * 16, 0, 0)})
        b = fake_img({0x0A: (b"\x01" * 32, 0, 0)})
        v = ad.compare_fingerprints(ad.section_fingerprints(a),
                                    ad.section_fingerprints(b))
        self.assertEqual(v[0x0A]["verdict"], "different")
        self.assertEqual(v[0x0A]["sizes"], (16, 32))

    def test_cl1_same_payload_different_framing_is_identical(self):
        payload = b"\x33" * 128
        a = fake_img({0x03: (payload, 1, 0)})
        b = fake_img({0x03: (payload, 1, 0)})
        fa = ad.section_fingerprints(a)
        fb = ad.section_fingerprints(b)
        fb[0x03]["md5_raw"] = "0" * 32
        v = ad.compare_fingerprints(fa, fb)
        self.assertEqual(v[0x03]["verdict"], "identical")
        self.assertFalse(v[0x03]["raw_identical"])

    def test_absent_when_only_in_one_side(self):
        a = fake_img({0x18: (b"\x55\xaa" * 8, 0, 0)})
        b = fake_img({0x20: (b"\x00" * 8, 0, 0)})
        v = ad.compare_fingerprints(ad.section_fingerprints(a),
                                    ad.section_fingerprints(b))
        self.assertEqual(v[0x18]["verdict"], "absent")
        self.assertEqual(v[0x18]["only_in"], "a16")
        self.assertEqual(v[0x20]["verdict"], "absent")
        self.assertEqual(v[0x20]["only_in"], "baseline")

    def test_error_side_makes_verdict_error(self):
        a = fake_img({0x0B: (b"\x00", 0, 1)})
        b = fake_img({0x0B: (b"\x00" * 16, 0, 0)})
        v = ad.compare_fingerprints(ad.section_fingerprints(a),
                                    ad.section_fingerprints(b))
        self.assertEqual(v[0x0B]["verdict"], "error")


class TestIni(unittest.TestCase):
    def test_ini_payload_zlib_roundtrip(self):
        text = "[foo]\nbar = 1\n"
        img = fake_img({0x30: (zlib.compress(text.encode()), 0, 0)})
        self.assertEqual(ad.ini_text(img), text)

    def test_ini_payload_rejects_non_zlib(self):
        img = fake_img({0x30: (b"not-zlib", 0, 0)})
        with self.assertRaises(ValueError):
            ad.ini_text(img)

    def test_unified_diff_labels_and_lines(self):
        a = "a = 1\nb = 2\n"
        b = "a = 1\nb = 3\n"
        out = ad.unified_diff_text(a, b, "from/x", "to/y")
        self.assertIn("--- from/x", out)
        self.assertIn("+++ to/y", out)
        self.assertIn("-b = 2", out)
        self.assertIn("+b = 3", out)

    def test_unified_diff_identical_is_empty(self):
        self.assertEqual(ad.unified_diff_text("x\n", "x\n", "a", "b"), "")


class TestImageInfo(unittest.TestCase):
    def _info_img(self, name, psid):
        data = set_image_info_fields(
            b"\x00" * 0x400, psid=psid, name=name,
            description="desc")
        raw = bytearray(data)
        raw[0x1c:0x1e] = (0x101B).to_bytes(2, "big")
        return fake_img({0x10: (bytes(raw), 0, 0)})

    def test_fields_and_device_id(self):
        img = self._info_img("PG171_Ax", "NVD0000000014")
        info = ad.image_info(img)
        self.assertEqual(info["name"], "PG171_Ax")
        self.assertEqual(info["psid"], "NVD0000000014")
        self.assertEqual(info["description"], "desc")
        self.assertEqual(info["device_id"], "0x101b")

    def test_absent_image_info_raises(self):
        img = fake_img({0x08: (b"\x00" * 8, 0, 0)})
        with self.assertRaises(KeyError):
            ad.image_info(img)


class TestConfigDiff(unittest.TestCase):
    def test_reuses_config_sku_diff_spans_with_hex(self):
        base = b"\x00" * 0x10 + b"\x01" + b"\x00" * 8
        var = b"\x00" * 0x10 + b"\x02" + b"\x00" * 8
        a = fake_img({0x09: (base, 0, 0)})
        b = fake_img({0x09: (var, 0, 0)})
        out = ad.config_diffs(a, b, types=(0x09,))
        self.assertEqual(len(out["09"]), 1)
        span = out["09"][0]
        self.assertEqual(span["offset"], 0x10)
        self.assertEqual(span["hex"], {"a16": "01", "base": "02"})

    def test_identical_configs_give_no_spans(self):
        a = fake_img({0x08: (b"\x00" * 16, 0, 0)})
        b = fake_img({0x08: (b"\x00" * 16, 0, 0)})
        out = ad.config_diffs(a, b, types=(0x08,))
        self.assertEqual(out["08"], [])

    def test_absent_config_section_recorded(self):
        a = fake_img({0x08: (b"\x00" * 16, 0, 0)})
        b = fake_img({0x11: (b"\x00" * 16, 0, 0)})
        out = ad.config_diffs(a, b, types=(0x11,))
        self.assertEqual(out["11"], {"absent": True})


class TestCollectImages(unittest.TestCase):
    def _make_root(self, td):
        root = Path(td)
        refs = root / "refs" / "fw"
        refs.mkdir(parents=True)
        payload = b"corpus image"
        img = refs / "a.bin"
        img.write_bytes(payload)
        return root, img, hashlib.md5(payload).hexdigest()

    def test_resolves_labels_and_gates_md5(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root, img, md5 = self._make_root(td)
            ref = ad.ImageRef(path=img, md5=md5, family="cx6",
                              ver="20_43_8002", sku="X", tier=3,
                              path_rel=Path("refs/fw/a.bin"))
            old = ad.T3
            ad.T3 = [ref]
            try:
                got = ad.collect_images(root, ["cx6/20_43_8002/X"])
                self.assertEqual([r.sku for r in got], ["X"])
                bad = ad.ImageRef(path=img, md5="0" * 32, family="cx6",
                                  ver="20_43_8002", sku="X", tier=3)
                ad.T3 = [bad]
                with self.assertRaises(ad.CorpusManifestError):
                    ad.collect_images(root, ["cx6/20_43_8002/X"])
            finally:
                ad.T3 = old

    def test_unknown_label_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root, img, md5 = self._make_root(td)
            ref = ad.ImageRef(path=img, md5=md5, family="cx6",
                              ver="20_43_8002", sku="X", tier=3)
            old = ad.T3
            ad.T3 = [ref]
            try:
                with self.assertRaises(ad.CorpusManifestError) as ctx:
                    ad.collect_images(root, ["cx6/20_43_8002/NOPE"])
                self.assertIn("unknown image label", str(ctx.exception))
            finally:
                ad.T3 = old


class TestIniDiffArtifacts(unittest.TestCase):
    def test_ini_diff_written_for_every_baseline(self):
        import tempfile
        info = set_image_info_fields(
            b"\x00" * 0x400, psid="NVD0000000014", name="PG171_Ax",
            description="desc")
        images = {"a16": fake_img(
            {0x10: (info, 0, 0),
             0x30: (zlib.compress(b"[ini]\nx = 1\n"), 0, 0)})}
        base_labels = []
        for tag, text in (("a", b"[ini]\nx = 1\n"),
                          ("b", b"[ini]\nx = 2\n"),
                          ("c", b"[ini]\nx = 3\ny = 7\n")):
            label = "cx6/20_43_000" + tag + "/MCX654105A-HCA"
            images[label] = fake_img(
                {0x10: (info, 0, 0),
                 0x30: (zlib.compress(text), 0, 0)})
            base_labels.append(label)
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            report = ad.build_report("a16", base_labels, images, out_dir)
            for tag in ("a", "b", "c"):
                path = out_dir / ("a16-ini.%s.diff.txt" % tag)
                self.assertTrue(path.is_file(), tag)
            third = out_dir / "a16-ini.c.diff.txt"
            self.assertGreater(third.stat().st_size, 0)
            self.assertIn("+y = 7", third.read_text())
            self.assertEqual(sorted(report["ini_diff"]), base_labels)


class TestMainRefusals(unittest.TestCase):
    def _run_main(self, images):
        import contextlib
        import io
        import tempfile

        def fake_collect_images(refs_root, labels):
            return [SimpleNamespace(path=label) for label in labels]

        def fake_load_image(ref):
            return images[ref.path]

        old_collect, old_load = ad.collect_images, ad.load_image
        ad.collect_images = fake_collect_images
        ad.load_image = fake_load_image
        err = io.StringIO()
        try:
            with tempfile.TemporaryDirectory() as td, \
                    contextlib.redirect_stderr(err):
                rc = ad.main(["--a16", "a16", "--baseline", "base",
                              "--out-dir", td])
        finally:
            ad.collect_images = old_collect
            ad.load_image = old_load
        return rc, err.getvalue()

    def test_non_zlib_ini_is_refused(self):
        info = set_image_info_fields(
            b"\x00" * 0x400, psid="NVD0000000014", name="PG171_Ax",
            description="desc")
        a16 = fake_img({0x10: (info, 0, 0), 0x30: (b"not-zlib", 0, 0)})
        base = fake_img({0x10: (info, 0, 0),
                         0x30: (zlib.compress(b"[ini]\nx = 1\n"), 0, 0)})
        rc, err = self._run_main({"a16": a16, "base": base})
        self.assertEqual(rc, 2)
        self.assertIn("refused:", err)
        self.assertIn("not a zlib stream", err)

    def test_missing_image_info_is_refused(self):
        a16 = fake_img({0x08: (b"\x00" * 16, 0, 0)})
        base = fake_img({0x08: (b"\x00" * 16, 0, 0)})
        rc, err = self._run_main({"a16": a16, "base": base})
        self.assertEqual(rc, 2)
        self.assertIn("refused:", err)
        self.assertIn("0x10", err)


if __name__ == "__main__":
    unittest.main()
