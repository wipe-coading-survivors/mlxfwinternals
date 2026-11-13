import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
F5 = REPO / "scripts" / "probes" / "cx5-fuzz5"


def run_py(script, args, cwd=None):
    return subprocess.run(
        [sys.executable, str(script)] + list(args),
        capture_output=True, text=True, cwd=cwd)


class TestSelectMergesCli(unittest.TestCase):
    def test_no_args_exits_nonzero_with_required_message(self):
        r = run_py(F5 / "select_merges.py", [])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("required", r.stderr)
        self.assertIn("--state-battery", r.stderr)
        self.assertIn("--state-disc", r.stderr)

    def test_source_has_no_tmp_opencode_paths(self):
        self.assertNotIn(
            "/tmp/opencode", (F5 / "select_merges.py").read_text())


class TestConsolidateBatteryCli(unittest.TestCase):
    def test_no_args_exits_nonzero_with_required_message(self):
        r = run_py(F5 / "consolidate_battery.py", [])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("required", r.stderr)
        for a in ("--vectors", "--disc", "--state-battery", "--state-disc"):
            self.assertIn(a, r.stderr)

    def test_run_from_outside_repo_writes_out(self):
        census = json.loads((F5 / "census_map.json").read_text())
        row_id = census["rows"][0]["id"]
        vectors = [{"id": "V-T1", "group": "fixture",
                    "census_rows": [row_id], "words": ["00000000"]}]
        disc = [{"id": "V-T1D", "group": "fixture-disc",
                 "census_rows": [row_id]}]
        state_b = {"completed": {
            "V-T1": {"verdicts": {
                "H-fx": {"verdict": "жива",
                         "observed": {"cr0x8c8": "0x0"}},
                "H-dead": {"verdict": "убита",
                           "observed": {"cr0x8c8": "0x1"}},
                "H-und": {"verdict": "неопределена"}}},
        }}
        state_d = {"completed": {
            "V-T1D": {"verdicts": {"H-fx": {"verdict": "жива"}},
                      "divergence": True},
        }}
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            decoy = tmp / "scripts" / "probes" / "cx5-fuzz5" / "census_map.json"
            decoy.parent.mkdir(parents=True)
            decoy.write_text(json.dumps(
                {"rows": [{"id": "mini-decoy-row", "op": "0x0c",
                           "selector": {}, "class": "zero-sites"}],
                 "verdicts": []}))
            vec_p = tmp / "vectors.json"
            disc_p = tmp / "disc.json"
            stb_p = tmp / "state_battery.json"
            std_p = tmp / "state_disc.json"
            out_p = tmp / "out" / "consolidation.txt"
            out_p.parent.mkdir()
            vec_p.write_text(json.dumps(vectors))
            disc_p.write_text(json.dumps(disc))
            stb_p.write_text(json.dumps(state_b))
            std_p.write_text(json.dumps(state_d))
            r = run_py(
                F5 / "consolidate_battery.py",
                ["--vectors", str(vec_p), "--disc", str(disc_p),
                 "--state-battery", str(stb_p), "--state-disc", str(std_p),
                 "--out", str(out_p)],
                cwd=str(tmp))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue(out_p.is_file(), r.stdout + r.stderr)
            self.assertGreater(out_p.stat().st_size, 0)
            table = out_p.read_text()
            self.assertIn(row_id, table)
            self.assertIn("V-T1D", table)

    def test_source_has_no_tmp_opencode_paths(self):
        self.assertNotIn(
            "/tmp/opencode", (F5 / "consolidate_battery.py").read_text())


class TestGhidraImportFileBasename(unittest.TestCase):
    def test_make_dry_run_imports_ghidra_name_bin(self):
        r = subprocess.run(
            ["make", "-n", "CRE=true", "ghidra-import-file",
             "FILE=/tmp/x.bin", "NAME=t"],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('cp "/tmp/x.bin" build/ghidra-t.bin', r.stdout)
        self.assertIn("import /work/build/ghidra-t.bin", r.stdout)


if __name__ == "__main__":
    unittest.main()
