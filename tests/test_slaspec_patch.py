import hashlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "irisc"))

import slaspec_patch  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "slaspec"
BASE = FIXTURES / "base.slaspec"
RESULT = FIXTURES / "result.slaspec"
PATCH = FIXTURES / "result.patch"

REAL_PATCH = REPO / "scripts" / "irisc" / "iRISC.slaspec.patch"
REAL_CACHE = REPO / "build" / "slaspec-cache"
REAL_CANON = REPO / "scripts" / "irisc" / "iRISC.slaspec"
COMPANION_UPSTREAM = (
    REPO.parent / "ghidra-container" / "scripts" / "irisc"
    / "iRISC.upstream.slaspec")


def sha(data):
    return hashlib.sha256(data).hexdigest()


class TestGenSynthetic:
    def test_gen_restores_result_bitwise(self, tmp_path):
        out = tmp_path / "iRISC.slaspec"
        got = slaspec_patch.gen(
            out=out, upstream=BASE, patch=PATCH, cache=tmp_path / "cache")
        assert got == out
        assert out.read_bytes() == RESULT.read_bytes()

    def test_gen_materializes_pristine_upstream(self, tmp_path):
        out = tmp_path / "iRISC.slaspec"
        slaspec_patch.gen(
            out=out, upstream=BASE, patch=PATCH, cache=tmp_path / "cache")
        upstream_out = tmp_path / "iRISC.upstream.slaspec"
        assert upstream_out.read_bytes() == BASE.read_bytes()

    def test_gen_noop_when_outputs_match(self, tmp_path):
        out = tmp_path / "iRISC.slaspec"
        slaspec_patch.gen(
            out=out, upstream=BASE, patch=PATCH, cache=tmp_path / "cache")
        got = slaspec_patch.gen(
            out=out, upstream=tmp_path / "absent.slaspec", patch=PATCH,
            cache=tmp_path / "cache")
        assert got == out
        assert out.read_bytes() == RESULT.read_bytes()

    def test_gen_upstream_sha_mismatch_is_integrity_error(self, tmp_path):
        bad = tmp_path / "bad-upstream.slaspec"
        bad.write_bytes(BASE.read_bytes().replace(b"alignment=4",
                                                  b"alignment=5"))
        with pytest.raises(slaspec_patch.IntegrityError):
            slaspec_patch.gen(out=tmp_path / "iRISC.slaspec", upstream=bad,
                              patch=PATCH, cache=tmp_path / "cache")

    def test_gen_result_sha_mismatch_is_integrity_error(self, tmp_path):
        header = PATCH.read_text().splitlines(keepends=True)
        header = [l for l in header if not l.startswith("# result-sha256:")]
        header.insert(2, "# result-sha256: %s\n" % sha(b"something-else"))
        tampered = tmp_path / "tampered.patch"
        tampered.write_text("".join(header) + "".join(
            PATCH.read_text().splitlines(keepends=True)[3:]))
        with pytest.raises(slaspec_patch.IntegrityError):
            slaspec_patch.gen(out=tmp_path / "iRISC.slaspec", upstream=BASE,
                              patch=tampered, cache=tmp_path / "cache")

    def test_gen_context_mismatch_is_integrity_error(self, tmp_path):
        lines = PATCH.read_text().splitlines(keepends=True)
        ctx = next(i for i, l in enumerate(lines) if l.startswith(" define"))
        lines[ctx] = " define TAMPERED;\n"
        tampered = tmp_path / "tampered.patch"
        tampered.write_text("".join(lines))
        with pytest.raises(slaspec_patch.IntegrityError):
            slaspec_patch.gen(out=tmp_path / "iRISC.slaspec", upstream=BASE,
                              patch=tampered, cache=tmp_path / "cache")

    def test_gen_missing_source_is_unavailable(self, tmp_path):
        with pytest.raises(slaspec_patch.SourceUnavailableError):
            slaspec_patch.gen(out=tmp_path / "iRISC.slaspec",
                              upstream=tmp_path / "absent.slaspec",
                              patch=PATCH, cache=tmp_path / "cache")

    def test_gen_uses_cache_offline(self, tmp_path):
        cache = tmp_path / "cache"
        slaspec_patch.gen(out=tmp_path / "iRISC.slaspec", upstream=BASE,
                          patch=PATCH, cache=cache)
        out2 = tmp_path / "again.slaspec"
        slaspec_patch.gen(out=out2, upstream=tmp_path / "absent.slaspec",
                          patch=PATCH, cache=cache)
        assert out2.read_bytes() == RESULT.read_bytes()
        assert (tmp_path / "again.upstream.slaspec").read_bytes() \
            == BASE.read_bytes()

    def test_gen_corrupted_cache_entry_refetched(self, tmp_path):
        cache = tmp_path / "cache"
        out = tmp_path / "iRISC.slaspec"
        slaspec_patch.gen(out=out, upstream=BASE, patch=PATCH, cache=cache)
        entry = next(cache.iterdir())
        entry.write_bytes(b"corrupted")
        out.unlink()
        slaspec_patch.gen(out=out, upstream=BASE, patch=PATCH, cache=cache)
        assert sha(entry.read_bytes()) == sha(BASE.read_bytes())


class TestGenCli:
    def test_main_gen_rc0(self, tmp_path):
        rc = slaspec_patch.main([
            "gen", "--out", str(tmp_path / "iRISC.slaspec"),
            "--upstream", str(BASE), "--patch", str(PATCH),
            "--cache", str(tmp_path / "cache")])
        assert rc == 0
        assert (tmp_path / "iRISC.slaspec").read_bytes() \
            == RESULT.read_bytes()

    def test_main_gen_source_unavailable_rc2(self, tmp_path):
        rc = slaspec_patch.main([
            "gen", "--out", str(tmp_path / "iRISC.slaspec"),
            "--upstream", str(tmp_path / "absent.slaspec"),
            "--patch", str(PATCH), "--cache", str(tmp_path / "cache")])
        assert rc == 2

    def test_main_gen_integrity_rc1(self, tmp_path):
        bad = tmp_path / "bad-upstream.slaspec"
        bad.write_bytes(BASE.read_bytes() + b"\n# extra\n")
        rc = slaspec_patch.main([
            "gen", "--out", str(tmp_path / "iRISC.slaspec"),
            "--upstream", str(bad), "--patch", str(PATCH),
            "--cache", str(tmp_path / "cache")])
        assert rc == 1


class TestRegen:
    def test_regen_roundtrip_gen_equals_canon(self, tmp_path):
        patch = tmp_path / "p.patch"
        slaspec_patch.regen(canon=RESULT, upstream=BASE, patch=patch,
                            cache=tmp_path / "cache")
        out = tmp_path / "iRISC.slaspec"
        slaspec_patch.gen(out=out, upstream=BASE, patch=patch,
                          cache=tmp_path / "cache")
        assert out.read_bytes() == RESULT.read_bytes()

    def test_regen_reproduces_fixture_patch(self, tmp_path):
        patch = tmp_path / "p.patch"
        slaspec_patch.regen(canon=RESULT, upstream=BASE, patch=patch,
                            cache=tmp_path / "cache")
        assert patch.read_bytes() == PATCH.read_bytes()

    def test_regen_idempotent(self, tmp_path):
        first = tmp_path / "first.patch"
        second = tmp_path / "second.patch"
        slaspec_patch.regen(canon=RESULT, upstream=BASE, patch=first,
                            cache=tmp_path / "cache")
        slaspec_patch.regen(canon=RESULT, upstream=BASE, patch=second,
                            cache=tmp_path / "cache")
        assert first.read_bytes() == second.read_bytes()

    def test_regen_header_fields(self, tmp_path):
        patch = tmp_path / "p.patch"
        slaspec_patch.regen(canon=RESULT, upstream=BASE, patch=patch,
                            cache=tmp_path / "cache")
        header, _ = slaspec_patch.read_patch(patch)
        assert header["upstream"] == slaspec_patch.DEFAULT_UPSTREAM_PIN
        assert header["upstream-sha256"] == sha(BASE.read_bytes())
        assert header["result-sha256"] == sha(RESULT.read_bytes())

    def test_regen_canon_missing_is_unavailable(self, tmp_path):
        with pytest.raises(slaspec_patch.SourceUnavailableError):
            slaspec_patch.regen(canon=tmp_path / "absent.slaspec",
                                upstream=BASE, patch=tmp_path / "p.patch",
                                cache=tmp_path / "cache")


class TestRealArtifact:
    def _upstream_source(self, expected, tmp_path):
        cached = REAL_CACHE / (expected + ".slaspec")
        if cached.is_file() and sha(cached.read_bytes()) == expected:
            return cached
        if COMPANION_UPSTREAM.is_file():
            data = COMPANION_UPSTREAM.read_bytes()
            if sha(data) == expected:
                return COMPANION_UPSTREAM
            lines = data.splitlines(keepends=True)
            i = 0
            while i < len(lines) and lines[i].startswith(b"#"):
                i += 1
            stripped = b"".join(lines[i:])
            if sha(stripped) == expected:
                src = tmp_path / "upstream-stripped.slaspec"
                src.write_bytes(stripped)
                return src
        return None

    def test_gen_real_patch_restores_canon(self, tmp_path):
        if not REAL_PATCH.is_file():
            pytest.skip("scripts/irisc/iRISC.slaspec.patch not generated")
        header, _ = slaspec_patch.read_patch(REAL_PATCH)
        src = self._upstream_source(header["upstream-sha256"], tmp_path)
        if src is None:
            pytest.skip("no upstream source: cache and companion checkout "
                        "absent")
        out = tmp_path / "iRISC.slaspec"
        slaspec_patch.gen(out=out, upstream=src, patch=REAL_PATCH,
                          cache=tmp_path / "cache")
        if REAL_CANON.is_file():
            assert out.read_bytes() == REAL_CANON.read_bytes()
        assert sha(out.read_bytes()) == header["result-sha256"]
