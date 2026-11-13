import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts" / "irisc"))

import crosscheck  # noqa: E402

SLASPEC_REPO = REPO / "scripts" / "irisc" / "iRISC.slaspec"
SLASPEC_UPSTREAM = REPO / "scripts" / "irisc" / "iRISC.upstream.slaspec"

skip_no_repo_slaspec = pytest.mark.skipif(
    not SLASPEC_REPO.is_file(),
    reason="scripts/irisc/iRISC.slaspec not generated (run make slaspec-gen)")
skip_no_upstream_slaspec = pytest.mark.skipif(
    not SLASPEC_UPSTREAM.is_file(),
    reason="scripts/irisc/iRISC.upstream.slaspec not generated "
           "(run make slaspec-gen)")


def make_git_dir(tmp_path):
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args],
                              capture_output=True, text=True, check=True)
    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("commit", "--allow-empty", "-q", "-m", "x")
    return subprocess.run(["git", "-C", str(tmp_path), "rev-parse",
                           "--short", "HEAD"],
                          capture_output=True, text=True,
                          check=True).stdout.strip()


def fixture_report():
    return {
        "image": "fw-test.bin",
        "configs": [
            {
                "config": "repo",
                "words_total": 100,
                "diffs": [
                    {"dc": 4, "word": "0x940002de", "ours": "x", "ghidra": "y",
                     "class": "decoder_bug"},
                    {"dc": 8, "word": "0x78802914", "ours": "x", "ghidra": "y",
                     "class": "documented"},
                    {"dc": 12, "word": "0x58000000", "ours": "x", "ghidra": "y",
                     "class": "data"},
                ],
            },
            {
                "config": "upstream",
                "words_total": 100,
                "diffs": [
                    {"dc": 16, "word": "0xa0100002", "ours": "x", "ghidra": "y",
                     "class": "outside_slaspec"},
                ],
            },
        ],
    }


class TestTaxonomy:
    def test_classes_exact(self):
        assert set(crosscheck.CLASSES) == {
            "decoder_bug", "documented", "data", "outside_slaspec"}

    def test_report_pass_all_four_classes(self):
        r = fixture_report()
        assert crosscheck.unclassified(r) == []
        assert set(crosscheck.class_counts(r)) == set(crosscheck.CLASSES)

    def test_report_fail_on_decoder_bug(self):
        r = fixture_report()
        assert crosscheck.report_pass(r) is False

    def test_report_pass_without_decoder_bug(self):
        r = fixture_report()
        r["configs"][0]["diffs"][0]["class"] = "documented"
        assert crosscheck.report_pass(r) is True

    def test_class_counts(self):
        counts = crosscheck.class_counts(fixture_report())
        assert counts == {"decoder_bug": 1, "documented": 1, "data": 1,
                          "outside_slaspec": 1}

    def test_report_fail_on_unknown_class(self):
        r = fixture_report()
        r["configs"][0]["diffs"][0]["class"] = "mystery"
        unc = crosscheck.unclassified(r)
        assert len(unc) == 1 and unc[0]["dc"] == 4
        assert crosscheck.report_pass(r) is False

    def test_report_fail_on_none_class(self):
        r = fixture_report()
        r["configs"][1]["diffs"][0]["class"] = None
        assert crosscheck.report_pass(r) is False

    def test_empty_report_passes(self):
        r = {"image": "x", "configs": [{"config": "repo", "words_total": 0,
                                        "diffs": []}]}
        assert crosscheck.report_pass(r) is True
        assert crosscheck.class_counts(r) == {}


EQUAL_PAIRS = [
    ("addi r3,zero,0x40a8", "addi r3,zero,0x40a8"),
    ("subi r5,r3,-0x10", "subi r5,r3,-16"),
    ("b.t.0x10 zero,0x91774", "b.t.eq64 zero,0x00091774"),
    ("b.f.0x0a zero,0x91774", "b.f.cmpres zero,0x00091774"),
    ("b.t.0x1c zero,0x91774", "b.t.unk.1c zero,0x00091774"),
    ("shrh r3,r4,0x1", "shr r3l,r4h,0x1"),
    ("csr.r r3,csr0xbc", "csr.r r3l,retaddr"),
    ("csr.r r3,csr0x05", "csr.r r3l,csr0005"),
    ("st.d r3,r1,0x4", "st.d r3l,r1l,0x4"),
    ("call 0x1e10c", "call 0x0001e10c"),
    ("lw.r r23,r1,r2", "lw.r r23l,r1l,r2l"),
    ("st.w r4,r23,0x6", "st.w r4l,r23l,0x6"),
    ("addi r4,zero,0x-2", "addi r4,zero,-0x2"),
    ("csr.r r4,csr0x1ac", "csr.r r4l,<BAD_register_263856:4>"),
    ("csr.r r8,csr0x4", "csr.r r8l,cpuinfo"),
    ("csr.r r3,csr0x8", "csr.r r3l,trace_addr"),
]


class TestNormalizeEqual:
    pytestmark = [skip_no_repo_slaspec]

    @pytest.mark.parametrize("ours,ghidra", EQUAL_PAIRS)
    def test_pair_normalizes_equal(self, ours, ghidra):
        assert crosscheck.normalize_ours(ours) == crosscheck.normalize_ghidra(ghidra)

    def test_ours_unknown_shape(self):
        assert crosscheck.normalize_ours(
            "op0x1d r3,r5,r2 imm=0x1234") == ("op0x1d", ["r3", "r5", "r2", 0x1234])

    def test_ghidra_unknown_shape(self):
        assert crosscheck.normalize_ghidra(
            "unk.1d r3,r5,r2,0x1234") == ("op0x1d", ["r3", "r5", "r2", 0x1234])


def make_classifier():
    return crosscheck.Classifier(data_tail_ops={0x16, 0x1d},
                                 census_ops={0x16, 0x1d, 0x36})


class TestClassify:
    pytestmark = [skip_no_repo_slaspec]

    def test_equal_known_is_none(self):
        assert make_classifier().classify(
            "addi r3,zero,0x40a8", "addi r3,zero,0x40a8") == "none"

    def test_mv_vs_or_documented(self):
        assert make_classifier().classify(
            "or r21,r2,r2", "mv r21,r2") == "documented"

    def test_andmsk_hi_vs_upstream_or_documented(self):
        # canon-sync 0x0c (2026-11-01): our leg renders andmsk.hi, the
        # upstream leg still renders the inherited `or` (pinned upstream
        # slaspec) — same operands (imm16 unsigned on both sides) must
        # classify documented, not decoder_bug
        assert make_classifier().classify(
            "andmsk.hi r4,r4,0x9fff", "or r4,r4,0x9fff") == "documented"
        assert make_classifier().classify(
            "andmsk.hi r6,r6,0xff", "or r6,r6,0xff") == "documented"
        # operand/imm mismatch on the same pair is still a bug
        assert make_classifier().classify(
            "andmsk.hi r6,r6,0xff", "or r6,r6,0xf0") == "decoder_bug"
        assert make_classifier().classify(
            "andmsk.hi r6,r6,0xff", "or r6,r7,0xff") == "decoder_bug"

    def test_lw_r_zx_documented(self):
        assert make_classifier().classify(
            "alu.0x18 r3,r4,r5", "lw.r.zx r3l,r4l,r5l") == "documented"

    def test_shr85_regnum_shamt_documented(self):
        assert make_classifier().classify(
            "alu.0x85 r4,r22,r31", "shr.85 r4l,r22l,0x1f") == "documented"
        assert make_classifier().classify(
            "alu.0x85 r4,r22,r3", "shr.85 r4l,r22l,0x3") == "documented"

    def test_alu_0xf_zero_pad_equal(self):
        assert make_classifier().classify(
            "alu.0xf r5,r6,r5", "alu.0xf r5,r6,r5") == "none"

    def test_jump_reserved_jmpop_documented(self):
        assert make_classifier().classify(
            "call 0xfe7f4b24", "jump.0x2 0xfe7f4b24") == "documented"
        assert make_classifier().classify(
            "jump 0xff844fac", "jump.0x3 0xff844fac") == "documented"

    def test_simm16_raw_display_documented(self):
        assert make_classifier().classify(
            "xor r6,r6,0x-8000", "xor r6,r6,0x8000") == "documented"
        assert make_classifier().classify(
            "ands r4,r4,0xfffc", "ands r4,r4,0xfffc") == "none"

    def test_jump_wrap_documented(self):
        assert make_classifier().classify(
            "jump 0xfe8356b4", "jump 0xfe8356b4") == "none"

    def test_jalr_vs_ret_r_documented(self):
        assert make_classifier().classify(
            "ret.r zero,zero,r3", "jalr r3l") == "documented"

    def test_st_i_documented(self):
        assert make_classifier().classify(
            "st.i r5,0x10", "st.i r3l,0x10") == "documented"

    def test_csr_w_funct_suffix_documented(self):
        assert make_classifier().classify(
            "csr.w r5,r3,0x10", "csr.w.05 r5,r3,0x10") == "documented"

    def test_csr_w_00_lossy_documented(self):
        assert make_classifier().classify(
            "csr.w r5,r3,0x0", "csr.w.00 r5,csr0000") == "documented"

    def test_csr_w_00_bad_register_documented(self):
        assert make_classifier().classify(
            "csr.w r6,zero,0x28",
            "csr.w.00 r6,<BAD_register_262304:4>") == "documented"

    def test_q_form_display_documented(self):
        assert make_classifier().classify(
            "st.q.1e r5,r4,0x110", "st.q.1e r5,r4l,0x114") == "documented"
        assert make_classifier().classify(
            "ld.q.17 r5,r4,0x110", "ld.q.17 r5,r4l,0x114") == "documented"

    def test_same_mnemonic_different_operand_is_bug(self):
        assert make_classifier().classify(
            "addi r3,zero,0x40a8", "addi r3,zero,0x40a9") == "decoder_bug"

    def test_wrong_mnemonic_is_bug(self):
        assert make_classifier().classify(
            "addi r3,zero,0x40a8", "subi r3,zero,0x40a8") == "decoder_bug"

    def test_ours_unknown_ghidra_known_outside(self):
        assert make_classifier().classify(
            "op0x38 r5,r3,r2 imm=0x0010", "cmp.w r3,r2,0x10") == "outside_slaspec"

    def test_ghidra_unknown_ours_known_outside(self):
        assert make_classifier().classify(
            "addi r3,zero,0x40a8", "unk.0 r3,zero,r2,0x40a8") == "outside_slaspec"

    def test_both_unknown_census_code_outside(self):
        assert make_classifier().classify(
            "op0x36 r3,r5,r2 imm=0x1234",
            "unk.36 r3,r5,r2,0x1234") == "outside_slaspec"

    def test_both_unknown_census_tail_data(self):
        assert make_classifier().classify(
            "op0x16 r3,r5,r2 imm=0x1234",
            "unk.16 r3,r5,r2,0x1234") == "data"

    def test_both_unknown_census_absent_data(self):
        assert make_classifier().classify(
            "op0x0f r3,r5,r2 imm=0x1234",
            "unk.0f r3,r5,r2,0x1234") == "data"

    def test_unparseable_is_unclassified(self):
        assert make_classifier().classify(
            "garbage ???", "more ???") is None

    def test_ghidra_missing_is_unclassified(self):
        assert make_classifier().classify("addi r3,zero,0x40a8", None) is None


class TestDumpParser:
    def test_parse_line(self):
        assert crosscheck.parse_dump_line(
            "00091774  b.t.eq32 zero,0x00091774") == (
            0x91774, "b.t.eq32 zero,0x00091774")

    def test_parse_line_extra_spaces(self):
        assert crosscheck.parse_dump_line(
            "00000000    addi r3,zero,0x40a8") == (
            0, "addi r3,zero,0x40a8")

    def test_parse_line_malformed(self):
        assert crosscheck.parse_dump("not a dump") == {}
        assert crosscheck.parse_dump_line("garbage") is None


class TestDataTailOps:
    def test_notes(self):
        census = {
            "0x36": {"note": "predicate-compare; f5 map open"},
            "0x16": {"note": "rare; version tail"},
            "0x1d": {"note": "rare in code; bulk is data-side table; version tail"},
            "0x2c": {"note": "all mask sites in table zones (strict 0)"},
            "0x39": {"note": "rare kernel tail"},
            "0x33": {"note": "Phase I0 static: reg-reg bit-ops"},
        }
        assert crosscheck.data_tail_ops(census) == {0x16, 0x1d, 0x2c}

    def test_empty(self):
        assert crosscheck.data_tail_ops({}) == set()


class TestUpstreamSlaspec:
    pytestmark = [skip_no_upstream_slaspec]

    def test_file_exists(self):
        assert crosscheck.UPSTREAM_SLASPEC.is_file()

    def test_sha256_pinned(self):
        got = hashlib.sha256(
            crosscheck.UPSTREAM_SLASPEC.read_bytes()).hexdigest()
        assert got == crosscheck.UPSTREAM_SLASPEC_SHA256

    def test_pin_comment(self):
        head = crosscheck.UPSTREAM_SLASPEC.read_text().splitlines()[0]
        assert not head.startswith("#")

    def test_upstream_slaspec_compiles_hint(self):
        text = crosscheck.UPSTREAM_SLASPEC.read_text()
        assert "CMPRES" not in text
        assert "cmp.w" not in text


class TestGhidraContainerRev:
    def test_short_rev_from_companion_checkout(self, tmp_path):
        expected = make_git_dir(tmp_path)
        assert crosscheck.ghidra_container_rev(tmp_path) == expected

    def test_none_when_dir_missing(self, tmp_path):
        assert crosscheck.ghidra_container_rev(tmp_path / "nope") is None

    def test_none_when_not_a_git_repo(self, tmp_path):
        (tmp_path / "plain").write_text("x")
        assert crosscheck.ghidra_container_rev(tmp_path) is None

    def test_report_contains_short_rev(self, tmp_path):
        expected = make_git_dir(tmp_path)
        report = {"image": "x", "configs": []}
        crosscheck.stamp_ghidra_container_rev(report, container_dir=tmp_path)
        assert report["ghidra_container_rev"] == expected

    def test_report_field_omitted_when_unavailable(self):
        report = {"image": "x", "configs": []}
        crosscheck.stamp_ghidra_container_rev(
            report, container_dir="/nonexistent-ghidra-container")
        assert "ghidra_container_rev" not in report
