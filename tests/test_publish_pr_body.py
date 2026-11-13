import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from publish import pr_body  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
NEUTRAL = "publish: snapshot of mlxini@" + SHA


def test_none_body_returns_neutral_default():
    assert pr_body.build_pr_body(None, SHA) == NEUTRAL


def test_empty_body_returns_neutral_default():
    assert pr_body.build_pr_body("", SHA) == NEUTRAL


def test_no_public_section_returns_neutral_default():
    body = "## Summary\ninternal notes only\n\n## Test plan\n- private\n"
    assert pr_body.build_pr_body(body, SHA) == NEUTRAL


def test_public_section_content_rides_verbatim():
    body = (
        "private intro line\n"
        "\n"
        "## public\n"
        "\n"
        "First public line.\n"
        "\n"
        "```sh\n"
        "make test-parallel\n"
        "```\n"
        "\n"
        "  indented  detail\n"
        "\n"
        "## After\n"
        "private tail\n")
    assert pr_body.build_pr_body(body, SHA) == (
        "First public line.\n"
        "\n"
        "```sh\n"
        "make test-parallel\n"
        "```\n"
        "\n"
        "  indented  detail")


def test_text_outside_block_never_rides():
    body = "SECRET-INTRO\n\n## public\nsafe line\n\n## internal\nSECRET-TAIL\n"
    out = pr_body.build_pr_body(body, SHA)
    assert out == "safe line"
    assert "SECRET-INTRO" not in out
    assert "SECRET-TAIL" not in out


def test_h1_heading_ends_the_section():
    body = "## public\ninside\n\n# Top heading\noutside\n"
    assert pr_body.build_pr_body(body, SHA) == "inside"


def test_setext_h1_ends_the_section():
    body = "## public\nsafe line\n\nConclusion\n==========\nSECRET-TAIL\n"
    out = pr_body.build_pr_body(body, SHA)
    assert out == "safe line"
    assert "SECRET-TAIL" not in out


def test_setext_h2_ends_the_section():
    body = "## public\nsafe\n\nSub heading\n-----\nSECRET-TAIL\n"
    out = pr_body.build_pr_body(body, SHA)
    assert out == "safe"
    assert "SECRET-TAIL" not in out


def test_setext_heading_text_never_rides():
    body = "## public\nsafe\nConclusion\n==========\nSECRET-TAIL\n"
    out = pr_body.build_pr_body(body, SHA)
    assert out == "safe"
    assert "Conclusion" not in out
    assert "SECRET-TAIL" not in out


def test_setext_only_section_falls_back_to_neutral():
    body = "## public\nHeading text\n============\nSECRET-TAIL\n"
    assert pr_body.build_pr_body(body, SHA) == NEUTRAL


def test_underline_after_blank_line_stays_in_content():
    body = "## public\nsafe\n\n======\nstill content\n"
    assert pr_body.build_pr_body(body, SHA) == "safe\n\n======\nstill content"


def test_marker_inside_code_fence_is_not_a_marker():
    for fence in ("```", "~~~"):
        body = (
            "private intro\n"
            "\n"
            f"{fence}md\n"
            "## public\n"
            f"{fence}\n"
            "\n"
            "SECRET-BETWEEN\n"
            "\n"
            "## public\n"
            "real block content\n"
            "\n"
            "## tail\n"
            "SECRET-TAIL\n")
        out = pr_body.build_pr_body(body, SHA)
        assert out == "real block content"
        assert "SECRET-BETWEEN" not in out
        assert "SECRET-TAIL" not in out


def test_fenced_marker_only_returns_neutral_default():
    body = (
        "intro\n"
        "\n"
        "```\n"
        "## public\n"
        "SECRET-FENCED\n"
        "```\n"
        "\n"
        "SECRET-TAIL\n")
    assert pr_body.build_pr_body(body, SHA) == NEUTRAL


def test_first_public_block_wins():
    body = "## public\nfirst block\n\n## public\nsecond block\n"
    assert pr_body.build_pr_body(body, SHA) == "first block"


def test_nested_heading_stays_in_content():
    body = "## public\n### nested\nkept as content\n"
    assert pr_body.build_pr_body(body, SHA) == "### nested\nkept as content"


def test_empty_public_section_falls_back_to_neutral():
    body = "intro\n\n## public\n\n## next\nprivate\n"
    assert pr_body.build_pr_body(body, SHA) == NEUTRAL


def test_marker_is_strict():
    for fake in (
            "### public\nx\n",
            "## Public\nx\n",
            "##public\nx\n",
            "## public extra\nx\n",
            " ## public\nx\n"):
        assert pr_body.build_pr_body(fake, SHA) == NEUTRAL


def _run_cli(args):
    env = dict(os.environ, PYTHONPATH=str(REPO / "scripts"))
    return subprocess.run(
        [sys.executable, "-m", "publish.pr_body", *args],
        env=env, capture_output=True, text=True)


def test_cli_without_body_file_prints_neutral_default():
    r = _run_cli(["--sha", SHA])
    assert r.returncode == 0
    assert r.stdout == NEUTRAL


def test_cli_body_file_rides_section_verbatim(tmp_path):
    body_file = tmp_path / "private.md"
    body_file.write_text(
        "secret intro\n\n## public\n\ncli content\n\n## tail\nsecret\n",
        encoding="utf-8")
    r = _run_cli(["--sha", SHA, "--body-file", str(body_file)])
    assert r.returncode == 0
    assert r.stdout == "cli content"
