import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from publish import build_public  # noqa: E402

ALLOWLIST_TEXT = """\
# comment line

README.md
docs/
tools/*
skills/guide
- docs/superpowers/
- docs/050-hardware/100-inventory*
- 'Problem statement on mellanox FW.md'
- tools/hidden.sh
"""

TRACKED_FILES = {
    "README.md": "readme\n",
    "LICENSE": "GPL-3.0-or-later\n",
    "docs/TOC.md": "toc\n",
    "docs/010-roadmap/map.md": "map\n",
    "docs/superpowers/plans/plan.md": "secret plan\n",
    "docs/050-hardware/100-inventory.md": "guid-dense\n",
    "docs/050-hardware/110-sku.md": "sku\n",
    "tools/run.sh": "run\n",
    "tools/hidden.sh": "hidden\n",
    "skills/guide/skill.md": "skill\n",
    "skills/other/other.md": "other\n",
    "Problem statement on mellanox FW.md": "private note\n",
    ".github/workflows/public-ci.yml": "name: public-ci\n",
    ".github/workflows/master-guard.yml": "name: master-guard\n",
    ".github/workflows/publish-automation.yml": "name: publish-automation\n",
}

RIDES = {
    "README.md",
    "docs/TOC.md",
    "docs/010-roadmap/map.md",
    "docs/050-hardware/110-sku.md",
    "tools/run.sh",
    "skills/guide/skill.md",
}


def _make_repo(root: Path) -> Path:
    root.mkdir(parents=True)
    for rel, text in TRACKED_FILES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for rel in ("tools/run.sh", "tools/hidden.sh"):
        (root / rel).chmod(0o755)

    def git(*args):
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True, capture_output=True, text=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("add", "-A")
    git("-c", "commit.gpgsign=false", "commit", "-qm", "init")
    (root / "untracked.txt").write_text("local scratch\n", encoding="utf-8")
    return root


@pytest.fixture()
def repo(tmp_path):
    return _make_repo(tmp_path / "master")


@pytest.fixture()
def allowlist(tmp_path):
    path = tmp_path / "allowlist.txt"
    path.write_text(ALLOWLIST_TEXT, encoding="utf-8")
    return path


def _build(repo, tmp_path, allowlist):
    out = tmp_path / "out"
    copied = build_public.build_public(repo, out, allowlist)
    return out, copied


def _relset(out, paths):
    return {str(p.relative_to(out)) for p in paths}


def test_parse_allowlist_rules(tmp_path):
    path = tmp_path / "a.txt"
    path.write_text(ALLOWLIST_TEXT, encoding="utf-8")
    includes, excludes = build_public.parse_allowlist(path)
    assert includes == [
        "README.md", "docs/", "tools/*", "skills/guide"]
    assert excludes == [
        "docs/superpowers/",
        "docs/050-hardware/100-inventory*",
        "Problem statement on mellanox FW.md",
        "tools/hidden.sh",
    ]


REAL_ALLOWLIST = REPO / "scripts" / "publish" / "allowlist.txt"


@pytest.mark.skipif(not REAL_ALLOWLIST.exists(),
                    reason="no publication allowlist (public clone)")
def test_real_allowlist_rules():
    includes, excludes = build_public.parse_allowlist(REAL_ALLOWLIST)
    assert "docs/" in includes
    assert "skills/irisc-asm" in includes
    assert "skills/" not in includes
    assert ".github/workflows/public-ci.yml" in includes
    assert ".github/" not in includes
    assert ".github/workflows/" not in includes
    assert "docs/superpowers/" in excludes
    assert "docs/050-hardware/100-inventory*" in excludes
    assert "Problem statement on mellanox FW.md" in excludes
    assert "scripts/publish/allowlist.txt" in excludes


@pytest.mark.skipif(not REAL_ALLOWLIST.exists(),
                    reason="no publication allowlist (public clone)")
def test_real_allowlist_public_ci_rides_private_workflows_dont(
        repo, tmp_path):
    out, copied = _build(repo, tmp_path, REAL_ALLOWLIST)
    rels = _relset(out, copied)
    assert ".github/workflows/public-ci.yml" in rels
    assert not (out / ".github/workflows/master-guard.yml").exists()
    assert not (out / ".github/workflows/publish-automation.yml").exists()


@pytest.mark.skipif(not REAL_ALLOWLIST.exists(),
                    reason="no publication allowlist (public clone)")
def test_real_allowlist_excludes_itself_from_snapshot(repo, tmp_path):
    allowlist_in_repo = repo / "scripts" / "publish" / "allowlist.txt"
    allowlist_in_repo.parent.mkdir(parents=True, exist_ok=True)
    allowlist_in_repo.write_text("README.md\n", encoding="utf-8")
    out, copied = _build(repo, tmp_path, REAL_ALLOWLIST)
    assert "scripts/publish/allowlist.txt" not in _relset(out, copied)
    assert not (out / "scripts" / "publish" / "allowlist.txt").exists()


def test_tracked_allowed_rides_exact_set(repo, tmp_path, allowlist):
    out, copied = _build(repo, tmp_path, allowlist)
    assert _relset(out, copied) == RIDES
    tree = [p for p in out.rglob("*") if p.is_file()]
    assert _relset(out, sorted(tree)) == RIDES
    for rel in RIDES:
        assert (out / rel).read_text(encoding="utf-8") == TRACKED_FILES[rel]


def test_untracked_never_rides(repo, tmp_path, allowlist):
    out, _ = _build(repo, tmp_path, allowlist)
    assert not (out / "untracked.txt").exists()
    assert "untracked.txt" not in _relset(out, out.rglob("*"))


def test_superpowers_never_rides(repo, tmp_path, allowlist):
    out, _ = _build(repo, tmp_path, allowlist)
    assert not (out / "docs/superpowers").exists()
    assert not (out / "docs/superpowers/plans/plan.md").exists()


def test_inventory_exclusion(repo, tmp_path, allowlist):
    out, _ = _build(repo, tmp_path, allowlist)
    assert not (out / "docs/050-hardware/100-inventory.md").exists()
    assert (out / "docs/050-hardware/110-sku.md").exists()


def test_exclusion_beats_inclusion(repo, tmp_path, allowlist):
    out, copied = _build(repo, tmp_path, allowlist)
    assert not (out / "tools/hidden.sh").exists()
    assert not (out / "LICENSE").exists()
    assert not (out / "Problem statement on mellanox FW.md").exists()
    assert (out / "tools/run.sh").exists()
    assert "tools/hidden.sh" not in _relset(out, copied)


def test_file_mode_preserved(repo, tmp_path, allowlist):
    out, _ = _build(repo, tmp_path, allowlist)
    mode = (out / "tools/run.sh").stat().st_mode & 0o777
    assert mode == 0o755


def test_quoted_inclusion_quotes_stripped(repo, tmp_path):
    allowlist = tmp_path / "quoted.txt"
    allowlist.write_text(
        "'Problem statement on mellanox FW.md'\n", encoding="utf-8")
    out = tmp_path / "out"
    copied = build_public.build_public(repo, out, allowlist)
    assert _relset(out, copied) == {"Problem statement on mellanox FW.md"}
    assert (out / "Problem statement on mellanox FW.md").exists()


PUBLIC_CI = REPO / ".github" / "workflows" / "public-ci.yml"


def _public_ci_text():
    return PUBLIC_CI.read_text(encoding="utf-8")


def test_public_ci_triggers_exactly_public_branch():
    lines = _public_ci_text().splitlines()
    start = lines.index("on:")
    triggers = []
    for line in lines[start + 1:]:
        if line and not line[0].isspace():
            break
        m = re.match(r"^  ([A-Za-z_][\w-]*):", line)
        if m:
            triggers.append(m.group(1))
    assert sorted(triggers) == ["pull_request", "push"]
    text = "\n".join(lines)
    assert re.search(
        r"^  pull_request:\n    branches: \[public\]$", text, re.M)
    assert re.search(
        r"^  push:\n    branches: \[public\]$", text, re.M)


def test_public_ci_every_job_carries_fork_guard():
    text = _public_ci_text()
    jobs = re.search(r"^jobs:$", text, re.M)
    assert jobs
    body = text[jobs.end():]
    headers = list(re.finditer(r"^  ([A-Za-z_][\w-]*):$", body, re.M))
    assert sorted(h.group(1) for h in headers) == ["cargo-test", "pytest"]
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
        block = body[header.end():end]
        assert re.search(
            r"^    if: vars\.PUBLIC_REPO == github\.repository$",
            block, re.M), header.group(1)


PUBLISH_AUTOMATION = REPO / ".github" / "workflows" / "publish-automation.yml"


def _publish_automation_text():
    return PUBLISH_AUTOMATION.read_text(encoding="utf-8")


@pytest.mark.skipif(not PUBLISH_AUTOMATION.exists(),
                    reason="no publish-automation workflow (public clone)")
def test_publish_automation_invokes_publish_py_directly():
    text = _publish_automation_text()
    assert re.search(
        r'^\s+PUBLISH_RC=0$',
        text, re.M)
    assert re.search(
        r'^\s+python3 -m scripts\.publish\.publish '
        r'--remote "\$PUBLIC_REMOTE_URL" --branch public-next '
        r'\|\| PUBLISH_RC=\$\?$',
        text, re.M)
    assert not re.search(
        r'^\s+PUBLISH_RC=\$\?$', text, re.M)
    assert not re.search(r"make\s+-C", text)
    assert not re.search(r"make\s+public", text)


@pytest.mark.skipif(not PUBLISH_AUTOMATION.exists(),
                    reason="no publish-automation workflow (public clone)")
def test_publish_automation_zero_diff_skips_pr_step():
    text = _publish_automation_text()
    assert re.search(r"^\s+id: publish$", text, re.M)
    assert re.search(r"\-eq 3", text)
    assert re.search(
        r'^\s+echo "skip=true" >> "\$GITHUB_OUTPUT"$', text, re.M)
    assert re.search(
        r"^        if: steps\.publish\.outputs\.skip != 'true'$",
        text, re.M)
