import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from publish import publish as pub  # noqa: E402


def _git(root: Path, *args, check=True, input=None):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=check, capture_output=True, text=True, input=input)


def _commit(repo: Path, tag: str, text: str, *parents: str) -> str:
    blob = _git(repo, "hash-object", "-w", "--stdin", input=text).stdout.strip()
    tree = _git(
        repo, "mktree", input=f"100644 blob {blob}\t{tag}.txt\n").stdout.strip()
    args = ["commit-tree", tree, "-m", tag]
    for parent in parents:
        args += ["-p", parent]
    return _git(repo, *args).stdout.strip()


def _remote_tip(repo: Path, remote: Path, branch: str) -> str:
    out = _git(repo, "ls-remote", str(remote),
               f"refs/heads/{branch}").stdout.strip()
    return out.split()[0]


def _make_repo(root: Path, branch: str = "master") -> Path:
    root.mkdir(parents=True)
    (root / "README.md").write_text("readme\n", encoding="utf-8")
    _git(root, "init", "-q", "-b", branch)
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    _git(root, "add", "-A")
    _git(root, "-c", "commit.gpgsign=false", "commit", "-qm", "init")
    return root


def _make_registry(root: Path) -> Path:
    path = root / "hardware.local.md"
    path.write_text(
        "CARD1_GUID = aabbccddeeff0011\nCARD1_MAC = aabbccddeeff\n",
        encoding="utf-8")
    return path


@pytest.fixture()
def repo(tmp_path):
    return _make_repo(tmp_path / "repo")


def test_preconditions_clean_master_empty(repo):
    _make_registry(repo)
    assert pub.check_preconditions(repo) == []


def test_preconditions_dirty_tree_non_empty(repo):
    _make_registry(repo)
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    errors = pub.check_preconditions(repo)
    assert len(errors) >= 1
    assert any("clean" in e.lower() for e in errors)


def test_preconditions_staged_change_is_dirty(repo):
    _make_registry(repo)
    (repo / "new.txt").write_text("new\n", encoding="utf-8")
    _git(repo, "add", "new.txt")
    errors = pub.check_preconditions(repo)
    assert any("clean" in e.lower() for e in errors)


def test_preconditions_untracked_not_dirty(repo):
    _make_registry(repo)
    (repo / "scratch.txt").write_text("local\n", encoding="utf-8")
    assert pub.check_preconditions(repo) == []


def test_preconditions_non_master_head_non_empty(repo):
    _make_registry(repo)
    errors = pub.check_preconditions(repo)
    assert errors == []
    other = _make_repo(repo.parent / "other", branch="other")
    _make_registry(other)
    errors = pub.check_preconditions(other)
    assert len(errors) >= 1
    assert any("master" in e for e in errors)


def test_preconditions_detached_head_non_empty(repo):
    _make_registry(repo)
    _git(repo, "checkout", "-q", "--detach")
    errors = pub.check_preconditions(repo)
    assert any("master" in e for e in errors)


def test_preconditions_missing_registry_non_empty(repo):
    errors = pub.check_preconditions(repo)
    assert any("hardware.local.md" in e for e in errors)


def test_preconditions_accumulates_errors(tmp_path):
    repo = _make_repo(tmp_path / "repo", branch="feature")
    errors = pub.check_preconditions(repo)
    assert any("master" in e for e in errors)
    assert any("hardware.local.md" in e for e in errors)


def _stage(wt: Path, rel: str, text: str):
    path = wt / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _git(wt, "add", rel)


@pytest.fixture()
def repo_wt(tmp_path):
    repo = _make_repo(tmp_path / "repo")
    wtpath = tmp_path / "wt"
    _git(repo, "worktree", "add", "--orphan", "-b", "tmp-public-snap",
         str(wtpath))
    return repo, wtpath


@pytest.fixture()
def wt(repo_wt):
    return repo_wt[1]


@pytest.mark.parametrize("rel", [
    "docs/superpowers/plans/plan.md",
    "docs/superpowers/journal/j.md",
    "docs/050-hardware/100-inventory.md",
    "docs/050-hardware/100-inventory-backup.md",
    "local.mk",
    "hardware.local.md",
    "refs/fw/image.bin",
    "scripts/irisc/iRISC.slaspec",
    "scripts/irisc/iRISC.upstream.slaspec",
    "iRISC.slaspec",
])
def test_staged_exclude_path_refused(wt, rel):
    _stage(wt, rel, "content\n")
    with pytest.raises(pub.PublishError, match="exclude path"):
        pub.verify_staged(wt)


def test_staged_synthetic_test_slaspec_allowed(wt):
    _stage(wt, "tests/fixtures/slaspec/base.slaspec", "<compiler spec/>\n")
    _stage(wt, "tests/fixtures/slaspec/result.slaspec", "<compiler spec/>\n")
    assert pub.verify_staged(wt) is None


def test_staged_empty_refused(wt):
    with pytest.raises(pub.PublishError, match="empty"):
        pub.verify_staged(wt)


def test_staged_clean_ok(wt):
    _stage(wt, "README.md", "readme\n")
    _stage(wt, "docs/TOC.md", "toc\n")
    assert pub.verify_staged(wt) is None


def test_staged_registry_value_refused(wt):
    _stage(wt, "docs/TOC.md", "card is aabbccddeeff0011 here\n")
    with pytest.raises(pub.PublishError, match="CARD1_GUID"):
        pub.verify_staged(wt, {"CARD1_GUID": "aabbccddeeff0011"})


def test_staged_registry_value_in_binary_refused(wt):
    (wt / "blob.bin").write_bytes(b"\x00aabbccddeeff0011\x00")
    _git(wt, "add", "blob.bin")
    with pytest.raises(pub.PublishError, match="blob.bin"):
        pub.verify_staged(wt, {"CARD1_GUID": "aabbccddeeff0011"})


def test_staged_registry_clean_ok(wt):
    _stage(wt, "docs/TOC.md", "no values here\n")
    assert pub.verify_staged(wt, {"CARD1_GUID": "aabbccddeeff0011"}) is None


def test_staged_registry_empty_values_ignored(wt):
    _stage(wt, "docs/TOC.md", "text\n")
    assert pub.verify_staged(wt, {"K": " ", "E": ""}) is None


GATE_VALUE = "cafeba5eba11feed"


def _gate_setup(repo_wt):
    repo, wt = repo_wt
    registry = repo / "hardware.local.md"
    registry.write_text(f"CARD1_GUID = {GATE_VALUE}\n", encoding="utf-8")
    scripts = repo / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    shutil.copy(
        REPO / "scripts" / "test-no-sensitive.sh",
        scripts / "test-no-sensitive.sh")
    return repo, wt, registry


def test_gate_no_sensitive_success_value_free_summary(repo_wt, capsys):
    repo, wt, registry = _gate_setup(repo_wt)
    _stage(wt, "docs/TOC.md", "clean content\n")
    rc = pub.gate_no_sensitive(repo, wt, registry)
    out = capsys.readouterr().out
    assert rc == 0
    assert "publish: test-no-sensitive ok (pass=" in out
    assert "fail=0)" in out
    assert GATE_VALUE not in out
    assert "(registry)" not in out


def test_gate_no_sensitive_failure_value_free_refusal(repo_wt, capsys):
    repo, wt, registry = _gate_setup(repo_wt)
    _stage(wt, "docs/TOC.md", f"leaked {GATE_VALUE} marker\n")
    rc = pub.gate_no_sensitive(repo, wt, registry)
    out = capsys.readouterr().out
    assert rc != 0
    assert ("publish: refuse: test-no-sensitive failed on the public "
            "worktree") in out
    assert ("details suppressed - run scripts/test-no-sensitive.sh "
            "locally") in out
    assert GATE_VALUE not in out
    assert "not ok" not in out
    assert "(registry)" not in out


def _fast_gate_makefile(repo, recipe):
    (repo / "Makefile").write_text(
        f"test-fast:\n\t{recipe}\n", encoding="utf-8")


FAST_RECIPE_OK = (
    f"echo \"ok - no '{GATE_VALUE}' (hardware.local.md) "
    "in tracked files\"")


def test_gate_test_fast_success_value_free_summary(repo, capsys):
    _fast_gate_makefile(repo, FAST_RECIPE_OK)
    rc = pub.gate_test_fast(repo)
    out = capsys.readouterr().out
    assert rc == 0
    assert "publish: make test-fast ok" in out
    assert GATE_VALUE not in out
    assert "ok - no" not in out


def test_gate_test_fast_failure_value_free_refusal(repo, capsys):
    _fast_gate_makefile(repo, FAST_RECIPE_OK + "\n\texit 1")
    rc = pub.gate_test_fast(repo)
    out = capsys.readouterr().out
    assert rc != 0
    assert ("publish: refuse: make test-fast is not green "
            "(details suppressed - run make test-fast locally)") in out
    assert GATE_VALUE not in out


def _bare(root: Path) -> Path:
    root.mkdir(parents=True)
    _git(root, "init", "-q", "--bare", "-b", "master")
    return root


def test_snapshot_root_commit_when_remote_public_absent(repo_wt, tmp_path):
    repo, wt = repo_wt
    target = _bare(tmp_path / "target.git")
    _stage(wt, "docs/TOC.md", "toc\n")
    master_sha = _git(repo, "rev-parse", "master").stdout.strip()
    snap, parent = pub.build_snapshot(repo, wt, str(target))
    assert parent is None
    assert _git(repo, "log", "-1", "--format=%s", snap).stdout.strip() \
        == f"publish: snapshot of {master_sha}"
    body = _git(repo, "cat-file", "-p", snap).stdout
    assert "parent" not in body
    assert pub.chain_is_safe(repo, snap) is True


def test_snapshot_chains_previous_public(repo_wt, tmp_path):
    repo, wt = repo_wt
    target = _bare(tmp_path / "target.git")
    _stage(wt, "docs/TOC.md", "toc\n")
    first, parent = pub.build_snapshot(repo, wt, str(target))
    assert parent is None
    _git(repo, "push", "-q", str(target), f"{first}:refs/heads/public")
    _stage(wt, "docs/TOC.md", "toc v2\n")
    second, parent = pub.build_snapshot(repo, wt, str(target))
    assert parent == first
    body = _git(repo, "cat-file", "-p", second).stdout
    assert f"parent {first}" in body
    assert pub.chain_is_safe(repo, second) is True


def test_chain_unsafe_when_history_shared(repo):
    head = _git(repo, "rev-parse", "master").stdout.strip()
    assert pub.chain_is_safe(repo, head) is False


def _run_pre_push(hook: Path, remote_arg: str, url_arg: str, remote_ref: str):
    zero = "0" * 40
    return subprocess.run(
        ["sh", str(hook), remote_arg, url_arg],
        input=f"{zero} {zero} {remote_ref} {zero}\n",
        capture_output=True, text=True)


def test_hook_generator_rejects_branch_outside_allowlist(repo):
    with pytest.raises(pub.PublishError, match="branch"):
        pub.write_pre_push_hook(repo, "origin", branch="master")


def test_hook_generator_rejects_public_next_suffix(repo):
    with pytest.raises(pub.PublishError, match="branch"):
        pub.write_pre_push_hook(repo, "origin", branch="public-evil")


def test_hook_allows_only_generated_branch_ref(repo):
    hook = pub.write_pre_push_hook(repo, "origin", branch="public-next")
    ok = _run_pre_push(hook, "origin", "origin", "refs/heads/public-next")
    assert ok.returncode == 0
    bad = _run_pre_push(hook, "origin", "origin", "refs/heads/master")
    assert bad.returncode != 0
    assert "refs/heads/public-next" in bad.stderr
    alien = _run_pre_push(hook, "origin", "origin", "refs/heads/public")
    assert alien.returncode != 0


def test_hook_default_branch_allows_public_only(repo):
    hook = pub.write_pre_push_hook(repo, "origin")
    ok = _run_pre_push(hook, "origin", "origin", "refs/heads/public")
    assert ok.returncode == 0
    bad = _run_pre_push(hook, "origin", "origin", "refs/heads/public-next")
    assert bad.returncode != 0


def test_push_next_absent_remote_ref_is_plain_push(repo, tmp_path, capsys):
    target = _bare(tmp_path / "target.git")
    snap = _commit(repo, "snap", "one\n")
    pub.push_snapshot(repo, str(target), snap, dry=True, branch="public-next")
    out = capsys.readouterr().out
    assert f"{snap}:refs/heads/public-next" in out
    assert "--force-with-lease" not in out
    pub.push_snapshot(repo, str(target), snap, dry=False, branch="public-next")
    assert _remote_tip(repo, target, "public-next") == snap


def test_push_next_fresh_lease_rewrites_foreign_tip(repo, tmp_path):
    target = _bare(tmp_path / "target.git")
    foreign = _commit(repo, "foreign", "foreign\n")
    _git(repo, "push", "-q", "--force", str(target),
         f"{foreign}:refs/heads/public-next")
    snap = _commit(repo, "snap", "snap\n")
    pub.push_snapshot(repo, str(target), snap, dry=False, branch="public-next")
    assert _remote_tip(repo, target, "public-next") == snap


def test_push_next_stale_lease_refused_remote_untouched(repo, tmp_path):
    target = _bare(tmp_path / "target.git")
    a = _commit(repo, "a", "a\n")
    b = _commit(repo, "b", "b\n")
    snap = _commit(repo, "snap", "s\n", a)
    _git(repo, "push", "-q", "--force", str(target), f"{a}:refs/heads/public-next")
    _git(repo, "update-ref", "refs/heads/raceb", b)
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.write_text(
        "#!/bin/sh\n"
        "[ -n \"$RACE_ARMED\" ] && exit 0\n"
        "export RACE_ARMED=1\n"
        f"git push -q --force {target} refs/heads/raceb:refs/heads/public-next"
        " 2>/dev/null || true\n"
        "exit 0\n", encoding="utf-8")
    hook.chmod(0o755)
    with pytest.raises(pub.PublishError, match="push failed"):
        pub.push_snapshot(repo, str(target), snap, dry=False, branch="public-next")
    assert _remote_tip(repo, target, "public-next") == b


def test_zero_diff_skip_when_parent_tree_identical(repo_wt, tmp_path):
    repo, wt = repo_wt
    target = _bare(tmp_path / "target.git")
    _stage(wt, "docs/TOC.md", "toc\n")
    first, parent = pub.build_snapshot(repo, wt, str(target))
    assert parent is None
    _git(repo, "push", "-q", str(target), f"{first}:refs/heads/public")
    second, parent = pub.build_snapshot(repo, wt, str(target))
    assert parent == first
    assert pub.zero_diff_skip(repo, "public-next", parent, second) is True
    assert pub.zero_diff_skip(repo, "public-next", None, second) is False


def test_zero_diff_no_skip_when_trees_differ(repo_wt, tmp_path):
    repo, wt = repo_wt
    target = _bare(tmp_path / "target.git")
    _stage(wt, "docs/TOC.md", "toc\n")
    first, _ = pub.build_snapshot(repo, wt, str(target))
    _git(repo, "push", "-q", str(target), f"{first}:refs/heads/public")
    _stage(wt, "docs/TOC.md", "toc v2\n")
    second, parent = pub.build_snapshot(repo, wt, str(target))
    assert parent == first
    assert pub.zero_diff_skip(repo, "public-next", parent, second) is False


def test_zero_diff_skip_not_for_public_branch(repo_wt, tmp_path):
    repo, wt = repo_wt
    target = _bare(tmp_path / "target.git")
    _stage(wt, "docs/TOC.md", "toc\n")
    first, _ = pub.build_snapshot(repo, wt, str(target))
    _git(repo, "push", "-q", str(target), f"{first}:refs/heads/public")
    second, parent = pub.build_snapshot(repo, wt, str(target))
    assert parent == first
    assert pub.zero_diff_skip(repo, "public", parent, second) is False


def test_zero_diff_rc_is_distinct_for_automation():
    assert pub.RC_ZERO_DIFF not in (0, 1, 2)


def test_push_public_dry_run_shape_unchanged(repo, tmp_path, capsys):
    target = _bare(tmp_path / "target.git")
    snap = _commit(repo, "snap", "one\n")
    pub.push_snapshot(repo, str(target), snap, dry=True)
    out = capsys.readouterr().out
    assert f"{snap}:refs/heads/public" in out
    assert "force" not in out


def test_push_public_non_ff_refused_without_force(repo, tmp_path):
    target = _bare(tmp_path / "target.git")
    a = _commit(repo, "a", "a\n")
    snap = _commit(repo, "snap", "s\n", a)
    other = _commit(repo, "other", "o\n")
    _git(repo, "push", "-q", "--force", str(target), f"{a}:refs/heads/public")
    _git(repo, "push", "-q", "--force", str(target),
         f"{other}:refs/heads/public")
    with pytest.raises(pub.PublishError, match="push failed"):
        pub.push_snapshot(repo, str(target), snap, dry=False)
    assert _remote_tip(repo, target, "public") == other


def test_fetch_parent_remote_unreachable_refuses(repo, tmp_path):
    with pytest.raises(pub.PublishError, match="ls-remote"):
        pub.fetch_parent(repo, str(tmp_path / "missing.git"))


def test_fetch_parent_absent_public_returns_none(repo, tmp_path):
    target = _bare(tmp_path / "target.git")
    assert pub.fetch_parent(repo, str(target)) is None


def test_fetch_parent_ignores_public_next(repo, tmp_path):
    target = _bare(tmp_path / "target.git")
    stray = _commit(repo, "stray", "stray\n")
    _git(repo, "push", "-q", "--force", str(target),
         f"{stray}:refs/heads/public-next")
    assert pub.fetch_parent(repo, str(target)) is None
