"""Publication orchestrator (spec §3, publication-branch-design).

`make public` pipeline, strictly in order: preconditions (clean tracked
tree, HEAD=master, green `make test-fast`, registry present) → pre-push
hook baked with THIS run's remote and destination branch → throwaway
orphan worktree → build_public + registry-driven transform → staged-tree
gate → adapted test-no-sensitive gate → snapshot commit (fetch-and-chain
parent) → chain-safety (no shared history with master) → zero-diff skip
(automation branch only) → push. The orphan snapshot must share NO
history with master; the worktree is cleaned up on every exit path after
its creation.

Destination branch (`--branch`): `public` (default; push without force,
non-ff divergence = refusal, phase A semantics unchanged) or `public-next`
(automation; parent chain still built from refs/heads/public, push with
`--force-with-lease` whose expected tip comes from a fresh `ls-remote`
immediately before the push, absent remote ref = plain first push).
"""

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path

from .build_public import build_public
from .transform import load_registry, transform_tree

REPO = Path(__file__).resolve().parents[2]

BRANCH = "tmp-public-snap"
WORKTREE_REL = Path("build") / "public-wt"

ALLOWED_BRANCHES = ("public", "public-next")
RC_ZERO_DIFF = 3

EXCLUDE_PATTERNS = (
    "docs/superpowers/*",
    "docs/050-hardware/100-inventory*",
    "local.mk",
    "hardware.local.md",
    "refs/*",
)
SLASPEC_PATTERN = "*.slaspec"
SLASPEC_EXEMPT_PREFIX = "tests/fixtures/"

_SUMMARY_LINE_RE = re.compile(r"^# pass=([0-9]+) fail=([0-9]+)$")


class PublishError(Exception):
    """A pipeline gate refused to continue."""


def _out(r: subprocess.CompletedProcess) -> str:
    return r.stdout.decode("utf-8", errors="surrogateescape")


def _err(r: subprocess.CompletedProcess) -> str:
    return r.stderr.decode("utf-8", errors="surrogateescape")


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=False)
    if check and r.returncode != 0:
        raise PublishError(
            f"git {' '.join(args)} failed (rc={r.returncode}): {_err(r).strip()}")
    return r


def check_preconditions(repo: Path) -> list:
    """Refusal reasons for the static preconditions; empty list = OK.

    Clean tree means no modification/staging of TRACKED content
    (`--untracked-files=no`): build_public copies the tracked working-tree
    files, so uncommitted tracked changes would diverge the snapshot from
    master, while untracked files can never ride the snapshot.
    """
    repo = Path(repo)
    errors = []
    r = _git(repo, "status", "--porcelain", "--untracked-files=no", check=False)
    if r.returncode != 0:
        errors.append(f"git status failed: {_err(r).strip()}")
    elif _out(r).strip():
        errors.append("working tree not clean (tracked/staged changes):")
        errors.extend("  " + line for line in _out(r).splitlines())
    r = _git(repo, "rev-parse", "--abbrev-ref", "HEAD", check=False)
    branch = _out(r).strip() if r.returncode == 0 else ""
    if branch != "master":
        errors.append(
            f"HEAD is not on master (got: {branch or 'unborn or detached'})")
    if not (repo / "hardware.local.md").is_file():
        errors.append("hardware.local.md not found (publication registry required)")
    return errors


def verify_staged(wt: Path, registry: dict | None = None) -> None:
    """Staged-tree gate; raises PublishError on any refusal.

    `git -C wt ls-files` must be non-empty, contain no exclude path, and no
    staged blob may contain a registry value (raw substring over bytes, the
    rg -F / test-no-sensitive semantics; normalized encodings are the
    transform's job, checked there).
    """
    r = _git(wt, "ls-files", "-z")
    files = [f for f in _out(r).split("\0") if f]
    if not files:
        raise PublishError("staged tree is empty (nothing to publish)")
    for rel in files:
        for pattern in EXCLUDE_PATTERNS:
            if fnmatch.fnmatch(rel, pattern):
                raise PublishError(
                    f"exclude path staged: {rel} (pattern {pattern})")
        if (fnmatch.fnmatch(rel, SLASPEC_PATTERN)
                and not rel.startswith(SLASPEC_EXEMPT_PREFIX)):
            raise PublishError(
                f"exclude path staged: {rel} "
                f"(pattern {SLASPEC_PATTERN} outside {SLASPEC_EXEMPT_PREFIX})")
    if registry:
        needles = [
            (key, value.strip().encode("utf-8"))
            for key, value in registry.items() if value.strip()]
        for rel in files:
            data = (wt / rel).read_bytes()
            for key, needle in needles:
                if needle in data:
                    raise PublishError(
                        f"registry value of {key!r} appears in staged file {rel}")
    return None


def resolve_remote_url(repo: Path, remote: str) -> str:
    r = _git(repo, "remote", "get-url", remote, check=False)
    url = _out(r).strip()
    if r.returncode == 0 and url:
        return url
    return remote


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


HOOK_TEMPLATE = """#!/bin/sh
# Generated by scripts/publish/publish.py (make public) - do not edit.
# Publication remote guard: a push targeting THIS remote may update only
# refs/heads/{{branch}} (branch is validated to be public or public-next;
# spec publication-branch-design, section 3).
baked_arg={arg}
baked_url={url}
baked_ref={ref}
if [ "$1" = "$baked_arg" ] || [ "$2" = "$baked_url" ]; then
    while read -r local_ref local_sha remote_ref remote_sha; do
        if [ "$remote_ref" != "$baked_ref" ]; then
            echo "pre-push: only $baked_ref may be pushed to the publication remote ($baked_url)" >&2
            exit 1
        fi
    done
fi
exit 0
"""


def write_pre_push_hook(repo: Path, remote: str, branch: str = "public") -> Path:
    if branch not in ALLOWED_BRANCHES:
        raise PublishError(
            f"branch must be one of {', '.join(ALLOWED_BRANCHES)} "
            f"(got: {branch!r})")
    git_dir = _out(_git(repo, "rev-parse", "--absolute-git-dir")).strip()
    hook = Path(git_dir) / "hooks" / "pre-push"
    hook.write_text(
        HOOK_TEMPLATE.format(
            arg=_sh_quote(remote), url=_sh_quote(resolve_remote_url(repo, remote)),
            ref=_sh_quote(f"refs/heads/{branch}")),
        encoding="utf-8")
    hook.chmod(0o755)
    return hook


def remote_tip(repo: Path, remote: str, branch: str):
    """Tip of remote's refs/heads/<branch> from a FRESH ls-remote.

    None when the remote is reachable but the ref is absent (first
    run); any ls-remote failure raises - a stale or cached tip must
    never feed a --force-with-lease.
    """
    r = _git(repo, "ls-remote", remote, f"refs/heads/{branch}", check=False)
    if r.returncode != 0:
        raise PublishError(
            f"ls-remote {remote} refs/heads/{branch} failed "
            f"(rc={r.returncode}): {_err(r).strip()}")
    out = _out(r).strip()
    return out.split()[0] if out else None


def fetch_parent(repo: Path, remote: str):
    """FETCH_HEAD of remote's public branch, or None (branch absent).

    The parent chain is ALWAYS built from refs/heads/public, whatever
    the destination branch is. A reachable remote without refs/heads/
    public yields None (root commit allowed); any ls-remote/fetch
    failure raises PublishError - a network error must never be
    mistaken for "no parent".
    """
    if remote_tip(repo, remote, "public") is None:
        return None
    r = _git(repo, "fetch", "--quiet", remote, "public", check=False)
    if r.returncode != 0:
        raise PublishError(
            f"fetch {remote} public failed (rc={r.returncode}): {_err(r).strip()}")
    r = _git(repo, "rev-parse", "--verify", "FETCH_HEAD", check=False)
    if r.returncode != 0:
        raise PublishError(
            f"FETCH_HEAD not resolvable after fetch of {remote} public "
            f"(rc={r.returncode}): {_err(r).strip()}")
    return _out(r).strip() or None


def build_snapshot(repo: Path, wt: Path, remote: str):
    """Snapshot commit of the wt index: (snap_sha, parent_sha_or_None).

    tree from `git -C wt write-tree`, parent from fetch-and-chain of the
    remote's public (absent = root commit), message pinned by the brief.
    """
    tree = _out(_git(wt, "write-tree")).strip()
    parent = fetch_parent(repo, remote)
    master_sha = _out(_git(repo, "rev-parse", "master")).strip()
    args = ["commit-tree", tree, "-m", f"publish: snapshot of {master_sha}"]
    if parent:
        args += ["-p", parent]
    snap = _out(_git(repo, *args)).strip()
    return snap, parent


def chain_is_safe(repo: Path, snap: str) -> bool:
    """True iff the snapshot shares NO history with master."""
    r = _git(repo, "merge-base", "master", snap, check=False)
    if r.returncode not in (0, 1):
        raise PublishError(
            f"git merge-base failed (rc={r.returncode}): {_err(r).strip()}")
    return r.returncode == 1 or not _out(r).strip()


def _tree_hash(repo: Path, rev: str) -> str:
    r = _git(repo, "rev-parse", "--verify", f"{rev}^{{tree}}", check=False)
    if r.returncode != 0:
        raise PublishError(
            f"rev-parse {rev}^{{tree}} failed (rc={r.returncode}): "
            f"{_err(r).strip()}")
    return _out(r).strip()


def zero_diff_skip(repo: Path, branch: str, parent, snap: str) -> bool:
    """True iff this run must skip the push: identical trees (automation).

    Compares TREE hashes of the new snapshot and its parent (chained
    from refs/heads/public) - never patches and never parent identity:
    equal trees with diverged history still mean "nothing new to
    publish", and different trees with any history still publish. Only
    the automation branch skips; BRANCH=public always pushes (phase A
    semantics).
    """
    if branch == "public" or parent is None:
        return False
    return _tree_hash(repo, parent) == _tree_hash(repo, snap)


def push_snapshot(repo: Path, remote: str, snap: str, dry: bool,
                  branch: str = "public") -> None:
    """Push snap to refs/heads/<branch> (no force for public).

    For the automation branch the expected tip comes from a fresh
    ls-remote immediately before the push: --force-with-lease refuses
    the update if the remote moved in between; an absent remote ref
    (first run) is a plain push without a lease.
    """
    refspec = f"{snap}:refs/heads/{branch}"
    flags = []
    if branch != "public":
        lease = remote_tip(repo, remote, branch)
        if lease is not None:
            flags.append(f"--force-with-lease=refs/heads/{branch}:{lease}")
    if dry:
        print(f"publish: DRY: push not executed: "
              f"git push {' '.join([*flags, remote, refspec])}")
        return
    r = subprocess.run(
        ["git", "-C", str(repo), "push", *flags, remote, refspec], check=False)
    if r.returncode != 0:
        if branch == "public":
            raise PublishError(
                "push failed (git output above); if non-fast-forward: the "
                "publication branch diverged - never force-push it (spec "
                "publication-branch-design, section 2); investigate manually")
        raise PublishError(
            "push failed (git output above); likely --force-with-lease "
            "mismatch: the remote tip moved after ls-remote (concurrent "
            "update) - re-run the pipeline, never force-push blindly")


def existing_worktree_reason(repo: Path, wt: Path):
    if wt.exists():
        return f"worktree path already exists: {wt}"
    r = _git(repo, "worktree", "list", "--porcelain", check=False)
    if r.returncode == 0:
        for line in _out(r).splitlines():
            if line.startswith("worktree "):
                try:
                    registered = Path(line.split(None, 1)[1])
                except (IndexError, OSError):
                    continue
                if registered == wt:
                    return f"worktree already registered: {wt}"
    r = _git(repo, "show-ref", "--verify", "--quiet",
             f"refs/heads/{BRANCH}", check=False)
    if r.returncode == 0:
        return f"branch {BRANCH} already exists"
    return None


def cleanup_worktree(repo: Path, wt: Path) -> None:
    """Best-effort cleanup on every exit path (worktree, dir, registration)."""
    r = subprocess.run(
        ["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)],
        capture_output=True, check=False)
    if r.returncode != 0 and r.stderr.strip():
        print(f"publish: cleanup: worktree remove: "
              f"{r.stderr.decode('utf-8', errors='surrogateescape').strip()}")
    if (repo / "build").is_dir():
        r = subprocess.run(
            [str(repo / "scripts" / "safe-rm"), "--under",
             str(repo / "build"), str(wt)],
            capture_output=True, check=False)
        if r.returncode != 0 and r.stderr.strip():
            print(f"publish: cleanup: safe-rm: "
                  f"{r.stderr.decode('utf-8', errors='surrogateescape').strip()}")
    r = subprocess.run(
        ["git", "-C", str(repo), "worktree", "prune"],
        capture_output=True, check=False)
    if r.returncode != 0 and r.stderr.strip():
        print(f"publish: cleanup: worktree prune: "
              f"{r.stderr.decode('utf-8', errors='surrogateescape').strip()}")


def gate_no_sensitive(repo: Path, wt: Path, registry_path: Path) -> int:
    """Run the publish-mode no-sensitive gate with fully captured output.

    The script's ok/ko lines quote registry values verbatim, so nothing
    it prints may reach the caller's stdout (runner-log constraint:
    values stay out of automation job logs). Success prints one
    value-free summary line parsed from the script's `# pass=N fail=M`
    tail; failure prints a suppressed-details refusal pointing at a
    local re-run. Returns the script's exit code.
    """
    r = subprocess.run(
        ["sh", str(repo / "scripts" / "test-no-sensitive.sh"),
         str(wt), str(registry_path)], capture_output=True, check=False)
    counts = "pass=? fail=?"
    for line in reversed(_out(r).splitlines()):
        m = _SUMMARY_LINE_RE.match(line.strip())
        if m:
            counts = f"pass={m.group(1)} fail={m.group(2)}"
            break
    if r.returncode != 0:
        print("publish: refuse: test-no-sensitive failed on the public "
              "worktree (details suppressed - run "
              "scripts/test-no-sensitive.sh locally)")
        return r.returncode
    print(f"publish: test-no-sensitive ok ({counts})")
    return 0


def gate_test_fast(repo: Path) -> int:
    """Run make test-fast with fully captured output; rc, value-free print.

    test-fast's test-no-sensitive prerequisite quotes every registry
    value in its ok/ko lines, and the automation clone carries the
    registry by design - nothing the target prints may reach the
    caller's stdout (runner-log constraint). Success prints one
    value-free summary line; failure prints a suppressed-details
    refusal pointing at a local re-run.
    """
    try:
        r = subprocess.run(
            ["make", "-C", str(repo), "test-fast"],
            capture_output=True, check=False)
    except OSError as e:
        print(f"publish: refuse: cannot run make test-fast: {e}")
        return 1
    if r.returncode != 0:
        print("publish: refuse: make test-fast is not green "
              "(details suppressed - run make test-fast locally)")
        return r.returncode
    print("publish: make test-fast ok (rc=0)")
    return 0


def run_pipeline(repo: Path, remote: str, dry: bool,
                 branch: str = "public") -> int:
    if branch not in ALLOWED_BRANCHES:
        print(f"publish: refuse: branch must be one of "
              f"{', '.join(ALLOWED_BRANCHES)} (got: {branch!r})")
        return 1
    errors = check_preconditions(repo)
    if errors:
        for error in errors:
            print(f"publish: refuse: {error}")
        return 1
    print("publish: preconditions ok (clean tracked tree, HEAD=master, "
          "registry present)")
    if gate_test_fast(repo) != 0:
        return 1
    hook = write_pre_push_hook(repo, remote, branch)
    print(f"publish: pre-push hook installed: {hook} "
          f"(only refs/heads/{branch} to {resolve_remote_url(repo, remote)})")
    wt = repo / WORKTREE_REL
    existing = existing_worktree_reason(repo, wt)
    if existing:
        print(f"publish: refuse: {existing}")
        print("publish: cleanup hint:")
        print(f"  git worktree remove --force {wt}")
        print(f"  {repo}/scripts/safe-rm --under {repo}/build {wt}")
        print("  git worktree prune")
        print(f"  git branch -D {BRANCH}  (only if the branch was somehow born)")
        return 1
    registry_path = repo / "hardware.local.md"
    registry = load_registry(registry_path)
    allowlist = repo / "scripts" / "publish" / "allowlist.txt"
    try:
        _git(repo, "worktree", "add", "--orphan", "-b", BRANCH, str(wt))
        print(f"publish: orphan worktree {wt} (branch {BRANCH}, empty index)")
        copied = build_public(repo, wt, allowlist)
        print(f"publish: build_public: {len(copied)} files")
        replaced = transform_tree(wt, registry)
        print(f"publish: transform_tree: {replaced} replacements")
        _git(wt, "add", "-A")
        staged = [f for f in _out(_git(wt, "ls-files", "-z")).split("\0") if f]
        verify_staged(wt, registry)
        print(f"publish: staged-tree gate ok: {len(staged)} staged files, "
              "no exclude paths, no registry values")
        if gate_no_sensitive(repo, wt, registry_path) != 0:
            return 1
        snap, parent = build_snapshot(repo, wt, remote)
        print(f"publish: snapshot {snap} "
              f"(parent: {parent or 'none, root commit'})")
        if not chain_is_safe(repo, snap):
            raise PublishError(
                f"snapshot {snap} shares history with master - refusing")
        print("publish: chain-safety ok: no common ancestor with master")
        if zero_diff_skip(repo, branch, parent, snap):
            print(f"publish: zero-diff skip: snapshot {snap} tree is "
                  f"identical to parent {parent} (refs/heads/public); "
                  f"nothing to push (rc={RC_ZERO_DIFF})")
            return RC_ZERO_DIFF
        push_snapshot(repo, remote, snap, dry, branch)
        return 0
    except PublishError as e:
        print(f"publish: refuse: {e}")
        return 1
    finally:
        cleanup_worktree(repo, wt)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="make public",
        description="Orphan-snapshot publication pipeline "
                    "(spec publication-branch-design).")
    parser.add_argument("--remote", required=True,
                        help="publication remote (URL or remote name)")
    parser.add_argument("--branch", default="public",
                        choices=list(ALLOWED_BRANCHES),
                        help="destination branch: public (default; push "
                             "without force, non-ff = refusal) or "
                             "public-next (automation; force-with-lease "
                             "from a fresh ls-remote, zero-diff skip with "
                             f"rc={RC_ZERO_DIFF})")
    parser.add_argument("--dry", action="store_true",
                        help="run everything up to the push; "
                             "print the push instead of executing it")
    args = parser.parse_args(argv)
    return run_pipeline(REPO, args.remote, args.dry, args.branch)


if __name__ == "__main__":
    sys.exit(main())
