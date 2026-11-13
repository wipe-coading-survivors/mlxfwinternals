"""Public-tree builder (spec §4, publication-branch-design).

parse_allowlist: allowlist file → (includes, excludes) rule lists; one rule
per line, `- ` prefix = exclusion (overrides any inclusion), surrounding
quotes stripped so shell-style quoting never leaks into the rule.
build_public: copy the TRACKED files of master_root (git ls-files -z) that
pass the allowlist into out, preserving relative paths and file modes;
returns the list of copied paths. Untracked files never ride; a file with
no matching inclusion rule never rides (allowlist, not denylist).
"""

import fnmatch
import shutil
import subprocess
from pathlib import Path


def parse_allowlist(path: Path):
    """Allowlist file → (includes, excludes).

    One rule per line: `docs/` = whole directory, `docs/NNN-*` = pattern,
    bare rule = file or directory it names, `- ` prefix = exclusion.
    Surrounding single/double quotes are stripped; blank lines and `#`
    comment lines are skipped.
    """
    includes = []
    excludes = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        excluded = False
        if rule.startswith("- "):
            excluded = True
            rule = rule[2:].strip()
        if len(rule) >= 2 and rule[0] == rule[-1] and rule[0] in "'\"":
            rule = rule[1:-1].strip()
        (excludes if excluded else includes).append(rule)
    return includes, excludes


def _parents(path: str):
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def rule_matches(rule: str, path: str) -> bool:
    """Does one rule cover `path` (a `/`-separated repo-relative path)?

    Trailing `/` = directory prefix; a bare rule matches the file it names
    or the directory it names (its contents); a rule with `*` is a pattern
    matched against the path and each of its parent directories.
    """
    if "*" in rule:
        if fnmatch.fnmatch(path, rule):
            return True
        return any(fnmatch.fnmatch(parent, rule) for parent in _parents(path))
    if rule.endswith("/"):
        return path.startswith(rule)
    return path == rule or path.startswith(rule + "/")


def _passes(includes, excludes, path: str) -> bool:
    if not any(rule_matches(rule, path) for rule in includes):
        return False
    return not any(rule_matches(rule, path) for rule in excludes)


def build_public(master_root: Path, out: Path, allowlist: Path) -> list[Path]:
    """Copy TRACKED+allowed files of master_root into out; return copies.

    Only paths listed by `git -C master_root ls-files -z` are considered;
    copies preserve relative paths and file modes (shutil.copy2, parent
    directories created as needed).
    """
    master_root = Path(master_root)
    out = Path(out)
    includes, excludes = parse_allowlist(allowlist)
    listing = subprocess.run(
        ["git", "-C", str(master_root), "ls-files", "-z"],
        capture_output=True,
        check=True,
    ).stdout
    copied = []
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        rel = entry.decode("utf-8", errors="surrogateescape")
        if not _passes(includes, excludes, rel):
            continue
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(master_root / rel, dst)
        copied.append(dst)
    return copied
