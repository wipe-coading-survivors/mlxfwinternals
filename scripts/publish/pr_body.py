"""Public PR body builder (publication phase B, plan Task 6).

build_pr_body is the automation's text security boundary: the public PR
body is either the neutral one-liner or the VERBATIM content of the
private PR body's `## public` section - no other text source, no
fallback to commit subjects, and private text outside the section never
rides. The section marker is strict: a line that is exactly a level-2
heading `## public` (level-3 look-alikes, case or spacing variants are
not markers), counted only OUTSIDE fenced code blocks (```/~~~ lines
toggle fencing; a marker quoted inside a fence is not a marker, and a
body with no unfenced marker yields no section). The section runs until
the next level-1/2 heading - ATX (`# `/`## `) or setext (a `=`/`-`
underline immediately after a non-blank line); deeper headings are
content and the terminating heading never rides. A section whose
content is blank falls back to the neutral default (an empty PR body
carries no context).
"""

import argparse
import re
import sys
from pathlib import Path

NEUTRAL_TEMPLATE = "publish: snapshot of mlxini@{sha}"

_SECTION_START_RE = re.compile(r"^##[ \t]+public[ \t]*$")
_SECTION_END_RE = re.compile(r"^#{1,2}[ \t]")
_FENCE_LINE_RE = re.compile(r"^(`{3,}|~{3,})")
_SETEXT_UNDERLINE_RE = re.compile(r"^(=+|-+)$")


def _public_section(private_pr_body: str):
    """Verbatim content of the first unfenced `## public` section; None.

    Outer blank/whitespace edges of the section are stripped; interior
    lines are returned byte-verbatim (first block wins). The start scan
    skips fenced regions; the section ends at a level-1/2 ATX heading
    or a setext underline directly after a non-blank content line
    (whose text line, being the heading itself, is dropped).
    """
    lines = private_pr_body.splitlines()
    start = None
    fenced = False
    for i, line in enumerate(lines):
        if _FENCE_LINE_RE.match(line):
            fenced = not fenced
            continue
        if not fenced and _SECTION_START_RE.match(line):
            start = i + 1
            break
    if start is None:
        return None
    content = []
    for line in lines[start:]:
        if (_SETEXT_UNDERLINE_RE.match(line)
                and content and content[-1].strip()):
            content.pop()
            break
        if _SECTION_END_RE.match(line):
            break
        content.append(line)
    text = "\n".join(content).strip()
    return text or None


def build_pr_body(private_pr_body: str | None, master_sha: str) -> str:
    """Public PR body: `## public` section verbatim or the neutral line."""
    section = _public_section(private_pr_body) if private_pr_body else None
    if section is not None:
        return section
    return NEUTRAL_TEMPLATE.format(sha=master_sha)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pr_body",
        description="Build the public PR body from a private PR body.")
    parser.add_argument("--sha", required=True,
                        help="master commit sha for the neutral default")
    parser.add_argument("--body-file",
                        help="file with the private PR body "
                             "(omit when there is no private body)")
    args = parser.parse_args(argv)
    private_body = None
    if args.body_file:
        try:
            private_body = Path(args.body_file).read_text(encoding="utf-8")
        except OSError as e:
            print(f"pr-body: refuse: cannot read body file: {e}",
                  file=sys.stderr)
            return 1
    sys.stdout.write(build_pr_body(private_body, args.sha))
    return 0


if __name__ == "__main__":
    sys.exit(main())
