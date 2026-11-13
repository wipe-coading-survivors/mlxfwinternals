#!/bin/sh
# Check: no sensitive (machine-local) values in tracked files.
# Master mode (no arguments, behavior unchanged): 1) Values from local.mk
# and hardware.local.md (both untracked, if exist): each VALUE must not
# appear in any tracked file (grep -F) outside docs/superpowers/** —
# journals/plans/specs/reports quote real identifiers (incl. machine paths
# and image tags) as historical records, never get published, and are
# exempt by owner decision 2026-11-06. A value identical to a value in
# local.mk.example is shared (declared non-machine-local by the tracked
# example) and skipped. hardware.local.md uses the same KEY = VALUE line
# format. 2) Generic (always, incl. without local.mk — CI-compatible):
# private IP ranges (10/8, 172.16/12, 192.168/16) with numeric
# boundaries. Scope: tracked files except docs/ and *.md — numbered docs,
# TODO and journals carry the documented lab topology (llm-rig excludes
# samba/ for the same reason); publish-time curation handles them
# (roadmap-restructure.md §5-§6). 127.0.0.1 (loopback) and 192.0.2.x
# (TEST-NET) are out of scope on purpose. A candidate directly preceded
# by '-' is a version fragment (RPM NEVRA), not an IP.
# Publish mode ($1 = public-worktree root, $2 = registry path): gates the
# STAGED public tree (git -C <wt> ls-files, not a filesystem walk). The
# registry file is REQUIRED — absent means refusal, not skip. Every
# registry VALUE is checked against ALL staged files (docs/superpowers/
# never rides, no example-shared skip: local.mk.example never rides
# either). The generic private-IP check keeps the master-mode scope
# (staged files except docs/ and *.md; registered IPs are covered by the
# value check after the transform). Any other hit in an in-scope file =
# fail.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)

pass=0
fail=0

ok() { pass=$((pass + 1)); echo "ok - $1"; }
ko() { fail=$((fail + 1)); echo "not ok - $1"; echo "  expected: $2"; echo "  actual:   $3"; }

mk_values() { # $1 = makefile; print values (one per line), skip #/blank
    [ -f "$1" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            ''|\#*) continue ;;
            *=*) ;;
            *) continue ;;
        esac
        v=${line#*=}
        v=$(printf '%s' "$v" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        [ -n "$v" ] && printf '%s\n' "$v"
    done < "$1"
}

if [ $# -eq 0 ]; then
    repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
    cd -- "$repo_root"

    grep_values() { # $@ = grep flags; scope: tracked files except docs/superpowers/
        git ls-files -z -- ':!docs/superpowers' | xargs -0 -r grep "$@" 2>/dev/null || true
    }

    grep_no_docs() { # $@ = grep flags; scope: tracked files except docs/ and *.md
        git ls-files -z -- ':!docs' ':!*.md' | xargs -0 -r grep "$@" 2>/dev/null || true
    }

    example_values=$(mk_values local.mk.example)

    for src in local.mk hardware.local.md; do
        if [ -f "$repo_root/$src" ]; then
            while IFS= read -r line || [ -n "$line" ]; do
                case $line in
                    ''|\#*) continue ;;
                    *=*) ;;
                    *) continue ;;
                esac
                v=${line#*=}
                v=$(printf '%s' "$v" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
                [ -n "$v" ] || continue
                if printf '%s\n' "$example_values" | grep -Fxq -- "$v"; then
                    ok "skip '$v' (shared with local.mk.example)"
                else
                    hits=$(grep_values -Fn -- "$v")
                    if [ -n "$hits" ]; then
                        ko "no '$v' ($src) in tracked files (docs/superpowers/ exempt)" "no match" "$hits"
                    else
                        ok "no '$v' ($src) in tracked files (docs/superpowers/ exempt)"
                    fi
                fi
            done < "$src"
        else
            ok "$src absent — values check skipped (generic part only)"
        fi
    done
else
    [ $# -eq 2 ] || { echo "usage: $0 [<worktree-root> <registry-path>]" >&2; exit 2; }
    wt=$(CDPATH= cd -- "$1" 2>/dev/null && pwd) || wt=
    if [ -z "$wt" ] || [ ! -d "$wt" ]; then
        echo "not ok - public worktree root not found: $1" >&2
        exit 1
    fi
    reg=$2
    if [ ! -f "$reg" ]; then
        echo "not ok - registry required in publish mode: $reg not found" >&2
        exit 1
    fi
    reg=$(CDPATH= cd -- "$(dirname -- "$reg")" && pwd)/$(basename -- "$reg")
    cd -- "$wt"

    grep_values() { # $@ = grep flags; scope: staged files of the public worktree
        git ls-files -z | xargs -0 -r grep "$@" 2>/dev/null || true
    }

    grep_no_docs() { # $@ = grep flags; scope: staged files except docs/ and *.md
        git ls-files -z -- ':!docs' ':!*.md' | xargs -0 -r grep "$@" 2>/dev/null || true
    }

    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            ''|\#*) continue ;;
            *=*) ;;
            *) continue ;;
        esac
        v=${line#*=}
        v=$(printf '%s' "$v" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        [ -n "$v" ] || continue
        hits=$(grep_values -Fn -- "$v")
        if [ -n "$hits" ]; then
            ko "no '$v' (registry) in staged public files" "no match" "$hits"
        else
            ok "no '$v' (registry) in staged public files"
        fi
    done < "$reg"
fi

pat='(^|[^0-9.-])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})([^0-9.]|$)'
hits=$(grep_no_docs -nE -- "$pat")
if [ -n "$hits" ]; then
    ko "no private-IP range in tracked files (docs/ and *.md excluded)" "no match" "$hits"
else
    ok "no private-IP range in tracked files (docs/ and *.md excluded)"
fi

echo "# pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
