import argparse
import difflib
import hashlib
import os
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

DEFAULT_PATCH = HERE / 'iRISC.slaspec.patch'
DEFAULT_CACHE = ROOT / 'build' / 'slaspec-cache'
DEFAULT_OUT = HERE / 'iRISC.slaspec'
DEFAULT_UPSTREAM_PIN = '4c488a43cdbcef957519e3800c3ba796712d3abb'
DEFAULT_UPSTREAM_URL = (
    'https://raw.githubusercontent.com/irisc-research-syndicate/'
    'ghidra-processor/%s/data/languages/iRISC.slaspec'
    % DEFAULT_UPSTREAM_PIN)
UPSTREAM_ENV = 'SLASPEC_UPSTREAM'

FROMFILE = 'iRISC.upstream.slaspec'
TOFILE = 'iRISC.slaspec'

PATCH_SHA_KEYS = ('upstream-sha256', 'result-sha256')

_HUNK_RE = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')


class SourceUnavailableError(Exception):
    pass


class IntegrityError(Exception):
    pass


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def upstream_output(out):
    return out.with_name(out.stem + '.upstream' + out.suffix)


def read_patch(path):
    path = Path(path)
    try:
        text = path.read_text()
    except OSError as e:
        raise IntegrityError('patch unreadable: %s (%s)' % (path, e))
    lines = text.splitlines(keepends=True)
    i = 0
    header = {}
    while i < len(lines) and lines[i].startswith('# '):
        key, _, value = lines[i][2:].strip().partition(':')
        header[key.strip()] = value.strip()
        i += 1
    for key in PATCH_SHA_KEYS:
        if not re.fullmatch(r'[0-9a-f]{64}', header.get(key, '')):
            raise IntegrityError(
                'patch %s: missing/invalid %r header' % (path, key))
    return header, ''.join(lines[i:])


def parse_unified(diff_text):
    lines = diff_text.splitlines(keepends=True)
    i = 0
    if i >= len(lines) or not lines[i].startswith('--- '):
        raise IntegrityError('patch: missing "--- " file header')
    i += 1
    if i >= len(lines) or not lines[i].startswith('+++ '):
        raise IntegrityError('patch: missing "+++ " file header')
    i += 1
    hunks = []
    while i < len(lines):
        m = _HUNK_RE.match(lines[i].rstrip('\n'))
        if not m:
            raise IntegrityError(
                'patch: expected hunk header, got %r' % lines[i])
        src_start = int(m.group(1))
        src_count = int(m.group(2)) if m.group(2) is not None else 1
        dst_count = int(m.group(4)) if m.group(4) is not None else 1
        i += 1
        ops = []
        seen_src = 0
        seen_dst = 0
        while seen_src < src_count or seen_dst < dst_count:
            if i >= len(lines):
                raise IntegrityError('patch: truncated hunk')
            tag = lines[i][:1]
            payload = lines[i][1:]
            if tag == ' ':
                ops.append((' ', payload))
                seen_src += 1
                seen_dst += 1
            elif tag == '-':
                ops.append(('-', payload))
                seen_src += 1
            elif tag == '+':
                ops.append(('+', payload))
                seen_dst += 1
            elif tag != '\\':
                raise IntegrityError(
                    'patch: bad hunk line: %r' % lines[i])
            i += 1
        hunks.append((src_start, ops))
    return hunks


def apply_unified(upstream_lines, hunks):
    result = []
    src = 0
    for src_start, ops in hunks:
        while src < src_start - 1:
            if src >= len(upstream_lines):
                raise IntegrityError('patch: hunk beyond end of upstream')
            result.append(upstream_lines[src])
            src += 1
        for tag, payload in ops:
            if tag == '+':
                result.append(payload)
                continue
            if src >= len(upstream_lines) \
                    or upstream_lines[src] != payload:
                raise IntegrityError(
                    'patch: %s mismatch at upstream line %d: %r'
                    % ('context' if tag == ' ' else 'removal', src + 1,
                       payload))
            if tag == ' ':
                result.append(upstream_lines[src])
            src += 1
    if src < len(upstream_lines):
        result.extend(upstream_lines[src:])
    return result


def fetch_bytes(source):
    source = os.fspath(source)
    if source.startswith(('http://', 'https://')):
        try:
            with urllib.request.urlopen(source, timeout=60) as r:
                return r.read()
        except Exception as e:
            raise SourceUnavailableError(
                'upstream fetch failed: %s (%s)' % (source, e))
    try:
        return Path(source).read_bytes()
    except OSError as e:
        raise SourceUnavailableError(
            'upstream unreadable: %s (%s)' % (source, e))


def obtain_upstream(source, expected_sha, cache_dir):
    cache_dir = Path(cache_dir)
    cache_path = cache_dir / (expected_sha + '.slaspec')
    if cache_path.is_file():
        data = cache_path.read_bytes()
        if sha256_hex(data) == expected_sha:
            return data
    data = fetch_bytes(source)
    got = sha256_hex(data)
    if got != expected_sha:
        raise IntegrityError(
            'upstream sha256 mismatch: expected %s, got %s (source %s)'
            % (expected_sha, got, source))
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(data)
    return data


def gen(out=None, upstream=None, patch=None, cache=None):
    out = Path(out) if out is not None else DEFAULT_OUT
    patch = Path(patch) if patch is not None else DEFAULT_PATCH
    cache_dir = Path(cache) if cache is not None else DEFAULT_CACHE
    header, diff_text = read_patch(patch)
    upstream_sha = header['upstream-sha256']
    result_sha = header['result-sha256']
    upstream_out = upstream_output(out)
    if out.is_file() and upstream_out.is_file() \
            and sha256_hex(out.read_bytes()) == result_sha \
            and sha256_hex(upstream_out.read_bytes()) == upstream_sha:
        return out
    source = upstream or os.environ.get(UPSTREAM_ENV) or DEFAULT_UPSTREAM_URL
    up_bytes = obtain_upstream(source, upstream_sha, cache_dir)
    up_lines = up_bytes.decode().splitlines(keepends=True)
    result_bytes = ''.join(
        apply_unified(up_lines, parse_unified(diff_text))).encode()
    got = sha256_hex(result_bytes)
    if got != result_sha:
        raise IntegrityError(
            'result sha256 mismatch after patch apply: expected %s, got %s'
            % (result_sha, got))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(result_bytes)
    upstream_out.write_bytes(up_bytes)
    return out


def regen(canon, upstream=None, patch=None, cache=None):
    canon_path = Path(canon)
    patch = Path(patch) if patch is not None else DEFAULT_PATCH
    cache_dir = Path(cache) if cache is not None else DEFAULT_CACHE
    try:
        canon_bytes = canon_path.read_bytes()
    except OSError as e:
        raise SourceUnavailableError(
            'canon unreadable: %s (%s)' % (canon_path, e))
    source = upstream or os.environ.get(UPSTREAM_ENV) or DEFAULT_UPSTREAM_URL
    up_bytes = fetch_bytes(source)
    for name, data in (('upstream', up_bytes), ('canon', canon_bytes)):
        if data and not data.endswith(b'\n'):
            raise IntegrityError(
                '%s %s does not end with a newline: deterministic unified '
                'diff impossible' % (name, canon_path if name == 'canon'
                                     else source))
    up_lines = up_bytes.decode().splitlines(keepends=True)
    canon_lines = canon_bytes.decode().splitlines(keepends=True)
    diff_text = ''.join(difflib.unified_diff(
        up_lines, canon_lines, fromfile=FROMFILE, tofile=TOFILE))
    header = '# upstream: %s\n# upstream-sha256: %s\n# result-sha256: %s\n' \
        % (DEFAULT_UPSTREAM_PIN, sha256_hex(up_bytes),
           sha256_hex(canon_bytes))
    patch.write_text(header + diff_text)
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / (sha256_hex(up_bytes) + '.slaspec')).write_bytes(up_bytes)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='slaspec_patch.py',
        description='slaspec patch-as-canon: gen materializes the untracked '
                    'slaspec files from the tracked patch; regen rebuilds '
                    'the patch from (upstream, canon)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    g = sub.add_parser('gen', help='materialize slaspec files from patch')
    g.add_argument('--out', default=str(DEFAULT_OUT))
    g.add_argument('--upstream', default=None,
                   help='upstream source: http(s) URL or local path '
                        '(default: env %s, then pinned URL)' % UPSTREAM_ENV)
    g.add_argument('--patch', default=str(DEFAULT_PATCH))
    g.add_argument('--cache', default=str(DEFAULT_CACHE))
    r = sub.add_parser(
        'regen', help='regenerate the patch from (upstream, canon)')
    r.add_argument('--canon', required=True)
    r.add_argument('--upstream', default=None)
    r.add_argument('--patch', default=str(DEFAULT_PATCH))
    r.add_argument('--cache', default=str(DEFAULT_CACHE))
    args = ap.parse_args(argv)
    try:
        if args.cmd == 'gen':
            out = gen(out=args.out, upstream=args.upstream,
                      patch=args.patch, cache=args.cache)
            print('slaspec_patch: gen %s' % out)
        else:
            regen(canon=args.canon, upstream=args.upstream,
                  patch=args.patch, cache=args.cache)
            print('slaspec_patch: regen %s' % args.patch)
    except SourceUnavailableError as e:
        print('slaspec_patch: %s' % e, file=sys.stderr)
        return 2
    except IntegrityError as e:
        print('slaspec_patch: %s' % e, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
