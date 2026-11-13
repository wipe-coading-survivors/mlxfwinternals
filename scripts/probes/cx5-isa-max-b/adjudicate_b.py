#!/usr/bin/env python3
"""isa-max cycle B adjudicator (C-B.1): pure function over the battery
vectors (matrix_b_vectors.json records with embedded expectations) and the
observed outcomes ({vector_id: value}) -> per-axis verdicts.

Per axis (records joined by the `axis` field):
- alive_models: models whose expectations match EVERY observed vector of
  the axis (at least one observation required);
- dead_models: models contradicted by at least one observed vector;
- models without any observation are listed in neither (untested);
- separated: every model of the axis was adjudicated (no untested) and at
  most one survived — the axis-level outcome T3 selects on;
- tried: how many of the axis vectors have an observation.

Value normalization (channels): expectations carry {'0x8c8': ...} and/or
{'echo': ...}; the 0x8c8 (CR low32) channel is compared when present, else
the echo channel.  'stock' matches only 'stock' (echo-stale control);
hex strings compare on the low 32 bits (the verified channel class of the
fuzz-4/fuzz-5 runner: 4B CR-store + stale-high tolerance).  Parsing is
strict (isa-max B task-3 hardening): anything but 'stock' or 0x-prefixed
hex raises ValueError -- an unparseable observed value must not silently
kill every model ('all dead' without a diagnostic); bare decimal strings
are rejected (they would parse as hex by accident).

Usage: adjudicate_b.py adjudicate MATRIX_JSON OBSERVED_JSON
"""
import argparse
import json
import sys

M32 = 0xffffffff


def _norm(value):
    s = str(value).strip().lower()
    if s == 'stock':
        return 'stock'
    if not (s.startswith('0x') and len(s) > 2
            and all(c in '0123456789abcdef' for c in s[2:])):
        raise ValueError(
            'unparseable value %r: expected 0x-prefixed hex or stock '
            '(bare decimal is rejected: the observed/expectation channel '
            'convention is hex)' % value)
    return int(s, 16) & M32


def _exp_value(exp):
    for chan in ('0x8c8', 'echo'):
        if chan in exp:
            return _norm(exp[chan])
    return None


def adjudicate(vectors, observed):
    axes = {}
    order = []
    for v in vectors:
        ax = v.get('axis')
        if not ax:
            continue
        if ax not in axes:
            axes[ax] = {'vectors': [], 'models': []}
            order.append(ax)
        axes[ax]['vectors'].append(v)
        for m in v.get('expectations', {}):
            if m not in axes[ax]['models']:
                axes[ax]['models'].append(m)
    out = {'axes': {}}
    for ax in order:
        info = axes[ax]
        tried = sum(1 for v in info['vectors'] if v['id'] in observed)
        alive, dead = [], []
        for m in sorted(info['models']):
            obs_vecs = [v for v in info['vectors']
                        if m in v.get('expectations', {})
                        and v['id'] in observed]
            if not obs_vecs:
                continue
            mismatch = any(
                _exp_value(v['expectations'][m]) != _norm(observed[v['id']])
                for v in obs_vecs)
            (dead if mismatch else alive).append(m)
        all_models = set(info['models'])
        adjudicated = set(alive) | set(dead)
        separated = adjudicated == all_models and len(alive) <= 1
        out['axes'][ax] = {
            'axis': ax,
            'alive_models': alive,
            'dead_models': dead,
            'separated': separated,
            'tried': tried,
        }
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='isa-max cycle B adjudicator (see module docstring)')
    ap.add_argument('mode', choices=['adjudicate'])
    ap.add_argument('matrix', help='matrix_b_vectors.json')
    ap.add_argument('observed', help='JSON {vector_id: value}')
    args = ap.parse_args(argv)
    vectors = json.loads(open(args.matrix).read())
    observed = json.loads(open(args.observed).read())
    res = adjudicate(vectors, observed)
    print(json.dumps(res, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
