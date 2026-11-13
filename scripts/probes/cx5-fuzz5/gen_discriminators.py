#!/usr/bin/env python3
"""fuzz5 Task-4 discriminator vectors (offline, same live session).

Built from gen_matrix models + patch-based on emitted fuzz5 vectors:
- op0x34 rogue family: operand-independence x2, idx-sweep (f5=4), flag,
  f5=0xb depM-vs-rogue, f5=2 flag=1 rogue membership
- op0x36 f5=0xa: split {eq32,eq16,V} (eq16-split pair + equal-pair stale-T)
- op0x33 f5=0 flag=1: split {pass,min} with (rs,rt)=(5,3)

Every patched word is round-trip verified (disasm->assemble == word).
Expectations computed ONLY via gen_matrix model functions.
Output: /tmp/opencode/f5t4/fuzz5_disc_vectors.json (marker + 11 vectors).
"""
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'scripts' / 'probes' / 'cx5-fuzz4'))
sys.path.insert(0, str(REPO / 'scripts' / 'probes' / 'cx5-fuzz5'))

import gen_vectors as f4
import gen_matrix as gm
from scripts.irisc import assemble, disasm

SRC = json.loads((REPO / 'scripts/probes/cx5-fuzz5/fuzz5_vectors.json').read_text())
BY = {v['id']: v for v in SRC}
M32 = gm.M32

f4.TAIL_WORDS = list(struct.unpack('>3I', f4.assemble(
    '\n'.join(f4.TAIL), base=0, profile=f4.PROFILE)))


def rt_verify(words, vid):
    for i, w in enumerate(words):
        line = disasm(w, i * 4)
        back = f4.assemble(line, base=0, profile=f4.PROFILE)
        wv = struct.unpack('>I', back[:4])[0]
        if wv != w:
            raise SystemExit('%s: word %d round-trip FAIL %08x -> %s -> %08x'
                             % (vid, i, w, line, wv))


def patch_selector(opword, f5, idx, flag):
    op16 = opword & 0xFFFF
    rt = (op16 >> 11) & 0x1F
    new16 = (rt << 11) | (flag << 10) | (idx << 5) | f5
    return (opword & 0xFFFF0000) | new16


def value_patch(vid, base_id, f5, idx, flag, a, b, exps, notes,
                op_word_idx=2):
    base = BY[base_id]
    words = [int(w, 16) for w in base['words']]
    words[0] = 0x00050000 | a
    words[1] = 0x00060000 | b
    words[op_word_idx] = patch_selector(words[op_word_idx], f5, idx, flag)
    words = ['%08x' % w for w in words]
    rt_verify([int(w, 16) for w in words], vid)
    rec = {'id': vid, 'group': 'disc', 'words': words,
           'expectations': exps, 'notes': notes}
    return rec


def exps34(f5, idx, a, b, rogue=None):
    sel = {'idx': idx}
    exps = {}
    for h, fn in gm.space34(f5, idx):
        lo = fn(a, b, sel) & M32
        exps[h] = {'0x8c8': '0x%08x' % lo, 'echo': '0x%08x' % lo}
    if rogue is not None:
        exps['H-rogue'] = {'0x8c8': '0x%08x' % rogue,
                           'echo': '0x%08x' % rogue}
    return exps


def exps33(f5, idx, a, b):
    sel = {'idx': idx}
    exps = {}
    for h, fn in gm.space33(f5, idx):
        lo = fn(a, b, sel) & M32
        exps[h] = {'0x8c8': '0x%08x' % lo, 'echo': '0x%08x' % lo}
    return exps


ROGUE = {(0, 0): 0xc, (0, 1): 0xd, (16, 1): 0xd0005}

out = []

# --- op0x34 rogue: operand independence (two points, non-rogue-model exps)
out.append(value_patch(
    'V-D34-OPDEP-A', 'V-M34-f504-i00', 4, 0, 0, 0x7fff, 0x321,
    exps34(4, 0, 0x7fff, 0x321, rogue=ROGUE[(0, 0)]),
    'rogue operand-independence: (4,0,0) with wide-distinct operands '
    '(0x7fff,0x321); rogue predicts 0xc regardless of operands'))
out.append(value_patch(
    'V-D34-OPDEP-B', 'V-M34-f508-i10-f1', 8, 10, 1, 0x7fff, 0x321,
    exps34(8, 10, 0x7fff, 0x321, rogue=0x3634),
    'rogue operand-independence: (8,10,1) with (0x7fff,0x321); live table '
    '0x3634 came from other operands (f5 8/12/22 identical)'))
# --- op0x34 rogue: idx sweep at f5=4 (exploratory, no expectations)
for idx in (1, 2, 3):
    out.append(value_patch(
        'V-D34-IDX%d' % idx, 'V-M34-f504-i00', 4, idx, 0, 1, 0,
        {}, 'rogue idx-axis at f5=4: idx=%d flag=0, exploratory capture'
        % idx))
out.append(value_patch(
    'V-D34-IDX1F', 'V-M34-f504-i00', 4, 1, 1, 1, 0,
    {}, 'rogue flag-axis at f5=4: idx=1 flag=1, exploratory capture'))
# --- op0x34 f5=0xb: depM vs rogue (depM matched 0xd0005 at (16,1) = rogue)
out.append(value_patch(
    'V-D34-F0B', 'V-M34-f504-i00', 0xb, 0, 0, 0x1234, 0x567,
    exps34(0xb, 0, 0x1234, 0x567, rogue=ROGUE[(0, 0)]),
    'f5=0b at (0,0): depR/depM predict operand-dependent values, rogue '
    'predicts 0xc; (16,1) point was degenerate (depM==rogue 0xd0005)'))
# --- op0x34 f5=2 flag=1: rogue membership (bclr family is flag=0 only?)
out.append(value_patch(
    'V-D34-F2F1', 'V-M34-f502-i00', 2, 0, 1, 5, 3,
    exps34(2, 0, 5, 3, rogue=ROGUE[(0, 1)]),
    'f5=2 flag=1 at (0): bclr/depR(W2)/depM predict operand values, '
    'rogue (0,1) predicts 0xd; live point (2,26,1)=0x070f0f0f was rogue'))

# --- op0x36 f5=0xa: split {eq32, eq16, V} (live: P(5,3)=F, P(0,1)=F)
D36 = [('H-eq32', gm.PRED36['H-eq32']), ('H-eq16', gm.PRED36['H-eq16']),
       ('H-lt32', gm.PRED36['H-lt32']), ('H-uge32', gm.PRED36['H-uge32']),
       ('H-ule32', gm.PRED36['H-ule32']), ('H-V', gm.PRED36['H-V'])]
v = gm.cc0a_echo_vec('V-D36-F0A-EQ16', 'disc', 0xa, (0x00010005, 0x0005),
                     D36, [],
                     'eq16-split: low16 equal, high16 differ; T={eq16} '
                     'F={eq32,lt32,uge32,ule32,V}')
rec = f4.emit(v)
rec['census_rows'] = []
out.append(rec)
v = gm.cc0a_cr_vec('V-D36-F0A-EQ', 'disc', 0xa, (7, 7), D36, [],
                   'equal pair: T={eq32,eq16,ule32} F={V}; predecessor '
                   'cmp38(7,7)=TRUE -> stale-T caveat (recorded)')
rec = f4.emit(v)
rec['census_rows'] = []
rec['stale_t'] = True
out.append(rec)

# --- op0x33 f5=0 flag=1: split {pass,min} with (rs,rt)=(5,3)
out.append(value_patch(
    'V-D33-F0F1', 'V-M33-f500-i00-f1', 0, 0, 1, 5, 3,
    exps33(0, 0, 5, 3),
    'pass/min split: rs=5 rt=3 -> pass=5, min=3 (old point (3,5) was '
    'degenerate: pass==min==3)'))

marker = BY['V-F4-MARKER']
ids = [r['id'] for r in out]
assert len(set(ids)) == len(ids), 'dup ids'
for r in out:
    joined = ''.join(r['words'])
    assert len(r['words']) == 10 and len(joined) == 80, r['id']
    f4.check_write_discipline([int(w, 16) for w in r['words']], r['id'])

dst = Path(__file__).resolve().parent / 'fuzz5_disc_vectors.json'
dst.write_text(json.dumps([marker] + out, indent=1) + '\n')
print('written %s: %d vectors + marker' % (dst, len(out)))
for r in out:
    print(' ', r['id'], 'exps:', len(r.get('expectations') or {}))
