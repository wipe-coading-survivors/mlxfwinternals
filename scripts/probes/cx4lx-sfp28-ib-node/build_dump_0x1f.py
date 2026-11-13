#!/usr/bin/env python3
"""cx4lx-sfp28-ib-node task-04l/04o: build the combined 0x1f+<trigger> dump images.

Image = consumer stock ri (base md5 dacbcf0e...) + two MAIN_CODE patches
+ R1 build-ID in 0x30:

1) C12-gate-lift word: dc 0x1f1f00 (raw 0x37e0f0)
   0xfcb1c083 -> 0x0011001f (addi r17,zero,0x1f; the 0x1f C12-analog word,
   task-04b/04h: lifts the C12 gate pm 0->2, Polling, so the AN path is
   active for the C12 module);
2) D2 dump hook (trigger-selectable; task-04l: H0, task-04o: H6):
   - H0: dc 0xd3850 (raw 0x24dbd4) 0x94fcca05 -> 0x940924d4 (call 0x31cba0)
     + the 18-word cave stub (stock emit2 call 0x6064 first; emit7 dump:
     self-check w2, bitset 0x0D600C..0x0D6018, gates 0xE2B4/0xD5DC).
     cx4lx-detour D2, live-proven on this card (task-04k: 71/71 events,
     self-check PASS). Trigger = any register command (host polling).
   - H6: dc 0x1b9da4 (raw 0x34277c) 0x94f93099 -> 0x94058b7f (call 0x31cba0)
     + the same 18-word stub (stock emit4 call 0x6008 first). Trigger =
     the AN-FSM trace site (~0.4 s loop, autonomous while AN is active).
     Silent on the STOCK base (AN gated, task-04k); on the 0x1f base the
     AN path is active (pm=2).

Why: root-fix data for the deterministic 14.32 Lx assert on the C12 module:
the bitset 0x0D600C..0x0D6018 + gates 0xE2B4/0xD5DC as 14.32 computes them
for C12. On the STOCK base the AN path is gated (pm=0) and the table is
never filled (task-04k baseline: 0x5014/0x30/0x0a0a0a0a/0x44444444, gates
0/0). On the 0x1f base the AN path is active, so the SAME hook prints the
AN-filled values. H0 saw the table only at register-command times -
task-04m (276 events): words 3-4 (0x0D6014/0x0D6018) NEVER filled (RAM
patterns), word 2 (0x0D6010) 0x30->0x0 on peer light - the fill process,
if any, runs autonomously in the AN path between host commands, invisible
to H0. H6 is the SAME emit7 stub called from the AN-FSM site - the only
way to observe the fill in the process. Risk (owner-accepted): if the H6
site is unreachable in the 14.32 AN path -> silence (still a result: move
to RE).

D2 mechanics are REUSED, not reimplemented: this driver runs
dump_d2_core.py (vendored copy of cx4lx-detour build_dump_d2.py, gates
[1]..[18]) as a subprocess with --trigger <H0|H6> + --extra-patch (the
0x1f word, pre-gated + decode-verified in the same clcrc/verify flow),
then adds:
  [G4]  regression diff vs the D2-<trigger> deliverable - expected ONLY
        the 0x37e0f0 zone (word + clcrc + ITOC entry) + the 0x30 build-ID
        zone;
  [G4i] informational diff vs the OTHER D2 deliverable - expected the
        0x1f zone + both hook-site zones + the stub word-1 zone + 0x30;
  [G9]  final == step1 byte-exact (device sections untouched, guides skip);
  [G10] determinism: second build -> bit-identical md5.
Core gates cover G0 ([1] base md5), G1 ([3] pre-patch words + cave zero +
boot word stock), G2 ([7] stub decode + [14] final words), G3 ([9]/[10]
clcrc round-trip + changed-line set), G5 ([11]/[13] verify deep),
G6 ([16] mstflint verify bootable), G7 ([17] q identity),
G8 ([13]/[18] 0x30 budget/addr + dc head marker).
"""
import argparse
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, REPO)
import mlxfwutil

CORE = str(Path(__file__).resolve().parent / 'dump_d2_core.py')
BASE_MD5 = 'dacbcf0e1cbc1bed3d5e916520fe6803'
X1F_DC = 0x1f1f00
X1F_RAW = 0x37e0f0
X1F_BEFORE = 0xfcb1c083
X1F_AFTER = 0x0011001f
X1F_DIS = 'addi r17,zero,0x1f'
SEC_ADDR = 0x16d000
HOOK_DC = {'H0': 0xd3850, 'H6': 0x1b9da4}
STUB_WORD1_DC = 0x31cba0 + 4  # cave word 1: stock-emit call (differs H0/H6)
TRIGGER_DATA = {
    'H0': dict(ref='cx4lx-dump-d2-h0.bin', ref_md5='34e3c615386ff0975aa5d2e1bde52387',
               out='cx4lx-dump-0x1f-h0.bin',
               build_id='; mlxini cx4lx-dump-0x1f-h0 (2026-10-11, dacbcf0e1cbc1bed3d5e916520fe6803): '
                        '0x1f mask (dc 0x1f1f00) + H0 dump hook @0xd3850 + emit7: '
                        'self-check 4000000, bitset 0x0D600C..0x0D6018, '
                        'gates 0xE2B4/0xD5DC (sfp28-ib-node root-fix)'),
    'H6': dict(ref='cx4lx-dump-d2-h6.bin', ref_md5='ab5c1c818636c3dc071490b5556b47de',
               out='cx4lx-dump-0x1f-h6.bin',
               build_id='; mlxini cx4lx-dump-0x1f-h6 (2026-10-11, dacbcf0e1cbc1bed3d5e916520fe6803): '
                        '0x1f mask (dc 0x1f1f00) + H6 AN-FSM dump hook + emit7: '
                        'self-check 4000000, bitset 0x0D600C..0x0D6018, '
                        'gates 0xE2B4/0xD5DC (sfp28-ib-node root-fix)'),
}


def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)


def md5of(p):
    return hashlib.md5(open(p, 'rb').read()).hexdigest()


def run_core(argv, label):
    r = subprocess.run([sys.executable, CORE] + argv, capture_output=True, text=True)
    for l in (r.stdout + r.stderr).strip().splitlines()[-12:]:
        print('  | ' + l)
    if r.returncode != 0:
        die('%s failed (rc=%d); last lines above' % (label, r.returncode))
    return r.stdout + r.stderr


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--trigger', default='H0', choices=sorted(TRIGGER_DATA),
                    help='H0 (register-command trigger, live-proven, task-04l) | '
                         'H6 (AN-FSM trigger, task-04o)')
    ap.add_argument('--base', default=REPO + '/build/c1-00-ri.bin',
                    help='consumer stock ri (md5-gated to %s)' % BASE_MD5)
    ap.add_argument('--ref', default=None,
                    help='D2-<trigger> deliverable for the [G4] regression diff '
                         '(default: per trigger)')
    ap.add_argument('--info-ref', default=None,
                    help='reference for the [G4i] informational cross-diff '
                         '(default: the OTHER D2 deliverable)')
    ap.add_argument('--out', default=None,
                    help='default: build/cx4lx-dump-0x1f-<trigger>.bin')
    ap.add_argument('--build-id-text', default=None,
                    help='R1 build-ID line (default: per trigger)')
    args = ap.parse_args()

    td = TRIGGER_DATA[args.trigger]
    other = 'H6' if args.trigger == 'H0' else 'H0'
    if args.ref is None:
        args.ref = REPO + '/build/' + td['ref']
    if args.info_ref is None:
        args.info_ref = REPO + '/build/' + TRIGGER_DATA[other]['ref']
    if args.out is None:
        args.out = REPO + '/build/' + td['out']
    if args.build_id_text is None:
        args.build_id_text = td['build_id']

    if not Path(args.base).is_file():
        die('base not found: %s' % args.base)
    if md5of(args.base) != BASE_MD5:
        die('base md5 mismatch (want %s)' % BASE_MD5)
    if not Path(args.ref).is_file():
        die('ref not found: %s' % args.ref)
    if md5of(args.ref) != td['ref_md5']:
        die('ref md5 mismatch (want %s) - G4 reference corrupt' % td['ref_md5'])
    if not Path(args.info_ref).is_file():
        die('info-ref not found: %s' % args.info_ref)
    if md5of(args.info_ref) != TRIGGER_DATA[other]['ref_md5']:
        die('info-ref md5 mismatch (want %s) - G4i reference corrupt' % TRIGGER_DATA[other]['ref_md5'])
    print('[G0] pre-check: base md5=%s OK; ref D2-%s md5=%s OK; info-ref D2-%s md5=%s OK'
          % (BASE_MD5, args.trigger, td['ref_md5'], other, TRIGGER_DATA[other]['ref_md5']))

    core_argv = ['--trigger', args.trigger,
                 '--base', args.base, '--base-md5', BASE_MD5,
                 '--guides', 'skip', '--out', args.out,
                 '--extra-patch', '0x%x:%08x:%08x:%s' % (X1F_DC, X1F_BEFORE, X1F_AFTER, X1F_DIS),
                 '--build-id-text', args.build_id_text,
                 '--build-id-date', '2026-10-11']
    print('[core] build 1:')
    for a in core_argv:
        print('      ' + a)
    core_out = run_core(core_argv, 'core build 1')
    for want in ('[18] mstflint dc', 'MT_2420110034', 'DONE'):
        if want not in core_out:
            die('core output missing %r - core gates did not all print' % want)

    out_final = open(args.out, 'rb').read()
    md5_final = hashlib.md5(out_final).hexdigest()

    img_new = mlxfwutil.Image(out_final, 'new')
    e03n = img_new.find_entry('ITOC', 0x03)
    e30n = img_new.find_entry('ITOC', 0x30)
    ent_off03 = img_new.itoc_off + 32 + e03n.index * 32
    ent_off30 = img_new.itoc_off + 32 + e30n.index * 32
    a3 = img_new.sec_abs(e30n)

    def word_zone(dc):
        line, within = divmod(dc, 64)
        raw = SEC_ADDR + line * 68 + within
        return set(range(raw, raw + 4)) | {SEC_ADDR + line * 68 + 66, SEC_ADDR + line * 68 + 67}

    # [G9] final == step1 outside the 0x30 build-ID intent zones (D2 [14]
    # precedent: final-vs-final-code = 0x30+entry only); DEV_INFO/MFG_INFO
    # (0xfee000/0xff8000) are far outside the allowed set.
    step1 = open(args.out + '.step1', 'rb').read()
    e30s = mlxfwutil.Image(step1, 'step1').find_entry('ITOC', 0x30)
    if img_new.sec_abs(e30s) != a3 or e30s.addr != e30n.addr:
        die('[G9] 0x30 moved between step1 and final: 0x%x/0x%x -> 0x%x/0x%x'
            % (e30s.addr, img_new.sec_abs(e30s), e30n.addr, a3))
    g9_allowed = set(range(a3, a3 + max(e30s.size, e30n.size)))
    g9_allowed |= set(range(ent_off30, ent_off30 + 32))
    g9_diffs = [i for i in range(len(step1)) if step1[i] != out_final[i]]
    g9_stray = [hex(i) for i in g9_diffs if i not in g9_allowed]
    if g9_stray:
        die('[G9] final != step1 outside 0x30 intent zones: %d stray bytes (first: %s)'
            % (len(g9_stray), g9_stray[:8]))
    print('[G9] final == step1 outside 0x30 intent zones: %d bytes differ, '
          'all in 0x30 section + ITOC-30 entry (DEV_INFO/MFG_INFO untouched)'
          % len(g9_diffs))

    # [G4] regression diff vs the D2-<trigger> deliverable (GATE)
    ref = open(args.ref, 'rb').read()
    if len(ref) != len(out_final):
        die('[G4] size mismatch vs ref: %d != %d' % (len(ref), len(out_final)))
    img_ref = mlxfwutil.Image(ref, 'ref')
    e03r = img_ref.find_entry('ITOC', 0x03)
    e30r = img_ref.find_entry('ITOC', 0x30)
    if (e03n.addr, e03n.size, e03n.clcrc) != (e03r.addr, e03r.size, e03r.clcrc):
        die('[G4] MAIN_CODE geometry differs vs ref')
    if e30n.addr != e30r.addr:
        die('[G4] 0x30 addr differs vs ref: 0x%x != 0x%x' % (e30n.addr, e30r.addr))
    allowed = word_zone(X1F_DC)
    allowed |= set(range(ent_off03 + 0x1a, ent_off03 + 0x20))
    allowed |= set(range(a3, a3 + max(e30n.size, e30r.size)))
    allowed |= set(range(ent_off30, ent_off30 + 32))
    diffs = [i for i in range(len(out_final)) if out_final[i] != ref[i]]
    stray = [hex(i) for i in diffs if i not in allowed]
    in_word = sum(1 for i in diffs if X1F_RAW <= i < X1F_RAW + 4)
    in_clcrc = sum(1 for i in diffs if i in word_zone(X1F_DC) and not (X1F_RAW <= i < X1F_RAW + 4))
    in_itoc03 = sum(1 for i in diffs if ent_off03 + 0x1a <= i < ent_off03 + 0x20)
    in_30 = sum(1 for i in diffs if a3 <= i < a3 + max(e30n.size, e30r.size))
    in_itoc30 = sum(1 for i in diffs if ent_off30 <= i < ent_off30 + 32)
    print('[G4] diff vs D2-%s: %d bytes (0x1f word=%d, clcrc=%d, ITOC-03 entry=%d, '
          '0x30 section=%d, ITOC-30 entry=%d); 0x30 size 0x%x -> 0x%x; strays=%s'
          % (args.trigger, len(diffs), in_word, in_clcrc, in_itoc03, in_30, in_itoc30,
             e30r.size, e30n.size, stray or 'NONE'))
    if stray:
        die('[G4] stray diff bytes vs D2-%s: %s' % (args.trigger, stray))

    # [G4i] informational diff vs the OTHER D2 deliverable (no gate:
    # expected zones = 0x1f + both hook sites + stub word 1 + 0x30)
    iref = open(args.info_ref, 'rb').read()
    iimg = mlxfwutil.Image(iref, 'info-ref')
    ie30 = iimg.find_entry('ITOC', 0x30)
    i_allowed = word_zone(X1F_DC)
    i_allowed |= word_zone(HOOK_DC[args.trigger])
    i_allowed |= word_zone(HOOK_DC[other])
    i_allowed |= word_zone(STUB_WORD1_DC)
    i_allowed |= set(range(ent_off03 + 0x1a, ent_off03 + 0x20))
    i_allowed |= set(range(a3, a3 + max(e30n.size, ie30.size)))
    i_allowed |= set(range(ent_off30, ent_off30 + 32))
    idiffs = [i for i in range(len(out_final)) if out_final[i] != iref[i]]
    istray = [hex(i) for i in idiffs if i not in i_allowed]
    print('[G4i] informational diff vs D2-%s: %d bytes (expected zones: 0x1f word+clcrc, '
          'hook dc 0x%x (ours, patched), hook dc 0x%x (theirs, patched), '
          'stub word1 dc 0x%x (stock-emit call differs), ITOC-03 entry, 0x30); '
          'strays=%s' % (other, len(idiffs), HOOK_DC[args.trigger], HOOK_DC[other],
                         STUB_WORD1_DC, istray or 'NONE'))

    with tempfile.TemporaryDirectory(prefix='dump0x1f-det2-') as td2:
        out2 = td2 + '/det2.bin'
        i_out = core_argv.index('--out')
        argv2 = core_argv[:i_out] + ['--out', out2] + core_argv[i_out + 2:]
        run_core(argv2, 'core build 2 (determinism)')
        md5_2 = md5of(out2)
    if md5_2 != md5_final:
        die('[G10] determinism FAIL: second build %s != %s' % (md5_2, md5_final))
    print('[G10] determinism: second build md5 identical (%s)' % md5_final)

    log = args.out.replace('.bin', '-build.log')
    with open(log, 'a') as f:
        f.write('\n--- driver gates (task-04l/04o, trigger %s) ---\n' % args.trigger)
        f.write('[G4] diff vs D2-%s (%s): %d bytes (0x1f word=%d, clcrc=%d, '
                'ITOC-03 entry=%d, 0x30 section=%d, ITOC-30 entry=%d), '
                '0x30 0x%x -> 0x%x, strays=NONE\n'
                % (args.trigger, td['ref_md5'], len(diffs), in_word, in_clcrc, in_itoc03,
                   in_30, in_itoc30, e30r.size, e30n.size))
        f.write('[G4i] informational diff vs D2-%s (%s): %d bytes, strays=%s\n'
                % (other, TRIGGER_DATA[other]['ref_md5'], len(idiffs), istray or 'NONE'))
        f.write('[G9] final == step1 outside 0x30 intent zones: %d bytes, '
                'strays=NONE (device sections untouched)\n' % len(g9_diffs))
        f.write('[G10] determinism OK: second build md5=%s\n' % md5_final)

    print('DONE %s md5=%s size=%d log=%s' % (args.out, md5_final, len(out_final), log))
    return 0


if __name__ == '__main__':
    sys.exit(main())
