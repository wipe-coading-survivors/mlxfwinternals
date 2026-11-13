#!/usr/bin/env python3
"""cx4lx-dumpcycle R-A4b (Task 8): generic-exec payload word listings P1..P4.

Word source for the Task-9 live cycles (`mlxscope dump exec --words ...`):
each payload is assembled with irisc_asm (cx4lx profile, strict — every form
used here is live: set2/set3/st.d/ld.d/jump, decode-verify per word) at the
RUNTIME org = fragment 0x31cb70 (the copy-loop dst rt 0xb1cb70), where the
stub executes the copied words. The LAST word of every payload is the tail
jump `jump <tail>` (1 word of the <=10 budget): tail = 0x31cbf4 with
--copydone on (marker @0x31cbec, exec-jump @0x31cbf0, csr.w @0x31cbf4),
0x31cbf0 with off — the tail word is org-aware: it is re-assembled at the
fragment address 0x31cb70+4*(N-1) and must be bit-exact to payload[N-1].

Payloads (addendum Global Constraints):
  P1 (6 w, marker-READY):    MAGIC -> CR 0x2320 (w0x8c8); expect = MAGIC.
  P2 (9 w, self-echo):       payload[0]/[1] read back via ld.d from the copied
                             buffer at 0x31cb70 -> 0x2320/0x2324; expect =
                             payload[0] (bit-exact copy proof).
  P3 (7 w, one-word read):   SHA-256 K[0] 0x428a2f98 (rt 0xb19850, anchor
                             sha256_k_table_dc 0x319850) -> 0x2320.
  P4 (6 w, COPY-DONE verify): writes ONLY w0x8c9 (CR 0x2324) = 0x600D600D,
                             leaves w0x8c8 = the stub marker (payload[N-1] =
                             the tail-jump word — printed, the `--expect`
                             input for P4).

Gates: word counts 6/9/7/6 <= PLD_MAX(10) == Task-7 LAYOUT; strict assemble
== hardcoded verified listing (EXPECTED_P, frozen in the Task-8 journal/
report); per-word decode gate (each word's irisc_dis render re-assembles
strict bit-exact at its own address); org-aware tail re-assembly
bit-exact; tail address per --copydone; no payload word accidentally
zero. Output: words as comma-separated hex (CLI-ready, no 0x prefix) +
expect values; log default derives from --copydone: on ->
build/cx4lx-dump-ra4b-payloads.log, off -> build/cx4lx-dump-ra4b-off-payloads.log
(mirrors the builder's per-variant --out naming).
"""
import argparse
import struct
import sys
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, REPO)
sys.path.insert(0, REPO + '/scripts/irisc')
import irisc_dis
from scripts.irisc import assemble, AsmError
from scripts.irisc.profiles import load_profile

FRAG_DC = 0x31cb70          # copy dst (rt 0xb1cb70) = payload runtime org
MAGIC = 0x44554D31          # Task-7 LAYOUT::MAGIC (verbatim, Review Focus 3)
W_PLD = 0x8c7               # Task-7 LAYOUT::W_PLD (payload zone start)
W_RESP = 0x8c8              # Task-7 LAYOUT::W_RESP (CR 0x2320)
PLD_MAX = 10                # Task-7 LAYOUT::PLD_MAX (0x8c7..0x8d0)
RESP_CR = W_RESP * 4        # 0x2320
TAIL_DC = {'on': 0x31cbf4, 'off': 0x31cbf0}
SHA256_K0_RT = 0xb19850     # SHA-256 K[0] table anchor (dc 0x319850)
SHA256_K0 = 0x428a2f98
P4_WORD = 0x600D600D

PAYLOADS = {
    'P1': (6, 'set2 r5,zero,0x%x\nset3 r5,r5,0x%x\n'
               'set2 r4,zero,0x0\nset3 r4,r4,0x%x\n'
               'st.d r5,r4,0x0\n'
            % (MAGIC >> 16, MAGIC & 0xffff, RESP_CR)),
    'P2': (9, 'set2 r3,zero,0x%x\nset3 r3,r3,0x%x\n'
               'ld.d r5,r3,0x0\nld.d r6,r3,0x4\n'
               'set2 r4,zero,0x0\nset3 r4,r4,0x%x\n'
               'st.d r5,r4,0x0\nst.d r6,r4,0x4\n'
            % ((FRAG_DC + 0x800000) >> 16, (FRAG_DC + 0x800000) & 0xffff, RESP_CR)),
    'P3': (7, 'set2 r3,zero,0x%x\nset3 r3,r3,0x%x\n'
               'ld.d r5,r3,0x0\n'
               'set2 r4,zero,0x0\nset3 r4,r4,0x%x\n'
               'st.d r5,r4,0x0\n'
            % (SHA256_K0_RT >> 16, SHA256_K0_RT & 0xffff, RESP_CR)),
    'P4': (6, 'set2 r5,zero,0x%x\nset3 r5,r5,0x%x\n'
               'set2 r4,zero,0x0\nset3 r4,r4,0x%x\n'
               'st.d r5,r4,0x0\n'
            % (P4_WORD >> 16, P4_WORD & 0xffff, RESP_CR + 4)),
}

EXPECT = {
    'P1': ('MAGIC echo @w0x%x (filter+copy+st.d->image+exec+channel)' % W_RESP,
           lambda ws: MAGIC),
    'P2': ('self-echo payload[0] @w0x%x, payload[1] @w0x%x (bit-exact copy + ld.d'
           ' from buffer)' % (W_RESP, W_RESP + 1), lambda ws: ws[0]),
    'P3': ('SHA-256 K[0] 0x%08x @w0x%x (arbitrary host-code read)' % (SHA256_K0, W_RESP),
           lambda ws: SHA256_K0),
    'P4': ('COPY-DONE marker payload[N-1] (tail-jump word) @w0x%x, exec effect'
           ' 0x%08x @w0x%x (base-zero st.d live, R-A1 s.5.4)' % (
               W_RESP, P4_WORD, W_RESP + 1), lambda ws: ws[-1]),
}

# Frozen verified listings (Task-8 journal/report — Task-9 live inputs):
# heads identical for both tails, last word = org-aware tail jump.
EXPECTED_P = {
    'on': {
        'P1': [0x24054455, 0x20a54d31, 0x24040000, 0x20842320, 0x6c802802, 0x9500001c],
        'P2': [0x240300b1, 0x2063cb70, 0x64650002, 0x64660006, 0x24040000, 0x20842320,
               0x6c802802, 0x6c803006, 0x95000019],
        'P3': [0x240300b1, 0x20639850, 0x64650002, 0x24040000, 0x20842320, 0x6c802802,
               0x9500001b],
        'P4': [0x2405600d, 0x20a5600d, 0x24040000, 0x20842324, 0x6c802802, 0x9500001c],
    },
    'off': {
        'P1': [0x24054455, 0x20a54d31, 0x24040000, 0x20842320, 0x6c802802, 0x9500001b],
        'P2': [0x240300b1, 0x2063cb70, 0x64650002, 0x64660006, 0x24040000, 0x20842320,
               0x6c802802, 0x6c803006, 0x95000018],
        'P3': [0x240300b1, 0x20639850, 0x64650002, 0x24040000, 0x20842320, 0x6c802802,
               0x9500001a],
        'P4': [0x2405600d, 0x20a5600d, 0x24040000, 0x20842324, 0x6c802802, 0x9500001b],
    },
}


def die(msg):
    print('FATAL: ' + msg)
    sys.exit(1)


def parse_args():
    p = argparse.ArgumentParser(description='cx4lx-dumpcycle R-A4b payload listings (P1..P4)')
    p.add_argument('--copydone', choices=('on', 'off'), default='on',
                   help='tail convention of the burned image: on (default) = tail'
                        ' 0x31cbf4; off = 0x31cbf0 (must match build_dump_ra3.py)')
    p.add_argument('--log', default=None,
                   help='default: build/cx4lx-dump-ra4b-payloads.log (--copydone on),'
                        ' build/cx4lx-dump-ra4b-off-payloads.log (off)')
    return p.parse_args()


lines_out = []
def say(msg=''):
    print(msg)
    lines_out.append(msg)


def main():
    args = parse_args()
    if args.log is None:
        args.log = REPO + '/build/cx4lx-dump-ra4b%s-payloads.log' % (
            '' if args.copydone == 'on' else '-off')
    prof = load_profile('cx4lx')
    tail = TAIL_DC[args.copydone]
    say('cx4lx-dump-ra4b payloads (--copydone %s): runtime org = fragment 0x%x'
        ' (dst rt 0x%x), tail 0x%x, PLD_MAX %d (w0x%x..w0x%x)' % (
            args.copydone, FRAG_DC, FRAG_DC + 0x800000, tail, PLD_MAX, W_PLD,
            W_PLD + PLD_MAX - 1))
    out = {}
    for name in ('P1', 'P2', 'P3', 'P4'):
        n, body = PAYLOADS[name]
        text = body + 'jump 0x%x\n' % tail
        try:
            data = assemble(text, base=FRAG_DC, profile=prof, strict=True)
        except AsmError as ex:
            die('%s strict assembly failed: %s' % (name, ex))
        ws = list(struct.unpack('>%dI' % (len(data) // 4), data))
        if len(ws) != n or len(ws) > PLD_MAX:
            die('%s is %d words, expected %d (<= PLD_MAX %d)' % (name, len(ws), n, PLD_MAX))
        if 0 in ws:
            die('%s contains a zero word (buffer stays zero = silent nop)' % name)
        if ws != EXPECTED_P[args.copydone][name]:
            die('%s (--copydone %s): assembled words != frozen verified listing\n'
                '  got      %s\n  expected %s'
                % (name, args.copydone, ['%08x' % w for w in ws],
                   ['%08x' % w for w in EXPECTED_P[args.copydone][name]]))
        last = ws[-1]
        d2 = assemble('jump 0x%x\n' % tail, base=FRAG_DC + 4 * (n - 1),
                      profile=prof, strict=True)
        if struct.unpack('>I', d2)[0] != last:
            die('%s: tail word %08x is not org-aware @0x%x (re-assembled %08x)'
                % (name, last, FRAG_DC + 4 * (n - 1), struct.unpack('>I', d2)[0]))
        if irisc_dis.dis(last, FRAG_DC + 4 * (n - 1)) != 'jump 0x%x' % tail:
            die('%s: last word does not decode as jump 0x%x' % (name, tail))
        for i, w in enumerate(ws):
            d = irisc_dis.dis(w, FRAG_DC + 4 * i)
            try:
                w2 = struct.unpack('>I', assemble(d, base=FRAG_DC + 4 * i,
                                                  profile=prof, strict=True))[0]
            except AsmError as ex:
                die('%s[%d] %08x: decode %r does not re-assemble: %s' % (name, i, w, d, ex))
            if w2 != w:
                die('%s[%d] %08x: decode %r re-assembles to %08x (not bit-exact)'
                    % (name, i, w, d, w2))
            say('    %s[%d] @0x%x %08x = %s' % (name, i, FRAG_DC + 4 * i, w, d))
        note, exp = EXPECT[name]
        out[name] = (ws, exp(ws))
        say('%s n=%d words=%s expect=0x%08x%s' % (
            name, len(ws), ','.join('%08x' % w for w in ws), exp(ws),
            ' [== frozen EXPECTED_P listing]' if ws == EXPECTED_P[args.copydone][name]
            else ''))
        say('    %s' % note)
    p4_marker = out['P4'][0][-1]
    say('P4 marker (payload[N-1] tail-jump word, --expect input) = %08x' % p4_marker)
    say('P4 full CLI: --words %s --expect 0x%08x' % (
        ','.join('%08x' % w for w in out['P4'][0]), p4_marker))
    Path(args.log).parent.mkdir(parents=True, exist_ok=True)
    open(args.log, 'w').write('\n'.join(lines_out) + '\n')
    say('DONE log=%s' % args.log)


if __name__ == '__main__':
    main()
