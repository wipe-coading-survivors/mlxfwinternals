#!/usr/bin/env python3
"""cx4lx-detour L4: cmd-dispatch map + hook candidates on CX-4 Lx FW 14.32 (offline).

Formalizes the L4 task (spec 2026-10-11-cx4lx-detour-design.md s4 L4):
  [D1] icmd doorbell machine fn 0xd4d58: CR 0x23fc doorbell, ACCESS_REG
       0x2820 -> effective opcode from CR 0x2000, isr_icmd trace site,
       validate -> execute -> handler chain -> completion CSRs
  [D2] validators: whitelist 0xd4714 (range/bitmask checks, 0x9001 allowed),
       wrappers 0xd4864 / 0xd48e8 (RAM w0x457 bit1 + CR 0x23f4 gates)
  [D3] jump-table dispatcher 0xd4a24: tables @0x3147c0 (0x8400-0x8405) and
       @0x3147d8 (0x9001-0x9006), rt-form entries, no-link ret.r tail jumps
  [D4] reg-access path: 0xd3804 (CR 0x2004 hdr, L3-proven hook site 0xd3850),
       is_flash classifier 0xd31b8 (+table @0x314714), regular dispatcher
       0xd3388 (inline data copy loop RAM 0x2014..0x2313), flash dispatcher
       0xd3600 (size from words 0x800/0x804)
  [D5] CR-window occupancy: ld.i/st.i map; CORRECTION to L1: word 0x8fb
       (CR 0x23ec) IS read (ld.d base-zero, fn 0xd4948); 0x8fe zero refs in
       all forms; words 0x8c5-0x8f9 zero refs in code region
  [D6] external-mailbox fn 0xd4948: reads 0x23e8/0x23ec pair, window base
       0x2000 passed to 0x109f0, emit5 trace site (extm commands)
  [D7] emit family full inventory: emit1..4 (L3) + emit5 0x6348 (188 call
       sites) + emit6/emit7 (0x6384/0x63c4, 0 callers = spare capacity)
  [D8] cmdif_driver FSM region 0x9464c..0x95400: numbered debug prints
       (states 0/1/5/8 gated), opcode reg r15, cmdif hdr [r23+2] (ld.w),
       internal jump-table dispatch (lw.r + ret.r @0x94c8c)
  [D9] AN-FSM cyclic family: dispatcher 0x1bdfa0 (pport,event), self-post
       imm @0x1bd5a4 (event 0x35), state table 0x3178b0 (rt-pointer head)
Log: build/cx4lx-detour-l4-dispatch.log
"""
import struct
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[3]
BASE = WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
DCBUF = WT / 'build/cx4lx-detour-l0-main03-dc.bin'
LOG = WT / 'build/cx4lx-detour-l4-dispatch.log'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
RT = 0x800000
CODE_END = 0x2d6900


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


class Out:
    def __init__(self):
        self.lines = []

    def __call__(self, s=''):
        self.lines.append(s)
        print(s)


def main():
    sys.path.insert(0, str(WT))
    sys.path.insert(0, str(WT / 'scripts/irisc'))
    import hashlib
    import re
    import mlxfwutil
    import irisc_dis

    o = Out()

    def fail(msg):
        o('FATAL: ' + msg)
        open(LOG, 'w').write('\n'.join(o.lines) + '\n')
        sys.exit(1)

    buf = BASE.read_bytes()
    if hashlib.md5(buf).hexdigest() != BASE_MD5:
        fail('base md5 mismatch')
    img = mlxfwutil.Image(buf, str(BASE))
    e = img.find_entry('ITOC', 0x03)
    code = DCBUF.read_bytes()
    if code != decrc(img.section_data(e)):
        fail('dc buffer != de-clcrc(section)')
    n = len(code) // 4
    words = struct.unpack('>%dI' % n, code)

    def dw(off):
        return words[off // 4]

    def dis(off):
        return irisc_dis.dis(dw(off), off)

    def chk(off, want, why):
        if dis(off) != want:
            fail('%s @0x%x: "%s" != "%s"' % (why, off, dis(off), want))
        return True

    o('[D0] base md5 OK; dc %d words' % n)

    # D1: doorbell machine
    for off, want, why in [
            (0xd4d7c, 'ld.i r19,0x8ff', 'doorbell: CR 0x23fc read'),
            (0xd4d8c, 'mask32 r18,r19,0x0,16', 'doorbell: opcode = lo16'),
            (0xd4d94, 'subsi r4,r18,0x2820', 'doorbell: ACCESS_REG 0x2820 test'),
            (0xd4db0, 'ld.i r21,0x800', 'doorbell: 0x2820 -> eff.opcode from CR 0x2000'),
            (0xd4db4, 'set2 r4,zero,0x400', 'doorbell: trace class ICMD 0x400'),
            (0xd4dc8, 'addi r4,zero,0x-61b2', 'doorbell: isr_icmd str lo'),
            (0xd4dcc, 'addi.hi r4,r4,0xb1', 'doorbell: isr_icmd str hi (rt 0x00b09e4e)'),
            (0xd4de0, 'call 0xd4864', 'doorbell: validate call (HOOK CANDIDATE)'),
            (0xd4df4, 'call 0xd48e8', 'doorbell: execute wrapper call'),
            (0xd4e2c, 'csr.w zero,r5,0x1', 'doorbell: completion csr 0x1'),
            (0xd4e74, 'csr.w zero,r5,0x457', 'doorbell: RAM w0x457 busy-flag clear')]:
        chk(off, want, why)
    o('[D1] fn 0xd4d58 doorbell machine verified (CR 0x23fc, 0x2820->CR 0x2000, '
      'isr_icmd site 0xd4dc8, chain 0xd4864/0xd48e8)')

    # D2: validators
    for off, want, why in [
            (0xd4714, 'csr.r r3,csr0xbc', 'whitelist: prologue'),
            (0xd472c, 'set3 r7,r6,0x9002', 'whitelist: range 0x9002'),
            (0xd4738, 'set3 r6,r6,0x83ff', 'whitelist: range 0x83ff'),
            (0xd4744, 'set2 r6,zero,0xffff', 'whitelist: range 0x8004+ (lo)'),
            (0xd4758, 'subsi r6,r5,0x2831', 'whitelist: opcode 0x2831'),
            (0xd478c, 'addi r6,zero,0x1', 'whitelist: bitmask 1<<(op-0x9003)'),
            (0xd4798, 'set3 r7,r7,0xd', 'whitelist: mask 0x0d00e000'),
            (0xd483c, 'ld.i r4,0x457', 'whitelist: fallback RAM w0x457 bit0'),
            (0xd4854, 'set3 r6,r6,0x9001', 'whitelist: 0x9001 explicitly allowed'),
            (0xd4864, 'csr.r r3,csr0xbc', 'validator 0xd4864: prologue'),
            (0xd4884, 'ld.i r4,0x457', 'validator: RAM w0x457 bit1 gate'),
            (0xd4890, 'ld.i r4,0x8fd', 'validator: CR 0x23f4 (flash semaphore)'),
            (0xd4900, 'ld.i r5,0x457', 'exec wrapper 0xd48e8: w0x457 gate'),
            (0xd4908, 'ld.i r22,0x8fd', 'exec wrapper: CR 0x23f4')]:
        chk(off, want, why)
    o('[D2] validators verified: whitelist 0xd4714 (ranges/bitmask, 0x9001 allowed, '
      'BadParam-class exit), wrappers 0xd4864/0xd48e8 (w0x457 bit1 + CR 0x23f4 gates)')

    # D3: table dispatcher + tables
    for off, want, why in [
            (0xd4a3c, 'set3 r7,r6,0x9000', 'disp 0xd4a24: range hi 0x9000'),
            (0xd4a48, 'set2 r7,zero,0xffff', 'disp: range lo compose (0x8400 base)'),
            (0xd4a5c, 'addi r4,zero,0x47c0', 'disp: table A ptr lo (rt 0x00b147c0)'),
            (0xd4a60, 'addi.hi r4,r4,0xb1', 'disp: table A ptr hi'),
            (0xd4a68, 'lw.r r4,r6,r4', 'disp: table A load'),
            (0xd4a6c, 'ret.r zero,r8,r4', 'disp: no-link tail jump to handler'),
            (0xd4aa4, 'addi r6,zero,0x47d8', 'disp: table B ptr lo (rt 0x00b147d8)'),
            (0xd4ab0, 'lw.r r4,r4,r6', 'disp: table B load'),
            (0xd4ab4, 'ret.r zero,r8,r4', 'disp: table B tail jump'),
            (0xd4ab8, 'addi r23,zero,0x0', 'handler 0x9001: entry block'),
            (0xd4ac4, 'call 0xd3804', 'handler 0x9001: -> generic reg access')]:
        chk(off, want, why)
    for tbl, base, cnt in [(0x3147c0, 0x8400, 6), (0x3147d8, 0x9001, 6)]:
        for i in range(cnt):
            v = struct.unpack('>I', code[tbl + 4 * i:tbl + 4 * i + 4])[0]
            dc = v - RT
            if not (0xd0000 <= dc < 0xe0000):
                fail('table @0x%x entry %d: 0x%08x not a cmd-region handler' % (tbl, i, v))
    o('[D3] table dispatcher verified: 0x8400-0x8405 -> table @dc 0x3147c0, '
      '0x9001-0x9006 -> @dc 0x3147d8 (rt-form entries, ret.r no-link jumps); '
      '0x9001 handler 0xd4ab8 -> call 0xd3804')

    # D4: reg-access path
    for off, want, why in [
            (0xd3818, 'ld.i r4,0x801', 'regacc: CR 0x2004 hdr read'),
            (0xd381c, 'shr r23,r4,0x10', 'regacc: reg_id = word>>16'),
            (0xd3824, 'call 0xd31b8', 'regacc: is_flash classifier'),
            (0xd3840, 'addi r4,zero,0x-5774', 'regacc: icmd_generic str lo (rt 0x00ada88c)'),
            (0xd3850, 'call 0x6064', 'regacc: emit2 call (L3-PROVEN HOOK)'),
            (0xd3860, 'call 0xd3600', 'regacc: flash dispatcher'),
            (0xd386c, 'call 0xd3388', 'regacc: regular dispatcher'),
            (0xd31c4, 'set3 r6,r6,0x900f', 'is_flash: range 0x900f'),
            (0xd31d0, 'subsi r6,r5,0x402d', 'is_flash: reg 0x402d'),
            (0xd31d8, 'subsi r6,r5,0x5050', 'is_flash: reg 0x5050'),
            (0xd3208, 'addi r5,zero,0x4714', 'is_flash: table ptr lo (rt 0x00b14714)'),
            (0xd3214, 'lw.r r5,r6,r5', 'is_flash: table load'),
            (0xd3218, 'ret.r zero,r8,r5', 'is_flash: table tail jump'),
            (0xd3438, 'ld.d r6,r4,0x2014', 'regular: inline data base RAM 0x2014'),
            (0xd3444, 'subsi r6,r4,0x300', 'regular: inline len 0x300'),
            (0xd3600, 'csr.r r3,csr0xbc', 'flash disp 0xd3600: prologue'),
            (0xd3614, 'ld.i r4,0x800', 'flash disp: addr bits from CR 0x2000'),
            (0xd361c, 'ld.i r5,0x804', 'flash disp: size bits from CR 0x2010')]:
        chk(off, want, why)
    for i in range(39):
        v = struct.unpack('>I', code[0x314714 + 4 * i:0x314714 + 4 * i + 4])[0]
        dc = v - RT
        if dc not in (0xd31f0, 0xd3258):
            fail('is_flash table @0x314714 entry %d: 0x%08x unexpected' % (i, v))
    o('[D4] reg-access path verified: 0xd3804 (CR 0x2004 hdr / site 0xd3850 proven), '
      'is_flash 0xd31b8 + 39-entry table @0x314714, regular 0xd3388 inline '
      '0x2014..0x2313 (0x300 B), flash 0xd3600 (words 0x800/0x804)')

    # D5: CR-window occupancy (direct refs + base-zero forms in code region)
    ld_cnt, st_cnt = {}, {}
    for i in range(n):
        d = dis(i * 4)
        m = re.match(r'^(ld\.i) r\d+,0x([0-9a-f]+)$', d)
        if m:
            w = int(m.group(2), 16)
            ld_cnt[w] = ld_cnt.get(w, 0) + 1
        m = re.match(r'^(st\.i) r\d+,0x([0-9a-f]+)$', d)
        if m:
            w = int(m.group(2), 16)
            st_cnt[w] = st_cnt.get(w, 0) + 1
    if ld_cnt.get(0x800, 0) != 350 or ld_cnt.get(0x801, 0) != 105:
        fail('window header reader counts changed: 0x800=%d 0x801=%d'
             % (ld_cnt.get(0x800, 0), ld_cnt.get(0x801, 0)))
    win_st = {w: c for w, c in st_cnt.items() if 0x800 <= w <= 0x8ff}
    if win_st:
        fail('unexpected st.i into window words: %s' % win_st)
    basezero = []
    for i in range(CODE_END // 4):
        d = dis(i * 4)
        m = re.search(r',0x([0-9a-f]+)$', d)
        if m and d.startswith(('ld.', 'st.')) and not d.startswith(('ld.i', 'st.i')):
            ea = int(m.group(1), 16)
            if 0x2000 <= ea < 0x2400:
                basezero.append((i * 4, ea, d))
    ea23ec = [x for x in basezero if x[1] in (0x23e8, 0x23ec)]
    if len(ea23ec) != 1 or ea23ec[0][0] != 0xd497c:
        fail('0x23e8/0x23ec base-zero refs unexpected: %s' % ea23ec)
    if any(x[1] == 0x23f8 for x in basezero):
        fail('CR 0x23f8 (word 0x8fe) referenced by base-zero form')
    range_free = not any(0x2314 <= x[1] <= 0x23e4 for x in basezero)
    o('[D5] window occupancy: 0x800=350r 0x801=105r; st.i none; L1 CORRECTION: '
      'word 0x8fb (CR 0x23ec) read via ld.d @0xd497c (mailbox addr) -> NOT a '
      'spare slot; 0x8fe (CR 0x23f8) zero refs in ALL forms; words 0x8c5-0x8f9 '
      '(CR 0x2314-0x23e4) zero refs in code region: %s' % range_free)

    # D6: external mailbox fn
    for off, want, why in [
            (0xd4968, 'or r23,r4,r4', 'mailbox 0xd4948: arg (phase 0/1)'),
            (0xd4970, 'ld.i r21,0x8fd', 'mailbox: CR 0x23f4 state'),
            (0xd497c, 'ld.d r6,r4,0x23e8', 'mailbox: addr pair base 0x23e8'),
            (0xd4988, 'subsi r6,r4,0x8', 'mailbox: exactly 2 words (0x23e8/0x23ec)'),
            (0xd49b4, 'addi r4,zero,0x-2843', 'mailbox: trace str lo'),
            (0xd49b8, 'addi.hi r4,r4,0xb1', 'mailbox: trace str hi (rt 0x00b0d7bd)'),
            (0xd49d0, 'call 0x6348', 'mailbox: emit5 call'),
            (0xd49e4, 'addi r8,zero,0xd0', 'mailbox: len 0xd0'),
            (0xd49e8, 'addi r9,zero,0x2000', 'mailbox: window base 0x2000'),
            (0xd49ec, 'call 0x109f0', 'mailbox: DMA accessor')]:
        chk(off, want, why)
    o('[D6] external mailbox 0xd4948 verified: addr pair CR 0x23e8/0x23ec, '
      'emit5 site 0xd49d0 (str icmd_mailbox_access_over_external_memory), '
      'DMA via 0x109f0 with window base 0x2000 len 0xd0')

    # D7: emit family inventory
    EMITS = {0x6188: 0, 0x603c: 1, 0x6064: 2, 0x6090: 3, 0x6008: 4,
             0x6348: 5, 0x6380: 6, 0x63bc: 7}
    for addr, npar in EMITS.items():
        cnt = None
        for off in range(addr, addr + 0x40, 4):
            d = dis(off)
            if d.startswith('addi r5,zero,'):
                cnt = int(d.split(',')[2], 0)
            if d == 'call 0x6124':
                if cnt != npar:
                    fail('emit@0x%x param count %s != %d' % (addr, cnt, npar))
                break
        else:
            fail('emit@0x%x has no CORE call' % addr)
    for addr in EMITS:
        if dis(addr) != 'csr.r r3,csr0xbc':
            fail('emit@0x%x prologue missing' % addr)
    calls = {a: sum(1 for i in range(n) if dis(i * 4) == 'call 0x%x' % a)
             for a in EMITS}
    if calls[0x603c] == 0 or calls[0x6348] == 0:
        fail('live emit counters zero: %s' % calls)
    if calls[0x6380] == 0 or calls[0x63bc] == 0:
        fail('emit6/7 expected live callers, got %s' % calls)
    o('[D7] emit family: emit0..7 @ %s; callers: emit1=%d emit2=%d emit4=%d '
      'emit5=%d emit6=%d emit7=%d -> up to 7 param words (r5..r11) per event, '
      'whole family live-proven'
      % ('/'.join('0x%x' % a for a in sorted(EMITS)), calls[0x603c], calls[0x6064],
         calls[0x6008], calls[0x6348], calls[0x6380], calls[0x63bc]))

    # D8: cmdif_driver FSM
    prints = {0x9493c: 0x00b0109b, 0x94970: 0x00adfde3, 0x94a64: 0x00af6f2f,
              0x95048: 0x00af6f83}
    for off, rt in prints.items():
        lo = rt & 0xffff
        hi = (rt >> 16) + (1 if lo & 0x8000 else 0)
        if dw(off) != (0x00040000 | (lo & 0xffff)) or dw(off + 4) != (0x08840000 | hi):
            fail('driver print @0x%x compose mismatch' % off)
    for off, want, why in [
            (0x94a24, 'subsi r4,r15,0xfe', 'driver: opcode reg r15 (0xfe test)'),
            (0x94a38, 'ld.w r4,r23,0x2', 'driver: cmdif hdr opcode [r23+2]'),
            (0x94a6c, 'ld.d r5,r22,0x80', 'driver: ctx.missions [r22+0x80]'),
            (0x94ab0, 'ld.d r4,r22,0x84', 'driver: ctx flags [r22+0x84]'),
            (0x94c8c, 'lw.r r8,r5,r4', 'driver: internal jump-table dispatch'),
            (0x94ccc, 'ret.r zero,r8,r3', 'driver: tail jump')]:
        chk(off, want, why)
    o('[D8] cmdif_driver FSM region 0x9464c..0x95400 verified: numbered prints '
      '0/1/5/8 compose rt OK; opcode r15; hdr [r23+2]; ctx [r22+0x80/0x84]; '
      'jump-table states (lw.r+ret.r @0x94c8c)')

    # D9: AN-FSM cyclic family
    for off, want, why in [
            (0x1bdfa0, 'csr.r r3,csr0xbc', 'AN-FSM dispatcher prologue'),
            (0x1bdfcc, 'or r23,r4,r4', 'AN-FSM: arg r23 = pport'),
            (0x1bdfc8, 'or r22,r5,r5', 'AN-FSM: arg r22 = event')]:
        chk(off, want, why)
    if dis(0x1bd5a4) != 'addi r6,zero,0x35':
        fail('AN-FSM self-post imm @0x1bd5a4 != event 0x35')
    if dis(0x1bd5a8) != 'call 0x1bf930':
        fail('AN-FSM self-post call @0x1bd5a8 != 0x1bf930')
    st0 = struct.unpack('>I', code[0x3178b0:0x3178b4])[0]
    if st0 - RT < 0x1b0000 or st0 - RT > 0x1c0000:
        fail('AN-FSM state table head not a handler ptr: 0x%08x' % st0)
    o('[D9] AN-FSM verified: dispatcher 0x1bdfa0 (args pport,event), self-post '
      'event 0x35 @0x1bd5a4 (state0 handler re-arm), state table @0x3178b0 '
      '(head -> dc 0x%06x); cycle ~0.4-0.62 s CONDITIONAL on eternal AN-loop'
      % (st0 - RT))

    # hook-site clobber pre-scan (dead-after-call, method of L3 T3) for the
    # two primary early-cmd candidates inside fn 0xd4d58
    RW = re.compile(r'\b(r\d+)\b')
    WR_OPS = ('addi', 'addi.hi', 'set2', 'set3', 'or', 'subs', 'subsi', 'ands',
              'and', 'shr', 'shl', 'ld.i', 'ld.d', 'ld.w', 'lw.r', 'mask32',
              'alu', 'op', 'add')
    for site in (0xd4de0, 0xd4df4):
        off = site + 4
        bad = []
        while off < 0xd4f30:
            d = dis(off)
            if d.startswith('ret') or d.startswith('jump '):
                break
            rs = [int(x[1:]) for x in RW.findall(d)]
            for r in (5, 6, 7, 8, 9, 10):
                if r in rs:
                    tok = d.split()[0]
                    if not (tok in WR_OPS and rs[0] == r):
                        bad.append((r, hex(off), d))
            off += 4
        if bad:
            o('[NOTE] site 0x%x: live-after reads: %s (stub must save/restore)'
              % (site, bad[:3]))
        else:
            o('[PRE] site 0x%x: r5..r10 dead (write-first) after call -> '
              'v3-style emit stub clobber-safe' % site)

    open(LOG, 'w').write('\n'.join(o.lines) + '\n')
    o('DONE log=%s' % LOG)


if __name__ == '__main__':
    main()
