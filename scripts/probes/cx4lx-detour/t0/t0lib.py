#!/usr/bin/env python3
"""cx4lx-detour T0 shared lib: base load, db0 string scan, loader/xref map."""
import struct
import sys
import re
from pathlib import Path

WT = Path.home() / 'git/IMPLEMENTATION/mlxini/.worktrees/cx4lx-detour'
sys.path.insert(0, str(WT))
sys.path.insert(0, str(WT / 'scripts/irisc'))
import mlxfwutil  # noqa: E402
from irisc_dis import dis, s16  # noqa: E402

BASE = WT / 'refs/fw/cx-4/fw-ConnectX4Lx-rel-14_32_1900-MCX4131A-GCA_Ax-UEFI-14.25.17-FlexBoot-3.6.502.bin'
BASE_MD5 = '3bd3230b1deae0cf74a08e31d59021d9'
RT = 0x800000
DB0_DC = 0x2d6900
DB0_SIZE = 0x44a00
CODE_END = DB0_DC          # code region below db0
GATE = 0x5f90
EMITS = {0x6188: 0, 0x603c: 1, 0x6064: 2, 0x6090: 3, 0x6008: 4,
         0x6348: 5, 0x6380: 6, 0x63bc: 7}


def decrc(data):
    out = bytearray()
    for i in range(len(data) // 68):
        out += data[i * 68:i * 68 + 64]
    return bytes(out)


class Code:
    def __init__(self):
        import hashlib
        buf = BASE.read_bytes()
        assert hashlib.md5(buf).hexdigest() == BASE_MD5, 'base md5 mismatch'
        img = mlxfwutil.Image(buf, str(BASE))
        e = img.find_entry('ITOC', 0x03)
        self.code = decrc(img.section_data(e))
        self.n = len(self.code) // 4
        self.words = struct.unpack('>%dI' % self.n, self.code)

    def dw(self, off):
        return self.words[off // 4]

    def dis(self, off):
        return dis(self.dw(off), off)

    def dis_range(self, lo, hi):
        out = []
        for off in range(lo, min(hi, self.n * 4), 4):
            out.append('%08x  %08x  %s' % (off, self.dw(off), self.dis(off)))
        return '\n'.join(out)

    def loaders(self):
        """map: rt-constant -> [sites] (addi rd,zero,lo; addi.hi rd,rd,hi back-to-back)."""
        loaded = {}
        prev = None
        for i in range(self.n - 1):
            w = self.words[i]
            op = w >> 26
            if op in (0x00, 0x01):
                prev = (i, (w >> 16) & 0x1f, s16(w & 0xffff))
            elif op in (0x02, 0x03) and prev is not None:
                poff, prd, pimm = prev
                if poff + 1 == i and prd == (w >> 16) & 0x1f:
                    val = (pimm + ((w & 0xffff) << 16)) & 0xffffffff
                    loaded.setdefault(val, []).append(poff * 4)
                prev = None
            else:
                prev = None
        return loaded

    def db0_strings(self):
        """[(dc_off, bytes)] printable NUL-terminated segments >=4B in db0."""
        db0 = self.code[DB0_DC:DB0_DC + DB0_SIZE]
        segs = []
        i = 0
        while i < len(db0):
            if 0x20 <= db0[i] < 0x7f:
                j = i
                while j < len(db0) and 0x20 <= db0[j] < 0x7f:
                    j += 1
                if j < len(db0) and db0[j] == 0 and j - i >= 4:
                    segs.append((DB0_DC + i, db0[i:j]))
                i = j + 1
            else:
                i += 1
        return segs

    def raw_words(self, val):
        pat = struct.pack('>I', val)
        out = []
        i = self.code.find(pat)
        while i != -1 and i < DB0_DC:
            out.append(i)
            i = self.code.find(pat, i + 1)
        return out

    def calls_to(self, target):
        """all call/jump sites to dc target (04x-xref pattern)."""
        out = []
        for i in range(self.n):
            w = self.words[i]
            if (w >> 26) == 0x25:
                tgt = i * 4 + ((w & 0xffffff) - 0x1000000 if (w & 0x800000) else (w & 0xffffff)) * 4
                if tgt == target:
                    kind = 'jump' if (w >> 24) & 1 else 'call'
                    out.append((i * 4, kind))
        return out

    @staticmethod
    def parse_imm(tok):
        tok = tok.replace('0x-', '-0x')
        return int(tok, 16)

    def const_tracker(self, lo, hi):
        """linear mini constant tracker over [lo,hi): regs {rN: const} for
        fresh-constant sequences addi rd,zero / addi.hi rd,rd / set2 rd,zero /
        set3 rd,rd (other operand regs invalidate)."""
        regs = {}

        def rd_of(d):
            m = re.match(r'^\S+ (r\d+|zero),', d)
            return m.group(1) if m else None

        for off in range(lo, hi, 4):
            d = self.dis(off)
            tok = d.split()[0]
            parts = d.replace(',', ' ').split()
            if tok in ('addi', 'addi.hi', 'set2', 'set3') and len(parts) == 4:
                dst, src = parts[1], parts[2]
                imm = self.parse_imm(parts[3])
                if tok in ('addi', 'set2') and src == 'zero':
                    regs[dst] = imm if tok == 'addi' else (imm << 16)
                elif tok in ('addi.hi', 'set3') and dst == src and dst in regs:
                    base = regs[dst]
                    regs[dst] = (base + (imm << 16)) if tok == 'addi.hi' else (base & ~0xffff) | (imm & 0xffff)
                else:
                    regs.pop(dst, None)
            else:
                for r in re.findall(r'\br\d+\b', d):
                    regs.pop(r, None)
        return regs

    def gate_context(self, site):
        """site = loader site (addi r4 lo). Walk back to nearest call GATE
        (<=0x40); class/level = constant-tracked r4/r5 in the 0x20 window
        ending at the GATE call."""
        for gate_off in range(site - 4, max(site - 0x40, 0) - 4, -4):
            if self.dis(gate_off) != 'call 0x%x' % GATE:
                continue
            regs = self.const_tracker(max(gate_off - 0x20, 0), gate_off)
            return regs.get('r4'), regs.get('r5')
        return None, None

    def emit_after(self, site):
        """nearest emit call within 0x40 after loader site."""
        for off in range(site, site + 0x40, 4):
            d = self.dis(off)
            m = re.match(r'^call (0x[0-9a-f]+)$', d)
            if m:
                a = int(m.group(1), 16)
                if a in EMITS:
                    return off, a, EMITS[a]
        return None
