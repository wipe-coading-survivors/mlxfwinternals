#!/usr/bin/env python3
"""Clean recount of unknown iRISC ops (code regions only).

Bin: build/ghidra-4030cda-main03-ac-dc.bin (de-clcrc MAIN_CODE).
File offset == Ghidra addr (base 0); runtime abs = file_off + 0x800000.
All instructions are 4 bytes (alignment=4), big-endian, op = bits 26..31.

Subcommands:
  step1      - full-binary op histogram (reproduce 2026-09-20 journal sec.6)
  run        - window classifier, anchor validation, cross-check, clean hist
  snippets   - context snippets for top-5 unknown ops (code regions)
  datamap    - largest data regions (for the report)
"""
import os, struct, sys, collections

BIN = os.path.expanduser('~/git/IMPLEMENTATION/mlxini/build/ghidra-4030cda-main03-ac-dc.bin')

KNOWN30 = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
           0x0e,0x12,0x13,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1e,0x25,0x28,0x29,
           0x2a,0x2b,0x32,0x3f}
RARE = [0x1f,0x20,0x21,0x22,0x23,0x24,0x26,0x27,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x35,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e]

PRINTABLE = set(range(0x20,0x7f)) | {0x09,0x0a,0x0d}

def load():
    buf = open(BIN,'rb').read()
    n = len(buf)//4
    words = struct.unpack_from('>%dI' % n, buf, 0)
    return buf, words, n

def word_features(w):
    op = w >> 26
    rs = (w>>21)&0x1f; rd=(w>>16)&0x1f
    b = (w&0xff, (w>>8)&0xff, (w>>16)&0xff, (w>>24)&0xff)
    is_zero = (w == 0)
    is_str = all(x in PRINTABLE or x==0 for x in b) and sum(x in PRINTABLE for x in b) >= 3
    is_cf = op in (0x25,0x28,0x29,0x2a,0x2b)
    is_call = (op==0x25 and ((w>>24)&1)==0)
    is_ret = (op==0x3f and (w&0x1ff) in (0x25,0x2d))
    is_plg = (op==0x12 and ((w>>25)&1)==0 and (w&0x7ff)==0xbc and rd!=0)  # csr.r rX,retaddr
    is_epl = (op==0x13 and (w&0x7ff)==0xbc)                               # csr.w ..,retaddr
    is_frm = (op==0x1c and rs==1)                                         # st.d!/st.q! r1,.. frame
    return op,is_zero,is_str,is_cf,is_call,is_ret,is_plg,is_epl,is_frm

def cf_target(w, off):
    """PC-relative target; verified vs Ghidra: tgt = PC + o*4 (no +4)."""
    op = w>>26
    if op==0x25:
        o = w & 0xffffff
        if o & 0x800000: o -= 0x1000000
    else:
        o = w & 0xffff
        if o & 0x8000: o -= 0x10000
    return off + o*4

def step1():
    buf, words, n = load()
    hist = collections.Counter(w>>26 for w in words)
    print('== FULL-binary op histogram (all %d 4-aligned words) ==' % n)
    print('%-6s %-9s %s' % ('op','count','status'))
    for op in sorted(hist):
        st = 'KNOWN' if op in KNOWN30 else 'UNKNOWN'
        print('0x%02x   %-9d %s' % (op, hist[op], st))
    print('total unknown-op words:', sum(c for o,c in hist.items() if o not in KNOWN30))
    print('zero words:', hist.get(0,0) and sum(1 for w in words if w==0))

# ------------- classifier (v2) -------------
W = 64      # window words
S = 8       # stride
TH_ZERO = 0.25
TH_ASCII = 0.30
TH_KNOWN = 0.62
TH_MONO  = 0.85   # single op >=85% of window words -> mono table ...
TH_ANCH  = 2      # ... unless >=2 function-anchor words (call/prolog/epilog/ret)

def classify(words, n):
    feat = [word_features(w) for w in words]
    ops = [f[0] for f in feat]
    known = [1 if o in KNOWN30 else 0 for o in ops]
    zero  = [1 if f[1] else 0 for f in feat]
    astr  = [1 if f[2] else 0 for f in feat]
    anch  = [1 if (f[4] or f[5] or f[6] or f[7] or f[8]) else 0 for f in feat]
    functs = [(w & 0x1ff) if (w>>26)==0x3f else None for w in words]
    votes = [0]*n; cover = [0]*n
    wstats = {}
    for start in range(0, n-W+1, S):
        sl = slice(start, start+W)
        kf = sum(known[sl])/W
        zf = sum(zero[sl])/W
        af = sum(astr[sl])/W
        na = sum(anch[sl])
        oc = collections.Counter(ops[sl])
        top_op, top_cnt = oc.most_common(1)[0]
        mono = top_cnt/W >= TH_MONO
        if mono and top_op == 0x3f:
            # ALU-dominated: real code uses many functs; 0xffffffff-fill tables don't
            fs = set(f for f in functs[sl] if f is not None)
            mono = len(fs) <= 3
        code = not (zf>=TH_ZERO or af>=TH_ASCII
                    or (mono and na < TH_ANCH)
                    or (kf<TH_KNOWN and na < TH_ANCH))
        wstats[start] = (kf,zf,af,top_cnt/W,na,code)
        for i in range(start, start+W):
            cover[i]+=1
            if code: votes[i]+=1
    code = [votes[i]*2 >= cover[i] for i in range(n)]
    return feat, ops, code, cover, votes, wstats

def anchors_report(words, code, n):
    code_anchors = [
        (0x01d58c, 0x20,  'entry 1d58c'),
        (0x01a4e4, 0x200, 'SP-init 1a4e4'),
        (0x01e10c, 0x300, 'main-init 1e10c'),
        (0x0d3a0c, 0x400, 'wrapper d3a0c'),
        (0x091534, 0x600, 'F_A 91534'),
        (0x0afd20, 0x600, 'F_C afd20'),
        (0x088cb0, 0x2b0, 'F_T cluster 88cb0 (switch-tables!)'),
    ]
    data_anchors = [
        (0x38d730, 0x4b9, 'zero free-region 38d730'),
        (0x397d48, 0x78,  'tail after last nonzero'),
    ]
    print('== anchor validation ==')
    for off, ln, name in code_anchors:
        i0, i1 = off//4, (off+ln)//4
        frac = sum(code[i0:i1])/max(1,(i1-i0))
        print('CODE?  %#08x+%#05x %-32s code_frac=%.3f %s' % (off, ln, name, frac, 'PASS' if frac>=0.95 else 'FAIL'))
    for off, ln, name in data_anchors:
        i0, i1 = off//4, (off+ln)//4
        frac = sum(code[i0:i1])/max(1,(i1-i0))
        print('DATA?  %#08x+%#05x %-32s code_frac=%.3f %s' % (off, ln, name, frac, 'PASS' if frac<=0.05 else 'FAIL'))
    # largest ASCII runs
    buf = open(BIN,'rb').read()
    runs=[]; i=0
    while i < len(buf):
        if buf[i] in PRINTABLE:
            j=i
            while j<len(buf) and (buf[j] in PRINTABLE): j+=1
            if j-i>=64: runs.append((i,j-i))
            i=j
        else: i+=1
    runs.sort(key=lambda t:-t[1])
    print('top ASCII runs (validate as DATA):')
    for off,ln in runs[:6]:
        i0,i1 = off//4,(off+ln)//4
        frac = sum(code[i0:i1])/max(1,(i1-i0))
        print('DATA?  %#08x+%#05x "%s"            code_frac=%.3f %s' % (off,ln,buf[off:off+24].decode('ascii','replace'),frac,'PASS' if frac<=0.05 else 'FAIL'))

def crosscheck(words, code, n):
    tot=0; in_code=0; out_file=0
    tgts = []
    for i,w in enumerate(words):
        if not code[i]: continue
        op=w>>26
        if op in (0x25,0x28,0x29,0x2a,0x2b):
            t = cf_target(w, i*4)
            tot+=1
            if not (0 <= t < len(words)*4): out_file+=1
            else:
                tgts.append(t//4)
                if code[t//4]: in_code+=1
    print('== cross-check: PC-relative targets from code regions ==')
    print('cf insns in code: %d; targets landing in code: %d (%.1f%%); out-of-file: %d'
          % (tot, in_code, 100.0*in_code/max(1,tot), out_file))
    return set(tgts)

def run():
    buf, words, n = load()
    feat, ops, code, cover, votes, wstats = classify(words, n)
    ncode = sum(code)
    print('words total %d; code words %d (%.1f%%); code bytes %d / %d = %.1f%%'
          % (n, ncode, 100.0*ncode/n, ncode*4, len(buf), 100.0*ncode*4/len(buf)))
    anchors_report(words, code, n)
    tgts = crosscheck(words, code, n)
    # clean histogram
    ch = collections.Counter(); dh = collections.Counter()
    for i,o in enumerate(ops):
        if o not in KNOWN30:
            (ch if code[i] else dh)[o]+=1
    print('== CLEAN histogram: UNKNOWN ops inside code regions (rank desc) ==')
    print('%-6s %-8s %-8s' % ('op','in_code','in_data'))
    for o,c in ch.most_common():
        print('0x%02x   %-8d %-8d' % (o, c, dh.get(o,0)))
    print('sum in_code=%d  sum in_data=%d' % (sum(ch.values()), sum(dh.values())))
    print('== known-op sanity (top) in code ==')
    kh = collections.Counter(o for i,o in enumerate(ops) if code[i])
    for o,c in kh.most_common(10):
        print('0x%02x %-8d %s' % (o,c,'KNOWN' if o in KNOWN30 else 'UNKNOWN'))
    return ch, dh, code, words, n

def datamap():
    buf, words, n = load()
    feat, ops, code, cover, votes, wstats = classify(words, n)
    # contiguous data runs >= 256 bytes
    runs=[]; i=0
    while i<n:
        if not code[i]:
            j=i
            while j<n and not code[j]: j+=1
            if (j-i)*4 >= 256: runs.append((i*4,(j-i)*4))
            i=j
        else: i+=1
    runs.sort(key=lambda t:-t[1])
    print('== largest DATA runs (>=256B) ==')
    print('count %d; total data bytes %d (%.1f%%)'
          % (len(runs), sum(l for _,l in runs), 100.0*sum(l for _,l in runs)/len(buf)))
    for off,l in runs[:25]:
        chunk = buf[off:off+16]
        printable = sum(x in PRINTABLE for x in buf[off:off+min(l,256)])
        kind = 'ascii' if printable/ min(l,256) > 0.7 else ('zeros' if buf[off:off+64].count(0)==64 else 'table/binary')
        print('%#08x + %#06x (%6d B)  %s  head=%s' % (off,l,l,kind,chunk.hex()))

if __name__=='__main__':
    cmd = sys.argv[1] if len(sys.argv)>1 else 'run'
    if cmd=='step1': step1()
    elif cmd=='run': run()
    elif cmd=='datamap': datamap()
    else: print(__doc__)
