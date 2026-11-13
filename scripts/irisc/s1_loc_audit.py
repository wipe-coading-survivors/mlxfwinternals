import re, struct

# parse raw LOC words from s1_loc_out.txt (=== LOC code section)
words = []
section = None
for ln in open('/tmp/opencode/irisc/s1_loc_out.txt'):
    s = ln.rstrip('\n')
    if s.startswith('=== LOC code'): section='loc'; continue
    if s.startswith('=== ') and section=='loc': section=None
    if section=='loc':
        m = re.match(r'^\s*([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s*;?\s*(.*)$', s)
        if m: words.append((int(m.group(1),16), int(m.group(2),16), m.group(3)))
assert len(words)==93, len(words)

def R(x): return 'zero' if x==0 else 'r%d'%x

def classify(w):
    op=w>>26; rd=(w>>16)&0x1f; rs=(w>>21)&0x1f; rt=(w>>11)&0x1f; f=w&0x1ff
    wr, rd_ = [], []
    if op in (0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0e,0x32):
        wr=[rd]; rd_=[rs]
    elif op==0x12:
        wr=[rd]; rd_=[]
    elif op==0x17 or op==0x18 or op==0x19:
        wr=[rd]; rd_=[rs]
    elif op==0x1a or op==0x1b:
        wr=[]; rd_=[rs,rt]
    elif op==0x1c:
        wr=[rs]; rd_=[rs,rt]
    elif op==0x25:
        wr=[]; rd_=[]
    elif op in (0x28,0x29,0x2a,0x2b):
        wr=[]; rd_=[rs]
    elif op==0x3f:
        if f in (0x25,0x2d): wr=[]; rd_=[rs,rt]
        elif f in (0x83,0x8a,0x85): wr=[rd]; rd_=[rs]
        else: wr=[rd]; rd_=[rs,rt]
    else:
        wr=None; rd_=[]
    return wr, rd_

PROTECTED = {2,4,5,6,7,8,16,17,18,19,20,21,22,23}
SCRATCH = set(range(9,16))

print('=== WRITES to protected regs (r2/r4-r8/r16-r23) by OLD locator ===')
bad=0
for a,w,c in words:
    wr,_ = classify(w)
    for r in (wr or []):
        if r in PROTECTED:
            bad+=1
            print('  %08x  %08x  WRITES r%-2d  ; %s'%(a,w,r,c.strip()))
print('total writes to protected: %d (expect 14 = ld.d restores 0x38d850..0x38d884)'%bad)
rest=[ (a,w) for a,w,c in words if classify(w)[0] and any(r in PROTECTED for r in classify(w)[0])]
print('all at DONE-restore block (0x38d850..0x38d888):', all(0x38d850<=a<=0x38d884 for a,_ in rest), 'count=%d'%len(rest))

print()
print('=== WRITES to r1 (SP) / r3 ===')
for a,w,c in words:
    wr,_ = classify(w)
    for r in (wr or []):
        if r in (1,3):
            print('  %08x  %08x  WRITES r%d  ; %s'%(a,w,r,c.strip()))

print()
print('=== READS of protected regs (src) by OLD locator ===')
for a,w,c in words:
    _,rds = classify(w)
    for r in rds:
        if r in PROTECTED:
            print('  %08x  %08x  READS r%-2d  ; %s'%(a,w,r,c.strip()))

print()
print('=== ALL writes: register histogram (OLD locator) ===')
from collections import Counter
hist=Counter()
for a,w,c in words:
    for r in (classify(w)[0] or []): hist[r]+=1
for r in sorted(hist): print('  r%-2d: %d'%(r,hist[r]))

print()
print('=== sanity: writes outside {r1,r3,r9-r15,protected} (expect none) ===')
other=[ (a,w,c) for a,w,c in words for r in (classify(w)[0] or []) if r not in (1,3) and r not in SCRATCH and r not in PROTECTED]
print('  ', other if other else 'NONE')

# also test build_s1.py DECODE-BACK parser behavior on old file
db={}
section=None
for ln in open('/tmp/opencode/irisc/s1_loc_out.txt'):
    s=ln.rstrip('\n')
    if s.startswith('=== DECODE-BACK'): section='db'; continue
    if s.startswith('=== '): section=None; continue
    if section=='db':
        m=re.match(r'^\s*([0-9a-fA-F]{8})\s+(.*?)\s*;.*$', s)
        if m: db[int(m.group(1),16)]=m.group(2).strip()
print()
print('=== build_s1.py DECODE-BACK parser on OLD file: %d entries (old build asserted 93)'%len(db))
