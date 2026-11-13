import struct, sys
BIN=sys.argv[1]
data=open(BIN,'rb').read()
n=len(data)
# find runs of all-zero bytes >= 0x80 (128B)
i=0; runs=[]
while i<n:
    if data[i]==0:
        j=i
        while j<n and data[j]==0: j+=1
        if j-i>=0x80: runs.append((i,j-i))
        i=j
    else: i+=1
runs.sort(key=lambda r:-r[1])
print("== zero runs >= 128B (top 25 by size) ==")
for (s,l) in runs[:25]:
    print("0x%08x - 0x%08x  len=0x%x (%dB)"%(s, s+l, l, l))
print("total runs:", len(runs))
# also: is there a big zero region in the middle (not just the tail)?
