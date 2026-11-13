import struct, sys
BIN=sys.argv[1]; magic=int(sys.argv[2],0)
data=open(BIN,'rb').read()
n=len(data)//4
for i in range(n):
    w=struct.unpack_from('>I',data,i*4)[0]
    if w==magic:
        print("0x%06x  (word idx %d)"%(i*4,i))
