#!/usr/bin/env python3
"""Full decrypt of pwd.db (devbean v1.0 + classic wxsqlite3 sqlcipher codec).
Params verified via HMAC-SHA1: PBKDF2-SHA1/64000, ps=4096, off1=24, reserve=48."""
import hashlib, hmac as hmac_mod, os, subprocess

DB = os.path.expanduser("~/Документы/mellanox/fw/PAC SFP Programmer/SFP Programmer -to customer/SFP Programmer Software/pwd.db")
OUT = "/tmp/opencode/pwd_decrypted.sqlite"
PASS = b"ChenLaoShi_YxFiber@123"
PS, RES = 4096, 48

data = open(DB, "rb").read()
salt = data[:16]
enc_key = hashlib.pbkdf2_hmac("sha1", PASS, salt, 64000, 32)
hmac_salt = bytes(b ^ 0x3A for b in salt)
hmac_key = hashlib.pbkdf2_hmac("sha1", enc_key, hmac_salt, 2, 32)
N = PS - RES
npages = len(data) // PS

def run(inp, *args):
    p = subprocess.run(["openssl", "enc", *args], input=inp, capture_output=True)
    return p.stdout if p.returncode == 0 else None

def ecb1(blk):
    return run(blk, "-d", "-aes-256-ecb", "-nopad", "-K", enc_key.hex())

def cbc(body, iv):
    return run(body, "-d", "-aes-256-cbc", "-nopad", "-K", enc_key.hex(), "-iv", iv.hex())

def decrypt_page(pgno):
    base = (pgno - 1) * PS
    off = 24 if pgno == 1 else 0
    ct = data[base + off: base + N]
    iv = data[base + N: base + N + 16]
    # HMAC-SHA1 check (hmac_use=1, pgno LE)
    msg = data[base + off: base + N + 16] + pgno.to_bytes(4, "little")
    calc = hmac_mod.new(hmac_key, msg, hashlib.sha1).digest()
    stored = data[base + N + 16: base + N + 36]
    ok = calc == stored
    frag = len(ct) % 16
    out = bytearray(len(ct))
    if frag:
        nb = len(ct) // 16
        o = (nb - 1) * 16
        block = ecb1(ct[o:o + 16])
        lastblock = bytes(block[i] ^ ct[o + 16 + i] for i in range(frag))
        stitched = ct[o + 16:o + 16 + frag] + block[frag:]
        mid = ecb1(stitched)
        prev = iv if o == 0 else ct[o - 16:o]
        out[o:o + 16] = bytes(a ^ b for a, b in zip(mid, prev))
        out[o + 16:] = lastblock
        body = ct[:o]
    else:
        body = ct
    if body:
        out[:len(body)] = cbc(body, iv)
    return bytes(out), ok

pages = []
for p in range(1, npages + 1):
    pt, ok = decrypt_page(p)
    if p == 1:
        page = b"SQLite format 3\x00" + data[16:24] + pt
    else:
        page = pt
    page += b"\x00" * (PS - len(page))
    pages.append(page)
    print(f"page {p}: hmac_ok={ok} first16={page[:16].hex()}")

open(OUT, "wb").write(b"".join(pages))
print("written:", OUT, len(pages) * PS, "bytes")
