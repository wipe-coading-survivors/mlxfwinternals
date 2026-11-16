#!/usr/bin/env python3
"""romdump RD-B (Task 2): H1b reader-stub image (ruling T2-R1, plan d34cbbd5).

The Task-1 rc3-bazzite composition is a pure input echo (the 23-word H1b stub
copies frame-copy bytes [r1+0xb0..0xd8) = host input[0x18..0x40) verbatim into
the response), so it cannot read card RAM. This module builds the amended
reader image through the same rc3_port machinery (base ri_stock graft, S0-cave
slot, hook 0x0E43C4, offline gates, deterministic rebuild, fresh 0xA0):

  dc 0x0E43C4  hook: stock dead-write -> HOOK_WORD 0x940AA4EC (call 0x38d774,
               byte-identical to the R-C3 canon hook - the stub stays at the
               canon dc, only its body changes)
  dc 0x38D774..24 words: the reader stub - ld.d r7,r1,0xb0 takes the read
               address from input word0 (frame-copy r1+0xb0), then 10x
               (ld.d r6,r7,4k / st.d r6,r18,0x10+4k) moves RAM[addr..addr+0x28)
               into response+0x10..0x38 (the out_mb window), then the canon
               exit triple resuming rt 0x8E43C8. Writes only r4/r6/r7 (within
               the site clobber set r4..r10); r11 and r17..r23 untouched.

Per success QUERY(created) the card therefore returns 40 B (10 BE words) of
iRISC RAM at the posted address - ~36 KB/s at the measured 910 cmd/s. The
stall aperture (>= 0xFFFF8000) is refused by the consumers, never posted.

CLI: --base <ri> --verify | --base <ri> --out <image.bin> (extra gates:
mlxfwutil verify --deep + sign --check, mstflint -i verify/q/dc, identity ==
base, dc build-ID first content line, deterministic rebuild; artifact + .md5
sidecar only after all gates).
"""

import argparse
import hashlib
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

import mlxfwutil
from scripts.irisc import assemble, disasm as dis
from scripts.irisc.profiles import load_profile
from scripts.probes.romdump import rc3_port

DEFAULT_BASE = rc3_port.DEFAULT_BASE

STUB_DC = rc3_port.STUB_DC
HOOK_DC = rc3_port.HOOK_DC
STUB_COUNT = 24
READ_WORDS = 10
READ_STRIDE = READ_WORDS * 4
STALL_FLOOR = 0xFFFF8000
ADDR_OFF = 0xB0
WRITE_LO = 0x10
RESUME_RT = rc3_port.RESUME_RT
EXIT_TRIPLE = rc3_port.EXIT_TRIPLE
DATA_REG = 6
ADDR_REG = 7
EXIT_REG = 4
ALLOWED_WRITES = {DATA_REG, ADDR_REG, EXIT_REG}
NO_WRITE_PREFIX = rc3_port.NO_WRITE_PREFIX

BUILD_ID = (
    "; mlxini romdump rd-reader v1 (2026-11-16, "
    "docs/superpowers/journal/2026-11-16-rom-dump-cx5-task-02): "
    "H1b reader port, hook 0x0E43C4 -> stub 24w @0x38d774, "
    "input w0=addr -> 10w readback, base ri_stock graft"
)


class RdReaderError(rc3_port.Rc3PortError):
    pass


def _assemble(text, base):
    data = assemble(text, base=base, profile=load_profile("cx5"), strict=True)
    return list(struct.unpack(">%dI" % (len(data) // 4), data))


def stub_text():
    lines = ["ld.d r%d,r1,0x%x" % (ADDR_REG, ADDR_OFF)]
    for k in range(READ_WORDS):
        lines.append("ld.d r%d,r%d,0x%x" % (DATA_REG, ADDR_REG, 4 * k))
        lines.append("st.d r%d,r18,0x%x" % (DATA_REG, WRITE_LO + 4 * k))
    lines.append("addi r%d,zero,0x%x" % (EXIT_REG, RESUME_RT & 0xffff))
    lines.append("addi.hi r%d,r%d,0x%x" % (EXIT_REG, EXIT_REG,
                                            RESUME_RT >> 16))
    lines.append("ret.r zero,zero,r%d" % EXIT_REG)
    return "\n".join(lines) + "\n"


def stub_words():
    words = _assemble(stub_text(), STUB_DC)
    if len(words) != STUB_COUNT:
        raise RdReaderError("stub is %d words, reader canon = %d"
                            % (len(words), STUB_COUNT))
    return words


def hook_word():
    return rc3_port.hook_word()


def _gate_stub(words, free):
    if len(words) != STUB_COUNT:
        raise RdReaderError("stub is %d words, reader canon = %d"
                            % (len(words), STUB_COUNT))
    if free - len(words) < 2:
        raise RdReaderError("stub slack %d < 2" % (free - len(words)))
    writes = set()
    addr_loads = []
    loads = []
    stores = []
    for i, word in enumerate(words):
        dc = STUB_DC + 4 * i
        text = dis(word, dc)
        if _assemble(text, dc)[0] != word:
            raise RdReaderError("stub word %d dis->re-assemble drift" % i)
        mnem, rest = text.split(" ", 1)
        ops = rest.split(",")
        if mnem == "ld.d":
            base = ops[1].strip()
            off = int(ops[2].strip(), 16)
            rd = int(ops[0].strip()[1:])
            if base == "r1":
                addr_loads.append((rd, off))
            elif base == "r%d" % ADDR_REG:
                loads.append((rd, off))
            else:
                raise RdReaderError("ld.d %d unexpected base %s"
                                    % (i, base))
        elif mnem == "st.d":
            if ops[1].strip() != "r18":
                raise RdReaderError("st.d %d base %s != r18 (response live-in)"
                                    % (i, ops[1].strip()))
            stores.append((int(ops[0].strip()[1:]),
                           int(ops[2].strip(), 16)))
        if mnem.startswith(("b.", "jump", "call")):
            raise RdReaderError("stub word %d is pc-relative (%s)" % (i, text))
        first = rest.split()[0].split(",")[0]
        if not mnem.startswith(NO_WRITE_PREFIX):
            if not first.startswith("r") or not first[1:].isdigit():
                raise RdReaderError("stub word %d unparsable dest: %s"
                                    % (i, text))
            writes.add(int(first[1:]))
    if addr_loads != [(ADDR_REG, ADDR_OFF)]:
        raise RdReaderError("address intake %s != ld.d r%d,r1,0x%x"
                            % (addr_loads, ADDR_REG, ADDR_OFF))
    if len(loads) != READ_WORDS or len(stores) != READ_WORDS:
        raise RdReaderError("width parity: %d data ld.d / %d st.d != %d"
                            % (len(loads), len(stores), READ_WORDS))
    for k, ((lr, lo), (sr, so)) in enumerate(zip(loads, stores)):
        if lo != 4 * k or so != WRITE_LO + 4 * k:
            raise RdReaderError("pair %d offsets 0x%x/0x%x break the mapping "
                                "addr+4k -> 0x%x+4k" % (k, lo, so, WRITE_LO))
        if lr != DATA_REG or sr != DATA_REG:
            raise RdReaderError("pair %d uses r%d/r%d != data r%d"
                                % (k, lr, sr, DATA_REG))
    if writes - ALLOWED_WRITES:
        raise RdReaderError("stub writes unexpected regs %s (r4/r6/r7 only)"
                            % sorted(writes))
    if words[-3:] != EXIT_TRIPLE:
        raise RdReaderError("exit triple %s != resume rt compose %s"
                            % ([hex(w) for w in words[-3:]],
                               [hex(w) for w in EXIT_TRIPLE]))


def build(ri):
    v = rc3_port.verify_base(ri)
    if not v["ok"]:
        raise RdReaderError("base incompatible: %s" % "; ".join(v["reasons"]))
    base = mlxfwutil.Image(bytes(ri), "base")
    words = stub_words()
    hook = hook_word()
    _gate_stub(words, v["free_slot_words"])
    e03 = base.find_entry("ITOC", 0x03)
    raw = base.section_data(e03)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    step1, exp_lines = rc3_port._graft(base, raw, code, tail, STUB_DC, words,
                                       hook)

    pimg = mlxfwutil.Image(step1, "step1", base=base.base, fmt=base.fmt)
    e30 = pimg.find_entry("ITOC", 0x30)
    ini_text = zlib.decompressobj().decompress(
        pimg.section_data(e30)).decode("latin1")
    ini_final, _dropped = rc3_port.edit_ini(ini_text, e30.size,
                                            build_id=BUILD_ID)
    try:
        step2 = mlxfwutil.inject_ini(pimg, ini_final)
    except ValueError as e:
        raise RdReaderError("0x30 inject failed: %s" % e)
    simg = mlxfwutil.Image(step2, "step2", base=base.base, fmt=base.fmt)
    e30n = simg.find_entry("ITOC", 0x30)
    if e30n.addr != e30.addr:
        raise RdReaderError("0x30 relocated: 0x%x -> 0x%x"
                            % (e30.addr, e30n.addr))
    if e30n.size > e30.size or e30.size - e30n.size < rc3_port.HEADROOM_MIN:
        raise RdReaderError("0x30 size gate: 0x%x -> 0x%x (headroom %d)"
                            % (e30.size, e30n.size, e30.size - e30n.size))
    rt = zlib.decompressobj().decompress(
        simg.section_data(e30n)).decode("latin1")
    if rt != ini_final:
        raise RdReaderError("0x30 round-trip mismatch")

    status, _, _ = mlxfwutil.sig_status(simg)
    if status not in ("stale", "fresh"):
        raise RdReaderError("0xA0 unexpected status pre-sign: %s" % status)
    ea0 = simg.find_entry("ITOC", 0xA0)
    a0 = simg.sec_abs(ea0)
    if ea0.size < mlxfwutil.SIG_SLOT_OFF + 32:
        raise RdReaderError("0xA0 section too small: 0x%x" % ea0.size)
    digest = mlxfwutil.sha256_digest(simg)
    out = bytearray(step2)
    out[a0 + mlxfwutil.SIG_SLOT_OFF:a0 + mlxfwutil.SIG_SLOT_OFF + 32] = digest
    fimg = mlxfwutil.Image(bytes(out), "final", base=base.base, fmt=base.fmt)
    errs = mlxfwutil.verify_image(fimg, deep=True)
    if errs:
        raise RdReaderError("final verify --deep failed: %s" % errs)
    status, _, _ = mlxfwutil.sig_status(fimg)
    if status != "fresh":
        raise RdReaderError("0xA0 not fresh after sign: %s" % status)

    dg = rc3_port.diff_gate(base, bytes(out), exp_lines)
    if dg["stray"]:
        raise RdReaderError("stray diff bytes outside the intended zones: %s"
                            % [hex(o) for o in dg["stray"][:8]])
    if dg["empty_zones"]:
        raise RdReaderError("expected zones with no diff bytes: %s"
                            % dg["empty_zones"])
    if dg["section_diff"] != ["ITOC 0x03", "ITOC 0x30", "ITOC 0xA0"]:
        raise RdReaderError("section-level diff %s != {ITOC 0x03, 0x30, 0xA0}"
                            % dg["section_diff"])
    return bytes(out)


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO))
    print("$ " + " ".join(str(c) for c in cmd))
    for stream in (r.stdout, r.stderr):
        for line in stream.strip().splitlines():
            print("    " + line)
    return r


def cmd_verify(args):
    return rc3_port.cmd_verify(args)


def cmd_build(args):
    base_path = Path(args.base)
    buf = base_path.read_bytes()
    md5 = hashlib.md5(buf).hexdigest()
    print("base: %s md5 %s" % (base_path, md5))
    if base_path.resolve() == DEFAULT_BASE.resolve() and \
            md5 != rc3_port.RI_MD5:
        print("FATAL: default base md5 != ri_stock canon %s" % rc3_port.RI_MD5)
        return 1
    out_path = Path(args.out)
    out = build(buf)
    md5 = hashlib.md5(out).hexdigest()
    print("built: %d B md5 %s" % (len(out), md5))
    gate_path = REPO / "build/rd-reader-gate.tmp"
    gate_path.parent.mkdir(parents=True, exist_ok=True)
    gate_path.write_bytes(out)

    r = _run(["python3", "mlxfwutil.py", "verify", "--deep", str(gate_path)])
    if r.returncode != 0:
        gate_path.unlink()
        return 1
    r = _run(["python3", "mlxfwutil.py", "sign", "--check", str(gate_path)])
    if r.returncode != 0 or "fresh" not in r.stdout:
        gate_path.unlink()
        return 1
    r = _run(["mstflint", "-i", str(gate_path), "verify"])
    text = r.stdout + r.stderr
    if r.returncode != 0 or "bootable" not in text or \
            "verification succeeded" not in text:
        gate_path.unlink()
        return 1

    def q_fields(path):
        rq = subprocess.run(["mstflint", "-i", str(path), "q"],
                            capture_output=True, text=True, cwd=str(REPO))
        got = {}
        for l in (rq.stdout + rq.stderr).splitlines():
            for k in ("FW Version", "PSID", "Base GUID", "Base MAC"):
                if l.strip().startswith(k + ":"):
                    rest = l.split(":", 1)[1].split()
                    got[k] = rest[0] if rest else ""
        return got

    qb, qf = q_fields(base_path), q_fields(gate_path)
    identity_ok = all(qf.get(k) == qb.get(k)
                      for k in ("FW Version", "PSID", "Base GUID", "Base MAC"))
    print("identity == base (FW/PSID/GUID/MAC): %s" % ("OK 4/4"
                                                       if identity_ok
                                                       else "MISMATCH"))
    if not identity_ok:
        gate_path.unlink()
        return 1
    r = subprocess.run(["mstflint", "-i", str(gate_path), "dc"],
                       capture_output=True, text=True, cwd=str(REPO))
    if r.returncode != 0:
        print("FATAL: mstflint dc rc=%d" % r.returncode)
        gate_path.unlink()
        return 1
    dl = [l.rstrip() for l in (r.stdout + r.stderr).splitlines()]
    mi = next((i for i, l in enumerate(dl) if BUILD_ID in l), None)
    if mi is None:
        print("FATAL: mstflint dc does not show the build-ID")
        gate_path.unlink()
        return 1
    pre = [l for l in dl[:mi]
           if l.strip() and not l.startswith(("-E-", "-W-", "-I-", "-"))]
    if any(not l.startswith(";;") for l in pre) or len(pre) > 1:
        print("FATAL: build-ID is not the first content line (pre: %r)" % pre)
        gate_path.unlink()
        return 1
    print("dc build-ID is the first content line after the banner: OK")

    rebuild = build(buf)
    md5b = hashlib.md5(rebuild).hexdigest()
    print("deterministic rebuild: %s" % ("OK" if md5b == md5
                                         else "MISMATCH %s" % md5b))
    if md5b != md5:
        gate_path.unlink()
        return 1
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(out)
    gate_path.unlink()
    sidecar = out_path.with_name(out_path.name + ".md5")
    try:
        rel = out_path.resolve().relative_to(REPO.resolve())
    except ValueError:
        rel = out_path
    sidecar.write_text("%s  %s\n" % (md5, rel))
    print("ALL GATES PASS")
    print("DONE %s md5=%s sidecar=%s" % (out_path, md5, sidecar))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description="romdump RD-B: H1b reader-stub image (offline)")
    p.add_argument("--base", default=str(DEFAULT_BASE),
                   help="base ri image (default: refs ri_stock.bin)")
    p.add_argument("--out", help="write the built image + .md5 sidecar")
    p.add_argument("--verify", action="store_true",
                   help="run verify_base on --base only")
    args = p.parse_args(argv)
    if args.verify:
        return cmd_verify(args)
    if args.out:
        return cmd_build(args)
    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
