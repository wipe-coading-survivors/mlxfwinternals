#!/usr/bin/env python3
"""romdump RD-C (Task 3): boot-time ROM probe image, v2 CR-window stash.

Hypothesis (spec s1): on the boot stage (before remap/init) the iRISC address
space may differ from runtime - ROM may be visible from boot code. v1 proved
the stub runs (hook on the unconditional entry path) but a MAIN-copy-region
stash does not survive to runtime (wipe/re-stage; journal task-03 Phase B).
v2 keeps the proven 36-word stub shape and moves the stash into the CR-window
class - the boot-injection canon's persistence precedent (0x23f0 marker
survived a full boot and stayed host-visible, 025 sections 3-4):

  stash: magic -> 0x23F0 (canon-vetted mapped slot: FW only reads it with
         ==0xbadc0ffe locked-semantics, never writes) and candidate values ->
         5 dead slots picked by the live CR-window survey + MAIN static scan
         (canon 4.3 methodology; scan reproduced the canon numbers: 202 st.i,
         max byte target 0x15C8; picks are zero-stock, reader-free, spread
         across distant clusters - see journal task-03 v2 section).

Composition (base ri_stock graft, offline gates, deterministic rebuild,
fresh 0xA0) per the boot-injection canon (025):

  dc 0x1D594   boot hook: stock main-init call 0x940002DE (call 0x1e10c) ->
               call BOOT_STUB_DC - the canon injection point, 3rd entry
               instruction after SP-init, executes on every boot; pinned
               byte-exact on ri_stock by rc3_port.SITE_WORDS
  dc 0x38D7D8..36 words (guard zone head): the boot stub - canon shellcode
               idiom (set2/set3 compose, st.d absolute, resume jump):
                 magic block: RAM[STASH_SITES[0] = 0x23F0] = MAGIC
                              (0xB0050001; locked-semantics benign per canon)
                 K blocks: r5 = candidate rt address (set2/set3), r6 =
                 RAM[r5] (ld.d), r5 = stash site (set2/set3),
                 RAM[r5] = r6 (st.d)
                 resume: jump 0x1E10C (canon main-init resume)
               Writes only r5/r6 - the canon-proven scratch set at this exact
               site (the main-init prologue reads r1/r3/r4/r23, never r5/r6).
  dc 0x0E43C4  reader hook + dc 0x38D774..24 words: the Task-2 rd-reader
               stub carried verbatim - runtime readback channel for the stash
               (input w0 = address -> 10-word readback per QUERY).

Readout after boot via the rd-reader channel (RAM view of the CR window;
one 0x4-B dump per site) - the setpci/VSEC cross-path was attempted and
deferred (CTRL not writable on this card, DATA stuck 0x20d; journal v2).

Candidate order: aperture (>= 0xFFFF8000, the runtime stall aperture - the
plan-sanctioned RD-C read) LAST, so every other candidate is stashed before
the risky aperture load; a hang there costs the boot (FNP recovery), not the
earlier verdicts' write-out.

decode_verify(words, candidates, sim_mem) is the offline sim of the stub: it
interprets the decoded instruction stream (set2/set3/ld.d/st.d/jump from
irisc dis) against a caller memory model and checks reads == candidates in
order, writes == {STASH_SITES}, site 0 == MAGIC - i.e. the assembled words
really implement "read candidates -> CR-window stash" semantics.

parse_readout(words_blob, candidates) turns the collected stash words
(K+1 BE u32, site order) into per-candidate verdicts {data | 00-fill |
ff-fill}; a missing magic means the stub did not run / the stash was wiped
(global no-verdict).

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
from scripts.probes.romdump import rc3_port, rd_reader

DEFAULT_BASE = rc3_port.DEFAULT_BASE

CANDIDATES = [0x0, 0x01002000, 0x00B97E00, 0x01001000, 0xFFFF8000]

BOOT_HOOK_DC = rc3_port.BOOT_WORD_DC
BOOT_HOOK_STOCK = rc3_port.SITE_WORDS[rc3_port.BOOT_WORD_DC]
READER_HOOK_DC = rc3_port.HOOK_DC
READER_STUB_DC = rd_reader.STUB_DC

BOOT_STUB_DC = rc3_port.GUARD_ZONE[0]
MAGIC_SITE = 0x23F0
VALUE_SLOTS = [0x2C00, 0x4C00, 0x5C00, 0x7C00, 0xEC00]
STASH_SITES = [MAGIC_SITE] + VALUE_SLOTS
CR_WINDOW = (0x2000, 0x10000)
MAGIC = 0xB0050001
RESUME_DC = 0x1E10C

ADDR_REG = 5
DATA_REG = 6
SCRATCH_WRITES = {ADDR_REG, DATA_REG}
WORDS_PER_CAND = 6
FIXED_WORDS = 6
GUARD_WORDS = (rc3_port.GUARD_ZONE[1] - rc3_port.GUARD_ZONE[0]) // 4
GUARD_SLACK_MIN = 2

VERDICT_DATA = "data"
VERDICT_00 = "00-fill"
VERDICT_FF = "ff-fill"

BUILD_ID = (
    "; mlxini romdump boot-probe v2 (2026-11-16, "
    "docs/superpowers/journal/2026-11-16-rom-dump-cx5-task-03): "
    "CR-window stash, boot hook 0x1D594 -> 36w @0x38D7D8, "
    "magic@0x23f0 + 5 cand -> 0x2c00/0x4c00/0x5c00/0x7c00/0xec00, "
    "+ rd-reader 24w, base ri_stock graft"
)


class BootProbeError(rc3_port.Rc3PortError):
    pass


def _assemble(text, base):
    data = assemble(text, base=base, profile=load_profile("cx5"), strict=True)
    return list(struct.unpack(">%dI" % (len(data) // 4), data))


def stub_words_len(count):
    return FIXED_WORDS + WORDS_PER_CAND * count


def _compose(dest, value):
    return ["set2 r%d,zero,0x%x" % (dest, value >> 16),
            "set3 r%d,r%d,0x%x" % (dest, dest, value & 0xFFFF)]


def boot_stub_text(candidates, sites):
    lines = _compose(DATA_REG, MAGIC)
    lines += _compose(ADDR_REG, sites[0])
    lines.append("st.d r%d,r%d,0x0" % (DATA_REG, ADDR_REG))
    for k, cand in enumerate(candidates):
        lines += _compose(ADDR_REG, cand)
        lines.append("ld.d r%d,r%d,0x0" % (DATA_REG, ADDR_REG))
        lines += _compose(ADDR_REG, sites[k + 1])
        lines.append("st.d r%d,r%d,0x0" % (DATA_REG, ADDR_REG))
    lines.append("jump 0x%x" % RESUME_DC)
    return "\n".join(lines) + "\n"


def boot_stub_words(candidates, sites=None):
    if sites is None:
        sites = STASH_SITES
    words = _assemble(boot_stub_text(candidates, sites), BOOT_STUB_DC)
    if len(words) != stub_words_len(len(candidates)):
        raise BootProbeError("stub is %d words, want %d"
                            % (len(words), stub_words_len(len(candidates))))
    return words


def boot_hook_word():
    word = _assemble("call 0x%x" % BOOT_STUB_DC, BOOT_HOOK_DC)[0]
    if word == BOOT_HOOK_STOCK:
        raise BootProbeError("boot hook word == stock (no-op patch)")
    if dis(word, BOOT_HOOK_DC) != "call 0x%x" % BOOT_STUB_DC:
        raise BootProbeError("boot hook decodes off: %s"
                             % dis(word, BOOT_HOOK_DC))
    return word


def reader_stub_words():
    return rd_reader.stub_words()


def reader_hook_word():
    return rd_reader.hook_word()


def build_plan(candidates, stash_sites=None):
    if not candidates:
        raise BootProbeError("no candidates")
    if len(set(candidates)) != len(candidates):
        raise BootProbeError("duplicate candidates: %s"
                            % [hex(c) for c in candidates])
    for c in candidates:
        if not 0 <= c <= 0xFFFFFFFF:
            raise BootProbeError("candidate 0x%x out of 32-bit range" % c)
    if stash_sites is None:
        stash_sites = STASH_SITES
    if len(stash_sites) != len(candidates) + 1:
        raise BootProbeError("stash sites %d != candidates %d + 1"
                            % (len(stash_sites), len(candidates)))
    if len(set(stash_sites)) != len(stash_sites):
        raise BootProbeError("duplicate stash sites: %s"
                            % [hex(s) for s in stash_sites])
    for s in stash_sites:
        if s % 4:
            raise BootProbeError("stash site 0x%x not 4-aligned" % s)
        if not CR_WINDOW[0] <= s < CR_WINDOW[1]:
            raise BootProbeError("stash site 0x%x outside CR window "
                                 "[0x%x,0x%x)" % (s, *CR_WINDOW))
    count = len(candidates)
    if GUARD_WORDS - stub_words_len(count) < GUARD_SLACK_MIN:
        raise BootProbeError("boot stub %d words leave guard slack < %d"
                            % (stub_words_len(count), GUARD_SLACK_MIN))
    return {"candidates": list(candidates), "count": count,
            "stash_sites": list(stash_sites),
            "stub_words": stub_words_len(count)}


def _parse(text):
    mnem, rest = text.split(" ", 1)
    ops = [o.strip() for o in rest.split(",")]
    return mnem, ops


def _gate_boot_stub(words, candidates):
    if len(words) != stub_words_len(len(candidates)):
        raise BootProbeError("stub is %d words, want %d"
                            % (len(words), stub_words_len(len(candidates))))
    writes = set()
    for i, word in enumerate(words):
        dc = BOOT_STUB_DC + 4 * i
        text = dis(word, dc)
        if _assemble(text, dc)[0] != word:
            raise BootProbeError("stub word %d dis->re-assemble drift" % i)
        mnem, ops = _parse(text)
        if mnem.startswith(("b.", "jump", "call")):
            if i != len(words) - 1 or mnem != "jump" or \
                    int(ops[0], 16) != RESUME_DC:
                raise BootProbeError("stub word %d unexpected pc-relative "
                                     "(%s)" % (i, text))
            continue
        if mnem not in ("set2", "set3", "ld.d", "st.d"):
            raise BootProbeError("stub word %d off-canon mnemonic %s"
                                 % (i, mnem))
        if mnem == "set2" and ops[1] != "zero":
            raise BootProbeError("set2 %d rs %s != zero (OR trap)" %
                                 (i, ops[1]))
        if mnem == "set3" and ops[1] != ops[0]:
            raise BootProbeError("set3 %d rs %s != rd %s (OR trap)" %
                                 (i, ops[1], ops[0]))
        if mnem in ("ld.d", "st.d"):
            if ops[1] != "r%d" % ADDR_REG:
                raise BootProbeError("%s %d base %s != r%d"
                                     % (mnem, i, ops[1], ADDR_REG))
        first = ops[0]
        if not mnem.startswith(("st.",)):
            if not first.startswith("r") or not first[1:].isdigit():
                raise BootProbeError("stub word %d unparsable dest: %s"
                                     % (i, text))
            writes.add(int(first[1:]))
    if writes - SCRATCH_WRITES:
        raise BootProbeError("stub writes unexpected regs %s (r5/r6 only)"
                            % sorted(writes))


def decode_verify(words, candidates, sim_mem, sites=None):
    if sites is None:
        sites = STASH_SITES
    res = {"ok": False, "reasons": [], "stash": [], "reads": [], "writes": {}}
    regs = {}
    writes = {}
    reads = []
    for i, word in enumerate(words):
        dc = BOOT_STUB_DC + 4 * i
        text = dis(word, dc)
        mnem, ops = _parse(text)
        if mnem == "set2":
            regs[int(ops[0][1:])] = int(ops[2], 16) << 16
        elif mnem == "set3":
            rd = int(ops[0][1:])
            regs[rd] = regs.get(rd, 0) | int(ops[2], 16)
        elif mnem == "ld.d":
            addr = (regs[int(ops[1][1:])] + int(ops[2], 16)) & 0xFFFFFFFF
            reads.append(addr)
            regs[int(ops[0][1:])] = sim_mem.get(addr, 0)
        elif mnem == "st.d":
            addr = (regs[int(ops[1][1:])] + int(ops[2], 16)) & 0xFFFFFFFF
            writes[addr] = regs.get(int(ops[0][1:]), 0)
        elif mnem == "jump":
            if i != len(words) - 1 or int(ops[0], 16) != RESUME_DC:
                res["reasons"].append("word %d unexpected %s" % (i, text))
        else:
            res["reasons"].append("word %d unparsable %s" % (i, text))
    if reads != list(candidates):
        res["reasons"].append("sim reads %s != candidates %s"
                            % ([hex(a) for a in reads],
                               [hex(c) for c in candidates]))
    if set(writes) != set(sites):
        res["reasons"].append("sim writes %s != stash sites %s"
                            % (sorted(writes), sorted(sites)))
    if writes.get(sites[0]) != MAGIC:
        res["reasons"].append("sim magic slot 0x%x = %r != 0x%08x"
                            % (sites[0], writes.get(sites[0]), MAGIC))
    for k, cand in enumerate(candidates):
        if writes.get(sites[k + 1]) != sim_mem.get(cand, 0):
            res["reasons"].append("sim site 0x%x != sim_mem[0x%x]"
                                 % (sites[k + 1], cand))
    res["reads"] = reads
    res["writes"] = writes
    res["sites"] = list(sites)
    res["stash"] = [writes.get(s, None) for s in sites]
    res["ok"] = not res["reasons"]
    return res


def readout_sites():
    return [(s, 4) for s in STASH_SITES]


def readout_len(count):
    return 4 * (count + 1)


def _verdict(word):
    if word == 0x00000000:
        return VERDICT_00
    if word == 0xFFFFFFFF:
        return VERDICT_FF
    return VERDICT_DATA


def parse_readout(data, candidates):
    if len(data) < readout_len(len(candidates)):
        raise ValueError("readout blob %d B < %d B stash window"
                         % (len(data), readout_len(len(candidates))))
    words = list(struct.unpack_from(">%dI" % (len(candidates) + 1), data, 0))
    magic_ok = words[0] == MAGIC
    verdicts = []
    if magic_ok:
        verdicts = [_verdict(w) for w in words[1:]]
    return {"magic_ok": magic_ok, "magic": words[0], "verdicts": verdicts,
            "words": {hex(c): w for c, w in zip(candidates, words[1:])}}


def _graft(base_img, raw, code, tail, patch):
    new_code = bytearray(code)
    for dc, word in patch.items():
        new_code[dc:dc + 4] = struct.pack(">I", word)
    new_code = bytes(new_code)
    changed = [dc for dc in range(0, len(code), 4)
               if rc3_port.w32(code, dc) != rc3_port.w32(new_code, dc)]
    if sorted(changed) != sorted(patch):
        raise BootProbeError("word-diff %s != intended %d words"
                            % ([hex(d) for d in changed], len(patch)))
    if rc3_port.w32(new_code, rc3_port.GRAFT_DC) != rc3_port.GRAFT_WORD:
        raise BootProbeError("graft word 0x%06x touched" % rc3_port.GRAFT_DC)
    exp_lines = sorted({dc // 64 for dc in patch})
    new_raw = mlxfwutil.clcrc_wrap(new_code, tail)
    diff_lines = [i for i in range(len(code) // 64)
                  if raw[i * 68:(i + 1) * 68] !=
                  new_raw[i * 68:(i + 1) * 68]]
    if diff_lines != exp_lines:
        raise BootProbeError("changed 68B lines %s != expected %s"
                            % (diff_lines, exp_lines))
    edits = [(0x03, i * 68, new_raw[i * 68:(i + 1) * 68]) for i in diff_lines]
    out = mlxfwutil.patch_sections(base_img, edits)
    pimg = mlxfwutil.Image(out, "step1", base=base_img.base, fmt=base_img.fmt)
    if pimg.section_data(pimg.find_entry("ITOC", 0x03)) != new_raw:
        raise BootProbeError("built MAIN_CODE raw mismatch")
    errs = mlxfwutil.verify_image(pimg, deep=True)
    if errs:
        raise BootProbeError("step1 verify --deep failed: %s" % errs)
    return out, exp_lines


def build(ri, candidates=None, stash_sites=None):
    if candidates is None:
        candidates = CANDIDATES
    plan = build_plan(candidates, stash_sites)
    v = rc3_port.verify_base(ri)
    if not v["ok"]:
        raise BootProbeError("base incompatible: %s" % "; ".join(v["reasons"]))
    reader_words = reader_stub_words()
    rd_reader._gate_stub(reader_words, v["free_slot_words"])
    boot_words = boot_stub_words(plan["candidates"], plan["stash_sites"])
    _gate_boot_stub(boot_words, plan["candidates"])
    sim = decode_verify(boot_words, plan["candidates"], {},
                        plan["stash_sites"])
    if not sim["ok"]:
        raise BootProbeError("decode_verify failed: %s" % sim["reasons"])

    patch = {BOOT_HOOK_DC: boot_hook_word(),
             READER_HOOK_DC: reader_hook_word()}
    for i, word in enumerate(boot_words):
        patch[BOOT_STUB_DC + 4 * i] = word
    for i, word in enumerate(reader_words):
        patch[READER_STUB_DC + 4 * i] = word
    if len(patch) != 2 + len(boot_words) + len(reader_words):
        raise BootProbeError("patch map size drift: %d" % len(patch))

    base = mlxfwutil.Image(bytes(ri), "base")
    e03 = base.find_entry("ITOC", 0x03)
    raw = base.section_data(e03)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    step1, exp_lines = _graft(base, raw, code, tail, patch)

    pimg = mlxfwutil.Image(step1, "step1", base=base.base, fmt=base.fmt)
    e30 = pimg.find_entry("ITOC", 0x30)
    ini_text = zlib.decompressobj().decompress(
        pimg.section_data(e30)).decode("latin1")
    ini_final, _dropped = rc3_port.edit_ini(ini_text, e30.size,
                                            build_id=BUILD_ID)
    try:
        step2 = mlxfwutil.inject_ini(pimg, ini_final)
    except ValueError as e:
        raise BootProbeError("0x30 inject failed: %s" % e)
    simg = mlxfwutil.Image(step2, "step2", base=base.base, fmt=base.fmt)
    e30n = simg.find_entry("ITOC", 0x30)
    if e30n.addr != e30.addr:
        raise BootProbeError("0x30 relocated: 0x%x -> 0x%x"
                            % (e30.addr, e30n.addr))
    if e30n.size > e30.size or e30.size - e30n.size < rc3_port.HEADROOM_MIN:
        raise BootProbeError("0x30 size gate: 0x%x -> 0x%x (headroom %d)"
                            % (e30.size, e30n.size, e30.size - e30n.size))
    rt = zlib.decompressobj().decompress(
        simg.section_data(e30n)).decode("latin1")
    if rt != ini_final:
        raise BootProbeError("0x30 round-trip mismatch")

    status, _, _ = mlxfwutil.sig_status(simg)
    if status not in ("stale", "fresh"):
        raise BootProbeError("0xA0 unexpected status pre-sign: %s" % status)
    ea0 = simg.find_entry("ITOC", 0xA0)
    a0 = simg.sec_abs(ea0)
    if ea0.size < mlxfwutil.SIG_SLOT_OFF + 32:
        raise BootProbeError("0xA0 section too small: 0x%x" % ea0.size)
    digest = mlxfwutil.sha256_digest(simg)
    out = bytearray(step2)
    out[a0 + mlxfwutil.SIG_SLOT_OFF:a0 + mlxfwutil.SIG_SLOT_OFF + 32] = digest
    fimg = mlxfwutil.Image(bytes(out), "final", base=base.base, fmt=base.fmt)
    errs = mlxfwutil.verify_image(fimg, deep=True)
    if errs:
        raise BootProbeError("final verify --deep failed: %s" % errs)
    status, _, _ = mlxfwutil.sig_status(fimg)
    if status != "fresh":
        raise BootProbeError("0xA0 not fresh after sign: %s" % status)

    dg = rc3_port.diff_gate(base, bytes(out), exp_lines)
    if dg["stray"]:
        raise BootProbeError("stray diff bytes outside the intended zones: %s"
                            % [hex(o) for o in dg["stray"][:8]])
    if dg["empty_zones"]:
        raise BootProbeError("expected zones with no diff bytes: %s"
                            % dg["empty_zones"])
    if dg["section_diff"] != ["ITOC 0x03", "ITOC 0x30", "ITOC 0xA0"]:
        raise BootProbeError("section-level diff %s != {ITOC 0x03, 0x30, 0xA0}"
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
    gate_path = REPO / "build/boot-probe-gate.tmp"
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
            for k in ("FW Version", "PSID", "Base Guid", "Base MAC"):
                if l.strip().startswith(k + ":"):
                    rest = l.split(":", 1)[1].split()
                    got[k] = rest[0] if rest else ""
        return got

    qb, qf = q_fields(base_path), q_fields(gate_path)
    identity_ok = all(qf.get(k) == qb.get(k)
                      for k in ("FW Version", "PSID", "Base Guid", "Base MAC"))
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
        description="romdump RD-C: boot-time ROM probe image v2 (offline)")
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
