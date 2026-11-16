#!/usr/bin/env python3
"""romdump RD-A (Task 1): R-C3 H1b readback port onto the bazzite ri_stock base.

Ports the phase-XI success-path readback (canon
docs/superpowers/reports/cx5-successpath-rc3.md; staging map
docs/superpowers/reports/cx5-successpath-rc12.md sections 2-6) onto the bazzite
card's own graft base refs/fw/cx-5-6/dumps/cx5-rom-2026-11-15/ri_stock.bin
(ri dump of the as-found 4030graft-vpi0-c4c6-bazzite FW; PSID
MT_0000000013, non-secure). Offline only: no burn here (owner GO first),
no live operations.

Composition (H1b, dc = MAIN_CODE de-clcrc byte offset, rt = dc + 0x800000):

  dc 0x0E43C4  hook: stock dead-write 0x00130000 (addi r19,zero,0x0) ->
               HOOK_WORD 0x940AA4EC (call 0x38d774) - byte-identical to the
               R-C3 canon hook (stub kept at the canon dc, so the encodings
               carry over verbatim; the v4-echo canary words that preceded
               the stub on the 81:00.0 base simply do not exist here)
  dc 0x38D774..23 words: the R-C3 H1b stub - 10x (ld.d r6,r1,0xb0+4k /
               st.d r6,r18,0x10+4k) moving the QUERY frame copy
               [r1+0x98..0xd8) window [r1+0xb0..0xd8) = input[0x18..0x40)
               (40B host payload) into response+0x10..0x38 (out_mb
               verbatim window), then the exit triple addi/addi.hi/ret.r
               composing resume rt 0x8E43C8. Writes only r4/r6; r11
               (mask32 @0x0e43c0) and r17..r23 never touched.
  0x30        Rule-1 build-ID inserted right after the banner (vendor ;;
               comments trimmed to headroom >= 32; 0x30 stays in place)
  0xA0        Rule-5 digest re-signed after all content changes

verify_base(ri) checks the base contract before any patching: MAIN_CODE
geometry (0x1c748 / 0x3d15a0 / clcrc=1 / param0=0x800000), the nine pinned
context words (boot word, BadParam call-site, collector call, r11 producer,
hook-site stock dead-write, r8=0x40 completion length, completion tail-call,
FN_A prologue, bazzite graft word @0x25a3ec), the zeroed cave
(S0 zone / cutout / 34-word stub slot / guarded tail), and the clcrc
round-trip.

build(ri) applies the composition with in-script gates (verify --deep after
graft and after sign, word-diff == hook + 23 stub words, clcrc-line diff ==
expected, 0x30 round-trip, fresh-0xA0 check, byte-diff whitelist via
diff_gate) and returns deterministic image bytes.

CLI: --base <ri> --verify | --base <ri> --out <image.bin> (extra gates:
mstflint -i verify/q/dc, mlxfwutil.py verify --deep + sign --check,
deterministic rebuild; writes the artifact + .md5 sidecar).
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

DEFAULT_BASE = REPO / "refs/fw/cx-5-6/dumps/cx5-rom-2026-11-15/ri_stock.bin"
RI_MD5 = "4c68cb924f460a08896c4ad344579b62"

MAIN_ADDR = 0x1C748
MAIN_SIZE = 0x3D15A0
CODE_LEN = 0x397DC0
PARAM0 = 0x800000

HOOK_DC = 0x0E43C4
HOOK_STOCK = 0x00130000
HOOK_WORD = 0x940AA4EC
R11_PRODUCER_DC = 0x0E43C0
R11_PRODUCER_DIS = "mask32 r11,r4,0x8,2"
COLLECTOR_DC = 0x0E43B8
COMPLETION_LEN_DC = 0x0E43D8
COMPLETION_TAIL_DC = 0x0E43E4
BADPARAM_CALL_DC = 0x0E437C
FN_A_DC = 0x18D964
BOOT_WORD_DC = 0x1D594
GRAFT_DC = 0x25A3EC
GRAFT_WORD = 0x0011001F

SITE_WORDS = {
    BOOT_WORD_DC: 0x940002DE,
    BADPARAM_CALL_DC: 0x9402A57A,
    COLLECTOR_DC: 0x9400001B,
    R11_PRODUCER_DC: 0xC88B0102,
    HOOK_DC: HOOK_STOCK,
    COMPLETION_LEN_DC: 0x00080040,
    COMPLETION_TAIL_DC: 0xFC008825,
    FN_A_DC: 0x480300BC,
    GRAFT_DC: GRAFT_WORD,
}

S0_ZONE = (0x38D730, 0x38D748)
CUTOUT_ZONE = (0x38D748, 0x38D750)
SLOT_ZONE = (0x38D750, 0x38D7D8)
GUARD_ZONE = (0x38D7D8, 0x38DBE8)
CAVE_ZONES = (("s0", S0_ZONE), ("cutout", CUTOUT_ZONE),
              ("stub slot", SLOT_ZONE), ("guard", GUARD_ZONE))

STUB_DC = 0x38D774
STUB_COUNT = 23
RESUME_RT = 0x8E43C8
READ_LO, READ_HI = 0xB0, 0xD8
WRITE_LO, WRITE_HI = 0x10, 0x38
PAIRS = (READ_HI - READ_LO) // 4
DATA_REG = 6
EXIT_REG = 4
GOLDEN_PAIR = [0x642600B2, 0x6E403012]
EXIT_TRIPLE = [0x000443C8, 0x0884008E, 0xFC002025]
ALLOWED_WRITES = {DATA_REG, EXIT_REG}
NO_WRITE_PREFIX = ("st.", "ret.", "b.", "jump", "call")

BUILD_ID = (
    "; mlxini romdump rc3-bazzite v1 (2026-11-15, "
    "docs/superpowers/journal/2026-11-15-rom-dump-cx5-task-01): "
    "H1b echo readback port, hook 0x0E43C4 -> stub 23w @0x38d774, "
    "base ri_stock graft"
)
BANNER = ";; Mellanox Technologies LTD"
HEADROOM_MIN = 32
PRIOR_ID_PREFIX = "; mlxini "


class Rc3PortError(Exception):
    pass


def w32(buf, off):
    return struct.unpack_from(">I", buf, off)[0]


def _assemble(text, base):
    data = assemble(text, base=base, profile=load_profile("cx5"), strict=True)
    return list(struct.unpack(">%dI" % (len(data) // 4), data))


def stub_text():
    lines = []
    for k in range(PAIRS):
        lines.append("ld.d r%d,r1,0x%x" % (DATA_REG, READ_LO + 4 * k))
        lines.append("st.d r%d,r18,0x%x" % (DATA_REG, WRITE_LO + 4 * k))
    lines.append("addi r%d,zero,0x%x" % (EXIT_REG, RESUME_RT & 0xffff))
    lines.append("addi.hi r%d,r%d,0x%x" % (EXIT_REG, EXIT_REG,
                                           RESUME_RT >> 16))
    lines.append("ret.r zero,zero,r%d" % EXIT_REG)
    return "\n".join(lines) + "\n"


def stub_words():
    words = _assemble(stub_text(), STUB_DC)
    if len(words) != STUB_COUNT:
        raise Rc3PortError("stub is %d words, canon H1b = %d"
                           % (len(words), STUB_COUNT))
    return words


def hook_word():
    word = _assemble("call 0x%x" % STUB_DC, HOOK_DC)[0]
    if word != HOOK_WORD:
        raise Rc3PortError("hook word %08x != R-C3 canon %08x"
                           % (word, HOOK_WORD))
    return word


def verify_base(ri):
    reasons = []
    result = {
        "ok": False,
        "reasons": reasons,
        "main_code": {},
        "clcrc_roundtrip": False,
        "cave_nonzero": [],
        "free_slot_words": 0,
        "stub_slack": 0,
    }
    try:
        img = mlxfwutil.Image(bytes(ri), "base")
    except ValueError as e:
        reasons.append(str(e))
        return result
    try:
        e = img.find_entry("ITOC", 0x03)
    except KeyError as e:
        reasons.append(str(e))
        return result
    geom = (e.addr, e.size, e.clcrc, e.param0)
    if geom != (MAIN_ADDR, MAIN_SIZE, 1, PARAM0):
        reasons.append("MAIN_CODE geometry mismatch: addr=0x%x size=0x%x "
                       "clcrc=%d param0=0x%x (want 0x%x/0x%x/1/0x%x)"
                       % (geom + (MAIN_ADDR, MAIN_SIZE, PARAM0)))
        return result
    result["main_code"] = {"addr": e.addr, "size": e.size, "clcrc": e.clcrc,
                           "param0": e.param0}
    try:
        raw = img.section_data(e)
        code, tail = mlxfwutil.clcrc_unwrap(raw)
        roundtrip = mlxfwutil.clcrc_wrap(code, tail) == raw
    except ValueError as ex:
        reasons.append("clcrc unwrap failed: %s" % ex)
        return result
    if not roundtrip:
        reasons.append("clcrc round-trip failed on the base")
        return result
    result["clcrc_roundtrip"] = True
    for dc, want in SITE_WORDS.items():
        got = w32(code, dc)
        if got != want:
            reasons.append("site 0x%06x: %08x != expected %08x"
                           % (dc, got, want))
    if w32(code, R11_PRODUCER_DC) == SITE_WORDS[R11_PRODUCER_DC] and \
            dis(w32(code, R11_PRODUCER_DC), R11_PRODUCER_DC) != R11_PRODUCER_DIS:
        reasons.append("r11 producer @0x%06x decodes off-canon"
                       % R11_PRODUCER_DC)
    nonzero = []
    for name, (lo, hi) in CAVE_ZONES:
        nonzero += [dc for dc in range(lo, hi, 4) if w32(code, dc)]
    result["cave_nonzero"] = nonzero
    if nonzero:
        reasons.append("cave not free: nonzero words @ %s"
                       % [hex(dc) for dc in nonzero[:8]])
    free = (SLOT_ZONE[1] - SLOT_ZONE[0]) // 4
    result["free_slot_words"] = free
    result["stub_slack"] = free - STUB_COUNT
    if result["stub_slack"] < 2:
        reasons.append("stub slack %d < 2 (R-E C-RE1 precedent)"
                       % result["stub_slack"])
    result["ok"] = not reasons
    return result


def _zw_pad(text):
    d = zlib.compress(text.encode("latin1"), 9)
    return len(d) + (4 - len(d) % 4) % 4


def edit_ini(text, size, build_id=None):
    if build_id is None:
        build_id = BUILD_ID
    lines = text.splitlines(keepends=True)
    banners = [i for i, l in enumerate(lines) if l.startswith(BANNER)]
    if len(banners) != 1:
        raise Rc3PortError("expected exactly one banner, got %d" % len(banners))
    bi = banners[0]
    prior = [l for l in lines if l.startswith(PRIOR_ID_PREFIX)]
    if prior:
        raise Rc3PortError("base ini already carries a mlxini build-ID: %r"
                           % prior[:1])
    lines.insert(bi + 1, build_id + "\n")
    kv0 = sum(1 for l in lines if l.strip() and not l.startswith(";"))
    cand = [i for i, l in enumerate(lines) if l.startswith(";;") and i != bi]
    dropped = []

    def cur_text():
        ds = set(dropped)
        return "".join(l for i, l in enumerate(lines) if i not in ds)

    while _zw_pad(cur_text()) > size - HEADROOM_MIN:
        if not cand:
            raise Rc3PortError("0x30: no ;; lines left to trim, still over "
                               "budget (size %d)" % size)
        dropped.append(cand.pop(0))
    ini_final = cur_text()
    kv1 = sum(1 for l in lines if l.strip() and not l.startswith(";"))
    if kv0 != kv1:
        raise Rc3PortError("key=value line count changed: %d -> %d" % (kv0, kv1))
    final_lines = ini_final.splitlines()
    if final_lines.index(build_id) != final_lines.index(BANNER) + 1:
        raise Rc3PortError("build-ID is not right after the banner")
    return ini_final, [lines[i].rstrip() for i in dropped]


def _gate_stub(words, free):
    if len(words) != STUB_COUNT:
        raise Rc3PortError("stub is %d words, canon H1b = %d"
                           % (len(words), STUB_COUNT))
    if free - len(words) < 2:
        raise Rc3PortError("stub slack %d < 2" % (free - len(words)))
    loads, stores, writes = [], [], set()
    for i, word in enumerate(words):
        dc = STUB_DC + 4 * i
        text = dis(word, dc)
        if _assemble(text, dc)[0] != word:
            raise Rc3PortError("stub word %d dis->re-assemble drift" % i)
        mnem, rest = text.split(" ", 1)
        ops = rest.split(",")
        if mnem == "ld.d":
            if ops[1].strip() != "r1":
                raise Rc3PortError("ld.d %d base %s != r1 (frame live-in)"
                                   % (i, ops[1]))
            loads.append((int(ops[0].strip()[1:]), int(ops[2].strip(), 16)))
        elif mnem == "st.d":
            if ops[1].strip() != "r18":
                raise Rc3PortError("st.d %d base %s != r18 (response live-in)"
                                   % (i, ops[1]))
            stores.append((int(ops[0].strip()[1:]), int(ops[2].strip(), 16)))
        if mnem.startswith(("b.", "jump", "call")):
            raise Rc3PortError("stub word %d is pc-relative (%s)" % (i, text))
        first = rest.split()[0].split(",")[0]
        if not mnem.startswith(NO_WRITE_PREFIX):
            if not first.startswith("r") or not first[1:].isdigit():
                raise Rc3PortError("stub word %d unparsable dest: %s"
                                   % (i, text))
            writes.add(int(first[1:]))
    if len(loads) != PAIRS or len(stores) != PAIRS:
        raise Rc3PortError("width parity: %d ld.d / %d st.d != %d pairs"
                           % (len(loads), len(stores), PAIRS))
    for k, ((lr, lo), (sr, so)) in enumerate(zip(loads, stores)):
        if lo != READ_LO + 4 * k or so != WRITE_LO + 4 * k:
            raise Rc3PortError("pair %d offsets 0x%x/0x%x break the byte "
                               "mapping 0x%x+4k -> 0x%x+4k"
                               % (k, lo, so, READ_LO, WRITE_LO))
        if lr != DATA_REG or sr != DATA_REG:
            raise Rc3PortError("pair %d uses r%d/r%d != data r%d"
                               % (k, lr, sr, DATA_REG))
    if writes - ALLOWED_WRITES:
        raise Rc3PortError("stub writes unexpected regs %s (r4/r6 only)"
                           % sorted(writes))
    if words[:2] != GOLDEN_PAIR:
        raise Rc3PortError("first pair %s != rc2 G8 golden %s"
                           % ([hex(w) for w in words[:2]],
                              [hex(w) for w in GOLDEN_PAIR]))
    if words[-3:] != EXIT_TRIPLE:
        raise Rc3PortError("exit triple %s != resume rt 0x%08X compose %s"
                           % ([hex(w) for w in words[-3:]], RESUME_RT,
                              [hex(w) for w in EXIT_TRIPLE]))


def _graft(base_img, raw, code, tail, stub_dc, words, hook):
    patch = {HOOK_DC: hook}
    for i, word in enumerate(words):
        patch[stub_dc + 4 * i] = word
    if len(patch) != 1 + len(words):
        raise Rc3PortError("patch map size drift: %d" % len(patch))
    new_code = bytearray(code)
    for dc, word in patch.items():
        new_code[dc:dc + 4] = struct.pack(">I", word)
    new_code = bytes(new_code)
    changed = [dc for dc in range(0, len(code), 4)
               if w32(code, dc) != w32(new_code, dc)]
    if sorted(changed) != sorted(patch):
        raise Rc3PortError("word-diff %s != intended %d words"
                           % ([hex(d) for d in changed], len(patch)))
    if w32(new_code, GRAFT_DC) != GRAFT_WORD:
        raise Rc3PortError("graft word 0x%06x touched" % GRAFT_DC)
    exp_lines = sorted({dc // 64 for dc in patch})
    new_raw = mlxfwutil.clcrc_wrap(new_code, tail)
    diff_lines = [i for i in range(len(code) // 64)
                  if raw[i * 68:(i + 1) * 68] !=
                  new_raw[i * 68:(i + 1) * 68]]
    if diff_lines != exp_lines:
        raise Rc3PortError("changed 68B lines %s != expected %s"
                           % (diff_lines, exp_lines))
    edits = [(0x03, i * 68, new_raw[i * 68:(i + 1) * 68]) for i in diff_lines]
    out = mlxfwutil.patch_sections(base_img, edits)
    pimg = mlxfwutil.Image(out, "step1", base=base_img.base, fmt=base_img.fmt)
    if pimg.section_data(pimg.find_entry("ITOC", 0x03)) != new_raw:
        raise Rc3PortError("built MAIN_CODE raw mismatch")
    errs = mlxfwutil.verify_image(pimg, deep=True)
    if errs:
        raise Rc3PortError("step1 verify --deep failed: %s" % errs)
    return out, exp_lines


def build(ri):
    v = verify_base(ri)
    if not v["ok"]:
        raise Rc3PortError("base incompatible: %s" % "; ".join(v["reasons"]))
    base = mlxfwutil.Image(bytes(ri), "base")
    words = stub_words()
    hook = hook_word()
    _gate_stub(words, v["free_slot_words"])
    e03 = base.find_entry("ITOC", 0x03)
    raw = base.section_data(e03)
    code, tail = mlxfwutil.clcrc_unwrap(raw)
    step1, exp_lines = _graft(base, raw, code, tail, STUB_DC, words, hook)

    pimg = mlxfwutil.Image(step1, "step1", base=base.base, fmt=base.fmt)
    e30 = pimg.find_entry("ITOC", 0x30)
    ini_text = zlib.decompressobj().decompress(
        pimg.section_data(e30)).decode("latin1")
    ini_final, _dropped = edit_ini(ini_text, e30.size)
    try:
        step2 = mlxfwutil.inject_ini(pimg, ini_final)
    except ValueError as e:
        raise Rc3PortError("0x30 inject failed: %s" % e)
    simg = mlxfwutil.Image(step2, "step2", base=base.base, fmt=base.fmt)
    e30n = simg.find_entry("ITOC", 0x30)
    if e30n.addr != e30.addr:
        raise Rc3PortError("0x30 relocated: 0x%x -> 0x%x"
                           % (e30.addr, e30n.addr))
    if e30n.size > e30.size or e30.size - e30n.size < HEADROOM_MIN:
        raise Rc3PortError("0x30 size gate: 0x%x -> 0x%x (headroom %d)"
                           % (e30.size, e30n.size, e30.size - e30n.size))
    rt = zlib.decompressobj().decompress(
        simg.section_data(e30n)).decode("latin1")
    if rt != ini_final:
        raise Rc3PortError("0x30 round-trip mismatch")

    status, _, _ = mlxfwutil.sig_status(simg)
    if status not in ("stale", "fresh"):
        raise Rc3PortError("0xA0 unexpected status pre-sign: %s" % status)
    ea0 = simg.find_entry("ITOC", 0xA0)
    a0 = simg.sec_abs(ea0)
    if ea0.size < mlxfwutil.SIG_SLOT_OFF + 32:
        raise Rc3PortError("0xA0 section too small: 0x%x" % ea0.size)
    digest = mlxfwutil.sha256_digest(simg)
    out = bytearray(step2)
    out[a0 + mlxfwutil.SIG_SLOT_OFF:a0 + mlxfwutil.SIG_SLOT_OFF + 32] = digest
    fimg = mlxfwutil.Image(bytes(out), "final", base=base.base, fmt=base.fmt)
    errs = mlxfwutil.verify_image(fimg, deep=True)
    if errs:
        raise Rc3PortError("final verify --deep failed: %s" % errs)
    status, _, _ = mlxfwutil.sig_status(fimg)
    if status != "fresh":
        raise Rc3PortError("0xA0 not fresh after sign: %s" % status)

    dg = diff_gate(base, bytes(out), exp_lines)
    if dg["stray"]:
        raise Rc3PortError("stray diff bytes outside the intended zones: %s"
                           % [hex(o) for o in dg["stray"][:8]])
    if dg["empty_zones"]:
        raise Rc3PortError("expected zones with no diff bytes: %s"
                           % dg["empty_zones"])
    if dg["section_diff"] != ["ITOC 0x03", "ITOC 0x30", "ITOC 0xA0"]:
        raise Rc3PortError("section-level diff %s != {ITOC 0x03, 0x30, 0xA0}"
                           % dg["section_diff"])
    return bytes(out)


def diff_gate(base_img, out_buf, exp_lines):
    b03 = base_img.find_entry("ITOC", 0x03)
    e30 = base_img.find_entry("ITOC", 0x30)
    ea0 = base_img.find_entry("ITOC", 0xA0)
    img = mlxfwutil.Image(bytes(out_buf), "final", base=base_img.base,
                          fmt=base_img.fmt)
    zones = {}
    for ln in exp_lines:
        zones["MAIN_CODE line %d" % ln] = range(b03.addr + ln * 68,
                                                b03.addr + ln * 68 + 68)
    for name, e in (("ITOC 0x03 entry", b03), ("ITOC 0x30 entry", e30)):
        off = base_img.itoc_off + 32 + e.index * 32
        zones[name] = range(off, off + 32)
    zones["0x30 section"] = range(e30.addr, e30.addr + e30.size)
    zones["0xA0 section"] = range(ea0.addr, ea0.addr + ea0.size)
    diffs = [i for i in range(len(out_buf))
             if out_buf[i] != base_img.buf[i]]
    dset = set(diffs)
    allowed = set()
    for r in zones.values():
        allowed |= set(r)
    stray = [i for i in diffs if i not in allowed]
    empty = [n for n, r in zones.items() if not any(i in dset for i in r)]
    changed_secs = []
    for toc in ("ITOC", "DTOC"):
        bes = list(base_img.entries(toc))
        fes = list(img.entries(toc))
        if len(bes) != len(fes):
            changed_secs.append("%s entry count %d -> %d"
                                % (toc, len(bes), len(fes)))
            continue
        for e, fe in zip(bes, fes):
            if fe.type != e.type or img.section_data(fe) != \
                    base_img.section_data(e):
                changed_secs.append("%s 0x%02X" % (toc, e.type))
    return {"diffs": diffs, "stray": stray, "empty_zones": empty,
            "section_diff": sorted(changed_secs)}


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO))
    print("$ " + " ".join(str(c) for c in cmd))
    for stream in (r.stdout, r.stderr):
        for line in stream.strip().splitlines():
            print("    " + line)
    return r


def cmd_verify(args):
    v = verify_base(Path(args.base).read_bytes())
    for k in ("ok", "main_code", "clcrc_roundtrip", "cave_nonzero",
              "free_slot_words", "stub_slack"):
        print("%s: %s" % (k, v[k]))
    for r in v["reasons"]:
        print("reason: %s" % r)
    print("verify_base verdict: %s" % ("OK" if v["ok"] else "INCOMPATIBLE"))
    return 0 if v["ok"] else 1


def cmd_build(args):
    base_path = Path(args.base)
    buf = base_path.read_bytes()
    md5 = hashlib.md5(buf).hexdigest()
    print("base: %s md5 %s" % (base_path, md5))
    if base_path.resolve() == DEFAULT_BASE.resolve() and md5 != RI_MD5:
        print("FATAL: default base md5 != ri_stock canon %s" % RI_MD5)
        return 1
    out_path = Path(args.out)
    out = build(buf)
    md5 = hashlib.md5(out).hexdigest()
    print("built: %d B md5 %s" % (len(out), md5))
    gate_path = REPO / "build/rc3-bazzite-gate.tmp"
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
        description="romdump RD-A: R-C3 H1b readback port (offline)")
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
