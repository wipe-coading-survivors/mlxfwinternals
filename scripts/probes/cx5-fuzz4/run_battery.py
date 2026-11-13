#!/usr/bin/env python3
"""fuzz4 Task-6 battery runner (host-side, root-mellanox, card 0000:81:00.0).

Runs the 24 fuzz4 vectors (all except the marker) via `mlxscope fuzzvec`
under a stabilized wrapper: V-F4-MARKER health check before and after every
vector.  Compares outcomes against fuzz4_vectors.json expectations, emits
per-hypothesis verdicts (жива / мертва / неопределена / wedge), keeps a
resumable state.json.  On a wedge (marker or run timeout/fail) it stops with
rc=42 and names the wedge vector; recovery (BMC cold cycle + VFIO rebind) is
done by the operator, then resume with `run --start N`.

Usage:
    run_battery.py selftest                 offline comparator checks
    run_battery.py run --start N [--end N]  live battery slice (indices into ORDER)
    run_battery.py summarize                verdict table from state.json
    run_battery.py dry-run [--start N]      print CLI, touch nothing

--vectors PATH: alternative battery JSON (fuzz-4 record format + a
V-F4-MARKER health record).  ORDER becomes the file order minus the
marker; state/logs/runs live under /root/<stem>-battery.  Without the
flag the runner is the stock fuzz-4 battery (env FUZZ4_JSON override as
before).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

TOOL = "/root/mlxscope"
BASE = Path("/root/fuzz4-t6")
JSON_PATH = Path(os.environ.get("FUZZ4_JSON", BASE / "fuzz4_vectors.json"))
STATE_PATH = BASE / "state.json"
BATTERY_LOG = BASE / "battery.log"
RUNS_DIR = BASE / "runs"
MARKERS_DIR = BASE / "markers"

RUN_TIMEOUT = 100
SENTINEL = 0xDEADBEEF
MARKER_PAYLOAD = (
    "2403f00d2063f00d6e401812000423206c801802"
    "0000000000000000000443c80884008efc002025"
)
MARKER_ID = "V-F4-MARKER"
MARKER_CR = 0xF00DF00D
STALE_T_VECTORS = {"V-ltV-1", "V-ltV-2"}

ORDER = [
    # w1prio (14)
    "V-0c-1", "V-0c-2", "V-0c-3",
    "V-34-1", "V-34-2", "V-34-6", "V-34-7",
    "V-0d-2", "V-0d-3", "V-0d-4", "V-0d-5",
    "V-33-2", "V-33-1", "V-33-3",
    # fuzz3rem (7)
    "V-f5map-1", "V-f5map-2", "V-f5map-3",
    "V-ltV-1", "V-ltV-2", "V-imm6", "V-op38-self",
    # c2rare (3)
    "V-r-3c", "V-r-39", "V-r-16",
]

WEDGE_RC = 42


# ---------------------------------------------------------------- summary ---

def parse_summary(text: str) -> dict | None:
    """Parse the last `[fuzzvec] summary:` line (output contract of the tool)."""
    for line in text.splitlines():
        if not line.startswith("[fuzzvec] summary:"):
            continue
        fields = line.split()[2:]
        kv = {}
        for f in fields:
            k, sep, v = f.partition("=")
            if sep:
                kv[k] = v
        need = ("created_id", "query_err", "status", "syndrome", "echo_ok",
                "canary", "sentinel_overwritten", "cr_post", "echo_zone",
                "destroy_err")
        if any(k not in kv for k in need):
            return None
        so = kv["sentinel_overwritten"].strip("[]")
        cr = kv["cr_post"].strip("[]")
        try:
            outcome = {
                "created_id": int(kv["created_id"]),
                "query_err": int(kv["query_err"]),
                "status": int(kv["status"]),
                "syndrome": int(kv["syndrome"], 16),
                "canary": kv["canary"] == "true",
                "destroy_err": int(kv["destroy_err"]),
                "sentinel_overwritten": [int(x, 16) for x in so.split(",")] if so else [],
                "cr_post": [int(x, 16) for x in cr.split(",")],
                "echo_zone": kv["echo_zone"].lower(),
            }
        except ValueError:
            return None
        if len(outcome["cr_post"]) != 8 or len(outcome["echo_zone"]) != 0x50:
            return None
        return outcome
    return None


# ------------------------------------------------------------- comparator ---

def cr_check(exp: str, cr_post: list[int]) -> str:
    """64-bit expectation = pair-check 0x8c8+0x8c9, low32 in the base slot."""
    val = int(exp, 16)
    low, high = val & 0xFFFFFFFF, val >> 32
    if cr_post[0] != low:
        return "NO"
    if cr_post[1] == high:
        return "MATCH"
    if cr_post[1] == SENTINEL:
        return "LOW32"  # 4B CR-write class, high half not CR-verified
    return "NO"


def echo_check(exp: str, echo_hex: str) -> str:
    b = bytes.fromhex(echo_hex)
    if exp == "stock":
        prefix = b[0:8].hex()
        if prefix == "0000000000000000" or prefix.startswith("f00df00d"):
            return "MATCH"
        return "NO"
    val = int(exp, 16)
    digits = len(exp.lower().removeprefix("0x"))
    n = min(8, max(4, (digits + 1) // 2))
    if n == 4:
        return "MATCH" if b[0:4] == val.to_bytes(4, "big") else "NO"
    low, high = val & 0xFFFFFFFF, val >> 32
    if b[0:8] == val.to_bytes(8, "big"):
        return "MATCH"
    if b[0:4] == low.to_bytes(4, "big"):
        if b[4:8] == high.to_bytes(4, "big"):
            return "MATCH-SPLIT"
        if b[4:8] == b"\x00" * 4:
            return "LOW32" if high == 0 else "LOW32-HIGHUNVER"
    return "NO"


def hyp_verdict(vid: str, exp: dict, o: dict, stale_t: bool = False) -> tuple[str, str]:
    statuses = []
    for k, v in exp.items():
        if k == "0x8c8":
            statuses.append(cr_check(v, o["cr_post"]))
        elif k == "echo":
            statuses.append(echo_check(v, o["echo_zone"]))
        else:
            statuses.append("NO")
    note = ""
    if "NO" in statuses:
        return "мертва", note
    verdict = "жива"
    if "LOW32-HIGHUNVER" in statuses:
        note = "low32 exact; expected high32 nonzero, unverifiable (4B store + zeroed mailbox)"
    elif "LOW32" in statuses or "MATCH-SPLIT" in statuses:
        note = "4B store class: low32 verified, high32 not independently verified"
    if any(v == "stock" for v in exp.values()) and stale_t:
        verdict, note = "неопределена", "stock echo: T-path vs stale-T (no predecessor)"
    return verdict, note


def vector_verdicts(vid: str, vec: dict, o: dict) -> dict:
    exps = vec.get("expectations") or {}
    stale_t = vid in STALE_T_VECTORS or bool(vec.get("stale_t"))
    if not exps:
        wrote = [hex(s) for s in o["sentinel_overwritten"]]
        v = "жива" if o["sentinel_overwritten"] else "мертва"
        return {"(no-hypothesis)": {
            "verdict": v,
            "observed": {
                "cr_post": [f"0x{x:08x}" for x in o["cr_post"]],
                "echo_zone": o["echo_zone"],
                "sentinel_overwritten": wrote,
            },
            "note": "exploratory rare op: data captured for offline analysis",
        }}
    out = {}
    for h, exp in exps.items():
        v, note = hyp_verdict(vid, exp, o, stale_t)
        obs = {k: exp[k] for k in exp}
        out[h] = {
            "verdict": v,
            "observed": {
                "cr0x8c8": f"0x{o['cr_post'][0]:08x}",
                "cr0x8c9": f"0x{o['cr_post'][1]:08x}",
                "echo16": o["echo_zone"][0:16],
            },
            "expected": obs,
            "note": note,
        }
    return out


# ------------------------------------------------------------------ runner ---

def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"next_index": 0, "completed": {}, "wedge": None, "dmesg_base": None}


def save_state(st: dict) -> None:
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False, indent=1))
    tmp.replace(STATE_PATH)


def blog(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    with BATTERY_LOG.open("a") as f:
        f.write(f"{ts} | {msg}\n")
    print(f"[{ts}] {msg}", flush=True)


def build_cli(vec: dict, payload: str) -> list[str]:
    cmd = [TOOL, "fuzzvec", "--payload-hex", payload]
    for slot, val in (vec.get("seeds") or {}).items():
        cmd += ["--seed", f"{slot}={val}"]
    return cmd


def run_tool(cmd: list[str], log: Path) -> tuple[int, dict | None, str]:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
        rc, out = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        rc = 124
        out = ((e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")) + \
              f"\n[runner] TIMEOUT after {RUN_TIMEOUT}s"
    log.write_text(out)
    return rc, parse_summary(out), out


def marker_check(o: dict | None) -> str | None:
    if o is None:
        return "no-summary"
    if o["created_id"] != 0:
        return f"created_id={o['created_id']}"
    if o["status"] != 0 or o["query_err"] != 0:
        return f"status={o['status']} err={o['query_err']}"
    if not o["canary"]:
        return "canary-missing"
    if o["cr_post"][0] != MARKER_CR:
        return f"cr0x8c8=0x{o['cr_post'][0]:08x}"
    if o["destroy_err"] != 0:
        return f"destroy_err={o['destroy_err']}"
    return None


def run_marker(tag: str) -> tuple[bool, str]:
    log = MARKERS_DIR / f"{tag}.log"
    cmd = [TOOL, "fuzzvec", "--payload-hex", MARKER_PAYLOAD]
    rc, o, _ = run_tool(cmd, log)
    if rc == 124:
        return False, "marker TIMEOUT"
    why = marker_check(o)
    if rc != 0 or why or o is None:
        return False, f"marker FAIL rc={rc} {why or ''}"
    return True, f"marker ok cr=0x{o['cr_post'][0]:08x}"


def dmesg_delta(base: int) -> list[str]:
    try:
        p = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=15)
        lines = p.stdout.splitlines()
    except Exception:
        return ["dmesg-unavailable"]
    new = lines[base:]
    pat = re.compile(r"81:00")
    noise = re.compile(r"vfio-pci.*(resetting|reset done)")
    return [l[:200] for l in new if pat.search(l) and not noise.search(l)]


def wedge_out(st: dict, vid: str, stage: str, detail: str) -> None:
    st["wedge"] = {"vector": vid, "stage": stage, "detail": detail}
    save_state(st)
    blog(f"WEDGE at {vid} ({stage}): {detail} -> rc={WEDGE_RC}, recovery needed")
    sys.exit(WEDGE_RC)


def do_run(vecs: dict, start: int, end: int) -> int:
    st = load_state()
    if st.get("dmesg_base") is None:
        p = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=15)
        st["dmesg_base"] = len(p.stdout.splitlines())
    save_state(st)
    idx = start
    while idx < end:
        vid = ORDER[idx]
        if vid in st["completed"] and "verdicts" in st["completed"][vid]:
            blog(f"{vid}: already completed, skip")
            idx += 1
            continue
        vec = vecs[vid]
        payload = "".join(vec["words"])
        blog(f"=== {vid} (idx {idx}) ===")
        ok, msg = run_marker(f"{idx:02d}-{vid}-pre")
        blog(f"{vid} pre-health: {msg}")
        if not ok:
            wedge_out(st, vid, "marker-pre", msg)

        outs, rcs = [], []
        for n in (1, 2, 3):
            if n == 3 and not (len(outs) == 2 and outs[0] != outs[1]):
                break
            rc, o, _ = run_tool(build_cli(vec, payload), RUNS_DIR / f"{vid}-{n}.log")
            blog(f"{vid} run{n}: rc={rc} "
                 + (f"cr0x8c8=0x{o['cr_post'][0]:08x} echo16={o['echo_zone'][0:16]}"
                    if o else "no-summary"))
            if rc == 124:
                blog(f"{vid} run{n}: TIMEOUT -> wedge suspicion")
                outs.append(None)
                rcs.append(rc)
                break
            outs.append(o)
            rcs.append(rc)
        timeout_seen = rcs and rcs[-1] == 124 and outs[-1] is None

        ok, msg = run_marker(f"{idx:02d}-{vid}-post")
        blog(f"{vid} post-health: {msg}")
        if not ok:
            wedge_out(st, vid, "marker-post" if not timeout_seen else "run+marker",
                      msg)

        good = [o for o in outs if o]
        if not good:
            st["completed"][vid] = {
                "verdicts": {"(tool)": {"verdict": "неопределена",
                                         "note": f"no summary in {len(outs)} run(s), rc={rcs}"}},
                "runs": len(outs), "rcs": rcs,
            }
            save_state(st)
            idx += 1
            continue

        key = lambda o: (o["cr_post"], o["echo_zone"], o["status"], o["syndrome"])  # noqa: E731
        best = max(good, key=lambda o: [key(x) for x in good].count(key(o)))
        divergence = len({json.dumps(key(o)) for o in good}) > 1
        verdicts = vector_verdicts(vid, vec, best)
        notes = [f"divergence across runs: {len(good)} runs" ] if divergence else []
        d = dmesg_delta(st["dmesg_base"])
        if d:
            blog(f"{vid} DMESG-DELTA: " + " ;; ".join(d[:6]))
            notes.append("dmesg-delta: " + "; ".join(d[:3]))
        st["completed"][vid] = {
            "verdicts": verdicts, "runs": len(outs), "rcs": rcs,
            "divergence": divergence, "notes": notes,
            "chosen": {"cr_post": [f"0x{x:08x}" for x in best["cr_post"]],
                       "echo_zone": best["echo_zone"],
                       "sentinel_overwritten": [hex(x) for x in best["sentinel_overwritten"]]},
        }
        for h, v in verdicts.items():
            blog(f"{vid} VERDICT {h}: {v['verdict']}" + (f" ({v['note']})" if v.get("note") else ""))
        st["next_index"] = idx + 1
        save_state(st)
        idx += 1
    blog(f"slice done (start={start} end={end})")
    return 0


def do_reverdict(vecs: dict) -> int:
    """Recompute verdicts from stored per-run outcomes (comparator updates)."""
    st = load_state()
    for vid, c in st["completed"].items():
        if "chosen" not in c or vid not in vecs:
            continue
        o = {"cr_post": [int(x, 16) for x in c["chosen"]["cr_post"]],
             "echo_zone": c["chosen"]["echo_zone"],
             "sentinel_overwritten": [int(x, 16) for x in c["chosen"]["sentinel_overwritten"]]}
        c["verdicts"] = vector_verdicts(vid, vecs[vid], o)
        for h, v in c["verdicts"].items():
            blog(f"REVERDICT {vid} {h}: {v['verdict']}"
                 + (f" ({v['note']})" if v.get("note") else ""))
    save_state(st)
    return 0


# --------------------------------------------------------------- reporting ---

def do_summarize() -> int:
    st = load_state()
    counts: dict[str, int] = {}
    rows = []
    for vid in ORDER:
        c = st["completed"].get(vid)
        if not c:
            rows.append((vid, "-", "not run", ""))
            continue
        for h, v in c["verdicts"].items():
            verdict = v["verdict"]
            counts[verdict] = counts.get(verdict, 0) + 1
            obs = v.get("observed", {})
            obs_s = obs if isinstance(obs, str) else json.dumps(obs, ensure_ascii=False)
            rows.append((vid, h, verdict, obs_s[:160]))
        if c.get("divergence"):
            rows.append((vid, "(meta)", "DIVERGENCE", str(c["notes"])))
    w = max(len(r[0]) for r in rows), max(len(r[1]) for r in rows)
    for vid, h, verdict, obs in rows:
        print(f"{vid:<{w[0]}} {h:<{w[1]}} {verdict:<12} {obs}")
    print(f"\ncounts: {counts}")
    if st.get("wedge"):
        print(f"wedge: {st['wedge']}")
    return 0


# ---------------------------------------------------------------- selftest ---

def synth(cr0: int, cr1: int = SENTINEL, echo8: bytes = b"") -> dict:
    cr = [SENTINEL] * 8
    cr[0], cr[1] = cr0, cr1
    e = (echo8 + b"\x00" * 0x28)[:0x28]
    return {"created_id": 0, "query_err": 0, "status": 0, "syndrome": 0,
            "canary": True, "destroy_err": 0, "sentinel_overwritten": [],
            "cr_post": cr, "echo_zone": e.hex()}


def selftest() -> int:
    ok = 0

    def chk(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        ok += 0 if cond else 1

    # parse_summary contract
    line = ("[fuzzvec] summary: created_id=0 query_err=0 status=0 syndrome=0x00000000 "
            "echo_ok=false canary=true sentinel_overwritten=[0x08c8] "
            "cr_post=[0xf00df00d,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef] "
            "echo_zone=" + ("00" * 0x28) + " destroy_err=0")
    o = parse_summary(line + "\ntrailing")
    chk("parse_summary", o is not None and o["cr_post"][0] == 0xF00DF00D
        and o["sentinel_overwritten"] == [0x8C8])
    chk("parse_summary garbage", parse_summary("hello") is None)

    # marker check
    m = synth(MARKER_CR)
    chk("marker_check ok", marker_check(m) is None)
    chk("marker_check bad cr", marker_check(synth(0x1234)) is not None)

    # T5 V-34-1 replay: cr0=0xfffffffd, high slot sentinel, echo 4B store
    v = synth(0xFFFFFFFD, SENTINEL, bytes.fromhex("fffffffd00000000"))
    v["sentinel_overwritten"] = [0x8C8]
    verdicts = vector_verdicts("V-34-1", {"expectations": {
        "H-34-clr": {"0x8c8": "0xfffffffffffffffd", "echo": "0xfffffffffffffffd"}}}, v)
    chk("V-34-1 replay жива+high-unver",
        verdicts["H-34-clr"]["verdict"] == "жива"
        and "unverifiable" in verdicts["H-34-clr"]["note"])

    # T5 V-0d-2 replay: H-0d-A split-match (low32 stored, mailbox zeroed high)
    v = synth(0x00FF0000, SENTINEL, bytes.fromhex("00ff000000000000"))
    verdicts = vector_verdicts("V-0d-2", {"expectations": {
        "H-0d-A": {"0x8c8": "0x0000000000ff0000", "echo": "0x0000000000ff0000"},
        "H-0d-raw": {"0x8c8": "0x00000000000000ff", "echo": "0x00000000000000ff"}}}, v)
    chk("V-0d-2 replay A жива / raw мертва",
        verdicts["H-0d-A"]["verdict"] == "жива"
        and verdicts["H-0d-raw"]["verdict"] == "мертва")

    # T5 V-0c-1 replay: observed 0x00cd1234 -> all trio dead
    exps = {"H-0c-ANDN-raw": {"0x8c8": "0xabcd1200", "echo": "0xabcd1200"},
            "H-0c-ANDN-sh16": {"0x8c8": "0xab001234", "echo": "0xab001234"},
            "H-0c-OR": {"0x8c8": "0xabcd12ff", "echo": "0xabcd12ff"}}
    verdicts = vector_verdicts("V-0c-1", {"expectations": exps},
                               synth(0x00CD1234, SENTINEL, bytes.fromhex("00cd1234")))
    chk("V-0c-1 replay all мертва",
        all(x["verdict"] == "мертва" for x in verdicts.values()))

    # stock echo: ltV -> неопределена for stock-Hs, мертва for write-H
    stock = b"\x00" * 8 + bytes.fromhex("00000004") + b"\x00" * (0x28 - 12)
    v = synth(SENTINEL, SENTINEL, stock)
    verdicts = vector_verdicts("V-ltV-1", {"expectations": {
        "H-36-f5p2-lt32": {"echo": "0x0000000080000000"},
        "H-36-f5p2-lt16": {"echo": "stock"},
        "H-36-f5p2-V": {"echo": "stock"}}}, v)
    chk("ltV stock -> неопределена/мертва",
        verdicts["H-36-f5p2-lt32"]["verdict"] == "мертва"
        and verdicts["H-36-f5p2-lt16"]["verdict"] == "неопределена"
        and verdicts["H-36-f5p2-V"]["verdict"] == "неопределена")

    # ltV write observed (F-path): lt32 жива, stock-Hs мертва
    v = synth(0x80000000, SENTINEL, bytes.fromhex("0000000080000000"))
    verdicts = vector_verdicts("V-ltV-1", {"expectations": {
        "H-36-f5p2-lt32": {"echo": "0x0000000080000000"},
        "H-36-f5p2-lt16": {"echo": "stock"},
        "H-36-f5p2-V": {"echo": "stock"}}}, v)
    chk("ltV write -> lt32 жива",
        verdicts["H-36-f5p2-lt32"]["verdict"] == "жива"
        and verdicts["H-36-f5p2-lt16"]["verdict"] == "мертва")

    # f5map sentinel-stays (T-path, known predecessor) -> жива
    v = synth(SENTINEL, SENTINEL, stock)
    verdicts = vector_verdicts("V-f5map-1", {"expectations": {
        "H-36-f5p4-ule32": {"0x8c8": "0xdeadbeef"}}}, v)
    chk("f5map sentinel-stay жива", verdicts["H-36-f5p4-ule32"]["verdict"] == "жива")

    # f5map write 5 (F-path)
    v = synth(5, SENTINEL, bytes.fromhex("00000005"))
    verdicts = vector_verdicts("V-f5map-1", {"expectations": {
        "H-36-f5p4-eq32": {"0x8c8": "0x5"}}}, v)
    chk("f5map write5 жива", verdicts["H-36-f5p4-eq32"]["verdict"] == "жива")

    # rare no-expectation vector
    v = synth(0xA1B2C3D8, SENTINEL, bytes.fromhex("a1b2c3d8"))
    v["sentinel_overwritten"] = [0x8C8]
    verdicts = vector_verdicts("V-r-39", {}, v)
    chk("rare op жива capture", verdicts["(no-hypothesis)"]["verdict"] == "жива")

    # ORDER sanity vs JSON
    vecs = json.loads(JSON_PATH.read_text()) if JSON_PATH.exists() else None
    if vecs:
        by_id = {v["id"]: v for v in vecs}
        ids = set(by_id)
        chk("ORDER covers all but marker",
            set(ORDER) == ids - {MARKER_ID} and len(ORDER) == len(ids) - 1)
        chk("payload lengths 80 hex",
            all(len(by_id[vid]["words"]) == 10 and
                len("".join(by_id[vid]["words"])) == 80 for vid in ORDER))
        chk("marker payload == tool constant",
            "".join(by_id[MARKER_ID]["words"]) == MARKER_PAYLOAD)
    print(f"selftest failures: {ok}")
    return 1 if ok else 0


# --------------------------------------------------------------------- main ---

def use_vectors(path: str) -> None:
    global JSON_PATH, BASE, STATE_PATH, BATTERY_LOG, RUNS_DIR, MARKERS_DIR, ORDER
    p = Path(path)
    vecs = json.loads(p.read_text())
    ids = [v["id"] for v in vecs]
    if MARKER_ID not in ids:
        sys.exit(f"--vectors: {p} has no {MARKER_ID} health record")
    if len(set(ids)) != len(ids):
        sys.exit(f"--vectors: {p} has duplicate ids")
    JSON_PATH = p
    BASE = Path("/root") / (p.stem + "-battery")
    STATE_PATH = BASE / "state.json"
    BATTERY_LOG = BASE / "battery.log"
    RUNS_DIR = BASE / "runs"
    MARKERS_DIR = BASE / "markers"
    ORDER = [i for i in ids if i != MARKER_ID]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["run", "summarize", "selftest", "dry-run", "reverdict"])
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=None)
    ap.add_argument("--vectors", default=None,
                    help="alternative battery JSON (fuzz-4 format + marker)")
    args = ap.parse_args()

    if args.vectors:
        use_vectors(args.vectors)
    if args.end is None:
        args.end = len(ORDER)

    if args.mode == "selftest":
        return selftest()
    if args.mode == "dry-run":
        vecs = {v["id"]: v for v in json.loads(JSON_PATH.read_text())}
        for vid in ORDER[args.start:args.end]:
            print(" ".join(build_cli(vecs[vid], "".join(vecs[vid]["words"]))))
        return 0
    if args.mode == "summarize":
        return do_summarize()
    if args.mode == "reverdict":
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        vecs = {v["id"]: v for v in json.loads(JSON_PATH.read_text())}
        return do_reverdict(vecs)

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    MARKERS_DIR.mkdir(parents=True, exist_ok=True)
    vecs = {v["id"]: v for v in json.loads(JSON_PATH.read_text())}
    return do_run(vecs, args.start, args.end)


if __name__ == "__main__":
    sys.exit(main())
