#!/usr/bin/env python3
"""cx4lx-an-fsm task-01: timeline analysis (Lx loop cadence, CX-5 restart cadence,
marker-based FW-ts<->epoch calibration)."""
import re, sys
from datetime import datetime, timezone

BASE = "/tmp/opencode/cx4lxan"
TS_RE = re.compile(r"^\[0x([0-9a-f]+)\]")

def parse_ts(line):
    m = TS_RE.match(line)
    return int(m.group(1), 16) if m else None

def load(path):
    out = []
    with open(path, errors="replace") as f:
        for ln in f:
            ts = parse_ts(ln)
            if ts is not None:
                out.append((ts, ln.rstrip()))
    return out

def markers(path):
    out = []
    for ln in open(path):
        p = ln.split()
        if len(p) >= 3:
            out.append(((float(p[0]) + float(p[1])) / 2, p[2]))
        elif len(p) == 2:
            try:
                out.append((float(p[0]), p[1]))
            except ValueError:
                pass
    return out

def icmd_pairs(events):
    return [ts for ts, l in events if "icmd_generic_reg_access" in l and "0x9040" in l]

def fit(pairs):
    """pairs: (fw_ts, epoch) -> (a,b,rate,resid_max) fw_ts = a + b*epoch (centered)"""
    n = len(pairs)
    if n < 2:
        return None
    mx = sum(e for _, e in pairs) / n
    my = sum(t for t, _ in pairs) / n
    sxx = sum((e - mx) ** 2 for _, e in pairs)
    sxy = sum((t - my) * (e - mx) for t, e in pairs)
    b = sxy / sxx
    a = my - b * mx
    rmax = max(abs(t - (a + b * e)) for t, e in pairs)
    return a, b, 1.0 / b, rmax  # 1/b = s per tick

def epochs_of(events, cal, pat):
    a, b, _, _ = cal
    return [ (a + b * 0 + (t - a)) / 1 for t in [] ]  # placeholder

def main():
    # ---- Bazzite window 1 ----
    bz = load(f"{BASE}/bazzite1/window.log")
    bz_m = markers(f"{BASE}/bazzite1/markers.txt")
    bz_icmd = icmd_pairs(bz)
    print(f"bazzite1: events={len(bz)} markers={len(bz_m)} icmd={len(bz_icmd)}")
    arm = [m for m in bz_m if m[1].startswith("arm")]
    pairs = list(zip(bz_icmd[:len(arm)], [e for e, _ in arm]))
    cal_bz = fit(pairs)
    if cal_bz:
        a, b, spt, rmax = cal_bz
        print(f"bazzite1 cal: {spt*1e9:.3f} ns/tick, resid={rmax/b:.3f} s over {len(pairs)} pts")
        def ep(t): return (t - a) / b
        inits = [t for t, l in bz if "init_ib_an_fsm" in l]
        t036 = [t for t, l in bz if "input_event 0x36" in l]
        t01 = [t for t, l in bz if "fsm_ps 0, fsm_ns 1" in l]
        t10 = [t for t, l in bz if "fsm_ps 1, fsm_ns 0" in l]
        t3d = [t for t, l in bz if "input_event 0x3d" in l]
        print(f"Lx: init={len(inits)} 0x36={len(t036)} 0->1={len(t01)} 1->0={len(t10)} 0x3d={len(t3d)}")
        e0, e1 = ep(inits[0]), ep(inits[-1])
        print(f"Lx window-of-inits: {e0:.2f}..{e1:.2f} span={e1-e0:.2f}s cycle={(e1-e0)/(len(inits)-1):.4f}s")
        pd = [(ep(inits[i+1]) - ep(inits[i])) for i in range(len(inits)-1)]
        pd_sorted = sorted(pd)
        print(f"Lx cycle periods: min={pd_sorted[0]:.3f} med={pd_sorted[len(pd)//2]:.3f} max={pd_sorted[-1]:.3f}")
        w0 = [m for m in bz_m if m[1] == "WINDOW-START"]
        w1 = [m for m in bz_m if m[1] == "WINDOW-END"]
        if w0 and w1:
            print(f"Lx WINDOW: {w0[0][0]:.2f}..{w1[0][0]:.2f} ({w1[0][0]-w0[0][0]:.1f}s)")

    # ---- Server probe calibration (for pre-window CX-5 bursts) ----
    pr = load(f"{BASE}/server1/owner-probe-41_00.0.log")
    pr_icmd = icmd_pairs(pr)
    pr_m = markers(f"{BASE}/server1/owner-probe-markers.txt")
    pr_m = [(e, l) for e, l in pr_m]  # marker-41:00.0-N
    pr_m.sort(key=lambda x: x[0])
    print(f"\nprobe: icmd={len(pr_icmd)} markers={len(pr_m)}")
    cal_pr = None
    if len(pr_icmd) == len(pr_m) and len(pr_icmd) >= 2:
        cal_pr = fit(list(zip(pr_icmd, [e for e, _ in pr_m])))
        if cal_pr:
            a, b, spt, rmax = cal_pr
            print(f"probe cal: {spt*1e9:.3f} ns/tick resid={rmax/b:.3f}s")

    # ---- CX-5 restarts: wake-test flush + window1 salvage ----
    for name, path in [("wake", f"{BASE}/server1/wake-test.log"), ("win1", f"{BASE}/server1/window.log"),
                       ("restore1", f"{BASE}/server1/restore.log")]:
        try:
            ev = load(path)
        except FileNotFoundError:
            continue
        r01 = [t for t, l in ev if "fsm_ps 0, fsm_ns 1" in l and "ib_speed_nego_fsm" in l]
        r_init = [t for t, l in ev if "init_ib_an_fsm" in l]
        r_36 = [t for t, l in ev if "input_event 0x36" in l]
        r_3d = [t for t, l in ev if "input_event 0x3d" in l]
        r_3e = [t for t, l in ev if "input_event 0x3e" in l]
        r_3f = [t for t, l in ev if "input_event 0x3f" in l]
        chosen = [l for _, l in ev if "set_preset_mask" in l]
        ts3 = [l for _, l in ev if "set_default_ts" in l]
        print(f"\n{name}: events={len(ev)} cx5[0->1]={len(r01)} init={len(r_init)} 0x36={len(r_36)} 0x3d={len(r_3d)} 0x3e={len(r_3e)} 0x3f={len(r_3f)}")
        for c in chosen[:4]: print("   ", c[:120])
        for c in ts3[:2]: print("   ", c[:120])
        if cal_pr and len(r01) >= 2:
            a, b, spt, _ = cal_pr
            eps = [(t - a) / b for t in r01]
            pd = sorted(eps[i+1] - eps[i] for i in range(len(eps)-1))
            print(f"   cx5 0->1 epochs: {eps[0]:.1f}..{eps[-1]:.1f} n={len(eps)}")
            print(f"   periods: min={pd[0]:.2f} med={pd[len(pd)//2]:.2f} max={pd[-1]:.2f}")
            print("   eps:", " ".join(f"{e:.1f}" for e in eps))

if __name__ == "__main__":
    main()
