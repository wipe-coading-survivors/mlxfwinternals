#!/usr/bin/env python3
"""B1 live-V1 helpers: wall-clock log wrapper + PCI device phase poller.

Run on the card host (root-bazzite). Usage:
  ts-wrap:    b1_helpers.py ts            (stdin -> stdout, wall-clock prefix)
  poller:     b1_helpers.py poll LOGFILE  (20 ms poll of present/bound/netdev,
              logs only state transitions as "<epoch> (present, bound, nd)")
B1 run of 2026-10-11: see docs/superpowers/reports/cx4lx-detour-b1.md.
"""
import os
import sys
import time

BDF = "0000:04:00.0"
NETDEV_PREFIX = "ibs5"


def ts_main():
    for line in sys.stdin:
        sys.stdout.write("%.6f %s" % (time.time(), line))
        sys.stdout.flush()


def present():
    return os.path.exists("/sys/bus/pci/devices/" + BDF)


def bound():
    return os.path.exists("/sys/bus/pci/devices/%s/driver" % BDF)


def nd():
    return len([n for n in os.listdir("/sys/class/net")
                if n.startswith(NETDEV_PREFIX)])


def poll_main(path):
    out = open(path, "a", 1)
    last = None
    while True:
        st = (present(), bound(), nd())
        if st != last:
            out.write("%.6f %s\n" % (time.time(), st))
            last = st
        time.sleep(0.02)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    if sys.argv[1] == "ts":
        ts_main()
    elif sys.argv[1] == "poll" and len(sys.argv) == 3:
        poll_main(sys.argv[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
