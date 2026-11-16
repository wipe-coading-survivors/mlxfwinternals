#!/usr/bin/env python3
"""romdump RD-B (Task 2): host loop for bulk zone dumps over the reader
channel.

The reader-stub image (rd_reader.py) returns 10 BE words (0x28 B) of iRISC
RAM per success QUERY(created): input word0 = read address, out_mb
[0x10..0x38) = RAM[addr..addr+0x28). zone_dump drives that channel in
chunks, committing each verified chunk to a local partial file before
advancing the resume state - a wedge (transport error / FW reload) never
loses committed progress: rerun resumes from state.json (fail-loud, no
blind retries; recovery is the documented mstfwreset procedure, then
rerun this script).

Core (tested): ZoneSpec / plan_chunks / check_stall / run_zone / finalize.
Live adapter (thin, untested here): SshChannel runs the mlxscope flowtable
dump mode on root-bazzite per chunk and pulls the chunk file back.

Wedge discipline: the stall aperture (top 32 KiB, >= 0xFFFF8000) is
refused before any post (check_stall); incidents go to the journal.

Zone extents (phase-3 map refined live 2026-11-16: B extends to 0x1080000,
word-probed zero at 0x1080000; A content ends ~0xCA0E2C with a zero tail to
0xCA8000 - artifacts keep the planned extents): A 0x00B97E00..0x00CA8000
(0x110200 B), B 0x01001000..0x01008000 (0x7F000 B).
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

READ_STRIDE = 0x28
STALL_FLOOR = 0xFFFF8000
DEFAULT_CHUNK_CMDS = 2048
DEFAULT_REFS = REPO / "refs/fw/cx-5-6/dumps/cx5-rom-2026-11-15"
DEFAULT_HOST = "root-bazzite"
DEFAULT_DEV = "/sys/bus/pci/devices/0000:03:00.0"


class ZoneDumpError(Exception):
    pass


class ChannelError(ZoneDumpError):
    pass


class ZoneSpec:
    def __init__(self, name, start, length):
        if start % 4 or length % 4:
            raise ZoneDumpError("zone %s extent must be 4-aligned" % name)
        self.name = name
        self.start = start
        self.length = length

    @property
    def end(self):
        return self.start + self.length


ZONES = {
    "A": ZoneSpec("A", 0xB97E00, 0x110200),
    "B": ZoneSpec("B", 0x1001000, 0x7F000),
}


class Chunk:
    def __init__(self, index, addr, nbytes):
        self.index = index
        self.addr = addr
        self.nbytes = nbytes


def plan_chunks(zone, chunk_cmds=DEFAULT_CHUNK_CMDS, stride=READ_STRIDE):
    chunk_bytes = chunk_cmds * stride
    chunks = []
    idx = 0
    addr = zone.start
    while addr < zone.end:
        nbytes = min(chunk_bytes, zone.end - addr)
        chunks.append(Chunk(idx, addr, nbytes))
        addr += nbytes
        idx += 1
    return chunks


def check_stall(zone, floor=STALL_FLOOR):
    if zone.start >= floor or zone.end > floor:
        raise ZoneDumpError(
            "zone %s 0x%x..0x%x enters the stall aperture (>= 0x%x)"
            % (zone.name, zone.start, zone.end, floor))
    for c in plan_chunks(zone):
        if c.addr >= floor:
            raise ZoneDumpError("chunk 0x%x enters the stall aperture" % c.addr)


def _append_partial(partial, data):
    with open(partial, "ab") as f:
        f.write(data)
        f.flush()


def _state_path(workdir, zone):
    return Path(workdir) / ("%s.state.json" % zone.name)


def _load_state(workdir, zone):
    p = _state_path(workdir, zone)
    if not p.exists():
        return {"zone": zone.name, "next_index": 0}
    return json.loads(p.read_text())


def _save_state(workdir, zone, next_index):
    p = _state_path(workdir, zone)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"zone": zone.name, "next_index": next_index}))
    tmp.replace(p)


def run_zone(zone, channel, workdir, chunk_cmds=DEFAULT_CHUNK_CMDS):
    check_stall(zone)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    partial = workdir / ("%s.partial" % zone.name)
    chunks = plan_chunks(zone, chunk_cmds)
    state = _load_state(workdir, zone)
    if state["zone"] != zone.name:
        raise ZoneDumpError("state zone mismatch: %s" % state["zone"])
    if partial.exists() and state["next_index"] == 0:
        partial.unlink()
    resumed = state["next_index"]
    done_bytes = partial.stat().st_size if partial.exists() else 0
    want_bytes = sum(c.nbytes for c in chunks[:resumed])
    if done_bytes != want_bytes:
        raise ZoneDumpError("partial %d B != committed chunks %d B"
                            % (done_bytes, want_bytes))
    for c in chunks[resumed:]:
        data = channel.read_chunk(c.addr, c.nbytes)
        if len(data) != c.nbytes:
            raise ChannelError("chunk 0x%x: got %d B, want %d"
                               % (c.addr, len(data), c.nbytes))
        _append_partial(partial, data)
        _save_state(workdir, zone, c.index + 1)
    return {"complete": True, "chunks": len(chunks), "resumed_from": resumed}


def finalize(zone, workdir, out_path, refs_rel=None):
    workdir = Path(workdir)
    partial = workdir / ("%s.partial" % zone.name)
    if not partial.exists() or partial.stat().st_size != zone.length:
        raise ZoneDumpError("zone %s incomplete: %s"
                            % (zone.name, partial.stat().st_size
                               if partial.exists() else "missing"))
    data = partial.read_bytes()
    out_path = Path(out_path)
    out_path.write_bytes(data)
    md5 = hashlib.md5(data).hexdigest()
    if refs_rel is None:
        refs_rel = "refs/fw/cx-5-6/dumps/cx5-rom-2026-11-15/%s" % out_path.name
    sidecar = out_path.with_name(out_path.name + ".md5")
    sidecar.write_text("%s  %s\n" % (md5, out_path))
    return "%s  %s" % (md5, refs_rel)


class SshChannel:
    """Live adapter: one mlxscope dump-mode run per chunk on root-bazzite."""

    def __init__(self, host=DEFAULT_HOST, dev=DEFAULT_DEV,
                 tool="/root/mlxscope", remote_dir="/root/romdump",
                 local_dir=None, chunk_cmds=DEFAULT_CHUNK_CMDS):
        self.host = host
        self.dev = dev
        self.tool = tool
        self.remote_dir = remote_dir
        self.local_dir = Path(local_dir) if local_dir else \
            Path("/tmp/opencode/romdump/chunks")
        self.local_dir.mkdir(parents=True, exist_ok=True)
        self.chunk_cmds = chunk_cmds
        self.seq = 0

    def _ssh(self, cmd, timeout=600):
        r = subprocess.run(["ssh", self.host, cmd], capture_output=True,
                           text=True, timeout=timeout)
        if r.returncode != 0:
            raise ChannelError("ssh rc=%d: %s%s"
                               % (r.returncode, r.stdout[-400:], r.stderr[-400:]))
        return r.stdout

    def read_chunk(self, addr, nbytes):
        cmds = (nbytes + READ_STRIDE - 1) // READ_STRIDE
        if cmds > self.chunk_cmds:
            raise ChannelError("chunk too large: %d cmds" % cmds)
        self.seq += 1
        name = "chunk-%08x-%d.bin" % (addr, self.seq)
        remote = "%s/%s" % (self.remote_dir, name)
        cmd = ("mkdir -p %s && %s flowtable --dev %s --dump-addr 0x%x "
               "--dump-len 0x%x --dump-out %s"
               % (self.remote_dir, self.tool, self.dev, addr, nbytes, remote))
        log = self._ssh(cmd)
        expected = cmds * READ_STRIDE
        local = self.local_dir / name
        scp = subprocess.run(["scp", "-q", "%s:%s" % (self.host, remote),
                              str(local)], capture_output=True, text=True,
                             timeout=300)
        if scp.returncode != 0:
            raise ChannelError("scp rc=%d: %s" % (scp.returncode,
                                                  scp.stderr[-400:]))
        data = local.read_bytes()
        self._ssh("rm -f %s" % remote)
        if len(data) == nbytes:
            return data
        if len(data) % READ_STRIDE == 0 and len(data) < expected:
            raise ChannelError("chunk 0x%x: tool completed only %d/%d B "
                               "(log tail: %s)" % (addr, len(data), nbytes,
                                                   log[-200:]))
        raise ChannelError("chunk 0x%x: pulled %d B, want %d"
                           % (addr, len(data), nbytes))


def cmd_run(args):
    zone = ZONES[args.zone.upper()]
    channel = SshChannel(chunk_cmds=args.chunk_cmds,
                         remote_dir=args.workdir)
    res = run_zone(zone, channel, args.workdir, chunk_cmds=args.chunk_cmds)
    print("zone %s: complete chunks=%d resumed_from=%d"
          % (zone.name, res["chunks"], res["resumed_from"]))
    refs = Path(args.refs)
    out = refs / ("zone%s.bin" % zone.name)
    line = finalize(zone, args.workdir, out)
    manifest = refs / "MANIFEST.md5"
    with open(manifest, "a") as f:
        f.write(line + "\n")
    print("finalized %s" % out)
    print("MANIFEST line: %s" % line)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description="romdump RD-B: bulk zone dump over the reader channel")
    p.add_argument("--zone", required=True, choices=sorted(ZONES),
                   help="zone to dump (A/B)")
    p.add_argument("--workdir", default="/tmp/opencode/romdump")
    p.add_argument("--refs", default=str(DEFAULT_REFS))
    p.add_argument("--chunk-cmds", type=int, default=DEFAULT_CHUNK_CMDS)
    args = p.parse_args(argv)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
