import re
import struct
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.corpus.manifest import IMAGE_TO_PROFILE
from scripts.irisc import disasm
from scripts.irisc.profiles import ProfileError, annotate, load_profile

PROFILE_ABSENT = "PROFILE_ABSENT"
PROFILE_DRIFT = "PROFILE_DRIFT"

_OFF_VERSION_KEYS = frozenset({"cx5/16_19_1200", "cx6dx/22_47"})
_FAMILY_FALLBACK = {
    "cx4": "cx4-1228",
    "cx4lx": "cx4lx",
    "cx5": "cx5",
    "cx6": "cx6-2043",
    "cx6dx": "cx6dx",
    "cx6lx": "cx6lx-2650",
}
_UNKNOWN_OP_RE = re.compile(r'\bop0x([0-9a-fA-F]{2})\b')


def profile_for(family, ver):
    prefix = "_".join(ver.split("_")[:2])
    for key in ("%s/%s" % (family, ver), "%s/%s" % (family, prefix)):
        if key in IMAGE_TO_PROFILE:
            return IMAGE_TO_PROFILE[key], key in _OFF_VERSION_KEYS
    return _FAMILY_FALLBACK[family], True


def _words(dc):
    return struct.unpack_from(">%dI" % (len(dc) // 4), dc, 0)


def disasm_section(dc, base_dc):
    lines = []
    for i, w in enumerate(_words(dc)):
        dc_addr = base_dc + 4 * i
        try:
            body = disasm(w, dc_addr)
        except Exception:
            body = "raw 0x%08x" % w
        lines.append({"dc": dc_addr, "w": w,
                      "text": "%08x  %08x  %s" % (dc_addr, w, body)})
    return lines


def disasm_txt(dc, base_dc, profile, lines=None):
    if lines is None:
        lines = disasm_section(dc, base_dc)
    text = "\n".join(line["text"] for line in lines)
    return annotate(text, profile)


def recount_delta(dc, profile, lines=None):
    hist = Counter()
    if lines is None:
        for w in _words(dc):
            m = _UNKNOWN_OP_RE.search(disasm(w, 0))
            if m:
                hist["0x" + m.group(1).lower()] += 1
    else:
        for line in lines:
            m = _UNKNOWN_OP_RE.search(line["text"])
            if m:
                hist["0x" + m.group(1).lower()] += 1
    census = set(profile.census)
    new_ops = sorted(op for op in hist if op not in census)
    return {
        "new_ops": new_ops,
        "counts": {op: hist[op] for op in sorted(hist)},
        "flag": PROFILE_DRIFT if new_ops else None,
    }


def disasm_stage(dc, base_dc, family, ver, lines=None):
    name, off_version = profile_for(family, ver)
    profile = None
    status = "OK"
    try:
        profile = load_profile(name)
    except ProfileError:
        status = PROFILE_ABSENT
    delta = recount_delta(dc, profile, lines=lines) \
        if profile is not None else None
    return {
        "profile": name,
        "off_version": off_version,
        "status": status,
        "drift": delta is not None and delta["flag"] == PROFILE_DRIFT,
        "delta": delta,
        "text": disasm_txt(dc, base_dc, profile, lines=lines),
    }
