"""Publication-time obfuscation transform (spec §5, publication-branch-design).

load_registry: hardware.local.md (KEY = VALUE) → dict, keys as-is.
fake_value: deterministic synthetic replacement for one registry value —
OUI from the NIC-vendor pool (real OUI never preserved), per-card MAC/GUID
tail shared so the pair keeps the real 0300-structure, IPs from TEST-NET-3,
hostnames node-<hex6>.
transform_tree: replace registry values across a text tree in all normalized
encodings; returns the total replacement count.
"""

import hashlib
import re
from pathlib import Path

VENDOR_OUI = {
    "HPE": "28:80:88",
    "DELL": "f8:db:88",
    "MELLANOX": "00:02:c9",
    "IBM": "00:1a:64",
    "SUN": "00:14:4f",
    "CISCO": "00:00:0c",
}

_POOL_LIST = tuple(
    dict.fromkeys(
        oui.replace(":", "").lower() for oui in VENDOR_OUI.values()))

OUI_POOL = frozenset(_POOL_LIST)

_GUID_HEX_LEN = 16
_MAC_HEX_LEN = 12
_HEX_RE = re.compile(r"[0-9a-f]+")
_SEP_RE = re.compile(r"[:.\-\s]")


def _sha(*parts: str) -> bytes:
    return hashlib.sha256("|".join(parts).encode("utf-8")).digest()


def _norm_hex(value: str, n: int):
    h = _SEP_RE.sub("", value.strip().lower())
    if len(h) == n and _HEX_RE.fullmatch(h):
        return h
    return None


def _real_oui(real: str):
    h = _norm_hex(real, _MAC_HEX_LEN) or _norm_hex(real, _GUID_HEX_LEN)
    return h[:6] if h else None


def _pick_oui(label: str, real_oui) -> str:
    idx = int.from_bytes(_sha(label, "oui")[:8], "big") % len(_POOL_LIST)
    oui = _POOL_LIST[idx]
    if real_oui is not None and oui == real_oui:
        oui = _POOL_LIST[(idx + 1) % len(_POOL_LIST)]
    return oui


def _card_tail(label: str) -> str:
    return _sha(label, "tail")[:3].hex()


def load_registry(path: Path) -> dict:
    """hardware.local.md → dict key→value (keys as-is incl. case).

    Lines `KEY = VALUE`; whitespace stripped; blank/comment lines and lines
    without `=` skipped; first occurrence of a key wins (same semantics as
    mlxfwutil.hw()).
    """
    reg = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        k = k.strip()
        if k and k not in reg:
            reg[k] = v.strip()
    return reg


def fake_value(label: str, field: str, real: str) -> str:
    """Deterministic synthetic replacement for one registry value.

    Same (label, field, real) → same output. MAC = pool OUI + per-card tail;
    GUID = pool OUI + 03:00 + same tail (pair linked like real cards); the
    picked OUI never equals the real value's OUI. IP fields → 203.0.113.x
    (TEST-NET-3, host 1..254); hostname → node-<hex6>; anything else → a
    deterministic hex token. guid/mac outputs are bare lowercase hex, the
    registry canonical form.
    """
    f = field.lower()
    if f.endswith("guid"):
        return _pick_oui(label, _real_oui(real)) + "0300" + _card_tail(label)
    if "mac" in f:
        return _pick_oui(label, _real_oui(real)) + _card_tail(label)
    if f.endswith("ip"):
        n = 1 + int.from_bytes(_sha(label, f, "ip")[:8], "big") % 254
        return f"203.0.113.{n}"
    if "host" in f:
        return "node-" + _sha(label, f, "host").hex()[:6]
    return _sha(label, f, real).hex()[:16]


TEXT_SUFFIXES = frozenset(
    {".md", ".py", ".rs", ".sh", ".txt", ".toml", ".json", ".example"})


_HEX_FORMS = (
    ("", 2), (":", 2), ("-", 2), (" ", 2), (":", 4), (".", 2), (".", 4))


def _fmt_sep(h: str, sep: str, size: int) -> str:
    return sep.join(h[i:i + size] for i in range(0, len(h), size))


def _paired_forms(h: str, fake: str):
    for sep, size in _HEX_FORMS:
        real = _fmt_sep(h, sep, size)
        repl = _fmt_sep(fake, sep, size)
        yield (real, repl)
        yield (real.upper(), repl.upper())


_KNOWN_FIELDS = ("BMC_IP", "HOSTNAME", "GUID", "MAC", "IP")


def _split_key(key: str):
    """(label, field) of a registry key, hw()-composition inverse.

    Longest known field suffix wins (BMC_IP before IP); keys with an
    unknown suffix fall back to the last underscore.
    """
    u = key.upper()
    for field in _KNOWN_FIELDS:
        if u.endswith("_" + field):
            return key[:-len(field) - 1], key[-len(field):]
    label, _, field = key.rpartition("_")
    return label, field


def _replacement_rules(registry: dict):
    subs = []
    patterns = []
    seen = set()
    for key, value in registry.items():
        value = value.strip()
        if not value:
            continue
        label, field = _split_key(key)
        f = field.lower()
        h = None
        if f.endswith("guid"):
            h = _norm_hex(value, _GUID_HEX_LEN)
        elif "mac" in f:
            h = _norm_hex(value, _MAC_HEX_LEN)
        if h is not None:
            fake = fake_value(label, field, value)
            for needle, repl in _paired_forms(h, fake):
                if needle not in seen:
                    seen.add(needle)
                    subs.append((needle, repl))
        else:
            patterns.append(
                (re.compile(r"\b%s\b" % re.escape(value)),
                 fake_value(label, field, value)))
    subs.sort(key=lambda pair: -len(pair[0]))
    return subs, patterns


def transform_tree(root: Path, registry: dict) -> int:
    """Replace registry values across root's text tree; return the count.

    Text files: known text suffixes or extension-less names, no nul byte
    (binaries are skipped untouched). Content is utf-8 with surrogateescape.
    Hex ids (GUID/MAC keys) are replaced in bare, colon/dash/dot/space pair
    and colon/dot quad forms, both cases, with form-preserving fakes; other
    values as word-boundary substrings. Longer needles apply first, so a
    MAC embedded in a GUID encoding never double-counts.
    """
    root = Path(root)
    subs, patterns = _replacement_rules(registry)
    if not subs and not patterns:
        return 0
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix and path.suffix not in TEXT_SUFFIXES:
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        text = data.decode("utf-8", errors="surrogateescape")
        count = 0
        for needle, repl in subs:
            if needle in text:
                count += text.count(needle)
                text = text.replace(needle, repl)
        for pattern, repl in patterns:
            text, n = pattern.subn(lambda _m, r=repl: r, text)
            count += n
        if count:
            path.write_text(text, encoding="utf-8", errors="surrogateescape")
            total += count
    return total
