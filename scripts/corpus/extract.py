import json
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from mlxfwutil import clcrc_unwrap
from scripts.irisc import recount_codehist as _RC


class PriorDisagreement(Exception):
    pass


DOMAIN_PRIOR = {}
for _t in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0D, 0x0E, 0x15):
    DOMAIN_PRIOR[_t] = "iRISC"
for _t in (0x0A, 0x0B, 0x0C):
    DOMAIN_PRIOR[_t] = "PHY"
DOMAIN_PRIOR[0x18] = "ROM"

DOMAIN_PRIOR_OVERRIDE: dict[tuple[str, int], str] = {
    ("cx6", 0x15): "data",
    ("cx7", 0x0F): "iRISC",
}


@dataclass
class SectionRec:
    typ: int
    size: int
    flash_addr: int
    param0: int
    param1: int
    cl: bool
    zipped: bool
    dev: bool
    raw: bytes = b""
    dc: bytes = b""
    status: str = "OK"
    status_reason: str = ""
    domain: str = "data"
    domain_override: str = ""
    domain_evidence: dict | None = None


def _instance_stats(dc: bytes):
    n = len(dc) // 4
    if n == 0:
        return "data", 0.0
    words = struct.unpack_from(">%dI" % n, dc, 0)
    _, _, code, _, _, _ = _RC.classify(words, n)
    n_code = sum(code)
    label = "iRISC" if 2 * n_code >= n else "data"
    return label, n_code / n


def classify_instance(dc: bytes) -> str:
    return _instance_stats(dc)[0]


def sections_of(img, family: str | None = None) -> list:
    recs = []
    for e in img.entries("ITOC"):
        override = (DOMAIN_PRIOR_OVERRIDE.get((family, e.type))
                    if family is not None else None)
        if override is not None:
            prior = override
        else:
            prior = DOMAIN_PRIOR.get(e.type, "data")
        rec = SectionRec(
            typ=e.type,
            size=e.size,
            flash_addr=e.addr,
            param0=e.param0,
            param1=e.param1,
            cl=bool(e.clcrc),
            zipped=bool(e.zipped),
            dev=bool(e.dev),
            domain=prior,
            domain_override="" if override is None else override,
        )
        raw = img.section_data(e)
        rec.raw = raw
        if e.zipped:
            rec.status = "SKIPPED"
            rec.status_reason = "zipped"
        elif e.size == 0:
            rec.raw = b""
            rec.dc = b""
        elif e.clcrc:
            try:
                payload, _tail = clcrc_unwrap(raw)
            except ValueError as exc:
                rec.status = "ERROR"
                rec.status_reason = str(exc)
            else:
                rec.dc = payload
        else:
            rec.dc = raw
        if override is not None:
            if rec.dc:
                label, ratio = _instance_stats(rec.dc)
                rec.domain_evidence = {
                    "classifier": label,
                    "code_ratio": round(ratio, 4),
                }
        elif prior == "iRISC" and rec.status == "OK" and rec.dc \
                and classify_instance(rec.dc) != "iRISC":
            raise PriorDisagreement(
                "section 0x%02x: domain prior iRISC but instance "
                "classifier says data" % e.type)
        recs.append(rec)
    return recs


def write_sections(out_dir, recs, extra_meta=None) -> None:
    sections_dir = Path(out_dir) / "sections"
    extras = extra_meta if extra_meta is not None else {}
    for rec in recs:
        d = sections_dir / ("%02X" % rec.typ)
        d.mkdir(parents=True, exist_ok=True)
        (d / "raw.bin").write_bytes(rec.raw)
        (d / "dc.bin").write_bytes(rec.dc)
        meta = asdict(rec)
        meta.pop("raw")
        meta.pop("dc")
        meta.update(extras.get(rec.typ, {}))
        (d / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
