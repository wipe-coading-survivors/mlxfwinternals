import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

_spec = importlib.util.spec_from_file_location(
    "section_diff",
    Path(__file__).resolve().parent.parent / "scripts" / "probes"
    / "securefw-arc-a" / "section_diff.py")
section_diff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(section_diff)

from mlxfwutil import Image, clcrc_wrap  # noqa: E402
from tests.fixtures.corpus.synth_image import build_synth_image  # noqa: E402

CX7_A = (REPO / "refs" / "fw" / "cx-7" / "dumps" / "cx7_firmware_dumps"
         / "28.33.0751" / "orig_firmware.bin")
CX7_B = (REPO / "refs" / "fw" / "cx-7" / "dumps" / "cx7_firmware_dumps"
         / "28.33.0800.bin")


def words(*ws):
    return struct.pack(">%dI" % len(ws), *ws)


def synth_pair():
    cl_same = words(*(range(0x100, 0x180)))
    cl_a = words(*range(0x200, 0x280))
    cl_b_words = list(range(0x200, 0x280))
    cl_b_words[10] = 0x11CC020A
    cl_b = words(*cl_b_words)
    plain_a = words(*range(0x300, 0x310))
    plain_b_words = list(range(0x300, 0x310))
    plain_b_words[3] = 0x303 | (0xAB << 24)
    plain_b_words[9] = 0x309 | (0xCD << 24)
    plain_b = words(*(plain_b_words + [0x3FF, 0x3FE]))

    def sections(with_e0, with_11):
        out = [
            {"typ": 0x30, "payload": b"ini-blob-same", "zipped": True},
            {"typ": 0x32, "payload": plain_a if with_e0 else plain_b},
            {"typ": 0x03, "payload": cl_a if with_e0 else cl_b, "cl": True,
             "param0": 0x800000, "param1": 0x800010},
        ]
        if with_e0:
            out.append({"typ": 0xE0, "payload": b"dev-data-only-a"})
        if with_11:
            out.append({"typ": 0x11, "payload": b"only-b"})
        out.append({"typ": 0x05, "payload": cl_same, "cl": True,
                    "param0": 0x700000})
        return out

    return (build_synth_image(sections(True, False)),
            build_synth_image(sections(False, True)),
            {"cl_same": cl_same, "cl_a": cl_a, "cl_b": cl_b})


def rows_by_type(rows):
    return {r["section"]: r for r in rows}


def test_synthetic_pair_statuses():
    buf_a, buf_b, _ = synth_pair()
    rep = section_diff.build_report_bytes(buf_a, buf_b, boot=False)
    rows = rows_by_type(rep["sections"])
    assert set(rows) == {"03", "05", "11", "30", "32", "E0"}
    assert rows["05"]["status"] == "identical"
    assert rows["30"]["status"] == "identical"
    assert rows["30"]["zipped"] is True
    assert rows["03"]["status"] == "different"
    assert rows["32"]["status"] == "different"
    assert rows["E0"]["status"] == "absent"
    assert rows["E0"]["only_in"] == "a"
    assert rows["11"]["status"] == "absent"
    assert rows["11"]["only_in"] == "b"


def test_synthetic_pair_delta_quantification():
    buf_a, buf_b, p = synth_pair()
    rep = section_diff.build_report_bytes(buf_a, buf_b, boot=False)
    rows = rows_by_type(rep["sections"])

    d32 = rows["32"]["delta"]
    assert d32["bytes_delta"] == 2
    assert d32["words_delta"] == 2
    assert d32["tail_bytes"] == 8
    assert d32["min_len"] == 64
    assert d32["pct"] == pytest.approx(2 / 64 * 100, abs=0.01)

    d03 = rows["03"]["delta"]
    assert d03["bytes_delta"] == 2
    assert d03["words_delta"] == 1
    raw_delta = sum(1 for x, y in zip(clcrc_wrap(p["cl_a"]),
                                      clcrc_wrap(p["cl_b"])) if x != y)
    assert raw_delta == 4
    assert d03["tail_bytes"] == 0

    assert rows["05"]["md5_a"] == rows["05"]["md5_b"]
    assert rows["05"]["md5_a"] == hashlib.md5(p["cl_same"]).hexdigest()
    assert rows["E0"]["md5_b"] is None
    assert rows["03"]["md5_a"] == hashlib.md5(p["cl_a"]).hexdigest()
    assert rows["03"]["size_a"] == len(p["cl_a"])
    assert rows["03"]["size_b"] == len(p["cl_b"])
    assert rows["03"]["cl"] is True


def test_synthetic_absent_and_identical_have_no_delta():
    buf_a, buf_b, _ = synth_pair()
    rep = section_diff.build_report_bytes(buf_a, buf_b, boot=False)
    rows = rows_by_type(rep["sections"])
    assert rows["E0"]["delta"] is None
    assert rows["11"]["delta"] is None
    assert rows["05"]["delta"]["bytes_delta"] == 0
    assert rows["05"]["delta"]["pct"] == 0.0


def test_section_rows_from_images_directly():
    buf_a, buf_b, _ = synth_pair()
    rows = rows_by_type(
        section_diff.section_rows(Image(buf_a), Image(buf_b)))
    assert rows["03"]["status"] == "different"
    assert rows["E0"]["status"] == "absent"
    assert rows["03"]["name"] == "MAIN_CODE"


def _call(src_idx, dst_idx):
    return 0x94000000 | ((dst_idx - src_idx) & 0xFFFFFF)


_RET = 0xFC000025
_FILLER_A = [0x00000001, 0x00000002, 0x00000003]


def _irisc_payload_a():
    ws = [_call(0, 4), 0x11111111, 0x22222222, 0x33333333]
    ws += [0x44444401, 0x44444402, 0x44444403, 0x44444404, _RET]
    ws += [_call(9, 12), 0x55555551, 0x55555552]
    ws += [0x66666661, 0x66666662, 0x66666663, 0x66666664, _RET]
    ws += [0x77777771, 0x77777772, 0x77777773, 0x77777774,
           0x77777775, 0x77777776, 0x77777777]
    return words(*ws)


def _irisc_payload_b():
    ws = list(struct.unpack(">24I", _irisc_payload_a()))
    ws[5] = 0x44444FF2
    ws[2] = 0x22FFFF2
    ws += [0x88888881, 0x88888882, 0x88888883, 0x88888884]
    return words(*ws)


class _ProfileStub:
    census = set()


def test_disasm_delta_counters():
    counters = section_diff.disasm_delta(
        _irisc_payload_a(), _irisc_payload_b(), 0x1000, 0x1000,
        None, None, _ProfileStub())
    assert counters["words_a"] == 24
    assert counters["words_b"] == 28
    assert counters["changed_words"] == 2
    assert counters["tail_words"] == 4
    assert counters["funcs_a"] == 2
    assert counters["funcs_b"] == 2
    assert counters["funcs_changed"] == 1
    assert counters["funcs_only_a"] == 0
    assert counters["funcs_only_b"] == 0


def test_disasm_delta_function_only_on_one_side():
    pa = _irisc_payload_a()
    wb = list(struct.unpack(">24I", pa))
    wb[0] = 0x00000009
    pb = words(*wb)
    counters = section_diff.disasm_delta(pa, pb, 0x1000, 0x1000,
                                         None, None, _ProfileStub())
    assert counters["funcs_a"] == 2
    assert counters["funcs_b"] == 1
    assert counters["funcs_only_a"] == 1
    assert counters["funcs_changed"] == 1


def test_print_table_header_labels_all_columns(capsys):
    buf_a, buf_b, _ = synth_pair()
    rep = section_diff.build_report_bytes(buf_a, buf_b, boot=False)
    section_diff.print_table(rep)
    out = capsys.readouterr().out
    hdr = [ln for ln in out.splitlines() if ln.startswith("sec  ")][0]
    for label in ("size_a", "size_b", "Bdelta", "wdelta", "tail",
                  "wcommon", "%"):
        assert label in hdr


def _boot_buffers():
    a = bytearray(b"\xff" * 0x2000)
    b = bytearray(b"\xff" * 0x2000)
    rec = bytes(i % 254 for i in range(0x200)) + b"\xff" * 0x40
    a[0x100:0x100 + len(rec)] = rec
    b[0x100:0x100 + len(rec)] = rec
    b[0x2A0] ^= 0x01
    b[0x2B1] ^= 0x02
    b[0x2C2] ^= 0x03
    for buf, dw1 in ((a, 0xE), (b, 0x10)):
        buf[0x1000:0x1008] = struct.pack(">II", 0x20400040, dw1)
        buf[0x1008:0x1018] = b"boot2-payload"
    return bytes(a), bytes(b)


def test_boot_rows_record_and_boot2():
    a, b = _boot_buffers()
    rows = rows_by_type(section_diff.boot_rows(a, b))
    rec = rows["BOOT_RECORD"]
    assert rec["status"] == "different"
    assert rec["delta"]["bytes_delta"] == 3
    assert rec["delta"]["min_len"] == 0xF00
    assert rec["dense_extent_a"] == 0x200
    assert rec["dense_extent_b"] == 0x200
    boot2 = rows["BOOT2"]
    assert boot2["status"] == "different"
    assert boot2["size_a"] == 0x48
    assert boot2["size_b"] == 0x50
    assert boot2["delta"]["tail_bytes"] == 8
    assert boot2["dw0"] == "0x20400040"


def test_boot_rows_identical_record():
    a, b = _boot_buffers()
    b = bytearray(b)
    b[0x2A0] ^= 0x01
    b[0x2B1] ^= 0x02
    b[0x2C2] ^= 0x03
    rows = rows_by_type(section_diff.boot_rows(a, bytes(b)))
    assert rows["BOOT_RECORD"]["status"] == "identical"


def test_main_json_artifact(tmp_path):
    buf_a, buf_b, _ = synth_pair()
    pa = tmp_path / "a.bin"
    pb = tmp_path / "b.bin"
    pa.write_bytes(buf_a)
    pb.write_bytes(buf_b)
    out = tmp_path / "diff.json"
    rc = section_diff.main([str(pa), str(pb), "--json", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["a"]["path"] == str(pa)
    assert data["b"]["path"] == str(pb)
    assert data["a"]["md5"] == hashlib.md5(buf_a).hexdigest()
    assert len(data["sections"]) == 6


@pytest.mark.slow
def test_real_cx7_pair_report_shape():
    if not (CX7_A.is_file() and CX7_B.is_file()):
        pytest.skip("cx7 pre-release images not present")
    rep = section_diff.build_report(CX7_A, CX7_B)
    rows = rows_by_type(rep["sections"])
    assert len(rep["sections"]) == 29
    assert len(rep["boot"]) == 2
    assert rows["03"]["status"] == "different"
    assert rows["03"]["cl"] is True
    assert rows["03"]["delta"]["bytes_delta"] == 4613144
    assert rows["03"]["size_a"] == 5114880
    boot = rows_by_type(rep["boot"])
    assert boot["BOOT2"]["size_a"] == 0x4814
    assert boot["BOOT2"]["size_b"] == 0x4ED4
    assert boot["BOOT_RECORD"]["status"] == "different"
    assert boot["BOOT_RECORD"]["delta"]["bytes_delta"] == 11
    assert boot["BOOT_RECORD"]["dense_extent_a"] == 0x440
    dis = rows["03"]["disasm"]
    assert dis["funcs_a"] == 12384
    assert dis["funcs_b"] == 12491
    assert dis["changed_words"] > 1200000
