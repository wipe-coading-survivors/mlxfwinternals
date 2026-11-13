import argparse
import ast
import os
import struct
import subprocess
import sys
import unittest
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scripts.irisc import assemble, encode_form, disasm, AsmError  # noqa: E402
import scripts.irisc.irisc_asm as ia  # noqa: E402
import test_irisc_dis  # noqa: E402  (inserts scripts/irisc into sys.path)
import irisc_dis  # noqa: E402

# golden v3-shellcode docs/250-re/120-irisc/025-boot-injection.md (6 слов, BE)
V3_WORDS = [0x24050000, 0x20a523f0, 0x2406badc, 0x20c60001, 0x6ca03002,
            0x95f24272]

# полный lossy-реестр рендеров (Architecture): слово не восстанавливается
# бит-экзакт из dis-текста — ассемблер канонизирует, гарантируется fixpoint
LOSSY_MNEMONICS = {"ld.q.17", "st.q.1e", "csr.w", "csr.r", "st.i", "ld.i",
                   "mask32"}


def _is_lossy(text):
    m = text.split()[0]
    return m in LOSSY_MNEMONICS or m.startswith("alu.0x")


def _golden_pairs():
    recorded = []
    orig = irisc_dis.dis

    def spy(w, off):
        res = orig(w, off)
        recorded.append((w, off, res))
        return res

    irisc_dis.dis = spy
    try:
        suite = unittest.defaultTestLoader.loadTestsFromModule(test_irisc_dis)
        with open(os.devnull, "w") as devnull:
            result = unittest.TextTestRunner(stream=devnull).run(suite)
        assert result.wasSuccessful()
    finally:
        irisc_dis.dis = orig
    seen = set()
    pairs = []
    for w, off, text in recorded:
        if (w, off) in seen:
            continue
        seen.add((w, off))
        pairs.append((w, off, text))
    return pairs


def test_v3_shellcode_from_friendly_syntax():
    src = "\n".join([
        "set2 r5,zero,0x0000", "set3 r5,r5,0x23f0",
        "set2 r6,zero,0xbadc", "set3 r6,r6,0x0001",
        "st.d r6,r5,0x0", "jump 0x1e10c"])
    assert assemble(src, base=0x38d730) == b"".join(
        struct.pack(">I", w) for w in V3_WORDS)


GOLDEN_PAIRS = _golden_pairs()


@pytest.mark.parametrize("w,off,text", GOLDEN_PAIRS,
                         ids=["%s_%08x" % (t.split()[0], w)
                              for w, _, t in GOLDEN_PAIRS])
def test_canonical_roundtrip_goldens(w, off, text):
    # base = off пары; lossless-формы бит-экзакт, lossy — fixpoint
    blob = assemble(text, base=off)
    assert len(blob) == 4
    w1 = struct.unpack(">I", blob)[0]
    if _is_lossy(text):
        assert disasm(w1, off) == text
        w2 = struct.unpack(">I", assemble(disasm(w1, off), base=off))[0]
        assert w2 == w1
    else:
        assert w1 == w


def test_unknown_op_generic_form():
    # op0x36-слово: dis рендерит 'op0x36 r1,r2,r3 imm=0x1234' — parse-back
    w = (0x36 << 26) | (2 << 21) | (1 << 16) | (3 << 11) | 0x1234
    assert encode_form("op0x36", rd=1, rs=2, rt=3, imm=0x1234) == w


def test_syndicate_dialect_and_sugar():
    src = "\n".join([
        "set32 r5, 0x12345678",
        "set64 r5, 5",
        "cmp38_eq32 r5,zero",
        "unk.r 0x3f,r1,r2,r3,0x37",
        "unk.i 0x36,r1,r2,0x1234",
        "dword 0x95f24272",
        "alur.0xb r1,r2,r3",
        "ld.q r5,r1,0x10",
        "ld.d r5,r1,r3,0x10",
        "st.q r0,r4,r7,0x18,0x0",
        "alu.r 0x25,zero,r8,r3",
        "ret.d r0,r0,r0",
    ])
    words = struct.unpack(">16I", assemble(src))
    assert words == (
        0x24051234, 0x20A55678,
        0x18050000, 0x1CA50000, 0x24A50000, 0x20A50005,
        0xE0A00002,
        0xFC411837,
        0xD8411234,
        0x95F24272,
        0xFC41180B,
        0x64250010,
        0x64251812,
        0x78803818,
        0xFD001825,
        0xFC00002D,
    )


def test_friendly_branch_and_label_two_pass():
    src = "\n".join([
        "lbl setup",
        "b.set r4,16,setup2",
        "b.t 0x0a,r1,setup",
        "lbl setup2",
        "call setup",
    ])
    assert struct.unpack(">3I", assemble(src)) == (0xA8900002, 0xA02AFFFF,
                                                   0x94FFFFFE)


def test_encode_form_matches_enc_reference():
    from scripts.irisc import enc
    assert encode_form("set2", rd=5, rs=0, imm=0) == enc.set2(5, 0)
    # Review Focus: set3 rs=rd OR-trap — encoding must stay identical to enc.set3
    assert encode_form("set3", rd=10, rs=0, imm=0x2390) == enc.set3(10, 0, 0x2390)
    assert encode_form("set3", rd=5, rs=5, imm=0x23F0) == enc.set3(5, 5, 0x23F0)
    assert encode_form("st.d", rt=3, rs=1, off=0x4) == enc.st_d(3, 1, 0x4)
    assert encode_form("jump", tgt=0) == 0x95000000
    assert encode_form("call", tgt=0xB78) == enc.call(0x1D594, 0x1E10C)
    assert encode_form("b.bset", sh=16, rs=4, tgt=0x10C) == enc.b_bset(16, 4, 0, 0x10C)
    assert encode_form("b.f.0x0a", rs=0, tgt=8) == enc.b_f(0x0A, 0x100, 0x108)
    assert encode_form("shl64.i", rd=4, rs=4, shamt=6) == enc.shl64_i(4, 4, 6)
    assert encode_form("cmp38_eq32", rs=5, rt=0) == enc.cmp38_sel(2, 5, 0)
    with pytest.raises(AsmError):
        encode_form("set64", rd=5, imm=5)


def test_op0xnn_opcode_range():
    # op is 6 bits: out-of-range op must raise AsmError, not struct.error
    with pytest.raises(AsmError):
        assemble("op0x40 r1,r2,r3 imm=0x0")
    with pytest.raises(AsmError):
        encode_form("op0xff", rd=1, rs=2, rt=3, imm=0)
    assert encode_form("op0x3f", rd=1, rs=2, rt=3, imm=0) == 0xFC411800


def test_encode_form_pattern_range_gates():
    # alu.0xNN funct is 9 bits, b.{t,f}.0xN cc is 5 bits: out-of-range
    # mnemonic suffix must raise AsmError, not silently mask
    with pytest.raises(AsmError):
        encode_form("alu.0x200", rd=1, rs=2, rt=3)
    with pytest.raises(AsmError):
        encode_form("b.t.0x20", rs=0, tgt=8)
    with pytest.raises(AsmError):
        encode_form("b.f.0x20", rs=0, tgt=8)
    assert encode_form("alu.0x1ff", rd=1, rs=2, rt=3) == \
        encode_form("alu", funct=0x1ff, rd=1, rs=2, rt=3)
    assert encode_form("b.t.0x1f", rs=0, tgt=8) == \
        encode_form("b.t", cc=0x1f, rs=0, tgt=8)


def test_bare_branch_arity():
    with pytest.raises(AsmError):
        assemble("b.t 0xa,r1")
    with pytest.raises(AsmError):
        assemble("b.set r4,16")
    with pytest.raises(AsmError):
        assemble("lbl x\nb.t 0xa,r1,x,junk")
    with pytest.raises(AsmError):
        assemble("lbl x\nb.clr 4,16,x,junk")


def _fixpoint(w, off=0):
    t = disasm(w, off)
    w1 = struct.unpack(">I", assemble(t, base=off))[0]
    w2 = struct.unpack(">I", assemble(disasm(w1, off), base=off))[0]
    return w1, w2


def test_lossy_fixpoint_per_class():
    # fixpoint на КАЖДОМ lossy-классе (Architecture, полный реестр)
    cases = {
        "q-form ld.q.17": 0x5C850114,
        "q-form st.q.1e": 0x7820281C,
        "csr.w cf": (0x13 << 26) | (2 << 21) | (5 << 16) | (3 << 11) | 0x45,
        "st.i rt": (0x13 << 26) | (2 << 21) | (0x1B << 16) | (3 << 11) | 0x7FF,
        "ld.i rs-bits": (0x12 << 26) | (1 << 25) | (3 << 21) | (4 << 16) | 0xBEEF,
        "alu funct bits 9..10": (0x3F << 26) | (2 << 21) | (1 << 16) | (3 << 11) | (1 << 10) | 0x37,
        "mask32 bits 15..11": (0x32 << 26) | (2 << 21) | (1 << 16) | (0x1F << 11) | (0x15 << 5) | 0xA,
        "addi op-lsb": (0x01 << 26) | (2 << 21) | (1 << 16) | 0x123,
        "addi.hi op-lsb": (0x03 << 26) | (2 << 21) | (1 << 16) | 0x123,
        "shr funct 0x8a": (0x3F << 26) | (2 << 21) | (1 << 16) | (4 << 11) | 0x8A,
    }
    canonical = {
        "addi op-lsb": (0x00 << 26) | (2 << 21) | (1 << 16) | 0x123,
        "addi.hi op-lsb": (0x02 << 26) | (2 << 21) | (1 << 16) | 0x123,
        "shr funct 0x8a": (0x3F << 26) | (2 << 21) | (1 << 16) | (4 << 11) | 0x83,
    }
    for name, w in cases.items():
        w1, w2 = _fixpoint(w)
        assert w1 != w, name
        assert w1 == w2, name
        if name in canonical:
            assert w1 == canonical[name], name
    assert disasm(cases["addi op-lsb"], 0).startswith("addi ")
    assert disasm(cases["shr funct 0x8a"], 0) == "shr r1,r2,0x4"


def test_canon_sync_and_hi_dep_c_022_asm():
    # canon slaspec = источник истины: and.hi — конструктор 061d7e0;
    # 0x34 lo11=0x022 смёржен как :dep.c литерал (canon-sync 2026-11-02,
    # P-formula {mask 0x6, deposit 0} — live X/Y батарея B), мнемоника
    # bclr.1 удалена из канона: asm-форма и профиль-ключ сняты
    assert encode_form("and.hi", rd=7, rs=7, imm=0xF0) == 0x34E700F0
    with pytest.raises(AsmError):
        encode_form("bclr.1", rd=4, rs=4)
    with pytest.raises(AsmError):
        assemble("bclr.1 r4,r4")
    # слово покрывается raw-формой op0xNN бит-экзакт (rt-поле видимо)
    assert encode_form("op0x34", rd=4, rs=4, rt=1, imm=0x0822) == 0xD0840822
    assert encode_form("op0x34", rd=4, rs=4, rt=0, imm=0x0022) == 0xD0840022
    for src, w in (("op0x34 r4,r4,r1 imm=0x0822", 0xD0840822),
                   ("op0x34 r4,r4,zero imm=0x0022", 0xD0840022)):
        blob = assemble(src)
        assert struct.unpack(">I", blob)[0] == w, src
        assert disasm(w, 0) == src, src
        assert assemble(disasm(w, 0)) == blob, src
    # strict-гейт: and.hi — static в профилях, проходит без allow_assumed
    assert len(assemble("and.hi r7,r7,0xf0\nop0x34 r4,r4,r1 imm=0x0822",
                        profile="cx5")) == 8
    assert len(assemble("and.hi r7,r7,0xf0\nop0x34 r4,r4,r1 imm=0x0822",
                        profile="cx4lx")) == 8


def test_canon_sync_dep_c_022_exact_rt_bits():
    # golden word d0840822 (Rosetta site @0x8c124, rt=1): после снятия
    # bclr.1-рендера слово рендерится lossless catch-all op0x34 (биты
    # 15..11 читаются) — roundtrip exact, не fixpoint
    w1, w2 = _fixpoint(0xD0840822)
    assert w1 == w2 == 0xD0840822
    assert disasm(0xD0840822, 0x8C124) == "op0x34 r4,r4,r1 imm=0x0822"


def test_canon_sync_0x0c_andmsk_hi_asm_roundtrip():
    # canon-sync 2026-11-01: op 0x0c imm hi-and mask (semantics merged
    # 06be769: rd_lo = rs_lo & ((imm16<<16)|0xffff)) renamed or ->
    # andmsk.hi; goldens are stock/builder words (0x30C600FF = the s2 v5m
    # m2 word, 0x308800FF = the rd2 C-source word @0x0e436c)
    assert encode_form("andmsk.hi", rd=6, rs=6, imm=0xFF) == 0x30C600FF
    assert encode_form("andmsk.hi", rd=8, rs=4, imm=0xFF) == 0x308800FF
    for src in ("andmsk.hi r6,r6,0xff", "andmsk.hi r4,r4,0x9fff"):
        blob = assemble(src)
        text = disasm(struct.unpack(">I", blob)[0], 0)
        assert text == src, src
        assert assemble(text) == blob, src
    # strict gate: live on cx5 (fuzz5 battery V-C2R-0Cx01ff), static on
    # cx4lx/cx6dx — passes without allow_assumed on all three
    assert len(assemble("andmsk.hi r6,r6,0xff", profile="cx5")) == 4
    assert len(assemble("andmsk.hi r6,r6,0xff", profile="cx4lx")) == 4
    assert len(assemble("andmsk.hi r6,r6,0xff", profile="cx6dx")) == 4
    # the old immediate `or` spelling is gone; the register form or#alu
    # (the REAL or) keeps its name and strict-passes via the `or` key
    with pytest.raises(AsmError):
        assemble("or r6,r6,0xff")
    assert assemble("or r5,r22,r22") == struct.pack(">I", 0xFEC5B008)
    assert len(assemble("or r5,r22,r22", profile="cx5")) == 4


def test_decode_verify_rejects_mismatch(monkeypatch):
    # слово, чей decode не совпадает с запрошенной формой -> AsmError
    monkeypatch.setattr(ia, "dis",
                        lambda w, off: "op0x00 zero,zero,zero imm=0x0000")
    with pytest.raises(AsmError):
        assemble("set2 r5,zero,0x0")


def test_no_jinja2_required(monkeypatch):
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "jinja2", None)
    assert assemble("set2 r5,zero,0x0") == struct.pack(">I", 0x24050000)


def _run_cli(tmp_path, source, out_name, extra=()):
    out = tmp_path / out_name
    subprocess.run(
        [sys.executable, "-m", "scripts.irisc.irisc_asm",
         "--int-arg", "r5", "5", "--base", "0x0"] + list(extra)
        + [str(source), str(out)],
        check=True, cwd=str(REPO))
    return out.read_bytes()


def test_cli_vendored_compat(tmp_path):
    # без-шаблонный путь — безусловный (jinja2 не нужен)
    src = tmp_path / "plain.asm"
    text = "lbl setup\naddi r7, zero, 0\njump setup\n"
    src.write_text(text)
    assert _run_cli(tmp_path, src, "plain.bin") == assemble(text, base=0)


def test_cli_vendored_compat_templated(tmp_path):
    # .asm с шаблоном {{ r5 }} — вендор-форма вызова (skip-if-no-jinja2)
    pytest.importorskip("jinja2")
    src = tmp_path / "templated.asm"
    src.write_text("set64 r5, {{ r5 }}\n")
    assert _run_cli(tmp_path, src, "templated.bin") == assemble("set64 r5, 5",
                                                                base=0)


PROBES_DIR = REPO / "scripts" / "probes" / "cx4lx-detour"


def _pack_words(words):
    return b"".join(struct.pack(">I", w) for w in words)


def _dis_text(words, base):
    return "\n".join(disasm(w, base + 4 * i) for i, w in enumerate(words))


def _builder_defs(path, names):
    # селекторы билдеров — ВЕРХНЕУРОВНЕВЫЕ скрипты (parse_args/чтение образа
    # при импорте): выбираем только литеральные присваивания и нужные def
    tree = ast.parse(path.read_text())
    body = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            body.append(node)
        elif isinstance(node, ast.Assign) and isinstance(
                node.value, (ast.Constant, ast.List, ast.Dict, ast.Set)):
            if any(isinstance(t, ast.Name) and t.id in names
                   for t in node.targets):
                body.append(node)
    ns = {"sys": sys, "argparse": argparse, "irisc_dis": irisc_dis,
          "REPO": str(REPO), "GCA_REF": str(REPO)}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), "exec"),
         ns)
    return ns


def _s2_stub(version):
    sys.path.insert(0, str(REPO / "scripts" / "s2"))
    try:
        from build_s2 import stub_words, STUB
    except FileNotFoundError:
        pytest.skip("hardware.local.md hw registry not present")
    return stub_words("A", version=version), STUB


def _t2_an_emit5_stub():
    ns = _builder_defs(
        PROBES_DIR / "build_cable_t2.py",
        {"parse_args", "die", "s16", "enc_call", "enc_addi", "enc_addi_hi",
         "enc_or", "enc_ld_d", "enc_csr_r", "enc_csr_w", "emit_stub",
         "SITES", "EMIT_ADDR", "AN_WORDS_DEFAULT", "AN_MARKER_DEFAULT",
         "DEC_MARKER_DEFAULT", "BASE_MD5", "GUID", "MAC", "BUILD_ID_DATE",
         "CAVE_DC", "RET_D", "REL24_LIMIT"})
    import mlxfwutil
    try:
        ns["GUID"] = "0x" + mlxfwutil.hw("CARD_CX4LX_BCAT", "guid")
        ns["MAC"] = "0x" + mlxfwutil.hw("CARD_CX4LX_BCAT", "mac")
    except FileNotFoundError:
        pytest.skip("hardware.local.md hw registry not present")
    saved = sys.argv
    sys.argv = ["build_cable_t2.py", "--emit", "5"]
    try:
        ns["args"] = ns["parse_args"]()
    finally:
        sys.argv = saved
    ns["LINK"] = ns["args"].link_reg
    ns["VR"] = ns["args"].verdict_reg
    ns["CTXR"] = ns["args"].ctx_reg
    return [w for w, _ in ns["emit_stub"]("H-AN", ns["CAVE_DC"])], ns["CAVE_DC"]


def test_stub_recipe_s2_v5l_prefix_bitexact():
    # C2: v5l w0-w13 (build_s2 stub_words) из dis-текста — бит-экзакт
    words, stub = _s2_stub(17)
    assert assemble(_dis_text(words, stub), base=stub) == _pack_words(words)


def test_stub_recipe_s2_v5l_prefix_from_sugar():
    # C2, сахар-источник: cmp38_eq32/bare-b.f/lbl; константы из build_s2
    sys.path.insert(0, str(REPO / "scripts" / "s2"))
    try:
        from build_s2 import (FN_A, ECHO_LEN, ECHO_MAGIC, PAY_SRC_OFF_V5B,
                              RESUME_LIVE, SLOT_FILTER_V5B, SLOT_N_V5B)
    except FileNotFoundError:
        pytest.skip("hardware.local.md hw registry not present")
    src = "\n".join([
        "csr.r r3,csr0xbc",
        "addi r11,r1,0x%x" % PAY_SRC_OFF_V5B,
        "ld.w r12,r1,0x%x" % SLOT_FILTER_V5B,
        "set3 r13,zero,0x5332",
        "cmp38_eq32 r12,r13",
        "b.f 0xa,zero,w_fast",
        "st.d r12,zero,0x%x" % ECHO_MAGIC,
        "ld.w r13,r1,0x%x" % SLOT_N_V5B,
        "st.d r13,zero,0x%x" % ECHO_LEN,
        "addi r11,r1,0x%x" % PAY_SRC_OFF_V5B,
        "set3 r3,zero,0x%x" % (RESUME_LIVE & 0xFFFF),
        "set2 r3,r3,0x%x" % (RESUME_LIVE >> 16),
        "ret.r zero,r8,r11",
        "lbl w_fast",
        "jump 0x%x" % FN_A,
    ])
    words, stub = _s2_stub(17)
    assert assemble(src, base=stub) == _pack_words(words)


def test_stub_recipe_cable_t2_emit5_bitexact():
    # C2: T2 H-AN emit5-стаб (build_cable_t2 emit_stub) из dis-текста
    words, cave = _t2_an_emit5_stub()
    assert assemble(_dis_text(words, cave), base=cave) == _pack_words(words)


def test_stub_recipe_lx_v3_shellcode_bitexact():
    # C2: Lx v3 shellcode (V1_SHELLCODE+STUB, build_detour_v3) из dis-текста
    ns = _builder_defs(PROBES_DIR / "build_detour_v3.py",
                       {"CAVE_DC", "V1_SHELLCODE", "STUB"})
    words = ns["V1_SHELLCODE"] + ns["STUB"]
    assert assemble(_dis_text(words, ns["CAVE_DC"]),
                    base=ns["CAVE_DC"]) == _pack_words(words)


def test_encode_form_pos_relative_and_signed_imm():
    # enc.py-делегация: pc-относительные формы и отрицательные imm в ядре
    from scripts.irisc import enc
    assert encode_form("jump", tgt=0x1E10C, pos=0x1D594) == enc.jump(0x1D594, 0x1E10C)
    assert encode_form("call", tgt=0x1E10C, pos=0x1D594) == enc.call(0x1D594, 0x1E10C)
    assert encode_form("b.f", cc=0x0A, rs=0, tgt=0x108, pos=0x100) == enc.b_f(0x0A, 0x100, 0x108)
    assert encode_form("b.bset", sh=16, rs=4, tgt=0x10C, pos=0x100) == enc.b_bset(16, 4, 0x100, 0x10C)
    assert encode_form("st.d!", rt=1, rs=1, off=-0x28) == enc.st_d_push(-0x28)
    assert encode_form("addi", rd=4, rs=0, imm=-0x28) == enc.addi(4, 0, -0x28)
