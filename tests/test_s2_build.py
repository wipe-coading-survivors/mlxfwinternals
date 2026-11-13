import os, struct, sys, unittest

import pytest
from pathlib import Path
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "irisc"))
sys.path.insert(0, str(REPO / "scripts" / "probes"))
sys.path.insert(0, str(REPO / "scripts" / "s2"))
import mlxfwutil, enc
from iron_boot_probe import decrc
try:
    from build_s2 import build, BASE, DETOUR_DC, STUB, MAGIC, ECHO_MAGIC
except FileNotFoundError:
    pytest.skip("hardware.local.md hw registry not present",
                allow_module_level=True)


_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "serial")
_BUILT = {}
_V2CORE = None


def built(version):
    if version not in _BUILT:
        _BUILT[version] = build(
            "/tmp/opencode/s2/w%s-s2-v%s.bin" % (_WORKER, version), version=version)
    return _BUILT[version]


def det(n):
    return "/tmp/opencode/s2/w%s-det%s.bin" % (_WORKER, n)


def v2_core():
    global _V2CORE
    if _V2CORE is None:
        from build_s2 import build_v2
        _V2CORE = build_v2()
    return _V2CORE


@pytest.mark.slow
class TestS2Build(unittest.TestCase):
    def test_build_v2(self):
        buf = built(2)
        img = mlxfwutil.Image(buf, "s2v2")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))
        self.assertEqual(w(0x38D764), 0xE1806802)  # selector funct5=2 (R9)
        self.assertNotEqual(w(STUB), 0)
        self.assertEqual(w(0x38D748), 0)   # запретный вырез
        self.assertEqual(w(0x38D7DC), 0)   # фатальная зона
        self.assertEqual(w(0x1D594), 0x940DC067)  # S0 жив
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])
    def test_stub_compare_word(self):
        # v1 burnt word @0x38d764 was 0xE1806800 (funct5=0 — trap/stall,
        # live incident task-07-debug); v2 differs by exactly the funct5 bits
        from build_s2 import stub_words
        self.assertEqual(stub_words("A")[5], 0xE1806802)
        self.assertEqual(stub_words("A")[5] ^ 0xE1806800, 2)
    def test_stub_fits(self):
        from build_s2 import stub_words
        self.assertLessEqual(len(stub_words("A")), 34)
    def test_v2_golden_words_unchanged(self):
        # drift guard: v2 stub must stay byte-identical (v2/v3 images burned
        # lineage); captured from build_s2.stub_words("A") @ c5f813f
        from build_s2 import stub_words
        V2_GOLDEN = [
            0x480300BC, 0x002B00B0, 0x642C00A1, 0x240D5332, 0x21AD434D,
            0xE1806802, 0xA40A001B, 0x6C046382, 0x642D00A5, 0x6C046B86,
            0x703F0FC2, 0x6C201802, 0x6C20301A, 0x002C0020, 0x65630001,
            0x6D801801, 0x016B0004, 0x018C0004, 0x15AD0001, 0xA400FFFB,
            0x002C0020, 0x00240034, 0x642500E9, 0x642600ED, 0x240300B8,
            0x2063D7C0, 0xFC006025, 0xFC000008, 0x64230001, 0x00040000,
            0xFEC5B008, 0x64260019, 0x00210040, 0x95F80064,
        ]
        self.assertEqual(stub_words("A"), V2_GOLDEN)
    def test_deterministic(self):
        b1 = build(det(1), version=2)
        b2 = build(det(2), version=2)
        self.assertEqual(b1, b2)


class TestS2StubV4(unittest.TestCase):
    # v4 (T9): filter on DISCRIM32=0x0432434D @input[8..0xC); N@0xC;
    # r5@0x10; payload src @0x14; r6-init removed (r6 keeps site value,
    # save/restore pair kept); budget 33 <= 34.
    def test_v4_golden_words(self):
        from build_s2 import stub_words
        V4_GOLDEN = [
            0x480300BC, 0x002B00B4, 0x642C00A9, 0x240D0432, 0x21AD434D,
            0xE1806802, 0xA40A001A, 0x6C046382, 0x642D00AD, 0x6C046B86,
            0x703F0FC2, 0x6C201802, 0x6C20301A, 0x002C0020, 0x65630001,
            0x6D801801, 0x016B0004, 0x018C0004, 0x15AD0001, 0xA400FFFB,
            0x002C0020, 0x00240034, 0x642500F1, 0x240300B8, 0x2063D7BC,
            0xFC006025, 0xFC000008, 0x64230001, 0x00040000, 0xFEC5B008,
            0x64260019, 0x00210040, 0x95F80065,
        ]
        self.assertEqual(stub_words("A", version=4), V4_GOLDEN)

    def test_v4_filter_offsets_and_constant(self):
        from build_s2 import stub_words, IN_OFF
        ws = stub_words("A", version=4)
        self.assertEqual(ws[1], enc.addi(11, 1, IN_OFF + 0x14))     # src payload @input+0x14
        self.assertEqual(ws[2], enc.ld_w(12, 1, IN_OFF + 8))       # filter word @input+8
        self.assertEqual(ws[3], enc.set2(13, 0x0432))              # DISCRIM32 hi
        self.assertEqual(ws[4], enc.set3(13, 13, 0x434D))          # DISCRIM32 lo (== v2 word)
        self.assertEqual(ws[5], 0xE1806802)                        # cmp38_sel(2,12,13) eq32
        self.assertEqual(ws[8], enc.ld_w(13, 1, IN_OFF + 0xC))     # N @input+0xC
        self.assertEqual(ws[22], enc.ld_w(5, 1, IN_OFF + 0x10 + 0x40))  # r5 @input+0x10 via pushed r1

    def test_v4_no_r6_init(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=4)
        self.assertNotIn(0x642600ED, ws)  # v2 r6-init ld_w(6,r1,0xEC) gone
        # r6 appears only as save (st.d) + restore (ld.w) of the frame slot
        self.assertEqual(ws.count(enc.ld_w(6, 1, 0x18)), 1)   # restore
        self.assertEqual(ws.count(enc.st_d(6, 1, 0x18)), 1)   # save

    def test_v4_budget(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=4)
        self.assertEqual(len(ws), 33)              # 34 -> 33 (r6-init removed)
        self.assertLessEqual(len(ws), 34)          # zone 0x38d750-0x38d7d8


@pytest.mark.slow
class TestS2BuildV4(unittest.TestCase):
    def test_build_v4_image(self):
        buf = built(4)
        img = mlxfwutil.Image(buf, "s2v4")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))
        # v4 filter words at exact image offsets (stub word 1..5 @0x38d754..64)
        self.assertEqual(w(0x38D754), 0x002B00B4)  # addi r11,r1,0xB4
        self.assertEqual(w(0x38D758), 0x642C00A9)  # ld.w r12,r1,0xA8
        self.assertEqual(w(0x38D75C), 0x240D0432)  # set2 r13,0x0432
        self.assertEqual(w(0x38D760), 0x21AD434D)  # set3 r13,r13,0x434D
        self.assertEqual(w(0x38D764), 0xE1806802)  # cmp38_sel(2) eq32
        self.assertEqual(w(0x38D770), 0x642D00AD)  # ld.w r13,r1,0xAC (N)
        self.assertEqual(w(0x38D7A8), 0x642500F1)  # ld.w r5,r1,0xF0
        self.assertEqual(w(0x38D7D0), 0x95F80065)  # W_FAST tail-jump FN_A
        self.assertEqual(w(0x38D7D4), 0)           # v4 stub is 33 words: tail word zero
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v4_bakes_card_guids(self):
        buf = built(4)
        img = mlxfwutil.Image(buf, "s2v4")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac), (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_v4_diff_vs_v3_only_code_section(self):
        v3 = built(2)
        v4 = built(4)
        i3, i4 = mlxfwutil.Image(v3, "v3"), mlxfwutil.Image(v4, "v4")
        # GUID sections byte-identical (bake pipeline untouched)
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(i4.section_data(i4.find_entry(toc, t)),
                             i3.section_data(i3.find_entry(toc, t)))
        # code section (de-CRC) differs only at detour + stub zone words
        c3 = decrc(i3.section_data(i3.find_entry("ITOC", 0x03)))
        c4 = decrc(i4.section_data(i4.find_entry("ITOC", 0x03)))
        diff_words = [a for a in range(0, len(c3), 4)
                      if struct.unpack_from(">I", c3, a)[0] != struct.unpack_from(">I", c4, a)[0]]
        self.assertTrue(diff_words)
        for a in diff_words:
            self.assertTrue(a == DETOUR_DC or 0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its TOC entry CRC
        e4 = i4.find_entry("ITOC", 0x03)
        ent_lo = i4.itoc_off + 32 + e4.index * 32
        allowed = set(range(e4.addr, e4.addr + e4.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v3)) if v3[i] != v4[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_v4_deterministic(self):
        b1 = build(det(1), version=4)
        b2 = build(det(2), version=4)
        self.assertEqual(b1, b2)

class TestS2StubV5A(unittest.TestCase):
    # v5a (T16, after T15-final "no decode-proven slot"): filter/frame/
    # payload-free echo-probe stub — on EVERY 0x0932 arrival echoes 4
    # candidate 16-bit halfwords [r1+X] to CR slots, then tail-jumps FN_A.
    # Clobber: r12 only; NO csr_r (ra lives in csr0xbc until FN_A prologue).
    V5A_PROBES = ((0xA0, 0x2380), (0xAA, 0x2384), (0xAC, 0x2388), (0xB2, 0x238C))

    def test_v5a_golden_words(self):
        from build_s2 import stub_words
        V5A_GOLDEN = [
            0x642C00A1, 0x6C046382, 0x642C00AB, 0x6C046386, 0x642C00AD,
            0x6C04638A, 0x642C00B3, 0x6C04638E, 0x95F8007D,
        ]
        self.assertEqual(stub_words("A", version=5), V5A_GOLDEN)

    def test_v5a_probe_offsets_and_cr_targets(self):
        from build_s2 import stub_words, FN_A
        ws = stub_words("A", version=5)
        for i, (X, CR) in enumerate(self.V5A_PROBES):
            self.assertEqual(ws[2 * i], enc.ld_w(12, 1, X))       # ld.w r12,[r1+X]
            self.assertEqual(ws[2 * i + 1], enc.st_d(12, 0, CR))  # st.d r12,0,CR
        self.assertEqual(ws[8], enc.jump(STUB + 4 * 8, FN_A))     # tail-jump

    def test_v5a_clobber_only_r12(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=5)
        self.assertNotIn(0x480300BC, ws)                    # no csr_r (ra via csr0xbc)
        self.assertNotIn(enc.st_d_push(-0x40), ws)          # no frame push
        self.assertEqual([w for w in ws if (w >> 26) == 0x19],
                         [enc.ld_w(12, 1, X) for X, _ in self.V5A_PROBES])  # ld.w: r12 only

    def test_v5a_budget(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=5)
        self.assertEqual(len(ws), 9)
        self.assertLessEqual(len(ws), 34)                   # zone 0x38d750-0x38d7d8

    def test_v5a_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=5)


@pytest.mark.slow
class TestS2BuildV5A(unittest.TestCase):
    def test_build_v5a_image(self):
        buf = built(5)
        img = mlxfwutil.Image(buf, "s2v5a")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour unchanged
        self.assertEqual(w(0x38D750), 0x642C00A1)  # ld.w r12,r1,0xa0
        self.assertEqual(w(0x38D754), 0x6C046382)  # st.d r12,0,0x2380
        self.assertEqual(w(0x38D75C), 0x6C046386)  # st.d r12,0,0x2384
        self.assertEqual(w(0x38D764), 0x6C04638A)  # st.d r12,0,0x2388
        self.assertEqual(w(0x38D76C), 0x6C04638E)  # st.d r12,0,0x238c
        self.assertEqual(w(0x38D770), 0x95F8007D)  # jump FN_A
        # zone tail after the 9 stub words stays zero (stock zeros untouched)
        for a in range(STUB + 36, STUB + 4 * 34, 4):
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5a_bakes_card_guids(self):
        buf = built(5)
        img = mlxfwutil.Image(buf, "s2v5a")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac), (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_v5a_diff_vs_v4_confined_to_stub_zone(self):
        v4 = built(4)
        v5 = built(5)
        i4, i5 = mlxfwutil.Image(v4, "v4"), mlxfwutil.Image(v5, "v5a")
        # GUID sections byte-identical (bake pipeline untouched)
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(i5.section_data(i5.find_entry(toc, t)),
                             i4.section_data(i4.find_entry(toc, t)))
        # detour word identical; code diffs confined to stub zone words
        c4 = decrc(i4.section_data(i4.find_entry("ITOC", 0x03)))
        c5 = decrc(i5.section_data(i5.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", c4, DETOUR_DC)[0],
                         struct.unpack_from(">I", c5, DETOUR_DC)[0])
        diff_words = [a for a in range(0, len(c4), 4)
                      if struct.unpack_from(">I", c4, a)[0] != struct.unpack_from(">I", c5, a)[0]]
        self.assertTrue(diff_words)
        for a in diff_words:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its TOC entry CRC
        e5 = i5.find_entry("ITOC", 0x03)
        ent_lo = i5.itoc_off + 32 + e5.index * 32
        allowed = set(range(e5.addr, e5.addr + e5.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v4)) if v4[i] != v5[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_v5a_deterministic(self):
        b1 = build(det(1), version=5)
        b2 = build(det(2), version=5)
        self.assertEqual(b1, b2)


class TestS2StubV5B(unittest.TestCase):
    # v5b (T18, consumes T17 verdict): MAGIC16 filter on the LIVE-PROVEN
    # slot [r1+0xaa] (= input[0x12..0x14), 16-bit BE, zext echo semantics);
    # N = input[0xC..0xE) via [r1+0xa4]; copy-loop as v2/v4 SHAPE but with
    # TWO ld.w/st.w halfword pairs per word (ld.w/st.w are 16-bit ops:
    # slaspec *[ram]:2 + T17 live) — the v2/v4 single-pair/addi-4 loop would
    # copy every other halfword; gauntlet (mandatory, T17-reconciliation:
    # k>=0x15 landing is a hypothesis) checks the first copied halfword
    # against 0x2407 (hi halfword of the marker word[0]) before any jump;
    # miss -> clean stock completion (pop + tail-jump FN_A), garbage NEVER
    # executes.  No r4/r5/r6 init (marker-lite needs none) => clobber is
    # exactly the base-allowed set {r3,r11,r12,r13}.  Review fix (1bffa34):
    # N loads into r13 (the subsi loop counter — r12 was overwritten by the
    # dst pointer before the loop) and a 3-word stub-side N guard
    # (set3 const 4 / cmp38 eq32 / b_f.cc0A -> W_FAST) sits between the N
    # echo and the frame push: [r1+0xa4] is hypothesis-grade, so garbage N
    # must never reach the copy loop (clean fast exit, filter-miss style).
    def test_v5b_golden_words(self):
        from build_s2 import stub_words
        V5B_GOLDEN = [
            0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
            0xA40A001B, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x200C0004,
            0xE1A06002, 0xA40A0015, 0x703F0FC2, 0x6C201802, 0x002C0020,
            0x65630001, 0x6D801801, 0x65630003, 0x6D801803, 0x016B0004,
            0x018C0004, 0x15AD0001, 0xA400FFF9, 0x642C0021, 0x200D2407,
            0xE1806802, 0xA40A0005, 0x002C0020, 0x240300B8, 0x2063D7CC,
            0xFC006025, 0x00210040, 0x95F80065,
        ]
        self.assertEqual(stub_words("A", version=6), V5B_GOLDEN)

    def test_v5b_filter_words(self):
        from build_s2 import stub_words, SLOT_FILTER_V5B, SLOT_N_V5B, PAY_SRC_OFF_V5B
        ws = stub_words("A", version=6)
        self.assertEqual(ws[1], enc.addi(11, 1, PAY_SRC_OFF_V5B))  # src = [r1+0xac]
        self.assertEqual(PAY_SRC_OFF_V5B, 0xAC)                    # T17: k=0x14
        self.assertEqual(ws[2], enc.ld_w(12, 1, SLOT_FILTER_V5B))  # [r1+0xaa] slot
        self.assertEqual(SLOT_FILTER_V5B, 0xAA)
        self.assertEqual(ws[3], enc.set3(13, 0, 0x5332))         # 1-word const
        self.assertEqual(ws[4], 0xE1806802)                      # cmp38_sel(2)
        self.assertEqual(ws[6], enc.st_d(12, 0, 0x2380))         # echo MAGIC16
        self.assertEqual(ws[7], enc.ld_w(13, 1, SLOT_N_V5B))     # N -> r13 (loop ctr)
        self.assertEqual(SLOT_N_V5B, 0xA4)
        self.assertEqual(ws[8], enc.st_d(13, 0, 0x2384))         # echo N from r13

    def test_v5b_loop_counter_dataflow_matches_n_slot(self):
        # review Critical-1 lesson: the golden list was derived from the
        # implementation and could not catch a dataflow break.  Decode the
        # stub (irisc_dis, not frozen words): the ld.w from [r1+0xa4] must
        # fill the SAME register the loop subsi decrements, and nothing in
        # between may overwrite that register.
        from build_s2 import stub_words, SLOT_N_V5B
        import irisc_dis
        ws = stub_words("A", version=6)
        dec = [irisc_dis.dis(w, STUB + 4 * i) for i, w in enumerate(ws)]
        n_ld = [i for i, s in enumerate(dec)
                if s.startswith("ld.w ") and s.endswith("r1,0x%x" % SLOT_N_V5B)]
        self.assertEqual(len(n_ld), 1, "exactly one N load from [r1+0x%x]" % SLOT_N_V5B)
        n_reg = dec[n_ld[0]].split()[1].split(",")[0]
        subsi = [i for i, s in enumerate(dec) if s.startswith("subsi ")]
        self.assertEqual(len(subsi), 1, "exactly one subsi (loop counter)")
        self.assertTrue(dec[subsi[0]].startswith("subsi %s," % n_reg),
                        "subsi counts %r but N was loaded into %r"
                        % (dec[subsi[0]], n_reg))
        for i in range(n_ld[0] + 1, subsi[0]):
            s = dec[i]
            self.assertFalse(s.startswith(("set", "addi", "subsi", "subi", "ld.", "csr.r",
                                           "or ", "and ", "xor ", "alu."))
                            and s.split()[1].split(",")[0] == n_reg,
                            "%r overwrites the N register %s before the loop" % (s, n_reg))

    def test_v5b_n_guard_branch_exits_to_w_fast(self):
        # review Important-2: stub-side N bound.  Between the N echo and the
        # frame push there MUST be a guard (set3 const 4 / cmp38 eq32 /
        # b_f.cc0A -> W_FAST) so a garbage N never reaches the copy loop.
        from build_s2 import stub_words, FN_A, SLOT_N_V5B
        import irisc_dis
        ws = stub_words("A", version=6)
        dec = [irisc_dis.dis(w, STUB + 4 * i) for i, w in enumerate(ws)]
        tail = [i for i, s in enumerate(dec) if s == "jump 0x%x" % FN_A]
        self.assertEqual(len(tail), 1)
        w_fast = STUB + 4 * tail[0]
        push = [i for i, s in enumerate(dec) if s.startswith("st.d!")]
        self.assertEqual(len(push), 1)
        n_echo = [i for i, s in enumerate(dec)
                  if s.startswith("st.d ") and s.endswith(",0x2384")]
        self.assertEqual(len(n_echo), 1)
        guard = [i for i in range(n_echo[0] + 1, push[0])
                 if dec[i].startswith("b.f.0xa ") and dec[i].endswith(",0x%x" % w_fast)]
        self.assertEqual(len(guard), 1, "N-guard b.f.cc0A -> W_FAST missing")
        gi = guard[0]
        self.assertEqual((ws[gi - 1] >> 26), 0x38)           # cmp38
        self.assertEqual(ws[gi - 1] & 0x7FF, 2)              # funct5=2 (eq32)
        self.assertEqual((ws[gi - 2] >> 26), 0x08)           # set3 (1-word const)
        self.assertEqual(ws[gi - 2] & 0xFFFF, 4)             # bound == 4 (PAYLOAD_MAX)
        n_ld = [i for i, s in enumerate(dec)
                if s.startswith("ld.w ") and s.endswith("r1,0x%x" % SLOT_N_V5B)]
        self.assertEqual(len(n_ld), 1)
        n_reg_no = int(dec[n_ld[0]].split()[1].split(",")[0][1:])
        self.assertEqual((ws[gi - 1] >> 21) & 0x1F, n_reg_no,   # cmp38 rs == N reg
                         "guard does not compare the N register")
        self.assertEqual((ws[gi - 1] >> 11) & 0x1F,
                         (ws[gi - 2] >> 16) & 0x1F,             # cmp38 rt == const reg
                         "guard does not compare against the bound constant")

    def test_v5b_copy_loop_two_halfword_pairs(self):
        # 16-bit ld.w/st.w: a contiguous 32-bit word needs BOTH halfwords
        # (offsets 0 and 2) per addi-4 iteration (T17 live width proof)
        from build_s2 import stub_words
        ws = stub_words("A", version=6)
        self.assertEqual(ws[15], enc.ld_w(3, 11, 0x0))
        self.assertEqual(ws[16], enc.st_w(3, 12, 0x0))
        self.assertEqual(ws[17], enc.ld_w(3, 11, 0x2))
        self.assertEqual(ws[18], enc.st_w(3, 12, 0x2))
        self.assertEqual(ws[19], enc.addi(11, 11, 4))
        self.assertEqual(ws[20], enc.addi(12, 12, 4))
        self.assertEqual(ws[21], enc.subsi(13, 13, 1))
        self.assertEqual(ws[22], enc.b_f(0x00, STUB + 4 * 22, STUB + 4 * 15))

    def test_v5b_gauntlet_words(self):
        from build_s2 import stub_words, FN_A
        ws = stub_words("A", version=6)
        resume, w_fast = STUB + 4 * 31, STUB + 4 * 32
        self.assertEqual(ws[23], enc.ld_w(12, 1, 0x20))       # copied word[0].hi
        self.assertEqual(ws[24], enc.set3(13, 0, 0x2407))     # marker-lite word0 hi
        self.assertEqual(ws[25], 0xE1806802)                  # cmp38_sel(2)
        self.assertEqual(ws[26], enc.b_f(0x0A, STUB + 4 * 26, resume))  # miss -> clean
        self.assertEqual(ws[27], enc.addi(12, 1, 0x20))       # payload ptr
        self.assertEqual(ws[28], enc.set2(3, 0x00B8))         # resume live-PC
        self.assertEqual(ws[29], enc.set3(3, 3, 0xD7CC))      # 0x800000+0x38d7cc
        self.assertEqual(ws[30], enc.ret_r(0, 0, 12))         # jump payload
        self.assertEqual(ws[31], enc.addi(1, 1, 0x40))        # pop frame
        self.assertEqual(ws[32], enc.jump(w_fast, FN_A))      # W_FAST tail-jump
        self.assertEqual(ws[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))  # filter -> fast

    def test_v5b_no_r4_r5_r6_touch(self):
        from build_s2 import stub_words
        import irisc_dis
        ws = stub_words("A", version=6)
        dec = [irisc_dis.dis(w, 0) for w in ws]
        self.assertTrue(all("r4" not in s and "r5" not in s and "r6" not in s
                            for s in dec))
        # no r4 result-buffer, no r5/r6 init, no r6 save/restore (untouched)
        self.assertNotIn(enc.addi(4, 1, 0x34), ws)
        self.assertNotIn(enc.st_d(6, 1, 0x18), ws)
        self.assertNotIn(enc.ld_w(6, 1, 0x18), ws)
        # r12 is the only ld.w destination outside {r3} (loop temp): filter/N/gauntlet
        lds = [w for w in ws if (w >> 26) == 0x19]
        self.assertEqual(lds, [enc.ld_w(12, 1, 0xAA), enc.ld_w(13, 1, 0xA4)]
                         + [enc.ld_w(3, 11, 0), enc.ld_w(3, 11, 2)]
                         + [enc.ld_w(12, 1, 0x20)])

    def test_v5b_budget(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=6)
        self.assertEqual(len(ws), 33)              # 30 -> 33 (+3 N-guard words)
        self.assertLessEqual(len(ws), 34)          # zone 0x38d750-0x38d7d8

    def test_v5b_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=6)


@pytest.mark.slow
class TestS2BuildV5B(unittest.TestCase):
    def test_build_v5b_image(self):
        buf = built(6)
        img = mlxfwutil.Image(buf, "s2v5b")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour unchanged
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D758), 0x642C00AB)  # ld.w r12,r1,0xaa (filter slot)
        self.assertEqual(w(0x38D75C), 0x200D5332)  # set3 r13,zero,0x5332
        self.assertEqual(w(0x38D760), 0xE1806802)  # cmp38_sel(2) eq32
        self.assertEqual(w(0x38D764), 0xA40A001B)  # b.f.cc0A -> W_FAST
        self.assertEqual(w(0x38D768), 0x6C046382)  # st.d r12,0,0x2380 (echo magic)
        self.assertEqual(w(0x38D76C), 0x642D00A5)  # ld.w r13,r1,0xa4 (N -> counter)
        self.assertEqual(w(0x38D770), 0x6C046B86)  # st.d r13,0,0x2384 (echo N)
        self.assertEqual(w(0x38D774), 0x200C0004)  # set3 r12,zero,4 (N-guard bound)
        self.assertEqual(w(0x38D778), 0xE1A06002)  # cmp38_sel(2,13,12) N eq32 4
        self.assertEqual(w(0x38D77C), 0xA40A0015)  # b.f.cc0A -> W_FAST (N guard)
        self.assertEqual(w(0x38D794), 0x65630003)  # ld.w r3,r11,0x2 (2nd halfword)
        self.assertEqual(w(0x38D798), 0x6D801803)  # st.w r3,r12,0x2
        self.assertEqual(w(0x38D7AC), 0x642C0021)  # gauntlet read [r1+0x20]
        self.assertEqual(w(0x38D7B0), 0x200D2407)  # set3 r13,zero,0x2407
        self.assertEqual(w(0x38D7B8), 0xA40A0005)  # b.f.cc0A -> RESUME (clean)
        self.assertEqual(w(0x38D7C8), 0xFC006025)  # ret.r -> payload
        self.assertEqual(w(0x38D7CC), 0x00210040)  # RESUME pop
        self.assertEqual(w(0x38D7D0), 0x95F80065)  # W_FAST jump FN_A
        for a in range(STUB + 4 * 33, STUB + 4 * 34, 4):   # zone tail: stock zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5b_bakes_card_guids(self):
        buf = built(6)
        img = mlxfwutil.Image(buf, "s2v5b")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac), (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_v5b_diff_vs_v5a_confined_to_stub_zone(self):
        v5a = built(5)
        v5b = built(6)
        ia, ib = mlxfwutil.Image(v5a, "v5a"), mlxfwutil.Image(v5b, "v5b")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ib.section_data(ib.find_entry(toc, t)),
                             ia.section_data(ia.find_entry(toc, t)))
        ca = decrc(ia.section_data(ia.find_entry("ITOC", 0x03)))
        cb = decrc(ib.section_data(ib.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", ca, DETOUR_DC)[0],
                         struct.unpack_from(">I", cb, DETOUR_DC)[0])
        diff_words = [a for a in range(0, len(ca), 4)
                      if struct.unpack_from(">I", ca, a)[0] != struct.unpack_from(">I", cb, a)[0]]
        self.assertTrue(diff_words)
        for a in diff_words:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        eb = ib.find_entry("ITOC", 0x03)
        ent_lo = ib.itoc_off + 32 + eb.index * 32
        allowed = set(range(eb.addr, eb.addr + eb.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5a)) if v5a[i] != v5b[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_v5b_deterministic(self):
        b1 = build(det(1), version=6)
        b2 = build(det(2), version=6)
        self.assertEqual(b1, b2)


class TestS2StubV5C(unittest.TestCase):
    # v5c-A (T20, plan addendum 4694434): frame-only diagnostic probe for the
    # write-path host-freeze (task-19-debug2: gauntlet-neg froze 2/2, RC1 =
    # zero-precedent forms).  Stub = v5b prefix words 0-11 (live-proven: G-echo
    # ran words 0-8 clean, the freeze runs passed the guard 9-11; branch
    # immediates retargeted to the new W_FAST) -> M0 -> push -> M1 -> pop ->
    # M2 -> jump FN_A.  Stage markers: set3 r12,zero,VAL + st.d r12,zero,
    # 0x238C (VAL 1/2/3) — the st.d word is the v5a-live byte-exact CR-0x238C
    # probe word; set3 rd=12 is stock-precedented (362 sites) AND v5b-live
    # (guard const 0x200C0004 ran clean).  NO saves, NO copy loop, NO
    # gauntlet, NO payload.  RC1 lesson: every word must carry a precedent
    # (stock-exact or live-proven) — asserted below word by word.
    def test_v5cA_golden_words(self):
        from build_s2 import stub_words
        V5CA_GOLDEN = [
            0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
            0xA40A000F, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x200C0004,
            0xE1A06002, 0xA40A0009, 0x200C0001, 0x6C04638E, 0x703F0FC2,
            0x200C0002, 0x6C04638E, 0x00210040, 0x200C0003, 0x6C04638E,
            0x95F80071,
        ]
        self.assertEqual(stub_words("A", version=7), V5CA_GOLDEN)

    def test_v5cA_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5cA"), stub_words("A", version=7))

    def test_v5cA_prefix_words_identical_to_v5b(self):
        # words 0-11 are v5b's live-proven prefix; only the two b_f.cc0A
        # immediates differ (retargeted W_FAST), so all OTHER words must be
        # byte-identical to the v5b golden list.
        from build_s2 import stub_words
        wa, wb = stub_words("A", version=7), stub_words("A", version=6)
        self.assertEqual(len(wb), 33)
        for i in list(range(0, 5)) + list(range(6, 11)):
            self.assertEqual(wa[i], wb[i], f"prefix word {i} drifted from v5b")
        # branch slots keep the same form (b_f.cc0A), new immediates
        for i in (5, 11):
            self.assertEqual(wa[i] >> 26, 0x29)
            self.assertEqual((wa[i] >> 16) & 0x1F, 0x0A)
            self.assertNotEqual(wa[i], wb[i])

    def test_v5cA_branches_target_w_fast(self):
        from build_s2 import stub_words, FN_A
        ws = stub_words("A", version=7)
        w_fast = STUB + 4 * 20                        # word 20 = jump FN_A
        self.assertEqual(ws[20], enc.jump(w_fast, FN_A))
        self.assertEqual(ws[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))
        self.assertEqual(ws[11], enc.b_f(0x0A, STUB + 4 * 11, w_fast))

    def test_v5cA_stage_markers(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=7)
        cr_word = enc.st_d(12, 0, 0x238C)
        self.assertEqual(cr_word, 0x6C04638E)         # v5a-live byte-exact
        for idx, val in ((12, 1), (15, 2), (18, 3)):  # M0/M1/M2
            self.assertEqual(ws[idx], enc.set3(12, 0, val))
            self.assertEqual(ws[idx + 1], cr_word)
        # marker register fields == v5b live guard-const form (set3 r12,zero,imm)
        for idx, _ in ((12, 1), (15, 2), (18, 3)):
            self.assertEqual((ws[idx] >> 26), 0x08)
            self.assertEqual(((ws[idx] >> 21) & 0x1F), 0)   # rs = zero
            self.assertEqual(((ws[idx] >> 16) & 0x1F), 12)  # rd = r12

    def test_v5cA_frame_words_stock_exact(self):
        # (a)-class precedents: stock-identical words (185/185 exact sites,
        # re-verified by the T20 stock scan; cf. task-19-debug2 Phase 2.1)
        from build_s2 import stub_words
        ws = stub_words("A", version=7)
        self.assertEqual(ws[14], 0x703F0FC2)          # st.d! r1,r1,-0x40 push
        self.assertEqual(ws[17], 0x00210040)          # addi r1,r1,0x40 pop

    def test_v5cA_every_word_has_precedent(self):
        # RC1 lesson (task-19-debug2 review): no zero-precedent forms in a
        # diagnostic stub.  Each word must be either (a) stock-identical or
        # (b) live-proven (v5a/v5b byte-exact or a v5b-live form with a
        # recomputed site-local immediate: b_f/jump) or (c) a marker word
        # whose FORM (op/rs/rd) is stock-precedented (set3 rd=12: 362 stock
        # sites) and v5b-live (0x200C0004 ran clean in G-echo).
        from build_s2 import stub_words
        ws = stub_words("A", version=7)
        v5b = set(stub_words("A", version=6))
        v5a = set(stub_words("A", version=5))
        stock_exact = {0x703F0FC2, 0x00210040, 0x480300BC}  # push/pop/csr.r
        v5a_live_marker = 0x6C04638E                       # st.d r12,0,0x238C
        marker_forms = {enc.set3(12, 0, v) for v in (1, 2, 3)}
        for i, w in enumerate(ws):
            ok = (w in v5b or w in v5a or w in stock_exact
                  or w == v5a_live_marker or w in marker_forms
                  or (w >> 26) == 0x29                      # b_f.cc0A retarget
                  or (w >> 26) == 0x25)                     # jump FN_A retarget
            self.assertTrue(ok, f"word {i} 0x{w:08x} has no precedent")
        self.assertEqual(len([w for w in ws if (w >> 26) == 0x29]), 2)

    def test_v5cA_no_saves_no_copy_no_gauntlet_no_payload(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=7)
        self.assertNotIn(enc.st_d(3, 1, 0x00), ws)     # no ra-save
        self.assertNotIn(enc.st_w(3, 12, 0x0), ws)     # no copy loop
        self.assertNotIn(enc.subsi(13, 13, 1), ws)     # no loop counter
        self.assertNotIn(enc.ld_w(12, 1, 0x20), ws)    # no gauntlet read
        self.assertNotIn(enc.set2(3, 0x00B8), ws)      # no resume-PC block
        self.assertNotIn(enc.ret_r(0, 0, 12), ws)      # no payload jump
        self.assertEqual(ws.count(enc.st_d_push(-0x40)), 1)   # exactly one push
        self.assertEqual(ws.count(enc.addi(1, 1, 0x40)), 1)   # exactly one pop

    def test_v5cA_clobber_confined(self):
        from build_s2 import stub_words
        import irisc_dis
        ws = stub_words("A", version=7)
        dec = [irisc_dis.dis(w, 0) for w in ws]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5cA_budget(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=7)
        self.assertEqual(len(ws), 21)
        self.assertLessEqual(len(ws), 34)              # zone 0x38d750-0x38d7d8

    def test_v5cA_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=7)


@pytest.mark.slow
class TestS2BuildV5C(unittest.TestCase):
    def test_build_v5cA_image(self):
        buf = built(7)
        img = mlxfwutil.Image(buf, "s2v5cA")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D758), 0x642C00AB)  # ld.w r12,r1,0xaa (filter)
        self.assertEqual(w(0x38D768), 0x6C046382)  # st.d r12,0,0x2380 (echo)
        self.assertEqual(w(0x38D77C), 0xA40A0009)  # N-guard b.f.cc0A -> W_FAST
        self.assertEqual(w(0x38D780), 0x200C0001)  # M0: set3 r12,zero,1
        self.assertEqual(w(0x38D784), 0x6C04638E)  # M0: st.d r12,0,0x238c
        self.assertEqual(w(0x38D788), 0x703F0FC2)  # push st.d! r1,r1,-0x40
        self.assertEqual(w(0x38D78C), 0x200C0002)  # M1: set3 r12,zero,2
        self.assertEqual(w(0x38D790), 0x6C04638E)  # M1: st.d r12,0,0x238c
        self.assertEqual(w(0x38D794), 0x00210040)  # pop addi r1,r1,0x40
        self.assertEqual(w(0x38D798), 0x200C0003)  # M2: set3 r12,zero,3
        self.assertEqual(w(0x38D79C), 0x6C04638E)  # M2: st.d r12,0,0x238c
        self.assertEqual(w(0x38D7A0), 0x95F80071)  # W_FAST jump FN_A
        for a in range(STUB + 4 * 21, STUB + 4 * 34, 4):   # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5cA_bakes_card_guids(self):
        buf = built(7)
        img = mlxfwutil.Image(buf, "s2v5cA")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac), (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_v5cA_diff_vs_v5b_confined_to_stub_zone(self):
        v5b = built(6)
        v5c = built(7)
        ib, ic = mlxfwutil.Image(v5b, "v5b"), mlxfwutil.Image(v5c, "v5cA")
        # GUID sections byte-identical (bake pipeline untouched)
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ic.section_data(ic.find_entry(toc, t)),
                             ib.section_data(ib.find_entry(toc, t)))
        # detour word identical; code diffs confined to stub zone words
        cb = decrc(ib.section_data(ib.find_entry("ITOC", 0x03)))
        cc = decrc(ic.section_data(ic.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", cb, DETOUR_DC)[0],
                         struct.unpack_from(">I", cc, DETOUR_DC)[0])
        diff_words = [a for a in range(0, len(cb), 4)
                      if struct.unpack_from(">I", cb, a)[0] != struct.unpack_from(">I", cc, a)[0]]
        self.assertTrue(diff_words)
        for a in diff_words:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its TOC entry CRC
        ec = ic.find_entry("ITOC", 0x03)
        ent_lo = ic.itoc_off + 32 + ec.index * 32
        allowed = set(range(ec.addr, ec.addr + ec.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5b)) if v5b[i] != v5c[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_v5cA_deterministic(self):
        b1 = build(det(1), version=7)
        b2 = build(det(2), version=7)
        self.assertEqual(b1, b2)


class TestS2StubV5CB(unittest.TestCase):
    # v5c-B (T21, task-19-debug2 §v5c-B purpose + task-20 Phase-2 ruling):
    # the FULL v5b write path under stage markers — EVERY suspect word
    # verbatim (ra-save, dst-init addi, copy loop ld.w/st.w x2 + addi strides
    # + subsi + back-edge, gauntlet ld/set3/cmp38/b_f), prefix == v5cA/v5b.
    # Budget resolution (hard 34-word zone): the brief's maximal design
    # (markers M0..M4 + gauntlet + payload-jump block + counter = 43 words)
    # cannot fit; dropped as redundant or dead-on-the-test-frame: M0 (push
    # live-proven innocent by v5c-A x2), M4 (pop innocent), M3 + payload
    # block (match-path only — THE test frame is gauntlet-neg = miss, and
    # payload words never executed in the freeze runs).  Kept: M1=2 after
    # the save, M2=3 after the copy loop (both -> CR 0x238C, values match
    # the brief's interpretation semantics), in-loop counter snapshot
    # st.d r13,zero,0x2388 after the 2nd st.w.  Exactly 34 words: freeze ->
    # CR 0x238C <2 = saves, =2 copy-loop (+0x2388 iteration detail), =3
    # gauntlet; clean completion = survived (RC1 write-path refuted).
    V5CB_GOLDEN = [
        0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
        0xA40A001C, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x200C0004,
        0xE1A06002, 0xA40A0016, 0x703F0FC2, 0x6C201802, 0x200C0002,
        0x6C04638E, 0x002C0020, 0x65630001, 0x6D801801, 0x65630003,
        0x6D801803, 0x6C046B8A, 0x016B0004, 0x018C0004, 0x15AD0001,
        0xA400FFF8, 0x200C0003, 0x6C04638E, 0x642C0021, 0x200D2407,
        0xE1806802, 0xA40A0001, 0x00210040, 0x95F80064,
    ]

    def test_v5cB_golden_words(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("A", version=8), self.V5CB_GOLDEN)

    def test_v5cB_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5cB"), stub_words("A", version=8))

    def test_v5cB_prefix_identical_to_v5cA(self):
        # prefix words 0-11 are the v5cA/v5b live-proven prefix; only the
        # two b_f.cc0A immediates differ (retargeted to the new W_FAST).
        from build_s2 import stub_words
        wa, wb = stub_words("A", version=8), stub_words("A", version=7)
        self.assertEqual(len(wb), 21)
        for i in list(range(0, 5)) + list(range(6, 11)):
            self.assertEqual(wa[i], wb[i], f"prefix word {i} drifted from v5cA")
        for i in (5, 11):
            self.assertEqual(wa[i] >> 26, 0x29)             # b_f form kept
            self.assertEqual((wa[i] >> 16) & 0x1F, 0x0A)    # cc0A kept
            self.assertNotEqual(wa[i], wb[i])               # imm retargeted

    def test_v5cB_suspects_verbatim_v5b(self):
        # THE diagnostic contract: suspect words byte-identical to v5b at
        # their (shifted) positions — catch them red-handed, not fix them.
        # v5b -> v5cB index map: push 12->12, save 13->13, dst-init 14->16,
        # loop body 15..18 -> 17..20, strides+subsi 19..21 -> 22..24,
        # gauntlet 23..25 -> 28..30 (counter inserted at 21, marker pair at
        # 14-15 and 26-27, gauntlet b_f 26 -> 31 retargeted to pop).
        from build_s2 import stub_words
        wa, wb = stub_words("A", version=8), stub_words("A", version=6)
        for va, vb in ((12, 12), (13, 13), (16, 14), (17, 15), (18, 16),
                       (19, 17), (20, 18), (22, 19), (23, 20), (24, 21),
                       (28, 23), (29, 24), (30, 25), (32, 31)):
            self.assertEqual(wa[va], wb[vb],
                             f"suspect word v5cB[{va}] != v5b[{vb}] {wb[vb]:08x}")
        # back-edge: same form/target-class, immediate -7 -> -8 (counter
        # word inserted into the loop body; task-19-debug2 §v5c-B documents
        # exactly this shift)
        self.assertEqual(wb[22], 0xA400FFF9)
        self.assertEqual(wa[25], 0xA400FFF8)
        self.assertEqual(wa[25] ^ wb[22], 1)
        # gauntlet miss branch: v5b form, immediate retargeted to the pop
        self.assertEqual((wa[31] >> 26), 0x29)
        self.assertEqual((wa[31] >> 16) & 0x1F, 0x0A)

    def test_v5cB_stage_markers(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=8)
        cr_word = enc.st_d(12, 0, 0x238C)
        self.assertEqual(cr_word, 0x6C04638E)         # v5a-live byte-exact
        for idx, val in ((14, 2), (26, 3)):           # M1 (post-save), M2 (post-copy)
            self.assertEqual(ws[idx], enc.set3(12, 0, val))
            self.assertEqual(ws[idx + 1], cr_word)
            self.assertEqual((ws[idx] >> 26), 0x08)           # set3
            self.assertEqual(((ws[idx] >> 21) & 0x1F), 0)     # rs = zero
            self.assertEqual(((ws[idx] >> 16) & 0x1F), 12)    # rd = r12
        # M1 sits between the save and the dst-init; M2 between the
        # back-edge and the gauntlet read
        self.assertEqual(ws[13], enc.st_d(3, 1, 0x00))        # save @13
        self.assertEqual(ws[16], enc.addi(12, 1, 0x20))       # dst-init @16
        self.assertEqual(ws[25] >> 26, 0x29)                  # back-edge @25
        self.assertEqual(ws[28], enc.ld_w(12, 1, 0x20))       # gauntlet @28

    def test_v5cB_counter_snapshot(self):
        # in-loop iteration-counter snapshot: st.d r13,zero,0x2388 after
        # the 2nd st.w (values 4/3/2/1 across the 4 iterations), before
        # the addi strides; rt=13/rs=zero = the v5b-live N-echo word form
        # (0x6C046B86 ran in every live magic run), CR 0x2388 = the
        # v5a-live probe-3 target word class (0x6C04638A).
        from build_s2 import stub_words
        ws = stub_words("A", version=8)
        self.assertEqual(ws[21], enc.st_d(13, 0, 0x2388))
        self.assertEqual(ws[21], 0x6C046B8A)
        self.assertEqual(ws[20], enc.st_w(3, 12, 0x2))        # 2nd st.w before
        self.assertEqual(ws[22], enc.addi(11, 11, 4))         # 1st stride after
        donor = enc.st_d(13, 0, 0x2384)                       # v5b-live N-echo
        self.assertEqual(donor, 0x6C046B86)
        self.assertIn(donor, ws[:12])                         # prefix keeps it
        for w in (ws[21], donor):                             # same field class
            self.assertEqual((w >> 26), 0x1B)
            self.assertEqual(((w >> 21) & 0x1F), 0)           # rs = zero
            self.assertEqual(((w >> 11) & 0x1F), 13)          # rt = r13

    def test_v5cB_branches(self):
        from build_s2 import stub_words, FN_A
        ws = stub_words("A", version=8)
        w_fast = STUB + 4 * 33                        # word 33 = jump FN_A
        self.assertEqual(len(ws), 34)
        self.assertEqual(ws[33], enc.jump(w_fast, FN_A))
        self.assertEqual(ws[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))   # filter
        self.assertEqual(ws[11], enc.b_f(0x0A, STUB + 4 * 11, w_fast))  # N-guard
        self.assertEqual(ws[25], enc.b_f(0x00, STUB + 4 * 25, STUB + 4 * 17))  # back-edge
        self.assertEqual(ws[31], enc.b_f(0x0A, STUB + 4 * 31, STUB + 4 * 32))  # gauntlet miss -> pop

    def test_v5cB_loop_counter_dataflow(self):
        # v5b review Critical-1 lesson: the ld.w from [r1+0xa4] must fill
        # the SAME register the loop subsi decrements, and nothing in
        # between may overwrite it (markers write r12; the counter st.d
        # only READS r13).
        from build_s2 import stub_words, SLOT_N_V5B
        import irisc_dis
        ws = stub_words("A", version=8)
        dec = [irisc_dis.dis(w, STUB + 4 * i) for i, w in enumerate(ws)]
        n_ld = [i for i, s in enumerate(dec)
                if s.startswith("ld.w ") and s.endswith("r1,0x%x" % SLOT_N_V5B)]
        self.assertEqual(len(n_ld), 1)
        n_reg = dec[n_ld[0]].split()[1].split(",")[0]
        subsi = [i for i, s in enumerate(dec) if s.startswith("subsi ")]
        self.assertEqual(len(subsi), 1)
        self.assertTrue(dec[subsi[0]].startswith("subsi %s," % n_reg))
        for i in range(n_ld[0] + 1, subsi[0]):
            s = dec[i]
            self.assertFalse(s.startswith(("set", "addi", "subsi", "subi", "ld.", "csr.r",
                                           "or ", "and ", "xor ", "alu."))
                            and s.split()[1].split(",")[0] == n_reg,
                            "%r overwrites the N register %s before the loop" % (s, n_reg))

    def test_v5cB_no_payload_block(self):
        # no payload jump (match path falls through to the pop too — the
        # payload never executes on any v5cB frame), no resume-PC block
        from build_s2 import stub_words
        ws = stub_words("A", version=8)
        self.assertNotIn(enc.ret_r(0, 0, 12), ws)
        self.assertNotIn(enc.ret_r(0, 0, 3), ws)
        self.assertTrue(all((w >> 26) != 0x3F for w in ws))   # no ret.r at all
        self.assertTrue(all((w >> 26) != 0x09 for w in ws))   # no set2 (resume PC)
        self.assertEqual(ws.count(enc.addi(12, 1, 0x20)), 1)  # dst-init only
        self.assertNotIn(enc.st_d(6, 1, 0x18), ws)            # no r6 save
        self.assertNotIn(enc.ld_w(6, 1, 0x18), ws)            # no r6 restore

    def test_v5cB_every_word_has_precedent(self):
        # RC1 lesson: every word either (a) stock-identical, (b) live-proven
        # byte-exact (v5a/v5b), (c) a marker/counter word whose FORM is
        # live-proven (set3 rd=12: 362 stock sites + v5b-live; st.d r12,
        # zero,0x238C: v5a-live; st.d r13,zero,0x2388: rt/rs fields of the
        # v5b-live N-echo word 0x6C046B86 + CR target of the v5a-live
        # 0x6C04638A), or (d) a live form with a recomputed immediate.
        from build_s2 import stub_words
        ws = stub_words("A", version=8)
        v5b = set(stub_words("A", version=6))
        v5a = set(stub_words("A", version=5))
        stock_exact = {0x703F0FC2, 0x00210040, 0x480300BC}
        marker_forms = {enc.set3(12, 0, 2), enc.set3(12, 0, 3)}
        for i, w in enumerate(ws):
            ok = (w in v5b or w in v5a or w in stock_exact
                  or w == 0x6C04638E or w in marker_forms or w == 0x6C046B8A
                  or (w >> 26) == 0x29 or (w >> 26) == 0x25)
            self.assertTrue(ok, f"word {i} 0x{w:08x} has no precedent")
        self.assertEqual(len([w for w in ws if (w >> 26) == 0x29]), 4)  # 2 prefix + back-edge + gauntlet

    def test_v5cB_clobber_confined(self):
        from build_s2 import stub_words
        import irisc_dis
        ws = stub_words("A", version=8)
        dec = [irisc_dis.dis(w, 0) for w in ws]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5cB_budget(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=8)
        self.assertEqual(len(ws), 34)                # full zone, counter fits
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5cB_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=8)


@pytest.mark.slow
class TestS2BuildV5CB(unittest.TestCase):
    def test_build_v5cB_image(self):
        buf = built(8)
        img = mlxfwutil.Image(buf, "s2v5cB")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D764), 0xA40A001C)  # filter b.f.cc0A -> W_FAST
        self.assertEqual(w(0x38D77C), 0xA40A0016)  # N-guard b.f.cc0A -> W_FAST
        self.assertEqual(w(0x38D780), 0x703F0FC2)  # push
        self.assertEqual(w(0x38D784), 0x6C201802)  # save ra (SUSPECT, v5b-verbatim)
        self.assertEqual(w(0x38D788), 0x200C0002)  # M1 set3 r12,zero,2
        self.assertEqual(w(0x38D78C), 0x6C04638E)  # M1 st.d r12,0,0x238c
        self.assertEqual(w(0x38D790), 0x002C0020)  # dst-init (SUSPECT)
        self.assertEqual(w(0x38D794), 0x65630001)  # ld.w r3,r11,0 (SUSPECT)
        self.assertEqual(w(0x38D798), 0x6D801801)  # st.w r3,r12,0 (SUSPECT)
        self.assertEqual(w(0x38D79C), 0x65630003)  # ld.w r3,r11,2 (SUSPECT)
        self.assertEqual(w(0x38D7A0), 0x6D801803)  # st.w r3,r12,2 (SUSPECT)
        self.assertEqual(w(0x38D7A4), 0x6C046B8A)  # counter st.d r13,0,0x2388
        self.assertEqual(w(0x38D7B4), 0xA400FFF8)  # back-edge b.f.cc00 -8
        self.assertEqual(w(0x38D7B8), 0x200C0003)  # M2 set3 r12,zero,3
        self.assertEqual(w(0x38D7BC), 0x6C04638E)  # M2 st.d r12,0,0x238c
        self.assertEqual(w(0x38D7C0), 0x642C0021)  # gauntlet read (SUSPECT)
        self.assertEqual(w(0x38D7C4), 0x200D2407)  # gauntlet const
        self.assertEqual(w(0x38D7CC), 0xA40A0001)  # gauntlet miss b.f -> pop
        self.assertEqual(w(0x38D7D0), 0x00210040)  # pop
        self.assertEqual(w(0x38D7D4), 0x95F80064)  # W_FAST jump FN_A
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5cB_bakes_card_guids(self):
        buf = built(8)
        img = mlxfwutil.Image(buf, "s2v5cB")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac), (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5cB_diff_vs_v5cA_confined_to_stub_zone(self):
        va = built(7)
        vb = built(8)
        ia, ib = mlxfwutil.Image(va, "v5cA"), mlxfwutil.Image(vb, "v5cB")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ib.section_data(ib.find_entry(toc, t)),
                             ia.section_data(ia.find_entry(toc, t)))
        ca = decrc(ia.section_data(ia.find_entry("ITOC", 0x03)))
        cb = decrc(ib.section_data(ib.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", ca, DETOUR_DC)[0],
                         struct.unpack_from(">I", cb, DETOUR_DC)[0])
        diff_words = [a for a in range(0, len(ca), 4)
                      if struct.unpack_from(">I", ca, a)[0] != struct.unpack_from(">I", cb, a)[0]]
        self.assertTrue(diff_words)
        for a in diff_words:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        eb = ib.find_entry("ITOC", 0x03)
        ent_lo = ib.itoc_off + 32 + eb.index * 32
        allowed = set(range(eb.addr, eb.addr + eb.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(va)) if va[i] != vb[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5cB_deterministic(self):
        b1 = build(det(1), version=8)
        b2 = build(det(2), version=8)
        self.assertEqual(b1, b2)


class TestS2StubV5D(unittest.TestCase):
    # v5d (T23, task-22 audit verdict "SMOKING GUN not found" + Step-7
    # sketch, review-approved): C1-candidate with a STOCK-CONFORMANCE copy
    # data path.  v5b flow verbatim (live-proven prefix w0-11, push, saves,
    # gauntlet, payload block, resume tail); the ONLY data-path change is
    # inside the copy loop: the two 16-bit ld.w/st.w halfword pairs
    # (st.w rt=3 AND rs=12 both 0/1947 stock — the TOP residual suspects of
    # the task-22 audit) collapse to ONE 32-bit ld.d/st.d pair.  Both new
    # words are byte-exact stock code words; every field of the loop is
    # stock-precedented EXACTLY ONE: subsi rd=13 (0/37907 — r13 reserved by
    # the stock ABI; live-proven writable by every v5b magic run; accepted
    # constrained minimum per task-22 review).  Known recorded residual:
    # the ADJACENT ld.d r3 -> st.d r3 shape is 0 in stock (fields
    # precedented, shape novel — record, do not fix).  M-marker
    # (set3 r12,zero,7 + st.d r12,zero,0x238C) after loop-exit = the
    # "copy done" liveness signal; the 2 words saved by the pair collapse
    # pay for it, so gauntlet/payload/resume/W_FAST stay at v5b indices
    # AND bytes.  33 of 34 zone words; W_FAST @word 32 = 0x38d7d0 (== v5b).
    V5D_GOLDEN = [
        0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
        0xA40A001B, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x200C0004,
        0xE1A06002, 0xA40A0015, 0x703F0FC2, 0x6C201802, 0x002C0020,
        0x65630002, 0x6D801802, 0x016B0004, 0x018C0004, 0x15AD0001,
        0xA400FFFB, 0x200C0007, 0x6C04638E, 0x642C0021, 0x200D2407,
        0xE1806802, 0xA40A0005, 0x002C0020, 0x240300B8, 0x2063D7CC,
        0xFC006025, 0x00210040, 0x95F80065,
    ]

    def test_v5d_golden_words(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("A", version=9), self.V5D_GOLDEN)

    def test_v5d_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5d"), stub_words("A", version=9))

    def test_v5d_diff_vs_v5b_exactly_copy_data_words(self):
        # THE v5d contract: v5b -> v5d touches ONLY the copy-loop data
        # words (4 halfword ops removed, 2 doubleword ops inserted, strides
        # stay 4), the back-edge immediate (recomputed -7 -> -5 for the
        # same loop-head target; 0xA400FFFB is itself a x314 stock word),
        # and the inserted M-marker pair; EVERYTHING else is byte-identical
        # at identical indices (prefix incl. its b_f immediates, push,
        # save, dst-init, strides, subsi, gauntlet, payload block, resume,
        # W_FAST).
        from build_s2 import stub_words
        wa, wb = stub_words("A", version=9), stub_words("A", version=6)
        self.assertEqual(len(wb), 33)
        self.assertEqual(wa[0:15], wb[0:15], "prefix/push/save/dst-init drifted")
        self.assertEqual(wb[15:19],
                         [0x65630001, 0x6D801801, 0x65630003, 0x6D801803])
        self.assertEqual(wa[15:17], [0x65630002, 0x6D801802])   # inserted
        self.assertEqual(wa[17:20], wb[19:22])                   # strides+subsi
        self.assertEqual(wa[20], 0xA400FFFB)                     # back-edge -5
        self.assertEqual(wb[22], 0xA400FFF9)                     # was -7
        self.assertEqual(wa[20] ^ wb[22], 2)
        self.assertEqual(wa[21:23], [0x200C0007, 0x6C04638E])    # M-marker
        self.assertEqual(wa[23:33], wb[23:33],
                         "gauntlet/payload/resume/W_FAST drifted from v5b")

    def test_v5d_copy_loop_words(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=9)
        self.assertEqual(ws[15], enc.ld_d(3, 11, 0x0))       # 32-bit load
        self.assertEqual(ws[16], enc.st_d(3, 12, 0x0))       # 32-bit store
        self.assertEqual(ws[17], enc.addi(11, 11, 4))        # stride 4 stays
        self.assertEqual(ws[18], enc.addi(12, 12, 4))        # stride 4 stays
        self.assertEqual(ws[19], enc.subsi(13, 13, 1))
        self.assertEqual(ws[20], enc.b_f(0x00, STUB + 4 * 20, STUB + 4 * 15))
        # the v5b 16-bit data words are GONE (0-precedent suspects removed)
        for gone in (0x65630001, 0x6D801801, 0x65630003, 0x6D801803):
            self.assertNotIn(gone, ws)

    def test_v5d_loop_dataflow(self):
        # v5b review Critical-1 lesson: decode, don't trust frozen words —
        # N must land in the register subsi decrements, the ld.d
        # destination must feed the st.d source, nothing clobbers either.
        from build_s2 import stub_words, SLOT_N_V5B
        import irisc_dis
        ws = stub_words("A", version=9)
        dec = [irisc_dis.dis(w, STUB + 4 * i) for i, w in enumerate(ws)]
        n_ld = [i for i, s in enumerate(dec)
                if s.startswith("ld.w ") and s.endswith("r1,0x%x" % SLOT_N_V5B)]
        self.assertEqual(len(n_ld), 1)
        n_reg = dec[n_ld[0]].split()[1].split(",")[0]
        subsi = [i for i, s in enumerate(dec) if s.startswith("subsi ")]
        self.assertEqual(len(subsi), 1)
        self.assertTrue(dec[subsi[0]].startswith("subsi %s," % n_reg))
        for i in range(n_ld[0] + 1, subsi[0]):
            s = dec[i]
            self.assertFalse(s.startswith(("set", "addi", "subsi", "subi", "ld.", "csr.r",
                                           "or ", "and ", "xor ", "alu."))
                            and s.split()[1].split(",")[0] == n_reg,
                            "%r overwrites the N register %s before the loop" % (s, n_reg))
        # ld.d r3,[r11+0] feeds st.d r3,[r12+0]: same temp register, and
        # the source/destination pointers keep the v5b roles (r11 src, r12 dst)
        self.assertEqual(dec[15], "ld.d r3,r11,0x0")
        self.assertEqual(dec[16], "st.d r3,r12,0x0")
        self.assertEqual(dec[14], "addi r12,r1,0x20")            # dst init
        self.assertEqual(dec[1], "addi r11,r1,0xac")             # src init

    def test_v5d_stock_precedents(self):
        # precedent assertions vs the clean stock blob (de-clcrc MAIN_CODE,
        # file off == Ghidra addr; counts re-verified by the task-23 scan,
        # classifier code regions == whole-blob for these exact words):
        #   ld.d r3,r11,0x0 (0x65630002) x1 exact, combo rs=11^rd=3 x2
        #   st.d r3,r12,0x0 (0x6D801802) x46 exact, ALL off=0
        #   back-edge 0xA400FFFB (b_f.cc00 -5) x314 (vs -7/-8: 74/65)
        #   subsi rd=13: 0/37907 — THE one 0-precedent field (residual)
        #   adjacent ld.d rd=3 -> st.d rt=3: 0 pairs (shape residual)
        #   v5b removed words 0x6D801801-class: 0 (zero-precedent gone)
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        ws = stub_words("A", version=9)
        self.assertEqual(sum(1 for w in words if w == 0x65630002), 1)
        self.assertEqual(sum(1 for w in words if w == 0x6D801802), 46)
        self.assertEqual(sum(1 for w in words if w == 0xA400FFFB), 314)
        self.assertEqual(sum(1 for w in words if w == 0x15AD0001), 0)
        # the ONE 0-field: no subsi anywhere in stock writes rd=13
        self.assertEqual(sum(1 for w in words
                             if (w >> 26) == 0x05 and ((w >> 16) & 0x1F) == 13), 0)
        # shape residual: adjacent ld.d(rd=3) -> st.d(rt=3) never occurs
        is_ld_d = lambda w: (w >> 26) == 0x19 and (w & 3) == 2 \
            and ((w >> 16) & 0x1F) == 3
        is_st_d = lambda w: (w >> 26) == 0x1B and (w & 3) == 2 \
            and ((w >> 11) & 0x1F) == 3
        adj = sum(1 for i in range(len(words) - 1)
                  if is_ld_d(words[i]) and is_st_d(words[i + 1]))
        self.assertEqual(adj, 0)
        # loop temp/pointer combos: exact words are code sites (whole-blob
        # == code counts: 1/46/314 above); the ld.d COMBO rs=11^rd=3 is
        # x2 in classifier code regions (task-23 scan) / x26 whole-blob
        # (data regions included) — assert the lower bound here
        ld_combo = sum(1 for w in words
                       if (w >> 26) == 0x19 and (w & 3) == 2
                       and ((w >> 21) & 0x1F) == 11 and ((w >> 16) & 0x1F) == 3)
        st_combo = sum(1 for w in words
                       if (w >> 26) == 0x1B and (w & 3) == 2
                       and ((w >> 21) & 0x1F) == 12 and ((w >> 11) & 0x1F) == 3)
        self.assertGreaterEqual(ld_combo, 2)
        self.assertEqual(st_combo, 46)
        # every v5d loop word except subsi appears in stock (subsi rd=13
        # is the recorded 0-field — asserted == 0 above)
        for w in ws[15:19]:
            self.assertIn(w, words, "loop word 0x%08x absent from stock" % w)

    def test_v5d_marker_words(self):
        # M-marker after loop-exit, before the gauntlet read: v5a-live
        # byte-exact CR word + v5cA-live marker form (set3 r12,zero,VAL ran
        # clean x2 live for VAL 1/2/3; rd=12: 362 stock sites), VAL=7 =
        # "copy done" (distinct from v5cA 1/2/3 and v5cB 2/3 semantics).
        from build_s2 import stub_words
        ws = stub_words("A", version=9)
        self.assertEqual(ws[21], enc.set3(12, 0, 7))
        self.assertEqual(ws[21], 0x200C0007)
        self.assertEqual((ws[21] >> 26), 0x08)
        self.assertEqual(((ws[21] >> 21) & 0x1F), 0)        # rs = zero
        self.assertEqual(((ws[21] >> 16) & 0x1F), 12)       # rd = r12
        self.assertEqual(ws[22], 0x6C04638E)                # v5a-live exact
        self.assertEqual(ws[20] >> 26, 0x29)                # after back-edge
        self.assertEqual(ws[23], enc.ld_w(12, 1, 0x20))     # before gauntlet

    def test_v5d_branches(self):
        from build_s2 import stub_words, FN_A
        ws = stub_words("A", version=9)
        w_fast = STUB + 4 * 32                          # word 32 = jump FN_A
        self.assertEqual(len(ws), 33)
        self.assertEqual(ws[32], enc.jump(w_fast, FN_A))
        self.assertEqual(ws[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))    # filter
        self.assertEqual(ws[11], enc.b_f(0x0A, STUB + 4 * 11, w_fast))  # N-guard
        self.assertEqual(ws[20], enc.b_f(0x00, STUB + 4 * 20, STUB + 4 * 15))  # loop
        resume = STUB + 4 * 31
        self.assertEqual(ws[26], enc.b_f(0x0A, STUB + 4 * 26, resume))  # gauntlet miss
        self.assertEqual(ws[31], enc.addi(1, 1, 0x40))                 # RESUME pop

    def test_v5d_prefix_immediates_identical_to_v5b(self):
        # W_FAST keeps the v5b address (marker pays for the pair collapse),
        # so the prefix b_f.cc0A immediates are v5b byte-exact (0x1B/0x15),
        # as are gauntlet b_f (0x0005), resume-PC set2/set3 and the jump.
        from build_s2 import stub_words
        wa, wb = stub_words("A", version=9), stub_words("A", version=6)
        for i in (5, 11, 26, 28, 29, 30, 31, 32):
            self.assertEqual(wa[i], wb[i], f"word {i} drifted from v5b")

    def test_v5d_clobber_confined(self):
        from build_s2 import stub_words
        import irisc_dis
        ws = stub_words("A", version=9)
        dec = [irisc_dis.dis(w, 0) for w in ws]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5d_budget(self):
        from build_s2 import stub_words
        ws = stub_words("A", version=9)
        self.assertEqual(len(ws), 33)                # 31 + 2-word M-marker
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5d_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=9)

    def test_v5d_lineage_untouched(self):
        # v5b/v5cA/v5cB goldens are frozen (burned-image lineage): the
        # version-9 addition must not disturb versions 6/7/8.
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)


@pytest.mark.slow
class TestS2BuildV5D(unittest.TestCase):
    def test_build_v5d_image(self):
        buf = built(9)
        img = mlxfwutil.Image(buf, "s2v5d")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D764), 0xA40A001B)  # filter b_f.cc0A -> W_FAST
        self.assertEqual(w(0x38D77C), 0xA40A0015)  # N-guard b_f.cc0A -> W_FAST
        self.assertEqual(w(0x38D780), 0x703F0FC2)  # push
        self.assertEqual(w(0x38D784), 0x6C201802)  # save ra (v5b-verbatim)
        self.assertEqual(w(0x38D788), 0x002C0020)  # dst-init (v5b-verbatim)
        self.assertEqual(w(0x38D78C), 0x65630002)  # ld.d r3,r11,0 (NEW, stock x1)
        self.assertEqual(w(0x38D790), 0x6D801802)  # st.d r3,r12,0 (NEW, stock x46)
        self.assertEqual(w(0x38D794), 0x016B0004)  # addi r11,r11,4
        self.assertEqual(w(0x38D798), 0x018C0004)  # addi r12,r12,4
        self.assertEqual(w(0x38D79C), 0x15AD0001)  # subsi r13,r13,1 (0-field)
        self.assertEqual(w(0x38D7A0), 0xA400FFFB)  # back-edge b.f.cc00 -5 (x314)
        self.assertEqual(w(0x38D7A4), 0x200C0007)  # M: set3 r12,zero,7
        self.assertEqual(w(0x38D7A8), 0x6C04638E)  # M: st.d r12,0,0x238c
        self.assertEqual(w(0x38D7AC), 0x642C0021)  # gauntlet read
        self.assertEqual(w(0x38D7B4), 0xE1806802)  # gauntlet cmp38_sel(2)
        self.assertEqual(w(0x38D7B8), 0xA40A0005)  # gauntlet miss b_f -> RESUME
        self.assertEqual(w(0x38D7C8), 0xFC006025)  # ret.r -> payload
        self.assertEqual(w(0x38D7CC), 0x00210040)  # RESUME pop
        self.assertEqual(w(0x38D7D0), 0x95F80065)  # W_FAST jump FN_A
        for a in range(STUB + 4 * 33, STUB + 4 * 34, 4):   # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5d_bakes_card_guids(self):
        buf = built(9)
        img = mlxfwutil.Image(buf, "s2v5d")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac), (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5d_diff_vs_v5b_copy_words_only(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone AND exactly the expected words
        # (loop data path + back-edge + marker; gauntlet/payload/resume/
        # W_FAST v5b byte-exact at the same addresses).
        v5b = built(6)
        v5d = built(9)
        ib, id_ = mlxfwutil.Image(v5b, "v5b"), mlxfwutil.Image(v5d, "v5d")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(id_.section_data(id_.find_entry(toc, t)),
                             ib.section_data(ib.find_entry(toc, t)))
        cb = decrc(ib.section_data(ib.find_entry("ITOC", 0x03)))
        cd = decrc(id_.section_data(id_.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", cb, DETOUR_DC)[0],
                         struct.unpack_from(">I", cd, DETOUR_DC)[0])
        gw = lambda c, a: struct.unpack_from(">I", c, a)[0]
        diff = [a for a in range(0, len(cb), 4) if gw(cb, a) != gw(cd, a)]
        expected = sorted(STUB + 4 * i for i in
                          (15, 16, 17, 18, 19, 20, 21, 22))   # loop shift + marker
        self.assertEqual(diff, expected,
                         "code diff is not exactly the copy-path words")
        # the v5b 16-bit halfword data words are gone from the whole zone
        # (v5d is also 33 words: the marker pair fills the slots the pair
        # collapse freed — nothing is zeroed, the words are replaced)
        for gone in (0x65630001, 0x6D801801, 0x65630003, 0x6D801803):
            self.assertNotIn(gone, [gw(cd, a) for a in
                                    range(STUB, STUB + 4 * 34, 4)])
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        ed = id_.find_entry("ITOC", 0x03)
        ent_lo = id_.itoc_off + 32 + ed.index * 32
        allowed = set(range(ed.addr, ed.addr + ed.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5b)) if v5b[i] != v5d[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5d_deterministic(self):
        b1 = build(det(1), version=9)
        b2 = build(det(2), version=9)
        self.assertEqual(b1, b2)


class TestS2StubV5E(unittest.TestCase):
    # v5e (T25, journal task-24 «Errata + v5e rev.2», review-driven rework):
    # ESCALATION N-GATES bisection stub — freeze at frame-N=k names the
    # block.  Prefix = live-exact v5b filter/echo/N-load+echo-0x2384 (w0-w8);
    # the v5b N-guard is REPLACED by the escalation flow: after push+saves
    # (v5b-verbatim 0-combo suspect) the L2 gate (set3 r12,zero,2 — v5cA-live
    # M1 word + cmp38_sel(2,13,12) — v5b-live guard word + b_t.cc0A -> TAIL)
    # early-exits on N==2; then dst-init (v5d-verbatim suspect) + ONE
    # ld.d/st.d pair (v5d-verbatim suspects), the L3 gate (set3 r12,zero,3 —
    # v5cA-live M2 word + cmp38 + b_t) exits on N==3; then dst RE-INIT
    # (addi r12,r1,0x20 — the dst-init word itself: the L3 gate clobbers
    # r12, rev.2's fix of the old N=4 absolute-EA corruption) and the
    # v5d-VERBATIM do-while copy loop (w21-w26 == v5d w15-w20 byte-exact);
    # shared TAIL: marker st.d r13,zero,0x238C (echo-word retarget
    # 0x2384->0x238C, live form; values N=2->2, N=3->3, N=4->0, N=1->0)
    # -> pop -> W_FAST jump FN_A (LAST word, w29 = 0x38d7c4).  30/34 zone
    # words.  Residuals (journal rev.2): echo-N1 runs the write path at
    # depth 1 (pair+loop x1, idempotent duplicate write); no garbage-N
    # guard (builder frames only, N in [1..4]); N=3 conflates dst-init vs
    # pair (disambiguator = L3-gate reorder, documented).
    V5E_GOLDEN = [
        0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
        0xA40A0018, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x703F0FC2,
        0x6C201802, 0x200C0002, 0xE1A06002, 0xA00A000E, 0x002C0020,
        0x65630002, 0x6D801802, 0x200C0003, 0xE1A06002, 0xA00A0008,
        0x002C0020, 0x65630002, 0x6D801802, 0x016B0004, 0x018C0004,
        0x15AD0001, 0xA400FFFB, 0x6C046B8E, 0x00210040, 0x95F80068,
    ]

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=10)

    def test_v5e_golden_words(self):
        self.assertEqual(self.ws(), self.V5E_GOLDEN)

    def test_v5e_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5e"), stub_words("A", version=10))
        self.assertEqual(stub_words("A", version="v5e"), stub_words("A", version=10))

    def test_v5e_prefix_live_exact_v5b(self):
        # THE escalation contract: prefix words w0-w4 (filter) and w6-w8
        # (echo MAGIC16 / N-load / echo N) are v5b/v5d BYTE-EXACT; only w5's
        # immediate retargets (+27/+24 -> W_FAST @w29); the v5b N-guard
        # block (set3 r12,zero,4 + cmp38 + b_f) is GONE — replaced by the
        # escalation gates that ACCEPT N in {1,2,3,4}.
        wd = self.ws()
        self.assertEqual(wd[0:5], [0x480300BC, 0x002B00AC, 0x642C00AB,
                                   0x200D5332, 0xE1806802])
        self.assertEqual(wd[6:9], [0x6C046382, 0x642D00A5, 0x6C046B86])
        self.assertEqual(wd[5], 0xA40A0018)                 # b_f.cc0A +24
        self.assertNotIn(0x200C0004, wd)                    # N-guard const gone
        self.assertNotIn(0xA40A0015, wd)                    # N-guard branch gone
        self.assertEqual(wd[9], 0x703F0FC2)                 # push right after echo

    def test_v5e_suspects_v5d_verbatim(self):
        # saves / dst-init / pair: v5d-verbatim suspect words (combo audit:
        # saves st.d rt=3^rs=1^off=0 = 0-combo; dst-init imm 0-TUPLE; the
        # pair words themselves byte-exact stock x1/x46).
        wd = self.ws()
        self.assertEqual(wd[10], 0x6C201802)                # saves (v5d w13)
        self.assertEqual(wd[14], 0x002C0020)                # dst-init (v5d w14)
        self.assertEqual(wd[15:17], [0x65630002, 0x6D801802])   # pair (v5d w15/16)

    def test_v5e_gate_words(self):
        # cascaded equality gates, EARLY-EXIT only: L2 (w11-w13) between
        # saves and dst-init (r12 provably free: last read w6, next def
        # w14); L3 (w17-w19) after the pair.  Every gate word live-exact:
        # set3 r12,zero,K = the v5cA-live M1/M2 words; cmp38_sel(2,13,12) =
        # the v5b-live guard word; b_t.cc0A exits = stock-exact x56/x75.
        wd = self.ws()
        self.assertEqual(wd[11], 0x200C0002)                # v5cA-live M1
        self.assertEqual(wd[12], 0xE1A06002)                # v5b-live guard
        self.assertEqual(wd[13], 0xA00A000E)                # b_t.cc0A +14
        self.assertEqual(wd[17], 0x200C0003)                # v5cA-live M2
        self.assertEqual(wd[18], 0xE1A06002)
        self.assertEqual(wd[19], 0xA00A0008)                # b_t.cc0A +8
        tail = STUB + 4 * 27                                # marker @w27
        self.assertEqual(wd[13], enc.b_t(0x0A, STUB + 4 * 13, tail))
        self.assertEqual(wd[19], enc.b_t(0x0A, STUB + 4 * 19, tail))
        self.assertEqual((wd[13] >> 26), 0x28)              # b_t (not b_f)

    def test_v5e_dst_reinit_before_loop(self):
        # rev.2 Critical fix: the L3 gate's set3 clobbers r12 (dst ptr), so
        # w20 RE-INITS it with the dst-init word itself (0-TUPLE x2 combo,
        # no store-via-r12 follows at the stock sites) — the loop never
        # runs with a clobbered dst (old v5e N=4 wrote absolute [0x8/0xc/
        # 0x10]).
        wd = self.ws()
        self.assertEqual(wd[20], 0x002C0020)
        self.assertEqual(wd[20], wd[14])                    # == dst-init word
        self.assertEqual(wd[21], enc.ld_d(3, 11, 0))        # loop head next

    def test_v5e_loop_v5d_verbatim(self):
        # the loop block w21-w26 == v5d w15-w20 BYTE-EXACT (ld.d/st.d pair,
        # strides, subsi, back-edge -5): N=4 falls straight into the
        # v5d-verbatim do-while loop — no pre-strides, no pre-dec, no L4.
        from build_s2 import stub_words
        self.assertEqual(self.ws()[21:27], stub_words("A", version=9)[15:21])

    def test_v5e_shared_tail(self):
        # TAIL entry = the marker; echo-word form (0x6C046B86 = st.d
        # r13,zero,0x2384 — LIVE in every magic run) with the offset
        # retargeted to 0x238C (offset class live: v5a/v5cA M-markers x3
        # writes); pop; W_FAST jump FN_A LAST (word 29 = 0x38d7c4).
        wd = self.ws()
        self.assertEqual(wd[27], 0x6C046B8E)
        self.assertEqual(wd[27] & 0xFFFF, 0x6B8E)
        self.assertEqual(wd[28], enc.addi(1, 1, 0x40))      # pop, stock x185
        self.assertEqual(wd[29], enc.jump(STUB + 4 * 29, 0x18D964))
        self.assertEqual(wd[29], 0x95F80068)

    def test_v5e_branches(self):
        wd = self.ws()
        w_fast = STUB + 4 * 29
        tail = STUB + 4 * 27
        self.assertEqual(len(wd), 30)
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))    # filter
        self.assertEqual(wd[13], enc.b_t(0x0A, STUB + 4 * 13, tail))    # L2 exit
        self.assertEqual(wd[19], enc.b_t(0x0A, STUB + 4 * 19, tail))    # L3 exit
        self.assertEqual(wd[26], enc.b_f(0x00, STUB + 4 * 26, STUB + 4 * 21))  # loop

    def test_v5e_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 30)                # 30/34 (rev.2: -4 vs 34)
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5e_clobber_confined(self):
        import irisc_dis
        dec = [irisc_dis.dis(w, 0) for w in self.ws()]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5e_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=10)

    def test_v5e_stock_precedents(self):
        # gate/dispatch stock counts (clean blob, task-24 rev.2 census;
        # whole-blob == code regions for exact words — re-verified):
        #   b_t.cc0A +14 (0xA00A000E) exact x56 / +8 (0xA00A0008) x75
        #   w5 retarget b_f.cc0A +24 (0xA40A0018) x14
        #   b_t.cc0A form x2315 code (x2316 whole-blob, 1 data site)
        #   [cmp38 -> b_t.cc0A] adjacent x15
        #   set3 rd=12^rs=0 combo x11 (exact set3 r12,zero,2/3: 0 — live)
        # 0-counts (suspects / live-exempt words, exact):
        #   saves 0x6C201802 / dst-init 0x002C0020 / subsi rd=13 /
        #   gate-cmp 0xE1A06002 (v5b-live) / marker 0x6C046B8E (rs=0 class)
        # precedented loop words: 0x65630002 x1 / 0x6D801802 x46 /
        #   0x016B0004 x6 / 0x018C0004 x3 / 0xA400FFFB x314
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        cnt = lambda x: sum(1 for w in words if w == x)
        ws = self.ws()
        self.assertEqual(cnt(0xA00A000E), 56)               # L2 exit word
        self.assertEqual(cnt(0xA00A0008), 75)               # L3 exit word
        self.assertEqual(cnt(0xA40A0018), 14)               # w5 retarget
        self.assertEqual(cnt(0xE1A06002), 0)                # gate cmp: live-exact
        self.assertEqual(cnt(0x6C046B8E), 0)                # marker: live class
        self.assertEqual(cnt(0x6C201802), 0)                # saves: 0-combo
        self.assertEqual(cnt(0x002C0020), 0)                # dst-init: 0-TUPLE
        self.assertEqual(cnt(0x15AD0001), 0)                # subsi rd=13
        for w in (0x65630002, 0x6D801802, 0x016B0004, 0x018C0004, 0xA400FFFB):
            self.assertGreater(cnt(w), 0)
        self.assertEqual(cnt(0x65630002), 1)
        self.assertEqual(cnt(0x6D801802), 46)
        self.assertEqual(cnt(0x016B0004), 6)
        self.assertEqual(cnt(0x018C0004), 3)
        self.assertEqual(cnt(0xA400FFFB), 314)
        # b_t.cc0A branch class + cmp38 adjacency (stock idiom the gates
        # consume; whole-blob includes 1 data-region site vs 2315 code)
        self.assertEqual(sum(1 for w in words if (w >> 26) == 0x28
                             and ((w >> 16) & 0x1F) == 0x0A), 2316)
        adj = sum(1 for i in range(len(words) - 1)
                  if (words[i] >> 26) == 0x38
                  and (words[i + 1] >> 26) == 0x28
                  and ((words[i + 1] >> 16) & 0x1F) == 0x0A)
        self.assertGreaterEqual(adj, 15)
        # set3 r12 gate consts: exact 0 (v5cA-live), form combo x11
        self.assertEqual(sum(1 for w in words if (w >> 26) == 0x08
                             and ((w >> 21) & 0x1F) == 0
                             and ((w >> 16) & 0x1F) == 12), 11)
        # every word of the stub is stock-exact, live-exact (v5b/v5cA/v5d
        # lineage goldens) or a documented suspect (journal rev.2 table)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7)) \
            | set(stub_words("A", version=8)) | set(stub_words("A", version=9))
        documented = {0xA40A0018, 0x200C0002, 0xE1A06002, 0xA00A000E,
                      0x200C0003, 0xA00A0008, 0x6C046B8E,
                      0x95F80068}    # W_FAST jump FN_A: live-form, imm recomputed
        for w in ws:
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5e_lineage_untouched(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)
        self.assertEqual(len(stub_words("A", version=9)), 33)


class TestS2StubV5F(unittest.TestCase):
    # v5f (T27, journal task-26 §Step 7, freeze-#6 fix): v5e escalation
    # flow with BOTH gates replaced by the STOCK SKIP-IDIOM
    # [cmp38; b_f.cc0A +2; jump TAIL] — b_t-taken (freeze-#6: the ONE
    # taken op=0x28 on 4030 froze the host at neg-N2) is ELIMINATED:
    # equality makes the b_f NOT-taken so the UNCONDITIONAL jump TAIL
    # executes; inequality takes the b_f +2 skip = b_f.cc0A at
    # CMPRES=false — the ONLY live-proven clean taken-conditional class
    # on 4030 (x5 boots via the w5 fallthrough).  Prefix w0-w10 = v5e
    # byte-exact (only w5's immediate retargets to the new W_FAST @w31,
    # stock-exact x10); dst-init/pair/L3-gate/dst-RE-INIT shift +1 word
    # (the L2 gate gains its jump word); loop w23-w28 == v5d w15-w20
    # byte-exact; shared TAIL: marker st.d r13,zero,0x238C @w29 (values
    # N=2->2, N=3->3, N=4->0, N=1->0) -> pop -> W_FAST jump FN_A LAST
    # (w31 = 0x38d7cc).  32 of 34 zone words.
    V5F_GOLDEN = [
        0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
        0xA40A001A, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x703F0FC2,
        0x6C201802, 0x200C0002, 0xE1A06002, 0xA40A0002, 0x9500000F,
        0x002C0020, 0x65630002, 0x6D801802, 0x200C0003, 0xE1A06002,
        0xA40A0002, 0x95000008, 0x002C0020, 0x65630002, 0x6D801802,
        0x016B0004, 0x018C0004, 0x15AD0001, 0xA400FFFB, 0x6C046B8E,
        0x00210040, 0x95F80066,
    ]

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=11)

    def test_v5f_golden_words(self):
        self.assertEqual(self.ws(), self.V5F_GOLDEN)

    def test_v5f_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5f"), stub_words("A", version=11))
        self.assertEqual(stub_words("A", version="v5f"), stub_words("A", version=11))

    def test_v5f_prefix_v5e_w5_retarget_only(self):
        # w0-w4 and w6-w10 == v5e BYTE-EXACT; ONLY w5's immediate
        # changes (+24 -> +26: W_FAST moved from w29 to w31; the new
        # word 0xA40A001A is stock-exact x10).
        from build_s2 import stub_words
        we, wf = stub_words("A", version=10), self.ws()
        self.assertEqual(wf[0:5], we[0:5])
        self.assertEqual(wf[6:11], we[6:11])
        self.assertEqual(wf[5], 0xA40A001A)                 # b_f.cc0A +26
        self.assertEqual(wf[5] ^ we[5], 2)                  # imm +24 -> +26

    def test_v5f_gates_stock_skip_idiom(self):
        # L2 (w11-w14) / L3 (w18-w21): set3 const + cmp38_sel(2,13,12) +
        # b_f.cc0A +2 (skip the jump word — stock x94, 74/94 sites stand
        # right after op36/op38: the skip-idiom) + jump TAIL (stock x222
        # / x365).  EQUALITY -> b_f NOT-taken -> the UNCONDITIONAL jump
        # executes; the taken-conditional the v5e gates used (b_t.cc0A)
        # is GONE.
        wd = self.ws()
        self.assertEqual(wd[11], 0x200C0002)                # v5cA-live M1
        self.assertEqual(wd[12], 0xE1A06002)                # v5b-live guard
        self.assertEqual(wd[13], 0xA40A0002)                # skip: b_f.cc0A +2
        self.assertEqual(wd[14], 0x9500000F)                # exit: jump +15
        self.assertEqual(wd[18], 0x200C0003)                # v5cA-live M2
        self.assertEqual(wd[19], 0xE1A06002)
        self.assertEqual(wd[20], 0xA40A0002)                # skip: b_f.cc0A +2
        self.assertEqual(wd[21], 0x95000008)                # exit: jump +8
        tail = STUB + 4 * 29
        self.assertEqual(wd[13], enc.b_f(0x0A, STUB + 4 * 13, STUB + 4 * 15))
        self.assertEqual(wd[20], enc.b_f(0x0A, STUB + 4 * 20, STUB + 4 * 22))
        self.assertEqual(wd[14], enc.jump(STUB + 4 * 14, tail))
        self.assertEqual(wd[21], enc.jump(STUB + 4 * 21, tail))

    def test_v5f_zero_bt_words_anywhere(self):
        # freeze-#6 fix at the WORD level: NO op=0x28 (b_t) word anywhere
        # in the stub — the taken-b_t class cannot occur on ANY path.
        for i, w in enumerate(self.ws()):
            self.assertNotEqual(w >> 26, 0x28, f"w{i}=0x{w:08x} is b_t")

    def test_v5f_v5e_bt_exit_words_gone(self):
        ws = set(self.ws())
        self.assertNotIn(0xA00A000E, ws)                    # v5e L2 exit x56
        self.assertNotIn(0xA00A0008, ws)                    # v5e L3 exit x75

    def test_v5f_suspects_v5d_verbatim(self):
        # saves / dst-init / pair: v5d-verbatim suspect words at their
        # v5e positions+1 (the L2 gate gained its jump word).
        wd = self.ws()
        self.assertEqual(wd[10], 0x6C201802)                # saves (v5e w10)
        self.assertEqual(wd[15], 0x002C0020)                # dst-init (v5e w14)
        self.assertEqual(wd[16:18], [0x65630002, 0x6D801802])   # pair (v5e w15/16)

    def test_v5f_dst_reinit_before_loop(self):
        # rev.2 fix kept: the L3 gate's set3 clobbers r12 (dst ptr), so
        # w22 RE-INITS it with the dst-init word itself before the loop.
        wd = self.ws()
        self.assertEqual(wd[22], 0x002C0020)
        self.assertEqual(wd[22], wd[15])                    # == dst-init word
        self.assertEqual(wd[23], enc.ld_d(3, 11, 0))        # loop head next

    def test_v5f_loop_v5d_verbatim(self):
        # the loop block w23-w28 == v5d w15-w20 BYTE-EXACT (ld.d/st.d
        # pair, strides, subsi, back-edge -5): N=4 falls straight into
        # the v5d-verbatim do-while loop.
        from build_s2 import stub_words
        self.assertEqual(self.ws()[23:29], stub_words("A", version=9)[15:21])

    def test_v5f_shared_tail(self):
        wd = self.ws()
        self.assertEqual(wd[29], 0x6C046B8E)                # marker 0x238C
        self.assertEqual(wd[30], enc.addi(1, 1, 0x40))      # pop, stock x185
        self.assertEqual(wd[31], enc.jump(STUB + 4 * 31, 0x18D964))
        self.assertEqual(wd[31], 0x95F80066)

    def test_v5f_branches(self):
        wd = self.ws()
        w_fast = STUB + 4 * 31
        tail = STUB + 4 * 29
        self.assertEqual(len(wd), 32)
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))    # filter
        self.assertEqual(wd[13], enc.b_f(0x0A, STUB + 4 * 13, STUB + 4 * 15))
        self.assertEqual(wd[14], enc.jump(STUB + 4 * 14, tail))        # L2 exit
        self.assertEqual(wd[20], enc.b_f(0x0A, STUB + 4 * 20, STUB + 4 * 22))
        self.assertEqual(wd[21], enc.jump(STUB + 4 * 21, tail))        # L3 exit
        self.assertEqual(wd[28], enc.b_f(0x00, STUB + 4 * 28, STUB + 4 * 23))  # loop

    def test_v5f_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 32)                # 32/34
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5f_clobber_confined(self):
        import irisc_dis
        dec = [irisc_dis.dis(w, 0) for w in self.ws()]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5f_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=11)

    def test_v5f_stock_precedents(self):
        # NEW-word stock counts (journal task-26 census, re-verified on
        # the clean blob whole-image):
        #   gate skip b_f.cc0A +2 (0xA40A0002) x94 (74/94 stand right
        #     after op36/op38 d=1 — the skip-idiom the gates consume)
        #   L2 exit jump +15 (0x9500000F) x222 / L3 exit jump +8
        #     (0x95000008) x365
        #   w5 retarget b_f.cc0A +26 (0xA40A001A) x10
        # REMOVED v5e exit words (stock-exact, but their TAKEN op=0x28
        # transition is the freeze-#6 block): 0xA00A000E x56,
        # 0xA00A0008 x75.
        # Classes: jump-form op=0x25 (bit24) x20169 whole (x20164 code);
        # b_f.cc0A x1483 whole (x1481 code).  0-counts / loop-word
        # counts: as v5e (live lineage).
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        cnt = lambda x: sum(1 for w in words if w == x)
        ws = self.ws()
        self.assertEqual(cnt(0xA40A0002), 94)               # gate skip word
        self.assertEqual(cnt(0x9500000F), 222)              # L2 exit jump
        self.assertEqual(cnt(0x95000008), 365)              # L3 exit jump
        self.assertEqual(cnt(0xA40A001A), 10)               # w5 retarget
        self.assertEqual(cnt(0xA00A000E), 56)               # v5e L2 (removed)
        self.assertEqual(cnt(0xA00A0008), 75)               # v5e L3 (removed)
        self.assertEqual(cnt(0xE1A06002), 0)                # gate cmp: live
        self.assertEqual(cnt(0x6C046B8E), 0)                # marker: live
        self.assertEqual(cnt(0x6C201802), 0)                # saves: 0-combo
        self.assertEqual(cnt(0x002C0020), 0)                # dst-init: 0-TUPLE
        self.assertEqual(cnt(0x15AD0001), 0)                # subsi rd=13
        for w in (0x65630002, 0x6D801802, 0x016B0004, 0x018C0004, 0xA400FFFB):
            self.assertGreater(cnt(w), 0)
        self.assertEqual(cnt(0x65630002), 1)
        self.assertEqual(cnt(0x6D801802), 46)
        self.assertEqual(cnt(0x016B0004), 6)
        self.assertEqual(cnt(0x018C0004), 3)
        self.assertEqual(cnt(0xA400FFFB), 314)
        # the gate-exit word class (unconditional jump form) and the
        # gate-skip branch class — whole-image counts
        self.assertEqual(sum(1 for w in words if (w >> 26) == 0x25
                             and (w >> 24) & 1), 20169)
        self.assertEqual(sum(1 for w in words if (w >> 26) == 0x29
                             and ((w >> 16) & 0x1F) == 0x0A), 1483)
        # set3 r12 gate consts: exact 0 (v5cA-live), form combo x11
        self.assertEqual(sum(1 for w in words if (w >> 26) == 0x08
                             and ((w >> 21) & 0x1F) == 0
                             and ((w >> 16) & 0x1F) == 12), 11)
        # every word of the stub is stock-exact, live-exact (v5b/v5cA/
        # v5cB/v5d/v5e lineage goldens) or documented (journal §Step 7)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7)) \
            | set(stub_words("A", version=8)) | set(stub_words("A", version=9)) \
            | set(stub_words("A", version=10))
        documented = {0xA40A001A, 0x200C0002, 0xE1A06002, 0x6C046B8E,
                      0x95F80066}    # W_FAST jump FN_A: live-form, imm recomputed
        for w in ws:
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5f_lineage_untouched(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)
        self.assertEqual(len(stub_words("A", version=9)), 33)
        self.assertEqual(len(stub_words("A", version=10)), 30)


class TestS2StubV5ESim(unittest.TestCase):
    # per-path REGISTER-TRUE pc-level simulation of the ACTUAL builder
    # output (journal task-24 rev.2 verify_v5e2.py semantics, ported):
    # register file incl. zero-reg, EQ (cc0A) / Z32 (cc00) flags, memory +
    # CR model.  Freeze-at-N=k names the block ONLY if the paths are what
    # the design says — so assert EAs, marker values, CRs and stack balance
    # per frame, with the input block = the TRIG frames' payload bytes.
    R1E = 0x1000
    NEG_CODE = [0x24065332, 0x20E74F4B, 0x6C043B8A, 0xFC001825]  # gauntlet-neg

    class Sim:
        def __init__(self, ws, N, magic=True, code=None):
            self.ws = ws
            self.mem = {}
            self.cr = {0x2380: 0, 0x2384: 0, 0x238C: 0}
            R1E = TestS2StubV5ESim.R1E
            self.mem[R1E + 0xA4] = N
            self.mem[R1E + 0xAA] = 0x5332 if magic else 0x1234
            for i, cw in enumerate(code if code is not None
                                   else TestS2StubV5ESim.NEG_CODE):
                self.mem[R1E + 0xAC + 4 * i] = cw
            self.r = {1: R1E, 3: 0xDEAD, 11: 0, 12: 0, 13: 0}
            self.pc = 0
            self.eq = False
            self.z32 = False
            self.stores = []
            self.taken = []                                 # (i, op, cc, latch)

        def rd(self, k):
            return 0 if k == 0 else self.r[k]

        def run(self, max_steps=200):
            STUB = 0x38D750
            for _ in range(max_steps):
                i = self.pc
                word = self.ws[i]
                op = word >> 26
                nxt = i + 1
                if op == 0x12:                              # csr.r
                    self.r[3] = 0xBCBC
                elif op == 0x00:                            # addi
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    self.r[(word >> 16) & 0x1F] = \
                        (self.rd((word >> 21) & 0x1F) + imm) & 0xFFFFFFFF
                elif op == 0x08:                            # set3
                    self.r[(word >> 16) & 0x1F] = \
                        (self.rd((word >> 21) & 0x1F) + (word & 0xFFFF)) & 0xFFFFFFFF
                elif op == 0x19:                            # ld.w / ld.d
                    rt, rs = (word >> 16) & 0x1F, (word >> 21) & 0x1F
                    if word & 1:
                        off = ((word >> 1) & 0x7FFF) << 1
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0) & 0xFFFF
                    else:
                        off = ((word >> 2) & 0x3FFF) << 2
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0)
                elif op == 0x1C:                            # st.d! push
                    imm = ((((word >> 16) & 0x1F) << 11)
                           | (((word >> 2) & 0x1FF) << 2))
                    if imm & 0x8000:
                        imm -= 0x10000
                    self.r[1] = (self.r[1] + imm) & 0xFFFFFFFF
                elif op == 0x1B:                            # st.d / st.w
                    rt, rs = (word >> 11) & 0x1F, (word >> 21) & 0x1F
                    off = (((word >> 16) & 0x1F) << 11) \
                        | (((word >> 2) & 0x1FF) << 2)
                    if rs == 0:
                        self.cr[off] = self.r[rt]
                        self.stores.append((off, self.r[rt], "CR"))
                    else:
                        ea = (self.rd(rs) + off) & 0xFFFFFFFF
                        R1E = TestS2StubV5ESim.R1E
                        kind = "STACK" if R1E - 0x40 <= ea < R1E else "ABS"
                        self.mem[ea] = self.r[rt]
                        self.stores.append((ea, self.r[rt], kind))
                elif op == 0x05:                            # subsi
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    self.r[(word >> 16) & 0x1F] = \
                        (self.rd((word >> 21) & 0x1F) - imm) & 0xFFFFFFFF
                    self.z32 = self.r[(word >> 16) & 0x1F] == 0
                elif op == 0x38:                            # cmp38_sel
                    self.eq = self.rd((word >> 21) & 0x1F) == \
                        self.rd((word >> 11) & 0x1F)
                elif op in (0x28, 0x29):                    # b_t / b_f
                    cc = (word >> 16) & 0x1F
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    cond = self.eq if cc == 0x0A else self.z32 if cc == 0 else False
                    if (cond if op == 0x28 else not cond):
                        self.taken.append((i, op, cc, cond))
                        nxt = i + imm
                elif op == 0x25:                            # jump/call: decoder
                    import irisc_dis
                    tgt = STUB + 4 * i + irisc_dis.s24(word) * 4
                    j = (tgt - STUB) // 4
                    if 0 <= j < len(self.ws):               # intra-stub: follow
                        nxt = j
                    else:                                   # leaves the stub
                        return "FN_A"
                self.pc = nxt
            return "RUNAWAY"

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=10)

    def pay_eas(self, s):
        lo = self.R1E - 0x40 + 0x20
        return {ea for ea, v, k in s.stores if k == "STACK" and lo <= ea < lo + 0x10}

    def test_sim_fallthrough_no_store_no_push(self):
        s = self.Sim(self.ws(), 1, magic=False)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.stores, [])                      # no CR, no stack
        self.assertEqual(s.r[1], self.R1E)                  # no push: balanced

    def test_sim_n2_no_write_path_ea(self):
        # freeze at N=2 => SAVES block: N=2 exits at the L2 gate BEFORE
        # dst-init — the ONLY stack write is the saves word [r1'+0x0].
        s = self.Sim(self.ws(), 2)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(self.pay_eas(s), set())            # no write-path EA
        stack = sorted(ea for ea, v, k in s.stores if k == "STACK")
        self.assertEqual(stack, [self.R1E - 0x40])          # saves only
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 2, 2))                    # marker: N=2 -> 2
        self.assertEqual(s.r[13], 2)                        # counter untouched
        self.assertEqual(s.r[1], self.R1E)                  # pop balanced

    def test_sim_n3_pair_ea_is_dst_init_target(self):
        # freeze at N=3 => WRITE-PAIR block: dst-init + ONE pair, straight
        # line; the pair's store EA == the dst-init target [r1'+0x20].
        s = self.Sim(self.ws(), 3)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo})             # exactly the pair EA
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 3, 3))                    # marker: N=3 -> 3
        self.assertEqual(s.r[13], 3)
        self.assertEqual(s.r[1], self.R1E)

    def test_sim_n4_loop_eas_match_v5d(self):
        # freeze at N=4 => LOOP block: N=4 falls through into the
        # v5d-verbatim loop; the four loop stores land EXACTLY on v5d's EA
        # set [r1'+0x20..0x2c] (r12 re-init fixed the old absolute-EA bug);
        # the pair's identical earlier write is an idempotent duplicate.
        s = self.Sim(self.ws(), 4)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(4)})
        self.assertEqual(len([1 for ea, v, k in s.stores
                              if k == "STACK" and ea == lo]), 2)   # pair + iter-1
        vals = [v for ea, v, k in s.stores if k == "STACK" and ea == lo]
        self.assertEqual(vals[0], vals[1])                  # idempotent dup
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 4, 0))                    # marker: N=4 -> 0
        self.assertEqual(s.r[13], 0)                        # counter exhausted
        self.assertEqual(s.r[1], self.R1E)

    def test_sim_n1_echo_depth1(self):
        # documented residual: echo-N1 is no longer a pure prefix control —
        # it runs dst-init + pair + loop x1 (1-word write into its own
        # frame's payload slot, idempotent duplicate) and exits with r13=0
        # (marker N=1 -> 0, == N=4's 0 — protocol disambiguates: echo runs
        # FIRST).
        s = self.Sim(self.ws(), 1)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo})
        self.assertEqual(len([1 for ea, v, k in s.stores
                              if k == "STACK" and ea == lo]), 2)
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 1, 0))                    # == v5cA/v5cB/v5d echo
        self.assertEqual(s.r[13], 0)
        self.assertEqual(s.r[1], self.R1E)

    def test_sim_no_absolute_non_cr_writes_all_paths(self):
        # EA class of EVERY store on EVERY path: {CR 0x2380/0x2384/0x238C}
        # U {[r1'+0x0] saves} U {[r1'+0x20..0x2c] payload slot} — zero
        # absolute non-CR writes (the rev.2 regression guard).
        for N in (1, 2, 3, 4):
            s = self.Sim(self.ws(), N)
            self.assertEqual(s.run(), "FN_A", f"N={N} did not complete")
            for ea, v, k in s.stores:
                self.assertNotEqual(k, "ABS", f"N={N}: absolute write 0x{ea:x}")
            if N > 0:
                self.assertIn((0x238C, {1: 0, 2: 2, 3: 3, 4: 0}[N], "CR"),
                              s.stores)

    def test_sim_loop_entry_state_matches_v5d(self):
        # N=4 enters the loop with the SAME register state v5d would have:
        # src r11=[r1+0xac], dst r12=[r1'+0x20] (re-init), counter r13=4 —
        # plus the byte-exact loop words => EA equivalence with v5d.
        from build_s2 import stub_words
        vd = stub_words("A", version=9)
        we = self.ws()
        self.assertEqual(we[21:27], vd[15:21])              # byte-exact block
        s = self.Sim(we, 4)
        s.run()
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(lo, self.R1E - 0x20)               # dst-init target
        # the 4 distinct payload EAs are exactly the dst-init window
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(4)})


class TestS2StubV5FSim(unittest.TestCase):
    # v5f per-path REGISTER-TRUE simulation (v5e Sim, extended to FOLLOW
    # INTRA-STUB JUMPS: the gate exits w14/w21 are unconditional jump
    # words — the simulator resolves op=0x25 targets via the decoder
    # (irisc_dis: off + s24(word)*4) and follows them inside the stub;
    # only a target OUTSIDE the stub (the W_FAST tail-jump FN_A) exits).
    # Freeze-at-N=k names the block ONLY if the paths are what the
    # design says — assert EAs, marker values, CRs, stack balance AND
    # the freeze-#6 class elimination per frame.
    Sim = TestS2StubV5ESim.Sim
    R1E = TestS2StubV5ESim.R1E

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=11)

    def pay_eas(self, s):
        lo = self.R1E - 0x40 + 0x20
        return {ea for ea, v, k in s.stores if k == "STACK" and lo <= ea < lo + 0x10}

    def test_sim_fallthrough_no_store_no_push(self):
        s = self.Sim(self.ws(), 1, magic=False)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.stores, [])                      # no CR, no stack
        self.assertEqual(s.r[1], self.R1E)                  # no push: balanced
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])  # w5 taken at false

    def test_sim_n2_saves_only_via_jump_exit(self):
        # freeze at N=2 => SAVES block: the L2 gate finds equality ->
        # w13 b_f NOT-taken -> w14 UNCONDITIONAL jump -> TAIL; the ONLY
        # stack write is the saves word [r1'+0x0]; ZERO taken
        # conditionals on the whole path (the freeze-#6 class — and ANY
        # taken-conditional — never fires).
        s = self.Sim(self.ws(), 2)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(self.pay_eas(s), set())            # no write-path EA
        stack = sorted(ea for ea, v, k in s.stores if k == "STACK")
        self.assertEqual(stack, [self.R1E - 0x40])          # saves only
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 2, 2))                    # marker: N=2 -> 2
        self.assertEqual(s.r[13], 2)                        # counter untouched
        self.assertEqual(s.r[1], self.R1E)                  # pop balanced
        self.assertEqual(s.taken, [])                       # ZERO taken

    def test_sim_n3_pair_ea_is_dst_init_target(self):
        # freeze at N=3 => WRITE-PAIR block: dst-init + ONE pair, the
        # L3 gate finds equality -> w20 NOT-taken -> w21 UNCONDITIONAL
        # jump -> TAIL; the pair's store EA == the dst-init target
        # [r1'+0x20].  The ONLY taken conditional on the path is the L2
        # skip w13 b_f.cc0A at latch FALSE target +2 — the stock
        # skip-idiom skip = the live-proven clean class (w5 fallthrough,
        # x5 boots); NO taken-at-latch-true, NO taken b_t anywhere.
        s = self.Sim(self.ws(), 3)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo})             # exactly the pair EA
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 3, 3))                    # marker: N=3 -> 3
        self.assertEqual(s.r[13], 3)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [(13, 0x29, 0x0A, False)])  # w13 skip at false

    def test_sim_n4_loop_eas_match_v5d(self):
        # freeze at N=4 => LOOP block: N=4 skips BOTH gates (two taken
        # b_f-at-false skips) and falls through into the v5d-verbatim
        # loop; the four loop stores land EXACTLY on v5d's EA set
        # [r1'+0x20..0x2c]; the pair's identical earlier write is an
        # idempotent duplicate.
        s = self.Sim(self.ws(), 4)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(4)})
        self.assertEqual(len([1 for ea, v, k in s.stores
                              if k == "STACK" and ea == lo]), 2)   # pair + iter-1
        vals = [v for ea, v, k in s.stores if k == "STACK" and ea == lo]
        self.assertEqual(vals[0], vals[1])                  # idempotent dup
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 4, 0))                    # marker: N=4 -> 0
        self.assertEqual(s.r[13], 0)                        # counter exhausted
        self.assertEqual(s.r[1], self.R1E)
        # taken set: the two gate skips (b_f.cc0A at latch false) + the
        # back-edge b_f.cc00 taken x3 (Z=false while the counter runs
        # down) — the DOCUMENTED residual: N=4 is the FIRST frame that
        # executes a taken back-edge (freeze@N=4 names it)
        self.assertEqual(s.taken[:2],
                         [(13, 0x29, 0x0A, False),
                          (20, 0x29, 0x0A, False)])
        self.assertEqual(s.taken[2:],
                         [(28, 0x29, 0x00, False)] * 3)

    def test_sim_n1_echo_depth1(self):
        # documented residual (== v5e): echo-N1 runs dst-init + pair +
        # loop x1 (idempotent duplicate write) and exits with r13=0
        # (marker N=1 -> 0, == N=4's 0 — protocol disambiguates: echo
        # runs FIRST).
        s = self.Sim(self.ws(), 1)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo})
        self.assertEqual(len([1 for ea, v, k in s.stores
                              if k == "STACK" and ea == lo]), 2)
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 1, 0))                    # == v5e echo
        self.assertEqual(s.r[13], 0)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(sorted(s.taken),
                         [(13, 0x29, 0x0A, False),
                          (20, 0x29, 0x0A, False)])

    def test_sim_gate_exits_reach_tail_without_taken_conditionals(self):
        # THE freeze-#6 fix, path level: reaching TAIL on N=2/N=3 needs
        # NO taken conditional — the firing gate's b_f is NOT-taken and
        # the exit word is the UNCONDITIONAL jump (v5e reached TAIL via
        # a TAKEN b_t: the freeze).  N=2: the whole path has ZERO taken
        # conditionals; N=3: the only taken conditional is the OTHER
        # gate's skip (b_f at latch false, +2), never the exit.
        for n, firing in ((2, 13), (3, 20)):
            s = self.Sim(self.ws(), n)
            self.assertEqual(s.run(), "FN_A")
            exit_takens = [t for t in s.taken if t[0] == firing]
            self.assertEqual(exit_takens, [],
                             f"N={n}: the firing gate w{firing} is TAKEN")
            for i, op, cc, latch in s.taken:
                self.assertNotEqual(op, 0x28)               # no taken b_t
                self.assertFalse(latch)                     # none at latch-true

    def test_sim_no_taken_bt_or_latch_true_all_paths(self):
        # ALL five paths (incl. fallthrough): no b_t word is EXECUTED
        # (none exist in the table) and every TAKEN conditional is a b_f
        # at latch FALSE — either cc0A (the skip-idiom skip / filter
        # fallthrough: the live-proven clean class) or the loop
        # back-edge cc00 (N=4 only, Z=false while the counter runs down
        # — the documented residual).  The freeze classes — taken b_t
        # and ANY taken-at-latch-true — are eliminated from the path
        # set ENTIRELY.
        for N, magic in ((1, True), (2, True), (3, True), (4, True),
                         (1, False)):
            s = self.Sim(self.ws(), N, magic=magic)
            self.assertEqual(s.run(), "FN_A", f"N={N} magic={magic}")
            for i, op, cc, latch in s.taken:
                self.assertNotEqual(op, 0x28,
                                    f"N={N}: taken b_t at w{i}")
                self.assertFalse(latch,
                                 f"N={N}: taken w{i} at latch TRUE")
                self.assertIn((op, cc), {(0x29, 0x0A), (0x29, 0x00)},
                              f"N={N}: taken w{i} op=0x{op:02x} cc=0x{cc:02x}")

    def test_sim_no_absolute_non_cr_writes_all_paths(self):
        # EA class of EVERY store on EVERY path: {CR 0x2380/0x2384/
        # 0x238C} U {[r1'+0x0] saves} U {[r1'+0x20..0x2c] payload slot}
        # — zero absolute non-CR writes (rev.2 regression guard kept).
        for N in (1, 2, 3, 4):
            s = self.Sim(self.ws(), N)
            self.assertEqual(s.run(), "FN_A", f"N={N} did not complete")
            for ea, v, k in s.stores:
                self.assertNotEqual(k, "ABS", f"N={N}: absolute write 0x{ea:x}")
            if N > 0:
                self.assertIn((0x238C, {1: 0, 2: 2, 3: 3, 4: 0}[N], "CR"),
                              s.stores)

    def test_sim_loop_entry_state_matches_v5d(self):
        # N=4 enters the loop with the SAME register state v5d would
        # have: src r11=[r1+0xac], dst r12=[r1'+0x20] (re-init), counter
        # r13=4 — plus the byte-exact loop words => EA equivalence.
        from build_s2 import stub_words
        vd = stub_words("A", version=9)
        wf = self.ws()
        self.assertEqual(wf[23:29], vd[15:21])              # byte-exact block
        s = self.Sim(wf, 4)
        s.run()
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(lo, self.R1E - 0x20)               # dst-init target
        # the 4 distinct payload EAs are exactly the dst-init window
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(4)})


class TestS2StubV5G(unittest.TestCase):
    # v5g (T28, linear fork-test stub): v5b flow MINUS gauntlet MINUS
    # payload-block MINUS ALL N-gates — fully LINEAR (the only clean
    # magic-run shape: v5cA and echo-N1 were linear).  Prefix w0-w10 =
    # v5e/v5f byte-exact (only w5's immediate retargets +26 -> +17 to
    # the new W_FAST @w22 — the shorter stub shifts it; 0xA40A0011
    # stock-exact x15); NO N==4 guard (all N in {1..4} proceed);
    # dst-init + ONE ld.d/st.d pair + the v5d-VERBATIM do-while loop
    # (w14-w19 == v5d w15-w20 byte-exact; runs xN, back-edge taken xN-1)
    # -> TAIL marker st.d r13,zero,0x238C (r13=0 after the loop for
    # every N>=1 — uninformative value, live-form kept for uniformity)
    # -> pop -> W_FAST jump FN_A LAST (w22 = 0x38d7a8).  ZERO gates,
    # ZERO skips, ZERO b_t words: the ONLY conditional words are the
    # filter b_f (w5) and the loop back-edge b_f (w19); the ONLY jump
    # word is W_FAST.  23 of 34 zone words (brief's ~26-28 estimate was
    # high: v5f 32 - L2 gate 4 - L3 gate 4 - dst re-init 1 = 23).
    V5G_GOLDEN = [
        0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
        0xA40A0011, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x703F0FC2,
        0x6C201802, 0x002C0020, 0x65630002, 0x6D801802,
        0x65630002, 0x6D801802, 0x016B0004, 0x018C0004,
        0x15AD0001, 0xA400FFFB, 0x6C046B8E, 0x00210040, 0x95F8006F,
    ]

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=12)

    def test_v5g_golden_words(self):
        self.assertEqual(self.ws(), self.V5G_GOLDEN)

    def test_v5g_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5g"), stub_words("A", version=12))
        self.assertEqual(stub_words("A", version="v5g"), stub_words("A", version=12))

    def test_v5g_prefix_v5f_w5_imm_only(self):
        # THE prefix contract: w0-w4 and w6-w10 == v5f (= v5e) BYTE-EXACT;
        # the ONLY delta is w5's IMMEDIATE field (+26 -> +17: W_FAST moved
        # from w31 to w22 with the shorter stub) — op/cc bits identical.
        from build_s2 import stub_words
        wf, wg = stub_words("A", version=11), self.ws()
        self.assertEqual(wg[0:5], wf[0:5])
        self.assertEqual(wg[6:11], wf[6:11])
        self.assertEqual(wg[5], 0xA40A0011)                 # b_f.cc0A +17
        self.assertEqual((wg[5] >> 16), (wf[5] >> 16))      # op+cc identical
        self.assertEqual((wf[5] & 0xFFFF) - (wg[5] & 0xFFFF), 9)   # imm 26->17
        self.assertEqual(wg[9], 0x703F0FC2)                 # push right after echo
        self.assertEqual(wg[10], 0x6C201802)                # saves (v5b-verbatim)

    def test_v5g_linear_zero_bt_single_jump(self):
        # THE fork-test shape, word level: NO op=0x28 (b_t) words; the
        # ONLY jump/call (op=0x25) word is W_FAST (w22, last); the ONLY
        # conditional branch words are the filter b_f (w5) and the loop
        # back-edge b_f (w19) — ZERO gates, ZERO skips.
        wd = self.ws()
        for i, w in enumerate(wd):
            self.assertNotEqual(w >> 26, 0x28, f"w{i}=0x{w:08x} is b_t")
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x25],
                         [22])                              # W_FAST only
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x29],
                         [5, 19])                           # filter + back-edge

    def test_v5g_gate_gauntlet_words_gone(self):
        # the v5f gate/skip words and the v5b gauntlet/N-guard words are
        # ALL absent: nothing gates on N, nothing checks the copied data,
        # nothing skips forward.
        wd = self.ws()
        for w in (0x200C0002, 0x200C0003, 0xE1A06002, 0xA40A0002,
                  0x9500000F, 0x95000008,          # v5f L2/L3 gates
                  0xA00A000E, 0xA00A0008,          # v5e b_t exits
                  0x200C0004, 0xA40A0015,          # v5b N-guard
                  0x200D2407):                    # v5b gauntlet const
            self.assertNotIn(w, wd, f"gate/gauntlet word 0x{w:08x} present")

    def test_v5g_suspects_v5d_verbatim(self):
        # saves / dst-init / pair: the v5d-verbatim suspect words at
        # their v5e positions (no gates => no +1 shift, no re-init).
        wd = self.ws()
        self.assertEqual(wd[10], 0x6C201802)                # saves (v5e w10)
        self.assertEqual(wd[11], 0x002C0020)                # dst-init (v5e w14)
        self.assertEqual(wd[12:14], [0x65630002, 0x6D801802])   # pair (v5e w15/16)
        # NO dst re-init: nothing clobbers r12 between w11 and the loop
        self.assertEqual(wd.count(0x002C0020), 1)

    def test_v5g_loop_v5d_verbatim(self):
        # the loop block w14-w19 == v5d w15-w20 BYTE-EXACT (ld.d/st.d
        # pair, strides, subsi, back-edge -5): every magic N in {1..4}
        # falls straight from the pair into the v5d-verbatim do-while
        # loop and runs it xN.
        from build_s2 import stub_words
        self.assertEqual(self.ws()[14:20], stub_words("A", version=9)[15:21])

    def test_v5g_shared_tail(self):
        # TAIL = marker st.d r13,zero,0x238C (r13=0 for every N>=1 after
        # the do-while loop — uninformative, live-form) -> pop -> W_FAST
        # jump FN_A LAST (w22 = 0x38d7a8).
        wd = self.ws()
        self.assertEqual(wd[20], 0x6C046B8E)                # marker 0x238C
        self.assertEqual(wd[21], enc.addi(1, 1, 0x40))      # pop, stock x185
        self.assertEqual(wd[22], enc.jump(STUB + 4 * 22, 0x18D964))
        self.assertEqual(wd[22], 0x95F8006F)

    def test_v5g_branches(self):
        wd = self.ws()
        w_fast = STUB + 4 * 22
        self.assertEqual(len(wd), 23)
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))    # filter
        self.assertEqual(wd[19], enc.b_f(0x00, STUB + 4 * 19, STUB + 4 * 14))  # loop

    def test_v5g_word_set_delta_vs_v5f(self):
        # word-level diff-vs-v5f confined: v5f-only words = exactly the
        # gate/skip/jump set + the old W_FAST; v5g-only words = exactly
        # the recomputed w5 imm + the new W_FAST imm.
        from build_s2 import stub_words
        wf = stub_words("A", version=11)
        wg = self.ws()
        self.assertEqual(set(wf) - set(wg),
                         {0xA40A001A, 0x200C0002, 0x200C0003, 0xE1A06002,
                          0xA40A0002, 0x9500000F, 0x95000008, 0x95F80066})
        self.assertEqual(set(wg) - set(wf), {0xA40A0011, 0x95F8006F})
        # the dst re-init word drops from x2 to x1 (multiset level)
        self.assertEqual(wf.count(0x002C0020), 2)
        self.assertEqual(wg.count(0x002C0020), 1)

    def test_v5g_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 23)                # 23/34
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5g_clobber_confined(self):
        import irisc_dis
        dec = [irisc_dis.dis(w, 0) for w in self.ws()]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5g_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=12)

    def test_v5g_stock_precedents(self):
        # NEW-word stock counts (clean blob whole-image, census as the
        # v5e/v5f tasks; re-verified for v5g's recomputed immediates):
        #   w5 retarget b_f.cc0A +17 (0xA40A0011) x15
        #   W_FAST jump FN_A imm recomputed (0x95F8006F) x0 — live-form
        #     class (every prior W_FAST word 0-count, live-clean x5+)
        # REMOVED v5f words (stock-exact, gone from the stub):
        #   gate skip 0xA40A0002 x94 / L2 exit 0x9500000F x222 /
        #   L3 exit 0x95000008 x365 / old w5 0xA40A001A x10 /
        #   old W_FAST 0x95F80066 x0.
        # Loop words as v5d (live lineage): 0x65630002 x1 / 0x6D801802
        #   x46 / 0x016B0004 x6 / 0x018C0004 x3 / 0xA400FFFB x314.
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        cnt = lambda x: sum(1 for w in words if w == x)
        ws = self.ws()
        self.assertEqual(cnt(0xA40A0011), 15)               # w5 retarget
        self.assertEqual(cnt(0x95F8006F), 0)                # W_FAST: live-form
        self.assertEqual(cnt(0xA40A0002), 94)               # v5f skip (removed)
        self.assertEqual(cnt(0x9500000F), 222)              # v5f L2 exit (removed)
        self.assertEqual(cnt(0x95000008), 365)              # v5f L3 exit (removed)
        self.assertEqual(cnt(0xA40A001A), 10)               # v5f w5 (removed)
        self.assertEqual(cnt(0xE1A06002), 0)                # gate cmp: live (absent)
        self.assertEqual(cnt(0x6C046B8E), 0)                # marker: live
        self.assertEqual(cnt(0x6C201802), 0)                # saves: 0-combo
        self.assertEqual(cnt(0x002C0020), 0)                # dst-init: 0-TUPLE
        self.assertEqual(cnt(0x15AD0001), 0)                # subsi rd=13
        for w in (0x65630002, 0x6D801802, 0x016B0004, 0x018C0004, 0xA400FFFB):
            self.assertGreater(cnt(w), 0)
        self.assertEqual(cnt(0x65630002), 1)
        self.assertEqual(cnt(0x6D801802), 46)
        self.assertEqual(cnt(0x016B0004), 6)
        self.assertEqual(cnt(0x018C0004), 3)
        self.assertEqual(cnt(0xA400FFFB), 314)
        # every word of the stub is stock-exact, live-exact (v5b/v5cA/
        # v5cB/v5d/v5e/v5f lineage goldens) or documented (imm-recomputed)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7)) \
            | set(stub_words("A", version=8)) | set(stub_words("A", version=9)) \
            | set(stub_words("A", version=10)) | set(stub_words("A", version=11))
        documented = {0xA40A0011, 0x95F8006F}   # recomputed imms, stock/live forms
        for w in ws:
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5g_lineage_untouched(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)
        self.assertEqual(len(stub_words("A", version=9)), 33)
        self.assertEqual(len(stub_words("A", version=10)), 30)
        self.assertEqual(len(stub_words("A", version=11)), 32)


class TestS2StubV5H(unittest.TestCase):
    # v5h (T29, named-suspect SAVE test): v5g MINUS the save word —
    # `st.d r3,r1,0x0` (v5g w10 = 0x6C201802, the sole surviving
    # 0-combo rt=3∧rs=r1∧off=0 store; stock census x0) is named the
    # freeze common-denominator (journal task-28 phase-2: freeze@N=2 on
    # the fully-linear v5g + ledger — SAVE ran on every freeze path AND
    # every clean magic path, the tail-frames being the difference);
    # r3 is dead at the detour per R3 — the save was vestigial paranoia.
    # Everything else keeps the v5g shape byte-exact: prefix w0-w4/
    # w6-w9 == v5g (only w5's immediate retargets +17 -> +16, W_FAST
    # w22 -> w21 with the -1 word shift: 0xA40A0010 stock-exact x22)
    # -> push -> [NO SAVE] -> dst-init (w10, the v5d word) -> pair
    # (w11-w12, v5d words) -> loop w13-w18 == v5d w15-w20 byte-exact
    # (the back-edge word 0xA400FFFB is UNCHANGED: its -5 offset is
    # relative, both ends shifted together) -> TAIL marker st.d r13,
    # zero,0x238C -> pop -> W_FAST jump FN_A LAST (w21 = 0x38d7a4,
    # 0x95F80070 live-form x0).  22 of 34 zone words (v5g 23 - 1).
    V5H_GOLDEN = [
        0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
        0xA40A0010, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x703F0FC2,
        0x002C0020,
        0x65630002, 0x6D801802,
        0x65630002, 0x6D801802, 0x016B0004, 0x018C0004,
        0x15AD0001, 0xA400FFFB, 0x6C046B8E, 0x00210040, 0x95F80070,
    ]

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=13)

    def test_v5h_golden_words(self):
        self.assertEqual(self.ws(), self.V5H_GOLDEN)

    def test_v5h_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5h"), stub_words("A", version=13))
        self.assertEqual(stub_words("A", version="v5h"), stub_words("A", version=13))

    def test_v5h_save_word_absent(self):
        # THE named-suspect contract: the SAVE word `st.d r3,r1,0x0`
        # (v5g w10 = 0x6C201802) is ABSENT from v5h — asserted BOTH as
        # the literal AND decoded (no op=0x1B store with rs=r1, rt=3,
        # off=0 anywhere).  The PUSH (0x703F0FC2, st.d! r1,r1,-0x40 —
        # the frame-allocation word, NOT the r3 save) stays stock-exact.
        wd = self.ws()
        self.assertNotIn(0x6C201802, wd)
        for i, w in enumerate(wd):
            if (w >> 26) == 0x1B:
                rs, rt = (w >> 21) & 0x1F, (w >> 11) & 0x1F
                off = (((w >> 16) & 0x1F) << 11) | (((w >> 2) & 0x1FF) << 2)
                self.assertFalse(rs == 1 and rt == 3 and off == 0,
                                 f"w{i}=0x{w:08x} is the 0-combo save")
        self.assertIn(0x703F0FC2, wd)                      # push: stock-exact

    def test_v5h_prefix_v5g_w5_imm_only(self):
        # THE prefix contract vs v5g: w0-w4 and w6-w9 == v5g BYTE-EXACT
        # (push w9 included); the ONLY prefix delta is w5's IMMEDIATE
        # (+17 -> +16: W_FAST moved w22 -> w21 when the save dropped) —
        # op+cc bits identical; w10 is the dst-init (v5g's w11) — the
        # save's slot is RE-USED by the next word, not zero-padded.
        from build_s2 import stub_words
        wg, wh = stub_words("A", version=12), self.ws()
        self.assertEqual(wh[0:5], wg[0:5])
        self.assertEqual(wh[6:10], wg[6:10])
        self.assertEqual(wh[5], 0xA40A0010)                 # b_f.cc0A +16
        self.assertEqual((wh[5] >> 16), (wg[5] >> 16))      # op+cc identical
        self.assertEqual((wg[5] & 0xFFFF) - (wh[5] & 0xFFFF), 1)   # imm 17->16
        self.assertEqual(wh[9], 0x703F0FC2)                 # push right after echo
        self.assertEqual(wh[10], 0x002C0020)                # dst-init in save slot

    def test_v5h_linear_zero_bt_single_jump(self):
        # THE v5g linearity contract carried over, word level: NO
        # op=0x28 (b_t) words; the ONLY jump/call (op=0x25) word is
        # W_FAST (w21, last); the ONLY conditional branch words are the
        # filter b_f (w5) and the loop back-edge b_f (w18).
        wd = self.ws()
        for i, w in enumerate(wd):
            self.assertNotEqual(w >> 26, 0x28, f"w{i}=0x{w:08x} is b_t")
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x25],
                         [21])                              # W_FAST only
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x29],
                         [5, 18])                           # filter + back-edge

    def test_v5h_gate_gauntlet_words_gone(self):
        # nothing gates on N, nothing checks the copied data, nothing
        # skips forward (v5g contract, regression-guarded).
        wd = self.ws()
        for w in (0x200C0002, 0x200C0003, 0xE1A06002, 0xA40A0002,
                  0x9500000F, 0x95000008,          # v5f L2/L3 gates
                  0xA00A000E, 0xA00A0008,          # v5e b_t exits
                  0x200C0004, 0xA40A0015,          # v5b N-guard
                  0x200D2407):                    # v5b gauntlet const
            self.assertNotIn(w, wd, f"gate/gauntlet word 0x{w:08x} present")

    def test_v5h_dst_pair_loop(self):
        # dst-init + pair at their shifted positions (v5d-verbatim
        # words); dst-init exactly once (nothing clobbers r12).
        wd = self.ws()
        self.assertEqual(wd[10], 0x002C0020)                # dst-init (v5d word)
        self.assertEqual(wd[11:13], [0x65630002, 0x6D801802])   # pair (v5d words)
        self.assertEqual(wd.count(0x002C0020), 1)           # no re-init

    def test_v5h_loop_v5d_verbatim(self):
        # the loop block w13-w18 == v5d w15-w20 BYTE-EXACT (ld.d/st.d
        # pair, strides, subsi, back-edge -5): every magic N in {1..4}
        # falls straight from the pair into the v5d-verbatim do-while
        # loop and runs it xN.
        from build_s2 import stub_words
        self.assertEqual(self.ws()[13:19], stub_words("A", version=9)[15:21])

    def test_v5h_shared_tail(self):
        # TAIL = marker st.d r13,zero,0x238C (r13=0 for every N>=1
        # after the do-while loop — uninformative, live-form) -> pop ->
        # W_FAST jump FN_A LAST (w21 = 0x38d7a4).
        wd = self.ws()
        self.assertEqual(wd[19], 0x6C046B8E)                # marker 0x238C
        self.assertEqual(wd[20], enc.addi(1, 1, 0x40))      # pop, stock x185
        self.assertEqual(wd[21], enc.jump(STUB + 4 * 21, 0x18D964))
        self.assertEqual(wd[21], 0x95F80070)

    def test_v5h_branches(self):
        wd = self.ws()
        w_fast = STUB + 4 * 21
        self.assertEqual(len(wd), 22)
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))    # filter
        self.assertEqual(wd[18], enc.b_f(0x00, STUB + 4 * 18, STUB + 4 * 13))  # loop

    def test_v5h_word_delta_vs_v5g_exactly_save_plus_imms(self):
        # THE diff-vs-v5g contract: v5h == v5g with EXACTLY the save
        # word removed + the two position-dependent immediates
        # recomputed (w5 filter +17 -> +16; W_FAST imm 0x6F -> 0x70).
        # Positional: w0-w9 == v5g w0-w9 except w5's imm field;
        # w10-w19 == v5g w11-w20 BYTE-EXACT (the shifted body).
        from build_s2 import stub_words
        wg, wh = stub_words("A", version=12), self.ws()
        self.assertEqual(wh[10:20], wg[11:21])              # the shifted body
        self.assertEqual(wh[0:5] + wh[6:10],
                         wg[0:5] + wg[6:10])                # prefix sans w5
        self.assertEqual(set(wg) - set(wh),
                         {0x6C201802, 0xA40A0011, 0x95F8006F})
        self.assertEqual(set(wh) - set(wg), {0xA40A0010, 0x95F80070})
        self.assertEqual(wg.count(0x6C201802), 1)           # the save, gone
        self.assertEqual(wh.count(0x6C201802), 0)
        for w in (0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
                  0x6C046382, 0x642D00A5, 0x6C046B86, 0x703F0FC2, 0x002C0020,
                  0x65630002, 0x6D801802, 0x016B0004, 0x018C0004, 0x15AD0001,
                  0xA400FFFB, 0x6C046B8E, 0x00210040):
            self.assertEqual(wh.count(w), wg.count(w), f"count drift 0x{w:08x}")

    def test_v5h_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 22)                # 22/34
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5h_clobber_confined(self):
        import irisc_dis
        dec = [irisc_dis.dis(w, 0) for w in self.ws()]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5h_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=13)

    def test_v5h_stock_precedents(self):
        # NEW-word stock counts (clean blob whole-image census, as the
        # v5e/v5f/v5g tasks):
        #   w5 retarget b_f.cc0A +16 (0xA40A0010) x22 — stock-exact
        #   W_FAST jump FN_A imm recomputed (0x95F80070) x0 — live-form
        #     class (every prior W_FAST word 0-count, live-clean x6+)
        # REMOVED v5g word: the save 0x6C201802 x0 — the 0-COMBO
        #   (rt=3, rs=1, off=0; the named suspect, absent from stock).
        # Loop words unchanged (v5d live lineage): 0x65630002 x1 /
        #   0x6D801802 x46 / 0x016B0004 x6 / 0x018C0004 x3 /
        #   0xA400FFFB x314.
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        cnt = lambda x: sum(1 for w in words if w == x)
        ws = self.ws()
        self.assertEqual(cnt(0xA40A0010), 22)               # w5 retarget
        self.assertEqual(cnt(0x95F80070), 0)                # W_FAST: live-form
        self.assertEqual(cnt(0x6C201802), 0)                # save: the 0-combo
        self.assertEqual(cnt(0xA40A0011), 15)               # v5g w5 (removed)
        self.assertEqual(cnt(0x95F8006F), 0)                # v5g W_FAST (removed)
        self.assertEqual(cnt(0x6C046B8E), 0)                # marker: live
        self.assertEqual(cnt(0x002C0020), 0)                # dst-init: 0-TUPLE
        self.assertEqual(cnt(0x15AD0001), 0)                # subsi rd=13
        for w in (0x65630002, 0x6D801802, 0x016B0004, 0x018C0004, 0xA400FFFB):
            self.assertGreater(cnt(w), 0)
        self.assertEqual(cnt(0x65630002), 1)
        self.assertEqual(cnt(0x6D801802), 46)
        self.assertEqual(cnt(0x016B0004), 6)
        self.assertEqual(cnt(0x018C0004), 3)
        self.assertEqual(cnt(0xA400FFFB), 314)
        # every word of the stub is stock-exact, live-exact (v5b/v5cA/
        # v5cB/v5d/v5e/v5f/v5g lineage goldens) or documented
        # (imm-recomputed)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7)) \
            | set(stub_words("A", version=8)) | set(stub_words("A", version=9)) \
            | set(stub_words("A", version=10)) | set(stub_words("A", version=11)) \
            | set(stub_words("A", version=12))
        documented = {0xA40A0010, 0x95F80070}   # recomputed imms, stock/live forms
        for w in ws:
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5h_lineage_untouched(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)
        self.assertEqual(len(stub_words("A", version=9)), 33)
        self.assertEqual(len(stub_words("A", version=10)), 30)
        self.assertEqual(len(stub_words("A", version=11)), 32)
        self.assertEqual(len(stub_words("A", version=12)), 23)


class TestS2StubV5I(unittest.TestCase):
    # v5i (T31, neutral-write discriminator): v5h with the pair+loop
    # block REPLACED by ONE NEUTRAL-CONSTANT frame write — `set3 r12,
    # zero,0xA5A5` + `st.d r12,r1,0x30` — NO input-derived values in
    # the write path (journal task-29 phase-2, freeze #9: tail-frame ×
    # ANY extra write into the pushed frame => freeze — save OR copies;
    # push-ra + CR writes always clean).  Fork: freeze => H-FRAMEGUARD
    # (ANY extra frame-write x tail-frame, content-independent); clean
    # => H-CONTENT (copied VALUES were the trigger; neutral constant
    # safe).  Prefix w0-w9 == v5h byte-exact (only w5's immediate
    # retargets +16 -> +9 to the new W_FAST @w14: 0xA40A0009
    # stock-exact x48 — the best count of the whole lineage); NO save,
    # NO dst-init, NO pair, NO loop, NO back-edge (conditionals =
    # filter w5 ONLY; N echoed 0x2384=N, never used for control).
    # TAIL marker word unchanged (st.d r13,zero,0x238C) — with the
    # loop GONE nothing zeroes r13, so a clean completion leaves
    # 0x238C = N (documented erratum vs the brief's "0x238C=0": the
    # word-level "TAIL unchanged" mandate wins; v5e/v5f marker
    # precedent is "r13 as-is"; freeze => 0x238C stays at the fresh
    # baseline 0 — the marker is the LAST CR write on the path).
    # 15 of 34 zone words; W_FAST @w14 = 0x38d788 (last).
    V5I_GOLDEN = [
        0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
        0xA40A0009, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x703F0FC2,
        0x200CA5A5, 0x6C206032, 0x6C046B8E, 0x00210040, 0x95F80077,
    ]

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=14)

    def test_v5i_golden_words(self):
        self.assertEqual(self.ws(), self.V5I_GOLDEN)

    def test_v5i_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5i"), stub_words("A", version=14))
        self.assertEqual(stub_words("A", version="v5i"), stub_words("A", version=14))

    def test_v5i_prefix_v5h_w5_imm_only(self):
        # THE prefix contract vs v5h: w0-w9 == v5h BYTE-EXACT (prefix +
        # push) except w5's IMMEDIATE (+16 -> +9: W_FAST moved w21 -> w14
        # when the copy block collapsed); op+cc bits identical.
        from build_s2 import stub_words
        wh, wi = stub_words("A", version=13), self.ws()
        self.assertEqual(len(wh), 22)
        self.assertEqual(wi[0:5], wh[0:5])
        self.assertEqual(wi[6:10], wh[6:10])
        self.assertEqual(wi[5], 0xA40A0009)                 # b_f.cc0A +9
        self.assertEqual((wi[5] >> 16), (wh[5] >> 16))      # op+cc identical
        self.assertEqual((wh[5] & 0xFFFF) - (wi[5] & 0xFFFF), 7)   # imm 16->9
        self.assertEqual(wi[9], 0x703F0FC2)                 # push right after echo

    def test_v5i_copy_block_gone(self):
        # THE neutral-write contract: the ENTIRE v5h write path after
        # the push is GONE — no save (already dropped in v5h), no
        # dst-init, no ld.d/st.d pair, no loop (data words, strides,
        # subsi counter, back-edge).  Nothing reads the payload window.
        wd = self.ws()
        for w in (0x6C201802,                   # save (v5h: already absent)
                  0x002C0020,                   # dst-init
                  0x65630002, 0x6D801802,       # pair + loop-head ld.d/st.d
                  0x016B0004, 0x018C0004,       # strides
                  0x15AD0001,                   # subsi counter
                  0xA400FFFB):                  # back-edge
            self.assertNotIn(w, wd, f"copy-block word 0x{w:08x} present")
        # no ld.d words at all (op 0x19 with bit0=0): nothing loads
        # from the input/payload window — the write path is const-only
        for i, w in enumerate(wd):
            if (w >> 26) == 0x19:
                self.assertTrue(w & 1, f"w{i}=0x{w:08x} is a 32-bit load")

    def test_v5i_zero_bt_single_jump_filter_only(self):
        # THE linearity contract, strongest of the lineage: NO b_t
        # words; the ONLY jump word is W_FAST (w14, last); the ONLY
        # conditional branch word is the filter b_f (w5) — the loop is
        # GONE, there is NO back-edge.
        wd = self.ws()
        for i, w in enumerate(wd):
            self.assertNotEqual(w >> 26, 0x28, f"w{i}=0x{w:08x} is b_t")
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x25],
                         [14])                              # W_FAST only
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x29],
                         [5])                               # filter ONLY

    def test_v5i_neutral_write_words(self):
        # THE discriminator words: set3 r12,zero,0xA5A5 (live FORM:
        # set3 r12,zero,* — stock x11 + v5b/v5cA-live consts) feeding
        # st.d r12,r1,0x30 (STOCK-EXACT x1 — the precedented tuple; the
        # brief's fallback clause never fires).  The store target is
        # the free frame slot 0x30 (between PAY_OFF window 0x20..0x30
        # and RES_OFF 0x34) — a slot NO prior version ever wrote.
        wd = self.ws()
        self.assertEqual(wd[10], enc.set3(12, 0, 0xA5A5))
        self.assertEqual(wd[10], 0x200CA5A5)
        self.assertEqual(wd[11], enc.st_d(12, 1, 0x30))
        self.assertEqual(wd[11], 0x6C206032)
        self.assertEqual((wd[10] >> 26), 0x08)
        self.assertEqual(((wd[10] >> 21) & 0x1F), 0)        # rs = zero
        self.assertEqual(((wd[10] >> 16) & 0x1F), 12)       # rd = r12
        self.assertEqual((wd[11] >> 26), 0x1B)
        self.assertEqual(((wd[11] >> 21) & 0x1F), 1)        # rs = r1 (frame)
        self.assertEqual(((wd[11] >> 11) & 0x1F), 12)       # rt = r12
        off = (((wd[11] >> 16) & 0x1F) << 11) | (((wd[11] >> 2) & 0x1FF) << 2)
        self.assertEqual(off, 0x30)

    def test_v5i_neutral_value_not_input_derived(self):
        # content-neutrality, dataflow level: the const def (w10: set3
        # r12,zero,0xA5A5 — sources are the ZERO-REG + imm, no register
        # input) is IMMEDIATELY followed by the frame store (w11:
        # st.d r12,r1,0x30) — nothing can interpose, so the stored
        # value is the compile-time constant 0xA5A5 on EVERY path.
        # (The prefix ld.w into r12 @w2 is 8 words earlier and feeds
        # only the filter cmp + CR echo.)
        import irisc_dis
        wd = self.ws()
        dec = [irisc_dis.dis(w, 0) for w in wd]
        self.assertTrue(dec[10].startswith("set3 r12,zero,"))
        self.assertTrue(dec[11].startswith("st.d r12,r1,0x30"))

    def test_v5i_shared_tail(self):
        # TAIL = marker st.d r13,zero,0x238C (the v5h w19 WORD
        # unchanged; r13 = N here — the loop that zeroed it is gone)
        # -> pop -> W_FAST jump FN_A LAST (w14 = 0x38d788).
        wd = self.ws()
        self.assertEqual(wd[12], 0x6C046B8E)                # marker word
        self.assertEqual(wd[13], enc.addi(1, 1, 0x40))      # pop, stock x185
        self.assertEqual(wd[14], enc.jump(STUB + 4 * 14, 0x18D964))
        self.assertEqual(wd[14], 0x95F80077)

    def test_v5i_branches(self):
        wd = self.ws()
        w_fast = STUB + 4 * 14
        self.assertEqual(len(wd), 15)
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))    # filter
        self.assertNotIn(enc.b_f(0x00, 0, 0), wd)          # no cc00 back-edge form

    def test_v5i_word_delta_vs_v5h_exactly_copy_block_plus_imms(self):
        # THE diff-vs-v5h contract: v5i == v5h with EXACTLY the copy
        # block removed (dst-init + pair + loop: 8 distinct words, the
        # ld.d/st.d pair words each x2 in v5h) + the neutral pair
        # inserted + the two position-dependent immediates recomputed
        # (w5 filter +16 -> +9; W_FAST imm 0x70 -> 0x77).
        from build_s2 import stub_words
        wh, wi = stub_words("A", version=13), self.ws()
        self.assertEqual(set(wh) - set(wi),
                         {0x002C0020, 0x65630002, 0x6D801802, 0x016B0004,
                          0x018C0004, 0x15AD0001, 0xA400FFFB,
                          0xA40A0010, 0x95F80070})
        self.assertEqual(set(wi) - set(wh),
                         {0x200CA5A5, 0x6C206032, 0xA40A0009, 0x95F80077})
        for w in (0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
                  0x6C046382, 0x642D00A5, 0x6C046B86, 0x703F0FC2,
                  0x6C046B8E, 0x00210040):
            self.assertEqual(wi.count(w), wh.count(w), f"count drift 0x{w:08x}")

    def test_v5i_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 15)                # 15/34
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5i_clobber_confined(self):
        import irisc_dis
        dec = [irisc_dis.dis(w, 0) for w in self.ws()]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5i_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=14)

    def test_v5i_stock_precedents(self):
        # NEW-word stock counts (clean blob whole-image census):
        #   w10 set3 r12,zero,0xA5A5 (0x200CA5A5) x0 — live-FORM class
        #     (set3 r12,zero,* stock x11; v5b N-guard 0x200C0004 +
        #     v5cA markers 0x200C0001/2/3 ran clean live)
        #   w11 st.d r12,r1,0x30 (0x6C206032) x1 — STOCK-EXACT, the
        #     neutral-write tuple is precedented (no fallback offset
        #     needed); class st.d rt=12,rs=r1,* = x26
        #   w5 retarget b_f.cc0A +9 (0xA40A0009) x48 — stock-exact,
        #     the BEST count of the lineage's w5 immediates
        #   W_FAST jump imm recomputed (0x95F80077) x0 — live-form
        #     class (every prior W_FAST word 0-count, live-clean x6+)
        # REMOVED v5h words: copy block 0x002C0020 x0 / 0x65630002 x1 /
        #   0x6D801802 x46 / 0x016B0004 x6 / 0x018C0004 x3 /
        #   0x15AD0001 x0 / 0xA400FFFB x314; w5 imm 0xA40A0010 x22;
        #   W_FAST 0x95F80070 x0.
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        cnt = lambda x: sum(1 for w in words if w == x)
        ws = self.ws()
        self.assertEqual(cnt(0x200CA5A5), 0)                # neutral const
        self.assertEqual(cnt(0x6C206032), 1)                # neutral store
        self.assertEqual(cnt(0xA40A0009), 48)               # w5 retarget
        self.assertEqual(cnt(0x95F80077), 0)                # W_FAST: live-form
        form = sum(1 for w in words if (w >> 26) == 0x08
                   and ((w >> 21) & 0x1F) == 0 and ((w >> 16) & 0x1F) == 12)
        self.assertEqual(form, 11)                          # set3 r12,zero,*
        cls = sum(1 for w in words if (w >> 26) == 0x1B
                  and ((w >> 21) & 0x1F) == 1 and ((w >> 11) & 0x1F) == 12)
        self.assertEqual(cls, 26)                           # st.d r12,r1,*
        # every word of the stub is stock-exact, live-exact (v5b..v5h
        # lineage goldens) or documented (imm-recomputed / new const)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7)) \
            | set(stub_words("A", version=8)) | set(stub_words("A", version=9)) \
            | set(stub_words("A", version=10)) | set(stub_words("A", version=11)) \
            | set(stub_words("A", version=12)) | set(stub_words("A", version=13))
        documented = {0x200CA5A5, 0xA40A0009, 0x95F80077}
        for w in ws:
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5i_lineage_untouched(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)
        self.assertEqual(len(stub_words("A", version=9)), 33)
        self.assertEqual(len(stub_words("A", version=10)), 30)
        self.assertEqual(len(stub_words("A", version=11)), 32)
        self.assertEqual(len(stub_words("A", version=12)), 23)
        self.assertEqual(len(stub_words("A", version=13)), 22)


class TestS2StubV5GSim(unittest.TestCase):
    # v5g per-path REGISTER-TRUE simulation (v5e/v5f Sim reused: follows
    # intra-stub jumps — v5g has none except the back-edge — and logs
    # every taken conditional).  BRANCH INVENTORY per path is THE
    # fork-test contract: N=1 zero taken conditionals; N=2/3/4 the loop
    # back-edge b_f.cc00 taken x(N-1) at latch FALSE — nothing else can
    # ever fire on a magic path (no gates, no skips; the filter b_f is
    # not-taken at magic).
    Sim = TestS2StubV5ESim.Sim
    R1E = TestS2StubV5ESim.R1E

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=12)

    def pay_eas(self, s):
        lo = self.R1E - 0x40 + 0x20
        return {ea for ea, v, k in s.stores if k == "STACK" and lo <= ea < lo + 0x10}

    def test_sim_fallthrough_no_store_no_push(self):
        s = self.Sim(self.ws(), 1, magic=False)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.stores, [])                      # no CR, no stack
        self.assertEqual(s.r[1], self.R1E)                  # no push: balanced
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])  # w5 taken at false

    def test_sim_n1_echo_depth1_zero_taken(self):
        # N=1 (echo frame, 24B no tail): the regression path — the SAME
        # linear shape v5e/v5f echo-N1 ran clean live x2 (prefix + push +
        # saves + dst-init + pair + loop x1 + marker + pop + W_FAST);
        # loop x1 exhausts the counter on the first subsi => the
        # back-edge is NOT taken: ZERO taken conditionals on the path.
        s = self.Sim(self.ws(), 1, code=[0xFC001825])
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo})             # pair + loop-x1 EA
        self.assertEqual([v for ea, v, k in s.stores
                          if k == "STACK" and ea == lo],
                         [0xFC001825, 0xFC001825])          # idempotent dup
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 1, 0))                    # marker: N=1 -> 0
        self.assertEqual(s.r[13], 0)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [])                       # ZERO taken

    def test_sim_n2_back_edge_taken_once(self):
        # N=2 (neg-family frame, 28B WITH payload tail): loop x2 — the
        # back-edge taken x1; the write path covers [r1'+0x20..0x24].
        s = self.Sim(self.ws(), 2)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo, lo + 4})     # pair + loop x2
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 2, 0))                    # marker: 0 (r13 end)
        self.assertEqual(s.r[13], 0)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [(19, 0x29, 0x00, False)])  # back-edge x1

    def test_sim_n3_back_edge_taken_twice(self):
        s = self.Sim(self.ws(), 3)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(3)})
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 3, 0))
        self.assertEqual(s.r[13], 0)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [(19, 0x29, 0x00, False)] * 2)  # back-edge x2

    def test_sim_n4_back_edge_taken_thrice_eas_match_v5d(self):
        # N=4 (neg-family frame, 36B): FULL copy — the four loop stores
        # land EXACTLY on v5d's EA set [r1'+0x20..0x2c]; the pair's
        # identical earlier write is an idempotent duplicate.
        s = self.Sim(self.ws(), 4)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(4)})
        self.assertEqual(len([1 for ea, v, k in s.stores
                              if k == "STACK" and ea == lo]), 2)   # pair + iter-1
        vals = [v for ea, v, k in s.stores if k == "STACK" and ea == lo]
        self.assertEqual(vals[0], vals[1])                  # idempotent dup
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 4, 0))
        self.assertEqual(s.r[13], 0)                        # counter exhausted
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [(19, 0x29, 0x00, False)] * 3)  # back-edge x3

    def test_sim_branch_inventory_per_path(self):
        # THE fork-test branch-inventory table: magic N=1 -> ZERO taken
        # conditionals; N=2/3/4 -> back-edge b_f.cc00 @w19 taken x(N-1),
        # at latch FALSE, and NOTHING else fires (the filter b_f w5 is
        # not-taken on every magic path).
        for n, k in ((1, 0), (2, 1), (3, 2), (4, 3)):
            s = self.Sim(self.ws(), n)
            self.assertEqual(s.run(), "FN_A", f"N={n} did not complete")
            self.assertEqual(s.taken, [(19, 0x29, 0x00, False)] * k,
                             f"N={n}: branch inventory mismatch")

    def test_sim_no_bt_no_latch_true_no_other_jumps(self):
        # ALL five paths: every taken conditional is a b_f (op 0x29) at
        # latch FALSE — the filter w5 (fallthrough only: the
        # live-proven clean class) or the loop back-edge w19 (N>=2).
        # No taken b_t exists (word level asserted in TestS2StubV5G);
        # no jump word is EXECUTED before W_FAST (none exist before it).
        for N, magic in ((1, True), (2, True), (3, True), (4, True),
                         (1, False)):
            s = self.Sim(self.ws(), N, magic=magic)
            self.assertEqual(s.run(), "FN_A", f"N={N} magic={magic}")
            for i, op, cc, latch in s.taken:
                self.assertNotEqual(op, 0x28,
                                    f"N={N}: taken b_t at w{i}")
                self.assertFalse(latch,
                                 f"N={N}: taken w{i} at latch TRUE")
                self.assertIn((op, cc), {(0x29, 0x0A), (0x29, 0x00)},
                              f"N={N}: taken w{i} op=0x{op:02x} cc=0x{cc:02x}")
            taken_words = {i for i, op, cc, latch in s.taken}
            self.assertTrue(taken_words <= {5, 19},
                            f"N={N}: taken outside {{w5, w19}}: {taken_words}")

    def test_sim_no_absolute_non_cr_writes_all_paths(self):
        # EA class of EVERY store on EVERY path: {CR 0x2380/0x2384/0x238C}
        # U {[r1'+0x0] saves} U {[r1'+0x20..0x2c] payload slot} — zero
        # absolute non-CR writes (lineage regression guard).
        for N in (1, 2, 3, 4):
            s = self.Sim(self.ws(), N)
            self.assertEqual(s.run(), "FN_A", f"N={N} did not complete")
            for ea, v, k in s.stores:
                self.assertNotEqual(k, "ABS", f"N={N}: absolute write 0x{ea:x}")
            self.assertIn((0x238C, 0, "CR"), s.stores)      # marker, value 0

    def test_sim_loop_entry_state_matches_v5d(self):
        # N=4 enters the loop with the SAME register state v5d would
        # have: src r11=[r1+0xac], dst r12=[r1'+0x20], counter r13=4 —
        # plus the byte-exact loop words => EA equivalence with v5d.
        from build_s2 import stub_words
        vd = stub_words("A", version=9)
        wg = self.ws()
        self.assertEqual(wg[14:20], vd[15:21])              # byte-exact block
        s = self.Sim(wg, 4)
        s.run()
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(lo, self.R1E - 0x20)               # dst-init target
        # the 4 distinct payload EAs are exactly the dst-init window
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(4)})


class TestS2StubV5HSim(unittest.TestCase):
    # v5h per-path REGISTER-TRUE simulation (v5e/v5f/v5g Sim reused):
    # THE named-suspect contract — with the save word gone, NO magic
    # path writes [r1'+0x0]; the frame's stack footprint is EXACTLY the
    # payload window [r1'+0x20 .. 0x20+4N).  Branch inventory per path
    # == v5g's modulo the -1 word shift: N=1 (echo) ZERO taken
    # conditionals; N=k (tail frames) back-edge w18 taken x(k-1) at
    # latch FALSE — nothing else can ever fire on a magic path.
    Sim = TestS2StubV5ESim.Sim
    R1E = TestS2StubV5ESim.R1E

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=13)

    def pay_eas(self, s):
        lo = self.R1E - 0x40 + 0x20
        return {ea for ea, v, k in s.stores if k == "STACK" and lo <= ea < lo + 0x10}

    def test_sim_fallthrough_no_store_no_push(self):
        s = self.Sim(self.ws(), 1, magic=False)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.stores, [])                      # no CR, no stack
        self.assertEqual(s.r[1], self.R1E)                  # no push: balanced
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])  # w5 taken at false

    def test_sim_n1_echo_depth1_zero_taken_no_save(self):
        # N=1 (echo frame, 24B no tail): the regression path — v5g
        # minus the save; the ONLY stack writes are the payload window
        # {lo} (pair + loop x1 idempotent dup); NO [r1'+0x0] save
        # write; ZERO taken conditionals on the path.
        s = self.Sim(self.ws(), 1, code=[0xFC001825])
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo})             # pair + loop-x1 EA
        stack = sorted(ea for ea, v, k in s.stores if k == "STACK")
        self.assertEqual(stack, [lo, lo])                   # idempotent dup ONLY
        self.assertNotIn(self.R1E - 0x40, stack)            # NO save write
        self.assertEqual([v for ea, v, k in s.stores
                          if k == "STACK" and ea == lo],
                         [0xFC001825, 0xFC001825])
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 1, 0))                    # marker: N=1 -> 0
        self.assertEqual(s.r[13], 0)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [])                       # ZERO taken

    def test_sim_n2_back_edge_taken_once(self):
        # N=2 (neg-family frame, 28B WITH payload tail): loop x2 — the
        # back-edge taken x1; the write path covers [r1'+0x20..0x24];
        # no save write.
        s = self.Sim(self.ws(), 2)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo, lo + 4})     # pair + loop x2
        stack = sorted(ea for ea, v, k in s.stores if k == "STACK")
        self.assertNotIn(self.R1E - 0x40, stack)            # NO save write
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 2, 0))                    # marker: 0 (r13 end)
        self.assertEqual(s.r[13], 0)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [(18, 0x29, 0x00, False)])  # back-edge x1

    def test_sim_n3_back_edge_taken_twice(self):
        s = self.Sim(self.ws(), 3)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(3)})
        self.assertNotIn(self.R1E - 0x40,
                         {ea for ea, v, k in s.stores if k == "STACK"})
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 3, 0))
        self.assertEqual(s.r[13], 0)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [(18, 0x29, 0x00, False)] * 2)  # back-edge x2

    def test_sim_n4_back_edge_taken_thrice_eas_match_v5d(self):
        # N=4 (neg-family frame, 36B): FULL copy — the four loop stores
        # land EXACTLY on v5d's EA set [r1'+0x20..0x2c]; the pair's
        # identical earlier write is an idempotent duplicate.
        s = self.Sim(self.ws(), 4)
        self.assertEqual(s.run(), "FN_A")
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(4)})
        self.assertEqual(len([1 for ea, v, k in s.stores
                              if k == "STACK" and ea == lo]), 2)   # pair + iter-1
        vals = [v for ea, v, k in s.stores if k == "STACK" and ea == lo]
        self.assertEqual(vals[0], vals[1])                  # idempotent dup
        self.assertNotIn(self.R1E - 0x40,
                         {ea for ea, v, k in s.stores if k == "STACK"})
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 4, 0))
        self.assertEqual(s.r[13], 0)                        # counter exhausted
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [(18, 0x29, 0x00, False)] * 3)  # back-edge x3

    def test_sim_branch_inventory_per_path(self):
        # THE branch-inventory table (v5g contract, -1 word shift):
        # magic N=1 -> ZERO taken conditionals; N=2/3/4 -> back-edge
        # b_f.cc00 @w18 taken x(N-1), at latch FALSE, and NOTHING else
        # fires (the filter b_f w5 is not-taken on every magic path).
        for n, k in ((1, 0), (2, 1), (3, 2), (4, 3)):
            s = self.Sim(self.ws(), n)
            self.assertEqual(s.run(), "FN_A", f"N={n} did not complete")
            self.assertEqual(s.taken, [(18, 0x29, 0x00, False)] * k,
                             f"N={n}: branch inventory mismatch")

    def test_sim_no_save_write_all_paths(self):
        # THE named-suspect assertion, path level: on EVERY magic path
        # the EA set of stack writes is NON-EMPTY and ⊆ the payload
        # window [r1'+0x20 .. 0x20+4N) — the save EA [r1'+0x0] is
        # NEVER written (v5g wrote it on EVERY magic path: the freeze
        # common-denominator word).
        for N in (1, 2, 3, 4):
            s = self.Sim(self.ws(), N)
            self.assertEqual(s.run(), "FN_A", f"N={N} did not complete")
            lo = self.R1E - 0x40 + 0x20
            eas = {ea for ea, v, k in s.stores if k == "STACK"}
            self.assertNotIn(self.R1E - 0x40, eas, f"N={N}: save EA written")
            self.assertTrue(eas, f"N={N}: no stack writes at all")
            for ea in eas:
                self.assertTrue(lo <= ea < lo + 4 * N,
                                f"N={N}: stack write 0x{ea:x} outside window")

    def test_sim_no_bt_no_latch_true_no_other_jumps(self):
        # ALL five paths: every taken conditional is a b_f (op 0x29) at
        # latch FALSE — the filter w5 (fallthrough only: the
        # live-proven clean class) or the loop back-edge w18 (N>=2).
        # No taken b_t exists (word level asserted in TestS2StubV5H);
        # no jump word is EXECUTED before W_FAST (none exist before it).
        for N, magic in ((1, True), (2, True), (3, True), (4, True),
                         (1, False)):
            s = self.Sim(self.ws(), N, magic=magic)
            self.assertEqual(s.run(), "FN_A", f"N={N} magic={magic}")
            for i, op, cc, latch in s.taken:
                self.assertNotEqual(op, 0x28,
                                    f"N={N}: taken b_t at w{i}")
                self.assertFalse(latch,
                                 f"N={N}: taken w{i} at latch TRUE")
                self.assertIn((op, cc), {(0x29, 0x0A), (0x29, 0x00)},
                              f"N={N}: taken w{i} op=0x{op:02x} cc=0x{cc:02x}")
            taken_words = {i for i, op, cc, latch in s.taken}
            self.assertTrue(taken_words <= {5, 18},
                            f"N={N}: taken outside {{w5, w18}}: {taken_words}")

    def test_sim_no_absolute_non_cr_writes_all_paths(self):
        # EA class of EVERY store on EVERY path: {CR 0x2380/0x2384/
        # 0x238C} U payload window — zero absolute non-CR writes (the
        # lineage regression guard; v5g's saves store is GONE too).
        for N in (1, 2, 3, 4):
            s = self.Sim(self.ws(), N)
            self.assertEqual(s.run(), "FN_A", f"N={N} did not complete")
            for ea, v, k in s.stores:
                self.assertNotEqual(k, "ABS", f"N={N}: absolute write 0x{ea:x}")
            self.assertIn((0x238C, 0, "CR"), s.stores)      # marker, value 0

    def test_sim_loop_entry_state_matches_v5d(self):
        # N=4 enters the loop with the SAME register state v5d would
        # have: src r11=[r1+0xac], dst r12=[r1'+0x20], counter r13=4 —
        # plus the byte-exact loop words => EA equivalence with v5d.
        from build_s2 import stub_words
        vd = stub_words("A", version=9)
        wh = self.ws()
        self.assertEqual(wh[13:19], vd[15:21])              # byte-exact block
        s = self.Sim(wh, 4)
        s.run()
        lo = self.R1E - 0x40 + 0x20
        self.assertEqual(lo, self.R1E - 0x20)               # dst-init target
        # the 4 distinct payload EAs are exactly the dst-init window
        self.assertEqual(self.pay_eas(s), {lo + 4 * j for j in range(4)})


class TestS2StubV5ISim(unittest.TestCase):
    # v5i per-path REGISTER-TRUE simulation (v5e/v5f/v5g/v5h Sim
    # reused): THE neutral-write contract — on every magic path the
    # ONLY frame write is [r1'+0x30] = 0xA5A5 (a compile-time constant;
    # the v5b..v5h payload-window copies [r1'+0x20..0x20+4N) are GONE);
    # N never reaches the frame or the control flow (echoed to CR
    # 0x2384 only); ZERO taken conditionals on ALL magic paths N=1..4
    # (the loop back-edge — the last remaining taken-conditional class
    # — is gone; only the fallthrough takes w5 at latch FALSE).
    Sim = TestS2StubV5ESim.Sim
    R1E = TestS2StubV5ESim.R1E

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=14)

    def test_sim_fallthrough_no_store_no_push(self):
        s = self.Sim(self.ws(), 1, magic=False)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.stores, [])                      # no CR, no stack
        self.assertEqual(s.r[1], self.R1E)                  # no push: balanced
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])  # w5 taken at false

    def test_sim_n1_echo_regression_zero_taken(self):
        # N=1 (echo frame, 24B no tail): the regression path — expect
        # clean live (the same linear prefix+push+CR-write shape ran
        # clean live x4: v5e/v5f/v5g/v5h echo-N1); the frame gets the
        # ONE neutral write; ZERO taken conditionals.
        s = self.Sim(self.ws(), 1, code=[0xFC001825])
        self.assertEqual(s.run(), "FN_A")
        lo30 = self.R1E - 0x40 + 0x30
        stack = [(ea, v) for ea, v, k in s.stores if k == "STACK"]
        self.assertEqual(stack, [(lo30, 0xA5A5)])           # the ONLY frame write
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 1, 1))                    # marker: r13=N (loop gone)
        self.assertEqual(s.r[13], 1)                        # N survives to TAIL
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [])                       # ZERO taken

    def test_sim_n2_neutral_write_only(self):
        # N=2 (neg-family tail frame, 28B — freeze reproducer lineage):
        # path IDENTICAL to N=1 (prefix + push + NEUTRAL-WRITE + marker
        # + pop + W_FAST); the tail bytes are NEVER read; ZERO taken.
        s = self.Sim(self.ws(), 2)
        self.assertEqual(s.run(), "FN_A")
        lo30 = self.R1E - 0x40 + 0x30
        stack = [(ea, v) for ea, v, k in s.stores if k == "STACK"]
        self.assertEqual(stack, [(lo30, 0xA5A5)])
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                         (0x5332, 2, 2))
        self.assertEqual(s.r[13], 2)
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.taken, [])                       # ZERO taken

    def test_sim_n3_n4_identical_path(self):
        # N=3/4: the instruction path is IDENTICAL to N=1/2 — N only
        # shifts the CR echo values; the discriminator variable is
        # purely the FRAME BYTES on the wire (tail present/absent).
        for n in (3, 4):
            s = self.Sim(self.ws(), n)
            self.assertEqual(s.run(), "FN_A", f"N={n} did not complete")
            lo30 = self.R1E - 0x40 + 0x30
            stack = [(ea, v) for ea, v, k in s.stores if k == "STACK"]
            self.assertEqual(stack, [(lo30, 0xA5A5)], f"N={n}")
            self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x238C]),
                             (0x5332, n, n), f"N={n}")
            self.assertEqual(s.r[13], n)
            self.assertEqual(s.r[1], self.R1E)
            self.assertEqual(s.taken, [], f"N={n}")         # ZERO taken

    def test_sim_branch_inventory_all_paths_zero_taken(self):
        # THE branch-inventory table: magic N=1..4 -> ZERO taken
        # conditionals (loop GONE — nothing can fire); fallthrough ->
        # the filter w5 taken once at latch FALSE (the live-proven
        # clean class).
        for n in (1, 2, 3, 4):
            s = self.Sim(self.ws(), n)
            self.assertEqual(s.run(), "FN_A", f"N={n} did not complete")
            self.assertEqual(s.taken, [], f"N={n}: branch inventory mismatch")
        s = self.Sim(self.ws(), 1, magic=False)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])

    def test_sim_no_bt_no_latch_true_no_other_jumps(self):
        # ALL five paths: every taken conditional is the filter b_f
        # (op 0x29, cc 0x0A) at latch FALSE — fallthrough only; no
        # taken b_t exists (word level asserted in TestS2StubV5I); no
        # jump word is EXECUTED before W_FAST (none exist before it).
        for N, magic in ((1, True), (2, True), (3, True), (4, True),
                         (1, False)):
            s = self.Sim(self.ws(), N, magic=magic)
            self.assertEqual(s.run(), "FN_A", f"N={N} magic={magic}")
            for i, op, cc, latch in s.taken:
                self.assertNotEqual(op, 0x28,
                                    f"N={N}: taken b_t at w{i}")
                self.assertFalse(latch,
                                 f"N={N}: taken w{i} at latch TRUE")
                self.assertIn((op, cc), {(0x29, 0x0A), (0x29, 0x00)},
                              f"N={N}: taken w{i} op=0x{op:02x} cc=0x{cc:02x}")
            taken_words = {i for i, op, cc, latch in s.taken}
            self.assertTrue(taken_words <= {5},
                            f"N={N}: taken outside {{w5}}: {taken_words}")

    def test_sim_only_frame_write_is_neutral_slot(self):
        # THE frame-write assertion, path level: on EVERY magic path
        # the stack-write EA set is EXACTLY {[r1'+0x30]} with value
        # 0xA5A5 — the old payload window [r1'+0x20..0x2c) and the
        # save slot [r1'+0x0] are NEVER written; N never reaches the
        # frame (content-neutral by construction).
        for N in (1, 2, 3, 4):
            s = self.Sim(self.ws(), N)
            self.assertEqual(s.run(), "FN_A", f"N={N} did not complete")
            eas = {ea for ea, v, k in s.stores if k == "STACK"}
            self.assertEqual(eas, {self.R1E - 0x40 + 0x30}, f"N={N}")
            for ea, v, k in s.stores:
                if k == "STACK":
                    self.assertEqual(v, 0xA5A5, f"N={N}: non-neutral frame value")
        # word level: no store word targets [r1'+0x20..0x30) or 0x0
        wd = self.ws()
        for i, w in enumerate(wd):
            if (w >> 26) == 0x1B and ((w >> 21) & 0x1F) == 1:
                off = (((w >> 16) & 0x1F) << 11) | (((w >> 2) & 0x1FF) << 2)
                self.assertEqual(off, 0x30, f"w{i}: frame store off 0x{off:x}")

    def test_sim_no_absolute_non_cr_writes_all_paths(self):
        # EA class of EVERY store on EVERY path: {CR 0x2380/0x2384/
        # 0x238C} U {[r1'+0x30] neutral} — zero absolute non-CR writes
        # (lineage regression guard; with the copy block gone even the
        # payload-window STACK writes are gone).
        for N in (1, 2, 3, 4):
            s = self.Sim(self.ws(), N)
            self.assertEqual(s.run(), "FN_A", f"N={N} did not complete")
            for ea, v, k in s.stores:
                self.assertNotEqual(k, "ABS", f"N={N}: absolute write 0x{ea:x}")
            self.assertIn((0x238C, N, "CR"), s.stores)      # marker: r13=N


class TestS2StubV5J(unittest.TestCase):
    # v5j rev.2 (Exit-C — T32 review; THE C1 PIVOT — exec-from-input,
    # journal task-30 Q4 sketch + errata f0e4804; task-31 phase-2
    # verdict: ZERO extra frame writes = live-proven safe class): the
    # payload EXECUTES IN-PLACE from the input landing zone
    # [r1+0xac..0xbc) — NO push, NO save, NO copy, NO neutral write:
    # the stub writes CR slots ONLY (always-clean class, v5i live x4
    # images).  Prefix w0-w8 == v5i byte-exact (only w5's immediate
    # retargets +9 -> +6 to the new W_FAST @w11: 0xA40A0006
    # stock-exact x70 — the BEST count of the whole lineage); NO
    # N-guard, NO gauntlet (N echoed 0x2384=N, never used for
    # control).  w9 re-establishes r11 = r1+0xac (the w1 word — dead
    # in v5i, the payload ptr here) immediately before w10 = `ret.r
    # zero,r8,r11` (0xFD005825): THE SINGLE register-target transfer
    # into the landing — rs=8 COMPUTED-JR CLASS, NO LINK (csr0xbc
    # keeps the pre-detour ra; word stock-exact x3, class x8986 live —
    # the canonical return idiom, journal task-30 return-state
    # inventory; NOT the rs=0 LINKING jalr of rev.1 — review
    # Important-2).  W_FAST jump FN_A LAST (w11 = 0x38d77c,
    # 0x95F8007A live-form x0).  12 of 34 zone words.
    V5J_GOLDEN = [
        0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332, 0xE1806802,
        0xA40A0006, 0x6C046382, 0x642D00A5, 0x6C046B86, 0x002B00AC,
        0xFD005825, 0x95F8007A,
    ]

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=15)

    def test_v5j_golden_words(self):
        self.assertEqual(self.ws(), self.V5J_GOLDEN)

    def test_v5j_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5j"), stub_words("A", version=15))
        self.assertEqual(stub_words("A", version="v5j"), stub_words("A", version=15))

    def test_v5j_prefix_v5i_w5_imm_only(self):
        # THE prefix contract vs v5i: w0-w8 == v5i BYTE-EXACT except
        # w5's IMMEDIATE (+9 -> +6: W_FAST moved w14 -> w11 when the
        # push/neutral/marker/pop block collapsed to w9+w10); op+cc
        # bits identical.
        from build_s2 import stub_words
        wi, wj = stub_words("A", version=14), self.ws()
        self.assertEqual(len(wi), 15)
        self.assertEqual(wj[0:5], wi[0:5])
        self.assertEqual(wj[6:9], wi[6:9])
        self.assertEqual(wj[5], 0xA40A0006)                 # b_f.cc0A +6
        self.assertEqual((wj[5] >> 16), (wi[5] >> 16))      # op+cc identical
        self.assertEqual((wi[5] & 0xFFFF) - (wj[5] & 0xFFFF), 3)   # imm 9->6

    def test_v5j_zero_frame_write_words(self):
        # THE zero-frame-writes contract, word level: NO push (op 0x1C),
        # NO pop, NO store with rs != zero (every op-0x1B word targets
        # a CR slot — the always-clean class), and NOTHING writes r1.
        wd = self.ws()
        for i, w in enumerate(wd):
            self.assertNotEqual(w >> 26, 0x1C, f"w{i}=0x{w:08x} is a push")
            if (w >> 26) == 0x1B:
                self.assertEqual(((w >> 21) & 0x1F), 0,
                                 f"w{i}=0x{w:08x} stores with rs != zero")
            if (w >> 26) == 0x00:
                self.assertNotEqual(((w >> 16) & 0x1F), 1,
                                    f"w{i}=0x{w:08x} writes r1")
        self.assertNotIn(0x703F0FC2, wd)                    # push: gone
        self.assertNotIn(0x00210040, wd)                    # pop: gone
        self.assertNotIn(0x6C206032, wd)                    # neutral write: gone

    def test_v5j_single_transfer_w10_no_link(self):
        # THE transfer contract (rev.2): exactly ONE op-0x3F word in
        # the stub — w10 `ret.r zero,r8,r11` (funct 0x25, rs=8
        # COMPUTED-JR CLASS — NO LINK, csr0xbc keeps the pre-detour
        # ra; rd=0, rt=r11 the payload ptr); it is the ONLY word
        # whose execution can redirect the PC to the landing.  NOT
        # the rs=0 LINKING jalr of rev.1 (review Important-2: the
        # link wrote csr0xbc = W_FAST and looped FN_A<->W_FAST).
        # The only jump word is W_FAST (w11, last); no call words.
        wd = self.ws()
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x3F],
                         [10])
        self.assertEqual(wd[10], enc.ret_r(8, 0, 11))
        self.assertEqual(wd[10], 0xFD005825)
        self.assertNotEqual(wd[10], enc.ret_r(0, 0, 11))     # NOT the linking jalr
        self.assertEqual((wd[10] >> 21) & 0x1F, 8)           # rs = r8 (jr class)
        self.assertEqual((wd[10] >> 16) & 0x1F, 0)           # rd = zero
        self.assertEqual((wd[10] >> 11) & 0x1F, 11)          # rt = r11
        self.assertEqual(wd[10] & 0x1FF, 0x25)               # funct ret.r
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x25],
                         [11])                              # W_FAST only
        self.assertEqual((wd[11] >> 24) & 1, 1)              # jump (no link)

    def test_v5j_w9_payload_ptr_reestablish(self):
        # w9 == w1 == `addi r11,r1,0xac` (PAY_SRC_OFF_V5B: landing
        # 0x98+0x14): the payload pointer re-established IMMEDIATELY
        # before the transfer (nothing between w9 and w10 can disturb
        # the r11 dataflow — they are adjacent words).
        from build_s2 import stub_words, PAY_SRC_OFF_V5B
        wd = self.ws()
        self.assertEqual(PAY_SRC_OFF_V5B, 0xAC)
        self.assertEqual(wd[9], enc.addi(11, 1, PAY_SRC_OFF_V5B))
        self.assertEqual(wd[9], wd[1])
        self.assertEqual(wd[9], 0x002B00AC)

    def test_v5j_zero_bt_filter_only_conditional(self):
        # linearity contract, strongest form: NO b_t words; the ONLY
        # conditional is the filter b_f (w5); the ONLY jump is W_FAST
        # (w11); no back-edge, no gates, no skips.
        wd = self.ws()
        for i, w in enumerate(wd):
            self.assertNotEqual(w >> 26, 0x28, f"w{i}=0x{w:08x} is b_t")
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x29],
                         [5])                               # filter ONLY
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x38],
                         [4])                               # one cmp (filter)

    def test_v5j_no_n_guard_no_gauntlet_words(self):
        # N never controls: no guard bound const, no N-vs-const cmp,
        # no gauntlet read/const; nothing gates on the code window.
        wd = self.ws()
        for w in (0x200C0004, 0x200C0002, 0x200C0003,   # guard/gate consts
                  0x200D2407,                            # gauntlet const
                  0x15AD0001,                            # subsi counter
                  0x002C0020, 0x65630002, 0x6D801802,   # copy block
                  0xA400FFFB):                           # back-edge
            self.assertNotIn(w, wd, f"gate/copy word 0x{w:08x} present")

    def test_v5j_wfast_last_and_filter_targets_it(self):
        wd = self.ws()
        w_fast = STUB + 4 * 11
        self.assertEqual(wd[11], enc.jump(w_fast, 0x18D964))
        self.assertEqual(wd[11], 0x95F8007A)
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))  # filter -> fast

    def test_v5j_word_delta_vs_v5i_exactly_block_plus_imms(self):
        # THE diff-vs-v5i contract: v5j == v5i with EXACTLY the frame
        # block removed (push + neutral pair + TAIL marker + pop) + the
        # transfer pair inserted (w9 addi is the w1 WORD, count 1 -> 2)
        # + the two position-dependent immediates recomputed (w5 filter
        # +9 -> +6; W_FAST imm 0x77 -> 0x7A) — rev.2: the transfer is
        # the rs=8 no-link word 0xFD005825.
        from build_s2 import stub_words
        wi, wj = stub_words("A", version=14), self.ws()
        self.assertEqual(set(wi) - set(wj),
                         {0x703F0FC2, 0x200CA5A5, 0x6C206032, 0x6C046B8E,
                          0x00210040, 0xA40A0009, 0x95F80077})
        self.assertEqual(set(wj) - set(wi),
                         {0xFD005825, 0xA40A0006, 0x95F8007A})
        self.assertEqual(wi.count(0x002B00AC), 1)          # w1 only
        self.assertEqual(wj.count(0x002B00AC), 2)          # w1 + w9
        for w in (0x480300BC, 0x642C00AB, 0x200D5332, 0xE1806802,
                  0x6C046382, 0x642D00A5, 0x6C046B86):
            self.assertEqual(wj.count(w), wi.count(w), f"count drift 0x{w:08x}")

    def test_v5j_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 12)                # 12/34
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5j_clobber_confined(self):
        import irisc_dis
        dec = [irisc_dis.dis(w, 0) for w in self.ws()]
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r22", "r23", "r4", "r5", "r6"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5j_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=15)

    def test_v5j_stock_precedents(self):
        # NEW-word stock counts (clean blob whole-image census):
        #   w5 retarget b_f.cc0A +6 (0xA40A0006) x70 — stock-exact,
        #     the BEST count of the lineage's w5 immediates (+9 was x48)
        #   w9/w1 addi r11,r1,0xac (0x002B00AC) x0 exact — LIVE (w1 of
        #     v5g/v5h/v5i, clean x3+ images); class addi r11,r1,* x110
        #   w10 ret.r zero,r8,r11 (0xFD005825) — rev.2: STOCK-EXACT x3
        #     (the rs=8 computed-jr class x8986: canonical return
        #     rt=r3 x8346 + jr rt!=r3 x640, live on every completion;
        #     rt=r11 subset x3); the rev.1 rs=0 jalr word (x0) LINKED
        #     and is REJECTED (class x294 kept below for contrast)
        #   W_FAST jump imm recomputed (0x95F8007A) x0 — live-form
        #     class (every prior W_FAST word 0-count, live-clean x6+)
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        cnt = lambda x: sum(1 for w in words if w == x)
        ws = self.ws()
        self.assertEqual(cnt(0xA40A0006), 70)               # w5 retarget
        self.assertEqual(cnt(0x002B00AC), 0)                # w9/w1: live word
        self.assertEqual(cnt(0xFD005825), 3)                # w10: STOCK-EXACT
        self.assertEqual(cnt(0x95F8007A), 0)                # W_FAST: live-form
        jr8 = sum(1 for w in words if (w >> 26) == 0x3F
                  and (w & 0x1FF) == 0x25 and ((w >> 21) & 0x1F) == 8)
        self.assertEqual(jr8, 8986)                         # the NO-LINK class
        jr8_r11 = sum(1 for w in words if (w >> 26) == 0x3F
                      and (w & 0x1FF) == 0x25
                      and ((w >> 21) & 0x1F) == 8
                      and ((w >> 11) & 0x1F) == 11)
        self.assertEqual(jr8_r11, 3)                        # rt=r11 jr subset
        jalr = sum(1 for w in words if (w >> 26) == 0x3F
                   and (w & 0x1FF) == 0x25 and ((w >> 21) & 0x1F) == 0)
        self.assertEqual(jalr, 294)                         # the REJECTED linking class
        addi_cls = sum(1 for w in words if (w >> 26) == 0x00
                       and ((w >> 21) & 0x1F) == 1 and ((w >> 16) & 0x1F) == 11)
        self.assertEqual(addi_cls, 110)                     # addi r11,r1,*
        # every word of the stub is stock-exact, live-exact (v5b..v5i
        # lineage goldens) or documented (imm-recomputed / the transfer)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7)) \
            | set(stub_words("A", version=8)) | set(stub_words("A", version=9)) \
            | set(stub_words("A", version=10)) | set(stub_words("A", version=11)) \
            | set(stub_words("A", version=12)) | set(stub_words("A", version=13)) \
            | set(stub_words("A", version=14))
        documented = {0xA40A0006, 0x95F8007A}
        for w in ws:
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5j_lineage_untouched(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)
        self.assertEqual(len(stub_words("A", version=9)), 33)
        self.assertEqual(len(stub_words("A", version=10)), 30)
        self.assertEqual(len(stub_words("A", version=11)), 32)
        self.assertEqual(len(stub_words("A", version=12)), 23)
        self.assertEqual(len(stub_words("A", version=13)), 22)
        self.assertEqual(len(stub_words("A", version=14)), 15)


class TestS2StubV5JSim(unittest.TestCase):
    # v5j rev.2 (Exit-C) per-path REGISTER-TRUE simulation with PAYLOAD
    # EXECUTION.  The v5e Sim model is re-based (SimV5J below) with the
    # rev.2 essentials:
    #   (a) the SLASPEC INSERT semantics — set3 rd,rs,imm inserts
    #       imm16 into bits 0..15, set2 into bits 16..31 (the base
    #       Sim's add model silently agrees only while the source's
    #       lo16 is zero; the v5j payload BUILDS S2OK from r12=0x5332
    #       whose lo16 is NOT zero — the real semantics are required);
    #   (b) op=0x3F funct-0x25 ret.r — the task-30 return-state
    #       inventory: rs=8 = COMPUTED JR, NO LINK (canonical return
    #       x8346 + jr class x640, live on every completion) — the
    #       rev.2 w10; rs=0 = LINKING jalr (csr0xbc <- pc+4, the
    #       dispatch idiom) — the REJECTED rev.1 form; both goto [rt];
    #       every link (jalr or call) is LOGGED and csr0xbc tracked;
    #   (c) op=0x25: bit24=1 jump (no link) / bit24=0 call (links);
    #   (d) LIVE address space (review Critical-1/#4 space-mix): stub
    #       words execute at file+0x800000, payload words at the stack
    #       EA r1+0xac+4i — the W_FAST file-space immediate AND the
    #       payload live-space immediate (built for LIVE FN_A
    #       0x98d964) BOTH resolve to the live FN_A; the exit target
    #       is recorded so tests assert the SPACE, not just "FN_A".
    # THE contracts (dispatch): r11 = r1+0xAC at the transfer; the
    # payload CR writes are {0x2388: S2OK} ONLY (rev.2: no landing
    # echo); then FN_A at the LIVE 0x98d964; the landing map is
    # input[k=0x14+4i] -> [r1+0xac+4i] (4 words); ZERO stack writes
    # and ZERO links (csr0xbc = pre-detour ra) on EVERY path.
    R1E = 0x1000
    STUB_LIVE = 0x800000 + 0x38D750
    FN_A_LIVE = 0x98D964                      # == 0x800000 + build_s2 FN_A
    RA_LIVE = 0x8E4380                        # pre-detour ra (call @0x0e437c +4)

    class SimV5J:
        def __init__(self, ws, N, magic=True, code=None, r1=None):
            TestS = TestS2StubV5JSim
            r1 = TestS.R1E if r1 is None else r1
            self.ws = ws
            self.mem = {}
            self.cr = {0x2380: 0, 0x2384: 0, 0x2388: 0, 0x238C: 0}
            self.csr0xbc = TestS.RA_LIVE
            self.links = []                                 # (ea, kind) link events
            self.mem[r1 + 0xA4] = N
            self.mem[r1 + 0xAA] = 0x5332 if magic else 0x1234
            for i, cw in enumerate(code):
                self.mem[r1 + 0xAC + 4 * i] = cw
            self.r = {1: r1, 3: 0xDEAD, 11: 0, 12: 0, 13: 0}
            self.pc = 0
            self.eq = False
            self.z32 = False
            self.stores = []
            self.taken = []                                 # (i, op, cc, latch)
            self.pay_fetch = []                             # payload word EAs
            self.exit_ea = None                             # recorded exit target

        def rd(self, k):
            return 0 if k == 0 else self.r[k]

        def run(self, max_steps=200):
            import irisc_dis
            STUB_L = TestS2StubV5JSim.STUB_LIVE
            FN_A_L = TestS2StubV5JSim.FN_A_LIVE
            for _ in range(max_steps):
                if isinstance(self.pc, int):
                    i = self.pc
                    if not 0 <= i < len(self.ws):
                        return "WILD_%08x" % (STUB_L + 4 * i)
                    word = self.ws[i]
                    ea = STUB_L + 4 * i                     # LIVE stub PC
                    nxt = i + 1
                else:
                    ea = self.pc[1]                         # LIVE stack PC
                    if ea not in self.mem:
                        return "DEAD_%08x" % ea
                    word = self.mem[ea]
                    self.pay_fetch.append(ea)
                    nxt = ("ea", ea + 4)
                op = word >> 26
                if op == 0x12:                              # csr.r
                    self.r[3] = self.csr0xbc
                elif op == 0x00:                            # addi
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    self.r[(word >> 16) & 0x1F] = \
                        (self.rd((word >> 21) & 0x1F) + imm) & 0xFFFFFFFF
                elif op == 0x08:                            # set3: insert lo16
                    self.r[(word >> 16) & 0x1F] = \
                        (self.rd((word >> 21) & 0x1F) & ~0xFFFF) | (word & 0xFFFF)
                elif op == 0x09:                            # set2: insert hi16
                    self.r[(word >> 16) & 0x1F] = \
                        (self.rd((word >> 21) & 0x1F) & 0xFFFFFFFF0000FFFF) \
                        | ((word & 0xFFFF) << 16)
                elif op == 0x19:                            # ld.w / ld.d
                    rt, rs = (word >> 16) & 0x1F, (word >> 21) & 0x1F
                    if word & 1:
                        off = ((word >> 1) & 0x7FFF) << 1
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0) & 0xFFFF
                    else:
                        off = ((word >> 2) & 0x3FFF) << 2
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0)
                elif op == 0x1B:                            # st.d / st.w
                    rt, rs = (word >> 11) & 0x1F, (word >> 21) & 0x1F
                    off = (((word >> 16) & 0x1F) << 11) \
                        | (((word >> 2) & 0x1FF) << 2)
                    if rs == 0:
                        self.cr[off] = self.r[rt]
                        self.stores.append((off, self.r[rt], "CR"))
                    else:
                        ea = (self.rd(rs) + off) & 0xFFFFFFFF
                        kind = "STACK" if self.r[1] - 0x40 <= ea < self.r[1] else "ABS"
                        self.mem[ea] = self.r[rt]
                        self.stores.append((ea, self.r[rt], kind))
                elif op == 0x38:                            # cmp38_sel eq32
                    self.eq = self.rd((word >> 21) & 0x1F) == \
                        self.rd((word >> 11) & 0x1F)
                elif op in (0x28, 0x29):                    # b_t / b_f (stub words)
                    if not isinstance(self.pc, int):
                        return "UNSUPPORTED_branch_in_payload"
                    cc = (word >> 16) & 0x1F
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    cond = self.eq if cc == 0x0A else self.z32 if cc == 0 else False
                    if (cond if op == 0x28 else not cond):
                        self.taken.append((self.pc, op, cc, cond))
                        nxt = self.pc + imm
                elif op == 0x25:                            # jump/call: ACTUAL (live) ea
                    if not word & 0x01000000:               # call: LINKS
                        self.csr0xbc = (ea + 4) & 0xFFFFFFFF
                        self.links.append((ea, "call"))
                    tgt = ea + irisc_dis.s24(word) * 4
                    j = (tgt - STUB_L) // 4
                    if 0 <= j < len(self.ws) and tgt == STUB_L + 4 * j:
                        nxt = j
                    elif tgt == FN_A_L:
                        self.exit_ea = tgt
                        return "FN_A"
                    else:
                        self.exit_ea = tgt
                        return "EXIT_%08x" % tgt
                elif op == 0x3F and (word & 0x1FF) == 0x25:  # ret.r
                    rs, rt = (word >> 21) & 0x1F, (word >> 11) & 0x1F
                    if rs == 0:                             # jalr: LINKS
                        self.csr0xbc = (ea + 4) & 0xFFFFFFFF
                        self.links.append((ea, "jalr"))
                    nxt = ("ea", self.rd(rt))               # both rs=0/rs=8 goto [rt]
                else:
                    return "UNSUPPORTED_op_%02x" % op
                self.pc = nxt
            return "RUNAWAY"

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=15)

    def payload_words(self, r1=None):
        import payload as pl
        return pl.payload_v5j(self.R1E if r1 is None else r1)

    def test_sim_fallthrough_no_store_no_transfer(self):
        s = self.SimV5J(self.ws(), 4, magic=False, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.exit_ea, 0x98D964)              # LIVE FN_A (file imm + live EA)
        self.assertEqual(s.stores, [])                      # no CR, no stack
        self.assertEqual(s.r[1], self.R1E)                  # r1 untouched
        self.assertEqual(s.pay_fetch, [])                   # no transfer
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])  # w5 taken at false
        self.assertEqual(s.links, [])                       # W_FAST = jump, no link
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # csr0xbc untouched

    def test_sim_magic_path_full_contract(self):
        # THE exec path (rev.2): prefix (echoes) -> w9 (r11 = r1+0xAC)
        # -> w10 (register transfer, NO LINK) -> payload p0..p3 from
        # the landing zone -> FN_A at the LIVE 0x98d964.  CR contract:
        # 0x2380=MAGIC16, 0x2384=N, 0x2388=S2OK — and NOTHING else
        # (rev.2 dropped the landing echo; 0x238C stays 0).  ZERO
        # taken conditionals; ZERO links; csr0xbc = pre-detour ra.
        s = self.SimV5J(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.exit_ea, 0x98D964)
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                         (0x5332, 4, 0x53324F4B, 0))
        self.assertEqual(s.r[11], self.R1E + 0xAC)          # r11 at/after transfer
        self.assertEqual(s.r[12], 0x53324F4B)               # payload build result
        self.assertEqual(s.r[1], self.R1E)                  # frame NEVER touched
        self.assertEqual(s.taken, [])                       # ZERO taken
        self.assertEqual(s.links, [])                       # ZERO links
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # no-link contract
        kinds = {k for _, _, k in s.stores}
        self.assertEqual(kinds, {"CR"})                     # CR writes only

    def test_sim_landing_map_k14(self):
        # THE landing map: input halfword/word k=0x14+4i lands at
        # [r1+0x98+0x14+4i] = [r1+0xac+4i] — the payload fetch
        # sequence IS the map (4 words, strictly consecutive).
        s = self.SimV5J(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0x98 + 0x14 + 4 * i for i in range(4)])
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0xAC + 4 * i for i in range(4)])

    def test_sim_zero_stack_writes_all_paths(self):
        # THE zero-frame-writes assertion, path level: on EVERY path
        # (magic and fallthrough) the store log contains NO stack and
        # NO absolute writes — the pushed-frame freeze class (#9)
        # cannot even in principle fire: there is NO pushed frame.
        for magic in (True, False):
            s = self.SimV5J(self.ws(), 4, magic=magic, code=self.payload_words())
            self.assertEqual(s.run(), "FN_A", f"magic={magic}")
            for ea, v, k in s.stores:
                self.assertNotIn(k, ("STACK", "ABS"),
                                 f"magic={magic}: non-CR write 0x{ea:x}")
            self.assertEqual(s.r[1], self.R1E, f"magic={magic}: r1 moved")

    def test_sim_transfer_reads_r11_register(self):
        # w10 transfers to the REGISTER r11 (not to a wired address):
        # the first fetched payload EA == the r11 value established by
        # w9.  rev.2: no landing echo — NOTHING writes CR 0x238C on
        # the magic path (the dropped st.d is gone entirely).
        s = self.SimV5J(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.pay_fetch[0], s.r[11])
        self.assertEqual(s.cr[0x238C], 0)
        self.assertNotIn(0x238C, [ea for ea, _, _ in s.stores])

    def test_sim_no_link_csr0xbc_untouched(self):
        # review Important-2 contract: the transfer must NOT link —
        # csr0xbc keeps the PRE-DETOUR ra through the whole magic path
        # (transfer + payload + FN_A entry), so FN_A's ret.d returns
        # into the dispatcher exactly like every v5-series clean
        # completion.  A linking w10 (rev.1) would have written
        # csr0xbc = W_FAST and looped FN_A<->W_FAST.
        s = self.SimV5J(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.links, [])                       # no jalr/call link events
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # pre-detour ra intact
        self.assertEqual(s.r[3], self.RA_LIVE)              # w0 captured it BEFORE
        # word level: the transfer is the rs=8 word, not the rs=0 jalr
        self.assertEqual(self.ws()[10], enc.ret_r(8, 0, 11))
        self.assertNotIn(enc.ret_r(0, 0, 11), self.ws())

    def test_sim_exit_targets_live_fn_a(self):
        # review Critical-1/#4 (space-mix): every exit resolves to the
        # LIVE FN_A 0x98d964 (= file 0x18d964 + 0x800000) — the W_FAST
        # word (file-space immediate, live stub EA) on the fallthrough
        # path AND the payload p3 (live-space immediate, stack EA) on
        # the magic path.  Cross-checked against build_s2's FN_A.
        import sys
        from pathlib import Path
        repo = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(repo / "scripts" / "s2"))
        from build_s2 import FN_A
        from payload import FN_A_LIVE_V5J
        self.assertEqual(FN_A_LIVE_V5J, 0x98D964)
        self.assertEqual(FN_A_LIVE_V5J, 0x800000 + FN_A)
        for magic in (True, False):
            s = self.SimV5J(self.ws(), 4, magic=magic, code=self.payload_words())
            self.assertEqual(s.run(), "FN_A", f"magic={magic}")
            self.assertEqual(s.exit_ea, FN_A_LIVE_V5J, f"magic={magic}")

    def test_sim_wrong_landing_base_c1_signal_survives(self):
        # the p3 immediate is built for an ASSUMED r1 (the true
        # absolute stack address was never measured).  A WRONG
        # assumption derails ONLY the post-payload exit: the C1 signal
        # (0x2388=S2OK) is written by p2 BEFORE p3 executes, and the
        # full 4-word payload has already fetched — a wrong base
        # cannot mask C1 (it makes the exit observable instead).
        s = self.SimV5J(self.ws(), 4, code=self.payload_words(self.R1E + 0x100))
        out = s.run()
        self.assertTrue(out.startswith("EXIT_"), f"wrong base unexpectedly clean: {out}")
        self.assertNotEqual(out, "FN_A")
        self.assertEqual(s.exit_ea, 0x98D964 - 0x100)       # off by the base delta
        self.assertEqual(s.cr[0x2388], 0x53324F4B)          # C1 gate intact
        self.assertEqual(s.cr[0x238C], 0)                   # nothing else written
        self.assertEqual(len(s.pay_fetch), 4)               # full payload ran

    def test_sim_all_stack_bases_exit_clean(self):
        # rev.2 mandate: the p3 immediate is built for the ASSUMED
        # base — for EVERY plausible stack base (SP-init cpu0..cpu14:
        # 0x7d1ff8 + k*0x2000) a payload built FOR that base exits to
        # the LIVE FN_A exactly (the s24 sweep in the payload tests
        # covers the dense range arithmetically; this is the
        # executing-model counterpart).
        import payload as pl
        for base in range(0x7D1FF8, 0x800000, 0x2000):
            s = self.SimV5J(self.ws(), 4, code=pl.payload_v5j(base), r1=base)
            self.assertEqual(s.run(), "FN_A", f"base 0x{base:x}")
            self.assertEqual(s.exit_ea, 0x98D964, f"base 0x{base:x}")

    def test_sim_branch_inventory_all_paths(self):
        # THE branch-inventory table: magic -> ZERO taken conditionals
        # (the ONLY conditional word is the filter b_f, not-taken at
        # magic); fallthrough -> w5 taken once at latch FALSE (the
        # live-proven clean class).  No b_t words exist at all.
        for n, magic, want in ((4, True, []), (1, True, []), (4, False, [(5, 0x29, 0x0A, False)])):
            s = self.SimV5J(self.ws(), n, magic=magic, code=self.payload_words())
            self.assertEqual(s.run(), "FN_A", f"N={n} magic={magic}")
            self.assertEqual(s.taken, want, f"N={n} magic={magic}")

    def test_sim_trig_frame_bytes_drive_the_path(self):
        # THE TRIG frame (the exact 36B host bytes of the live phase)
        # drives the full path: unpack N / MAGIC16 / the 4 payload
        # words FROM THE FRAME BYTES, run at r1 = the default assumed
        # base — the frame-as-built is self-consistent end to end and
        # exits at the LIVE FN_A.
        import payload as pl
        frame = pl.input_block_v5j()                        # default base
        b = bytes.fromhex(frame.hex())
        n = struct.unpack(">H", b[0xC:0xE])[0]
        magic16 = struct.unpack(">H", b[0x12:0x14])[0]
        words = list(struct.unpack(">4I", b[0x14:0x24]))
        self.assertEqual((n, magic16), (4, 0x5332))
        r1 = pl.R1_DEFAULT_V5J
        s = self.SimV5J(self.ws(), n, code=words, r1=r1)
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.exit_ea, 0x98D964)
        self.assertEqual((s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                         (4, 0x53324F4B, 0))
        self.assertEqual(s.pay_fetch, [r1 + 0xAC + 4 * i for i in range(4)])


class TestS2StubV5K(unittest.TestCase):
    # v5k rev.2 (T33-review 40d902a fix — Critical-1 + Important-2):
    # the rev.1 Exit-D was MISVERIFIED — the detour path
    # (0x0e4258 push 0xf8 -> 0x0e42b8 linking ret.r r17 -> 0x0e42bc ->
    # b_t 0x0e4310 -> call 0xebc9c @0x0e4328 -> call 0xcaec0 @0x0e4358
    # -> detour 0x0e437c) NEVER pops the fn's 0xf8 frame: each nested
    # callee prologue overwrites the INNER [(R-0xf8)+4] with its resume
    # (last writer: call 0xcaec0 -> 0x8E435C), so the rev.1 w10
    # `ld.d r3,r1,0x4' loaded the INNER residue and p3 ret.r re-entered
    # the detour path => deterministic LIVELOCK (review Critical-1);
    # also r17-r23 (saved 0x0e425c-74, restored ONLY on the epilogue
    # path 0x0e42e8-0x0e4300) leaked on any non-epilogue exit (review
    # Important-2).  THE FIX (review's design): a STUB-SIDE EPILOGUE
    # REPLICA — the stub preloads r3 with the ABSOLUTE live address of
    # a 10-word byte-copy of the fn's own epilogue (0x0e42e8..0x0e430c:
    # 7 restores r23..r17 from [r1+0xdc..0xf4], pop addi r1,r1,0xf8,
    # ld.d r3,r1,0x4 — NOW the OUTER [R+4], the fn's true saved
    # dispatcher ra written by the prologue @0x0e4254 — and the fn's
    # own final ret.r); the payload p3 `ret.r zero,r8,r3' (UNCHANGED
    # 0xFD001825) exits into the replica, which completes the fn's
    # epilogue: registers restored, frame popped, return to the
    # dispatcher.  Livelock GONE by design (single transit; the outer
    # [R+4] is consumed exactly once); r17-r23 leak GONE (restores).
    # Layout (24 words, W_FAST LAST @w23 = 0x38d7ac — lineage
    # convention): prefix w0-w8 == v5j byte-exact (only w5's immediate
    # retargets +6 -> +18: 0xA40A0012 stock-exact x27); w9 payload
    # ptr (== w1); w10 `set3 r3,zero,0xd784' + w11 `set2 r3,r3,0x00b8'
    # build r3 = live replica address 0xB8D784 = 0x800000 +
    # (STUB+4*13) — the stub zone is ABSOLUTE space, base-independent
    # BY CONSTRUCTION (OR-semantics-safe order: rs=zero FIRST for lo —
    # clean under BOTH insert and OR semantics — then rs=r3 hi-insert;
    # after w10 hi16(r3)==0 so insert and OR agree on w11 too);
    # w12 `ret.r zero,r8,r11' THE transfer (stock x3, no-link);
    # w13-w22 the REPLICA (all 10 words BYTE-EXACT stock — the
    # strongest precedent class possible); w23 W_FAST jump FN_A.
    # ZERO memory writes outside CR echoes on every path (restores are
    # READS; the pop addi r1,r1,0xf8 is the stock SP-restore register
    # word itself — stock-exact, and frame-write discipline concerns
    # memory writes, none exist); ZERO b_t; r4/r5/r6/r14-r16 never
    # touched.
    V5K_GOLDEN = [
        0x480300BC,        # w0  csr.r r3,csr0xbc
        0x002B00AC,        # w1  addi r11,r1,0xac
        0x642C00AB,        # w2  ld.w r12,r1,0xaa (filter)
        0x200D5332,        # w3  set3 r13,zero,0x5332
        0xE1806802,        # w4  cmp38_sel(2,12,13)
        0xA40A0012,        # w5  b_f.cc0A +18 -> W_FAST (w23, stock x27)
        0x6C046382,        # w6  st.d r12,zero,0x2380 (echo MAGIC16)
        0x642D00A5,        # w7  ld.w r13,r1,0xa4 (N)
        0x6C046B86,        # w8  st.d r13,zero,0x2384 (echo N)
        0x002B00AC,        # w9  addi r11,r1,0xac (payload ptr, == w1)
        0x2003D784,        # w10 set3 r3,zero,0xd784 (replica lo, rs=zero)
        0x246300B8,        # w11 set2 r3,r3,0x00b8 (replica hi insert)
        0xFD005825,        # w12 ret.r zero,r8,r11 (THE transfer, no-link)
        0x643700DE,        # w13 ld.d r23,r1,0xdc (REPLICA @0x38d784)
        0x643600E2,        # w14 ld.d r22,r1,0xe0
        0x643500E6,        # w15 ld.d r21,r1,0xe4
        0x643400EA,        # w16 ld.d r20,r1,0xe8
        0x643300EE,        # w17 ld.d r19,r1,0xec
        0x643200F2,        # w18 ld.d r18,r1,0xf0
        0x643100F6,        # w19 ld.d r17,r1,0xf4
        0x002100F8,        # w20 addi r1,r1,0xf8 (pop, stock @0x0e4304)
        0x64230006,        # w21 ld.d r3,r1,0x4 (OUTER [R+4], stock x8347)
        0xFD001825,        # w22 ret.r zero,r8,r3 (fn's own final word)
        0x95F8006E,        # w23 jump FN_A (W_FAST, last)
    ]
    REPLICA_SRC = 0x0E42E8                 # fn 0x0e4250 epilogue, 10 words
    REPLICA_LIVE = 0x800000 + STUB + 4 * 13   # 0xB8D784

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=16)

    def test_v5k_golden_words(self):
        self.assertEqual(self.ws(), self.V5K_GOLDEN)

    def test_v5k_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5k"), stub_words("A", version=16))
        self.assertEqual(stub_words("A", version="v5k"), stub_words("A", version=16))

    def test_v5k_prefix_v5j_w5_imm_only(self):
        # THE prefix contract vs v5j: w0-w4/w6-w8 == v5j BYTE-EXCEPT
        # except w5's IMMEDIATE (+6 -> +18: W_FAST moved w11 -> w23
        # when the r3-build pair + the 10-word replica were inserted);
        # op+cc bits identical.
        from build_s2 import stub_words
        wj, wk = stub_words("A", version=15), self.ws()
        self.assertEqual(len(wj), 12)
        self.assertEqual(wk[0:5], wj[0:5])
        self.assertEqual(wk[6:9], wj[6:9])
        self.assertEqual(wk[5], 0xA40A0012)                 # b_f.cc0A +18
        self.assertEqual((wk[5] >> 16), (wj[5] >> 16))      # op+cc identical
        self.assertEqual((wk[5] & 0xFFFF) - (wj[5] & 0xFFFF), 12)   # imm 6->18

    def test_v5k_replica_words_byte_exact_vs_stock(self):
        # THE core precedent contract: the 10 replica words (w13-w22)
        # are a BYTE-EXACT copy of the stock epilogue words
        # @0x0e42e8..0x0e430c — decoded from the base image (the
        # builder's own source) AND cross-checked against the census
        # blob.  Nothing is adjusted (no absolute immediate exists in
        # any of the 10 words — all register+offset forms).
        wd = self.ws()
        src = BASE.read_bytes()
        img = mlxfwutil.Image(src, "base")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        stock = [struct.unpack_from(">I", code, self.REPLICA_SRC + 4 * i)[0]
                 for i in range(10)]
        self.assertEqual(wd[13:23], stock)
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        b = blob.read_bytes()
        blobw = [struct.unpack_from(">I", b, self.REPLICA_SRC + 4 * i)[0]
                 for i in range(10)]
        self.assertEqual(stock, blobw)                      # base == blob
        self.assertEqual(wd[13:23], blobw)                  # replica == blob
        # every replica word is a byte-exact STOCK word (census counts)
        words = struct.unpack(">%dI" % (len(b) // 4), b)
        cnt = lambda x: sum(1 for w in words if w == x)
        self.assertEqual([cnt(w) for w in blobw],
                         [6, 7, 6, 5, 5, 3, 2, 17, 8347, 8346])

    def test_v5k_replica_decode_semantics(self):
        # decode-level contract of the replica block: 7 restores in the
        # STOCK reverse order (r23 @0xdc FIRST .. r17 @0xf4 LAST — the
        # mirror image of the saves 0x0e425c-74), then the pop, the
        # outer-ra load, the final ret.r.  Offsets/regs verified from
        # the stock decode (T33-review addresses confirmed).
        import irisc_dis
        wd = self.ws()
        dec = [irisc_dis.dis(w, 0) for w in wd[13:23]]
        self.assertEqual(dec, [
            "ld.d r23,r1,0xdc", "ld.d r22,r1,0xe0", "ld.d r21,r1,0xe4",
            "ld.d r20,r1,0xe8", "ld.d r19,r1,0xec", "ld.d r18,r1,0xf0",
            "ld.d r17,r1,0xf4", "addi r1,r1,0xf8",
            "ld.d r3,r1,0x4", "ret.r zero,r8,r3"])
        # the fn's own final word @0x0e430c is byte-exact the last
        # replica word (and the epilogue-pair load precedes it)
        src = BASE.read_bytes()
        img = mlxfwutil.Image(src, "base")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", code, 0x0E430C)[0],
                         wd[22])
        self.assertEqual(struct.unpack_from(">I", code, 0x0E4308)[0],
                         wd[21])

    def test_v5k_r3_build_words(self):
        # THE r3-build pair: w10 `set3 r3,ZERO,0xd784' (rs=zero — the
        # lo16 is CLEAN under BOTH semantics, the OR-semantics lesson
        # of journal task-32) THEN w11 `set2 r3,r3,0x00b8' (hi-insert
        # against the just-built value whose hi16 is 0 — insert and OR
        # agree) => r3 = 0x00B8D784 = live replica address, built from
        # the w0 residue r3=0x8E4380 (csr.r) deterministically.
        from build_s2 import stub_words
        wd = self.ws()
        self.assertEqual(self.REPLICA_LIVE, 0xB8D784)
        self.assertEqual(wd[10], enc.set3(3, 0, self.REPLICA_LIVE & 0xFFFF))
        self.assertEqual(wd[10], 0x2003D784)
        self.assertEqual((wd[10] >> 21) & 0x1F, 0)          # rs = ZERO
        self.assertEqual((wd[10] >> 16) & 0x1F, 3)          # rd = r3
        self.assertEqual(wd[11], (0x09 << 26) | (3 << 21) | (3 << 16)
                         | (self.REPLICA_LIVE >> 16))       # rs-bearing set2
        self.assertEqual(wd[11], 0x246300B8)
        self.assertEqual((wd[11] >> 21) & 0x1F, 3)          # rs = r3
        self.assertEqual((wd[11] >> 16) & 0x1F, 3)          # rd = r3
        # OR-safe (exact under BOTH semantics) from the REAL live
        # residue r3=0x8E4380 (what w0's csr.r leaves):
        for residue in (0x8E4380, 0, 0xFFFFFFFF, 0x12345678):
            for model in ("or", "insert"):
                if model == "or":
                    r = (0 & 0xFFFF0000) | ((0 & 0xFFFF) | 0xD784)
                    r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (0xB8 << 16))
                else:
                    r = (residue & ~0xFFFF & 0xFFFFFFFF) | 0xD784
                    r = (r & 0x0000FFFF) | (0xB8 << 16)
                self.assertEqual(r, 0x00B8D784,
                                 f"residue 0x{residue:x} {model}")
        # WRONG-form witness (the rs=rd set3 the v5j anomaly taught):
        # building the LO half from the residue register ORs garbage in
        r = (0x8E4380 & 0xFFFF0000) | ((0x8E4380 & 0xFFFF) | 0xD784)
        r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (0xB8 << 16))
        self.assertNotEqual(r, 0x00B8D784)                  # hi residue leaks
        self.assertEqual(r, 0x00BED784)                     # 0x8E-hi ORed in

    def test_v5k_r3_build_order_lo_first(self):
        # the OR-semantics-safe ORDER: the set3 (lo) word comes FIRST,
        # the set2 (hi) word SECOND — reversing them would OR the hi
        # build against the w0 residue's hi16 (0x8E..) and corrupt.
        wd = self.ws()
        self.assertEqual(wd[10] >> 26, 0x08)                # set3 (lo) first
        self.assertEqual(wd[11] >> 26, 0x09)                # set2 (hi) second

    def test_v5k_zero_memory_writes_pop_is_reg_write(self):
        # THE write-discipline contract, word level: NO op-0x1B word
        # with rs != zero (every store targets a CR slot — the
        # always-clean class); NOTHING writes memory; the ONLY r1
        # writer is w20 `addi r1,r1,0xf8' — the fn's own STOCK pop
        # word (byte-exact @0x0e4304), a REGISTER write (SP-restore),
        # not a frame memory write.  Reads (restores incl.) allowed.
        wd = self.ws()
        for i, w in enumerate(wd):
            if (w >> 26) == 0x1B:
                self.assertEqual(((w >> 21) & 0x1F), 0,
                                 f"w{i}=0x{w:08x} stores with rs != zero")
            if (w >> 26) == 0x00 and ((w >> 16) & 0x1F) == 1:
                self.assertEqual(i, 20, f"w{i}=0x{w:08x} writes r1")
        self.assertEqual(wd[20], 0x002100F8)                # stock pop word
        self.assertNotIn(0x703F0FC2, wd)                    # push: gone
        self.assertNotIn(0x6C206032, wd)                    # neutral write: gone

    def test_v5k_transfers_no_link(self):
        # THE control contract: exactly TWO op-0x3F words in the stub
        # — w12 `ret.r zero,r8,r11' (THE transfer into the payload;
        # rs=8 computed-jr class, NO LINK, stock x3) and w22
        # `ret.r zero,r8,r3' (the replica final = the fn's own ret.r,
        # stock x8346) — BOTH rs=8 no-link (csr0xbc keeps the
        # pre-detour ra; nothing on any path links).  The only jump
        # word is W_FAST (w23, last); no call words.
        wd = self.ws()
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x3F],
                         [12, 22])
        self.assertEqual(wd[12], enc.ret_r(8, 0, 11))
        self.assertEqual(wd[12], 0xFD005825)
        self.assertEqual(wd[22], enc.ret_r(8, 0, 3))
        self.assertEqual(wd[22], 0xFD001825)
        for i in (12, 22):
            self.assertEqual((wd[i] >> 21) & 0x1F, 8)       # rs = r8 (jr)
            self.assertNotEqual((wd[i] >> 21) & 0x1F, 0)    # NOT linking jalr
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x25],
                         [23])                              # W_FAST only
        self.assertEqual((wd[23] >> 24) & 1, 1)             # jump (no link)

    def test_v5k_w9_payload_ptr_reestablish(self):
        # w9 == w1 == `addi r11,r1,0xac`: the payload pointer
        # re-established immediately before the r3-build/transfer
        # (nothing between w9 and the transfer disturbs r11/r3).
        from build_s2 import stub_words, PAY_SRC_OFF_V5B
        wd = self.ws()
        self.assertEqual(PAY_SRC_OFF_V5B, 0xAC)
        self.assertEqual(wd[9], enc.addi(11, 1, PAY_SRC_OFF_V5B))
        self.assertEqual(wd[9], wd[1])
        self.assertEqual(wd[9], 0x002B00AC)

    def test_v5k_zero_bt_filter_only_conditional(self):
        # linearity contract: NO b_t words; the ONLY conditional is
        # the filter b_f (w5); the ONLY jump is W_FAST (w23); the ONLY
        # cmp is the filter (w4); no back-edge, no gates, no skips.
        wd = self.ws()
        for i, w in enumerate(wd):
            self.assertNotEqual(w >> 26, 0x28, f"w{i}=0x{w:08x} is b_t")
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x29],
                         [5])                               # filter ONLY
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x38],
                         [4])                               # one cmp (filter)

    def test_v5k_no_n_guard_no_gauntlet_words(self):
        # N never controls: no guard bound const, no N-vs-const cmp,
        # no gauntlet read/const; nothing gates on the code window.
        wd = self.ws()
        for w in (0x200C0004, 0x200C0002, 0x200C0003,   # guard/gate consts
                  0x200D2407,                            # gauntlet const
                  0x15AD0001,                            # subsi counter
                  0x002C0020, 0x65630002, 0x6D801802,   # copy block
                  0xA400FFFB):                           # back-edge
            self.assertNotIn(w, wd, f"gate/copy word 0x{w:08x} present")

    def test_v5k_wfast_last_and_filter_targets_it(self):
        wd = self.ws()
        w_fast = STUB + 4 * 23
        self.assertEqual(w_fast, 0x38D7AC)
        self.assertEqual(wd[23], enc.jump(w_fast, 0x18D964))
        self.assertEqual(wd[23], 0x95F8006E)
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))  # filter -> fast

    def test_v5k_word_delta_vs_v5j_exactly_replica_plus_build(self):
        # THE diff-vs-v5j contract: v5k rev.2 == v5j + the r3-build
        # pair + the 10-word replica, with the two position-dependent
        # immediates recomputed (w5 filter +6 -> +18; W_FAST imm
        # 0x7A -> 0x86E-relative form 0x95F8006E).  Everything else —
        # including the transfer word and both addi payload-ptr words
        # — identical.
        from build_s2 import stub_words
        wj, wk = stub_words("A", version=15), self.ws()
        self.assertEqual(set(wj) - set(wk),
                         {0xA40A0006, 0x95F8007A})
        self.assertEqual(set(wk) - set(wj),
                         {0xA40A0012, 0x2003D784, 0x246300B8, 0x95F8006E,
                          0x643700DE, 0x643600E2, 0x643500E6, 0x643400EA,
                          0x643300EE, 0x643200F2, 0x643100F6, 0x002100F8,
                          0x64230006, 0xFD001825})
        for w in (0x002B00AC, 0xFD005825):
            self.assertEqual(wk.count(w), wj.count(w), f"count drift 0x{w:08x}")
        for w in (0x480300BC, 0x642C00AB, 0x200D5332, 0xE1806802,
                  0x6C046382, 0x642D00A5, 0x6C046B86):
            self.assertEqual(wk.count(w), wj.count(w), f"count drift 0x{w:08x}")

    def test_v5k_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 24)                # 24/34
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5k_clobber_confined(self):
        # rev.2 clobber contract: r4/r5/r6 (site args) and r14/r15/r16
        # NEVER touched; r17-r23 ARE touched — ONLY by the replica
        # RESTORE words (the fn's own epilogue semantics: the fix for
        # review Important-2); r1 written only by the stock pop.
        import irisc_dis
        wd = self.ws()
        dec = [irisc_dis.dis(w, 0) for w in wd]
        for s in dec:
            for reg in ("r4", "r5", "r6", "r14", "r15", "r16"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")
        for i, s in enumerate(dec):
            hits = [reg for reg in ("r17", "r18", "r19", "r20", "r21",
                                    "r22", "r23") if reg + "," in s]
            if hits:
                self.assertTrue(13 <= i <= 19,
                                f"w{i} {s!r} touches {hits} outside replica")

    def test_v5k_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=16)

    def test_v5k_stock_precedents(self):
        # NEW-word stock counts (census blob whole-image, re-verified
        # this task):
        #   w5 retarget b_f.cc0A +18 (0xA40A0012) x27 — stock-exact
        #   w10 set3 r3,zero,0xd784 (0x2003D784) x0 — live-form: the
        #     set3 rs=zero class x7348 + v5i-neutral-write live x4
        #   w11 set2 r3,r3,0xb8 (0x246300B8) x0 — live-form (set2
        #     rs=rd hi-insert = the S2OK p1 live-exact class)
        #   W_FAST jump imm (0x95F8006E) x0 — live-form class (every
        #     prior W_FAST word 0-count, live-clean x7+)
        #   ALL 10 replica words byte-exact stock (counts 6/7/6/5/5/3/2/
        #     17/8347/8346 — the strongest precedent class possible;
        #     asserted in detail in test_v5k_replica_words_byte_exact)
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        cnt = lambda x: sum(1 for w in words if w == x)
        ws = self.ws()
        self.assertEqual(cnt(0xA40A0012), 27)                # w5 retarget
        self.assertEqual(cnt(0x2003D784), 0)                 # w10: live-form
        self.assertEqual(cnt(0x246300B8), 0)                 # w11: live-form
        self.assertEqual(cnt(0x95F8006E), 0)                 # W_FAST: live-form
        for w in ws[13:23]:
            self.assertGreater(cnt(w), 0,
                               "replica word 0x%08x not stock" % w)
        s3_zero = sum(1 for w in words if (w >> 26) == 0x08
                      and ((w >> 21) & 0x1F) == 0)
        self.assertEqual(s3_zero, 7348)                      # set3 rs=zero class
        # every word of the stub is stock-exact, live-exact (v5b..v5j
        # lineage goldens) or documented (the two build words + W_FAST)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7)) \
            | set(stub_words("A", version=8)) | set(stub_words("A", version=9)) \
            | set(stub_words("A", version=10)) | set(stub_words("A", version=11)) \
            | set(stub_words("A", version=12)) | set(stub_words("A", version=13)) \
            | set(stub_words("A", version=14)) | set(stub_words("A", version=15))
        documented = {0x2003D784, 0x246300B8, 0x95F8006E}
        for w in ws:
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5k_lineage_untouched(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)
        self.assertEqual(len(stub_words("A", version=9)), 33)
        self.assertEqual(len(stub_words("A", version=10)), 30)
        self.assertEqual(len(stub_words("A", version=11)), 32)
        self.assertEqual(len(stub_words("A", version=12)), 23)
        self.assertEqual(len(stub_words("A", version=13)), 22)
        self.assertEqual(len(stub_words("A", version=14)), 15)
        self.assertEqual(len(stub_words("A", version=15)), 12)
        self.assertEqual(len(stub_words("A", version=16)), 24)

class TestS2StubV5KSim(unittest.TestCase):
    # v5k rev.2 per-path REGISTER-TRUE simulation with PAYLOAD and
    # REPLICA execution.  The Sim model (re-based from rev.1 after the
    # T33 review):
    #   (a) the LIVE ROOT-CAUSED set3/set2 semantics (journal task-32
    #       phase-2): set3 ORs imm into the SOURCE's lo16 when
    #       building, set2 ORs into the hi half the same way (the v5j
    #       anomaly witness: rs=r12=0x5332 -> 0x5332|0x4F4B = 0x5F7B
    #       EXACT); insert and OR agree whenever the respective source
    #       half is zero (rs=zero ALWAYS);
    #   (b) THE FN FRAME MODEL (review Critical-1 grounding): r1 at
    #       the detour is R-0xf8 — the fn 0x0e4250 pushed 0xf8
    #       @0x0e4258 and the detour path NEVER pops (the pop
    #       @0x0e4304 is epilogue-path only); the INNER mem[r1+4]
    #       holds the last nested-call resume (call 0xcaec0 @0x0e4358
    #       -> 0x8E435C — the livelock value); the OUTER mem[r1+0xf8+4]
    #       holds the fn's true saved ra (the prologue store @0x0e4254
    #       of csr0xbc at fn entry = the DISPATCHER's call resume —
    #       the value chain verified from the stock decode); the save
    #       slots mem[r1+0xdc..0xf4] hold r17..r23 (saves @0x0e425c-74);
    #       r17-r23 arrive CLOBBERED (the fn body modifies them —
    #       review Important-2);
    #   (c) ret.r to a live EA INSIDE the stub zone CONTINUES as stub
    #       words — THE REPLICA executes (w13-w22) as part of the run;
    #       a live EA outside the stub is an EXIT (exit_ea records
    #       it); a wild low stack fetch stays DEAD;
    #   (d) LIVE address space: stub words at file+0x800000, payload
    #       words at the stack EA r1+0xac+4i.
    # THE contracts (dispatch): w10/w11 build r3 = 0xB8D784 (the
    # replica live address) BEFORE the transfer — under the model's OR
    # semantics from the REAL w0 residue r3=0x8E4380; the payload CR
    # writes are {0x2388: S2OK} ONLY; p3 exits into the REPLICA; the
    # replica restores r17-r23 from the save slots, pops r1 by 0xf8
    # (r1 == R at the end), reads the OUTER [R+4] (NEVER the inner
    # residue) and exits to the dispatcher ra — BASE-INDEPENDENT by
    # construction (no word encodes any stack absolute; asserted by
    # sweeping r1 over ALL 16 SP bases with the FIXED word list).
    R1E = 0x1000
    STUB_LIVE = 0x800000 + 0x38D750
    FN_A_LIVE = 0x98D964                      # == 0x800000 + build_s2 FN_A
    RA_LIVE = 0x8E4380                        # pre-detour ra (call @0x0e437c +4)
    INNER_RA = 0x8E435C                       # [(R-0xf8)+4] residue: the
                                             # caec0-call resume (livelock value)
    OUTER_RA = 0x8AA1D8                       # [R+4]: the dispatcher's call
                                             # resume (task-30 Q1 dispatch PC)
    SAVED_REGS = (23, 22, 21, 20, 19, 18, 17)  # slot order 0xdc..0xf4

    class SimV5K:
        def __init__(self, ws, N, magic=True, code=None, r1=None,
                     outer_ra=None, inner_ra=None):
            TestS = TestS2StubV5KSim
            r1 = TestS.R1E if r1 is None else r1
            self.ws = ws
            self.mem = {}
            self.cr = {0x2380: 0, 0x2384: 0, 0x2388: 0, 0x238C: 0}
            self.csr0xbc = TestS.RA_LIVE
            self.links = []                                 # (ea, kind) link events
            self.mem[r1 + 0xA4] = N
            self.mem[r1 + 0xAA] = 0x5332 if magic else 0x1234
            self.mem[r1 + 0x4] = (TestS.INNER_RA if inner_ra is None
                                  else inner_ra)            # INNER residue seed
            self.mem[r1 + 0xF8 + 0x4] = (TestS.OUTER_RA if outer_ra is None
                                         else outer_ra)     # OUTER dispatcher ra
            for i, reg in enumerate(TestS.SAVED_REGS):      # save slots (saves
                self.mem[r1 + 0xDC + 4 * i] = 0xCAFE0000 + reg  # @0x0e425c-74)
            for i, cw in enumerate(code):
                self.mem[r1 + 0xAC + 4 * i] = cw
            self.r = {1: r1, 3: 0xDEAD, 11: 0, 12: 0, 13: 0}
            for reg in TestS.SAVED_REGS:                    # arrive CLOBBERED
                self.r[reg] = 0xDEAD0000 + reg              # (Important-2)
            self.pc = 0
            self.eq = False
            self.z32 = False
            self.stores = []
            self.taken = []                                 # (i, op, cc, latch)
            self.pay_fetch = []                             # payload word EAs
            self.exit_ea = None                             # recorded exit target
            self.n = 0                                      # step counter
            self.load_log = []                              # (step, rt, ea)
            self.fetch_steps = []                           # (step, ea)
            self.r1_writes = []                             # (step, new r1)
            self.replica_entry = None                       # step p3 entered replica

        def rd(self, k):
            return 0 if k == 0 else self.r[k]

        def run(self, max_steps=200):
            import irisc_dis
            STUB_L = TestS2StubV5KSim.STUB_LIVE
            FN_A_L = TestS2StubV5KSim.FN_A_LIVE
            for _ in range(max_steps):
                if isinstance(self.pc, int):
                    i = self.pc
                    if not 0 <= i < len(self.ws):
                        return "WILD_%08x" % (STUB_L + 4 * i)
                    word = self.ws[i]
                    ea = STUB_L + 4 * i                     # LIVE stub PC
                    nxt = i + 1
                else:
                    ea = self.pc[1]                         # LIVE stack PC
                    if ea >= 0x800000:
                        # a live target INSIDE the stub zone = the REPLICA
                        off = ea - STUB_L
                        if 0 <= off < 4 * len(self.ws) and off % 4 == 0:
                            if self.replica_entry is None:
                                self.replica_entry = self.n
                            self.pc = off // 4
                            continue
                        self.exit_ea = ea                   # code target: EXIT
                        return "EXIT_%08x" % ea
                    if ea not in self.mem:
                        return "DEAD_%08x" % ea
                    word = self.mem[ea]
                    self.pay_fetch.append(ea)
                    self.fetch_steps.append((self.n, ea))
                    nxt = ("ea", ea + 4)
                self.n += 1
                op = word >> 26
                if op == 0x12:                              # csr.r
                    self.r[3] = self.csr0xbc
                elif op == 0x00:                            # addi
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    rd = (word >> 16) & 0x1F
                    self.r[rd] = \
                        (self.rd((word >> 21) & 0x1F) + imm) & 0xFFFFFFFF
                    if rd == 1:
                        self.r1_writes.append((self.n - 1, self.r[1]))
                elif op == 0x08:                            # set3: OR into lo16
                    # LIVE root-caused semantics (journal task-32
                    # phase-2): 0x5332|0x4F4B = 0x5F7B — the v5j
                    # anomaly reproduced EXACTLY by this model
                    rs = self.rd((word >> 21) & 0x1F)
                    self.r[(word >> 16) & 0x1F] = \
                        (rs & 0xFFFF0000) | ((rs & 0xFFFF) | (word & 0xFFFF))
                elif op == 0x09:                            # set2: OR into hi16
                    rs = self.rd((word >> 21) & 0x1F)
                    self.r[(word >> 16) & 0x1F] = \
                        (rs & 0x0000FFFF) | ((rs & 0xFFFF0000)
                                            | ((word & 0xFFFF) << 16))
                elif op == 0x19:                            # ld.w / ld.d
                    rt, rs = (word >> 16) & 0x1F, (word >> 21) & 0x1F
                    if word & 1:
                        off = ((word >> 1) & 0x7FFF) << 1
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0) & 0xFFFF
                    else:
                        off = ((word >> 2) & 0x3FFF) << 2
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0)
                    self.load_log.append((self.n - 1, rt, self.rd(rs) + off))
                elif op == 0x1B:                            # st.d / st.w
                    rt, rs = (word >> 11) & 0x1F, (word >> 21) & 0x1F
                    off = (((word >> 16) & 0x1F) << 11) \
                        | (((word >> 2) & 0x1FF) << 2)
                    if rs == 0:
                        self.cr[off] = self.r[rt]
                        self.stores.append((off, self.r[rt], "CR"))
                    else:
                        ea = (self.rd(rs) + off) & 0xFFFFFFFF
                        kind = "STACK" if self.r[1] - 0x40 <= ea < self.r[1] else "ABS"
                        self.mem[ea] = self.r[rt]
                        self.stores.append((ea, self.r[rt], kind))
                elif op == 0x38:                            # cmp38_sel eq32
                    self.eq = self.rd((word >> 21) & 0x1F) == \
                        self.rd((word >> 11) & 0x1F)
                elif op in (0x28, 0x29):                    # b_t / b_f (stub words)
                    if not isinstance(self.pc, int):
                        return "UNSUPPORTED_branch_in_payload"
                    cc = (word >> 16) & 0x1F
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    cond = self.eq if cc == 0x0A else self.z32 if cc == 0 else False
                    if (cond if op == 0x28 else not cond):
                        self.taken.append((self.pc, op, cc, cond))
                        nxt = self.pc + imm
                elif op == 0x25:                            # jump/call: ACTUAL (live) ea
                    if not word & 0x01000000:               # call: LINKS
                        self.csr0xbc = (ea + 4) & 0xFFFFFFFF
                        self.links.append((ea, "call"))
                    tgt = ea + irisc_dis.s24(word) * 4
                    j = (tgt - STUB_L) // 4
                    if 0 <= j < len(self.ws) and tgt == STUB_L + 4 * j:
                        nxt = j
                    elif tgt == FN_A_L:
                        self.exit_ea = tgt
                        return "FN_A"
                    else:
                        self.exit_ea = tgt
                        return "EXIT_%08x" % tgt
                elif op == 0x3F and (word & 0x1FF) == 0x25:  # ret.r
                    rs, rt = (word >> 21) & 0x1F, (word >> 11) & 0x1F
                    if rs == 0:                             # jalr: LINKS
                        self.csr0xbc = (ea + 4) & 0xFFFFFFFF
                        self.links.append((ea, "jalr"))
                    nxt = ("ea", self.rd(rt))               # both rs=0/rs=8 goto [rt]
                else:
                    return "UNSUPPORTED_op_%02x" % op
                self.pc = nxt
            return "RUNAWAY"

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=16)

    def payload_words(self):
        import payload as pl
        return pl.payload_v5k()

    def test_sim_fallthrough_no_store_no_transfer(self):
        s = self.SimV5K(self.ws(), 4, magic=False, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.exit_ea, 0x98D964)              # LIVE FN_A (file imm + live EA)
        self.assertEqual(s.stores, [])                      # no CR, no stack
        self.assertEqual(s.r[1], self.R1E)                  # r1 untouched (no pop!)
        self.assertEqual(s.pay_fetch, [])                   # no transfer
        self.assertEqual(s.replica_entry, None)             # replica never runs
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])  # w5 taken at false
        self.assertEqual(s.links, [])                       # W_FAST = jump, no link
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # csr0xbc untouched

    def test_sim_magic_path_full_contract(self):
        # THE exec path (Exit-D rev.2): prefix (echoes) -> w9 (r11 =
        # r1+0xAC) -> w10/w11 (r3 = 0xB8D784 replica address) -> w12
        # (register transfer, NO LINK) -> payload p0..p3 from the
        # landing zone -> p3 enters the REPLICA (w13) -> 7 restores ->
        # pop (r1 = R) -> ld.d r3 = the OUTER [R+4] dispatcher ra ->
        # ret.r -> EXIT to the dispatcher.  CR contract:
        # 0x2380=MAGIC16, 0x2384=N, 0x2388=S2OK, 0x238C=0; r17-r23
        # RESTORED; r1 POPPED; ZERO taken conditionals; ZERO links;
        # ZERO stack/absolute writes.
        s = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.OUTER_RA)
        self.assertEqual(s.exit_ea, self.OUTER_RA)
        self.assertNotEqual(s.exit_ea, self.INNER_RA)       # NOT the livelock value
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                         (0x5332, 4, 0x53324F4B, 0))
        self.assertEqual(s.r[11], self.R1E + 0xAC)          # r11 at/after transfer
        self.assertEqual(s.r[1], self.R1E + 0xF8)           # r1 POPPED (R)
        self.assertEqual(s.r[3], self.OUTER_RA)             # replica final load
        self.assertEqual(s.r[12], 0x53324F4B)               # payload build result
        for reg in self.SAVED_REGS:                         # Important-2 fixed
            self.assertEqual(s.r[reg], 0xCAFE0000 + reg,
                             f"r{reg} not restored")
        self.assertEqual(s.taken, [])                       # ZERO taken
        self.assertEqual(s.links, [])                       # ZERO links
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # no-link contract
        kinds = {k for _, _, k in s.stores}
        self.assertEqual(kinds, {"CR"})                     # CR writes only

    def test_sim_replica_restores_each_reg_from_its_slot(self):
        # the 7 restores read each register's OWN save slot (the
        # saves @0x0e425c-74 mapping, verified from the decode):
        # r23 <- [r1+0xdc], r22 <- [r1+0xe0], ..., r17 <- [r1+0xf4],
        # in the STOCK reverse order (r23 first).
        s = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.OUTER_RA)
        seq = [(rt, ea) for _, rt, ea in s.load_log if 17 <= rt <= 23]
        R = self.R1E + 0xF8
        self.assertEqual(seq, [(23, R - 0xF8 + 0xDC), (22, R - 0xF8 + 0xE0),
                               (21, R - 0xF8 + 0xE4), (20, R - 0xF8 + 0xE8),
                               (19, R - 0xF8 + 0xEC), (18, R - 0xF8 + 0xF0),
                               (17, R - 0xF8 + 0xF4)])
        self.assertEqual(seq[0][1], self.R1E + 0xDC)        # r23 slot FIRST
        self.assertEqual(seq[-1][1], self.R1E + 0xF4)       # r17 slot LAST

    def test_sim_pop_before_outer_read(self):
        # THE Critical-1 fix, path level: the replica POPS first
        # (r1 += 0xf8 — exactly one r1 write, the stock pop word),
        # THEN loads [r1+4] — the step log proves the final load's EA
        # is the OUTER slot R+4; the INNER residue slot (R-0xf8)+4 is
        # NEVER read by anything on the magic path.
        s = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.OUTER_RA)
        R = self.R1E + 0xF8
        self.assertEqual(s.r1_writes, [(s.r1_writes[0][0], R)])   # ONE pop
        pop_step = s.r1_writes[0][0]
        final_ld = [e for e in s.load_log if e[1] == 3]
        self.assertEqual(len(final_ld), 1)                  # only the replica ld
        step, rt, ea = final_ld[0]
        self.assertEqual(ea, R + 4)                         # the OUTER slot
        self.assertLess(pop_step, step)                     # pop BEFORE read
        inner_eas = [e for _, _, e in s.load_log if e == self.R1E + 4]
        self.assertEqual(inner_eas, [])                     # inner NEVER read
        self.assertEqual(s.exit_ea, self.OUTER_RA)

    def test_sim_rev1_exit_d_livelock_witness(self):
        # Critical-1 regression witness: the REV.1 stub (commit 40d902a,
        # 13 words — golden below) loaded r3 from the INNER [r1+4] and
        # its p3 exit went to the seeded residue 0x8E435C — the resume
        # of `call 0xcaec0` @0x0e4358.  The stock decode proves the
        # region [0x0e435c, 0x0e437c) is LINEAR (no control words) and
        # falls straight into the detour call @0x0e437c: on HW the exit
        # re-executes the detour -> stub -> payload -> exit again =>
        # DETERMINISTIC LIVELOCK (the review's Critical-1, grounded).
        REV1 = [0x480300BC, 0x002B00AC, 0x642C00AB, 0x200D5332,
                0xE1806802, 0xA40A0007, 0x6C046382, 0x642D00A5,
                0x6C046B86, 0x002B00AC, 0x64230006, 0xFD005825,
                0x95F80079]
        s = self.SimV5K(REV1, 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.INNER_RA)
        self.assertEqual(s.exit_ea, self.INNER_RA)          # rev.1: inner!
        self.assertEqual(s.r[1], self.R1E)                  # rev.1 never pops
        self.assertEqual(s.cr[0x2388], 0x53324F4B)          # S2OK fired once
        # decode: linear region -> the exit re-enters the detour
        src = BASE.read_bytes()
        img = mlxfwutil.Image(src, "base")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        for a in range(0x0E435C, 0x0E437C, 4):
            wd = struct.unpack_from(">I", code, a)[0]
            op = wd >> 26
            ctl = op in (0x25, 0x28, 0x29) or (op == 0x3F and (wd & 0x1FF) == 0x25)
            self.assertFalse(ctl, f"word @0x{a:x} is control — witness broken")
        # and rev.2 with the SAME seeds exits to the OUTER ra instead
        s2 = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s2.run(), "EXIT_%08x" % self.OUTER_RA)

    def test_sim_r3_build_before_transfer(self):
        # w10/w11 build r3 = the replica live address BEFORE the w12
        # transfer — the model's OR semantics with the REAL w0 residue
        # (csr.r r3 = 0x8E4380) prove the pair residue-proof; p3
        # enters the replica (replica_entry recorded before any
        # further stub steps), pay_fetch[0] is the payload landing.
        s = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.OUTER_RA)
        self.assertEqual(s.replica_entry is not None, True)
        self.assertLess(s.replica_entry, 30)                # early: right after p3
        self.assertEqual(s.pay_fetch[0], s.r[11])
        # the transfer's target register content at p3 time == replica
        # (checked via the replica actually being entered from r3)
        self.assertEqual(s.replica_entry >= s.fetch_steps[-1][0], True)

    def test_sim_r3_value_exact_under_or_semantics(self):
        # the executing model (OR semantics built in — the v5j anomaly
        # witness model) builds r3 = 0xB8D784 EXACTLY on the way to
        # the replica: w0 leaves r3 = 0x8E4380 (the live residue), w10
        # (rs=zero) zeroes the lo, w11 inserts the hi — non-vacuous by
        # construction (the residue flows through the model registers).
        s = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.OUTER_RA)
        self.assertEqual(s.replica_entry is not None, True)  # r3 landed IN stub
        # re-derive with the same OR model, residue-tracked:
        r = 0x8E4380                                          # w0: csr.r residue
        r = (0 & 0xFFFF0000) | ((0 & 0xFFFF) | 0xD784)        # w10: set3 rs=zero
        r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (0xB8 << 16))  # w11: set2
        self.assertEqual(r, 0x00B8D784)
        self.assertEqual(0x00B8D784, self.STUB_LIVE + 4 * 13)

    def test_sim_landing_map_k14(self):
        # THE landing map: input halfword/word k=0x14+4i lands at
        # [r1+0x98+0x14+4i] = [r1+0xac+4i] — the payload fetch
        # sequence IS the map (4 words, strictly consecutive).
        s = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.OUTER_RA)
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0x98 + 0x14 + 4 * i for i in range(4)])
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0xAC + 4 * i for i in range(4)])

    def test_sim_zero_stack_writes_all_paths(self):
        # THE write-discipline assertion, path level: on EVERY path
        # (magic and fallthrough) the store log contains NO stack and
        # NO absolute writes — the replica's restores are READS and
        # its pop is a REGISTER write; the freeze-#9 class (tail-frame
        # x ANY extra write into the pushed frame) cannot fire.
        for magic in (True, False):
            s = self.SimV5K(self.ws(), 4, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.OUTER_RA),
                            f"magic={magic}: unexpected {out}")
            for ea, v, k in s.stores:
                self.assertNotIn(k, ("STACK", "ABS"),
                                 f"magic={magic}: non-CR write 0x{ea:x}")

    def test_sim_no_link_csr0xbc_untouched(self):
        # the transfer, the payload exit AND the replica final are ALL
        # rs=8 no-link words: csr0xbc keeps the PRE-DETOUR ra through
        # the whole magic path — no link event anywhere.
        s = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.OUTER_RA)
        self.assertEqual(s.links, [])                       # no jalr/call link events
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # pre-detour ra intact
        wd = self.ws()
        self.assertEqual(wd[12], enc.ret_r(8, 0, 11))
        self.assertEqual(wd[22], enc.ret_r(8, 0, 3))
        self.assertEqual(self.payload_words()[3], enc.ret_r(8, 0, 3))
        self.assertNotIn(enc.ret_r(0, 0, 11), wd)

    def test_sim_exit_targets_seeded_outer_ra(self):
        # THE Exit-D rev.2 contract: the replica's final ret.r exits
        # THROUGH r3 = the OUTER [R+4] — whatever the fn's prologue
        # saved there (the dispatcher's call resume).  Seeds include
        # the REAL dispatch-table PCs of task-30 Q1 (0x8aa1d8/
        # 0x8acedc live) — the exit TRACKS the seed, word-for-word
        # identical payload every time, while the inner residue stays
        # poisoned at 0x8E435C.
        for seed in (0x8AA1D8, 0x8ACEDC, 0x8E42BC, 0x900004):
            s = self.SimV5K(self.ws(), 4, code=self.payload_words(),
                            outer_ra=seed)
            self.assertEqual(s.run(), "EXIT_%08x" % seed, f"seed 0x{seed:x}")
            self.assertEqual(s.exit_ea, seed)
            self.assertNotEqual(s.exit_ea, self.INNER_RA)
            self.assertEqual(s.cr[0x2388], 0x53324F4B)      # C1 intact

    def test_sim_exit_base_independence_all_16_sp_bases(self):
        # THE v5k headline contract: the SAME FIXED word list (stub
        # AND payload — built ONCE, outside the sweep; no word encodes
        # any stack absolute) exits correctly from EVERY SP base
        # (SP-init 0x7d1ff8 + (cpuinfo&0xf)<<13, all 16 cores): the
        # exit target TRACKS the seeded OUTER [R+4] at each base, the
        # frame is POPPED, r17-r23 restored and the C1 signal lands
        # everywhere.  The v5j p3 base-dependence is GONE BY
        # CONSTRUCTION; the rev.1 inner-read livelock is GONE BY
        # CONSTRUCTION (the replica pops first).
        import payload as pl
        fixed_stub, fixed_payload = self.ws(), pl.payload_v5k()
        for k in range(16):
            base = 0x7D1FF8 + k * 0x2000
            seed = self.OUTER_RA + 4 * k                 # distinct per base
            s = self.SimV5K(fixed_stub, 4, code=fixed_payload, r1=base,
                            outer_ra=seed)
            self.assertEqual(s.run(), "EXIT_%08x" % seed, f"base 0x{base:x}")
            self.assertEqual(s.exit_ea, seed, f"base 0x{base:x}")
            self.assertEqual(s.cr[0x2388], 0x53324F4B, f"base 0x{base:x}")
            self.assertEqual(s.r[1], base + 0xF8, f"base 0x{base:x}: popped")
            for reg in self.SAVED_REGS:
                self.assertEqual(s.r[reg], 0xCAFE0000 + reg,
                                 f"base 0x{base:x}: r{reg} restored")
            self.assertEqual(s.pay_fetch, [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")
        # and the frame bytes are ONE frame for ALL bases (no param)
        self.assertEqual(len(pl.input_block_v5k()), 0x24)

    def test_sim_s2ok_exact_from_filter_residue(self):
        # THE Fix-1 contract under the LIVE ROOT-CAUSED OR semantics
        # — non-vacuous form: the WRONG (v5j rs=rd) p0 form is modeled
        # WITH the seed flowing through it (seed-dependent garbage;
        # the live residue 0x5332 reproduces the observed 0x5F7B
        # anomaly EXACTLY), while the v5k p0 (rs=zero) is clean for
        # EVERY seed.  (c) the executing model lands S2OK exact.
        # (a) anomaly witness: the OR model reproduces the v5j value
        r = 0x5332                                            # filter residue
        r = (r & 0xFFFF0000) | ((r & 0xFFFF) | 0x4F4B)        # v5j p0 form
        self.assertEqual(r, 0x5F7B)                           # == live CR value
        self.assertNotEqual(r, 0x4F4B)
        # (b) discriminator: wrong form is seed-DEPENDENT (and wrong
        # for the live residue); v5k form is clean for every seed
        for seed in (0x5332, 0, 0xFFFFFFFF, 0x12345678, 0x5F7B):
            wrong = (seed & 0xFFFF0000) | ((seed & 0xFFFF) | 0x4F4B)
            right = (0 & 0xFFFF0000) | ((0 & 0xFFFF) | 0x4F4B)
            self.assertEqual(right, 0x4F4B, f"seed 0x{seed:x}")
            if seed & 0xFFFF:
                self.assertNotEqual(wrong, right, f"seed 0x{seed:x}")
        self.assertEqual((0x5332 & 0xFFFF) | 0x4F4B, 0x5F7B)  # the live one
        # (c) full-run: the executing model (OR semantics built in)
        # builds S2OK EXACT from the live filter residue path
        s = self.SimV5K(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.OUTER_RA)
        self.assertEqual(s.r[12], 0x53324F4B)
        self.assertEqual(s.cr[0x2388], 0x53324F4B)

    def test_sim_branch_inventory_all_paths(self):
        # THE branch-inventory table: magic -> ZERO taken
        # conditionals (the ONLY conditional word is the filter b_f,
        # not-taken at magic); fallthrough -> w5 taken once at latch
        # FALSE (the live-proven clean class).  No b_t words exist.
        for n, magic, want in ((4, True, []), (1, True, []), (4, False, [(5, 0x29, 0x0A, False)])):
            s = self.SimV5K(self.ws(), n, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.OUTER_RA),
                            f"N={n} magic={magic}: {out}")
            self.assertEqual(s.taken, want, f"N={n} magic={magic}")

    def test_sim_trig_frame_bytes_drive_the_path(self):
        # THE TRIG frame (the exact 36B host bytes of the live phase)
        # drives the full path at SEVERAL bases — the SAME frame
        # bytes (no base parameter exists): unpack N / MAGIC16 / the
        # 4 payload words FROM THE FRAME BYTES, run, and the exit
        # lands on the seeded OUTER dispatcher-ra everywhere.
        import payload as pl
        frame = pl.input_block_v5k()
        b = bytes.fromhex(frame.hex())
        n = struct.unpack(">H", b[0xC:0xE])[0]
        magic16 = struct.unpack(">H", b[0x12:0x14])[0]
        words = list(struct.unpack(">4I", b[0x14:0x24]))
        self.assertEqual((n, magic16), (4, 0x5332))
        for base in (self.R1E, 0x7D1FF8, 0x7D9FF8, 0x7EFFF8):
            seed = self.OUTER_RA + 0x10
            s = self.SimV5K(self.ws(), n, code=words, r1=base,
                            outer_ra=seed)
            self.assertEqual(s.run(), "EXIT_%08x" % seed, f"base 0x{base:x}")
            self.assertEqual((s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                             (4, 0x53324F4B, 0), f"base 0x{base:x}")
            self.assertEqual(s.r[1], base + 0xF8, f"base 0x{base:x}: popped")
            self.assertEqual(s.pay_fetch, [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")


class TestS2StubV5L(unittest.TestCase):
    # v5l (task-34, journal task-33 phase-2 grounding): v5k rev.2 MINUS
    # the replica — r3 preloads THE CALL-SITE RESUME 0x008E4380 (live
    # = file 0x0E437C detour call + 4; the value csr0xbc holds at detour
    # entry, the value stock FN_A returns through: FN_A's own prologue
    # `csr.r r3,csr0xbc` @0x18d964 is BYTE-EXACT the stub's w0).  The
    # v5k live run PROVED the payload 4/4 executed from the input
    # landing with CR 0x2388 = 0x53324F4B EXACT (C1 criterion
    # achieved) but the replica exit WEDGED — the fn body AFTER the
    # call-site (which builds the QUERY completion: stock decode
    # 0x0E4380 `or r19,r4,r4` -> 0x0E4384 `subsi r4,r19,0x0` ->
    # 0x0E4388 `b.f.0x0 ->0x8E42E4` early-exit vs the 0x0E438C+ QUERY
    # path) never ran.  v5l returns the payload INTO the body at the
    # resume point AS FN_A's return would: p3 `ret.r zero,r8,r3` with
    # r3 = 0x8E4380 -> body -> stock completion.  r4 at resume = 0
    # (v5i-documented stock arg setup `addi r4,zero,0` @0x0E4374) ==
    # the stock post-FN_A BadParam value; r1 = R-0xf8 (the fn frame,
    # as at any FN_A return — the BODY pops it, not us).
    # Layout (14 words, W_FAST LAST @w13 = 0x38d784): prefix w0-w8 ==
    # v5k byte-exact except w5's immediate (+18 -> +8: W_FAST moved
    # w23 -> w13; 0xA40A0008 stock-exact x74 — the BEST prefix-retarget
    # count of the lineage); w9 payload ptr (== w1); w10 `set3
    # r3,ZERO,0x4380` + w11 `set2 r3,r3,0x008e` build r3 = 0x008E4380
    # (OR-semantics-safe order: rs=zero FIRST for lo — clean under
    # BOTH insert and OR semantics — then rs=r3 hi-insert; after w10
    # hi16(r3)==0 so insert and OR agree on w11 too; the w0 csr.r
    # residue IS 0x8E4380 already — the pair rebuilds it explicitly,
    # deterministic from ANY residue); w12 `ret.r zero,r8,r11' THE
    # transfer (stock x3, no-link); w13 W_FAST jump FN_A.  The REPLICA
    # IS DELETED — no fn-exit words, no restores, NO POP (the body's
    # own epilogue does all of that on HW): ZERO memory writes outside
    # the CR echoes, ZERO r1 writes at all, r17-r23 NEVER touched (the
    # body's epilogue restores them), ZERO b_t; r4/r5/r6/r14-r16 never
    # touched.
    V5L_GOLDEN = [
        0x480300BC,        # w0  csr.r r3,csr0xbc (residue = 0x8E4380)
        0x002B00AC,        # w1  addi r11,r1,0xac
        0x642C00AB,        # w2  ld.w r12,r1,0xaa (filter)
        0x200D5332,        # w3  set3 r13,zero,0x5332
        0xE1806802,        # w4  cmp38_sel(2,12,13)
        0xA40A0008,        # w5  b_f.cc0A +8 -> W_FAST (w13, stock x74)
        0x6C046382,        # w6  st.d r12,zero,0x2380 (echo MAGIC16)
        0x642D00A5,        # w7  ld.w r13,r1,0xa4 (N)
        0x6C046B86,        # w8  st.d r13,zero,0x2384 (echo N)
        0x002B00AC,        # w9  addi r11,r1,0xac (payload ptr, == w1)
        0x20034380,        # w10 set3 r3,zero,0x4380 (resume lo, rs=zero)
        0x2463008E,        # w11 set2 r3,r3,0x008e (resume hi insert)
        0xFD005825,        # w12 ret.r zero,r8,r11 (THE transfer, no-link)
        0x95F80078,        # w13 jump FN_A (W_FAST, last)
    ]
    RESUME_LIVE = 0x008E4380              # == PC_BASE + DETOUR_DC + 4

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=17)

    def test_v5l_golden_words(self):
        self.assertEqual(self.ws(), self.V5L_GOLDEN)

    def test_v5l_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5l"), stub_words("A", version=17))
        self.assertEqual(stub_words("A", version="v5l"), stub_words("A", version=17))

    def test_v5l_prefix_v5k_w5_imm_only(self):
        # THE prefix contract vs v5k: w0-w4/w6-w8 == v5k BYTE-EXCEPT
        # except w5's IMMEDIATE (+18 -> +8: W_FAST moved w23 -> w13
        # when the 10-word replica was deleted); op+cc bits identical.
        from build_s2 import stub_words
        wk, wl = stub_words("A", version=16), self.ws()
        self.assertEqual(len(wk), 24)
        self.assertEqual(wl[0:5], wk[0:5])
        self.assertEqual(wl[6:9], wk[6:9])
        self.assertEqual(wl[5], 0xA40A0008)                 # b_f.cc0A +8
        self.assertEqual((wl[5] >> 16), (wk[5] >> 16))      # op+cc identical
        self.assertEqual((wk[5] & 0xFFFF) - (wl[5] & 0xFFFF), 10)  # imm 18->8

    def test_v5l_replica_absent(self):
        # THE v5l headline structural contract: the v5k EPILOGUE
        # REPLICA IS DELETED — no replica word appears in the stub, no
        # word loads from the save-slot region, no pop word, no
        # epilogue-pair ld.d/ret.r; the ONLY op-0x3F word is the w12
        # transfer.  The stub is exactly 10 words shorter than v5k.
        import irisc_dis
        from build_s2 import stub_words, REPLICA_WORDS
        wd = self.ws()
        self.assertEqual(len(wd), len(stub_words("A", version=16)) - 10)
        for w in REPLICA_WORDS:
            self.assertNotIn(w, wd, f"replica word 0x{w:08x} present")
        dec = [irisc_dis.dis(w, 0) for w in wd]
        for i, s in enumerate(dec):
            self.assertNotIn("0xdc", s, f"w{i} {s!r} reads a save slot")
            self.assertNotIn("0xf4", s, f"w{i} {s!r} reads a save slot")
            self.assertNotEqual(s, "addi r1,r1,0xf8", f"w{i} is the pop")
            self.assertNotEqual(s, "ld.d r3,r1,0x4", f"w{i} is the outer-ra load")
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x3F],
                         [12])                              # transfer ONLY
        self.assertNotIn(0xFD001825, wd)                   # fn final ret.r: gone

    def test_v5l_r3_build_words(self):
        # THE r3-build pair: w10 `set3 r3,ZERO,0x4380' (rs=zero — the
        # lo16 is CLEAN under BOTH semantics, the proven v5k pattern)
        # THEN w11 `set2 r3,r3,0x008e' (hi-insert against the
        # just-built value whose hi16 is 0 — insert and OR agree) =>
        # r3 = 0x008E4380 = THE CALL-SITE RESUME (live detour call
        # 0x8E437C + 4), deterministic from ANY w0 residue.
        wd = self.ws()
        self.assertEqual(self.RESUME_LIVE, 0x8E4380)
        self.assertEqual(self.RESUME_LIVE, 0x800000 + 0x0E437C + 4)
        self.assertEqual(wd[10], enc.set3(3, 0, self.RESUME_LIVE & 0xFFFF))
        self.assertEqual(wd[10], 0x20034380)
        self.assertEqual((wd[10] >> 21) & 0x1F, 0)          # rs = ZERO
        self.assertEqual((wd[10] >> 16) & 0x1F, 3)          # rd = r3
        self.assertEqual(wd[11], (0x09 << 26) | (3 << 21) | (3 << 16)
                         | (self.RESUME_LIVE >> 16))        # rs-bearing set2
        self.assertEqual(wd[11], 0x2463008E)
        self.assertEqual((wd[11] >> 21) & 0x1F, 3)          # rs = r3
        self.assertEqual((wd[11] >> 16) & 0x1F, 3)          # rd = r3
        # OR-safe (exact under BOTH semantics) from ANY residue
        # (including the REAL w0 residue 0x8E4380 — which equals the
        # target: the pair is explicit, not load-bearing):
        for residue in (0x8E4380, 0, 0xFFFFFFFF, 0x12345678, 0xDEAD4380):
            for model in ("or", "insert"):
                if model == "or":
                    r = (0 & 0xFFFF0000) | ((0 & 0xFFFF) | 0x4380)
                    r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (0x8E << 16))
                else:
                    r = (residue & ~0xFFFF & 0xFFFFFFFF) | 0x4380
                    r = (r & 0x0000FFFF) | (0x8E << 16)
                self.assertEqual(r, 0x008E4380,
                                 f"residue 0x{residue:x} {model}")
        # WRONG-form witness (the rs=rd set3 the v5j anomaly taught):
        # building the LO half from a foreign residue register ORs the
        # residue's garbage in — non-vacuous with a NON-target residue
        # (hi16 merges too: 0xDEAD|0x008E = 0xDEAF)
        r = (0xDEAD4380 & 0xFFFF0000) | ((0xDEAD4380 & 0xFFFF) | 0x4380)
        r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (0x8E << 16))
        self.assertNotEqual(r, 0x008E4380)                  # hi residue leaks
        self.assertEqual(r, 0xDEAF4380)                     # 0xDE-hi ORed in

    def test_v5l_r3_build_order_lo_first(self):
        # the OR-semantics-safe ORDER: the set3 (lo) word comes FIRST,
        # the set2 (hi) word SECOND — reversing them would OR the hi
        # build against a foreign residue's hi16 and corrupt.
        wd = self.ws()
        self.assertEqual(wd[10] >> 26, 0x08)                # set3 (lo) first
        self.assertEqual(wd[11] >> 26, 0x09)                # set2 (hi) second

    def test_v5l_r3_is_stock_fn_a_return_state(self):
        # THE "as FN_A's return would" precedent, decode-level: stock
        # FN_A @0x18d964 opens with `csr.r r3,csr0xbc` — BYTE-EXACT
        # the stub's w0 — and returns through r3 (the canonical
        # `ret.r zero,r8,r3' family): at the call-site resume the
        # stock post-FN_A r3 IS the resume address 0x8E4380 (the very
        # value w10/w11 build and p3 consumes).  Verified against the
        # base image AND the census blob.
        wd = self.ws()
        self.assertEqual(wd[0], 0x480300BC)                 # == FN_A prologue
        src = BASE.read_bytes()
        img = mlxfwutil.Image(src, "base")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", code, 0x18D964)[0],
                         wd[0])                             # FN_A prologue == w0
        self.assertEqual(struct.unpack_from(">I", code, 0x0E437C)[0],
                         0x9402A57A)                        # stock call FN_A
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        b = blob.read_bytes()
        self.assertEqual(struct.unpack_from(">I", b, 0x18D964)[0], wd[0])
        words = struct.unpack(">%dI" % (len(b) // 4), b)
        self.assertEqual(sum(1 for w in words if w == 0x480300BC), 8348)
        # and the body's first post-call word marshals r4 (our r4=0:
        # the v5i-documented stock arg value — see Sim tests)
        self.assertEqual(struct.unpack_from(">I", code, 0x0E4380)[0],
                         0xFC932008)                        # or r19,r4,r4

    def test_v5l_zero_memory_writes_no_pop(self):
        # THE write-discipline contract, word level: NO op-0x1B word
        # with rs != zero (every store targets a CR slot — the
        # always-clean class); NOTHING writes memory; NOTHING writes
        # r1 AT ALL (unlike v5k's replica pop — the BODY pops its own
        # frame on HW; v5l has no register SP-restore word either).
        wd = self.ws()
        for i, w in enumerate(wd):
            if (w >> 26) == 0x1B:
                self.assertEqual(((w >> 21) & 0x1F), 0,
                                 f"w{i}=0x{w:08x} stores with rs != zero")
            if (w >> 26) == 0x00 and ((w >> 16) & 0x1F) == 1:
                self.fail(f"w{i}=0x{w:08x} writes r1")
        self.assertNotIn(0x002100F8, wd)                    # the pop: gone
        self.assertNotIn(0x703F0FC2, wd)                    # push: gone
        self.assertNotIn(0x6C206032, wd)                    # neutral write: gone

    def test_v5l_transfers_no_link(self):
        # THE control contract: exactly ONE op-0x3F word in the stub
        # — w12 `ret.r zero,r8,r11' (THE transfer into the payload;
        # rs=8 computed-jr class, NO LINK, stock x3).  csr0xbc keeps
        # the pre-detour ra (nothing on any path links).  The only
        # jump word is W_FAST (w13, last); no call words.
        wd = self.ws()
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x3F],
                         [12])
        self.assertEqual(wd[12], enc.ret_r(8, 0, 11))
        self.assertEqual(wd[12], 0xFD005825)
        self.assertEqual((wd[12] >> 21) & 0x1F, 8)          # rs = r8 (jr)
        self.assertNotEqual((wd[12] >> 21) & 0x1F, 0)       # NOT linking jalr
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x25],
                         [13])                              # W_FAST only
        self.assertEqual((wd[13] >> 24) & 1, 1)             # jump (no link)

    def test_v5l_w9_payload_ptr_reestablish(self):
        # w9 == w1 == `addi r11,r1,0xac`: the payload pointer
        # re-established immediately before the r3-build/transfer
        # (nothing between w9 and the transfer disturbs r11/r3).
        from build_s2 import stub_words, PAY_SRC_OFF_V5B
        wd = self.ws()
        self.assertEqual(PAY_SRC_OFF_V5B, 0xAC)
        self.assertEqual(wd[9], enc.addi(11, 1, PAY_SRC_OFF_V5B))
        self.assertEqual(wd[9], wd[1])
        self.assertEqual(wd[9], 0x002B00AC)

    def test_v5l_zero_bt_filter_only_conditional(self):
        # linearity contract: NO b_t words; the ONLY conditional is
        # the filter b_f (w5); the ONLY jump is W_FAST (w13); the ONLY
        # cmp is the filter (w4); no back-edge, no gates, no skips.
        wd = self.ws()
        for i, w in enumerate(wd):
            self.assertNotEqual(w >> 26, 0x28, f"w{i}=0x{w:08x} is b_t")
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x29],
                         [5])                               # filter ONLY
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x38],
                         [4])                               # one cmp (filter)

    def test_v5l_no_n_guard_no_gauntlet_words(self):
        # N never controls: no guard bound const, no N-vs-const cmp,
        # no gauntlet read/const; nothing gates on the code window.
        wd = self.ws()
        for w in (0x200C0004, 0x200C0002, 0x200C0003,   # guard/gate consts
                  0x200D2407,                            # gauntlet const
                  0x15AD0001,                            # subsi counter
                  0x002C0020, 0x65630002, 0x6D801802,   # copy block
                  0xA400FFFB):                           # back-edge
            self.assertNotIn(w, wd, f"gate/copy word 0x{w:08x} present")

    def test_v5l_wfast_last_and_filter_targets_it(self):
        wd = self.ws()
        w_fast = STUB + 4 * 13
        self.assertEqual(w_fast, 0x38D784)
        self.assertEqual(wd[13], enc.jump(w_fast, 0x18D964))
        self.assertEqual(wd[13], 0x95F80078)
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))  # filter -> fast

    def test_v5l_word_delta_vs_v5k_exactly_replica_deletion(self):
        # THE diff-vs-v5k contract: v5l == v5k MINUS the 10 replica
        # words, with the four position-dependent immediates
        # recomputed (w5 filter +18 -> +8; w10 lo 0xd784 -> 0x4380;
        # w11 hi 0xb8 -> 0x8e; W_FAST moved w23 -> w13).  Everything
        # else — including the transfer word and both addi payload-ptr
        # words — identical.
        from build_s2 import stub_words
        wk, wl = stub_words("A", version=16), self.ws()
        self.assertEqual(set(wk) - set(wl),
                         {0xA40A0012, 0x2003D784, 0x246300B8, 0x95F8006E,
                          0x643700DE, 0x643600E2, 0x643500E6, 0x643400EA,
                          0x643300EE, 0x643200F2, 0x643100F6, 0x002100F8,
                          0x64230006, 0xFD001825})
        self.assertEqual(set(wl) - set(wk),
                         {0xA40A0008, 0x20034380, 0x2463008E, 0x95F80078})
        for w in (0x002B00AC, 0xFD005825):
            self.assertEqual(wl.count(w), wk.count(w), f"count drift 0x{w:08x}")
        for w in (0x480300BC, 0x642C00AB, 0x200D5332, 0xE1806802,
                  0x6C046382, 0x642D00A5, 0x6C046B86):
            self.assertEqual(wl.count(w), wk.count(w), f"count drift 0x{w:08x}")

    def test_v5l_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 14)                # 14/34
        self.assertLessEqual(len(ws), 34)            # zone 0x38d750-0x38d7d8

    def test_v5l_clobber_confined(self):
        # v5l clobber contract: r4/r5/r6 (site args), r14/r15/r16 AND
        # r17-r23 (the fn's save-set — the BODY's epilogue restores
        # them on HW, the stub touches NOTHING of them; contrast v5k
        # where the replica restored r17-r23 itself) never touched;
        # r1 never written (no pop — the body pops).
        import irisc_dis
        wd = self.ws()
        dec = [irisc_dis.dis(w, 0) for w in wd]
        for s in dec:
            for reg in ("r4", "r5", "r6", "r14", "r15", "r16",
                        "r17", "r18", "r19", "r20", "r21", "r22", "r23"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")

    def test_v5l_rejects_mode_b(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("B", version=17)

    def test_v5l_stock_precedents(self):
        # NEW-word stock counts (census blob whole-image, re-verified
        # this task):
        #   w5 retarget b_f.cc0A +8 (0xA40A0008) x74 — stock-exact,
        #     the BEST prefix-retarget count of the lineage (v5j +6
        #     x70, v5k +18 x27)
        #   w10 set3 r3,zero,0x4380 (0x20034380) x0 — live-form: the
        #     set3 rs=zero class x7348 + v5i-neutral-write live x4
        #   w11 set2 r3,r3,0x8e (0x2463008E) x0 — live-form (set2
        #     rs=rd hi-insert = the S2OK p1 live-exact class)
        #   W_FAST jump imm (0x95F80078) x0 — live-form class (every
        #     prior W_FAST word 0-count, live-clean x7+)
        #   w0 (0x480300BC) x8348 — the canonical csr.r idiom, BYTE-
        #     EXACT FN_A's own prologue; w12 transfer x3 stock.
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        cnt = lambda x: sum(1 for w in words if w == x)
        ws = self.ws()
        self.assertEqual(cnt(0xA40A0008), 74)                # w5 retarget
        self.assertEqual(cnt(0x20034380), 0)                 # w10: live-form
        self.assertEqual(cnt(0x2463008E), 0)                 # w11: live-form
        self.assertEqual(cnt(0x95F80078), 0)                 # W_FAST: live-form
        self.assertEqual(cnt(0x480300BC), 8348)              # w0: canonical
        self.assertEqual(cnt(0xFD005825), 3)                 # w12: stock
        s3_zero = sum(1 for w in words if (w >> 26) == 0x08
                      and ((w >> 21) & 0x1F) == 0)
        self.assertEqual(s3_zero, 7348)                      # set3 rs=zero class
        # every word of the stub is stock-exact, live-exact (v5b..v5k
        # lineage goldens) or documented (the two build words + W_FAST)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7)) \
            | set(stub_words("A", version=8)) | set(stub_words("A", version=9)) \
            | set(stub_words("A", version=10)) | set(stub_words("A", version=11)) \
            | set(stub_words("A", version=12)) | set(stub_words("A", version=13)) \
            | set(stub_words("A", version=14)) | set(stub_words("A", version=15)) \
            | set(stub_words("A", version=16))
        documented = {0x20034380, 0x2463008E, 0x95F80078}
        for w in ws:
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5l_lineage_untouched(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("A", version=6)), 33)
        self.assertEqual(len(stub_words("A", version=7)), 21)
        self.assertEqual(len(stub_words("A", version=8)), 34)
        self.assertEqual(len(stub_words("A", version=9)), 33)
        self.assertEqual(len(stub_words("A", version=10)), 30)
        self.assertEqual(len(stub_words("A", version=11)), 32)
        self.assertEqual(len(stub_words("A", version=12)), 23)
        self.assertEqual(len(stub_words("A", version=13)), 22)
        self.assertEqual(len(stub_words("A", version=14)), 15)
        self.assertEqual(len(stub_words("A", version=15)), 12)
        self.assertEqual(len(stub_words("A", version=16)), 24)
        self.assertEqual(len(stub_words("A", version=17)), 14)


class TestS2StubV5LSim(unittest.TestCase):
    # v5l per-path REGISTER-TRUE simulation with PAYLOAD execution.
    # The Sim model (re-based from v5k after the task-33 phase-2
    # verdict): same live-root-caused set3/set2 OR semantics, same fn
    # frame model (inner [r1+4] = the 0x8E435C livelock residue; outer
    # [r1+0xf8+4] = the dispatcher ra; save slots r17-r23 CLOBBERED on
    # entry) — PLUS the v5l contract: a ret.r to a live EA OUTSIDE the
    # stub zone is an EXIT (the replica continuation class is GONE —
    # no live stub EA is a target anymore).  THE v5l dispatch: w10/w11
    # build r3 = 0x8E4380 (THE CALL-SITE RESUME) before the transfer;
    # the payload CR writes are {0x2388: S2OK} ONLY; p3 EXITS to
    # 0x8E4380 — INTO the fn body (the stock decode at 0x0E4380
    # `or r19,r4,r4' then branches on the marshaled FN_A result; the
    # body builds the QUERY completion and reaches its own epilogue
    # ON HW — outside the sim's stub/stack word scope by design).
    # r4 seeded 0 (the v5i-documented stock arg setup @0x0E4374) and
    # asserted UNTOUCHED at the exit: the body reads exactly the
    # stock-equivalent value.  r1 NEVER popped (r1 == R-0xf8 at exit —
    # the body pops on HW); r17-r23 NEVER restored (the body's
    # epilogue restores on HW).
    R1E = 0x1000
    STUB_LIVE = 0x800000 + 0x38D750
    FN_A_LIVE = 0x98D964                      # == 0x800000 + build_s2 FN_A
    RA_LIVE = 0x8E4380                        # THE v5l exit: call-site resume
    INNER_RA = 0x8E435C                       # [(R-0xf8)+4] residue: the
                                              # caec0-call resume (livelock value)
    OUTER_RA = 0x8AA1D8                       # [R+4]: the dispatcher's call
                                              # resume (the v5k replica exit)
    SAVED_REGS = (23, 22, 21, 20, 19, 18, 17)  # slot order 0xdc..0xf4

    class SimV5L:
        def __init__(self, ws, N, magic=True, code=None, r1=None,
                     outer_ra=None, inner_ra=None):
            TestS = TestS2StubV5LSim
            r1 = TestS.R1E if r1 is None else r1
            self.ws = ws
            self.mem = {}
            self.cr = {0x2380: 0, 0x2384: 0, 0x2388: 0, 0x238C: 0}
            self.csr0xbc = TestS.RA_LIVE
            self.links = []                                 # (ea, kind) link events
            self.mem[r1 + 0xA4] = N
            self.mem[r1 + 0xAA] = 0x5332 if magic else 0x1234
            self.mem[r1 + 0x4] = (TestS.INNER_RA if inner_ra is None
                                  else inner_ra)            # INNER residue seed
            self.mem[r1 + 0xF8 + 0x4] = (TestS.OUTER_RA if outer_ra is None
                                         else outer_ra)     # OUTER dispatcher ra
            for i, reg in enumerate(TestS.SAVED_REGS):      # save slots (saves
                self.mem[r1 + 0xDC + 4 * i] = 0xCAFE0000 + reg  # @0x0e425c-74)
            for i, cw in enumerate(code):
                self.mem[r1 + 0xAC + 4 * i] = cw
            self.r = {1: r1, 3: 0xDEAD, 4: 0, 11: 0, 12: 0, 13: 0}
            for reg in TestS.SAVED_REGS:                    # arrive CLOBBERED
                self.r[reg] = 0xDEAD0000 + reg              # (fn body state)
            self.pc = 0
            self.eq = False
            self.z32 = False
            self.stores = []
            self.taken = []                                 # (i, op, cc, latch)
            self.pay_fetch = []                             # payload word EAs
            self.exit_ea = None                             # recorded exit target
            self.n = 0                                      # step counter
            self.load_log = []                              # (step, rt, ea)
            self.fetch_steps = []                           # (step, ea)
            self.r1_writes = []                             # (step, new r1)

        def rd(self, k):
            return 0 if k == 0 else self.r[k]

        def run(self, max_steps=200):
            import irisc_dis
            STUB_L = TestS2StubV5LSim.STUB_LIVE
            FN_A_L = TestS2StubV5LSim.FN_A_LIVE
            for _ in range(max_steps):
                if isinstance(self.pc, int):
                    i = self.pc
                    if not 0 <= i < len(self.ws):
                        return "WILD_%08x" % (STUB_L + 4 * i)
                    word = self.ws[i]
                    ea = STUB_L + 4 * i                     # LIVE stub PC
                    nxt = i + 1
                else:
                    ea = self.pc[1]                         # LIVE stack PC
                    if ea >= 0x800000:
                        # a live target INSIDE the stub zone would be
                        # a stub continuation (the v5k replica class —
                        # DELETED in v5l; kept in the model to catch a
                        # regression); ANY live target here is an EXIT
                        # (the v5l p3 exits to 0x8E4380, the fn body)
                        off = ea - STUB_L
                        if 0 <= off < 4 * len(self.ws) and off % 4 == 0:
                            return "STUB_ZONE_TARGET_%08x" % ea
                        self.exit_ea = ea                   # code target: EXIT
                        return "EXIT_%08x" % ea
                    if ea not in self.mem:
                        return "DEAD_%08x" % ea
                    word = self.mem[ea]
                    self.pay_fetch.append(ea)
                    self.fetch_steps.append((self.n, ea))
                    nxt = ("ea", ea + 4)
                self.n += 1
                op = word >> 26
                if op == 0x12:                              # csr.r
                    self.r[3] = self.csr0xbc
                elif op == 0x00:                            # addi
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    rd = (word >> 16) & 0x1F
                    self.r[rd] = \
                        (self.rd((word >> 21) & 0x1F) + imm) & 0xFFFFFFFF
                    if rd == 1:
                        self.r1_writes.append((self.n - 1, self.r[1]))
                elif op == 0x08:                            # set3: OR into lo16
                    # LIVE root-caused semantics (journal task-32
                    # phase-2): 0x5332|0x4F4B = 0x5F7B — the v5j
                    # anomaly reproduced EXACTLY by this model
                    rs = self.rd((word >> 21) & 0x1F)
                    self.r[(word >> 16) & 0x1F] = \
                        (rs & 0xFFFF0000) | ((rs & 0xFFFF) | (word & 0xFFFF))
                elif op == 0x09:                            # set2: OR into hi16
                    rs = self.rd((word >> 21) & 0x1F)
                    self.r[(word >> 16) & 0x1F] = \
                        (rs & 0x0000FFFF) | ((rs & 0xFFFF0000)
                                            | ((word & 0xFFFF) << 16))
                elif op == 0x19:                            # ld.w / ld.d
                    rt, rs = (word >> 16) & 0x1F, (word >> 21) & 0x1F
                    if word & 1:
                        off = ((word >> 1) & 0x7FFF) << 1
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0) & 0xFFFF
                    else:
                        off = ((word >> 2) & 0x3FFF) << 2
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0)
                    self.load_log.append((self.n - 1, rt, self.rd(rs) + off))
                elif op == 0x1B:                            # st.d / st.w
                    rt, rs = (word >> 11) & 0x1F, (word >> 21) & 0x1F
                    off = (((word >> 16) & 0x1F) << 11) \
                        | (((word >> 2) & 0x1FF) << 2)
                    if rs == 0:
                        self.cr[off] = self.r[rt]
                        self.stores.append((off, self.r[rt], "CR"))
                    else:
                        ea = (self.rd(rs) + off) & 0xFFFFFFFF
                        kind = "STACK" if self.r[1] - 0x40 <= ea < self.r[1] else "ABS"
                        self.mem[ea] = self.r[rt]
                        self.stores.append((ea, self.r[rt], kind))
                elif op == 0x38:                            # cmp38_sel eq32
                    self.eq = self.rd((word >> 21) & 0x1F) == \
                        self.rd((word >> 11) & 0x1F)
                elif op in (0x28, 0x29):                    # b_t / b_f (stub words)
                    if not isinstance(self.pc, int):
                        return "UNSUPPORTED_branch_in_payload"
                    cc = (word >> 16) & 0x1F
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    cond = self.eq if cc == 0x0A else self.z32 if cc == 0 else False
                    if (cond if op == 0x28 else not cond):
                        self.taken.append((self.pc, op, cc, cond))
                        nxt = self.pc + imm
                elif op == 0x25:                            # jump/call: ACTUAL (live) ea
                    if not word & 0x01000000:               # call: LINKS
                        self.csr0xbc = (ea + 4) & 0xFFFFFFFF
                        self.links.append((ea, "call"))
                    tgt = ea + irisc_dis.s24(word) * 4
                    j = (tgt - STUB_L) // 4
                    if 0 <= j < len(self.ws) and tgt == STUB_L + 4 * j:
                        nxt = j
                    elif tgt == FN_A_L:
                        self.exit_ea = tgt
                        return "FN_A"
                    else:
                        self.exit_ea = tgt
                        return "EXIT_%08x" % tgt
                elif op == 0x3F and (word & 0x1FF) == 0x25:  # ret.r
                    rs, rt = (word >> 21) & 0x1F, (word >> 11) & 0x1F
                    if rs == 0:                             # jalr: LINKS
                        self.csr0xbc = (ea + 4) & 0xFFFFFFFF
                        self.links.append((ea, "jalr"))
                    nxt = ("ea", self.rd(rt))               # both rs=0/rs=8 goto [rt]
                else:
                    return "UNSUPPORTED_op_%02x" % op
                self.pc = nxt
            return "RUNAWAY"

    def ws(self):
        from build_s2 import stub_words
        return stub_words("A", version=17)

    def payload_words(self):
        import payload as pl
        return pl.payload_v5l()

    def test_sim_fallthrough_no_store_no_transfer(self):
        s = self.SimV5L(self.ws(), 4, magic=False, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.exit_ea, 0x98D964)              # LIVE FN_A (file imm + live EA)
        self.assertEqual(s.stores, [])                      # no CR, no stack
        self.assertEqual(s.r[1], self.R1E)                  # r1 untouched
        self.assertEqual(s.pay_fetch, [])                   # no transfer
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])  # w5 taken at false
        self.assertEqual(s.links, [])                       # W_FAST = jump, no link
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # csr0xbc untouched

    def test_sim_magic_path_full_contract(self):
        # THE v5l exec path: prefix (echoes) -> w9 (r11 = r1+0xAC) ->
        # w10/w11 (r3 = 0x8E4380 THE CALL-SITE RESUME) -> w12
        # (register transfer, NO LINK) -> payload p0..p3 from the
        # landing zone -> p3 EXITS to 0x8E4380 — INTO THE FN BODY at
        # the resume point, exactly as FN_A's return would (FN_A's
        # own prologue `csr.r r3,csr0xbc' == w0 byte-exact; FN_A
        # returns through r3 the same value).  CR contract:
        # 0x2380=MAGIC16, 0x2384=N, 0x2388=S2OK, 0x238C=0; r1 NOT
        # popped (the body pops on HW); r17-r23 NOT restored (the
        # body's epilogue restores on HW); r4 = 0 UNTOUCHED (the
        # stock-equivalent FN_A result the body marshals at
        # 0x0E4380); ZERO taken conditionals; ZERO links; ZERO
        # stack/absolute writes.
        s = self.SimV5L(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.exit_ea, self.RA_LIVE)
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                         (0x5332, 4, 0x53324F4B, 0))
        self.assertEqual(s.r[11], self.R1E + 0xAC)          # r11 at/after transfer
        self.assertEqual(s.r[1], self.R1E)                  # r1 NOT popped (no pop word)
        self.assertEqual(s.r1_writes, [])                   # ZERO r1 writes
        self.assertEqual(s.r[3], self.RA_LIVE)              # the resume address
        self.assertEqual(s.r[4], 0)                         # v5i: stock arg value
        self.assertEqual(s.r[12], 0x53324F4B)               # payload build result
        for reg in self.SAVED_REGS:                         # the body restores later
            self.assertEqual(s.r[reg], 0xDEAD0000 + reg,
                             f"r{reg} touched before the body's epilogue")
        self.assertEqual(s.taken, [])                       # ZERO taken
        self.assertEqual(s.links, [])                       # ZERO links
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # no-link contract
        kinds = {k for _, _, k in s.stores}
        self.assertEqual(kinds, {"CR"})                     # CR writes only

    def test_sim_exit_is_callsite_resume_discriminates_v5k(self):
        # THE v5l discrimination: the exit EA is EXACTLY the
        # call-site resume 0x8E4380 — NOT the inner livelock residue
        # 0x8E435C (rev.1 v5k Critical-1) and NOT the outer
        # dispatcher ra 0x8AA1D8 (the v5k rev.2 replica exit — which
        # skipped the body and wedged live).  The outer seed is
        # POISONED differently and the exit ignores it: the body (not
        # the payload) will consume [R+4] via its own epilogue.
        for seed in (0x8AA1D8, 0x8ACEDC, 0x900004):
            s = self.SimV5L(self.ws(), 4, code=self.payload_words(),
                            outer_ra=seed)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"outer seed 0x{seed:x}")
            self.assertEqual(s.exit_ea, self.RA_LIVE)
            self.assertNotEqual(s.exit_ea, seed)
            self.assertNotEqual(s.exit_ea, self.INNER_RA)
            self.assertEqual(s.cr[0x2388], 0x53324F4B)      # C1 intact
        for seed in (0x8E435C, 0xDEAD0004):
            s = self.SimV5L(self.ws(), 4, code=self.payload_words(),
                            inner_ra=seed)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"inner seed 0x{seed:x}")
            self.assertNotEqual(s.exit_ea, seed)            # residue never read

    def test_sim_no_stub_zone_target_on_any_path(self):
        # the v5k replica class is GONE: NO run ever targets a live
        # EA INSIDE the stub zone (the model names it explicitly if it
        # happens); the wedge-hypothesis (ii) of task-33 (fetch/exec
        # at the 0xB8D7A0 stub-zone page) cannot fire — v5l executes
        # NOTHING from the stub zone after the transfer.
        for magic in (True, False):
            s = self.SimV5L(self.ws(), 4, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.RA_LIVE),
                            f"magic={magic}: unexpected {out}")

    def test_sim_r3_build_before_transfer_exact(self):
        # w10/w11 build r3 = 0x8E4380 BEFORE the w12 transfer — the
        # model's OR semantics with the REAL w0 residue (csr.r r3 =
        # 0x8E4380 — which EQUALS the target: the residue flow is
        # non-vacuous and the pair is explicitly rebuild-any-residue);
        # the payload words never touch r3, so the preload survives
        # to p3; pay_fetch[0] is the payload landing.
        s = self.SimV5L(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.pay_fetch[0], s.r[11])
        # re-derive with the same OR model, residue-tracked:
        r = 0x8E4380                                          # w0: csr.r residue
        r = (0 & 0xFFFF0000) | ((0 & 0xFFFF) | 0x4380)        # w10: set3 rs=zero
        r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (0x8E << 16))  # w11: set2
        self.assertEqual(r, 0x008E4380)
        self.assertEqual(s.exit_ea, r)                        # p3 consumed r3
        # the p3 word is the canonical return through r3
        self.assertEqual(self.payload_words()[3], enc.ret_r(8, 0, 3))

    def test_sim_landing_map_k14(self):
        # THE landing map: input halfword/word k=0x14+4i lands at
        # [r1+0x98+0x14+4i] = [r1+0xac+4i] — the payload fetch
        # sequence IS the map (4 words, strictly consecutive).
        s = self.SimV5L(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0x98 + 0x14 + 4 * i for i in range(4)])
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0xAC + 4 * i for i in range(4)])

    def test_sim_zero_stack_writes_all_paths(self):
        # THE write-discipline assertion, path level: on EVERY path
        # (magic and fallthrough) the store log contains NO stack and
        # NO absolute writes — v5l has no restores, no pop, no frame
        # writes AT ALL (the freeze-#9 class cannot fire; the body's
        # own stock frame writes happen only ON HW after the exit).
        for magic in (True, False):
            s = self.SimV5L(self.ws(), 4, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.RA_LIVE),
                            f"magic={magic}: unexpected {out}")
            for ea, v, k in s.stores:
                self.assertNotIn(k, ("STACK", "ABS"),
                                 f"magic={magic}: non-CR write 0x{ea:x}")

    def test_sim_no_link_csr0xbc_untouched(self):
        # the transfer AND the payload exit are BOTH rs=8 no-link
        # words: csr0xbc keeps the PRE-DETOUR ra through the whole
        # magic path — no link event anywhere (the fn body will read
        # csr0xbc-class state only through its own stock words).
        s = self.SimV5L(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.links, [])                       # no jalr/call link events
        self.assertEqual(s.csr0xbc, self.RA_LIVE)           # pre-detour ra intact
        wd = self.ws()
        self.assertEqual(wd[12], enc.ret_r(8, 0, 11))
        self.assertEqual(self.payload_words()[3], enc.ret_r(8, 0, 3))
        self.assertNotIn(enc.ret_r(0, 0, 11), wd)

    def test_sim_exit_base_independence_all_16_sp_bases(self):
        # THE v5l headline contract: the SAME FIXED word list (stub
        # AND payload — built ONCE, outside the sweep; no word encodes
        # any stack absolute) exits to the SAME ABSOLUTE resume
        # 0x8E4380 from EVERY SP base (SP-init 0x7d1ff8 +
        # (cpuinfo&0xf)<<13, all 16 cores): the landing map tracks
        # the base, the C1 signal lands everywhere, r1 stays the
        # UNPOPPED fn frame at every base (the body pops on HW).
        import payload as pl
        fixed_stub, fixed_payload = self.ws(), pl.payload_v5l()
        for k in range(16):
            base = 0x7D1FF8 + k * 0x2000
            s = self.SimV5L(fixed_stub, 4, code=fixed_payload, r1=base)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"base 0x{base:x}")
            self.assertEqual(s.exit_ea, self.RA_LIVE, f"base 0x{base:x}")
            self.assertEqual(s.cr[0x2388], 0x53324F4B, f"base 0x{base:x}")
            self.assertEqual(s.r[1], base, f"base 0x{base:x}: NOT popped")
            for reg in self.SAVED_REGS:
                self.assertEqual(s.r[reg], 0xDEAD0000 + reg,
                                 f"base 0x{base:x}: r{reg} touched")
            self.assertEqual(s.pay_fetch, [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")
        # and the frame bytes are ONE frame for ALL bases (no param)
        self.assertEqual(len(pl.input_block_v5l()), 0x24)

    def test_sim_s2ok_exact_from_filter_residue(self):
        # Fix-1 contract carried from v5k (UNCHANGED payload words):
        # the executing model (OR semantics built in — the v5j anomaly
        # witness model) builds r12 = 0x53324F4B EXACTLY on the way
        # to the exit.
        s = self.SimV5L(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.r[12], 0x53324F4B)
        self.assertEqual(s.cr[0x2388], 0x53324F4B)

    def test_sim_branch_inventory_all_paths(self):
        # THE branch-inventory table: magic -> ZERO taken
        # conditionals (the ONLY conditional word is the filter b_f,
        # not-taken at magic); fallthrough -> w5 taken once at latch
        # FALSE (the live-proven clean class).  No b_t words exist.
        for n, magic, want in ((4, True, []), (1, True, []), (4, False, [(5, 0x29, 0x0A, False)])):
            s = self.SimV5L(self.ws(), n, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.RA_LIVE),
                            f"N={n} magic={magic}: {out}")
            self.assertEqual(s.taken, want, f"N={n} magic={magic}")

    def test_sim_trig_frame_bytes_drive_the_path(self):
        # THE TRIG frame (the exact 36B host bytes of the live phase)
        # drives the full path at SEVERAL bases — the SAME frame
        # bytes (no base parameter exists): unpack N / MAGIC16 / the
        # 4 payload words FROM THE FRAME BYTES, run, and the exit
        # lands on the call-site resume 0x8E4380 everywhere.
        import payload as pl
        frame = pl.input_block_v5l()
        b = bytes.fromhex(frame.hex())
        n = struct.unpack(">H", b[0xC:0xE])[0]
        magic16 = struct.unpack(">H", b[0x12:0x14])[0]
        words = list(struct.unpack(">4I", b[0x14:0x24]))
        self.assertEqual((n, magic16), (4, 0x5332))
        for base in (self.R1E, 0x7D1FF8, 0x7D9FF8, 0x7EFFF8):
            s = self.SimV5L(self.ws(), n, code=words, r1=base)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"base 0x{base:x}")
            self.assertEqual((s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                             (4, 0x53324F4B, 0), f"base 0x{base:x}")
            self.assertEqual(s.r[1], base, f"base 0x{base:x}: NOT popped")
            self.assertEqual(s.pay_fetch, [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")

class TestS2StubV5M(unittest.TestCase):
    # v5m (task-2, mode "B" — S2B): the FIRST output-mailbox stub.  v5l
    # flow with the stub TAIL extended by the m2 WRITE-POST block from
    # the Task-1 verdict (MARSHAL_MECH m2, ranked choice): on a magic
    # frame, AFTER the echo prefix and BEFORE the payload transfer, the
    # stub calls the stock transport wrapper
    # `0x18064c(r4=0, r5=obj, r6=C, r7=buf)` (= X1=0x18a668(obj,C) ->
    # 0x2ae98 -> 0x2a154: DMA 0x40 bytes buf -> host X1, byte-exact —
    # one call instead of hand-building X1).  r4=0 selects the
    # dir==0 WRITE-POST subpath (stock decode 0x180674-0x180690);
    # obj = r22 (callee-saved, set in the fn prologue — the stub only
    # READS it); C = [r1+0xac]|0xff (ld.d then or-imm — the same key
    # the stock F_SYN FETCH uses every fallthrough run); buf = r1+0xb0
    # = input[0x18..0x58) (payload p1..p3 + stack tail — ZERO new
    # FW-RAM writes: the POSTed bytes are the TRIG frame's own).  The
    # call is a REAL call: it links csr0xbc and clobbers the
    # caller-saved set (its own prologue does `csr.r r3,csr0xbc`), so
    # per the Task-1 class note r3/r11 are (RE)BUILT AFTER the m2
    # block (w15 restores r4=0 the body requires; w16 re-establishes
    # the payload ptr; w17/w18 rebuild r3 = RESUME_LIVE 0x008E4380).
    # Layout: 21 words — prefix w0-w8 == v5l byte-exact except w5's
    # immediate retargets +8 -> +15 (W_FAST moved w13 -> w20:
    # 0xA40A000F stock-exact x19); w9-w15 the m2 block (7 words, all
    # stock-exact or golden-from-blob: 0x00040000 x9351 / 0xFEC5B008
    # x3226 / 0x642600AE x5 / 0x30C600FF x47 / 0x002700B0 x5 / the
    # site-imm call word); w16-w19 == v5l w9-w12 byte-exact (payload
    # ptr, r3 build lo/hi, THE transfer — all shifted +7); w20 W_FAST
    # jump FN_A LAST (0x95F80071 — byte-exact the v5cA W_FAST word:
    # same address 0x38d7a0).  21 of 34 zone words.  The payload and
    # the TRIG frame are UNCHANGED v5l (4 words / 36B): mode B lives
    # entirely in the burnt stub.
    V5M_GOLDEN = [
        0x480300BC,        # w0  csr.r r3,csr0xbc (prefix == v5l)
        0x002B00AC,        # w1  addi r11,r1,0xac
        0x642C00AB,        # w2  ld.w r12,r1,0xaa (filter)
        0x200D5332,        # w3  set3 r13,zero,0x5332
        0xE1806802,        # w4  cmp38_sel(2,12,13)
        0xA40A000F,        # w5  b_f.cc0A +15 -> W_FAST (w20, stock x19)
        0x6C046382,        # w6  st.d r12,zero,0x2380 (echo MAGIC16)
        0x642D00A5,        # w7  ld.w r13,r1,0xa4 (N)
        0x6C046B86,        # w8  st.d r13,zero,0x2384 (echo N)
        0x00040000,        # w9  addi r4,zero,0      m2: r4=dir=0 (stock x9351)
        0xFEC5B008,        # w10 or r5,r22,r22       m2: r5=obj (stock x3226)
        0x642600AE,        # w11 ld.d r6,r1,0xac     m2: r6=C raw (stock x5)
        0x30C600FF,        # w12 andmsk.hi r6,r6,0xff m2: r6=C (GOLDEN x47)
        0x002700B0,        # w13 addi r7,r1,0xb0     m2: r7=buf (stock x5)
        0x94F7CBB1,        # w14 call 0x18064c       m2: THE WRITE-POST
        0x00040000,        # w15 addi r4,zero,0      restore r4=0 (body requires)
        0x002B00AC,        # w16 addi r11,r1,0xac    payload ptr AFTER the call
        0x20034380,        # w17 set3 r3,zero,0x4380 r3 build lo (== v5l w10)
        0x2463008E,        # w18 set2 r3,r3,0x008e   r3 build hi (== v5l w11)
        0xFD005825,        # w19 ret.r zero,r8,r11   THE transfer (no-link, x3)
        0x95F80071,        # w20 jump FN_A           W_FAST last (== v5cA word)
    ]
    RESUME_LIVE = 0x008E4380              # == PC_BASE + DETOUR_DC + 4 (v5l)
    M2_TRANSPORT = 0x18064C               # the WRITE-POST wrapper (file space)

    def ws(self):
        from build_s2 import stub_words
        return stub_words("B", version=18)

    def test_v5m_golden_words(self):
        self.assertEqual(self.ws(), self.V5M_GOLDEN)

    def test_v5m_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5m"), stub_words("B", version=18))
        self.assertEqual(stub_words("B", version="v5m"),
                         stub_words("B", version=18))
        with self.assertRaises(ValueError):
            stub_words("A", version="v5m")          # v5m is mode B ONLY

    def test_v5m_prefix_v5l_w5_imm_only(self):
        # THE prefix contract vs v5l: w0-w4/w6-w8 == v5l BYTE-EXACT
        # except w5's IMMEDIATE (+8 -> +15: W_FAST moved w13 -> w20
        # when the 7-word m2 block was inserted); op+cc bits identical.
        from build_s2 import stub_words
        wl, wm = stub_words("A", version=17), self.ws()
        self.assertEqual(len(wl), 14)
        self.assertEqual(wm[0:5], wl[0:5])
        self.assertEqual(wm[6:9], wl[6:9])
        self.assertEqual(wm[5], 0xA40A000F)                 # b_f.cc0A +15
        self.assertEqual((wm[5] >> 16), (wl[5] >> 16))      # op+cc identical
        self.assertEqual((wm[5] & 0xFFFF) - (wl[5] & 0xFFFF), 7)  # imm 8->15

    def test_v5m_m2_words_exact_forms(self):
        # THE m2 block word-by-word: every word is an exact enc.* form
        # or the golden immediate-OR word extracted from the stock blob
        # (enc.py has NO immediate-OR encoder — op 0x0C; precedent T3-S2:
        # golden word, encoded inline, reported; stock census x47).
        wd = self.ws()
        self.assertEqual(wd[9], enc.addi(4, 0, 0))           # r4=dir=0
        self.assertEqual(wd[9], 0x00040000)                  # stock @0x0e4374
        self.assertEqual(wd[10], enc.or_(5, 22, 22))         # r5=obj
        self.assertEqual(wd[10], 0xFEC5B008)                 # stock @0x0e4378
        self.assertEqual(wd[11], enc.ld_d(6, 1, 0xAC))       # r6=C raw
        self.assertEqual(wd[11], 0x642600AE)
        self.assertEqual(wd[12], (0x0C << 26) | (6 << 21) | (6 << 16) | 0xFF)
        self.assertEqual(wd[12], 0x30C600FF)                 # GOLDEN x47
        self.assertEqual(wd[13], enc.addi(7, 1, 0xB0))       # r7=buf
        self.assertEqual(wd[13], 0x002700B0)
        self.assertEqual(wd[14], enc.call(STUB + 4 * 14, self.M2_TRANSPORT))
        self.assertEqual(wd[14], 0x94F7CBB1)                 # site-imm class
        self.assertEqual(wd[15], enc.addi(4, 0, 0))          # restore r4=0

    def test_v5m_m2_call_signature_decode(self):
        # decode-level signature: the call target is THE transport
        # wrapper 0x18064c, args r4=0 / r5=r22 / r6=[r1+0xac]|0xff /
        # r7=r1+0xb0, in exactly this order, with the r4=0 restore
        # right after the call (the body requires r4=0 at the resume).
        import irisc_dis
        wd = self.ws()
        dec = [irisc_dis.dis(w, STUB + 4 * i) for i, w in enumerate(wd)]
        self.assertEqual(dec[9], "addi r4,zero,0x0")
        self.assertEqual(dec[10], "or r5,r22,r22")
        self.assertEqual(dec[11], "ld.d r6,r1,0xac")
        self.assertEqual(dec[12], "andmsk.hi r6,r6,0xff")
        self.assertEqual(dec[13], "addi r7,r1,0xb0")
        self.assertEqual(dec[14], "call 0x%x" % self.M2_TRANSPORT)
        self.assertEqual(dec[15], "addi r4,zero,0x0")
        # exactly ONE call word in the stub; r22 is READ (obj), never written
        calls = [i for i, w in enumerate(wd)
                 if (w >> 26) == 0x25 and not (w >> 24) & 1]
        self.assertEqual(calls, [14])

    def test_v5m_r3r11_built_after_the_call(self):
        # THE Task-1 class note implemented: the m2 call clobbers the
        # caller-saved set (its own prologue is `csr.r r3,csr0xbc`), so
        # the payload ptr and the r3 build sit AFTER the call:
        # w16 == the v5l w9 word, w17/w18 == the v5l w10/w11 words
        # byte-exact (the SAME OR-safe lo-first build of RESUME_LIVE),
        # w19 THE transfer.  Nothing between the call and the transfer
        # depends on a pre-call value of r3/r11.
        from build_s2 import stub_words
        wl, wd = stub_words("A", version=17), self.ws()
        self.assertEqual(wd[16], wl[9])                     # payload ptr
        self.assertEqual(wd[16], enc.addi(11, 1, 0xAC))
        self.assertEqual(wd[17], wl[10])                    # r3 build lo
        self.assertEqual(wd[17], enc.set3(3, 0, self.RESUME_LIVE & 0xFFFF))
        self.assertEqual((wd[17] >> 21) & 0x1F, 0)          # rs = ZERO
        self.assertEqual(wd[18], wl[11])                    # r3 build hi
        self.assertEqual(wd[18], (0x09 << 26) | (3 << 21) | (3 << 16)
                         | (self.RESUME_LIVE >> 16))        # rs-bearing set2
        self.assertEqual(wd[19], wl[12])                    # THE transfer
        self.assertEqual(wd[19], enc.ret_r(8, 0, 11))       # no-link

    def test_v5m_transfers_and_jumps(self):
        # control words: exactly ONE ret.r (w19, rs=8 computed-jr,
        # NO LINK — the payload exit class; the w10 register-OR is the
        # OTHER 0x3F-space word — the alu f=8 form, not a transfer)
        # and exactly TWO op-0x25 words — the m2 call w14 (LINKS: a
        # real call) and W_FAST w20 (jump, no link, LAST word).
        wd = self.ws()
        self.assertEqual([i for i, w in enumerate(wd)
                          if (w >> 26) == 0x3F and (w & 0x1FF) == 0x25],
                         [19])
        self.assertEqual((wd[19] >> 21) & 0x1F, 8)          # rs = r8 (jr)
        self.assertEqual([i for i, w in enumerate(wd)
                          if (w >> 26) == 0x3F and (w & 0x1FF) == 0x08],
                         [10])                              # alu or (register)
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x25],
                         [14, 20])
        self.assertEqual((wd[14] >> 24) & 1, 0)             # call (links)
        self.assertEqual((wd[20] >> 24) & 1, 1)             # jump (no link)

    def test_v5m_wfast_last_and_filter_targets_it(self):
        wd = self.ws()
        w_fast = STUB + 4 * 20
        self.assertEqual(w_fast, 0x38D7A0)
        self.assertEqual(wd[20], enc.jump(w_fast, 0x18D964))
        self.assertEqual(wd[20], 0x95F80071)                # == v5cA W_FAST
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))

    def test_v5m_budget(self):
        ws = self.ws()
        self.assertEqual(len(ws), 21)               # 21/34 (13 spare)
        self.assertLessEqual(len(ws), 34)           # zone 0x38d750-0x38d7d8

    def test_v5m_clobber_confined(self):
        # v5m stub WRITES only {r3,r4,r5,r6,r7,r11,r12,r13} (the v5l
        # set + the m2 arg regs); r22 is READ ONLY (`or r5,r22,r22' —
        # the obj source); r17-r23 NEVER written; r1 NEVER written
        # (no push/pop words — the callee below r1 manages its own
        # balanced frame; the body pops the fn frame).
        import irisc_dis
        wd = self.ws()
        dec = [irisc_dis.dis(w, 0) for w in wd]
        writers = set()
        for s in dec:
            parts = s.split()
            if parts[0] in ("addi", "set3", "set2", "or", "ld.d", "ld.w",
                            "csr.r", "subsi", "and", "xor"):
                writers.add(parts[1].split(",")[0])
        self.assertLessEqual(writers, {"r3", "r4", "r5", "r6", "r7",
                                       "r11", "r12", "r13"})
        for s in dec:
            for reg in ("r14", "r15", "r16", "r17", "r18", "r19", "r20",
                        "r21", "r23", "r1,"):
                self.assertNotIn(reg + ",", s, f"{s!r} touches {reg}")
        # r22 appears ONLY as the read source of the obj marshal
        self.assertEqual([s for s in dec if "r22" in s], ["or r5,r22,r22"])
        # no memory writes at all: every st.d has rs == zero (CR echoes)
        for i, w in enumerate(wd):
            if (w >> 26) == 0x1B:
                self.assertEqual(((w >> 21) & 0x1F), 0,
                                 f"w{i}=0x{w:08x} stores with rs != zero")

    def test_v5m_diff_vs_v5l_tail_only(self):
        # THE diff contract: the changed words are w5 (the canonical
        # lineage retarget) and the tail w9..w20 — the prefix
        # w0-w4/w6-w8 is untouched; the shared v5l words (payload ptr,
        # r3 build, transfer) survive byte-exact at SHIFTED indexes.
        from build_s2 import stub_words
        wl, wm = stub_words("A", version=17), self.ws()
        self.assertEqual(wm[0:5] + wm[6:9], wl[0:5] + wl[6:9])
        # v5l tail words w9-w12 all present in v5m at SHIFTED indexes
        # (+7: after the 7-word m2 block) — byte-exact survival
        for i in range(9, 13):
            self.assertEqual(wm[i + 7], wl[i],
                             f"v5l w{i} drifted at v5m w{i + 7}")
        # the payload-ptr word count is stable (v5l w1/w9 -> v5m w1/w16)
        self.assertEqual(wm.count(0x002B00AC), wl.count(0x002B00AC))
        # the m2 block words are NEW to the zone (absent from v5l)
        for w in (0x00040000, 0xFEC5B008, 0x642600AE, 0x30C600FF,
                  0x002700B0, 0x94F7CBB1):
            self.assertNotIn(w, wl)
            self.assertIn(w, wm)
        # W_FAST moved w13 -> w20 (both last)
        self.assertEqual(wl[13] >> 26, 0x25)
        self.assertEqual(wm[20] >> 26, 0x25)
        self.assertNotEqual(wl[13], wm[20])                 # new site-imm

    def test_v5m_rejects_mode_a(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("A", version=18)              # v5m builds mode B only

    def test_v5m_rejects_mode_b_old_versions(self):
        # lineage hygiene: mode B is v5m/v5n/v5o/v5q/v5r-only — every
        # other version still rejects it (the v5l-lineage rejection
        # tests stay green)
        from build_s2 import stub_words, STUB_LAYOUT
        for v in sorted(STUB_LAYOUT):
            if v in (18, 19, 20, 22, 23):    # v5m/v5n/v5o/v5q/v5r — mode-B
                continue
            with self.assertRaises(ValueError, msg=f"version {v}"):
                stub_words("B", version=v)

    def test_v5m_stock_precedents(self):
        # NEW-word stock counts (census blob whole-image, verified this
        # task; golden extraction — journal task-02 Step 0):
        #   w9/w15 addi r4,zero,0 (0x00040000) x9351 — stock-exact (the
        #     stock arg-setup word @0x0e4374 itself)
        #   w10 or r5,r22,r22 (0xFEC5B008) x3226 — stock-exact (the
        #     stock obj-marshal word @0x0e4378 itself)
        #   w11 ld.d r6,r1,0xac (0x642600AE) x5 — stock-exact
        #   w12 andmsk.hi r6,r6,0xff (0x30C600FF) x47 — THE GOLDEN
        #     immediate-mask word from the blob (enc.py has no op-0x0C
        #     encoder)
        #   w13 addi r7,r1,0xb0 (0x002700B0) x5 — stock-exact
        #   w14 call site-imm (0x94F7CBB1) x0 — the call-word class
        #     (x47732 stock call words; every site-imm is unique)
        #   w5 retarget b_f.cc0A +15 (0xA40A000F) x19 — stock-exact
        #   w20 W_FAST (0x95F80071) x0 — live-form AND byte-exact the
        #     v5cA W_FAST word (same address 0x38d7a0)
        from build_s2 import stub_words
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        raw = blob.read_bytes()
        words = struct.unpack(">%dI" % (len(raw) // 4), raw)
        cnt = lambda x: sum(1 for w in words if w == x)
        self.assertEqual(cnt(0x00040000), 9351)
        self.assertEqual(cnt(0xFEC5B008), 3226)
        self.assertEqual(cnt(0x642600AE), 5)
        self.assertEqual(cnt(0x30C600FF), 47)
        self.assertEqual(cnt(0x002700B0), 5)
        self.assertEqual(cnt(0x94F7CBB1), 0)                 # site-imm
        self.assertEqual(cnt(0xA40A000F), 19)
        self.assertEqual(cnt(0x95F80071), 0)                 # live-form
        self.assertGreater(sum(1 for w in words
                               if (w >> 26) == 0x25 and not (w >> 24) & 1),
                           40000)                            # call class
        # the golden immediate-mask word decodes as the m2 key mask
        import irisc_dis
        self.assertEqual(irisc_dis.dis(0x30C600FF, 0), "andmsk.hi r6,r6,0xff")
        # every v5m word is stock-exact, lineage-live or documented
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7))
        for v in range(8, 18):
            lineage |= set(stub_words("A", version=v))
        documented = {0x00040000, 0xFEC5B008, 0x642600AE, 0x30C600FF,
                      0x002700B0, 0x94F7CBB1}
        for w in self.ws():
            self.assertTrue(w in lineage or w in set(words) or w in documented,
                            "word 0x%08x not stock/live/documented" % w)

    def test_v5m_lineage_untouched(self):
        from build_s2 import stub_words
        for v, n in ((2, 34), (4, 33), (5, 9), (6, 33), (7, 21), (8, 34),
                      (9, 33), (10, 30), (11, 32), (12, 23), (13, 22),
                      (14, 15), (15, 12), (16, 24), (17, 14), (18, 21)):
            self.assertEqual(len(stub_words("A" if v != 18 else "B",
                                            version=v)), n, f"v{v}")


class TestS2StubV5N(unittest.TestCase):
    # v5n (plan-2 s2b2, mode "B" — m2' X1-from-p0, THE DIRECT POST):
    # the v5m flow with the m2 wrapper-call REPLACED by a hand-built
    # X1 + the DIRECT transport call 0x2ae98 (r4=X1, r5=buf, r6=0):
    # w9 `ld.d r4,r1,0xac' = zext32(p0) = w (the TRIG frame's own p0 —
    # ZERO new data), w10 `shl64.i r4,r4,6' = w<<6, w11 `set1
    # r4,r4,0x8fc0' => X1 = 0x8FC010A2E400 (64B-aligned by
    # construction), w12 r5 = buf r1+0xb0, w13 r6 = 0, w14 THE DIRECT
    # POST.  The tail grows by ONE word vs v5m (21 -> 22): w16
    # `set3 r12,zero,0x4f4b' (== v5m p0, the live-proven S2OK-lo word)
    # rebuilds r12 AFTER the prefix w2 has loaded the frame-magic
    # 0x5332 into it — without it p1 `set2 r12,r12,0x5332' would keep
    # 0x5332 in the LO half and CR 0x2388 would be 0x53325332, not
    # 0x53324F4B (T1 G-a: the call does NOT clobber r12; the cause is
    # the w2 load).  W_FAST shifts w20 -> w21 (0x38d7a4, the v5h
    # address: 0x95F80070), w5's immediate +15 -> +16 (0xA40A0010,
    # stock x22).  Budget 22/34.
    V5N_GOLDEN = [
        0x480300BC,        # w0  csr.r r3,csr0xbc (prefix == v5m)
        0x002B00AC,        # w1  addi r11,r1,0xac
        0x642C00AB,        # w2  ld.w r12,r1,0xaa (filter)
        0x200D5332,        # w3  set3 r13,zero,0x5332
        0xE1806802,        # w4  cmp38_sel(2,12,13)
        0xA40A0010,        # w5  b_f.cc0A +16 -> W_FAST (w21, stock x22)
        0x6C046382,        # w6  st.d r12,zero,0x2380 (echo MAGIC16)
        0x642D00A5,        # w7  ld.w r13,r1,0xa4 (N)
        0x6C046B86,        # w8  st.d r13,zero,0x2384 (echo N)
        0x642400AE,        # w9  ld.d r4,r1,0xac      m2': r4 = zext32(p0) = w
        0xFC843081,        # w10 shl64.i r4,r4,6      m2': r4 = w<<6 (stock x253)
        0x1C848FC0,        # w11 set1 r4,r4,0x8fc0    m2': r4 = X1 (stock x3)
        0x002500B0,        # w12 addi r5,r1,0xb0      m2': r5 = buf (stock x6)
        0x00060000,        # w13 addi r6,zero,0       m2': r6 = status = 0
        0x94F275C4,        # w14 call 0x2ae98         m2': THE DIRECT POST
        0x00040000,        # w15 addi r4,zero,0       restore r4=0 (stock x9351)
        0x200C4F4B,        # w16 set3 r12,zero,0x4f4b r12 rebuild (== v5m p0)
        0x002B00AC,        # w17 addi r11,r1,0xac     payload ptr (post-call)
        0x20034380,        # w18 set3 r3,zero,0x4380  r3 build lo (== v5m w17)
        0x2463008E,        # w19 set2 r3,r3,0x008e    r3 build hi (== v5m w18)
        0xFD005825,        # w20 ret.r zero,r8,r11    THE transfer (no-link)
        0x95F80070,        # w21 jump 0x18d964        W_FAST last (== v5h word)
    ]
    M2_POST_DIRECT = 0x2AE98              # the direct transport (file space)

    def ws(self):
        from build_s2 import stub_words
        return stub_words("B", version=19)

    def test_v5n_golden_words(self):
        self.assertEqual(self.ws(), self.V5N_GOLDEN)

    def test_v5n_layout(self):
        from build_s2 import STUB_LAYOUT
        self.assertEqual(STUB_LAYOUT[19], (22, 21))

    def test_v5n_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5n"), stub_words("B", version=19))
        self.assertEqual(stub_words("B", version="v5n"),
                         stub_words("B", version=19))
        with self.assertRaises(ValueError):
            stub_words("A", version="v5n")          # v5n is mode B ONLY

    def test_v5n_rejects_mode_a(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("A", version=19)             # v5n builds mode B only

    def test_v5n_mode_b_v5m_still_ok(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("B", version=18)), 21)

    def test_v5n_prefix_v5m_w5_imm_only(self):
        # THE prefix contract vs v5m: w0-w4/w6-w8 == v5m BYTE-EXACT
        # except w5's IMMEDIATE (+15 -> +16: W_FAST moved w20 -> w21
        # when the r12-rebuild word entered the tail)
        from build_s2 import stub_words
        wm, wn = stub_words("B", version=18), self.ws()
        self.assertEqual(wn[0:5], wm[0:5])
        self.assertEqual(wn[6:9], wm[6:9])
        self.assertEqual(wn[5], 0xA40A0010)                 # b_f.cc0A +16
        self.assertEqual((wn[5] >> 16), (wm[5] >> 16))      # op+cc identical
        self.assertEqual((wn[5] & 0xFFFF) - (wm[5] & 0xFFFF), 1)  # imm 15->16

    def test_v5n_m2prime_words_exact_forms(self):
        # THE m2' block word-by-word: every word an exact enc.* form
        # (the whole block now ENCODABLE — no golden-from-blob words).
        wd = self.ws()
        self.assertEqual(wd[9], enc.ld_d(4, 1, 0xAC))       # r4 = zext32(p0)
        self.assertEqual(wd[9], 0x642400AE)                 # stock x20
        self.assertEqual(wd[10], enc.shl64_i(4, 4, 6))      # r4 = w<<6
        self.assertEqual(wd[10], 0xFC843081)                # stock x253
        self.assertEqual(wd[11], enc.set1(4, 4, 0x8FC0))    # r4 = X1
        self.assertEqual(wd[11], 0x1C848FC0)                # stock x3
        self.assertEqual(wd[12], enc.addi(5, 1, 0xB0))      # r5 = buf
        self.assertEqual(wd[12], 0x002500B0)
        self.assertEqual(wd[13], enc.addi(6, 0, 0))         # r6 = status = 0
        self.assertEqual(wd[13], 0x00060000)
        self.assertEqual(wd[14], enc.call(STUB + 4 * 14, self.M2_POST_DIRECT))
        self.assertEqual(wd[14], 0x94F275C4)                # site-imm class
        self.assertEqual(wd[15], enc.addi(4, 0, 0))         # restore r4=0

    def test_v5n_call_signature_decode(self):
        # decode-level signature at THE site (pc = 0x38d788): the call
        # targets THE DIRECT transport 0x2ae98; exactly ONE call word
        # in the stub (W_FAST is a no-link jump)
        import irisc_dis
        wd = self.ws()
        dec = [irisc_dis.dis(w, STUB + 4 * i) for i, w in enumerate(wd)]
        self.assertEqual(dec[9], "ld.d r4,r1,0xac")
        self.assertEqual(dec[10], "shl64.i r4,r4,0x6")
        self.assertEqual(dec[11], "set1 r4,r4,0x8fc0")
        self.assertEqual(dec[12], "addi r5,r1,0xb0")
        self.assertEqual(dec[13], "addi r6,zero,0x0")
        self.assertEqual(dec[14], "call 0x%x" % self.M2_POST_DIRECT)
        self.assertEqual(dec[15], "addi r4,zero,0x0")
        calls = [i for i, w in enumerate(wd)
                 if (w >> 26) == 0x25 and not (w >> 24) & 1]
        self.assertEqual(calls, [14])

    def test_v5n_r12_rebuild_and_tail_after_the_call(self):
        # the tail after the m2' call: w16 rebuilds r12 (the S2OK-lo
        # word == v5m p0, LIVE-PROVEN — the prefix w2 loaded 0x5332
        # into r12, and the call does NOT clobber it: T1 G-a), w17 the
        # payload ptr, w18/w19 rebuild r3 = RESUME_LIVE, w20 THE
        # transfer — w17-w20 == v5m w16-w19 byte-exact (the shared
        # OR-safe lo-first r3 build).
        from build_s2 import stub_words
        wm, wd = stub_words("B", version=18), self.ws()
        self.assertEqual(wd[16], enc.set3(12, 0, 0x4F4B))
        self.assertEqual(wd[16], 0x200C4F4B)                # == v5m p0
        self.assertEqual(wd[17], wm[16])                    # payload ptr
        self.assertEqual(wd[17], enc.addi(11, 1, 0xAC))
        self.assertEqual(wd[18], wm[17])                    # r3 build lo
        self.assertEqual(wd[19], wm[18])                    # r3 build hi
        self.assertEqual(wd[20], wm[19])                    # THE transfer
        self.assertEqual(wd[20], enc.ret_r(8, 0, 11))       # no-link

    def test_v5n_wfast_last_and_filter_targets_it(self):
        wd = self.ws()
        w_fast = STUB + 4 * 21
        self.assertEqual(w_fast, 0x38D7A4)
        self.assertEqual(wd[21], enc.jump(w_fast, 0x18D964))
        self.assertEqual(wd[21], 0x95F80070)                # == v5h W_FAST
        self.assertEqual(wd[5], enc.b_f(0x0A, STUB + 4 * 5, w_fast))

    def test_v5n_transfers_and_jumps(self):
        # exactly ONE ret.r (w20, rs=8 computed-jr, NO LINK) and
        # exactly TWO op-0x25 words — the m2' call w14 (LINKS) and
        # W_FAST w21 (jump, no link, LAST word)
        wd = self.ws()
        self.assertEqual([i for i, w in enumerate(wd)
                          if (w >> 26) == 0x3F and (w & 0x1FF) == 0x25],
                         [20])
        self.assertEqual((wd[20] >> 21) & 0x1F, 8)          # rs = r8 (jr)
        self.assertEqual([i for i, w in enumerate(wd) if (w >> 26) == 0x25],
                         [14, 21])
        self.assertEqual((wd[14] >> 24) & 1, 0)             # call (links)
        self.assertEqual((wd[21] >> 24) & 1, 1)             # jump (no link)

    def test_v5n_budget(self):
        from build_s2 import ZONE_WORDS
        ws = self.ws()
        self.assertEqual(len(ws), 22)                       # 22/34
        self.assertLessEqual(len(ws), ZONE_WORDS)           # zone 0x38d750-0x38d7d8

    def test_v5n_clobber_confined(self):
        # v5n stub WRITES only {r3,r4,r5,r6,r11,r12,r13}; r1 NEVER
        # written (no push/pop — the callee frame is balanced, the
        # body pops); r22 NEVER touched (v5n does not read obj); no
        # memory writes outside the CR echoes.
        import irisc_dis
        wd = self.ws()
        dec = [irisc_dis.dis(w, 0) for w in wd]
        writers = set()
        for s in dec:
            parts = s.split()
            if parts[0] in ("addi", "set1", "set2", "set3", "or", "ld.d",
                            "ld.w", "csr.r", "shl64.i", "subsi", "and",
                            "xor"):
                writers.add(parts[1].split(",")[0])
        self.assertLessEqual(writers, {"r3", "r4", "r5", "r6", "r11",
                                       "r12", "r13"})
        self.assertNotIn("r1", writers)
        for reg in ("r2", "r7", "r8", "r9", "r10", "r14", "r15", "r16",
                    "r17", "r18", "r19", "r20", "r21", "r22", "r23"):
            self.assertNotIn(reg, writers, f"stub writes {reg}")
        for s in dec:
            self.assertNotIn("r22", s, f"{s!r} touches r22")
        # no memory writes at all: every st.d has rs == zero (CR echoes)
        for i, w in enumerate(wd):
            if (w >> 26) == 0x1B:
                self.assertEqual(((w >> 21) & 0x1F), 0,
                                 f"w{i}=0x{w:08x} stores with rs != zero")

    def test_v5n_stock_precedents(self):
        # NEW/CHANGED word stock counts (Task-1 CENSUS, de-crc'd code
        # file — code space canonical):
        #   w5  b_f.cc0A +16 (0xA40A0010) x22 — stock-exact
        #   w9  ld.d r4,r1,0xac (0x642400AE) x20 — stock-exact
        #        (incl. 0xe4368, the stock detour caller)
        #   w10 shl64.i r4,r4,6 (0xFC843081) x253 — stock-exact
        #   w11 set1 r4,r4,0x8fc0 (0x1C848FC0) x3 — stock-exact
        #        (@0x82a74/0x90b14/0x90c04)
        #   w12 addi r5,r1,0xb0 (0x002500B0) x6 — stock-exact
        #   w13 addi r6,zero,0 (0x00060000) x2317 — common word
        #   w15 addi r4,zero,0 (0x00040000) x9351 — stock-exact
        #   w14 call site-imm (0x94F275C4) x0 — the call-word class
        #        (every site-imm is unique)
        #   w16 set3 r12,zero,0x4f4b (0x200C4F4B) x0 — == v5m p0 (new
        #        to the zone)
        #   w21 W_FAST (0x95F80070) x0 — live-form, byte-exact the
        #        v5h W_FAST word (the same address 0x38d7a4)
        from build_s2 import stub_words
        code = REPO / "build" / "4030cda-main03-code-patched3.bin"
        if not code.exists():
            self.skipTest("de-crc'd code not present")
        raw = code.read_bytes()
        words = struct.unpack(">%dI" % (len(raw) // 4), raw)
        cnt = lambda x: sum(1 for w in words if w == x)
        self.assertEqual(cnt(0xA40A0010), 22)
        self.assertEqual(cnt(0x642400AE), 20)
        self.assertEqual(cnt(0xFC843081), 253)
        self.assertEqual(cnt(0x1C848FC0), 3)
        self.assertEqual(cnt(0x002500B0), 6)
        self.assertEqual(cnt(0x00060000), 2317)
        self.assertEqual(cnt(0x00040000), 9351)
        self.assertEqual(cnt(0x94F275C4), 0)                # site-imm
        self.assertEqual(cnt(0x200C4F4B), 0)                # == v5m p0
        self.assertEqual(cnt(0x95F80070), 0)                # live-form
        self.assertGreater(sum(1 for w in words
                               if (w >> 26) == 0x25 and not (w >> 24) & 1),
                           40000)                           # call class
        # the m2' words self-decode to the planned mnemonics
        import irisc_dis
        self.assertEqual(irisc_dis.dis(0xFC843081, 0), "shl64.i r4,r4,0x6")
        self.assertEqual(irisc_dis.dis(0x1C848FC0, 0), "set1 r4,r4,0x8fc0")
        # every v5n word is stock-exact, lineage-live or v5m-lineage
        # EXCEPT the two census-x0 words that are the POINT of v5n
        # (the new-to-zone set must be EXACTLY these two):
        #   w14 0x94F275C4 — THE DIRECT call (call-word class: every
        #        site-imm is unique by construction)
        #   w16 0x200C4F4B — the r12 rebuild, == v5m PAYLOAD p0
        #        (moved from the payload into the stub zone)
        lineage = set(stub_words("A", version=6)) | set(stub_words("A", version=7))
        for v in range(8, 18):
            lineage |= set(stub_words("A", version=v))
        lineage |= set(stub_words("B", version=18))
        stock = set(words)
        new_words = [w for w in self.ws() if w not in lineage and w not in stock]
        self.assertEqual(len(new_words), 2,
                         "the new-to-zone set must be exactly w14/w16: %r"
                         % ["0x%08x" % w for w in new_words])
        self.assertEqual(set(new_words), {self.ws()[14], self.ws()[16]})

    def test_v5n_lineage_untouched(self):
        # all versions 2..18 build as before (18 as mode B); 19 joins
        # as the second mode-B version; 20 (v5o) as the third
        from build_s2 import stub_words
        for v, n in ((2, 34), (4, 33), (5, 9), (6, 33), (7, 21), (8, 34),
                      (9, 33), (10, 30), (11, 32), (12, 23), (13, 22),
                      (14, 15), (15, 12), (16, 24), (17, 14), (18, 21),
                      (19, 22), (20, 22)):
            self.assertEqual(len(stub_words("A" if v not in (18, 19, 20)
                                             else "B", version=v)), n,
                             f"v{v}")


class TestS2StubV5O(unittest.TestCase):
    # v5o (plan-3 s2b2, mode "B" — ladder A.2 candidate 1: in_mb0):
    # the v5n m2' stub VERBATIM (22 words, byte-exact): the m2' block
    # reads p0 (w) from the TRIG frame at RUNTIME — the image is
    # w-independent (plan design fact 1).  w = 0x428B80 (IOVA in_mb0
    # = 0x10A2E000, 2 sessions) enters ONLY through the TRIG frame's
    # p0 (Б.6-1); X1 = 0x8FC010A2E000.  Identity vs v5n is a TESTED
    # contract (not an assumption).
    W = 0x428B80
    X1 = 0x8FC010A2E000
    V5O_GOLDEN = TestS2StubV5N.V5N_GOLDEN          # byte-exact the v5n words

    def ws(self):
        from build_s2 import stub_words
        return stub_words("B", version=20)

    def test_v5o_golden_words(self):
        self.assertEqual(self.ws(), self.V5O_GOLDEN)

    def test_v5o_identity_v5n_words(self):
        from build_s2 import stub_words
        self.assertEqual(self.ws(), stub_words("B", version=19))

    def test_v5o_layout(self):
        from build_s2 import STUB_LAYOUT
        self.assertEqual(STUB_LAYOUT[20], (22, 21))

    def test_v5o_alias(self):
        from build_s2 import stub_words
        self.assertEqual(stub_words("v5o"), stub_words("B", version=20))
        self.assertEqual(stub_words("B", version="v5o"),
                         stub_words("B", version=20))
        with self.assertRaises(ValueError):
            stub_words("A", version="v5o")         # v5o is mode B ONLY

    def test_v5o_rejects_mode_a(self):
        from build_s2 import stub_words
        with self.assertRaises(ValueError):
            stub_words("A", version=20)            # v5o builds mode B only

    def test_v5o_mode_b_v5m_v5n_still_ok(self):
        from build_s2 import stub_words
        self.assertEqual(len(stub_words("B", version=18)), 21)
        self.assertEqual(len(stub_words("B", version=19)), 22)


class TestS2StubV5MSim(unittest.TestCase):
    # v5m per-path REGISTER-TRUE simulation with the m2 WRITE-POST call
    # and PAYLOAD execution.  Model re-based from the v5l Sim (same
    # fn-frame model: inner [r1+4] residue, outer [R+4] dispatcher ra,
    # r17-r23 clobbered-on-arrival) PLUS:
    #   - op-0x0C immediate-OR (the m2 key word);
    #   - THE m2 call model: a call word targeting LIVE 0x98064C
    #     records the call event (args r4/r5/r6/r7), LINKS csr0xbc to
    #     the resume, CLOBBERS the caller-saved set with garbage
    #     (r3/r4/r5/r6/r11/r12/r13 — proving the post-call re-establish
    #     discipline is LOAD-BEARING), preserves r1 (balanced callee
    #     frame) and r17-r23 (callee-saved convention), and CONTINUES
    #     at the next stub word (the callee returned).
    # The POST itself is a DMA read of buf -> host X1: modeled as an
    # EVENT, not a store — the card-side RAM is only READ (task-1:
    # byte-exact 0x40-byte POST; zero new FW-RAM writes).
    R1E = 0x1000
    STUB_LIVE = 0x800000 + 0x38D750
    FN_A_LIVE = 0x98D964
    M2_LIVE = 0x98064C                      # == 0x800000 + 0x18064c
    RA_LIVE = 0x8E4380                      # the exit: call-site resume
    INNER_RA = 0x8E435C
    OUTER_RA = 0x8AA1D8
    SAVED_REGS = (23, 22, 21, 20, 19, 18, 17)
    CALL_CLOBBER = (3, 4, 5, 6, 11, 12, 13)

    class SimV5M:
        def __init__(self, ws, N, magic=True, code=None, r1=None,
                     outer_ra=None, inner_ra=None):
            TestS = TestS2StubV5MSim
            r1 = TestS.R1E if r1 is None else r1
            self.ws = ws
            self.mem = {}
            self.cr = {0x2380: 0, 0x2384: 0, 0x2388: 0, 0x238C: 0}
            self.csr0xbc = TestS.RA_LIVE
            self.links = []
            self.mem[r1 + 0xA4] = N
            self.mem[r1 + 0xAA] = 0x5332 if magic else 0x1234
            self.mem[r1 + 0x4] = (TestS.INNER_RA if inner_ra is None
                                  else inner_ra)
            self.mem[r1 + 0xF8 + 0x4] = (TestS.OUTER_RA if outer_ra is None
                                         else outer_ra)
            for i, reg in enumerate(TestS.SAVED_REGS):
                self.mem[r1 + 0xDC + 4 * i] = 0xCAFE0000 + reg
            for i, cw in enumerate(code):
                self.mem[r1 + 0xAC + 4 * i] = cw
            self.r = {1: r1, 3: 0xDEAD, 4: 0, 5: 0x11112222, 6: 0x33334444,
                      7: 0x55556666, 11: 0, 12: 0, 13: 0}
            for reg in TestS.SAVED_REGS:
                self.r[reg] = 0xDEAD0000 + reg
            self.pc = 0
            self.eq = False
            self.z32 = False
            self.stores = []
            self.taken = []
            self.pay_fetch = []
            self.exit_ea = None
            self.n = 0
            self.load_log = []
            self.r1_writes = []
            self.m2 = []                             # (ea, r4, r5, r6, r7)

        def rd(self, k):
            return 0 if k == 0 else self.r[k]

        def run(self, max_steps=200):
            import irisc_dis
            STUB_L = TestS2StubV5MSim.STUB_LIVE
            FN_A_L = TestS2StubV5MSim.FN_A_LIVE
            M2_L = TestS2StubV5MSim.M2_LIVE
            for _ in range(max_steps):
                if isinstance(self.pc, int):
                    i = self.pc
                    if not 0 <= i < len(self.ws):
                        return "WILD_%08x" % (STUB_L + 4 * i)
                    word = self.ws[i]
                    ea = STUB_L + 4 * i
                    nxt = i + 1
                else:
                    ea = self.pc[1]
                    if ea >= 0x800000:
                        off = ea - STUB_L
                        if 0 <= off < 4 * len(self.ws) and off % 4 == 0:
                            return "STUB_ZONE_TARGET_%08x" % ea
                        self.exit_ea = ea
                        return "EXIT_%08x" % ea
                    if ea not in self.mem:
                        return "DEAD_%08x" % ea
                    word = self.mem[ea]
                    self.pay_fetch.append(ea)
                    nxt = ("ea", ea + 4)
                self.n += 1
                op = word >> 26
                if op == 0x12:
                    self.r[3] = self.csr0xbc
                elif op == 0x00:
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    rd = (word >> 16) & 0x1F
                    self.r[rd] = \
                        (self.rd((word >> 21) & 0x1F) + imm) & 0xFFFFFFFF
                    if rd == 1:
                        self.r1_writes.append((self.n - 1, self.r[1]))
                elif op == 0x08:
                    rs = self.rd((word >> 21) & 0x1F)
                    self.r[(word >> 16) & 0x1F] = \
                        (rs & 0xFFFF0000) | ((rs & 0xFFFF) | (word & 0xFFFF))
                elif op == 0x09:
                    rs = self.rd((word >> 21) & 0x1F)
                    self.r[(word >> 16) & 0x1F] = \
                        (rs & 0x0000FFFF) | ((rs & 0xFFFF0000)
                                            | ((word & 0xFFFF) << 16))
                elif op == 0x0C:                      # or imm (the m2 key)
                    self.r[(word >> 16) & 0x1F] = \
                        self.rd((word >> 21) & 0x1F) | (word & 0xFFFF)
                elif op == 0x19:
                    rt, rs = (word >> 16) & 0x1F, (word >> 21) & 0x1F
                    if word & 1:
                        off = ((word >> 1) & 0x7FFF) << 1
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0) & 0xFFFF
                    else:
                        off = ((word >> 2) & 0x3FFF) << 2
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0)
                    self.load_log.append((self.n - 1, rt, self.rd(rs) + off))
                elif op == 0x1B:
                    rt, rs = (word >> 11) & 0x1F, (word >> 21) & 0x1F
                    off = (((word >> 16) & 0x1F) << 11) \
                        | (((word >> 2) & 0x1FF) << 2)
                    if rs == 0:
                        self.cr[off] = self.r[rt]
                        self.stores.append((off, self.r[rt], "CR"))
                    else:
                        ea = (self.rd(rs) + off) & 0xFFFFFFFF
                        kind = "STACK" if self.r[1] - 0x40 <= ea < self.r[1] else "ABS"
                        self.mem[ea] = self.r[rt]
                        self.stores.append((ea, self.r[rt], kind))
                elif op == 0x38:
                    self.eq = self.rd((word >> 21) & 0x1F) == \
                        self.rd((word >> 11) & 0x1F)
                elif op in (0x28, 0x29):
                    if not isinstance(self.pc, int):
                        return "UNSUPPORTED_branch_in_payload"
                    cc = (word >> 16) & 0x1F
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    cond = self.eq if cc == 0x0A else self.z32 if cc == 0 else False
                    if (cond if op == 0x28 else not cond):
                        self.taken.append((self.pc, op, cc, cond))
                        nxt = self.pc + imm
                elif op == 0x25:
                    is_call = not word & 0x01000000
                    if is_call:                          # call: LINKS
                        self.csr0xbc = (ea + 4) & 0xFFFFFFFF
                        self.links.append((ea, "call"))
                    tgt = ea + irisc_dis.s24(word) * 4
                    if is_call and tgt == M2_L:
                        # THE m2 WRITE-POST call: model the callee
                        # contract — record the args (the signature IS
                        # the protocol), clobber the caller-saved set
                        # with garbage (the re-establish words after
                        # the call are LOAD-BEARING), preserve r1 (the
                        # callee frame is balanced) and r17-r23
                        # (convention) — and CONTINUE at the resume.
                        self.m2.append((ea, self.r[4], self.r[5],
                                        self.r[6], self.r[7]))
                        for reg in TestS2StubV5MSim.CALL_CLOBBER:
                            self.r[reg] = (0xCCCC0000 + reg) & 0xFFFFFFFF
                        nxt = i + 1
                    else:
                        j = (tgt - STUB_L) // 4
                        if 0 <= j < len(self.ws) and tgt == STUB_L + 4 * j:
                            nxt = j
                        elif tgt == FN_A_L:
                            self.exit_ea = tgt
                            return "FN_A"
                        else:
                            self.exit_ea = tgt
                            return "EXIT_%08x" % tgt
                elif op == 0x3F and (word & 0x1FF) == 0x08:  # alu or (register)
                    self.r[(word >> 16) & 0x1F] = \
                        self.rd((word >> 21) & 0x1F) | self.rd((word >> 11) & 0x1F)
                elif op == 0x3F and (word & 0x1FF) == 0x25:
                    rs, rt = (word >> 21) & 0x1F, (word >> 11) & 0x1F
                    if rs == 0:
                        self.csr0xbc = (ea + 4) & 0xFFFFFFFF
                        self.links.append((ea, "jalr"))
                    nxt = ("ea", self.rd(rt))
                else:
                    return "UNSUPPORTED_op_%02x" % op
                self.pc = nxt
            return "RUNAWAY"

    def ws(self):
        from build_s2 import stub_words
        return stub_words("B", version=18)

    def payload_words(self):
        import payload as pl
        return pl.payload_v5m()

    def test_sim_fallthrough_no_m2_no_store_no_transfer(self):
        # non-magic frames NEVER reach the m2 block: the filter b_f
        # (w5, taken at latch FALSE — the only live-proven clean
        # taken-conditional class) jumps straight to W_FAST -> FN_A.
        s = self.SimV5M(self.ws(), 4, magic=False, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.exit_ea, 0x98D964)
        self.assertEqual(s.m2, [])                         # NO POST
        self.assertEqual(s.stores, [])
        self.assertEqual(s.pay_fetch, [])
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.r1_writes, [])

    def test_sim_magic_path_full_contract(self):
        # THE v5m exec path: prefix (echoes) -> m2 block (args -> THE
        # WRITE-POST call -> r4 restore) -> payload ptr/r3 rebuild ->
        # transfer -> payload p0..p3 from the landing -> p3 EXITS to
        # 0x8E4380 (the fn body resume, as v5l).  CR contract:
        # 0x2380=MAGIC16, 0x2384=N, 0x2388=S2OK, 0x238C=0; exactly ONE
        # m2 call; r1 NOT popped; r17-r23 preserved through the call
        # AND the stub; r4 == 0 at the exit (RESTORED after the call
        # clobbered it); ZERO stack/absolute writes (the POST is a DMA
        # read, modeled as an event); ZERO taken conditionals.
        code = self.payload_words()
        s = self.SimV5M(self.ws(), 4, code=code)
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.exit_ea, self.RA_LIVE)
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                         (0x5332, 4, 0x53324F4B, 0))
        self.assertEqual(len(s.m2), 1)
        m2_ea, a4, a5, a6, a7 = s.m2[0]
        self.assertEqual(m2_ea, self.STUB_LIVE + 4 * 14)   # w14
        self.assertEqual(a4, 0)                            # dir=0 POST
        self.assertEqual(a5, 0xDEAD0000 + 22)              # obj == r22
        self.assertEqual(a6, code[0] | 0xFF)               # C == p0|0xff
        self.assertEqual(a7, self.R1E + 0xB0)              # buf == r1+0xb0
        self.assertEqual(s.r[1], self.R1E)                 # NOT popped
        self.assertEqual(s.r1_writes, [])
        self.assertEqual(s.r[4], 0)                        # restored (w15)
        self.assertEqual(s.r[3], self.RA_LIVE)             # rebuilt (w17/18)
        self.assertEqual(s.r[11], self.R1E + 0xAC)         # rebuilt (w16)
        for reg in self.SAVED_REGS:
            self.assertEqual(s.r[reg], 0xDEAD0000 + reg,
                             f"r{reg} touched (call must preserve)")
        self.assertEqual(s.taken, [])
        kinds = {k for _, _, k in s.stores}
        self.assertEqual(kinds, {"CR"})                    # CR writes only
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0xAC + 4 * i for i in range(4)])

    def test_sim_m2_call_clobber_reestablished(self):
        # THE load-bearing discipline: the model CLOBBERS r3/r4/r11
        # with garbage AT the call — the run still lands the payload
        # transfer on r1+0xac and the exit on 0x8E4380 ONLY because
        # w15/w16/w17/w18 re-establish them AFTER the call.  (A stub
        # variant that builds r3/r11 before the m2 block would exit to
        # garbage — the model catches it by construction.)  csr0xbc is
        # DIRTY after the call (the call linked it to the w15 resume
        # 0xB8D78C) — documented SAFE: the post-resume body path writes
        # csr0xbc via its own `call 0x0e4424' @0x0e43b8 before any
        # read (blob scan, journal task-02 Step 0.5), and the early-
        # exit path reads only [R+4].
        code = self.payload_words()
        s = self.SimV5M(self.ws(), 4, code=code)
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.links, [(self.STUB_LIVE + 4 * 14, "call")])
        self.assertEqual(s.csr0xbc, 0xB8D78C)              # w15 live resume
        for garbage_reg, rebuilt in ((3, self.RA_LIVE), (4, 0),
                                     (11, self.R1E + 0xAC)):
            self.assertNotEqual(s.r[garbage_reg], 0xCCCC0000 + garbage_reg)
            self.assertEqual(s.r[garbage_reg], rebuilt)

    def test_sim_m2_post_precedes_payload(self):
        # protocol order: the POST fires BEFORE the payload executes —
        # the exfil'd buf bytes are the PRISTINE TRIG frame (p1..p3 as
        # delivered by the host; the payload's only RAM-visible effect
        # is none — S2OK goes to CR space, not to buf).
        order = {}
        code = self.payload_words()
        s = self.SimV5M(self.ws(), 4, code=code)
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(len(s.m2), 1)
        self.assertEqual(s.pay_fetch[0], self.R1E + 0xAC)
        self.assertEqual(s.cr[0x2388], 0x53324F4B)         # after the POST

    def test_sim_exit_is_callsite_resume_ignores_seeds(self):
        # the exit EA is EXACTLY the call-site resume — never the
        # inner livelock residue, never the outer dispatcher ra, at
        # any seed.
        for seed in (0x8AA1D8, 0x8ACEDC, 0x900004):
            s = self.SimV5M(self.ws(), 4, code=self.payload_words(),
                            outer_ra=seed)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"outer seed 0x{seed:x}")
        for seed in (0x8E435C, 0xDEAD0004):
            s = self.SimV5M(self.ws(), 4, code=self.payload_words(),
                            inner_ra=seed)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"inner seed 0x{seed:x}")

    def test_sim_no_stub_zone_target_on_any_path(self):
        for magic in (True, False):
            s = self.SimV5M(self.ws(), 4, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.RA_LIVE),
                            f"magic={magic}: unexpected {out}")

    def test_sim_zero_stack_writes_all_paths(self):
        for magic in (True, False):
            s = self.SimV5M(self.ws(), 4, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.RA_LIVE),
                            f"magic={magic}: unexpected {out}")
            for ea, v, k in s.stores:
                self.assertNotIn(k, ("STACK", "ABS"),
                                 f"magic={magic}: non-CR write 0x{ea:x}")

    def test_sim_base_independence_all_16_sp_bases(self):
        # the SAME FIXED word list (stub AND payload) at EVERY SP base
        # (SP-init 0x7d1ff8 + k*0x2000, all 16 cores): the m2 call
        # signature tracks the base (obj/C are base-independent
        # values; buf == base+0xb0), the C1 signal lands everywhere,
        # the exit is the ABSOLUTE resume everywhere, r1 stays the
        # UNPOPPED fn frame.
        import payload as pl
        fixed_stub, fixed_payload = self.ws(), pl.payload_v5m()
        for k in range(16):
            base = 0x7D1FF8 + k * 0x2000
            s = self.SimV5M(fixed_stub, 4, code=fixed_payload, r1=base)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"base 0x{base:x}")
            self.assertEqual(s.exit_ea, self.RA_LIVE, f"base 0x{base:x}")
            self.assertEqual(s.cr[0x2388], 0x53324F4B, f"base 0x{base:x}")
            self.assertEqual(len(s.m2), 1, f"base 0x{base:x}")
            self.assertEqual(s.m2[0][4], base + 0xB0, f"base 0x{base:x}")
            self.assertEqual(s.r[1], base, f"base 0x{base:x}: NOT popped")
            for reg in self.SAVED_REGS:
                self.assertEqual(s.r[reg], 0xDEAD0000 + reg,
                                 f"base 0x{base:x}: r{reg} touched")
            self.assertEqual(s.pay_fetch, [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")

    def test_sim_s2ok_exact(self):
        s = self.SimV5M(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.r[12], 0x53324F4B)
        self.assertEqual(s.cr[0x2388], 0x53324F4B)

    def test_sim_branch_inventory_all_paths(self):
        for n, magic, want in ((4, True, []), (1, True, []),
                               (4, False, [(5, 0x29, 0x0A, False)])):
            s = self.SimV5M(self.ws(), n, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.RA_LIVE),
                            f"N={n} magic={magic}: {out}")
            self.assertEqual(s.taken, want, f"N={n} magic={magic}")

    def test_sim_trig_frame_bytes_drive_the_path(self):
        # THE TRIG frame (the exact 36B host bytes) drives the full
        # path — unpack N / MAGIC16 / the 4 payload words FROM THE
        # FRAME BYTES, run at several bases: everywhere the m2 call
        # fires with C = frame_p0|0xff and the exit lands on the
        # call-site resume.
        import payload as pl
        frame = pl.input_block_v5m()
        b = bytes.fromhex(frame.hex())
        n = struct.unpack(">H", b[0xC:0xE])[0]
        magic16 = struct.unpack(">H", b[0x12:0x14])[0]
        words = list(struct.unpack(">4I", b[0x14:0x24]))
        self.assertEqual((n, magic16), (4, 0x5332))
        for base in (self.R1E, 0x7D1FF8, 0x7D9FF8, 0x7EFFF8):
            s = self.SimV5M(self.ws(), n, code=words, r1=base)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"base 0x{base:x}")
            self.assertEqual((s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                             (4, 0x53324F4B, 0), f"base 0x{base:x}")
            self.assertEqual(len(s.m2), 1, f"base 0x{base:x}")
            self.assertEqual(s.m2[0][3], words[0] | 0xFF, f"base 0x{base:x}")
            self.assertEqual(s.m2[0][4], base + 0xB0, f"base 0x{base:x}")
            self.assertEqual(s.r[1], base, f"base 0x{base:x}: NOT popped")
            self.assertEqual(s.pay_fetch, [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")


class TestS2StubV5NSim(unittest.TestCase):
    # v5n per-path REGISTER-TRUE simulation with the m2' DIRECT-POST
    # call and PAYLOAD execution (p0 = w executes IN-PLACE).  Model
    # re-based from the v5l/v5m Sim (same fn-frame model) PLUS:
    #   - 64-BIT registers (slaspec register space size=8): set0/
    #     set1/set2/set3 are 16-bit slice replaces, shl64.i a 64-bit
    #     shift, addi a sign-extended simm16 into 64 bits, st.d the
    #     LO 32 bits, ld.d a zext32;
    #   - THE m2' call model: a call word targeting LIVE 0x82AE98
    #     (== 0x800000 + 0x2ae98, the DIRECT transport) records the
    #     call event (args r4/r5/r6 — the signature IS the protocol),
    #     LINKS csr0xbc to the resume, CLOBBERS the T1 clobber-set
    #     {r3,r4,r5,r7-r11} with garbage (the post-call re-establish
    #     words are LOAD-BEARING), does NOT write r12 (T1 G-a),
    #     preserves r1 (balanced callee frame), r2/r6 (convention)
    #     and r17-r23 (callee-saved) — and CONTINUES at the next
    #     stub word (the callee returned).
    # The POST itself is a DMA read of buf -> host X1: modeled as an
    # EVENT, not a store — the card-side RAM is only READ (zero new
    # FW-RAM writes).
    R1E = 0x1000
    STUB_LIVE = 0x800000 + 0x38D750
    FN_A_LIVE = 0x98D964
    M2P_LIVE = 0x800000 + 0x2AE98             # the direct transport (live)
    RA_LIVE = 0x8E4380                        # the exit: call-site resume
    SAVED_REGS = (23, 22, 21, 20, 19, 18, 17)
    CALL_CLOBBER = (3, 4, 5, 7, 8, 9, 10, 11)   # T1 clobber-set

    class SimV5N:
        MASK = 0xFFFFFFFFFFFFFFFF

        def __init__(self, ws, N, magic=True, code=None, r1=None):
            TestS = TestS2StubV5NSim
            r1 = TestS.R1E if r1 is None else r1
            self.ws = ws
            self.mem = {}
            self.cr = {0x2380: 0, 0x2384: 0, 0x2388: 0, 0x238C: 0}
            self.csr0xbc = TestS.RA_LIVE
            self.links = []
            self.mem[r1 + 0xA4] = N
            self.mem[r1 + 0xAA] = 0x5332 if magic else 0x1234
            for i, cw in enumerate(code or []):
                self.mem[r1 + 0xAC + 4 * i] = cw
            self.r = {1: r1, 2: 0x40000000, 3: 0xDEAD, 4: 0,
                      5: 0x11112222, 6: 0x33334444, 7: 0x55556666,
                      8: 0x77778888, 9: 0x9999AAAA, 10: 0xBBBBCCCC,
                      11: 0, 12: 0, 13: 0}
            for reg in TestS.SAVED_REGS:
                self.r[reg] = 0xDEAD0000 + reg
            self.pc = 0
            self.eq = False
            self.stores = []
            self.taken = []
            self.pay_fetch = []
            self.events = []                  # ("call"|"fetch", ea) order
            self.exit_ea = None
            self.n = 0
            self.load_log = []
            self.r1_writes = []
            self.r12_trace = []               # (stub idx, r12 after)
            self.m2p = []                     # (ea, r4, r5, r6)

        def rd(self, k):
            return 0 if k == 0 else self.r[k]

        def run(self, max_steps=200):
            import irisc_dis
            STUB_L = TestS2StubV5NSim.STUB_LIVE
            FN_A_L = TestS2StubV5NSim.FN_A_LIVE
            M2P_L = TestS2StubV5NSim.M2P_LIVE
            MASK = self.MASK
            for _ in range(max_steps):
                if isinstance(self.pc, int):
                    i = self.pc
                    if not 0 <= i < len(self.ws):
                        return "WILD_%08x" % (STUB_L + 4 * i)
                    word = self.ws[i]
                    ea = STUB_L + 4 * i
                    nxt = i + 1
                else:
                    ea = self.pc[1]
                    if ea >= 0x800000:
                        off = ea - STUB_L
                        if 0 <= off < 4 * len(self.ws) and off % 4 == 0:
                            return "STUB_ZONE_TARGET_%08x" % ea
                        self.exit_ea = ea
                        return "EXIT_%08x" % ea
                    if ea not in self.mem:
                        return "DEAD_%08x" % ea
                    word = self.mem[ea]
                    self.pay_fetch.append(ea)
                    self.events.append(("fetch", ea))
                    nxt = ("ea", ea + 4)
                self.n += 1
                op = word >> 26
                if op == 0x12:
                    self.r[3] = self.csr0xbc
                elif op == 0x00:
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    rd = (word >> 16) & 0x1F
                    self.r[rd] = \
                        (self.rd((word >> 21) & 0x1F) + imm) & MASK
                    if rd == 1:
                        self.r1_writes.append((self.n - 1, self.r[1]))
                elif op in (0x06, 0x07, 0x08, 0x09):
                    rd, rs = (word >> 16) & 0x1F, (word >> 21) & 0x1F
                    imm = word & 0xFFFF
                    v = self.rd(rs)
                    if op == 0x06:                    # set0: bits 48-63
                        v = (v & 0x0000FFFFFFFFFFFF) | (imm << 48)
                    elif op == 0x07:                  # set1: bits 32-47
                        v = (v & 0xFFFF0000FFFFFFFF) | (imm << 32)
                    elif op == 0x08:                  # set3: bits 0-15
                        v = (v & 0xFFFFFFFFFFFF0000) | imm
                    else:                             # set2: bits 16-31
                        v = (v & 0xFFFFFFFF0000FFFF) | (imm << 16)
                    self.r[rd] = v & MASK
                    if rd == 1:
                        self.r1_writes.append((self.n - 1, v))
                elif op == 0x19:
                    rt, rs = (word >> 16) & 0x1F, (word >> 21) & 0x1F
                    if word & 1:                      # ld.w: zext16
                        off = ((word >> 1) & 0x7FFF) << 1
                        self.r[rt] = \
                            self.mem.get(self.rd(rs) + off, 0) & 0xFFFF
                    elif word & 2:                    # ld.d: zext32
                        off = ((word >> 2) & 0x3FFF) << 2
                        self.r[rt] = self.mem.get(self.rd(rs) + off, 0)
                    else:                             # ld.q: raw 64
                        off = ((word >> 2) & 0x3FFF) << 2
                        lo = self.mem.get(self.rd(rs) + off, 0)
                        hi = self.mem.get(self.rd(rs) + off + 4, 0)
                        self.r[rt] = ((hi << 32) | lo) & MASK
                    self.load_log.append((self.n - 1, rt, self.rd(rs) + off))
                elif op == 0x1B:
                    rt, rs = (word >> 11) & 0x1F, (word >> 21) & 0x1F
                    off = (((word >> 16) & 0x1F) << 11) \
                        | (((word >> 2) & 0x1FF) << 2)
                    if rs == 0:
                        self.cr[off] = self.r[rt] & 0xFFFFFFFF
                        self.stores.append((off, self.r[rt] & 0xFFFFFFFF,
                                            "CR"))
                    else:
                        ea2 = (self.rd(rs) + off) & 0xFFFFFFFF
                        kind = "STACK" if self.r[1] - 0x40 <= ea2 < self.r[1] \
                            else "ABS"
                        self.mem[ea2] = self.r[rt] & 0xFFFFFFFF
                        self.stores.append((ea2, self.r[rt] & 0xFFFFFFFF,
                                            kind))
                elif op == 0x38:
                    self.eq = self.rd((word >> 21) & 0x1F) == \
                        self.rd((word >> 11) & 0x1F)
                elif op in (0x28, 0x29):
                    if not isinstance(self.pc, int):
                        return "UNSUPPORTED_branch_in_payload"
                    imm = word & 0xFFFF
                    if imm & 0x8000:
                        imm -= 0x10000
                    cond = self.eq if (word >> 16) & 0x1F == 0x0A else False
                    if (cond if op == 0x28 else not cond):
                        self.taken.append((self.pc, op,
                                           (word >> 16) & 0x1F, cond))
                        nxt = self.pc + imm
                elif op == 0x25:
                    is_call = not word & 0x01000000
                    if is_call:                          # call: LINKS
                        self.csr0xbc = (ea + 4) & MASK
                        self.links.append((ea, "call"))
                    tgt = ea + irisc_dis.s24(word) * 4
                    if is_call and tgt == M2P_L:
                        # THE m2' DIRECT-POST call: record the args,
                        # clobber the T1 set with garbage (the
                        # re-establish words after the call are
                        # LOAD-BEARING), preserve r1/r2/r6/r12-r16/
                        # r17-r23 — and CONTINUE at the resume.
                        self.m2p.append((ea, self.r[4], self.r[5],
                                        self.r[6]))
                        self.events.append(("call", ea))
                        for reg in TestS2StubV5NSim.CALL_CLOBBER:
                            self.r[reg] = (0xCCCC0000 + reg) & 0xFFFFFFFF
                        nxt = i + 1
                    else:
                        j = (tgt - STUB_L) // 4
                        if 0 <= j < len(self.ws) and tgt == STUB_L + 4 * j:
                            nxt = j
                        elif tgt == FN_A_L:
                            self.exit_ea = tgt
                            return "FN_A"
                        else:
                            self.exit_ea = tgt
                            return "EXIT_%08x" % tgt
                elif op == 0x3F and (word & 0x1FF) == 0x81:   # shl64.i
                    sh = (word >> 11) & 0x1F
                    rd = (word >> 16) & 0x1F
                    self.r[rd] = \
                        (self.rd((word >> 21) & 0x1F) << sh) & MASK
                    if rd == 1:
                        self.r1_writes.append((self.n - 1, self.r[rd]))
                elif op == 0x3F and (word & 0x1FF) == 0x25:
                    rs, rt = (word >> 21) & 0x1F, (word >> 11) & 0x1F
                    if rs == 0:
                        self.csr0xbc = (ea + 4) & MASK
                        self.links.append((ea, "jalr"))
                    nxt = ("ea", self.rd(rt))
                else:
                    return "UNSUPPORTED_op_%02x" % op
                self.pc = nxt
                if isinstance(nxt, int):
                    self.r12_trace.append((i, self.r.get(12, 0)))
            return "RUNAWAY"

    def ws(self):
        from build_s2 import stub_words
        return stub_words("B", version=19)

    def payload_words(self):
        import payload as pl
        return pl.payload_v5n()

    def test_sim_fallthrough_no_m2p_no_store_no_transfer(self):
        # non-magic frames NEVER reach the m2' block: the filter b_f
        # (w5, taken at latch FALSE) jumps straight to W_FAST -> FN_A.
        s = self.SimV5N(self.ws(), 4, magic=False, code=self.payload_words())
        self.assertEqual(s.run(), "FN_A")
        self.assertEqual(s.exit_ea, 0x98D964)
        self.assertEqual(s.m2p, [])                         # NO POST
        self.assertEqual(s.stores, [])
        self.assertEqual(s.pay_fetch, [])
        self.assertEqual(s.taken, [(5, 0x29, 0x0A, False)])
        self.assertEqual(s.r[1], self.R1E)
        self.assertEqual(s.r1_writes, [])

    def test_sim_magic_path_full_contract(self):
        # THE v5n exec path: prefix (echoes) -> m2' block (w9
        # w = zext32(p0) -> w10 w<<6 -> w11 X1 -> w12 buf -> w13 0
        # -> w14 THE DIRECT POST) -> r4 restore -> r12 rebuild ->
        # payload ptr/r3 rebuild -> transfer -> p0 (= w: addi
        # r2,r2,0x-7470, P0_SAFE) + p1..p3 (S2OK, return) IN-PLACE
        # from the landing -> exit to 0x8E4380 (the fn body resume).
        # CR contract: 0x2380=MAGIC16, 0x2384=N, 0x2388=S2OK,
        # 0x238C=0; exactly ONE direct call with the EXACT
        # signature; r1 NEVER written; ZERO non-CR writes.
        code = self.payload_words()
        s = self.SimV5N(self.ws(), 4, code=code)
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.exit_ea, self.RA_LIVE)
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                         (0x5332, 4, 0x53324F4B, 0))
        self.assertEqual(len(s.m2p), 1)
        ea, a4, a5, a6 = s.m2p[0]
        self.assertEqual(ea, self.STUB_LIVE + 4 * 14)       # w14
        self.assertEqual(a4, 0x8FC010A2E400)                # X1 EXACT
        self.assertEqual(a5, self.R1E + 0xB0)               # buf == r1+0xb0
        self.assertEqual(a6, 0)                             # status = 0
        self.assertEqual(s.r[1], self.R1E)                  # NOT touched
        self.assertEqual(s.r1_writes, [])
        self.assertEqual(s.r[4], 0)                         # restored (w15)
        self.assertEqual(s.r[3], self.RA_LIVE)              # rebuilt (w18/19)
        self.assertEqual(s.r[11], self.R1E + 0xAC)          # rebuilt (w17)
        # p0 EXECUTED in place: addi r2,r2,0x-7470 (imm16 0x8B90,
        # sign-extended per the slaspec/sim model)
        self.assertEqual(s.r[2], (0x40000000 - 0x7470) & 0xFFFFFFFF)
        for reg in self.SAVED_REGS:
            self.assertEqual(s.r[reg], 0xDEAD0000 + reg,
                             f"r{reg} touched (call must preserve)")
        self.assertEqual(s.taken, [])
        kinds = {k for _, _, k in s.stores}
        self.assertEqual(kinds, {"CR"})
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0xAC + 4 * i for i in range(4)])

    def test_sim_post_precedes_payload(self):
        # protocol order: THE DIRECT POST fires BEFORE the payload
        # executes — the exfil'd buf bytes are the PRISTINE TRIG
        # frame (S2OK goes to CR space, not to buf).
        code = self.payload_words()
        s = self.SimV5N(self.ws(), 4, code=code)
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(len(s.m2p), 1)
        call_pos = s.events.index(("call", s.m2p[0][0]))
        fetch_pos = s.events.index(("fetch", s.pay_fetch[0]))
        self.assertLess(call_pos, fetch_pos)

    def test_sim_r12_chain(self):
        # THE r12 chain: w2 loads the frame-magic 0x5332 -> the call
        # does NOT write r12 (T1 G-a) -> w16 rebuilds the lo16 (the
        # S2OK-lo word) -> at p1 r12 == 0x00004F4B -> p1 inserts the
        # hi16 -> S2OK EXACT in CR 0x2388.
        code = self.payload_words()
        s = self.SimV5N(self.ws(), 4, code=code)
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        tr = dict(s.r12_trace)
        self.assertEqual(tr[2], 0x5332)                 # w2: frame magic
        self.assertEqual(tr[14], 0x5332)                # call: r12 NOT written
        self.assertEqual(tr[16], 0x4F4B)                # w16: S2OK-lo rebuild
        self.assertEqual(s.r[12], 0x53324F4B)           # after p1
        self.assertEqual(s.cr[0x2388], 0x53324F4B)      # EXACT

    def test_sim_r12_rebuild_load_bearing(self):
        # NEGATIVE CONTROL: w16 neutralized (no r12 write) -> p1
        # keeps the w2 magic in the LO half -> CR 0x2388 =
        # 0x53325332, NOT S2OK (the test MUST catch this).
        ws = self.ws()
        ws[16] = enc.addi(0, 0, 0)                      # no-op at w16
        s = self.SimV5N(ws, 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.r[12], 0x53325332)
        self.assertEqual(s.cr[0x2388], 0x53325332)

    def test_sim_call_clobber_reestablished(self):
        # THE load-bearing discipline: the model CLOBBERS the T1 set
        # (r3/r4/r5/r7-r11) with garbage AT the call — the run still
        # lands the payload transfer on r1+0xac and the exit on
        # 0x8E4380 ONLY because w15/w17/w18/w19 re-establish them
        # AFTER the call.  csr0xbc is DIRTY after the call (the call
        # linked it to the w15 resume 0xB8D78C) — documented SAFE
        # (the post-resume body path re-links via its own
        # `call 0x0e4424' before any read; the early-exit path reads
        # only the outer [R+4] — the v5m blob-scan verdict carries
        # over: the same resume body).
        code = self.payload_words()
        s = self.SimV5N(self.ws(), 4, code=code)
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.links, [(self.STUB_LIVE + 4 * 14, "call")])
        self.assertEqual(s.csr0xbc, 0xB8D78C)           # w15 live resume
        for garbage_reg, rebuilt in ((3, self.RA_LIVE), (4, 0),
                                     (11, self.R1E + 0xAC)):
            self.assertNotEqual(s.r[garbage_reg],
                                (0xCCCC0000 + garbage_reg) & 0xFFFFFFFF)
            self.assertEqual(s.r[garbage_reg], rebuilt)

    def test_sim_exit_is_callsite_resume_all_16_sp_bases(self):
        # the SAME FIXED word list (stub AND payload) at EVERY SP
        # base (SP-init 0x7d1ff8 + k*0x2000, all 16 cores): the
        # direct call signature tracks the base (X1 is
        # base-INDEPENDENT; buf == base+0xb0; status = 0), the C1
        # signal lands everywhere, the exit is the ABSOLUTE resume
        # everywhere, r1 stays the UNPOPPED fn frame.
        import payload as pl
        fixed_stub, fixed_payload = self.ws(), pl.payload_v5n()
        for k in range(16):
            base = 0x7D1FF8 + k * 0x2000
            s = self.SimV5N(fixed_stub, 4, code=fixed_payload, r1=base)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"base 0x{base:x}")
            self.assertEqual(s.exit_ea, self.RA_LIVE, f"base 0x{base:x}")
            self.assertEqual(s.cr[0x2388], 0x53324F4B, f"base 0x{base:x}")
            self.assertEqual(len(s.m2p), 1, f"base 0x{base:x}")
            self.assertEqual(s.m2p[0][1], 0x8FC010A2E400,
                             f"base 0x{base:x}: X1")
            self.assertEqual(s.m2p[0][2], base + 0xB0, f"base 0x{base:x}: buf")
            self.assertEqual(s.m2p[0][3], 0, f"base 0x{base:x}: status")
            self.assertEqual(s.r[1], base, f"base 0x{base:x}: NOT popped")
            for reg in self.SAVED_REGS:
                self.assertEqual(s.r[reg], 0xDEAD0000 + reg,
                                 f"base 0x{base:x}: r{reg} touched")
            self.assertEqual(s.pay_fetch, [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")

    def test_sim_s2ok_exact(self):
        s = self.SimV5N(self.ws(), 4, code=self.payload_words())
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.r[12], 0x53324F4B)
        self.assertEqual(s.cr[0x2388], 0x53324F4B)

    def test_sim_zero_stack_writes_all_paths(self):
        for magic in (True, False):
            s = self.SimV5N(self.ws(), 4, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.RA_LIVE),
                            f"magic={magic}: unexpected {out}")
            for ea, v, k in s.stores:
                self.assertNotIn(k, ("STACK", "ABS"),
                                 f"magic={magic}: non-CR write 0x{ea:x}")

    def test_sim_branch_inventory_all_paths(self):
        for magic, want in ((True, []), (False, [(5, 0x29, 0x0A, False)])):
            s = self.SimV5N(self.ws(), 4, magic=magic, code=self.payload_words())
            out = s.run()
            self.assertTrue(out in ("FN_A", "EXIT_%08x" % self.RA_LIVE),
                            f"magic={magic}: {out}")
            self.assertEqual(s.taken, want, f"magic={magic}")

    def test_sim_trig_frame_bytes_drive_the_path(self):
        # THE TRIG frame (the exact 36B host bytes) drives the full
        # path — unpack N / MAGIC16 / the 4 payload words FROM THE
        # FRAME BYTES, run at several bases: everywhere the direct
        # call fires with X1 = (0x8FC0<<32)|(frame_p0<<6) and the
        # exit lands on the call-site resume.
        import payload as pl
        frame = pl.trig_v5n()
        b = bytes.fromhex(frame.hex())
        n = struct.unpack(">H", b[0xC:0xE])[0]
        magic16 = struct.unpack(">H", b[0x12:0x14])[0]
        words = list(struct.unpack(">4I", b[0x14:0x24]))
        self.assertEqual((n, magic16), (4, 0x5332))
        for base in (self.R1E, 0x7D1FF8, 0x7D9FF8, 0x7EFFF8):
            s = self.SimV5N(self.ws(), n, code=words, r1=base)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"base 0x{base:x}")
            self.assertEqual((s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                             (4, 0x53324F4B, 0), f"base 0x{base:x}")
            self.assertEqual(len(s.m2p), 1, f"base 0x{base:x}")
            self.assertEqual(s.m2p[0][1], (0x8FC0 << 32) | (words[0] << 6),
                             f"base 0x{base:x}: X1 from frame p0")
            self.assertEqual(s.m2p[0][2], base + 0xB0, f"base 0x{base:x}")
            self.assertEqual(s.r[1], base, f"base 0x{base:x}: NOT popped")
            self.assertEqual(s.pay_fetch, [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")


class TestS2StubV5OSim(TestS2StubV5NSim):
    # v5o per-path sim: the v5n model VERBATIM (the stub words are
    # byte-exact v5n — w-independent m2') with the TRIG v5o frame:
    # p0 = w = 0x428B80 (in_mb0) -> X1 = 0x8FC010A2E000.  Only the
    # frame-dependent expectations change.
    W = 0x428B80
    X1 = 0x8FC010A2E000

    def ws(self):
        from build_s2 import stub_words
        return stub_words("B", version=20)

    def payload_words(self):
        import payload as pl
        return pl.payload_v5n(self.W)

    def test_sim_magic_path_full_contract(self):
        code = self.payload_words()
        s = self.SimV5N(self.ws(), 4, code=code)
        self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE)
        self.assertEqual(s.exit_ea, self.RA_LIVE)
        self.assertEqual((s.cr[0x2380], s.cr[0x2384], s.cr[0x2388],
                          s.cr[0x238C]), (0x5332, 4, 0x53324F4B, 0))
        self.assertEqual(len(s.m2p), 1)
        ea, a4, a5, a6 = s.m2p[0]
        self.assertEqual(ea, self.STUB_LIVE + 4 * 14)       # w14
        self.assertEqual(a4, self.X1)                       # X1 EXACT (in_mb0)
        self.assertEqual(a5, self.R1E + 0xB0)               # buf == r1+0xb0
        self.assertEqual(a6, 0)                             # status = 0
        self.assertEqual(s.r[1], self.R1E)                  # NOT touched
        self.assertEqual(s.r1_writes, [])
        self.assertEqual(s.r[4], 0)                         # restored (w15)
        self.assertEqual(s.r[3], self.RA_LIVE)              # rebuilt (w18/19)
        self.assertEqual(s.r[11], self.R1E + 0xAC)          # rebuilt (w17)
        # p0 EXECUTED in place: addi r2,r2,0x-7480 (imm16 0x8B80,
        # sign-extended per the slaspec/sim model)
        self.assertEqual(s.r[2], (0x40000000 - 0x7480) & 0xFFFFFFFF)
        for reg in self.SAVED_REGS:
            self.assertEqual(s.r[reg], 0xDEAD0000 + reg,
                             f"r{reg} touched (call must preserve)")
        self.assertEqual(s.taken, [])
        kinds = {k for _, _, k in s.stores}
        self.assertEqual(kinds, {"CR"})
        self.assertEqual(s.pay_fetch,
                         [self.R1E + 0xAC + 4 * i for i in range(4)])

    def test_sim_trig_frame_bytes_drive_the_path(self):
        # override: THE v5o frame (not the default v5n frame) drives the
        # path — X1 from frame p0 == 0x8FC010A2E000 everywhere
        import payload as pl
        frame = pl.trig_v5n(self.W)
        b = bytes.fromhex(frame.hex())
        n = struct.unpack(">H", b[0xC:0xE])[0]
        magic16 = struct.unpack(">H", b[0x12:0x14])[0]
        words = list(struct.unpack(">4I", b[0x14:0x24]))
        self.assertEqual((n, magic16), (4, 0x5332))
        self.assertEqual(words[0], self.W)
        for base in (self.R1E, 0x7D1FF8, 0x7D9FF8, 0x7EFFF8):
            s = self.SimV5N(self.ws(), n, code=words, r1=base)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"base 0x{base:x}")
            self.assertEqual((s.cr[0x2384], s.cr[0x2388], s.cr[0x238C]),
                             (4, 0x53324F4B, 0), f"base 0x{base:x}")
            self.assertEqual(len(s.m2p), 1, f"base 0x{base:x}")
            self.assertEqual(s.m2p[0][1], self.X1,
                             f"base 0x{base:x}: X1 from frame p0")
            self.assertEqual(s.m2p[0][2], base + 0xB0, f"base 0x{base:x}")
            self.assertEqual(s.r[1], base, f"base 0x{base:x}: NOT popped")
            self.assertEqual(s.pay_fetch,
                             [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")

    def test_sim_exit_is_callsite_resume_all_16_sp_bases(self):
        import payload as pl
        fixed_stub, fixed_payload = self.ws(), pl.payload_v5n(self.W)
        for k in range(16):
            base = 0x7D1FF8 + k * 0x2000
            s = self.SimV5N(fixed_stub, 4, code=fixed_payload, r1=base)
            self.assertEqual(s.run(), "EXIT_%08x" % self.RA_LIVE,
                             f"base 0x{base:x}")
            self.assertEqual(s.exit_ea, self.RA_LIVE, f"base 0x{base:x}")
            self.assertEqual(s.cr[0x2388], 0x53324F4B, f"base 0x{base:x}")
            self.assertEqual(len(s.m2p), 1, f"base 0x{base:x}")
            self.assertEqual(s.m2p[0][1], self.X1, f"base 0x{base:x}: X1")
            self.assertEqual(s.m2p[0][2], base + 0xB0, f"base 0x{base:x}: buf")
            self.assertEqual(s.m2p[0][3], 0, f"base 0x{base:x}: status")
            self.assertEqual(s.r[1], base, f"base 0x{base:x}: NOT popped")
            for reg in self.SAVED_REGS:
                self.assertEqual(s.r[reg], 0xDEAD0000 + reg,
                                 f"base 0x{base:x}: r{reg} touched")
            self.assertEqual(s.pay_fetch,
                             [base + 0xAC + 4 * i for i in range(4)],
                             f"base 0x{base:x}")


@pytest.mark.slow
class TestS2BuildV5E(unittest.TestCase):
    def test_build_v5e_image(self):
        buf = built(10)
        img = mlxfwutil.Image(buf, "s2v5e")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D764), 0xA40A0018)  # filter b_f.cc0A -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # echo N
        self.assertEqual(w(0x38D774), 0x703F0FC2)  # push
        self.assertEqual(w(0x38D778), 0x6C201802)  # saves (v5d-verbatim)
        self.assertEqual(w(0x38D77C), 0x200C0002)  # L2: set3 r12,zero,2
        self.assertEqual(w(0x38D780), 0xE1A06002)  # L2: cmp38 N vs 2
        self.assertEqual(w(0x38D784), 0xA00A000E)  # L2: b_t.cc0A +14 -> TAIL
        self.assertEqual(w(0x38D788), 0x002C0020)  # dst-init (v5d-verbatim)
        self.assertEqual(w(0x38D78C), 0x65630002)  # pair ld.d
        self.assertEqual(w(0x38D790), 0x6D801802)  # pair st.d
        self.assertEqual(w(0x38D794), 0x200C0003)  # L3: set3 r12,zero,3
        self.assertEqual(w(0x38D798), 0xE1A06002)  # L3: cmp38 N vs 3
        self.assertEqual(w(0x38D79C), 0xA00A0008)  # L3: b_t.cc0A +8 -> TAIL
        self.assertEqual(w(0x38D7A0), 0x002C0020)  # dst RE-INIT
        self.assertEqual(w(0x38D7A4), 0x65630002)  # loop head (v5d-verbatim)
        self.assertEqual(w(0x38D7B8), 0xA400FFFB)  # back-edge -5
        self.assertEqual(w(0x38D7BC), 0x6C046B8E)  # TAIL marker st.d r13,0,0x238c
        self.assertEqual(w(0x38D7C0), 0x00210040)  # pop
        self.assertEqual(w(0x38D7C4), 0x95F80068)  # W_FAST jump FN_A (last)
        for a in range(STUB + 4 * 30, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5e_bakes_card_guids(self):
        buf = built(10)
        img = mlxfwutil.Image(buf, "s2v5e")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5e_diff_vs_v5d_confined_to_stub_zone(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone (v5e re-lays-out the zone after
        # the shared prefix; nothing outside 0x38d750-0x38d7d8 moves).
        v5d = built(9)
        v5e = built(10)
        id5, ie = mlxfwutil.Image(v5d, "v5d"), mlxfwutil.Image(v5e, "v5e")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ie.section_data(ie.find_entry(toc, t)),
                             id5.section_data(id5.find_entry(toc, t)))
        cd = decrc(id5.section_data(id5.find_entry("ITOC", 0x03)))
        ce = decrc(ie.section_data(ie.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", cd, DETOUR_DC)[0],
                         struct.unpack_from(">I", ce, DETOUR_DC)[0])
        diff = [a for a in range(0, len(cd), 4)
                if struct.unpack_from(">I", cd, a)[0]
                != struct.unpack_from(">I", ce, a)[0]]
        self.assertTrue(diff)
        for a in diff:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        ee = ie.find_entry("ITOC", 0x03)
        ent_lo = ie.itoc_off + 32 + ee.index * 32
        allowed = set(range(ee.addr, ee.addr + ee.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5d)) if v5d[i] != v5e[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5e_deterministic(self):
        b1 = build(det(1), version=10)
        b2 = build(det(2), version=10)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5F(unittest.TestCase):
    def test_build_v5f_image(self):
        buf = built(11)
        img = mlxfwutil.Image(buf, "s2v5f")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D764), 0xA40A001A)  # filter b_f.cc0A -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # echo N
        self.assertEqual(w(0x38D774), 0x703F0FC2)  # push
        self.assertEqual(w(0x38D778), 0x6C201802)  # saves (v5d-verbatim)
        self.assertEqual(w(0x38D77C), 0x200C0002)  # L2: set3 r12,zero,2
        self.assertEqual(w(0x38D780), 0xE1A06002)  # L2: cmp38 N vs 2
        self.assertEqual(w(0x38D784), 0xA40A0002)  # L2: b_f.cc0A +2 skip
        self.assertEqual(w(0x38D788), 0x9500000F)  # L2: jump +15 -> TAIL
        self.assertEqual(w(0x38D78C), 0x002C0020)  # dst-init (v5d-verbatim)
        self.assertEqual(w(0x38D790), 0x65630002)  # pair ld.d
        self.assertEqual(w(0x38D794), 0x6D801802)  # pair st.d
        self.assertEqual(w(0x38D798), 0x200C0003)  # L3: set3 r12,zero,3
        self.assertEqual(w(0x38D79C), 0xE1A06002)  # L3: cmp38 N vs 3
        self.assertEqual(w(0x38D7A0), 0xA40A0002)  # L3: b_f.cc0A +2 skip
        self.assertEqual(w(0x38D7A4), 0x95000008)  # L3: jump +8 -> TAIL
        self.assertEqual(w(0x38D7A8), 0x002C0020)  # dst RE-INIT
        self.assertEqual(w(0x38D7AC), 0x65630002)  # loop head (v5d-verbatim)
        self.assertEqual(w(0x38D7C0), 0xA400FFFB)  # back-edge -5
        self.assertEqual(w(0x38D7C4), 0x6C046B8E)  # TAIL marker st.d r13,0,0x238c
        self.assertEqual(w(0x38D7C8), 0x00210040)  # pop
        self.assertEqual(w(0x38D7CC), 0x95F80066)  # W_FAST jump FN_A (last)
        for a in range(STUB + 4 * 32, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5f_bakes_card_guids(self):
        buf = built(11)
        img = mlxfwutil.Image(buf, "s2v5f")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5f_diff_vs_v5e_confined_to_stub_zone(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone (v5f re-lays-out the zone after
        # the shared prefix; nothing outside 0x38d750-0x38d7d8 moves).
        v5e = built(10)
        v5f = built(11)
        ie, if_ = mlxfwutil.Image(v5e, "v5e"), mlxfwutil.Image(v5f, "v5f")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(if_.section_data(if_.find_entry(toc, t)),
                             ie.section_data(ie.find_entry(toc, t)))
        ce = decrc(ie.section_data(ie.find_entry("ITOC", 0x03)))
        cf = decrc(if_.section_data(if_.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", ce, DETOUR_DC)[0],
                         struct.unpack_from(">I", cf, DETOUR_DC)[0])
        diff = [a for a in range(0, len(ce), 4)
                if struct.unpack_from(">I", ce, a)[0]
                != struct.unpack_from(">I", cf, a)[0]]
        self.assertTrue(diff)
        for a in diff:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        ef = if_.find_entry("ITOC", 0x03)
        ent_lo = if_.itoc_off + 32 + ef.index * 32
        allowed = set(range(ef.addr, ef.addr + ef.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5e)) if v5e[i] != v5f[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5f_deterministic(self):
        b1 = build(det(1), version=11)
        b2 = build(det(2), version=11)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5G(unittest.TestCase):
    def test_build_v5g_image(self):
        buf = built(12)
        img = mlxfwutil.Image(buf, "s2v5g")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D764), 0xA40A0011)  # filter b_f.cc0A -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # echo N
        self.assertEqual(w(0x38D774), 0x703F0FC2)  # push
        self.assertEqual(w(0x38D778), 0x6C201802)  # saves (v5b-verbatim)
        self.assertEqual(w(0x38D77C), 0x002C0020)  # dst-init (v5d-verbatim)
        self.assertEqual(w(0x38D780), 0x65630002)  # pair ld.d
        self.assertEqual(w(0x38D784), 0x6D801802)  # pair st.d
        self.assertEqual(w(0x38D788), 0x65630002)  # loop head (v5d-verbatim)
        self.assertEqual(w(0x38D79C), 0xA400FFFB)  # back-edge -5
        self.assertEqual(w(0x38D7A0), 0x6C046B8E)  # TAIL marker st.d r13,0,0x238c
        self.assertEqual(w(0x38D7A4), 0x00210040)  # pop
        self.assertEqual(w(0x38D7A8), 0x95F8006F)  # W_FAST jump FN_A (last)
        for a in range(STUB + 4 * 23, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5g_bakes_card_guids(self):
        buf = built(12)
        img = mlxfwutil.Image(buf, "s2v5g")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5g_diff_vs_v5f_confined_to_stub_zone(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone (v5g re-lays-out the zone
        # after the shared prefix; nothing outside 0x38d750-0x38d7d8
        # moves).
        v5f = built(11)
        v5g = built(12)
        if_, ig = mlxfwutil.Image(v5f, "v5f"), mlxfwutil.Image(v5g, "v5g")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ig.section_data(ig.find_entry(toc, t)),
                             if_.section_data(if_.find_entry(toc, t)))
        cf = decrc(if_.section_data(if_.find_entry("ITOC", 0x03)))
        cg = decrc(ig.section_data(ig.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", cf, DETOUR_DC)[0],
                         struct.unpack_from(">I", cg, DETOUR_DC)[0])
        diff = [a for a in range(0, len(cf), 4)
                if struct.unpack_from(">I", cf, a)[0]
                != struct.unpack_from(">I", cg, a)[0]]
        self.assertTrue(diff)
        for a in diff:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        eg = ig.find_entry("ITOC", 0x03)
        ent_lo = ig.itoc_off + 32 + eg.index * 32
        allowed = set(range(eg.addr, eg.addr + eg.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5f)) if v5f[i] != v5g[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5g_deterministic(self):
        b1 = build(det(1), version=12)
        b2 = build(det(2), version=12)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5H(unittest.TestCase):
    def test_build_v5h_image(self):
        buf = built(13)
        img = mlxfwutil.Image(buf, "s2v5h")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D764), 0xA40A0010)  # filter b_f.cc0A -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # echo N
        self.assertEqual(w(0x38D774), 0x703F0FC2)  # push
        self.assertEqual(w(0x38D778), 0x002C0020)  # dst-init (save slot reused)
        self.assertNotEqual(w(0x38D778), 0x6C201802)  # THE save word: gone
        self.assertEqual(w(0x38D77C), 0x65630002)  # pair ld.d
        self.assertEqual(w(0x38D780), 0x6D801802)  # pair st.d
        self.assertEqual(w(0x38D784), 0x65630002)  # loop head (v5d-verbatim)
        self.assertEqual(w(0x38D798), 0xA400FFFB)  # back-edge -5
        self.assertEqual(w(0x38D79C), 0x6C046B8E)  # TAIL marker st.d r13,0,0x238c
        self.assertEqual(w(0x38D7A0), 0x00210040)  # pop
        self.assertEqual(w(0x38D7A4), 0x95F80070)  # W_FAST jump FN_A (last)
        for a in range(STUB + 4 * 22, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5h_bakes_card_guids(self):
        buf = built(13)
        img = mlxfwutil.Image(buf, "s2v5h")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5h_diff_vs_v5g_confined_to_stub_zone(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone (v5h re-lays-out the zone
        # after the shared prefix; nothing outside 0x38d750-0x38d7d8
        # moves).
        v5g = built(12)
        v5h = built(13)
        ig, ih = mlxfwutil.Image(v5g, "v5g"), mlxfwutil.Image(v5h, "v5h")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ih.section_data(ih.find_entry(toc, t)),
                             ig.section_data(ig.find_entry(toc, t)))
        cg = decrc(ig.section_data(ig.find_entry("ITOC", 0x03)))
        ch = decrc(ih.section_data(ih.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", cg, DETOUR_DC)[0],
                         struct.unpack_from(">I", ch, DETOUR_DC)[0])
        diff = [a for a in range(0, len(cg), 4)
                if struct.unpack_from(">I", cg, a)[0]
                != struct.unpack_from(">I", ch, a)[0]]
        self.assertTrue(diff)
        for a in diff:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        eh = ih.find_entry("ITOC", 0x03)
        ent_lo = ih.itoc_off + 32 + eh.index * 32
        allowed = set(range(eh.addr, eh.addr + eh.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5g)) if v5g[i] != v5h[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5h_deterministic(self):
        b1 = build(det(1), version=13)
        b2 = build(det(2), version=13)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5I(unittest.TestCase):
    def test_build_v5i_image(self):
        buf = built(14)
        img = mlxfwutil.Image(buf, "s2v5i")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D764), 0xA40A0009)  # filter b_f.cc0A -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # echo N
        self.assertEqual(w(0x38D774), 0x703F0FC2)  # push
        self.assertEqual(w(0x38D778), 0x200CA5A5)  # neutral set3 r12,zero,0xA5A5
        self.assertEqual(w(0x38D77C), 0x6C206032)  # neutral st.d r12,r1,0x30
        self.assertEqual(w(0x38D780), 0x6C046B8E)  # TAIL marker st.d r13,0,0x238c
        self.assertEqual(w(0x38D784), 0x00210040)  # pop
        self.assertEqual(w(0x38D788), 0x95F80077)  # W_FAST jump FN_A (last)
        # the copy-block words of the v5h layout are GONE from the zone
        for a in (0x38D778,):                       # was dst-init in v5h
            self.assertNotEqual(w(a), 0x002C0020)
        self.assertNotEqual(w(0x38D77C), 0x6D801802)  # pair st.d: gone
        for a in range(STUB + 4 * 15, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5i_bakes_card_guids(self):
        buf = built(14)
        img = mlxfwutil.Image(buf, "s2v5i")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5i_diff_vs_v5h_confined_to_stub_zone(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone (v5i re-lays-out the zone
        # after the shared prefix; nothing outside 0x38d750-0x38d7d8
        # moves).
        v5h = built(13)
        v5i = built(14)
        ih, ii = mlxfwutil.Image(v5h, "v5h"), mlxfwutil.Image(v5i, "v5i")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ii.section_data(ii.find_entry(toc, t)),
                             ih.section_data(ih.find_entry(toc, t)))
        ch = decrc(ih.section_data(ih.find_entry("ITOC", 0x03)))
        ci = decrc(ii.section_data(ii.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", ch, DETOUR_DC)[0],
                         struct.unpack_from(">I", ci, DETOUR_DC)[0])
        diff = [a for a in range(0, len(ch), 4)
                if struct.unpack_from(">I", ch, a)[0]
                != struct.unpack_from(">I", ci, a)[0]]
        self.assertTrue(diff)
        for a in diff:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        ei = ii.find_entry("ITOC", 0x03)
        ent_lo = ii.itoc_off + 32 + ei.index * 32
        allowed = set(range(ei.addr, ei.addr + ei.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5h)) if v5h[i] != v5i[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5i_deterministic(self):
        b1 = build(det(1), version=14)
        b2 = build(det(2), version=14)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5J(unittest.TestCase):
    def test_build_v5j_image(self):
        buf = built(15)
        img = mlxfwutil.Image(buf, "s2v5j")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # csr.r r3,csr0xbc
        self.assertEqual(w(0x38D754), 0x002B00AC)  # addi r11,r1,0xac (w1)
        self.assertEqual(w(0x38D764), 0xA40A0006)  # filter b_f.cc0A +6 -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # echo N
        self.assertEqual(w(0x38D774), 0x002B00AC)  # w9: payload ptr re-establish
        self.assertEqual(w(0x38D778), 0xFD005825)  # w10: ret.r zero,r8,r11 (no-link, stock x3)
        self.assertEqual(w(0x38D77C), 0x95F8007A)  # W_FAST jump FN_A (last)
        # the v5i frame words are GONE from the zone (push/neutral/TAIL/pop)
        self.assertNotEqual(w(0x38D778), 0x703F0FC2)         # push: gone
        self.assertNotEqual(w(0x38D780), 0x6C206032)         # neutral: gone
        self.assertNotEqual(w(0x38D784), 0x00210040)         # pop: gone
        for a in range(STUB + 4 * 12, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5j_bakes_card_guids(self):
        buf = built(15)
        img = mlxfwutil.Image(buf, "s2v5j")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5j_diff_vs_v5i_confined_to_stub_zone(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone (v5j re-lays-out the zone
        # after the shared prefix; nothing outside 0x38d750-0x38d7d8
        # moves).
        v5i = built(14)
        v5j = built(15)
        ii, ij = mlxfwutil.Image(v5i, "v5i"), mlxfwutil.Image(v5j, "v5j")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ij.section_data(ij.find_entry(toc, t)),
                             ii.section_data(ii.find_entry(toc, t)))
        ci = decrc(ii.section_data(ii.find_entry("ITOC", 0x03)))
        cj = decrc(ij.section_data(ij.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", ci, DETOUR_DC)[0],
                         struct.unpack_from(">I", cj, DETOUR_DC)[0])
        diff = [a for a in range(0, len(ci), 4)
                if struct.unpack_from(">I", ci, a)[0]
                != struct.unpack_from(">I", cj, a)[0]]
        self.assertTrue(diff)
        for a in diff:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        ej = ij.find_entry("ITOC", 0x03)
        ent_lo = ij.itoc_off + 32 + ej.index * 32
        allowed = set(range(ej.addr, ej.addr + ej.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5i)) if v5i[i] != v5j[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5j_deterministic(self):
        b1 = build(det(1), version=15)
        b2 = build(det(2), version=15)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5K(unittest.TestCase):
    def test_build_v5k_image(self):
        buf = built(16)
        img = mlxfwutil.Image(buf, "s2v5k")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # w0 csr.r r3,csr0xbc
        self.assertEqual(w(0x38D754), 0x002B00AC)  # w1 addi r11,r1,0xac
        self.assertEqual(w(0x38D764), 0xA40A0012)  # w5 filter b_f.cc0A +18 -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # w8 echo N
        self.assertEqual(w(0x38D774), 0x002B00AC)  # w9 payload ptr re-establish
        self.assertEqual(w(0x38D778), 0x2003D784)  # w10 set3 r3,zero,0xd784 (replica lo)
        self.assertEqual(w(0x38D77C), 0x246300B8)  # w11 set2 r3,r3,0xb8 (replica hi)
        self.assertEqual(w(0x38D780), 0xFD005825)  # w12 ret.r zero,r8,r11 (no-link)
        self.assertEqual(w(0x38D784), 0x643700DE)  # w13 replica: ld.d r23,r1,0xdc
        self.assertEqual(w(0x38D79C), 0x643100F6)  # w19 replica: ld.d r17,r1,0xf4
        self.assertEqual(w(0x38D7A0), 0x002100F8)  # w20 replica: pop (stock @0x0e4304)
        self.assertEqual(w(0x38D7A4), 0x64230006)  # w21 replica: ld.d r3,r1,0x4
        self.assertEqual(w(0x38D7A8), 0xFD001825)  # w22 replica: the fn's own ret.r
        self.assertEqual(w(0x38D7AC), 0x95F8006E)  # w23 W_FAST jump FN_A (last)
        for a in range(STUB + 4 * 24, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5k_replica_byte_exact_vs_stock(self):
        # image-level byte-exactness: the BUILT image's replica words
        # (0x38d784..0x38d7ac) equal the STOCK epilogue words
        # @0x0e42e8..0x0e430c — read independently from the base image
        # AND cross-checked against the census blob (10/10 words).
        v5k = built(16)
        ik = mlxfwutil.Image(v5k, "s2v5k")
        ck = decrc(ik.section_data(ik.find_entry("ITOC", 0x03)))
        ib = mlxfwutil.Image(BASE.read_bytes(), "base")
        cb = decrc(ib.section_data(ib.find_entry("ITOC", 0x03)))
        for i in range(10):
            got = struct.unpack_from(">I", ck, STUB + 4 * (13 + i))[0]
            stock = struct.unpack_from(">I", cb, 0x0E42E8 + 4 * i)[0]
            self.assertEqual(got, stock, f"replica word {i} drift")
        blob = REPO / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        b = blob.read_bytes()
        for i in range(10):
            self.assertEqual(struct.unpack_from(">I", b, 0x0E42E8 + 4 * i)[0],
                             struct.unpack_from(">I", ck, STUB + 4 * (13 + i))[0],
                             f"replica word {i} vs blob drift")

    def test_build_v5k_bakes_card_guids(self):
        buf = built(16)
        img = mlxfwutil.Image(buf, "s2v5k")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5k_diff_vs_v5j_confined_to_stub_zone(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone (v5k rev.2 adds the r3-build
        # pair + the 10-word replica and retargets two immediates;
        # nothing outside 0x38d750-0x38d7d8 moves).
        v5j = built(15)
        v5k = built(16)
        ij, ik = mlxfwutil.Image(v5j, "v5j"), mlxfwutil.Image(v5k, "v5k")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(ik.section_data(ik.find_entry(toc, t)),
                             ij.section_data(ij.find_entry(toc, t)))
        cj = decrc(ij.section_data(ij.find_entry("ITOC", 0x03)))
        ck = decrc(ik.section_data(ik.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", cj, DETOUR_DC)[0],
                         struct.unpack_from(">I", ck, DETOUR_DC)[0])
        diff = [a for a in range(0, len(cj), 4)
                if struct.unpack_from(">I", cj, a)[0]
                != struct.unpack_from(">I", ck, a)[0]]
        self.assertTrue(diff)
        for a in diff:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        ek = ik.find_entry("ITOC", 0x03)
        ent_lo = ik.itoc_off + 32 + ek.index * 32
        allowed = set(range(ek.addr, ek.addr + ek.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5j)) if v5j[i] != v5k[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5k_deterministic(self):
        b1 = build(det(1), version=16)
        b2 = build(det(2), version=16)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5L(unittest.TestCase):
    def test_build_v5l_image(self):
        buf = built(17)
        img = mlxfwutil.Image(buf, "s2v5l")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # w0 csr.r r3,csr0xbc
        self.assertEqual(w(0x38D754), 0x002B00AC)  # w1 addi r11,r1,0xac
        self.assertEqual(w(0x38D764), 0xA40A0008)  # w5 filter b_f.cc0A +8 -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # w8 echo N
        self.assertEqual(w(0x38D774), 0x002B00AC)  # w9 payload ptr re-establish
        self.assertEqual(w(0x38D778), 0x20034380)  # w10 set3 r3,zero,0x4380 (resume lo)
        self.assertEqual(w(0x38D77C), 0x2463008E)  # w11 set2 r3,r3,0x8e (resume hi)
        self.assertEqual(w(0x38D780), 0xFD005825)  # w12 ret.r zero,r8,r11 (no-link)
        self.assertEqual(w(0x38D784), 0x95F80078)  # w13 W_FAST jump FN_A (last)
        for a in range(STUB + 4 * 14, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5l_no_replica_words_in_image(self):
        # image-level: NO replica word appears anywhere in the stub
        # zone (the v5k replica block 0x38d784..0x38d7ac is DELETED —
        # W_FAST moved back to 0x38d784; the tail is zeros).
        from build_s2 import REPLICA_WORDS
        v5l = built(17)
        img = mlxfwutil.Image(v5l, "s2v5l")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        zone = [struct.unpack_from(">I", code, a)[0]
                for a in range(STUB, STUB + 4 * 34, 4)]
        for w in REPLICA_WORDS:
            self.assertNotIn(w, zone, f"replica word 0x{w:08x} in stub zone")
        self.assertEqual(zone[14:], [0] * 20)               # tail zeros

    def test_build_v5l_bakes_card_guids(self):
        buf = built(17)
        img = mlxfwutil.Image(buf, "s2v5l")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5l_diff_vs_v5k_confined_to_stub_zone(self):
        # image-level: detour identical, GUID sections identical, code
        # diffs confined to the stub zone (v5l deletes the 10-word
        # replica and recomputes four immediates; nothing outside
        # 0x38d750-0x38d7d8 moves).
        v5k = built(16)
        v5l = built(17)
        ik, il = mlxfwutil.Image(v5k, "v5k"), mlxfwutil.Image(v5l, "v5l")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(il.section_data(il.find_entry(toc, t)),
                             ik.section_data(ik.find_entry(toc, t)))
        ck = decrc(ik.section_data(ik.find_entry("ITOC", 0x03)))
        cl = decrc(il.section_data(il.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", ck, DETOUR_DC)[0],
                         struct.unpack_from(">I", cl, DETOUR_DC)[0])
        diff = [a for a in range(0, len(ck), 4)
                if struct.unpack_from(">I", ck, a)[0]
                != struct.unpack_from(">I", cl, a)[0]]
        self.assertTrue(diff)
        for a in diff:
            self.assertTrue(0x38D750 <= a < 0x38D7D8,
                            f"word @0x{a:x} changed outside stub zone")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        el = il.find_entry("ITOC", 0x03)
        ent_lo = il.itoc_off + 32 + el.index * 32
        allowed = set(range(el.addr, el.addr + el.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5k)) if v5k[i] != v5l[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5l_deterministic(self):
        b1 = build(det(1), version=17)
        b2 = build(det(2), version=17)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5M(unittest.TestCase):
    # v5m (task-2, mode "B") image-level contracts: the burnt zone
    # carries the 21-word m2 stub at the exact offsets, the mode
    # plumbing rejects A/18 and B/<old> both ways, and the diff vs
    # v5l is confined to the stub-zone tail.
    def test_build_v5m_image(self):
        from build_s2 import stub_words
        buf = built(18)
        img = mlxfwutil.Image(buf, "s2v5m")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # w0 csr.r r3,csr0xbc
        self.assertEqual(w(0x38D754), 0x002B00AC)  # w1 addi r11,r1,0xac
        self.assertEqual(w(0x38D764), 0xA40A000F)  # w5 filter b_f.cc0A +15 -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # w8 echo N
        self.assertEqual(w(0x38D774), 0x00040000)  # w9 m2: addi r4,zero,0
        self.assertEqual(w(0x38D778), 0xFEC5B008)  # w10 m2: or r5,r22,r22
        self.assertEqual(w(0x38D77C), 0x642600AE)  # w11 m2: ld.d r6,r1,0xac
        self.assertEqual(w(0x38D780), 0x30C600FF)  # w12 m2: andmsk.hi r6,r6,0xff (golden)
        self.assertEqual(w(0x38D784), 0x002700B0)  # w13 m2: addi r7,r1,0xb0
        self.assertEqual(w(0x38D788), 0x94F7CBB1)  # w14 m2: call 0x18064c
        self.assertEqual(w(0x38D78C), 0x00040000)  # w15 restore r4=0
        self.assertEqual(w(0x38D790), 0x002B00AC)  # w16 payload ptr (post-call)
        self.assertEqual(w(0x38D794), 0x20034380)  # w17 set3 r3,zero,0x4380
        self.assertEqual(w(0x38D798), 0x2463008E)  # w18 set2 r3,r3,0x8e
        self.assertEqual(w(0x38D79C), 0xFD005825)  # w19 ret.r zero,r8,r11
        self.assertEqual(w(0x38D7A0), 0x95F80071)  # w20 W_FAST jump FN_A (last)
        # the whole zone == stub_words (bit-exact burn) + tail zeros
        ws = stub_words("B", version=18)
        self.assertEqual([w(STUB + 4 * i) for i in range(len(ws))], ws)
        for a in range(STUB + 4 * 21, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5m_mode_plumbing(self):
        # build() mode inference: version 18 defaults to mode "B" (the
        # CLI `build_s2.py OUT 18` works); an EXPLICIT mode="A" for 18
        # is rejected (v5m is mode-B-only), as is any explicit older
        # version with mode "B" (lineage hygiene, both directions).
        b1 = build(det(1), version=18)             # inferred mode B
        b2 = build(det(2), mode="B", version=18)   # explicit mode B
        self.assertEqual(b1, b2)
        with self.assertRaises(ValueError):
            build(det(3), mode="A", version=18)
        with self.assertRaises(ValueError):
            build(det(3), mode="B", version=17)

    def test_build_v5m_bakes_card_guids(self):
        buf = built(18)
        img = mlxfwutil.Image(buf, "s2v5m")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5m_diff_vs_v5l_tail_only(self):
        # THE diff-vs-v5l contract, image level: detour identical,
        # GUID sections identical, and the de-CRC code diff is EXACTLY
        # {w5 (the canonical immediate retarget)} U {w9..w20 (the m2
        # tail)} — the prefix w0-w4/w6-w8 is byte-identical and
        # NOTHING outside the stub zone moves.
        v5l = built(17)
        v5m = built(18)
        il, im = mlxfwutil.Image(v5l, "v5l"), mlxfwutil.Image(v5m, "v5m")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(im.section_data(im.find_entry(toc, t)),
                             il.section_data(il.find_entry(toc, t)))
        cl = decrc(il.section_data(il.find_entry("ITOC", 0x03)))
        cm = decrc(im.section_data(im.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", cl, DETOUR_DC)[0],
                         struct.unpack_from(">I", cm, DETOUR_DC)[0])
        diff = [a for a in range(0, len(cl), 4)
                if struct.unpack_from(">I", cl, a)[0]
                != struct.unpack_from(">I", cm, a)[0]]
        expected = {STUB + 4 * 5} | set(range(STUB + 4 * 9, STUB + 4 * 21, 4))
        self.assertEqual(set(diff), expected,
                         "diff vs v5l not confined to the stub-zone tail")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        em = im.find_entry("ITOC", 0x03)
        ent_lo = im.itoc_off + 32 + em.index * 32
        allowed = set(range(em.addr, em.addr + em.size)) | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5l)) if v5l[i] != v5m[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5m_deterministic(self):
        b1 = build(det(1), version=18)
        b2 = build(det(2), version=18)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5N(unittest.TestCase):
    # v5n (plan-2 s2b2, mode "B" — m2' X1-from-p0, THE DIRECT POST)
    # image-level contracts: the burnt zone carries the 22-word m2'
    # stub at the exact offsets, the mode plumbing accepts B/19 and
    # rejects A/19, and the diff vs v5m is EXACTLY the m2' rework
    # (w5 + w9..w14 + w16..w21; w15 identical) confined to the stub
    # zone.
    def test_build_v5n_image(self):
        from build_s2 import stub_words
        buf = built(19)
        img = mlxfwutil.Image(buf, "s2v5n")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))  # detour
        self.assertEqual(w(0x38D750), 0x480300BC)  # w0 csr.r r3,csr0xbc
        self.assertEqual(w(0x38D754), 0x002B00AC)  # w1 addi r11,r1,0xac
        self.assertEqual(w(0x38D764), 0xA40A0010)  # w5 filter b_f.cc0A +16 -> W_FAST
        self.assertEqual(w(0x38D770), 0x6C046B86)  # w8 echo N
        self.assertEqual(w(0x38D774), 0x642400AE)  # w9 m2': ld.d r4,r1,0xac (w)
        self.assertEqual(w(0x38D778), 0xFC843081)  # w10 m2': shl64.i r4,r4,6
        self.assertEqual(w(0x38D77C), 0x1C848FC0)  # w11 m2': set1 r4,r4,0x8fc0 (X1)
        self.assertEqual(w(0x38D780), 0x002500B0)  # w12 m2': addi r5,r1,0xb0 (buf)
        self.assertEqual(w(0x38D784), 0x00060000)  # w13 m2': addi r6,zero,0 (status)
        self.assertEqual(w(0x38D788), 0x94F275C4)  # w14 m2': call 0x2ae98 DIRECT
        self.assertEqual(w(0x38D78C), 0x00040000)  # w15 restore r4=0
        self.assertEqual(w(0x38D790), 0x200C4F4B)  # w16 r12 rebuild (== v5m p0)
        self.assertEqual(w(0x38D794), 0x002B00AC)  # w17 payload ptr (post-call)
        self.assertEqual(w(0x38D798), 0x20034380)  # w18 set3 r3,zero,0x4380
        self.assertEqual(w(0x38D79C), 0x2463008E)  # w19 set2 r3,r3,0x8e
        self.assertEqual(w(0x38D7A0), 0xFD005825)  # w20 ret.r zero,r8,r11
        self.assertEqual(w(0x38D7A4), 0x95F80070)  # w21 W_FAST jump FN_A (last)
        # the whole zone == stub_words (bit-exact burn) + tail zeros
        ws = stub_words("B", version=19)
        self.assertEqual([w(STUB + 4 * i) for i in range(len(ws))], ws)
        for a in range(STUB + 4 * 22, STUB + 4 * 34, 4):    # zone tail: zeros
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)           # forbidden cut
        self.assertEqual(w(0x38D7DC), 0)           # fatal zone
        self.assertEqual(w(0x1D594), 0x940DC067)   # S0 alive
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5n_mode_plumbing(self):
        # build() mode inference: version 19 defaults to mode "B" (the
        # CLI `build_s2.py OUT 19` works); an EXPLICIT mode="A" for 19
        # is rejected (v5n is mode-B-only), as is any explicit older
        # version with mode "B" (lineage hygiene, both directions);
        # mode "B" + 18 still builds v5m.
        b1 = build(det(1), version=19)             # inferred mode B
        b2 = build(det(2), mode="B", version=19)   # explicit mode B
        self.assertEqual(b1, b2)
        with self.assertRaises(ValueError):
            build(det(3), mode="A", version=19)
        with self.assertRaises(ValueError):
            build(det(3), mode="B", version=17)
        self.assertEqual(build(det(4), mode="B", version=18),
                         build(det(5), version=18))

    def test_build_v5n_bakes_card_guids(self):
        buf = built(19)
        img = mlxfwutil.Image(buf, "s2v5n")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                         (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5n_diff_vs_v5m_m2prime_rework_only(self):
        # THE diff-vs-v5m contract, image level: detour identical,
        # GUID sections identical, and the de-CRC code diff is EXACTLY
        # {w5 (the canonical immediate retarget +15 -> +16)} U
        # {w9..w14 (the m2' block)} U {w16..w21 (the r12-rebuild tail;
        # w15 addi r4,zero,0 is IDENTICAL to v5m w15)} — the prefix
        # w0-w4/w6-w8 is byte-identical and NOTHING outside the stub
        # zone moves.
        v5m = built(18)
        v5n = built(19)
        im, in_ = mlxfwutil.Image(v5m, "v5m"), mlxfwutil.Image(v5n, "v5n")
        for toc, t in (("DTOC", 0xE1), ("DTOC", 0xE0)):
            self.assertEqual(in_.section_data(in_.find_entry(toc, t)),
                             im.section_data(im.find_entry(toc, t)))
        cm = decrc(im.section_data(im.find_entry("ITOC", 0x03)))
        cn = decrc(in_.section_data(in_.find_entry("ITOC", 0x03)))
        self.assertEqual(struct.unpack_from(">I", cm, DETOUR_DC)[0],
                         struct.unpack_from(">I", cn, DETOUR_DC)[0])
        diff = [a for a in range(0, len(cm), 4)
                if struct.unpack_from(">I", cm, a)[0]
                != struct.unpack_from(">I", cn, a)[0]]
        expected = {STUB + 4 * i for i in
                    (5, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21)}
        self.assertEqual(set(diff), expected,
                         "diff vs v5m not the m2' rework (w15 must be "
                         "identical)")
        # file-level diffs confined to ITOC 0x03 raw section + its entry CRC
        en = in_.find_entry("ITOC", 0x03)
        ent_lo = in_.itoc_off + 32 + en.index * 32
        allowed = set(range(en.addr, en.addr + en.size)) \
            | set(range(ent_lo, ent_lo + 32))
        raw_diff = [i for i in range(len(v5m)) if v5m[i] != v5n[i]]
        self.assertTrue(raw_diff)
        self.assertTrue(set(raw_diff) <= allowed)

    def test_build_v5n_deterministic(self):
        b1 = build(det(1), version=19)
        b2 = build(det(2), version=19)
        self.assertEqual(b1, b2)


@pytest.mark.slow
class TestS2BuildV5O(unittest.TestCase):
    # v5o image-level contracts: THE identity contract — built(20) is
    # BYTE-EXACT built(19) (the stub is w-independent) and its md5 is
    # the burnt v5n image's (Б.3): the v5o artifact IS the v5n
    # firmware, named for the ladder (Б.2).
    V5N_MD5 = "b91848dc96354b1003fc29397aa39eba"

    def test_build_v5o_identity_v5n_file(self):
        import hashlib
        v5o, v5n = built(20), built(19)
        self.assertEqual(v5o, v5n)
        self.assertEqual(hashlib.md5(v5o).hexdigest(), self.V5N_MD5)

    def test_build_v5o_image(self):
        from build_s2 import stub_words
        buf = built(20)
        img = mlxfwutil.Image(buf, "s2v5o")
        e = img.find_entry("ITOC", 0x03)
        code = decrc(img.section_data(e))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), enc.call(DETOUR_DC, STUB))
        ws = stub_words("B", version=20)
        self.assertEqual([w(STUB + 4 * i) for i in range(len(ws))], ws)
        for a in range(STUB + 4 * 22, STUB + 4 * 34, 4):
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)
        self.assertEqual(w(0x38D7DC), 0)
        self.assertEqual(w(0x1D594), 0x940DC067)
        self.assertEqual(mlxfwutil.verify_image(img, deep=True), [])

    def test_build_v5o_mode_plumbing(self):
        b1 = build(det(1), version=20)             # inferred mode B
        b2 = build(det(2), mode="B", version=20)   # explicit mode B
        self.assertEqual(b1, b2)
        with self.assertRaises(ValueError):
            build(det(3), mode="A", version=20)
        with self.assertRaises(ValueError):
            build(det(3), mode="B", version=17)
        self.assertEqual(build(det(4), mode="B", version=20),
                         build(det(5), mode="B", version=19))

    def test_build_v5o_bakes_card_guids(self):
        buf = built(20)
        img = mlxfwutil.Image(buf, "s2v5o")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual((m.guid, m.mac),
                          (CARD_GUID, CARD_MAC))
        self.assertTrue(m.crc_ok())

    def test_build_v5o_deterministic(self):
        self.assertEqual(build(det(1), version=20),
                         build(det(2), version=20))


class TestS2BuildV5Q(unittest.TestCase):
    # v5q (plan-4 s3 trigger-probe, builder v22, mode "B"): the v5o
    # prefix (magic filter + m2' DIRECT POST) + the RUNTIME mode
    # branch — the mode is a FRAME bit (frame word[4] hi-half:
    # 0 = A / 1 = B), not an image bit, so ONE image serves both
    # modes.  A -> r3 = RESUME_LIVE 0x008E4380 (byte-exact v5o exit);
    # B -> the Task-6 RE-b' exit: status block ([r1+0x8] = 0x00030000
    # via 0x24040003/0x6C20200A, [r1+0xc] = 0 via 0x6C20000E) +
    # r3 = JUMP_B 0x008E43A4.  F_EXACT = none (Task-7 RE-a: no FW
    # validation on F in 0x2ae98/0x2a154) -> the live T1/T2 w pair
    # (0x00600000/0x00600001, P0_SAFE per Task 3 Step 5).
    JUMP_B = 0x008E43A4
    W_F0, W_F40 = 0x00600000, 0x00600001

    def test_v5q_layout(self):
        from build_s2 import STUB_LAYOUT, ZONE_WORDS, stub_words
        self.assertIn(22, STUB_LAYOUT)
        total, _wfast = STUB_LAYOUT[22]
        ws = stub_words("B", version=22)
        self.assertEqual(len(ws), total)
        self.assertLessEqual(total, ZONE_WORDS)

    def test_v5q_contains_post_and_resume(self):
        from build_s2 import stub_words, M2_POST_DIRECT, RESUME_LIVE
        ws = stub_words("B", version=22)
        # call-word is position-dependent (target = PC + imm) — check
        # PRESENCE at any slot, not a fixed site.
        self.assertTrue(any(enc.call(STUB + 4 * i, M2_POST_DIRECT) in ws
                            for i in range(len(ws))))
        self.assertIn(enc.set3(3, 0, RESUME_LIVE & 0xFFFF), ws)

    def test_v5q_mode_b_jump_and_status(self):
        from build_s2 import stub_words
        # Task-6 RE-b' contract words, verbatim:
        ws = stub_words("B", version=22)
        self.assertIn(enc.set3(3, 0, 0x43A4), ws)     # r3 lo -> JUMP_B
        self.assertIn(0x2463008E, ws)                 # r3 hi (== v5o w19)
        self.assertIn(0x24040003, ws)                 # set2 r4,zero,0x3
        self.assertIn(0x6C20200A, ws)                 # st.d r4,r1,0x8
        self.assertIn(0x6C20000E, ws)                 # st.d zero,r1,0xc
        self.assertIn(0xFD005825, ws)                 # transfer (== v5o w20)

    def test_v5q_mode_branch_control_flow(self):
        # Review finding 2: pin the MODE-BRANCH control words (targets +
        # the 16-bit mode compare), not just word presence — this is what
        # catches the "mode A unreachable" regression (finding 1).
        from build_s2 import stub_words, MODE_SLOT_V5Q, STUB
        ws = stub_words("B", version=22)
        pc = lambda i: STUB + 4 * i
        # mode load (16-bit halfword), A-const = 0, compare:
        self.assertEqual(ws[16], enc.ld_w(13, 1, MODE_SLOT_V5Q))
        self.assertEqual(ws[17], enc.set3(12, 0, 0))   # A == mode half 0
        self.assertEqual(ws[18], enc.cmp38_sel(2, 13, 12))
        # w19 b.t -> A block (w26): mode A is REACHABLE (not dead).
        self.assertEqual(ws[19], enc.b_t(0x0A, pc(19), pc(26)))
        # w25 jump -> tail (w28): unconditional skip of the A block.
        self.assertEqual(ws[25], enc.jump(pc(25), pc(28)))
        # w5 b.f (magic miss) -> W_FAST (w31).
        self.assertEqual(ws[5], enc.b_f(0x0A, pc(5), pc(31)))
        # decoded targets (independent of the encoder, via disassembler):
        import irisc_dis
        self.assertEqual(irisc_dis.dis(ws[19], pc(19)),
                         'b.t.0xa zero,0x38d7b8')
        self.assertEqual(irisc_dis.dis(ws[25], pc(25)),
                         'jump 0x38d7c0')
        self.assertEqual(irisc_dis.dis(ws[5], pc(5)),
                         'b.f.0xa zero,0x38d7cc')

    def test_v5q_wfast_position(self):
        from build_s2 import STUB_LAYOUT, stub_words, FN_A
        _total, wfast_idx = STUB_LAYOUT[22]
        ws = stub_words("B", version=22)
        self.assertEqual(ws[wfast_idx],
                         enc.jump(STUB + 4 * wfast_idx, FN_A))

    def test_v5q_frames_count_and_shape(self):
        from build_s2 import trig_frames_v5q
        frames = trig_frames_v5q()
        self.assertEqual(len(frames), 4)   # (A/B) x (F0/F40)
        for (mode, fname), f in frames.items():
            self.assertEqual(len(f), 0x24)
            self.assertEqual(f[4:8], b"\x00\x00\x00\x00")  # input[4..8)=0
            self.assertEqual(struct.unpack_from(">H", f, 0x12)[0], 0x5332)
            self.assertEqual(struct.unpack_from(">H", f, 0x10)[0],
                             1 if mode == "B" else 0)      # mode slot
            self.assertEqual(struct.unpack_from(">I", f, 0x14)[0],
                             self.W_F0 if fname == "F0" else self.W_F40)
        # A frames are BYTE-EXACT the v5n/v5o live frames (mode slot
        # stays 0) — the v5o lineage is preserved.
        import payload as pl
        self.assertEqual(frames[("A", "F40")], pl.trig_v5n(self.W_F40))
        self.assertEqual(frames[("A", "F0")], pl.trig_v5n(self.W_F0))
        # B frames differ from the A twins ONLY in the mode slot:
        self.assertEqual(frames[("B", "F40")][:0x10],
                         frames[("A", "F40")][:0x10])
        self.assertEqual(frames[("B", "F40")][0x12:],
                         frames[("A", "F40")][0x12:])


@pytest.mark.slow
class TestS2BuildV5R(unittest.TestCase):
    # v5r (plan-4 s3 trigger-probe, builder v23, mode "B"): v5o + the
    # LATE detour point P (RE-c, task-09) + the mode bit (A/B) — the C1
    # stub: the v5q prefix (magic filter + m2' DIRECT POST) + the mode
    # branch, with the C1 LATE exits — BOTH A and B return to the
    # detour's ra (RESUME_P = live 0x008E43C8 = P+4); the v5q
    # body-absolutes (RESUME_LIVE 0x008E4380 / JUMP_B 0x008E43A4) are
    # REMOVED (at a late point they're back in the body -> double
    # CQE-POST), and the magic-miss W_FAST is a no-op ret.d (return
    # [retaddr] = the detour's ra) — NOT the v5q tail-jump FN_A (which
    # would run FN_A over the stock word).  The early detour @DETOUR_DC
    # is RESTORED TO STOCK (0x9402A57A) — anti-confound (no two POSTs).
    P = 0x0E43C4
    RESUME_P = 0x008E43C8
    ORIG_WORD_P = 0x00130000
    W_F0, W_F40 = 0x00600000, 0x00600001

    @staticmethod
    def _code(version):
        buf = built(version)
        img = mlxfwutil.Image(buf, "s2v%s" % version)
        e = img.find_entry("ITOC", 0x03)
        return decrc(img.section_data(e))

    def test_v5r_layout(self):
        from build_s2 import stub_words, STUB_LAYOUT, ZONE_WORDS
        self.assertIn(23, STUB_LAYOUT)
        total, _wfast = STUB_LAYOUT[23]
        ws = stub_words("B", version=23)
        self.assertEqual(len(ws), total)
        self.assertLessEqual(total, ZONE_WORDS)

    def test_v5r_early_detour_restored_to_stock(self):
        # anti-confound: the early detour @DETOUR_DC == stock (0x9402A57A)
        from build_s2 import DETOUR_DC, STOCK_WORDS
        code = self._code(23)
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(DETOUR_DC), STOCK_WORDS[DETOUR_DC])

    def test_v5r_late_detour_at_P(self):
        # the late detour @P == call STUB (0x38d750); P from RE-c (task-09)
        from build_s2 import STUB
        code = self._code(23)
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(self.P), enc.call(self.P, STUB))
        # the stock word @P is REPLACED (not left behind):
        self.assertNotEqual(w(self.P), self.ORIG_WORD_P)

    def test_v5r_frames_count(self):
        from build_s2 import trig_frames_v5r
        self.assertEqual(len(trig_frames_v5r()), 4)   # (A/B) x (F0/F40)

    def test_v5r_stub_in_image(self):
        # the burned stub == stub_words; the zone tail is zero; the
        # guarded zones are clean; the S0 injection is alive; the image
        # verifies deep.
        from build_s2 import stub_words
        code = self._code(23)
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        ws = stub_words("B", version=23)
        self.assertEqual([w(STUB + 4 * i) for i in range(len(ws))], ws)
        for a in range(STUB + 4 * len(ws), STUB + 4 * 34, 4):
            self.assertEqual(w(a), 0, f"zone tail word @0x{a:x} not zero")
        self.assertEqual(w(0x38D748), 0)
        self.assertEqual(w(0x38D7DC), 0)
        self.assertEqual(w(0x1D594), 0x940DC067)
        self.assertEqual(mlxfwutil.verify_image(mlxfwutil.Image(built(23), "s2v5r"),
                                             deep=True), [])

    def test_v5r_c1_exits(self):
        # C1 contract: BOTH modes return to RESUME_P (P+4) — NOT the
        # v5q body-absolutes; the magic-miss W_FAST is a no-op ret.d,
        # NOT jump FN_A.  The POST and the magic-path transfer are
        # byte-exact the v5o/v5q T2-live words.
        from build_s2 import stub_words, STUB_LAYOUT, STUB, M2_POST_DIRECT
        ws = stub_words("B", version=23)
        pc = lambda i: STUB + 4 * i
        # the shared tail rebuilds r3 = RESUME_P (lo-first OR-safe pair):
        self.assertIn(enc.set3(3, 0, self.RESUME_P & 0xFFFF), ws)  # 0x200343C8
        self.assertIn(0x2463008E, ws)                              # r3 hi
        # the v5q body-absolutes are GONE:
        self.assertNotIn(enc.set3(3, 0, 0x4380), ws)   # RESUME_LIVE lo
        self.assertNotIn(enc.set3(3, 0, 0x43A4), ws)   # JUMP_B lo
        # the mode branch: 16-bit mode load, A-const 0, compare,
        # b.t -> the shared tail (A skips the B status block):
        self.assertEqual(ws[16], enc.ld_w(13, 1, 0xA8))
        self.assertEqual(ws[17], enc.set3(12, 0, 0))
        self.assertEqual(ws[18], enc.cmp38_sel(2, 13, 12))
        self.assertEqual(ws[19], enc.b_t(0x0A, pc(19), pc(23)))
        # the B block: the Task-6 status contract VERBATIM, then
        # fall-through to the tail (NO r3 = JUMP_B setup):
        self.assertEqual(ws[20], 0x24040003)   # set2 r4,zero,0x3
        self.assertEqual(ws[21], 0x6C20200A)   # st.d r4,r1,0x8 (status)
        self.assertEqual(ws[22], 0x6C20000E)   # st.d zero,r1,0xc (syndrome)
        # the POST is intact (== v5o/v5q w14, T2-live):
        self.assertEqual(ws[14], enc.call(pc(14), M2_POST_DIRECT))
        # the magic-path transfer + payload exit (== v5o/v5q):
        self.assertEqual(ws[25], enc.set3(12, 0, 0x4F4B))
        self.assertEqual(ws[26], enc.addi(11, 1, 0xAC))
        self.assertEqual(ws[27], 0xFD005825)   # ret.r zero,r8,r11
        # W_FAST = the no-op ret.d (return [retaddr]), NOT jump FN_A:
        _total, wfast = STUB_LAYOUT[23]
        self.assertEqual(ws[wfast], 0xFC00002D)
        from build_s2 import FN_A
        self.assertFalse(any(w == enc.jump(STUB + 4 * i, FN_A)
                             for i, w in enumerate(ws)))
        # decoded control words (independent of the encoder):
        import irisc_dis
        self.assertEqual(irisc_dis.dis(ws[5], pc(5)), 'b.f.0xa zero,0x38d7c0')
        self.assertEqual(irisc_dis.dis(ws[19], pc(19)), 'b.t.0xa zero,0x38d7ac')
        self.assertEqual(irisc_dis.dis(ws[wfast], pc(wfast)),
                         'ret.d zero,zero,zero')

    def test_v5r_frames_shape(self):
        from build_s2 import trig_frames_v5r, trig_frames_v5q
        frames = trig_frames_v5r()
        self.assertEqual(len(frames), 4)
        for (mode, fname), f in frames.items():
            self.assertEqual(len(f), 0x24)
            self.assertEqual(struct.unpack_from(">H", f, 0x12)[0], 0x5332)
            self.assertEqual(struct.unpack_from(">H", f, 0x10)[0],
                             1 if mode == "B" else 0)      # mode slot
            self.assertEqual(struct.unpack_from(">I", f, 0x14)[0],
                             self.W_F0 if fname == "F0" else self.W_F40)
        # the frames are IDENTICAL to the v5q frames: the C1 change is
        # in the stub's exits, not the frame shape.
        self.assertEqual(frames, trig_frames_v5q())

    def test_v5r_mode_plumbing(self):
        b1 = build(det(101), version=23)             # inferred mode B
        b2 = build(det(102), mode="B", version=23)   # explicit mode B
        self.assertEqual(b1, b2)
        with self.assertRaises(ValueError):
            build(det(103), mode="A", version=23)
        self.assertEqual(build(det(104), mode="B", version=23), built(23))


CARD_GUID = int(mlxfwutil.hw("CARD_CX5_EDR100", "guid"), 16)
CARD_MAC = int(mlxfwutil.hw("CARD_CX5_EDR100", "mac"), 16)

@pytest.mark.slow
class TestS2BuildV3Guids(unittest.TestCase):
    def test_card_constants_match_stock_backup(self):
        import build_s2
        self.assertEqual((build_s2.CARD_GUID, build_s2.CARD_MAC), (CARD_GUID, CARD_MAC))

    def test_v3_devinfo_bakes_card_guids(self):
        buf = built(2)
        img = mlxfwutil.Image(buf, "s2v3")
        valid = mlxfwutil.find_valid_devinfo(img)
        self.assertEqual(len(valid), 1)
        m = mlxfwutil.MDevInfo.parse(img.section_data(valid[0]))
        self.assertEqual(m.guid, CARD_GUID)
        self.assertEqual(m.mac, CARD_MAC)
        self.assertTrue(m.crc_ok())

    def test_v3_mfginfo_bakes_card_guids(self):
        buf = built(2)
        img = mlxfwutil.Image(buf, "s2v3")
        d0 = img.section_data(img.find_entry("DTOC", 0xE0))
        self.assertEqual(int.from_bytes(d0[0x28:0x30], "big"), CARD_GUID)
        self.assertEqual(int.from_bytes(d0[0x38:0x40], "big"), CARD_MAC)

    def test_v3_itoc03_identical_to_v2(self):
        from build_s2 import build_v2
        v2 = v2_core()
        v3 = built(2)
        v2img, v3img = mlxfwutil.Image(v2, "v2"), mlxfwutil.Image(v3, "v3")
        self.assertEqual(v3img.section_data(v3img.find_entry("ITOC", 0x03)),
                         v2img.section_data(v2img.find_entry("ITOC", 0x03)))

    def test_v3_byte_equivalent_to_guides_cli_on_v2(self):
        from build_s2 import build_v2
        v2path = "/tmp/opencode/s2/w%s-v2-guids-eq.bin" % _WORKER
        Path(v2path).write_bytes(v2_core())
        inj = "/tmp/opencode/s2/w%s-v2-guids-inj.bin" % _WORKER
        rc = mlxfwutil.main(["guides", v2path, "--guid", hex(CARD_GUID),
                          "--mac", hex(CARD_MAC), "-o", inj])
        self.assertEqual(rc, 0)
        self.assertEqual(built(2),
                         Path(inj).read_bytes())

if __name__ == "__main__":
    unittest.main()
