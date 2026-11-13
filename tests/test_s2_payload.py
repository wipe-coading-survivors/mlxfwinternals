import struct, sys, unittest
from pathlib import Path
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts" / "irisc"))
sys.path.insert(0, str(REPO / "scripts" / "s2"))
import enc, irisc_dis, payload


def _build_s2():
    try:
        import build_s2
    except FileNotFoundError:
        raise unittest.SkipTest("hardware.local.md hw registry not present")
    return build_s2


class TestMarker(unittest.TestCase):
    def test_marker_writes_cr_and_returns(self):
        ws = payload.marker(3, 4)
        dec = [irisc_dis.dis(w, 0) for w in ws]
        self.assertTrue(any("0x2388" in s for s in dec))
        self.assertEqual(ws[-1], enc.ret_r(0, 0, 3))

    def test_marker_layout_five_words(self):
        ws = payload.marker(1, 2)
        self.assertEqual(len(ws), 5)
        dec = [irisc_dis.dis(w, 0) for w in ws]
        self.assertEqual(dec[0], "set2 r7,zero,0x5332")
        self.assertEqual(dec[1], "set3 r7,r7,0x4f4b")
        self.assertEqual(dec[2], "st.d r7,zero,0x2388")
        self.assertEqual(dec[3], "st.d r5,zero,0x238c")
        self.assertEqual(dec[4], "ret.r zero,zero,r3")

    def test_marker_no_call_no_r4(self):
        dec = [irisc_dis.dis(w, 0) for w in payload.marker(1, 2)]
        self.assertTrue(all(not s.startswith("call") for s in dec))
        self.assertTrue(all("r4" not in s for s in dec))

    def test_marker_rejects_non_u32(self):
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.marker(0x100000000, 0)
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.marker(0, -1)


class TestInputBlock(unittest.TestCase):
    def test_input_block_layout(self):
        b = payload.input_block([0xFC000008], r5=0x1111, r6=0x2222)
        w = struct.unpack(">5I", b)
        self.assertEqual(w[0], 0x5332434D)  # MAGIC
        self.assertEqual(w[1], 1)           # N
        self.assertEqual(w[2], 0x1111)
        self.assertEqual(w[3], 0x2222)
        self.assertEqual(w[4], 0xFC000008)

    def test_size_budget(self):
        self.assertLessEqual(len(payload.input_block(payload.marker(1, 2), 0, 0)),
                             payload.PAYLOAD_MAX + 16)

    def test_payload_max_matches_in_size(self):
        self.assertEqual(payload.PAYLOAD_MAX, 20)
        self.assertEqual(payload.PAYLOAD_MAX + 16, 0x24)

    def test_full_budget_boundary_ok(self):
        b = payload.input_block([0xFC000008] * 5, 0, 0)
        self.assertEqual(len(b), 36)
        self.assertEqual(struct.unpack(">I", b[4:8])[0], 5)

    def test_rejects_empty_payload(self):
        with self.assertRaisesRegex(AssertionError, "1..5"):
            payload.input_block([], 0, 0)

    def test_rejects_over_budget(self):
        with self.assertRaisesRegex(AssertionError, "1..5"):
            payload.input_block([0xFC000008] * 6, 0, 0)

    def test_rejects_non_u32_word(self):
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block([0x100000000], 0, 0)
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block([-1], 0, 0)

    def test_rejects_non_u32_r5_r6(self):
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block([1], 0x100000000, 0)
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block([1], 0, -1)


class TestMarkerLiteV4(unittest.TestCase):
    def test_marker_lite_four_words(self):
        ws = payload.marker_lite()
        self.assertEqual(len(ws), 4)
        dec = [irisc_dis.dis(w, 0) for w in ws]
        self.assertEqual(dec[0], "set2 r7,zero,0x5332")
        self.assertEqual(dec[1], "set3 r7,r7,0x4f4b")
        self.assertEqual(dec[2], "st.d r7,zero,0x2388")
        self.assertEqual(dec[3], "ret.r zero,zero,r3")

    def test_marker_lite_golden_words(self):
        # golden: S2OK=0x53324F4B -> CR 0x2388 (gate G5' for T11)
        self.assertEqual(payload.marker_lite(),
                         [0x24075332, 0x20E74F4B, 0x6C043B8A, 0xFC001825])

    def test_marker_lite_last_word_ret_r(self):
        self.assertEqual(payload.marker_lite()[-1], enc.ret_r(0, 0, 3))

    def test_marker_lite_no_call_no_r4_no_r6(self):
        dec = [irisc_dis.dis(w, 0) for w in payload.marker_lite()]
        self.assertTrue(all(not s.startswith("call") for s in dec))
        self.assertTrue(all("r4" not in s and "r6" not in s for s in dec))


class TestInputBlockV4(unittest.TestCase):
    def test_v4_constants(self):
        self.assertEqual(payload.DISCRIM32, 0x0432434D)
        self.assertEqual(payload.OPCODE_V4, 0x09320000)
        self.assertEqual(payload.PAYLOAD_MAX_V4, 4)

    def test_input_block_v4_layout(self):
        b = payload.input_block_v4([0xFC001825], r5=0x1111)
        w = struct.unpack(">6I", b)
        self.assertEqual(w[0], 0x09320000)   # opcode word fixed (dispatcher routes on 09 32)
        self.assertEqual(w[1], 0x00000000)   # input[4..8) MUST be 0 (T9 G5/G6/G7)
        self.assertEqual(w[2], 0x0432434D)   # DISCRIM32 @k=8..0xB
        self.assertEqual(w[3], 1)            # N == len(words)
        self.assertEqual(w[4], 0x1111)       # r5-init @k=0x10
        self.assertEqual(w[5], 0xFC001825)   # code @k=0x14

    def test_input_block_v4_full_budget(self):
        b = payload.input_block_v4(payload.marker_lite(), r5=1)
        self.assertEqual(len(b), 0x24)       # N=4 fills strictly-clean window 0x24
        self.assertEqual(struct.unpack(">I", b[0xC:0x10])[0], 4)

    def test_input_block_v4_rejects_empty(self):
        with self.assertRaisesRegex(AssertionError, "1\.\.4"):
            payload.input_block_v4([], 0)

    def test_input_block_v4_rejects_over_budget(self):
        with self.assertRaisesRegex(AssertionError, "1\.\.4"):
            payload.input_block_v4([0xFC001825] * 5, 0)

    def test_input_block_v4_rejects_non_u32(self):
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block_v4([0x100000000], 0)
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block_v4([-1], 0)
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block_v4([1], 0x100000000)

    def test_trig_cmd_v4_hex(self):
        # exact trigger inputs for T11 (mlxscope --input-hex)
        echo = payload.input_block_v4([enc.ret_r(0, 0, 3)], r5=0)
        self.assertEqual(echo.hex(),
                         "09320000000000000432434d0000000100000000fc001825")
        exec_ = payload.input_block_v4(payload.marker_lite(), r5=1)
        self.assertEqual(exec_.hex(),
                         "09320000000000000432434d0000000400000001"
                         "2407533220e74f4b6c043b8afc001825")


class TestInputBlockV5B(unittest.TestCase):
    # v5b (T18): MAGIC16=0x5332 @input[0x12..0x14) (T17 live-proven filter
    # slot [r1+0xaa]); N @input[0xC..0xE) (16-bit, words); code @0x14..0x24
    # (PAYLOAD_MAX_V5B=4); input[4..8)=0 (validator G5/G6/G7) and
    # input[8..0xC)=0 (TT=0 class + tn=0) asserted fail-loud.
    def test_v5b_constants(self):
        self.assertEqual(payload.MAGIC16, 0x5332)
        self.assertEqual(payload.GAUNTLET_HI, 0x2407)
        self.assertEqual(payload.OPCODE_V5B, payload.OPCODE_V4)
        self.assertEqual(payload.PAYLOAD_MAX_V5B, 4)

    def test_input_block_v5b_layout(self):
        b = payload.input_block_v5b([0xFC001825])
        self.assertEqual(b[0:4], bytes.fromhex("09320000"))   # opcode fixed
        self.assertEqual(b[4:0xC], b"\x00" * 8)               # 4..8 + TT/tn zeros
        self.assertEqual(b[0xC:0xE], b"\x00\x01")             # N=1 (BE16)
        self.assertEqual(b[0xE:0x12], b"\x00" * 4)            # pad zeros
        self.assertEqual(b[0x12:0x14], b"\x53\x32")           # MAGIC16
        self.assertEqual(b[0x14:0x18], b"\xfc\x00\x18\x25")   # code @0x14

    def test_input_block_v5b_full_budget(self):
        b = payload.input_block_v5b(payload.marker_lite())
        self.assertEqual(len(b), 0x24)                        # N=4 fills window
        self.assertEqual(b[0xC:0xE], b"\x00\x04")
        self.assertEqual(struct.unpack(">I", b[0x14:0x18])[0], 0x24075332)

    def test_input_block_v5b_rejects_empty(self):
        with self.assertRaisesRegex(AssertionError, "1\.\.4"):
            payload.input_block_v5b([])

    def test_input_block_v5b_rejects_over_budget(self):
        with self.assertRaisesRegex(AssertionError, "1\.\.4"):
            payload.input_block_v5b([0xFC001825] * 5)

    def test_input_block_v5b_rejects_non_u32(self):
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block_v5b([0x100000000])
        with self.assertRaisesRegex(AssertionError, "u32"):
            payload.input_block_v5b([-1])

    def test_marker_lite_hi_halfword_matches_gauntlet(self):
        # the stub gauntlet compares the first copied halfword (BE hi of
        # word[0]) against GAUNTLET_HI; marker-lite word[0]=0x24075332
        self.assertEqual(payload.marker_lite()[0] >> 16, payload.GAUNTLET_HI)

    def test_trig_cmd_v5b_hex(self):
        # exact trigger inputs for T19 (mlxscope --input-hex); the tool
        # zero-pads to the 36B window (v4 precedent: blocks are not padded)
        fallthrough = "09320000" + "00" * 32                  # stock zeros
        echo = payload.input_block_v5b([enc.ret_r(0, 0, 3)])
        self.assertEqual(len(echo), 0x18)                     # 0x14 + 4N (N=1)
        self.assertEqual(echo.hex(),
                         "093200000000000000000000"
                         "0001000000005332fc001825")
        exec_ = payload.input_block_v5b(payload.marker_lite())
        self.assertEqual(exec_.hex(),
                         "093200000000000000000000"
                         "0004000000005332"
                         "2407533220e74f4b6c043b8afc001825")
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                                   # hi: 0x2407 -> 0x2406
        negative = payload.input_block_v5b(neg)
        self.assertEqual(negative.hex(),
                         "093200000000000000000000"
                         "0004000000005332"
                         "2406533220e74f4b6c043b8afc001825")
        self.assertEqual(len(fallthrough), 72)


class TestTrigV5C(unittest.TestCase):
    # T20: THE test frame for the v5c-A live run (phase 2) is the freeze-
    # reproducing gauntlet-neg frame from journal task-18 §TRIG_CMD (the only
    # frame that ever froze the host: N=4 + MAGIC16 + hi=0x2406, 2/2 freezes
    # on 7.1.10/7.2.5 — task-19/task-19-debug2).  On v5c-A this frame passes
    # filter + N-guard and walks the ENTIRE instrumented path M0->push->M1->
    # pop->M2->jump.  Byte-exactness is verified programmatically against
    # payload.input_block_v5b (same construction as the v5b golden test).
    FREEZE_FRAME = ("093200000000000000000000"
                   "0004000000005332"
                   "2406533220e74f4b6c043b8afc001825")

    def test_freeze_frame_byte_exact(self):
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                       # hi: 0x2407 -> 0x2406
        self.assertEqual(payload.input_block_v5b(neg).hex(), self.FREEZE_FRAME)
        b = bytes.fromhex(self.FREEZE_FRAME)
        self.assertEqual(struct.unpack(">I", b[0:4])[0], 0x09320000)  # opcode
        self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)       # N=4
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0x5332)  # MAGIC16
        self.assertEqual(struct.unpack(">H", b[0x14:0x16])[0], 0x2406)  # gauntlet hi

    def test_freeze_frame_drives_full_v5cA_path(self):
        # the frame satisfies both stub gates: [r1+0xaa]=MAGIC16 (filter eq32
        # passes) and [r1+0xa4]=4 (N-guard eq32 passes) => control reaches
        # M0 and every marker stage — the diagnostic contract of T20.
        b = bytes.fromhex(self.FREEZE_FRAME)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
        self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)


class TestTrigV5CB(unittest.TestCase):
    # T21: live phase-2 frames for v5c-B.  PROTOCOL ORDER: the freeze-
    # reproducing gauntlet-neg frame runs FIRST (the diagnostic run), the
    # exec frame (gauntlet MATCH, hi=0x2407) second — hence the numbered
    # method names.  On v5cB both frames pass filter + N-guard and walk the
    # same instrumented write path (save -> copy -> gauntlet); the gauntlet
    # outcome only selects b_f-vs-fallthrough, and both reach the pop —
    # the payload block is absent (budget: never executed on these frames
    # in v5b either — the freeze run branched away at the gauntlet miss).
    NEG_FRAME = ("093200000000000000000000"
                 "0004000000005332"
                 "2406533220e74f4b6c043b8afc001825")
    EXEC_FRAME = ("093200000000000000000000"
                  "0004000000005332"
                  "2407533220e74f4b6c043b8afc001825")

    def test_01_neg_frame_byte_exact(self):
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                       # hi: 0x2407 -> 0x2406
        self.assertEqual(payload.input_block_v5b(neg).hex(), self.NEG_FRAME)
        b = bytes.fromhex(self.NEG_FRAME)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
        self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)      # N=4
        self.assertEqual(struct.unpack(">H", b[0x14:0x16])[0], 0x2406)  # gauntlet miss

    def test_02_exec_frame_byte_exact_and_full_path(self):
        self.assertEqual(payload.input_block_v5b(payload.marker_lite()).hex(),
                         self.EXEC_FRAME)
        for frame, hi in ((self.NEG_FRAME, 0x2406), (self.EXEC_FRAME, 0x2407)):
            b = bytes.fromhex(frame)
            # both gates pass => control reaches save/copy/gauntlet on BOTH
            # frames (identical instrumented path, gauntlet cmp differs)
            self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
            self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)
            self.assertEqual(struct.unpack(">H", b[0x14:0x16])[0], hi)


class TestTrigV5D(unittest.TestCase):
    # T23: v5d keeps the v5b input-block contract byte-exact — the host
    # TRIG frames are UNCHANGED (payload.py untouched); only the stub's
    # copy-loop data words differ (ld.d/st.d instead of 2x ld.w/st.w).
    # The C1 interpretation frame is EXEC (gauntlet match -> payload ->
    # 0x2388=0x53324F4B); NEG walks the same copy path with a gauntlet
    # miss (clean stock completion).  PROTOCOL ORDER for the live phase:
    # neg FIRST (freeze-reproducer on v5b lineage), exec second.
    FALLTHROUGH = "09320000" + "00" * 32
    ECHO = ("093200000000000000000000"
            "0001000000005332fc001825")
    NEG = ("093200000000000000000000"
           "0004000000005332"
           "2406533220e74f4b6c043b8afc001825")
    EXEC = ("093200000000000000000000"
            "0004000000005332"
            "2407533220e74f4b6c043b8afc001825")

    def test_frames_byte_exact_v5b(self):
        # byte-exact against the v5b frame goldens (test_trig_cmd_v5b_hex
        # / TestTrigV5CB): the input-block builder did not change
        self.assertEqual(payload.input_block_v5b([enc.ret_r(0, 0, 3)]).hex(),
                         self.ECHO)
        self.assertEqual(payload.input_block_v5b(payload.marker_lite()).hex(),
                         self.EXEC)
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                       # hi: 0x2407 -> 0x2406
        self.assertEqual(payload.input_block_v5b(neg).hex(), self.NEG)
        self.assertEqual(len(self.FALLTHROUGH), 72)

    def test_frames_drive_v5d_gates(self):
        # both magic frames pass the v5d filter ([r1+0xaa]=MAGIC16) and
        # the N-guard ([r1+0xa4]=4) => control reaches the stock-conformance
        # copy loop and the M-marker on BOTH; the gauntlet byte then picks
        # miss (NEG: pop, clean) vs match (EXEC: payload, C1 signal)
        for frame in (self.NEG, self.EXEC):
            b = bytes.fromhex(frame)
            self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
            self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)
        self.assertEqual(struct.unpack(">H", bytes.fromhex(self.NEG)[0x14:0x16])[0],
                         0x2406)
        self.assertEqual(struct.unpack(">H", bytes.fromhex(self.EXEC)[0x14:0x16])[0],
                         0x2407)

    def test_exec_frame_payload_writes_c1_signal(self):
        # C1 interpretation input: the copied marker-lite payload writes
        # S2OK=0x53324F4B to CR 0x2388 (gate G5') and returns via ret.r r3
        ws = payload.marker_lite()
        self.assertEqual(ws[0] >> 16, payload.GAUNTLET_HI)   # gauntlet passes
        self.assertEqual(struct.pack(">2I", ws[0], ws[1])[0:4],
                         bytes.fromhex("24075332"))


class TestTrigV5E(unittest.TestCase):
    # T25 (v5e escalation bisection, journal task-24 rev.2 §TRIG frames):
    # ONE burn, five frames — fallthrough, echo-N1, then the ESCALATION
    # neg frames N=2/3/4 (freeze at N=k names the block: saves / write-
    # pair / loop).  neg_code = marker_lite()[0] ^ 0x00010000 (hi=0x2406
    # lineage); the code-window content is INERT in v5e (no gauntlet) —
    # N=2 copies nothing, N=3 copies word0 into the own frame's payload
    # slot, N=4 is the byte-exact v5b/v5cB/v5d freeze reproducer.
    # payload.py is UNCHANGED (input_block_v5b already asserts N==len in
    # [1..4]); the N=2/N=3 frames are its new inputs (neg_code[:2]/[:3]).
    FALLTHROUGH = "09320000" + "00" * 32
    ECHO_N1 = ("093200000000000000000000"
               "0001000000005332fc001825")
    NEG_N2 = ("093200000000000000000000"
              "0002000000005332"
              "2406533220e74f4b")
    NEG_N3 = ("093200000000000000000000"
              "0003000000005332"
              "2406533220e74f4b6c043b8a")
    NEG_N4 = ("093200000000000000000000"
              "0004000000005332"
              "2406533220e74f4b6c043b8afc001825")

    def neg_code(self):
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                       # hi: 0x2407 -> 0x2406
        return neg

    def test_01_echo_n1_frame_byte_exact(self):
        # echo-N1 runs FIRST (protocol): depth-1 write path, marker->0
        self.assertEqual(payload.input_block_v5b([enc.ret_r(0, 0, 3)]).hex(),
                         self.ECHO_N1)

    def test_02_neg_n2_frame_byte_exact(self):
        # freeze at N=2 => SAVES block (L2 gate exit before dst-init)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:2]).hex(),
                         self.NEG_N2)

    def test_03_neg_n3_frame_byte_exact(self):
        # freeze at N=3 => WRITE-PAIR block (dst-init + one ld.d/st.d)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:3]).hex(),
                         self.NEG_N3)

    def test_04_neg_n4_frame_byte_exact_freeze_reproducer(self):
        # N=4 => LOOP block: the byte-exact existing freeze reproducer
        # (task-19/19-debug2/23 frame — input_block_v5b(neg_code) N=4)
        self.assertEqual(payload.input_block_v5b(self.neg_code()).hex(),
                         self.NEG_N4)

    def test_05_fallthrough_frame(self):
        # non-magic: b_f at w5 -> W_FAST, nothing executed, nothing echoed
        self.assertEqual(len(self.FALLTHROUGH), 72)         # 36B window
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)  # no MAGIC16

    def test_escalation_frames_drive_v5e_gates(self):
        # every magic frame passes the filter ([r1+0xaa]=MAGIC16); the
        # escalation gates then route on N: 2 -> L2 exit, 3 -> L3 exit,
        # 4 -> fallthrough into the loop, 1 -> depth-1 echo path
        for frame, n in ((self.ECHO_N1, 1), (self.NEG_N2, 2),
                         (self.NEG_N3, 3), (self.NEG_N4, 4)):
            b = bytes.fromhex(frame)
            self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0],
                             payload.MAGIC16)
            self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], n)
            self.assertIn(n, (1, 2, 3, 4))                   # N-guard domain

    def test_n2_n3_code_window_inert_content(self):
        # v5e has NO gauntlet: the copied words are never decoded — the
        # N=2 frame carries 2 inert words, N=3 carries 3 (one live copy)
        self.assertEqual(struct.unpack(">2I", bytes.fromhex(self.NEG_N2)[0x14:0x1C]),
                         (0x24065332, 0x20E74F4B))
        self.assertEqual(len(bytes.fromhex(self.NEG_N2)), 0x1C)   # 0x14 + 4*2
        self.assertEqual(len(bytes.fromhex(self.NEG_N3)), 0x20)   # 0x14 + 4*3


class TestTrigV5F(unittest.TestCase):
    # T27 (v5f skip-idiom-gated escalation, journal task-26 §Step 7):
    # the TRIG frames are UNCHANGED vs v5e — payload.py is untouched
    # (input_block_v5b already asserts N==len in [1..4]); v5f only
    # re-wires the stub gates that CONSUME N.  Byte-exactness asserted
    # against the v5e goldens; the code-window content stays INERT in
    # v5f (no gauntlet) exactly as in v5e.
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH
    ECHO_N1 = TestTrigV5E.ECHO_N1
    NEG_N2 = TestTrigV5E.NEG_N2
    NEG_N3 = TestTrigV5E.NEG_N3
    NEG_N4 = TestTrigV5E.NEG_N4

    def neg_code(self):
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                       # hi: 0x2407 -> 0x2406
        return neg

    def test_01_frames_byte_exact_v5e(self):
        self.assertEqual(payload.input_block_v5b([enc.ret_r(0, 0, 3)]).hex(),
                         self.ECHO_N1)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:2]).hex(),
                         self.NEG_N2)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:3]).hex(),
                         self.NEG_N3)
        self.assertEqual(payload.input_block_v5b(self.neg_code()).hex(),
                         self.NEG_N4)

    def test_02_frames_drive_v5f_skip_idiom_gates(self):
        # every magic frame passes the filter ([r1+0xaa]=MAGIC16); the
        # skip-idiom gates then route on N: 2 -> L2 equality -> jump TAIL
        # (marker 2), 3 -> L3 equality -> jump TAIL (marker 3), 4 -> both
        # skips taken-at-false -> loop (marker 0), 1 -> depth-1 echo path
        for frame, n in ((self.ECHO_N1, 1), (self.NEG_N2, 2),
                         (self.NEG_N3, 3), (self.NEG_N4, 4)):
            b = bytes.fromhex(frame)
            self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0],
                             payload.MAGIC16)
            self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], n)

    def test_03_fallthrough_frame(self):
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)         # 36B window
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)  # no MAGIC16


class TestTrigV5G(unittest.TestCase):
    # T28 (v5g LINEAR fork-test): the TRIG frames are UNCHANGED vs
    # v5e/v5f — payload.py is untouched (input_block_v5b already
    # asserts N==len in [1..4]); v5g has NO gates, so every magic N in
    # {1..4} PROCEEDS linearly (loop xN, back-edge taken xN-1).  N=1 is
    # the byte-exact echo regression (clean-proven x2 lineage: v5e/v5f
    # echo-N1); N=2/3/4 = the input_block_v5b(neg) family (journal
    # task-25/27 hex) — 28/32/36B frames WITH payload tails.
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH
    ECHO_N1 = TestTrigV5E.ECHO_N1
    NEG_N2 = TestTrigV5E.NEG_N2
    NEG_N3 = TestTrigV5E.NEG_N3
    NEG_N4 = TestTrigV5E.NEG_N4

    def neg_code(self):
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                       # hi: 0x2407 -> 0x2406
        return neg

    def test_01_frames_byte_exact_neg_family(self):
        # N=1 byte-exact echo; N=2/3/4 = input_block_v5b(neg) family
        # byte-exact (the journal task-25/27 dispatch hex)
        self.assertEqual(payload.input_block_v5b([enc.ret_r(0, 0, 3)]).hex(),
                         self.ECHO_N1)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:2]).hex(),
                         self.NEG_N2)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:3]).hex(),
                         self.NEG_N3)
        self.assertEqual(payload.input_block_v5b(self.neg_code()).hex(),
                         self.NEG_N4)

    def test_02_frames_drive_v5g_linear_flow(self):
        # every magic frame passes the filter ([r1+0xaa]=MAGIC16); v5g
        # gates on NOTHING: N in {1,2,3,4} ALL proceed linearly into
        # dst-init + pair + loop xN (freeze-trigger fork: INPUT vs SKIP)
        for frame, n in ((self.ECHO_N1, 1), (self.NEG_N2, 2),
                         (self.NEG_N3, 3), (self.NEG_N4, 4)):
            b = bytes.fromhex(frame)
            self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0],
                             payload.MAGIC16)
            self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], n)
            self.assertIn(n, (1, 2, 3, 4))           # all-N acceptance

    def test_03_neg_family_tail_sizes(self):
        # the fork's INPUT variable: payload-tail bytes present for
        # N>=2 (28/32/36B frames) vs the 24B echo frame (no tail)
        self.assertEqual(len(bytes.fromhex(self.ECHO_N1)), 0x18)   # 24B
        self.assertEqual(len(bytes.fromhex(self.NEG_N2)), 0x1C)   # 28B
        self.assertEqual(len(bytes.fromhex(self.NEG_N3)), 0x20)   # 32B
        self.assertEqual(len(bytes.fromhex(self.NEG_N4)), 0x24)   # 36B

    def test_04_fallthrough_frame(self):
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)         # 36B window
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)  # no MAGIC16


class TestTrigV5H(unittest.TestCase):
    # T29 (v5h named-suspect SAVE test): the TRIG frames are UNCHANGED
    # vs v5g/v5f/v5e — payload.py is untouched (input_block_v5b already
    # asserts N==len in [1..4]); v5h gates on NOTHING (v5g shape minus
    # the save word): every magic N in {1..4} proceeds linearly (loop
    # xN, back-edge taken xN-1).  echo-N1 = the regression frame
    # (expect clean — the same shape ran clean live x3); neg-N2/3/4 =
    # the tail frames: clean => SAVE x TAIL named (the 0-combo save
    # word is the trigger; write-path FULLY rehabilitated -> v5i-C1);
    # freeze => deeper (pair/loop x tail-CONTENT — copied VALUES matter).
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH
    ECHO_N1 = TestTrigV5E.ECHO_N1
    NEG_N2 = TestTrigV5E.NEG_N2
    NEG_N3 = TestTrigV5E.NEG_N3
    NEG_N4 = TestTrigV5E.NEG_N4

    def neg_code(self):
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                       # hi: 0x2407 -> 0x2406
        return neg

    def test_01_frames_byte_exact_neg_family(self):
        # N=1 byte-exact echo; N=2/3/4 = input_block_v5b(neg) family
        # byte-exact (the journal task-25/27/28 dispatch hex)
        self.assertEqual(payload.input_block_v5b([enc.ret_r(0, 0, 3)]).hex(),
                         self.ECHO_N1)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:2]).hex(),
                         self.NEG_N2)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:3]).hex(),
                         self.NEG_N3)
        self.assertEqual(payload.input_block_v5b(self.neg_code()).hex(),
                         self.NEG_N4)

    def test_02_frames_drive_v5h_no_save_flow(self):
        # every magic frame passes the filter ([r1+0xaa]=MAGIC16); v5h
        # gates on NOTHING: N in {1,2,3,4} ALL proceed linearly into
        # dst-init + pair + loop xN (named-suspect test: SAVE x TAIL)
        for frame, n in ((self.ECHO_N1, 1), (self.NEG_N2, 2),
                         (self.NEG_N3, 3), (self.NEG_N4, 4)):
            b = bytes.fromhex(frame)
            self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0],
                             payload.MAGIC16)
            self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], n)
            self.assertIn(n, (1, 2, 3, 4))           # all-N acceptance

    def test_03_neg_family_tail_sizes(self):
        # the tail variable: payload-tail bytes present for N>=2
        # (28/32/36B frames) vs the 24B echo frame (no tail)
        self.assertEqual(len(bytes.fromhex(self.ECHO_N1)), 0x18)   # 24B
        self.assertEqual(len(bytes.fromhex(self.NEG_N2)), 0x1C)   # 28B
        self.assertEqual(len(bytes.fromhex(self.NEG_N3)), 0x20)   # 32B
        self.assertEqual(len(bytes.fromhex(self.NEG_N4)), 0x24)   # 36B

    def test_04_fallthrough_frame(self):
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)         # 36B window
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)  # no MAGIC16


class TestTrigV5I(unittest.TestCase):
    # T31 (v5i neutral-write discriminator): the TRIG frames are
    # UNCHANGED vs v5e/v5f/v5g/v5h — payload.py is untouched; v5i
    # gates on NOTHING and reads NOTHING from the code window (no
    # ld.d, no gauntlet): every magic N in {1..4} walks the IDENTICAL
    # path prefix+push+NEUTRAL-WRITE+marker+pop+jump.  echo-N1 = the
    # regression frame (expect clean — the same shape minus the copy
    # block ran clean live x4); neg-N2/3/4 = the tail frames: freeze
    # => H-FRAMEGUARD (ANY extra frame-write x tail-frame,
    # content-independent — the neutral constant froze too); clean =>
    # H-CONTENT (the copied VALUES were the trigger; neutral safe).
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH
    ECHO_N1 = TestTrigV5E.ECHO_N1
    NEG_N2 = TestTrigV5E.NEG_N2
    NEG_N3 = TestTrigV5E.NEG_N3
    NEG_N4 = TestTrigV5E.NEG_N4

    def neg_code(self):
        neg = list(payload.marker_lite())
        neg[0] ^= 0x00010000                       # hi: 0x2407 -> 0x2406
        return neg

    def test_01_frames_byte_exact_neg_family(self):
        # N=1 byte-exact echo; N=2/3/4 = input_block_v5b(neg) family
        # byte-exact (the journal task-25/27/28/29 dispatch hex)
        self.assertEqual(payload.input_block_v5b([enc.ret_r(0, 0, 3)]).hex(),
                         self.ECHO_N1)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:2]).hex(),
                         self.NEG_N2)
        self.assertEqual(payload.input_block_v5b(self.neg_code()[:3]).hex(),
                         self.NEG_N3)
        self.assertEqual(payload.input_block_v5b(self.neg_code()).hex(),
                         self.NEG_N4)

    def test_02_frames_drive_v5i_neutral_flow(self):
        # every magic frame passes the filter ([r1+0xaa]=MAGIC16); v5i
        # consumes NOTHING else from the frame: N is echoed (0x2384=N)
        # but never gates control, and the code-window bytes are never
        # read — the discriminator variable is purely tail-present vs
        # tail-absent on the wire.
        for frame, n in ((self.ECHO_N1, 1), (self.NEG_N2, 2),
                         (self.NEG_N3, 3), (self.NEG_N4, 4)):
            b = bytes.fromhex(frame)
            self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0],
                             payload.MAGIC16)
            self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], n)
            self.assertIn(n, (1, 2, 3, 4))           # all-N acceptance

    def test_03_neg_family_tail_sizes(self):
        # the discriminator variable: payload-tail bytes present on the
        # wire for N>=2 (28/32/36B frames) vs the 24B echo frame
        self.assertEqual(len(bytes.fromhex(self.ECHO_N1)), 0x18)   # 24B
        self.assertEqual(len(bytes.fromhex(self.NEG_N2)), 0x1C)   # 28B
        self.assertEqual(len(bytes.fromhex(self.NEG_N3)), 0x20)   # 32B
        self.assertEqual(len(bytes.fromhex(self.NEG_N4)), 0x24)   # 36B

    def test_04_code_window_inert_in_v5i(self):
        # v5i reads ONLY the halfwords [r1+0xaa] (filter) and [r1+0xa4]
        # (N echo): the stub's load words target exactly those offsets
        # — the neg-family code bytes (0x2406... lineage) are never
        # loaded, copied or decoded (stub-level: no ld.d words at all)
        import sys
        from pathlib import Path
        repo = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(repo / "scripts" / "s2"))
        stub_words = _build_s2().stub_words
        ws = stub_words("A", version=14)
        loads = [w for w in ws if (w >> 26) == 0x19]
        self.assertEqual(loads, [enc.ld_w(12, 1, 0xAA), enc.ld_w(13, 1, 0xA4)])
        for w in loads:
            self.assertTrue(w & 1)                  # 16-bit loads only

    def test_05_fallthrough_frame(self):
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)         # 36B window
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)  # no MAGIC16


class TestPayloadV5J(unittest.TestCase):
    # v5j rev.2 (Exit-C — T32 review) exec-from-input payload: 4 words
    # that EXECUTE IN-PLACE from the landing zone [r1+0xac..0xbc);
    # frame 36B (the STANDARD neg-frame size, all bytes k<=0x23 —
    # inside the T2 strictly-clean window, no corruption-zone
    # exposure).  Build of S2OK uses the SLASPEC INSERT semantics:
    # p0 `set3 r12,r12,0x4f4b` inserts the LO half, p1 `set2 r12,r12,
    # 0x5332` the HI half («build-hi») — r12 = 0x53324F4B
    # DETERMINISTICALLY.  p2 writes S2OK to CR 0x2388 (gate G5; the
    # v5a-live probe word) — the FULL C1 signal (rev.2 DROPS the rev.1
    # landing-echo st.d: S2OK self-validates).  p3 = `jump` to the
    # LIVE FN_A 0x98d964 (= file 0x18d964 + 0x800000 — review
    # Critical-1: rev.1 encoded the file-space target, off 0x800000)
    # from live PC r1+0xb8 (k=0x20) — POSITION-DEPENDENT on the
    # assumed stack base (default = SP-init cpu0 0x7d1ff8; the s24
    # immediate fits EVERY stack base 0x7d1ff8..0x7ffff8 — asserted
    # below with the worst-case margin).
    V5J_PAYLOAD = [
        0x218C4F4B,        # p0 set3 r12,r12,0x4f4b  (lo16 insert)
        0x258C5332,        # p1 set2 r12,r12,0x5332  (hi16 insert -> S2OK)
        0x6C04638A,        # p2 st.d r12,zero,0x2388 (S2OK, v5a-live word)
        0x9506EE2D,        # p3 jump 0x98d964 — LIVE FN_A (PC r1+0xb8, base 0x7d1ff8)
    ]

    def test_v5j_payload_golden_words(self):
        self.assertEqual(payload.payload_v5j(), self.V5J_PAYLOAD)

    def test_v5j_payload_word_forms(self):
        import sys
        from pathlib import Path
        repo = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(repo / "scripts" / "s2"))
        stub_words = _build_s2().stub_words
        ws = payload.payload_v5j()
        dec = [irisc_dis.dis(w, 0) for w in ws[:3]]
        self.assertEqual(dec[0], "set3 r12,r12,0x4f4b")
        self.assertEqual(dec[1], "set2 r12,r12,0x5332")
        self.assertEqual(dec[2], "st.d r12,zero,0x2388")
        self.assertEqual(irisc_dis.dis(ws[3], payload.R1_DEFAULT_V5J + payload.P3_PC_OFF_V5J),
                         "jump 0x98d964")
        self.assertEqual(ws[0], enc.set3(12, 12, 0x4F4B))
        self.assertEqual(ws[1] >> 26, 0x09)                  # set2 op
        self.assertEqual((ws[1] >> 21) & 0x1F, 12)           # rs = r12 (keeps lo)
        self.assertEqual((ws[1] >> 16) & 0x1F, 12)           # rd = r12
        self.assertEqual(ws[2], enc.st_d(12, 0, 0x2388))
        self.assertEqual((ws[3] >> 26), 0x25)                # jump
        self.assertEqual((ws[3] >> 24) & 1, 1)               # no link
        # the v2-marker hi/lo idiom, rd remapped to r12
        m = payload.marker(1, 2)
        self.assertEqual((m[0] >> 26), (ws[1] >> 26))        # set2
        self.assertEqual((m[1] >> 26), (ws[0] >> 26))        # set3
        # p2 is the v5a-live probe-3 word byte-exact
        self.assertIn(ws[2], stub_words("A", version=5))

    def test_v5j_payload_p3_targets_live_fn_a(self):
        # review Critical-1 (space correctness): the payload executes
        # at LIVE stack PCs, so the jump target must be the LIVE FN_A
        # (file 0x18d964 + 0x800000) — NOT the file-space address the
        # rev.1 builder encoded (0x18d964 from a live PC = 0x800000
        # low).  Cross-checked against build_s2's own FN_A.
        import sys
        from pathlib import Path
        repo = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(repo / "scripts" / "s2"))
        FN_A = _build_s2().FN_A
        ws = payload.payload_v5j()
        tgt = payload.R1_DEFAULT_V5J + payload.P3_PC_OFF_V5J + irisc_dis.s24(ws[3]) * 4
        self.assertEqual(tgt, 0x98D964)                      # LIVE FN_A
        self.assertEqual(tgt, 0x800000 + FN_A)               # == live build_s2 FN_A
        self.assertEqual(payload.FN_A_V5J, 0x18D964)         # file offset
        self.assertEqual(payload.PC_BASE_V5J, 0x800000)
        self.assertEqual(payload.FN_A_LIVE_V5J, 0x98D964)

    def test_v5j_payload_builds_s2ok_regardless_of_r12(self):
        # insert semantics: BOTH halves overwritten — the build is
        # invariant to the incoming r12 (lo AND hi garbage alike)
        for seed in (0x5332, 0, 0xFFFFFFFF, 0x12345678, 0x4F4B, 0x53324F4B):
            r = seed & 0xFFFFFFFF
            r = (r & ~0xFFFF) | 0x4F4B                       # p0 set3 lo16
            r = (r & 0xFFFFFFFF0000FFFF) | (0x5332 << 16)    # p1 set2 hi16
            self.assertEqual(r, 0x53324F4B, f"seed 0x{seed:x}")

    def test_v5j_payload_jump_parametrized(self):
        # p3 lands on the LIVE FN_A from ANY assumed base (the
        # immediate is recomputed); the default frame uses
        # R1_DEFAULT_V5J
        for base in (0x1000, 0x7D1FF8, 0x7D3FF8, 0x7E9FF8, 0x7FFFF8):
            ws = payload.payload_v5j(base)
            tgt = base + payload.P3_PC_OFF_V5J + irisc_dis.s24(ws[3]) * 4
            self.assertEqual(tgt, payload.FN_A_LIVE_V5J, f"base 0x{base:x}")
        self.assertNotEqual(payload.payload_v5j(0x1000)[3],
                            payload.payload_v5j()[3])        # imm depends on base

    def test_v5j_payload_p3_s24_fits_all_stack_bases(self):
        # rev.2 mandate: the p3 immediate fits s24 for EVERY stack
        # base 0x7d1ff8..0x7ffff8 (dense step-8 sweep over the whole
        # SP-init range).  Worst case = the SMALLEST base (largest
        # positive immediate); the margin to the s24 ceiling is
        # asserted exactly.
        imms = []
        for base in range(payload.R1_MIN_V5J, payload.R1_MAX_V5J + 1, 8):
            ws = payload.payload_v5j(base)
            diff = payload.FN_A_LIVE_V5J - (base + payload.P3_PC_OFF_V5J)
            self.assertEqual(diff % 4, 0, f"base 0x{base:x}: unaligned diff")
            imm = irisc_dis.s24(ws[3])
            self.assertEqual(imm, diff // 4, f"base 0x{base:x}: imm mismatch")
            self.assertTrue(-0x800000 <= imm <= 0x7FFFFF, f"base 0x{base:x}: s24 overflow")
            tgt = base + payload.P3_PC_OFF_V5J + imm * 4
            self.assertEqual(tgt, payload.FN_A_LIVE_V5J, f"base 0x{base:x}: target")
            imms.append(imm)
        self.assertEqual(max(imms), 0x6EE2D)                 # min base 0x7d1ff8
        self.assertEqual(min(imms), 0x6362D)                 # max base 0x7ffff8
        self.assertEqual(0x7FFFFF - max(imms), 0x7911D2)     # worst-case s24 margin (words)

    def test_v5j_payload_rejects_bad_landing(self):
        # fail-loud (ruling R8): u32 + 4-aligned (the jump encoding
        # needs whole-word steps) + s24 reachable
        with self.assertRaises(AssertionError):
            payload.payload_v5j(-1)
        with self.assertRaises(AssertionError):
            payload.payload_v5j(1 << 32)
        with self.assertRaises(AssertionError):
            payload.payload_v5j(0x1002)                      # unaligned
        with self.assertRaises(AssertionError):
            payload.payload_v5j(0)
        with self.assertRaisesRegex(AssertionError, "s24"):
            payload.payload_v5j(0x4000000)                   # imm cannot fit s24


class TestTrigV5J(unittest.TestCase):
    # T32 rev.2 TRIG frames: v5j has NO N-guard and NO gauntlet — EVERY
    # magic frame TRANSFERS into the landing, so the ONLY safe magic
    # frame is the FULL 36B TRIG (4-word payload; the lineage's 24B
    # echo / 28-32B neg frames would land p0 + garbage — NOT valid
    # v5j inputs).  The frame is neg-SHAPE (v5b layout: opcode /
    # pads / N@0xC / MAGIC16@0x12 / code@0x14..) with the payload at
    # k=0x14..0x24 — the STANDARD neg-frame size (36B), fully inside
    # the T2 strictly-clean window (transfer window ceiling 0x38):
    # NO byte at k>=0x24 (the corruption zone) — the rev.1 40B
    # novelty is gone, review Important-3 moot.  N=4 in the header is
    # ECHOED (0x2384=N) and NEVER used for control.
    TRIG = ("0932000000000000000000000004000000005332"
            "218c4f4b258c53326c04638a9506ee2d")
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH                     # 36B, no magic

    def test_01_trig_frame_byte_exact(self):
        self.assertEqual(payload.input_block_v5j().hex(), self.TRIG)

    def test_02_trig_frame_layout(self):
        b = bytes.fromhex(self.TRIG)
        self.assertEqual(len(b), 0x24)                        # 36B standard frame
        self.assertEqual(b[0:4], struct.pack(">I", payload.OPCODE_V5B))
        self.assertEqual(b[4:0xC], b"\x00" * 8)               # validator pads
        self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)   # N=4 (echo only)
        self.assertEqual(b[0xE:0x12], b"\x00" * 4)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
        self.assertEqual(list(struct.unpack(">4I", b[0x14:0x24])),
                         payload.payload_v5j())

    def test_03_fallthrough_frame_unchanged(self):
        # the non-magic regression frame is the lineage 36B fallthrough
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)

    def test_04_parametrized_base_changes_only_p3(self):
        a = payload.input_block_v5j()
        c = payload.input_block_v5j(landing_r1=0x7D3FF8)
        self.assertEqual(len(a), len(c))
        self.assertEqual(a[:0x20], c[:0x20])                  # p0..p2 identical
        self.assertNotEqual(a[0x20:0x24], c[0x20:0x24])      # only p3 differs

    def test_05_no_short_magic_frame(self):
        # documented: v5j accepts exactly ONE magic frame shape — the
        # full 36B TRIG (the builder emits nothing else; there is no
        # N-parameter to shrink)
        self.assertEqual(len(payload.input_block_v5j()), 0x24)


class TestPayloadV5K(unittest.TestCase):
    # v5k rev.2 (T33-review 40d902a fix) exec-from-input payload: 4
    # words that EXECUTE IN-PLACE from the landing zone [r1+0xac..0xbc)
    # — frame 36B (the STANDARD neg-frame size, all bytes k<=0x23 —
    # inside the T2 strictly-clean window).  Fix 1 (exact S2OK): p0 =
    # `set3 r12,ZERO,0x4f4b` — the live ROOT-CAUSE of the v5j lo16
    # anomaly (journal task-32 phase-2) is set3's OR semantics:
    # incoming r12=0x5332 filter residue ORed 0x5332|0x4F4B = 0x5F7B
    # == the observed CR value EXACTLY; rs=zero makes lo16 =
    # 0x0000|0x4F4B CLEAN under BOTH insert and OR semantics.  p1 =
    # `set2 r12,r12,0x5332` UNCHANGED (the live-exact v5j word).  p2
    # writes S2OK to CR 0x2388 (the FULL C1 signal, self-validating).
    # Fix 2 (rev.2 — stub-side epilogue replica): p3 = `ret.r
    # zero,r8,r3` (0xFD001825, THE canonical return word, stock
    # x8346, byte-exact fn 0x0e4250's own final word @0x0e430c) —
    # exits THROUGH r3, which the STUB's w10/w11 preloaded with the
    # ABSOLUTE live address of the replica block (stub zone —
    # base-independent by construction; the payload never touches
    # r3).  The replica (stub w13-w22) executes the fn's own
    # epilogue: restores r17-r23, pops the 0xf8 frame, reads the
    # OUTER [R+4] (the dispatcher ra the prologue saved @0x0e4254)
    # and returns — livelock (rev.1 Critical-1) and the r17-r23 leak
    # (Important-2) are both GONE by design.  NO word encodes ANY
    # stack absolute — the payload is BASE-INDEPENDENT by
    # construction (one fixed frame serves every SP base).
    V5K_PAYLOAD = [
        0x200C4F4B,        # p0 set3 r12,zero,0x4f4b  (lo16 CLEAN — rs=zero)
        0x258C5332,        # p1 set2 r12,r12,0x5332    (hi16 insert, live-exact)
        0x6C04638A,        # p2 st.d r12,zero,0x2388   (S2OK, v5a-live word)
        0xFD001825,        # p3 ret.r zero,r8,r3       (canonical return, stock x8346)
    ]

    def test_v5k_payload_golden_words(self):
        self.assertEqual(payload.payload_v5k(), self.V5K_PAYLOAD)

    def test_v5k_payload_word_forms(self):
        import sys
        from pathlib import Path
        repo = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(repo / "scripts" / "s2"))
        stub_words = _build_s2().stub_words
        ws = payload.payload_v5k()
        dec = [irisc_dis.dis(w, 0) for w in ws]
        self.assertEqual(dec[0], "set3 r12,zero,0x4f4b")
        self.assertEqual(dec[1], "set2 r12,r12,0x5332")
        self.assertEqual(dec[2], "st.d r12,zero,0x2388")
        self.assertEqual(dec[3], "ret.r zero,r8,r3")
        self.assertEqual(ws[0], enc.set3(12, 0, 0x4F4B))
        self.assertEqual(ws[1] >> 26, 0x09)                  # set2 op
        self.assertEqual((ws[1] >> 21) & 0x1F, 12)           # rs = r12 (keeps lo)
        self.assertEqual((ws[1] >> 16) & 0x1F, 12)           # rd = r12
        self.assertEqual(ws[2], enc.st_d(12, 0, 0x2388))
        self.assertEqual(ws[3], enc.ret_r(8, 0, 3))
        # p2 is the v5a-live probe-3 word byte-exact
        self.assertIn(ws[2], stub_words("A", version=5))

    def test_v5k_payload_p0_rs_zero_lo16_clean(self):
        # THE Fix-1 contract: p0's SOURCE is the zero register (rs=0)
        # — under the live OR semantics the built lo16 is
        # 0x0000|imm = imm CLEAN (and under slaspec insert it is
        # trivially imm) — from ANY incoming r12 (the v5j anomaly
        # witness: the rs=rd form ORed the 0x5332 filter residue in,
        # 0x5332|0x4F4B = 0x5F7B == the observed live CR value).
        # NON-VACUOUS form (T33-review minor): the WRONG (rs=rd) form
        # is modeled with the seed FLOWING through it — seed-
        # dependent garbage, the live residue reproducing 0x5F7B —
        # while the v5k form is clean for every seed.
        ws = payload.payload_v5k()
        self.assertEqual((ws[0] >> 21) & 0x1F, 0)            # rs = ZERO
        self.assertEqual((ws[0] >> 16) & 0x1F, 12)           # rd = r12
        self.assertNotEqual((ws[0] >> 21) & 0x1F, 12)        # NOT rs=rd (v5j form)
        # anomaly witness: the OR model reproduces the live value
        self.assertEqual(0x5332 | 0x4F4B, 0x5F7B)

        def build_v5j_form(seed):
            # p0 `set3 r12,r12,imm` (the WRONG rs=rd form): the source
            # IS r12 — the seed flows through and leaks into the build
            r = (seed & 0xFFFF0000) | ((seed & 0xFFFF) | 0x4F4B)
            r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (0x5332 << 16))
            return r

        def build_v5k_form(seed):
            # p0 `set3 r12,ZERO,imm` (the v5k form): the source is the
            # ZERO register — architecturally 0 whatever r12 (= seed) holds
            src = 0
            r = (src & 0xFFFF0000) | ((src & 0xFFFF) | 0x4F4B)
            r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (0x5332 << 16))
            return r

        # the v5k form builds S2OK EXACT for every seed; the v5j form
        # is seed-DEPENDENT and misses (the live residue 0x5332
        # reproducing the observed 0x53325F7B CR anomaly exactly)
        for seed in (0x5332, 0, 0xFFFFFFFF, 0x12345678, 0x5F7B, 0x53325F7B):
            self.assertEqual(build_v5k_form(seed), 0x53324F4B,
                             f"seed 0x{seed:x}")
            if (seed & 0xFFFF) not in (0x4F4B, 0):
                self.assertNotEqual(build_v5j_form(seed), 0x53324F4B,
                                    f"seed 0x{seed:x}: v5j form must leak")
        self.assertEqual(build_v5j_form(0x5332), 0x53325F7B)  # live anomaly
        self.assertEqual(build_v5j_form(0x5332) >> 16, 0x5332)  # hi landed exact

    def test_v5k_payload_base_independent_no_jump_words(self):
        # THE Fix-2 structural contract: NO op-0x25 word (no jump, no
        # call — nothing encodes an absolute or PC-relative target);
        # payload_v5k() takes NO parameters (the v5j landing_r1 param
        # and its s24 sweep are gone) — one fixed word list for every
        # SP base; the only control word is the p3 register return.
        import inspect
        ws = payload.payload_v5k()
        self.assertEqual([w >> 26 for w in ws], [0x08, 0x09, 0x1B, 0x3F])
        self.assertFalse(any((w >> 26) == 0x25 for w in ws))
        self.assertEqual(inspect.signature(payload.payload_v5k).parameters, {})
        self.assertEqual(inspect.signature(payload.input_block_v5k).parameters, {})
        self.assertEqual(payload.payload_v5k(), payload.payload_v5k())  # fixed

    def test_v5k_payload_p3_canonical_return_word(self):
        # p3 = 0xFD001825 — THE canonical return (stock x8346, live
        # on every completion) and BYTE-EXACT the FINAL word of fn
        # 0x0e4250's own epilogue @0x0e430c (the T33-review corrected
        # attribution: the fn's epilogue pair is ld.d r3,r1,0x4
        # @0x0e4308 + ret.r @0x0e430c — the pairing load is the
        # replica's w21; the family idiom also appears @0x0e4734/
        # 0x0e4738).  Cross-checked against the stock base image code
        # section and the census blob.
        import sys
        from pathlib import Path
        repo = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(repo / "scripts" / "probes"))
        sys.path.insert(0, str(repo))
        from iron_boot_probe import decrc
        import mlxfwutil
        ws = payload.payload_v5k()
        self.assertEqual(ws[3], 0xFD001825)
        self.assertEqual((ws[3] >> 21) & 0x1F, 8)            # rs = r8 (no-link)
        self.assertEqual((ws[3] >> 11) & 0x1F, 3)            # rt = r3
        blob = repo / "build" / "ghidra-4030cda-main03-ac-dc.bin"
        if not blob.exists():
            self.skipTest("stock blob not present")
        words = struct.unpack(">%dI" % (len(blob.read_bytes()) // 4),
                              blob.read_bytes())
        self.assertEqual(sum(1 for w in words if w == 0xFD001825), 8346)
        src = (repo / "build" / "4030-cda-patched3.bin").read_bytes()
        img = mlxfwutil.Image(src, "base")
        code = decrc(img.section_data(img.find_entry("ITOC", 0x03)))
        w = lambda a: struct.unpack_from(">I", code, a)[0]
        self.assertEqual(w(0x0E4308), 0x64230006)            # fn epilogue ld.d
        self.assertEqual(w(0x0E430C), 0xFD001825)            # fn final ret.r
        self.assertEqual(w(0x0E430C), ws[3])                 # p3 byte-exact
        self.assertEqual(w(0x0E4734), 0x64230006)            # family idiom too
        self.assertEqual(w(0x0E4738), 0xFD001825)

    def test_v5k_payload_budget(self):
        ws = payload.payload_v5k()
        self.assertEqual(len(ws), payload.PAYLOAD_MAX_V5K)
        self.assertEqual(payload.PAYLOAD_MAX_V5K, 4)         # k=0x14..0x24


class TestTrigV5K(unittest.TestCase):
    # T33 TRIG frames: v5k has NO N-guard and NO gauntlet — EVERY
    # magic frame TRANSFERS into the landing, so the ONLY safe magic
    # frame is the FULL 36B TRIG (4-word payload; the lineage's 24B
    # echo / 28-32B neg frames would land p0 + garbage — NOT valid
    # v5k inputs).  The frame is neg-SHAPE (v5b layout: opcode /
    # pads / N@0xC / MAGIC16@0x12 / code@0x14..) with the payload at
    # k=0x14..0x24 — the STANDARD neg-frame size (36B), fully inside
    # the T2 strictly-clean window.  N=4 in the header is ECHOED
    # (0x2384=N) and NEVER used for control (the journal's N=4
    # choice kept — documented).  THE v5k novelty: ONE fixed frame
    # for ALL stack bases (no base parameter — the payload words are
    # base-independent; the v5j frame was single-base).
    TRIG = ("0932000000000000000000000004000000005332"
            "200c4f4b258c53326c04638afd001825")
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH                     # 36B, no magic

    def test_01_trig_frame_byte_exact(self):
        self.assertEqual(payload.input_block_v5k().hex(), self.TRIG)

    def test_02_trig_frame_layout(self):
        b = bytes.fromhex(self.TRIG)
        self.assertEqual(len(b), 0x24)                        # 36B standard frame
        self.assertEqual(b[0:4], struct.pack(">I", payload.OPCODE_V5B))
        self.assertEqual(b[4:0xC], b"\x00" * 8)               # validator pads
        self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)   # N=4 (echo only)
        self.assertEqual(b[0xE:0x12], b"\x00" * 4)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
        self.assertEqual(list(struct.unpack(">4I", b[0x14:0x24])),
                         payload.payload_v5k())

    def test_03_fallthrough_frame_unchanged(self):
        # the non-magic regression frame is the lineage 36B fallthrough
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)

    def test_04_one_frame_all_bases(self):
        # THE v5k novelty: input_block_v5k() takes NO base parameter
        # — the SAME 36B bytes are the TRIG frame at EVERY SP base
        # (contrast v5j: input_block_v5j(landing_r1=...) rebuilt p3
        # per base).  Frame bytes contain no stack absolute: the
        # only absolute-looking word (0xfd001825) is the canonical
        # RETURN word, not an address.
        frame = payload.input_block_v5k()
        self.assertEqual(len(frame), 0x24)
        self.assertNotIn(b"\x7d\x1f\xf8", frame)              # no stack bytes
        self.assertNotIn(b"\xf8\xff\x7d", frame)
        words = list(struct.unpack(">4I", frame[0x14:0x24]))
        for k in range(16):
            base = 0x7D1FF8 + k * 0x2000
            self.assertEqual(words, payload.payload_v5k(),
                             f"base 0x{base:x}: words must be the FIXED list")

    def test_05_no_short_magic_frame(self):
        # documented: v5k accepts exactly ONE magic frame shape — the
        # full 36B TRIG (the builder emits nothing else; there is no
        # N-parameter to shrink)
        self.assertEqual(len(payload.input_block_v5k()), 0x24)


class TestPayloadV5L(unittest.TestCase):
    # v5l (task-34, journal task-33 phase-2 grounding) exec-from-input
    # payload: 4 words — THE SAME WORDS AS v5k (Fix 1 exact-S2OK build
    # + canonical p3), NEW EXIT SEMANTICS: p3 `ret.r zero,r8,r3' (the
    # canonical return, stock x8346) returns THROUGH r3, which the
    # v5l STUB's w10/w11 preloaded with 0x008E4380 — THE CALL-SITE
    # RESUME (live = file 0x0E437C detour call + 4; the value csr0xbc
    # holds at detour entry; the value stock FN_A returns through —
    # FN_A's own prologue `csr.r r3,csr0xbc' @0x18d964 is byte-exact
    # the stub's w0).  The payload RETURNS INTO THE FN BODY at the
    # resume point, as FN_A's return would: the body marshals r4
    # (stock decode 0x0E4380 `or r19,r4,r4' — our r4=0, the
    # v5i-documented stock arg value `addi r4,zero,0' @0x0E4374),
    # builds the QUERY completion, reaches its OWN epilogue (the
    # r17-r23 restores + the 0xf8 pop + the outer-[R+4] return the
    # v5k replica tried to synthesize — now executed BY the fn's own
    # words on HW) — stock completion.  The payload never touches r3
    # (the preload survives to p3); NO word encodes ANY stack
    # absolute — base-independent by construction.
    V5L_PAYLOAD = [
        0x200C4F4B,        # p0 set3 r12,zero,0x4f4b  (lo16 CLEAN — rs=zero)
        0x258C5332,        # p1 set2 r12,r12,0x5332    (hi16 insert, live-exact)
        0x6C04638A,        # p2 st.d r12,zero,0x2388   (S2OK, v5a-live word)
        0xFD001825,        # p3 ret.r zero,r8,r3       (canonical return, stock x8346)
    ]

    def test_v5l_payload_golden_words(self):
        self.assertEqual(payload.payload_v5l(), self.V5L_PAYLOAD)

    def test_v5l_payload_word_forms(self):
        ws = payload.payload_v5l()
        dec = [irisc_dis.dis(w, 0) for w in ws]
        self.assertEqual(dec[0], "set3 r12,zero,0x4f4b")
        self.assertEqual(dec[1], "set2 r12,r12,0x5332")
        self.assertEqual(dec[2], "st.d r12,zero,0x2388")
        self.assertEqual(dec[3], "ret.r zero,r8,r3")
        self.assertEqual(ws[0], enc.set3(12, 0, 0x4F4B))
        self.assertEqual(ws[1] >> 26, 0x09)                  # set2 op
        self.assertEqual((ws[1] >> 21) & 0x1F, 12)           # rs = r12 (keeps lo)
        self.assertEqual((ws[1] >> 16) & 0x1F, 12)           # rd = r12
        self.assertEqual(ws[2], enc.st_d(12, 0, 0x2388))
        self.assertEqual(ws[3], enc.ret_r(8, 0, 3))

    def test_v5l_payload_words_equal_v5k_new_semantics(self):
        # THE v5l payload contract: the WORD LIST is UNCHANGED vs v5k
        # (p0/p1/p2 the live-proven exact-S2OK build; p3 the canonical
        # return) — the semantics change lives in the STUB (r3 preload
        # = the call-site resume instead of the replica address).  The
        # live v5k phase-2 already PROVED these 4 words execute 4/4
        # with CR 0x2388 = 0x53324F4B EXACT.
        self.assertEqual(payload.payload_v5l(), payload.payload_v5k())

    def test_v5l_payload_p3_returns_into_fn_body(self):
        # THE cross-module contract: p3 returns through r3, and the
        # v5l STUB's w10/w11 build r3 = 0x8E4380 = THE CALL-SITE
        # RESUME = PC_BASE + DETOUR_DC + 4 (build_s2's own constants);
        # the payload never writes r3 between the transfer and p3
        # (word-form proof: no p-word has rd=r3).
        build_s2 = _build_s2()
        ws = payload.payload_v5l()
        stub = build_s2.stub_words("A", version=17)
        self.assertEqual(ws[3], 0xFD001825)
        self.assertEqual((ws[3] >> 21) & 0x1F, 8)            # rs = r8 (no-link)
        self.assertEqual((ws[3] >> 11) & 0x1F, 3)            # rt = r3
        # the resume target, re-derived from the stub build words
        lo = stub[10] & 0xFFFF
        hi = stub[11] & 0xFFFF
        for model in ("or", "insert"):
            r = (0 & 0xFFFF0000) | lo                        # set3 rs=zero
            r = (r & 0x0000FFFF) | ((r & 0xFFFF0000) | (hi << 16))  # set2
            self.assertEqual(r, 0x008E4380, model)
        self.assertEqual(0x008E4380,
                         build_s2.PC_BASE + build_s2.DETOUR_DC + 4)
        # no payload word writes r3 (the preload survives)
        for w in ws[:3]:
            self.assertNotEqual((w >> 16) & 0x1F, 3, f"0x{w:08x} writes r3")

    def test_v5l_payload_base_independent_no_jump_words(self):
        # THE structural contract: NO op-0x25 word (no jump, no call
        # — nothing encodes an absolute or PC-relative target);
        # payload_v5l() takes NO parameters — one fixed word list for
        # every SP base; the only control word is the p3 register
        # return.
        import inspect
        ws = payload.payload_v5l()
        self.assertEqual([w >> 26 for w in ws], [0x08, 0x09, 0x1B, 0x3F])
        self.assertFalse(any((w >> 26) == 0x25 for w in ws))
        self.assertEqual(inspect.signature(payload.payload_v5l).parameters, {})
        self.assertEqual(inspect.signature(payload.input_block_v5l).parameters, {})
        self.assertEqual(payload.payload_v5l(), payload.payload_v5l())  # fixed

    def test_v5l_payload_budget(self):
        ws = payload.payload_v5l()
        self.assertEqual(len(ws), payload.PAYLOAD_MAX_V5L)
        self.assertEqual(payload.PAYLOAD_MAX_V5L, 4)         # k=0x14..0x24


class TestTrigV5L(unittest.TestCase):
    # T34 TRIG frames: v5l has NO N-guard and NO gauntlet — EVERY
    # magic frame TRANSFERS into the landing, so the ONLY safe magic
    # frame is the FULL 36B TRIG (4-word payload).  The frame is
    # neg-SHAPE (v5b layout: opcode / pads / N@0xC / MAGIC16@0x12 /
    # code@0x14..) with the payload at k=0x14..0x24 — the STANDARD
    # neg-frame size (36B), fully inside the T2 strictly-clean
    # window.  N=4 in the header is ECHOED (0x2384=N) and NEVER used
    # for control.  ONE fixed frame for ALL stack bases (the payload
    # words are base-independent; the v5l exit is the ABSOLUTE
    # call-site resume — also base-independent).
    TRIG = ("0932000000000000000000000004000000005332"
            "200c4f4b258c53326c04638afd001825")
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH                     # 36B, no magic

    def test_01_trig_frame_byte_exact(self):
        self.assertEqual(payload.input_block_v5l().hex(), self.TRIG)

    def test_02_trig_frame_layout(self):
        b = bytes.fromhex(self.TRIG)
        self.assertEqual(len(b), 0x24)                        # 36B standard frame
        self.assertEqual(b[0:4], struct.pack(">I", payload.OPCODE_V5B))
        self.assertEqual(b[4:0xC], b"\x00" * 8)               # validator pads
        self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)   # N=4 (echo only)
        self.assertEqual(b[0xE:0x12], b"\x00" * 4)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
        self.assertEqual(list(struct.unpack(">4I", b[0x14:0x24])),
                         payload.payload_v5l())

    def test_03_trig_bytes_equal_v5k_frame(self):
        # documented identity: the v5l frame bytes == the v5k frame
        # bytes (same 4 payload words, same header) — the live-proven
        # v5k TRIG delivery (frame on card byte-exact, S2OK exact)
        # carries over UNCHANGED; only the burnt stub differs.
        self.assertEqual(payload.input_block_v5l(), payload.input_block_v5k())

    def test_04_fallthrough_frame_unchanged(self):
        # the non-magic regression frame is the lineage 36B fallthrough
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)

    def test_05_one_frame_all_bases(self):
        # input_block_v5l() takes NO base parameter — the SAME 36B
        # bytes are the TRIG frame at EVERY SP base.  Frame bytes
        # contain no stack absolute: the only absolute-looking word
        # (0xfd001825) is the canonical RETURN word, not an address.
        frame = payload.input_block_v5l()
        self.assertEqual(len(frame), 0x24)
        self.assertNotIn(b"\x7d\x1f\xf8", frame)              # no stack bytes
        self.assertNotIn(b"\xf8\xff\x7d", frame)
        words = list(struct.unpack(">4I", frame[0x14:0x24]))
        for k in range(16):
            base = 0x7D1FF8 + k * 0x2000
            self.assertEqual(words, payload.payload_v5l(),
                             f"base 0x{base:x}: words must be the FIXED list")

    def test_06_no_short_magic_frame(self):
        # documented: v5l accepts exactly ONE magic frame shape — the
        # full 36B TRIG (the builder emits nothing else; there is no
        # N-parameter to shrink)
        self.assertEqual(len(payload.input_block_v5l()), 0x24)


class TestPayloadV5M(unittest.TestCase):
    # v5m (task-2, mode "B") payload: THE SAME 4 WORDS AS v5l (Task-1
    # verdict: «Payload — 4 слова без изменений (p0–p2 S2OK, p3
    # resume)») — mode B lives ENTIRELY in the burnt stub (the m2
    # WRITE-POST block).  The POST buf r1+0xb0 exfils input[0x18..0x58)
    # = p1..p3 + stack tail BEFORE the payload executes (pristine TRIG
    # bytes); the key C = [r1+0xac]|0xff = p0|0xff = 0x200C4FFF.
    V5M_PAYLOAD = [
        0x200C4F4B,        # p0 set3 r12,zero,0x4f4b  (lo16 CLEAN — rs=zero)
        0x258C5332,        # p1 set2 r12,r12,0x5332    (hi16 insert, live-exact)
        0x6C04638A,        # p2 st.d r12,zero,0x2388   (S2OK, v5a-live word)
        0xFD001825,        # p3 ret.r zero,r8,r3       (canonical return, stock x8346)
    ]
    C_KEY = 0x200C4F4B | 0xFF                     # the m2 key: p0|0xff

    def test_v5m_payload_golden_words(self):
        self.assertEqual(payload.payload_v5m(), self.V5M_PAYLOAD)

    def test_v5m_payload_word_forms(self):
        ws = payload.payload_v5m()
        dec = [irisc_dis.dis(w, 0) for w in ws]
        self.assertEqual(dec[0], "set3 r12,zero,0x4f4b")
        self.assertEqual(dec[1], "set2 r12,r12,0x5332")
        self.assertEqual(dec[2], "st.d r12,zero,0x2388")
        self.assertEqual(dec[3], "ret.r zero,r8,r3")
        self.assertEqual(ws[0], enc.set3(12, 0, 0x4F4B))
        self.assertEqual(ws[1] >> 26, 0x09)                  # set2 op
        self.assertEqual((ws[1] >> 21) & 0x1F, 12)           # rs = r12 (keeps lo)
        self.assertEqual((ws[1] >> 16) & 0x1F, 12)           # rd = r12
        self.assertEqual(ws[2], enc.st_d(12, 0, 0x2388))
        self.assertEqual(ws[3], enc.ret_r(8, 0, 3))

    def test_v5m_payload_words_equal_v5l(self):
        # THE v5m payload contract: the WORD LIST is UNCHANGED vs v5l
        # (the live-proven exact-S2OK build + the canonical p3 return
        # into the fn body) — the mode-B difference lives in the STUB.
        self.assertEqual(payload.payload_v5m(), payload.payload_v5l())

    def test_v5m_payload_p3_returns_into_fn_body(self):
        # THE cross-module contract: p3 returns through r3, and the
        # v5m STUB's w17/w18 build r3 = 0x8E4380 = THE CALL-SITE
        # RESUME = PC_BASE + DETOUR_DC + 4 (build_s2's own constants);
        # the payload never writes r3 between the transfer and p3.
        build_s2 = _build_s2()
        ws = payload.payload_v5m()
        stub = build_s2.stub_words("B", version=18)
        self.assertEqual(ws[3], 0xFD001825)
        self.assertEqual((ws[3] >> 21) & 0x1F, 8)            # rs = r8 (no-link)
        self.assertEqual((ws[3] >> 11) & 0x1F, 3)            # rt = r3
        self.assertEqual(stub[17] & 0xFFFF, 0x4380)          # w17 lo
        self.assertEqual(stub[18] & 0xFFFF, 0x008E)          # w18 hi
        for model in ("or", "insert"):
            r = (0 & 0xFFFF0000) | (stub[17] & 0xFFFF)       # set3 rs=zero
            r = (r & 0x0000FFFF) | ((r & 0xFFFF0000)
                                    | ((stub[18] & 0xFFFF) << 16))  # set2
            self.assertEqual(r, 0x008E4380, model)
        self.assertEqual(0x008E4380,
                         build_s2.PC_BASE + build_s2.DETOUR_DC + 4)
        self.assertEqual(build_s2.RESUME_LIVE, 0x008E4380)
        for w in ws[:3]:
            self.assertNotEqual((w >> 16) & 0x1F, 3, f"0x{w:08x} writes r3")

    def test_v5m_payload_base_independent_no_jump_words(self):
        # structural contract: NO op-0x25 word (no jump, no call — the
        # payload NEVER calls: the m2 call lives in the STUB); no
        # parameters — one fixed word list for every SP base.
        import inspect
        ws = payload.payload_v5m()
        self.assertEqual([w >> 26 for w in ws], [0x08, 0x09, 0x1B, 0x3F])
        self.assertFalse(any((w >> 26) == 0x25 for w in ws))
        self.assertEqual(inspect.signature(payload.payload_v5m).parameters, {})
        self.assertEqual(inspect.signature(payload.input_block_v5m).parameters, {})
        self.assertEqual(payload.payload_v5m(), payload.payload_v5m())

    def test_v5m_payload_budget(self):
        ws = payload.payload_v5m()
        self.assertEqual(len(ws), payload.PAYLOAD_MAX_V5M)
        self.assertEqual(payload.PAYLOAD_MAX_V5M, 4)         # k=0x14..0x24

    def test_v5m_c_key_from_first_payload_word(self):
        # the m2 POST key derives from the FRAME itself: C = p0|0xff
        # (documented constant for the Task-3 live gate — the tool's
        # buffer-scan marker protocol)
        self.assertEqual(self.C_KEY, 0x200C4FFF)
        self.assertEqual(payload.payload_v5m()[0] | 0xFF, self.C_KEY)


class TestTrigV5M(unittest.TestCase):
    # T02 TRIG frames: the v5m magic frame is the UNCHANGED 36B v5l
    # TRIG (same header + the same 4 payload words — the mode-B delta
    # is the burnt stub only); every magic frame POSTs AND transfers,
    # so the full TRIG is the ONLY safe magic shape.  The m2 POST
    # exfils [r1+0xb0..0xf0) = p1..p3 + stack tail to host X1; the
    # Task-3 live gate scans the tool buffers for the p1..p3 marker
    # bytes (STOP-protocol: no marker in tool memory => STOP).
    TRIG = ("0932000000000000000000000004000000005332"
            "200c4f4b258c53326c04638afd001825")
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH                     # 36B, no magic

    def test_01_trig_frame_byte_exact(self):
        self.assertEqual(payload.input_block_v5m().hex(), self.TRIG)

    def test_02_trig_frame_layout(self):
        b = bytes.fromhex(self.TRIG)
        self.assertEqual(len(b), 0x24)                        # 36B standard frame
        self.assertEqual(b[0:4], struct.pack(">I", payload.OPCODE_V5B))
        self.assertEqual(b[4:0xC], b"\x00" * 8)               # validator pads
        self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)   # N=4 (echo only)
        self.assertEqual(b[0xE:0x12], b"\x00" * 4)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
        self.assertEqual(list(struct.unpack(">4I", b[0x14:0x24])),
                         payload.payload_v5m())

    def test_03_trig_bytes_equal_v5l_frame(self):
        # documented identity: the v5m frame bytes == the v5l frame
        # bytes (the live-proven v5l TRIG delivery carries over; only
        # the burnt stub differs)
        self.assertEqual(payload.input_block_v5m(), payload.input_block_v5l())

    def test_04_fallthrough_frame_unchanged(self):
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)

    def test_05_one_frame_all_bases(self):
        # input_block_v5m() takes NO base parameter — the SAME 36B
        # bytes at EVERY SP base; no stack absolute in the frame.
        frame = payload.input_block_v5m()
        self.assertEqual(len(frame), 0x24)
        self.assertNotIn(b"\x7d\x1f\xf8", frame)              # no stack bytes
        self.assertNotIn(b"\xf8\xff\x7d", frame)
        words = list(struct.unpack(">4I", frame[0x14:0x24]))
        for k in range(16):
            base = 0x7D1FF8 + k * 0x2000
            self.assertEqual(words, payload.payload_v5m(),
                             f"base 0x{base:x}: words must be the FIXED list")

    def test_06_no_short_magic_frame(self):
        # v5m accepts exactly ONE magic frame shape — the full 36B
        # TRIG (every magic frame POSTs and transfers)
        self.assertEqual(len(payload.input_block_v5m()), 0x24)


class TestPayloadV5N(unittest.TestCase):
    # v5n (plan-2 s2b2, mode "B" — m2' X1-from-p0): p0 = w (DATA — the
    # X1 base, w = IOVA>>6 of the output mailbox; the stub's m2' block
    # builds X1 = (0x8FC0<<32)|(w<<6) from it and calls the DIRECT
    # transport 0x2ae98), p1..p3 = the v5m marker VERBATIM (the
    # delivery target: S2OK build + the fn-body return).  p0 decodes
    # to a HARMLESS addi (op 0x00, rd/rs in {0,2} — T1 P0_SAFE: r2 is
    # caller-saved, the post-resume body has ZERO r2 uses).
    V5N_PAYLOAD = [
        0x00428B90,        # p0 = w (out_mb0): addi r2,r2,0x-7470 (P0_SAFE)
        0x258C5332,        # p1 set2 r12,r12,0x5332    (== v5m p1, verbatim)
        0x6C04638A,        # p2 st.d r12,zero,0x2388   (== v5m p2)
        0xFD001825,        # p3 ret.r zero,r8,r3       (== v5m p3)
    ]
    X1 = {"out_mb0": 0x8FC010A2E400,
          "in_mb0": 0x8FC010A2E000,
          "cqe": 0x8FC010000000}

    def test_v5n_payload_golden_words(self):
        self.assertEqual(payload.payload_v5n(0x428B90), self.V5N_PAYLOAD)

    def test_v5n_default_w_out_mb0(self):
        self.assertEqual(payload.payload_v5n(), self.V5N_PAYLOAD)

    def test_v5n_p1_p3_verbatim_v5m(self):
        # THE marker contract: p1..p3 == v5m p1..p3 byte-exact
        # (the marker — the delivery target — is untouched)
        self.assertEqual(payload.payload_v5n()[1:], payload.payload_v5m()[1:])

    def test_v5n_all_candidates(self):
        for name, w in payload.V5N_W_CANDIDATES.items():
            ws = payload.payload_v5n(w)
            self.assertEqual(len(ws), 4, name)
            self.assertEqual(ws[0], w, name)
            self.assertEqual(ws[1:], payload.payload_v5m()[1:], name)

    def test_v5n_sp_guard(self):
        # p0 = w must NEVER touch r1 (the stack pointer): a decoded
        # rd==1 or rs==1 is rejected fail-loud
        for bad in (0x1 << 16, 0x1 << 21,
                    (0x1 << 16) | 0x8000,
                    (0x1 << 21) | (0x2 << 16)):
            with self.assertRaises(AssertionError):
                payload.payload_v5n(bad)

    def test_v5n_rejects_zero_and_high(self):
        # w must stay in the op-0x00 (addi) domain: 0 and
        # w >= 0x4000000 are rejected
        for bad in (0, 0x4000000, 0x428B90 | 0x4000000):
            with self.assertRaises(AssertionError):
                payload.payload_v5n(bad)

    def test_v5n_p0_candidates_decode_harmless_addi(self):
        # P0_SAFE: every candidate decodes to op 0x00 addi with
        # rd/rs in {0,2} — the r2 clobber is harmless (T1 r2-census
        # over the body [0x0E4380..0x0E4424)); cqe leaves r2 alone
        for w in payload.V5N_W_CANDIDATES.values():
            self.assertEqual(w >> 26, 0x00)                     # op addi
            self.assertIn((w >> 16) & 0x1F, (0, 2))             # rd
            self.assertIn((w >> 21) & 0x1F, (0, 2))             # rs
        # exact irisc_dis output (signed imm16 rendering)
        self.assertEqual(irisc_dis.dis(0x00428B90, 0), "addi r2,r2,0x-7470")
        self.assertEqual(irisc_dis.dis(0x00428B80, 0), "addi r2,r2,0x-7480")
        self.assertEqual(irisc_dis.dis(0x00400000, 0), "addi zero,r2,0x0")

    def test_v5n_x1(self):
        # X1(w) = (0x8FC0<<32) | (w<<6) — 64B-aligned by construction
        # (w = IOVA>>6), so (X1 & 0x3F) = 0
        for name, w in payload.V5N_W_CANDIDATES.items():
            self.assertEqual((0x8FC0 << 32) | (w << 6), self.X1[name])
            self.assertEqual(self.X1[name] & 0x3F, 0)


class TestTrigV5N(unittest.TestCase):
    # the v5n TRIG frame (36B): the UNCHANGED header + payload p0 = w
    # (0x428B90) + p1..p3 the v5m marker verbatim.  last byte k=0x23
    # — inside the strictly-clean window.
    TRIG = ("0932000000000000000000000004000000005332"
            "00428b90258c53326c04638afd001825")
    FALLTHROUGH = TestTrigV5E.FALLTHROUGH                     # 36B, no magic

    def test_01_trig_frame_byte_exact(self):
        self.assertEqual(payload.trig_v5n(0x428B90).hex(), self.TRIG)

    def test_02_trig_frame_layout(self):
        b = payload.trig_v5n()
        self.assertEqual(len(b), 0x24)                        # 36B, k=0x23 last
        self.assertEqual(b[0:4], struct.pack(">I", payload.OPCODE_V5B))
        self.assertEqual(b[4:0xC], b"\x00" * 8)               # validator pads
        self.assertEqual(struct.unpack(">H", b[0xC:0xE])[0], 4)   # N=4
        self.assertEqual(b[0xE:0x12], b"\x00" * 4)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], payload.MAGIC16)
        self.assertEqual(list(struct.unpack(">4I", b[0x14:0x24])),
                         TestPayloadV5N.V5N_PAYLOAD)

    def test_03_p0_is_w(self):
        # p0 = w: the frame carries the candidate VALUE, not code
        b = payload.trig_v5n(0x428B90)
        self.assertEqual(struct.unpack(">I", b[0x14:0x18])[0], 0x428B90)
        b2 = payload.trig_v5n(0x428B80)
        self.assertEqual(struct.unpack(">I", b2[0x14:0x18])[0], 0x428B80)
        b3 = payload.trig_v5n(0x400000)
        self.assertEqual(struct.unpack(">I", b3[0x14:0x18])[0], 0x400000)

    def test_04_fallthrough_frame_unchanged(self):
        b = bytes.fromhex(self.FALLTHROUGH)
        self.assertEqual(len(self.FALLTHROUGH), 72)
        self.assertEqual(struct.unpack(">H", b[0x12:0x14])[0], 0)


class TestTrigV5O(unittest.TestCase):
    # v5o (plan-3 s2b2, mode "B" — ladder A.2 candidate 1: in_mb0):
    # TRIG = trig_v5n(w) with w = 0x428B80 (IOVA in_mb0 = 0x10A2E000,
    # 2-session-attested).  The Б.6 precomputed frame is pinned here
    # (verified 2026-10-03: trig_v5n(0x428B90) reproduces the burnt
    # v5n frame byte-exact — the only diff vs v5n is the p0 word).
    W = 0x428B80
    X1 = 0x8FC010A2E000
    TRIG_V5O = ("0932000000000000000000000004000000005332"
                "00428b80258c53326c04638afd001825")

    def test_01_trig_v5o_byte_exact(self):
        self.assertEqual(payload.trig_v5n(self.W).hex(), self.TRIG_V5O)
        self.assertEqual(len(self.TRIG_V5O), 72)

    def test_02_x1_in_mb0_guard(self):
        self.assertEqual((0x8FC0 << 32) | (self.W << 6), self.X1)
        self.assertEqual(self.X1 & 0x3F, 0)

    def test_03_p0_safe_decode(self):
        # P0_SAFE (plan-2 T1, all candidates covered): op 0x00 addi,
        # rd/rs = 2 — harmless r2 clobber
        self.assertEqual(self.W >> 26, 0x00)
        self.assertIn((self.W >> 16) & 0x1F, (0, 2))
        self.assertIn((self.W >> 21) & 0x1F, (0, 2))
        self.assertEqual(irisc_dis.dis(0x00428B80, 0),
                         "addi r2,r2,0x-7480")


if __name__ == "__main__":
    unittest.main()
