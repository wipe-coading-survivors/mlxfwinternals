import os
import subprocess
import unittest

import pytest

BIN = os.environ.get("CH34X_FRAMES_BIN", "")
if not BIN:
    pytest.skip("ch34x_frames binary not built", allow_module_level=True)


class GoldenFrames(unittest.TestCase):
    """T2: байтовая точность диаг-бинаря ch34x_frames (C-билдер, патч
    1.5). Ожидаемые кадры — независимые константы: канон CH347T —
    tests/test_ch347_frames.py (live-подтверждённые векторы W1/T6),
    ch341-фрейминг чтения — по образцу ch341i2c.py build_read_frames
    (head + IN-продолжения ≤30 Б, IN|0-хвост), ch341-лимиты записи —
    кадр ≤16 Б / после OUT ≤11 Б. Политика записи: v1-кадр как есть,
    при превышении лимита — выровненные mwrite4 (сплит), невыровненное —
    RMW (O10: dword-квантование вниз); сохранённые байты RMW —
    placeholder 00 (diag без шины)."""

    GOLDEN = {
        ("mread4", "ch347"): [
            "aa 74 85 90 00 0f 00 14 74 81 91 c3 c0 75 00"],
        ("mread4", "ch341"): [
            "aa 74 85 90 00 0f 00 14 74 81 91 c3 c0 75 00"],
        ("mwrite4", "ch347"): [
            "aa 74 89 90 00 0f 00 14 12 34 56 78 75 00"],
        ("mwrite4", "ch341"): [
            "aa 74 89 90 00 0f 00 14 12 34 56 78 75 00"],
        ("read_block64", "ch347"): [
            "aa 74 85 90 00 0f 00 14 74 81 91 ff c0 75 00"],
        ("read_block64", "ch341"): [
            "aa 74 85 90 00 0f 00 14 74 81 91 d4 00",
            "aa de 00",
            "aa cd c0 75 00"],
        ("write_block16_gw", "ch347"): [
            "aa 74 95 90 00 0f 04 10 10 11 12 13 14 15 16 17"
            " 18 19 1a 1b 1c 1d 1e 1f 75 00"],
        ("write_block16_gw", "ch341"): [
            "aa 74 89 90 00 0f 04 10 10 11 12 13 75 00",
            "aa 74 89 90 00 0f 04 14 14 15 16 17 75 00",
            "aa 74 89 90 00 0f 04 18 18 19 1a 1b 75 00",
            "aa 74 89 90 00 0f 04 1c 1c 1d 1e 1f 75 00"],
        ("write_block16_split", "ch347"): [
            "aa 74 89 90 00 0f 04 10 10 11 12 13 75 00",
            "aa 74 89 90 00 0f 04 14 14 15 16 17 75 00",
            "aa 74 89 90 00 0f 04 18 18 19 1a 1b 75 00",
            "aa 74 89 90 00 0f 04 1c 1c 1d 1e 1f 75 00"],
        ("write_block16_split", "ch341"): [
            "aa 74 89 90 00 0f 04 10 10 11 12 13 75 00",
            "aa 74 89 90 00 0f 04 14 14 15 16 17 75 00",
            "aa 74 89 90 00 0f 04 18 18 19 1a 1b 75 00",
            "aa 74 89 90 00 0f 04 1c 1c 1d 1e 1f 75 00"],
        ("probe_0x48", "ch347"): [
            "aa 74 80 90 75 00"],
        ("probe_0x48", "ch341"): [
            "aa 74 80 90 75 00"],
        ("set_speed_400k", "ch347"): [
            "aa 62 00"],
        ("set_speed_400k", "ch341"): [
            "aa 62 00"],
        ("write_unaligned_rm", "ch347"): [
            "aa 74 85 90 00 0f 04 10 74 81 91 c3 c0 75 00",
            "aa 74 89 90 00 0f 04 10 00 00 12 13 75 00",
            "aa 74 89 90 00 0f 04 14 14 15 16 17 75 00"],
        ("write_unaligned_rm", "ch341"): [
            "aa 74 85 90 00 0f 04 10 74 81 91 c3 c0 75 00",
            "aa 74 89 90 00 0f 04 10 00 00 12 13 75 00",
            "aa 74 89 90 00 0f 04 14 14 15 16 17 75 00"],
    }

    def run_scenario(self, scenario, profile):
        out = subprocess.run(
            [BIN, scenario, "--profile", profile],
            capture_output=True, text=True, check=True)
        return [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]

    def test_golden_frames(self):
        for (scenario, profile), expected in sorted(self.GOLDEN.items()):
            with self.subTest(scenario=scenario, profile=profile):
                self.assertEqual(self.run_scenario(scenario, profile),
                                 expected)


if __name__ == "__main__":
    unittest.main()
