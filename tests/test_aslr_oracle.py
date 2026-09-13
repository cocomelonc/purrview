import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("aslr_oracle", ROOT / "tools" / "aslr_oracle.py")
ORACLE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ORACLE)

SAMPLE_MAPS = """\
7abcabc00000-7abcabc01000 r--p 00000000 fd:03 1111  /data/app/~~x/lab.purrview-y/lib/arm64/libpurrview.so
7abcabc01000-7abcabc05000 r-xp 00001000 fd:03 1111  /data/app/~~x/lab.purrview-y/lib/arm64/libpurrview.so
7abcabc05000-7abcabc06000 r--p 00005000 fd:03 1111  /data/app/~~x/lab.purrview-y/lib/arm64/libpurrview.so
7abcabc06000-7abcabc07000 rw-p 00006000 fd:03 1111  /data/app/~~x/lab.purrview-y/lib/arm64/libpurrview.so
7abcabc10000-7abcabc90000 r-xp 00000000 fd:03 2222  /system/lib64/libc.so
7fff00000000-7fff00021000 rw-p 00000000 00:00 0     [anon:libc_malloc]
"""


class AslrOracleParsingTests(unittest.TestCase):
    def test_finds_lowest_segment_as_base(self):
        base = ORACLE.parse_library_base(SAMPLE_MAPS, "libpurrview.so")
        self.assertEqual(base, 0x7ABCABC00000)

    def test_ignores_unrelated_libraries_and_anon_mappings(self):
        self.assertIsNone(ORACLE.parse_library_base(SAMPLE_MAPS, "libmissing.so"))
        base = ORACLE.parse_library_base(SAMPLE_MAPS, "libc.so")
        self.assertEqual(base, 0x7ABCABC10000)

    def test_pid_matching_is_exact_or_worker_suffixed(self):
        lines = [
            "USER   PID  PPID VSIZE  RSS   WCHAN  ADDR S NAME",
            "u0_a1  100  1     1000  1000  0      0    S lab.purrview",
            "u0_a1  101  1     1000  1000  0      0    S lab.purrview:png_decoder",
            "u0_a2  102  1     1000  1000  0      0    S lab.purrview.evil",
            "u0_a3  103  1     1000  1000  0      0    S other.app",
        ]
        ps_output = "\n".join(lines) + "\n"

        class FakeResult:
            returncode = 0
            stdout = ps_output
            stderr = ""

        calls = []

        def fake_run_adb(args, adb_bin, serial, timeout):
            calls.append(args)
            return FakeResult()

        original = ORACLE.run_adb
        ORACLE.run_adb = fake_run_adb
        try:
            pids = ORACLE.find_pids("lab.purrview", "adb", None, 5.0)
        finally:
            ORACLE.run_adb = original
        self.assertEqual(sorted(pids), [(100, "lab.purrview"), (101, "lab.purrview:png_decoder")])


class AslrOracleSimulationTests(unittest.TestCase):
    def test_simulate_is_deterministic_and_bounded(self):
        first = ORACLE.simulate_offline()
        second = ORACLE.simulate_offline()
        self.assertEqual(first, second)
        _, address, page = first
        self.assertEqual(address, ORACLE.TOY_BASE | (page << 12))
        self.assertLessEqual(page, 0xFFF)


if __name__ == "__main__":
    unittest.main()
