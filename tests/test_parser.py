import ctypes
import importlib.util
import random
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('samples', ROOT / 'tools/generate_samples.py')
samples = importlib.util.module_from_spec(spec)
spec.loader.exec_module(samples)

class ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        lib = Path(cls.tmp.name) / 'parser.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', str(ROOT / 'app/src/main/cpp/parser.c'), '-lz', '-o', str(lib)], check=True)
        cls.lib = ctypes.CDLL(str(lib))
        cls.lib.inspect_png.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        cls.lib.inspect_png.restype = ctypes.c_int
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def parse(self, data, fixed=False):
        out = ctypes.create_string_buffer(1024)
        buf = ctypes.create_string_buffer(data)
        return self.lib.inspect_png(buf, len(data), fixed, out, len(out)), out.value.decode()
    def test_normal(self):
        for fixed in (False, True): self.assertEqual(self.parse(samples.png(64,64), fixed)[0], 0)
    def test_bypass_and_fix(self):
        data = samples.png(256,64)
        status, detail = self.parse(data)
        self.assertEqual(status, 1)
        self.assertIn('Required: 65536', detail)
        self.assertIn('Checked: 0', detail)
        self.assertEqual(self.parse(data, True)[0], 2)
    def test_threshold(self):
        self.assertEqual(self.parse(samples.png(128,64), True)[0], 0)
        self.assertEqual(self.parse(samples.png(129,64), True)[0], 2)
    def test_crc(self):
        data = bytearray(samples.png(64,64)); data[29] ^= 1
        self.assertIn('CRC mismatch', self.parse(bytes(data))[1])
    def test_truncations(self):
        data = samples.png(64,64)
        for n in range(len(data)): self.assertEqual(self.parse(data[:n])[0], -1)
    def test_trailing_bytes(self): self.assertEqual(self.parse(samples.png(64,64)+b'x')[0], -1)
    def test_random_inputs(self):
        rng = random.Random(42)
        for _ in range(1000): self.assertEqual(self.parse(rng.randbytes(rng.randrange(0,512)))[0], -1)
    def test_dimensions(self):
        import struct
        for w,h in [(0,1),(1,0),(16385,1),(0xffffffff,0xffffffff)]:
            data = b'\x89PNG\r\n\x1a\n' + samples.chunk(b'IHDR', struct.pack('>IIBBBBB',w,h,8,6,0,0,0))
            self.assertEqual(self.parse(data)[0], -1)

if __name__ == '__main__': unittest.main()
