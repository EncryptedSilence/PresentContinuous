import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cipher_set  # noqa: E402


class TestCipherSet(unittest.TestCase):
    def test_resolve_returns_seven_ciphers_with_expected_rounds(self):
        got = {name: rounds for _, name, rounds in cipher_set.resolve()}
        self.assertEqual(got, {
            "present-80-r16": 16,
            "present-80-lin444-297-r7": 7,
            "cipher-D": 8,
            "cipher-D-lin444-297-r5": 5,
            "cipher-D-lin444-297-aes-r5": 5,
            "aes-r5": 5,
            "aes-lin444-0-8-15-r4": 4,
        })

    def test_every_variant_file_exists(self):
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        for path, _, _ in cipher_set.resolve():
            self.assertTrue(os.path.isfile(os.path.join(root, path)), path)

    def test_gen_fpga_reexports_the_same_set(self):
        import gen_fpga
        self.assertEqual(gen_fpga.DEFAULT_VARIANTS, cipher_set.DEFAULT_VARIANTS)
        self.assertEqual(gen_fpga.FPGA_VARIANT_OVERRIDES, cipher_set.VARIANT_OVERRIDES)


if __name__ == "__main__":
    unittest.main()
