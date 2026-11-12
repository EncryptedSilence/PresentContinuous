import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cipher_set  # noqa: E402


class TestCipherSet(unittest.TestCase):
    def test_resolve_returns_seven_ciphers_with_expected_rounds(self):
        with mock.patch.dict(os.environ, {cipher_set.CIPHER_SET_ENV: ""}):
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

    def test_full_set_is_present80_r31_and_aes128_r10(self):
        with mock.patch.dict(os.environ, {cipher_set.CIPHER_SET_ENV: "full"}):
            got = [(name, rounds, cipher_set.family(name, path))
                   for path, name, rounds in cipher_set.resolve()]
        self.assertEqual(got, [("present-80", 31, "narrow"), ("aes-128", 10, "aes")])

    def test_unknown_set_is_refused(self):
        with mock.patch.dict(os.environ, {cipher_set.CIPHER_SET_ENV: "bogus"}):
            with self.assertRaises(SystemExit):
                cipher_set.resolve()

    def test_every_variant_file_exists(self):
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        for path, _, _ in cipher_set.resolve():
            self.assertTrue(os.path.isfile(os.path.join(root, path)), path)

    def test_gen_fpga_reexports_the_same_set(self):
        import gen_fpga
        self.assertIs(gen_fpga.DEFAULT_VARIANTS, cipher_set.DEFAULT_VARIANTS)
        self.assertIs(gen_fpga.FPGA_VARIANT_OVERRIDES, cipher_set.VARIANT_OVERRIDES)

    def test_committed_ctr_header_matches_the_generator(self):
        """bench/gen/ctr_cipher_set.h is committed, so it can go stale by hand.

        The Makefile regenerates it before building the CTR harness, which means
        a hand-edited copy is silently overwritten rather than reported. This
        says so out loud instead, and is the guard that the seven names and two
        round counts the harness compiles against are still cipher_set.resolve()'s.
        """
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        path = os.path.join(root, "bench", "gen", "ctr_cipher_set.h")
        self.assertTrue(os.path.isfile(path), path)
        with open(path) as fh:
            self.assertEqual(
                fh.read(), cipher_set.ctr_header(),
                "bench/gen/ctr_cipher_set.h is stale; regenerate with "
                "`make bench/gen/ctr_cipher_set.h`")

    def test_ctr_header_carries_every_cipher_and_round_count(self):
        header = cipher_set.ctr_header()
        for _, name, rounds in cipher_set.resolve():
            self.assertIn(f'"{name}", {rounds}, ', header, name)
        self.assertIn(f"#define CTR_CIPHER_COUNT {len(cipher_set.resolve())}", header)


if __name__ == "__main__":
    unittest.main()
