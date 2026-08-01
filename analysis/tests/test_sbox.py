"""S-box property computations, checked against known values for PRESENT."""

import unittest

from present_sat import sbox as sboxlib
from present_sat import variants

PRESENT_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]


class TestSboxProperties(unittest.TestCase):
    def test_present_sbox_is_optimal(self):
        self.assertTrue(sboxlib.is_permutation(PRESENT_SBOX, 4))
        self.assertEqual(sboxlib.differential_uniformity(PRESENT_SBOX), 4)
        self.assertEqual(sboxlib.linearity(PRESENT_SBOX), 8)
        self.assertTrue(sboxlib.is_optimal_4bit(PRESENT_SBOX))

    def test_present_sbox_branch_number_is_three(self):
        # A design criterion of PRESENT: it is what gives the 10-active-S-boxes-in-
        # 5-rounds bound its strength.
        self.assertEqual(sboxlib.branch_number(PRESENT_SBOX, 4), 3)

    def test_inverse_round_trips(self):
        inv = sboxlib.inverse(PRESENT_SBOX)
        for x in range(16):
            self.assertEqual(inv[PRESENT_SBOX[x]], x)

    def test_ddt_rows_sum_to_size(self):
        d = sboxlib.ddt(PRESENT_SBOX)
        for row in d:
            self.assertEqual(sum(row), 16)
        self.assertEqual(d[0][0], 16)

    def test_identity_has_uniformity_16(self):
        ident = list(range(16))
        self.assertEqual(sboxlib.differential_uniformity(ident), 16)


class TestWeightModel(unittest.TestCase):
    def test_present_weights(self):
        wm = sboxlib.WeightModel(PRESENT_SBOX, 4)
        self.assertTrue(wm.exact)
        self.assertEqual(wm.weights_used, [0, 2, 3])
        self.assertEqual(wm.min_active_weight(), 2)
        self.assertEqual(wm.transitions[(0, 0)], 0)

    def test_only_zero_to_zero_has_weight_zero(self):
        wm = sboxlib.WeightModel(PRESENT_SBOX, 4)
        zeros = [k for k, w in wm.transitions.items() if w == 0]
        self.assertEqual(zeros, [(0, 0)])

    def test_transitions_match_ddt_support(self):
        wm = sboxlib.WeightModel(PRESENT_SBOX, 4)
        d = sboxlib.ddt(PRESENT_SBOX)
        for a in range(16):
            for b in range(16):
                self.assertEqual((a, b) in wm.transitions, d[a][b] > 0)


class TestShippedVariants(unittest.TestCase):
    def test_all_variants_validate(self):
        vs = variants.load_all()
        self.assertGreater(len(vs), 0)
        for v in vs:
            v.validate()
            self.assertEqual(sboxlib.inverse(sboxlib.inverse(v.sbox)), v.sbox)

    def test_reference_variant_matches_the_specification(self):
        v = variants.get("present-80")
        self.assertEqual(v.sbox, PRESENT_SBOX)
        self.assertEqual(v.pbox, variants.present_pbox())
        self.assertEqual(v.rounds, 31)
        self.assertEqual(v.key_bits, 80)

    def test_variant_names_are_unique(self):
        names = [v.name for v in variants.load_all()]
        self.assertEqual(len(names), len(set(names)))

    def test_rejects_a_non_permutation_sbox(self):
        v = variants.get("present-80")
        broken = variants.Variant(name="broken", sbox=[0] * 16, pbox=v.pbox,
                                  rounds=31, key_bits=80, key_schedule="present80")
        with self.assertRaises(ValueError):
            broken.validate()

    def test_rejects_mismatched_key_size(self):
        v = variants.get("present-80")
        broken = variants.Variant(name="broken", sbox=v.sbox, pbox=v.pbox,
                                  rounds=31, key_bits=128, key_schedule="present80")
        with self.assertRaises(ValueError):
            broken.validate()


if __name__ == "__main__":
    unittest.main()
