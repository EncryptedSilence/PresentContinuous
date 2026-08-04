"""The lin444 linear layer and the column form that both pipelines consume."""

import unittest

from present_sat import linear, model, slp, variants


class TestLin444(unittest.TestCase):
    def test_matches_the_shiftgen2_definition(self):
        """Word-wise, against a transcription of ShiftGen2's lin444_r1."""
        def rotl(a, c):
            c %= 16
            return ((a << c) | (a >> (16 - c))) & 0xFFFF if c else a

        c0 = [2, 9, 7]
        state = 0x0123456789ABCDEF
        d = [(state >> (16 * w)) & 0xFFFF for w in range(4)]
        o = [0] * 4
        o[0] = d[0] ^ rotl(d[1], c0[0]) ^ rotl(d[2], c0[1]) ^ rotl(d[3], c0[2])
        o[1] = d[1] ^ rotl(d[2], c0[0]) ^ rotl(d[3], c0[1]) ^ rotl(o[0], c0[2])
        o[2] = d[2] ^ rotl(d[3], c0[0]) ^ rotl(o[0], c0[1]) ^ rotl(o[1], c0[2])
        o[3] = d[3] ^ rotl(o[0], c0[0]) ^ rotl(o[1], c0[1]) ^ rotl(o[2], c0[2])
        want = sum(o[w] << (16 * w) for w in range(4))

        self.assertEqual(linear.lin444(state, c0), want)

    def test_invertible_for_every_c0(self):
        """It is unitriangular over GF(2), so no c0 can make it singular."""
        for c0 in [(0, 0, 0), (0, 1, 3), (2, 9, 7), (15, 15, 15), (1, 0, 8)]:
            fwd, inv = linear.build({"type": "lin444", "word_bits": 16, "c0": list(c0)})
            self.assertFalse(linear.is_permutation_columns(fwd) and c0 != (0, 0, 0))
            for i in range(64):
                self.assertEqual(linear.apply_columns(inv, fwd[i]), 1 << i, c0)

    def test_c000_is_the_only_permutation_case(self):
        """With all rotations zero every word XORs into the next, still not a permutation."""
        fwd, _ = linear.build({"type": "lin444", "word_bits": 16, "c0": [0, 0, 0]})
        self.assertFalse(linear.is_permutation_columns(fwd))

    def test_density_of_the_shipped_constants(self):
        for c0 in ([2, 9, 7], [0, 1, 3]):
            fwd, _ = linear.build({"type": "lin444", "word_bits": 16, "c0": c0})
            self.assertAlmostEqual(linear.density(fwd), 8.75)

    def test_rejects_out_of_range_constants(self):
        with self.assertRaises(ValueError):
            linear.validate_spec({"type": "lin444", "word_bits": 16, "c0": [0, 1, 16]}, "x")
        with self.assertRaises(ValueError):
            linear.validate_spec({"type": "nope", "word_bits": 16, "c0": [0, 1, 3]}, "x")


class TestVariantIntegration(unittest.TestCase):
    def test_pbox_variants_have_single_bit_columns(self):
        v = variants.get("present-80")
        self.assertTrue(v.is_permutation_layer)
        self.assertTrue(linear.is_permutation_columns(v.lin_cols))
        self.assertEqual(v.lin_cols, [1 << p for p in v.pbox])

    def test_lin444_variants_are_not_permutations(self):
        for name in ("present-80-lin444-297", "present-80-lin444-013"):
            v = variants.get(name)
            self.assertFalse(v.is_permutation_layer)
            self.assertIsNone(v.pbox)
            self.assertFalse(linear.is_permutation_columns(v.lin_cols))

    def test_the_model_encodes_a_non_permutation_layer(self):
        """The rows are the transpose of the column form, and must reproduce it."""
        import random
        for name in ("present-80-lin444-297", "present-80-lin444-1-15-13", "present-80"):
            v = variants.get(name)
            rows = model.linear_layer_rows(v)
            random.seed(11)
            for _ in range(200):
                x = random.getrandbits(64)
                got = sum(1 << i for i in range(64)
                          if sum((x >> j) & 1 for j in rows[i]) & 1)
                self.assertEqual(got, linear.apply_columns(v.lin_cols, x), name)

    def test_a_permutation_layer_costs_nothing_to_encode(self):
        """The classical PRESENT encoding, recovered rather than special-cased."""
        v = variants.get("present-80")
        self.assertTrue(all(len(r) == 1 for r in model.linear_layer_rows(v)))
        m = model.build(v, 2, model.MODE_ACTIVE)
        # 64 input bits + 2 x (64 S-box outputs + 16 activity flags), no layer vars
        self.assertEqual(m.cnf.nv, 64 + 2 * (64 + 16))

    def test_a_variant_needs_exactly_one_layer_definition(self):
        common = dict(sbox=list(range(16)), rounds=31, key_bits=80, key_schedule="present80")
        both = variants.Variant(name="both", pbox=list(range(64)),
                                linear={"type": "lin444", "word_bits": 16, "c0": [0, 1, 3]},
                                **common)
        with self.assertRaises(ValueError):
            both.validate()
        neither = variants.Variant(name="neither", **common)
        with self.assertRaises(ValueError):
            neither.validate()


class TestXorCost(unittest.TestCase):
    """The bitsliced XOR count is a function of the constants, not a constant.

    Two descriptions of the layer have to agree: the closed form in slp.form(),
    which is what the C cost model and the ShiftGen2 sweep use, and the search in
    slp.build(), which enumerates every shared pair of operands and emits the
    program tools/gen_c.py compiles. Every program is checked against lin444
    itself on all 64 basis vectors, so a cost here is backed by a construction
    rather than by an argument.
    """

    ALL = [(x, y, z) for x in range(16) for y in range(16) for z in range(16)]

    ROT = lambda self, x, c: ((x << (c % 16)) | (x >> ((16 - c) % 16))) & 0xFFFF

    def _split(self, s):
        return [(s >> (16 * w)) & 0xFFFF for w in range(4)]

    def test_cost_tiers(self):
        """Three sharing conditions, and how many triples each one catches.

        c == a + b buys three shared pairs; b == 2a and the arithmetic progression
        buy two each. They are independent conditions that overlap, which is why
        the tiers are not 256/512/3328: the 160 tier is what is left of the two
        two-sharing families once the ones that also satisfy c == a + b have been
        promoted to 144.
        """
        by_cost = {}
        for c in self.ALL:
            by_cost.setdefault(linear.lin444_cost(c), []).append(c)
        self.assertEqual(sorted(by_cost), [144, 160, 192])
        self.assertEqual([len(by_cost[k]) for k in (192, 160, 144)], [3360, 480, 256])
        for c in by_cost[144]:
            self.assertEqual(c[2] % 16, (c[0] + c[1]) % 16)

    def test_decryption_tiers_are_the_mirror_image(self):
        """The inverse recovers the last word first, so a and c swap roles."""
        for c in self.ALL:
            a, b, z = c
            self.assertEqual(slp.inv_cost(c), slp.cost((z, b, a)), c)

    def test_the_search_agrees_with_the_closed_form_everywhere(self):
        """All 4096 triples, both directions: same count, and it computes lin444.

        slp.programs() raises if the search and the closed form disagree, and
        verifies both programs against linear.lin444 / lin444_inv on every basis
        vector -- so this is the whole cross-check, run exhaustively.
        """
        for c in self.ALL:
            (_fwd, n_fwd), (_inv, n_inv) = slp.programs(c)
            self.assertEqual(n_fwd, linear.lin444_cost(c), c)
            self.assertEqual(n_inv, slp.inv_cost(c), c)

    def _geo_form(self, s, a):
        """128 XORs: four shared temporaries, valid only for c = (a, 2a, 3a)."""
        R = self.ROT
        d = self._split(s)
        V = d[2] ^ R(d[3], a)          # 16
        Y = d[1] ^ R(V, a)             # 16
        o0 = d[0] ^ R(Y, a)            # 16
        o1 = Y ^ R(o0, 3 * a)          # 16, reuses the whole tail of o0's chain
        X = o0 ^ R(o1, a)              # 16
        o2 = V ^ R(X, 2 * a)           # 16, reuses V directly
        o3 = d[3] ^ R(X, a) ^ R(o2, 3 * a)   # 32
        return sum(w << (16 * i) for i, w in enumerate((o0, o1, o2, o3)))

    def test_the_geometric_family_beats_the_generator_and_it_does_not_matter(self):
        """A known gap, pinned down so it stays known.

        The search only shares *pairs* of operands. c = (a, 2a, 3a) admits reuse of
        whole chains and reaches 128, below the 144 the generator finds. Nothing
        implements it: every triple in that family diffuses badly -- run
        tools/shiftgen_present and compare the a2 column -- so no usable constants
        live there and the missing tier costs nothing.
        """
        states = [0, 1, 1 << 63, 0x0123456789ABCDEF, 0xFEDCBA9876543210]
        for a in range(16):
            c = (a, (2 * a) % 16, (3 * a) % 16)
            self.assertEqual(linear.lin444_cost(c), 144, c)
            for s in states:
                self.assertEqual(self._geo_form(s, a), linear.lin444(s, c, 16),
                                 f"128-XOR form disagrees at a={a}, state={s:#x}")

    def test_shipped_variants_declare_the_cost_their_constants_imply(self):
        for name, enc, dec in (("present-80-lin444-297", 192, 192),
                               ("present-80-lin444-013", 192, 192),
                               ("present-80-lin444-1-15-13", 160, 160),
                               ("present-80-lin444-213", 144, 192)):
            c = variants.get(name).linear["c0"]
            self.assertEqual(linear.lin444_cost(c), enc, name)
            self.assertEqual(slp.inv_cost(c), dec, name)


if __name__ == "__main__":
    unittest.main()
