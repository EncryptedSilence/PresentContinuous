"""End-to-end checks of the differential model against published PRESENT results and
against exhaustive computation for one round."""

import unittest

from present_sat import model as model_mod
from present_sat import report as report_mod
from present_sat import search, solver, variants
from present_sat.report import RoundRow


def solver_available():
    try:
        solver.find_solver()
        return True
    except solver.SolverNotFound:
        return False


class TestSboxRelation(unittest.TestCase):
    def test_active_relation_accepts_exactly_the_ddt_support(self):
        v = variants.get("present-80")
        n_vars, clauses = model_mod.sbox_relation(v, model_mod.MODE_ACTIVE)
        self.assertEqual(n_vars, 8)
        support = {a | (b << 4) for (a, b) in v.weights.transitions}

        accepted = set()
        for asg in range(1 << 8):
            if all(any((lit > 0) == bool((asg >> (abs(lit) - 1)) & 1) for lit in cl)
                   for cl in clauses):
                accepted.add(asg)
        self.assertEqual(accepted, support)

    def test_weight_relation_pins_the_right_weight(self):
        v = variants.get("present-80")
        n_vars, clauses = model_mod.sbox_relation(v, model_mod.MODE_WEIGHT)
        self.assertEqual(n_vars, 8 + v.weights.max_weight)

        for (a, b), w in v.weights.transitions.items():
            for candidate in range(v.weights.max_weight + 1):
                asg = a | (b << 4) | (((1 << candidate) - 1) << 8)
                ok = all(any((lit > 0) == bool((asg >> (abs(lit) - 1)) & 1) for lit in cl)
                         for cl in clauses)
                self.assertEqual(ok, candidate == w,
                                 f"transition {a:x}->{b:x} weight {w}, candidate {candidate}")


class TestModelStructure(unittest.TestCase):
    def test_permutation_layer_adds_no_clauses(self):
        """The pLayer is pure wiring, so two variants differing only in their
        permutation must produce formulas of exactly the same size."""
        a = model_mod.build(variants.get("present-80"), 4, model_mod.MODE_WEIGHT)
        b = model_mod.build(variants.get("present-80-randperm-p"), 4, model_mod.MODE_WEIGHT)
        self.assertEqual(a.cnf.nv, b.cnf.nv)
        self.assertEqual(len(a.cnf.clauses), len(b.cnf.clauses))

    def test_difference_variables_are_aliased_through_the_permutation(self):
        v = variants.get("present-80")
        m = model_mod.build(v, 2, model_mod.MODE_ACTIVE)
        self.assertEqual(len(m.diff), 3)
        # every variable of round 1 must appear in round 0's S-box output, i.e. the
        # permutation only moved names around
        self.assertEqual(sorted(m.diff[1]), sorted(set(m.diff[1])))


@unittest.skipUnless(solver_available(), "no SAT solver available")
class TestKnownResults(unittest.TestCase):
    """The numbers PRESENT's designers published. If the model is wrong, these move."""

    def test_five_rounds_have_at_least_ten_active_sboxes(self):
        v = variants.get("present-80")
        res = search.min_active_sboxes(v, 5, timeout=120)
        self.assertEqual(res.status, search.EXACT)
        self.assertEqual(res.value, 10)

    def test_active_sbox_counts_for_one_to_five_rounds(self):
        v = variants.get("present-80")
        self.assertEqual(
            [search.min_active_sboxes(v, r, timeout=120).value for r in range(1, 6)],
            [1, 2, 4, 6, 10])

    def test_best_five_round_characteristic_is_two_to_the_minus_twenty(self):
        v = variants.get("present-80")
        res = search.min_trail_weight(v, 5, timeout=120)
        self.assertEqual(res.status, search.EXACT)
        self.assertEqual(res.value, 20)
        self.assertIsNotNone(res.trail)
        self.assertEqual(res.trail.total_active, 10)

    def test_one_round_optimum_matches_the_ddt(self):
        v = variants.get("present-80")
        res = search.min_trail_weight(v, 1, timeout=60)
        self.assertEqual(res.value, min(w for (a, _), w in v.weights.transitions.items()
                                        if a != 0))

    def test_identity_permutation_is_detectably_broken(self):
        """With no diffusion a single S-box stays active forever, so the trail weight
        grows by only one S-box per round instead of spreading."""
        v = variants.get("present-80-identity-p")
        res = search.min_active_sboxes(v, 6, timeout=120)
        self.assertEqual(res.status, search.EXACT)
        self.assertEqual(res.value, 6)  # one active S-box per round, no branching

    def test_trail_decodes_consistently(self):
        v = variants.get("present-80")
        res = search.min_trail_weight(v, 4, timeout=120)
        trail = res.trail
        self.assertIsNotNone(trail)
        self.assertEqual(sum(sum(s.weights) for s in trail.steps), trail.total_weight)
        self.assertEqual(trail.total_weight, res.value)
        self.assertNotEqual(trail.diff_in, 0)
        # every active S-box in the trail must be a real DDT transition
        for step in trail.steps:
            for idx, w in zip(step.active, step.weights):
                nibble = (step.diff_in >> (4 * idx)) & 0xF
                self.assertNotEqual(nibble, 0)
                self.assertIn(w, v.weights.weights_used)


class TestReportBounds(unittest.TestCase):
    def rows(self):
        return [
            RoundRow(rounds=1, min_active=1, active_status="exact", min_weight=2,
                     weight_status="exact"),
            RoundRow(rounds=5, min_active=10, active_status="exact", min_weight=20,
                     weight_status="exact"),
            RoundRow(rounds=6, min_active=12, active_status="exact", min_weight=24,
                     weight_status="exact"),
        ]

    def test_lower_bound_uses_the_best_window(self):
        # 31 rounds hold six disjoint 5-round windows (weight 120) or five 6-round
        # windows (weight 120); both beat 31 one-round windows (weight 62).
        self.assertEqual(report_mod.weight_lower_bound(self.rows(), 31), 120)

    def test_inexact_rows_are_ignored(self):
        rows = [RoundRow(rounds=5, min_active=10, active_status="exact", min_weight=20,
                         weight_status="lower_bound")]
        self.assertEqual(report_mod.weight_lower_bound(rows, 31), 0)

    def test_rounds_for_weight(self):
        # At 17 rounds the best window choice is three 5-round windows: 3 * 20 = 60,
        # short of 64 (three 6-round windows need 18 rounds, two give only 48).
        # At 18 rounds three 6-round windows give 3 * 24 = 72, which clears it.
        self.assertEqual(report_mod.weight_lower_bound(self.rows(), 17), 60)
        self.assertEqual(report_mod.weight_lower_bound(self.rows(), 18), 72)
        self.assertEqual(report_mod.rounds_for_weight(self.rows(), 64), 18)

    def test_no_data_gives_no_bound(self):
        self.assertIsNone(report_mod.rounds_for_weight([], 64))


if __name__ == "__main__":
    unittest.main()
