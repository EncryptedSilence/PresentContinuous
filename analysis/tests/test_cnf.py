"""The CNF layer is where a silent bug turns into wrong cryptanalysis rather than an
error, so these tests check encodings against brute force rather than against
themselves."""

import itertools
import random
import unittest

from present_sat import solver
from present_sat.cnf import (CNF, at_most_k, count_solutions_bruteforce,
                             relation_clauses, verify_relation)


def solver_available():
    try:
        solver.find_solver()
        return True
    except solver.SolverNotFound:
        return False


def satisfying_assignments(n_vars, clauses):
    out = []
    for bits in itertools.product([0, 1], repeat=n_vars):
        if all(any((lit > 0) == bool(bits[abs(lit) - 1]) for lit in cl) for cl in clauses):
            out.append(sum(b << i for i, b in enumerate(bits)))
    return set(out)


class TestRelationEncoding(unittest.TestCase):
    def test_random_relations_are_encoded_exactly(self):
        rng = random.Random(20260801)
        for n in (3, 4, 5):
            for _ in range(20):
                size = 1 << n
                valid = {a for a in range(size) if rng.random() < 0.4}
                if not valid or len(valid) == size:
                    continue
                clauses = relation_clauses(n, valid)
                self.assertEqual(satisfying_assignments(n, clauses), valid)

    def test_full_relation_needs_no_clauses(self):
        self.assertEqual(relation_clauses(3, set(range(8))), [])

    def test_verify_relation_catches_a_wrong_encoding(self):
        valid = {0b00, 0b11}
        clauses = relation_clauses(2, valid)
        verify_relation(2, valid, clauses)          # the real encoding is fine
        with self.assertRaises(AssertionError):
            verify_relation(2, {0b01}, clauses)     # a different relation is not


class TestCardinality(unittest.TestCase):
    """The sequential counter introduces O(n*k) auxiliary variables, so its
    correctness is checked by asking a solver whether each forced assignment of the
    *original* literals is extendable - brute-forcing the auxiliaries would be
    exponential in n*k."""

    def is_satisfiable(self, cnf, extra):
        formula = CNF()
        formula.nv = cnf.nv
        formula.clauses = list(cnf.clauses) + [list(c) for c in extra]
        return solver.solve(formula, timeout=30).status == solver.SAT

    def test_at_most_k_accepts_exactly_the_right_assignments(self):
        if not solver_available():
            self.skipTest("no SAT solver available")
        for n in range(1, 7):
            for k in range(0, n + 2):
                cnf = CNF()
                lits = cnf.new_vars(n)
                at_most_k(cnf, lits, k)
                for bits in itertools.product([0, 1], repeat=n):
                    forced = [[lits[i]] if b else [-lits[i]] for i, b in enumerate(bits)]
                    self.assertEqual(
                        self.is_satisfiable(cnf, forced), sum(bits) <= k,
                        f"n={n} k={k} bits={bits}")

    def test_at_most_k_without_auxiliaries_matches_brute_force(self):
        """The k == 0 and k >= n shortcuts add no auxiliaries, so brute force works."""
        for n in range(1, 5):
            for k in (0, n, n + 1):
                cnf = CNF()
                lits = cnf.new_vars(n)
                at_most_k(cnf, lits, k)
                self.assertEqual(cnf.nv, n, "expected no auxiliary variables")
                expected = {sum(b << i for i, b in enumerate(bits))
                            for bits in itertools.product([0, 1], repeat=n)
                            if sum(bits) <= k}
                self.assertEqual(satisfying_assignments(cnf.nv, cnf.clauses), expected)

    def test_at_most_zero_forces_all_false(self):
        cnf = CNF()
        lits = cnf.new_vars(4)
        at_most_k(cnf, lits, 0)
        self.assertEqual(satisfying_assignments(cnf.nv, cnf.clauses), {0})

    def test_negative_bound_is_unsatisfiable(self):
        cnf = CNF()
        lits = cnf.new_vars(2)
        at_most_k(cnf, lits, -1)
        self.assertIn([], cnf.clauses)


class TestDimacs(unittest.TestCase):
    def test_header_and_clause_count(self):
        cnf = CNF()
        a, b = cnf.new_vars(2)
        cnf.add([a, -b])
        cnf.add([-a])
        text = cnf.to_dimacs()
        self.assertIn("p cnf 2 2", text)
        self.assertTrue(text.rstrip().endswith("0"))


if __name__ == "__main__":
    unittest.main()
