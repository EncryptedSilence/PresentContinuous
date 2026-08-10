"""The two v2 CUDA result files, checked as a contract rather than as numbers.

These files are produced by build/gpu_bench, which needs a CUDA device, so nothing
here re-runs the measurement -- `make test` must pass on a machine with no GPU. What
it does check is everything about the files that a later task, a reader or a paper
table depends on and that a re-run could silently break:

  * the provenance marker is present and is one of the two values the harness can
    write, so a smoke run cannot be mistaken for the campaign;
  * block evaluation covers exactly the seven ciphers tools/cipher_set.py defines,
    under those names -- the previous CUDA CSVs called two of them something else;
  * master-key search covers only the constructions with a master-key schedule, says
    in the file itself why each of the other four is absent, and carries the key model
    as a column so a comment-stripping reader still sees which object was searched;
  * block evaluation records every absent kernel family as either inapplicable or
    unwritten, so a best-per-cipher table cannot silently credit a cipher for kernels
    somebody happened to write for it;
  * the 4 h budget columns really are the rate times 14400 s, so no number in either
    file reaches a table by hand.
"""

import csv
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cipher_set  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
BLOCK_EVAL = os.path.join(ROOT, "results", "v2", "cuda", "block-eval.csv")
MASTER_KEY = os.path.join(ROOT, "results", "v2", "cuda", "master-key-search.csv")

# bench/gpu_bench.cu's BUDGET_SECONDS. Stated once here and checked against the file,
# which is the point: the CSV's budget column must be the rate times this and not a
# separately typed number.
BUDGET_SECONDS = 14400.0

# The constructions with no master-key schedule. Each must be named in
# master-key-search.csv's own header, with a reason, rather than only in prose.
NO_MASTER_KEY = (
    "cipher-D",
    "cipher-D-lin444-297-r5",
    "cipher-D-lin444-297-aes-r5",
    "aes-lin444-0-8-15-r4",
)


def read_csv(path):
    """Returns (header_comment_text, list of row dicts).

    Both files open with a '#'-prefixed provenance and explanation block, the same
    convention results/m4-speed.csv and results/wide-speed-arm.csv use.
    """
    with open(path, encoding="ascii") as fh:
        lines = fh.read().splitlines()
    comments = [ln for ln in lines if ln.startswith("#")]
    body = [ln for ln in lines if not ln.startswith("#")]
    rows = list(csv.DictReader(body))
    return "\n".join(comments), rows


class TestGpuV2Csv(unittest.TestCase):
    def test_both_files_exist(self):
        for path in (BLOCK_EVAL, MASTER_KEY):
            self.assertTrue(os.path.isfile(path),
                            f"{path} is missing; regenerate with `make gpu-bench-v2`")

    def test_provenance_marker_is_the_first_line_and_a_known_value(self):
        """The marker is what stops a smoke run being read as a campaign result.

        build/gpu_bench writes SMOKE-RUN unless it is given --campaign, so this also
        pins the fact that there is no third state and no hand-edited one.
        """
        for path in (BLOCK_EVAL, MASTER_KEY):
            with open(path, encoding="ascii") as fh:
                first = fh.readline().rstrip("\n")
            self.assertIn(first, ("# provenance: SMOKE-RUN", "# provenance: CAMPAIGN"),
                          f"{path} has no recognisable provenance marker on line 1")

    def test_smoke_runs_say_so_in_words_as_well(self):
        for path in (BLOCK_EVAL, MASTER_KEY):
            comments, _ = read_csv(path)
            if comments.splitlines()[0].endswith("SMOKE-RUN"):
                self.assertIn("NOT A MEASUREMENT RESULT", comments,
                              f"{path} is marked SMOKE-RUN but does not say what that means")

    def test_block_eval_has_the_renamed_metric_columns(self):
        _, rows = read_csv(BLOCK_EVAL)
        self.assertTrue(rows, "block-eval.csv has no data rows")
        for column in ("cipher", "impl", "rounds", "block_bits", "blocks",
                       "gb_per_sec", "ns_per_block",
                       "block_evals_per_sec", "block_evals_in_4h", "status", "note"):
            self.assertIn(column, rows[0], column)

    def test_every_row_has_the_full_column_count(self):
        """`note` is the last unquoted field, so a comma in it splits the row."""
        for path in (BLOCK_EVAL, MASTER_KEY):
            with open(path, encoding="ascii") as fh:
                body = [ln for ln in fh.read().splitlines() if not ln.startswith("#")]
            width = len(body[0].split(","))
            for line in body[1:]:
                self.assertEqual(len(line.split(",")), width,
                                 f"{path}: wrong field count in: {line[:80]}")

    def test_block_eval_covers_exactly_the_seven_ciphers(self):
        """Block evaluation is the cross-construction comparison, so all seven.

        Under tools/cipher_set.py's names: the pre-v2 CUDA CSVs called cipher-D
        'cipher-D-r8' and cipher-D-lin444-297-aes-r5 'cipher-D-AES-lin444-297-r5',
        which no other target in this repository would have matched up with.
        """
        _, rows = read_csv(BLOCK_EVAL)
        expected = {name for _, name, _ in cipher_set.resolve()}
        self.assertEqual({r["cipher"] for r in rows}, expected)

    def test_block_eval_round_counts_come_from_cipher_set(self):
        _, rows = read_csv(BLOCK_EVAL)
        expected = {name: rounds for _, name, rounds in cipher_set.resolve()}
        for row in rows:
            self.assertEqual(int(row["rounds"]), expected[row["cipher"]], row["cipher"])

    def test_master_key_has_its_own_metric_column(self):
        _, rows = read_csv(MASTER_KEY)
        self.assertTrue(rows, "master-key-search.csv has no data rows")
        for column in ("cipher", "rounds", "key_bits", "key_model", "candidates",
                       "master_key_candidates_per_sec", "master_key_candidates_in_4h"):
            self.assertIn(column, rows[0], column)

    def test_key_model_is_carried_as_data_not_only_as_prose(self):
        """The caveat has to survive a reader that strips '#' lines.

        aes-r5's row says key_bits=128, while variants/wide/aes.json -- the object every
        differential bound here was computed for -- declares 640 independent key bits.
        A table generator consumes columns, so the distinction has to be in one.
        """
        _, rows = read_csv(MASTER_KEY)
        got = {r["cipher"]: r["key_model"] for r in rows}
        self.assertEqual(got, {
            "present-80-r16": "present-80",
            "present-80-lin444-297-r7": "present-80",
            "aes-r5": "fips197-aes128",
        })
        for row in rows:
            self.assertTrue(row["key_model"], f"{row['cipher']} has an empty key_model")

    def test_master_key_header_does_not_overstate_the_verification(self):
        """It must claim the checks that ran, not a tidier set that did not.

        No row in this file has a published test vector of its own: all three are
        reduced-round and one is a modified construction. The header therefore has to
        distinguish the full-round family anchors from the per-row checks, and must not
        claim src/keyschedule.c had anything to do with the AES row.
        """
        comments, _ = read_csv(MASTER_KEY)
        self.assertNotIn(
            "Every kernel below reproduced its construction's published test vectors",
            comments, "the overstated verification sentence is back")
        for phrase in ("family anchor", "31 rounds", "FIPS-197 C.1",
                       "present_encrypt_ref", "encrypt_aes_host",
                       "src/keyschedule.c contains no AES"):
            self.assertIn(phrase, comments, phrase)

    def test_master_key_covers_only_constructions_that_have_one(self):
        _, rows = read_csv(MASTER_KEY)
        all_seven = {name for _, name, _ in cipher_set.resolve()}
        present = {r["cipher"] for r in rows}
        self.assertTrue(present <= all_seven,
                        f"master-key-search.csv names a cipher outside the set: "
                        f"{present - all_seven}")
        self.assertEqual(present, all_seven - set(NO_MASTER_KEY))

    def test_every_absent_construction_is_explained_in_the_file(self):
        """The exclusion is a claim about the constructions, so it lives in the data.

        A reader who opens master-key-search.csv and finds three of seven rows must
        be able to see, without leaving the file, that the other four are absent by
        construction rather than because nobody got round to them.
        """
        comments, _ = read_csv(MASTER_KEY)
        for name in NO_MASTER_KEY:
            self.assertIn(name, comments,
                          f"{name} is absent from master-key-search.csv but the file "
                          f"never says why")
        self.assertIn("independent round-key material", comments)
        self.assertIn("block-eval.csv", comments)

    def test_budget_columns_are_derived_not_typed(self):
        """No number reaches a table by hand -- including the 4 h ones."""
        for path, rate, budget in (
            (BLOCK_EVAL, "block_evals_per_sec", "block_evals_in_4h"),
            (MASTER_KEY, "master_key_candidates_per_sec", "master_key_candidates_in_4h"),
        ):
            _, rows = read_csv(path)
            for row in rows:
                if row.get("status", "measured") != "measured":
                    continue
                got = float(row[budget])
                want = float(row[rate]) * BUDGET_SECONDS
                self.assertAlmostEqual(
                    got / want, 1.0, places=5,
                    msg=f"{path}: {row['cipher']} budget is not the rate x "
                        f"{BUDGET_SECONDS:.0f} s")

    def test_every_construction_has_at_least_one_measured_row(self):
        _, rows = read_csv(BLOCK_EVAL)
        measured = {r["cipher"] for r in rows if r["status"] == "measured"}
        self.assertEqual(measured, {name for _, name, _ in cipher_set.resolve()})

    def test_portfolio_gaps_are_classified_and_explained(self):
        """Absent kernels are the difference between a comparison and an artefact.

        A table taking the best row per cipher credits each cipher for whichever kernels
        somebody wrote for it. So every absence carries a status saying whose gap it is,
        and a reason; `unwritten` in particular is an admission that the gap is ours.
        """
        _, rows = read_csv(BLOCK_EVAL)
        gaps = [r for r in rows if r["status"] != "measured"]
        self.assertTrue(gaps, "no portfolio gaps recorded at all, which cannot be right")
        for row in gaps:
            self.assertIn(row["status"], ("inapplicable", "unwritten"),
                          f"{row['cipher']}/{row['impl']} has status {row['status']!r}")
            self.assertTrue(row["note"].strip(),
                            f"{row['cipher']}/{row['impl']} is absent with no reason given")
            self.assertEqual(row["block_evals_per_sec"], "",
                             "a non-measured row must carry no timing figure")

    def test_no_kernel_family_is_absent_without_a_classification(self):
        """The union of families per block width, minus what each cipher has, must be
        exactly the set of recorded gaps -- otherwise an absence went unrecorded."""
        _, rows = read_csv(BLOCK_EVAL)
        by_width = {}
        for row in rows:
            if row["status"] == "measured":
                by_width.setdefault(row["block_bits"], set()).add(row["impl"])
        have = {}
        width_of = {}
        for row in rows:
            if row["status"] == "measured":
                have.setdefault(row["cipher"], set()).add(row["impl"])
                width_of[row["cipher"]] = row["block_bits"]
        recorded = {}
        for row in rows:
            if row["status"] != "measured":
                recorded.setdefault(row["cipher"], set()).add(row["impl"])
        for cipher, impls in have.items():
            expected = by_width[width_of[cipher]] - impls
            self.assertEqual(recorded.get(cipher, set()), expected,
                             f"{cipher}: recorded gaps do not match the families it lacks")

    def test_block_eval_header_does_not_claim_plain_comparability(self):
        """The file is a comparison across the kernels that exist, and must say so."""
        comments, _ = read_csv(BLOCK_EVAL)
        self.assertNotIn(
            "block evaluation is the cross-construction\n# comparison, and it is "
            "defined for every one of them", comments,
            "the unqualified comparability claim is back")
        for phrase in ("comparison across the kernels that happen\n# to exist",
                       "inapplicable", "unwritten",
                       "status == measured"):
            self.assertIn(phrase, comments, phrase)

    def test_makefile_defines_ctr_gen_before_the_gpu_bench_rule(self):
        """A prerequisite list is expanded when make parses it, not when it runs.

        $(BUILD)/gpu_bench lists $(CTR_GEN); if that variable were still defined next
        to its own rule further down the file, the prerequisite would expand to
        nothing here and a stale generated header would never be rebuilt. This has
        already happened once in this Makefile, with M4_NM_PRESENT and `test:`.
        """
        with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as fh:
            text = fh.read()
        definition = re.search(r"^CTR_GEN\s*:?=", text, re.MULTILINE)
        self.assertIsNotNone(definition, "CTR_GEN is no longer defined in the Makefile")
        use = text.index("$(BUILD)/gpu_bench: bench/gpu_bench.cu")
        self.assertLess(definition.start(), use,
                        "CTR_GEN is defined after the gpu_bench rule that uses it as a "
                        "prerequisite, so it expands to nothing there")


if __name__ == "__main__":
    unittest.main()
