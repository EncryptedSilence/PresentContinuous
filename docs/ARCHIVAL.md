# Archival And Reproducibility

This document defines the repository as the authoritative reproducibility artifact for the
lightweight-cipher comparison at equal proven single-trail differential margin.

## Scope Of The Artifact

The artifact contains the implementation code, SAT model, benchmark programs, variant
definitions, documentation and committed result files needed to inspect and reproduce the
reported experiments. GitHub is the sole maintained source of truth. Zenodo must archive only
immutable GitHub releases created from repository tags; no separate Zenodo source package is
maintained.

The practical speed measurements were taken on an Intel Core i9-14900HX. That platform
represents neither the constrained legitimate endpoint nor specialised attacker hardware.
Reported `cyc/B` values are nominal invariant-TSC ticks per byte, not literal core-clock
cycles. Exact environment details are in [measurement-environment.md](measurement-environment.md).

## Repository Structure

| path | role |
|---|---|
| `src/`, `include/` | 64-bit PRESENT-like implementations and public headers |
| `bench/` | speed and avalanche benchmark programs |
| `analysis/` | SAT model, search scripts, witness checks and Python tests |
| `variants/`, `variants/wide/` | cipher variant definitions |
| `tools/` | code generation, synthesis helpers and artifact tools |
| `tests/` | C implementation and variant tests |
| `docs/` | experiment descriptions and archival documentation |
| `results/` | committed speed, differential, bound-search and avalanche results |
| `paper/` | reserved paper area; the unpublished manuscript is intentionally absent |

## Exact Measurement Environment

The recorded speed environment was:

- Intel Core i9-14900HX;
- gcc 13.3.0;
- benchmark compilation with `-O3 -march=native`;
- processes pinned to CPU 2;
- Linux kernel 6.17.

See [measurement-environment.md](measurement-environment.md) for toolchain paths, solver
versions, firmware, power settings, TSC caveats and reproduction limits.

## Reproduction Commands

Short validation:

```sh
make test
make validate-artifact
```

Speed measurements:

```sh
taskset -c 2 ./build/bench --csv results/speed.csv
taskset -c 2 ./build/wide_bench --rounds 4 --c0 0 8 15 --csv results/wide-speed-r4.csv
taskset -c 2 ./build/wide_bench --rounds 5 --c0 0 8 15 --csv results/wide-speed-r5.csv
```

Avalanche experiment:

```sh
./build/avalanche --csv results/avalanche.csv --E 1000000
```

Differential analysis and reports:

```sh
python3 analysis/cli.py analyze --all
make report
```

The long SAT searches documented in [speed-at-equal-security.md](speed-at-equal-security.md)
are not run by CI or `make validate-artifact`.

## Provenance Of Measured, Derived And Estimated Values

- Speed CSVs in `results/speed.csv`, `results/wide-speed-r4.csv` and
  `results/wide-speed-r5.csv` are measured on the environment above.
- `results/*-differential.csv`, `results/rounds-at-64.csv` and
  `results/bound-search/` are SAT-derived or replay-verified outputs.
- `results/avalanche.csv` is measured by `bench/avalanche.c` with a replayable PRNG seed
  recorded in the CSV.
- GPU, FPGA and ASIC capacities discussed in the documentation are externally sourced or
  engineering estimates rather than measurements made by this repository.
- Single-trail differential bounds do not establish complete cipher security. They do not cover
  differential clustering, linear cryptanalysis, related-key attacks or structural attacks.

## Files Included In Releases

Release archives are GitHub-generated source archives from annotated tags. Everything required
for reproduction must be committed before tagging, including:

- source code and headers;
- benchmark and analysis programs;
- variant definitions;
- tests;
- documentation;
- committed result CSVs and bound-search evidence;
- `CITATION.cff`;
- `artifact-manifest.json`;
- `results/release-manifest.json` once generated for a release tag.

## Files Intentionally Excluded

Do not include:

- unpublished DONATION manuscript DOCX files;
- private correspondence;
- credentials;
- local build directories;
- solver binaries where redistribution is unclear;
- raw files not referenced by the experiment;
- machine-specific temporary files;
- external local tool directories such as `Activation/`, `BranchConfirm/`, `ShiftGen2/` or
  `ShiftGen3/`.

If solver binaries are excluded, record exact source revisions and build instructions instead.
The current solver details are in [measurement-environment.md](measurement-environment.md).

## DOI And Release Procedure

### Phase 1: Bootstrap Release

1. Merge the repository-preparation pull request.
2. Ensure the repository is public.
3. Connect the repository in Zenodo GitHub integration.
4. Enable `EncryptedSilence/PresentContinuous`.
5. Run:

   ```sh
   make validate-artifact
   ```

6. Generate:

   ```sh
   python3 tools/make_release_manifest.py \
       --tag artifact-v0.1.0 \
       --output results/release-manifest.json
   ```

7. Commit the generated release manifest.
8. Create annotated Git tag `artifact-v0.1.0`.
9. Push the tag.
10. Create a GitHub release from the tag.
11. Wait for Zenodo to archive the release.
12. Record the Zenodo concept DOI and the Zenodo version DOI for `artifact-v0.1.0`.

The bootstrap release does not need to contain the final paper.

### Phase 2: DOI Integration

1. Add the Zenodo concept DOI to `CITATION.cff`.
2. Add the concept DOI to `README.md`.
3. Add the approved TeX paper under `paper/`.
4. In the paper, cite the Zenodo concept DOI, exact GitHub release tag and exact Git commit SHA.
5. Do not put a version-specific Zenodo DOI inside the paper.
6. Re-run validation.
7. Generate a new release manifest for `artifact-v1.0.0` using the concept DOI.
8. Commit all changes.
9. Tag `artifact-v1.0.0`.
10. Create the final GitHub release.
11. Zenodo will issue a separate version DOI for `artifact-v1.0.0`.
12. Add the version DOI only to GitHub release notes and, if desired, a later metadata-only
    repository update. It does not require rebuilding the paper.

## Known Limitations

- Repository-owned material is licensed under Apache-2.0; third-party redistribution questions
  are tracked in [ARCHIVAL_REVIEW.md](ARCHIVAL_REVIEW.md).
- Ibrayev's affiliation is intentionally recorded as `AFFILIATION TO BE CONFIRMED`.
- Absolute `cyc/B` values are nominal TSC ticks, not core cycles.
- SAT bounds are single-trail bounds and are not complete security proofs.
- Optional GPU, FPGA, ASIC, Orange Pi and STM32 experiments are not part of this artifact.
