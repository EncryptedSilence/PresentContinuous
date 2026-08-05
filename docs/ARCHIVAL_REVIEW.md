# Archival Review

This review records licensing and provenance issues relevant to GitHub release archives and
Zenodo preservation. It does not alter the cryptographic algorithms, measurements, SAT results
or experimental conclusions.

## Repository License

The repository owner selected the Apache License 2.0 for repository-owned material. The root
[LICENSE](../LICENSE) file contains the Apache-2.0 text, and `CITATION.cff` records
`license: Apache-2.0`.

This repository license does not override separate terms for third-party material.

## Third-Party And External Material

| path | status | archival note |
|---|---|---|
| `docs/2012-529.pdf` | externally authored PDF | Redistribution terms were not established during this pass. Keep the file for now, but confirm its redistribution permission before public archival. |
| `tools/known_circuits.py` | includes a hand-transcribed published AES S-box circuit | The source notes identify the circuit lineage in project documentation as Boyar-Peralta. Confirm citation and redistribution expectations for the transcription before archival. |
| `src/gen/sbox_circuits.h` | generated circuits, including the AES S-box circuit used by benchmarks | Generated project output, but it may contain a generated form of the published AES circuit. Treat it together with `tools/known_circuits.py` for attribution review. |
| `third_party/` | local solver sources and builds, ignored by Git | Solver binaries and source trees are not part of the committed artifact. Exact solver versions and build notes are recorded in [measurement-environment.md](measurement-environment.md). |
| `Activation/`, `BranchConfirm/`, `ShiftGen2/`, `ShiftGen3/` | external tool directories | These are ignored and must not be included in repository releases unless separately reviewed and intentionally vendored. |

## Release Archive Policy

GitHub remains the maintained source of truth. Zenodo should archive only immutable GitHub
releases created from tags. Do not manually upload a separate Zenodo source package.
