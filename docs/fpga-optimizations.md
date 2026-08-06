# FPGA Core Optimization and Alveo V80 Estimate

## Objective

This experiment implements two hardware architectures for each selected 64-bit
cipher:

- `area`: minimize the resources of one encryption lane, accepting a larger
  initiation interval.
- `speed`: maximize sustained candidate throughput with a fully streaming lane.

The RTL is verified with known-answer tests (KATs), synthesized and routed with
Gowin, and then extrapolated to an AMD Alveo V80. The main attacker metric is
candidate encryptions per second. One candidate test means one 64-bit block
encryption with the supplied key material.

## Cores

The generated matrix contains both targets for:

- PRESENT-80-r16
- PRESENT-80-lin444-297-r7
- cipher-D-r8
- cipher-D-lin444-297-r5
- cipher-D-lin444-297-AES-r5

The generator writes the exact architecture, latency, and initiation interval of
each core to `fpga/generated/cores.csv`.

## Optimizations

### Area cores

The original iterative cores instantiated all S-boxes for a round and selected a
round key through a large variable-index mux. The optimized area cores instead:

- instantiate one physical S-box and process one nibble or byte per cycle;
- shift state and key material through fixed slices, avoiding variable part-select
  muxes;
- accumulate the substituted block and apply the linear layer once per round;
- keep a rolling PRESENT-80 key register instead of recomputing every round key
  from the original key;
- shift independent round-key material forward instead of multiplexing the full
  384-bit or 576-bit bus.

The initiation interval is `rounds * S-boxes_per_block + 1`: 257 cycles for
PRESENT-80-r16, 113 for PRESENT-lin444-r7, 65 for cipher-D-r8, and 41 for the
5-round byte-oriented variants.

### Speed cores

Every speed core accepts a new plaintext and key on every cycle (`II = 1`). The
key data is pipelined with its block, which is required for a real candidate stream
whose key changes every cycle. The optimizations are:

- one independently registered pipeline per cipher round;
- separate substitution and linear-layer stages to shorten the critical path;
- stage-local PRESENT key evolution;
- shrinking independent-key tails, so a stage retains only keys still needed by
  later rounds;
- final whitening in its own short output stage;
- a verified Boyar-Peralta Boolean AES S-box instead of a 256-entry logic table;
- pipeline cuts at the AES circuit's top, middle, and bottom boundaries, followed
  by a separate linear-layer stage.

The normal speed latency is two cycles per round. The deeply pipelined AES core is
four cycles per round. Latency does not reduce sustained throughput because all
speed cores have `II = 1`.

### Measurement integrity

The generated core hierarchy is marked `syn_hier = "hard"`, and architectural
pipeline registers use `syn_preserve`. This prevents the low-I/O test wrapper's
deterministic key stream from collapsing key and state delays across cycles.
Resource collection reads the `core` submodule, excluding wrapper registers and
LUTs. Timing still comes from the complete post-route design.

This correction matters. Before preservation, Gowin reported only 339 registers
and 568 LUTs inside `cipher_D_speed`; the standalone streaming architecture is
actually 5,665 registers and 8,694 LUTs.

## Validation and build

Run the experiment in this order because generation recreates the Gowin project
directories:

```sh
make fpga-kat
make fpga-gowin-build
make fpga-gowin-report
make fpga-capacity
```

The KAT suite checks all ten cores. Area cores are tested sequentially. Speed cores
receive different keys on consecutive cycles, which checks state/key alignment as
well as ciphertext correctness.

All ten final Gowin builds completed synthesis, placement, routing, timing analysis,
power analysis, and bitstream generation. Every final row meets its explicit SDC
clock constraint. Raw post-route results are in `results/fpga-gowin.csv` and
`results/fpga-gowin.md`.

## V80 projection

The Alveo V80 budget uses the official 2.6 million LUT and 132 Mb block-RAM
figures from the [AMD Alveo V80 product brief](https://www.amd.com/content/dam/amd/en/documents/products/accelerators/alveo/v80/alveo-v80-product-brief.pdf).
The 5.2 million flip-flop budget follows from the Versal CLB ratio of 32 LUTs to
64 flip-flops documented in the [Versal CLB architecture manual](https://docs.amd.com/r/en-US/am005-versal-clb/CLB-Resources).

For each resource class, the estimate is:

```text
cores = min(floor(0.80 * V80_resource / Gowin_core_resource))
rate  = cores * Gowin_postroute_Fmax / initiation_interval
```

The 80% budget reserves fabric for routing, clocks, candidate generation, result
comparison, and host control. Gowin ALUs are charged as LUTs. Gowin BSRAM counts
are interpreted as 18 Kb units; no final core is BRAM-limited in this logic-mapped
matrix.

## Final results

| cipher | target | core regs | core LUT+ALU | met Fmax (MHz) | II | V80 cores at 80% | candidate tests/s | throughput (Gb/s) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PRESENT-80-r16 | area | 300 | 657 | 152.828 | 257 | 3,165 | 1.882104e9 | 120.455 |
| PRESENT-80-r16 | speed | 4,657 | 2,161 | 203.441 | 1 | 893 | 1.816728e11 | 11,627.060 |
| PRESENT-80-lin444-297-r7 | area | 300 | 787 | 132.947 | 113 | 2,642 | 3.108371e9 | 198.936 |
| PRESENT-80-lin444-297-r7 | speed | 2,047 | 1,920 | 214.993 | 1 | 1,083 | 2.328374e11 | 14,901.595 |
| cipher-D-r8 | area | 731 | 1,484 | 131.414 | 65 | 1,401 | 2.832477e9 | 181.279 |
| cipher-D-r8 | speed | 5,665 | 8,694 | 149.998 | 1 | 239 | 3.584952e10 | 2,294.369 |
| cipher-D-lin444-297-r5 | area | 539 | 1,300 | 125.116 | 41 | 1,600 | 4.882576e9 | 312.485 |
| cipher-D-lin444-297-r5 | speed | 2,587 | 6,106 | 179.991 | 1 | 340 | 6.119694e10 | 3,916.604 |
| cipher-D-lin444-297-AES-r5 | area | 539 | 1,141 | 119.169 | 41 | 1,822 | 5.295754e9 | 338.928 |
| cipher-D-lin444-297-AES-r5 | speed | 6,357 | 4,056 | 165.267 | 1 | 512 | 8.461670e10 | 5,415.469 |

The speed architecture is the attacker-optimal choice for every tested cipher. Its
projected candidate-rate advantage over the corresponding area core is 96.5x for
PRESENT-80-r16, 74.9x for PRESENT-lin444-r7, 12.7x for cipher-D-r8, 12.5x for
cipher-D-lin444-r5, and 16.0x for cipher-D-lin444-AES-r5.

Among the tested designs, PRESENT-80-lin444-297-r7 has the highest projected
absolute rate at `2.33e11` candidate tests/s. The AES S-box circuit improves the
5-round byte-oriented speed result to `8.46e10` tests/s, 1.38x the corresponding
cipher-D-table variant, despite its deeper pipeline and larger register count.

## Interpretation limits

These are first-order Alveo V80 estimates, not V80 implementation results. The
resource counts and Fmax are from a routed Gowin GW5A design. Gowin and Versal use
different LUTs, memories, routing, and clock networks, so neither resource mapping
nor frequency transfers exactly. Dense replication can also lower Fmax even with a
20% reserve.

A final V80 claim requires generating XCV80 RTL projects, synthesizing and routing
the replicated lanes in Vivado, and reporting achieved clock, post-route resource
use, congestion, power, and thermal limits. Until then, the table is suitable for
ranking architectures and estimating order of magnitude, but it should be labeled
as an extrapolation in AC/DC conclusions.

For variants with `independent` round keys, the 384-bit or 576-bit input is raw
round-key material rather than a conventional master-key schedule. Candidate rate
is therefore the useful comparison metric; the full-keyspace time in the CSV is a
formal consequence of that interface, not a practical attack estimate.
