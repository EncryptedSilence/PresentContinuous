# FPGA Core Optimization and Alveo V80 Estimate

## Objective

This experiment implements two hardware architectures for each selected cipher:

- `area`: minimize the resources of one encryption lane, accepting a larger
  initiation interval.
- `speed`: maximize sustained candidate throughput with a fully streaming lane.

The RTL is verified with known-answer tests (KATs), synthesized and routed with
Gowin, and then extrapolated to an AMD Alveo V80. The main attacker metric is
candidate encryptions per second. One candidate test means one block encryption
with the supplied key material.

## Cores

The generated matrix contains both targets for:

- PRESENT-80-r16
- PRESENT-80-lin444-297-r7
- cipher-D-r8
- cipher-D-lin444-297-r5
- cipher-D-lin444-297-AES-r5
- AES-r5 (128-bit block)
- AES-lin444-(0,8,15)-r4 (128-bit block)

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
- shift independent round-key material forward instead of multiplexing buses from
  384 to 768 bits wide.

The initiation interval is `rounds * S-boxes_per_block + 1`: 257 cycles for
PRESENT-80-r16, 113 for PRESENT-lin444-r7, 65 for cipher-D-r8, 41 for the
64-bit 5-round byte-oriented variants, 81 for AES-r5, and 65 for AES-lin444-r4.

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
- AES-r5 omits MixColumns in its last round, while AES-lin444 applies its
  `(0,8,15)` XOR-rotate layer in all four rounds.

The normal speed latency is two cycles per round. The deeply pipelined AES core is
four cycles per round. Latency does not reduce sustained throughput because all
speed cores have `II = 1`.

### Clock constraint search

Candidate rate is `cores * Fmax / II`, so the routed clock is a first-class result
rather than a byproduct. Place-and-route stops optimizing as soon as it meets the
constraint, which makes any hand-picked constraint a *lower bound* on what the
design can reach: `present-80-lin444-297-r7-speed` was constrained at 200 MHz and
closed at 215 MHz with 0.349 ns of slack still unspent, and every area core was
constrained at 125 MHz simply because that was the number somebody typed.

`tools/fpga_fmax_search.py` walks the constraint down instead of guessing it. From
a build that passes with slack `S` at period `P`, the next candidate is `P - S`,
the period the design actually achieved. Gowin also reports exactly zero slack
whenever it stops the moment it meets timing, which carries no information about
the ceiling, so a zero-slack pass probes 3% tighter rather than concluding the
search is finished. The first failure switches the search to bisection against the
tightest passing period, and it stops when the bracket closes below 0.02 ns, which
is inside the tool's own run-to-run variation. Failing periods are recorded, so a
later run resumes the bisection instead of re-paying for place-and-route runs it
has already done.

The result per core is written to `fpga/clock_constraints.json`, which
`tools/gen_fpga.py` reads when it emits each project's SDC. The searched
constraints therefore survive regeneration and stay reviewable, and a core with no
searched entry falls back to a deliberately loose seed.

Gowin place-and-route is not deterministic run to run. The same RTL at the same
constraint closed `cipher-D-lin444-297-r5-area` with 0.047 ns of slack in one run
and missed by 0.065 ns in the next, so the tightest period the search observes is
one sample of a noisy process rather than a property of the design. Reported slack
cannot detect this, because the tool stops optimizing the moment it meets the
constraint and therefore reports roughly zero slack on every passing build. A
constraint is accepted here only if an independent from-scratch build also meets it,
which is what `make fpga-gowin-build` provides; `fpga_fmax_search.py --confirm`
relaxes the period by 2% per failed confirmation until one holds. Thirteen of the
fourteen cores reproduced their searched constraint directly. The fourteenth needed
one guard band step, after which four consecutive independent builds met timing
with a 0.05 ns spread in achieved delay.

Tightening the constraint did not change any core's resource use: registers and
LUT+ALU counts are identical across all fourteen cores, so the router did not
replicate logic to close timing. The gain is therefore entirely a clock gain, and
it carries through to candidate rate at full ratio. The geometric mean gain over
the previous constraint set is 1.19x, ranging from 1.00x for a core that was
already at its ceiling to 1.57x for one whose constraint was simply a round number.

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
make fpga-generate
make fpga-kat
make fpga-gowin-build
make fpga-gowin-report
make fpga-capacity
```

The clock constraints are an input to this flow, not a product of it. Re-running the
search is a separate, much longer step, needed only when the RTL changes:

```sh
python3 tools/fpga_fmax_search.py --max-builds 12   # walk each constraint down
python3 tools/fpga_fmax_search.py --confirm         # require an independent rebuild
```

The KAT suite checks all fourteen cores. Area cores are tested sequentially. Speed cores
receive different keys on consecutive cycles, which checks state/key alignment as
well as ciphertext correctness. For the 128-bit cores, direct byte/word references
are checked against the GF(2)-matrix reference before generated expectations are
used by RTL simulation.

All fourteen final Gowin builds completed synthesis, placement, routing, timing
analysis, power analysis, and bitstream generation. Every final row meets its
explicit SDC clock constraint. Raw post-route results are in
`results/fpga-gowin.csv` and `results/fpga-gowin.md`.

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

| cipher | bits | target | core regs | core LUT+ALU | met Fmax (MHz) | II | V80 cores at 80% | candidate tests/s | throughput (Gb/s) |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PRESENT-80-r16 | 64 | area | 300 | 657 | 240.061 | 257 | 3,165 | 2.956393e9 | 189.209 |
| PRESENT-80-r16 | 64 | speed | 4,657 | 2,161 | 255.979 | 1 | 893 | 2.285892e11 | 14,629.712 |
| PRESENT-80-lin444-297-r7 | 64 | area | 300 | 787 | 202.711 | 113 | 2,642 | 4.739491e9 | 303.327 |
| PRESENT-80-lin444-297-r7 | 64 | speed | 2,047 | 1,920 | 292.831 | 1 | 1,083 | 3.171360e11 | 20,296.702 |
| cipher-D-r8 | 64 | area | 731 | 1,484 | 176.875 | 65 | 1,401 | 3.812337e9 | 243.990 |
| cipher-D-r8 | 64 | speed | 5,665 | 8,694 | 157.019 | 1 | 239 | 3.752754e10 | 2,401.763 |
| cipher-D-lin444-297-r5 | 64 | area | 539 | 1,300 | 139.204 | 41 | 1,600 | 5.432351e9 | 347.670 |
| cipher-D-lin444-297-r5 | 64 | speed | 2,587 | 6,106 | 184.158 | 1 | 340 | 6.261372e10 | 4,007.278 |
| cipher-D-lin444-297-AES-r5 | 64 | area | 539 | 1,141 | 127.052 | 41 | 1,822 | 5.646067e9 | 361.348 |
| cipher-D-lin444-297-AES-r5 | 64 | speed | 6,357 | 4,056 | 169.586 | 1 | 512 | 8.682803e10 | 5,556.994 |
| AES-r5 | 128 | area | 1,052 | 2,053 | 121.857 | 81 | 1,013 | 1.523965e9 | 195.067 |
| AES-r5 | 128 | speed | 12,677 | 7,411 | 181.442 | 1 | 280 | 5.080376e10 | 6,502.881 |
| AES-lin444-(0,8,15)-r4 | 128 | area | 924 | 1,915 | 122.749 | 65 | 1,086 | 2.050853e9 | 262.509 |
| AES-lin444-(0,8,15)-r4 | 128 | speed | 9,121 | 6,369 | 141.261 | 1 | 326 | 4.605109e10 | 5,894.539 |

The speed architecture is the attacker-optimal choice for every tested cipher. Its
projected candidate-rate advantage over the corresponding area core is 77.3x for
PRESENT-80-r16, 66.9x for PRESENT-lin444-r7, 9.8x for cipher-D-r8, 11.5x for
cipher-D-lin444-r5, 15.4x for cipher-D-lin444-AES-r5, 33.3x for AES-r5, and
22.5x for AES-lin444-r4. These ratios are smaller than the previous constraint set
reported because the area cores gained the most clock from the search: their 125 MHz
constraint was the furthest below what the fabric delivers.

Among the tested designs, PRESENT-80-lin444-297-r7 has the highest projected
absolute rate at `3.17e11` candidate tests/s. The AES S-box circuit improves the
5-round byte-oriented speed result to `8.68e10` tests/s, 1.39x the corresponding
cipher-D-table variant, despite its deeper pipeline and larger register count.

The clock search reversed one earlier conclusion between the 128-bit rows.
AES-lin444-r4 was reported 1.03x faster than AES-r5 by candidate rate, which was an
artifact of AES-r5 being under-constrained: AES-r5-speed gained 13.9% clock under
the search while AES-lin444-r4-speed was already at its ceiling and gained nothing.
AES-lin444-r4 is now 0.91x AES-r5 by candidate rate. It still uses 14% less logic,
so it remains the better choice per unit of fabric, but its lower round count no
longer buys an absolute rate advantage.

## Candidates that did not win

Two resource reductions look attractive on their own terms but lose once the
binding constraint is checked. `cores` is `min` over resource classes, so shrinking
anything other than the binding resource buys nothing.

Mapping the independent-key delay lines to shift registers. `aes-r5-speed` carries
7,680 bits of pure key delay, about 61% of its 12,677 registers, and a delay line is
exactly what an SRL implements. But that core is limited by logic, not registers:
its 7,411 LUT+ALU allow 280 cores while its registers allow 328. Every core in this
matrix with a pure key-delay line is logic-limited, and the one core that is
register-limited, `present-80-r16-speed`, has no delay line to convert -- its 4,657
registers are live state and key material, `16 rounds * 2 stages * (64 + 80)` bits.
SRL mapping would trade a slack resource for the binding one and lower the estimate.

Moving `cipher-D-speed`'s 64 S-box ROMs into block RAM. That core is the worst in
the matrix at 8,694 LUT+ALU and 239 cores, and the ROMs dominate it. Charging those
tables to BRAM instead makes BRAM the binding class at roughly 187 cores, so the
logic mapping the generator already emits is the better one.

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

For variants with `independent` round keys, including both 128-bit additions, the
input is raw round-key material rather than a conventional master-key schedule.
AES-r5 receives 768 bits and AES-lin444-r4 receives 640 bits per candidate. This
matches the GPU experiment's pre-expanded-key timing model, but it does not include
AES-128 key expansion or candidate generation. Candidate rate is therefore the
useful implementation comparison; the full-keyspace time in the CSV is a formal
consequence of that interface, not a practical attack estimate.
