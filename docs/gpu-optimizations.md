# GPU encryption optimizations

This document records the CUDA optimization sweep implemented in
`bench/gpu_bench.cu` and measured on an NVIDIA GeForce RTX 5070 Laptop GPU
(compute capability 12.0). The objective was to find the fastest bulk encryption
kernel for every cipher currently represented in the GPU benchmark.

## Measurement protocol

Each row encrypts 1,048,576 independent blocks. Key expansion is outside the timed
region, and every block in a row uses the same pre-expanded round keys. Five warm-up
launches precede 15 timed launches; the reported value is the median CUDA-event time.
Input and output remain in device memory.

The reported GB/s is effective cipher throughput:

```
blocks * block_bytes / kernel_time
```

It is not physical DRAM bandwidth. The benchmark measures the round-function cost
for a large batch after key setup. A brute-force attacker benchmark must additionally
assign a candidate key to each thread and include the corresponding key schedule.

### These numbers are L2-resident

At 1,048,576 blocks the input and output together are 16 MiB for a 64-bit cipher and
32 MiB for a 128-bit one, against a 32 MB L2 on this GPU. The rows above therefore
measure the round function against cache, not against memory. Re-running at
16,777,216 blocks, where the working set is 256 or 512 MiB and cannot be resident,
costs every cipher its fastest rows. Both columns are the best kernel at that size;
the full rows are in `results/gpu-speed-optimized.csv` and `results/gpu-speed-16m.csv`.

| cipher | 1M blocks | 16M blocks | ratio |
|---|---:|---:|---:|
| PRESENT-r16 | 203.53 | 157.69 | 0.77x |
| PRESENT-lin444-r7 | 261.10 | 166.07 | 0.64x |
| cipher-D-r8 | 63.72 | 47.67 | 0.75x |
| cipher-D-lin444-r5 | 162.52 | 104.93 | 0.65x |
| cipher-D-AES-lin444-r5 | 191.63 | 104.93 | 0.55x |
| AES-r5 | 180.60 | 94.46 | 0.52x |
| AES-lin444-r4 | 289.18 | 169.47 | 0.59x |
| AES-r10 | 93.74 | 61.07 | 0.65x |
| AES-lin444-r5 | 238.53 | 169.23 | 0.71x |

The fastest ciphers lose the most, which is what a bandwidth ceiling looks like. Two
pairs land on the same number once they hit it: cipher-D-lin444-r5 and
cipher-D-AES-lin444-r5 both reach exactly 104.93 GB/s, from two different kernels,
despite differing by 1.18x at 1M blocks; AES-lin444-r4 and AES-lin444-r5 reach 169.47
and 169.23 despite differing by 1.21x. Ciphers with different round-function costs
cannot converge on one throughput unless neither is the limiting factor.

Which kernel wins also changes. Bitslicing still wins both PRESENT variants at 16M
blocks, by 5.88x and 1.88x over the best table kernel there, but its 190 registers
leave only about two blocks resident per multiprocessor, and that is enough
concurrency to hide L2 latency and not enough to hide DRAM latency. For
cipher-D-AES-lin444-r5 it drops from 191.63 to 65.97 GB/s and the single-state
shared-S-box kernel overtakes it at 104.81. The interleaved kernels shift the same
way: AES T-tables and AES-lin444 are won by x2 at 1M blocks and by x4 and x1
respectively at 16M.

The 1M-block protocol is kept because the question this benchmark answers is the
relative round-function cost of cipher variants, and cache residency is what isolates
that from the memory system. But the absolute GB/s figures do not describe bulk
encryption of large buffers, cross-cipher ratios measured at 1M blocks compress at
bulk sizes, and the fastest kernel for a cipher is not the same at both sizes. An
attacker workload does not have this problem in the first place: candidates are
generated in registers rather than streamed from memory, so the L2-resident figure is
the relevant one for the attack model this repository is about.

The final binary was compiled with CUDA 13.0 for `sm_120`. The active kernels have no
register spills. Launch sweeps at 128, 256, and 512 threads per block showed that 256
threads is the best general default; smaller differences between sweep runs should be
treated as clock and power-management noise on the laptop GPU.

## Most effective optimizations

### Bitslicing ciphers with a small S-box circuit

The first sweep optimized every modified cipher and left the unmodified one alone:
PRESENT-r16 sat at 1.00x while its lin444 variant gained and AES gained 35x. A
comparison built that way measures optimization effort as much as cipher design,
which is the failure the README records as having once reversed a conclusion.

The bitsliced kernel removes the table lookup entirely. Each thread holds 32 blocks
as 64 bit-planes of 32 bits, transposing them in registers on load and back on
store, so the S-box becomes a gate circuit evaluated 32 blocks at a time and there
is no state-dependent addressing anywhere in the round. PRESENT uses the 15-gate
circuit already in `src/gen/sbox_circuits.h`; the byte-oriented AES S-box uses the
132-gate Boyar-Peralta circuit. Both linear layers get cheaper rather than more
expensive in this form: the pLayer is a permutation of plane indices and folds into
the store, and lin444 becomes plane-index arithmetic. Round keys are splatted one
bit per word into constant memory, so the key XOR is 64 uniform XORs.

The PRESENT circuit computes `S(x) ^ 0xC` rather than `S(x)`. Rather than spend
gates undoing that, the kernel pushes the constant through the linear layer and
folds `lin(0xC)` into the following round key, the same cancellation
`src/present_core.c` already uses.

This is the largest improvement for the two PRESENT variants, 5.09x for PRESENT-r16
and 3.11x for PRESENT-lin444-r7, and it also wins for cipher-D-AES-lin444-r5 at
1.96x, where the AES S-box's small circuit beats the fused table.

It is not a general technique. It requires the S-box to have a cheap Boolean
circuit, and cipher-D's unstructured 8-bit S-box does not: BDD synthesis puts it
around 1,107 gates against AES's 132. cipher-D therefore stays on the table path,
and the kernel is only offered for the two S-boxes that have a usable circuit.
`bitslice_sbox_kind()` decides this by deriving the AES S-box algebraically from
inversion in GF(2^8) plus the affine map instead of comparing against a stored
table, so a variant whose JSON drifts cannot silently select the wrong circuit.
The circuit, the transpose, and the kernel are each checked before any timed run.

Blocks are 128 threads. The 64 planes plus temporaries need about 190 registers,
which caps occupancy near 340 threads per SM whatever the block size, and 512
threads spills.

### Memory coalescing in the interleaved kernels

The multi-state kernels gave thread `t` the blocks `t*ILP .. t*ILP+ILP-1`, so
consecutive lanes in a warp addressed locations `ILP` apart and each load touched
`ILP` times more cache lines than it needed. Indexing them as
`blockIdx.x*blockDim.x*ILP + threadIdx.x` with a `blockDim.x` stride per state makes
every load contiguous across the warp. Measured in isolation this stride costs up
to 1.43x on a pure copy.

This changes a conclusion in the previous sweep rather than only adding speed. The
best interleaving depth was reported as x1 for AES-lin444 and x2 for AES T-tables,
with four-state interleaving said to reduce throughput. Under coalesced indexing
the depths are within noise of each other: 288.70 against 289.18 GB/s for
AES-lin444 at x1 and x2, and 180.60 against 180.54 for AES T-tables at x2 and x4.
The apparent optimum was a property of the addressing, not of the interleaving.

The three `*-ilp4` kernels keep the original strided indexing on purpose. They are
the baseline controls reproduced in `results/gpu-speed.csv` and changing them would
silently move the baseline.

### Shared AES T-tables

The original AES kernel read its four 256-entry T-tables from constant memory at
state-dependent indices. Threads in a warp therefore requested different addresses,
which removed the broadcast advantage of constant memory and serialized the table
traffic.

The optimized kernel cooperatively copies the 4 KiB T-table set and 256-byte final-round
S-box into shared memory once per thread block. Rounds are template parameters, so the
compiler fully specializes and unrolls the five- and ten-round kernels. Processing two
independent blocks per thread provides enough instruction-level parallelism without the
occupancy loss observed at four blocks per thread.

This is the largest measured improvement: 32.3x for AES-r5 and 35.8x for AES-r10.

### Shared S-box with arithmetic lin444

The fused AES-lin444 table occupies 64 KiB and returns a full 128-bit contribution for
each input byte. Its random global loads dominate the short four- and five-round
ciphers. Copying the full table to shared memory also performs poorly: it consumes most
of a multiprocessor's shared-memory budget and costs 64 KiB of setup traffic per CUDA
block.

The winning kernel copies only the 256-byte S-box to shared memory. It substitutes the
16 state bytes there and evaluates `lin444` directly with compile-time rotate constants.
This raises AES-lin444-r4 from 29.45 to 289.18 GB/s and AES-lin444-r5 from 23.74 to
238.53 GB/s.

The same strategy is best for the 64-bit, five-round cipher-D lin444 variants. Four
independent states per thread amortize the shared S-box setup and expose enough
independent work to hide lookup latency. The table variant reaches 162.52 GB/s,
1.67x its previous fused-table result. The AES-S-box variant is faster still when
bitsliced, so this kernel is no longer its best implementation.

### Specialized PRESENT nibble table

PRESENT's native table is only 2 KiB: 16 positions by 16 possible nibbles, with each
entry already containing the S-box and linear-layer contribution. For
PRESENT-lin444-r7, placing this table in shared memory and specializing the seven-round
loop raises throughput from 83.94 to 93.56 GB/s, which the bitsliced kernel then beats
by a further 2.79x.

Combining two PRESENT nibbles into each lookup halves the lookup count but expands the
working set to 16 KiB. It was slower on this GPU. Among the table kernels the 2 KiB
global-table version remains the best for PRESENT-r16, but the bitsliced kernel beats
all of them by 5.09x, so no table path is the fastest implementation for either
PRESENT variant.

### Compile-time specialization and state alignment

Round count, S-box width, linear-layer kind, and rotation constants are template
arguments in the optimized kernels. This removes round-time branches and permits full
unrolling. The 128-bit state is explicitly 16-byte aligned so CUDA can use vectorized
state loads and stores.

The 64-bit benchmark also tests one, two, and four states per thread. With coalesced
indexing the depth matters much less than it appeared to: x4 is best for the
five-round 64-bit lin444 designs, and the AES kernels are flat between x1, x2, and x4.

### Architecture-aware compilation

The Makefile now defaults to `-arch=native`, avoiding a generic legacy target and PTX
JIT as the normal benchmark path. `-Xptxas=-warn-spills` makes register spilling visible
during every build. A specific target remains available, for example:

```sh
make CUDA_ARCH=sm_120 build/gpu_bench
```

## Results

The baseline is the fastest implementation for each cipher in
`results/gpu-speed.csv`. The optimized value is the fastest row in
`results/gpu-speed-optimized.csv`.

| cipher | fastest optimized kernel | baseline GB/s | optimized GB/s | speedup |
|---|---|---:|---:|---:|
| PRESENT-r16 | `bitslice-x32` | 40.02 | 203.53 | 5.09x |
| PRESENT-lin444-r7 | `bitslice-x32` | 83.94 | 261.10 | 3.11x |
| cipher-D-r8 | `byte-global` | 63.49 | 63.72 | 1.00x |
| cipher-D-lin444-r5 | `shared-sbox-x4` | 97.13 | 162.52 | 1.67x |
| cipher-D-AES-lin444-r5 | `bitslice-x32` | 97.56 | 191.63 | 1.96x |
| AES-r5 | `shared-table-x2` | 5.59 | 180.60 | 32.31x |
| AES-lin444-r4 | `shared-sbox-x2` | 29.45 | 289.18 | 9.82x |
| AES-r10 | `shared-table-x2` | 2.62 | 93.74 | 35.79x |
| AES-lin444-r5 | `shared-sbox` | 23.74 | 238.53 | 10.05x |

cipher-D-r8 is the one cipher with no worthwhile optimization. Its S-box is 8-bit and
unstructured, which rules out bitslicing, and its fused byte table already sits in
the cache path, which leaves nothing for shared memory to fix.

## Candidates that did not win

- The 64 KiB AES-lin444 table in shared memory was slower than both its global-table
  version and the 256-byte shared-S-box arithmetic kernel.
- Bitslicing the 128-bit ciphers was not attempted. Holding 32 blocks as 128 planes
  would spill, so it needs the byte-sliced layout with bitsliced ShiftRows and
  MixColumns rather than a wider version of the 64-bit kernel. The T-table kernels
  already reach 180 GB/s at five rounds, so the expected gain did not justify it;
  this is a judgement, not a measurement.
- Shared 16 KiB fused byte tables did not beat the global-cache path for cipher-D-r8.
- Pair-fused PRESENT tables reduced load count but lost the locality advantage of the
  native 2 KiB nibble table.
- A compile-time direct PRESENT round remained much slower than its fused table path;
  specializing a costly bit permutation does not remove the work.

These losing candidates remain in the benchmark because they document the search space
and provide regression controls for future GPU architectures.

## Reproduction

```sh
make build/gpu_bench
build/gpu_bench --blocks 1048576 --csv results/gpu-speed-run.csv
```

`make gpu-bench` writes `results/gpu-speed-optimized.csv`. It must not write
`results/gpu-speed.csv`, which is the frozen pre-optimization baseline this document
compares against.

Every implementation is checked against the scalar host reference before timing. A
mismatch aborts the program, so performance rows are emitted only after the kernel has
passed its correctness gate. The bitsliced kernel adds three gates of its own: the
S-box circuit is evaluated against the variant's own S-box table over all 16 or 256
inputs, the 32x32 transpose is checked against its definition, and the kernel is run
over enough blocks to cross a thread-block boundary and exercise every transpose lane
before its result is compared with the host reference.
