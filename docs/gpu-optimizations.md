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

The final binary was compiled with CUDA 13.0 for `sm_120`. The active kernels have no
register spills. Launch sweeps at 128, 256, and 512 threads per block showed that 256
threads is the best general default; smaller differences between sweep runs should be
treated as clock and power-management noise on the laptop GPU.

## Most effective optimizations

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

This is the largest measured improvement: 31.2x for AES-r5 and 35.4x for AES-r10.

### Shared S-box with arithmetic lin444

The fused AES-lin444 table occupies 64 KiB and returns a full 128-bit contribution for
each input byte. Its random global loads dominate the short four- and five-round
ciphers. Copying the full table to shared memory also performs poorly: it consumes most
of a multiprocessor's shared-memory budget and costs 64 KiB of setup traffic per CUDA
block.

The winning kernel copies only the 256-byte S-box to shared memory. It substitutes the
16 state bytes there and evaluates `lin444` directly with compile-time rotate constants.
This raises AES-lin444-r4 from 29.45 to 287.75 GB/s and AES-lin444-r5 from 23.74 to
237.77 GB/s.

The same strategy is best for the 64-bit, five-round cipher-D lin444 variants. Four
independent states per thread amortize the shared S-box setup and expose enough
independent work to hide lookup latency. Both variants reach about 160 GB/s, around
1.6-1.7x their previous fused-table results.

### Specialized PRESENT nibble table

PRESENT's native table is only 2 KiB: 16 positions by 16 possible nibbles, with each
entry already containing the S-box and linear-layer contribution. For
PRESENT-lin444-r7, placing this table in shared memory and specializing the seven-round
loop raises throughput from 83.94 to 88.92 GB/s.

Combining two PRESENT nibbles into each lookup halves the lookup count but expands the
working set to 16 KiB. It was slower on this GPU. Original PRESENT-r16 therefore keeps
the existing 2 KiB global-table kernel, whose 40.05 GB/s remains the best measured
implementation.

### Compile-time specialization and state alignment

Round count, S-box width, linear-layer kind, and rotation constants are template
arguments in the optimized kernels. This removes round-time branches and permits full
unrolling. The 128-bit state is explicitly 16-byte aligned so CUDA can use vectorized
state loads and stores.

The 64-bit benchmark also tests one, two, and four states per thread. More interleaving
is not automatically faster: the best depth is x1 for AES-lin444, x2 for AES T-tables,
and x4 for the five-round 64-bit lin444 designs.

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
| PRESENT-r16 | `table` | 40.02 | 40.05 | 1.00x |
| PRESENT-lin444-r7 | `nibble-shared-ct` | 83.94 | 88.92 | 1.06x |
| cipher-D-r8 | `byte-global` | 63.49 | 63.86 | 1.01x |
| cipher-D-lin444-r5 | `shared-sbox-x4` | 97.13 | 162.72 | 1.68x |
| cipher-D-AES-lin444-r5 | `shared-sbox-x4` | 97.56 | 160.04 | 1.64x |
| AES-r5 | `shared-table-x2` | 5.59 | 174.30 | 31.19x |
| AES-lin444-r4 | `shared-sbox` | 29.45 | 287.75 | 9.77x |
| AES-r10 | `shared-table-x2` | 2.62 | 92.61 | 35.36x |
| AES-lin444-r5 | `shared-sbox` | 23.74 | 237.77 | 10.02x |

## Candidates that did not win

- Four-state interleaving did not hide more AES T-table latency and reduced throughput
  relative to the two-state kernel.
- The 64 KiB AES-lin444 table in shared memory was slower than both its global-table
  version and the 256-byte shared-S-box arithmetic kernel.
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

Every implementation is checked against the scalar host reference before timing. A
mismatch aborts the program, so performance rows are emitted only after the kernel has
passed its correctness gate.
