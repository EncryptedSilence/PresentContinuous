# PRESENT_mod results

Speed and differential strength for every variant.

SAT solver: `cadical 3.0.1`

## Summary

`du/bn` are the S-box's differential uniformity and differential branch number (lower du is better, higher bn is better). `gates` is the size of the synthesised bitslice circuit -- comparable only within a width, since a 4-bit S-box covers four state bits and an 8-bit one covers eight. The three `cyc/B` columns are the single-block table implementation, the 4-way interleaved one, and the AVX2 bitsliced one (256 blocks at a time) -- lower is better, and the spread between them is much larger than the spread between variants. Absolute cyc/B depend on what else the machine was doing when `make bench` last ran, so compare variants with `tools/compare.sh`, which reports within-process ratios, rather than by subtracting columns here. Which of the three wins is not fixed: AVX2 is fastest for every 4-bit variant and slowest for the 8-bit one, whose circuit is 74x larger. `w(r)` columns give the optimal differential characteristic weight, so probability `2^-w`, and `w/round` is that divided by the deepest round count searched. `rounds@64` is the smallest round count for which the data below *proves* every characteristic costs at least 2^-64; `margin` is the variant's actual round count divided by that.

| variant | rounds | S-box du/bn | gates | table | table-x4 | avx2 | active(5) | w(5) | w(6) | w/round | bound w(rounds) | rounds@64 | margin |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `cipher-D-lin444-1-15-13` | 8 | 4/3 | 1107 | 4.76 | 2.72 | 7.53 | - | - | - | - | - | - | - |
| `cipher-D-lin444-297-aes-r5` | 5 | 4/2 | 132 | 2.50 | 1.64 | 1.28 | - | - | - | 18.25 | 73 | 4 | 1.25x |
| `cipher-D-lin444-297-aes` | 8 | 4/2 | 132 | 4.59 | 2.61 | 1.80 | - | - | - | 18.25 | 146 | 4 | 2.00x |
| `cipher-D-lin444-297` | 8 | 4/3 | 1107 | 4.77 | 2.72 | 7.44 | - | - | - | 17.00 | 136 | 4 | 2.00x |
| `cipher-D` | 8 | 4/3 | 1107 | 4.76 | 2.72 | 7.64 | 7 | 44 | 51 | 9.62 | 77 | 7 | 1.14x |
| `present-128` | 31 | 4/3 | 15 | 27.13 | 10.50 | 1.48 | 10 | 20 | 24 | 4.33 | 123 | 16 | 1.94x |
| `present-80-identity-p` | 31 | 4/3 | 15 | 25.56 | 10.32 | 1.46 | 5 | 10 | 12 | 2.00 | 62 | 32 | 0.97x |
| `present-80-lin444-013-r16` | 16 | 4/3 | 15 | 12.08 | 5.36 | 1.58 | - | - | - | - | - | - | - |
| `present-80-lin444-013` | 31 | 4/3 | 15 | 25.05 | 10.21 | 2.66 | - | - | - | 8.00 | 224 | 8 | 3.88x |
| `present-80-lin444-1-15-13` | 31 | 4/3 | 15 | 26.00 | 10.66 | 2.65 | - | - | - | 9.00 | 252 | 8 | 3.88x |
| `present-80-lin444-213` | 31 | 4/3 | 15 | 25.85 | 10.82 | 2.70 | - | - | - | 7.00 | 196 | 12 | 2.58x |
| `present-80-lin444-297-r18` | 18 | 4/3 | 15 | 13.84 | 6.01 | 1.67 | - | - | - | - | - | - | - |
| `present-80-lin444-297` | 31 | 4/3 | 15 | 25.73 | 11.34 | 2.63 | - | - | - | 9.67 | 290 | 9 | 3.44x |
| `present-80-r16` | 16 | 4/3 | 15 | 12.03 | 5.23 | 0.91 | 10 | 20 | 24 | 4.33 | 64 | 16 | 1.00x |
| `present-80-randperm-p` | 31 | 4/3 | 15 | 25.41 | 10.01 | 1.40 | 5 | 12 | 15 | 3.75 | 108 | 20 | 1.55x |
| `present-80-rotate-p` | 31 | 4/3 | 15 | 25.51 | 10.51 | 1.42 | 5 | 10 | 12 | 2.00 | 62 | 32 | 0.97x |
| `present-80-sbox-opt1` | 31 | 4/2 | 15 | 26.14 | 10.07 | 1.52 | 5 | 13 | 16 | 2.83 | 84 | 24 | 1.29x |
| `present-80-sbox-opt2` | 31 | 4/2 | 11 | 25.50 | 10.22 | 1.26 | 5 | 10 | 12 | 2.00 | 62 | 32 | 0.97x |
| `present-80-sbox-weak1` | 31 | 8/2 | 16 | 25.41 | 10.02 | 1.47 | 5 | 11 | 14 | 2.58 | 75 | 27 | 1.15x |
| `present-80-sbox-weak2` | 31 | 8/2 | 8 | 25.70 | 10.23 | 1.17 | 5 | 9 | 11 | 1.92 | 57 | 35 | 0.89x |
| `present-80` | 31 | 4/3 | 15 | 27.14 | 11.41 | 1.43 | 10 | 20 | 24 | 4.33 | 123 | 16 | 1.94x |

## Per-variant detail

### `cipher-D-lin444-1-15-13`

Cipher-D with its bit permutation replaced by the lin444_r1 XOR-rotate layer, c0=(1, 15, 13): the cheapest to evaluate bitsliced of the four (160 XORs/round) and the fastest on PRESENT; kept as the speed control. Same 8-bit S-box, same 8 rounds plus a whitening key, same raw 576-bit key. Four 16-bit words, unitriangular over GF(2) so always invertible.

- S-box: differential uniformity 4, linearity 32, algebraic degree 7, branch number 3
- Weight per active S-box: [0, 6, 7] (exact)

_no differential results yet; run `make analysis`_

### `cipher-D-lin444-297-aes-r5`

cipher-D-lin444-297 with the AES S-box (FIPS-197: inversion in GF(2^8) mod 0x11B, then the AES affine map), 5 rounds -- cut to the point where the proven bound is still past 2^-64. Same lin444 c0=(2, 9, 7) layer, same raw key. The AES S-box has a 113-gate published circuit against the ~1100 gates this repository's BDD synthesis finds for cipher-D's supplied table.

- S-box: differential uniformity 4, linearity 32, algebraic degree 7, branch number 2
- Weight per active S-box: [0, 6, 7] (exact)
- Provable bound: every differential characteristic over 5 rounds has probability at most 2^-73

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 6 | 2^-6 | 0.08 |
| 2 | 4 | 24 | 2^-24 | 1.35 |
| 3 | 8 | 50 | 2^-50 | 49.06 |
| 4 | 11 | 73 | 2^-73 | 607.20 |

### `cipher-D-lin444-297-aes`

cipher-D-lin444-297 with the AES S-box (FIPS-197: inversion in GF(2^8) mod 0x11B, then the AES affine map), 8 rounds -- cipher-D's own round count. Same lin444 c0=(2, 9, 7) layer, same raw key. The AES S-box has a 113-gate published circuit against the ~1100 gates this repository's BDD synthesis finds for cipher-D's supplied table.

- S-box: differential uniformity 4, linearity 32, algebraic degree 7, branch number 2
- Weight per active S-box: [0, 6, 7] (exact)
- Provable bound: every differential characteristic over 8 rounds has probability at most 2^-146

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 6 | 2^-6 | 0.09 |
| 2 | 4 | 24 | 2^-24 | 1.41 |
| 3 | 8 | 50 | 2^-50 | 53.63 |
| 4 | 11 | 73 | 2^-73 | 633.61 |

### `cipher-D-lin444-297`

Cipher-D with its bit permutation replaced by the lin444_r1 XOR-rotate layer, c0=(2, 9, 7): highest ShiftGen2 score (13.19), and by far the strongest of the four on PRESENT (2^-290 over 31 rounds); 192 XORs/round. Same 8-bit S-box, same 8 rounds plus a whitening key, same raw 576-bit key. Four 16-bit words, unitriangular over GF(2) so always invertible.

- S-box: differential uniformity 4, linearity 32, algebraic degree 7, branch number 3
- Weight per active S-box: [0, 6, 7] (exact)
- Provable bound: every differential characteristic over 8 rounds has probability at most 2^-136

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 6 | 2^-6 | 0.13 |
| 2 | 4 | 24 | 2^-24 | 0.89 |
| 3 | 8 | 52 | 2^-52 | 125.88 |
| 4 | 10 | 68 | 2^-68 | 399.59 |

### `cipher-D`

Cipher-D: 8-bit S-box (differential uniformity 4, branch number 3), pLayer L(i)=i//8+8*(i%8) -- the 8x8 bit transpose, so bit k of S-box j becomes bit j of S-box k. 8 rounds plus a whitening key; round keys independent (a raw 576-bit key, not derived from anything shorter).

- S-box: differential uniformity 4, linearity 32, algebraic degree 7, branch number 3
- Weight per active S-box: [0, 6, 7] (exact)
- Provable bound: every differential characteristic over 8 rounds has probability at most 2^-77

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 6 | 2^-6 | 0.09 |
| 2 | 2 | 12 | 2^-12 | 0.28 |
| 3 | 4 | 24 | 2^-24 | 0.85 |
| 4 | 6 | 36 | 2^-36 | 2.57 |
| 5 | 7 | 44 | 2^-44 | 12.60 |
| 6 | 8 | 51 | 2^-51 | 20.95 |
| 7 | 10 | 64 | 2^-64 | 63.28 |
| 8 | 12 | 77 | 2^-77 | 145.70 |

### `present-128`

Original PRESENT-128: same round function, 128-bit key schedule.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-123

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.01 |
| 3 | 4 | 8 | 2^-8 | 0.02 |
| 4 | 6 | 12 | 2^-12 | 0.10 |
| 5 | 10 | 20 | 2^-20 | 0.91 |
| 6 | 12 | 24 | 2^-24 | 1.95 |
| 7 | 14 | 28 | 2^-28 | 3.73 |
| 8 | 16 | 32 | 2^-32 | 5.04 |
| 9 | 18 | 36 | 2^-36 | 10.05 |
| 10 | 20 | 41 | 2^-41 | 23.57 |
| 11 | 22 | 46 | 2^-46 | 49.99 |
| 12 | 24 | 52 | 2^-52 | 134.78 |

### `present-80-identity-p`

pLayer replaced by the identity: no diffusion between S-boxes at all. Deliberately broken; used to confirm the analysis detects weakness.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-62

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.01 |
| 3 | 3 | 6 | 2^-6 | 0.01 |
| 4 | 4 | 8 | 2^-8 | 0.02 |
| 5 | 5 | 10 | 2^-10 | 0.03 |
| 6 | 6 | 12 | 2^-12 | 0.04 |
| 7 | 7 | 14 | 2^-14 | 0.06 |
| 8 | 8 | 16 | 2^-16 | 0.07 |
| 9 | 9 | 18 | 2^-18 | 0.10 |
| 10 | 10 | 20 | 2^-20 | 0.13 |
| 11 | 11 | 22 | 2^-22 | 0.17 |
| 12 | 12 | 24 | 2^-24 | 0.18 |

### `present-80-lin444-013-r16`

lin444 c0=(0, 1, 3) cut to 16 rounds, the count at which its proven differential margin matches full PRESENT's 1.94x. Answers whether a stronger-but-slower layer wins once the rounds it saves are taken into account.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)

_no differential results yet; run `make analysis`_

### `present-80-lin444-013`

pLayer replaced by the lin444_r1 XOR-rotate layer with c0=(0, 1, 3): best branch number (bmin 7); score 13.11; 192 XORs/round. Four 16-bit words, unitriangular over GF(2) so always invertible.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-224

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.01 |
| 2 | 5 | 10 | 2^-10 | 0.20 |
| 3 | 9 | 20 | 2^-20 | 17.31 |
| 4 | 14 | 32 | 2^-32 | 264.40 |

### `present-80-lin444-1-15-13`

pLayer replaced by the lin444_r1 XOR-rotate layer with c0=(1, 15, 13): best arithmetic-progression triple, so 160 XORs/round; bmin 7; score 11.66. Four 16-bit words, unitriangular over GF(2) so always invertible.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-252

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.01 |
| 2 | 5 | 10 | 2^-10 | 0.19 |
| 3 | 10 | 21 | 2^-21 | 24.32 |
| 4 | 16 | 36 | 2^-36 | 1371.83 |

### `present-80-lin444-213`

pLayer replaced by the lin444_r1 XOR-rotate layer with c0=(2, 1, 3): best triple with c2 == c0+c1, so 144 XORs/round; bmin 7; score 12.25. Four 16-bit words, unitriangular over GF(2) so always invertible.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-196

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 4 | 8 | 2^-8 | 0.06 |
| 3 | 8 | 16 | 2^-16 | 3.51 |
| 4 | 11 | 28 | 2^-28 | 121.72 |

### `present-80-lin444-297-r18`

lin444 c0=(2, 9, 7) cut to 18 rounds, the count at which its proven differential margin matches full PRESENT's 1.94x. Answers whether a stronger-but-slower layer wins once the rounds it saves are taken into account.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)

_no differential results yet; run `make analysis`_

### `present-80-lin444-297`

pLayer replaced by the lin444_r1 XOR-rotate layer with c0=(2, 9, 7): highest ShiftGen2 score (13.19); bmin 6; 192 XORs/round. Four 16-bit words, unitriangular over GF(2) so always invertible.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-290

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.01 |
| 2 | 6 | 12 | 2^-12 | 0.39 |
| 3 | 13 | 29 | 2^-29 | 896.38 |
| 4 | ≥19 | ≥38 | 2^-38 | 3220.01 |

### `present-80-r16`

PRESENT-80 reduced to 16 rounds. Round-count axis.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 16 rounds has probability at most 2^-64

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.01 |
| 3 | 4 | 8 | 2^-8 | 0.02 |
| 4 | 6 | 12 | 2^-12 | 0.09 |
| 5 | 10 | 20 | 2^-20 | 0.75 |
| 6 | 12 | 24 | 2^-24 | 2.12 |
| 7 | 14 | 28 | 2^-28 | 3.67 |
| 8 | 16 | 32 | 2^-32 | 5.02 |
| 9 | 18 | 36 | 2^-36 | 10.11 |
| 10 | 20 | 41 | 2^-41 | 23.50 |
| 11 | 22 | 46 | 2^-46 | 49.94 |
| 12 | 24 | 52 | 2^-52 | 134.63 |

### `present-80-randperm-p`

pLayer replaced by a pseudorandom bit permutation (seeded, reproducible). Tests whether PRESENT's designed pLayer beats an arbitrary one.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-108

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.01 |
| 3 | 3 | 6 | 2^-6 | 0.02 |
| 4 | 4 | 9 | 2^-9 | 0.05 |
| 5 | 5 | 12 | 2^-12 | 0.21 |
| 6 | 6 | 15 | 2^-15 | 0.36 |
| 7 | 8 | 19 | 2^-19 | 1.00 |
| 8 | 10 | 24 | 2^-24 | 3.31 |
| 9 | 12 | 30 | 2^-30 | 11.31 |
| 10 | 14 | 36 | 2^-36 | 38.95 |
| 11 | 16 | 42 | 2^-42 | 118.04 |
| 12 | 17 | 45 | 2^-45 | 136.33 |

### `present-80-rotate-p`

pLayer replaced by a rotation of the state by one bit. Diffusion stays local: each S-box feeds only its neighbours.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-62

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.01 |
| 3 | 3 | 6 | 2^-6 | 0.01 |
| 4 | 4 | 8 | 2^-8 | 0.02 |
| 5 | 5 | 10 | 2^-10 | 0.03 |
| 6 | 6 | 12 | 2^-12 | 0.04 |
| 7 | 7 | 14 | 2^-14 | 0.06 |
| 8 | 8 | 16 | 2^-16 | 0.08 |
| 9 | 9 | 18 | 2^-18 | 0.10 |
| 10 | 10 | 20 | 2^-20 | 0.14 |
| 11 | 11 | 22 | 2^-22 | 0.24 |
| 12 | 12 | 24 | 2^-24 | 0.35 |

### `present-80-sbox-opt1`

PRESENT-80 with an alternative optimal 4-bit S-box (differential uniformity 4, linearity 8), found by seeded search.

- S-box: differential uniformity 4, linearity 8, algebraic degree 3, branch number 2
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-84

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.01 |
| 3 | 3 | 7 | 2^-7 | 0.03 |
| 4 | 4 | 10 | 2^-10 | 0.10 |
| 5 | 5 | 13 | 2^-13 | 0.21 |
| 6 | 6 | 16 | 2^-16 | 0.65 |
| 7 | 7 | 19 | 2^-19 | 1.04 |
| 8 | 8 | 22 | 2^-22 | 2.03 |
| 9 | 9 | 25 | 2^-25 | 3.44 |
| 10 | 10 | 28 | 2^-28 | 6.30 |
| 11 | 11 | 31 | 2^-31 | 9.98 |
| 12 | 12 | 34 | 2^-34 | 14.70 |

### `present-80-sbox-opt2`

PRESENT-80 with an alternative optimal 4-bit S-box (differential uniformity 4, linearity 8), found by seeded search.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 2
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-62

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.01 |
| 3 | 3 | 6 | 2^-6 | 0.01 |
| 4 | 4 | 8 | 2^-8 | 0.02 |
| 5 | 5 | 10 | 2^-10 | 0.02 |
| 6 | 6 | 12 | 2^-12 | 0.04 |
| 7 | 7 | 14 | 2^-14 | 0.10 |
| 8 | 8 | 16 | 2^-16 | 0.13 |
| 9 | 9 | 18 | 2^-18 | 0.14 |
| 10 | 10 | 20 | 2^-20 | 0.28 |
| 11 | 11 | 22 | 2^-22 | 0.37 |
| 12 | 12 | 24 | 2^-24 | 0.46 |

### `present-80-sbox-weak1`

PRESENT-80 with a deliberately weaker S-box (differential uniformity 8), so a single active S-box can cost as little as one bit of probability.

- S-box: differential uniformity 8, linearity 8, algebraic degree 3, branch number 2
- Weight per active S-box: [0, 1, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-75

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 1 | 2^-1 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.02 |
| 3 | 3 | 6 | 2^-6 | 0.05 |
| 4 | 4 | 8 | 2^-8 | 0.11 |
| 5 | 5 | 11 | 2^-11 | 0.36 |
| 6 | 6 | 14 | 2^-14 | 1.08 |
| 7 | 7 | 17 | 2^-17 | 2.01 |
| 8 | 8 | 19 | 2^-19 | 3.17 |
| 9 | 9 | 22 | 2^-22 | 5.79 |
| 10 | 10 | 25 | 2^-25 | 9.46 |
| 11 | 11 | 28 | 2^-28 | 12.44 |
| 12 | 12 | 31 | 2^-31 | 20.33 |

### `present-80-sbox-weak2`

PRESENT-80 with a deliberately weaker S-box (differential uniformity 8), so a single active S-box can cost as little as one bit of probability.

- S-box: differential uniformity 8, linearity 16, algebraic degree 2, branch number 2
- Weight per active S-box: [0, 1, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-57

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 1 | 2^-1 | 0.00 |
| 2 | 2 | 3 | 2^-3 | 0.01 |
| 3 | 3 | 5 | 2^-5 | 0.03 |
| 4 | 4 | 7 | 2^-7 | 0.07 |
| 5 | 5 | 9 | 2^-9 | 0.11 |
| 6 | 6 | 11 | 2^-11 | 0.26 |
| 7 | 7 | 13 | 2^-13 | 0.57 |
| 8 | 8 | 15 | 2^-15 | 0.87 |
| 9 | 9 | 17 | 2^-17 | 1.51 |
| 10 | 10 | 19 | 2^-19 | 2.19 |
| 11 | 11 | 21 | 2^-21 | 3.31 |
| 12 | 13 | 23 | 2^-23 | 4.71 |

### `present-80`

Original PRESENT-80 (Bogdanov et al., CHES 2007). Reference variant.

- S-box: differential uniformity 4, linearity 8, algebraic degree 2, branch number 3
- Weight per active S-box: [0, 2, 3] (exact)
- Provable bound: every differential characteristic over 31 rounds has probability at most 2^-123

| rounds | min active S-boxes | min weight | probability | solver s |
|---|---|---|---|---|
| 1 | 1 | 2 | 2^-2 | 0.00 |
| 2 | 2 | 4 | 2^-4 | 0.01 |
| 3 | 4 | 8 | 2^-8 | 0.02 |
| 4 | 6 | 12 | 2^-12 | 0.08 |
| 5 | 10 | 20 | 2^-20 | 0.67 |
| 6 | 12 | 24 | 2^-24 | 1.59 |
| 7 | 14 | 28 | 2^-28 | 3.19 |
| 8 | 16 | 32 | 2^-32 | 4.25 |
| 9 | 18 | 36 | 2^-36 | 8.65 |
| 10 | 20 | 41 | 2^-41 | 20.79 |
| 11 | 22 | 46 | 2^-46 | 45.73 |
| 12 | 24 | 52 | 2^-52 | 123.84 |


## Caveats

- These are single-characteristic bounds. A differential can cluster many characteristics with the same input and output difference, making the differential more probable than the best single characteristic. Use `analysis/cli.py cluster` to measure clustering for a specific difference pair.
- A bound on characteristic probability is not a proof of resistance to differential cryptanalysis, and says nothing about linear, algebraic, or related-key attacks.
- Cycle counts are nominal TSC ticks, not core clock cycles; see the README.

