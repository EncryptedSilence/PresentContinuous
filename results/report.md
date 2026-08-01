# PRESENT_mod results

Speed and differential strength for every variant.

SAT solver: `cadical 3.0.1`

## Summary

`du/bn` are the S-box's differential uniformity and differential branch number (lower du is better, higher bn is better). `gates` is the size of the synthesised bitslice circuit. `cyc/B` is the table implementation's throughput figure; `bitslice` is the 64-block-parallel one. `w(r)` columns give the optimal differential characteristic weight, so probability `2^-w`, and `w/round` is that divided by the deepest round count searched. `rounds@64` is the smallest round count for which the data below *proves* every characteristic costs at least 2^-64; `margin` is the variant's actual round count divided by that.

| variant | rounds | S-box du/bn | gates | cyc/B table | cyc/B bitslice | active(5) | w(5) | w(6) | w/round | best bound w(31) | rounds@64 | margin |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `present-128` | 31 | 4/3 | 20 | 23.07 | 7.58 | 10 | 20 | 24 | 4.33 | 123 | 16 | 1.94x |
| `present-80-identity-p` | 31 | 4/3 | 20 | 24.51 | 7.69 | 5 | 10 | 12 | 2.00 | 62 | 32 | 0.97x |
| `present-80-r16` | 16 | 4/3 | 20 | 10.50 | 4.93 | 10 | 20 | 24 | 4.33 | 123 | 16 | 1.00x |
| `present-80-randperm-p` | 31 | 4/3 | 20 | 23.13 | 8.17 | 5 | 12 | 15 | 3.75 | 108 | 20 | 1.55x |
| `present-80-rotate-p` | 31 | 4/3 | 20 | 23.71 | 8.26 | 5 | 10 | 12 | 2.00 | 62 | 32 | 0.97x |
| `present-80-sbox-opt1` | 31 | 4/2 | 22 | 23.05 | 7.74 | 5 | 13 | 16 | 2.83 | 84 | 24 | 1.29x |
| `present-80-sbox-opt2` | 31 | 4/2 | 17 | 22.84 | 7.23 | 5 | 10 | 12 | 2.00 | 62 | 32 | 0.97x |
| `present-80-sbox-weak1` | 31 | 8/2 | 20 | 23.03 | 7.61 | 5 | 11 | 14 | 2.58 | 75 | 27 | 1.15x |
| `present-80-sbox-weak2` | 31 | 8/2 | 12 | 24.17 | 7.08 | 5 | 9 | 11 | 1.92 | 57 | 35 | 0.89x |
| `present-80` | 31 | 4/3 | 20 | 22.74 | 7.58 | 10 | 20 | 24 | 4.33 | 123 | 16 | 1.94x |

## Per-variant detail

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
| 4 | 6 | 12 | 2^-12 | 0.11 |
| 5 | 10 | 20 | 2^-20 | 0.82 |
| 6 | 12 | 24 | 2^-24 | 1.89 |
| 7 | 14 | 28 | 2^-28 | 3.72 |
| 8 | 16 | 32 | 2^-32 | 5.02 |
| 9 | 18 | 36 | 2^-36 | 10.00 |
| 10 | 20 | 41 | 2^-41 | 23.65 |
| 11 | 22 | 46 | 2^-46 | 49.89 |
| 12 | 24 | 52 | 2^-52 | 134.76 |


## Caveats

- These are single-characteristic bounds. A differential can cluster many characteristics with the same input and output difference, making the differential more probable than the best single characteristic. Use `analysis/cli.py cluster` to measure clustering for a specific difference pair.
- A bound on characteristic probability is not a proof of resistance to differential cryptanalysis, and says nothing about linear, algebraic, or related-key attacks.
- Cycle counts are nominal TSC ticks, not core clock cycles; see the README.

