# Full-round PRESENT-80 (31 rounds) and AES-128 (10 rounds) in the project's CTR harness

These are the project harness's CTR backends (bench/ctr_*.c, src/present_*), run
with the full-round cipher set (`CTR_CIPHER_SET=full`, tools/cipher_set.py) instead
of the default seven reduced-round ciphers. Same CTR contract as everything else
here: 12-byte nonce || BE32 counter, key setup outside the timing.

Build: the generated headers (bench/gen/ctr_cipher_set.h, fw/m4/gen/*) are checked in
for the default set, so the full set is built in a separate worktree:

    export CTR_CIPHER_SET=full
    make -B bench/gen/ctr_cipher_set.h fw/m4/gen/cipher_set.h fw/m4/gen/ciphers.mk fw/m4/gen/kat_vectors.h
    make build/kat_fullset && ./build/kat_fullset    # PASS: 44 checks, 0 failures
    make build/ctr_bench

Files:
- `x86-present-aes-{4096,65536}.csv`: `taskset -c 2 ./build/ctr_bench --csv ... --size N`,
  i9-14900HX P-core. `tsc_per_byte` is TSC ticks (2.4 GHz), not core cycles.
- `x86-present-bitslice-avx2-corefreq-khz.txt`: scaling_cur_freq of cpu2 sampled every
  0.1 s (400 samples, mean 5.382 GHz) during a long ctr-bitslice-avx2 run at 64 KiB.
  Core cycles/byte for that backend = 5.382e9 * 8 / (16735 Mbit/s) = 2.57.
- `m4-board-present-80-r31.out`, `m4-board-aes-128-r10.out`: STM32F407 board,
  `python3 tools/run_m4_bench.py --run-only ctr_tune_present_80` (resp. `ctr_tune_aes_128`),
  configuration product (code in flash, 5 WS, prefetch + ART), 64 KiB in place, on-board
  KAT and CTR cross-check before timing (header lines `kat:` / `ctr-kat:`). The firmware
  needed `X(31)` in PRESENT_FIXED_ROUNDS_LIST (include/present/present.h) for the table
  backend at 31 rounds.
- `x86-aes-table-x8-65536-freqrun.csv`, `x86-aes-table-x8-corefreq-khz.txt`: the same for
  AES-128 ctr-table-x8 (best software AES, no AES-NI): 39 samples, mean 5.552 GHz,
  5988 Mbit/s, core cycles/byte = 5.552e9 * 8 / 5988e6 = 7.4.
