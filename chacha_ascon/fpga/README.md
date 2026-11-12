# Full-round FPGA cores (GW5A-25A)

Round-iterative cores of the full-round ciphers in the report (`docs/fullround-report.md`, §7):
one round per clock, the key schedule computed on the fly, and the next block loaded in the
clock of the last round, so the engine never idles between blocks.

| core | file | block | clocks/block (II) | first block after `load` |
|---|---|---|---|---|
| AES-128-CTR | `rtl/aes_ctr.v` (`NK=4`) | 128 bit | 10 | 11 |
| AES-256-CTR | `rtl/aes_ctr.v` (`NK=8`) | 128 bit | 14 | 15 |
| Qalqan-CTR | `rtl/qalqan_ctr.v` | 128 bit | 15 | 290 (273-step key schedule once per key) |
| ChaCha20 | `rtl/chacha20_ctr.v` | 512 bit | 20 | 22 |
| Ascon-AEAD128 | `rtl/ascon128_aead.v` | 128 bit | 8 (p^8 per block) | init 13, last block to tag 12 |
| PRESENT-80-CTR | `rtl/present80_ctr.v` | 64 bit | 31 | 32 |

The CTR contracts are those of the software (`include/blockctr.h`: nonce[12] ‖ BE32(ctr+j); PRESENT
BE64(ctr+j); ChaCha20 RFC 8439; Ascon SP 800-232), so a core produces byte-for-byte the keystream
of the C implementations.

## Verification: `make sim`

1. Runs the host KAT suite (`make -C .. test`), so the reference C code is checked first.
2. `tools/gen_tables.py` takes the S-boxes from the C sources (`rtl/*.vh`).
3. `tools/gen_vectors.c`, linked to the reference objects, writes vectors to
   `build/ca/fpga/vec`. Case 0 of each cipher is a published KAT (FIPS-197 C.1/C.3, the Qalqan
   sample, RFC 8439, PRESENT key 0), and the others include counter wrap-around. Ascon covers
   AD and message lengths of 0..1024 bytes across the block boundaries.
4. Every core runs under Icarus (`tb/tb_ctr.v`, `tb/tb_ascon.v`). The testbench checks every
   keystream block (Ascon: every ciphertext block and the tag) and measures the II and latency
   in the table above. A corrupted vector makes it fail.

## Resources and Fmax without a Gowin license: `make oss`

`tools/oss_flow.py` runs the open-source flow (yosys `synth_gowin -family gw5a`,
nextpnr-himbaechel with the Apicula database for the GW5A-25A, part GW5A-LV25MG121NES) for each
core:

- **core only:** the core module synthesized alone, giving LUT4, MUX2_LUT*, ALU and FF counts
  (`core_*` columns);
- **wrapper:** `rtl/tops.v` is placed and routed with three seeds, giving post-route Fmax from
  nextpnr's timing model (best and median) and the utilisation of the whole design (`top_*`).
  The wrapper feeds key, nonce and counter from a serial shift register and XOR-folds every
  output block onto 8 pins, so nothing is constant-folded. Pins come from the MBGA121N pin table
  of the Gowin IDE installation (`GOWIN`); this needs no license.
- throughput = Fmax × block bits / II.

The same flow also runs on the reduced-round cores in `fpga/generated/`, which have real Gowin
IDE results (`results/fpga-gowin.md`). The `calib_*` rows put the two tools side by side on the
same device. **The open-source numbers are estimates.** Gowin's synthesis and timing model
differ from yosys/nextpnr, so the publishable figures are Gowin's (see below).

Details that change the numbers:

- **Two LUT mappers.** Every design is synthesized twice, with yosys' default `abc9` and with the
  classic `abc` (`-noabc9`); the `mapper` column says which. They differ by up to 2.4× in LUTs
  (Qalqan: 15.4k with abc9, 6.5k with abc), so the report gives the range.
- **`-nolutram`.** nextpnr-himbaechel has no GW5A placement for LUT RAM (RAM16SDP4), so Qalqan's
  16 × 128-bit round-key memory becomes block RAM (4 BSRAM) here. Gowin may use LUT RAM instead.
- **Calibration** (`calib_*` rows, ratio open flow / Gowin, on the six round-iterative "area" cores):
  LUT 0.78–1.30, FF 1.07–1.16, Fmax 0.71–1.13. Fmax is most pessimistic through the 8-bit
  AES S-boxes (0.71–0.92). There is one outlier (`abc` on cipher_D_area: 550 vs 177 MHz). On the unrolled "speed"
  cores the LUT ratio goes up to 7.7, so do not use those as a reference.
- yowasp-yosys is a 32-bit WebAssembly build: `calib_cipher_D_speed` with `abc9` runs out of its
  4 GiB address space (`bad_alloc`). The full-round cores are far below that.
- Fmax: the median of three placer seeds. The best seed is up to 30 % higher (PRESENT, Ascon).
- A full run (13 calibration and 6 full-round designs × 2 mappers × 3 seeds) takes about 40 minutes with 4 jobs.

Tools are YoWASP builds in two virtualenvs, because yosys and nextpnr need different wasmtime
versions:
`~/.local/share/fpga-oss` (yowasp-yosys 0.59, wasmtime < 30) and `~/.local/share/fpga-oss-pnr`
(yowasp-nextpnr-himbaechel-gowin 0.11, wasmtime 47). Override them with `YOSYS=` and `NEXTPNR=`.

Output: `chacha_ascon/results/fpga/oss-gw5a.csv`; logs in `build/ca/fpga/oss/<core>/`.

## Gowin IDE (the reported numbers)

```
make gowin-projects        # gen/gowin/<core>/{<core>.gprj, cipher_core.sdc, build_gowin.tcl} (wipes gen/gowin)
make gowin-build           # fpga/build_all_gowin.sh over gen/modules.txt (GOWIN=, GW_SH=)
make gowin-sweep           # tools/gowin_sweep.py: clock-constraint sweep -> results/fpga/gowin-sweep.csv
make gowin-report          # tools/gowin_collect.py -> results/fpga/gowin-gw5a.{csv,md}
```

The projects reuse the repository's Gowin tooling unchanged. The wrappers name the core instance
`core`, so the collector reports the core's own resources, as it does for the reduced-round
cores. Gowin's place-and-route is timing-driven. A core that meets a loose constraint
gets faster with a tighter one (Qalqan 78 → 103 MHz, Ascon 115 → 138 MHz). So the sweep raises
the constraint while Fmax grows, and leaves every project built at a constraint it meets.

Results (Gowin IDE 1.9.12.02, GW5A-LV25MG121NES, every core meets timing at its Fmax):

| core | LUT | FF | ALU | BSRAM | Fmax MHz | Mbit/s |
|---|---|---|---|---|---|---|
| ascon128 | 1831 | 715 | | | 138.0 | 2208 |
| aes128 | 6404 | 646 | | | 104.7 | 1340 |
| chacha20 | 2837 | 1960 | 896 | | 50.1 | 1283 |
| qalqan | 3749 | 1165 | 472 | 4 | 103.3 | 881 |
| aes256 | 7764 | 902 | | | 93.4 | 854 |
| present80 | 681 | 359 | | | 206.2 | 426 |

Critical paths:
- ChaCha20: four dependent 32-bit additions of a quarter-round (22.6 ns).
- AES-256: the key schedule (`rk1` → S-box → w0..w3 XOR chain → state).
- AES-128: the round.
- Qalqan: the 128-bit addition counter block + rk0 at the load of the next block. It could be
  computed a clock ahead.
