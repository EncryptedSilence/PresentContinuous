# Alveo V80 FPGA Capacity Estimate

Only cores meeting their Gowin post-route clock constraint are included. The V80 estimate uses Gowin post-route Fmax without an assumed frequency uplift and reserves 20% of each resource class for routing, control, clocking, and host integration.

## Target

| target | LUTs | flip-flops | BRAM 18 Kb equivalents | usable | source |
| --- | --- | --- | --- | --- | --- |
| alveo-v80 | 2600000 | 5200000 | 7509 | 80% | [V80 product brief](https://www.amd.com/content/dam/amd/en/documents/products/accelerators/alveo/v80/alveo-v80-product-brief.pdf), [Versal CLB manual](https://docs.amd.com/r/en-US/am005-versal-clb/CLB-Resources) |

## Capacity

| core | mode | rounds | block_bits | key_bits | core_registers | core_logic | core_bsram18k | gowin_constraint_mhz | gowin_postroute_fmax_mhz | initiation_interval_cycles | theoretical_cores | theoretical_limit | estimated_cores_80pct | estimated_limit | candidate_tests_per_sec | throughput_gbps | full_keyspace_years |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| present_80_r16_area | area | 16 | 64 | 80 | 300 | 657 | 0 | 125.000 | 152.828 | 257 | 3957 | logic | 3165 | logic | 1.882104e+09 | 120.455 | 1e7.31 |
| present_80_r16_speed | speed | 16 | 64 | 80 | 4657 | 2161 | 0 | 200.000 | 203.441 | 1 | 1116 | registers | 893 | registers | 1.816728e+11 | 11627.060 | 1e5.32 |
| present_80_lin444_297_r7_area | area | 7 | 64 | 80 | 300 | 787 | 0 | 125.000 | 132.947 | 113 | 3303 | logic | 2642 | logic | 3.108371e+09 | 198.936 | 1e7.09 |
| present_80_lin444_297_r7_speed | speed | 7 | 64 | 80 | 2047 | 1920 | 0 | 200.000 | 214.993 | 1 | 1354 | logic | 1083 | logic | 2.328374e+11 | 14901.595 | 1e5.22 |
| cipher_D_area | area | 8 | 64 | 576 | 731 | 1484 | 0 | 125.000 | 131.414 | 65 | 1752 | logic | 1401 | logic | 2.832477e+09 | 181.279 | 1e156.44 |
| cipher_D_speed | speed | 8 | 64 | 576 | 5665 | 8694 | 0 | 149.993 | 149.998 | 1 | 299 | logic | 239 | logic | 3.584952e+10 | 2294.369 | 1e155.34 |
| cipher_D_lin444_297_r5_area | area | 5 | 64 | 384 | 539 | 1300 | 0 | 125.000 | 125.116 | 41 | 2000 | logic | 1600 | logic | 4.882576e+09 | 312.485 | 1e98.41 |
| cipher_D_lin444_297_r5_speed | speed | 5 | 64 | 384 | 2587 | 6106 | 0 | 179.986 | 179.991 | 1 | 425 | logic | 340 | logic | 6.119694e+10 | 3916.604 | 1e97.31 |
| cipher_D_lin444_297_aes_r5_area | area | 5 | 64 | 384 | 539 | 1141 | 0 | 119.048 | 119.482 | 41 | 2278 | logic | 1822 | logic | 5.309664e+09 | 339.818 | 1e98.37 |
| cipher_D_lin444_297_aes_r5_speed | speed | 5 | 64 | 384 | 6357 | 4056 | 0 | 164.989 | 165.267 | 1 | 641 | logic | 512 | logic | 8.461670e+10 | 5415.469 | 1e97.17 |
| aes_r5_area | area | 5 | 128 | 768 | 1052 | 2053 | 0 | 101.999 | 102.672 | 81 | 1266 | logic | 1013 | logic | 1.284034e+09 | 164.356 | 1e214.58 |
| aes_r5_speed | speed | 5 | 128 | 768 | 12677 | 7411 | 0 | 157.011 | 159.349 | 1 | 350 | logic | 280 | logic | 4.461772e+10 | 5711.068 | 1e213.04 |
| aes_lin444_0_8_15_r4_area | area | 4 | 128 | 640 | 924 | 1915 | 0 | 100.000 | 103.362 | 65 | 1357 | logic | 1086 | logic | 1.726940e+09 | 221.048 | 1e175.92 |
| aes_lin444_0_8_15_r4_speed | speed | 4 | 128 | 640 | 9121 | 6369 | 0 | 139.997 | 141.261 | 1 | 408 | logic | 326 | logic | 4.605109e+10 | 5894.539 | 1e174.50 |
