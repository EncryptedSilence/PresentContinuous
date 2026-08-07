# Alveo V80 FPGA Capacity Estimate

Only cores meeting their Gowin post-route clock constraint are included. The V80 estimate uses Gowin post-route Fmax without an assumed frequency uplift and reserves 20% of each resource class for routing, control, clocking, and host integration.

## Target

| target | LUTs | flip-flops | BRAM 18 Kb equivalents | usable | source |
| --- | --- | --- | --- | --- | --- |
| alveo-v80 | 2600000 | 5200000 | 7509 | 80% | [V80 product brief](https://www.amd.com/content/dam/amd/en/documents/products/accelerators/alveo/v80/alveo-v80-product-brief.pdf), [Versal CLB manual](https://docs.amd.com/r/en-US/am005-versal-clb/CLB-Resources) |

## Capacity

| core | mode | rounds | block_bits | key_bits | core_registers | core_logic | core_bsram18k | gowin_constraint_mhz | gowin_postroute_fmax_mhz | initiation_interval_cycles | theoretical_cores | theoretical_limit | estimated_cores_80pct | estimated_limit | candidate_tests_per_sec | throughput_gbps | full_keyspace_years |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| present_80_r16_area | area | 16 | 64 | 80 | 300 | 657 | 0 | 240.038 | 240.061 | 257 | 3957 | logic | 3165 | logic | 2.956393e+09 | 189.209 | 1e7.11 |
| present_80_r16_speed | speed | 16 | 64 | 80 | 4657 | 2161 | 0 | 255.820 | 255.979 | 1 | 1116 | registers | 893 | registers | 2.285892e+11 | 14629.712 | 1e5.22 |
| present_80_lin444_297_r7_area | area | 7 | 64 | 80 | 300 | 787 | 0 | 201.979 | 202.711 | 113 | 3303 | logic | 2642 | logic | 4.739491e+09 | 303.327 | 1e6.91 |
| present_80_lin444_297_r7_speed | speed | 7 | 64 | 80 | 2047 | 1920 | 0 | 292.740 | 292.831 | 1 | 1354 | logic | 1083 | logic | 3.171360e+11 | 20296.702 | 1e5.08 |
| cipher_D_area | area | 8 | 64 | 576 | 731 | 1484 | 0 | 176.678 | 176.875 | 65 | 1752 | logic | 1401 | logic | 3.812337e+09 | 243.990 | 1e156.31 |
| cipher_D_speed | speed | 8 | 64 | 576 | 5665 | 8694 | 0 | 156.986 | 157.019 | 1 | 299 | logic | 239 | logic | 3.752754e+10 | 2401.763 | 1e155.32 |
| cipher_D_lin444_297_r5_area | area | 5 | 64 | 384 | 539 | 1300 | 0 | 138.160 | 139.204 | 41 | 2000 | logic | 1600 | logic | 5.432351e+09 | 347.670 | 1e98.36 |
| cipher_D_lin444_297_r5_speed | speed | 5 | 64 | 384 | 2587 | 6106 | 0 | 184.128 | 184.158 | 1 | 425 | logic | 340 | logic | 6.261372e+10 | 4007.278 | 1e97.30 |
| cipher_D_lin444_297_aes_r5_area | area | 5 | 64 | 384 | 539 | 1141 | 0 | 127.000 | 127.052 | 41 | 2278 | logic | 1822 | logic | 5.646067e+09 | 361.348 | 1e98.34 |
| cipher_D_lin444_297_aes_r5_speed | speed | 5 | 64 | 384 | 6357 | 4056 | 0 | 169.434 | 169.586 | 1 | 641 | logic | 512 | logic | 8.682803e+10 | 5556.994 | 1e97.16 |
| aes_r5_area | area | 5 | 128 | 768 | 1052 | 2053 | 0 | 121.847 | 121.857 | 81 | 1266 | logic | 1013 | logic | 1.523965e+09 | 195.067 | 1e214.51 |
| aes_r5_speed | speed | 5 | 128 | 768 | 12677 | 7411 | 0 | 181.357 | 181.442 | 1 | 350 | logic | 280 | logic | 5.080376e+10 | 6502.881 | 1e212.99 |
| aes_lin444_0_8_15_r4_area | area | 4 | 128 | 640 | 924 | 1915 | 0 | 122.745 | 122.749 | 65 | 1357 | logic | 1086 | logic | 2.050853e+09 | 262.509 | 1e175.85 |
| aes_lin444_0_8_15_r4_speed | speed | 4 | 128 | 640 | 9121 | 6369 | 0 | 141.263 | 141.261 | 1 | 408 | logic | 326 | logic | 4.605109e+10 | 5894.539 | 1e174.50 |
