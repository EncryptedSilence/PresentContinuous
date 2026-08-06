# FPGA Brute-Force Capacity

All successfully routed cores are included. Throughput uses post-route `Actual Fmax`, not the nominal 100 MHz constraint. Area cores use initiation interval `rounds + 2`; speed cores use initiation interval `1`.

## Targets

| target | logic | registers | bsram | source |
| --- | --- | --- | --- | --- |
| alveo-v80 | 2600000 |  |  | AMD Alveo V80 product page: 2.6M LUTs; https://www.amd.com/en/products/accelerators/alveo/v80.html |
| gowin-largest-installed | 138240 | 138240 | 6120 | /home/leo/gowin/Gowin_V1.9.12.02_linux/IDE/data/device/device_info.csv |

## Capacity

| target | core | mode | rounds | timing_met_at_constraint | constraint_mhz | postroute_fmax_mhz | initiation_interval_cycles | cores_fit | limiting_resource | blocks_per_sec | gbps |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| alveo-v80 | present_80_r16_area | area | 16 | no | 100.000 | 69.574 | 18 | 639 | logic | 2469877000.000 | 158.072 |
| gowin-largest-installed | present_80_r16_area | area | 16 | no | 100.000 | 69.574 | 18 | 34 | logic | 131417555.556 | 8.411 |
| alveo-v80 | present_80_r16_speed | speed | 16 | yes | 100.000 | 168.175 | 1 | 1224 | logic | 205846200000.000 | 13174.157 |
| gowin-largest-installed | present_80_r16_speed | speed | 16 | yes | 100.000 | 168.175 | 1 | 65 | logic | 10931375000.000 | 699.608 |
| alveo-v80 | present_80_lin444_297_r7_area | area | 7 | no | 100.000 | 63.780 | 9 | 613 | logic | 4344126666.667 | 278.024 |
| gowin-largest-installed | present_80_lin444_297_r7_area | area | 7 | no | 100.000 | 63.780 | 9 | 32 | logic | 226773333.333 | 14.513 |
| alveo-v80 | present_80_lin444_297_r7_speed | speed | 7 | yes | 100.000 | 125.094 | 1 | 1425 | logic | 178258950000.000 | 11408.573 |
| gowin-largest-installed | present_80_lin444_297_r7_speed | speed | 7 | yes | 100.000 | 125.094 | 1 | 75 | logic | 9382050000.000 | 600.451 |
| alveo-v80 | cipher_D_area | area | 8 | no | 100.000 | 93.975 | 10 | 1092 | logic | 10262070000.000 | 656.772 |
| gowin-largest-installed | cipher_D_area | area | 8 | no | 100.000 | 93.975 | 10 | 58 | logic | 545055000.000 | 34.884 |
| alveo-v80 | cipher_D_speed | speed | 8 | yes | 100.000 | 145.761 | 1 | 4220 | logic | 615111420000.000 | 39367.131 |
| gowin-largest-installed | cipher_D_speed | speed | 8 | yes | 100.000 | 145.761 | 1 | 109 | bsram | 15887949000.000 | 1016.829 |
| alveo-v80 | cipher_D_lin444_297_r5_area | area | 5 | yes | 100.000 | 100.012 | 7 | 1820 | logic | 26003120000.000 | 1664.200 |
| gowin-largest-installed | cipher_D_lin444_297_r5_area | area | 5 | yes | 100.000 | 100.012 | 7 | 96 | logic | 1371593142.857 | 87.782 |
| alveo-v80 | cipher_D_lin444_297_r5_speed | speed | 5 | yes | 100.000 | 108.249 | 1 | 438 | logic | 47413062000.000 | 3034.436 |
| gowin-largest-installed | cipher_D_lin444_297_r5_speed | speed | 5 | yes | 100.000 | 108.249 | 1 | 23 | logic | 2489727000.000 | 159.343 |
| alveo-v80 | cipher_D_lin444_297_aes_r5_area | area | 5 | yes | 100.000 | 100.012 | 7 | 1820 | logic | 26003120000.000 | 1664.200 |
| gowin-largest-installed | cipher_D_lin444_297_aes_r5_area | area | 5 | yes | 100.000 | 100.012 | 7 | 96 | logic | 1371593142.857 | 87.782 |
| alveo-v80 | cipher_D_lin444_297_aes_r5_speed | speed | 5 | yes | 100.000 | 108.249 | 1 | 438 | logic | 47413062000.000 | 3034.436 |
| gowin-largest-installed | cipher_D_lin444_297_aes_r5_speed | speed | 5 | yes | 100.000 | 108.249 | 1 | 23 | logic | 2489727000.000 | 159.343 |
