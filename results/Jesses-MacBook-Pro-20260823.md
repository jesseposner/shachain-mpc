# shachain_step benchmark

Host: Jesses-MacBook-Pro, Apple M4 Max, 2026-08-23. 3 parties on loopback. MP-SPDZ 892ac0e.

Times in seconds (wall, including preprocessing). T_sha = K edges of SHA-256, T_chk = scalar validity check, T_b2a = Boolean-to-Z_q conversion. Traffic is party 0 only.

| run | total | T_sha | T_chk | T_b2a | party-0 traffic |
|---|---:|---:|---:|---:|---|
| seq K=1, Rep3 bin, semi-honest | 0.062238 | 0.05333 | 0.008391 | – | 0.004292 MB, 1868 rounds |
| seq K=1, Rep3 bin, malicious | 0.070079 | 0.061987 | 0.007499 | – | 0.476248 MB, 1875 rounds |
| seq K=1, Rep3 +B2A, semi-honest | 0.067863 | 0.058447 | 0.007934 | 0.000922 | 0.0145 MB, 1868 rounds |
| seq K=1, Rep3 +B2A, malicious | 0.075628 | 0.062561 | 0.007644 | 0.004816 | 0.824461 MB, 1905 rounds |
| seq K=10, Rep3 bin, semi-honest | 0.524604 | 0.516407 | 0.007662 | – | 0.039617 MB, 16331 rounds |
| seq K=10, Rep3 bin, malicious | 0.566251 | 0.556606 | 0.009013 | – | 4.04709 MB, 16359 rounds |
| seq K=10, Rep3 +B2A, semi-honest | 0.55045 | 0.540532 | 0.008408 | 0.000969 | 0.049825 MB, 16331 rounds |
| seq K=10, Rep3 +B2A, malicious | 0.522421 | 0.509331 | 0.007736 | 0.004672 | 4.33622 MB, 16368 rounds |
| seq K=1, BMR, semi-honest | 0.071491 | – | – | – | 14.0484 MB, 129 rounds |
| seq K=1, BMR, malicious | 0.258788 | – | – | – | 34.3761 MB, 1755 rounds |
| par N=100, Rep3 bin, semi-honest | 0.078518 | 0.070208 | 0.007705 | – | 0.288696 MB, 1868 rounds |
| par N=100, Rep3 bin, malicious | 0.121594 | 0.11041 | 0.01046 | – | 4.35347 MB, 2106 rounds |
| par N=100, Rep3 +B2A, semi-honest | 0.102113 | 0.079939 | 0.008122 | 0.013276 | 1.11606 MB, 1872 rounds |
| par N=100, Rep3 +B2A, malicious | 0.181392 | 0.090512 | 0.009234 | 0.080842 | 12.573 MB, 1932 rounds |
| par N=1000, Rep3 bin, semi-honest | 0.229285 | 0.217097 | 0.008901 | – | 2.83881 MB, 1868 rounds |
| par N=1000, Rep3 bin, malicious | 0.49109 | 0.474606 | 0.014997 | – | 41.4281 MB, 4213 rounds |
| par N=1000, Rep3 +B2A, semi-honest | 0.332951 | 0.203585 | 0.008145 | 0.117121 | 11.2315 MB, 1918 rounds |
| par N=1000, Rep3 +B2A, malicious | 1.24251 | 0.387532 | 0.008688 | 0.843021 | 124.879 MB, 2310 rounds |
