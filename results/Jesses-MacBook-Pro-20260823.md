# shachain_step benchmark

Host: Jesses-MacBook-Pro, Apple M4 Max, 2026-08-23. 3 parties on loopback. MP-SPDZ 892ac0e.

Times in seconds (wall, including preprocessing). T_sha = K edges of SHA-256, T_chk = scalar validity check, T_b2a = Boolean-to-Z_q conversion. Traffic is party 0 only.

| run | total | T_sha | T_chk | T_b2a | party-0 traffic |
|---|---:|---:|---:|---:|---|
| seq K=1, Rep3 bin, semi-honest | 0.061782 | 0.053934 | 0.007208 | – | 0.004292 MB, 1868 rounds |
| seq K=1, Rep3 bin, malicious | 0.070246 | 0.06219 | 0.00749 | – | 0.476248 MB, 1875 rounds |
| seq K=1, Rep3 +B2A, semi-honest | 0.066366 | 0.05765 | 0.007265 | 0.000922 | 0.0145 MB, 1868 rounds |
| seq K=1, Rep3 +B2A, malicious | 0.07365 | 0.061095 | 0.007385 | 0.004534 | 0.824461 MB, 1905 rounds |
| seq K=10, Rep3 bin, semi-honest | 0.487792 | 0.479707 | 0.007471 | – | 0.039617 MB, 16331 rounds |
| seq K=10, Rep3 bin, malicious | 0.513665 | 0.505989 | 0.007105 | – | 4.04709 MB, 16359 rounds |
| seq K=10, Rep3 +B2A, semi-honest | 0.495323 | 0.486078 | 0.007856 | 0.000879 | 0.049825 MB, 16331 rounds |
| seq K=10, Rep3 +B2A, malicious | 0.516928 | 0.503556 | 0.008119 | 0.004616 | 4.33622 MB, 16368 rounds |
| seq K=1, BMR one-shot, semi-honest | 0.083473 | online: 0.009948 s, 0.008704 MB | garble incl: 0.083473 | – | 14.0484 MB, 129 rounds |
| seq K=1, BMR one-shot, malicious | 0.262712 | online: 0.010874 s, 0.008768 MB | garble incl: 0.262712 | – | 34.3761 MB, 1755 rounds |
| seq K=48, BMR one-shot, semi-honest | 3.79577 | online: 0.487844 s, 0.008704 MB | garble incl: 3.79577 | – | 659.111 MB, 5389 rounds |
| seq K=48, BMR one-shot, malicious | 11.2781 | online: 0.493962 s, 0.008768 MB | garble incl: 11.2781 | – | 1609.87 MB, 81289 rounds |
| seq K=48 cold start, Rep3 bin, malicious | 2.40561 | 2.39704 | 0.007931 | – | 19.1596 MB, 77516 rounds |
| par N=100, Rep3 bin, semi-honest | 0.082831 | 0.074926 | 0.007278 | – | 0.288696 MB, 1868 rounds |
| par N=100, Rep3 bin, malicious | 0.112975 | 0.10374 | 0.00856 | – | 4.35347 MB, 2106 rounds |
| par N=100, Rep3 +B2A, semi-honest | 0.095064 | 0.074673 | 0.007104 | 0.012558 | 1.11606 MB, 1872 rounds |
| par N=100, Rep3 +B2A, malicious | 0.180937 | 0.094373 | 0.007796 | 0.078086 | 12.573 MB, 1932 rounds |
| par N=1000, Rep3 bin, semi-honest | 0.22092 | 0.211819 | 0.007557 | – | 2.83881 MB, 1868 rounds |
| par N=1000, Rep3 bin, malicious | 0.507946 | 0.492207 | 0.014234 | – | 41.4281 MB, 4213 rounds |
| par N=1000, Rep3 +B2A, semi-honest | 0.336815 | 0.211265 | 0.007556 | 0.115577 | 11.2315 MB, 1918 rounds |
| par N=1000, Rep3 +B2A, malicious | 1.2282 | 0.383951 | 0.009036 | 0.832519 | 124.879 MB, 2310 rounds |
