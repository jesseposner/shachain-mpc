# shachain_step benchmark

Host: Jesses-MacBook-Pro, Apple M4 Max, 2026-08-23. 3 parties on loopback.

MP-SPDZ 892ac0e, shachain-mpc . Recording both matters: figures from before the vectorised-hashing fix or the batching change do not describe the current system.

Times in seconds (wall, including preprocessing). T_sha = K edges of SHA-256, T_chk = scalar validity check, T_b2a = Boolean-to-Z_q conversion. Traffic is party 0 only.

| run | total | T_sha | T_chk | T_b2a | party-0 traffic |
|---|---:|---:|---:|---:|---|
| seq K=1, Rep3 bin, semi-honest | 0.05592 | 0.054283 | 0.000554 | – | 0.004127 MB, 1628 rounds |
| seq K=1, Rep3 bin, malicious | 0.059298 | 0.058113 | 0.00063 | – | 0.482632 MB, 1635 rounds |
| seq K=1, Rep3 +B2A, semi-honest | 0.061577 | 0.0587 | 0.000547 | 0.001266 | 0.014335 MB, 1628 rounds |
| seq K=1, Rep3 +B2A, malicious | 0.062572 | 0.0564 | 0.000652 | 0.004754 | 0.830845 MB, 1665 rounds |
| seq K=10, Rep3 bin, semi-honest | 0.522717 | 0.521682 | 0.000493 | – | 0.039452 MB, 16091 rounds |
| seq K=10, Rep3 bin, malicious | 0.581402 | 0.580194 | 0.000641 | – | 4.05347 MB, 16119 rounds |
| seq K=10, Rep3 +B2A, semi-honest | 0.573907 | 0.571773 | 0.000659 | 0.000907 | 0.04966 MB, 16091 rounds |
| seq K=10, Rep3 +B2A, malicious | 0.587618 | 0.581465 | 0.000665 | 0.004858 | 4.34323 MB, 16128 rounds |
| seq K=1, BMR one-shot, semi-honest | 0.086843 | online: 0.010401 s, 0.008704 MB | garble incl: 0.086843 | – | 14.2909 MB, 129 rounds |
| seq K=1, BMR one-shot, malicious | 0.269215 | online: 0.01032 s, 0.008768 MB | garble incl: 0.269215 | – | 34.9425 MB, 1780 rounds |
| seq K=48, BMR one-shot, semi-honest | 3.37734 | online: 0.542709 s, 0.008704 MB | garble incl: 3.37734 | – | 659.354 MB, 5394 rounds |
| seq K=48, BMR one-shot, malicious | 11.9811 | online: 0.541607 s, 0.008768 MB | garble incl: 11.9811 | – | 1610.44 MB, 81318 rounds |
| seq K=48 cold start, Rep3 bin, malicious | 2.74085 | 2.73956 | 0.000621 | – | 19.1659 MB, 77276 rounds |
| par N=100, Rep3 bin, semi-honest | 0.057701 | 0.056482 | 0.000606 | – | 0.308527 MB, 1628 rounds |
| par N=100, Rep3 bin, malicious | 0.087463 | 0.085324 | 0.00147 | – | 4.59869 MB, 1880 rounds |
| par N=100, Rep3 +B2A, semi-honest | 0.069292 | 0.055273 | 0.000586 | 0.012756 | 1.13589 MB, 1632 rounds |
| par N=100, Rep3 +B2A, malicious | 0.150811 | 0.071639 | 0.000685 | 0.07763 | 12.8007 MB, 1692 rounds |
| par N=1000, Rep3 bin, semi-honest | 0.062465 | 0.060479 | 0.000635 | – | 3.03787 MB, 1628 rounds |
| par N=1000, Rep3 bin, malicious | 0.364725 | 0.350589 | 0.012715 | – | 44.3763 MB, 4141 rounds |
| par N=1000, Rep3 +B2A, semi-honest | 0.178187 | 0.059164 | 0.000736 | 0.116884 | 11.4305 MB, 1678 rounds |
| par N=1000, Rep3 +B2A, malicious | 1.01944 | 0.246569 | 0.001468 | 0.769908 | 127.238 MB, 2070 rounds |
