#!/usr/bin/env python3
"""Write party 0's MP-SPDZ input file for shachain_step.

Usage: input.py <mp-spdz-dir> <seed-hex> [n]

The program reads the 32-byte value as one 256-bit integer whose bit i is
v[i] = bit (7 - i % 8) of byte i // 8 (see shachain_step.mpc). n copies are
written so that N parallel chains can be fed.
"""
import sys

mpspdz, seed_hex = sys.argv[1], sys.argv[2]
n = int(sys.argv[3]) if len(sys.argv) > 3 else 1
seed = bytes.fromhex(seed_hex)
assert len(seed) == 32
val = 0
for i in range(256):
    val |= ((seed[i // 8] >> (7 - i % 8)) & 1) << i
with open(f'{mpspdz}/Player-Data/Input-P0-0', 'w') as f:
    f.write('\n'.join([str(val)] * n) + '\n')
