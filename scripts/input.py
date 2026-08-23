#!/usr/bin/env python3
"""Write party 0's MP-SPDZ input file for shachain_step.

Usage: input.py <mp-spdz-dir> <seed-hex> [n] [nparties]

The program reads the 32-byte value as one 256-bit integer whose bit i is
v[i] = bit (7 - i % 8) of byte i // 8 (see shachain_step.mpc). n copies are
written so that N parallel chains can be fed. With nparties > 1, the same
file is written for each contributing party; the XOR of an odd number of
identical contributions equals the value itself, which keeps the reference
comparison valid when exercising CONTRIB.
"""
import sys

mpspdz, seed_hex = sys.argv[1], sys.argv[2]
n = int(sys.argv[3]) if len(sys.argv) > 3 else 1
nparties = int(sys.argv[4]) if len(sys.argv) > 4 else 1
seed = bytes.fromhex(seed_hex)
assert len(seed) == 32
val = 0
for i in range(256):
    val |= ((seed[i // 8] >> (7 - i % 8)) & 1) << i
for i in range(nparties):
    with open(f'{mpspdz}/Player-Data/Input-P{i}-0', 'w') as f:
        f.write('\n'.join([str(val)] * n) + '\n')
