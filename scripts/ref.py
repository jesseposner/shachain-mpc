#!/usr/bin/env python3
"""Plaintext BOLT #3 reference: walk K right edges from a seed.

Usage: ref.py <seed-hex> <K>
Prints the resulting 32-byte value, whether it is a valid secp256k1 scalar,
and its value as a Z_q element (signed representative, as MP-SPDZ prints it).
"""
import hashlib
import sys

Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def flip(v, b):
    v = bytearray(v)
    v[b // 8] ^= 1 << (b % 8)
    return bytes(v)


def walk(seed, bits):
    x = seed
    for b in bits:
        x = hashlib.sha256(flip(x, b)).digest()
    return x


if __name__ == '__main__':
    seed = bytes.fromhex(sys.argv[1])
    k = int(sys.argv[2])
    h = walk(seed, [47 - i for i in range(k)])
    s = int.from_bytes(h, 'big')
    print(f'hash   {h.hex()}')
    print(f'valid  {int(1 <= s < Q)}')
    r = s % Q
    print(f'scalar {r - Q if r > Q // 2 else r}')
