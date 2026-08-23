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


# Official BOLT #3 generation test vectors (03-transactions.md, "generation tests").
BOLT_VECTORS = [
    ('0000000000000000000000000000000000000000000000000000000000000000',
     0xFFFFFFFFFFFF,
     '02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148'),
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
     0xFFFFFFFFFFFF,
     '7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc'),
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
     0x0AAAAAAAAAAA,
     '56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528'),
    ('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
     0x555555555555,
     '9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31'),
    ('0101010101010101010101010101010101010101010101010101010101010101',
     1,
     '915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c'),
]


def generate_from_seed(seed, index):
    """BOLT #3 generate_from_seed via the same walk() used everywhere here."""
    return walk(seed, [b for b in range(47, -1, -1) if (index >> b) & 1])


def selftest():
    for seed_hex, index, expected in BOLT_VECTORS:
        got = generate_from_seed(bytes.fromhex(seed_hex), index).hex()
        assert got == expected, (seed_hex, index, expected, got)
    print(f'PASS: {len(BOLT_VECTORS)} official BOLT #3 test vectors')


if __name__ == '__main__':
    if sys.argv[1] == 'selftest':
        selftest()
        sys.exit(0)
    seed = bytes.fromhex(sys.argv[1])
    k = int(sys.argv[2])
    h = walk(seed, [47 - i for i in range(k)])
    s = int.from_bytes(h, 'big')
    print(f'hash   {h.hex()}')
    print(f'valid  {int(1 <= s < Q)}')
    r = s % Q
    print(f'scalar {r - Q if r > Q // 2 else r}')
