#!/usr/bin/env python3
"""Point-export prototype: publish P = s*G from a replicated Z_q sharing.

Consumes the Persistence/Transactions-P<i>.data files written by
shachain_step with EXPORT=1 (a calibration share of the constant 1, then the
share of the per-commitment scalar s). Each simulated party:

  1. reads only its own share file (two field elements per sint);
  2. computes one curve point per share component;
  3. publishes the points.

The combiner then cross-checks that each replicated component yields the same
point from both parties holding it, and sums one point per distinct summand
to obtain P. No party ever handles s itself.

Usage: point_export.py <mp-spdz-dir> [expected-scalar] [--corrupt]

With an expected scalar (decimal), verifies P == expected*G and that the
reconstructed scalar matches; without, just prints P. With --corrupt, one
party publishes a point for a tampered share; the run must abort on the
replicated cross-check.
"""
import sys
import time

Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P_FIELD = 2**256 - 2**32 - 977
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P_FIELD == 0:
        return None
    if a == b:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P_FIELD) % P_FIELD
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P_FIELD) % P_FIELD
    x3 = (lam * lam - x1 - x2) % P_FIELD
    return (x3, (lam * (x1 - x3) - y1) % P_FIELD)


def ec_mul(k, point=(GX, GY)):
    k %= Q
    result, addend = None, point
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result


def read_shares(path):
    """Return the list of 32-byte field elements (little-endian ints)."""
    with open(path, 'rb') as f:
        data = f.read()
    hdr_len = int.from_bytes(data[:8], 'little')
    body = data[8 + hdr_len:]
    assert len(body) % 32 == 0, f'unexpected body length {len(body)}'
    return [int.from_bytes(body[i:i + 32], 'little')
            for i in range(0, len(body), 32)]


def main():
    corrupt = '--corrupt' in sys.argv
    args = [a for a in sys.argv[1:] if a != '--corrupt']
    mpspdz = args[0]
    expected = int(args[1]) if len(args) > 1 else None

    # Each party reads only its own file: [cal_c1, cal_c2, s_c1, s_c2].
    raw = [read_shares(f'{mpspdz}/Persistence/Transactions-P{i}.data')
           for i in range(3)]
    for r in raw:
        assert len(r) == 4, f'expected 4 field elements, got {len(r)}'

    # Calibration: the constant 1 was written first. Summing one component
    # per summand across parties gives 1 * R (mod q), revealing the Montgomery
    # factor R. Replicated structure (verified below on the real shares):
    # party i's first component equals party (i+1)'s second component.
    R = sum(r[0] for r in raw) % Q
    assert R == 2**256 % Q, 'Montgomery factor is not 2^256'
    Rinv = pow(R, -1, Q)

    # The scalar's shares, de-Montgomeryised locally by each party.
    shares = [((r[2] * Rinv) % Q, (r[3] * Rinv) % Q) for r in raw]

    if corrupt:
        # Party 1 tampers with its copy of a replicated component.
        shares[1] = ((shares[1][0] + 1) % Q, shares[1][1])

    # Party step: publish one point per component.
    t0 = time.time()
    published = [(ec_mul(c1), ec_mul(c2)) for c1, c2 in shares]
    per_party = (time.time() - t0) / 3

    # Combiner step: cross-check each replicated pair by POINT equality
    # (party i first component vs party i+1 second component), then sum the
    # three summand points.
    for i in range(3):
        j = (i + 1) % 3
        assert published[i][0] == published[j][1], \
            f'replicated point mismatch between P{i} and P{j}: corruption'
    t1 = time.time()
    P = None
    for i in range(3):
        P = ec_add(P, published[i][0])
    combine = time.time() - t1

    print(f'P.x = {P[0]:064x}')
    print(f'P.y = {P[1]:064x}')
    print(f'party point time  {per_party * 1000:.2f} ms (pure Python; '
          f'libsecp256k1 is ~1000x faster)')
    print(f'combine time      {combine * 1000:.3f} ms')

    if expected is not None:
        assert P == ec_mul(expected), 'P != expected*G'
        s = sum(sh[0] for sh in shares) % Q
        assert s == expected % Q, 'reconstructed scalar mismatch'
        print('PASS: P == s*G and replicated cross-checks hold')


if __name__ == '__main__':
    main()
