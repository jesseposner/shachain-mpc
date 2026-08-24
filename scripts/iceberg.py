"""Iceberg's key material, reimplemented byte-for-byte in Python.

The shachain needs a secret shared so that any authorised quorum can derive
from it and no sub-threshold coalition can. Iceberg already has exactly that
object, so this engine takes it rather than inventing one.

An Iceberg share is "a collection of 32-byte seeds, one for every group of
t-1 participants that this participant is NOT a member of"
(`include/secp256k1_iceberg.h`). For t=2 that is one seed per other
participant, which is the structure this engine wants: a summand held by
everyone except one member, so any quorum holds them all and losing a member
loses nothing.

Everything here follows the C in
`src/modules/iceberg/{rss,keygen}_impl.h`:

  * BIP340-style tagged hashes. The C uses precomputed midstates; the
    equivalence was checked by recomputing both midstates from
    SHA256(tag) || SHA256(tag) and comparing them to the constants in the C,
    for "VPSS/prf" and "Iceberg/dealer". `selftest()` re-runs that check.
  * Colex subset ranking, from `secp256k1_rss_subset_rank`.
  * Dealer seeds: H_"Iceberg/dealer"(root32 || n || t || rank), with the
    header packed as six bytes exactly as `secp256k1_iceberg_dealer_seed`
    packs it.

Derivation for the shachain uses a tag of its own, so a shachain summand can
never collide with a signing share even though both come from the same seed.
Iceberg's own PRF reduces its output to a scalar; the shachain wants a bit
string to feed SHA-256, so this takes the digest unreduced. The two are
independent derivations from shared seeds, which is what a domain-separated
tag is for.
"""

import hashlib
import struct

DEALER_TAG = 'Iceberg/dealer'
VPSS_PRF_TAG = 'VPSS/prf'
# Domain separation for this engine's derivations from the same seeds.
SHACHAIN_SEED_TAG = 'Iceberg/shachain/seed'
SHACHAIN_MASK_TAG = 'Iceberg/shachain/buffer-mask'


def tagged(tag, msg):
    """BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()


def binom(n, k):
    if k > n or k < 0:
        return 0
    r = 1
    for i in range(k):
        r = r * (n - i) // (i + 1)
    return r


def subset_rank(n, size, subset):
    """Rank of a subset, matching secp256k1_rss_subset_rank.

    `subset` is a bitmask over participants 1..n.
    """
    rank = 0
    remaining = size
    j = 1
    while j <= n and remaining > 0:
        if subset & (1 << j):
            remaining -= 1
        else:
            rank += binom(n - j, remaining - 1)
        j += 1
    return rank


def subset_unrank(n, size, rank):
    """Inverse of subset_rank, as a bitmask over participants 1..n."""
    for mask in range(1 << (n + 1)):
        if bin(mask >> 1).count('1') == size and not (mask & 1):
            if subset_rank(n, size, mask) == rank:
                return mask
    raise ValueError('no subset of that rank')


def dealer_seed(root32, n, t, rank):
    """One seed of the dealing, matching secp256k1_iceberg_dealer_seed."""
    header = struct.pack('>BBI', n, t, rank)
    return tagged(DEALER_TAG, root32 + header)


def deal(root32, n, t):
    """Deal a group, matching secp256k1_iceberg_shares_gen.

    Returns {participant (1-based): {rank: seed}} holding, for each
    participant, the seeds whose subsets do not contain it.
    """
    total = binom(n, t - 1)
    shares = {}
    for k in range(1, n + 1):
        held = {}
        for rank in range(total):
            if subset_unrank(n, t - 1, rank) & (1 << k):
                continue
            held[rank] = dealer_seed(root32, n, t, rank)
        shares[k] = held
    return shares


def vpss_prf(seed32, w):
    """Iceberg's own PRF, for cross-checking. Output is reduced to a scalar
    by the C; this returns the digest before reduction."""
    return tagged(VPSS_PRF_TAG, seed32 + w)


def shachain_summand(seed32, tag, value_id):
    """This engine's derivation from an Iceberg seed.

    Domain-separated from Iceberg's own PRF, and unreduced, because the
    shachain needs a bit string rather than a scalar.
    """
    return tagged(tag, seed32 + value_id.encode())


def selftest():
    """Check the tagged-hash construction against the midstates in the C."""
    expected = {
        'VPSS/prf': [0x2c0fc184, 0x5cc276f5, 0x96930a47, 0x1991257e,
                     0x5b0bb737, 0x8786890c, 0x875ba8bb, 0x6b6162bb],
        'Iceberg/dealer': [0xb40815ea, 0x9e117bfa, 0x4a71724f, 0x1f71a00e,
                           0x19cf3ed1, 0xd5ff1efc, 0xeb8b1dd5, 0x024d39e8],
    }
    K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
         0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
         0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
         0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
         0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
         0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
         0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
         0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
         0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
         0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    M = 0xffffffff

    def rr(x, n):
        return ((x >> n) | (x << (32 - n))) & M

    def midstate(block):
        w = list(struct.unpack('>16I', block))
        for i in range(16, 64):
            s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & M)
        a, b, c, d, e, f, g, h = IV
        for i in range(64):
            S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)
            ch = (e & f) ^ ((~e & M) & g)
            t1 = (h + S1 + ch + K[i] + w[i]) & M
            S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & M
            h, g, f, e, d, c, b, a = (g, f, e, (d + t1) & M, c, b, a,
                                      (t1 + t2) & M)
        return [(x + y) & M for x, y in zip(IV, [a, b, c, d, e, f, g, h])]

    for tag, want in expected.items():
        th = hashlib.sha256(tag.encode()).digest()
        got = midstate(th + th)
        assert got == want, (tag, got, want)
    print(f'PASS tagged-hash construction matches {len(expected)} midstates '
          f'in the Iceberg C')

    # For t=2 every participant must hold a seed for each other participant.
    n, t = 4, 2
    shares = deal(bytes(32), n, t)
    for k in range(1, n + 1):
        ranks = set(shares[k])
        assert len(ranks) == binom(n, t - 1) - binom(n - 1, t - 2), ranks
        for rank in ranks:
            assert not (subset_unrank(n, t - 1, rank) & (1 << k))
    print(f'PASS dealing gives each of {n} participants '
          f'{len(shares[1])} seeds, none naming itself')


if __name__ == '__main__':
    selftest()
