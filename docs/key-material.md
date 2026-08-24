# Key material comes from Iceberg

The shachain needs a secret shared so that any authorised quorum can derive
from it and no sub-threshold coalition can. Iceberg already produces exactly
that object, so this engine takes it rather than generating its own.

## What was wrong before

Setup dealt its own summands: member j originated summand j alone and sent
it to the other holders. Two failures, both recorded as `docs/todo.md` item
1.2.

Every member is missing exactly one summand, so a weak generator at that one
originator handed the whole seed to anyone who compromised a single other
member. The threshold survives one corruption, but one bad generator plus
one corruption sufficed, and a bad generator is not a corruption.

Nothing stopped an originator sending different bytes to different holders
either, so different quorums would derive different chains, surfacing as a
stuck channel during a quorum change.

An intermediate version of this engine answered with a commit-and-reveal
ceremony: every holder contributed, contributions were committed before
being revealed, and holders published digests that had to agree. It worked,
and it was the wrong answer, because it was a second key generation sitting
beside the one Iceberg has to run anyway, with its own trust assumptions to
analyse. It also could not close its own last gap, since it trusted the
coordinator to relay one commitment table to every member.

## What it uses instead

An Iceberg share is "a collection of 32-byte seeds, one for every group of
t-1 participants that this participant is NOT a member of"
(`include/secp256k1_iceberg.h`). At t=2 that is one seed per other
participant: exactly a summand held by everyone except one member, so any
quorum holds them all and losing a member loses nothing. It is the structure
this engine had been reinventing.

`scripts/iceberg.py` reimplements the parts needed, byte-for-byte from
`src/modules/iceberg/{rss,keygen}_impl.h` in the benchmark repository:

- **Tagged hashing.** Iceberg uses BIP340-style tagged hashes with
  precomputed midstates. The reimplementation recomputes those midstates
  from `SHA256(tag) || SHA256(tag)` and checks them against the constants the
  C hard-codes, for `VPSS/prf` and `Iceberg/dealer`. Both match.
- **Subset ranking**, from `secp256k1_rss_subset_rank`. At t=2 the subset of
  rank r names participant r+1, so participant k holds every rank but k-1.
- **Dealing**, from `secp256k1_iceberg_shares_gen`: seeds are
  `H_"Iceberg/dealer"(root || n || t || rank)`, and each participant receives
  the seeds whose subsets do not name it.

Derivation for the shachain uses tags of its own, `Iceberg/shachain/seed`
and `Iceberg/shachain/buffer-mask`, so a shachain summand cannot collide with
a signing share drawn from the same seed. Iceberg's own PRF reduces its
output to a scalar; the shachain takes the digest unreduced, because it
needs a bit string to feed SHA-256.

## What this buys

Setup's security is now Iceberg's key generation's security. Not better, not
worse, and not a second thing to analyse. The coordinator-relay gap is gone
because key generation does not pass through this coordinator at all.

Iceberg specifies key generation as coming from a trusted dealer or a
distributed key generation. The PoC models the dealer, matching
`secp256k1_iceberg_shares_gen`. A deployment substitutes whichever Iceberg
deploys, and nothing downstream changes, because what arrives is the same
object.

That last point is the argument the Threshold BOLT Shachain draft asks for
when it warns against the shachain growing a separate, weaker path beside
the signing one. Here it does not have one.
