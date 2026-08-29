//! Property tests. The BOLT vectors in tests/bolt.rs pin five known
//! points; these assert the rules those points are instances of, over
//! the whole input domain.
//!
//! - Oracle: the MPC engine against the plaintext `sha2` crate, for the
//!   single hash and for `generate_from_seed` across the 48-bit index
//!   space (the fixed vectors cover five indices; this covers the rule).
//! - Roundtrip: share then reconstruct is the identity, at every width.
//! - Invariant: any single corrupted share-component copy, at any
//!   position, in any lane word, is caught at reconstruction.

use proptest::prelude::*;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256 as RefSha256};

use shachain_engine::engine::Session;
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{reconstruct_lanes, share_lanes, Sha256};
use shachain_engine::shachain::generate_from_seed;

/// Plaintext BOLT #3 generate_from_seed, the walk from scripts/ref.py.
fn ref_generate(seed: [u8; 32], index: u64) -> [u8; 32] {
    let mut x = seed;
    for b in (0..48).rev() {
        if (index >> b) & 1 == 1 {
            x[b / 8] ^= 1 << (b % 8);
            x = RefSha256::digest(x).into();
        }
    }
    x
}

fn run_hashes(lanes: &[[u8; 32]], dealer_seed: [u8; 32]) -> Vec<[u8; 32]> {
    let sha = Sha256::load().expect("set MPSPDZ to an MP-SPDZ checkout");
    let keys = KeySet::from_seed([1u8; 32]);
    let mut rng = ChaCha12Rng::from_seed(dealer_seed);
    let shared = share_lanes(lanes, &mut rng);
    let mut session = Session::new(&keys, shared.words);
    let digest = sha.hash32(&mut session, &shared);
    reconstruct_lanes(&digest, lanes.len()).unwrap()
}

proptest! {
    // Each case evaluates the 135k-gate circuit at least once; keep the
    // budgets matched to that cost rather than the library default.
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Oracle: the engine's hash equals SHA-256 in every lane, for any
    /// messages at any lane count (1..=96 spans one and two words,
    /// including partly filled words).
    #[test]
    fn hash_matches_sha2(
        lanes in prop::collection::vec(any::<[u8; 32]>(), 1..=96),
        dealer in any::<[u8; 32]>(),
    ) {
        let out = run_hashes(&lanes, dealer);
        for (got, msg) in out.iter().zip(&lanes) {
            prop_assert_eq!(&got[..], &RefSha256::digest(msg)[..]);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    /// Oracle over the index space: generate_from_seed matches the
    /// plaintext walk for any seed and any 48-bit index, index 0 (no
    /// hashes at all) included.
    #[test]
    fn walk_matches_reference(
        seeds in prop::collection::vec(any::<[u8; 32]>(), 1..=3),
        index in 0..(1u64 << 48),
        dealer in any::<[u8; 32]>(),
    ) {
        let sha = Sha256::load().expect("circuit");
        let keys = KeySet::from_seed([1u8; 32]);
        let mut rng = ChaCha12Rng::from_seed(dealer);
        let shared = share_lanes(&seeds, &mut rng);
        let mut session = Session::new(&keys, shared.words);
        let out = generate_from_seed(&sha, &mut session, &shared, index);
        let lanes = reconstruct_lanes(&out, seeds.len()).unwrap();
        for (got, seed) in lanes.iter().zip(&seeds) {
            prop_assert_eq!(*got, ref_generate(*seed, index));
        }
    }
}

proptest! {
    /// Roundtrip: dealing and reconstructing is the identity.
    #[test]
    fn share_reconstruct_roundtrip(
        lanes in prop::collection::vec(any::<[u8; 32]>(), 1..=130),
        dealer in any::<[u8; 32]>(),
    ) {
        let mut rng = ChaCha12Rng::from_seed(dealer);
        let shared = share_lanes(&lanes, &mut rng);
        let out = reconstruct_lanes(&shared, lanes.len()).unwrap();
        prop_assert_eq!(out, lanes);
    }

    /// Invariant: flipping any bits in any single stored copy of any
    /// component is always caught by the replicated cross-check. (A
    /// consistent rewrite of both copies is a two-party corruption and
    /// out of this model.)
    #[test]
    fn any_single_corruption_is_caught(
        lanes in prop::collection::vec(any::<[u8; 32]>(), 1..=130),
        dealer in any::<[u8; 32]>(),
        party in 0usize..3,
        comp in 0usize..2,
        pos in any::<prop::sample::Index>(),
        mask in 1u64..,
    ) {
        let mut rng = ChaCha12Rng::from_seed(dealer);
        let mut shared = share_lanes(&lanes, &mut rng);
        let i = pos.index(shared.c[party][comp].len());
        shared.c[party][comp][i] ^= mask;
        prop_assert!(reconstruct_lanes(&shared, lanes.len()).is_err());
    }
}
