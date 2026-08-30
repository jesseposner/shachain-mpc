//! M5 exit criteria: the dZKP backend computes the same function
//! (oracle against sha2), the walk survives it, traffic lands at ~1 bit
//! per AND per party, and a flipped bit anywhere in a corrupt party's
//! outgoing stream, evaluation message, proof share, residual, coin,
//! or opening, aborts.
//!
//! Soundness here is statistical (~2^-50 per batch): a single flipped
//! evaluation bit escapes only if the random lambda combination
//! annihilates it, which no test run will ever see.

use proptest::prelude::*;
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256 as RefSha256};

use shachain_engine::dzkp::DzkpSession;
use shachain_engine::engine::Backend;
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{reconstruct_lanes, share_lanes, Sha256};
use shachain_engine::shachain::generate_from_seed;

fn setup() -> (Sha256, KeySet, ChaCha12Rng) {
    (
        Sha256::load().expect("set MPSPDZ to an MP-SPDZ checkout"),
        KeySet::from_seed([1u8; 32]),
        ChaCha12Rng::from_seed([2u8; 32]),
    )
}

#[test]
fn dzkp_backend_matches_sha2_and_costs_one_bit() {
    let (sha, keys, mut rng) = setup();
    let mut msgs = vec![[0u8; 32]; 64];
    for m in &mut msgs {
        rng.fill_bytes(m);
    }
    let shared = share_lanes(&msgs, &mut rng);
    let mut session = DzkpSession::new(&keys, shared.words);
    let digest = sha.hash32(&mut session, &shared).unwrap();
    let lanes = reconstruct_lanes(&digest, 64).unwrap();
    for (lane, msg) in lanes.iter().zip(&msgs) {
        assert_eq!(lane[..], RefSha256::digest(msg)[..]);
    }
    let and_instances = (sha.circuit.n_and * 64) as f64;
    let bits_per_and = session.sent_bytes[0] as f64 * 8.0 / and_instances;
    println!("dzkp: {bits_per_and:.4} bits/AND/lane per party, {} rounds", session.rounds);
    assert!(bits_per_and > 1.0 && bits_per_and < 1.1, "measured {bits_per_and}");
}

#[test]
fn dzkp_walk_matches_reference() {
    let (sha, keys, mut rng) = setup();
    let seed = [9u8; 32];
    let index = 0b11u64; // two hashes
    let shared = share_lanes(&[seed], &mut rng);
    let mut session = DzkpSession::new(&keys, shared.words);
    let out = generate_from_seed(&sha, &mut session, &shared, index).unwrap();
    let lanes = reconstruct_lanes(&out, 1).unwrap();
    let mut x = seed;
    for b in [1usize, 0] {
        x[b / 8] ^= 1 << (b % 8);
        x = RefSha256::digest(x).into();
    }
    assert_eq!(lanes[0], x);
}

fn cheating_run(bit: u64) -> Result<(), String> {
    let (sha, keys, mut rng) = setup();
    let mut msgs = vec![[0u8; 32]; 64];
    for m in &mut msgs {
        rng.fill_bytes(m);
    }
    let shared = share_lanes(&msgs, &mut rng);
    let mut session = DzkpSession::new(&keys, shared.words);
    let mut tapes = [
        sha.build_tape(0, &shared.party(0)),
        sha.build_tape(1, &shared.party(1)),
        sha.build_tape(2, &shared.party(2)),
    ];
    session.cheating_eval(&sha.circuit, &sha.sched, &mut tapes, bit)?;
    // If evaluation somehow survived, reconstruction is the last line.
    let digest = Shared256FromTapes::extract(&sha, &tapes);
    reconstruct_lanes(&digest, 64).map(|_| ())
}

/// Assemble the three tapes' outputs back into a dealer-side value.
struct Shared256FromTapes;
impl Shared256FromTapes {
    fn extract(
        sha: &Sha256,
        tapes: &[shachain_engine::engine::PartyTape; 3],
    ) -> shachain_engine::sha256::Shared256 {
        let mut digest = shachain_engine::sha256::Shared256::zero(tapes[0].words);
        for (p, tape) in tapes.iter().enumerate() {
            digest.c[p] = sha.extract(tape).c;
        }
        digest
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10, ..ProptestConfig::default() })]

    /// One flipped bit anywhere in party 1's outgoing stream aborts.
    /// The stream is ~180 KB of evaluation resharing plus the proof
    /// messages, residuals, coins, and openings behind it.
    #[test]
    fn any_corrupted_bit_aborts(bit in 0u64..1_400_000) {
        let outcome = cheating_run(bit);
        prop_assert!(outcome.is_err());
    }
}
