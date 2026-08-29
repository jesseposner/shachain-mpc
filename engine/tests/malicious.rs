//! M2/M3 exit criteria: the malicious backend computes the same function
//! (oracle against sha2 and the BOLT walk), any single corrupted bit on
//! the wire aborts, and the traffic lands where FLNW says it should.
//!
//! The cheat hook flips one arbitrary bit of party 1's entire outgoing
//! byte stream, in send order: a multiplication resharing, an opening
//! (the cut, a sacrifice, a Beaver d/e, the coin), or one of the
//! comparison hashes themselves. What the tests cannot cover is the
//! 2^-sigma event the bucket bound is about, a coordinated multi-triple
//! forgery surviving the shuffle; that rests on the paper's
//! combinatorics, not on these runs.

use proptest::prelude::*;
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256 as RefSha256};

use shachain_engine::mal::{MalSession, SecurityParams};
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{reconstruct_lanes, share_lanes, Sha256};
use shachain_engine::shachain::generate_from_seed;

/// Small statistical parameter for tests: min batch 2^8 instead of 2^20,
/// so a single hash's triple demand is the batch and oversupply is zero.
fn test_params() -> SecurityParams {
    SecurityParams { sigma: 16, ..SecurityParams::default() }
}

fn setup() -> (Sha256, KeySet, ChaCha12Rng) {
    (
        Sha256::load().expect("set MPSPDZ to an MP-SPDZ checkout"),
        KeySet::from_seed([1u8; 32]),
        ChaCha12Rng::from_seed([2u8; 32]),
    )
}

/// Honest run: the malicious backend is still the same function.
#[test]
fn malicious_backend_matches_sha2() {
    let (sha, keys, mut rng) = setup();
    let mut msgs = vec![[0u8; 32]; 64];
    for m in &mut msgs {
        rng.fill_bytes(m);
    }
    let shared = share_lanes(&msgs, &mut rng);
    let mut session = MalSession::new(&keys, shared.words, test_params());
    let digest = sha.hash32(&mut session, &shared).unwrap();
    let lanes = reconstruct_lanes(&digest, 64).unwrap();
    for (lane, msg) in lanes.iter().zip(&msgs) {
        assert_eq!(lane[..], RefSha256::digest(msg)[..]);
    }
}

/// The BOLT walk end to end under the malicious backend.
#[test]
fn malicious_backend_walks_bolt_vector() {
    let (sha, keys, mut rng) = setup();
    let seed: [u8; 32] = [1u8; 32];
    let shared = share_lanes(&[seed], &mut rng);
    let mut session = MalSession::new(&keys, shared.words, test_params());
    let out = generate_from_seed(&sha, &mut session, &shared, 1).unwrap();
    let lanes = reconstruct_lanes(&out, 1).unwrap();
    assert_eq!(
        hex::encode(lanes[0]),
        "915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c"
    );
}

/// Traffic accounting: triple generation (bucket of 3), two sacrifice
/// openings per surviving triple pair, two Beaver openings per gate.
/// With zero oversupply that is ~9 bits per AND per party; assert the
/// envelope and print the measured figure.
#[test]
fn malicious_traffic_is_flnw_shaped() {
    let (sha, keys, mut rng) = setup();
    let shared = share_lanes(&vec![[3u8; 32]; 64], &mut rng);
    let mut session = MalSession::new(&keys, shared.words, test_params());
    sha.hash32(&mut session, &shared).unwrap();
    assert_eq!(session.stock(), 0, "batch sizing should leave no oversupply here");
    let and_instances = (sha.circuit.n_and * 64) as f64;
    let bits_per_and = session.sent_bytes[0] as f64 * 8.0 / and_instances;
    println!("malicious: {bits_per_and:.3} bits/AND/lane per party (paper's optimized form: 7)");
    assert!(bits_per_and > 8.9 && bits_per_and < 10.0, "measured {bits_per_and}");
}

fn cheating_run(cheat_bit: u64) -> Result<(), String> {
    let (sha, keys, mut rng) = setup();
    let mut msgs = vec![[0u8; 32]; 64];
    for m in &mut msgs {
        rng.fill_bytes(m);
    }
    let shared = share_lanes(&msgs, &mut rng);
    let mut session = MalSession::new(&keys, shared.words, test_params());
    session.cheat_bit = Some(cheat_bit);
    let digest = sha.hash32(&mut session, &shared)?;
    reconstruct_lanes(&digest, 64).map(|_| ())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Invariant: one flipped bit anywhere in party 1's outgoing byte
    /// stream, a triple resharing, any opening, or a comparison hash,
    /// always surfaces as an abort (or, for a surviving triple whose
    /// damage reaches the output, as a reconstruction failure). One
    /// hash puts about 1.6 MB on party 1's wires; index within it.
    #[test]
    fn any_corrupted_bit_aborts(bit in 0u64..12_000_000) {
        let outcome = cheating_run(bit);
        prop_assert!(outcome.is_err());
    }
}
