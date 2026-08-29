//! M1 exit criteria: the official BOLT #3 vectors byte-for-byte, per-lane
//! distinct hashing, the replicated cross-check catching corruption, and
//! communication of exactly one bit per AND per party per lane.

use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256 as RefSha256};

use shachain_engine::engine::Session;
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{reconstruct_lanes, share_lanes, Sha256};
use shachain_engine::shachain::generate_from_seed;

/// The five official BOLT #3 generation vectors (03-transactions.md),
/// copied from scripts/ref.py.
const BOLT_VECTORS: [(&str, u64, &str); 5] = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        0xFFFFFFFFFFFF,
        "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
    ),
    (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        0xFFFFFFFFFFFF,
        "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
    ),
    (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        0x0AAAAAAAAAAA,
        "56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528",
    ),
    (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        0x555555555555,
        "9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31",
    ),
    (
        "0101010101010101010101010101010101010101010101010101010101010101",
        1,
        "915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c",
    ),
];

fn setup() -> (Sha256, KeySet, ChaCha12Rng) {
    (
        Sha256::load().expect("set MPSPDZ to an MP-SPDZ checkout"),
        KeySet::from_seed([1u8; 32]),
        ChaCha12Rng::from_seed([2u8; 32]),
    )
}

fn seed32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

/// 64 distinct random messages in 64 lanes against the sha2 crate: the
/// circuit semantics, the wire mapping, and per-lane distinctness (the
/// MP-SPDZ vectorised-hashing bug class) in one check.
#[test]
fn compress_matches_sha2_in_every_lane() {
    let (sha, keys, mut rng) = setup();
    let mut msgs = vec![[0u8; 32]; 64];
    for m in &mut msgs {
        rng.fill_bytes(m);
    }
    let shared = share_lanes(&msgs, &mut rng);
    let mut session = Session::new(&keys, shared.words);
    let digest = sha.hash32(&mut session, &shared);
    let lanes = reconstruct_lanes(&digest, 64).unwrap();
    for (lane, msg) in lanes.iter().zip(&msgs) {
        assert_eq!(lane[..], RefSha256::digest(msg)[..]);
    }
}

#[test]
fn official_bolt_vectors() {
    let (sha, keys, mut rng) = setup();
    for (seed_hex, index, expected) in BOLT_VECTORS {
        let shared = share_lanes(&[seed32(seed_hex)], &mut rng);
        let mut session = Session::new(&keys, shared.words);
        let out = generate_from_seed(&sha, &mut session, &shared, index);
        let lanes = reconstruct_lanes(&out, 1).unwrap();
        assert_eq!(hex::encode(lanes[0]), expected, "index {index:#x}");
    }
}

/// Three distinct seeds walking the same index stay distinct per lane,
/// against a plaintext reference computed here.
#[test]
fn distinct_seeds_walk_distinct() {
    let (sha, keys, mut rng) = setup();
    let index = 0b101u64; // flips bits 2 and 0, two hashes
    let mut seeds = vec![[0u8; 32]; 3];
    for s in &mut seeds {
        rng.fill_bytes(s);
    }
    let shared = share_lanes(&seeds, &mut rng);
    let mut session = Session::new(&keys, shared.words);
    let out = generate_from_seed(&sha, &mut session, &shared, index);
    let lanes = reconstruct_lanes(&out, 3).unwrap();
    for (lane, seed) in lanes.iter().zip(&seeds) {
        let mut x = *seed;
        for b in [2usize, 0] {
            x[b / 8] ^= 1 << (b % 8);
            x = RefSha256::digest(x).into();
        }
        assert_eq!(lane[..], x[..]);
    }
}

#[test]
fn corrupted_component_is_caught() {
    let (_, _, mut rng) = setup();
    let mut msgs = vec![[0u8; 32]; 1];
    rng.fill_bytes(&mut msgs[0]);
    let mut shared = share_lanes(&msgs, &mut rng);
    shared.c[1][0][17] ^= 1; // party 1's copy of x1 no longer matches party 0's
    assert!(reconstruct_lanes(&shared, 1).is_err());
}

/// The semi-honest floor, by actual count: each party sends exactly one
/// bit per AND gate per lane.
#[test]
fn one_bit_per_and_per_party() {
    let (sha, keys, mut rng) = setup();
    let shared = share_lanes(&vec![[3u8; 32]; 64], &mut rng);
    let mut session = Session::new(&keys, shared.words);
    let _ = sha.hash32(&mut session, &shared);
    let expected_bytes = (sha.circuit.n_and * shared.words * 8) as u64;
    assert_eq!(session.sent_bytes, [expected_bytes; 3]);
    let bits_per_and_per_lane = expected_bytes as f64 * 8.0 / (sha.circuit.n_and * 64) as f64;
    assert_eq!(bits_per_and_per_lane, 1.0);
    println!(
        "per party: {} ANDs -> {:.2} KB sent per hash-lane",
        sha.circuit.n_and,
        expected_bytes as f64 / 1024.0 / 64.0
    );
}
