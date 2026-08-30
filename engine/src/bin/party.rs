//! One party of the ring, as its own process over TCP.
//!
//! Usage: party <id> <addr0> <addr1> <addr2> <K> <N> [semi|mal] [sigma]
//!
//! Runs the K-edge, N-lane benchmark walk. Inputs are benchmark dealing:
//! every process derives the same test sharing from a fixed seed and
//! keeps only its own components; real deployments take their share
//! components from Iceberg-derived key material instead. At the end,
//! parties 1 and 2 hand their digest components to party 0, which
//! cross-checks the replicated copies, reconstructs lane 0, and verifies
//! it against a local plaintext walk.

use std::time::Instant;

use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256 as RefSha256};

use shachain_engine::engine::{PartyBackend, SemiParty};
use shachain_engine::mal::{MalParty, SecurityParams};
use shachain_engine::net::tcp_ring;
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{share_lanes, PartyShared, Sha256};
use shachain_engine::shachain::walk_edges_party;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let id: usize = args[0].parse().expect("party id");
    let addrs: [String; 3] = [args[1].clone(), args[2].clone(), args[3].clone()];
    let k: usize = args[4].parse().expect("K");
    let n: usize = args[5].parse().expect("N");
    let malicious = args.get(6).map(String::as_str) == Some("mal");
    let sigma: u32 = args.get(7).map_or(40, |s| s.parse().expect("sigma"));

    let sha = Sha256::load().expect("circuit");
    let keys = KeySet::from_seed([7u8; 32]);
    let mut rng = ChaCha12Rng::from_seed([9u8; 32]);
    let mut seeds = vec![[0u8; 32]; n];
    for s in &mut seeds {
        rng.fill_bytes(s);
    }
    let mine = share_lanes(&seeds, &mut rng).party(id);

    let mut net = tcp_ring(id, &addrs).expect("ring");
    let t0 = Instant::now();
    let out = if malicious {
        let params = SecurityParams { sigma, ..SecurityParams::default() };
        let mut party = MalParty::new(id, &keys.party(id), params);
        walk_edges_party(&sha, &mut party, &mut net, &mine, k)
    } else {
        let mut party = SemiParty::new(id, &keys.party(id));
        walk_edges_party(&sha, &mut party, &mut net, &mine, k)
    }
    .expect("walk aborted");
    let wall = t0.elapsed();

    // Hand components to party 0 for checked reconstruction: party 1
    // reaches party 0 over its prev wire, party 2 over its next.
    let words = out.words;
    let concat: Vec<u64> = out.c[0].iter().chain(out.c[1].iter()).copied().collect();
    match id {
        1 => net.send_raw(true, &concat).expect("send"),
        2 => net.send_raw(false, &concat).expect("send"),
        _ => {
            let from1 = net.recv_raw(true).expect("recv p1");
            let from2 = net.recv_raw(false).expect("recv p2");
            let digest = reconstruct_lane0(&out, &from1, &from2, words);
            let mut expected = seeds[0];
            for i in 0..k {
                let b = 47 - i;
                expected[b / 8] ^= 1 << (b % 8);
                expected = RefSha256::digest(expected).into();
            }
            assert_eq!(digest, expected, "digest mismatch against plaintext walk");
            println!("digest {}", hex(&digest));
            println!("verified against plaintext walk");
        }
    }
    println!(
        "party {id}: rounds {}, sent {:.2} MB, wall {:.3} s",
        net.rounds,
        net.sent_bytes as f64 / 1e6,
        wall.as_secs_f64()
    );
}

/// Cross-check every replicated copy, then reconstruct lane 0.
/// Party 0 holds (x0, x1); party 1 sent (x1, x2); party 2 sent (x2, x0).
fn reconstruct_lane0(own: &PartyShared, from1: &[u64], from2: &[u64], words: usize) -> [u8; 32] {
    let len = 256 * words;
    assert_eq!(from1.len(), 2 * len);
    assert_eq!(from2.len(), 2 * len);
    let mut out = [0u8; 32];
    for m in 0..256 {
        let i = m * words; // lane 0 lives in word 0 of each entry
        let (x0, x1) = (own.c[0][i], own.c[1][i]);
        let (x1b, x2) = (from1[i], from1[len + i]);
        let (x2b, x0b) = (from2[i], from2[len + i]);
        assert_eq!(x1, x1b, "component x1 differs between its holders");
        assert_eq!(x2, x2b, "component x2 differs between its holders");
        assert_eq!(x0, x0b, "component x0 differs between its holders");
        out[m / 8] |= (((x0 ^ x1 ^ x2) & 1) as u8) << (m % 8);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
