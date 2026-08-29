//! K edges, N lanes: wall clock and per-party traffic.
//!
//! Usage: bench [K] [N] [mal]   (defaults: 10 edges, 64 lanes, semi-honest)

use std::time::Instant;

use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};

use shachain_engine::engine::Session;
use shachain_engine::mal::{MalSession, SecurityParams};
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{share_lanes, Sha256};
use shachain_engine::shachain::walk_edges;

fn main() {
    let mut args = std::env::args().skip(1);
    let k: usize = args.next().map_or(10, |a| a.parse().expect("K"));
    let n: usize = args.next().map_or(64, |a| a.parse().expect("N"));
    let malicious = args.next().as_deref() == Some("mal");

    let sha = Sha256::load().expect("circuit");
    let keys = KeySet::from_seed([7u8; 32]);
    let mut rng = ChaCha12Rng::from_seed([9u8; 32]);
    let mut seeds = vec![[0u8; 32]; n];
    for s in &mut seeds {
        rng.fill_bytes(s);
    }
    let shared = share_lanes(&seeds, &mut rng);

    let t0 = Instant::now();
    let (sent, rounds, stock, label) = if malicious {
        let params = SecurityParams::default();
        let mut session = MalSession::new(&keys, shared.words, params);
        walk_edges(&sha, &mut session, &shared, k).expect("honest run aborted");
        (
            session.sent_bytes[0],
            session.rounds,
            session.stock(),
            format!("malicious (FLNW, sigma {})", params.sigma),
        )
    } else {
        let mut session = Session::new(&keys, shared.words);
        walk_edges(&sha, &mut session, &shared, k).expect("semi-honest never aborts");
        (session.sent_bytes[0], session.rounds, 0, "semi-honest".into())
    };
    let dt = t0.elapsed();

    let hashes = (k * n) as f64;
    let and_instances = (sha.circuit.n_and * k * 64 * shared.words) as f64;
    println!("{label}: edges {k}, lanes {n} ({} words), AND gates/hash {}", shared.words, sha.circuit.n_and);
    println!("wall {:.3} s, {:.0} hash-lanes/s", dt.as_secs_f64(), hashes / dt.as_secs_f64());
    println!(
        "{rounds} message rounds total, {:.1} per hash (circuit AND depth: what a WAN pays)",
        rounds as f64 / k as f64
    );
    println!(
        "sent per party {:.2} MB, {:.3} bits/AND/lane over the run",
        sent as f64 / 1e6,
        sent as f64 * 8.0 / and_instances
    );
    if malicious && stock > 0 {
        let consumed = (sha.circuit.n_and * k * shared.words) as f64;
        println!(
            "triple stock left: {stock} words ({:.0}% oversupply from minimum batch sizing)",
            100.0 * stock as f64 / consumed
        );
    }
}
