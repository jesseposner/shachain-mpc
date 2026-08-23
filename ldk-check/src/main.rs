//! Feed MPC-derived BOLT #3 per-commitment secrets to LDK's shachain
//! verifier (`CounterpartyCommitmentSecrets`), exactly as a channel
//! counterparty would during `revoke_and_ack` processing.
//!
//! Input: lines of `<commitment index> <secret hex>` on a file named by the
//! first argument, in BOLT order (index 2^48-1 first, descending).
//!
//! Checks:
//!   1. LDK accepts the whole sequence (insert_secret consistency).
//!   2. LDK rejects the sequence when any one byte is corrupted.
//!   3. LDK can re-derive earlier secrets from later ones.

use lightning::ln::chan_utils::CounterpartyCommitmentSecrets;

fn load(path: &str) -> Vec<(u64, [u8; 32])> {
    std::fs::read_to_string(path)
        .expect("cannot read input file")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split_whitespace();
            let idx: u64 = it.next().unwrap().parse().unwrap();
            let bytes = hex::decode(it.next().unwrap()).unwrap();
            (idx, <[u8; 32]>::try_from(bytes.as_slice()).unwrap())
        })
        .collect()
}

fn main() {
    let secrets = load(&std::env::args().nth(1).expect("usage: ldk-check <file>"));
    assert!(!secrets.is_empty());

    // 1. The genuine sequence must be accepted in full.
    let mut store = CounterpartyCommitmentSecrets::new();
    for (idx, secret) in &secrets {
        store
            .provide_secret(*idx, *secret)
            .unwrap_or_else(|_| panic!("LDK rejected genuine secret at index {}", idx));
    }
    println!("PASS: LDK accepted all {} MPC-derived secrets", secrets.len());

    // 2. Corrupting any single byte of the last secret must be rejected,
    //    because it no longer derives the earlier ones.
    let (last_idx, last_secret) = *secrets.last().unwrap();
    let mut rejected = 0;
    for byte in 0..32 {
        let mut store = CounterpartyCommitmentSecrets::new();
        for (idx, secret) in &secrets[..secrets.len() - 1] {
            store.provide_secret(*idx, *secret).unwrap();
        }
        let mut bad = last_secret;
        bad[byte] ^= 1;
        if store.provide_secret(last_idx, bad).is_err() {
            rejected += 1;
        }
    }
    assert_eq!(rejected, 32, "corrupted secrets must always be rejected");
    println!("PASS: LDK rejected all 32 single-byte corruptions of the last secret");

    // 3. Later secrets must let LDK re-derive earlier ones.
    let mut store = CounterpartyCommitmentSecrets::new();
    for (idx, secret) in &secrets {
        store.provide_secret(*idx, *secret).unwrap();
    }
    for (idx, secret) in &secrets {
        let derived = store
            .get_secret(*idx)
            .unwrap_or_else(|| panic!("LDK cannot derive index {}", idx));
        assert_eq!(&derived, secret, "derived secret mismatch at {}", idx);
    }
    println!("PASS: LDK re-derived every provided secret from its store");
}
