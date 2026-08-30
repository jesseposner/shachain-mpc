//! M3c exit criteria: a block prepared under the malicious backend,
//! released leaf by leaf through the masked one-round path, matches the
//! plaintext walk at every index, a wrong summand copy is caught by the
//! adapter's cross-check, and the full descending sequence is accepted
//! by unmodified rust-lightning's CounterpartyCommitmentSecrets.

use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256 as RefSha256};

use shachain_engine::chain::{
    combine_pairs, masked_pair, open_release, prepare_first_block, summand_pair, Block,
};
use shachain_engine::engine::run_parties;
use shachain_engine::mal::{MalParty, SecurityParams};
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{share_lanes, PartyShared, Sha256};

const H: u32 = 4; // 16-leaf block: full pipeline in test time

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

/// Run the three parties and return each party's block.
fn prepare_blocks(keys: &KeySet, seed: [u8; 32]) -> [Block; 3] {
    let sha = Sha256::load().expect("set MPSPDZ to an MP-SPDZ checkout");
    let mut rng = <rand_chacha::ChaCha12Rng as rand_core::SeedableRng>::from_seed([2u8; 32]);
    let shared = share_lanes(&[seed], &mut rng);
    let params = SecurityParams { sigma: 16, ..SecurityParams::default() };
    let mk = |p: usize| {
        (MalParty::new(p, &keys.party(p), params), shared.party(p), None::<Block>)
    };
    let mut states = [mk(0), mk(1), mk(2)];
    run_parties(&mut states, None, |_, (be, mine, out), net| {
        *out = Some(prepare_first_block(&sha, be, net, mine, H)?);
        Ok(())
    })
    .expect("honest preparation aborted");
    states.map(|(_, _, block)| block.expect("block prepared"))
}

#[test]
fn block_releases_match_reference_and_ldk_accepts() {
    let keys = KeySet::from_seed([1u8; 32]);
    let seed = [1u8; 32];
    let blocks = prepare_blocks(&keys, seed);
    let root = blocks[0].root_index;

    // Consume descending, as Lightning does: highest index first.
    let mut lines = String::new();
    for lane in (0..1usize << H).rev() {
        let vid = root + lane as u64;
        let masked = combine_pairs(&[
            masked_pair(&keys.party(0), &blocks[0], lane),
            masked_pair(&keys.party(1), &blocks[1], lane),
            masked_pair(&keys.party(2), &blocks[2], lane),
        ])
        .expect("masked publish cross-check");
        let secret = open_release(
            masked,
            &[
                summand_pair(&keys.party(0), vid),
                summand_pair(&keys.party(1), vid),
                summand_pair(&keys.party(2), vid),
            ],
        )
        .expect("release cross-check");
        assert_eq!(secret, ref_generate(seed, vid), "index {vid}");
        lines.push_str(&format!("{} {}\n", vid, hex::encode(secret)));
    }

    // The counterparty's verdict: unmodified rust-lightning.
    let ldk_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ldk-check");
    let ldk_bin = ldk_dir.join("target/release/ldk-check");
    if !ldk_bin.exists() {
        let built = Command::new("cargo")
            .args(["build", "--release", "--bin", "ldk-check"])
            .current_dir(&ldk_dir)
            .status()
            .expect("cargo");
        assert!(built.success(), "could not build ldk-check");
    }
    let file = std::env::temp_dir().join("engine-chain-secrets.txt");
    std::fs::write(&file, lines).unwrap();
    let out = Command::new(&ldk_bin).arg(&file).output().expect("run ldk-check");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "ldk-check failed: {stdout}");
    assert!(stdout.contains("PASS: LDK accepted"), "{stdout}");
    println!("{stdout}");
}

#[test]
fn wrong_summand_copy_is_caught() {
    let keys = KeySet::from_seed([1u8; 32]);
    let vid = 281474976710650u64;
    let mut pairs = [
        summand_pair(&keys.party(0), vid),
        summand_pair(&keys.party(1), vid),
        summand_pair(&keys.party(2), vid),
    ];
    pairs[1].0[7] ^= 1; // party 1 lies about summand 1; party 0 holds the honest copy
    assert!(combine_pairs(&pairs).is_err());
}
