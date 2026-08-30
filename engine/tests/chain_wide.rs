//! The expansion's lane bookkeeping across the word boundary: a 128-leaf
//! block (two words) under the semi-honest backend, every leaf checked
//! against the plaintext walk through the masked release path.

use sha2::{Digest, Sha256 as RefSha256};

use shachain_engine::chain::{
    combine_pairs, masked_pair, open_release, prepare_first_block, summand_pair, Block,
};
use shachain_engine::engine::{run_parties, SemiParty};
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{share_lanes, Sha256};

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

#[test]
fn wide_block_matches_reference_in_every_lane() {
    const H: u32 = 7; // 128 lanes: the interleave spans two words
    let keys = KeySet::from_seed([1u8; 32]);
    let seed = [5u8; 32];
    let sha = Sha256::load().expect("set MPSPDZ to an MP-SPDZ checkout");
    let mut rng = <rand_chacha::ChaCha12Rng as rand_core::SeedableRng>::from_seed([2u8; 32]);
    let shared = share_lanes(&[seed], &mut rng);
    let mk = |p: usize| (SemiParty::new(p, &keys.party(p)), shared.party(p), None::<Block>);
    let mut states = [mk(0), mk(1), mk(2)];
    run_parties(&mut states, None, |_, (be, mine, out), net| {
        *out = Some(prepare_first_block(&sha, be, net, mine, H)?);
        Ok(())
    })
    .expect("preparation aborted");
    let blocks = states.map(|(_, _, b)| b.expect("block prepared"));
    let root = blocks[0].root_index;

    for lane in 0..1usize << H {
        let vid = root + lane as u64;
        let masked = combine_pairs(&[
            masked_pair(&keys.party(0), &blocks[0], lane),
            masked_pair(&keys.party(1), &blocks[1], lane),
            masked_pair(&keys.party(2), &blocks[2], lane),
        ])
        .unwrap();
        let secret = open_release(
            masked,
            &[
                summand_pair(&keys.party(0), vid),
                summand_pair(&keys.party(1), vid),
                summand_pair(&keys.party(2), vid),
            ],
        )
        .unwrap();
        assert_eq!(secret, ref_generate(seed, vid), "lane {lane}");
    }
}
