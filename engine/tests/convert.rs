//! M4 exit criteria: the q-mask circuit computes (s + s0 + s1 + s2)
//! mod q against an independent bigint reference; a block converted
//! under the malicious backend yields public points P = s*G that match
//! the plaintext secrets; the q-release recovers exactly the bytes the
//! XOR release recovers and refuses a wrong summand, a wrong point
//! copy, or a tampered t.

use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256 as RefSha256};

use shachain_engine::bristol::eval_clear;
use shachain_engine::chain::{
    combine_pairs, masked_pair, open_release, prepare_first_block, summand_pair, Block,
};
use shachain_engine::convert::{
    build_qmask_circuit, point_pair, published_point, qmask_summand_pair, release_q, Converter,
    Q_BYTES,
};
use shachain_engine::engine::run_parties;
use shachain_engine::mal::{MalParty, SecurityParams};
use shachain_engine::rep3::KeySet;
use shachain_engine::sha256::{share_lanes, Sha256};

const H: u32 = 4;

// --- little bigint reference: 5 x u64 limbs, LSB first ---

fn limbs(b: &[u8; 32]) -> [u64; 5] {
    let mut out = [0u64; 5];
    for (i, byte) in b.iter().rev().enumerate() {
        out[i / 8] |= (*byte as u64) << (8 * (i % 8));
    }
    out
}

fn add(a: [u64; 5], b: [u64; 5]) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..5 {
        let s = a[i] as u128 + b[i] as u128 + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    out
}

fn geq(a: [u64; 5], b: [u64; 5]) -> bool {
    for i in (0..5).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub(a: [u64; 5], b: [u64; 5]) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut borrow = 0i128;
    for i in 0..5 {
        let d = a[i] as i128 - b[i] as i128 - borrow;
        out[i] = d as u64;
        borrow = i64::from(d < 0) as i128;
    }
    out
}

fn ref_qmask(vals: [[u8; 32]; 4]) -> [u8; 32] {
    let q = limbs(&Q_BYTES);
    let mut u = [0u64; 5];
    for v in &vals {
        u = add(u, limbs(v));
    }
    while geq(u, q) {
        u = sub(u, q);
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[31 - i] = (u[i / 8] >> (8 * (i % 8))) as u8;
    }
    out
}

fn bits_lsb(b: &[u8; 32]) -> Vec<bool> {
    (0..256).map(|i| (b[31 - i / 8] >> (i % 8)) & 1 == 1).collect()
}

#[test]
fn qmask_circuit_matches_bigint() {
    let c = build_qmask_circuit();
    let mut rng = ChaCha12Rng::from_seed([3u8; 32]);
    for case in 0..40 {
        let mut vals = [[0u8; 32]; 4];
        for v in &mut vals {
            rng.fill_bytes(v);
        }
        if case == 0 {
            // Force the deep-reduction corner: everything near maximal.
            vals = [[0xffu8; 32]; 4];
        }
        let inputs: Vec<Vec<bool>> = std::iter::once(vec![false, true])
            .chain(vals.iter().map(bits_lsb))
            .collect();
        let out = eval_clear(&c, &inputs);
        let expected = bits_lsb(&ref_qmask(vals));
        assert_eq!(out, expected, "case {case}");
    }
}

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
fn block_points_and_q_release_end_to_end() {
    let keys = KeySet::from_seed([1u8; 32]);
    let seed = [1u8; 32];
    let sha = Sha256::load().expect("set MPSPDZ to an MP-SPDZ checkout");
    let conv = Converter::new();
    let mut rng = ChaCha12Rng::from_seed([2u8; 32]);
    let shared = share_lanes(&[seed], &mut rng);
    let params = SecurityParams { sigma: 16, ..SecurityParams::default() };
    let mk = |p: usize| {
        (
            MalParty::new(p, &keys.party(p), params),
            keys.party(p),
            shared.party(p),
            None::<(Block, Vec<[u8; 32]>)>,
        )
    };
    let mut states = [mk(0), mk(1), mk(2)];
    run_parties(&mut states, None, |_, (be, pk, mine, out), net| {
        let block = prepare_first_block(&sha, be, net, mine, H)?;
        let ts = conv.mask_block(be, net, pk, &block)?;
        *out = Some((block, ts));
        Ok(())
    })
    .expect("honest run aborted");
    let results = states.map(|(_, _, _, r)| r.expect("prepared"));
    let root = results[0].0.root_index;

    // The opened t values are public: all parties must agree.
    assert_eq!(results[0].1, results[1].1);
    assert_eq!(results[1].1, results[2].1);

    for lane in (0..1usize << H).rev() {
        let vid = root + lane as u64;
        let t = results[0].1[lane];
        let expected = ref_generate(seed, vid);

        // The published point equals the plaintext secret times G.
        let qpairs = [
            point_pair(&keys.party(0), vid),
            point_pair(&keys.party(1), vid),
            point_pair(&keys.party(2), vid),
        ];
        let p = published_point(&t, &qpairs).expect("point cross-check");
        let ref_point = {
            use k256::elliptic_curve::sec1::ToSec1Point;
            let s = k256::SecretKey::from_slice(&expected).unwrap();
            let a: [u8; 33] =
                s.public_key().to_sec1_point(true).as_bytes().try_into().unwrap()
            ;
            a
        };
        assert_eq!(p, ref_point, "index {vid}");

        // The q-release recovers the exact bytes and passes the point
        // equation; it must agree with the XOR release byte for byte.
        let spairs = [
            qmask_summand_pair(&keys.party(0), vid),
            qmask_summand_pair(&keys.party(1), vid),
            qmask_summand_pair(&keys.party(2), vid),
        ];
        let secret = release_q(&t, &spairs, &p).expect("release");
        assert_eq!(secret, expected, "index {vid}");

        let xor_masked = combine_pairs(&[
            masked_pair(&keys.party(0), &results[0].0, lane),
            masked_pair(&keys.party(1), &results[1].0, lane),
            masked_pair(&keys.party(2), &results[2].0, lane),
        ])
        .unwrap();
        let xor_secret = open_release(
            xor_masked,
            &[
                summand_pair(&keys.party(0), vid),
                summand_pair(&keys.party(1), vid),
                summand_pair(&keys.party(2), vid),
            ],
        )
        .unwrap();
        assert_eq!(secret, xor_secret);

        // Refusals: a wrong point copy, a wrong summand copy, a bad t.
        let mut bad_points = qpairs;
        bad_points[2].0[5] ^= 1;
        assert!(published_point(&t, &bad_points).is_err());
        let mut bad_summands = spairs;
        bad_summands[0].1[9] ^= 1;
        assert!(release_q(&t, &bad_summands, &p).is_err());
        let mut bad_t = t;
        bad_t[3] ^= 1;
        assert!(release_q(&bad_t, &spairs, &p).is_err());
    }
}
