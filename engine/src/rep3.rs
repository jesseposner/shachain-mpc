//! Replicated 3-party XOR sharing over bitsliced words.
//!
//! A secret bit-vector x is x0 ^ x1 ^ x2; party i holds the pair
//! (x_i, x_{i+1}) (indices mod 3). Every value here is a `u64` word
//! carrying 64 independent lanes.
//!
//! Correlated randomness: key j is shared by parties j and j+1. Party i
//! derives its zero-share as alpha_i = F(k_i) ^ F(k_{i-1}); summed over
//! the parties each key stream appears twice, so the alphas XOR to zero.

use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};

/// The three pairwise PRF keys. In production each key is derived
/// pairwise (Iceberg-style, per docs/key-material.md); for tests all
/// three come from one master seed.
pub struct KeySet(pub [[u8; 32]; 3]);

impl KeySet {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut rng = ChaCha12Rng::from_seed(seed);
        let mut keys = [[0u8; 32]; 3];
        for k in &mut keys {
            rng.fill_bytes(k);
        }
        KeySet(keys)
    }
}

/// Party i's view of the correlated randomness.
pub struct ZeroShare {
    own: ChaCha12Rng,
    prev: ChaCha12Rng,
}

impl ZeroShare {
    pub fn new(keys: &KeySet, party: usize) -> Self {
        ZeroShare {
            own: ChaCha12Rng::from_seed(keys.0[party]),
            prev: ChaCha12Rng::from_seed(keys.0[(party + 2) % 3]),
        }
    }

    /// Next zero-share word. All parties must draw in lockstep.
    pub fn next(&mut self) -> u64 {
        self.own.next_u64() ^ self.prev.next_u64()
    }
}

/// Split one word into replicated shares: [(x0,x1), (x1,x2), (x2,x0)].
pub fn share_word(x: u64, rng: &mut impl RngCore) -> [(u64, u64); 3] {
    let x0 = rng.next_u64();
    let x1 = rng.next_u64();
    let x2 = x ^ x0 ^ x1;
    [(x0, x1), (x1, x2), (x2, x0)]
}

/// A public constant as a sharing: x0 carries the value.
pub fn public_word(x: u64) -> [(u64, u64); 3] {
    [(x, 0), (0, 0), (0, x)]
}

/// Reconstruct with the replicated cross-check: every component is held
/// by two parties, and the copies must agree.
pub fn reconstruct_word(shares: [(u64, u64); 3]) -> Result<u64, String> {
    for i in 0..3 {
        let (copy_a, copy_b) = (shares[i].1, shares[(i + 1) % 3].0);
        if copy_a != copy_b {
            return Err(format!("component x{} differs between its two holders", (i + 1) % 3));
        }
    }
    Ok(shares[0].0 ^ shares[1].0 ^ shares[2].0)
}
