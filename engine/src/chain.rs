//! The shachain engine proper: block expansion, the masked buffer, and
//! the one-round release.
//!
//! A block is the subtree covering the next 2^h consecutive indices,
//! expanded level by level. Level d doubles the frontier: the left
//! child of each node is the node itself (no hash), the right child is
//! SHA-256 of the node with bit h-d flipped, so a level is one uniform
//! vectorised hash whose lanes are the current frontier, and a block
//! costs h hash rounds for 2^h - 1 hashes. Lightning consumes indices
//! downward, so the first block roots at 2^48 - 2^h and its highest
//! lane is released first.
//!
//! Prepared leaves are never reconstructed. Following
//! docs/buffer-storage.md, each leaf is published as a masked value
//! whose mask summands derive from long-term keys, one summand per
//! component in the same replicated pattern as the shares: summand j
//! comes from key j-1, so party i derives summands i and i+1, every
//! summand has two holders, and any quorum re-derives everything.
//! Releasing a leaf is one round of plain messaging: each party sends
//! its summand pair, the adapter compares the duplicated copies and
//! XORs them into the masked value. A wrong summand is caught by its
//! honest co-holder's copy.
//!
//! The mask keys here are derived from the pairwise protocol keys under
//! a domain tag; a production deployment deals distinct long-term keys
//! for the purpose, as the buffer-storage design describes.

use sha2::{Digest, Sha256 as HashFn};

use crate::engine::PartyBackend;
use crate::net::PartyNet;
use crate::rep3::PartyKeys;
use crate::sha256::{flip_party, PartyShared, Sha256};

/// Root index of the first block of depth h: the subtree covering
/// [2^48 - 2^h, 2^48), the first 2^h indices Lightning consumes.
pub fn first_block_root(h: u32) -> u64 {
    (1u64 << 48) - (1u64 << h)
}

fn lane_bit(x: &PartyShared, comp: usize, m: usize, lane: usize) -> u64 {
    (x.c[comp][m * x.words + lane / 64] >> (lane % 64)) & 1
}

fn set_lane_bit(x: &mut PartyShared, comp: usize, m: usize, lane: usize, bit: u64) {
    x.c[comp][m * x.words + lane / 64] |= bit << (lane % 64);
}

/// Interleave two n-lane values: a's lanes land even, b's lanes odd.
/// This is the left-child/right-child merge of one expansion level.
fn interleave(a: &PartyShared, b: &PartyShared, n: usize) -> PartyShared {
    let words = (2 * n).div_ceil(64);
    let mut out = PartyShared { words, c: [vec![0u64; 256 * words], vec![0u64; 256 * words]] };
    for comp in 0..2 {
        for m in 0..256 {
            for l in 0..n {
                set_lane_bit(&mut out, comp, m, 2 * l, lane_bit(a, comp, m, l));
                set_lane_bit(&mut out, comp, m, 2 * l + 1, lane_bit(b, comp, m, l));
            }
        }
    }
    out
}

/// One party's copy of a prepared block: 2^h leaves still in shared
/// form, lane i holding index `root_index + i`.
pub struct Block {
    pub root_index: u64,
    pub h: u32,
    pub leaves: PartyShared,
}

/// Walk from the seed to the block root (one lane, 48-h edges), then
/// expand h levels. Total hash rounds: 48, the cold-start count.
pub fn prepare_first_block(
    sha: &Sha256,
    be: &mut impl PartyBackend,
    net: &mut PartyNet,
    seed: &PartyShared,
    h: u32,
) -> Result<Block, String> {
    let root_index = first_block_root(h);
    let mut x = seed.clone();
    for b in (h..48).rev() {
        // The root's set bits are 47..h; flip and hash each.
        let all = vec![!0u64; x.words];
        flip_party(be.party(), &mut x, b as usize, &all);
        x = sha.hash32_party(be, net, &x)?;
    }
    for d in 1..=h {
        let lanes = 1usize << (d - 1);
        let mut inp = x.clone();
        let all = vec![!0u64; inp.words];
        flip_party(be.party(), &mut inp, (h - d) as usize, &all);
        let right = sha.hash32_party(be, net, &inp)?;
        x = interleave(&x, &right, lanes);
    }
    Ok(Block { root_index, h, leaves: x })
}

/// One party's component pair of a 32-byte value, extracted from a lane.
pub fn lane_components(x: &PartyShared, lane: usize) -> ([u8; 32], [u8; 32]) {
    let mut out = [[0u8; 32]; 2];
    for (comp, bytes) in out.iter_mut().enumerate() {
        for m in 0..256 {
            bytes[m / 8] |= (lane_bit(x, comp, m, lane) as u8) << (m % 8);
        }
    }
    (out[0], out[1])
}

fn derive(tag: &[u8], key: &[u8; 32], vid: u64) -> [u8; 32] {
    let mut h = HashFn::new();
    h.update(tag);
    h.update(key);
    h.update(vid.to_le_bytes());
    h.finalize().into()
}

/// Party i's summand pair for a leaf: (summand_i, summand_{i+1}),
/// derived from its two keys under a mask-only domain tag.
pub fn summand_pair(keys: &PartyKeys, vid: u64) -> ([u8; 32], [u8; 32]) {
    (derive(b"shachain-mask-v1", &keys.prev, vid), derive(b"shachain-mask-v1", &keys.own, vid))
}

fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Party i's masked component pair for one leaf: shares XORed with its
/// summands. Publishing these is safe; the missing summand blinds any
/// corrupt minority.
pub fn masked_pair(keys: &PartyKeys, block: &Block, lane: usize) -> ([u8; 32], [u8; 32]) {
    let (x_i, x_next) = lane_components(&block.leaves, lane);
    let (s_i, s_next) = summand_pair(keys, block.root_index + lane as u64);
    (xor32(x_i, s_i), xor32(x_next, s_next))
}

/// Adapter side: combine three replicated pairs into one value,
/// comparing every duplicated copy first. pairs[i] = (v_i, v_{i+1}).
pub fn combine_pairs(pairs: &[([u8; 32], [u8; 32]); 3]) -> Result<[u8; 32], String> {
    for i in 0..3 {
        if pairs[i].1 != pairs[(i + 1) % 3].0 {
            return Err(format!("component {} differs between its two holders", (i + 1) % 3));
        }
    }
    Ok(xor32(xor32(pairs[0].0, pairs[1].0), pairs[2].0))
}

/// Adapter side: the release itself. One round of plain messaging, no
/// MPC session: XOR the cross-checked summands into the published
/// masked value.
pub fn open_release(
    masked: [u8; 32],
    summands: &[([u8; 32], [u8; 32]); 3],
) -> Result<[u8; 32], String> {
    Ok(xor32(masked, combine_pairs(summands)?))
}
