//! The BOLT #3 walk on shared values.

use crate::engine::{Backend, PartyBackend};
use crate::net::PartyNet;
use crate::sha256::{flip, flip_party, PartyShared, Sha256, Shared256};

/// BOLT #3 `generate_from_seed`: flip each set bit of `index` from bit 47
/// down and hash. Every lane walks the same index; per-lane indices are
/// M3's flip-mask batching. Err is a malicious backend's abort.
pub fn generate_from_seed(
    sha: &Sha256,
    s: &mut impl Backend,
    seed: &Shared256,
    index: u64,
) -> Result<Shared256, String> {
    let all = vec![!0u64; seed.words];
    let mut x = seed.clone();
    for b in (0..48).rev() {
        if (index >> b) & 1 == 1 {
            flip(&mut x, b, &all);
            x = sha.hash32(s, &x)?;
        }
    }
    Ok(x)
}

/// K consecutive edges from the root, bits 47, 46, ...: the same walk
/// `scripts/ref.py <seed> <K>` prints, for benchmarks and cross-checks.
pub fn walk_edges(
    sha: &Sha256,
    s: &mut impl Backend,
    seed: &Shared256,
    k: usize,
) -> Result<Shared256, String> {
    let all = vec![!0u64; seed.words];
    let mut x = seed.clone();
    for i in 0..k {
        flip(&mut x, 47 - i, &all);
        x = sha.hash32(s, &x)?;
    }
    Ok(x)
}

/// The same walk, one party's side, for a standalone process.
pub fn walk_edges_party(
    sha: &Sha256,
    be: &mut impl PartyBackend,
    net: &mut PartyNet,
    seed: &PartyShared,
    k: usize,
) -> Result<PartyShared, String> {
    let all = vec![!0u64; seed.words];
    let mut x = seed.clone();
    for i in 0..k {
        flip_party(be.party(), &mut x, 47 - i, &all);
        x = sha.hash32_party(be, net, &x)?;
    }
    Ok(x)
}
