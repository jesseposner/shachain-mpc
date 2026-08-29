//! SHA-256 of a 32-byte message via the Bristol Fashion circuit, plus the
//! shared-value representation the shachain walk lives on.
//!
//! Wire convention, confirmed against MP-SPDZ's `Compiler/circuit.py`:
//! wire j of a circuit input is bit j of that input read as a big-endian
//! integer. So for input 0 (the 512-bit padded block), byte k bit t
//! (t = 0 the least significant bit of the byte) sits on wire
//! 8*(63-k) + t; the 256-bit state and output use 8*(31-k) + t.
//!
//! Shared values use BOLT's own bit addressing: entry m = 8*byte + bit,
//! bit least-significant-first within the byte, exactly the positions
//! BOLT #3's `flip` touches.

use std::env;
use std::path::PathBuf;

use rand_core::RngCore;

use crate::bristol::Circuit;
use crate::engine::{Backend, Tapes};
use crate::rep3::{reconstruct_word, share_word};

pub const IV: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5,
    0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0,
    0xcd, 0x19,
];

/// A shared 32-byte value across 64*words lanes.
/// `c[party][component][entry * words + w]`, entries in BOLT bit order.
#[derive(Clone)]
pub struct Shared256 {
    pub words: usize,
    pub c: [[Vec<u64>; 2]; 3],
}

impl Shared256 {
    pub fn zero(words: usize) -> Self {
        let blank = || [vec![0u64; 256 * words], vec![0u64; 256 * words]];
        Shared256 { words, c: [blank(), blank(), blank()] }
    }
}

/// BOLT #3 flip: XOR a public 1 into bit position b, in the lanes named
/// by `mask` (one u64 per word, bit l = lane 64*w + l).
pub fn flip(x: &mut Shared256, b: usize, mask: &[u64]) {
    for w in 0..x.words {
        x.c[0][0][b * x.words + w] ^= mask[w];
        x.c[2][1][b * x.words + w] ^= mask[w];
    }
}

/// Deal `lanes` values into one shared vector. Unused lanes are zero.
pub fn share_lanes(lanes: &[[u8; 32]], rng: &mut impl RngCore) -> Shared256 {
    let words = lanes.len().div_ceil(64);
    let mut out = Shared256::zero(words);
    for m in 0..256 {
        for w in 0..words {
            let mut v = 0u64;
            for (l, lane) in lanes.iter().skip(w * 64).take(64).enumerate() {
                v |= u64::from((lane[m / 8] >> (m % 8)) & 1) << l;
            }
            let shares = share_word(v, rng);
            for p in 0..3 {
                out.c[p][0][m * words + w] = shares[p].0;
                out.c[p][1][m * words + w] = shares[p].1;
            }
        }
    }
    out
}

/// Reconstruct the first `n` lanes, cross-checking every replicated copy.
pub fn reconstruct_lanes(x: &Shared256, n: usize) -> Result<Vec<[u8; 32]>, String> {
    let mut lanes = vec![[0u8; 32]; n];
    for m in 0..256 {
        for w in 0..x.words {
            let i = m * x.words + w;
            let v = reconstruct_word([
                (x.c[0][0][i], x.c[0][1][i]),
                (x.c[1][0][i], x.c[1][1][i]),
                (x.c[2][0][i], x.c[2][1][i]),
            ])
            .map_err(|e| format!("entry {m}: {e}"))?;
            for (l, lane) in lanes.iter_mut().skip(w * 64).take(64).enumerate() {
                lane[m / 8] |= (((v >> l) & 1) as u8) << (m % 8);
            }
        }
    }
    Ok(lanes)
}

pub struct Sha256 {
    pub circuit: Circuit,
}

impl Sha256 {
    /// Load the circuit from the MP-SPDZ checkout ($MPSPDZ, or a sibling
    /// of the repository). Not vendored: the circuit file carries the
    /// Bristol/KU Leuven license, and this crate is MIT.
    pub fn load() -> Result<Self, String> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(base) = env::var("MPSPDZ") {
            candidates.push(base.into());
        }
        candidates.push("../MP-SPDZ".into());
        candidates.push("../../MP-SPDZ".into());
        for base in &candidates {
            let path = base.join("Programs/Circuits/sha256.txt");
            if path.exists() {
                let circuit = Circuit::load(&path)?;
                if circuit.inputs != [512, 256] || circuit.outputs != [256] {
                    return Err(format!("{}: unexpected circuit shape", path.display()));
                }
                return Ok(Sha256 { circuit });
            }
        }
        Err("sha256.txt not found; set MPSPDZ to an MP-SPDZ checkout".into())
    }

    /// One shachain edge's hash: SHA-256 of a 32-byte shared message.
    /// Padding and IV are public; the message shares are the only secret
    /// input, so an edge costs exactly the circuit's 22,573 ANDs. Under
    /// a malicious backend, Err is an abort.
    pub fn hash32(&self, s: &mut impl Backend, msg: &Shared256) -> Result<Shared256, String> {
        assert_eq!(s.words(), msg.words);
        let words = msg.words;
        let mut t = Tapes::new(self.circuit.n_wires, words);

        // Input 0: the padded block. Message bytes 0..32 come from the
        // shares; bytes 32..64 are the fixed padding for a 256-bit
        // message: 0x80, zeros, then the bit length 256 big-endian.
        let mut pad = [0u8; 64];
        pad[32] = 0x80;
        pad[62] = 0x01;
        let block0 = self.circuit.input_offset(0);
        for k in 0..64 {
            for bit in 0..8 {
                let wire = block0 + 8 * (63 - k) + bit;
                if k < 32 {
                    let m = 8 * k + bit;
                    for p in 0..3 {
                        for comp in 0..2 {
                            let (src, dst) = (&msg.c[p][comp], &mut t.c[p][comp]);
                            dst[wire * words..(wire + 1) * words]
                                .copy_from_slice(&src[m * words..(m + 1) * words]);
                        }
                    }
                } else {
                    let v = if (pad[k] >> bit) & 1 == 1 { !0u64 } else { 0 };
                    for w in 0..words {
                        t.set_public(wire, w, v);
                    }
                }
            }
        }

        // Input 1: the IV, public.
        let state0 = self.circuit.input_offset(1);
        for k in 0..32 {
            for bit in 0..8 {
                let wire = state0 + 8 * (31 - k) + bit;
                let v = if (IV[k] >> bit) & 1 == 1 { !0u64 } else { 0 };
                for w in 0..words {
                    t.set_public(wire, w, v);
                }
            }
        }

        s.eval(&self.circuit, &mut t)?;

        let out0 = self.circuit.output_offset(0);
        let mut digest = Shared256::zero(words);
        for k in 0..32 {
            for bit in 0..8 {
                let wire = out0 + 8 * (31 - k) + bit;
                let m = 8 * k + bit;
                for p in 0..3 {
                    for comp in 0..2 {
                        let (src, dst) = (&t.c[p][comp], &mut digest.c[p][comp]);
                        dst[m * words..(m + 1) * words]
                            .copy_from_slice(&src[wire * words..(wire + 1) * words]);
                    }
                }
            }
        }
        Ok(digest)
    }
}
