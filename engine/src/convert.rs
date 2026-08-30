//! Boolean-to-scalar conversion and point export, with no arithmetic
//! MPC at all.
//!
//! Instead of daBit machinery over Z_q, the leaf is published masked
//! additively mod q: t = (s + s_0 + s_1 + s_2) mod q, where the s_j are
//! summands derived from long-term keys under a domain tag of their own
//! (never the XOR-mask summands: the two paddings must be independent).
//! Each summand is known to exactly two parties, who sit together on
//! one replicated component, so its Boolean sharing is constructible
//! locally with zero communication, and the whole mask is one Boolean
//! circuit: three ripple additions and four conditional subtractions of
//! q, evaluated once per block across every lane, then opened.
//!
//! Everything else is public arithmetic:
//!   point:   P = t*G - sum_j (s_j * G), each s_j*G published by its two
//!            holders and cross-checked;
//!   release: s = t - sum_j s_j (mod q), one round, no MPC, checked
//!            against P by the same equation the counterparty verifies.
//!
//! The construction identifies a secret with its class mod q, which is
//! exact unless the 32-byte secret is >= q: probability ~2^-128, the
//! same invalid-scalar branch the rest of this repository documents.

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256 as HashFn};

use crate::bristol::{Circuit, Gate};
use crate::chain::Block;
use crate::engine::{PartyBackend, PartyTape, Schedule};
use crate::net::PartyNet;
use crate::rep3::PartyKeys;

/// secp256k1 group order, big-endian.
pub const Q_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
    0x41, 0x41,
];

const QMASK_TAG: &[u8] = b"shachain-qmask-v1";

/// Little bit-vector circuit builder. Wires for the inputs come first,
/// then gate outputs; `finish` copies the result onto fresh final wires
/// so the Bristol outputs-are-last convention holds.
struct Builder {
    inputs: Vec<usize>,
    gates: Vec<Gate>,
    next: u32,
    zero: u32,
}

impl Builder {
    /// Input 0 is two constant wires (zero, one); the caller's inputs
    /// follow.
    fn new(input_sizes: &[usize]) -> Builder {
        let mut inputs = vec![2];
        inputs.extend_from_slice(input_sizes);
        let next = inputs.iter().sum::<usize>() as u32;
        Builder { inputs, gates: Vec::new(), next, zero: 0 }
    }

    fn input_offset(&self, k: usize) -> u32 {
        self.inputs[..k + 1].iter().sum::<usize>() as u32
    }

    fn xor(&mut self, a: u32, b: u32) -> u32 {
        let o = self.next;
        self.next += 1;
        self.gates.push(Gate::Xor(a, b, o));
        o
    }

    fn and(&mut self, a: u32, b: u32) -> u32 {
        let o = self.next;
        self.next += 1;
        self.gates.push(Gate::And(a, b, o));
        o
    }

    fn inv(&mut self, a: u32) -> u32 {
        let o = self.next;
        self.next += 1;
        self.gates.push(Gate::Inv(a, o));
        o
    }

    /// a + b over `width` bits, LSB first; result has width+1 bits.
    fn add(&mut self, a: &[u32], b: &[u32], width: usize) -> Vec<u32> {
        let zero = self.zero;
        let get = move |v: &[u32], i: usize| if i < v.len() { v[i] } else { zero };
        let mut carry = self.zero;
        let mut out = Vec::with_capacity(width + 1);
        for i in 0..width {
            let (ai, bi) = (get(a, i), get(b, i));
            let axb = self.xor(ai, bi);
            let s = self.xor(axb, carry);
            let t1 = self.and(ai, bi);
            let t2 = self.and(axb, carry);
            carry = self.xor(t1, t2);
            out.push(s);
        }
        out.push(carry);
        out
    }

    /// a + K for a constant K over `width` bits; returns (sum, carry_out).
    fn add_const(&mut self, a: &[u32], k_bits: &[bool], width: usize) -> (Vec<u32>, u32) {
        let mut carry = self.zero;
        let mut out = Vec::with_capacity(width);
        for i in 0..width {
            let ai = if i < a.len() { a[i] } else { self.zero };
            let ki = i < k_bits.len() && k_bits[i];
            if ki {
                // sum = a ^ c ^ 1, carry' = a | c
                let axc = self.xor(ai, carry);
                out.push(self.inv(axc));
                let na = self.inv(ai);
                let nc = self.inv(carry);
                let nand = self.and(na, nc);
                carry = self.inv(nand);
            } else {
                // sum = a ^ c, carry' = a & c
                out.push(self.xor(ai, carry));
                carry = self.and(ai, carry);
            }
        }
        (out, carry)
    }

    /// If u >= q, replace u with u - q; via u + (2^width - q), whose
    /// carry-out is exactly the comparison.
    fn cond_subtract_q(&mut self, u: &[u32], width: usize) -> Vec<u32> {
        // K = 2^width - q, LSB first.
        let mut k_bits = vec![false; width];
        let q = q_bits_lsb();
        // two's complement: invert q's bits (padded to width) and add 1.
        let mut carry = true;
        for (i, kb) in k_bits.iter_mut().enumerate() {
            let qi = i < 256 && q[i];
            let inv = !qi;
            *kb = inv ^ carry;
            carry = inv && carry;
        }
        let (v, ge) = self.add_const(u, &k_bits, width);
        // out = ge ? v : u, one AND per bit.
        let mut out = Vec::with_capacity(width);
        for i in 0..width {
            let ui = if i < u.len() { u[i] } else { self.zero };
            let uxv = self.xor(ui, v[i]);
            let sel = self.and(ge, uxv);
            out.push(self.xor(ui, sel));
        }
        out
    }

    fn finish(mut self, result: &[u32]) -> Circuit {
        let zero = self.zero;
        let outs: Vec<u32> = result.iter().map(|&w| self.xor(w, zero)).collect();
        debug_assert_eq!(*outs.last().unwrap() as usize, self.next as usize - 1);
        let n_and = self.gates.iter().filter(|g| matches!(g, Gate::And(..))).count();
        Circuit {
            n_wires: self.next as usize,
            inputs: self.inputs,
            outputs: vec![result.len()],
            gates: self.gates,
            n_and,
        }
    }
}

fn q_bits_lsb() -> Vec<bool> {
    (0..256).map(|i| (Q_BYTES[31 - i / 8] >> (i % 8)) & 1 == 1).collect()
}

/// (s + s0 + s1 + s2) mod q. Inputs (after the constant pair): s and the
/// three summands, each 256 bits LSB first. Output: 256 bits LSB first.
pub fn build_qmask_circuit() -> Circuit {
    let mut b = Builder::new(&[256, 256, 256, 256]);
    let input = |k: usize| -> Vec<u32> {
        let off = b.input_offset(k);
        (off..off + 256).collect()
    };
    let (s, s0, s1, s2) = (input(0), input(1), input(2), input(3));
    let u = b.add(&s, &s0, 257);
    let u = b.add(&u, &s1, 258);
    let mut u = b.add(&u, &s2, 259);
    for _ in 0..4 {
        u = b.cond_subtract_q(&u, 259);
    }
    b.finish(&u[..256])
}

/// The q-mask summand pair party i derives: (s_i, s_{i+1}), from its two
/// keys under the q-mask tag. Independent of the XOR-mask summands.
pub fn qmask_summand_pair(keys: &PartyKeys, vid: u64) -> ([u8; 32], [u8; 32]) {
    let derive = |key: &[u8; 32]| -> [u8; 32] {
        let mut h = HashFn::new();
        h.update(QMASK_TAG);
        h.update(key);
        h.update(vid.to_le_bytes());
        h.finalize().into()
    };
    (derive(&keys.prev), derive(&keys.own))
}

pub struct Converter {
    pub circuit: Circuit,
    pub sched: Schedule,
}

impl Converter {
    pub fn new() -> Self {
        let circuit = build_qmask_circuit();
        let sched = Schedule::new(&circuit);
        Converter { circuit, sched }
    }

    /// One party's side: mask every lane of a block mod q and open the
    /// results. Returns the public t value per lane, big-endian bytes.
    pub fn mask_block(
        &self,
        be: &mut impl PartyBackend,
        net: &mut PartyNet,
        keys: &PartyKeys,
        block: &Block,
    ) -> Result<Vec<[u8; 32]>, String> {
        let party = be.party();
        let words = block.leaves.words;
        let lanes = 1usize << block.h;
        let mut tape = PartyTape::new(self.circuit.n_wires, words);

        // Constant wires.
        for w in 0..words {
            tape.set_public(party, 0, w, 0);
            tape.set_public(party, 1, w, !0);
        }

        // s: integer bit i of the leaf is BOLT entry 8*(31 - i/8) + i%8.
        let s_off = self.circuit.input_offset(1);
        for i in 0..256 {
            let m = 8 * (31 - i / 8) + i % 8;
            for comp in 0..2 {
                for w in 0..words {
                    tape.c[comp][(s_off + i) * words + w] =
                        block.leaves.c[comp][m * words + w];
                }
            }
        }

        // Summand j: component j carries the value, held by parties j-1
        // and j; everyone else contributes zeros. Party p writes its
        // first component if p == j, its second if p+1 == j.
        for j in 0..3 {
            let off = self.circuit.input_offset(2 + j);
            let comp = if party == j {
                Some(0)
            } else if (party + 1) % 3 == j {
                Some(1)
            } else {
                None
            };
            let Some(comp) = comp else { continue };
            // The pair is (s_p, s_{p+1}): s_p from keys.prev, s_{p+1}
            // from keys.own. Party p's component 0 is x_p (so summand p,
            // from prev), component 1 is x_{p+1} (summand p+1, from own).
            for lane in 0..lanes {
                let vid = block.root_index + lane as u64;
                let (s_prev, s_own) = qmask_summand_pair(keys, vid);
                let bytes = if comp == 0 { s_prev } else { s_own };
                for i in 0..256 {
                    let bit = u64::from((bytes[31 - i / 8] >> (i % 8)) & 1);
                    tape.c[comp][(off + i) * words + lane / 64] |= bit << (lane % 64);
                }
            }
        }

        be.eval_circuit(&self.circuit, &self.sched, &mut tape, net)?;

        // Open the outputs.
        let out0 = self.circuit.output_offset(0);
        let mut shares = Vec::with_capacity(256 * words);
        for i in 0..256 {
            for w in 0..words {
                let idx = (out0 + i) * words + w;
                shares.push((tape.c[0][idx], tape.c[1][idx]));
            }
        }
        let vals = be.open_words(net, &shares)?;
        let mut out = vec![[0u8; 32]; lanes];
        for i in 0..256 {
            for (lane, t) in out.iter_mut().enumerate() {
                let v = vals[i * words + lane / 64];
                t[31 - i / 8] |= (((v >> (lane % 64)) & 1) as u8) << (i % 8);
            }
        }
        Ok(out)
    }
}

impl Default for Converter {
    fn default() -> Self {
        Self::new()
    }
}

fn scalar(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(bytes))
}

fn compress(p: ProjectivePoint) -> [u8; 33] {
    p.to_affine().to_sec1_point(true).as_bytes().try_into().expect("compressed point")
}

/// Party i's published point pair for a leaf: (s_i*G, s_{i+1}*G).
pub fn point_pair(keys: &PartyKeys, vid: u64) -> ([u8; 33], [u8; 33]) {
    let (s_prev, s_own) = qmask_summand_pair(keys, vid);
    (
        compress(ProjectivePoint::GENERATOR * scalar(&s_prev)),
        compress(ProjectivePoint::GENERATOR * scalar(&s_own)),
    )
}

/// Adapter side: P = t*G - sum of the summand points, after comparing
/// every replicated copy. pairs[i] = (Q_i, Q_{i+1}).
pub fn published_point(
    t: &[u8; 32],
    pairs: &[([u8; 33], [u8; 33]); 3],
) -> Result<[u8; 33], String> {
    let mut p = ProjectivePoint::GENERATOR * scalar(t);
    for i in 0..3 {
        if pairs[i].1 != pairs[(i + 1) % 3].0 {
            return Err(format!("summand point {} differs between its holders", (i + 1) % 3));
        }
        let q = k256::PublicKey::from_sec1_bytes(&pairs[i].0)
            .map_err(|e| format!("bad point: {e}"))?;
        p -= q.to_projective();
    }
    Ok(compress(p))
}

/// Adapter side: the release. s = t - sum_j s_j (mod q), cross-checked
/// copies first, then the point equation the counterparty verifies.
pub fn release_q(
    t: &[u8; 32],
    summands: &[([u8; 32], [u8; 32]); 3],
    point: &[u8; 33],
) -> Result<[u8; 32], String> {
    let mut s = scalar(t);
    for i in 0..3 {
        if summands[i].1 != summands[(i + 1) % 3].0 {
            return Err(format!("summand {} differs between its holders", (i + 1) % 3));
        }
        s -= scalar(&summands[i].0);
    }
    let bytes: [u8; 32] = s.to_bytes().into();
    if compress(ProjectivePoint::GENERATOR * s) != *point {
        return Err("released secret does not match the published point".into());
    }
    Ok(bytes)
}
