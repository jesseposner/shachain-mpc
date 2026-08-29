//! Malicious security with abort: Beaver evaluation from bucket-verified
//! triples, after Furukawa-Lindell-Nof-Weinstein (Eurocrypt 2017,
//! eprint 2016/944).
//!
//! Why this shape and not post-hoc verification of live transcripts: here
//! the only multiplications happen on *random* triples in preprocessing,
//! so any error a cheater injects is independent of secret wire values by
//! construction. The triples are then checked by opening a random sample
//! and by pairwise sacrifice inside randomly assigned buckets, where a
//! surviving forgery needs matching errors across a shuffle the adversary
//! cannot predict (the shuffle coin is drawn after the triples are
//! fixed). The online phase is Beaver: linear operations plus openings,
//! and every opening is cross-checked between parties, so the two honest
//! parties always compare views. Every detected inconsistency is an
//! abort; a corrupt minority can stop the computation but not skew it.
//!
//! Parameters follow the paper: bucket size B and a minimum batch of
//! 2^(sigma/(B-1)) surviving triples for statistical security 2^-sigma
//! (B=3 and 2^20 for sigma=40), plus a small opened sample. We do not
//! claim a tighter bound than the paper proves, and we skip its
//! bucket-cache optimization (as does MP-SPDZ's `ps-rep-bin`), paying
//! ~9 bits per AND per party instead of the optimized 7.
//!
//! In-process model: the three parties run in lockstep; the view
//! comparison after an open and the batched zero-check are direct
//! equality checks here, standing in for the constant-size hash
//! exchanges of a deployment. The `Cheat` hook flips one bit of one
//! message from party 1 as received by party 0, leaving party 1's own
//! state intact: exactly the power of a corrupt sender over one wire.

use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};

use crate::bristol::{Circuit, Gate};
use crate::engine::{Backend, Tapes};
use crate::rep3::{KeySet, PairRand, ZeroShare};

#[derive(Clone, Copy, Debug)]
pub struct SecurityParams {
    /// Statistical security exponent: detection failure <= 2^-sigma.
    pub sigma: u32,
    /// Bucket size B: B-1 sacrifices per surviving triple.
    pub bucket: usize,
    /// Triples opened per generation batch (the cut).
    pub opened: usize,
}

impl Default for SecurityParams {
    fn default() -> Self {
        SecurityParams { sigma: 40, bucket: 3, opened: 64 }
    }
}

impl SecurityParams {
    /// Minimum surviving triples per batch for the bucket bound.
    pub fn min_batch(&self) -> usize {
        1usize << (self.sigma as usize).div_ceil(self.bucket - 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CheatPhase {
    /// Flip the n-th multiplication message (triple generation).
    Mult,
    /// Flip the n-th opening message (cut, sacrifice, or Beaver).
    Open,
}

#[derive(Clone, Copy, Debug)]
pub struct Cheat {
    pub phase: CheatPhase,
    pub word: usize,
}

/// One 64-lane triple: replicated share pairs per party for a, b, c.
#[derive(Clone, Copy)]
struct TripleWord {
    a: [(u64, u64); 3],
    b: [(u64, u64); 3],
    c: [(u64, u64); 3],
}

pub struct MalSession {
    words: usize,
    zero: [ZeroShare; 3],
    rand: [PairRand; 3],
    coin: [PairRand; 3],
    pool: Vec<TripleWord>,
    pub params: SecurityParams,
    pub cheat: Option<Cheat>,
    pub sent_bytes: [u64; 3],
    pub and_words_evaluated: u64,
    mult_seen: usize,
    open_seen: usize,
}

impl MalSession {
    pub fn new(keys: &KeySet, words: usize, params: SecurityParams) -> Self {
        assert!(params.bucket >= 2, "bucket size must be at least 2");
        MalSession {
            words,
            zero: [ZeroShare::new(keys, 0), ZeroShare::new(keys, 1), ZeroShare::new(keys, 2)],
            rand: [
                PairRand::new(keys, 0, 1),
                PairRand::new(keys, 1, 1),
                PairRand::new(keys, 2, 1),
            ],
            coin: [
                PairRand::new(keys, 0, 2),
                PairRand::new(keys, 1, 2),
                PairRand::new(keys, 2, 2),
            ],
            pool: Vec::new(),
            params,
            cheat: None,
            sent_bytes: [0; 3],
            and_words_evaluated: 0,
            mult_seen: 0,
            open_seen: 0,
        }
    }

    /// Verified triples currently in stock (words of 64 lanes each).
    pub fn stock(&self) -> usize {
        self.pool.len()
    }

    fn flip_if_cheating(&mut self, phase: CheatPhase, seen: usize) -> u64 {
        match self.cheat {
            Some(c) if c.phase == phase && c.word == seen => 1,
            _ => 0,
        }
    }

    /// Semi-honest multiplication of two replicated sharings: each party
    /// resends its randomized local product to the previous party. This
    /// is the only place a product is computed, and it only ever runs on
    /// random inputs.
    fn mult(&mut self, x: [(u64, u64); 3], y: [(u64, u64); 3]) -> [(u64, u64); 3] {
        let mut r = [0u64; 3];
        for p in 0..3 {
            let (xi, xj) = x[p];
            let (yi, yj) = y[p];
            r[p] = (xi & yi) ^ (xi & yj) ^ (xj & yi) ^ self.zero[p].next();
        }
        let seen = self.mult_seen;
        self.mult_seen += 1;
        // Party 1's message to party 0 is the one the cheat hook owns:
        // party 0 receives r_1 as its second component.
        let flip = self.flip_if_cheating(CheatPhase::Mult, seen);
        let mut out = [(0u64, 0u64); 3];
        for p in 0..3 {
            out[p] = (r[p], r[(p + 1) % 3]);
            self.sent_bytes[p] += 8;
        }
        out[0].1 ^= flip;
        out
    }

    /// Open a sharing: party i receives its missing component from party
    /// i+1, then all parties compare the reconstructed value (the view
    /// comparison; two of the three comparers are always honest).
    fn open(&mut self, x: [(u64, u64); 3]) -> Result<u64, String> {
        let seen = self.open_seen;
        self.open_seen += 1;
        let flip = self.flip_if_cheating(CheatPhase::Open, seen);
        let mut v = [0u64; 3];
        for p in 0..3 {
            // Party p+1 sends its second component, which is comp p+2.
            let received = x[(p + 1) % 3].1 ^ if p == 0 { flip } else { 0 };
            v[p] = x[p].0 ^ x[p].1 ^ received;
            self.sent_bytes[(p + 1) % 3] += 8;
        }
        if v[0] != v[1] || v[1] != v[2] {
            return Err("abort: opened values differ between parties".into());
        }
        Ok(v[0])
    }

    /// Check that a sharing is zero: party i's pair XORs to the third
    /// component, which both other parties hold. Deployed as one batched
    /// hash exchange; compared directly here, so it costs no counted
    /// traffic.
    fn check_zero(&self, w: [(u64, u64); 3]) -> Result<(), String> {
        for p in 0..3 {
            let claimed = w[p].0 ^ w[p].1;
            if claimed != w[(p + 1) % 3].1 || claimed != w[(p + 2) % 3].0 {
                return Err("abort: sacrifice check is nonzero".into());
            }
        }
        Ok(())
    }

    /// A public coin no party could predict before the triples were
    /// fixed: the XOR of all three PRSS streams, opened. The adversary
    /// holds two of the three keys, so the third stream blinds it.
    fn draw_coin_seed(&mut self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        for chunk in seed.chunks_mut(8) {
            let p0 = self.coin[0].next();
            let p1 = self.coin[1].next();
            let _ = self.coin[2].next();
            // r0 ^ r1 ^ r2: party 0 holds (r0, r1), party 1 holds (r1, r2).
            let word = p0.0 ^ p0.1 ^ p1.1;
            chunk.copy_from_slice(&word.to_le_bytes());
            for p in 0..3 {
                self.sent_bytes[p] += 8;
            }
        }
        seed
    }

    /// Verify that t1's product is correct using t2, consuming t2.
    /// With rho = a1^a2 and sigma = b1^b2 opened,
    /// c1 ^ c2 ^ sigma&a2 ^ rho&b2 ^ rho&sigma = e1 ^ e2, the XOR of the
    /// two triples' errors: zero iff the errors match, and the shuffle
    /// makes matching errors across a bucket a 2^-sigma event.
    fn sacrifice(&mut self, t1: &TripleWord, t2: &TripleWord) -> Result<(), String> {
        let rho = self.open(xor3(t1.a, t2.a))?;
        let sigma = self.open(xor3(t1.b, t2.b))?;
        let mut w = xor3(t1.c, t2.c);
        w = xor3(w, and_public(sigma, t2.a));
        w = xor3(w, and_public(rho, t2.b));
        w = xor_public(w, rho & sigma);
        self.check_zero(w)
    }

    /// Generate, cut, shuffle, bucket, sacrifice: `target` verified
    /// triples out, `target * bucket + opened` generated.
    fn refill(&mut self, target: usize) -> Result<(), String> {
        let gen = target * self.params.bucket + self.params.opened;
        let mut trips = Vec::with_capacity(gen);
        for _ in 0..gen {
            let a = [self.rand[0].next(), self.rand[1].next(), self.rand[2].next()];
            let b = [self.rand[0].next(), self.rand[1].next(), self.rand[2].next()];
            let c = self.mult(a, b);
            trips.push(TripleWord { a, b, c });
        }

        // The coin is drawn only now, after every triple message is sent.
        let mut shuffle_rng = ChaCha12Rng::from_seed(self.draw_coin_seed());
        for i in (1..trips.len()).rev() {
            let j = (shuffle_rng.next_u64() % (i as u64 + 1)) as usize;
            trips.swap(i, j);
        }

        // The cut: open a sample completely and check c = a & b.
        for t in trips.iter().take(self.params.opened) {
            let a = self.open(t.a)?;
            let b = self.open(t.b)?;
            let c = self.open(t.c)?;
            if c != a & b {
                return Err("abort: opened triple is wrong".into());
            }
        }

        for bucket in trips[self.params.opened..].chunks_exact(self.params.bucket) {
            for partner in &bucket[1..] {
                self.sacrifice(&bucket[0], partner)?;
            }
            self.pool.push(bucket[0]);
        }
        Ok(())
    }

    fn ensure(&mut self, needed: usize) -> Result<(), String> {
        while self.pool.len() < needed {
            let deficit = needed - self.pool.len();
            self.refill(deficit.max(self.params.min_batch()))?;
        }
        Ok(())
    }
}

impl Backend for MalSession {
    fn words(&self) -> usize {
        self.words
    }

    /// Beaver evaluation: AND gates consume one verified triple per word
    /// and open d = x^a, e = y^b; everything else is local and linear, so
    /// a corrupt party's only remaining moves are bad openings, caught by
    /// the view comparison, and bad shares of its own inputs, which the
    /// replicated cross-check at reconstruction catches.
    fn eval(&mut self, circuit: &Circuit, t: &mut Tapes) -> Result<(), String> {
        assert_eq!(self.words, t.words);
        let words = self.words;
        self.ensure(circuit.n_and * words)?;
        for gate in &circuit.gates {
            match *gate {
                Gate::Xor(x, y, o) => {
                    let (xw, yw, ow) =
                        (x as usize * words, y as usize * words, o as usize * words);
                    for p in 0..3 {
                        for comp in 0..2 {
                            for w in 0..words {
                                let tape = &mut t.c[p][comp];
                                tape[ow + w] = tape[xw + w] ^ tape[yw + w];
                            }
                        }
                    }
                }
                Gate::Inv(x, o) => {
                    let (xw, ow) = (x as usize * words, o as usize * words);
                    for p in 0..3 {
                        for comp in 0..2 {
                            for w in 0..words {
                                let tape = &mut t.c[p][comp];
                                tape[ow + w] = tape[xw + w];
                            }
                        }
                    }
                    for w in 0..words {
                        t.c[0][0][ow + w] ^= !0;
                        t.c[2][1][ow + w] ^= !0;
                    }
                }
                Gate::And(x, y, o) => {
                    let (xw, yw, ow) =
                        (x as usize * words, y as usize * words, o as usize * words);
                    for w in 0..words {
                        let trip = self.pool.pop().expect("ensured above");
                        let xs = read(t, xw + w);
                        let ys = read(t, yw + w);
                        let d = self.open(xor3(xs, trip.a))?;
                        let e = self.open(xor3(ys, trip.b))?;
                        let mut z = trip.c;
                        z = xor3(z, and_public(d, trip.b));
                        z = xor3(z, and_public(e, trip.a));
                        z = xor_public(z, d & e);
                        for p in 0..3 {
                            t.c[p][0][ow + w] = z[p].0;
                            t.c[p][1][ow + w] = z[p].1;
                        }
                        self.and_words_evaluated += 1;
                    }
                }
            }
        }
        Ok(())
    }
}

fn read(t: &Tapes, idx: usize) -> [(u64, u64); 3] {
    [
        (t.c[0][0][idx], t.c[0][1][idx]),
        (t.c[1][0][idx], t.c[1][1][idx]),
        (t.c[2][0][idx], t.c[2][1][idx]),
    ]
}

fn xor3(x: [(u64, u64); 3], y: [(u64, u64); 3]) -> [(u64, u64); 3] {
    [
        (x[0].0 ^ y[0].0, x[0].1 ^ y[0].1),
        (x[1].0 ^ y[1].0, x[1].1 ^ y[1].1),
        (x[2].0 ^ y[2].0, x[2].1 ^ y[2].1),
    ]
}

fn and_public(mask: u64, x: [(u64, u64); 3]) -> [(u64, u64); 3] {
    [
        (mask & x[0].0, mask & x[0].1),
        (mask & x[1].0, mask & x[1].1),
        (mask & x[2].0, mask & x[2].1),
    ]
}

/// XOR a public word into the sharing: component x0, held by parties
/// 0 and 2.
fn xor_public(mut x: [(u64, u64); 3], v: u64) -> [(u64, u64); 3] {
    x[0].0 ^= v;
    x[2].1 ^= v;
    x
}
