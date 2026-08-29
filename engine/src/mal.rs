//! Malicious security with abort: Beaver evaluation from bucket-verified
//! triples, after Furukawa-Lindell-Nof-Weinstein (Eurocrypt 2017,
//! eprint 2016/944), each party running only its own side.
//!
//! Why this shape and not post-hoc verification of live transcripts: here
//! the only multiplications happen on *random* triples in preprocessing,
//! so any error a cheater injects is independent of secret wire values by
//! construction. The triples are then checked by opening a random sample
//! and by pairwise sacrifice inside randomly assigned buckets, where a
//! surviving forgery needs matching errors across a shuffle the adversary
//! cannot predict (the shuffle coin is drawn after the triples are
//! fixed). The online phase is Beaver: linear operations plus openings.
//! Openings are logged and the logs compared by hash at every
//! checkpoint, so the two honest parties always compare views; the
//! zero-checks compare each party's claimed third component against the
//! copies its neighbors hold, again by hash. Every detected
//! inconsistency is an abort; a corrupt minority can stop the
//! computation but not skew it.
//!
//! Parameters follow the paper: bucket size B and a minimum batch of
//! 2^(sigma/(B-1)) surviving triples for statistical security 2^-sigma
//! (B=3 and 2^20 for sigma=40), plus a small opened sample. We do not
//! claim a tighter bound than the paper proves, and we skip its
//! bucket-cache optimization (as does MP-SPDZ's `ps-rep-bin`).

use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256 as HashFn};

use crate::bristol::{Circuit, Gate};
use crate::engine::{local_gate, run_parties, Backend, PartyTape, Schedule};
use crate::net::PartyNet;
use crate::rep3::{KeySet, PairRand, PartyKeys, ZeroShare};

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

/// One party's share pairs of one 64-lane triple.
#[derive(Clone, Copy)]
struct PTriple {
    a: (u64, u64),
    b: (u64, u64),
    c: (u64, u64),
}

/// One party's whole malicious state: keys, streams, verified triples,
/// and the log of every public value it has seen since the last
/// checkpoint.
struct MalParty {
    party: usize,
    zero: ZeroShare,
    rand: PairRand,
    coin: PairRand,
    pool: Vec<PTriple>,
    log: Vec<u64>,
}

impl MalParty {
    fn new(party: usize, keys: &PartyKeys) -> Self {
        MalParty {
            party,
            zero: ZeroShare::new(keys),
            rand: PairRand::new(keys, 1),
            coin: PairRand::new(keys, 2),
            pool: Vec::new(),
            log: Vec::new(),
        }
    }

    /// Open a batch: send second components to the previous party (whose
    /// missing component they are), reconstruct, log for the view check.
    fn open_batch(&mut self, net: &mut PartyNet, shares: &[(u64, u64)]) -> Result<Vec<u64>, String> {
        let out: Vec<u64> = shares.iter().map(|s| s.1).collect();
        let inb = net.reshare_prev(&out)?;
        let vals: Vec<u64> =
            shares.iter().zip(&inb).map(|(s, &recv)| s.0 ^ s.1 ^ recv).collect();
        self.log.extend_from_slice(&vals);
        Ok(vals)
    }

    /// Views checkpoint: every opened value was public, so all logs must
    /// hash identically. Two of the three comparers are always honest.
    fn view_check(&mut self, net: &mut PartyNet) -> Result<(), String> {
        let own = hash_words(&self.log);
        let (from_prev, from_next) = net.exchange_both(&own)?;
        if from_prev != own || from_next != own {
            return Err("abort: opened values differ between parties".into());
        }
        self.log.clear();
        Ok(())
    }

    /// Zero-check a batch: each party's pair must XOR to the third
    /// component, held by both neighbors. The claimed vector travels as
    /// a hash and is compared against the copies each neighbor stores.
    fn check_zero_batch(&mut self, net: &mut PartyNet, ws: &[(u64, u64)]) -> Result<(), String> {
        let claimed: Vec<u64> = ws.iter().map(|w| w.0 ^ w.1).collect();
        let firsts: Vec<u64> = ws.iter().map(|w| w.0).collect();
        let seconds: Vec<u64> = ws.iter().map(|w| w.1).collect();
        let (from_prev, from_next) = net.exchange_both(&hash_words(&claimed))?;
        // The previous party's claim names our second component's vector;
        // the next party's claim names our first's.
        if from_prev != hash_words(&seconds) || from_next != hash_words(&firsts) {
            return Err("abort: sacrifice check is nonzero".into());
        }
        Ok(())
    }

    /// A public coin no party could predict before the triples were
    /// fixed: an opened PRSS random. The adversary misses one of the
    /// three key streams, which blinds it until the opening.
    fn draw_coin_seed(&mut self, net: &mut PartyNet) -> Result<[u8; 32], String> {
        let shares: Vec<(u64, u64)> = (0..4).map(|_| self.coin.next()).collect();
        let vals = self.open_batch(net, &shares)?;
        let mut seed = [0u8; 32];
        for (chunk, v) in seed.chunks_mut(8).zip(&vals) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
        Ok(seed)
    }

    /// Generate, cut, shuffle, bucket, sacrifice: `target` verified
    /// triples in, `target * bucket + opened` generated. Six rounds
    /// regardless of size.
    fn refill(&mut self, net: &mut PartyNet, target: usize, params: &SecurityParams) -> Result<(), String> {
        let gen = target * params.bucket + params.opened;
        let mut trips = Vec::with_capacity(gen);
        let mut out = Vec::with_capacity(gen);
        for _ in 0..gen {
            let a = self.rand.next();
            let b = self.rand.next();
            let r = (a.0 & b.0) ^ (a.0 & b.1) ^ (a.1 & b.0) ^ self.zero.next();
            out.push(r);
            trips.push(PTriple { a, b, c: (r, 0) });
        }
        let inb = net.reshare_prev(&out)?;
        for (t, &recv) in trips.iter_mut().zip(&inb) {
            t.c.1 = recv;
        }

        // The coin comes only now, after every triple message is sent,
        // and the shuffle it seeds is computed identically everywhere.
        let mut shuffle_rng = ChaCha12Rng::from_seed(self.draw_coin_seed(net)?);
        for i in (1..trips.len()).rev() {
            let j = (shuffle_rng.next_u64() % (i as u64 + 1)) as usize;
            trips.swap(i, j);
        }

        // The cut: open a sample completely and check c = a & b.
        let mut cut_shares = Vec::with_capacity(3 * params.opened);
        for t in trips.iter().take(params.opened) {
            cut_shares.extend_from_slice(&[t.a, t.b, t.c]);
        }
        let vals = self.open_batch(net, &cut_shares)?;
        for abc in vals.chunks_exact(3) {
            if abc[2] != abc[0] & abc[1] {
                return Err("abort: opened triple is wrong".into());
            }
        }

        // Sacrifice, batched across every bucket: open rho = a1^a2 and
        // sigma = b1^b2 per (head, partner) pair, then zero-check
        // c1 ^ c2 ^ sigma&a2 ^ rho&b2 ^ rho&sigma, which equals the XOR
        // of the two triples' errors.
        let buckets: Vec<&[PTriple]> =
            trips[params.opened..].chunks_exact(params.bucket).collect();
        let mut pair_shares = Vec::new();
        for bucket in &buckets {
            for partner in &bucket[1..] {
                pair_shares.push(xor2(bucket[0].a, partner.a));
                pair_shares.push(xor2(bucket[0].b, partner.b));
            }
        }
        let opened = self.open_batch(net, &pair_shares)?;
        let mut ws = Vec::with_capacity(opened.len() / 2);
        let mut k = 0;
        for bucket in &buckets {
            for partner in &bucket[1..] {
                let (rho, sigma) = (opened[k], opened[k + 1]);
                k += 2;
                let mut w = xor2(bucket[0].c, partner.c);
                w = xor2(w, and_public(sigma, partner.a));
                w = xor2(w, and_public(rho, partner.b));
                w = xor_public(w, rho & sigma, self.party);
                ws.push(w);
            }
        }
        self.check_zero_batch(net, &ws)?;
        self.view_check(net)?;
        let survivors: Vec<PTriple> = buckets.iter().map(|b| b[0]).collect();
        self.pool.extend(survivors);
        Ok(())
    }

    /// Beaver evaluation of one circuit: per level, one batched opening
    /// of d = x^a and e = y^b, then linear work; a views checkpoint at
    /// the end. Everything a cheater can do lands in an opening or a
    /// hash, and both are compared.
    fn eval_circuit(
        &mut self,
        net: &mut PartyNet,
        c: &Circuit,
        s: &Schedule,
        t: &mut PartyTape,
        params: &SecurityParams,
    ) -> Result<(), String> {
        let words = t.words;
        let need = c.n_and * words;
        while self.pool.len() < need {
            let deficit = need - self.pool.len();
            self.refill(net, deficit.max(params.min_batch()), params)?;
        }
        for phase in 0..=s.depth {
            for &gi in &s.locals[phase] {
                local_gate(self.party, c.gates[gi], t);
            }
            let ands = &s.ands[phase];
            if ands.is_empty() {
                continue;
            }
            let mut trips = Vec::with_capacity(ands.len() * words);
            let mut de_shares = Vec::with_capacity(2 * ands.len() * words);
            for &gi in ands {
                let Gate::And(x, y, _) = c.gates[gi] else { unreachable!() };
                let (xw, yw) = (x as usize * words, y as usize * words);
                for w in 0..words {
                    let trip = self.pool.pop().expect("ensured above");
                    de_shares.push(xor2((t.c[0][xw + w], t.c[1][xw + w]), trip.a));
                    de_shares.push(xor2((t.c[0][yw + w], t.c[1][yw + w]), trip.b));
                    trips.push(trip);
                }
            }
            let opened = self.open_batch(net, &de_shares)?;
            let mut k = 0;
            for &gi in ands {
                let Gate::And(_, _, o) = c.gates[gi] else { unreachable!() };
                let ow = o as usize * words;
                for w in 0..words {
                    let trip = trips[k / 2];
                    let (d, e) = (opened[k], opened[k + 1]);
                    k += 2;
                    let mut z = trip.c;
                    z = xor2(z, and_public(d, trip.b));
                    z = xor2(z, and_public(e, trip.a));
                    z = xor_public(z, d & e, self.party);
                    t.c[0][ow + w] = z.0;
                    t.c[1][ow + w] = z.1;
                }
            }
        }
        self.view_check(net)
    }
}

pub struct MalSession {
    words: usize,
    parties: Option<[MalParty; 3]>,
    pub params: SecurityParams,
    /// Bit index into party 1's outgoing byte stream to flip in transit:
    /// the full power of a corrupt sender over one bit, anywhere.
    pub cheat_bit: Option<u64>,
    pub sent_bytes: [u64; 3],
    pub rounds: u64,
}

impl MalSession {
    pub fn new(keys: &KeySet, words: usize, params: SecurityParams) -> Self {
        assert!(params.bucket >= 2, "bucket size must be at least 2");
        let parties = [
            MalParty::new(0, &keys.party(0)),
            MalParty::new(1, &keys.party(1)),
            MalParty::new(2, &keys.party(2)),
        ];
        MalSession {
            words,
            parties: Some(parties),
            params,
            cheat_bit: None,
            sent_bytes: [0; 3],
            rounds: 0,
        }
    }

    /// Verified triples currently in stock (words of 64 lanes each).
    pub fn stock(&self) -> usize {
        self.parties.as_ref().expect("state present")[0].pool.len()
    }
}

impl Backend for MalSession {
    fn words(&self) -> usize {
        self.words
    }

    fn eval(
        &mut self,
        circuit: &Circuit,
        sched: &Schedule,
        tapes: &mut [PartyTape; 3],
    ) -> Result<(), String> {
        let mut parties = self.parties.take().expect("state present");
        let [p0, p1, p2] = &mut parties;
        let [t0, t1, t2] = tapes;
        let mut states = [(p0, t0), (p1, t1), (p2, t2)];
        let params = self.params;
        let result = run_parties(&mut states, self.cheat_bit, |_, (mp, tape), net| {
            mp.eval_circuit(net, circuit, sched, tape, &params)
        });
        self.parties = Some(parties);
        let (sent, rounds) = result?;
        for p in 0..3 {
            self.sent_bytes[p] += sent[p];
        }
        self.rounds += rounds;
        Ok(())
    }
}

fn xor2(x: (u64, u64), y: (u64, u64)) -> (u64, u64) {
    (x.0 ^ y.0, x.1 ^ y.1)
}

fn and_public(mask: u64, x: (u64, u64)) -> (u64, u64) {
    (mask & x.0, mask & x.1)
}

/// XOR a public word into the sharing: component x0, held by parties
/// 0 (first component) and 2 (second).
fn xor_public(mut x: (u64, u64), v: u64, party: usize) -> (u64, u64) {
    if party == 0 {
        x.0 ^= v;
    }
    if party == 2 {
        x.1 ^= v;
    }
    x
}

fn hash_words(words: &[u64]) -> Vec<u64> {
    let mut h = HashFn::new();
    for w in words {
        h.update(w.to_le_bytes());
    }
    h.finalize()[..].chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
}
