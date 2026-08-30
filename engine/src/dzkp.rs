//! Malicious security at ~1 bit per AND: semi-honest evaluation plus a
//! distributed zero-knowledge proof over the transcript, in the style
//! of Boyle-Gilboa-Ishai-Nof (CCS 2019 / Asiacrypt 2020; the AntCPLab
//! USENIX'23 artifact is the nearest running relative). This module is
//! RECONSTRUCTED from that line of work, not transcribed from it; the
//! argument below is self-contained on purpose, and this layer sits
//! behind the same trait as the FLNW backend, which remains the
//! conservative default until this one has been reviewed.
//!
//! Why 3PC replicated sharing admits this at all: party i's message for
//! an AND gate is r_i = x_i y_i + x_i y_{i+1} + x_{i+1} y_i + F_{k_{i-1}}
//! + F_{k_i}, and every variable in that equation is known to one of
//! the other two parties: x_i, y_i, the received r_i, and the k_{i-1}
//! stream to party i-1 (the left verifier), and x_{i+1}, y_{i+1}, the
//! k_i stream to party i+1 (the right verifier). So "party i evaluated
//! honestly" is a statement whose witness the verifiers jointly hold.
//!
//! The reduction: draw one random field element per transcript bit
//! (expanded from a joint coin fixed AFTER the transcript; the coin is
//! opened PRSS randomness, and the prover is missing one of its three
//! streams). The lambda-weighted sum of all gate errors is zero iff
//! every gate is correct, except with probability 2^-64, and it
//! rearranges into IP(u, v) = tau_L + tau_R: u known to the left
//! verifier, v to the right, both to the prover, targets held locally.
//!
//! The proof (a fully linear IOP): per round, chunk the vectors into
//! blocks of 8, interpolate each block, and let h be the sum of the
//! blockwise products f_l * g_l. The prover sends h's evaluations
//! additively split between the verifiers, so no proof message alone
//! reveals anything. The verifiers check sum_j h(e_j) against the
//! target by exchanging residuals (masked by the split), then a fresh
//! joint coin rho folds the claim eightfold: u' = f(rho), v' = g(rho),
//! target' = h(rho). A cheating prover who fakes h to survive the sum
//! check has committed to a wrong polynomial, which diverges from the
//! true one at a random rho except with probability deg/(2^64 - 17);
//! the falsehood is preserved down to the base case, where the
//! verifiers compute f(rho*), g(rho*) FROM THEIR OWN DATA, blinded
//! uniform by one prover-chosen random coordinate, open them, and check
//! the product against the opened h(rho*). Overall soundness is
//! roughly 2^-50 per verified batch; state it, don't round it.
//!
//! Ordering invariant (the eprint 2026/234 lesson): verification runs
//! at the end of every circuit evaluation, inside `eval_circuit`,
//! before control returns to anyone who could open a value derived
//! from it. Openings themselves are double-verified: each party
//! receives its missing component from both of its holders.

use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256 as HashFn};

use crate::bristol::{Circuit, Gate};
use crate::engine::{local_gate, PartyBackend, PartyTape, Schedule};
use crate::gf64::{lagrange_at, Gf64};
use crate::net::PartyNet;
use crate::rep3::{PairRand, PartyKeys, ZeroShare};

const B: usize = 8;
const NPTS: usize = 17; // evaluation points 1..=17; data points are 1..=8

fn pts(n: usize) -> Vec<Gf64> {
    (1..=n as u64).map(Gf64).collect()
}

#[derive(Default)]
struct Transcript {
    x0: Vec<u64>,
    x1: Vec<u64>,
    y0: Vec<u64>,
    y1: Vec<u64>,
    f_prev: Vec<u64>,
    f_own: Vec<u64>,
    r_out: Vec<u64>,
    r_in: Vec<u64>,
}

impl Transcript {
    fn clear(&mut self) {
        *self = Transcript::default();
    }
}

pub struct DzkpParty {
    party: usize,
    zero: ZeroShare,
    coin: PairRand,
    prng: ChaCha12Rng,
    t: Transcript,
}

impl DzkpParty {
    pub fn new(party: usize, keys: &PartyKeys) -> Self {
        let mut h = HashFn::new();
        h.update(b"dzkp-prover-rng");
        h.update(keys.own);
        DzkpParty {
            party,
            zero: ZeroShare::new(keys),
            coin: PairRand::new(keys, 3),
            prng: ChaCha12Rng::from_seed(h.finalize().into()),
            t: Transcript::default(),
        }
    }

    /// Joint public coin words: opened PRSS randomness, each party
    /// receiving its missing component from BOTH holders. Unpredictable
    /// to any single party until opened, and unforgeable by one.
    fn coin_words(&mut self, net: &mut PartyNet, n: usize) -> Result<Vec<u64>, String> {
        let pairs: Vec<(u64, u64)> = (0..n).map(|_| self.coin.next()).collect();
        open_double(net, &pairs)
    }

    fn coin_field(&mut self, net: &mut PartyNet, forbidden: &[Gf64]) -> Result<Gf64, String> {
        loop {
            let w = Gf64(self.coin_words(net, 1)?[0]);
            if !forbidden.contains(&w) {
                return Ok(w);
            }
        }
    }

    /// Verify the recorded transcript: three proof instances, each
    /// party once prover, once left verifier, once right verifier.
    fn verify(&mut self, net: &mut PartyNet) -> Result<(), String> {
        if self.t.x0.is_empty() {
            return Ok(());
        }
        let seed_words = self.coin_words(net, 4)?;
        for prover in 0..3 {
            self.run_instance(net, prover, &seed_words)?;
        }
        self.t.clear();
        Ok(())
    }

    fn run_instance(
        &mut self,
        net: &mut PartyNet,
        prover: usize,
        seed_words: &[u64],
    ) -> Result<(), String> {
        let words = self.t.x0.len();
        let bits = words * 64;
        let lambda = expand_lambda(seed_words, prover, bits);

        // Roles: V_L = prover-1 holds u and tau_L; V_R = prover+1 holds
        // v and tau_R; the prover holds both vectors and no target.
        let me = self.party;
        let is_p = me == prover;
        let is_vl = me == (prover + 2) % 3;
        let is_vr = me == (prover + 1) % 3;

        let bit = |col: &Vec<u64>, g: usize| (col[g / 64] >> (g % 64)) & 1 == 1;
        let mut u: Option<Vec<Gf64>> = None;
        let mut v: Option<Vec<Gf64>> = None;
        let mut tau = Gf64::ZERO;
        if is_p || is_vl {
            // u = (lambda_g * x_comp, lambda_g * y_comp): the prover's
            // own components are the left verifier's second components.
            let (xc, yc) = if is_p { (&self.t.x0, &self.t.y0) } else { (&self.t.x1, &self.t.y1) };
            let mut vec = Vec::with_capacity(2 * bits);
            for g in 0..bits {
                vec.push(if bit(xc, g) { lambda[g] } else { Gf64::ZERO });
                vec.push(if bit(yc, g) { lambda[g] } else { Gf64::ZERO });
            }
            u = Some(vec);
        }
        if is_p || is_vr {
            let (xc, yc) = if is_p { (&self.t.x1, &self.t.y1) } else { (&self.t.x0, &self.t.y0) };
            let mut vec = Vec::with_capacity(2 * bits);
            for g in 0..bits {
                vec.push(if bit(yc, g) { Gf64::ONE } else { Gf64::ZERO });
                vec.push(if bit(xc, g) { Gf64::ONE } else { Gf64::ZERO });
            }
            v = Some(vec);
        }
        if is_vl {
            for g in 0..bits {
                let local = bit(&self.t.r_in, g)
                    ^ (bit(&self.t.x1, g) & bit(&self.t.y1, g))
                    ^ bit(&self.t.f_own, g);
                if local {
                    tau = tau.add(lambda[g]);
                }
            }
        }
        if is_vr {
            for g in 0..bits {
                if bit(&self.t.f_prev, g) {
                    tau = tau.add(lambda[g]);
                }
            }
        }

        let all_pts = pts(NPTS);
        let data_pts = &all_pts[..B];
        // Extension basis: evaluate a block polynomial (defined by its
        // values at points 1..8) at points 9..17.
        let ext: Vec<Vec<Gf64>> =
            (B..NPTS).map(|p| lagrange_at(data_pts, all_pts[p])).collect();

        let mut len = 2 * bits;
        while len > B {
            let blocks = len.div_ceil(B);
            if is_p {
                let (uu, vv) = (u.as_ref().unwrap(), v.as_ref().unwrap());
                let mut hev = [Gf64::ZERO; NPTS];
                let entry = |w: &Vec<Gf64>, i: usize| {
                    if i < len { w[i] } else { Gf64::ZERO }
                };
                for l in 0..blocks {
                    let mut fv = [Gf64::ZERO; NPTS];
                    let mut gv = [Gf64::ZERO; NPTS];
                    for j in 0..B {
                        fv[j] = entry(uu, l * B + j);
                        gv[j] = entry(vv, l * B + j);
                    }
                    for p in B..NPTS {
                        for j in 0..B {
                            fv[p] = fv[p].add(ext[p - B][j].mul(fv[j]));
                            gv[p] = gv[p].add(ext[p - B][j].mul(gv[j]));
                        }
                    }
                    for p in 0..NPTS {
                        hev[p] = hev[p].add(fv[p].mul(gv[p]));
                    }
                }
                let (pi_l, pi_r) = self.split(&hev);
                net.send_raw(true, &pi_l)?;
                net.send_raw(false, &pi_r)?;
            }
            let pi: Option<Vec<Gf64>> = if is_vl {
                Some(recv_field(net, true, NPTS)?)
            } else if is_vr {
                Some(recv_field(net, false, NPTS)?)
            } else {
                None
            };

            // Consistency: sum of h over the data points equals the
            // target. Residuals are uniform, masked by the proof split.
            if let Some(pi) = &pi {
                let mut delta = tau;
                for p in pi.iter().take(B) {
                    delta = delta.add(*p);
                }
                // V_L reaches V_R over its prev wire; V_R's replies come
                // back in on that same prev wire (V_R sends on its next).
                let send_prev = is_vl;
                net.send_raw(send_prev, &[delta.0])?;
                let other = Gf64(net.recv_raw(!send_prev)?[0]);
                if delta.add(other) != Gf64::ZERO {
                    return Err("abort: transcript proof sum check".into());
                }
            }

            let rho = self.coin_field(net, &all_pts)?;
            let fold_basis = lagrange_at(data_pts, rho);
            let fold = |w: &Vec<Gf64>| -> Vec<Gf64> {
                (0..blocks)
                    .map(|l| {
                        let mut acc = Gf64::ZERO;
                        for j in 0..B {
                            let i = l * B + j;
                            if i < len {
                                acc = acc.add(fold_basis[j].mul(w[i]));
                            }
                        }
                        acc
                    })
                    .collect()
            };
            if let Some(uu) = &u {
                u = Some(fold(uu));
            }
            if let Some(vv) = &v {
                v = Some(fold(vv));
            }
            if let Some(pi) = &pi {
                let hb = lagrange_at(&all_pts, rho);
                tau = pi.iter().zip(&hb).fold(Gf64::ZERO, |a, (p, b)| a.add(p.mul(*b)));
            }
            len = blocks;
        }

        // Base case: one prover-chosen random coordinate per vector
        // makes the final evaluations uniform, so they can be opened.
        let n = len;
        let npts_base = n + 1;
        let hpts = 2 * npts_base - 1;
        let base_pts = pts(npts_base);
        let h_pts = pts(hpts);
        if is_p {
            let (ustar, vstar) = (Gf64(self.prng.next_u64()), Gf64(self.prng.next_u64()));
            let prod = ustar.mul(vstar);
            let p_l = Gf64(self.prng.next_u64());
            let p_r = prod.add(p_l);
            net.send_raw(true, &[ustar.0, p_l.0])?;
            net.send_raw(false, &[vstar.0, p_r.0])?;
            let mut uu = u.take().unwrap();
            let mut vv = v.take().unwrap();
            uu.push(ustar);
            vv.push(vstar);
            let ext_base: Vec<Vec<Gf64>> =
                (npts_base..hpts).map(|p| lagrange_at(&base_pts, h_pts[p])).collect();
            let mut fv = vec![Gf64::ZERO; hpts];
            let mut gv = vec![Gf64::ZERO; hpts];
            for j in 0..npts_base {
                fv[j] = uu[j];
                gv[j] = vv[j];
            }
            for p in npts_base..hpts {
                for j in 0..npts_base {
                    fv[p] = fv[p].add(ext_base[p - npts_base][j].mul(fv[j]));
                    gv[p] = gv[p].add(ext_base[p - npts_base][j].mul(gv[j]));
                }
            }
            let hev: Vec<Gf64> = (0..hpts).map(|p| fv[p].mul(gv[p])).collect();
            let (pi_l, pi_r) = self.split(&hev);
            net.send_raw(true, &pi_l)?;
            net.send_raw(false, &pi_r)?;
            let _ = self.coin_field(net, &h_pts)?; // stay in coin lockstep
            return Ok(());
        }

        let from_next = is_vl;
        let blind = recv_field(net, from_next, 2)?;
        let (star, p_share) = (blind[0], blind[1]);
        let pi = recv_field(net, from_next, hpts)?;
        let mut vec = if is_vl { u.take().unwrap() } else { v.take().unwrap() };
        vec.push(star);

        let mut delta = tau.add(p_share);
        for p in pi.iter().take(npts_base) {
            delta = delta.add(*p);
        }
        let send_prev = is_vl; // V_L talks to V_R over its prev wire
        net.send_raw(send_prev, &[delta.0])?;
        let other = Gf64(net.recv_raw(!send_prev)?[0]);
        if delta.add(other) != Gf64::ZERO {
            return Err("abort: transcript proof base sum check".into());
        }

        let rho = self.coin_field(net, &h_pts)?;
        let eval_basis = lagrange_at(&base_pts, rho);
        let mine =
            vec.iter().zip(&eval_basis).fold(Gf64::ZERO, |a, (w, b)| a.add(w.mul(*b)));
        let h_basis = lagrange_at(&h_pts, rho);
        let h_share = pi.iter().zip(&h_basis).fold(Gf64::ZERO, |a, (p, b)| a.add(p.mul(*b)));
        net.send_raw(send_prev, &[mine.0, h_share.0])?;
        let theirs = recv_field(net, !send_prev, 2)?;
        let (other_eval, other_h) = (theirs[0], theirs[1]);
        if mine.mul(other_eval) != h_share.add(other_h) {
            return Err("abort: transcript proof product check".into());
        }
        Ok(())
    }

    fn split(&mut self, vals: &[Gf64]) -> (Vec<u64>, Vec<u64>) {
        let l: Vec<u64> = vals.iter().map(|_| self.prng.next_u64()).collect();
        let r: Vec<u64> = vals.iter().zip(&l).map(|(v, m)| v.0 ^ m).collect();
        (l, r)
    }
}

/// Three dZKP parties on in-process wires, one thread each: the same
/// `Backend` face the other sessions wear.
pub struct DzkpSession {
    words: usize,
    parties: Option<[DzkpParty; 3]>,
    pub sent_bytes: [u64; 3],
    pub rounds: u64,
}

impl DzkpSession {
    pub fn new(keys: &crate::rep3::KeySet, words: usize) -> Self {
        let parties = [
            DzkpParty::new(0, &keys.party(0)),
            DzkpParty::new(1, &keys.party(1)),
            DzkpParty::new(2, &keys.party(2)),
        ];
        DzkpSession { words, parties: Some(parties), sent_bytes: [0; 3], rounds: 0 }
    }

    pub fn cheating_eval(
        &mut self,
        circuit: &Circuit,
        sched: &Schedule,
        tapes: &mut [PartyTape; 3],
        cheat_bit: u64,
    ) -> Result<(), String> {
        self.eval_inner(circuit, sched, tapes, Some(cheat_bit))
    }

    fn eval_inner(
        &mut self,
        circuit: &Circuit,
        sched: &Schedule,
        tapes: &mut [PartyTape; 3],
        cheat_bit: Option<u64>,
    ) -> Result<(), String> {
        let mut parties = self.parties.take().expect("state present");
        let [p0, p1, p2] = &mut parties;
        let [t0, t1, t2] = tapes;
        let mut states = [(p0, t0), (p1, t1), (p2, t2)];
        let result = crate::engine::run_parties(&mut states, cheat_bit, |_, (dp, tape), net| {
            dp.eval_circuit(circuit, sched, tape, net)
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

impl crate::engine::Backend for DzkpSession {
    fn words(&self) -> usize {
        self.words
    }

    fn eval(
        &mut self,
        circuit: &Circuit,
        sched: &Schedule,
        tapes: &mut [PartyTape; 3],
    ) -> Result<(), String> {
        self.eval_inner(circuit, sched, tapes, None)
    }
}

fn recv_field(net: &mut PartyNet, from_next: bool, n: usize) -> Result<Vec<Gf64>, String> {
    let w = net.recv_raw(from_next)?;
    if w.len() != n {
        return Err("abort: framing".into());
    }
    Ok(w.into_iter().map(Gf64).collect())
}

/// Open replicated words with each party receiving its missing
/// component from BOTH of its holders: self-verifying, no hash round.
fn open_double(net: &mut PartyNet, shares: &[(u64, u64)]) -> Result<Vec<u64>, String> {
    let seconds: Vec<u64> = shares.iter().map(|s| s.1).collect();
    let firsts: Vec<u64> = shares.iter().map(|s| s.0).collect();
    net.send_raw(true, &seconds)?;
    net.send_raw(false, &firsts)?;
    net.rounds += 1;
    let a = net.recv_raw(true)?;
    let b = net.recv_raw(false)?;
    if a.len() != shares.len() || b.len() != shares.len() {
        return Err("abort: framing".into());
    }
    let mut out = Vec::with_capacity(shares.len());
    for (i, s) in shares.iter().enumerate() {
        if a[i] != b[i] {
            return Err("abort: opened component differs between its holders".into());
        }
        out.push(s.0 ^ s.1 ^ a[i]);
    }
    Ok(out)
}

fn expand_lambda(seed_words: &[u64], prover: usize, bits: usize) -> Vec<Gf64> {
    let mut h = HashFn::new();
    h.update(b"dzkp-lambda");
    for w in seed_words {
        h.update(w.to_le_bytes());
    }
    h.update([prover as u8]);
    let mut rng = ChaCha12Rng::from_seed(h.finalize().into());
    (0..bits).map(|_| Gf64(rng.next_u64())).collect()
}

impl PartyBackend for DzkpParty {
    fn party(&self) -> usize {
        self.party
    }

    /// Semi-honest evaluation with a recorded transcript, verified
    /// before returning: nothing derived from this circuit can be
    /// opened until every party's messages have been proven correct.
    fn eval_circuit(
        &mut self,
        c: &Circuit,
        s: &Schedule,
        t: &mut PartyTape,
        net: &mut PartyNet,
    ) -> Result<(), String> {
        let words = t.words;
        for phase in 0..=s.depth {
            for &gi in &s.locals[phase] {
                local_gate(self.party, c.gates[gi], t);
            }
            let ands = &s.ands[phase];
            if ands.is_empty() {
                continue;
            }
            let mut out = Vec::with_capacity(ands.len() * words);
            for &gi in ands {
                let Gate::And(x, y, o) = c.gates[gi] else { unreachable!() };
                let (xw, yw, ow) =
                    (x as usize * words, y as usize * words, o as usize * words);
                for w in 0..words {
                    let (xi, xj) = (t.c[0][xw + w], t.c[1][xw + w]);
                    let (yi, yj) = (t.c[0][yw + w], t.c[1][yw + w]);
                    let (fp, fo) = self.zero.next_halves();
                    let r = (xi & yi) ^ (xi & yj) ^ (xj & yi) ^ fp ^ fo;
                    self.t.x0.push(xi);
                    self.t.x1.push(xj);
                    self.t.y0.push(yi);
                    self.t.y1.push(yj);
                    self.t.f_prev.push(fp);
                    self.t.f_own.push(fo);
                    self.t.r_out.push(r);
                    t.c[0][ow + w] = r;
                    out.push(r);
                }
            }
            let inb = net.reshare_prev(&out)?;
            self.t.r_in.extend_from_slice(&inb);
            for (k, &gi) in ands.iter().enumerate() {
                let Gate::And(_, _, o) = c.gates[gi] else { unreachable!() };
                let ow = o as usize * words;
                for w in 0..words {
                    t.c[1][ow + w] = inb[k * words + w];
                }
            }
        }
        self.verify(net)
    }

    fn open_words(
        &mut self,
        net: &mut PartyNet,
        shares: &[(u64, u64)],
    ) -> Result<Vec<u64>, String> {
        assert!(self.t.x0.is_empty(), "opening with an unverified transcript pending");
        open_double(net, shares)
    }
}
