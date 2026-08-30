//! Party-separated evaluation of a Bristol circuit under Rep3.
//!
//! Each party runs its own thread over its own state, its two PRF keys,
//! and its two wires; nothing here reads another party's memory. Gates
//! are pre-grouped into a schedule by AND depth, so evaluation costs one
//! batched message round per level, which is the number a wide-area
//! deployment pays for: the SHA-256 circuit's measured round count is
//! its AND depth, directly comparable to the MP-SPDZ figures in
//! `results/`.

use std::thread;

use crate::bristol::{Circuit, Gate};
use crate::net::{trio, PartyNet};
use crate::rep3::{KeySet, ZeroShare};

/// Local gates and AND gates grouped by the round in which they run.
/// Phase r: apply the local gates whose inputs exist after round r, then
/// exchange one message carrying every AND of round r.
pub struct Schedule {
    pub locals: Vec<Vec<usize>>,
    pub ands: Vec<Vec<usize>>,
    pub depth: usize,
}

impl Schedule {
    pub fn new(c: &Circuit) -> Self {
        let mut avail = vec![0usize; c.n_wires];
        let mut depth = 0;
        let mut locals: Vec<Vec<usize>> = Vec::new();
        let mut ands: Vec<Vec<usize>> = Vec::new();
        let slot = |v: &mut Vec<Vec<usize>>, r: usize, g: usize| {
            if v.len() <= r {
                v.resize(r + 1, Vec::new());
            }
            v[r].push(g);
        };
        for (gi, gate) in c.gates.iter().enumerate() {
            match *gate {
                Gate::Xor(x, y, o) => {
                    let r = avail[x as usize].max(avail[y as usize]);
                    slot(&mut locals, r, gi);
                    avail[o as usize] = r;
                }
                Gate::Inv(x, o) => {
                    let r = avail[x as usize];
                    slot(&mut locals, r, gi);
                    avail[o as usize] = r;
                }
                Gate::And(x, y, o) => {
                    let r = avail[x as usize].max(avail[y as usize]);
                    slot(&mut locals, r, gi);
                    avail[o as usize] = r + 1;
                    depth = depth.max(r + 1);
                }
            }
        }
        locals.resize(depth + 1, Vec::new());
        ands.resize(depth + 1, Vec::new());
        // Split the per-round gate lists: ANDs move to their own lanes,
        // keeping original order within a round.
        for r in 0..=depth {
            let (l, a) = std::mem::take(&mut locals[r])
                .into_iter()
                .partition(|&gi| !matches!(c.gates[gi], Gate::And(..)));
            locals[r] = l;
            ands[r] = a;
        }
        Schedule { locals, ands, depth }
    }
}

/// One party's wire storage: `c[component][wire * words + w]`.
/// Component 0 of party i is x_i, component 1 is x_{i+1}.
pub struct PartyTape {
    pub words: usize,
    pub c: [Vec<u64>; 2],
}

impl PartyTape {
    pub fn new(n_wires: usize, words: usize) -> Self {
        PartyTape { words, c: [vec![0u64; n_wires * words], vec![0u64; n_wires * words]] }
    }

    /// Install a public constant: component x0 carries the value, held
    /// by party 0 (first component) and party 2 (second).
    pub fn set_public(&mut self, party: usize, wire: usize, w: usize, value: u64) {
        let i = wire * self.words + w;
        self.c[0][i] = 0;
        self.c[1][i] = 0;
        if party == 0 {
            self.c[0][i] = value;
        }
        if party == 2 {
            self.c[1][i] = value;
        }
    }
}

/// Apply one local gate to one party's tape.
pub fn local_gate(party: usize, gate: Gate, t: &mut PartyTape) {
    let words = t.words;
    match gate {
        Gate::Xor(x, y, o) => {
            let (xw, yw, ow) = (x as usize * words, y as usize * words, o as usize * words);
            for comp in 0..2 {
                for w in 0..words {
                    let tape = &mut t.c[comp];
                    tape[ow + w] = tape[xw + w] ^ tape[yw + w];
                }
            }
        }
        Gate::Inv(x, o) => {
            let (xw, ow) = (x as usize * words, o as usize * words);
            for comp in 0..2 {
                for w in 0..words {
                    let tape = &mut t.c[comp];
                    tape[ow + w] = tape[xw + w];
                }
            }
            // NOT is a public-constant XOR into component x0.
            for w in 0..words {
                if party == 0 {
                    t.c[0][ow + w] ^= !0;
                }
                if party == 2 {
                    t.c[1][ow + w] ^= !0;
                }
            }
        }
        Gate::And(..) => unreachable!("AND gates are not local"),
    }
}

/// One party's side of a protocol: the interface a standalone process
/// runs, and the same code the in-process sessions thread together.
pub trait PartyBackend {
    fn party(&self) -> usize;
    fn eval_circuit(
        &mut self,
        c: &Circuit,
        s: &Schedule,
        t: &mut PartyTape,
        net: &mut PartyNet,
    ) -> Result<(), String>;

    /// Open shared words publicly. The malicious backend logs and
    /// view-checks the opening; the semi-honest one just reconstructs.
    fn open_words(
        &mut self,
        net: &mut PartyNet,
        shares: &[(u64, u64)],
    ) -> Result<Vec<u64>, String>;
}

/// One semi-honest party.
pub struct SemiParty {
    party: usize,
    zero: ZeroShare,
}

impl SemiParty {
    pub fn new(party: usize, keys: &crate::rep3::PartyKeys) -> Self {
        SemiParty { party, zero: ZeroShare::new(keys) }
    }
}

impl PartyBackend for SemiParty {
    fn party(&self) -> usize {
        self.party
    }

    /// Per level, compute the randomized local products, reshare toward
    /// the previous party, and take the next party's batch as the
    /// second components.
    fn eval_circuit(
        &mut self,
        c: &Circuit,
        s: &Schedule,
        t: &mut PartyTape,
        net: &mut PartyNet,
    ) -> Result<(), String> {
        let (party, zero) = (self.party, &mut self.zero);
        let words = t.words;
        for phase in 0..=s.depth {
            for &gi in &s.locals[phase] {
                local_gate(party, c.gates[gi], t);
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
                    let r = (xi & yi) ^ (xi & yj) ^ (xj & yi) ^ zero.next();
                    t.c[0][ow + w] = r;
                    out.push(r);
                }
            }
            let inb = net.reshare_prev(&out)?;
            for (k, &gi) in ands.iter().enumerate() {
                let Gate::And(_, _, o) = c.gates[gi] else { unreachable!() };
                let ow = o as usize * words;
                for w in 0..words {
                    t.c[1][ow + w] = inb[k * words + w];
                }
            }
        }
        Ok(())
    }

    fn open_words(
        &mut self,
        net: &mut PartyNet,
        shares: &[(u64, u64)],
    ) -> Result<Vec<u64>, String> {
        let out: Vec<u64> = shares.iter().map(|s| s.1).collect();
        let inb = net.reshare_prev(&out)?;
        Ok(shares.iter().zip(&inb).map(|(s, &recv)| s.0 ^ s.1 ^ recv).collect())
    }
}

/// A circuit evaluation backend over per-party tapes. `Session` is the
/// semi-honest floor; `mal::MalSession` aborts on any detected cheat.
pub trait Backend {
    fn words(&self) -> usize;
    fn eval(
        &mut self,
        circuit: &Circuit,
        sched: &Schedule,
        tapes: &mut [PartyTape; 3],
    ) -> Result<(), String>;
}

/// Three semi-honest parties on in-process wires, one thread each.
pub struct Session {
    words: usize,
    parties: Option<[SemiParty; 3]>,
    pub sent_bytes: [u64; 3],
    pub rounds: u64,
}

impl Session {
    pub fn new(keys: &KeySet, words: usize) -> Self {
        let parties = [
            SemiParty::new(0, &keys.party(0)),
            SemiParty::new(1, &keys.party(1)),
            SemiParty::new(2, &keys.party(2)),
        ];
        Session { words, parties: Some(parties), sent_bytes: [0; 3], rounds: 0 }
    }
}

/// Run one closure per party on its own thread, with its own net, and
/// merge the traffic counters. Any party's abort is the session's.
pub fn run_parties<S: Send, F>(
    states: &mut [S; 3],
    cheat_bit: Option<u64>,
    f: F,
) -> Result<([u64; 3], u64), String>
where
    F: Fn(usize, &mut S, &mut PartyNet) -> Result<(), String> + Sync,
{
    let mut nets = trio();
    nets[1].cheat_bit = cheat_bit;
    let [s0, s1, s2] = states;
    let [n0, n1, n2] = nets;
    let fr = &f;
    // Each net moves into its thread: a party that returns (abort
    // included) drops its wires, so the other parties' receives fail
    // instead of waiting forever, and the abort cascades.
    let run = |party: usize, state: &mut S, mut net: PartyNet| {
        let r = fr(party, state, &mut net);
        (r, net.sent_bytes, net.rounds)
    };
    let (r0, r1, r2) = thread::scope(|scope| {
        let h0 = scope.spawn(move || run(0, s0, n0));
        let h1 = scope.spawn(move || run(1, s1, n1));
        let h2 = scope.spawn(move || run(2, s2, n2));
        (h0.join().unwrap(), h1.join().unwrap(), h2.join().unwrap())
    });
    r0.0?;
    r1.0?;
    r2.0?;
    Ok(([r0.1, r1.1, r2.1], r0.2))
}

impl Backend for Session {
    fn words(&self) -> usize {
        self.words
    }

    fn eval(
        &mut self,
        circuit: &Circuit,
        sched: &Schedule,
        tapes: &mut [PartyTape; 3],
    ) -> Result<(), String> {
        let mut parties = self.parties.take().expect("session state present");
        let [p0, p1, p2] = &mut parties;
        let [t0, t1, t2] = tapes;
        let mut states = [(p0, t0), (p1, t1), (p2, t2)];
        // Split the borrow: run_parties needs one mutable state per party.
        let result = run_parties(&mut states, None, |_, (party, tape), net| {
            party.eval_circuit(circuit, sched, tape, net)
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
