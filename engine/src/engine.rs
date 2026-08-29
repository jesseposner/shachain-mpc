//! Lockstep evaluation of a Bristol circuit under Rep3.
//!
//! The three parties live in one process for M1, but their state is kept
//! in separate per-party arrays and every AND explicitly produces the
//! word each party sends; `sent_bytes` counts exactly that traffic. M3
//! splits this across processes without changing the arithmetic.

use crate::bristol::{Circuit, Gate};
use crate::rep3::{KeySet, ZeroShare};

/// Per-party wire storage: `c[party][component][wire * words + w]`.
/// Component 0 of party i is x_i, component 1 is x_{i+1}.
pub struct Tapes {
    pub words: usize,
    pub c: [[Vec<u64>; 2]; 3],
}

impl Tapes {
    pub fn new(n_wires: usize, words: usize) -> Self {
        let blank = || [vec![0u64; n_wires * words], vec![0u64; n_wires * words]];
        Tapes { words, c: [blank(), blank(), blank()] }
    }

    /// Install a public constant on a wire: x0 carries the value, which
    /// parties 0 and 2 hold.
    pub fn set_public(&mut self, wire: usize, w: usize, value: u64) {
        let i = wire * self.words + w;
        for p in 0..3 {
            self.c[p][0][i] = 0;
            self.c[p][1][i] = 0;
        }
        self.c[0][0][i] = value;
        self.c[2][1][i] = value;
    }
}

/// A circuit evaluation backend. `Session` is the semi-honest floor;
/// `mal::MalSession` runs the same circuits with malicious security and
/// aborts on any detected cheat.
pub trait Backend {
    fn words(&self) -> usize;
    fn eval(&mut self, circuit: &Circuit, t: &mut Tapes) -> Result<(), String>;
}

/// One party's ongoing protocol state plus traffic counters, shared
/// across every circuit evaluated under the same key material.
pub struct Session {
    pub words: usize,
    zero: [ZeroShare; 3],
    pub sent_bytes: [u64; 3],
}

impl Session {
    pub fn new(keys: &KeySet, words: usize) -> Self {
        Session {
            words,
            zero: [ZeroShare::new(keys, 0), ZeroShare::new(keys, 1), ZeroShare::new(keys, 2)],
            sent_bytes: [0; 3],
        }
    }

    fn eval_gates(&mut self, circuit: &Circuit, t: &mut Tapes) {
        assert_eq!(self.words, t.words);
        let words = self.words;
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
                    // NOT is a public-constant XOR into component x0.
                    for w in 0..words {
                        t.c[0][0][ow + w] ^= !0;
                        t.c[2][1][ow + w] ^= !0;
                    }
                }
                Gate::And(x, y, o) => {
                    let (xw, yw, ow) =
                        (x as usize * words, y as usize * words, o as usize * words);
                    for w in 0..words {
                        let mut r = [0u64; 3];
                        for p in 0..3 {
                            let xi = t.c[p][0][xw + w];
                            let xj = t.c[p][1][xw + w];
                            let yi = t.c[p][0][yw + w];
                            let yj = t.c[p][1][yw + w];
                            r[p] = (xi & yi) ^ (xi & yj) ^ (xj & yi) ^ self.zero[p].next();
                        }
                        // Party p sends r_p to party p-1 and keeps it as
                        // its own component; its second component is
                        // r_{p+1}, received from party p+1.
                        for p in 0..3 {
                            t.c[p][0][ow + w] = r[p];
                            t.c[p][1][ow + w] = r[(p + 1) % 3];
                            self.sent_bytes[p] += 8;
                        }
                    }
                }
            }
        }
    }
}

impl Backend for Session {
    fn words(&self) -> usize {
        self.words
    }

    fn eval(&mut self, circuit: &Circuit, t: &mut Tapes) -> Result<(), String> {
        self.eval_gates(circuit, t);
        Ok(())
    }
}
