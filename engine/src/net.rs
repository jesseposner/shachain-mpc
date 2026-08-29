//! The wires between parties.
//!
//! Each party holds a duplex link to its next and previous neighbor and
//! never sees the third link. The in-process transport is a pair of
//! channels per link; a TCP transport slots in behind the same `Wire`
//! trait for the multi-process deployment (M3b). A closed wire is an
//! abort, which is how one party's abort cascades to the others.
//!
//! `cheat_bit` models a corrupt party 1 with exactly the power of a bad
//! sender: bit n of everything the party ever puts on its wires, in send
//! order, arrives flipped, while the party's own state stays consistent.

use std::sync::mpsc::{channel, Receiver, Sender};

pub trait Wire: Send {
    fn send(&mut self, bytes: Vec<u8>) -> Result<(), String>;
    fn recv(&mut self) -> Result<Vec<u8>, String>;
}

pub struct ChannelWire {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl Wire for ChannelWire {
    fn send(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        self.tx.send(bytes).map_err(|_| "abort: peer is gone".to_string())
    }

    fn recv(&mut self) -> Result<Vec<u8>, String> {
        self.rx.recv().map_err(|_| "abort: peer is gone".to_string())
    }
}

/// One party's endpoints plus its traffic accounting. A round, for the
/// counters, is one batched exchange this party takes part in.
pub struct PartyNet {
    pub prev: Box<dyn Wire>,
    pub next: Box<dyn Wire>,
    pub sent_bytes: u64,
    pub rounds: u64,
    pub cheat_bit: Option<u64>,
}

impl PartyNet {
    fn corrupt(&mut self, bytes: &mut [u8]) {
        if let Some(bit) = self.cheat_bit {
            let offset = self.sent_bytes * 8;
            let span = bytes.len() as u64 * 8;
            if bit >= offset && bit < offset + span {
                let local = bit - offset;
                bytes[(local / 8) as usize] ^= 1 << (local % 8);
            }
        }
    }

    fn send(&mut self, to_prev: bool, words: &[u64]) -> Result<(), String> {
        let mut bytes = Vec::with_capacity(words.len() * 8);
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        self.corrupt(&mut bytes);
        self.sent_bytes += bytes.len() as u64;
        if to_prev { self.prev.send(bytes) } else { self.next.send(bytes) }
    }

    fn recv(&mut self, from_next: bool) -> Result<Vec<u64>, String> {
        let bytes = if from_next { self.next.recv()? } else { self.prev.recv()? };
        if bytes.len() % 8 != 0 {
            return Err("abort: framing".into());
        }
        Ok(bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
    }

    /// The resharing round every protocol step here uses: send a batch to
    /// the previous party, receive the same shape from the next.
    pub fn reshare_prev(&mut self, out: &[u64]) -> Result<Vec<u64>, String> {
        self.send(true, out)?;
        self.rounds += 1;
        let inb = self.recv(true)?;
        if inb.len() != out.len() {
            return Err("abort: framing".into());
        }
        Ok(inb)
    }

    /// Send the same message both ways and collect both neighbors'.
    /// Used for the constant-size hash comparisons.
    pub fn exchange_both(&mut self, msg: &[u64]) -> Result<(Vec<u64>, Vec<u64>), String> {
        self.send(true, msg)?;
        self.send(false, msg)?;
        self.rounds += 1;
        let from_prev = self.recv(false)?;
        let from_next = self.recv(true)?;
        Ok((from_prev, from_next))
    }
}

/// Three in-process parties wired in a ring.
pub fn trio() -> [PartyNet; 3] {
    // links[i] connects party i (as "next" side) with party i+1 (as
    // "prev" side): party i's next wire talks to party i+1's prev wire.
    let mut links = Vec::new();
    for _ in 0..3 {
        let (atx, arx) = channel();
        let (btx, brx) = channel();
        links.push((
            ChannelWire { tx: atx, rx: brx }, // held by party i as `next`
            ChannelWire { tx: btx, rx: arx }, // held by party i+1 as `prev`
        ));
    }
    let (n2, p0) = links.pop().unwrap();
    let (n1, p2) = links.pop().unwrap();
    let (n0, p1) = links.pop().unwrap();
    [
        PartyNet { prev: Box::new(p0), next: Box::new(n0), sent_bytes: 0, rounds: 0, cheat_bit: None },
        PartyNet { prev: Box::new(p1), next: Box::new(n1), sent_bytes: 0, rounds: 0, cheat_bit: None },
        PartyNet { prev: Box::new(p2), next: Box::new(n2), sent_bytes: 0, rounds: 0, cheat_bit: None },
    ]
}
