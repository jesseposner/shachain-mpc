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

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

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

/// Length-prefixed frames over one TCP stream, with all writes on a
/// dedicated thread. The protocol's invariant is that sends never
/// block: in a refill round every party sends a multi-megabyte batch to
/// its previous neighbor before anyone reads, and blocking writes
/// deadlock the ring the moment the socket buffers fill (found the hard
/// way; the unbounded in-process channels could never show it).
/// TCP_NODELAY is set at connect time: rounds are exactly the small,
/// latency-critical writes Nagle's algorithm would sit on.
pub struct TcpWire {
    tx: Sender<Vec<u8>>,
    reader: TcpStream,
}

impl TcpWire {
    fn new(stream: TcpStream) -> Result<Self, String> {
        let mut writer = stream.try_clone().map_err(|e| format!("clone: {e}"))?;
        let (tx, rx) = channel::<Vec<u8>>();
        std::thread::spawn(move || {
            // Exits when the sender drops (wire dropped: abort or done)
            // or the peer is gone; either way the stream clone closes.
            while let Ok(bytes) = rx.recv() {
                let len = (bytes.len() as u32).to_le_bytes();
                if writer.write_all(&len).and_then(|()| writer.write_all(&bytes)).is_err() {
                    break;
                }
            }
        });
        Ok(TcpWire { tx, reader: stream })
    }
}

impl Wire for TcpWire {
    fn send(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        self.tx.send(bytes).map_err(|_| "abort: peer is gone".to_string())
    }

    fn recv(&mut self) -> Result<Vec<u8>, String> {
        let mut len = [0u8; 4];
        self.reader.read_exact(&mut len).map_err(|e| format!("abort: wire: {e}"))?;
        let n = u32::from_le_bytes(len) as usize;
        if n > 1 << 30 {
            return Err("abort: framing".into());
        }
        let mut bytes = vec![0u8; n];
        self.reader.read_exact(&mut bytes).map_err(|e| format!("abort: wire: {e}"))?;
        Ok(bytes)
    }
}

/// Join the ring as one party over TCP: bind our own address, dial the
/// next party, accept the previous one. Binding before dialing means
/// start order does not matter; the dial retries while peers come up.
pub fn tcp_ring(party: usize, addrs: &[String; 3]) -> Result<PartyNet, String> {
    let listener = TcpListener::bind(&addrs[party])
        .map_err(|e| format!("bind {}: {e}", addrs[party]))?;
    let next_addr = &addrs[(party + 1) % 3];
    let deadline = Instant::now() + Duration::from_secs(10);
    let next = loop {
        match TcpStream::connect(next_addr) {
            Ok(s) => break s,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("connect {next_addr}: {e}")),
        }
    };
    let (prev, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
    for s in [&next, &prev] {
        s.set_nodelay(true).map_err(|e| format!("nodelay: {e}"))?;
    }
    Ok(PartyNet {
        prev: Box::new(TcpWire::new(prev)?),
        next: Box::new(TcpWire::new(next)?),
        sent_bytes: 0,
        rounds: 0,
        cheat_bit: None,
    })
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

    /// One-off directed send/recv, for handing final share components to
    /// a designated party (output reconstruction). Not a counted round.
    pub fn send_raw(&mut self, to_prev: bool, words: &[u64]) -> Result<(), String> {
        self.send(to_prev, words)
    }

    pub fn recv_raw(&mut self, from_next: bool) -> Result<Vec<u64>, String> {
        self.recv(from_next)
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
