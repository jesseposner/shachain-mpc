//! Long-running Lightning counterparty for the PoC driver.
//!
//! Reads JSONL commands on stdin, answers one JSON line each:
//!   {"cmd":"point","idx":N,"point":"02..hex33"}   store the per-commitment point
//!   {"cmd":"secret","idx":N,"secret":"hex32"}     provide_secret to LDK's
//!       shachain store (BOLT insert_secret checks) AND verify the secret
//!       matches the point published earlier for that index.
//!
//! Replies {"ok":true} or {"ok":false,"err":"..."}. Any state that LDK or the
//! point check rejects produces ok:false, which the driver treats as fatal.

use lightning::ln::chan_utils::CounterpartyCommitmentSecrets;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::io::{BufRead, Write};

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    // minimal JSON field extraction; driver emits flat objects
    let pat = format!("\"{}\":", key);
    let start = line.find(&pat)? + pat.len();
    let rest = line[start..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next()
    } else {
        rest.split(|c: char| c == ',' || c == '}').next().map(str::trim)
    }
}

fn main() {
    let secp = Secp256k1::new();
    let mut store = CounterpartyCommitmentSecrets::new();
    let mut points: HashMap<u64, Vec<u8>> = HashMap::new();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line.expect("stdin read");
        if line.trim().is_empty() {
            continue;
        }
        let reply = handle(&secp, &mut store, &mut points, &line);
        let msg = match reply {
            Ok(()) => "{\"ok\":true}".to_string(),
            Err(e) => format!("{{\"ok\":false,\"err\":\"{}\"}}", e),
        };
        writeln!(out, "{}", msg).unwrap();
        out.flush().unwrap();
    }
}

fn handle(
    secp: &Secp256k1<secp256k1::All>,
    store: &mut CounterpartyCommitmentSecrets,
    points: &mut HashMap<u64, Vec<u8>>,
    line: &str,
) -> Result<(), String> {
    let cmd = field(line, "cmd").ok_or("missing cmd")?;
    let idx: u64 = field(line, "idx")
        .ok_or("missing idx")?
        .parse()
        .map_err(|_| "bad idx")?;
    match cmd {
        "point" => {
            let hexpt = field(line, "point").ok_or("missing point")?;
            let bytes = hex::decode(hexpt).map_err(|_| "bad point hex")?;
            PublicKey::from_slice(&bytes).map_err(|_| "not a valid point")?;
            points.insert(idx, bytes);
            Ok(())
        }
        "secret" => {
            let hexs = field(line, "secret").ok_or("missing secret")?;
            let bytes = hex::decode(hexs).map_err(|_| "bad secret hex")?;
            let secret: [u8; 32] =
                bytes.as_slice().try_into().map_err(|_| "not 32 bytes")?;
            // 1. BOLT derivation-consistency check, as any peer runs it.
            store
                .provide_secret(idx, secret)
                .map_err(|_| "insert_secret: not a valid shachain")?;
            // 2. The revealed secret must match the earlier point.
            let expected = points.get(&idx).ok_or("no point stored for idx")?;
            let sk = SecretKey::from_slice(&secret)
                .map_err(|_| "secret not a valid scalar")?;
            let pk = PublicKey::from_secret_key(secp, &sk);
            if pk.serialize().as_slice() != expected.as_slice() {
                return Err("secret does not match published point".into());
            }
            Ok(())
        }
        other => Err(format!("unknown cmd {}", other)),
    }
}
