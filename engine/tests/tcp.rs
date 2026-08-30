//! M3b exit criterion: three real processes over TCP compute the walk,
//! semi-honest and malicious, and party 0's checked reconstruction
//! matches the plaintext reference. The party binary asserts the match
//! itself; the test asserts every process says so and exits cleanly.

use std::net::TcpListener;
use std::process::Command;

fn free_addrs() -> [String; 3] {
    // Bind ephemeral ports to learn free numbers, then release them.
    // Mildly racy, harmless locally.
    let grab = || {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("127.0.0.1:{}", l.local_addr().unwrap().port())
    };
    [grab(), grab(), grab()]
}

fn run_trio(extra: &[&str]) -> Vec<String> {
    let addrs = free_addrs();
    let children: Vec<_> = (0..3)
        .map(|id| {
            let mut args =
                vec![id.to_string(), addrs[0].clone(), addrs[1].clone(), addrs[2].clone()];
            args.extend(extra.iter().map(|s| s.to_string()));
            Command::new(env!("CARGO_BIN_EXE_party"))
                .args(&args)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    children
        .into_iter()
        .map(|c| {
            let out = c.wait_with_output().unwrap();
            assert!(out.status.success(), "party exited with {:?}", out.status);
            String::from_utf8(out.stdout).unwrap()
        })
        .collect()
}

#[test]
fn three_processes_semi_honest() {
    let outs = run_trio(&["3", "64"]);
    assert!(outs[0].contains("verified against plaintext walk"), "{}", outs[0]);
}

#[test]
fn three_processes_malicious() {
    let outs = run_trio(&["2", "64", "mal", "16"]);
    assert!(outs[0].contains("verified against plaintext walk"), "{}", outs[0]);
}
