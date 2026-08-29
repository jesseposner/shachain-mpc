//! Bespoke Rep3 engine for the BOLT #3 shachain.
//!
//! Milestone 1: semi-honest replicated 3-party evaluation of the Bristol
//! Fashion SHA-256 circuit, bitsliced 64 lanes per machine word, with the
//! shachain walk on top. The three parties run in lockstep inside one
//! process; per-party state is kept strictly separate so the evaluation
//! logic survives the move to three processes unchanged (M3).
//!
//! Protocol: Araki-Furukawa-Lindell-Nof-Ohara (CCS 2016). One bit sent
//! per AND gate per party; XOR, NOT and constants are local.

pub mod bristol;
pub mod engine;
pub mod mal;
pub mod net;
pub mod rep3;
pub mod sha256;
pub mod shachain;
