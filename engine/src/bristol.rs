//! Bristol Fashion circuit parser.
//!
//! Header: `n_gates n_wires`, then one line of input sizes prefixed by
//! their count, then one line of output sizes. Gates follow in
//! topological order as `n_in n_out in... out TYPE`. Inputs occupy the
//! lowest wires in declaration order; outputs are the highest wires.

use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub enum Gate {
    Xor(u32, u32, u32),
    And(u32, u32, u32),
    Inv(u32, u32),
}

pub struct Circuit {
    pub n_wires: usize,
    pub inputs: Vec<usize>,
    pub outputs: Vec<usize>,
    pub gates: Vec<Gate>,
    pub n_and: usize,
}

impl Circuit {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        parse(&text)
    }

    /// First wire of input `k`.
    pub fn input_offset(&self, k: usize) -> usize {
        self.inputs[..k].iter().sum()
    }

    /// First wire of output `k`.
    pub fn output_offset(&self, k: usize) -> usize {
        self.n_wires - self.outputs.iter().sum::<usize>() + self.outputs[..k].iter().sum::<usize>()
    }
}

/// Clear-text evaluation, for testing circuits (both parsed and built).
pub fn eval_clear(c: &Circuit, inputs: &[Vec<bool>]) -> Vec<bool> {
    assert_eq!(inputs.len(), c.inputs.len());
    let mut wires = vec![false; c.n_wires];
    let mut w = 0;
    for (input, size) in inputs.iter().zip(&c.inputs) {
        assert_eq!(input.len(), *size);
        wires[w..w + size].copy_from_slice(input);
        w += size;
    }
    for gate in &c.gates {
        match *gate {
            Gate::Xor(a, b, o) => wires[o as usize] = wires[a as usize] ^ wires[b as usize],
            Gate::And(a, b, o) => wires[o as usize] = wires[a as usize] & wires[b as usize],
            Gate::Inv(a, o) => wires[o as usize] = !wires[a as usize],
        }
    }
    let out0 = c.output_offset(0);
    wires[out0..out0 + c.outputs.iter().sum::<usize>()].to_vec()
}

fn parse(text: &str) -> Result<Circuit, String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let mut next = |what: &str| lines.next().ok_or_else(|| format!("missing {what}"));

    let header: Vec<usize> = ints(next("header")?)?;
    let [n_gates, n_wires] = header[..] else {
        return Err("header is not `n_gates n_wires`".into());
    };
    let inputs = sized_list(next("input sizes")?)?;
    let outputs = sized_list(next("output sizes")?)?;

    let mut gates = Vec::with_capacity(n_gates);
    let mut n_and = 0;
    for line in lines {
        let mut toks = line.split_whitespace();
        let n_in: usize = tok(&mut toks, line)?;
        let n_out: usize = tok(&mut toks, line)?;
        let mut wires = Vec::with_capacity(n_in + n_out);
        for _ in 0..n_in + n_out {
            wires.push(tok::<u32>(&mut toks, line)?);
        }
        let kind = toks.next().ok_or_else(|| format!("no gate type in {line:?}"))?;
        gates.push(match (kind, n_in, n_out) {
            ("XOR", 2, 1) => Gate::Xor(wires[0], wires[1], wires[2]),
            ("AND", 2, 1) => {
                n_and += 1;
                Gate::And(wires[0], wires[1], wires[2])
            }
            ("INV", 1, 1) => Gate::Inv(wires[0], wires[1]),
            _ => return Err(format!("unsupported gate {line:?}")),
        });
    }
    if gates.len() != n_gates {
        return Err(format!("expected {n_gates} gates, parsed {}", gates.len()));
    }
    Ok(Circuit { n_wires, inputs, outputs, gates, n_and })
}

fn ints(line: &str) -> Result<Vec<usize>, String> {
    line.split_whitespace()
        .map(|t| t.parse().map_err(|e| format!("{t:?}: {e}")))
        .collect()
}

fn sized_list(line: &str) -> Result<Vec<usize>, String> {
    let v = ints(line)?;
    let (&count, sizes) = v.split_first().ok_or("empty size list")?;
    if sizes.len() != count {
        return Err(format!("size list {line:?} does not match its count"));
    }
    Ok(sizes.to_vec())
}

fn tok<T: std::str::FromStr>(
    toks: &mut std::str::SplitWhitespace,
    line: &str,
) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    toks.next()
        .ok_or_else(|| format!("truncated gate line {line:?}"))?
        .parse()
        .map_err(|e| format!("in {line:?}: {e}"))
}
