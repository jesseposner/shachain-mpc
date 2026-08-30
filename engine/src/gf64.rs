//! GF(2^64), the extension field the transcript proofs live in.
//! Modulus x^64 + x^4 + x^3 + x + 1. Multiplication uses the aarch64
//! polynomial multiplier when the CPU has it, with a portable shift-XOR
//! fallback.

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Gf64(pub u64);

impl Gf64 {
    pub const ZERO: Gf64 = Gf64(0);
    pub const ONE: Gf64 = Gf64(1);

    pub fn add(self, other: Gf64) -> Gf64 {
        Gf64(self.0 ^ other.0)
    }

    pub fn mul(self, other: Gf64) -> Gf64 {
        let (hi, lo) = clmul(self.0, other.0);
        Gf64(reduce(hi, lo))
    }

    /// Fermat inversion: x^(2^64 - 2). Zero maps to zero; callers never
    /// invert zero (evaluation points are distinct nonzero values).
    pub fn inv(self) -> Gf64 {
        let mut result = Gf64::ONE;
        let mut base = self;
        // 2^64 - 2 = 0xFFFF_FFFF_FFFF_FFFE
        let e: u64 = u64::MAX - 1;
        for i in 0..64 {
            if (e >> i) & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
        }
        result
    }
}

/// x^64 = x^4 + x^3 + x + 1: fold the high word in twice (the second
/// fold's high part is at most 4 bits and folds cleanly).
fn reduce(hi: u64, lo: u64) -> u64 {
    let fold = |h: u64| (h << 4) ^ (h << 3) ^ (h << 1) ^ h;
    let hi2 = (hi >> 60) ^ (hi >> 61) ^ (hi >> 63);
    lo ^ fold(hi) ^ fold(hi2)
}

#[cfg(target_arch = "aarch64")]
mod accel {
    #[target_feature(enable = "aes")]
    unsafe fn pmull(a: u64, b: u64) -> u128 {
        // vmull_p64: 64x64 -> 128 carryless multiply.
        core::arch::aarch64::vmull_p64(a, b)
    }

    pub fn clmul(a: u64, b: u64) -> Option<(u64, u64)> {
        if std::arch::is_aarch64_feature_detected!("aes") {
            let p = unsafe { pmull(a, b) };
            Some(((p >> 64) as u64, p as u64))
        } else {
            None
        }
    }
}

fn clmul_soft(a: u64, b: u64) -> (u64, u64) {
    let (mut hi, mut lo) = (0u64, 0u64);
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            lo ^= a << i;
            if i > 0 {
                hi ^= a >> (64 - i);
            }
        }
    }
    (hi, lo)
}

fn clmul(a: u64, b: u64) -> (u64, u64) {
    #[cfg(target_arch = "aarch64")]
    if let Some(p) = accel::clmul(a, b) {
        return p;
    }
    clmul_soft(a, b)
}

/// Lagrange basis coefficients at x for interpolation points `pts`:
/// c_j = prod_{t != j} (x - pt_t) / (pt_j - pt_t).
pub fn lagrange_at(pts: &[Gf64], x: Gf64) -> Vec<Gf64> {
    let n = pts.len();
    // prefix[j] = prod_{t < j} (x - pt_t), suffix likewise from the right.
    let mut prefix = vec![Gf64::ONE; n + 1];
    for j in 0..n {
        prefix[j + 1] = prefix[j].mul(x.add(pts[j]));
    }
    let mut suffix = vec![Gf64::ONE; n + 1];
    for j in (0..n).rev() {
        suffix[j] = suffix[j + 1].mul(x.add(pts[j]));
    }
    (0..n)
        .map(|j| {
            let mut denom = Gf64::ONE;
            for t in 0..n {
                if t != j {
                    denom = denom.mul(pts[j].add(pts[t]));
                }
            }
            prefix[j].mul(suffix[j + 1]).mul(denom.inv())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_axioms_spotcheck() {
        let a = Gf64(0x1234_5678_9abc_def0);
        let b = Gf64(0x0fed_cba9_8765_4321);
        let c = Gf64(0xdead_beef_cafe_f00d);
        assert_eq!(a.mul(b), b.mul(a));
        assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
        assert_eq!(a.mul(a.inv()), Gf64::ONE);
        assert_eq!(a.mul(Gf64::ONE), a);
        // Accelerated and soft paths agree.
        let (hi, lo) = clmul_soft(a.0, b.0);
        assert_eq!(clmul(a.0, b.0), (hi, lo));
    }

    #[test]
    fn lagrange_interpolates() {
        // f(x) = 3x^2-ish over GF: pick values at pts, re-evaluate at a
        // point via the basis, compare against direct interpolation of
        // a polynomial defined by those values (identity at the points).
        let pts: Vec<Gf64> = (1u64..=5).map(Gf64).collect();
        let vals: Vec<Gf64> = [7u64, 11, 13, 17, 19].map(Gf64).to_vec();
        for (j, p) in pts.iter().enumerate() {
            let basis = lagrange_at(&pts, *p);
            let mut v = Gf64::ZERO;
            for (b, val) in basis.iter().zip(&vals) {
                v = v.add(b.mul(*val));
            }
            assert_eq!(v, vals[j]);
        }
    }
}
