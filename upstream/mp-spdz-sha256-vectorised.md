# MP-SPDZ: circuit.sha256 is wrong for every lane but the first

Reported against a stock checkout at `892ac0e` (2026-08-17), with no patches
beyond two needed to build under Xcode clang 21 (removing `-Werror` from
`CONFIG`, and a dependent-template fix in `Protocols/ReplicatedInput.hpp`).
Neither touches `Compiler/circuit.py`.

## Symptom

`circuit.sha256` given a vectorised `sbitvec` returns the correct digest in
lane 0 and wrong digests in every other lane. It does not raise, warn, or
fail: it returns plausible 32-byte values.

## Reproducing, without needing to know the input encoding

Feed the *same* value to both lanes. Whatever convention the caller uses,
both lanes must produce the same digest.

```python
# Programs/Source/repro.mpc
from Compiler.GC.types import sbitvec
from circuit import sha256
t = sbitvec.get_type(256)
x = t.get_input_from(0, size=2)
for e in sha256(x).elements():
    e.reveal().print_reg()
```

With two identical inputs in `Player-Data/Input-P0-0`:

```
0x72cd6e8422c407fb6d098690f1130b7ded7ec2f7f5e1d30bd9d521f015363793
0x5c726d2f5f0922dbbd71db12399cd91bd530dcf9ed0f0198c0e5713893bcb0fa
```

The same input produced two different digests. Lane 0 is the correct
`SHA256(0x01 * 32)`; lane 1 is not a SHA-256 of anything the caller supplied.

The same test on `sha3_256` returns one distinct value, as it should.

## Cause

`sha256` builds its padding and its initial hash state with `sbit()`, which
is one bit wide, in `Compiler/circuit.py`:

```python
282:    padded = x.v + [sbit(b) for b in padding]
296:        [sbit((h[i // 8] >> (7 - i % 8)) & 1) for i in range(256)]))
```

With an n-lane input, those constants supply lane 0 and leave every other
lane zero, so only lane 0 gets the real padding and IV.

`sha3_256` in the same file does the right thing: it takes the width from
its input, `n = x.v[0].n`, and sizes its constants to match. The correct
pattern is already present a hundred lines away.

## Fix

Broadcast each constant across all lanes:

```python
t = sbits.get_type(n)
ones = (1 << n) - 1
def const(b):
    return t(ones if b else 0)
```

then use `const(...)` where `sbit(...)` appears. A working version is
`sha256_lanes` in `programs/shachain_step.mpc` of this repository, checked
against the plaintext reference for three lanes from three distinct seeds.

## Impact

Vectorising is the natural way to batch hashing, and batching is what makes
SHA-256 affordable in Boolean MPC: on a three-party replicated protocol,
64 lanes cost 1,775 communication rounds against 1,621 for a single lane, so
64 times the work for a tenth more rounds. Anyone reaching for that gets
correct output in one lane and silent garbage in the rest.

We ran a full day of batched benchmarks against the broken path before
noticing, because our own check only ever read lane 0.
