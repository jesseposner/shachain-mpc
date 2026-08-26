# Experiments that did not work

Kept because a measured negative result is worth as much as a positive one,
and because the next person to have the same idea should find the number
rather than repeat the work.

## sha256_native.mpc: SHA-256 from native integers, 1.5x slower

Rounds equal a circuit's AND-depth. The Bristol sha256 circuit is 1,607 deep,
almost all of it addition, because it uses ripple-carry adders at roughly 31
deep per 32-bit add. Measured alone, MP-SPDZ's own `sbitint` addition looked
far shallower:

| dependent 32-bit adds | rounds | marginal |
|---:|---:|---:|
| 1 | 23 | - |
| 16 | 65 | 2.8 per add |
| 64 | 113 | 1.0 per add |

At one round per add, SHA-256's roughly 350 dependent adds should have cost
a few hundred rounds against 1,635.

The result was 2,456 rounds, half again worse than the circuit it was meant
to replace. Its digest is also wrong, and that bug was not chased because
the performance case had already failed.

Bare addition chains are the compiler's best case: nothing else competes and
the additions merge. In
SHA-256 each round interleaves additions with the AND gates of Ch and Maj,
and the critical path carries about five dependent additions per round
(`t1 = h + S1 + ch + K + w[i]` is four by itself, before `a = t1 + t2`). The
marginal cost measured on a bare chain does not survive that context.

A successful direct attack needs carry-save adder trees, so that the
five-term sums reduce to two terms in a couple of cheap levels before a
single carry-propagating add, plus a parallel-prefix adder for that final
step. That is a real piece of work rather than a wiring change, and the
prize is bounded: the SHA depth sets the cost of recovery and of refilling
the lookahead buffer, both background operations, while the payment path is
already one round and untouched by any of it.

Garbling is the cheaper route because it is input-independent. Any circuit
the system will need can be garbled ahead of time and evaluated in
three online rounds, which is what already makes channel open 4.8 s instead
of 54 minutes. Applying that to recovery and to buffer refill attacks the
same cost without touching the circuit, and reuses machinery that exists.
