# The prepared buffer: replicated, not volatile

The worst number this system had was recovery. A quorum change cost a
77,151-round rebuild from the seed, about 51 minutes across three
continents, during which the channel could not advance at all. That number
is now zero, and the change is small.

## Why recovery was needed

A prepared secret used to be stored as a public masked value plus one random
mask per *online* member:

    secret = MASKED xor m0 xor m1 xor m2

That is a 3-of-3 sharing. Lose any single member's masks and the whole
prepared buffer is unrecoverable, so one member dropping out forced a
complete rebuild from the seed. The design was deliberate, following the
Threshold BOLT Shachain draft's preference for volatile session state and
rewarming from the seed, which minimises long-lived secret material. The
measurement is what changed the balance: rewarming is 51 minutes over a wide
area, and it freezes the channel.

## What replaces it

Hide each prepared value under the same structure the seed already uses: a
replicated sharing of four summands, summand j derivable by every member
except j. Any three members hold all four, and losing any one member loses
nothing.

The summands are not stored. Each is derived from a long-term key,

    summand_j(vid) = SHA256(key_j || vid)

where key_j is distributed member-to-member at setup exactly as the seed
summands are. So a buffer of any depth costs no secret storage and needs no
per-leaf distribution: any member holding key_j can recompute that summand
for any value on demand.

| | volatile masks | replicated summands |
|---|---|---|
| one member drops out | buffer destroyed, 77,151-round rebuild | **nothing happens** |
| secret storage per prepared leaf | 32 B per member | **none** |
| public storage per prepared leaf | 32 B | 32 B |
| long-lived secret material | the seed | the seed, plus four 32-byte keys |
| revealing a secret | 1 round | 1 round, with a free cross-check |

Revealing gains integrity rather than losing it. Every summand is derivable
by three members, so the adapter compares the copies it receives before
XOR-ing, and then checks the result against the point published for that
state. A member that supplies a wrong summand is caught twice over.

## Measured

Local lifecycle, four members, quorum of three, member 2 dropped and the
standby taking over mid-channel:

| | rounds after the change | lifecycle |
|---|---:|---:|
| rebuild from the seed (`--restore-on-change`) | 77,151 | 32.2 s |
| replicated buffer, no rebuild | **0** | **18.5 s** |

An unmodified rust-lightning counterparty accepted every point and secret in
both. The rebuild path is kept behind a flag, because it is still what a true
cold start needs, and because it measures what recovery used to cost.

## What this costs

Four extra 32-byte keys per member, held for the life of the channel. In
exchange the architecture loses its volatile-secret-state concept entirely:
the seed and those keys are the only secrets, everything else is public
bookkeeping or derivable. Recovery from losing a member stops being an
operation at all.

The rebuild is still needed if enough members lose durable state at once to
exceed the replication, which is outside the corruption model the rest of the
design assumes.
