# The setup ceremony

Summand j of the seed is held by every member except j. Nobody may choose
it, and every holder must end up with the same bytes. The original setup
guaranteed neither.

## What was wrong

**One member chose each summand.** Member j's summand came from a single
originator's generator. Since every member is missing exactly one summand,
a weak generator at that one originator handed the whole seed to anyone who
compromised a single other member. That is a failure the corruption model
does not even count: the threshold survives one *corruption*, but here one
bad generator plus one corruption is enough, and a bad generator is not a
corruption.

**An originator could equivocate.** Nothing stopped it sending different
bytes to different holders. Different quorums would then derive different
chains. With the replicated buffer this surfaces as a channel that cannot
advance rather than as theft, since a released secret is checked against
its published point, but a stuck channel is still a failure and it would
surface at the worst moment, during a quorum change.

Both were recorded in `docs/todo.md` as item 1.2 before being fixed. The
second is worth restating because it is easy to get wrong: contributing
entropy from everyone leaves equivocation untouched. It fixes only the
first problem.

## The ceremony

Every holder of summand j contributes to it, and the summand is the XOR of
those contributions, so it is uniform if any single contributor's generator
is sound. One 64-byte contribution covers both the seed summand and the
buffer mask key.

Contributions are committed before they are revealed. Each contributor
publishes `SHA256(contribution || nonce || sid || from || j)` to the
coordinator, which relays the whole table to everyone, and only then reveals
to co-holders. Without this a contributor could wait to see the others and
choose its own value to steer the result, so committing first is what makes
the XOR uniform rather than merely random-looking.

Every holder then verifies each contribution against the published
commitment, combines, and publishes a digest of the summand it computed. The
coordinator refuses to continue unless all holders of a summand publish the
same digest.

The coordinator sees commitments and digests. It never sees a contribution
or a summand.

## Why two checks

They catch different faults, and both are exercised in `scripts/test.sh`.

| fault | caught by | mechanism |
|---|---|---|
| reveal something other than what was committed | commitment check | the revealed value does not hash to the published commitment |
| send different bytes to different holders | commitment check | a contributor can only commit to one value, so at least one holder sees a mismatch |
| verify every contribution, then keep a different summand | digest cross-check | holders of that summand publish different digests |

The commitment check is what actually defeats equivocation: committing to a
single value makes sending two different ones detectable by construction.
The digest cross-check is the backstop for a holder that computes or stores
the wrong thing after every check has passed, which no commitment can catch.

## Remaining gaps

The ceremony detects and aborts; it does not identify and continue. A member
that reveals a bad contribution stops setup rather than being excluded,
which is the right default for a setup step that can simply be re-run, but
it means a single faulty member can prevent setup indefinitely.

It also assumes the commitment table reaches every member unaltered. Here
that is the coordinator relaying it, so a corrupted coordinator could show
different tables to different members. Since the coordinator is trusted for
availability but not confidentiality elsewhere in this design, closing that
gap wants the members to echo the table to each other and compare, which
they do not yet do.
