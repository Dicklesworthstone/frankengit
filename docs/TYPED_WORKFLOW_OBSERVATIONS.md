# Typed reads of saved workflow observations

FG-095b's receiving-side evidence path now decodes the existing, version-one
`TrustedWorkflowReceipt` representation rather than treating its body as an
opaque hash. The public surface is re-exported from
`fgit_runner::coordinator::delivery::journal::history`:

- `decode_trusted_observation` verifies an externally selected commitment and
  reconstructs an immutable `VerifiedLocalObservation`.
- `verify_trusted_job` additionally binds one completed proposal to its exact
  single-job evidence. A multi-job workflow receipt is not interchangeable with
  a job fragment. Neither is a different job's valid receipt. A one-job
  workflow has identical full/job bytes and remains valid.

## Binding and format

Validation compares tenant, repository, run, attempt, source authority head,
native source commit (including SHA-1/SHA-256 domain), trust domain, workflow
source and graph commitments, exact effective limits, logical timestamp, job
identifier and conclusion. Every source remains the existing producer's value;
no new canonical schema, hash preimage, dependency or runtime is introduced.

The reader preserves nanosecond timeout identity from the binary envelope.
Report JSON displays milliseconds, which must agree with the envelope but is
not sufficient to reconstruct it. The accepted JSON is the exact version-one
emitter grammar, including its closed fields, UTF-8/escaped-control spelling,
hexadecimal binary output, fixed shell/environment labels and false authority
bit. Re-encoding through the original producer must reproduce the entire frame.
Unknown/duplicate/reordered fields, false success summaries, truncated frames,
extra bytes, repeated job identifiers, decreasing step indices and invalid
success/containment combinations are refused. Raw logs are never interpreted
as terminal control sequences.

Input is capped before hashing or allocation (64 MiB maximum, with a caller
selected smaller bound). Jobs, steps, names, failure text and retained output
have independent bounds. Parsing polls cancellation during collections, text
and output processing and returns no partial result. Hashing and final
re-encoding are finite operations under the same byte envelope; this is not a
latency benchmark or a constant-memory streaming claim.

## Authority boundary

`VerifiedLocalObservation` proves byte consistency and, when checked against a
proposal, subject consistency. It does not prove that a producer ran the code,
that source is authorized, that containment succeeded in reality, or that its
claim is current. Caller-selected commitments are not signatures. A downstream
publisher must still authenticate the producer and verify its capability,
current source/policy and required evidence before canonical publication.

The decoded value deliberately cannot become a `TrustedWorkflowReceipt` or a
scheduler handle. That private producer-only construction boundary remains
intact. A trusted-local succeeded or skipped job stays `ActionRequired`;
`Success`/`Neutral` are never invented. The canonical check publisher and
hostile-code execution remain unfinished, separate boundaries.

## Regression and verification scope

Eight authored Rust tests cover real coordinator/encoder round trips in both
native hash domains and every step outcome, all eleven bound coordinates,
wrong-job/full-receipt/conclusion substitution, every truncation, corrupt
summaries, resource bounds, binary logs, Unicode/control text, signed exit
codes, exact nanoseconds and cancellation. The worker fixture tests control
flow, not OS isolation. Native compilation and Rust test execution have not
been performed in the editing environment because Cargo/rustc are absent.

## Reading a retained journal

`FileCheckJournal::read_trusted_job` selects a completed fact by its accepted
batch ID and zero-based fact index at an exact `CheckJournalPin`. It verifies
the retained batch/acknowledgement and the selected evidence, then applies the
same typed binding checks. The evidence record length is checked against the
caller's ceiling before allocating its body. Delivered results remain readable;
unknown selectors, stale snapshots, queued facts and missing evidence refuse.
Nothing is acknowledged or removed by this read.

The Unix operator command is available as a Cargo-discovered runner binary:

```sh
cargo run --locked -p fgit-runner --bin fgit-workflow-inspect -- \
  /absolute/private/checks.journal \
  "$TENANT_HEX" "$REPOSITORY_HEX" "$JOURNAL_SHA256" \
  "$BATCH_SHA256" "$FACT_INDEX" \
  --minimum "$RETAINED_BYTES" "$RETAINED_TAIL_SHA256"
```

Identifiers use fixed-width lowercase hex, without digest display prefixes.
`--minimum` is optional; a pin retained independently is required to detect
rollback to a still-valid older journal. The command does not infer repository
scope from paths, create missing files, obtain network credentials, load source,
compile a workflow, or execute a job. The existing private-file journal owns
locking and storage validation. Opening uses its existing bounded replay and
sync behavior; this is a no-content-mutation read, not a promise of zero I/O.

Successful output is one JSON object containing the exact evidence/subject and
snapshot identities, an explicit containment indicator and the original report.
The authority flag remains false and binary output stays hexadecimal. Refusals
emit no successful result; broken output returns failure instead of an apparent
success. The binary refuses on non-Unix hosts, matching the storage profile.

Seven additional authored Rust tests exercise actual file reopen, post-delivery
readback, wrong-subject evidence with a valid hash, snapshot/size/cancellation
refusals, retained containment, command argument boundaries and a real separate
inspection process for both Git object formats. Worker observations are fixtures;
the command test does not claim a hostile execution boundary. These tests have
not been compiled or run in this editing environment.

## Moving evidence and proposals together

`FileCheckJournal::transfer_next_trusted` transfers one oldest pending batch to
another operator-selected, same-repository journal instance. The receiver gets
all referenced evidence as well as the original proposal bytes. This closes
the gap in merely forwarding a proposal whose bodies remain stranded in the
originating journal.

The transfer first bounds the sum of unique referenced bodies using verified
record metadata, then reads and semantically checks every completed fact. No
destination content is changed until all those checks pass. It persists bodies
before the destination accepts the proposal. Only the destination's durable
acceptance allows the source's existing FIFO acknowledgement record to advance.
Missing/mismatched evidence, unavailable storage, capacity exhaustion and
cancellation keep source custody. A partial destination evidence prefix is
reusable; a lost destination acknowledgement is reconciled by exact existing
batch deduplication, including after reopen. Cancellation after durable
acceptance does not replace the acknowledgement with inferred non-acceptance.

The maximum evidence byte argument is an aggregate unique-body bound (up to
64 MiB), not a per-body allowance multiplied by batch size. Both journals keep
their own independent limits and existing phase/order checks. Command-only
receipts are explicitly unsupported by this trusted-observation path. The
existing generic custody API is unchanged; no publisher, remote endpoint,
runner credential or capability is supplied by a workflow document. This is
not replication authority or canonical successful-check publication.

Six further authored Rust tests cover two-format transfer/reopen, source
acknowledgement and destination evidence, exact lost-response retry without
new destination records, a late wrong-subject body with no destination writes,
aggregate byte boundaries, cancellation after a partial copy, and wrong-scope
or full destinations followed by exact retry. Two additional tests pin the single-job full/fragment byte equivalence and
late cancellation after destination acceptance. There are 23 authored Rust
tests for the complete change. Native compilation/execution remains unverified.
