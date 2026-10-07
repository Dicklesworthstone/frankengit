# Restartable local webhook dispatch

Owning work: FG-046. `fg webhook dispatch` connects the native canonical outbox
reader to the existing signed HTTP transport. Unlike manual `deliver`, it owns
bounded retries and records attempts durably. Unlike the separate strong
canonical settlement driver, it **never acknowledges, removes, or changes a
canonical outbox obligation**.

## Run one sweep

```sh
fg webhook dispatch ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --id WEBHOOK_ID --destination CANONICAL_DESTINATION --at-least-once
```

First register the HTTP endpoint using `fg webhook register` and find its
original canonical destination using `fg webhook outbox`. The destination is
not a URL and is never rewritten. This is one explicitly configured local
subscription, not canonical subscription fan-out. A whole event batch must
match the current registration; the dispatcher does not remove some events
while claiming to transmit the original batch commitment.

Defaults: one complete outbox scan, up to 16 due attempts, 16,384 retained
entries, and a 5-second transport deadline per attempt. Adjust them with
`--max-deliveries` (1–1,000), `--max-scan-entries` (1–16,384), and
`--attempt-timeout-secs` (1–60). SHA-256 repositories require
`--object-format sha256`. The default is SHA-1. Every option, bound, and duplicate
flag is validated before executing the dispatcher. The two consent flags are
mandatory; registration alone does not start delivery.

A one-shot sweep does not sleep through retry backoff. It records pending work
and exits; a later invocation resumes the same journal, original payload, next
attempt ordinal, and delay. An accepted observation suppresses further sends
by this local dispatcher, including after process restart or lost stdout.

## Continuous lifetime

```sh
fg webhook dispatch ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --id WEBHOOK_ID --destination CANONICAL_DESTINATION --at-least-once \
  --continuous --stop-file /run/frankengit/webhook.stop --poll-millis 1000
```

The stop file must be absent until shutdown and must be a regular file when
present. Links and special files refuse. SIGTERM, SIGINT, or the stop file stops
new admissions and drains the current operation. Stop requests are latched:
removing the file or recovering from a stop-file I/O error cannot resume the
same invocation after its drain was requested. No detached delivery tasks
are spawned. A transport interrupted after reservation retains an unknown
outcome, not proof of non-delivery. The existing HTTP adapter closes its socket
before returning an observation. Blocking filesystem operations and OS DNS
resolution cannot be preempted; request/transport deadlines do not eliminate
that platform limitation. Source reads also have their inherited finite runtime
budget and can refuse before the transport deadline.

Each sweep emits bounded newline-delimited JSON observations and a summary.
An observation is emitted only after the repository runtime has closed and its
local result has been synced. A failed output stream terminates the invocation;
it does not undo or erase a recorded acceptance. All records explicitly say
`canonical_settled:false`. Observation records distinguish a transport verdict
from an adapter refusal. `evidence_sha256` hashes the adapter's actual returned
evidence or refusal; it does not claim an error is a receiver response or an
authenticated receipt. Raw error/response prose is not printed.

Exit status: 0 means no pending, failed, or unknown work among the selected
subscription's examined entries; 1 means pending/backoff, a sweep bound, or
requested stop; 2 means refusal or known rejection/exhaustion; 3 means an
unresolved transport outcome. Counters describe the current sweep, not all
historical sends. Filtered or already canonically claimed entries are separate
counts, not accepted deliveries. Neither a narrowed filter nor another
canonical owner can clear a previous unknown local send. A stopped partial sweep is labelled stopped.
An infrastructure error may follow an earlier accepted send; consult the journal
rather than interpreting the exit status as proof that nothing happened.

## What is durable, and what is not

The journal is `webhooks/dispatch-ID-DESTINATION_HASH.journal` under the supplied
storage root. A stable inode is held under an exclusive nonblocking file lock
for the invocation's entire lifetime. It is created privately, synced, and its
directory is synced before use. Reopened valid journals are re-synced before
retry decisions. Each reservation and result is appended and synced. A write
or sync error poisons that owner and forbids further sends.

The header binds tenant, repository, repository incarnation, native hash format,
webhook ID, original destination, exact endpoint URL, and retry schedule. An
endpoint, incarnation, or schedule change hits the same journal slot and refuses
instead of resetting attempts. Payload commitments are bound per delivery key.
Secrets are not stored in the journal. Registrations are reopened before each
attempt so secret rotation and subscription narrowing are observed; neither
resets attempt identity. The controller retains no startup registration or obsolete signing secret
between sweeps. An already admitted attempt can finish under its
captured configuration. This is not instantaneous revocation or protection
against hostile concurrent edits to operator-owned directories.

A send first syncs an `in-flight` reservation. A crash at any point after that
reservation consumes its ordinal. On restart, an unfinished attempt is possibly
delivered; explicit at-least-once mode permits only the **next** attempt, after
its retained delay and within the frozen maximum. A subsequent HTTP rejection
cannot erase an earlier unknown outcome. Later acceptance establishes local
observation of delivery, but duplicate effects remain possible. Even an explicit HTTP failure can follow receiver-side effects: a known
response is not proof of non-execution. The attempt header and local journal
do not make an ordinary HTTP receiver idempotent.

Retry scheduling uses the registration's existing deterministic exponential
backoff and jitter. The dispatcher admits 2–16 attempts and schedule parameters
up to one day; jitter may extend the configured maximum delay by 20%. Clock
rollback relative to a retained observation refuses rather than shortening
backoff. Separate process invocations never reset the retry ceiling. Manual
`deliver`/`dead-letter replay` remain explicitly separate operations and do not
consult or modify this dispatch journal.

The bounded journal admits 16,384 keys and 16 MiB of framed records; space for
both reservation and observation is checked before a send. Full journals refuse
before another reservation. There is no automatic compaction or deletion in
this profile. **Do not delete, replace, truncate, or copy a journal while a
worker may own it, and do not delete it to clear a retry limit.** Replacing a
locked file can create two owners on different inodes; deleting a retained
journal can duplicate earlier effects. All parent directories must be owned
and controlled by the operator. Locks fence cooperating dispatchers on the
same filesystem, not another machine, an unrelated manual sender, or the
canonical strong-settlement worker. Do not run competing delivery profiles for
the same subscription.

The checksum chain detects corrupt, truncated, reordered, or semantically
invalid records. A torn tail refuses; it is never silently discarded. This is
not authentication, malicious-rollback detection, a receiver receipt proof, or
repository authority. A complete older valid prefix can represent a legitimate
crash point; deliberate rollback to such a prefix is outside the trust profile.

## Source selection and limits

Every sweep selects and verifies **one complete bounded outbox snapshot**.
Exceeding the scan ceiling refuses the whole snapshot rather than returning a
partial list as though it were complete. Delivery keys are not append-ordered:
a newly admitted key can precede previous keys, so no key cursor is persisted as
an append watermark. Local journal entries suppress already observed successes
when the next complete scan revisits them.

Before each due send, the dispatcher reselects its exact key and payload from
current authenticated authority and observes whether another canonical owner
has claimed or settled it. This is an observation, **not a canonical claim or
lease**, and can race with another delivery profile. It reuses existing native
batch validation and refuses payload or repository-incarnation changes. It does
not discover source bytes from filenames, the diagnostic dead-letter store, or
the journal. Repository shutdown must succeed before network I/O.

Output limits do not imply bounded total history cost. These APIs still verify
the existing whole-outbox representation, and selection repeats for due work.
No constant-time lookup, performance improvement, outbox-capacity increase,
canonical retention change, or successful full-compatibility claim follows.

## Egress and verification boundary

The existing HTTP adapter supplies exact committed event bytes, stable delivery
IDs, HMAC signing, SSRF checks, explicit response classification, and a bounded
attempt deadline. Strict egress is the default. `--permissive-for-tests` enables
the existing loopback test profile. **HTTPS remains unsupported and is refused
without any plaintext downgrade.** This does not provide TLS or a general
production multi-user deployment.

No production external Git, new dependency, alternate async runtime, new forge
event type, or canonical publication is introduced. The existing strong
settlement driver's `DownstreamIdempotency::Strong` requirement is unchanged.

Native tests added with the implementation are invoked by:

```sh
cargo test -p fgit-cli --bin fg webhook_commands::dispatcher
```

They include real-file journal locking/restart/corruption tests and real-node,
loopback-HTTP campaigns with SHA-1/SHA-256 authority, signed payload preservation,
retry after lost acknowledgement, output failure, cancellation, bounded scans,
and endpoint/subscription refusal. These tests were **authored, not executed**
in the implementation environment: Cargo, rustc and rustfmt were unavailable.
No bead closure, native test pass, real-binary campaign, or production-readiness
claim is made by this document.
