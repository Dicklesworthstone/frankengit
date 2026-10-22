# Restartable local webhook dispatch

Owning work: FG-046; canonical composition: frankengit-root-doctrine-x2mv.4.55. `fg webhook dispatch` connects the native canonical outbox
reader to the existing signed HTTP transport. The default legacy mode described
below is observation-only. With `--canonical-principal`, use the explicit
canonical mode in the next section. Unlike manual `deliver`, it owns
bounded retries and records attempts durably. Unlike the separate strong
canonical settlement driver, it **never acknowledges, removes, or changes a
canonical outbox obligation**.

## Canonical dispatch with an explicit route intent

```sh
fg webhook dispatch ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --id WEBHOOK_ID --destination CANONICAL_DESTINATION --at-least-once \
  --canonical-principal PRINCIPAL_ID
```

The same option is supported by `dispatch fanout`. Routes sharing a destination
form one immutable selected plan before the first send. The operator must supply
the complete intended route set: this command does not discover all subscribers
or administer a canonical subscription registry. The first canonical RCR binds
the principal, endpoint/incarnation/fence commitments, strict/permissive SSRF
authority and retry policies. Attempt timeout remains an invocation deadline. A
subsequent invocation must present the identical plan and principal. Adding or
removing a member, changing an endpoint or ceiling, and narrowing an owed member's
filter refuse without dropping that responsibility. Secret rotation is observed
before each send. All route fences remain held through node shutdown.

Authority history owns markers, observations, backoff and terminal outcomes.
The local journal supplies the stable process fence and detects legacy attempts;
it does not decide retries or canonical completion. A legacy observation without
a canonical marker refuses before claim and requires explicit reconciliation.
Canonical HTTP acceptance is published before aggregate terminal settlement.
One receiver's acceptance cannot retire another owed route. Missing replies and
recovered send markers are Unknown for non-probing HTTP; they escalate and never
automatically resend. Known transient responses retain the original bounded
schedule across invocations. Zero remaining invocation allowance still permits
recovery/finalization, without reserving a fresh send.

Strict SSRF and unsupported TLS refusals are definite transport failures: they
publish canonical terminal failure and retain a local diagnostic without opening
a connection. There is no HTTPS downgrade. Legacy mode retains its pre-claim URL
preflight; canonical replay also preflights before admitting a new replay intent.

Per-delivery JSON names its canonical progress root, whether terminal settlement
was published, and whether the active slot was retired. These observations are
emitted while the node is still open; the final sweep record follows awaited
shutdown. `canonical_settled:true` can include Escalated: inspect `active_retired`
and the unknown-route count. Exit 3 denotes unresolved outcomes. The persisted
receipt, recoverable through `fg webhook receipt`, commits to canonical route
outcomes and actual transport evidence commitments. It proves recorded observations,
not receiver-side exactly-once behavior. Broken stdout cannot undo publication.

The normative bounded profile and non-claims are in
[MERGE_FORGE_EVENT_DELIVERY_CONTRACT.md](MERGE_FORGE_EVENT_DELIVERY_CONTRACT.md#explicitly-owned-weak-dispatch-profile).
Explicit new sealed manual replay is described in
[WEBHOOK_OPERATOR_DELIVERY.md](WEBHOOK_OPERATOR_DELIVERY.md#canonical-replay-with-a-new-sealed-intent).
Current revision-bound execution and independent batch acceptance remain
required before full .4.55 capability credit.

## Legacy observation-only mode

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
storage root. Its `.lock` sidecar is a stable inode held under an exclusive
nonblocking file lock for the invocation's entire lifetime, including checkpoint replacement. It is created privately, synced, and its
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

Temporary DNS lookup errors and empty DNS answers use that same bounded retry
path. They consume an attempt and become a terminal dead letter only when the
retry limit is exhausted. Unsafe DNS answers, excessive answer counts, and
destination-policy violations still refuse permanently before connecting. The
complete answer set is validated before selecting any address; a public address
does not make a mixed public/private answer set safe.

The bounded journal admits 16,384 keys and a 16 MiB data file. Before reserving
an attempt, the worker guarantees room for both its reservation and observation.
When the append log reaches that bound, it writes a complete checkpoint into a
private file in the same directory, syncs the body, atomically replaces the data
file, and syncs the directory. The stable `.lock` fence remains held throughout.
Every delivery key, payload commitment, attempt ordinal, terminal result,
cumulative uncertainty flag, next-attempt time, latest evidence digest and clock
floor is retained. No acceptance is dropped to make space and no budget resets.
Superseded per-attempt log frames are not retained by this local profile; this
is a compacted retry state, not a complete audit archive or receiver proof.
A process crash can leave a private staging file; such files are never selected
on reopen. The data-file bound is not a total-directory or orphan-cleanup claim.

A failure before replacement leaves the old selected file intact. An unknown
replacement/directory-sync result poisons the owner: it cannot send again until
reopening and verifying the selected file. Reopen never chooses a scratch file,
an older checkpoint, or a valid prefix of corrupt data. Compaction is deterministic
for identical retained state. The journal version is now `fgit-webhook-dispatch-v2`,
with an ordered, count-bound checkpoint followed by ordinary lifecycle records.
Version 1 journals, including those produced by `c64d6df`, require the explicit
offline migration below. Ordinary dispatch never converts a journal implicitly
or resets its counters. New installations use v2.

**Retain both the `.journal` and `.journal.lock` files.** Losing either one alone
refuses rather than initializing a new budget. Do not replace or remove either
file while a worker may own it. Files must be private, singly-linked regular
files. The owner checks inode identity and length before appends and checkpoint
publication. These checks are not confinement against hostile directory mutation
or authenticated protection against an operator rolling both files back.
All parent directories must be controlled by the operator. Locks fence
cooperating dispatchers on the same filesystem, not another machine, an unrelated
manual sender, or the canonical strong-settlement worker. Do not run competing
delivery profiles for the same subscription.

The checksum chain detects corrupt, truncated, reordered, or semantically
invalid records. A torn tail refuses; it is never silently discarded. This is
not authentication, malicious-rollback detection, a receiver receipt proof, or
repository authority. A complete older valid prefix can represent a legitimate
crash point; deliberate rollback to such a prefix is outside the trust profile.

## Upgrade an existing v1 journal without losing delivery responsibility

Stop the old dispatcher and disable its automatic restart before upgrading.
Keep the original journal. The file is below the node storage directory at
`webhooks/dispatch-WEBHOOK_ID-SHA256_OF_DESTINATION_BYTES.journal`; use the exact
slot for the original subscription, not a new empty path.

First inspect the stopped file without changing it:

```sh
fg webhook dispatch-migrate /path/to/dispatch-7-DESTINATION_HASH.journal --trusted-local
```

The preview validates the entire original v1 checksum chain and legal lifecycle,
then reports `original_sha256`, the intended v2 checkpoint hash, retained-key
count, retry limit, scope digest and exact clock floor. It acquires an exclusive
data-file lock to exclude the old worker, but creates no file, fence or backup.
This is an operator-owned local-file operation: it needs no registration, secret,
node runtime or network, and it cannot change the retained repository binding.

Apply only to the exact previewed bytes:

```sh
fg webhook dispatch-migrate /path/to/dispatch-7-DESTINATION_HASH.journal --trusted-local \
  --apply --expected-sha256 ORIGINAL_SHA256_FROM_PREVIEW
```

The migrator holds the old data-inode lock and the new stable sidecar lock.
It preserves an exact private `.v1-backup`, syncs that backup and its directory,
then uses the worker's existing stage/sync/replace/directory-sync protocol to
install v2. It verifies complete retained-state equivalence before replacement.
All delivery keys, payload hashes, consumed ordinals, outcomes, cumulative
uncertainty, next-attempt times, latest evidence hashes and the clock floor are
preserved. No request is sent, no canonical obligation is settled, and no failed
or potentially delivered attempt becomes a fresh attempt one.

An interrupted conversion can be repeated with the **same original checksum**.
Before replacement it revalidates v1; after replacement it verifies the exact
installed v2 checkpoint against the retained v1 backup. A complete previously
visible result is resynchronized before success. An exact partial initialization
prefix of the new fence may be completed only while the original checksum-pinned
v1 file remains locked. Wrong scopes, malformed records, torn journals, mismatched
backups, missing migrated data/fences and public, linked or special files refuse.
The backup is not overwritten and is never a fallback source for the worker.

If an old worker restarted and changed v1 after the preview, the checksum pin
refuses. If a new worker has already appended to v2, reapplying migration also
refuses rather than rolling it back. Inspect the current v2 state instead.
A lost stdout receipt does not undo migration: retain the files and repeat with
the original checksum before restarting delivery. Do not delete the backup,
fence or current journal to clear a refusal. Operator rollback, hostile parent
mutation, noncooperating writers and multi-host fencing remain outside this
local profile. A process crash may leave private staging residue; it is never
selected on reopen and is not a delivery source.

The focused native result below includes the migration and checkpoint Rust
tests. Their injected filesystem boundaries do not establish crash durability
on an untested filesystem.
## Inspect status without pausing a worker

```sh
fg webhook dispatch-status ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --id WEBHOOK_ID --destination CANONICAL_DESTINATION --limit 20
```

This command authenticates the existing local repository binding, closes its
node runtime, then reads a bounded journal prefix without taking the dispatch
fence, syncing records, reserving retries or contacting a receiver. It is usable
while a dispatcher owns the journal. `--at-least-once`, `--attempt`, continuous
mode, stop controls and egress options are refused on this read-only command.

The result includes the retained attempt ordinal, last state and evidence digest,
next-attempt timestamp, exhausted-budget flag and cumulative uncertainty for each
listed delivery. Counts cover the entire observed journal, not just its page.
`rejected` counts latest recorded rejections; `unresolved` also counts earlier
unknown attempts that such a rejection cannot erase. An accepted observation
resolves local at-least-once delivery, not the possibility of duplicate effects.
Full-width timestamps and webhook IDs are decimal strings, without JSON-number
rounding. `payload_binding_sha256` is the journal's algorithm-bound root hash,
not a replacement canonical payload root. Raw response prose and secrets are
never returned.

For continuation, pass `--after NEXT_AFTER --expected-tail JOURNAL_TAIL_SHA256`.
The tail commits the exact observed prefix. Append or compaction may change it;
a changed token refuses rather than combining different journal snapshots.
Start a new listing explicitly after that refusal. Configuration diagnostics are
refreshed independently; the token pins journal records, not live registration state.
Pages admit 1–100 entries
and responses are capped at 256 KiB. A torn concurrent append or corrupt data
also refuses; the reader never trims bytes and presents a fabricated clean status.

The command can show retained failures after registration disablement, an
endpoint/schedule change, or configuration failure. `configuration_available`
and `scope_matches_current` distinguish those cases; false/null scope agreement
must not be interpreted as current configuration authorizing the old records.
A missing journal reports `journal_present:false`, not an empty canonical queue.
One missing half of a journal/fence pair is a refusal, not a fresh empty journal.
`clock_behind_floor` exposes a clock rollback that would fence retries.

This is an observation, not a retry permit, receiver proof, or authoritative
pending-queue view. A complete live append may still await its owner's sync,
so `durability_verified` is always false. `transport_attempted`, `journal_modified`
and `canonical_settled` are also false. Exit 0 means the status read completed,
not that the displayed deliveries succeeded. It never clears failures or resets
attempt counters. Native status tests cover reads during checkpoint replacement,
pinned pagination, missing/corrupt state, full-width values, SHA-1/SHA-256 native
node bindings, disabled/changed/unavailable configuration, and output failure.
These Rust tests are included in the focused native result below.

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
and endpoint/subscription refusal. A strict remote run at clean native source
`c37f7f7c0e38326a7dc4ed9a4f4ce370769a5325` executed the dispatcher filter:
72 passed, 0 failed, 0 ignored, 744 unrelated tests filtered. This is a focused
Rust result, not an independent batch, full-workspace, or release gate.
In an isolated clone, restoring only the original malformed 34-character
tenant/repository fixture IDs made
`routes_are_explicit_sorted_and_keep_single_worker_defaults` fail at
`fanout.rs:344:10` with `invalid tenant ID` (0 passed, 1 failed, exit 101).
Restoring the committed fixture preceded the clean 72-test result. This is a
causal regression control by the same implementer, not independent review.

The separate product campaign uses an already built native binary:

```sh
FG_BIN=/absolute/path/to/fg FGE_PROFILE=release \
  bash scripts/e2e/suites/forge/webhook_delivery.sh
```

It never invokes Cargo or selects a target directory. In SHA-1 and SHA-256
repositories it opens a real issue, compares received payloads with canonical
outbox inspection, independently checks HMAC before and after rotation, exercises
connection refusal and HTTP rejection, replays a retained dead letter, and
resumes bounded two-route fan-out in new processes. It checks that accepted
observations suppress local resends while the canonical outbox stays unchanged.
Missing `FG_BIN` is an error. Command transcripts and actual HTTP requests are
retained; a partial campaign cannot supply successful acceptance facts.

This campaign does not replace the Rust dispatcher test gate above. The older
`FG-046-E2E-*` assertions that matched Cargo test transcripts were not product
execution evidence; the binary campaign uses `FG-046-NATIVE-*` identifiers.
Automatic backoff timing, dual-secret verification windows, and crash injection
remain separate Rust test obligations. Authored campaign code alone earns no
executed result or bead completion.

On October 21, the campaign at `d9cf96e9` plus the positional `fg init` format
correction executed 60 native commands and all 15 acceptance assertions on
Linux, with no failures or skips. It used the retained `05e29b11` release binary,
SHA-256 `e7e4daa3bd424ca9aafa7466d0377ca796974bbd52a940fc1c6fb95c2e4ee8c8`.
Every crate, Cargo manifest/lockfile, and toolchain byte matches the Rust test
revision above. The binary was not rebuilt from the campaign's whole source
tree; these identities remain distinct. The first run refused the campaign's
incorrect `init --object-format` syntax; the correction uses the documented
positional format. Both runs are retained under
`/data/tmp/frankengit-peachhorse-webhook-d9cf96e9-20261021T2016` on `csd`.
The clean `c37f7f7c0e38326a7dc4ed9a4f4ce370769a5325` campaign subsequently
ran against the release binary compiled from that same tracked revision:
15 passed, 0 failed, 0 skipped, 60 native commands and 12 actual HTTP requests,
with containment reported `ok`. The binary's SHA-256 is
`6becb907a60087228f2c19f325bdd28daafe4b0c068d2721ccec4893e34ad819`;
receipts are in `result-c37` under the same retained `csd` root. The strict
remote build itself exited 0; RCH's subsequent Mac artifact transfer refused
the Linux target (RCH-E327, overall exit 102). The binary was separately copied,
hash-checked and executed on Linux. No local target was replaced, no transfer
gate was bypassed, and this is not a successful RCH artifact-transfer gate.
Independent batch verification and bead closure remain separate.

`DEP-264` admits Python 3 only as this campaign's external tooling. The helper
uses the supplied standard library for HTTP, JSON, HMAC, and child-process
ownership, with no package installation or network dependency. Each run records
the exact interpreter version alongside the binary digest. Python's interpreter
and native extension implementation, including any crypto backend, stay outside
the production binaries and their Rust dependency graph. The interpreter's
PSF-2.0 license and bundled third-party notices remain its licensing boundary;
the campaign does not redistribute it. The audit surface is the small helper,
its standard-library calls, and the selected interpreter. A Bash receiver would
require a second HTTP/JSON parser and platform-specific signing helpers; a Rust
test receiver would restore a build prerequisite to this prebuilt-binary lane.
Remove this tooling admission when no campaign needs it, after an equivalent
native receiver/oracle replaces these checks. This is not an exception for
Python, C libraries, or another runtime inside FrankenGit production.

### Checkpoint continuation validation

Additional native tests cover deterministic checkpoint/reopen equivalence,
interruption before and after rename and after directory sync, repeated automatic
compaction, preservation of exhausted/unknown/accepted entries, maximum-key
snapshots, missing data or fences, inode replacement, hard links, legacy refusal,
and checksum-valid malformed checkpoints. These tests are included in the
focused native result above.
This change removes the local append-history stop, not the canonical outbox's
16,384-entry ceiling, canonical retention requirements, or whole-history read cost.

Migration regressions also cover stopped-file preview, original-checksum changes,
all 2..16 retry ceilings, exact uncertainty preservation, old/new live-owner
exclusion, interrupted fence/backup/checkpoint boundaries, idempotent recovery,
corrupt or progressed v2 without backup fallback, conflicting backups, and lost
stdout. These are included in the focused native result above, not a whole
workspace or operational upgrade certification.
