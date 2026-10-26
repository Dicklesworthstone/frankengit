# Signed repository-source backup approval

Related: `frankengit-root-doctrine-x2mv.4.21` and `.4.44`; comprehensive plan
21.5–21.8. This operator boundary authenticates `fg backup` archives rather
than the portable Git bundles supported by `attest_git_bundle.mjs`. It is NOT
a signed Repository Capsule, service backup, canonical authorization, or a
replacement for the native authority/graph/payload checks.

## Create and check an independent approval

Export with the native `fg backup export` command. Independently review its
namespace, incarnation, hash format and head-generation receipt. Then:

```sh
node scripts/attest_repository_backup.mjs sign backup.fgit backup.approval.json \
  --private-key /private/backup-signing.pem \
  --tenant-id "$TENANT_HEX" --repository-id "$REPOSITORY_HEX" \
  --incarnation-id "$INCARNATION_HEX" --object-format sha256 \
  --head-generation "$HEAD_GENERATION"

node scripts/attest_repository_backup.mjs check backup.fgit backup.approval.json \
  --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT_HEX" --repository-id "$REPOSITORY_HEX" \
  --incarnation-id "$INCARNATION_HEX" --object-format sha256 \
  --minimum-head-generation "$EXTERNALLY_RETAINED_FLOOR"
```

Signing streams actual artifact bytes into SHA-256 and signs the operator's
identity declarations. It does not parse the archive or establish that those
declarations describe valid native state. A native preflight must additionally
verify the archive and compare its actual identity before restore. A check
verifies the separately supplied Ed25519 key, exact namespace/incarnation/format,
minimum generation, lifetime and artifact bytes. Never obtain the trusted key
or the generation floor from an untrusted adjacent file or the approval itself.
An explicit floor is not a claim that the selected checkpoint is the newest.

Both commands default to a 1 GiB archive ceiling and one 300-second deadline.
`--max-archive-bytes` permits at most 1 TiB; `--timeout-secs` at most 3600 seconds.
Only 64 KiB of archive payload is buffered; the report gives observed read counts.
Blocking filesystem calls remain cooperative, not forcibly interruptible.
An unstable file, symlink, wrong signer, foreign incarnation, wrong format,
below-floor generation, expired approval or altered artifact refuses. Unknown
options and incomplete identity declarations are not inferred or defaulted.

`--expires-at` accepts an optional second-precision UTC deadline. Keys are strict
Ed25519 PKCS#8 private / SPKI public PEM; private files require current-user,
owner-only permissions and a single hard link. New approval files are staged,
synchronized, read back, installed without replacement and directory-synchronized.
Their parent must be an existing owner-private directory. SIGKILL can retain a
private staging file. No automatic cleanup or recursive deletion is performed.

## Wire boundary and trust

The distinct payload type is
`application/vnd.frankengit.repository-backup-approval.v1+json`. DSSE v1 PAE signs
that exact type and the original payload bytes. The application payload has one
strict JSON spelling, with positive full-width u64 generations and artifact byte
counts encoded as decimal strings. Its scope is
`authority_and_selected_git_objects`. Source-bundle signatures, alternate scopes,
extra claims and noncanonical signed payloads cannot cross into this profile.
The key ID is SHA-256 of canonical SPKI DER, never a key-discovery mechanism.

The operator chooses the trust key and floor. This does not implement PKI,
revocation distribution, key rotation, canonical permission checking, routing,
external-effect replay, external-artifact restoration, or full capsule recovery.
The native engine's own scope/verification non-claims must remain intact.

## Executable validation

```sh
node --test tests/operator/repository-backup-approval.test.mjs
```

The tests execute actual Ed25519 signatures, standalone command processes,
filesystem operations, a larger-than-16-MiB sparse archive, mutation detection,
resource/cancellation refusals, generation-floor boundaries and no-replace
publication. Their opaque archive fixture is deliberately not valid native
repository state. These are signing/I/O tests, not native recovery, Rust,
full-workspace, power-loss, performance or bead-closure evidence.

## JavaScript approval wrapper

The JavaScript operator wrapper composes the detached approval with the existing
`fg backup verify` and `fg backup restore` commands. It does not change their
archive format, authority implementation, quarantine, graph validation,
original-payload commitments, or authority-last publication.

```sh
node scripts/restore_repository_backup_native.mjs restore backup.fgit \
  --fg "$PWD/target/release/fg" --trusted-local \
  --approval backup.approval.json --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT_HEX" --repository-id "$REPOSITORY_HEX" \
  --incarnation-id "$INCARNATION_HEX" --object-format sha256 \
  --minimum-head-generation "$EXTERNALLY_RETAINED_FLOOR" \
  --verification-instance 900000001 --destination-instance 900000002 \
  --destination /private/restored-node \
  --approval-record /private/restore-approval-record.json
```

Use `verify` instead of `restore` and omit the three destination/record arguments
for verification without destination changes. Both native instance IDs must be
positive signed-SQL integers and must differ from the original archive's store
instance, as enforced by the native engine. The wrapper does not infer the source
instance. The executable is an explicitly trusted absolute path, never a PATH
lookup, shell command, Git subprocess or fallback implementation.

The full signature/namespace/incarnation/format/generation policy and streamed
artifact hash are verified before launching even the native preflight. A fresh
private scratch root holds native verification metadata, not copied Git payloads.
The preflight receipt must agree with every signed identity, generation, artifact
hash and size. It must report successful native authority import, graph checking,
original commitments, node close and scratch removal, while keeping its explicit
non-claims. Only then may a restore begin. A valid signature cannot bless false
operator identity declarations or skip native content validation.

One shared monotonic deadline covers authentication, hashing, preflight, record
synchronization and restore. Native calls receive the remaining budget and the
signed digest. Each native operation revalidates that digest against its own
pinned input handle, before directory creation and across its passes. A source
path replaced after preflight cannot substitute different bytes. The wrapper
never implements a parallel archive decoder and never passes keys or approval
paths to the child.

### Interrupted restore and explicit resume

The approval record is synchronized outside the destination before native restore
submission. It binds the exact destination, destination instance, verified signer,
signed statement and externally supplied generation-floor policy. Its parent and
the destination parent must be existing current-user, owner-private directories.
Existing records are never overwritten. Add `--resume` with the same arguments
to invoke the native exact-intent resume protocol. Every resume reauthenticates
and verifies the archive; a changed signer, floor, namespace, statement, destination
or instance refuses before the native restore. The record itself is not authority
and cannot substitute for a valid signature from the separately trusted key.

A native failure, malformed reply, cancellation, lost output or failed cleanup
can occur after authority publication. The wrapper reports
`restore_attempted_unknown` rather than rollback, keeps the approval record, never
deletes destination state and never automatically resubmits. Native cancellation
owns its child through termination, escalation and process/pipe closure. Explicit
resume continues only the native `.restore-intent`; it never merges newer state.
An interruption between approval recording and native intent creation can leave
a record without a resumable destination. Preserve and inspect that boundary;
this adapter does not promise automatic recovery from every crash point.

Approval expiry is rechecked after preflight and immediately before submission.
In native signed mode (the only restore mode since 63c9572f) the native side also
observes expiry immediately before its authority publication boundary, and the
receipt reports `approval_effect_time_enforced: true`
([NATIVE_BACKUP_OPERATOR_APPROVAL.md](NATIVE_BACKUP_OPERATOR_APPROVAL.md)). That is
still not an external revocation lease. Confirmed native
completion is not retroactively rolled back by later expiry or lost wrapper
stdout. This is not a canonical authorization or instant-revocation mechanism.
Do not serve partial roots or automatically replay restored outbox/external effects.

### Integration evidence boundary

```sh
node --test tests/operator/repository-backup-approval.test.mjs \
  tests/operator/repository-backup-native.test.mjs
FG_NATIVE_BIN="$PWD/target/release/fg" \
  node --test tests/operator/repository-backup-native.test.mjs
```

Default adapter tests use real Ed25519, filesystem and process operations with a
DELIBERATELY FAKE native contract process and opaque JSON archive fixtures. They
cover native receipt mismatches, exact full-width counters, changed source paths,
expired approval during preflight, preserved unknown publication, cancellation
and reaping, no-fallback behavior, changed resume policy and failed stdout after
confirmed completion. They are not native archive, Rust, durable-backend or
power-loss evidence. The separate actual-`fg` test exports an empty native node,
signs its archive, restores it, and calls native doctor; it is explicitly skipped
unless `FG_NATIVE_BIN` is supplied. No full service/capsule or bead closure claim.

## Native approval enforcement in `fg backup`

The native `fg backup verify` and `fg backup restore` commands also accept the
existing detached approval directly. The command verifies DSSE and Ed25519 in
Rust, using the existing crypto implementation. It does not launch the
JavaScript issuer, a wrapper, Git, or another executable. The archive format and
the native authority, object-graph and payload-commitment checks stay the same.

```sh
fg backup verify backup.fgit /private/new-verification-root --trusted-local \
  --expected-sha256 "$INDEPENDENT_ARCHIVE_SHA256" --verification-instance 900000001 \
  --approval backup.approval.json --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT_HEX" --repository-id "$REPOSITORY_HEX" \
  --incarnation-id "$INCARNATION_HEX" --object-format sha256 \
  --minimum-head-generation "$EXTERNALLY_RETAINED_FLOOR"

fg backup restore backup.fgit /private/new-restored-node --trusted-local \
  --expected-sha256 "$INDEPENDENT_ARCHIVE_SHA256" --destination-instance 900000002 \
  --approval backup.approval.json --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT_HEX" --repository-id "$REPOSITORY_HEX" \
  --incarnation-id "$INCARNATION_HEX" --object-format sha256 \
  --minimum-head-generation "$EXTERNALLY_RETAINED_FLOOR"
```

All seven approval options are required together: `--approval`, `--trust-key`,
`--tenant-id`, `--repository-id`, `--incarnation-id`, `--object-format` and
`--minimum-head-generation`. The independently selected `--expected-sha256`
remains required even in signed mode. Unknown or duplicate options and partial
approval policy refuse. Omitting all seven preserves the existing unsigned,
checksum-pinned command behavior and receipt fields.

The native transfer defaults remain 1 GiB and 300 seconds. The existing
`--max-archive-bytes` permits 1 through 1099511627776 bytes; the native leaf
`--timeout-secs` permits 1 through 86400 seconds. These native limits are distinct
from the JavaScript issuer/wrapper's 3600-second ceiling. The native commands
also accept `--max-blob-bytes` from 1 through 1099511627776 bytes, defaulting to
32 MiB. This independently permits larger blob payloads through chunked native
verification and restore; commit, tree and tag bodies retain their 32 MiB
limit. The total archive ceiling still applies. Authority metadata retains its
independent 64 MiB bound, and the existing object-count/reference/graph limits
remain in force. Selecting larger budgets changes neither the signed archive
identity nor its original payload commitments. Control input is bounded separately to 16 KiB per approval envelope,
4096 bytes per decoded signed payload and 8192 bytes per trusted public-key
file. Reading and verification use one operation deadline; no subsequent
approval check renews it.

For all three repository backup operations, an explicit leading `fg
--timeout-secs` narrows the native leaf timeout. For example, `fg --timeout-secs
30 backup restore ... --timeout-secs 600` has a 30-second effective allowance;
a larger global value cannot widen a smaller leaf value. Fractional global
seconds retain their precision. With no explicit global override the existing
leaf defaults apply. The shared library `run_with_timeout` entrypoint supplies
the same cap without global mutable state; `run` and the compatibility executable
keep their existing defaults. The separate authority-only backup executable is
outside this `fg backup` dispatch.

Before creating verification scratch or reserving a restore intent, the native
command snapshots both control files, authenticates the exact original signed
payload and separate trusted key, checks the external identity and generation
floor, and verifies the approval lifetime. It then verifies the independently
pinned archive through one open input and requires its actual tenant,
repository, incarnation, hash format, head generation, whole-file digest and
byte count to match the signed statement. This prevents an otherwise valid
signature over false operator declarations from authorizing different native
state. Later passes rehash that same pinned input while checking authority,
the selected graph and original payload commitments.

The control files and destination parent are operator-controlled local inputs.
Use stable trusted paths and keep the source, destination and quarantine away
from concurrent mutation or serving. File/path identity checks and the restore
lock do not isolate the command from an adversary with the same filesystem
authority. The public key is supplied independently; a key adjacent to an
untrusted archive does not establish its trust.

### Publication-time approval and exact signed resume

After the quarantined node has verified and closed, approval freshness is
checked again. The final freshness and operation-deadline check runs immediately
before `PreparedPublication::publish`, whose create-only authority-file link is
the visibility boundary. This also applies when an unpublished signed restore
is resumed. Expiry at that point refuses publication and retains the exact
quarantine/intent for diagnosis. This is a cooperative local prepublication
check, not an atomic wall-clock lease, a revocation service, or canonical
authorization. Blocking filesystem calls cannot be interrupted at an exact
deadline instant.

Signed attempts use an 80-byte `FGRES002` `.restore-intent`. In addition to the
archive pin and destination instance, it commits to a domain-separated digest
of the exact original envelope bytes, canonical trusted SPKI bytes and external
namespace, hash format and generation-floor policy. Legacy unsigned attempts
retain the exact 48-byte `FGRES001` encoding. Resume compares the full expected
intent before any quarantine normalization, database open or surviving alias
cleanup. Both signed-to-unsigned downgrade and unsigned-to-signed
reinterpretation refuse. Changing even an independently accepted floor or
reformatting the original envelope changes the signed binding.

Add `--resume` only with the original checksum, destination instance, approval
and trust policy. Each invocation reauthenticates the controls and rechecks
their current lifetime; no cached intent stands in for a signature. A newly
issued or renewed approval requires a new destination rather than changing the
meaning of an existing signed intent. No external approval-record file is
needed for this direct native mode; the binding is part of the native intent
itself.

An already-published resume verifies the exact imported snapshot and objects
without advancing authority tokens. An early resume refusal, including a
missing/changed approval, expired signature or invalid archive, reports that a
prior attempt may already have published authority. After confirmed publication,
later expiry, directory/alias cleanup failure, final verification failure or
receipt-output failure cannot be reported as prevention or rollback. The command
preserves destination state. It never overwrites, merges or rewinds newer work.

### Native receipts and selected validation

Signed successful receipts set outer `signature_verified` to true and add an
`approval` object containing the trusted key ID, exact binding SHA-256, external
minimum generation and full authenticated statement. Existing graph, payload,
reopen/close, scratch-removal or resume fields retain their meanings. The
approval object explicitly reports that newest-checkpoint and complete-capsule
verification are false. Approval receipt formatting does not recheck expiry
after a confirmed publication.

The following commands select the added validation; this documentation does not
assert that a particular checkout has passed them. Use the pinned toolchain and
an isolated Cargo target directory. The native unit campaigns marked ignored
require an explicitly selected Node.js executable solely to run the existing
issuer as a test fixture generator. Their production verify/restore paths are
Rust, and expiry is tested with a per-operation injected wall clock that has no
production or environment-controlled counterpart.

```sh
export CARGO_TARGET_DIR=/data/frankengit-targets/signed-native-backup
cargo test -p fgit-node --lib source_retrieval::backup::repository --locked -- --test-threads=1
FG_BACKUP_APPROVAL_NODE="$(command -v node)" \
  cargo test -p fgit-node --lib resume_engine_tests::signed_tests --locked \
  -- --ignored --test-threads=1
cargo build -p fgit-cli --bin fg --locked
FG_NATIVE_BIN="$CARGO_TARGET_DIR/debug/fg" \
  node --test tests/operator/repository-backup-native-approval.test.mjs
```

Ordinary tests cover complete-policy parsing, independent checksum requirements,
exact versioned intent bytes, changed trust bindings, both directions of signed
mode reinterpretation and truthful resume errors. The selected native campaigns
exercise real JS-issued signatures over native archives in both hash domains,
source-loss recovery, native preflight, exact resumed state, wrong signer,
mutated payload, false signed header declarations, wrong floor and expiry at the
publication boundary. A clock advance after publication checks that completion
remains truthful. The separate real-`fg` process test imports a nonempty source,
exports its archive, deletes the source, then verifies/restores and resumes with
an empty executable search path for every `fg` invocation. It is skipped unless
`FG_NATIVE_BIN` is supplied. These checks do not establish full service or signed
capsule recovery, exhaustive power-loss behavior or the broader bead's closure.

## Native history across activated checkpoints

An existing capsule activation advances the authority head without adding a
decision batch. Native materialization, selected source closure, historical
batch reads, legacy forge/outbox reconstruction, outbox progress and forge-event
pages verify those edges through one shared bounded history reader. The reader
re-identifies the predecessor and inspects the original canonical capsule bytes.
It requires the successor to equal that predecessor with exactly the next
generation, exact predecessor ID and new checkpoint pointer. Every other head
field stays equal, including decision positions and state roots. An actual
decision edge still requires the complete decision-batch verification.

Each checkpoint consumes one predecessor-edge allowance and contributes no
synthetic decision, event or progress record. Missing, corrupt or mismatched
capsule evidence refuses the read. Cancellation is checked around immutable
reads before their results are interpreted. Current-head operations and genuine
historical decision/RCR positions retain their existing meanings. Retained
metadata pagination still enforces its checkpoint-epoch boundary; identifying an
older checkpoint-only head as a separate historical projection position remains
outside this reader integration.

Source-backup authority snapshots retain canonical capsule bodies and predecessor
heads in their existing immutable-body enumeration, subject to the same finite
authority snapshot limits. Restore imports those original bodies before head
publication. The native checkpoint regression exercises real admission on both
sides of activation, close/reopen, source export/restore and exact history/ref/
object readback. The focused contract and admission tests cover malformed edges,
missing evidence, cancellation, deterministic retries and bounded traversal.
These are executable test targets; their presence alone does not establish that
a native execution gate passed.

General signed-capsule archive restore, external-artifact replay and the complete
forge recovery drill remain separate integration work.
