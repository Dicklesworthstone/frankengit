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

## Approved native verification and restore

The native operator path now composes the detached approval with the existing
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
It is a submission gate, NOT a lease enforced at the native authority publication
instruction. `approval_effect_time_enforced` remains false. Confirmed native
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
