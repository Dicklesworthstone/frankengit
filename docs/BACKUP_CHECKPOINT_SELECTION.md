# Select a signed repository checkpoint without fallback

Related: plan 21.5–21.8 and `frankengit-root-doctrine-x2mv.4.21` / `.4.44`.
This implements selection within an explicit candidate set, not signed Repository
Capsules, a complete archive catalog, key rotation, or the newest global head.

`selectRepositoryBackup(candidates, trustKey, policy, options)` accepts 1–64
explicit `{input, approval}` pairs and the existing independently supplied
public-key, tenant, repository, incarnation, object-format and generation-floor
policy. It reads no directories or remote services. Paths locate bytes; input
order, filenames, timestamps and unsigned metadata never rank checkpoints.
Every descriptor and policy is captured before the first asynchronous operation.

Every supplied approval must authenticate through the existing Ed25519/DSSE
verifier in that exact namespace. Invalid signatures, foreign identities,
unreadable approvals and malformed statements fail the whole selection, rather
than silently removing part of the operator's requested set. The signer and
resource bounds never come from an approval. The detached approval format and
ordinary single-archive verification behavior are unchanged.

Selection compares the authenticated full-width generation integers BEFORE
checking the winner's expiry, external minimum, size or artifact availability.
A newer signed checkpoint with an expired approval, missing/corrupt artifact,
future issue time or over-budget size is a refusal, never a reason to recover
an older checkpoint. Missing or expired *lower* artifacts do not interfere with
a usable higher checkpoint; only the winning artifact is opened and hashed.
The configured byte budget applies to that artifact, while approval inspection
retains the existing absolute one-TiB signed-size ceiling.

Distinct signed statements at the highest generation are ambiguous and refuse.
This is not an accusation of signer misconduct: repeated export or approval
renewal may legitimately differ. This bounded profile does not invent a renewal
or same-generation merge policy. The operator must explicitly narrow the set.
Identical signed statements at different supplied locations are aliases, chosen
in deterministic path order, with their count retained. There is no automatic
replica/path failover; a missing selected alias also refuses.

A shared bounded deadline and cancellation signal cover all approval reads,
signature checks and selected-artifact hashing. Hashing uses the existing 64-KiB
streaming reader, with inode/type/size/change checks. The selected approval's
validity is checked again after hashing and through the returned `checkCurrent`.
Signature-only inspection has a deliberately different return shape and labels
its unchecked validity; ordinary `verifyRepositoryBackupApproval` still checks
validity before returning an authentication result.

The read-only report includes the selected paths, exact approval SHA-256,
trusted-key ID, signed statement, policy, deterministic candidate-set digest and
all inspected candidate identities. `newest_checkpoint_verified` and
`candidate_set_completeness_verified` stay false: an omitted backup cannot be
discovered from supplied files. Retain the independent generation floor elsewhere.
The report is not authority, a native content check or a pinned file handle.
Downstream consumers must reauthenticate and enforce its exact approval/key pins,
then use native archive/authority/graph validation. No saved report alone can
authorize restore, publish routing, or replay external effects.

## Executable coverage

```sh
node --test tests/operator/repository-backup-selection.test.mjs
```

The tests run real Ed25519 operations and filesystem reads, including full-u64
selection, permutations, ambiguity, missing/corrupt/expired newer checkpoints,
old unavailable archives, forged/foreign approvals, cancellation, one deadline,
mutable callers and over-16-MiB hashing. Artifacts are explicitly opaque bytes,
not native archive fixtures. These tests do not establish Rust execution, native
restore correctness, catalog completeness or power-loss durability.

## Operator selection, native verification and restore

The executable entrypoint provides three operations over the same selection:

```sh
node scripts/select_repository_backup_native.mjs select \
  --candidate /backup/checkpoint-a.fgit /backup/checkpoint-a.approval.json \
  --candidate /backup/checkpoint-b.fgit /backup/checkpoint-b.approval.json \
  --trust-key /independent/backup-public.pem \
  --tenant-id "$TENANT_HEX" --repository-id "$REPOSITORY_HEX" \
  --incarnation-id "$INCARNATION_HEX" --object-format sha256 \
  --minimum-head-generation "$EXTERNALLY_RETAINED_FLOOR"
```

`select` authenticates the explicit set and winning artifact, prints its report,
and performs no native invocation or destination writes. It does not verify the
archive's internal graph or authority. Use `verify` to additionally run the
existing native preflight, with these extra arguments:

```sh
  --fg "$PWD/target/release/fg" --trusted-local --verification-instance 900000001
```

Use `restore` to preflight and restore the selected checkpoint, adding:

```sh
  --destination /private/restored-node --destination-instance 900000002 \
  --approval-record /private/restore-approval.json
```

The last two snippets are arguments appended to the first command, replacing its
`select` operation. Native instance IDs must satisfy the native engine's existing
positive-SQL-integer and source-instance rules. Destination and approval-record
parents must already be owner-private. `--max-archive-bytes` sets the selected
artifact budget; `--timeout-secs` sets one 1..3600-second allowance for selection,
reauthentication, native preflight, approval recording and restoration combined.
SIGINT/SIGTERM request cancellation through the existing child owner, which
terminates, escalates and reaps rather than dropping the active process.

`runSelectedRepositoryBackup` validates the full native grammar for EVERY
possible candidate before source I/O, then selects once. It passes the exact
selected raw approval hash and independently authenticated key ID as additional
constraints to `runApprovedRepositoryBackup`. That existing runner reauthenticates
key, statement, policy and artifact, rejects changed selection pins, and performs
all native checks. A different valid lower artifact and its valid signature at
the same filenames cannot pass this boundary. These equality constraints never
substitute for a current signature or native validation. Native preflight refusal
also never triggers another selection or a lower-checkpoint retry.

Add `--resume` to `restore` to use the native exact-intent recovery protocol.
The set is freshly authenticated and selected on every invocation. A different
highest statement, signer, destination or generation floor cannot match the
original private restore-approval record and refuses before restore. Identical
signed statements at another path may still describe the same original operation.
This does not silently switch an interrupted destination to a newer checkpoint.
A newly observed unusable higher checkpoint still blocks fallback on resume.

The existing restore record, authority-last publication, uncertain-outcome and
post-completion rules remain unchanged. Lost replies/cancellation retain state;
failed stdout after confirmed completion preserves the complete result. There is
no automatic repair, record replacement, destination deletion or external-effect
replay. Approval expiry gates submission, not the exact native publication
instruction. Never serve incomplete roots. See `SIGNED_REPOSITORY_BACKUPS.md`
for the existing restore envelope and retained-state limitations.

Run the composition tests with the core tests:

```sh
node --test tests/operator/repository-backup-selection.test.mjs \
  tests/operator/repository-backup-selected.test.mjs
```

Composition tests use real Ed25519, CLI/child processes and filesystem operations,
but reuse the explicitly fake native contract process and opaque JSON artifacts.
They do not run the Rust engine. They cover both hash formats, full-u64 receipts,
valid-checkpoint substitution, native refusal/contradictory reports, exact resume,
changed floors, cancellation/reaping and failed output after completion. Removing
only the two new equality guards makes three targeted regressions fail while the
artifact-corruption test still passes; ordinary signature/hash checks alone do
not enforce selection continuity. No Rust build, backend, power-loss, global
catalog completeness or performance claim follows from these adapter tests.
