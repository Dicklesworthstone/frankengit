# Signed checkpoint replica scrub

Related bead: `frankengit-root-doctrine-x2mv.4.21` (partial, not closed).
Plan references: comprehensive plan §20.6 (scrub evidence), §21.3 and §21.6
(highest trusted checkpoint selection and independently verified recovery).

Selection stops at a usable replica. That is useful for recovery but does not
establish the health of the remaining copies. The scrub operation shares the
selector's approval authentication, full-width generation ranking, immutable
candidate snapshot, optional retained witness, and bounded file scanner. It
checks **every supplied copy of the highest uniquely signed checkpoint** and
reports later-copy corruption even when the first copy is healthy.

## Run a health check

```sh
node scripts/scrub_repository_backups.mjs \
  --candidate /backup-a/repository.backup /backup-a/repository.approval \
  --candidate /backup-b/repository.backup /backup-b/repository.approval \
  --trust-key /trusted/operator-ed25519.pub \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --minimum-distinct-files 2 \
  --max-archive-bytes 1073741824 --max-replica-bytes 2147483648 \
  --timeout-secs 300
```

Exit **0** means the complete scan authenticated every current-checkpoint copy
and met the requested distinct-file count. Exit **2** means the scan completed
but copies were unavailable/corrupt or too few distinct files were verified.
Both produce a complete JSON report on stdout. Exit **1** means refusal or an
incomplete operation: inspect stderr, not an assumed healthy result. A failed
result-pipe write preserves `completed_result` when the scan had already finished.

The report includes each attempted path and reason, aggregate read accounting,
full-width checkpoint generation, the authenticated candidate-set commitment,
and separate counts of authentic candidate paths and distinct verified files.
A corrupt or missing approval is a fatal trust failure, not a corrupt payload
that can be silently skipped. Equal-generation signed conflicts also refuse.

## Retain observations across runs

Append `--witness /independent/recovery-witness` to use an **existing** witness
initialized through `scripts/repository_backup_witness.mjs init`. The witness
key and floor are external inputs, not learned from candidate names or contents.
The existing exclusive lease spans approval inspection and byte scrubbing, and
is drained on ordinary errors/cancellation. A killed owner leaves its lease
blocking; no timeout/PID guessing, lock stealing or automatic reset is added.

Signed newer and conflicting observations are retained before artifact and
freshness checks. A later command therefore cannot omit an unavailable or
expired newer checkpoint to obtain a healthy result for an older one. Missing,
corrupt or differently bound witness state refuses. Physical parent aliases are
checked so source/control paths do not overlap the independent witness directory.
Stable owner-controlled parent directories remain a required trust boundary.

Without a witness, archive and approval files are read-only and no persistent
anti-rollback memory is created. Even with a witness, omitted evidence never
observed locally is not detected: global newest-checkpoint and candidate-set
completeness claims remain false. The witness is recovery evidence, not a second
repository authority or an authorization grant.

## Work, identity and applicability limits

At most 64 explicit candidate pairs are accepted. Every supplied approval must
authenticate in the same namespace before payload reads. Only the highest
uniquely signed statement's copies are scrubbed; lower-checkpoint candidates are
counted as not scrubbed and their payloads are never opened as fallback.

`--max-archive-bytes` caps an individual archive. `--max-replica-bytes` caps total
payload reads and defaults to the archive ceiling; checking several large copies
requires an explicit larger allowance. Before another copy is opened, its full
signed length must fit the remaining work budget. Two N-byte copies fit exactly
2N payload bytes; a 2N-1 budget produces an incomplete report, never success after
only one copy. Bounded control reads and one-byte EOF probes are separate. One
monotonic deadline/cancellation signal covers signature, witness and scan work.
Trusted library progress callbacks and consumers of stdout must themselves make
progress; they are not sandboxed or preempted by that deadline.

Each file is streamed with a 64 KiB buffer and checked for exact signed length,
SHA-256 digest, regular-file type and stable open/named metadata. Final-component
symlinks are not followed. Device/inode observations come from that verified read
interval, not a separate pre-scan lookup. Hard links and path aliases therefore
cannot inflate `distinct_authenticated_files` or satisfy a larger minimum count.

**Distinct files are not independent failure domains.** The scan is sequential,
not an atomic multi-file snapshot or a lease on future availability. A signed
artifact hash does not prove native archive semantics. The report explicitly
sets native verification, simultaneous availability, independent failure domains,
global currentness and candidate-set completeness claims to false. This operator
surface neither launches `fg` nor restores, repairs, deletes, re-signs or publishes
repository state. Existing native verification remains mandatory before restore.

## Local verification

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-replicas.test.mjs \
  scripts/tests/repository-backup-scrub.test.mjs \
  scripts/tests/repository-backup-scrub-cli.test.mjs
```

The focused tests use actual files, Ed25519 approvals, CLI subprocesses and the
existing persisted witness. They include a killed/reaped scrub owner, restart
anti-rollback, signature/expiry/floor refusals, duplicate-inode accounting,
corruption after the first healthy copy, exact resource bounds, cancellation,
path substitution and failed output delivery. Payloads are opaque operator test
bytes, **not native `fg` archives**; no native restore, Rust workspace, hardware
power-loss or full recovery acceptance is implied by these tests.
