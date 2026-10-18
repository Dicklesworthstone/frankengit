# Signed backup redundancy replenishment

Related bead: `frankengit-root-doctrine-x2mv.4.21` (partial, not closed).
Comprehensive plan: §20.6 (scrub evidence), §21.6 (verified recovery materials),
§21.8 (independently controlled recovery copies).

[Scrubbing](SIGNED_BACKUP_SCRUB.md) detects damaged copies. Replenishment creates
replacement copies in explicitly selected private directories using the existing
[replica publisher](SIGNED_BACKUP_REPLICA_PUBLICATION.md). It does not overwrite
or delete the damaged originals, repair canonical object-fabric placement,
re-sign an archive, run native `fg`, or change repository authority or routing.
A conflict at an existing content-addressed output refuses: nominate a fresh
location instead of expecting automatic destructive repair.

## One command, one signed checkpoint

```sh
node scripts/replenish_repository_backups.mjs \
  --candidate /source/repository.backup /source/repository.approval \
  --replica-directory /backup-a/repository \
  --replica-directory /backup-b/repository \
  --trust-key /trusted/operator-ed25519.pub \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --max-archive-bytes 1073741824 --max-total-read-bytes 9663676416 \
  --progress-json
```

All 1..16 destination directories must already exist, be owner-private, and
support no-follow opens, create-only hard links, file synchronization and
directory synchronization. Destination order is canonical, not caller order.
Aliased/nested directories and duplicate directory identities refuse before the
first publication. Open directory identities remain checked across the operation.
Place copies under independently controlled storage according to operator policy;
the implementation does not prove that two directories have independent failures.

All supplied approvals authenticate, and the highest uniquely signed checkpoint
is selected before any destination is written. Missing or corrupt payloads may
use another copy of that same signed statement, never an older checkpoint.
The exact selected envelope digest and independently trusted key ID are pinned
across every subsequent copy. Substituting another valid checkpoint, key or
serialization cannot retarget later copies. Each publication still performs
full signature, freshness, hash, length, readback and durability checks.

After publication, the complete output set is scrubbed again. Success requires
every destination's original approval bytes and a distinct authenticated file
at each location. Late corruption, changed approvals and hard-link aliases
cannot be hidden by an earlier successful publication receipt. This sequential
verification is not a simultaneous snapshot or a guarantee of future availability.
The original selected source must remain available until copying finishes;
previously completed output can be nominated explicitly as a retry's source.

## Partial completion and exact restart

Exit **0** returns one complete JSON report. Exit **1** is a refusal or incomplete
operation, not rollback: inspect `replenishment.completed_replicas`,
`active_destination`, the active publisher's `publication_state`, `replica`, and
cleanup information. The group is deliberately **not atomic**. Confirmed copies
are recorded before callbacks or the next destination begins and are never
removed to simulate rollback. Exact existing files are read back and synchronized
without rewriting their inode. Bad conflicting files are not replaced.

For a restart of the original intent, append:

```sh
--checkpoint "$ORIGINAL_APPROVAL_SHA256" "$ORIGINAL_TRUSTED_KEY_ID"
```

The two strings come from the original report's `checkpoint`, a partial error
report, or the `checkpoint_pinned` progress record. Pins only constrain intent;
they do not authorize untrusted/expired/below-floor input or bypass native checks.
Without a pin, a new invocation selects again from its supplied set. There is
no durable multi-destination job index or automatic discovery of old outputs.

`--progress-json` emits at most 17 milestone records on stderr: one checkpoint
pin before copying, followed by each confirmed destination. A broken progress
stream refuses further work. A broken final stdout stream retains the completed
result in the error protocol. Loss of either channel never proves non-publication.
SIGTERM/SIGINT request drain; a hard process kill can leave owned temporary files.
A subsequent invocation neither claims nor deletes that killed process's scratch.

## Independent retained checkpoint witness

Append `--witness DIRECTORY` to use an existing independently initialized
[checkpoint witness](RECOVERY_CHECKPOINT_WITNESS.md). Its exclusive lease spans
selection, copying, output scrubbing and owned descriptor cleanup. Higher or
conflicting signed observations remain constraining on subsequent runs, even
when their archive is unavailable. Missing/corrupt state and killed-owner leases
refuse; no reset, lock stealing, PID-age heuristic or unsigned fallback exists.

The witness must be physically separate from destinations, the independent key,
and the selected source/control files. Parent aliases are checked before backup publication
and again after observers. Stable, owner-controlled parents remain a requirement;
this is not containment against malicious same-user filesystem writers. The
witness records retained recovery evidence, not canonical repository authority
or proof of the newest checkpoint beyond the explicitly supplied/retained set.

## Bounded work and evidence

`--max-archive-bytes` limits one archive, at most 1 TiB. The separate total read
budget covers initial source selection, each publisher's source authentication,
copying, destination readback, and final output scrub. At most 64 source candidates
and 16 destinations are admitted; total payload allowance is capped at 128 TiB.
Small control reads and bounded one-byte EOF probes have separate fixed bounds.
The default is `(1 + 4 × destinations) × archive ceiling`.

After source selection, fresh-copy worst-case work for **all** targets and the
final scrub must fit before any target is staged, including on retries. For two
fresh destinations and a healthy N-byte source, exactly 9N payload bytes suffice;
9N−1 refuses before publication. Reusing both outputs actually reads 7N, but the
same conservative upfront reservation still applies. A corrupt source probe
adds its actual payload reads. A larger aggregate budget never raises a single
archive limit. One monotonic deadline spans the witness and every phase.
Trusted observers and pipe consumers must make progress; they are not preempted.

Run the focused tests:

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-replication.test.mjs \
  scripts/tests/repository-backup-replenishment.test.mjs \
  scripts/tests/repository-backup-replenishment-cli.test.mjs
```

Tests use actual Node processes, filesystem operations, Ed25519 approvals,
retained witness state, SIGTERM and SIGKILL with child reaping, and exact restart
through the real CLI. Payloads are opaque test bytes, **not native `fg` archives**.
No Rust build, native archive/forge restore, whole-workspace gate, independent
failure-domain assurance, hardware-power-loss guarantee, global-currentness or
complete capsule recovery is established by these operator tests.
