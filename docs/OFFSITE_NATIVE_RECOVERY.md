# Offsite acquisition through signed native recovery

Related bead: `frankengit-root-doctrine-x2mv.4.21` remains partial.
Comprehensive plan sections 21.3, 21.6 and 21.8 require verified recovery materials,
independently retained checkpoint constraints, and a native restore boundary.

`recover_repository_backup.mjs` connects the existing HTTPS downloader and local
replica publisher to the existing signed native backup adapter. One existing
checkpoint witness remains exclusively owned across acquisition, native preflight,
restore/resume, socket and child drain, and control-file cleanup. The operator
neither parses a native archive nor implements a competing authority store.
A downloaded or cached file is never by itself permission to restore a repository.

## Restore from an explicit offsite source

Initialize the independent witness separately through
`scripts/repository_backup_witness.mjs init`. Choose an existing private cache
and stable, owner-controlled parent directories for the new native destination
and its separate approval record. Keep the Ed25519 key and original signed
approval independent of the source URL file and the cache.

```sh
node scripts/recover_repository_backup.mjs restore \
  --cache-directory /private/recovery-cache \
  --sources /private/backup-source-urls.json \
  --approval /independent/repository.approval.json \
  --trust-key /independent/operator-ed25519.pub \
  --witness /independent/checkpoint-witness \
  --fg /absolute/path/to/fg --trusted-local --verification-instance 11 \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --destination /private/restored-repository --destination-instance 12 \
  --approval-record /private/native-restore-approval.json \
  --max-archive-bytes 1073741824 --max-acquisition-bytes 4294967296 \
  --timeout-secs 300 --progress-json
```

The source file has the same bounded private JSON-array format as
[SIGNED_BACKUP_HTTPS_ACQUISITION.md](SIGNED_BACKUP_HTTPS_ACQUISITION.md).
The existing downloader enforces TLS verification, explicit mirror preference,
exact signed content, protocol refusals, URL redaction and bounded transfer.
An optional `--ca-file` supplies an independently trusted private-service CA.
Raw signed URLs are never command arguments or diagnostic fields.

Use `verify` instead of `restore`, omitting `--destination`,
`--destination-instance`, `--approval-record` and `--resume`, to execute native
signed preflight only. The cache can be populated in either mode. The native
`fg backup verify` command owns its verification scratch, and the existing
adapter validates the exact signed identity and the complete native receipt.
`verify` never submits a native restore.

## Native handoff and retained trust

All options, policy fields and paths are snapshotted before the first await.
Every native integer and operation choice is validated before file/network work;
the actual content-addressed cache paths then enter the complete existing native
option validator before remote acquisition. No dummy paths or guessed native
receipts stand in for validation.

The independently supplied approval is inspected and its signed observation is
retained before freshness, archive-size, cache or remote-availability checks.
Expired, unavailable and oversized higher checkpoints remain constraining after
failure. Invalid signatures do not become observations. The witness must require
the exact retained statement; equal-generation conflicts and a weaker retained
minimum cannot be bypassed by cache reuse or by `--resume`.

The original approval digest and independent trusted-key ID are passed as equality
pins to both the acquisition/publisher and the native adapter. Another valid
approval cannot retarget the native call after acquisition. The adapter reopens
and authenticates the acquired bytes, stages the original signed controls, runs
native verification, records the exact restore intent, and invokes native restore
only after its preflight. Native signed checks, source commitments, authority
publication, exact resume and receipt validation remain native responsibilities.
No native failure triggers a different mirror, checkpoint or automatic native retry.

Lexical and resolved physical paths separate the witness, cache, native
destination and approval record from one another and from original input/control
files and the native executable. The cache directory remains open and its identity
is checked across phases. Parent redirection and cache-directory replacement are
rechecked after trusted observers. This detects observed changes, not malicious
same-user writes between arbitrary filesystem operations: stable owner-controlled
ancestors and a trusted executable remain requirements.

## Offline continuation and exact resume

A correctly named cached archive is reauthenticated and synchronized through the
existing replica publisher, not accepted on filename or existence. A missing
cached approval can be published from the original independently signed envelope
after the archive bytes verify. Wrong bytes, unsafe permissions, symlinks or
conflicting cached approvals refuse. They never authorize overwriting the cache
or silently downloading a replacement over conflicting files.

A cache hit does not read the URL or TLS-CA file and opens no network connection.
These flags may be omitted entirely when the acquired archive remains available.
The independent approval, Ed25519 key and witness are still required. The operation
can therefore continue after signed URLs expire or their files are removed.
Nonexistent paths explicitly left in the command must still have stable existing
parents for physical separation checks.

After an interrupted native restore, repeat the original destination, destination
instance, approval record and policy, adding:

```sh
--resume --checkpoint "$ORIGINAL_APPROVAL_SHA256" "$ORIGINAL_TRUSTED_KEY_ID"
```

Take the pins from the original complete/partial receipt or the
`checkpoint_pinned` progress record. The existing version-2 native approval record
must match exactly; neither destination changes nor re-signed input are a resume.
A repeated native command is an explicit original-intent resume, not an inferred
rollback or a new-key retry. The native adapter still runs preflight and verifies
its `already_published` result. The operator adds no second restore engine or
parallel persistent job database.

If no native restore was attempted and no approval record exists, a fresh restore
can consume the verified cache. A missing archive requires an explicit URL source
file; there is no directory listing, remote discovery or trust in an abandoned
partial download. The command processes one signed approval, not a global latest
checkpoint search. Independently retained observations cannot reveal newer
checkpoints the operator has never observed.

## Failure, drain and result delivery

A confirmed acquisition is recorded before calling a progress observer or native
preflight. Errors retain the original checkpoint, expected candidate, acquisition
receipt, phase, native state and available native completion information. Failed
native restore may have published: inspect `state`, the native approval record and
the native resume result instead of deleting the destination.

Exit **0** means the requested native operation completed and its report was
delivered. Exit **1** means refusal, interruption or uncertainty; it is not rollback.
Exit **4** means native completion was observed but local cleanup or report delivery
failed. `completed_result` or `native_receipt` retains that knowledge. The result
includes `native` (the existing adapter's validated receipt), `acquisition`,
`checkpoint`, `candidate`, and `recovery_witness`. A completed acquisition alone
never qualifies for exit 4 or native completion.

With `--progress-json`, at most six redacted phase records are written to stderr.
A broken progress channel refuses further work. A broken final stdout channel
retains the completed result through the error protocol when stderr is available.
SIGTERM/SIGINT request the existing network and child drain. The witness lease is
released only after those owners and local resources settle. A SIGKILL or failed
child containment can leave the witness lease blocking; no lock stealing, PID-age
heuristic, reset or deletion of unknown children is introduced. A killed parent is
not proof that remote work or a separately grouped native child has stopped.

## Bounds and verification scope

The per-archive limit (default 1 GiB, maximum 1 TiB) remains distinct from the
acquisition payload limit (default four times the archive limit, maximum 19 TiB).
The latter covers the existing downloader/publisher or cache publisher only. For
a healthy N-byte source, fresh acquisition uses 4N payload work; verified cached
reuse uses 2N. Native preflight and restore retain their existing engine limits and
are **not** included in acquisition read accounting. One monotonic cooperative
deadline covers the whole operation; child drain retains the process owner's
separate bounded shutdown phase. Filesystem calls, trusted observers and output
consumers must themselves make progress; they are not forcibly preempted.

Run focused verification:

```sh
node --test --test-concurrency=1 \
  scripts/tests/repository-backup-recovery.test.mjs \
  scripts/tests/repository-backup-recovery-cli.test.mjs \
  scripts/tests/repository-backup-download.test.mjs \
  scripts/tests/repository-backup-download-cli.test.mjs \
  scripts/tests/repository-backup-replication.test.mjs
```

Tests use actual TLS, Ed25519 signatures, files and reaped command/child processes.
The executable native-schema peer is explicitly **not fg** and does not parse
archives or implement authority. Its output directory is labelled as a fixture,
not a restored repository. Tests establish operator composition, exact bindings,
owned lifetimes and preservation of observed results; they do not establish Rust
compilation, native Git/forge restore, actual authorization/CAS, full-workspace
acceptance, public-provider interoperability, hardware power-loss behavior,
independent failure domains or complete capsule recovery. The native receipt's
existing `authority_and_selected_git_objects` scope remains unchanged; routing,
external effects and complete capsule restoration are not claimed.
