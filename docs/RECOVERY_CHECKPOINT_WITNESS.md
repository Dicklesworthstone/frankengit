# Independently retained source-recovery witness

The trusted-local source-backup selector can retain authenticated checkpoint
observations between invocations. After observing generation 20, a later
invocation presenting only generation 19 cannot select it. This is recovery
memory, not repository authority, global freshness proof or Repository Capsule
restore. Related bead: `frankengit-root-doctrine-x2mv.4.21`; normative boundary:
`NORMATIVE_PROTOCOL_CONTRACTS.md` section 23.

## Commands

Initialize once under an existing owner-private parent:

```sh
node scripts/repository_backup_witness.mjs init /private/recovery-witness \
  --trust-key /private/public.pem \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --incarnation-id 33333333333333333333333333333333 \
  --object-format sha256 --minimum-head-generation 1
```

Use the same directory, key and namespace with `inspect` or `select`. Selection
requires one to 64 `--candidate ARCHIVE APPROVAL` pairs. Inspection authenticates
retained signatures without opening archive payloads. These commands do not
launch a node or restore repository state. Missing/corrupt witnesses are never
silently initialized. A stronger independent floor is persisted; weakening it
or changing the trusted key/namespace is refused, not treated as migration.

## Persistence and ownership

The canonical `witness.json` is bounded to 64 KiB and holds original signed
observations. Two distinct statements at the highest generation retain a
persistent ambiguity; only a strictly higher authenticated generation supersedes
it. Identical-statement replicas do not rewrite state. Every authenticated
higher observation is synchronized before progress callbacks, expiry checks or
archive hashing. Missing, corrupt, expired, future-dated or over-budget artifacts
cannot erase that observation; an invalid signature cannot advance it.

Updates use private staging, sync, readback, atomic root-last rename and directory
sync under an exclusive create-only lease. The callback owns the lease through
its complete operation. Competing operators refuse immediately. Ordinary failure
releases the lease after owned work settles; failed child containment retains it
while closing local descriptors. A crash leaves `.witness-lock` blocking. There
is no age/PID-based lock stealing: independently establish that all associated
processes stopped and preserve the retained evidence before manual intervention.

## Verification and non-claims

Run `node --test tests/operator/repository-backup-witness.test.mjs`. Tests use
actual Ed25519 signatures, private filesystem operations, CLI processes, restart
selection and a killed lock owner. Test artifacts are opaque bytes, not native
`fg` archives. This does not establish Rust archive/graph/authority execution.

Retain the directory independently from repositories and archives on stable,
trusted owner-controlled local paths. Replacing the entire witness with an older
copy is outside this trust model and requires an external anchor to detect.
Signatures do not prove backup-catalog completeness, global currentness, present
readability, RPO or RTO. Reports retain `newest_checkpoint_verified=false`.
Unwitnessed selection remains supported and reports supplied-set-only semantics.
This is not a multi-host lock, authority database or complete forge recovery.
