# Independently retained source-recovery witness

The trusted-local source-backup operator can retain authenticated checkpoint
observations between invocations. This closes the previous supplied-set-only
rollback gap: after observing generation 20, a later invocation presenting only
generation 19 cannot select it. It does not implement Repository Capsule restore
or turn a source-backup approval into repository authority.

Related work: `frankengit-root-doctrine-x2mv.4.21`. Normative boundary:
`NORMATIVE_PROTOCOL_CONTRACTS.md` section 23. The signed source-backup profile,
native graph/authority verification, independent trust policy and exact resume
binding remain unchanged.

## Commands

Initialize once in a new directory under an existing owner-private parent:

```sh
node scripts/repository_backup_witness.mjs init /private/recovery-witness \
  --trust-key /private/public.pem \
  --tenant-id 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --incarnation-id 33333333333333333333333333333333 \
  --object-format sha256 --minimum-head-generation 1
```

Use the same directory, key and namespace with `inspect` or `select`. Selection
requires one to 64 `--candidate ARCHIVE APPROVAL` pairs. `inspect` reauthenticates
retained signatures without opening archive payloads. These commands do not
launch a node or change repository state. A stronger independent generation
floor is persisted; a later weaker floor is refused. Key/namespace changes are
not an implicit migration.

## Retained evidence and publication

`witness.json` is at most 64 KiB. Its canonical JSON stores the independent
policy, trusted SPKI key identity and the original signed envelope at the highest
observed generation. Two distinct statements at that generation retain a
persistent ambiguity witness. More conflicting statements need not be retained:
two already establish refusal. Only a strictly higher authenticated generation
supersedes that ambiguity. Equal-statement replicas do not rewrite state.

Every newly authenticated higher observation is synchronized before progress,
expiry checks or archive hashing. Missing, corrupt, expired, future-dated or
currently over-budget artifacts do not erase the remembered generation. An
invalid signature does not ratchet the witness. An earlier valid observation
survives failure to authenticate a later supplied candidate. Every supplied
approval still must authenticate; the selector does not silently drop one.

Updates use private staging, file sync and readback, atomic root-last rename,
and directory sync under an exclusive create-only lease. Missing/corrupt state
is never empty state. A failed update never rewinds a visible replacement.
Ordinary failures release the lease after owned work settles; failed child
containment retains it. File descriptors close even when the lease is retained.

A process crash leaves `.witness-lock` deliberately blocking. There is no
PID-based lock stealing or age-based expiry. Before manually removing this file,
an operator must independently establish that every associated operator and
native process is stopped, preserve and inspect the retained state, and retain
its existing floor. An incomplete initialization is an error, not permission to
reset a witness that may previously have constrained recovery.

## Trust and non-claims

Retain this directory independently from the repository and source archives,
on stable trusted local paths. The filesystem and its owner are trusted to
preserve the latest acknowledged state. Deleting or replacing the entire witness
with an older copy cannot be detected without an external durable trust anchor.
A signature authenticates an observation, not the completeness of a backup
catalog, global freshness, current authority, archive readability or measured
RPO/RTO. The report therefore keeps `newest_checkpoint_verified=false`.

The witness is optional. Unwitnessed legacy selection remains a supplied-set-only
operation and must not claim remembered anti-rollback protection. This is not a
multi-host lock, an authorization database, a forge/external-artifact restore
engine, a background worker or an automatic retry protocol.

## Executable boundary

`node --test tests/operator/repository-backup-witness.test.mjs` exercises actual
Ed25519 signatures, bounded file I/O, durable restart selection, CLI processes,
exclusive ownership and a killed lock owner. Artifacts in these tests are opaque
bytes, not native `fg` archives; passing them does not establish Rust archive,
graph, authority or full recovery execution.

## Native verify, restore and resume

Pass `--witness /private/recovery-witness` to the existing
`scripts/select_repository_backup_native.mjs select|verify|restore` command,
keeping its usual candidate, independently supplied trust and native destination
arguments. Initialization is never implicit. The library equivalent is the
`witness` option on `runSelectedRepositoryBackup`.

The witness lease spans the entire operation: candidate authentication, retained
floor checks, native preflight, signed restore/resume and native child/input
cleanup. A second cooperating operator is refused while any of those phases is
active. Retained higher or conflicting evidence refuses *before* native preflight;
no destination is touched. Failed native containment retains the witness lease.
Missing witnesses on a resume report `existing_unknown`, not rollback. Confirmed
native completion survives later witness cleanup errors via `completed_result`.

Witness storage must be separate from candidates, keys, executables, destination
roots and operator approval records. The native signed-approval bytes, selected
archive digest, independent policy and exact original resume binding are not
rewritten to the witness floor. The witness constrains selection; native Rust
still independently validates the signed statement, archive and authority.

Run both test targets with:

```sh
node --test tests/operator/repository-backup-witness*.test.mjs
```

The integration tests use the unchanged repository's explicitly fake native
protocol peer, with actual child processes, signature verification and private
control files. The opt-in real-source recovery/resume test requires
`FG_NATIVE_BIN=/absolute/path/to/fg`. Without it, the native Rust scenario is an
explicit skip. These tests do not establish full signed-capsule or forge recovery.

## Same-checkpoint replicas and independent read budgets

The witnessed selector retains the concurrent replica failover behavior: it may
try another explicitly supplied copy only when its original signed statement
is identical to the highest selected checkpoint. A missing or corrupt copy does
not justify choosing a lower generation. Retained observations and conflicts
continue to constrain every subsequent invocation, including one where all
newer copies were unavailable or exceeded that invocation's work allowance.

`select_repository_backup_native.mjs` accepts `--max-replica-bytes N` to bound
total payload reads across selection replicas independently of
`--max-archive-bytes N`. Its library equivalent is `maximumReplicaBytes` on
`runSelectedRepositoryBackup`. The default equals the archive limit; the maximum
is 64 TiB across at most 64 candidates. Every archive still has the separate
1 TiB hard ceiling and any smaller caller-selected limit. The aggregate setting
is not forwarded to native verification or restore, does not enlarge their
archive limit, and does not renew the whole-operation deadline.

Separation checks resolve existing path and parent aliases before native work
and again after native-stage observers. The selected archive, approval, trusted
key, executable, destination and operator approval record must not contain or
be contained by the witness. Unavailable lower-generation artifacts and their
parents are not opened by these checks. This prevents an alias from placing the
independently retained witness inside the restore target or vice versa; it is
not a sandbox against an owner concurrently replacing trusted directories.

The witness, replica-composition and native-bridge tests are discovered by the
`repository-backup-witness*.test.mjs` glob above. The native-bridge scenarios
remain protocol-peer tests except the explicitly opt-in `FG_NATIVE_BIN` case.
