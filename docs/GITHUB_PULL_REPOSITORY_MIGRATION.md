# Whole-collection GitHub PR destination migration

FG-049 (`frankengit-fg049-github-compat-xdo`), comprehensive plan §31.3.
A completed [GitHub PR collection](GITHUB_PULL_COLLECTION.md) can now select one
bounded destination migration instead of requiring separately numbered manual
preparation and execution of every capture. This is an external operator that
composes the existing capture validators, PR compiler, private request slots,
original-key sender and outcome journal. Native authorization and publication
remain exclusively server-owned.

## Command-line workflow

Use `scripts/migrate_github_pull_collection.mjs` with the completed source
collection, the existing destination selection JSON shape below, and the native
PR writer token. Source GitHub credentials are not used by this command:

```sh
node scripts/migrate_github_pull_collection.mjs prepare \
  --collection-dir /srv/import/pr-collection \
  --collection-confirm "$COLLECTION_PLAN_SHA256" \
  --complete-confirm "$COLLECTION_COMPLETE_SHA256" \
  --selection /srv/import/destination.json \
  --workdir /srv/import/repository-migration \
  --token-file /srv/import/native-pr-writer.token

node scripts/migrate_github_pull_collection.mjs run \
  --workdir /srv/import/repository-migration --confirm "$MIGRATION_SHA256" \
  --token-file /srv/import/native-pr-writer.token --max-operations 100

node scripts/migrate_github_pull_collection.mjs status \
  --workdir /srv/import/repository-migration --confirm "$MIGRATION_SHA256"
```

`MIGRATION_SHA256` is preparation's new outer `plan_sha256`. Repeat `run` with
that same pin after a paused result. `inspect` and `status` both perform complete
offline source, child and journal validation. `recover` uses the same workdir/pin
and an optional native recovery token, without submitting a successor. Explicit
resubmission is `run --retry-key "$ORIGINAL_PENDING_KEY"`, never a new plan.
Network commands accept a private `--ca-file` for the existing HTTPS transport.

Preparation accepts lower `--max-steps` and `--max-request-bytes` ceilings. Every
command accepts `--timeout-ms` from 1 to 300,000, including file preflight and
output. Native results still drain to bounded local custody after network
cancellation. JSON output escapes terminal controls and is bounded to 8 MiB;
output waits are at most ten seconds within the remaining command allowance.
A broken output stream retains its completed result and original pins in a
bounded error diagnostic rather than repeating work.

Exit **0** means a successful selected command or completely committed execution.
Preparation/inspection/status may succeed while reporting incomplete migration.
Execution exit **1** is a native refusal, **3** is a ready/paused/unresolved result,
**2** is argument/preflight refusal, and **4** reports retained/verified custody or
an uncertain output result. Always inspect `complete`, `state` and the original
current key; no exit code proves rollback.

The `batch` command returns a selected original child without executing it. To
emit a private create-only branch selection for that batch instead:

```sh
node scripts/migrate_github_pull_collection.mjs requirements \
  --workdir /srv/import/repository-migration --confirm "$MIGRATION_SHA256" \
  --batch 2 --principal "$BRANCH_PRINCIPAL_HEX32" \
  --out /srv/import/branches-batch-2.json
```

Use that file with the existing branch bootstrap `prepare` command and its
independent writer credential. The diagnostic returns both the outer migration
pin and original child pin; retain the new branch plan pin separately. Existing
output files refuse instead of being overwritten. This does not provision Git
objects, execute any branch request or send a PR implicitly.

## Prepare once, retain one outer plan

The library entrypoint is `scripts/lib/github-pull-migration.mjs`:

```js
const prepared = await prepareGithubPullMigration({
  workdir: '/srv/import/repository-migration',
  collectionDir: '/srv/import/pr-collection',
  collectionConfirm: independentlyRetainedCollectionPlanSha256,
  completeConfirm: independentlyRetainedCollectionCompleteSha256,
  selection: {
    endpoint: 'https://destination.example/repo',
    scope: {
      tenant_id: '11111111111111111111111111111111',
      repository_id: '22222222222222222222222222222222',
      repository_incarnation: '33333333333333333333333333333333',
      principal_id: '44444444444444444444444444444444',
      object_format: 'sha1'
    },
    number_start: '1000',
    namespace: 'refs/heads/import/github/',
    merged: 'refuse',
    drafts: 'refuse'
  },
  tokenFile: '/srv/import/native-pr-writer.token'
});
```

Both source pins are required. A collection plan pins membership and limits;
its separately retained completion pin also commits the captured content.
Preparation verifies the complete collection, compiles every capture and checks
the whole destination-number window before creating a single request key. It
never refreshes source data, repartitions batches, skips unsupported PRs or
contacts the destination. Every destination counter uses exact u64 arithmetic.
The starting number applies to the whole inventory: each batch begins at that
number plus its original zero-based first-member index.

The source collection is copied privately and revalidated. Each child under
`batches/batch-NNNNNN` is an ordinary unchanged GitHub PR import job with its own
capture, request keys, manifest and execution journal. The outer `manifest.json`
binds source completion, normalized destination selection, original credential
fingerprint, every child plan pin, counts and aggregate limits. It is published
last, only after full source/child/journal readback. Independently retain the
returned **`plan_sha256`**, which is different from both source pins.

Preparation is one-shot and offline, **not resumable partial preparation**.
A failed preparation retains its partial directory and any child keys; no root
means it is not an executable whole migration. Existing directories are never
overwritten, repaired or assigned replacement keys. Do not execute partial
children or mix manual child sends with the coordinator. Existing original-key
recovery remains available for separately supervised recovery where necessary.
No completed plan may be regenerated to escape uncertain destination outcomes.

## Ordered execution and recovery

```js
await executeGithubPullMigration({
  workdir: prepared.workdir, confirm: prepared.plan_sha256,
  operation: 'run', tokenFile: '/srv/import/native-pr-writer.token',
  maxOperations: 100
});

await executeGithubPullMigration({
  workdir: prepared.workdir, confirm: prepared.plan_sha256,
  operation: 'status'
});
```

Every invocation validates the retained collection and **all** child plans and
journals before networking. Attempted later batches past an unresolved earlier
batch refuse. Execution delegates to the existing native PR executor in order;
only a completely committed child permits the next. The operation allowance
(default 100, maximum 8,192) is shared across batches, not renewed at each child.
One operation is a sender or outcome lookup; the existing sender performs at
most one mutation POST plus its preflight and confirmation lookups. The single
1–300,000 ms invocation deadline includes all preflight and child work.

Missing receipts remain unknown. Normal resumption recovers the original key,
never automatically resends. An explicit `retryKey` must match the current
pending original key; consent cannot apply to another batch or successor step.
The original credential is required for sends. A rotated credential may recover
only the independently retained original principal. `operation: 'recover'`
performs no mutation and stops after its child recovery, even when that recovery
completes the child; it does not submit the next batch.

The existing exclusive child attempt reservations arbitrate concurrent runners.
There is no new outer progress database, lock to steal, request format or source
of authority. Status is derived from original child observations, preserving
compatible terminal evidence and rejecting contradictions. Native refusals stop
later work; earlier committed operations remain committed. This is **not an
atomic whole-repository migration** and has no automatic rollback.

`status` is offline, validates the entire plan/journal and reports committed
steps/batches, unresolved attempts and the exact current original key. A completed
migration also returns from `run` without credentials or network access. The
original collection directory and source credentials may be removed after
preparation; the whole migration retains its required source content.

## Branch and Git prerequisites

`githubPullMigrationBatch({workdir, confirm, batch})` returns the original child
path, plan pin, capture pin and exact destination-number start after whole-plan
validation. Supplying an independently selected `principal` also returns that
child's unchanged branch-bootstrap selection and its requirements hash. This
never alters child keys or submits branch mutations. Requirements are bounded
per batch, not combined into an oversized bootstrap selection.

Git objects and exact destination branches must still be provisioned separately
through the existing native transfer/bootstrap workflows. Unknown, hidden-only,
fork-only or deleted tips do not become reachable merely because an archive
contains their OIDs. Branch creation and subsequent PR admission remain native
policy decisions. Source titles/bodies, explicit merged/draft consent and
attribution-only reviews retain the existing compiler's semantics. Only open,
comment and close requests are generated: no approval, merge, actor impersonation
or backdated native audit history.

## Bounds and verification

The source keeps its existing 10,000-PR, 64 MiB collection and individual 100-PR,
2,000-record, 1 MiB capture ceilings. The whole migration is additionally limited
to **32,768 steps** and **128 MiB of intent content**; preparation options
`maxSteps` and `maxRequestBytes` may lower these. The outer manifest is at most
4 MiB. Each child still enforces the original 8,192-step / 64 MiB intent ceiling.
Full intent-size checking may refuse during offline preparation; no executable
outer root or destination send is produced. Source captures exist in the retained
collection and their child jobs; filesystem block overhead is not counted.

Attempt/journal ceilings remain **per child**: 32 attempts per step, at most
32,768 attempts and 32 MiB of journal/reserved-result content per child. This
coordinator does not claim a new shared whole-migration journal-byte quota.
Received child observations drain locally after network cancellation. Damaged,
partial, unexpectedly linked or aliased files refuse without automatic repair.
Private-file checks do not establish hostile-same-UID isolation or physical
power-loss durability.

```sh
bash scripts/verify_github_pull_repository_migration.sh
```

The tests execute the full original compiler, source/child loaders, sender and
journal with real private files and loopback HTTP response-schema peers. Source
fixtures are constructed with the existing capture transport and canonical
collection codecs; they are not live GitHub snapshots. Native destination peers
do not implement Git, authority or policy. Tests cover shared operation budgets,
exact number windows, refusal before requests for invalid late batches, corrupt
later children, lost replies, original-key retry, rotated credentials, concurrent
runners, source removal and independent branch requirements. No native Rust
server, reachability/admission/CAS, deployment, maximum-population throughput,
full-workspace or completed FG-049 gate is claimed.

The combined suite also drives real Node CLI processes through preparation,
requirements, bounded execution and offline status. A 101-PR/202-operation HTTP
case spans five original batches and the default 100-operation boundary. Actual
SIGTERM/SIGINT/SIGKILL during later-batch committed peer responses recover in fresh
processes without duplicate mutation POSTs. A SIGTERM during offline preparation
retains original child keys but cannot produce an executable incomplete outer
root. Recomputed outer pins do not waive child scope, partition or total checks.
These are operator consistency tests, not native engine or hardware fault tests.
