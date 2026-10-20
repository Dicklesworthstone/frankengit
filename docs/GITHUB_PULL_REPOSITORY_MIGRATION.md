# Whole-collection GitHub PR destination migration

FG-049 (`frankengit-fg049-github-compat-xdo`), comprehensive plan §31.3.
A completed [GitHub PR collection](GITHUB_PULL_COLLECTION.md) can now select one
bounded destination migration instead of requiring separately numbered manual
preparation and execution of every capture. This is an external operator that
composes the existing capture validators, PR compiler, private request slots,
original-key sender and outcome journal. Native authorization and publication
remain exclusively server-owned.

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
