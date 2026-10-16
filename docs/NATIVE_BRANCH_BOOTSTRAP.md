# Create-only native branch bootstrap

FG-049 (`frankengit-fg049-github-compat-xdo`): establish historical destination
branch coordinates before PR migration. This external operator uses the existing
[HTTP branch API](HTTP_BRANCH_API.md) and original-key outcome reader. It does
not implement Git, transfer objects, update/delete refs, grant permissions or
replace native reachability, branch protection or authority-CAS checks.

## Command-line workflow

Use an explicit private selection file with the shape below, then retain the
returned `plan_sha256` independently:

```sh
node scripts/bootstrap_native_branches.mjs prepare \
  --workdir /srv/import/branch-job \
  --selection /srv/import/branch-selection.json \
  --token-file /srv/import/branch-writer.token

node scripts/bootstrap_native_branches.mjs inspect \
  --workdir /srv/import/branch-job --confirm "$BRANCH_PLAN_SHA256"

node scripts/bootstrap_native_branches.mjs run \
  --workdir /srv/import/branch-job --confirm "$BRANCH_PLAN_SHA256" \
  --token-file /srv/import/branch-writer.token --max-operations 100
```

`inspect` returns the complete retained requirements and validated journal
summary; `status` returns the progress summary without the complete selection.
Neither needs credentials or accesses the network. `run` continues a paused
batch with the same plan. A missing result is recovered, not resent. Explicit
original-key recovery and retry are distinct operations:

```sh
node scripts/bootstrap_native_branches.mjs recover \
  --workdir /srv/import/branch-job --confirm "$BRANCH_PLAN_SHA256" \
  --token-file /srv/import/recovery.token

node scripts/bootstrap_native_branches.mjs run \
  --workdir /srv/import/branch-job --confirm "$BRANCH_PLAN_SHA256" \
  --token-file /srv/import/branch-writer.token --retry-key "$ORIGINAL_PENDING_KEY"
```

All commands accept `--timeout-ms` from 1 to 300,000. The same invocation deadline
covers selection/plan reading, validation, preparation, network work and output.
Received native observations still drain to bounded local result custody after
network cancellation. `run`/`recover` accept a private `--ca-file` for the existing
certificate-verified HTTPS transport. There is no token-value argument, ambient
credential discovery, arbitrary URL override, or unbounded automatic retry.

Exit **0** means the selected operation succeeded; prepare, requirements, status
and inspect can succeed without any branch being created. For execution, **0**
means every original create has been confirmed committed, **1** means a native
refusal, and **3** means an incomplete ready/paused/unresolved batch. **2** reports
argument/preflight refusal. **4** reports an error with a retained or potentially
published plan/result: inspect the reported original pin, never infer rollback.
Output is terminal-control escaped and bounded to 8 MiB (to accommodate escaped
1 MiB selections), with at most a 10-second output wait within the command
budget. Error diagnostics retain a completed result after an output failure.

## Derive requirements from an existing PR migration

A [prepared native PR migration](NATIVE_PULL_IMPORT.md) already contains exact
source and target branch coordinates. The bootstrap adapter uses its unchanged
full loader: authenticate the manifest pin, validate the complete retained source
archive, reconstruct every PR operation, and check all original request keys and
bodies. It never consumes an unchecked metadata snippet or edits a PR request.

Choose per-PR destination refs under the intended bootstrap namespace when
originally preparing the PR migration, for example:

```json
"pull_ref_map": [
  {
    "source_number": "9",
    "source_ref": "refs/heads/import/project/pr-9/source",
    "target_ref": "refs/heads/import/project/pr-9/base"
  }
]
```

Inspect the complete derived branch requirements without generating any key or
contacting either repository. The branch principal is selected independently;
it is never inferred from a source actor or from the PR writer's permissions:

```sh
node scripts/bootstrap_native_branches.mjs requirements \
  --migration-dir /srv/import/prepared-pulls \
  --migration-confirm "$PR_PLAN_SHA256" \
  --namespace refs/heads/import/project/ \
  --principal "$BRANCH_PRINCIPAL_HEX32"

node scripts/bootstrap_native_branches.mjs prepare-pulls \
  --migration-dir /srv/import/prepared-pulls \
  --migration-confirm "$PR_PLAN_SHA256" \
  --namespace refs/heads/import/project/ \
  --principal "$BRANCH_PRINCIPAL_HEX32" \
  --workdir /srv/import/branch-job \
  --token-file /srv/import/branch-writer.token
```

Both commands are offline. The selection retains the exact destination endpoint,
repository identity, incarnation and Git hash domain of the pinned PR plan, with
the explicitly selected branch principal. Equal requirements for the same ref
and tip are deduplicated; conflicting tips for one ref refuse. Every requirement
must be inside the explicit namespace. A main/base branch outside it is not
silently skipped or assumed to exist. An occupied branch, even at the desired
tip, is still a native create-only refusal.

The returned `requirements_sha256` commits the complete normalized selection;
its origin binds `PR_PLAN_SHA256`. `prepare-pulls` publishes an independent branch
plan and returns its new `plan_sha256`, which must be used for branch execution.
The PR plan's original keys remain unchanged. The resulting branch job can be
inspected, run and recovered after the source archive, PR migration directory,
and PR writer credential have been removed; it retains its complete requirements.
Once branch creation is confirmed, run the original PR migration separately with
its original pin. This command never opens a PR or submits an approval/merge.

This is a bounded nonempty create-only profile, not automatic repair of an
arbitrary destination. A legacy PR plan with conflicting historical tips remains
inspectable/recoverable through the PR operator but refuses branch bootstrap.
A plan naming refs outside the selected namespace requires separately supervised
provisioning. Configure appropriate mappings before preparing/submitting a new
migration; do not regenerate a plan to escape an unresolved original request.
Git objects must still be imported separately and remain accessible through
visible native history. Branch creation cannot make hidden-only or unknown
objects available. Later branch movement is still checked by native PR admission;
bootstrap completion is historical evidence, not a retention lock on the refs.

## Library workflow

`prepareBootstrap` from `scripts/lib/branch-bootstrap.mjs` takes `workdir`,
`tokenFile`, and an explicit selection:

```json
{
  "endpoint": "https://destination.example/repo",
  "scope": {
    "tenant_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "repository_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "repository_incarnation": "cccccccccccccccccccccccccccccccc",
    "principal_id": "dddddddddddddddddddddddddddddddd",
    "object_format": "sha1"
  },
  "namespace": "refs/heads/import/project/",
  "refs": [
    {
      "ref": "refs/heads/import/project/pr-9/source",
      "new_commit": "1111111111111111111111111111111111111111"
    },
    {
      "ref": "refs/heads/import/project/pr-9/base",
      "new_commit": "2222222222222222222222222222222222222222"
    }
  ]
}
```

Select scope independently of source actors. Every branch must be a child of the
explicit namespace; this profile requires a named namespace below `refs/heads/`.
Only `POST /api/v1/source/branches/create` can be sent. There is no force,
expected-old override, rename, delete, implicit tip refresh or fallback.
The target must be absent even if an occupied branch has the desired tip.
The commit must already be authorized and reachable through visible native
history. Import the Git objects separately. Receive and outcomes-read grants
are required for execution; PR-write authority does not imply either grant.

Preparation is offline and validates the entire selection before generating
keys. It saves the sorted requirements, original credential fingerprint and
all exact requests under a new private directory, re-reads them, and publishes
`manifest.json` last. Retain the returned `plan_sha256` independently. Requests
are bound to endpoint, repository incarnation, principal, hash domain, namespace,
exact ref and tip, credential fingerprint, nonce and original key. These local
commitments are retry custody, not native transaction IDs or authorization.

`runBootstrap({workdir, confirm, tokenFile, maxOperations})` verifies the whole
plan before any network operation. Its default allowance is 100 operations;
one operation uses at most an outcome lookup, a create request and a confirmation
lookup. Pass the same pin to continue a bounded batch. Native refusal stops the
batch without touching later branches. Earlier commits are not rolled back.

Before dispatch, an exclusive attempt directory and synchronized `started.json`
reserve the original key. Lost output or process death leaves an unknown request,
not permission to resend. An ordinary subsequent run only recovers that key.
`operation: "recover"` never submits a mutation or starts an unattempted branch.
`retryKey` requires explicit consent for the exact currently unresolved original
key; the original body and credential remain mandatory. An existing publication
or terminal prevents another create. No absent outcome proves non-commit.

`bootstrapStatus({workdir, confirm})` validates the plan and entire journal
without credentials, network requests or explicit writes. Complete plans can
also run offline. Completion means every original create was confirmed committed;
it does not prove the refs still have those values after later writes/deletions.
PR admission must still check its exact source and target tips.

## Failure and resource boundaries

All paths are absolute, owner-private POSIX paths outside Git worktrees. Existing
output is not overwritten. Requests, attempt reservations and results are
create-only; gaps, unexpected files, torn records, changed directory identities
or contradictory native observations refuse. Concurrent runners arbitrate
attempt slots instead of stealing process locks. Compatible late nonterminal
observations cannot erase an already observed terminal.

A rotated token may recover only when the response identifies the original
principal. It cannot create a later branch or resend an original body. Tokens
are never saved in plans or results. HTTP is limited to numeric loopback;
remote endpoints require certificate-verified HTTPS, with no redirects or
ambient credentials. Native response text is not included in diagnostics.

Limits are 8,192 branches, 1 MiB per selection/manifest, 16 KiB per request and
response, 64 MiB aggregate request files, 32 attempts per branch, 32,768 attempts
per job and 32 MiB of journal contents including capacity reserved for missing
results. A result is bounded to 64 KiB. Limits count file contents, not filesystem
block overhead. The deadline (at most 300 seconds) spans an invocation's full
preflight and network work. A received result is finalized locally even after
network cancellation; an interrupted finalizer leaves retained suspect custody.
These checks do not claim a hostile-same-UID sandbox or power-loss durability.

## Verification

```sh
bash scripts/verify_native_branch_bootstrap.sh
```

The tests execute unchanged production outcome decoding/HTTP and private-file
helpers with the new compiler, sender, coordinator and journal. Loopback peers
implement explicit response-schema fixtures, not Rust fg or native Git semantics.
They cover both Git domains, full u64 decision sequences, exact-key restarts,
refusals, credential rotation, concurrent runners, corrupted/torn custody,
cancellation and cumulative attempt limits. The 8,192-branch case is compiler
and request-validation coverage, not a native server capacity measurement.
No Rust/admission/CAS, deployed service, hardware durability or full-workspace
verification is claimed. No Rust or dependency files are changed.

The CLI/bridge suite also runs the complete unchanged production PR preparer,
archive validator, request compiler and loader; no substitute loader or partial
source extraction is used. A static archive fixture supplies API observations,
not Git objects or server authority. Tests cover SHA-1/SHA-256 requirement
extraction, shared bases, per-PR and byte-only ref mappings, conflicting legacy
bases, explicit branch-principal selection, original PR key preservation, and
branch execution after source removal. Real Node child processes receive
SIGTERM/SIGINT/SIGKILL during committed response-schema peer replies and recover
in fresh processes without duplicate branch POSTs. A 101-branch HTTP batch spans
the default 100-operation allowance. Late concurrent weaker observations,
redirects, response bounds, wrong principals, broken/stalled output and strict
CLI argument refusals have explicit tests. This remains JS operator/HTTP-schema
and private-file validation, not Rust server/admission/CAS or maximum-capacity
HTTP performance evidence.
