# Create-only native branch bootstrap

FG-049 (`frankengit-fg049-github-compat-xdo`): establish historical destination
branch coordinates before PR migration. This external operator uses the existing
[HTTP branch API](HTTP_BRANCH_API.md) and original-key outcome reader. It does
not implement Git, transfer objects, update/delete refs, grant permissions or
replace native reachability, branch protection or authority-CAS checks.

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
