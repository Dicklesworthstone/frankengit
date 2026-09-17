# Native reference discovery and branch lifecycle over HTTP

The source gateway supports discovering direct refs and creating, advancing,
deleting and atomically renaming branches. This completes the missing branch
step in a remote read -> topic branch -> source edit -> PR workflow. These
operations call the existing `list_refs_in`, `list_branch_refs_in`,
`list_tag_refs_in` and `admit_branch_updates_durable_in` node interfaces.
There is no HTTP-local ref database or new publication/transaction identity.

This is an implemented bounded interface, not a passing Rust build or a claim
that the live interoperability/concurrency tests have run at this revision.
The deployment remains loopback-only with operator-managed credentials.

## Enable and authorize

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants \
  --allow-source --allow-receive --allow-outcomes
```

Use the canonical URL from the readiness record as `REPO_URL`. The repository
must already exist. The reloadable credential file remains bound to its exact
incarnation. No new scope or listener flag is introduced:

| Operation | Token grant | Deployment ceiling |
|---|---|---|
| Ref listing | `read` | `--allow-source` |
| Branch create/update/delete/rename | `receive` | `--allow-source` and `--allow-receive` |
| Original transaction recovery | `outcomes-read` | `--allow-outcomes` |

A receive-only token cannot list refs, inspect files, or prepare source edits.
A read-only token cannot mutate a branch. PR/review/merge grants imply neither.
Every mutation requires an explicit `Idempotency-Key`; ref listing rejects that
header because it does not create a transaction. Forwarded identity headers
never authenticate. Rotation retains retry identity when the principal stays
the same; different principals using the same textual key have separate scopes.
Revocation affects subsequent authentications, not already authenticated work.

Authentication, deployment/grant checks and quotas precede `100 Continue` and
body intake. Branch operations use mutation quota; listing uses the separate
source-read quota. Outcome recovery retains its independent quota.

## Discover current direct refs

```text
POST {REPO_URL}/api/v1/source/refs
```

Use application/x-www-form-urlencoded. `object_format` is required and must
match the repository (`sha1` or `sha256`). Optional fields:

- `namespace`: `all` (default), `branches`, or `tags`.
- `limit`: canonical decimal 1 through 100; default 50.
- `after`: full last ref name from the previous page, within this namespace.
- `expected_head`: exact `snapshot_token`; required whenever `after` is present.

```sh
curl --fail-with-body --header @/secure/source-reader.headers \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'namespace=branches' \
  --data-urlencode 'limit=50' \
  "$REPO_URL/api/v1/source/refs"
```

The `source_refs` JSON response contains repository/incarnation/hash domain,
source_head, snapshot_token, namespace, after, limit, next_after and `refs`.
Each row has `ref`, authoritative lowercase `ref_hex`, and native `object_id`.
`ref` retains the original UTF-8 text or is null for a non-UTF-8 name; `ref_hex`
always preserves the exact bytes. Branch-publication updates use the same pair.
Rows are byte-ordered and current canonical hidden-ref rules apply before
counting disclosed rows. No symbolic HEAD row or implicit tag peeling is added;
a direct tag can point at a tag object rather than a commit.

Carry `next_after` as `after` and the original token as `expected_head` when
continuing. A null cursor means the selected namespace has no further visible
rows. These are strict current-head pins, not retained historical pagination.
Any intervening publication can return 409 `source_snapshot_moved`, rather than
mixing pages. Reopening preserves a token only while that head remains current.
Unknown/corrupt evidence is an error, never an empty ref list.
The request accepts only UTF-8 `after`, not a byte cursor. If a page would need
a non-UTF-8 continuation, it returns 503 `repository_unavailable`, never a null
cursor falsely indicating completion. Non-UTF-8 rows otherwise remain readable.

## Create a topic branch

```text
POST {REPO_URL}/api/v1/source/branches/create
```

Required fields: `object_format`, `ref`, `new_commit`. The full ref must be in
`refs/heads/`. The destination must be absent; this precondition is built into
the native request, not an optional client hint.

```sh
curl --fail-with-body --header @/secure/branch-writer.headers \
  --header 'Idempotency-Key: topic-create-1' \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/heads/topic' \
  --data-urlencode "new_commit=$BASE_COMMIT" \
  "$REPO_URL/api/v1/source/branches/create"
```

The commit must already be verified and reachable through visible selected
history, including permitted ancestors. A digest alone grants no object access;
unknown, hidden-only or non-commit objects cannot become branch tips here.
This endpoint does not accept a PACK or introduce objects.

## Advance or delete an exact branch

```text
POST {REPO_URL}/api/v1/source/branches/update
POST {REPO_URL}/api/v1/source/branches/delete
```

Update requires `object_format`, `ref`, `expected_commit`, `new_commit`.
Delete requires `object_format`, `ref`, `expected_commit`.
Every OID must be nonzero lowercase hex in the declared native domain. No
unspecified expected-old, zero sentinel, force flag or implicit current-tip
refresh is accepted. Updates use ordinary non-forced admission and canonical
ref protection. Deleting the authority-selected default branch is refused.

For a newly generated, unstaged commit, use the existing `/source/apply` bundle
operation described in `HTTP_SOURCE_CHANGE_API.md`, not a branch update that
merely names the object. Preparation/inspection still grant no write authority.

## Atomically rename

```text
POST {REPO_URL}/api/v1/source/branches/rename
```

Required fields: `object_format`, `ref`, `expected_commit`, `new_ref`.
The two names must be distinct full branches. Rename lowers to exactly one
expected-tip deletion and one absent-destination creation of the SAME commit.
Both commands share one seal, one TxId, and one terminal admission decision.
It is never implemented as independently published delete/create HTTP calls.

```sh
curl --fail-with-body --header @/secure/branch-writer.headers \
  --header 'Idempotency-Key: topic-rename-1' \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/heads/topic' \
  --data-urlencode "expected_commit=$REVIEWED_TIP" \
  --data-urlencode 'new_ref=refs/heads/topic-renamed' \
  "$REPO_URL/api/v1/source/branches/rename"
```

An occupied destination, moved source, policy refusal or competing publication
cannot publish only half the rename. The default branch cannot be renamed by
this API: it does not alter HEAD configuration. Branch operations also do not
rewrite PR metadata or emit a fabricated PR transition. Update a PR explicitly
with its new source name and expected PR version when appropriate; old candidate
subjects/approvals do not silently acquire different branch coordinates.

## Outcomes and retry semantics

HTTP 200 `branch_publication` contains `atomic: true`, `terminal: true`, one
tx_id and decision_sequence, the committed repository_commit_id and submitted
updates. Rename has two update entries but ONE decision. HTTP 409 with the same
receipt type and `outcome: refused` is an authenticated canonical refusal.
`forge_transition: false` distinguishes this from a coupled PR merge.

The same principal, key and semantic request recover the original result after
branch movement, deletion or restart. They do not replay a creation to resurrect
a deleted branch. Key reuse with different semantics returns a request-level
409 `idempotency_key_reuse`, not a new canonical decision.

After losing a receipt, the original principal can use an outcomes-read token:

```sh
curl --fail-with-body --request POST --header @/secure/recovery.headers \
  --header 'Idempotency-Key: topic-rename-1' \
  --header 'Content-Length: 0' \
  "$REPO_URL/api/v1/outcomes"
```

Use the ordinary transaction selector, NOT non-atomic receive command/session
selectors. A rename is atomic. Recovery does not need either branch to still
exist or permission to write. Missing/undecided evidence is not rollback.

Request-level errors use `source_error`. Invalid forms/media, wrong domains,
unsafe names, duplicate or inapplicable fields and truncated HTTP are rejected.
Pre-admission default-branch restrictions return 409 `branch_operation_refused`;
non-commit targets return 409 `branch_target_not_commit`. These are not invented
terminal decisions. An awaited authority failure, timeout or failed response
construction after admission remains outcome-unknown; recover the same key.

Forms are bounded to 256 KiB, ref pages to 100 entries, and complete responses to
1 MiB or the configured server ceiling, whichever is smaller. Full fixed-length
or chunked HTTP framing must finish before authority work. No successful partial
list/receipt is returned. The native graph/validation and listener work limits
still apply; no detached task, new dependency or alternate runtime is introduced.

## Focused verification

```sh
cargo test -p fgit-node --lib smart_http::server::source
cargo test -p fgit-node --lib treefs_workspace::branches
cargo test -p fgit-node --test branch_http --test source_change_http \
  --test source_http --test outcome_http --test smart_http_server
```

The new TCP scenarios cover both native formats, fixed/chunked requests, branch
lifecycle, rename destination conflict, two competing renames, source/default
branch invariants, unchanged forge/outbox/object state, key conflicts, forgotten
client receipts, restart, credential rotation/revocation, principal isolation,
read-only recovery, malformed input and auth denial before body intake. Test
presence is not evidence of execution. Hosted IAM, retained ref-list snapshots,
remote default-branch configuration and tag mutation remain separate work.
