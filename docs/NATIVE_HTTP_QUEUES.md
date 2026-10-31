# Authenticated HTTP merge queues

The smart HTTP server exposes durable queue reads, enqueue, dequeue, reorder and
independently authorized fast-forward queue-head landing through the native
repository authority. Writes use the same canonical commands, exact predecessor
checks and recoverable outcomes as `fg queue`. No separate queue database is
introduced.

## Enable the surface

Start the existing smart HTTP server with `--credentials-file` and
`--allow-queues`. Queue access is disabled by default. The listening receipt
reports `queues_enabled`.

Enable queue-head publication separately with `--allow-queue-landings`. It also
requires `--credentials-file` and is disabled by default. Its listening receipt
field is `queue_landings_enabled`. Either deployment switch can be enabled
without the other.

Add the required independent scopes to a credential row:

| Scope | Permission |
|---|---|
| `queues-read` | List queues and read one queue |
| `queues-write` | Enqueue, dequeue and reorder |
| `queues-land` | Fast-forward exactly the first queued PR, subject to its target ref ceiling and canonical protection |
| `outcomes-read` | Recover a prior transaction through the separate outcome API |

The credential scope order extends the existing grammar by appending
`queues-read,queues-write,queues-land` after `artifact-read`. Existing credentials keep
their original permissions. Neither `receive`, PR, review nor merge scopes
implicitly grant queue access. A write-only queue token does not grant reads.
Neither `queues-write` nor `merges-write` grants queue landing, and `queues-land`
grants no reads, membership management, reviews, Git pushes or ordinary PR merges.
The server's static token profile does not grant queue scopes.

The authenticated token supplies the principal. Requests cannot supply an actor,
principal or trusted-local assertion. Queue management changes queue metadata;
it does not publish a ref move, merge a PR or bypass protected merge admission.
A v2 credential with ref-write ceiling `none` can therefore manage queue intent.
Landing requires a ceiling that permits the target branch; selecting only the
source branch is insufficient. The source is read and retained, not rewritten.

Credential files are revalidated using the existing request authentication path.
Revoked tokens, corrupt tables and foreign-incarnation tables refuse. Credentials,
route, grant and deployment ceiling are checked before accepting a request body
or sending `100 Continue`.

## Routes

The paths below follow the configured repository route, for example
`/project.git/api/v1/queues`.

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/queues` | List complete visible queues |
| `GET` | `/api/v1/queues/{number}` | Read one visible queue |
| `POST` | `/api/v1/queues/{number}/enqueue` | Insert or replace an exact PR candidate |
| `POST` | `/api/v1/queues/{number}/dequeue` | Remove an entry with an explicit reason |
| `POST` | `/api/v1/queues/{number}/reorder` | Set the complete nonempty execution order |
| `POST` | `/api/v1/queues/{number}/land` | Atomically fast-forward the exact queue head and merge its PR |

Use `Authorization: Bearer <token>`. Reads accept no body or idempotency header.
Writes require `Content-Type: application/x-www-form-urlencoded` and the original
client `Idempotency-Key` header. Unknown or inapplicable fields, duplicate scalar
fields, malformed encodings and noncanonical integer spellings refuse.

## Exact write coordinates

Every write includes these form fields:

| Field | Meaning |
|---|---|
| `expected_incarnation` | Exact current repository incarnation, lowercase hexadecimal |
| `object_format` | `sha1` or `sha256`, matching the repository |
| `expected_version` | Exact queue version; `0` only for a first enqueue |
| `target_ref` or `target_ref_hex` | Exactly one encoding of the full target branch name |

Enqueue additionally requires `pull_request`, `expected_pull_request_version`,
`source_ref` or `source_ref_hex`, `expected_source_tip`, and
`expected_target_tip`. Optional `priority` is an unsigned 32-bit integer,
defaulting to zero. Object IDs must be nonzero, lowercase and native to the
repository format. The open PR, its exact version, its recorded branches/tips
and both live refs must agree with the request.

```bash
curl --fail-with-body "$BASE/api/v1/queues/1/enqueue" \
  -H "Authorization: Bearer $QUEUE_TOKEN" \
  -H 'Idempotency-Key: enqueue-pr-42-observation-1' \
  --data-urlencode "expected_incarnation=$INCARNATION" \
  --data-urlencode 'object_format=sha1' \
  --data-urlencode 'expected_version=0' \
  --data-urlencode 'target_ref=refs/heads/main' \
  --data-urlencode 'pull_request=42' \
  --data-urlencode 'expected_pull_request_version=1' \
  --data-urlencode 'source_ref=refs/heads/feature' \
  --data-urlencode "expected_source_tip=$SOURCE_COMMIT" \
  --data-urlencode "expected_target_tip=$TARGET_COMMIT" \
  --data-urlencode 'priority=10'
```

Dequeue requires `pull_request` and `reason`, one of `withdrawn`, `conflict`,
`check-failed`, `base-moved`, `evicted` or `admin-override`. Reasons describe the
action and do not grant permissions.

Reorder requires one repeated `entry` field for each current PR, exactly once,
in the intended order. An empty, incomplete, duplicated or foreign membership
refuses. Higher priority normally enters first, with FIFO among equal priorities;
an explicit reorder persists its supplied order.

The target branch remains bound to the queue number after all entries are
removed. An empty existing queue requires its current positive version.

## Exact queue-head landing

The landing form includes every common write coordinate, plus `pull_request`,
`expected_pull_request_version`, `expected_policy_epoch`, exactly one of
`source_ref` or `source_ref_hex`, `expected_source_tip`, and
`expected_target_tip`. The queue, PR and policy versions must be positive. The
queue version must leave room for two events and the PR version for one. The
source and target branch names and tips must be distinct. There is no `priority`
field for landing.

```bash
curl --fail-with-body "$BASE/api/v1/queues/1/land" \
  -H "Authorization: Bearer $LAND_TOKEN" \
  -H 'Idempotency-Key: land-pr-42-observation-1' \
  --data-urlencode "expected_incarnation=$INCARNATION" \
  --data-urlencode 'object_format=sha1' \
  --data-urlencode 'expected_version=5' \
  --data-urlencode "expected_policy_epoch=$POLICY_EPOCH" \
  --data-urlencode 'pull_request=42' \
  --data-urlencode 'expected_pull_request_version=3' \
  --data-urlencode 'source_ref=refs/heads/feature' \
  --data-urlencode 'target_ref=refs/heads/main' \
  --data-urlencode "expected_source_tip=$SOURCE_COMMIT" \
  --data-urlencode "expected_target_tip=$TARGET_COMMIT"
```

Admission verifies that this is the first queued PR, its open canonical state
and version match, the recorded and live branch tips agree, and the selected
policy epoch is current. It proves target ancestry from native Git objects and
enforces current branch policy, required reviews and workflow checks. A transport
grant supplies permission to submit; it cannot supply an approval or successful
check. There is no merge-method fallback, force option, bundle upload or
caller-supplied batch result in this endpoint.

Successful landing moves the target to the existing source commit and publishes
queue `BatchFormed`, PR `MergeCommittedNative`, and queue `BatchLanded` together
in one Repository Commit Record. The queue advances by two versions, the PR by
one, and remaining entries retain their order. No source ref, synthetic ref or
new commit is created. Divergent candidates refuse this fast-forward profile.

## Read consistency and bounds

List queries accept `limit=1..100` (default `50`), `after`, and `expected_head`.
Use the first page's `snapshot_token` as `expected_head` for continuation;
`after` greater than zero requires it. Single-queue reads also accept
`expected_head`. Tokens pin one retained repository head across later ordinary
publications. An unavailable snapshot returns a typed conflict; it is never
silently replaced by current state.

Current hidden-ref policy applies before disclosure, including for a retained
snapshot. If a target or any source entry is hidden, the entire queue is hidden.
Single hidden and absent queues share the same `404` response. Responses include
lossless `*_ref_hex` fields for non-UTF-8 reference names.

The command body is bounded to 64 KiB, the queue to 1,024 entries, and complete
JSON responses to the smaller of 8 MiB and the server response limit. The native
history scan bounds documented in [NATIVE_MERGE_QUEUE.md](NATIVE_MERGE_QUEUE.md)
also apply. Request a smaller list page if its complete response is too large.

## Terminal outcomes and retries

A committed write returns `200`; a canonical refused write returns `409` with
the transaction ID, decision sequence and refusal identity. A write receipt
describes that original decision. Management reports `refs_changed: false`;
landing reports `true` only for a committed decision and includes the immutable
landing guards and `method: "fast-forward-only"` in `proposed_action`. It does
not perform a latest-state read after publication. Use a separate read for
today's queue state.

If a response is lost, retry the identical body with the same token principal
and `Idempotency-Key`. Recovery retains the original outcome after later queue
edits and process restart. Changing bytes while reusing a key refuses. Do not
refresh versions or replace the key while recovering an ambiguous attempt.
The outcome API is independently available when enabled with `--allow-outcomes`
and granted `outcomes-read`, including to a principal without queue scopes.

Every landing request revalidates its current deployment and credential grants.
The v2 target reference ceiling is checked before admission, including an
identical retry. If a token's ceiling no longer permits the target, resubmission
returns `403 ref_write_scope_denied`; use separately granted `outcomes-read`
with the original principal and key to recover the historical outcome. This
does not reauthorize the write. A refusal solely from the ceiling binds no
transaction, so the same command and key may be submitted after the operator
grants the target. These are the same rules as the other
[HTTP reference publishers](HTTP_REF_WRITE_SCOPES.md).

Authentication, malformed-envelope and resource errors are not canonical queue
refusals. A transport failure or `outcome_unknown` response is not evidence that
the publication did not commit. The existing outcome and identical-retry
contracts apply.

## Implementation and focused tests

The adapter lives in `fgit-node/src/smart_http/server/queues`; it invokes
`OneNode::admit_queue_durable_in` and the canonical snapshot APIs directly.
Landing invokes `OneNode::land_queue_head_durable_in` with the credential's
authenticated session and unchanged original key.
`crates/fgit-node/tests/queue_http.rs` exercises real TCP requests, both object
formats, live credential changes, exact retries, disconnect recovery, pagination,
restart and unchanged refs. Parser tests cover hostile envelopes and bounded
forms. Test source presence does not imply that a particular revision passed.
`crates/fgit-node/tests/queue_landing_http.rs` exercises real TCP landing in both
hash domains, atomic ref/PR/queue post-state, stale and nonhead refusals, actual
candidate review, target scope expansion and narrowing, independent outcome
recovery, lost responses and process restart. Parser and credential tests cover
strict fields, version exhaustion, equal-tip rejection and independent grants.
