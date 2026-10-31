# Authenticated HTTP merge queue management

The smart HTTP server exposes durable queue reads, enqueue, dequeue and reorder
through the native repository authority. Writes use the same canonical commands,
exact predecessor checks and recoverable outcomes as `fg queue`. No separate
queue database is introduced.

## Enable the surface

Start the existing smart HTTP server with `--credentials-file` and
`--allow-queues`. Queue access is disabled by default. The listening receipt
reports `queues_enabled`.

Add the required independent scopes to a credential row:

| Scope | Permission |
|---|---|
| `queues-read` | List queues and read one queue |
| `queues-write` | Enqueue, dequeue and reorder |
| `outcomes-read` | Recover a prior transaction through the separate outcome API |

The credential scope order extends the existing grammar by appending
`queues-read,queues-write` after `artifact-read`. Existing credentials keep
their original permissions. Neither `receive`, PR, review nor merge scopes
implicitly grant queue access. A write-only queue token does not grant reads.
The server's static token profile does not grant queue scopes.

The authenticated token supplies the principal. Requests cannot supply an actor,
principal or trusted-local assertion. Queue management changes queue metadata;
it does not publish a ref move, merge a PR or bypass protected merge admission.
A v2 credential with ref-write ceiling `none` can therefore carry queue scopes.
There is no HTTP queue landing route in this profile.

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
describes that original decision and reports `refs_changed: false`. It does not
perform a latest-state read after publication. Use a separate read for today's
queue state.

If a response is lost, retry the identical body with the same token principal
and `Idempotency-Key`. Recovery retains the original outcome after later queue
edits and process restart. Changing bytes while reusing a key refuses. Do not
refresh versions or replace the key while recovering an ambiguous attempt.
The outcome API is independently available when enabled with `--allow-outcomes`
and granted `outcomes-read`, including to a principal without queue scopes.

Authentication, malformed-envelope and resource errors are not canonical queue
refusals. A transport failure or `outcome_unknown` response is not evidence that
the publication did not commit. The existing outcome and identical-retry
contracts apply.

## Implementation and focused tests

The adapter lives in `fgit-node/src/smart_http/server/queues`; it invokes
`OneNode::admit_queue_durable_in` and the canonical snapshot APIs directly.
`crates/fgit-node/tests/queue_http.rs` exercises real TCP requests, both object
formats, live credential changes, exact retries, disconnect recovery, pagination,
restart and unchanged refs. Parser tests cover hostile envelopes and bounded
forms. Test source presence does not imply that a particular revision passed.
