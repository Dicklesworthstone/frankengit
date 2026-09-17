# Native release tags over HTTP

The source API can create lightweight and annotated tags, delete exact tag
objects, and inspect recursively peeled native tag chains. It calls the existing
`OneNode::admit_tag_durable_in` and `read_tag_in` engines. There is no HTTP-local
tag database, external Git process, alternate publication mechanism, or new
transaction identity. Metadata becomes native Git tag bytes, which the existing
quarantine validates before ordinary sealed ref admission.

This documents implemented interfaces, not a passing Rust build or executed HTTP
acceptance result. The deployment remains the bounded, loopback-only,
operator-managed credential profile. Full hosted IAM, TLS, release assets,
OpenAPI generation and cryptographic tag-signature verification are separate.

## Deployment and permissions

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants \
  --allow-source --allow-receive --allow-outcomes
```

Use the canonical repository URL in the readiness record as `REPO_URL`.
Provision the existing private, incarnation-bound credential table with
`--print-credentials-header`. No new scope or deployment switch is introduced.

| Operation | Token grant | Deployment switches |
|---|---|---|
| Inspect a tag or list tag refs | `read` | `--allow-source` |
| Create/delete a tag | `receive` | `--allow-source` and `--allow-receive` |
| Recover the original decision | `outcomes-read` | `--allow-outcomes` |

A receive-only principal cannot inspect code or annotations. A read-only
principal cannot create/delete tags. PR/review/merge permissions do not imply
either grant. The tagger string is Git content, NOT the authenticated principal;
HTTP responses explicitly distinguish them. Forwarded identity headers never
authenticate. Current canonical hidden-ref policy and original-target visible
reachability still apply. A bare OID cannot authorize undisclosed original data.

Read queries use the source-read quota. Mutations use the normal publication
quota; recovery retains its independent quota. Credential rotation/revocation
applies to subsequent authentications. In-flight requests retain their bounded
grant. Static-token and older source-disabled node entry points stay disabled.

## Envelope and exact byte encodings

```text
POST {REPO_URL}/api/v1/source/tags/lightweight
POST {REPO_URL}/api/v1/source/tags/annotated
POST {REPO_URL}/api/v1/source/tags/delete
POST {REPO_URL}/api/v1/source/tags/inspect
```

All accept complete `application/x-www-form-urlencoded` bodies (optionally
`charset=utf-8`), with fixed-length or chunked HTTP framing. No multipart upload,
pack upload, local clone or checkout is needed. URLs have no query parameters.
`Git-Protocol` is not applicable. Bodies are capped at 256 KiB. The entire
framing boundary must complete before command parsing or native admission.

Every request requires `object_format` (`sha1` or `sha256`, matching the repo)
and EXACTLY ONE of `ref` or `ref_hex`. The latter is lowercase hexadecimal for
the complete raw ref name, allowing non-UTF-8 names without lossy conversion.
The name must be a valid full `refs/tags/*` ref of at most 4,096 bytes. Responses
use `ref_hex` as the authoritative name encoding; do not assume it is UTF-8.

Every OID is lowercase, nonzero and in the declared native hash domain.
Duplicate scalar fields, unknown/inapplicable fields, ambiguous name encodings,
unsafe ref names and implicit force/overwrite options are refused. All mutation
requests require a client-selected `Idempotency-Key`. Inspection rejects that
header: a read creates no mutation or durable inspection session.

Authentication, deployment/grant checks, declared-body limits and applicable
quota precede `100 Continue`. No success is sent merely because a tag object
was constructed or staged.

## Create a lightweight tag

In addition to the common fields, provide `target`, the exact native object OID.
The destination is required to be absent; there is no overwrite operation.
The target may be a visible native commit, tree, blob or annotated tag. No new
annotation object is synthesized. A lightweight alias of an annotated tag
naturally exposes that object's chain when inspected.

```sh
curl --fail-with-body --header @/secure/tag-writer.headers \
  --header 'Idempotency-Key: release-v1-lightweight-attempt-1' \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/tags/v1' \
  --data-urlencode "target=$COMMIT_OID" \
  "$REPO_URL/api/v1/source/tags/lightweight"
```

## Create an annotated tag

Required additional fields are `target`, `target_kind`, `tagger`, `timestamp`
and `message_hex`. `target_kind` is exactly `commit`, `tree`, `blob` or `tag`;
quarantine verifies it against actual native object bytes. Declaring an object
kind does not prove it. The original target must pass the existing visibility
and reachability checks; an unreferenced/deleted-only object is not an oracle.

`tagger` must satisfy the native bounded `Name <email>` identity grammar.
`timestamp` is an explicit canonical unsigned decimal UTC Unix timestamp, zero
through i64::MAX. `message_hex` is at most 64 KiB of decoded original bytes;
empty is allowed. The native constructor rejects NUL. CRLF, non-UTF-8 bytes and
missing final newline are preserved. No ambient identity, timestamp, trimming,
newline insertion, signature or branch-tip lookup is inferred.

```sh
curl --fail-with-body --header @/secure/tag-writer.headers \
  --header 'Idempotency-Key: release-v1-annotated-attempt-1' \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/tags/v1-annotated' \
  --data-urlencode "target=$COMMIT_OID" \
  --data-urlencode 'target_kind=commit' \
  --data-urlencode 'tagger=Release Author <release@example.invalid>' \
  --data-urlencode 'timestamp=1790000000' \
  --data-urlencode 'message_hex=52656c656173652076310a' \
  "$REPO_URL/api/v1/source/tags/annotated"
```

The example message is the exact bytes `Release v1\n`. Native annotation bytes
bind object, type, tag name, tagger, timestamp and message. The resulting tag OID
is the proposed ref value in the existing semantic request; different metadata
therefore changes the sealed ref operation. A same-key change is not a new
permitted operation. Construction itself grants no publication authority.

Signature-looking bytes may be preserved as message content under the native
profile. This endpoint neither signs nor cryptographically verifies them. Their
presence grants no trust, authentication strength or protected-ref permission.

## Inspect a tag and its nested annotation chain

Required fields are only the common ones. Optional fields:

| Field | Meaning |
|---|---|
| `expected_head` | Exact algorithm-qualified `snapshot_token` from a previous response. |
| `expected_object` | Exact OUTER ref value to compare with this selected tag. |
| `max_tags` | Narrow the maximum chain depth, from 1 through 64. |
| `max_object_bytes` | Narrow the per-object decode limit, at most 1 MiB. |
| `max_total_bytes` | Narrow the total original-byte read limit, at most 4 MiB. |

The total budget includes the terminal non-tag object, even though its body is
not included in the response. Limits are enforced before native decoding.
These pins are strict current-head comparisons, not retained historical reads.
An intervening publication returns 409 `source_snapshot_moved`; a mismatched
outer ref expectation returns 409 `tag_object_moved`. An expected OID is only a
comparison, never an arbitrary-object read capability.

```sh
curl --fail-with-body --header @/secure/tag-reader.headers \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/tags/v1-annotated' \
  "$REPO_URL/api/v1/source/tags/inspect"
```

A `source_tag` response includes repository/incarnation/hash format, exact
`source_head`, `snapshot_token`, `ref_hex`, outer `object_id`, `peeled_object`,
`peeled_kind`, and the complete bounded `annotations` array in outer-to-inner
order. Each annotation carries its OID, target OID/kind, original `body_hex`,
byte length, and `signature` (`absent` or `opaque_unverifiable`). Every annotation
body can be hashed with its native `tag <length>\0` Git object framing to confirm
its ID. Every followed edge is validated, not guessed from an OID's shape.

`signature_verified` and `tagger_is_authenticated_principal` are always false.
No annotation count or peeled-kind label establishes signature trust or how an
alias was originally created. No terminal blob/tree/commit payload is returned.
Native cycles, kind mismatches, corrupt or unavailable objects and limit failures
produce errors, not an empty or truncated successful chain. JSON is fully built
before success and capped at 12 MiB or the server ceiling, whichever is smaller.

Tag inventory is the existing `/api/v1/source/refs` query with `namespace=tags`;
see [HTTP_BRANCH_API.md](HTTP_BRANCH_API.md). It is a direct-ref list, not a
recursive annotation report.

## Delete an exact tag

Provide `expected_object`, the current OUTER tag ref OID. For an annotated tag,
this is the tag object, not its peeled commit. The exact lease reaches canonical
admission. A stale/wrong lease becomes a canonical refusal, not a silently
refreshed deletion. There is no force, unspecified-old, replacement or default
branch rewrite.

```sh
curl --fail-with-body --header @/secure/tag-writer.headers \
  --header 'Idempotency-Key: release-v1-delete-attempt-1' \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/tags/v1-annotated' \
  --data-urlencode "expected_object=$TAG_OBJECT_OID" \
  "$REPO_URL/api/v1/source/tags/delete"
```

Deletion removes the named ref, not annotation bytes still reachable by aliases
or outer tags. It does not rewrite PR metadata or synthesize a forge event.

## Canonical results, retries and recovery

A `tag_publication` response carries operation, principal, exact ref/old/new
object coordinates, `atomic: true`, one TxId, decision sequence, and either the
committed RCR or canonical refusal record/code. Committed results use HTTP 200;
canonical refusals use 409. Errors before a decision do not masquerade as those
receipts. Changed-key semantics return a key-reuse error without publishing an
additional decision.

Identical terminal retries recover the original result even after the tag has
been deleted. They do not recreate it. A new create under a fresh key still
requires an absent destination. Racing creations cannot both win that condition.
The recovered result is evidence of the original operation, not a current-ref
freshness assertion. Transport failure, cancellation or a missing response does
not prove non-commit. Post-decision response-encoding failure means a lost receipt,
not a rolled-back publication.

Read-only recovery uses `POST {REPO_URL}/api/v1/outcomes`, an empty body, the
ORIGINAL `Idempotency-Key` and an `outcomes-read` token for the original principal.
It requires no tag metadata and works with mutation services disabled. Rotation
preserves retry identity when the principal stays unchanged. Another principal
using the same textual key observes its own namespace only. See
[HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md).

Some native quarantine, object or infrastructure failures are conservatively
reported as HTTP 503 `outcome_unknown` on mutation entry. Do not interpret that
as an authenticated refusal or assume that blindly retrying invalid input will
succeed. Inspect the original outcome and correct genuinely new commands under
new keys. Read errors carry `outcome_unknown: false`.

## Verification

```sh
cargo test -p fgit-node --lib smart_http::server::source
cargo test -p fgit-node --lib treefs_workspace::tags
cargo test -p fgit-node --test tag_http --test branch_http --test source_http \
  --test source_change_http --test outcome_http --test smart_http_server
```

The HTTP regressions use imported native objects, the real listener, canonical
admission and reopened embedded state. They cover both hash formats, original
annotation bytes, raw tag names, recursive peeling, wrong deletion leases,
competing releases, stable retries, receipt loss, write revocation, principal
isolation, signature non-trust, denial before body intake and incomplete frames.
Tests being committed is not evidence that they executed at this revision.
