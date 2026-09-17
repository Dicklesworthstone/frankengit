# Native source diff over HTTP

`POST {repository-route}/api/v1/source/diff` exposes the native source-review
engine used by `fg diff`. It is a read-only query, not a patch application,
merge, approval, or transaction. Enable the existing source API and use a
credential with the explicit `read` scope. Receive or PR metadata scopes alone
do not grant source disclosure. Do not supply an `Idempotency-Key`.

Requests use `application/x-www-form-urlencoded`, including when the body is
chunked. Authorization and repository routing precede body intake. URL query
parameters and Git protocol headers are not accepted.

## Request

```text
object_format=sha1&before_ref=refs/heads/main&after_ref=refs/heads/topic&mode=merge-base
```

`object_format`, `before_ref`, and `after_ref` are required. Both refs are
selected from one authenticated current authority head, with canonical hidden
refs still applied. `expected_before` and `expected_after`, when supplied, are
exact nonzero native commit IDs to compare against those selected tips; they
are not object selectors. `expected_head` accepts the response's
`snapshot_token`. An intervening repository decision invalidates that token,
even when the compared Git tips remain unchanged.

`mode=direct` (the default) compares the two selected trees. `mode=merge-base`
compares their unique best common ancestor to the after tip. No common ancestor
or multiple best bases yields a conflict response, not a guessed base.

Optional `path_prefix_hex` fields may repeat up to 64 times. Each is a nonempty
lowercase-hex raw repository path prefix with component boundaries, not a glob
or filesystem path. `dir` selects `dir` and descendants, not `directory`.
`context_lines` is 0 through 20 and defaults to 3.

Every native limit can be lowered, but not raised:

| Field | Default and ceiling |
|---|---:|
| `max_tree_entries` | 100,000 |
| `max_changes` | 512 |
| `max_text_files` | 64 |
| `max_blob_bytes` | 1,048,576 |
| `max_output_bytes` | 8,388,608 |
| `max_hunks` | 4,096 |
| `max_diff_work` | 1,000,000 |

Limits must be positive canonical decimal integers. Unknown, duplicate
non-prefix, and inapplicable fields are rejected. These are per-request bounded
profiles, not a general large-repository performance claim.

## Response

The response identifies tenant, repository, incarnation, authority head,
original tips, actual compared base, root trees, mode, path filters and context.
`complete:true` means the entire requested comparison was produced; no
successful partial diff is returned. `entry_count` includes explicit directory
records and is not a regular-file count.

Entries are ordered by raw path bytes and include `path_hex`, change kind,
nullable before/after identities, and exact octal modes. Text content carries
additions/deletions, the native algorithm, and before/after hunk payloads in hex.
Spans use zero-based, half-open byte intervals and zero-based line coordinates.
CRLF, non-UTF-8 bytes and missing final newlines are preserved.

Binary entries report identities and sizes, not binary content. Mode-only
content is marked `identical`; directories and gitlinks use `object_only`.
Symlink payloads are data and are never followed. No attributes, external
helper, hook, text conversion, rename heuristic or whitespace normalization
executes. The JSON is not itself an applicable unified patch.

The serialized response also has an 8 MiB ceiling, tightened by the listener's
response bound. Hex expansion is charged before allocation. Source limits,
response limits, missing objects and cancellation never produce an empty
success in place of a failed comparison. Responses are buffered and checked
before sending success headers; transport failure can still interrupt delivery.

400 denotes malformed options, 401/403 authentication or scope failure, 404 an
unavailable/hidden selection, 409 a moved precondition or unsupported ancestry,
413 a reported resource bound, and 503 an unavailable native/source operation.
No backend diagnostics or internal missing-object IDs are returned in errors.
The existing listener transport-security and operator-managed credential
profile is unchanged; this endpoint is not a hosted-deployment certification.

## Verification

`source_diff_http` contains real-listener SHA-1/SHA-256 tests for exact payloads,
mode/binary/gitlink distinctions, direction, merge-base mode, path filters,
restart, scopes, credential rotation, snapshot movement and no read-created
transaction. Parser and serializer unit tests cover malformed selectors,
resource limits, byte spans, response expansion and output cancellation.

The editing environment used to add this endpoint had no Cargo/Rust compiler.
These tests are implemented but were not executed there; no compilation,
Clippy, formatting, conformance or release-gate pass is claimed.
