# Resolve a conflicted PR candidate over HTTP

`POST {REPO_URL}/api/v1/pulls/{number}/resolve` completes the remote conflict
workflow: discover conflicts through `/prepare`, submit explicit resolutions,
download the resulting native bundle, review that exact candidate, and publish
it through the existing reviewed merge endpoint.

Resolution is a **read-only construction operation**, not a Git push or merge.
It does not stage objects, create a transaction or idempotency binding, cast a
vote, update refs/PR metadata, or publish an outbox obligation. The native
resolver reproduces the conflicts from authenticated objects and accepts every
and only actual conflict path. Missing, extra or invalid choices return no
candidate. A valid bundle is not an approval or publication receipt.

The implementation reuses the existing native resolution planner, independent
object validator, pack writer, multipart framing and owned HTTP serving path.
There is no new Git engine, filesystem checkout, candidate database, dependency
or runtime. This document describes interfaces, not an executed Rust acceptance
result or a completed hosted-forge release.

## Authorization and request identity

Use `fg serve-http --allow-pulls` with the existing repository-bound, reloadable
credential file. The SAME token must grant both `read` and `pulls-read`, because
the response discloses source code and PR coordinates. Separate tokens for one
principal do not combine their grants. Review/merge/write permissions imply
neither read, and old static-token or PR-disabled entry points remain disabled.
The credential is reauthenticated on every request under current grants.

Do not send an `Idempotency-Key`; it is rejected. Resolution creates no mutation
to recover. Repeating construction with identical source and commit metadata
reconstructs an artifact, not a transaction. Later approval and merge requests
need their own principals, scopes, exact candidate and original retry keys.

All construction stays subject to current canonical hidden-ref policy. A page
token is not a historical-policy bypass. The service remains loopback-only and
operator-managed; this does not introduce TLS or organization/team IAM.

## Exact input

The request repeats all eleven `/prepare` fields:

```text
object_format, pull_request_version, policy_epoch,
source_ref, target_ref, source_tip, target_tip,
author, committer, timestamp, message
```

It additionally requires `merge_base`, the exact lowercase native OID returned
by conflict discovery. All hash domains must match the repository. The node
checks the current open PR version, policy epoch, branch identities and tips,
then pins native resolution to that same authenticated authority head. The
native planner independently checks the unique merge base. Concurrent changes
can refuse construction rather than silently refreshing any submitted field.

Add one repeated `resolution` field for every actual conflict. Paths are the
lowercase `path_hex` bytes returned by `/prepare`, not decoded UTF-8 names or
local filenames. The closed grammar is:

| Resolution value | Meaning |
|---|---|
| `<path_hex>:base` | Select the exact base entry, including its native type/mode. |
| `<path_hex>:ours` | Select the target branch entry (first parent). |
| `<path_hex>:theirs` | Select the source branch entry (second parent). |
| `<path_hex>:delete` | Explicitly remove this conflicted path. |
| `<path_hex>:file:100644:file_N` | Exact bytes of multipart part `file_N`, ordinary file mode. |
| `<path_hex>:file:100755:file_N` | Exact bytes of multipart part `file_N`, executable file mode. |

Selecting an absent base/side is NOT shorthand for deletion. Duplicate paths,
ancestor/descendant overlaps, empty path components, NUL, `.`/`..` and `.git`
components are refused by the native resolution validator. Choices cannot
modify a clean path or insert unrelated files. Explicit file replacement has
only the two regular-file modes above; no arbitrary mode or external driver
is accepted. Native side selection retains that side's existing entry.

Resolution order does not change semantics. Paths are sorted before native
construction. Numbered upload parts are transport references, not candidate
identity: what matters is the exact chosen path, mode and bytes. Empty files,
NUL, non-UTF-8 content and exact line endings are preserved without normalization.

### Side selection without binary uploads

Use `application/x-www-form-urlencoded` with the required fields and repeated
`resolution` fields. For example, append this to the exact preparation form:

```text
&merge_base=<exact-base-oid>&resolution=66696c65ff2e747874:ours
```

The example path is the raw Git name `file\xff.txt`. It is not opened as a local
path. Use `--data-urlencode` when building fields with curl; raw `&`, `+` or `%`
in author/message text must not alter the form grammar.

### Exact binary replacement

Use `multipart/form-data`. Include one `command` part containing the complete
URL-encoded command, and one `application/octet-stream` part for each referenced
file. Valid attachment names are `file_0` through `file_127`, with canonical
decimal spelling. Part order is irrelevant. Every file must be referenced
exactly once: missing, reused, duplicate or unused attachments fail closed.

Example command additions for an explicit executable-file replacement:

```text
&merge_base=<exact-base-oid>&resolution=66696c65ff2e747874:file:100755:file_0
```

With the complete command saved as URL-encoded `resolve.form` and intentionally
chosen bytes in `resolved.bin`:

```sh
curl --fail-with-body --header @/secure/preparation.headers \
  --form 'command=<resolve.form;type=application/x-www-form-urlencoded' \
  --form 'file_0=@resolved.bin;type=application/octet-stream' \
  --dump-header resolved.headers --output resolved.body \
  "$REPO_URL/api/v1/pulls/41/resolve"
```

For multiple conflicts, repeat the `resolution` form field and provide each
referenced file as a separate numbered part. A file part's optional filename
is ignored and is never opened, written or interpreted as authority. No bundle
part, transfer encoding, nested MIME, preamble or epilogue is accepted here.
Fixed-length and chunked HTTP framing are supported. The complete HTTP and MIME
envelopes must finish before construction; truncation or trailing bytes do not
produce a partial candidate.

## Result and review

A successful resolution returns HTTP 200 `multipart/mixed`, using the same
metadata-plus-binary-bundle format as automatic preparation. The JSON retains
`type: "merge_preparation"` and adds:

```json
{
  "state": "resolved",
  "resolution_profile": "exact-path-resolutions-v1",
  "read_only": true,
  "objects_staged": false,
  "transaction_created": false,
  "published": false,
  "merge_authorized": false
}
```

`resolutions` contains one sorted receipt per resolved path: byte-exact
`path_hex`, original conflict kind and base/ours/theirs OIDs and modes, selected
`choice`, and resulting OID/mode or null for explicit deletion. The response
also includes the exact PR review subject, source head, candidate base/commit/
tree, bundle length and SHA-256 transport checksum. Actual replacement bytes
are in the Git bundle; upload filenames do not appear in the derived receipts.

Extract the metadata and binary bundle using the client example in
[HTTP_CANDIDATE_PREPARATION_API.md](HTTP_CANDIDATE_PREPARATION_API.md), accepting
`state: "resolved"` as well as `clean`. Inspect the resulting artifact and submit
that exact bundle to the existing candidate review endpoint. See
[HTTP_REVIEW_MERGE_API.md](HTTP_REVIEW_MERGE_API.md).

Changing any resolution bytes, file mode, selected side or Git commit metadata
can change the candidate ID. An approval of the original candidate cannot
approve the changed one. Required independent reviewers and mandatory branch
protection remain checks inside the existing merge driver at publication.
The resolver never relaxes them or turns a displayed receipt into permission.

## Refusals and bounds

All failures return the existing `pull_request_error` family with
`outcome_unknown: false`: this endpoint has attempted no canonical mutation.
They are not permanent transaction decisions. Important HTTP 409 codes are:

```text
preparation_subject_moved       PR/version/tip/policy/snapshot no longer matches
resolution_base_mismatch       submitted base is not the verified unique base
unresolved_conflicts           at least one actual conflict lacks a choice
resolution_names_clean_path    a choice names a non-conflict
resolution_side_missing        selected side has no entry; deletion must be explicit
no_conflicts_to_resolve         the exact inputs have no conflicts
```

Bad grammar, duplicate/overlapping paths, invalid modes and missing/unused file
parts return 400. Current permission failures are 401/403, unavailable PRs/refs
are 404, unsupported media 415, exceeded resource envelopes 413, throttling 429,
and unavailable/corrupt native evidence 503. Cancellation remains a read error,
not a fabricated conflict or successful empty result. No-common-ancestor and
multiple-best-base refusals retain the existing preparation error codes.

The bounded profile permits 128 resolutions, paths up to 4096 bytes, at most
1 MiB per uploaded file, and at most 32 MiB total owned resolution bytes
(including decoded paths). Commands remain limited to 256 KiB encoded and the
existing per-value decoder bounds. Complete uploads additionally have a fixed
allowance for at most 129 bounded MIME headers/delimiters and remain narrowed
by configured HTTP limits. All native graph/tree/content/output/work budgets
continue to apply; discovery and reconstruction share one native work budget.

Multipart parsing borrows the bounded HTTP buffer. After constructing owned
native choices, the gateway drops that buffer before graph traversal and bundle
generation. This is bounded memory buffering, not disk-spooled or unbounded
streaming. Replies retain the preparation metadata/bundle ceilings and are
fully framed and checked before the first success byte.

## Verification

```sh
cargo test -p fgit-node --lib smart_http::server::pulls
cargo test -p fgit-node --test conflict_resolution_http \
  --test candidate_preparation_http --test review_merge_http --test pull_request_http
```

The tests use native imports, actual TCP handlers and embedded authority. They
cover exact binary replacement, all side choices, explicit deletion, restart,
unstaged candidates, independent review, a changed unapproved candidate, coupled
publication, permissions, absent mutation bindings, malformed framing, stale
PR/policy, hidden refs, cancellation and native work limits in both object
formats where applicable. Test presence is not evidence that they ran at this
revision. Broader rename/driver support, cross-repository PRs, browser editing,
retention leases and production deployment remain separate work.
