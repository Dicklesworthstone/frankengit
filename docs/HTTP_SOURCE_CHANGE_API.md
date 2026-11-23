# Remote source editing through native Git candidates

The source API now connects repository reads to exact unified-patch preparation,
actual candidate inspection, and explicit single-branch publication. These are
three separate operations over the existing native TreeFS, patch, bundle and
admission engines. There is no HTTP-owned checkout, candidate database, alternate
Git engine, or new transaction-identity rule.

This document describes committed interfaces, not an executed Rust acceptance
result. The service remains the bounded loopback, operator-managed credential
profile. Full hosted IAM, TLS termination, generated OpenAPI and browser editing
remain separate work.

## Deployment and permissions

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants \
  --allow-source --allow-receive --allow-outcomes
```

Use the canonical repository URL from the listener readiness record as REPO_URL.
A private credential table is provisioned with the existing exact-incarnation
header and token hashes. Scopes are independent:

| Operation | Required grant | Deployment switches |
|---|---|---|
| Source browse/search, patch preparation, candidate inspection | `read` | `--allow-source` |
| Apply an exact source candidate | Operator `receive`, or scoped sponsored `source-publish` | `--allow-source` AND `--allow-receive` |
| Recover the original transaction outcome | `outcomes-read` | `--allow-outcomes` |

Canonical [sponsored agent credentials](SPONSORED_AGENT_CREDENTIALS.md) may prepare
and inspect with the independent `source-candidates` scope and `--allow-source`.
Neither `source-read` nor `source-history-read` implies this scope. The agent
uses the same multipart command, exact expected commit, patch profiles and
response artifacts documented below. Candidate work retains the original
bounded request and produces no staged objects or transaction. Its total wire
input and output each remain within 64 MiB, including framing and the operator's
possibly smaller limits. Candidate permission grants no publication authority.

A separately issued `source-publish` agent grant may apply a supplied
single-parent candidate to its exact allowed existing branch. Its immutable
publication scope must authorize every native changed path, including deleted
paths and both sides of renames; a path prefix ends at a repository path
component boundary. It uses the same multipart form, original Idempotency-Key,
quarantine and atomic admission as an operator publication. Both
`--allow-source` and `--allow-receive` remain required. The original credential
request owns the actual input/output reservation, deadline, agent identity and
key throughout parsing and native publication. A session receipt alone cannot
authorize this operation, and a new phase cannot renew its deadline.

This scoped grant does not authorize initial commits, raw Git receive, ref
creation or deletion, replay, rebase, PR publication, review, merge, or source
disclosure. Preparation and inspection still require `source-candidates`.
Current canonical publication scope and branch protection are checked at the
exact admission basis. See [scoped source publication](AGENT_SCOPED_SOURCE_PUBLICATION.md)
for issuance and the native proof boundary.

A read token cannot publish. A receive-only token can publish an independently
supplied bundle but cannot use source inspection or preparation to read code.
PR/issue/review/merge permissions imply neither grant. Existing static-token and
older node serving entry points do not enable the source API. Credential rotation
and revocation apply at each authentication; in-flight requests retain their
bounded grants. Forwarded identities never authenticate.

Prepare and inspect consume the source-read quota. Apply consumes mutation quota,
just like a push. Outcome lookup retains its separate recovery quota. Every
accepted connection still belongs to the listener's bounded child lifecycle.

## 1. Prepare an exact patch

```text
POST {REPO_URL}/api/v1/source/prepare
```

Send multipart/form-data containing exactly one `command` part and one `patch`
part, in either order. The command is application/x-www-form-urlencoded. Patch
bytes are text/x-diff or application/octet-stream and are not UTF-8 decoded or
newline-normalized by the gateway. Optional filenames are ignored, never used
as filesystem paths.

All seven command fields are required:

```text
object_format, ref, expected_commit, author, committer, timestamp, message
```

`ref` is a full existing branch such as refs/heads/main. `expected_commit` is its
independently selected nonzero lowercase SHA-1/SHA-256 native OID; `object_format`
must match the repository. Author, committer, positive timestamp and message are
explicit Git content, not authenticated identities. No ambient branch, metadata,
clock, expected-old refresh or force flag is inferred.

Optional `patch_profile` selects an explicit native grammar. Omit it or select
`exact-tree-v1` for the existing regular-file behavior. Select
`exact-tree-binary-v1` for verified edited binary renames, `exact-symlink-v1`
to create, edit, delete or rename inert Git symlink blobs, or `exact-gitlink-v1`
for opaque submodule-pointer creation, update and deletion alongside ordinary
text changes such as `.gitmodules`. Sponsored
`source-candidates` requests and ordinary source readers use these same choices.
The profile is echoed in response metadata when supplied; it never grants
publication rights. Unknown or duplicate profiles refuse, and `inspect` and
`apply` do not accept this preparation-only field. Optional
`expected_result_tree` independently pins the complete native result; a mismatch
returns 409 before any candidate is disclosed.

With the complete encoded fields in prepare.form and an intentionally chosen
patch in change.patch:

```sh
curl --fail-with-body --header @/secure/source-reader.headers \
  --form 'command=<prepare.form;type=application/x-www-form-urlencoded' \
  --form 'patch=@change.patch;type=application/octet-stream' \
  --dump-header prepared.headers --output prepared.body \
  "$REPO_URL/api/v1/source/prepare"
```

The native parser supports exact creation, deletion, text modification,
executable-bit changes, quoted raw paths and missing final newlines. Context and
offsets must match exactly; supplied index identities must match verified old/new
blobs. The [binary profile](HTTP_BINARY_REFACTORING.md) checks both directions of
encoded binary moves. Explicit `exact-symlink-v1` preserves mode `120000` and the
exact target blob, including absolute paths and `..` components as source bytes.
It never follows targets, writes a host link or reads a target from the host.
The other profiles continue to refuse symlink edits. Repository entry paths
still reject traversal, and both endpoints of a rename must pass the same
native path checks. Gitlink edits require the explicit `exact-gitlink-v1`
[full-index pointer grammar](NATIVE_EXACT_PATCH.md#explicit-opaque-gitlink-profile).
Their foreign commit targets are never read, imported or traversed. The gitlink
profile refuses binary/symlink sections, renames and entry-type conversions;
every older profile retains its gitlink refusal. Fuzzy application, rename guessing, copies,
external drivers and arbitrary object writes remain unsupported. Every file
must succeed before a candidate is returned. Unchanged siblings are preserved
by the existing native exporter.

A successful response is multipart/mixed: JSON `metadata`, then the native binary
`bundle`. It uses the same two-part extraction pattern documented in
[HTTP_CANDIDATE_PREPARATION_API.md](HTTP_CANDIDATE_PREPARATION_API.md), but the JSON
type is `source_preparation`. It contains source_commit, source_rcr,
candidate_commit, root_tree, patch_sha256, object_count, bundle byte length and
SHA-256 transport checksum, and path receipts with old/new blob IDs, mode and
hunk count. Paths use byte-exact `path_hex`. For `exact-gitlink-v1`, all path
receipts instead use `old_object` and `new_object`; mode `57344` (octal `160000`)
identifies a gitlink. A deletion has a null new identity and mode. Older profiles
retain the existing `old_blob` and `new_blob` keys.
Preparation, inspection and publication replies include authoritative lowercase
`ref_hex` for exact native reference bytes; `ref` retains UTF-8 text or is null
when those bytes are not UTF-8.

The bundle has exactly one prerequisite and the candidate has the expected base
as its sole parent. SHA-1 uses bundle v2; SHA-256 declares the native format in
bundle v3. Identical inputs and metadata reconstruct the same candidate. The
source RCR identifies its selected source; the response does not invent a
separately sampled authority-head token.

Preparation is read-only: objects are NOT staged, no key is bound, no transaction
is sealed, no ref changes and no forge/outbox effects publish. The artifact's
`publication_authorized: false` does not change meaning if it is later applied.
Do not send Idempotency-Key to preparation; it is rejected.

## 2. Inspect the actual candidate

```text
POST {REPO_URL}/api/v1/source/inspect
```

The multipart request requires `command` plus a nonempty `bundle` part of type
application/x-git-bundle or application/octet-stream. Its command has exactly
four required fields:

```text
object_format, ref, expected_commit, candidate_commit
```

Both OIDs are exact, nonzero native identities and must differ. The caller names
them independently of the untrusted bundle header. No path filter is accepted.

```sh
curl --fail-with-body --header @/secure/source-reader.headers \
  --form 'command=<candidate.form;type=application/x-www-form-urlencoded' \
  --form 'bundle=@candidate.bundle;type=application/x-git-bundle' \
  --output inspection.json \
  "$REPO_URL/api/v1/source/inspect"
```

The existing native inspector validates the envelope, identities, sole parent,
prerequisites, candidate closure, and pack coverage. Thin-delta original reads
are restricted to the selected visible parent history. A successful response is
`source_inspection` JSON containing the actual direct base-to-candidate tree
comparison, full native commit body in `candidate_commit_body_hex`, ordered
parents, bundle checksum, exact source head and snapshot token.

All changed paths are included within the supported envelope. Text hunks carry
hexadecimal before/after bytes and zero-based line/half-open byte spans, with
three context lines. CRLF, missing final newline and non-UTF-8 bytes stay exact.
Binary and object-only entries are explicit, not empty text diffs; binary bodies
are not included. No successful partial/truncated report is returned.

Inspection creates no objects, vote, transaction or publication capability. It
requires the actual bundle on every invocation and rejects Idempotency-Key.
This HTTP adapter currently maps native inspection failures conservatively to
503 repository_unavailable, including invalid, stale, or unavailable candidate
evidence. Such a failure is not an empty diff, approval or canonical refusal.
It does not imply the client should keep retrying an unchanged invalid bundle.

## 3. Publish only the explicitly selected candidate

```text
POST {REPO_URL}/api/v1/source/apply
Idempotency-Key: <client-selected-original-key>
```

Use the same four candidate fields and multipart bundle under an operator
receive-scoped credential or a sponsored source-publish credential with an
explicit immutable ref/path scope. Both source and receive deployment switches
are required:

```sh
curl --fail-with-body --header @/secure/source-writer.headers \
  --header 'Idempotency-Key: source-edit-attempt-1' \
  --form 'command=<candidate.form;type=application/x-www-form-urlencoded' \
  --form 'bundle=@candidate.bundle;type=application/x-git-bundle' \
  "$REPO_URL/api/v1/source/apply"
```

Operator publication uses the native workspace publisher. Sponsored publication
uses OneNode::apply_agent_workspace_bundle_in with the original live request
proof, including its original retry key. New work enters production quarantine,
verifies the single-parent candidate, and uses existing sealed,
atomic single-ref admission with the original expected-old assertion and native
push policy. The adapter never substitutes the latest branch tip. Concurrent
edits based on the same old commit cannot both replace that ref successfully.
There is no force option or source-only fallback for a reviewed PR merge.

`source_publication` JSON reports principal, ref, expected/candidate commits,
TxId, decision sequence, authenticated outcome, and its decision-record identity.
HTTP 200 means committed; HTTP 409 with outcome refused is a canonical refusal.
Key reuse with changed semantics is a request conflict, not another terminal
decision. External delivery is not claimed; delivery_acknowledged is null.
A source-only edit does not close a PR or manufacture an approval. Actual PR
merges must use the separate coupled reviewed-merge endpoint.

Exact retries recover the original terminal decision even after the branch has
advanced. They still require the bound bundle envelope on this endpoint. A
recovered terminal receipt authenticates the sealed ref operation, NOT the
integrity or provenance of a newly substituted transport encoding. Use inspect
for independent byte verification and outcome lookup for recovery alone.

Before native publication entry, a missing/mismatched live proof or original key
is refused. A complete multipart body exceeding the original sponsored input
reservation returns HTTP 413. Expired request custody cannot be renewed by
creating a new parsing or publication phase.

After native publication entry, infrastructure/cancellation failure remains
outcome_unknown rather than proof of rollback. Staged candidate objects on a
failed or refused attempt are not canonical ref publication. Once a final HTTP
response starts, socket or shutdown failure cannot append a second response.

## Lost-response recovery without write permission

Keep the original key and principal. The existing bodyless recovery endpoint
needs no bundle, patch, branch coordinates or live write grant:

```sh
curl --fail-with-body --request POST --header @/secure/recovery.headers \
  --header 'Idempotency-Key: source-edit-attempt-1' \
  --header 'Content-Length: 0' \
  "$REPO_URL/api/v1/outcomes"
```

The original principal may receive a rotated outcomes-read-only credential
after its receive or scoped source-publication permission is revoked. Lookup
does not resubmit the operation. The source_publication receipt keeps its
existing schema; this canonical lookup returns the recorded original
agent/sponsor/credential witness as principal_provenance. Credential rotation,
a narrower replacement grant or a retry must not replace that witness with
the current request's identity evidence.
Another principal using the same textual key remains in its own namespace.
Missing or undecided evidence does not certify rollback. See
[HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md).

## Bounds, errors and verification

Commands are at most 256 KiB. Patch input is at most 16 MiB; incoming/outgoing
bundles are at most 64 MiB in this HTTP profile, further narrowed by configured
HTTP limits. Patch metadata is capped at 1 MiB; inspection JSON at 32 MiB and
the server response ceiling. Native graph, object, patch, export and inspection
budgets still apply. Bounded multipart parsing borrows the HTTP-owned input;
preparation/inspection release that input before constructing their response.
Patch responses write the owned bundle directly, not through another full copy.
This is not disk-spooled or unbounded streaming intake.

Complete HTTP and MIME framing precedes engine entry. Duplicate/unknown fields,
wrong domains, unsafe paths, unsupported media, missing payloads and incomplete
framing fail closed. Preparation returns 409 for moved source/context mismatch,
400 for unsupported or invalid patches, 413 for explicit resource exhaustion,
and a read error for unavailable evidence/cancellation. Errors use source_error;
read failures never manufacture a transaction refusal or mutation ambiguity.

Focused checks:

```sh
cargo test -p fgit-node --lib smart_http::server::source
cargo test -p fgit-node --lib smart_http::server::tests::agent_credentials::source_read::candidates
cargo test -p fgit-node --lib smart_http::server::pulls::collaboration::source_upload
cargo test -p fgit-node --test source_change_http --test source_http \
  --test outcome_http --test smart_http_server
```

The new tests exercise real TCP handlers, imported native objects, embedded
authority, restart, competing edits, exact retries, lost-response recovery,
permission separation, malformed input and preservation of untouched bytes.
Sponsored publication cases additionally cover both Git hash domains, exact
ref/path ceilings, both service switches, original key/proof/reservation custody,
request expiry, large real bundles, credential rotation and immutable canonical
provenance on terminal recovery. Test presence is not evidence that these tests
ran at this revision. Remote
workspace sessions, initial repository creation, direct binary editing, richer
patch formats, browser UI, and production acceptance are not completed here.
