# Native cherry-pick and revert over HTTP

## Implemented boundary

The explicit source service exposes body-bearing read operations:

```text
POST {repository-route}/api/v1/source/cherry-pick/prepare
POST {repository-route}/api/v1/source/revert/prepare
POST {repository-route}/api/v1/source/cherry-pick/resolve
POST {repository-route}/api/v1/source/revert/resolve
Authorization: Bearer <read-scoped credential>
```

Preparation accepts `application/x-www-form-urlencoded`. Resolution accepts
that media type for side choices, or `multipart/form-data` for exact file bytes.
The operations call `OneNode::prepare_replay_bundle_in` and
`OneNode::prepare_resolved_replay_bundle_in`, using the existing native path-v1
planner and independently validating the single-parent candidate. No second
Git engine, mutable checkout, process, or new publication primitive participates.
This is one historical commit, not a range sequencer.

The source-service switch must be enabled. Credentials must explicitly grant
`read`; `receive` does not imply read permission. Authentication and read quota
precede body intake and `100 Continue`. An `Idempotency-Key` is rejected because
neither operation creates a transaction. Hidden and absent refs are
indistinguishable. Repository-incarnation credential binding remains in force.
Sharing the established PR resolution multipart parser does not enable PR
operations or confer PR-read, review, or merge permissions.

## Explicit input

Required common form fields:

| Field | Meaning |
| --- | --- |
| `profile` | Exactly `path-v1`; no implicit compatibility profile. |
| `object_format` | `sha1` or `sha256`, matching the selected repository. |
| `target_ref` or `target_ref_hex` | Exactly one encoding of the destination branch. |
| `source_ref` or `source_ref_hex` | Exactly one encoding of the visible history authorizing selection. |
| `expected_target` | Exact current target tip, not an expected-old value refreshed by the server. |
| `expected_source` | Exact current source tip. |
| `commit` | Selected historical commit reachable from that source tip. |
| `author` | Explicit native commit author identity. |
| `timestamp` | Positive Unix seconds, at most `i64::MAX`. |
| `message` or `message_hex` | Exactly one encoding of the new commit message. |

`committer` optionally differs from the supplied author. Neither identity is
an authentication claim. `expected_head` pins the exact authority head using
the returned `snapshot_token`: optional for automatic preparation, mandatory
for resolution. `mainline` selects a positive, one-based stored parent of a
merge commit; it is required for merges, defaults to one for a single-parent
commit, and is inapplicable to a root commit.

Refs must be fully qualified branch names. Text form values use ordinary
percent encoding; the `*_hex` fields accept bounded lowercase hexadecimal and
preserve non-UTF-8 bytes. OIDs are nonzero lowercase native hex with the exact
repository digest width. Unknown fields, duplicates, competing encodings,
force flags, caller-supplied principals, and arbitrary merge bases refuse.

Source and target may be the same branch. In particular, reverting an older
commit does not require a second branch. The selected commit is found by a
bounded source-history walk before its body is read. Merely being present in
the admitted object store or target history does not authorize that selection.

Every `PreparationLimits` dimension can be narrowed through the corresponding
snake-case field: `max_commits`, `max_edges`, `max_tree_entries`, `max_depth`,
`max_path_bytes`, `max_content_merges`, `max_text_bytes`, `max_conflicts`,
`max_objects`, and `max_output_bytes`. Zero or a value above the native default
refuses. The existing form/HTTP limits also apply; a theoretical native maximum
is not a promise that every encoding fits the smaller transport envelope.

## Explicit conflict resolution

Retain the automatic conflict response's exact snapshot token and replay
coordinates. Send those common inputs to the corresponding `/resolve` endpoint
with one repeated `resolution` field for every actual conflict:

```text
resolution=<lowercase-path-hex>:base
resolution=<lowercase-path-hex>:ours
resolution=<lowercase-path-hex>:theirs
resolution=<lowercase-path-hex>:delete
resolution=<lowercase-path-hex>:file:100644:file_0
resolution=<lowercase-path-hex>:file:100755:file_1
```

For file choices, send a multipart `command` part containing the URL-encoded
form, plus named `file_0` through `file_127` parts with media type
`application/octet-stream`. Multipart filename parameters are not host paths.
Empty and binary bodies are exact data. Each file part must be referenced
exactly once; missing, reused, duplicate and unreferenced parts refuse. File
mode is explicitly regular (`100644`) or executable (`100755`). Neither a
symlink upload nor implicit newline or marker normalization is supported.

The existing MIME policy caps each file at 1 MiB, total file content at 32 MiB,
and files at 128, plus bounded form/header overhead. The caller's native limits
can be smaller. Checks precede copying the file bodies into native choices;
the transport buffer is released before native planning and packing.

The native planner reproduces conflicts from the pinned replay. Choices cannot
change clean paths, select a missing side as deletion, overlap, or omit an
actual conflict. Unknown choices do not fall back to automatic preparation.
A source/target or authority change rejects the old resolution. Selecting ours
can legitimately reproduce the target tree and return `no_change` without an
empty commit; the explicit resolution receipts are still returned.

For cherry-pick, base is the selected commit's parent and theirs is the selected
commit. For revert, base is the selected commit and theirs is its selected
parent. Ours is always the target. Choosing `theirs` in a revert must not be
interpreted as accepting the original selected commit's content.

## Complete results

A clean replay returns HTTP 200 `multipart/mixed` with JSON `metadata` and a
binary `application/x-git-bundle` attachment. Metadata binds repository,
incarnation, authority snapshot, direction, refs, exact source/target/selected
commit, chosen parent/mainline, candidate commit/tree, and bundle length/SHA-256.
The response includes generated, packed, and borrowed object counts.

A resolved candidate uses `state: resolved` and
`resolution_profile: exact-path-resolutions-v1`. Each sorted receipt includes
the reproduced conflict, applied choice, and resulting native entry or null
for deletion. The adapter checks receipt paths, choices, side identities and,
for uploaded files, native blob hash and mode against the exact submitted bytes.
A resolved response cannot carry outstanding conflicts.

The candidate has exactly one parent: `expected_target`. Its bundle includes
all required source-side objects absent from the target's reachable closure;
the selected historical commit is not an implicit bundle prerequisite. SHA-1
uses native bundle v2 and SHA-256 native bundle v3. Metadata is capped at 2 MiB,
bundles at 64 MiB, and the configured complete-response bound can be smaller.
The binary attachment is not duplicated into a hexadecimal response buffer.
Multipart delimiters are checked against both payloads before success.

Automatic conflicts return HTTP 409 JSON with `state: conflicted`, exact raw
path bytes, conflict kind, and actual base/ours/theirs native entries. There is
no candidate commit, partial pack, or staged object. An unchanged output tree
returns HTTP 200 JSON with `state: no_change` and no bundle. It is not proof
that a patch appeared earlier in history, and it does not manufacture an empty
commit. Non-clean shapes explicitly use null candidate/bundle fields.

Malformed inputs, missing snapshot/choices and invalid mainlines produce 400;
missing/hidden refs and commits outside the authorized source history produce
404; moved tips/head, missing merge mainline, clean-path choices, absent sides,
unresolved conflicts and a request to resolve an already clean replay produce
409; resource refusals produce 413. Required-object, reconstruction, validation,
and infrastructure failures are not successful empty results. No preparation
or resolution error asserts a canonical committed/refused transaction.

## Inspection and publication are separate

Save the binary bundle and inspect it through the existing endpoint:

```text
POST {repository-route}/api/v1/source/inspect
Content-Type: multipart/form-data; boundary=...

command: object_format=<format>&ref=<target>&expected_commit=<original-target>&candidate_commit=<candidate>
bundle:  <exact candidate bundle bytes>
```

`source/apply` accepts that same explicit command and bundle, but requires the
independent `receive` grant, enabled Git writes, and an `Idempotency-Key`.
It reuses ordinary sealed workspace admission, current policy and expected-old
checks, and outcome recovery. A completed same-key retry remains the original
transaction even after restart or target advancement. Preparing, resolving or
downloading a candidate never grants that write permission.

## Evidence and non-claims

`crates/fgit-node/tests/source_replay_http.rs` adds real-listener scenarios for
both hash formats: reproducible native preparation, borrowed dependencies,
no-change/inverse/conflict outcomes, source-history authorization, native bounds,
read-scope and pre-body key refusal, credential rotation, independent inspection,
explicit publication, and restart/terminal retry.

`crates/fgit-node/tests/source_replay_resolution_http.rs` adds all side choices,
delete and no-change resolution, exact empty/binary/executable files, independent
inspection and apply, stale snapshot refusal after restart, same-key recovery,
missing/reused/unused file rejection, narrowed budgets, and authorization before
body intake. Focused parser, receipt, response and framing tests cover malformed
coordinates, byte paths, cancellation, metadata bounds, and write failure.

These new tests were authored but not executed in the implementation environment:
`cargo`, `rustc`, and `rustfmt` were unavailable. No compilation, conformance,
Clippy, performance or repository-gate pass is claimed. The authoritative
implementation remains the owning native replay/admission engines; this adapter
does not complete the broad API bridge, remote rebase, a multi-commit sequencer,
hosted IAM, or general Git compatibility.
