# Native cherry-pick and revert over HTTP

## Implemented boundary

The explicit source service exposes two body-bearing read operations:

```text
POST {repository-route}/api/v1/source/cherry-pick/prepare
POST {repository-route}/api/v1/source/revert/prepare
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <read-scoped credential>
```

They call `OneNode::prepare_replay_bundle_in`, which uses the existing native
path-v1 replay planner and independently validates the resulting single-parent
candidate. No second Git engine, mutable checkout, process, or new publication
primitive participates. This is one historical commit, not a range sequencer.

The source-service switch must be enabled. Credentials must explicitly grant
`read`; `receive` does not imply read permission. Authentication and read quota
precede body intake and `100 Continue`. An `Idempotency-Key` is rejected because
preparation does not create a transaction. Hidden and absent refs are
indistinguishable. Repository-incarnation credential binding remains in force.

## Explicit input

Required form fields:

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
an authentication claim. `expected_head` optionally pins the exact authority
head using the returned `snapshot_token`. `mainline` selects a positive,
one-based stored parent of a merge commit; it is required for merges, defaults
to one for a single-parent commit, and is inapplicable to a root commit.

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

## Complete results

A clean replay returns HTTP 200 `multipart/mixed` with JSON `metadata` and a
binary `application/x-git-bundle` attachment. Metadata binds repository,
incarnation, authority snapshot, direction, refs, exact source/target/selected
commit, chosen parent/mainline, candidate commit/tree, and bundle length/SHA-256.
The response includes generated, packed, and borrowed object counts.

The candidate has exactly one parent: `expected_target`. Its bundle includes
all required source-side objects absent from the target's reachable closure;
the selected historical commit is not an implicit bundle prerequisite. SHA-1
uses native bundle v2 and SHA-256 native bundle v3. Metadata is capped at 2 MiB,
bundles at 64 MiB, and the configured complete-response bound can be smaller.
The binary attachment is not duplicated into a hexadecimal response buffer.
Multipart delimiters are checked against both payloads before success.

Conflicts return HTTP 409 JSON with `state: conflicted`, exact raw path bytes,
conflict kind, and actual base/ours/theirs native entries. There is no candidate
commit, partial pack, or staged object. For revert, base is the selected commit
and theirs is its selected parent; ours is always the target.

An unchanged output tree returns HTTP 200 JSON with `state: no_change` and no
bundle. It is not proof that a patch appeared earlier in history, and it does
not manufacture an empty commit. Both non-clean shapes explicitly use null
candidate/bundle fields.

Malformed inputs and mainlines produce 400; missing/hidden refs and commits
outside the authorized source history produce 404; moved tips/head and missing
merge mainline produce 409; resource refusals produce 413. Required-object,
validation, and infrastructure failures are not successful empty results.
No preparation error asserts a canonical committed/refused transaction.

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
transaction even after restart or target advancement. Preparing or downloading
a candidate never grants that write permission.

## Evidence and non-claims

`crates/fgit-node/tests/source_replay_http.rs` adds real-listener scenarios for
both hash formats: reproducible native preparation, borrowed dependencies,
no-change/inverse/conflict outcomes, source-history authorization, native bounds,
read-scope and pre-body key refusal, credential rotation, independent inspection,
explicit publication, and restart/terminal retry. Focused parser, response and
framing tests cover malformed coordinates, lossless paths, cancellation,
metadata bounds, and write failure.

These new tests were authored but not executed in the implementation environment:
`cargo`, `rustc`, and `rustfmt` were unavailable. No compilation, conformance,
Clippy, performance or repository-gate pass is claimed. The authoritative
implementation remains the owning native replay/admission engines; this adapter
does not complete the broad API bridge, rebase, a multi-commit sequencer, hosted
IAM, conflict resolution transport, or general Git compatibility.
