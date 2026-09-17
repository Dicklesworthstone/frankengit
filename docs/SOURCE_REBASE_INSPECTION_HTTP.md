# Complete rebase candidate inspection

The source API now supports a read-only inspection between rebase preparation
(or conflict resolution) and explicit publication:

```text
POST {repository-route}/api/v1/source/rebase/inspect
```

This endpoint inspects the **actual uploaded bundle**, not a preparation receipt
or a fresh rerun of the rebase algorithm. It returns the final old-source-to-new
comparison and every parent-to-child comparison in the candidate series. A
change introduced in an intermediate commit and removed later therefore remains
visible even when the final source tree is unchanged.

## Authentication and transport

The existing source API switch and `read` credential grant are required.
Authentication, repository-incarnation binding and the source read quota precede
body intake. A `receive`-only credential does not permit inspection. An
`Idempotency-Key` is rejected: this operation never seals a transaction, stages
objects, appends a forge event, creates an approval, or moves a ref.

The request is multipart/form-data with exactly two parts, in either order:

- `command`: application/x-www-form-urlencoded with the fields below;
- `bundle`: application/x-git-bundle (or application/octet-stream), containing
  the actual candidate Git bundle, not a filename or an object-store key.

Filename parameters have no authority and never name server files. The existing
bounded HTTP and multipart parsers own fixed-length/chunked framing, limits,
delimiters and completion. An incomplete body yields no inspection. Ordinary
URL-encoded requests without a bundle, query parameters and Git-Protocol headers
are not supported on this route.

## Exact request coordinates

All fields are unique. Unknown fields refuse rather than being ignored.

| Field | Contract |
| --- | --- |
| `profile` | Required, exactly `linear-v1`. |
| `object_format` | Required, repository-native `sha1` or `sha256`. |
| `source_ref` or `source_ref_hex` | Exactly one encoding of the source branch. |
| `onto_ref` or `onto_ref_hex` | Exactly one encoding of a distinct onto branch. |
| `expected_source` | Required exact current source tip. |
| `expected_onto` | Required exact current onto tip and bundle prerequisite. |
| `candidate_commit` | Required independently selected candidate tip. |
| `expected_head` | Optional exact `alg:<algorithm>:<digest>` snapshot token. |
| `context_lines` | Optional 0..20, default 3. |

References are fully qualified `refs/heads/...` names, bounded to 4096 bytes.
Hex encodings preserve arbitrary valid ref bytes. Native object IDs are nonzero,
lowercase and use the repository's exact digest width.

The optional `max_tree_entries`, `max_changes`, `max_text_files`,
`max_blob_bytes`, `max_output_bytes`, `max_hunks` and `max_diff_work` fields may
narrow the existing native ReviewLimits. These fields describe review work and
retained native diff payload, not the expanded HTTP JSON size. Zero or values
above the native defaults refuse. Path filters and alternative comparison modes
are intentionally absent: a successful result covers all changed paths.

There is no upstream, empty-commit policy, committer, resolution choice, force
flag, principal override or original-to-rewritten mapping in this request.
Those are preparation/publication concerns, not evidence about uploaded bytes.

## What is checked

Both references, their exact tips, optional authority head, and current hidden-ref
policy are checked at one authenticated snapshot. The bundle must advertise the
source branch and candidate, with exactly one prerequisite equal to onto.

External delta bases and candidate dependencies may be borrowed **only from
onto's verified history**. Merely being admitted somewhere in the repository, or
reachable from the old source, is not enough. Missing source-side objects must
be included in the bundle. Native hashes, object kinds, pack checksums and full
candidate closure are validated using the existing stage-free inspector.

The uploaded candidate must form a single-parent chain back to onto. Every
rewritten commit is supplied by the pack, with at most 256 commits, 2 MiB per
commit body and 16 MiB of retained commit bodies in the native reader. Unrelated
extra uploaded objects refuse; transitive pack-local delta bases are permitted
only as counted transport dependencies. A zero-commit series with candidate
identical to onto and a valid empty pack remains supported.

Only after candidate verification does the final diff reader gain access to the
old source's verified history. All original-object reads share the same finite
budget. Native tree traversal, changed entries, text-file comparisons, hunk
counts and retained diff bytes are accumulated over the **entire series plus
its final comparison**, not reset per commit. Per-blob size and per-text diff
work limits retain their native meanings. Review text diffs use cooperative
cancellation and preserve the original source cancellation/resource refusal.

## Result shape

A successful response is one bounded JSON object of type `rebase_inspection`.
It includes repository/incarnation scope, source head and snapshot token, raw
ref bytes, exact source/onto/candidate IDs, bundle digest and measurements,
`commit_count`, `net_change`, and `commits` in oldest-first order.

`net_change` is the existing `source_diff` object comparing the old source tree
with the candidate tree. Each `commits` item contains `index`, `commit`, `parent`,
`tree`, `body_hex`, and `diff`. Its `diff` is the same `source_diff` shape for
that commit's actual sole parent and result. Nested reference names label the
inspected source branch; their exact requested OIDs identify the comparison.
They are not a claim that a newly uploaded commit is already its canonical tip.

The complete native commit body is encoded losslessly, including author,
committer, encoding, message and any other accepted metadata. File paths and
hunk bytes retain the existing lossless hex representation and exact spans.
Binary changes, mode-only changes, directories and gitlinks remain distinct;
binary bodies are not included and gitlinks are not traversed.

JSON, including hexadecimal expansion and nested comparison metadata, has an
aggregate 8 MiB ceiling and is further narrowed by the listener's response
ceiling. Oversize output refuses before a success response is sent. It never
returns a successful prefix or truncates commits to fit. The native 16 MiB
commit-body allowance does not promise those bytes fit the HTTP representation.

## Publication and non-claims

The result explicitly reports `objects_staged=false`, `transaction_created=false`,
`published=false`, `approval_created=false`, `publication_authorized=false` and
`replay_equivalence_verified=false`. Structure and actual content are verified;
correspondence with an original replay sequence, human authorship, signature
trust, policy approval and publication permission are not inferred.

Use the separately write-scoped `rebase/apply` endpoint for publication. Its
expected-old lease remains the original **source** tip, not onto. Inspection
does not change its protection checks or terminal retry recovery. Inspection
with an old snapshot/tip may fail after apply, while an identical apply retry
still recovers its original decision. None of the existing workspace, merge,
PR inspection or publication profiles is widened by this endpoint.

## Regression targets and verification boundary

`fgit-forge --test review_series` covers native equivalence, transient changes,
cumulative budgets, exact boundaries and cancellation checkpoints.
`fgit-node --test rebase_inspection` covers actual native commit/pack inspection,
restart, metadata, transient changes, omitted source objects, corruption and
empty series. `fgit-node --test source_rebase_inspection_http` covers the live
HTTP workflow, grants, keys, rotation, framing, limits and explicit publication.

These tests were authored with the implementation but were **not executed in
the authoring environment**, which lacked cargo, rustc and rustfmt. Compilation,
Clippy, formatting and repository-wide verification are not claimed here.
