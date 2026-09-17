# Commit-specific rebase conflict resolution over HTTP

This extends [native linear rebase](SOURCE_REBASE_HTTP.md) with a read-only route:

```text
POST {repository-route}/api/v1/source/rebase/resolve
```

The same source service switch, explicit `read` grant, canonical hidden-ref
policy, principal read quota and pre-body authentication apply. Resolution
rejects transaction keys. It never publishes a successful prefix, changes a
branch, or grants permission to apply its resulting candidate.

## Bind choices to original commits

Submit all preparation fields with the same explicit source tip, upstream,
onto tip, committer, empty policy and resource limits. `expected_head` is
mandatory: use the conflict response's `snapshot_token`. Resolution reconstructs
from those original coordinates; it does not continue from an unverified
intermediate object ID or a mutable server-side sequencer.

Add repeated `resolution` fields using this grammar:

```text
<original-commit-oid>:<path-hex>:base
<original-commit-oid>:<path-hex>:ours
<original-commit-oid>:<path-hex>:theirs
<original-commit-oid>:<path-hex>:delete
<original-commit-oid>:<path-hex>:file:<100644|100755>:<file_N>
```

IDs use the repository's native hash format. Paths are lowercase hexadecimal
repository bytes, not host filenames. `ours` is the accumulated rebased tree;
`theirs` is the original commit currently being replayed; `base` is that
original commit's sole parent. A missing side is not shorthand for deletion.
The same path can legitimately have separate choices at different original
commits. Duplicate or overlapping paths within one original commit refuse.

Only recipes for original commits in the selected linear suffix are valid.
A recipe must resolve every actual conflict in its commit and may not change
clean paths or clean commits. No rename, marker stripping, text normalization,
external merge driver, or merge-commit flattening is implicit.

## Upload exact file contents

Side-only choices may use `application/x-www-form-urlencoded`. File choices
use the existing bounded `multipart/form-data` resolution envelope: one
`command` part containing the form, and `application/octet-stream` parts named
`file_0` through `file_127`. Parts may arrive in either order. Multipart
filenames are ignored and never opened on the server.

Every file part must be referenced exactly once. Missing, reused, duplicate,
mistyped, oversized or unreferenced parts refuse. Empty files remain files;
binary bytes and the explicit regular/executable mode are preserved exactly.
The command is at most 256 KiB. File parts are at most 1 MiB each and 32 MiB
in total under the shared upload profile. Native `max_text_bytes`,
`max_conflicts` and `max_output_bytes` can narrow this further. Recipe counts
and retained bytes are charged across the whole series, not per commit.

The HTTP upload buffer is released before native discovery/reconstruction;
only the selected bounded file bytes remain owned by the recipes.

## Later conflicts and empty results

A request may resolve one commit and discover an unspecified conflict later
in the suffix. This returns HTTP 409 with the new `stopped_commit`, provisional
completed-step mappings, and the already-consumed resolution receipts, but
**no candidate and no bundle**. Include all earlier choices as well as the
new choices in the next request. The unchanged authority snapshot and original
source coordinates let the complete series be reproduced after a node restart.

Future-step recipes may remain unused only in a stopped result. A clean result
must consume every supplied recipe. Resolution receipts bind each processed
original commit to actual conflict sides, choice, and resulting mode/object ID.
The response builder verifies that the returned choices match the request;
custom-file results must match the exact requested native blob hash and mode.
Recipes cannot claim completion by returning the right number of wrong records.

Resolving to `ours` can make a step empty. The explicit stop/drop/keep policy
still applies. A `became_empty` stop can therefore contain a resolution receipt
for its stopped original commit without a completed-step mapping for that
commit. A fully dropped suffix returns a complete onto-only candidate with a
real zero-object pack. Neither situation is silently treated as a new commit.

## Independent publication

Review the complete artifact and publish through `source/rebase/apply`, as
specified in the base contract. File parts and recipes are construction inputs,
not publication credentials; applying a reviewed artifact requires only its
independent exact coordinates, bundle, write grant, and idempotency key. Native
pack/closure/linear-chain validation and current policy remain authoritative.
A stale resolution snapshot is a read conflict, whereas an uncertain publication
must be recovered with the original transaction key, never presumed rolled back.

## Regression coverage and limits

`source_rebase_resolution_http` exercises two independent conflicts in real
SHA-1/SHA-256 repositories, a stop after resolving only the first, restart and
reconstruction, binary and empty uploaded files, part-order/chunked equivalence,
explicit apply and terminal retry, stale snapshots, side choices, empty-result
policy, invalid subjects/parts, global limits and denial before 100-continue.
Focused tests also tamper with resolution blob IDs/modes and future-step claims.

These tests were authored, not executed, in the editing environment. Rust
compilation, formatting, Clippy and repository verification remain unverified.
This is not interactive reorder/squash support, a merge-preserving rebase,
a hosted CI service, or a partial-history publication mechanism.
