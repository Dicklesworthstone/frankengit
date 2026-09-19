# Exact-path source history

`POST {repository-route}/api/v1/source/log` accepts an optional `path_hex`
URL-encoded form field. It returns file or directory change history from the
same current visible ref used by ordinary source history. No host checkout,
external Git engine, blob read, or canonical mutation is performed.

Example form for `src`:

```text
object_format=sha1&ref=refs/heads/main&path_hex=737263&limit=50
```

The listener must have source endpoints enabled and the credential must have
its existing Git read grant. This is a bounded, repository-wide read profile,
not a new path-scoped authorization scheme. The current canonical hidden-ref
policy still applies. An `Idempotency-Key` remains invalid for source reads.

## Selection semantics

Paths are nonempty raw Git path bytes encoded as canonical lowercase hex.
The path limit is 4096 decoded bytes and 64 components. Empty components,
leading/trailing slashes, NUL, `.` and `..` components are rejected. Non-UTF-8
names are preserved. No URL decoding or filesystem normalization is applied to
the decoded path bytes; normal form decoding precedes the hex decoder.

A root commit matches when the path exists. Any other commit matches when the
path's exact `(mode, native object ID)` differs from **at least one** of its
stored parents. A directory compares its subtree ID. This includes additions,
content changes, executable-bit changes, type changes, deletion and recreation.
A merge can match even when its selected entry equals its first parent.

This is explicitly **unsimplified, same-path history**, not Git's default
history-simplification algorithm, `--follow`, first-parent history, or a rename
heuristic. Original parents are returned unchanged. Symlinks and gitlinks are
opaque leaf entries; their contents and targets are never followed. An absent
path at the tip may still have deletion history. A never-present path produces
a complete empty page, not a missing-ref response.

## Results and pagination

Filtered responses use `type: "source_path_log"` and include:

```json
{
  "path_hex": "737263",
  "path_selection": "changed-against-any-parent-v1",
  "total_commits_scope": "matching-path",
  "history_simplified": false,
  "renames_followed": false
}
```

All existing identity, snapshot, read-only and native-commit fields remain.
`source_commit` is the actual ref tip, which need not itself appear among the
matching commits. The ordering remains `child-before-parent-native-id-v1`.
`total_commits`, `after`, and `next_after` count **matching** commits. Filtering
precedes pagination. For continuation, retain the same ref and path, supply the
returned `snapshot_token` as `expected_head`, and use the returned `next_after`.
A nonzero offset without that snapshot is rejected. A changed head refuses the
query rather than mixing pages from different snapshots. Optional
`expected_commit` still checks the selected ref tip, not the first matching row.

## Bounds and failures

Existing `max_commits`, `max_edges`, and `max_metadata_bytes` controls apply.
With `path_hex`, clients may also lower `max_tree_entries` (ceiling 100000) and
`max_cached_bytes` (ceiling 33554432). Those two fields are rejected without a
path. Cache accounting bounds logical entry payload; the graph ceiling also
bounds cache cardinality. All controls must be nonzero and cannot exceed the
profile defaults.

Graph limits cover the complete selected ancestry, even nonmatching commits.
Tree work is charged across the query; identical root-tree/path selections are
cached. The selected object owner retains its pre-allocation object-size and
identity checks. Metadata and response expansion are separately bounded.
Missing/corrupt required objects, cancellation or exhausted limits never become
a successful partial or empty page. No transaction outcome is created.

Without `path_hex`, the existing whole-graph endpoint and its stronger
nonempty/tip-first response checks are unchanged. Blame is unchanged.
