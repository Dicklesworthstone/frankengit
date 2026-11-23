# Resolve an exact pull-request rebase over HTTP

`POST {REPO_URL}/api/v1/pulls/{number}/resolve-rebase` reconstructs an existing
open PR's complete source suffix with explicit original-commit conflict recipes.
The route uses the same native engine as source rebase resolution. It requires
`read` and `pulls-read` on the same credential, `--allow-pulls`, and current
visibility for both branches. It is a body-bearing read: no transaction key,
vote, staging object, ref change or PR event is created.

## Exact request

Begin with a stopped [`prepare-rebase`](HTTP_CANDIDATE_PREPARATION_API.md)
response. Preserve its exact subject, original upstream, committer, timestamp
and explicit empty policy. Resolution takes the preparation form fields and
adds a required `expected_head` containing the response's `snapshot_token`.
The native operation checks the current PR version, policy epoch, source tip,
target tip and authority head together. It refuses a moved head even when an
unrelated publication left the PR coordinates unchanged.

Add at least one repeated `resolution` field, using one of these descriptors:

```text
ORIGINAL_OID:PATH_HEX:base
ORIGINAL_OID:PATH_HEX:ours
ORIGINAL_OID:PATH_HEX:theirs
ORIGINAL_OID:PATH_HEX:delete
ORIGINAL_OID:PATH_HEX:file:100644:FILE_PART
ORIGINAL_OID:PATH_HEX:file:100755:FILE_PART
```

`ORIGINAL_OID` is the full lowercase native ID of the original commit whose
conflict is being resolved. `PATH_HEX` encodes the exact Git path bytes, including
non-UTF-8 names. `ours` selects the accumulated rebased tree, `theirs` selects the
original commit's entry, and `base` selects its parent's entry. Selecting an
absent side refuses; choose `delete` explicitly to remove an entry. Replacement
files permit only regular or executable file modes.

Plain side/delete recipes may use `application/x-www-form-urlencoded`.
File recipes use `multipart/form-data`: one `command` part with that form media
type, and one `application/octet-stream` part per referenced `file_0` through
`file_127`. Part order is irrelevant. Files are exact borrowed request bytes;
client filenames never select a server filesystem path. Each named part must be
consumed exactly once. Missing, reused, duplicate and unreferenced parts refuse.
Fixed-length and chunked HTTP framing are supported.

Every recipe for one original commit must cover all conflicts at that step.
Duplicate paths, parent/child path overlap, clean paths, clean commits, commits
outside the original suffix and provisional rewritten IDs refuse. Reusing one
path at different original commits is valid. Unknown fields, duplicate subject
fields, query parameters, an alternate `method`, author/message replacements,
and resolution requests without recipes or a head pin refuse. The ordinary
`resolve` route cannot reinterpret these commands as merge-commit resolution.

## Complete candidates and later stops

Resolution uses the same `pull_request_rebase_preparation` metadata type,
`profile: "path-v1"`, `method: "rebase"`, and read-only flags as preparation.
It additionally reports:

```json
{
  "resolution_profile": "original-commit-path-v1",
  "resolution_input_commits": 2,
  "resolution_consumed_commits": 1,
  "resolutions": [
    {
      "original": "<original native commit ID>",
      "paths": [
        {
          "conflict": {
            "path_hex": "<exact path bytes>",
            "kind": "content",
            "base": null,
            "ours": {"mode": 33188, "oid": "<native blob ID>"},
            "theirs": {"mode": 33188, "oid": "<native blob ID>"}
          },
          "choice": "theirs",
          "result": {"mode": 33188, "oid": "<selected native blob ID>"}
        }
      ]
    }
  ]
}
```

Consumed receipts are in original replay order, with byte-sorted paths.
The response validator checks each receipt's requested choice and selected
native identity, including the exact mode and blob hash of file bytes.

A complete result returns HTTP 200 multipart metadata plus the target-named
bundle. All recipes must have been consumed. Every retained rewritten commit
and original author/message remains inspectable through the separate
`inspect-rebase` route; the source branch stays at its original tip.

If a later original commit conflicts, HTTP 409 returns `state: "conflicted"`,
its `stopped_commit`, discovered conflicts, consumed earlier recipes and
provisional completed steps. A newly empty step under `empty=stop` similarly
returns `state: "became_empty"`. Both have `bundle: null`,
`candidate_commit: null`, `series_complete: false` and
`provisional_steps: true`. Future recipes may remain unused only in such a
stopped result. Retain earlier choices and send the complete recipe set again;
each attempt reconstructs the whole original suffix. No successful prefix can
be inspected or published as a complete PR candidate. An entirely dropped
series refuses because it would not advance the target.

## Bounds and publication

The profile allows 128 total path choices across the series, 4096 decoded bytes
per path, 1 MiB per replacement file, and 32 MiB total decoded recipe path/file
bytes. The shared multipart ceiling adds bounded command/framing overhead.
Existing 256-commit, graph/tree/work, 32 MiB generated-object and request-lifetime
bounds still apply to the entire reconstruction. Output retains the 2 MiB
metadata and 64 MiB bundle caps, narrowed by the configured response limit.

A moved subject/head is HTTP 409 `preparation_subject_moved`. Invalid recipes
are 400; missing sides, incomplete choices and attempts to resolve clean
steps/paths are 409; resource limits are 413. These are read failures, not
canonical mutation refusals or unknown publication outcomes.

After a clean result, use native whole-series inspection, then explicit
`method=rebase` review and merge. Resolution receipts authorize neither action.
Existing protected-path rules examine every intermediate commit, and target
movement plus the PR merge event and outbox obligation publish atomically.
Retry recovery for review or merge retains its original command and key;
reconstructing another candidate does not settle an ambiguous mutation.

Regressions are in `fgit-node/tests/native_rebase_merge.rs` and
`fgit-node/tests/native_pull_rebase_http.rs`: both hash formats, two successive
conflicts, exact binary replacement, head movement, incomplete candidates,
dedicated inspection, protected review, unchanged source and merge retry.
Authored tests alone do not establish an executed gate.
