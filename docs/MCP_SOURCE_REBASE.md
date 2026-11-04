# Complete linear rebase through MCP

`frankengit_source_candidate` exposes the native whole-series rebase engine
through `prepare_rebase`, `resolve_rebase`, and `inspect_rebase`. These
operations require the explicit operator source-read grant and
`profile: "linear-v1"`. They prepare and independently inspect a complete
immutable candidate without staging objects, moving branches, opening a
transaction, or choosing publication authority.

The suffix `(upstream, expected_source]` is replayed oldest first onto
`expected_onto`. Source and onto are distinct visible branches selected at one
authenticated authority snapshot. Each original commit must have exactly one
parent along that suffix. Original author headers, message bytes, and supported
encoding metadata are preserved. The new committer and timestamp are explicit
inputs; original signatures are not copied onto different commits.

Publication is a separate tool, **`frankengit_source_publish_rebase`**, under
the independent source-write grant. It replaces the original source branch
using its exact old tip as the lease. The onto commit is the bundle's sole
prerequisite. Those identities have different purposes and are never exchanged.

The adapter delegates to `OneNode::prepare_rebase_bundle_in`,
`prepare_resolved_rebase_bundle_in`, and `inspect_rebase_bundle_in`.
`apply_rebase_bundle_durable_in` remains the publication owner. There is no
replacement graph, merge, pack, policy, or authority implementation in MCP.

## Prepare a complete series

Example arguments for `frankengit_source_candidate` (replace the bracketed
identities with independently selected native IDs):

```json
{
  "operation": "prepare_rebase",
  "profile": "linear-v1",
  "reference": "refs/heads/topic",
  "onto_reference": "refs/heads/main",
  "expected_source": "<exact source tip>",
  "expected_onto": "<exact onto tip>",
  "upstream": "<exclusive original upstream>",
  "empty": "stop",
  "committer": "Operator <operator@example.invalid>",
  "timestamp": "1788883200"
}
```

The preparation and resolution shapes are closed:

| Input | Meaning |
| --- | --- |
| `operation` | `prepare_rebase` or `resolve_rebase`. |
| `profile` | Required, exactly `linear-v1`. |
| `reference` / `reference_hex` | Exactly one encoding of the original source branch to rebase. |
| `onto_reference` / `onto_reference_hex` | Exactly one encoding of the distinct onto branch. |
| `expected_source` | Exact current source tip, also the eventual publication lease. |
| `expected_onto` | Exact current onto tip, also the new series' first parent and sole bundle prerequisite. |
| `upstream` | Exclusive original ancestor. The entire suffix after it is replayed; no implicit merge-base selection. |
| `expected_head` | Optional preparation snapshot token; required for resolution. |
| `empty` | Required policy `stop`, `drop`, or `keep` for changes that become empty. |
| `committer` | Required native identity, at most 1024 bytes, with native header/control validation. |
| `timestamp` | Required positive canonical decimal string, at most `i64::MAX` Unix seconds; emitted in UTC. |
| `resolutions` | Required only for resolution; choices keyed by original commit identity. |

Refs must be fully qualified `refs/heads/` names. Hex encodings preserve exact
non-UTF-8 bytes. All commit IDs are nonzero lowercase native SHA-1 or SHA-256 hex
matching the opened repository. Both raw and text forms together refuse. Unknown
fields, arbitrary principals, force flags, shell commands, message/author
overrides, and publication keys are not accepted by these read operations.

`empty` never defaults. `stop` reports the exact newly empty original commit
without a candidate; `drop` records a `dropped_empty` mapping to the previous
rebased tip; `keep` constructs an empty commit. Originally empty commits remain
preserved independently of this policy. An empty suffix (`upstream` equals
`expected_source`) is valid and yields the onto commit with a zero-object pack.

### Complete outcomes

Responses bind the repository, incarnation, hash format, snapshot token, raw
source and onto refs, exact source/upstream/onto IDs, explicit committer and
timestamp, and empty policy. All counters use canonical decimal strings.

| State | Contract |
| --- | --- |
| `clean` | The entire series completed. `complete` and `series_complete` are true. Exact bundle bytes and inspection/publication argument templates are present. |
| `conflicted` | `stopped_commit` identifies the original with unresolved conflicts. Sorted raw paths and exact base/ours/theirs entries are present. No candidate or bundle is returned. |
| `became_empty` | The explicit `stop` policy stopped at a newly empty original. No candidate or bundle is returned. |

Each chronological step names the `original`, `rewritten`, `tree`, and kind
(`replayed`, `preserved_empty`, or `dropped_empty`). On a stop, any preceding
steps and resolution receipts are diagnostic: `provisional_steps` is true,
`complete`, `series_complete`, and `candidate_available` are false, and candidate,
bundle digest, and both handoffs are null. A successfully reconstructed prefix
cannot be published through this result.

The clean result includes a bundle digest, encoded byte count, and generated,
packed, and borrowed object counts. Export includes needed source-only trees and
blobs; the source branch is never an implicit pack prerequisite. Preparation
sets `inspection_performed: false`; its mapping is not a substitute for reviewing
the uploaded bytes.

## Resolve conflicts against original commits

Retain the original coordinates, committer, timestamp, empty policy, and
`snapshot_token`. Set `operation: "resolve_rebase"`, set `expected_head` to that
token, and add choices for original commits:

```json
{
  "resolutions": [
    {
      "original": "<first conflicted original commit>",
      "paths": [
        {"path_hex": "524541444d45", "choice": "ours"}
      ]
    },
    {
      "original": "<later conflicted original commit>",
      "paths": [
        {
          "path_hex": "7372632f61",
          "choice": "file",
          "mode": "100755",
          "bytes_hex_chunks": ["00ff0d0a"]
        }
      ]
    }
  ]
}
```

This fragment supplements the full resolution request. `original` is the
original native commit ID, never an ordinal or a provisional rewritten ID.
Every call reconstructs the series from the same original source and onto pins.
There is no mutable sequencer or hidden continue state.

At each step, **ours** is the accumulated rebased tree, **theirs** is that
original commit, and **base** is its sole original parent. The path grammar is
shared with one-commit replay: `base`, `ours`, `theirs`, `delete`, and `file`.
A file accepts only mode `100644` or `100755`; an empty chunk array explicitly
creates an empty file. Whole native side choices preserve directory, symlink,
and gitlink identities without following links or executing drivers.

Every supplied path must be an actual conflict at its original commit, and all
conflicts at a supplied step must be covered. Duplicate originals, duplicate or
overlapping paths, missing sides, malformed paths, clean-path choices, and
originals outside the suffix refuse. Unspecified later conflicts stop with
diagnostics and no candidate. Earlier decisions must be supplied again on the
next call. Future recipes can remain unused only in a stopped result.

Resolution receipts follow actual chronological execution. They include the
original ID and each exact discovered conflict, selected choice, and resulting
entry. The adapter checks the receipt against the submitted set, including raw
paths, mode, and replacement blob identity. Source-tip, onto-tip, or authority
movement rejects the original request; it is never silently rebased again on
newer state.

## Independently inspect the uploaded series

Call `frankengit_source_candidate` with the clean result's
`inspection_arguments`. They select `inspect_rebase` and include the exact
source and onto refs/tips, candidate, snapshot token, bundle digest, and complete
bundle chunks. The operation can also inspect independently supplied bytes with
the same explicit coordinates; it does not trust a preparation report.

The inspection shape requires `operation`, `profile`, both branch selectors,
`expected_source`, `expected_onto`, `expected_candidate`, and
`bundle_hex_chunks`. `expected_head` and `expected_bundle_sha256` are optional
independent assertions. Path filters and merge-base mode are not supported for
whole-series inspection.

The native inspector validates the bundle, pack identities, object closure,
and entire bounded single-parent chain ending at onto. Only onto-reachable
objects can supply external pack bases, even if source-only objects happen to
exist in storage. Inspection returns:

- `net_change`: the full old-source-to-candidate tree comparison.
- `commits`: each rewritten commit in order, with exact parent, tree, native
  commit-body hex, and its full parent-to-child comparison.
- Exact submitted bundle digest/length, pack counts, expanded and closure counts,
  and transport-only object counts.
- `completion_scope: "entire_rebase_series_and_net_tree"`, with explicit full
  series/path flags and a publication argument template containing these bytes.

Reviewing every step exposes transient changes that disappear from the final
tree. The shared source-review renderer retains its existing raw path, span,
and hunk validation. Binary bodies are not embedded; their native identities and
classification remain explicit. Inspection does not authenticate authors,
establish replay equivalence, grant approval, or authorize publication.

## Publish with an original caller-owned retry key

After reviewing the actual bytes, use the independent source-write grant to
call `frankengit_source_publish_rebase` with the returned
`publication_arguments` plus an original caller-owned `idempotency_key`:

```json
{
  "reference_hex": "<exact source branch hex>",
  "expected_source": "<original source tip>",
  "onto": "<sole prerequisite>",
  "expected_candidate": "<reviewed complete candidate tip>",
  "bundle_hex_chunks": ["<complete reviewed bundle chunks>"],
  "idempotency_key": "<preserved caller-owned original key>"
}
```

The write shape has no current-head input, onto branch lookup, or preparation
profile override. The dedicated native publisher validates the complete linear
series before a new admission and uses existing authorization, branch
protection, quarantine, sealed decision, and expected-old behavior. The ordinary
single-commit publisher remains a separate tool.

Preserve the original key and exact command for recovery. A terminal retry can
recover its historical decision after reopening, after the source advances, or
after policy changes. The ref transaction seals old source and new candidate;
it does not seal the onto input, pack encoding, committer, or replay decisions.
Accordingly, publication reports `submitted_onto` and
`bundle_validation_receipt: null`. A recovered terminal success does not
attest that newly submitted bytes were independently inspected or that a
different encoding reproduced the same replay. Use `inspect_rebase` for current
evidence about exact uploaded bytes.

## Finite whole-result limits

| Preparation input | Default | Maximum |
| --- | ---: | ---: |
| `max_commits` | 256 | 256 |
| `max_edges` | 16384 | 16384 |
| `max_tree_entries` | 100000 | 100000 |
| `max_preparation_bytes` | 262144 | 1048576 |

Values are positive integers. Generated/packed objects are capped at 1024 and
conflicts at 64. Other native preparation and source-read dimensions retain
their existing finite bounds.

Resolution permits at most 64 paths across all original commits. Decoded path
bytes and all replacement file bytes share one 24 KiB allowance; each path is
at most 4096 bytes. Limits do not restart at the next original commit.

| Inspection input | Default | Maximum |
| --- | ---: | ---: |
| `context_lines` | 3 | 20 |
| `max_changes` | 64 | 64 |
| `max_blob_bytes` | 1048576 | 1048576 |
| `max_output_bytes` | 65536 | 131072 |
| `max_diff_work` | 1000000 | 1000000 |

`context_lines` can be zero; all other values are positive. Text files are
capped at 32 and hunks at 256 across the net comparison and every commit
comparison together. Tree entries, changed entries, text files, retained
path/hunk bytes, and hunks share cumulative native allowances. `max_blob_bytes`
is a per-blob bound and `max_diff_work` is a per-text comparison bound, as in
ordinary source review; the cumulative 32-text limit also bounds the number of
diff invocations. Raw commit bodies additionally share a 128 KiB limit before
hex expansion.

The MCP input remains 64 KiB with individual strings at most 16 KiB. Bundles
are at most 24 KiB, encoded as up to three 8 KiB decoded hex chunks. The complete
handoff arguments are checked independently with space for RPC framing and the
original publication key. The complete encoded result, including hex expansion
and handoffs, must fit 1 MiB. Budget or
cancellation exhaustion refuses the whole response rather than returning a
truncated successful candidate or inspection.

Source reads and writes are independent grants. The sponsored agent profile
cannot invoke these operations, including direct handler entry points. This
profile does not add merge-preserving rebase, rename inference, mutable
continue/abort state, implicit force, signature authentication, or automatic
conflict policy changes.

## Regression coverage

Unit fixtures cover the closed operation schemas, raw refs and both hash
domains, exact original-bound resolution grammar, shared replay choices,
whole-series byte/path limits, generated commit/mapping validation, transport
handoffs, and encoded-result/cancellation refusals. Persisted native fixtures
exercise clean two-commit preparation and independent inspection, a resolved
first step followed by a later conflict without a partial bundle, complete
resolution and inspection, explicit empty stop/drop/keep and empty suffixes,
snapshot/tip movement, resource limits, malformed uploads, and independent
capability refusals. These tests also check that source authority and native
object staging remain unchanged by the read workflow. A complete MCP protocol
fixture passes the returned arguments through inspection and publication,
advances the branch through the existing patch publisher, reopens the node, and
recovers the original rebase decision with the caller's original retry key.
