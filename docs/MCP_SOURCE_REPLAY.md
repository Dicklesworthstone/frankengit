# One-commit cherry-pick and revert through MCP

The existing `frankengit_source_candidate` tool now supports
`operation: "prepare_replay"` and `operation: "resolve_replay"`.
They expose the native one-commit replay engine to an explicitly enabled local
operator MCP source-read profile. A successful preparation returns an ordinary
single-parent Git bundle plus ready-to-use arguments for the existing candidate
inspector and source publisher.

The source branch authorizes selection of one historical commit. The selected
commit need not be the branch tip; later source edits are excluded. Cherry-pick
applies that commit's change. Revert applies its inverse and appends a new commit
whose only parent is the exact target tip. Source and target may be the same
branch. Neither operation stages objects, changes refs, creates a transaction,
grants approval, or chooses a publication retry key.

This adapter calls `OneNode::prepare_replay_bundle_in` and
`OneNode::prepare_resolved_replay_bundle_in`. Native source visibility,
historical reachability, root/mainline handling, conflict discovery, reconstruction
and complete target-only bundle validation remain in those APIs. See the
[native replay contract](NATIVE_COMMIT_REPLAY.md) and
[explicit resolution contract](NATIVE_REPLAY_CONFLICT_RESOLUTION.md).

## Inputs

Both operations use the following closed input shape:

| Field | Contract |
| --- | --- |
| `operation` | `prepare_replay` or `resolve_replay`. |
| `profile` | Required, exactly `path-v1`. |
| `direction` | Required, `cherry-pick` or `revert`. |
| `reference` / `reference_hex` | Exactly one encoding of the full target branch name. |
| `source_reference` / `source_reference_hex` | Exactly one encoding of the visible source branch. |
| `expected_base` | Exact current target tip, also the candidate's sole parent. |
| `expected_source` | Exact current source tip authorizing the history walk. |
| `selected_commit` | One commit reachable from that source tip. |
| `mainline` | Optional integer from 1 through 65535, selecting stored parent order. Required for a merge; omitted for a root; an ordinary commit defaults to one. |
| `expected_head` | Exact returned snapshot token. Optional for prepare; required for resolve. |
| `author`, `committer` | Required explicit native header identities, each at most 1024 bytes. |
| `timestamp` | Required positive canonical decimal string, at most `i64::MAX` Unix seconds; UTC encoding. |
| `message_hex` | Required lowercase hex of a nonempty, NUL-free message, at most 4096 decoded bytes. |
| `resolutions` | Required only for resolve; every and only actual conflicts. |

Refs must be fully qualified `refs/heads/` names. Hex alternatives preserve
non-UTF-8 bytes; there is no lossy path normalization. Commit IDs are nonzero
lowercase native SHA-1 or SHA-256 hex matching the opened repository. Mixed
formats, ambiguous encodings, unknown fields, force flags, principals,
arbitrary merge bases, bundle paths and idempotency keys are rejected.

Author and committer are content claims, never credentials. Their native header
syntax is validated, including control/header-injection rejection. Exact
message bytes, CRLF and a missing final newline are retained. The reply's actual
commit bytes are checked against all supplied metadata and the sole target
parent before a candidate handoff is returned.

Example preparation arguments (replace the bracketed identities):

```json
{
  "operation": "prepare_replay",
  "profile": "path-v1",
  "direction": "cherry-pick",
  "reference": "refs/heads/main",
  "source_reference": "refs/heads/topic",
  "expected_base": "<exact target native commit>",
  "expected_source": "<exact source native commit>",
  "selected_commit": "<selected historical native commit>",
  "author": "Operator <operator@example.invalid>",
  "committer": "Operator <operator@example.invalid>",
  "timestamp": "1788883200",
  "message_hex": "4170706c792073656c6563746564206368616e67650a"
}
```

## Complete results and separate publication

Every successful reply binds repository, incarnation, object format, actual
authority snapshot, exact raw refs, source/target/selected commits, requested
mainline, selected parent/mainline, explicit metadata and operation. The
possible states are:

| State | Result |
| --- | --- |
| `prepared` | Automatic replay produced one complete candidate. |
| `resolved` | Explicit choices produced one complete candidate and resolution receipts. |
| `conflicted` | Complete sorted conflicts with exact base/ours/theirs identities and modes; no candidate or handoff. |
| `no_change` | The resulting tree equals the target tree; no empty commit or handoff. Resolution receipts remain present when choices produced this result. |

A clean candidate includes exact commit-body hex, an optional UTF-8 view,
root tree, sole parent, bundle digest/length and generated/packed/borrowed
object counts. The bundle includes needed source-only objects and uses only
the exact target commit as its prerequisite. Source history is not an implicit
prerequisite.

For a candidate:

1. Call `frankengit_source_candidate` with the returned
   `inspection_arguments`. They include `operation: "inspect"`,
   the exact authority snapshot, native candidate and bundle digest. Inspection
   compares the entire candidate tree against the target; preparation itself
   reports `inspection_performed: false`.
2. Review the actual inspection result.
3. Under an independently granted source-write profile, call
   `frankengit_source_publish` with the returned `publication_arguments` plus
   a caller-owned original `idempotency_key`. Preserve that exact command/key
   for retries.

Publication retains the existing sealed admission, expected-old target,
canonical decision and historical recovery behavior. A moved target is never
silently refreshed or forced. A previously decided identical-key retry recovers
its original outcome after reopening or a later branch update. Preparation
does not acquire a PR review/merge grant or impose a new repository-wide
protection policy.

## Resolve the original conflicts

Retain the exact preparation coordinates and `snapshot_token`. Change
the operation to `resolve_replay`, set `expected_head` to that original
token, and supply one choice per conflict:

```json
{
  "resolutions": [
    {"path_hex": "7372632f61", "choice": "ours"},
    {"path_hex": "7372632f62", "choice": "delete"},
    {
      "path_hex": "7372632f63",
      "choice": "file",
      "mode": "100755",
      "bytes_hex_chunks": ["00ff0d0a"]
    }
  ]
}
```

This is a fragment to add to the complete replay request, not a standalone
tool invocation. Allowed choices are `base`, `ours`, `theirs`, `delete`,
and `file`. File mode must be `100644` or `100755`;
`bytes_hex_chunks: []` explicitly creates an empty file. Binary bytes are
preserved. Choosing an absent side does not mean deletion.

Ours always means the target. For cherry-pick, base is the selected parent and
theirs is the selected commit. **For revert, base is the selected commit and
theirs is its selected parent.** Whole directory, symlink and gitlink side
choices retain native identity; nothing follows a symlink or executes a driver.

The native engine reproduces the original conflict set at the pinned snapshot.
Duplicate, overlapping, missing, extra or clean-path choices refuse. Resolving
a clean replay refuses with `no_conflicts_to_resolve`. Receipt validation
joins the complete submitted set by exact raw path and checks each side or
uploaded file hash/mode. Source-tip, target-tip or authority movement rejects
the old resolution instead of restarting against newer state.

## Resource and access boundaries

The ordinary MCP input envelope remains 64 KiB, with strings of at most 16 KiB.
Bundles remain at most 24 KiB, represented by up to three 8 KiB decoded hex
chunks. Both inspection and publication argument templates are independently
checked to leave room for RPC framing and the caller's key.

Resolution admits at most 64 choices. Their decoded path bytes plus all supplied
file content share a 24 KiB aggregate budget; each path is at most 4096 bytes.
These transport limits are independent of the native planner's limits:

| Optional integer input | Default | Maximum |
| --- | ---: | ---: |
| `max_commits` | 4096 | 4096 |
| `max_edges` | 16384 | 16384 |
| `max_tree_entries` | 100000 | 100000 |
| `max_preparation_bytes` | 262144 | 1048576 |

Values must be positive. The adapter additionally caps generated/packed objects
at 1024 and conflicts at 64; other native preparation dimensions retain their
existing bounds. Native source-read and closure-validation budgets remain
independent. An artifact that exceeds the smaller MCP bundle envelope refuses
rather than returning a partial upload.

The complete encoded reply, including raw-path hex expansion, conflict receipts,
commit metadata and both bundle handoffs, must fit 1 MiB. Work, cancellation and
serialization checkpoints use the same native request context. Exhaustion
returns a typed refusal, never a truncated result marked complete.

Only the explicitly enabled operator source-read profile can invoke these
operations. A source-write grant alone does not grant source disclosure. The
sponsored agent tool profile remains closed to candidate replay, including a
direct-handler check; repository text cannot enable it.

This is one-commit path-v1 replay. It adds no range sequencer, persistent
continue/abort state, linear rebase operation, rename inference, force update,
signature authentication or new publication primitive.

## Verification status

The change registers nine Rust unit tests and five persisted-node integration
tests. The latter use actual native object/authority stores and MCP protocol
calls for both SHA-1 and SHA-256. Coverage includes historical selection excluding
later source changes, source-only borrowed objects, raw source refs, exact
metadata, inspection, independent write grants, publication, reopen and
original-key recovery after a later update, same-branch revert, binary conflict
resolution, resolved no-change, root/mainline semantics, stale pins, unavailable
selection and work-budget refusal. Unit tests additionally cover closed schemas,
registry field parity, raw resolution paths, malformed choices, independent
transport/encoded-output bounds and typed cancellation.

Production and test code were checked against the exact native API definitions
and existing persisted fixtures. The editing host was unavailable: Rust
compilation, unit/integration test execution, rustfmt and Clippy were **not run**
for this change. Source review is not execution evidence.
