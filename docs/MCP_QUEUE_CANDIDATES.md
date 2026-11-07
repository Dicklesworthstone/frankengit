# Exact queue-head candidates over MCP

`frankengit_source_candidate` with `operation: "prepare_queue_merge"` constructs
an unpublished two-parent merge for the exact first PR in a canonical merge
queue. It validates the queue, PR, branch tips and policy at one authenticated
snapshot. A clean result supplies separate inspection, review and queue-landing
arguments for that same candidate.

Preparation is read-only. It returns native Git objects inside a bounded bundle
without importing them into the repository, moving refs, changing the queue or
PR, sealing a request, recording a review, running workflows or publishing check
results. The trusted-local operator grants remain the authority for each later
operation. This is the single-head queue profile; it does not construct a
multi-PR speculative batch or grant automatic landing authority.

## Launch grants

Queue preparation requires all three read grants together:

```sh
fg-mcp "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --object-format sha256 --expected-incarnation "$INCARNATION" \
  --allow-source --allow-pulls --allow-queues
```

Use the actual existing repository's object format and incarnation. A read-only
session needs no mutation principal. Source, PR and queue reads remain
independent; source writes, PR writes, queue management, reviews and landing do
not imply any of them. Missing read grants are rejected before parsing the
operation's subject or reading native objects. Canonical hidden-ref policy still
applies, including hiding a complete queue when one of its sources is hidden.

| Stage | Required launch grants | Caller action |
| --- | --- | --- |
| Head target refresh | Both `--allow-queue-writes --allow-pull-writes` | When the target advanced, submit the exact original head PR metadata and explicit old/new target observations to `frankengit_queue_refresh`. |
| Queue preparation | `--allow-source --allow-pulls --allow-queues` | Supply the exact queue and PR subject plus explicit commit metadata. |
| Candidate inspection | `--allow-source --allow-pulls` | Submit the returned `inspection_arguments` to `frankengit_source_candidate`. |
| Candidate review | `--allow-review-writes` | Submit `candidate_arguments` to `frankengit_pull_review` with an independently chosen decision, reviewer version and original key. |
| Queue landing | `--allow-queue-landings` | Submit the original queue `publication_arguments` to `frankengit_queue_land_candidate` with a caller-owned original key. |
| Outcome recovery | `--allow-outcomes` | Query `frankengit_transaction_outcome` with the original key. |

Refresh, review, landing and outcome sessions require the launch-bound `--principal` and
`--expected-incarnation`. The operator sponsors each mutation as that principal;
tool arguments and commit author/committer text cannot choose another actor.
Granting ordinary reviewed merges does not grant queue landing. See
[MCP metadata writes and recovery](MCP_METADATA_WRITES.md) for session and
terminal-receipt semantics.

## Supply the exact queue and PR subject

The preparation input keeps queue coordinates separate from PR coordinates:

| Field | Meaning |
| --- | --- |
| `queue_number` | Positive canonical decimal string identifying the queue. |
| `expected_queue_version` | Exact positive queue predecessor version, with room for two successor versions. |
| `number` | Positive canonical decimal string identifying the first queued PR. |
| `expected_version` | Exact positive PR version, with room for its successor. |
| `policy_epoch` | Exact positive current policy epoch as a canonical decimal string. |
| `expected_source`, `expected_target` | Explicit nonzero lowercase native commit OIDs in the selected repository's SHA-1 or SHA-256 format. |
| `source_reference`, `target_reference` | Full, distinct `refs/heads/` branch names. Each accepts its lossless lowercase `_hex` alternative instead; supply exactly one representation per branch. |
| `expected_head` | Optional exact snapshot token; the returned preparation snapshot must match it. |

References are bounded to 1,024 raw bytes. The queue must be idle, with no active
batch, and its first entry must match the selected PR and source tip. The native
selector also checks that the PR is open with the recorded version, branch pair,
live tips and policy epoch. It fences object construction to the same authority
head as queue selection. It never refreshes a changed observation automatically.

Supply `author`, `committer`, `timestamp` and `message_hex` explicitly. Identities
use `Name <address>` form and are at most 1,024 bytes each. `timestamp` is a
positive canonical decimal string of Unix seconds, at most `i64::MAX`.
`message_hex` encodes a nonempty commit message of at most 4 KiB without NUL.
These fields determine native commit bytes; they confer no approval or actor
identity.

`method` defaults to `merge-commit`, the only accepted queue preparation method.
The candidate records target then source as its two ordered parents. Squash and
fast-forward selectors are refused. `merge_profile` defaults to `path-merge-v1`;
`exact-renames-v1` is also available and recognizes the native planner's unique
exact-content regular-file moves. Neither profile runs external merge drivers,
hooks or repository commands.

After the MCP initialization handshake, the following is a complete preparation
call template. Replace every angle-bracket placeholder with actual observations
or intentionally chosen commit metadata before sending it. Decimal strings and
OIDs are not placeholder-tolerant; the names below are explanatory, not runnable
values.

```json
{
  "jsonrpc": "2.0",
  "id": "prepare-queue-1",
  "method": "tools/call",
  "params": {
    "name": "frankengit_source_candidate",
    "arguments": {
      "operation": "prepare_queue_merge",
      "queue_number": "<actual-queue-number>",
      "expected_queue_version": "<actual-queue-version>",
      "number": "<actual-head-pr-number>",
      "expected_version": "<actual-pr-version>",
      "policy_epoch": "<actual-policy-epoch>",
      "source_reference": "<actual-full-source-branch>",
      "target_reference": "<actual-full-target-branch>",
      "expected_source": "<actual-source-commit-oid>",
      "expected_target": "<actual-target-commit-oid>",
      "expected_head": "<actual-snapshot-token>",
      "author": "Chosen Author <author@example.invalid>",
      "committer": "Chosen Committer <committer@example.invalid>",
      "timestamp": "<chosen-positive-unix-seconds>",
      "message_hex": "<chosen-message-as-lowercase-hex>",
      "method": "merge-commit",
      "merge_profile": "path-merge-v1"
    }
  }
}
```

Choose the author and committer text for the intended commit as well. No
idempotency key, principal, upload, successful-check assertion or required
reviewer list belongs in this read operation.

## Keep the three returned argument objects separate

The result identifies `type: "queue_merge_preparation"`, its queue and PR
coordinates, snapshot, profile and method. A `clean` result includes the merge
base, candidate commit, root tree, ordered parents, exact commit bytes, bundle
digest and byte count. Its `candidate_available` field is true.

1. **Inspect:** Submit `inspection_arguments` directly to
   `frankengit_source_candidate`. This uses `operation: "inspect_pull_merge"`,
   the exact snapshot, native candidate and bundle digest to inspect the actual
   resulting tree. Preparation alone is not a full-tree inspection.
2. **Review:** Retain `candidate_arguments` for `frankengit_pull_review`. An
   independently authorized reviewer supplies `review_version`, `decision` and
   `idempotency_key`, plus any decision-required reason. The template identifies
   the PR and exact candidate, not a queue management command.
3. **Land:** Retain the preparation's original `publication_arguments` and
   `publication_tool: "frankengit_queue_land_candidate"`. An independently
   authorized landing session adds its own `idempotency_key` and submits those
   arguments unchanged.

**Preserve the original queue publication template across inspection.** The
generic `inspect_pull_merge` result describes an ordinary PR publication and
can return `frankengit_pull_merge_reviewed` with a different
`publication_arguments` shape. It does not retain the queue number or queue
version. Use its inspection evidence for the selected candidate, and keep the
queue preparation's publication tool and arguments for eventual queue landing.

The queue landing template intentionally renames the preparation coordinates:

| Preparation coordinate | Queue landing argument |
| --- | --- |
| `queue_number` | `number` |
| `expected_queue_version` | `expected_version` |
| PR `number` | `pull_request` |
| PR `expected_version` | `expected_pull_request_version` |
| `policy_epoch` | `expected_policy_epoch` |

It also preserves exact branch bytes, source/target/base/candidate OIDs, actual
repository incarnation, object format and original bundle chunks. It contains
no retry key, `method`, reviewer identity, required reviewer list or check claim.
Current canonical review/check/protected-ref and required-queue rules still
apply at admission. One committed landing moves the target, records the PR
merge and advances the queue twice in a single repository decision.

`conflicted` returns native conflict paths and base/ours/theirs identities;
`already_up_to_date` returns no new candidate. In either case the inspection,
review and publication argument objects, candidate commit, tree and parents
are null, with `candidate_available: false`. Neither result dequeues a PR or
declares it merged. Resource exhaustion and unsupported preparation conditions
are errors, not partial clean candidates.

## Finite work and transport bounds

| Input limit | Default | Maximum |
| --- | --- | --- |
| `max_commits` | 4,096 | 4,096 |
| `max_tree_entries` | 100,000 | 100,000 |
| `max_conflicts` | 64 | 64 |
| `max_output_bytes` | 262,144 | 1,048,576 |

These optional limits are positive JSON integers. Generated object count is
bounded to 1,024, and native graph, source-read, merge-work and request budgets
remain in force. `max_output_bytes` bounds generated object bodies; it does not
raise the MCP bundle transport ceiling.

The returned inline bundle has at most three nonempty lowercase hexadecimal
chunks, at most 8,192 decoded bytes per chunk and 24,576 bytes total. Oversized
artifacts refuse rather than truncate. Generated argument objects reserve 4 KiB
within the 64 KiB MCP request ceiling for the surrounding request and caller
fields. Complete preparation responses remain bounded to 2 MiB. Use the
[native queue CLI](NATIVE_MERGE_QUEUE.md) to prepare larger artifacts and the CLI
or binary HTTP candidate-landing surface to publish them; the MCP chunk limits
remain fixed.

## Continue after the target advances

An earlier queue entry can land while the next PR still records the previous
target. Before constructing its next candidate, an independently authorized
session can call `frankengit_queue_refresh` with both queue-write and PR-write
grants. This exact idle-head operation verifies the original complete PR
title/body, original source branch/tip, target branch, old recorded target,
explicit new live target, queue/PR versions and current policy epoch. It
publishes one target-only PR Update without moving refs or changing queue
membership, order, priority, enqueuing actor or queue version.

After the refresh commits, prepare a new candidate using the updated PR version
and target observation. Previously prepared candidate arguments and old review
or check evidence remain bound to their original subject; they cannot be
silently rewritten into the new attempt. The tool is an explicit mutation with
its own immutable durable key, not an automatic read-time adjustment or a new
queue-runner authorization. Full fields, text bounds and recovery behavior are
documented in [MCP queue refresh](MCP_METADATA_WRITES.md#refresh-the-recorded-target-of-an-idle-queue-head).

## Staleness and original-key recovery

A reordered queue, changed membership/version, non-head PR, moved branch,
changed PR or changed policy can produce `queue_subject_moved`. Hidden or absent
selection returns `reference_unavailable`; an optional snapshot mismatch returns
`candidate_snapshot_moved`. Native preparation-budget exhaustion returns
`resource_limit`, and recognized cancellation returns `preparation_cancelled`.
Preparation does not replace those guards with newer values. A new preparation
requires a deliberate fresh observation of the queue and subject.

Once landing has been attempted, retain that attempt's exact original arguments
and durable key. A timeout, cancellation or lost reply does not prove rollback.
Use a new JSON-RPC ID with the same tool, command and key for retry, or query the
original principal's key through independently granted
`frankengit_transaction_outcome`. Do not refresh the queue/PR versions, policy,
candidate or key while resolving an uncertain attempt.

For the original candidate landing, omit `bundle_hex_chunks` or send `[]` to
recover a known terminal outcome before native object intake, even after later
queue, PR or policy changes. Unknown operations still need valid candidate
bytes to publish. Missing or corrupt unknown-operation bytes yield
`queue_mutation_outcome_unknown`; they do not prove canonical refusal or
rollback. A known canonical refusal remains the original refusal after new
reviews arrive. A separately intended new operation uses fresh observations
and a new key after the earlier attempt has been resolved.

Parser and native integration test definitions cover both hash formats, exact
queue/PR mapping, independent grants, clean and conflicting preparation,
inspection, separately sponsored review, guarded landing, staleness and terminal
recovery. Their existence is not a passing execution claim; validation must
record the tested revision and actual result.
