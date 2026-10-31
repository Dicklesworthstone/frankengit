# Native merge queues and atomic head landing

`fg queue` manages durable, versioned merge queues through the same repository
authority and admission path used by pull requests. Each accepted enqueue,
dequeue or reorder is a canonical forge event with an outbox obligation and one
recoverable terminal transaction outcome. `fg queue land` executes an exact
queue-head PR through native fast-forward admission and atomically publishes the
target move, PR merge and queue completion.

The landing profile handles one existing fast-forward candidate. Speculative
merge trains, synthetic merge objects and autonomous required-check execution
remain separate work under `frankengit-fg083a-merge-queue-impl-95fm`. Queue
membership commands do not grant approval; landing enforces the existing review,
check, authentication and protected-ref rules.

## Operator boundary

Every command requires `--trusted-local`. The operator supplies the principal
for writes; this is the existing explicit operator-asserted authentication
profile, not a remote credential or an agent capability. Authenticated remote
membership management is available through the separately scoped
[HTTP queue API](NATIVE_HTTP_QUEUES.md). That API does not expose landing.

Writes also require the repository's exact incarnation, an original client
idempotency key, the queue number, its target branch and expected queue version.
Queue version `0` means that the stream must not exist and is accepted only for
the first enqueue. Existing queues require their exact positive version.

The queue number remains bound to its original target branch even after every
entry is removed. An empty existing queue is not a new stream.

## Enqueue an exact pull request

Obtain the current PR version, source branch and source/target commit IDs from
the native PR view. Then submit the exact observation:

```bash
fg queue enqueue "$STORAGE" "$TENANT" "$REPOSITORY" 1 \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" \
  --idempotency-key queue-pr-42-v1 \
  --expected-version 0 --target-ref refs/heads/main \
  --pull-request 42 --expected-pull-version 1 \
  --source-ref refs/heads/feature \
  --expected-source-tip "$SOURCE_COMMIT" \
  --expected-target-tip "$TARGET_COMMIT" \
  --priority 10
```

The PR must be open, visible and at the named aggregate version. Its recorded
source branch, target branch and both tips must match the request, and both
live refs must still name those tips. A moved branch requires an explicit PR
refresh and a new command based on the new observation. Validation runs against
the exact authority predecessor selected for each publication attempt.

The actor comes from the authenticated publication session. Queue event bytes,
the observed PR version and expected target tip all participate in the sealed
request, preventing retry from silently selecting a different candidate.

Higher priority enters before lower priority; equal priority uses enqueue order.
Re-enqueueing an already queued PR with a new key and exact current versions
replaces its source/tip, actor, priority and FIFO position. The queue holds at
most 1,024 entries. Replacement remains possible when the queue is full.

## Read and paginate

```bash
fg queue show "$STORAGE" "$TENANT" "$REPOSITORY" 1 --trusted-local
fg queue list "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local --limit 20
```

Responses include `source_head`, an opaque `snapshot_token`, queue versions,
entries and explicit execution order. Reference names also include hexadecimal
bytes so a non-UTF-8 Git ref is not silently replaced by a lossy display string.

Use the first page's token when continuing:

```bash
fg queue list "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --after "$NEXT_AFTER" --limit 20 --expected-head "$SNAPSHOT_TOKEN"
```

`--after` greater than zero requires a snapshot token. A token selects that exact
retained ancestor across ordinary publications; it never silently selects newer
state. The existing retained-metadata read contract bounds historical traversal
and refuses unavailable snapshots, policy/configuration epoch changes and
compaction boundaries.

Current canonical hidden-ref policy and caller visibility apply before any
queue is disclosed. A queue with a hidden target or source entry is omitted as
a whole. Hidden and absent queues have the same single-queue response. Pages
contain up to 100 complete visible queues, ordered by queue number. CLI output
is bounded to 8 MiB; request a smaller page if a complete response exceeds it.

Queue reads reconstruct state from canonically committed events. The active
outbox provides a fast path. Successful delivery may retire its entries, so
missing queue events are recovered from the verified repository record history
at the selected head. Acknowledgment does not erase the queue's prior state.

A request scans at most 65,536 forge events and 128 MiB of encoded event and
decision batches, and retains at most 32 MiB of selected queue events. History
recovery additionally bounds traversal to 4,096 predecessor steps and 65,536
decisions. Refusals and checkpoint steps count toward the work bounds even
though they do not change a queue. Listing reconstructs all queues after the
cursor before selecting the visible page, so a small page limit does not avoid
these history limits. Single-queue reads and writes also scan the outbox and
may require history recovery. Exceeding a bound produces an explicit resource
refusal; unavailable or compacted required history also refuses. Indexed,
incremental queue reconstruction remains future work.

## Reorder and remove

Reorder supplies the complete set of current PR numbers, exactly once, in the
desired order. It persists that order without changing their priority fields:

```bash
fg queue reorder "$STORAGE" "$TENANT" "$REPOSITORY" 1 \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" \
  --idempotency-key queue-order-v3 \
  --expected-version 3 --target-ref refs/heads/main \
  --entry 43 --entry 42
```

Unknown, duplicated or omitted entries are refused. Existing historical queue
events retain their prefix-reorder replay semantics; this command requires a
complete order so the operator's intended membership is explicit.

Removal records its reason and actor:

```bash
fg queue dequeue "$STORAGE" "$TENANT" "$REPOSITORY" 1 \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" \
  --idempotency-key queue-remove-42-v4 \
  --expected-version 4 --target-ref refs/heads/main \
  --pull-request 42 --reason withdrawn
```

Reasons are `withdrawn`, `conflict`, `check-failed`, `base-moved`, `evicted` and
`admin-override`. They are recorded classifications, not permission grants.
Removing an absent entry refuses. Membership changes refuse while a canonical
batch is active; replay requires that batch's exact identity and ordered
membership when accepting its terminal event.

## Land the exact queue head

Read the current queue and its first PR, then supply all observed guards. Landing
requires a positive queue version, the actual current PR version, current policy
epoch, and the exact source and target tips:

```bash
fg queue land "$STORAGE" "$TENANT" "$REPOSITORY" 1 \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" \
  --idempotency-key land-queue-1-pr-42-observation-1 \
  --expected-version "$QUEUE_VERSION" \
  --expected-policy-epoch "$POLICY_EPOCH" \
  --pull-request 42 --expected-pull-version "$PR_VERSION" \
  --source-ref refs/heads/feature --target-ref refs/heads/main \
  --expected-source-tip "$SOURCE_COMMIT" \
  --expected-target-tip "$TARGET_COMMIT"
```

The PR must be open, visible, at the exact requested version, and the first entry
in the queue's persisted execution order. Both the queued entry and canonical
PR must name the requested source candidate. The queue must be idle and bound to
the requested target. Live source and target refs must still match their observed
tips. A stale queue, PR or policy observation refuses; a lower-priority or reordered
non-head entry cannot skip ahead. A valid landing needs a new target tip, with
the expected target commit proven to be its ancestor by the native object reader.

Landing uses **FastForwardOnly**. It does not manufacture a merge commit, fall back
to another merge method, run a workflow, or accept a caller assertion that checks
passed. Required checks and reviews must already exist as valid evidence for the
exact native candidate. Withdrawn approval, missing checks, disallowed
authentication, hidden refs and divergent histories refuse through the ordinary
native merge rules. These rules are reevaluated at each selected authority head
if publication races with another transaction.

A successful landing publishes one RCR, one terminal decision and one outbox
obligation containing this ordered event batch:

| Event | Aggregate version | Result |
|---|---|---|
| `BatchFormed` | Queue `q + 1` | Identify the one exact selected entry |
| `MergeCommittedNative` | PR `p + 1` | Record the native fast-forward merge |
| `BatchLanded` | Queue `q + 2` | Complete that batch and remove only its entry |

The target ref advances in that same publication. No intermediate formation,
partially merged PR or separately dequeued state is authoritative. Remaining
entries preserve their order; their next landing must explicitly account for
the moved target and the PR's current observation. This profile does not create
synthetic queue refs or move the source branch.

The sealed request commits to the entire event batch, exact non-force ref move,
policy epoch and authenticated principal. Retrying the original landing cannot
silently select a new queue head or new candidate. Two competing requests for the
same queue predecessor can produce only one successful landing; the loser is a
durable stale refusal. An identical retry of the winning request recovers the
original decision even after later queue edits, policy replacement or restart.

Successful landing receipts report `refs_changed: true`. Membership command
receipts and canonical refusals report `false`. Receipt output failure preserves
the known terminal transaction identity in the diagnostic; recover it with the
original key instead of interpreting the failure as rollback.

## Retry and recovery

A response describes the original terminal decision, not necessarily today's
queue state. Retrying the identical command with the same principal and key
recovers the same transaction and outcome, including after process restart or
later queue mutations. Recovery precedes new-publication intake and quota gates.
Reusing a key with different command bytes is refused.

After a timeout, lost response or output failure, retry the **identical** command
or use `fg outcome`. Do not replace the key or refresh versions while recovering
an ambiguous attempt. Once its outcome is known, a new intended action receives
a new key and freshly observed versions.

| Exit code | Meaning |
|---|---|
| `0` | Complete read or committed queue command |
| `2` | Input, infrastructure, cleanup or output error; not evidence of rollback |
| `3` | Canonical terminal refusal |
| `4` | Single requested queue unavailable or absent |

Both SHA-1 and SHA-256 repositories use this interface. Pass
`--object-format sha256` for SHA-256 repositories; mixed or zero object IDs are
refused before publication.

## Implementation and verification entrypoints

The queue model owns bounded replay and command construction in
`fgit-forge::merge_queue`. Native admission owns exact sealing, current PR and
ref validation, canonical replay and publication in
`fgit_admission::merge::native::queue`. `OneNode` adds authenticated session
provenance, visibility, retained snapshots and outcome recovery. `fg queue`
calls those APIs directly; no queue side file or separate authoritative table
is introduced.

Focused tests cover model transitions, command guards, persistent node
lifecycle, hash formats, conflicting observations, visibility and restart.
Landing tests also cover atomic coupled stream advancement, real ancestry,
review withdrawal and reapproval, missing required checks, competing attempts,
and activated authentication policies with recorded evidence.
`scripts/e2e/suites/product/merge_queue.sh` drives the prebuilt `FG_BIN` across
fresh CLI processes. It reports its own results; presence of the suite is not a
claim that the full speculative merge-queue acceptance has passed.
