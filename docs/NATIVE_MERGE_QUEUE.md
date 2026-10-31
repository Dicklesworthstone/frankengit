# Native merge queue management

`fg queue` manages durable, versioned merge queues through the same repository
authority and metadata admission path used by pull requests. Each accepted
enqueue, dequeue or reorder is a canonical forge event with an outbox obligation
and one recoverable terminal transaction outcome.

This interface manages queue membership and order. Speculative batch execution,
required-check orchestration and atomic batch landing are still separate work
under `frankengit-fg083a-merge-queue-impl-95fm`. Queue commands do not move Git
refs, merge a PR or grant review approval. The existing review and protected
merge APIs continue to enforce their own rules.

## Operator boundary

Every command requires `--trusted-local`. The operator supplies the principal
for writes; this is the existing explicit operator-asserted authentication
profile, not a remote credential or an agent capability. A server must establish
its own authorization before exposing the node methods to a remote caller.

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
`scripts/e2e/suites/product/merge_queue.sh` drives the prebuilt `FG_BIN` across
fresh CLI processes. It reports its own results; presence of the suite is not a
claim that the full speculative merge-queue acceptance has passed.
