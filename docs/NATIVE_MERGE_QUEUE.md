# Native merge queues and atomic head landing

`fg queue` manages durable, versioned merge queues through the same repository
authority and admission path used by pull requests. Each accepted enqueue,
dequeue or reorder is a canonical forge event with an outbox obligation and one
recoverable terminal transaction outcome. `fg queue land` executes an exact
queue-head PR through native fast-forward admission and atomically publishes the
target move, PR merge and queue completion.

`fg queue prepare` constructs a real two-parent merge candidate for a divergent
queue head. `fg queue land-candidate` validates its bundle and publishes the
candidate with the same atomic queue/PR/ref transition. Both landing profiles
handle one exact queue head. A [queue workflow watcher](NATIVE_MERGE_QUEUE_WORKFLOW_WATCH.md)
can select the current head, prepare its real candidate, execute it on a fixed
CI branch and publish exact checks. Speculative multi-PR trains, synthetic queue
refs and autonomous landing remain separate work under
`frankengit-fg083a-merge-queue-impl-95fm`. Queue membership and
preparation do not grant approval; landing enforces current review, check,
authentication and protected-ref rules.

## Operator boundary

Every command requires `--trusted-local`. The operator supplies the principal
for writes; this is the existing explicit operator-asserted authentication
profile, not a remote credential or an agent capability. Authenticated remote
membership management and both landing profiles are available through the
separately scoped [HTTP queue API](NATIVE_HTTP_QUEUES.md). The candidate endpoint
accepts an exact prepared bundle with the queue/PR/ref/policy observations;
HTTP publication does not construct or refresh that candidate implicitly.

Writes also require the repository's exact incarnation, an original client
idempotency key, the queue number, its target branch and expected queue version.
Queue version `0` means that the stream must not exist and is accepted only for
the first enqueue. Existing queues require their exact positive version.

The queue number remains bound to its original target branch even after every
entry is removed. An empty existing queue is not a new stream.

## Require queue landing on a protected branch

An administrator can add `--require-merge-queue refs/heads/main` to a complete
`fg protection set` replacement. The branch may require only a queue, or combine
that requirement with exact candidate reviews and workflow checks. Preserve all
other intended branch rules and administrators when replacing the policy; see
[mandatory branch protection](MANDATORY_REVIEW_PROTECTION.md).

Ordinary receive, imports, branch changes, workspace/rebase publication and
ordinary PR merges cannot supply queue authority. Only a validated canonical
queue landing at the selected repository basis can satisfy the requirement.
Both `land` and `land-candidate`, including their authenticated HTTP counterparts,
can qualify. Any native queue targeting that exact branch can qualify, but only
its current head may land. Queue membership, a synthetic-looking event batch,
a successful local workflow journal or a caller-supplied receipt is insufficient.

Installing or replacing protection advances the policy epoch. A newly intended
landing must name the current epoch; an already decided request keeps its
original outcome. Upgrade all writers before activating the required policy
encoding. Queue preparation, inspection, review votes and workflow execution
remain available because they do not publish a protected target move.

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

## Prepare and land a divergent head

Independent PRs commonly diverge after an earlier queue entry moves the target.
First update the surviving PR's recorded target to the observed live target,
and re-enqueue it with the exact current queue and PR versions. This is a new
intended operation; never refresh guards merely to recover an earlier request.
The queue's first entry then supplies the exact preparation subject:

```bash
fg queue prepare "$STORAGE" "$TENANT" "$REPOSITORY" 1 \
  --trusted-local --expected-incarnation "$INCARNATION" \
  --expected-version "$QUEUE_VERSION" --expected-policy-epoch "$POLICY_EPOCH" \
  --pull-request 43 --expected-pull-version "$PR_VERSION" \
  --source-ref refs/heads/next-feature --target-ref refs/heads/main \
  --expected-source-tip "$SOURCE_COMMIT" --expected-target-tip "$TARGET_COMMIT" \
  --profile path-v1 --author 'Integrator <integrator@example.invalid>' \
  --timestamp 1700000000 --message 'Integrate the reviewed queue head' \
  --output-bundle queue-head.bundle
```

Preparation reads the idle queue, exact first entry, open PR, policy and native
objects from the same authenticated authority head. A concurrent publication
between these selections refuses instead of combining observations. The
operation leaves repository authority unchanged. It never reserves a canonical
batch, updates a ref, writes a check or seals a landing request.

Both supported profiles are explicit: `path-v1` uses the existing bounded path
merge; `exact-renames-v1` additionally handles unique content-identical regular
file moves. Neither implies Git `ort` equivalence or ambient merge drivers.
Author, timestamp and message are required; the committer defaults to the author
unless `--committer` is supplied. Identical object inputs and metadata produce
the same native candidate identity. Commit style is always two-parent.

A clean result returns `candidate_commit`, `merge_base`, `root_tree`, exact queue
and PR guards, source/target tips and the selected snapshot token. The complete
bundle is created atomically as a new regular file; an existing destination is
never replaced. Local bundles are bounded to 128 MiB and complete JSON to 8 MiB.
Conflicts return structured path/conflict information and exit `5`, with no
bundle. An already-integrated source returns `already_up_to_date` with no bundle.

Review the actual candidate using the existing
[exact candidate review workflow](EXACT_CANDIDATE_REVIEW_WORKFLOW.md). When policy
requires CI, the existing [merge-candidate workflow watcher](NATIVE_PULL_REQUEST_MERGE_WORKFLOW_WATCH.md)
can prepare, admit to a fixed CI branch, execute and canonically publish checks
for that same commit. Use identical source/target observations, merge profile,
author, committer, timestamp and message. A source-head check or a successful
local journal without its canonical check publication cannot satisfy the exact
candidate's required checks. The CI branch must still select that candidate.

Submit the reviewed bundle with the candidate coordinates from preparation:

```bash
fg queue land-candidate "$STORAGE" "$TENANT" "$REPOSITORY" 1 \
  --trusted-local --principal "$PRINCIPAL" \
  --expected-incarnation "$INCARNATION" --idempotency-key land-queue-1-pr-43-candidate-1 \
  --expected-version "$QUEUE_VERSION" --expected-policy-epoch "$POLICY_EPOCH" \
  --pull-request 43 --expected-pull-version "$PR_VERSION" \
  --source-ref refs/heads/next-feature --target-ref refs/heads/main \
  --expected-source-tip "$SOURCE_COMMIT" --expected-target-tip "$TARGET_COMMIT" \
  --merge-base "$MERGE_BASE" --expected-commit "$CANDIDATE_COMMIT" \
  --bundle queue-head.bundle
```

For authenticated remote publication, send the same exact observations and
bundle to `POST /api/v1/queues/{number}/land-candidate` using the
[bounded multipart profile](NATIVE_HTTP_QUEUES.md#prepared-two-parent-candidate-landing).
The remote bundle limit is 64 MiB, subject to a smaller configured HTTP limit.
The `queues-land` grant and current target reference ceiling apply independently
of queue management and ordinary PR merge permissions.

The node privately quarantines the bundle, verifies the actual commit and
closure, proves ordered parents `[target-before, source]` and common ancestry,
and applies current native review/check/authentication policy. A received
ref-only proof is never admitted separately. The exact queue head, PR, live
refs and policy are independently checked again against each publication basis.
Candidate bytes and earlier preparation do not waive those guards.

Success produces the same three-event batch as fast-forward landing, with
`MergeCommittedNative` and `BatchLanded` naming the actual two-parent candidate.
One RCR and one decision advance the target, queue by two versions and PR by one.
The source ref and other queued entries remain intact. The seal binds the full
event batch, policy and `two-parent-head/v1` profile; it cannot alias the existing
`fast-forward-head/v1` request. Batch identity alone is not candidate evidence:
different commit metadata may produce a different candidate for the same entry.

The native `land_queue_head_bundle_durable_in` API retains the publication
session's authentication provenance and resolves an exact decided request before
quarantine, new-work quota or current policy checks. A known decision therefore
does not require retained bundle bytes. The CLI reads the bounded bundle first;
if it is unavailable, recover with `fg outcome` and the original principal/key.
Different candidate coordinates under an already used key refuse. A prior
canonical refusal remains that refusal after a later approval or check; use a
deliberate new key only after resolving the original outcome.

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
| `0` | Complete read, prepared/no-op candidate, or committed queue command |
| `2` | Input, infrastructure, cleanup or output error; not evidence of rollback |
| `3` | Canonical terminal refusal |
| `4` | Single requested queue unavailable or absent |
| `5` | Candidate preparation conflicts; no bundle was created |

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
Candidate tests exercise real divergent histories, two-parent object validation,
exact subject selection, malformed bundles, stale guards and original outcomes.
`scripts/e2e/suites/product/merge_queue.sh` drives the prebuilt `FG_BIN` across
fresh CLI processes, including a fast-forward head followed by preparation and
two-parent landing of its divergent successor. It reports its own results; presence of the suite is not a
claim that the full speculative merge-queue acceptance has passed.
