# Native PR and workflow observations at repository positions

`fg at` reads persisted authority history and the existing native PR/check
read models. Current queries include real native PR metadata and lifecycle
state, including merge-only receipts. They no longer substitute an empty PR
map for `latest`, the current decision, or the current authority head.

```text
fg at <storage-root> <tenant> <repository> <position>
fg at <storage-root> <tenant> <repository> <position> refs
fg at <storage-root> <tenant> <repository> <position> prs
fg at <storage-root> <tenant> <repository> <position> checks <pr-number>
fg at <storage-root> <tenant> <repository> <position> diff <other-position>
```

The existing `--actor <principal>` and `--expected-incarnation <id>` options
remain available. This is the existing local operator command surface; a
principal spelling is not a replacement for an authenticated deployment policy.

Positions use `latest`, `decision:N`, `sequence:N`, `commit:<RCR-id>` or
`head:<authority-head-id>`. A requested capsule still needs an available typed
capsule projection and refuses when it is unavailable. The command does not
invent a capsule from a source backup.

## Native state and historical selection

The summary counts the union of visible native PRs and the historical
Digest-valued compatibility view. Its detailed text identifies the two views.
`prs` displays native titles and open/closed/merged state. A merge-only receipt
keeps its real source/target refs and merge commit; it does not invent a title,
opener, or prior metadata. Git SHA-1 and SHA-256 tips retain their typed domains.
A native row takes precedence over a compatibility row at the same PR number.

`diff` compares the complete native PR read models at both selected endpoints.
Metadata edits, close/reopen transitions, changed tips and merge state count as
changes. Ref differences still come from the position-addressed ref projection.
A direction change is honored, including a PR present only at the first endpoint.

`checks N` reads the workflow observations attached to PR N's recorded source
ref and commit at the selected head. It reports the exact selected head,
source tip, whether that source is current at that position, each check ID,
publisher, job, terminal conclusion, and original evidence SHA-256/length.
It does not disclose the evidence body. A changed or deleted source at the
selected head yields an empty check list with `source_current=false`, following
the native check-reader contract. Missing or currently hidden PRs are reported
as having no visible native PR. An observation is not a green merge decision;
merge admission still evaluates its own policy and evidence.

Historical PR and check reads reuse the node's authenticated retained-head
selection. Unsupported policy/configuration/checkpoint or compaction boundaries
refuse; a missing historical page is never replaced with a current one. Current
canonical hidden-ref policy gates both source and target. The existing actor
option additionally restricts these views to refs present in the current
materialization. Historical policy is data, not renewed disclosure authority.

## One exact read basis

One original command context covers authentication, complete history, every
native page, and final readback. The materialized admission receipt must equal
the initial authenticated receipt. The command verifies the same receipt after
loading history and again after constructing the complete answer. Concurrent
head movement therefore refuses the whole query before rendering any answer.
The node is explicitly shut down on success and refusal; shutdown failure does
not return an apparently complete snapshot.

Canonical RCR inventory order is not aggregate causal order. Legacy projection
orders events by aggregate/version within each authenticated decision batch and
refuses conflicting bodies at one version. Native metadata and check projection
use their existing typed authority-frontier readers. A checkpoint-only head
advance preserves its actual current head identity and generation without
fabricating a decision batch or erasing PR state.

The existing complete history/replay bounds remain. Each native PR or check
walk accepts at most 65,536 rows and a 32 MiB row-content budget, in pages of at
most 100. A diff owns two independently bounded native walks. The node's own
history, event, page-memory, cancellation and deadline limits also apply. These
are work/content bounds, not a total process RSS claim; no partial answer is
returned when a bound is exhausted.

## Scope and regression coverage

This slice exposes native PR lifecycle/metadata and per-PR workflow observations
through existing position selection. It does not claim the full plan section
31.8 forge snapshot: review conversations, every issue/queue projection,
retention roots and complete capsule projection remain separate surfaces.
Historical ref reconstruction retains the existing projector's genesis profile;
current refs come from the exact authenticated materialization.

The native regression sources exercise real SHA-1 and SHA-256 import and PR
publications, current aliases, historical open/closed state, reopen differences,
source-directory removal and reopen. On Linux they execute a real trusted-local
workflow, publish its verified check, compare before/after decision positions,
and query the actual `fg` process with an empty executable search path. Separate
real-authority cases cover stale read fences, cancellation and event ordering.
These source cases require the repository's native test gate; their presence is
not evidence that an unbuilt revision has passed it.
