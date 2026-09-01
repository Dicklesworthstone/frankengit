# Beads Reconciliation Queue — 2026-09-01

**Status:** non-authoritative operator handoff  
**Do not treat this file as Beads state.** Every claim, comment, dependency, and status transition must be applied through the repository's current `br` interface after re-reading the live issue graph.

## Why this queue exists

The environment used for this implementation wave has GitHub content/write access but does not provide:

- a local FrankenGit worktree;
- `br` or `bv`;
- a Rust toolchain;
- safe transactional access to the approximately multi-megabyte `.beads/issues.jsonl` ledger.

Hand-replacing the ledger through the contents API would risk discarding concurrent comments, dependencies, status transitions, and append-only history. No Bead was therefore claimed, commented, moved, verified, or closed by this wave.

## Implementation evidence to reconcile

### Level-1 action packet

Revisions:

- `72a9160de05c5b126e4e8b4e29c95ae15da32786` — close action-packet continuity, complete-context, run-scope, task, generation, target, evidence, and budget gaps;
- `2378bb3477ad37725dc240f96c21841e8d98bded` — public-path action-packet test source;
- `b5933a65eb3430ac28ece22f08b125e8d4cc72b9` — activate and re-export the module.

Implemented boundary:

- exact claim-activation situation;
- exact task and task-projection generation;
- complete plan-approved context packet set;
- complete same-ID `IntentRun` scope and budget revalidation;
- bounded ordered nonzero steps;
- operation and target containment;
- evidence requirement references;
- aggregate resource attenuation;
- peer-change commitments;
- mandatory preconditions;
- result, refusal, continuation, and executor-profile commitments.

Not implemented:

- action execution;
- capability issuance or effect-time revocation;
- TreeFS/sandbox/evidence adapters;
- task transition;
- durable packet encoding/storage;
- canonical publication.

### Evidence-grounded outcome learning

Revisions:

- `a23125a0ed39aeead9c4f52053f4ac2660ed4ed4` — immutable learning core;
- `78ac0bc9abfad728392b8d53593c85a58ea4c3bd` — public-path learning test source;
- `5997e8d2389d85098e18a96a5bb3372da0587e75` — initial activation;
- `4dc1d58d064329323e52e61959a65d1d3723ef8a` — add plan-strict public wrapper;
- `477408afdfe9004c20de7c0ab671860f8dc30e71` — simplify and pin the exact-class guard;
- `16b51ce3fbfaf1c80ce29967be63f3d93f4593cb` — make the strict wrapper the only public construction API.

Implemented boundary:

- exact situation/action-packet/plan/run/task binding;
- complete requirement outcome matrix;
- exact plan-required evidence class for satisfied/partial lines;
- artifact-linked supporting evidence;
- machine-classified verifier independence;
- plan-contained ownership findings;
- failed hypotheses with applicability and invalidation conditions;
- measured phase resources conserved under plan budget;
- reusable patterns with applicability, invalidation, expected savings, and evidence;
- explicit negative-evidence references;
- typed completed/refused/cancelled/handed-off/contained outcomes.

Not implemented:

- evidence artifact resolution;
- a durable authorization-filtered learning index;
- retrieval ranking or measured avoided-work campaign;
- task verification/closure;
- ECC assembly or publication;
- authority derived from learning.

### Active-claim and packet continuity

Revisions:

- `c8a29a125755f521e18bc62607b9744ce7f1578e` — add `ActiveClaimContinuityReceipt` and `AgentActionPacketContinuation`;
- `207bbb6730b3deb19c0d39f55649a6ab82c8fd35` — public-path continuity test source;
- `c3ac9e32733852af80cb98ec85eb9ddfa841d8b1` — activate and re-export the continuity module.

Implemented boundary:

- exact activation-situation identity;
- exact authenticated authority receipt;
- same Intent Run and workspace;
- no change to any of the ten situation components;
- strictly advancing logical time;
- live claim and run;
- unchanged observed task generation;
- immutable original packet identity;
- later-situation binding;
- original continuation contract;
- fresh mandatory-precondition recheck commitment.

Not implemented:

- plan-relative invalidation when a component changes;
- authority-history proof for a later head;
- continuity-aware public handoff/cancellation construction;
- executor consumption of the continuation receipt.

### Documentation revisions

- `884e7475b5a579ad8c30fcda3166f88e4d3d1b40` — implementation-status ledger reconciled to the source tower;
- `ec0c74a917367b7048df0a39c118aa12ae7e8bbe` — changelog updated from architecture-only to active implementation;
- `4b083d09efe2990d12a6e946a29990fa4222378f` — dated change record for action, learning, and continuity.

## Verification state

No Rust or repository-owned verification command was executed in the implementation environment. In particular, there is no observed result for:

```text
cargo fmt --all --check
cargo test -p fgit-agent
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

Source-level tests and commit messages are not substitutes for those results.

## Recommended operator procedure

First inspect the actual installed tracker syntax and live graph:

```text
br --help
br ready --json
br list --json
bv --robot-triage
```

Then search for the existing Bead whose acceptance contract owns the Agent Control Plane, bounded action packets, handoff/cancellation reconciliation, or outcome learning. Do not infer an ID from this document.

For the unambiguously owning Bead, attach a progress comment that:

- names the exact implementation revisions above;
- states that source and focused test cases are present;
- states that no Rust command result was observed;
- states that handoff/cancellation still need continuity-aware public boundaries;
- states that product adapters, durable codecs/storage, robot/API surfaces, ECC assembly, and independent verification remain absent.

Move the Bead to an implementation-complete or `batch_pending`-equivalent state only when the current Bead policy and acceptance contract support that transition. Do not mark it `verified` or `closed` without the designated revision-bound independent gate.

## Suggested progress-comment substance

```text
Agent Control Plane implementation advanced through bounded Level-1 action packets, plan-strict evidence-grounded outcome learning, and explicit time-only active-claim/action-packet continuity. Relevant revisions: 72a9160d, 2378bb34, b5933a65, a23125a0, 78ac0bc9, 4dc1d58d, 477408af, 16b51ce3, c8a29a12, 207bbb67, c3ac9e32. Source-level tests are present. No formatter/compiler/test/clippy/fast-lane or independent batch result was observed in the implementation environment. Handoff/cancellation still require continuity-aware public construction, and production task/executor/storage/robot/ECC/learning-index surfaces remain absent. Verification or closure is not requested without the designated gate.
```

## Stop conditions for reconciliation

Do not apply a transition when:

- more than one plausible owning Bead exists;
- the Bead acceptance contract excludes this implementation;
- a newer revision changes any named module after a verification result;
- current dependencies reveal a blocker omitted here;
- the local command results fail or are incomplete;
- the only available evidence is source presence, a summary, or hosted Actions state.

The correct outcome in those cases is a progress comment, dependency update, or new narrowly scoped Bead through `br`, never a hand-edited ledger or manufactured closure.