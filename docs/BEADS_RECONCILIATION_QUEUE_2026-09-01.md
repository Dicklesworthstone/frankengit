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
- `16b51ce3fbfaf1c80ce29967be63f3d93f4593cb` — make the strict wrapper the only public construction API;
- `bc5cfc41d10c03068f0972185ffafd7e8fb5e9ea` — run canonical structural validation before exact-class enforcement so malformed row order cannot change the first refusal.

Implemented boundary:

- exact situation/action-packet/plan/run/task binding;
- complete requirement outcome matrix;
- exact plan-required evidence class for satisfied/partial lines;
- deterministic structural refusal precedence before the strict plan-relative class check;
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
- executor consumption of the continuation receipt.

### Proof-carrying handoff and safe cancellation

Revisions:

- `36e64f71d5d17c6d8553339e14c52a6a0bdb1592` — add the public proof-carrying handoff facade;
- `990016ce756cc41fe7c2216d1364f1034a32924c` — add the first public proof-carrying cancellation facade;
- `5ac024eba6a28b1334306a1a6c520eef412a5d46` — make raw handoff/cancellation engines crate-private and expose only the facades;
- `65a69399f9f11a4b36d51033a9a47126b7f4e665` — add public-path lifecycle-continuity integration tests;
- `b9ffc200b03c6e77ff4235211de6d31ba29cf4bb` — remove an unused test import under the warnings-as-errors policy;
- `82fd0c9df4f9930349133bb5631c595fe8ef7977` — correct cancellation so context change never blocks a conservative stop;
- `a91ab9808e9c8bf4849b87208207cffac7dc172b` — update integration tests for changed-context cancellation and optional continuity evidence;
- `9d5ab0616dcb41becd7cb0a323e0863ccb10d635` — reconcile crate-level continuation-versus-cancellation semantics;
- `d6b8cdc6ff996d208822338f06c34001ba125352` — pin the exact changed-component continuity refusal.

Implemented boundary:

- raw capsule and cancellation state-machine engines are crate-private;
- public handoff construction accepts the exact claim-activation situation or a validated `ActiveClaimContinuityReceipt`;
- public handoff identity commits the private canonical capsule plus the continuity proof choice and receipt ID when present;
- receiver acceptance binds the proof-carrying public capsule identity;
- public cancellation binds the exact latest situation, active claim when present, and complete reconciliation report;
- cancellation remains available after peer/search/conflict/evidence/capability/obligation/registry/graph or other context change;
- optional cancellation continuity evidence is revalidated and committed into the public request identity;
- public cancellation completion commits the public request identity, preserving optional proof evidence through terminal state;
- frozen effect membership, immutable effect identity, monotone evidence and charged resources, explicit task release/transfer, named escalation transfer, and leak containment remain enforced by the private engine.

Fresh-review correction:

- the first provisional cancellation facade copied handoff's exact-activation-or-continuity prerequisite;
- that was rejected because handoff continues work while cancellation reduces work;
- the final API never requires continuity to request cancellation.

Not implemented:

- production task claim/release/transfer mutation;
- process reaping or workspace cleanup;
- effect-time capability revocation;
- a later-head ancestry witness for receiver acceptance;
- durable public/private ID codecs and migration;
- a production cancellation orchestrator or action executor;
- canonical publication.

### Documentation revisions

- `884e7475b5a579ad8c30fcda3166f88e4d3d1b40` — implementation-status ledger reconciled to the source tower;
- `ec0c74a917367b7048df0a39c118aa12ae7e8bbe` — changelog updated from architecture-only to active implementation;
- `4b083d09efe2990d12a6e946a29990fa4222378f` — dated change record for action, learning, and continuity;
- `0434581dc1756cb4728f8143e5615211a3b3da88` — dated record extended through the deterministic learning-refusal correction;
- `f6c8e2c72b3f7b51b0dda2b957c422dcd3d8eb84` — implementation status reconciled through proof-carrying lifecycle semantics;
- `a5f56a48d35355fbb138ec623738a745f446abb3` — changelog reconciled through the lifecycle wave;
- `cf9ad1f596373719def5be295927f76865cb424a` — focused lifecycle-continuity design contract;
- `5dfae3590f70ed33120112c1ae6b181b92b8d5d8` — dated implementation record extended through the lifecycle closure.

## Verification state

No Rust or repository-owned verification command was executed in the implementation environment. In particular, there is no observed result for:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

Source-level tests and commit messages are not substitutes for those results.

The designated verifier must test `d6b8cdc6ff996d208822338f06c34001ba125352` or a descendant containing the documentation-only commits. A result against an earlier facade revision does not cover the corrected cancellation semantics or exact typed-refusal oracle.

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
- states that the former handoff/cancellation continuity gap is closed with a proof-carrying handoff facade and a changed-context-safe cancellation facade;
- states that production task/executor/storage/robot/ECC/learning-index surfaces remain absent.

Move the Bead to an implementation-complete or `batch_pending`-equivalent state only when the current Bead policy and acceptance contract support that transition. Do not mark it `verified` or `closed` without the designated revision-bound independent gate.

## Suggested progress-comment substance

```text
Agent Control Plane implementation advanced through bounded Level-1 action packets, plan-strict evidence-grounded outcome learning, time-only active-claim/action-packet continuity, proof-carrying handoff, and changed-context-safe cancellation. Relevant final source revisions include 72a9160d, b5933a65, bc5cfc41, c8a29a12, c3ac9e32, 36e64f71, 5ac024eb, 82fd0c9d, a91ab980, 9d5ab061, and d6b8cdc6. Raw handoff/cancellation engines are crate-private. Later handoff requires and commits full-context continuity; cancellation never requires continuity to stop but optionally retains it in public request/completion identity. Focused public-path test source is present. No formatter/compiler/test/clippy/fast-lane or independent batch result was observed in the implementation environment. Production task/executor/storage/robot/ECC/learning-index surfaces remain absent. Verification or closure is not requested without the designated gate.
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
