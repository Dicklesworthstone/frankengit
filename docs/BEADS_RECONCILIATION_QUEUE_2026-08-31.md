# Beads Reconciliation Queue — 2026-08-31

**Status:** non-authoritative operator handoff  
**Do not treat this file as Beads state.** Apply any transition through `br` only after independently re-reading the current issue and dependency graph.

## Why this queue exists

The connected GitHub content interface refuses or truncates the approximately multi-megabyte `.beads/issues.jsonl` blob, and the implementation environment used for these commits does not provide `br` or `bv`. Hand-replacing the ledger through the GitHub contents API would be unsafe: it could discard concurrent rows, comments, dependency changes, or append-only history.

No Bead was therefore claimed, moved, verified, or closed by these commits.

## Reconciliation candidates

### Existing merge task: `frankengit-asa3`

Recommended action after re-read: add a progress comment only; do not close.

Evidence to attach:

- `docs/MERGE_FORGE_EVENT_DELIVERY_CONTRACT.md` narrows the remaining defect to the production persisted-state bridge, pure canonical forge-position/outbox transition, same-CAS admission wiring, fault/retry evidence, and worker consumption where not already generic.
- Current source inspection found that merge stages the forge event batch and records its root but carries forward the canonical forge-position and outbox roots.
- No revision-bound implementation or batch result for the remaining delivery gap was produced in this work session.

Suggested comment substance:

```text
Remaining durable-delivery gap has been reduced to an explicit implementation contract in docs/MERGE_FORGE_EVENT_DELIVERY_CONTRACT.md. The task is still incomplete: production admission must persist canonical forge-position/outbox state and publish both successor roots in the same authority-head CAS, with retry/fault evidence. No verification or closure requested.
```

### Agent control-plane architecture and situation receipt

Recommended action after searching for an existing owning Bead: either attach progress to that Bead or create one if policy permits. Do not retroactively claim verified status.

Landed source/docs:

- `docs/AGENT_CONTROL_PLANE_ARCHITECTURE.md`;
- `crates/fgit-agent/src/situation.rs`;
- `crates/fgit-agent/tests/situation.rs`;
- `docs/AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`.

Important negative evidence:

- the first situation commit accidentally replaced established `fgit-agent` re-exports and required immediate corrective commits;
- no Rust formatter/compiler/test/clippy result was observed;
- no CLI, collector, mutation, handoff, or publication path is claimed.

Recommended status: implementation present, verification pending under the repository's designated batch gate.

### Deterministic work-frontier core

Recommended action after searching for an existing owning Bead: attach as an unverified implementation increment or create a narrowly scoped Bead.

Landed source/docs:

- `crates/fgit-agent-control/src/lib.rs`;
- `crates/fgit-agent-control/Cargo.toml`;
- `crates/fgit-agent-control/README.md`;
- dated change record under `docs/changes/`.

Claimed implementation boundary:

- authority-bound task-projection input;
- bounded deterministic eligibility;
- explicit exclusion reasons;
- advisory deterministic ordering;
- stable frontier commitment;
- focused source-level tests.

Not claimed:

- actual Beads collection or mutation;
- workspace membership or dependency-constellation verification;
- compilation, formatting, tests, clippy, or batch success;
- authority, capability, reservation, or publication.

Recommended status: implementation present, verification pending.

### SQLModel/test-internals defect candidate

Recommended action: retain candidate-fix/pending-verification status unless a newer revision-bound gate result exists.

Prior commit review showed the dependency-constellation change removing the unwanted `visibility` proc-macro and `test-internals` feature from the resolved graph, but no qualifying verification receipt was observed in this session.

## Commands for the Beads-capable operator

The operator should first run the repository-prescribed sync/triage flow from `AGENTS.md`, then inspect exact current state before applying anything. At minimum:

```text
br show frankengit-asa3 --json
br ready --json
bv --robot-triage
```

Use the repository's actual supported `br` comment/update syntax after inspecting `br --help`; do not copy guessed flags from this handoff.

Any verification transition must name the exact tested revision and batch evidence. If `main` advanced after a test result, preserve that fact rather than silently rebinding the result.