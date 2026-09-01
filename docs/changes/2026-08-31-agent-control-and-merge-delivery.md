# 2026-08-31: Agent control plane and merge-delivery contract

## Added

- `docs/AGENT_CONTROL_PLANE_ARCHITECTURE.md`, defining one authority-bound observe → orient → plan → act → verify → reconcile → learn loop over existing FrankenGit primitives rather than a second workflow or truth plane.
- `fgit-agent::situation`, with deterministic `AgentSituationReceipt` and `SituationDelta` types over one authenticated authority receipt, optional Intent Run/workspace binding, explicit observed-or-omitted component generations, and rollback/fork refusals.
- Focused `fgit-agent` situation tests using the repository's authenticated in-memory authority-store fixture.
- `crates/fgit-agent-control`, implementing a bounded deterministic `WorkFrontier` that separates hard eligibility from advisory ordering and retains a typed exclusion for every rejected task row.
- `docs/AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`, preserving exact implementation boundaries and negative verification evidence.
- `docs/MERGE_FORGE_EVENT_DELIVERY_CONTRACT.md`, narrowing the remaining merge defect to persisted canonical forge-position/outbox state, same-CAS publication, stable effect identity, and crash/retry evidence.

## Corrected during implementation

The initial situation-receipt commit accidentally replaced established `fgit-agent` public re-exports with names from a stale API shape. A follow-up commit restored the exact existing public surface and added only the new situation module and exports. The situation implementation and tests were then rewritten against the current authority, codec, Intent Run, and TreeFS APIs.

This correction is part of the permanent history. It is intentionally documented rather than hidden because it is useful negative evidence for future cross-crate changes: preserve the owning crate's existing export surface before adding a protocol slice.

## Work-frontier policy

The v1 frontier applies hard preconditions before any ordering:

1. exact task-projection generation;
2. non-terminal phase;
3. no declared blockers;
4. active authenticated Intent Run;
5. compatible assignment;
6. verifier independence;
7. issued capability coverage;
8. known-clear conflict state or a reservation owned by the active run.

Eligible rows are then ordered deterministically by rework, verification, implementation, declared priority, downstream unlock count, estimated evidence cost, and stable task identity.

The frontier does not claim or mutate Beads and grants no authority.

## Verification status

No Rust toolchain result was observed in the implementation environment. Therefore this change record makes no claim that formatting, compilation, tests, clippy, or the repository batch gate passed.

Required focused commands include:

```text
cargo fmt --all --check
cargo test -p fgit-agent --test situation
cargo test -p fgit-agent
cargo test -p fgit-agent-control
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo clippy -p fgit-agent-control --all-targets -- -D warnings
```

A designated revision-bound batch gate remains required before any related Bead may be represented as verified or closed.

## Remaining merge gap

Merge admission still needs the production persisted-state bridge and atomic wiring described in `MERGE_FORGE_EVENT_DELIVERY_CONTRACT.md`. Staging a forge event batch and recording its root does not by itself advance the canonical forge position or create a durable outbox obligation.