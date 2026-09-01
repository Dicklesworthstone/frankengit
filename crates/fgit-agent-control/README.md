# `fgit-agent-control`

Deterministic decision support over the authority-bound agent protocol.

The first implemented surface is `WorkFrontier::build`. It accepts:

- one `fgit_agent::AgentSituationReceipt`;
- the task-projection generation committed by that receipt;
- a bounded set of immutable `WorkItem` rows collected by an adapter.

It produces:

- eligible candidates in one deterministic advisory order;
- every excluded row with its first failed hard precondition;
- a stable commitment to the basis, candidates, exclusions, and ranking witnesses.

## Invariants

Eligibility runs before ordering. No priority, unlock count, cost estimate, model output, or task identifier can make an ineligible row eligible.

The v1 hard-precondition order is:

1. exact task-projection generation;
2. non-terminal task phase;
3. no declared blockers;
4. active authenticated Intent Run;
5. compatible assignment;
6. verifier independence;
7. already-issued capability coverage;
8. known-clear conflict state or a reservation owned by the active run.

Only eligible rows are ordered. The closed v1 ordering is:

1. rework;
2. verification;
3. implementation;
4. lower declared priority value;
5. higher downstream unlock count;
6. lower estimated evidence cost;
7. lexical task identity.

The ordering is advisory. It does not grant authority, claim a Bead, reserve a conflict surface, execute a tool, or publish repository state.

## Adapter contract

A Beads or other task adapter must:

- collect rows from the exact task-projection generation named by the situation receipt;
- derive capability and coordination inputs from authenticated or explicitly derived state;
- preserve stale, unknown, and conflicting states rather than normalizing them into readiness;
- submit at most `MAX_WORK_ITEMS` rows per bounded frontier;
- perform task claims or status mutations only through their owning protocol after frontier construction.

An omitted task projection is a typed frontier refusal, not an empty frontier.

## Verification status

Focused unit tests are present in `src/lib.rs`. No revision-bound Rust toolchain result has yet been observed for this crate, so its presence in source is not a claim that formatting, compilation, tests, clippy, or the repository batch gate passed.