# 2026-09-01: Complete Intent Run identity across the Agent Control Plane

## Scope

This correction removes the remaining places where a numeric `RunId` could be mistaken for the complete machine-enforced identity of an agent run.

`RunId` remains a coordination handle. `IntentRunCommitment` is the identity used for authorization-sensitive continuity. It commits:

```text
RunId
exact AuthorityReadReceiptId
allowed operation classes
resource budget
expiry
```

The complete commitment now propagates through the full control path:

```text
IntentRun
  -> AgentSituationReceipt
  -> AgentControlPulse
  -> AgentChangePlan
  -> TaskClaimReceipt
  -> ActiveTaskClaim
  -> AgentActionPacket
  -> TaskProjectionLease
  -> transferred assignment preference
  -> task mutation envelope and persistence reconciliation
  -> restart lease reconstruction and cleanup
```

Every object remains derived control or coordination evidence. None becomes repository authority merely because it carries a stronger identity.

## Situation and workspace binding

`AgentSituationReceipt` now records both the run coordination ID and `IntentRunCommitment`. Its stable identity includes both values.

A workspace binding must agree with the complete run, not only the numeric ID. Situation deltas classify a commitment change as a run change even when the ID was reused.

## Pulse and planning

`AgentControlPulse` re-computes the supplied run commitment and compares it with the exact situation before producing an actionable recommendation.

`AgentChangePlan` then retains that commitment and refuses a same-ID reconstructed run before effect-scope or resource arithmetic. Its v2 identity commits the exact complete run selected by the pulse.

This refusal order is deliberate. A changed budget, expiry, authority read, or operation set is first an identity substitution; reporting only the downstream scope deficit would understate the protocol violation.

## Claim and activation

`TaskClaimReceipt` and `ActiveTaskClaim` now retain the complete claimant identity.

Claim admission requires the pulse, plan, and supplied run to agree on one commitment. Activation additionally requires the refreshed situation and supplied run to preserve it.

Conflict detection treats overlapping live claims with equal `RunId` but unequal `IntentRunCommitment` as different owners. Numeric identity reuse can no longer collapse a real conflict.

## Action packets

`AgentActionPacket` now binds the same commitment as the situation, plan, and activated claim. Construction refuses identity substitution before context, step, operation, or budget validation.

The v2 packet identity therefore names the exact executor scope rather than only its coordination handle.

## Semantic task leases

`TaskProjectionLease` now stores the claimant `IntentRunCommitment`. The commitment participates in semantic task-state identity and successor-generation derivation.

Release and transfer validate the lease, original claim receipt, activated claim, and supplied source run against that commitment before creating another transition. Restart reconstruction must obtain the same commitment from durable lease history and compare it with the original claim and refreshed situation.

History adapter identity and evidence remain audit metadata; they do not alter semantic task state. The claimant commitment is different: it identifies who actually owns the lease and therefore belongs in semantic state.

## Complete transfer preferences

Fresh review found that retaining the successor commitment only in the transfer audit record was insufficient. A successor assignment containing only `RunId` could still be claimed by another run that reused that ID.

Transferred task state now uses:

```text
Assigned {
  run_id,
  run_commitment,
}
```

The assignment remains a preference, not a plan, capability, lease, or active claim. The intended successor must still construct a fresh situation, pulse, plan, persisted claim, and activation. When it does so, the semantic kernel requires its complete commitment to match the transferred preference.

A same-ID run with another budget, expiry, authority read, or operation set is refused with `AssignedRunCommitmentMismatch`.

## Persistence and recovery

Task mutation envelopes and persistence receipts retain the expanded transfer semantics. Exact-predecessor reconciliation therefore distinguishes successors selected for different complete runs even when their numeric IDs match.

Lease-history reconstruction carries the complete original claimant. Restart cleanup also retains the existing `RunBoundRecoveredTaskClaim` defense in depth and revalidates the supplied run before semantic mutation or store I/O.

Cleanup remains available after claim and run expiry. Expiry stops new work; it does not erase responsibility. The original expired run commitment is still required and cannot be replaced by a same-ID run with a later expiry.

## Focused source tests

The current tree contains public-path source coverage for:

- one commitment surviving situation, pulse, plan, claim, activation, action packet, and semantic lease construction;
- same-ID altered runs being refused at pulse, plan, claim, activation, packet, and release boundaries;
- overlapping same-ID claims with different commitments remaining conflicts;
- deterministic complete-run lease reconstruction;
- same-head later-read substitution refusal;
- same-ID altered lease-history refusal;
- complete transferred assignment state;
- the exact intended successor claiming a transferred generation;
- a same-ID altered successor being refused before lease creation;
- restart cleanup after expiry retaining its complete-run identity.

These are source tests, not a revision-bound execution result.

## Schema lineage

The identity-bearing profiles were advanced rather than silently changing old domains:

```text
AgentSituationReceipt       v2
AgentControlPulse           v2
AgentChangePlan             v2
TaskClaimReceipt            v2
ActiveTaskClaim             v2
AgentActionPacket           v2
TaskProjectionSnapshot      v4
TaskProjectionGeneration    v4
TaskProjectionTransition    v4
TaskLeaseReconstruction     v2
TaskClaimRecovery           v2
TaskMutationEnvelope        v3
TaskPersistenceReceipt      v3
```

The persistence envelope profile already commits the v4 predecessor/successor snapshot identities and the complete successor commitment in transfer semantics; its field layout did not require another revision after the semantic assignment correction.

## Explicit non-claims

This correction does not implement:

- a durable global run-binding registry;
- a concrete Beads transport or codec mapping;
- durable codecs and migrations for the new control objects;
- action-packet execution;
- effect-time capability revocation;
- process or workspace cleanup;
- ECC assembly or canonical publication;
- robot CLI, native API, or MCP surfaces;
- independent batch verification or Bead closure.

## Verification boundary

The implementation environment used for this correction did not provide a usable local FrankenGit checkout, Rust toolchain, or `br`/`bv`. No `cargo fmt`, build, test, Clippy, repository verification, or Beads transition is claimed by this record.

The exact final source revision or a source-identical descendant must pass the repository-owned local and designated independent gates before the correction is represented as verified.