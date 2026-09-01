# 2026-09-01: Agent Control Plane task recovery and persisted cleanup

## Scope

This wave closes the restart gap between task collection and safe responsibility cleanup.

The preceding control plane could collect current task rows, compute deterministic task transitions, and persist exact-predecessor mutations. It still lacked a complete public path for a restarted process to:

1. turn a collected claimed row back into its exact active lease;
2. prove that lease matches the original claim receipt;
3. recover an active claim under the exact authenticated read event;
4. release the recovered claim through the one-shot persistence protocol;
5. retain recovery evidence through success, conflict, or ambiguity.

The implementation supplies that path without creating a second task database or treating task state as repository authority.

## Starting basis

The wave began at live `main`:

```text
3a8318b529762569d0dcb048efd39b43584ed262
```

That revision already contained `task_collection_bridge.rs` and a public-path test file, but the crate root did not declare or re-export the module. The first correction activated the already-landed source so it participated in compilation.

## Incremental source commits

The source and focused-test sequence was deliberately incremental:

```text
9f54b2c699e7a116fbb50c79189fbf750a428cfd
    fix(agent-control): activate collected task bridge

35870ebaeb870530a1f278ea7b021fbb9c114687
    feat(agent-control): reconstruct collected active leases

b95cf5b284f3b3e93f15429cdb86195a7177c359
    feat(agent-control): expose lease reconstruction evidence

93f7e1f9bbe39a410bdad11edce93ec92d8dae17
    test(agent-control): pin durable lease reconstruction

3fe49f292137d1825b0009dce16839c16669a49f
    fix(agent-control): derive real plan IDs in lease tests

af9561a2e9a2832cc56c5d315979f754b0cc46e6
    fix(agent-control): make lease fixture temporally coherent

e2b33a62b6602c54522b0dcfc221fbfa395ac8fa
    feat(agent-control): recover active claims from persisted leases

6448d04ab243bfa8fc568463f6bab86c1e264a5a
    feat(agent-control): expose restart-safe claim recovery

8aa8e1c12b25fdf0496b2e2507ef4bfce9031b1c
    test(agent-control): pin restart-safe active claim recovery

c76916d3bcb3ec28c5a406b6cb4d31db605f32fd
    feat(agent-control): persist recovered task cleanup

5d82bc407919ce6d4ccd249808db2067b4190043
    feat(agent-control): expose persisted restart cleanup

1402ca7696009f17f6466d37cc89f12cb6b6d794
    test(agent-control): pin persisted restart cleanup

e453dc36e0011267b1e8fc5b0b9744f021946a71
    fix(agent-control): model post-request recovery reads
```

Documentation reconciliation followed those source commits.

## Activated collection bridge

The existing collection bridge and public-path test were disconnected from `fgit-agent` because `lib.rs` did not declare the module.

The module is now compiled and exported. An unassigned collected row can become an exact authority-bound claim basis only when:

- the collection and supplied authority use the same exact authenticated read event;
- the task exists;
- the row carries no assignee, plan, expiry, or reservation state.

A claimed row returns `LeaseReconstructionRequired` rather than being downgraded to unclaimed state.

## Durable lease reconstruction

`TaskLeaseHistoryObservation` supplies the only current-claim facts absent from the v1 collected row:

```text
previous generation
original claim instant
```

It also binds collection receipt, task, current generation, history-reader profile, and evidence root to prevent replay across another collection.

`reconstruct_collected_task_lease` reuses and validates the collected row's:

- assignee;
- plan;
- expiry;
- reservation surface;
- conflict state;
- phase;
- current generation.

The resulting `TaskLeaseReconstructionReceipt` retains:

- exact collection identity;
- exact authenticated read identity;
- reconstructed semantic snapshot;
- historical predecessor and claim time;
- adapter and evidence commitments.

History adapter/evidence identity remains separate from semantic task state.

## Fresh-review fixture corrections

Two fixture shortcuts were found and corrected before documentation was frozen.

### Opaque plan identity

The first lease test attempted to construct an `AgentChangePlanId` from arbitrary bytes. That constructor is intentionally not public.

The test now builds a real:

```text
AgentSituationReceipt
-> WorkFrontier
-> AgentControlPulse
-> AgentChangePlan
```

and uses the plan's actual commitment.

### Temporal coherence

The first real plan was built against the already-claimed generation. That produced a valid plan identity but an impossible history.

The corrected fixture builds the plan at logical time 14 against the predecessor generation, records the claim at time 15, and observes the current claimed row at time 21.

## Active-claim recovery

`activate_reconstructed_task_claim` compares the reconstruction with the original `TaskClaimReceipt` across:

- task;
- plan;
- assignee and supplied run;
- predecessor generation;
- current generation;
- reservation surface;
- claim time;
- expiry.

The reconstruction, fresh situation, and supplied run must use the same exact authenticated read event.

A later read of the same authority head, even with the same numeric `RunId`, is not interchangeable.

`RecoveredActiveTaskClaim` commits:

```text
lease reconstruction receipt
original claim receipt
fresh active-claim activation
```

## Persistence-gated recovered release

`task_recovery` carries the recovered claim through conservative durable cleanup.

`persist_recovered_task_release`:

- refuses another reconstruction or claim before store I/O;
- uses the invoked store profile as the transition adapter identity;
- applies release against the exact reconstructed predecessor;
- routes the result through the ordinary one-shot task-store protocol;
- permits cleanup after claim expiry;
- retains recovery and reconstruction identities in every terminal outcome.

A confirmed result becomes `PersistedRecoveredTaskRelease`, whose identity includes the ordinary task-persistence receipt.

Conflict and `NeedsReconciliation` retain:

```text
recovery identity
lease reconstruction identity
exact mutation envelope
complete store execution result
```

## Store-time correction

The first scripted persistence test supplied the earlier collection timestamp as the store's initial read time even though that read occurred after the cleanup request.

The generic store protocol correctly rejected that observation as older than the transition it was asked to interpret.

The fixture now models the actual ordering:

```text
release request at time 90
initial and confirming store reads at time 91
```

Semantic snapshot identity remains stable across the reread; only freshness advances.

## Focused source tests

The public path now covers:

- unassigned collection-to-claim-basis conversion;
- exact-read substitution refusal;
- missing-task refusal;
- deterministic lease reconstruction from a real historical plan;
- plan, assignee, generation, surface, claim-time, and expiry retention;
- history generation replay refusal;
- claim-time temporal inversion refusal;
- original claim revalidation;
- active-claim recovery;
- same-head read substitution refusal during recovery;
- durable release after claim expiry;
- explicit rework successor state;
- reconstruction and recovery identity retention after confirmation;
- reconstruction substitution refusal before store I/O;
- ambiguous release preserving recovery identity as debt.

Test source is not a revision-bound test result.

## Documentation reconciliation

The wave adds:

- [`../AGENT_CONTROL_PLANE_TASK_RECOVERY.md`](../AGENT_CONTROL_PLANE_TASK_RECOVERY.md)

and reconciles:

- [`../AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](../AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)
- [`../AGENT_CONTROL_PLANE_TASK_COORDINATION.md`](../AGENT_CONTROL_PLANE_TASK_COORDINATION.md)
- the root changelog;
- the non-authoritative Beads reconciliation queue.

## Verification state

The implementation environment did not contain a local FrankenGit checkout, `cargo`, `rustc`, or `rustfmt`. A public archive fetch was also unavailable through the execution environment.

No result is claimed for:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

GitHub-hosted Actions availability or status was not used as evidence.

The designated verifier must test the final descendant containing all recovery source and documentation commits.

## Explicit non-claims

This wave does not implement:

- concrete `br`/Beads collection, history, CAS, flush, reread, or probe I/O;
- durable codecs or migrations for the new receipts;
- an envelope-ID quiescence probe;
- multi-task atomic transactions;
- distributed reservation arbitration;
- process or workspace cleanup;
- action execution;
- robot/API/MCP task commands;
- ECC-backed verification and closure;
- repository publication;
- independent batch verification or Bead closure.

## Next production slice

The next coherent slice is the concrete Beads transport that implements:

```text
collection
lease-history read
exact-predecessor mutation
flush
complete authenticated reread
envelope-ID probe
```

It must return the typed receipts already defined here and must not hand-edit `.beads/issues.jsonl` or infer success from process exit status alone.