# Beads Reconciliation Queue — Task Recovery — 2026-09-01

**Status:** non-authoritative operator handoff  
**Do not treat this file as Beads state.** Every claim, comment, dependency, and lifecycle transition must be applied through the repository's current `br` interface after re-reading the live issue graph.

## Why this queue exists

The implementation environment provided GitHub source read/write access but did not provide:

- a local FrankenGit worktree;
- `br` or `bv`;
- Cargo, rustc, rustfmt, or Clippy;
- safe transactional access to the live Beads database.

The repository's `.beads/issues.jsonl` must not be replaced through the contents API. Doing so could discard concurrent comments, dependencies, transitions, and append-only history.

No Bead was claimed, commented, moved, verified, or closed by this wave.

## Starting revision

The wave began at:

```text
3a8318b529762569d0dcb048efd39b43584ed262
```

## Exact implementation revisions

```text
9f54b2c699e7a116fbb50c79189fbf750a428cfd
    activate the already-landed collection bridge in the owning crate

35870ebaeb870530a1f278ea7b021fbb9c114687
    add collection-bound durable lease reconstruction

b95cf5b284f3b3e93f15429cdb86195a7177c359
    expose lease reconstruction evidence

93f7e1f9bbe39a410bdad11edce93ec92d8dae17
    add public-path lease reconstruction tests

3fe49f292137d1825b0009dce16839c16669a49f
    replace forged plan IDs with real control-plane plans

af9561a2e9a2832cc56c5d315979f754b0cc46e6
    make the historical plan/claim fixture temporally coherent

e2b33a62b6602c54522b0dcfc221fbfa395ac8fa
    add original-claim revalidation and active-claim recovery

6448d04ab243bfa8fc568463f6bab86c1e264a5a
    expose restart-safe claim recovery

8aa8e1c12b25fdf0496b2e2507ef4bfce9031b1c
    add exact-read recovery tests

c76916d3bcb3ec28c5a406b6cb4d31db605f32fd
    add persistence-gated recovered task release

5d82bc407919ce6d4ccd249808db2067b4190043
    expose persisted restart cleanup

1402ca7696009f17f6466d37cc89f12cb6b6d794
    add public-path recovered cleanup tests

e453dc36e0011267b1e8fc5b0b9744f021946a71
    correct store-reread time ordering in the recovery oracle

cd6d92434e0b4f4e8e8c9c67bedfdfaef857c2f7
    atomically bind claim recovery to complete Intent Run identity

fa7f09bfe7e08f309d4511642722176a25b61d29
    expose the run-bound recovery cleanup API

4334255e65320e1f2fb4364941efd02d8bec8860
    pin cleanup after run expiry and same-ID run substitution refusal
```

Documentation-only descendants follow those source commits.

## Implemented boundary

### Collection bridge activation

- `task_collection_bridge` is declared and re-exported by `fgit-agent`;
- an exact collected unassigned row can become an authority-bound claim basis;
- a claimed row cannot silently use the unassigned path;
- exact authenticated-read substitution is refused.

### Durable lease reconstruction

- history binds exact collection receipt, task, and current generation;
- predecessor generation and original claim instant are supplied explicitly;
- assignee, plan, expiry, phase, conflict state, and complete reservation surface are reused from the validated collection;
- history replay, temporal inversion, zero adapter identity, invalid generations, and invalid surfaces fail closed;
- semantic task identity remains independent from history adapter/evidence identity;
- a stable reconstruction receipt retains semantic state and audit evidence separately.

### Restart active-claim recovery

- the original `TaskClaimReceipt` is required;
- task, plan, assignee, predecessor/current generations, surface, claim time, and expiry must match the reconstructed lease;
- reconstruction, refreshed situation, and supplied run must use the same exact authenticated read event;
- a later same-head read with the same numeric `RunId` is refused;
- ordinary recovery identity commits reconstruction, original claim, and fresh activation.

### Complete-run recovery binding

- `recover_task_claim_for_cleanup` performs activation and complete-run commitment in one API call;
- `RunBoundRecoveredTaskClaimId` commits the ordinary recovery identity plus the exact `IntentRunCommitment`;
- callers cannot attach a different same-ID run after activation;
- cleanup re-computes the supplied run commitment before semantic mutation or store I/O;
- changes to exact authority read, operation scope, resource budget, or expiry are refused;
- release remains possible after the original run expires, but the caller cannot replace it with a same-ID copy carrying a later expiry.

### Persistence-gated cleanup

- an expired run-bound recovered claim may still release its task;
- the invoked store profile becomes the transition adapter identity;
- another reconstruction, claim, or complete run is refused before store I/O;
- the ordinary one-shot read/CAS/flush/reread protocol is reused;
- confirmed success retains run-bound recovery, ordinary recovery, reconstruction, and persistence identities;
- conflict and uncertainty retain the same recovery identities plus the complete mutation envelope;
- an ambiguous write followed by the predecessor remains reconciliation debt.

## Fresh-review corrections

The source/test wave corrected four shortcuts before the final handoff was frozen:

1. **Opaque identity fabrication:** tests build a real `AgentChangePlan`; they do not construct arbitrary plan IDs.
2. **Impossible history:** the plan is built against the predecessor generation before the recorded claim instant.
3. **Stale store read:** the scripted store reread is timestamped after the release request, matching anti-rollback semantics.
4. **Numeric run substitution:** persisted cleanup now consumes an atomic run-bound recovery value rather than trusting `RunId` after recovery.

## Focused source tests present

The current tree includes public-path source tests for:

- unassigned-row bridging;
- same-head exact-read refusal;
- missing task;
- deterministic lease reconstruction;
- complete lease field retention;
- generation replay refusal;
- claim-time rollback refusal;
- original claim recovery;
- same-head read substitution refusal during recovery;
- atomic complete-run binding;
- durable release after both claim and run expiry;
- same-ID changed-scope/budget/expiry refusal before store I/O;
- explicit rework state;
- run-bound recovery/reconstruction identity retention;
- pre-I/O reconstruction substitution refusal;
- ambiguous cleanup debt retaining complete recovery identity.

Source presence is not a test result.

## Not implemented

This wave does not supply:

- concrete `br`/Beads collection or row decoding;
- concrete lease-history lookup;
- concrete task CAS/update commands;
- collaborative or projection flush integration;
- authenticated tracker reread mapping;
- an envelope-ID quiescence probe;
- durable codecs or migrations for the new receipts;
- complete-run commitments in the older generic task claim/lease vocabulary outside the restart-cleanup facade;
- multi-task atomicity or distributed reservations;
- process/workspace/effect cleanup;
- action-packet execution;
- robot, native API, or MCP surfaces;
- ECC-backed verification/closure;
- repository publication;
- independent batch verification.

## Verification required

Before moving the owning Bead to any verified or closed state, run and preserve revision-bound evidence for at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --all-targets
cargo clippy -p fgit-agent --all-targets -- -D warnings
cargo test -p fgit-registry-check
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

The evidence must name:

- exact tested revision;
- pinned Rust toolchain;
- dependency constellation;
- every command and exit status;
- introduced, pre-existing, or indeterminate classification for failures;
- every source edit after the result.

Hosted Actions status is not required and is not a substitute.

## Recommended operator procedure

Read the live graph first:

```text
br --help
br ready --json
br list --status=open --json
bv --robot-triage
```

Locate the existing Bead whose acceptance contract owns Agent Control Plane task collection, persistence, restart recovery, or Beads adapter integration. Do not infer an issue ID from this document.

For the unambiguous owning Bead:

1. attach a progress comment naming the exact revisions above;
2. state that source and focused test cases are present;
3. state that no local Rust command result was observed in the implementation environment;
4. state that the generic storage-neutral protocols are implemented but the concrete Beads transport remains absent;
5. attach verification evidence after the local/designated gate;
6. move only to the lifecycle state permitted by the current acceptance contract;
7. run `br sync --flush-only` after Beads mutations.

## Suggested progress-comment substance

```text
Agent Control Plane task recovery advanced from pre-situation collection through exact-read collection bridging, durable active-lease reconstruction, original TaskClaimReceipt revalidation, restart-safe active-claim recovery, atomic complete-IntentRun binding, and persistence-gated release after both claim and run expiry. Source revisions are 9f54b2c6, 35870eba, b95cf5b2, 93f7e1f9, 3fe49f29, af9561a2, e2b33a62, 6448d04a, 8aa8e1c1, c76916d3, 5d82bc40, 1402ca76, e453dc36, cd6d9243, fa7f09bf, and 4334255e. Same-ID changes to authority read, scope, budget, or expiry now refuse before store I/O. Confirmed, conflicting, and ambiguous outcomes retain the run-bound recovery, ordinary recovery, and lease reconstruction identities. Focused public-path test source is present. No formatter/compiler/test/Clippy/repository-lane or independent batch result was observed in the implementation environment. Concrete br/Beads read/history/CAS/flush/reread/probe I/O, durable codecs, generic claim/lease run commitments, process cleanup, action execution, robot surfaces, ECC closure, and canonical publication remain absent. Verification or closure is not requested without the designated revision-bound gate.
```

## Stop conditions

Do not transition the Bead when:

- more than one plausible owner exists;
- the acceptance contract excludes this implementation;
- a newer source revision invalidates the recorded gate;
- any required command fails or was not run;
- a concrete Beads transport is required but only the generic trait/oracle exists;
- the only evidence is source presence, this summary, or hosted Actions status.

The safe outcome is a progress comment, dependency update, or new narrowly scoped Bead through `br`, never a hand-edited ledger or manufactured closure.