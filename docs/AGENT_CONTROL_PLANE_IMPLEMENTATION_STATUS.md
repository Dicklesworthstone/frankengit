# Agent Control Plane Implementation Status

**Status:** implementation ledger, not an authority source  
**Normative architecture:** [`AGENT_CONTROL_PLANE_ARCHITECTURE.md`](AGENT_CONTROL_PLANE_ARCHITECTURE.md)  
**Owning crate:** `crates/fgit-agent`  
**Verification state:** source and focused tests are present; no revision-bound Rust batch result has been observed for this slice

## Landed slice

The first executable Agent Control Plane slice is the authority-bound observation substrate in `fgit-agent::situation`.

It implements:

- `AgentSituationReceipt`, committed to one complete `AuthorityReadReceipt`;
- exact optional binding to an authenticated `IntentRun`;
- optional TreeFS workspace summary constructed only from a real `WorkspaceBinding`;
- a closed ten-component v1 profile covering task, registry, graph, search, evidence, peer, and obligation generations;
- explicit typed omissions instead of silently missing context;
- deterministic input ordering and receipt identity;
- same-head enforcement for every observed component;
- `SituationDelta` with explicit run, workspace, authority, time, and component transitions;
- refusal of cross-repository comparison, time rollback, authority-generation rollback, same-generation forks, and generation changes without new head identity.

The higher-generation delta state is intentionally named `LaterGenerationObserved`. It does not claim predecessor continuity. Such a claim requires an authenticated authority-history witness.

## Deliberately absent

This slice does not implement or imply:

- Beads collection or mutation;
- task eligibility or ranking;
- work claiming or reservations;
- plan persistence;
- capability issuance or widening;
- source retrieval or context-packet assembly;
- workspace mutation;
- evidence execution;
- handoff or cancellation settlement;
- canonical publication;
- an `fg agent` CLI, API, or MCP adapter;
- successful compilation, tests, formatting, clippy, or batch verification.

Those are separate final-abstraction slices. None may treat this status file, an agent summary, or the presence of source code as completion evidence.

## Required verification evidence

Before this slice may be represented as verified, a revision-bound gate must record at least:

```text
cargo fmt --all --check
cargo test -p fgit-agent --test situation
cargo test -p fgit-agent
cargo clippy -p fgit-agent --all-targets -- -D warnings
```

The repository batch policy may require a broader command set. The narrower commands above are necessary evidence, not sufficient authority to close a Bead by themselves.

The gate should also preserve:

- exact tested revision;
- Rust toolchain identity;
- dependency constellation identity;
- complete command outcomes;
- whether failures are introduced, pre-existing, or indeterminate;
- any source edits made after the result.

## Next coherent slices

The implementation order remains:

1. attach a real projection collector to produce the ten component observations or typed omissions;
2. expose the receipt in a stable robot-mode command/API;
3. implement deterministic task eligibility and a bounded `WorkFrontier` over a receipt;
4. bind one task acceptance contract to an `AgentChangePlan` and requirement/evidence matrix;
5. implement handoff and cancellation reconciliation;
6. index evidence-grounded outcome learning without granting it authority.

The active repository implementation priorities outside this control-plane slice remain governed by Beads and the authenticated repository state, not by this document.