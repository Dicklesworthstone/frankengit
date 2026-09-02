# FrankenGit Agent Control Plane Architecture

**Status:** product architecture profile; additive to the existing Agent Collaboration Protocol  
**Scope:** the agent-facing observation, planning, execution, verification, handoff, and learning surfaces of FrankenGit  
**Authority:** subordinate to [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md), [`AGENT_PROTOCOL.md`](AGENT_PROTOCOL.md), and the repository authority-head model  
**Implementation ledger:** [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md)  
**Handoff ancestry:** [`AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md`](AGENT_CONTROL_PLANE_HANDOFF_ANCESTRY.md)  
**Initial consumers:** `fg` CLI, native API, MCP surface, TreeFS workspaces, multi-agent schedulers, review agents, and human operators inspecting agent work

---

## 1. Why this layer exists

FrankenGit already has the right correctness primitives for agent work:

- one authenticated repository authority head;
- immutable decision history;
- stable transaction seals and terminal outcomes;
- `IntentRun`, `AuthorityReadReceipt`, and attenuated capabilities;
- provenance-preserving `ContextPacket` objects;
- sparse TreeFS workspaces;
- obligation-typed effects;
- Evidence-Carrying Changes;
- typed graph, search, claim, and negative-evidence generations.

Those primitives are necessary but not sufficient for an excellent agent experience. Without one coherent control plane, an agent must repeatedly rediscover which head is current, which task is actionable, which documents are normative, which files and symbols own the behavior, which other agents are active, which evidence is stale, which attempts already failed, and which effects remain unsettled. That wastes context, compute, network traffic, wall-clock time, and human attention. Worse, it encourages agents to substitute conversational confidence for canonical state.

The Agent Control Plane, abbreviated **ACP**, is the product layer that composes the existing primitives into one deterministic operating loop:

```text
observe -> orient -> plan -> act -> verify -> reconcile -> learn
    ^                                                    |
    +----------------------------------------------------+
```

ACP is not a second workflow engine, task database, source of repository truth, or authorization system. It is a typed, progressive-disclosure view and command surface over existing canonical and derived state. Every ACP answer is pinned to an authenticated authority position and names the generations, budgets, assumptions, and omissions used to produce it.

---

## 2. Non-negotiable invariants

### 2.1 One truth plane

ACP never owns repository truth. Canonical state remains immutable bodies plus the one CAS-selected `RepositoryAuthorityHead`. Beads, indexes, search, graphs, workspaces, dashboards, reservations, and agent summaries are projections or proposed effects.

An ACP view MUST name the exact authority receipt from which it was derived. A write MUST become canonical only through the ordinary sealed transaction and authority-head transition. No control-plane row, lease, score, recommendation, or status badge can publish refs, forge state, retention, or external effects.

### 2.2 One authority vocabulary

ACP reuses `IntentRun`, `Capability`, `ContextPacket`, `WorkspaceManifest`, `EffectRecord`, and `EvidenceCarryingChange`. It does not create parallel concepts with weaker semantics such as “agent session,” “tool permission,” “context bundle,” “working copy,” “side-effect log,” or “completion report” when the normative type already exists.

A product rendering may use friendly labels, but its machine identity and state transitions remain the normative ones.

### 2.3 Observation is not authorization

Graph centrality, Beads priority, ownership history, model output, test history, or a previous successful agent may recommend work. They never grant authority. Every consequential operation is checked against the active Intent Run and capability chain at effect time.

### 2.4 Compact views never erase uncertainty

Progressive disclosure may omit detail but may not omit the existence of uncertainty, stale generations, blocked requirements, conflicting evidence, unverified claims, unsettled obligations, or scope boundaries. A compact view contains typed counters and continuation identities for every omitted class.

### 2.5 Handoffs preserve identity, ancestry, and debt

A handoff carries the exact base, intent, accepted requirements, modified objects, unresolved questions, failed approaches, outstanding obligations, evidence state, and budget consumption. It cannot convert “not checked” into “passed,” discard negative evidence, or silently widen scope.

Source capsule construction and receiver authority acceptance are separate proofs. The source must use its exact activation situation or full-context continuity. A receiver at a later authority head must prove an exact bounded predecessor path from the capsule's head; generation comparison alone is not ancestry.

Receiver acceptance binds the complete `IntentRunCommitment`, exact authority relationship, and every inherited effect responsibility. It grants no capability or task ownership.

### 2.6 Cancellation is a protocol

Cancelling an ACP run requests cancellation, drains children and effects, reconciles ambiguous external outcomes, finalizes evidence, releases or transfers reservations, and records containment failures. Dropping a client connection is never sufficient.

---

## 3. The agent operating loop

### 3.1 Observe

The agent obtains an `AgentSituationReceipt` that binds:

- authenticated repository authority receipt;
- exact task/Beads projection generation;
- claim and compatibility registry generations;
- graph, search, symbol, ownership, and test generations;
- active Intent Run and capability summary;
- workspace identity and overlay state, when one exists;
- current obligations and ambiguous effects;
- active peer work visible under policy;
- verification results with revision bindings;
- known negative evidence and invalidated assumptions;
- explicit freshness, coverage, and omission metadata.

Observation is side-effect free. It may be served from derived generations only when their basis and containment proofs are stated.

### 3.2 Orient

ACP derives a `WorkFrontier`: a deterministic set of tasks that are actionable under the current authority position, dependency graph, ownership/reservation state, capabilities, budgets, and policy.

The frontier distinguishes:

- **ready:** all declared blockers satisfied and claimable;
- **blocked:** dependency or external convergence missing;
- **assigned elsewhere:** actionable in principle but not safely claimable;
- **verification pending:** implementation exists but evidence gate is incomplete;
- **rework:** a prior candidate failed a named gate;
- **stale:** task basis or acceptance contract predates a material change;
- **superseded:** a canonical decision replaced the work;
- **unknown:** required projection is missing or inconsistent.

A recommendation score is advisory. The deterministic eligibility filter runs first. The score then ranks only eligible work and emits a decision witness naming inputs, tie-breaks, and fallback.

### 3.3 Plan

The agent converts one frontier item into an `AgentChangePlan` bound to an `IntentRun`.

The plan contains:

- task identity and exact acceptance contract;
- owning subsystem and invariant;
- canonical and derived inputs;
- intended files, symbols, schemas, registries, and tests;
- rejected shortcuts;
- expected side effects and obligations;
- evidence requirements and verifier independence;
- resource budget and stop conditions;
- dependency and coordination declarations;
- staged checkpoints that each form a complete final-abstraction slice;
- explicit non-claims.

The plan is inspectable and amendable. An amendment creates a new committed plan identity and records why the prior plan was insufficient. Repository text cannot amend it.

### 3.4 Act

Execution occurs in a capability-scoped TreeFS workspace. ACP presents the smallest useful surface for each step:

- exact files and spans relevant to the current plan;
- callable tools permitted by capability;
- preconditions and expected outputs;
- current resource and effect budgets;
- peer changes that intersect the declared conflict set;
- the latest authority delta since the plan basis.

Every external or canonical effect uses the checked effect broker, stable idempotency, and an obligation. Local edits remain proposed state until exported into an Evidence-Carrying Change and admitted through the ordinary publication path.

### 3.5 Verify

Verification maps every acceptance line to evidence or an explicit disposition. ACP separates:

- syntax and static checks;
- deterministic unit/integration/conformance checks;
- differential-oracle evidence;
- fault and crash evidence;
- security and resource-bound evidence;
- performance/economic evidence;
- formal or bounded-model evidence;
- platform/target evidence;
- human or independent-agent review.

Each result is revision-bound. A result observed at an ancestor is shown as historical unless a declared reuse rule proves it remains applicable.

### 3.6 Reconcile

Before publication, handoff, cancellation, or completion, ACP reconciles:

- current authority versus plan basis;
- workspace changes versus permitted paths and operations;
- task dependencies and peer reservations;
- sealed transaction outcomes;
- external effects with ambiguous responses;
- resource reservations versus actual consumption;
- evidence claims versus exact artifacts;
- generated summaries versus underlying requirement dispositions.

Reconciliation produces either a publication-ready Evidence-Carrying Change, a typed rebase/replan requirement, a blocked handoff, or a cancellation/containment report.

### 3.7 Learn

A terminal run emits an `OutcomeLearningRecord` containing only evidence-grounded, reusable information:

- which plan hypotheses held or failed;
- which source locations actually owned the behavior;
- which tests discriminated the defect;
- which fixtures were misleading;
- which dependencies or capabilities blocked progress;
- measured resource cost by phase;
- successful and unsuccessful recovery paths;
- applicability and expiry conditions;
- links to negative evidence and canonical outcomes.

Learning records improve future retrieval and planning but remain derived evidence. They cannot authorize, publish, or override current source.

---

## 4. Core control-plane objects

### 4.1 `AgentSituationReceipt`

```text
AgentSituationReceipt {
  schema_version,
  situation_id,
  repository_id,
  authority_read_receipt,
  intent_run_id?,
  intent_run_commitment?,
  workspace_id?,
  task_projection_generation?,
  claim_registry_generation,
  compatibility_registry_generation,
  source_graph_generation?,
  symbol_graph_generation?,
  ownership_generation?,
  search_generation?,
  test_evidence_generation?,
  active_peer_set_root?,
  obligation_summary_root?,
  authority_delta_summary?,
  freshness,
  coverage,
  omissions[],
  generated_at_logical_time,
  canonical_commitment,
}
```

The receipt is immutable. Refresh yields a new receipt and a typed delta; it never mutates the old observation in place.

### 4.2 `WorkFrontier`

```text
WorkFrontier {
  frontier_id,
  situation_id,
  eligibility_policy_id,
  candidate_tasks[],
  excluded_tasks[],
  dependency_witness,
  conflict_witness,
  ranking_witness?,
  budget_model,
  continuation?,
}
```

Each candidate includes readiness state, blockers, expected unlocks, ownership/conflict domains, estimated evidence cost, and a claim command or typed reason no claim is available. The frontier must be reproducible from its named inputs.

### 4.3 `AgentChangePlan`

```text
AgentChangePlan {
  plan_id,
  situation_id,
  intent_run_id,
  intent_run_commitment,
  task_id,
  acceptance_contract_root,
  owning_invariants[],
  input_context_packets[],
  intended_change_surface[],
  conflict_surface[],
  checkpoints[],
  evidence_plan[],
  effect_plan[],
  resource_budget,
  stop_conditions[],
  rejected_shortcuts[],
  non_claims[],
  sponsor_or_policy_approval,
}
```

A checkpoint is useful only when it lands a coherent final-abstraction slice. “Create empty crate,” “add interface now, implementation later,” and “make tests green by weakening the oracle” are invalid checkpoints.

### 4.4 `SituationDelta`

```text
SituationDelta {
  from_situation_id,
  to_situation_id,
  authority_changes[],
  task_changes[],
  peer_changes[],
  evidence_changes[],
  capability_changes[],
  obligation_changes[],
  invalidated_assumptions[],
  recommended_reconciliation,
}
```

This is the primary refresh primitive. It lets an agent update context incrementally instead of rebuilding a giant prompt after every commit.

### 4.5 `AgentHandoffCapsule` and `AgentHandoffAcceptance`

```text
AgentHandoffCapsule {
  capsule_id,
  source_run_id,
  source_run_commitment,
  source_instance_id,
  target_selector,
  latest_situation_id,
  plan_id,
  workspace_snapshot_id?,
  changed_object_roots[],
  requirement_dispositions[],
  evidence_records[],
  unresolved_questions[],
  failed_approaches[],
  outstanding_obligations[],
  budget_consumed,
  requested_next_actions[],
  capability_attenuation,
  expiry,
  producer_attestation,
}

AgentHandoffAcceptance v2 {
  acceptance_id,
  capsule_id,
  receiver_situation_id,
  receiver_run_id,
  receiver_run_commitment,
  receiver_instance_id,
  accepted_at,
  authority_relation,
  authority_ancestry_receipt?,
  receiver_operations,
  receiver_budget,
  receiver_expiry,
  target_resolution,
  inherited_effect_responsibilities[],
}
```

The receiver independently refreshes authority and either accepts under the same authenticated head or supplies an exact bounded ancestry receipt proving its current head descends from the source. The recommended sync/async host driver authenticates the current slot and consumes the proof in one operation.

Acceptance does not transfer task ownership or mint a receiver plan. Cross-head task transfer requires a separate two-authority-basis persistence envelope.

### 4.6 `OutcomeLearningRecord`

```text
OutcomeLearningRecord {
  learning_id,
  source_run_id,
  source_run_commitment,
  task_id,
  terminal_outcome,
  exact_revision_or_decision,
  confirmed_ownership[],
  discriminating_evidence[],
  failed_hypotheses[],
  resource_observations[],
  reusable_patterns[],
  applicability,
  invalidation_conditions,
  negative_evidence_refs[],
  verifier_attestations[],
}
```

The record is indexed for retrieval only after schema and evidence validation. Unsupported self-assessments are retained as unverified annotations or discarded according to policy.

---

## 5. Progressive disclosure and context economics

Agent ergonomics is largely the art of presenting exactly enough truth at each decision point.

ACP defines four stable disclosure levels generated from the same receipt:

### Level 0: pulse

A compact machine-first summary suitable for every tool turn:

- authority head and delta count;
- active task and status;
- next required action;
- blockers and conflicts;
- remaining budget;
- unsettled obligations;
- evidence state;
- continuation identities.

Target size is bounded and policy-configurable. It never embeds arbitrary source text.

### Level 1: action packet

Everything needed for one concrete action:

- exact preconditions;
- relevant source spans and contracts;
- permitted tools/effects;
- expected result schema;
- refusal semantics;
- nearby peer changes;
- tests and evidence attached to the acceptance line.

### Level 2: subsystem packet

The owning subsystem’s contracts, dependency neighborhood, recent decisions, negative evidence, and cross-cutting constraints. This is the normal planning surface.

### Level 3: audit expansion

Complete source/evidence lineage, graph witnesses, raw results, historical attempts, authority proofs, and handoff ancestry required for independent review or incident analysis.

An agent requests expansion by stable identity, not by asking the server to repeat an unbounded transcript. Every compact node carries a continuation token or object identity that opens the exact detail behind it.

### 5.1 Value-of-information budgeting

Before expanding context or running an expensive check, ACP may estimate:

```text
expected_value = probability_decision_changes * avoided_failure_cost
                 - retrieval_or_execution_cost
```

The estimate is advisory and identity-bound. Hard correctness requirements always run even when their estimated short-term value is low. Statistical support may prioritize optional evidence; it never suppresses mandatory gates.

### 5.2 Negative-result reuse

When a prior run established that a source location, test, or hypothesis does not discriminate a defect, ACP surfaces that negative evidence before spending the same resources again. Reuse requires matching applicability conditions and source/toolchain identity; stale negative evidence is advisory, not binding.

---

## 6. Beads and task-graph integration

Beads remains the repository’s issue/dependency projection and `bv` remains the graph-aware triage engine. ACP integrates them without turning either into repository authority.

### 6.1 Task identity and canonical basis

A task view binds the Beads issue identity and projection generation to an authority receipt. A task status change is auditable task metadata; it does not prove the code or forge state changed. Conversely, a code commit does not silently close a task.

### 6.2 Claiming

A claim is permitted only when:

- the task is ready under its dependency graph;
- the claimant’s Intent Run covers it;
- conflict/reservation policy permits the declared surface;
- the task basis is not stale;
- required capabilities and budgets exist.

The claim yields a receipt. Failure to claim is typed: blocked, already assigned, stale basis, insufficient capability, budget unavailable, projection unavailable, or policy refusal.

### 6.3 Verification-bound transitions

Implementation completion and verification completion remain distinct. ACP renders at least:

```text
open -> in_progress -> implementation_ready -> batch_pending
     -> verified -> closed
```

The actual repository policy may use a smaller vocabulary, but the machine view must preserve the distinction. A transition to a verification-pending state names the implementation revision, acceptance mapping, known defects, and exact checks already observed. Only the designated gate can attach the verification receipt and close.

### 6.4 Rework routing

A failed gate returns the task to the same owning plan when possible and attaches:

- failed command and revision;
- minimal discriminating output;
- suspected ownership surface;
- whether the failure is introduced, pre-existing, or indeterminate;
- evidence needed to re-enter verification.

Rework does not create an unbounded new task unless the original acceptance contract truly excludes the defect. Scope splitting to manufacture closure is refused.

### 6.5 Handoff acceptance versus task transfer

A receiver may accept responsibility metadata under the same head or a proven descendant head without automatically changing the task projection.

Same-read task transfer uses the existing single-basis exact-predecessor envelope. A transfer whose source lease and receiver assignment are governed by different authority heads needs a two-authority-basis envelope and separate reconciliation rules. The implementation must not weaken the existing same-read equality check to simulate that protocol.

---

## 7. Multi-agent concurrency

### 7.1 Conflict surfaces

Every plan declares a conflict surface over files, schemas, registries, crate APIs, authority keys, forge entities, tests, and external effects. ACP combines declared surfaces with deterministic dependency and ownership analysis.

A conflict prediction is a warning or scheduling input, not authority. Canonical publication and exact-predecessor checks remain the final arbiter.

### 7.2 Reservations

Reservations are bounded coordination aids with owner, scope, basis, expiry, and handoff semantics. They cannot hide canonical changes or grant write authority. A stale reservation is observable and reclaimable under policy.

### 7.3 Shared-contract freezing

When multiple agents consume one interface, ACP records a contract epoch. A producer publishes the exact API/schema commitment; consumers bind plans to it. An interface change invalidates dependent plans explicitly rather than letting each agent silently reinterpret the contract.

### 7.4 Duplicate work

Two agents may intentionally race on independent implementations only when the Intent Run declares a comparison policy and budget. Otherwise ACP detects equivalent task, surface, and acceptance roots and recommends consolidation. Duplicate preparation is never confused with duplicate canonical publication.

---

## 8. Agent-facing commands and API

The initial command family should be small and composable:

```text
fg agent observe        # authenticated AgentSituationReceipt
fg agent next           # deterministic eligible WorkFrontier top choice
fg agent frontier       # complete bounded frontier with witnesses
fg agent plan           # create or inspect an AgentChangePlan
fg agent refresh        # SituationDelta from the prior receipt
fg agent explain        # expand one refusal, blocker, score, or requirement
fg agent effects        # obligations and ambiguous external outcomes
fg agent evidence       # requirement-to-evidence matrix
fg agent reconcile      # publication/handoff/cancellation readiness
fg agent handoff        # produce or accept an AgentHandoffCapsule
fg agent outcome        # inspect terminal outcome and learning record
```

All commands support a stable machine format. Human rendering is generated from the same typed result. Machine output rules:

- one schema version and result kind per response;
- deterministic field order and tie-breaks;
- explicit units and bounded arrays;
- stable object identities instead of prose references;
- continuations for truncated sets;
- refusals as typed results, not stderr-only strings;
- no ANSI, progress bars, or interactive prompts in robot mode;
- exact revision/authority/generation binding in every evidence-bearing response.

MCP and native API operations mirror these contracts instead of wrapping shell output.

---

## 9. Refusal model

ACP uses typed refusals for conditions including:

- authority receipt stale or unverifiable;
- required generation missing, mixed, or outside containment;
- task blocked, assigned, stale, or superseded;
- capability absent, expired, revoked, or wrong audience;
- plan widens the Intent Run;
- conflict surface unknown or actively reserved;
- context budget exhausted before mandatory coverage;
- workspace dirty outside permitted scope;
- requirement missing a disposition;
- evidence stale, unbound, unsupported, or wrong claim class;
- obligation unsettled or external outcome ambiguous;
- handoff loses source continuity, authority ancestry, exact receiver-run identity, or negative evidence;
- ancestry proof names another ancestor, descendant, repository, slot, store, token, or hop count;
- publication basis moved;
- cancellation containment incomplete.

Every refusal names the failed precondition, supporting receipt, whether retry can help, and the minimal safe next action. It never silently falls back to a broader read, ambient credential, unverified summary, weaker gate, or generation-only ancestry claim.

---

## 10. Security and prompt-injection boundary

ACP renders authenticated control metadata and untrusted source text through structurally separate channels. Tool clients receive distinct fields, not delimiter conventions inside one string.

Untrusted content cannot:

- alter the active plan or acceptance contract;
- request capabilities or secrets;
- suppress a mandatory check;
- mark its own requirement satisfied;
- choose verifier independence;
- widen retrieval scope;
- approve publication;
- hide negative evidence;
- alter retention or disclosure;
- change budget or effect destinations;
- assert that one authority head descends from another;
- convert handoff acceptance into task ownership.

Any model-generated plan amendment is a proposal evaluated against the Intent Run and policy. Any model-generated claim remains unsupported until evidence validates it.

---

## 11. First implementation slices

Each slice must land as a real final abstraction with success, refusal, determinism, resource, and stale-basis tests.

### Slice A: authority-bound observation

Implement `AgentSituationReceipt` for one repository using:

- authenticated authority read;
- claim/compatibility registry identities;
- optional Beads projection identity;
- optional workspace identity;
- explicit missing-generation and omission fields.

Expose it through a library API and `fg agent observe --format json`. No recommendation or mutation is required. The slice is complete when the receipt can be independently re-read and its identities verified.

### Slice B: deterministic work frontier

Compose Beads readiness, dependencies, assignment state, capability scope, and conflict declarations into `WorkFrontier`. Start with deterministic eligibility and tie-breaks; statistical ranking is optional and must have a deterministic fallback.

### Slice C: situation deltas

Given two receipts, emit a bounded `SituationDelta` that identifies invalidated assumptions and the minimal context refresh. This is the primary mechanism for reducing repeated context assembly.

### Slice D: plan and evidence matrix

Bind one task acceptance contract to an `AgentChangePlan`, then render requirement dispositions and revision-bound evidence. Publication remains outside this slice.

### Slice E: handoff and cancellation reconciliation

Produce and verify `AgentHandoffCapsule`; preserve source continuity; accept receivers at the same or a proven descendant authority head; settle or transfer obligations; prove that omitted negative evidence, changed base, forged ancestry, or amplified capability is refused.

### Slice F: outcome learning

Index validated `OutcomeLearningRecord` objects and demonstrate one measurable reduction in repeated retrieval or failed-check cost without allowing a learning record to influence authorization or canonical publication.

---

## 12. Verification matrix

The control plane requires tests for:

- canonical byte stability and identity-domain separation;
- authority receipt authentication and stale-head refusal;
- bounded exact authority-head ancestry and current-token binding;
- deterministic ordering and closed tie-breaks;
- mixed-generation refusal;
- compact/full rendering equivalence;
- continuation completeness and bounds;
- task eligibility versus advisory ranking separation;
- capability attenuation and revocation freshness;
- prompt-injection channel separation;
- workspace path/capability containment;
- obligation settlement on success, refusal, crash, cancellation, and handoff;
- evidence revision binding and invalidation;
- requirement-disposition completeness;
- peer conflict and contract-epoch invalidation;
- handoff replay, tamper detection, no amplification, wrong-ancestor refusal, and sync/async parity;
- resource ceilings before allocation or expensive retrieval;
- deterministic fallback when statistical support is absent;
- negative-evidence applicability and expiry.

Performance evidence must report context bytes, retrieval work, graph/search requests, model tokens, CPU, memory, wall time, and repeated-work avoided. “Fewer tokens” is not useful if the compact view suppresses a blocker or causes more failed actions.

---

## 13. Explicit non-claims

This architecture does not claim that every ACP product surface is implemented. The exact landed library boundary is maintained in [`AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md`](AGENT_CONTROL_PLANE_IMPLEMENTATION_STATUS.md).

Current library slices include authority-bound observation, frontier, planning, task coordination, capability/effect authorization, reconciliation, proof-carrying handoff and receiver acceptance, cancellation, and outcome learning. They do not by themselves provide a complete product host, durable transport for every value, action-packet executor, cross-head task-transfer persistence protocol, robot API, or canonical publication service.

This document does not make Beads canonical repository state, make graph/model output authoritative, authorize agents through text, permit ambient credentials, weaken batch verification, or replace the ordinary transaction/publication path.

It does not require a centralized hosted service. The same contracts must work in the embedded profile, with missing optional generations represented explicitly.

It does not promise that an agent will make good decisions. It makes the state, authority, evidence, uncertainty, cost, and consequences of those decisions legible enough to inspect and control.

---

## 14. Design test

The Agent Control Plane succeeds when an agent can answer, from one authority-bound receipt and bounded expansions:

1. What exact repository state am I observing?
2. What am I authorized and budgeted to do?
3. Which work is truly actionable now, and why?
4. Which invariant and subsystem own it?
5. What changed since my last observation?
6. Which other work conflicts with mine?
7. What evidence will satisfy every acceptance line?
8. Which attempts already failed, under what applicability conditions?
9. Which effects or obligations are still live or ambiguous?
10. Can I publish, hand off, or cancel without losing truth or responsibility?

The answer must remain correct without trusting the agent’s prose, memory, model provider, or conversational transcript.
