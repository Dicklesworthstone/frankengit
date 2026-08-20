# FrankenGit Agent Collaboration Protocol

**Status:** normative architecture profile (its IntentRun, AuthorityReadReceipt, and Evidence-Carrying Change constructs are depended on by `NORMATIVE_PROTOCOL_CONTRACTS.md` §28, which wins on any conflict)  
**Scope:** software agents operating through FrankenGit  
**Last updated:** 2026-08-20

FrankenGit treats software agents as first-class collaborators, never as ambiently trusted shell sessions. The protocol makes an agent’s sponsor, identity, intent, authority, canonical base, supplied context, workspace state, effects, evidence, resource use, delegation, and terminal outcomes explicit enough that humans and other agents can inspect the change without trusting a conversational transcript.

The protocol is model- and harness-neutral. A local CLI agent, hosted coding agent, deterministic bot, review agent, migration worker, or human-driven automation client uses the same control objects and capability boundaries.

This document refines the general rules in [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md). Canonical publication still occurs through the ordinary transaction seal, decision batch, and repository authority head. The Agent Protocol does not create a second mutation mechanism.

---

## 1. Design goals

The protocol MUST provide:

1. **Attribution:** identify sponsor, delegator, agent principal, execution instance, harness, declared model/runtime, and capability issuer.
2. **Intent integrity:** preserve the exact authorized task independently of repository text, tool output, and later conversation.
3. **Least authority:** grant only required repositories, refs, paths, operations, secrets, destinations, time, compute, storage, and spend.
4. **Canonical-base integrity:** pin every read/work/publication attempt to an authenticated authority receipt and exact source generations.
5. **Workspace isolation:** provide a sparse Git TreeFS copy-on-write environment with explicit process, network, secret, and effect powers.
6. **Evidence:** bind claims to immutable commands, inputs, outputs, traces, diffs, benchmarks, and verifier attestations.
7. **Cancellation safety:** close through quiescence without orphaned tasks, credentials, prepared writes, unknown external effects, or hidden budget use.
8. **Reviewability:** expose equivalent human-readable and machine-compact views from the same canonical records.
9. **Delegation without amplification:** allow sub-agents while preserving authority ancestry, provenance, budgets, and output contracts.
10. **Economic accountability:** meter resource use and reserve before expensive or external effects.
11. **Ordinary Git escape:** publish ordinary Git objects/refs; agent metadata enriches the forge but never traps source history.

---

## 2. Threat assumptions

The protocol assumes:

- repository files, issues, comments, diffs, webpages, package metadata, test output, and tool responses may contain prompt injection;
- an agent may misunderstand intent, hallucinate state, fabricate evidence, select the wrong tool, or omit critical context;
- a model, harness, plugin, verifier, or workspace image may be compromised;
- producer and verifier may collude or share hidden state;
- retries, cancellation, crash, process pause, and partitions may occur after effects begin;
- external services may lack idempotency or return ambiguous failures;
- secrets may be requested through malicious content;
- agents may broaden scope, recurse indefinitely, or consume excessive resources;
- a fully authorized patch may still be incorrect or malicious.

Correctness therefore comes from capability enforcement, typed state machines, canonical publication, obligation settlement, and evidence verification—not from asking an agent to behave.

---

## 3. Identities and roles

### 3.1 Sponsor

A `SponsorId` is the human or organizational principal accountable for authorizing an Intent Run. Sponsorship records who granted authority; it does not imply authorship of every line.

### 3.2 Agent principal

```text
AgentPrincipal {
  principal_id,
  display_name,
  owner_or_operator,
  public_keys,
  allowed_harness_classes,
  reputation_scope,
  created_at,
  revoked_at?
}
```

A logical principal may persist across runs. It has no authority without an Intent Run and capability chain.

### 3.3 Agent instance

An `AgentInstanceId` identifies one execution and binds:

- principal;
- harness and version;
- declared model/provider/runtime or deterministic implementation;
- executable/container/environment commitment where available;
- sponsor and delegating parent;
- attestation domain;
- start, expiry, and revocation handle.

Model identity is provenance, not a security guarantee. The system remains correct when the declaration is absent or false.

### 3.4 Capability issuer

The issuer evaluates organization/repository policy and creates attenuated audience-bound capabilities. It may be a self-hosted repository, organization authority, or managed FrankenGit service.

### 3.5 Independent verifier

A verifier is a separately identified principal or deterministic service. Independence is a typed evidence class, not self-declaration. Dimensions include:

- mutable workspace;
- credentials and effect authority;
- model/harness implementation;
- supplied context and hidden state;
- oracle/toolchain;
- operator/organization;
- human oversight.

Policy states which dimensions must differ for each risk class.

### 3.6 Child agent

A child receives a `SubIntent`, attenuated capabilities, bounded budget, exact inputs, output schema, and evidence requirements. The parent cannot delegate authority or budget it does not possess.

---

## 4. Canonical base and authority receipts

### 4.1 `AuthorityReadReceipt`

Every run begins from a verified authority read:

```text
AuthorityReadReceipt {
  repository_id,
  authority_head_id,
  authority_head_generation,
  backend_version_token,
  latest_decision_batch_id,
  latest_repository_sequence,
  latest_repository_commit_id,
  ref_root,
  forge_position_root,
  retention_root,
  policy_epoch,
  format_epoch,
  verified_at_logical_time,
  verifier_profile,
}
```

The receipt proves what the agent was allowed to treat as current at workspace creation. A backend ETag/version without an authenticated head-body check is insufficient.

### 4.2 Checkpoint relationship

A run MAY also name a repository capsule/checkpoint used to accelerate materialization or restore. The checkpoint is not current-state authority. The AuthorityReadReceipt names the current head and any suffix replayed beyond the checkpoint.

### 4.3 Refresh

A workspace never silently floats. Refresh creates a new receipt and one explicit relation:

- `FastForwarded`;
- `RebasedByIntentReplay`;
- `RebasedByStructuredPatch`;
- `MergedByDeclaredProof`;
- `ConflictRefused`.

The evidence record distinguishes checks performed before and after refresh.

---

## 5. Intent Run

The **Intent Run** is the authoritative agent control object. Natural language may explain the goal; machine fields enforce scope.

```text
IntentRun {
  schema_version,
  run_id,
  sponsor_id,
  agent_principal_id,
  agent_instance_constraints,
  parent_run_id?,
  repository_id,
  base_authority_receipt,
  optional_checkpoint_id?,
  target_refs,
  objective,
  acceptance_contract,
  allowed_path_patterns,
  denied_path_patterns,
  allowed_operation_classes,
  required_evidence,
  verifier_policy,
  publication_policy,
  resource_budget,
  secret_policy,
  network_policy,
  delegation_policy,
  retention_and_disclosure_policy,
  expiry,
  request_commitment,
  sponsor_authorization,
}
```

### 5.1 Objective and acceptance contract

`objective` is explanatory and cannot widen machine scope. The acceptance contract lists observable requirements: tests, compatibility cases, benchmarks, paths, migrations, security checks, documentation, and allowed uncertainty. Every requirement receives a terminal disposition.

### 5.2 Identity

The canonical Intent Run bytes are committed into `run_id` under a versioned domain. Reusing a run ID with different bytes is a terminal protocol violation.

### 5.3 Repository text is not control metadata

Files, comments, issues, tool output, and external pages are untrusted data. They cannot alter the Intent Run, capabilities, verifier policy, publication policy, or budgets.

---

## 6. Capability model

Capabilities are unforgeable, audience-bound authorizations checked by the service performing the operation.

```text
Capability {
  capability_id,
  issuer,
  subject_agent_instance,
  tenant_id,
  repository_id?,
  operation,
  resource_selector,
  ref_selector?,
  path_selector?,
  secret_class?,
  network_destination_class?,
  max_calls?,
  max_bytes?,
  max_cost?,
  not_before,
  expires_at,
  parent_capability?,
  intent_run_id,
  tx_or_effect_binding?,
  audience,
  caveats,
  issuer_authenticator,
}
```

### 6.1 Initial operation classes

- read canonical object/body;
- read authorized derived generation;
- create/read/modify TreeFS workspace;
- execute sandboxed process;
- access named network destination/class;
- request purpose-bound secret handle;
- invoke external integration;
- create immutable candidate object;
- prepare publication transaction;
- submit review/check/evidence;
- mutate issue/comment/forge entity;
- delegate sub-intent;
- consume compute/model/storage/network budget.

A broad `repo_write` or inherited sponsor token is forbidden.

### 6.2 Attenuation

Delegation may only intersect selectors, reduce quotas, shorten expiry, narrow operations, bind additional identities, and add caveats. A verifier checks the complete ancestry. Missing ancestry or amplification is refused.

### 6.3 Revocation and freshness

High-value tools validate revocation/freshness at effect time, not only workspace creation. Revocation is interpreted at a named canonical position. Cached capability decisions have explicit maximum age and invalidation.

---

## 7. Context Packet

A **Context Packet** is a bounded, provenance-preserving retrieval product. It is not an unstructured prompt dump and never claims completeness without a closure proof.

```text
ContextPacket {
  packet_id,
  repository_id,
  authority_read_receipt,
  source_generation_set,
  request_intent,
  authorization_scope,
  retrieval_budget,
  sources[],
  relationships[],
  omissions[],
  coverage_claims[],
  ranking_and_fusion_identity,
  decision_witnesses[],
  packet_commitment,
}
```

Each source entry records:

- immutable object/forge identity;
- path/ref/commit context;
- byte/AST/diff span;
- exact source generation and canonical position;
- retrieval channel: exact, lexical, symbol, structural, semantic, graph, history, ownership, test, policy;
- score/calibration metadata where meaningful;
- authorization receipt;
- transform/summarization lineage;
- freshness and invalidation conditions.

### 7.1 Control versus source channels

Context has two structurally distinct channels:

1. authenticated control metadata generated under the Intent Run;
2. visibly delimited untrusted source content.

Human, API, and compact agent renderings preserve the separation. A source file cannot masquerade as a capability or system instruction.

### 7.2 Coverage and omissions

Coverage claims are typed, for example:

- exhaustive authorized paths matching pattern P at authority head H;
- all direct reverse dependencies in graph generation G;
- top-k semantic candidates under model/index identity M;
- all protected policy files;
- sampled history, not exhaustive history.

Approximate retrieval says approximate. Every packet lists deliberate and budget-induced omissions. No mixed-generation packet is valid without a declared join receipt that names every contributing generation and the join policy; for cross-time queries the receipt names each exact position and labels the packet as a cross-time join rather than a single-position view. This is the same rule as `GRAPH_INTELLIGENCE_ARCHITECTURE.md` §2 and normative invariant 20.

### 7.3 Deterministic ranking receipts

Any graph/search operation whose ordering affects context selection names a closed tie-break policy and emits a decision-path/complexity witness. Statistical ranking remains advisory and identity-bound; deterministic exact channels remain available as fallback.

---

## 8. Git TreeFS workspace

An agent workspace is a disposable Git TreeFS materialization identified by `WorkspaceId`.

```text
WorkspaceManifest {
  workspace_id,
  intent_run_id,
  base_authority_receipt,
  optional_checkpoint_id?,
  sparse_path_set,
  base_tree_roots,
  overlay_root,
  intent_log_root,
  process_profile,
  network_profile,
  secret_handle_ids,
  budget_profile,
  staged_epoch,
  visible_epoch,
  durable_epoch,
  manifest_commitment,
}
```

### 8.1 Creation

Workspace creation resolves:

- current authority receipt and optional checkpoint+suffix;
- authorized sparse path set;
- immutable base tree/blob objects;
- writable COW overlay;
- descriptor-relative path root;
- process/network/secret/effect capabilities;
- CPU, memory, disk, process, time, and output budgets.

### 8.2 Path safety

All path resolution is relative to an opened capability root. The host rejects traversal, symlink/reparse/hardlink escape, device nodes, alternate streams, case-fold ambiguity, reserved names, and platform-specific aliasing according to the workspace profile. Lazy fetch rechecks authorization at object resolution.

### 8.3 Intent log and snapshot

Overlay mutation produces an append-only intent log. Snapshots use root-last publication and explicit staged/visible/durable epochs. Crash replay reconstructs the overlay or refuses; it never exposes a partially published snapshot as complete.

### 8.4 Process isolation

Subprocesses receive only explicit handles, environment, filesystem roots, network routes, secret handles, budgets, and child-task ownership. No cloud metadata, sponsor credential, host home directory, Docker socket, or ambient repository token is inherited.

### 8.5 Diff and object closure

Publication derives a deterministic net-effect normal form, ordinary Git object closure, and source-spanned diff. Generated and ignored files remain visible to evidence policy; “ignored” is not “nonexistent.”

---

## 9. Effect broker and obligation ledger

Every consequential operation uses an Asupersync-owned obligation and produces a ledger record.

```text
EffectRecord {
  effect_id,
  run_id,
  agent_instance_id,
  parent_effect_id?,
  capability_id,
  operation,
  canonical_input_commitment,
  source_authority_receipt?,
  budget_reserved,
  external_idempotency_key?,
  obligation_state,
  terminal_outcome?,
  output_commitments[],
  budget_consumed,
  reconciliation_evidence?,
}
```

Obligation states follow the normative lifecycle: `Reserved -> Committed -> Acknowledged`, or `Reserved -> Aborted`, exactly as defined in `CALM_AND_OBLIGATIONS.md` §6. Region closure requires every obligation to be settled or terminally quarantined.

The ledger distinguishes:

- pure canonical reads;
- derived local writes;
- immutable candidate creation;
- prepared canonical mutation;
- committed/refused canonical mutation;
- external effects such as email, deployment, package publication, cloud resource change, or billing reservation.

At-least-once retries use stable effect identities. An external API without idempotency support is wrapped by an effect-specific reconciliation protocol. “Maybe it happened” is not a valid terminal state for a registered effect.

---

## 10. Evidence-Carrying Change

```text
EvidenceCarryingChange {
  change_id,
  intent_run_id,
  base_authority_receipt,
  refreshed_authority_receipt?,
  reconciliation_record?,
  proposed_git_object_closure,
  proposed_commits[],
  workspace_manifest,
  net_effect_root,
  diff_commitment,
  context_packet_ids[],
  requirement_dispositions[],
  evidence_records[],
  known_limitations[],
  negative_evidence_refs[],
  risk_classification,
  requested_publication,
  producer_attestation,
}
```

### 10.1 Evidence record

Each record states:

- claim supported and claim class;
- exact implementation/toolchain/command;
- inputs, environment, source position, and budgets;
- output artifact identity;
- pass/fail/refused/indeterminate outcome;
- scope, assumptions, and exclusions;
- replay completeness class;
- verifier identity/independence class;
- freshness/invalidation conditions.

“All tests pass” is a summary, not evidence.

### 10.2 Requirement disposition

Each acceptance requirement is exactly one of:

- satisfied with evidence;
- partially satisfied with explicit boundary;
- not applicable with reason;
- blocked by typed refusal;
- unsatisfied.

Missing requirements cannot disappear from a generated summary.

### 10.3 Known limitations and negative evidence

Agents are rewarded for disclosing uncertainty, stale context, untested platforms, flaky evidence, performance noise, migration risk, and semantic assumptions. Failed hypotheses link the negative-evidence ledger so later agents do not repeat them as novel ideas.

---

## 11. Verification and review

### 11.1 Deterministic verification

Schema, formatting, identity, path policy, dependency constitution, required checks, evidence signatures, decision replay, and source-span consistency are deterministic services.

### 11.2 Independent agent review

A review agent receives the Intent Run, proposed closure/diff, evidence, relevant Context Packets, and a distinct review capability. It does not receive producer hidden state or unrestricted secrets unless policy deliberately classifies that weaker evidence. Findings include severity, location, invariant, evidence, confidence, proposed disposition, and decision witness.

### 11.3 Human review

The human view shows:

- sponsor/agent/delegation lineage;
- canonical base and refresh relation;
- changed paths/risk classes;
- evidence graph and stale/failed checks;
- exact capabilities and external effects;
- resource cost;
- omissions and unresolved uncertainty;
- publication transaction to authorize.

Human approval is a signed/authorized canonical forge event under a named policy snapshot. It is not inferred from conversational wording or a reaction emoji.

### 11.4 Example policies

Repositories may require:

- human approval for every agent-authored change;
- independent agent plus human review for auth/crypto/workflow/release paths;
- multiple native builds for release code;
- no production-secret access;
- changed-line, dependency, capability, or cost ceilings;
- mandatory refresh and rerun after target movement;
- automatic merge only for low-risk generated updates with complete deterministic evidence.

---

## 12. Publication protocol

An agent never directly sets a ref. It submits a publication proposal that becomes the ordinary sealed repository mutation.

Publication binds:

- target refs and expected values;
- proposed Git object closure and net effects;
- current/permitted authority receipt;
- Intent Run, Context Packet, evidence, and verifier identities;
- approvals/checks and policy snapshot;
- actor/capability;
- stable idempotency key.

If the authority head changed, policy may:

- refuse with a conflict certificate;
- require new context and reconciliation;
- replay declared intents;
- apply a structured patch/merge proof;
- enter a deterministic merge queue;
- accept only if refined witnesses prove all relevant reads/invariants remain valid.

A successful head CAS publishes one decision batch containing the RCR and returns the immutable transaction outcome plus new AuthorityReadReceipt. It does not return a newly minted capsule unless a checkpoint was independently created for that exact RCR. A timeout is resolved by `TxId` lookup.

---

## 13. Delegation protocol

```text
SubIntent {
  child_run_id,
  parent_run_id,
  objective,
  input_commitments,
  output_schema,
  attenuated_capabilities,
  budget,
  deadline,
  required_evidence,
  disclosure_policy,
}
```

The child returns an immutable result bundle. The parent validates schema, commitments, evidence, and authority ancestry before use. Child prose is untrusted data. Recursion depth, fan-out, aggregate budget, context duplication, and wall-clock are bounded.

Delegation lineage and cost remain visible in the final Evidence-Carrying Change.

---

## 14. Cancellation, failure, and quiescence

### 14.1 Causes

Sponsor request, policy revocation, timeout, budget exhaustion, superseded run, security quarantine, operator shutdown, parent failure, or repository deletion may request cancellation.

### 14.2 Canonical mutation boundary

- before transaction sealing: cancellation may leave no canonical transaction;
- after sealing but before head publication: work drains/aborts safely; later retry uses the same sealed identity;
- after successful head publication: canonical result remains; only response/outbox/derived work may cancel.

Cancellation never asserts non-commit.

### 14.3 Quiescence

A run is `Quiescent` only after:

- child tasks and agents are joined or terminally quarantined;
- processes and network sessions stop;
- temporary capabilities/secrets are revoked or expire;
- prepared candidate writes are aborted, retained under policy, or resolved;
- canonical/external effects are reconciled by stable identity;
- workspace retention/deletion is decided;
- logs/evidence are sealed;
- budget accounting is final;
- no unresolved obligation remains.

---

## 15. Budgets and economics

An Intent Run may bound:

- model/tool tokens or monetary cost;
- CPU/GPU time;
- memory and TreeFS storage;
- object bytes/requests;
- network ingress/egress and destinations;
- wall-clock duration;
- process count;
- context/retrieval bytes;
- external API calls;
- changed files/bytes/lines;
- delegated depth/fan-out;
- publication attempts and witness-refinement budget.

Expensive operations reserve before execution. Settlement uses measured consumption. Budget exhaustion requests cancellation and returns a typed outcome; repository text cannot raise its own budget.

---

## 16. Privacy and retention

- Conversational transcripts are derived data, not automatically canonical repository history.
- Policy may retain none, redacted, encrypted, or full transcripts.
- Evidence necessary for protected mutation remains verifiable for the configured audit period even when conversational text is removed.
- Context Packets, embeddings, graph generations, logs, and evidence inherit source authorization and retention.
- Hosted FrankenGit must not use private source/context/transcripts/evidence for model training without separate explicit authorization.
- Deletion claims distinguish logical invisibility, scheduled physical deletion, backup expiry, and cryptographic erasure.

---

## 17. Typed refusal taxonomy

Initial refusals include:

- `IntentExpired`
- `IntentBytesConflict`
- `SponsorUnauthorized`
- `AgentIdentityRevoked`
- `AuthorityReceiptInvalid`
- `AuthorityReceiptStale`
- `CapabilityMissing`
- `CapabilityExpired`
- `CapabilityAudienceMismatch`
- `CapabilityScopeViolation`
- `DelegationAmplifiesAuthority`
- `ContextGenerationMixed`
- `ContextCoverageUnsupported`
- `WorkspaceBaseUnavailable`
- `WorkspacePolicyViolation`
- `PathOutsideScope`
- `NetworkDestinationDenied`
- `SecretPurposeDenied`
- `BudgetInsufficient`
- `EvidenceMissing`
- `EvidenceInvalid`
- `EvidenceStale`
- `IndependentVerificationRequired`
- `TargetRefMoved`
- `WitnessRefinementInsufficient`
- `PublicationPolicyRefused`
- `CancellationInProgress`
- `ObligationsOutstanding`
- `ExternalEffectIndeterminate`
- `SchemaUnsupported`

Refusals are inspectable protocol outcomes, not generic internal errors.

---

## 18. Conformance requirements

An implementation cannot claim Agent Protocol conformance until it passes:

1. capability attenuation, ancestry, audience, expiry, and replay property tests;
2. repository-content prompt-injection red-team corpus;
3. secret-exfiltration attempts across tool, process, log, context, evidence, and output surfaces;
4. TreeFS path/symlink/reparse/hardlink escape corpus;
5. cancellation at every task/effect/publication yield point;
6. duplicate, delayed, reordered, and fabricated tool results;
7. child recursion, budget, context duplication, and authority amplification;
8. producer/verifier trust-domain classification tests;
9. stale authority receipt and target-ref movement publication tests;
10. exact external-effect reconciliation after crash and retry;
11. human/API/compact rendering equivalence;
12. evidence fabrication, stale evidence, and mixed-generation context rejection;
13. cross-tenant workspace/index/cache isolation;
14. quiescence proof with no orphan task, credential, process, or obligation;
15. ordinary Git export of the committed result.

Claims and evidence levels are governed by [`VERIFY_SPEC.md`](../VERIFY_SPEC.md).

---

## 19. Minimal viable protocol slice

The first implementation supports one repository and one local agent harness with:

- authorized Intent Run;
- verified AuthorityReadReceipt;
- read/TreeFS/process/network/effect capabilities;
- bounded Context Packet with omissions;
- sparse COW TreeFS workspace and intent log;
- effect obligations and ledger;
- content-addressed logs/check evidence;
- Evidence-Carrying Change;
- independent deterministic verification;
- publication proposal through the ordinary sealed transaction/head CAS;
- cancellation to quiescence.

It should not begin with agent chat, reputation, marketplaces, autonomous issue selection, multi-agent swarms, or model routing. Those become safe only after the control protocol works.
