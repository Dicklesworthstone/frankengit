# FrankenGit Agent Collaboration Protocol

**Status:** proposed protocol draft
**Scope:** software agents operating through FrankenGit
**Last updated:** 2026-08-19

FrankenGit treats software agents as first-class collaborators, but not as ambiently trusted shell sessions. The protocol makes an agent’s authority, intent, inputs, work, evidence, cost, and terminal outcome explicit enough that humans and other agents can inspect and reproduce the change without trusting a conversational transcript.

The protocol is model- and harness-neutral. A Codex-like coding agent, a local CLI agent, a hosted review agent, a deterministic bot, or a human-driven automation client uses the same control objects and capability boundaries.

---

## 1. Design goals

The protocol MUST provide:

1. **Attribution:** identify the agent instance, harness, model/runtime declaration, sponsor, delegator, and capability issuer.
2. **Intent integrity:** preserve the exact authorized task independently of repository text and tool output.
3. **Least authority:** grant only the operations, repositories, refs, paths, resources, secrets, time, and spend required.
4. **Workspace isolation:** provide a capsule-pinned, sparse, copy-on-write environment with explicit network and process powers.
5. **Evidence:** bind claims to immutable tests, logs, diffs, analyses, and verifier results.
6. **Cancellation safety:** reach quiescence without orphaned work, credentials, prepared writes, or unknown external effects.
7. **Reviewability:** expose a compact machine protocol and a parallel human-readable view.
8. **Composability:** allow agent delegation without authority amplification or provenance loss.
9. **Economic accountability:** meter storage, compute, network, model/tool usage, and external effects against budgets.
10. **Git escape:** publish ordinary Git commits and refs; the agent protocol enriches collaboration but does not make source history proprietary.

---

## 2. Threat assumptions

The protocol assumes:

- repository files, issues, comments, diffs, test output, webpages, and tool responses may contain prompt injection;
- an agent can misunderstand sponsor intent, hallucinate state, claim tests passed when they did not, or select unsafe tools;
- a model or harness may be compromised;
- a delegated agent may return fabricated evidence;
- retries, cancellation, crashes, and network partitions may occur after external effects;
- secrets may be requested by malicious content;
- agents may be induced to broaden scope or consume excessive resources;
- an authorized patch may still be wrong or malicious.

Correctness therefore comes from capability enforcement, canonical state transitions, evidence verification, and publication policy—not from asking the agent to behave.

---

## 3. Identities and roles

### 3.1 Human sponsor

A `SponsorId` is the human or organizational principal accountable for authorizing an Intent Run. Sponsorship does not mean the sponsor authored every line; it identifies who granted the work authority and receives policy notifications.

### 3.2 Agent principal

An `AgentPrincipal` identifies the logical agent identity. It may be persistent across runs, but every execution has a distinct `AgentInstanceId`.

Recommended fields:

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

### 3.3 Agent instance

An `AgentInstance` binds one execution environment to:

- principal;
- harness and harness version;
- declared model/provider/runtime or deterministic bot identity;
- binary/container/environment commitment where available;
- sponsor and optional delegating parent;
- start time and expiry;
- attestation trust domain.

A model declaration is provenance, not a security guarantee. FrankenGit MUST remain correct when it is false or unavailable.

### 3.4 Capability issuer

The issuer evaluates policy and produces attenuated, audience-bound capabilities. The issuer may be the repository, organization, self-hosted administrator, or managed FrankenGit control plane.

### 3.5 Independent verifier

A verifier is a separately identified principal or deterministic service that evaluates evidence. It MUST NOT inherit the patch-producing agent’s write authority unless policy explicitly requires it, and protected workflows should prefer separate trust domains.

### 3.6 Child agent

A child is created by delegation from a parent Intent Run. It receives an explicit sub-intent, attenuated capabilities, budget, and output contract. The parent cannot delegate rights it does not possess.

---

## 4. Intent Run

The **Intent Run** is the authoritative control object. Natural-language text may be included, but the object also carries machine-enforceable scope.

```text
IntentRun {
  schema_version,
  run_id,
  sponsor_id,
  agent_principal_id,
  agent_instance_constraints,
  parent_run_id?,
  repository_id,
  base_capsule,
  target_refs,
  objective,
  acceptance_contract,
  allowed_path_patterns,
  denied_path_patterns,
  allowed_operation_classes,
  required_evidence,
  publication_policy,
  resource_budget,
  secret_policy,
  network_policy,
  delegation_policy,
  expiry,
  request_commitment,
  sponsor_signature_or_authorization,
}
```

### 4.1 Objective

`objective` is explanatory. It may be natural language, structured requirements, issue references, or a generated work order. It does not override the machine-enforced fields.

### 4.2 Acceptance contract

The acceptance contract lists observable conditions: tests, compatibility cases, benchmarks, file/path requirements, migration constraints, security checks, documentation changes, and allowed uncertainty. A missing condition is not silently inferred as authority.

### 4.3 Base capsule and target refs

Every run begins from an immutable `base_capsule`. Target refs define where publication may be proposed. The workspace may refresh derived context, but a final publication must declare how it rebased or reconciled from the original base.

### 4.4 Request commitment

The canonical encoding of the Intent Run is hashed and bound to its identity. Reusing a `run_id` with different bytes is a terminal protocol violation.

---

## 5. Capability model

Capabilities are unforgeable, audience-bound authorizations evaluated by tools and services. A model cannot grant itself authority by emitting text.

A capability should include:

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
  max_calls?,
  max_bytes?,
  max_cost?,
  not_before,
  expires_at,
  parent_capability?,
  intent_run_id,
  nonce_or_txn_binding?,
  audience,
  caveats,
  issuer_signature_or_mac,
}
```

### 5.1 Operation classes

Initial operation classes should include:

- read canonical object;
- read derived context;
- create workspace;
- modify workspace path;
- execute sandboxed process;
- access network destination/class;
- request secret handle;
- invoke external integration;
- create immutable object;
- propose commit/ref transaction;
- submit review/check/evidence;
- publish comment or issue mutation;
- delegate sub-intent;
- consume compute/model/storage budget.

A broad “repo write” token is not an acceptable agent capability.

### 5.2 Attenuation

Delegation can only intersect selectors, reduce quotas, shorten expiry, narrow operation classes, and add caveats. A verifier checks the full ancestry. An absent parent or invalid attenuation is a typed refusal.

### 5.3 Revocation and expiry

Short-lived capabilities should expire naturally. Revocation events apply at a defined canonical position. Tools must validate freshness at use time for high-value operations, not only when a workspace starts.

---

## 6. Context Packet

A **Context Packet** is a bounded, provenance-preserving retrieval product intended for an agent or reviewer. It is not an unstructured prompt dump and never claims to be the entire repository unless a closure proof accompanies it.

```text
ContextPacket {
  packet_id,
  repository_id,
  capsule_id,
  request_intent,
  authorization_scope,
  retrieval_budget,
  sources[],
  relationships[],
  omissions[],
  coverage_claims[],
  ranking_and_fusion_identity,
  generated_at,
  expiry_or_freshness_policy,
  packet_commitment,
}
```

Each source entry includes:

- immutable object or forge-event identity;
- path/ref/commit context;
- byte or AST span;
- retrieval channel: exact, lexical, structural, semantic, graph, history, ownership, test, or policy;
- score and calibration metadata where meaningful;
- authorization decision;
- transform/summarization lineage;
- freshness position.

### 6.1 Prompt-injection separation

Context has two channels:

1. **control metadata**, generated by FrankenGit and authenticated under the Intent Run;
2. **untrusted source content**, visibly delimited and never interpreted as authority.

Rendered UI, API, and compact agent formats preserve this distinction. A source file cannot masquerade as capability metadata.

### 6.2 Coverage

Coverage claims are typed. Examples:

- all files matching an exact path pattern at capsule X;
- all direct reverse dependencies represented in projection generation Y;
- top-k semantic candidates under model/index identity Z;
- all protected policy files;
- sampled historical examples, not exhaustive.

Approximate retrieval must say approximate. Missing index generations must fail or degrade explicitly.

---

## 7. Workspace protocol

An agent workspace is a disposable materialization identified by `WorkspaceId` and pinned to an immutable capsule.

### 7.1 Creation

Workspace creation resolves:

- capsule and sparse path set;
- writable overlay and base layers;
- filesystem/path policy;
- process isolation profile;
- network policy;
- secret handles;
- CPU, memory, disk, process, wall-clock, and output budgets;
- tool inventory and versions;
- evidence capture policy.

The result is an attested workspace manifest.

### 7.2 Filesystem rules

- descriptor-relative operations and no-follow semantics for security-sensitive paths;
- explicit handling of symlinks, submodules, case folding, Unicode normalization, executable bits, and file modes;
- no write outside the overlay;
- no implicit access to sibling repositories or host files;
- generated files and ignored files remain visible in the final workspace diff/evidence policy where relevant.

### 7.3 Execution

Every process execution records:

- command identity and normalized arguments;
- working directory;
- environment commitment with secrets redacted or represented by handles;
- tool/binary/container identity;
- input capsule/workspace generation;
- network and filesystem capabilities;
- resource budget;
- stdout/stderr/log artifact identities;
- exit and cancellation outcome;
- child-process obligations.

Interactive shells are an execution mode, not an authority boundary.

### 7.4 Refresh and rebase

A workspace does not silently float to a new ref. Refresh creates a new base capsule relation and records the reconciliation method. Publication evidence distinguishes tests run before and after reconciliation.

---

## 8. Tool-call and effect ledger

Every consequential tool invocation produces an append-only ledger entry:

```text
EffectRecord {
  effect_id,
  run_id,
  agent_instance_id,
  parent_effect_id?,
  capability_id,
  operation,
  canonical_input_commitment,
  started_at,
  budget_reserved,
  external_idempotency_key?,
  terminal_outcome,
  output_commitments[],
  budget_consumed,
  obligations_created[],
  obligations_resolved[],
}
```

The ledger distinguishes:

- pure reads;
- local derived writes;
- immutable canonical object creation;
- proposed canonical mutation;
- committed canonical mutation;
- external effects such as email, deployment, package publish, or cloud resource change.

At-least-once retries require idempotency identities. An external API without idempotency support is wrapped by an effect-specific reconciliation state machine; it cannot be treated as exactly once.

---

## 9. Evidence-Carrying Change

An **Evidence-Carrying Change** packages a proposed source change with machine-verifiable lineage.

```text
EvidenceCarryingChange {
  change_id,
  intent_run_id,
  base_capsule,
  proposed_commits[],
  workspace_manifest,
  diff_commitment,
  requirement_dispositions[],
  evidence_records[],
  known_limitations[],
  risk_classification,
  requested_publication,
  producer_attestation,
}
```

### 9.1 Evidence record

Each record declares:

- claim being supported;
- command/procedure and implementation identity;
- exact inputs and environment;
- output artifact commitment;
- pass/fail/refused/indeterminate outcome;
- scope and exclusions;
- verifier identity;
- freshness and invalidation conditions.

A prose sentence such as “all tests pass” is not evidence. It may summarize records, but protected checks evaluate the records themselves.

### 9.2 Requirement disposition

Every acceptance requirement is one of:

- satisfied with evidence;
- partially satisfied with explicit boundary;
- not applicable with reason;
- blocked by typed refusal;
- unsatisfied.

Missing requirements cannot silently disappear from the summary.

### 9.3 Known limitations

Agents are rewarded for disclosing uncertainty, stale context, untested platforms, flaky evidence, performance noise, migration risk, and semantic assumptions. Publication policy may reject the change, but the disclosure is still protocol-correct.

---

## 10. Verification and review

### 10.1 Deterministic verification

Schema validation, formatting, object identity, path policy, dependency rules, required tests, and evidence signatures should be deterministic services.

### 10.2 Independent agent review

A review agent receives the Intent Run, patch, evidence, relevant Context Packet, and a distinct review capability. It should not receive producer hidden state or unrestricted secrets. Its findings are structured by severity, location, invariant, evidence, confidence, and proposed disposition.

### 10.3 Human review

The human view shows:

- sponsor and agent lineage;
- task and machine scope;
- changed paths and risk classes;
- evidence graph and stale/failed checks;
- exact capabilities used;
- resource cost;
- unresolved uncertainty;
- publication transaction to be authorized.

Human approval is a signed forge event with policy identity. It is not inferred from a comment emoji or agent summary.

### 10.4 Policy examples

A repository may require:

- human approval for any agent-authored change;
- independent agent review plus human approval for auth/crypto/workflow paths;
- two diverse builds for release code;
- no agent access to production secrets;
- a maximum changed-line or dependency budget;
- mandatory rebase and rerun after target-ref movement;
- automatic merge for low-risk generated updates with complete deterministic evidence.

---

## 11. Publication protocol

An agent never directly “sets the branch.” It submits a publication proposal that becomes a `RefTxn` only after policy evaluation.

Publication binds:

- target refs and expected values;
- proposed commit object graph;
- current or permitted base capsule;
- Intent Run and evidence identities;
- approvals/checks;
- policy snapshot;
- actor/capability;
- idempotency identity.

If target state changed, policy may:

- refuse with a conflict certificate;
- require agent reconciliation;
- invoke a deterministic merge queue;
- accept only if the declared invariant/read sets remain valid.

A successful publication is admitted by one Repository Commit Record and returns the committed Repository Capsule. When publication also changes canonical PR/release/deployment state, those event bytes are children of the same record. A timeout is resolved by transaction identity.

---

## 12. Delegation protocol

A parent may issue a `SubIntent`:

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
}
```

The child returns an immutable result bundle. The parent must validate schema, commitments, and evidence before use. Child prose is untrusted data. Recursion depth, fan-out, aggregate budget, and wall-clock limits are policy-controlled.

Delegation lineage remains visible in the final Evidence-Carrying Change.

---

## 13. Cancellation, failure, and quiescence

### 13.1 Cancellation states

Cancellation is a first-class signal with a cause: sponsor request, policy revocation, timeout, budget exhaustion, superseded run, security quarantine, operator shutdown, or parent failure.

### 13.2 Quiescence contract

A run is `Quiescent` only after:

- child tasks and child agents are joined or terminally quarantined;
- temporary capabilities and secrets are revoked/expired;
- processes and network sessions are stopped;
- prepared transactions are aborted or resolved;
- external effects are reconciled by idempotency identity;
- workspace retention/deletion is decided;
- logs and evidence are sealed;
- budget accounting is final.

### 13.3 Unknown outcomes are defects

For canonical writes and registered external effects, the protocol provides a queryable terminal identity. “The connection dropped, so maybe it happened” is not an acceptable final state.

---

## 14. Budgets and economics

An Intent Run may carry budgets for:

- model/tool tokens or provider cost;
- CPU/GPU time;
- memory and workspace storage;
- object-store bytes and requests;
- network ingress/egress;
- wall-clock duration;
- subprocess count;
- retrieval/context bytes;
- external API calls;
- number/size of changed files;
- number/depth of delegated agents.

Budgets reserve before expensive operations where possible and settle against measured use. Budget exhaustion returns a typed terminal outcome and invokes quiescence. Agents cannot increase their own budget by editing repository configuration.

---

## 15. Privacy and retention

- Agent transcripts are derived evidence, not automatically canonical repository state.
- Repositories may choose no transcript retention, redacted retention, encrypted retention, or full retention under policy.
- Evidence required to justify a protected mutation must remain verifiable for the configured audit period even if conversational text is deleted.
- Context Packets and embeddings inherit source authorization and retention.
- Hosted FrankenGit must not use private source, context, transcripts, or evidence for model training without separate explicit authorization.

---

## 16. Protocol refusal taxonomy

Initial typed refusals include:

- `IntentExpired`
- `IntentBytesConflict`
- `SponsorUnauthorized`
- `AgentIdentityRevoked`
- `CapabilityMissing`
- `CapabilityExpired`
- `CapabilityAudienceMismatch`
- `CapabilityScopeViolation`
- `DelegationAmplifiesAuthority`
- `BaseCapsuleUnavailable`
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
- `PublicationPolicyRefused`
- `CancellationInProgress`
- `ObligationsOutstanding`
- `ExternalEffectIndeterminate`
- `SchemaUnsupported`

Refusals are safe, inspectable protocol outcomes, not generic internal errors.

---

## 17. Conformance requirements

An implementation cannot claim Agent Protocol conformance until it passes:

1. capability attenuation and replay property tests;
2. repository-content prompt-injection red-team corpus;
3. secret-exfiltration attempts across tool, log, Context Packet, and evidence surfaces;
4. cancellation at every execution/effect/publication yield point;
5. duplicate and reordered tool-result delivery;
6. child-agent recursion, budget, and authority tests;
7. producer/verifier trust-domain separation tests;
8. stale-base and target-ref movement publication tests;
9. exact effect reconciliation after crash and retry;
10. human/compact protocol rendering equivalence;
11. evidence fabrication and stale-evidence rejection;
12. cross-tenant workspace/index/cache isolation.

Claims and evidence levels are governed by [VERIFY_SPEC.md](../VERIFY_SPEC.md).

---

## 18. Minimal viable protocol slice

The first implementation should support one repository and one local agent harness with:

- signed or locally authorized Intent Run;
- read/write/process capabilities;
- capsule-pinned copy-on-write workspace;
- command/effect ledger;
- content-addressed logs and test evidence;
- Evidence-Carrying Change;
- independent deterministic verification;
- publication proposal through `RefTxn`;
- cancellation-to-quiescence.

It should not begin with agent chat, reputation, a marketplace, autonomous issue selection, multi-agent swarms, or model routing. Those features become safe only after the control protocol works.
