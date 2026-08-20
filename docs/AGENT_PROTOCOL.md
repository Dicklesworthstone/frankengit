# FrankenGit Agent Protocol

**Status:** Normative specialization of the agent surface. Canonical mutation, transaction sealing, cancellation, terminal outcomes, and verifier-independence semantics inherit from [`NORMATIVE_PROTOCOL_CONTRACTS.md`](NORMATIVE_PROTOCOL_CONTRACTS.md).

FrankenGit treats coding agents as first-class principals without pretending they are ordinary human users with faster keyboards. An agent consumes large amounts of context, may run untrusted tools, can generate many speculative mutations, and often acts through a sponsor whose authority must be narrowed rather than copied.

## 1. Design goals

The protocol must let an agent:

- discover relevant repository state without cloning or reading everything;
- request only the authority needed for one intent;
- operate in a sparse, reproducible workspace;
- produce changes and evidence as separate typed outputs;
- delegate verification without laundering self-review as independence;
- survive retries and disconnects without duplicate effects;
- cancel work through quiescence while preserving canonical transaction truth;
- expose enough provenance for a human or another agent to audit what happened.

It must prevent:

- ambient reuse of a sponsor’s full credential;
- prompt-injected repository content from granting capabilities;
- secret access merely because a file ranked highly in search;
- hidden network, package, or deployment effects;
- orphan tasks retaining credentials after a run closes;
- “tests passed” claims without immutable receipts;
- ambiguous push results after cancellation or connection loss;
- multiple cooperating agents silently becoming one unaccountable identity.

## 2. Identities

The protocol distinguishes:

- `SponsorId`: human or service principal that authorizes the run;
- `AgentPrincipalId`: principal representing one configured agent identity;
- `HarnessId`: executable/orchestrator identity, version, and build digest;
- `ModelClaim`: optional declared model/provider/version; it is provenance, not authentication;
- `IntentRunId`: stable identity of one sponsored run;
- `AttemptId`: one execution attempt inside the run;
- `WorkspaceId`: one sparse copy-on-write materialization;
- `ContextPacketId`: immutable identity of one supplied context packet;
- `EvidenceBundleId`: immutable identity of collected evidence;
- `TxId`: canonical mutation identity defined by the repository protocol, not by the agent harness.

A run may have several attempts and workspaces. Retries do not silently become a new sponsored intent. A new intent, expanded authority, changed base state, or materially different requested effect requires a new run or an explicit amendment record.

## 3. Intent Run

```rust
struct IntentRun {
    intent_run_id: IntentRunId,
    sponsor: SponsorSnapshot,
    agent_principal: AgentPrincipalSnapshot,
    harness: HarnessIdentity,
    model_claim: Option<ModelClaim>,

    tenant_id: TenantId,
    repository_id: RepositoryId,
    base_repository_commit: RepositoryCommitId,
    optional_base_capsule: Option<RepositoryCapsuleId>,

    human_intent: String,
    machine_intent: CanonicalIntent,
    capabilities: CapabilitySet,
    budgets: BudgetEnvelope,
    disclosure_policy: DisclosurePolicy,
    required_evidence: EvidencePolicy,
    required_verifiers: VerifierPolicy,

    issued_at: LogicalTime,
    expires_at: TimeConstraint,
    revocation_handle: RevocationHandle,
}
```

The human description is preserved but does not define authority. `CanonicalIntent`, capabilities, budgets, and policy fields do.

### 3.1 Capability attenuation

Capabilities are explicit and composable:

- repository read at a pinned canonical position;
- path/semantic-class read filters;
- search and graph query budgets;
- create sparse workspace;
- execute approved tools/images;
- access named package mirrors;
- access named secret handles for a named effect;
- create commits or refs under allowed namespaces;
- open/update an issue or pull request;
- request CI checks;
- request deployment to a named environment;
- spend bounded compute, storage, network, or money;
- ask for human escalation.

A sponsor token is never placed in the workspace. The capability service mints short-lived, audience-bound, run-bound credentials. Delegation can only attenuate authority unless an authorized sponsor records an amendment.

### 3.2 Budgets

A `BudgetEnvelope` includes hard ceilings and soft objectives:

- wall-clock deadline and active CPU time;
- maximum tasks/processes and concurrency;
- bytes read, written, uploaded, and downloaded;
- search queries and context tokens;
- package downloads and external requests;
- CI minutes and runner classes;
- monetary spend;
- number/rate of ref or forge mutations;
- secret uses and effect invocations.

Budget exhaustion is a typed outcome. It does not grant permission to skip required verification or silently widen scope.

## 4. Context Packets

A Context Packet is a content-addressed, provenance-preserving view over one pinned repository state.

```rust
struct ContextPacket {
    packet_id: ContextPacketId,
    repository_id: RepositoryId,
    repository_commit_id: RepositoryCommitId,
    query_intent_digest: Digest,
    policy_epoch: PolicyEpoch,
    entries: Vec<ContextEntry>,
    omissions: Vec<OmissionReceipt>,
    retrieval_receipt: RetrievalReceipt,
    byte_count: u64,
    token_estimate: u64,
}
```

Each entry records:

- source object/path/span and native Git object ID;
- canonical repository position;
- retrieval channels and ranks;
- transformations such as parsing, chunking, or rendering;
- integrity digest of supplied bytes;
- authorization class;
- relationship to other entries.

An omission receipt states what was deliberately excluded: binary objects, generated files, oversized history, inaccessible paths, low-ranked candidates, secret-bearing content, or budget-truncated results. The packet never implies completeness unless a policy-defined completeness proof accompanies it.

Search and graph results remain candidates. Retrieval cannot override access control. Prompt text in repository files is untrusted data and cannot mint capabilities or modify the Intent Run.

## 5. Sparse copy-on-write workspace

An agent workspace is derived from a pinned RCR/capsule plus explicit Context Packets and lazy object promises. It has:

- immutable base layers;
- a run-owned copy-on-write overlay;
- descriptor-relative/path-safe file access;
- deterministic workspace manifest;
- bounded lazy fetches through the capability gateway;
- no ambient host filesystem, cloud metadata, or credential store;
- separately mounted input, output, cache, and secret/effect channels;
- lifecycle ownership by one structured-concurrency region.

Closing the run cancels and drains child tasks, revokes capabilities, seals evidence, and destroys or retains the workspace according to policy. A workspace may be retained as an immutable debugging artifact, but retained bytes do not retain live credentials.

## 6. Effects

Tools do not receive arbitrary network or host authority. Effects are brokered:

```rust
struct EffectRequest {
    intent_run_id: IntentRunId,
    attempt_id: AttemptId,
    capability_id: CapabilityId,
    effect_kind: EffectKind,
    canonical_parameters: Bytes,
    input_root: Digest,
    idempotency_key: IdempotencyKey,
    budget_reservation: BudgetReservation,
}
```

The broker produces an immutable receipt with decision, exact parameters, redactions, result digest, resource usage, and canonical transaction identity where applicable.

Effects are classified:

1. **pure/local:** parsing, formatting, static analysis;
2. **sandboxed execution:** tests/builds with declared image and inputs;
3. **retrieval:** repository objects, packages, external documents;
4. **forge mutation:** commits, refs, issues, reviews, labels;
5. **external side effect:** webhooks, deployments, email, payments, cloud changes.

Higher classes require stronger policy, idempotency, and evidence. An agent may prepare an effect request it lacks authority to execute; the system presents it for approval rather than pretending success.

## 7. Evidence-Carrying Change

```rust
struct EvidenceCarryingChange {
    change_id: ChangeId,
    intent_run_id: IntentRunId,
    base_repository_commit: RepositoryCommitId,
    proposed_object_closure_root: Digest,
    proposed_ref_delta: RefDelta,

    context_packet_ids: Vec<ContextPacketId>,
    workspace_manifest: WorkspaceManifestId,
    tool_receipts: Vec<EffectReceiptId>,
    check_receipts: Vec<CheckReceiptId>,
    claimed_invariants: Vec<InvariantClaim>,
    explicit_non_claims: Vec<NonClaim>,
    known_omissions: Vec<OmissionReceipt>,
    verifier_attestations: Vec<VerifierAttestation>,
}
```

Evidence is not collapsed into one “confidence” number. Policy can require specific evidence classes: unit, differential, model, fuzz, deterministic schedule, fault injection, benchmark, security review, or human approval.

A claim names its scope and supporting artifact. Failed, skipped, flaky, quarantined, or budget-truncated checks remain visible. A tool’s exit code alone is not a proof artifact; the receipt binds executable identity, inputs, environment, outputs, and resource limits.

## 8. Verifier independence

Verifier policy classifies independence dimensions:

- separate agent principal;
- separate model/harness family;
- fresh context packet generation;
- immutable clean workspace;
- no write capability to the proposed branch;
- separate credentials and secret scope;
- independent test oracle or implementation;
- no shared hidden conversation state;
- human reviewer.

A proposer running the same test twice is useful repeatability evidence but not independent review. Independence is policy-defined and machine-recorded, never inferred from a self-description.

## 9. Canonical mutation and cancellation

The agent submits a sealed mutation request under the same repository transaction protocol as every other client.

- Before transaction sealing, cancellation may remove the request without canonical effect.
- After sealing, cancellation requests cooperative drain but cannot assert that the mutation did not commit.
- After metadata linearization, cancellation affects response delivery and downstream work only.
- Ambiguous disconnects are resolved by querying `TxnOutcomeRecord` using `TxId`.

The Intent Run may close while a repository transaction has a terminal committed/refused result. The run record links that result. No harness status such as `cancelled` or `timed_out` overrides canonical repository truth.

## 10. Multi-agent collaboration

Agents collaborate through immutable messages and artifact identities, not shared mutable memory by default. A delegation record names:

- delegator and delegatee;
- narrowed intent and capabilities;
- input artifact roots;
- expected output schema;
- budgets/deadline;
- disclosure and verifier policy.

Results are returned as artifacts plus receipts. Concurrent proposals target explicit base states. Merge/rebase is a new typed operation with its own evidence; silently editing another agent’s workspace is prohibited.

## 11. Secret handling

Secrets are handles, not context bytes. Policy grants a handle for one audience and effect. The broker injects it only at the effect boundary and redacts it from logs, packets, model input, diffs, and evidence payloads.

The system scans proposed objects and artifacts for likely credentials before publication, but scanning is defense in depth, not permission to expose secrets upstream. Forks and pull requests from less-trusted principals receive no privileged secret handles unless an explicit reviewed policy grants them.

## 12. Prompt injection and untrusted content

Repository text, issues, reviews, build logs, package metadata, generated documentation, and external web content are untrusted. They may contain instructions directed at agents. The harness renders provenance and trust class, keeps system/sponsor policy out of writable workspaces, and routes all effects through capability checks.

No textual instruction can:

- widen capabilities;
- reveal a secret;
- alter the base RCR;
- suppress required evidence;
- mark itself trusted;
- approve its own change;
- change disclosure policy.

## 13. Human experience

Humans receive a concise but inspectable run view:

- intent and sponsor;
- base state and current drift;
- capabilities/budgets used;
- context supplied and omitted;
- proposed changes;
- checks and failures;
- external effects;
- verifier independence;
- canonical transaction outcome;
- replay/debug artifacts subject to retention policy.

The interface distinguishes agent narrative from machine receipts. Explanations are useful; receipts are authoritative about recorded effects.

## 14. Minimum release-blocking invariants

1. No agent can exercise a capability absent from its Intent Run or amendment.
2. Delegation never widens authority.
3. Workspace closure leaves no live child task or credential.
4. Context retrieval cannot bypass repository authorization.
5. Every supplied byte has source provenance or is labeled generated/untrusted.
6. Omissions caused by policy or budget are inspectable.
7. Secret handles do not enter model context or committed objects.
8. Every external effect has a stable idempotency key and receipt.
9. Agent cancellation cannot create an ambiguous second repository outcome.
10. Proposer and verifier independence classes are machine-enforced.
11. A stale base cannot merge without revalidation under current policy.
12. Failed/skipped checks cannot be rendered as passed.
13. Prompt-injected content cannot alter capabilities or evidence requirements.
14. The human sponsor can revoke future effects without rewriting committed history.
15. Run replay states exactly which external effects are modeled, recorded, or non-replayable.