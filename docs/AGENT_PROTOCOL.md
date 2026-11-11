# FrankenGit Agent Collaboration Protocol

**Status:** normative architecture profile (its IntentRun, AuthorityReadReceipt, and Evidence-Carrying Change constructs are depended on by `NORMATIVE_PROTOCOL_CONTRACTS.md` §28, which wins on any conflict)  
**Scope:** software agents operating through FrankenGit  
**Last updated:** 2026-09-02

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

`RunId` is a stable coordination handle. `IntentRunCommitment` is the versioned commitment to every machine-enforced run field, including the exact authenticated authority-read event, allowed operation classes, resource budget, and expiry. Reusing one `RunId` with a different commitment is a terminal protocol violation.

Every task lease, plan, claim, action packet, effect record, reconciliation report, handoff, cancellation record, and learning record that can outlive an API call retains the complete commitment. Numeric equality alone never proves that two run values are interchangeable.

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
- consume compute/model/storage/network budget;
- submit an ordinary ref transaction under `PublishRefTransaction`.

`PublishRefTransaction` is the fourteenth class, appended at discriminant 13.
The original thirteen discriminants remain unchanged. `PreparePublication`
authorizes preparation only; it cannot authorize submission to repository
authority. Both classes remain independently attenuable.

A broad `repo_write` or inherited sponsor token is forbidden.

### 6.2 Attenuation

Delegation may only intersect selectors, reduce quotas, shorten expiry, narrow operations, bind additional identities, and add caveats. A verifier checks the complete ancestry. Missing ancestry or amplification is refused.

### 6.3 Revocation and freshness

High-value tools validate the complete capability ancestry and revocation/freshness at effect time, not only workspace creation or request parsing. Revocation is interpreted at one named authenticated repository position and exact read event. A cached decision commits an explicit maximum age and uses a half-open interval:

```text
revocation_observed_at <= effect_time < valid_until
```

Use exactly at `valid_until` is stale. A head generation, wall-clock timestamp, or cache hit without the authenticated read is insufficient.

For an external effect, request acceptance and outbox reservation are not the irreversible boundary. The downstream-visible boundary is dispatch. A request-time authorization MUST NOT be reused at a later dispatch instant. The dispatcher obtains a new authorization for the exact run, chain, leaf, effect ID, parent, operation, cost, and canonical input immediately before committing the typed outbox obligation.

Revocation prevents new consequential work; it does not prevent cleanup. Abort-before-dispatch, stable-key reconciliation after commit, acknowledgement, terminal failure, escalation resolution, cancellation, and containment remain available after later revocation or expiry.

The native recovered-ref profile implements pre-start cleanup through
`fg agent settle --action abort-reserved`: an authenticated original run,
independently retained tail and exclusive journal custody can append only the
existing Abort event for an exact still-Reserved publication obligation. Started
work and unrelated suffixes refuse. This releases the original reservation;
it does not establish canonical transaction absence, cancel another attempt,
renew authority or authorize resubmission. See the
[durability and retry contract](AGENT_EFFECT_JOURNAL.md#abort-a-recovered-pre-start-reservation).

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
  run_commitment,
  agent_instance_id,
  parent_effect_id?,
  capability_id,
  effect_class,
  operation,
  canonical_input_commitment,
  source_authority_receipt?,
  budget_reserved,
  budget_consumed,
  external_idempotency_key?,
  obligation_state,
  obligation_class?,
  terminal_outcome?,
  output_commitments[],
  reconciliation_evidence?,
  accepted_at,
}
```

The broker computes `run_commitment` before budget moves. Its append-only journal establishes numeric and complete run identity from the first accepted effect and refuses a later record from another complete run, even when `run_id` is equal. Reconciliation and cancellation preserve the same commitment.

New live requests may name a parent only when that distinct effect has already
been accepted by the same broker at or before the child's logical acceptance
time. This check happens before budget reservation or journal mutation; a
refused child identity remains available for a corrected retry. Parent identities
need not be numerically increasing, and terminal parents remain valid historical
causes. Historical journal replay retains its existing semantics: complete
inventory reconciliation still checks missing parents, self-parenting, time
inversions, and cycles, without requiring parent-before-child record order.

Obligation states follow the normative lifecycle: `Reserved -> Committed -> Acknowledged`, or `Reserved -> Aborted`, exactly as defined in `CALM_AND_OBLIGATIONS.md` §6. Region closure requires every obligation to be settled or terminally quarantined.

The ledger distinguishes:

- pure canonical reads;
- derived local writes;
- immutable candidate creation;
- prepared canonical mutation;
- committed/refused canonical mutation;
- external effects such as email, deployment, package publication, cloud resource change, or billing reservation.

At-least-once retries use stable effect identities. An external API without idempotency support is wrapped by an effect-specific reconciliation protocol. “Maybe it happened” is not a valid terminal state for a registered effect.

### 9.1 External dispatch proof

A checked external-effect path retains two separate authorizations:

1. request-time authorization before the run budget is reserved;
2. dispatch-time authorization immediately before the downstream-visible obligation commits.

The second authorization is reconstructed from the exact retained `EffectRequest`. It must preserve the verified ancestry and leaf capability used at acceptance and use a fresh revocation receipt for the actual dispatch instant. A refusal returns the live reservation. A post-commit journal failure returns the deferred obligation. Neither path loses cleanup ownership.

Outbox reservation and dispatch MUST use the broker that owns the accepted effect's journal and resource ledger. Equality of run, agent, or region IDs—even equality of the complete Intent Run—does not transfer that custody. Dispatch also MUST preserve the complete run commitment recorded at acceptance. A custody or run mismatch refuses before journal, budget, or dispatch-proof mutation and returns the original live grant or reservation; cleanup still acts on its original obligation.

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

### 12.1 Implemented preparation gate

`fgit-agent::WorkspaceBinding::prepare_ref_transaction` requires an
`AgentPublicationEvidence` bundle. This is the sole constructor of
`AgentRefTransaction`; a caller cannot prepare an agent ref transaction through
an evidence-free overload. The gate consumes the existing `AgentChangePlan`,
Context Packets, TreeFS overlay and export, Evidence-Carrying Change, named
requirement outcomes, ECC policy, and run reconciliation report.

Before collecting checks, the host derives and retains an
`AgentPublicationSubject` with those checks. Preparation recomputes the subject
from the complete run commitment, plan identity, exact Context Packet set,
workspace manifest, actual overlay root, exported object identities and bodies,
base/result trees, touched paths, and requested ref commands. A subject from
another run budget, expiry, context, workspace, export or request refuses even
when the numeric run ID is reused. Its tree-diff commitment identifies the
base/result trees, overlay and touched paths; it does not replace a textual diff
or the ordinary closure-validation boundary. Supplying a newly computed
subject with old checks is not evidence authentication: the trusted evidence
owner must retain the original subject and authenticate its artifacts.

Preparation checks the approval mode and exact approval or exemption-policy
root against the host's independently selected `expected_approval`. This binds
the selection; it does not authenticate an approval, sponsor, or principal.
Every plan requirement must appear exactly once, with the ECC's corresponding
disposition and supporting records of the required class. This initial strict
profile accepts only `SatisfiedWithEvidence`; partial, blocked, unsatisfied,
omitted and not-applicable outcomes refuse. Named verifier attestations must be
present and upheld. Requirements requesting independence must link a fully
independent verifier, and the ECC policy's required dimensions must be supported
by upheld attestations. Independence is computed from the existing party facts.

The reconciliation report must name the same complete run and authenticated
authority receipt, contain no unresolved effects, and precede the preparation
time. Preparation also checks the run's observation and expiry window. Legacy
refresh receipts contain numeric bases and cannot establish a new authenticated
publication basis here, so they refuse with `RefreshRequiresReplan`. A moved
base needs a newly bound run, plan, subject and evidence through the existing
authority/refresh owners. This gate does not make an old report current or
prevent new effects after that report; the execution owner must supply its
current settled report and close or drain responsibility before publication.

The gate bounds records, requirement references, object counts, path/overlay
metadata and object-body bytes before retaining the binding. The resulting
transaction keeps an immutable `AgentPublicationBinding` accessible through
`publication_evidence()`. This evidence identity is separate from the ordinary
semantic request and transaction identity: retrying the same sealed ref request
with additional evidence retains the same `TxId`, and reusing its idempotency
key for different ref semantics still refuses at the ordinary authority seal.

`crates/fgit-agent/tests/publication.rs` exercises nonempty TreeFS exports in both
Git formats through this mandatory gate and the existing reference authority's
ordinary seal, including refusal counterparts and retry identity. It does not
exercise native admission or a successful authority-head CAS. Effect-time
capability/revocation checks, artifact authentication, native closure admission,
and final head publication remain with their existing owners.

#### Native patch preparation

`fgit-node::OneNode::prepare_agent_workspace_patch_in` applies a bounded patch
through the existing native TreeFS reader, evaluator and exporter. It returns
`PreparedAgentPatchCandidate<A>` with the actual `WorkspaceBinding`, overlay,
`ExportPlan`, exact-predecessor proposal, candidate bundle and commit body held
together behind immutable accessors. The host can collect checks against these
exact bytes and pass the retained export and bundle directly to the native
publication consumer; it does not have to reconstruct a workspace or export
from a patch receipt.

`prepare_agent_workspace_patch_for_new_branch_in` is the explicit creation
profile. It takes the same source inputs plus a destination branch. The source
head/commit and destination absence are checked in one authenticated selection;
an occupied or hidden destination refuses before source object reads. The
candidate's sole parent remains the original source commit, its bundle
advertises the destination, and its proposal requires `ExpectedRef::Absent`.
Publication therefore creates the new branch while preserving the source.
Preparation grants no ref authority, and neither stale authority nor a newly
occupied destination can silently turn creation into an update or a replan.

`AgentWorkspacePatchInput` takes an authenticated Intent Run, original branch
and commit, explicit disclosure and TreeFS capabilities, patch, deterministic
commit metadata and limits. Preparation requires the run's read, TreeFS,
candidate-creation and publication-preparation classes. The selected head must
equal the run's authenticated head, and the source RCR and branch predecessor
must match. Hidden paths, incomplete directory disclosure, stale bases,
expired or regressing logical time, cancellation and resource exhaustion
refuse. The host supplies a monotone clock in the run/capability time domain
and keeps the original request deadline within that run's lifetime.

The prepared candidate's `publication_subject` binds the retained state to the
host's actual plan and Context Packets before evidence collection.
`prepare_ref_transaction` then uses the existing mandatory gate with that
original subject, independently supplied evidence, reconciliation, policy and
approval. It fills the overlay and export from its retained state. Preparation
alone creates no evidence, verifier independence, publication approval or
canonical ref update. This native host API retains state in memory; the host
still owns sponsorship, current revocations, cumulative run-budget accounting
and durable custody. It is not a source-write grant for sponsored HTTP/MCP
credentials or a restartable agent executor.


### 12.2 Checked canonical submission responsibility

`fgit-agent::CurrentAuthorityRevocationCheckedEffectBroker` provides a separate
submission lifecycle after preparation. `reserve_ref_transaction` requires the
`PublishRefTransaction` capability, a current-authority revocation receipt, an
exact complete-run binding, and an acknowledged durable journal sink. A
prepared transaction or publication evidence bundle alone grants no submission
authority.

`RefTransactionBinding` derives the ordinary seal from the prepared request,
host-authenticated principal, tenant, and original idempotency key. It retains
the full seal and publication-evidence binding, and can additionally bind the
adapter's exact custody commitment. The complete input determines the broker
effect identity; the ordinary `TxId` remains unchanged by agent provenance or
custody metadata. An adapter using the optional custody pin must verify it
against the actual objects and export it will submit.

Before the resource reservation becomes a typed `RefTransactionSubmission`,
the journal persists the exact binding. The additive `RefTransactionBound`
event uses tag 4 and retains the seal, publication binding, and optional custody
commitment. Existing event tags 1–3 retain their encodings. Recovery validates
the complete run, framing, digest chain, event sequence, and replayed lifecycle;
an independently retained acknowledged tail is required for a reconciliation
report. An unanchored journal is inspection input, not settlement evidence.

`start_ref_transaction` rechecks current authority immediately before
committing submission responsibility. It preserves the accepted ancestry and
leaf capability, full run commitment, and actual broker journal/ledger custody.
Another broker cannot take the reservation by copying run, agent, or region
IDs. A pre-start refusal returns the original reservation, which remains
abortable after expiry or revocation. A journal failure after responsibility
commits returns a pending obligation; the host must retain it and must not
dispatch on that error.

Committing this obligation means responsibility for submission has begun. It
does not establish a successful ref update, and the broker itself does not
write a seal, validate an object closure, or publish an authority head. Those
operations remain with ordinary repository admission.

`PendingRefTransactionSubmission::reconcile_async` only observes authority.
It reauthenticates the run's historical head through the original store and
head slot, requires the exact stored seal, and resolves the original `TxId`.
Both an authenticated commit and an authenticated refusal acknowledge the
obligation; the retained terminal outcome states which occurred. Unknown
outcomes and failed observations preserve pending responsibility. There is no
post-start abort or automatic resubmission path, and later expiry or revocation
does not prevent observation and cleanup.

`observe_ref_transaction_with_cumulative_async` performs the same original-run
and complete-seal authentication using a retained `CumulativeOutcomes` witness.
The authority layer rechecks its exact current head token, repository and
outcome root before reconciling any accelerator hint. A changed or absent head
returns `StaleOutcomeBasis`, distinct from an authenticated undecided result;
callers must recollect within their original request. The original run's head
body, issuance evidence and transaction seal remain required even when older
decision batches are no longer available. `reconcile_observed` can settle live
responsibility using this private authenticated observation, but first requires
the exact original binding, complete run and custody commitment. A mismatch
returns the unchanged pending submission.

`reauthorize_retained_ref_transaction` supplies the authorization half of an
explicit live continuation before the first ordinary admission invocation. It
checks the same actual broker journal and ledger, a writable acknowledged
journal sink, the retained charged obligation, original full run, original
chain and leaf, current revocations, and original authority head. It does not
reserve another effect, reset a budget, rewrite journal events, or prove that
admission has not already been invoked. A native host must separately retain
private, non-cloneable evidence of that boundary and the exact validated object
custody. Already-invoked admission and failed journal writers remain
observation-only; an undecided lookup is never permission to dispatch again.

Recovered bindings can be passed to `observe_ref_transaction_async` without
reissuing admission. A journal failure after an authoritative observation has
already settled the resource returns the terminal observation and settlement
receipt together with the persistence error. A pending journal prefix cannot
be treated as proof that the repository mutation failed.

The broker lifecycle tests use the reference authority's ordinary seals and
canonical decision publication, including refusal decisions, exact custody
mismatches, revocation, anchored recovery, and journal write failures. These
tests establish the submission-responsibility boundary; native object
admission and transport remain separately owned.

### 12.3 Native trusted-local publication consumer

`fgit-node::OneNode::publish_agent_ref_transaction_trusted_local_in` connects
the checked transaction and broker lifecycle to production quarantine and
ordinary asynchronous receive admission. Its explicit local-host profile
supports one atomic, non-force branch creation or exact update to a
single-parent commit. The original expected-old value (including explicit
absence) and ordinary idempotency key survive unchanged into the canonical
seal. Other publication shapes require their own checked adapter.

A checked `ExpectedRef::Absent` proposal can publish its reviewed changes on a
new feature branch while preserving the existing source branch. Its receive
command carries Git's format-width zero as the expected old value. The bundle
still names exactly one nonzero prerequisite from the current canonical
repository history; that prerequisite is the candidate's actual sole parent,
whose identity is bound by the sealed candidate OID and independent body
approval. The parent is never substituted for the absence precondition.
Ordinary admission refuses an occupied destination, including an identical
tip, and the exact prepared-head requirement also prevents a concurrent
creation from being silently replanned. This profile does not create a root
commit or import an unrelated parent from the uploaded pack.

The host supplies `TrustedLocalAgentPublicationInput`: the prepared
`AgentRefTransaction`, original `ExportPlan`, reviewed bundle, verified
capability ancestry, and a separate `TrustedLocalAgentPublicationApproval`.
That approval independently names the real local operator principal, original
key, complete publication-evidence binding, and SHA-256 of the reviewed commit
body. Copying those commitments from agent input is not independent approval.
The adapter keeps this boundary explicitly local; it does not convert existing
HTTP/MCP `AgentRequest` credentials into source-publication grants. Ordinary
installed ref authorization still evaluates the operator principal.

The current authority configuration must select an actual canonical capability
revocation generation through configuration schema v2.2.
`OneNode::init_with_agent_revocations` explicitly opts a new repository into
an empty canonical generation. Ordinary initialization retains its prior
profile. This constructor does not upgrade an existing repository or supply an
administrative revocation-update operation; an absent generation remains a
hard refusal.

Before new work, the consumer compares the checked reconciliation report with
the actual broker's current records and requires the plan to include
`PublishRefTransaction`. Reservation requires a durable broker. Production
quarantine retains private, synchronized object custody while the adapter
checks the actual receive command and verifies:

- the candidate's native identity and independently approved commit-body hash;
- its sole parent equals the original expected-old commit for an update, or
  the single canonical prerequisite for branch creation;
- its tree equals both the checked proposal's resulting tree and export root;
- the actual parent's tree equals the checked workspace base tree;
- every exported object's verified kind and bytes equal the checked export.

The checked export commitment is recomputed through
`AgentPublicationSubject::verify_export`. A mandatory native custody pin
combines that commitment with the approved candidate-body hash in the durable
submission binding. Intake is bounded to 10,000 exported objects, 64 MiB of
export bodies, a 2 MiB candidate commit, and a 128 MiB bundle. Quarantine is
additionally limited to the export count plus one commit and the export byte
count plus the bounded candidate. Its admitted input/expanded envelope and
object count determine the broker's reserved cost; callers cannot replace
those costs with their own assertion.

The profile requires the run's exact prepared authority head to remain current.
Current canonical revocations are read again after quarantine and before
irreversible start. The consumer strengthens the real validation proof with
`BasisBoundValidatedReceive::requiring_exact_publication_basis`; ordinary
admission therefore refuses a changed initial or CAS-retry basis even when
object-closure authority remains equivalent. Only the existing ordinary
admission path owns the eventual prepared batch and head CAS.

The trusted host explicitly maps its logical-time unit and origin to this live
node with `TrustedLocalAgentPublicationClock`. The mapping cannot move to
another runtime or survive a restart. The original request's native absolute
deadline must already fit inside the actual start authorization's expiry,
including capability and fresh-revocation limits. An overly long or unbounded
request refuses; the adapter never substitutes an independent context that
would lose the caller's cancellation or remaining quotas.

`NativeAgentSubmission` preserves both the ordinary admission result and
the responsibility-reconciliation result. An admission error is not proof of
non-commit. Pre-start errors return an abortable reservation; post-start
errors retain pending responsibility. Both canonical commit and canonical
refusal can settle submission, and callers must inspect the terminal outcome
before reporting a successful ref update.

There is one explicit live continuation for a cancellation or deadline failure
after successful responsibility start but before the host invokes ordinary
admission. That failure returns `UndispatchedNativeAgentPublication`, an
opaque owner of the original validated receive, synchronized private staging,
pending obligation, authenticated principal and original key. Its private
identity also retains the original logical clock and live node; constructing a
new clock with the same numbers cannot replace it. The owner cannot be cloned
or reconstructed from a recovered journal.

`resume_undispatched_agent_ref_transaction_in` consumes that owner with a fresh
request context, the same broker and clock, and the capability chain. It takes
no bundle, export, new approval or replacement key. An original canonical
terminal is reconciled first and returned as `Reconciled`, without another
authorization or dispatch. Otherwise the current revocations, exact prepared
head, actual writable journal/ledger ownership, original chain, and finite new
request deadline must all permit completion of the first dispatch. The
original input charge remains consumed exactly once; the implementation does
not parse, quarantine or reserve the effect again.

Authorization and pre-dispatch refusals return the same owner. Dropping an
in-flight continuation future instead discards native custody and leaves
observation-only journal debt; arbitrary future cancellation is not resumable.
Once ordinary admission has been invoked, every outcome is returned through
`NativeAgentSubmission`; even an
apparently early admission error cannot recover a resumable owner. A journal
mirror failure during start also returns pending responsibility without this
owner. Cold recovery and a moved authority basis therefore do not acquire a
new retry right. `into_pending` deliberately discards the native object custody
while preserving observation-only debt; it does not cancel or settle anything.

An exact effect already retained by the broker can recover its original
terminal outcome after expiry or loss of transport bytes without another
dispatch. `reconcile_agent_ref_transaction_in` accepts a fresh finite
cleanup context for live debt. After a cold reopen,
`observe_recovered_agent_ref_transaction_in` obtains the original TxId and
seal from the authenticated original run and externally anchored journal.
This recovery operation is read-only: an undecided result retains debt, and
observing a terminal does not append an ACK to a recovered journal or by itself
establish quiescence.

These native observation paths, including retained live continuation, use the
authority-selected retained outcome checkpoint. They verify its complete
terminal set against the exact current head token and outcome root, while
preserving original-run, full-seal and custody authentication. Covered decision
batches need not remain replayable. Head movement triggers bounded recollection
within the caller's original request; an absent current head refuses even if
its historical issuance record survives. Without a selected checkpoint, replay
still stops at a reachable terminal. Missing optional checkpoint evidence may
fall back to history, but incomplete history cannot establish an undecided
result. None of these observations renews execution authority.

`settle_recovered_agent_ref_transaction_in` supplies the separate cold cleanup
path. It reauthenticates the original saved run and independently pinned journal
prefix, holds exclusive file custody through the ordinary original-TxId lookup,
and appends only the existing ACK for an authenticated terminal. An interrupted
partial or complete copy of that exact ACK can be completed or synchronized;
any other suffix refuses without truncation. A candidate inventory is exposed
only after file synchronization and the cancellation checkpoint succeed. An
undecided result leaves bytes unchanged and returns no complete inventory.

Both canonical commit and refusal can clear the original submission debt after
expiry or revocation. The operation never creates an issuing broker, revives
native object custody, reserves more resources or calls admission. Original
spend and unrelated effects remain unchanged. The returned successor tail must
be retained independently; an ambiguous persistence result keeps the exact
terminal and ACK candidate for a retry using the original pins. See
[`AGENT_EFFECT_JOURNAL.md`](AGENT_EFFECT_JOURNAL.md#cleanup-of-recovered-canonical-ref-submissions)
for the host contract and the distinction between strict inspection and narrow
ACK completion.

The native tests in `crates/fgit-node/src/agent_publication/tests.rs` use the
embedded authority and production initial/ref publication paths in both Git
formats. They cover branch creation and update with exact ordinary retry
identity and cold journal/run recovery, occupied-branch refusal, substituted
or noncanonical prerequisites, actual parent/base-tree mismatch, canonical
refusal settlement, candidate/export mismatch, separate approval
and capability gates, finite-deadline and cancellation refusal, missing
revocation configuration, and a real competing publication changing the
prepared basis. The ECC fixtures supply explicit host assertions; these tests
do not claim a hosted agent, a model executor, or general evidence-artifact
authentication.

`agent_publication/resumption_tests.rs` exercises deterministic cancellation
between real preparation and the first admission call, retained private object
custody, successful continuation without replacement inputs or another charge,
clock/broker/capability/deadline substitutions, moved-head refusal, and original
terminal settlement before fresh authorization. These tests cover the bounded
live owner; they do not establish general crash replay or journal-writer repair.

`agent_publication/checkpoint_tests.rs` uses real native admission and retained
checkpoint publication in both Git formats. A read wrapper withholds an older
decision batch to distinguish retained recovery from the original replay path.
The cases cover live settlement, expired retry, reopened durable acknowledgement,
corrupt checkpoint fallback, cancellation, missing current authority and
terminal-only recovery with incomplete older history. Original run heads,
issuance evidence and transaction seals remain retained throughout; these tests
do not establish a general history-retention or garbage-collection policy.

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
- `CapabilityRevoked`
- `CapabilityRevocationStale`
- `CapabilityAncestryMismatch`
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

1. capability attenuation, ancestry, audience, expiry, replay, and ancestor-revocation property tests;
2. repository-content prompt-injection red-team corpus;
3. secret-exfiltration attempts across tool, process, log, context, evidence, and output surfaces;
4. TreeFS path/symlink/reparse/hardlink escape corpus;
5. cancellation at every task/effect/publication yield point;
6. duplicate, delayed, reordered, and fabricated tool results;
7. child recursion, budget, context duplication, and authority amplification;
8. producer/verifier trust-domain classification tests;
9. stale authority receipt and target-ref movement publication tests;
10. exact external-effect reconciliation after crash and retry;
11. revocation between request acceptance, outbox reservation, and irreversible dispatch;
12. human/API/compact rendering equivalence;
13. evidence fabrication, stale evidence, and mixed-generation context rejection;
14. cross-tenant workspace/index/cache isolation;
15. quiescence proof with no orphan task, credential, process, or obligation;
16. ordinary Git export of the committed result.

Claims and evidence levels are governed by [`VERIFY_SPEC.md`](../VERIFY_SPEC.md).

---

## 19. Minimal viable protocol slice

The first implementation supports one repository and one local agent harness with:

- authorized Intent Run and complete run commitment;
- verified AuthorityReadReceipt;
- read/TreeFS/process/network/effect capabilities;
- bounded named-position revocation read and effect-time authorization;
- bounded Context Packet with omissions;
- sparse COW TreeFS workspace and intent log;
- effect obligations, complete-run-bound ledger records, and dispatch-time revocation recheck;
- content-addressed logs/check evidence;
- Evidence-Carrying Change;
- independent deterministic verification;
- publication proposal through the ordinary sealed transaction/head CAS;
- cancellation to quiescence.

It should not begin with agent chat, reputation, marketplaces, autonomous issue selection, multi-agent swarms, or model routing. Those become safe only after the control protocol works.
