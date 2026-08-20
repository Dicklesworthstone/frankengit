# FrankenGit Security Threat Model

**Status:** architecture draft
**Applies to:** the proposed self-hosted and managed FrankenGit system
**Last updated:** 2026-08-19

This document defines what FrankenGit must protect, which actors and failures it must assume, which controls belong in the deterministic correctness path, and which risks remain after those controls. It is a design contract, not a claim that an implementation already exists or has passed an audit.

FrankenGit is unusually security-sensitive because it combines five high-value systems:

1. a source-of-truth service for code and release history;
2. an identity, authorization, and policy system;
3. a general-purpose parser and renderer for attacker-controlled content;
4. a build and automation platform that executes untrusted code;
5. an agent platform that turns natural-language intent into tool use.

The design therefore assumes that malformed bytes, malicious repositories, compromised dependencies, stolen credentials, hostile contributors, buggy operators, Byzantine peers, and prompt-injected content will all occur. Security cannot depend on any one parser, replica, model, administrator, cloud, or statistical detector behaving perfectly.

---

## 1. Security objectives

FrankenGit MUST preserve the following properties.

### 1.1 Repository integrity

- A committed reference value MUST be the value accepted by the corresponding `RefTxn` state transition.
- No acknowledged transaction may disappear after the promised durability boundary.
- No unacknowledged transaction may be reported as committed merely because partial objects or cache state survived.
- Every referenced Git object MUST be byte-for-byte compatible with its declared Git object identifier.
- Every FrankenGit envelope, segment, manifest, and Repository Capsule MUST verify under its declared digest, Merkle, and signature rules.
- Repair MUST reproduce the exact committed bytes or fail closed. Approximate recovery is forbidden.

### 1.2 Authorization integrity

- Every externally initiated mutation MUST be attributable to an authenticated actor or explicitly configured anonymous capability.
- Authorization MUST be evaluated against a versioned policy snapshot identified in the transaction record.
- A capability MUST be narrowly scoped by tenant, repository, operation, resource, ref/path where applicable, expiry, and budget.
- Stale, replayed, confused-deputy, or cross-tenant capabilities MUST be rejected deterministically.

### 1.3 Confidentiality

- Private repository objects, metadata, search indexes, artifacts, logs, secrets, and derived embeddings MUST not cross tenant or repository authorization boundaries.
- Content-addressed deduplication MUST NOT become an existence oracle across mutually distrusting tenants.
- Secrets MUST not be included in prompts, Context Packets, logs, caches, attestations, or error messages unless a specific capability authorizes the flow.
- Encrypted-at-rest data MUST remain distinguishable from access control: possession of ciphertext is not permission to decrypt, and access control is not a substitute for encryption.

### 1.4 Availability and bounded resource use

- Untrusted inputs MUST be processed under explicit CPU, memory, byte, object-count, recursion, expansion, wall-clock, and output budgets.
- Cancellation MUST have a bounded route to quiescence. A cancelled operation may not retain untracked obligations, locks, leases, credentials, or child processes.
- A single repository, actor, webhook, workflow, agent, federation peer, or malformed object MUST not be able to exhaust a cell without crossing a declared admission or quota boundary.

### 1.5 Auditability and non-equivocation

- Security-sensitive transitions MUST emit immutable, causally linked audit events.
- Repository Capsules and policy snapshots MUST make history equivocation detectable within the stated trust model.
- Audit records MUST distinguish request receipt, authorization, preparation, commit, acknowledgement, publication, repair, and refusal.
- Sensitive audit fields MUST support tenant-controlled encryption and selective disclosure without destroying the integrity chain.

### 1.6 Safe interoperability

- Git, SSH, HTTP, webhook, package, identity, federation, and CI compatibility MUST not bypass FrankenGit invariants.
- Compatibility parsers MUST fail closed on ambiguity, size-limit violations, malformed encodings, integer overflow, recursive expansion, and unsupported cryptographic algorithms.
- Import and export paths MUST preserve ordinary Git escape hatches without silently weakening the canonical-state model.

---

## 2. Non-objectives and explicit limits

The following are not promised by the architecture alone:

- preventing an authorized maintainer from intentionally merging malicious code;
- proving that source code is correct or free of vulnerabilities;
- protecting plaintext after an authorized client or runner receives it;
- guaranteeing anonymity against traffic analysis by the operator or cloud provider;
- making a compromised endpoint trustworthy;
- recovering encryption keys that were destroyed without an authorized escrow or backup policy;
- inferring malicious intent from statistical anomaly scores;
- preventing every denial of service from a sufficiently large upstream network attack;
- making SHA-1 collision risk disappear for legacy Git history.

These limits must be stated in product documentation and incident reports. They must not be obscured by terms such as “zero trust,” “immutable,” “verified,” or “self-healing.”

---

## 3. Protected assets

| Asset | Security consequence if compromised |
|---|---|
| Git object bytes and identifiers | source/history corruption, malicious release substitution |
| Reference transaction log | branch/tag rollback, equivocation, lost or fabricated pushes |
| Repository Capsules and signing keys | forged recoverability roots or false history continuity |
| Forge event streams | altered issues, reviews, approvals, merge state, policy history |
| Identity and policy state | unauthorized access or privilege escalation |
| Tenant encryption keys | disclosure or permanent loss of private data |
| Runner and deployment credentials | supply-chain compromise and infrastructure takeover |
| Agent capabilities and sponsor relationships | autonomous unauthorized mutation or exfiltration |
| Webhook secrets and delivery state | forged commands, replay, SSRF, downstream compromise |
| Package and release artifacts | dependency substitution and downstream compromise |
| Search/graph/vector indexes | private-code leakage, inference, stale security decisions |
| Audit/evidence records | inability to reconstruct incidents or prove controls ran |
| Repair symbols and backups | corruption amplification, availability loss, existence leakage |
| Cache/materialization fleet | stale reads, poisoned Git execution, cross-tenant leakage |
| Control-plane configuration | systemic outage or policy bypass |

---

## 4. Actors and assumed capabilities

### 4.1 Honest users and agents

They may make mistakes, send stale requests, retry after timeouts, misconfigure policies, upload malformed repositories unintentionally, or request operations beyond their capabilities.

### 4.2 Malicious external actors

They may possess valid low-privilege accounts, control public repository content, trigger clones and webhooks, create forks, open pull requests, submit workflow definitions, send protocol-level malformed data, and measure timing or cache behavior.

### 4.3 Malicious or compromised collaborators

They may hold legitimate write, review, package, runner, or administration capabilities. FrankenGit must limit blast radius, preserve attribution, enforce independent approval policies, and make their actions reconstructable. It cannot guarantee that an action explicitly authorized by policy is benign.

### 4.4 Compromised software agents

An agent may be prompt-injected by repository text, manipulated by tool output, confused about identity or task scope, induced to expose secrets, or caused to spend unbounded resources. Agent output is untrusted until policy and evidence gates accept it.

### 4.5 Malicious repositories and artifacts

Repository data may contain parser bombs, path tricks, case-folding collisions, symlink attacks, submodule attacks, Unicode confusables, huge object graphs, adversarial deltas, decompression bombs, malicious Markdown/HTML, workflow code, package metadata, and content designed to manipulate agents or reviewers.

### 4.6 Compromised runners or cache workers

A worker may return fabricated outputs, steal credentials, poison shared caches, retain tenant data, or tamper with attestations. Hosted execution must assume workers are disposable and potentially compromised.

### 4.7 Faulty or malicious federation peers

Peers may replay old events, equivocate, advertise unavailable objects, withhold repair symbols, forge identities, flood gossip, or exploit schema/version differences.

### 4.8 Operators and infrastructure providers

Operators may make mistakes or misuse privilege. A cloud provider may lose, corrupt, delay, reorder, duplicate, or expose data within the limits of the service contract. Managed FrankenGit must minimize standing operator access and make privileged actions tamper-evident. Self-hosters remain responsible for their root trust and key custody.

### 4.9 Dependency and toolchain attackers

A transitive dependency, compiler, build script, package registry, container image, or update channel may be compromised. The dependency graph and release process are part of the security boundary.

---

## 5. Trust zones

FrankenGit divides the system into explicit zones. Data crossing a boundary must carry identity, integrity, budget, and confidentiality metadata.

1. **Untrusted edge:** Git clients, browsers, API clients, webhooks, federation peers, package clients.
2. **Protocol termination:** SSH/HTTP/TLS termination, request normalization, authentication, admission budgets.
3. **Truth plane:** object admission, `RefTxn`, forge-event commit, Repository Capsule construction, policy snapshot verification.
4. **Materialization plane:** bare-repository views, worktrees, pack generation, indexes, search/graph projections, caches.
5. **Execution plane:** CI runners, preview deployments, agent sandboxes, external tools.
6. **Key plane:** KMS/HSM or self-hosted key service, signing, envelope encryption, secret issuance.
7. **Evidence plane:** audit log, attestations, verification artifacts, incident exports.
8. **Operator plane:** deployment control, configuration, break-glass access, repair orchestration.

The truth plane MUST NOT trust outputs from materialization, execution, intelligence, or federation merely because they were produced inside FrankenGit. Every boundary has a verification contract.

---

## 6. Core security invariants

The following invariants are release-blocking.

### S-01: Root-last commitment

A Repository Capsule becomes visible only after every required immutable object, manifest, forge-event range, ref-transaction result, and durability witness named by the capsule is present and verified. Recovery must never infer commitment from partially written descendants.

### S-02: Idempotent terminal transaction identity

A `RefTxnId` maps to exactly one terminal outcome: committed with one capsule, or refused with one typed reason. Retries after timeout or cancellation return that outcome. The same identity cannot be reused with different request bytes.

### S-03: Fenced mutation

Every mutable writer carries a valid epoch or fencing token. A stale writer cannot commit even if it still holds network connections, cached policy, a process lease, or local files.

### S-04: Object-before-reference

No ref may commit to an object graph whose required objects have not passed admission, identity verification, and promised durability. Lazy fetch may defer non-required objects only where ordinary Git/promisor semantics explicitly permit it.

### S-05: No derived authority

Caches, search indexes, graph projections, embeddings, Markdown renderings, agent summaries, CI conclusions, and statistical alarms are never authoritative for ref values, policy, approval count, identity, or durability.

### S-06: Capability attenuation

A delegated capability may only narrow authority. No service, runner, workflow, or agent may mint broader rights than its input capability.

### S-07: Tenant separation before deduplication

Cross-tenant physical deduplication is forbidden by default. Where a deployment enables it, the design must prevent digest-based existence probes, key confusion, authorization bypass, and repair-symbol leakage, and must document the residual side channel.

### S-08: Verified repair

RaptorQ decoding, replica copy, backup restoration, and cache refill are candidate reconstruction mechanisms. Recovered bytes become usable only after exact digest, Merkle membership, object-identifier, length, type, and—where required—signature verification.

### S-09: Bounded interpretation

Every parser, delta resolver, decompressor, renderer, archive reader, diff engine, merge driver, workflow interpreter, and graph traversal operates under explicit limits and cannot recursively invoke an unlimited subordinate interpreter.

### S-10: Statistical non-authority

Conformal predictors, e-processes, learned classifiers, reputation scores, and anomaly detectors may trigger bounded reversible controls or human review. They cannot mutate repository truth, revoke identity permanently, allege wrongdoing, or bypass deterministic authorization.

### S-11: Secret non-persistence by default

Secrets are issued just in time, scoped, short-lived, and excluded from canonical events, general logs, caches, Context Packets, agent transcripts, and artifacts. Any exception must be an explicit typed secret output with retention and encryption policy.

### S-12: Cancellation reaches quiescence

A cancelled or timed-out operation reaches a terminal outcome with no unowned child task, lock, lease, temporary credential, ref preparation, mounted workspace, or external side effect left outside an obligation record.

### S-13: Canonical effects are atomic

When one authorized operation changes both Git-visible refs and canonical forge state, a single Repository Commit Record admits the ref delta and event batch. Outbox delivery is separate and may retry, but it cannot create, omit, or duplicate the canonical event. Recovery from commit records reproduces both effects or neither.

---

## 7. Threat analysis and required controls

## 7.1 Malformed Git objects, packs, and deltas

**Threats**

- integer overflow and truncation in pack/index parsing;
- delta chains with extreme depth or expansion ratio;
- decompression bombs and memory exhaustion;
- cyclic or inconsistent object graphs;
- duplicate object identifiers with different bytes;
- path traversal through archive-like interfaces;
- malformed commit, tree, tag, signature, or encoding headers;
- SHA-1 collision or chosen-prefix attacks against legacy object identities;
- algorithm confusion during SHA-1/SHA-256 transition.

**Required controls**

- streaming parsers with checked arithmetic and strict maximums;
- declared compressed and expanded lengths, object counts, delta depth, recursion depth, and wall-clock budgets;
- quarantine admission: objects remain unreachable until the full required graph verifies;
- independent re-hashing of canonical Git object framing;
- algorithm-tagged object identifiers; never infer algorithm from length alone;
- optional collision-detection and dual-digest envelopes for SHA-1 repositories;
- BLAKE3 FrankenGit content commitment in addition to, not instead of, the Git OID;
- test corpora from Git conformance, historical CVEs, generated adversarial packs, and differential implementations;
- no shell invocation based on object paths or metadata.

**Residual risk**

Legacy SHA-1 history remains dependent on SHA-1 identity semantics at the Git compatibility layer. FrankenGit can detect many collision patterns and commit to exact bytes under a stronger envelope digest, but it cannot retroactively make two colliding SHA-1 names distinct to an unmodified Git client.

## 7.2 Reference races, replay, and stale writers

**Threats**

- lost updates and compare-and-swap races;
- replayed push requests;
- a writer committing after lease expiry or leadership change;
- partial atomic pushes;
- force-push policy checked against stale state;
- duplicate acknowledgement after retry;
- split-brain region commits.

**Required controls**

- serializable `RefTxn` evaluation over explicit read/write/invariant-key sets;
- fencing epochs validated at the final commit point;
- request-byte commitment bound to `RefTxnId`;
- atomic multi-ref state transition;
- policy snapshot identity recorded and revalidated where policy requires current-state semantics;
- root-last Repository Capsule publication;
- single home authority for a mutable ref namespace in the first multi-region profile;
- deterministic conflict certificates and terminal typed outcomes;
- simulation campaigns that kill, delay, duplicate, reorder, and partition every protocol step.

## 7.3 Object-store and storage-layer failures

**Threats**

- acknowledged write not actually durable under the configured provider;
- stale or inconsistent listing;
- overwritten immutable key;
- corruption at rest or in transit;
- accidental lifecycle deletion;
- key-prefix confusion or tenant escape;
- restore that omits a manifest or event range;
- provider or region outage.

**Required controls**

- use only documented conditional-put and read-after-write properties in correctness paths;
- never depend on bucket listing to establish object existence or order;
- immutable keys include type, tenant namespace, digest, and format version;
- end-to-end content verification on read and repair;
- independently versioned manifests and deletion tombstones;
- lifecycle policy compiler with dry-run evidence and protected minimum retention;
- multi-failure-domain placement appropriate to the declared durability class;
- periodic reconstructability drills from object fabric plus capsules, not snapshots alone;
- provider adapters subjected to a semantic conformance suite.

## 7.4 Cache and materialization poisoning

**Threats**

- a stale bare repository serves an old ref;
- a compromised cache injects altered pack bytes;
- cross-tenant workspace remnants leak data;
- a materializer claims a capsule it did not actually build;
- case-folding, symlink, hardlink, mount, or path-normalization attacks escape a workspace;
- reused build caches smuggle malicious outputs.

**Required controls**

- every materialization is capsule-pinned and records its generation;
- ref answers come from canonical state or a verified capsule-bound projection, not `.git/refs` alone;
- generated packs are verified against requested reachable objects before delivery;
- workspace roots use descriptor-relative operations, no-follow semantics, canonical path policy, mount isolation, and ownership cleanup;
- caches are content-addressed by complete inputs and trust domain, with signed provenance for privileged reuse;
- tenant-sensitive materializations are wiped or cryptographically discarded before reuse;
- sampled independent rematerialization and differential Git checks.

## 7.5 Identity, session, and authorization attacks

**Threats**

- credential theft, token replay, session fixation, OAuth/OIDC confusion;
- malicious SSO group mapping;
- deploy-key reuse across repositories;
- policy race or stale authorization cache;
- privilege escalation through organization ownership, app installation, or team nesting;
- confused deputy between API, Git transport, Actions, and agents;
- forged commit identity mistaken for authenticated pusher identity.

**Required controls**

- distinguish author, committer, signer, pusher, approving identity, workflow identity, agent identity, sponsor, and operator;
- audience-, issuer-, tenant-, repository-, operation-, and expiry-bound tokens;
- nonce or transaction binding for high-value mutations;
- versioned policy snapshots and cache invalidation by identity;
- explicit app installations and attenuated delegated capabilities;
- hardware-backed or passkey authentication support for privileged actions;
- protected operations may require independent approvals or threshold authorization;
- signed-commit status is evidence, not a substitute for push authorization;
- break-glass access is time-bound, separately approved where configured, and immutably audited.

## 7.6 Agent prompt injection and tool abuse

**Threats**

- repository text instructs an agent to ignore sponsor intent;
- issue comments or tool output request secret disclosure;
- an agent expands its task from one repository or ref to another;
- an agent launders a dangerous command through a shell or workflow;
- a model hallucinates that a test passed or that it has authority;
- untrusted generated patches alter policy, workflow, dependency, release, or security files unnoticed;
- agent-to-agent messages create authority confusion.

**Required controls**

- the authoritative Intent Run is a typed, signed control object outside repository content;
- repository content and tool output are labeled untrusted data, never instructions with ambient precedence;
- capabilities are enforced by tools and services, not by model compliance;
- secret handles are non-readable unless the exact tool and destination are authorized;
- high-risk path classes trigger independent review or stronger evidence policy;
- agent claims refer to immutable evidence artifacts; prose cannot mark checks as passed;
- every tool call records actor, sponsor, intent, capability, input commitment, output commitment, cost, and terminal status;
- child agents receive attenuated capabilities and explicit ancestry;
- cancellation and budget exhaustion revoke temporary capabilities and force workspace quiescence;
- configurable publication gate separates “agent produced” from “canonical mutation accepted.”

**Residual risk**

An authorized agent can still produce harmful code that passes available tests, just as an authorized human can. FrankenGit reduces scope, increases evidence, and improves attribution; it does not prove semantic benevolence.

## 7.7 CI runner escape and supply-chain compromise

**Threats**

- workflow code escapes a container or VM;
- service credentials are stolen;
- cache poisoning crosses branches or tenants;
- mutable action tags change behavior;
- artifact or provenance substitution;
- untrusted pull requests access privileged workflows;
- build output depends on undeclared network, clock, randomness, or environment;
- compromised runner fabricates a successful attestation.

**Required controls**

- strong isolation profiles, with microVM or equivalent boundary for hostile workloads;
- no long-lived cloud credentials in runners; use short-lived audience-bound credentials;
- privilege separation between untrusted PR workflows and protected release workflows;
- immutable action and dependency pinning policies;
- network egress controls and declared service capabilities;
- content-addressed input/output and cache keys including trust domain;
- signed attestations binding workflow definition, source capsule, runner image, policy, inputs, and outputs;
- optional independent or diverse rebuild for high-assurance releases;
- runner quarantine and forensic retention after anomalies;
- attestations are evidence from a trust domain, not proof that the worker was uncompromised.

## 7.8 Webhooks, integrations, and SSRF

**Threats**

- forged or replayed webhook deliveries;
- attacker-controlled callback URL reaches metadata or internal services;
- DNS rebinding and redirect chains;
- oversized or recursively encoded payloads;
- integration token overreach;
- retry storms and duplicate external effects.

**Required controls**

- signed payloads with timestamp, delivery identity, body commitment, and bounded replay window;
- outbound destination policy after every DNS resolution and redirect;
- block link-local, loopback, private, metadata, and operator-defined restricted ranges unless explicitly allowed;
- response size/time budgets;
- idempotency keys and effect ledgers for deliveries;
- per-integration attenuated capability and revocation;
- circuit breakers and tenant quotas;
- no implicit trust because an integration is “official.”

## 7.9 Markdown, diff, image, and document rendering

**Threats**

- cross-site scripting, unsafe URL schemes, HTML injection;
- catastrophic parser behavior;
- source-map confusion leading comments to wrong lines;
- malicious SVG, image, font, archive, or PDF content;
- browser isolation bypass through previews;
- misleading Unicode, bidirectional text, or invisible changes.

**Required controls**

- safe deterministic Franken Markdown profile by default;
- HTML disabled or strictly sanitized with an allowlist and URL-scheme policy;
- rendering budgets and recursion limits;
- source spans carried through parse/render rather than reconstructed heuristically;
- isolated preview origins and restrictive content security policy;
- active content stripped or served as download where safe rendering is unavailable;
- visible warnings and alternate views for bidi controls, homoglyph risk, huge generated files, and binary diffs;
- renderer fuzzing and differential tests.

## 7.10 Search, graph, embeddings, and Context Packets

**Threats**

- private content leaks into another tenant’s index or embedding store;
- stale index omits a security-relevant file;
- retrieved snippets are treated as complete truth;
- crafted content manipulates ranking or agent behavior;
- embeddings reveal membership or sensitive phrases;
- provenance is lost during fusion or summarization.

**Required controls**

- authorization filtering at ingest and query, with query-time revalidation for mutable membership;
- tenant- and visibility-bound index generations;
- every result carries source identity, capsule/event position, path, span, retrieval method, and freshness;
- Context Packets declare omissions, budgets, and coverage; they never claim completeness without an executable closure proof;
- exact lexical/path lookup remains available beside approximate retrieval;
- embeddings encrypted and not cross-tenant deduplicated by default;
- statistical quality gates cannot authorize mutation;
- prompt-injection labeling and structural separation of source data from control metadata.

## 7.11 RaptorQ and repair-path attacks

**Threats**

- malformed repair symbols trigger decoder bugs or resource exhaustion;
- symbols from different objects are mixed;
- a peer advertises sufficient repair data but withholds it;
- corrupted bytes are accepted because decode succeeded;
- repair symbols leak cross-tenant object existence;
- redundancy consumes more storage or bandwidth than replication would have.

**Required controls**

- symbol identity binds tenant, object type, object digest, codec version, source-block parameters, symbol index, and length;
- decoder limits on symbol count, block size, memory, CPU, and retries;
- recovered bytes verified against end-to-end digest and structural commitments;
- repair placement policy considers correlated failure domains;
- no cross-tenant symbol pools by default;
- adaptive redundancy is bounded by deterministic minimum/maximum policy;
- periodic reconstruction tests and measured comparison against simpler replication;
- fallback to replicas or backup is explicit; “self-healing” must not loop indefinitely.

## 7.12 Federation and history equivocation

**Threats**

- peer presents different histories to different observers;
- signed events are replayed after revocation;
- schema downgrade changes interpretation;
- object availability is falsely advertised;
- gossip amplification causes denial of service;
- identity keys are rotated or compromised ambiguously.

**Required controls**

- signed, hash-linked event streams and Repository Capsules;
- explicit federation namespace, authority, schema version, and policy;
- monotonic positions or causal context with fork detection;
- key-rotation and revocation events with well-defined effective points;
- bounded gossip, peer quotas, and proof-of-possession/availability sampling where useful;
- incompatible schema or algorithm versions fail closed rather than reinterpret bytes;
- local policy decides whether remote approvals, checks, packages, and identities are trusted.

## 7.13 Operator, control-plane, and key compromise

**Threats**

- administrator silently reads private code;
- operator changes retention, policy, or keys;
- control-plane bug affects all cells;
- signing key for capsules or releases is stolen;
- tenant encryption key is lost;
- emergency repair bypasses normal invariant checks.

**Required controls**

- least-privilege service identities and just-in-time operator elevation;
- separation of duties for high-impact hosted operations;
- immutable audit events for privileged access and configuration;
- tenant-managed keys where required, with explicit availability trade-offs;
- HSM/KMS-backed signing keys, rotation, revocation, and threshold options;
- cell isolation and staged rollout with bounded blast radius;
- break-glass tools produce a repair proposal and evidence bundle; canonical mutation still passes invariant checks;
- dual-control destructive lifecycle operations;
- reproducible infrastructure definitions and configuration provenance.

**Residual risk**

A fully compromised self-hosted root or managed control plane can deny service and may access data for which it holds decryption authority. FrankenGit’s goal is to minimize standing privilege and make misuse detectable, not to claim cryptographic protection from the entity that controls every key and binary.

## 7.14 Dependency, compiler, and release-channel compromise

**Threats**

- malicious crate or transitive update;
- compromised source repository or package registry;
- build script executes arbitrary code;
- compiler or linker injects behavior;
- release binary differs from reviewed source;
- update channel serves a malicious binary.

**Required controls**

- small, justified dependency universe for truth-plane crates;
- lockfiles, checksums, source provenance, and dependency marginal ledger;
- no new dependency without owner, threat analysis, license review, and removal plan;
- hermetic release builds with pinned toolchains;
- reproducible-build target and diverse rebuild verification for release artifacts;
- signed release manifests and update metadata with rollback protection;
- SBOM and vulnerability/advisory monitoring;
- named unsafe boundary crates only, each with an unsafe ledger and targeted tests;
- fuzzing, sanitizers, Miri or equivalent where applicable, and source review for parsers/crypto boundaries.

---

## 8. Cryptographic architecture

FrankenGit uses cryptography for distinct purposes that MUST NOT be conflated.

| Mechanism | Purpose |
|---|---|
| Git SHA-1/SHA-256 OID | Git compatibility and object identity within the selected Git format |
| BLAKE3 envelope/segment digest | fast exact integrity and FrankenGit content addressing |
| Merkle commitment | membership and complete-set commitment |
| Digital signature | actor, capsule, attestation, or federation authenticity |
| AEAD | confidentiality and integrity of encrypted payloads |
| HMAC/keyed digest | authenticated internal tokens or blinded identifiers |
| RaptorQ | erasure recovery, not authenticity or secrecy |
| e-process/e-value | sequential statistical evidence, not cryptographic proof |

Cryptographic algorithms and encodings are versioned and domain-separated. Verification APIs return typed outcomes that distinguish unknown algorithm, malformed encoding, invalid signature, wrong key epoch, digest mismatch, policy refusal, and unavailable key.

Key rotation must preserve the ability to validate historical events. Revocation semantics must define whether they invalidate past signatures, future signatures, or both. Repository export must not require FrankenGit private signing keys to preserve ordinary Git usability, though a capsule-verification export may include public key history and attestations.

---

## 9. Privacy and data minimization

- Canonical events store only fields needed for deterministic replay, accountability, and configured compliance.
- General analytics, ranking features, and model traces are derived data with independent retention.
- Private content is excluded from telemetry by default; digests used for metrics are keyed where raw content hashes would enable membership tests.
- Context Packets minimize disclosed content and include an authorization proof or reference appropriate to the deployment.
- User deletion and legal-hold semantics are explicit about immutable Git history, forks, caches, backups, audit requirements, and cryptographic erasure.
- Hosted service documentation must disclose whether operators can decrypt tenant content under each key-management profile.
- Training or external model use of repository content is opt-in and separately authorized. It cannot be inferred from permission to host or index a repository.

---

## 10. Security state machines

Security-critical workflows are explicit state machines rather than collections of booleans.

### 10.1 Object admission

`Received -> Quarantined -> Parsed -> IdentityVerified -> PolicyAccepted -> DurabilitySatisfied -> Admitted`

Any failure enters a typed terminal refusal. Cancellation before admission leaves no reachable object. Duplicate bytes may resolve idempotently to an existing admitted identity without repeating side effects.

### 10.2 Ref transaction

`Received -> Authenticated -> Authorized(policy_snapshot) -> ObjectsSatisfied -> CanonicalEffectsSealed -> Prepared(fence) -> RepositoryCommitRecorded -> CapsulePublished -> Acknowledged`

A timeout after `Committed` resolves by `RefTxnId`; it does not create an unknown outcome. A prepared transaction whose fence is stale cannot commit.

### 10.3 Agent Intent Run

`Draft -> Sponsored -> CapabilityIssued -> WorkspaceReady -> Running -> EvidenceSubmitted -> Verification -> PublicationDecision -> Quiescent`

`Cancelled`, `BudgetExhausted`, `Refused`, and `Failed` are terminal only after obligations are resolved or explicitly quarantined for operator action.

### 10.4 CI execution

`Admitted -> Planned -> InputsResolved -> Isolated -> Running -> OutputsSealed -> Attested -> Published`

Unattested outputs may be retained for debugging but cannot satisfy protected checks.

---

## 11. Detection, response, and statistical controls

Deterministic controls prevent known-invalid transitions. Detection systems look for failures and attacks that remain possible.

FrankenGit may maintain e-processes or other anytime-valid monitors for:

- ref-conflict and force-push regime shifts;
- object corruption, repair demand, or missing-symbol rates;
- authorization denials and token-replay patterns;
- runner escape indicators and cache divergence;
- secret-scanner hit-rate shifts;
- unusual clone, fetch, package, or artifact exfiltration volume;
- search quality, stale-index, or Context Packet omission rates;
- webhook and federation peer behavior;
- latency, error, and resource-regime changes after rollout.

Permitted automatic responses are bounded and reversible: reduce concurrency, disable a cache generation, increase verification sampling, quarantine a worker, stop a rollout, require stronger approval, or route to human review. Permanent identity sanctions, public accusations, irreversible history mutation, or deletion cannot be driven solely by a statistical score.

Every detector must declare:

- null and alternative interpretation;
- input provenance and delayed-label behavior;
- reset and regime-change policy;
- optional-stopping validity assumptions;
- action thresholds and maximum automatic action;
- appeal and operator override path;
- false-positive and false-negative evaluation.

---

## 12. Security verification program

No security claim advances beyond “proposed” without evidence in the project’s claim registry. Required lanes include:

1. **Parser and protocol fuzzing:** Git objects, packs, protocol v0/v1/v2, SSH commands, HTTP, Markdown, diffs, archives, packages, workflow syntax, federation envelopes.
2. **Differential testing:** compare ordinary Git behavior, object reachability, packs, refs, merge bases, signatures, and transport results across supported clients.
3. **Property and model testing:** `RefTxn` serializability, fencing, idempotency, capability attenuation, root-last commitment, deletion/retention safety.
4. **Deterministic distributed simulation:** crash, partition, reorder, duplication, stale reads, corrupt writes, clock jumps, cancellation, and retry at every yield point.
5. **Repair campaigns:** remove arbitrary source symbols, manifests, replicas, caches, nodes, and regions; prove exact reconstruction or typed unavailability.
6. **Isolation tests:** workspace path escape, symlink/hardlink/mount tricks, runner breakout, cross-tenant cache and memory reuse.
7. **Red-team agent suites:** prompt injection, secret requests, authority confusion, tool-output injection, recursive delegation, budget abuse, evidence fabrication.
8. **Cryptographic test vectors:** domain separation, algorithm agility, key rotation/revocation, signature and AEAD failure handling.
9. **Supply-chain gates:** dependency review, provenance, reproducible release comparison, SBOM, signed update path.
10. **External audit:** before production hosted availability and after material changes to truth-plane, identity, runner, key, or federation architecture.

See [VERIFY_SPEC.md](VERIFY_SPEC.md) for evidence levels and release gates.

---

## 13. Severity and response priorities

| Severity | Example | Required response |
|---|---|---|
| Critical | unauthorized canonical ref mutation; cross-tenant private-code disclosure; release-signing key compromise | contain immediately, stop affected mutations/distribution, preserve evidence, notify affected tenants under policy, rotate/recover, publish post-incident analysis |
| High | runner escape with credential access; policy bypass without known exploitation; capsule equivocation | quarantine affected domains, revoke capabilities, investigate full exposure window, repair and validate |
| Medium | bounded denial of service; stale derived index; repair redundancy below target | mitigate, measure affected SLO/claims, prevent recurrence |
| Low | defense-in-depth defect without reachable impact | track, test, and fix under normal release process |

Severity is based on demonstrated capability and blast radius, not on whether exploitation was intentional.

---

## 14. Disclosure and incident artifacts

The project should publish a security policy and private reporting channel before accepting production code. A security report should receive a stable identity, encrypted attachment path, and acknowledgement without forcing public issue disclosure.

For incidents, the evidence bundle should include, subject to confidentiality:

- affected tenant/repository/cell and time interval;
- exact capsule, event, policy, binary, and configuration identities;
- actor and capability history;
- detection and containment timeline;
- integrity and confidentiality impact;
- repair/reconstruction evidence;
- which architectural claim or test failed;
- permanent corrective action and new regression gate.

“Human error” is not a root cause. The analysis must identify why the system permitted one mistake to produce the observed impact.

---

## 15. Residual-risk register

The following risks remain material even under the proposed controls:

1. **Git compatibility complexity.** Git’s historical formats, client diversity, and implementation-defined edges create a large parser and semantic attack surface.
2. **Authorized malicious change.** Process and evidence reduce but do not eliminate harmful code accepted by legitimate policy.
3. **Legacy SHA-1 semantics.** Stronger envelopes improve integrity but do not change what old clients name.
4. **Execution isolation.** Running hostile build code remains a high-risk subsystem and may require platform-specific hardened boundaries.
5. **Agent semantic errors.** Capability enforcement limits authority, but reviewers and tests can still miss bad logic.
6. **Operator/key authority.** Whoever controls binaries and decryption keys retains substantial power.
7. **Novel protocol risk.** `RefTxn`, Repository Capsules, and repair integration require formalization, adversarial implementation review, and long fault campaigns before trust.
8. **Economic denial of service.** Correct bounded operations can still be costly at aggregate scale; pricing, quotas, and admission must evolve without harming availability.
9. **Federation trust ambiguity.** Signed remote events prove origin, not truth, quality, availability, or local acceptability.
10. **Statistical monitor misuse.** Operational pressure can tempt teams to promote anomaly scores into unreviewed security decisions; governance must prevent this drift.

---

## 16. Security definition of done for production v1

FrankenGit is not security-ready for production merely because it passes unit tests. Production v1 requires all of the following:

- truth-plane invariants at evidence level E4 or higher under [VERIFY_SPEC.md](VERIFY_SPEC.md);
- completed Git protocol/object conformance matrix for the advertised feature set;
- deterministic crash/partition/cancellation campaigns with no unresolved ambiguous outcomes;
- cross-tenant isolation campaign across storage, cache, index, runner, logs, and repair symbols;
- independent security review of `RefTxn`, capability, key, object-admission, renderer, and runner boundaries;
- signed, reproducible release pipeline with rollback protection;
- disaster recovery from canonical object fabric and capsules, not a privileged filesystem snapshot;
- tested key loss, key rotation, compromised-key, and break-glass procedures;
- incident response runbook and private disclosure channel;
- no critical or high-severity open finding without a documented, time-bounded exception accepted by the project owner;
- hosted-service claims precisely matching the tested deployment profile.

Until those conditions hold, security statements must remain scoped to the evidence actually produced.
