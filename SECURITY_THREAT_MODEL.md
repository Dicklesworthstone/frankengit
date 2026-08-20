# FrankenGit Security Threat Model

**Status:** architecture draft; no implementation or audit claim  
**Architecture version:** 3.0  
**Applies to:** embedded, self-hosted cluster, FrankenGit.com, agents, CI, federation, and release tooling

FrankenGit combines a source-of-truth service, identity/policy system, hostile-input protocol/parser stack, immutable storage fabric, build platform, graph/search engine, agent capability broker, and software release pipeline. The design assumes malformed bytes, malicious repositories, compromised collaborators, prompt-injected agents, hostile runners, faulty storage, stale caches, malicious repair symbols, operator mistakes, dependency/toolchain compromise, and remote-service failure will all occur.

Security cannot depend on one parser, local repository, cloud provider, model, graph, runner, operator, workflow badge, or decoder behaving perfectly.

## 1. Security objectives

### 1.1 Canonical integrity and non-equivocation

- A repository state is canonical only if reachable from the verified `RepositoryAuthorityHead` selected by an exact predecessor conditional replacement.
- One sealed logical transaction has at most one terminal decision.
- Ref and forge transitions belonging to one operation publish atomically in one RCR.
- No unpublished object, candidate batch, local row, cache, gossip message, or materialization may be reported as committed.
- Head predecessor/generation, decision sequence, repository sequence, and authenticated roots cannot roll back or fork silently.
- A higher acknowledged unresolved root fails closed rather than falling back quietly.

### 1.2 Git and immutable-byte integrity

- Native Git object identity and format are preserved exactly.
- SHA-1 and SHA-256 are separate typed domains.
- Pack/delta/DEFLATE/wire parsing is bounded and rejects ambiguity, overflow, recursion, expansion, and malformed structure.
- Internal objects, segments, manifests, evidence, generations, and capsules verify canonical identity/length/structure.
- Repair reproduces exact committed bytes or fails closed.

### 1.3 Authorization integrity

- Every authority attempt binds an authenticated principal snapshot and effective capability root.
- Capabilities are scoped by tenant/repository/ref/path/object/effect/secret/network/time/budget and revocable handle.
- Delegation can only narrow authority.
- Canonical policy uses one exact input root and does not consult mutable projections, wall clock, network calls, or unversioned model output.
- Stale/replayed/confused-deputy/cross-tenant capabilities fail deterministically.

### 1.4 Confidentiality and privacy

- Private source, refs, metadata, graph/search/vector data, context, logs, evidence, artifacts, repair symbols, and secrets remain inside authorization/encryption domains.
- Dedup, caches, timing, range requests, embeddings, and error messages do not become cross-tenant existence or membership oracles.
- Secrets are brokered, least privilege, short lived, redacted, and absent from prompts/context/logs unless explicitly authorized.
- Training/external model use is separate opt-in authority, never inferred from hosting or indexing permission.

### 1.5 Availability and bounded work

- Every untrusted parser/algorithm/protocol has CPU, memory, bytes, objects, recursion/depth, expansion, fanout, peers/paths, wall time, and output limits.
- Authority contention, ATP, graph/search expansion, TreeFS pages, CI, agent work, repair, GC, outbox, and release attempts are quota/budget governed.
- Cancellation has a route to quiescence or explicit containment failure; no orphan task/process/VM/tunnel/upload/secret/credential/obligation remains invisible.

### 1.6 Auditability and recoverability

- Seals, prepared evidence, decisions, RCRs, outbox, repairs, deletions, overrides, policy epochs, and releases emit immutable evidence.
- Replay completeness is explicit.
- Backups/capsules/restores use the same commitments as normal reads.
- Security incidents can reconstruct actor/capability/input/basis/decision/publication/effect history subject to confidentiality policy.

## 2. Explicit non-objectives

The architecture alone does not promise to:

- prevent an authorized maintainer from intentionally accepting malicious code;
- prove source correctness or vulnerability absence;
- protect plaintext after an authorized endpoint receives it;
- make a compromised endpoint or release host trustworthy;
- guarantee anonymity against operator/provider traffic analysis;
- recover keys destroyed without an authorized recovery policy;
- make legacy Git SHA-1 semantics disappear;
- infer malicious intent from anomaly scores;
- withstand an arbitrarily large upstream volumetric attack;
- turn signatures into proof of trustworthy code;
- turn memory-safe Rust into proof of correct logic, cryptography, or resource use.

Product and incident language must state these limits instead of hiding behind “immutable,” “verified,” “zero trust,” or “self-healing.”

## 3. Protected assets

| Asset | Compromise impact |
|---|---|
| Authority head/version tokens | forged, rolled-back, or equivocated repository truth |
| Seals/decisions/RCRs/batches | duplicate/lost/fabricated transaction outcomes |
| Git objects/refs/pack material | source/history corruption or malicious substitution |
| Forge events/projections | false approvals, PR/issue/release/policy history |
| Policy/capability/identity state | unauthorized access or confused deputy |
| Tenant encryption/signing keys | disclosure, forgery, or permanent loss |
| Object/segment manifests and placements | missing/corrupt/unrecoverable data or existence leakage |
| RaptorQ symbols/repair evidence | corruption amplification or stale resurrection |
| TreeFS workspaces/build inputs | path escape, source substitution, secret theft |
| Search/graph/vector/context generations | private-code leakage or stale/misleading decisions |
| Runner/build/release credentials | supply-chain compromise |
| Artifacts/packages/releases/SBOM/provenance | downstream dependency substitution |
| Audit/evidence/negative evidence | incident opacity or claim laundering |
| Local DSR manifests and release assets | malicious update distribution |
| Operator/admin configuration | systemic bypass or destructive outage |

## 4. Adversaries and assumed capabilities

### 4.1 External low-privilege attacker

Can create accounts/public repositories/forks/PRs/issues, invoke Git/API/webhook/package surfaces, send malformed streams, measure timing/cache behavior, and attempt resource exhaustion.

### 4.2 Malicious or compromised collaborator

May hold legitimate write/review/package/runner/admin capability. The system limits blast radius and preserves attribution but cannot prove an action explicitly allowed by policy is benevolent.

### 4.3 Compromised agent

May be prompt-injected, induced to request secrets/effects, fabricate evidence, recursively delegate, exceed budgets, or misunderstand base/identity. Model text is untrusted; only capabilities and receipts govern effects.

### 4.4 Malicious repository/artifact

May contain parser/decompression/delta bombs, path/symlink/submodule/case/Unicode tricks, huge graphs, active Markdown/SVG/images, hostile workflows/packages, generated files that manipulate reviewers, and content designed to poison context/embeddings.

### 4.5 Compromised runner/workspace/cache/materializer

May steal credentials, retain tenant data, fabricate checks, poison caches, serve stale/corrupt files, or tamper with artifacts. These workers are disposable and non-authoritative.

### 4.6 Faulty/malicious storage or network

May lose, corrupt, truncate, replay, delay, duplicate, reorder, ambiguously acknowledge, throttle, misroute across tenants/endpoints, or resurrect versioned/lifecycle objects. Gossip and listings may be incomplete or stale.

### 4.7 Malicious federation peer

May replay/equivocate, advertise unavailable/corrupt objects, withhold symbols, flood gossip, exploit schema skew, impersonate identities, or spam social state.

### 4.8 Operator/provider/toolchain attacker

May misuse privilege or compromise KMS, authority/object endpoints, compiler, dependency, build script, proc macro, local DSR host, SSH channel, installer, signing key, package registry, or release mirror.

## 5. Trust zones

1. Untrusted Internet/client edge.
2. Pure-Rust protocol termination and bounded decoding.
3. Authentication/capability issuance.
4. Canonical transaction/policy/reference model.
5. AuthorityStore client and repository head key.
6. Immutable object/segment/decision/evidence fabric.
7. Local FrankenSQLite projections/caches/materializers.
8. TreeFS workspaces and adapters.
9. Search/graph/document generation pipeline.
10. Agent context/effect broker.
11. CI runners/build hosts/package proxy.
12. Repair/checkpoint/GC/archive infrastructure.
13. Operator/key/billing/control plane.
14. Local DSR/signing/release distribution plane.
15. Federation peers and remote integrations.

Data crossing zones carries typed identity, authorization/confidentiality, integrity, budget, source position, and replay class where applicable.

## 6. Release-blocking security invariants

1. Only an exact-version conditional head replacement publishes repository state.
2. Head predecessor/generation and decision/RCR sequences cannot fork/rollback silently.
3. One seal identity cannot own two semantic requests or terminal outcomes.
4. Client cancellation/lost response cannot create duplicate or unknown canonical effects.
5. Policy basis and actor capability are immutable inputs to a decision.
6. No staged/quarantined bytes become canonical retention roots before commit.
7. No committed closure is absent from authenticated retention roots.
8. Pure-Rust production contains no foreign-Git/FFI/subprocess fallback or first-party unsafe.
9. Untrusted parsing/expansion is bounded before or during allocation/work.
10. Derived projections/graphs/models cannot grant authority or disclose beyond canonical authorization.
11. Repair verifies original commitments and current authority before placement publication.
12. GC cannot sweep authenticated or grace-period roots.
13. Agent/runner/workspace effects are capability-bounded and obligation-owned.
14. Secrets are non-ambient and revocable.
15. Generation/checkpoint/release root publication is anti-rollback and root-last.
16. Local signed release manifest, not hosted workflow/remote asset state, defines an official release.
17. Cross-tenant dedup/cache/search/repair cannot become an existence/disclosure oracle.
18. Admin overrides and break-glass actions are explicit immutable events with scope and evidence.

## 7. Threat analysis and required controls

### 7.1 Git object, pack, delta, and wire attacks

**Threats**

- integer overflow, malformed pkt-line/sideband/pack/trailer;
- DEFLATE bomb, delta cycle/depth/fanout/aggregate amplification;
- thin-pack base confusion or missing-object smuggling;
- tree ordering/mode/name/path edge cases;
- commit/tag header/encoding abuse;
- SHA-1 collision tricks and hash-format confusion;
- hidden-ref probing and capability downgrade;
- non-atomic/atomic push semantic confusion;
- resource exhaustion by object count/graph closure.

**Controls**

- clean-room pure-Rust codecs/state machines with checked arithmetic;
- quarantine before reachability/retention;
- declared byte/object/depth/fanout/work/memory/time limits;
- native typed hash domains and collision-defense profile;
- exact hidden-ref authorization and advertisement policy;
- protocol/service/capability matrix; no fictional protocol-v2 push assumption;
- fuzz/source-derived/adversarial differential corpus;
- no shell command/path construction from repository data.

### 7.2 Authority-head, retry, and stale-publication attacks

**Threats**

- forged/stale version token;
- ABA through byte-identical restored head;
- two contenders both believe they committed;
- ambiguous timeout after server-side CAS success;
- proxy/gateway caches stale head reads;
- lifecycle/versioning resurrects retired head;
- candidate batch/local row/gossip mistaken for canonical;
- idempotency-key reuse with different request;
- policy TOCTOU across retries.

**Controls**

- backend conformance for strong create/read/CAS and ABA-safe tokens;
- canonical predecessor-linked monotone head body;
- exact-key authority reads before sensitive operations;
- seal put-if-absent and immutable outcome index;
- lost-response resolution by rereading head/outcome;
- no local projection or notification authority;
- prepared-capsule witness revalidation and deterministic policy basis;
- fail closed on inconsistent authority responses.

### 7.3 Immutable storage attacks

**Threats**

- wrong tenant/object returned under valid locator;
- truncation/bit flip/range splicing;
- stale manifest/location/catalog;
- deletion/lifecycle/restore resurrection;
- untrusted endpoint/redirect;
- cross-tenant dedup existence oracle;
- encrypted object copied into wrong key domain;
- listing incompleteness causes recovery omission.

**Controls**

- verify exact identity/length/type/tenant/encryption on every read;
- follow known authenticated roots, never listing for correctness;
- minimal owned storage adapters and endpoint allowlists;
- separate logical identity from mutable placement records;
- tenant-scoped dedup/encryption by default;
- lifecycle/versioning conformance and tombstone evidence;
- obligations for replication/archive/repair debt;
- independent archive profiles for high-value data.

### 7.4 Materialization and TreeFS attacks

**Threats**

- poisoned bare repository/pack/index/cache;
- stale materialization served as current;
- path traversal, symlink/hardlink/mount escape;
- case-folding/Unicode normalization collision;
- submodule or archive escape;
- workspace overlay leaks across run/tenant;
- local file existence mistaken for publication;
- cancelled tool leaves output/credential/process.

**Controls**

- immutable source receipts and currentness modes;
- quarantine/rebuild corrupt derived state;
- descriptor-relative path capabilities and platform profiles;
- explicit symlink/submodule/case/Unicode rules;
- isolated overlay/cache namespaces;
- semantic intents/export; local files have no authority;
- staged/visible/durable output epochs;
- Asupersync obligation/quiescence checks and forced containment.

### 7.5 Authentication, capability, and confused-deputy attacks

**Threats**

- token substitution across tenant/repo/ref/effect;
- delegation widens scope;
- stale revocation/expiry;
- service or agent uses sponsor/admin ambient token;
- weak auth used for high-impact override;
- replayed signed request;
- capability serialized into logs/context/cache.

**Controls**

- typed audience/scope/operation/budget/expiry/revocation handles;
- delegation attenuation proof;
- principal/auth-strength snapshot in canonical policy input;
- brokered secrets/effects; no ambient sponsor token/cloud metadata;
- idempotency/nonces according to protocol;
- redaction and secret-taint tests;
- high-impact dual/independent approval policy and immutable overrides.

### 7.6 Agent prompt injection and tool abuse

**Threats**

- repository/web/package text instructs secret disclosure or capability widening;
- tool output injects commands/evidence;
- agent edits policy/workflow/security files outside intent;
- recursive agents exceed budget or evade verifier independence;
- fabricated test/review/explanation;
- context retrieval leaks inaccessible neighbors/embeddings.

**Controls**

- text/data structurally separated from capability/control channels;
- exact Intent Run and non-textual effect broker;
- path/effect/secret/network/budget scopes;
- Context Packets with authorization, provenance, transforms, omissions;
- Evidence-Carrying Change with tool/effect/check receipts;
- verifier independence classification/enforcement;
- sensitive-file policy and explicit publication review;
- red-team prompt/tool/context suites;
- canonical revalidation of any agent proposal.

### 7.7 CI runner, workflow, cache, and supply-chain execution attacks

**Threats**

- runner/VM escape or cloud-metadata access;
- fork obtains protected secrets;
- cache poisoning across trust domains;
- workflow expression/injection or incompatible lowering;
- fabricated green check/artifact/log;
- orphan process/tunnel/credential after cancellation;
- package proxy/dependency substitution;
- malicious artifact published as release.

**Controls**

- immutable BuildInputCapsule and pinned runner image/toolchain;
- VM/sandbox profile, no metadata, explicit egress/proxy;
- short-lived brokered secrets under fork/trust policy;
- immutable trust-domain cache keys and verification;
- typed workflow lowering and unsupported-expression refusal;
- check/artifact receipts with source/toolchain/host/output/resource identity;
- cancellation/reaping/containment campaign;
- artifact/provenance/signature policy before canonical check/publication.

### 7.8 ATP-Git and peer/cache attacks

**Threats**

- false have summary causes missing bytes;
- malicious delta basis or reconstruction map;
- path/relay/tunnel privacy downgrade;
- peer lies about pieces/availability or sends corrupt data;
- swarm amplification/endgame DoS;
- trust-scoped cache poisoning;
- adaptive controller chooses unsafe overhead/path;
- RaptorQ decoder bomb.

**Controls**

- final closure and native object identity verification;
- authenticated profile/manifest/basis identity;
- typed path security/privacy/budget constraints;
- bounded paths/peers/pieces/duplicates/memory/work;
- peer/cache trust ledgers and quarantine;
- deterministic fallback to ordinary transfer;
- identity-bound policy/regime/hard floors/ceilings;
- original commitment verification and decoder limits;
- loser cancellation/drain obligations.

### 7.9 Webhooks, integrations, imports, and SSRF

**Threats**

- callback reaches loopback/private/link-local/metadata/admin endpoints;
- DNS rebinding/redirect/IPv6 encoding bypass;
- signature/replay/confused tenant;
- unbounded retries/fanout/payload;
- imported forge state bypasses policy or drops semantics;
- integration token overbroad or leaked.

**Controls**

- URL canonicalization, DNS/IP revalidation, redirect caps, restricted-range policy;
- signed stable delivery IDs, timestamps/nonces, at-least-once idempotency;
- egress capabilities and network budgets;
- bounded queues/backoff/dead letter/evidence;
- migration adapters produce explicit unsupported/loss reports;
- narrow integration tokens and immutable audit.

### 7.10 Markdown, diff, image, SVG, and document attacks

**Threats**

- script/active content/XSS;
- malicious links/images/data URIs/remote fetch;
- parser/layout/font/image/decompression resource exhaustion;
- source-span/review-anchor misattachment;
- renderer differs across human/API/agent surfaces;
- generated content hides security-relevant text.

**Controls**

- one safe source-spanned AST lineage;
- raw active content escaped/disabled by default;
- host-brokered remote assets and policy;
- strict bytes/nesting/table/code/font/image/layout/output budgets;
- deterministic rendering/goldens;
- exact/remapped/ambiguous/outdated review-anchor states;
- no renderer/network/file ambient authority.

### 7.11 Search, graph, vector, and Context Packet attacks

**Threats**

- unauthorized content leaks through snippet/embedding/neighbor/aggregate;
- mixed or stale generation influences security decision;
- graph edge/model hallucination treated as exact;
- adversarial repository poisons ranking/context;
- query fanout/graph traversal DoS;
- cache/view revision confusion;
- tie-break nondeterminism changes reviewer/context choice.

**Controls**

- authorization before candidate disclosure and inherited labels;
- immutable predecessor-linked anti-rollback generations;
- query pins one generation vector;
- exact/deterministic/statistical edge types;
- canonical revalidation for authority-sensitive operations;
- bounded candidate/fanout/depth/token budgets;
- closed tie-break policy and decision-path/complexity witness;
- source spans/provenance/omissions in Context Packets;
- deterministic fallback when models unavailable.

### 7.12 RaptorQ, repair, checkpoint, and GC attacks

**Threats**

- wrong-source/malicious/stale symbols;
- decoder resource attack;
- valid old bytes overwrite newer placement;
- repair resurrects deleted/expired data;
- scrub/repair loop causes DoS;
- capsule/checkpoint signature or root rollback;
- GC omits PR/legal-hold/migration/backup/in-flight root;
- approximate filter false negative authorizes deletion.

**Controls**

- authenticated source/profile/symbol identity and strict decoder budgets;
- verify all original commitments/codec/tenant;
- reread authority/retention before placement commit;
- repair as normal authority-governed effect with obligation/evidence;
- rate/debt/governor/kill switch;
- body-first/root-last and highest-ack anti-rollback;
- root registry, exact reachability, tombstone/grace/revalidation;
- model/property/fault/clean-restore campaigns;
- approximate structures only as accelerators.

### 7.13 Federation and local-first attacks

**Threats**

- signed peer equivocation/replay/key rollback;
- CRDT last-writer-wins applied to protected refs;
- spam/moderation abuse;
- remote object advertisement without availability;
- offline proposal assumes stale policy/base still valid;
- schema skew or unknown required event.

**Controls**

- signed key history, domain/version/sequence, equivocation evidence;
- operation-class CALM registry; protected refs remain local coordinated admission;
- observations/proposals/mirror namespaces rather than remote authority;
- local policy/moderation and rate limits;
- availability/repair evidence distinct from identity;
- offline bundle revalidation against current head/policy;
- unknown required version fails closed.

### 7.14 Operator, key, dependency, and release compromise

**Threats**

- admin edits local repository/SQLite/bucket/root manually;
- signing/KMS/release key stolen;
- dependency/compiler/build script/proc macro compromised;
- local DSR host/SSH route/source checkout tampered;
- partial/mismatched assets uploaded;
- GitHub account or release page altered;
- rollback to vulnerable binary/toolchain/configuration.

**Controls**

- all supported mutation/repair/migration through typed protocols;
- break-glass capabilities, dual control where policy, immutable audit;
- key purpose separation, rotation/revocation/threshold/archive recovery;
- closed dependency registry, one lock/constellation, transitive unsafe/build evidence;
- dated nightly and intentional advancement;
- DSR exact source/host/toolchain/target attempt identities;
- exact asset allowlist/checksums/SBOM/provenance/signatures/installer smoke;
- local signed release manifest published last;
- remote mirror reconciliation and update anti-rollback;
- independent rebuild/verification for high assurance.

## 8. Cryptographic architecture

- Native Git identity uses repository hash format exactly.
- Internal IDs are domain-separated, versioned, algorithm-typed canonical digests.
- Signatures bind unsigned logical bodies; mutable placement/acknowledgements do not create circular identity.
- AEAD/envelope encryption binds tenant/repository/object class/key purpose/version.
- TLS/authenticated transport uses approved pure-Rust Asupersync/Rust ecosystem primitives under dependency policy.
- Keys are separated for identity, authority/admin, capsule, evidence, package/release, webhook, tenant encryption, and recovery.
- Rotation/revocation/mixed-version/algorithm deprecation are explicit formats and tested state machines.
- Fundamental pure-Rust crypto dependencies are preferred over bespoke unreviewed primitive implementation.

Content address proves byte identity, not authorship; signature proves key use, not benevolence; encryption does not replace authorization or deletion evidence.

## 9. Privacy and data minimization

- Tenant/repository/security/encryption/dedup domains are explicit.
- Private content is excluded from telemetry by default; keyed digests replace raw content hashes when membership tests matter.
- Context Packets minimize disclosed content and record authorization/omissions.
- Logs/evidence use structured redaction and tenant-controlled encryption/selective disclosure.
- Cross-tenant physical dedup is initially disfavored.
- Deletion language distinguishes logical invisibility, grace/tombstone, physical placements, backups/repair material, and cryptographic erasure.
- Hosted documentation discloses operator decryption capability per key profile.

## 10. Security-critical state machines

### 10.1 Object admission

```text
Received -> Quarantined -> BoundedParsed -> NativeIdentityVerified
         -> Closure/PolicyAccepted -> Staged -> Visible -> DurabilitySatisfied
```

Failures are typed. Duplicate exact identity is idempotent. Staging does not imply visibility.

### 10.2 Repository mutation

```text
Received -> Authenticated -> Canonicalized -> Sealed
         -> BasisRead -> Prepared -> Batched -> CASAttempted
         -> Committed | Refused | RetrySameSeal
         -> Outbox/MaterializationDrain -> Response
```

Ambiguous response resolves through authority/outcome lookup.

### 10.3 Agent Intent Run

```text
Draft -> Sponsored -> CapabilitiesIssued -> Context/TreeFSReady -> Running
      -> EvidenceSubmitted -> Verification -> PublicationDecision
      -> Quiescent | ContainedFailure
```

Cancel/budget/refusal do not become terminal until obligations resolve or containment is explicit.

### 10.4 CI job

```text
Admitted -> BuildInputCapsuleVerified -> Isolated -> Running
         -> OutputsSealed -> Attested -> PolicyAccepted -> Published
         -> Quiescent
```

Unattested/debug outputs cannot satisfy protected checks.

### 10.5 Repair

```text
Detected -> Quarantined -> SymbolsGathered -> Decoded -> CommitmentsVerified
         -> Authority/RetentionRevalidated -> PlacementCommitted | Discarded
         -> Attested
```

### 10.6 Release

```text
RunCreated -> TargetAttempts -> AssetsVerified -> Tests/Smoke/SBOM/Signatures
           -> CompleteMatrix -> LocalManifestSigned/Published
           -> RemoteMirrorsReconciled
```

No complete matrix means no authoritative release.

## 11. Detection and adaptive controls

E-processes/conformal/change-point/no-regret systems may monitor authorization denials/replays, force/ref conflict regimes, corruption/repair demand, cache/generation divergence, runner indicators, secret scanning, exfiltration volume, webhook/federation behavior, and rollout/resource regimes.

Automatic actions are bounded/reversible: reduce budgets/concurrency, disable/quarantine cache or worker, stop rollout, increase sampling, require stronger review, or route to human incident handling.

Every detector binds population/selection/window/regime/candidate/fallback/assumptions and maximum action. It cannot solely drive permanent identity sanction, public accusation, history mutation, deletion, access grant, or billing.

## 12. Security verification program

Required lanes include:

1. constitutional dependency/unsafe/FFI/subprocess/runtime scans;
2. Git/object/pack/wire/archive/document/workflow/package/webhook fuzzing and resource tests;
3. authority/seal/outcome/head/CAS model and fault tests;
4. differential Git and declared API/workflow compatibility;
5. deterministic distributed/concurrency/cancellation/obligation simulation;
6. storage corruption/endpoint/tenant/lifecycle/anti-rollback campaigns;
7. TreeFS path/adapter/workspace isolation and materialization poisoning;
8. ATP peer/path/cache/swarm/adaptive/decoder adversarial suites;
9. repair/GC/checkpoint/restore and legal-hold races;
10. agent prompt/tool/context/secret/capability/verifier red teams;
11. runner escape/cache/fork-secret/egress/orphan campaigns;
12. search/graph authorization, generation, tie-break, poisoning, and fanout tests;
13. cryptographic vector/domain/key rotation/revocation failure tests;
14. DSR host/source/SSH/asset/signature/SBOM/remote-reconciliation attacks;
15. independent review before hosted production and after authority/key/runner/federation changes.

See [`VERIFY_SPEC.md`](VERIFY_SPEC.md).

## 13. Severity and response

| Severity | Examples | Response |
|---|---|---|
| Critical | unauthorized head/ref mutation; cross-tenant private-code disclosure; release-signing/manifest compromise | stop affected publication/distribution, revoke/contain, preserve evidence, rotate/recover, notify under policy, public post-incident scope |
| High | runner escape with credential access; authority rollback ambiguity; policy bypass; capsule equivocation | quarantine domains, revoke capabilities, determine full exposure window, repair/restore/validate |
| Medium | bounded DoS; stale derived generation; durability below target without canonical loss | mitigate, narrow affected claims/SLO, clear debt, add regression |
| Low | unreachable defense-in-depth defect | track and fix through normal evidence gates |

Severity follows demonstrated capability/blast radius, not intent.

## 14. Incident evidence and disclosure

A private reporting channel and stable encrypted evidence identity are required before production code. Incident packs include, subject to confidentiality:

- affected namespaces/cells/backends/hosts/time/sequence window;
- exact head/RCR/capsule/policy/configuration/binary/toolchain/dependency identities;
- actor/capability/secret/effect history;
- detection, containment, repair, restore, and release timeline;
- integrity/confidentiality/availability/claim impact;
- replay completeness and missing artifact classes;
- failed invariant/control/test assumption;
- permanent fix, negative evidence, and new release gate.

“Human error” is not a root cause; the analysis identifies why one mistake had that effect.

## 15. Residual risks

1. Full Git compatibility is a large semantic/parser surface.
2. Authorized malicious changes remain possible.
3. Legacy SHA-1 names remain legacy SHA-1 names.
4. Host OS/hypervisor runner isolation is platform-specific and high risk.
5. Agents/verifiers/tests can agree on wrong logic within their authority.
6. Key/operator/binary control remains powerful despite audit/attenuation.
7. New decision/ATP/TreeFS/repair protocols require long adversarial maturation.
8. Aggregate economic denial of service can remain costly despite bounded operations.
9. Signed federation proves origin, not truth or availability.
10. Statistical governance can drift toward overreach under operational pressure.
11. First-party safe Rust does not audit all transitive dependency unsafe or compiler defects.
12. Object-store CAS guarantees can be invalidated by undocumented provider/gateway changes; continuous conformance is required.

## 16. Security definition of done for production v1

Production v1 requires:

- release-blocking authority/transaction/repair/GC/capability invariants at E4 or stronger where specified;
- declared pure-Rust Git conformance and hostile resource matrix;
- no first-party unsafe/FFI/foreign-Git/runtime/dependency violation;
- deterministic crash/partition/retry/cancel/obligation campaigns with no ambiguous canonical outcomes;
- cross-tenant storage/cache/index/context/runner/log/repair isolation campaign;
- independent review of authority, Git codec, capability, TreeFS, runner, key, repair/GC, and release boundaries;
- signed root-last local DSR release with rollback/reconciliation protection;
- clean independent capsule/object-fabric restore and measured scoped RPO/RTO;
- tested key loss/rotation/compromise/break-glass and incident response;
- no unbounded critical/high finding without explicit time-bounded owner exception and claim demotion;
- product/security wording matching the exact tested deployment profile.

Until then, security statements remain architecture proposals or scoped evidence claims.
