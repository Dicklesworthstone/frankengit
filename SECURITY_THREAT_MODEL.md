# FrankenGit Security Threat Model

**Status:** Pre-implementation architecture threat model  
**Canonical semantics:** [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md)

A security control that depends on a projection, materialization, search result, model output, or statistical alarm must revalidate against canonical state before authorizing an effect.

## 1. Security objectives

FrankenGit must protect:

- confidentiality of private repositories, hidden refs, issues, artifacts, packages, logs, secrets, and agent context;
- integrity and ordering of Git refs, canonical forge events, policies, outcomes, retention roots, and audit evidence;
- availability under malicious Git clients, oversized repositories, agent swarms, runner abuse, and infrastructure failures;
- tenant isolation in storage, caches, search/graph, CI, billing, support, and repair;
- provenance of commits, checks, artifacts, packages, releases, agent effects, and administrator overrides;
- recoverability without accepting forged/corrupt reconstructed bytes;
- truthful deletion/retention behavior;
- deterministic and inspectable authorization decisions.

## 2. Explicit non-objectives and non-claims

The architecture does not claim that:

- content addressing proves authorship or safety;
- signed commits/tags make their content trustworthy;
- object-store durability proves end-to-end restoration;
- RaptorQ supplies cryptographic integrity, consensus, freshness, or authorization;
- deterministic replay reproduces external effects that were not recorded/modeled;
- a green CI check proves code is safe outside the named environment/check;
- an LLM explanation or confidence score is security evidence;
- branch protection prevents a compromised administrator/control plane from using bypass powers;
- public source under the current rider is OSI open source.

## 3. Assets

### Canonical assets

- native Git objects and their typed OIDs;
- sealed mutation requests and terminal outcomes;
- RCR chain, head pointer, writer epochs;
- ref/forge/object/policy/retention roots;
- canonical forge events;
- policy and membership state;
- legal holds/deletion state;
- transactional outbox;
- capsule/backup manifests and keys;
- audit/override evidence.

### Sensitive derived assets

- bare repositories and packs;
- search/vector/graph generations;
- web projections and notifications;
- Context Packets and workspaces;
- CI logs/artifacts/caches;
- LFS/package/release bytes;
- billing/usage/support data;
- operational telemetry.

### Secrets and credentials

- user sessions, SSH keys, PATs, OAuth/OIDC tokens;
- service and repository writer credentials;
- signing keys, KMS/DEK/KEK material;
- webhook secrets;
- CI/deployment secrets;
- agent effect capability tokens;
- backup/replication credentials.

## 4. Threat actors

- unauthenticated Internet attacker;
- authenticated low-privilege user;
- malicious repository collaborator;
- compromised user/agent token;
- malicious fork/PR contributor;
- prompt-injected repository/external content;
- malicious package/artifact/import producer;
- compromised CI job or runner image;
- tenant attempting cross-tenant access/resource theft;
- malicious/compromised operator or support account;
- stale/partitioned infrastructure node;
- compromised object store, cache, mirror, or repair-symbol source;
- dependency/supply-chain attacker;
- external service receiving webhooks/effects;
- accidental administrator or software bug.

## 5. Trust boundaries

1. Internet ↔ SSH/smart-HTTP/API gateway.
2. Gateway ↔ authentication/capability service.
3. Git protocol parsing/quarantine ↔ canonical mutation kernel.
4. Mutation kernel ↔ transactional metadata substrate.
5. Mutation kernel ↔ immutable object/event storage.
6. Canonical truth ↔ materializers and caches.
7. Canonical events ↔ projections/search/graph.
8. Forge ↔ CI runners and package/build network.
9. Agent harness/workspace ↔ capability/effect broker.
10. Service ↔ secret/KMS/signing systems.
11. Service ↔ webhook/import/export/external APIs.
12. Primary service ↔ backup/replication/repair infrastructure.
13. Tenant data plane ↔ operator/support/admin plane.
14. Hosted control plane ↔ billing/abuse systems.

Every crossing has typed authentication, authorization, input limits, versioning, observability, and failure behavior.

## 6. Canonical transaction threats

### T-CAN-1 Duplicate mutation through retry

**Attack/failure:** response is lost; client retries; two commits occur.

**Controls:** one canonical `TxId`; durable seal; compare-and-set terminal outcome; outcome lookup; idempotent immutable staging/outbox delivery IDs.

**Evidence:** concurrent duplicate histories, crash/lost-response matrix, linearizability checker.

### T-CAN-2 Idempotency-key confusion

**Attack:** reuse same key with different request body to retrieve/overwrite another outcome.

**Controls:** TxId/request seal binds canonical request digest and authenticated principal/repository; mismatch typed refusal.

### T-CAN-3 Stale writer publication

**Attack/failure:** partitioned old leader continues committing.

**Controls:** consensus/lease-backed repository epoch; every metadata commit compares current epoch; failover advances epoch; object staging has no canonical authority.

### T-CAN-4 Mixed-snapshot policy TOCTOU

**Attack:** protection/review/status/membership changes while push/merge policy reads inconsistent projections.

**Controls:** one pinned canonical repository snapshot; deterministic policy input root; serializable compare-and-commit; retry/refuse on drift.

### T-CAN-5 Ref/forge split commit

**Failure:** branch moves without PR merge event, or UI merge event without branch move.

**Controls:** one RCR binds both roots/event batch; one metadata linearization point; projections derive afterward.

### T-CAN-6 Cancellation ambiguity

**Attack/failure:** client sees cancellation and assumes no commit, then performs conflicting action.

**Controls:** post-seal cancellation cannot claim non-commit; query `TxnOutcomeRecord`; response status distinguishes local cancellation from canonical outcome.

### T-CAN-7 Outcome overwrite/fork

**Attack:** compromised node writes conflicting committed/refused outcome.

**Controls:** linearizable absent→one CAS, immutable record identity, RCR existence/TxId binding, audit alarm; metadata consensus/fencing.

## 7. Git protocol/object threats

### T-GIT-1 Pack/decompression/delta bomb

**Controls:** request/pack/object/expanded byte ceilings; compression ratio; delta depth/fan-out/aggregate work; reserved memory/CPU; cancellation checkpoints; tenant concurrency quotas; parser fuzzing.

### T-GIT-2 Malformed object/path confusion

Trees can contain dangerous names/modes/bytes; archives/checkouts can traverse via symlink or normalization mismatch.

**Controls:** exact Git parsing; typed raw names; no unsafe path materialization; descriptor-relative access; checkout/archive policy for absolute, `..`, NUL, reserved Windows names, Unicode/case collisions, symlink/hardlink/submodule semantics.

### T-GIT-3 Hidden/private ref disclosure

**Controls:** advertisement authorization before names/OIDs; no shared cache key lacking tenant/auth scope; reachability checks for wants; negative tests for OID guessing; projection/search authorization.

### T-GIT-4 SHA/type confusion and collision

**Controls:** typed `(algorithm,digest)`; repository-format binding; stronger internal envelope digest/length/type; explicit collision-defense policy; no silent translation.

### T-GIT-5 Quarantine escape

**Attack:** uploaded object becomes reachable/retained before policy/ref commit.

**Controls:** transaction namespace; no canonical location/retention root until RCR; promotion by verified identity; orphan expiry; object store credentials scoped to staging paths where possible.

### T-GIT-6 Signed-object overtrust

**Controls:** signature verification produces evidence with key/trust/policy epoch; signatures never bypass content/policy/check requirements automatically.

### T-GIT-7 Partial-clone promisor abuse

**Controls:** authenticated typed promises; canonical retention still complete; lazy fetch authorization; filter/work bounds; no client promise treated as durable source.

## 8. Authentication, authorization, and capability threats

### T-AUTH-1 Token audience/scope confusion

**Controls:** audience, tenant, repository, run, effect, expiry, nonce/session binding as appropriate; short-lived tokens; revocation; no bearer reuse across services.

### T-AUTH-2 Privilege escalation through delegation

**Controls:** attenuation-only capability algebra; sponsor-authorized amendment for widening; machine-checkable subset relation; immutable delegation receipts.

### T-AUTH-3 Stale membership/protection projection

**Controls:** canonical snapshot for commit policy; read projections display freshness; security-sensitive reads revalidate.

### T-AUTH-4 Administrator bypass abuse

**Controls:** least privilege; step-up auth; explicit reason/ticket; immutable override event/evidence; dual control for high-risk actions; alerting; no audit deletion by same action.

### T-AUTH-5 SSH command injection

**Controls:** fixed command parser; repository ID lookup rather than shell path concatenation; no shell evaluation; strict key/principal mapping; environment allowlist.

## 9. Agent threats

### T-AG-1 Prompt injection

Repository files/issues/logs/web content instruct agent to reveal secrets or perform effects.

**Controls:** untrusted provenance labels; system/sponsor policy outside writable context; effects behind non-textual capabilities; secret handles not bytes; approval/evidence requirements immutable within run.

### T-AG-2 Ambient sponsor authority

**Controls:** never mount sponsor token; mint attenuated run/effect credentials; hard budgets; separate read/write/secret/network capabilities.

### T-AG-3 Context leakage

**Controls:** authorization before retrieval/embedding/snippet; tenant-scoped caches/indexes; Context Packet source labels; no inaccessible neighbor expansion; audit query/result identities.

### T-AG-4 Orphan task/credential

**Controls:** structured-concurrency ownership; cancellation drain/finalize; process/network cleanup; token expiry/revocation; workspace destruction/retention scrubbing; invariant probes.

### T-AG-5 Self-review laundering

**Controls:** verifier independence dimensions enforced by policy; separate clean workspace/credentials/context/oracle; proposer cannot self-assert class.

### T-AG-6 Effect duplication

**Controls:** stable effect idempotency keys, reservations, receipts, terminal lookup, transactional outbox for forge effects.

### T-AG-7 Agent-generated evidence forgery

**Controls:** broker/runner signs or content-addresses receipts; executable/input/environment binding; narrative separate; failed/skipped states immutable.

## 10. CI runner threats

### T-CI-1 Sandbox escape/host compromise

**Controls:** strong VM/microVM/container boundary selected by threat model; no privileged sockets/devices; patched minimal images; per-job identity; egress restrictions; host rotation; red-team tests.

### T-CI-2 Secret theft from untrusted fork

**Controls:** trust classification; no privileged secrets by default; explicit environment approval; secret broker/audience; output redaction; protected deployment rules.

### T-CI-3 Cache poisoning

**Controls:** trust-domain/tenant/repository/toolchain/source keyed caches; immutable content digest; writers/readers separated; untrusted cache not promoted to trusted; provenance.

### T-CI-4 Forged check status

**Controls:** check receipt signed/bound to exact RCR/object closure, runner/image/toolchain/policy; canonical policy validates receipt issuer/class/currentness.

### T-CI-5 Artifact/log active content/path attack

**Controls:** inert storage, safe rendering/download headers, archive path validation, size/decompression limits, redaction, malware policy hooks.

### T-CI-6 Orphan workload/crypto mining

**Controls:** hard CPU/memory/disk/network/time budgets; process-tree/cgroup/VM teardown; cancellation acknowledgement; host-level watchdog; billing anomaly review.

## 11. Web, rendering, import, webhook threats

### T-WEB-1 XSS/active Markdown/SVG

**Controls:** safe Markdown AST/rendering; raw HTML policy; URL sanitization; SVG sanitization or rasterization; CSP; separate origins for untrusted content; download disposition.

### T-WEB-2 CSRF/session fixation/open redirect

**Controls:** SameSite/CSRF tokens, origin checks, session rotation, allowlisted return targets, step-up auth.

### T-WEB-3 SSRF via webhooks/import/avatar/remote image

**Controls:** scheme/port policy; DNS resolution and IP-range checks before each connection/redirect; block metadata/private/control networks; proxy with egress ACL; response size/time limits; no credential forwarding.

### T-WEB-4 Webhook replay/forgery

**Controls:** per-hook secret/signature, timestamp/delivery ID, retries with same ID, rotation, TLS, audit; consumers advised idempotency.

### T-WEB-5 Import archive/path/credential leak

**Controls:** streaming limits; archive traversal/symlink checks; separate quarantine; remote URL credential stripping; explicit private-source auth; importer process isolation; canonical validation before publication.

## 12. Storage, repair, backup, and deletion threats

### T-STO-1 Object substitution/corruption

**Controls:** verify typed digest/length/codec on read and before canonical use; encrypted/authenticated transport/storage as policy; scrub; independent replicas/repair symbols.

### T-STO-2 Malicious RaptorQ symbols

**Controls:** authenticated envelope/source ID/profile; symbol dedup/limits; quarantine decode; original digest/Merkle/Git/codec verification; no mutable metadata dependence.

### T-STO-3 False placement durability

**Controls:** failure-domain-aware policy; attested placement receipts; independent probes; restore drills; no durability claim from raw replica/symbol count.

### T-STO-4 Capsule rollback/fork

**Controls:** exact repository/RCR/epoch binding; trusted key/registry policy; head/sequence comparison; old capsule labeled historical; signatures outside stable ID; root-last pointer.

### T-STO-5 Backup exfiltration

**Controls:** separate credentials/accounts, encryption, access logs, least privilege, offline/immutable options, restore access controls, secret/key handling, retention/deletion policy.

### T-STO-6 GC root omission

**Controls:** authenticated root catalog; reference and incremental reachability equivalence; legal holds/PR/queue/release/artifact/backup/migration roots; grace/revalidation; property/fault tests.

### T-STO-7 Misleading deletion

**Controls:** user/API states for logical hidden, queued, swept primary, backup expiry, crypto erasure; evidence and policy; no instantaneous claim when backups/replicas persist.

## 13. Search/graph/projection threats

### T-PROJ-1 Stale authorization

**Controls:** position receipts; canonical revalidation for effect; security-sensitive permission change invalidation; fail closed where freshness bound exceeded.

### T-PROJ-2 Cross-tenant embedding/snippet leak

**Controls:** tenant/security-domain partitioning; authorization-aware indexing; no global ANN graph exposing neighbors; deletion/revocation propagation tests.

### T-PROJ-3 Poisoned ranking/context

**Controls:** provenance/explanations; diverse lexical/semantic signals; prompt-injection labels; budgets; no ranking-based authority; abuse detection only reversible.

### T-PROJ-4 Malformed code parser exhaustion

**Controls:** parser isolation, byte/depth/time limits, fallback plain text, fuzzing, cancellation.

## 14. Package, LFS, release, and artifact threats

- digest confusion/media-type mismatch;
- mutable tag/version overwrite;
- typosquatting/dependency confusion;
- malware/provenance forgery;
- quota bypass/dedup side channels;
- cross-tenant object access;
- retention/GC root loss;
- oversized/range/decompression abuse.

Controls include native typed digests, immutable blob storage, evented tag/version policy, namespace authorization, quotas, provenance/signature evidence, package proxy policy, optional review/scanning, tenant-safe dedup, and complete retention roots.

## 15. Multi-tenant and economic abuse threats

### T-TEN-1 Cross-tenant access

Every key/cache/index/artifact/effect includes tenant/security domain. Negative tests attempt ID guessing, shared digest access, cache side channels, search leakage, billing/support/admin confusion, and restore mix-up.

### T-TEN-2 Noisy neighbor/resource exhaustion

Hierarchical reservations/quotas for ingress, pack validation, metadata, object bytes, egress, materialization, search, CI, agents, repair, and webhooks. Fair queues and load shedding preserve canonical metadata/recovery operations.

### T-TEN-3 Billing manipulation

Transactional usage records tied to operation/outbox identities; reconciliation; duplicate suppression; signed meter configuration; disputes expose evidence. Statistical estimates do not directly charge.

### T-TEN-4 Abuse/spam/malware

Rate/reputation/review systems may throttle/quarantine reversibly; appeals/admin evidence; public hosting policy; no irreversible accusation from one model/detector.

## 16. Supply-chain threats

- compromised dependencies/toolchains/actions/images/models;
- tag moving in CI;
- malicious build scripts/proc macros;
- unsigned release artifacts;
- dependency license conflict;
- model artifact substitution.

Controls:

- exact lockfiles and immutable Git/Action/image/model pins;
- checksum/signature/provenance manifests;
- dependency allow/deny/advisory/license gates;
- minimal dependencies and feature graphs;
- reproducible/independent release builds where feasible;
- SBOM and source/toolchain identity;
- no network in canonical builds unless explicitly provisioned;
- protected release signing and key rotation;
- scalar/reference implementations for critical optimized paths.

## 17. Operator and insider threats

- unauthorized data access/support tooling;
- policy/retention override;
- key theft;
- audit suppression;
- destructive migration/restore;
- covert cross-tenant query;
- emergency bypass abuse.

Controls: least privilege, just-in-time access, dual control, step-up auth, immutable audit, query purpose/ticket, customer-visible logs where appropriate, separation of duties, key isolation, canary/honey access, periodic access review, and break-glass expiry.

The architecture cannot fully prevent a sufficiently privileged owner from changing code/policy; it can make privileged actions explicit, attributable, and harder to conceal.

## 18. Availability threats

Prioritize canonical mutation/outcome lookup and recovery over derived work under overload. Controls:

- admission and per-stage budgets;
- backpressure rather than unbounded queues;
- circuit breakers and deterministic degradation;
- cached/read-only service where safe;
- regional materialization rebuild;
- metadata consensus/fencing;
- object placement and backups;
- repair/scrub scheduling with emergency reserves;
- chaos/failover/restore exercises;
- bounded dependency timeouts/cancellation;
- no outbox/projection failure blocking canonical commit beyond durable enqueue.

## 19. Cryptography and key management

- algorithms/parameters/key purposes are registry-versioned;
- domain separation for every signed/hashed object;
- keys have owner, environment, purpose, activation/revocation, and rotation;
- tenant/customer-managed key options are a later explicit product decision;
- envelope encryption separates data keys and wrapping keys;
- signature verification binds trust policy epoch;
- random number generation comes from approved OS/crypto sources, not deterministic test RNG;
- secret zeroization is used where meaningful but not advertised as complete forensic erasure;
- key compromise has re-sign/re-encrypt/revoke/migration playbooks.

## 20. Logging and privacy

Logs use IDs/positions rather than source/secrets by default. Structured fields have sensitivity classes and retention. Redaction happens before broad sinks. Debug artifacts require explicit authorization and expiry. Agent prompts/context and private code are not silently retained for model training or analytics; hosted terms must state any data use precisely.

## 21. Security release gates

Before public developer preview:

- object/pack/parser fuzz/resource gates;
- transaction/outcome/RCR fault model;
- auth/capability negatives;
- no-secret fixtures;
- dependency/action pinning;
- safe rendering/import/webhook basics;
- backup/export path.

Before hosted alpha:

- tenant isolation matrix;
- CI boundary if CI is offered;
- operator access controls;
- key/secret management;
- webhook SSRF/replay;
- GC/retention/legal hold;
- restore rehearsal;
- external security review of exposed surfaces.

Before production security claim:

- sustained patch/update process;
- incident response and security contact;
- penetration/red-team results with remediation;
- failover/restore evidence;
- release provenance/SBOM;
- supported-version policy;
- hosted privacy/deletion/data-residency commitments;
- no critical unresolved threat-model rows for shipped features.

## 22. Review questions for every change

1. Which trust boundary changes?
2. What new attacker-controlled bytes/state enter?
3. Which canonical identity and owner apply?
4. Can stale/derived state authorize?
5. Can retry/cancellation duplicate or hide an effect?
6. What is the linearization/publication point?
7. Are CPU/memory/disk/network/depth bounded?
8. Can tenant/private data enter a shared cache/index/log?
9. Can an agent/CI job obtain ambient credentials/network?
10. Do signatures/attestations create circular identity?
11. Does repair verify the original commitment?
12. Can GC/delete omit a root or overstate erasure?
13. Can an administrator override invisibly?
14. Is the control tested negatively and under crash/race?
15. Is the public claim no stronger than the evidence?