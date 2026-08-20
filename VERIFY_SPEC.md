# FrankenGit Verification Specification

**Status:** Normative evidence contract for architecture and future implementation.  
**Protocol target:** [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md)

Passing documentation checks is necessary but never sufficient evidence that a protocol or storage implementation is correct.

## 1. Evidence levels

A claim carries one of these statuses:

| Level | Meaning | Minimum evidence |
|---|---|---|
| `specified` | Normative contract exists | owner, identity, state machine, refusal/recovery, non-claims |
| `implemented` | Code reaches the contract surface | build + focused tests; no compatibility/readiness implication |
| `differentially_verified` | Named external/reference oracle agrees over a versioned corpus | corpus identity, oracle versions, raw results, accepted divergences |
| `fault_validated` | Adversarial/crash/concurrency campaigns support the scoped invariants | seeds/traces, environment, fault matrix, artifact schema |
| `operationally_validated` | Deployment evidence supports bounded production claims | config, workload, time window, raw telemetry, SLO rule, limitations |
| `unsupported` | Intentionally unavailable | typed refusal and compatibility documentation |

No test count promotes a subsystem automatically. A claim registry maps every public statement to one artifact and scope.

## 2. Artifact requirements

Every evidence artifact includes:

- schema/version;
- producing commit and dirty-state flag;
- tool/executable identities;
- platform/toolchain/configuration;
- exact input/corpus identities;
- random/deterministic seeds;
- start/end logical and wall times where relevant;
- resource limits;
- result and all skips/refusals;
- raw sample/trace references;
- replay command;
- assumptions and non-claims;
- signature/content digest where required.

Artifacts are immutable. Human summaries are projections over them.

## 3. Documentation/architecture gate

`python3 scripts/verify_docs.py` must pass. It verifies:

- constitutional files and intended directories;
- no flattened docs or transfer artifacts;
- relative Markdown links and code fences;
- immutable pins for third-party Actions;
- explicit pre-implementation and source-available status;
- one canonical `TxId` formula;
- corrected upload-pack/receive-pack language;
- mandatory outcome, forge-position, capsule, and RaptorQ boundaries.

Architecture review additionally checks that every new format/protocol declares identity, owner, publication point, refusal, cancellation, retry, recovery, migration, and evidence.

## 4. Canonical encoding and identity gates

### V-ID-1 Canonical bytes

For each record version:

- golden byte fixtures;
- decode/re-encode equality;
- map/set ordering determinism;
- Unicode/string normalization rule;
- integer/length overflow negatives;
- unknown-version/field behavior;
- cross-platform/compiler determinism.

### V-ID-2 Typed digest separation

Tests must prove:

- SHA-1 Git OID cannot be passed as SHA-256/internal ID;
- same digest bytes under different domains/types are unequal;
- repository/tenant/object type are bound where specified;
- signatures bind intended body/version/domain;
- signature rotation does not change unsigned object identity.

### V-ID-3 Sole TxId derivation

Generate requests varying each semantic field and each non-semantic attempt field. Semantic changes must change canonical request digest/TxId; retry count, transport connection, receiving node, and wall clock must not. Reused key/different request must refuse.

## 5. Sealed transaction and terminal outcome gates

Model and implementation must cover:

- two simultaneous identical attempts;
- identical retry after crash/disconnect;
- idempotency-key body mismatch;
- commit versus refusal race;
- cancellation before seal, after seal, during validation, immediately before metadata commit, immediately after commit, and during response;
- stale writer during attempt;
- metadata timeout with unknown client result;
- duplicate outcome publication;
- outcome lookup after process/node failover.

Release-blocking invariants:

1. at most one seal body per `TxId`;
2. at most one terminal outcome per seal;
3. committed/refused outcomes cannot both exist;
4. byte-identical republish is idempotent;
5. no terminal record means retry—not implicit refusal;
6. client cancellation cannot erase/contradict committed state;
7. committed outcome references an existing valid RCR;
8. refused outcome cannot mutate repository sequence/roots.

Use a pure reference state machine, generated command sequences, linearizability history checking, deterministic scheduler exploration, and crash-point tests.

## 6. RCR and canonical repository state gates

### V-RCR-1 Chain continuity

Verify repository ID, epoch/sequence rule, parent pointer, TxId uniqueness, and head pointer. Inject missing parent, duplicate sequence, epoch rollback, stale writer, and forked chain.

### V-RCR-2 Atomic ref/forge publication

For PR merge, branch deletion, protection change with mutation, merge-queue transition, and release/tag publication, crash/fault at every staging/metadata/outbox boundary. No observer may see only one half of the canonical transition.

### V-RCR-3 Pinned policy snapshot

Record policy input root. Race changes to refs, reviews, checks, CODEOWNERS, policy epoch, membership, quota, and legal hold. Attempt must commit only if the compared snapshot remains current or restart/refuse under explicit semantics.

### V-RCR-4 Resulting roots

Reference implementation recomputes ref, forge-position, object-closure, policy, retention, and outbox roots. Incremental implementation must match full rebuild.

### V-RCR-5 Transactional outbox

Crash/retry/duplicate delivery/poison consumer/cursor loss/rebuild tests. Canonical events occur once; downstream delivery may be repeated with stable IDs. Failed delivery cannot roll back RCR.

## 7. Git object and pack gates

### V-GIT-1 Object codec

Differential corpus for blob/tree/commit/tag under supported object formats. Cover malformed headers, NULs, oversized lengths, duplicate/unsorted tree entries, invalid modes/names, encoding oddities, signatures, and collision-defense policy.

### V-GIT-2 Pack/index/delta

- official/source-derived pack fixtures;
- thin packs and base completion;
- OFS/REF deltas;
- deep/wide delta graphs;
- checksum/trailer corruption;
- truncation/extra bytes;
- decompression bombs and aggregate work limits;
- duplicate objects;
- cancellation/resource reservation;
- index/multi-pack-index/bitmap consistency where supported.

Fuzzers and property tests must enforce bounded memory/CPU and no panic/UB.

### V-GIT-3 Upload-pack

Named Git client matrix over SSH/smart HTTP:

- v0/v1 and v2 `ls-refs`/`fetch`;
- sideband/progress/error behavior;
- wants/haves, tags, symrefs;
- shallow/deepen/unshallow;
- filters and promisor/lazy object fetch;
- empty/unborn repositories;
- interruptions/slow clients;
- authentication/hidden refs.

Capture normalized packet transcripts and final object/ref equivalence.

### V-GIT-4 Receive-pack

Named Git client matrix:

- create/update/delete refs;
- fast-forward/force/force-with-lease-like expected olds;
- atomic multi-ref capability;
- push options;
- report-status/sideband errors;
- signed push certificates when supported;
- thin packs, missing objects, hidden refs;
- duplicate/retried sessions;
- quarantine cleanup/promotion;
- policy refusal mapping.

Do not create a “protocol v2 push” lane unless Git standardizes one.

### V-GIT-5 SHA-1/SHA-256

Separate repository fixtures and type-level tests. No implicit conversion. Imports/exports preserve native format. If SHA-256 support is gated, unsupported operations refuse explicitly.

### V-GIT-6 LFS

Official clients and protocol fixtures for batch upload/download/verify, resumability, range behavior, digest/length mismatch, quotas, authorization, locks, retention, interrupted transfers, and cross-tenant isolation.

## 8. Materialization gates

- build bare/pack/sparse view from canonical state;
- compare refs/object closure and Git behavior against reference;
- delete all local materialization and rebuild;
- inject stale/corrupt/truncated packs/indexes;
- source position receipt must match;
- concurrent readers during refresh;
- crash during generation and root-last switch;
- bounded disk/memory/startup;
- no materializer can mutate canonical truth directly;
- cache eviction cannot remove canonical retention roots.

## 9. Capsule, backup, and restore gates

### V-CAP-1 Identity

Unsigned body goldens; signatures/placement excluded; key/signature rotation keeps capsule ID; body changes alter ID.

### V-CAP-2 Exact-state binding

Capsule binds exact RCR/roots. Generate later RCRs and prove old capsule cannot be reported as current forge/ref state.

### V-CAP-3 Root-last crash matrix

Interrupt before/after each dependency write, durability receipt, body hash, signature, pointer publication, and retention transition. No incomplete capsule becomes visible.

### V-CAP-4 Restore rehearsal

From fresh infrastructure, restore metadata/object/event state, replay later RCRs, rebuild projections/materializations, and verify all roots. Report measured RPO/RTO and missing external effects.

### V-CAP-5 Byzantine/malformed inputs

Invalid signatures, wrong repository, downgrade registry, missing manifests, cyclic references, oversized/deep manifests, malicious placement claims, and split-brain capsules fail closed.

## 10. RaptorQ gates

For each registry row advancing beyond `specified`:

- RFC/independent vectors where applicable;
- deterministic canonical envelope goldens;
- random and adversarial erasure patterns;
- bit flips/truncation/duplicates;
- symbols mixed across objects/profiles;
- malformed encoding symbol IDs;
- too many symbols/resource exhaustion;
- cancellation and crash;
- insufficient-symbol typed failure;
- decoded-but-wrong commitment rejection;
- independent failure-domain placement simulation;
- end-to-end repaired placement and consumer read;
- encode/decode benchmark with scalar/reference oracle.

A test that only calls encode then decode in memory is insufficient for a self-healing claim.

## 11. GC, retention, and deletion gates

Property/model tests generate refs, hidden refs, PR heads, queue refs, releases, packages, artifacts, legal holds, backups/capsules, migrations, and tombstones while concurrent mutations occur.

Invariants:

- no authenticated/unexpired root is swept;
- root snapshot/policy epoch is revalidated before sweep;
- legal hold activation wins races according to explicit order;
- grace horizon covers replica/projection/backup assumptions;
- interrupted mark/sweep resumes safely;
- stale materialization reachability cannot retain/delete canonical data by itself;
- deletion status distinguishes logical/physical/backup/crypto stages;
- audit evidence cannot be deleted by the operation it records unless policy explicitly schedules it later.

## 12. Forge semantic gates

### Issues/PR/reviews

- event replay equals incremental projection;
- duplicate event idempotency;
- schema evolution/mixed versions;
- stable identities/edit histories;
- review anchor outdated/remap behavior;
- authorization at canonical position;
- import/export round trip.

### Protection/merge queue

- target movement at every check/merge phase;
- review/status/CODEOWNERS changes;
- policy epoch/bypass/admin races;
- synthetic ref identity;
- batch success/failure/split;
- stale CI invalidation;
- merge RCR atomically changes PR and target ref;
- queue recovery after scheduler loss.

### Webhooks/APIs

- stable delivery IDs/signatures/retries;
- SSRF-safe destinations and DNS/IP revalidation;
- duplicate/out-of-order consumer guidance;
- endpoint pagination/error/race fixtures;
- rate/size limits;
- versioned accepted divergences.

## 13. Search and graph gates

- immutable generation/root-last publication;
- full rebuild equals incremental result for reference corpus;
- canonical source position exposed;
- authorization filtering before disclosure;
- deletion/permission change propagation and stale-query behavior;
- deterministic ties/order;
- lexical initial result survives semantic/rerank failure;
- embedding/model identity and fallback status;
- source-linked explanation accuracy;
- relevance corpus and raw metrics;
- index corruption/rebuild;
- adversarial code/text/resource limits.

No search quality metric is a security or completeness proof.

## 14. Agent-system gates

### Capabilities/budgets

- absent capability denied;
- delegation cannot widen;
- audience/run/repository/path/ref confusion negatives;
- expiry/revocation races;
- budget atomicity/exhaustion;
- no sponsor credential in workspace.

### Context Packet

- every byte has provenance/transform/position;
- explicit omission receipts;
- unauthorized result impossible, including semantic/graph leakage;
- deterministic packet under fixed inputs;
- budget truncation honest;
- prompt-injected content remains untrusted.

### Workspace/effects

- descriptor/path traversal and symlink attacks;
- host/cloud metadata isolation;
- no credential/task residue after cancellation;
- lazy fetch authorization;
- effect idempotency and receipt integrity;
- external network/package/secret policy;
- destructive tool containment;
- reproducible workspace manifest.

### Evidence/verifiers

- forged/tampered receipt rejection;
- failed/skipped/flaky checks preserved;
- stale-base revalidation;
- shared workspace/credential/context downgrades independence;
- proposer cannot self-approve policy requiring independent verifier;
- narrative cannot override machine receipt.

## 15. CI runner gates

Threat-driven red-team corpus:

- sandbox escape attempts;
- cloud metadata and host socket access;
- secret exfiltration from fork/untrusted PR;
- cache poisoning across trust/tenant/repository boundaries;
- artifact/log path traversal and active content;
- package proxy confusion;
- orphan process/network after cancellation;
- runner image/toolchain substitution;
- forged check receipt;
- resource-exhaustion/noisy-neighbor;
- cleanup after crash/host loss.

Receipts bind exact source RCR/object closure, image/toolchain, policy, secrets class, cache inputs, outputs, and resource use.

## 16. Security gates

- threat model updated per new surface;
- authn/authz/capability negative matrix;
- tenant isolation tests;
- parser/render/import/archive/webhook fuzz and resource bounds;
- dependency/advisory/license/supply-chain policy;
- immutable Action pins;
- secret scanning/redaction negative/positive fixtures;
- admin override and audit tamper tests;
- key rotation/revocation and backup recovery;
- incident-disable/kill switches;
- external penetration review before hosted production.

## 17. Multi-node/failover gates

Use deterministic simulation plus real multi-node fault campaigns:

- network partition/asymmetric loss/reordering/duplication;
- process pause/GC/CPU starvation;
- stale leader/lease expiry/epoch advance;
- metadata/object-store partial failure;
- lost response after commit;
- rolling upgrade/downgrade/mixed schema;
- region loss and restore;
- clock jump/skew where wall time is used operationally;
- outbox/projection lag;
- quota/billing reconciliation.

Run linearizability checking against recorded operation histories. RPO/RTO/SLO claims require named topology/config and raw artifacts.

## 18. Performance and economics gates

Each benchmark artifact records dataset and workload digest, hardware/OS/toolchain, config, cold/warm state, samples, tail distributions, CPU/memory/disk/network, correctness checks, baseline versions, and replay command.

Required workloads eventually include:

- small and huge repo clone/fetch/push;
- monorepo partial clone and sparse agent context;
- many tiny concurrent refs/repositories;
- huge pack/delta validation;
- materialization cold rebuild/hot cache;
- PR/merge queue contention;
- search initial/refined latency and quality;
- CI checkout/cache/artifact flow;
- backup/restore/repair/GC;
- tenant noisy-neighbor/admission;
- storage/egress/compute cost per useful operation.

Do not publish a multiplier without raw data and an honest comparable baseline.

## 19. Release lanes

### Documentation/spec release

- docs verifier green;
- normative contracts/ADRs consistent;
- unresolved decisions explicit;
- no implementation/readiness claims.

### Developer preview

- local reference model and Git object/protocol core;
- supported matrix rows explicitly narrow;
- destructive-data warning;
- migration/export path;
- fuzz/fault critical lanes green.

### Alpha

Requires transaction kernel, materializer, backup/restore, GC roots, issues/PR/merge critical path, authentication/capabilities, and core Git differential lanes. No irreplaceable production-data recommendation.

### Beta

Requires multi-node/failover evidence, hosted tenant isolation, security review, CI boundary if offered, operational telemetry, upgrade/rollback, and measured recovery.

### Production claim

Requires defined SLO/configuration, sustained evidence window, incident/restore drills, release artifact provenance, supported-version policy, and truthful license/product terms.

## 20. Verification command registry

Every lane receives a stable machine name, owner, prerequisites, timeout, resource class, artifact schema, and exact command. “Skipped” is a typed result with reason; required lanes cannot turn an unavailable dependency into green.

The first command is:

```bash
python3 scripts/verify_docs.py
```

Future Rust gates are added only when the corresponding real slice exists.