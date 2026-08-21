# FrankenGit Verification Specification

**Status:** normative evidence and release-gate contract for the pre-implementation phase  
**Architecture version:** 3.0  
**Local entrypoint:** `./scripts/verify.sh`

A forge can fail silently across identity, ordering, storage, parsing, authorization, repair, derived state, agent effects, or release provenance. A large passing unit-test count is necessary and radically insufficient. FrankenGit advances claims only through named evidence classes and immutable replay artifacts.

## 1. Verification doctrine

1. Every critical invariant has one owner, executable pass/fail signal, and evidence hooks.
2. Reference behavior precedes optimization.
3. Success, refusal, cancellation, retry, crash, corruption, resource exhaustion, and malicious input are separate test dimensions.
4. Git compatibility includes observable output order, tie-breaks, protocol bytes, errors, and resource refusals.
5. Canonical and derived/statistical systems have separate gates.
6. Every root-last protocol enumerates interruption points and anti-rollback behavior.
7. Local repository-owned commands are verification authority; hosted workflow status is not.
8. Skipped, unavailable, flaky, or missing-artifact results are structured terminal outcomes, not success.
9. Negative evidence and disproven hypotheses are retained.
10. No public claim exceeds the strongest admissible evidence in its registry row.

## 2. Claim-strength lattice

```text
invariant > proof > bounded_model > statistical > slo > benchmark
```

The relation means “may justify,” not “is numerically larger.” Examples:

- a benchmark cannot justify an invariant;
- a bounded model cannot justify unbounded liveness;
- an SLO cannot justify exact Git parity;
- a statistical detector cannot justify authorization;
- a proof over an abstraction requires implementation refinement evidence.

`registries/claim_classes.tsv` is machine checked. Evidence routing that attempts a weaker-to-stronger edge fails closed.

## 3. Evidence levels

| Level | Name | Required character |
|---|---|---|
| E0 | Source/constitution | static dependency/layer/unsafe/FFI/format/registry policy |
| E1 | Local exact | unit, property, golden, canonical bytes, deterministic repeat |
| E2 | Reference/model | pure state machine, metamorphic properties, bounded checking |
| E3 | Differential/conformance | named external oracle/version/corpus and accepted divergences |
| E4 | Fault/adversarial | crash, retry, partition, corruption, resource, malicious input |
| E5 | Performance/economic | pinned raw samples, correctness oracle, A/A, tails, cost |
| E6 | Operational/SLO | named deployment/profile, canary/soak/restore evidence |

A subsystem may require a vector such as `E1+E2+E3+E4`, not one scalar “maturity score.”

## 4. Replay completeness

Every evidence pack declares:

- **Replayable:** deterministic inputs, schedule, toolchain, and required artifacts are present.
- **Structural replay:** logical control/data shape is reproducible; named external classes are absent.
- **Verifiable with supplied artifacts:** exact missing artifact classes and commitments are identified.
- **Audit only:** inspectable evidence without a complete replay/verification path.

Secrets, hardware entropy, cloud-provider internals, and third-party responses may be absence-only classes. The system never labels them replayable merely because hashes were logged.

## 5. Bootstrap and constitutional lanes

### 5.1 Documentation/registry lane

Must check:

- required files and relative links;
- balanced fences and parseable TSV/YAML/TOML where applicable;
- one authoritative transaction-identity formula;
- no positive fictional “protocol v2 push” claim;
- no flattened transfer artifacts or platform junk;
- registry schemas, sorted unique IDs, status vocabularies, and cross references;
- README pre-implementation and source-available wording;
- plan/normative/architecture link and required contract phrases;
- workflow actions pinned and delegated to repository-owned scripts.

### 5.2 Dependency/memory-safety lane

Must check every first-party Rust target and Cargo manifest for:

- `#![forbid(unsafe_code)]` or inherited forbid;
- no `unsafe`, `extern "C"`, raw FFI declarations, inline assembly, or lint relaxation;
- no production subprocess invocation of `git` or another VCS engine;
- no banned dependency/runtime/native class;
- one `Cargo.lock` and dated nightly;
- dependency registry approval, including the resolved Cargo.lock transitive graph;
- one explicit `crate_layers.tsv` row for every workspace `fgit-*` package, with every direct first-party edge restricted to its declared lower-or-equal dependency layers and no L3 sibling edge;
- version-universe consistency, build-script/proc-macro policy, and transitive-unsafe evidence (the closed-world name check and the first-party build-script/proc-macro refusals run today; version-universe and transitive-unsafe evidence join the lane as that machinery lands);
- enumeration of the *enabled* build-script and proc-macro surface of the resolved graph, compared row-by-row with the dependency registry. Enabled means reachable from a workspace member over normal and build edges — development edges only from members themselves — after platform filtering, not merely present in `Cargo.lock`. The two are not the same number and the difference is not noise: at the time this clause was written the unfiltered lock listed 37 build scripts and 14 proc macros where the enabled set on `x86_64-unknown-linux-gnu` held 29 and 10, the remainder being Windows, wasm and macOS packages that never build here. A registry row records the state of the packages it wins under the registry's own precedence rule (exact pattern, then longest pattern, then lowest identifier), which is what allows a glob row and an exact row to describe the same package without contradicting each other. Drift in either direction is a refusal: an enabled build script or proc macro with no matching active row, and a row asserting a build script or proc macro the resolved graph does not have;
- refusal when a build script emits `cargo:rustc-link-lib` or `cargo:rustc-link-search` for a package whose registry `ffi_policy` denies a foreign engine. Linking native object code is a property of the build, not of the manifest, so the manifest cannot be the oracle for it;
- refusal when any first-party crate acquires a third-party derive macro. The check reads `[dependencies]`, `[dev-dependencies]` and `[build-dependencies]` in both inline and table form, because a derive macro reaches first-party code through a test fixture's dependency section before it ever reaches `src/`;
- no empty engine crate or placeholder durable abstraction (a review obligation until crate-graph checks exist);
- exactly one root `Cargo.lock` (nested lockfiles are refused).

Status of the three clauses above covering enabled-surface enumeration, the `ffi_policy`
link refusal, and the third-party derive refusal: specified here, not yet enforced by the
lane. They are written first so the registry schema and the checker are built against a
fixed obligation rather than the obligation being back-fitted to whatever the checker
happens to do. Until the machinery lands they are review obligations, and this lane must
not be described as enforcing them. Enumeration additionally has no present violation to
find — every enabled build script and proc macro in the graph already matches an active
registry row — so its value is drift refusal, not discovery, and reporting it as a catch
would overstate the evidence. The `ffi_policy` clause is the one with a live violation
behind it.

### 5.3 Local execution lane

The same checks must run without a hosted Actions token. `.github/workflows` is tested as a local DSR/`act` adapter, not a remote authority.

### 5.4 Asupersync/FrankenSQLite integration lane

The adopted runtime, storage, gateway, projection, and TUI stack must pass one exact-constellation lane before any dependent product slice can claim completion. The lane checks:

- exactly one Asupersync version and public type universe in the production lockfile; two Cargo-resolved 0.x versions fail;
- runtime-owned production `Cx` construction, capability narrowing, finite child-budget meet, and preservation of success/error/cancelled/panicked `Outcome` states;
- one compiled node lifecycle with dependency-ordered start, request → drain → finalize cancellation, explicit stop/join, and zero unresolved obligations or a typed containment failure;
- deterministic Lab schedule/crashpack coverage plus separate native parked-worker, real-file/socket, blocking-worker, signal, and process-teardown coverage;
- explicit obligation-leak policy: fail-fast in verification/release; no `Silent`, and no log-only result credited as quiescence;
- FrankenSQLite `default-features = false` with the minimal role-specific feature closure, no C API/native SQLite, no concurrent stock-SQLite access, and no unpublished/absolute path or `[patch]` dependency;
- asynchronous FrankenSQLite calls receive the runtime-owned `&Cx`; connection/worker count and command queues are bounded; every worker has explicit close/join evidence;
- awaited transaction commit/rollback, whole-transaction retry over only the registered transient family, fresh-snapshot handling for `SnapshotTooOld`, and refusal when retry budget is exhausted;
- authority CAS history equivalence and exactly one winner under every claimed contender profile; and
- projection watermark, authority-negative, migration, wipe/rebuild, cancellation, and bounded-writer tests against the exact claimed FrankenSQLite concurrency envelope.

Planted-negative fixtures must introduce a second Asupersync, Tokio, an absolute sibling path, a forbidden sqlmodel backend, a feature/unsafe/proc-macro drift, capability widening, an unbounded request budget, statement-only retry, an unclosed database worker, and an unsupported writer count; each fixture must fail for the intended reason. The current sibling projects are settled adoptions, but their integration remains blocked until their owned upstream version/path updates make this lane green.

## 6. Canonical encoding and identity suites

For every identity-bearing type:

- golden canonical bytes across native/WASM targets;
- round trip and rejection of noncanonical alternatives;
- explicit version/algorithm/domain;
- bounded decoder behavior;
- map/set/order/Unicode/integer normalization;
- unknown-major fail-closed behavior;
- domain-separation/cross-type non-confusion;
- SHA-1/SHA-256 Git type boundary;
- migration/mixed-version goldens;
- fuzz/metamorphic corpus.

Release blocker: two implementations must not produce different canonical bytes for the same logical value.

## 7. AuthorityStore backend conformance

Each embedded/object-store/future authority backend runs the same suite:

1. strong put-if-absent under races;
2. exact read-after-write for known key;
3. conditional replace with exact predecessor token;
4. one winner under N concurrent candidates;
5. ABA prevention across byte-identical rewrites/restores;
6. ambiguous timeout after server-side success;
7. stale proxy/gateway/cache behavior;
8. regional failover and version token continuity;
9. lifecycle/versioning cannot resurrect retired head silently;
10. authentication/endpoint confusion negatives;
11. cancellation before/after request transmission;
12. throttling/backoff/idempotency;
13. no reliance on listing order/completeness;
14. audit receipt for successful conditional write.

A backend profile cannot ship because its vendor documentation sounds strong; the deployed path must pass.

## 8. Repository decision-log invariants

### 8.1 Seal/idempotency

- identical retries discover the same seal/outcome;
- different canonical request under same idempotency key is rejected;
- request IDs/network attempts cannot split logical identity;
- seal body is immutable and exact-key recoverable;
- seal existence never implies commit.

### 8.2 Terminal outcomes

- at most one terminal decision per sealed transaction;
- committed/refused race has one winner;
- byte-identical replay is idempotent;
- conflicting second outcome is detected as invariant failure;
- outcome-index accelerators rebuild exactly from decision history;
- connection loss/cancel ambiguity resolves by head/outcome lookup.

### 8.3 Head/batch/RCR continuity

- head predecessor and generation are continuous;
- decision sequence is gap-free in canonical history;
- repository sequence advances only for commits;
- batch predecessor matches exact selected head;
- all resulting roots match reference scratch evaluation;
- every committed RCR belongs to one canonical batch and transaction;
- no unpublished batch becomes visible via local catalog/projection;
- highest acknowledged unresolved head fails closed.

### 8.4 Ref/forge atomicity

Matrix includes:

- PR merge and target ref;
- merge queue dequeue/synthetic ref/target update;
- release/tag and release event;
- protected override and audit event;
- package namespace and provenance event;
- multi-ref atomic push;
- non-atomic receive-pack mapping.

Fault at every write/CAS/response/outbox point must expose old-complete or new-complete canonical state, never split state.

## 9. Intent/effect and transaction semantics

Test:

- statement order and read-your-own-writes;
- mismatch trichotomy: no-op, statement error, transaction abort;
- identity/inverse-cancellation/absorbed no-ops;
- target-disjoint net-effect normal form;
- source-intent → surviving-effect/no-op/error mapping totality;
- duplicate/conflicting map values fail closed;
- canonical ordering independent of hash-map iteration/schedule;
- policy input root and exact basis;
- wall-clock/network/projection/model reads absent from canonical evaluation;
- deterministic refusal codes/evidence.

## 10. Per-core lanes, combiner, and witness refinement

### 10.1 Lane state machine

Exercise valid/invalid transitions, overflow/backpressure profiles, cancellation, lane retirement/reuse, producer crash, combiner crash, and no lost/duplicated prepared capsules.

### 10.2 Combiner refinement

Compare optimized output to the pure reference model over:

- random and adversarial transaction sets;
- independent/conflicting/cyclic conflict graphs;
- deterministic tie-breaks;
- batch-size/time/byte cuts;
- CAS winners/losers and repeated rebases;
- starvation escalation;
- cancellation during every phase.

### 10.3 Witness refinement

For every refinement class:

- coarse witness is conservative;
- finer witness cannot convert a true conflict into false independence;
- unavailable/failed refinement falls back conservatively;
- value-of-information calculation and inputs are receipted;
- refinement work stays inside CPU/I/O/latency budgets;
- conflict sketches never authorize admission;
- semantic rebase preserves sealed intent or emits a new explicit proposal.

### 10.4 Performance claim boundary

Measure end-to-end committed decisions/CAS, batch fill, queue tails, CAS retries, reused preparation, aborts, memory, and cost. A lower lane lock-contention microbenchmark cannot establish repository throughput.

## 11. Pure-Rust Git conformance

Maintain a versioned upstream-Git matrix and source-derived/adversarial corpus.

### 11.1 Object and hash

- exact blob/tree/commit/tag framing;
- SHA-1/SHA-256 native identity;
- collision-defense behavior;
- tree modes/order/names;
- weird but accepted commit/tag headers/encodings;
- malformed length/type/hash refusals.

### 11.2 Pack/delta/DEFLATE

- pack versions/count/trailer/checksum;
- OFS/REF deltas, thin packs, chains, cycles;
- depth/fan-out/expanded-byte/ratio/aggregate work bounds;
- streaming/cancellation and partial input;
- deterministic pack construction profiles where claimed;
- fuzz and decompression-bomb corpus.

### 11.3 Wire/services

- pkt-line/sideband and capability advertisement;
- upload-pack fetch/clone protocol versions/capabilities;
- receive-pack push/delete/force/atomic/non-atomic/push options/status;
- shallow/deepen/partial/promisor/filter;
- hidden refs/authorization;
- signed pushes where declared;
- errors, ordering, and disconnect behavior.

Fetch and push are tested as distinct services. A standardized “protocol v2 push” does not exist; push compatibility is tested through receive-pack.

### 11.4 Migration/export

Import/export round trips preserve declared Git-visible objects/refs and accepted divergences. Upstream Git runs only as external oracle/tool against exported bytes.

## 12. Immutable object-fabric suites

For each backend/profile:

- immutable put/read/range and exact identity;
- ambiguous/duplicate/partial operations;
- truncation/bit flip/wrong length/wrong tenant/key;
- deterministic segment/index/Merkle record boundaries;
- compaction logical-identity preservation;
- placement manifest and failure-domain evidence;
- stale/missing/corrupt local catalog rebuild;
- lifecycle/versioning/retention/object-lock behavior;
- encryption/key rotation and dedup-domain negatives;
- request throttling/cancellation/obligation closure;
- listing unavailable/incomplete without correctness loss.

## 13. ATP-Git verification

### 13.1 Semantic parity

For every transfer profile, reconstructed native object closure and resulting Git operation equal ordinary/reference transfer.

### 13.2 Have/delta/dedupe

- exact have sets never omit required bytes;
- probabilistic summaries can add transfer but never omit correctness-critical bytes without verification/retry;
- delta basis/closure/profile identity exact;
- unique payload mapping reconstructs byte-identical object set/order where observable;
- full fallback has typed reason and parity.

### 13.3 Paths/swarm

- path security/privacy/budget constraints;
- race winner and loser drain;
- loss/reorder/duplication/asymmetry/partition;
- peer lies/withholding/corrupt pieces;
- rarity/endgame determinism;
- trust-scoped cache contamination negatives;
- bounded peers/paths/pieces/duplicates/memory.

### 13.4 Adaptive RaptorQ/pacing

- identity-bound observations/policy/fallback;
- insufficient evidence → deterministic safe profile;
- regime alarm/reset;
- decoder input/work/memory bounds;
- original commitment verification;
- no performance claim without end-to-end transfer/cost samples.

## 14. TreeFS and materialization suites

Test direct API and every supported adapter:

- immutable base exactness and lazy authorized fetch;
- descriptor-relative path containment;
- symlink/submodule/case/Unicode/platform path rules;
- sparse reads and promisor failure;
- semantic edit intents and source spans;
- overlay statement order/read-your-own-writes;
- staged/visible/durable output epochs;
- export to exact Git objects/proposed effects;
- crash/cancel/quiescence with no orphan temp/output/credential;
- BuildInputCapsule reproducibility;
- standard bare/worktree/pack/commit-graph receipt and rebuild;
- materialization corruption/poisoning quarantine;
- toolchain compatibility matrix for sparse-directory/FUSE profiles.

## 15. CALM and obligation suites

### 15.1 CALM registry

For each operation row:

- monotonicity/merge laws where coordination-free;
- bounded commutativity and conflict witness where applicable;
- proof that coordinated operations cannot bypass authority;
- retractions/deletions explicitly reclassify non-monotone state.

### 15.2 Obligations

Fault/cancel every reserve/commit/acknowledge/abort/transfer/drain boundary — including the committed-but-unacknowledged window, where retry must be idempotent and region close must leave an explicit unacknowledged-effect record — for:

- object/segment writes;
- authority CAS;
- outbox delivery;
- secret lease;
- runner/workspace allocation;
- ATP pieces/paths;
- context fetch;
- repair placement;
- retention/deletion;
- billing reserve;
- release upload.

Region close must report zero unresolved obligations or a typed containment failure with owners/evidence.

## 16. Forge/product state verification

Event aggregates, projections, APIs, and merge queue test:

- event identity/order/schema/upcast;
- RCR admission of exact event batches;
- projection watermark/currentness and full rebuild;
- PR head/base/review/check invalidation;
- source-spanned review anchor exact/remapped/ambiguous/outdated behavior;
- branch protection/CODEOWNERS/status/override basis;
- merge queue synthetic head and target races;
- webhook/outbox at-least-once stable delivery IDs;
- release/package namespace races and provenance;
- GitHub-compatible API pagination/errors/race/idempotency where claimed.

## 17. Search and graph verification

### 17.1 Generation authority

- immutable generation identity and exact predecessor;
- sequence+nonce/anti-rollback floor;
- root-last shard/manifest activation;
- interrupted highest activation fails closed;
- no mixed-generation query;
- deterministic rebuild from canonical sources;
- authorization labels preserved through all shards/caches.

### 17.2 Progressive retrieval

- `Initial` remains valid if refinement fails;
- stable result IDs/order/tie-breaks;
- source spans and authority/generation receipts;
- lexical/path/symbol/semantic/graph channel explanations;
- bounded candidate/rerank/context budgets;
- offline/missing-model graceful behavior.

### 17.3 Graph algorithms

Optimized algorithms compare to scalar/reference implementations across fixed and mutation corpora. Verify:

- stable external IDs/order with dense internal representation;
- closed tie-break policy;
- complexity witness inputs/observed work/decision-path digest;
- SCC/condensation, dominators, reachability, bridges/articulation, paths, flow/cut, matching, topo/critical path, centrality/community as used;
- incremental updates versus full recompute;
- exact/deterministic/statistical edge type separation;
- no advisory graph result can grant access or delete/mutate canonical state.

## 18. RaptorQ, repair, checkpoint, and restore

### 18.1 Coding class registry

Every encoded class declares source bytes/identity, block/symbol/repair profile, authenticated symbol metadata, maximum decoder work/memory/input count, placement/failure domains, trigger, post-decode commitments, and typed failure.

### 18.2 Repair state machine

Inject loss/corruption/malicious/stale symbols at every phase. Verify:

- quarantine before acceptance;
- source digest/length/internal/native identity/Merkle/codec/tenant verification;
- current authority/retention reread before placement publication;
- stale repair cannot overwrite newer or resurrect deleted data;
- fail closed inside/beyond declared recovery envelope;
- evidence records exact symbols/profile/resources/authority basis/result.

### 18.3 Capsule/root-last

Crash before/after every body/checksum/sync/manifest/signature/root/ack/cleanup boundary. Recovery yields old-complete or new-complete; unresolved higher acknowledged generation never silently falls back.

### 18.4 Clean restore

Restore to clean account/region/backend/embedded node and verify head, decision suffix, refs, forge aggregates, outcomes, retention, object closure, Git export, projections/generations, and measured RPO/RTO. Backups without passing restore artifacts do not advance claims.

## 19. GC, retention, and deletion

Model/property/fault matrices include:

- current/protected/hidden refs and safety/reflog roots;
- PR/merge queue/review/evidence roots;
- releases/packages/artifacts/LFS/provenance;
- legal holds/admin pins;
- capsule/backup/migration/federation roots;
- in-flight obligations and new objects during mark;
- grace/tombstone/replica/repair/archive horizons;
- stale/corrupt accelerators;
- repeated/interrupted sweep;
- logical versus physical versus backup/crypto deletion claims.

No approximate filter or local Git GC result may independently authorize deletion.

## 20. Agent, capability, and CI security verification

### 20.1 Intent Runs and capabilities

- sponsor/agent/base/objective/budget/expiry/revocation binding;
- delegation only narrows;
- ref/path/object/secret/network/effect boundaries;
- prompt/repository text cannot mint/widen capabilities;
- revocation/cancel races;
- no sponsor/host/cloud metadata ambient access.

### 20.2 Context/Evidence-Carrying Changes

- source spans/generation/authorization/omissions;
- deterministic transforms and packet identity;
- exact proposed object/effect closure;
- tool/effect/check receipts;
- verifier independence classification/enforcement;
- known omissions/non-claims;
- stale base/policy revalidation.

### 20.3 Runner/workflow

- workflow lowering/conformance for declared subset;
- immutable BuildInputCapsule;
- VM/sandbox, egress, secrets, process/resource bounds;
- fork secret policy;
- trust-domain cache poisoning;
- cancellation/reaping/no orphan processes/tunnels/uploads;
- log/artifact redaction/provenance;
- compromised runner cannot publish canonical result without valid receipts/policy.

## 21. Statistical policy verification

For conformal/e-process/no-regret/OPE/change-point/Beta/Lyapunov controllers:

- evidence identity includes metric/population/selection/window/regime/candidate/fallback/assumptions/numeric/toolchain;
- deterministic replay of observations/choice/reset;
- support/ESS/applicability gates;
- hard action floors/ceilings and kill switch;
- insufficient evidence/regime alarm → fallback;
- optional witness collection failure classification;
- public coverage/false-alarm statement matches assumptions;
- forbidden authority targets cannot be wired through types/registries;
- policy epoch does not reinterpret prior canonical history.

## 22. Security/adversarial program

At minimum:

- Git/pack/delta/DEFLATE bombs and parser fuzzing;
- hidden-ref and cross-tenant disclosure;
- stale/forged authority token and rollback;
- storage endpoint/tenant/key confusion;
- materialization/cache/generation poisoning;
- path traversal/symlink/case/Unicode/archive attacks;
- Markdown/SVG/image/link active content;
- webhook SSRF/DNS rebinding/redirect/replay;
- LFS/package namespace and malware/provenance attacks;
- prompt injection/tool/secret abuse;
- runner escape/cache/secret exfiltration;
- malicious repair symbols and GC races;
- operator override/key/release compromise;
- dependency/toolchain/build-script/proc-macro/supply-chain tamper;
- DSR host/SSH/artifact/remote-release reconciliation attacks.

Security tests enforce resource ceilings as well as semantic rejection.

## 23. Performance and economic evidence

Every benchmark artifact contains source/tree/lock/toolchain/OS/CPU/target/build profile, dataset/workload, warm/cold/cache state, commands/environment whitelist, baseline/candidate/A-A, raw samples, tails, CPU/memory/requests/bytes/egress/storage, correctness oracle, and replay/rollback.

Required system metrics include:

- authority read/CAS latency and contention;
- decisions/RCRs per CAS and batch distribution;
- preparation reuse/refinement/abort/starvation;
- Git object/pack/wire throughput and resource tails;
- ATP versus ordinary transfer across paths/loss/receiver-have cohorts;
- TreeFS startup/read/write/export versus checkout profiles;
- search/graph generation/query/freshness/decision-witness cost;
- repair/restore/GC and storage amplification;
- agent/context/check marginal cost;
- release target build/reproducibility/evidence cost.

Benchmark claims remain profile-scoped and cannot be rounded up to universal performance.

## 24. Local verification and DSR release gates

### 24.1 Lane hierarchy

```text
docs
constitution
fast
full
release
```

`full` and `release` remain explicitly dormant/spec-only until their real implementation surfaces exist; they must not report fake green coverage.

### 24.2 Exact test-suite manifest

When `full` and `release` activate, a checked-in versioned manifest names every required acceptance/surface ID and script for the selected profile. Runtime discovery is compared with that independent expected set. A green receipt requires exact equality of required and passed IDs and records expected, discovered, selected, started, passed, failed, skipped, unsupported, filtered, ignored, timed-out, and malformed-log sets.

The same manifest maps every required acceptance ID to exactly one active owning Bead. The release-gate owner must reach that complete owner set through blocking dependencies. A dependency rewrite is invalid if it drops or silently substitutes a required campaign owner, even when the script-discovery sets still happen to match.

A minimum script count, filesystem glob, or manifest regenerated from discovery cannot establish completeness. Zero-run, missing, duplicate, unregistered, unsupported, skipped, filtered, ignored, timed-out, early-exit-without-terminal-assertion, malformed-log, stale-revision, and wrong-profile cases are non-pass for required rows. Structural defects report `FAIL` before a clean partial run may report `INCOMPLETE`; partial modes never report `PASS`. First-attempt failures remain in the receipt.

### 24.3 DSR target attempts

A completed target is reusable only when source/tree/lock/constellation/nightly/target/CPU/features/profile/lane/environment/input identities match. Partial target success is resumable but no authoritative release manifest is created.

### 24.4 Exact release contract

Before root publication:

- all requested target-native tests succeed;
- exact primary/companion assets exist, with no symlink/path/collision/unlisted discovery;
- deterministic archives and checksum sidecars verify;
- SBOM/provenance/signatures verify;
- installer/extraction/version/smoke tests use staged assets;
- verification/negative-evidence roots are complete;
- signed local manifest is published last;
- remote mirrors match exact name/size/digest.

GitHub-hosted Actions status cannot substitute for any row.

## 25. Release-blocking invariant catalog

At minimum, production-v1 cannot ship until executable evidence covers:

1. one transaction identity derivation and key-reuse rejection;
2. one terminal outcome per sealed transaction;
3. no cancellation/lost response creates ambiguity or duplicate effect;
4. head predecessor/generation and decision/repository sequence continuity;
5. atomic ref/forge/outcome/retention/outbox roots;
6. exact authority-store CAS semantics under deployed topology;
7. no staged/quarantined object becomes a retention root before commit;
8. no committed object closure is omitted from retention;
9. per-core batching/reference equivalence;
10. witness refinement is conservative;
11. pure-Rust Git declared conformance and resource bounds;
12. SHA-1/SHA-256 type separation;
13. ATP/ordinary transfer parity;
14. TreeFS path/capability/export/quiescence;
15. generation anti-rollback and no mixed generation;
16. projection lag cannot authorize;
17. repair verifies original commitments and current authority;
18. GC cannot sweep authenticated/grace roots;
19. CALM classifications and obligation closure;
20. agent verifier independence/capability bounds;
21. runner isolation/cache/secret/cancellation;
22. statistical fallback and forbidden-target separation;
23. root-last capsule/restore and measured recovery;
24. locally reproducible exact release without hosted Actions;
25. every public claim justified by admissible immutable evidence.

## 26. Failure disposition

A failing lane is handled by one of:

- fix implementation/spec/test;
- narrow the supported profile/claim;
- quarantine a flaky/environmental lane with explicit release consequence and owner;
- record negative evidence and reject the hypothesis;
- declare a typed unsupported surface;
- halt the release.

Deleting or weakening a test because it is inconvenient requires an ADR/evidence update and cannot silently preserve the prior claim.

## 27. Verification completion criterion

Verification is complete only for a named source/dependency/toolchain/format/policy/deployment profile and claim set. There is no final global “verified” bit. A new dependency, toolchain, format epoch, backend, target, optimization, policy, or threat can invalidate evidence and demote claims automatically.
