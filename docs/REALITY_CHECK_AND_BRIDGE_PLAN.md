# FrankenGit reality check and bridge plan — 2026-09-07

FrankenGit has a working, bounded pure-Rust Git node and substantial subsystem implementations. It does not yet deliver the integrated forge, agent product, hosted deployment or release system described by its vision. The largest remaining gap is composition: public operations, durable effects, actual adapters and independent verification must connect the existing libraries.

This assessment binds product source to `b74b666dc644c6ed18697f3950690bf289c33114`, on Linux x86_64 with `nightly-2026-08-31`. It distinguishes observed runtime behavior, inspected implementations and future requirements. It is not a security audit, universal compatibility result, benchmark claim or batch-verification certificate.

**Consumer and retirement:** the repository owner, subsystem assignees and batch orchestrator use this document to sequence the first deployable forge and prevent incomplete library work from receiving product credit. The observed defect classes are missing production adapters, incomplete composition, acceptance/evidence mismatch and stale documentation. Replace this snapshot in place when a later revision-bound assessment supersedes it; implementation evidence and authoritative Beads take over each resolved row. This report grants no runtime authority or capability credit.

## 1. What was actually examined

All of `AGENTS.md` and `README.md` were read. The assessment also examined the comprehensive plan, architecture, normative protocol contracts, dependency constitution and sibling integration profile, verification specification, threat model, Git compatibility matrix, relevant ADRs, agent control-plane status and reconciliation documents, claims and dependency registries, source and test inventories, public node/CLI dispatch, and selected subsystem implementations and E2E scripts.

The authoritative tracker baseline came from `br list --status all --limit 0 --no-db --json`, with `has_more=false`, and `br ready --unassigned --no-db --json`. Advisory analysis used the mandatory `scripts/bv_compat.sh` wrapper. Code review traced important user operations across owning crates; it did not review every line of all 47 first-party crates or exhaustively audit every closed issue.

Builds ran offline, locally, with `RCH_CARGO_WRAPPER_BYPASS=1` and the private target `/data/frankengit-targets/reality-20260907-VdyQfM`. Full logs, command receipts, tracker snapshots and E2E artifacts are retained in `/tmp/frankengit-reality-20260907-VdyQfM`. No dependencies were upgraded, goldens regenerated, assertions weakened or product source changed.

## 2. Current executable evidence

These are results observed during this assessment at the stated source revision, not recalled historical results.

| Check | Actual result | What it establishes |
|---|---|---|
| `./scripts/verify.sh fast` | Exit 1 | Docs and constitution stages succeeded, then formatting failed in seven `fgit-wire` files. The canonical fast lane did not pass or reach its later checks. |
| `cargo test --workspace --all-targets --locked --no-fail-fast` | Exit 0; 4,590 passed, 0 failed, 24 ignored across 490 test-result groups | The current workspace compiles and its nonignored local tests execute successfully. Ignored differential/fault/benchmark workers still require their owning campaigns. |
| `cargo build --locked -p fgit-cli` | Exit 0 | A fresh binary exists from the assessed source. |
| `./scripts/verify.sh constitution`, after that build | Exit 0, with native-linkage evaluation skipped | The implemented checks accept this tree, but build-script linkage evidence discovery is ineffective under this Cargo layout. This is not a complete native-linkage clearance. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Exit 101 | `visibility_composed_records.rs:55` fails `collapsible_if`. Do not extrapolate one reported error into proof that no later errors exist. |
| Selected real-node E2E campaign | Exit 0; four suites, 152 distinct acceptance IDs, no failed/skipped/unsupported/timed-out cells | Nonempty clone, raw push, historical `fg at`, and pinned-client incremental fetch work for the exercised profiles. |
| Separate SHA-256 repository E2E | Exit 0; 26 acceptance IDs | A separately rebuilt binary initializes/refuses formats correctly, serves SHA-256 and transfers a nonempty repository to pinned Git 2.54.0. It does not prove the complete SHA-256 push/fetch matrix. |
| `./scripts/verify.sh full` | Exit 3, explicitly dormant | The canonical full conformance/lab/fault/fuzz/corpus lane is not complete. |
| `./scripts/verify.sh release` | Exit 3, explicitly dormant | License checking and a release wiring probe do not produce a releasable target matrix or release publication. |

The selected E2E invocation used the freshly built `FG_BIN` and the repository's `run_all.sh`. `first_clone.sh`, `first_push.sh` and `time_travel.sh` use the ordinary installed Git 2.55.0 client; they are compatibility observations, not the pinned differential lane. `incremental_fetch.sh` uses the verified, sandboxed Git 2.54.0 oracle with source and binary digest checks. Do not promote the ordinary-client cells to the constitution's pinned-oracle claim class. The XL push option was not enabled.

The pinned incremental campaign exercised v1/v2 fetch, three concurrent clients, exact introduced-object counts, packs smaller than the declared fraction of the full clone, strict fsck, exact checked-out bytes, and client/server interruption followed by successful recovery. This is meaningful live protocol evidence. It does not establish throughput leadership, internet transport security, large-repository envelopes or multi-region reliability.

The historical-state suite created nonempty durable history, published a later refusal, recovered an earlier decision by decision and head identity, compared both endpoints and refused a position ahead of authority. Capsule checkpoints and positions inside multi-decision batches remain outside that cell.

Late in the selected E2E work, the audit's eight tracker additions temporarily appeared in the shared tracker because `br` defaults linked worktrees to the canonical tracker. Product source and HEAD remained unchanged; the records were preserved in the isolated tracker and the placement corrected. The results above are source-scoped observations, not an independently recorded `batch_verify` gate. This distinction also applies to any further targeted scenario run while audit metadata was being prepared.

## 3. The vision-to-product map

“Implemented library” below means there is real behavior and a tested boundary; it does not imply the whole deployment product is available. Bead references abbreviate the unique FG numbers where that is clearer. The exact records remain in the tracked issue export.

| Vision area | Present implementation / evidence | Remaining product or proof gap | Existing work |
|---|---|---|---|
| Canonical identities and encodings | `fgit-types`, `crypto`, `codec`, `reference`; native hash domains and typed bodies | Complete schema-family coverage, migration and exact producer/consumer evidence | FG-002/003 closed; `b3wy` and incarnation work active |
| One authority, seal, outcome and RCR | `authority`, `txn`, `admission`, `chronicle`; real embedded CAS/publication and recovery code | Preserve atomic outcomes across every newly wired product effect | FG-004/007/008/009 implemented; relevant integration beads remain |
| Embedded durable node | `authority-fsqlite` plus `OneNode`; fresh nonempty clone/push/history evidence | Wider operational and concurrency envelopes, service lifecycle and upgrade evidence | FG-005 and FG-028a closed; FG-028b pending |
| Remote object-store authority | Provider-neutral adapter and strict version-token probe | Built-in HTTPS transport refuses; no live remote product path proved here | FG-006 closed; uncovered residual now tracked |
| Immutable object fabric | Envelopes, microsegments, verified objects, placement/retention abstractions | Production remote placement and operational campaigns for each sold durability profile | FG-020/021 closed; FG-036/037/077 remain |
| Git object/pack/DEFLATE | Native parsers, codecs, delta resolution, indexing and writer implementations | Complete pinned corpus, resource, format and transport matrix at one revision | FG-015/016/017 implemented; ignored oracle workers and FG-090 matter |
| Clone and fetch | Live raw daemon, nonempty clone and pinned incremental fetch | Smart HTTP and authenticated SSH product surfaces; complete compatibility envelope | FG-018/028, FG-105, FG-047 |
| Push | Real raw-daemon receive path with an operator-supplied principal, quarantine and admission | Transport authentication, full policy composition, protected-ref evidence and broader adversarial cells | `hh37`, `jkbo`, FG-019c pending; FG-043r in progress |
| Import, export and hash formats | Real import/export paths; typed SHA-1/SHA-256 support | Packed-import completion, full SHA-256 transfer/push matrix and migration behavior | FG-106 active, FG-058 open, FG-059 active |
| Durable forge merge | Forge state/diff/merge logic and synchronous admission tests | Permitted OneNode merge still refuses before CAS; forge/outbox integration also unfinished | `asa3` in progress; FG-029 evidence pending |
| PRs, reviews and protection | `fgit-forge`, `fgit-policy` and related typed state machines | Durable user-facing lifecycle, current policy wiring, merge races and delivery | FG-029, FG-043r/c, FG-083 |
| Issues, discussions and inbox | Planned event-backed product | Complete write/read/notification workflows and projections | FG-045 open |
| Derived read models | `fgit-projection` exists and uses admitted sqlmodel/FrankenSQLite | Actual consumer projections, transaction outcome/cleanup/retry contract and broad evidence | FG-093a/b pending; FG-093c open |
| Identity and account security | `fgit-identity` and policy primitives; local tests | Bind authenticated clients to live transport/API operations and account lifecycle evidence | FG-042 epic open, security campaign pending |
| REST, schema and GitHub compatibility | `fgit-schema` descriptors and schema work | Admitted gateway, real API operations, generated contract/clients where specified, import compatibility | FG-048c blocked; FG-048b/049 open |
| CLI, doctor, web and TUI | CLI currently dispatches init/import/doctor/serve/export/at | Full machine protocol and useful auth/repository/PR/issue/search/run/evidence workflows; web/TUI | FG-051/050/094 open |
| TreeFS and materializers | Immutable base, COW overlay, semantic intent/export, archives and sparse manifests | Real safe sparse host directory and optional mounted adapter | FG-026/052/076 closed; uncovered residuals now tracked |
| ATP-Git acceleration | Conservative whole-object planning, exact reconstruction and trust-scoped cache code | Node/CLI product wiring, adaptive/pack/chunk profiles and measured end-to-end benefit | FG-022/023/075 implemented; remaining profiles and campaigns |
| RaptorQ, repair and GC | Coding, original-commitment validation, repair/scrub/compaction and retention logic | Deployment-bound backing storage, remaining MUST classes, real clean restore and debt control | FG-024/025/033/078/079 implemented; FG-077 and operational work open |
| Search and graph intelligence | Substantial `fgit-graph` deterministic/temporal/algorithmic libraries | Lexical/symbol search product, semantic refinement, authorized progressive query surface | FG-031/080/081/082 implemented; FG-032 open |
| Statistics and optimization | Statistical/fallback/evidence libraries and benchmark/SLO tooling | Production consumers and current exact-profile A/A, baseline/candidate and tail/cost evidence | FG-054/067 and scoped FG-036c closed; no general performance claim |
| Agent protocol and control plane | Extensive typed run/capability/situation/plan/claim/handoff/recovery code; tests now execute | Concrete task I/O, nine other live collectors, production action executor, durable broker and assembled ECC flow | FG-030 closed; FG-072/074 and uncovered assembly work remain |
| Agent tools and MCP | Protocol primitives available | Capability-narrow actual server/tools, transport lifecycle and live-client evidence | FG-096 open |
| Workflow and CI | Workflow lowering plus bounded local process runner and receipts | Workflow coordinator/check publication and hostile-code isolation; descendant/resource enforcement | FG-095b/c open; `25cs` blocked |
| Build reuse and evidence exchange | Library contracts, verified artifact/evidence handling | Integrated cache/execution/publication service and supported remote exchange behavior | FG-039/040 implemented at bounded scope; consumers still needed |
| Snapshots and bisection | Historical `fg at` has live evidence; snapshot/bisection libraries exist | Full state/capsule/batch-position scope and bisection campaign | FG-038a/b pending; FG-038c open |
| Releases and packages | Durable attempt journal, source-tree/key boundaries, inventories and signed local-root mechanisms | Real target execution entrypoint and release gate; package protocol endpoints | `0zjt` and FG-060 pending; FG-091/100 open |
| Distributed and hosted operations | Cell/routing/read-mode/SLO/fault models and libraries | Live backend integration, multi-region operations, routing decision, incident/restore/readiness evidence | FG-036b pending; FG-065/088 open; `b5ph` blocked |
| Enterprise/federation/billing | Design and some supporting primitives | Complete declared customer workflows and exact authority/domain boundaries | FG-063/101/102/103/104 and related work open |
| Proof and security assurance | Bounded models, scoped Lean claims, negative tests and source safety rules | Whole production refinement is unproved; live cross-tenant/runner/storage and independent review gates remain | FG-041 bounded; FG-066/071/072/086 and release gates remain |

This is a breadth map of the documented vision, not an assertion that every code path in each row was audited. The backend, merge, projection, runner, agent and release boundaries received deeper source tracing because they determine whether library breadth becomes a usable forge.

## 4. Findings that should change priorities

### 4.1 Durable merge is blocked before publication

The README says the real store/projection merge path reaches head CAS, leaving only outbox delivery. The source says otherwise, and the call chain supports the source's warning.

[`OneNode::admit_merge_durable_in`](../crates/fgit-node/src/lib.rs) passes its `DurableAdmissionMaterializer` into `admit_merge_async`. That async function's commit branch still invokes synchronous materialization. The materializer's synchronous `stage_ref_state` and forge-body staging methods return `DurabilityProfileUnavailable`. The explicit known-defect comment starts at node line 6698; the rejecting implementations are around lines 2053 and 2141. Thus a permitted durable merge cannot complete this path.

The cited [`merge_admission_race.rs`](../crates/fgit-admission/tests/merge_admission_race.rs) uses synchronous `admit_merge` with a test `Store(Rc<Commitments>)`. Its passing result is useful bounded admission evidence. Promoting it to proof that the durable OneNode composition can commit is proof-class inflation (RH-2). `asa3` already owns the complete fix: retain its full acceptance scope and require a real reopened-node success beside the refusal/race cases. Do not create a duplicate “merge done” bead or close on outbox work alone.

### 4.2 Projection implementation exists, but its acceptance mapping is incomplete

The installed sqlmodel 0.4.2 stack now compiles and the projection tests execute; the README's eight-error sqlmodel blocker is stale. However, `fgit-projection` is primarily a watermark/identity/applied-decision substrate, not an implemented issues/PR/search/API read model.

[`session.rs`](../crates/fgit-projection/src/session.rs) collapses cancellation and panic into `ProjectionError::Interrupted` (`flatten`, lines 79–86), despite the sibling profile requiring preservation of four-way outcomes. Inspection did not find the promised explicit close/join and whole-transaction transient-retry implementation. The code also documents that part of the identity decision-range receipt does not advance with folds. These are specific acceptance concerns for FG-093b, not merely future consumer UI work. Its `batch_pending` status deserves line-by-line review against the existing acceptance criteria before closure. FG-093c's campaign cannot excuse missing implementation in FG-093b.

### 4.3 Release primitives are ahead of the actual release command

[`fgit-release-attempt`](../crates/fgit-release/src/bin/fgit-release-attempt.rs) accepts only `--release-gate-probe`. The attempt library can journal files/results and sign a local root, but its production target step is injected and the default is unavailable. The release E2E script explicitly says its fixture supplies terminal target results and claims neither an OS target executor nor a published release.

`0zjt` nevertheless has acceptance requiring the real host target through runner obligations and `verify.sh release` returning zero for a host-only completed matrix. The current script returns three. Its pending status cannot be treated as satisfaction of those conditions. Preserve FG-091's independently defined required-suite set and complete the real runner/CLI/signing path; do not redefine “release” as a successful probe.

### 4.4 A hosted adapter and a hostile runner are not available by implication

[`fgit-object-store`](../crates/fgit-object-store/src/lib.rs) has real provider-neutral protocol logic, but its built-in TLS constructor unconditionally refuses. Scripted HTTP responses do not establish a live hosted backend.

[`ProcessSubstrate`](../crates/fgit-runner/src/lib.rs) is explicitly for trusted local commands. It does not establish namespaces, cgroups, comprehensive descendant containment or measured CPU/memory/disk/network enforcement. The ADR and blocked `25cs` agree. A typed isolation policy and a passing local command are not sufficient to accept hostile CI workloads.

### 4.5 Agent architecture is extensive; the useful production loop is missing

The current control plane has much more than empty types: exact run identities, claim persistence orchestration, revocation, ancestry, recovery and cross-head transfer logic are substantive. The stale status document even understates the newer cross-head implementation.

But its own boundaries still lack concrete backend I/O, nine production situation collectors, an action executor, a durable broker journal and complete ECC orchestration. The CLI also does not expose the envisaged complete agent operations. Finishing more receipt types without connecting these consumers would deepen the imbalance. Reuse the existing abstractions for one persisted, restartable, authorized source change with real tool evidence and ordinary admission.

### 4.6 The native-linkage checker misses real build evidence

The fresh build emitted, for example, `debug/build/serde/<hash>/run/stdout` and analogous files for libc and crc32c. [`collect_native_linkage`](../tools/registry-check/src/enabled_macros.rs) searches only older `output` paths. The checker therefore repeats “build once” even after a successful build. The missing evidence is observed; forbidden native linkage is not alleged. Fix discovery with exact target/profile/package provenance and planted positive/negative controls, then reevaluate the evidence.

### 4.7 Specifications and snapshots disagree

The comprehensive plan's §0.3 precedence order conflicts with AGENTS.md §2. Its §4.2 puts merge queue in subsequent scope, while its v1 definition of done and the compatibility matrix require it. Its licensing completion criterion conflicts with the already resolved D14 choice, `LicenseRef-MIT-OpenAI-Anthropic-Rider`; the rider must not be called OSI-approved open source. The root Cargo.toml comment also retains the unsafe incremental crate-creation order that AGENTS §16.1 explicitly replaced.

These are contract-reconciliation tasks. This assessment does not silently choose new publication semantics, weaken v1 requirements or reopen the owner's licensing decision. Separately, the README's nonexistent historical-E2E and current sqlmodel-blocker claims should be updated with the newly observed evidence, while its durable-merge claim should be demoted.

## 5. What the tracker does and does not cover

The baseline has **556 non-tombstone issue records**: 445 closed, 69 open, 26 batch_pending, seven in progress, four blocked and five deferred. The wrapper encounters another 25 tombstones in the raw export. The dependency graph has 754 edges and no cycles. `br ready --unassigned --no-db --json` returned an empty array. Advisory importance does not make an assigned or blocked issue claimable.

There is substantial existing coverage for the missing product: HTTP, SSH, policy rewiring, durable merge, projections, search, issues, API, UI, MCP, workflow execution, isolation, packages, hosted operation and release gates already have work. Generating another umbrella backlog for those would create competing ownership rather than progress.

**Implementing only the currently open and in-progress records would not establish the whole vision.** It would omit pending/blocked/deferred work, independent acceptance verification, residual gaps beneath closed beads, and the uncovered adapters above. Even completing all known issues is insufficient if completion continues to mean a narrower library result than its acceptance conditions.

The strongest coverage defects are residuals under closed FG-006 and FG-052, production agent assembly absent from the active task descriptions, and the newly observed native-linkage evidence-discovery defect. Eight additional records cover these plus contract reconciliation. Existing assignees, statuses, acceptance conditions and closure gates are preserved.

## 6. Bridge plan: ship coherent capabilities in dependency order

### A. Restore a usable evidence baseline without confusing it with feature progress

Resolve the current formatting and Clippy findings through the existing wire owner; fix the native-linkage discovery defect; independently review pending acceptance mappings; reconcile contradictory instructions and stale present-tense claims. FG-091 must connect the real exact-suite matrix to `full` and `release`, retaining typed non-pass cells. Exit criterion: a reproducible current fast result and an honest full/release inventory. Formatting alone earns no forge capability credit.

### B. Deliver one authenticated durable forge operation

Prioritize FG-047/105, FG-043r, `asa3`, FG-093 and the forge event/outbox consumer as a single customer-visible chain: authenticate, read protected state, push a proposed change, open/review/merge it, observe the new ref and forge state, restart, and recover the same outcome. UI expansion should consume this chain rather than invent a parallel write path.

Exit evidence must include one real permitted merge through OneNode, two competing merges with exactly one winner, stale/revoked policy refusals, lost-response retry, crash before/after CAS, coherent projection rebuild and idempotent outbox delivery. Ref and forge state must publish in the same RCR. Existing open issue/notification and webhook work remains required for its declared scope; it is not traded away to call this milestone complete.

### C. Make agent-native behavior usable over those real components

Connect the concrete task store, all generation-bound collectors, a safe host TreeFS workspace and the durable action executor. Reuse existing control-plane authorization and recovery APIs. Coordinate with FG-051/096 for public machine interfaces and FG-072/074 for independent verification/delegation; those existing owners retain their work.

The demonstration must survive a fresh-process restart with its original sealed identity, reconcile ambiguous effects, publish through ordinary admission and prove cleanup. A model need not be required for deterministic conformance: a supplied agent action plan can exercise the real product orchestration, while model-mediated behavior has its own recorded harness identity. Do not substitute mocked host effects for the conformance path.

### D. Complete the single-node team product

Implement the remaining declared issues/reviews/inbox, account lifecycle, REST and full CLI, progressive search, workflow coordination, package/artifact and UI surfaces against those shared write/read APIs. Use one watermark contract and authorization before disclosure. Complete the blocked hostile-runner prerequisite before accepting untrusted workflows. Close existing acceptance conditions where they belong; do not move missing functionality to follow-ups to close an epic.

### E. Add real remote operation and recovery

Connect the admitted HTTPS authority transport and chosen backend; validate its nonstandard authority requirements rather than assuming generic object-storage parity. Resolve `b5ph` routing authority before rename/transfer/cutover implementation. Complete current distributed fault, clean restore, RaptorQ-required classes, cross-tenant and operational-degradation work on actual declared storage/runtime profiles.

Measure RPO/RTO, resource floors and repair/checkpoint/outbox debt, plus requests, bytes and cost. Statistical routing or repair heuristics must preserve deterministic fallback and cannot acquire authorization/deletion authority. A single-host multi-cell test is not a multi-region deployment result.

### F. Publish an actual independently verified release

Finish `0zjt` and FG-091 with a real bounded runner target command, exact source snapshot, complete requested assets, key-purpose-bound signatures, verified root-last manifest, clean resume and withheld publication on any missing target. Default host support must not imply a complete cross-platform matrix. Remote releases remain distribution adapters. Include installation, rollback, schema migration and a clean restore rehearsal for the declared release profile.

### G. Earn performance and later-scope claims from the integrated system

Keep ATP profiles, sparse sharing, batching, graph/statistical refinements, federation, managed runners and enterprise extensions in their existing dependency graph. Select optimizations from measured end-to-end bytes/work/latency/cost and preserve A/A controls, scalar/reference equivalence, tails, rollback and negative results. The live incremental-fetch result is a useful starting mechanism witness, not a general speed claim. The optional FUSE adapter stays explicitly optional; it is not silently required to make the unmounted node useful.

## 7. Plan refinement and safeguards

The ambition passes expanded the plan from local test health to (1) a complete durable forge operation, (2) a persisted agent operation and (3) operational recovery, release and economic evidence. They preserve the full documented scope while giving each milestone a real consumer and observable exit.

Four refinement passes checked the proposed work against existing ownership, authority/cancellation contracts, positive and negative runtime evidence, and dependency/readiness behavior. They removed duplicates for merge/release/projection, made the optional mount separate from required host workspaces, made the task adapter's actual atomicity a prerequisite rather than an assumed br capability, and pinned every new acceptance claim to a real operation. The final review retained eight new records and no source implementation changes.

Before implementation, the assignee must rederive HEAD, dirty paths, reservations and exact authoritative readiness. This report does not authorize taking an assigned bead. `batch_pending` remains a handoff, and the batch orchestrator alone records a revision-bound gate and closes a bead.

## 8. Audit-branch additions and evidence appendix

Eight new unassigned records are preserved on `audit/reality-20260907`, in the isolated worktree `/tmp/frankengit-reality-worktree-20260907-VdyQfM`. They are not yet merged into the shared main tracker. To inspect that tracker, explicitly set `BEADS_DIR` to the worktree’s `.beads` directory; a plain br invocation otherwise resolves to the main tracker. Existing issue records remain byte-identical to the baseline.


| New bead | Priority/type | Concrete obligation |
|---|---|---|
| `frankengit-audit-native-linkage-l0xt` | P1 bug | Current nightly build-script evidence discovery |
| `frankengit-audit-objectstore-https-88g7` | P1 feature | Live remote authority transport and backend conformance |
| `frankengit-audit-treefs-host-zb0q` | P2 feature | Real safe sparse host workspace |
| `frankengit-audit-treefs-fuse-mwck` | P3 feature | Optional real mount; depends on host workspace |
| `frankengit-audit-agent-task-store-xcu9` | P1 feature | Concrete durable task/Beads adapter |
| `frankengit-audit-agent-collectors-sjzo` | P1 feature | Actual generation-bound situation sources |
| `frankengit-audit-agent-execution-p7sa` | P1 feature | Persisted agent execution, recovery and ordinary admission |
| `frankengit-audit-contract-reconcile-fjsz` | P1 question | Resolve contradictory instructions and stale implementation claims |

The agent task adapter depends on the existing projection implementation. Live collectors depend on that adapter and existing search/compatibility-ledger work. The executor depends on the adapters, real TreeFS host workspace, hostile-isolation prerequisite and verifier-independence work. This keeps the full production acceptance blocked on its real prerequisites while allowing ready foundational tasks to proceed. No existing bead was reassigned, self-closed, split or weakened.

Five selected E2E suites passed **178 distinct acceptance IDs** across two runner invocations. This is intentionally not a full-suite result. Counts by suite: first clone 19, first push 21, historical state 15, pinned incremental fetch 97, SHA-256 repository 26. Both invocations report no containment failure, malformed evidence, hidden skip or retry-laundered pass. The ordinary-client cells and pinned-oracle cells retain their different evidence classes.

The source audit did not execute every ignored corpus worker, a complete Miri/fuzz/Lean campaign, an untrusted-runner escape test, a live remote object-store/multi-region campaign, the XL push envelope, a full cross-target matrix or a signed production release. The absence of those results is not reported as a source failure or a pass.

Selected raw evidence digests (SHA-256), all under the scratch evidence directory named in section 1:

| Artifact | Digest |
|---|---|
| `workspace-tests.stdout` | `9fcc92381cc04940ba7ec0feca5587f60fb9c3b3ccdbb2da9545bfe2a734e197` |
| `workspace-tests.stderr` | `b4f7245532ab72b2c823c142f03c3a06ea60085fd876b3b56a0ae9230224d912` |
| `fast.stdout` | `8e658b5e273a88c2991921fd2fd832bfae16b34e9b45ce62cdc491ac456e518a` |
| `fast.stderr` | `d619c0fb8bf19ba57de50b64ac143a6e05b8ad460e9082465b81f325ba4887eb` |
| `clippy.stderr` | `1958f1ad3b9ce16ee969f9f6d155389204b30d034caadc91629b4c2e08303baa` |
| `e2e-selected/receipt.ndjson` | `3ef78a3afe921e24de4216554a2465e17bc3e2578315c62210782b24591026b7` |
| `e2e-sha256/receipt.ndjson` | `ea6e6ab7947535d5d451b97b73a2611e447e5370126c9eea5140cf2512c86fcd` |
| `full.stderr` | `85055b83dde3934730c1abf62c2a9c7803b9e877a9692064514037cae9ccd3a7` |
| `release.stderr` | `0377e6cbc35810f2591ad13f8640e6eb77b5b483cee5f6f32b3c138146e24854` |

Raw logs are local review artifacts, not published durable evidence. Commit and target/toolchain binding, limitations, summary counts and artifact digests are preserved here so these observations cannot be confused with later runs.

Final tracker validation used the isolated `BEADS_DIR`: 564 non-tombstone records, 768 dependency edges, no cycles in both br and the compatibility-wrapped bv graph. Exactly four new records were authoritatively ready and unassigned: native-linkage discovery, remote HTTPS authority, sparse host workspace, and contract reconciliation. The other four retain their declared dependencies. The pre-existing 556 issue records remain byte-identical; the shared main checkout returned to its original clean state. No bead was claimed or closed during this assessment.

The two-file audit change consists of this report and the eight added JSONL records. The documentation lane and whitespace check completed successfully on that draft; the handoff also records validation at the final audit commit. Full raw evidence stays outside the source tree.
