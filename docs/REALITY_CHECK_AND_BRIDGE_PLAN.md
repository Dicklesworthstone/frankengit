# FrankenGit reality check and bridge plan — 2026-10-21

FrankenGit contains a substantial bounded native Git node and real forge mechanisms. It is still an integration-stage product. The source does not yet deliver the complete authenticated team forge, sponsored agent workflow, operational recovery, scale, or release promised by the plan. This is not an empty scaffold, and counting completed beads is not a measure of how close those outcomes are.

**Source:** `26c6a7f196496df1ca7ac663418ff9d2791b9550`, inspected in a clean isolated worktree on `codex/reality-check-20261021`. Runtime code and tests were not changed by this assessment. Results below bind this source, not subsequent `main`. Dates use America/New_York; raw tool timestamps may be October 22 UTC.

**Consumer, gate, defect and retirement:** the owner and independent batch verifier use this existing plan to select the work gating a usable team deployment. Observed defects are incomplete product joins, history-dependent resource cliffs, stale verification/ownership claims, and blocked exact-source execution. Supersede this document in place after the next revision-bound assessment; it grants no authority to deploy, close issues, ratify architecture, or weaken gates.

## 1. What changed since October 20

- The tracked verification queue has drained materially: **13 batch_pending + 9 in_progress = 22**, compared with the prior intake's 36. There are **507 closed, 98 open, 20 rework, 10 blocked, 5 deferred**, 662 live rows and 25 tombstones. These are intake counts, not capability credit.
- `.4.56` now records non-author review of the IcyIbis pending wave. Its disclosed independence is another session/context/worktree within the same model family and harness, without human independence. The old statement that 21 IcyIbis items remain pending is obsolete. The appointment/independence question remains with the owner; this audit does not validate every closure.
- Native required checks and quorums remain real admission gates. Workflow branch filters and trusted squash-candidate workflow composition have landed. A source-head PR workflow is still different from testing the synthetic merge candidate.
- `fgit-agent` is now a normal dependency of `fgit-node`. `source_retrieval/agent_context.rs` constructs a head/RCR/forge-position-bound ContextPacket. **No product call site for `context_packet_for_run` was found.** A dependency edge and public bridge are not a working sponsored agent run.
- The production `#[expect]` checker hole was addressed in `cf0b531f`; licence-file fields, workflow pin overrides and the missing agent lockfile edge were repaired in `c16bb765` / `05ff5b45`. Older claims that those particular defects remain unfixed are obsolete. `.4.15` still owns substantial remaining contract/registry drift.
- Receive ingress/processing/response budgets have an implementation and focused historical native evidence at `7fb8cf97` (`3gdw`). The cancellation-timer repair `465a807d` and Unix-socket fixture correction `ceb9a21e` are present; `lq27` remains in progress without fresh execution of that repair here.
- The current browser module profile is much healthier; the current formatter is not clean (§2). Larger-repository merge limits are a major additional product blocker (§4), already owned by `rffg`.

## 2. Fresh evidence and limits

Host: arm64 macOS; pinned Node **26.8.1**; pinned Rust **nightly-2026-08-31**, rustc `90850177249efe0321573c569aec5d12b257f8d6`; installed Apple Git **2.50.1** is only a test peer, not the pinned compatibility oracle. Full raw streams and intake/closure/graph data are outside source at `/private/tmp/frankengit-reality-20261021`; `evidence-summary.json` indexes their SHA-256 digests. Browser TAP: `575c08a6c33104742bf766be3c916bf4ba46a6fd9d9eb796c0a1584bed13f0f1`; scripts TAP: `240bdfac54650e8f7e4172143bcaed7daf12ff28cff3fec499f6a403c80de1a6`.

| Check at `26c6a7f1` | Observed result | What it establishes |
|---|---|---|
| Full AGENTS.md / README.md intake | 484 / 802 lines read | Contribution contract and complete README vision; not product proof. |
| Pinned bootstrap metadata | exit 0 | Pin and transport URLs agree; no toolchain advancement. |
| Licence gate | exit 0 | Exact `LicenseRef-MIT-OpenAI-Anthropic-Rider`, OSI marker `no`. |
| `cargo fmt --all -- --check` | **exit 1**, one file | Extra blank line in `fgit-node/src/source_retrieval/agent_context.rs:52`; October 20 formatting success has regressed. No source edited to repair it. |
| Pinned browser JS profile, 122 files | **exit 0: 3,635 passed, 0 failed, 1 skipped**, 3,636 tests | Clean-source Node/module evidence, 122.9 s. Chromium case skipped; not a complete real-browser or native-server gate. Owned process group reported quiescent. |
| Pinned operator JS profile, 166 files | **exit 124 at campaign deadline (600 s)**, no terminal suite aggregate; process group quiescent, failure artifacts retained | Retain terminal result and first failures; no live-fg claim from peers/doubles. |
| Pinned scripts JS profile, 66 files | **exit 0: 1,394 passed, 0 failed/skipped**, 319.0 s; owned process group quiescent | VM modules enabled by owned profile; same evidence limits. |
| Strict remote CLI/all-target syntax attempt | **exit 103 / RCH-E413 before compilation** | Healthy worker selected; fixture-manifest preflight defect (§4). No compiler/test outcome. |
| Storage admission | **exit 1, critical**, about 190.9 GB free / 4.78% | Absolute free bytes do not override the configured ratio gate. `/data/frankengit-targets` absent locally; no local compiler fallback. |
| Remote fleet read | 14/16 workers healthy/reachable | The old fleet-not-ready explanation is obsolete; this does not prove build admission or worker execution. |
| Pinned Git oracle verify | **exit 69**, no local binary receipt | Current Tier A not executed; installed Git is no replacement. |
| Claims artifact digest comparison | CLM-001..005 match; two CLM-006 artifacts differ | Source identity only, not rerun Lean proofs or Rust refinement. CLM-006 remains `implemented`. |
| Public [GitHub Releases API](https://api.github.com/repos/Dicklesworthstone/frankengit/releases?per_page=5) | empty list, October 21 | No GitHub release observed; no complete distribution-channel or live-deployment inventory. |
| Wrapped graph analysis | initial 687 rows, 25 tombstones; no cycles | `BV_BIN=/Users/jemanuel/.local/bin/bv` (0.25.2); PATH's 0.12.0 refused by wrapper. `br` alone authorizes claims. |

No current native binary is available in this checkout. Following AGENTS §16.2, the audit attempted the permitted syntax gate, rather than appointing itself union verifier. Native tests, Clippy, real-client E2E and the canonical fast lane were **not** run here. `scripts/verify.sh` itself still exports the prohibited local-build bypass; it was inspected, not used to override that contract. Its `full` function unconditionally refuses and its `release` path also ends in a dormant refusal. There is no current one-SHA full/release result from this assessment.

Historical evidence stays useful within scope: Tier A is 18 rows and 624 checks at `18f77336` over `git://` only; native deadline tests at `7fb8cf97`; the Clippy census in `.4.26` at `d9cf96e9` reports 1,373 findings across 13 crates with a capped-lint diagnostic census, while the actual deny-warnings lane stops in fgit-schema. None is silently promoted to this source. Prior October 17/20 failure counts are not a current failure inventory.

## 3. Vision checklist and existing ownership

PARTIAL means real implementation with missing breadth/integration. LIBRARY means the named mechanism lacks a normal product consumer. UNPROVEN means its required outcome lacks current executed evidence. REFUSED identifies explicit unsupported behavior. None of the broad goals below is promoted to WORKING solely from source/test presence or an older pass.

Abbreviated `.4.N` is `frankengit-root-doctrine-x2mv.4.N`; FG names identify uniquely titled tracker records. The matrix retains every class from plan §4.1, §44 phase exits and §49 completion criteria.

| # | Testable goal | Reality / remaining outcome | Status | Existing owner |
|---|---|---|---|---|
| 1 | Create/import/export and retry exact native repositories | CLI/node, bounded spool, batch placement; scale/recovery campaign outstanding | PARTIAL | FG-106, `gzdy`, `pc9g`, `eq4h` |
| 2 | Ordinary Git in declared SHA-1/SHA-256 Tier A | 18 rows, historical pinned success; current revalidation needed | PARTIAL | `.4.60`, FG-090, FG-098 |
| 3 | SSH/HTTP usable beyond one trusted host | Real adapters; loopback HTTP, no admitted native TLS | PARTIAL | FG-105, `.4.30`, `.4.13` |
| 4 | Atomic refs and ref/forge merges | Real admission/head CAS; restart/race breadth gated | PARTIAL | `.4.20`, `.4.58`, FG-019c |
| 5 | Users/orgs/teams and authenticated revocable actors | Identity library and transport bindings; CLI/MCP trust supplied principals | PARTIAL | `.4.13`, `.4.34`, FG-101 |
| 6 | Protection enforces current reviews/checks | Native candidate checks and review quorums; general policy integrity unresolved | PARTIAL | `.4.6`, `.4.12`, `.4.20` |
| 7 | PR/comments/reviews/reopen/merge | Real native/API/browser paths; full-history merge ceilings block larger repositories | PARTIAL | `.4.20`, `.4.23`, `.4.58` |
| 8 | Issues/discussions/notifications | Issues and assignment events; complete discussion/notification product absent | PARTIAL | FG-045 |
| 9 | Event API and settled webhook delivery | Feeds exist; dispatcher reports `canonical_settled:false` | PARTIAL | `.4.35`, `.4.55`, `.4.57`, `e0eg`, FG-046 |
| 10 | Safe Markdown and reliable browser UI | Native rendering and JS pages; Rust/WASM primary stack and full browser qualification incomplete | PARTIAL | `.4.11`, `.4.46`, FG-050, `.4.14` |
| 11 | Fresh lexical/symbol search after writes | Real indexes/stamps/guarded publication; automatic maintenance/retention incomplete | PARTIAL | `.4.19`, FG-032a/b/c |
| 12 | CI trigger → run → publish → gate | Native watch/report/artifact/check paths; trusted host only | PARTIAL | `.4.12`, `.4.70`, `25cs` |
| 13 | Sponsored agent run through ECC | Agent now in node dependency closure; authority-bound context bridge has no product call site; full run absent | PARTIAL / UNPROVEN | `.4.24`, `.4.34`, `p7sa`, `xcu9`, `sjzo` |
| 14 | Independently restore accepted source and forge state | Native backup/bundle pieces; substantial JS orchestration; full drill required | PARTIAL | `.4.21`, `.4.42`, `.4.62` |
| 15 | Conforming off-node object-store deployment | Adapter exists; built-in HTTPS refuses; node fabric not composed | REFUSED / LIBRARY | `88g7`, `.4.61` |
| 16 | Live GitHub migration round trip | Extensive JS migration/custody; stand-in peers dominate tests | PARTIAL | FG-049, `.4.59` |
| 17 | One outcome, stable retry, exact publication | Real authority/chronicle/admission; current union gate absent | PARTIAL | `.4.29`, `.4.47`, `.4.51` |
| 18 | Hot-repo lanes/combiner/witness scaling | Components exist; node writer gate 1; product combiner/witness absent | LIBRARY / UNPROVEN | `.4.9`, `.4.39`, `.4.63` |
| 19 | ATP transfer parity and measured savings | No product dependency path | LIBRARY | `.4.22` |
| 20 | Sparse shared TreeFS without full clones | Trusted Linux adapter/command custody; shared-base cost/FUSE incomplete | PARTIAL | `zb0q`, `mwck`, `.4.38`, `.4.40` |
| 21 | Position-bound graph decisions and witnesses | Useful ancestry/index code; nine graph registry rows `specified` | PARTIAL | `.4.36`, `.4.64`, FG-064 |
| 22 | GC/retention/repair/RaptorQ on node data | Codec/library slices, no composed product path | LIBRARY | `.4.10`, FG-077, FG-036 |
| 23 | Verified reads and time travel | `verify-read`, `at`, `bisect` and historical E2E; current/broad coverage incomplete | PARTIAL | `.4.41`, `c7tb`, FG-038b/c |
| 24 | Statistical operational adaptation | Controller constructed; no production observe/backoff call in retry loop | PARTIAL | `.4.37` |
| 25 | Evidence exchange and build reuse | Typed libraries without product adoption | LIBRARY | `.4.68`, `.4.69` |
| 26 | Formal production refinement | Contained Lean model and bounded trace bridge, not a Rust proof | PARTIAL | `.4.67`, FG-041 |
| 27 | Native signed DSR release matrix | `full` dormant, release publication unsupported | REFUSED | FG-035, FG-091, `0zjt` |
| 28 | Upgrades/security/external adopter success | Open campaigns; source presence cannot satisfy them | UNPROVEN | `.4.62`, `.4.65`, `.4.66` |
| 29 | Measured throughput/economics/RPO/RTO | Bounded samples; published deployment targets/drills absent | UNPROVEN | `.4.63`, `.4.21`, FG-036 |
| 30 | Hosted/federated/packages/dogfood | Fragmentary protocols, no complete operated service/release loop | PARTIAL / UNPROVEN | FG-063/065/100/102/104, `.4.25` |

The current owning paths were checked against the matrix, including the following publication/disclosure joins:

- Git serving/import: `fgit-cli/src/{main.rs,import_command.rs}`, `fgit-node/src/{lib.rs,smart_http.rs,quarantine_validator.rs,upload_visibility.rs}`, shared receive-session drivers, `fgit-pack`, `fgit-wire` and `fgit-git-object`.
- Canonical publication: `fgit-admission/src/merge/native/{protection.rs,objects.rs}`, `fgit-node/src/treefs_workspace/native_merge.rs`, authority/chronicle/transaction crates. Exact candidate checks and latest review quorums are actually called by native admission; they are not merely policy APIs with no callers.
- Retrieval/agents: `fgit-node/src/source_retrieval/{context.rs,agent_context.rs}`, CLI/MCP retrieval adapters, `fgit-agent` protocol/control-plane exports. Retrieval context explicitly calls itself untrusted source data; only the uncalled bridge constructs an Agent Protocol packet.
- UI/transport: the loopback restriction is enforced in `fgit-node/src/smart_http/server.rs`; `browser.rs` embeds `.mjs` modules. The UI is implemented, but differs from accepted ADR-0013's primary Rust/WASM selection.
- Delivery/recovery: native canonical outbox APIs and CLI webhook dispatcher/journal are distinct. `docs/WEBHOOK_DISPATCHER.md` explicitly disclaims canonical settlement; backup/source-bundle verification and publication paths retain original-identity/profile boundaries.
- Adaptive retry: `fgit-authority-fsqlite/src/adaptive_retry.rs`, `engine.rs` and `portable_store.rs` construct/expose the controller; production retry loops still do not feed observations or consult its backoff policy.

A manifest traversal includes normal dependencies under target-specific tables (Linux runner included), excluding dev/build edges. It finds **48 crates**, 35 in `fg`'s union normal dependency closure and 13 outside. Five outside are tooling/evidence/release-oriented: benchmark, lab, proof-bridge, release and SLO. The remaining **eight product islands** are ATP-Git, compaction, exchange, object-store, projection, RaptorQ, repair and witness. This is a static manifest result, not target-specific linker/dead-code proof. The agent bridge illustrates why reachability alone is insufficient.

A keyword scan over 1,326 crate `src` Rust files (601,624 lines, including inline tests) found no `todo!`, `unimplemented!`, unsafe block, `extern "C"` or `asm!` matches; crate-root forbid declarations are present. This is a lexical screen, **not** an AST audit, transitive dependency audit, proof of no stubs, or evidence that product callers exist. Behavioral and call-site inspection, explicit refusals and absent consumers determine the judgments above.

## 4. Controlling defects and stop conditions

### 4.1 Ordinary repository size blocks the team workflow

`fgit-forge/src/preparation.rs:90` defaults to 4,096 commits / 16,384 edges; `validate` refuses larger caller limits. `source_merge_bases` builds the complete ancestor index of both tips before querying their bases. An uncomplicated near-tip PR can therefore fail because of unrelated old history. `rffg` records native probes at other named builds (200 commits allowed, 5,000 refused); these are corroborating historical observations, not fresh runs here.

There is a second bound even when commit history is tiny. `fgit-admission/src/merge/native/objects.rs` validates the candidate's complete reachable closure, including blob bodies, under **100,000 objects, 400,000 edges and 128 MiB total**. Larger supplied limits refuse. `rffg` records a two-commit/100k-file probe failing during preparation. Thus simply removing the merge-base cliff will not make larger repositories mergeable.

Fixes need authority-bound reusable ancestry/closure evidence and bounded delta/frontier work, with exact reference-oracle equivalence, rather than a blind constant increase or treating an unauthenticated index as authority. The present bounds remain safety semantics until their contracts are deliberately revised. `rffg` and `.4.36` own this work; no duplicate feature epic is needed.

### 4.2 Sustained operation and throughput remain bounded

Forge-position and outbox canonical bodies still cap state entries at **16,384** (`fgit-codec/src/canonical_state.rs`). This is not automatically a universal lifetime event count: stream/frontier layout controls consumption. Required checks independently scan at most **4,096 history steps, 65,536 batches/events, 128 MiB** (`merge/native/protection/checks.rs`). A valid old success must never outlive a later canonical failure merely because an accelerator missed it.

`MAX_CONCURRENT_WRITERS = 1` in the node still controls the live listener writer gate. Per-core preparation, deterministic batching and witness libraries are not evidence of product throughput. `.4.7/.9/.36/.39/.63` must bind reusable histories/checkpoints, conservative conflict witnesses and real measurements to their consumers.

### 4.3 Exact-source remote verification is presently blocked

The final syntax command used explicit `--base 26c6a7f... --clean-overlay --no-overlay`, strict remote execution and a private target. RCH selected healthy `ts1`, then classified deliberately invalid checker fixtures as selected Cargo sources:

1. `tools/registry-check/tests/fixtures/crate_graph/forbidden_surfaces/crates/forbidden/Cargo.toml` intentionally names absent `build.rs`.
2. `tools/registry-check/tests/fixtures/workspace_inheritance/table_header/crates/table/Cargo.toml` intentionally uses `/absolute/unpublished`.

These are checker input data outside the selected CLI workspace/dependency graph. Preflight must distinguish that role while still transferring fixture bytes for checker tests, and still reject equivalent invalid **real selected dependencies**. Do not remove or weaken planted negatives, disable preflight, or treat refusal as a compiled result. The upstream/source-selection repair and a regression test belong to `.4.72`, related to `.4.26/.18/.15`.

Earlier launch corrections were invocation failures: `--source-content-receipt` is incompatible with clean-overlay, the `/private/tmp` worktree is outside the configured canonical root, and clean-overlay requires explicit no-overlay selection. They were corrected before the final reproducible preflight refusal; none is a product failure or successful compiler run.

### 4.4 Trust and delivery boundaries are incomplete

CLI/MCP trusted-local writes still accept operator-asserted principals. HTTP requires loopback and operator/scoped credentials; no listener terminates admitted native TLS. SSH deploy keys do not establish a complete account/org/team/revocation product. Required-check enforcement does not by itself complete general policy integrity or hostile CI isolation (`25cs`).

The dispatcher can durably journal at-least-once HTTP attempts, including ambiguity and retry custody, but continues to report `canonical_settled:false`. The strong native settlement abstraction existing separately does not make this dispatcher drain canonical obligations. `.4.55` remains an integration obligation even when `.4.57` fanout tests are repaired.

### 4.5 Architectural contradictions require owner decisions

- AGENTS §16.2 prohibits `RCH_CARGO_WRAPPER_BYPASS=1`; `scripts/verify.sh` unconditionally exports it while quoting obsolete rules. The bring-up fallback and inherited root bead context also retain obsolete local-build instructions.
- Constitution/integration text still requires Asupersync 0.4.x and says no constellation exists; current admitted manifests/locks select 0.5.0. The source profile also retains older fsqlite/adopted-sibling premises. `.4.15` has partially fixed other drift, not this contradiction.
- ADR-0011 adopts fastapi_rust and ADR-0013 a real-DOM Rust/WASM primary UI. The implemented owned HTTP gateway and JS primary/browser/operator surfaces differ. A supported TS/React alternative does not silently ratify the current primary stack. `.4.14` and FG-048c retain the decision/admission boundary.
- Default legacy JS bundle decoding still implements pack/delta/inflate/idx outside the Rust engine decision. Selecting native verification for some paths is progress; `.4.44` must retire or explicitly ratify the remaining path.
- Plan §4.2 places merge queue/packages later; §49.10 includes them in 1.0. The plan already records this contradiction; `audit-contract-reconcile-fjsz` owns it. Preserve both scopes until owner resolution.
- Current dependency policy explicitly describes psm's host-assembled stack stub; the required pure-Rust/native-linkage ruling and remaining stale rationales belong to `.4.14/.15`. A source-level forbid scan does not resolve them.

Affected implementation must stop at those decisions; independent work can continue. This report neither changes the constitution nor selects whichever text is convenient.

## 5. Would completing existing beads finish the vision?

**Coverage is substantially present; completion is not established.** Every top-level goal in §3 has existing non-closed ownership. That is not evidence that every acceptance detail is adequate. In particular, original titles, descriptions and historical receipts can disagree with newer code and with the owner decisions they depend on.

Finishing implementation checklists without the protected team-day `.4.23`, real-agent `.4.24`, context/graph exit `.4.64`, independent security `.4.66`, restore/upgrade `.4.21/.62`, external adopter `.4.65`, and actual DSR release joins would still leave the vision undelivered. An external organization, a live provider, a production workload and independent verifier cannot be replaced by a fixture or a project actor's assertion.

No top-level NO_BEAD class was found. The newly observed RCH fixture-selection defect lacked an exact owner and receives one bounded defect with its regression tests in the same unit of work. Existing owners receive updated evidence/refined exits, rather than a second competing roadmap or separate test-only beads that evade AGENTS §16.2.

## 6. Bridge plan: concrete exits and owning work

All exits bind one source SHA, source/toolchain/target/profile, exact inputs, complete raw streams, assertion IDs, first failures, and non-claims. Missing/ignored/skipped/timed-out cells remain non-pass. Code and its unit/refusal/cancellation/resource/crash tests stay together; independent integration campaigns stay independent. Sizes indicate breadth, not calendar estimates.

| Order | Change and owning records | Executable success, refusal and recovery exit | Size |
|---|---|---|---|
| A | Restore exact-source execution and current union: `.4.72`, `.4.26/.29/.18/.15/.56` | Distinguish fixture data from real Cargo inputs without source omission; real invalid-dependency twin still refuses. Correct source formatting, run allowed independent one-SHA docs/constitution/schema/check/tests/Clippy plus all required product/browser/operator cells. Record verifier independence rather than replacing it with another status artifact. | L |
| B | Make ordinary-repository PR work bounded: `rffg`, `.4.36/.20/.58` | Persist/reuse authenticated ancestry and closure evidence at the selected head, with bounded incremental work. Tiny PRs over >4,096 commits, >100k objects and >128 MiB admitted content prepare/review/merge correctly in both formats; missing/corrupt/stale evidence and exhausted work fail closed. Compare candidates, bases, full objects and atomic ref/PR/outcome state to the exact oracle. | XL |
| C | Supported authenticated team deployment: `.4.13/.14/.30`, FG-048c/050, `.4.23` | Resolve stack/TLS boundary, bind real users/teams/revocable credentials at writes and disclosure. Two users clone/push/review through HTTP/SSH; wrong principal/ref/path, revoked key, CSRF and stale-policy twins publish/disclose nothing. Restart preserves the original stable outcome. | XL |
| D | Exact protected PR/CI loop: `.4.6/.12/.20/.23/.58/.70`, `25cs` | Check the exact merge candidate, collect independent quorum, merge, lose response, restart and recover the same outcome with ref/PR/outbox atomicity. Later failure, withdrawal, moved candidate or incomplete history denies. Trusted-host evidence remains separate until hostile runner isolation/cancellation/secret reaping are actually demonstrated. | L/XL |
| E | Canonical delivery, not only a journal: `.4.55/.57`, `e0eg`, FG-046 | Connect real HTTP attempt custody to current-authority outbox settlement. Crash around downstream acknowledgement, restart with the original delivery key and verify retained debt. At-least-once remains explicit; timeout/ambiguous send cannot prove non-execution. Bound the fanout loop and its refusal twin. | L |
| F | Predictable import, transfer and serving: `eq4h/gzdy/pc9g/3gdw/e6jj`, `.4.28/.33/.60`, FG-105 | Qualify larger two-format local/transport repositories with independent ingress, processing and response clocks, source-absent same-key recovery, cold export, delta work and exact clone-back. Current cross-transport pinned adversarial evidence is separate from git:// Tier A. Preserve finite bounds, receipt refusals and A/A performance controls. | L |
| G | Sustained forge/check/search service: `.4.7/.9/.19/.36/.39/.63`, FG-032 | Cross present state/history bounds using authenticated settled-prefix/frontier mechanisms; keep latest-check and historical-proof equivalence. Exercise concurrent reads/writes and destroy/rebuild indexes. Measure useful committed decisions per CAS, tails, memory, bytes, requests and cost; no score/index becomes authority. | XL |
| H | Restore/upgrade/repair real accepted state: `.4.10/.21/.42/.61/.62`, `88g7`, FG-036/077 | Admit live HTTPS object fabric/backend conformance, independently restore source+forge+outcome+policy from signed materials, serve and mutate, measure scoped RPO/RTO. Corrupt the newest acknowledged root: refuse rather than roll back. Exercise key loss, mixed versions, GC retention and stale repair revalidation. | XL |
| I | Real agent with shared sparse workspace: `.4.24/.34/.38/.40`, `p7sa/xcu9/sjzo/zb0q/mwck`, FG-096 | Bind credentials and IntentRun to the actual context bridge and broker; create sparse shared-base edits, collect ECC/verifier receipts and publish through ordinary admission. Revoke/cancel at every responsibility boundary; prove child/process/secret/workspace/effect quiescence or typed containment failure. Measure per-workspace cost and retain host-byte representability twins. | XL |
| J | Turn advanced libraries into bounded consumers: `.4.22/.37/.64/.67/.68/.69` | ATP parity and measured savings; retry loop actually records and consults the controller with low-support/regime fallback; position-bound graph decisions; a newly covered Rust/reference history; evidence imports only tighten checks; cache reuse binds exact BuildInputCapsule and poisoning/reverification rules. Each gets an actual product caller before an optimization claim. | XL |
| K | Finish the distribution/operated-service scope: FG-035/091, `0zjt`, `.4.25/.63/.65/.66`, FG-063/065/100/101/102/104 | Resolve scope, complete native signed DSR asset/installer matrix and root-last manifest. Security, upgrade, external migration/operate/restore/export and dogfood/release are executed joins. Packages, federation, billing/hosted controls retain their own full acceptance; no blanket launch from an isolated test. | XL |

Ordering is leverage, not permission to invent blocking graph edges. A and the owner-approved trust boundary gate broad deployment; the history/candidate bounds gate ordinary PR use. Existing dependency edges remain authoritative. A native merge gate can improve while unrelated owner decisions remain unresolved, without declaring the whole product complete.

## 7. Ambition rounds and refinement

The skill's frozen bead-generation and refinement prompts are applied verbatim as the planning instructions; repository rules take precedence where they require code/tests in one bead and the compatibility wrapper for every bv call. The bridge is revised in place.

Three ambition passes strengthen its actual outcomes:

1. Replace disconnected subsystem milestones with team-day, agent-run, destroy/restore and external-adopter exits. Keep the full ATP/TreeFS/hosted scope; do not shrink the promise to an empty-repository demo.
2. Reduce repeated work through one selected authenticated ancestry/closure/frontier basis shared by merge preparation, independent candidate verification, checks and history where their contracts permit it. A reusable witness must remain subordinate to authority. This addresses measured history/closure cliffs without simply expanding memory caps.
3. Make economics an end-to-end constraint: decisions/CAS, useful bytes, workspace deltas, tail latency, repair/outbox debt and first-failure preservation. Prefer wiring an existing abstraction to adding an abstract controller with no caller; require baseline/candidate/A-A and a rollback/negative result.

Five refinement passes check: (1) all 30 goals against v1 and all §49 classes; (2) current ownership/readiness and real prerequisite edges; (3) test/oracle/independence class and complete required-cell coverage; (4) bounds, crash/ambiguity/cancellation/retention and permitted twins; (5) final user-visible exits and graph consistency. Corrections made during those passes include distinguishing the now-linked agent from its uncalled bridge, separating the two merge-size walls, retiring the stale verifier-deadlock count, retaining Chromium's non-pass skip, and classifying the remote preflight as no native execution. The final plan review found no further structural gap; unexecuted empirical obligations remain explicit.

## 8. Tracker handoff and audit boundaries

Added one bounded P1 defect, `frankengit-root-doctrine-x2mv.4.72`, with the exact strict-remote reproduction, real-dependency refusal twins, source-selection, cancellation/slot-cleanup and integration acceptance. Related edges connect it to `.4.26`, `.4.18` and `.4.15`; no artificial blocking edges were added. Seven additive source-bound evidence/refinement comments update the root assessment epic, `.4.15/.24/.26/.56/.71` and `rffg`. Existing statuses, assignees, acceptance and batch gates are preserved. No bead is claimed, moved to batch_pending or self-closed by this audit.

Final wrapped triage, insights, suggestions and plan commands exit 0 over **688 rows / 663 live / 25 tombstones**. Both graph insights and authoritative `br dep cycles --no-db --json` report no cycles. Final states are 507 closed, 99 open, 20 rework, 10 blocked, 5 deferred, 13 batch_pending and 9 in_progress; debt stays 22/36. Authoritative ready returns 36 unassigned items, including the new defect; that is readiness, not an assignment or a waiver. A semantic preservation check confirms all 687 pre-existing IDs, statuses, assignees, acceptance fields and old comments, with only the seven intended added comments/updated timestamps and the one new issue. Graph analysis remains advisory.

Tracker handling exposed a stale SQLite cache. The first ordinary `br create` allocated an already-used child ID and the export guard refused. A subsequent `sync --merge --force-jsonl` unexpectedly used a stale base and temporarily changed the JSONL; it was not accepted as recovery. `br history restore` restored the exact original backup, verified byte-for-byte. All successful additions then used `br --no-db` and source-mode sync. The pre-existing 687 records were checked unchanged after the new issue; later comparisons permit only the intended additive comments/related edges. Raw before/after and tool receipts are retained. A subsequent explicit JSONL-to-cache import completed without changing the authoritative source bytes. `br sync --status` now reports healthy, zero anomalies, zero dirty records and equal 688-row coverage. This is a corrected audit error, not permission to repeat forced merges or to infer product completion from the cache.

The earlier October 20 assessment remains in this file's git history (`80697d30`, with the source binding `7eaf1df8`). This revision is an audit/bridge update, not a source implementation, production qualification, release, complete Rust refinement proof, or independent review of every prior closure.

Both requested files were read completely. The broader intake inventoried the Markdown corpus and examined the full normative protocol and dependency constitution; integration profile; plan requirements/scope/roadmap/definition of done; verification/security/release contracts; relevant transport, workflow, workspace, graph, agent and delivery specs; current owning source/call sites, registries and authoritative Beads records. It is not a claim to have read every line of every auxiliary Markdown page or all 601k lines of Rust. The checklist tracks all promised capability classes while preserving those inspection and execution limits.
