# FrankenGit reality check and bridge plan — 2026-10-17 (supersedes 2026-10-13 in place)

FrankenGit is still a real, bounded, pure-Rust Git node with an atomic forge core. In the ten days since `6deda35c` it grew faster than at any time before: 239 commits on `origin/main` (152,198 lines added) plus 10 local commits that never reached origin. The growth is real but lopsided. Its shape has also changed what is risky:

- **Most of the new code is not Rust.** About 73,000 of the added lines are JavaScript (`.mjs`). 171 of the 239 commits touch `.mjs` and no `.rs`. A second product plane now exists in Node, made of GitHub migration, signed backups, source authoring and workflow supervision. Its tests run against stand-in "native-schema" peers rather than a live `fg` (§5.3).
- **`main` could not build `fg` for five days.** From `dad1b3ff`/`dcbf4cbf` (2026-10-11) to `a3b9e94b`/`4194a463` (2026-10-16), 182 commits landed on a tree whose `fg` binary did not compile. 192 of the 239 messages say Rust/Cargo was not run, and 174 assert owner authorization for direct-main publication (§5.2).
- **Two writers diverged.** Local `main` in the shared checkout carried 10 commits (2026-10-13..16) that never reached origin. Origin carried 239 that local never saw. Three fixes were made twice: E0689, the 512 MiB import envelope and the browser test repairs. One local commit (`da1943de`) had never compiled. This assessment landed both lines as one merge and repaired it forward (§5.1, §9).
- **Nothing was verified.** No bead has closed since 2026-09-29: 18 days, 249 commits. Verification debt is 35 of the policy's hard limit of 36 (§5.4).
- **Real Rust capability did land.** It includes:
  - PR conversation comments, squash merges, issue assignment and MCP/HTTP protection administration;
  - forge-state bisection (`fg bisect`);
  - verified blob reads over HTTP (`fg verify-read`);
  - streaming bundle export and recovery;
  - a disk-spooled 512 MiB import;
  - workflow step contexts, static matrices and owned process groups (§5.6).

  The forge is closer to a team's daily needs than on 2026-10-13. It is still not a forge a team can rely on: the same capacity cliffs, unwired required checks, self-asserted principals, missing TLS and ten library islands remain (§5.7).

**Binding.**
- Source and executable evidence for this assessment are taken at **`f73a3ccae34beedb7fe0fd876562d09a90cb04c6`** (`origin/main`, 2026-10-17 20:55 −0400) and at the landing merge **`bdec9ae19612c18fa4aff5cc2fedd97f057e3c0e`** (§9).
- Toolchain and tools: `nightly-2026-08-31` (rustc 1.100.0-nightly 908501772), git 2.55.0, Node 22.22.1 (`/usr/bin/node`; the host default `~/.nvm` Node is 22.2.0, see §2), Google Chrome 155.
- Host: 64 cores, shared with other projects' builds (load 25–66 during the runs).
- Private targets: `/data/frankengit-targets/rc_20261017` (origin) and `rc_20261017_land` (landing). Builds ran locally with `RCH_CARGO_WRAPPER_BYPASS=1`, because `rch` refuses worktrees outside `/data/projects`.
- Prior baselines are kept in the History section and in git history of this file.
- This is not a security audit, universal compatibility result, benchmark claim or batch-verification certificate. Nothing here closes, reopens or verifies a bead.

**Consumer and retirement.** The owner, the batch verifier and every assignee use this document to decide what is done and what to build next. The defect classes it tracks are:
- an unverified main;
- divergent writers;
- a second product plane outside the constitution;
- unwired product paths;
- capacity ceilings;
- stale claims.

Replace it in place when a later revision-bound assessment supersedes it. It grants no capability credit.

## 1. What was examined

- All of `AGENTS.md` (repository and parent), `README.md`, the 2026-10-13 version of this document, and the plan's scope (§3–§4), roadmap (§44) and definition of done (§49).
- Three independent read-only audits. Each was told to write nothing, and the assessor re-checked every critical claim against source:
  - **The commit stream.** All 239 commits `6deda35c..f73a3cca` classified by theme, language, bead citation and self-declared execution, plus the build-break chain from the diffs.
  - **The JavaScript plane.** Inventory, entrypoints, Git semantics re-implemented in JS, lanes, docs, registries and ADRs.
  - **The measuring stick.** A vision checklist from the plan with an owning-bead map, and the vision goals no non-closed bead covers.
- Direct source checks at `f73a3cca`:
  - `crates/fgit-codec/src/canonical_state.rs:20,22` (16,384 ceilings);
  - `crates/fgit-node/src/lib.rs:4933` (`MAX_CONCURRENT_WRITERS = 1`);
  - `evaluate_protected_ref` (no caller outside `fgit-policy`);
  - `deliver_forge_outbox_in` (one test caller, `crates/fgit-node/tests/native_merge_publication.rs:1068`);
  - `crates/fgit-node/src/treefs_workspace/trusted_workflow/durable/publication.rs:319-327` (`Succeeded → Success`);
  - the loopback-only `fg serve-http` (`crates/fgit-cli/src/smart_http_server.rs:216`);
  - the six side binaries in `crates/fgit-node/src/bin/`;
  - the MCP catalog against `crates/fgit-schema/generated/mcp_parity_manifest.json`;
  - `cargo metadata` linkage of every workspace crate into `fg`.
- The tracker, from both exports (`origin/main:.beads/issues.jsonl` and the local one), merged field by field (§9).

## 2. Executable evidence

| Check | `f73a3cca` (origin) | Landing merge | What it establishes |
|---|---|---|---|
| `cargo check --workspace --all-targets --locked` | **exit 0** (171 s); 267 warning lines; `fgit-node` lib 20 warnings | **exit 0**; 231 warning lines; `fgit-node` lib 1 (origin's `private_interfaces` at `smart_http/server/pulls.rs:63`) | Origin compiles again after the 2026-10-11..16 break. The local line did not: `da1943de` (x2mv.4.37) never compiled, so local `main` was unbuildable from 2026-10-16. It was repaired in the landing (§9). |
| `cargo fmt --all -- --check` | **exit 1: 179 files**, 2,071 hunks (103 in `fgit-cli`, 60 in `fgit-node`) | exit 1: 79 files, all origin's; the landing formats only the files it edited | Local `3f8b1f28` had formatted the whole tree on 2026-10-13. Origin, written without rustfmt, was unformatted again. |
| `fgit-schema-gen check` (part of `verify.sh fast`) | **exit 1**: `fgit-graph` encodes `source-lexical-manifest` (test copy in `lexical/stored/omissions/tests.rs`) with no description | **exit 0** | Fixed in the landing by describing the family in `crates/fgit-graph/canonical-bodies.tsv`. |
| `./scripts/verify.sh docs` | **exit 1**: broken link `docs/LOCAL_MEDIA_RECOVERY.md → RECOVERY_CHECKPOINT_CANDIDATES.md` (never committed, `bf4daffc`) | **exit 0** (352 Markdown files, 462 registry rows) | The link was repointed to `CHECKPOINT_SET_RECOVERY.md`, the doc that describes grouped checkpoint candidates. |
| `./scripts/verify.sh constitution` | **exit 0** (1,972 Rust files) | **exit 0** (1,973 Rust files) | No unsafe, forbidden dependency or unapproved lint relaxation in first-party Rust. The checker does not look at JavaScript (§5.3). |
| Workspace test binaries (every `profile.test` artifact, run from its package directory) | 688 test binaries, 0 compile errors: **8,913 passed, 46 failed**, 41 ignored. 16 binaries failed and none timed out (pool of 6, host load 25–60) | focused crates only (below) | Three clusters account for 35 of the 46 failures:<br>• webhook dispatcher, 23 (`x2mv.4.57`);<br>• squash and resolved merges across node, HTTP and MCP, 7 (`x2mv.4.58`);<br>• trusted workflow check publication, 5 (`x2mv.4.70`).<br>The other 11 are listed on `x2mv.4.26`. Each one rerun alone failed again: webhook, MCP candidate, `workflow_publication`, `cli_refusal_vocabulary`, `bundle_stream_export`, `atomic_merge`. At `2b7f35ac` there were 26 failures, mostly load-induced budget cancellations; these are not. |
| `cargo test -p fgit-schema --all-targets` | **1 failure**: `coverage::the_two_derivations_of_the_covered_set_agree` (`verified-blob` body from `209b9c5c` never registered) | **all pass** | Registered `verified-blob` as an undescribed body (it nests a whole `verified-read-envelope` frame, the `signed-envelope` obstacle). |
| `cargo test -p fgit-authority-fsqlite --all-targets` | pass | pass, including the 5 adaptive-retry controller tests that had never run | §9 |
| `cargo test -p fgit-cli --all-targets` | 1,041 passed, **31 failed**: 23 webhook dispatcher; 2 MCP squash/resolution, counted in both `fg` and `fg-mcp`; `cli_refusal_vocabulary`; `bundle_stream_export`; `workflow_publication` ×2 | 1,058 passed, **18 failed** (16 unique): 10 webhook fan-out, 2 MCP ×2 binaries, `cli_refusal_vocabulary`, `bundle_stream_export`, `workflow_publication` ×2 | Every landing failure also fails on origin's own binaries, so the merge introduces none. It removes 13 dispatcher failures, because local `fff457f2` (x2mv.4.52) lands. |
| `node --test tests/browser/*.test.mjs` (Node 22.22.1) | **3,600 tests: 3,507 pass, 92 fail**, 1 skipped | 3,600 tests: 3,512 pass, **87 fail**. All are search-view or search-context harness drift, plus 1 pulls-checks. The reversed `gzip, br` fixture from `7c604293` was restored to the HTTP order and passes | The failures are harness drift, not page failures: 60 × "Missing HTML element context-enabled" across the search views (the fake DOM never runs `search-context.mjs:321`, which creates that control), and 17 context-controller cases whose harness omits `search-context-package.mjs`. All 4 real-browser suites pass (below). Under Node 22.2.0 origin fails 98. At `6deda35c` it was 31 of 2,508. |
| `node --test tests/operator/**/*.test.mjs` | Node 22.22.1: **3,819 tests, 3,795 pass, 13 fail**. Node 22.2.0: 3,806 tests, **240 fail** | — | The operator plane's own tests mostly pass on a current Node. They pass against stand-in peers, not a live `fg` (§5.3). No Node version is pinned anywhere, and the suites are version-sensitive. |
| `node --test scripts/**/*.test.mjs` | Node 22.22.1: **1,392 tests, 1,364 pass, 28 fail**. Node 22.2.0: 212 fail | — | Same, for the backup, recovery and search-view CLIs. |
| Product lane: the `verify.sh e2e` suite selection (69 suites) run with a **release** `fg` built at `f73a3cca` (sha256 `dd0a9889…`) | **62 of 69 pass** (1,770 s). By kind: e2e-binary 58/64, real-browser 4/4 (pages 75 assertions, client_fetch 9, cross_site 12, Markdown CSP 27), js-unit 0/1. Not ok:<br>• `webhook_delivery` (FG-046-E2E-007/018/021/022/023);<br>• `candidate_approval_publication` and `pull_request_cli`, the stale-pin campaigns failing since 2026-09-27;<br>• `merge_preparation`, a canonical `TargetRefMoved` refusal;<br>• `tag_lifecycle` TAGS-015, which needs the pinned oracle;<br>• `packed_import_profiles`, zero assertions (`fge: invalid phase verify`);<br>• `contract_tests`, the browser node:test suite | — | Every transport, SSH, smart-HTTP, continuous-serve, SHA-256, incremental-fetch, time-travel and real-browser suite passes with stock clients. `verify.sh e2e` itself builds a debug `fg`; the release build avoids the debug-only deadline failures recorded in earlier checks. A green lane still needs the 7 suites above. |

Ordinary-client cells use the installed Git 2.55.0, OpenSSH and Chrome 155. They are compatibility observations, not the constitution's pinned-oracle class.

## 3. The short answer

**Where are we really?** Still at the end of plan Phase 2 (pure-Rust Git core), with a growing slice of Phase 5 (forge core) and trusted-local fragments of Phases 4 and 6. Phase 5's exit, "a real team can operate the forge" (PLAN:3496), is not met. Phase 3's exit (ATP-Git parity) and Phase 4's exit (sparse workspaces without full clones) have not started as product paths. The README's four qualifiers are still undelivered:
- **Humans:** one trusted operator; principals are self-asserted; required checks cannot gate a merge.
- **Agents:** `fgit-agent` (37,176 lines) is still linked into nothing. The new "agent" work is JavaScript source-authoring tooling over HTTP, not the IntentRun/ECC authority model.
- **Extreme scale:** one writer per process; forge publication stops at 16,384 events; search caps sit below this repository's size.
- **Recovery:** signed backups exist, mostly in JavaScript; there is no GC, scrub, repair or RaptorQ on node data.

**What works (with evidence).**
- Everything listed on 2026-10-13 still works at `f73a3cca`:
  - raw git-daemon, SSH and smart-HTTP clone/fetch/push with stock Git (v0/v1/v2 upload, thin packs, `COMPRESSED_V3`, per-ref report-status);
  - SHA-256 repositories;
  - `fg at`, the atomic durable PR merge, issues/branches/tags;
  - continuous serve modes with drain;
  - deterministic concurrent-writer refusals;
  - the cursor-paged event feed over CLI, MCP, HTTP and browser;
  - safe Markdown;
  - all 13 served browser pages in real Chrome (the 4 real-browser suites pass).

  See §2 for the runs.
- **Δ New Rust capability, reachable through `fg`:**
  - `fg pr comment|comments` (`49993cc9`);
  - squash merges with conflict resolution (`7cffff1e`, `2e0afc17`, `9b761967`);
  - `fg issue assign|unassign`;
  - protection administration over MCP/HTTP (`99d76103`, `919509e9`);
  - `fg bisect` over authenticated forge history (`5939edcd`..`710c75d7`, natively tested);
  - `fg verify-read`: a ref-and-path blob proof checked against an independently supplied head (`209b9c5c`, `bba44b5c`). This is the first verified read on a transport.
  - `fg bundle verify|recover|export --streaming`;
  - `fg import --max-expanded-mib` with disk spooling and multi-pack sources (288 and 576 MiB runs recorded);
  - workflow step env/working directory, static matrices, process-group ownership and terminal cleanup (`fgit-runner`, natively tested);
  - a successful trusted workflow now maps to `Success` (`e5af2464`).

**What does not work or is not implemented.**
- **Verification.** No independent verifier since 2026-09-29. The tracker allows one more claim before it refuses all new work.
- **Merge gating.** Required checks cannot gate a merge. `evaluate_protected_ref` has no production caller, and a `Success` check is displayed "without granting merge authority" (`f0b8a026`).
- **Identity.** Every CLI and MCP write is self-asserted (`--principal`, or `operator_asserted_at_launch` for the new MCP protection writes).
- **Webhooks.**
  - Delivery is still a local sidecar journal reporting `"canonical_settled":false` (`crates/fgit-cli/src/webhook_commands/dispatcher.rs:37`). The new fan-out extends that journal.
  - 23 dispatcher tests fail at `f73a3cca`, 10 of them fan-out. 13 pass once the local `fff457f2` lands.
  - The `webhook_delivery` e2e suite fails 5 assertions.
- **Merges and checks fail their own tests.**
  - Squash and conflict-resolved merges fail 7 restart/recovery/atomicity tests across the node library, HTTP and MCP (`x2mv.4.58`).
  - Trusted workflow check publication fails 5 tests after the `Success` mapping change (`x2mv.4.70`).
- **Capacity.** 16,384 forge events or outbox entries end all forge publication. One writer per process.
- **Storage and deployment.** No TLS on any listener (Node clients do TLS for themselves). Non-loopback HTTP is refused. There is no GC, scrub, repair, RaptorQ or object-store fabric.
- **Islands.** Ten product crates (61,736 `src/` lines) are linked into no binary. The landing links `fgit-statistics` through a constructed but unconsulted retry controller.
- **Lanes red at origin:** docs, schema-gen, rustfmt, plus failing tests (§2).

**What is blocking us.** In order of leverage:
1. **No one verifies, and nothing stops unverified landings.** The same two failures were reported on 2026-09-23, 2026-09-27 and 2026-10-13. Since then the unverified stream grew nearly fourfold: 239 commits in ten days, against 61 in the previous period.
2. **Two writers on `main` without a landing protocol.** Local sessions committed for four days without pushing. The producer pushed without fetching their work. Fixes were duplicated, and a broken commit sat in the unpushed line.
3. **A second product plane outside the constitution.** The JavaScript plane holds about 43,000 production lines. It includes a hand-written pack/DEFLATE/delta/idx engine on product paths, and it is accepted by no ADR or registry row. Owner decision D2 has been open for 24 days and does not cover the operator plane at all (new decision D10, §5.3).
4. **Composition debt is unchanged.** The same ten crates, the same unwired required-check and outbox-settlement paths, the same ceilings.

**If every open and in-progress bead were implemented, would the gap close?** No.
- The verification queue cannot drain without a second verifier: 21 of the `batch_pending` beads belong to the only appointed verifier.
- The JavaScript plane has no bead or decision that brings it under the constitution or tests it against a live `fg`.
- Eleven vision goals and three failing-test clusters had no non-closed owner before this assessment (below).
- Several open beads describe superseded or conflicting work (§5.8).
- The integrating exit tests for Phases 5 and 6 (`x2mv.4.23`, `x2mv.4.24`) are still the only beads whose success implies the qualifiers, and Phases 7–9 had none.

**Vision goals with no non-closed bead before this assessment** (now covered by the beads in §8):
- a live-`fg` lane for the JavaScript operator plane;
- a declared Tier-A Git compatibility tier run against the pinned oracle (plan DoD 2, Phase 2 exit);
- an object-store-backed object fabric (v1 item 15; only the authority adapter had an owner);
- single-node upgrade, rollback and mixed-version recovery (DoD 14);
- published performance and unit-economics targets with a measuring lane (DoD 17, §48);
- a Phase 7 exit test;
- the refinement-bridge residue of the formal core;
- evidence-pack import that only tightens local checks;
- build-output reuse receipts and spot checks;
- an external organization's migrate/operate/restore/export run (DoD 20);
- an independent security assessment (DoD 13);
- three failing-test clusters with no owner: webhook fan-out, squash/resolution merges, and workflow check publication.

## 4. Vision checklist

Status vocabulary:

| Status | Meaning |
|---|---|
| WORKING | Executed end to end through the product binary in this assessment or its cited revision-bound suite |
| PARTIAL | Real, but part of the stated goal is missing |
| LIBRARY-ONLY | Real code with no production caller |
| JS-ONLY | Implemented only in the JavaScript plane |
| STUB | Placeholder behaviour behind a real interface |
| BROKEN | Present and defective |
| NOT_STARTED | No code |

**v1 functional scope (plan §4.1)**

| # | Goal | 2026-10-13 | Now | Evidence | Work |
|---|---|---|---|---|---|
| 1 | Repository creation/import/export | WORKING (bounded) | WORKING (bounded) Δ | `fg import` disk-spooled to 512 MiB reachable closure (`8e8e2b69`, `60f7a032`); streaming bundle export | FG-106 (rw), `e6jj` |
| 2 | SSH and smart HTTP access | PARTIAL | PARTIAL | Stock clients work on all three transports; loopback-only HTTP, no TLS, ed25519-only SSH keys | `x2mv.4.30`, `x2mv.4.13` |
| 3 | Protocol-accurate clone/fetch/push | WORKING (declared tier) | WORKING (undeclared tier) | No Tier A is declared and no pinned-oracle lane runs | `x2mv.4.60`, `x2mv.4.33`, FG-098 |
| 4 | Branch/tag listing and atomic ref updates | WORKING | WORKING | `fg branch/tag/refs`; HTTP and MCP branch tools | — |
| 5 | Users, orgs, teams, tokens, deploy keys | PARTIAL | PARTIAL | Deploy keys and HTTP tokens only; self-asserted CLI/MCP principals | `x2mv.4.13`, `x2mv.4.34` |
| 6 | Protected refs and policy snapshots | PARTIAL, fail-closed | PARTIAL Δ | Protection administration over MCP/HTTP; review protection enforced; required checks never evaluated in production | `x2mv.4.6`, `x2mv.4.12` |
| 7 | PRs, reviews, comments, labels, merge | PARTIAL | PARTIAL Δ | Conversation comments, squash and resolution merges, fast-forward; still missing line comments, approval survival rules, quorum/ownership and required checks; 7 squash/resolution tests fail across node, HTTP and MCP | `x2mv.4.20`, `x2mv.4.7`, `x2mv.4.58` |
| 8 | Issues and discussions | PARTIAL | PARTIAL Δ | Assignment added; no discussions, milestones or notifications | FG-045 |
| 9 | Webhooks and event API | PARTIAL | PARTIAL / BROKEN | Event feed works; webhook fan-out tests fail; delivery state is a sidecar, never canonical | `x2mv.4.55`, FG-046, `x2mv.4.57` |
| 10 | Safe Markdown rendering | PARTIAL | PARTIAL | HTTP, MCP and browser; no source spans | `x2mv.4.11` (blocked, D2) |
| 11 | Basic lexical and symbol search | PARTIAL | PARTIAL Δ | Oversized files are now omitted rather than aborting a build; default modes still stale after forge writes; still side binaries on origin | `x2mv.4.19`, FG-032a |
| 12 | CI with artifacts and cache | PARTIAL (trusted) | PARTIAL (trusted) Δ | Step contexts, matrices and process groups in Rust; triggering is an external Node polling supervisor; checks never gate merges; `LocalArtifactStore` has no consumer | `x2mv.4.12`, `x2mv.4.70`, `25cs`, `x2mv.4.69` |
| 13 | Agent identities, Intent Runs, workspaces, evidence | PARTIAL / LIBRARY-ONLY | LIBRARY-ONLY + JS-ONLY | `fgit-agent` unlinked; source-authoring workspaces exist only as Node tools | `x2mv.4.24`, `p7sa`, `x2mv.4.34` |
| 14 | Backup, capsule export, scrub, verify, restore | PARTIAL | PARTIAL, mostly JS-ONLY Δ | `fg backup` in Rust. Signing, selection, replication, scrub, offsite and local-media recovery are Node (40 of 42 recovery commits) | `x2mv.4.21`, `x2mv.4.10` |
| 15 | Single-node and object-store deployment | PARTIAL / STUB | PARTIAL / NOT_STARTED (fabric) | Object-store authority adapter blocked on TLS; no object-store fabric at all | `88g7`, `x2mv.4.61` |
| 16 | GitHub import and compatibility matrix | NOT_STARTED / stale | JS-ONLY / stale | GitHub issue and PR migration in Node, tested against fixtures, never against live GitHub or a live `fg` | FG-049, FG-090, `x2mv.4.59` |

**Roadmap phase exits (plan §44)**

| Phase | Exit | Status |
|---|---|---|
| 0 Constitution | drift rejected mechanically | PARTIAL: the constitution lane is green for Rust, blind to 43K lines of production JS |
| 1 Authority kernel | one terminal outcome, atomic ref/forge | WORKING in the reference slice; production residue in `x2mv.4.51`, `x2mv.4.47` |
| 2 Git core | narrow declared tier, no foreign Git | WORKING for stock clients, but the tier is undeclared and the pinned-oracle lane is absent (`x2mv.4.60`) |
| 3 Fabric and ATP-Git | native = ordinary transfer results | NOT_STARTED as product (`x2mv.4.22`, P3) |
| 4 TreeFS | sparse workspaces without full clones | PARTIAL (trusted host adapter; JS workspaces copy files) |
| 5 Forge core | a real team can operate it | NOT MET (`x2mv.4.23`) |
| 6 Agent and CI | bounded agents and CI end to end | NOT MET (`x2mv.4.24`) |
| 7 Search and graph | reproducible, authority-safe decisions | NOT MET (`x2mv.4.64`) |
| 8 Recovery, GC, multi-region | measured RPO/RTO | NOT MET (`x2mv.4.21` drill, FG-036) |
| 9 Hosted and federation | FrankenGit.com economics | NOT STARTED |

**README core innovations**

| Innovation | Status | Evidence |
|---|---|---|
| One RCR, one head CAS for ref and forge | WORKING | merge, reopen, receive, conversation and assignment paths publish through admission |
| Stable retry identity, immutable outcomes | WORKING | `fg outcome`; MCP/HTTP keyed retries |
| Per-core preparation, flat combiner, witness refinement | LIBRARY-ONLY | `fgit-txn` combiner/lanes have no external caller; `fgit-witness` unlinked |
| ATP-Git | LIBRARY-ONLY | no dependents |
| TreeFS | PARTIAL | trusted sparse host adapter; JS editing workspaces outside TreeFS |
| Typed graph fabrics | PARTIAL Δ | `fgit-diff` ancestry index serves forge/admission ancestry; GRAPH-001..009 still "specified" |
| CALM and obligation-typed effects | PARTIAL | runner obligations still counters; process-group ownership improved |
| Repair through authority | LIBRARY-ONLY | `fgit-repair`, `fgit-raptorq`, `fgit-compaction` unlinked |
| Conformal/e-process policy | LIBRARY-ONLY → linked, unconsulted (landing) | `x2mv.4.37` controller constructed in `FsqliteAuthorityStore`; no retry loop consults it |
| Local root-last releases | STUB | `verify.sh release` exits 3 |

**Beyond parity:**
- Verified reads: **PARTIAL Δ**. `fg verify-read` checks a blob proof served over loopback HTTP. Broader proof coverage and the browser path remain (`x2mv.4.41`).
- Time travel: WORKING (`fg at`) plus `fg bisect` Δ.
- Evidence economy: LIBRARY-ONLY.
- Deterministic build outputs: STUB.
- Formal core: contained Lean model only.

**Constitution:**
- `#![forbid(unsafe_code)]`, no Tokio/OpenSSL/libgit2, no production `git` subprocess: pass for Rust.
- **Rust-only Git semantics: violated in production paths not ratified by any decision (§5.3).**
- One runtime: Node event loops now host long-lived services (`fg_workflow_supervisor serve`, `fg_pull_sync_watch`).
- Closed dependency universe: Node's TLS, SHA and Ed25519 implementations have no registry row.

## 5. Findings that should change priorities

### 5.1 Two writers on `main`, with no landing protocol

- On 2026-10-17 the shared checkout's `main` was **10 commits ahead and 239 behind** `origin/main`, diverged at `6deda35c`. The 10 local commits (2026-10-13..16) were:
  - this document's 10-13 version (`9477ceac`);
  - the E0689, warning and rustfmt repair (`3f8b1f28`);
  - the webhook suite alignment (`fff457f2`, x2mv.4.52);
  - the sparse-lease CLOEXEC/flock fix (`415e394a`, x2mv.4.43);
  - the 512 MiB import envelope (`a68d3f45`, x2mv.4.28);
  - MCP registry parity (`ea0d6ca8`, x2mv.4.17);
  - the 31 browser test repairs (`7c604293`, 5f68);
  - side binaries folded into `fg` subcommands (`de834364`, x2mv.4.54);
  - the adaptive retry controller (`da1943de`, x2mv.4.37);
  - a tracker export (`7a8224e4`).
- **Duplicated work.** Origin independently fixed E0689 (`d27192b6`), raised the import envelope to 512 MiB with a different design (`8e8e2b69`, `60f7a032`), and repaired some of the same browser tests. Five origin commits cite x2mv.4.28 while it was `batch_pending` under another agent.
- **A broken commit sat unpushed.** `da1943de` declared "no compile ran". It did not compile: 15 errors against `fgit-statistics`'s real API. Local `main` was unbuildable from 2026-10-16 00:43 until this landing.
- **The landing.** This assessment merged both lines (§9) and fixed forward:
  - `da1943de` now compiles and its 5 tests pass;
  - the MCP parity check now covers origin's 5 new tools, and the served catalog is the validated one;
  - the side-binary dispatch was re-applied over origin's new `bisect`/`verify-read` commands;
  - the tracker was merged field by field.
- **Lesson.** Neither writer could see the other. Every session must end with `git fetch` + `git push`, as AGENTS.md "Landing the Plane" already requires. The structural fix is a single landing point that compiles every commit (§6 track A).

### 5.2 Five days without a buildable `fg`, under an asserted mandate

- `dad1b3ff` (2026-10-11 07:44) imported a private module from `fgit-cli`, so the `fg` binary stopped building. `dcbf4cbf` (08:36) added an enum variant with no match arm, so the `fgit-node` lib stopped building. Both were repaired only by `4194a463` and `a3b9e94b` on 2026-10-16. **182 commits** landed in between. Other breaks: `669dfda0`, `f0847cc1`, `e5af2464` (four missing commas, repaired by `2fbb70dc`).
- 192 of the 239 commit messages (80%) say Rust/Cargo was unavailable or not run. 19 (8%) report a passing native run, 15 of them from 2026-10-16/17. The stream does now compile its Rust sometimes, which is a real improvement, and it disclaims closures honestly: about 82 messages say "no bead closure", and none self-closes.
- 174 messages state that the owner authorized direct-main publication. No recorded ruling exists: D7 in `x2mv.4.14` is still open. This assessment does not rule. It records that the 2026-10-11..16 window is what the D7 options were written to prevent. A compile sentinel (option a) would have caught `dad1b3ff` within minutes. Because the breaks were independent, finding the first bad commit costs about log₂(182) ≈ 8 builds by bisection.

### 5.3 A second product plane in JavaScript

| | 6deda35c | f73a3cca |
|---|---|---|
| Production JS (files / lines) | 61 / 13,354 | **237 / 43,039** |
| JS tests and harness | 148 / 21,262 | 432 / 64,274 |
| Production entrypoints under `scripts/` | 5 | **49** (plus 65 `scripts/operator` and 66 `scripts/lib` modules) |

- **It is a product, not tooling.** GitHub issue and PR migration exists only in Node (`scripts/{import,capture,migrate}_github_*.mjs`, `{discover,collect,migrate}_github_pulls.mjs`). So does most of backup signing, selection, replication, scrub and recovery: 40 of the 42 recovery commits. So do source-authoring workspaces and the workflow supervisor. The plan assigns these to `fg` subcommands (§31.6), and the docs call them "production JavaScript".
- **It re-implements Git on product paths.** `crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs` (866 lines) contains:
  - an RFC 1951 inflater with an Adler-32 check;
  - pack v2 parsing with OFS/REF delta resolution;
  - delta application;
  - tree, commit and tag parsing;
  - idx-v2 and CRC32 generation.

  That module is compiled into `fg` (`include_str!`). It is the default verifier and recovery engine of `scripts/{verify,recover}_git_bundle.mjs`, and recovery writes a bare Git repository without Rust. It also gates `fg_source_changes` candidate packs. Another 20 modules hash or serialize Git objects. AGENTS.md §6 ("Own object, pack/delta/DEFLATE … in Rust") and accepted ADR-0013 (:12, :46, :73) forbid this. No registry row or ADR admits it. Node's TLS/crypto have no dependency-policy row.
- **Its integration with Rust is largely untested.**
  - 146 commit messages say their tests ran against stand-in "native-schema" peers.
  - 38 operator test files start loopback stand-ins, and none starts `fg serve-http`.
  - No `verify.sh` lane runs the operator suites.
  - Under Node 22.22.1 those suites mostly pass (3,795/3,819; 1,364/1,392). Under the host's default Node 22.2.0, 240 and 212 tests fail. Nothing pins the Node version.
- **What it does well.** No JS holds authority: every mutation goes through native HTTP or `fg` subcommands that re-validate. There are no npm dependencies and no production `git` subprocess.
- **New owner decision D10:** ratify the operator plane (with an ADR, registry rows, a pinned Node and a live-`fg` lane), port it into `fg` subcommands, or both in sequence. D2 (the browser) now includes a served Git decoder (`x2mv.4.44`). Whatever the ruling, `x2mv.4.59` (the live-`fg` operator lane) is needed: it is the ratification evidence and the porting oracle.

### 5.4 Verification is still vacant

- **0 closes since 2026-09-29** (18 days, 249 commits).
- Merged tracker, before this assessment's additions: 635 live records (486 closed, 84 open, 27 `batch_pending`, 17 rework, 8 blocked, 8 in progress, 5 deferred). Verification debt is **35 of hard 36**:
  - IcyIbis 21 `batch_pending` + 1 in progress;
  - ChartreuseStone 6 + 1;
  - five "Astra*" identities with 1–2 in progress each, claimed by commits in the producer stream.
- 21 `batch_pending` beads belong to the only appointed verifier, and `forbid_self_close_after_in_progress` bars them. `x2mv.4.56` (filed 2026-10-13, local only until this landing) owns the fix.
- In queueing terms the service rate has been zero for 18 days. Batching at one SHA amortizes the build cost across all 27 beads, so one verifier day at one pinned SHA can clear most of the queue. It needs a second appointed verifier (D8 extension).

### 5.5 Lane health at `f73a3cca`

- docs **red** (broken link), schema-gen **red**, rustfmt **red** (179 files), check green with 267 warning lines, constitution green.
- 46 failing tests across 16 binaries, plus 7 non-ok e2e suites:
  - webhook dispatcher, 23 (`x2mv.4.57`);
  - squash/resolution merges across node, HTTP and MCP, 7 (`x2mv.4.58`);
  - workflow check publication, 5 (`x2mv.4.70`);
  - `fgit-runner` `sparse_workspace` ×2;
  - two `source_index_scope*` CLI tests;
  - one each: `fgit-schema` coverage, `cli_refusal_vocabulary`, `bundle_stream_export`, `admission_staging_refusals` and `fgit-forge` `atomic_merge`.
- The landing turns docs, schema-gen and `fgit-schema` green. `fgit-runner` `sparse_workspace` passes 17/17 because the local x2mv.4.43 lease fix lands. 13 webhook dispatcher tests pass because local `fff457f2` lands. rustfmt drops to 79 files.
- `x2mv.4.26` (fast lane) owns the remainder; its last comment says "fixed at 3f8b1f28", which was true only for the local line.

### 5.6 What real capability landed, and how far it can be trusted

The Rust items in §3 have code, tests and in several cases native runs reported by the implementer, mostly on 2026-10-16/17. None has an independent verification. Two of them fail their own tests at `f73a3cca`:
- webhook fan-out (`b22c5f67`, `a18bd82c`), never compiled at commit time: 23 dispatcher tests fail on origin, 10 after the landing;
- squash and resolved merges (`7cffff1e`, `2e0afc17`, `9b761967`, `f5127abd`): 7 tests across the node library, HTTP and MCP, all on restart, recovery or atomic publication.

The workflow `Succeeded → Success` change left two tests expecting `ActionRequired` (five workflow-publication tests fail in all, including `publication::tests::pull_request_checks::source_movement_suppresses_stale_checks_until_matching_new_execution_is_published`; filed as `x2mv.4.70`).

### 5.7 Unchanged ceilings and islands

- **Capacity.** The 16,384 forge-position and outbox ceilings are unchanged (`canonical_state.rs:20,22`). `915ae8e4` removed a separate 4,096 review-read cap but "does not … remove the 16,384-entry publication limit". `MAX_CONCURRENT_WRITERS = 1` is unchanged.
- **Islands.** Linkage by `cargo metadata` at `f73a3cca`: 33 of 49 members link into `fg`. Ten product crates, the same as on 2026-09-23, link into nothing: `fgit-agent` 37,176, `fgit-atp-git` 4,472, `fgit-statistics` 3,863, `fgit-projection` 3,106, `fgit-raptorq` 2,878, `fgit-repair` 2,664, `fgit-witness` 2,495, `fgit-exchange` 2,011, `fgit-object-store` 1,802, `fgit-compaction` 1,269. The landing links `fgit-statistics` without consulting it.
- **Required checks.** `evaluate_protected_ref` still has no production caller. The policy engine's required-check path is consumed by nothing outside `fgit-policy`.

### 5.8 Tracker drift and obsolete beads

The audits found open beads that describe delivered or conflicting work. They were commented, not transitioned; transitions belong to the verifier:
- **FG-105 / FG-105a** (smart HTTP, delivered on the owned server, premised on the unresolved D1 gateway);
- **FG-019** (a roll-up; only fg019c remains);
- **FG-050 and FG-051a** (conflict with the shipped JS browser and hand-dispatched CLI);
- **fg096b** (MCP server, shipped);
- **fg051c and fg094b** (duplicate TUI beads);
- **ykaa** (a 2026-08-24 decision queue whose sources are closed);
- **szm0** (a self-declared duplicate);
- **x2mv.4.26** (stale status);
- **fg035** (a roll-up).

Phase 3 and 4 owners sit at P3/P2 while the Phase 5/6 exit tests are P1. That inverts the plan's §50 order. It is recorded as owner decision D11, below.

## 6. Bridge plan

Order is by leverage. Existing owners keep their beads. Every track's exit is an executed result bound to a SHA.

**A. One `main`, compiled on every commit, and a second verifier (P0).**
1. **Landing (done here, §9).** Both lines are merged and compiled, with focused tests compared against origin.
2. **D7 recorded by the owner.** Whatever the ruling, a compile sentinel runs `cargo check --workspace --all-targets`, schema-gen, docs and the focused tests of touched crates on every new `origin/main` commit. It files or repairs breaks under the originating bead, and it bisects a red range in about log₂ k builds. `x2mv.4.2` implements it. The stronger form is `x2mv.4.25` (dogfood): writers push to a FrankenGit node whose required check is that sentinel, and it mirrors to GitHub. FrankenGit then verifies FrankenGit, and a divergent unpushed line cannot exist.
3. **D8 extended to a second verifier.** `x2mv.4.29` then runs a union verification at one SHA over all 27 `batch_pending` beads and `x2mv.4.56`'s queue.
4. **Every session lands or hands off.** `git fetch`, merge, push, or an explicit handoff comment naming the unpushed SHAs.
5. **Pin Node** for every JS lane (one place, typed refusal otherwise).

Exit: at one named SHA, `verify.sh fast` and `verify.sh e2e` exit 0, verification debt is below 28, and the sentinel has run on every commit since it landed.

**B. The JavaScript plane under a decision (P1).**
- D10 rules on the operator plane.
- The live-`fg` operator lane (`x2mv.4.59`) runs in every outcome.
- `x2mv.4.44` turns the duplicated decoder into evidence: until retirement, the JS and Rust bundle verifiers run differentially over the same corpora. A disagreement is a bug in one of them, and the lane says which.
- If D10 chooses porting, the order is GitHub migration (FG-049), then backups (`x2mv.4.21`), then source authoring (`p7sa`). Each JS entrypoint becomes a thin client of an `fg` subcommand, and the lane is the parity oracle.

**C. Integrity of what shipped (P1).**
- Failing-test clusters: webhook fan-out (`x2mv.4.57`), squash/resolution merges (`x2mv.4.58`), workflow check publication (`x2mv.4.70`).
- The remaining failing tests and lanes (`x2mv.4.26`, `5f68`).
- Required-check enforcement in receive and merge (`x2mv.4.6`, `x2mv.4.12`).
- Authenticated principals on every write (`x2mv.4.13`, `x2mv.4.34`).
- TLS or a ratified proxy profile (D9, then `x2mv.4.30`).
- Canonical outbox settlement (`x2mv.4.55`).

**D. A forge a team can run (Phase 5 exit, P1).** Exit test: team day, `x2mv.4.23`.
- The 16,384 ceiling via the settled-prefix MMR checkpoint (`x2mv.4.7`).
- Writer throughput against a published target (`x2mv.4.9` plus `x2mv.4.63`).
- The remaining PR workflow (`x2mv.4.20`) and search freshness (`x2mv.4.19`).
- The backup product in `fg` (`x2mv.4.21`).

**E. Close Phase 2 properly, then decide on Phases 3–4 (P1/P2).**
- Declare Tier A and run it against the pinned oracle (`x2mv.4.60`).
- D11 decides whether Phases 3–4 (`x2mv.4.22` ATP-Git, TreeFS `zb0q`/`mwck`) stay behind Phase 5. The plan says they come first (§50 steps 11–13).

**F. 1.0 definition-of-done gaps (P2/P3).** Upgrade/rollback (`x2mv.4.62`), the object-store fabric (`.61`), published performance targets (`.63`), the Phase 7 exit test (`.64`), the external-organization run (`.65`), the independent security assessment (`.66`), the refinement-bridge residue (`.67`), evidence import (`.68`) and build reuse (`.69`).

**G. Distributed, hosted and release (unchanged, after A–D).** `88g7`, `b5ph`, `0zjt`, FG-091, `25cs`.

**Owner decisions, all in `x2mv.4.14`:**
- D1: gateway versus ADR-0011.
- D2: browser versus ADR-0013, now including the served JS Git decoder.
- D3: sibling crate publication.
- D4: psm.
- D5: hostile CI.
- D6: routing authority and v1 scope.
- D7: direct-main publication. Asserted in 174 commit messages but never recorded.
- D8: verifiers. Extend it to a second verifier.
- D9: TLS.
- **D10 (new):** the JavaScript operator plane.
- **D11 (new):** phase order (Phases 3–4 vs 5–6).

## 7. How the plan was refined

**Phase 2 draft.** The 2026-10-13 checklist was re-graded at `f73a3cca`, and the gaps were mapped onto existing beads. Gaps with no owner became beads (§8).

**Executed-evidence feedback.** Three findings changed the plan's centre of gravity:
- Running the operator suites under two Node versions (240 vs 13 failures) showed the JS plane's evidence depends on an unpinned toolchain.
- Landing the two lines exposed that the local line itself carried an uncompiled commit, and that a mechanical merge would have made `fg mcp` refuse to start: its startup parity check validated a catalog different from the one it served.
- Running origin's own test binaries showed that every `fgit-cli` failure in the landing tree predates the merge. The landing also clears 15 failures: 13 dispatcher tests and 2 lease tests.

Together they moved "a landing point that compiles every commit" from a process suggestion to track A's first mechanism.

**Ambition pass 1.** Every track got an executable exit. The operator plane got a lane that serves both possible D10 outcomes, instead of waiting for the ruling.

**Ambition pass 2 (mechanisms).**
- The dogfood node (`x2mv.4.25`) is the structural answer to both §5.1 and §5.2. One landing point removes divergence by construction, and its required check is the compile sentinel.
- Batching verification at one SHA turns the verifier's cost from per-bead builds into one build plus per-bead acceptance reading. That is why one appointed verifier day can drain most of the queue.
- Running the duplicated decoders differentially turns a constitution violation into a correctness oracle until one side is retired.

**Ambition pass 3 (where mathematics pays).**
- **Bisection and group testing for the sentinel.** With k unverified commits and d independent breaks, adaptive group testing finds every culprit in O(d log k) builds rather than k. The 2026-10-11..16 window (k = 182, d ≈ 5) would cost about 40 builds instead of 182.
- **The settled-prefix Merkle Mountain Range checkpoint** (`x2mv.4.7`) stays the single mechanism for three problems:
  - bounded canonical state at O(log n);
  - O(log n) historical proofs for `fg verify-read` and the event feed;
  - a role for `fgit-projection` as the per-aggregate index.
- **CALM lattice types** (grow-only comment sets, observed-remove label sets) remain the basis for commuting monotone forge intents across CAS losers (`x2mv.4.39`). The new conversation and assignment intents are exactly that class.

**Refinement rounds** (the frozen Phase 5 prompt, applied to the new beads):
1. **Structure.** `scripts/bv_compat.sh --robot-insights` and `--robot-suggest` were run after creation. They found no cycles, and none of the suggestions involves a new bead. Only edges where work genuinely cannot proceed first are blocking.
2. **Evidence completeness.** The full origin workspace run (688 binaries) arrived after the first beads were filed, and changed them:
   - `x2mv.4.58` widened from 2 MCP tests to the 7-test squash/resolution cluster across node, HTTP and MCP;
   - `x2mv.4.70` was added for the 5 workflow-publication failures;
   - `x2mv.4.57` gained the failing e2e assertion ids and the shared-target defect.
3. **Tests and logging.** Every new bead maps each acceptance line to a named test or e2e assertion with a planted negative. The epic gained a logging and test standard for `.57`–`.70`: NDJSON steps, replay lines, no silenced stderr, pinned Node, no shared target directories, and Rust-read verification of JS results.
4. **Honesty.**
   - No new bead can close on refusal-only work.
   - The operator lane must check results through Rust reads, not the JS client's own report.
   - The security and external-organization beads cannot be satisfied by an agent of this swarm.
   - The dry run in `x2mv.4.65` does not close it.
5. **User impact and convergence.** Priorities were checked against what blocks a team first: merging with required checks, remote HTTP with TLS, the event ceiling, writer latency and failing merge tests. That puts the three failing-test clusters, the operator lane and Tier A at P1, and the 1.0 gaps at P2–P3. A final pass found nothing further to change.

## 8. Tracker changes made by this assessment

Every change below was made with `br … --no-db` against the merged export and is committed with this document. No bead was closed, reopened, claimed or reassigned.

**New children of `frankengit-root-doctrine-x2mv.4`** (label `reality-check-2026-10-17`). Each is self-contained: consumer, observed evidence with SHAs and file:line, deliverable, acceptance with a planted negative, and non-claims.

| Bead | P | Obligation |
|---|---|---|
| `x2mv.4.57` | P1 | `fg webhook dispatch fanout`: 10 fan-out tests fail at `f73a3cca` and after the landing (13 more dispatcher tests fail on origin only); `webhook_delivery` e2e fails 5 assertions |
| `x2mv.4.58` | P1 | Squash and conflict-resolved merges fail restart/recovery/atomicity tests on node, HTTP and MCP (7 tests) |
| `x2mv.4.59` | P1 | A live-`fg` lane for the JavaScript operator plane, with pinned Node |
| `x2mv.4.60` | P1 | Declare Tier A and run it against the pinned oracle (Phase 2 exit, DoD 2) |
| `x2mv.4.61` | P2 | An object fabric on an S3-compatible store (v1 item 15) |
| `x2mv.4.62` | P2 | Single-node upgrade, rollback and mixed-version recovery (DoD 14) |
| `x2mv.4.63` | P2 | Published performance and unit-economics targets and their lane (DoD 17) |
| `x2mv.4.64` | P2 | EXIT TEST Phase 7 |
| `x2mv.4.65` | P2 | EXIT TEST DoD 20: an external organization's run |
| `x2mv.4.66` | P2 | Independent security assessment (DoD 13) |
| `x2mv.4.67` | P3 | The refinement-bridge coverage inventory, with one history closed differentially |
| `x2mv.4.68` | P3 | Evidence-pack import that only tightens local checks |
| `x2mv.4.69` | P3 | Build-output reuse receipts and spot checks |
| `x2mv.4.70` | P1 | Trusted workflow check publication: 5 tests fail after `Succeeded → Success` |

**Edges.** Blocking edges were added only where the work cannot proceed first:
- `.61` is blocked by `.30` (TLS);
- `.65` is blocked by `.23` and FG-091;
- `.68` is blocked by `.6`;
- `.69` is blocked by `.12`;
- `.64` is blocked by `.19`.

Everything else is `related`: `.57`–`.55`/FG-046, `.58`–`.20`, `.59`–`.14`/FG-049/`.21`, `.60`–FG-090/`.33`, `.61`–`88g7`, `.62`–`.21`, `.63`–`.9`, `.64`–`.36` and `.70`–`.12`. `scripts/bv_compat.sh --robot-insights` reports no cycles. None of the 50 `--robot-suggest` suggestions involves a new bead.

**Evidence comments** were posted on:
- the decision queue `x2mv.4.14`: D7 status, the D8 extension, and the new D10 (JavaScript operator plane) and D11 (phase order);
- `x2mv.4.2`, `.12`, `.17`, `.18`, `.21`, `.26`, `.28`, `.37`, `.44`, `.54`, `.55`, `.56` and `5f68`;
- the epic, with the logging and test standard for `.57`–`.70`.

**Supersession comments** were posted on 11 beads that look delivered, conflicting or duplicate: `x2mv.1`, `x2mv.1.1`, FG-019, FG-050, FG-051a, fg096b, fg051c, fg094b, ykaa, szm0 and fg035. Dispositions are left to the owner and the verifier.

**Merged tracker after these changes:** 674 records, 649 live (486 closed, 98 open, 27 `batch_pending`, 17 rework, 8 blocked, 8 in progress, 5 deferred) and 25 tombstones. Verification debt is 35 of hard 36.

## 9. Landing record

The shared checkout's `main` (`7a8224e4`) and `origin/main` (`f73a3cca`) diverged at `6deda35c`. They were joined by one merge commit, **`bdec9ae19612c18fa4aff5cc2fedd97f057e3c0e`**, with both as parents. Its tree compiles (`cargo check --workspace --all-targets --locked` exit 0). It was built in a private worktree, so no other agent's checkout was touched. It was fast-forwarded into the shared checkout and pushed (`f73a3cca..bdec9ae1`) before this document and the tracker changes were committed on top.

**How the conflicts were resolved.**
- 30 files conflicted. For 18 of the 25 conflicted Rust files, the local side's change was only formatting: rustfmt of base and of local were identical. Those files take origin's content exactly.
- The other seven, and the non-Rust files, were resolved by hand:

| Area | Resolution |
|---|---|
| `crates/fgit-cli/src/main.rs`, `crates/fgit-node/src/source_retrieval.rs` (x2mv.4.54) | Local subcommand routing re-applied over origin's new `bisect`/`verify-read` dispatch and `backup::run_with_timeout`; `#[path]` module wiring restored |
| `crates/fgit-cli/src/mcp/backend.rs`, `backend/protection.rs` (x2mv.4.17) | One catalog: `NodeTools::tools` returns `tools_for_options`, which now includes origin's PR-comment tools. Protection show and set are listed by `protection::registered_tools()`. Origin's duplicate `show_tool()` removed |
| `crates/fgit-schema` registry and generated artifacts | 5 registry entries for origin's new tools (`issue_assign`, `issue_unassign`, `pull_comment`, `pull_comments`, `protection_set`) with the server's real fields and refusal codes; 42 entries, 38 active; artifacts regenerated, `check` exit 0 |
| `crates/fgit-schema` coverage (origin defect) | `verified-blob` registered as undescribed with its reason (nested `verified-read-envelope` frame) and added to the coverage type list |
| `crates/fgit-graph/canonical-bodies.tsv` (origin defect) | `source-lexical-manifest` described |
| `crates/fgit-authority-fsqlite` (x2mv.4.37, `da1943de`) | Fixed forward to the real `fgit-statistics`, `fgit-types` and `fgit-codec` APIs; `portable_store.rs` initializer; snapshot accessor. 5/5 controller tests pass on their first run |
| `crates/fgit-node/src/source_retrieval/integrity/bundle_verify.rs` | Duplicate re-export from the mixed merge removed |
| `crates/fgit-node/src/loose_import.rs` (x2mv.4.28) | Origin's spooled design kept; it already carries the local 512 MiB constants |
| `recovery/tests.rs` (E0689) | Origin's fix kept (`d27192b6`) |
| `Cargo.lock` | Regenerated offline; only workspace-internal edges changed (`fgit-authority-fsqlite` → `fgit-crypto`/`fgit-statistics`, `fgit-cli` → `fgit-schema`); no external crate version moved |
| `.beads/issues.jsonl` | Three-way field merge against `6deda35c`. Side-only changes kept. Where both sides changed a record, comments and dependencies were unioned and status/assignee taken from the side that changed them. 660 records, no hard conflict |
| Browser tests, `scripts/lib/source-recovery.mjs` | Origin's versions where they conflicted; origin had repaired the same tests and the same post-publication finalization |
| `tests/browser/response-content-encoding.test.mjs` | Local `7c604293` had reversed the `gzip, br` fixture to pass on Node 22.2. The HTTP order, brotli over gzip, is restored and passes on Node 22.22.1 (55/55) |
| `docs/LOCAL_MEDIA_RECOVERY.md` (origin defect) | Broken link repointed |

**What the landing does not do.**
- It does not run rustfmt over origin's code: 79 files remain unformatted, all of them origin's.
- It does not fix origin's failing webhook fan-out or MCP squash/resolution tests; those are filed (§8).
- It closes, reopens and verifies no bead.

**Focused tests compared, origin vs landing** (same host, same toolchain):

| Package / suite | `f73a3cca` | Landing `bdec9ae1` |
|---|---|---|
| `cargo check --workspace --all-targets` | exit 0, 267 warning lines | exit 0, 231 warning lines |
| `fgit-schema-gen check`, `verify.sh docs` | exit 1, exit 1 | exit 0, exit 0 |
| `fgit-schema --all-targets` | 1 failure (coverage) | all pass |
| `fgit-authority-fsqlite --all-targets` | pass | pass, including 5 new controller tests |
| `fgit-cli --all-targets` | 1,041 passed, 31 failed | 1,058 passed, 18 failed, all also failing on origin |
| `fgit-runner --test sparse_workspace` | 2 failures | 17/17 |
| `fgit-forge --test atomic_merge` | 1 failure | 1 failure (origin defect, unchanged) |
| browser node:test (Node 22.22.1) | 92 failures / 3,600 | 87 failures / 3,600 |

The landing tree's full workspace test build was not run: the host disk had about 55 GB free, and one fgit-node test build takes about 35 GB. The crates the merge changed were run instead, as above.

## 10. Evidence appendix

Paths are relative to the assessor's session scratchpad. These are review artifacts, not published durable evidence.

| Artifact | SHA-256 |
|---|---|
| `fg-release-f73a3cca` (release `fg` at `f73a3cca`) | `dd0a988982b41ee5ae4709131d17fbe1f5834c9a68fd5bfe825362b0dfde31b4` |
| `logs/check.log` (origin `cargo check --all-targets`) | `3ea9f769acec74b4cb17253c509432a03f7e349460af73c78c39ae2d71779233` |
| `logs/fmt.log` (origin rustfmt check) | `e8d7ce60672c5dc14dfe4a56c2cbd792984b237ca13264237413014f6572ccb0` |
| `logs/fmt-files.txt` (origin unformatted file list) | `e061d7b85ab49dc17536ef7df3af775396af8a348a1f6d825cbb6a61ba320047` |
| `logs/schema_check_origin.log` (origin schema-gen check) | `cb23736ce29ab620935d2e18424c41ca7fc99ab3da1286898d9713fa61dc303f` |
| `logs/lane_docs_origin.log` (origin docs lane) | `48c2cec17cb873b4c84bc8816f7f17085e33c0d154abb6ca247dfb737c1d1a03` |
| `logs/lane_constitution_origin.log` (origin constitution lane) | `aeb73b03d709a248ec34d053150ce563d40e651825d3628f6957df83b4684342` |
| `logs/origin-tests/results.jsonl` (origin, 688 test binaries) | `4b6d144f9740bd90de7dab1bd67081613ec7da4bc3213955aa95655b6efa14e4` |
| `logs/origin-tests.out` (origin test driver summary) | `3202bca22e1a7970486c757c1f11f537a73041aad68b8b632f4076bdbfdd6888` |
| `e2e-origin/run/receipt.ndjson` (origin e2e, 69 suites) | `96d598220c06b70334c9c5a1f2573db957c0b1fc51767ca639a8f44fcac22748` |
| `logs/js_origin2222_browser.tap` (origin browser node:test, Node 22.22.1) | `e19794cfff4738a60aba4cbbb31f503ff146ad266cea23e5afd36b00e9679b95` |
| `logs/js_origin2222_operator.tap` (origin operator node:test, Node 22.22.1) | `8262f4589719535b78f0c5efe4aeeccff1cb5763ca5173e193fcb850341ebe85` |
| `logs/js_origin2222_scripts.tap` (origin scripts node:test, Node 22.22.1) | `ff57f037dc17c7435d62d08acd0f0b320c94942c29be7e7ef9db57333df9c096` |
| `logs/js_browser.tap` (origin browser node:test, Node 22.2.0) | `b97d5c8c64f8badca1da3600c9cb4c2c9595737d033bc392decf345e39071b5c` |
| `logs/js_operator.tap` (origin operator node:test, Node 22.2.0) | `3baacad63c3376e5ceb1c67969a4b0decb0adad02dc371831c0a781a3bd8f87b` |
| `logs/js_scripts.tap` (origin scripts node:test, Node 22.2.0) | `f99809aa8066e120a424f57c31a38654d786a3b55d532a2d95cb17322378d073` |
| `logs/land_check_final.log` (landing `cargo check --all-targets`) | `07cf855f968b04bda94abb907f85f02126e01899925d9ff70ce443ffb202704f` |
| `logs/land_docs.log` (landing docs lane) | `00f0b6f37b13dadc19fe5cdc3957e86b6c76e4d0bccc429447f879de408b9546` |
| `logs/land_constitution.log` (landing constitution lane) | `563de18a37dc269420533f81b0dc3fcba52c95e786d1ed9ebbae7bbcde6831dd` |
| `logs/land-tests/land-fgit-cli.log` (landing `fgit-cli --all-targets`) | `1e9f08d18eab6e5e92332784bd8f5aa284e13bf8628bae858bc4eca1a1a69eee` |
| `logs/land_js_browser_2222.tap` (landing browser node:test, Node 22.22.1) | `b4f7e52a02be8dfa6bf03d47e8acbaeab26175d08974cb0c37c7afdccd037e20` |
| `issues_merged.jsonl` (tracker merge, before the new beads) | `05cab89a62f02749623058b721620541036373758e38dc98ac456b196c2f6c7c` |
| `bv_insights.json` (`bv_compat.sh --robot-insights`) | `5916ef14b4083f302405b8b83f76414faaab806f38308fe9a9035f5108c1b4a5` |
| `bv_suggest.json` (`bv_compat.sh --robot-suggest`) | `7f78ce885a3911a57b935e6d4cc8e1dab25df54c9bb5fce3f485c19dbb1cfdb3` |

The `fgit-schema` landing run recorded in `logs/land-tests/land-fgit-schema.log` predates the coverage repair. The repaired tree's `cargo test -p fgit-schema --all-targets` was rerun in the session and passed every binary.

## History

Earlier assessments are kept in git history of this file: 2026-09-23 (`6c762f42`), 2026-09-27/29 (`f3da9d4f` and the D8 verifier wave at `14ce0fa1`) and 2026-10-13 (`9477ceac`). Their binding facts, carried forward:
- **2026-09-23:** main did not compile (`46b922e7`); the SSH key exchange used a constant key; ten crates were islands.
- **2026-09-27:** main compiled at `2b7f35ac`, 7,624 tests passed and 26 failed; browser pages could not call their API in Chrome from 2026-09-18 to 2026-09-27 (`x2mv.4.45`).
- **2026-09-29:** the D8 union verification at `14ce0fa1` closed 10 beads and returned 17 to rework.
- **2026-10-13:** the 30 commits after `25fd5d1c` were uncompiled, `0b9b1c85` broke `--all-targets` (E0689), and 142 files were unformatted.
