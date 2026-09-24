# FrankenGit reality check and bridge plan — 2026-09-23

FrankenGit is a real, bounded, pure-Rust Git server with a genuinely atomic forge core. It serves clone, fetch and push to stock Git clients, and a pull-request merge publishes the ref move, the PR state and the outbox entry in one authority compare-and-swap. It is not yet a forge a team can rely on. The gap has changed shape since 2026-09-07, from "missing composition" to "unverified breadth":

- The rate of new surface is far ahead of verification. Main does not compile at HEAD. 163 commits since 2026-09-07 say in their own messages that compilation or tests were not run (115 because Cargo/rustc was unavailable).
- A 2026-09-22 closure wave marked the SSH transport, hostile-CI campaign, projection substrate and policy rewiring complete when their acceptance was not met.
- About 68K lines of product crates (agent plane, ATP-Git, RaptorQ/repair/GC, safe Markdown, projections, statistics) are linked into no binary.

This supersedes the 2026-09-07 snapshot in place.

**Binding.**
- Source was inspected at `46b922e7` (HEAD at the start of the assessment). HEAD does not compile.
- Executable evidence was produced in an isolated detached worktree at its parent, `94a77dfb`, the newest commit whose product binary builds. The run used `nightly-2026-08-31` on Linux x86_64, a private target directory, and a private `CARGO_HOME` (symlinked registry, `CARGO_NET_OFFLINE=true`), because other projects' builds held the shared package-cache lock. The repository's own `verify.sh` sets `RCH_CARGO_WRAPPER_BYPASS=1`, and the direct cargo invocations here did the same.
- Unrelated projects' builds were running concurrently. Timing-sensitive results are labelled as such.
- This is not a security audit, universal compatibility result, benchmark claim or batch-verification certificate.

**Consumer and retirement.** The repository owner, the batch orchestrator and every assignee use this document to decide what is actually done and what to build next. The observed defect classes are:
- uncompiled code on main;
- acceptance-unmet closures;
- product crates with no production caller;
- security defects on shipped listeners;
- stale public claims.

Replace this snapshot in place when a later revision-bound assessment supersedes it. The epic `frankengit-root-doctrine-x2mv.4` and its children take over each resolved row. This report grants no capability credit.

## 1. What was examined

All of `AGENTS.md`, `README.md` and the previous reality check were read. The comprehensive plan's product definition, v1 scope (§4.1), delivery roadmap (§44), success metrics (§48) and definition of done (§49) were read, as were the normative contracts' release-blocking invariants (§32) and the verification specification's structure.

Six independent read-only audits traced six subsystems through source, tests, docs and the tracker:
- the Git transport surface;
- forge workflows;
- user surfaces (CLI, HTTP, browser, MCP, TUI);
- the agent plane, TreeFS and CI;
- search, graphs and projections;
- durability, operations, release and the constitution.

Every critical claim those audits made was re-checked directly before inclusion. Examples:
- the SSH constant key at `crates/fgit-ssh/src/session.rs:419`;
- the 4,096-event read cap at `crates/fgit-admission/src/merge/native/pull_request.rs:214-245`;
- the dummy webhook payload in `crates/fgit-node/src/webhook.rs:268-282`;
- the hard-coded policy facts at `crates/fgit-admission/src/policy_bridge.rs:277-285`;
- the fail-open receive check at `crates/fgit-admission/src/lib.rs:2469-2474`;
- the combiner having no callers;
- the crate reachability graph derived from every manifest.

The tracker baseline was `br list --status all --limit 0 --no-db --json` (569 records, `has_more=false`), plus `br ready --unassigned --no-db --json` and `br gate list` for every bead closed since 2026-09-17. Git history since 2026-09-07 was classified by bead reference and by self-declared execution status.

## 2. Executable evidence at `94a77dfb`

The host filesystem filled (0 bytes free) late in the first test pass. Every binary from #500 onward, and every failure, was re-run once the owner freed space. The seven race binaries were run a third time from a near-idle host. The counts below combine valid first-pass results with the rerun.

| Check | Result | What it establishes |
|---|---|---|
| `cargo check --workspace --all-targets` at HEAD `46b922e7` | exit 101: fgit-runner lib E0423 (`journaled/observations.rs:114-115`) | `fg` cannot be built at HEAD. Newer origin commits (`3a7ab99b`, `bfb3bb30`, `33583151`) were pushed on top, each declaring it was never compiled. |
| `verify.sh docs` | exit 1 | Stale README claim block (CLM-001 demoted by ecdc799d) plus a hosted write-to-main workflow merged 2026-09-22. |
| `verify.sh constitution` (after a fresh build) | exit 0 | Checks pass. Native linkage is evaluated against cached observations. psm's `libpsm_s.a` (assembled x86_64 object plus a C flag probe) is admitted by DEP-262. |
| `cargo fmt --all -- --check` | exit 1 | Drift in 72 files at HEAD, all from post-2026-09-22 commits. |
| `cargo check --workspace --all-targets` | exit 101 | fgit-forge lib-test target: 29 errors (uncompiled daa87647). |
| `fgit-schema-gen check` | exit 0 | Generated schema artifacts are current. |
| `cargo test --workspace --all-targets --no-fail-fast` | exit 101, **zero tests run** | cargo aborts on uncompilable test targets (fgit-forge lib test, and fgit-node `fg-repository-backup` bin test). |
| All compilable test executables (`cargo build --all-targets --keep-going`, then each binary run) | 629 executables ran. 6,779 passed, **45 failed**, 31 ignored, across 26 failing binaries. The run used `cargo build --all-targets --keep-going` and then ran each binary. It was re-run from #500 on after a host ENOSPC, and the race binaries were run a third time from a near-idle host. | Classes: 7 concurrent-writer race tests where losers get `503 outcome_unknown` (reproducible; `x2mv.4.27`); snapshot-pin contract disagreement (issue/PR); branch-root and fast-forward semantic drift; backup/restore quarantine-cleanup failures; drift from the uncompiled stream (event kind 11, workflow files, bundle form fields, CLI JSON); a TreeFS lease `WouldBlock`; one temp-dir collision. Details in `x2mv.4.26`. |
| `cargo clippy --workspace --all-targets -D warnings` | exit 101 | At least 30 errors (fgit-diff 23, fgit-schema 5, fgit-resource 1, registry-check 1). Dependents not linted. |
| `verify.sh full` / `release` | exit 3 / exit 3 | Explicit dormancy. `release` reaches only `--release-gate-probe`. |
| `cargo build --release -p fgit-cli` | exit 0 | A release `fg` exists for 94a77dfb. |
| E2E `first_clone`, `first_push`, `time_travel` (debug `fg`, Git 2.55.0) | 19/19, 21/21, 15/15 | Non-empty clone, raw push with its refusal twin, and historical state work through the binary. |
| E2E `sha256_repo_roundtrip` | 26/26 | SHA-256 repository init/refusal/serve/clone. |
| E2E `incremental_fetch` (pinned Git 2.54.0 oracle) | debug: 29/30; release: **97/97** | The debug failure was `fg import` hitting its wall-clock deadline (`ResourceBudgetExceeded; exhaustion=Some(Deadline)`) at load average ~39. The release binary passes. |
| E2E `ssh_transport_security` (OpenSSH client) | 23/23 | Authentication and command refusals only. It does not test confidentiality, and the key exchange is not confidential (§5.3). |
| E2E `tag_lifecycle` | 7/15 | Suite defects, not a product failure: `ls-remote` shows both tags correctly advertised. |
| Orphaned smokes (run by no lane): smart_http, source_search, workspace_publication, transaction_outcome | pass | Smart HTTP passes SHA-1 and SHA-256 over v0/v1/v2 with stock Git, **using an injected `Idempotency-Key` header**. |
| Orphaned smokes: pull_request, issue | **fail** | A stale `--expected-head` pin returns a page (exit 0) where the campaign requires a typed refusal ("stale pin disclosed a mixed page"). The `issue_http` snapshot-walk test also fails. The code, the tests and the campaigns disagree on the snapshot-pin contract, and have since 5c294d6e. |

Ordinary-client cells (`first_clone`, `first_push`, `time_travel`, `tag_lifecycle`, `ssh_transport_security`) use the installed Git 2.55.0 and OpenSSH. They are compatibility observations, not the constitution's pinned-oracle class. `incremental_fetch` uses the verified pinned Git 2.54.0 oracle.

## 3. The short answer

**Where are we really?** Roughly at the end of plan Phase 2 (pure-Rust Git core), with a real but narrow slice of Phase 5 (forge core) and trusted-local fragments of Phases 4 and 6. Phases 3, 7, 8 and 9 exist only as libraries. The README vision of "a forge designed for humans, autonomous coding agents, extreme scale, and independently verifiable recovery" is not delivered in any of its four qualifiers yet.

**What works (with evidence).**
- The canonical core:
  - one transaction-identity derivation;
  - seals;
  - RCR;
  - the exact-predecessor head CAS on FrankenSQLite;
  - lost-response outcome recovery (`fg outcome`).
- Raw git-daemon clone/fetch/push with quarantine and typed refusals, against real clients.
- Loose and idx/pack import, and export.
- SHA-256 repositories.
- `fg at` time travel over durable history.
- PR open/update/close/review and a durable merge whose ref, PR state and outbox publish in one RCR. It survives reopen and process death (`crates/fgit-node/tests/native_merge_publication.rs`, `native_merge_durable_crashes.rs`).
- Issues with comments, labels and linear-scan search.
- Branches and tags.
- Trusted-local TreeFS workspaces through `fg workspace run/apply`, on a real openat2-confined sparse host adapter.
- A loopback-only smart-HTTP server that serves fetch and (with a nonstandard header) push.
- A stdio MCP server with write tools.
- A static JavaScript browser shell.
- Literal, regex, lexical-index and Rust-symbol search.

**What does not work or is not implemented.**
- Concurrent writers: the losing writer gets `503 outcome_unknown` or the wrong refusal count instead of a deterministic refusal. Seven race tests fail, reproducibly (§5.11).
- Snapshot-pinned PR/issue reads disagree with their own campaigns and tests about stale pins (§5.11).
- Authority backup restore reports incomplete on every tested path.
- SSH is not confidential (§5.3).
- Stock `git push` over HTTP fails.
- PR/issue reads stop after 4,096 forge events (§5.5).
- Policy evaluation fabricates facts and fails open (§5.6).
- Webhooks send an empty dummy payload.
- CI is trusted-host only: no triggers, no published checks, no required-check gating.
- There is no GC, scrub, repair or RaptorQ on node data; the fabric grows forever.
- No remote authority backend.
- No per-core lanes or combiner in admission.
- No ATP-Git on any path.
- No safe Markdown rendering.
- No projection read models.
- The agent plane is an island.
- No authenticated identity on CLI or MCP writes.
- No TUI, GitHub import, LFS, merge queue in admission, or release.

**What is blocking us.** In order of leverage:
1. **Verification collapse.** Code lands on main uncompiled, gates close on "crate tests pass" instead of acceptance lines, and most new work bypasses the tracker (§5.1, §5.2, §5.9). Until this stops, nobody, including the owner, can know what works.
2. **Composition debt.** Libraries are finished to a much higher standard than their integration. The next unit of value comes from connecting existing crates to the node, not from writing more of them (§5.4).
3. **Owner decisions:**
   - ADR-0011 gateway and ADR-0013 web UI versus what shipped;
   - publishing fastapi_rust and frankentui on Asupersync 0.5;
   - psm native assembly;
   - the hostile-CI isolation stance;
   - routing authority (`b5ph`);
   - v1 scope precedence (`fjsz`).
   All are listed in `frankengit-root-doctrine-x2mv.4.14`.

**If every open and in-progress bead were implemented, would the gap close?** No:
- Most of the gap sits under beads that are already closed (§5.2) or has no bead at all. Examples: SSH confidentiality, the event-log cliff, policy fact fabrication, node GC/repair, combiner integration, safe Markdown, the CI product loop, identity binding, the backup product, and the unwired smoke campaigns.
- Several open beads describe a product that no longer matches what exists. FG-051a requires CLI commands not to import storage, but every verb opens the node in-process. FG-050 wants a server-rendered UI, but ADR-0013 forbids that and a JavaScript shell shipped instead.
- There are now 0 in-progress beads, and the stream carrying most new code is not claimed at all.

**Vision goals with no bead before this assessment** are listed in §6. They are now covered by `frankengit-root-doctrine-x2mv.4.*`.

## 4. Vision checklist

Status vocabulary:

| Status | Meaning |
|---|---|
| WORKING | Executed end to end through the product binary in this assessment or its cited revision-bound suite |
| PARTIAL | Real, but part of the stated goal is missing |
| LIBRARY-ONLY | Real code with no production caller |
| STUB | Placeholder behaviour behind a real interface |
| BROKEN | Present and defective |
| NOT_STARTED | No code |

**v1 functional scope (plan §4.1)**

| # | Goal | Status | Evidence | Work |
|---|---|---|---|---|
| 1 | Repository creation/import/export | WORKING (bounded) | `fg init/import/export`; first_clone/first_push at 94a77dfb | FG-106 pending; `e6jj` 128 MiB writer ceiling |
| 2 | SSH and smart HTTP access | BROKEN / PARTIAL | SSH fixed ephemeral key; HTTP loopback-only, `Idempotency-Key` required, node reopened per request, exits after 1,024 requests | `x2mv.4.4`, `x2mv.4.8`; FG-105a/b open |
| 3 | Protocol-accurate clone/fetch/push | WORKING for the declared daemon tier | e2e §2; push options never advertised; `atomic` on HTTP only | FG-019 open, FG-098 |
| 4 | Branch/tag listing and atomic ref updates | WORKING | `fg branch/tag/refs`, HTTP branch/tag APIs | — |
| 5 | Users, orgs, teams, tokens, deploy keys | PARTIAL | fgit-identity library; only SSH deploy keys and a loopback HTTP token file are used; CLI/MCP principals are self-asserted | `x2mv.4.13` |
| 6 | Protected refs and policy snapshots | BROKEN | Mandatory review works inline, but the policy engine gets fabricated facts, fails open on receive, and never activates stored snapshots | `x2mv.4.6` |
| 7 | PRs, reviews, comments, labels, merge | PARTIAL | Atomic durable merge works; no reopen, PR comments, squash/ff, or approval-survival rule; 4,096-event cliff | `x2mv.4.7`, `x2mv.4.20` |
| 8 | Issues and discussions | PARTIAL | Issues work; no discussions, assignees, milestones or notifications | FG-045 |
| 9 | Webhooks and event API | STUB / PARTIAL | `fg events` pull feed works; webhook payload is a dummy and there is no worker | FG-046 (rework comment) |
| 10 | Safe Markdown rendering | LIBRARY-ONLY | fgit-doc has no dependents | `x2mv.4.11` |
| 11 | Basic lexical and symbol search | PARTIAL | Works on quiet repositories; any write stales the index; builds abort on one bad file | `x2mv.4.19`, FG-032a |
| 12 | CI with artifacts and cache | PARTIAL (trusted only) | `fg workflow run` durable journal; no triggers, check publication, artifacts, cache or isolation | `x2mv.4.12`, `25cs` |
| 13 | Agent identities, Intent Runs, workspaces, evidence | PARTIAL / LIBRARY-ONLY | Workspaces work (trusted); IntentRun/broker/ECC are an island | `x2mv.4.24`, `xcu9`, `sjzo`, `p7sa` |
| 14 | Backup, capsule export, scrub, verify, restore | PARTIAL / BROKEN | Backup binaries exist but restore tests fail at 94a77dfb (§2); capped at 1 GiB/100K objects; no scrub/repair | `x2mv.4.21`, `x2mv.4.10` |
| 15 | Single-node and object-store deployment | PARTIAL / STUB | Single node works; object-store adapter refuses TLS and speaks a private protocol | `88g7` (comment) |
| 16 | GitHub import and compatibility matrix | NOT_STARTED / stale | FG-049 open; matrix last edited 2026-09-04 | FG-049, FG-090 |

**README core innovations**

| Innovation | Status | Evidence |
|---|---|---|
| Decisions + RCR, one head CAS for ref and forge | WORKING (merge path) | asa3 chain, reopen/crash tests |
| Stable retry identity, immutable outcomes | WORKING | `fg outcome`; transaction_outcome recovery |
| Per-core preparation, flat combiner, witness refinement | LIBRARY-ONLY | `fgit-txn` combiner/lanes have 0 external callers; fgit-witness has 0 dependents (`x2mv.4.9`) |
| ATP-Git | LIBRARY-ONLY | 0 dependents (`x2mv.4.22`) |
| TreeFS | PARTIAL | Library plus trusted sparse host adapter; files copied, not shared; no FUSE |
| Typed graph fabrics | LIBRARY-ONLY | Algorithms real; none of the nine GRAPH views built from canonical data |
| CALM and obligation-typed effects | PARTIAL | Vocabulary exists; runner "obligations" are counters; no Asupersync regions in runner, agent or TreeFS |
| Repair through authority | LIBRARY-ONLY | fgit-repair has 0 dependents (`x2mv.4.10`) |
| Conformal/e-process policy | LIBRARY-ONLY | fgit-statistics consumed only by unlinked crates |
| Local root-last releases | STUB | `verify.sh release` exits 3; the release attempt is a probe (`0zjt` comment) |

**Beyond parity:**
- Verified reads: LIBRARY-ONLY; node functions have no transport caller.
- Time travel: WORKING (`fg at`).
- Evidence economy: LIBRARY-ONLY (fgit-exchange unlinked).
- Deterministic build outputs: STUB (in-memory `OutputStore`).
- Formal core: contained Lean model only, as the README says.

**Constitution:**
- `#![forbid(unsafe_code)]`: pass (all roots).
- No Tokio, hyper, OpenSSL, ring or libgit2: pass.
- No production `git` subprocess: pass.
- One Asupersync constellation: pass at 0.5.0, but the constitution text still says 0.4.x.
- Native code: psm assembles and links `libpsm_s.a` (verified in `build/psm/*/out`), which the registry admits while DEP-182 says the opposite (`x2mv.4.15`, D4).
- Lint-relaxation gate: misses `#[expect(`.

## 5. Findings that should change priorities

### 5.1 Main is being fed code nobody compiled

- About 1,000 non-merge commits landed between 2026-09-07 and origin/main `bfb3bb30`. 163 of them state that compilation or tests were not run, and 115 explicitly say Cargo/rustc was unavailable. The stream stayed active during this assessment: `3a7ab99b` and `bfb3bb30` were pushed on top of the broken HEAD, and both declare they were never compiled. That includes every feature commit from 2026-09-22 onward.
- HEAD `46b922e7` fails `cargo check` in fgit-runner (`journaled/observations.rs:114-115`, E0423). Because fgit-node and fgit-cli depend on it, `fg` cannot be built at HEAD.
- At `94a77dfb`:
  - the fgit-forge lib-test target has 29 compile errors in the uncompiled exact-rename tests (daa87647);
  - an fgit-node bin-test target misses a struct field (`resume_engine_tests.rs:134`);
  - the new `WorkflowCheck` event kind broke an existing codec contract test (`crates/fgit-forge/tests/atomic_merge.rs:481`: "kind 11 must be refused").
- Formatting drift covers 72 files, all from post-2026-09-22 commits.

The 2026-08-31..09-02 toolchain-less stream did the same thing once already (omr4). This is the root cause of most other findings. It gets P0 treatment in `x2mv.4.1` and `x2mv.4.2`.

### 5.2 The 2026-09-22 closure wave overstates delivery

Twenty-eight beads closed on one day. Twelve batch_verify gates have no note and no SHA, which AGENTS.md 16.2 calls unsupported. One gate provider is also the implementer of several beads closed in the same wave.

Beads whose own acceptance lines are demonstrably unmet: FG-047/047b (SSH), FG-095b and FG-095c (workflow, "hostile execution"), FG-072, FG-093b, FG-029b, FG-043r/b/c, FG-096a and FG-094a. Several "e2e" suites cited as evidence are `cargo test` wrappers that grep test names, not product runs.

`x2mv.4.3` lists every line and requires the verifier to reopen or re-close each one with SHA-bound, acceptance-mapped evidence. It also requires the tooling to refuse SHA-less or self-provided gates.

This assessment did not reopen any bead. That transition belongs to the independent verifier.

### 5.3 SSH is not confidential

`crates/fgit-ssh/src/session.rs:419` initialises every session's ephemeral X25519 key from the constant `[0x77; 32]`, and the KEXINIT cookie is constant. Other problems:
- the MAC comparison is not constant-time;
- a peer can make the server buffer about 4 GiB before authentication;
- flow control is ignored;
- a silent client pins a worker forever;
- push has never been tested over SSH.

Host-key signatures still authenticate the server. Session contents are recoverable from the transcript. `fg serve-ssh` binds any address. See `x2mv.4.4`.

Separately, `fg serve --receive-principal` also binds any address, so any network peer can push as that principal (`x2mv.4.5`).

### 5.4 About 68K lines of product crates run in no program

Reachability derived from every manifest: 32 of the 48 crates under `crates/` link into `fg`. Of the 16 that do not, five are tooling (lab, benchmark, proof-bridge, slo, release). The other eleven are product crates with neither a production dependent nor a binary, about 68K source lines in total:

fgit-agent, fgit-atp-git, fgit-raptorq, fgit-repair, fgit-compaction, fgit-doc, fgit-projection, fgit-statistics, fgit-witness, fgit-exchange, fgit-object-store.

In addition, the per-core lanes and flat combiner inside fgit-txn have no caller outside that crate. Their closed beads certified library slices. Three README core innovations (per-core preparation, ATP-Git, repair through authority) and two "beyond parity" capabilities (evidence exchange, build reuse) therefore have no runtime effect.

Integration beads now exist for each: `x2mv.4.9`, `.10`, `.11`, `.22`, `.24`, and existing `88g7`.

### 5.5 The forge has a hard event cliff

Settled outbox entries are never removed. Every materialization re-verifies the whole outbox. PR and issue reads refuse above 4,096 forge or outbox entries, and that includes the review check a protected merge performs. At 16,384 entries the codec refuses all forge publication (`crates/fgit-codec/src/canonical_state.rs:21-22`). The projection substrate built to avoid exactly this has no consumer. See `x2mv.4.7`.

### 5.6 Policy evaluation is decorative

- Every principal is presented to the policy engine as `Human` with `MultiFactor` at time zero.
- Receive-path compile or evaluation errors skip the check (`if let Ok`).
- Branch names are interpolated into policy source.
- Any `ci_check` receipt satisfies all required checks regardless of name or commit.
- The snapshot identity is not bound into the RCR.

Mandatory review protection works only because it is an inline check. See `x2mv.4.6`.

### 5.7 The shipped user surfaces diverge from the accepted ADRs

- `fg serve-http` is a hand-written HTTP/1.1 server carrying Git, about 40 REST routes (form-encoded, hex bytes, no OpenAPI) and the browser. The plan explicitly rejected an owned HTTP surface in favour of fastapi_rust.
- The browser is about 7.8K lines of hand-written JavaScript that re-implements Git object hashing. ADR-0013 forbids a JavaScript-first primary UI. Its roughly 740 tests use a fake DOM and run in no lane.
- The CLI and MCP open storage in-process with self-asserted principals.

These may be acceptable interims, but no ADR says so. They are owner decisions D1 and D2 in `x2mv.4.14`.

The external blocker is now concrete. Published fastapi-core 0.4.4 and ftui-runtime 0.7.0 require asupersync ^0.4.9, while the local fastapi_rust and frankentui sources already pin 0.5.0 but are unpublished (D3). FG-094a's closed ftui admission is invalid on 0.5.0.

### 5.8 CI is trusted-host execution with inflatable labels

- `ProcessSubstrate` runs `/bin/sh -eu -c` as a direct child, as the host user, with full network.
- It ignores the isolation and egress fields that `RunnerPolicy` requires, and always reports one reaped process.
- Nothing triggers runs from pushes or PRs.
- Check results are not published to PRs.
- Required checks cannot pass.
- The only hostile-isolation bead (`25cs`) has no description.

See `x2mv.4.12` and owner decision D5.

### 5.9 The tracker no longer describes the work

- Only 348 of 1,000 non-merge commits since 2026-09-07 cite a bead.
- The heaviest streams landed against beads that are open, unassigned and untouched since 2026-08-21: FG-051a (28 commits), FG-032/FG-032a (41), FG-105/FG-105a (13), FG-050, FG-096b. Others went to unrelated closed beads (browser work credited to asa3, FG-044 and FG-058).
- No bead is in progress.
- 28 beads are batch_pending, the policy's soft verification-debt limit; the oldest has waited since 2026-08-26.
- About 40 Python smoke campaigns, and the browser tests, run in no lane, while seven docs tell readers to run them. See `x2mv.4.18` and `x2mv.4.2`.

### 5.10 Documentation is stale in both directions

The README still says:
- smart HTTP and SSH are absent;
- no native API, MCP, UI or search exists;
- the constellation is Asupersync 0.4.x;
- sqlmodel is 0.4.2.

It also:
- presents per-core microbatching, clustered object-store deployment and portable capsule backup in the present tense;
- describes asa3's outbox "reconciliation worker", which does not exist;
- links a `#reality-snapshot-2026-09-04` anchor that no longer exists.

The negative-evidence ledger has not changed since 2026-08-29. This assessment updates the README snapshot. The remaining reconciliation belongs to `fjsz` and `x2mv.4.15`.

### 5.11 Concurrent writers and pinned reads are not deterministic

Seven race tests fail in three independent runs, including one that started on a near-idle host:
- `issue_http_race`, `pull_request_http` and `source_change_http`;
- `initial_commit_http`, `branch_http` and `tag_http`;
- `guarded_git_daemon`.

Where the tests expect one winner and one typed refusal, the losing writer gets HTTP `503 {"code":"outcome_unknown"}`, or the refusal counts are wrong. This violates the normative rule that a sealed transaction reaches exactly one terminal decision, and that CAS losers re-evaluate the same sealed request. `outcome_unknown` is for genuine transport ambiguity, not a lost race. Relatedly, `fg branch update` on a protected branch reports a deterministic pre-seal refusal as "no terminal outcome ... not evidence of non-commit". See `x2mv.4.27`.

Separately, the PR and issue campaigns and the `issue_http` snapshot-walk tests disagree with the code about stale `--expected-head` pins, and have since `5c294d6e`. A stale pin returns a page where the campaigns require a typed refusal. The contract must be decided explicitly (`x2mv.4.26`).

## 6. Tracker coverage

Baseline counts: 569 records (475 closed, 55 open, 28 batch_pending, 6 blocked, 5 deferred, 0 in progress). `br ready --unassigned` returned four records: FG-032a, FG-045, FG-093c and `xcu9`. Of the eight 2026-09-07 audit beads:
- two progressed: `zb0q` (with strong evidence) and `l0xt`;
- none closed;
- the rest are untouched.

Vision goals that had no owning bead before this assessment:
- SSH confidentiality and robustness;
- deterministic concurrent-writer outcomes;
- daemon bind policy;
- policy fact integrity;
- the forge event cliff;
- smart-HTTP stock-push compatibility and serving lifecycle;
- combiner integration;
- node GC/scrub/repair/RaptorQ/compaction;
- safe Markdown;
- the CI product loop after FG-095 closed;
- identity binding on write surfaces;
- the MCP registry drift;
- the orphaned campaigns;
- search usability on active repositories;
- the PR workflow gaps;
- the backup product;
- ATP-Git on a real path;
- integrating exit tests for a human team and an agent;
- dogfooding;
- constitution and registry drift;
- repository hygiene;
- stopping uncompiled landings.

## 7. Bridge plan

Order is by leverage, not ease. Existing owners keep their beads.

**A. Make main trustworthy again (P0).**
1. Compile HEAD and run the never-run tests (`x2mv.4.1`).
2. Refuse uncompiled landings in the path the producers actually use, and route the unclaimed streams through their beads (`x2mv.4.2`).
3. Return the canonical fast lane to green (`x2mv.4.26`).
4. Re-verify the closure wave line by line (`x2mv.4.3`).
5. Make concurrent-writer losers deterministic (`x2mv.4.27`).

Exit: `verify.sh fast` exits 0 at a named SHA and every listed closure is either re-closed with mapped evidence or reopened. This earns no feature credit. It is what makes every later claim checkable.

**B. Fix the shipped security and integrity defects (P0/P1).** SSH key exchange and robustness (`.4.4`), daemon bind policy (`.4.5`), policy facts and fail-open (`.4.6`), webhook rework (FG-046 comment), and constitution checker holes (`.4.15`).

**C. Make the single-node forge usable by a real team (P1).** Remove the event cliff (`.4.7`), make stock push over HTTP work in a long-running server (`.4.8`), bind identity on every write (`.4.13`), close the CI loop with published and required checks (`.4.12`), and run every orphaned campaign in lanes (`.4.18`). Exit test: **team day** (`.4.23`), one scripted day through the real binary over SSH and HTTP with auth, protection, CI, merge races, crash recovery, backup and restore, with an economics record against upstream Git.

**D. Put the pillars on real paths (P2).** Node GC/scrub/repair/RaptorQ (`.4.10`), combiner integration with an equivalence oracle and measured evidence (`.4.9`), safe Markdown (`.4.11`), usable search (`.4.19`), PR workflow gaps (`.4.20`), backup product (`.4.21`), ATP-Git on one path (`.4.22`), and dogfooding this repository (`.4.25`).

**E. Agents on the designed authority model (P1, after C).** Task store, collectors and executor (existing `xcu9`, `sjzo`, `p7sa`), the MCP server (FG-096b), and the **agent day** exit test (`.4.24`). One agent authority model, not two.

**F. Distributed, hosted and release (existing work).** Remote authority backend (`88g7`, which now also needs a provider protocol mapping), routing authority (`b5ph`), release target execution (`0zjt`, FG-091), and hostile isolation (`25cs` after D5). None of this should start before A-C, except owner decisions.

## 8. How the plan was refined

**Ambition pass 1.** The first draft only repaired gates and the security defects. It was extended so that each pillar that exists only as a library gets a concrete path into the product with measured evidence. Where a claimed benefit (combiner throughput, ATP-Git bytes) is not measured on the real path, negative results must be recorded.

**Ambition pass 2.**
- Added two integrating exit tests (team day, agent day). Their pass/fail is the only evidence that may back a "usable forge" or "agent-native" claim.
- Added dogfooding, because hosting this repository would have exposed four of the scale cliffs found here within a day.
- Added an economics record to team day, so performance claims get a real denominator.

**Refinement passes.**
- (1) Duplicates. Defects inside existing open implementation beads (FG-105a, FG-032a, FG-096b) became bug beads with `related` edges, so no existing owner's readiness changed. Findings on batch_pending beads became evidence comments, not new beads.
- (2) Dependencies. Only the exit tests and the closure re-verification carry blocking edges. Everything else can start immediately.
- (3) Evidence. Every bead requires a permitted twin for each refusal, discovered suites that drive the real binary, SHA-bound results, and explicit labelling of `cargo test` wrappers.
- (4) Honesty. No bead reopens or reassigns existing work. Removals (debris, the hosted workflow) require explicit owner approval of the exact command.
- (5) Evidence feedback. After the executed test run, two beads were added: the fast-lane bead with the exact failing list, and the CAS-loser bead for the reproducible race class. A positive comment on `zb0q` was corrected when its sparse-workspace test failed. The priorities of team-day prerequisites were aligned to P1. One suspected search failure (`source_index_reconcile`) was dropped when it passed on rerun; it had been disk-affected.

## 9. Tracker changes made by this assessment

New epic `frankengit-root-doctrine-x2mv.4` with 27 children (`.4.1`-`.4.27`), labelled `reality-check-2026-09-23`:

| Bead | Type | P | Obligation |
|---|---|---|---|
| `frankengit-root-doctrine-x2mv.4.1` | bug | P0 | main does not compile: fgit-runner observations.rs E0423 at 46b922e7 and fgit-forge rename tests (29 errors) never compiled |
| `frankengit-root-doctrine-x2mv.4.2` | bug | P0 | Stop uncompiled commits landing on main and route the unclaimed implementation streams through their beads |
| `frankengit-root-doctrine-x2mv.4.3` | task | P0 | Re-verify the 2026-09-22 closure wave line by line; reopen closures whose acceptance is unmet; forbid SHA-less and self-provided gates |
| `frankengit-root-doctrine-x2mv.4.4` | bug | P0 | fgit-ssh is not confidential: fixed ephemeral X25519 key, fixed cookie, non-constant-time MAC check, pre-auth unbounded buffering, ignored flow control |
| `frankengit-root-doctrine-x2mv.4.5` | bug | P1 | fg serve --receive-principal accepts non-loopback listeners: unauthenticated network push |
| `frankengit-root-doctrine-x2mv.4.6` | bug | P1 | Policy integrity: fabricated principal facts, fail-open receive checks, policy-source injection, unmatched required checks, unbound snapshot identity |
| `frankengit-root-doctrine-x2mv.4.7` | bug | P1 | Forge stops serving PR/issue reads after 4,096 events and refuses all publication at 16,384: bound read cost independent of history |
| `frankengit-root-doctrine-x2mv.4.8` | bug | P1 | Smart HTTP: stock git push fails without Idempotency-Key; node reopened per request; server exits after 1,024 requests; transport capability divergence |
| `frankengit-root-doctrine-x2mv.4.9` | feature | P2 | Wire per-core preparation lanes, flat combiner and witness refinement into real admission with an equivalence oracle and measured evidence |
| `frankengit-root-doctrine-x2mv.4.10` | feature | P1 | Wire GC/retention, scrub/repair, RaptorQ and compaction onto real node data (fg gc / fg scrub / fg repair) |
| `frankengit-root-doctrine-x2mv.4.11` | feature | P1 | Render issue/PR/comment Markdown safely through fgit-doc on HTTP, browser and MCP (v1 scope item 10) |
| `frankengit-root-doctrine-x2mv.4.12` | feature | P1 | CI product loop: event-triggered runs, canonical check publication, required-check gating, honest substrate receipts, artifacts/cache |
| `frankengit-root-doctrine-x2mv.4.13` | feature | P1 | Bind authenticated fgit-identity principals to every write surface; operator-asserted principals become explicit and recorded |
| `frankengit-root-doctrine-x2mv.4.14` | question | P1 | OWNER DECISIONS 2026-09-23: hand-rolled gateway vs ADR-0011, JS web UI vs ADR-0013, publish fastapi_rust/frankentui on asupersync 0.5, psm native assembly, hostile-CI stance |
| `frankengit-root-doctrine-x2mv.4.15` | bug | P1 | Constitution checker and registry drift: #[expect] lint hole, psm/DEP-182 misstatement, 0.4.x text vs 0.5.0 lock, stale rationales, missing license-file, stale negative-evidence ledger |
| `frankengit-root-doctrine-x2mv.4.16` | task | P2 | Inventory and (owner-approved) removal of 174 patch-transport files, .visibility-payload and the hosted write-to-main workflow |
| `frankengit-root-doctrine-x2mv.4.17` | bug | P2 | MCP tool registry and parity manifest disagree with the real fg mcp server; add drift check and stdio live-client e2e |
| `frankengit-root-doctrine-x2mv.4.18` | task | P1 | Run the ~40 orphaned smoke campaigns and browser tests in lanes; label cargo-test-wrapper suites; remove foreign target dirs and RCH bypass from suites |
| `frankengit-root-doctrine-x2mv.4.19` | bug | P1 | Indexed search is unusable on an active repository: forge-only writes stale the index, builds abort on one bad file, no in-server maintenance, no index GC |
| `frankengit-root-doctrine-x2mv.4.20` | feature | P1 | PR workflow gaps: reopen, conversation/line comments, squash/ff merge, approval survival rule, quorum/path ownership, protection admin over HTTP/MCP |
| `frankengit-root-doctrine-x2mv.4.21` | feature | P1 | Backup/restore as fg subcommands: streaming (no 1 GiB/100k caps), signed manifests, capsule restore, destroy-and-restore drill with RTO |
| `frankengit-root-doctrine-x2mv.4.22` | feature | P3 | Put ATP-Git on one real transfer path with differential parity and measured bytes/time vs standard transfer |
| `frankengit-root-doctrine-x2mv.4.23` | test | P1 | EXIT TEST: one real team day through the fg binary over SSH and smart HTTP with auth, protection, CI checks, merge races, crash recovery, backup/restore |
| `frankengit-root-doctrine-x2mv.4.24` | test | P1 | EXIT TEST: one real agent run through IntentRun, ContextPacket, TreeFS, broker, ECC and ordinary admission (fgit-agent off the island) |
| `frankengit-root-doctrine-x2mv.4.25` | feature | P2 | Dogfood: host the FrankenGit repository on a long-lived FrankenGit node with daily parity, search and time-travel checks |
| `frankengit-root-doctrine-x2mv.4.26` | bug | P0 | Canonical fast lane is red at every failable stage: docs, rustfmt (72 files), check (2 uncompilable test targets), clippy, 45 failing tests in 26 binaries, stale-pin campaign failures |
| `frankengit-root-doctrine-x2mv.4.27` | bug | P1 | Concurrent writers: CAS losers get 503 outcome_unknown or wrong refusal counts instead of a deterministic terminal refusal (7 race tests, reproducible on an idle host) |

Evidence comments were added to FG-046, FG-046b, FG-083a, `0zjt`, FG-036b, `25cs`, `88g7`, `l0xt` and `zb0q` (plus a correction on `zb0q` after its sparse-workspace test failed), and to the new beads `.4.1`, `.4.14`, `.4.18` and `.4.21`. The owner-decision bead `.4.14` is set to `blocked` so agents do not claim it. The priorities of the team-day prerequisites `.4.10`, `.4.11`, `.4.19`, `.4.20` and `.4.21` were raised to P1. No existing bead was claimed, reopened, reassigned or closed, and no product source was changed. Another agent's commit `b4b34777` swept most of these tracker records into origin before this assessment's own commit; the content is identical.

## 10. Evidence appendix

| Artifact (scratchpad-relative) | SHA-256 |
|---|---|
| `evidence/check.stderr` | `1aee0413278197c93be9ee7909b6397f13376ce8675ada596a5aae72c602ba9f` |
| `evidence_wt2/docs.stderr` | `86dca73cd7218481aab5a1bdb552db52d0fc81ec82b270bbdb13d75e3cff107d` |
| `evidence_wt2/fmt.stdout` | `84bac4f23a5e28717976adcf03b8552877dfe65e8b162be89e34610cc67a7e42` |
| `evidence_wt2/check.stderr` | `8f15bd4b059224f5d96441adacadd840436d888d2102a54b1afac0a1b1c9f5b9` |
| `evidence_wt2/test.stderr` | `a84f7bab7c579d36be81186e86d483de73889e1b53f9c9a1ed03256265b738a7` |
| `evidence_wt2/clippy.stderr` | `728e537f6611e6e96c95993141f09f09ea88dd11ff1e92f47e1477bc23a05260` |
| `evidence_wt2/constitution_after_build.stderr` | `b6435abac27319409020f9f36bc5519390468403d590bf3eae5deea52e9b50d7` |
| `evidence_wt2/full.stderr` | `85055b83dde3934730c1abf62c2a9c7803b9e877a9692064514037cae9ccd3a7` |
| `evidence_wt2/release.stderr` | `52f8e20b710e7075b692deb84e245ea6e11f7f941618006c8c91b5ff2cc3476e` |
| `evidence_testbins/results.tsv` (first pass; ENOSPC after ~#527) | `c1e4b807194fce01054c190c5aafb66e13a8c65582ccb5dc1a7bcb9e41203cdc` |
| `evidence_e2e/node/receipt.ndjson` | `d49fa8f678e8ba3213a8ae26853e144c29ccbe74e84d0880e74d0648975f8305` |
| `evidence_e2e_release/receipt.ndjson` | `6e4d53c725679e13b41b7d4d9e59aa802b087ab6fc3c8bd235b02aa13c2c24e9` |
| `evidence_e2e/smokes.tsv` | `865231abc6775cf587de3ecc6c424806cf21e0fdf214eeb0f64d7fa3e6a90335` |
| `evidence_tests/test_forge_integration.stdout` | `952eba193a10284f539991d15a06c0f14c69c8310a113d2b0ac2a1c270255982` |
| `fg-94a77dfb` (debug) | `ab220a508863b1989dc09b109b70c06c7c017a2eba64eb653f25881fc63c34d2` |
| `fg-94a77dfb-release` | `37742eca1735e094b8383c48816d3e985134d7141d2f7fc82ab7842517b1aa2d` |
| `beads_all.json` (tracker baseline) | `9e492495e1f706e82b11814c9cb3db5689a00bee075523444ddac2af6787aae0` |
| `evidence_testbins_rerun/results.tsv` | `f0fae09d25d17274f8d2700fd06dc25aeb7e2b2a18fbcaa5d693cf76042a3f85` |
| `evidence_race_idle/results.tsv` | `202cc835d10f9e1142f5699b155519a333b45365ec538919e74fa23de34ead02` |
| `final_fails.tsv` | `8b1f162dd4721619f213a48a3c82ae4ca288ef1dc729a8a7b0807bf45a1610be` |
| `final_summary.txt` | `fcae5e94e535d3a4a9184fa08c7587d843795e13a01148095396ac184a2b6510` |

Raw logs, NDJSON receipts and the isolated worktree remain in the session scratchpad. They are review artifacts, not published durable evidence. The commit, toolchain and profile binding, the limitations, and the summary counts are recorded here so these observations cannot be confused with later runs.
