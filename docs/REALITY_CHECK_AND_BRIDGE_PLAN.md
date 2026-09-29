# FrankenGit reality check and bridge plan — 2026-09-27

FrankenGit is a real, bounded, pure-Rust Git server with an atomic forge core, and in the four days since the 2026-09-23 check its shipped transports became substantially more trustworthy:
- SSH key exchange is confidential.
- A stock `git push` over smart HTTP works without a nonstandard header.
- Concurrent writers get deterministic outcomes.
- The policy engine fails closed.
- Main compiles at HEAD.

It is still not a forge a team can rely on, and the gap has changed shape again, from "unverified breadth" to "**a verification loop with nobody in it**":
- No bead has closed since 2026-09-23.
- The tracker's verification debt stood at 34 of its hard limit of 36 at the pinned SHA. By 2026-09-28 it had reached 36, so the tracker refuses new claims.
- The two P0 re-verification beads are blocked behind a `batch_pending` bead that only an absent verifier can close.
- No repository lane runs a single end-to-end suite.

Meanwhile the toolchain-less stream continues (73 of its 77 commits declare they were not compiled or tested). Every library island the 2026-09-23 check found is still an island.

This supersedes the 2026-09-23 snapshot in place. Deltas against it are marked **Δ**.

**Binding.**
- Source was inspected at `2b7f35ac` (origin/main at the start of the assessment, 2026-09-27).
- Executable evidence was produced at the same SHA, in an isolated detached worktree. The run used the repository toolchain `nightly-2026-08-31` (`rustc 1.100.0-nightly 908501772`) on Linux x86_64, a private target directory, and `RCH_CARGO_WRAPPER_BYPASS=1`.
- The host has 64 cores. Other projects' workloads (video rendering, a Lean build) kept the load average between 190 and 245 throughout. Timing-sensitive results are labelled as such.
- This is not a security audit, universal compatibility result, benchmark claim or batch-verification certificate. Nothing in it closes, reopens or verifies a bead.

**Consumer and retirement.** The repository owner, the batch orchestrator and every assignee use this document to decide what is actually done and what to build next. The observed defect classes are:
- a vacant verification role;
- uncompiled code on main;
- product crates with no production caller;
- capacity ceilings that a real team would hit;
- evidence that runs in no lane;
- stale public claims.

Replace this snapshot in place when a later revision-bound assessment supersedes it. Rows resolved by the epic `frankengit-root-doctrine-x2mv.4` and its children retire from this document. This report grants no capability credit.

## 1. What was examined

All of `AGENTS.md`, `README.md` and the 2026-09-23 version of this document were read. Six independent read-only audits traced six subsystems through source, tests, docs, commits and the tracker at `2b7f35ac`:
- Git transports;
- forge workflows;
- user surfaces (CLI, HTTP, browser, MCP, TUI, safe Markdown);
- the agent plane, TreeFS and CI;
- search, graphs and the README pillars;
- durability, operations, release and process health.

Every critical claim those audits made was re-checked directly against the source before inclusion. Examples:
- the 16,384-entry codec ceiling (`crates/fgit-codec/src/canonical_state.rs:19-22`);
- the raised read cap (`crates/fgit-admission/src/merge/native/pull_request.rs:213-215`);
- the neutralised principal facts (`crates/fgit-admission/src/policy_bridge.rs:296-312`, `lib.rs:1374-1384`);
- the only caller of the outbox delivery settler, which is a test (`crates/fgit-node/tests/native_merge_publication.rs:1068`);
- the workflow check conclusion that can never be green (`crates/fgit-node/src/treefs_workspace/trusted_workflow/durable/publication.rs:316-318`);
- symbol-index staleness on any forge write (`crates/fgit-node/src/treefs_workspace/source_search/symbols/indexed.rs:326-331`);
- `fg serve`'s one-session default (`crates/fgit-cli/src/guarded_git_server.rs:114-118`);
- the uncompiled SSH rekey commit (`67336a56`);
- the JavaScript pack/DEFLATE decoder (`crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs`, 560 lines);
- the hard-coded field in the browser Markdown probe (`scripts/e2e/browser_issue_markdown_probe.mjs:127`);
- the tracker policy's verification-debt limits (`.beads/policy.yaml`).

The tracker was read from the tracked export (`.beads/issues.jsonl`, 598 live records) and from `br ready --unassigned --no-db --json`. Git history since 2026-09-23 was classified by author, bead reference and self-declared execution status.

## 2. Executable evidence at `2b7f35ac`

The pinned run started at 21:44Z on 2026-09-27 and ended at 00:33Z on 2026-09-28. The smoke and suite runs at the same SHA ended at 02:10Z. The product lane at `a51f1ad7`, the first run of `./scripts/verify.sh e2e`, is recorded as its own row.

| Check | Result | What it establishes |
|---|---|---|
| `cargo check --workspace --all-targets --keep-going` | **exit 0** (545 s) | **Δ Main compiles at HEAD**, for the first time since before the 2026-09-23 check. It compiled only because of `78b22405`/`7f42b729`, which repaired `e5e547fa`. |
| `cargo fmt --all -- --check` | exit 1: 62 files, 515 hunks | 58 of the 62 files were last touched by the author working without a toolchain. The other four are small, in files that toolchain sessions edited, including this assessor's `00a7903a` and the `78b22405` fix. On 2026-09-23 it was 72 files. |
| Per-package `cargo test --all-targets --no-fail-fast` (49 packages) | **7,624 passed, 26 failed, 32 ignored**, with 0 compile errors (**Δ**: on 2026-09-23, 2 test targets did not compile and plain `cargo test` ran zero tests) | All 26 failures are in two packages.<br>• fgit-cli (2): the protection test failed because its `fg pr open` ended "ambiguous: cancelled after transmission", which is the flat 15 s CLI deadline (`x2mv.4.50`); it passes alone. A webhook dead-letter replay hit `ResourceBudgetExceeded`. **Correction (2026-09-28):** that one is *not* the deadline class. It fails alone in 3 s at `e98c2d05`, because `49fbc0f3`'s attempt guard refuses every manual replay (attempt = retained attempts + 1 > max_attempts). Filed as `x2mv.4.52`.<br>• fgit-node (24): 22 are budget cancellations under load (`Cancelled`, `Ambiguous(Cancelled)`, `CancellationInProgress`).<br>The sanctioned rerun at `a7264905` (1,608 passed, 61 failed at load ~210) was checked by rerunning every failure by exact name in isolation: 57 of 58 lib failures pass. What remains are two deterministic failures in `9f420dee`'s new PR-check tests, recorded on `x2mv.4.12`. |
| `cargo clippy --workspace --all-targets -D warnings` | exit 101: 44 error lines | Every file involved was last written by the author working without a toolchain:<br>• the admission replay tests (`a500c6da`, `77b9cf4d`), 12 `unused async` and 12 `match over ()` findings;<br>• `fgit-ssh` rekey (`67336a56`), which does not pass Clippy;<br>• the fgit-graph lexical tests and manifest, the fgit-forge opaque-token tests, and admission `objects.rs`.<br>Tracked by `x2mv.4.26`. |
| `verify.sh docs` | **exit 0** at `2b7f35ac` and at `b7de0d5e` plus this document's README edit (**Δ**, exit 1 on 2026-09-23) | The stale claim block and the hosted-workflow findings from 2026-09-23 no longer fail the lane.<br>**It went red again after the pinned SHA.** From `9f420dee`, `pull-request-checks.yml` ran on hosted pushes and held the only copy of its verification commands. From `7847acca`, `constitution` also failed, on three first-party lint relaxations in `ssh.rs`. Both lanes pass again at `05c972ed`: the commands became the `verify.sh` lanes `pull-request-checks` and `continuous-serve` (`05c972ed`), and the relaxations were removed (`54715988`). |
| `verify.sh constitution`, `full`, `release` | constitution **exit 1** at `2b7f35ac` (exit 0 after `5ed070b1`); full exit 3; release exit 3 | The constitution failure was three redundant `#[allow(clippy::too_many_arguments)]` attributes this assessment's author added in `e367df7b` and `784fd886`; fixed in `5ed070b1`. `full` and `release` are explicit dormancy refusals (`verify.sh:94-116`). |
| 37 root-level `scripts/e2e/*_smoke.py` campaigns with debug `fg` at `2b7f35ac`, git 2.55.0 (29 had no invoker in any lane; all are discovered suites since `a25a0645`) | **29 pass, 7 fail, 1 timeout** | **Δ** `issue_smoke` passes; it failed on 2026-09-23. Failures:<br>• stale-pin page instead of refusal: `candidate_approval_publication`, `pull_request_cli` (`x2mv.4.26`);<br>• bare `ERR` instead of report-status `ng` for refused targets: `existing_target_receive`, `quarantine_typed_graph` (`x2mv.4.49`);<br>• CLI 15 s deadline under load: `protection` (`x2mv.4.50`);<br>• `fg doctor` parses a SHA-256 sample as SHA-1: `source_import_graph` (`x2mv.4.48`).<br>`smart_http_node_reuse` was run without its suite arguments and hit the 20-minute cap; see the lane row. |
| FG_BIN suites under `suites/{node,transport,forge}` and `admission/import_recovery` at `2b7f35ac` | **23 of 26 ok** | Failures:<br>• `webhook_delivery`: a stale suite with the old syntax (FG-046);<br>• `tag_lifecycle` TAGS-015: needs a pinned-oracle run directory;<br>• `smart_http_node_reuse`: timeout, explained below.<br>**Δ** All three SSH suites pass at a SHA that includes the uncompiled rekey `67336a56`. |
| **Product lane** `./scripts/verify.sh e2e` at `a51f1ad7` (55 suites, debug `fg`, load ~150-240) | **44 of 55 ok**. Per kind (passed/started): e2e-binary 42/51, real-browser 2/2, js-unit 0/1, undeclared 0/1 | This is the first time any repository lane has run end-to-end suites. The 11 non-ok suites are the smoke and suite failures above, plus:<br>• the browser contract tests (22 fake-DOM failures);<br>• `perf_baseline`, which timed out and is now kind `benchmark` (`5add4010`);<br>• `smart_http_node_reuse`, which timed out, although its campaign completed: 4 database opens per 400 traced connections, 1,000 fetches, fetch p50 1.1 s in debug at load ~200, about 40 minutes against the 30-minute budget.<br>Three suites that rebuilt `fg` instead of using the lane's binary were fixed in `5add4010`.<br>**Rerun at `0693fc8f`:** 54 suites (perf_baseline is now a benchmark), **46 ok**. Per kind: e2e-binary 44/51, real-browser 2/2, js-unit 0/1. `smart_http_node_reuse` passes with the lane default of 200 fetches. The acceptance evidence at 1,000 fetches uses a release build. The 8 non-ok suites are the known failures above. |
| **Real-browser Markdown CSP suite** (`suites/forge/browser_markdown_csp.sh`, Chrome 154, Node 22.2) | fg at `2b7f35ac`: 10/19. fg built from the `5561f2f9` tree: **19/19** | At `2b7f35ac` the issues page cannot make a single API call ("Failed to execute 'fetch' on 'Window': Illegal invocation", §5.8, `x2mv.4.45`).<br>**Since `a9092649`** the suite also opens a PR over HTTP with the same hostile body and checks it on `/ui/pulls/`. It passes 27/27 with fg built from the `75b8c3a8` tree. The planted negative at `2b7f35ac` fails the browser and api_json assertions. |
| **Real-browser client fetch suite** (`suites/browser/client_fetch.sh`) | fg at `2b7f35ac`: 3/9. fg built from the `b7de0d5e` tree: **9/9** | Before `56bba7ee`, no request from the issue, pulls-core or history client reaches the network. After it, all three reach the API with 200. |
| Real-Chrome boot of all 13 served pages (scratch probe, fg from the `5561f2f9` tree) | 12/12 main pages boot with no exception, console error or CSP violation; `/ui/export-verify/` answers `GET` with 405 | The 21 failing node:test browser tests (below) look like fake-DOM fixture drift, not broken pages. |
| `node --test tests/browser/*.test.mjs` at `41eab465` | 1,752 tests: 1,731 pass, **21 fail**. Identical before and after `56bba7ee` | Failures: search view since `b87b8635` (18 tests, "Cannot read properties of null (reading 'addEventListener')"), PR selection, binary authoring, and installed-Git apply. No lane runs this suite. |
| `cargo test -p fgit-policy --all-targets` at `b7de0d5e` | 10 binaries green, including `required_status_checks` 11/11 | `1a3a351a` (committed after the pinned SHA, by the author working without a toolchain) compiles and passes. `evaluate_protected_ref` still has no production caller. |
| **SSH 200 MB push** (`ssh_git_compat.sh`, `FG_E2E_SSH_DELTA_BASE_BYTES=209715200`, release fg) | **fails at `2b7f35ac`**: "receive failed before admission" | **Δ** Root cause: a flat 60 s socket read timeout applied to the whole session. Git sends nothing while it compresses a large pack, and under load that took more than a minute. Fixed in `b8b79a11`, which adds the regression SSH-COMPAT-065/066: stock ssh, 75 s of client silence after the advertisement. `7847acca` later replaced that idle bound with an absolute, work-scaled session deadline. Default-size SSH suites pass 40/40, 13/13 and 27/27 at both `b8b79a11` and `bd45641f`. The planted negative at `2b7f35ac` fails only SSH-COMPAT-065. |
| **Continuous `fg serve` / `fg serve-ssh`** (`x2mv.4.32`, `suites/node/continuous_git_transports.sh`) | landed uncompiled in `7847acca`; **passes 11/11** after the harness fix `f4560746`, release fg at `bd45641f` | **Δ** The first run failed at the first held git:// push, because `GIT_PROXY_COMMAND` held a command line Git cannot exec. After the fix:<br>• SHA-1 and SHA-256, 210 sequential stock sessions per transport, 840 in total;<br>• SIGTERM during a held atomic push: the push completes, the drain settles 217 = 217, and the process exits in 2.5–3.5 s;<br>• a connection attempted during the drain gets ECONNREFUSED.<br>Focused Rust tests: 22/22 (lib), 10/10 (`guarded_git_daemon`), 28/28 (fg serve commands). Bounded git:// suites are not regressed: first_push 23/23, incremental_fetch 97/97, capability_parity 5/5, sha256_repo_roundtrip 25/25. |

Ordinary-client cells use the installed Git 2.55.0, OpenSSH and Chrome. They are compatibility observations, not the constitution's pinned-oracle class; the pinned oracle is not installed on this host.

## 3. The short answer

**Where are we really?** At the same phase as on 2026-09-23: the end of plan Phase 2 (pure-Rust Git core), with a real slice of Phase 5 (forge core) and trusted-local fragments of Phases 4 and 6. What moved is that the slice is safer to expose. SSH is now a real transport. Smart HTTP now serves stock clients and runs continuously. Concurrent writers get deterministic outcomes, the policy path fails closed, and safe Markdown reaches HTTP, MCP and the browser. The README vision of "a forge designed for humans, autonomous coding agents, extreme scale, and independently verifiable recovery" is still delivered in none of its four qualifiers:
- **Humans:** only one trusted operator. Identity is self-asserted, required checks cannot pass, and there are no PR comments.
- **Agents:** the agent plane is a 37K-line island.
- **Extreme scale:** there is one writer at a time, forge publication stops at 16,384 events, and search cannot index this repository.
- **Recovery:** there is no GC, scrub, repair or signed capsule.

**What works (with evidence).**
- Everything in the 2026-09-23 list still works:
  - the canonical core (transaction identity, seals, RCR, exact-predecessor head CAS, `fg outcome`);
  - raw git-daemon clone/fetch/push;
  - import and export;
  - SHA-256 repositories;
  - `fg at`;
  - the atomic durable PR merge;
  - issues, branches and tags;
  - trusted-local workspaces;
  - stdio MCP;
  - literal, regex, lexical and Rust-symbol search on quiet repositories.
- **Δ SSH (`fg serve-ssh`):**
  - per-session OS entropy for the key exchange;
  - a constant-time tag check;
  - strict KEX;
  - bounded pre-authentication ingress;
  - honoured flow control;
  - protocol v2 negotiation;
  - push through the same guarded receive coordinator as git://.

  Its suites passed 38/38, 13/13 and 23/23 at `784fd886`/`eba31282`, as reported by the implementer. The later rekey commit `67336a56` was never compiled by its author; see §2 for this run.
- **Δ Smart HTTP (`fg serve-http`):**
  - Stock `git push` works through a discovery-scoped `307` to an attempt URL (`03d42b79`, `16bb3cfc`).
  - Opened nodes are pooled instead of reopened per request, and are revalidated on lease (`63f2d30a`, `eba31282`).
  - `--continuous` mode drains on a stop file, SIGTERM or SIGINT (`f56cbe47`, `444fbe6b`, `0da01149`).
  - Upload capabilities over HTTP are identical to git://, and receive capabilities over HTTP are identical to git:// and SSH (`09a03439`).
  - Release A/B, 1,000 fetches: database opens went from 802 to 4 per 400 connections, and fetch p99 went from 0.32–1.9 s to 0.07–0.09 s.
- **Δ Deterministic concurrent writers.** CAS losers now get a typed refusal, never `503 outcome_unknown` (the x2mv.4.27 chain `d6764e73` … `e367df7b`). This is achieved by admitting one writer at a time per process (see §5.5).
- **Δ Policy fails closed.**
  - Branch names reach the policy engine as AST operands, not source text (`408df528`).
  - Compile and evaluation errors refuse the receive (`59784c88`).
  - Policies that read unavailable principal or evidence facts are refused rather than evaluated against fabricated ones (`dec9c122`).
- **Δ PR reopen** through CLI, HTTP and the browser, with e2e `pull_request_reopen` passing at `b8332d2a`.
- **Δ Safe Markdown.** fgit-doc renders issue, comment and PR bodies over HTTP (`render=html_safe`) and MCP (four profiles), and the browser displays them through an allowlist builder. fgit-doc is the first formerly-unlinked crate to link into `fg`.
- **Δ Webhook payloads are real.** They are a signed HMAC envelope of authority-selected canonical event frames (`3026f76f`), and the placeholder path now refuses.
- **Δ Restore works** for the authority backup (`b8e5f8ad`) and the repository backup (`19c680bc`), and `fg backup export|verify|restore` exists (`3b45aca8`).
- **Δ Search is partly fixed:**
  - an opt-in revalidated lexical mode survives metadata-only writes;
  - a long word or macro token no longer aborts an index build.
- **Δ Bead citation on commits** rose from 35% to 87%.

**What does not work or is not implemented.**
- **Verification:**
  - no independent verifier has acted since 2026-09-23;
  - no end-to-end suite runs in any repository lane;
  - about 38 root-level smoke campaigns and about 900 browser tests run nowhere.
- **Identity:**
  - every CLI and MCP write names a self-asserted `--principal`;
  - there are no users, organizations, teams or token administration;
  - there are no agent principals.
- **CI.** It runs trusted code on the host only. Nothing triggers it, and a published check maps success to `ActionRequired`, so a required check can never pass. The fgit-policy rule engine that would evaluate required checks has no production caller.
- **Forge capacity.**
  - Forge publication refuses at 16,384 outbox or forge-position entries.
  - Settled outbox entries are never removed.
  - Every PR or issue read still scans the whole outbox.
- **Throughput.** One writer per process.
- **Missing PR workflow:**
  - PR conversation comments and line comments;
  - PR labels;
  - squash and rebase merges;
  - approval survival;
  - quorum or CODEOWNERS;
  - protection administration over HTTP or MCP.

  The fast-forward merge (`d80190e5` … `e5e547fa`) exists but has never been run by its author.
- **Webhooks and events:**
  - no webhook delivery worker; delivery is manual only;
  - no HTTPS webhook client;
  - no native event feed over HTTP or MCP.
- **Search:**
  - symbol reads and the default HTTP mode still go stale on any forge write;
  - one file over 8 MiB, or one malformed `.rs` file, aborts a whole build;
  - its caps cannot index this repository;
  - there is no index maintenance inside the server and no index GC.
- **Storage and deployment:**
  - no GC, scrub, repair, RaptorQ or compaction on node data;
  - no signed capsule;
  - no TLS on any transport;
  - no non-loopback HTTP;
  - **Δ** `fg serve` and `fg serve-ssh` now have `--continuous --stop-file` with SIGTERM/SIGINT drain. It landed uncompiled in `7847acca` and was executed and repaired on 2026-09-28 (§2, `x2mv.4.32`).
- **Absent entirely:**
  - no TUI, LFS, GitHub import, merge queue in admission, or release.
- **Unchanged islands:** the agent plane, ATP-Git, the combiner and per-core lanes, graph views, statistics, projections, verified reads on a transport, evidence exchange, and the object-store backend.

**What is blocking us.** In order of leverage:
1. **The verification loop is vacant (§5.1).**
   - AGENTS.md §16.2 makes the batch orchestrator the only closer. No orchestrator has acted since 2026-09-23.
   - The two P0 beads that were supposed to restore trust (`x2mv.4.3` closure re-verification, `x2mv.4.26` fast lane) are blocked by `x2mv.4.1`, which sits in `batch_pending`.
   - Verification debt reached the hard limit of 36 on 2026-09-28.
   - `verify.sh` runs no end-to-end suite, and `full` is dormant.
   - Until someone verifies at a SHA and the product suites run in a lane, the tracker cannot move and no claim can be checked.
2. **Uncompiled landings continue under an asserted mandate (§5.2).** 73 of the toolchain-less producer's 77 commits declare they were not compiled or tested. Five of them broke the build or tests and had to be repaired by other sessions. 32 of them state that the owner explicitly requested direct-main publication, which contradicts the P0 bead `x2mv.4.2`. Only the owner can reconcile the two (decision D7).
3. **Composition debt is unchanged (§5.4).** About 61.7K lines in 10 product crates are still linked into no binary. The cheapest path to each README pillar remains connecting an existing crate to a real consumer that needs it.
4. **Capacity ceilings a real team would hit (§5.5):**
   - the 16,384-event publication ceiling;
   - writer serialization;
   - search caps below this repository's own size;
   - unbounded storage growth.
5. **Owner decisions D1–D6 are unanswered** (`x2mv.4.14`), and the paused surfaces kept growing regardless (§5.7).

**If every open and in-progress bead were implemented, would the gap close?** No:
- Nothing can close until the verification role is staffed. The P0 track is blocked by construction.
- Some vision goals have no bead at all (see below and §6).
- Some open beads describe work that has since happened under another bead, or a product that no longer exists:
  - FG-105/105a/105b and FG-019 have been untouched since August, while the smart-HTTP and receive work was credited to `x2mv.4.8` and `x2mv.4.4`;
  - FG-051a and FG-050 still conflict with the shipped in-process CLI and the JavaScript browser.
- The integrating exit tests (`x2mv.4.23` team day, `x2mv.4.24` agent day) are the only beads whose success implies the vision qualifiers. Their prerequisites include beads nobody has claimed.

**Vision goals with no bead before this assessment** (now covered by the beads in §9):
- a verifier at a named SHA and product suites in a lane;
- TLS and a non-loopback HTTP deployment profile;
- continuous lifetime and drain for `fg serve` and `fg serve-ssh`;
- restoring write concurrency safely, with negative evidence for the single-writer gate;
- typed graph views built from canonical data;
- a production consumer for `fgit-statistics`;
- CALM routing and Asupersync regions or typed obligations in runner, TreeFS and agent code;
- agents as first-class principals;
- TreeFS shared materialization and its measurement;
- PR labels;
- an HTTPS webhook client;
- a native event feed;
- CSRF and Origin protection on the browser-facing API;
- a verified-read transport route;
- binary-driven transport coverage for partial clone, notes and submodules;
- a contract for fsqlite companion files;
- replacing or ruling on the JavaScript pack decoder;
- a root-cause fix for the sparse-workspace lease;
- the owner rulings on direct-main publication (D7) and on the verifier role (D8).

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

| # | Goal | 2026-09-23 | Now | Evidence | Work |
|---|---|---|---|---|---|
| 1 | Repository creation/import/export | WORKING (bounded) | WORKING (bounded) | `fg init/import/export/bundle`; import budget wiring `531354b0`/`670ef4e9`/`8ba0cccd`; import capped at 128 MiB | `x2mv.4.28`, FG-106, `e6jj` |
| 2 | SSH and smart HTTP access | BROKEN / PARTIAL | **PARTIAL** (Δ) | SSH confidential with KEX and robustness fixes. HTTP stock push, pooling, continuous mode and drain all work. Still loopback-only HTTP with no TLS, no keep-alive and ed25519-only SSH keys, and the rekey is uncompiled at landing. | `x2mv.4.4`, `x2mv.4.8` (in progress); `.4.30`, `.4.31`, `.4.32` (new) |
| 3 | Protocol-accurate clone/fetch/push | WORKING (daemon tier) | WORKING on all three transports for the declared tier (Δ) | v0/v1/v2 upload on git://, SSH and HTTP; receive v0/v1; `atomic` advertised on all three; push options, signed push, report-status-v2 and push sideband not advertised; partial clone and notes untested through `fg` | FG-019, FG-098, `.4.33` (new) |
| 4 | Branch/tag listing and atomic ref updates | WORKING | WORKING | `fg branch/tag/refs`; HTTP routes; `tag_lifecycle` 14/15 (TAGS-015 needs the pinned oracle) | — |
| 5 | Users, orgs, teams, tokens, deploy keys | PARTIAL | PARTIAL | Only SSH deploy keys and HTTP token/credential files; CLI/MCP principals self-asserted; no admin surface | `x2mv.4.13`; `.4.34` (new) |
| 6 | Protected refs and policy snapshots | BROKEN | **PARTIAL, fail-closed** (Δ) | Injection and fail-open fixed. Fabricated facts replaced by refusal. Rule engine (`evaluate_protected_ref`) has no production caller, any `ci_check` satisfies every required check, snapshot identity not in the RCR, stored snapshots never activated. After the pinned SHA, `1a3a351a` bound each required check to its name, ref and exact commit inside fgit-policy (verified 11/11 at `b7de0d5e`), but the engine still has no production caller. | `x2mv.4.6` |
| 7 | PRs, reviews, comments, labels, merge | PARTIAL | PARTIAL (Δ reopen) | Reopen works; fast-forward unverified; no PR comments, labels, squash/rebase or approval survival; read cap 65,536 but publication stops at 16,384 | `x2mv.4.20`, `x2mv.4.7` |
| 8 | Issues and discussions | PARTIAL | PARTIAL | Issues with comments, labels and rendered Markdown; no discussions, assignees, milestones or notifications | FG-045 |
| 9 | Webhooks and event API | STUB / PARTIAL | **PARTIAL** (Δ) | Real signed payload and operator CLI; no worker; plaintext HTTP only; no HTTP/MCP event feed | FG-046, FG-046b; `.4.35` (new) |
| 10 | Safe Markdown rendering | LIBRARY-ONLY | **PARTIAL** (Δ) | HTTP, MCP and browser render. Review text renders nowhere, and HTTP has no source spans. The real-browser CSP suite passes 19/19 on the issues page with fg built from the `5561f2f9` tree, after its evidence defects and x2mv.4.45 were fixed (§5.8). | `x2mv.4.11` (in progress) |
| 11 | Basic lexical and symbol search | PARTIAL | PARTIAL | Revalidated lexical mode is opt-in. Symbols and the default HTTP mode go stale. Build aborts on any file over 8 MiB or any malformed `.rs`. Caps below this repository's size. No search e2e suite. | `x2mv.4.19`, FG-032a |
| 12 | CI with artifacts and cache | PARTIAL (trusted only) | PARTIAL (trusted only) | Check publication exists as a library path only, maps success to `ActionRequired`, and has no CLI or HTTP route; no triggers, artifacts, cache or isolation | `x2mv.4.12`, `25cs`, D5 |
| 13 | Agent identities, Intent Runs, workspaces, evidence | PARTIAL / LIBRARY-ONLY | PARTIAL / LIBRARY-ONLY | Workspaces trusted-local; `fgit-agent` 37,176 lines, zero dependents; no agent principal type | `x2mv.4.24`, `xcu9`, `sjzo`, `p7sa`; `.4.34` (new) |
| 14 | Backup, capsule export, scrub, verify, restore | PARTIAL / BROKEN | **PARTIAL** (Δ restore fixed) | `fg backup` exists; restore works; 1 GiB and 100K-object caps; unsigned; no capsule, scrub or repair | `x2mv.4.21`, `x2mv.4.10` |
| 15 | Single-node and object-store deployment | PARTIAL / STUB | PARTIAL / STUB | Single node improved (continuous HTTP, drain, pooling); object store refuses TLS (`TlsTransportNotAdmitted`) | `88g7`; `.4.30`, `.4.32` (new) |
| 16 | GitHub import and compatibility matrix | NOT_STARTED / stale | NOT_STARTED / stale | Matrix last edited 2026-09-04 and does not reflect SSH, HTTP push or capability parity | FG-049, FG-090 |

**README core innovations**

| Innovation | Status | Evidence |
|---|---|---|
| Decisions + RCR, one head CAS for ref and forge | WORKING (merge, reopen, receive paths) | asa3 chain, reopen/crash tests, deterministic losers (Δ) |
| Stable retry identity, immutable outcomes | WORKING | `fg outcome`; retries of unknown originals resolve to terminal (`80506e03`) |
| Per-core preparation, flat combiner, witness refinement | LIBRARY-ONLY | `fgit-txn` combiner/lanes used only by fgit-txn tests; fgit-witness has no dependents. `fgit-node/src/node_lanes.rs` is a connection pool, not this. |
| ATP-Git | LIBRARY-ONLY | No dependents |
| TreeFS | PARTIAL | Trusted sparse host adapter; files copied, not shared; no FUSE; lease `WouldBlock` intermittent |
| Typed graph fabrics | LIBRARY-ONLY (generation substrate live for search only) | GRAPH-001..009 all "specified" in `registries/graph_views.tsv` |
| CALM and obligation-typed effects | PARTIAL | fgit-calm is called only by unwired federation code; runner obligations are `usize` counters; no Asupersync regions in runner, agent or TreeFS |
| Repair through authority | LIBRARY-ONLY | fgit-repair, fgit-raptorq and fgit-compaction have no production dependent |
| Conformal/e-process policy | LIBRARY-ONLY | fgit-statistics is consumed only by unlinked crates |
| Local root-last releases | STUB | `verify.sh release` runs the licence gate and a probe, then exits 3 |

**Beyond parity:**
- Verified reads: LIBRARY-ONLY. The node functions are linked but called only by tests. The browser "verified downloads" check object hashes, not FG-037 inclusion proofs.
- Time travel: WORKING (`fg at`, `time_travel` suite).
- Evidence economy: LIBRARY-ONLY (fgit-exchange unlinked).
- Deterministic build outputs: STUB (in-memory `OutputStore`).
- Formal core: contained Lean model only.

**Constitution:**
- `#![forbid(unsafe_code)]`: pass.
- No Tokio, hyper, OpenSSL, ring or libgit2, and no production `git` subprocess: pass.
- One Asupersync constellation at 0.5.0: pass, though the constitution text still says 0.4.x (`x2mv.4.15`).
- psm native assembly: unresolved (D4).
- **Δ Rust-only Git semantics: tension.** The browser now ships a 560-line JavaScript pack/DEFLATE/delta decoder, and Git object hashing appears in 17 JavaScript modules. AGENTS.md §3.1 and §6 say FrankenGit owns pack, delta and DEFLATE semantics in Rust. No decision admits a second implementation outside Rust (§5.7). After the pinned SHA, `ed88d0dd` and `41eab465` moved the decoder into `transfers-protocol.mjs` (786 lines). The browser now serves it as its pre-import and pre-download verifier, so it is on a product path (`x2mv.4.44`).

## 5. Findings that should change priorities

### 5.1 The verification loop is vacant

- **No bead has closed since 2026-09-23.** 175 non-merge commits landed in those four days.
- **No independent verifier has commented on any `x2mv.4` child.** Every implementer comment on a child comes from one agent (IcyIbis) and is self-verified.
- **Verification debt** (in_progress plus batch_pending) is 34, against `.beads/policy.yaml`'s soft limit of 28 and hard limit of 36. Two more claims and the tracker refuses new work. The 30 `batch_pending` beads span 16 assignees; the oldest has waited since 2026-08-26.
- **The P0 track that was meant to restore trust cannot start.** `x2mv.4.3` (re-verify the 2026-09-22 closure wave) and `x2mv.4.26` (fast lane) both have a blocking edge on `x2mv.4.1`, which is `batch_pending` and can only be closed by the batch verifier.
- **No repository lane runs any end-to-end suite.**
  - `scripts/verify.sh` never calls `scripts/e2e/run_all.sh`, and `full` is an explicit dormancy refusal (`verify.sh:94`).
  - 38 root-level smoke campaigns have no invoker in any suite or lane.
  - About 900 browser tests run on a fake DOM, in no lane.
  - Every transport and forge "pass" since 2026-09-23 is an implementer-reported run at a past SHA.
- **Several suites under `scripts/e2e/suites/` only wrap `cargo test`** and never touch `fg`:
  - agent: `agent_delegation`, `agent_adversarial`;
  - workflow: `workflow_execution`;
  - transport: `atp_*`;
  - graph, statistics, txn, witness;
  - `verified_reads_tamper`.

  They read as product evidence on bead records.

This is the highest-leverage defect in the project. The fix is not more process. Someone has to be the verifier (owner decision D8), the product suites have to run in a lane, and the backlog has to be processed at a named SHA. See `x2mv.4.29`, `x2mv.4.18`, `x2mv.4.46` and `x2mv.4.47`.

### 5.2 Uncompiled code keeps landing, now under an asserted owner mandate

The "Jeff Emanuel" author has landed 77 commits since 2026-09-23. 73 of them state that compilation or tests were not run, and 60 of those change Rust. Build or test breaks it landed after the 2026-09-23 document, each repaired by another session:

| Break | What broke | Repaired by |
|---|---|---|
| `a103783a` | main did not build | `fbcbe656` |
| `aaf7b421` | fgit-node lib test, E0425 | `1b51c5ad` |
| `c7679132`, `bc2c2a0d` | three search tests | `651238cf`, `8d40f88d`, `00a7903a` |
| `531354b0` | its own parser test failed from the start | `670ef4e9` |
| `e5e547fa` | a `const fn` comparing `&str` with `==`, plus a changed call signature | `78b22405`, `7f42b729` |

Main compiled at `2b7f35ac` only because of the last repair.

Thirty-two of these commits state that the owner explicitly requested direct-main publication. `x2mv.4.2` (P0) says uncompiled landings must stop. Both cannot be the rule. This assessment does not rule on it. It adds decision **D7** to `x2mv.4.14`, framed as the owner choosing among:
- a compile sentinel that checks each landed commit within minutes and files or repairs breaks under the originating bead;
- a staging branch that an integrator fast-forwards after `cargo check` and the focused tests;
- accepting the breakage rate explicitly, recorded as negative evidence.

Two of the stream's commits cite the wrong bead: `3b45aca8` and `83ec52a9` are backup work credited to `x2mv.4.11` (Markdown).

### 5.3 What the bridge delivered, and how far that can be trusted

Four P0/P1 defects from 2026-09-23 have code fixes with SHA-bound, implementer-run evidence:
- SSH confidentiality (`x2mv.4.4`);
- the daemon bind policy (`x2mv.4.5`);
- deterministic concurrent writers (`x2mv.4.27`);
- stock HTTP push and serving lifetime (`x2mv.4.8`).

Two more are fixed in part:
- policy fail-open and injection (`x2mv.4.6`);
- the event read cap (`x2mv.4.7`).

The executable run in §2 re-runs the relevant tests and suites at `2b7f35ac`. Until an independent verifier reproduces them, the honest label is "implemented and self-verified", not "done".

One of those fixes had a regression, disclosed on its bead. `36f62452` made the git:// peer probe treat a half-closed socket as gone; `8b3ffddc` fixed it. It was caught only because filtered tests were re-run. That shows how easily a "passes" note can be wrong.

### 5.4 About 61.7K lines of product crates still run in no program

By `cargo metadata`, 33 of the 48 crates under `crates/` link into `fg`. That is up by one: fgit-doc, via `adb58daa`. Five of the remaining 15 are tooling (lab, benchmark, proof-bridge, slo, release). The other ten are product crates with neither a production dependent nor a binary:

| Crate | Source lines |
|---|---|
| fgit-agent | 37,176 |
| fgit-atp-git | 4,472 |
| fgit-statistics | 3,863 |
| fgit-projection | 3,106 |
| fgit-raptorq | 2,878 |
| fgit-repair | 2,664 |
| fgit-witness | 2,495 |
| fgit-exchange | 2,011 |
| fgit-object-store | 1,802 |
| fgit-compaction | 1,269 |

None of their integration beads (`x2mv.4.9`, `.10`, `.22`, `.24`, `88g7`) has been claimed.

Three linked modules are also effectively dead:
- The combiner and lanes in fgit-txn have no caller outside that crate.
- fgit-graph's algorithms, architecture and temporal modules have no caller outside that crate.
- The node's verified-read functions are called only by tests.

The projection substrate may become permanently orphaned. The issue event cliff was addressed by paged replay (`a500c6da`) instead, which `x2mv.4.7` allowed, and nobody has decided whether fgit-projection still has a consumer.

### 5.5 Capacity ceilings a real team would hit

- **Forge publication stops at 16,384 entries.** `MAX_FORGE_POSITION_STATE_ENTRIES` and `MAX_OUTBOX_STATE_ENTRIES` are both 16,384 (`crates/fgit-codec/src/canonical_state.rs:19-22`), and settled outbox entries are never removed. After 16,384 forge events every PR, issue and review publication is refused, permanently. The read cap was raised to 65,536 events, 128 MiB scanned and 32 MiB retained (`a500c6da`, `77b9cf4d`), so the publication ceiling now binds first. Each read still scans the whole outbox. The 128 MiB scan limit also binds early for large bodies, at about 2,000 bodies of 64 KiB (an inference).
- **One writer per process.**
  - `MAX_CONCURRENT_WRITERS = 1` (`e367df7b`) made CAS losers deterministic by serializing writers after ingress.
  - Its commit reports the slowest of eight concurrent writers at 57–85 s under host load around 90.
  - It is the right correctness fix and the wrong end state. No negative-evidence row or performance bead records it.
  - The README pillar that should replace it is per-core preparation with a flat combiner (`x2mv.4.9`, still an island).
- **Search cannot index this repository.** The limits are 20,000 files, 64 MiB of source and 20,000 declarations. This repository has about 33K Rust declarations and a 10 MiB tracker export.
- **Storage grows without bound.** There is no GC, and settled outbox entries are never removed.

### 5.6 Protected branches with required checks cannot be merged

Every piece of the required-check path exists, but nothing connects them:
- The policy engine's required-check evaluation (`evaluate_protected_ref`, `crates/fgit-policy/src/protected_ref.rs:562-585`) has no caller outside fgit-policy, and it would accept any `ci_check` receipt for any check name.
- The only production check publisher (`admit_trusted_workflow_check_in`) has no CLI or HTTP caller, and maps success to `ActionRequired`.
- Nothing triggers a workflow from a push or PR.

The practical result: protection works for mandatory review, which is an inline check, and for nothing else. See `x2mv.4.6` and `x2mv.4.12`.

### 5.7 The paused surfaces kept growing

`x2mv.4.14` says work affected by D1 (the hand-written gateway versus ADR-0011) and D2 (the JavaScript browser versus ADR-0013) stays paused until the owner rules. Neither ADR has changed since 2026-08-21, and no ruling is recorded. Since 2026-09-23:
- **The browser grew by 1,843 lines of JavaScript**, to 9,676 lines in 44 modules. 17 of its 19 commits came from the toolchain-less producer.
- **It gained a 560-line pack, DEFLATE and delta decoder** (`bundle-verify.mjs`), used by `scripts/verify_git_bundle.mjs` as a recovery verifier.
- **The HTTP API grew to about 71 routes.** They are form-encoded, with no body schema, no CSRF or Origin check, and Basic challenges that let browsers cache credentials.
- **The MCP tool registry and the parity manifest now agree on only 16 of 28 names**, and no lane checks them (`x2mv.4.17`).

This is not a judgement on whether the shipped surfaces are good. It records that a declared pause is not being enforced, and that the Rust-only Git semantics rule now has a JavaScript exception nobody approved.

### 5.8 Evidence defects

- **At `2b7f35ac`, `scripts/e2e/browser_issue_markdown_probe.mjs:127` reported `csp_meta_or_header_present: true` as a literal**, a hard-coded success field of class RH-12. Its driver asserted nothing. The suite it named (`suites/forge/browser_markdown_csp.sh`) did not exist, and the probe waited for a status text the page never shows.
  - The probe belongs to `x2mv.4.11`, in progress under this assessment's author, and was swept into `d7dc118d`/`0a76cdd1` before it had ever run.
  - Fixed in `5561f2f9`: the probe records the CSP header Chrome actually received, and a 19-assertion suite asserts every fact, with permitted twins.
  - Its first honest run is what exposed `x2mv.4.45`: 1,731 of 1,752 fake-DOM tests passed while no API-calling browser page worked.
- **`scripts/e2e/smart_http_smoke.py:75` still injects `Idempotency-Key`.** Only `stock_http_push_faults` proves the header-free stock push.
- **`suites/forge/webhook_delivery.sh`** uses the old `deliver` syntax and ends commands in `|| true`.
- **The authority and repository backup suites have never been executed.** The new `source_backup_preflight.sh` has never run.

### 5.9 Documentation is stale in both directions

- **The README understates the transports.** Lines 84–88, 147, 157 and 165 still say:
  - a stock HTTP push needs `Idempotency-Key`;
  - SSH uses a constant key;
  - webhooks send a placeholder (line 170);
  - safe Markdown is library-only (line 182).
- **The README states targets as current.**
  - "Agent-native collaboration" (lines 526–546) describes an Intent Run model that no binary runs.
  - §3, §5 and §7 describe per-core publication, a million workspaces and CALM routing in the present tense, without a status marker.
- **`docs/GIT_COMPATIBILITY_MATRIX.md` was last edited 2026-09-04.**
- **`docs/MCP_*.md` omit five tools and the `render` option.**

This assessment refreshes the README's dated snapshot and boundary paragraph. The rest belongs to `x2mv.4.15` and FG-090.

### 5.10 Tracker health

| | Records | Closed | Open | batch_pending | Blocked | Deferred | In progress |
|---|---|---|---|---|---|---|---|
| 2026-09-23 | 569 | 475 | 55 | 28 | 6 | 5 | 0 |
| 2026-09-27 | 598 | 475 | 77 | 30 | 7 | 5 | 4 |

- All 29 new records are the `x2mv.4` epic and its children.
- Commits landed against open, unassigned beads without claiming them:
  - `x2mv.4.19` (19 commits) and `x2mv.4.26` (19);
  - `x2mv.4.20` (13) and `x2mv.4.28` (5);
  - `x2mv.4.6` (4), `x2mv.4.21` (3) and `x2mv.4.7` (2).
- The P0 process beads `x2mv.4.2` and `x2mv.4.3` have no owner and no comments.
- `br` refused every write from 2026-09-24 23:23 to 2026-09-27 21:11. The cause was a stale `beads.db-shm` that survived a disk-full crash; it was moved aside with the owner's approval. Bead comments for that period were entered late.

### 5.11 Incident during this assessment

A read-only audit subagent dispatched by this assessment overwrote the scratchpad copy of the 2026-09-23 tracker baseline (`beads_all.json`, SHA-256 `9e492495…`) with a fresh export, despite an instruction not to modify files. The baseline's counts survive in this document and in `.beads/issues.jsonl` history at `6c762f42`, but the original bytes are gone. The 2026-09-23 appendix row is marked accordingly. The instruction was the assessor's, and so is the responsibility.

**The host disk filled (2026-09-28, about 05:05Z).** The root filesystem, which holds `/data`, reached 100% with 2.7 MB free. It cut off the sanctioned `cargo test -p fgit-node` run at `b8b79a11` mid-log, so that run is not evidence. The assessor stopped its own 200 MB SSH run, which could not produce valid evidence. The assessor's private cargo caches (about 97 GB) were removed by the repository owner after an explicit approval, because the safety hook refused the command. Any e2e or cargo result from that window should be treated as suspect.

**Duplicated work on `x2mv.4.32`.** The assessor claimed `.32` and began its own implementation. Meanwhile the author working without a toolchain landed a complete one (`7847acca`, "Related: x2mv.4.32") without claiming the bead. The assessor's parallel version was never committed; it is kept as a patch in its scratchpad. The assessor switched to executing and repairing `7847acca` instead. The cause is §5.2: an unclaimed implementation stream bypasses the claim that is meant to prevent exactly this.

## 6. Tracker coverage

`br ready --unassigned --no-db --json` returned 20 records. 16 of them are `x2mv.4` children; the others are FG-032a, FG-045, FG-093c and `xcu9`. Neither P0 track bead is ready (`x2mv.4.3` and `x2mv.4.26` are blocked by `x2mv.4.1`).

Vision goals with no owning bead before this assessment, now covered in §9:
- **Verification:**
  - a verifier at a named SHA working through the backlog;
  - product end-to-end suites in a repository lane.
- **Transports and deployment:**
  - a non-loopback HTTP profile with TLS;
  - continuous lifetime and drain for `fg serve` and `fg serve-ssh`;
  - binary-driven transport coverage for partial clone, notes, submodules and atomic push over SSH and git://.
- **Capacity:** safe write concurrency beyond one writer, with negative evidence for the gate.
- **Identity:** agents as first-class principals.
- **Forge:**
  - PR labels;
  - an HTTPS webhook client and a native event feed;
  - CSRF and Origin protection.
- **README pillars:**
  - graph views from canonical data;
  - a production consumer for statistics;
  - CALM routing and Asupersync regions in runner, TreeFS and agent;
  - TreeFS sharing;
  - verified reads on a transport.
- **Correctness and contracts:**
  - the fsqlite companion-file contract;
  - the sparse-workspace lease;
  - the JavaScript pack decoder.
- **Owner rulings:** D7 and D8.

## 7. Bridge plan

Order is by leverage, not ease. Existing owners keep their beads. Every track's exit is an executed result bound to a SHA, never a closure count.

**A. Put someone in the verification loop and make the product suites run (P0).**
1. The owner names the batch verifier (D8). The verifier runs `x2mv.4.29`, union verification at one SHA over every `batch_pending` bead and `x2mv.4.1`. That unblocks `x2mv.4.3` and `x2mv.4.26`.
2. `x2mv.4.18` (raised to P0) wires `scripts/e2e/run_all.sh` into a repository lane. It turns the 38 root smokes into discovered suites and labels the cargo-test wrappers. The real-browser suites land in the same lane: `browser_markdown_csp.sh`, `client_fetch.sh`, and the every-page smoke `x2mv.4.46`.
3. The owner rules on D7. Then `x2mv.4.2` implements the ruling. Option (a), a compile sentinel, becomes product work once `x2mv.4.25` runs it as FrankenGit's own required check.
4. `x2mv.4.26` returns the fast lane to green, using the failing list in §2.
5. `x2mv.4.3` re-verifies the 2026-09-22 closure wave line by line.
6. `x2mv.4.47` adds a deterministic simulation lane for the concurrency class that load testing keeps finding.

Exit: at one named SHA, `verify.sh fast` and the e2e lane exit 0, verification debt is below 28, and every 2026-09-22 closure is re-closed with mapped evidence or reopened. This earns no feature credit. It is what makes every later claim checkable.

**B. Security and integrity on the shipped listeners (P1).**
- Browser pages that cannot call their API (`x2mv.4.45`; fix landed in `56bba7ee`, awaiting the verifier).
- Cross-site request forgery on the browser-facing API (`x2mv.4.31`).
- The uncompiled SSH rekey (`x2mv.4.4`: re-run the SSH suites at HEAD before handoff).
- The unwired policy rule engine: snapshot identity and activation (`x2mv.4.6`). `1a3a351a` fixed the any-check-satisfies-all defect inside fgit-policy (verified at `b7de0d5e`: 11/11), but nothing calls the engine yet.
- Constitution and registry drift (`x2mv.4.15`), including the JavaScript Git decoder, now on a served path (`x2mv.4.44`, D2).

**C. A forge a real team can run (P1).** The exit test is team day (`x2mv.4.23`).
- **Capacity:**
  - the 16,384-event ceiling and history-proportional reads (`x2mv.4.7`), with a settled-prefix Merkle Mountain Range checkpoint as the proposed mechanism and fgit-projection as the per-aggregate index;
  - writer concurrency (`x2mv.4.9`, which first measures where the single-writer service time goes, then `x2mv.4.39` for commuting monotone intents);
  - GC, scrub and repair (`x2mv.4.10`);
  - search at this repository's scale (`x2mv.4.19`).
- **The product loop:**
  - CI checks that can pass, with triggers (`x2mv.4.12`), running under Asupersync regions and typed obligations (`x2mv.4.38`);
  - identity on every write surface (`x2mv.4.13`);
  - PR conversation comments, labels and merge strategies (`x2mv.4.20`);
  - a webhook worker (FG-046) and a native event feed (`x2mv.4.35`);
  - the backup product (`x2mv.4.21`, `x2mv.4.42`).
- **Deployment:**
  - TLS or a ratified proxy posture (D9, then `x2mv.4.30`);
  - continuous `fg serve` and `fg serve-ssh` (`x2mv.4.32`);
  - binary-driven transport coverage feeding the compatibility matrix (`x2mv.4.33`).

**D. Agents on the designed authority model (P1, after C's identity work).**
- Agent principals with sponsor chains (`x2mv.4.34`).
- The task store, collectors and executor (`xcu9`, `sjzo`, `p7sa`).
- The MCP server (FG-096b) and its drift fix (`x2mv.4.17`).
- Exit test: agent day (`x2mv.4.24`).

One authority model, not two.

**E. Pillars on real paths (P2).** Each is connected to a consumer that needs it and has a measured effect or a recorded negative result:
- commit-ancestry graph for admission (`x2mv.4.36`);
- verified reads on HTTP (`x2mv.4.41`);
- ATP-Git on one path (`x2mv.4.22`);
- adaptive CAS retry as the first statistics consumer (`x2mv.4.37`);
- TreeFS sharing (`x2mv.4.40`);
- the sparse lease fix (`x2mv.4.43`).

**F. Dogfood as the integrating test (P2, after A and C).** `x2mv.4.25` hosts this repository on a long-lived node fed from origin/main. Its required check is `cargo check` plus focused tests, run by FrankenGit's own CI loop: FrankenGit verifies FrankenGit. Its week-long record (storage growth, events against the ceiling, search lag, check latency) is the evidence that the forge qualifier is earned.

**G. Distributed, hosted and release (existing work, after A–C).**
- Remote authority backend (`88g7`, after D9).
- Routing authority (`b5ph`).
- Release target execution (`0zjt`, FG-091).
- Hostile isolation (`25cs`, after D5).

**Owner decisions, all in `x2mv.4.14`:**
- D1: the hand-written gateway versus ADR-0011.
- D2: the JavaScript browser versus ADR-0013. This now includes a served JavaScript Git decoder.
- D3: publishing fastapi_rust and frankentui on Asupersync 0.5.
- D4: psm native assembly.
- D5: the hostile-CI stance.
- D6: routing authority and v1 scope.
- D7: direct-main publication without a toolchain.
- D8: who is the batch verifier.
- D9: the TLS posture.

D7 and D8 gate track A. Nothing else in this plan is as cheap or as leveraged.

## 8. How the plan was refined

**Phase 2 draft.** The first draft re-graded the 2026-09-23 checklist and turned every gap with no bead into a bead: `.29`–`.44`, each carrying its observed evidence, deliverable, acceptance with twins, and relations.

**Executed-evidence feedback.** Running the swarm's untested real-browser probe (`x2mv.4.11`) found two things:
- A hard-coded success field in the probe itself (§5.8).
- A shipped outage: every browser page built on the issue, pulls-core or history client could not make a single API call in Chrome, and had not been able to since 2026-09-18/19. Meanwhile 1,731 of 1,752 fake-DOM browser tests passed.

That added `x2mv.4.45`, fixed in `56bba7ee`, with real-browser suites in `5561f2f9` and `b7de0d5e`. It also changed the plan's centre of gravity: the weakest link is the evidence system, not any one feature.

**Ambition pass 1.** Each track got an executable exit instead of a closure target, and two beads were added:
- `x2mv.4.46`: every served page booted, connected, read from and written to in a real browser, in the lane.
- `x2mv.4.47`: a deterministic simulation lane that drives the real admission and authority code through fgit-lab and Asupersync's lab runtime.

**Ambition pass 2 (mechanisms, not wishes).**
- `x2mv.4.9` now starts from a measured decomposition of single-writer service time. Throughput under one gate is about 1/S; a batch-B combiner only amortizes the CAS and fsync share. If preparation dominates, moving it outside the permit beats the combiner, and a combiner that cannot beat it is recorded as negative evidence.
- `x2mv.4.7` gets one mechanism for three problems: a settled-prefix Merkle Mountain Range checkpoint. It bounds canonical state at O(log n), gives O(log n) historical-event proofs to verified reads (`x2mv.4.41`) and the event feed (`x2mv.4.35`), and settles fgit-projection's fate: it becomes the per-aggregate index.
- `x2mv.4.25` became the integrating test: FrankenGit hosts and verifies FrankenGit, with its own CI as the compile sentinel (D7 option a).

**Ambition pass 3 (deeper mathematics where it pays).**
- PCT schedules (Burckhardt et al., 2010) give the simulation lane a stated probability of finding depth-d concurrency bugs per seed budget.
- The CALM theorem, with lattice types (grow-only sets for comments, observed-remove sets for labels), makes `x2mv.4.39`'s commuting of monotone intents a property-tested claim, not a case-by-case argument.
- Corrected-commit-date generation numbers and changed-path Bloom filters are stretch accelerations for `x2mv.4.36`. Each has an exact-walk oracle and a negative-evidence path.

**Refinement rounds** (the frozen Phase 5 prompt):
1. **Structure.** `bv` found no cycles. Its 20 missing-dependency suggestions were keyword overlaps among older beads and were not adopted; none involved the new beads.
   - Team day's burst step was updated to cross today's binding 16,384 ceiling instead of the obsolete 4,096 one.
   - `x2mv.4.32` now blocks team day, because a day on a server that exits after N sessions is not a deployment.
   - `x2mv.4.29` and `x2mv.4.18` now carry the real-browser suites and the node:test browser suite, including its 21 pre-existing failures.
   - A real-Chrome boot of all 12 main pages found no exceptions, which points those failures at fake-DOM fixture drift.
2. **Consistency and standards.** `x2mv.4.32` was raised to P1 to match the exit test it blocks. `x2mv.4.12` must not invent a second lifecycle model, so it builds on `x2mv.4.38` regions or carries its own reap test. One logging and test standard was recorded on the epic for children `.29`–`.47`.
3. **User impact.** Priorities were checked against what blocks a team first: merging with required checks, remote HTTP, PR conversation, the event ceiling, writer latency. No change.
4. **Honesty.** No new bead can close on refusal-only work or a narrowed claim. `x2mv.4.45`'s one forward-pointing acceptance line was narrowed to its own fix scope and satisfied, instead of being laundered into `x2mv.4.46`.
5. **Convergence.** A final pass found nothing further to change.

## 9. Tracker changes made by this assessment

The epic `frankengit-root-doctrine-x2mv.4` gained 24 children, `.29`–`.52`, labelled `reality-check-2026-09-27`. `.48`–`.50` were filed from the smoke failures in §2, `.51` from the sanctioned fgit-node rerun, and `.52` from the fgit-cli rerun at `e98c2d05`. On 2026-09-28 the tracker holds 621 live records: 475 closed, 97 open, 34 batch_pending, 8 blocked, 5 deferred and 2 in progress. That puts verification debt at 36, exactly the hard limit, so the tracker refuses every new claim until a verifier closes beads (D8). `.11` moved to blocked on D2, which freed the one slot `.32` took. This assessment added two claims: `.45`, now batch_pending, and `.18`.

| Bead | Status | P | Assignee | Obligation |
|---|---|---|---|---|
| `x2mv.4.1` | batch_pending | P0 | IcyIbis | main does not compile: fgit-runner observations.rs E0423 at 46b922e7 and fgit-forge rename tests (29 errors) never compiled |
| `x2mv.4.2` | open | P0 | — | Stop uncompiled commits landing on main and route the unclaimed implementation streams through their beads |
| `x2mv.4.3` | open | P0 | — | Re-verify the 2026-09-22 closure wave line by line; reopen closures whose acceptance is unmet; forbid SHA-less and self-provided gates |
| `x2mv.4.4` | in_progress | P0 | IcyIbis | fgit-ssh is not confidential: fixed ephemeral X25519 key, fixed cookie, non-constant-time MAC check, pre-auth unbounded buffering, ignored flow control |
| `x2mv.4.5` | batch_pending | P1 | IcyIbis | fg serve --receive-principal accepts non-loopback listeners: unauthenticated network push |
| `x2mv.4.6` | open | P1 | — | Policy integrity: fabricated principal facts, fail-open receive checks, policy-source injection, unmatched required checks, unbound snapshot identity |
| `x2mv.4.7` | open | P1 | — | Forge stops serving PR/issue reads after 4,096 events and refuses all publication at 16,384: bound read cost independent of history |
| `x2mv.4.8` | batch_pending | P1 | IcyIbis | Smart HTTP: stock git push fails without Idempotency-Key; node reopened per request; server exits after 1,024 requests; transport capability divergence |
| `x2mv.4.9` | open | P1 | — | Wire per-core preparation lanes, flat combiner and witness refinement into real admission with an equivalence oracle and measured evidence |
| `x2mv.4.10` | open | P1 | — | Wire GC/retention, scrub/repair, RaptorQ and compaction onto real node data (fg gc / fg scrub / fg repair) |
| `x2mv.4.11` | blocked (D2) | P1 | IcyIbis | Render issue/PR/comment Markdown safely through fgit-doc on HTTP, browser and MCP (v1 scope item 10) |
| `x2mv.4.12` | open | P1 | — | CI product loop: event-triggered runs, canonical check publication, required-check gating, honest substrate receipts, artifacts/cache |
| `x2mv.4.13` | open | P1 | — | Bind authenticated fgit-identity principals to every write surface; operator-asserted principals become explicit and recorded |
| `x2mv.4.14` | blocked | P1 | — | OWNER DECISIONS 2026-09-23: hand-rolled gateway vs ADR-0011, JS web UI vs ADR-0013, publish fastapi_rust/frankentui on asupersync 0.5, psm native assembly, hostile-CI stance |
| `x2mv.4.15` | open | P1 | — | Constitution checker and registry drift: #[expect] lint hole, psm/DEP-182 misstatement, 0.4.x text vs 0.5.0 lock, stale rationales, missing license-file, stale negative-evidence ledger |
| `x2mv.4.16` | open | P2 | — | Inventory and (owner-approved) removal of 174 patch-transport files, .visibility-payload and the hosted write-to-main workflow |
| `x2mv.4.17` | open | P2 | — | MCP tool registry and parity manifest disagree with the real fg mcp server; add drift check and stdio live-client e2e |
| `x2mv.4.18` | batch_pending | P0 | IcyIbis | Run the ~40 orphaned smoke campaigns and browser tests in lanes; label cargo-test-wrapper suites; remove foreign target dirs and RCH bypass from suites |
| `x2mv.4.19` | open | P1 | — | Indexed search is unusable on an active repository: forge-only writes stale the index, builds abort on one bad file, no in-server maintenance, no index GC |
| `x2mv.4.20` | open | P1 | — | PR workflow gaps: reopen, conversation/line comments, squash/ff merge, approval survival rule, quorum/path ownership, protection admin over HTTP/MCP |
| `x2mv.4.21` | open | P1 | — | Backup/restore as fg subcommands: streaming (no 1 GiB/100k caps), signed manifests, capsule restore, destroy-and-restore drill with RTO |
| `x2mv.4.22` | open | P3 | — | Put ATP-Git on one real transfer path with differential parity and measured bytes/time vs standard transfer |
| `x2mv.4.23` | open | P1 | — | EXIT TEST: one real team day through the fg binary over SSH and smart HTTP with auth, protection, CI checks, merge races, crash recovery, backup/restore |
| `x2mv.4.24` | open | P1 | — | EXIT TEST: one real agent run through IntentRun, ContextPacket, TreeFS, broker, ECC and ordinary admission (fgit-agent off the island) |
| `x2mv.4.25` | open | P2 | — | Dogfood: host the FrankenGit repository on a long-lived FrankenGit node with daily parity, search and time-travel checks |
| `x2mv.4.26` | open | P0 | — | Canonical fast lane is red at every failable stage: docs, rustfmt (72 files), check (2 uncompilable test targets), clippy, 45 failing tests in 26 binaries, stale-pin campaign failures |
| `x2mv.4.27` | batch_pending | P1 | IcyIbis | Concurrent writers: CAS losers get 503 outcome_unknown or wrong refusal counts instead of a deterministic terminal refusal (7 race tests, reproducible on an idle host) |
| `x2mv.4.28` | open | P2 | — | Loose import (fg import) uses a flat 15 s database budget; scale it to staged bytes like receive (asb8) |
| `x2mv.4.29` (new) | open | P0 | — | Union batch verification at one named SHA over every batch_pending bead: verification debt 34 of hard 36, no close since 2026-09-23 |
| `x2mv.4.30` (new) | open | P1 | — | TLS for FrankenGit transports: a pure-Rust TLS closure (serve-http server; webhook and object-store clients) or an owner-ratified same-host reverse-proxy profile |
| `x2mv.4.31` (new) | open | P1 | — | Browser-facing HTTP API accepts state-changing form POSTs with no CSRF or Origin check, and Basic challenges let browsers cache and replay credentials |
| `x2mv.4.32` (new) | in_progress | P1 | IcyIbis | fg serve and fg serve-ssh: continuous lifetime with SIGTERM/SIGINT drain; fg serve exits after one session by default |
| `x2mv.4.33` (new) | open | P2 | — | Binary-driven transport coverage for partial clone, notes, submodule gitlinks and atomic push over SSH and git://; matrix rows from executed suites |
| `x2mv.4.34` (new) | open | P1 | — | Agents as first-class principals: an fgit-identity agent credential with a sponsor chain, presented to admission and policy as PrincipalKind::Agent |
| `x2mv.4.35` (new) | open | P2 | — | Native event feed over HTTP and MCP: cursor-paged canonical forge events with authorization filtering |
| `x2mv.4.36` (new) | open | P2 | — | Build GRAPH-001 commit ancestry from canonical data and use it for admission ancestry checks, with an equivalence oracle and measured effect |
| `x2mv.4.37` (new) | open | P3 | — | First production consumer of fgit-statistics: bounded adaptive authority-CAS retry with e-process regime detection and a deterministic fallback |
| `x2mv.4.38` (new) | open | P2 | — | Runner, TreeFS workspace and agent effects under Asupersync regions with typed reserve/commit/abort obligations instead of counters |
| `x2mv.4.39` (new) | open | P2 | — | Consult CALM classification in admission: commute monotone forge intents across CAS losers instead of refusing them |
| `x2mv.4.40` (new) | open | P3 | — | TreeFS shared host materialization: share immutable file bytes across workspaces with copy-on-write, and measure per-workspace cost |
| `x2mv.4.41` (new) | open | P2 | — | Verified reads on a transport: serve FG-037 envelopes over HTTP, verify them in fg, and make browser verified downloads use real inclusion proofs |
| `x2mv.4.42` (new) | open | P2 | — | Pin the fsqlite companion-file contract that authority backup, restore and cleanup depend on |
| `x2mv.4.43` (new) | open | P2 | — | Sparse workspace lease takes a non-blocking flock with no bounded wait: intermittent WouldBlock |
| `x2mv.4.44` (new) | open | P2 | — | Offline bundle verification in Rust (fg bundle verify); retire or owner-ratify the JavaScript pack/DEFLATE/delta decoder |
| `x2mv.4.45` (new) | batch_pending | P1 | IcyIbis | Browser pages cannot call the API in a real browser: stored fetch invoked as a method (Illegal invocation) since 2026-09-18 |
| `x2mv.4.46` (new) | open | P1 | — | Real-browser boot, connect, read and write smoke for every served page against fg serve-http |
| `x2mv.4.47` (new) | open | P2 | — | Deterministic simulation lane: drive OneNode admission and the authority store through fgit-lab and the Asupersync lab runtime with PCT schedules and fault plans |
| `x2mv.4.48` (new) | open | P2 | — | fg doctor parses its sample object id as SHA-1 even in a SHA-256 repository |
| `x2mv.4.49` (new) | open | P2 | — | Guarded git-daemon receive reports per-ref refusals of a received pack as a fatal ERR packet instead of report-status ng |
| `x2mv.4.50` (new) | open | P1 | — | CLI forge commands race a flat 15 s Database-class deadline; under load writes end ambiguous instead of completing |
| `x2mv.4.51` (new) | open | P2 | — | Under deadline pressure, admission reports cancellation as integrity refusals (AuthorityReceiptInvalid, EvidenceInvalid, EvidenceMissing) |
| `x2mv.4.52` (new) | open | P2 | — | Manual webhook replay of a dead letter is always refused: 49fbc0f3's attempt guard rejects attempt max_attempts+1 (ResourceBudgetExceeded) |

**Edges.** Blocking edges were added only where the work genuinely cannot proceed first:
- `.30` is blocked by `.14` (decision D9);
- `.24` is blocked by `.34`;
- `.25` is blocked by `.12` and `.10`;
- `.23` is blocked by `.32`.

All other edges are `related`. `bv` reports no cycles.

**Priority changes.**
- `.18` rose to P0: it is the second half of the verification freeze.
- `.9` rose to P1: it now has a measured consumer, the single-writer gate.
- `.32` rose to P1: it blocks team day.

**Evidence and design comments** were added to:
- decisions `.14` (D7, D8, D9);
- `.2`, `.6`, `.7`, `.9`, `.11`, `.12`, `.17`, `.18`, `.19`, `.20`, `.23`, `.25`, `.29`, `.36`, `.39`, `.44` and `.45`;
- the epic (the children's logging and test standard);
- FG-046 and FG-093.

**Code landed during the assessment,** all under beads and SHA-bound:
- `56bba7ee`: the browser fetch-receiver fix plus a regression test that fails 3/3 on the unfixed code (`.45`).
- `5561f2f9`: the real-browser Markdown CSP suite, replacing a probe that hard-coded its CSP field (`.11`).
- `b7de0d5e`: the real-browser per-client fetch suite, 9/9 with the fix and 3/9 without (`.45`).

**Not done.** No existing bead was closed, reopened or reassigned. Transitions belong to the independent verifier. `.45` stays in progress until its sanctioned crate test run.

### Batch verification at `14ce0fa1` and what followed (2026-09-28/29, decision D8)

The owner appointed IcyIbis as batch verifier (D8). The terms: verify every batch_pending bead at one pinned SHA (`14ce0fa1`). Close only beads IcyIbis did not author, and only when every acceptance line is observed with SHA-bound evidence; otherwise send the bead to rework, naming the failing line. IcyIbis's own beads wait for another verifier. This supersedes the "Not done" paragraph above for everything after 2026-09-28.

**Union run at `14ce0fa1`.**

| Step | Result |
|---|---|
| docs | pass |
| constitution | fail: one first-party `too_many_arguments` allow, removed in `e6854d0b` |
| fmt | fail: 81 files, formatted in `417c7bb8` |
| check | pass |
| schema | pass |
| workspace tests | 654 binaries, 7,766 passed, 58 failed |
| clippy | fail at the lowest layer |

- Rerun alone, 56 of the 58 test failures pass. They are budget cancellations under parallel load.
- The two deterministic failures:
  - `native_protection_smoke` (fixed by x2mv.4.50, passing at `0b142c15`);
  - `pull_request_checks_http::actual_workflow_observations_are_paged_by_exact_ids_without_evidence_bodies` (x2mv.4.12).
- The e2e lane passed 46 of 55 suites. Rerun with a release `fg` at `0b142c15`, `continuous_git_transports` passes 11/11. Its failure was the flat 15 s served-upload clock. The other eight are the defects already mapped on x2mv.4.18.

**Verdicts, 28 beads.**
- **Closed (10):**
  - hfh8, smke, omr4, 3wy2, x796, xefn, clzl;
  - rpqx: count-once accounting; the 85 MB push works with a release `fg`;
  - l0xt: a planted forbidden native link is refused by name;
  - x7ja: a stock-client fetch receives exactly the 13 missing objects of 36;
  - 1n25: a same-session A/B at `14ce0fa1` with only the fix reverted took the clone from 21.9 s to 4.2 s (5.2x), with pack bytes identical.
- **Rework (17):**
  - 1e3q, 0zjt, c7tb, fg083a, fg063, fg074, fg036b, fg038b, zb0q, jkbo, fg019c, fg046, fg046b, asb8, e6jj;
  - x2mv.2: one-copy and determinism are not exercised;
  - b3wy: two schema descriptions do not match their encoders.
- Each verdict is a comment on its bead. Verification debt fell from 36 (the hard limit) to 12. Every remaining batch_pending bead is IcyIbis's own.

**A regression the verifier introduced, and its repair.**
- `0b142c15` (x2mv.4.53) moved the served git:// and SSH paths from the Database class onto the session clock. It added a structural test enforcing that.
- This broke x7ja R5's ratified contract: the kxmb test `git_daemon_deadline::one_node_reports_database_budget_expiry_while_the_session_is_live`.
- The sanctioned run found it. `b9919b20` restored the ceiling, and the regression is noticed on x7ja and x2mv.4.53.
- R5 and e6jj's XL clone-back (PUSH-036) then conflicted under the fixed 15 s default. The owner ruled for a work-scaled ceiling, landed in `0b0f3ecb`: served fabric reads earn Database time by the verified bytes they deliver (the receive-side doctrine of asb8). kxmb stays 9/9.

**Capability landed.**

| Change | Commit | Measured |
|---|---|---|
| Served packs use `COMPRESSED_V3` | `ac618476` (frankengit-77qh) | Planning is 2.4-27x faster than V2 across three corpus shapes. The XL clone-back went from 297.6 s to 131 s and now passes under the default envelope. FG-028c egress +0.04%. |
| CLI commands run on one operator time policy | `b7f4e427` (x2mv.4.50, batch_pending) | Protection smoke 2/2 and the command-time suite 25/25 under load at `ac618476`. |
| Clippy's lowest layer drained | `319eddfb` | fgit-graph, fgit-ssh, fgit-forge and fgit-admission are clean. |

**Filed.**
- frankengit-pazc: the client's `thin-pack` is parsed and never used, so a 3-commit fetch costs 99.5% of a clone's bytes.
- frankengit-77qh: done above.
- frankengit-mkgq: `source_symbols_cli` has failed 4/4 since `9ce9b346`. Root-scope narrowing refuses the test's non-UTF-8 fixture.

**Not claimed.**
- The workspace clippy lane is still red. The crates above the drained layer, fgit-node and up, are unmeasured.
- Path-aware delta candidate order and stored-delta reuse are not built.
- No bead IcyIbis authored has been independently verified.

## 10. Evidence appendix

| Artifact (scratchpad-relative) | SHA-256 |
|---|---|
| `rc-evidence/check.log` | `9e6ca086f9b567ae83546d9e6bb44cb386ff990aa113f3357d7cf95b5ec09ca8` |
| `rc-evidence/fmt.log` | `18a8dd210c492c7debd7e4c687036001a7f99ac0f3f748180394ae49154b4e33` |
| `rc-evidence/fmt-files.txt` | `7e33c7b5127c2bb102dac7fa6f08811e81e1ffd45c32f0bd7a69c508c2210939` |
| `rc-evidence/test-fgit-admission.log` | `e4a180fccd126f2d237e3c77f866b07aebf6ab7e830d473a90bef6c322fd8a05` |
| `rc-evidence/md-csp-3.log` | `61aed55c4a1be95651cc9d4243052256b55cc83600c0e115bb9cd863e24b29bf` |
| `rc-evidence/client-fetch-md/receipt.ndjson` | `0f6e48ba57d55de43675ca3b0971612b4aab50491e6d389f863738bc6cbfff70` |
| `rc-evidence/client-fetch-rc/receipt.ndjson` | `391d7dc535412b13fb8e2ce190bd53ecd5de1a0df7d86b3ce9a0a7e16a85761d` |
| `rc-evidence/md-csp-3/receipt.ndjson` | `3df00d63bd6b504f09a9fed3dc515bd6dff841d48051a9be8b2aac5bc000848f` |
| `fg-debug-rc` | `5b0e0c11f899e9933efcf9b5ebf99fd9bd6a7463c222d9ccddd53ae0e0ad2e4d` |
| `fg-debug-md` | `714882984f0eabed46360ed4a91da13f3fa6e7aa178e942f46eb1d229abea0b7` |
| `bv_suggest.json` | `3fdfb929074c7966a0994e0a1cad93d57f7ca1408c0da4f7cd17fd0022437218` |
| `bv_insights.json` | `3dd8d72350401cb18501a48b85ddc3fd38e42b458458db1d9fbc8faa81c01d81` |
| `rc_findings.md` | `6a78eed861d09ae8dfddd26bffcff81fb8f3bb1c6e8b583cd3bd9c9905fea3d5` |
| `docs-lane.log` | `3d58803fafe565d256cdbf9aed9ebf4da02d8b4c1727d92bea7f9845c3a77fed` |

`fg-debug-rc` is the debug `fg` built at `2b7f35ac` by the pinned run. `fg-debug-md` is built from the private worktree containing `56bba7ee` and `5561f2f9` on top of `41eab465`.

The 2026-09-23 appendix listed `beads_all.json` (`9e492495…`) as the tracker baseline. That scratchpad file was overwritten on 2026-09-27 by an audit subagent of this assessment (§5.11), so the earlier digest no longer names a retrievable artifact. The baseline counts stay in this document and in `.beads/issues.jsonl` history at `6c762f42`.

Raw logs, NDJSON receipts and the isolated worktrees remain in the session scratchpad. They are review artifacts, not published durable evidence.
