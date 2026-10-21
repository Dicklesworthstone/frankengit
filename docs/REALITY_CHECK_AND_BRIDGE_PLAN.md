# FrankenGit reality check and bridge plan — 2026-10-20

FrankenGit has a substantial, bounded Git node and an increasingly useful native
forge core. It remains an integration-stage product. It has not established
production readiness, a complete agent-native workflow, extreme-scale operation,
or a releasable distribution. The October 17 assessment understates several
capabilities that have since landed. Repeating its failure counts as current
would be as misleading as treating all new code as independently verified.

**Source binding:** `7eaf1df8d218354572159c1e0f212e330d1da9f4`.
This assessment branch changes documentation and tracker records only. There
are 130 commits reachable after `f73a3cca`, including the merge of the previously
divergent line. That count earns no capability credit.

**Consumer and retirement:** the repository owner and batch verifier use this
existing document to select the work gating a usable team deployment. Observed
defect classes are stale claims, unclosed verification, architectural divergence,
missing product consumers, and capacity cliffs. Supersede it in place after a
later revision-bound assessment. It grants no deployment or closure authority.

## 1. Material changes since October 17

| Old finding | Current source and evidence | Judgment |
|---|---|---|
| No declared pinned-oracle tier | 18 rows in `registries/compatibility_tiers.tsv`; row-bound receipt producer; README records 624/624 checks at `8a992b6e` | Real progress. Historical receipt, `git://` only; not reproduced here. |
| Required checks never gate merges | Native direct-ref and merge enforcement call `checks::verify_at`; node materializers call both gates | Old blanket finding is obsolete. Current native acceptance still needs execution. |
| CI triggering only in Node | Native ref watch, durable execution-to-check recovery and PR source-head watching (`b77774e5`, `3aa21f15`, `fe8c006f`, `91382cb8`) | Real native composition; trusted-host, bounded polling, source-head-only PR limits remain. |
| Per-object import durability | `bcb339e8` / `9e18d433`: bounded batch placement and directory fences | Reduced sync calls; throughput target unestablished, median improvement near baseline spread. |
| Quadratic pack lookup work | `10423859`: indexed resolver lookups with duplicate-key/oracle tests | Real algorithmic correction; independent acceptance still pending. |
| Large-import failure looked like a 300 s timeout | `2a9c7023`: 1 MiB canonical-body limit; `1425ba02`: metadata preflight and leading global timeout | Corrected cause and finite profile; full 100k-object CLI campaign outstanding. |
| No closes since September 29 | `.4.43` and `.4.17` closed October 19; HEAD-symref work reopened and handed off | Zero-throughput claim obsolete; queue still at its hard limit. |
| Formatting red | Fresh format check exits 0 at `7eaf1df8` | Formatting fixed at this revision; no build/test/Clippy implication. |

The native check verifier binds the exact candidate commit, source ref,
publisher, workflow graph and job. It selects the latest canonical result,
requires the source still to name the candidate, and rechecks after CAS loss.
A later failure supersedes an earlier success. Missing/corrupt history is
unavailable, not permission. The generic `evaluate_protected_ref` lacking an
external caller does not prove this newer native gate is absent.

PR watching can execute the current source while `fg pr checks` still selects
the PR's recorded source. Updating PR metadata remains explicit. A source-head
success does not prove that a synthetic merged tree builds.

## 2. Evidence obtained in this assessment

Host: Apple Silicon macOS; Node **26.8.1**; installed Apple Git **2.50.1**;
Rust pin **nightly-2026-08-31**. Installed Node and Apple Git are not claimed as
the project's pinned compatibility oracle. Raw logs remain outside source in
`/tmp/frankengit-reality-20261020`.

| Check at source `7eaf1df8` | Result | Limit |
|---|---|---|
| AGENTS.md and README.md | All 484 and 807 lines read | Contract/vision intake, not implementation proof. |
| Pinned bootstrap metadata | exit 0 | Pin/URLs agree; no download or toolchain advancement. |
| `cargo fmt --all -- --check` | exit 0 | Formatting only. |
| `scripts/license_gate.sh` | exit 0 | Exact `LicenseRef-MIT-OpenAI-Anthropic-Rider`, OSI marker `no`. |
| `verify.sh --no-artifact full` | exit 3 | Deliberately dormant; a non-pass. |
| Pinned oracle verification | exit 69, no local binary receipt | Current Tier A not run; Apple Git is no substitute. |
| Public GitHub Releases API | empty release list on 2026-10-20 | No published GitHub release observed; not a complete distribution-channel inventory. |
| Browser Node suite: 122 files, concurrency 2 | 3,632 tests: 3,626 passed, 5 failed, 1 skipped | JS tests, not Chrome or native-server evidence. |
| Operator Node suite: 150 files, concurrency 2 | audit timeout at 180 s, no terminal aggregate | Partial execution with failures, never a suite pass. |
| Script Node suite: 68 files, concurrency 2 | audit timeout at 180 s, no terminal aggregate | Partial execution with failures; no native-server implication. |
| Focused bootstrap with default macOS temp path | 0/2, unsafe-directory refusal | Canonical spelling mismatch. |
| Same bootstrap with `TMPDIR=/private/tmp` | 2/2 | Isolates one environment/fixture defect, not a whole-plane pass. |
| Claim artifact digests | CLM-001..005 match; two CLM-006 artifacts differ | Digests do not rerun Lean or prove Rust refinement. CLM-006 is only `implemented`. |
| Wrapped graph analysis | 683 rows, 25 tombstones, 658 visible; no cycles in insights | `BV_BIN` override required: PATH has unsupported bv 0.12.0. `br` alone authorizes claims. |

Five browser failures: one `/var` versus `/private/var` path assertion, and four
raw non-UTF-8 filename creations rejected by this filesystem. Preserve Git byte
semantics and host-representability limits. Fix the fixture/profile; do not weaken
security checks or turn required cells into successful skips. The temp-path
control establishes one cause, not every operator failure or the timeout.

### Native execution boundary

No current `fg` binary exists in this macOS checkout. `sbh check --need 20G`
exits 1 for critical free-space ratio despite roughly 203 GB free; the prescribed
`/data/frankengit-targets` volume path is unavailable. RCH admission recognizes
the check as offload-eligible, but fleet health reports `not_ready`. An inspected
remote checkout is at `2a9c7023` and its default debug binary dates to August;
neither substitutes for current source. No bypass, fleet reconfiguration,
storage deletion, or toolchain upgrade was performed.

This run does **not** establish a current native build, Rust workspace test
pass, Clippy pass, real-client E2E pass, or live deployment. Fresh native
execution remains a bridge obligation, rather than a fabricated result.

The public [GitHub Releases API](https://api.github.com/repos/Dicklesworthstone/frankengit/releases?per_page=5)
returned an empty list. This supports no-published-GitHub-release wording, not a
claim to have inspected every possible deployment or distribution channel.

Historical evidence remains useful and separate:

- `.4.26`: 9,383 passed / 1 failed across 700 binaries at `e5204790`, with that
  fixture repaired later. It explicitly records no one-SHA end-to-end `fast`
  success; Clippy remained unmet.
- `eq4h`: earlier node tests and Tier A receipts, plus an interrupted aggregate
  containing a hanging webhook test. Cases passing alone do not repair that
  aggregate's evidence.
- October 17's 46 Rust failures and 62/69 product suites are historical counts,
  not this revision's failure inventory.

## 3. Vision and existing ownership

**PARTIAL:** real code with missing breadth/integration. **LIBRARY:** no normal
dependency path into `fg`. **UNPROVEN:** required outcome lacks current executed
evidence. **REFUSED:** explicit unsupported boundary. Historical bounded success
does not promote a whole subsystem to WORKING.

Abbreviated `.4.N` means `frankengit-root-doctrine-x2mv.4.N`. FG identifiers
refer to uniquely titled tracker items. This matrix covers plan §4.1, the
roadmap exits, README innovations, and §49 completion classes.

| # | Testable goal | Reality / remaining outcome | Status | Existing owner |
|---|---|---|---|---|
| 1 | Create/import/export and retry exact native repositories | CLI/node, bounded spool, batch placement; scale/recovery campaign outstanding | PARTIAL | FG-106, `gzdy`, `pc9g`, `eq4h` |
| 2 | Ordinary Git in declared SHA-1/SHA-256 Tier A | 18 rows, historical pinned success; current revalidation needed | PARTIAL | `.4.60`, FG-090, FG-098 |
| 3 | SSH/HTTP usable beyond one trusted host | Real adapters; loopback HTTP, no admitted native TLS | PARTIAL | FG-105, `.4.30`, `.4.13` |
| 4 | Atomic refs and ref/forge merges | Real admission/head CAS; restart/race breadth gated | PARTIAL | `.4.20`, `.4.58`, FG-019c |
| 5 | Users/orgs/teams and authenticated revocable actors | Identity library and transport bindings; CLI/MCP trust supplied principals | PARTIAL | `.4.13`, `.4.34`, FG-101 |
| 6 | Protection enforces current reviews/checks | Native candidate checks and review quorums; general policy integrity unresolved | PARTIAL | `.4.6`, `.4.12`, `.4.20` |
| 7 | PR/comments/reviews/reopen/merge | Real native/API/browser paths; full team workflow unproven | PARTIAL | `.4.20`, `.4.23`, `.4.58` |
| 8 | Issues/discussions/notifications | Issues and assignment events; complete discussion/notification product absent | PARTIAL | FG-045 |
| 9 | Event API and settled webhook delivery | Feeds exist; dispatcher reports `canonical_settled:false` | PARTIAL | `.4.35`, `.4.55`, `.4.57`, `e0eg`, FG-046 |
| 10 | Safe Markdown and reliable browser UI | Native rendering and JS pages; host suite failures, accepted WASM architecture differs | PARTIAL | `.4.11`, `.4.46`, FG-050, `.4.14` |
| 11 | Fresh lexical/symbol search after writes | Real indexes/stamps/guarded publication; automatic maintenance/retention incomplete | PARTIAL | `.4.19`, FG-032a/b/c |
| 12 | CI trigger → run → publish → gate | Native watch/report/artifact/check paths; trusted host only | PARTIAL | `.4.12`, `.4.70`, `25cs` |
| 13 | Sponsored agent run through ECC | Typed agent library; product host/credential/executor composition absent | LIBRARY | `.4.24`, `.4.34`, `p7sa`, `xcu9`, `sjzo` |
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
| 24 | Statistical operational adaptation | Controller constructed; retry loop does not consult it | PARTIAL | `.4.37` |
| 25 | Evidence exchange and build reuse | Typed libraries without product adoption | LIBRARY | `.4.68`, `.4.69` |
| 26 | Formal production refinement | Contained Lean model and bounded trace bridge, not a Rust proof | PARTIAL | `.4.67`, FG-041 |
| 27 | Native signed DSR release matrix | `full` dormant, release publication unsupported | REFUSED | FG-035, FG-091, `0zjt` |
| 28 | Upgrades/security/external adopter success | Open campaigns; source presence cannot satisfy them | UNPROVEN | `.4.62`, `.4.65`, `.4.66` |
| 29 | Measured throughput/economics/RPO/RTO | Bounded samples; published deployment targets/drills absent | UNPROVEN | `.4.63`, `.4.21`, FG-036 |
| 30 | Hosted/federated/packages/dogfood | Fragmentary protocols, no complete operated service/release loop | PARTIAL / UNPROVEN | FG-063/065/100/102/104, `.4.25` |

No top-level goal above was found wholly absent from non-closed work. Ownership
was checked against descriptions and critical owning records, not just titles.
This is better coverage than prior assessments, not a proof every acceptance
line is complete. A newly observed host-portability defect needs a bounded
owner within that larger program (§7).

**Would finishing every open bead finish the vision?** Most named mechanisms
are now represented. Completion still requires settling contradictory scope
and framework decisions, refreshing stale acceptance, and executing the
team-day, agent-run, Phase 7, restore, security and external-adopter joins.
Individually closed beads cannot substitute for those outcomes or for actual
independent participants where independence is required.

## 4. Remaining controlling constraints

### Capacity and wiring

- Forge-position and outbox canonical state still allow at most **16,384
  entries** (`fgit-codec/src/canonical_state.rs`). These are encoded state-entry
  bounds, not automatically a universal lifetime event count: stream/frontier
  layout determines entry consumption. Raising a read limit does not remove them.
- `MAX_CONCURRENT_WRITERS` remains **1**. Parallel preparation and correct CAS
  semantics do not establish parallel committed throughput.
- Manifest traversal, including target-specific normal dependencies, finds nine
  product islands outside `fg`: agent, ATP-Git, compaction, exchange, object-store,
  projection, RaptorQ, repair, witness; **57,873 `src` lines**. Dependency
  reachability is not linker/dead-code proof. Statistics is linked but its
  constructed controller remains unconsulted by retry loops.
- Required-check verification has **4,096 history-step**, 65,536 batch/event,
  and 128 MiB limits. Exhaustion fails closed. An authenticated index/checkpoint
  must preserve latest-result semantics before claiming scalable protection.
- The new 16 MiB closure envelope still permits at most **762,596 SHA-1** or
  **493,444 SHA-256** members in the present codec. Payload, pack, graph and time
  bounds are independent. Encoder tests do not replace the 100k CLI campaign.

### Architectural contradictions: stop affected implementation

1. AGENTS.md §16.2 prohibits the RCH bypass; `scripts/verify.sh` exports it
   unconditionally and cites obsolete instructions. Inherited tracker context
   and `one_node_bringup.sh` also carry old local-build directives.
2. The integration constitution requires Asupersync 0.4.x and says no
   constellation exists; manifests/lockfiles select admitted 0.5.0. `.4.15`
   already owns the contradiction.
3. Accepted ADR-0011 selects fastapi_rust; product HTTP uses the owned adapter.
   ADR-0013 selects a primary Rust/WASM UI; served primary and operator paths
   are JS. D1/D2/D10 are not resolved by continued implementation.
4. Embedded `transfers-protocol.mjs` still implements pack/delta/inflate/idx.
   JS clients can explicitly select native bundle verification, a real step
   forward; the default legacy decoder is neither retired nor ratified.
5. Plan §4.2 and §49 disagree on merge queue/packages in 1.0; product-first
   versus ATP/TreeFS order is unresolved. Preserve scope pending owner ruling.

Rust-only scans cannot certify the JS plane's dependency/runtime/crypto posture.
No npm dependencies and no production foreign-Git subprocess do not resolve
the architecture mismatch. This assessment records, rather than rules on, it.

### Verification capacity

Intake: **658 live** = 487 closed, 102 open, 28 batch_pending, 19 rework,
9 blocked, 8 in_progress, 5 deferred; plus 25 tombstones. Verification debt is
**36/36**. IcyIbis owns **21 pending** items; the recorded D8 appointment cannot
independently close that actor's own work. Two recent closures are real, yet
the queue remains saturated. `eq4h` / `.4.60` show implementation evidence
accumulating while handoff is capacity-blocked. `br ready` does not waive capacity.

## 5. Bridge plan: outcomes, not crate count

Existing owners keep their scope. Code and its tests remain in one bead;
independent integration campaigns stay separate. No additional certificate
is needed. Every exit binds one source SHA, profile, artifacts and non-claims.

| Order | Deliverable / owners | Executable exit and refusal twin | Size |
|---|---|---|---|
| A | Verifiable landing and independent queue service: `.4.2/.15/.26/.29/.56` | One SHA: docs, constitution, fmt, check, schema, tests, Clippy and discovered product/browser/operator lanes. Missing, timed-out or stale cells prevent success; independent line-by-line acceptance. | L |
| B | Supported authenticated deployment: `.4.13/.14/.30`, FG-048c, FG-050 | Two users operate remotely through admitted TLS or a ratified proxy boundary. Wrong actor/scope, CSRF, revoked key and untrusted workflow publish nothing. | XL |
| C | Protected PR lifecycle: `.4.12/.20/.23/.58/.70` | Run checks, prepare/check exact merge candidate, collect quorum, merge, lose reply, restart, recover original outcome; assert ref/PR/outbox atomicity in both formats. Later failure/withdrawal/moved candidate denies. | L |
| D | Canonical webhook settlement: `.4.55/.57`, `e0eg`, FG-046 | Real delivery settles through authority. Crash around downstream acknowledgement probes original stable key. No sidecar-only completion or fabricated exactly-once claim. | L |
| E | Predictable import and serving: `eq4h`, `gzdy`, `pc9g`, `3gdw`, `e6jj` | Full 100k-object two-format CLI campaign: strict global/local timeout twins, original-key recovery with absent source, cold export, strict pack intake, exact bodies. A/A-controlled performance trials and crash-before-CAS twins. | L |
| F | Sustained forge operation: `.4.7/.9/.19/.39/.63` | Cross present state bounds while preserving historical proofs/latest checks; concurrent admission and fresh search versus canonical oracle; measure decisions/CAS, tails, memory, bytes and cost. | XL |
| G | Independently restorable repository: `.4.10/.21/.42/.61/.62`, `88g7` | Destroy derived state, restore authenticated source/forge/outcome/policy, serve and mutate; measure RPO/RTO. Corrupt newest acknowledged root fails closed. | XL |
| H | Real agent/sparse workspace: `.4.24/.34/.38/.40`, `p7sa`, `xcu9`, `sjzo`, `zb0q`, `mwck` | Agent credential → IntentRun/context → sparse shared workspace → brokered effects → ECC → normal admission; revoke/cancel and prove cleanup or explicit containment debt. | XL |
| I | Accelerated witnessed derived work: `.4.22/.36/.37/.64/.67/.68/.69` | One real consumer per library, scalar/deterministic oracle and measured benefit; ATP exact parity, witnessed graph decisions, evidence only tightens checks, unsupported statistics selects fallback. | XL |
| J | Releasable/adoptable product: FG-035, FG-091, `0zjt`, `.4.25/.65/.66` | Native target matrix, signed root-last manifest, installer/consumer evidence, independent security and external migrate/operate/restore/export; self-dogfood under the same rules. | XL |

Ordering expresses leverage, not invented blocking edges. A/B gate the team-day
exit. Native fault/performance work can proceed where its real prerequisites
exist. D9 precedes live HTTPS backend claims; owner decisions do not block
unrelated fixes. No phase-3/4 feature is silently dropped.

## 6. Ambition and refinement

The skill's frozen generation and refinement prompts govern this assessment.
Three ambition passes improve the bridge in place:

1. Replace crate-local completion with protected team-day, restore and real-agent
   joins; retain ATP/TreeFS scope and external acceptance.
2. Share final mechanisms: authenticated settled-prefix/checkpoint indexing for
   forge reads, latest checks and history; batch placement for import/receive;
   native bundle verification as the common recovery verifier. Each needs
   equivalence/failure evidence before adoption.
3. Bind optimization to a supported workload and oracle: conservative conflict
   graphs, deterministic batches, exact checkpoint frontiers, original-key
   recovery, A/A-controlled measurements. Wire existing abstractions before
   adding more abstract machinery.

Five refinement passes cover completeness, dependency/ownership, evidence
strength, failure/resource semantics, and user-visible convergence. Concrete
corrections include target-specific dependency traversal; distinguishing
state-entry caps from event counts; replacing the obsolete no-check-gate finding;
isolating the macOS path cause with a permitted twin; and preserving metadata
preflight/global-timeout acceptance in the import exit. The final pass includes
terminal JS results and graph validation. A first timeout remains non-pass.

## 7. Tracker handoff and limits

Reuse existing bridge owners; create no new program epic. Record the bounded
host-portability defect and relate it to `.4.26` / `.4.59`. Append fresh
evidence and refined exits to existing constitutional, queue, CI, capacity,
operator and import records. Keep statuses/assignees unchanged, with no forced
claim or self-closure. New defect: `frankengit-root-doctrine-x2mv.4.71`. Additive
evidence/refinement comments update `.4.12`, `.4.15`, `.4.26`, `.4.56`,
`.4.59`, `.4.63` and `gzdy`; related edges connect `.4.71` to `.4.26` and
`.4.59` without introducing blocking prerequisites. Final wrapped `bv`
triage/insights/suggestions and authoritative `br dep cycles` succeed over 684 rows (659 visible, 25
tombstones); both cycle reports are empty. Suggestions do not mention the new
item. States after the new open bug: 487 closed, 103 open, 28 batch_pending,
19 rework, 9 blocked, 8 in_progress, 5 deferred; debt remains 36/36.

Evidence is indexed in `/tmp/frankengit-reality-20261020/evidence-summary.json`.
The browser log SHA-256 is
`0a2bd3ab8b76fd2e60d1eda069e62c073347496d95672fd8b106f41f4df9903c`.
The paired bootstrap logs are
`e453cb21d616273baf8cc803f9daa8cf9d9c4f47bf13ac7eb4f8f3b9f867e66a`
and `5eac11dc535ac4e7829b62deaa4dee912df237e6e3d2c33ba7e2c6fa37501126`.
The two timed-out logs are retained in full without aggregate success claims.

Documentation is prepared on isolated branch `codex/reality-check-20261020`.
`br` resolves linked worktrees to the shared authoritative tracker, so tracker
updates are additive changes in the default checkout, synchronized after every
mutation. The default checkout's runtime source, statuses and assignees are
preserved; its tracker changes remain available for the repository's normal
landing workflow. Intake source remains `7eaf1df8`. This is a comprehensive
product/coverage assessment, not line-by-line review of all 599k Rust source or 57k subsystem-doc
lines. AGENTS.md and README.md were read in full; the full normative protocol
and dependency constitution, plan scope/requirements/roadmap/definition-of-done,
integration/release profiles, verification/threat contracts, relevant subsystem
docs, source call paths, registries and authoritative tracker evidence were
examined. Native, broad security, physical power-loss, deployment and complete
Rust-refinement claims remain unestablished.

## History

October 17's assessment remains in git history of this file (`f73a3cca`, landing
`bdec9ae1`). Prior snapshots: September 23 `6c762f42`, September 27/29
`f3da9d4f` / `14ce0fa1`, October 13 `9477ceac`. They are historical evidence,
not standing gate results.
