# Changelog

All notable changes to FrankenGit are documented here.

**Scope and method:** this changelog is reconstructed from the complete git history of [`Dicklesworthstone/frankengit`](https://github.com/Dicklesworthstone/frankengit) (34 commits through the v3 integration at `f3fe619`, 2026-08-19 through 2026-08-20, plus the wave documented under Unreleased). The project is pre-implementation: every entry describes architecture, contracts, registries, and verification tooling, not shipped software. There are no git tags and no GitHub Releases yet; the version spine below tracks **architecture document versions**, which are the only versioned artifact this repository has produced. Claim discipline applies here too: nothing in this file asserts implemented behavior.

## Version timeline

| Architecture version | Date | State | Anchor |
|---|---|---|---|
| v1 (exploratory plan) | 2026-08-19 | superseded same day | [`1c05cf0`](https://github.com/Dicklesworthstone/frankengit/commit/1c05cf0) |
| v2 (audited first-cut) | 2026-08-19 | superseded | [`5cb517c`](https://github.com/Dicklesworthstone/frankengit/commit/5cb517c) |
| v3 (FrankenSuite deep synthesis) | 2026-08-20 | current | [`f3fe619`](https://github.com/Dicklesworthstone/frankengit/commit/f3fe619) |

No `1.0` product version exists or is claimed. The definition of done for 1.0 is comprehensive-plan §49.

## [Unreleased] — 2026-08-20

Consistency-audit fixes, constitutional-checker hardening, and ambition extensions on top of the v3 architecture. These changes land as the grouped commits immediately following [`f3fe619`](https://github.com/Dicklesworthstone/frankengit/commit/f3fe619) in the git history.

### Fixed — cross-document contract drift (fresh-eyes audit)

A full-tree audit (five parallel reviewers plus an end-to-end read of the comprehensive plan) found no defect in the core authority model, but did find cross-document drift, which the constitution itself classifies as release-blocking:

- `docs/OBJECT_STORE_DECISION_LOG.md` struct definitions realigned field-for-field with the authoritative `docs/NORMATIVE_PROTOCOL_CONTRACTS.md`: `TransactionSealBody` no longer carries capability/epoch/time fields that would break byte-identical idempotent retry; `PreparedTxnCapsule` regains `seal_id`; `RepositoryDecisionBatchBody` drops the non-normative `first_committed_sequence`.
- `docs/CALM_AND_OBLIGATIONS.md` taxonomy now defines exactly the seven classes the registry uses (dropping the never-used `monotone_coordination_free`, defining `monotone_scoped` and `local_deterministic`); peer/piece availability reclassified as retractable `commutative_but_bounded` state; the obligation trait aligned to the normative lifecycle (`Reserved → Committed → Acknowledged`, or `Reserved → Aborted`); the §10 example table uses exact class tokens and the correct authority names; `registries/calm_operations.tsv` gains rows CALM-013/014.
- `docs/GIT_TREE_FS.md`: `WorkspaceSnapshotBody` gains the `staged_epoch` its own invariant referenced; `TreeEditIntent` gains variants (symlink, directory create/remove, conflict markers, entry classes) so every §3.2 overlay entry kind is producible from a typed intent; the secrets-in-overlay "by default" escape hatch is closed outright.
- One mixed-generation join rule now governs `docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md`, `docs/AGENT_PROTOCOL.md` §7.2, and normative invariant 20, including explicit cross-time join receipts.
- `docs/RAPTORQ_PERMEATION_MAP.md` vs `registries/durable_objects.tsv` reconciled: the registry gains an `encoding_class` column carrying the MUST/POLICY/MAY/EXEMPT/DEFERRED taxonomy, the merged artifact row splits into `ci_artifact_or_log` (policy) and `release_asset` (must), and `git_object_microsegment` (must) is registered (DUR-016/017).
- Lane state machine named identically everywhere (`Writable → Sealed → Combining → Retired → Writable`); backlog FG-014 corrected.
- Present-tense claims of nonexistent machinery rephrased to pre-implementation obligations (`constellation.lock`, TreeFS/CALM/graph test and gate claims), per the claim lattice.
- Negative-evidence prose ledger and `registries/negative_evidence.tsv` synchronized one-to-one (17 entries each, NEG-013..017 added, prose entries now cite their registry IDs).
- Smaller corrections: README section count, ADR-0001 revision labeling vs the repo-wide v2/v3 vocabulary, compatibility-matrix status vocabulary matched to the values its rows actually use, stale `2026-08-19` date headers, GitHub-unrenderable LaTeX math replaced with a text formula, and normative-status labels aligned across the four companion profiles.

### Fixed — constitutional checker blind spots (`fgit-registry-check`)

The audit treated the checker itself as an attack surface and closed every hole found:

- workflow gate: detects `- uses:` list-form actions (the SHA-pin check previously never fired on real syntax) and inline trigger forms (`on: push`, `on: [push, pull_request]`, `- push`), not just block-form `push:`; `schedule:`, `workflow_run:`, and `repository_dispatch:` triggers are refused as hosted automatic execution too, and inline `on: workflow_dispatch` is accepted;
- dependency gate: `[dependencies.NAME]` table + `package = "real"` rename evasion closed; `package=` without spaces parsed; `[patch]`/`[replace]` sections refused; and a new Cargo.lock pass enforces the closed world over the full transitive graph, matching what NEG-010 always claimed;
- markdown gate: link checking is now fence-, inline-code-, and escaped-backtick-aware, validates reference-style `[label]: target` definitions, handles `<angle bracket>` targets, and no longer aborts a file's remaining links on one malformed link;
- phrase gates: the `protocol v2 push` guard uses word boundaries ("nothing" no longer satisfies "not"); the exactly-one-canonical-`TxId`-derivation check is whitespace-tolerant in both directions;
- source gate: the forbidden-`unsafe` scan is whitespace-tolerant (`unsafe{`, `unsafe  fn`) and covers `trait`/`extern`, and crate-root `#![forbid(unsafe_code)]` checking extends to `src/bin/*.rs`;
- traversal: directory symlinks are no longer followed (no foreign-tree recursion or cycles);
- lane scoping: `docs`/`constitution` check sets are now genuinely disjoint per `VERIFY_SPEC.md` §5.1/§5.2 instead of both running everything.

### Fixed — verification and release machinery

- `.github/workflows/docs-integrity.yml` gains the SHA-pinned checkout step without which no hosted or default-`act` dispatch could ever succeed, plus explicit toolchain-bootstrap notes; still dispatch-only with zero unique logic.
- `scripts/verify.sh`: bare invocation now prints usage and exits 2 instead of silently running the heavyweight `fast` lane; `docs`/`constitution` lanes invoke their scoped check sets.
- `docs/LOCAL_VERIFICATION_AND_RELEASE_PIPELINE.md` lane descriptions match what the lanes actually run (clippy and full workspace tests included; license/layer checks marked not-yet-implemented).
- `ops/dsr/frankengit.yaml.example` uses a placeholder path instead of one developer machine's layout.
- `SECURITY_THREAT_MODEL.md` gains §7.5a: account takeover and interactive authentication lifecycle (credential stuffing, MFA recovery abuse, session hijacking, OAuth/OIDC theft, maintainer ATO) with typed controls — previously the most common real forge compromise vector had no row.

### Added — ambition extensions (proposal-class)

Five capabilities that reuse the existing truth machinery without adding any, each with a comprehensive-plan section, a G4 backlog slice, an `ARCHITECTURE.md` summary, and a README explainer:

- **Verified reads / trustless serving** (plan §18.7, FG-037): Merkle inclusion proofs from any answer to a named authenticated head; mirrors and CDNs become cryptographically incapable of lying.
- **Decision-addressed forge snapshots** (plan §31.8, FG-038): `fg at <decision>` opens the complete forge as of one decision; bisection generalizes from commits to forge state.
- **Cross-organization evidence exchange** (plan §34.8, FG-039): content-addressed evidence packs travel between organizations with claim classes intact; imports tighten but never bypass local checks.
- **Deterministic build-output reuse** (plan §29.8, FG-040): declared-deterministic CI outputs become trust-scoped derived state keyed by exact `BuildInputCapsule` identity — remote-build-cache economics from existing machinery.
- **Mechanized proof of the ordered residue** (plan §40.8, FG-041): machine-checked theorems for the seal/outcome/batch/head core, occupying the top of the claim lattice.

### Added

- This changelog.
- The bead graph (`.beads/`): the FULL doc set converted into an executable, self-documenting task graph via beads_rust (196 beads across gates G0-G6) — first the FG-001..041 seed (137 beads), then a G5 completeness wave (FG-042..065, 32 more beads) closing the gaps a plan-vs-graph audit found: the diff/merge engine FG-029 silently assumed, identity/auth/policy, SSH, APIs/schema codegen, GitHub import, web UI, CLI/doctor, LFS, materialization accelerators, the statistical-policy and claims/evidence frameworks, quotas, crypto/keys, SHA-256 repos, incarnations/migration, packages, federation, hosted operations, and the unhoused open decisions including the launch-blocking license resolution (D14). A final pass mined the supporting docs beyond the plan (normative contracts, verify spec, threat model, agent protocol, ATP/TreeFS/CALM/graph/RaptorQ/object-store profiles, compatibility matrix, registries) for normative machinery and required-v1 rows the plan-derived beads missed — adding G6 (FG-066..086): the merge queue, the cross-cutting security program, the benchmark and toolchain-refresh lanes, CALM/cross-tenant conformance campaigns, verifier-independence and effect-broker machinery, RaptorQ coverage for every MUST class, the scrub scheduler, compaction protocol, temporal graph queries, and the git-notes/submodule conformance slices. A final full-doc sweep mined the four docs earlier waves treated as historical (the FrankenSuite deep-dive synthesis, research provenance, ARCHITECTURE, ADR-0001), adding FG-087..090: the crate-layer checker, the degradation-matrix conformance lane, the shared deterministic worker-budget calculator, and the compatibility-ledger generator that derives the matrix and release claims from executable differential results. Total: 200 beads across G0-G6, acyclic.

## v3 — 2026-08-20 — FrankenSuite deep-synthesis architecture

One commit ([`f3fe619`](https://github.com/Dicklesworthstone/frankengit/commit/f3fe619), 47 files, +12,329/−3,016) integrating the 46-file deep-revision tree produced by a source-level pass across the FrankenSuite (Asupersync/ATP, FrankenSQLite, FrankenFS, FrankenSearch/Quill, franken_markdown, FrankenGraphDB, FrankenNetworkX, Doodlestein Self-Releaser).

**Delivered:**

- **Fundamental architecture correction:** no external relational metadata database co-authoring repository truth, and no leased home cell — canonical state became one immutable decision stream plus one authenticated `RepositoryAuthorityHead` replaced by conditional CAS; FrankenSQLite reassigned to embedded authority profile and local MVCC projections.
- New normative machinery: Git-specialized ATP transport profile (`docs/ATP_GIT_PROFILE.md`), Git TreeFS sparse workspaces (`docs/GIT_TREE_FS.md`), CALM operation registry and obligation-typed effects (`docs/CALM_AND_OBLIGATIONS.md`), typed graph fabric with decision-path witnesses (`docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md`), object-store decision log (`docs/OBJECT_STORE_DECISION_LOG.md`), dependency and memory-safety constitution, local verification/release pipeline, and negative-evidence ledger.
- Nine machine-validated TSV registries under `registries/` and the zero-dependency Rust checker `tools/registry-check` (first compiled and run under the pinned `nightly-2026-08-19` during integration).
- `scripts/verify.sh` lanes (`docs|constitution|fast|full|release`; the dormant `full`/`release` lanes refuse with exit 3 rather than reporting false green), `rust-toolchain.toml` dated-nightly pin, workspace `Cargo.toml`/`Cargo.lock`, and the DSR configuration example.
- The comprehensive plan rewritten to ~53 sections/184 KB (v3.0); superseded Python verifier `scripts/verify_docs.py` removed.

## v2 — 2026-08-19 — Audited first-cut architecture

The bulk of the repository's commit history: the exploratory v1 plan replaced by an audited architecture and a documentation-integrity apparatus.

**Delivered capability:** a spec-first repository whose documents are internally cross-checked and CI-gated.

**Representative commits:**

- [`5cb517c`](https://github.com/Dicklesworthstone/frankengit/commit/5cb517c) — replace exploratory plan with audited architecture v2
- [`78e4878`](https://github.com/Dicklesworthstone/frankengit/commit/78e4878) — define normative protocol contracts
- [`bc7c2aa`](https://github.com/Dicklesworthstone/frankengit/commit/bc7c2aa) — replace verification spec with invariant-linked evidence gates
- [`b05855b`](https://github.com/Dicklesworthstone/frankengit/commit/b05855b) — replace threat model with audited trust-boundary analysis
- [`bc97f16`](https://github.com/Dicklesworthstone/frankengit/commit/bc97f16) — constrain RaptorQ to verified immutable-object repair
- [`50d3b8b`](https://github.com/Dicklesworthstone/frankengit/commit/50d3b8b) — define agent-native protocol with attenuated authority
- [`011f901`](https://github.com/Dicklesworthstone/frankengit/commit/011f901) — record fresh-eyes architecture audit dispositions
- [`6e017c6`](https://github.com/Dicklesworthstone/frankengit/commit/6e017c6) — enforce documentation integrity in CI
- [`41876cc`](https://github.com/Dicklesworthstone/frankengit/commit/41876cc) — restore explicit current license text (source-available, not OSI)

A trailing series of `chore:` commits ([`a401936`](https://github.com/Dicklesworthstone/frankengit/commit/a401936) through [`06275f4`](https://github.com/Dicklesworthstone/frankengit/commit/06275f4)) removed flattened duplicate copies and one-time transfer/bootstrap artifacts, establishing the rule that generated and transfer artifacts stay out of source.

## v1 — 2026-08-19 — Initial publication

- [`1c05cf0`](https://github.com/Dicklesworthstone/frankengit/commit/1c05cf0) — publish the initial FrankenGit architecture and execution plan.

Superseded within the day by v2; retained in history as the starting point the audits measured against.

## Notes for agents

- Truth order when documents disagree: executable checks → `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` → constitutions/registries → ADRs → comprehensive plan → summaries (plan §0.3). This changelog is a summary — the bottom of that hierarchy.
- Start any change by reading `AGENTS.md`, then run `./scripts/verify.sh fast` before and after.
- The issue backlog (`docs/INITIAL_ISSUE_BACKLOG.md`, FG-001..FG-041) is the dependency-ordered work graph; nothing is implemented yet.
- Rejected ideas live in `docs/NEGATIVE_EVIDENCE_LEDGER.md` / `registries/negative_evidence.tsv` — consult them before proposing work in the same area.
