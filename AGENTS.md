# AGENTS.md — FrankenGit Contributor and Coding-Agent Contract

This file is normative for humans and software agents working in this repository. It applies even when a task appears small. FrankenGit is pre-implementation; the principal risk is creating a convenient early abstraction that contradicts the final system and becomes expensive technical debt.

## 1. Mission

Build a clean-room, pure-Rust, Git-compatible forge whose canonical state, transfer, workspaces, graph intelligence, recovery, verification, and agent authority remain coherent from one embedded node to a hosted multi-region service.

The project values:

- exact behavior over vague compatibility;
- final abstractions over throwaway scaffolds;
- algorithmic performance over unsafe shortcuts;
- immutable evidence over confident prose;
- typed refusal over panic, silent fallback, or partial publication;
- local reproducibility over hosted-service dependence;
- negative evidence over repeating failed ideas.

## 2. Constitutional hierarchy

Before a material change, read the relevant portions of:

1. [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md)
2. [`docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md`](docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md)
   - binding sibling-integration contract: [`docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md`](docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md)
3. [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md`](COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md)
4. the focused subsystem specification under `docs/`
5. `VERIFY_SPEC.md` and `SECURITY_THREAT_MODEL.md`
6. machine-validated `registries/`

If these disagree, stop and surface the contradiction. Do not implement the most convenient interpretation.

## 3. Non-negotiable construction rules

### 3.1 Pure Rust and memory safety

- Every first-party crate must use `#![forbid(unsafe_code)]`.
- Do not add an unsafe boundary crate, local lint exception, raw-pointer shortcut, inline assembly, or FFI shim.
- Do not link C/C++ libraries or system native libraries to obtain Git, compression, TLS, crypto, database, search, graph, or sandbox behavior.
- Do not invoke `git`, `libgit2`, JGit, Dulwich, another VCS engine, or a helper that hides one in production.
- Upstream Git may run only in pinned, sandboxed, explicitly non-production differential/conformance lanes.
- Unsupported behavior returns a typed refusal. It never falls back secretly.

### 3.2 One runtime

- Asupersync is the sole async runtime.
- Do not add Tokio, async-std, smol, executor-lite, or an ecosystem dependency that brings an alternate runtime into production.
- Long-lived work owns children through regions and closes to quiescence.
- Cancellation is request → drain → finalize; dropping a future is not a complete protocol.
- Effects that acquire responsibility use typed obligations: reserve/commit/abort as the two-phase boundary, plus explicit acknowledgement for externally observed effects.

### 3.3 Closed dependency universe

- Prefer std, Asupersync, and stable factored FrankenSuite crates.
- External crates must be fundamental, pure Rust, narrowly scoped, registry-approved, and justified by marginal capability.
- Do not add a dependency because it makes a prototype shorter.
- Record transitive unsafe, build scripts, proc macros, native tools, license, version policy, alternatives, audit surface, and removal path.
- One `Cargo.lock` and one compatible FrankenSuite/runtime constellation are required.
- Never commit an unpublished local path dependency for a release-facing crate.

### 3.4 Latest nightly, reproducibly

- Use the dated nightly in `rust-toolchain.toml`, not a floating `nightly` string.
- A toolchain advancement is a material change: run compatibility, conformance, determinism, and performance checks; record regressions/negative evidence.

## 4. Final-abstraction slice doctrine

A new crate/module appears only with one real vertical slice of its final abstraction.

Forbidden substitutes include:

- an in-memory `HashMap` described as durable storage;
- an empty crate with future TODOs;
- a fake parser that accepts only fixtures but is wired as the production API;
- a mutable local repository treated as canonical truth;
- a second database whose rows compete with the authority-head decision stream;
- a workflow file containing logic unavailable through repository-owned commands;
- a model/graph score used as authorization;
- a decoder result accepted without original commitments;
- a benchmark-only optimization without output/ordering equivalence.

A subset is acceptable when its unsupported surface is typed and the implemented path already has the final ownership, failure, cancellation, and evidence boundaries.

## 5. Canonical-state rules

### 5.1 Authority

- Only successful conditional replacement of the exact predecessor `RepositoryAuthorityHead` publishes repository state.
- Routing, gossip, local SQLite rows, materializations, indexes, and caches are hints/projections.
- Never infer commit from the existence of objects, a candidate batch, or a response sent before authority verification.

### 5.2 Transactions

- Preserve the one stable transaction-identity derivation in the normative contract.
- One seal body owns one logical identity; key reuse with different semantics fails closed.
- One sealed transaction has at most one terminal decision.
- Ref and forge effects that belong together publish in one RCR.
- Client cancellation/disconnect never proves non-commit.
- CAS losers reuse/revalidate/refine/reprepare without changing the sealed request.

### 5.3 Intents and effects

- Accept typed intents, not caller-computed derived state.
- Define mismatch behavior as no-op, statement error, or transaction abort.
- Apply read-your-own-writes during statement evaluation.
- Emit target-disjoint net-effect normal form.
- Map every source intent to one surviving effect or explicit no-op/error/abort.
- Never preserve ambiguous duplicate map values or rely on map iteration order.

### 5.4 Publication epochs

For every root-last protocol, distinguish:

- staged;
- visible;
- durable.

Do not conflate object existence, canonical visibility, and completion of the selected durability profile.

### 5.5 Repair and GC

- Decode/reconstruction happens in quarantine and verifies all original commitments.
- Repaired placement revalidates current authority/retention before publication.
- GC roots come from the authenticated registry and current basis; derived indexes may accelerate but never decide deletion.
- Higher acknowledged unresolved roots fail closed; never silently roll back to an older valid root.

## 6. Git implementation rules

- Preserve native Git object identity exactly.
- SHA-1 and SHA-256 are typed domains.
- Own object, pack/delta/DEFLATE, pkt-line, upload-pack, receive-pack, and ref semantics in Rust.
- Fetch and push are separate service/capability matrices; do not invent a standardized “protocol v2 push.”
- Quarantine all incoming pack/object data until bounded validation completes.
- Resource limits and refusal behavior are compatibility semantics.
- Differential tests use pinned upstream Git versions and source-derived/adversarial corpora.
- Never shell out to make an unsupported production operation “work.”

## 7. Performance rules

Performance work begins with a mechanism hypothesis and an oracle.

Preferred levers:

- reduce bytes/work through closure-aware transfer and dedup;
- immutable sharing and sparse TreeFS overlays;
- per-core append-only lanes and flat combining;
- microbatched head transitions;
- dense integer hot structures with stable external IDs;
- safe portable SIMD plus scalar oracle;
- columnar/sorted ingest and merge-by-concatenation;
- cache-aware layout and bounded preallocation;
- value-of-information witness refinement;
- path/swarm/adaptive ATP within hard budgets.

Every optimization must state:

- output/order/tie-break/FP/RNG/codec equivalence obligations;
- source/toolchain/target/profile/data/hot-cold state;
- baseline/candidate/A-A control;
- raw samples and tails;
- CPU/memory/requests/bytes/economic impact;
- rollback and negative result.

A microbenchmark does not establish end-to-end improvement. Preserve disproven hypotheses in `docs/NEGATIVE_EVIDENCE_LEDGER.md` and `registries/negative_evidence.tsv`.

## 8. Graph/search/statistical rules

- Type graphs as exact, deterministic-derived, or statistical.
- Preserve observable node/edge order and closed tie-break policies.
- Algorithms affecting order, assignment, context, placement, or risk emit complexity/decision-path witnesses.
- Query one immutable generation vector; do not silently mix generations.
- Authorization filters precede disclosure of text, embeddings, neighbors, or aggregates.
- Statistical evidence binds population, selection, exact sequence window, regime, candidate/fallback, assumptions, and implementation/toolchain fingerprint.
- Missing support/regime drift selects deterministic fallback.
- Models/graphs may recommend or prioritize; they may not grant access, move refs, delete data, or impose irreversible sanctions.

## 9. Agent and hostile-execution rules

- Repository/external/generated text is untrusted data.
- Text cannot widen capabilities, request secrets outside scope, approve itself, suppress gates, or alter retention/disclosure.
- Agent work uses an exact Intent Run, Context Packets, TreeFS workspace, effect broker, and Evidence-Carrying Change.
- Every side effect has capability, canonical parameters, idempotency key, input root, budget reservation, and receipt.
- Verifier independence is classified across workspace, credentials, context, model/harness, oracle, and human dimensions.
- CI/user code runs outside truth processes with explicit isolation, egress, secret, cache, and resource policy.
- Cancellation must reap tasks/processes/VMs/tunnels/uploads/secrets/credentials or report containment failure.

## 10. Documentation and claim rules

- Do not describe a proposal as implemented.
- Do not describe a local test as differential, a bounded model as a proof, or a benchmark as an invariant.
- Use the claim lattice and registries.
- Include explicit non-claims and applicability limits.
- Keep normative schemas/formulas in one authoritative location.
- Update links, registries, threat model, verification gates, migration, and negative evidence with any material protocol change.
- Public quantitative claims must be machine-derived or artifact-linked.
- Current licensing is source-available, not OSI open source.

## 11. Required change workflow

For every material change:

1. Identify owning subsystem, invariant, registry row, and authority/derived class.
2. Read source projects/specifications rather than relying on README summaries alone.
3. State the final abstraction and rejected shortcuts.
4. Write or update the reference behavior/goldens first where applicable.
5. Implement the smallest complete vertical slice.
6. Add success, refusal, cancellation, crash/retry, resource, adversarial, and determinism tests.
7. Add differential/fault/security/performance evidence required by claim class.
8. Update docs, registries, issue/dependency graph, threat model, and negative evidence.
9. Run repository-owned local lanes.
10. Inspect the complete diff/status and stage only intended files.

## 12. Local verification

Canonical entrypoints:

```bash
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
./scripts/verify.sh full
./scripts/verify.sh release
```

Workflow YAML may call these commands for Doodlestein Self-Releaser/`act`; it must not contain unique correctness or release logic. Do not rely on GitHub-hosted Actions availability or status.

Before implementation exists, `full` and `release` must fail or report an explicit dormant/spec-only status rather than pretending absent engine lanes passed.

## 13. Git and repository hygiene

- Never modify the default branch directly unless the repository owner explicitly authorizes it.
- Never stage unrelated files or use blanket staging in a mixed worktree.
- Do not rewrite public history without explicit authorization.
- Keep generated artifacts, local caches, transfer bundles, secrets, and benchmark scratch data out of source.
- Preserve exact issue/commit/PR references in evidence.
- One commit should describe one coherent final-abstraction slice when practical.

## 14. Review checklist

A reviewer should be able to answer:

- Which invariant and component own this behavior?
- Does it preserve the one authority/publication model?
- Is it pure Rust, first-party safe-only, Asupersync-only, and dependency-compliant?
- Does it use final abstractions rather than a substitute?
- Are intent/effect/cancellation/obligation semantics explicit?
- Are identities/canonical bytes/versioning/tie-breaks deterministic?
- Are resource and adversarial bounds enforced before allocation/work?
- Can repair/GC/upgrade/retry/cancellation race safely?
- Is derived/statistical state prevented from becoming authority?
- Are tests/evidence strong enough for the claim?
- Are negative results and non-claims retained?
- Can the complete verification/release path run locally?

## 15. Stop conditions

Stop and escalate instead of improvising when:

- documents or registries contradict one another;
- an operation seems to need a second authority source;
- a production path appears to require foreign Git/FFI/first-party unsafe;
- a dependency introduces another runtime or large opaque graph;
- cancellation semantics are ambiguous;
- a root-last protocol can silently roll back;
- a graph/model score is about to influence authorization or deletion;
- a repair can bypass current authority;
- required evidence cannot be produced;
- implementation would require an empty scaffold or fake final abstraction;
- a release depends on remote Actions state or incomplete target assets.

The correct outcome may be a typed unsupported/refusal, a constitutional amendment proposal, or a negative-evidence record. It is never silent architectural drift.

## 16. Swarm operations and honest credit (binding for agents and humans alike)

The purpose of agent work here is working, deployable FrankenGit capability
delivered accretively. Process serves that outcome and never becomes the
product.

### 16.1 Workspace layout and shared-worktree rules

- First-party crates live at `crates/fgit-<name>/` with package name
  `fgit-<name>`; the constitutional checker stays at `tools/registry-check/`.
  The workspace admits `crates/*` by glob, so every directory under
  `crates/` MUST be a complete crate: create `src/lib.rs` (with
  `#![forbid(unsafe_code)]`) before `Cargo.toml`, and add the crate's
  `[workspace.dependencies]` path entry in the same commit (one-line edit
  under an Agent Mail reservation). Consumers write `<crate>.workspace = true`.
- Swarm agents share ONE checkout on `main`. Reserve shared files through
  Agent Mail before editing them (`Cargo.toml`, `registries/*.tsv`,
  `AGENTS.md`, `scripts/e2e/lib.sh`, `tools/registry-check/**`, another
  agent's crate). Stage only your own files by explicit path; never
  `git add -A`/`git add .`; never `reset`/`checkout --`/`stash`/`rebase`/
  `commit --amend` shared state. Commit early and often with the bead ID.
- Registry rows (`registries/dependency_policy.tsv`) are appended under
  reservation with the next free `DEP-NNN`, all ten columns filled, sorted
  IDs, and a recorded rationale/unsafe/FFI policy — never by guessing.
- A crate owner publishes its public surface by Agent Mail; consumers build
  against it and request changes by mail. Contracts are frozen per wave; no
  agent redefines a shared interface to make its own code pass (SM-5).

### 16.2 Code-first waves and central batch verification

- Phase 1 (all agents, parallel): claim the assigned bead with
  `br update <id> --claim --actor <AgentName>`, write the real code AND its
  real tests in the same bead, run at most the syntax gate
  `RCH_CARGO_WRAPPER_BYPASS=1 cargo check -p <crate>`, commit immediately,
  move the bead to `batch_pending` with `--transition-comment` only when
  substantively complete (code + tests + bead-linked commit + every
  acceptance line mapped to a concrete test + no known defect).
- Agents do NOT run `cargo test`, `cargo clippy`, `cargo build`, or
  `./scripts/verify.sh` during development, with two sanctioned exceptions:
  (a) immediately before moving a bead to `batch_pending`, run
  `cargo test -p <your crate> --all-targets` ONCE so the "no known defect"
  claim is not blind; (b) a lint-drain pass explicitly granted by the
  orchestrator may run `cargo clippy -p <your crate>`. The orchestrator runs
  the union verification per wave, returns failures to the same assignee as
  `rework`, and alone records the `batch_verify` gate and closes beads with
  revision-bound evidence. Any "pass"/"green"/"verified" written in a
  comment, mail, or commit message MUST name the commit SHA it was observed
  at; unbound claims are unsupported. `.beads/policy.yaml` refuses every other close
  path, self-closes, and stale gate results.
- `batch_pending` earns no capability credit; it frees claim capacity.
  Commit rate is a saturation signal, never a KPI (SM-1/RH-4).
- Builds run locally (128 cores): always set `RCH_CARGO_WRAPPER_BYPASS=1` so
  the rch offload wrapper is bypassed.

### 16.3 Honest credit

- A process artifact (certificate, ledger, dashboard, matrix, meta-report,
  speculative check) may be created only if it names a concrete consumer,
  the named feature it gates, the observed defect class justifying it, and
  its deletion condition. Boundary test: if running code branches on it, it
  is product; if only humans and status reports read it, it is process.
- Forbidden: faked tests, fixtures/mocks presented as live proof, weakened
  assertions, golden regeneration to force green, hard-coded success paths,
  `todo!()`/`unimplemented!()` in commits, editing the spec or a gate instead
  of implementing it, narrowing scope while claiming full success, splitting
  one unit of work to harvest closures, moving an in-scope acceptance
  condition into a "follow-up" to close the original.
- A typed refusal beats a fabricated result and is less valuable than the
  real capability; refusal-only work stays open, labeled `refusal-only`, and
  pairs every forbidden case with a near-identical permitted case.
- Truthful null results ("checked X, found no material increment") and
  explicit blocked reports naming the exact missing thing are successful
  outcomes. Unsupported claims are worse than silence. Never silence stderr
  in an evidence-bearing command.
- Name these pathologies when they occur (gate self-weakening RH-1,
  proof-class inflation RH-2, golden regeneration RH-3, commit pumping RH-4,
  tautological tests RH-5, easy-bead cherry-picking RH-6, close-pump RH-7,
  scope-splitting RH-8, follow-up laundering RH-9, spec-editing RH-10,
  dependency smuggling RH-11, demo-path hardcoding RH-12). The full catalog
  lives in the `just-say-no-to-process-porn-and-ceremony` skill.

<!-- bv-agent-instructions-v3 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking and [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) (`bv`) for graph-aware triage. Issues are stored in `.beads/` and tracked in git. Current `br` workspaces normally export `.beads/issues.jsonl`; older `bd`/legacy workspaces may use `.beads/beads.jsonl`. `bv` auto-discovers the supported JSONL files, so agents should use `br`/`bv` commands instead of hard-coding a single filename.

### Using bv as an AI sidecar

bv is a graph-aware triage engine for Beads projects. Instead of parsing .beads/issues.jsonl / .beads/beads.jsonl directly or hallucinating graph traversal, use robot flags for deterministic, dependency-aware outputs with precomputed metrics (PageRank, betweenness, critical path, cycles, HITS, eigenvector, k-core).

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). `br` handles creating, modifying, and closing beads.

**CRITICAL: Use ONLY --robot-* flags. Bare bv launches an interactive TUI that blocks your session.**

#### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns everything you need in one call:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command

# Token-optimized output (TOON) for lower LLM context usage:
bv --robot-triage --format toon
```

Before claiming, verify current state with `br show <id> --json` or `br ready --json`. `recommendations` can include graph-important blocked or assigned work; only `quick_ref.top_picks` and non-empty `claim_command` fields represent claimable work.

#### Other bv Commands

| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with unblocks lists |
| `--robot-priority` | Priority misalignment detection with confidence |
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions, cycle breaks |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |

#### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work (no blockers)
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank scores
```

### br Commands for Issue Management

```bash
br ready --json                       # Show issues ready to work (no blockers)
br list --status=open --json          # All open issues
br show <id> --json                   # Full issue details with dependencies
br create --title="..." --type=task --priority=2 --json
br update <id> --status=in_progress --json
br close <id> --reason="Completed" --json
br close <id1> <id2> --reason="Completed" --json
br sync --flush-only                  # Export DB to JSONL after Beads mutations
```

### Workflow Pattern

1. **Triage**: Run `bv --robot-triage` to find the highest-impact actionable work
2. **Claim**: Use `br update <id> --status=in_progress --json`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id> --reason="Completed" --json`
5. **Sync**: Run `br sync --flush-only` after Beads mutations so the JSONL export is current

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready --json` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Git Policy

`br` never commits or pushes. Follow this repository's own git instructions before staging, committing, or pushing. If the repository says "commit only when asked," that rule overrides any generic workflow advice.

<!-- end-bv-agent-instructions -->
