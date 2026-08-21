# ADR-0006: Search Ships Lexical-First; the Semantic Profile Is Earned by Calibration

- **Status:** proposed
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (search)
- **Scope:** plan decision D10 — local model path, embedding identities, download/offline policy, WASM and server profiles, calibration, privacy, degradation
- **Binds:** `frankengit-fg032-search-kob`, `frankengit-fg032a-search-impl-koh`, `frankengit-fg032b-search-evidence-9gd`, `frankengit-fg032c-search-refinement-jkt7`
- **Spec sections:** plan §D10 and §32, `AGENTS.md` §8 (statistical evidence, regime drift, deterministic fallback), §3.3 (closed dependency universe)

## Context

Semantic retrieval needs a model, and a model brings an artifact identity, a download path, a licence, a calibration story, and a privacy boundary. Each of those is a decision the plan has not made. Lexical, path, and symbol channels need none of them and cover the majority of real repository search.

## Settled

- Exact channels — lexical, path, symbol — are deterministic with named tie-breaks and are the baseline. They are not a fallback bolted on later; they ship first and remain authoritative for ranking determinism.
- Missing support or regime drift selects the deterministic fallback (`AGENTS.md` §8). Degradation is a designed path, not an error.
- Authorisation filters precede disclosure of text, embeddings, neighbours, or aggregates. An embedding is disclosure.
- Statistical evidence binds population, selection, exact sequence window, regime, candidate and fallback, assumptions, and toolchain fingerprint. A ranking claim without those is not admissible.

## Remaining choice

The model path itself, and whether the semantic channel ships in v1 at all.

## Decision (proposed)

1. **Lexical-first is the shipped profile.** The semantic channel is additive and gated; nothing in the progressive protocol may require it to return a correct result.
2. **Collection corpus for the decision.** Query and judgement sets drawn from three sources: real repository navigation traces; a symbol-lookup set where ground truth is mechanical (definition sites); and an adversarial set where lexical and semantic disagree. Judgements are recorded artifacts, not a reviewer's memory.
3. **Interim conservative profile.** No model. Exact channels only, with the progressive protocol shaped so a semantic tier can be added without changing the response contract.
4. **Decision threshold.** A model path is adopted only when it shows a pre-declared retrieval improvement over the exact baseline on the traced and adversarial sets, *and* is pure Rust with no runtime of its own, *and* runs offline with a pinned artifact identity, *and* has a calibrated abstention that selects the deterministic fallback rather than guessing.
5. **Offline by default.** No build-time or first-run download. A model artifact is admitted like any other dependency: pinned identity, recorded licence, audited surface.
6. **Revisit trigger.** Re-open when the adversarial set shows exact channels missing a class of query users actually issue, or when an admissible pure-Rust model path appears that clears the threshold.

## Alternatives and why they are rejected

**A. Ship a semantic channel in v1 with a well-known embedding model.** Rejected: it imports a model artifact, a licence, and usually a native runtime before any evidence that it beats the exact channels on this corpus, and `AGENTS.md` §8 will not accept a ranking claim without calibration.

**B. Call an external embedding service.** Rejected outright: it sends repository content off-box, defeats the offline requirement, and puts an authorisation boundary in someone else's process.

**C. Make the semantic channel mandatory in the progressive protocol.** Rejected: it makes every search depend on the least deterministic component, and turns model absence into an outage.

**D. Defer all search until the model question is settled.** Rejected: the exact channels are independently valuable and unblock four beads.

## Evidence required before acceptance

- the query and judgement sets as committed replayable artifacts;
- exact-channel baseline results with named tie-breaks and a determinism campaign;
- for any candidate model: pinned artifact identity, licence record, pure-Rust and no-second-runtime proof, offline operation, and calibrated abstention behaviour;
- a privacy analysis showing authorisation precedes embedding disclosure;
- degradation evidence: with the model absent, corrupt, and mid-generation-swap.

## Migration and rollback

The semantic tier is a separate generation with its own manifest. Adding it activates a generation; removing it deactivates one. No exact-channel index is rewritten either way, so rollback is deactivation rather than reindexing.

## Dependency, target, and unsafe consequences

Today: none — the interim profile adds no dependency. Any future model path needs registry rows for itself and its transitives, must be pure Rust, and must not require a first-party unsafe relaxation. A WASM profile inherits the same rule; wasm-bindgen-generated unsafe is transitive surface to be pinned and ledgered, never a first-party exception.

## Non-claims

- No claim that exact channels are sufficient for all retrieval needs. The claim is that they are sufficient to ship and that they are deterministic.
- No claim about any specific model's quality; none has been measured on this corpus.
- No relevance or latency claim is made by this ADR at all.

## Supersession rule

A future ADR may adopt a model path once the threshold evidence exists. It may not make the semantic channel load-bearing for correctness, and it may not introduce a network dependency at query time.
