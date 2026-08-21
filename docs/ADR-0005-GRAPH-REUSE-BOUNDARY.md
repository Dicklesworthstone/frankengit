# ADR-0005: The Graph Reuse Boundary Is Drawn at the Type and Runtime Universe, Not at Convenience

- **Status:** proposed
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (graph fabric)
- **Scope:** plan decision D9 — which FrankenGraphDB / FrankenNetworkX surfaces are consumed directly and which mechanisms are ported
- **Binds:** `frankengit-fg031-graph-fabric-zhd`, `frankengit-fg031a-graph-impl-j7x`, `frankengit-fg031b-graph-evidence-ndf`, `frankengit-fg032c-search-refinement-jkt7`
- **Spec sections:** plan §D9, §6.6 and §43.3 (sibling reuse), `AGENTS.md` §3.2 (one runtime), §3.3 (closed dependency universe), §8 (graph/search/statistical rules)

## Context

FrankenGraphDB and FrankenNetworkX contain mechanisms FrankenGit genuinely needs: temporal streams, generation roots, deterministic traversal with closed tie-breaks, and evidence-governed adaptation. Consuming them wholesale is attractive and is also how a second runtime, a second identity family, or a second notion of "current generation" enters the system without anyone deciding to admit one.

## Settled

- One runtime universe. A sibling that pulls a second async runtime is not consumable at any convenience level (`AGENTS.md` §3.2).
- One version universe. Queries read a single immutable generation vector; nothing may silently mix generations (`AGENTS.md` §8, plan §6.4).
- Observable node and edge order is part of the contract, with closed tie-breaks. A reused algorithm that does not pin its order is not reusable as-is.
- A graph score may recommend or prioritise. It may never grant access, move a ref, delete data, or impose a sanction (`AGENTS.md` §8).

## Remaining choice

Which specific crates cross the boundary as dependencies, and which mechanisms are re-implemented inside `fgit-graph`.

## Decision (proposed)

Draw the boundary by **what the surface commits us to**, not by how much code it saves:

1. **Consume directly** a sibling surface only when all four hold: it is pure Rust with no runtime of its own; its types do not become part of FrankenGit's canonical bytes or identities; its observable ordering is specified and testable; and its version can be pinned into the single constellation.
2. **Port the mechanism** when the surface would otherwise place sibling types inside a canonical body, an identity, or a persisted generation manifest. Canonical shapes are `fgit-codec`'s and `fgit-types`' to own; a sibling type reaching a durable format is a schema owned by someone outside this repository.
3. **Never consume** anything that supplies its own executor, its own storage authority, or its own notion of a current generation.
4. Any consumed surface is wrapped behind a `fgit-graph` trait, so admission is one edit and removal is one edit. A sibling API appearing directly in a consumer crate's signatures is a boundary violation regardless of how convenient it is.

## Alternatives and why they are rejected

**A. Consume the sibling graph stack wholesale.** Rejected: it imports a second generation authority and a second identity family into durable state, and plan §6.4 permits exactly one.

**B. Port everything; depend on nothing.** Rejected: it discards audited, deterministic algorithm work for no invariant gain, and re-implementation is where ordering and tie-break bugs are actually born.

**C. Decide crate by crate as implementation proceeds, without a written rule.** Rejected: that is how the boundary erodes. Each individual call looks reasonable; the aggregate is a second universe.

**D. Wrap everything behind traits and consume freely.** Rejected as insufficient: a trait hides the API but not the runtime, the identity family, or the persisted schema. The wrapper is necessary, not sufficient.

## Evidence required before acceptance

- the exact crate list, pinned, with each entry justified against the four consumption conditions;
- a `Cargo.lock` closed-world scan showing no second runtime and no unadmitted transitive;
- determinism campaigns proving observable order and tie-breaks are stable across the pinned versions;
- a demonstration that no sibling type appears in any canonical body, identity, or generation manifest;
- an authority-safety campaign showing a graph result cannot move a ref, delete data, or widen access.

## Migration and rollback

Every consumed surface sits behind a `fgit-graph` trait, so replacing a sibling with a port is a single implementation swap with no change to consumers. Rollback is the same operation in reverse. Because sibling types are excluded from durable formats by construction, neither direction is a data migration.

## Dependency, target, and unsafe consequences

Each admitted crate needs an active row in `registries/dependency_policy.tsv` covering it and its transitives, with unsafe and FFI policy recorded. First-party wrappers keep `#![forbid(unsafe_code)]`. Any sibling requiring a lint relaxation is not admissible; the correction belongs upstream.

## Non-claims

- This ADR does not name the crates. It names the test a crate must pass, and deliberately stops there.
- No claim is made that the sibling implementations are correct; admission requires our own determinism evidence, not theirs.
- No performance claim either way between consuming and porting.

## Supersession rule

A future ADR may name the crate list. It may not relax the four consumption conditions, and it may not admit a surface whose types reach a canonical body.
