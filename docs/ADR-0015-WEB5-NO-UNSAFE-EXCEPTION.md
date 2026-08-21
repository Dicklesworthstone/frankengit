# ADR-0015: WEB-5 — There Is No First-Party Unsafe Exception, Including for WASM

- **Status:** **accepted 2026-08-21 by GoldLotus ruling (fg061 comment 1114)**; records a settled constitutional position and the mechanism that enforces it
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture
- **Scope:** first-party unsafe policy across native and WebAssembly targets, and the sibling convergence prerequisite that gates every WEB adoption
- **Binds:** `frankengit-fg048c-fastapi-admission-hogb`, `frankengit-fg093a-sqlmodel-admission-cm7y`, `frankengit-fg094a-ftui-admission-xxnu`, `frankengit-fg050-web-ui-5pt`
- **Spec sections:** `AGENTS.md` §3.1 (every first-party crate forbids unsafe; no local lint exception), §3.3, plan §D-WEB and §43.3, `docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md`

## Context

`wasm-bindgen` and every Rust web framework built on it emit `unsafe` in generated glue, and the usual accommodation is a crate-level relaxation in the crate that hosts the generated code. That relaxation is small, local, and looks harmless — and it is the exact shape of the exception that ends the rule, because once one first-party crate carries it, "does first-party code forbid unsafe?" stops having a yes-or-no answer.

The distinction that makes the rule survivable is not about how much unsafe exists. It is about **who owns it**.

## Settled, and recorded here rather than reopened

- **Every** first-party crate declares `#![forbid(unsafe_code)]`, native and WASM alike. There is no target-conditional exemption, no "generated code" exemption, and no per-crate waiver.
- `wasm-bindgen` and framework-generated or framework-linked unsafe is **transitive dependency surface**. It must be pinned, expanded where practicable, audited, and ledgered — the same treatment any other external unsafe receives.
- If integrating a sibling **requires** a first-party lint relaxation, that blocks integration and the correction belongs upstream. The project waits; it does not carve an exception.
- All adopted siblings must first converge in their owned upstream repositories on one Asupersync 0.4.x and registry-resolvable FrankenSQLite sources. This is a blocking integration prerequisite, not a framework-selection question.

## Remaining choice

None on policy. What remains is the mechanism, and mechanism is the whole difficulty: a rule enforced by intention is not enforced.

## Decision (proposed)

1. **Machine-checked, not reviewed.** The constitution checker already refuses a missing `#![forbid(unsafe_code)]` in a crate root and refuses `#[allow(unsafe_code)]` anywhere in first-party source. That check is the enforcement; this ADR records that it must remain and must cover WASM crates identically.
2. **A planted check proves the checker bites.** A fixture carrying a first-party unsafe exception must make the lane fail. A gate nobody has watched fail is not known to work — this project has already found two checkers this session that passed only because they were never tested against the thing they claimed to catch.
3. **Generated unsafe is ledgered per admitted crate**: enabled features, reachability, expansion where practicable, soundness or advisory evidence, owner, containment, and removal path.
4. **The sibling convergence prerequisite is recorded on each admission bead** so a blocked adoption is visible in the graph rather than remembered.
5. **The escape hatch is explicit and narrow**: a constitutional amendment through `AGENTS.md`, argued in the open. Not a crate attribute, not a build flag, not a target-conditional.

## Alternatives and why they are rejected

**A. Allow a first-party unsafe exception for WASM glue crates.** Rejected: it is the exception that ends the rule. The generated code is not first-party work, and treating it as dependency surface costs nothing and keeps the invariant answerable.

**B. Vendor and hand-audit the generated glue as first-party code.** Rejected: it converts external generated code into first-party code the project must then own and re-audit on every regeneration, which is more unsafe under our name, not less.

**C. Avoid WASM entirely to avoid the question.** Rejected: it would forfeit the in-browser verified read, which is the reason the substrate is shared in the first place.

**D. Rely on review to catch relaxations.** Rejected: sixteen agents, a shared index, and a fast wave. Review has already missed things this session that a checker caught immediately.

## Evidence required before acceptance

- the planted-exception fixture and a demonstration that the lane fails on it;
- confirmation that the checker's crate-root scan covers WASM crate roots on the same terms;
- an unsafe ledger populated for at least one admitted framework, showing the treatment is real rather than described;
- for each WEB adoption, the sibling's `Cargo.lock` closed-world scan showing exactly one runtime and registry-resolvable sources.

## Migration and rollback

None. This records an existing constitutional position and the mechanism that enforces it. If an amendment ever relaxes it, that amendment carries its own migration and its own argument, in the open.

## Dependency, target, and unsafe consequences

This is the decision that governs the others: it narrows what may be admitted and makes admission of an unsafe-requiring sibling impossible without an amendment. Its cost is honestly a slower path to a web UI, and that cost is accepted rather than hidden.

## Non-claims

- No claim that FrankenGit contains no unsafe code. It contains unsafe **transitively**, in dependencies, and the ledger exists to make that visible rather than to pretend otherwise.
- No claim that `#![forbid(unsafe_code)]` makes first-party code correct; it removes one class of defect, not logic, protocol, or authorisation bugs (`docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §31).
- No claim that the current siblings can meet this bar. Whether they can is exactly what the admission beads must establish.

## Supersession rule

Only a constitutional amendment to `AGENTS.md` §3.1 may supersede this, argued in the open with its blast radius stated. An implementation shortcut, a build flag, or a target-conditional attribute cannot.
