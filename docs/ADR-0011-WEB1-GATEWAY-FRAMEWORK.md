# ADR-0011: WEB-1 — fastapi_rust Is the Gateway and API Framework

- **Status:** proposed (records a settled adoption; the open item is its admission prerequisite)
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (gateway, API)
- **Scope:** the HTTP gateway and typed API framework
- **Binds:** `frankengit-fg048c-fastapi-admission-hogb`, `frankengit-fg096b-mcp-server-kr90`
- **Spec sections:** plan §D-WEB and §43.3, `AGENTS.md` §3.2 (one runtime), §3.3 (closed dependency universe), `docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md`

## Context

The gateway terminates untrusted network input for smart HTTP, the native API, and the web surface. Framework choice therefore decides which runtime the hostile-input path runs on, and a framework carrying its own executor would end the one-runtime rule at the first request.

## Settled, and recorded here rather than reopened

`fastapi_rust` is the gateway and API framework. It is pure Rust, Asupersync-native rather than Tokio-based, and generates OpenAPI that feeds the schema registry — so the published contract is derived from the code instead of maintained beside it. The considered alternative was a fully owned gateway; it was rejected because it would re-implement routing, extraction, and OpenAPI generation with no invariant gain, and because a first-party gateway is not more auditable than a pinned sibling that already satisfies the runtime rule.

## Remaining choice

None on selection. What remains is **admission**, which is a real prerequisite and not a formality.

## Decision (proposed)

1. The framework is `fastapi_rust`. This ADR records that, and the choice is not reopened absent new evidence about the runtime contract.
2. **Admission is blocked** until the sibling converges on the single selected Asupersync 0.4.x contract and resolves to registry-resolvable sources. The reviewed revision targets Asupersync 0.3.x; cargo resolving two runtime versions is a failure, not reconciliation (plan §43.3).
3. Generated OpenAPI is an **output**, never an authority. The schema registry consumes it; no admission or authorisation decision reads it.
4. The gateway holds no canonical state. It terminates transport and calls the authority path; it never becomes a second writer.

## Alternatives and why they are rejected

**A. A Tokio-based framework.** Rejected: two runtimes in one process, forbidden by `AGENTS.md` §3.2, and the hostile-input path is the worst place to hold that contradiction.

**B. A fully owned gateway.** Rejected: substantial re-implementation for no invariant gain. Reconsidered only if the sibling cannot converge on the runtime contract.

**C. Adopt now and patch the runtime locally.** Rejected: a local patch is an unpublished path dependency for a release-facing crate, which `AGENTS.md` §3.3 forbids, and it forks a sibling the project does not own.

## Evidence required before acceptance

- the sibling pinned to the selected Asupersync 0.4.x with a `Cargo.lock` closed-world scan showing exactly one runtime;
- registry rows for the framework and every transitive, with unsafe, build-script, proc-macro, and FFI policy recorded;
- an admission campaign covering hostile framing, oversize bodies, slow clients, and cancellation reaping through the framework;
- proof that generated OpenAPI never participates in an authorisation decision.

## Migration and rollback

The gateway is a leaf. Replacement means re-implementing routing behind the same typed API surface, with no change to canonical state. Rollback from admission is deregistration; the API contract is owned by the schema registry, not by the framework.

## Dependency, target, and unsafe consequences

Admission adds the framework and its transitives to the closed universe; each needs a row. First-party gateway code keeps `#![forbid(unsafe_code)]`. A framework requiring a first-party unsafe relaxation is not admissible — see `docs/ADR-0015-WEB5-NO-UNSAFE-EXCEPTION.md`.

## Non-claims

- No claim that the sibling is currently admissible. It is not, and the prerequisite is stated as blocking.
- No performance claim relative to any other framework.
- No claim that generated OpenAPI is complete or that it constitutes a compatibility guarantee.

## Supersession rule

A future ADR may replace the framework if the runtime contract cannot be met. It may not admit a second runtime, and it may not make generated schema authoritative.
