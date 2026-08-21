# ADR-0012: WEB-2 — sqlmodel_rust on FrankenSQLite Is the Projection Substrate, and Projections Are Never Authority

- **Status:** **accepted 2026-08-21 by GoldLotus ruling (fg061 comment 1114)**; records a settled adoption; the open items are backend exclusion and admission
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (projections)
- **Scope:** the derived read-model substrate
- **Binds:** `frankengit-fg093a-sqlmodel-admission-cm7y`, `frankengit-fg093b-projection-implementation-b9vp`, `frankengit-fg093c-projection-evidence-5qky`, `frankengit-fg029b-forge-evidence-bkk`
- **Spec sections:** plan §D-WEB and §43.3, `AGENTS.md` §5.1 (routing, local rows and indexes are hints), §3.3, `docs/ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md`

## Context

Forge surfaces need queryable read models: issue lists, PR views, search facets, dashboards. The danger is not the query layer — it is that a convenient, indexed, transactional read model starts being treated as truth, at which point the authority-head decision stream has a competitor.

## Settled, and recorded here rather than reopened

`sqlmodel_rust`, restricted to the `sqlmodel-frankensqlite` backend, is the type-safe substrate for derived projection read-models over FrankenSQLite. The `sqlmodel-sqlite` backend (C `libsqlite3-sys`), `sqlmodel-postgres`, and `sqlmodel-mysql` are **excluded** by the closed dependency universe and must never enter the graph — the first would put a C library on the path `AGENTS.md` §3.1 closes, and the others would add a second storage authority.

## Remaining choice

None on selection. What remains is enforcing the backend exclusion mechanically, and admission.

## Decision (proposed)

1. The substrate is `sqlmodel_rust` with the FrankenSQLite backend only.
2. **Projections are projections.** A row in a projection is a hint (`AGENTS.md` §5.1). No admission, authorisation, GC, or retention decision may read one. Projection lag must never authorise a mutation or a deletion.
3. Every projection carries a **watermark** identifying the decision-stream position it reflects, so a reader can tell how stale it is instead of assuming currency.
4. Projections are **rebuildable from the stream alone**. Deleting every projection and rebuilding must produce identical content; a projection holding state not derivable from the stream is a second authority and is a defect.
5. **Backend exclusion is enforced by the checker**, not by intention. The forbidden backends are unadmitted in the registry, and a planted check proves the lane fails if one appears.
6. **Admission is blocked** until the sibling pins one Asupersync 0.4.x and drops its unpublished absolute FrankenSQLite path patches in favour of an admitted release (plan §43.3).

## Alternatives and why they are rejected

**A. Postgres or MySQL for projections.** Rejected: a second storage authority and an external service dependency for a local-first system.

**B. C SQLite via `libsqlite3-sys`.** Rejected: `AGENTS.md` §3.1 forbids linking a C database library, and FrankenSQLite exists precisely so this is unnecessary.

**C. Hand-rolled queries against FrankenSQLite with no type layer.** Rejected as unnecessary: the type-safe layer prevents a class of query and migration errors, and it is separable if the sibling ever fails admission.

**D. Serve reads directly from the decision stream.** Rejected: it makes every list view a full scan, and the projection exists to make derived reads affordable without making them authoritative.

## Evidence required before acceptance

- registry rows for the substrate and transitives, with the three forbidden backends unadmitted and a planted check proving the lane fails if one enters;
- a rebuild campaign: delete every projection, rebuild from the stream, and compare byte-for-byte;
- watermark and lag campaigns, including a mutation attempted against a stale projection, which must refuse rather than proceed;
- cancellation drills during rebuild that reach quiescence and leave no partial projection visible.

## Migration and rollback

Projections are derived and disposable. Substrate replacement is a rebuild, not a data migration, and rollback is the same. This is a direct consequence of rule 4 — a projection that could not be discarded would also be one that could not be replaced.

## Dependency, target, and unsafe consequences

Admission adds the substrate crates and transitives; each needs a row, and the three excluded backends stay unadmitted. First-party projection code keeps `#![forbid(unsafe_code)]`.

## Non-claims

- No claim that the sibling is currently admissible; the path-patch and runtime prerequisites are blocking.
- No query-performance claim.
- No claim that projections are consistent with the stream at any instant — they are watermarked precisely because they are not.

## Supersession rule

A future ADR may change the substrate. It may not admit a projection as authority, remove the watermark, or admit an excluded backend.
