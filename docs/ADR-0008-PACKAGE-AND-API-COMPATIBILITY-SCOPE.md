# ADR-0008: Compatibility Scope Is a Measured Registry, Never a Blanket Claim

- **Status:** **accepted 2026-08-21 by GoldLotus ruling (fg061 comment 1096)**
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (compatibility, packages, API)
- **Scope:** plan decision D12 — Git LFS, OCI, and GitHub REST/GraphQL/Actions subsets
- **Binds:** `frankengit-fg053-lfs-i3h`, `frankengit-fg060-packages-artifacts-76l`, `frankengit-fg090-compat-ledger-u9y9`, `frankengit-fg098-planned-git-compat-l9w4`, `frankengit-fg099-graphql-jaxv`, `frankengit-fg100-package-registries-sbn3`
- **Spec sections:** plan §D12 and §§40–42, `AGENTS.md` §6 (Git rules), §10 (claim rules), `docs/GIT_COMPATIBILITY_MATRIX.md`

## Context

"GitHub-compatible" is the single easiest false claim in this domain. Every surface — LFS, OCI, REST, GraphQL, Actions — is large, versioned, and full of behaviour that only shows up under a real client. A blanket compatibility statement is unfalsifiable marketing; a measured per-endpoint registry is a fact.

## Settled

- Every compatibility surface has a **measured registry row**, generated from executed evidence, not a prose assertion (`AGENTS.md` §10: public quantitative claims must be machine-derived or artifact-linked).
- Unsupported behaviour returns a typed refusal and never a silent partial success (`AGENTS.md` §3.1).
- Differential evidence uses pinned upstream clients in sandboxed non-production lanes (`AGENTS.md` §6).
- The compatibility ledger is generated, so drift between the claim and the behaviour is a lane failure rather than a documentation lapse.

## Remaining choice

The ordering of surfaces and the depth of each subset.

## Decision (proposed)

1. **Order by migration blocking-ness, measured, not assumed.** A surface is prioritised by how often its absence *prevents* a repository from moving, which is an observable property of real migrations rather than a matter of taste.
2. **Collection corpus.** Endpoint and feature usage sampled from three sources: the client traffic a self-hosted instance actually sees; the surfaces a set of real migration attempts touch; and the CI integrations those repositories depend on. Recorded as artifacts.
3. **Interim conservative scope.** Git LFS first, then OCI artifacts. Both are content-addressed, both have narrow well-specified protocols, both block migration outright when missing, and neither requires emulating another vendor's evolving semantics.
4. **Decision threshold for any REST/GraphQL/Actions subset.** An endpoint enters scope only with: a differential test against a pinned real client; a registry row recording exactly which behaviours are covered and which are refused; and a named consumer that is blocked without it. No endpoint is implemented because it is easy.
5. **Revisit trigger.** Usage evidence shows an out-of-scope surface blocking migrations, or an in-scope surface proves unfalsifiable under differential test and must be narrowed.

## Alternatives and why they are rejected

**A. Aim for broad GitHub API compatibility.** Rejected: unbounded, permanently trailing a moving target, and it would force blanket claims `AGENTS.md` §10 forbids.

**B. Implement no vendor-compatible surface; native API only.** Rejected: it makes migration impossible for exactly the users the project targets, and LFS absence blocks repositories mechanically.

**C. Ship a thin passthrough to a real GitHub instance for unimplemented endpoints.** Rejected outright: it is a hidden dependency on the system being replaced and would make a hosted deployment silently leak.

**D. Decide scope from published API popularity.** Rejected as sufficient: popularity is not blocking-ness. A rarely called endpoint that gates every migration outranks a frequently polled one with a native equivalent.

## Evidence required before acceptance

- the usage and migration corpora as committed artifacts;
- for LFS and OCI: differential tests against pinned real clients, including failure and resume paths;
- a generated compatibility ledger whose rows are produced by executed tests, with a planted-drift check proving the generator fails when behaviour and claim diverge;
- for every refusal, a test that the refusal is typed and reaches the client intelligibly.

## Migration and rollback

Scope is additive and each surface is independently deployable. Removing one is deregistration plus a ledger regeneration; the ledger's job is to make the removal visible rather than silent. No canonical state depends on a compatibility surface, so nothing migrates.

## Dependency, target, and unsafe consequences

LFS and OCI are protocol work over the existing artifact fabric and add no dependency by themselves. Any client library considered for differential testing lives in a pinned non-production lane, never in the product path.

## Non-claims

- **FrankenGit does not claim GitHub compatibility.** It claims exactly the rows in the generated ledger, and only for the pinned client versions those rows were measured against.
- No claim that LFS and OCI are sufficient for any given migration.
- The corpora are bounded samples and do not establish behaviour for unobserved clients.

## Supersession rule

A future ADR may reorder or extend scope on usage evidence. It may not introduce a blanket compatibility claim, and it may not admit a passthrough to an external instance.
