# ADR-0014: WEB-4 — FrankenTUI Owns the Terminal Surface and an Optional Web Skin, Never the Primary UI

- **Status:** **accepted 2026-08-21 by GoldLotus ruling (fg061 comment 1114)**; records a settled scope boundary
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (TUI)
- **Scope:** the terminal operator and agent surface, and the optional terminal-style web skin
- **Binds:** `frankengit-fg094a-ftui-admission-xxnu`, `frankengit-fg094b-tui-implementation-pa34`
- **Spec sections:** plan §D-WEB and §43.2, `AGENTS.md` §3.2, §3.3

## Context

`frankentui` is a mature pure-Rust terminal UI kernel with an `asupersync-executor` feature and a WASM backend. That WASM backend is the hazard: it makes a terminal-style web surface easy, and "easy" is how a terminal aesthetic becomes the primary interface for users who never asked for one.

## Settled, and recorded here rather than reopened

- `frankentui` is the kernel for `fgit-tui`, the operator, agent, and SSH console.
- Its WASM backend **may** additionally serve a parallel terminal-style web surface as an **alternate**.
- It is explicitly **not** the primary web UI, which is a conventional real-DOM app (`docs/ADR-0013-WEB3-PRIMARY-WEB-UI.md`).
- The ftui demo and showcase crates, and their transitive Tokio, are **excluded**.

## Remaining choice

None on scope. What remains is admission and mechanical enforcement of the exclusions.

## Decision (proposed)

1. `fgit-tui` is built on the `frankentui` kernel crates with the `asupersync-executor` feature.
2. **The demo and showcase crates are unadmitted**, and their exclusion is enforced by the registry rather than by discipline — they carry transitive Tokio, and admitting them would end the one-runtime rule sideways.
3. The terminal-style web skin, if built, is an **alternate surface**. Nothing in the product may route a default user to it, and no capability may exist only there.
4. **The TUI is a client.** It holds no canonical state and gets no privileged path; it calls the same API as any other surface. An operator console is exactly where a convenience back door would otherwise appear.
5. **Admission is blocked** until the sibling converges on the selected Asupersync 0.4.x (plan §43.3).

## Alternatives and why they are rejected

**A. Terminal-style web surface as the primary UI.** Rejected: it fails the accessibility, selection, and SEO requirements that decided WEB-3, for an aesthetic most users did not choose.

**B. Build the TUI on a different terminal kernel.** Rejected: `frankentui` already satisfies the runtime rule and is pure Rust; a second kernel adds a dependency graph for no invariant gain.

**C. No TUI at all.** Rejected: the operator, agent, and SSH surfaces are real requirements, and a terminal client is the right shape for them.

**D. Give the TUI a privileged local path for operator convenience.** Rejected: it creates a second authority path and an unaudited one, in the surface most likely to be used under incident pressure.

## Evidence required before acceptance

- registry rows for the admitted kernel crates and transitives, with demo and showcase crates unadmitted and a planted check proving the lane fails if Tokio enters;
- a `Cargo.lock` closed-world scan showing exactly one runtime;
- proof that the TUI uses only the public API and holds no canonical state;
- if the web skin ships, evidence that no default route reaches it and no capability is exclusive to it.

## Migration and rollback

The TUI is a client and holds no state, so replacing or removing it costs no migration. Dropping the web skin removes a route.

## Dependency, target, and unsafe consequences

Admission adds the kernel crates and transitives; each needs a row. First-party TUI code keeps `#![forbid(unsafe_code)]`. The optional web skin adds a `wasm32` target and inherits ADR-0015 unchanged.

## Non-claims

- No claim that the sibling is currently admissible; runtime convergence is blocking.
- No claim that the web skin will be built. It is permitted, not planned.
- No usability claim for either surface.

## Supersession rule

A future ADR may change the kernel or drop the skin. It may not make a terminal-style surface the primary web UI, admit the demo or showcase crates, or give the TUI a privileged path.
