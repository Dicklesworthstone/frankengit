# ADR-0013: WEB-3 — The Primary Web UI Is a Real-DOM Pure-Rust WASM App; Leptos Versus Dioxus Is the Open Choice

- **Status:** proposed — this is the one WEB decision with a genuinely open selection
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (web UI)
- **Scope:** the primary browser surface: framework, SSR and hydration, CSS, and toolchain
- **Binds:** `frankengit-fg050-web-ui-5pt`, `frankengit-fg048c-fastapi-admission-hogb`
- **Spec sections:** plan §D-WEB and §43.2, `AGENTS.md` §3.1 (pure Rust, no first-party unsafe), §3.3, §10 (claim rules)

## Context

Two things about the web UI are settled and one is not. Settled: it renders the **real DOM**, and it is **pure Rust compiled to WebAssembly** rather than a JavaScript framework. Open: whether that is Leptos or Dioxus, and the exact SSR, hydration, CSS, and tooling shape.

The settled half matters because both plausible wrong turns are expensive. A canvas-painted UI breaks text selection, accessibility, translation, find-in-page, and SEO — everything a forge's public pages exist for. A React front end would put the primary surface outside the Rust substrate, so canonical types, the `fgit-doc` renderer, and the verified-read verifier would be re-implemented in TypeScript and drift.

## Settled, and recorded here rather than reopened

- Real DOM, not canvas. The terminal aesthetic is `frankentui`'s and is explicitly not the primary web UI (`docs/ADR-0014-WEB4-FRANKENTUI-SCOPE.md`).
- Pure Rust to WASM, with the canonical codec, the `fgit-doc` renderer, and the verified-read verifier as **native code in the same build** — not FFI'd into JavaScript. This is what lets the browser check Merkle inclusion proofs against a trusted head so a mirror or CDN cannot lie to it.
- A generated TypeScript client plus a React reference front end remains a **permanently supported alternative**, so third parties and JavaScript contributors keep a first-class path. This is a no-loss guarantee, not a courtesy.
- The honest cost is recorded rather than hidden: a smaller component ecosystem than React and a smaller contributor pool. A polished GitHub-like look is more first-party design work, achievable with Tailwind.

## Remaining choice

Leptos versus Dioxus, and with it SSR and hydration strategy, CSS pipeline, and build tooling.

## Decision (proposed)

Do not pick the framework in this ADR. Pick the **criteria**, in priority order, and require a spike against them:

1. **No first-party unsafe.** Framework macros and runtime must not require a first-party lint relaxation. Generated `wasm-bindgen` unsafe is transitive surface to be pinned, expanded where practicable, audited, and ledgered — never a first-party exception (`docs/ADR-0015-WEB5-NO-UNSAFE-EXCEPTION.md`). **This criterion is disqualifying, not weighted.**
2. **SSR with hydration that degrades honestly.** Public pages must render server-side for SEO and for no-WASM clients. A framework whose SSR story requires a JavaScript runtime on the server does not qualify.
3. **Accessibility and text selection out of the box**, since they are the reason for choosing real DOM at all.
4. **Bundle size and time-to-interactive on the heavy screens** — large diffs, big trees, blame — measured, not assumed, because that is where WASM is supposed to pay.
5. **Dependency graph size and auditability** under the closed universe. Fewer transitives with clearer provenance wins.
6. **Build toolchain without an npm front-end path** in the first-party build.

The spike implements the same non-trivial screen — a large diff view with blame — in both frameworks and reports against all six. Neither is adopted on preference or popularity.

## Alternatives and why they are rejected

**A. React as the primary UI.** Rejected: the substrate would be re-implemented in TypeScript and would drift from the Rust one, and the in-browser verifier would become an FFI shim rather than native code. Retained as a supported alternative front end.

**B. A canvas-painted or terminal-style primary UI.** Rejected: it breaks selection, accessibility, translation, find-in-page, and SEO for most users. Available as an optional alternate skin, never as primary.

**C. Server-rendered HTML with no WASM.** Rejected: the verified-read verifier must run in the browser, and shipping it as JavaScript reintroduces the drift this decision exists to prevent.

**D. Pick a framework now on reputation.** Rejected: criterion 1 is disqualifying and has not been evaluated for either candidate. Choosing before that check is choosing blind.

## Evidence required before acceptance

- the two spikes, committed, implementing the same screen;
- for each: a `cargo tree` and closed-world scan, a recorded audit of framework-generated unsafe, measured bundle size and time-to-interactive on the heavy screen, and an accessibility pass;
- proof of SSR without a JavaScript server runtime;
- a demonstration that the canonical codec and verifier run as native Rust in the same build.

## Migration and rollback

The UI holds no canonical state, so replacement is re-implementation against the same typed API and costs no data migration. The supported TypeScript client plus React reference is the standing fallback, which is why the no-loss guarantee is load-bearing rather than decorative.

## Dependency, target, and unsafe consequences

Whichever framework is chosen adds a substantial transitive graph requiring registry rows, plus a `wasm32` target and its own unsafe ledger entries. First-party UI crates keep `#![forbid(unsafe_code)]`. A framework that cannot meet criterion 1 is disqualified regardless of how it scores elsewhere.

## Non-claims

- **No framework is selected by this ADR.** Any statement that FrankenGit uses Leptos or Dioxus is currently unsupported.
- No performance claim for WASM over JavaScript; criterion 4 exists because that advantage is concentrated on heavy screens and is otherwise assumed too readily.
- No claim that the first-party component work is small. It is recorded as a real cost.

## Supersession rule

A future ADR may select the framework once both spikes exist. It may not make the primary UI canvas-painted or JavaScript-first, drop the TypeScript and React alternative, or admit a first-party unsafe exception.
