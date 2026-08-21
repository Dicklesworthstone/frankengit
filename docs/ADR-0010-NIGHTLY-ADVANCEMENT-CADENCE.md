# ADR-0010: The Toolchain Advances on Evidence, on a Fixed Cadence, Never on Convenience

- **Status:** proposed
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (toolchain, release)
- **Scope:** plan decision D15 — dated-nightly pinning and the advancement procedure
- **Binds:** `frankengit-fg068-toolchain-refresh-x5y3`, `frankengit-fg041a-proof-toolchain-cww`
- **Spec sections:** plan §D15, `AGENTS.md` §3.4 (latest nightly, reproducibly), §7 (performance evidence), §12 (local verification)

## Context

`rust-toolchain.toml` pins a dated nightly, which `AGENTS.md` §3.4 calls a material change to advance. Without a stated cadence, advancement happens the way it always does: someone hits a compiler bug or wants a stabilised feature, bumps the pin, and the diff is invisible because everything still compiles. The risk is not that the build breaks — it is that it does not, while behaviour, lint set, or codegen has moved underneath the evidence.

## Settled

- The pin is a dated nightly, never a floating `nightly` string.
- Advancement requires compatibility, conformance, determinism, and performance checks, with regressions recorded as negative evidence (`AGENTS.md` §3.4).
- Clippy pedantic and nursery are `deny`. A new nightly routinely adds lints, so an advancement is expected to produce work, and that work is not optional.

## Remaining choice

The cadence, and who may advance the pin.

## Decision (proposed)

1. **Scheduled, not reactive.** A candidate advancement is evaluated on a fixed cadence, and the pin moves only when a candidate passes. An urgent advancement to obtain a fix is permitted but takes the same evidence path, compressed rather than skipped.
2. **The candidate is evaluated in a branch, never on the default branch.** The full local verification lane runs against the candidate before the pin moves, so the default branch never carries an unevaluated toolchain.
3. **Advancement is one commit that moves the pin and nothing else**, alongside a separate commit for any lint or API fallout. A pin bump bundled with its own fallout is unreviewable, which is how a behaviour change hides.
4. **Determinism is the blocking check.** Golden artifacts, canonical bytes, and rendered surfaces must be byte-identical across the old and new toolchain. A codegen or formatting difference that changes a canonical byte blocks advancement outright; a difference that changes only a rendered surface requires an explicit marked golden change with a stated reason.
5. **Regressions are recorded even when the advancement proceeds.** A performance regression inside tolerance still goes to `docs/NEGATIVE_EVIDENCE_LEDGER.md` and `registries/negative_evidence.tsv`, because the next investigator needs to know it was seen and accepted.
6. **Rollback is always available and is exercised**, not merely assumed: the previous pin must build and pass the lane at the moment of advancement.

## Alternatives and why they are rejected

**A. Track the latest nightly automatically.** Rejected: it makes every build a different toolchain, which destroys reproducibility and makes any evidence unbound to a compiler.

**B. Pin and never advance.** Rejected: the pin ages into a compiler nobody can install, and the project loses fixes it depends on. Deferral is not stability.

**C. Advance whenever a developer needs a feature.** Rejected: that is the reactive path, and it consistently bundles the pin with the change that motivated it, which is exactly what makes the diff unreviewable.

**D. Advance on a cadence with no evidence gate.** Rejected: a schedule without a gate is just a slower version of tracking latest.

## Evidence required before acceptance

- the lane definition that a candidate must pass, executable locally without network or hosted-runner dependence (`AGENTS.md` §12);
- a determinism comparison across toolchains over the committed golden artifacts;
- a demonstrated rollback on a populated tree;
- the negative-evidence recording path proven by an actual recorded regression, not by a description of one.

## Migration and rollback

Advancement changes one file. Rollback is reverting it and rebuilding, which is required to be demonstrated at advancement time rather than assumed. Because canonical bytes are a blocking check, no advancement can leave durable state that the previous toolchain cannot read.

## Dependency, target, and unsafe consequences

None directly. Advancement may change the lint surface and the target matrix; both changes are recorded rather than absorbed. A new nightly that requires a first-party unsafe relaxation is refused, not accommodated.

## Non-claims

- No claim that a passing lane means the new toolchain is bug-free; it means the declared checks were run and recorded.
- No performance claim across toolchains beyond the recorded samples.
- No claim that the cadence is optimal. It is stated so advancement is a decision rather than an accident.

## Supersession rule

A future ADR may change the cadence. It may not remove the determinism gate on canonical bytes, and it may not permit advancement on the default branch without an evaluated candidate.
