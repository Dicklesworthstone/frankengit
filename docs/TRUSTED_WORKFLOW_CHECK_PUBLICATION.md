# Trusted workflow observations in canonical forge history

FG-095b's `fgit-forge::event::workflow_check` defines an immutable job
observation. It records what an authenticated reporting principal submits,
not independently attested execution. `ActionRequired`, `Failure`, `Cancelled`
and `TimedOut` are the only conclusions. There is no successful or neutral
protected-check result, and no conversion to a review approval or green check.

## Identity and compatibility

Each publisher/run/attempt/exact UTF-8 job name has one full 256-bit identity.
The stream label is `check/` followed by 52 lowercase base32hex characters with
canonical zero padding. No invocation or job digest is truncated to fit the
existing 64-byte forge label. Different evidence, source or conclusion for the
same identity does not create a second stream; publication must reject a second
terminal report. A deliberate new execution requires its own attempt identity.

The event adds required aggregate kind 7 (zero u64 escape, u32 kind, raw 32-byte
identity) and payload kind 11 to the existing forge-event codec. The aggregate
version is exactly 1. The payload binds reporting principal, canonical branch,
native source commit, run/attempt/graph commitments, exact job name, conclusion,
and original evidence bytes. `workflow_check.rs` is the byte-layout authority.
Existing aggregate and event tags, schema versions, and body encodings remain
unchanged. Older readers reject the new required kinds rather than ignoring
an authority-selected event they cannot interpret. Upgrade readers before
publishing this kind; do not write it into a mixed-version deployment.

Job names are nonempty UTF-8 without controls, at most 1,024 bytes. Evidence is
nonempty and bounded to 1 MiB, checked before copying or encoding. Evidence
bytes are inside the event, so a later forge publication retains them under the
same immutable event/batch commitments instead of an untracked local file.
This first subject profile names canonical branches; tag peeling, unpublished
candidates, and signed independent runner attestations are separate boundaries.

## Current scope

The event and batch encoders/decoders implement these identity, framing and
resource checks. The legacy digest-valued PR projection does not reinterpret
workflow observations as PR rows. This record definition alone does not enable
a writer, replace authority-head CAS, publish a local journal, or satisfy a
protected branch's checks.

The eight Rust tests in `event/workflow_check/tests.rs` cover both native hash
domains, all admitted conclusions, all 256 identity bits, canonical labels,
conflicting bodies under one identity, aggregate/version corruption, exact
bounds, truncation, unknown conclusions, and legacy-byte preservation.

Rust compilation and Rust tests were not run in the editing environment:
Cargo and rustc are absent. Source/blob equality, patch whitespace, lexical
checks and independent identity/framing reference checks are not native gate
results. Run `cargo test -p fgit-forge --lib workflow_check --locked` and the
owning integration lanes with the pinned toolchain before acceptance.
