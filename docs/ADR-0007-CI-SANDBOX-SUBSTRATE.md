# ADR-0007: CI Isolation Is a Pluggable Substrate Behind One Containment Contract

- **Status:** **accepted 2026-08-21 by GoldLotus ruling (fg061 comment 1096)**
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (CI, runners)
- **Scope:** plan decision D11 — sandbox substrate per platform, network and secret brokering, snapshot and cleanup, determinism
- **Binds:** `frankengit-fg034-ci-receipts-1tq`, `frankengit-fg034a-runner-impl-7xq`, `frankengit-fg034b-ci-corpus-kzi`, `frankengit-fg095b-workflow-execution-mynp`, `frankengit-fg095c-workflow-evidence-6opd`
- **Spec sections:** plan §D11 and §29, `AGENTS.md` §9 (hostile execution, cancellation must reap), §3.1 (no FFI for sandbox behaviour)

## Context

CI runs code chosen by whoever opened the pull request. It is the one place where FrankenGit deliberately executes hostile input, and the isolation primitive differs per platform: namespaces and cgroups on Linux, a VM boundary where namespaces are insufficient, and materially different facilities on macOS and Windows. Choosing one substrate now would either exclude platforms or overfit to Linux.

## Settled

- The control plane is pure Rust and is **not** the sandbox. The isolation primitive is an operating-system facility invoked as an external process boundary, which is expressly not the "hidden subprocess fallback" `AGENTS.md` §3.1 forbids — that rule is about faking unsupported *product* behaviour, not about using the OS to contain hostile code.
- CI runs outside truth processes with explicit isolation, egress, secret, cache, and resource policy (`AGENTS.md` §9).
- Cancellation must reap tasks, processes, VMs, tunnels, uploads, secrets, and credentials, **or report a containment failure**. A sandbox that cannot prove reaping is not admissible.
- A green CI job proves nothing about correctness (`docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §31); a check receipt records what ran, not what is true.

## Remaining choice

Which substrate is implemented first, and the exact per-platform matrix.

## Decision (proposed)

1. **Define the containment contract first, substrate second.** A substrate is admissible only if it can demonstrate: no egress except through the broker; no secret visible outside its declared scope; complete reaping on cancellation, including orphan detection; a deterministic clean state per run; and a resource ceiling enforced before work starts rather than observed after.
2. **Substrate is a trait with a conformance suite, not a hard-coded call.** Every substrate passes the same hostile corpus. Adding a platform is implementing a trait and passing the suite.
3. **Linux namespaces plus cgroups is the first implementation**, chosen because it is the platform the release lanes already require and because it makes the reaping and resource-ceiling obligations observable without a hypervisor. This is a sequencing decision, not a statement that it is the strongest boundary.
4. **A VM substrate is required before any multi-tenant hosted execution.** Namespace isolation is sufficient for self-hosted single-tenant use and is not claimed to be sufficient against a hostile tenant.
5. **macOS and Windows are typed unsupported until their substrate passes the same suite.** An unsupported platform returns a typed refusal; it does not silently run with weaker isolation.

## Alternatives and why they are rejected

**A. One substrate everywhere, chosen now.** Rejected: no single primitive spans the target platforms, so this either drops platforms or pretends a weaker boundary is equivalent.

**B. Containers via an existing engine as the primary boundary.** Rejected as primary: it adds a large external daemon with its own privilege surface and lifecycle to the trusted path, and its cancellation semantics are not ours to guarantee. Not rejected as a *host-provided* substrate behind the same trait and suite.

**C. Run CI in-process with capability restrictions.** Rejected: `AGENTS.md` §9 requires CI outside truth processes, and no in-language restriction contains arbitrary native code.

**D. Defer CI until the substrate question is settled.** Rejected: the contract and the receipt model are the load-bearing parts and can be built and tested against the first substrate.

## Evidence required before acceptance

- an escape corpus per substrate: filesystem, network, process, and credential escape attempts, each expected to be contained and *recorded*;
- cancellation drills proving reaping, including a deliberately unreapable child that must surface a containment failure rather than a silent success;
- cache-poisoning and secret-scope campaigns;
- determinism: the same job on the same inputs produces the same receipt;
- explicit measurement of what the substrate does **not** contain, recorded as negative evidence.

## Migration and rollback

Substrates sit behind one trait, so replacing or adding one changes no workflow schema and no receipt format. A substrate that fails its suite is removed by deregistration; jobs targeting it then receive a typed refusal rather than falling back to a weaker boundary. Silent downgrade is the specific failure this structure exists to prevent.

## Dependency, target, and unsafe consequences

Substrate control uses OS interfaces through the standard library where possible. Any crate needed for namespace or cgroup control requires a registry row with unsafe and FFI policy recorded, and first-party crates keep `#![forbid(unsafe_code)]`. The target matrix narrows honestly: platforms without a passing substrate are typed unsupported rather than best-effort.

## Non-claims

- No claim that namespace isolation is sufficient against a hostile tenant. It is not, and that is why the VM substrate gates hosted execution.
- No claim of completeness for the escape corpus; it is a bounded adversarial sample and its gaps are recorded.
- No performance or throughput claim.

## Supersession rule

A future ADR may change the substrate order or add platforms. It may not weaken the containment contract, and it may not permit a silent fallback to a substrate that has not passed the suite.
