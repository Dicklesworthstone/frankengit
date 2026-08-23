# Contributing to FrankenGit

FrankenGit is in a spec-first, pre-implementation phase. Contributions should remove ambiguity, add executable evidence, or deliver one complete final-abstraction vertical slice. Empty crate scaffolds, placeholder APIs, foreign-Git fallbacks, and performance claims without replay artifacts are not accepted.

## Read before changing anything

Read, in this order:

1. [`AGENTS.md`](AGENTS.md)
2. [`docs/NORMATIVE_PROTOCOL_CONTRACTS.md`](docs/NORMATIVE_PROTOCOL_CONTRACTS.md)
3. [`docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md`](docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md)
4. [`ARCHITECTURE.md`](ARCHITECTURE.md)
5. [`VERIFY_SPEC.md`](VERIFY_SPEC.md)
6. [`SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md)
7. the focused design document for the subsystem being changed

## Required change shape

Every nontrivial change identifies:

- the owned invariant or claim;
- canonical identities and exact byte encodings affected;
- intent, effect, and publication boundaries;
- success, refusal, retry, cancellation, crash, and recovery behavior;
- resource bounds and adversarial inputs;
- compatibility oracle and accepted divergence, where relevant;
- evidence artifacts and replay command;
- dependency, memory-safety, and layer effects;
- negative evidence or superseded design disposition.

Implementation changes must add success and failure evidence at the same time. A fast path must retain a scalar/reference oracle. A statistical or graph-derived controller must retain a deterministic safe fallback and may not acquire canonical authority.

## Local verification

GitHub-hosted Actions are not a project dependency. Run repository-owned lanes locally:

```bash
./scripts/verify.sh docs
./scripts/verify.sh constitution
./scripts/verify.sh fast
```

`full` and `release` intentionally refuse while their implementation-era gates are dormant. Doodlestein Self-Releaser will execute the same repository-owned commands across registered native hosts when release artifacts exist.

## Dependency and implementation rules

- Production is clean-room pure Rust on the pinned dated nightly.
- First-party crates use `#![forbid(unsafe_code)]`.
- Asupersync is the sole runtime.
- Production never links or invokes C Git, `libgit2`, JGit, Dulwich, another Git engine, or a C/C++ runtime library.
- New dependencies require an explicit `registries/dependency_policy.tsv` row and evidence under the dependency constitution.
- Crates enter the workspace only with a real vertical slice; no empty architecture cosplay.

## Licensing

Inbound contributions are under `LicenseRef-MIT-OpenAI-Anthropic-Rider`, the MIT licence plus the OpenAI/Anthropic rider, resolved as decision D14 by the repository owner on 2026-08-23. The full text is in [`LICENSE`](LICENSE).

These terms withhold rights from named parties, so they are **not** OSI-approved open source and the conventional inbound assumptions that come with a bare MIT project do not apply. Read [`docs/LICENSING_DECISION.md`](docs/LICENSING_DECISION.md) before contributing code.
