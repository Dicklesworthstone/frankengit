# Contributing to FrankenGit

FrankenGit is currently in a spec-first phase. Contributions should reduce ambiguity, supply executable evidence, or implement a complete vertical slice. Empty crate scaffolds and broad placeholder APIs are not accepted.

Before opening a change:

1. Read `AGENTS.md`, `docs/NORMATIVE_PROTOCOL_CONTRACTS.md`, `VERIFY_SPEC.md`, and `SECURITY_THREAT_MODEL.md`.
2. Run `python3 scripts/verify_docs.py`.
3. Identify the invariant owner, canonical identity, failure modes, and evidence artifact for the change.
4. Preserve Git compatibility unless an explicit registry row records and tests an intentional divergence.
5. Never strengthen a public claim beyond its checked-in evidence.

Implementation changes must include tests for success, refusal, cancellation, retry, crash/recovery, and resource exhaustion where applicable. Security-sensitive format or protocol changes require a threat-model update.

The current custom license is provisional; see `docs/LICENSING_DECISION.md` before contributing code or assuming conventional open-source inbound terms.