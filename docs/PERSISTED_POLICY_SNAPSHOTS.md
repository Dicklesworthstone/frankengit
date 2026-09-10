# Persisted compiled-policy snapshots

`fgit-admission::policy_bridge::persisted` stores and evaluates the existing
`fgit-policy` compiled snapshots through the existing authority object store.
It does not activate a policy or make the opt-in candidate-review gate mandatory.

## Exact identity before evaluation

`evaluate_protection` now checks that `PolicySnapshotSource` actually returned
the requested `PolicySnapshotId` before evaluating any input. Previously a source
could return a valid allowing snapshot for a requested denying snapshot; the
verdict would still have named the requested identity. That substitution now
returns `IdentityMismatch`. The verdict's identity comes from the snapshot
actually evaluated, not from an unchecked lookup argument.

`PolicyFrame::compile` uses the existing bounded policy compiler and canonical
encoder. `PolicyFrame::from_bytes` accepts stored/transferred frames only after
strict decoding, identity derivation and exact re-encoding. A normalized body
with different original bytes cannot be admitted as a canonical frame.

`stage_policy` and `stage_policy_async` put the complete frame at the standard
immutable body key for the registered `frankengit/policy-snapshot/v1` identity.
They return an acknowledged `Created` or `IdenticalRetry` receipt. A conflicting
slot is an error, never an overwrite. No head is created or changed, and no
second policy database, parser, identity scheme or runtime is introduced.

`read_policy` and `read_policy_async` read that exact key and independently
recompute the policy identity. Missing, malformed, noncanonical, substituted
and oversized bodies all fail rather than selecting an allow policy or a
fallback default. `evaluate_stored_policy` and its async twin pass that checked
snapshot to the existing evaluator and retain the normal protection verdict
and rule trace.

## Ownership and resource limits

The async functions await the caller's `AsyncAuthorityStore` with its context.
They do not create an executor, detach work or call a blocking runtime bridge.
A caller-owned checkpoint distinguishes cancellation from resource exhaustion.
Read, decode and evaluation paths check it before returning a successful result.

After an acknowledged immutable put, staging returns the known write receipt;
a cancellation arriving then cannot turn that acknowledgement into a claim that
nothing was written. An authority error retains its operation and original
failure, including ambiguity. The adapter does not automatically retry an
ambiguous write. A caller can reconcile by the exact immutable identity, while
preserving any unresolved outcome.

The maximum admitted profile is a 1 MiB frame, 64 KiB single byte/text field,
4096 collection elements and depth 32. Callers may lower these limits, not
silently disable or increase them. Invalid limits refuse before storage reads.
The authority backend independently owns the bound on allocating its returned
immutable value; the adapter's frame bound is applied before codec processing.

## Storage is not activation

The existing incarnation-configuration `policy_root` points to a
`HiddenRefPolicyBody`. It is not a compiled `PolicySnapshotId`, and this adapter
does not reinterpret it as one. Knowledge of a compiled policy ID likewise does
not grant the right to read, activate or evaluate it for an authorized action.
The storage owner must enforce access, and the admission owner must select the
ID through authenticated repository policy before using its verdict.

There is no configuration-selection or activation mutation in this change.
Staged policy existence is not authority and creates no new retention root.
This does not alter `merge apply`, receive-pack, source import or workspace
publication. The opt-in `apply-reviewed` gate remains as documented in
[the exact-candidate review workflow](EXACT_CANDIDATE_REVIEW_WORKFLOW.md).
Repository-wide mandatory review protection remains unfinished: it must select
and bind policy through authenticated configuration and enforce the same
preconditions across every applicable publication path and every CAS replan.
Principal facts, review receipts, graph facts and evaluation time still need
independent provenance; the pure policy evaluator does not authenticate them.

## Verification status

Ten registered Rust test functions were added: two source-identity regressions,
six reference-store/codec/evaluator tests, and two file-backed node tests.
The latter exercise the production async authority interface for SHA-1 and
SHA-256 nodes, explicit shutdown/reopen, immutable-slot substitution, cancelled
reads and unchanged canonical repository state. They are not substitutes for
process-death, power-loss or concurrent policy-activation fault campaigns.

At the editing session, lexical/delimiter checks and exact local-versus-GitHub
blob hashes were checked. Cargo, rustc, a built `fg`, rustfmt and Clippy were
unavailable. No Rust compilation, native test execution or passing production
gate is claimed. No bead was closed.
