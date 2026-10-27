# Persisted compiled-policy snapshots

`fgit-admission::policy_bridge::persisted` stores and evaluates the existing
`fgit-policy` compiled snapshots through the existing authority object store.
Immutable staging by this module does not activate a policy. The separate
[canonical ref-policy activation path](CANONICAL_REF_POLICY_ACTIVATION.md)
selects a bounded compiled snapshot through the existing administrator-owned
protection aggregate and authority-head CAS.

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

Staged policy existence is not authority and creates no new retention root.
The activation path embeds exact canonical snapshot bytes in a protection
event, selects it through the authenticated forge frontier, and enforces it
in direct-ref and native-merge publication, including CAS replans. Existing
review/check protection remains independently mandatory when installed.
The ref-only activation profile refuses principal facts. A separate
`reference_actor_id_v1` profile accepts only the exact principal identifier
bound by admission to the sealed request, using required event kind 17 and
policy-decision schema 1.3. HTTP retains its credential-established principal;
trusted local CLI and MCP retain their operator-assertion boundary. Actor
attributes, authentication strength, memberships, review receipts, graph facts
and evaluation time still require independent provenance and remain refused.
The pure policy evaluator does not authenticate identities. Old ref-only event
kind 16 and evidence schema 1.2 remain closed to actor predicates.

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
