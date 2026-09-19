# Asynchronous graph-generation publication and recovery

`fgit-graph::GenerationAuthority` now has a production `AsyncAuthorityStore`
path. The former surface required `AuthorityStore`, which is the synchronous
reference/conformance interface; the embedded FrankenSQLite store implements
the asynchronous interface. The new path does not bridge by blocking, install
a runtime, add a dependency, or change the generation body/key encoding.

This is the graph-generation activation prerequisite used by the shared
search/graph design in plan section 27 and FG-032a. It does not implement a
persistent source-search index, a graph builder, semantic ranking, search
segments, source extraction, an HTTP indexing service, or FG-032 completion.

## Publication

A caller with an already authorized, tenant/repository/incarnation-scoped head
key can call `stage_and_activate_async(&request_context, &candidate)`. Every
storage operation receives the supplied invocation context. The synchronous
`stage_and_activate` and asynchronous path share the same predecessor, view,
generation and result-validation code.

The flow is: encode the immutable generation, put it at its existing exact
key, read and authenticate the generation head, then initialize genesis or
conditionally replace the exact observed predecessor token. No second head
read refreshes the candidate's precondition. A CAS loser remains a typed
`ConcurrentActivation`; no automatic replan or retry changes the candidate.
An inconsistent genesis/counter shape cannot be extended.

The publisher checks a returned success receipt against the exact head key,
proposed generation and encoded body. It does not make another asynchronous
call after confirmed publication, so a later context cancellation cannot turn
that observed result into a refusal. A mismatched success receipt returns
`InvalidActivationReceipt`, which does **not** establish rollback. Underlying
store ambiguity is preserved without manufacturing an outcome.

The preexisting retry behavior is retained: passing an already-active candidate
to `stage_and_activate` is not another activation and fails its predecessor
check. Use the separate read-only recovery API after an interrupted reply.

The caller remains responsible for validating the source stamp, authorizing
the operation, staging all referenced vertices/edges/index/evidence bodies,
and satisfying the selected durability profile. This API only selects the
immutable generation root. A `GenerationActivation` confirms that root
selection, not a stronger placement or disaster-recovery guarantee, and never
publishes a repository ref, forge event, or transaction outcome.

## Pinned selection and anti-rollback checkpoints

`read_active` and `read_active_async` return a `SelectedGeneration`, or `None`
for an uninitialized head. A selection includes the exact body, generation ID,
head generation, and observed body/byte counts. It is not an access capability.

The read authenticates the head, verifies the active body's immutable backing,
and retains that single observation throughout. An optional minimum
`GenerationActivation` is a caller-retained checkpoint. The reader proves that
its selected history contains that exact identity at that exact generation.
A higher checkpoint, a different identity at the same position, a missing
ancestor, or a fork never silently falls back to an older valid body.

No checkpoint is persisted on behalf of a client. Callers retain it under their
existing authority/receipt policy and bind the supplied head key and expected
view to the authorized repository incarnation. Query parameters cannot grant
access or choose an arbitrary cross-tenant head key at a service boundary.

## Interrupted activation recovery

`recover_activation` and `recover_activation_async` take the candidate's exact
generation ID, expected view, optional retained checkpoint, and bounded read
parameters. They return one of four observations:

- `Uninitialized`: the selected head slot does not exist, with no unresolved
  caller checkpoint. It does not cancel another in-flight writer.
- `Active`: the candidate is the exact selected generation.
- `Superseded`: its identity appears on the verified predecessor path from the
  selected head; the original inferred generation and current selection remain
  distinct.
- `NotInSelectedHistory`: the complete verified chain reached genesis without
  finding the candidate. It says nothing about a later concurrent publication.

The candidate being staged at an immutable key is never sufficient. Recovery
only follows exact predecessor keys rooted in the authenticated observation.
It does not list storage, trust an outcome cache, stage objects, mutate a head,
refresh the selected head midway, or automatically retry the candidate.

Every visited body is bounded, decoded canonically, re-encoded exactly, checked
against its committed generation identity, checked for the selected view and
consistent generation/link shape, and checked against prior visits. Missing,
substituted or corrupt bodies refuse; they do not become a negative result.
A positive candidate match cannot skip an unresolved retained checkpoint.

## Bounds and cancellation

`GenerationReadLimits` defaults to at most 4096 immutable generation reads,
16 KiB per body and 16 MiB total returned head/body bytes. Each limit can be
narrowed, not disabled or widened. The active immutable backing counts as one
read; the head and its backing both count toward bytes. Exact predecessor
reads are bounded before issuing another operation. The backend separately
owns its read-allocation ceiling before returning a buffer to this layer.

All asynchronous store calls carry the request context. A caller-owned live
probe is checked before/after storage work and before returning a selection.
Read cancellation yields `ReadCancelled`, with no provisional public result.
The caller's runtime still owns cancellation, draining and backend lifecycle;
dropping a future is not shutdown or containment evidence.

## Verification boundary

The patch adds 22 Rust regression tests: 12 activation tests and 10 recovery
tests. They use the real reference authority store under an explicitly
`cfg(test)` asynchronous forwarding adapter, not a durable backend. One test
forces a genuine `Pending` before storage to exercise suspension; others inject
an actual competing CAS, lose replies after actual head writes, and interrupt
between staging and CAS. Recovery tests cover exact checkpoints, staged-only
candidates, missing/substituted history, exact resource boundaries,
cancellation and a writer advancing during the selected walk.

The implementation session had no Rust/Cargo/rustfmt executable. These tests
have **not** been executed, and Rust
compilation, formatting, Clippy, real FrankenSQLite execution, full-workspace
checks and release gates remain unverified. Locally generated patches preserve
the unchanged existing tests and contain no new dependency or schema version.

Focused checks for an authorized build lane with the pinned toolchain:

```bash
cargo check --locked -p fgit-graph --all-targets
cargo test --locked -p fgit-graph generation
```

A passing reference-store test is not a claim of live backend cancellation,
crash recovery, complete search indexing, or production readiness.
