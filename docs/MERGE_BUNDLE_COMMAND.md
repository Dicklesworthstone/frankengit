# Applying a reviewed merge bundle

`fg merge apply` connects a saved Git bundle to the native merge admission
path. It imports verified candidate objects and publishes the target-ref
movement, native forge event, aggregate position and outbox obligation together.
It does not run a merge algorithm, modify the reviewed tree, invoke Git, invent
an approval, or force a branch update.

**Implementation status:** the command, node adapter and tests are committed.
Rust compilation and the complete real-binary smoke campaign have not been
executed in the editing environment. The validation observations below concern
Python helpers and transport fixtures, not a passing FrankenGit runtime gate.

## Command

Supply coordinates independently of the bundle. In this example the source
and target branches already exist in the node, their tips are the reviewed
parents, and the reviewed candidate is a two-parent native Git commit.

```bash
fg merge apply "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main "$REVIEWED_BUNDLE" \
  --trusted-local \
  --principal "$PRINCIPAL_ID" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --source-ref refs/heads/topic \
  --expected-source "$SOURCE_COMMIT" \
  --expected-target "$TARGET_COMMIT" \
  --merge-base "$COMMON_BASE" \
  --expected-commit "$REVIEWED_MERGE_COMMIT" \
  --pull-request 17 \
  --expected-version 0
```

`fg merge --help` and `fg merge apply --help` print the argument contract.
All review fields are mandatory. Repeated or unknown options are errors.
SHA-1 and SHA-256 are supported; all four supplied object IDs must be nonzero
and belong to the repository's native domain. Source and target must be
distinct fully qualified branch refs with distinct tips. The candidate must
have exactly two parents in the order **target-before, source**, and the
supplied base must be an ancestor of both parents. Native object bytes, not
caller-supplied edge metadata, establish these relationships.

`--expected-version 0` explicitly selects a new aggregate stream containing a
merge receipt. It does **not** fabricate an opened or approved pull request.
A positive version requires that exact existing aggregate position; closed
or already-merged aggregates cannot silently reopen. Merge-only streams do
not become fictional opened-PR rows in historical projections. The actual
native event remains in authenticated repository history.

The principal and retry key are supplied by an authorized local operator.
`--trusted-local` is an explicit acknowledgement of that boundary, not a
credential check or hostile-code sandbox. This command is not a remote forge
authentication service. Its bundle file must be a stable regular artifact
under the operator's control; symlinks, devices, empty files and oversized
files refuse before repository opening.

## Bundle contract

The artifact advertises exactly one branch: the target branch named in the
command, pointing to exactly the reviewed candidate. Its prerequisite frontier
must include the expected target-before commit. Up to 64 unique prerequisite
commits are accepted, and **every prerequisite** must already belong to
authenticated, selected repository history and identify a real native commit.
A matching object found only in storage is not sufficient authorization.

The bounded profile accepts Git bundle v2 for SHA-1 and v3 with exactly one
supported `object-format` capability. Unknown capabilities, partial-clone
bundles, duplicate prerequisites, zero IDs and multiple advertised refs
refuse. Extra required objects must be supplied by the pack or the selected
history; the bundle cannot enlarge its own external-object authority.

An external Git checkout can produce the artifact. For example, after a human
has reviewed a merge whose local `refs/heads/main` points to the exact candidate:

```bash
git bundle create reviewed-merge.bundle refs/heads/main "^$TARGET_COMMIT"
```

That is a separate artifact-production step, not a subprocess run by `fg`.
Git may emit both target-before and common-base boundary prerequisites for a
merge; the frontier support accommodates that shape. The candidate's source
and target tips still must match the independently supplied review coordinates.

The intake ceiling is 128 MiB, with a 16 KiB header and at most 64 prerequisites.
Pack expansion is separately bounded. Native merge validation has independent
default ceilings of 100,000 objects, 400,000 edges, 32 MiB per object and
128 MiB total object bytes; tighter node limits and request budgets also apply.
A resource limit is not permission to truncate a closure or publish a partial
merge.

`fg workspace apply` remains a separate, narrower operation: exactly one
prerequisite and exactly one parent. A merge bundle cannot use it to bypass
forge and outbox publication.

## Publication and recovery

The node executes this sequence:

```text
independent review coordinates + saved artifact
    -> bounded envelope and visibility checks
    -> authenticated prerequisite verification
    -> production pack quarantine and object staging
    -> native merge validation at the admission basis
    -> one Ref + Forge + Outbox fold
    -> immutable dependencies
    -> one exact-predecessor authority-head CAS
    -> authenticated terminal outcome
```

Quarantine does not publish the synthetic receive command used to validate
the pack. The adapter discards that source-only proof and enters the existing
native merge driver. There is no intermediate ref-only commit, second seal or
parallel outbox database. The driver rechecks current source/target positions,
aggregate state and native closure, so the quarantine/admission interval does
not authorize a stale merge. Already staged objects may remain after refusal;
their presence does not prove publication.

A terminal response is one JSON line with `type: "merge_publication"`, outcome,
transaction ID, decision sequence, committed RCR or refusal identity, repository,
PR/version, all reviewed commit coordinates, and hexadecimal source/target ref
bytes. The retry key is not echoed. The RCR identity is distinct from the native
Git candidate identity. `delivery_acknowledged` is `null`: publishing an outbox
obligation does not observe a destination acknowledgement, and a retry may
recover an older merge whose delivery has since advanced.

Exit status is zero only when a committed result was reported and the node
closed cleanly. A canonical refusal, I/O failure or cleanup failure exits 2.
A nonzero exit is therefore **not proof of non-commit**. Known terminal decisions
are retained in the JSON receipt or output-failure diagnostics; shutdown errors
cannot convert an acknowledged commit into an uncommitted claim.

To reconcile uncertainty, repeat the identical artifact, principal, key and
review coordinates. Successful and refused retries recover the original
terminal result. Retrying an old successful merge after another merge must
not move the target backwards or enqueue another delivery. Reusing the key
with changed candidate, PR, version or other sealed semantics refuses instead
of aliasing the original decision. A genuinely revised review is a new
operation, not a recovery technique for an uncertain old one.

## Tests and observed validation

The implementation adds seven embedded-node integration tests in
`crates/fgit-node/tests/merge_bundle_publication.rs`, six CLI/shared-helper
tests, and two prerequisite parser tests. They cover unstaged objects, both
hash domains, one coupled head transition, native identity reuse, reopen and
later-descendant retries, competing candidates, changed-key semantics, wrong
parents/versions, invalid artifacts, the workspace boundary and unserving-node
intake. Existing workspace and sealed-native tests remain registered.

The fresh-process CLI campaign runs against an explicitly supplied built binary:

```bash
python3 scripts/e2e/merge_publication_smoke.py --fg /absolute/path/to/fg
```

It fingerprints the executable and exercises both hash formats by default.
Missing binaries and failed assertions are errors, not skipped successes.
Its negative frontier cases include absent prerequisites, selected blobs used
as prerequisites and duplicates. It also checks terminal receipts, unchanged
state after refusals, retries, historical refs and post-merge export.

Executed in this editing session: Python syntax/help checks, fixture native
identity/pack/checksum checks for both formats, 15 negative receipt-helper cases,
a missing-binary refusal, and temporary Git 2.47.3 bundle verification/fetch of
the fixtures in both formats. An ordinary Git bundle-generation experiment
also demonstrated the target-plus-base prerequisite shape. These checks
validate fixtures and helpers only. Rust compilation, Clippy, native tests and
the complete `fg` campaign were not run because the environment has no Rust
toolchain or built `fg`. No broader forge completion or bead closure is claimed.

The full publication/delivery semantics and remaining acceptance belong to
[the merge delivery contract](MERGE_FORGE_EVENT_DELIVERY_CONTRACT.md).
