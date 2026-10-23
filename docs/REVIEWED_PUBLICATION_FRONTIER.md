# Reviewed publication above an admitted blob frontier

A small source candidate can now pass ordinary reviewed-bundle publication when
its changed trees directly reference more inherited blob data than the original
body-read budget. The reviewed source/merge/rebase bundle intake explicitly opts
into `ProductionQuarantineValidator::for_reviewed_candidate`. No untrusted form
field, patch profile or bundle metadata can select this trust boundary.

The existing source HTTP endpoint and `fg_source_edit.mjs` operator commands use
this path without a new flag. Preparation and inspection still return the exact
candidate bundle; publication consumes those retained bytes and the independently
reviewed commit. It does not regenerate a patch against the latest source.

## What can be reused

The canonical authority-selected set alone is not enough. The quarantine must
prove each original dependency reachable from the current visible refs through
fully verified native commit/tree/tag bytes. Only a `Blob` edge discovered in
that original graph may use the bounded storage envelope for identity, namespace,
required kind, exact locally stored length and per-object limits. An uploaded
wrapper cannot supply its own permission to borrow an omitted original.

Untyped reused ref roots still require actual bodies. Uploaded objects retain
pack checksums, native hashes, required-kind checks and graph coverage. External
REF_DELTA bases retain full-body verification and the shared original-input byte
ledger, even when a reconstructed result has the same ID as a stored original.
Missing or corrupt metadata, contradictory kinds, hidden/disconnected inputs,
exhausted graph work and cancellation refuse before candidate staging. Complete
prerequisite validation continues to verify every original body.

Ordinary Git receive validators keep their historical full-body behavior and
limits. The crate-private opt-in changes only reviewed candidate intake; it does
not enlarge raw receive capability, a bundle profile or an operator's credentials.
No size, entry, graph, deadline or delta limit is raised, and no dependency,
subprocess, runtime or alternate publication engine is introduced.

## Metadata reuse is not a scrub

An unchanged admitted blob's envelope is not a new payload-integrity certificate.
Unread corrupted payload bytes may coexist with a successful metadata check;
actual reads still verify their original commitments and refuse corruption.
Doctor/scrub retain integrity-audit responsibility. Tests deliberately corrupt a
payload to keep this boundary explicit, and separately corrupt the envelope to
require refusal. This is the same immutable-reference distinction used by the
candidate inspector, not permission to pass unverified new bytes.

## Admission and recovery remain unchanged

All source writes retain authentication, current canonical policy, expected-old
refs, exact candidate-parent validation, sealed transaction identity and authority
CAS. Staging is not publication. A disconnect or lost output is not non-commit.
The operator retains the exact reviewed bundle in its create-only journal before
sending, refuses an automatic resend after a lost terminal, and recovers the
original key from the outcome endpoint, even after a successor moves the branch.
A locally retained terminal can then reopen without source files or a server.

## Executable coverage and limits

`quarantine_validator::typed_closure::tests::admitted_blob_tests` exercises real
file-backed fabric with explicitly supplied unit-test selection. Its refusal
and permitted twins cover strict-default compatibility, exact graph-byte bounds,
wrong kinds, missing/malformed envelopes, corrupt delta bases, unrelated originals,
complete prerequisite checks and cancellation without partial authorization.

`candidate_publication_frontier.sh` uses the actual Node operator and compiled
Rust `fg serve-http`, not a mock. Both hash formats use seven 20 MiB unchanged
blobs beside one small file edit. Python independently computes native blobs,
complete trees, commits and bundles. The campaign checks wrong-result refusal,
read/write credential separation, retained custody after recipe deletion, lost
stdout, a later independent successor, original-key recovery without resend and
source/server-free terminal reopening. Every inherited blob is finally reread
through native verification rather than assumed intact from metadata.

This does not establish unbounded repositories, raw-Git large-push qualification,
a completed review/merge/CI product loop, hostile execution isolation, physical
power-loss behavior or full-workspace/release readiness. `frankengit-t0iw` remains
open for its complete independently verified acceptance.
