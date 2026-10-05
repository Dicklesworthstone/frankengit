# Fast-forward-only pull request publication

Related bead: `frankengit-root-doctrine-x2mv.4.20`. This implements one merge
method, not the bead's conversation, squash, quorum or protection-admin work.

## Endpoint and exact command

`POST {repository-route}/api/v1/pulls/{number}/fast-forward`

The repository's PR endpoint must be enabled. Authentication is explicit
Bearer authentication with the existing code-publication permission checked
by `permits_reviewed_merge()`, not merely PR metadata-write permission. The
normal gateway cross-site, quota, writer and deadline gates still apply.
An `Idempotency-Key` is mandatory. The only content type is
`application/x-www-form-urlencoded` (optional `charset=utf-8`).

Exactly six fields are required:

| Field | Meaning |
| --- | --- |
| `object_format` | The repository's explicit `sha1` or `sha256` domain. |
| `pull_request_version` | The observed positive PR aggregate version. |
| `source_ref` | The complete source branch ref. |
| `source_tip` | That branch's exact native lowercase object ID. |
| `target_ref` | The complete target branch ref. |
| `target_tip` | That branch's exact native lowercase object ID. |

Send raw 40- or 64-digit OIDs in HTTP forms, not a `sha1:` or `sha256:` prefix.
Percent-encode ref names. The decoded form is capped at 8 KiB, wire intake at
16 KiB, and chunked intake at 1,024 chunks. Fixed and chunked bodies must be
complete before admission. Unknown fields, duplicates, exhausted versions,
zero IDs, mismatched hash domains and candidate uploads are refused.

There is deliberately no `force`, policy assertion, author, candidate,
merge-base or reviewer field. The existing native fast-forward driver owns
ancestry, exact-version/tip checks, current branch protection, canonical retry
identity, and atomic ref/PR/outbox publication. It publishes the existing
source commit, not a newly constructed merge commit. Divergence does not
select another merge method. This endpoint does not bypass review protection;
protection that this native merge method cannot satisfy remains a refusal.

## Outcomes and retry

A native terminal decision is returned as `fast_forward_merge_publication`,
schema version 1. HTTP 200 means a canonical committed decision; HTTP 409 with
this receipt means a canonical refusal. The receipt binds the repository
incarnation, principal, PR number and version, both ref identities (text plus
native hex bytes), both tips, transaction, decision sequence and either the
repository commit record or refusal record. Native OIDs in responses may use
the explicit hash-domain prefix. `delivery_acknowledged` remains `null`.

Not every HTTP error is a canonical refusal. A connection loss, timeout,
nonterminal API error, invalid receipt or response-budget failure must not be
interpreted as proof of rollback. Retain the identical six-field command and
original key. Retry those exact bytes or use the existing keyed
`POST {repository-route}/api/v1/outcomes` lookup, without a command body.
Absence in an outcome lookup is not proof of non-commit. Never refresh the
version or tips while retrying the old key.

## Browser client

The existing `PullClient` request lifecycle accepts `fast-forward` through
`stageMetadata(number, 'fast-forward', fields)`. Despite that historical
method name, the transport treats this action as code publication, not a
metadata permission. Staging is local; `send()` is an explicit separate step.
The same saved-request export, restore, retry and outcome-recovery machinery
is reused. No candidate bundle is retained or uploaded for this action.

The client validates the exact terminal coordinates, native reference bytes,
repository scope and previously observed transaction/principal. Transport
requires an explicit keyed POST outside the cancellable-read lane. Cancelling
views does not abort this publication. A disconnect still means uncertainty,
not rollback. Browser text forms refuse byte-only refs rather than converting
them lossily.

## Verification scope

`node --test tests/browser/pulls-fast-forward.test.mjs` exercises the real
browser command, receipt, retry-key, recovery and transport modules with a
controlled Fetch boundary. These tests are not a live native-server run.
The Rust adapter's five tests live in
`crates/fgit-node/src/smart_http/server/pulls/fast_forward/tests.rs`.
Native compilation, native tests and a served end-to-end merge must still be
run in a Rust-equipped environment; they were not available in the authoring
runtime. No complete-workspace gate or bead closure is claimed.
