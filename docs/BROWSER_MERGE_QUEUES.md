# Merge queues in the browser

Open `<repository-route>/ui/queues/` to inspect and manage the native merge
queues and land an exact queue head by fast-forward or an inspected native
two-parent merge commit. This is a client
of the existing authenticated queue and outcome APIs. Queue order, PR state,
branch protection and publication remain owned by native admission.

The page is served when either `--allow-queues` or `--allow-queue-landings` is
enabled. Its local static assets work without enabling the PR or source browser.
The deployment switches and token scopes still govern each API independently:

| Operation | Required token scope |
| --- | --- |
| List or inspect queues | `queues-read` |
| Enqueue, dequeue or reorder | `queues-write` |
| Load an exact PR observation | `pulls-read`, with the PR API enabled |
| Prepare a queue-head merge candidate | Independent `read`, `pulls-read`, and `queues-read` on one credential; PR and queue APIs enabled |
| Inspect the complete candidate bundle | Independent `read` and `pulls-read`; PR API enabled |
| Submit an exact queue-head landing | `queues-land`, with queue landings enabled |
| Recover the original transaction outcome | `outcomes-read`, with outcome recovery enabled |

Queue management permission does not authorize landing. Landing also checks the
target reference ceiling and current native protection, review and workflow
requirements. Tokens are never combined to manufacture a larger grant.

## Inspect and prepare

List pagination retains its original snapshot. Selecting a queue shows its
version, target branch, full execution order and current first entry. An entry
being first does not establish that its checks or reviews permit publication.
Refresh explicitly to observe a newer snapshot; prepared requests retain their
original coordinates.

The first enqueue creates a queue at version zero. An existing empty queue still
has its original target and a positive version. Enqueue binds the exact open PR
version, source and target branches and observed tips. Existing PR observations
can supply those values when the credential has the separate read grant.
Reference byte fields preserve names that cannot be represented as UTF-8.

Dequeue requires an explicit reason. Reorder supplies the complete membership
once each in the intended order. Neither operation moves a Git reference.

Fast-forward landing additionally binds the exact first queued PR and a positive
policy epoch. The caller supplies the observed policy epoch; the browser does
not infer approval from queue position or a green-looking row. Divergence or a
stale observation remains a native refusal. There is no force or automatic
merge-method fallback.

## Diverged queue heads: prepare, inspect and land

Select **Prepare merge candidate** on the first queue entry, or choose the
explicit merge-commit action. Load the PR coordinates at the selected snapshot,
enter the observed policy epoch, and supply the author, committer, positive Unix
timestamp and exact commit message. The browser supports text or hex-encoded
message bytes and the native `path-merge-v1` and `exact-renames-v1` profiles.

**Prepare and inspect complete candidate** first sends a read-only request to
`queues/{number}/prepare`. It retains the queue version and first entry, exact
PR version, policy epoch, repository incarnation, both branch byte names, and
both tips. It validates the native multipart envelope, complete metadata,
candidate/bundle identities and the entire returned landing command. It then
uploads those exact bytes to `pulls/{number}/inspect`, using raw reference hex
alternatives throughout. Neither request carries a publication key or creates
a transaction. Conflicts and already-up-to-date results produce no candidate;
there is no prefix batching, partial candidate, conflict-resolution fallback,
or automatic publication.

The complete native inspection must bind the same PR/policy/ref/tip subject,
bundle SHA-256 and candidate identity. The browser also checks the native Git
commit-body hash, ordered target/source parents, direct target-to-candidate
comparison, every changed path, and every text-hunk span. A later inspection
snapshot is allowed when that exact subject remains unchanged; it never
refreshes the original queue guards. The page displays every returned changed
path and hunk using literal text. Binary changes retain exact object identities
and sizes; the native report excludes their object bodies.

Download the exact bundle and complete inspection with the original native
landing form. For text branch references, **Export candidate for independent PR
review** produces the existing PR browser's import format. A reviewer uses
their own credential on the Pull requests page; import performs native
reinspection before any explicit review. The PR browser's review-import form
still requires text refs; byte-only refs remain available in the native bundle
and inspection downloads. Preparation and inspection do not manufacture
reviews, workflow checks, or a landing grant.

**Stage this inspected candidate landing** prepares a local multipart request
to `queues/{number}/land-candidate`. Save its private recovery receipt, review
the exact coordinates, then confirm and send. Landing rechecks the canonical
queue head, both versions/tips, policy, eligible independent reviews and
required checks, then atomically publishes the target update, PR merge and
queue completion. Draft changes, selection changes, cancellation and disconnect
invalidate the inspected candidate; they cannot rewrite an already staged or
dispatched command. No uninspected candidate can be staged through the ordinary
queue management method.

## Save, send and recover

Preparing a change performs no mutation. Review its exact coordinates, save its
private recovery receipt and then send explicitly. Subsequent form edits cannot
change the prepared body or idempotency key.

The receipt binds the repository route, tenant, repository incarnation, native
object format, credential fingerprint, complete command and original key. It
contains no bearer token. Protect it as private repository data. Restoring a
receipt validates its commitment and does not dispatch work.

Existing management/fast-forward receipts retain the
`frankengit-queue-retry-v1` format and 256 KiB limit. Candidate landings use
`frankengit-queue-candidate-retry-v1` with a 24 MiB limit, including the exact
original landing form and base64 bundle. Its deterministic multipart boundary,
original nonce and fingerprint reconstruct identical request bytes and the
original key after reopening. Import validates those commitments without
preparing a replacement candidate, reading the current queue, or claiming new
inspection. A native historical terminal receipt describes that original
decision even if the queue, tips or policy have since changed.

An interrupted request remains unresolved until a validated native terminal
decision settles it. Retrying uses the original body and key. Outcome recovery
only looks up that original key and does not resubmit the change. Missing seals,
undecided outcomes and lost replies do not prove that nothing committed.

An explicitly selected recovery-only connection can use a replacement token
for the original principal when it has the independent outcome grant. That
connection cannot read queues, prepare changes or resend writes. Ordinary
reconnection retains the original credential-fingerprint requirement.

Committed queue management reports no reference changes. A committed landing
reports the original atomic target move, PR merge and queue transition; it is
not reconstructed from today's queue. A canonical refusal remains the same
refusal when retried. Prepare a new request with a new key only for an explicitly
new attempt.

## Boundaries and verification

The page uses literal DOM text, same-origin authenticated requests, finite
response budgets and checked numeric coordinates. Tokens remain in memory;
disconnect clears visible private observations while retaining unresolved
token-free custody. Cancelling reads does not discard or establish rollback of
a write.

Queue candidate bundles are limited to 16 MiB, preparation metadata to 2 MiB,
and full inspection responses to 8 MiB. Preparation and inspection share a
60-second total browser read deadline in addition to individual transport
deadlines. Cancellation, credential changes and late hash/read completions
cannot select an obsolete candidate. Downloads use inert MIME types and
temporary object URLs that are revoked on disconnect and page exit.

Focused client and controller tests live in
`tests/browser/queues-native.test.mjs`,
`tests/browser/queues-candidate.test.mjs`, and
`tests/browser/queues-view.test.mjs`. Run each directly with the selected Node
runtime to see its registered cases. These tests use explicit API/DOM doubles.
They do not establish live-browser interoperability or native queue correctness.
The existing `queue_http`, `queue_landing_http` and `queue_preparation_http`
native integration targets cover the corresponding service boundaries.

The native wire contracts are documented in
[`NATIVE_HTTP_QUEUES.md`](NATIVE_HTTP_QUEUES.md) and
[`NATIVE_HTTP_QUEUE_PREPARATION.md`](NATIVE_HTTP_QUEUE_PREPARATION.md).
