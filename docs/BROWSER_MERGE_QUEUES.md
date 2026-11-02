# Merge queues in the browser

Open `<repository-route>/ui/queues/` to inspect and manage the native merge
queues and submit an exact queue head for fast-forward landing. This is a client
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

## Save, send and recover

Preparing a change performs no mutation. Review its exact coordinates, save its
private recovery receipt and then send explicitly. Subsequent form edits cannot
change the prepared body or idempotency key.

The receipt binds the repository route, tenant, repository incarnation, native
object format, credential fingerprint, complete command and original key. It
contains no bearer token. Protect it as private repository data. Restoring a
receipt validates its commitment and does not dispatch work.

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

Focused client and controller tests live in
`tests/browser/queues-native.test.mjs` and
`tests/browser/queues-view.test.mjs`. Run each directly with the selected Node
runtime to see its registered cases. These tests use explicit API/DOM doubles.
They do not establish live-browser interoperability or native queue correctness.
The existing `queue_http`, `queue_landing_http` and `queue_preparation_http`
native integration targets cover the corresponding service boundaries.

The native wire contracts are documented in
[`NATIVE_HTTP_QUEUES.md`](NATIVE_HTTP_QUEUES.md) and
[`NATIVE_HTTP_QUEUE_PREPARATION.md`](NATIVE_HTTP_QUEUE_PREPARATION.md).
