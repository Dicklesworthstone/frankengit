# Native issue browser

The issue-enabled one-node HTTP profile exposes `<repository-route>/ui/issues/`.
This thin client uses the existing native issue and outcome services; it creates
no second issue database or publication path. Static assets contain no private
repository data. Source and issue profile switches remain independent, and
shared CSS is available when either profile is enabled. API requests still
require independent `issues-read`, `issues-write`, and `outcomes-read` grants.
Outcome recovery additionally requires its existing endpoint switch.

## Workflow

List issues and page their canonical event history at one explicit snapshot.
Open an issue with an explicit number and version zero, or select an existing
issue to prepare a comment, field edit, close or reopen at its exact version.
Title, body and labels can be replaced independently; an explicitly selected
empty label replacement clears the set. Preparation makes no HTTP mutation.
Inspect the prepared request, save its private recovery receipt, and send it
explicitly. Later editor changes cannot change the prepared body or retry key.
Native text is inert, not executable HTML or rendered Markdown. UTF-8 limits,
exact safe integers, response byte budgets and snapshot continuity are checked.

## Ambiguous outcomes

Only a validated native terminal decision settles a request. Canonical issue
refusals use HTTP 409, while generic conflicts such as key reuse are not new
terminal decisions. Lost responses retain the original body and key. Retry is
explicit and byte-identical; recovery sends only the original key to the
read-only outcome service. Missing keys, missing seals and undecided results
never establish non-commit. Neither terminal decision implies external delivery.

Save the recovery receipt before sending: page memory is not durable. Receipts
contain private draft text, route/origin, the exact request and a credential
fingerprint, but not the token. A random nonce plus a SHA-256 request commitment
prevents a modified saved request from reusing the original key. This is not a
signature or server authority proof. Restoring does not dispatch work, and an
exported or restored request cannot be discarded as definitely unsent. Recovery
requires the original token; operators must not reassign it to another principal.

Tokens live only in page memory. Disconnect clears tokens, visible data and
editors while retaining an unresolved token-free request for recovery. No
cookies, ambient credentials, redirects, external scripts or third-party
requests are used. HTTPS is required except on trusted loopback origins.

## Validation

Run `node --test tests/browser/issues-native.test.mjs tests/browser/issues-view.test.mjs`.
The 27 tests passed locally when landing the initial workflow; they use explicit
DOM/fetch doubles, not a live authority service. Added Rust asset tests cover
independent profile switches, exact routes, framing refusals and response bounds.
Rust/Cargo was unavailable in the implementation environment, so Rust compilation,
workspace gates, actual browser rendering and live-node acceptance remain unverified.
Related integration bridge: `frankengit-asa3`.
