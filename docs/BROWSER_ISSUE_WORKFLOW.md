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
Open an issue with an explicit number and version zero. Select an existing issue
to prepare a comment without an expected version; the browser uses the explicit
`append-comment` intent so concurrent commenters can all publish. Adding
assignees also uses a version-independent intent. Field edits, assignee removal,
close, reopen, lock and unlock still require the exact displayed version.
Title, body and labels can be replaced independently; an explicitly selected
empty label replacement clears the set. Preparation makes no HTTP mutation.
Inspect the prepared request, save its private recovery receipt, and send it
explicitly. Later editor changes cannot change the prepared body or retry key.
Native text is inert, not executable HTML or rendered Markdown. UTF-8 limits,
exact safe integers, response byte budgets and snapshot continuity are checked.

Issue details display the assigned principal IDs. **Add assignees** prepares an
`add-assignees` request without an expected version. Independent additions
preserve each other's assignments and unrelated edits. The current union must
still fit the 16-assignee bound; a competing addition can consume the last slot
before publication. **Remove assignees** prepares an exact-version metadata
delta. Enter one 32-character lowercase hexadecimal principal ID per line, up
to 16 distinct IDs. Removing changes only the named IDs.
The removal editor is prefilled with the current set so it can be narrowed
before preparation. Assignments confer no repository access or membership.
As with comments, preparing, saving a receipt and explicitly sending are
separate actions; editing the form later cannot change the prepared request.

Lists and issue details show whether discussion is locked, independently of the
open/closed state. **Lock discussion** and **Unlock discussion** prepare a
payloadless action at the displayed positive version under the existing
`issues-write` grant. The browser disables comment preparation for a selected
locked issue. Native admission also refuses both strict and append comments
while locked, including a comment prepared before another writer locks it.
Edits, assignments, close and reopen remain available and preserve the lock.
The UI never guesses a replacement predecessor after a stale-version refusal.

## Ambiguous outcomes

Only a validated native terminal decision settles a request. Canonical issue
refusals use HTTP 409, while generic conflicts such as key reuse are not new
terminal decisions. Lost responses retain the original body and key. Retry is
explicit and byte-identical; recovery sends only the original key to the
read-only outcome service. Missing keys, missing seals and undecided results
never establish non-commit. Neither terminal decision implies external delivery.
Lock changes do not rewrite historical outcomes: an identical lock/unlock retry
recovers its original decision, a comment committed before locking still recovers
that commit, and a comment refused while locked remains refused after unlocking.

Save the recovery receipt before sending: page memory is not durable. Receipts
contain private draft text, route/origin, the exact request and a credential
fingerprint, but not the token. A random nonce plus a SHA-256 request commitment
prevents a modified saved request from reusing the original key. This is not a
signature or server authority proof. Restoring does not dispatch work, and an
exported or restored request cannot be discarded as definitely unsent. Recovery
requires the original token; operators must not reassign it to another principal.
Existing saved `comment` receipts retain their exact version, original route,
body and key. Restoring or retrying them never converts them to `append-comment`.
Existing saved `assign` and `unassign` receipts likewise keep their exact version,
original route, body and key. They are never converted to `add-assignees`.
New append and additive-assignee receipts have `expected_version: null`;
changing a profile in a saved receipt fails the original request commitment
check. Additive-assignee terminal replies must identify
`command_profile: "issue.add-assignees.v1"`. Retrying an old successful addition
after a later removal recovers the original result and does not add the removed
principal again. A capacity refusal also remains the original refusal after
capacity is freed; a new attempt requires a new prepared request and key.

Tokens live only in page memory. Disconnect clears tokens, visible data and
editors while retaining an unresolved token-free request for recovery. No
cookies, ambient credentials, redirects, external scripts or third-party
requests are used. HTTPS is required except on trusted loopback origins.

## Validation

Run `node --test tests/browser/issues-native.test.mjs tests/browser/issues-assignees.test.mjs tests/browser/issues-view.test.mjs`.
These focused client/controller tests cover saved legacy request identity,
additive intent preparation, typed terminal replies and response-loss recovery
after a later removal. They use explicit DOM/fetch doubles and do not establish
live-browser interoperability. Rust asset tests separately cover independent
profile switches, exact routes, framing refusals and response bounds. The native
`scripts/e2e/suites/node/issue_assignees.sh` campaign exercises concurrent HTTP
additions and persisted recovery with a prebuilt `FG_BIN`.
Related integration bridge: `frankengit-asa3`.
