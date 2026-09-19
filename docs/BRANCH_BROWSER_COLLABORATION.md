# Native branch lifecycle in the browser

The existing source-enabled gateway serves `<repository-route>/ui/branches/`,
linked from the source browser. This is a client of the existing native refs,
branch-admission and outcome APIs. It introduces no repository authority,
object store, dependency, listener, runtime, or alternative branch policy.

## Working path

Connect with an operator-provisioned repository token and load an explicit
SHA-1 or SHA-256 reference snapshot. Branches, tags or all direct references
can be listed. Every continuation retains the original namespace, page size,
last-ref cursor, repository incarnation and authority-head comparison. A
snapshot conflict refuses rather than silently switching to a current page.
Rows are compared as exact bytes. Valid UTF-8 names and non-UTF-8 names are
both displayed with their hex identity; directional display controls are
escaped. Byte-only names cannot be submitted through the native text-form API.
The native list encoder also refuses an unrepresentable byte-only continuation
rather than reporting an invented end of listing.

Select a listed branch and explicitly prepare one operation:

- **Create:** select a branch tip and enter a new full branch name. Admission
  requires an absent destination. Absence from a bounded page is not proof of
  absence and never grants authority.
- **Update:** select an existing branch and another listed branch's exact tip.
  The existing branch's old tip is fixed. The native no-force policy remains
  in charge; the client does not assert that a proposed update is permissible.
- **Delete:** retain the selected branch's exact expected old tip.
- **Rename:** one expected-old deletion and one absent-destination creation
  with the same tip, submitted as a single native atomic command.

Preparation creates only a local frozen request. The interface displays the
exact ref effects and original key, then requires a separate confirmation to
send. Read permission does not imply receive permission. The operator must
also enable Git writes. Existing source, issue, PR, initial-history and history
profiles keep their own API ceilings. The branch transport permits only
`source/refs`, the four named `source/branches/*` operations, and `outcomes`.

A result is accepted only as a complete native `branch_publication`: correct
scope, operation, principal, transaction, terminal outcome, HTTP status and all
ordered expected/new ref effects. A partial, reordered, forced, non-atomic or
inconsistent rename response remains unresolved. No result changes forge state,
retargets PRs, or implicitly changes the default branch. Protected/default
branch constraints remain native admission decisions.

## Recovery without repeating a different operation

Before the first send, the client fixes the operation, canonical form bytes,
original nonce/key, credential fingerprint and repository incarnation. Editor
changes cannot replace the pending request. Network failures and arbitrary
HTTP errors never prove rollback. Explicit retry uses exactly the same body
and key, with no branch-presence read. In particular, a successful rename with
a lost reply must remain recoverable after its old name no longer exists.

Outcome lookup is a bodyless POST with the original key and independent
`outcomes-read` permission. Key-not-observed, seal-not-observed and undecided
states retain responsibility. Previously observed transaction and principal
identities cannot disappear or change silently. A canonical committed or
refused decision clears the request and the now-stale browsing snapshot.

Recovery receipts contain metadata and the original request, not the token.
The key commitment binds origin, route, credential fingerprint, incarnation,
object format, operation, nonce and exact request bytes. Changed command or
scope fields cannot silently reuse the original key. This is not a signed
receipt or a replacement for native authorization. Restore requires the same
credential and route, sends nothing, and needs no preliminary ref lookup.
Exported/restored or sent requests cannot be discarded as unsent local work.
The page warns before leaving with outstanding responsibility. Disconnect
clears tokens and views while preserving the pending request for recovery.

## Bounds and exclusions

Native list pages are limited to 100 rows and 1 MiB. The browser retains at most
2,048 rows from one namespace snapshot, with explicit refusal before exhausting
that session budget. Native names are at most 4,096 bytes. Command encoding
uses the existing 256 KiB ceiling, terminal receipts at most 64 KiB, outcome
responses 32 KiB, and downloaded/restored retry records 64 KiB. File size is
checked before receipt I/O. Delayed reads cannot restore data after disconnect.

No force push, arbitrary-OID source selection, symbolic-ref/default-branch
management, tag mutation, cross-repository operation, automatic retry, policy
editing or inferred approval is added. This product slice advances the
one-node forge workflow; it does not close the comprehensive forge plan or
claim independent verification of the owning admission work.

## Validation boundary

```
node --test tests/browser/branches.test.mjs tests/browser/branches-view.test.mjs
node --test tests/browser/*.test.mjs
```

The implementation run passed 94 new branch tests: 77 client/adversarial cases
and 17 controller/UI cases. The restored selected-file browser fixture passed
326 tests with no failures or skips. Both native hash formats, pinned
pagination, complete atomic rename receipts, hostile ref bytes, closed routes,
frozen retries, all outcome states, tampered receipts and cancellation are
covered. Module syntax and changed-file whitespace checks passed.

HTTP, DOM and File fixtures are test doubles. This was not a complete current
checkout, a real browser session or a live native node. Three Rust static-route
regression tests are supplied but were not executed: Rust/Cargo was unavailable.
Rust compilation, native end-to-end interoperability, full-workspace, Clippy,
independent batch verification and release gates remain unverified.
