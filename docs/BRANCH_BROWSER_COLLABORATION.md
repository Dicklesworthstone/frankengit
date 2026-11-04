# Native branch lifecycle in the browser

The existing source-enabled gateway serves `<repository-route>/ui/branches/`,
linked from the source browser. This is a client of the existing native refs,
branch-admission and outcome APIs. It introduces no repository authority,
object store, dependency, listener, runtime, or alternative branch policy.

## Working path

Connect with an operator-provisioned repository token and load an explicit
SHA-1 or SHA-256 reference snapshot. Branches, tags or all direct references
can be listed. Every continuation retains the original namespace, page size,
last-ref cursor, repository incarnation and authority-head comparison. Branch
list requests explicitly select native hex cursors, so a nonfinal page ending
at a byte-only branch can continue without inventing a text name. A
snapshot conflict refuses rather than silently switching to a current page.
Rows are compared as exact bytes. Valid UTF-8 names and non-UTF-8 names are
both displayed with their hex identity; directional display controls are
escaped. Single-operation text commands require UTF-8 names; the atomic batch
path keeps raw `ref_hex` identities and accepts listed byte-only branches.
The default UTF-8 cursor validator remains available for callers selecting that
legacy profile; a response cannot silently switch cursor encodings.

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
`source/refs`, the four named single-operation `source/branches/*` routes,
`source/branches/transaction`, and `outcomes`.

## Coordinated branch changes

The same page stages a bounded mixed batch over the existing native
[atomic branch transaction API](HTTP_BRANCH_TRANSACTIONS.md). Select a create,
update or delete, then choose **Add exact change to atomic batch**. Each addition
immediately captures its target's expected old OID and its new OID, where
applicable, from the pinned reference listing. Every target is an exact raw
reference-byte identity. Each branch can appear once; duplicate targets,
unchanged updates, unlisted sources, tags and unsupported operations refuse
locally. New destination names use validated UTF-8 text. A byte-only listed
branch can supply a new tip or be updated or deleted through the batch.

Up to 32 changes can be staged. Individual changes can be removed, or the
unprepared batch cleared, without submitting a request. Loading a continuation
at the same snapshot preserves every captured tip. Loading a fresh snapshot,
cancelling the view or disconnecting clears unprepared staging. Preparation
then freezes all changes as one pending request; controls cannot substitute
later tips. Existing single-operation preparation requires an empty staging
list, so it cannot silently discard staged work.

The full effects preview includes every expected absence, old OID, new OID,
deletion, raw reference identity and the original key. A separate confirmation
sends exactly one native request. The form contains one `object_format` and
ordered repeated `create`, `update` and `delete` fields, with raw hex names and
canonical bare OIDs. The gateway makes one native atomic admission: the entire
batch commits or refuses together. No series of independent publications or
client-side rollback is used. This browser profile intentionally excludes a
rename batch item; the existing single atomic rename remains available.

A result is accepted only as a complete native `branch_publication`: correct
scope, operation, principal, transaction, terminal outcome, HTTP status and all
ordered expected/new ref effects. A partial, reordered, forced, non-atomic or
inconsistent rename or batch response remains unresolved. In particular, every
ordered batch effect must match, including exact byte-only names and both OIDs;
a successful subset cannot settle the whole request. No result changes forge state,
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

Single-operation receipts retain the existing `frankengit-branch-retry-v1`
schema and key commitment without changes. Atomic batches use the distinct
`frankengit-branch-transaction-retry-v1` schema with a closed ordered array of
raw-hex changes. Relabelling either receipt type as the other is rejected.
The key binds the operation and complete original serialized body, including
batch order. An imported batch restores all original effects without listing
refs or sending anything. Preparation checks that the whole batch, including
space for the largest JSON-escaped transaction/principal recovery observations, will fit a
downloadable receipt. An oversized batch stays unprepared so changes can be
removed. Download status asks the user to verify that the offered file was
saved; it does not claim durable storage.

## Bounds and exclusions

Native list pages are limited to 100 rows and 1 MiB. The browser retains at most
2,048 rows from one namespace snapshot, with explicit refusal before exhausting
that session budget. Transaction names enforce the native 1,024-byte reference
ceiling. Command encoding uses the existing 256 KiB ceiling. Single-operation
decision responses are at most 64 KiB and complete batch decisions at most
512 KiB; outcome responses are 32 KiB and downloaded/restored retry records
64 KiB. A batch can hit the receipt byte limit before its 32-operation count
limit. File size is
checked before receipt I/O. Delayed reads cannot restore data after disconnect.

No force push, arbitrary-OID source selection, symbolic-ref/default-branch
management, tag mutation, cross-repository operation, automatic retry, policy
editing or inferred approval is added. This product slice advances the
one-node forge workflow; it does not close the comprehensive forge plan or
claim independent verification of the owning admission work.

## Validation boundary

```
node --test tests/browser/branches.test.mjs tests/browser/branches-transaction.test.mjs tests/browser/branches-view.test.mjs
node --test tests/browser/*.test.mjs
```

The focused suites cover both native hash formats, pinned pagination, complete
atomic rename and mixed-batch receipts, byte-only branches, hostile display
text, closed routes, exact frozen retries, all outcome states, tampered receipts,
historical v1 receipt compatibility, preparation and in-flight cancellation,
operation/byte limits, and controller confirmation and recovery flows.

HTTP, DOM and File fixtures are test doubles. Passing them establishes the
browser client's contract under those fixtures, not a live native-node or real
browser end-to-end result. Native admission remains the existing API's
responsibility; this browser addition changes no backend policy or route.
