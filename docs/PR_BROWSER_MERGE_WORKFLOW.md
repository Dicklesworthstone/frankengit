# Native PR review and merge workflows

## Exact candidate review with native reference bytes

The `/ui/pulls/` page supports candidate preparation, explicit conflict
resolution, independent candidate import, approval, changes requested,
withdrawal, and reviewed merge publication for branch names containing
non-UTF-8 bytes. Select an existing open PR to prepare from its observed branch
bytes, tips and version, or import a candidate exported by another reviewer or
the [merge queue page](BROWSER_MERGE_QUEUES.md). Author, committer, timestamp,
message and policy epoch remain explicit inputs.

Each request supplies exactly one of `source_ref` / `source_ref_hex` and exactly
one of `target_ref` / `target_ref_hex`. Hex is lowercase and represents at most
1024 native bytes; the decoded value must be a valid complete `refs/heads/`
reference. Text and hex may be mixed across the two sides. Duplicate aliases,
missing aliases, malformed hex and invalid reference bytes are rejected before
dispatch. Display labels never become reference identities. Native replies
retain both their optional text label and exact hex bytes; changed bytes fail
validation even when both labels are null.

Importing a `frankengit-browser-candidate-v1` file always uploads its exact
bundle and selected subject to the native inspector again. A checksum or a
saved inspection cannot enable review by itself. The page displays reference
bytes, both tips, PR version, policy epoch, merge base, candidate identity,
parents, bundle commitment and complete changed-path inspection. Preparation
and reinspection create no review or publication. Approve, request changes or
withdraw must be prepared separately and explicitly sent under the reviewer's
own credential. Reviewed merge publication remains a separate command with
explicit reviewer requirements and all current native protection gates.

Queue candidates keep the same candidate commit, merge base, bundle and subject
through export and independent PR reinspection. An exported PR candidate can
be shared again without changing those coordinates. The queue owner retains
the original queue landing guards and submits that exact candidate through the
queue landing endpoint; a candidate file does not grant landing authority or
replace the queue's native checks.

Existing text candidate files and `frankengit-pr-retry-v1` receipts retain their
schema, serialization order, command bodies and idempotency keys. New receipts
preserve the chosen text or hex aliases. Restoring a dispatched review or merge
reconstructs its original multipart/form bytes and key without refreshing
references, policy or versions. An explicitly selected outcome-only recovery
connection may use a replacement credential for the original principal; it
cannot re-inspect, reconstruct or resend the mutation.

PR metadata creation/update/close/reopen still uses the separate text-only
form. The PR fast-forward publication command below is also text-only. A
source-tip candidate imported with hex references may be inspected and
reviewed, but its fast-forward publication control remains unavailable. This
does not restrict the native raw-reference queue landing workflow.

## Fast-forward merges from the PR page

The served `/ui/pulls/` page now offers **Prepare fast-forward merge** for an
open PR with representable recorded branch names and distinct source/target
tips. This completes the browser interaction on top of the existing
[fast-forward HTTP command](FAST_FORWARD_PULL_REQUEST_HTTP.md), rather than
introducing another publication path.

Select a PR, inspect its recorded changes, and prepare the fast-forward request.
The page copies the selected PR number, version, hash format and both recorded
branch names/tips. Editing the separate metadata form cannot replace those
coordinates. Preparation sends no request, creates no candidate commit, and
clears any previous confirmation. The saved request appears in the existing
publication panel. Confirm it explicitly and use **Send / retry exact request**.

The native endpoint remains responsible for current authority, live branch
preconditions, ancestry, independent grants, branch protection, and atomic
publication of the ref move and PR transition. The button is not an ancestry
oracle, approval, or protection bypass. Divergence/refusal never selects force
or a different merge algorithm automatically. The reviewed candidate workflow
remains a separate explicit operation.

A terminal response consumes the selected merge observation: explicitly reload
the PR before preparing another fast-forward. A missing, malformed, revoked,
interrupted or lost reply retains the original pending request. Outcome lookup
does not resend it, and absence does not prove non-commit. Export/restore uses
the existing credential-fingerprint-bound receipt with its original command and
idempotency key; no token or candidate bundle is written into this receipt.
Closed/merged PRs, byte-only names, equal tips, wrong scope/hash domains, and
exhausted exact-integer versions do not become actionable proposals.

## Reproduction and evidence boundary

```sh
node --test tests/browser/pulls-fast-forward-view.test.mjs
node --test tests/browser/pulls-raw-references.test.mjs tests/browser/queues-candidate.test.mjs
CHROME=/path/to/chromium node tests/browser/pulls-fast-forward-chromium.mjs
```

The first command exercises the production view, client, command codecs and
WebCrypto with a controlled DOM/Fetch boundary. It covers both hash domains,
confirmation, hostile form edits, refused proposals, canonical refusal,
disconnect, malformed receipts, and saved-receipt recovery with unchanged keys.
It is not a native-server or real-browser suite.

The raw-reference tests exercise text/hex and mixed subjects in both native
hash domains, queue-to-reviewer handoff, mandatory reinspection, review and
merge staging, binary conflict resolution, exact retry bytes/keys, replacement
credential recovery, and the actual PR view controller. Their HTTP/DOM
boundaries are controlled; they do not establish native admission or
live-browser interoperability.

The Chromium command drives the checked-in HTML and modules in Chromium over a
bounded local HTTP fixture under a restrictive CSP. It requires an explicitly
supplied browser, refuses missing clients, and closes the browser, server and
temporary profile. Its API is controlled: even a pass establishes browser
wiring and HTTP behavior, not native admission or policy correctness. Managed
browsers that disallow loopback cannot run this fixture; that is a non-pass,
not a reason to change the browser's security policy.

The native alias contracts are documented in
[candidate preparation](HTTP_CANDIDATE_PREPARATION_API.md),
[conflict resolution](HTTP_CONFLICT_RESOLUTION_API.md), and
[reviewed merge](HTTP_REVIEW_MERGE_API.md). Native `fg serve-http` integration,
full-workspace gates and independent bead acceptance remain separate
obligations.
