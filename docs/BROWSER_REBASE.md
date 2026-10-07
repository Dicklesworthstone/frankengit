# Linear branch rebase in the source browser

The source-enabled gateway serves `<repository-route>/ui/rebase/`, linked from
source browsing. It uses the existing native rebase prepare/resolve/inspect/apply
APIs. It neither runs Git nor adds a store, publication authority, force bypass,
PR retargeting or default-branch change.

## Select, resolve, inspect, publish

Connect a scoped token and select distinct source and onto branches. Both root
reads must share one authority snapshot. Supply the full upstream object ID,
explicit empty-commit policy, new committer and timestamp. The native engine
checks that `(upstream, source]` is a supported linear suffix; it does not flatten
merge commits. A changed source tip or snapshot refuses instead of refreshing a
precondition silently.

Each conflict requires an explicit base, ours, theirs, deletion or file choice.
Here ours means onto plus the replayed prefix, and theirs is the original commit
being replayed. Missing sides never imply deletion. File resolutions support
regular/executable modes, UTF-8 with explicit LF/CRLF conversion, hexadecimal
bytes or exact binary uploads, including empty and NUL-containing files. Every
upload size and the cumulative recipe budget are checked before the first read.

Recipes bind ORIGINAL commit IDs and exact byte paths. The same file can receive
different choices at successive commits. Earlier accepted recipes remain intact
when a later commit conflicts or becomes empty. At a became-empty stop, Continue
with Drop or Keep changes only the series' empty policy: source, onto, upstream,
committer, timestamp and earlier recipes are retained. This policy applies to
commits that become empty, not originally empty commits. Failed continuations
retain the stopped session and cannot enable publication.

A stopped prefix is only an explanation; it has no publishable bundle. Every
complete candidate, including a wholly dropped series with zero new commits,
must pass native inspection of the ACTUAL bundle. The browser checks its digest,
every rewritten commit hash, single parent, tree and committer, and full net and
per-commit diff coordinates. The UI displays the net source-branch change and
every rewritten commit. Binary/object-only/identical changes stay distinct.
Escaped previews are bounded; repository bytes are text nodes, never markup.

Preparing publication sends nothing. A separate checkbox confirms the source
branch, exact old tip, onto and final candidate before EVERY send or unchanged
retry. The expected old source is not confused with the onto pack prerequisite.
Native admission retains authorization, branch protection, object/closure
validation and the exact-old ref transaction. A candidate equal to the source
tip is not submitted as a rewrite.

## Recovery and cancellation

Lost or inconsistent publication replies retain the frozen body and original
idempotency key. Read-only outcome lookup sends no mutation body and never treats
absence as rollback. Token-free receipts preserve publication across reloads;
restoring one neither repeats rebase nor rereads moved branch tips. A sent or
exported request cannot be discarded as locally unsent. The original credential
fingerprint is required; rotation-aware same-principal recovery is not provided.

Disconnect/page exit clears credentials, recipes and candidate views, preserving
an outstanding publication in memory for receipt export. Closing the page needs
a saved original-request receipt for publication recovery. Unsent work can be
saved separately as an explicit draft, described below; nothing is persisted
automatically. Read cancellation never claims non-commit. No automatic retries,
local storage, third-party requests or credentials in URLs are introduced.

## Portable drafts for unsent work

**Save rebase draft** downloads `frankengit-rebase-draft.json`. It retains both
exact branch tips and trees, the original snapshot and repository scope, upstream,
committer/time, empty-commit policy, chosen commit ceiling and accepted earlier
conflict recipes. A recipe binds its ORIGINAL commit and exact byte path, side
identities, choice, and any custom file bytes/mode. Binary, executable and empty
files survive without text conversion. The same path at successive commits
remains separate work.

Current form edits are not silently accepted: to include the current conflict,
select **Include every current conflict choice** and complete all its choices.
The complete file-size and cumulative budgets are checked before reading uploads.
An incomplete set refuses the save rather than silently omitting selected paths.
Without that option, the download contains accepted earlier recipes only; the
status explicitly warns that current unsubmitted choices are excluded. Saving
never calls preparation, resolution, inspection or publication. A download request
is not proof that a browser or filesystem completed the save.

**Load draft locally** accepts the exact saved file under the same origin and
repository route. It makes no repository request and restores no candidate,
inspection, approval, publication body, key or credential fingerprint. The file
contains no access token. Any connected appropriately scoped credential can later
request revalidation; the draft itself grants nothing. Publication/recovery
receipts use their separate existing format and cannot be loaded as drafts.

The loaded settings and retained-recipe counts are displayed as unvalidated work.
**Resume saved draft (read only)** first authenticates both branch selections
using the original snapshot and compares their exact commits, trees and scope.
Only then does it upload saved resolutions to the existing native prepare/resolve
API. Every returned conflict receipt must match the saved original conflict and
chosen side or exact file identity. A complete result must again pass native
inspection of its actual bundle before publication can be prepared. Stale pins,
changed scope, failed inspection or cancellation leave no publishable candidate;
failed resume retains the draft for inspection/export rather than refreshing tips.
A stopped result can continue through the existing conflict/empty-policy controls.

Draft JSON has a closed schema and a SHA-256 checksum over its origin, route and
exact compact payload. The checksum detects accidental changes, NOT authorship or
intent: an adversary can rewrite it. Duplicate keys, unknown fields, oversized
inputs, unsafe paths, duplicate/overlapping paths within one original commit,
wrong hash widths, unsupported modes, implicit deletion and widened budgets
refuse. File decoding/hash work follows complete descriptor preflight. Drafts
remain subject to 32 commits, 64 choices, 256 KiB per custom file and 1 MiB of
combined path/file bytes; the serialized file is at most 3 MiB. Use the exact
generated JSON rather than pretty-printing or editing its wrapper.

A pending publication blocks draft save/load/resume. Save its ORIGINAL-REQUEST
receipt instead: resuming an unsent draft is never evidence that an older write
did not commit. Loading a draft is an explicit replacement of local unsent work;
invalid imports cannot replace the prior branch/recipe session. Selecting a file
cancels an obsolete candidate view. Disconnect clears loaded drafts and file
controls; page-exit warnings include loaded but not yet resumed work. Download
handles are revoked on disconnect or expiry. No new endpoint, asset route, native
engine, authority model, dependency or automatic storage was introduced.

## Bounds and evidence

The existing client ceiling is 32 linear commits, now narrowable per request,
and 64 cumulative conflict choices. Custom files are at most 256 KiB; recipe
paths and bytes share 1 MiB. Bundles and inspection responses are each at most
8 MiB. Inspection retains at most 128 changed paths, 64 text files and 512 hunks
across the series, with a shared 1 MiB path/hunk allowance. Commit bodies are at
most 256 KiB each and 2 MiB combined. Native preparation and inspection share one
60-second default read deadline, separately from per-request transport bounds.
The native service can refuse work inside these browser ceilings.

This integrates the previously delivered interface with the concurrent client
at `0eae6506`, not a replacement copy of that client. Existing request/recovery
formats and native publication remain unchanged. The browser verifies supplied
bytes, not authority signatures, replay equivalence or original-author/message
fidelity. Those remain native-server claims. Public-history rewrites can affect
collaborators even when the exact-old transaction succeeds.

```sh
node --test tests/browser/rebase-session.test.mjs tests/browser/rebase-view.test.mjs
node tests/browser/rebase-git-oracle.mjs \
  /absolute/path/to/git 'git version <exact-version>' <executable-sha256>
node --test tests/browser/rebase-drafts*.test.mjs
node tests/browser/rebase-drafts-browser.mjs /absolute/path/to/chromium
```

The original interface implementation run (published at `53c52b0a`) executed
40 focused tests (18 session/continuation and 22 interface/import-route cases)
plus 232 retained source/issue/PR/authoring regressions: 272 passed, no failures
or skips. HTTP/DOM/File fixtures were explicit test doubles; commit hashes used
actual WebCrypto. That selected fixture was NOT the full repository/browser suite.
These historical results are not a current workspace gate.

The draft client at local fixture `910e3309113fc3d27dfccfb06c60e0feaf2219a7`
(published byte-identically at `d1b94ffe`) passed 66 new tests. The UI increment
adds 16 HTML-derived DOM tests and two actual loopback HTTP/Node-Fetch tests.
The latter preserve binary/empty uploads and original-key retry/recovery over
real sockets, but their server still supplies synthetic native-wire responses.
No native Rust algorithm or admission execution is established by these tests.

The Chromium command serves the exact page/modules under the shell CSP, then
drives real controls, File uploads, downloads and Fetch against that same
explicit protocol double. In this implementation environment Chromium refused
the FIRST loopback navigation with `net::ERR_BLOCKED_BY_ADMINISTRATOR`; zero
browser scenarios executed. Its authored scenario assertions are not pass
evidence. The command fails nonzero on navigation, browser or assertion errors.
It is browser/client coverage, never a substitute for `fg serve-http` E2E tests.

Pinned non-production Git 2.47.3, executable SHA-256
`356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60`, previously
passed eight real-rebase scenarios and 113 checks in SHA-1/SHA-256: ordinary
replay, original empty commits, kept/dropped redundant changes, exact parents
and metadata, binary contents, raw-path siblings, bundle verification and strict
fsck. The browser validated reports constructed from those real objects, not
native server replies. This historical compatibility lane was not rerun for drafts.

Rust/Cargo is unavailable in the draft environment. No Rust code changed in the
draft increments; native compilation, native route tests, live-node execution,
Clippy, full-workspace and release gates were not run. No bead closure or release
readiness is claimed.
