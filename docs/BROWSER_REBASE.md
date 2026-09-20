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
a saved receipt for recovery; unsent rebase drafts/recipes are not persisted.
Read cancellation never claims non-commit. No automatic retries, local storage,
third-party requests or credentials in URLs are introduced.

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
```

The implementation run executed 40 focused tests (18 session/continuation and
22 interface/import-route cases) plus 232 retained source/issue/PR/authoring
regressions: 272 passed, no failures or skips. HTTP/DOM/File fixtures are explicit
test doubles; commit hashes use actual WebCrypto. The selected fixture is NOT
the full current repository or its full browser suite. Existing upstream rebase
protocol tests are preserved, not replaced by the additional session fixture.

Pinned non-production Git 2.47.3, executable SHA-256
`356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60`, passed eight
real-rebase scenarios and 113 checks in SHA-1/SHA-256: ordinary replay, original
empty commits, kept/dropped redundant changes, exact parents and metadata,
binary contents, raw-path siblings, bundle verification and strict fsck. The
browser validates reports constructed from those real objects, not native server
replies. This is compatibility evidence, not native replay or authority testing.

Rust/Cargo is unavailable. Native compilation, the three Rust route-test
functions, real-browser rendering, live HTTP/admission, Clippy, full-workspace
and release gates were not executed. No bead closure or release readiness is
claimed.
