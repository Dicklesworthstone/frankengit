# Initial history through the source browser

## Product boundary

An operator's source-enabled gateway serves `<repository-route>/ui/initial/`.
The existing source editor links to this page. It creates a root commit on an
absent branch of an **already initialized FrankenGit node**; it does not create
an authority namespace or provision a new repository. No existing branch is
updated, no synthetic parent is introduced, and the default branch is unchanged.

This is a human-facing composition over the existing native initial-commit
engine, not a second authority or object store. It advances the one-node forge
composition without asserting closure of `frankengit-asa3` or the complete
forge plan. The editor for existing history remains documented separately in
[SOURCE_BROWSER_AUTHORING.md](SOURCE_BROWSER_AUTHORING.md).

The shell and byte-identical shared helper modules require `allow_source`.
Static assets contain no repository data. Every request is authenticated by the
existing native endpoint: preparation uses the source read grant; publication
also requires the independent receive grant and operator Git-write enablement;
recovery requires outcomes-read. PR and issue permissions do not grant these
operations. The initial client's transport permits only `source/initial/prepare`,
`source/initial/apply`, and `outcomes`, not the existing source-edit or PR APIs.

## Complete workflow

1. Connect an explicitly provisioned repository token, name a full branch and
   the native SHA-1 or SHA-256 format, and explicitly select expected absence.
   A missing/hidden branch response is never used to infer creation authority.
2. Queue exact regular-file bytes with mode `100644` or `100755`. Paths may be
   UTF-8 text or exact lowercase hexadecimal bytes. Uploads preserve arbitrary
   non-NUL bytes, line endings, and final-newline presence. Text edits explicitly
   select LF or CRLF. Empty files and nested directories are supported.
3. Enter author, committer, Unix timestamp, and message. Preparation submits a
   creation-only patch to the native `source/initial/prepare` endpoint. An
   optional authority snapshot is a preparation comparison, not a branch lease.
4. Inspect the displayed complete file manifest, root tree, root commit,
   metadata, patch digest, and bundle commitment. A native preparation artifact
   is not an authority publication. Changing files, branch, format, snapshot,
   or commit metadata invalidates the candidate rather than refreshing it.
5. Prepare a publication request locally, then separately confirm and send its
   exact branch, candidate, bundle, and original idempotency key. Native
   `source/initial/apply` owns quarantine, closure validation, sealed admission,
   and the atomic expected-absent ref transition. The application request has
   no parent, current-head refresh, force option, or default-branch side effect.

## Verification before publication

Before network preparation, `initial-plan.mjs` computes every requested blob,
all containing trees in Git's virtual-slash name order, and the zero-parent
commit. Duplicate identical bodies share an object; the complete object count
and unique-body bytes are bounded. File-order changes do not change this plan.
The root commit uses the exact submitted metadata and UTC offset `+0000`.

The response must match this independently constructed root tree and commit,
exact commit body, sorted file paths, modes, lengths, blob identities, object
count, and patch SHA-256. Parents and bundle prerequisites must be empty. The
bounded multipart envelope and bundle SHA-256 must also match, and all
no-staging/no-publication/default-branch flags must retain their native meaning.
Missing, extra, reordered, malformed, or changed file records fail closed.

The browser does **not** decode or verify the pack inside the bundle, prove
server authority, or authorize publication from a matching checksum. The
native publisher still validates the actual submitted bundle against the
candidate and its complete object closure. This is deliberately distinct from
the existing single-parent editor's native inspection endpoint; no synthetic
parent or inapplicable inspection request is manufactured for a root commit.

## Lost replies and original-key recovery

Preparing the publication request sends nothing. Its command, bundle, multipart
bytes, nonce, and idempotency key are frozen. The key commitment covers the
origin, route, credential fingerprint, repository incarnation, hash format,
branch, expected-absent flag, candidate, and exact body digest. Editor changes
cannot alter that request. No background retry or replacement key is generated.

A send error or disconnect retains the original request and reports unknown
outcome. Explicit retry sends the same bytes and key without a preliminary
branch-presence read: native terminal recovery must precede branch absence
checks. Otherwise an already successful creation could be mistaken for failure
because its branch now exists. Validated canonical HTTP 409 refusals are
terminal; arbitrary conflict responses are not.

Read-only recovery posts the original key without a body. Key-not-observed,
seal-not-observed, and undecided observations retain responsibility; none proves
non-commit. An observed transaction/principal cannot be silently replaced later.
Token-free recovery receipts preserve the original request across reloads and
must be restored under the original credential, route, and incarnation. Restore
sends nothing. A sent or exported request cannot be discarded as an unsent one.
Receipts contain repository bytes and must be protected separately from tokens.

## Bounds and unsupported operations

The browser narrows, never widens, the native ceilings: 64 paths; 256 KiB per
file; 1 MiB generated patch; 4,096-byte paths with at most 64 components; at most
8,192 unique Git objects and 8 MiB of unique object bodies; 1 MiB metadata,
16 MiB bundle, and 24 MiB recovery receipt. Command encoding retains the
existing 256 KiB ceiling. All coordinates use exactly representable integers.
File sizes and aggregate draft budgets are checked before file reads.

NUL-containing files, symlinks, gitlinks, binary patches, copies, renames,
modifications/deletions of existing history, and parented commits are unsupported
here. Source bytes are DOM text, never HTML. Credentials are memory-only and
cleared on disconnect/page exit; late reads cannot restore cleared draft data.
The page warns before losing local files or outstanding publication responsibility.

## Local evidence and remaining gates

Repository-owned focused commands:

```sh
node --test tests/browser/initial.test.mjs tests/browser/initial-view.test.mjs
node --test tests/browser/*.test.mjs
node tests/browser/initial-git-oracle.mjs
```

The implementation run passed 107 new client/UI tests (79 client, 28 UI) and
339 tests in the restored selected-file browser fixture, with zero failures or
skips. Tests cover both hash domains, hostile manifests and envelopes,
missing/extra files, complete closure construction, independent profile routing,
file and network cancellation, frozen creation-only requests, canonical
refusals, all recovery states, and tampered saved receipts.

The explicitly non-production Git oracle pins Git 2.47.3 and reports its binary
SHA-256. Its 140 checks exercise real index patch application, blob/tree/commit
identities, exact root commit bytes, and file-order determinism across both
hash formats, including non-UTF-8 paths/content, virtual-slash tree ordering,
empty files, modes, and final-newline variants. It does not run in production.

The JavaScript suite uses DOM/File/HTTP doubles in a selected-file fixture, not
a current full checkout or a live native node. Three Rust static-handler tests
are supplied but were not executed because Rust/Cargo was unavailable. Native
compilation, live-browser and live-node interoperability, full-workspace,
Clippy, independent batch verification, and release gates remain unverified.
