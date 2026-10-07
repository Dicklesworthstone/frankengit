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
   bytes, including NUL, line endings, and final-newline presence. Text edits
   explicitly select LF or CRLF; hexadecimal entry bypasses text conversion.
   Empty hex input creates an empty file, not a deletion. Multiple files or one
   directory can be imported as an atomic local batch, as described below.
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

## Binary project import

Use **Queue selected files atomically** for multiple files, or **Queue directory
contents atomically** for a browser directory selection. Choose a common regular
or executable mode and an optional repository directory prefix explicitly. The
browser does not expose original executable bits; imported file names never
infer them. The single-file editor can replace an individual queued file with
an explicitly chosen mode or byte content before preparation.

Directory import validates the complete browser-supplied relative paths and one
common top-level folder, removes exactly that folder, and preserves the nested
path suffix. A prefix such as `vendor/project` is prepended without path
normalization. The application applies no ignore rules or hidden-file filters to
selected files. A selected `.git` component, traversal component, duplicated
name, file/directory overlap, or already queued destination rejects the entire
batch. Use a source-only directory rather than silently dropping Git metadata.
For individual non-UTF-8 paths, use the existing hexadecimal path control;
browser directory names are supplied as text.

Before the first read, the importer checks the selected FileList count, every
path and mode, every file size, and the combined retained/new byte budget. It
captures file identities and descriptors, reads exact bytes, then validates the
complete generated patch. Only a complete result replaces the queue. A late read
failure, truncation, encoded-patch overflow, disconnect or changed selection
cannot leave a successful prefix behind. Cancellation waits for an in-progress
File read to settle, discards its result and prevents subsequent reads; it does
not claim to abort the browser's underlying file operation.

Imports are local queue operations: no API request, history discovery, repository
creation or publication occurs. All files still enter one creation-only native
preparation and the existing separately confirmed publication. An outstanding
publication blocks imports; its original-key recovery remains unchanged. Failed
replacement/import attempts invalidate any older candidate and confirmation
without destroying the previously queued files. Byte previews are inert, escaped
and limited to 4,096 bytes per file; they are not evidence of full-file content.

The file picker supplies selected regular-file bytes, not a host filesystem
manifest. Symlink identities, empty directories, permissions beyond the explicit
regular/executable mode, unselected files and existing Git history are not
imported or claimed complete. Directory selection requires browser support for
`webkitdirectory`; the ordinary multiple-file control remains separate.

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
file; 1 MiB combined input bytes and 1 MiB generated patch; 4,096-byte paths with at most 64 components; at most
8,192 unique Git objects and 8 MiB of unique object bodies; 1 MiB metadata,
16 MiB bundle, and 24 MiB recovery receipt. Command encoding retains the
existing 256 KiB ceiling. All coordinates use exactly representable integers.
File sizes and aggregate draft budgets are checked before file reads.

Symlinks, gitlinks, compressed Git-binary-patch uploads, copies, renames,
modifications/deletions of existing history, and parented commits are unsupported
here. Source bytes are DOM text, never HTML. Credentials are memory-only and
cleared on disconnect/page exit; late reads cannot restore cleared draft data.
The page warns before losing queued files or outstanding publication responsibility.

## Local evidence and remaining gates

Repository-owned focused commands:

```sh
node --test tests/browser/initial.test.mjs tests/browser/initial-view.test.mjs \
  tests/browser/initial-import.test.mjs tests/browser/initial-import-view.test.mjs \
  tests/browser/initial-import-http.test.mjs
node tests/browser/initial-import-git-oracle.mjs \
  /absolute/path/to/git 'git version <exact-version>' <executable-sha256>
```

The binary-import increment's selected-file run contains 197 passing tests:
59 new client/import cases, 29 new HTML-derived DOM cases, two new real loopback
HTTP/default-Node-Fetch cases, and 107 existing initial-client/UI regressions.
The enclosing implementation commit records the exact tested local revision.
The two former NUL-refusal expectations now distinguish supported byte content
from malformed byte containers and still reject unsupported file modes. Other
initial-publication/recovery assertions are retained. These are not the full
current repository or browser suite.

The pinned non-production Git 2.47.3 executable (SHA-256
`356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60`)
passed 16 scenarios and 720 checks across SHA-1/SHA-256: actual patch/index
application, exact blob/tree/root-commit identities, content/modes, deduplicated
objects, byte-path ordering and strict fsck. Corpora include all 256 byte values,
embedded patch-marker lines, 64-file and 256-KiB-file boundaries, raw paths,
empty files and executable files. This validates generated-patch interoperability,
not the native Rust initial-commit algorithm or its publication pipeline.

The HTTP tests use actual sockets and default Fetch, but their server returns
explicit synthetic native-wire replies. They check exact binary patch uploads,
creation-only fields, lost replies, unchanged restored retries and bodyless
outcome lookup. DOM/File tests do not establish real-browser rendering. The
Chromium attempt was blocked at its first navigation by
`ERR_BLOCKED_BY_ADMINISTRATOR`; zero browser scenarios executed.

No Rust or shared transport/publication source changes are part of this import
increment. Native compilation, live `fg serve-http` interoperability, Rust
static-handler tests, full-workspace tests, Clippy, independent verification and
release gates remain unverified. The native service may refuse work within the
browser's declared limits; no production-readiness or bead closure is claimed.
