# Native source authoring browser

## Implemented boundary

The source-enabled repository HTTP gateway serves `<repository-route>/ui/source/`.
This is a bounded authoring surface over the existing native source APIs, not a
new repository store, authority, parser backend, listener, or runtime. Source
read permission permits selection, preparation and inspection; publication also
requires the existing receive grant and operator Git-write switch. The public
static shell includes no repository content or credentials. PR and issue
profile enablement is not widened by its shared JavaScript helpers.

The implemented workflow is: select an existing branch and immutable native
commit; load complete files; queue explicit edits or upload a Git patch; prepare
and inspect the native candidate; prepare a local publication request; separately
confirm and send it. Native admission still owns quarantine, object validation,
policy, sealed request identity and exact-predecessor authority CAS. This is a
bounded interface slice of comprehensive-plan sections 17, 24 and 31, not
completion of the forge, `frankengit-asa3`, or the release compatibility matrix.

## Exact file changes and preparation

The editor supports create, modify, delete, and regular/executable mode changes
for up to 64 paths, including binary regular files containing NUL and arbitrary
byte values. A complete file is limited to 256 KiB. Both the combined before/after
input and generated patch are limited to 1 MiB, with an additional 65,536-line
combined-input budget (lines are delimited by LF bytes).
Ancestor/descendant conflicts and duplicate paths are refused. Paths are exact
bytes, including non-UTF-8 names; the browser emits Git C-quoted path headers
and full-file hunks. File content is not normalized by patch construction.
CRLF and missing final newlines are preserved. Empty-file and mode-only changes
use native header-only patch forms.

Loaded bytes are verified against their Git blob identity and must be complete,
not a first page masquerading as a file. Unedited editor content retains the
original bytes. Editing text deliberately applies the selected LF/CRLF policy;
an exact replacement-file upload performs no conversion. File sizes are checked
before asynchronous reads and again after completion. Selection changes and
disconnects invalidate late file reads and candidate preparation.

The native regular-file literal-hunk parser and applier already compare payloads
as byte slices, including NUL. The source editor explicitly opts into those byte
semantics; it does not encode or decode Git's compressed `GIT binary patch`
format. That compressed format, symlinks, gitlinks, copies and renames remain
unsupported by this authoring path. Shared patch-helper defaults stay text-only
unless callers explicitly request binary bytes; the separate initial-history
browser is not widened by this change. Existing-branch source authoring still
requires an existing commit-valued branch and does not initialize a repository,
rewrite history or implement directory moves. Unsupported work refuses rather
than calling Git in production or silently changing semantics.

### Binary uploads, hex editing and exact downloads

The same existing source page can load, create, replace, delete or change the
executable bit of a binary file. No additional endpoint or privilege is needed.
NUL, invalid UTF-8, non-text controls and directional display controls select
hex view automatically instead of being passed through a lossy text decoder.
The full bounded hex editor accepts exact byte pairs with ASCII spacing. An
empty hex value means an empty file, not deletion; deletion is a separate action
retaining the original verified blob and mode. Path labels retain raw hex
identities and escape directional display controls.

Switching between text and hex views preserves the complete original or edited
bytes, including a BOM, CRLF, bare CR and a missing final newline. Switching
binary/non-text bytes to text refuses. Only an explicit subsequent text edit
applies the selected LF/CRLF policy. Hex editing and exact replacement uploads
never perform that conversion. The browser bounds hex text to 786,432 characters
and decoded bytes to 256 KiB before queueing. A permitted many-line patch is
assembled iteratively rather than exceeding JavaScript's argument-count limit.

Replacement-file size and the remaining combined draft budget are checked
before reading its bytes. Failed, truncated or superseded file reads invalidate
the selected replacement: queueing or downloading cannot silently reuse a previous
successful replacement or original blob. The user must explicitly reselect,
clear the failed selection, or edit the draft. Late file and native-read results
cannot repopulate a cleared or disconnected view. Local draft changes invalidate
an earlier candidate without modifying an already frozen publication request.

Download exact draft bytes saves an `application/octet-stream` file with the
fixed name `frankengit-file.bin`. Repository names never choose executable markup
or a download path, and neither download nor hex editing sends an API request.
Download object URLs are released after use and on disconnect/page exit. The
page warns before losing unqueued modified/uploaded bytes as well as queued
edits or pending publication responsibility. Downloads contain repository data,
not independently authenticated evidence of native publication.

Preparation sends only the existing closed native form: ref, object format,
expected commit, author, committer, timestamp and message, plus exact patch
bytes. Commit identity and time are explicit. A changed branch tip is not
silently refreshed. Unrelated authority-head changes need not alter the native
commit precondition; the native service revalidates current authority and policy.

## Candidate verification and publication

Preparation responses carry the native bundle and bounded metadata. The client
checks the exact multipart envelope, patch digest, bundle SHA-256, parent,
repository incarnation, paths and modes. For queued edits it also independently
checks expected old/new Git blob identities. Browser bundles are limited to
16 MiB, deliberately below the broader native profile.

The actual returned bundle then passes native read-only inspection. The browser
checks its SHA-1 or SHA-256 native commit-object identity, single ordered parent,
tree identity, complete changed-path report and prepared effects. A failed or
cancelled preparation cannot retain an older selectable candidate. WebCrypto
hash checks detect identity mismatches; they do not substitute for native
validation, transport trust, verified-read proofs, or authorization.

Preparing publication has no network effect. A separate confirmation sends the
frozen native command, candidate bundle and idempotency key. Editing the page
cannot rewrite that saved request. Native `source_publication` replies use
HTTP 200 for committed decisions and HTTP 409 for canonical refusals; ordinary
HTTP errors do not become terminal decisions. Delivery acknowledgement is not
inferred from canonical visibility.

## Ambiguity and original-request recovery

Before dispatch, the client acquires responsibility for the original request.
Lost, malformed or mismatched replies leave that request unresolved. There is
no automatic retry, new-key retry, implicit rollback, or pre-retry branch-tip
refresh. Outcome lookup sends the original key and no mutation body. Missing
keys, missing seals and undecided observations do not prove non-commit.

A token-free receipt retains the complete candidate and original request.
Its key commits to the exact route, origin, repository incarnation, object
format, credential fingerprint, command, nonce, MIME boundary and request bytes.
Import reconstitutes the same request rather than trusting it as a new inspected
candidate. This is a consistency commitment, not a signature or authority grant;
native admission remains mandatory. Receipt files contain repository data and
must be handled accordingly.

The bounded browser recovery profile requires the original token fingerprint;
it does not yet provide same-principal recovery after token rotation. Outcome
lookup needs its independent outcomes-read grant. A sent or exported request
cannot be discarded as locally unsent. Disconnect clears source data and the
credential but retains unresolved request responsibility for receipt export.
No token is stored in URLs, browser persistent storage, or receipts.

## Local checks and non-claims

Run client/DOM contract tests with:

```sh
node --test tests/browser/*.test.mjs
```

An explicitly non-production Git differential lane applies generated patches in
fresh disposable SHA-1/SHA-256 repositories. It requires the exact chosen Git
binary path, version string and SHA-256 before invocation:

```sh
node tests/browser/source-edit-git-oracle.mjs \
  /absolute/path/to/git 'git version <pinned-version>' <binary-sha256>
```

Its cases cover quoted byte paths, whitespace and separator-like names, empty
creation/deletion, executable bits, CRLF, missing final newline, and non-UTF-8
NUL-free content. The lane reports the concrete binary identity. It is a local
patch-format differential check, not native Rust conformance or a release gate.
No production browser code invokes Git.

The binary-authoring lane exercises the same production browser encoder, not a
parallel patch implementation:

```sh
node --test tests/browser/source-binary.test.mjs tests/browser/source-binary-view.test.mjs
node tests/browser/source-binary-git-oracle.mjs \
  /absolute/path/to/git 'git version <pinned-version>' <binary-sha256>
cargo test --locked -p fgit-diff --test patch_binary_bytes
```

The binary-authoring implementation run passed 296 JavaScript tests: 232 retained
regressions, 35 new binary client/encoder cases and 29 new UI cases, with no
failures, cancellations or skips. UI tests exercise text-area newline normalization,
exact hex/byte downloads, mixed text/binary drafts, failed/superseded uploads,
pre-read aggregate bounds, cancellation, explicit publication confirmation and
unchanged original-key recovery. HTTP/DOM/File fixtures are test doubles.

Pinned non-production Git 2.47.3 passed 192 binary cases across both hash domains,
all 256 byte values, unusual raw paths, create/delete/replace/mode changes,
empty-versus-absent files, CRLF and missing newlines. Each case checks actual
forward and reverse index application, exact blob bytes/modes/native identities,
untouched siblings and restoration of the original tree. The retained NUL-free
Git lane was rerun and passed its 144 cases. Both logs identify the exact Git
executable SHA-256. These are patch-format interoperability checks, not execution
of the native Rust source HTTP/admission pipeline or a signature check.

Eight new Rust integration tests pin existing literal-byte hunk behavior,
including differing context after NUL, control-looking payloads, limits and
refusals. They were not executed because Rust/Cargo was unavailable. There is
no native production Rust change or new route in this binary-authoring batch.
The tests ran in a selected-file browser fixture, not a complete current
workspace checkout. Native compilation, native-node interoperability, real-browser
rendering, Clippy, full-workspace verification and release acceptance remain
unverified; JavaScript or Git-oracle success does not establish those gates.
