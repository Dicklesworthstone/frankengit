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
for up to 64 paths. A complete file is limited to 256 KiB. The generated patch
is limited to 1 MiB, with an additional 65,536-line combined-input budget.
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

The native regular-file patch profile does not support binary patches,
NUL-containing content, symlinks, gitlinks, copies or renames. This first surface
requires an existing commit-valued branch; it does not initialize an empty
repository, rewrite history, or implement directory moves. Unsupported work
refuses rather than calling Git in production or silently changing semantics.

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

The authoring-session test report covers the retained selected-file browser
fixture, not a full current workspace checkout. DOM, HTTP and File test doubles
exercise the client contracts. Rust static-route tests are included separately;
Rust compilation, native-node interoperability, real-browser rendering, Clippy,
full-workspace verification and release acceptance require their actual lanes
and are not implied by JavaScript or Git-oracle success.
