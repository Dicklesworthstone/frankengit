# Native cherry-pick and revert in the browser

The source-enabled gateway serves `<repository-route>/ui/replay/`, linked from
source browsing. It connects the existing one-commit native replay, conflict
resolution, candidate inspection and ordinary source publication APIs. No new
authority, Git engine, object store, dependency or runtime is introduced. This
is a bounded forge interface, not completion of the whole web/forge plan.

## Select and prepare

Connect an explicitly provisioned repository token and select destination and
source-history branches in the repository's SHA-1 or SHA-256 domain. Both
branches are read under one exact authority-head comparison; a changed head
refuses rather than combining tips. A same-branch revert needs only one read.
The interface deliberately supports UTF-8 branch names accepted by the existing
source publication form, not an arbitrary object lookup or cross-repository input.

Select cherry-pick or revert, the full native commit ID, explicit author and
committer identities, Unix timestamp and message. The native engine checks that
the chosen commit belongs to the selected visible source history. A merge commit
requires an explicit one-based mainline parent. A root commit has no synthetic
source parent; every resulting candidate has the destination tip as its single
parent. Metadata uses the native UTC `+0000` encoding. Author text is data, not
an authenticated principal or signature.

Preparation is read-only. Clean, conflicted and no-change results are distinct.
No-change is not a successful publication and enables no publication controls.
Arbitrary errors or unavailable history never become an empty/no-change result.
Changes to replay inputs invalidate the old candidate; changes to either branch
or hash format invalidate the selected snapshot too. Nothing refreshes silently.

## Resolve every conflict deliberately

Each reported conflict exposes the exact path bytes, kind and side identities.
No choice is selected by default. The meanings of the sides depend on direction:

- **Ours** is the current destination tree in both operations.
- **Cherry-pick:** base is the selected parent; theirs is the selected commit.
- **Revert:** base is the selected commit; theirs is the selected parent, the
  undo side. It is not the source branch's current tip.

Choose base, ours, theirs, explicit deletion, or a resolved regular/executable
file for every path. Selecting an absent side refuses; it never silently means
deletion. Custom file uploads preserve arbitrary bytes, including NUL and empty
files. Text entry uses an explicit LF or CRLF policy. All file sizes and their
aggregate budget are checked before the first file read. Every choice and its
bytes are captured before asynchronous hashing or network work.

Resolution reproduces the original replay under the same snapshot, exact tips,
selected parent/mainline and commit metadata. Its receipts must match every
original conflict, chosen side, resulting mode and native blob identity. No
missing, duplicate, extra or substituted choice is accepted. Native directory
reconstruction remains the server's responsibility; a directory choice can
expand into descendant changes rather than one file-level diff row.

## Inspect, then explicitly publish

A clean or resolved artifact's exact bundle digest and size are checked before
uploading the actual bundle to the native `source/inspect` endpoint. The client
checks the destination, old tip, candidate, sole parent, snapshot, complete-path
flag and direct before/after tree identities. It reconstructs the expected
commit bytes from the explicit metadata and verifies the native SHA-1/SHA-256
commit identity. Regular-file/deletion resolutions also agree with the resulting
diff. A failed inspection never enables publication.

The interface displays every changed path and its modes/object identities, with
bounded text previews and explicit binary/opaque content notices. It does not
reimplement the three-way replay algorithm or independently prove the complete
pack/tree closure. Native preparation and quarantine retain those duties. A
matching checksum never grants authorization.

Preparing publication creates only a local frozen request. A separate checked
confirmation sends the existing `source/apply` command with its exact expected
destination tip, candidate bundle and original idempotency key. This appends a
single-parent commit; it does not force-rewrite history, move the source branch,
change the default branch or alter PR metadata. Source-history selection is
preparation provenance, not a new source-ref lease at publication time. Current
native destination policy and conditional admission still decide publication.

## Lost replies and original-request recovery

Network failures, timeouts and disconnects leave the original request pending.
Explicit retry sends exactly the same bytes and key without rerunning replay,
resolving conflicts again or reading newer refs. A changed form cannot alter the
saved effect. Arbitrary HTTP 409 errors are not terminal decisions; only a
validated matching native committed/refused receipt settles the request.

Bodyless outcome lookup uses its own read grant. Key-not-observed,
seal-not-observed and undecided results retain uncertainty; none proves rollback.
A previously observed transaction or principal cannot silently change or vanish.

Token-free recovery files use the existing `frankengit-source-retry-v1` format.
They interoperate with the ordinary source editor because replay publication is
that same source command. Restore requires the original route, credential and
repository incarnation, verifies the original request commitment, and sends
nothing. It does not manufacture a new key or require a live source-history
read. Sent/exported/restored requests cannot be discarded as unsent local work.
Recovery files contain repository bytes and must be protected independently of
tokens. Page exit warns of outstanding responsibility; disconnect clears tokens,
draft metadata, conflict file controls and candidate views.

## Bounds and native grants

The static shell requires `allow_source`. Selection, preparation, resolution
and inspection require the native source-read grant. Publication additionally
requires native receive permission and the operator's write enablement. Outcome
lookup requires its independent grant. The browser transport admits only these
replay/source operations and outcomes; existing profiles gain no replay routes.

The browser permits 64 conflicts, 256 KiB per custom file, 1 MiB combined custom
bytes, a 256 KiB encoded command, a 16 MiB bundle and 1 MiB preparation metadata.
Native preparation is further narrowed to 8 MiB generated output and 256 KiB
text-merge inputs. Inspection replies are bounded to 8 MiB, with at most 512
changed paths through the existing comparison validator. Displayed text is
limited to 256 KiB combined and explicitly labels omitted previews. Recovery
files are bounded to 24 MiB; timestamps and coordinates require exact safe
integers. Server/configuration limits can narrow these ceilings further.

No multi-commit rebase, force update, automatic conflict choice, signing,
cross-repository replay or bypass of protected-branch review is added. Raw paths
and binary resolution bytes remain lossless; repository strings enter DOM text
only and directional display controls are escaped. Cancellation, file replacement
and late HTTP/hash results cannot repopulate a cleared candidate.

## Executable evidence and remaining gates

```sh
node --test tests/browser/replay.test.mjs tests/browser/replay-view.test.mjs
node --test tests/browser/*.test.mjs
node tests/browser/replay-git-oracle.mjs /absolute/pinned/git \
  'git version 2.47.3' <expected-sha256-of-executable>
```

The selected-file implementation fixture passed 341 JavaScript tests: 75 new
client/protocol cases, 34 interface/import-route cases, and 232 retained browser
regressions. No failures, cancellations or skips. Tests cover both formats and
directions, explicit mainline/root semantics, exact native-shaped inspection,
binary/empty conflict files, malformed artifacts, resource limits, cancellation,
confirmation, original-key retries and cross-editor recovery interoperability.

The explicitly non-production Git 2.47.3 lane passed 44 checks over ten scenarios
across both hash formats. It runs real cherry-pick/revert, root cherry-pick and
merge-mainline operations, then checks the resulting exact commit bytes, native
identities, parents and tree/path identities through the browser validator.
Metadata/parent substitutions refuse, and the disposable repositories pass
strict Git fsck. The executable hash is pinned and recorded. Authority/HTTP
reports in this lane are synthetic: it is Git-object/browser interoperability,
not execution or differential verification of the native Rust replay algorithm.

JavaScript tests use HTTP/DOM/File doubles in a selected-file fixture, not a full
current repository checkout or live browser. Three Rust static-route tests are
included but were not executed because Rust/Cargo was unavailable. Native
compilation, live-browser/native-node interoperability, full-workspace tests,
Clippy, independent verification and release acceptance remain unverified.
