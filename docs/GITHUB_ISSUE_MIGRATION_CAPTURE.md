# Resumable acquisition of a complete issue migration

FG-049's `captureGithubIssueMigration` in
`scripts/lib/github-issue-capture-migration.mjs` connects independently pinned
repository discovery to the complete migration preparer. It captures every fixed
inventory batch, retains completed captures across invocations, and emits the
existing `frankengit-github-issue-migration-sources-v1` selection file. No native
server, native credential, mutation, request key or permission is involved.

## Source lifetime and restart

`operation: 'start'` accepts an absent `workdir`, `inventoryFile` and its
independently retained `inventorySha256`. The inventory is copied privately.
A create-only `session.json` binds its digest, the absolute output directory,
source credential fingerprint (or anonymous selection), number offset and
whole-capture limits. It is synchronized last before source access. Retain the
returned `session_sha256` separately, including from `error.capture_progress`.

`operation: 'resume'` takes only that work directory, its original `confirm`
pin, and the same optional source `tokenFile`. It never rediscovers membership,
changes the partition, rereads completed batches from GitHub, or replaces a
capture. The original external inventory file is no longer needed. A failed
GET may be performed again in an explicit later source session; this is not a
native mutation retry. Every newly captured batch still passes the existing
two-equal-observations, full comment enumeration, source identity, source scope
and native command representability checks.

The shared `createGithubIssueCaptureSession` owns one HTTP deadline and one
request/response-byte/retry allowance across all its batches. Captures within an
owner are sequential; a second overlapping capture refuses rather than mixing
passes. A failed capture closes the owner. The old `captureGithubIssues` entry
point delegates to the same algorithm with its existing per-call defaults.
`createGithubSource` additionally accepts a lower `maxRequests` (1–4096).
Request statistics count actual fetch invocations, not the rejected next call.

The acquisition invocation has one deadline of at most 300 seconds, including
initialization and filesystem checks. Defaults are eight new batches, 4096 HTTP
requests, 64 MiB of successful response bodies and no automatic source retries.
`maxBatches` may be 1–128; `maxReadBytes` may be 1–256 MiB; `maxSourceRetries` may
be 0–10. These per-invocation controls can be changed on resume without changing
selection. Retry behavior and body cancellation remain in the existing source
HTTP owner. Requests are serial, GET-only and use constructed GitHub API URLs.

## Retained captures and complete handoff

Each complete capture is synchronized into
`capture-NNNNNN-<sha256>.json` in the original capture format. Its filename binds
its batch and bytes; there is no mutable last-batch cursor or a separate
per-batch receipt window. Every invocation validates the entire retained prefix,
including exact inventory membership, native text limits and comment identities
across batches. Unknown files, duplicate batches, gaps, changed bytes, symlinks,
hard links and incomplete writes refuse before new network access. Nothing is
automatically erased, evicted, overwritten or repaired.

The persistent envelope is at most 128 batches, 64 MiB of captures and 10,000
native command steps. Each original capture keeps its own 100-issue, 2000-comment
and 1-MiB limits. `maxCaptureBytes`, `maxSteps` and `offset` may be selected at
start and then become immutable. A population exceeding 128 fixed batches must
be repartitioned through a separately reviewed inventory, not changed on resume.

Only after all batches are present and revalidated is `sources.json` written
last. It contains the original inventory digest, every capture's path/digest,
the original offset and the whole-capture bounds. Retain the returned
`sources.sha256` independently and review the capture provenance. This file is
accepted by the existing migration preparation source-selection loader. Capture
completion never implicitly prepares or submits native requests. The destination
preparer still enforces its separate aggregate request-byte and credential rules.

`operation: 'status'` requires the work directory and original session pin. It
reads only retained local files, without source credentials, network access,
writes or locks. It can report a retained owner; it cannot establish that owner
is dead or that a source is currently unchanged. After full capture, resume can
also validate the complete handoff without the source credential or network.
A complete set of captures without a final handoff can be finalized by resume.

One create-only `capture.owner` directory covers network acquisition and final
handoff. Cancellation drains the current HTTP body and releases a stable owner.
SIGKILL or uncertain HTTP body cleanup can retain the lock. There is no PID-based
lock stealing: reconcile the original process before explicit operator repair.
Directory or lock replacement is never cleaned as the original owner. A crash
while writing a capture can leave a suspect file that requires diagnosis rather
than automatic replay. A completed handoff survives subsequent output failure.

## Evidence and limits

The focused target is `tests/operator/github_issue_capture_migration.test.mjs`.
It uses actual source HTTP ownership, discovery/capture codecs, native issue
command encoding and private filesystem operations, with a GitHub response-schema
peer. It covers multi-page comments, full-width numeric aliases, byte equivalence,
restart, bounds, corruption, source changes, credentials, cancellation, ownership
and path replacement. It is not a live GitHub or Rust/native-server test.

The local execution environment used the unchanged first 98 lines of the
production `issues.mjs` module (the complete dependency closure of the native
mutation encoder used by source capture), not its unrelated browser HTTP client.
No Rust code, wire protocol, authority rule or dependency is changed here.

A hash is not GitHub authentication. Two equal source observations are not an
atomic snapshot, and separately captured batches can describe different times.
Quiesce source edits and preserve source visibility. Intermediate files are
trusted local custody until the final selection is independently reviewed and
pinned. Stable owner-controlled parent directories are required; these controls
are not a hostile same-UID sandbox or a filesystem power-loss proof. PRs,
attachments, permissions and actors-as-native-principals are not imported.
