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

`operation: 'prepare'` performs the same offline session creation, without
starting source access. It returns the original pin for a subsequent resume.

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

## Command workflow

Use Node.js 22.16 or later and a stable owner-private parent directory. First
obtain and independently retain the inventory pin using the existing discovery
command in [GITHUB_ISSUE_INVENTORY.md](GITHUB_ISSUE_INVENTORY.md). Quiesce source
edits and review its membership. Example paths below must be replaced with your
selected deployment; the source token is a GitHub read credential, not a native
FrankenGit credential.

```sh
node scripts/capture_github_issue_migration.mjs start \
  --workdir /srv/migration/source-captures \
  --inventory /srv/migration/inventory.json --inventory-sha256 "$INVENTORY_SHA" \
  --token-file /srv/operator/github-read-token --max-batches 8
```

`start` prints a `github_issue_capture_session_ready` JSON row containing the
original `session_sha256` **before any network request**, then captures missing
batches. Save that pin independently as `SESSION_SHA`. A broken initial output
stops before source access; SIGKILL after network begins cannot lose the already
emitted session reference. A final JSON row describes the captured prefix or
complete handoff. Source budgets and the first output wait share the command's
operation deadline. Each output write has its own additional ten-second bound;
reporting a completed observation never starts a new acquisition.

```sh
node scripts/capture_github_issue_migration.mjs resume \
  --workdir /srv/migration/source-captures --confirm "$SESSION_SHA" \
  --token-file /srv/operator/github-read-token --max-batches 8

node scripts/capture_github_issue_migration.mjs status \
  --workdir /srv/migration/source-captures --confirm "$SESSION_SHA"
```

Use `prepare` instead of `start` to create only the offline source session. Do
not run start again against an occupied directory. Run resume explicitly after
a batch ceiling or a reconciled source error; completed captures are never
refetched. A retained owner still blocks resume, even after SIGKILL. Status
cannot accept new source credentials, inventory selection or network budgets.

When complete, review the captured provenance and independently retain the
returned `sources.sha256` as `SOURCES_SHA`. The complete source selection is
validated through the same parser used by destination preparation, not a
parallel permissive interpretation. The separate destination operation is:

```sh
node scripts/migrate_github_issues.mjs prepare \
  --workdir /srv/migration/native-prepared \
  --sources /srv/migration/source-captures/sources.json --sources-sha256 "$SOURCES_SHA" \
  --url https://forge.example/repository/ \
  --tenant 11111111111111111111111111111111 \
  --repository 22222222222222222222222222222222 \
  --token-file /srv/operator/native-issue-token
```

Then use the existing, independently approved native plan and its run/status
semantics from [GITHUB_ISSUE_MIGRATION_EXECUTION.md](GITHUB_ISSUE_MIGRATION_EXECUTION.md).
The source command does not automatically execute any destination operation.

Exit 0 means complete source capture, or completion of the explicit offline
prepare operation. Exit 3 means a captured prefix, cancellation, retained owner
or source error after validated session progress. Exit 2 means invalid input or
failure before validated progress. Exit 4 means a known result followed by an
output/cleanup error, not a successful capture command. Diagnostics preserve the
original session pin and known capture progress without printing credentials.
All output is bounded JSON with terminal-control escaping. None of these exit
codes describes a native transaction outcome.

## Evidence and limits

The focused targets are `tests/operator/github_issue_capture_migration.test.mjs`
and `tests/operator/github_issue_capture_command.test.mjs`. Run them through
`bash scripts/verify_github_issue_capture.sh`.
It uses actual source HTTP ownership, discovery/capture codecs, native issue
command encoding and private filesystem operations, with a GitHub response-schema
peer. The command tests run unchanged production modules in actual Node
processes; only the GitHub HTTP response peer is injected through a test preload.
They also drive the actual migration source-selection loader, both signals,
closed/stalled output and the complete 128-batch boundary. It covers multi-page comments, full-width numeric aliases, byte equivalence,
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
