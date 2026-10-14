# Restartable remote event consumer

`node scripts/fg_events.mjs` makes the native scoped event feed usable by an
external bot or integration without losing its local position on restart.
`init`, `capture`, `watch` and `inspect` share the same configuration, remote
page validator and immutable local archive. Each saved record contains its
**complete page and resume cursor together**. There is no separately advanced
cursor file that could skip a page whose bytes were never saved.

Related work: `frankengit-root-doctrine-x2mv.4.35`, FG-046, plan sections 24
and 31. This is an external Node operator tool, not part of the Rust truth
process. It does not acknowledge a webhook, mutate the server, activate a
subscription, run repository code or decode native events. See the
[scoped feed](SCOPED_FORGE_EVENT_FEED.md) and
[acquisition boundary](REMOTE_EVENT_CAPTURE.md).

## Configuration and initialization

Use Node 22.16.0 or later and an operator-controlled POSIX filesystem supporting
file and directory sync and atomic same-filesystem directory rename. Input files
must be private, owned by the effective process user, singly linked regular
files. Final symlinks and special files are refused. The archive and its parent
directories must be controlled by the operator; parent-path mutation by a
hostile process is outside this profile.

Create `subscription.json` with independently retained service identities:

```json
{
  "type": "frankengit_event_subscription",
  "schema_version": 1,
  "endpoint": "https://forge.example/repo.git",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "object_format": "sha1",
    "issues_read": true,
    "pulls_read": false
  },
  "after": "0",
  "page_size": 20
}
```

Replace the example identities and endpoint with the intended service's values.
The expected scope is not learned by trusting whatever repository the first
response names. `issues_read` and `pulls_read` must equal the server's exact
credential/endpoint grant intersection. Grants are not widened automatically.
`after` is an explicit starting position: `"0"` starts from the beginning;
choosing a later cursor deliberately excludes earlier history.

Keep the 64-character lowercase hexadecimal Bearer credential in a separate
private file, with an optional final newline. Do not put it in command-line
arguments. Provision both files with mode 0600, then initialize:

```sh
umask 077
node scripts/fg_events.mjs init \
  --archive ./events-archive --config ./subscription.json \
  --token-file ./event-token --trusted-local
```

Initialization is local-only. It creates a private archive directory and a
synced immutable binding record. The binding includes the full configuration
and a domain-separated SHA-256 credential digest, **not the credential itself**.
Repeating initialization with identical inputs preserves existing pages.
Different configuration or credentials refuse. A missing/corrupt binding beside
retained pages is not repaired by manufacturing a fresh empty archive.

The actual service API still enforces authorization. A valid local configuration
or binding is neither a server grant nor an authority receipt.

## Capture, resume and poll

```sh
node scripts/fg_events.mjs capture \
  --archive ./events-archive --config ./subscription.json \
  --token-file ./event-token --trusted-local \
  --max-pages 16 --timeout-ms 30000
```

Each page is validated, saved and synced before a
`frankengit_event_page_saved` receipt is written to stdout. The receipt reports
the local `tail_sha256`, `resume_after`, page/event counts and `local_synced:true`.
It does not dump event bodies. Capture reopens and verifies the archive before
its first HTTP request and resumes after the last saved page. Neither capture
nor inspection implicitly initializes an absent archive.

A filtered empty page can still carry `has_more:true`. The consumer saves that
page's `resume_after` and continues, rather than interpreting an empty visible
array as EOF. Full u64 repository sequences and u32 event indexes remain exact
decimal strings. Frame hex is preserved unchanged. Pages are append-stable,
not pinned to one head across the entire capture; each records its own head.
`caught_up_at_observed_head:true` means that the last observed page had no
continuation, not that no later commit can exist.

Default capture limits are 16 pages, 32 MiB of received JSON and 30 seconds.
`--max-pages` admits 1..64; `--max-bytes` admits 1..33,554,432;
`--timeout-ms` admits 1..300,000. Network reads and archive checkpoints share
the operation deadline. Each response is additionally bounded to 2 MiB.
Local filesystem calls are not preemptible. A custom API `onPage` callback owns
its own liveness; the CLI output path has a separate 10-second bound and is
interruptible by shutdown. The deadline is not renewed for each page.

A later read or storage failure does not erase earlier synced pages. Retain
receipts and repeat capture explicitly after resolving the failure. To require
an exact local tip before any request, add `--expected-tail RETAINED_SHA256`.
A changed tip refuses instead of overwriting or combining another writer's work.
An output error is not evidence that capture saved nothing.

For bounded continuous polling:

```sh
node scripts/fg_events.mjs watch \
  --archive ./events-archive --config ./subscription.json \
  --token-file ./event-token --trusted-local \
  --poll-ms 1000 --max-sweeps 1000
```

Watch defaults to those values. It accepts 100..60,000 ms between sweeps and
1..1,000,000 sweeps; per-capture bounds still apply. The next sweep must resume
from the previous sweep's exact retained tail. It polls successful completed
reads, but **stops on the first failed request**, rather than retrying failures
in the background. An identical quiet page does not grow the archive; a changed
head, watermark or page is a new observation. Configuration and an optional CA
file are snapshotted at startup; the credential is reread before each sweep.

SIGTERM/SIGINT abort the in-flight read and stop future admissions. A cancellation
before page publication leaves the prior saved cursor intact. Once a page is
published, its sync/readback is completed before late cancellation is observed.
Blocked stdout is closed on shutdown so a full output pipe cannot hold a saved
page indefinitely. SIGKILL can leave an unselected private staging directory;
restart never adopts it as a page. None of these process tests proves hardware
power-loss durability on every filesystem.

Remote endpoints require verified HTTPS. Numeric loopback HTTP is supported
for the native server's existing loopback profile. An optional `--ca-file FILE`
provides a private PEM trust bundle of at most 128 KiB; certificate and hostname
verification remain mandatory. This uses Node's external client transport and
does **not** add native Rust TLS. Redirects, ambient credentials, cookies,
unsupported encodings and mutation routes are refused or absent.

## Inspect saved events offline

```sh
node scripts/fg_events.mjs inspect \
  --archive ./events-archive --config ./subscription.json --trusted-local

node scripts/fg_events.mjs inspect \
  --archive ./events-archive --config ./subscription.json --trusted-local \
  --expected-tail RETAINED_SHA256 --page 2
```

Inspection requires no credential and makes no network call or archive mutation.
It validates the binding, complete bounded chain and all pages. `--page` selects
one saved page for output after that validation and deliberately reveals its
opaque frame bytes and metadata. The returned data is inert; the tool never
executes it. Without `--page`, output contains only bounded status metadata.
`durability_verified:false` distinguishes read-only inspection from a writer's
sync boundary. A simultaneously appended suffix may not be in an observed
prefix; an inspection is not a lease excluding another writer.

## Archive layout and trust boundary

```text
events-archive/
  binding/record.json
  page-00000001/record.json
  page-00000002/record.json
  .stage-XXXXXX/record.json     # possible crash residue, never selected
```

The binding and page directories are mode 0700 and data files mode 0600.
Records use a deterministic local JSON envelope, not a new native canonical
codec. Each numbered page commits to its predecessor's SHA-256 and requested
cursor. There is no mutable `latest` pointer or fallible cursor-only update.

Publication writes and syncs a private staging record and its directory, checks
the expected predecessor and absent next slot, renames the directory into that
slot, syncs the archive directory, and reads back the exact bytes. POSIX rename
cannot replace another writer's **nonempty** committed directory. Competing
cooperating processes may both fetch a page, but at most one publishes that
slot; the other stops and must reopen. No persistent lock remains after a crash.
Do not delete, empty or replace selected directories while a consumer is active.

A write/sync error before rename cannot select the staged page. A failed final
directory sync after rename reports `local_publication_unknown:true`; a page
may be visible. The owner is poisoned and cannot append again. Reopening
validates and resynchronizes the selected prefix before it can be used for
further capture. Cancellation or failed output cannot assert non-publication.

Limits are 4,096 pages, 128 MiB of selected records, and 4,353 directory entries
including staging residue. Individual record limits cover one bounded native
page plus its local envelope. A capacity failure retains existing data; nothing
is silently pruned or reset. There is no automatic migration, compaction,
staging cleanup or total-disk-usage guarantee. A supported archive is bounded,
not an infinite queue. Verification is O(retained history), not constant-time.

Hash chaining detects corruption and broken predecessor links, not a malicious
operator rewriting an entire archive. An independently retained tail detects
an edited tip or a valid-prefix rollback; without such a pin, a complete older
prefix is indistinguishable from an earlier legitimate crash point. A checksum
is not authentication. Server policy changes within unchanged grants are not
reconstructed as an ACL history. The feed is explicitly filtered, reveals
activity gaps, and supplies no native authority/completeness/absence proof.

Changing a credential, grant profile, repository incarnation or endpoint
requires an explicitly new archive and chosen backfill cursor. Broadening a
grant does not retroactively recover events skipped by an old cursor. This tool
does not guarantee exactly-once downstream side effects: a bot reading saved
pages must own its own idempotency and processing checkpoints. No HTTP reply or
local saved record settles a canonical outbox obligation.

Exit codes: 0 for completed commands/caught-up capture; 1 for a page-bounded
capture with continuation or a watch that reached its configured sweep count;
2 for refusal; 130 for cancellation. Error records say
`saved_pages_may_exist:true`, and may carry the last synced receipt. Refusals
never echo raw credentials or response prose.

## Verification

```sh
scripts/verify_event_consumer.sh
```

The focused lane executes the real production imports on Node, actual private
files, child processes and HTTP/TLS sockets. HTTP pages are explicit native-schema
fixtures, not a running Rust `fg` server or a native codec oracle. Coverage
includes filtered restart, full-width cursors, multiple-process publication,
strict input/permission checks, expected-tip refusal, corrupt/grafted/gapped
archives, the actual 4,096-page ceiling, output loss/backpressure, SIGTERM and
SIGKILL before/after prior page persistence, staging abandonment and a planted
post-rename directory-sync failure with permitted recovery. OpenSSL is used only
for an ephemeral TLS test certificate. No new package dependency is introduced.
Native Rust compilation, real-fg integration, multi-host deployment and independent
batch verification remain separate gates; this does not close the owning bead.
