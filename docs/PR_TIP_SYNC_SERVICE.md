# Opt-in automatic PR tip synchronization

`node scripts/fg_pull_sync_watch.mjs` supervises the existing native-API PR tip
synchronizer. It is a foreground external operator client, not a Git engine,
server trigger, mutable forge database, CI runner, or merge authority.

The concrete workflow is: observe open PRs and their current branches at one
snapshot, retain changed-tip requests, publish through the native exact-version
metadata API, persist terminal observations, and poll again. This refreshes PR
metadata after observed pushes while preserving the currently selected title,
body, branch names, and expected version. Native admission independently checks
current versions, ref tips, and authorization. The watcher never moves a branch,
closes or retargets a PR, runs a workflow, merges code, or carries approvals to a
changed subject.

This is polling, not an exactly-once push feed. Intermediate tips between polls
can be missed. There is no promise to execute CI once per push, or to observe every
push event. The atomic unit remains one native PR update, not the whole batch.

## Explicit policy and installation

Use Node 22+ with raw JSON number sources on POSIX, a configured native HTTP API,
and an operator-provided token permitted to read PR metadata, read source refs,
and update PR metadata. Native grants remain independent. No credential is
inferred from the environment, cookie jar, Git configuration, or another process.
The configuration's principal is an independent expectation; only the server
authenticates the supplied token. Use the correct principal's scoped credential.

Create a private, nonsymlink `0700` state directory and a separate private control
directory. Put the token in a private regular file, optionally followed by one LF.
A configuration has exactly these fields (replace all example values):

```json
{
  "schema": "frankengit-pr-sync-watch-v1",
  "destination": {
    "endpoint": "https://forge.example/team/repo.git",
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "principal_id": "44444444444444444444444444444444",
    "object_format": "sha1"
  },
  "selected": "all-open",
  "state_directory": "/srv/pr-sync/state",
  "max_batches": 128,
  "state_bytes": 67108864,
  "policy": "recorded-tips-only"
}
```

`selected` can instead be an explicit array such as `[7, 12]`. That selection
never widens automatically. A closed/missing explicitly selected PR or a missing
branch stops discovery rather than editing an incomplete subset. `all-open`
discovers later new PRs and excludes closed PRs.

```sh
node scripts/fg_pull_sync_watch.mjs once \
  --config /srv/pr-sync/control/watch.json \
  --token-file /srv/pr-sync/control/token --allow-tip-updates

node scripts/fg_pull_sync_watch.mjs serve \
  --config /srv/pr-sync/control/watch.json \
  --token-file /srv/pr-sync/control/token --allow-tip-updates \
  --poll-millis 1000 --max-polls 86400 --max-updates 128

node scripts/fg_pull_sync_watch.mjs status \
  --config /srv/pr-sync/control/watch.json
```

The explicit policy and `--allow-tip-updates` authorize this bounded class of
unattended changes. They do not authorize arbitrary metadata edits or retries.
For per-batch manual review and confirmation, use `fg_pull_sync.mjs` instead.
HTTPS uses certificate verification; an optional private `--ca-file` is passed to
both discovery and publication. Cleartext HTTP is restricted to numeric loopback.

## Retained requests and decisions

One manager owns `state_directory/owner.lock`. A byte-exact `binding.json` fixes
the endpoint, repository incarnation, principal, PR selection, and capacity policy.
A changed binding refuses before network work. Tokens are not in the binding.

Changed requests are retained under `batch-000001`, `batch-000002`, and so on.
These are ordinary one-off synchronizer plan directories: `plan.json`, start
markers, first outcome observations, and terminal receipts use the existing
formats and validators. The next batch cannot be created while an earlier batch
has pending/unknown requests. The complete plan is synced before any update.
Receipt capacity is reserved before creating a batch, including space for every
possible start, observation, and terminal record. Empty or interrupted batch
creation is left visible and blocks restart; it is not silently replaced.

A sweep may stop after `--max-updates`; remaining requests stay prepared in their
original batch and finish before any new discovery. Repeated polls with unchanged
tips do not create a request or increment the PR version. Across restarts, a
previously committed/refused identical request is not submitted with a new key.
Identity here includes the PR number and complete normalized request fields,
including expected version, metadata, and both tips; unrelated authority-head
changes do not reset it. Different PRs remain eligible even when an old request
was refused.

Suppressed requests are reported as historical decisions, never as current or
unchanged PRs. A refusal whose request fields remain identical requires explicit
operator action rather than an automatic new key, even after a policy change.
A changed PR version, metadata, or tip defines a new request that may be selected
in a later snapshot. A deliberate manual retry/replan uses the one-off client and
must preserve any unresolved original request.

## Lost responses and recovery

A missing, malformed, wrong-scope, or incomplete publication response stops the
service. No automatic resend or replan is attempted. Offline status identifies
the batch; recover it through the existing read-only command:

```sh
node scripts/fg_pull_sync.mjs recover \
  --state /srv/pr-sync/state/batch-000001 \
  --endpoint https://forge.example/team/repo.git \
  --token-file /srv/pr-sync/control/outcome-token
```

The recovery token may be rotated but must identify the original principal and
have outcome-read permission. A missing outcome does not prove non-commit. If
needed, an explicitly confirmed `fg_pull_sync.mjs send --retry` uses the original
plan, body, principal namespace, and key. The watcher itself has no retry option.
After recovery has settled the old requests, a restarted watcher recognizes those
receipts before selecting more work. Prepared requests still require their
original credential; rotation never silently changes a saved request's key.

SIGTERM/SIGINT stop discovery and new submissions, but allow one active bounded
publication to finish and retain its validated decision. The active publication
has at most the lesser of 30 seconds and the sweep's remaining request budget.
Cancellation between jobs cannot submit the next job. SIGKILL may leave a manager
or batch sender lock. Neither lock is stolen. A known remote terminal does not
prove an old local owner drained; retained sender ownership blocks new batches
as well. Prove local quiescence and inspect retained state before operator lock
recovery. Read-only outcome recovery remains separately owned and never removes
sender locks. No lock-removal command is supplied by this service.

## Resource and failure boundaries

Each sweep inherits the existing discovery limits: at most 4,096 PR rows, 128
selected open PRs, 256 pages, and 16 MiB of wire responses under one finite budget.
The default sweep budget is 120 seconds, configurable through `--timeout-ms` up
to 300 seconds. An individual HTTP request stays bounded. `--max-updates` is 1–128
per sweep. Poll intervals are 100–60,000 milliseconds; the service has an explicit
maximum poll count of 1–1,000,000.

At most 128 retained batches and 64 MiB of reserved serialized plan/receipt bytes
are supported, with lower operator-selected limits. The byte budget is not a
measurement of filesystem block usage. No history is evicted. Capacity exhaustion
stops new admission; this is a bounded operator profile, not an unbounded service
or a retention/GC implementation. Local private storage is trusted against
same-UID hostile mutation or deletion; copying/deleting a ledger is not a safe
way to reset deduplication. Keep its recovery material and backups.

Only transient discovery failures (transport/timeouts and HTTP 408, 409, 429,
502, 503, 504) receive bounded polling backoff, stopping after three consecutive
failures. Authentication, schema, custody, publication, and output failures do not
enter that retry path. Files and final observations survive later output failure.
Output is bounded JSON/NDJSON; status contains counts, paths, and plan identities,
not credentials or PR text. Publication events retain native terminal identities.

Exit codes: `0` completed selected work; `1` observed canonical refusal; `2`
input/read/custody failure; `3` pending/unknown work; `4` known result with local
cleanup/output failure. Historical refusals are not proof of current branch state.

## Verification boundary

`tests/operator/pull_sync_watch.test.mjs` exercises actual HTTP sockets, private
files, CLI processes, signals, later pushes, exact request deduplication,
concurrent ownership, partial batches, original-key recovery, and the exact
serialized receipt-capacity boundary. Run it with the unchanged one-off suites:

```sh
node --test tests/operator/pull_sync*.test.mjs
```

The remote node in these tests is explicitly a native-schema contract fixture,
not Rust `fg`. These are client orchestration tests, not native authorization,
CAS, review-freshness, live-deployment, hardware-power-loss, or full-workspace
acceptance. No server permission is inferred from local checks. The broader
`frankengit-root-doctrine-x2mv.4.20` and CI product-loop acceptance remain open;
no required-green check, merge permission, or approval-survival rule is added.
