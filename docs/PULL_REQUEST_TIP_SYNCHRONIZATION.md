# Synchronize recorded PR tips after a push

`scripts/fg_pull_sync.mjs` discovers tip-only metadata updates over the existing
native HTTP APIs. It is an external operator client, not a replacement Git,
authorization, review, or admission engine. It requires Node 22 or newer with
JSON.parse raw-number sources, on POSIX, and uses no additional dependencies.

## Why this operation exists

The native PR aggregate records exact source and target commit IDs. A subsequent
push can leave those recorded IDs behind the live branches. Reading the PR does
not change them. This operator selects one complete snapshot, compares recorded
and actual tips, and prepares explicit `update` commands. The native admission
path in `fgit-admission/src/merge/native/pull_request.rs` checks the exact PR
version and both actual ref tips again when each command is admitted.

Title, body, branch names, and expected PR version remain byte-for-byte/semantically
unchanged. Only changed source/target tips enter a request. An unchanged PR gets
no request and no version increment. A missing/closed explicitly selected PR or
unavailable branch refuses the whole discovery; nothing closes or retargets it.
Existing reviews are NOT carried forward as current reviews of changed code.

## Independent destination and credentials

Create a private destination JSON file with exactly these fields:

```json
{
  "endpoint": "https://forge.example/team/repo.git",
  "tenant_id": "11111111111111111111111111111111",
  "repository_id": "22222222222222222222222222222222",
  "repository_incarnation": "33333333333333333333333333333333",
  "object_format": "sha1",
  "principal_id": "44444444444444444444444444444444"
}
```

Use actual independently obtained repository identities and publisher principal,
not these examples. Discovery needs independent PR-read and source-read grants.
The server, not this file, authenticates and authorizes the bearer. HTTP is allowed
only to numeric loopback addresses. HTTPS verifies certificates; `--ca-file` adds
an explicit private CA. No redirects, cookies, inferred proxies, or automatic
network retries are used. The token file holds exactly 64 lowercase hex digits
with at most one final newline. Tokens are not stored in the plan or printed.
Control files must be owner-private regular files with no hardlinks; their parent
and the plan directory must be stable, nonsymlink, owner-private 0700 directories.
Same-UID hostile storage replacement is outside this trusted operator profile.

## Inspect and retain a plan

Choose explicit PR numbers, or opt in to `--all-open`:

```sh
node scripts/fg_pull_sync.mjs inspect \
  --destination /srv/control/destination.json --token-file /srv/control/token \
  --pr 7 --pr 12

node scripts/fg_pull_sync.mjs prepare \
  --destination /srv/control/destination.json --token-file /srv/control/token \
  --all-open --state /srv/pr-tip-plan

node scripts/fg_pull_sync.mjs show --state /srv/pr-tip-plan
```

Preparation writes a synced create-only `plan.json`. It records original metadata,
new tips, exact request keys, credential fingerprint, destination, snapshot,
selection, and an integrity digest. Preparation sends no mutation. Keep this plan;
do not overwrite it with newly discovered tips under an earlier request's key.
A plan digest detects accidental changes; it is not a signature or independent
server-authority proof. `show` requires neither credentials nor network access.

## Bounded discovery

One discovery has a 120-second default total budget, adjustable to 300 seconds.
It reads at most 4,096 PR rows, selects at most 128 open PRs, and consumes at most
256 total native pages and 16 MiB response bytes. Every page has 50 entries and
all continuations retain the first authority snapshot. A moved snapshot refuses
rather than mixing pages or refreshing implicitly. Unchanged PRs remain visible
in the report. A plan is bounded by 20 MiB; an over-budget plan is not saved.

The current native metadata/form profile takes UTF-8 branch names. Selected
byte-only refs refuse; unrelated byte-only names remain data, but an unencodable
native pagination cursor also refuses rather than skipping a page. Git SHA-1
and SHA-256 are separate domains. PR/version counters above JavaScript's exact
safe integer range refuse before publication; unquoted native decision counters
are handled separately without precision loss.

## Validation boundary

`tests/operator/pull_sync_plan.test.mjs` uses actual loopback HTTP and independently
selected repository coordinates. Its peer is explicitly a native-schema contract
fixture, not the Rust `fg` server. It tests discovery, strict framing, bounds,
metadata preservation, and plan integrity; it does not establish native policy,
CAS, review invalidation, live deployment, or full-workspace acceptance.

Related: comprehensive plan sections 25.1, 25.4, 25.8; bridge bead
`frankengit-root-doctrine-x2mv.4.20`. No broad bead closure or approval-reuse claim.

## Confirm and publish

Review the complete `show` output, including changed source and target IDs. Send
only the plan whose digest was reviewed, supplying the endpoint independently:

```sh
node scripts/fg_pull_sync.mjs send \
  --state /srv/pr-tip-plan \
  --endpoint https://forge.example/team/repo.git \
  --token-file /srv/control/token \
  --confirm "$REVIEWED_PLAN_SHA256" \
  --max-requests 128
```

The original credential fingerprint must match for publication. The native server
still authenticates the token and checks its independent PR-write grant. A local
principal pin is not authority. `send` never rediscovers tips, edits metadata,
creates a PR, moves a ref, or sends a merge or review. The native engine admits
one exact-version `update` per changed PR and rechecks both branch tips. A concurrent
PR edit or branch move produces a native refusal, not overwritten expectations.

A batch is **not atomic** across PRs: earlier decisions remain committed when a
later request fails. Every request acquires a synced `started-NNN.json` marker
before opening its update socket. A validated committed/refused receipt is saved
before proceeding. Each request keeps its original key. Limits can leave later
requests prepared but unstarted; another explicitly confirmed `send` continues
those requests without rediscovery. All selected work shares one deadline.

## Lost replies and recovery

An interrupted update remains unknown until reconciled. Normal `send` refuses
when any original request is unresolved. Read-only remote recovery requires no
local native executable or repository storage, and can use a replacement token
for the same original principal:

```sh
node scripts/fg_pull_sync.mjs recover \
  --state /srv/pr-tip-plan \
  --endpoint https://forge.example/team/repo.git \
  --token-file /srv/control/current-outcome-token \
  --max-requests 128

node scripts/fg_pull_sync.mjs status --state /srv/pr-tip-plan
```

The replacement credential needs the server's independent outcome-read permission.
Recovery selects only started requests and calls the existing bodyless original-key
`/api/v1/outcomes` endpoint. It never publishes, recreates missing branches, modifies
the plan, or starts a prepared request. It retains the first transaction/seal
observation and terminal decision as bounded, create-only records. An outcome
already durably retained in that first observation remains known even when writing
the duplicate terminal record failed. Status and subsequent sends use that
retained evidence; they do not repair or recreate files automatically.

`key_not_observed`, `seal_not_observed`, and `undecided` are NOT rollback decisions.
To explicitly retry an unresolved request, supply `send --retry`, the same original
credential, endpoint, and reviewed plan digest. Each started request first performs
an outcome lookup. A terminal result is saved without resubmission; otherwise the
explicit retry can submit only its original unchanged body/key. It never replans
against later source. A different original transaction/seal, a conflicting terminal,
or knowledge learned concurrently rejects the operation before another mutation.

## Ownership, interruption, and limits

One sender holds `owner.lock`; read-only recovery uses a separate `recovery.lock`.
Recovery never removes or steals a sender's lock, even after SIGKILL. A recovered
canonical outcome is not proof that the old sender has stopped. Operators must
reconcile process ownership separately before any intentional lock removal.
SIGTERM/SIGINT stop new work, close the active owned socket, and preserve started
responsibility. A fully received valid decision is persisted even if cancellation
arrives while local storage is finishing. Filesystem or output failures do not
turn that decision into an invented rollback.

The 128-request plan admits at most three 16 KiB observation records per request,
in addition to the 20 MiB plan. No history is evicted. Each sweep handles at most
128 pending requests: each retry can make one lookup and at most one identical
update; recovery makes lookups only. Network responses and aggregate discovery
bytes are bounded before further accumulation. Control-file/storage calls remain
subject to filesystem latency; deadlines are not a hardware real-time guarantee.
No credentials are persisted, and parser diagnostics do not quote malformed server
bytes that could reflect a credential.

The plan needs stable private storage and independent operator review. Checksums
are integrity evidence, not signatures, rollback-proof storage, or a way to trust
an attacker-controlled same-UID filesystem. Deleting a whole plan/namespace loses
its responsibility records; automatic reconstruction or a new key is not recovery.

## Exit status and test scope

- **0**: the requested result is complete and selected publications are committed,
  or there was no work. A successful inspect/show is not publication evidence.
- **1**: at least one canonical PR update was refused.
- **2**: input, read, or local operation failed without a newly established terminal.
- **3**: publication remains prepared/unknown, a work bound left pending requests,
  or an interrupted submitted request has no complete validated reply.
- **4**: a terminal/result was established but local persistence, cleanup, or output
  failed. Inspect saved state and retained diagnostics; do not assume rollback.

`show` says publication status was not queried. `status` is an offline view of
retained historical decisions, not a claim of current source or current reviews.

Run the focused tests:

```sh
node --test tests/operator/pull_sync*.test.mjs
```

In addition to discovery, the tests exercise actual private files, HTTP/TLS sockets,
private-CA verification, CLI processes, SIGTERM/SIGKILL, exact resends, partial batches,
stale selections, credential rotation, parallel recovery, receipt/write failures,
output loss, and exact full-width decision counters. The executable/HTTP authority
peer is a native-schema contract fixture, NOT Rust `fg`. Native authorization/CAS,
review freshness, deployment correctness, and a full Rust workspace pass require
separate real-node validation. No automatic per-push subscription, CI trigger,
approval survival policy, or broad PR-product completeness is claimed.


### Concurrent receipt readers

Publication and recovery can inspect the same create-only receipt while its
synced temporary hard link is being removed. A reader retries only that local
observation for at most 32 attempts over 250 ms; every successful read still
requires the original private-file, single-link, stability, scope and schema
checks. This does not retry a network request. An interrupted write or persistent
hard link continues to refuse, with its files preserved for inspection. No
reader unlinks another process's temporary file or steals an owner lock.
