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
