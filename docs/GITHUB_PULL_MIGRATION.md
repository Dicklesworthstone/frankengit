# GitHub pull-request migration

FG-049 (`frankengit-fg049-github-compat-xdo`), comprehensive plan §31.3.
The GitHub issue importer deliberately excludes pull requests. This separate
foreign-source profile retains PR metadata, discussion comments, submitted review
observations, and inline review locations without inventing native identities.
It reuses the existing bounded GitHub source transport and private-file custody.

## Capture and inspect

```sh
node scripts/migrate_github_pulls.mjs capture \
  --repository OWNER/REPO --pull 9 --pull 17 \
  --token-file /srv/import/github-reader.token \
  --out /srv/import/github-pulls.json

node scripts/migrate_github_pulls.mjs inspect-capture \
  --capture /srv/import/github-pulls.json --confirm "$CAPTURE_SHA256"
```

Keep the returned `capture_sha256` independently. A source token is optional for
public resources; it is never accepted as an argument value or retained in the
capture. All files are owner-private, with new output created exclusively outside
Git worktrees. Existing or partial files are not overwritten or repaired.
Inspection is offline and requires the exact capture pin. Output failure retains
the completed capture and pin rather than repeating requests. Exit 0 is success,
2 is refusal, and 4 reports retained/potentially published custody or output error.

The command captures 1–100 explicitly selected PR numbers, not an implicit whole
repository. Each observation reads the repository identity, brackets each PR's
three complete paginated streams with metadata reads, and rechecks repository
identity. Two complete normalized observations must agree. Changed tips, bodies,
review states, inline locations or repository identity cause refusal. No prefix
is called complete. This is **not an atomic GitHub snapshot**: quiesce edits while
capturing; equal observations cannot prove that no intervening change occurred.
The package retains that limitation as a machine-readable consistency field.

Pagination links may select only the next page of the same stream and selected
repository (including its numeric repository alias); requests are constructed
locally, never by following arbitrary response URLs. Discussion and inline counts
must match the bracketing metadata. Duplicate records, invalid continuations and
disagreement with those counts refuse. Reviews have no independent total-count
proof beyond the source pagination contract. Source reads use the existing API version and source HTTP/byte/deadline
limits. No automatic source retry, attachment download or fork traversal occurs.

## Prepare a native destination plan

Capture and native request planning use separate schemas and separate pins.
GitHub IDs never become native principal IDs or fabricated snapshot tokens.
Select an existing SHA-1 destination repository and an independently authorized
native PR writer in a private JSON file:

```json
{
  "endpoint": "https://destination.example/repo",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "principal_id": "44444444444444444444444444444444",
    "object_format": "sha1"
  },
  "number_start": "100",
  "namespace": "refs/heads/import/github/",
  "merged": "refuse",
  "drafts": "refuse"
}
```

Destination numbers are consecutive in selected source-number order. The starting
number is a canonical decimal string through the full native u64 range. Overflow
refuses preparation. No collision search, automatic renumbering or actor-derived
credential is used. The namespace is explicit, consists of nonempty ASCII
letter/digit/underscore/hyphen components, and ends in `/`. Each source PR gets
separate `<namespace>pr-N/head` and `<namespace>pr-N/base` branches at its unchanged
SHA-1 tips. Fork labels are retained as provenance, never converted into implicit
remote URLs, credentials or destination refs.

```sh
node scripts/migrate_github_pulls.mjs prepare \
  --capture /srv/import/github-pulls.json --capture-confirm "$CAPTURE_SHA256" \
  --selection /srv/import/destination.json \
  --token-file /srv/import/native-pr-writer.token \
  --workdir /srv/import/github-pr-job

node scripts/migrate_github_pulls.mjs inspect \
  --workdir /srv/import/github-pr-job --confirm "$PLAN_SHA256"
```

Both operations are offline. Keep the new `plan_sha256` independently. Preparation
fully validates the original capture and compiles every native command before
creating any request keys. It checks native title/body/form limits without
truncation; an unsupported title or body refuses the whole preparation. A null
GitHub body becomes an empty native body while its original null remains in the
metadata observation. Titles and non-null bodies remain exact, including BOM,
CRLF, Unicode and final-newline bytes.

Closed PRs end closed. A merged PR requires `merged: "as-closed"`; this imports
it as closed with merge provenance, not as a native merge. A draft requires
`drafts: "as-ordinary"` because this importer does not create native draft state.
The defaults refuse these conversions. All selected consent and destination
coordinates are sealed into the local plan and cannot change during resumption.
No active approval, merge, workflow result, branch movement or authority is emitted.

The source copy is `capture.json`, not a native archive. `requests/step-NNNNNN`
contains ordinary immutable `remote_pull` intent slots, with keys created by the
existing native PR codec. The root `manifest.json` binds the source pin, complete
normalized selection, command sequence, every request digest, total request bytes
and original native credential fingerprint. It is published only after private
file synchronization and complete source/request readback. Interrupted or damaged
preparation refuses in place; no automatic repair or new replacement keys.

### Provision the required historical branches

`inspect` reports every required branch and exact tip. `requirements` emits a
private selection file for the existing [create-only branch bootstrap](NATIVE_BRANCH_BOOTSTRAP.md),
using an independently selected branch principal:

```sh
node scripts/migrate_github_pulls.mjs requirements \
  --workdir /srv/import/github-pr-job --confirm "$PLAN_SHA256" \
  --principal "$BRANCH_PRINCIPAL_HEX32" --out /srv/import/github-branches.json

node scripts/bootstrap_native_branches.mjs prepare \
  --workdir /srv/import/branch-job --selection /srv/import/github-branches.json \
  --token-file /srv/import/native-branch-writer.token
```

Requirements are derived only after full pinned plan validation; existing PR
keys never change. The emitted selection has the bootstrap's existing generic
format, with no fabricated native-source origin. The result separately binds the
PR plan pin and `requirements_sha256`; retain both, then independently retain the
branch plan's pin. Execute branch bootstrap separately. Git objects and their
visible authorized history must first be imported through the native Git transfer
interfaces. GitHub fork, retired or deleted-only tips may require separately
retained authorized Git data. This workflow neither fetches forks nor pretends an
OID is sufficient to make an unknown or hidden object reachable.

## Execute and recover

```sh
node scripts/migrate_github_pulls.mjs run \
  --workdir /srv/import/github-pr-job --confirm "$PLAN_SHA256" \
  --token-file /srv/import/native-pr-writer.token --max-operations 100

node scripts/migrate_github_pulls.mjs status \
  --workdir /srv/import/github-pr-job --confirm "$PLAN_SHA256"

node scripts/migrate_github_pulls.mjs recover \
  --workdir /srv/import/github-pr-job --confirm "$PLAN_SHA256" \
  --token-file /srv/import/native-recovery.token
```

The shared native PR batch executor now has two repository-owned source loaders.
Its native-archive entrypoint and output schema remain unchanged. Both loaders
use the same unmodified native sender, original-key outcome reader, reservation
journal and result validators. Capture content and command-line fields cannot
supply a loader, sender, executable or replacement endpoint.

Before networking, `run` verifies the retained capture, recompiles the plan and
validates every original request. Before each potential send it synchronizes an
exclusive original-key attempt reservation. Only an observed committed native
terminal allows a successor. A native refusal stops the batch; earlier commits
are not rolled back. There is no atomic whole-migration transaction.

One invocation defaults to 100 sender/recovery operations, at most 8,192. Each
sender operation uses at most one mutation POST plus preflight and confirmation
lookups. A paused batch resumes with the same plan pin and original keys. Missing
results remain unknown, not permission to resend. Normal resumption recovers the
original key; explicit retry uses `run --retry-key "$ORIGINAL_PENDING_KEY"` with
the original native credential and immutable body. A retained publication or
terminal prevents another mutation POST. `recover` never starts an unattempted
step or sends a successor, including after it confirms an earlier commit.
A rotated credential may only recover the independently selected original
principal. Source GitHub tokens have no role in destination execution.

`status` reads the full plan and journal offline. `inspect` reads the immutable
plan only; use `status` for execution progress. Source capture paths and source
credentials may be removed after preparation. A completed job returns offline
without destination credentials. Concurrent observations preserve the strongest
compatible outcome; a late weaker read cannot erase a committed decision.
SIGTERM/SIGINT drain received observations to bounded result custody; a fresh
process after SIGKILL can recover a reservation with a missing result. There is
no global lock to steal. Concurrent first sends arbitrate an exclusive slot.

Native execution shares one 1–300,000 ms invocation deadline, including validation.
Received results drain locally after network cancellation rather than disappearing.
`run` and `recover` accept a private `--ca-file` for the existing HTTPS transport.
Output failure retains original plan/result diagnostics without repeating work.
Exit 0 means operation success, or complete execution; prepare/inspect/status may
succeed while reporting incomplete work. Execution exit 1 is a native refusal,
3 is ready/paused/unresolved, 2 is argument or preflight refusal, and 4 reports an
error with retained/verified custody or uncertain output. Read `state`, `complete`
and the original current key, not just the exit code. Do not mix manual sends
with batch execution or regenerate a plan to escape an unresolved request.

## Imported provenance representation

Only native `open`, `comment` and `close` operations are generated. Full selected
PR metadata, each discussion comment, each submitted review and each inline
review comment become clearly labeled ordinary native comments. No review API
is called. Each observation is serialized as JSON and split into at most 32 KiB
UTF-8 fragments at complete code-point boundaries. The comment includes a warning,
a one-line versioned header, a blank line and the literal fragment. The header
binds capture SHA-256, repository alias, source PR number, observation kind/source
ID, whole-record SHA-256 and exact part count/number. Concatenate fragment payloads
in part order, verify the whole-record digest and parse JSON to recover the exact
retained record, including text and nullable fields. This is attributed migration
content, not backdated native audit events, active votes or anchored native review
threads. Stream order is preserved within discussion/review/inline streams; their
cross-stream historical chronology is not reconstructed.

## Retained observations

PR fields include title/body (including null), GitHub IDs, actors, lifecycle,
draft/lock state, timestamps, exact SHA-1 head/base coordinates and repository
aliases, merge observation, labels, assignees and milestone summary. A deleted
fork is retained as a null repository, not replaced by an invented source repo.
Each submitted review retains its author, decision, body, reviewed commit and
submission time. Inline comments retain literal path/diff hunk/body, original
and current commit/line/side/position fields, review ID and reply-to ID. These
locations are historical observations, not recreated native anchored reviews.
Pending/unsubmitted or unknown review states refuse; finish or discard pending
reviews before capturing. Nullable authors and outdated locations remain null.

Only named fields are retained. Requested teams/reviewers, reactions, attachments,
checks, files/commit inventories, edits/deletions, hidden or inaccessible data and
timeline events are outside this profile. No Git objects are downloaded. Source
URLs are provenance only and are never authority. The SHA-1 input profile refuses
other hash domains rather than translating object IDs. No active approval, merge
permission, policy, timestamped native audit history or principal is imported.

## Bounds and verification

At most 100 PRs, 2,000 total discussion/review/inline records and 1 MiB of normalized
capture content. Source response bytes and requests are cumulative across both
observations (defaults 64 MiB and 4,096 requests; configurable lower request bound
and source byte allowance up to the existing 256 MiB ceiling). An individual
response retains the shared transport's 8 MiB ceiling. A command deadline is
1–300,000 ms, including local preflight and output. Data exceeding a limit refuses,
never truncates. The output file is not a canonical backup or a signed source proof.

```sh
bash scripts/verify_github_pull_migration.sh
```

Tests run the unchanged production GitHub transport and file helpers with actual
loopback HTTP response-schema peers, plus fresh Node CLI processes. A test-only
fetch adapter maps the fixed api.github.com origin to the local peer; the product
has no custom source endpoint or URL override. Tests cover three-stream pagination,
changed observations, scope/refusal/budgets, offline inspection, broken output,
and real SIGTERM/SIGINT/SIGKILL during incomplete responses. They do not contact
GitHub live, exercise native Rust admission/CAS or establish hardware durability.

Protocol references: GitHub's REST documentation for [PRs](https://docs.github.com/en/rest/pulls/pulls),
[reviews](https://docs.github.com/en/rest/pulls/reviews),
[inline comments](https://docs.github.com/en/rest/pulls/comments), and
[discussion comments](https://docs.github.com/en/rest/issues/comments).

The destination plan is bounded to 8,192 steps and 64 MiB of native intent bytes;
selection may lower `max_steps` and `max_request_bytes`. Native per-command limits
are unchanged. The shared journal retains at most 32 attempts per step, 32,768
attempts per job and 32 MiB of records/reserved missing-result capacity. Directory,
private-file, no-overwrite and damage-refusal checks do not establish a hostile
same-UID sandbox or physical power-loss durability.

Destination tests execute the complete production capture/compiler/loaders/sender/
original-key journal against real loopback response-schema peers. They cover
exact u64 numbering, long provenance reconstruction, lifecycle consent, old native
archive compatibility, a 105-operation batch split at the default limit, changed
files/credentials, lost replies, explicit retry, concurrent runners and late weaker
observations. Fresh Node CLI processes are interrupted by SIGTERM/SIGINT/SIGKILL
during committed peer replies and recover without duplicate mutation POSTs.
The peer does not implement Git or native authority: no native Rust server,
reachability/admission/CAS, full-workspace, live GitHub or release gate is claimed.
