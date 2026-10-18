# GitHub issue and comment migration

`node scripts/import_github_issues.mjs` captures selected GitHub issues and imports
them through the shipped FrankenGit issue API. It does not open a local node,
write its database, invoke a foreign Git engine, or impersonate source authors.
The destination server owns authentication, policy, expected-version validation
and every canonical terminal decision.

## Supported migration

The imported native state includes issue titles, literal source bodies, label
names, every captured current comment in source-ID order, and final open/closed
state. A provenance block precedes each imported body. It retains original URLs,
repository/issue/comment numeric aliases, author IDs and logins, creation/update
times, label details, assignees, milestone summary, state reason and locked flag.
The original body is an unchanged suffix, including its line endings.

**Source metadata is attribution only.** All new native events belong to the
principal authenticated by the destination token. Source authors are not enrolled
as native accounts; assignees do not become native assignments, source timestamps
do not become audit timestamps, and a source lock does not install access policy.
GitHub IDs remain source aliases, separate from native authority identities.

This is an issue/comment snapshot migration, **not a full GitHub repository
import**. Pull requests are explicitly refused. Git commits, reviews, reactions,
projects, attachments, edit/deletion history, timeline events, releases, actions,
webhooks and other unsupported surfaces are not migrated. Linked attachments
remain literal links; the importer never fetches them or sends credentials to
those links. No link rewriting is performed. Source PR-number gaps are retained.

## Capture and review

Use Node 22.16 or newer with JSON reviver source context. Source capture pins
GitHub REST API version `2026-03-10`, reads `api.github.com` only, and does not
follow redirects. The source credential may be omitted for public repositories.
Prepare private files and a private directory on a supported Unix filesystem:

```sh
umask 077
mkdir migration
# Provision source-token and native-token privately; do not put tokens in argv.

node scripts/import_github_issues.mjs capture \
  --repository example/project --issue 12 --issue 19 \
  --token-file migration/source-token --out migration/capture.json

node scripts/import_github_issues.mjs inspect \
  --capture migration/capture.json --offset 1000
```

Issue numbers are explicit: there is no implicit whole-repository crawl.
The capture includes two complete observations of the selected repository
identity, issue metadata and current comments; they must be identical after
normalization. Comment counts, unique IDs, scope and pagination are checked.
This detects many concurrent edits but **does not establish an atomic snapshot**
or exclude changes that revert between observations. Quiesce the selected issues
while capturing. A failed/rate-limited/changed source is refused without automatic
retry or a partial usable package. Select and recapture explicitly.

The source API may spell a continuation with a numeric repository ID. Such a
link must still have the same host, repository identity, issue, page size and next
page number. The importer then constructs its own canonical request URL; it never
uses a server-provided URL as a credential destination.

Limits are explicit: 100 issues, 2,000 total comments, a canonical 1 MiB package,
8 MiB per source reply and 64 MiB aggregate source reads by default. The aggregate
ceiling can be selected with `--max-read-bytes` up to 256 MiB. Both passes count.
Source IDs retain exact full-width unsigned-64-bit decimal values; destination
issue numbers and versions must fit the shipped client's exact safe-integer
profile. Native title, body, label and encoded-form limits also apply **after**
adding provenance. Nothing is silently truncated. The native step proposal itself
must fit 1 MiB. Large migrations require explicitly selected disjoint batches.

## Prepare a destination plan

The destination token file contains exactly 64 lowercase hexadecimal characters,
optionally followed by one newline. Its principal needs independent issue-read,
issue-write and outcome-read grants, and the corresponding server endpoints must
be enabled. Native permission checks happen on the server, not during preparation.

```sh
node scripts/import_github_issues.mjs prepare \
  --capture migration/capture.json --workdir migration/job \
  --url https://forge.example/team/project.git/ui/issues/ \
  --tenant-id TENANT_HEX --repository-id REPOSITORY_HEX \
  --token-file migration/native-token --offset 1000
```

Preparation performs no network requests or mutations. It copies the exact
capture into a **new** private directory, compiles all native steps, and saves
every original request/key before publishing a synced manifest last. The manifest binds the source and compiled-step hashes,
exact URL, tenant/repository IDs, offset, original native credential fingerprint
and the hash of every prepared request. The complete request set is bounded to
16 MiB, with a 256 KiB manifest ceiling.
It contains no access token. Record the returned `plan_sha256` independently and
review the `inspect` output before sending. The example maps issues 12 and 19 to
1012 and 1019, rather than discovering or renumbering occupied targets.

If preparation is interrupted, its partial directory is retained and cannot be
run without a complete valid manifest. Preparation never overwrites that directory.
The original source package can disappear after successful preparation; restart
uses the exact retained copy, not GitHub or the original capture path.

## Publish and resume

```sh
node scripts/import_github_issues.mjs run \
  --workdir migration/job --confirm PREPARED_PLAN_SHA256 \
  --url https://forge.example/team/project.git/ui/issues/ \
  --tenant-id TENANT_HEX --repository-id REPOSITORY_HEX \
  --token-file migration/native-token --max-mutations 100
```

Supply the destination independently on every invocation. It must equal the
prepared URL and scope. The original destination token fingerprint must match.
Source GitHub credentials are never used for destination publication.
HTTPS is mandatory except for explicit trusted-loopback HTTP.

Offline preparation constrains each request to the explicitly expected native
repository. This is an intent constraint, not an authenticated repository view
or a grant; the shipped client uses it only to tighten later response checks.

For each issue, the plan opens version zero, appends comments against exact
successive predecessor versions, then closes it if the captured source is closed.
It neither overwrites occupied issues nor adapts to another writer's version.
All original request records are already sealed by preparation. Run verifies the
complete set against the manifest before network access, then uses the shipped
operator's original-key outcome lookup before sending any request. Each sender
also establishes its own exact-file and parent sync barrier. A durable `started`
marker records local dispatch responsibility; it never replaces a missing
receipt. A validated terminal is saved with its original receipt hash before
another planned mutation is considered.

Restart rechecks original canonical outcomes, including previously retained
terminals; a mutable local success index is not enough. Refusal stops the batch.
Missing or substituted earlier decisions also stop it. A lost response that the
server subsequently reports committed is recovered without resending the command.
An original already attempted locally whose outcome remains unknown stops at
that step by default. A transient lookup failure before any local dispatch
marker does not strand the job: its exact presealed request remains available.

```sh
# Observe only; may retain validated local terminal observations, never sends.
node scripts/import_github_issues.mjs status \
  --workdir migration/job --confirm PREPARED_PLAN_SHA256 \
  --url https://forge.example/team/project.git/ui/issues/ \
  --tenant-id TENANT_HEX --repository-id REPOSITORY_HEX \
  --token-file migration/native-token

# Explicitly permit exact retry of an unresolved ORIGINAL request.
# Add --retry-unresolved to the same run command, without changing its plan.
```

`--retry-unresolved` invokes the existing operator's outcome-first, single exact
resend. It does not generate another request/key, refresh policy/versions, or
claim absence proves non-commit. Later untouched steps may run only after the
original is observed committed. `--max-mutations` (1–2200, default 100) bounds
mutation-capable operator calls in that invocation; earlier outcome checks do
not consume it. The whole-operation timeout defaults to 300 seconds and covers
file intake, checks and requests. A timeout is not a rollback certificate.

A batch is **not atomic**: earlier issue/comment commits remain even if a later
step conflicts, is refused, times out or fails locally. Preserve the entire
private work directory and confirmation hash across interruptions. Do not delete
step records to restart work. Any missing or changed prepared request requires operator investigation, even
if it belongs to a later untouched step. It is deliberately not auto-repaired
into a new request. `not_started_locally` means no local dispatch was recorded,
not proof that nobody else could have submitted an exported original.

## Ownership, signals and limitations

Only one `run` owns a job's sender lock. Normal completion/error/SIGTERM cancels
local waits and releases the owned lock; a SIGKILL leaves it blocking. No
age-based lock stealing occurs. `status` can still recover an original outcome
with the stale lock present. Before manually removing a killed sender's lock,
the operator must independently establish that its process is no longer running
and preserve every other job/step file. Do not remove locks based on time alone.

Files and directories are owner-private; inputs are regular single-link files,
final symlinks are refused and exact descriptors/parent directories are synced.
This trusted-local POSIX profile is not a hostile same-UID sandbox or a hardware
power-loss proof. Blocking filesystem operations can delay cancellation and
cleanup beyond the nominal deadline. Do not modify files inside an active job.

Credential rotation for this issue importer is not supported: keep the original
native token/grants available for outcome recovery. Token-to-principal mapping
and the destination repository incarnation must remain stable. The current native
issue read/publication schema binds tenant/repository but does not carry an
incarnation, so this client does not claim safe replay across repository
re-creation or credential reassignment. The separate PR/protection recovery
clients' rotated-credential capabilities do not imply that support here.

Exit codes: 0 for successful capture/inspection/preparation or all planned steps
observed committed; 1 for a bounded prefix, not-started or unresolved original;
3 for a canonical refusal; 2 for an error. Error reports retain partial progress
and any just-validated terminal. If stdout fails after completion, the error
separately carries `completed_result`; the exit status does not undo publication.

## Verification and remaining acceptance

```sh
node --test \
  tests/operator/issue-native-absence.test.mjs \
  tests/operator/github-issue-source.test.mjs \
  tests/operator/github-issue-import.test.mjs
```

These tests execute the shipped JavaScript capture/compiler, IssueClient,
runIssueOperation, filesystem custody and real CLI child processes. Source HTTP
responses are controlled GitHub fixtures; the loopback receiver is explicitly a
native-schema contract peer, **not `fg`**. They do not establish native
policy/CAS correctness, live GitHub compatibility, production TLS behavior,
hardware crash durability or full FG-049 acceptance. Run the complete workflow
against a built native server before relying on it for a production migration.
