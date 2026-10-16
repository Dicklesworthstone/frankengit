# Native pull-request migration

FG-049 (`frankengit-fg049-github-compat-xdo`), plan §31.3 and migration risk R20.
This external operator converts a complete [native PR read archive](NATIVE_PULL_ARCHIVE.md)
into ordinary `remote_pull` request slots. It does not implement Git, restore
canonical history, impersonate source actors, import approvals, or bypass native
policy. No Rust source, runtime or dependency change is required.

## Prepare and inspect

Create a private selection file outside Git worktrees:

```json
{
  "endpoint": "https://destination.example/repo",
  "scope": {
    "tenant_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "repository_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "repository_incarnation": "cccccccccccccccccccccccccccccccc",
    "principal_id": "dddddddddddddddddddddddddddddddd",
    "object_format": "sha1"
  },
  "number_start": "100",
  "merged": "refuse",
  "ref_map": []
}
```

The destination scope is selected independently, not derived from the archived
actors. Destination PR numbers are consecutive, in the archive's source order,
starting at the exact decimal `number_start` (full u64). Collisions are native
refusals; no number, version, ref or tip is silently refreshed. Import Git objects
and establish the required destination branches separately before submitting.

```sh
node scripts/migrate_native_pulls.mjs prepare \
  --archive-dir /srv/import/pulls/archive \
  --archive-confirm "$ARCHIVE_SHA256" \
  --selection /srv/import/selection.json \
  --token-file /srv/import/destination.token \
  --workdir /srv/import/prepared

node scripts/migrate_native_pulls.mjs inspect \
  --workdir /srv/import/prepared --confirm "$PLAN_SHA256"
```

Both operations are offline. Keep the returned `plan_sha256` independently.
Preparation verifies the complete archive with the existing native decoders and
page traversal, then verifies every owned page against the original commitments.
It compiles the entire source before generating keys, checks all receipt sizes
before creating output, retains a private copy of the archive, and publishes the
manifest only after full readback of source and every request. Inspection works
after removal of the original source archive and credential.

Each `requests/step-NNNNNN` directory is an ordinary immutable request slot
compatible with the [remote PR operator](REMOTE_PULL_REQUESTS.md). The batch
coordinator below reuses that same sender and original-key outcome reader; it
does not generate another native request representation. Do not mix manual sends
with batch execution. The batch is not an atomic destination transaction.

## Execute, resume and recover

```sh
node scripts/migrate_native_pulls.mjs run \
  --workdir /srv/import/prepared --confirm "$PLAN_SHA256" \
  --token-file /srv/import/destination.token --max-operations 100

node scripts/migrate_native_pulls.mjs status \
  --workdir /srv/import/prepared --confirm "$PLAN_SHA256"
```

`run` verifies the entire retained archive, recompiles its plan and checks every
original request before contacting the destination. It then executes in source
order through the unchanged `submitPull` sender. Each new request uses an
original-key lookup before sending and a confirmation lookup afterwards. Only an
observed committed terminal permits a successor. A native refusal stops the plan:
no automatic renumbering, version update, branch refresh or strategy fallback.

The default allowance is 100 sender/recovery operations per invocation; it can be
lowered or raised to at most 8,192. One sender operation uses at most three HTTP
requests, while a recovery uses one. All calls share the invocation's remaining
deadline, including preflight. Exhausting the operation allowance returns an
explicit incomplete result. Run again with the **same plan pin** to continue.
Already confirmed requests are not submitted again. The destination credential
is required only when a network operation is needed; completed jobs run offline.

Before any potential send, an exclusive append-only attempt slot is created and
its `started.json` reservation is synchronized. It binds the complete plan pin,
original key, step, operation and preceding reservation. A missing result means
**unknown**, not permission to resend. A normal later `run` can only recover that
key. Read-only recovery can also be requested separately:

```sh
node scripts/migrate_native_pulls.mjs recover \
  --workdir /srv/import/prepared --confirm "$PLAN_SHA256" \
  --token-file /srv/import/recovery.token
```

`recover` never submits a PR mutation, even after it confirms a previous commit.
It does not start an unattempted step. A rotated credential may read the original
outcome only if the native response still identifies the independently retained
original principal. Sending a new request or retry requires the original
credential fingerprint. An optional `--ca-file` supplies a private certificate
trust file to the existing HTTPS transport; no redirect or ambient credentials
are used.

A still-unresolved request remains fenced until the operator explicitly consents
to retrying **that exact original key**:

```sh
node scripts/migrate_native_pulls.mjs run \
  --workdir /srv/import/prepared --confirm "$PLAN_SHA256" \
  --token-file /srv/import/destination.token \
  --retry-key "$ORIGINAL_PENDING_KEY"
```

Retry performs another original-key lookup first. A retained publication or
terminal prevents another POST. Otherwise it may resend only the unchanged body,
key and expected versions. Consent does not apply to any later unresolved key.
An absent outcome is never presented as proof of non-commit. If preparation or
execution was interrupted, do not prepare a replacement plan to obtain new keys.

`status` validates the full plan and the complete journal without credentials,
network access, or explicit file writes. `inspect` checks the immutable source
and request plan only; use `status` for execution progress. The journal retains
native `pullRecord` observations and validates them with the existing native
record/outcome decoders. Within one invocation it owns its verified immutable
prefix, reading new attempts and previously missing results without reopening
and synchronizing every completed record after each operation. Caller-supplied
cache data is never accepted. Every new invocation and every `status` performs a
full readback. Compatible concurrent reads may arrive out of order:
a weaker nonterminal cannot erase a committed outcome, while conflicting
transaction or terminal identities refuse replay. No local observation becomes
repository authority.

Concurrent runners arbitrate exclusive attempt slots; a loser refuses instead of
overwriting another reservation. No global execution lock is stolen after a
stopped process. SIGTERM/SIGINT drain the native HTTP operation and retain its
result before exit. SIGKILL can leave a reservation without its result; a new
process recovers the same original key. The `unsettled_attempts` count records
missing per-attempt results; a later independent terminal lookup can settle the
key even while an older attempt lacks its own result. Completion requires every
step's committed outcome, not a count of attempted requests or output files.

A torn reservation/result, a gap, unexpected files, inconsistent journal scope
or a replaced directory refuse in place. An empty attempt directory left before
its reservation was completed also refuses; it is not guessed to prove no send.
There is no automatic repair, truncation or deletion. Original request slots
remain available for separately supervised recovery. Whole-plan rollback is not
provided: earlier committed operations survive a later refusal.

## Preserved data and explicit boundaries

Titles and bodies are retained exactly. An origin comment records the source
repository, snapshot, PR number/state/version, actors, raw refs, Git tips and
merge observation. Original conversation bodies are appended in order with
source actor/version attribution. Latest API-visible reviews are appended as
**comments**, including their subjects, candidate observations and decisions;
no review or approval API is invoked. Long bodies are split at UTF-8 boundaries
with part numbers and a commitment to the original body; concatenating their
payloads preserves BOM, CRLF and final-newline bytes.

Only `open`, `comment` and `close` requests are generated. Closed source PRs end
closed. A merged source PR refuses unless `merged: "as-closed"` explicitly
consents to importing it as closed with merge provenance, not recreating a merge.
Metadata-less legacy merge records refuse the whole preparation rather than
inventing a title or silently skipping a PR. The archive remains retained in full.

The destination must use the source Git hash domain. Native tips are unchanged;
there is no object-ID translation or ref mutation. `ref_map` can explicitly map
`source_hex` raw branch bytes to a UTF-8 destination branch. Byte-only names
require this mapping. Duplicate, unused, or aliasing mappings refuse.

Native PR opening requires each selected destination branch to name the exact
recorded tip. Historical PRs can have different old tips under the same original
branch name. New preparation refuses a plan that assigns conflicting tips to one
destination branch, before it generates any request keys. `pull_ref_map` provides
an explicit per-PR alternative to the global ref map, without translating OIDs:

```json
"pull_ref_map": [
  {
    "source_number": "9",
    "source_ref": "refs/heads/import/pr-9/source",
    "target_ref": "refs/heads/import/pr-9/base"
  }
]
```

Each entry supplies both destination refs for that archived source PR; it takes
precedence over global mappings for that PR. There are at most 4,096 entries,
with exact decimal source numbers. Unused entries, duplicates and attempts to
supply replacement tips refuse. Provision these branches separately at the
original source/target OIDs before execution. The operator neither creates nor
moves a ref to make a PR open succeed. A later destination branch move still
produces a native refusal. Closing a successfully imported PR does not require
an implicit tip refresh.

The new field is omitted from normalized legacy selections when not supplied;
existing v1 plan encodings and keys stay unchanged. The new shared-tip check is
a preparation precondition, not a reason to reinterpret or discard already
sealed v1 requests. Such retained plans remain inspectable and their original
keys recoverable, while the destination still decides whether any send is valid.

Source metadata history before the archived current row, original review event
logs, timestamps unavailable in the API, active approvals, credentials,
permissions, attachments, Git objects and workflow evidence are not restored.
This is bounded data migration, not complete FG-049 or a canonical backup restore.

## Bounds and failure

Defaults/ceilings: 8,192 prepared operations, 64 MiB source archive content and
64 MiB total native intent files, with existing per-command and private-file
bounds unchanged. Selection may lower `max_steps`, `max_source_bytes` and
`max_request_bytes`. The default operation deadline is 300 seconds, including
validation. Execution retains at most 32 attempts per step, 32,768 attempts per
job and 32 MiB total for journal contents and reserved capacity for missing results.
Each reservation is at most 1 KiB and each result at most 129 KiB (the original
native record remains bounded to 128 KiB). Before dispatch, enough capacity is
reserved for the full result; prior attempts count across every invocation.
These byte bounds do not count filesystem block overhead. Cancellation does not
discard an already received terminal: bounded local result finalization drains
after the network deadline, rather than pretending a result vanished. Refusal
never labels a prefix complete. All records are owner-private
and create-only, outside Git worktrees; damaged or partial preparation is retained
and cannot run as a complete plan. These checks are not a hostile-same-UID sandbox
or a hardware power-loss durability claim.

CLI exit **0** means preparation/inspection/status succeeded, or all execution
steps are confirmed committed. Preparation and status can succeed while reporting
an incomplete migration. Execution exit **1** is a native refusal; **3** is a
ready, paused or unresolved incomplete result. Exit **2** is an argument or
preflight refusal. Exit **4** reports an error with a verified/retained plan or
uncertain output; inspect its status instead of regenerating requests. Always
read `state`, `complete`, and the original current key, not just the exit code.
Output failure never deletes a result, generates keys or resends requests.

## Local verification

```sh
bash scripts/verify_native_pull_import.sh
```

Tests execute the full production archive validator, command codec, file custody,
remote sender and original-key outcome decoder against actual loopback HTTP
response-schema peers. They exercise both hash domains, exact u64 numbering,
metadata/comments/reviews, merged-state consent, byte-only mappings, resource
bounds, corruption, source removal and real CLI processes. Batch tests cover
lost replies, exact-key explicit retry, refusal/collision stops, credential
rotation, publication-before-confirmation failures, out-of-order concurrent
reads, unchanged keys across operation limits, cumulative attempts, and a
21-PR/105-operation HTTP migration split at the default 100-operation allowance.
Real child processes receive SIGTERM, SIGINT and SIGKILL during a committed HTTP
response, then recover from a fresh process without a duplicate mutation POST.
Torn/missing record tests are controlled filesystem cases, not physical
power-loss tests. The fixture's destination state is only a schema peer; it is
not an implementation of or evidence for native Git and admission correctness.
These are not Rust
`fg`/admission/CAS tests, Git object-closure tests, or a deployed service gate.
