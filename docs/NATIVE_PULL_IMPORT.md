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

Each `requests/step-NNNNNN` directory is an ordinary immutable request slot usable
with the [remote PR operator](REMOTE_PULL_REQUESTS.md). Inspect its original key,
then use its normal explicit send/recover lifecycle; never prepare a replacement
key after an uncertain send. Preparation and inspection themselves do not send.
The batch is not an atomic destination transaction.

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

Source metadata history before the archived current row, original review event
logs, timestamps unavailable in the API, active approvals, credentials,
permissions, attachments, Git objects and workflow evidence are not restored.
This is bounded data migration, not complete FG-049 or a canonical backup restore.

## Bounds and failure

Defaults/ceilings: 8,192 prepared operations, 64 MiB source archive content and
64 MiB total native intent files, with existing per-command and private-file
bounds unchanged. Selection may lower `max_steps`, `max_source_bytes` and
`max_request_bytes`. The default operation deadline is 300 seconds, including
validation. Refusal never labels a prefix complete. All records are owner-private
and create-only, outside Git worktrees; damaged or partial preparation is retained
and cannot run as a complete plan. These checks are not a hostile-same-UID sandbox
or a hardware power-loss durability claim.

CLI exit 0 means prepared/inspected, not migrated. Exit 2 is refusal. Exit 4
reports a failure with retained or uncertain local output; inspect the retained
pin instead of regenerating requests.

## Local verification

```sh
bash scripts/verify_native_pull_import.sh
```

Tests execute the full production archive validator, command codec, file custody,
remote sender and original-key outcome decoder against actual loopback HTTP
response-schema peers. They exercise both hash domains, exact u64 numbering,
metadata/comments/reviews, merged-state consent, byte-only mappings, resource
bounds, corruption, source removal and real CLI processes. These are not Rust
`fg`/admission/CAS tests, Git object-closure tests, or a deployed service gate.
