# Persistent-key remote Git-bundle transfer

FG-058 / FG-049: external operator access to the existing native HTTP bundle
import/fetch endpoints. This closes the Git-object-transfer prerequisite for
branch bootstrap and PR migration without implementing another Git engine.
The server still owns pack decoding, graph closure, reachability, visibility,
ref protection, admission and the single atomic terminal decision.

## Command-line workflow

The repository must already exist, and source/read, receive and outcomes-read
grants must be independently enabled on the native HTTP service. An exported
artifact is not permission to write the destination. Use private selection files
and retain the returned independent pins at each step.

A source selection contains the exact source endpoint and four-field identity;
`expected_head` is optional but prevents substituting a later snapshot:

```json
{
  "endpoint": "https://source.example/repo",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "object_format": "sha1"
  },
  "expected_head": "alg:2:6666666666666666666666666666666666666666666666666666666666666666",
  "max_bytes": 67108864
}
```

```sh
node scripts/remote_bundle.mjs export \
  --workdir /srv/transfer/download --selection /srv/transfer/source.json \
  --token-file /srv/transfer/source-reader.token

node scripts/remote_bundle.mjs inspect-download \
  --workdir /srv/transfer/download --confirm "$DOWNLOAD_SHA256"
```

`DOWNLOAD_SHA256` is the returned `download_sha256`, not the artifact hash.
The download validates the native profile, all identity headers, exact optional
snapshot, fixed length and artifact SHA-256. It rejects ambiguous duplicate
headers, redirects, unknown content coding, mixed identity and oversize input
before sealing anything. Only fully received and verified bytes are published;
`download.json` is written last after private payload synchronization/readback.
The descriptor binds source scope/head/snapshot and complete artifact length/hash.
Offline inspection needs no source connection or credential. This is transport
integrity, not an independent signature, Git validation or canonical backup.

The native export service has a larger 128 MiB construction ceiling, but this
operator intentionally accepts at most **64 MiB**, so a downloaded artifact fits
the current HTTP import/fetch payload envelope. `max_bytes` may lower that bound.
Larger downloads refuse before body allocation rather than producing a useful-
looking prefix or an artifact known to exceed the destination profile. Source
export is pinned to the current native head, not a retained historical read;
a changed or expired pin requires a new explicit source selection, not an
unannounced fallback. Cancellation during delivery leaves no complete download.
An interrupted local publication retains its partial directory without repair.

The destination selection is the `selection` object in the library example
below: it adds the independently selected destination `principal_id` and an
explicit `operation` (`import` or `fetch`). For example, fetch can preserve the
source main branch under a remote-tracking ref with an absent lease:

```json
"operation": "fetch",
"mappings": [{
  "source_hex": "726566732f68656164732f6d61696e",
  "destination_hex": "726566732f72656d6f7465732f696d706f72742f6d61696e",
  "expected_old": "absent"
}]
```

```sh
node scripts/remote_bundle.mjs prepare \
  --workdir /srv/transfer/upload --selection /srv/transfer/destination.json \
  --bundle-file /srv/transfer/download/repository.bundle \
  --bundle-confirm "$ARTIFACT_SHA256" \
  --token-file /srv/transfer/destination-writer.token

node scripts/remote_bundle.mjs inspect \
  --workdir /srv/transfer/upload --confirm "$INTENT_SHA256"

node scripts/remote_bundle.mjs run \
  --workdir /srv/transfer/upload --confirm "$INTENT_SHA256" \
  --token-file /srv/transfer/destination-writer.token

node scripts/remote_bundle.mjs status \
  --workdir /srv/transfer/upload --confirm "$INTENT_SHA256"
```

`ARTIFACT_SHA256` is the export's `artifact_sha256`; `INTENT_SHA256` is the new
prepared request's `intent_sha256`. Preparing copies owned bytes into the upload
job, so the source download can be removed without changing a later upload.
`inspect` verifies the payload and entire journal; `status` intentionally does
not need payload bytes. Never prepare a replacement key to escape uncertainty:

```sh
node scripts/remote_bundle.mjs recover \
  --workdir /srv/transfer/upload --confirm "$INTENT_SHA256" \
  --token-file /srv/transfer/recovery.token

node scripts/remote_bundle.mjs run \
  --workdir /srv/transfer/upload --confirm "$INTENT_SHA256" \
  --token-file /srv/transfer/destination-writer.token --retry-key "$ORIGINAL_KEY"
```

Every command accepts `--timeout-ms` (1–300,000). Network commands also accept
`--ca-file` for a private certificate trust file. Secrets are read from private
files, never arguments. Argument grammar is closed: force, URL/lease overrides,
implicit refresh and scientific/rounded timeout spellings refuse. The invocation
deadline includes selection loading, validation and output. After an output
failure, a bounded diagnostic retains the completed result and original pin;
it does not repeat reads/uploads or delete custody.

Exit **0** means the selected operation succeeded; preparation and status can
succeed while reporting an incomplete transfer. Execution **1** means a native
refusal, **3** means ready/unresolved, and **2** means argument/preflight failure.
Exit **4** means a retained or potentially published result could not be reported
normally. Read `state`, `complete`, `observation` and the original key. A received
publication may remain in the observation even when confirmation was interrupted.

After the Git transfer is confirmed, the existing [branch bootstrap](NATIVE_BRANCH_BOOTSTRAP.md)
and [PR migration](NATIVE_PULL_IMPORT.md) operate separately with their original
plans and credentials. This does not atomically combine those operations.
Only native-visible source roots and their selected closures are transferred;
retired/hidden-only historical PR tips may still require separate authorized
retention/export support. No download or client-side digest makes them visible.

## Library API

`scripts/operator/remote_bundle.mjs` exports `prepareRemoteBundle`,
`inspectRemoteBundle` and `runRemoteBundle`. Preparation is offline and requires
an independently selected SHA-256 of the exact input bundle. The work directory
must be absent below an owner-private directory outside Git worktrees.

```js
const prepared = await prepareRemoteBundle({
  workdir: '/srv/transfer/job',
  bundleFile: '/srv/transfer/repository.bundle',
  bundleConfirm: independentlyRetainedArtifactSha256,
  tokenFile: '/srv/transfer/writer.token',
  selection: {
    endpoint: 'https://destination.example/repo',
    scope: {
      tenant_id: '11111111111111111111111111111111',
      repository_id: '22222222222222222222222222222222',
      repository_incarnation: '33333333333333333333333333333333',
      principal_id: '44444444444444444444444444444444',
      object_format: 'sha1'
    },
    operation: 'import'
  }
});
```

Retain `intent_sha256` independently. Preparation copies the exact private bundle,
then publishes its immutable request last. That request retains a fresh original
idempotency key, complete selected destination identity, artifact commitment,
operation and mappings, and a fingerprint of the original bearer. It never
retains the bearer itself. Preparation does **not** validate the Git bundle and
reports `native_bundle_validated:false`. Its successful return grants no native
object or ref validity: only native admission does that.

`operation:'import'` requests creation of every advertised direct ref with an
expected-absent lease. Review the selected artifact before preparing it. The
operator does not parse its Git header to invent a ref inventory or infer HEAD.
An existing destination name is a native refusal, not an update opportunity.

For `operation:'fetch'`, supply 1–64 `mappings`, each containing `source_hex`,
`destination_hex`, and `expected_old` (`'absent'` or an exact nonzero unqualified
native OID). Raw ref bytes are preserved, including non-UTF8 names. Destinations
must be under `refs/heads/`, `refs/remotes/` or `refs/tags/`; duplicate destinations
refuse. The native engine decides which selected object closures are admitted.
Neither operation has force, pruning, ref deletion or implicit lease refresh.

## Execution and recovery

Call `runRemoteBundle({workdir, confirm: intent_sha256, tokenFile})` to execute.
One invocation performs at most one bundle upload plus its original-key preflight
and confirmation lookups. Before networking it synchronizes an exclusive
append-only attempt reservation. An occupied slot is never overwritten.

A missing result means unknown, not permission to resend. A normal subsequent
run only looks up that same key. Explicit `retryKey: prepared.key` permits an
unchanged-body retry using the original credential, after another lookup.
A retained publication or terminal prevents resubmission. `operation:'recover'`
never uploads, starts an unattempted transfer, or creates a new request key.
A rotated bearer may recover only the independently retained original principal;
it cannot submit. No redirects, ambient credentials or automatic HTTP retries
are used. Optional `caFile` supplies private certificate trust for HTTPS.

`inspectRemoteBundle({workdir,confirm})` reads the intent and complete attempt
journal offline. `verifyPayload:true` also validates retained payload bytes.
Original-key recovery and offline status do not require the payload, so its loss
cannot justify a replacement key. A confirmed job can be returned offline.
The journal preserves received native observations after cancellation. Compatible
late nonterminal observations cannot erase a confirmed decision; contradictory
native identities or outcomes refuse. Completion requires a matching committed
outcome, not a successful HTTP status or presence of objects.

All credentials and files must be owner-private, singly linked regular files.
Torn reservations/results, unknown files, gaps, changed pins and directory
replacement refuse in place. No automatic repair, deletion or lock stealing is
provided. An earlier missing result may remain visible in `unsettled_attempts`
even after an independent original-key lookup settles the transaction.
Do not mix manual sends with this job's executor.

## Bounds and evidence

The payload limit is 64 MiB, matching the current native HTTP write ceiling,
not the larger native export envelope. Command forms are at most 256 KiB and
requests at most 1 MiB. A job retains at most 32 attempts, each with a 1 KiB
reservation and 64 KiB result. Responses are capped at 16 KiB. One invocation's
1–300,000 ms deadline covers preflight, file validation and all network calls;
received observations drain to bounded local custody after network cancellation.
A payload is owned as bounded bytes, not an unbounded streaming Git parser.

Run `bash scripts/verify_remote_bundle.sh`. Tests execute the full production
operator and unchanged original-key outcome client with real HTTP schema peers
and owner-private files. The peer does not implement Git or authority, and its
opaque test payloads do not establish pack validity, native admission/CAS,
whole-repository compatibility, deployment safety or hardware power-loss
durability. No Rust source, runtime, dependency, grant or native protocol changes.
The broader Git interchange and migration beads remain partial.

The focused suite also executes real Node CLI processes through export/inspect/
prepare/run/status, independent source/destination credentials, SHA-1/SHA-256
transfer, and recovery after SIGTERM/SIGINT/SIGKILL during a committed response
peer. It exercises actual 64 MiB HTTP downloads and multipart uploads, and the
32-attempt cumulative bound. Those are operator transport/custody capacity tests,
not 64 MiB native Git acceptance, native-server performance or a release gate.
