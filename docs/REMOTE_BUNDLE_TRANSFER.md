# Persistent-key remote Git-bundle transfer

FG-058 / FG-049: external operator access to the existing native HTTP bundle
import/fetch endpoints. This closes the Git-object-transfer prerequisite for
branch bootstrap and PR migration without implementing another Git engine.
The server still owns pack decoding, graph closure, reachability, visibility,
ref protection, admission and the single atomic terminal decision.

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
