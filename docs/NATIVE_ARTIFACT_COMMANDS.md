# Native immutable artifact commands

`fg artifact put`, `inspect`, and `export` connect the CLI to the existing
`fgit_object_fabric::artifact::storage::LocalArtifactStore`. There is no second
payload format or database and no subprocess doing hashing or storage. This is
explicit trusted-local byte custody, not a repository mutation or a remote API.

All commands select an existing private root plus tenant, repository,
repository incarnation, and trust domain. Inspect/export require the original
artifact ID, not a filename. Put requires the expected raw payload SHA-256 and
length. The storage owner checks the entire payload and retained stage before
installing its immutable name; an existing name is accepted only after full
verification. A corrupt existing object is never overwritten by a retry.

```sh
fg --timeout-secs 120 artifact put /srv/fg-artifacts \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  33333333333333333333333333333333 \
  --trusted-local --trust-domain trusted-ci \
  --source /srv/ci-output/test-report.json \
  --payload-sha256 <64-lowercase-hex> --payload-bytes <exact-length> \
  --kind ci_artifact --media-type application/json
```

Use actual scope IDs and an independently retained expected payload digest.
Substitute `inspect --id <artifact-id>` or `export --id <artifact-id>
--output /srv/export/test-report.json`, retaining the same root and scope flags.
The export parent must exist with mode 0700 and the destination must not exist.
Export verifies into a private temporary file and installs the verified bytes
only afterward; it never truncates or replaces an existing file or symlink.

## Identity, provenance and compatibility

The JSON result includes the artifact and payload digests, exact length/media/kind,
complete scope and its commitment, optional producer/check/source commitments,
and the canonical retention encoding. `--expected-id` additionally pins the full
put identity before any storage is opened. Changing kind, media, provenance or
retention changes that identity. Changing scope selects a different storage
namespace even for the same identity. Original artifact encoding is unchanged.

`--source-rcr`, `--build-capsule`, and `--check-receipt` accept SHA-256 commitments.
They are supplied assertions; this command does not authenticate those producers
or verify a check receipt. Its result explicitly records
`provenance_authenticated: false` and `canonical_repository_published: false`.
No reference, release alias, package namespace or required check is published.

Put currently selects the existing `HotEphemeral` retention encoding, with
`--ttl-secs` defaulting to 86400. TTL is immutable metadata, NOT automatic deletion.
Inspect/export preserve other retention encodings already present in the store.
No cache hit, retention-root authority, legal-hold enforcement or garbage
collection is inferred from an artifact's existence.

## Bounds and lifecycle

The default payload bound is 64 MiB. `--max-payload-mib` selects 1..512 MiB;
metadata remains bounded by the existing store. Empty payloads are valid when
their expected digest and length match. Storage streams in 64 KiB chunks.
One `ArtifactOperation` deadline begins before storage selection and spans all
verification, retry and output-staging phases. The global `--timeout-secs`
override remains a ceiling; artifact operations reject durations over one hour.
SIGTERM/SIGINT use the existing Asupersync-backed `TerminationSignals` latch and
are polled by the same operation. No additional runtime or foreign code is used.
Filesystem system calls and stdout are not forcibly preempted by this deadline.

Argument refusals occur before storage access. Payload, storage or cancellation
refusals can leave an empty scope directory, but do not expose an unverified
export prefix. After final linking, an error is not proof of absence. Original
staging/collision/durability rules are described in `LOCAL_ARTIFACT_STORAGE.md`.
Root, export parents and source ancestors must be operator-controlled and stable.
Symlink and nonregular input checks do not create a sandbox against hostile
same-UID directory replacement. The store needs an operator-managed disk quota.

Exit 0 means the selected operation completed; 2 is a refusal; 3 is uncertain
local publication; 4 means completion was observed but writing/flushing stdout
failed. A best-effort stderr diagnostic retains the complete successful receipt
on output failure. Inspect or retry the original identity; do not rerun the
producing workflow just because a receipt was lost. No payload bytes go to stdout.

## Verification

`cargo test -p fgit-cli --bin fg artifact_command --locked --offline` exercises
strict preflight, exact identity pins, source-free reopen, binary payloads,
collision retry, corruption, foreign scope, symlink/nonregular refusal,
cancellation and completed-storage/output-failure separation using real files.
The existing `fgit-object-fabric` artifact-storage suite remains the storage
oracle. These checks are not hostile-filesystem or physical-power-loss evidence.
