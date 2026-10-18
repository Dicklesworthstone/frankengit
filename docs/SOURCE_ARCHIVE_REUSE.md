# Verified source archive reuse

Repeated source exports can reuse already possessed blob bytes without downloading
all unchanged files. This is acquisition reuse, **not an incremental archive
format**: every output is a complete v1 source archive, independently readable
without any earlier archive. No source store, native route, dependency, Git
implementation or publication authority is added.

## Capture from a retained archive

Supply both an owner-private prior archive and its independently retained SHA-256.
Use a new selection file with the independently chosen current commit. The prior
archive never selects the next commit, endpoint, reference or authority head.

```sh
node scripts/fg_source_archive.mjs capture \
  --selection /srv/archive-input/current.json \
  --token-file /srv/archive-input/source.token \
  --layout portable \
  --reuse-archive /srv/archive-output/prior.tar \
  --reuse-sha256 "$RETAINED_PRIOR_ARCHIVE_SHA256" \
  --output /srv/archive-output/current.tar
```

The original private-file requirements, optional `--ca-file` and tightened
`--limits` remain supported. `--reuse-archive` and `--reuse-sha256` are a pair;
missing, malformed, corrupt or unsafe reuse inputs fail before a credentialed
request. They are not silently ignored or replaced with a cold capture.
The prior archive must match the selected endpoint, tenant, repository,
incarnation and native hash domain. A different reference or commit in that
same scope is permitted; no ancestry relationship is inferred or required.

The selected output layout can differ from the input layout. All original
portable-path checks still apply; use `objects` explicitly for byte-only names.
Nothing extracts or modifies the base archive. Existing outputs, including the
base itself, refuse rather than being overwritten. Concurrent output writers,
signals and delivery failures use the existing create-only publication contract.

## What is verified again

Before connecting, the operator repeats the same closed-tar, manifest, member-set,
commit, tree and file proof as offline inspection. It does not trust a manifest
because its archive hash matches. All prior files are checked, including files
that will not be reused. File bytes are detached before asynchronous network
work; subsequent caller mutation or replacement of the base file cannot alter
the retained input. A missing base discovered on a later invocation refuses.

The operator then authenticates a fresh read and verifies the independently
selected commit and **every directory page** at one current authority snapshot.
No old tree, path, kind, ref tip, source record or currentness claim substitutes
for a fresh observation. Only after the complete tree membership verifies can
matching native blob IDs select previously checked bytes. Renames and mode
changes therefore reuse payloads without retaining obsolete paths or kinds;
deleted files stay absent. Gitlinks remain unhydrated and symlinks remain inert
payloads. Newly encountered identical blobs also download once per capture,
even without a prior archive.

The completed capture is checked again before archive construction. Capture and
archive schemas and deterministic member ordering are unchanged. For an identical
source selection and layout, cold and reused acquisitions produce identical tar
bytes. Reuse metrics are outside the archive, so the output hash does not depend
on how its bytes were obtained.

A current authorization, quota or source-pin refusal still stops acquisition;
there is no offline fallback. Reused blobs are **locally possessed bytes**, not a
new per-blob network read or a freshly issued blob authorization receipt. Current
commit and tree requests remain subject to native grants and limits. This feature
does not revoke previously exported data or assert permission to redistribute it.
Git hash checks are not author authentication, native SHA-1 collision detection,
authority-signature verification or independent branch-freshness proof.

## Accounting and bounds

The CLI's `read_metrics` distinguishes:

| Field | Meaning |
| --- | --- |
| `requests`, `wire_bytes` | Actual current source HTTP requests and received JSON body bytes |
| `blob_requests` | Current blob range requests, including the empty-file request when needed |
| `downloaded_blob_bytes` | Complete unique blob payload bytes acquired over HTTP |
| `reused_files`, `reused_blob_bytes` | Current file occurrences and bytes supplied by the prior capture |
| `deduplicated_files`, `deduplicated_blob_bytes` | Later current file occurrences supplied by a blob downloaded earlier in this capture |
| `blob_bytes` | Total logical bytes across every current file occurrence |

`blob_bytes` equals downloaded + reused + deduplicated blob bytes. Repeated files
still consume logical file-count and byte limits. `maxBlobBytes` applies to cached
files too; neither caching nor archive object-layout deduplication expands the
64 MiB total logical output ceiling. Tree, depth, request and wire limits still
apply. Reuse cannot bypass an unavailable or incomplete current tree.

The prior input is independently bounded by the existing hard archive/capture
ceilings (80 MiB tar, 12 MiB manifest, 64 MiB logical file payload). Narrower limits
for the new output do not incorrectly reject a valid larger prior archive whose
unused files are irrelevant to that output. Prior verification, detachment,
acquisition and output preparation spend the CLI's single configured deadline;
network work receives only its remaining time. Hashing and parsing remain bounded
synchronous work, not preemptible or constant-time operations.

This implementation holds the bounded prior input, reusable blob copies, current
capture and serialized output in memory. It reduces network work, not necessarily
CPU or peak memory. It is not a streaming cache, persistent cache service or an
unbounded archive exporter. The CLI receipt includes `reuse_archive_sha256` to
identify the selected base without embedding local paths, tokens or a required
base dependency in the new archive.

## Offline inspection and API

The normal inspection command is unchanged and requires neither the base archive
nor any credentials:

```sh
node scripts/fg_source_archive.mjs inspect \
  --archive /srv/archive-output/current.tar \
  --sha256 "$RETAINED_CURRENT_ARCHIVE_SHA256"
```

`restoreSourceCapture(archiveBytes, expectedArchiveHash)` returns a detached,
fully verified in-memory v1 capture without filesystem or network effects.
`captureSource(selection, token, { reuse: priorCapture, ...options })` revalidates
that capture and uses it only as a scoped source of immutable blob bytes. Its
returned `capture` is self-contained; `metrics` is a separate observation.

## Verification scope

```sh
bash scripts/verify_source_archive.sh
```

The repository-owned script discovers the new `source_archive_reuse*.test.mjs`
suites alongside all existing capture, tar and CLI regressions. Tests run complete
production modules with actual files, HTTP/TLS sockets and CLI processes. They
cover both Git formats, both layouts, changed commits, byte/mode/path changes,
mutated inputs, corrupted/rehashed archives, private-file checks, logical budgets,
deadlines, auth refusal, signals and output failure. HTTP peers are explicit
native-schema fixtures, not a live Rust node. Passing these tests does not claim
Cargo, native authorization, whole-workspace, deployment or power-loss validation.
