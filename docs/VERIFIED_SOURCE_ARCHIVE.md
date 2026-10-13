# Verified source archives

The external operator module `scripts/operator/source_archive.mjs` acquires a
complete, bounded source snapshot from the existing authenticated `source/log`,
`source/tree` and `source/blob` HTTP APIs. It does not invoke Git, stage objects,
move refs, publish forge events, or change native authorization.

The concrete consumer is a source export whose file contents and paths must be
bound to an independently selected commit. Individually checking blob hashes is
insufficient: a server can otherwise substitute the file-to-path mapping or omit
files while every returned blob still hashes correctly.

## Selection and proof

`captureSource(selection, token, options)` requires the repository endpoint,
tenant ID, repository ID, incarnation, object format, full UTF-8 reference, and
expected commit. A supplied `expected_head` is an additional constraint. The
expected commit must be obtained independently to establish a meaningful trust
anchor. A commit-valued reference is required; annotated tags are not implicitly
peeled. This operation reads the current ref, not an arbitrary historical OID.

The first bounded log page verifies the original commit bytes and its tree and
parent summaries. Every subsequent request retains the selected head, commit,
reference, scope and source record. Directory pages are assembled and hashed in
native Git order, which differs from the API's raw-name pagination order for
names that prefix directory names. The root tree is bound to the hashed commit;
every child tree is bound to its parent. Every directory must verify before blob
acquisition begins. Complete files are then read in native ranges of at most
1 MiB and hashed with the Git blob header under SHA-1 or SHA-256.

No successful prefix is returned. Missing pages, entries, objects, changed
snapshots, unsafe native traversal components, wrong modes, mismatching blobs,
resource exhaustion, cancellation, or unavailable native reads refuse the whole
operation. There is no re-selection or network retry. The node's native history
bounds can also refuse the initial log read even when the requested tip exists.

The result contains a capture (original commit bytes, reconstructed exact tree
bytes, raw hexadecimal paths and file buffers) and separately computed read
metrics. Symlink targets remain bytes, and gitlinks remain exact tree identities;
submodule repositories are never traversed. No host paths are created.
`validateCapture` independently repeats the complete membership/hash checks and
refuses missing, unreachable, duplicate or changed material before a consumer
uses a public capture.

## Bounds and transport

Default hard ceilings are 4,096 entries, 1,024 directories including the root,
32 path components, 4 MiB of tree bodies, 16 MiB per blob, 64 MiB of total file
payload, 8,192 requests and 192 MiB of received JSON body bytes. Limits can only
be tightened. The whole acquisition, including hashing, shares a monotonic
120-second deadline. The implementation retains one bounded capture in memory;
limits are not streaming or constant-memory claims.

Only verified HTTPS or canonical numeric-loopback HTTP is allowed. Credentials
are supplied explicitly and never included in the capture. An optional bounded
private CA bundle selects the explicit trust roots for that connection; certificate
and hostname checks remain enabled. There are no redirects, cookies, ambient
proxy use, mutation methods, idempotency keys, or automatic retries. Malformed
response text is not copied into error diagnostics. Current native scope gates
and quota decisions still apply to every request.

## Limits of the claim

This checks native Git content and tree membership, not authority signatures,
author identity, Git SHA-1 collision detection, independently current branch
state, permission to redistribute source, or repository/forge backup completeness.
Gitlinks are represented, not hydrated. Noncanonical original tree modes cannot
be reconstructed from the current API's kind-only summaries; such trees refuse
rather than being silently rewritten. Capture paths remain arbitrary native byte
names, not permission to materialize them on a host filesystem.

## Validation

```sh
bash scripts/verify_source_archive.sh
```

The source peers are real loopback HTTP sockets implementing the inspected native
schema, not Rust `fg`. Separate tests run installed Git as a non-production
hashing oracle for both object formats. A passing contract suite is not a live-node
permission/admission test, a real-browser test, or the full workspace gate.


## Capture a downloadable archive

The complete command is `scripts/fg_source_archive.mjs`. Filesystem operations
require Node 22.16 or later on the POSIX private-file profile. The service must
already expose the native source APIs and the token must have the existing source
read/upload-pack grant. Archive capture does not need receive, PR, outcome, or
administrator permission.

Keep the selection, token, optional CA and optional limit files in owner-private
0700 directories outside untrusted workspaces. Each input must be a private,
regular, single-link file without symlink aliases. The output's existing parent
must also be owner-private 0700. The command creates only the requested archive
file, never source-named host paths. Example selection-file shape (replace the
commit placeholder with an independently obtained full native ID):

```json
{
  "endpoint": "https://forge.example/team/repo.git",
  "tenant_id": "11111111111111111111111111111111",
  "repository_id": "22222222222222222222222222222222",
  "repository_incarnation": "33333333333333333333333333333333",
  "object_format": "sha1",
  "ref": "refs/heads/main",
  "expected_commit": "REPLACE_WITH_FULL_NATIVE_COMMIT_ID"
}
```

The token file contains exactly 64 lowercase hexadecimal characters and an
optional single newline. It is never included as archive metadata. Source itself
may contain secrets: the exporter is not a redaction service or a permission to
redistribute repository content.

```sh
node scripts/fg_source_archive.mjs capture \
  --selection /srv/archive-input/selection.json \
  --token-file /srv/archive-input/source.token \
  --layout portable \
  --output /srv/archive-output/source.tar
```

`--ca-file` accepts a private PEM bundle without disabling hostname verification.
`--limits` accepts a private JSON object of any `ARCHIVE_LIMITS` fields; values
can only tighten the published limits. Existing output paths, including symlinks,
are refused. A collision that appears during capture cannot overwrite the other
writer's file.

Capture verifies all source, constructs the complete deterministic archive,
inspects it again, then writes/syncs it under a temporary name and makes the final
name visible with the existing create-only writer. It reads the final file back
before emitting a compact JSON receipt containing the archive SHA-256, native
commit/root identities, counts and read metrics. No source text is printed to
stdout. Once file publication starts, SIGTERM/SIGINT allow that write and readback
to drain. A hard crash may leave a private temporary file or a complete final
file; existence is not a verification result. No stale files are stolen,
overwritten, or automatically resumed. This is not a hardware-power-loss or
universal filesystem durability guarantee.

## Two explicit layouts

Both layouts contain `frankengit-source.json`, an exact proof manifest with original
commit/tree bytes, source selection, file identities and original raw hexadecimal
paths. They preserve the complete selected superproject tree, including gitlink
identities, but not parent-commit bodies, other refs, forge state or submodule
repositories. Neither layout is a backup or a complete Git checkout.

`portable` puts files below `source/` using a strict printable-ASCII, non-colliding
path profile. It refuses traversal, VCS metadata aliases, Windows device/stream
names, case collisions and paths not representable by the bounded ustar header.
It never normalizes, guesses or drops a filename. Symlink **payloads become regular
files**, executable files have archive mode 0644, directories have mode 0755, and
gitlinks become empty directories with their true identities in the manifest.
This is deliberately an inert file export, not executable checkout fidelity.
Attributes such as `export-ignore`, `export-subst`, filters and LFS hydration are
not interpreted: exact committed bytes, including pointer files, are retained.

`objects` stores each distinct, verified blob at
`payloads/<object-format>-<native-id>.blob`. Every original path/kind remains in
the manifest, so raw non-UTF-8, long or platform-conflicting names remain lossless
without creating unsafe archive paths. Only byte-identical blobs share a member.
This is the lossless portable representation for source names the `portable`
layout cannot materialize. The command does not silently switch layouts.

Archives use deterministic uncompressed ustar framing, zero timestamps and
owner IDs, no link/device/sparse/PAX/GNU-extension records, a maximum 12 MiB proof
manifest, and an 80 MiB archive ceiling. Equivalent normalized captures generate
identical bytes regardless of traversal order. Different observed authority
snapshots or endpoint selections can legitimately produce different archive
hashes even for the same source commit. Archive generation and acquisition retain
bounded buffers; they are not constant-memory streaming operations.

## Verify offline, without extracting

Retain the receipt hash independently of the archive. Later inspection needs only
the private archive file and that hash, not the original selection file, token,
network, repository storage or `fg` executable:

```sh
node scripts/fg_source_archive.mjs inspect \
  --archive /srv/archive-output/source.tar \
  --sha256 "$INDEPENDENTLY_RETAINED_ARCHIVE_SHA256"
```

Inspection first checks that external archive hash, then validates the complete
closed tar framing, manifest, every member, source tree chain and blob identity.
It reconstructs the expected metadata/member set and ordering, rejects duplicates,
extra payloads, changed paths, padding or proof-class claims, and never extracts
anything. It does not accept arbitrary third-party tar extensions. Successful
inspection is content/path verification against the selected commit, not an
authority signature or a freshness/authorization proof. To unpack using other
tools, choose a new empty directory and treat all contents as untrusted data.

Exit codes: 0 means a verified archive or successful inspection; 2 is input,
source, verification, profile or resource refusal; 3 is cancellation before file
publication; 4 means file publication or output delivery needs inspection. Exit 4
includes either a validated `retained_receipt` or an explicitly unconfirmed
expected path/hash. The latter never asserts the path exists or belongs to this
writer. A broken stdout pipe cannot delete an already saved artifact.

The tests add real CLI process, private-file, TLS trust/hostname, interruption,
concurrent writer and broken-output cases. Python's standard tar reader checks
interoperability separately from the production inspector. An isolated negative
control removing tree hash checks makes the missing-entry refusal test fail;
fixtures with individually valid blobs cannot establish a complete tree alone.
These are still explicit native-schema HTTP fixtures, not a live Rust-node test.
