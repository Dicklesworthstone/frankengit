# Native self-contained Git bundle transfer

`fg bundle export` and `fg bundle import` connect native Git bundles to the
embedded node. They transfer Git objects and direct refs between repositories
without invoking another Git implementation. They do not back up or migrate
canonical authority, issues, reviews, policy, accounts, credentials or outbox.

## Usage

For an existing SHA-256 source node, export to an absent output path:

```bash
fg bundle export "$SOURCE_ROOT" "$SOURCE_TENANT" "$SOURCE_REPOSITORY" repo.bundle \
  --trusted-local --object-format sha256
```

Initialize a destination with the matching native object format, then import:

```bash
fg init "$DESTINATION_ROOT" "$DESTINATION_TENANT" "$DESTINATION_REPOSITORY" sha256
printf '%s' 'offline-transfer-001' | \
  fg bundle import "$DESTINATION_ROOT" "$DESTINATION_TENANT" "$DESTINATION_REPOSITORY" repo.bundle \
    --trusted-local --object-format sha256 --principal "$PRINCIPAL" --key-stdin
```

These are trusted-local operator commands, not remote authentication endpoints.
For SHA-1, initialize with `sha1` and use `--object-format sha1` (the default).
Each command produces one JSON receipt. Exit 0 means export/committed import,
3 means canonical import refusal, and 2 means invalid input, infrastructure,
output or cleanup failure. A committed receipt remains committed even if later
cleanup or receipt output fails. Retry the original operation and key, or use
`fg outcome`, rather than assuming an error proves non-commit.

Export publishes the artifact with the existing create-only, synced file
publication helper. It never truncates or replaces an existing output. Input
files must be bounded regular files in the same trusted-local filesystem
profile used by reviewed merge/rebase artifact intake. Stdin keys retain exact
bytes, including newlines, and are not printed in receipts.

## Semantics and support

Export selects one authenticated current authority head and applies both the
canonical hidden-ref policy and the caller's narrowing visibility filter. Only
the complete graph reachable from those visible direct refs is exported.
Retained objects reachable only from deleted/hidden refs are not extra roots.
The library entrypoint optionally requires an exact expected authority head;
a mismatch refuses rather than mixing snapshots. Native object bytes and IDs
are preserved. Output ordering is deterministic and uses the existing native
compressed, no-delta pack profile.

The codec writes V2/SHA-1 and V3/SHA-256. Input accepts ordinary unordered direct
ref advertisements, optional HEAD, V2/SHA-1, and V3/SHA-1 or V3/SHA-256. V3 without
an object-format capability has the format's SHA-1 default. A HEAD advertisement
must name an advertised branch tip. It is not permission to change destination
HEAD configuration, and such configuration is deliberately preserved.

Fresh imports reconstruct the supplied pack in quarantine. Every native object
is verified; every selected graph edge must resolve with its required kind.
Branch tips must be commits. All referenced objects and delta bases must be
supplied in the bundle: omitted objects cannot be borrowed from destination
storage even when they are present there. Existing receive behavior retains its
separate authenticated borrowing profile. Only a completely verified selected
closure is staged for admission.

Every advertised direct ref is an expected-absent creation, and all creations
belong to one atomic native receive transaction. A single destination-name
collision refuses the whole ref update, even when both tips are identical.
Existing policy and exact-basis authority publication remain mandatory. There
is no force switch, implicit overwrite, caller-minted closure proof, separate
branch database or automatic conflict retry.

Exact terminal recovery precedes serving/quota/current-object checks. As with
native receive, the sealed identity binds the semantic ref command set, not a
particular compression of the same objects. Recovery is not fresh verification
of an artifact: the bounded header still identifies the exact operation, but
an already authenticated terminal outcome need not re-verify pack bytes.

Unsupported profiles return refusals: incremental/prerequisite bundles,
filtered/partial bundles, unknown or duplicate capabilities, detached HEAD,
empty direct-ref sets and implicit hash-domain conversions. Limits include
4096 header records, a 1 MiB header, a 128 MiB whole-file bound and the node's
stricter pack, expansion, object-size, graph-work and cancellation budgets.
This is a bounded complete-transfer profile, not streaming large-repository
support or a universal Git interoperability claim.

## Implementation and verification

`fgit-pack::full_bundle` owns the bounded envelope and deterministic writer.
`OneNode::export_full_git_bundle_in` and
`OneNode::import_full_git_bundle_durable_in` own current-authority selection,
quarantine composition, exact replay and publication. The complete-import
profile shares required-kind graph validation with the production receive
validator while explicitly disabling external-object borrowing.

Run `bash scripts/verify_native_bundle.sh check` and
`bash scripts/verify_native_bundle.sh test` locally. The thin connected runner
calls these same entrypoints without write credentials. Tests include both
native hash domains, byte-safe names, corruption/limits/cancellation, real
file-backed transfer and reopen recovery, atomic collisions, visibility,
missing-object refusal despite destination availability, terminal receipt
failure handling and fresh `fg` process transfer. The CLI campaign independently
decodes native exported pack bytes with Python's standard-library hash/zlib
implementations and checks that deleting a branch removes its exclusive
history from subsequent exports while preserving shared ancestors.

These tests are bounded native implementation evidence. They are not a pinned
upstream-Git differential campaign, remote transport authentication evidence,
full forge backup/restore evidence or completion of the wider FG-051a bead.

## Repeatable synchronization with `fg bundle fetch`

Import remains create-only. Fetch is the explicit update path for an existing
repository: select advertised source refs and map them into destination refs.
Every mapping states either `absent` or the exact old native object ID that the
operator previously observed. A batch is one atomic receive transaction; a
stale destination refuses all changes, including otherwise valid creations.

```bash
printf '%s' 'fetch-first-001' | fg bundle fetch \
  "$DESTINATION_ROOT" "$DESTINATION_TENANT" "$DESTINATION_REPOSITORY" repo.bundle \
  --trusted-local --object-format sha256 --principal "$PRINCIPAL" --key-stdin \
  --map refs/heads/main refs/remotes/upstream/main absent

printf '%s' 'fetch-update-002' | fg bundle fetch \
  "$DESTINATION_ROOT" "$DESTINATION_TENANT" "$DESTINATION_REPOSITORY" newer.bundle \
  --trusted-local --object-format sha256 --principal "$PRINCIPAL" --key-stdin \
  --map refs/heads/main refs/remotes/upstream/main "$PREVIOUS_MAIN_OID" \
  --map refs/heads/topic refs/heads/review-topic absent
```

`--map-hex SOURCE_HEX DESTINATION_HEX absent-or-old-oid` preserves arbitrary
valid native reference-name bytes. Mixed `--map` and `--map-hex` inputs are
accepted. Repeated destination names, unknown sources, implicit `latest`, zero
old IDs, wildcards, force, and prune are refused. One source can feed multiple
explicit destinations. Neither unselected source refs nor their exclusive
objects are published. HEAD and forge metadata remain untouched.

Destinations are restricted to `refs/heads/`, `refs/remotes/`, and `refs/tags/`.
Branches and remote-tracking refs must target commits. An update must be equal
or a fast-forward proven from actual verified commit-parent edges in the
supplied pack. Tree edges and advertised IDs do not prove ancestry. Tags may
be created or reasserted at the same ID, but never replaced. This requirement
is additional to, not a replacement for, current authority policy and exact
expected-old admission. A mandatory review policy still blocks direct changes
to its protected branches.

The input remains self-contained, even when the destination already stores
its ancestry. This is repeatable offline synchronization, not prerequisite-
bundle negotiation, network fetch, a remote-authentication endpoint, or
bandwidth-efficient incremental transfer. Existing pack byte, object, graph,
and cancellation bounds remain in force. An additional finite ancestry-work
budget is shared across every update and parent edge in the batch.

The receipt type is `git_bundle_fetch`; it includes tenant, repository,
principal, native format, canonical transaction/decision identity, sorted
requested mappings, reference count, outcome and cleanup state. Exit 0 means
committed, 3 means a canonical refusal, and 2 means input, quarantine,
infrastructure, output or cleanup failure. A typed pre-admission refusal is
not a recorded canonical decision. A transport error is not proof of
non-commit; use the original scoped key for recovery.

The sealed operation is the canonical destination/expected-old/new command
set. Reordering mappings does not change that identity, and alternate source
advertisements of the same native target do not invent a second authority
operation. Retry after a terminal decision recovers that decision before
current intake checks; it is not fresh verification of the bundle contents.
No automatic rebase or changed-old-tip retry is performed.

Library users call `OneNode::fetch_full_git_bundle_durable_in` with
`fgit_node::BundleRefMapping` values. The codec's `select_updates` derives
bounded, deterministic update targets; it provides no authority or object
proof. Node quarantine verifies supplied native objects and ancestry before
staging, then uses the existing basis-bound admission path.

The bundle verification script also runs mapped-fetch unit/integration cases
and `native_bundle_fetch_smoke`. The fresh-process test exercises both hash
domains, raw names, selected-object closure, fast-forward updates, atomic
stale-tip rejection, exact retries and corrupt input using the real `fg`
binary. Exported objects are independently decoded in the test with Python's
standard-library hash/zlib implementation; no external Git process supplies
production behavior.
