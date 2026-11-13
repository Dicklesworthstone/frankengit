# Require LFS payloads before accepting a Git push

`fg serve`, `fg serve-ssh`, and `fg serve-http` accept an explicit
`--require-lfs-payloads <absolute-private-directory>` deployment policy. When
selected, the shared production quarantine validator checks supported LFS
pointers throughout the proposed Git history before promoting received objects
or submitting their ref updates for admission. A successful LFS upload alone
still grants no authority to publish a branch.

This implements the receive-side pointer-availability part of
`frankengit-fg053-lfs-i3h`. It does not close that bead's retention, interoperability,
or wider acceptance requirements.

## Configure the custody requirement

Use the same existing, operator-owned private artifact directory that receives
the repository's LFS payloads. The current storage profile requires Unix and
mode `0700`. The CLI validates custody before reporting listener readiness.

```sh
fg serve-http /srv/frankengit-state "$TENANT_ID" "$REPOSITORY_ID" 127.0.0.1:8080 \
  --trusted-local --credentials-file /srv/frankengit-credentials \
  --lfs-root /srv/frankengit-lfs --allow-receive \
  --require-lfs-payloads /srv/frankengit-lfs \
  --continuous --stop-file /srv/frankengit-stop
```

For SSH or raw Git, add the same `--require-lfs-payloads` argument to the
existing service command. Payloads can be uploaded through a separately
configured HTTP listener or imported with the [LFS portability commands](GIT_LFS_PORTABILITY.md).
Their namespace must match the exact tenant, repository, and authenticated
incarnation served by the Git listener.

The requirement is independent of `--lfs-root`, receive enablement and transport
credential grants. It neither enables an LFS endpoint nor gives a writer LFS
download access. HTTP transfer still requires its own `lfs-read` or `lfs-write`
grant. Each listener's readiness record includes `lfs_payloads_required`.
Omitting the new option preserves the previous Git-only validation behavior.
Deployments must select the requirement on every receive listener that should
enforce it; this option is not a persisted repository-wide policy.

Embedded callers select `NodeConfig::with_receive_lfs_root` and can call
`OneNode::validate_receive_lfs_storage` before reporting readiness. Reopened
service lanes retain the configuration. The check is part of the production
quarantine validator, including reviewed candidates that use that validator;
this does not claim that every native import or forge mutation uses it.

## What the validator checks

The existing pack, graph-kind, visibility, principal and reference checks remain
in force. After native graph authorization succeeds, the LFS check starts from
every nondeleted proposed ref tip and follows commit parents, trees and tags.
Submodule gitlinks remain external references and are not traversed.

The walk includes existing objects, not just the uploaded pack. An empty pack
creating another ref, a new commit that reuses an old tree, and a later commit
that removes a pointer still check pointers in the selected history. Unrelated
objects supplied as pack extras do not cause LFS lookups. Deletion-only pushes
do not require payload custody.

Pointers use the existing extension-free canonical v1 parser: exact version
line, lowercase SHA-256 OID, decimal size and trailing newline. Small blobs with
a recognized LFS version prefix but unsupported pointer syntax refuse instead
of being interpreted as ordinary content. Legacy Git Media/Hawser versions and
noncanonical leading whitespace are recognized for refusal. The original
bytes are never normalized or rewritten. The recognition bound is 1024 bytes;
larger native blobs remain ordinary Git content. This is a deliberately bounded
subset of the [Git LFS pointer specification](https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md),
not an attributes-driven requirement that every large file use LFS.

Each distinct LFS OID is checked once. Conflicting declared sizes for one OID
refuse. `LfsStore` verifies the complete stored payload's SHA-256 and exact byte
length in the selected tenant/repository/incarnation namespace. A file or an
unfinished Tus session merely being present is insufficient. Payloads from
another repository or incarnation cannot satisfy the requirement.

Existing native blobs are read to verified EOF, with bounded streaming for
large blobs. An unverified storage header cannot conceal a small pointer by
claiming that its body is larger. Uploaded objects already passed native pack
verification; small spooled pointer candidates are verified again when read.

## Bounds and refusal behavior

The check shares the original receive cancellation/deadline capability and
adds these fixed aggregate ceilings per validation:

| Resource | Maximum |
| --- | ---: |
| Distinct reached native objects | 1,000,000 |
| Traversed native edges | 4,000,000 |
| Metadata and small pointer-candidate bytes | 256 MiB |
| Existing native blob verification | 4 GiB |
| Distinct LFS OIDs | 4,096 |
| Total declared LFS payload bytes verified | 4 GiB |
| One LFS payload | 512 MiB |

The existing pack/object limits also apply. Repeated graph references and
identical pointers do not multiply verification work. Reaching a bound refuses
the request; the implementation never accepts a partial scan. This profile
walks the proposed history and makes no incremental-scan performance claim.

Missing payloads return `ObjectClosureIncomplete`. Recognizable malformed or
unsupported pointers return `ObjectHeaderInvalid`; corrupt verified custody
returns `EvidenceInvalid`; unavailable custody returns
`DurabilityProfileUnavailable`; exhausted limits return `ResourceBudgetExceeded`.
Cancellation preserves the existing typed receive refusal. Diagnostics do not
disclose the payload identity or filesystem path. A failing check precedes
staging and admission, including all siblings of a non-atomic push.

After uploading a missing payload, retry the original Git push. The check does
not change transaction identities or overwrite historical decisions. Ordinary
receive validation still precedes outcome recovery: subsequent custody damage
can refuse a retry before it recovers an earlier committed outcome. Use the
existing independently authorized outcome API when that distinction matters;
a refused attempt never proves that an earlier attempt did not commit.

The LFS backend currently retains payloads permanently. This check does not
introduce a GC root or a lease against future collection, and assumes the
existing immutable, operator-protected custody contract. Pointer-aware GC must
add its own canonical retention integration before that contract changes.

## Focused verification

The native validator tests cover both Git hash formats, missing/uploaded/corrupt
payloads, existing history and empty packs, unrelated pack extras, gitlinks,
namespace isolation, deletion, cancellation, budgets and malformed pointers.
The HTTP integration test drives persisted receive and LFS upload over real
loopback connections, including restart and unchanged authority on refusal.
These are native integration tests, not a pinned stock-client qualification.

```sh
cargo test --locked -p fgit-node --lib quarantine_validator::lfs::tests
cargo test --locked -p fgit-node --test lfs_streaming_http receive_policy -- --test-threads=1
```
