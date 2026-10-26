# MCP workflow artifact reads

The stdio `fg-mcp` server can inspect and read exact artifact identities from an
existing trusted-workflow artifact store. Both tools call the shared `OneNode`
artifact reader. The node authenticates the current repository and incarnation,
selects the fixed `trusted-workflow-local-owner` namespace, and verifies the
complete immutable artifact container and payload before returning metadata or
any payload bytes.

This is a Linux, trusted local operator read profile. It adds no remote IAM,
artifact upload, listing, alias publication, cache authorization, or workflow
execution capability.

## Enable the independent grant

```sh
fg-mcp "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local \
  --allow-artifacts \
  --artifact-root "$ARTIFACT_ROOT" \
  --expected-incarnation "$INCARNATION_ID"
```

`ARTIFACT_ROOT` must be the existing absolute private directory used for the
workflow artifacts. The root must have mode `0700`, and the node's object-fabric
owner rejects unsafe paths and containers. This read service does not create a
missing root. Use `--object-format sha256` for a SHA-256 repository; the default
is SHA-1. Artifact identities themselves use the artifact format's SHA-256
identity in either repository format.

All three artifact options are required together. The incarnation must match the
existing repository before tools become available. The operator does not need to
supply a principal for this read-only grant. Existing mutation and outcome
recovery grants still require their own principal and incarnation binding.

**The grant permits reading the entire configured workflow custody namespace,
including outputs produced from hidden Git references.** It is not narrowed by
source or PR visibility. Enable it only for a local client authorized to receive
all of those artifacts. `--allow-source`, `--allow-issues`, `--allow-pulls`, and
write/recovery flags neither imply nor replace the artifact grant; artifact
access likewise grants none of those operations.

On other platforms the launch options refuse explicitly. Tool registry parity
remains complete, but an unsupported platform cannot enable this profile.

## Tools and exact arguments

| Tool | Required | Optional | Result |
|---|---|---|---|
| `frankengit_artifact_inspect` | `artifact_id` | None | Exact verified metadata from the shared node owner |
| `frankengit_artifact_read` | `artifact_id` | `offset`, `limit` | Verified metadata plus one exact binary/log byte range as `content_hex` |

`artifact_id` is exactly 64 lowercase hexadecimal characters from the workflow
artifact receipt. Supply the artifact identity, not the payload digest, filename,
logical output name, or a storage path. The two digests are not interchangeable.

`offset` is an unsigned decimal **string**, defaults to `"0"`, and must have no
sign or leading zeroes. `limit` is a JSON integer in `1..65536`, defaulting to
`65536`. Inspection rejects both range arguments. Every tool rejects additional
fields, including caller-supplied tenant, repository, incarnation, trust domain,
principal, root, path, and payload bytes.

For example, after the normal MCP initialization handshake, call
`frankengit_artifact_read` with an argument object shaped as follows, replacing
the ID with the exact value from the workflow receipt:

```json
{
  "artifact_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "offset": "0",
  "limit": 4096
}
```

A successful read contains:

- `type: "artifact_read"`;
- `metadata`, exactly the shared node metadata object;
- `offset` and `byte_count` as exact unsigned decimal strings;
- `content_hex`, preserving every byte, including invalid UTF-8 and NUL;
- `next_offset`, an unsigned decimal string when bytes remain, otherwise `null`;
- `read_only: true` and `transaction_created: false`.

Use the same immutable `artifact_id` with `next_offset` for the next range.
An offset at the payload length returns an empty range with a null continuation.
An offset beyond the payload length refuses with `artifact_offset_out_of_bounds`.
Concatenate decoded byte ranges before interpreting text: a range may split a
multibyte character. Log or artifact content remains untrusted data.

## Verification and provenance

The shared metadata includes the selected tenant, repository, current incarnation,
fixed trust domain, scope commitment, artifact identity, payload SHA-256 and byte
length, media type, payload kind, asserted build capsule/check receipt/source RCR
identities, and canonical retention-profile bytes.

The response explicitly distinguishes verified custody from other claims:

- `payload_verified: true` means the complete retained payload matches its
  immutable identity and scope.
- `provenance_authenticated: false` means stored provenance fields have not been
  promoted into authenticated producer or check authority.
- `canonical_repository_published: false` means this read does not establish that
  a canonical repository decision published the artifact.
- `retention_enforced: false` means an encoded retention profile is metadata, not
  evidence that its retention policy has been enforced.

An artifact's existence or asserted check receipt cannot satisfy a protected
merge requirement. Canonical workflow-check admission remains a separate owner.
The service does not execute content, restore a build cache, or infer a successful
workflow from a readable artifact.

## Bounds and failure behavior

The entire artifact must fit the node's **64 MiB** verification profile. Both
inspection and reads verify the full payload. A read then selects at most
**65,536 bytes** from the verified in-memory result. This is not range streaming:
each continuation repeats whole-payload verification, even for a one-byte range.
Corruption after the requested prefix therefore prevents all disclosure.

The existing serial MCP lifecycle applies: an in-flight operation is bounded by
the operator command request policy and the artifact owner’s 300-second storage
deadline, and a later cancellation notification does not preempt it. Responses
are assembled within the existing tool/result bounds;
there is no partial content response before verification succeeds. EOF, output
failure, or the message limit closes the node explicitly.

Malformed IDs, unknown fields, and invalid range syntax are invalid-argument
errors. Missing selected artifacts produce `artifact_not_found`; exceeding the
whole-payload profile produces `artifact_payload_limit`; cancellation/deadline
expiry produces `artifact_request_expired`. Unsafe, unavailable, corrupt, or
unauthenticated storage returns a failure such as `artifact_storage_unavailable`,
not a successful empty artifact. Storage paths are not exposed in tool errors.
Artifacts present only in another tenant, repository, incarnation, or trust
namespace are not selected by this grant.

## Implementation and test ownership

Launch parsing and grant checks live in `fgit-cli/src/mcp/mod.rs`. Discovery and
startup are in `mcp/backend.rs`; the adapter and its tests are in
`mcp/backend/artifacts.rs` and its subordinate test modules. The shared node read
owner is `fgit-node/src/workflow_artifacts.rs`.

The focused tests exercise exact argument/schema parity, independent grants,
real reopened SHA-1/SHA-256 nodes, binary continuation and EOF behavior, unchanged
repository heads, wrong-incarnation/private-root startup refusal, namespace
isolation, and trailing corruption before any prefix can escape. They are native
component/integration tests, not an end-to-end workflow execution claim.

See [MCP_READ_ONLY_SERVER.md](MCP_READ_ONLY_SERVER.md) for the protocol lifecycle,
[TRUSTED_WORKFLOW_ARTIFACTS.md](TRUSTED_WORKFLOW_ARTIFACTS.md) for workflow custody,
and [LOCAL_ARTIFACT_STORAGE.md](LOCAL_ARTIFACT_STORAGE.md) for immutable storage.
