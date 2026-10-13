# Verified source snapshot acquisition

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
private CA bundle augments this explicit TLS connection configuration; certificate
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
node --test tests/operator/source_archive.test.mjs
```

The source peers are real loopback HTTP sockets implementing the inspected native
schema, not Rust `fg`. Separate tests run installed Git as a non-production
hashing oracle for both object formats. A passing contract suite is not a live-node
permission/admission test, a real-browser test, or the full workspace gate.
