# Portable Git bundle transfers

This is the browser bridge to the native `source/bundle/export`, `import` and
`fetch` endpoints. It moves Git objects and direct refs, not forge events,
issues, review authority, default HEAD, credentials or repository capsules.
The existing native pack/quarantine/closure and sealed admission engines remain
the only publication path. Related product composition: `frankengit-asa3`.

## Export, import and mapped fetch

Select the target repository identity and authority snapshot using the existing
read-only reference endpoint. Export pins that snapshot and checks the native
full-v1 response headers, repository incarnation, object format, artifact SHA-256,
bundle envelope and native pack trailer before offering a file for download.
The downloaded bytes are unchanged. Export failure or cancellation cannot leave
a partial or old artifact available as a new successful export.

Load a full Git bundle, inspect its advertised refs and explicit HEAD OID, then
prepare one of two different native mutations. Import creates all advertised
direct refs with absent-destination expectations; the advertised HEAD is not
installed. Fetch requires explicit source/destination mappings, each with either
an absent expectation or an exact old native OID. It can import a subset into
an existing repository. No wildcard, implicit force, automatic destination,
old-tip refresh, default-branch rewrite or hidden-ref permission is introduced.

The client validates the bundle header and pack trailer checksum; it never
inflates objects or claims that header/ref/closure semantics have been admitted.
The preview marks `objects_verified: false`. A matching checksum is transport
integrity, not authorization or native object verification. Native admission
still checks object identities, closure, policy, destination leases and the
one atomic authority transition. In particular an uploaded bundle remains
untrusted even when its outer checksums are correct.

The supported browser transport profile is self-contained v2/v3 Git bundles,
SHA-1/SHA-256, optional branch-valued HEAD, direct byte-valued `refs/*`, and pack
version 2. Prerequisites, filters, unknown capabilities, detached/unadvertised
HEAD and malformed envelopes refuse. This intentionally matches the existing
full-bundle HTTP intake, not the separate incremental native bundle engine.

## Exact request responsibility

Prepare freezes the exact bundle, digest, mapping set, repository incarnation,
form, MIME boundary and random original key without dispatching a write. Sending
is a separate action. The native receipt must match operation, target scope,
command count, atomic/terminal decision and explicit non-claims about forge/HEAD
changes and transport revalidation. Generic 409s, incomplete receipts and lost
responses never establish non-commit. There is no target-ref pre-read on retry.

Recovery uses the existing bodyless original-key endpoint and decoder. Missing
keys/seals and undecided results remain unresolved; observed transaction and
principal identities cannot silently regress. A saved receipt contains bundle
bytes and mappings but not the token. It is bound to the original credential
fingerprint, origin/route, scope, operation and exact multipart bytes. This is a
request commitment, not a signature. Restore checks the full commitment and
never sends automatically. Sent or exported requests cannot be discarded as
unsent. Preserve the receipt before page closure; page memory is not durable.
The original valid credential is required and must not be reassigned.

## Bounds and verification

The browser allows at most 16 MiB of bundle bytes, 256 KiB of header records,
1024 advertisements (including HEAD), 4096 bytes per ref, 64 mapped/imported
refs per publication, 256 KiB of encoded form and 24 MiB of receipt. Fetch may
select a bounded subset from a larger advertised set. Raw names stay hex data;
header text is never interpreted as a host path, URL or executable command.
No production Git subprocess, dependency, authority store or runtime is added.

Run:

```sh
node --test tests/browser/transfers.test.mjs
node tests/browser/transfers-git-oracle.mjs
```

The first lane executes real browser modules with HTTP/authority doubles. Its
tiny synthetic pack deliberately does not prove object closure. The separate
non-production oracle requires Git 2.47.3 (optionally `FGIT_TEST_GIT`) and checks
actual Git-produced SHA-1/SHA-256 bundles, unchanged exports, mirror clone/fsck,
binary blobs, annotated tags, reordered advertisements and corruption refusal.
Neither lane proves live Rust-node admission, deployment authorization, actual
browser rendering, full-workspace or release conformance.
