# Independently verify source candidate pack objects

`verifySourceCandidatePack` in `scripts/operator/source_candidate_pack.mjs`
checks the actual incremental bundle from native source preparation against the
independently reviewed change. It supplements, rather than replaces, the existing
source, exact-effect, whole-tree, candidate-commit and metadata checks.

Previously those checks authenticated the expected new tree commitment and the
commit body supplied in the inspection report, but did not decode the candidate
pack itself. A corrupt or incomplete pack could pass when an internally coherent
report supplied its updated transport hash. The native admission engine would
still have to refuse that pack; an operator now has an independent offline check
before that publication boundary.

The supported original envelope is exactly `patch.rs::pack`: a v2 SHA-1 bundle or
v3 SHA-256 bundle, one `patch base` prerequisite naming the retained base commit,
one selected native branch naming the candidate, and a compressed no-delta pack.
Other envelope and transport profiles refuse rather than being normalized into
this one. The original bundle bytes are returned unchanged.

## Reuse and verification boundary

The source-authoring kernel independently derives the whole resulting tree and
its rebuilt parent-tree identities. Combined with every non-deleted after-image
blob and the verified candidate commit, these determine the native exporter's
exact deduplicated object inventory. Rebuilt empty non-root directories emit no
object; an empty resulting root does. Mode-only changes still emit their blob.

The existing `verifyGitBundleObjects` decoder in `transfers-protocol.mjs` owns all
pack framing, checksums, zlib/DEFLATE, object hashing and finite work accounting.
This adapter introduces no pack parser or inflater. Since that decoder's public
full-bundle envelope refuses prerequisites, object checking uses a PRIVATE
in-memory assertion envelope over the BYTE-IDENTICAL original pack. Each expected
object ID becomes a decoder assertion; all must exist and the count must match
exactly. This excludes missing, substituted and extra objects. The view is never
exported, submitted to a server or presented as a self-contained source bundle.
The existing full-bundle entrypoints still reject the original incremental input.

The result identifies the ORIGINAL artifact hash, selected base/candidate/tree,
reviewed draft hash and expected object-inventory hash. It explicitly distinguishes
verified packed objects from unverified external base closure. It does not prove
that unchanged base subtrees are currently available, traverse the prerequisite's
history, follow gitlinks, authenticate an author, establish freshness, grant
permission, or attest a committed transaction. Native admission and authority
remain separate. Git's native hash assumptions still apply.

## Library consumer

```js
import { verifySourceCandidatePack } from './scripts/operator/source_candidate_pack.mjs';

const checked = await verifySourceCandidatePack(
  sourcePackageBytes, independentExpectation, explicitChanges,
  savedCandidate.capture, savedCandidate.bundle,
  { confirmDraftSha256: reviewedDraftHash, timeoutMs: 30000 },
);
// checked.bundle is the unchanged original incremental bundle.
// checked.verification has original artifact and exact object-inventory evidence.
// checked.verification.base_closure_verified remains false.
```

This function has no filesystem, network, token, native subprocess or publication
option. The complete existing validators own caller inputs before asynchronous
work. One monotonic operation deadline covers source verification and pack work;
cancellation never returns a successful subset. Decoder `limits` may only narrow
the existing ceilings. In particular the assertion view is limited to 1024 unique
objects, 256 KiB of header bytes and 16 MiB overall; source candidate input remains
at most 8 MiB. Both views are retained during verification, so this is not a
streaming-memory claim. The shared decoder separately bounds expanded bytes,
object sizes, work and its own at-most-30-second decode lifetime. The outer
`timeoutMs` is 1..300000 (default 30000).

Run `bash scripts/verify_source_candidate_packs.sh`. Tests apply actual patches
with installed Git and construct the native-shaped object inventory from Git's
independent tree walk. They exercise exact resource edges, binary/compact edits,
mode-only changes, identical subtrees, empty roots, lost caller ownership,
corrupt compression/checksums, omitted and extra objects, and original-envelope
substitution in both hash domains. Native-shaped HTTP peers are fixtures, not an
executed Rust `fg` server. No Rust, real-browser, native admission/CAS,
full-workspace, semantic-compatibility or complete backup claim follows.
