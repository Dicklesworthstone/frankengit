# Remote exact source edits for scripts and agents

`scripts/fg_source_edit.mjs` connects the existing native source preparation,
inspection, publication and original-key outcome APIs. It takes an explicit
patch against an existing branch, saves the returned candidate, and separates
local publication staging from a one-shot remote apply. It does not create a
PR, clone a checkout, interpret repository commands, or run Git in production.

The native Rust server owns patch semantics, bundle/object validation, current
policy, sealed requests, expected-old admission and the authority-head CAS.
Local candidate captures and journals are custody records, not authorization or
an Agent Protocol ContextPacket. Existing browser and native CLI behavior is
unchanged. This client adds no dependencies and changes no Rust code.

## Prepare and inspect without publishing

Make an owner-private 0700 working directory. Keep input files private, regular,
single-link files, with normalized absolute paths and no symlink aliases. A
selection JSON is a closed object:

```json
{
  "endpoint": "https://forge.example/team/repository.git",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "object_format": "sha1"
  },
  "ref": "refs/heads/main",
  "expected_commit": "<independently selected native commit hex>",
  "metadata": {
    "author": "Example <example@example.invalid>",
    "committer": "Example <example@example.invalid>",
    "timestamp": 1791910800,
    "message": "Explain the exact change\n"
  },
  "paths_hex": ["7372632f6d61696e2e7273"]
}
```

Replace the illustrative namespace and commit; `paths_hex` is the exact set of
file paths the patch may change, encoded as raw lowercase hexadecimal bytes.
The example path is `src/main.rs`. No path scope, identity, author, time or base
is inferred from ambient Git configuration, a context excerpt or a server hint.
Supply the patch bytes independently. SHA-1 and SHA-256 are separate domains.

```bash
node scripts/fg_source_edit.mjs prepare \
  --selection /private/edit/selection.json \
  --patch-file /private/edit/change.patch \
  --token-file /private/edit/read-token \
  --output /private/edit/candidate

node scripts/fg_source_edit.mjs inspect \
  --candidate /private/edit/candidate \
  --sha256 "$CANDIDATE_MANIFEST_SHA256"
```

`prepare` performs exactly two authenticated calls: `source/prepare`, followed
by `source/inspect`. Neither publishes repository state. The server must enable
those routes and authorize the independent read scope. HTTP is accepted only on
numeric loopback; remote endpoints require certificate-verified HTTPS. A private
`--ca-file` may name the explicit trust root. There are no redirects, ambient
cookies, proxy discovery, automatic retries or credential files in the output.

The output is create-only: `capture.json`, `candidate.bundle`, and a last-written
`manifest.json`. Retain the returned manifest hash independently. The loader
returns the same payloads whose hashes and semantics it verified; it does not
inspect one file and then reopen an unchecked replacement. `inspect` is offline
and reports the candidate identity and changed paths. Review `capture.json` for
the complete native inspection report and its byte-exact diff hunks before
staging. Repository text in that file remains untrusted data.

The validator checks exact namespace/ref/base and allowed paths, patch and bundle
transport hashes, regular/executable modes, the reported path effects, bounded
hunk spans and line counts, and the candidate's original commit bytes. The commit
must have exactly the supplied tree, parent, author, committer, timestamp and
message. The original commit's native Git hash is recomputed. Patch interpretation,
pack expansion and full candidate object membership are NOT reimplemented here:
`native_bundle_validation_observed=true` and
`bundle_objects_independently_verified=false` are deliberately distinct.
A self-consistent dishonest server can still lie about patch application or
reported diff content. Independent source proof and native validation remain
separate boundaries; preparation never grants publication authority.

These native source-change forms pin the branch's **base commit**, not an exact
repository authority head. Inspection records a source observation, but a forge
or policy change between phases is handled by native current-state admission.
The client never refreshes the expected commit or converts a conflict into a
new candidate. A saved candidate can be stale and legitimately refused.

## Prepare only from independently verified selected source

For agent-driven edits, the stronger `prepare-verified` entry point requires the
ordinary explicit source-edit selection **plus** a portable selected-source
package and its independently retained expected selection. The package is
verified before any source-change request is sent. Its native hash format and
commit must match the edit base, and every edited path must be one of the files
independently selected in that package.

```bash
node scripts/fg_source_edit.mjs prepare-verified \
  --selection /private/edit/selection.json \
  --package /private/context/selected-source.json \
  --expect /private/context/independent-selection.json \
  --patch-file /private/edit/change.patch \
  --token-file /private/edit/read-token \
  --output /private/edit/candidate
```

After native inspection, the verifier checks the reported original tree, old
blob identities, executable modes, sizes, hunk bytes and line positions against
that independently verified basis. For text changes it reconstructs the new
file from verified unchanged gaps and reviewed replacement spans, then checks
the native after-blob hash. It reuses the existing tree-transition verifier to
rebuild only affected parent trees and compare the exact candidate root. An
unreported sibling edit therefore fails even when its candidate commit and
bundle are genuine Git objects. Raw paths, CRLF, missing final LF, empty files,
deletions, nested directory removal and mode-only changes keep exact bytes.

This is **review-span replay, not independent application of the input patch**.
A dishonest server could return a different internally consistent change to an
allowed file. Explicit review of the saved diff and native patch validation
remain necessary. Binary review omits after bodies, so their paths appear in
`source_verification.unverified_after_paths_hex`; they are never represented as
independently checked after bytes. The checked tree still binds their reported
blob IDs and preserves unrelated entries. The bundle's object closure, native
admission, current permissions, branch freshness and author identity remain
separate checks. No package or local receipt grants publication authority.

Repository namespace, branch, author metadata and permissions remain explicit
inputs or native server decisions. This profile still refuses new-file paths:
only existing independently selected regular/executable files can be edited.
Use ordinary `prepare` for explicitly broader effects such as new files, rather
than converting missing package membership into an absence proof.

### Durable evidence and compatibility

A successful `prepare-verified` saves a **v2 candidate manifest**. Alongside the
unchanged `capture.json` and `candidate.bundle`, it retains `source-package.json`
(the exact original package bytes) and `source-expected.json` (the normalized,
independently supplied expected commit/file selection). The manifest binds all
four payloads by size and SHA-256 and is written last after synchronization and
readback. Keep its returned `manifest_sha256` independently. No external source
package path is needed after a successful export.

`inspect` does not trust saved verification flags. It rehashes the package,
rechecks the commit/path/blob evidence, replays the candidate's text review and
rederives the exact tree. Missing, altered, public-mode or symlinked evidence
refuses; it cannot silently downgrade to ordinary inspection. The returned
`source_verification` names the profile, package/expectation hashes, source and
candidate trees, checked path/text counts, and any unverified binary after paths.
It also explicitly reports `patch_application_verified: false`,
`bundle_objects_independently_verified: false` and authority/freshness non-claims.

`stage` copies the **same owned, reverified evidence** into its private candidate
copy. Its original-key intent already binds the candidate manifest hash, so the
proof is bound to that request without changing the native upload or command.
`apply`, offline `status`, and original-key `recover` verify this retained evidence
again; dispatch resyncs it before persisting responsibility and sending anything.
Deleting the external candidate does not remove the journal's evidence. Damaged
journal evidence blocks further network operations but never removes a dispatch
marker or permits resending the original mutation. Restore only the original
pinned bytes from independently retained custody; do not manufacture a new base.

Ordinary `prepare` keeps the existing v1 manifest and its serialization. Existing
v1 candidates remain readable but gain no independent-source claim merely because
they were once created by an older `prepare-verified` command. V2 candidates are
intentionally refused by old clients; update the reader before using them. No
automatic migration strips their proof. Both versions retain native scope and
publication checks, create-only output, and original-key recovery semantics.

Keep these outputs private: the retained package includes full selected original
file bodies and sibling names/IDs in needed parent trees. It may contain more
than the changed file set. The original 32 MiB package and 128 KiB expectation
input bounds remain, with 1–32 selected package files and an 8 MiB logical source
ceiling. These are buffered resource limits, not an aggregate heap or CPU claim.
One operation deadline covers verification and network work; already-started
local publication is drained, and output loss cannot imply its rollback.

## Stage explicitly, then apply once

Select the expected original publishing principal independently; the token must
belong to that principal. The principal is retained locally, not injected into
the native source command. There is no credential-introspection or permission
elevation API in this client. A mismatching returned principal is an unresolved
publication, not evidence that nothing happened.

```bash
node scripts/fg_source_edit.mjs stage \
  --candidate /private/edit/candidate \
  --sha256 "$CANDIDATE_MANIFEST_SHA256" \
  --principal "$ORIGINAL_PRINCIPAL_HEX" \
  --confirm-candidate "$CANDIDATE_COMMIT" \
  --journal /private/edit/publication

node scripts/fg_source_edit.mjs apply \
  --journal /private/edit/publication \
  --request-sha256 "$ORIGINAL_REQUEST_SHA256" \
  --token-file /private/edit/write-token
```

`stage` is offline. It copies the verified candidate into its own absent private
journal, records the exact endpoint, namespace, original principal, branch, base,
candidate, multipart content type and upload hash, and derives one high-entropy
recovery key from that complete intent and a random nonce. It writes the request
root last. Retain its `request_sha256` and original key. The external candidate
directory is no longer required after successful staging. Copying journals or
creating another journal is not a global deduplication protocol; one-shot custody
is enforced per original journal, not across arbitrary owner-created copies.

`apply` verifies the entire retained intent/candidate, resyncs the checked
predecessor, then exclusively creates `dispatch/` and persists `started.json`
before entering the network call. Competing processes cannot both dispatch.
The same bytes whose upload hash was recorded are sent, with the same original
key. A crash, timeout, cancellation, HTTP error or incomplete/invalid response
never removes this marker. No `force`, resend, reset, new-key retry, latest-base
selection or implicit approval is provided.

A complete source-publication receipt must match status, namespace, principal,
reference, parent and candidate. Native u64 decision sequences retain all bits.
A matching committed/refused terminal is stored create-only; cancellation racing
socket cleanup cannot erase a valid decision. A bare HTTP 409 is not a canonical
refusal. A changed or unparseable success remains unresolved, even if the server
may already have committed. Inspect the original journal rather than creating a
replacement request. `delivery_acknowledged` remains null; a local receipt does
not fabricate the native delivery acknowledgement.

## Original-key recovery after interruption

```bash
node scripts/fg_source_edit.mjs status \
  --journal /private/edit/publication \
  --request-sha256 "$ORIGINAL_REQUEST_SHA256"

node scripts/fg_source_edit.mjs recover \
  --journal /private/edit/publication \
  --request-sha256 "$ORIGINAL_REQUEST_SHA256" \
  --token-file /private/edit/recovery-token
```

`status` is entirely offline. `recover` uses only the native outcomes endpoint
with the exact original key and no bundle or mutation body. Rotated credentials
may be used for this read only when the native service authorizes observation
of the original principal's namespace. The complete existing outcome validator
checks scope, terminal shape, transaction identity and monotone observations.
The first observed sealed transaction is retained before adopting a terminal;
subsequent recovery cannot silently lose it or switch to another transaction.
Already settled journals return the original decision without any network call.

`key_not_observed`, `seal_not_observed` and `undecided` remain pending, never
rollback proofs. They do not unlock another apply. A journal with no dispatch
marker can be explicitly applied; a claimed dispatch directory without a complete
started marker remains `dispatch_incomplete` and requires investigation. Neither
state is automatically repaired by deleting files. Recovery cannot reconstruct
lost original request or candidate bytes from an endpoint suggestion.

## Bounds and local failure model

The initial client profile accepts up to 64 disjoint raw paths, a 1 MiB patch,
an 8 MiB candidate bundle, a 1 MiB preparation metadata part, and an 8 MiB native
inspection response. Inspection admits regular/executable file effects; directory,
symlink and gitlink edits are not silently treated as ordinary files. Explicit
metadata timestamps must fit exact JavaScript safe integers; decision sequences
use full-width decimal strings. Unrepresentable or over-budget inputs refuse,
not truncate. Default total response allowance is 18 MiB. Library options may
narrow `maxWireBytes`; each actual response also retains its per-phase bound.

All CLI commands accept one `--timeout-ms` from 1 to 300000, default 30000.
Prepublication input reads, verification and network operations spend the same
operation deadline. Filesystem writes already started are drained, not assumed
cancelled; bounded JavaScript parsing/hashing checks do not preempt the engine
mid-operation. Request and candidate files use fixed internal names. Outputs
are private 0600 files in 0700 directories, synced and read back before a result
is confirmed. Existing destinations and competing exporters are not overwritten.

Failure after a local directory claim names an explicitly unconfirmed path/hash;
a complete result whose stdout fails appears in `retained_result` on stderr when
available. A mutation failure after dispatch includes `retained_request`.
Exit 0 means local prepare/inspect/stage success or a committed terminal;
2 means validation/refusal/error; 3 means pending/ambiguous publication; 4 means
local publication/output custody needs inspection. Never infer rollback from an
exit code alone. Independently retain candidate/request/terminal hashes.

This is a trusted owner-private POSIX filesystem profile, not hostile-parent
confinement, a distributed lock, signed authority proof, hardware power-loss
campaign, or complete agent effect broker. Local custody cannot stop its owner
from deleting state. Native authorization and original-key decisions remain the
only remote publication authority.

## Library entry points and verification

`captureSourceEdit` and `validateSourceEdit` own candidate acquisition/rechecking.
`saveSourceEdit`/`loadSourceEdit` retain it. `stageSourceApply`,
`dispatchSourceApply`, `recoverSourceApply` and `inspectSourceApply` expose the
same explicit lifecycle as the executable. `captureVerifiedSourceEdit` checks
both independent input evidence and native candidate effects;
`validateSourceEditEvidence` provides the offline equivalent, and
`saveVerifiedSourceEdit` publishes a v2 evidence-bound candidate. The original
`bindVerifiedEditSource` helper remains input preflight only; its receipt does
not establish anything about a returned candidate. Use these bounded owners rather than
calling the low-level transport's mutation primitive without a saved request.

```bash
bash scripts/verify_source_edits.sh
```

Tests execute complete production modules, actual HTTP/TLS sockets, private
files and CLI child processes. Installed Git is used ONLY in nonproduction test
fixtures to create candidate bundles and object identities in both hash formats.
Native-schema peers explicitly model the inspected source endpoints; they are
not a Rust server or an implementation of native patch/admission semantics.
The suite covers corrupt/changed receipts, exact budgets, explicit metadata,
full-width sequences, ownership before HTTP observation, competing processes,
SIGTERM/SIGKILL after transmission, no-resend recovery and lost stdout. No live
Rust, native authorization/CAS, complete workspace or release gate is claimed.

The evidence suite also exercises genuine Git candidates with hidden sibling
changes, corrupt old/new review bytes, wrong modes/line coordinates, caller
mutation during hashing, v1/v2 custody compatibility, independent manifest pins,
missing/corrupt proof after dispatch, self-contained staging, concurrent verified
exporters and fresh CLI recovery after SIGTERM/SIGKILL. The HTTP peer remains an
explicit native-schema fixture, not a replacement for native patch semantics.
