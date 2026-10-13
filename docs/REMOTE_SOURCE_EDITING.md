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
same explicit lifecycle as the executable. Use these bounded owners rather than
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
