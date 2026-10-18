# Sparse native source proofs

`captureSourcePaths` and `validatePathCapture` in
`scripts/operator/source_archive.mjs` use the existing archive transport and
native Git verifier to acquire only selected file bodies and their parent-tree
closure. The consumer is source-context verification: an excerpt alone does not
prove that its claimed blob occurs at its claimed path in the selected commit.

```js
import { captureSourcePaths, validatePathCapture }
  from './scripts/operator/source_archive.mjs';
const paths = ['7372632f6d61696e2e7273']; // exact bytes for src/main.rs
const { capture, metrics } = await captureSourcePaths(selection, readToken, paths,
  { signal, limits: { maxTotalBlobBytes: 8388608 } });
const proof = validatePathCapture(capture, selection, paths);
```

`selection` has the same independently supplied endpoint, tenant, repository,
incarnation, Git format, full ref, expected native commit and optional exact
snapshot as the complete archive API. Retain the expected commit independently;
accepting a commit chosen by an untrusted peer cannot authenticate intended
source. The validator requires the expected selection and paths separately from
the proof. This establishes commit-to-tree-to-path-to-blob membership and bytes,
not current-ref authority, author identity, freshness, retention or agent powers.

Paths are nonempty, unique, exact lowercase-hex native byte paths. They are not
globs or prefix grants. Up to 32 paths and 32 KiB of combined path bytes are
admitted, within the existing depth/size profile. A path cannot also be an
ancestor of another selected file. Regular, executable, and symlink *payloads*
are supported; symlinks are never followed. Directory or gitlink targets and
missing paths refuse before any file body is fetched. Context consumers should
additionally require regular/executable kinds rather than interpreting symlinks.

The log reader authenticates the explicitly pinned native commit bytes. Every
needed directory is fully paged and reconstructed in native Git tree order, then
checked against its committed identity. All sibling entries in those parent
trees are necessary proof material. Unrelated subtrees are not traversed and
unselected blobs are not requested. Thus path membership can be established
without hydrating a complete repository; this is not logarithmic proof size when
a required directory is very wide. Existing ancestry-page and resource limits
still apply.

Only after every requested file is found does acquisition read its complete blob
through bounded native ranges. Repeated blobs are downloaded once within the
call but every path occurrence counts toward logical output limits and receives
an independent buffer. All required bytes, ranges, modes, source coordinates,
page cursors and native identities must agree. A missing page or corrupt body
cannot produce a partial successful proof. The same finite deadline, request and
wire limits span all reads. There are no redirects, automatic retries, broader
fallback selections, server changes, native code execution or added dependencies.

The in-memory `frankengit-source-path-capture-v1` schema is deliberately distinct
from `frankengit-source-capture-v1`. It adds a normalized `paths_hex` selection.
Complete archive validation rejects sparse captures; sparse validation rejects
complete captures, omitted selected files, unrelated extra bodies, missing
parents and valid-but-wrong blob substitutions. Validation checks every native
commitment again rather than trusting acquisition status. The returned
`complete_repository: false` distinguishes verified requested paths from a
complete repository inventory. Its `entries` inventory contains only entries in
visited parent trees, not an exhaustive traversal.

Existing `captureSource`, complete archive validation, prior-capture reuse and
archive serialization keep their contracts. Sparse calls currently accept only
`limits`, `signal`, and `ca`; they do not silently reuse another snapshot.

## Verification

```bash
node --test tests/operator/source_archive.test.mjs \
  tests/operator/source_path_capture.test.mjs
```

The added tests use complete normal production imports and actual HTTP sockets
against explicit native-schema peers, not a Rust server. They test both Git
formats, selected-only I/O, complete parent paging, raw paths, empty files,
symlink payloads, mode/identity grafts, corrupt/missing/extra proof material,
independent roots, cumulative bounds despite deduplication, cancellation and
HTTP refusals. Installed Git independently hashes captured commit/tree/blob
bytes in both formats. No live Rust authorization, whole-workspace readiness,
authenticated-ref proof, measured speedup or FG-032 closure is claimed.

## Portable proof for a saved context capture

`scripts/fg_context_proof.mjs` connects the sparse verifier to an existing
`capture.json` from the source-context exporter or a saved native
`context-initial` JSON response. This is an additional, explicitly authorized
source read. The new proof file contains **full selected file bodies and all
sibling names in required parent trees**, not only the original excerpts. Keep
it private; sharing it may disclose substantially more source than the context.
Unrelated subtrees and unselected blob bodies are not downloaded.

Retain the original capture hash independently (the existing export receipt's
`capture_sha256`, not its `manifest_sha256`). Supply a separate private selection
JSON in the archive selection format, including an independently selected
`expected_commit`. Do not take an untrusted response's suggested commit as that
independent root. Example:

```bash
node scripts/fg_context_proof.mjs capture \
  --selection /private/context/independent-selection.json \
  --context /private/context/bundle/capture.json \
  --context-sha256 "$CAPTURE_SHA256" \
  --token-file /private/context/read-token \
  --output /private/context/source-proof.json

node scripts/fg_context_proof.mjs inspect \
  --selection /private/context/independent-selection.json \
  --context /private/context/bundle/capture.json \
  --context-sha256 "$CAPTURE_SHA256" \
  --proof /private/context/source-proof.json \
  --proof-sha256 "$PROOF_SHA256"
```

Both operations require normalized absolute paths, owner-private directories
and private regular single-link files. Capture accepts optional `--limits` in
the existing archive limits format and `--ca-file` for certificate-verified
HTTPS. Defaults bound complete selected source to 8 MiB, with 8 MiB per file;
explicit limits may increase these only within the existing 64 MiB aggregate
and 16 MiB per-file ceilings. The original context is separately capped at
12 MiB, 32 unique returned paths, and 1 MiB of excerpt bytes. Empty returned
context has no source bodies to prove and is refused before connecting.

The observed source snapshot in the hash-pinned context narrows the supplied
selection, never overrides its independent commit or endpoint. Every selected
file must be regular/executable with the exact committed blob identity and
length. Every original excerpt range is compared byte-for-byte against that
complete verified blob, including CRLF, raw bytes and empty files. All requested
files must pass; the verifier cannot swap a failed selection for another file.
The original capture, query, ranking and completeness records remain unchanged.

The library exposes `captureContextProof(contextBytes, contextHash, selection,
token, options)` and `inspectContextProof(proofBytes, proofHash, contextBytes,
contextHash, selection, check)`. Acquisition returns canonical proof bytes, a
receipt and actual source-read metrics. Inspection has no networking or token
argument. It checks both independently retained input hashes, decodes a closed
portable schema, repeats native commit/tree/path/blob verification and original
excerpt comparisons, then requires identical canonical proof encoding. The
proof includes all required native object bytes; it does not need a source
store, full repository, previous proof, Git executable or server for inspection.
The pinned original context and independent selection are still required.

Proof JSON uses `frankengit-context-source-proof-v1`, with hex full blob bodies
rather than implicit Buffer JSON. Its fixed 160 MiB encoded ceiling accounts for
hex expansion and bounded parent paths. This is a buffered verifier, not a
streaming or reduced-memory claim. Synchronous bounded checks probe cancellation
before/after; they do not interrupt a JavaScript hash or JSON operation midway.

Receipts distinguish `selected_path_membership_verified` and
`excerpt_bytes_verified` from the deliberately false `search_evidence_verified`,
`complete_repository`, `authority_verified`, `freshness_verified`, and
`agent_context_packet` flags. Byte proof does not validate ranking, coverage,
query matching, anchors, declaration semantics, policy or an authenticated ref
head. Native context/agent validation remains separate. Summary fields supplied
inside a saved capture are never promoted into this receipt. Local CLI receipts
omit the potentially large per-file detail; library receipts retain bounded
path/blob/range hashes without duplicating source bytes.

Output publication is create-only with file/directory sync and complete
readback verification through the shared custody module. Existing destinations
and competing writers cannot be overwritten. Cancellation before publication
creates no final proof; once publication starts, its write/sync/readback is
drained. A failed final sync or lost stdout does not prove absence. Exit 4
retains a verified receipt or an explicitly unconfirmed path/hash for inspection.
Inspection reads no credential or network configuration. Neither operation
executes repository text, extracts source, changes the remote repository or
retries a different source. This is a trusted owner-private POSIX filesystem
profile, not hostile-parent confinement or a hardware power-loss proof.

```bash
bash scripts/verify_source_context_proofs.sh
```

New tests exercise normal CLI processes, real files/sockets, SHA-1/SHA-256,
partial and raw excerpts, independently rooted membership, canonical offline
replay, rewritten local hashes with false source bytes, wrong kinds, caller
mutation, full-file budgets, concurrent exports, SIGTERM/SIGKILL and broken
stdout. The context fixture is explicitly a native wire projection for byte
proof, not a simulated search engine. The complete source-context ranking and
retrieval test suites, live Rust interoperability and full-workspace gates are
separate and are not claimed by these tests.
