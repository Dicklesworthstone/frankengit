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
