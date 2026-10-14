# Exact source authoring from verified packages

`scripts/fg_source_changes.mjs` connects a selected-source package to the existing
native source preparation and candidate publication workflow. It removes the need
for an operator or agent to construct a unified patch by hand.

The local authoring kernel imports the existing complete source-package verifier
and exact-patch encoder. Native Rust still owns patch application, candidate
object/graph validation, authorization, admission, and publication. The client also derives the exact expected root tree from verified parent trees
and locally constructed effects. No new Git engine, source executor, authority
store, or publication route is introduced.

## Before starting

Use Node 22.16.0 or later and POSIX owner-private files. Every input is an absolute,
normalized path to an owner-private regular file with one link, inside a real
owner-owned `0700` directory. Symlink aliases, public inputs, FIFOs, shared parent
directories, and existing output destinations are refused. Outputs are `0600`
files in a newly created `0700` directory. This trusted-local profile is not
confinement against hostile same-user processes or hostile parent replacement.

Retain the selected-source package and its **independently chosen** expectation:
`{format, commit, files: [{pathHex, blob}]}`. The expectation does not come from
an imported package or from the server's assertion of its current commit.
Acquisition is documented in [SELECTED_SOURCE_PACKAGE_OPERATOR.md](SELECTED_SOURCE_PACKAGE_OPERATOR.md).

Package verification checks the exact selected commit, required parent trees,
path membership, file modes, and full original blob bytes. It does not prove
repository authority, freshness, author identity, signatures, or search coverage.
Repository text remains untrusted data after its hash has been verified.

## Describe the changes

A private changes JSON file has this closed schema:

```json
{
  "schema": "frankengit-source-changes-v1",
  "changes": [
    {
      "path_hex": "7372632f6d61696e2e7273",
      "operation": "replace-once",
      "before_utf8": "old()",
      "after_utf8": "new()"
    }
  ]
}
```

`path_hex` is the exact original repository byte path, not a glob or local
filesystem path. The example selects `src/main.rs`. Existing-file operations must
name a file present in the independently verified package. A `create` instead
requires proof of absence under that same independent commit, as described below.

Supported operations:

- `create`: supply exactly one of `content_utf8` or `content_hex` and an explicit
  `executable: true` or `false`. The target must be proved absent, not just absent
  from the package's selected file list. An empty value creates an empty file.
- `replace`: supply exactly one of `content_utf8` or `content_hex` for the entire
  after-image. An empty value is an empty file, not deletion.
- `replace-once`: supply one `before_utf8` or `before_hex`, and one `after_utf8`
  or `after_hex`. The nonempty before-image must appear exactly once in the
  original bytes. Overlapping matches count as ambiguity. No regex, case folding,
  fuzzy matching, or inferred occurrence is used.
- `splice`: supply a nonempty `splices` array. Each element has `byte_offset`,
  one `before_utf8` or `before_hex`, and one `after_utf8` or `after_hex`. Offsets
  address the **original** file, not the output of an earlier splice. Elements
  are strictly increasing and non-overlapping. Empty before-images insert bytes;
  empty after-images remove bytes. Original before-bytes must match exactly.
- `delete`: supply only `path_hex` and `operation`.
- `mode`: supply `path_hex`, `operation`, and `executable: true` or `false`.

`replace`, `replace-once`, and `splice` may also carry `executable`. Without it,
the original executable bit is preserved. Hex is lowercase and even-length;
UTF-8 rejects unpaired surrogates. CRLF, byte offsets, BOMs, raw non-UTF-8 path
names and NUL-free non-UTF-8 content are preserved. In the default profile, NUL-bearing binary files are
refused by this profile rather than silently converted or delegated elsewhere.

Duplicate paths, file/ancestor conflicts, unsafe paths and inapplicable fields
are refused. A mix of effective edits and no-ops records each no-op explicitly;
an entirely unchanged request is refused. Creation is never inferred from a
`replace`, and renames are never inferred from a delete/create pair.

### Creating files without assuming sparse absence

For example, to add `src/new.rs`:

```json
{
  "schema": "frankengit-source-changes-v1",
  "changes": [
    {
      "path_hex": "7372632f6e65772e7273",
      "operation": "create",
      "content_utf8": "pub fn new_feature() {}\n",
      "executable": false
    }
  ]
}
```

The existing source package retains complete parent trees, including unselected
sibling entries. `verifyPathAbsence` reuses the membership verifier's bounded
Git decoder, native hashes and commit-to-tree traversal; it does not introduce
another parser or trust a saved success flag. It walks each explicit target
through those verified entries. A missing entry proves the whole remaining path
absent, allowing a new directory chain such as `new_module/sub/file.rs` when
`new_module` is absent from the proved root tree.

An existing file, executable, directory, symlink or gitlink at the target refuses.
An existing non-directory ancestor refuses. An existing directory whose full
contents are not in the proof also refuses: omission of a subtree or a blob is
not absence. Acquire a new independently pinned package containing an existing
anchor file in that directory before trying again; no implicit reads, widened
selection, refresh or overwrite is performed. Empty repositories and existing
empty directories without a selected anchor remain outside this package profile.

The draft's optional `creation_preconditions` records the exact target, first
absent prefix, parent path and parent tree ID for each creation. The reviewed
draft hash covers these witnesses, the independent commit and after-image. Old
and new paths share the same edit-count, path-byte, retained-byte, patch and time
budgets; file/ancestor collisions across creations, updates and deletions refuse.
This is absence at a named Git commit, not current repository authority, an access
grant or permission to publish. Native preparation and admission still own those
checks. A concurrent branch move does not make an old absence proof fresh.

Existing-file-only drafts keep their original bytes and review hashes. Creation
drafts report `created_path_count`; candidate inspection additionally reports
`creation_absence_independently_verified`. Standard saved-candidate and original
idempotency-key recovery formats are unchanged.

## Review an offline draft

```bash
node scripts/fg_source_changes.mjs draft \
  --package /private/session/source-package.json \
  --expect /private/session/expect.json \
  --changes /private/session/changes.json \
  --output /private/session/draft
```

This command makes no network request and requires no token. It creates
`patch.diff` followed by `manifest.json`. Inspect both and independently retain
the returned `manifest_sha256`. The manifest binds the original package hash,
normalized expected selection and edit hashes, verified source commit/root tree,
exact patch hash/size, old/new blob IDs and modes, explicit no-op paths, and any
commit-bound creation preconditions. The returned `expected_tree` is independently
recomputed from those inputs; the v1 manifest bytes and reviewed hash remain
unchanged by this additional verification.
Neither the manifest nor patch grants mutation authority.

A reviewed draft is not silently changed to accommodate a moved branch, a new
package, a different edit description, or a different native response.

## Prepare an exact native candidate

Prepare uses the existing `source_edit_candidate.mjs` selection schema:

```json
{
  "endpoint": "https://forge.example/project",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "object_format": "sha1"
  },
  "ref": "refs/heads/main",
  "expected_commit": "<independently selected native commit ID>",
  "metadata": {
    "author": "Operator <operator@example.invalid>",
    "committer": "Operator <operator@example.invalid>",
    "timestamp": 1700000001,
    "message": "Replace the selected call\n"
  },
  "paths_hex": ["7372632f6d61696e2e7273"]
}
```

Replace the example namespace and commit with the intended repository identities.
Select commit metadata explicitly. `paths_hex` must equal the manifest's effective
paths, excluding its `no_op_paths_hex`. The native object format and expected base
must equal the independently verified package. An endpoint, namespace, or branch
is an explicit operator selection, not an authority claim derived from a package.

```bash
node scripts/fg_source_changes.mjs prepare \
  --package /private/session/source-package.json \
  --expect /private/session/expect.json \
  --changes /private/session/changes.json \
  --selection /private/session/selection.json \
  --token-file /private/session/token \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256" \
  --output /private/session/candidate
```

The command re-verifies the package, regenerates the draft, and checks the exact
reviewed manifest hash and native selection before opening a request. Native
preparation and bundle inspection share one remaining-time and response budget.
HTTPS verifies certificates; `--ca-file` may name explicit private PEM trust
roots. Plain HTTP is restricted to canonical numeric loopback. There are no
redirects, retries, ambient credentials, or TLS-verification bypasses.

Both native reports must agree with all intended old/new blob IDs and modes;
the reported before-tree must equal the independently verified root. The client
also rebuilds the affected parent trees locally and requires the candidate
commit's root to match the resulting **whole-tree commitment**. A self-consistent
report cannot hide an extra file, an omitted deletion or a changed unrelated
subtree behind the requested file list; a different root is refused before the
candidate output directory is created.

The output is the **standard** source candidate directory: `capture.json`,
`candidate.bundle`, and `manifest.json`. The result includes the original draft
pin and an explicit intended-effect report binding. No credential is persisted.

### Independent whole-root commitment

`deriveEditedTree` uses the existing membership verifier, tree-entry codec, Git
ordering and native digest implementation. It verifies the original committed
basis, checks exact before-image identities/modes and creation absence, then
rebuilds only affected parents bottom-up. Untouched entries and subtree IDs are
preserved byte-for-byte by identity rather than reread or replaced. Identical
subtrees at different paths keep separate overlays. Touched directories that
become empty are removed; untouched explicit empty subtrees remain referenced,
and an empty root still has the native empty-tree identity. This follows the
native `fgit-treefs` exporter boundary; it is not another patch application engine.

The resulting `frankengit-source-tree-transition-v1` receipt includes the base
commit, before/after root IDs, ordered rewritten-directory commitments and bounded
work counters. It is derived evidence, never repository authority. The authoring
library returns it as `tree`; the CLI prints `expected_tree` for the offline draft
and requires that value again during preparation and saved-candidate inspection.
No cached success flag supplies the root and no additional source request runs.
Existing v1 draft manifests, patch bytes, candidate files and original recovery
keys remain unchanged. The exact original source proof and locally constructed
file effects determine the derived root without a new consent format.

A successful candidate binding reports `candidate_root_matches_exact_effects`,
`expected_tree`, `tree_transition_profile` and
`unrelated_subtree_commitments_preserved`. The existing native commit-body check
binds that root to the candidate ID, parent and explicit metadata. A coherent
candidate with an unreported change therefore fails the root comparison even
when its reported old/new blobs and modes are all correct.

**Limit:** a native hash commitment is not independent verification of every
object body in the candidate pack or its transitive closure. Untouched subtrees
are deliberately not expanded. Independent full-tree/object and bundle-object
flags remain false; the new flag describes the exact root commitment, not a
pack traversal, collision-proof stronger hash, signature, authorship or authority
proof. Native Rust still verifies actual pack/object admission and publication.
These observations do not establish that a dishonest authority published the
requested root; publication and outcome recovery retain their own trust boundary.

## Re-check and publish separately

Offline inspection regenerates the draft from its original source evidence and
revalidates the complete standard candidate. It accepts no token or network option:

```bash
node scripts/fg_source_changes.mjs inspect-candidate \
  --package /private/session/source-package.json \
  --expect /private/session/expect.json \
  --changes /private/session/changes.json \
  --candidate /private/session/candidate \
  --sha256 "$CANDIDATE_MANIFEST_SHA256" \
  --confirm-draft-sha256 "$REVIEWED_DRAFT_SHA256"
```

The existing `scripts/fg_source_edit.mjs stage`, `apply`, `status`, and `recover`
commands consume that standard candidate unchanged. They separately require the
original principal and explicit candidate confirmation, retain a publication
journal, submit once, and resolve uncertain replies using the original key.
This authoring CLI has no stage/apply endpoint and never automatically publishes.

## Bounds, interruption, and validation scope

The defaults are hard ceilings: 32 edit paths, 1 MiB per edited before/after file,
4 MiB of retained before-plus-after bytes, 4,096 total splices, 1 MiB of generated
patch input, and a 10 MiB changes JSON envelope. The existing package remains
bounded to 32 MiB encoded and 8 MiB full logical source. Absence verification
shares the membership profile: at most 128 complete trees, 16,384 entries, 4 MiB
of tree bytes, 32 creation targets and 32 KiB of target path bytes. Root derivation
separately bounds output work to 2,048 affected directories, 32,768 encoded entries
and 8 MiB of tree bodies, while retaining the original proof limits. The 32-file,
64-component creation maximum fits without expanding unrelated subtrees. The
shared `deriveEditedTree` API accepts narrower `membership` and `output` bounds;
none can raise these ceilings. Output encoding/hash work is checked before each
new tree body is allocated, and cancellation returns no partial root. An encoded patch may hit
its limit before either individual file does. The library accepts narrower edit
limits; the CLI uses the fixed profile. `--timeout-ms` is 1–300,000 (30,000 default)
across input reads, local verification, and any native preparation/inspection.

A local output directory is claimed create-only. After that point, an admitted
write/sync/readback drains rather than being abandoned on late cancellation.
An output or stdout failure returns exit 4 and retains the original location and
hashes when known. Interrupted slots are never deleted, reset, or overwritten;
inspect them instead of treating missing output as proof of absence. File and
directory sync/readback do not establish a universal hardware power-loss guarantee.

Run the focused external-client lane with:

```bash
bash scripts/verify_source_changes.sh
```

Tests execute complete production imports, actual HTTP/TLS sockets, private files,
CLI processes, WebCrypto, and the unchanged native-candidate owner/recovery client.
Installed Git is used only in test fixtures to apply real patches and construct
real candidate trees/commits/bundles in both hash domains. It is not the pinned
Git conformance lane. HTTP native-schema peers remain explicit fixtures, not a
running Rust fg server, authorization/admission/CAS execution, or a complete
sandboxed agent run. This work does not close the broader agent-execution beads.

## Explicit binary-safe profile

Set `byte_profile: "binary-safe-v1"` in the changes JSON to use every regular-file
operation with arbitrary bytes, including NUL. The existing default and its review
hashes remain unchanged. This opt-in is part of the normalized request and reviewed
draft, not a permission grant. See [BINARY_SOURCE_AUTHORING.md](BINARY_SOURCE_AUTHORING.md)
for counted raw-byte patches, unchanged resource ceilings and tested integration
through workspace capture, replay, preparation, staging and recovery.
